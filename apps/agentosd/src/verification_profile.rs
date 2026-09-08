use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactPrincipalKind, AuthenticatedArtifactPrincipal,
    canonical_request_digest, content_address,
};
use egopulse_codex_adapter::codex_protocol_fingerprint;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactStatus, ContentAddress,
        IntegrityStatus, LineageBinding, ProducerIdentity, Provenance, SealArtifactCommand,
        StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    verification::v1::{CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus},
};
use egopulse_verification_authority::{VerificationAuthority, canonical_checker_profile_digest};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{
    artifact::{
        ConfiguredArtifactAdmissionGuard, DerivedWorkspaceAdmissionBinding,
        DerivedWorkspaceAdmissionHandle,
    },
    verification::SystemCheckerProfileAttestation,
    verification_material::{VerificationMaterialError, VerifiedRepositoryVerificationMaterial},
};

const DEPLOYMENT_SCHEMA: &str = "egopulse.checker-profile-attestation/v1";
const DEPLOYMENT_MEDIA_TYPE: &str = "application/vnd.egopulse.checker-profile-attestation.v1+json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryCheckerRole {
    Scope,
    Tests,
    Review,
}

impl RepositoryCheckerRole {
    const fn criterion_type(self) -> &'static str {
        match self {
            Self::Scope => "scope",
            Self::Tests => "tests",
            Self::Review => "review",
        }
    }

    const fn assurance(self) -> CheckerAssuranceClass {
        match self {
            Self::Scope | Self::Tests => CheckerAssuranceClass::Deterministic,
            Self::Review => CheckerAssuranceClass::ModelAssisted,
        }
    }

    const fn checker_id(self) -> &'static str {
        match self {
            Self::Scope => "agentosd.repository-scope-checker",
            Self::Tests => "agentosd.repository-tests-checker",
            Self::Review => "codex-adapter.repository-review-checker",
        }
    }

    const fn implementation_id(self) -> &'static str {
        match self {
            Self::Scope => "verification-output/repository-scope/v1",
            Self::Tests => "verification-output/repository-tests/v1",
            Self::Review => "codex-adapter/readonly-repository-review/v1",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RepositoryCheckerProfileDeployment {
    pub(crate) role: RepositoryCheckerRole,
    pub(crate) checker_profile_id: String,
    pub(crate) input_contract_ref: ContractReference,
    pub(crate) output_contract_ref: ContractReference,
    pub(crate) sandbox_profile_ref: ContractReference,
    pub(crate) tool_policy_ref: ContractReference,
    pub(crate) data_egress_policy_ref: ContractReference,
    pub(crate) budget_profile_ref: ContractReference,
    pub(crate) timeout_ms: u64,
    pub(crate) model: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct RepositoryCheckerDeploymentConfig {
    pub(crate) scope: RepositoryCheckerProfileDeployment,
    pub(crate) tests: RepositoryCheckerProfileDeployment,
    pub(crate) review: RepositoryCheckerProfileDeployment,
    pub(crate) attestation_type_ref: ContractReference,
    pub(crate) attestation_transformation_ref: ContractReference,
    pub(crate) retention_profile_ref: ContractReference,
    pub(crate) governed_collector_principal_id: String,
    pub(crate) artifact_authority_principal_id: String,
    pub(crate) sensitivity_class: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedRepositoryCheckerProfiles {
    pub(crate) scope: CheckerProfile,
    pub(crate) tests: CheckerProfile,
    pub(crate) review: CheckerProfile,
}

pub(crate) struct RepositoryCheckerDeploymentPreparer {
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    admission: DerivedWorkspaceAdmissionHandle,
    verification: Arc<Mutex<VerificationAuthority>>,
    attestation: SystemCheckerProfileAttestation,
    config: RepositoryCheckerDeploymentConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RepositoryCheckerProfileError {
    #[error("repository checker deployment configuration is invalid")]
    InvalidConfiguration,
    #[error("repository checker deployment material is invalid")]
    InvalidMaterial,
    #[error("repository checker deployment Authority is unavailable")]
    Unavailable,
    #[error("repository checker profile conflicts with immutable deployed identity")]
    Conflict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckerDeploymentPayload {
    schema: String,
    declaration_kind: String,
    role: String,
    checker_profile_id: String,
    checker_id: String,
    checker_version: String,
    input_contract_ref: FrozenReference,
    output_contract_ref: FrozenReference,
    supported_criterion_types: Vec<String>,
    assurance_class: i32,
    sandbox_profile_ref: FrozenReference,
    tool_policy_ref: FrozenReference,
    data_egress_policy_ref: FrozenReference,
    budget_profile_ref: FrozenReference,
    timeout_ms: u64,
    network_allowed: bool,
    model: Option<String>,
    capability_basis: CompiledCapabilityBasis,
    profile_digest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompiledCapabilityBasis {
    agentosd_version: String,
    implementation_id: String,
    codex_protocol: Option<CodexProtocolBasis>,
    runtime_probe_performed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexProtocolBasis {
    protocol_name: String,
    protocol_version: String,
    schema_sha256: String,
    adapter_version: String,
    expected_native_executable_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FrozenReference {
    contract_id: String,
    version: String,
    sha256: String,
}

impl From<&ContractReference> for FrozenReference {
    fn from(value: &ContractReference) -> Self {
        Self {
            contract_id: value.contract_id.clone(),
            version: value.version.clone(),
            sha256: value.sha256.clone(),
        }
    }
}

impl RepositoryCheckerDeploymentPreparer {
    pub(crate) fn new(
        artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
        admission: DerivedWorkspaceAdmissionHandle,
        verification: Arc<Mutex<VerificationAuthority>>,
        config: RepositoryCheckerDeploymentConfig,
    ) -> Result<Self, RepositoryCheckerProfileError> {
        validate_config(&config)?;
        Ok(Self {
            artifact,
            admission,
            verification: Arc::clone(&verification),
            attestation: SystemCheckerProfileAttestation::new(verification),
            config,
        })
    }

    pub(crate) fn prepare_for(
        &self,
        material: &VerifiedRepositoryVerificationMaterial,
        issued_at: Timestamp,
    ) -> Result<PreparedRepositoryCheckerProfiles, RepositoryCheckerProfileError> {
        let scope = self.prepare_one(&self.config.scope, material, issued_at)?;
        let tests = self.prepare_one(&self.config.tests, material, issued_at)?;
        let review = self.prepare_one(&self.config.review, material, issued_at)?;
        Ok(PreparedRepositoryCheckerProfiles {
            scope,
            tests,
            review,
        })
    }

    fn prepare_one(
        &self,
        deployment: &RepositoryCheckerProfileDeployment,
        material: &VerifiedRepositoryVerificationMaterial,
        issued_at: Timestamp,
    ) -> Result<CheckerProfile, RepositoryCheckerProfileError> {
        let artifact_id = attestation_artifact_id(&deployment.checker_profile_id);
        let existing_profile = self.attestation_profile(&deployment.checker_profile_id)?;
        if let Some(existing) = existing_profile {
            self.verify_existing(&existing, deployment, &artifact_id)?;
            self.attestation
                .attest_one(existing.clone(), issued_at)
                .map_err(|_| RepositoryCheckerProfileError::Conflict)?;
            return Ok(existing);
        }

        let mut profile = profile_candidate(deployment, artifact_id.clone());
        profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
        let payload = deployment_payload(deployment, &profile);
        let bytes = serde_json::to_vec(&payload)
            .map_err(|_| RepositoryCheckerProfileError::InvalidConfiguration)?;
        let lineage = material
            .binding
            .lineage
            .as_ref()
            .ok_or(RepositoryCheckerProfileError::InvalidMaterial)?;
        let source_binding_ref = format!(
            "checker-profile-deployment:{}",
            profile.profile_digest_sha256
        );
        let binding_artifact_ids = declaration_binding_artifact_ids(material)?;
        self.stage_and_seal(
            &artifact_id,
            &bytes,
            lineage,
            &material.baseline.workspace_ref,
            &source_binding_ref,
            &binding_artifact_ids,
            &issued_at,
        )?;
        self.attestation
            .attest_one(profile.clone(), issued_at)
            .map_err(|_| RepositoryCheckerProfileError::Conflict)?;
        self.read_profile(&profile.checker_profile_id)?
            .ok_or(RepositoryCheckerProfileError::Conflict)
    }

    fn attestation_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<CheckerProfile>, RepositoryCheckerProfileError> {
        self.read_profile(profile_id)
    }

    fn read_profile(
        &self,
        profile_id: &str,
    ) -> Result<Option<CheckerProfile>, RepositoryCheckerProfileError> {
        self.verification
            .lock()
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            .checker_profile(profile_id)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)
    }

    fn stage_and_seal(
        &self,
        artifact_id: &str,
        bytes: &[u8],
        lineage: &LineageBinding,
        workspace_ref: &str,
        source_binding_ref: &str,
        binding_artifact_ids: &[String],
        issued_at: &Timestamp,
    ) -> Result<(), RepositoryCheckerProfileError> {
        let address = content_address(bytes);
        let candidate = ArtifactDescriptor {
            artifact_id: artifact_id.to_owned(),
            revision: 1,
            status: ArtifactStatus::Staged as i32,
            semantic_class: ArtifactSemanticClass::TypedExtension as i32,
            type_contract_ref: Some(self.config.attestation_type_ref.clone()),
            media_type: DEPLOYMENT_MEDIA_TYPE.to_owned(),
            content: Some(address.clone()),
            integrity_status: IntegrityStatus::Unverified as i32,
            provenance: Some(Provenance {
                lineage: Some(lineage.clone()),
                producer: Some(ProducerIdentity {
                    principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
                    principal_id: self.config.governed_collector_principal_id.clone(),
                    component_name: "agentosd-checker-profile-deployment".to_owned(),
                    component_version: env!("CARGO_PKG_VERSION").to_owned(),
                    capability_profile_id: None,
                    native_execution_ref: None,
                }),
                input_artifact_ids: binding_artifact_ids.to_vec(),
                transformation_contract_ref: Some(
                    self.config.attestation_transformation_ref.clone(),
                ),
                workspace_ref: workspace_ref.to_owned(),
                observed_at: None,
                captured_at: None,
                raw_source_ref: Some(source_binding_ref.to_owned()),
            }),
            sensitivity_class: self.config.sensitivity_class.clone(),
            retention_profile_ref: Some(self.config.retention_profile_ref.clone()),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        };
        let expected_candidate = candidate.clone();
        let mut authority = self
            .artifact
            .lock()
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        if let Some(existing) = authority
            .read_artifact(artifact_id)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
        {
            verify_existing_deployment_artifact(
                &authority,
                &existing,
                artifact_id,
                bytes,
                &self.config,
                false,
            )?;
            if existing.status == ArtifactStatus::Sealed as i32 {
                return Ok(());
            }
            let provenance = existing
                .provenance
                .as_ref()
                .ok_or(RepositoryCheckerProfileError::Conflict)?;
            let _recovery_lease = self
                .admission
                .register(DerivedWorkspaceAdmissionBinding {
                    workspace_ref: provenance.workspace_ref.clone(),
                    lineage: provenance
                        .lineage
                        .clone()
                        .ok_or(RepositoryCheckerProfileError::Conflict)?,
                    source_binding_ref: provenance
                        .raw_source_ref
                        .clone()
                        .ok_or(RepositoryCheckerProfileError::Conflict)?,
                })
                .map_err(|_| RepositoryCheckerProfileError::Conflict)?;
            let sealed = authority
                .execute(
                    &seal_command(artifact_id, address, "seal", issued_at),
                    &principal(
                        ArtifactPrincipalKind::ArtifactAuthority,
                        &self.config.artifact_authority_principal_id,
                    ),
                )
                .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
            if !sealed.committed && !sealed.replayed {
                return Err(RepositoryCheckerProfileError::Conflict);
            }
            let stored = authority
                .read_artifact(artifact_id)
                .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
                .ok_or(RepositoryCheckerProfileError::Conflict)?;
            return verify_existing_deployment_artifact(
                &authority,
                &stored,
                artifact_id,
                bytes,
                &self.config,
                true,
            );
        }
        let _lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: workspace_ref.to_owned(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.to_owned(),
            })
            .map_err(|_| RepositoryCheckerProfileError::InvalidMaterial)?;
        authority
            .put_blob(bytes, &address)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        let staged = authority
            .execute(
                &stage_command(candidate, artifact_id, "stage", issued_at),
                &principal(
                    ArtifactPrincipalKind::GovernedCollector,
                    &self.config.governed_collector_principal_id,
                ),
            )
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        if !staged.committed && !staged.replayed {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
        let sealed = authority
            .execute(
                &seal_command(artifact_id, address, "seal", issued_at),
                &principal(
                    ArtifactPrincipalKind::ArtifactAuthority,
                    &self.config.artifact_authority_principal_id,
                ),
            )
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        if !sealed.committed && !sealed.replayed {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
        let stored = authority
            .read_artifact(artifact_id)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            .ok_or(RepositoryCheckerProfileError::Conflict)?;
        verify_existing_artifact(&authority, &stored, &expected_candidate, bytes, true)
    }

    fn verify_existing(
        &self,
        profile: &CheckerProfile,
        deployment: &RepositoryCheckerProfileDeployment,
        artifact_id: &str,
    ) -> Result<(), RepositoryCheckerProfileError> {
        let expected = profile_candidate(deployment, artifact_id.to_owned());
        if profile.status != CheckerProfileStatus::Active as i32
            || profile.checker_profile_id != expected.checker_profile_id
            || profile.checker_id != expected.checker_id
            || profile.checker_version != expected.checker_version
            || profile.input_contract_ref != expected.input_contract_ref
            || profile.output_contract_ref != expected.output_contract_ref
            || profile.supported_criterion_types != expected.supported_criterion_types
            || profile.assurance_class != expected.assurance_class
            || profile.sandbox_profile_ref != expected.sandbox_profile_ref
            || profile.tool_policy_ref != expected.tool_policy_ref
            || profile.data_egress_policy_ref != expected.data_egress_policy_ref
            || profile.timeout_ms != expected.timeout_ms
            || profile.network_allowed != expected.network_allowed
            || profile.attestation_evidence_artifact_ids
                != expected.attestation_evidence_artifact_ids
            || profile.profile_digest_sha256 != canonical_checker_profile_digest(profile)
        {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
        let authority = self
            .artifact
            .lock()
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        let artifact = authority
            .read_artifact(artifact_id)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            .ok_or(RepositoryCheckerProfileError::Conflict)?;
        let address = artifact
            .content
            .as_ref()
            .ok_or(RepositoryCheckerProfileError::Conflict)?;
        let bytes = authority
            .read_blob(address)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        let payload: CheckerDeploymentPayload =
            serde_json::from_slice(&bytes).map_err(|_| RepositoryCheckerProfileError::Conflict)?;
        if payload != deployment_payload(deployment, profile) {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
        verify_existing_deployment_artifact(
            &authority,
            &artifact,
            artifact_id,
            &bytes,
            &self.config,
            true,
        )
    }
}

fn profile_candidate(
    deployment: &RepositoryCheckerProfileDeployment,
    artifact_id: String,
) -> CheckerProfile {
    let (checker_version, _) = compiled_checker_basis(deployment.role);
    CheckerProfile {
        checker_profile_id: deployment.checker_profile_id.clone(),
        revision: 0,
        status: CheckerProfileStatus::Unspecified as i32,
        checker_id: deployment.role.checker_id().to_owned(),
        checker_version,
        input_contract_ref: Some(deployment.input_contract_ref.clone()),
        output_contract_ref: Some(deployment.output_contract_ref.clone()),
        supported_criterion_types: vec![deployment.role.criterion_type().to_owned()],
        assurance_class: deployment.role.assurance() as i32,
        sandbox_profile_ref: Some(deployment.sandbox_profile_ref.clone()),
        tool_policy_ref: Some(deployment.tool_policy_ref.clone()),
        data_egress_policy_ref: Some(deployment.data_egress_policy_ref.clone()),
        timeout_ms: deployment.timeout_ms,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![artifact_id],
        attested_at: None,
    }
}

fn deployment_payload(
    deployment: &RepositoryCheckerProfileDeployment,
    profile: &CheckerProfile,
) -> CheckerDeploymentPayload {
    let (checker_version, codex_protocol) = compiled_checker_basis(deployment.role);
    CheckerDeploymentPayload {
        schema: DEPLOYMENT_SCHEMA.to_owned(),
        declaration_kind: "compiled_implementation_and_validated_configuration".to_owned(),
        role: deployment.role.criterion_type().to_owned(),
        checker_profile_id: deployment.checker_profile_id.clone(),
        checker_id: deployment.role.checker_id().to_owned(),
        checker_version,
        input_contract_ref: FrozenReference::from(&deployment.input_contract_ref),
        output_contract_ref: FrozenReference::from(&deployment.output_contract_ref),
        supported_criterion_types: vec![deployment.role.criterion_type().to_owned()],
        assurance_class: deployment.role.assurance() as i32,
        sandbox_profile_ref: FrozenReference::from(&deployment.sandbox_profile_ref),
        tool_policy_ref: FrozenReference::from(&deployment.tool_policy_ref),
        data_egress_policy_ref: FrozenReference::from(&deployment.data_egress_policy_ref),
        budget_profile_ref: FrozenReference::from(&deployment.budget_profile_ref),
        timeout_ms: deployment.timeout_ms,
        network_allowed: false,
        model: deployment.model.clone(),
        capability_basis: CompiledCapabilityBasis {
            agentosd_version: env!("CARGO_PKG_VERSION").to_owned(),
            implementation_id: deployment.role.implementation_id().to_owned(),
            codex_protocol,
            runtime_probe_performed: false,
        },
        profile_digest_sha256: profile.profile_digest_sha256.clone(),
    }
}

fn compiled_checker_basis(role: RepositoryCheckerRole) -> (String, Option<CodexProtocolBasis>) {
    if role != RepositoryCheckerRole::Review {
        return (env!("CARGO_PKG_VERSION").to_owned(), None);
    }
    let observed = codex_protocol_fingerprint();
    (
        observed.adapter_version.clone(),
        Some(CodexProtocolBasis {
            protocol_name: observed.protocol_name,
            protocol_version: observed.protocol_version,
            schema_sha256: observed.schema_sha256,
            adapter_version: observed.adapter_version,
            expected_native_executable_version: observed.native_executable_version,
        }),
    )
}

fn declaration_binding_artifact_ids(
    material: &VerifiedRepositoryVerificationMaterial,
) -> Result<Vec<String>, RepositoryCheckerProfileError> {
    let lineage = material
        .binding
        .lineage
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::InvalidMaterial)?;
    if !lineage_complete(lineage) {
        return Err(RepositoryCheckerProfileError::InvalidMaterial);
    }
    let set_ids = material
        .evidence
        .iter()
        .flat_map(|evidence| evidence.artifact_ids.iter())
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let fixed_ids = [
        material.baseline.artifact.descriptor.artifact_id.as_str(),
        material.initial_manifest.descriptor.artifact_id.as_str(),
        material.patch.descriptor.artifact_id.as_str(),
        material.final_manifest.descriptor.artifact_id.as_str(),
    ];
    let receipt_ids = material
        .command_observations
        .iter()
        .filter_map(|observation| observation.receipt.as_ref())
        .map(|receipt| receipt.descriptor.artifact_id.as_str());
    validate_declaration_binding_ids(fixed_ids.into_iter().chain(receipt_ids), &set_ids)
}

fn validate_declaration_binding_ids<'a>(
    ids: impl IntoIterator<Item = &'a str>,
    set_ids: &std::collections::BTreeSet<&str>,
) -> Result<Vec<String>, RepositoryCheckerProfileError> {
    let mut unique = std::collections::BTreeSet::new();
    let mut validated = Vec::new();
    for id in ids {
        if id.trim().is_empty() || !set_ids.contains(id) || !unique.insert(id) {
            return Err(RepositoryCheckerProfileError::InvalidMaterial);
        }
        validated.push(id.to_owned());
    }
    Ok(validated)
}

fn validate_config(
    config: &RepositoryCheckerDeploymentConfig,
) -> Result<(), RepositoryCheckerProfileError> {
    if config.scope.role != RepositoryCheckerRole::Scope
        || config.tests.role != RepositoryCheckerRole::Tests
        || config.review.role != RepositoryCheckerRole::Review
        || !all_references_valid(config)
        || [
            &config.governed_collector_principal_id,
            &config.artifact_authority_principal_id,
            &config.sensitivity_class,
        ]
        .into_iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(RepositoryCheckerProfileError::InvalidConfiguration);
    }
    let mut ids = std::collections::BTreeSet::new();
    for deployment in [&config.scope, &config.tests, &config.review] {
        if !ids.insert(deployment.checker_profile_id.as_str())
            || deployment.checker_profile_id.trim().is_empty()
            || deployment.timeout_ms == 0
        {
            return Err(RepositoryCheckerProfileError::InvalidConfiguration);
        }
    }
    if config.scope.model.is_some()
        || config.tests.model.is_some()
        || config
            .review
            .model
            .as_deref()
            .is_none_or(|model| model.trim().is_empty())
    {
        return Err(RepositoryCheckerProfileError::InvalidConfiguration);
    }
    Ok(())
}

fn all_references_valid(config: &RepositoryCheckerDeploymentConfig) -> bool {
    [
        &config.attestation_type_ref,
        &config.attestation_transformation_ref,
        &config.retention_profile_ref,
    ]
    .into_iter()
    .chain(
        [&config.scope, &config.tests, &config.review]
            .into_iter()
            .flat_map(|deployment| {
                [
                    &deployment.input_contract_ref,
                    &deployment.output_contract_ref,
                    &deployment.sandbox_profile_ref,
                    &deployment.tool_policy_ref,
                    &deployment.data_egress_policy_ref,
                    &deployment.budget_profile_ref,
                ]
            }),
    )
    .all(contract_reference_valid)
}

fn contract_reference_valid(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lineage_complete(lineage: &LineageBinding) -> bool {
    !lineage.task_id.trim().is_empty()
        && lineage.task_revision > 0
        && lineage.work_revision > 0
        && !lineage.run_id.trim().is_empty()
        && lineage.run_revision > 0
        && !lineage.step_id.trim().is_empty()
        && lineage.step_revision > 0
        && !lineage.attempt_id.trim().is_empty()
        && lineage.attempt_revision > 0
        && !lineage.dispatch_id.trim().is_empty()
        && lineage.fencing_token > 0
}

fn attestation_artifact_id(profile_id: &str) -> String {
    format!("artifact:checker-profile-attestation:{profile_id}")
}

fn verify_existing_artifact(
    authority: &ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    actual: &ArtifactDescriptor,
    expected: &ArtifactDescriptor,
    bytes: &[u8],
    require_sealed: bool,
) -> Result<(), RepositoryCheckerProfileError> {
    let address = actual
        .content
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    let expected_provenance = expected
        .provenance
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    if actual.artifact_id != expected.artifact_id
        || (actual.status != ArtifactStatus::Staged as i32
            && actual.status != ArtifactStatus::Sealed as i32)
        || (require_sealed && actual.status != ArtifactStatus::Sealed as i32)
        || actual.integrity_status != IntegrityStatus::DigestVerified as i32
        || actual.semantic_class != expected.semantic_class
        || actual.type_contract_ref != expected.type_contract_ref
        || actual.media_type != expected.media_type
        || actual.provenance.as_ref() != Some(expected_provenance)
        || actual.sensitivity_class != expected.sensitivity_class
        || actual.retention_profile_ref != expected.retention_profile_ref
        || content_address(bytes) != *address
        || authority
            .read_blob(address)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            != bytes
    {
        return Err(RepositoryCheckerProfileError::Conflict);
    }
    Ok(())
}

fn verify_existing_deployment_artifact(
    authority: &ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    actual: &ArtifactDescriptor,
    artifact_id: &str,
    bytes: &[u8],
    config: &RepositoryCheckerDeploymentConfig,
    require_sealed: bool,
) -> Result<(), RepositoryCheckerProfileError> {
    let address = actual
        .content
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    let provenance = actual
        .provenance
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    let payload: CheckerDeploymentPayload =
        serde_json::from_slice(bytes).map_err(|_| RepositoryCheckerProfileError::Conflict)?;
    let expected_source = format!(
        "checker-profile-deployment:{}",
        payload.profile_digest_sha256
    );
    if actual.artifact_id != artifact_id
        || (actual.status != ArtifactStatus::Staged as i32
            && actual.status != ArtifactStatus::Sealed as i32)
        || (require_sealed && actual.status != ArtifactStatus::Sealed as i32)
        || actual.integrity_status != IntegrityStatus::DigestVerified as i32
        || actual.semantic_class != ArtifactSemanticClass::TypedExtension as i32
        || actual.type_contract_ref.as_ref() != Some(&config.attestation_type_ref)
        || actual.media_type != DEPLOYMENT_MEDIA_TYPE
        || actual.sensitivity_class != config.sensitivity_class
        || actual.retention_profile_ref.as_ref() != Some(&config.retention_profile_ref)
        || provenance.transformation_contract_ref.as_ref()
            != Some(&config.attestation_transformation_ref)
        || provenance.input_artifact_ids.is_empty()
        || provenance.workspace_ref.trim().is_empty()
        || provenance.raw_source_ref.as_deref() != Some(expected_source.as_str())
        || !provenance.lineage.as_ref().is_some_and(lineage_complete)
        || producer.principal_kind != ArtifactPrincipalKind::GovernedCollector.as_str()
        || producer.principal_id != config.governed_collector_principal_id
        || producer.component_name != "agentosd-checker-profile-deployment"
        || producer.component_version != env!("CARGO_PKG_VERSION")
        || producer.capability_profile_id.is_some()
        || producer.native_execution_ref.is_some()
        || content_address(bytes) != *address
        || authority
            .read_blob(address)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            != bytes
    {
        return Err(RepositoryCheckerProfileError::Conflict);
    }
    verify_bound_inputs(authority, provenance)
}

fn verify_bound_inputs(
    authority: &ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    provenance: &Provenance,
) -> Result<(), RepositoryCheckerProfileError> {
    let lineage = provenance
        .lineage
        .as_ref()
        .ok_or(RepositoryCheckerProfileError::Conflict)?;
    let mut unique = std::collections::BTreeSet::new();
    for artifact_id in &provenance.input_artifact_ids {
        if artifact_id.trim().is_empty() || !unique.insert(artifact_id.as_str()) {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
        let input = authority
            .read_artifact(artifact_id)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?
            .ok_or(RepositoryCheckerProfileError::Conflict)?;
        let address = input
            .content
            .as_ref()
            .ok_or(RepositoryCheckerProfileError::Conflict)?;
        let input_bytes = authority
            .read_blob(address)
            .map_err(|_| RepositoryCheckerProfileError::Unavailable)?;
        if input.status != ArtifactStatus::Sealed as i32
            || input.integrity_status != IntegrityStatus::DigestVerified as i32
            || input
                .provenance
                .as_ref()
                .and_then(|value| value.lineage.as_ref())
                != Some(lineage)
            || input
                .provenance
                .as_ref()
                .map(|value| value.workspace_ref.as_str())
                != Some(provenance.workspace_ref.as_str())
            || content_address(&input_bytes) != *address
        {
            return Err(RepositoryCheckerProfileError::Conflict);
        }
    }
    Ok(())
}

fn stage_command(
    candidate: ArtifactDescriptor,
    id: &str,
    operation: &str,
    issued_at: &Timestamp,
) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::StageArtifact(
        StageArtifactCommand {
            metadata: Some(metadata(id, operation, issued_at)),
            candidate: Some(candidate),
        },
    ))
}

fn seal_command(
    id: &str,
    address: ContentAddress,
    operation: &str,
    issued_at: &Timestamp,
) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::SealArtifact(
        SealArtifactCommand {
            metadata: Some(metadata(id, operation, issued_at)),
            artifact_id: id.to_owned(),
            expected_revision: 1,
            observed_content: Some(address),
        },
    ))
}

fn metadata(id: &str, operation: &str, issued_at: &Timestamp) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("checker-profile-{operation}:{id}"),
        idempotency_scope: "checker-profile-deployment-v1".to_owned(),
        idempotency_key: format!("{operation}:{id}"),
        request_digest_sha256: String::new(),
        issued_at: Some(*issued_at),
        correlation_id: id.to_owned(),
        causation_id: Some(format!("checker-profile-deployment:{id}")),
    }
}

fn command_with_digest(command: artifact_command::Command) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(command),
    };
    let digest = canonical_request_digest(&command).expect("constructed Artifact command");
    match command.command.as_mut().expect("constructed command") {
        artifact_command::Command::StageArtifact(value) => {
            value
                .metadata
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        artifact_command::Command::SealArtifact(value) => {
            value
                .metadata
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        _ => unreachable!("deployment uses only stage and seal"),
    }
    command
}

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

impl From<VerificationMaterialError> for RepositoryCheckerProfileError {
    fn from(_: VerificationMaterialError) -> Self {
        Self::InvalidMaterial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn deployment(
        role: RepositoryCheckerRole,
        profile_id: &str,
    ) -> RepositoryCheckerProfileDeployment {
        RepositoryCheckerProfileDeployment {
            role,
            checker_profile_id: profile_id.to_owned(),
            input_contract_ref: reference("input"),
            output_contract_ref: reference("output"),
            sandbox_profile_ref: reference("sandbox"),
            tool_policy_ref: reference("tools"),
            data_egress_policy_ref: reference("egress"),
            budget_profile_ref: reference("budget"),
            timeout_ms: 30_000,
            model: (role == RepositoryCheckerRole::Review).then(|| "review-model".to_owned()),
        }
    }

    fn config() -> RepositoryCheckerDeploymentConfig {
        RepositoryCheckerDeploymentConfig {
            scope: deployment(RepositoryCheckerRole::Scope, "profile:repository-scope:v1"),
            tests: deployment(RepositoryCheckerRole::Tests, "profile:repository-tests:v1"),
            review: deployment(
                RepositoryCheckerRole::Review,
                "profile:repository-review:v1",
            ),
            attestation_type_ref: reference("checker-deployment"),
            attestation_transformation_ref: reference("checker-deployment-capture"),
            retention_profile_ref: reference("retention"),
            governed_collector_principal_id: "collector:verification-deployment".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
            sensitivity_class: "internal".to_owned(),
        }
    }

    #[test]
    fn deployment_payload_uses_compiled_identity_without_claiming_runtime_probe() {
        let deployment = deployment(
            RepositoryCheckerRole::Review,
            "profile:repository-review:v1",
        );
        let artifact_id = attestation_artifact_id(&deployment.checker_profile_id);
        let mut profile = profile_candidate(&deployment, artifact_id);
        profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);

        let payload = deployment_payload(&deployment, &profile);
        let observed = codex_protocol_fingerprint();
        let protocol = payload
            .capability_basis
            .codex_protocol
            .as_ref()
            .expect("review deployment has a compiled Codex protocol basis");
        assert_eq!(
            payload.checker_id,
            RepositoryCheckerRole::Review.checker_id()
        );
        assert_eq!(payload.checker_version, observed.adapter_version);
        assert_eq!(protocol.schema_sha256, observed.schema_sha256);
        assert_eq!(
            protocol.expected_native_executable_version,
            observed.native_executable_version
        );
        assert!(!payload.capability_basis.runtime_probe_performed);
        assert_eq!(payload.model.as_deref(), Some("review-model"));
        assert!(!payload.network_allowed);
    }

    #[test]
    fn deployment_config_fixes_roles_and_requires_review_model_only() {
        let valid = config();
        assert_eq!(validate_config(&valid), Ok(()));

        let mut missing_review_model = valid.clone();
        missing_review_model.review.model = None;
        assert_eq!(
            validate_config(&missing_review_model),
            Err(RepositoryCheckerProfileError::InvalidConfiguration)
        );

        let mut deterministic_model = valid;
        deterministic_model.scope.model = Some("unexpected".to_owned());
        assert_eq!(
            validate_config(&deterministic_model),
            Err(RepositoryCheckerProfileError::InvalidConfiguration)
        );
    }

    #[test]
    fn declaration_binding_accepts_set_receipt_without_requiring_command_intent() {
        let set_ids =
            std::collections::BTreeSet::from(["baseline", "initial", "patch", "final", "receipt"]);
        let ids = validate_declaration_binding_ids(
            ["baseline", "initial", "patch", "final", "receipt"],
            &set_ids,
        )
        .expect("sealed set members are valid deployment inputs");

        assert_eq!(
            ids,
            vec![
                "baseline".to_owned(),
                "initial".to_owned(),
                "patch".to_owned(),
                "final".to_owned(),
                "receipt".to_owned(),
            ]
        );
        assert!(!set_ids.contains("intent"));
    }
}
