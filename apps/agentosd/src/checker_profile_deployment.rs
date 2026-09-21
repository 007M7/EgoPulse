//! Deployment of a checker profile that no repository workflow owns.
//!
//! The Verification Authority attests a checker profile only when every entry
//! in `attestation_evidence_artifact_ids` is a sealed, digest-verified
//! Artifact. The repository path seals its own compiled declaration as that
//! evidence. An environment with no repository material has nothing to seal,
//! so a profile declared in the Verification worker configuration is deployed
//! here: the worker seals the declaration it was configured with before it
//! attests the profile, and a profile is never attested when that sealing
//! fails.

use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactPrincipalKind, AuthenticatedArtifactPrincipal,
    canonical_request_digest, content_address,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactStatus, ContentAddress,
        IntegrityStatus, LineageBinding, ProducerIdentity, Provenance, SealArtifactCommand,
        StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    verification::v1::CheckerProfile,
};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::ConfiguredArtifactAdmissionGuard;

pub(crate) const CHECKER_PROFILE_DEPLOYMENT_SCHEMA: &str =
    "egopulse.checker-profile-attestation/v1";
const DEPLOYMENT_MEDIA_TYPE: &str = "application/vnd.egopulse.checker-profile-attestation.v1+json";

/// Deterministic identity of the sealed declaration that evidences one
/// checker profile's attestation. It is derived from the profile id alone so a
/// configuration can cite the artifact it will get, and so a restart seals and
/// verifies the same object instead of a second one.
#[must_use]
pub(crate) fn deployment_artifact_id(checker_profile_id: &str) -> String {
    format!("artifact:checker-profile-attestation:{checker_profile_id}")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerProfileDeploymentConfig {
    pub workspace_ref: String,
    pub artifact_type_ref: ContractReference,
    pub transformation_contract_ref: ContractReference,
    pub retention_profile_ref: ContractReference,
    pub collector_principal_id: String,
    pub artifact_authority_principal_id: String,
    pub sensitivity_class: String,
}

impl CheckerProfileDeploymentConfig {
    pub fn validate(&self) -> Result<(), CheckerProfileDeploymentError> {
        if self.workspace_ref.trim().is_empty()
            || self.collector_principal_id.trim().is_empty()
            || self.artifact_authority_principal_id.trim().is_empty()
            || self.sensitivity_class.trim().is_empty()
            || [
                &self.artifact_type_ref,
                &self.transformation_contract_ref,
                &self.retention_profile_ref,
            ]
            .iter()
            .any(|reference| {
                reference.contract_id.trim().is_empty()
                    || reference.version.trim().is_empty()
                    || reference.sha256.trim().is_empty()
            })
        {
            return Err(CheckerProfileDeploymentError::Invalid(
                "checker_profile_deployment",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CheckerProfileDeploymentError {
    #[error("checker profile deployment is invalid: {0}")]
    Invalid(&'static str),
    #[error("checker profile declaration could not be encoded")]
    Encoding,
    #[error("stored checker profile declaration conflicts with the configured one")]
    Conflict,
    #[error("checker profile declaration store is unavailable")]
    Unavailable,
    #[error("checker profile declaration was rejected by the Artifact Authority: {0}")]
    Rejected(String),
}

/// Declaration content of one deployed checker profile. It records what the
/// daemon configuration declared and the digest of the profile that was
/// attested from it, so the sealed evidence and the attested profile can be
/// compared after a restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckerProfileDeclaration {
    schema: String,
    declaration_kind: String,
    declared_by: String,
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
    timeout_ms: u64,
    network_allowed: bool,
    profile_digest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FrozenReference {
    contract_id: String,
    version: String,
    sha256: String,
}

impl From<&ContractReference> for FrozenReference {
    fn from(reference: &ContractReference) -> Self {
        Self {
            contract_id: reference.contract_id.clone(),
            version: reference.version.clone(),
            sha256: reference.sha256.clone(),
        }
    }
}

pub struct ConfiguredCheckerProfileDeployment {
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    config: CheckerProfileDeploymentConfig,
}

impl ConfiguredCheckerProfileDeployment {
    pub fn new(
        artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
        config: CheckerProfileDeploymentConfig,
    ) -> Result<Self, CheckerProfileDeploymentError> {
        config.validate()?;
        Ok(Self { artifact, config })
    }

    /// Seals the configured declaration if it is not sealed yet, and returns
    /// the artifact that evidences the profile's attestation. A declaration
    /// already stored under the same identity is verified rather than
    /// replaced, and a staged-but-unsealed one is completed, so a restart
    /// converges on exactly one object.
    pub fn ensure_sealed(
        &self,
        profile: &CheckerProfile,
        lineage: &LineageBinding,
        issued_at: &Timestamp,
    ) -> Result<String, CheckerProfileDeploymentError> {
        let artifact_id = deployment_artifact_id(&profile.checker_profile_id);
        let bytes = serde_json::to_vec(&declaration(profile))
            .map_err(|_| CheckerProfileDeploymentError::Encoding)?;
        let address = content_address(&bytes);
        let candidate = self.descriptor(&artifact_id, &address, lineage);
        let mut authority = self
            .artifact
            .lock()
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?;
        if let Some(existing) = authority
            .read_artifact(&artifact_id)
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?
        {
            verify_declaration(&authority, &existing, &candidate, &bytes, false)?;
            if existing.status == ArtifactStatus::Sealed as i32 {
                return Ok(artifact_id);
            }
            self.seal(&mut authority, &artifact_id, address.clone(), issued_at)?;
            let stored = authority
                .read_artifact(&artifact_id)
                .map_err(|_| CheckerProfileDeploymentError::Unavailable)?
                .ok_or(CheckerProfileDeploymentError::Conflict)?;
            verify_declaration(&authority, &stored, &candidate, &bytes, true)?;
            return Ok(artifact_id);
        }
        authority
            .put_blob(&bytes, &address)
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?;
        let staged = authority
            .execute(
                &stage_command(candidate.clone(), &artifact_id, issued_at),
                &principal(
                    ArtifactPrincipalKind::GovernedCollector,
                    &self.config.collector_principal_id,
                ),
            )
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?;
        if !staged.committed && !staged.replayed {
            return Err(CheckerProfileDeploymentError::Rejected(command_refusal(
                &staged,
            )));
        }
        self.seal(&mut authority, &artifact_id, address, issued_at)?;
        let stored = authority
            .read_artifact(&artifact_id)
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?
            .ok_or(CheckerProfileDeploymentError::Conflict)?;
        verify_declaration(&authority, &stored, &candidate, &bytes, true)?;
        Ok(artifact_id)
    }

    fn seal(
        &self,
        authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
        artifact_id: &str,
        address: ContentAddress,
        issued_at: &Timestamp,
    ) -> Result<(), CheckerProfileDeploymentError> {
        let sealed = authority
            .execute(
                &seal_command(artifact_id, address, issued_at),
                &principal(
                    ArtifactPrincipalKind::ArtifactAuthority,
                    &self.config.artifact_authority_principal_id,
                ),
            )
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?;
        if !sealed.committed && !sealed.replayed {
            return Err(CheckerProfileDeploymentError::Rejected(command_refusal(
                &sealed,
            )));
        }
        Ok(())
    }

    fn descriptor(
        &self,
        artifact_id: &str,
        address: &ContentAddress,
        lineage: &LineageBinding,
    ) -> ArtifactDescriptor {
        ArtifactDescriptor {
            artifact_id: artifact_id.to_owned(),
            revision: 1,
            status: ArtifactStatus::Staged as i32,
            semantic_class: ArtifactSemanticClass::TypedExtension as i32,
            type_contract_ref: Some(self.config.artifact_type_ref.clone()),
            media_type: DEPLOYMENT_MEDIA_TYPE.to_owned(),
            content: Some(address.clone()),
            integrity_status: IntegrityStatus::Unverified as i32,
            provenance: Some(Provenance {
                lineage: Some(lineage.clone()),
                producer: Some(ProducerIdentity {
                    principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
                    principal_id: self.config.collector_principal_id.clone(),
                    component_name: "agentosd-checker-profile-deployment".to_owned(),
                    component_version: env!("CARGO_PKG_VERSION").to_owned(),
                    capability_profile_id: None,
                    native_execution_ref: None,
                }),
                input_artifact_ids: Vec::new(),
                transformation_contract_ref: Some(self.config.transformation_contract_ref.clone()),
                workspace_ref: self.config.workspace_ref.clone(),
                observed_at: None,
                captured_at: None,
                raw_source_ref: Some(format!("checker-profile-deployment:{artifact_id}")),
            }),
            sensitivity_class: self.config.sensitivity_class.clone(),
            retention_profile_ref: Some(self.config.retention_profile_ref.clone()),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        }
    }
}

fn declaration(profile: &CheckerProfile) -> CheckerProfileDeclaration {
    CheckerProfileDeclaration {
        schema: CHECKER_PROFILE_DEPLOYMENT_SCHEMA.to_owned(),
        declaration_kind: "configured_worker_checker_profile".to_owned(),
        declared_by: "agentosd verification worker configuration".to_owned(),
        checker_profile_id: profile.checker_profile_id.clone(),
        checker_id: profile.checker_id.clone(),
        checker_version: profile.checker_version.clone(),
        input_contract_ref: FrozenReference::from(
            profile
                .input_contract_ref
                .as_ref()
                .unwrap_or(&empty_reference()),
        ),
        output_contract_ref: FrozenReference::from(
            profile
                .output_contract_ref
                .as_ref()
                .unwrap_or(&empty_reference()),
        ),
        supported_criterion_types: profile.supported_criterion_types.clone(),
        assurance_class: profile.assurance_class,
        sandbox_profile_ref: FrozenReference::from(
            profile
                .sandbox_profile_ref
                .as_ref()
                .unwrap_or(&empty_reference()),
        ),
        tool_policy_ref: FrozenReference::from(
            profile
                .tool_policy_ref
                .as_ref()
                .unwrap_or(&empty_reference()),
        ),
        data_egress_policy_ref: FrozenReference::from(
            profile
                .data_egress_policy_ref
                .as_ref()
                .unwrap_or(&empty_reference()),
        ),
        timeout_ms: profile.timeout_ms,
        network_allowed: profile.network_allowed,
        profile_digest_sha256: profile.profile_digest_sha256.clone(),
    }
}

fn empty_reference() -> ContractReference {
    ContractReference::default()
}

fn verify_declaration(
    authority: &ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    actual: &ArtifactDescriptor,
    expected: &ArtifactDescriptor,
    bytes: &[u8],
    require_sealed: bool,
) -> Result<(), CheckerProfileDeploymentError> {
    let address = actual
        .content
        .as_ref()
        .ok_or(CheckerProfileDeploymentError::Conflict)?;
    let expected_provenance = expected
        .provenance
        .as_ref()
        .ok_or(CheckerProfileDeploymentError::Conflict)?;
    let actual_provenance = actual
        .provenance
        .as_ref()
        .ok_or(CheckerProfileDeploymentError::Conflict)?;
    if actual.artifact_id != expected.artifact_id
        || (actual.status != ArtifactStatus::Staged as i32
            && actual.status != ArtifactStatus::Sealed as i32)
        || (require_sealed && actual.status != ArtifactStatus::Sealed as i32)
        || actual.integrity_status != IntegrityStatus::DigestVerified as i32
        || actual.semantic_class != expected.semantic_class
        || actual.type_contract_ref != expected.type_contract_ref
        || actual.retention_profile_ref != expected.retention_profile_ref
        || actual.media_type != expected.media_type
        || actual_provenance.lineage != expected_provenance.lineage
        || actual_provenance.workspace_ref != expected_provenance.workspace_ref
        || actual_provenance.transformation_contract_ref
            != expected_provenance.transformation_contract_ref
        || actual_provenance.producer != expected_provenance.producer
        || authority
            .read_blob(address)
            .map_err(|_| CheckerProfileDeploymentError::Unavailable)?
            != bytes
    {
        return Err(CheckerProfileDeploymentError::Conflict);
    }
    Ok(())
}

fn stage_command(
    candidate: ArtifactDescriptor,
    id: &str,
    issued_at: &Timestamp,
) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::StageArtifact(
        StageArtifactCommand {
            metadata: Some(metadata(id, "stage", issued_at)),
            candidate: Some(candidate),
        },
    ))
}

fn seal_command(id: &str, address: ContentAddress, issued_at: &Timestamp) -> ArtifactCommand {
    command_with_digest(artifact_command::Command::SealArtifact(
        SealArtifactCommand {
            metadata: Some(metadata(id, "seal", issued_at)),
            artifact_id: id.to_owned(),
            expected_revision: 1,
            observed_content: Some(address),
        },
    ))
}

/// Names the Artifact Authority's own refusal instead of a generic code, so a
/// rejected deployment can be diagnosed from the daemon's startup output.
fn command_refusal(
    result: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactCommandResult,
) -> String {
    match result.safe_error_fingerprint.as_deref() {
        Some(fingerprint) => format!("{}:{fingerprint}", result.error_code),
        None => format!("{}:no-safe-fingerprint", result.error_code),
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
        _ => unreachable!("checker profile deployment uses only stage and seal"),
    }
    command
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

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}
