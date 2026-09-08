use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{
    ArtifactAdmissionGuard, ArtifactAuthority, ArtifactClock, ArtifactPrincipalKind,
    AuthenticatedArtifactPrincipal, canonical_artifact_set_manifest,
    canonical_request_digest as artifact_request_digest, content_address,
};
use egopulse_cognition_runtime::task_authority::TaskAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactErrorCode, ArtifactSemanticClass,
        ArtifactSetStatus, ArtifactStatus, ClaimStatus, HashAlgorithm, IntegrityStatus,
        LineageBinding, ProducerIdentity, Provenance, SealArtifactCommand, StageArtifactCommand,
        artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{TaskStatus, get_task_response},
    verdict::v1::{
        CreateFounderSupportingMaterialCommand, FounderSupportingMaterial,
        FounderSupportingMaterialReceipt, FounderSupportingMaterialRole, RiskCategory,
        VerdictScope,
    },
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPortResult, CommandPrincipal, FounderSupportingMaterialPort,
};
use egopulse_verification_authority::canonical_verification_payload;
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle};
use crate::verdict::FounderVerificationEvidenceSource;

pub const MATERIAL_SCHEMA_VERSION: u64 = 1;
pub const MATERIAL_MEDIA_TYPE: &str =
    "application/vnd.egopulse.founder-supporting-material+protobuf";
const FOUNDER_AUTHORITY_KIND: &str = "FounderVerdictAuthority.FounderAuthority";
const MAX_MATERIAL_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FounderSupportingMaterialBinding {
    pub lineage: LineageBinding,
    pub workspace_ref: String,
    pub source_binding_ref: String,
    pub input_artifact_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FounderSupportingMaterialBindingError {
    PermissionDenied,
    ScopeStale,
    IntegrityFailure,
    Unavailable,
}

/// Test seam for the owner-bound reader below. Production construction uses
/// `OwnerBoundFounderSupportingMaterialSource`, which performs all owner reads
/// before returning this closed binding.
pub trait FounderSupportingMaterialBindingSource: Send + Sync + 'static {
    fn bind(
        &self,
        scope: &VerdictScope,
        authenticated_founder_principal_id: &str,
    ) -> Result<FounderSupportingMaterialBinding, FounderSupportingMaterialBindingError>;
}

/// Production owner reader. Every fact comes from an existing shared owner
/// handle; construction opens no second store and exposes no mutation path.
pub struct OwnerBoundFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    task_authority: Arc<Mutex<TaskAuthority>>,
    verification_source: Arc<dyn FounderVerificationEvidenceSource>,
    artifact_authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
    allowed_founder_principal_ids: BTreeSet<String>,
}

impl<G, C> OwnerBoundFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    pub fn new(
        task_authority: Arc<Mutex<TaskAuthority>>,
        verification_source: Arc<dyn FounderVerificationEvidenceSource>,
        artifact_authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        allowed_founder_principal_ids: BTreeSet<String>,
    ) -> Result<Self, FounderSupportingMaterialConfigurationError> {
        if allowed_founder_principal_ids.is_empty()
            || allowed_founder_principal_ids
                .iter()
                .any(|principal| principal.trim().is_empty())
        {
            return Err(FounderSupportingMaterialConfigurationError::InvalidPolicy);
        }
        Ok(Self {
            task_authority,
            verification_source,
            artifact_authority,
            allowed_founder_principal_ids,
        })
    }
}

impl<G, C> FounderSupportingMaterialBindingSource
    for OwnerBoundFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn bind(
        &self,
        scope: &VerdictScope,
        authenticated_founder_principal_id: &str,
    ) -> Result<FounderSupportingMaterialBinding, FounderSupportingMaterialBindingError> {
        if !self
            .allowed_founder_principal_ids
            .contains(authenticated_founder_principal_id)
        {
            return Err(FounderSupportingMaterialBindingError::PermissionDenied);
        }
        let task = self
            .task_authority
            .lock()
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?;
        let owner = task
            .task_owner_principal_id(&scope.task_id)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            .ok_or(FounderSupportingMaterialBindingError::ScopeStale)?;
        if owner != authenticated_founder_principal_id {
            return Err(FounderSupportingMaterialBindingError::PermissionDenied);
        }
        let snapshot = match task
            .get_task(&scope.task_id)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            .outcome
        {
            Some(get_task_response::Outcome::Task(snapshot)) => snapshot,
            _ => return Err(FounderSupportingMaterialBindingError::ScopeStale),
        };
        drop(task);
        if snapshot.status != TaskStatus::VerdictPending as i32
            || snapshot.revision != scope.task_revision
            || snapshot.work_revision != scope.work_revision
            || snapshot.artifact_set_id.as_deref() != Some(scope.artifact_set_id.as_str())
            || snapshot.verification_artifact_id.as_deref()
                != Some(scope.verification_artifact_id.as_str())
            || snapshot.acceptance_contract_ref.as_ref() != scope.acceptance_contract_ref.as_ref()
        {
            return Err(FounderSupportingMaterialBindingError::ScopeStale);
        }

        let verification = self
            .verification_source
            .verification_artifact(&scope.verification_artifact_id)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            .ok_or(FounderSupportingMaterialBindingError::ScopeStale)?;
        let verification_binding = verification
            .binding
            .as_ref()
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        if verification.verification_artifact_id != scope.verification_artifact_id
            || verification.version != 1
            || verification.completed_at.is_none()
            || verification
                .provenance
                .as_ref()
                .is_none_or(|provenance| provenance.verifier_principal_id.trim().is_empty())
            || verification.canonical_payload.as_ref() != scope.verification_payload.as_ref()
            || verification.canonical_payload.as_ref()
                != Some(&canonical_verification_payload(&verification))
            || verification_binding.artifact_set_id != scope.artifact_set_id
            || verification_binding.artifact_set_manifest.as_ref()
                != scope.artifact_set_manifest.as_ref()
            || verification_binding.acceptance_contract_ref.as_ref()
                != scope.acceptance_contract_ref.as_ref()
            || verification_binding.claim_id.trim().is_empty()
            || verification_binding
                .claim_semantic_profile_ref
                .as_ref()
                .is_none_or(|reference| !contract_is_complete(reference))
        {
            return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
        }
        let expected_lineage = verification_binding
            .lineage
            .as_ref()
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        // Verification retains the ArtifactSet/run lineage from the Active
        // Task revision. The current Verdict scope is later because Task has
        // recorded evidence and the completed Verification artifact.
        if expected_lineage.task_id != scope.task_id
            || expected_lineage.task_revision > scope.task_revision
            || expected_lineage.work_revision != scope.work_revision
        {
            return Err(FounderSupportingMaterialBindingError::ScopeStale);
        }

        let authority = self
            .artifact_authority
            .lock()
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?;
        let set = authority
            .read_artifact_set(&scope.artifact_set_id)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            .ok_or(FounderSupportingMaterialBindingError::ScopeStale)?;
        if set.status != ArtifactSetStatus::Sealed as i32
            || set.lineage.as_ref() != Some(expected_lineage)
            || set.canonical_manifest.as_ref() != scope.artifact_set_manifest.as_ref()
            || set.sealed_at.is_none()
            || !unique_nonempty(&set.artifact_ids)
            || !unique_nonempty(&set.claim_ids)
            || !unique_nonempty(&set.evidence_ids)
            || !set.claim_ids.contains(&verification_binding.claim_id)
        {
            return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
        }
        let manifest = set
            .canonical_manifest
            .as_ref()
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        if authority
            .read_blob(manifest)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            != canonical_artifact_set_manifest(&set)
        {
            return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
        }
        let claim = authority
            .read_claim(&verification_binding.claim_id)
            .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        if claim.status != ClaimStatus::Proposed as i32
            || claim.lineage.as_ref() != Some(expected_lineage)
            || claim.semantic_profile_ref.as_ref()
                != verification_binding.claim_semantic_profile_ref.as_ref()
            || claim.acceptance_contract_ref.as_ref()
                != verification_binding.acceptance_contract_ref.as_ref()
            || claim.subject_artifact_ids.is_empty()
            || !unique_nonempty(&claim.subject_artifact_ids)
            || claim
                .subject_artifact_ids
                .iter()
                .any(|id| !set.artifact_ids.contains(id))
        {
            return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
        }
        let claim_statement = claim
            .statement
            .as_ref()
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        authority
            .read_blob(claim_statement)
            .map_err(|_| FounderSupportingMaterialBindingError::IntegrityFailure)?;
        let mut workspace_ref = None;
        let mut source_binding_ref = None;
        for artifact_id in &set.artifact_ids {
            let artifact = authority
                .read_artifact(artifact_id)
                .map_err(|_| FounderSupportingMaterialBindingError::Unavailable)?
                .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
            let provenance = artifact
                .provenance
                .as_ref()
                .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
            if artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
                || provenance.lineage.as_ref() != Some(expected_lineage)
                || provenance.workspace_ref.trim().is_empty()
                || workspace_ref
                    .as_ref()
                    .is_some_and(|workspace| workspace != &provenance.workspace_ref)
            {
                return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
            }
            authority
                .read_blob(
                    artifact
                        .content
                        .as_ref()
                        .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?,
                )
                .map_err(|_| FounderSupportingMaterialBindingError::IntegrityFailure)?;
            workspace_ref.get_or_insert_with(|| provenance.workspace_ref.clone());
            if artifact.semantic_class == ArtifactSemanticClass::RepositoryBaseline as i32 {
                if source_binding_ref.is_some() {
                    return Err(FounderSupportingMaterialBindingError::IntegrityFailure);
                }
                source_binding_ref = provenance.raw_source_ref.clone();
            }
        }
        let workspace_ref = workspace_ref
            .filter(|value| !value.trim().is_empty())
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        let source_binding_ref = source_binding_ref
            .filter(|value| !value.trim().is_empty())
            .ok_or(FounderSupportingMaterialBindingError::IntegrityFailure)?;
        Ok(FounderSupportingMaterialBinding {
            lineage: expected_lineage.clone(),
            workspace_ref,
            source_binding_ref,
            input_artifact_ids: set.artifact_ids,
        })
    }
}

#[derive(Clone, Debug)]
pub struct FounderSupportingMaterialPolicy {
    pub type_contract_ref: ContractReference,
    pub transformation_contract_ref: ContractReference,
    pub retention_profile_ref: ContractReference,
    pub collector_principal_id: String,
    pub artifact_authority_principal_id: String,
    pub component_name: String,
    pub component_version: String,
    pub sensitivity_class: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FounderSupportingMaterialConfigurationError {
    #[error("Founder supporting-material policy is incomplete")]
    InvalidPolicy,
}

impl FounderSupportingMaterialPolicy {
    pub fn validate(self) -> Result<Self, FounderSupportingMaterialConfigurationError> {
        if !contract_is_complete(&self.type_contract_ref)
            || !contract_is_complete(&self.transformation_contract_ref)
            || !contract_is_complete(&self.retention_profile_ref)
            || self.collector_principal_id.trim().is_empty()
            || self.artifact_authority_principal_id.trim().is_empty()
            || self.collector_principal_id == self.artifact_authority_principal_id
            || self.component_name.trim().is_empty()
            || self.component_version.trim().is_empty()
            || self.sensitivity_class.trim().is_empty()
        {
            return Err(FounderSupportingMaterialConfigurationError::InvalidPolicy);
        }
        Ok(self)
    }
}

/// Daemon-owned composition port. It exposes one governed business operation,
/// while retaining the existing Artifact Authority as the only writer.
pub(crate) struct GovernedFounderSupportingMaterialPort<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
    binding_source: Arc<dyn FounderSupportingMaterialBindingSource>,
    policy: FounderSupportingMaterialPolicy,
    admission: DerivedWorkspaceAdmissionHandle,
}

impl<G, C> GovernedFounderSupportingMaterialPort<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    pub(crate) fn new(
        authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        binding_source: Arc<dyn FounderSupportingMaterialBindingSource>,
        policy: FounderSupportingMaterialPolicy,
        admission: DerivedWorkspaceAdmissionHandle,
    ) -> Result<Self, FounderSupportingMaterialConfigurationError> {
        Ok(Self {
            authority,
            binding_source,
            policy: policy.validate()?,
            admission,
        })
    }
}

impl<G, C> FounderSupportingMaterialPort for GovernedFounderSupportingMaterialPort<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn create(
        &self,
        command: &CreateFounderSupportingMaterialCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<FounderSupportingMaterialReceipt>, CommandPortFailure> {
        validate_gateway_principal(principal)?;
        validate_material_command(command)?;
        let metadata = command
            .metadata
            .as_ref()
            .ok_or(CommandPortFailure::InvalidArgument)?;
        let expected_request_digest = canonical_material_request_digest(command)
            .ok_or(CommandPortFailure::InvalidArgument)?;
        if metadata.request_digest_sha256 != expected_request_digest {
            return Err(CommandPortFailure::InvalidArgument);
        }
        let scope = command
            .scope
            .as_ref()
            .ok_or(CommandPortFailure::InvalidArgument)?;
        let binding = self
            .binding_source
            .bind(scope, &principal.principal_id)
            .map_err(binding_error)?;
        validate_binding(&binding, scope)?;

        let payload = FounderSupportingMaterial {
            material_id: command.material_id.clone(),
            schema_version: MATERIAL_SCHEMA_VERSION,
            role: command.role,
            scope: Some(scope.clone()),
            lineage: Some(binding.lineage.clone()),
            authenticated_founder_principal_id: principal.principal_id.clone(),
            body: command.body.clone(),
            coverage: command.coverage.clone(),
        };
        let payload_bytes = payload.encode_to_vec();
        let payload_address = content_address(&payload_bytes);
        let stable_identity = framed_sha256("founder-supporting-material", &command.material_id);
        let artifact_id = founder_supporting_material_artifact_id(&command.material_id);
        let producer = ProducerIdentity {
            principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
            principal_id: self.policy.collector_principal_id.clone(),
            component_name: self.policy.component_name.clone(),
            component_version: self.policy.component_version.clone(),
            capability_profile_id: None,
            native_execution_ref: None,
        };
        let candidate = ArtifactDescriptor {
            artifact_id: artifact_id.clone(),
            revision: 0,
            status: ArtifactStatus::Unspecified as i32,
            semantic_class: ArtifactSemanticClass::TypedExtension as i32,
            type_contract_ref: Some(self.policy.type_contract_ref.clone()),
            media_type: MATERIAL_MEDIA_TYPE.to_owned(),
            content: Some(payload_address.clone()),
            integrity_status: IntegrityStatus::Unspecified as i32,
            provenance: Some(Provenance {
                lineage: Some(binding.lineage.clone()),
                producer: Some(producer),
                input_artifact_ids: binding.input_artifact_ids.clone(),
                transformation_contract_ref: Some(self.policy.transformation_contract_ref.clone()),
                workspace_ref: binding.workspace_ref.clone(),
                observed_at: None,
                captured_at: None,
                raw_source_ref: Some(binding.source_binding_ref.clone()),
            }),
            sensitivity_class: self.policy.sensitivity_class.clone(),
            retention_profile_ref: Some(self.policy.retention_profile_ref.clone()),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        };

        let collector = AuthenticatedArtifactPrincipal {
            kind: ArtifactPrincipalKind::GovernedCollector,
            principal_id: self.policy.collector_principal_id.clone(),
            authenticated: true,
        };
        let authority_principal = AuthenticatedArtifactPrincipal {
            kind: ArtifactPrincipalKind::ArtifactAuthority,
            principal_id: self.policy.artifact_authority_principal_id.clone(),
            authenticated: true,
        };
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| CommandPortFailure::Unavailable)?;
        let _lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: binding.workspace_ref.clone(),
                lineage: binding.lineage.clone(),
                source_binding_ref: binding.source_binding_ref.clone(),
            })
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        authority
            .put_blob(&payload_bytes, &payload_address)
            .map_err(|_| CommandPortFailure::Unavailable)?;
        let stage = execute_artifact_command(
            &mut authority,
            artifact_command(artifact_command::Command::StageArtifact(
                StageArtifactCommand {
                    metadata: Some(derived_metadata(metadata, &stable_identity, "stage")),
                    candidate: Some(candidate.clone()),
                },
            )),
            &collector,
        )?;
        let seal = execute_artifact_command(
            &mut authority,
            artifact_command(artifact_command::Command::SealArtifact(
                SealArtifactCommand {
                    metadata: Some(derived_metadata(metadata, &stable_identity, "seal")),
                    artifact_id: artifact_id.clone(),
                    expected_revision: 1,
                    observed_content: Some(payload_address.clone()),
                },
            )),
            &authority_principal,
        )?;
        let sealed = authority
            .read_artifact(&artifact_id)
            .map_err(|_| CommandPortFailure::Unavailable)?
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let sealed_bytes = authority
            .read_blob(
                sealed
                    .content
                    .as_ref()
                    .ok_or(CommandPortFailure::IntegrityFailure)?,
            )
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        if !sealed_material_matches(&sealed, &candidate) || sealed_bytes != payload_bytes {
            return Err(CommandPortFailure::IntegrityFailure);
        }

        Ok(CommandPortResult {
            result: FounderSupportingMaterialReceipt {
                committed: true,
                replayed: stage.replayed || seal.replayed,
                material_id: command.material_id.clone(),
                artifact_id,
                role: command.role,
                scope: Some(scope.clone()),
                canonical_payload: Some(payload_address),
                command_id: metadata.command_id.clone(),
                correlation_id: metadata.correlation_id.clone(),
            },
            source_revision: None,
            await_target: None,
        })
    }
}

#[must_use]
pub fn canonical_material_request_digest(
    command: &CreateFounderSupportingMaterialCommand,
) -> Option<String> {
    let mut canonical = command.clone();
    canonical.metadata.as_mut()?.request_digest_sha256.clear();
    Some(hex::encode(Sha256::digest(canonical.encode_to_vec())))
}

#[must_use]
pub fn founder_supporting_material_artifact_id(material_id: &str) -> String {
    format!(
        "founder-material-{}",
        framed_sha256("founder-supporting-material", material_id)
    )
}

/// Read-only adapter over the existing shared Artifact Authority handle. It
/// returns verified bytes and never exposes the blob store or a second writer.
pub struct ArtifactAuthorityFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
}

impl<G, C> ArtifactAuthorityFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    #[must_use]
    pub fn new(authority: Arc<Mutex<ArtifactAuthority<G, C>>>) -> Self {
        Self { authority }
    }
}

impl<G, C> crate::verdict::FounderSupportingMaterialSource
    for ArtifactAuthorityFounderSupportingMaterialSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn material(
        &self,
        artifact_id: &str,
        scope: &VerdictScope,
    ) -> Result<
        Option<crate::verdict::FounderSupportingMaterialEvidence>,
        crate::verdict::FounderSupportingMaterialEvidenceError,
    > {
        let authority = self
            .authority
            .lock()
            .map_err(|_| crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable)?;
        let Some(descriptor) = authority
            .read_artifact(artifact_id)
            .map_err(|_| crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable)?
        else {
            return Ok(None);
        };
        let content = descriptor
            .content
            .as_ref()
            .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
        let payload = authority.read_blob(content).map_err(|_| {
            crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure
        })?;
        let set = authority
            .read_artifact_set(&scope.artifact_set_id)
            .map_err(|_| crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable)?
            .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
        if set.status != ArtifactSetStatus::Sealed as i32
            || set.canonical_manifest.as_ref() != scope.artifact_set_manifest.as_ref()
            || set.lineage.as_ref().is_none_or(|lineage| {
                lineage.task_id != scope.task_id
                    || lineage.task_revision > scope.task_revision
                    || lineage.work_revision != scope.work_revision
            })
            || !unique_nonempty(&set.artifact_ids)
        {
            return Err(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure);
        }
        let manifest = set
            .canonical_manifest
            .as_ref()
            .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
        if authority
            .read_blob(manifest)
            .map_err(|_| crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable)?
            != canonical_artifact_set_manifest(&set)
        {
            return Err(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure);
        }
        let expected_lineage = set
            .lineage
            .as_ref()
            .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
        let mut workspace_ref = None;
        let mut source_binding_ref = None;
        for input_artifact_id in &set.artifact_ids {
            let input = authority
                .read_artifact(input_artifact_id)
                .map_err(|_| crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable)?
                .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
            let provenance = input
                .provenance
                .as_ref()
                .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?;
            if input.status != ArtifactStatus::Sealed as i32
                || input.integrity_status != IntegrityStatus::DigestVerified as i32
                || provenance.lineage.as_ref() != Some(expected_lineage)
                || provenance.workspace_ref.trim().is_empty()
                || workspace_ref
                    .as_ref()
                    .is_some_and(|workspace| workspace != &provenance.workspace_ref)
            {
                return Err(
                    crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure,
                );
            }
            authority
                .read_blob(input.content.as_ref().ok_or(
                    crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure,
                )?)
                .map_err(|_| {
                    crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure
                })?;
            workspace_ref.get_or_insert_with(|| provenance.workspace_ref.clone());
            if input.semantic_class == ArtifactSemanticClass::RepositoryBaseline as i32 {
                if source_binding_ref.is_some() {
                    return Err(
                        crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure,
                    );
                }
                source_binding_ref = provenance.raw_source_ref.clone();
            }
        }
        Ok(Some(crate::verdict::FounderSupportingMaterialEvidence {
            descriptor,
            payload,
            bound_workspace_ref: workspace_ref
                .filter(|value| !value.trim().is_empty())
                .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?,
            bound_source_binding_ref: source_binding_ref
                .filter(|value| !value.trim().is_empty())
                .ok_or(crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure)?,
            bound_input_artifact_ids: set.artifact_ids,
        }))
    }
}

fn validate_gateway_principal(principal: &CommandPrincipal) -> Result<(), CommandPortFailure> {
    if principal.principal_id.trim().is_empty()
        || principal.required_authority_principal_kinds.as_slice() != [FOUNDER_AUTHORITY_KIND]
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(())
}

fn validate_material_command(
    command: &CreateFounderSupportingMaterialCommand,
) -> Result<(), CommandPortFailure> {
    let metadata = command
        .metadata
        .as_ref()
        .ok_or(CommandPortFailure::InvalidArgument)?;
    if !bounded(&command.material_id)
        || command.body.trim().is_empty()
        || command.body.len() > MAX_MATERIAL_BODY_BYTES
        || !metadata_complete(metadata)
        || !scope_complete(command.scope.as_ref())
    {
        return Err(CommandPortFailure::InvalidArgument);
    }
    let role = FounderSupportingMaterialRole::try_from(command.role)
        .map_err(|_| CommandPortFailure::InvalidArgument)?;
    let coverage = command
        .coverage
        .as_ref()
        .ok_or(CommandPortFailure::InvalidArgument)?;
    validate_ids(&coverage.discrepancy_ids)?;
    validate_ids(&coverage.unverified_item_ids)?;
    let risk = RiskCategory::try_from(coverage.risk_category)
        .map_err(|_| CommandPortFailure::InvalidArgument)?;
    match role {
        FounderSupportingMaterialRole::ReworkRequiredChanges
            if risk == RiskCategory::Unspecified => {}
        FounderSupportingMaterialRole::RiskRationale
        | FounderSupportingMaterialRole::CompensatingControl
            if risk != RiskCategory::Unspecified
                && (!coverage.discrepancy_ids.is_empty()
                    || !coverage.unverified_item_ids.is_empty()) => {}
        _ => return Err(CommandPortFailure::InvalidArgument),
    }
    Ok(())
}

fn validate_binding(
    binding: &FounderSupportingMaterialBinding,
    scope: &VerdictScope,
) -> Result<(), CommandPortFailure> {
    let lineage = &binding.lineage;
    if lineage.task_id != scope.task_id
        || lineage.task_revision > scope.task_revision
        || lineage.work_revision != scope.work_revision
        || lineage.run_id.trim().is_empty()
        || lineage.run_revision == 0
        || lineage.step_id.trim().is_empty()
        || lineage.step_revision == 0
        || lineage.attempt_id.trim().is_empty()
        || lineage.attempt_revision == 0
        || lineage.dispatch_id.trim().is_empty()
        || lineage.fencing_token == 0
        || binding.workspace_ref.trim().is_empty()
        || binding.input_artifact_ids.is_empty()
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    validate_ids(&binding.input_artifact_ids).map_err(|_| CommandPortFailure::IntegrityFailure)
}

fn derived_metadata(
    source: &CommandMetadata,
    stable_identity: &str,
    operation: &str,
) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("founder-material:{stable_identity}:{operation}"),
        idempotency_key: format!("{stable_identity}:{operation}"),
        idempotency_scope: "founder-supporting-material/v1".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: source.issued_at,
        correlation_id: source.correlation_id.clone(),
        causation_id: Some(source.command_id.clone()),
    }
}

fn artifact_command(command: artifact_command::Command) -> ArtifactCommand {
    let mut value = ArtifactCommand {
        command: Some(command),
    };
    let digest = artifact_request_digest(&value).expect("Artifact command variant is present");
    match value.command.as_mut().expect("Artifact command variant") {
        artifact_command::Command::StageArtifact(command) => {
            command
                .metadata
                .as_mut()
                .expect("derived stage metadata")
                .request_digest_sha256 = digest;
        }
        artifact_command::Command::SealArtifact(command) => {
            command
                .metadata
                .as_mut()
                .expect("derived seal metadata")
                .request_digest_sha256 = digest;
        }
        _ => unreachable!("supporting material emits only stage and seal"),
    }
    value
}

fn execute_artifact_command<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    command: ArtifactCommand,
    principal: &AuthenticatedArtifactPrincipal,
) -> Result<
    egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactCommandResult,
    CommandPortFailure,
>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let result = authority
        .execute(&command, principal)
        .map_err(|_| CommandPortFailure::Unavailable)?;
    if result.committed {
        return Ok(result);
    }
    match ArtifactErrorCode::try_from(result.error_code).unwrap_or(ArtifactErrorCode::Unspecified) {
        ArtifactErrorCode::InvalidArgument
        | ArtifactErrorCode::IdempotencyConflict
        | ArtifactErrorCode::RevisionConflict
        | ArtifactErrorCode::DigestMismatch
        | ArtifactErrorCode::LengthMismatch
        | ArtifactErrorCode::SchemaInvalid
        | ArtifactErrorCode::LineageMismatch
        | ArtifactErrorCode::ScopeViolation
        | ArtifactErrorCode::IndependenceViolation
        | ArtifactErrorCode::Quarantined
        | ArtifactErrorCode::IntegrityFailure
        | ArtifactErrorCode::SecretDetected
        | ArtifactErrorCode::RetentionConflict
        | ArtifactErrorCode::MemberNotSealed
        | ArtifactErrorCode::PermissionDenied
        | ArtifactErrorCode::Unauthenticated
        | ArtifactErrorCode::NotFound
        | ArtifactErrorCode::Unspecified => Err(CommandPortFailure::IntegrityFailure),
    }
}

fn sealed_material_matches(sealed: &ArtifactDescriptor, candidate: &ArtifactDescriptor) -> bool {
    sealed.artifact_id == candidate.artifact_id
        && sealed.revision == 2
        && sealed.status == ArtifactStatus::Sealed as i32
        && sealed.integrity_status == IntegrityStatus::DigestVerified as i32
        && sealed.semantic_class == ArtifactSemanticClass::TypedExtension as i32
        && sealed.type_contract_ref == candidate.type_contract_ref
        && sealed.media_type == candidate.media_type
        && sealed.content == candidate.content
        && sealed.provenance == candidate.provenance
        && sealed.sensitivity_class == candidate.sensitivity_class
        && sealed.retention_profile_ref == candidate.retention_profile_ref
        && sealed.sealed_at.is_some()
        && sealed.quarantine_reason_code.is_none()
}

fn binding_error(error: FounderSupportingMaterialBindingError) -> CommandPortFailure {
    match error {
        FounderSupportingMaterialBindingError::PermissionDenied
        | FounderSupportingMaterialBindingError::ScopeStale
        | FounderSupportingMaterialBindingError::IntegrityFailure => {
            CommandPortFailure::IntegrityFailure
        }
        FounderSupportingMaterialBindingError::Unavailable => CommandPortFailure::Unavailable,
    }
}

fn validate_ids(values: &[String]) -> Result<(), CommandPortFailure> {
    let mut unique = BTreeSet::new();
    if values
        .iter()
        .any(|value| !bounded(value) || !unique.insert(value.as_str()))
    {
        return Err(CommandPortFailure::InvalidArgument);
    }
    Ok(())
}

fn unique_nonempty(values: &[String]) -> bool {
    let mut unique = BTreeSet::new();
    !values.is_empty()
        && values
            .iter()
            .all(|value| !value.trim().is_empty() && unique.insert(value))
}

fn metadata_complete(metadata: &CommandMetadata) -> bool {
    bounded(&metadata.command_id)
        && bounded(&metadata.idempotency_key)
        && bounded(&metadata.idempotency_scope)
        && bounded(&metadata.correlation_id)
        && metadata.issued_at.is_some()
        && metadata.request_digest_sha256.len() == 64
        && metadata
            .request_digest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn scope_complete(scope: Option<&VerdictScope>) -> bool {
    scope.is_some_and(|scope| {
        bounded(&scope.task_id)
            && scope.task_revision > 0
            && scope.work_revision > 0
            && bounded(&scope.artifact_set_id)
            && content_address_complete(scope.artifact_set_manifest.as_ref())
            && bounded(&scope.verification_artifact_id)
            && content_address_complete(scope.verification_payload.as_ref())
            && scope
                .acceptance_contract_ref
                .as_ref()
                .is_some_and(contract_is_complete)
    })
}

fn content_address_complete(
    address: Option<&egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress>,
) -> bool {
    address.is_some_and(|address| {
        address.algorithm == HashAlgorithm::Sha256 as i32
            && address.digest.len() == 64
            && address
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && address.byte_length > 0
    })
}

fn contract_is_complete(reference: &ContractReference) -> bool {
    bounded(&reference.contract_id)
        && bounded(&reference.version)
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
}

fn framed_sha256(domain: &str, value: &str) -> String {
    let mut framed = Vec::with_capacity(domain.len() + value.len() + 16);
    framed.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    framed.extend_from_slice(domain.as_bytes());
    framed.extend_from_slice(&(value.len() as u64).to_be_bytes());
    framed.extend_from_slice(value.as_bytes());
    hex::encode(Sha256::digest(framed))
}
