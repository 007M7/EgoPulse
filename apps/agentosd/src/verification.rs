use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, PendingTaskVerification, PrincipalKind as TaskPrincipalKind,
    TaskAuthority, TaskAuthorityFailure, canonical_request_digest as task_canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ArtifactSet, ArtifactSetStatus, ClaimStatus, ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        RecordTaskVerificationCommand, TaskCommand, TaskEventKind, TaskSnapshot, TaskStatus,
        get_task_response, task_command,
    },
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
        CreateVerificationRequestCommand, VerificationBinding, VerificationCommand,
        VerificationRequest, VerificationStatus, verification_command,
    },
};
use egopulse_verification_authority::{
    ArtifactReferenceSource, ArtifactReferenceSourceError, AuthenticatedVerificationPrincipal,
    CheckerOutputSink, CheckerOutputSource, GovernedCheckerSupervisor, GovernedSegoRunner,
    GovernedVerificationBatchPlan, GovernedVerificationChecker,
    GovernedVerificationExecutionCoordinator, GovernedVerificationExecutionError,
    GovernedVerificationExecutionPlan, SegoMapperPolicy, SystemVerificationClock,
    VerificationAuthority, VerificationAuthorityFailure, VerificationClock,
    VerificationPrincipalKind, canonical_request_digest,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::{future::Future, path::PathBuf, pin::Pin, time::Duration};
use thiserror::Error;

const TASK_ACCEPTANCE: &str = "task_acceptance";
const HANDOFF_IDEMPOTENCY_SCOPE: &str = "task-verification-handoff-v1";
const PROFILE_ATTESTATION_SCOPE: &str = "system-checker-profile-attestation-v1";
const SYSTEM_VERIFICATION_PRINCIPAL: &str = "verification-bootstrap:local";
const TASK_VERIFICATION_WRITEBACK_SCOPE: &str = "system-task-verification-writeback-v1";
const SYSTEM_TASK_VERIFICATION_PRINCIPAL: &str = "verification-worker:local";

/// The parts of Artifact/Verification binding that cannot be inferred from a
/// Task handoff. They are reviewed configuration, not Agent output.
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationBindingTemplate {
    pub claim_id: String,
    pub claim_semantic_profile_ref: ContractReference,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffPlan {
    pub binding: VerificationBindingTemplate,
    pub criterion_ids: Vec<String>,
    pub checker_profile_refs: Vec<ContractReference>,
}

/// Reviewed Verification policy whose primary Claim identity is resolved from
/// the current Artifact Set at handoff consumption time.
#[derive(Clone, Debug, PartialEq)]
pub struct DynamicPrimaryClaimHandoffPlan {
    pub claim_semantic_profile_ref: ContractReference,
    pub criterion_ids: Vec<String>,
    pub checker_profile_refs: Vec<ContractReference>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffRequest {
    pub verification_request_id: String,
    pub request: VerificationRequest,
    pub message_id: String,
    pub payload_digest_sha256: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CheckerProfileAttestationResult {
    pub checker_profile_id: String,
    pub committed: bool,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum CheckerProfileAttestationError {
    #[error("checker profile ID is empty")]
    InvalidProfileId,
    #[error("checker profile attestation command could not be canonicalized")]
    Canonicalization,
    #[error("Verification Authority lock is poisoned")]
    VerificationLock,
    #[error("Verification Authority command failed: {0}")]
    Verification(#[from] VerificationAuthorityFailure),
    #[error("checker profile attestation was rejected: {0}")]
    Rejected(String),
}

/// System-only application entry point for checker profile attestation.
///
/// The caller supplies a reviewed profile candidate, but never supplies the
/// authority principal. Verification Authority remains responsible for
/// validating profile structure, canonical digest and Artifact-backed
/// attestation evidence before activating it.
pub struct SystemCheckerProfileAttestation {
    verification: Arc<Mutex<VerificationAuthority>>,
}

impl SystemCheckerProfileAttestation {
    #[must_use]
    pub fn new(verification: Arc<Mutex<VerificationAuthority>>) -> Self {
        Self { verification }
    }

    pub fn attest_one(
        &self,
        profile: CheckerProfile,
        issued_at: Timestamp,
    ) -> Result<CheckerProfileAttestationResult, CheckerProfileAttestationError> {
        if profile.checker_profile_id.trim().is_empty() {
            return Err(CheckerProfileAttestationError::InvalidProfileId);
        }
        let checker_profile_id = profile.checker_profile_id.clone();
        if let Some(existing) = self
            .verification
            .lock()
            .map_err(|_| CheckerProfileAttestationError::VerificationLock)?
            .checker_profile(&checker_profile_id)?
        {
            if existing.profile_digest_sha256 == profile.profile_digest_sha256
                && existing.status == CheckerProfileStatus::Active as i32
            {
                return Ok(CheckerProfileAttestationResult {
                    checker_profile_id,
                    committed: false,
                    replayed: true,
                });
            }
            return Err(CheckerProfileAttestationError::Rejected(
                "CHECKER_PROFILE_DIGEST_CONFLICT".to_owned(),
            ));
        }
        let command = checker_profile_attestation_command(profile, issued_at)?;
        let result = self
            .verification
            .lock()
            .map_err(|_| CheckerProfileAttestationError::VerificationLock)?
            .execute(
                &command,
                &AuthenticatedVerificationPrincipal {
                    kind: VerificationPrincipalKind::VerificationAuthority,
                    principal_id: SYSTEM_VERIFICATION_PRINCIPAL.to_owned(),
                    authenticated: true,
                    checker_profile_id: None,
                },
            )?;
        if !result.committed && !result.replayed {
            return Err(CheckerProfileAttestationError::Rejected(
                result
                    .safe_error_fingerprint
                    .unwrap_or_else(|| "CHECKER_PROFILE_ATTESTATION_REJECTED".to_owned()),
            ));
        }
        Ok(CheckerProfileAttestationResult {
            checker_profile_id,
            committed: result.committed,
            replayed: result.replayed,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskVerificationWriteBackResult {
    pub task_id: String,
    pub verification_artifact_id: String,
    pub committed: bool,
    pub replayed: bool,
    pub task_revision: u64,
}

#[derive(Debug, Error)]
pub enum TaskVerificationWriteBackError {
    #[error("Task ID or Verification artifact ID is empty")]
    InvalidIdentity,
    #[error("Task revision or work revision is invalid")]
    InvalidRevision,
    #[error("Task Authority lock is poisoned")]
    TaskLock,
    #[error("Verification Authority lock is poisoned")]
    VerificationLock,
    #[error("Task Authority read failed: {0}")]
    Task(#[from] TaskAuthorityFailure),
    #[error("Verification Authority read failed: {0}")]
    Verification(#[from] VerificationAuthorityFailure),
    #[error("completed Verification artifact was not found")]
    ArtifactNotFound,
    #[error("Verification artifact does not bind the expected Task revision")]
    ArtifactBindingMismatch,
    #[error("Task is not the expected VerificationPending snapshot")]
    TaskSnapshotMismatch,
    #[error("Task verification write-back command could not be canonicalized")]
    Canonicalization,
    #[error("Task verification write-back was rejected: {0}")]
    Rejected(String),
}

/// System-only write-back boundary. It proves the completed artifact belongs
/// to the exact pending Task snapshot before submitting the sole Task mutation
/// through Task Authority. No client or checker principal can be injected.
pub struct SystemTaskVerificationWriteBack {
    task: Arc<Mutex<TaskAuthority>>,
    verification: Arc<Mutex<VerificationAuthority>>,
}

impl SystemTaskVerificationWriteBack {
    #[must_use]
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        verification: Arc<Mutex<VerificationAuthority>>,
    ) -> Self {
        Self { task, verification }
    }

    fn needs_processing(
        &self,
        request: &VerificationRequest,
        artifact_id: &str,
    ) -> Result<bool, TaskVerificationWriteBackError> {
        let lineage = request
            .binding
            .as_ref()
            .and_then(|binding| binding.lineage.as_ref())
            .ok_or(TaskVerificationWriteBackError::ArtifactBindingMismatch)?;
        let task = self
            .task
            .lock()
            .map_err(|_| TaskVerificationWriteBackError::TaskLock)?;
        let snapshot = match task.get_task(&lineage.task_id)?.outcome {
            Some(get_task_response::Outcome::Task(snapshot)) => snapshot,
            _ => return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch),
        };
        request_needs_processing(request, &snapshot, artifact_id)
    }

    pub fn record_one(
        &self,
        task_id: &str,
        expected_revision: u64,
        work_revision: u64,
        verification_artifact_id: &str,
        issued_at: Timestamp,
    ) -> Result<TaskVerificationWriteBackResult, TaskVerificationWriteBackError> {
        if task_id.trim().is_empty() || verification_artifact_id.trim().is_empty() {
            return Err(TaskVerificationWriteBackError::InvalidIdentity);
        }
        if expected_revision == 0 || work_revision == 0 {
            return Err(TaskVerificationWriteBackError::InvalidRevision);
        }
        {
            let verification = self
                .verification
                .lock()
                .map_err(|_| TaskVerificationWriteBackError::VerificationLock)?;
            let artifact = verification
                .verification_artifact(verification_artifact_id)?
                .ok_or(TaskVerificationWriteBackError::ArtifactNotFound)?;
            let lineage = artifact
                .binding
                .as_ref()
                .and_then(|binding| binding.lineage.as_ref())
                .ok_or(TaskVerificationWriteBackError::ArtifactBindingMismatch)?;
            if lineage.task_id != task_id
                || lineage.task_revision.checked_add(1) != Some(expected_revision)
                || lineage.work_revision != work_revision
            {
                return Err(TaskVerificationWriteBackError::ArtifactBindingMismatch);
            }
        }
        let task_snapshot = {
            let task = self
                .task
                .lock()
                .map_err(|_| TaskVerificationWriteBackError::TaskLock)?;
            match task.get_task(task_id)?.outcome {
                Some(get_task_response::Outcome::Task(snapshot)) => snapshot,
                _ => return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch),
            }
        };
        if task_snapshot.task_id != task_id || task_snapshot.work_revision != work_revision {
            return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch);
        }
        if task_snapshot.status != TaskStatus::VerificationPending as i32 {
            if task_snapshot.revision > expected_revision
                && task_snapshot.verification_artifact_id.as_deref()
                    == Some(verification_artifact_id)
            {
                return Ok(TaskVerificationWriteBackResult {
                    task_id: task_id.to_owned(),
                    verification_artifact_id: verification_artifact_id.to_owned(),
                    committed: false,
                    replayed: true,
                    task_revision: task_snapshot.revision,
                });
            }
            return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch);
        }
        if task_snapshot.revision != expected_revision {
            return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch);
        }
        let idempotency_key = format!("{task_id}:{verification_artifact_id}:{expected_revision}");
        let mut command = TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    meta: Some(CommandMetadata {
                        command_id: format!("task-verification-writeback-{idempotency_key}"),
                        idempotency_key,
                        idempotency_scope: TASK_VERIFICATION_WRITEBACK_SCOPE.to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(issued_at),
                        correlation_id: verification_artifact_id.to_owned(),
                        causation_id: None,
                    }),
                    task_id: task_id.to_owned(),
                    expected_revision,
                    work_revision,
                    verification_artifact_id: verification_artifact_id.to_owned(),
                },
            )),
        };
        let digest = task_canonical_request_digest(&command)?;
        if let Some(task_command::Command::RecordTaskVerification(value)) = command.command.as_mut()
        {
            value
                .meta
                .as_mut()
                .expect("write-back metadata")
                .request_digest_sha256 = digest;
        } else {
            return Err(TaskVerificationWriteBackError::Canonicalization);
        }
        let result = self
            .task
            .lock()
            .map_err(|_| TaskVerificationWriteBackError::TaskLock)?
            .execute(
                &command,
                &AuthenticatedPrincipal {
                    kind: TaskPrincipalKind::SegoVerification,
                    principal_id: SYSTEM_TASK_VERIFICATION_PRINCIPAL.to_owned(),
                    authenticated: true,
                },
            )?;
        if let Some(error) = result.outcome.as_ref().and_then(|outcome| {
            match outcome {
            egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Error(
                error,
            ) => Some(error.safe_detail_code.clone()),
            _ => None,
        }
        }) {
            return Err(TaskVerificationWriteBackError::Rejected(error));
        }
        let task_revision = result
            .committed_event
            .as_ref()
            .map(|event| event.resulting_revision)
            .unwrap_or(expected_revision + 1);
        Ok(TaskVerificationWriteBackResult {
            task_id: task_id.to_owned(),
            verification_artifact_id: verification_artifact_id.to_owned(),
            committed: result.committed_event.is_some(),
            replayed: result.replayed,
            task_revision,
        })
    }
}

fn checker_profile_attestation_command(
    profile: CheckerProfile,
    issued_at: Timestamp,
) -> Result<VerificationCommand, CheckerProfileAttestationError> {
    let idempotency_key = format!(
        "{}:{}",
        profile.checker_profile_id, profile.profile_digest_sha256
    );
    let command_id = format!(
        "checker-profile-attestation-{}",
        hex::encode(Sha256::digest(idempotency_key.as_bytes()))
    );
    let mut command = VerificationCommand {
        command: Some(verification_command::Command::AttestCheckerProfile(
            AttestCheckerProfileCommand {
                metadata: Some(CommandMetadata {
                    command_id,
                    idempotency_key,
                    idempotency_scope: PROFILE_ATTESTATION_SCOPE.to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: Some(issued_at),
                    correlation_id: profile.checker_profile_id.clone(),
                    causation_id: None,
                }),
                profile: Some(profile),
            },
        )),
    };
    let digest = canonical_request_digest(&command)
        .ok_or(CheckerProfileAttestationError::Canonicalization)?;
    if let Some(verification_command::Command::AttestCheckerProfile(value)) =
        command.command.as_mut()
    {
        value
            .metadata
            .as_mut()
            .expect("attestation metadata was constructed")
            .request_digest_sha256 = digest;
    }
    Ok(command)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationHandoffPlanError {
    #[error("verification handoff plan is invalid")]
    Invalid,
    #[error("Task handoff is not VerificationPending")]
    TaskNotVerificationPending,
    #[error("Task handoff acceptance contract is missing")]
    AcceptanceContractMissing,
    #[error("Artifact set is missing, unsealed, or does not belong to the handoff")]
    ArtifactSetInvalid,
    #[error("handoff belongs to another reviewed worker plan")]
    NotOurWork,
    #[error("Artifact set primary Claim is missing, ambiguous, or invalid")]
    PrimaryClaimInvalid,
    #[error("Task handoff and configured lineage do not match")]
    LineageMismatch,
}

impl VerificationHandoffPlan {
    pub fn validate(&self) -> Result<(), VerificationHandoffPlanError> {
        let binding = &self.binding;
        if binding.claim_id.trim().is_empty()
            || !contract_reference_valid(&binding.claim_semantic_profile_ref)
            || self.criterion_ids.is_empty()
            || !unique_nonempty(&self.criterion_ids)
            || self.checker_profile_refs.is_empty()
            || !self
                .checker_profile_refs
                .iter()
                .all(contract_reference_valid)
            || !unique_contract_references(&self.checker_profile_refs)
        {
            return Err(VerificationHandoffPlanError::Invalid);
        }
        Ok(())
    }

    pub fn request_for(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
    ) -> Result<VerificationHandoffRequest, VerificationHandoffPlanError> {
        self.validate()?;
        let snapshot = handoff
            .event
            .snapshot
            .as_ref()
            .ok_or(VerificationHandoffPlanError::LineageMismatch)?;
        if snapshot.status != TaskStatus::VerificationPending as i32
            || handoff.event.kind != TaskEventKind::EvidenceSubmitted as i32
            || snapshot.task_id != handoff.event.task_id
            || snapshot.revision != handoff.event.resulting_revision
            || snapshot.work_revision != handoff.event.work_revision
        {
            return Err(VerificationHandoffPlanError::TaskNotVerificationPending);
        }
        let acceptance_contract_ref = snapshot
            .acceptance_contract_ref
            .clone()
            .ok_or(VerificationHandoffPlanError::AcceptanceContractMissing)?;
        if !contract_reference_valid(&acceptance_contract_ref) {
            return Err(VerificationHandoffPlanError::AcceptanceContractMissing);
        }
        let artifact_set_id = snapshot
            .artifact_set_id
            .as_deref()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if artifact_set.status != ArtifactSetStatus::Sealed as i32
            || artifact_set.artifact_set_id != artifact_set_id
        {
            return Err(VerificationHandoffPlanError::ArtifactSetInvalid);
        }
        let lineage = artifact_set
            .lineage
            .clone()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if !lineage_valid(&lineage)
            || lineage.task_id != snapshot.task_id
            // The Artifact Set is produced while the run is active. The
            // Task evidence handoff is the next Task revision, so the
            // handoff snapshot must be exactly one revision newer than the
            // execution lineage. Requiring equality would reject every
            // real runner-produced return.
            || lineage.task_revision.checked_add(1) != Some(snapshot.revision)
            || lineage.work_revision != snapshot.work_revision
        {
            return Err(VerificationHandoffPlanError::LineageMismatch);
        }
        let artifact_set_manifest = artifact_set
            .canonical_manifest
            .clone()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if !content_address_valid(&artifact_set_manifest) {
            return Err(VerificationHandoffPlanError::ArtifactSetInvalid);
        }
        if !artifact_set
            .claim_ids
            .iter()
            .any(|id| id == &self.binding.claim_id)
        {
            return Err(VerificationHandoffPlanError::NotOurWork);
        }
        let binding = VerificationBinding {
            lineage: Some(lineage),
            artifact_set_id: artifact_set_id.to_owned(),
            artifact_set_manifest: Some(artifact_set_manifest),
            claim_id: self.binding.claim_id.clone(),
            claim_semantic_profile_ref: Some(self.binding.claim_semantic_profile_ref.clone()),
            acceptance_contract_ref: Some(acceptance_contract_ref),
        };
        let verification_request_id =
            deterministic_request_id(&snapshot.task_id, snapshot.revision, snapshot.work_revision);
        let request = VerificationRequest {
            verification_request_id: verification_request_id.clone(),
            revision: 0,
            status: 0,
            verification_type: TASK_ACCEPTANCE.to_owned(),
            binding: Some(binding),
            criterion_ids: self.criterion_ids.clone(),
            checker_profile_refs: self.checker_profile_refs.clone(),
            created_at: None,
            hold_reason_code: None,
        };
        Ok(VerificationHandoffRequest {
            verification_request_id,
            request,
            message_id: handoff.message_id.clone(),
            payload_digest_sha256: handoff.payload_digest_sha256.clone(),
        })
    }

    pub fn create_command(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        issued_at: Timestamp,
    ) -> Result<VerificationCommand, VerificationHandoffPlanError> {
        let prepared = self.request_for(handoff, artifact_set)?;
        let mut metadata = CommandMetadata {
            command_id: format!("verification-handoff-{}", prepared.message_id),
            idempotency_key: prepared.message_id.clone(),
            idempotency_scope: HANDOFF_IDEMPOTENCY_SCOPE.to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(issued_at),
            correlation_id: prepared.message_id.clone(),
            causation_id: None,
        };
        let mut command = VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata.clone()),
                    request: Some(prepared.request),
                },
            )),
        };
        metadata.request_digest_sha256 =
            canonical_request_digest(&command).ok_or(VerificationHandoffPlanError::Invalid)?;
        if let Some(verification_command::Command::CreateVerificationRequest(value)) =
            command.command.as_mut()
        {
            value.metadata = Some(metadata);
        }
        Ok(command)
    }
}

impl DynamicPrimaryClaimHandoffPlan {
    pub fn validate(&self) -> Result<(), VerificationHandoffPlanError> {
        if !contract_reference_valid(&self.claim_semantic_profile_ref)
            || !unique_nonempty(&self.criterion_ids)
            || self.checker_profile_refs.is_empty()
            || !self
                .checker_profile_refs
                .iter()
                .all(contract_reference_valid)
            || !unique_contract_references(&self.checker_profile_refs)
        {
            return Err(VerificationHandoffPlanError::Invalid);
        }
        Ok(())
    }

    /// Resolves the sole current Artifact Set Claim and converts this dynamic
    /// policy into the existing explicit binding plan. The Claim ID always
    /// comes from Artifact Authority; configuration cannot substitute one.
    pub fn resolve(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        artifact: &dyn ArtifactReferenceSource,
    ) -> Result<VerificationHandoffPlan, VerificationHandoffIntakeError> {
        self.validate()?;
        let [claim_id] = artifact_set.claim_ids.as_slice() else {
            return Err(VerificationHandoffPlanError::PrimaryClaimInvalid.into());
        };
        if claim_id.trim().is_empty() || !unique_nonempty(&artifact_set.artifact_ids) {
            return Err(VerificationHandoffPlanError::PrimaryClaimInvalid.into());
        }

        let resolved = VerificationHandoffPlan {
            binding: VerificationBindingTemplate {
                claim_id: claim_id.clone(),
                claim_semantic_profile_ref: self.claim_semantic_profile_ref.clone(),
            },
            criterion_ids: self.criterion_ids.clone(),
            checker_profile_refs: self.checker_profile_refs.clone(),
        };
        let prepared = resolved.request_for(handoff, artifact_set)?;
        let binding = prepared
            .request
            .binding
            .as_ref()
            .ok_or(VerificationHandoffPlanError::PrimaryClaimInvalid)?;
        let claim = artifact
            .read_claim(claim_id)?
            .ok_or(VerificationHandoffPlanError::PrimaryClaimInvalid)?;
        if claim.claim_id.as_str() != claim_id.as_str()
            || claim.status != ClaimStatus::Proposed as i32
            || claim.semantic_profile_ref.as_ref() != Some(&self.claim_semantic_profile_ref)
            || claim.acceptance_contract_ref.as_ref() != binding.acceptance_contract_ref.as_ref()
            || claim.lineage.as_ref() != artifact_set.lineage.as_ref()
            || !unique_nonempty(&claim.subject_artifact_ids)
            || claim
                .subject_artifact_ids
                .iter()
                .any(|id| !artifact_set.artifact_ids.contains(id))
        {
            return Err(VerificationHandoffPlanError::PrimaryClaimInvalid.into());
        }
        Ok(resolved)
    }
}

#[derive(Debug, Error)]
pub enum VerificationHandoffIntakeError {
    #[error("Task handoff preparation is blocked: {0}")]
    PreparationBlocked(&'static str),
    #[error("Task Authority handoff read failed: {0}")]
    Task(#[from] TaskAuthorityFailure),
    #[error("Verification Authority command failed: {0}")]
    Verification(#[from] VerificationAuthorityFailure),
    #[error("Verification handoff plan failed: {0}")]
    Plan(#[from] VerificationHandoffPlanError),
    #[error("Artifact Authority read failed: {0}")]
    Artifact(#[from] ArtifactReferenceSourceError),
    #[error("Task Authority lock is poisoned")]
    TaskLock,
    #[error("Verification Authority lock is poisoned")]
    VerificationLock,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffConsumeResult {
    pub message_id: String,
    pub payload_digest_sha256: String,
    pub verification_request_id: String,
    pub committed: bool,
    pub replayed: bool,
    pub task_outbox_acknowledged: bool,
    pub error_code: i32,
    pub safe_error_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerificationHandoffBlockage {
    pub(crate) task_id: String,
    pub(crate) message_id: String,
    pub(crate) reason_code: &'static str,
}

pub(crate) struct VerificationHandoffIntakeReport {
    pub(crate) consumed: Option<VerificationHandoffConsumeResult>,
    pub(crate) blockages: Vec<VerificationHandoffBlockage>,
}

/// Explicit reviewed composition for the first single-checker Verification
/// worker. The worker never derives a checker, workspace, request bytes, or
/// mapper policy from a Task payload.
#[derive(Clone)]
pub struct VerificationWorkerConfig {
    pub handoff_plan: VerificationHandoffPlan,
    pub checker_profile: CheckerProfile,
    pub checker_executable: PathBuf,
    pub checker_arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub checker_request: Vec<u8>,
    pub mapper_policy: SegoMapperPolicy,
    pub verification_run_id_prefix: String,
    pub verification_artifact_id_prefix: String,
    pub execution_id_prefix: String,
    pub tool_receipt_artifact_ids: Vec<String>,
    pub model_call_receipt_artifact_ids: Vec<String>,
    pub checker_timeout: Duration,
    pub checker_output_limit: u64,
    /// Where this environment reads the checker's review artifact from.
    pub output_source: CheckerOutputSource,
    /// Declared capture of the checker's own output; the sink is composed from
    /// it at the application boundary.
    pub checker_output_capture: Option<crate::CheckerOutputCaptureConfig>,
    /// Seals the exact checker bytes so results cite the checker's own output.
    /// Absent keeps the configured raw output artifact as the citation.
    pub checker_output_sink: Option<Arc<dyn CheckerOutputSink>>,
    /// Present when no repository workflow deploys this profile, so the worker
    /// seals the configured declaration itself before attesting it.
    pub checker_profile_deployment: Option<crate::CheckerProfileDeploymentConfig>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum VerificationWorkerConfigurationError {
    #[error("Verification worker configuration is invalid: {0}")]
    Invalid(&'static str),
    #[error("checker supervisor specification is invalid")]
    CheckerSupervisor,
    #[error("Verification handoff plan is invalid: {0}")]
    HandoffPlan(#[from] VerificationHandoffPlanError),
}

impl VerificationWorkerConfig {
    fn validate(&self) -> Result<(), VerificationWorkerConfigurationError> {
        self.handoff_plan.validate()?;
        if self.handoff_plan.criterion_ids.len() != 1
            || self.mapper_policy.criterion_id != self.handoff_plan.criterion_ids[0]
            || !self
                .handoff_plan
                .checker_profile_refs
                .iter()
                .any(|value| value == &self.mapper_policy.checker_profile_ref)
            || self.checker_profile.checker_profile_id.trim().is_empty()
            || self.checker_executable.as_os_str().is_empty()
            || self.working_directory.as_os_str().is_empty()
            || self.checker_request.is_empty()
            || self.verification_run_id_prefix.trim().is_empty()
            || self.verification_artifact_id_prefix.trim().is_empty()
            || self.execution_id_prefix.trim().is_empty()
            || self.mapper_policy.raw_output_artifact_id.trim().is_empty()
            || (self.mapper_policy.positive_acceptance
                && self.checker_profile.assurance_class
                    != CheckerAssuranceClass::Deterministic as i32)
            || self.checker_timeout.is_zero()
            || self.checker_output_limit == 0
        {
            return Err(VerificationWorkerConfigurationError::Invalid(
                "single-checker reviewed inputs",
            ));
        }
        if let Some(capture) = self.checker_output_capture.as_ref() {
            capture.validate().map_err(|_| {
                VerificationWorkerConfigurationError::Invalid("checker output capture")
            })?;
            if self.checker_output_sink.is_none() {
                return Err(VerificationWorkerConfigurationError::Invalid(
                    "checker output capture sink",
                ));
            }
        }
        if let Some(deployment) = self.checker_profile_deployment.as_ref() {
            deployment
                .validate()
                .map_err(|_| VerificationWorkerConfigurationError::Invalid("checker deployment"))?;
            // The attestation cites artifacts, so the profile must cite the
            // declaration this worker is about to seal: a profile that named a
            // different (or no) evidence would either fail attestation or be
            // attested on evidence nobody deployed.
            if !self
                .checker_profile
                .attestation_evidence_artifact_ids
                .contains(&crate::checker_profile_deployment::deployment_artifact_id(
                    &self.checker_profile.checker_profile_id,
                ))
            {
                return Err(VerificationWorkerConfigurationError::Invalid(
                    "checker profile deployment evidence",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod deployment_tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::verification::v1::{
        CriterionRequirement, DiscrepancySeverity,
    };

    fn reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "ab".repeat(32),
        }
    }

    fn profile() -> egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfile {
        egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfile {
            checker_profile_id: "profile-a".to_owned(),
            revision: 1,
            status: 1,
            checker_id: "checker".to_owned(),
            checker_version: "v1".to_owned(),
            input_contract_ref: Some(reference("input")),
            output_contract_ref: Some(reference("output")),
            supported_criterion_types: vec!["criterion".to_owned()],
            assurance_class: 1,
            sandbox_profile_ref: Some(reference("sandbox")),
            tool_policy_ref: Some(reference("tools")),
            data_egress_policy_ref: Some(reference("egress")),
            timeout_ms: 1000,
            network_allowed: false,
            profile_digest_sha256: String::new(),
            attestation_evidence_artifact_ids: Vec::new(),
            attested_at: None,
        }
    }

    fn config(
        checker_profile: egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfile,
        checker_profile_deployment: Option<crate::CheckerProfileDeploymentConfig>,
    ) -> VerificationWorkerConfig {
        VerificationWorkerConfig {
            handoff_plan: VerificationHandoffPlan {
                binding: VerificationBindingTemplate {
                    claim_id: "claim".to_owned(),
                    claim_semantic_profile_ref: reference("claim-semantic"),
                },
                criterion_ids: vec!["criterion".to_owned()],
                checker_profile_refs: vec![reference("profile-a")],
            },
            checker_profile,
            checker_profile_deployment,
            checker_executable: "checker".into(),
            checker_arguments: Vec::new(),
            working_directory: ".".into(),
            checker_request: b"{}".to_vec(),
            output_source: CheckerOutputSource::Stdout,
            checker_output_capture: None,
            checker_output_sink: None,
            mapper_policy: SegoMapperPolicy {
                criterion_id: "criterion".to_owned(),
                requirement: CriterionRequirement::MustPass,
                checker_profile_ref: reference("profile-a"),
                contract_id: "sego.review.artifact/v1".to_owned(),
                contract_revision: 3,
                expected_scope: "scope".to_owned(),
                expected_diff_hash: "cd".repeat(32),
                expected_reviewer: "checker".to_owned(),
                expected_engine_version: "v1".to_owned(),
                expected_review_mode: "mode".to_owned(),
                positive_acceptance: false,
                failure_threshold: DiscrepancySeverity::Major,
                raw_output_artifact_id: "artifact".to_owned(),
                raw_output_address:
                    egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress {
                        algorithm: 1,
                        digest: "ef".repeat(32),
                        byte_length: 1,
                    },
                finding_evidence: std::collections::BTreeMap::new(),
            },
            verification_run_id_prefix: "verification-run:".to_owned(),
            verification_artifact_id_prefix: "verification-artifact:".to_owned(),
            execution_id_prefix: "verification-execution:".to_owned(),
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: Vec::new(),
            checker_timeout: std::time::Duration::from_secs(1),
            checker_output_limit: 1024,
        }
    }

    fn deployment() -> crate::CheckerProfileDeploymentConfig {
        crate::CheckerProfileDeploymentConfig {
            workspace_ref: "default".to_owned(),
            artifact_type_ref: reference("checker-profile-attestation"),
            transformation_contract_ref: reference("checker-profile-deployment"),
            retention_profile_ref: reference("verification-records"),
            collector_principal_id: "collector:checker-profile-deployment".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
            sensitivity_class: "local-user-data".to_owned(),
        }
    }

    #[test]
    fn a_deployment_screen_declares_the_artifact_its_worker_will_seal() {
        assert_eq!(
            crate::checker_profile_deployment::deployment_artifact_id("profile-a"),
            "artifact:checker-profile-attestation:profile-a"
        );
    }

    #[test]
    fn a_deployment_requires_the_profile_to_cite_its_declaration() {
        assert!(deployment().validate().is_ok());
        // Without a cited declaration the profile would be attested on
        // evidence this worker never seals.
        assert!(config(profile(), Some(deployment())).validate().is_err());
        let mut cited = profile();
        cited.attestation_evidence_artifact_ids =
            vec![crate::checker_profile_deployment::deployment_artifact_id(
                "profile-a",
            )];
        assert!(config(cited.clone(), Some(deployment())).validate().is_ok());
        // Without a deployment the configuration keeps its previous meaning.
        assert!(config(cited, None).validate().is_ok());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationWorkerCycleResult {
    Idle,
    Held {
        verification_request_id: String,
        task_id: String,
        verification_run_id: String,
        reason_code: String,
    },
    Completed {
        verification_request_id: String,
        task_id: String,
        verification_artifact_id: String,
        execution_replayed: bool,
        write_back_replayed: bool,
    },
}

#[derive(Debug, Error)]
pub enum VerificationWorkerCycleError {
    #[error("checker profile attestation failed: {0}")]
    Attestation(#[from] CheckerProfileAttestationError),
    #[error("checker profile deployment failed: {0}")]
    Deployment(#[from] crate::checker_profile_deployment::CheckerProfileDeploymentError),
    #[error("verification handoff intake failed: {0}")]
    Intake(#[from] VerificationHandoffIntakeError),
    #[error(
        "verification handoff was rejected by the Authority (error_code={error_code}, fingerprint={safe_error_fingerprint:?})"
    )]
    HandoffRejected {
        error_code: i32,
        safe_error_fingerprint: Option<String>,
    },
    #[error("Verification Authority read failed: {0}")]
    Authority(#[from] VerificationAuthorityFailure),
    #[error("Verification Authority lock is poisoned")]
    AuthorityLock,
    #[error("verification request is missing a valid Task lineage")]
    RequestLineage,
    #[error("verification request does not match this worker's reviewed plan")]
    RequestConfigurationMismatch,
    #[error("verification execution failed: {0}")]
    Execution(#[from] GovernedVerificationExecutionError),
    #[error("Task verification write-back failed: {0}")]
    WriteBack(#[from] TaskVerificationWriteBackError),
}

fn request_needs_processing(
    request: &VerificationRequest,
    task: &TaskSnapshot,
    artifact_id: &str,
) -> Result<bool, TaskVerificationWriteBackError> {
    let binding = request
        .binding
        .as_ref()
        .ok_or(TaskVerificationWriteBackError::ArtifactBindingMismatch)?;
    let lineage = binding
        .lineage
        .as_ref()
        .ok_or(TaskVerificationWriteBackError::ArtifactBindingMismatch)?;
    let expected_revision = lineage
        .task_revision
        .checked_add(1)
        .ok_or(TaskVerificationWriteBackError::ArtifactBindingMismatch)?;
    if !lineage_valid(lineage)
        || artifact_id.trim().is_empty()
        || task.task_id != lineage.task_id
        || task.revision < expected_revision
        || task.work_revision < lineage.work_revision
    {
        return Err(TaskVerificationWriteBackError::TaskSnapshotMismatch);
    }
    // A later work revision is authoritative supersession, not permission to
    // execute an old checker again or write its result over the revised Task.
    if task.work_revision > lineage.work_revision {
        return Ok(false);
    }
    if task.status == TaskStatus::VerificationPending as i32
        && task.revision == expected_revision
        && task.artifact_set_id.as_deref() == Some(binding.artifact_set_id.as_str())
        && task.acceptance_contract_ref == binding.acceptance_contract_ref
    {
        // This includes Completed after a crash before its Task write-back.
        return Ok(true);
    }
    if request.status == VerificationStatus::Completed as i32
        && task.revision > expected_revision
        && task.verification_artifact_id.as_deref() == Some(artifact_id)
        && task.artifact_set_id.as_deref() == Some(binding.artifact_set_id.as_str())
        && task.acceptance_contract_ref == binding.acceptance_contract_ref
    {
        return Ok(false);
    }
    Err(TaskVerificationWriteBackError::TaskSnapshotMismatch)
}

/// The daemon's one durable Verification worker boundary. A cycle first
/// attests the configured profile, consumes at most one new Task handoff, then
/// scans Verification-owned queued/running/completed requests so a crash after
/// handoff ACK or after artifact completion remains recoverable.
pub trait VerificationWorker: Send + Sync + 'static {
    fn run_once<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<VerificationWorkerCycleResult, VerificationWorkerCycleError>>
                + Send
                + 'a,
        >,
    >;
}

pub struct ConfiguredVerificationWorker {
    execution: ConfiguredVerificationExecution,
    verification: Arc<Mutex<VerificationAuthority>>,
    attestation: SystemCheckerProfileAttestation,
    intake: VerificationHandoffIntake,
    coordinator: GovernedVerificationExecutionCoordinator<SystemVerificationClock>,
    write_back: SystemTaskVerificationWriteBack,
    checker_profile_deployment: Option<crate::ConfiguredCheckerProfileDeployment>,
    /// Handoff blockages already reported, so a pending handoff this worker
    /// does not serve is named once instead of on every cycle.
    reported_handoff_blockages:
        std::sync::Mutex<std::collections::BTreeSet<(String, String, String)>>,
}

/// The production repository path changes only preparation and execution;
/// durable request intake, scheduling, recovery and Task write-back remain shared.
enum ConfiguredVerificationExecution {
    Legacy(Box<VerificationWorkerConfig>),
    Prepared {
        criterion_ids: Vec<String>,
        checker_profile_ids: Vec<String>,
        checker: Arc<dyn GovernedVerificationChecker>,
    },
}

impl ConfiguredVerificationExecution {
    fn owns(&self, request: &VerificationRequest) -> bool {
        match self {
            Self::Legacy(config) => {
                request.criterion_ids == config.handoff_plan.criterion_ids
                    && request.checker_profile_refs == config.handoff_plan.checker_profile_refs
            }
            Self::Prepared {
                criterion_ids,
                checker_profile_ids,
                ..
            } => {
                request.criterion_ids == *criterion_ids
                    && request.checker_profile_refs.len() == checker_profile_ids.len()
                    && request
                        .checker_profile_refs
                        .iter()
                        .zip(checker_profile_ids)
                        .all(|(reference, id)| reference.contract_id == *id)
            }
        }
    }

    fn artifact_id(&self, request_id: &str) -> String {
        let prefix = match self {
            Self::Legacy(config) => &config.verification_artifact_id_prefix,
            Self::Prepared { .. } => "verification-artifact:",
        };
        format!("{prefix}{request_id}")
    }

    fn run_id(&self, request_id: &str) -> String {
        let prefix = match self {
            Self::Legacy(config) => &config.verification_run_id_prefix,
            Self::Prepared { .. } => "verification-run:",
        };
        format!("{prefix}{request_id}")
    }
}

impl ConfiguredVerificationWorker {
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        config: VerificationWorkerConfig,
        checker_profile_deployment: Option<crate::ConfiguredCheckerProfileDeployment>,
    ) -> Result<Self, VerificationWorkerConfigurationError> {
        config.validate()?;
        let supervisor = GovernedCheckerSupervisor::new(
            config.checker_executable.clone(),
            config.checker_arguments.clone(),
            config.checker_timeout,
            config.checker_output_limit,
        )
        .map_err(|_| VerificationWorkerConfigurationError::CheckerSupervisor)?;
        let checker_profile_deployment = checker_profile_deployment;
        let intake = VerificationHandoffIntake::new(
            Arc::clone(&task),
            artifact,
            Arc::clone(&verification),
            config.handoff_plan.clone(),
            AuthenticatedVerificationPrincipal {
                kind: VerificationPrincipalKind::TaskAuthority,
                principal_id: "task-authority:verification-worker".to_owned(),
                authenticated: true,
                checker_profile_id: None,
            },
        )?;
        let coordinator = GovernedVerificationExecutionCoordinator::new(
            Arc::clone(&verification),
            GovernedSegoRunner::new(supervisor),
        );
        Ok(Self {
            execution: ConfiguredVerificationExecution::Legacy(Box::new(config)),
            verification: Arc::clone(&verification),
            attestation: SystemCheckerProfileAttestation::new(Arc::clone(&verification)),
            intake,
            coordinator,
            write_back: SystemTaskVerificationWriteBack::new(task, verification),
            checker_profile_deployment,
            reported_handoff_blockages: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        })
    }

    pub(crate) fn new_prepared(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        preparation: Arc<dyn VerificationHandoffPreparation>,
        criterion_ids: Vec<String>,
        checker_profile_ids: Vec<String>,
        checker: Arc<dyn GovernedVerificationChecker>,
    ) -> Result<Self, VerificationWorkerConfigurationError> {
        if !unique_nonempty(&criterion_ids) || !unique_nonempty(&checker_profile_ids) {
            return Err(VerificationHandoffPlanError::Invalid.into());
        }
        Ok(Self {
            execution: ConfiguredVerificationExecution::Prepared {
                criterion_ids,
                checker_profile_ids,
                checker,
            },
            verification: Arc::clone(&verification),
            attestation: SystemCheckerProfileAttestation::new(Arc::clone(&verification)),
            intake: VerificationHandoffIntake {
                task: Arc::clone(&task),
                artifact,
                verification: Arc::clone(&verification),
                plan: VerificationHandoffPlanSource::Prepared(preparation),
                principal: AuthenticatedVerificationPrincipal {
                    kind: VerificationPrincipalKind::TaskAuthority,
                    principal_id: "task-authority:verification-worker".to_owned(),
                    authenticated: true,
                    checker_profile_id: None,
                },
            },
            coordinator: GovernedVerificationExecutionCoordinator::from_authority(Arc::clone(
                &verification,
            )),
            write_back: SystemTaskVerificationWriteBack::new(task, verification),
            checker_profile_deployment: None,
            reported_handoff_blockages: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        })
    }

    /// Lineage of the work this worker is configured to verify, read from the
    /// pending handoff it owns. The deployment is bound to that work, so it is
    /// sealed only while such a handoff exists.
    fn deployment_lineage(
        &self,
    ) -> Result<
        Option<egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding>,
        VerificationWorkerCycleError,
    > {
        let owned_claim = match &self.execution {
            ConfiguredVerificationExecution::Legacy(config) => {
                Some(config.handoff_plan.binding.claim_id.clone())
            }
            ConfiguredVerificationExecution::Prepared { .. } => None,
        };
        let pending = {
            let task = self
                .intake
                .task
                .lock()
                .map_err(|_| VerificationWorkerCycleError::AuthorityLock)?;
            task.pending_task_verifications()
                .map_err(|_| VerificationWorkerCycleError::RequestLineage)?
        };
        for handoff in pending {
            let Some(artifact_set_id) = handoff
                .event
                .snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.artifact_set_id.as_deref())
            else {
                continue;
            };
            let Some(artifact_set) = self
                .intake
                .artifact
                .read_artifact_set(artifact_set_id)
                .map_err(|_| VerificationWorkerCycleError::RequestLineage)?
            else {
                continue;
            };
            if let Some(claim) = owned_claim.as_deref()
                && !artifact_set.claim_ids.iter().any(|id| id == claim)
            {
                continue;
            }
            if let Some(lineage) = artifact_set.lineage.clone() {
                return Ok(Some(lineage));
            }
        }
        Ok(None)
    }

    async fn run_cycle(
        &self,
    ) -> Result<VerificationWorkerCycleResult, VerificationWorkerCycleError> {
        let issued_at = VerificationClock::now(&SystemVerificationClock);
        // A profile is attested only on evidence that exists. The declaration
        // is sealed against the lineage of the work this worker serves, so it
        // can only be deployed while that work is pending — and request
        // creation then requires the profile to be attested already.
        let mut profile_ready = self.checker_profile_deployment.is_none();
        if let ConfiguredVerificationExecution::Legacy(config) = &self.execution {
            if let Some(deployment) = self.checker_profile_deployment.as_ref()
                && let Some(lineage) = self.deployment_lineage()?
            {
                deployment.ensure_sealed(&config.checker_profile, &lineage, &issued_at)?;
                profile_ready = true;
            }
            if profile_ready {
                self.attestation
                    .attest_one(config.checker_profile.clone(), issued_at)?;
            }
        }
        let intake = self.intake.consume_one_with_report(issued_at)?;
        let mut new_blockages = Vec::new();
        {
            let mut reported = self
                .reported_handoff_blockages
                .lock()
                .map_err(|_| VerificationWorkerCycleError::AuthorityLock)?;
            for blockage in &intake.blockages {
                let key = (
                    blockage.task_id.clone(),
                    blockage.message_id.clone(),
                    blockage.reason_code.to_owned(),
                );
                if reported.insert(key) {
                    new_blockages.push(blockage.clone());
                }
            }
        }
        for blockage in &new_blockages {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "verification_handoff_not_served",
                    "task_id": blockage.task_id,
                    "message_id": blockage.message_id,
                    "safe_detail_code": blockage.reason_code,
                })
            );
        }
        if let Some(handoff) = intake.consumed
            && !handoff.committed
            && !handoff.replayed
        {
            return Err(VerificationWorkerCycleError::HandoffRejected {
                error_code: handoff.error_code,
                safe_error_fingerprint: handoff.safe_error_fingerprint,
            });
        }
        let requests = {
            let verification = self
                .verification
                .lock()
                .map_err(|_| VerificationWorkerCycleError::AuthorityLock)?;
            verification.execution_requests()?
        };
        // Completed requests remain durable Verification facts. Only requests
        // still needing execution or Task write-back belong in this work queue.
        // Consult the Task owner after releasing the Verification lock.
        let mut request = None;
        for candidate in requests {
            if !self.execution.owns(&candidate) {
                continue;
            }
            let artifact_id = self
                .execution
                .artifact_id(&candidate.verification_request_id);
            if self.write_back.needs_processing(&candidate, &artifact_id)? {
                request = Some(candidate);
                break;
            }
        }
        let Some(request) = request else {
            return Ok(VerificationWorkerCycleResult::Idle);
        };
        let lineage = request
            .binding
            .as_ref()
            .and_then(|binding| binding.lineage.as_ref())
            .ok_or(VerificationWorkerCycleError::RequestLineage)?;
        if lineage.task_id.trim().is_empty()
            || lineage.task_revision == 0
            || lineage.work_revision == 0
        {
            return Err(VerificationWorkerCycleError::RequestLineage);
        }

        let verification_run_id = self.execution.run_id(&request.verification_request_id);
        let verification_artifact_id = self.execution.artifact_id(&request.verification_request_id);
        let outcome = match &self.execution {
            ConfiguredVerificationExecution::Legacy(config) => {
                self.coordinator
                    .execute_one(GovernedVerificationExecutionPlan {
                        verification_request_id: request.verification_request_id.clone(),
                        verification_run_id,
                        execution_id: format!(
                            "{}{}",
                            config.execution_id_prefix, request.verification_request_id
                        ),
                        working_directory: config.working_directory.clone(),
                        checker_request: config.checker_request.clone(),
                        mapper_policy: config.mapper_policy.clone(),
                        verification_artifact_id: verification_artifact_id.clone(),
                        tool_receipt_artifact_ids: config.tool_receipt_artifact_ids.clone(),
                        model_call_receipt_artifact_ids: config
                            .model_call_receipt_artifact_ids
                            .clone(),
                        issued_at,
                        output_source: config.output_source,
                        checker_output_sink: config.checker_output_sink.clone(),
                    })
                    .await
            }
            ConfiguredVerificationExecution::Prepared { checker, .. } => {
                self.coordinator
                    .execute_prepared(
                        GovernedVerificationBatchPlan {
                            verification_request_id: request.verification_request_id.clone(),
                            verification_run_id,
                            verification_artifact_id: verification_artifact_id.clone(),
                            issued_at,
                        },
                        checker.as_ref(),
                    )
                    .await
            }
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(GovernedVerificationExecutionError::HeldForRecovery {
                verification_run_id,
                reason_code,
            }) => {
                tracing::warn!(safe_reason_code = %reason_code, "verification held without re-executing its checker");
                return Ok(VerificationWorkerCycleResult::Held {
                    verification_request_id: request.verification_request_id.clone(),
                    task_id: lineage.task_id.clone(),
                    verification_run_id,
                    reason_code,
                });
            }
            Err(error) => return Err(error.into()),
        };
        // A failed checker is a failed criterion either way. Emitting the
        // report here keeps the attribution (exit code, declared stop reason,
        // captured artifact) observable even when nothing was sealed.
        if let Some(failure) = outcome.checker_failure.as_ref() {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "verification_checker_failed",
                    "verification_request_id":
                        outcome.verification_artifact.verification_request_id.clone(),
                    "verification_run_id": outcome.verification_artifact.verification_run_id.clone(),
                    "safe_failure_code": failure.kind.safe_code(),
                    "exit_code": failure.exit_code,
                    "checker_declared_code": failure.checker_declared_code,
                    "output_sha256": failure.output_sha256,
                    "output_byte_length": failure.output_byte_length,
                    "captured_artifact_id": failure.captured_artifact_id,
                    "cited_configured_input_artifact_id":
                        failure.cited_configured_input_artifact_id,
                    "capture_failure_code": failure.capture_failure_code,
                })
            );
        }
        let write_back = self.write_back.record_one(
            &lineage.task_id,
            lineage
                .task_revision
                .checked_add(1)
                .ok_or(VerificationWorkerCycleError::RequestLineage)?,
            lineage.work_revision,
            &verification_artifact_id,
            issued_at,
        )?;
        Ok(VerificationWorkerCycleResult::Completed {
            verification_request_id: request.verification_request_id,
            task_id: lineage.task_id.clone(),
            verification_artifact_id,
            execution_replayed: outcome.replayed || outcome.recovered_existing_result,
            write_back_replayed: write_back.replayed,
        })
    }
}

impl VerificationWorker for ConfiguredVerificationWorker {
    fn run_once<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<VerificationWorkerCycleResult, VerificationWorkerCycleError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.run_cycle())
    }
}

/// Consumes one durable Task handoff. ACK is deliberately after the
/// Verification Authority commit/replay, so a crash between the two is safe:
/// the deterministic idempotency key replays the same Verification request.
pub struct VerificationHandoffIntake {
    task: Arc<Mutex<TaskAuthority>>,
    artifact: Box<dyn ArtifactReferenceSource>,
    verification: Arc<Mutex<VerificationAuthority>>,
    plan: VerificationHandoffPlanSource,
    principal: AuthenticatedVerificationPrincipal,
}

enum VerificationHandoffPlanSource {
    Explicit(VerificationHandoffPlan),
    DynamicPrimaryClaim(DynamicPrimaryClaimHandoffPlan),
    Prepared(Arc<dyn VerificationHandoffPreparation>),
}

pub(crate) trait VerificationHandoffPreparation: Send + Sync {
    fn prepare(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        artifact: &dyn ArtifactReferenceSource,
    ) -> Result<VerificationHandoffPlan, VerificationHandoffIntakeError>;
}

impl VerificationHandoffIntake {
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        plan: VerificationHandoffPlan,
        principal: AuthenticatedVerificationPrincipal,
    ) -> Result<Self, VerificationHandoffPlanError> {
        plan.validate()?;
        Ok(Self {
            task,
            artifact,
            verification,
            plan: VerificationHandoffPlanSource::Explicit(plan),
            principal,
        })
    }

    pub fn new_dynamic_primary_claim(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        plan: DynamicPrimaryClaimHandoffPlan,
        principal: AuthenticatedVerificationPrincipal,
    ) -> Result<Self, VerificationHandoffPlanError> {
        plan.validate()?;
        Ok(Self {
            task,
            artifact,
            verification,
            plan: VerificationHandoffPlanSource::DynamicPrimaryClaim(plan),
            principal,
        })
    }

    pub fn consume_one(
        &self,
        issued_at: Timestamp,
    ) -> Result<Option<VerificationHandoffConsumeResult>, VerificationHandoffIntakeError> {
        let report = self.consume_one_with_report(issued_at)?;
        for blocked in report.blockages {
            tracing::warn!(task_id = %blocked.task_id, message_id = %blocked.message_id,
                safe_reason_code = blocked.reason_code, "Task verification handoff remains pending; later Tasks may proceed");
        }
        Ok(report.consumed)
    }

    pub(crate) fn consume_one_with_report(
        &self,
        issued_at: Timestamp,
    ) -> Result<VerificationHandoffIntakeReport, VerificationHandoffIntakeError> {
        let pending = {
            let task = self
                .task
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::TaskLock)?;
            task.pending_task_verifications()?
        };
        let mut blockages = Vec::new();
        for handoff in pending {
            let resolved = self.prepare_handoff(&handoff, issued_at);
            let (command, expected_request_id) = match resolved {
                Ok(prepared) => prepared,
                // A handoff this worker's plan does not describe is simply not
                // its work: it stays pending for a worker that can serve it.
                // Only the material of a handoff this plan does own, and its
                // commit, may fail the cycle.
                Err(error)
                    if matches!(
                        &error,
                        VerificationHandoffIntakeError::PreparationBlocked(_)
                            | VerificationHandoffIntakeError::Plan(_)
                    ) =>
                {
                    let reason_code = match error {
                        VerificationHandoffIntakeError::PreparationBlocked(reason) => reason,
                        VerificationHandoffIntakeError::Plan(
                            VerificationHandoffPlanError::LineageMismatch,
                        ) => "VERIFICATION_HANDOFF_LINEAGE_MISMATCH",
                        VerificationHandoffIntakeError::Plan(
                            VerificationHandoffPlanError::NotOurWork,
                        ) => "VERIFICATION_HANDOFF_NOT_OUR_WORK",
                        VerificationHandoffIntakeError::Plan(_) => "VERIFICATION_MATERIAL_INVALID",
                        _ => "VERIFICATION_MATERIAL_UNAVAILABLE",
                    };
                    blockages.push(VerificationHandoffBlockage {
                        task_id: handoff
                            .event
                            .snapshot
                            .as_ref()
                            .map(|snapshot| snapshot.task_id.clone())
                            .unwrap_or_default(),
                        message_id: handoff.message_id.clone(),
                        reason_code,
                    });
                    continue;
                }
                Err(error) => return Err(error),
            };
            // Once the owning Authority sees a command, preserve its existing
            // rejection/error and ACK ordering. Only preparation is task-local.
            let consumed = self.commit_handoff(handoff, command, expected_request_id)?;
            return Ok(VerificationHandoffIntakeReport {
                consumed: Some(consumed),
                blockages,
            });
        }
        Ok(VerificationHandoffIntakeReport {
            consumed: None,
            blockages,
        })
    }

    fn prepare_handoff(
        &self,
        handoff: &PendingTaskVerification,
        issued_at: Timestamp,
    ) -> Result<(VerificationCommand, String), VerificationHandoffIntakeError> {
        let artifact_set_id = handoff
            .event
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.artifact_set_id.as_deref())
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        let artifact_set = self
            .artifact
            .read_artifact_set(artifact_set_id)?
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        let plan = match &self.plan {
            VerificationHandoffPlanSource::Explicit(plan) => plan.clone(),
            VerificationHandoffPlanSource::DynamicPrimaryClaim(plan) => {
                plan.resolve(handoff, &artifact_set, self.artifact.as_ref())?
            }
            VerificationHandoffPlanSource::Prepared(preparation) => {
                preparation.prepare(handoff, &artifact_set, self.artifact.as_ref())?
            }
        };
        let command = plan.create_command(handoff, &artifact_set, issued_at)?;
        let expected_request_id = plan
            .request_for(handoff, &artifact_set)?
            .verification_request_id;
        Ok((command, expected_request_id))
    }

    fn commit_handoff(
        &self,
        handoff: PendingTaskVerification,
        command: VerificationCommand,
        expected_request_id: String,
    ) -> Result<VerificationHandoffConsumeResult, VerificationHandoffIntakeError> {
        let result = {
            let mut verification = self
                .verification
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::VerificationLock)?;
            verification.execute(&command, &self.principal)?
        };
        if !result.committed && !result.replayed {
            return Ok(VerificationHandoffConsumeResult {
                message_id: handoff.message_id,
                payload_digest_sha256: handoff.payload_digest_sha256,
                verification_request_id: expected_request_id,
                committed: false,
                replayed: false,
                task_outbox_acknowledged: false,
                error_code: result.error_code,
                safe_error_fingerprint: result.safe_error_fingerprint,
            });
        }
        let acknowledged = {
            let mut task = self
                .task
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::TaskLock)?;
            task.acknowledge_cross_authority_outbox(
                &handoff.message_id,
                &handoff.payload_digest_sha256,
            )?
        };
        Ok(VerificationHandoffConsumeResult {
            message_id: handoff.message_id,
            payload_digest_sha256: handoff.payload_digest_sha256,
            verification_request_id: expected_request_id,
            committed: result.committed,
            replayed: result.replayed,
            task_outbox_acknowledged: acknowledged,
            error_code: result.error_code,
            safe_error_fingerprint: result.safe_error_fingerprint,
        })
    }
}

fn deterministic_request_id(task_id: &str, revision: u64, work_revision: u64) -> String {
    let seed = format!("{task_id}:{revision}:{work_revision}");
    format!(
        "verification-request-{}",
        hex::encode(Sha256::digest(seed.as_bytes()))
    )
}

fn unique_nonempty(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| !value.trim().is_empty())
        && values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == values.len()
}

fn unique_contract_references(values: &[ContractReference]) -> bool {
    values
        .iter()
        .map(|value| (&value.contract_id, &value.version, &value.sha256))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == values.len()
}

fn contract_reference_valid(value: &ContractReference) -> bool {
    !value.contract_id.trim().is_empty()
        && !value.version.trim().is_empty()
        && value.sha256.len() == 64
        && value
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lineage_valid(
    value: &egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding,
) -> bool {
    !value.task_id.trim().is_empty()
        && value.task_revision > 0
        && value.work_revision > 0
        && !value.run_id.trim().is_empty()
        && value.run_revision > 0
        && !value.step_id.trim().is_empty()
        && value.step_revision > 0
        && !value.attempt_id.trim().is_empty()
        && value.attempt_revision > 0
        && !value.dispatch_id.trim().is_empty()
        && value.fencing_token > 0
}

fn content_address_valid(value: &ContentAddress) -> bool {
    value.algorithm == HashAlgorithm::Sha256 as i32
        && value.byte_length > 0
        && value.digest.len() == 64
        && value
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "verification_handoff_tests.rs"]
mod handoff_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactDescriptor, ArtifactSet, ArtifactSetStatus, Claim, ClaimStatus, ContentAddress,
            Evidence, HashAlgorithm, LineageBinding,
        },
        task::v1::{TaskEvent, TaskEventKind, TaskSnapshot},
    };

    struct ClaimOnlySource {
        claim: Claim,
    }

    impl ArtifactReferenceSource for ClaimOnlySource {
        fn read_artifact(
            &self,
            _artifact_id: &str,
        ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
            Ok(None)
        }

        fn read_claim(
            &self,
            claim_id: &str,
        ) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
            Ok((self.claim.claim_id == claim_id).then(|| self.claim.clone()))
        }

        fn read_evidence(
            &self,
            _evidence_id: &str,
        ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
            Ok(None)
        }

        fn read_artifact_set(
            &self,
            _artifact_set_id: &str,
        ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
            Ok(None)
        }
    }

    fn contract(seed: &str) -> ContractReference {
        ContractReference {
            contract_id: format!("contract-{seed}"),
            version: "0.1.0".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn plan() -> VerificationHandoffPlan {
        VerificationHandoffPlan {
            binding: VerificationBindingTemplate {
                claim_id: "claim-1".to_owned(),
                claim_semantic_profile_ref: contract("semantic"),
            },
            criterion_ids: vec!["criterion-1".to_owned()],
            checker_profile_refs: vec![contract("checker")],
        }
    }

    fn handoff() -> PendingTaskVerification {
        let snapshot = TaskSnapshot {
            task_id: "task-1".to_owned(),
            revision: 4,
            work_revision: 2,
            status: TaskStatus::VerificationPending as i32,
            acceptance_contract_ref: Some(contract("acceptance")),
            artifact_set_id: Some("artifact-set-1".to_owned()),
            ..TaskSnapshot::default()
        };
        PendingTaskVerification {
            message_id: "task-outbox-verification-1".to_owned(),
            payload_digest_sha256: "c".repeat(64),
            event: TaskEvent {
                event_id: "task-event-1".to_owned(),
                kind: TaskEventKind::EvidenceSubmitted as i32,
                task_id: "task-1".to_owned(),
                resulting_revision: 4,
                work_revision: 2,
                snapshot: Some(snapshot),
                ..TaskEvent::default()
            },
        }
    }

    fn artifact_set() -> ArtifactSet {
        ArtifactSet {
            artifact_set_id: "artifact-set-1".to_owned(),
            status: ArtifactSetStatus::Sealed as i32,
            lineage: Some(LineageBinding {
                task_id: "task-1".to_owned(),
                // Artifact production precedes the Task evidence handoff
                // by one Task revision.
                task_revision: 3,
                work_revision: 2,
                run_id: "run-1".to_owned(),
                run_revision: 1,
                step_id: "step-1".to_owned(),
                step_revision: 1,
                attempt_id: "attempt-1".to_owned(),
                attempt_revision: 1,
                dispatch_id: "dispatch-1".to_owned(),
                fencing_token: 1,
            }),
            claim_ids: vec!["claim-1".to_owned()],
            canonical_manifest: Some(ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "b".repeat(64),
                byte_length: 128,
            }),
            ..ArtifactSet::default()
        }
    }

    fn dynamic_plan() -> DynamicPrimaryClaimHandoffPlan {
        DynamicPrimaryClaimHandoffPlan {
            claim_semantic_profile_ref: contract("semantic"),
            criterion_ids: vec!["criterion-1".to_owned()],
            checker_profile_refs: vec![contract("checker")],
        }
    }

    #[test]
    fn worker_skips_written_completion_but_keeps_unwritten_completion_after_restart() {
        let handoff = handoff();
        let mut request = plan()
            .request_for(&handoff, &artifact_set())
            .expect("request")
            .request;
        request.status = VerificationStatus::Completed as i32;
        let pending = handoff.event.snapshot.expect("Task snapshot");
        let mut written = pending.clone();
        written.revision += 1;
        written.status = TaskStatus::VerdictPending as i32;
        written.verification_artifact_id = Some("verification-artifact-1".to_owned());
        // Same durable Verification status, different owner write-back facts.
        // The first must not mask the second in an ordered request scan.
        let needs = [&written, &pending].map(|task| {
            request_needs_processing(&request, task, "verification-artifact-1")
                .expect("consistent snapshots")
        });
        assert_eq!(needs, [false, true]);
        assert_eq!(needs.into_iter().position(|value| value), Some(1));
        written.verification_artifact_id = Some("unrelated-artifact".to_owned());
        assert!(matches!(
            request_needs_processing(&request, &written, "verification-artifact-1"),
            Err(TaskVerificationWriteBackError::TaskSnapshotMismatch)
        ));
    }

    #[test]
    fn worker_does_not_reexecute_an_old_work_revision_or_accept_foreign_task_state() {
        let handoff = handoff();
        let request = plan()
            .request_for(&handoff, &artifact_set())
            .expect("request")
            .request;
        let mut revised = handoff.event.snapshot.expect("Task snapshot");
        revised.revision += 3;
        revised.work_revision += 1;
        revised.status = TaskStatus::Ready as i32;
        revised.artifact_set_id = None;
        revised.verification_artifact_id = None;
        assert!(
            !request_needs_processing(&request, &revised, "verification-artifact-1")
                .expect("old work is superseded")
        );
        revised.task_id = "another-task".to_owned();
        assert!(matches!(
            request_needs_processing(&request, &revised, "verification-artifact-1"),
            Err(TaskVerificationWriteBackError::TaskSnapshotMismatch)
        ));
    }

    fn dynamic_artifact_set_and_claim() -> (ArtifactSet, Claim) {
        let mut artifact_set = artifact_set();
        artifact_set.claim_ids = vec!["claim-runtime-42".to_owned()];
        artifact_set.artifact_ids = vec!["artifact-1".to_owned()];
        let claim = Claim {
            claim_id: "claim-runtime-42".to_owned(),
            status: ClaimStatus::Proposed as i32,
            semantic_profile_ref: Some(contract("semantic")),
            lineage: artifact_set.lineage.clone(),
            subject_artifact_ids: vec!["artifact-1".to_owned()],
            acceptance_contract_ref: Some(contract("acceptance")),
            ..Claim::default()
        };
        (artifact_set, claim)
    }

    #[test]
    fn explicit_plan_binds_task_facts_without_deriving_verification_policy() {
        let request = plan()
            .request_for(&handoff(), &artifact_set())
            .expect("valid handoff");
        assert_eq!(request.request.verification_type, TASK_ACCEPTANCE);
        assert_eq!(
            request
                .request
                .binding
                .as_ref()
                .unwrap()
                .lineage
                .as_ref()
                .unwrap()
                .task_id,
            "task-1"
        );
        assert_eq!(
            request.request.binding.as_ref().unwrap().artifact_set_id,
            "artifact-set-1"
        );
        assert_eq!(request.request.criterion_ids, vec!["criterion-1"]);
        assert_eq!(request.request.checker_profile_refs.len(), 1);
    }

    #[test]
    fn non_owned_handoff_is_distinct_from_invalid_material() {
        let mut other = artifact_set();
        other.claim_ids = vec!["another-worker-claim".to_owned()];
        assert_eq!(
            plan().request_for(&handoff(), &other).unwrap_err(),
            VerificationHandoffPlanError::NotOurWork
        );
        other.lineage = None;
        assert_eq!(
            plan().request_for(&handoff(), &other).unwrap_err(),
            VerificationHandoffPlanError::ArtifactSetInvalid
        );
    }
    #[test]
    fn dynamic_plan_binds_the_current_artifact_set_primary_claim() {
        let (artifact_set, claim) = dynamic_artifact_set_and_claim();
        let source = ClaimOnlySource { claim };
        let resolved = dynamic_plan()
            .resolve(&handoff(), &artifact_set, &source)
            .expect("current primary Claim should resolve");
        let request = resolved
            .request_for(&handoff(), &artifact_set)
            .expect("resolved plan should create a request");

        assert_eq!(resolved.binding.claim_id, "claim-runtime-42");
        assert_eq!(
            request.request.binding.as_ref().unwrap().claim_id,
            "claim-runtime-42"
        );
    }

    #[test]
    fn dynamic_plan_rejects_claim_contract_and_lineage_mismatches() {
        let (artifact_set, claim) = dynamic_artifact_set_and_claim();
        let mut semantic_mismatch = claim.clone();
        semantic_mismatch.semantic_profile_ref = Some(contract("other-semantic"));
        assert!(matches!(
            dynamic_plan().resolve(
                &handoff(),
                &artifact_set,
                &ClaimOnlySource {
                    claim: semantic_mismatch
                }
            ),
            Err(VerificationHandoffIntakeError::Plan(
                VerificationHandoffPlanError::PrimaryClaimInvalid
            ))
        ));

        let mut acceptance_mismatch = claim.clone();
        acceptance_mismatch.acceptance_contract_ref = Some(contract("other-acceptance"));
        assert!(matches!(
            dynamic_plan().resolve(
                &handoff(),
                &artifact_set,
                &ClaimOnlySource {
                    claim: acceptance_mismatch
                }
            ),
            Err(VerificationHandoffIntakeError::Plan(
                VerificationHandoffPlanError::PrimaryClaimInvalid
            ))
        ));

        let mut lineage_mismatch = claim;
        lineage_mismatch.lineage.as_mut().unwrap().dispatch_id = "other-dispatch".to_owned();
        assert!(matches!(
            dynamic_plan().resolve(
                &handoff(),
                &artifact_set,
                &ClaimOnlySource {
                    claim: lineage_mismatch
                }
            ),
            Err(VerificationHandoffIntakeError::Plan(
                VerificationHandoffPlanError::PrimaryClaimInvalid
            ))
        ));
    }

    #[test]
    fn dynamic_plan_rejects_ambiguous_or_out_of_set_primary_claims() {
        let (mut artifact_set, mut claim) = dynamic_artifact_set_and_claim();
        artifact_set.claim_ids.push("claim-runtime-43".to_owned());
        assert!(matches!(
            dynamic_plan().resolve(
                &handoff(),
                &artifact_set,
                &ClaimOnlySource {
                    claim: claim.clone()
                }
            ),
            Err(VerificationHandoffIntakeError::Plan(
                VerificationHandoffPlanError::PrimaryClaimInvalid
            ))
        ));

        artifact_set.claim_ids.pop();
        claim.subject_artifact_ids = vec!["artifact-outside-set".to_owned()];
        assert!(matches!(
            dynamic_plan().resolve(&handoff(), &artifact_set, &ClaimOnlySource { claim }),
            Err(VerificationHandoffIntakeError::Plan(
                VerificationHandoffPlanError::PrimaryClaimInvalid
            ))
        ));
    }

    #[test]
    fn handoff_command_uses_deterministic_digest_bound_idempotency() {
        let command = plan()
            .create_command(
                &handoff(),
                &artifact_set(),
                Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                },
            )
            .expect("valid command");
        let verification_command::Command::CreateVerificationRequest(create) =
            command.command.as_ref().expect("command")
        else {
            panic!("wrong command");
        };
        let metadata = create.metadata.as_ref().expect("metadata");
        assert_eq!(metadata.idempotency_key, "task-outbox-verification-1");
        assert_eq!(metadata.idempotency_scope, HANDOFF_IDEMPOTENCY_SCOPE);
        assert_eq!(
            canonical_request_digest(&command).as_deref(),
            Some(metadata.request_digest_sha256.as_str())
        );
    }

    #[test]
    fn checker_profile_attestation_command_is_system_scoped_and_digest_bound() {
        let profile = CheckerProfile {
            checker_profile_id: "checker-profile-1".to_owned(),
            profile_digest_sha256: "a".repeat(64),
            ..CheckerProfile::default()
        };
        let command = checker_profile_attestation_command(
            profile,
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            },
        )
        .expect("command should canonicalize");
        let verification_command::Command::AttestCheckerProfile(attest) =
            command.command.as_ref().expect("command")
        else {
            panic!("wrong command");
        };
        let metadata = attest.metadata.as_ref().expect("metadata");
        assert_eq!(metadata.idempotency_scope, PROFILE_ATTESTATION_SCOPE);
        assert_eq!(metadata.correlation_id, "checker-profile-1");
        assert_eq!(
            canonical_request_digest(&command).as_deref(),
            Some(metadata.request_digest_sha256.as_str())
        );
    }

    #[test]
    fn invalid_plan_is_rejected_before_any_authority_is_opened() {
        let mut invalid = plan();
        invalid.criterion_ids.clear();
        assert_eq!(
            invalid.validate(),
            Err(VerificationHandoffPlanError::Invalid)
        );
    }
}
