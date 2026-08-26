use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, PendingTaskVerification, PrincipalKind as TaskPrincipalKind,
    TaskAuthority, TaskAuthorityFailure, canonical_request_digest as task_canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ArtifactSet, ArtifactSetStatus, ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        RecordTaskVerificationCommand, TaskCommand, TaskEventKind, TaskStatus, get_task_response,
        task_command,
    },
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
        CreateVerificationRequestCommand, VerificationBinding, VerificationCommand,
        VerificationRequest, verification_command,
    },
};
use egopulse_verification_authority::{
    ArtifactReferenceSource, ArtifactReferenceSourceError, AuthenticatedVerificationPrincipal,
    GovernedCheckerSupervisor, GovernedSegoRunner, GovernedVerificationExecutionCoordinator,
    GovernedVerificationExecutionError, GovernedVerificationExecutionPlan, SegoMapperPolicy,
    SystemVerificationClock, VerificationAuthority, VerificationAuthorityFailure,
    VerificationClock, VerificationPrincipalKind, canonical_request_digest,
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
                || lineage.task_revision != expected_revision
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
            || !artifact_set
                .claim_ids
                .iter()
                .any(|id| id == &self.binding.claim_id)
        {
            return Err(VerificationHandoffPlanError::ArtifactSetInvalid);
        }
        let lineage = artifact_set
            .lineage
            .clone()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if !lineage_valid(&lineage)
            || lineage.task_id != snapshot.task_id
            || lineage.task_revision != snapshot.revision
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

#[derive(Debug, Error)]
pub enum VerificationHandoffIntakeError {
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
}

/// Explicit reviewed composition for the first single-checker Verification
/// worker. The worker never derives a checker, workspace, request bytes, or
/// mapper policy from a Task payload.
#[derive(Clone, Debug)]
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
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationWorkerCycleResult {
    Idle,
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
    #[error("verification handoff intake failed: {0}")]
    Intake(#[from] VerificationHandoffIntakeError),
    #[error("verification handoff was rejected by the Authority")]
    HandoffRejected,
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
    config: VerificationWorkerConfig,
    verification: Arc<Mutex<VerificationAuthority>>,
    attestation: SystemCheckerProfileAttestation,
    intake: VerificationHandoffIntake,
    coordinator: GovernedVerificationExecutionCoordinator<SystemVerificationClock>,
    write_back: SystemTaskVerificationWriteBack,
}

impl ConfiguredVerificationWorker {
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        config: VerificationWorkerConfig,
    ) -> Result<Self, VerificationWorkerConfigurationError> {
        config.validate()?;
        let supervisor = GovernedCheckerSupervisor::new(
            config.checker_executable.clone(),
            config.checker_arguments.clone(),
            config.checker_timeout,
            config.checker_output_limit,
        )
        .map_err(|_| VerificationWorkerConfigurationError::CheckerSupervisor)?;
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
            config,
            verification: Arc::clone(&verification),
            attestation: SystemCheckerProfileAttestation::new(Arc::clone(&verification)),
            intake,
            coordinator,
            write_back: SystemTaskVerificationWriteBack::new(task, verification),
        })
    }

    async fn run_cycle(
        &self,
    ) -> Result<VerificationWorkerCycleResult, VerificationWorkerCycleError> {
        let issued_at = VerificationClock::now(&SystemVerificationClock);
        self.attestation
            .attest_one(self.config.checker_profile.clone(), issued_at)?;
        if let Some(handoff) = self.intake.consume_one(issued_at)?
            && !handoff.committed
            && !handoff.replayed
        {
            return Err(VerificationWorkerCycleError::HandoffRejected);
        }
        let request = {
            let verification = self
                .verification
                .lock()
                .map_err(|_| VerificationWorkerCycleError::AuthorityLock)?;
            verification
                .execution_requests()?
                .into_iter()
                .find(|request| {
                    request.criterion_ids == self.config.handoff_plan.criterion_ids
                        && request.checker_profile_refs
                            == self.config.handoff_plan.checker_profile_refs
                })
        };
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
        let verification_run_id = format!(
            "{}{}",
            self.config.verification_run_id_prefix, request.verification_request_id
        );
        let verification_artifact_id = format!(
            "{}{}",
            self.config.verification_artifact_id_prefix, request.verification_request_id
        );
        let execution_id = format!(
            "{}{}",
            self.config.execution_id_prefix, request.verification_request_id
        );
        let outcome = self
            .coordinator
            .execute_one(GovernedVerificationExecutionPlan {
                verification_request_id: request.verification_request_id.clone(),
                verification_run_id,
                execution_id,
                working_directory: self.config.working_directory.clone(),
                checker_request: self.config.checker_request.clone(),
                mapper_policy: self.config.mapper_policy.clone(),
                verification_artifact_id: verification_artifact_id.clone(),
                tool_receipt_artifact_ids: self.config.tool_receipt_artifact_ids.clone(),
                model_call_receipt_artifact_ids: self
                    .config
                    .model_call_receipt_artifact_ids
                    .clone(),
                issued_at,
            })
            .await?;
        let write_back = self.write_back.record_one(
            &lineage.task_id,
            lineage.task_revision,
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
    plan: VerificationHandoffPlan,
    principal: AuthenticatedVerificationPrincipal,
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
            plan,
            principal,
        })
    }

    pub fn consume_one(
        &self,
        issued_at: Timestamp,
    ) -> Result<Option<VerificationHandoffConsumeResult>, VerificationHandoffIntakeError> {
        let handoff = {
            let task = self
                .task
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::TaskLock)?;
            task.pending_task_verifications()?.into_iter().next()
        };
        let Some(handoff) = handoff else {
            return Ok(None);
        };
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
        let command = self
            .plan
            .create_command(&handoff, &artifact_set, issued_at)?;
        let expected_request_id = self
            .plan
            .request_for(&handoff, &artifact_set)?
            .verification_request_id;
        let result = {
            let mut verification = self
                .verification
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::VerificationLock)?;
            verification.execute(&command, &self.principal)?
        };
        if !result.committed && !result.replayed {
            return Ok(Some(VerificationHandoffConsumeResult {
                message_id: handoff.message_id,
                payload_digest_sha256: handoff.payload_digest_sha256,
                verification_request_id: expected_request_id,
                committed: false,
                replayed: false,
                task_outbox_acknowledged: false,
            }));
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
        Ok(Some(VerificationHandoffConsumeResult {
            message_id: handoff.message_id,
            payload_digest_sha256: handoff.payload_digest_sha256,
            verification_request_id: expected_request_id,
            committed: result.committed,
            replayed: result.replayed,
            task_outbox_acknowledged: acknowledged,
        }))
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
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactSet, ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding,
        },
        task::v1::{TaskEvent, TaskEventKind, TaskSnapshot},
    };

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
                task_revision: 4,
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
