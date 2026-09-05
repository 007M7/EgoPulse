mod adapter_evidence;
mod composite_guard;
mod harness_dispatch;
mod ingestion;
mod single_harness_workflow;
mod store;
mod task_activation_guard;

pub use adapter_evidence::AdapterBackedHarnessEvidenceResolver;
pub use composite_guard::CompositeCollaborationGuard;
pub use harness_dispatch::{
    CompositeHarnessDispatchRunner, GovernedHarnessDispatchRunner, GovernedTaskActivationRunner,
    HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
    TaskRecoveryFinding, TaskRecoveryKind, dispatch_pending, pump_observations,
};
pub use ingestion::{HarnessFactIngestionDisposition, HarnessFactIngestionResult};
pub use single_harness_workflow::{
    SingleHarnessWorkConfig, SingleHarnessWorkError, SingleHarnessWorkResult,
    TrustedDispatchRouteProfile, build_dispatch_route_binding, canonical_route_binding_digest,
    start_single_harness_workflow,
};
pub use task_activation_guard::{
    TaskActivationGuardSet, TaskActivationReferenceGuard, TaskActivationReferenceHandle,
};

use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptCancellationDisposition,
    AttemptSnapshot, AttemptStatus, BeginAttemptReconciliationCommand, CollaborationCommand,
    CollaborationCommandResult, CollaborationError, CollaborationErrorCode, CollaborationEvent,
    CollaborationEventKind, CollaborationSnapshot, CommitStepReturnCommand, CreateAttemptCommand,
    CreateRunCommand, GetCollaborationResponse, Lease, MarkAttemptOutcomeUnknownCommand,
    ReconciliationDisposition, RecordAttemptCancellationOutcomeCommand,
    RecordAttemptReconciliationCommand, RecordAttemptReturnCommand, RecordDeliveryReceiptCommand,
    RecordDispatchIntentCommand, RecordHarnessAckCommand, RecordRunningObservationCommand,
    RecoveryClass, RequestAttemptCancellationCommand, RunSnapshot, RunStatus, StepSnapshot,
    StepStatus, collaboration_command, collaboration_command_result, get_collaboration_response,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, DispatchRouteBinding, NativeSessionStrategy,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

pub use store::CollaborationStoreInspection;
use store::{
    AttemptWrite, CollaborationCommit, CollaborationLineageStore, CollaborationStore, OutboxWrite,
    PendingDispatchRecord, PendingProjectionRecord, ProjectionBootstrapCandidate,
    ProjectionBootstrapWrite, RunWrite, StepWrite, StoreError,
};

const AUTHORITY_REF: &str = "agentosd:collaboration-control/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollaborationPrincipalKind {
    TaskAuthority,
    CollaborationControl,
    AttemptSupervisor,
    HarnessAdapter,
    RecoveryWorker,
    ArtifactAuthority,
    FounderAuthority,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCollaborationPrincipal {
    pub kind: CollaborationPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

pub struct CollaborationSqlCipherKey([u8; 32]);

impl CollaborationSqlCipherKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for CollaborationSqlCipherKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct CollaborationControlConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: CollaborationSqlCipherKey,
}

pub struct CollaborationLineageReaderConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: CollaborationSqlCipherKey,
}

/// Read-only owner-module port for resolving Attempt-to-Task lineage. The
/// SQLCipher connection is query-only and exposes no Collaboration snapshots
/// or mutation capability to callers.
pub struct CollaborationLineageReader {
    store: CollaborationLineageStore,
}

impl CollaborationLineageReader {
    pub fn open(
        config: CollaborationLineageReaderConfig,
    ) -> Result<Self, CollaborationControlError> {
        if config.store_epoch.trim().is_empty() {
            return Err(CollaborationControlError::Persistence);
        }
        Ok(Self {
            store: CollaborationLineageStore::open(
                &config.database_path,
                &config.key.0,
                &config.store_epoch,
            )?,
        })
    }

    pub fn task_id_for_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<Option<String>, CollaborationControlError> {
        if attempt_id.trim().is_empty() {
            return Err(CollaborationControlError::Persistence);
        }
        self.store
            .task_id_for_attempt(attempt_id)
            .map_err(CollaborationControlError::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceGuardRejection {
    InvalidArgument,
    ContractMismatch,
    StaleTaskReference,
    UnverifiedReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceAuthorization {
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseAuthorization {
    pub ttl_seconds: u64,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchMaterial {
    pub input_bundle_sha256: String,
    pub sandbox_profile_ref: ContractReference,
    pub tool_policy_ref: ContractReference,
    pub data_egress_policy_ref: ContractReference,
    pub approval_policy_ref: ContractReference,
    pub session_strategy: NativeSessionStrategy,
    pub native_session_ref: Option<String>,
    pub checkpoint_ref: Option<String>,
    pub route_binding: Option<DispatchRouteBinding>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHarnessEvidence {
    pub harness_session_ref: Option<String>,
    pub evidence_refs: Vec<String>,
}

pub const DELIVERY_OUTCOME_UNKNOWN_REASON_CODE: &str = "HARNESS_DELIVERY_OUTCOME_UNKNOWN";

/// Provider-neutral read port for immutable evidence owned by a Harness Adapter.
/// Collaboration never reads an Adapter database and never receives provider-private types.
pub trait HarnessEvidenceResolver {
    /// Proves that an Adapter-owned durable delivery receipt records an
    /// unknown outcome for the exact Collaboration attempt. The default is
    /// fail-closed so a reference guard cannot authorize recovery by itself.
    fn validate_delivery_unknown(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let _ = (command, snapshot);
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection>;

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection>;

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    /// Independent read port that joins an Artifact Authority technical
    /// receipt to the exact terminal Adapter evidence. The default is
    /// fail-closed so existing non-return guards cannot accidentally authorize
    /// a return transition.
    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        let _ = (command, snapshot);
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    /// Proves that a sealed technical return has an accepted Verification
    /// result. The default is fail-closed so technical intake cannot be
    /// mistaken for workflow completion.
    fn resolve_step_return(
        &self,
        command: &CommitStepReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        let _ = (command, snapshot);
        Err(ReferenceGuardRejection::UnverifiedReference)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedArtifactReturn {
    pub artifact_set_id: String,
    pub return_handoff_id: String,
    pub dispatch_id: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedStepReturn {
    pub artifact_set_id: String,
    pub return_handoff_id: String,
    pub verification_artifact_id: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingArtifactReturn {
    pub message_id: String,
    pub payload_digest_sha256: String,
    pub receipt: egopulse_domain_contracts::v01::egopulse::artifact::v1::ReturnReceipt,
}

pub trait ArtifactReturnSource: Send + Sync {
    fn pending_returns(&self) -> Result<Vec<PendingArtifactReturn>, String>;
    fn acknowledge_return(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, String>;
}

pub trait CollaborationReferenceGuard {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        run: &RunSnapshot,
        step: &StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection>;

    fn resolve_dispatch_material(
        &self,
        command: &RecordDispatchIntentCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection>;

    fn validate_unknown_outcome(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection>;
}

pub trait AuthorityClock {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAuthorityClock;

impl AuthorityClock for SystemAuthorityClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDispatch {
    pub message_id: String,
    pub source_event_id: String,
    pub canonical_payload_digest_sha256: String,
    pub envelope: DispatchEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A Collaboration `delivered` outbox fact is only evidence that Collaboration
/// recorded its own delivery transition. It is not Adapter transport proof;
/// a C2 runner must independently revalidate the durable Adapter receipt.
pub struct DeliveredDispatchForObservation {
    pub message_id: String,
    pub source_event_id: String,
    pub canonical_payload_digest_sha256: String,
    pub envelope: DispatchEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeldDispatchRecoveryState {
    OutcomeUnknown,
    Reconciling { reconciliation_id: String },
    Held,
    CancellationPending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldDispatchForRecovery {
    pub message_id: String,
    pub source_event_id: String,
    pub canonical_payload_digest_sha256: String,
    pub envelope: DispatchEnvelope,
    pub state: HeldDispatchRecoveryState,
}

/// Typed, digest-checked evidence handed from Task Authority to the
/// Collaboration single writer. The source owns the original outbox and is
/// responsible for acknowledging it only after the collaboration commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskActivationHandoff {
    pub message_id: String,
    pub payload_digest_sha256: String,
    pub task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskActivationSourceError {
    Unavailable,
    Integrity,
}

pub trait TaskActivationSource: Send + Sync {
    fn pending_task_activations(
        &self,
    ) -> Result<Vec<TaskActivationHandoff>, TaskActivationSourceError>;

    fn acknowledge_task_activation(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, TaskActivationSourceError>;
}

impl<T> TaskActivationSource for std::sync::Arc<T>
where
    T: TaskActivationSource + ?Sized,
{
    fn pending_task_activations(
        &self,
    ) -> Result<Vec<TaskActivationHandoff>, TaskActivationSourceError> {
        (**self).pending_task_activations()
    }

    fn acknowledge_task_activation(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, TaskActivationSourceError> {
        (**self).acknowledge_task_activation(message_id, payload_digest_sha256)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SingleHarnessWorkflowResolverError {
    Unavailable,
    InvalidConfiguration,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SingleHarnessWorkflowResolution {
    NotApplicable,
    Resolved(Box<SingleHarnessWorkConfig>),
    ResolvedWithRouteBinding {
        config: Box<SingleHarnessWorkConfig>,
        route_binding:
            Box<egopulse_domain_contracts::v01::egopulse::harness::v1::DispatchRouteBinding>,
    },
}

pub trait SingleHarnessWorkflowResolver: Send + Sync {
    fn resolve(
        &self,
        activation: &TaskActivationHandoff,
    ) -> Result<SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolverError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingCollaborationProjection {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub canonical_payload_digest_sha256: String,
    pub rebuild_baseline: bool,
    pub snapshot: CollaborationSnapshot,
    pub event: CollaborationEvent,
}

#[derive(Debug, Error)]
pub enum CollaborationControlError {
    #[error("collaboration control persistence failed")]
    Persistence,
    #[error("collaboration control durable data could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("principal is not authorized to poll the Harness dispatch outbox")]
    DispatchPollNotAuthorized,
}

impl From<StoreError> for CollaborationControlError {
    fn from(_: StoreError) -> Self {
        Self::Persistence
    }
}

pub struct CollaborationControl<G, C> {
    store: CollaborationStore,
    guard: G,
    clock: C,
}

impl<G, C> CollaborationControl<G, C>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    pub fn open(
        config: CollaborationControlConfig,
        guard: G,
        clock: C,
    ) -> Result<Self, CollaborationControlError> {
        let mut store =
            CollaborationStore::open(&config.database_path, &config.key.0, &config.store_epoch)?;
        let bootstrap_writes = store
            .projection_bootstrap_candidates()?
            .into_iter()
            .map(encode_projection_bootstrap)
            .collect::<Result<Vec<_>, _>>()?;
        store.complete_projection_bootstrap(&bootstrap_writes)?;
        Ok(Self {
            store,
            guard,
            clock,
        })
    }

    pub fn execute(
        &mut self,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                CollaborationErrorCode::InvalidArgument,
                "COLLABORATION_COMMAND_REQUIRED",
                None,
                None,
            ));
        };
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                CollaborationErrorCode::Unauthenticated,
                "AUTHENTICATED_PRINCIPAL_REQUIRED",
                None,
                None,
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                CollaborationErrorCode::PermissionDenied,
                "COLLABORATION_OPERATION_NOT_AUTHORIZED",
                None,
                None,
            ));
        }

        let Some(meta) = command_metadata(command) else {
            return Ok(error_result(
                CollaborationErrorCode::InvalidArgument,
                "COMMAND_METADATA_REQUIRED",
                None,
                None,
            ));
        };
        if !metadata_is_complete(meta) {
            return Ok(error_result(
                CollaborationErrorCode::InvalidArgument,
                "COMMAND_METADATA_INCOMPLETE",
                None,
                None,
            ));
        }
        let canonical_digest = canonical_request_digest(command);
        if canonical_digest.as_deref() != Some(meta.request_digest_sha256.as_str()) {
            return Ok(error_result(
                CollaborationErrorCode::InvalidArgument,
                "REQUEST_DIGEST_MISMATCH",
                None,
                None,
            ));
        }

        if let Some(record) = self.store.idempotency_record(
            &principal.principal_id,
            operation,
            &meta.idempotency_scope,
            &meta.idempotency_key,
        )? {
            if record.request_digest_sha256 != meta.request_digest_sha256 {
                return Ok(error_result(
                    CollaborationErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_DIGEST",
                    Some(record.run_revision),
                    None,
                ));
            }
            let mut result = CollaborationCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }

        match command
            .command
            .as_ref()
            .expect("operation requires variant")
        {
            collaboration_command::Command::CreateRun(value) => {
                self.create_run(value, command, principal)
            }
            collaboration_command::Command::ActivateRun(value) => {
                self.activate_run(value, command, principal)
            }
            collaboration_command::Command::CreateAttempt(value) => {
                self.create_attempt(value, command, principal)
            }
            collaboration_command::Command::AcquireAttemptLease(value) => {
                self.acquire_lease(value, command, principal)
            }
            collaboration_command::Command::RecordDispatchIntent(value) => {
                self.record_dispatch_intent(value, command, principal)
            }
            collaboration_command::Command::RecordDeliveryReceipt(value) => {
                self.record_delivery_receipt(value, command, principal)
            }
            collaboration_command::Command::RecordHarnessAck(value) => {
                self.record_harness_ack(value, command, principal)
            }
            collaboration_command::Command::RecordRunningObservation(value) => {
                self.record_running_observation(value, command, principal)
            }
            collaboration_command::Command::RecordAttemptReturn(value) => {
                self.record_attempt_return(value, command, principal)
            }
            collaboration_command::Command::CommitStepReturn(value) => {
                self.commit_step_return(value, command, principal)
            }
            collaboration_command::Command::RequestAttemptCancellation(value) => {
                self.request_attempt_cancellation(value, command, principal)
            }
            collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
                self.record_attempt_cancellation_outcome(value, command, principal)
            }
            collaboration_command::Command::BeginAttemptReconciliation(value) => {
                self.begin_attempt_reconciliation(value, command, principal)
            }
            collaboration_command::Command::RecordAttemptReconciliation(value) => {
                self.record_attempt_reconciliation(value, command, principal)
            }
            collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
                self.mark_outcome_unknown(value, command, principal)
            }
            _ => Ok(error_result(
                CollaborationErrorCode::RecoveryRequired,
                "DEPENDENCY_PROOF_NOT_AVAILABLE_G4_03",
                None,
                None,
            )),
        }
    }

    pub fn get_collaboration(
        &self,
        run_id: &str,
    ) -> Result<GetCollaborationResponse, CollaborationControlError> {
        Ok(match self.load_snapshot(run_id)? {
            Some(snapshot) => GetCollaborationResponse {
                outcome: Some(get_collaboration_response::Outcome::Snapshot(snapshot)),
            },
            None => GetCollaborationResponse {
                outcome: Some(get_collaboration_response::Outcome::Error(
                    collaboration_error(
                        CollaborationErrorCode::NotFound,
                        "COLLABORATION_RUN_NOT_FOUND",
                        None,
                        None,
                    ),
                )),
            },
        })
    }

    pub fn pending_dispatches(
        &self,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<Vec<PendingDispatch>, CollaborationControlError> {
        authorize_harness_dispatch_read(principal)?;
        self.store
            .pending_dispatches()?
            .into_iter()
            .map(decode_dispatch_outbox_record)
            .collect()
    }

    pub fn delivered_dispatches_for_observation(
        &self,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<Vec<DeliveredDispatchForObservation>, CollaborationControlError> {
        authorize_harness_dispatch_read(principal)?;
        let mut eligible = Vec::new();
        for record in self.store.delivered_dispatches()? {
            let dispatch = decode_dispatch_outbox_record(record)?;
            let snapshot = self
                .load_snapshot(&dispatch.envelope.run_id)?
                .ok_or(CollaborationControlError::Persistence)?;
            if delivered_observation_lineage_is_eligible(&snapshot, &dispatch.envelope)? {
                eligible.push(DeliveredDispatchForObservation {
                    message_id: dispatch.message_id,
                    source_event_id: dispatch.source_event_id,
                    canonical_payload_digest_sha256: dispatch.canonical_payload_digest_sha256,
                    envelope: dispatch.envelope,
                });
            }
        }
        Ok(eligible)
    }

    pub fn held_dispatches_for_recovery(
        &self,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<Vec<HeldDispatchForRecovery>, CollaborationControlError> {
        if !principal.authenticated
            || !matches!(
                principal.kind,
                CollaborationPrincipalKind::RecoveryWorker
                    | CollaborationPrincipalKind::CollaborationControl
            )
            || principal.principal_id.trim().is_empty()
        {
            return Err(CollaborationControlError::DispatchPollNotAuthorized);
        }
        let mut recovery = Vec::new();
        for record in self.store.held_dispatches()? {
            let dispatch = decode_dispatch_outbox_record(record)?;
            let envelope = dispatch.envelope;
            let Some(snapshot) = self.load_snapshot(&envelope.run_id)? else {
                return Err(CollaborationControlError::Persistence);
            };
            let run = snapshot
                .run
                .as_ref()
                .filter(|run| run.run_id == envelope.run_id)
                .ok_or(CollaborationControlError::Persistence)?;
            let attempt = snapshot
                .attempts
                .iter()
                .find(|attempt| attempt.attempt_id == envelope.attempt_id)
                .ok_or(CollaborationControlError::Persistence)?;
            if attempt.dispatch_id.as_deref() != Some(envelope.dispatch_id.as_str()) {
                return Err(CollaborationControlError::Persistence);
            }
            let state = match AttemptStatus::try_from(attempt.status) {
                Ok(AttemptStatus::OutcomeUnknown) => HeldDispatchRecoveryState::OutcomeUnknown,
                Ok(AttemptStatus::Reconciling) => {
                    let event = self
                        .store
                        .latest_event_blob(&envelope.run_id)?
                        .ok_or(CollaborationControlError::Persistence)?;
                    let event = CollaborationEvent::decode(event.as_slice())?;
                    if event.kind != CollaborationEventKind::ReconciliationStarted as i32
                        || event.attempt_id.as_deref() != Some(attempt.attempt_id.as_str())
                    {
                        return Err(CollaborationControlError::Persistence);
                    }
                    let mut ids = event.evidence_refs.iter().filter_map(|value| {
                        value
                            .strip_prefix("reconciliation:")
                            .filter(|id| !id.trim().is_empty())
                    });
                    let reconciliation_id = ids
                        .next()
                        .ok_or(CollaborationControlError::Persistence)?
                        .to_owned();
                    if ids.next().is_some() {
                        return Err(CollaborationControlError::Persistence);
                    }
                    HeldDispatchRecoveryState::Reconciling { reconciliation_id }
                }
                Ok(AttemptStatus::Held) if run.status == RunStatus::Held as i32 => {
                    HeldDispatchRecoveryState::Held
                }
                Ok(AttemptStatus::CancellationPending)
                    if run.status == RunStatus::CancellationPending as i32 =>
                {
                    HeldDispatchRecoveryState::CancellationPending
                }
                _ => continue,
            };
            recovery.push(HeldDispatchForRecovery {
                message_id: dispatch.message_id,
                source_event_id: dispatch.source_event_id,
                canonical_payload_digest_sha256: dispatch.canonical_payload_digest_sha256,
                envelope,
                state,
            });
        }
        Ok(recovery)
    }

    pub fn pending_projection_messages(
        &self,
    ) -> Result<Vec<PendingCollaborationProjection>, CollaborationControlError> {
        self.store
            .pending_projection_messages()?
            .into_iter()
            .map(decode_projection_record)
            .collect()
    }

    pub fn retained_projection_messages_for_rebuild(
        &self,
    ) -> Result<Vec<PendingCollaborationProjection>, CollaborationControlError> {
        self.store
            .retained_projection_messages()?
            .into_iter()
            .map(decode_projection_record)
            .collect()
    }

    pub fn acknowledge_projection_message(
        &mut self,
        message_id: &str,
        canonical_payload_digest_sha256: &str,
    ) -> Result<bool, CollaborationControlError> {
        self.store
            .acknowledge_projection_message(message_id, canonical_payload_digest_sha256)
            .map_err(Into::into)
    }

    pub fn inspect_store(&self) -> Result<CollaborationStoreInspection, CollaborationControlError> {
        self.store.inspect().map_err(Into::into)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, CollaborationControlError> {
        self.store.integrity_is_ok().map_err(Into::into)
    }

    fn create_run(
        &mut self,
        value: &CreateRunCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        if !create_run_is_complete(value) {
            return Ok(error_result(
                CollaborationErrorCode::InvalidArgument,
                "CREATE_RUN_INPUT_INVALID",
                None,
                None,
            ));
        }
        if self.load_snapshot(&value.run_id)?.is_some() {
            return Ok(error_result(
                CollaborationErrorCode::StateConflict,
                "RUN_ALREADY_EXISTS",
                None,
                None,
            ));
        }
        let authorization = match self.guard.validate_create_run(value) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        let now = self.clock.now();
        let plan = value.plan.clone().expect("validated plan");
        let step_id = plan
            .steps
            .first()
            .expect("validated one-step plan")
            .step_id
            .clone();
        let run = RunSnapshot {
            run_id: value.run_id.clone(),
            revision: 1,
            task_id: value.task_id.clone(),
            task_revision_at_creation: value.task_revision,
            work_revision: value.work_revision,
            status: RunStatus::Planned as i32,
            plan: Some(plan),
            step_ids: vec![step_id.clone()],
            hold_reason_code: None,
            created_at: Some(now),
            updated_at: Some(now),
        };
        let step = StepSnapshot {
            step_id,
            run_id: value.run_id.clone(),
            revision: 1,
            status: StepStatus::Ready as i32,
            attempt_ids: Vec::new(),
            current_attempt_id: None,
            artifact_set_id: None,
            return_handoff_id: None,
            hold_reason_code: None,
            updated_at: Some(now),
        };
        let snapshot = CollaborationSnapshot {
            run: Some(run),
            steps: vec![step],
            attempts: Vec::new(),
        };
        self.persist(
            command,
            principal,
            snapshot,
            None,
            Some(0),
            None,
            CollaborationEventKind::RunCreated,
            authorization.evidence_refs,
            None,
            now,
        )
    }

    fn activate_run(
        &mut self,
        value: &ActivateRunCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("ACTIVATE_RUN_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let run = snapshot.run.as_ref().expect("stored run");
        if run.revision != base.expected_run_revision {
            return Ok(run_revision_conflict(run.revision));
        }
        if run.status != RunStatus::Planned as i32 {
            return Ok(state_conflict("RUN_MUST_BE_PLANNED"));
        }
        let authorization = match self.guard.validate_activate_run(value, run) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        let now = self.clock.now();
        let previous_run_revision = run.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.status = RunStatus::Active as i32;
        run.updated_at = Some(now);
        self.persist(
            command,
            principal,
            snapshot,
            Some(previous_run_revision),
            None,
            None,
            CollaborationEventKind::RunActivated,
            authorization.evidence_refs,
            None,
            now,
        )
    }

    fn create_attempt(
        &mut self,
        value: &CreateAttemptCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("CREATE_ATTEMPT_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let run = snapshot.run.as_ref().expect("stored run");
        if run.revision != base.expected_run_revision {
            return Ok(run_revision_conflict(run.revision));
        }
        if run.status != RunStatus::Active as i32 {
            return Ok(state_conflict("RUN_MUST_BE_ACTIVE"));
        }
        let Some(step_index) = snapshot
            .steps
            .iter()
            .position(|step| step.step_id == value.step_id)
        else {
            return Ok(not_found("COLLABORATION_STEP_NOT_FOUND"));
        };
        let step = &snapshot.steps[step_index];
        if step.revision != value.expected_step_revision {
            return Ok(entity_revision_conflict(run.revision, step.revision));
        }
        if !matches!(
            StepStatus::try_from(step.status),
            Ok(StepStatus::Ready | StepStatus::Active)
        ) {
            return Ok(state_conflict("STEP_NOT_ATTEMPTABLE"));
        }
        if value.attempt_id.trim().is_empty()
            || value.harness_id.trim().is_empty()
            || value.workspace_ref.trim().is_empty()
            || !value
                .capability_profile_ref
                .as_ref()
                .is_some_and(contract_reference_is_complete)
            || snapshot
                .attempts
                .iter()
                .any(|attempt| attempt.attempt_id == value.attempt_id)
        {
            return Ok(invalid("CREATE_ATTEMPT_INPUT_INVALID"));
        }
        if active_attempt_count(&snapshot) >= 1 || step.current_attempt_id.is_some() {
            return Ok(error_result(
                CollaborationErrorCode::CapacityExhausted,
                "V01_SINGLE_ACTIVE_ATTEMPT_CAPACITY_EXHAUSTED",
                Some(run.revision),
                Some(step.revision),
            ));
        }
        let max_attempts = run
            .plan
            .as_ref()
            .and_then(|plan| plan.steps.iter().find(|item| item.step_id == step.step_id))
            .map(|item| item.max_attempts)
            .unwrap_or_default();
        let attempt_number = u32::try_from(step.attempt_ids.len() + 1).unwrap_or(u32::MAX);
        if attempt_number > max_attempts {
            return Ok(error_result(
                CollaborationErrorCode::CapacityExhausted,
                "STEP_MAX_ATTEMPTS_EXHAUSTED",
                Some(run.revision),
                Some(step.revision),
            ));
        }
        let authorization = match self.guard.validate_create_attempt(value, run, step) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        let now = self.clock.now();
        let previous_run_revision = run.revision;
        let previous_step_revision = step.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = StepStatus::Active as i32;
        step.attempt_ids.push(value.attempt_id.clone());
        step.current_attempt_id = Some(value.attempt_id.clone());
        step.updated_at = Some(now);
        snapshot.attempts.push(AttemptSnapshot {
            attempt_id: value.attempt_id.clone(),
            run_id: base.run_id.clone(),
            step_id: value.step_id.clone(),
            revision: 1,
            attempt_number,
            status: AttemptStatus::Created as i32,
            harness_id: value.harness_id.clone(),
            capability_profile_ref: value.capability_profile_ref.clone(),
            workspace_ref: value.workspace_ref.clone(),
            dispatch_id: None,
            dispatch_fingerprint: None,
            harness_session_ref: None,
            last_harness_sequence: 0,
            lease: None,
            latest_checkpoint_id: None,
            recovery_class: RecoveryClass::ReconcileBeforeRetry as i32,
            hold_reason_code: None,
            created_at: Some(now),
            updated_at: Some(now),
        });
        self.persist(
            command,
            principal,
            snapshot,
            Some(previous_run_revision),
            Some(previous_step_revision),
            Some(0),
            CollaborationEventKind::AttemptCreated,
            authorization.evidence_refs,
            None,
            now,
        )
    }

    fn acquire_lease(
        &mut self,
        value: &AcquireAttemptLeaseCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("ACQUIRE_LEASE_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if !matches!(
            AttemptStatus::try_from(attempt.status),
            Ok(AttemptStatus::Created | AttemptStatus::Interrupted)
        ) {
            return Ok(state_conflict("ATTEMPT_NOT_LEASEABLE"));
        }
        if value.owner_instance_id.trim().is_empty()
            || !value
                .lease_policy_ref
                .as_ref()
                .is_some_and(contract_reference_is_complete)
        {
            return Ok(invalid("LEASE_INPUT_INVALID"));
        }
        let authorization = match self.guard.authorize_lease(value, attempt) {
            Ok(value) if value.ttl_seconds > 0 => value,
            Ok(_) => return Ok(invalid("LEASE_TTL_INVALID")),
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        let now = self.clock.now();
        let previous_fence = attempt
            .lease
            .as_ref()
            .map_or(0, |lease| lease.fencing_token);
        if let Some(lease) = attempt.lease.as_ref()
            && !timestamp_expired(lease.expires_at.as_ref(), &now)
        {
            return Ok(state_conflict("ATTEMPT_LEASE_STILL_ACTIVE"));
        }
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let expires_at = Timestamp {
            seconds: now
                .seconds
                .saturating_add(i64::try_from(authorization.ttl_seconds).unwrap_or(i64::MAX)),
            nanos: now.nanos,
        };
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Leased as i32;
        attempt.lease = Some(Lease {
            lease_id: Uuid::now_v7().to_string(),
            owner_instance_id: value.owner_instance_id.clone(),
            fencing_token: previous_fence + 1,
            acquired_at: Some(now),
            expires_at: Some(expires_at),
            heartbeat_at: Some(now),
            lease_policy_ref: value.lease_policy_ref.clone(),
        });
        attempt.updated_at = Some(now);
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::LeaseAcquired,
            authorization.evidence_refs,
            None,
            now,
        )
    }

    fn record_dispatch_intent(
        &mut self,
        value: &RecordDispatchIntentCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("DISPATCH_INTENT_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::Leased as i32 {
            return Ok(state_conflict("ATTEMPT_MUST_BE_LEASED"));
        }
        let Some(lease) = attempt.lease.as_ref() else {
            return Ok(state_conflict("CURRENT_LEASE_REQUIRED"));
        };
        if lease.lease_id != value.lease_id || lease.fencing_token != value.fencing_token {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        let now = self.clock.now();
        if timestamp_expired(lease.expires_at.as_ref(), &now) {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.dispatch_id.trim().is_empty() || !sha256_is_complete(&value.dispatch_fingerprint) {
            return Ok(invalid("DISPATCH_IDENTITY_INVALID"));
        }
        let material = match self.guard.resolve_dispatch_material(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        if !dispatch_material_is_complete(&material) {
            return Ok(guard_error(ReferenceGuardRejection::ContractMismatch));
        }
        if material.route_binding.as_ref().is_some_and(|binding| {
            attempt
                .capability_profile_ref
                .as_ref()
                .is_none_or(|reference| reference.contract_id != binding.capability_profile_id)
        }) {
            return Ok(guard_error(ReferenceGuardRejection::ContractMismatch));
        }
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let mut envelope = build_dispatch_envelope(
            command_metadata(command).expect("validated metadata"),
            &snapshot,
            step_index,
            attempt_index,
            value,
            &material,
            &now,
        );
        let fingerprint = canonical_dispatch_fingerprint(&envelope);
        if fingerprint != value.dispatch_fingerprint {
            return Ok(error_result(
                CollaborationErrorCode::ContractMismatch,
                "DISPATCH_FINGERPRINT_MISMATCH",
                Some(run_previous),
                Some(attempt_previous),
            ));
        }
        envelope.dispatch_fingerprint = fingerprint.clone();
        envelope
            .meta
            .as_mut()
            .expect("dispatch metadata")
            .request_digest_sha256 = fingerprint;

        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::DispatchPending as i32;
        attempt.dispatch_id = Some(value.dispatch_id.clone());
        attempt.dispatch_fingerprint = Some(value.dispatch_fingerprint.clone());
        attempt.updated_at = Some(now);
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::DispatchIntentRecorded,
            material.evidence_refs,
            Some(envelope),
            now,
        )
    }

    fn record_delivery_receipt(
        &mut self,
        value: &RecordDeliveryReceiptCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("DELIVERY_RECEIPT_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::DispatchPending as i32 {
            return Ok(state_conflict("ATTEMPT_MUST_BE_DISPATCH_PENDING"));
        }
        if attempt.dispatch_id.as_deref() != Some(value.dispatch_id.as_str()) {
            return Ok(error_result(
                CollaborationErrorCode::ContractMismatch,
                "DISPATCH_ID_MISMATCH",
                Some(snapshot.run.as_ref().expect("stored run").revision),
                Some(attempt.revision),
            ));
        }
        if !current_fence_matches(attempt, value.fencing_token) {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.delivery_receipt_id.trim().is_empty()
            || !sha256_is_complete(&value.receipt_digest_sha256)
        {
            return Ok(invalid("DELIVERY_RECEIPT_IDENTITY_INVALID"));
        }
        let resolved = match self.guard.resolve_delivery_receipt(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        if resolved
            .harness_session_ref
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Ok(guard_error(ReferenceGuardRejection::ContractMismatch));
        }

        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Dispatched as i32;
        if resolved.harness_session_ref.is_some() {
            attempt.harness_session_ref = resolved.harness_session_ref;
        }
        attempt.updated_at = Some(now);
        let mut evidence = resolved.evidence_refs;
        evidence.push(format!("delivery-receipt:{}", value.delivery_receipt_id));
        evidence.push(format!(
            "delivery-receipt-digest:{}",
            value.receipt_digest_sha256
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::DeliveryRecorded,
            evidence,
            None,
            now,
        )
    }

    fn record_harness_ack(
        &mut self,
        value: &RecordHarnessAckCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("HARNESS_ACK_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status == AttemptStatus::DispatchPending as i32 {
            return Ok(state_conflict("DELIVERY_RECEIPT_REQUIRED"));
        }
        if attempt.status != AttemptStatus::Dispatched as i32 {
            return Ok(state_conflict("ATTEMPT_MUST_BE_DISPATCHED"));
        }
        if attempt.dispatch_id.as_deref() != Some(value.dispatch_id.as_str()) {
            return Ok(error_result(
                CollaborationErrorCode::ContractMismatch,
                "DISPATCH_ID_MISMATCH",
                Some(snapshot.run.as_ref().expect("stored run").revision),
                Some(attempt.revision),
            ));
        }
        if !current_fence_matches(attempt, value.fencing_token) {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.harness_sequence <= attempt.last_harness_sequence {
            return Ok(sequence_conflict(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.ack_receipt_id.trim().is_empty()
            || !sha256_is_complete(&value.receipt_digest_sha256)
        {
            return Ok(invalid("HARNESS_ACK_IDENTITY_INVALID"));
        }
        let resolved = match self.guard.resolve_harness_ack(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        if let (Some(existing), Some(resolved)) = (
            attempt.harness_session_ref.as_ref(),
            resolved.harness_session_ref.as_ref(),
        ) && existing != resolved
        {
            return Ok(error_result(
                CollaborationErrorCode::ContractMismatch,
                "HARNESS_SESSION_REF_MISMATCH",
                Some(snapshot.run.as_ref().expect("stored run").revision),
                Some(attempt.revision),
            ));
        }
        if resolved
            .harness_session_ref
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Ok(guard_error(ReferenceGuardRejection::ContractMismatch));
        }

        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Acknowledged as i32;
        attempt.last_harness_sequence = value.harness_sequence;
        if resolved.harness_session_ref.is_some() {
            attempt.harness_session_ref = resolved.harness_session_ref;
        }
        attempt.updated_at = Some(now);
        let mut evidence = resolved.evidence_refs;
        evidence.push(format!("ack-receipt:{}", value.ack_receipt_id));
        evidence.push(format!(
            "harness-observation-digest:{}",
            value.receipt_digest_sha256
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::AckRecorded,
            evidence,
            None,
            now,
        )
    }

    fn record_running_observation(
        &mut self,
        value: &RecordRunningObservationCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("RUNNING_OBSERVATION_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::Acknowledged as i32 {
            return Ok(state_conflict("HARNESS_ACK_REQUIRED"));
        }
        if !current_fence_matches(attempt, value.fencing_token) {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.harness_sequence <= attempt.last_harness_sequence {
            return Ok(sequence_conflict(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.lifecycle_event_id.trim().is_empty()
            || !sha256_is_complete(&value.event_digest_sha256)
        {
            return Ok(invalid("RUNNING_OBSERVATION_IDENTITY_INVALID"));
        }
        let authorization = match self.guard.validate_running_observation(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };

        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Running as i32;
        attempt.last_harness_sequence = value.harness_sequence;
        attempt.updated_at = Some(now);
        let mut evidence = authorization.evidence_refs;
        evidence.push(format!("lifecycle-event:{}", value.lifecycle_event_id));
        evidence.push(format!(
            "harness-observation-digest:{}",
            value.event_digest_sha256
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::RunningObserved,
            evidence,
            None,
            now,
        )
    }

    fn record_attempt_return(
        &mut self,
        value: &RecordAttemptReturnCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("ATTEMPT_RETURN_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if !matches!(
            AttemptStatus::try_from(attempt.status),
            Ok(AttemptStatus::Acknowledged | AttemptStatus::Running)
        ) {
            return Ok(state_conflict("ATTEMPT_NOT_ACCEPTING_RETURN"));
        }
        if !current_fence_matches(attempt, value.fencing_token) {
            return Ok(fencing_rejected(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.harness_sequence <= attempt.last_harness_sequence {
            return Ok(sequence_conflict(
                snapshot.run.as_ref().expect("stored run").revision,
                attempt.revision,
            ));
        }
        if value.artifact_return_receipt_id.trim().is_empty()
            || !sha256_is_complete(&value.receipt_digest_sha256)
        {
            return Ok(invalid("ARTIFACT_RETURN_RECEIPT_IDENTITY_INVALID"));
        }
        let resolved = match self.guard.resolve_attempt_return(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        if resolved.artifact_set_id.trim().is_empty()
            || resolved.return_handoff_id.trim().is_empty()
            || resolved.dispatch_id.trim().is_empty()
            || resolved.evidence_refs.is_empty()
            || resolved
                .evidence_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Ok(invalid("ARTIFACT_RETURN_RESOLUTION_INVALID"));
        }

        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.status = RunStatus::ReturnPending as i32;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = StepStatus::ReturnPending as i32;
        step.artifact_set_id = Some(resolved.artifact_set_id.clone());
        step.return_handoff_id = Some(resolved.return_handoff_id.clone());
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Returned as i32;
        attempt.last_harness_sequence = value.harness_sequence;
        attempt.updated_at = Some(now);
        let mut evidence = resolved.evidence_refs;
        evidence.push(format!(
            "artifact-return-receipt:{}",
            value.artifact_return_receipt_id
        ));
        evidence.push(format!(
            "artifact-return-receipt-digest:{}",
            value.receipt_digest_sha256
        ));
        evidence.push(format!("artifact-set:{}", resolved.artifact_set_id));
        evidence.push(format!("return-handoff:{}", resolved.return_handoff_id));
        evidence.push(format!("dispatch:{}", resolved.dispatch_id));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::ReturnRecorded,
            evidence,
            None,
            now,
        )
    }

    fn commit_step_return(
        &mut self,
        value: &CommitStepReturnCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("STEP_RETURN_COMMIT_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let run = snapshot.run.as_ref().expect("stored run");
        if run.revision != base.expected_run_revision {
            return Ok(run_revision_conflict(run.revision));
        }
        let Some(step_index) = snapshot
            .steps
            .iter()
            .position(|step| step.step_id == value.step_id)
        else {
            return Ok(not_found("COLLABORATION_STEP_NOT_FOUND"));
        };
        let step = &snapshot.steps[step_index];
        if step.revision != value.expected_step_revision {
            return Ok(entity_revision_conflict(run.revision, step.revision));
        }
        let Some(attempt_index) = snapshot.attempts.iter().position(|attempt| {
            attempt.attempt_id == value.attempt_id && attempt.step_id == value.step_id
        }) else {
            return Ok(not_found("COLLABORATION_ATTEMPT_NOT_FOUND"));
        };
        let attempt = &snapshot.attempts[attempt_index];
        if run.status != RunStatus::ReturnPending as i32
            || step.status != StepStatus::ReturnPending as i32
            || attempt.status != AttemptStatus::Returned as i32
        {
            return Ok(state_conflict("STEP_RETURN_COMMIT_NOT_PENDING"));
        }
        if step.current_attempt_id.as_deref() != Some(value.attempt_id.as_str())
            || step.artifact_set_id.as_deref() != Some(value.artifact_set_id.as_str())
            || step.return_handoff_id.as_deref() != Some(value.return_handoff_id.as_str())
            || value.artifact_set_id.trim().is_empty()
            || value.return_handoff_id.trim().is_empty()
        {
            return Ok(error_result(
                CollaborationErrorCode::ContractMismatch,
                "STEP_RETURN_COMMIT_REFERENCE_MISMATCH",
                Some(run.revision),
                Some(step.revision),
            ));
        }
        let resolved = match self.guard.resolve_step_return(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        if resolved.artifact_set_id != value.artifact_set_id
            || resolved.return_handoff_id != value.return_handoff_id
            || resolved.verification_artifact_id.trim().is_empty()
            || resolved.evidence_refs.is_empty()
            || resolved
                .evidence_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Ok(invalid("STEP_RETURN_VERIFICATION_PROOF_INVALID"));
        }

        let now = self.clock.now();
        let previous_run_revision = run.revision;
        let previous_step_revision = step.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.status = RunStatus::Returned as i32;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = StepStatus::Returned as i32;
        step.updated_at = Some(now);
        let mut evidence = resolved.evidence_refs;
        evidence.push(format!(
            "verification-artifact:{}",
            resolved.verification_artifact_id
        ));
        evidence.push(format!("artifact-set:{}", value.artifact_set_id));
        evidence.push(format!("return-handoff:{}", value.return_handoff_id));
        self.persist(
            command,
            principal,
            snapshot,
            Some(previous_run_revision),
            Some(previous_step_revision),
            None,
            CollaborationEventKind::StepReturnCommitted,
            evidence,
            None,
            now,
        )
    }

    fn request_attempt_cancellation(
        &mut self,
        value: &RequestAttemptCancellationCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("CANCELLATION_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(value) => value,
            Err(value) => return Ok(*value),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if !matches!(
            AttemptStatus::try_from(attempt.status),
            Ok(AttemptStatus::DispatchPending
                | AttemptStatus::Dispatched
                | AttemptStatus::Acknowledged
                | AttemptStatus::Running)
        ) {
            return Ok(state_conflict("ATTEMPT_NOT_CANCELLABLE"));
        }
        if value.task_cancellation_request_id.trim().is_empty() {
            return Ok(invalid("TASK_CANCELLATION_REQUEST_REQUIRED"));
        }
        let authorization = match self.guard.validate_cancellation_request(value, &snapshot) {
            Ok(value) => value,
            Err(value) => return Ok(guard_error(value)),
        };
        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("run");
        run.revision += 1;
        run.status = RunStatus::CancellationPending as i32;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::CancellationPending as i32;
        attempt.updated_at = Some(now);
        let mut evidence = authorization.evidence_refs;
        evidence.push(format!(
            "task-cancellation:{}",
            value.task_cancellation_request_id
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::CancellationRequested,
            evidence,
            None,
            now,
        )
    }

    fn record_attempt_cancellation_outcome(
        &mut self,
        value: &RecordAttemptCancellationOutcomeCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("CANCELLATION_OUTCOME_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(value) => value,
            Err(value) => return Ok(*value),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::CancellationPending as i32 {
            return Ok(state_conflict("CANCELLATION_MUST_BE_PENDING"));
        }
        if value.cancellation_receipt_id.trim().is_empty() {
            return Ok(invalid("CANCELLATION_RECEIPT_REQUIRED"));
        }
        let disposition = match AttemptCancellationDisposition::try_from(value.disposition) {
            Ok(AttemptCancellationDisposition::Unspecified) | Err(_) => {
                return Ok(invalid("CANCELLATION_DISPOSITION_INVALID"));
            }
            Ok(value) => value,
        };
        let authorization = match self.guard.validate_cancellation_outcome(value, &snapshot) {
            Ok(value) => value,
            Err(value) => return Ok(guard_error(value)),
        };
        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let (run_status, step_status, attempt_status, recovery, hold) = match disposition {
            AttemptCancellationDisposition::CancelledConfirmed => (
                RunStatus::Cancelled,
                StepStatus::Cancelled,
                AttemptStatus::Cancelled,
                RecoveryClass::ReconcileBeforeRetry,
                None,
            ),
            AttemptCancellationDisposition::ReturnFound => (
                RunStatus::ReturnPending,
                StepStatus::ReturnPending,
                AttemptStatus::Returned,
                RecoveryClass::ReconcileBeforeRetry,
                None,
            ),
            AttemptCancellationDisposition::OutcomeUnknown => (
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::OutcomeUnknown,
                RecoveryClass::ReconcileBeforeRetry,
                Some("CANCELLATION_OUTCOME_UNKNOWN".to_owned()),
            ),
            AttemptCancellationDisposition::Unspecified => unreachable!(),
        };
        let run = snapshot.run.as_mut().expect("run");
        run.revision += 1;
        run.status = run_status as i32;
        run.hold_reason_code = hold.clone();
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = step_status as i32;
        step.hold_reason_code = hold.clone();
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = attempt_status as i32;
        attempt.recovery_class = recovery as i32;
        attempt.hold_reason_code = hold;
        attempt.updated_at = Some(now);
        let mut evidence = authorization.evidence_refs;
        evidence.push(format!(
            "cancellation-receipt:{}",
            value.cancellation_receipt_id
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::CancellationRecorded,
            evidence,
            None,
            now,
        )
    }

    fn begin_attempt_reconciliation(
        &mut self,
        value: &BeginAttemptReconciliationCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("RECONCILIATION_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(value) => value,
            Err(value) => return Ok(*value),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::OutcomeUnknown as i32 {
            return Ok(state_conflict("OUTCOME_UNKNOWN_REQUIRED"));
        }
        if value.reconciliation_id.trim().is_empty() {
            return Ok(invalid("RECONCILIATION_ID_REQUIRED"));
        }
        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("run");
        run.revision += 1;
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::Reconciling as i32;
        attempt.updated_at = Some(now);
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::ReconciliationStarted,
            vec![format!("reconciliation:{}", value.reconciliation_id)],
            None,
            now,
        )
    }

    fn record_attempt_reconciliation(
        &mut self,
        value: &RecordAttemptReconciliationCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("RECONCILIATION_RESULT_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(value) => value,
            Err(value) => return Ok(*value),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if attempt.status != AttemptStatus::Reconciling as i32 {
            return Ok(state_conflict("RECONCILIATION_NOT_ACTIVE"));
        }
        if value.reconciliation_id.trim().is_empty() || value.evidence_id.trim().is_empty() {
            return Ok(invalid("RECONCILIATION_EVIDENCE_REQUIRED"));
        }
        let latest = self
            .store
            .latest_event_blob(&base.run_id)?
            .ok_or(CollaborationControlError::Persistence)?;
        let latest = CollaborationEvent::decode(latest.as_slice())?;
        if latest.kind != CollaborationEventKind::ReconciliationStarted as i32
            || latest.attempt_id.as_deref() != Some(base.attempt_id.as_str())
            || !latest
                .evidence_refs
                .iter()
                .any(|item| item == &format!("reconciliation:{}", value.reconciliation_id))
        {
            return Ok(state_conflict("RECONCILIATION_ID_MISMATCH"));
        }
        let disposition = match ReconciliationDisposition::try_from(value.disposition) {
            Ok(ReconciliationDisposition::Unspecified) | Err(_) => {
                return Ok(invalid("RECONCILIATION_DISPOSITION_INVALID"));
            }
            Ok(value) => value,
        };
        let authorization = match self.guard.validate_reconciliation(value, &snapshot) {
            Ok(value) => value,
            Err(value) => return Ok(guard_error(value)),
        };
        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let (run_status, step_status, attempt_status, recovery, hold) = match disposition {
            ReconciliationDisposition::ReturnFound => (
                RunStatus::ReturnPending,
                StepStatus::ReturnPending,
                AttemptStatus::Returned,
                RecoveryClass::ReconcileBeforeRetry,
                None,
            ),
            ReconciliationDisposition::NoEffectProven
            | ReconciliationDisposition::RetryIdempotent => (
                RunStatus::Active,
                StepStatus::Active,
                AttemptStatus::Interrupted,
                RecoveryClass::RetryIdempotent,
                None,
            ),
            ReconciliationDisposition::ResumeSafe => (
                RunStatus::Active,
                StepStatus::Active,
                AttemptStatus::Interrupted,
                RecoveryClass::ResumeSafe,
                None,
            ),
            ReconciliationDisposition::Compensate => (
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::Held,
                RecoveryClass::Compensatable,
                Some("COMPENSATION_REQUIRED".to_owned()),
            ),
            ReconciliationDisposition::ManualOnly => (
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::Held,
                RecoveryClass::ManualOnly,
                Some("MANUAL_RECOVERY_REQUIRED".to_owned()),
            ),
            ReconciliationDisposition::IrreversibleUnknown => (
                RunStatus::Held,
                StepStatus::Held,
                AttemptStatus::Held,
                RecoveryClass::Irreversible,
                Some("IRREVERSIBLE_OUTCOME_UNKNOWN".to_owned()),
            ),
            ReconciliationDisposition::Unspecified => unreachable!(),
        };
        let run = snapshot.run.as_mut().expect("run");
        run.revision += 1;
        run.status = run_status as i32;
        run.hold_reason_code = hold.clone();
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = step_status as i32;
        step.hold_reason_code = hold.clone();
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = attempt_status as i32;
        attempt.recovery_class = recovery as i32;
        attempt.hold_reason_code = hold;
        attempt.updated_at = Some(now);
        let mut evidence = authorization.evidence_refs;
        evidence.push(format!("reconciliation-evidence:{}", value.evidence_id));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::ReconciliationRecorded,
            evidence,
            None,
            now,
        )
    }

    fn mark_outcome_unknown(
        &mut self,
        value: &MarkAttemptOutcomeUnknownCommand,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let Some(base) = value.base.as_ref() else {
            return Ok(invalid("OUTCOME_UNKNOWN_BASE_REQUIRED"));
        };
        let Some(mut snapshot) = self.load_snapshot(&base.run_id)? else {
            return Ok(not_found("COLLABORATION_RUN_NOT_FOUND"));
        };
        let (step_index, attempt_index) = match validate_attempt_preconditions(&snapshot, base) {
            Ok(indexes) => indexes,
            Err(result) => return Ok(*result),
        };
        let attempt = &snapshot.attempts[attempt_index];
        if !matches!(
            AttemptStatus::try_from(attempt.status),
            Ok(AttemptStatus::DispatchPending
                | AttemptStatus::Dispatched
                | AttemptStatus::Acknowledged
                | AttemptStatus::Running
                | AttemptStatus::CancellationPending)
        ) {
            return Ok(state_conflict("ATTEMPT_CANNOT_BECOME_OUTCOME_UNKNOWN"));
        }
        if value.reason_code.trim().is_empty() || value.uncertainty_evidence_id.trim().is_empty() {
            return Ok(invalid("UNCERTAINTY_EVIDENCE_REQUIRED"));
        }
        let authorization = match self.guard.validate_unknown_outcome(value, &snapshot) {
            Ok(value) => value,
            Err(rejection) => return Ok(guard_error(rejection)),
        };
        let now = self.clock.now();
        let run_previous = snapshot.run.as_ref().expect("stored run").revision;
        let step_previous = snapshot.steps[step_index].revision;
        let attempt_previous = attempt.revision;
        let run = snapshot.run.as_mut().expect("stored run");
        run.revision += 1;
        run.status = RunStatus::Held as i32;
        run.hold_reason_code = Some(value.reason_code.clone());
        run.updated_at = Some(now);
        let step = &mut snapshot.steps[step_index];
        step.revision += 1;
        step.status = StepStatus::Held as i32;
        step.hold_reason_code = Some(value.reason_code.clone());
        step.updated_at = Some(now);
        let attempt = &mut snapshot.attempts[attempt_index];
        attempt.revision += 1;
        attempt.status = AttemptStatus::OutcomeUnknown as i32;
        attempt.recovery_class = RecoveryClass::ReconcileBeforeRetry as i32;
        attempt.hold_reason_code = Some(value.reason_code.clone());
        attempt.updated_at = Some(now);
        let mut evidence = authorization.evidence_refs;
        evidence.push(format!(
            "uncertainty-evidence:{}",
            value.uncertainty_evidence_id
        ));
        self.persist(
            command,
            principal,
            snapshot,
            Some(run_previous),
            Some(step_previous),
            Some(attempt_previous),
            CollaborationEventKind::OutcomeMarkedUnknown,
            evidence,
            None,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn persist(
        &mut self,
        command: &CollaborationCommand,
        principal: &AuthenticatedCollaborationPrincipal,
        snapshot: CollaborationSnapshot,
        previous_run_revision: Option<u64>,
        changed_step_previous_revision: Option<u64>,
        changed_attempt_previous_revision: Option<u64>,
        kind: CollaborationEventKind,
        evidence_refs: Vec<String>,
        dispatch_envelope: Option<DispatchEnvelope>,
        now: Timestamp,
    ) -> Result<CollaborationCommandResult, CollaborationControlError> {
        let operation = operation_name(command).expect("validated operation");
        let meta = command_metadata(command).expect("validated metadata");
        let run = snapshot.run.as_ref().expect("mutation run");
        let changed_step = changed_step_previous_revision.and_then(|previous| {
            changed_step_id(command).and_then(|step_id| {
                snapshot
                    .steps
                    .iter()
                    .find(|step| step.step_id == step_id)
                    .map(|step| (step, previous))
            })
        });
        let changed_attempt = changed_attempt_previous_revision.and_then(|previous| {
            changed_attempt_id(command).and_then(|attempt_id| {
                snapshot
                    .attempts
                    .iter()
                    .find(|attempt| attempt.attempt_id == attempt_id)
                    .map(|attempt| (attempt, previous))
            })
        });
        let event_id = Uuid::now_v7().to_string();
        let event = CollaborationEvent {
            event_id: event_id.clone(),
            command_id: meta.command_id.clone(),
            kind: kind as i32,
            run_id: run.run_id.clone(),
            expected_run_revision: previous_run_revision.unwrap_or(0),
            resulting_run_revision: run.revision,
            step_id: changed_step.map(|(step, _)| step.step_id.clone()),
            resulting_step_revision: changed_step.map(|(step, _)| step.revision),
            attempt_id: changed_attempt.map(|(attempt, _)| attempt.attempt_id.clone()),
            resulting_attempt_revision: changed_attempt.map(|(attempt, _)| attempt.revision),
            authenticated_principal_id: principal.principal_id.clone(),
            authority_ref: AUTHORITY_REF.to_owned(),
            idempotency_key: meta.idempotency_key.clone(),
            request_digest_sha256: meta.request_digest_sha256.clone(),
            correlation_id: meta.correlation_id.clone(),
            causation_id: meta.causation_id.clone(),
            evidence_refs,
            occurred_at: Some(now),
        };
        let result = CollaborationCommandResult {
            replayed: false,
            outcome: Some(collaboration_command_result::Outcome::Snapshot(
                snapshot.clone(),
            )),
            committed_event: Some(event.clone()),
        };
        let event_bytes = event.encode_to_vec();
        let projection_bytes = result.encode_to_vec();
        let mut outboxes = vec![OutboxWrite {
            message_id: Uuid::now_v7().to_string(),
            attempt_id: None,
            destination_domain: "local-read-model".to_owned(),
            payload_kind: "collaboration-snapshot-v1".to_owned(),
            canonical_payload_digest_sha256: sha256_bytes(&projection_bytes),
            payload: projection_bytes,
        }];
        if let Some(envelope) = dispatch_envelope {
            let payload = envelope.encode_to_vec();
            outboxes.push(OutboxWrite {
                message_id: Uuid::now_v7().to_string(),
                attempt_id: changed_attempt.map(|(attempt, _)| attempt.attempt_id.clone()),
                destination_domain: "harness-adapter".to_owned(),
                payload_kind: "dispatch-envelope".to_owned(),
                canonical_payload_digest_sha256: sha256_bytes(&payload),
                payload,
            });
        }

        let commit = CollaborationCommit {
            run: RunWrite {
                run_id: run.run_id.clone(),
                task_id: run.task_id.clone(),
                work_revision: run.work_revision,
                revision: run.revision,
                status: run.status,
                snapshot: run.encode_to_vec(),
                expected_revision: previous_run_revision,
            },
            step: changed_step.map(|(step, previous)| StepWrite {
                step_id: step.step_id.clone(),
                run_id: step.run_id.clone(),
                revision: step.revision,
                status: step.status,
                snapshot: step.encode_to_vec(),
                expected_revision: (previous != 0).then_some(previous),
            }),
            attempt: changed_attempt.map(|(attempt, previous)| AttemptWrite {
                attempt_id: attempt.attempt_id.clone(),
                run_id: attempt.run_id.clone(),
                step_id: attempt.step_id.clone(),
                revision: attempt.revision,
                status: attempt.status,
                snapshot: attempt.encode_to_vec(),
                expected_revision: (previous != 0).then_some(previous),
            }),
            event_id,
            command_id: meta.command_id.clone(),
            request_digest_sha256: meta.request_digest_sha256.clone(),
            event: event_bytes,
            authenticated_principal_id: principal.principal_id.clone(),
            operation: operation.to_owned(),
            idempotency_scope: meta.idempotency_scope.clone(),
            idempotency_key: meta.idempotency_key.clone(),
            result: result.encode_to_vec(),
            outboxes,
            hold_dispatch_for_attempt: matches!(
                kind,
                CollaborationEventKind::OutcomeMarkedUnknown
                    | CollaborationEventKind::CancellationRequested
            )
            .then(|| {
                changed_attempt
                    .expect("unknown outcome changes attempt")
                    .0
                    .attempt_id
                    .clone()
            }),
            deliver_dispatch_for_attempt: (kind == CollaborationEventKind::DeliveryRecorded).then(
                || {
                    changed_attempt
                        .expect("delivery receipt changes attempt")
                        .0
                        .attempt_id
                        .clone()
                },
            ),
            committed_at_seconds: now.seconds,
        };
        self.store.commit(&commit)?;
        Ok(result)
    }

    fn load_snapshot(
        &self,
        run_id: &str,
    ) -> Result<Option<CollaborationSnapshot>, CollaborationControlError> {
        let Some(blobs) = self.store.snapshot_blobs(run_id)? else {
            return Ok(None);
        };
        Ok(Some(CollaborationSnapshot {
            run: Some(RunSnapshot::decode(blobs.run.as_slice())?),
            steps: blobs
                .steps
                .iter()
                .map(|bytes| StepSnapshot::decode(bytes.as_slice()))
                .collect::<Result<Vec<_>, _>>()?,
            attempts: blobs
                .attempts
                .iter()
                .map(|bytes| AttemptSnapshot::decode(bytes.as_slice()))
                .collect::<Result<Vec<_>, _>>()?,
        }))
    }
}

fn authorize_harness_dispatch_read(
    principal: &AuthenticatedCollaborationPrincipal,
) -> Result<(), CollaborationControlError> {
    if !principal.authenticated
        || principal.kind != CollaborationPrincipalKind::HarnessAdapter
        || principal.principal_id.trim().is_empty()
    {
        return Err(CollaborationControlError::DispatchPollNotAuthorized);
    }
    Ok(())
}

fn decode_dispatch_outbox_record(
    record: PendingDispatchRecord,
) -> Result<PendingDispatch, CollaborationControlError> {
    let actual_digest = hex::encode(Sha256::digest(record.payload.as_slice()));
    let attempt_id = record
        .attempt_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CollaborationControlError::Persistence)?;
    if record.message_id.trim().is_empty()
        || record.source_event_id.trim().is_empty()
        || record.canonical_payload_digest_sha256 != actual_digest
    {
        return Err(CollaborationControlError::Persistence);
    }
    let envelope = DispatchEnvelope::decode(record.payload.as_slice())?;
    if envelope.attempt_id != attempt_id {
        return Err(CollaborationControlError::Persistence);
    }
    Ok(PendingDispatch {
        message_id: record.message_id,
        source_event_id: record.source_event_id,
        canonical_payload_digest_sha256: record.canonical_payload_digest_sha256,
        envelope,
    })
}

fn delivered_observation_lineage_is_eligible(
    snapshot: &CollaborationSnapshot,
    envelope: &DispatchEnvelope,
) -> Result<bool, CollaborationControlError> {
    if envelope.run_id.trim().is_empty()
        || envelope.step_id.trim().is_empty()
        || envelope.attempt_id.trim().is_empty()
        || envelope.dispatch_id.trim().is_empty()
    {
        return Err(CollaborationControlError::Persistence);
    }
    let run = snapshot
        .run
        .as_ref()
        .filter(|run| run.run_id == envelope.run_id)
        .ok_or(CollaborationControlError::Persistence)?;
    let mut steps = snapshot
        .steps
        .iter()
        .filter(|step| step.step_id == envelope.step_id);
    let step = steps.next().ok_or(CollaborationControlError::Persistence)?;
    if steps.next().is_some() {
        return Err(CollaborationControlError::Persistence);
    }
    let mut attempts = snapshot
        .attempts
        .iter()
        .filter(|attempt| attempt.attempt_id == envelope.attempt_id);
    let attempt = attempts
        .next()
        .ok_or(CollaborationControlError::Persistence)?;
    if attempts.next().is_some()
        || step.run_id != run.run_id
        || attempt.run_id != run.run_id
        || attempt.step_id != step.step_id
        || attempt.dispatch_id.as_deref() != Some(envelope.dispatch_id.as_str())
    {
        return Err(CollaborationControlError::Persistence);
    }

    let run_status =
        RunStatus::try_from(run.status).map_err(|_| CollaborationControlError::Persistence)?;
    let step_status =
        StepStatus::try_from(step.status).map_err(|_| CollaborationControlError::Persistence)?;
    let attempt_status = AttemptStatus::try_from(attempt.status)
        .map_err(|_| CollaborationControlError::Persistence)?;
    let live = run_status == RunStatus::Active
        && step_status == StepStatus::Active
        && matches!(
            attempt_status,
            AttemptStatus::Dispatched | AttemptStatus::Acknowledged | AttemptStatus::Running
        );
    if !live {
        return Ok(false);
    }
    if run
        .step_ids
        .iter()
        .filter(|step_id| step_id.as_str() == envelope.step_id)
        .count()
        != 1
        || step
            .attempt_ids
            .iter()
            .filter(|attempt_id| attempt_id.as_str() == envelope.attempt_id)
            .count()
            != 1
        || step.current_attempt_id.as_deref() != Some(envelope.attempt_id.as_str())
    {
        return Err(CollaborationControlError::Persistence);
    }

    let capability_profile_ref = envelope
        .capability_profile_ref
        .as_ref()
        .ok_or(CollaborationControlError::Persistence)?;
    let request_digest_sha256 = envelope
        .meta
        .as_ref()
        .map(|meta| meta.request_digest_sha256.as_str())
        .ok_or(CollaborationControlError::Persistence)?;
    if envelope.fencing_token == 0
        || !sha256_is_complete(&envelope.dispatch_fingerprint)
        || !sha256_is_complete(request_digest_sha256)
        || !contract_reference_is_complete(capability_profile_ref)
        || attempt.capability_profile_ref.as_ref() != Some(capability_profile_ref)
        || attempt.dispatch_fingerprint.as_deref() != Some(envelope.dispatch_fingerprint.as_str())
        || canonical_dispatch_fingerprint(envelope) != envelope.dispatch_fingerprint
        || request_digest_sha256 != envelope.dispatch_fingerprint
        || !current_fence_matches(attempt, envelope.fencing_token)
    {
        return Err(CollaborationControlError::Persistence);
    }
    Ok(true)
}

fn decode_projection_record(
    record: PendingProjectionRecord,
) -> Result<PendingCollaborationProjection, CollaborationControlError> {
    let result = CollaborationCommandResult::decode(record.payload.as_slice())?;
    let snapshot = match result.outcome {
        Some(collaboration_command_result::Outcome::Snapshot(snapshot)) => snapshot,
        _ => return Err(CollaborationControlError::Persistence),
    };
    let event = result
        .committed_event
        .ok_or(CollaborationControlError::Persistence)?;
    if event.event_id != record.source_event_id
        || event.resulting_run_revision != record.source_revision
    {
        return Err(CollaborationControlError::Persistence);
    }
    Ok(PendingCollaborationProjection {
        message_id: record.message_id,
        source_event_id: record.source_event_id,
        source_revision: record.source_revision,
        canonical_payload_digest_sha256: record.canonical_payload_digest_sha256,
        rebuild_baseline: record.rebuild_baseline,
        snapshot,
        event,
    })
}

fn encode_projection_bootstrap(
    candidate: ProjectionBootstrapCandidate,
) -> Result<ProjectionBootstrapWrite, CollaborationControlError> {
    let run = RunSnapshot::decode(candidate.snapshots.run.as_slice())?;
    let steps = candidate
        .snapshots
        .steps
        .iter()
        .map(|value| StepSnapshot::decode(value.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let attempts = candidate
        .snapshots
        .attempts
        .iter()
        .map(|value| AttemptSnapshot::decode(value.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    let event = CollaborationEvent::decode(candidate.event.as_slice())?;
    if run.run_id != candidate.run_id
        || run.revision != candidate.source_revision
        || event.event_id != candidate.source_event_id
        || event.resulting_run_revision != candidate.source_revision
        || steps.iter().any(|step| step.run_id != candidate.run_id)
        || attempts
            .iter()
            .any(|attempt| attempt.run_id != candidate.run_id)
    {
        return Err(CollaborationControlError::Persistence);
    }
    let result = CollaborationCommandResult {
        replayed: false,
        outcome: Some(collaboration_command_result::Outcome::Snapshot(
            CollaborationSnapshot {
                run: Some(run),
                steps,
                attempts,
            },
        )),
        committed_event: Some(event),
    };
    let payload = result.encode_to_vec();
    let identity = sha256_bytes(
        format!(
            "g4-08a|collaboration|{}|{}|{}",
            candidate.run_id, candidate.source_revision, candidate.source_event_id
        )
        .as_bytes(),
    );
    Ok(ProjectionBootstrapWrite {
        run_id: candidate.run_id,
        source_event_id: candidate.source_event_id,
        source_revision: candidate.source_revision,
        message_id: format!("collaboration-bootstrap-v1-{identity}"),
        canonical_payload_digest_sha256: sha256_bytes(&payload),
        payload,
        created_at_seconds: candidate.created_at_seconds,
    })
}

#[must_use]
pub fn canonical_request_digest(command: &CollaborationCommand) -> Option<String> {
    command.command.as_ref()?;
    let mut canonical = command.clone();
    let meta = command_metadata_mut(&mut canonical)?;
    clear_volatile_metadata(meta);
    Some(sha256_bytes(&canonical.encode_to_vec()))
}

/// Fills the request digest after a command has been assembled. Keeping this
/// beside the canonicalization function prevents internal workflow builders
/// from implementing subtly different digest rules.
pub fn seal_request_digest(command: &mut CollaborationCommand) -> Option<String> {
    let digest = canonical_request_digest(command)?;
    command_metadata_mut(command)?.request_digest_sha256 = digest.clone();
    Some(digest)
}

#[must_use]
pub fn canonical_dispatch_fingerprint(envelope: &DispatchEnvelope) -> String {
    let mut canonical = envelope.clone();
    canonical.dispatch_fingerprint.clear();
    if let Some(meta) = canonical.meta.as_mut() {
        clear_volatile_metadata(meta);
    }
    sha256_bytes(&canonical.encode_to_vec())
}

fn build_dispatch_envelope(
    source_meta: &CommandMetadata,
    snapshot: &CollaborationSnapshot,
    step_index: usize,
    attempt_index: usize,
    command: &RecordDispatchIntentCommand,
    material: &DispatchMaterial,
    now: &Timestamp,
) -> DispatchEnvelope {
    let run = snapshot.run.as_ref().expect("stored run");
    let step = &snapshot.steps[step_index];
    let attempt = &snapshot.attempts[attempt_index];
    let plan = run.plan.as_ref().expect("validated run plan");
    let step_plan = plan
        .steps
        .iter()
        .find(|item| item.step_id == step.step_id)
        .expect("stored step plan");
    DispatchEnvelope {
        meta: Some(CommandMetadata {
            command_id: command.dispatch_id.clone(),
            idempotency_key: command.dispatch_id.clone(),
            idempotency_scope: attempt.attempt_id.clone(),
            request_digest_sha256: String::new(),
            issued_at: Some(*now),
            correlation_id: source_meta.correlation_id.clone(),
            causation_id: Some(source_meta.command_id.clone()),
        }),
        run_id: run.run_id.clone(),
        run_revision: run.revision + 1,
        step_id: step.step_id.clone(),
        step_revision: step.revision + 1,
        attempt_id: attempt.attempt_id.clone(),
        attempt_revision: attempt.revision + 1,
        dispatch_id: command.dispatch_id.clone(),
        dispatch_fingerprint: String::new(),
        fencing_token: command.fencing_token,
        capability_profile_ref: attempt.capability_profile_ref.clone(),
        input_bundle_ref: step_plan.input_bundle_ref.clone(),
        input_bundle_sha256: material.input_bundle_sha256.clone(),
        workspace_ref: attempt.workspace_ref.clone(),
        budget_profile_ref: plan.budget_profile_ref.clone(),
        sandbox_profile_ref: Some(material.sandbox_profile_ref.clone()),
        tool_policy_ref: Some(material.tool_policy_ref.clone()),
        data_egress_policy_ref: Some(material.data_egress_policy_ref.clone()),
        approval_policy_ref: Some(material.approval_policy_ref.clone()),
        session_strategy: material.session_strategy as i32,
        native_session_ref: material.native_session_ref.clone(),
        checkpoint_ref: material.checkpoint_ref.clone(),
        route_binding: material.route_binding.clone(),
    }
}

fn validate_attempt_preconditions(
    snapshot: &CollaborationSnapshot,
    base: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptCommandBase,
) -> Result<(usize, usize), Box<CollaborationCommandResult>> {
    let run = snapshot.run.as_ref().expect("stored run");
    if run.revision != base.expected_run_revision {
        return Err(Box::new(run_revision_conflict(run.revision)));
    }
    let Some(step_index) = snapshot
        .steps
        .iter()
        .position(|step| step.step_id == base.step_id)
    else {
        return Err(Box::new(not_found("COLLABORATION_STEP_NOT_FOUND")));
    };
    let step = &snapshot.steps[step_index];
    if step.revision != base.expected_step_revision {
        return Err(Box::new(entity_revision_conflict(
            run.revision,
            step.revision,
        )));
    }
    let Some(attempt_index) = snapshot.attempts.iter().position(|attempt| {
        attempt.attempt_id == base.attempt_id && attempt.step_id == base.step_id
    }) else {
        return Err(Box::new(not_found("COLLABORATION_ATTEMPT_NOT_FOUND")));
    };
    let attempt = &snapshot.attempts[attempt_index];
    if attempt.revision != base.expected_attempt_revision {
        return Err(Box::new(entity_revision_conflict(
            run.revision,
            attempt.revision,
        )));
    }
    Ok((step_index, attempt_index))
}

fn active_attempt_count(snapshot: &CollaborationSnapshot) -> usize {
    snapshot
        .attempts
        .iter()
        .filter(|attempt| {
            !matches!(
                AttemptStatus::try_from(attempt.status),
                Ok(AttemptStatus::Returned
                    | AttemptStatus::Failed
                    | AttemptStatus::Cancelled
                    | AttemptStatus::Superseded
                    | AttemptStatus::Expired)
            )
        })
        .count()
}

fn create_run_is_complete(command: &CreateRunCommand) -> bool {
    let Some(plan) = command.plan.as_ref() else {
        return false;
    };
    let Some(step) = plan.steps.first() else {
        return false;
    };
    !command.run_id.trim().is_empty()
        && !command.task_id.trim().is_empty()
        && command.task_revision > 0
        && command.work_revision > 0
        && !plan.plan_id.trim().is_empty()
        && sha256_is_complete(&plan.digest_sha256)
        && plan.max_active_attempts == 1
        && plan.steps.len() == 1
        && plan
            .budget_profile_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
        && !step.step_id.trim().is_empty()
        && !step.step_kind.trim().is_empty()
        && step.depends_on_step_ids.is_empty()
        && !step.input_bundle_ref.trim().is_empty()
        && step
            .expected_output_contract_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
        && step
            .required_capability_profile_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
        && step.max_attempts == 2
}

fn dispatch_material_is_complete(material: &DispatchMaterial) -> bool {
    sha256_is_complete(&material.input_bundle_sha256)
        && contract_reference_is_complete(&material.sandbox_profile_ref)
        && contract_reference_is_complete(&material.tool_policy_ref)
        && contract_reference_is_complete(&material.data_egress_policy_ref)
        && contract_reference_is_complete(&material.approval_policy_ref)
        && material.session_strategy != NativeSessionStrategy::Unspecified
        && material
            .route_binding
            .as_ref()
            .is_none_or(dispatch_route_binding_is_complete)
}

fn dispatch_route_binding_is_complete(binding: &DispatchRouteBinding) -> bool {
    !binding.provider_bootstrap_profile_id.trim().is_empty()
        && !binding.selected_harness_id.trim().is_empty()
        && !binding.provider_model_id.trim().is_empty()
        && !binding.capability_profile_id.trim().is_empty()
        && sha256_is_complete(&binding.route_binding_sha256)
        && canonical_route_binding_digest(binding)
            .is_ok_and(|digest| digest == binding.route_binding_sha256)
}

fn metadata_is_complete(meta: &CommandMetadata) -> bool {
    !meta.command_id.trim().is_empty()
        && !meta.idempotency_key.trim().is_empty()
        && !meta.idempotency_scope.trim().is_empty()
        && sha256_is_complete(&meta.request_digest_sha256)
        && meta.issued_at.is_some()
        && !meta.correlation_id.trim().is_empty()
}

fn contract_reference_is_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && sha256_is_complete(&reference.sha256)
}

fn sha256_is_complete(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn timestamp_expired(expires_at: Option<&Timestamp>, now: &Timestamp) -> bool {
    expires_at.is_none_or(|expires| (expires.seconds, expires.nanos) <= (now.seconds, now.nanos))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn clear_volatile_metadata(meta: &mut CommandMetadata) {
    meta.command_id.clear();
    meta.request_digest_sha256.clear();
    meta.issued_at = None;
    meta.correlation_id.clear();
    meta.causation_id = None;
}

fn operation_name(command: &CollaborationCommand) -> Option<&'static str> {
    Some(match command.command.as_ref()? {
        collaboration_command::Command::CreateRun(_) => "create_run",
        collaboration_command::Command::ActivateRun(_) => "activate_run",
        collaboration_command::Command::CreateAttempt(_) => "create_attempt",
        collaboration_command::Command::AcquireAttemptLease(_) => "acquire_attempt_lease",
        collaboration_command::Command::RenewAttemptLease(_) => "renew_attempt_lease",
        collaboration_command::Command::RecordDispatchIntent(_) => "record_dispatch_intent",
        collaboration_command::Command::RecordDeliveryReceipt(_) => "record_delivery_receipt",
        collaboration_command::Command::RecordHarnessAck(_) => "record_harness_ack",
        collaboration_command::Command::RecordRunningObservation(_) => "record_running_observation",
        collaboration_command::Command::RecordAttemptReturn(_) => "record_attempt_return",
        collaboration_command::Command::MarkAttemptOutcomeUnknown(_) => {
            "mark_attempt_outcome_unknown"
        }
        collaboration_command::Command::BeginAttemptReconciliation(_) => {
            "begin_attempt_reconciliation"
        }
        collaboration_command::Command::RecordAttemptReconciliation(_) => {
            "record_attempt_reconciliation"
        }
        collaboration_command::Command::RecordCheckpoint(_) => "record_checkpoint",
        collaboration_command::Command::RequestAttemptCancellation(_) => {
            "request_attempt_cancellation"
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(_) => {
            "record_attempt_cancellation_outcome"
        }
        collaboration_command::Command::HoldAttempt(_) => "hold_attempt",
        collaboration_command::Command::ResumeAttempt(_) => "resume_attempt",
        collaboration_command::Command::CommitStepReturn(_) => "commit_step_return",
        collaboration_command::Command::SupersedeRun(_) => "supersede_run",
        collaboration_command::Command::ExpireRun(_) => "expire_run",
    })
}

fn operation_allowed(operation: &str, kind: CollaborationPrincipalKind) -> bool {
    match operation {
        "create_run" | "activate_run" | "supersede_run" | "expire_run" => {
            kind == CollaborationPrincipalKind::TaskAuthority
        }
        "create_attempt" => kind == CollaborationPrincipalKind::CollaborationControl,
        "commit_step_return" => kind == CollaborationPrincipalKind::CollaborationControl,
        "acquire_attempt_lease" | "renew_attempt_lease" | "record_dispatch_intent" => {
            kind == CollaborationPrincipalKind::CollaborationControl
                || kind == CollaborationPrincipalKind::AttemptSupervisor
        }
        "begin_attempt_reconciliation"
        | "record_attempt_reconciliation"
        | "record_checkpoint"
        | "record_attempt_cancellation_outcome"
        | "hold_attempt"
        | "resume_attempt" => {
            kind == CollaborationPrincipalKind::CollaborationControl
                || kind == CollaborationPrincipalKind::AttemptSupervisor
                || kind == CollaborationPrincipalKind::RecoveryWorker
        }
        "request_attempt_cancellation" => {
            kind == CollaborationPrincipalKind::TaskAuthority
                || kind == CollaborationPrincipalKind::CollaborationControl
                || kind == CollaborationPrincipalKind::AttemptSupervisor
        }
        "record_delivery_receipt" | "record_harness_ack" | "record_running_observation" => {
            kind == CollaborationPrincipalKind::HarnessAdapter
        }
        "record_attempt_return" => kind == CollaborationPrincipalKind::ArtifactAuthority,
        "mark_attempt_outcome_unknown" => {
            kind == CollaborationPrincipalKind::RecoveryWorker
                || kind == CollaborationPrincipalKind::CollaborationControl
        }
        _ => false,
    }
}

fn command_metadata(command: &CollaborationCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        collaboration_command::Command::CreateRun(value) => value.meta.as_ref(),
        collaboration_command::Command::ActivateRun(value) => value.base.as_ref()?.meta.as_ref(),
        collaboration_command::Command::CreateAttempt(value) => value.base.as_ref()?.meta.as_ref(),
        collaboration_command::Command::AcquireAttemptLease(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RenewAttemptLease(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordDispatchIntent(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordDeliveryReceipt(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordHarnessAck(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordRunningObservation(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordAttemptReturn(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::BeginAttemptReconciliation(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordAttemptReconciliation(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordCheckpoint(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RequestAttemptCancellation(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::HoldAttempt(value) => value.base.as_ref()?.meta.as_ref(),
        collaboration_command::Command::ResumeAttempt(value) => value.base.as_ref()?.meta.as_ref(),
        collaboration_command::Command::CommitStepReturn(value) => {
            value.base.as_ref()?.meta.as_ref()
        }
        collaboration_command::Command::SupersedeRun(value) => value.base.as_ref()?.meta.as_ref(),
        collaboration_command::Command::ExpireRun(value) => value.base.as_ref()?.meta.as_ref(),
    }
}

fn command_metadata_mut(command: &mut CollaborationCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        collaboration_command::Command::CreateRun(value) => value.meta.as_mut(),
        collaboration_command::Command::ActivateRun(value) => value.base.as_mut()?.meta.as_mut(),
        collaboration_command::Command::CreateAttempt(value) => value.base.as_mut()?.meta.as_mut(),
        collaboration_command::Command::AcquireAttemptLease(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RenewAttemptLease(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordDispatchIntent(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordDeliveryReceipt(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordHarnessAck(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordRunningObservation(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordAttemptReturn(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::BeginAttemptReconciliation(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordAttemptReconciliation(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordCheckpoint(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RequestAttemptCancellation(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::HoldAttempt(value) => value.base.as_mut()?.meta.as_mut(),
        collaboration_command::Command::ResumeAttempt(value) => value.base.as_mut()?.meta.as_mut(),
        collaboration_command::Command::CommitStepReturn(value) => {
            value.base.as_mut()?.meta.as_mut()
        }
        collaboration_command::Command::SupersedeRun(value) => value.base.as_mut()?.meta.as_mut(),
        collaboration_command::Command::ExpireRun(value) => value.base.as_mut()?.meta.as_mut(),
    }
}

fn changed_step_id(command: &CollaborationCommand) -> Option<&str> {
    match command.command.as_ref()? {
        collaboration_command::Command::CreateRun(value) => value
            .plan
            .as_ref()?
            .steps
            .first()
            .map(|step| step.step_id.as_str()),
        collaboration_command::Command::CreateAttempt(value) => Some(&value.step_id),
        collaboration_command::Command::AcquireAttemptLease(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordDispatchIntent(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordDeliveryReceipt(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordHarnessAck(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordRunningObservation(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordAttemptReturn(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RequestAttemptCancellation(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::BeginAttemptReconciliation(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::RecordAttemptReconciliation(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
            Some(&value.base.as_ref()?.step_id)
        }
        collaboration_command::Command::CommitStepReturn(value) => Some(&value.step_id),
        _ => None,
    }
}

fn changed_attempt_id(command: &CollaborationCommand) -> Option<&str> {
    match command.command.as_ref()? {
        collaboration_command::Command::CreateAttempt(value) => Some(&value.attempt_id),
        collaboration_command::Command::AcquireAttemptLease(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordDispatchIntent(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordDeliveryReceipt(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordHarnessAck(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordRunningObservation(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordAttemptReturn(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RequestAttemptCancellation(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::BeginAttemptReconciliation(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::RecordAttemptReconciliation(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
            Some(&value.base.as_ref()?.attempt_id)
        }
        _ => None,
    }
}

fn guard_error(rejection: ReferenceGuardRejection) -> CollaborationCommandResult {
    match rejection {
        ReferenceGuardRejection::InvalidArgument => invalid("REFERENCE_INPUT_INVALID"),
        ReferenceGuardRejection::ContractMismatch => error_result(
            CollaborationErrorCode::ContractMismatch,
            "REFERENCE_CONTRACT_MISMATCH",
            None,
            None,
        ),
        ReferenceGuardRejection::StaleTaskReference => error_result(
            CollaborationErrorCode::StaleTaskReference,
            "TASK_REFERENCE_STALE",
            None,
            None,
        ),
        ReferenceGuardRejection::UnverifiedReference => error_result(
            CollaborationErrorCode::RecoveryRequired,
            "REFERENCE_PROOF_REQUIRED",
            None,
            None,
        ),
    }
}

fn invalid(detail: &str) -> CollaborationCommandResult {
    error_result(CollaborationErrorCode::InvalidArgument, detail, None, None)
}

fn not_found(detail: &str) -> CollaborationCommandResult {
    error_result(CollaborationErrorCode::NotFound, detail, None, None)
}

fn state_conflict(detail: &str) -> CollaborationCommandResult {
    error_result(CollaborationErrorCode::StateConflict, detail, None, None)
}

fn run_revision_conflict(current: u64) -> CollaborationCommandResult {
    error_result(
        CollaborationErrorCode::RunRevisionConflict,
        "RUN_REVISION_CONFLICT",
        Some(current),
        None,
    )
}

fn entity_revision_conflict(run: u64, entity: u64) -> CollaborationCommandResult {
    error_result(
        CollaborationErrorCode::EntityRevisionConflict,
        "ENTITY_REVISION_CONFLICT",
        Some(run),
        Some(entity),
    )
}

fn fencing_rejected(run: u64, attempt: u64) -> CollaborationCommandResult {
    error_result(
        CollaborationErrorCode::FencingRejected,
        "ATTEMPT_FENCING_TOKEN_REJECTED",
        Some(run),
        Some(attempt),
    )
}

fn sequence_conflict(run: u64, attempt: u64) -> CollaborationCommandResult {
    error_result(
        CollaborationErrorCode::SequenceConflict,
        "HARNESS_OBSERVATION_SEQUENCE_CONFLICT",
        Some(run),
        Some(attempt),
    )
}

fn current_fence_matches(attempt: &AttemptSnapshot, fencing_token: u64) -> bool {
    attempt
        .lease
        .as_ref()
        .is_some_and(|lease| lease.fencing_token == fencing_token)
}

fn error_result(
    code: CollaborationErrorCode,
    detail: &str,
    current_run_revision: Option<u64>,
    current_entity_revision: Option<u64>,
) -> CollaborationCommandResult {
    CollaborationCommandResult {
        replayed: false,
        outcome: Some(collaboration_command_result::Outcome::Error(
            collaboration_error(code, detail, current_run_revision, current_entity_revision),
        )),
        committed_event: None,
    }
}

fn collaboration_error(
    code: CollaborationErrorCode,
    detail: &str,
    current_run_revision: Option<u64>,
    current_entity_revision: Option<u64>,
) -> CollaborationError {
    CollaborationError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable: matches!(
            code,
            CollaborationErrorCode::RunRevisionConflict
                | CollaborationErrorCode::EntityRevisionConflict
        ),
        recovery_required: matches!(
            code,
            CollaborationErrorCode::OutcomeUnknown
                | CollaborationErrorCode::RecoveryRequired
                | CollaborationErrorCode::IntegrityFailure
        ),
        current_run_revision,
        current_entity_revision,
        audit_ref: None,
    }
}
