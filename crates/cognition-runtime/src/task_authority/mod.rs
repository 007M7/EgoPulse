//! C-01 Task single-writer boundary for the V-01 vertical unit.
//!
//! The storage module is deliberately private. Callers submit frozen protobuf
//! commands with an OS-derived principal context and receive contract results.

mod store;

use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    ApplyFounderVerdictCommand, CreateTaskCommand, FounderDecision, GetTaskResponse,
    ReviseTaskCommand, TaskCommand, TaskCommandResult, TaskError, TaskErrorCode, TaskEvent,
    TaskEventKind, TaskSnapshot, TaskStatus, get_task_response, task_command, task_command_result,
};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    ConsumeFounderVerdictCommand, VerdictCommand, verdict_command,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use store::{CreateCommit, CrossAuthorityOutbox, MutationCommit, StoreError, TaskStore};
pub use store::{PendingTaskOutbox, TaskStoreInspection};

const TASK_AUTHORITY_REF: &str = "egopulse/task-authority/v1";
const CREATE_TASK_OPERATION: &str = "create_task";

/// SQLCipher key material. It is consumed when the Authority opens and is
/// zeroed when dropped. Key acquisition/wrapping remains an OS integration.
pub struct SqlCipherKey([u8; 32]);

impl SqlCipherKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SqlCipherKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct TaskAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: SqlCipherKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Founder,
    FounderAuthority,
    CollaborationControl,
    SegoVerification,
    Harness,
    Model,
    RecoveryCoordinator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    pub kind: PrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreationGuardRejection {
    InvalidArgument,
    ContractMismatch,
    StaleReference,
    UnverifiedReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreationAuthorization {
    pub evidence_refs: Vec<String>,
}

/// Resolves the CreateTask references at the Authority boundary. Implementors
/// must validate immutable input/scope and exact contract/profile references;
/// returning success is authorization evidence, not a string-shape check.
pub trait TaskCreationGuard: Send + Sync + 'static {
    fn validate(
        &self,
        command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionGuardRejection {
    InvalidArgument,
    StateConflict,
    ContractMismatch,
    StaleReference,
    UnverifiedReference,
    TerminalGateUnsatisfied,
    IntegrityFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionAuthorization {
    pub evidence_refs: Vec<String>,
    pub founder_decision: Option<FounderDecision>,
    pub founder_verdict_state_revision: Option<u64>,
}

pub trait TaskTransitionGuard: Send + Sync + 'static {
    fn validate(
        &self,
        command: &TaskCommand,
        current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection>;
}

struct DenyUnresolvedTransitions;

impl TaskTransitionGuard for DenyUnresolvedTransitions {
    fn validate(
        &self,
        _command: &TaskCommand,
        _current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        Err(TransitionGuardRejection::UnverifiedReference)
    }
}

#[derive(Debug, Error)]
pub enum TaskAuthorityFailure {
    #[error("task authority storage is unavailable")]
    Storage,
    #[error("task authority stored protobuf could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("task authority clock is before the Unix epoch")]
    Clock,
}

impl From<StoreError> for TaskAuthorityFailure {
    fn from(_: StoreError) -> Self {
        Self::Storage
    }
}

pub struct TaskAuthority {
    store: TaskStore,
    creation_guard: Box<dyn TaskCreationGuard>,
    transition_guard: Box<dyn TaskTransitionGuard>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskProjectionMessage {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub event: TaskEvent,
}

impl TaskAuthority {
    pub fn open(
        config: TaskAuthorityConfig,
        creation_guard: impl TaskCreationGuard,
    ) -> Result<Self, TaskAuthorityFailure> {
        Self::open_with_transition_guard(config, creation_guard, DenyUnresolvedTransitions)
    }

    pub fn open_with_transition_guard(
        config: TaskAuthorityConfig,
        creation_guard: impl TaskCreationGuard,
        transition_guard: impl TaskTransitionGuard,
    ) -> Result<Self, TaskAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(TaskAuthorityFailure::Storage);
        }
        let store = TaskStore::open(
            &config.database_path,
            config.key.expose(),
            &config.store_epoch,
        )?;
        Ok(Self {
            store,
            creation_guard: Box::new(creation_guard),
            transition_guard: Box::new(transition_guard),
        })
    }

    /// Executes one frozen Task command. Only CreateTask reaches a mutation in
    /// G4-02; other operations fail closed after the applicable front-door
    /// checks until their cross-domain proof is implemented.
    pub fn execute(
        &mut self,
        command: &TaskCommand,
        principal: &AuthenticatedPrincipal,
    ) -> Result<TaskCommandResult, TaskAuthorityFailure> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                TaskErrorCode::InvalidArgument,
                "TASK_COMMAND_MISSING",
                None,
            ));
        };

        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                TaskErrorCode::Unauthenticated,
                "OS_PRINCIPAL_NOT_AUTHENTICATED",
                task_precondition(command)
                    .and_then(|(task_id, _)| self.store.current_revision(task_id).ok().flatten()),
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                TaskErrorCode::PermissionDenied,
                "PRINCIPAL_OPERATION_NOT_ALLOWED",
                task_precondition(command)
                    .and_then(|(task_id, _)| self.store.current_revision(task_id).ok().flatten()),
            ));
        }

        let Some(meta) = command_metadata(command) else {
            return Ok(error_result(
                TaskErrorCode::InvalidArgument,
                "COMMAND_METADATA_MISSING",
                None,
            ));
        };
        if !metadata_is_complete(meta) {
            return Ok(error_result(
                TaskErrorCode::InvalidArgument,
                "COMMAND_METADATA_INCOMPLETE",
                None,
            ));
        }

        let actual_digest = canonical_request_digest(command)?;
        if meta.request_digest_sha256 != actual_digest {
            return Ok(error_result(
                TaskErrorCode::InvalidArgument,
                "REQUEST_DIGEST_MISMATCH",
                task_precondition(command)
                    .and_then(|(task_id, _)| self.store.current_revision(task_id).ok().flatten()),
            ));
        }

        if let Some(record) = self.store.idempotency_record(
            &principal.principal_id,
            operation,
            &meta.idempotency_scope,
            &meta.idempotency_key,
        )? {
            if record.request_digest_sha256 != actual_digest {
                return Ok(error_result(
                    TaskErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
                    Some(record.task_revision),
                ));
            }
            let mut result = TaskCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }

        if let Some((task_id, expected_revision)) = task_precondition(command) {
            let Some(current_revision) = self.store.current_revision(task_id)? else {
                return Ok(error_result(
                    TaskErrorCode::NotFound,
                    "TASK_NOT_FOUND",
                    None,
                ));
            };
            if expected_revision != current_revision {
                return Ok(error_result(
                    TaskErrorCode::RevisionConflict,
                    "EXPECTED_REVISION_STALE",
                    Some(current_revision),
                ));
            }
        }

        match command.command.as_ref() {
            Some(task_command::Command::CreateTask(create)) => {
                if !create_structure_is_complete(create) {
                    return Ok(error_result(
                        TaskErrorCode::InvalidArgument,
                        "CREATE_TASK_INPUT_INCOMPLETE",
                        None,
                    ));
                }
                let authorization = match self.creation_guard.validate(create) {
                    Ok(authorization) if !authorization.evidence_refs.is_empty() => authorization,
                    Ok(_) => {
                        return Ok(error_result(
                            TaskErrorCode::UnverifiedReference,
                            "CREATE_TASK_GUARD_EVIDENCE_MISSING",
                            None,
                        ));
                    }
                    Err(rejection) => return Ok(creation_guard_error(rejection)),
                };
                self.commit_create(create, principal, &actual_digest, &authorization)
            }
            Some(task_command::Command::ActivateTask(_))
            | Some(task_command::Command::SubmitTaskEvidence(_))
            | Some(task_command::Command::RecordTaskVerification(_))
            | Some(task_command::Command::ApplyFounderVerdict(_))
            | Some(task_command::Command::ReviseTask(_)) => {
                self.commit_transition(command, principal, &actual_digest)
            }
            Some(_) => Ok(error_result(
                TaskErrorCode::UnverifiedReference,
                "DEPENDENCY_PROOF_NOT_AVAILABLE",
                task_precondition(command)
                    .and_then(|(task_id, _)| self.store.current_revision(task_id).ok().flatten()),
            )),
            None => Ok(error_result(
                TaskErrorCode::InvalidArgument,
                "TASK_COMMAND_MISSING",
                None,
            )),
        }
    }

    pub fn get_task(&self, task_id: &str) -> Result<GetTaskResponse, TaskAuthorityFailure> {
        let outcome = match self.store.task_snapshot(task_id)? {
            Some(snapshot) => {
                get_task_response::Outcome::Task(TaskSnapshot::decode(snapshot.as_slice())?)
            }
            None => get_task_response::Outcome::Error(TaskError {
                code: TaskErrorCode::NotFound as i32,
                safe_detail_code: "TASK_NOT_FOUND".to_owned(),
                retryable: false,
                recovery_required: false,
                current_revision: None,
                audit_ref: None,
            }),
        };
        Ok(GetTaskResponse {
            outcome: Some(outcome),
        })
    }

    pub fn inspect_store(&self) -> Result<TaskStoreInspection, TaskAuthorityFailure> {
        self.store.inspect().map_err(TaskAuthorityFailure::from)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, TaskAuthorityFailure> {
        self.store
            .integrity_is_ok()
            .map_err(TaskAuthorityFailure::from)
    }

    pub fn commit_receipt_exists(
        &self,
        event_id: &str,
        task_id: &str,
        revision: u64,
    ) -> Result<bool, TaskAuthorityFailure> {
        self.store
            .commit_receipt_exists(event_id, task_id, revision)
            .map_err(TaskAuthorityFailure::from)
    }

    pub fn pending_cross_authority_outbox(
        &self,
    ) -> Result<Vec<PendingTaskOutbox>, TaskAuthorityFailure> {
        self.store
            .pending_cross_authority_outbox()
            .map_err(TaskAuthorityFailure::from)
    }

    pub fn drain_projection_outbox(
        &self,
    ) -> Result<Vec<TaskProjectionMessage>, TaskAuthorityFailure> {
        self.decode_projection_messages(self.store.pending_projection_outbox()?)
    }

    pub fn projection_baselines(&self) -> Result<Vec<TaskProjectionMessage>, TaskAuthorityFailure> {
        self.decode_projection_messages(self.store.projection_baselines()?)
    }

    fn decode_projection_messages(
        &self,
        pending_messages: Vec<store::PendingTaskProjectionOutbox>,
    ) -> Result<Vec<TaskProjectionMessage>, TaskAuthorityFailure> {
        pending_messages
            .into_iter()
            .map(|pending| {
                let actual_digest = hex::encode(Sha256::digest(&pending.payload));
                let event = TaskEvent::decode(pending.payload.as_slice())?;
                if actual_digest != pending.payload_digest_sha256
                    || event.event_id != pending.source_event_id
                    || event.resulting_revision != pending.source_revision
                    || event.snapshot.as_ref().is_none_or(|snapshot| {
                        snapshot.task_id != event.task_id
                            || snapshot.revision != pending.source_revision
                    })
                {
                    return Err(TaskAuthorityFailure::Storage);
                }
                Ok(TaskProjectionMessage {
                    message_id: pending.message_id,
                    source_event_id: pending.source_event_id,
                    source_revision: pending.source_revision,
                    payload_digest_sha256: pending.payload_digest_sha256,
                    event,
                })
            })
            .collect()
    }

    pub fn acknowledge_projection(
        &mut self,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, TaskAuthorityFailure> {
        self.store
            .acknowledge_projection_outbox(message_id, expected_payload_digest_sha256)
            .map_err(TaskAuthorityFailure::from)
    }

    fn commit_create(
        &mut self,
        command: &CreateTaskCommand,
        principal: &AuthenticatedPrincipal,
        request_digest: &str,
        authorization: &CreationAuthorization,
    ) -> Result<TaskCommandResult, TaskAuthorityFailure> {
        let meta = command
            .meta
            .as_ref()
            .expect("metadata checked before commit");
        let now = current_timestamp()?;
        let task_id = format!("task-{}", Uuid::now_v7());
        let event_id = format!("task-event-{}", Uuid::now_v7());
        let outbox_message_id = format!("task-outbox-{}", Uuid::now_v7());
        let snapshot = TaskSnapshot {
            task_id: task_id.clone(),
            revision: 1,
            work_revision: 1,
            status: TaskStatus::Ready as i32,
            resume_status: TaskStatus::Unspecified as i32,
            work_type: command.work_type.clone(),
            input_snapshot_id: command.input_snapshot_id.clone(),
            target_scope_ref: command.target_scope_ref.clone(),
            acceptance_contract_ref: command.acceptance_contract_ref.clone(),
            budget_profile_ref: command.budget_profile_ref.clone(),
            current_run_id: None,
            artifact_set_id: None,
            verification_artifact_id: None,
            founder_verdict_id: None,
            hold_reason_code: None,
            created_at: Some(now),
            updated_at: Some(now),
        };
        let event = TaskEvent {
            event_id: event_id.clone(),
            command_id: meta.command_id.clone(),
            kind: TaskEventKind::Created as i32,
            task_id: task_id.clone(),
            expected_revision: 0,
            resulting_revision: 1,
            work_revision: 1,
            authenticated_principal_id: principal.principal_id.clone(),
            authority_ref: TASK_AUTHORITY_REF.to_owned(),
            idempotency_key: meta.idempotency_key.clone(),
            request_digest_sha256: request_digest.to_owned(),
            correlation_id: meta.correlation_id.clone(),
            causation_id: meta.causation_id.clone(),
            evidence_refs: contract_evidence_refs(command, authorization),
            occurred_at: Some(now),
            snapshot: Some(snapshot.clone()),
        };
        let result = TaskCommandResult {
            replayed: false,
            committed_event: Some(event.clone()),
            outcome: Some(task_command_result::Outcome::Task(snapshot.clone())),
        };

        let snapshot_bytes = snapshot.encode_to_vec();
        let event_bytes = event.encode_to_vec();
        let result_bytes = result.encode_to_vec();
        let event_digest = hex::encode(Sha256::digest(&event_bytes));
        self.store.commit_create(&CreateCommit {
            task_id: &task_id,
            revision: 1,
            work_revision: 1,
            status: TaskStatus::Ready as i32,
            snapshot: &snapshot_bytes,
            created_at_seconds: now.seconds,
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest_sha256: request_digest,
            event: &event_bytes,
            authenticated_principal_id: &principal.principal_id,
            operation: CREATE_TASK_OPERATION,
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result_bytes,
            outbox_message_id: &outbox_message_id,
            outbox_payload_digest_sha256: &event_digest,
        })?;
        Ok(result)
    }

    fn commit_transition(
        &mut self,
        command: &TaskCommand,
        principal: &AuthenticatedPrincipal,
        request_digest: &str,
    ) -> Result<TaskCommandResult, TaskAuthorityFailure> {
        let (task_id, expected_revision) =
            task_precondition(command).expect("supported transition has a task precondition");
        let Some(snapshot_bytes) = self.store.task_snapshot(task_id)? else {
            return Ok(error_result(
                TaskErrorCode::NotFound,
                "TASK_NOT_FOUND",
                None,
            ));
        };
        let current = TaskSnapshot::decode(snapshot_bytes.as_slice())?;
        let authorization = match self.transition_guard.validate(command, &current) {
            Ok(value) if !value.evidence_refs.is_empty() => value,
            Ok(_) => {
                return Ok(error_result(
                    TaskErrorCode::UnverifiedReference,
                    "TRANSITION_GUARD_EVIDENCE_MISSING",
                    Some(current.revision),
                ));
            }
            Err(rejection) => return Ok(transition_guard_error(rejection, current.revision)),
        };
        let now = current_timestamp()?;
        let mut next = current.clone();
        next.revision = current.revision + 1;
        next.updated_at = Some(now);
        let (kind, mut evidence_refs, cross_verdict_state_revision) = match command.command.as_ref()
        {
            Some(task_command::Command::ActivateTask(value)) => {
                if current.status != TaskStatus::Ready as i32
                    || value.work_revision != current.work_revision
                    || value.run_id.trim().is_empty()
                {
                    return Ok(error_result(
                        TaskErrorCode::StateConflict,
                        "ACTIVATE_PRECONDITION_FAILED",
                        Some(current.revision),
                    ));
                }
                next.status = TaskStatus::Active as i32;
                next.current_run_id = Some(value.run_id.clone());
                (TaskEventKind::Activated, vec![value.run_id.clone()], None)
            }
            Some(task_command::Command::SubmitTaskEvidence(value)) => {
                if current.status != TaskStatus::Active as i32
                    || value.work_revision != current.work_revision
                    || value.return_handoff_id.trim().is_empty()
                    || value.artifact_set_id.trim().is_empty()
                {
                    return Ok(error_result(
                        TaskErrorCode::StateConflict,
                        "EVIDENCE_PRECONDITION_FAILED",
                        Some(current.revision),
                    ));
                }
                next.status = TaskStatus::VerificationPending as i32;
                next.artifact_set_id = Some(value.artifact_set_id.clone());
                (
                    TaskEventKind::EvidenceSubmitted,
                    vec![
                        value.return_handoff_id.clone(),
                        value.artifact_set_id.clone(),
                    ],
                    None,
                )
            }
            Some(task_command::Command::RecordTaskVerification(value)) => {
                if current.status != TaskStatus::VerificationPending as i32
                    || value.work_revision != current.work_revision
                    || value.verification_artifact_id.trim().is_empty()
                    || current.artifact_set_id.is_none()
                {
                    return Ok(error_result(
                        TaskErrorCode::StateConflict,
                        "VERIFICATION_PRECONDITION_FAILED",
                        Some(current.revision),
                    ));
                }
                next.status = TaskStatus::VerdictPending as i32;
                next.verification_artifact_id = Some(value.verification_artifact_id.clone());
                (
                    TaskEventKind::VerificationRecorded,
                    vec![value.verification_artifact_id.clone()],
                    None,
                )
            }
            Some(task_command::Command::ApplyFounderVerdict(value)) => {
                if current.status != TaskStatus::VerdictPending as i32
                    || value.work_revision != current.work_revision
                    || value.founder_verdict_id.trim().is_empty()
                    || current.artifact_set_id.is_none()
                    || current.verification_artifact_id.is_none()
                {
                    return Ok(error_result(
                        TaskErrorCode::StateConflict,
                        "VERDICT_PRECONDITION_FAILED",
                        Some(current.revision),
                    ));
                }
                let Some(decision) = authorization.founder_decision else {
                    return Ok(error_result(
                        TaskErrorCode::TerminalGateUnsatisfied,
                        "FOUNDER_DECISION_UNRESOLVED",
                        Some(current.revision),
                    ));
                };
                let Some(state_revision) = authorization.founder_verdict_state_revision else {
                    return Ok(error_result(
                        TaskErrorCode::TerminalGateUnsatisfied,
                        "VERDICT_STATE_UNRESOLVED",
                        Some(current.revision),
                    ));
                };
                next.status = match decision {
                    FounderDecision::Accept => TaskStatus::Completed as i32,
                    FounderDecision::Rework => TaskStatus::Rework as i32,
                    FounderDecision::Reject => TaskStatus::Rejected as i32,
                    FounderDecision::Unspecified => {
                        return Ok(error_result(
                            TaskErrorCode::TerminalGateUnsatisfied,
                            "FOUNDER_DECISION_INVALID",
                            Some(current.revision),
                        ));
                    }
                };
                next.founder_verdict_id = Some(value.founder_verdict_id.clone());
                (
                    TaskEventKind::VerdictApplied,
                    vec![value.founder_verdict_id.clone()],
                    Some(state_revision),
                )
            }
            Some(task_command::Command::ReviseTask(value)) => {
                if current.status != TaskStatus::Rework as i32
                    || value.expected_work_revision != current.work_revision
                    || !revise_structure_complete(value)
                {
                    return Ok(error_result(
                        TaskErrorCode::StateConflict,
                        "REVISE_PRECONDITION_FAILED",
                        Some(current.revision),
                    ));
                }
                next.status = TaskStatus::Ready as i32;
                next.work_revision = current.work_revision + 1;
                next.input_snapshot_id = value.new_input_snapshot_id.clone();
                next.target_scope_ref = value.new_target_scope_ref.clone();
                next.acceptance_contract_ref = value.new_acceptance_contract_ref.clone();
                next.current_run_id = None;
                next.artifact_set_id = None;
                next.verification_artifact_id = None;
                next.founder_verdict_id = None;
                (
                    TaskEventKind::Revised,
                    vec![value.new_input_snapshot_id.clone()],
                    None,
                )
            }
            _ => unreachable!("caller limits supported transitions"),
        };
        evidence_refs.extend(authorization.evidence_refs);
        let meta = command_metadata(command).expect("metadata checked");
        let event_id = format!("task-event-{}", Uuid::now_v7());
        let event = TaskEvent {
            event_id: event_id.clone(),
            command_id: meta.command_id.clone(),
            kind: kind as i32,
            task_id: task_id.to_owned(),
            expected_revision,
            resulting_revision: next.revision,
            work_revision: next.work_revision,
            authenticated_principal_id: principal.principal_id.clone(),
            authority_ref: TASK_AUTHORITY_REF.to_owned(),
            idempotency_key: meta.idempotency_key.clone(),
            request_digest_sha256: request_digest.to_owned(),
            correlation_id: meta.correlation_id.clone(),
            causation_id: meta.causation_id.clone(),
            evidence_refs,
            occurred_at: Some(now),
            snapshot: Some(next.clone()),
        };
        let result = TaskCommandResult {
            replayed: false,
            committed_event: Some(event.clone()),
            outcome: Some(task_command_result::Outcome::Task(next.clone())),
        };
        let event_bytes = event.encode_to_vec();
        let event_digest = hex::encode(Sha256::digest(&event_bytes));
        let read_outbox_id = format!("task-outbox-read-{}", Uuid::now_v7());
        let cross_outbox_id = format!("task-outbox-verdict-{}", Uuid::now_v7());
        let consume_payload = match (command.command.as_ref(), cross_verdict_state_revision) {
            (Some(task_command::Command::ApplyFounderVerdict(value)), Some(state_revision)) => {
                Some(build_consume_verdict_command(
                    value,
                    state_revision,
                    &event,
                    meta,
                    now,
                ))
            }
            _ => None,
        };
        let consume_bytes = consume_payload.as_ref().map(Message::encode_to_vec);
        let consume_digest = consume_bytes
            .as_ref()
            .map(|bytes| hex::encode(Sha256::digest(bytes)));
        let cross = consume_bytes
            .as_ref()
            .zip(consume_digest.as_ref())
            .map(|(payload, digest)| CrossAuthorityOutbox {
                message_id: &cross_outbox_id,
                destination_domain: "founder-verdict-authority",
                payload_digest_sha256: digest,
                payload,
            });
        let changed = self.store.commit_mutation(&MutationCommit {
            task_id,
            expected_revision,
            resulting_revision: next.revision,
            work_revision: next.work_revision,
            status: next.status,
            snapshot: &next.encode_to_vec(),
            committed_at_seconds: now.seconds,
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest_sha256: request_digest,
            event: &event_bytes,
            authenticated_principal_id: &principal.principal_id,
            operation: operation_name(command).expect("operation checked"),
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result.encode_to_vec(),
            read_outbox_message_id: &read_outbox_id,
            event_digest_sha256: &event_digest,
            cross_authority_outbox: cross,
        })?;
        if !changed {
            return Ok(error_result(
                TaskErrorCode::RevisionConflict,
                "EXPECTED_REVISION_STALE",
                self.store.current_revision(task_id)?,
            ));
        }
        Ok(result)
    }
}

pub fn canonical_request_digest(command: &TaskCommand) -> Result<String, TaskAuthorityFailure> {
    let mut canonical = command.clone();
    if let Some(meta) = command_metadata_mut(&mut canonical) {
        meta.command_id.clear();
        meta.request_digest_sha256.clear();
        meta.issued_at = None;
        meta.correlation_id.clear();
        meta.causation_id = None;
    }
    Ok(hex::encode(Sha256::digest(canonical.encode_to_vec())))
}

fn current_timestamp() -> Result<Timestamp, TaskAuthorityFailure> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TaskAuthorityFailure::Clock)?;
    Ok(Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    })
}

fn operation_name(command: &TaskCommand) -> Option<&'static str> {
    match command.command.as_ref()? {
        task_command::Command::CreateTask(_) => Some(CREATE_TASK_OPERATION),
        task_command::Command::ActivateTask(_) => Some("activate_task"),
        task_command::Command::SubmitTaskEvidence(_) => Some("submit_task_evidence"),
        task_command::Command::RecordTaskVerification(_) => Some("record_task_verification"),
        task_command::Command::ApplyFounderVerdict(_) => Some("apply_founder_verdict"),
        task_command::Command::ReviseTask(_) => Some("revise_task"),
        task_command::Command::InterruptTask(_) => Some("interrupt_task"),
        task_command::Command::HoldTask(_) => Some("hold_task"),
        task_command::Command::ResumeTask(_) => Some("resume_task"),
        task_command::Command::RequestTaskCancellation(_) => Some("request_task_cancellation"),
        task_command::Command::RecordTaskCancellationOutcome(_) => {
            Some("record_task_cancellation_outcome")
        }
        task_command::Command::SupersedeTask(_) => Some("supersede_task"),
        task_command::Command::ExpireTask(_) => Some("expire_task"),
    }
}

fn operation_allowed(operation: &str, kind: PrincipalKind) -> bool {
    match operation {
        "create_task" | "request_task_cancellation" => kind == PrincipalKind::Founder,
        "activate_task"
        | "submit_task_evidence"
        | "interrupt_task"
        | "hold_task"
        | "resume_task"
        | "record_task_cancellation_outcome" => kind == PrincipalKind::CollaborationControl,
        "record_task_verification" => kind == PrincipalKind::SegoVerification,
        "apply_founder_verdict" | "revise_task" | "supersede_task" | "expire_task" => {
            kind == PrincipalKind::FounderAuthority
        }
        _ => false,
    }
}

fn command_metadata(command: &TaskCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        task_command::Command::CreateTask(value) => value.meta.as_ref(),
        task_command::Command::ActivateTask(value) => value.meta.as_ref(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_ref(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_ref(),
        task_command::Command::ApplyFounderVerdict(value) => value.meta.as_ref(),
        task_command::Command::ReviseTask(value) => value.meta.as_ref(),
        task_command::Command::InterruptTask(value) => value.meta.as_ref(),
        task_command::Command::HoldTask(value) => value.meta.as_ref(),
        task_command::Command::ResumeTask(value) => value.meta.as_ref(),
        task_command::Command::RequestTaskCancellation(value) => value.meta.as_ref(),
        task_command::Command::RecordTaskCancellationOutcome(value) => value.meta.as_ref(),
        task_command::Command::SupersedeTask(value) => value.meta.as_ref(),
        task_command::Command::ExpireTask(value) => value.meta.as_ref(),
    }
}

fn command_metadata_mut(command: &mut TaskCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_mut(),
        task_command::Command::ApplyFounderVerdict(value) => value.meta.as_mut(),
        task_command::Command::ReviseTask(value) => value.meta.as_mut(),
        task_command::Command::InterruptTask(value) => value.meta.as_mut(),
        task_command::Command::HoldTask(value) => value.meta.as_mut(),
        task_command::Command::ResumeTask(value) => value.meta.as_mut(),
        task_command::Command::RequestTaskCancellation(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskCancellationOutcome(value) => value.meta.as_mut(),
        task_command::Command::SupersedeTask(value) => value.meta.as_mut(),
        task_command::Command::ExpireTask(value) => value.meta.as_mut(),
    }
}

fn task_precondition(command: &TaskCommand) -> Option<(&str, u64)> {
    match command.command.as_ref()? {
        task_command::Command::CreateTask(_) => None,
        task_command::Command::ActivateTask(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::SubmitTaskEvidence(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::RecordTaskVerification(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::ApplyFounderVerdict(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::ReviseTask(value) => Some((&value.task_id, value.expected_revision)),
        task_command::Command::InterruptTask(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::HoldTask(value) => Some((&value.task_id, value.expected_revision)),
        task_command::Command::ResumeTask(value) => Some((&value.task_id, value.expected_revision)),
        task_command::Command::RequestTaskCancellation(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::RecordTaskCancellationOutcome(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::SupersedeTask(value) => {
            Some((&value.task_id, value.expected_revision))
        }
        task_command::Command::ExpireTask(value) => Some((&value.task_id, value.expected_revision)),
    }
}

fn metadata_is_complete(meta: &CommandMetadata) -> bool {
    !meta.command_id.trim().is_empty()
        && !meta.idempotency_key.trim().is_empty()
        && !meta.idempotency_scope.trim().is_empty()
        && !meta.request_digest_sha256.trim().is_empty()
        && meta.issued_at.is_some()
        && !meta.correlation_id.trim().is_empty()
}

fn create_structure_is_complete(command: &CreateTaskCommand) -> bool {
    !command.work_type.trim().is_empty()
        && !command.input_snapshot_id.trim().is_empty()
        && !command.target_scope_ref.trim().is_empty()
        && command
            .acceptance_contract_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
        && command
            .budget_profile_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
}

fn revise_structure_complete(command: &ReviseTaskCommand) -> bool {
    !command.new_input_snapshot_id.trim().is_empty()
        && !command.new_target_scope_ref.trim().is_empty()
        && command
            .new_acceptance_contract_ref
            .as_ref()
            .is_some_and(contract_reference_is_complete)
}

fn build_consume_verdict_command(
    applied: &ApplyFounderVerdictCommand,
    verdict_state_revision: u64,
    event: &TaskEvent,
    task_meta: &CommandMetadata,
    now: Timestamp,
) -> VerdictCommand {
    let status = event
        .snapshot
        .as_ref()
        .and_then(|snapshot| TaskStatus::try_from(snapshot.status).ok())
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|| "TASK_STATUS_UNSPECIFIED".to_owned());
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::ConsumeFounderVerdict(
            ConsumeFounderVerdictCommand {
                metadata: Some(CommandMetadata {
                    command_id: format!("consume-verdict-{}", event.event_id),
                    idempotency_key: format!(
                        "consume:{}:{}",
                        applied.founder_verdict_id, event.event_id
                    ),
                    idempotency_scope: "task-authority/verdict-consumption/v1".to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: Some(now),
                    correlation_id: task_meta.correlation_id.clone(),
                    causation_id: Some(task_meta.command_id.clone()),
                }),
                founder_verdict_id: applied.founder_verdict_id.clone(),
                expected_state_revision: verdict_state_revision,
                task_event_id: event.event_id.clone(),
                consumed_task_revision: event.expected_revision,
                resulting_task_revision: event.resulting_revision,
                resulting_task_status: status,
                task_commit_receipt_ref: format!("task-commit:{}", event.event_id),
            },
        )),
    };
    let digest = canonical_verdict_request_digest(&command);
    if let Some(verdict_command::Command::ConsumeFounderVerdict(consume)) = command.command.as_mut()
    {
        consume
            .metadata
            .as_mut()
            .expect("constructed metadata")
            .request_digest_sha256 = digest;
    }
    command
}

fn canonical_verdict_request_digest(command: &VerdictCommand) -> String {
    let mut canonical = command.clone();
    if let Some(verdict_command::Command::ConsumeFounderVerdict(consume)) =
        canonical.command.as_mut()
        && let Some(meta) = consume.metadata.as_mut()
    {
        meta.command_id.clear();
        meta.request_digest_sha256.clear();
        meta.issued_at = None;
        meta.correlation_id.clear();
        meta.causation_id = None;
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

fn contract_reference_is_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn creation_guard_error(rejection: CreationGuardRejection) -> TaskCommandResult {
    let (code, detail) = match rejection {
        CreationGuardRejection::InvalidArgument => {
            (TaskErrorCode::InvalidArgument, "CREATE_TASK_INPUT_INVALID")
        }
        CreationGuardRejection::ContractMismatch => (
            TaskErrorCode::ContractMismatch,
            "CREATE_TASK_CONTRACT_MISMATCH",
        ),
        CreationGuardRejection::StaleReference => {
            (TaskErrorCode::StaleReference, "CREATE_TASK_REFERENCE_STALE")
        }
        CreationGuardRejection::UnverifiedReference => (
            TaskErrorCode::UnverifiedReference,
            "CREATE_TASK_REFERENCE_UNVERIFIED",
        ),
    };
    error_result(code, detail, None)
}

fn transition_guard_error(
    rejection: TransitionGuardRejection,
    current_revision: u64,
) -> TaskCommandResult {
    let (code, detail) = match rejection {
        TransitionGuardRejection::InvalidArgument => {
            (TaskErrorCode::InvalidArgument, "TRANSITION_INPUT_INVALID")
        }
        TransitionGuardRejection::StateConflict => {
            (TaskErrorCode::StateConflict, "TRANSITION_STATE_CONFLICT")
        }
        TransitionGuardRejection::ContractMismatch => (
            TaskErrorCode::ContractMismatch,
            "TRANSITION_CONTRACT_MISMATCH",
        ),
        TransitionGuardRejection::StaleReference => {
            (TaskErrorCode::StaleReference, "TRANSITION_REFERENCE_STALE")
        }
        TransitionGuardRejection::UnverifiedReference => (
            TaskErrorCode::UnverifiedReference,
            "TRANSITION_REFERENCE_UNVERIFIED",
        ),
        TransitionGuardRejection::TerminalGateUnsatisfied => (
            TaskErrorCode::TerminalGateUnsatisfied,
            "TERMINAL_GATE_UNSATISFIED",
        ),
        TransitionGuardRejection::IntegrityFailure => (
            TaskErrorCode::IntegrityFailure,
            "TRANSITION_REFERENCE_INTEGRITY_FAILURE",
        ),
    };
    error_result(code, detail, Some(current_revision))
}

fn error_result(
    code: TaskErrorCode,
    detail: &str,
    current_revision: Option<u64>,
) -> TaskCommandResult {
    TaskCommandResult {
        replayed: false,
        committed_event: None,
        outcome: Some(task_command_result::Outcome::Error(TaskError {
            code: code as i32,
            safe_detail_code: detail.to_owned(),
            retryable: matches!(code, TaskErrorCode::RevisionConflict),
            recovery_required: matches!(
                code,
                TaskErrorCode::IntegrityFailure | TaskErrorCode::RecoveryRequired
            ),
            current_revision,
            audit_ref: None,
        })),
    }
}

fn contract_evidence_refs(
    command: &CreateTaskCommand,
    authorization: &CreationAuthorization,
) -> Vec<String> {
    let mut evidence_refs: Vec<String> = [
        command.acceptance_contract_ref.as_ref(),
        command.budget_profile_ref.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(contract_reference_string)
    .collect();
    evidence_refs.extend(authorization.evidence_refs.iter().cloned());
    evidence_refs
}

fn contract_reference_string(reference: &ContractReference) -> String {
    format!(
        "contract:{}@{}#{}",
        reference.contract_id, reference.version, reference.sha256
    )
}
