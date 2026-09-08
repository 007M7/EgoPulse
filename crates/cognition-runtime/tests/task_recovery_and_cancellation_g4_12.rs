use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCancellationReconciliation,
    TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization, TransitionGuardRejection,
    canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    ActivateTaskCommand, CreateTaskCommand, HoldTaskCommand, InterruptTaskCommand,
    RecordTaskCancellationOutcomeCommand, RequestTaskCancellationCommand, ResumeTaskCommand,
    TaskCommand, TaskErrorCode, TaskEventKind, TaskStatus, task_command, task_command_result,
};
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const STORE_EPOCH: &str = "task-store-recovery-test";
const TEST_KEY: [u8; 32] = [0x43; 32];

struct FixtureCreationGuard;

impl TaskCreationGuard for FixtureCreationGuard {
    fn validate(
        &self,
        command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        if command.work_type != "governed_repository_change"
            || command.input_snapshot_id != "input-001"
            || command.target_scope_ref != "repo-scope-001"
        {
            return Err(CreationGuardRejection::UnverifiedReference);
        }
        Ok(CreationAuthorization {
            evidence_refs: vec!["input-snapshot:input-001@verified".to_owned()],
        })
    }
}

struct FixtureTransitionGuard;

impl TaskTransitionGuard for FixtureTransitionGuard {
    fn validate(
        &self,
        _command: &TaskCommand,
        _current: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        Ok(TransitionAuthorization {
            evidence_refs: vec!["transition-proof:fixture".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

struct IsolatedStore {
    root: PathBuf,
}

impl IsolatedStore {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create isolated Task Authority test directory");
        Self { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("task-authority.sqlcipher")
    }
}

impl Drop for IsolatedStore {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        assert!(self.root.starts_with(&temp_root));
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove isolated Task Authority test directory");
        }
    }
}

fn open_authority(path: &Path) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: path.to_owned(),
            store_epoch: STORE_EPOCH.to_owned(),
            key: SqlCipherKey::new(TEST_KEY),
        },
        FixtureCreationGuard,
        FixtureTransitionGuard,
    )
    .expect("open encrypted Task Authority")
}

fn founder() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "founder:test".to_owned(),
        authenticated: true,
    }
}

fn collaboration_control() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:test".to_owned(),
        authenticated: true,
    }
}

fn metadata(command_id: &str, idempotency_key: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        idempotency_scope: "recovery-test/v01".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_777_073_600,
            nanos: 0,
        }),
        correlation_id: command_id.to_owned(),
        causation_id: None,
    }
}

fn contract_ref(contract_id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: contract_id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn set_digest(command: &mut TaskCommand) {
    let digest = canonical_request_digest(command).expect("canonical Task request digest");
    match command.command.as_mut().expect("Task command variant") {
        task_command::Command::CreateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::ActivateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::InterruptTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::HoldTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::ResumeTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::RequestTaskCancellation(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::RecordTaskCancellationOutcome(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        _ => panic!("test helper does not support this command"),
    }
}

fn active_task(authority: &mut TaskAuthority) -> String {
    let mut create = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata("cmd-create-001", "create-001")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-001".to_owned(),
            target_scope_ref: "repo-scope-001".to_owned(),
            acceptance_contract_ref: Some(contract_ref(
                "repository_change_acceptance",
                "1",
                &"a".repeat(64),
            )),
            budget_profile_ref: Some(contract_ref("v01-quality-budget", "0.1", &"b".repeat(64))),
            work_capability_route: None,
        })),
    };
    set_digest(&mut create);
    let created = authority.execute(&create, &founder()).expect("create Task");
    let task_id = match created.outcome.expect("created outcome") {
        task_command_result::Outcome::Task(snapshot) => snapshot.task_id,
        task_command_result::Outcome::Error(error) => {
            panic!("expected created Task, got {}", error.safe_detail_code)
        }
    };
    let mut activate = TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(metadata("cmd-activate-001", "activate-001")),
            task_id: task_id.clone(),
            expected_revision: 1,
            work_revision: 1,
            run_id: "run-001".to_owned(),
        })),
    };
    set_digest(&mut activate);
    let activated = authority
        .execute(&activate, &collaboration_control())
        .expect("activate Task");
    match activated.outcome.expect("activated outcome") {
        task_command_result::Outcome::Task(snapshot) => {
            assert_eq!(snapshot.status, TaskStatus::Active as i32);
            task_id
        }
        task_command_result::Outcome::Error(error) => {
            panic!("expected active Task, got {}", error.safe_detail_code)
        }
    }
}

fn ready_task(authority: &mut TaskAuthority, identity: &str) -> String {
    let mut create = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata(
                &format!("cmd-create-{identity}"),
                &format!("create-{identity}"),
            )),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-001".to_owned(),
            target_scope_ref: "repo-scope-001".to_owned(),
            acceptance_contract_ref: Some(contract_ref(
                "repository_change_acceptance",
                "1",
                &"a".repeat(64),
            )),
            budget_profile_ref: Some(contract_ref("v01-quality-budget", "0.1", &"b".repeat(64))),
            work_capability_route: None,
        })),
    };
    set_digest(&mut create);
    snapshot_of(
        &authority
            .execute(&create, &founder())
            .expect("create Ready Task"),
    )
    .task_id
}

fn snapshot_of(
    result: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
    match result.outcome.clone().expect("Task result outcome") {
        task_command_result::Outcome::Task(snapshot) => snapshot,
        task_command_result::Outcome::Error(error) => {
            panic!(
                "expected committed Task, got error {}",
                error.safe_detail_code
            )
        }
    }
}

fn error_code_of(
    result: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskErrorCode {
    match result.outcome.as_ref().expect("Task result outcome") {
        task_command_result::Outcome::Error(error) => {
            TaskErrorCode::try_from(error.code).expect("known Task error code")
        }
        task_command_result::Outcome::Task(_) => panic!("expected Task error"),
    }
}

#[test]
fn interrupt_and_resume_round_trip_restores_active_with_event_provenance() {
    let isolated = IsolatedStore::new("task-interrupt-resume");
    let mut authority = open_authority(&isolated.database_path());
    let task_id = active_task(&mut authority);

    let mut interrupt = TaskCommand {
        command: Some(task_command::Command::InterruptTask(InterruptTaskCommand {
            meta: Some(metadata("cmd-interrupt-001", "interrupt-001")),
            task_id: task_id.clone(),
            expected_revision: 2,
            interruption_evidence_id: "crash-receipt-001".to_owned(),
        })),
    };
    set_digest(&mut interrupt);
    let interrupted = authority
        .execute(&interrupt, &collaboration_control())
        .expect("interrupt Task");
    let snapshot = snapshot_of(&interrupted);
    assert_eq!(snapshot.status, TaskStatus::Interrupted as i32);
    assert_eq!(snapshot.revision, 3);
    assert_eq!(
        interrupted.committed_event.as_ref().expect("event").kind,
        TaskEventKind::Interrupted as i32
    );

    let replayed = authority
        .execute(&interrupt, &collaboration_control())
        .expect("replay interrupt idempotently");
    assert!(replayed.replayed);

    let mut resume = TaskCommand {
        command: Some(task_command::Command::ResumeTask(ResumeTaskCommand {
            meta: Some(metadata("cmd-resume-001", "resume-001")),
            task_id: task_id.clone(),
            expected_revision: 3,
            expected_resume_status: TaskStatus::Active as i32,
            recovery_evidence_id: "recovery-plan-001".to_owned(),
        })),
    };
    set_digest(&mut resume);
    let resumed = authority
        .execute(&resume, &collaboration_control())
        .expect("resume Task");
    let snapshot = snapshot_of(&resumed);
    assert_eq!(snapshot.status, TaskStatus::Active as i32);
    assert_eq!(snapshot.revision, 4);
    assert_eq!(
        resumed.committed_event.as_ref().expect("event").kind,
        TaskEventKind::Resumed as i32
    );
}

#[test]
fn hold_requires_reason_and_recovery_evidence_and_resumes_to_active_only() {
    let isolated = IsolatedStore::new("task-hold-resume");
    let mut authority = open_authority(&isolated.database_path());
    let task_id = active_task(&mut authority);

    let mut incomplete = TaskCommand {
        command: Some(task_command::Command::HoldTask(HoldTaskCommand {
            meta: Some(metadata("cmd-hold-bad", "hold-bad")),
            task_id: task_id.clone(),
            expected_revision: 2,
            hold_reason_code: "  ".to_owned(),
            recovery_evidence_id: String::new(),
        })),
    };
    set_digest(&mut incomplete);
    let rejected = authority
        .execute(&incomplete, &collaboration_control())
        .expect("reject incomplete hold");
    assert_eq!(error_code_of(&rejected), TaskErrorCode::StateConflict);

    let mut hold = TaskCommand {
        command: Some(task_command::Command::HoldTask(HoldTaskCommand {
            meta: Some(metadata("cmd-hold-001", "hold-001")),
            task_id: task_id.clone(),
            expected_revision: 2,
            hold_reason_code: "awaiting_external_dependency".to_owned(),
            recovery_evidence_id: "recovery-plan-002".to_owned(),
        })),
    };
    set_digest(&mut hold);
    let held = authority
        .execute(&hold, &collaboration_control())
        .expect("hold Task");
    assert_eq!(snapshot_of(&held).status, TaskStatus::Held as i32);

    let mut wrong_target = TaskCommand {
        command: Some(task_command::Command::ResumeTask(ResumeTaskCommand {
            meta: Some(metadata("cmd-resume-bad-target", "resume-bad-target")),
            task_id: task_id.clone(),
            expected_revision: 3,
            expected_resume_status: TaskStatus::Ready as i32,
            recovery_evidence_id: "recovery-plan-002".to_owned(),
        })),
    };
    set_digest(&mut wrong_target);
    let rejected = authority
        .execute(&wrong_target, &collaboration_control())
        .expect("reject non-active resume target");
    assert_eq!(error_code_of(&rejected), TaskErrorCode::StateConflict);

    let mut resume = TaskCommand {
        command: Some(task_command::Command::ResumeTask(ResumeTaskCommand {
            meta: Some(metadata("cmd-resume-002", "resume-002")),
            task_id: task_id.clone(),
            expected_revision: 3,
            expected_resume_status: TaskStatus::Active as i32,
            recovery_evidence_id: "recovery-plan-002".to_owned(),
        })),
    };
    set_digest(&mut resume);
    let resumed = authority
        .execute(&resume, &collaboration_control())
        .expect("resume held Task");
    assert_eq!(snapshot_of(&resumed).status, TaskStatus::Active as i32);
}

#[test]
fn interruption_and_resume_fail_closed_for_wrong_status_or_principal() {
    let isolated = IsolatedStore::new("task-recovery-guards");
    let mut authority = open_authority(&isolated.database_path());
    let task_id = active_task(&mut authority);

    let mut resume_active = TaskCommand {
        command: Some(task_command::Command::ResumeTask(ResumeTaskCommand {
            meta: Some(metadata("cmd-resume-active", "resume-active")),
            task_id: task_id.clone(),
            expected_revision: 2,
            expected_resume_status: TaskStatus::Active as i32,
            recovery_evidence_id: "recovery-plan-003".to_owned(),
        })),
    };
    set_digest(&mut resume_active);
    let rejected = authority
        .execute(&resume_active, &collaboration_control())
        .expect("reject resume of an Active Task");
    assert_eq!(error_code_of(&rejected), TaskErrorCode::StateConflict);

    let mut founder_interrupt = TaskCommand {
        command: Some(task_command::Command::InterruptTask(InterruptTaskCommand {
            meta: Some(metadata("cmd-interrupt-founder", "interrupt-founder")),
            task_id: task_id.clone(),
            expected_revision: 2,
            interruption_evidence_id: "crash-receipt-002".to_owned(),
        })),
    };
    set_digest(&mut founder_interrupt);
    let denied = authority
        .execute(&founder_interrupt, &founder())
        .expect("reject Founder interruption");
    assert_eq!(error_code_of(&denied), TaskErrorCode::PermissionDenied);
}

#[test]
fn cancellation_outcome_terminates_the_cancel_loop_under_collaboration_control_only() {
    let isolated = IsolatedStore::new("task-cancellation-outcome");
    let mut authority = open_authority(&isolated.database_path());
    let task_id = active_task(&mut authority);

    let mut request = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(metadata("cmd-cancel-001", "cancel-001")),
                task_id: task_id.clone(),
                expected_revision: 2,
                reason_code: "founder_abandoned".to_owned(),
            },
        )),
    };
    set_digest(&mut request);
    let requested = authority
        .execute(&request, &founder())
        .expect("request cancellation");
    assert_eq!(
        snapshot_of(&requested).status,
        TaskStatus::CancellationPending as i32
    );

    let mut founder_outcome = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(metadata("cmd-outcome-founder", "outcome-founder")),
                task_id: task_id.clone(),
                expected_revision: 3,
                outcome: TaskStatus::Cancelled as i32,
                cancellation_receipt_id: "receipt-001".to_owned(),
            },
        )),
    };
    set_digest(&mut founder_outcome);
    let denied = authority
        .execute(&founder_outcome, &founder())
        .expect("reject Founder-owned cancellation outcome");
    assert_eq!(error_code_of(&denied), TaskErrorCode::PermissionDenied);

    let mut wrong_outcome = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(metadata("cmd-outcome-wrong", "outcome-wrong")),
                task_id: task_id.clone(),
                expected_revision: 3,
                outcome: TaskStatus::Completed as i32,
                cancellation_receipt_id: "receipt-001".to_owned(),
            },
        )),
    };
    set_digest(&mut wrong_outcome);
    let rejected = authority
        .execute(&wrong_outcome, &collaboration_control())
        .expect("reject non-cancelled outcome");
    assert_eq!(error_code_of(&rejected), TaskErrorCode::StateConflict);

    let mut outcome = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(metadata("cmd-outcome-001", "outcome-001")),
                task_id: task_id.clone(),
                expected_revision: 3,
                outcome: TaskStatus::Cancelled as i32,
                cancellation_receipt_id: "receipt-001".to_owned(),
            },
        )),
    };
    set_digest(&mut outcome);
    let cancelled = authority
        .execute(&outcome, &collaboration_control())
        .expect("record cancellation outcome");
    let snapshot = snapshot_of(&cancelled);
    assert_eq!(snapshot.status, TaskStatus::Cancelled as i32);
    assert_eq!(snapshot.revision, 4);
    assert_eq!(
        cancelled.committed_event.as_ref().expect("event").kind,
        TaskEventKind::CancellationRecorded as i32
    );

    let replayed = authority
        .execute(&outcome, &collaboration_control())
        .expect("replay cancellation outcome idempotently");
    assert!(replayed.replayed);
}

#[test]
fn active_cancellation_handoff_replays_exactly_across_authority_restart() {
    let isolated = IsolatedStore::new("task-cancellation-handoff-recovery");
    let mut authority = open_authority(&isolated.database_path());
    let task_id = active_task(&mut authority);

    let mut request = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(metadata("cmd-cancel-handoff-001", "cancel-handoff-001")),
                task_id: task_id.clone(),
                expected_revision: 2,
                reason_code: "founder_abandoned".to_owned(),
            },
        )),
    };
    set_digest(&mut request);
    let requested = authority
        .execute(&request, &founder())
        .expect("commit active cancellation request");
    let event_id = requested
        .committed_event
        .as_ref()
        .expect("cancellation event")
        .event_id
        .clone();
    let pending = authority
        .pending_task_cancellations()
        .expect("read cancellation handoff");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event.event_id, event_id);
    assert_eq!(
        pending[0]
            .event
            .snapshot
            .as_ref()
            .expect("snapshot")
            .task_id,
        task_id
    );
    assert_eq!(
        pending[0]
            .event
            .snapshot
            .as_ref()
            .expect("snapshot")
            .current_run_id
            .as_deref(),
        Some("run-001")
    );
    let message_id = pending[0].message_id.clone();
    let payload_digest = pending[0].payload_digest_sha256.clone();

    drop(authority);
    let mut recovered = open_authority(&isolated.database_path());
    let replayed = recovered
        .execute(&request, &founder())
        .expect("replay cancellation request after restart");
    assert!(replayed.replayed);
    let recovered_pending = recovered
        .pending_task_cancellations()
        .expect("recover cancellation handoff");
    assert_eq!(recovered_pending.len(), 1);
    assert_eq!(recovered_pending[0].message_id, message_id);
    assert_eq!(recovered_pending[0].payload_digest_sha256, payload_digest);
    assert_eq!(recovered_pending[0].event.event_id, event_id);

    assert!(
        recovered
            .acknowledge_cross_authority_outbox(&message_id, &payload_digest)
            .expect("acknowledge exact cancellation handoff")
    );
    assert!(
        recovered
            .pending_task_cancellations()
            .expect("read acknowledged cancellation handoff")
            .is_empty()
    );
}

#[test]
fn ready_cancellation_settles_from_exact_task_event_without_native_run() {
    let isolated = IsolatedStore::new("ready-task-cancellation");
    let database_path = isolated.database_path();
    let mut authority = open_authority(&database_path);
    let task_id = ready_task(&mut authority, "ready-cancel");
    let mut request = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(metadata("cmd-cancel-ready", "cancel-ready")),
                task_id: task_id.clone(),
                expected_revision: 1,
                reason_code: "founder_abandoned".to_owned(),
            },
        )),
    };
    set_digest(&mut request);
    authority
        .execute(&request, &founder())
        .expect("request Ready cancellation");
    let pending = authority
        .pending_task_cancellations()
        .expect("read Ready cancellation handoff");
    assert_eq!(pending.len(), 1);
    assert!(
        pending[0]
            .event
            .snapshot
            .as_ref()
            .expect("frozen Task")
            .current_run_id
            .is_none()
    );

    let settled = authority
        .reconcile_task_cancellation(
            &pending[0].message_id,
            &pending[0].payload_digest_sha256,
            &collaboration_control(),
        )
        .expect("settle Ready cancellation");
    assert_eq!(
        settled,
        TaskCancellationReconciliation::SettledAndAcknowledged {
            status: TaskStatus::Cancelled,
            committed: true,
            replayed: false,
        }
    );
    assert!(
        authority
            .pending_task_cancellations()
            .expect("cancellation handoff consumed")
            .is_empty()
    );
    let snapshot = authority.get_task(&task_id).expect("read cancelled Task");
    let task = match snapshot.outcome.expect("Task outcome") {
        egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome::Task(
            task,
        ) => task,
        _ => panic!("expected Task snapshot"),
    };
    assert_eq!(task.status, TaskStatus::Cancelled as i32);
    assert!(task.current_run_id.is_none());

    drop(authority);
    let reopened = open_authority(&database_path);
    assert!(
        reopened
            .pending_task_cancellations()
            .expect("reopen consumed cancellation")
            .is_empty()
    );
}

#[test]
fn ready_cancellation_rejects_forged_evidence_and_cleans_late_ack_after_restart() {
    let isolated = IsolatedStore::new("ready-task-cancellation-replay");
    let database_path = isolated.database_path();
    let mut authority = open_authority(&database_path);
    let task_id = ready_task(&mut authority, "ready-replay");
    let mut request = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(metadata("cmd-cancel-ready-replay", "cancel-ready-replay")),
                task_id: task_id.clone(),
                expected_revision: 1,
                reason_code: "founder_abandoned".to_owned(),
            },
        )),
    };
    set_digest(&mut request);
    authority
        .execute(&request, &founder())
        .expect("request Ready cancellation");
    let pending = authority
        .pending_task_cancellations()
        .expect("read Ready cancellation handoff")
        .pop()
        .expect("one cancellation handoff");

    let mut forged = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(metadata("cmd-ready-forged", "ready-forged")),
                task_id: task_id.clone(),
                expected_revision: 2,
                outcome: TaskStatus::Cancelled as i32,
                cancellation_receipt_id: "task-event-forged".to_owned(),
            },
        )),
    };
    set_digest(&mut forged);
    let rejected = authority
        .execute(&forged, &collaboration_control())
        .expect("reject forged Ready cancellation evidence");
    assert_eq!(error_code_of(&rejected), TaskErrorCode::UnverifiedReference);

    let mut exact = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(CommandMetadata {
                    command_id: format!("settle-ready-cancellation-{}", pending.event.event_id),
                    idempotency_key: format!("ready-cancellation:{}", pending.event.event_id),
                    idempotency_scope: "task-authority/ready-cancellation/v1".to_owned(),
                    request_digest_sha256: String::new(),
                    issued_at: pending.event.occurred_at,
                    correlation_id: pending.event.correlation_id.clone(),
                    causation_id: Some(pending.event.event_id.clone()),
                }),
                task_id: task_id.clone(),
                expected_revision: 2,
                outcome: TaskStatus::Cancelled as i32,
                cancellation_receipt_id: pending.event.event_id.clone(),
            },
        )),
    };
    set_digest(&mut exact);
    let committed = authority
        .execute(&exact, &collaboration_control())
        .expect("commit exact Ready cancellation outcome before ACK");
    assert!(!committed.replayed);
    let replayed = authority
        .execute(&exact, &collaboration_control())
        .expect("replay exact cancellation outcome");
    assert!(replayed.replayed);

    drop(authority);
    let mut reopened = open_authority(&database_path);
    let reconciled = reopened
        .reconcile_task_cancellation(
            &pending.message_id,
            &pending.payload_digest_sha256,
            &collaboration_control(),
        )
        .expect("consume late ACK after restart");
    assert_eq!(
        reconciled,
        TaskCancellationReconciliation::SettledAndAcknowledged {
            status: TaskStatus::Cancelled,
            committed: false,
            replayed: true,
        }
    );
    assert!(
        reopened
            .pending_task_cancellations()
            .expect("late ACK consumed")
            .is_empty()
    );
}

#[test]
fn terminal_active_run_consumes_late_cancellation_ack_without_redelivery() {
    let isolated = IsolatedStore::new("active-task-cancellation-late-ack");
    let database_path = isolated.database_path();
    let mut authority = open_authority(&database_path);
    let task_id = active_task(&mut authority);
    let mut request = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(metadata("cmd-cancel-late-ack", "cancel-late-ack")),
                task_id: task_id.clone(),
                expected_revision: 2,
                reason_code: "founder_abandoned".to_owned(),
            },
        )),
    };
    set_digest(&mut request);
    authority
        .execute(&request, &founder())
        .expect("request active cancellation");
    let pending = authority
        .pending_task_cancellations()
        .expect("read active cancellation handoff")
        .pop()
        .expect("one cancellation handoff");

    let mut outcome = TaskCommand {
        command: Some(task_command::Command::RecordTaskCancellationOutcome(
            RecordTaskCancellationOutcomeCommand {
                meta: Some(metadata("cmd-cancel-return", "cancel-return")),
                task_id,
                expected_revision: 3,
                outcome: TaskStatus::Interrupted as i32,
                cancellation_receipt_id: "sealed-return:artifact-001".to_owned(),
            },
        )),
    };
    set_digest(&mut outcome);
    let interrupted = authority
        .execute(&outcome, &collaboration_control())
        .expect("record evidence-backed interrupted outcome");
    assert_eq!(
        snapshot_of(&interrupted).status,
        TaskStatus::Interrupted as i32
    );

    drop(authority);
    let mut reopened = open_authority(&database_path);
    let reconciled = reopened
        .reconcile_task_cancellation(
            &pending.message_id,
            &pending.payload_digest_sha256,
            &collaboration_control(),
        )
        .expect("consume terminal active-run cancellation ACK");
    assert_eq!(
        reconciled,
        TaskCancellationReconciliation::SettledAndAcknowledged {
            status: TaskStatus::Interrupted,
            committed: false,
            replayed: true,
        }
    );
    assert!(
        reopened
            .pending_task_cancellations()
            .expect("late active-run ACK consumed")
            .is_empty()
    );
}
