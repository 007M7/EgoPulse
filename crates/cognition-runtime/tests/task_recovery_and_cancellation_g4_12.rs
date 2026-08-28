use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection, canonical_request_digest,
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
