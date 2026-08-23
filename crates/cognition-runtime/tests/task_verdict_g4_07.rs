use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand, FounderDecision,
    RecordTaskVerificationCommand, ReviseTaskCommand, SubmitTaskEvidenceCommand, TaskCommand,
    TaskErrorCode, TaskSnapshot, TaskStatus, task_command, task_command_result,
};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{VerdictCommand, verdict_command};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["creation-proof-01".to_owned()],
        })
    }
}

#[derive(Clone, Copy)]
struct StaticTransitionGuard {
    decision: FounderDecision,
    reject_apply: bool,
}

impl TaskTransitionGuard for StaticTransitionGuard {
    fn validate(
        &self,
        command: &TaskCommand,
        _current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        if self.reject_apply
            && matches!(
                command.command,
                Some(task_command::Command::ApplyFounderVerdict(_))
            )
        {
            return Err(TransitionGuardRejection::StaleReference);
        }
        let apply = matches!(
            command.command,
            Some(task_command::Command::ApplyFounderVerdict(_))
        );
        Ok(TransitionAuthorization {
            evidence_refs: vec!["resolved-owner-proof-01".to_owned()],
            founder_decision: apply.then_some(self.decision),
            founder_verdict_state_revision: apply.then_some(1),
        })
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("egopulse-task-g4-07-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated test directory");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("egopulse-task-g4-07-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn accept_drives_one_terminal_task_commit_and_durable_verdict_consume_outbox() {
    let (_root, mut authority) = authority("accept", FounderDecision::Accept, false);
    let task = advance_to_verdict_pending(&mut authority);
    let apply = apply_command(&task, "founder-verdict-accept-01");
    let applied = execute(
        &mut authority,
        apply.clone(),
        principal(PrincipalKind::FounderAuthority),
    );
    let completed = task_from(applied.clone());
    assert_eq!(completed.status, TaskStatus::Completed as i32);
    assert_eq!(completed.revision, task.revision + 1);
    assert_eq!(
        completed.founder_verdict_id.as_deref(),
        Some("founder-verdict-accept-01")
    );
    let event = applied.committed_event.expect("task event committed");
    assert!(
        authority
            .commit_receipt_exists(&event.event_id, &task.task_id, completed.revision)
            .expect("receipt lookup")
    );

    let pending = authority
        .pending_cross_authority_outbox()
        .expect("cross outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].destination_domain, "founder-verdict-authority");
    assert_eq!(
        pending[0].payload_digest_sha256,
        hex::encode(Sha256::digest(&pending[0].payload))
    );
    let consume =
        VerdictCommand::decode(pending[0].payload.as_slice()).expect("decode consume command");
    let Some(verdict_command::Command::ConsumeFounderVerdict(consume)) = consume.command else {
        panic!("consume verdict command expected");
    };
    assert_eq!(consume.founder_verdict_id, "founder-verdict-accept-01");
    assert_eq!(consume.task_event_id, event.event_id);
    assert_eq!(consume.consumed_task_revision, task.revision);
    assert_eq!(consume.resulting_task_revision, completed.revision);
    assert_eq!(consume.resulting_task_status, "TASK_STATUS_COMPLETED");

    let replay = execute(
        &mut authority,
        apply,
        principal(PrincipalKind::FounderAuthority),
    );
    assert!(replay.replayed);
    assert_eq!(
        authority
            .inspect_store()
            .expect("inspect")
            .cross_authority_outbox_count,
        1
    );

    let denied = execute(
        &mut authority,
        apply_command(&completed, "founder-verdict-other"),
        principal(PrincipalKind::Harness),
    );
    assert_eq!(error_code(denied), TaskErrorCode::PermissionDenied);
    assert_eq!(
        authority
            .get_task(&task.task_id)
            .expect("get")
            .outcome
            .map(task_from_outcome)
            .expect("task")
            .revision,
        completed.revision
    );
}

#[test]
fn rework_requires_separate_revision_command_and_clears_old_work_bindings() {
    let (_root, mut authority) = authority("rework", FounderDecision::Rework, false);
    let task = advance_to_verdict_pending(&mut authority);
    let rework = task_from(execute(
        &mut authority,
        apply_command(&task, "founder-verdict-rework-01"),
        principal(PrincipalKind::FounderAuthority),
    ));
    assert_eq!(rework.status, TaskStatus::Rework as i32);
    assert_eq!(rework.work_revision, 1);

    let revised = task_from(execute(
        &mut authority,
        revise_command(&rework),
        principal(PrincipalKind::FounderAuthority),
    ));
    assert_eq!(revised.status, TaskStatus::Ready as i32);
    assert_eq!(revised.work_revision, 2);
    assert_eq!(revised.input_snapshot_id, "input-snapshot-02");
    assert!(revised.current_run_id.is_none());
    assert!(revised.artifact_set_id.is_none());
    assert!(revised.verification_artifact_id.is_none());
    assert!(revised.founder_verdict_id.is_none());
}

#[test]
fn reject_drives_rejected_terminal_state_and_matching_consume_command() {
    let (_root, mut authority) = authority("reject", FounderDecision::Reject, false);
    let task = advance_to_verdict_pending(&mut authority);
    let rejected = task_from(execute(
        &mut authority,
        apply_command(&task, "founder-verdict-reject-01"),
        principal(PrincipalKind::FounderAuthority),
    ));
    assert_eq!(rejected.status, TaskStatus::Rejected as i32);
    assert_eq!(rejected.revision, task.revision + 1);
    assert_eq!(
        rejected.founder_verdict_id.as_deref(),
        Some("founder-verdict-reject-01")
    );

    let pending = authority
        .pending_cross_authority_outbox()
        .expect("cross outbox");
    assert_eq!(pending.len(), 1);
    let consume =
        VerdictCommand::decode(pending[0].payload.as_slice()).expect("decode consume command");
    let Some(verdict_command::Command::ConsumeFounderVerdict(consume)) = consume.command else {
        panic!("consume verdict command expected");
    };
    assert_eq!(consume.resulting_task_status, "TASK_STATUS_REJECTED");
    assert_eq!(consume.consumed_task_revision, task.revision);
    assert_eq!(consume.resulting_task_revision, rejected.revision);
}

#[test]
fn stale_verdict_guard_and_stale_revision_are_zero_write_failures() {
    let (_root, mut authority) = authority("stale", FounderDecision::Reject, true);
    let task = advance_to_verdict_pending(&mut authority);
    let before = authority.inspect_store().expect("inspect");
    let rejected = execute(
        &mut authority,
        apply_command(&task, "founder-verdict-stale-01"),
        principal(PrincipalKind::FounderAuthority),
    );
    assert_eq!(error_code(rejected), TaskErrorCode::StaleReference);
    assert_eq!(authority.inspect_store().expect("inspect"), before);

    let mut stale = apply_command(&task, "founder-verdict-stale-02");
    let Some(task_command::Command::ApplyFounderVerdict(value)) = stale.command.as_mut() else {
        unreachable!()
    };
    value.expected_revision -= 1;
    resign(&mut stale);
    let rejected = execute(
        &mut authority,
        stale,
        principal(PrincipalKind::FounderAuthority),
    );
    assert_eq!(error_code(rejected), TaskErrorCode::RevisionConflict);
    assert_eq!(authority.inspect_store().expect("inspect"), before);
}

fn authority(
    name: &str,
    decision: FounderDecision,
    reject_apply: bool,
) -> (TempRoot, TaskAuthority) {
    let root = TempRoot::new(name);
    let authority = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.path().join("task.db"),
            store_epoch: format!("epoch-{name}"),
            key: SqlCipherKey::new([47; 32]),
        },
        AllowCreation,
        StaticTransitionGuard {
            decision,
            reject_apply,
        },
    )
    .expect("open task authority");
    (root, authority)
}

fn advance_to_verdict_pending(authority: &mut TaskAuthority) -> TaskSnapshot {
    let created = task_from(execute(
        authority,
        create_command(),
        principal(PrincipalKind::Founder),
    ));
    let active = task_from(execute(
        authority,
        activate_command(&created),
        principal(PrincipalKind::CollaborationControl),
    ));
    let evidence = task_from(execute(
        authority,
        evidence_command(&active),
        principal(PrincipalKind::CollaborationControl),
    ));
    let verified = task_from(execute(
        authority,
        verification_command(&evidence),
        principal(PrincipalKind::SegoVerification),
    ));
    assert_eq!(verified.status, TaskStatus::VerdictPending as i32);
    verified
}

fn execute(
    authority: &mut TaskAuthority,
    mut command: TaskCommand,
    principal: AuthenticatedPrincipal,
) -> egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult {
    resign(&mut command);
    authority
        .execute(&command, &principal)
        .expect("task command result")
}

fn resign(command: &mut TaskCommand) {
    let digest = canonical_request_digest(command).expect("canonical digest");
    let meta = match command.command.as_mut().expect("command") {
        task_command::Command::CreateTask(v) => v.meta.as_mut(),
        task_command::Command::ActivateTask(v) => v.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(v) => v.meta.as_mut(),
        task_command::Command::RecordTaskVerification(v) => v.meta.as_mut(),
        task_command::Command::ApplyFounderVerdict(v) => v.meta.as_mut(),
        task_command::Command::ReviseTask(v) => v.meta.as_mut(),
        _ => unreachable!(),
    }
    .expect("metadata");
    meta.request_digest_sha256 = digest;
}

fn create_command() -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(meta("create")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-snapshot-01".to_owned(),
            target_scope_ref: "scope-01".to_owned(),
            acceptance_contract_ref: Some(contract_ref("acceptance", SHA_A)),
            budget_profile_ref: Some(contract_ref("budget", SHA_B)),
        })),
    }
}
fn activate_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(meta("activate")),
            task_id: task.task_id.clone(),
            expected_revision: task.revision,
            work_revision: task.work_revision,
            run_id: "run-01".to_owned(),
        })),
    }
}
fn evidence_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::SubmitTaskEvidence(
            SubmitTaskEvidenceCommand {
                meta: Some(meta("evidence")),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                return_handoff_id: "handoff-01".to_owned(),
                artifact_set_id: "artifact-set-01".to_owned(),
            },
        )),
    }
}
fn verification_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::RecordTaskVerification(
            RecordTaskVerificationCommand {
                meta: Some(meta("verification")),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                verification_artifact_id: "verification-artifact-01".to_owned(),
            },
        )),
    }
}
fn apply_command(task: &TaskSnapshot, verdict_id: &str) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(meta("apply")),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                founder_verdict_id: verdict_id.to_owned(),
            },
        )),
    }
}
fn revise_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::ReviseTask(ReviseTaskCommand {
            meta: Some(meta("revise")),
            task_id: task.task_id.clone(),
            expected_revision: task.revision,
            expected_work_revision: task.work_revision,
            new_input_snapshot_id: "input-snapshot-02".to_owned(),
            new_target_scope_ref: "scope-02".to_owned(),
            new_acceptance_contract_ref: Some(contract_ref("acceptance", SHA_B)),
        })),
    }
}

fn task_from(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("outcome") {
        task_command_result::Outcome::Task(task) => task,
        task_command_result::Outcome::Error(error) => panic!("unexpected task error: {:?}", error),
    }
}
fn task_from_outcome(
    outcome: egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome,
) -> TaskSnapshot {
    match outcome {
        egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome::Task(
            task,
        ) => task,
        _ => panic!("task expected"),
    }
}
fn error_code(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskErrorCode {
    match result.outcome.expect("outcome") {
        task_command_result::Outcome::Error(error) => {
            TaskErrorCode::try_from(error.code).expect("known code")
        }
        _ => panic!("error expected"),
    }
}
fn principal(kind: PrincipalKind) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind,
        principal_id: format!("principal-{kind:?}"),
        authenticated: true,
    }
}
fn contract_ref(id: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: digest.to_owned(),
    }
}
fn meta(prefix: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command-{prefix}-{}", Uuid::now_v7()),
        idempotency_key: format!("idem-{prefix}-{}", Uuid::now_v7()),
        idempotency_scope: "g4-07".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }),
        correlation_id: format!("correlation-{prefix}"),
        causation_id: None,
    }
}
