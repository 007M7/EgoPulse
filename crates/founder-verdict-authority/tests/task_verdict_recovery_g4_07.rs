use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection,
    canonical_request_digest as task_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{ContentAddress, HashAlgorithm};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand, FounderDecision,
    RecordTaskVerificationCommand, SubmitTaskEvidenceCommand, TaskCommand, TaskSnapshot,
    TaskStatus, task_command, task_command_result,
};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    ConfirmationClass, FounderVerdictDecision, IssueFounderVerdictCommand, VerdictCommand,
    VerdictScope, verdict_command,
};
use egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationConclusion;
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictAuthorityFailure, VerdictClock,
    VerdictPrincipalKind, VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
    canonical_request_digest as verdict_request_digest,
};
use prost::Message;
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy)]
struct FixedClock;
impl VerdictClock for FixedClock {
    fn now(&self) -> Result<Timestamp, VerdictAuthorityFailure> {
        Ok(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        })
    }
}

struct AllowCreation;
impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["creation-proof".to_owned()],
        })
    }
}

#[derive(Clone, Default)]
struct SharedState {
    issued_verdict_id: Arc<Mutex<Option<String>>>,
    issue_context: Arc<Mutex<Option<ResolvedVerdictContext>>>,
    task_commit_valid: Arc<Mutex<bool>>,
}

#[derive(Clone)]
struct IntegratedGuard(SharedState);

impl TaskTransitionGuard for IntegratedGuard {
    fn validate(
        &self,
        command: &TaskCommand,
        _: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        let apply = match command.command.as_ref() {
            Some(task_command::Command::ApplyFounderVerdict(value)) => Some(value),
            _ => None,
        };
        if let Some(apply) = apply {
            let issued = self.0.issued_verdict_id.lock().expect("issued lock");
            if issued.as_deref() != Some(apply.founder_verdict_id.as_str()) {
                return Err(TransitionGuardRejection::StaleReference);
            }
        }
        Ok(TransitionAuthorization {
            evidence_refs: vec!["resolved-proof".to_owned()],
            founder_decision: apply.map(|_| FounderDecision::Accept),
            founder_verdict_state_revision: apply.map(|_| 1),
        })
    }
}

impl VerdictReferenceResolver for IntegratedGuard {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        _: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        let context = self
            .0
            .issue_context
            .lock()
            .expect("context lock")
            .clone()
            .ok_or(VerdictReferenceRejection::NotFound)?;
        Ok((
            context,
            FounderAuthorization {
                authenticated_founder_principal_id: "founder:local".to_owned(),
                authority_ref: "founder-authority:local".to_owned(),
                confirmation_class: ConfirmationClass::Explicit,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: Timestamp {
                    seconds: 1_781_999_900,
                    nanos: 0,
                },
                valid_until: Timestamp {
                    seconds: 1_782_000_300,
                    nanos: 0,
                },
                authority_policy_ref: contract_ref("founder-policy", SHA_B),
                evidence_refs: vec!["confirmation-proof".to_owned()],
            },
        ))
    }
    fn validate_task_commit(
        &self,
        _: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
    ) -> Result<(), VerdictReferenceRejection> {
        (*self.0.task_commit_valid.lock().expect("receipt lock"))
            .then_some(())
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    }
}

struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-07-recovery-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("temp root");
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
            .is_some_and(|v| v.starts_with("egopulse-g4-07-recovery-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn task_commit_survives_abort_before_verdict_consumption_and_replays_once() {
    let root = TempRoot::new();
    let shared = SharedState::default();
    let guard = IntegratedGuard(shared.clone());
    let mut task = open_task(root.path(), guard.clone());
    let pending = advance_to_verdict_pending(&mut task);
    let activations = task
        .pending_task_activations()
        .expect("activated Task handoff");
    assert_eq!(activations.len(), 1);
    assert!(
        task.acknowledge_cross_authority_outbox(
            &activations[0].message_id,
            &activations[0].payload_digest_sha256,
        )
        .expect("acknowledge Collaboration activation handoff")
    );
    assert!(
        task.pending_cross_authority_outbox()
            .expect("activation outbox drained")
            .is_empty()
    );
    let scope = VerdictScope {
        task_id: pending.task_id.clone(),
        task_revision: pending.revision,
        work_revision: pending.work_revision,
        artifact_set_id: pending.artifact_set_id.clone().expect("artifact set"),
        artifact_set_manifest: Some(address(SHA_A)),
        verification_artifact_id: pending
            .verification_artifact_id
            .clone()
            .expect("verification"),
        verification_payload: Some(address(SHA_B)),
        acceptance_contract_ref: pending.acceptance_contract_ref.clone(),
    };
    *shared.issue_context.lock().expect("context lock") = Some(ResolvedVerdictContext {
        scope: scope.clone(),
        verification_conclusion: VerificationConclusion::Passed,
        open_discrepancy_ids: vec![],
        open_unverified_item_ids: vec![],
        non_overridable_gate_ids: vec![],
    });

    let mut verdict = open_verdict(root.path(), guard.clone());
    let issued = verdict
        .execute(
            &signed_issue(scope),
            &verdict_principal(VerdictPrincipalKind::FounderAuthority),
        )
        .expect("issue verdict");
    let verdict_id = issued.verdict.expect("verdict").founder_verdict_id;
    *shared.issued_verdict_id.lock().expect("issued lock") = Some(verdict_id.clone());

    let applied = execute_task(
        &mut task,
        apply_command(&pending, &verdict_id),
        PrincipalKind::FounderAuthority,
    );
    let completed = task_from(applied.clone());
    let event = applied.committed_event.expect("event");
    assert_eq!(completed.status, TaskStatus::Completed as i32);
    assert_eq!(
        task.pending_cross_authority_outbox().expect("outbox").len(),
        1
    );

    drop(task);
    drop(verdict);

    let reopened_task = open_task(root.path(), guard.clone());
    let restored = reopened_task
        .get_task(&pending.task_id)
        .expect("get task")
        .outcome
        .map(task_outcome)
        .expect("task");
    assert_eq!(restored.revision, completed.revision);
    assert!(
        reopened_task
            .commit_receipt_exists(&event.event_id, &pending.task_id, completed.revision)
            .expect("receipt")
    );
    let outbox = reopened_task
        .pending_cross_authority_outbox()
        .expect("replayed outbox");
    assert_eq!(outbox.len(), 1);
    *shared.task_commit_valid.lock().expect("receipt lock") = true;

    let mut reopened_verdict = open_verdict(root.path(), guard);
    let consume = VerdictCommand::decode(outbox[0].payload.as_slice()).expect("consume payload");
    let consumed = reopened_verdict
        .execute(
            &consume,
            &verdict_principal(VerdictPrincipalKind::TaskAuthority),
        )
        .expect("consume verdict");
    assert!(consumed.committed);
    let replay = reopened_verdict
        .execute(
            &consume,
            &verdict_principal(VerdictPrincipalKind::TaskAuthority),
        )
        .expect("replay consume");
    assert!(replay.replayed);
    let inspection = reopened_verdict.inspect_store().expect("inspect");
    assert_eq!(inspection.consumption_receipt_count, 1);
    assert_eq!(inspection.event_count, 2);
    assert_eq!(
        reopened_task
            .get_task(&pending.task_id)
            .expect("get task")
            .outcome
            .map(task_outcome)
            .expect("task")
            .revision,
        completed.revision
    );
}

fn open_task(root: &Path, guard: IntegratedGuard) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task.db"),
            store_epoch: "task-epoch".to_owned(),
            key: SqlCipherKey::new([51; 32]),
        },
        AllowCreation,
        guard,
    )
    .expect("open task")
}
fn open_verdict(root: &Path, guard: IntegratedGuard) -> FounderVerdictAuthority<FixedClock> {
    FounderVerdictAuthority::open_with_clock(
        VerdictAuthorityConfig {
            database_path: root.join("verdict.db"),
            store_epoch: "verdict-epoch".to_owned(),
            key: VerdictSqlCipherKey::new([52; 32]),
        },
        guard,
        FixedClock,
    )
    .expect("open verdict")
}

fn advance_to_verdict_pending(task: &mut TaskAuthority) -> TaskSnapshot {
    let created = task_from(execute_task(task, create_command(), PrincipalKind::Founder));
    let active = task_from(execute_task(
        task,
        TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(meta("activate")),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run-01".to_owned(),
            })),
        },
        PrincipalKind::CollaborationControl,
    ));
    let evidence = task_from(execute_task(
        task,
        TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    meta: Some(meta("evidence")),
                    task_id: active.task_id.clone(),
                    expected_revision: active.revision,
                    work_revision: active.work_revision,
                    return_handoff_id: "handoff-01".to_owned(),
                    artifact_set_id: "artifact-set-01".to_owned(),
                },
            )),
        },
        PrincipalKind::CollaborationControl,
    ));
    task_from(execute_task(
        task,
        TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    meta: Some(meta("verification")),
                    task_id: evidence.task_id.clone(),
                    expected_revision: evidence.revision,
                    work_revision: evidence.work_revision,
                    verification_artifact_id: "verification-artifact-01".to_owned(),
                },
            )),
        },
        PrincipalKind::SegoVerification,
    ))
}

fn execute_task(
    task: &mut TaskAuthority,
    mut command: TaskCommand,
    kind: PrincipalKind,
) -> egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult {
    let digest = task_request_digest(&command).expect("task digest");
    match command.command.as_mut().expect("command") {
        task_command::Command::CreateTask(v) => v.meta.as_mut(),
        task_command::Command::ActivateTask(v) => v.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(v) => v.meta.as_mut(),
        task_command::Command::RecordTaskVerification(v) => v.meta.as_mut(),
        task_command::Command::ApplyFounderVerdict(v) => v.meta.as_mut(),
        _ => unreachable!(),
    }
    .expect("meta")
    .request_digest_sha256 = digest;
    task.execute(
        &command,
        &AuthenticatedPrincipal {
            kind,
            principal_id: format!("principal-{kind:?}"),
            authenticated: true,
        },
    )
    .expect("task result")
}

fn signed_issue(scope: VerdictScope) -> VerdictCommand {
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(meta("issue")),
                scope: Some(scope),
                decision: FounderVerdictDecision::Accept as i32,
                observed_verification_conclusion: VerificationConclusion::Passed as i32,
                risk_acceptances: vec![],
                rework_directive: None,
                reason_code: String::new(),
                rationale_artifact_id: None,
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "confirmation-01".to_owned(),
                expires_at: Some(Timestamp {
                    seconds: 1_782_003_600,
                    nanos: 0,
                }),
                supersedes_founder_verdict_id: None,
            },
        )),
    };
    let digest = verdict_request_digest(&command);
    if let Some(verdict_command::Command::IssueFounderVerdict(issue)) = command.command.as_mut() {
        issue.metadata.as_mut().expect("meta").request_digest_sha256 = digest;
    }
    command
}

fn create_command() -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(meta("create")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-01".to_owned(),
            target_scope_ref: "scope-01".to_owned(),
            acceptance_contract_ref: Some(contract_ref("acceptance", SHA_A)),
            budget_profile_ref: Some(contract_ref("budget", SHA_B)),
        })),
    }
}
fn apply_command(task: &TaskSnapshot, verdict: &str) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(meta("apply")),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                founder_verdict_id: verdict.to_owned(),
            },
        )),
    }
}
fn task_from(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("outcome") {
        task_command_result::Outcome::Task(task) => task,
        other => panic!("task expected: {other:?}"),
    }
}
fn task_outcome(
    outcome: egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome,
) -> TaskSnapshot {
    match outcome {
        egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome::Task(
            task,
        ) => task,
        _ => panic!("task expected"),
    }
}
fn verdict_principal(kind: VerdictPrincipalKind) -> AuthenticatedVerdictPrincipal {
    AuthenticatedVerdictPrincipal {
        kind,
        principal_id: format!("verdict-principal-{kind:?}"),
        authenticated: true,
    }
}
fn address(digest: &str) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: digest.to_owned(),
        byte_length: 128,
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
        idempotency_scope: "g4-07-recovery".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }),
        correlation_id: format!("correlation-{prefix}"),
        causation_id: None,
    }
}
