#![forbid(unsafe_code)]

//! Production Task/Founder Verdict composition evidence for G4-07.
//!
//! This test uses the same Authority boundaries as production, but replaces
//! only the external Verification artifact resolver with a deterministic
//! reviewed fixture. It proves that an issued Verdict remains pending until an
//! explicit Task application, and that the durable outboxes can settle after
//! that application without giving Task a Verdict write path.

use egopulse_agentosd::{
    ConfiguredFounderVerdictConsumeWorker, ConfiguredTaskTransitionGuard,
    FounderTaskCommitEvidenceSource, FounderVerdictConsumeCycleResult, FounderVerdictConsumeWorker,
    SharedFounderVerdictAuthority, TaskAuthorityCommitReceiptSource,
};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection, canonical_request_digest as task_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand,
        RecordTaskVerificationCommand, SubmitTaskEvidenceCommand, TaskCommand, TaskSnapshot,
        TaskStatus, task_command, task_command_result,
    },
    verdict::v1::{
        ConfirmationClass, ConsumeFounderVerdictCommand, FounderVerdictDecision,
        FounderVerdictStateKind, IssueFounderVerdictCommand, VerdictCommand, VerdictScope,
        verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictAuthorityFailure, VerdictClock,
    VerdictPrincipalKind, VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
    canonical_request_digest as verdict_digest,
};
use prost::Message;
use prost_types::Timestamp;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
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
            evidence_refs: vec!["g4-07-test:creation-reviewed".to_owned()],
        })
    }
}

struct ApplyGuardClockObservation {
    inner: ConfiguredTaskTransitionGuard,
    apply_entry: Arc<Mutex<Option<Timestamp>>>,
}

impl TaskTransitionGuard for ApplyGuardClockObservation {
    fn validate(
        &self,
        command: &TaskCommand,
        current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        let observed = matches!(
            command.command.as_ref(),
            Some(task_command::Command::ApplyFounderVerdict(_))
        )
        .then(now);
        if let Some(observed) = observed.as_ref() {
            *self
                .apply_entry
                .lock()
                .expect("Apply guard clock observation") = Some(*observed);
        }
        let result = self.inner.validate(command, current);
        if let Some(observed) = observed.as_ref() {
            // Force the system clock past the guard-entry observation without
            // sleeping. Before the production fix, Task captures its event
            // time only after this guard returns, so the invariant below fails
            // deterministically. After the fix, Task has already captured it.
            while timestamp_at_or_before(&now(), observed) {
                std::hint::spin_loop();
            }
        }
        result
    }
}

#[derive(Clone)]
struct StaticVerdictResolver {
    context: ResolvedVerdictContext,
}

impl VerdictReferenceResolver for StaticVerdictResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        if principal.kind != VerdictPrincipalKind::FounderAuthority {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        Ok((
            self.context.clone(),
            FounderAuthorization {
                authenticated_founder_principal_id: "founder:local".to_owned(),
                authority_ref: "founder-authority:g4-07".to_owned(),
                confirmation_class: ConfirmationClass::Explicit,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: now(),
                valid_until: command.expires_at.expect("expiry"),
                authority_policy_ref: contract("founder-policy", 0x33),
                evidence_refs: vec!["g4-07-test:founder-confirmation".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        Ok(())
    }
}

struct ReceiptBackedVerdictResolver {
    issue: StaticVerdictResolver,
    receipts: TaskAuthorityCommitReceiptSource,
}

impl VerdictReferenceResolver for ReceiptBackedVerdictResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        self.issue.resolve_issue(command, principal)
    }

    fn validate_task_commit(
        &self,
        command: &ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        self.receipts.validate_task_commit(command, scope)
    }

    fn validate_task_commit_before_expiry(
        &self,
        command: &ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
        expires_at: &Timestamp,
    ) -> Result<(), VerdictReferenceRejection> {
        self.receipts
            .validate_task_commit_before_expiry(command, scope, expires_at)
    }
}

#[derive(Clone)]
struct FixedVerdictClock(Timestamp);

impl VerdictClock for FixedVerdictClock {
    fn now(&self) -> Result<Timestamp, VerdictAuthorityFailure> {
        Ok(self.0)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("egopulse-g4-07-production-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create G4-07 test root");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn issued_founder_verdict_applies_to_task_and_daemon_consumes_outbox() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let mut task = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.path().join("task.db"),
            store_epoch: "g4-07-task".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        },
        AllowCreation,
        ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(&verdict_handle)),
    )
    .expect("open Task Authority");

    let pending = advance_to_verdict_pending(&mut task);
    let scope = VerdictScope {
        task_id: pending.task_id.clone(),
        task_revision: pending.revision,
        work_revision: pending.work_revision,
        artifact_set_id: pending.artifact_set_id.clone().expect("artifact set"),
        artifact_set_manifest: Some(address(SHA_A)),
        verification_artifact_id: pending
            .verification_artifact_id
            .clone()
            .expect("verification artifact"),
        verification_payload: Some(address(SHA_B)),
        acceptance_contract_ref: pending.acceptance_contract_ref.clone(),
    };
    let verdict_authority = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.path().join("verdict.db"),
            store_epoch: "g4-07-verdict".to_owned(),
            key: VerdictSqlCipherKey::new([42; 32]),
        },
        StaticVerdictResolver {
            context: ResolvedVerdictContext {
                scope: scope.clone(),
                verification_conclusion: VerificationConclusion::Passed,
                open_discrepancy_ids: Vec::new(),
                open_unverified_item_ids: Vec::new(),
                non_overridable_gate_ids: Vec::new(),
            },
        },
    )
    .expect("open Founder Verdict Authority");
    *verdict_handle.lock().expect("verdict handle") = Some(verdict_authority);

    let mut issue = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(metadata("issue")),
                scope: Some(scope),
                decision: FounderVerdictDecision::Accept as i32,
                observed_verification_conclusion: VerificationConclusion::Passed as i32,
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "confirm:g4-07".to_owned(),
                expires_at: Some(Timestamp {
                    seconds: now().seconds + 300,
                    nanos: 0,
                }),
                ..Default::default()
            },
        )),
    };
    seal_verdict(&mut issue);
    let issued = verdict_handle
        .lock()
        .expect("verdict handle")
        .as_mut()
        .expect("verdict authority")
        .execute(
            &issue,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::FounderAuthority,
                principal_id: "founder:local".to_owned(),
                authenticated: true,
            },
        )
        .expect("issue Founder Verdict");
    assert!(issued.committed);
    let verdict_id = issued.verdict.expect("issued verdict").founder_verdict_id;

    let applied = execute_task(
        &mut task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::ApplyFounderVerdict(
                ApplyFounderVerdictCommand {
                    meta: Some(metadata("apply")),
                    task_id: pending.task_id.clone(),
                    expected_revision: pending.revision,
                    work_revision: pending.work_revision,
                    founder_verdict_id: verdict_id.clone(),
                },
            )),
        }),
        PrincipalKind::FounderAuthority,
    );
    let completed = task_from(applied);
    assert_eq!(completed.status, TaskStatus::Completed as i32);
    assert_eq!(completed.revision, pending.revision + 1);
    let outbox = task
        .pending_cross_authority_outbox()
        .expect("Task cross-authority outbox");
    assert_eq!(
        outbox
            .iter()
            .filter(|message| message.destination_domain == "founder-verdict-authority")
            .count(),
        1
    );

    let task = Arc::new(Mutex::new(task));
    let worker = ConfiguredFounderVerdictConsumeWorker::new(
        Arc::clone(&task),
        Arc::clone(&verdict_handle),
        "task-authority:founder-verdict-consumer",
    )
    .expect("configure consume worker");
    let consumed = worker.run_once().await.expect("consume Founder Verdict");
    assert!(matches!(
        consumed,
        FounderVerdictConsumeCycleResult::Consumed {
            replayed: false,
            ..
        }
    ));
    assert!(
        task.lock()
            .expect("Task Authority lock")
            .pending_cross_authority_outbox()
            .expect("pending Task outbox")
            .into_iter()
            .all(|message| message.destination_domain != "founder-verdict-authority")
    );
    let (_, state) = verdict_handle
        .lock()
        .expect("Verdict Authority lock")
        .as_ref()
        .expect("Founder Verdict Authority")
        .get(&verdict_id)
        .expect("read consumed Founder Verdict")
        .expect("stored Founder Verdict");
    assert_eq!(
        state.state,
        egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictStateKind::Consumed
            as i32
    );
}

#[tokio::test]
async fn issued_verdict_worker_does_not_apply_without_explicit_task_command() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let mut task = open_task(root.path(), Arc::clone(&verdict_handle));
    let pending = advance_to_verdict_pending(&mut task);
    let scope = scope_for(&pending);
    install_verdict_authority(root.path(), &verdict_handle, scope.clone());
    let verdict_id = issue_verdict(
        &verdict_handle,
        scope,
        FounderVerdictDecision::Accept,
        now_plus(300),
    );
    let before = task.inspect_store().expect("inspect Task before worker");
    let task = Arc::new(Mutex::new(task));
    let worker = consume_worker(Arc::clone(&task), Arc::clone(&verdict_handle));

    assert_eq!(
        worker.run_once().await.expect("run Issue-only cycle"),
        FounderVerdictConsumeCycleResult::Idle
    );
    assert_eq!(current_task(&task, &pending.task_id), pending);
    assert_eq!(
        task.lock()
            .expect("Task Authority")
            .inspect_store()
            .expect("inspect Task after worker"),
        before,
        "delivery worker must not synthesize an ApplyFounderVerdict command"
    );
    let owner = verdict_handle.lock().expect("verdict handle");
    let verdict = owner.as_ref().expect("Founder Verdict Authority");
    assert_eq!(
        verdict
            .pending_task_handoffs()
            .expect("pending Issue handoff")
            .len(),
        1,
        "Issue notification stays pending until explicit Task application is proven"
    );
    let (_, state) = verdict
        .get(&verdict_id)
        .expect("read Founder Verdict")
        .expect("stored Founder Verdict");
    assert_eq!(state.state, FounderVerdictStateKind::Issued as i32);
}

#[tokio::test]
async fn lost_issue_ack_reopens_and_acks_exact_historical_application_without_second_task_write() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let mut task = open_task(root.path(), Arc::clone(&verdict_handle));
    let pending = advance_to_verdict_pending(&mut task);
    let scope = scope_for(&pending);
    install_verdict_authority(root.path(), &verdict_handle, scope.clone());
    let verdict_id = issue_verdict(
        &verdict_handle,
        scope.clone(),
        FounderVerdictDecision::Accept,
        now_plus(300),
    );

    let applied = execute_task(
        &mut task,
        apply_command(&pending, &verdict_id, "lost-issue-ack"),
        PrincipalKind::FounderAuthority,
    );
    assert_eq!(task_from(applied).status, TaskStatus::Completed as i32);
    let after_apply = task.inspect_store().expect("inspect applied Task store");
    assert!(
        task.applied_founder_verdict(&scope, &verdict_id)
            .expect("resolve exact applied Verdict")
            .is_some()
    );
    assert!(
        task.applied_founder_verdict(&scope, "verdict:other")
            .expect("reject other Verdict identity")
            .is_none()
    );
    let mut wrong_scope = scope.clone();
    wrong_scope.artifact_set_id = "artifact-set:other".to_owned();
    assert!(
        task.applied_founder_verdict(&wrong_scope, &verdict_id)
            .is_err()
    );
    let mut other_task_scope = scope.clone();
    other_task_scope.task_id = "task:other".to_owned();
    assert!(
        task.applied_founder_verdict(&other_task_scope, &verdict_id)
            .expect("other Task has no matching historical event")
            .is_none()
    );
    assert_eq!(
        verdict_handle
            .lock()
            .expect("verdict handle")
            .as_ref()
            .expect("Founder Verdict Authority")
            .pending_task_handoffs()
            .expect("pending Issue handoff")
            .len(),
        1,
        "manual Task application intentionally leaves the Issue handoff unacknowledged"
    );
    drop(task);
    *verdict_handle.lock().expect("verdict handle") = None;

    let reopened = Arc::new(Mutex::new(open_task(
        root.path(),
        Arc::clone(&verdict_handle),
    )));
    install_verdict_authority(root.path(), &verdict_handle, scope.clone());
    assert!(
        reopened
            .lock()
            .expect("reopened Task")
            .applied_founder_verdict(&scope, &verdict_id)
            .expect("recover historical application after reopen")
            .is_some()
    );
    let worker = consume_worker(Arc::clone(&reopened), Arc::clone(&verdict_handle));
    assert!(matches!(
        worker.run_once().await.expect("consume Task outbox first"),
        FounderVerdictConsumeCycleResult::Consumed {
            replayed: false,
            ..
        }
    ));
    let before_ack_recovery = reopened
        .lock()
        .expect("reopened Task")
        .inspect_store()
        .expect("inspect before Issue ACK recovery");
    assert_eq!(before_ack_recovery, after_apply);

    assert!(matches!(
        worker
            .run_once()
            .await
            .expect("recover lost Issue handoff ACK"),
        FounderVerdictConsumeCycleResult::ApplicationAcknowledged {
            ref founder_verdict_id,
            ref task_id,
            replayed: true,
            ..
        } if founder_verdict_id == &verdict_id && task_id == &pending.task_id
    ));
    assert_eq!(
        reopened
            .lock()
            .expect("reopened Task")
            .inspect_store()
            .expect("inspect after Issue ACK recovery"),
        before_ack_recovery,
        "ACK recovery must not append another Task event or idempotency result"
    );
    assert!(
        verdict_handle
            .lock()
            .expect("verdict handle")
            .as_ref()
            .expect("Founder Verdict Authority")
            .pending_task_handoffs()
            .expect("Issue handoff acknowledged")
            .is_empty()
    );
}

#[test]
fn applied_before_expiry_can_be_consumed_after_expiry_with_production_task_receipt() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let apply_guard_entry = Arc::new(Mutex::new(None));
    let mut task = open_task_with_apply_clock_observation(
        root.path(),
        Arc::clone(&verdict_handle),
        Arc::clone(&apply_guard_entry),
    );
    let pending = advance_to_verdict_pending(&mut task);
    let scope = scope_for(&pending);
    install_verdict_authority(root.path(), &verdict_handle, scope.clone());
    let expires_at = now_plus(300);
    let verdict_id = issue_verdict(
        &verdict_handle,
        scope.clone(),
        FounderVerdictDecision::Accept,
        expires_at,
    );
    let applied = execute_task(
        &mut task,
        apply_command(&pending, &verdict_id, "apply-before-expiry"),
        PrincipalKind::FounderAuthority,
    );
    assert_eq!(task_from(applied).status, TaskStatus::Completed as i32);
    let guard_entry = (*apply_guard_entry
        .lock()
        .expect("Apply guard clock observation"))
    .expect("Apply guard was called");
    let application = task
        .applied_founder_verdict(&scope, &verdict_id)
        .expect("read exact applied Verdict")
        .expect("applied Verdict event");
    let occurred_at = application
        .occurred_at
        .as_ref()
        .expect("Task application timestamp");
    assert!(
        timestamp_at_or_before(occurred_at, &guard_entry),
        "Task must capture the commit timestamp before expiry validation"
    );
    let consume = pending_consume_command(&task);
    let receipt = match consume.command.as_ref() {
        Some(verdict_command::Command::ConsumeFounderVerdict(receipt)) => receipt,
        other => panic!("ConsumeFounderVerdict expected, got {other:?}"),
    };
    assert_eq!(receipt.task_event_id, application.event_id);
    assert_eq!(
        receipt.task_commit_receipt_ref,
        format!("task-commit:{}", application.event_id)
    );
    let task = Arc::new(Mutex::new(task));
    *verdict_handle.lock().expect("verdict handle") = None;

    let mut late_authority = FounderVerdictAuthority::open_with_clock(
        VerdictAuthorityConfig {
            database_path: root.path().join("verdict.db"),
            store_epoch: "g4-07-verdict".to_owned(),
            key: VerdictSqlCipherKey::new([42; 32]),
        },
        ReceiptBackedVerdictResolver {
            issue: StaticVerdictResolver {
                context: ResolvedVerdictContext {
                    scope,
                    verification_conclusion: VerificationConclusion::Passed,
                    open_discrepancy_ids: Vec::new(),
                    open_unverified_item_ids: Vec::new(),
                    non_overridable_gate_ids: Vec::new(),
                },
            },
            receipts: TaskAuthorityCommitReceiptSource::new(task),
        },
        FixedVerdictClock(timestamp_after(expires_at)),
    )
    .expect("reopen Founder Verdict Authority after expiry");
    let result = late_authority
        .execute(
            &consume,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::TaskAuthority,
                principal_id: "task-authority:late-receipt".to_owned(),
                authenticated: true,
            },
        )
        .expect("consume receipt applied before expiry");
    assert!(result.committed);
    assert!(!result.replayed);
    assert_eq!(
        result.state.expect("consumed state").state,
        FounderVerdictStateKind::Consumed as i32
    );
}

#[test]
fn production_task_receipt_source_rejects_boundary_and_binding_drift() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let mut task = open_task(root.path(), Arc::clone(&verdict_handle));
    let pending = advance_to_verdict_pending(&mut task);
    let scope = scope_for(&pending);
    install_verdict_authority(root.path(), &verdict_handle, scope.clone());
    let verdict_id = issue_verdict(
        &verdict_handle,
        scope.clone(),
        FounderVerdictDecision::Accept,
        now_plus(300),
    );
    let task = Arc::new(Mutex::new(task));
    let receipts = TaskAuthorityCommitReceiptSource::new(Arc::clone(&task));
    let unapplied = ConsumeFounderVerdictCommand {
        founder_verdict_id: verdict_id.clone(),
        expected_state_revision: 1,
        task_event_id: "task-event:not-applied".to_owned(),
        consumed_task_revision: scope.task_revision,
        resulting_task_revision: scope.task_revision + 1,
        resulting_task_status: TaskStatus::Completed.as_str_name().to_owned(),
        task_commit_receipt_ref: "task-commit:task-event:not-applied".to_owned(),
        ..Default::default()
    };
    assert_eq!(
        receipts.validate_task_commit_before_expiry(&unapplied, &scope, &now_plus(300)),
        Err(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    );

    let applied = execute_task(
        &mut task.lock().expect("Task Authority"),
        apply_command(&pending, &verdict_id, "receipt-boundaries"),
        PrincipalKind::FounderAuthority,
    );
    assert_eq!(task_from(applied).status, TaskStatus::Completed as i32);
    let command = pending_consume_command(&task.lock().expect("Task Authority"));
    let consume = match command.command.as_ref() {
        Some(verdict_command::Command::ConsumeFounderVerdict(consume)) => consume.clone(),
        other => panic!("ConsumeFounderVerdict expected, got {other:?}"),
    };
    let event = task
        .lock()
        .expect("Task Authority")
        .applied_founder_verdict(&scope, &verdict_id)
        .expect("read applied Founder Verdict")
        .expect("applied Founder Verdict event");
    let applied_at = event.occurred_at.expect("application timestamp");
    assert_eq!(
        receipts.validate_task_commit_before_expiry(&consume, &scope, &timestamp_after(applied_at)),
        Ok(())
    );
    assert_eq!(
        receipts.validate_task_commit_before_expiry(&consume, &scope, &applied_at),
        Err(VerdictReferenceRejection::TaskCommitReceiptInvalid),
        "application at the expiry boundary is not an in-window application"
    );

    let mut wrong_id = consume.clone();
    wrong_id.founder_verdict_id = "verdict:other".to_owned();
    assert!(
        receipts
            .validate_task_commit_before_expiry(&wrong_id, &scope, &timestamp_after(applied_at))
            .is_err()
    );
    let mut wrong_scope = scope.clone();
    wrong_scope.artifact_set_id = "artifact-set:other".to_owned();
    assert!(
        receipts
            .validate_task_commit_before_expiry(
                &consume,
                &wrong_scope,
                &timestamp_after(applied_at)
            )
            .is_err()
    );
    let mut wrong_event = consume.clone();
    wrong_event.task_event_id = "task-event:other".to_owned();
    wrong_event.task_commit_receipt_ref = "task-commit:task-event:other".to_owned();
    assert!(
        receipts
            .validate_task_commit_before_expiry(&wrong_event, &scope, &timestamp_after(applied_at))
            .is_err()
    );
    let mut wrong_status = consume.clone();
    wrong_status.resulting_task_status = TaskStatus::Rejected.as_str_name().to_owned();
    assert!(
        receipts
            .validate_task_commit_before_expiry(&wrong_status, &scope, &timestamp_after(applied_at))
            .is_err()
    );
    let mut empty_receipt = consume;
    empty_receipt.task_commit_receipt_ref.clear();
    assert!(
        receipts
            .validate_task_commit_before_expiry(
                &empty_receipt,
                &scope,
                &timestamp_after(applied_at)
            )
            .is_err()
    );
}

fn open_task(root: &Path, verdict_handle: SharedFounderVerdictAuthority) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task.db"),
            store_epoch: "g4-07-task".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        },
        AllowCreation,
        ConfiguredTaskTransitionGuard::with_founder_verdict(verdict_handle),
    )
    .expect("open Task Authority")
}

fn open_task_with_apply_clock_observation(
    root: &Path,
    verdict_handle: SharedFounderVerdictAuthority,
    apply_entry: Arc<Mutex<Option<Timestamp>>>,
) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task.db"),
            store_epoch: "g4-07-task".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        },
        AllowCreation,
        ApplyGuardClockObservation {
            inner: ConfiguredTaskTransitionGuard::with_founder_verdict(verdict_handle),
            apply_entry,
        },
    )
    .expect("open Task Authority with Apply clock observation")
}

fn install_verdict_authority(
    root: &Path,
    verdict_handle: &SharedFounderVerdictAuthority,
    scope: VerdictScope,
) {
    let verdict = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.join("verdict.db"),
            store_epoch: "g4-07-verdict".to_owned(),
            key: VerdictSqlCipherKey::new([42; 32]),
        },
        StaticVerdictResolver {
            context: ResolvedVerdictContext {
                scope,
                verification_conclusion: VerificationConclusion::Passed,
                open_discrepancy_ids: Vec::new(),
                open_unverified_item_ids: Vec::new(),
                non_overridable_gate_ids: Vec::new(),
            },
        },
    )
    .expect("open Founder Verdict Authority");
    *verdict_handle.lock().expect("verdict handle") = Some(verdict);
}

fn issue_verdict(
    verdict_handle: &SharedFounderVerdictAuthority,
    scope: VerdictScope,
    decision: FounderVerdictDecision,
    expires_at: Timestamp,
) -> String {
    let mut issue = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(metadata("issue-worker")),
                scope: Some(scope),
                decision: decision as i32,
                observed_verification_conclusion: VerificationConclusion::Passed as i32,
                reason_code: if decision == FounderVerdictDecision::Reject {
                    "founder-rejected".to_owned()
                } else {
                    String::new()
                },
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "confirm:g4-07".to_owned(),
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )),
    };
    seal_verdict(&mut issue);
    let result = verdict_handle
        .lock()
        .expect("verdict handle")
        .as_mut()
        .expect("Founder Verdict Authority")
        .execute(
            &issue,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::FounderAuthority,
                principal_id: "founder:local".to_owned(),
                authenticated: true,
            },
        )
        .expect("issue Founder Verdict");
    assert!(result.committed);
    result.verdict.expect("issued Verdict").founder_verdict_id
}

fn scope_for(pending: &TaskSnapshot) -> VerdictScope {
    VerdictScope {
        task_id: pending.task_id.clone(),
        task_revision: pending.revision,
        work_revision: pending.work_revision,
        artifact_set_id: pending.artifact_set_id.clone().expect("artifact set"),
        artifact_set_manifest: Some(address(SHA_A)),
        verification_artifact_id: pending
            .verification_artifact_id
            .clone()
            .expect("verification artifact"),
        verification_payload: Some(address(SHA_B)),
        acceptance_contract_ref: pending.acceptance_contract_ref.clone(),
    }
}

fn apply_command(pending: &TaskSnapshot, verdict_id: &str, label: &str) -> TaskCommand {
    seal_task(TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(metadata(label)),
                task_id: pending.task_id.clone(),
                expected_revision: pending.revision,
                work_revision: pending.work_revision,
                founder_verdict_id: verdict_id.to_owned(),
            },
        )),
    })
}

fn consume_worker(
    task: Arc<Mutex<TaskAuthority>>,
    verdict: SharedFounderVerdictAuthority,
) -> ConfiguredFounderVerdictConsumeWorker {
    ConfiguredFounderVerdictConsumeWorker::new(
        task,
        verdict,
        "task-authority:founder-verdict-consumer",
    )
    .expect("configure consume worker")
}

fn pending_consume_command(task: &TaskAuthority) -> VerdictCommand {
    let message = task
        .pending_cross_authority_outbox()
        .expect("Task cross-authority outbox")
        .into_iter()
        .find(|message| message.destination_domain == "founder-verdict-authority")
        .expect("pending Founder Verdict consumption");
    VerdictCommand::decode(message.payload.as_slice()).expect("decode ConsumeFounderVerdict")
}

fn current_task(task: &Arc<Mutex<TaskAuthority>>, task_id: &str) -> TaskSnapshot {
    let response = task
        .lock()
        .expect("Task Authority")
        .get_task(task_id)
        .expect("get Task");
    match response.outcome.expect("Task response") {
        egopulse_domain_contracts::v01::egopulse::task::v1::get_task_response::Outcome::Task(
            snapshot,
        ) => snapshot,
        other => panic!("Task expected, got {other:?}"),
    }
}

fn now_plus(seconds: i64) -> Timestamp {
    let mut timestamp = now();
    timestamp.seconds += seconds;
    timestamp
}

fn timestamp_after(mut timestamp: Timestamp) -> Timestamp {
    if timestamp.nanos == 999_999_999 {
        timestamp.seconds += 1;
        timestamp.nanos = 0;
    } else {
        timestamp.nanos += 1;
    }
    timestamp
}

fn advance_to_verdict_pending(task: &mut TaskAuthority) -> TaskSnapshot {
    let created = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(metadata("create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-01".to_owned(),
                target_scope_ref: "scope-01".to_owned(),
                acceptance_contract_ref: Some(contract("acceptance", 0x11)),
                budget_profile_ref: Some(contract("budget", 0x22)),
                work_capability_route: None,
            })),
        }),
        PrincipalKind::Founder,
    ));
    let active = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(metadata("activate")),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run-01".to_owned(),
            })),
        }),
        PrincipalKind::CollaborationControl,
    ));
    let evidence = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    meta: Some(metadata("evidence")),
                    task_id: active.task_id.clone(),
                    expected_revision: active.revision,
                    work_revision: active.work_revision,
                    return_handoff_id: "handoff-01".to_owned(),
                    artifact_set_id: "artifact-set-01".to_owned(),
                },
            )),
        }),
        PrincipalKind::CollaborationControl,
    ));
    task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    meta: Some(metadata("verification")),
                    task_id: evidence.task_id.clone(),
                    expected_revision: evidence.revision,
                    work_revision: evidence.work_revision,
                    verification_artifact_id: "verification-artifact-01".to_owned(),
                },
            )),
        }),
        PrincipalKind::SegoVerification,
    ))
}

fn execute_task(
    task: &mut TaskAuthority,
    command: TaskCommand,
    kind: PrincipalKind,
) -> egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult {
    task.execute(
        &command,
        &AuthenticatedPrincipal {
            kind,
            principal_id: format!("g4-07:{kind:?}"),
            authenticated: true,
        },
    )
    .expect("Task command result")
}

fn task_from(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("Task outcome") {
        task_command_result::Outcome::Task(task) => task,
        other => panic!("Task outcome expected, got {other:?}"),
    }
}

fn metadata(operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("g4-07:{operation}:{}", Uuid::now_v7()),
        idempotency_key: format!("g4-07:{operation}:{}", Uuid::now_v7()),
        idempotency_scope: "g4-07-production".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: format!("g4-07:{operation}"),
        causation_id: None,
    }
}

fn seal_task(mut command: TaskCommand) -> TaskCommand {
    let digest = task_digest(&command).expect("Task digest");
    match command.command.as_mut() {
        Some(task_command::Command::CreateTask(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::ActivateTask(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::SubmitTaskEvidence(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::RecordTaskVerification(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::ApplyFounderVerdict(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        _ => panic!("unexpected Task command"),
    }
    command
}

fn seal_verdict(command: &mut VerdictCommand) {
    let digest = verdict_digest(command);
    if let Some(verdict_command::Command::IssueFounderVerdict(value)) = command.command.as_mut() {
        value
            .metadata
            .as_mut()
            .expect("verdict metadata")
            .request_digest_sha256 = digest;
    }
}

fn contract(id: &str, byte: u8) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: hex::encode([byte; 32]),
    }
}

fn address(digest: &str) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: digest.to_owned(),
        byte_length: 128,
    }
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock");
    Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    }
}

fn timestamp_at_or_before(left: &Timestamp, right: &Timestamp) -> bool {
    (left.seconds, left.nanos) <= (right.seconds, right.nanos)
}
