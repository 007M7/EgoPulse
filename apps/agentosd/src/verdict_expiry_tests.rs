use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
    canonical_request_digest as task_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        IssueHarnessApprovalDecisionCommand,
    },
    task::v1::{
        ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand,
        RecordTaskVerificationCommand, SubmitTaskEvidenceCommand, TaskCommand, TaskSnapshot,
        TaskStatus, task_command, task_command_result,
    },
    verdict::v1::{
        ConfirmationClass, ConsumeFounderVerdictCommand, FounderVerdict, FounderVerdictDecision,
        FounderVerdictState, FounderVerdictStateKind, IssueFounderVerdictCommand, VerdictCommand,
        VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
    canonical_request_digest as verdict_digest,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, FounderVerdictExpiryAuthorizationError, PolicyAuthorityConfig,
    PolicyDecisionAuthority, PolicyPrincipalKind, PolicyReferenceRejection,
    PolicyReferenceResolver, PolicySqlCipherKey, ResolvedApprovalAuthorization,
};
use prost_types::Timestamp;
use uuid::Uuid;

use crate::{
    ConfiguredTaskTransitionGuard, TaskAuthorityCommitReceiptSource,
    verdict::FounderTaskCommitEvidenceSource,
};

use super::*;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TASK_EPOCH: &str = "c06-expiry-task-v1";
const VERDICT_EPOCH: &str = "c06-expiry-verdict-v1";
const POLICY_EPOCH: &str = "c06-expiry-policy-v1";

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["c06-expiry-test:creation-reviewed".to_owned()],
        })
    }
}

struct DenyApprovalReferences;

impl PolicyReferenceResolver for DenyApprovalReferences {
    fn resolve_issue(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }

    fn validate_adapter_receipt(
        &self,
        _command: &ConsumeHarnessApprovalDecisionCommand,
        _record: &HarnessApprovalDecisionRecord,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }
}

struct ProductionExpiryVerdictResolver {
    context: ResolvedVerdictContext,
    task_receipts: TaskAuthorityCommitReceiptSource,
    expiry: FounderVerdictExpiryProofSource,
}

impl VerdictReferenceResolver for ProductionExpiryVerdictResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        if !principal.authenticated
            || principal.kind != VerdictPrincipalKind::FounderAuthority
            || principal.principal_id != "founder:c06-expiry"
        {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        let expires_at = command
            .expires_at
            .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
        Ok((
            self.context.clone(),
            FounderAuthorization {
                authenticated_founder_principal_id: principal.principal_id.clone(),
                authority_ref: "founder-authority:c06-expiry".to_owned(),
                confirmation_class: ConfirmationClass::Explicit,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: now(),
                valid_until: expires_at,
                authority_policy_ref: contract("founder-policy", 0x33),
                evidence_refs: vec!["c06-expiry-test:explicit-founder-confirmation".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        command: &ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        self.task_receipts.validate_task_commit(command, scope)
    }

    fn validate_task_commit_before_expiry(
        &self,
        command: &ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
        expires_at: &Timestamp,
    ) -> Result<(), VerdictReferenceRejection> {
        self.task_receipts
            .validate_task_commit_before_expiry(command, scope, expires_at)
    }

    fn validate_expiry_for_verdict(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ExpireFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        verdict: &FounderVerdict,
        state: &FounderVerdictState,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        self.expiry.validate(command, principal, verdict, state)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("egopulse-c06-expiry-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated C-06 expiry root");
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

struct Composition {
    task: Arc<Mutex<TaskAuthority>>,
    verdict: SharedFounderVerdictAuthority,
    policy: Arc<Mutex<PolicyDecisionAuthority>>,
    gate: Arc<Mutex<()>>,
    pending: TaskSnapshot,
    scope: VerdictScope,
    policy_ref: ContractReference,
}

impl Composition {
    fn new(root: &Path) -> Self {
        let verdict: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
        let mut task = open_task(root, Arc::clone(&verdict));
        let pending = advance_to_verdict_pending(&mut task);
        let scope = scope_for(&pending);
        let task = Arc::new(Mutex::new(task));
        let policy_ref = contract("founder-verdict-expiry-policy", 0x44);
        let policy = open_policy(
            root,
            Arc::clone(&task),
            Arc::clone(&verdict),
            policy_ref.clone(),
        );
        install_verdict(
            root,
            &verdict,
            Arc::clone(&task),
            Arc::clone(&policy),
            scope.clone(),
            policy_ref.clone(),
        );
        Self {
            task,
            verdict,
            policy,
            gate: Arc::new(Mutex::new(())),
            pending,
            scope,
            policy_ref,
        }
    }

    fn worker(&self) -> ExpiryRecoveringVerdictWorker {
        let consumer = ConfiguredFounderVerdictConsumeWorker::new_with_operation_gate(
            Arc::clone(&self.task),
            Arc::clone(&self.verdict),
            "task-authority:c06-expiry-consumer",
            Arc::clone(&self.gate),
        )
        .expect("configure Founder Verdict consume worker");
        ExpiryRecoveringVerdictWorker {
            consumer,
            task: Arc::clone(&self.task),
            verdict: Arc::clone(&self.verdict),
            policy: Arc::clone(&self.policy),
            operation_gate: Arc::clone(&self.gate),
        }
    }

    fn disconnect_verdict(&self) {
        *self.verdict.lock().expect("Founder Verdict handle") = None;
    }
}

#[tokio::test]
async fn expired_unapplied_verdict_uses_real_policy_authorization_and_allows_new_issue() {
    let root = TempRoot::new("expire-and-reissue");
    let composition = Composition::new(root.path());
    let first = issue_verdict(&composition.verdict, composition.scope.clone(), now_plus(1));
    tokio::time::sleep(Duration::from_millis(1_250)).await;

    assert!(matches!(
        composition.worker().run_once().await.expect("expire Verdict"),
        FounderVerdictConsumeCycleResult::Expired {
            ref founder_verdict_id,
            ref task_id,
        } if founder_verdict_id == &first && task_id == &composition.pending.task_id
    ));
    let (_, expired_state) = read_verdict(&composition.verdict, &first);
    assert_eq!(expired_state.state, FounderVerdictStateKind::Expired as i32);
    assert_eq!(
        current_task(&composition.task, &composition.pending.task_id),
        composition.pending,
        "expiry must not synthesize a Task application"
    );
    assert!(
        composition
            .verdict
            .lock()
            .expect("Founder Verdict handle")
            .as_ref()
            .expect("Founder Verdict Authority")
            .pending_task_handoffs()
            .expect("pending task handoffs")
            .is_empty(),
        "the expired Issue notification is acknowledged only after Expire commits"
    );

    let replacement = issue_verdict(
        &composition.verdict,
        composition.scope.clone(),
        now_plus(300),
    );
    assert_ne!(replacement, first);
    let (_, replacement_state) = read_verdict(&composition.verdict, &replacement);
    assert_eq!(
        replacement_state.state,
        FounderVerdictStateKind::Issued as i32
    );
    composition.disconnect_verdict();
}

#[tokio::test]
async fn unexpired_unapplied_verdict_is_idle_and_policy_persists_no_authorization() {
    let root = TempRoot::new("not-expired");
    let composition = Composition::new(root.path());
    let verdict_id = issue_verdict(
        &composition.verdict,
        composition.scope.clone(),
        now_plus(300),
    );
    let before = composition
        .policy
        .lock()
        .expect("Policy Authority")
        .inspect_store()
        .expect("inspect Policy store");
    let state_revision = read_verdict(&composition.verdict, &verdict_id).1.revision;
    assert!(matches!(
        composition
            .policy
            .lock()
            .expect("Policy Authority")
            .issue_founder_verdict_expiry(&verdict_id, state_revision, &policy_principal()),
        Err(FounderVerdictExpiryAuthorizationError::NotExpired)
    ));
    assert_eq!(
        composition
            .worker()
            .run_once()
            .await
            .expect("run early cycle"),
        FounderVerdictConsumeCycleResult::Idle
    );
    assert_eq!(
        composition
            .policy
            .lock()
            .expect("Policy Authority")
            .inspect_store()
            .expect("inspect Policy store after early cycle"),
        before,
        "NotExpired must not persist an authorization"
    );
    assert_eq!(
        read_verdict(&composition.verdict, &verdict_id).1.state,
        FounderVerdictStateKind::Issued as i32
    );
    composition.disconnect_verdict();
}

#[tokio::test]
async fn task_application_before_expiry_consumes_after_expiry_and_is_never_expired() {
    let root = TempRoot::new("applied-before-expiry");
    let composition = Composition::new(root.path());
    let verdict_id = issue_verdict(&composition.verdict, composition.scope.clone(), now_plus(1));
    let applied = execute_task(
        &mut composition.task.lock().expect("Task Authority"),
        apply_command(&composition.pending, &verdict_id, "apply-before-expiry"),
        PrincipalKind::FounderAuthority,
    );
    assert_eq!(task_from(applied).status, TaskStatus::Completed as i32);
    tokio::time::sleep(Duration::from_millis(1_250)).await;

    assert!(matches!(
        composition
            .worker()
            .run_once()
            .await
            .expect("consume applied Verdict"),
        FounderVerdictConsumeCycleResult::Consumed {
            ref founder_verdict_id,
            replayed: false,
            ..
        } if founder_verdict_id == &verdict_id
    ));
    assert_eq!(
        read_verdict(&composition.verdict, &verdict_id).1.state,
        FounderVerdictStateKind::Consumed as i32
    );
    composition.disconnect_verdict();
}

#[tokio::test]
async fn saved_authorization_reopens_exactly_and_forged_policy_bindings_are_rejected() {
    let root = TempRoot::new("authorization-reopen");
    let composition = Composition::new(root.path());
    let verdict_id = issue_verdict(&composition.verdict, composition.scope.clone(), now_plus(1));
    tokio::time::sleep(Duration::from_millis(1_250)).await;
    let (verdict, state) = read_verdict(&composition.verdict, &verdict_id);
    let authorization = composition
        .policy
        .lock()
        .expect("Policy Authority")
        .issue_founder_verdict_expiry(&verdict_id, state.revision, &policy_principal())
        .expect("persist real expiry authorization");
    let authorization_time = authorization.evaluated_at.expect("authorization time");
    let valid = sealed_expiry_command(
        &authorization.authorization_id,
        &verdict_id,
        state.revision,
        authorization_time,
    );
    let valid_expire = match valid.command.as_ref() {
        Some(verdict_command::Command::ExpireFounderVerdict(expire)) => expire,
        other => panic!("ExpireFounderVerdict expected, got {other:?}"),
    };
    let wrong_policy_source = FounderVerdictExpiryProofSource {
        policy: Arc::clone(&composition.policy),
        task: Arc::clone(&composition.task),
        policy_ref: contract("wrong-expiry-policy", 0x55),
    };
    assert_eq!(
        wrong_policy_source.validate(valid_expire, &verdict_policy_principal(), &verdict, &state),
        Err(VerdictReferenceRejection::IntegrityFailure)
    );

    let forged = sealed_expiry_command(
        "founder-verdict-expiry-v1-forged",
        &verdict_id,
        state.revision,
        now(),
    );
    let rejected = composition
        .verdict
        .lock()
        .expect("Founder Verdict handle")
        .as_mut()
        .expect("Founder Verdict Authority")
        .execute(&forged, &verdict_policy_principal())
        .expect("reject forged Policy binding");
    assert!(!rejected.committed);
    assert!(!rejected.replayed);
    assert_eq!(
        read_verdict(&composition.verdict, &verdict_id).1,
        state,
        "a forged Policy reference must not change Verdict state"
    );

    let policy_ref = composition.policy_ref.clone();
    let scope = composition.scope.clone();
    composition.disconnect_verdict();
    drop(composition.policy);
    drop(composition.task);

    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let task = Arc::new(Mutex::new(open_task(
        root.path(),
        Arc::clone(&verdict_handle),
    )));
    let policy = open_policy(
        root.path(),
        Arc::clone(&task),
        Arc::clone(&verdict_handle),
        policy_ref.clone(),
    );
    install_verdict(
        root.path(),
        &verdict_handle,
        Arc::clone(&task),
        Arc::clone(&policy),
        scope,
        policy_ref,
    );
    assert_eq!(
        policy
            .lock()
            .expect("reopened Policy Authority")
            .founder_verdict_expiry_authorization(&authorization.authorization_id)
            .expect("read saved authorization after reopen"),
        Some(authorization)
    );
    let gate = Arc::new(Mutex::new(()));
    let worker = ExpiryRecoveringVerdictWorker {
        consumer: ConfiguredFounderVerdictConsumeWorker::new_with_operation_gate(
            Arc::clone(&task),
            Arc::clone(&verdict_handle),
            "task-authority:c06-expiry-reopen",
            Arc::clone(&gate),
        )
        .expect("configure reopened consume worker"),
        task,
        verdict: Arc::clone(&verdict_handle),
        policy,
        operation_gate: gate,
    };
    assert!(matches!(
        worker.run_once().await.expect("recover saved authorization"),
        FounderVerdictConsumeCycleResult::Expired {
            ref founder_verdict_id,
            ..
        } if founder_verdict_id == &verdict_id
    ));
    assert_eq!(
        read_verdict(&verdict_handle, &verdict_id).1.state,
        FounderVerdictStateKind::Expired as i32
    );
    *verdict_handle.lock().expect("Founder Verdict handle") = None;
}

fn open_task(root: &Path, verdict: SharedFounderVerdictAuthority) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task.db"),
            store_epoch: TASK_EPOCH.to_owned(),
            key: SqlCipherKey::new([61; 32]),
        },
        AllowCreation,
        ConfiguredTaskTransitionGuard::with_founder_verdict(verdict),
    )
    .expect("open Task Authority")
}

fn open_policy(
    root: &Path,
    task: Arc<Mutex<TaskAuthority>>,
    verdict: SharedFounderVerdictAuthority,
    policy_ref: ContractReference,
) -> Arc<Mutex<PolicyDecisionAuthority>> {
    Arc::new(Mutex::new(
        PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: POLICY_EPOCH.to_owned(),
                key: PolicySqlCipherKey::new([62; 32]),
            },
            FounderExpiryPolicyResolver {
                approval: Box::new(DenyApprovalReferences),
                task,
                verdict,
                policy_ref,
            },
        )
        .expect("open Policy Authority"),
    ))
}

fn install_verdict(
    root: &Path,
    verdict_handle: &SharedFounderVerdictAuthority,
    task: Arc<Mutex<TaskAuthority>>,
    policy: Arc<Mutex<PolicyDecisionAuthority>>,
    scope: VerdictScope,
    policy_ref: ContractReference,
) {
    let resolver = ProductionExpiryVerdictResolver {
        context: ResolvedVerdictContext {
            scope,
            verification_conclusion: VerificationConclusion::Passed,
            open_discrepancy_ids: Vec::new(),
            open_unverified_item_ids: Vec::new(),
            non_overridable_gate_ids: Vec::new(),
        },
        task_receipts: TaskAuthorityCommitReceiptSource::new(Arc::clone(&task)),
        expiry: FounderVerdictExpiryProofSource {
            policy,
            task,
            policy_ref,
        },
    };
    let authority = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.join("verdict.db"),
            store_epoch: VERDICT_EPOCH.to_owned(),
            key: VerdictSqlCipherKey::new([63; 32]),
        },
        resolver,
    )
    .expect("open Founder Verdict Authority");
    *verdict_handle.lock().expect("Founder Verdict handle") = Some(authority);
}

fn issue_verdict(
    verdict: &SharedFounderVerdictAuthority,
    scope: VerdictScope,
    expires_at: Timestamp,
) -> String {
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(metadata("issue")),
                scope: Some(scope),
                decision: FounderVerdictDecision::Accept as i32,
                observed_verification_conclusion: VerificationConclusion::Passed as i32,
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "confirm:c06-expiry".to_owned(),
                expires_at: Some(expires_at),
                ..Default::default()
            },
        )),
    };
    seal_verdict(&mut command);
    let result = verdict
        .lock()
        .expect("Founder Verdict handle")
        .as_mut()
        .expect("Founder Verdict Authority")
        .execute(&command, &founder_principal())
        .expect("issue Founder Verdict");
    assert!(result.committed, "new explicit Issue must commit");
    result
        .verdict
        .expect("issued Founder Verdict")
        .founder_verdict_id
}

fn read_verdict(
    handle: &SharedFounderVerdictAuthority,
    verdict_id: &str,
) -> (FounderVerdict, FounderVerdictState) {
    handle
        .lock()
        .expect("Founder Verdict handle")
        .as_ref()
        .expect("Founder Verdict Authority")
        .get(verdict_id)
        .expect("read Founder Verdict")
        .expect("stored Founder Verdict")
}

fn founder_principal() -> AuthenticatedVerdictPrincipal {
    AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::FounderAuthority,
        principal_id: "founder:c06-expiry".to_owned(),
        authenticated: true,
    }
}

fn policy_principal() -> AuthenticatedPolicyPrincipal {
    AuthenticatedPolicyPrincipal {
        kind: PolicyPrincipalKind::PolicyAuthority,
        principal_id: EXPIRY_PRINCIPAL.to_owned(),
        authenticated: true,
    }
}

fn verdict_policy_principal() -> AuthenticatedVerdictPrincipal {
    AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::PolicyAuthority,
        principal_id: EXPIRY_PRINCIPAL.to_owned(),
        authenticated: true,
    }
}

fn sealed_expiry_command(
    authorization_id: &str,
    verdict_id: &str,
    revision: u64,
    at: Timestamp,
) -> VerdictCommand {
    let mut command = expiry_command(authorization_id, verdict_id, revision, at);
    let digest = verdict_digest(&command);
    if let Some(verdict_command::Command::ExpireFounderVerdict(expire)) = command.command.as_mut()
        && let Some(metadata) = expire.metadata.as_mut()
    {
        metadata.request_digest_sha256 = digest;
    }
    command
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

fn advance_to_verdict_pending(task: &mut TaskAuthority) -> TaskSnapshot {
    let created = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(metadata("create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-c06-expiry".to_owned(),
                target_scope_ref: "scope-c06-expiry".to_owned(),
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
                task_id: created.task_id,
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run-c06-expiry".to_owned(),
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
                    task_id: active.task_id,
                    expected_revision: active.revision,
                    work_revision: active.work_revision,
                    return_handoff_id: "handoff-c06-expiry".to_owned(),
                    artifact_set_id: "artifact-set-c06-expiry".to_owned(),
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
                    task_id: evidence.task_id,
                    expected_revision: evidence.revision,
                    work_revision: evidence.work_revision,
                    verification_artifact_id: "verification-artifact-c06-expiry".to_owned(),
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
            principal_id: format!("c06-expiry:{kind:?}"),
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
        command_id: format!("c06-expiry:{operation}:{}", Uuid::now_v7()),
        idempotency_key: format!("c06-expiry:{operation}:{}", Uuid::now_v7()),
        idempotency_scope: "c06-expiry-production".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: format!("c06-expiry:{operation}"),
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
    if let Some(verdict_command::Command::IssueFounderVerdict(issue)) = command.command.as_mut() {
        issue
            .metadata
            .as_mut()
            .expect("metadata")
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

fn now_plus(seconds: i64) -> Timestamp {
    let mut timestamp = now();
    timestamp.seconds += seconds;
    timestamp
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
