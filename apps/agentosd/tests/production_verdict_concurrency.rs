#![forbid(unsafe_code)]

use egopulse_agentosd::{
    AuthorityCommandPorts, AuthorityPrincipalResolver, SharedFounderVerdictAuthority,
};
use egopulse_cognition_runtime::{
    memory_authority::MemoryPrincipalKind,
    task_authority::{
        CreationAuthorization, CreationGuardRejection, PrincipalKind as TaskPrincipalKind,
        SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
    },
};
use egopulse_domain_contracts::v01::egopulse::{
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, ExpireHarnessApprovalDecisionCommand,
        HarnessApprovalDecisionRecord, IssueHarnessApprovalDecisionCommand,
        RevokeHarnessApprovalDecisionCommand,
    },
    task::v1::{ApplyFounderVerdictCommand, CreateTaskCommand, TaskCommand, task_command},
    verdict::v1::{
        ConsumeFounderVerdictCommand, ExpireFounderVerdictCommand, IssueFounderVerdictCommand,
        RevokeFounderVerdictCommand, VerdictCommand, VerdictScope, verdict_command,
    },
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, TaskCommandPort, VerdictCommandPort,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityConfig, PolicyPrincipalKind,
    PolicyReferenceRejection, PolicyReferenceResolver, PolicySqlCipherKey,
    ResolvedApprovalAuthorization,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier, Mutex, mpsc},
    thread,
    time::Duration,
};
use uuid::Uuid;

struct DenyCreation;

impl TaskCreationGuard for DenyCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Err(CreationGuardRejection::UnverifiedReference)
    }
}

struct DenyPolicy;

impl PolicyReferenceResolver for DenyPolicy {
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

    fn validate_revoke(
        &self,
        _command: &RevokeHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }

    fn validate_expiry(
        &self,
        _command: &ExpireHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }
}

struct DenyVerdict;

impl VerdictReferenceResolver for DenyVerdict {
    fn resolve_issue(
        &self,
        _command: &IssueFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_task_commit(
        &self,
        _command: &ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_revoke(
        &self,
        _command: &RevokeFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_expiry(
        &self,
        _command: &ExpireFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }
}

struct RendezvousPrincipalResolver(Arc<Barrier>);

impl AuthorityPrincipalResolver for RendezvousPrincipalResolver {
    fn resolve_task(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure> {
        self.0.wait();
        Ok(TaskPrincipalKind::FounderAuthority)
    }

    fn resolve_policy(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<PolicyPrincipalKind, CommandPortFailure> {
        Ok(PolicyPrincipalKind::LocalUser)
    }

    fn resolve_verdict(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<VerdictPrincipalKind, CommandPortFailure> {
        self.0.wait();
        Ok(VerdictPrincipalKind::FounderAuthority)
    }

    fn resolve_memory(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<MemoryPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "egopulse-founder-verdict-concurrency-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&path).expect("create test root");
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

#[test]
fn task_apply_and_verdict_state_change_wait_for_the_same_operation_gate() {
    let root = TempRoot::new();
    let task = Arc::new(Mutex::new(
        TaskAuthority::open(
            TaskAuthorityConfig {
                database_path: root.path().join("task.db"),
                store_epoch: "concurrency-task".to_owned(),
                key: SqlCipherKey::new([31; 32]),
            },
            DenyCreation,
        )
        .expect("open Task Authority"),
    ));
    let policy = Arc::new(Mutex::new(
        egopulse_policy_decision_authority::PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.path().join("policy.db"),
                store_epoch: "concurrency-policy".to_owned(),
                key: PolicySqlCipherKey::new([32; 32]),
            },
            DenyPolicy,
        )
        .expect("open Policy Authority"),
    ));
    let verdict: SharedFounderVerdictAuthority = Arc::new(Mutex::new(Some(
        FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.path().join("verdict.db"),
                store_epoch: "concurrency-verdict".to_owned(),
                key: VerdictSqlCipherKey::new([33; 32]),
            },
            DenyVerdict,
        )
        .expect("open Founder Verdict Authority"),
    )));
    let rendezvous = Arc::new(Barrier::new(3));
    let gate = Arc::new(Mutex::new(()));
    let ports = Arc::new(
        AuthorityCommandPorts::new_shared_authority_handles_with_operation_gate(
            task,
            policy,
            verdict,
            Arc::new(RendezvousPrincipalResolver(Arc::clone(&rendezvous))),
            Arc::clone(&gate),
        ),
    );
    let gate_guard = gate.lock().expect("operation gate");
    let (completed_tx, completed_rx) = mpsc::channel();

    let task_ports = Arc::clone(&ports);
    let task_completed = completed_tx.clone();
    let task_thread = thread::spawn(move || {
        let _result = TaskCommandPort::execute(
            task_ports.as_ref(),
            &TaskCommand {
                command: Some(task_command::Command::ApplyFounderVerdict(
                    ApplyFounderVerdictCommand::default(),
                )),
            },
            &principal("TaskAuthority.FounderAuthority"),
        );
        task_completed.send(()).expect("report Task result");
    });

    let verdict_ports = Arc::clone(&ports);
    let verdict_thread = thread::spawn(move || {
        let _result = VerdictCommandPort::execute(
            verdict_ports.as_ref(),
            &VerdictCommand {
                command: Some(verdict_command::Command::RevokeFounderVerdict(
                    RevokeFounderVerdictCommand::default(),
                )),
            },
            &principal("FounderVerdictAuthority.FounderAuthority"),
        );
        completed_tx.send(()).expect("report Verdict result");
    });

    rendezvous.wait();
    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(25))
            .is_err(),
        "both cross-Authority commands must remain blocked while the shared gate is held"
    );
    drop(gate_guard);
    completed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first command leaves gate");
    completed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second command leaves gate");
    task_thread.join().expect("Task command thread");
    verdict_thread.join().expect("Verdict command thread");
}

fn principal(required_kind: &str) -> CommandPrincipal {
    CommandPrincipal {
        principal_id: "os-user:concurrency-test".to_owned(),
        required_authority_principal_kinds: vec![required_kind.to_owned()],
    }
}
