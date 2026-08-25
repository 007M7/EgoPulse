use std::sync::{Arc, Mutex};

use crate::projections::{OwnerProjectionSource, PendingOwnerProjection, ProjectionSourceFailure};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, PrincipalKind as TaskPrincipalKind, TaskAuthority, TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::{
    localapi::v1::{SourceDomain, SourceRevision},
    policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
    task::v1::{TaskCommand, TaskCommandResult},
    verdict::v1::{VerdictCommand, VerdictCommandResult},
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderVerdictAuthority, VerdictAuthorityFailure,
    VerdictPrincipalKind,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPortResult, CommandPrincipal, PolicyCommandPort, TaskCommandPort,
    VerdictCommandPort,
};
use egopulse_local_api::read_tokens::AwaitTarget;
use egopulse_local_ide_control::collaboration_control::{
    TaskActivationHandoff, TaskActivationSource, TaskActivationSourceError,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityFailure, PolicyDecisionAuthority,
    PolicyPrincipalKind,
};

/// The local API session authenticates an OS peer, but it does not by itself
/// establish an Authority principal kind. This provider is the explicit
/// composition boundary that resolves the accepted profile constraints into
/// one owner principal. It must be backed by trusted local policy in a real
/// deployment; it is never inferred from request fields or environment data.
pub trait AuthorityPrincipalResolver: Send + Sync + 'static {
    fn resolve_task(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure>;

    fn resolve_policy(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<PolicyPrincipalKind, CommandPortFailure>;

    fn resolve_verdict(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<VerdictPrincipalKind, CommandPortFailure>;
}

/// Explicitly denies owner principal resolution. It is used by the daemon's
/// default/foundation path so an absent identity provider cannot become a
/// fabricated Founder grant.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthorityPrincipalResolver;

impl AuthorityPrincipalResolver for DenyAllAuthorityPrincipalResolver {
    fn resolve_task(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }

    fn resolve_policy(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<PolicyPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }

    fn resolve_verdict(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<VerdictPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

/// Concrete owner adapters used by the composition root. Each adapter holds
/// exactly one Authority instance and never exposes its private store. The
/// mutex is a process-local single-writer serialization point; it is not a
/// second source of business facts.
pub struct AuthorityCommandPorts {
    task: Mutex<TaskAuthority>,
    policy: Mutex<PolicyDecisionAuthority>,
    verdict: Mutex<FounderVerdictAuthority>,
    principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
}

impl AuthorityCommandPorts {
    #[must_use]
    pub fn new(
        task: TaskAuthority,
        policy: PolicyDecisionAuthority,
        verdict: FounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        Self {
            task: Mutex::new(task),
            policy: Mutex::new(policy),
            verdict: Mutex::new(verdict),
            principal_resolver,
        }
    }

    fn task_principal(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<AuthenticatedPrincipal, CommandPortFailure> {
        let kind = self.principal_resolver.resolve_task(principal)?;
        require_constraint(principal, "TaskAuthority", task_kind_name(kind))?;
        Ok(AuthenticatedPrincipal {
            kind,
            principal_id: principal.principal_id.clone(),
            authenticated: true,
        })
    }

    fn policy_principal(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<AuthenticatedPolicyPrincipal, CommandPortFailure> {
        let kind = self.principal_resolver.resolve_policy(principal)?;
        require_constraint(principal, "PolicyDecisionAuthority", policy_kind_name(kind))?;
        Ok(AuthenticatedPolicyPrincipal {
            kind,
            principal_id: principal.principal_id.clone(),
            authenticated: true,
        })
    }

    fn verdict_principal(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<AuthenticatedVerdictPrincipal, CommandPortFailure> {
        let kind = self.principal_resolver.resolve_verdict(principal)?;
        require_constraint(
            principal,
            "FounderVerdictAuthority",
            verdict_kind_name(kind),
        )?;
        Ok(AuthenticatedVerdictPrincipal {
            kind,
            principal_id: principal.principal_id.clone(),
            authenticated: true,
        })
    }
}

impl TaskCommandPort for AuthorityCommandPorts {
    fn execute(
        &self,
        command: &TaskCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        let owner_principal = self.task_principal(principal)?;
        let mut authority = self
            .task
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        let result = authority
            .execute(command, &owner_principal)
            .map_err(task_failure)?;
        let (source_revision, await_target) = result
            .committed_event
            .as_ref()
            .and_then(|event| {
                event.snapshot.as_ref().map(|snapshot| {
                    (
                        SourceRevision {
                            domain: SourceDomain::Task as i32,
                            aggregate_id: snapshot.task_id.clone(),
                            revision: snapshot.revision,
                            last_event_id: event.event_id.clone(),
                        },
                        AwaitTarget::Task {
                            task_id: snapshot.task_id.clone(),
                        },
                    )
                })
            })
            .map_or((None, None), |(revision, target)| {
                (Some(revision), Some(target))
            });
        Ok(CommandPortResult {
            result,
            source_revision,
            await_target,
        })
    }
}

impl TaskActivationSource for AuthorityCommandPorts {
    fn pending_task_activations(
        &self,
    ) -> Result<Vec<TaskActivationHandoff>, TaskActivationSourceError> {
        let authority = self
            .task
            .lock()
            .map_err(|_| TaskActivationSourceError::Unavailable)?;
        authority
            .pending_task_activations()
            .map_err(task_activation_source_error)
            .and_then(|messages| {
                messages
                    .into_iter()
                    .map(|message| {
                        let task = message
                            .event
                            .snapshot
                            .ok_or(TaskActivationSourceError::Integrity)?;
                        Ok(TaskActivationHandoff {
                            message_id: message.message_id,
                            payload_digest_sha256: message.payload_digest_sha256,
                            task,
                        })
                    })
                    .collect()
            })
    }

    fn acknowledge_task_activation(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, TaskActivationSourceError> {
        self.task
            .lock()
            .map_err(|_| TaskActivationSourceError::Unavailable)?
            .acknowledge_cross_authority_outbox(message_id, payload_digest_sha256)
            .map_err(task_activation_source_error)
    }
}

impl PolicyCommandPort for AuthorityCommandPorts {
    fn execute(
        &self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure> {
        let owner_principal = self.policy_principal(principal)?;
        let mut authority = self
            .policy
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        let wrapper = egopulse_domain_contracts::v01::egopulse::policy::v1::PolicyDecisionCommand {
            command: Some(
                egopulse_domain_contracts::v01::egopulse::policy::v1::
                    policy_decision_command::Command::IssueHarnessApprovalDecision(command.clone()),
            ),
        };
        let result = authority
            .execute(&wrapper, &owner_principal)
            .map_err(policy_failure)?;
        let (source_revision, await_target) = result
            .event
            .as_ref()
            .and_then(|event| {
                result
                    .decision_record
                    .as_ref()
                    .and_then(|record| record.request.as_ref().map(|request| (record, request)))
                    .map(|(record, request)| {
                        (
                            SourceRevision {
                                domain: SourceDomain::PolicyDecision as i32,
                                aggregate_id: record.authority_decision_ref.clone(),
                                revision: event.resulting_state_revision,
                                last_event_id: event.event_id.clone(),
                            },
                            AwaitTarget::HarnessApproval {
                                approval_request_id: request.approval_request_id.clone(),
                            },
                        )
                    })
            })
            .map_or((None, None), |(revision, target)| {
                (Some(revision), Some(target))
            });
        Ok(CommandPortResult {
            result,
            source_revision,
            await_target,
        })
    }
}

impl VerdictCommandPort for AuthorityCommandPorts {
    fn execute(
        &self,
        command: &VerdictCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        let owner_principal = self.verdict_principal(principal)?;
        let mut authority = self
            .verdict
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        let result = authority
            .execute(command, &owner_principal)
            .map_err(verdict_failure)?;
        Ok(CommandPortResult {
            result,
            // The Local Read Model has no FounderVerdict view in the frozen
            // contract, so this port must not invent an await target.
            source_revision: None,
            await_target: None,
        })
    }
}

impl OwnerProjectionSource for AuthorityCommandPorts {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        let task = self
            .task
            .lock()
            .map_err(|_| ProjectionSourceFailure::Task)?
            .drain_projection_outbox()
            .map_err(|_| ProjectionSourceFailure::Task)?
            .into_iter()
            .map(|message| PendingOwnerProjection::Task(Box::new(message)));
        let policy = self
            .policy
            .lock()
            .map_err(|_| ProjectionSourceFailure::Policy)?
            .pending_projection_messages()
            .map_err(|_| ProjectionSourceFailure::Policy)?
            .into_iter()
            .map(|message| PendingOwnerProjection::Policy(Box::new(message)));
        let verdict = self
            .verdict
            .lock()
            .map_err(|_| ProjectionSourceFailure::Verdict)?
            .drain_projection_outbox()
            .map_err(|_| ProjectionSourceFailure::Verdict)?
            .into_iter()
            .map(|message| PendingOwnerProjection::Verdict(Box::new(message)));
        Ok(task.chain(policy).chain(verdict).collect())
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let acknowledged = match message {
            PendingOwnerProjection::Collaboration(_)
            | PendingOwnerProjection::AdapterApproval(_)
            | PendingOwnerProjection::Artifact(_)
            | PendingOwnerProjection::Verification(_) => return Ok(false),
            PendingOwnerProjection::Task(message) => self
                .task
                .lock()
                .map_err(|_| ProjectionSourceFailure::Task)?
                .acknowledge_projection(&message.message_id, &message.payload_digest_sha256)
                .map_err(|_| ProjectionSourceFailure::Task)?,
            PendingOwnerProjection::Policy(message) => self
                .policy
                .lock()
                .map_err(|_| ProjectionSourceFailure::Policy)?
                .acknowledge_projection_message(&message.message_id, &message.payload_digest_sha256)
                .map_err(|_| ProjectionSourceFailure::Policy)?,
            PendingOwnerProjection::Verdict(message) => self
                .verdict
                .lock()
                .map_err(|_| ProjectionSourceFailure::Verdict)?
                .acknowledge_projection(&message.message_id, &message.payload_digest_sha256)
                .map_err(|_| ProjectionSourceFailure::Verdict)?,
        };
        if acknowledged { Ok(true) } else { Ok(false) }
    }
}

fn require_constraint(
    principal: &CommandPrincipal,
    authority: &str,
    kind: &str,
) -> Result<(), CommandPortFailure> {
    let expected = format!("{authority}.{kind}");
    if principal
        .required_authority_principal_kinds
        .iter()
        .any(|candidate| candidate == &expected)
    {
        Ok(())
    } else {
        Err(CommandPortFailure::IntegrityFailure)
    }
}

fn task_kind_name(kind: TaskPrincipalKind) -> &'static str {
    match kind {
        TaskPrincipalKind::Founder => "Founder",
        TaskPrincipalKind::FounderAuthority => "FounderAuthority",
        TaskPrincipalKind::CollaborationControl => "CollaborationControl",
        TaskPrincipalKind::SegoVerification => "SegoVerification",
        TaskPrincipalKind::Harness => "Harness",
        TaskPrincipalKind::Model => "Model",
        TaskPrincipalKind::RecoveryCoordinator => "RecoveryCoordinator",
    }
}

fn policy_kind_name(kind: PolicyPrincipalKind) -> &'static str {
    match kind {
        PolicyPrincipalKind::LocalUser => "LocalUser",
        PolicyPrincipalKind::FounderPolicy => "FounderPolicy",
        PolicyPrincipalKind::HarnessAdapter => "HarnessAdapter",
        PolicyPrincipalKind::PolicyAuthority => "PolicyAuthority",
        PolicyPrincipalKind::RecoveryCoordinator => "RecoveryCoordinator",
        PolicyPrincipalKind::Model => "Model",
        PolicyPrincipalKind::UserInterface => "UserInterface",
    }
}

fn verdict_kind_name(kind: VerdictPrincipalKind) -> &'static str {
    match kind {
        VerdictPrincipalKind::FounderAuthority => "FounderAuthority",
        VerdictPrincipalKind::TaskAuthority => "TaskAuthority",
        VerdictPrincipalKind::Harness => "Harness",
        VerdictPrincipalKind::Checker => "Checker",
        VerdictPrincipalKind::Model => "Model",
        VerdictPrincipalKind::RecoveryCoordinator => "RecoveryCoordinator",
        VerdictPrincipalKind::PolicyAuthority => "PolicyAuthority",
    }
}

fn task_failure(error: TaskAuthorityFailure) -> CommandPortFailure {
    match error {
        TaskAuthorityFailure::Decode(_) | TaskAuthorityFailure::InvalidCrossAuthorityHandoff => {
            CommandPortFailure::IntegrityFailure
        }
        TaskAuthorityFailure::Storage | TaskAuthorityFailure::Clock => {
            CommandPortFailure::Unavailable
        }
    }
}

fn task_activation_source_error(error: TaskAuthorityFailure) -> TaskActivationSourceError {
    match error {
        TaskAuthorityFailure::Decode(_) | TaskAuthorityFailure::InvalidCrossAuthorityHandoff => {
            TaskActivationSourceError::Integrity
        }
        TaskAuthorityFailure::Storage | TaskAuthorityFailure::Clock => {
            TaskActivationSourceError::Unavailable
        }
    }
}

fn policy_failure(error: PolicyAuthorityFailure) -> CommandPortFailure {
    match error {
        PolicyAuthorityFailure::Decode(_) => CommandPortFailure::IntegrityFailure,
        PolicyAuthorityFailure::Storage | PolicyAuthorityFailure::Clock => {
            CommandPortFailure::Unavailable
        }
    }
}

fn verdict_failure(error: VerdictAuthorityFailure) -> CommandPortFailure {
    match error {
        VerdictAuthorityFailure::Decode(_) => CommandPortFailure::IntegrityFailure,
        VerdictAuthorityFailure::Storage | VerdictAuthorityFailure::Clock => {
            CommandPortFailure::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_cognition_runtime::task_authority::{
        CreationAuthorization, CreationGuardRejection, SqlCipherKey, TaskAuthorityConfig,
        TaskCreationGuard,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        policy::v1::{
            ConsumeHarnessApprovalDecisionCommand, ExpireHarnessApprovalDecisionCommand,
            HarnessApprovalDecisionRecord, IssueHarnessApprovalDecisionCommand,
            RevokeHarnessApprovalDecisionCommand,
        },
        task::v1::TaskCommand,
        verdict::v1::{
            ConsumeFounderVerdictCommand, ExpireFounderVerdictCommand, IssueFounderVerdictCommand,
            RevokeFounderVerdictCommand, VerdictCommand,
        },
    };
    use egopulse_founder_verdict_authority::{
        FounderVerdictAuthority, VerdictAuthorityConfig, VerdictReferenceRejection,
        VerdictReferenceResolver, VerdictSqlCipherKey,
    };
    use egopulse_policy_decision_authority::{
        PolicyAuthorityConfig, PolicyReferenceRejection, PolicyReferenceResolver,
        PolicySqlCipherKey, ResolvedApprovalAuthorization,
    };
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    struct DenyCreation;

    impl TaskCreationGuard for DenyCreation {
        fn validate(
            &self,
            _command: &egopulse_domain_contracts::v01::egopulse::task::v1::CreateTaskCommand,
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
        ) -> Result<
            (
                egopulse_founder_verdict_authority::ResolvedVerdictContext,
                egopulse_founder_verdict_authority::FounderAuthorization,
            ),
            VerdictReferenceRejection,
        > {
            Err(VerdictReferenceRejection::PermissionDenied)
        }

        fn validate_task_commit(
            &self,
            _command: &ConsumeFounderVerdictCommand,
            _scope: &egopulse_domain_contracts::v01::egopulse::verdict::v1::VerdictScope,
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

    struct StaticPrincipalResolver;

    impl AuthorityPrincipalResolver for StaticPrincipalResolver {
        fn resolve_task(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<TaskPrincipalKind, CommandPortFailure> {
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
            Ok(VerdictPrincipalKind::FounderAuthority)
        }
    }

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("egopulse-c4-owners-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("owner test root");
        root
    }

    fn principal(kinds: &[&str]) -> CommandPrincipal {
        CommandPrincipal {
            principal_id: "os-user:c4-test".to_owned(),
            required_authority_principal_kinds: kinds
                .iter()
                .map(|kind| (*kind).to_owned())
                .collect(),
        }
    }

    #[test]
    fn each_command_port_calls_its_owner_and_preserves_owner_failure() {
        let root = root();
        let task = TaskAuthority::open(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            DenyCreation,
        )
        .expect("task owner");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("verdict owner");
        let ports =
            AuthorityCommandPorts::new(task, policy, verdict, Arc::new(StaticPrincipalResolver));

        assert!(
            TaskActivationSource::pending_task_activations(&ports)
                .expect("Task activation source")
                .is_empty()
        );

        let task_result = TaskCommandPort::execute(
            &ports,
            &TaskCommand { command: None },
            &principal(&["TaskAuthority.FounderAuthority"]),
        )
        .expect("Task owner result");
        assert!(task_result.result.outcome.is_some());
        assert!(task_result.source_revision.is_none());

        let policy_result = PolicyCommandPort::execute(
            &ports,
            &IssueHarnessApprovalDecisionCommand::default(),
            &principal(&["PolicyDecisionAuthority.LocalUser"]),
        )
        .expect("Policy owner result");
        assert!(!policy_result.result.committed);
        assert!(policy_result.source_revision.is_none());

        let verdict_result = VerdictCommandPort::execute(
            &ports,
            &VerdictCommand { command: None },
            &principal(&["FounderVerdictAuthority.FounderAuthority"]),
        )
        .expect("Verdict owner result");
        assert!(!verdict_result.result.committed);
        assert!(verdict_result.source_revision.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn adapter_rejects_a_resolved_kind_outside_gateway_constraints() {
        let root = root();
        let task = TaskAuthority::open(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            DenyCreation,
        )
        .expect("task owner");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("verdict owner");
        let ports =
            AuthorityCommandPorts::new(task, policy, verdict, Arc::new(StaticPrincipalResolver));
        assert!(matches!(
            TaskCommandPort::execute(
                &ports,
                &TaskCommand { command: None },
                &principal(&["TaskAuthority.Founder"]),
            ),
            Err(CommandPortFailure::IntegrityFailure)
        ));
        let _ = fs::remove_dir_all(root);
    }
}
