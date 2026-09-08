use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::SharedFounderVerdictAuthority;
use crate::approval_delivery::{
    ApprovalDeliveryCycleError, ApprovalDeliverySource, ApprovalPolicyEvidence,
    PendingApprovalDelivery,
};
use crate::cancellation_delivery::TaskCancellationReconciler;
use crate::projections::{OwnerProjectionSource, PendingOwnerProjection, ProjectionSourceFailure};
use egopulse_cognition_runtime::context_authority::ContextPrincipalKind;
use egopulse_cognition_runtime::memory_authority::MemoryPrincipalKind;
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, NoRunTaskCancellationProof, PrincipalKind as TaskPrincipalKind,
    TaskAuthority, TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::CommandMetadata,
    harness::v1::{ApprovalDecisionEnvelope, ApprovalDecisionReceipt},
    localapi::v1::{SourceDomain, SourceRevision},
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionStateKind,
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, PolicyDecisionCommandResult,
        policy_decision_command,
    },
    task::v1::{TaskCommand, TaskCommandResult, task_command},
    verdict::v1::{VerdictCommand, VerdictCommandResult, verdict_command},
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
    TaskCancellationHandoff, TaskCancellationSource, TaskCancellationSourceError,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityFailure, PolicyDecisionAuthority,
    PolicyPrincipalKind, canonical_request_digest,
};
use prost::Message;
use sha2::{Digest, Sha256};
use uuid::Uuid;

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

    fn resolve_memory(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<MemoryPrincipalKind, CommandPortFailure>;

    /// Context Founder authority must be supplied by a trusted daemon-owned
    /// identity binding. Existing resolvers remain fail-closed until they
    /// explicitly opt into Context governance.
    fn resolve_context(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<ContextPrincipalKind, CommandPortFailure> {
        let _ = principal;
        Err(CommandPortFailure::Unavailable)
    }
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

    fn resolve_memory(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<MemoryPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

/// Concrete owner adapters used by the composition root. Each adapter holds
/// exactly one Authority instance and never exposes its private store. The
/// mutex is a process-local single-writer serialization point; it is not a
/// second source of business facts.
pub struct AuthorityCommandPorts {
    task: Arc<Mutex<TaskAuthority>>,
    policy: Arc<Mutex<PolicyDecisionAuthority>>,
    verdict: SharedFounderVerdictAuthority,
    cross_authority_operation_gate: Arc<Mutex<()>>,
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
        Self::new_shared(
            Arc::new(Mutex::new(task)),
            policy,
            verdict,
            principal_resolver,
        )
    }

    /// Composes a shared Task Authority handle so the command port, activation
    /// projector and cross-authority receipt reader all observe one serialized
    /// owner. No second Task store or independent write path is created.
    #[must_use]
    pub fn new_shared(
        task: Arc<Mutex<TaskAuthority>>,
        policy: PolicyDecisionAuthority,
        verdict: FounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        Self::new_shared_handles(
            task,
            policy,
            Arc::new(Mutex::new(Some(verdict))),
            principal_resolver,
        )
    }

    /// Composes a shared, late-bound Verdict Authority handle. The handle is
    /// populated by the production composition root only after the Task
    /// Authority has been constructed with the matching transition guard.
    #[must_use]
    pub fn new_shared_handles(
        task: Arc<Mutex<TaskAuthority>>,
        policy: PolicyDecisionAuthority,
        verdict: SharedFounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        Self::new_shared_handles_with_operation_gate(
            task,
            policy,
            verdict,
            principal_resolver,
            Arc::new(Mutex::new(())),
        )
    }

    /// Uses the composition-owned gate for the only two operations that cross
    /// the Task/Founder Verdict boundary. Ordinary owner commands do not take
    /// this gate.
    #[must_use]
    pub fn new_shared_handles_with_operation_gate(
        task: Arc<Mutex<TaskAuthority>>,
        policy: PolicyDecisionAuthority,
        verdict: SharedFounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
        cross_authority_operation_gate: Arc<Mutex<()>>,
    ) -> Self {
        Self::new_shared_authority_handles_with_operation_gate(
            task,
            Arc::new(Mutex::new(policy)),
            verdict,
            principal_resolver,
            cross_authority_operation_gate,
        )
    }

    /// Composes all cross-Authority owner handles and their shared operation
    /// gate. Production background workers must receive clones of these same
    /// handles rather than opening a second Policy owner.
    #[must_use]
    pub fn new_shared_authority_handles_with_operation_gate(
        task: Arc<Mutex<TaskAuthority>>,
        policy: Arc<Mutex<PolicyDecisionAuthority>>,
        verdict: SharedFounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
        cross_authority_operation_gate: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            task,
            policy,
            verdict,
            cross_authority_operation_gate,
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

/// Fixed authenticated owner used only by daemon-owned system activation.
/// It is never derived from a client principal or request metadata.
const SYSTEM_ACTIVATION_PRINCIPAL_ID: &str = "collaboration-control:system-activation";
const SYSTEM_EVIDENCE_INTAKE_PRINCIPAL_ID: &str = "collaboration-control:artifact-evidence-intake";

impl TaskCommandPort for AuthorityCommandPorts {
    fn replay_system_revision_if_recorded(
        &self,
        command: &TaskCommand,
    ) -> Result<Option<CommandPortResult<TaskCommandResult>>, CommandPortFailure> {
        if !matches!(command.command, Some(task_command::Command::ReviseTask(_))) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let principal = AuthenticatedPrincipal {
            kind: TaskPrincipalKind::FounderAuthority,
            principal_id: "founder-authority:rework-confirmation".to_owned(),
            authenticated: true,
        };
        let result = self
            .task
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?
            .replay_recorded(command, &principal)
            .map_err(task_failure)?;
        Ok(result.map(|result| {
            let source_revision = result.committed_event.as_ref().and_then(|event| {
                event.snapshot.as_ref().map(|task| SourceRevision {
                    domain: SourceDomain::Task as i32,
                    aggregate_id: task.task_id.clone(),
                    revision: task.revision,
                    last_event_id: event.event_id.clone(),
                })
            });
            let await_target = source_revision.as_ref().map(|revision| AwaitTarget::Task {
                task_id: revision.aggregate_id.clone(),
            });
            CommandPortResult {
                result,
                source_revision,
                await_target,
            }
        }))
    }

    fn execute_system_revision(
        &self,
        command: &TaskCommand,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        if !matches!(command.command, Some(task_command::Command::ReviseTask(_))) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        self.execute_as_owner(
            command,
            AuthenticatedPrincipal {
                kind: TaskPrincipalKind::FounderAuthority,
                principal_id: "founder-authority:rework-confirmation".to_owned(),
                authenticated: true,
            },
        )
    }

    fn execute(
        &self,
        command: &TaskCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        let owner_principal = self.task_principal(principal)?;
        self.execute_as_owner(command, owner_principal)
    }

    fn execute_system_activation(
        &self,
        command: &TaskCommand,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        if !matches!(
            command.command,
            Some(task_command::Command::ActivateTask(_))
        ) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let owner_principal = AuthenticatedPrincipal {
            kind: TaskPrincipalKind::CollaborationControl,
            principal_id: SYSTEM_ACTIVATION_PRINCIPAL_ID.to_owned(),
            authenticated: true,
        };
        self.execute_as_owner(command, owner_principal)
    }

    fn execute_system_evidence_intake(
        &self,
        command: &TaskCommand,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        if !matches!(
            command.command,
            Some(task_command::Command::SubmitTaskEvidence(_))
        ) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let owner_principal = AuthenticatedPrincipal {
            kind: TaskPrincipalKind::CollaborationControl,
            principal_id: SYSTEM_EVIDENCE_INTAKE_PRINCIPAL_ID.to_owned(),
            authenticated: true,
        };
        self.execute_as_owner(command, owner_principal)
    }
}

impl AuthorityCommandPorts {
    fn execute_as_owner(
        &self,
        command: &TaskCommand,
        owner_principal: AuthenticatedPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        let _cross_authority_guard = if matches!(
            command.command,
            Some(task_command::Command::ApplyFounderVerdict(_))
        ) {
            Some(
                self.cross_authority_operation_gate
                    .lock()
                    .map_err(|_| CommandPortFailure::IntegrityFailure)?,
            )
        } else {
            None
        };
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

    fn claim_task_activation(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, TaskActivationSourceError> {
        self.task
            .lock()
            .map_err(|_| TaskActivationSourceError::Unavailable)?
            .claim_task_activation(message_id, payload_digest_sha256)
            .map_err(task_activation_source_error)
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

impl TaskCancellationSource for AuthorityCommandPorts {
    fn pending_task_cancellations(
        &self,
    ) -> Result<Vec<TaskCancellationHandoff>, TaskCancellationSourceError> {
        let authority = self
            .task
            .lock()
            .map_err(|_| TaskCancellationSourceError::Unavailable)?;
        authority
            .pending_task_cancellations()
            .map_err(task_cancellation_source_error)
            .and_then(|messages| {
                messages
                    .into_iter()
                    .map(|message| {
                        let requested_at = message
                            .event
                            .occurred_at
                            .ok_or(TaskCancellationSourceError::Integrity)?;
                        let task = message
                            .event
                            .snapshot
                            .clone()
                            .ok_or(TaskCancellationSourceError::Integrity)?;
                        Ok(TaskCancellationHandoff {
                            message_id: message.message_id,
                            payload_digest_sha256: message.payload_digest_sha256,
                            cancellation_request_id: message.event.event_id,
                            requested_at,
                            task,
                        })
                    })
                    .collect()
            })
    }

    fn acknowledge_task_cancellation(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, TaskCancellationSourceError> {
        self.task
            .lock()
            .map_err(|_| TaskCancellationSourceError::Unavailable)?
            .acknowledge_cross_authority_outbox(message_id, payload_digest_sha256)
            .map_err(|_| TaskCancellationSourceError::Integrity)
    }
}

impl TaskCancellationReconciler for AuthorityCommandPorts {
    fn reconcile_task_cancellation(
        &self,
        handoff: &TaskCancellationHandoff,
    ) -> Result<
        egopulse_cognition_runtime::task_authority::TaskCancellationReconciliation,
        TaskCancellationSourceError,
    > {
        self.task
            .lock()
            .map_err(|_| TaskCancellationSourceError::Unavailable)?
            .reconcile_task_cancellation(
                &handoff.message_id,
                &handoff.payload_digest_sha256,
                &AuthenticatedPrincipal {
                    kind: TaskPrincipalKind::CollaborationControl,
                    principal_id: "collaboration-control:task-cancellation".to_owned(),
                    authenticated: true,
                },
            )
            .map_err(task_cancellation_source_error)
    }

    fn settle_no_run_task_cancellation(
        &self,
        proof: &NoRunTaskCancellationProof,
    ) -> Result<
        egopulse_cognition_runtime::task_authority::TaskCancellationReconciliation,
        TaskCancellationSourceError,
    > {
        self.task
            .lock()
            .map_err(|_| TaskCancellationSourceError::Unavailable)?
            .settle_no_run_task_cancellation(
                proof,
                &AuthenticatedPrincipal {
                    kind: TaskPrincipalKind::CollaborationControl,
                    principal_id: "collaboration-control:task-cancellation".to_owned(),
                    authenticated: true,
                },
            )
            .map_err(task_cancellation_source_error)
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

impl ApprovalDeliverySource for AuthorityCommandPorts {
    fn approval_policy_evidence(
        &self,
        authority_decision_ref: &str,
    ) -> Result<Option<ApprovalPolicyEvidence>, ApprovalDeliveryCycleError> {
        let authority = self
            .policy
            .lock()
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?;
        let Some((record, state)) = authority
            .get(authority_decision_ref)
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?
        else {
            return Ok(None);
        };
        if HarnessApprovalDecisionStateKind::try_from(state.state)
            != Ok(HarnessApprovalDecisionStateKind::Issued)
        {
            return Ok(None);
        }
        let mut matched = None;
        // All Policy writes use this same owner lock. Unknown deliveries retain
        // their pending envelope until the existing Consume transition commits.
        for message in authority
            .pending_outbox()
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?
            .into_iter()
            .filter(|message| {
                message.destination_domain == "harness-adapter"
                    && message.payload_kind == "approval-decision-envelope-v1"
            })
        {
            if hex::encode(Sha256::digest(&message.payload)) != message.payload_digest_sha256 {
                return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
            }
            let envelope = ApprovalDecisionEnvelope::decode(message.payload.as_slice())
                .map_err(|_| ApprovalDeliveryCycleError::OwnerIntegrity)?;
            if envelope.authority_decision_ref != authority_decision_ref {
                continue;
            }
            if matched.is_some() || state.revision == 0 || state.revision != message.source_revision
            {
                return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
            }
            matched = Some(envelope);
        }
        let envelope = matched.ok_or(ApprovalDeliveryCycleError::OwnerIntegrity)?;
        Ok(Some((record, state, envelope)))
    }

    fn pending_approval_deliveries(
        &self,
    ) -> Result<Vec<PendingApprovalDelivery>, ApprovalDeliveryCycleError> {
        let authority = self
            .policy
            .lock()
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?;
        let outbox = authority
            .pending_outbox()
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?;
        let mut pending = Vec::new();
        for message in outbox.into_iter().filter(|message| {
            message.destination_domain == "harness-adapter"
                && message.payload_kind == "approval-decision-envelope-v1"
        }) {
            if hex::encode(Sha256::digest(&message.payload)) != message.payload_digest_sha256 {
                return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
            }
            let envelope = ApprovalDecisionEnvelope::decode(message.payload.as_slice())
                .map_err(|_| ApprovalDeliveryCycleError::OwnerIntegrity)?;
            let Some((record, state)) = authority
                .get(&envelope.authority_decision_ref)
                .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?
            else {
                return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
            };
            if HarnessApprovalDecisionStateKind::try_from(state.state)
                != Ok(HarnessApprovalDecisionStateKind::Issued)
            {
                continue;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?;
            let expired = record.expires_at.as_ref().is_none_or(|expires_at| {
                expires_at.seconds < i64::try_from(now.as_secs()).unwrap_or(i64::MAX)
                    || (expires_at.seconds == i64::try_from(now.as_secs()).unwrap_or(i64::MAX)
                        && expires_at.nanos
                            <= i32::try_from(now.subsec_nanos()).unwrap_or(i32::MAX))
            });
            let request = record
                .request
                .ok_or(ApprovalDeliveryCycleError::OwnerIntegrity)?;
            if state.revision == 0
                || state.revision != message.source_revision
                || envelope.meta.as_ref().is_none_or(|metadata| {
                    metadata.request_digest_sha256 != record.canonical_payload_digest_sha256
                        || metadata.idempotency_key != record.authority_decision_ref
                        || metadata.idempotency_scope != "policy-decision-to-harness-adapter"
                })
                || envelope.attempt_id != request.attempt_id
                || envelope.dispatch_id != request.dispatch_id
                || envelope.fencing_token != request.fencing_token
                || envelope.approval_request_id != request.approval_request_id
                || envelope.action_digest_sha256 != request.action_digest_sha256
                || envelope.native_routing_ref != request.native_routing_ref
                || envelope.authority_decision_ref != record.authority_decision_ref
                || envelope.decision != record.decision
            {
                return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
            }
            pending.push(PendingApprovalDelivery {
                source_event_id: message.source_event_id,
                envelope,
                request,
                expected_state_revision: state.revision,
                expired,
            });
        }
        Ok(pending)
    }

    fn consume_delivered_approval(
        &self,
        delivery: &PendingApprovalDelivery,
        receipt: ApprovalDecisionReceipt,
        harness_adapter_principal_id: &str,
    ) -> Result<PolicyDecisionCommandResult, ApprovalDeliveryCycleError> {
        if harness_adapter_principal_id.trim().is_empty() {
            return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
        }
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?;
        let stable_identity = format!(
            "{}:{}",
            delivery.envelope.authority_decision_ref, receipt.receipt_id
        );
        let mut command = PolicyDecisionCommand {
            command: Some(
                policy_decision_command::Command::ConsumeHarnessApprovalDecision(
                    ConsumeHarnessApprovalDecisionCommand {
                        metadata: Some(CommandMetadata {
                            command_id: format!("approval-consume-{stable_identity}"),
                            idempotency_key: stable_identity,
                            idempotency_scope: "policy-approval-delivery-consume-v1".to_owned(),
                            request_digest_sha256: String::new(),
                            issued_at: Some(prost_types::Timestamp {
                                seconds: i64::try_from(issued_at.as_secs())
                                    .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?,
                                nanos: i32::try_from(issued_at.subsec_nanos())
                                    .expect("subsecond nanoseconds fit i32"),
                            }),
                            correlation_id: Uuid::now_v7().to_string(),
                            causation_id: Some(delivery.source_event_id.clone()),
                        }),
                        authority_decision_ref: delivery.envelope.authority_decision_ref.clone(),
                        expected_state_revision: delivery.expected_state_revision,
                        adapter_receipt: Some(receipt),
                    },
                ),
            ),
        };
        let digest = canonical_request_digest(&command);
        let Some(policy_decision_command::Command::ConsumeHarnessApprovalDecision(consume)) =
            command.command.as_mut()
        else {
            return Err(ApprovalDeliveryCycleError::OwnerIntegrity);
        };
        consume
            .metadata
            .as_mut()
            .ok_or(ApprovalDeliveryCycleError::OwnerIntegrity)?
            .request_digest_sha256 = digest;
        self.policy
            .lock()
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)?
            .execute(
                &command,
                &AuthenticatedPolicyPrincipal {
                    kind: PolicyPrincipalKind::HarnessAdapter,
                    principal_id: harness_adapter_principal_id.to_owned(),
                    authenticated: true,
                },
            )
            .map_err(|_| ApprovalDeliveryCycleError::OwnerUnavailable)
    }
}

impl VerdictCommandPort for AuthorityCommandPorts {
    fn execute(
        &self,
        command: &VerdictCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        let owner_principal = self.verdict_principal(principal)?;
        let _cross_authority_guard = if verdict_command_changes_issued_state(command) {
            Some(
                self.cross_authority_operation_gate
                    .lock()
                    .map_err(|_| CommandPortFailure::IntegrityFailure)?,
            )
        } else {
            None
        };
        let mut verdict_handle = self
            .verdict
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        let authority = verdict_handle
            .as_mut()
            .ok_or(CommandPortFailure::Unavailable)?;
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

fn verdict_command_changes_issued_state(command: &VerdictCommand) -> bool {
    match command.command.as_ref() {
        Some(verdict_command::Command::ConsumeFounderVerdict(_))
        | Some(verdict_command::Command::RevokeFounderVerdict(_))
        | Some(verdict_command::Command::ExpireFounderVerdict(_)) => true,
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => issue
            .supersedes_founder_verdict_id
            .as_ref()
            .is_some_and(|verdict_id| !verdict_id.trim().is_empty()),
        None => false,
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
            .map_err(|_| ProjectionSourceFailure::Verdict)?;
        let verdict = verdict.as_ref().ok_or(ProjectionSourceFailure::Verdict)?;
        let verdict = verdict
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
                .as_mut()
                .ok_or(ProjectionSourceFailure::Verdict)?
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

fn task_cancellation_source_error(error: TaskAuthorityFailure) -> TaskCancellationSourceError {
    match error {
        TaskAuthorityFailure::Decode(_) | TaskAuthorityFailure::InvalidCrossAuthorityHandoff => {
            TaskCancellationSourceError::Integrity
        }
        TaskAuthorityFailure::Storage | TaskAuthorityFailure::Clock => {
            TaskCancellationSourceError::Unavailable
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
        TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization, TransitionGuardRejection,
        canonical_request_digest,
    };
    use egopulse_domain_contracts::v01::egopulse::common::v1::{
        CommandMetadata, ContractReference,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        policy::v1::{
            ConsumeHarnessApprovalDecisionCommand, ExpireHarnessApprovalDecisionCommand,
            HarnessApprovalDecisionRecord, IssueHarnessApprovalDecisionCommand,
            RevokeHarnessApprovalDecisionCommand,
        },
        task::v1::{
            ActivateTaskCommand, CreateTaskCommand, SubmitTaskEvidenceCommand, TaskCommand,
            TaskEventKind, TaskSnapshot, TaskStatus, task_command, task_command_result,
        },
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
    use prost_types::Timestamp;
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

    struct AllowCreation;

    impl TaskCreationGuard for AllowCreation {
        fn validate(
            &self,
            _command: &CreateTaskCommand,
        ) -> Result<CreationAuthorization, CreationGuardRejection> {
            Ok(CreationAuthorization {
                evidence_refs: vec!["fixture:create-authorized".to_owned()],
            })
        }
    }

    struct AllowTransition;

    impl TaskTransitionGuard for AllowTransition {
        fn validate(
            &self,
            _command: &TaskCommand,
            _current: &TaskSnapshot,
        ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
            Ok(TransitionAuthorization {
                evidence_refs: vec!["fixture:transition-authorized".to_owned()],
                founder_decision: None,
                founder_verdict_state_revision: None,
            })
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

        fn resolve_memory(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<MemoryPrincipalKind, CommandPortFailure> {
            Err(CommandPortFailure::Unavailable)
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

    fn task_metadata(command_id: &str, idempotency_key: &str) -> CommandMetadata {
        CommandMetadata {
            command_id: command_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            idempotency_scope: "agentosd-owner-test".to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(Timestamp {
                seconds: 1_777_073_600,
                nanos: 0,
            }),
            correlation_id: format!("correlation-{command_id}"),
            causation_id: None,
        }
    }

    fn task_contract_ref(contract_id: &str, version: &str, sha256: &str) -> ContractReference {
        ContractReference {
            contract_id: contract_id.to_owned(),
            version: version.to_owned(),
            sha256: sha256.to_owned(),
        }
    }

    fn set_task_digest(command: &mut TaskCommand) {
        let digest = canonical_request_digest(command).expect("canonical Task request digest");
        match command.command.as_mut().expect("Task command variant") {
            task_command::Command::CreateTask(value) => {
                value
                    .meta
                    .as_mut()
                    .expect("create metadata")
                    .request_digest_sha256 = digest;
            }
            task_command::Command::ActivateTask(value) => {
                value
                    .meta
                    .as_mut()
                    .expect("activate metadata")
                    .request_digest_sha256 = digest;
            }
            task_command::Command::SubmitTaskEvidence(value) => {
                value
                    .meta
                    .as_mut()
                    .expect("evidence metadata")
                    .request_digest_sha256 = digest;
            }
            _ => panic!("owner test helper does not support this Task command"),
        }
    }

    fn task_snapshot(
        result: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
    ) -> TaskSnapshot {
        match result.outcome.clone().expect("Task command outcome") {
            task_command_result::Outcome::Task(snapshot) => snapshot,
            task_command_result::Outcome::Error(error) => {
                panic!("expected Task snapshot, got {}", error.safe_detail_code)
            }
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
    fn system_activation_admits_only_activate_task_under_the_fixed_owner() {
        let root = root();
        let task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task-system-activation".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            AllowCreation,
            AllowTransition,
        )
        .expect("task owner");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy-system-activation".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict-system-activation".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("verdict owner");
        let task_handle = Arc::new(Mutex::new(task));

        let snapshot = {
            let mut authority = task_handle.lock().expect("Task owner lock");
            let mut create = TaskCommand {
                command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                    meta: Some(task_metadata("sysact-create", "sysact-create")),
                    work_type: "governed_repository_change".to_owned(),
                    input_snapshot_id: "input-sysact".to_owned(),
                    target_scope_ref: "scope-sysact".to_owned(),
                    acceptance_contract_ref: Some(task_contract_ref(
                        "acceptance-sysact",
                        "1",
                        &"a".repeat(64),
                    )),
                    budget_profile_ref: Some(task_contract_ref(
                        "budget-sysact",
                        "1",
                        &"b".repeat(64),
                    )),
                    work_capability_route: None,
                })),
            };
            set_task_digest(&mut create);
            let created = authority
                .execute(
                    &create,
                    &AuthenticatedPrincipal {
                        kind: TaskPrincipalKind::Founder,
                        principal_id: "founder:sysact-test".to_owned(),
                        authenticated: true,
                    },
                )
                .expect("create fixture Task");
            task_snapshot(&created)
        };

        let ports = AuthorityCommandPorts::new_shared(
            Arc::clone(&task_handle),
            policy,
            verdict,
            Arc::new(StaticPrincipalResolver),
        );

        let mut smuggled_create = TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(task_metadata("sysact-smuggle", "sysact-smuggle")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-sysact".to_owned(),
                target_scope_ref: "scope-sysact".to_owned(),
                acceptance_contract_ref: Some(task_contract_ref(
                    "acceptance-sysact",
                    "1",
                    &"a".repeat(64),
                )),
                budget_profile_ref: Some(task_contract_ref("budget-sysact", "1", &"b".repeat(64))),
                work_capability_route: None,
            })),
        };
        set_task_digest(&mut smuggled_create);
        let error = ports
            .execute_system_activation(&smuggled_create)
            .expect_err("non-activation commands must not pass the system boundary");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));

        let mut activate = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(task_metadata("sysact-activate", "sysact-activate")),
                task_id: snapshot.task_id.clone(),
                expected_revision: snapshot.revision,
                work_revision: snapshot.work_revision,
                run_id: "run-sysact-001".to_owned(),
            })),
        };
        set_task_digest(&mut activate);
        let result = ports
            .execute_system_activation(&activate)
            .expect("system activation commits through the owner");
        let activated = task_snapshot(&result.result);
        assert_eq!(activated.status, TaskStatus::Active as i32);
        assert_eq!(activated.current_run_id.as_deref(), Some("run-sysact-001"));
        assert!(result.source_revision.is_some());
        assert!(matches!(
            result.await_target,
            Some(AwaitTarget::Task { .. })
        ));

        let replay = ports
            .execute_system_activation(&activate)
            .expect("replayed system activation");
        assert!(replay.result.replayed);
        assert!(!result.result.replayed);

        drop(ports);
        drop(task_handle);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn system_evidence_intake_admits_only_task_evidence_under_the_fixed_owner() {
        let root = root();
        let task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task-system-evidence".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            AllowCreation,
            AllowTransition,
        )
        .expect("task owner");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy-system-evidence".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict-system-evidence".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("verdict owner");
        let task_handle = Arc::new(Mutex::new(task));

        let created = {
            let mut authority = task_handle.lock().expect("Task owner lock");
            let mut create = TaskCommand {
                command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                    meta: Some(task_metadata("sysevidence-create", "sysevidence-create")),
                    work_type: "governed_repository_change".to_owned(),
                    input_snapshot_id: "input-sysevidence".to_owned(),
                    target_scope_ref: "scope-sysevidence".to_owned(),
                    acceptance_contract_ref: Some(task_contract_ref(
                        "acceptance-sysevidence",
                        "1",
                        &"a".repeat(64),
                    )),
                    budget_profile_ref: Some(task_contract_ref(
                        "budget-sysevidence",
                        "1",
                        &"b".repeat(64),
                    )),
                    work_capability_route: None,
                })),
            };
            set_task_digest(&mut create);
            let result = authority
                .execute(
                    &create,
                    &AuthenticatedPrincipal {
                        kind: TaskPrincipalKind::Founder,
                        principal_id: "founder:sysevidence-test".to_owned(),
                        authenticated: true,
                    },
                )
                .expect("create fixture Task");
            task_snapshot(&result)
        };

        let ports = AuthorityCommandPorts::new_shared(
            Arc::clone(&task_handle),
            policy,
            verdict,
            Arc::new(StaticPrincipalResolver),
        );
        let mut activate = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(task_metadata(
                    "sysevidence-activate",
                    "sysevidence-activate",
                )),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run-sysevidence-001".to_owned(),
            })),
        };
        set_task_digest(&mut activate);
        let activated = task_snapshot(
            &ports
                .execute_system_activation(&activate)
                .expect("system activation")
                .result,
        );

        let error = ports
            .execute_system_evidence_intake(&activate)
            .expect_err("non-evidence commands must not pass the system boundary");
        assert!(matches!(error, CommandPortFailure::IntegrityFailure));

        let mut evidence = TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    meta: Some(task_metadata("sysevidence-submit", "sysevidence-submit")),
                    task_id: activated.task_id.clone(),
                    expected_revision: activated.revision,
                    work_revision: activated.work_revision,
                    return_handoff_id: "return-handoff-sysevidence".to_owned(),
                    artifact_set_id: "artifact-set-sysevidence".to_owned(),
                },
            )),
        };
        set_task_digest(&mut evidence);
        let result = ports
            .execute_system_evidence_intake(&evidence)
            .expect("system evidence intake commits through the owner");
        let submitted = task_snapshot(&result.result);
        assert_eq!(submitted.status, TaskStatus::VerificationPending as i32);
        assert_eq!(
            submitted.artifact_set_id.as_deref(),
            Some("artifact-set-sysevidence")
        );
        assert!(result.source_revision.is_some());
        assert!(matches!(
            result.await_target,
            Some(AwaitTarget::Task { .. })
        ));

        let replay = ports
            .execute_system_evidence_intake(&evidence)
            .expect("replayed system evidence intake");
        assert!(replay.result.replayed);
        assert!(!result.result.replayed);

        drop(ports);
        drop(task_handle);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn activation_source_port_reads_and_acknowledges_real_task_authority_outbox() {
        let root = root();
        let task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task-source".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            AllowCreation,
            AllowTransition,
        )
        .expect("task owner");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy-source".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict-source".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("verdict owner");
        let task_handle = Arc::new(Mutex::new(task));

        {
            let mut authority = task_handle.lock().expect("Task owner lock");
            let mut create = TaskCommand {
                command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                    meta: Some(task_metadata("source-create", "source-create")),
                    work_type: "governed_repository_change".to_owned(),
                    input_snapshot_id: "input-source".to_owned(),
                    target_scope_ref: "scope-source".to_owned(),
                    acceptance_contract_ref: Some(task_contract_ref(
                        "acceptance-source",
                        "1",
                        &"a".repeat(64),
                    )),
                    budget_profile_ref: Some(task_contract_ref(
                        "budget-source",
                        "1",
                        &"b".repeat(64),
                    )),
                    work_capability_route: None,
                })),
            };
            set_task_digest(&mut create);
            let created = authority
                .execute(
                    &create,
                    &AuthenticatedPrincipal {
                        kind: TaskPrincipalKind::Founder,
                        principal_id: "founder:source-test".to_owned(),
                        authenticated: true,
                    },
                )
                .expect("create source fixture Task");
            let snapshot = task_snapshot(&created);

            let mut activate = TaskCommand {
                command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                    meta: Some(task_metadata("source-activate", "source-activate")),
                    task_id: snapshot.task_id,
                    expected_revision: snapshot.revision,
                    work_revision: snapshot.work_revision,
                    run_id: "run-source-001".to_owned(),
                })),
            };
            set_task_digest(&mut activate);
            let activated = authority
                .execute(
                    &activate,
                    &AuthenticatedPrincipal {
                        kind: TaskPrincipalKind::CollaborationControl,
                        principal_id: "collaboration-control:source-test".to_owned(),
                        authenticated: true,
                    },
                )
                .expect("activate source fixture Task");
            assert_eq!(
                activated
                    .committed_event
                    .as_ref()
                    .expect("activation event")
                    .kind,
                TaskEventKind::Activated as i32
            );
        }

        let ports = AuthorityCommandPorts::new_shared(
            task_handle,
            policy,
            verdict,
            Arc::new(StaticPrincipalResolver),
        );
        let pending = TaskActivationSource::pending_task_activations(&ports)
            .expect("read real TaskAuthority activation source");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task.status, TaskStatus::Active as i32);
        assert_eq!(
            pending[0].task.current_run_id.as_deref(),
            Some("run-source-001")
        );
        assert!(
            !TaskActivationSource::acknowledge_task_activation(
                &ports,
                &pending[0].message_id,
                &"0".repeat(64),
            )
            .expect("reject wrong source digest")
        );
        let message_id = pending[0].message_id.clone();
        let payload_digest = pending[0].payload_digest_sha256.clone();

        drop(ports);

        let reopened_task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task-source".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            AllowCreation,
            AllowTransition,
        )
        .expect("reopen task owner after source interruption");
        let policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy-source".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("reopen policy owner");
        let verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict-source".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("reopen verdict owner");
        let recovered_ports = AuthorityCommandPorts::new(
            reopened_task,
            policy,
            verdict,
            Arc::new(StaticPrincipalResolver),
        );
        let recovered_pending = TaskActivationSource::pending_task_activations(&recovered_ports)
            .expect("read durable source after interruption");
        assert_eq!(recovered_pending.len(), 1);
        assert_eq!(recovered_pending[0].message_id, message_id);
        assert_eq!(recovered_pending[0].payload_digest_sha256, payload_digest);

        let competing_task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "c4-task-source".to_owned(),
                key: SqlCipherKey::new([1; 32]),
            },
            AllowCreation,
            AllowTransition,
        )
        .expect("open competing task owner");
        let competing_policy = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "c4-policy-source".to_owned(),
                key: PolicySqlCipherKey::new([2; 32]),
            },
            DenyPolicy,
        )
        .expect("open competing policy owner");
        let competing_verdict = FounderVerdictAuthority::open(
            VerdictAuthorityConfig {
                database_path: root.join("verdict.db"),
                store_epoch: "c4-verdict-source".to_owned(),
                key: VerdictSqlCipherKey::new([3; 32]),
            },
            DenyVerdict,
        )
        .expect("open competing verdict owner");
        let competing_ports = AuthorityCommandPorts::new(
            competing_task,
            competing_policy,
            competing_verdict,
            Arc::new(StaticPrincipalResolver),
        );
        let competing_pending = TaskActivationSource::pending_task_activations(&competing_ports)
            .expect("read source through competing port");
        assert_eq!(competing_pending.len(), 1);
        assert_eq!(competing_pending[0].message_id, message_id);
        assert_eq!(competing_pending[0].payload_digest_sha256, payload_digest);
        assert!(
            TaskActivationSource::acknowledge_task_activation(
                &recovered_ports,
                &message_id,
                &payload_digest,
            )
            .expect("acknowledge recovered source handoff")
        );
        assert!(
            !TaskActivationSource::acknowledge_task_activation(
                &competing_ports,
                &message_id,
                &payload_digest,
            )
            .expect("competing source ACK is rejected after first consumer")
        );
        assert!(
            TaskActivationSource::pending_task_activations(&recovered_ports)
                .expect("read source after ACK")
                .is_empty()
        );
        assert!(
            TaskActivationSource::pending_task_activations(&competing_ports)
                .expect("read competing source after ACK")
                .is_empty()
        );

        drop(competing_ports);
        drop(recovered_ports);
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
