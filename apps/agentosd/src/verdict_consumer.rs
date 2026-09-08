use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use crate::SharedFounderVerdictAuthority;
use egopulse_cognition_runtime::task_authority::{TaskAuthority, TaskAuthorityFailure};
use egopulse_domain_contracts::v01::egopulse::{
    task::v1::TaskStatus,
    verdict::v1::{FounderVerdictDecision, VerdictCommand, verdict_command},
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, PendingTaskVerdictHandoff, VerdictAuthorityFailure,
    VerdictPrincipalKind,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

const FOUNDER_VERDICT_DESTINATION: &str = "founder-verdict-authority";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FounderVerdictConsumeCycleResult {
    Idle,
    Expired {
        founder_verdict_id: String,
        task_id: String,
    },
    Consumed {
        message_id: String,
        founder_verdict_id: String,
        replayed: bool,
    },
    ApplicationAcknowledged {
        message_id: String,
        founder_verdict_id: String,
        task_id: String,
        replayed: bool,
    },
}

#[derive(Debug, Error)]
pub enum FounderVerdictConsumeCycleError {
    #[error("Policy Authority did not authorize Founder Verdict expiry")]
    ExpiryAuthorizationRejected,
    #[error("cross-Authority Founder Verdict operation gate is poisoned")]
    OperationGate,
    #[error("Task Authority is unavailable")]
    TaskAuthority(#[source] TaskAuthorityFailure),
    #[error("Task Authority lock is poisoned")]
    TaskAuthorityLock,
    #[error("Founder Verdict Authority is unavailable")]
    VerdictAuthorityUnavailable,
    #[error("Founder Verdict Authority lock is poisoned")]
    VerdictAuthorityLock,
    #[error("Founder Verdict handoff is malformed")]
    InvalidHandoff,
    #[error(
        "Founder Verdict handoff was rejected (error_code={error_code}, fingerprint={safe_error_fingerprint:?})"
    )]
    HandoffRejected {
        error_code: i32,
        safe_error_fingerprint: Option<String>,
    },
    #[error("Founder Verdict Authority failed")]
    VerdictAuthority(#[source] VerdictAuthorityFailure),
    #[error("Task outbox acknowledgement was not accepted")]
    AcknowledgementRejected,
}

pub trait FounderVerdictConsumeWorker: Send + Sync + 'static {
    fn run_once<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        FounderVerdictConsumeCycleResult,
                        FounderVerdictConsumeCycleError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}

/// Consumes Task -> Verdict receipts and acknowledges Issue notifications only
/// after proof of an already committed Task application. The daemon never
/// submits ApplyFounderVerdict; pending consumption takes priority.
pub struct ConfiguredFounderVerdictConsumeWorker {
    task: Arc<Mutex<TaskAuthority>>,
    verdict: SharedFounderVerdictAuthority,
    cross_authority_operation_gate: Arc<Mutex<()>>,
    principal: AuthenticatedVerdictPrincipal,
}

impl ConfiguredFounderVerdictConsumeWorker {
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        verdict: SharedFounderVerdictAuthority,
        principal_id: impl Into<String>,
    ) -> Result<Self, FounderVerdictConsumeWorkerConfigurationError> {
        Self::new_with_operation_gate(task, verdict, principal_id, Arc::new(Mutex::new(())))
    }

    pub fn new_with_operation_gate(
        task: Arc<Mutex<TaskAuthority>>,
        verdict: SharedFounderVerdictAuthority,
        principal_id: impl Into<String>,
        cross_authority_operation_gate: Arc<Mutex<()>>,
    ) -> Result<Self, FounderVerdictConsumeWorkerConfigurationError> {
        let principal_id = principal_id.into();
        if principal_id.trim().is_empty() {
            return Err(FounderVerdictConsumeWorkerConfigurationError::InvalidPrincipalId);
        }
        Ok(Self {
            task,
            verdict,
            cross_authority_operation_gate,
            principal: AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::TaskAuthority,
                principal_id,
                authenticated: true,
            },
        })
    }

    fn run_cycle(
        &self,
    ) -> Result<FounderVerdictConsumeCycleResult, FounderVerdictConsumeCycleError> {
        let _cross_authority_guard = self
            .cross_authority_operation_gate
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::OperationGate)?;
        let message = {
            let task = self
                .task
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::TaskAuthorityLock)?;
            task.pending_cross_authority_outbox()
                .map_err(FounderVerdictConsumeCycleError::TaskAuthority)?
                .into_iter()
                .find(|message| message.destination_domain == FOUNDER_VERDICT_DESTINATION)
        };
        let Some(message) = message else {
            return self.acknowledge_applied_verdicts();
        };

        let actual_digest = hex::encode(Sha256::digest(&message.payload));
        if actual_digest != message.payload_digest_sha256 {
            return Err(FounderVerdictConsumeCycleError::InvalidHandoff);
        }
        let command = VerdictCommand::decode(message.payload.as_slice())
            .map_err(|_| FounderVerdictConsumeCycleError::InvalidHandoff)?;
        let founder_verdict_id = match command.command.as_ref() {
            Some(verdict_command::Command::ConsumeFounderVerdict(consume))
                if !consume.founder_verdict_id.trim().is_empty() =>
            {
                consume.founder_verdict_id.clone()
            }
            _ => return Err(FounderVerdictConsumeCycleError::InvalidHandoff),
        };

        let result = {
            let mut verdict_handle = self
                .verdict
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::VerdictAuthorityLock)?;
            let verdict = verdict_handle
                .as_mut()
                .ok_or(FounderVerdictConsumeCycleError::VerdictAuthorityUnavailable)?;
            verdict
                .execute(&command, &self.principal)
                .map_err(FounderVerdictConsumeCycleError::VerdictAuthority)?
        };
        if !result.committed && !result.replayed {
            return Err(FounderVerdictConsumeCycleError::HandoffRejected {
                error_code: result.error_code,
                safe_error_fingerprint: result.safe_error_fingerprint.clone(),
            });
        }

        let acknowledged = self
            .task
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::TaskAuthorityLock)?
            .acknowledge_cross_authority_outbox(&message.message_id, &message.payload_digest_sha256)
            .map_err(FounderVerdictConsumeCycleError::TaskAuthority)?;
        if !acknowledged {
            return Err(FounderVerdictConsumeCycleError::AcknowledgementRejected);
        }
        Ok(FounderVerdictConsumeCycleResult::Consumed {
            message_id: message.message_id,
            founder_verdict_id,
            replayed: result.replayed,
        })
    }

    fn acknowledge_applied_verdicts(
        &self,
    ) -> Result<FounderVerdictConsumeCycleResult, FounderVerdictConsumeCycleError> {
        let handoffs = {
            let owner = self
                .verdict
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::VerdictAuthorityLock)?;
            owner
                .as_ref()
                .ok_or(FounderVerdictConsumeCycleError::VerdictAuthorityUnavailable)?
                .pending_task_handoffs()
                .map_err(FounderVerdictConsumeCycleError::VerdictAuthority)?
        };
        // Issue is a notification, not authority to apply after a restart.
        // Only an explicit client operation may submit ApplyFounderVerdict.
        // Scan past unapplied notifications so they cannot block receipt cleanup.
        for handoff in handoffs {
            let scope = handoff
                .verdict
                .scope
                .as_ref()
                .ok_or(FounderVerdictConsumeCycleError::InvalidHandoff)?;
            let expected_status = match FounderVerdictDecision::try_from(handoff.verdict.decision) {
                Ok(FounderVerdictDecision::Accept) => TaskStatus::Completed,
                Ok(FounderVerdictDecision::Rework) => TaskStatus::Rework,
                Ok(FounderVerdictDecision::Reject) => TaskStatus::Rejected,
                _ => return Err(FounderVerdictConsumeCycleError::InvalidHandoff),
            };
            let applied = self
                .task
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::TaskAuthorityLock)?
                .applied_founder_verdict(scope, &handoff.verdict.founder_verdict_id)
                .map_err(FounderVerdictConsumeCycleError::TaskAuthority)?;
            if let Some(event) = applied {
                if event
                    .snapshot
                    .as_ref()
                    .is_none_or(|snapshot| snapshot.status != expected_status as i32)
                {
                    return Err(FounderVerdictConsumeCycleError::InvalidHandoff);
                }
                return self.acknowledge_application(&handoff, true);
            }
        }
        Ok(FounderVerdictConsumeCycleResult::Idle)
    }

    fn acknowledge_application(
        &self,
        handoff: &PendingTaskVerdictHandoff,
        replayed: bool,
    ) -> Result<FounderVerdictConsumeCycleResult, FounderVerdictConsumeCycleError> {
        let acknowledged = self
            .verdict
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::VerdictAuthorityLock)?
            .as_mut()
            .ok_or(FounderVerdictConsumeCycleError::VerdictAuthorityUnavailable)?
            .acknowledge_task_handoff(&handoff.message_id, &handoff.payload_digest_sha256)
            .map_err(FounderVerdictConsumeCycleError::VerdictAuthority)?;
        if !acknowledged {
            return Err(FounderVerdictConsumeCycleError::AcknowledgementRejected);
        }
        Ok(FounderVerdictConsumeCycleResult::ApplicationAcknowledged {
            message_id: handoff.message_id.clone(),
            founder_verdict_id: handoff.verdict.founder_verdict_id.clone(),
            task_id: handoff
                .verdict
                .scope
                .as_ref()
                .ok_or(FounderVerdictConsumeCycleError::InvalidHandoff)?
                .task_id
                .clone(),
            replayed,
        })
    }
}

impl FounderVerdictConsumeWorker for ConfiguredFounderVerdictConsumeWorker {
    fn run_once<'a>(
        &'a self,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        FounderVerdictConsumeCycleResult,
                        FounderVerdictConsumeCycleError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.run_cycle() })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum FounderVerdictConsumeWorkerConfigurationError {
    #[error("Founder Verdict consume worker principal id is empty")]
    InvalidPrincipalId,
}
