//! C-06 recovery for an expired Verdict that was never applied to Task.
//! Policy persists the authorization; Verdict remains the sole state writer.

#[cfg(test)]
#[path = "verdict_expiry_tests.rs"]
mod tests;

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::task_authority::TaskAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::{CommandMetadata, ContractReference},
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        IssueHarnessApprovalDecisionCommand,
    },
    verdict::v1::{
        ExpireFounderVerdictCommand, FounderVerdict, FounderVerdictState, FounderVerdictStateKind,
        VerdictCommand, verdict_command,
    },
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, VerdictPrincipalKind, VerdictReferenceRejection,
    canonical_request_digest,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyDecisionAuthority, PolicyPrincipalKind,
    PolicyReferenceRejection, PolicyReferenceResolver, ResolvedApprovalAuthorization,
    ResolvedFounderVerdictExpiry,
};
use prost_types::Timestamp;

use crate::{
    ConfiguredFounderVerdictConsumeWorker, FounderVerdictConsumeCycleError,
    FounderVerdictConsumeCycleResult, FounderVerdictConsumeWorker, SharedFounderVerdictAuthority,
};

const EXPIRY_PRINCIPAL: &str = "policy-authority:founder-verdict-expiry";

pub(crate) struct FounderExpiryPolicyResolver {
    pub approval: Box<dyn PolicyReferenceResolver>,
    pub task: Arc<Mutex<TaskAuthority>>,
    pub verdict: SharedFounderVerdictAuthority,
    pub policy_ref: ContractReference,
}

impl PolicyReferenceResolver for FounderExpiryPolicyResolver {
    fn resolve_issue(
        &self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        self.approval.resolve_issue(command, principal)
    }

    fn validate_adapter_receipt(
        &self,
        command: &ConsumeHarnessApprovalDecisionCommand,
        record: &HarnessApprovalDecisionRecord,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        self.approval
            .validate_adapter_receipt(command, record, principal)
    }

    fn resolve_founder_verdict_expiry(
        &self,
        verdict_id: &str,
        expected_state_revision: u64,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedFounderVerdictExpiry, PolicyReferenceRejection> {
        if !principal.authenticated
            || principal.kind != PolicyPrincipalKind::PolicyAuthority
            || principal.principal_id != EXPIRY_PRINCIPAL
        {
            return Err(PolicyReferenceRejection::PermissionDenied);
        }
        let (verdict, state) = self
            .verdict
            .lock()
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
            .as_ref()
            .ok_or(PolicyReferenceRejection::NotFound)?
            .get(verdict_id)
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
            .ok_or(PolicyReferenceRejection::NotFound)?;
        if state.state != FounderVerdictStateKind::Issued as i32
            || state.revision != expected_state_revision
        {
            return Err(PolicyReferenceRejection::RequestMismatch);
        }
        let scope = verdict
            .scope
            .as_ref()
            .ok_or(PolicyReferenceRejection::IntegrityFailure)?;
        let applied = self
            .task
            .lock()
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
            .applied_founder_verdict(scope, verdict_id)
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?;
        if applied.is_some() {
            return Err(PolicyReferenceRejection::PolicyDenied);
        }
        // These references name actual owner reads. Policy's own clock checks
        // expiry and its durable receipt binds the entire immutable snapshot.
        let evidence_refs = vec![
            format!("founder-verdict:{verdict_id}@{expected_state_revision}"),
            format!(
                "task-application-absence:{}@{}:{verdict_id}",
                scope.task_id, scope.task_revision
            ),
        ];
        Ok(ResolvedFounderVerdictExpiry {
            verdict,
            state,
            policy_ref: self.policy_ref.clone(),
            evidence_refs,
        })
    }
}

pub(crate) struct FounderVerdictExpiryProofSource {
    pub policy: Arc<Mutex<PolicyDecisionAuthority>>,
    pub task: Arc<Mutex<TaskAuthority>>,
    pub policy_ref: ContractReference,
}

impl FounderVerdictExpiryProofSource {
    pub(crate) fn validate(
        &self,
        command: &ExpireFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        verdict: &FounderVerdict,
        state: &FounderVerdictState,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        if !principal.authenticated
            || principal.kind != VerdictPrincipalKind::PolicyAuthority
            || principal.principal_id != EXPIRY_PRINCIPAL
        {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        let authorization = self
            .policy
            .lock()
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .founder_verdict_expiry_authorization(&command.policy_decision_ref)
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .ok_or(VerdictReferenceRejection::PermissionDenied)?;
        if authorization.authorization_id != command.policy_decision_ref
            || authorization.verdict.as_ref() != Some(verdict)
            || authorization.state.as_ref() != Some(state)
            || authorization.policy_ref.as_ref() != Some(&self.policy_ref)
            || authorization.authenticated_principal_id != EXPIRY_PRINCIPAL
            || command.founder_verdict_id != verdict.founder_verdict_id
            || command.expected_state_revision != state.revision
            || state.state != FounderVerdictStateKind::Issued as i32
        {
            return Err(VerdictReferenceRejection::IntegrityFailure);
        }
        let scope = verdict
            .scope
            .as_ref()
            .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
        if self
            .task
            .lock()
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .applied_founder_verdict(scope, &verdict.founder_verdict_id)
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .is_some()
        {
            return Err(VerdictReferenceRejection::TaskCommitReceiptInvalid);
        }
        Ok(vec![authorization.authorization_id])
    }
}

pub(crate) struct ExpiryRecoveringVerdictWorker {
    pub consumer: ConfiguredFounderVerdictConsumeWorker,
    pub task: Arc<Mutex<TaskAuthority>>,
    pub verdict: SharedFounderVerdictAuthority,
    pub policy: Arc<Mutex<PolicyDecisionAuthority>>,
    pub operation_gate: Arc<Mutex<()>>,
}

impl ExpiryRecoveringVerdictWorker {
    fn expire_once(
        &self,
    ) -> Result<FounderVerdictConsumeCycleResult, FounderVerdictConsumeCycleError> {
        // All client Apply/state changes and both recovery paths take this same
        // composition gate before touching an owner. No mutex spans an await.
        let _gate = self
            .operation_gate
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::InvalidHandoff)?;
        let handoffs = self
            .verdict
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::VerdictAuthorityLock)?
            .as_ref()
            .ok_or(FounderVerdictConsumeCycleError::VerdictAuthorityUnavailable)?
            .pending_task_handoffs()
            .map_err(FounderVerdictConsumeCycleError::VerdictAuthority)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| FounderVerdictConsumeCycleError::InvalidHandoff)?;
        let mut first_failure = None;
        for handoff in handoffs {
            match self.expire_handoff(&handoff, now) {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => {}
                Err(error) => {
                    // The notification remains pending. One held authorization
                    // must not prevent another Task's expiry from progressing.
                    if first_failure.is_none() {
                        first_failure = Some(error);
                    }
                }
            }
        }
        match first_failure {
            Some(error) => Err(error),
            None => Ok(FounderVerdictConsumeCycleResult::Idle),
        }
    }

    fn expire_handoff(
        &self,
        handoff: &egopulse_founder_verdict_authority::PendingTaskVerdictHandoff,
        now: std::time::Duration,
    ) -> Result<Option<FounderVerdictConsumeCycleResult>, FounderVerdictConsumeCycleError> {
        let expires_at = handoff
            .verdict
            .expires_at
            .as_ref()
            .ok_or(FounderVerdictConsumeCycleError::InvalidHandoff)?;
        if !matches!(
            FounderVerdictStateKind::try_from(handoff.state.state),
            Ok(FounderVerdictStateKind::Issued | FounderVerdictStateKind::Expired)
        ) || (now.as_secs() as i64, now.subsec_nanos() as i32)
            < (expires_at.seconds, expires_at.nanos)
        {
            return Ok(None);
        }
        let scope = handoff
            .verdict
            .scope
            .as_ref()
            .ok_or(FounderVerdictConsumeCycleError::InvalidHandoff)?;
        if self
            .task
            .lock()
            .map_err(|_| FounderVerdictConsumeCycleError::TaskAuthorityLock)?
            .applied_founder_verdict(scope, &handoff.verdict.founder_verdict_id)
            .map_err(FounderVerdictConsumeCycleError::TaskAuthority)?
            .is_some()
        {
            return Ok(None);
        }
        if handoff.state.state == FounderVerdictStateKind::Issued as i32 {
            let authorization = self
                .policy
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::InvalidHandoff)?
                .issue_founder_verdict_expiry(
                    &handoff.verdict.founder_verdict_id,
                    handoff.state.revision,
                    &AuthenticatedPolicyPrincipal {
                        kind: PolicyPrincipalKind::PolicyAuthority,
                        principal_id: EXPIRY_PRINCIPAL.to_owned(),
                        authenticated: true,
                    },
                )
                .map_err(|_| FounderVerdictConsumeCycleError::ExpiryAuthorizationRejected)?;
            let authorization_time = authorization
                .evaluated_at
                .ok_or(FounderVerdictConsumeCycleError::InvalidHandoff)?;
            let mut command = expiry_command(
                &authorization.authorization_id,
                &handoff.verdict.founder_verdict_id,
                handoff.state.revision,
                authorization_time,
            );
            let digest = canonical_request_digest(&command);
            if let Some(verdict_command::Command::ExpireFounderVerdict(expire)) =
                command.command.as_mut()
                && let Some(metadata) = expire.metadata.as_mut()
            {
                metadata.request_digest_sha256 = digest;
            }
            let result = self
                .verdict
                .lock()
                .map_err(|_| FounderVerdictConsumeCycleError::VerdictAuthorityLock)?
                .as_mut()
                .ok_or(FounderVerdictConsumeCycleError::VerdictAuthorityUnavailable)?
                .execute(
                    &command,
                    &AuthenticatedVerdictPrincipal {
                        kind: VerdictPrincipalKind::PolicyAuthority,
                        principal_id: EXPIRY_PRINCIPAL.to_owned(),
                        authenticated: true,
                    },
                )
                .map_err(FounderVerdictConsumeCycleError::VerdictAuthority)?;
            if !result.committed && !result.replayed {
                return Err(FounderVerdictConsumeCycleError::HandoffRejected {
                    error_code: result.error_code,
                    safe_error_fingerprint: result.safe_error_fingerprint,
                });
            }
        }
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
        Ok(Some(FounderVerdictConsumeCycleResult::Expired {
            founder_verdict_id: handoff.verdict.founder_verdict_id.clone(),
            task_id: scope.task_id.clone(),
        }))
    }
}

impl FounderVerdictConsumeWorker for ExpiryRecoveringVerdictWorker {
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
        Box::pin(async move {
            match self.consumer.run_once().await? {
                FounderVerdictConsumeCycleResult::Idle => self.expire_once(),
                result => Ok(result),
            }
        })
    }
}

fn expiry_command(
    authorization_id: &str,
    verdict_id: &str,
    revision: u64,
    at: Timestamp,
) -> VerdictCommand {
    VerdictCommand {
        command: Some(verdict_command::Command::ExpireFounderVerdict(
            ExpireFounderVerdictCommand {
                metadata: Some(CommandMetadata {
                    command_id: format!("expire:{authorization_id}"),
                    request_digest_sha256: String::new(),
                    idempotency_scope: "founder-verdict-expiry/v1".to_owned(),
                    idempotency_key: authorization_id.to_owned(),
                    correlation_id: authorization_id.to_owned(),
                    issued_at: Some(at),
                    ..Default::default()
                }),
                founder_verdict_id: verdict_id.to_owned(),
                expected_state_revision: revision,
                policy_decision_ref: authorization_id.to_owned(),
            },
        )),
    }
}
