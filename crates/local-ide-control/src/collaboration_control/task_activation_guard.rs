use super::{
    AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptSnapshot, CollaborationReferenceGuard,
    CollaborationSnapshot, CreateAttemptCommand, CreateRunCommand, DispatchMaterial,
    HarnessEvidenceResolver, LeaseAuthorization, MarkAttemptOutcomeUnknownCommand,
    RecordAttemptCancellationOutcomeCommand, RecordAttemptReconciliationCommand,
    RecordAttemptReturnCommand, RecordDeliveryReceiptCommand, RecordDispatchIntentCommand,
    RecordHarnessAckCommand, RecordRunningObservationCommand, ReferenceAuthorization,
    ReferenceGuardRejection, RequestAttemptCancellationCommand, ResolvedArtifactReturn,
    ResolvedHarnessEvidence, RunSnapshot, SingleHarnessWorkConfig, StepSnapshot,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunPlan;
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskSnapshot, TaskStatus};
use std::sync::{Arc, Mutex};

/// Reference guard for the first production vertical: a Task activation event
/// is the only source from which a single governed Harness run may be created.
/// It contains no Task store handle; the activation snapshot is immutable
/// evidence supplied by Task Authority and remains the sole cross-authority
/// reference this guard evaluates.
#[derive(Clone, Debug, PartialEq)]
pub struct TaskActivationReferenceGuard {
    task: TaskSnapshot,
    plan: RunPlan,
    harness_id: String,
    capability_profile_ref: ContractReference,
    workspace_ref: String,
    owner_instance_id: String,
    lease_policy_ref: ContractReference,
    lease_ttl_seconds: u64,
    material: DispatchMaterial,
}

/// A shared binding used by the single-writer worker. The binding changes only
/// between activation transactions, while CollaborationControl and the
/// Harness Adapter continue to share one runtime and one durable writer.
#[derive(Clone, Default)]
pub struct TaskActivationReferenceHandle {
    state: Arc<Mutex<Option<TaskActivationReferenceGuard>>>,
}

impl TaskActivationReferenceHandle {
    pub(crate) fn new(state: Arc<Mutex<Option<TaskActivationReferenceGuard>>>) -> Self {
        Self { state }
    }

    pub(crate) fn bind(
        &self,
        task: TaskSnapshot,
        config: &SingleHarnessWorkConfig,
        lease_ttl_seconds: u64,
    ) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        *state = Some(TaskActivationReferenceGuard::new(
            task,
            config,
            lease_ttl_seconds,
        ));
        Ok(())
    }

    fn with_guard<T>(
        &self,
        operation: impl FnOnce(&TaskActivationReferenceGuard) -> Result<T, ReferenceGuardRejection>,
    ) -> Result<T, ReferenceGuardRejection> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        state
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
            .and_then(operation)
    }
}

/// A Collaboration guard whose task reference is explicitly rebound by the
/// activation consumer. Harness evidence remains delegated to the separate
/// Adapter owner; this type only joins the two at the Collaboration boundary.
pub struct TaskActivationGuardSet<E> {
    reference: TaskActivationReferenceHandle,
    evidence: E,
}

impl<E> TaskActivationGuardSet<E> {
    #[must_use]
    pub fn new(evidence: E) -> (Self, TaskActivationReferenceHandle) {
        let handle = TaskActivationReferenceHandle::new(Arc::new(Mutex::new(None)));
        (
            Self {
                reference: handle.clone(),
                evidence,
            },
            handle,
        )
    }
}

impl<E> CollaborationReferenceGuard for TaskActivationGuardSet<E> {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.validate_create_run(command))
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.validate_activate_run(command, run))
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        run: &RunSnapshot,
        step: &StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.validate_create_attempt(command, run, step))
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.authorize_lease(command, attempt))
    }

    fn resolve_dispatch_material(
        &self,
        command: &RecordDispatchIntentCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.resolve_dispatch_material(command, snapshot))
    }

    fn validate_unknown_outcome(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.validate_unknown_outcome(command, snapshot))
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_guard(|guard| guard.validate_cancellation_request(command, snapshot))
    }
}

impl<E> HarnessEvidenceResolver for TaskActivationGuardSet<E>
where
    E: HarnessEvidenceResolver,
{
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.evidence.resolve_delivery_receipt(command, snapshot)
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.evidence.resolve_harness_ack(command, snapshot)
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence
            .validate_running_observation(command, snapshot)
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence
            .validate_cancellation_outcome(command, snapshot)
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence.validate_reconciliation(command, snapshot)
    }

    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        self.evidence.resolve_attempt_return(command, snapshot)
    }
}

impl TaskActivationReferenceGuard {
    #[must_use]
    pub fn new(
        task: TaskSnapshot,
        config: &SingleHarnessWorkConfig,
        lease_ttl_seconds: u64,
    ) -> Self {
        Self {
            task,
            plan: config.plan.clone(),
            harness_id: config.harness_id.clone(),
            capability_profile_ref: config.capability_profile_ref.clone(),
            workspace_ref: config.workspace_ref.clone(),
            owner_instance_id: config.owner_instance_id.clone(),
            lease_policy_ref: config.lease_policy_ref.clone(),
            lease_ttl_seconds,
            material: config.material.clone(),
        }
    }

    #[must_use]
    pub fn task(&self) -> &TaskSnapshot {
        &self.task
    }

    fn task_is_active_for_run(&self, run_id: &str) -> bool {
        self.task.status == TaskStatus::Active as i32
            && self.task.current_run_id.as_deref() == Some(run_id)
    }

    fn run_matches_task(&self, run: &RunSnapshot) -> bool {
        run.task_id == self.task.task_id
            && run.task_revision_at_creation == self.task.revision
            && run.work_revision == self.task.work_revision
            && self.task_is_active_for_run(&run.run_id)
    }

    fn step_is_planned(&self, step_id: &str) -> bool {
        self.plan.steps.iter().any(|step| step.step_id == step_id)
    }
}

impl CollaborationReferenceGuard for TaskActivationReferenceGuard {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if !self.task_is_active_for_run(&command.run_id)
            || command.task_id != self.task.task_id
            || command.task_revision != self.task.revision
            || command.work_revision != self.task.work_revision
            || command.plan.as_ref() != Some(&self.plan)
        {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "task-activation:{}@{}#{}",
                self.task.task_id, self.task.revision, self.task.work_revision
            )],
        })
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if !self.run_matches_task(run) || command.confirmed_task_revision != self.task.revision {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "task-active:{}@{}",
                self.task.task_id, self.task.revision
            )],
        })
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        run: &RunSnapshot,
        step: &StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if !self.run_matches_task(run)
            || !self.step_is_planned(&command.step_id)
            || step.step_id != command.step_id
            || command.harness_id != self.harness_id
            || command.capability_profile_ref.as_ref() != Some(&self.capability_profile_ref)
            || command.workspace_ref != self.workspace_ref
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![
                format!(
                    "capability-profile:{}@{}",
                    self.capability_profile_ref.contract_id, self.capability_profile_ref.version
                ),
                format!("workspace:{}@isolated", self.workspace_ref),
            ],
        })
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        _attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        if command.owner_instance_id != self.owner_instance_id
            || command.lease_policy_ref.as_ref() != Some(&self.lease_policy_ref)
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(LeaseAuthorization {
            ttl_seconds: self.lease_ttl_seconds,
            evidence_refs: vec![format!(
                "lease-policy:{}@{}",
                self.lease_policy_ref.contract_id, self.lease_policy_ref.version
            )],
        })
    }

    fn resolve_dispatch_material(
        &self,
        _command: &RecordDispatchIntentCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        let Some(run) = snapshot.run.as_ref() else {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        };
        if !self.run_matches_task(run) {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        }
        Ok(self.material.clone())
    }

    fn validate_unknown_outcome(
        &self,
        _command: &MarkAttemptOutcomeUnknownCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    fn validate_cancellation_request(
        &self,
        _command: &RequestAttemptCancellationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::collaboration::v1::CreateRunCommand;
    use egopulse_domain_contracts::v01::egopulse::harness::v1::NativeSessionStrategy;

    fn contract_ref(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "0.1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn config() -> SingleHarnessWorkConfig {
        SingleHarnessWorkConfig {
            run_id: "run-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            plan: RunPlan::default(),
            harness_id: "codex".to_owned(),
            capability_profile_ref: contract_ref("capability"),
            workspace_ref: "workspace-001".to_owned(),
            lease_policy_ref: contract_ref("lease"),
            owner_instance_id: "attempt-supervisor-001".to_owned(),
            material: DispatchMaterial {
                input_bundle_sha256: "b".repeat(64),
                sandbox_profile_ref: contract_ref("sandbox"),
                tool_policy_ref: contract_ref("tool"),
                data_egress_policy_ref: contract_ref("egress"),
                approval_policy_ref: contract_ref("approval"),
                session_strategy: NativeSessionStrategy::CreateNew,
                native_session_ref: None,
                checkpoint_ref: None,
                evidence_refs: vec!["material:verified".to_owned()],
            },
            task_authority_principal_id: "task-authority:001".to_owned(),
            collaboration_principal_id: "collaboration-control:001".to_owned(),
            attempt_supervisor_principal_id: "attempt-supervisor:001".to_owned(),
            harness_adapter_principal_id: "adapter:codex".to_owned(),
        }
    }

    #[test]
    fn accepts_only_the_activated_task_revision_and_run_plan() {
        let config = config();
        let task = TaskSnapshot {
            task_id: "task-001".to_owned(),
            revision: 2,
            work_revision: 1,
            status: TaskStatus::Active as i32,
            current_run_id: Some(config.run_id.clone()),
            ..Default::default()
        };
        let guard = TaskActivationReferenceGuard::new(task, &config, 30);
        let command = CreateRunCommand {
            meta: None,
            run_id: config.run_id,
            task_id: "task-001".to_owned(),
            task_revision: 2,
            work_revision: 1,
            plan: Some(config.plan),
        };
        assert!(guard.validate_create_run(&command).is_ok());

        let mut stale = command;
        stale.task_revision = 1;
        assert_eq!(
            guard.validate_create_run(&stale),
            Err(ReferenceGuardRejection::StaleTaskReference)
        );
    }
}
