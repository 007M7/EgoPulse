use super::{
    AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptSnapshot, CollaborationReferenceGuard,
    CollaborationSnapshot, CommitStepReturnCommand, CreateAttemptCommand, CreateRunCommand,
    DispatchMaterial, HarnessEvidenceResolver, LeaseAuthorization,
    MarkAttemptOutcomeUnknownCommand, RecordAttemptCancellationOutcomeCommand,
    RecordAttemptReconciliationCommand, RecordAttemptReturnCommand, RecordDeliveryReceiptCommand,
    RecordDispatchIntentCommand, RecordHarnessAckCommand, RecordRunningObservationCommand,
    ReferenceAuthorization, ReferenceGuardRejection, RequestAttemptCancellationCommand,
    ResolvedArtifactReturn, ResolvedHarnessEvidence, ResolvedStepReturn, RunSnapshot,
    SingleHarnessWorkConfig, StepSnapshot, TaskCancellationHandoff,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{AttemptStatus, RunPlan};
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
    state: Arc<Mutex<TaskReferenceState>>,
}

#[derive(Default)]
struct TaskReferenceState {
    activation: Option<TaskActivationReferenceGuard>,
    cancellation: Option<TaskCancellationReferenceGuard>,
}

/// A short-lived proof installed only while one already-validated Task
/// cancellation handoff is committed into its exact Collaboration attempt.
/// The Task event itself remains owned by Task Authority; this value never
/// grants another Task, Run, Attempt, or retry permission.
#[derive(Clone, Debug, PartialEq)]
struct TaskCancellationReferenceGuard {
    handoff: TaskCancellationHandoff,
    run: RunSnapshot,
    step: StepSnapshot,
    attempt: AttemptSnapshot,
}

impl TaskActivationReferenceHandle {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(TaskReferenceState::default())),
        }
    }

    pub(crate) fn bind(
        &self,
        task: TaskSnapshot,
        config: &SingleHarnessWorkConfig,
        lease_ttl_seconds: u64,
    ) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.activation = Some(TaskActivationReferenceGuard::new(
            task,
            config,
            lease_ttl_seconds,
        ));
        state.cancellation = None;
        Ok(())
    }

    pub(crate) fn bind_cancellation(
        &self,
        handoff: TaskCancellationHandoff,
        snapshot: &CollaborationSnapshot,
        attempt: &AttemptSnapshot,
    ) -> Result<(), ()> {
        let guard = TaskCancellationReferenceGuard::new(handoff, snapshot, attempt)?;
        let mut state = self.state.lock().map_err(|_| ())?;
        state.cancellation = Some(guard);
        Ok(())
    }

    /// Clears the one-shot cancellation binding before the runner can process
    /// another handoff. A failed/aborted commit cannot authorize a later Task.
    pub(crate) fn clear_cancellation(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        state.cancellation = None;
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
            .activation
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
            .and_then(operation)
    }

    fn with_cancellation_guard<T>(
        &self,
        operation: impl FnOnce(&TaskCancellationReferenceGuard) -> Result<T, ReferenceGuardRejection>,
    ) -> Result<T, ReferenceGuardRejection> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        state
            .cancellation
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
        let handle = TaskActivationReferenceHandle::new();
        (
            Self {
                reference: handle.clone(),
                evidence,
            },
            handle,
        )
    }
}

impl<E> CollaborationReferenceGuard for TaskActivationGuardSet<E>
where
    E: HarnessEvidenceResolver,
{
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
        self.evidence.validate_delivery_unknown(command, snapshot)
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .with_cancellation_guard(|guard| guard.validate_cancellation_request(command, snapshot))
    }
}

impl<E> HarnessEvidenceResolver for TaskActivationGuardSet<E>
where
    E: HarnessEvidenceResolver,
{
    fn validate_delivery_unknown(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence.validate_delivery_unknown(command, snapshot)
    }

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

    fn resolve_cancellation_return(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        self.evidence.resolve_cancellation_return(command, snapshot)
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

    fn resolve_step_return(
        &self,
        command: &CommitStepReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        self.evidence.resolve_step_return(command, snapshot)
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

impl TaskCancellationReferenceGuard {
    fn new(
        handoff: TaskCancellationHandoff,
        snapshot: &CollaborationSnapshot,
        attempt: &AttemptSnapshot,
    ) -> Result<Self, ()> {
        let run_id = handoff
            .task
            .current_run_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(())?;
        let run = snapshot
            .run
            .as_ref()
            .filter(|run| {
                run.run_id == run_id
                    && run.task_id == handoff.task.task_id
                    && run.work_revision == handoff.task.work_revision
            })
            .ok_or(())?;
        let step = snapshot
            .steps
            .iter()
            .find(|step| step.step_id == attempt.step_id && step.run_id == run_id)
            .ok_or(())?;
        if handoff.message_id.trim().is_empty()
            || handoff.payload_digest_sha256.len() != 64
            || !handoff
                .payload_digest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || handoff.cancellation_request_id.trim().is_empty()
            || handoff.task.task_id.trim().is_empty()
            || handoff.task.status != TaskStatus::CancellationPending as i32
            || attempt.run_id != run_id
            || attempt
                .dispatch_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            || !matches!(
                AttemptStatus::try_from(attempt.status),
                Ok(AttemptStatus::DispatchPending
                    | AttemptStatus::Dispatched
                    | AttemptStatus::Acknowledged
                    | AttemptStatus::Running)
            )
        {
            return Err(());
        }
        Ok(Self {
            handoff,
            run: run.clone(),
            step: step.clone(),
            attempt: attempt.clone(),
        })
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let base = command
            .base
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let meta = base
            .meta
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if command.task_cancellation_request_id != self.handoff.cancellation_request_id
            || base.run_id != self.run.run_id
            || base.expected_run_revision != self.run.revision
            || base.step_id != self.step.step_id
            || base.expected_step_revision != self.step.revision
            || base.attempt_id != self.attempt.attempt_id
            || base.expected_attempt_revision != self.attempt.revision
            || meta.command_id
                != format!(
                    "task-cancellation-delivery:{}",
                    self.handoff.cancellation_request_id
                )
            || meta.idempotency_key != self.handoff.cancellation_request_id
            || meta.idempotency_scope != self.attempt.attempt_id
            || meta.issued_at.as_ref() != Some(&self.handoff.requested_at)
            || meta.correlation_id != self.handoff.task.task_id
            || meta.causation_id.as_deref() != Some(self.handoff.cancellation_request_id.as_str())
            || !complete_lowercase_sha256(&meta.request_digest_sha256)
            || snapshot.run.as_ref() != Some(&self.run)
            || snapshot
                .steps
                .iter()
                .find(|step| step.step_id == self.step.step_id)
                != Some(&self.step)
            || snapshot
                .attempts
                .iter()
                .find(|attempt| attempt.attempt_id == self.attempt.attempt_id)
                != Some(&self.attempt)
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "task-cancellation:{}@{}#{}:{}",
                self.handoff.task.task_id,
                self.handoff.task.revision,
                self.handoff.task.work_revision,
                self.handoff.message_id
            )],
        })
    }
}

fn complete_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        if let Some(digest) = self.task.input_snapshot_id.strip_prefix("ctx:") {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || self.plan.steps.is_empty()
            {
                return Err(ReferenceGuardRejection::StaleTaskReference);
            }
            let expected_ref = format!("ctx-{digest}.json");
            if self.material.input_bundle_sha256 != digest
                || self
                    .plan
                    .steps
                    .iter()
                    .any(|step| step.input_bundle_ref != expected_ref)
            {
                return Err(ReferenceGuardRejection::StaleTaskReference);
            }
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
    use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
        AttemptCommandBase, CreateRunCommand, Lease, RequestAttemptCancellationCommand, StepPlan,
    };
    use egopulse_domain_contracts::v01::egopulse::common::v1::CommandMetadata;
    use egopulse_domain_contracts::v01::egopulse::harness::v1::NativeSessionStrategy;
    use prost_types::Timestamp;

    struct DenyEvidence;

    impl HarnessEvidenceResolver for DenyEvidence {
        fn resolve_delivery_receipt(
            &self,
            _command: &RecordDeliveryReceiptCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn resolve_harness_ack(
            &self,
            _command: &RecordHarnessAckCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_running_observation(
            &self,
            _command: &RecordRunningObservationCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_cancellation_outcome(
            &self,
            _command: &RecordAttemptCancellationOutcomeCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_reconciliation(
            &self,
            _command: &RecordAttemptReconciliationCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }
    }

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
                route_binding: None,
                evidence_refs: vec!["material:verified".to_owned()],
            },
            task_authority_principal_id: "task-authority:001".to_owned(),
            collaboration_principal_id: "collaboration-control:001".to_owned(),
            attempt_supervisor_principal_id: "attempt-supervisor:001".to_owned(),
            harness_adapter_principal_id: "adapter:codex".to_owned(),
        }
    }

    fn cancellation_snapshot() -> (CollaborationSnapshot, AttemptSnapshot) {
        let attempt = AttemptSnapshot {
            attempt_id: "attempt-cancel-001".to_owned(),
            run_id: "run-cancel-001".to_owned(),
            step_id: "step-cancel-001".to_owned(),
            revision: 7,
            status: AttemptStatus::Running as i32,
            dispatch_id: Some("dispatch-cancel-001".to_owned()),
            lease: Some(Lease {
                lease_id: "lease-cancel-001".to_owned(),
                fencing_token: 3,
                ..Default::default()
            }),
            ..Default::default()
        };
        (
            CollaborationSnapshot {
                run: Some(RunSnapshot {
                    run_id: "run-cancel-001".to_owned(),
                    task_id: "task-cancel-001".to_owned(),
                    revision: 5,
                    work_revision: 2,
                    ..Default::default()
                }),
                steps: vec![StepSnapshot {
                    step_id: "step-cancel-001".to_owned(),
                    run_id: "run-cancel-001".to_owned(),
                    revision: 6,
                    ..Default::default()
                }],
                attempts: vec![attempt.clone()],
            },
            attempt,
        )
    }

    fn cancellation_handoff() -> TaskCancellationHandoff {
        TaskCancellationHandoff {
            message_id: "task-outbox-cancellation-001".to_owned(),
            payload_digest_sha256: "a".repeat(64),
            cancellation_request_id: "task-event-cancellation-001".to_owned(),
            requested_at: Timestamp {
                seconds: 123,
                nanos: 456,
            },
            task: TaskSnapshot {
                task_id: "task-cancel-001".to_owned(),
                revision: 4,
                work_revision: 2,
                status: TaskStatus::CancellationPending as i32,
                current_run_id: Some("run-cancel-001".to_owned()),
                ..Default::default()
            },
        }
    }

    fn cancellation_command(
        handoff: &TaskCancellationHandoff,
        snapshot: &CollaborationSnapshot,
        attempt: &AttemptSnapshot,
    ) -> RequestAttemptCancellationCommand {
        let run = snapshot.run.as_ref().expect("run");
        let step = snapshot.steps.first().expect("step");
        RequestAttemptCancellationCommand {
            base: Some(AttemptCommandBase {
                meta: Some(CommandMetadata {
                    command_id: format!(
                        "task-cancellation-delivery:{}",
                        handoff.cancellation_request_id
                    ),
                    idempotency_key: handoff.cancellation_request_id.clone(),
                    idempotency_scope: attempt.attempt_id.clone(),
                    request_digest_sha256: "b".repeat(64),
                    issued_at: Some(handoff.requested_at),
                    correlation_id: handoff.task.task_id.clone(),
                    causation_id: Some(handoff.cancellation_request_id.clone()),
                }),
                run_id: run.run_id.clone(),
                expected_run_revision: run.revision,
                step_id: step.step_id.clone(),
                expected_step_revision: step.revision,
                attempt_id: attempt.attempt_id.clone(),
                expected_attempt_revision: attempt.revision,
            }),
            task_cancellation_request_id: handoff.cancellation_request_id.clone(),
        }
    }

    #[test]
    fn cancellation_proof_is_exact_one_shot_and_task_scoped() {
        let (snapshot, attempt) = cancellation_snapshot();
        let handoff = cancellation_handoff();
        let handle = TaskActivationReferenceHandle::new();
        handle
            .bind_cancellation(handoff.clone(), &snapshot, &attempt)
            .expect("bind exact Task cancellation handoff");

        let command = cancellation_command(&handoff, &snapshot, &attempt);
        assert!(
            handle
                .with_cancellation_guard(|guard| {
                    guard.validate_cancellation_request(&command, &snapshot)
                })
                .is_ok()
        );

        let mut old_attempt = command.clone();
        old_attempt
            .base
            .as_mut()
            .expect("base")
            .expected_attempt_revision -= 1;
        assert!(
            handle
                .with_cancellation_guard(|guard| {
                    guard.validate_cancellation_request(&old_attempt, &snapshot)
                })
                .is_err()
        );

        let mut forged_request = command.clone();
        forged_request.task_cancellation_request_id = "task-event-forged".to_owned();
        assert!(
            handle
                .with_cancellation_guard(|guard| {
                    guard.validate_cancellation_request(&forged_request, &snapshot)
                })
                .is_err()
        );

        let mut other_task = handoff.clone();
        other_task.task.task_id = "task-other-001".to_owned();
        assert!(
            handle
                .bind_cancellation(other_task, &snapshot, &attempt)
                .is_err()
        );

        handle.clear_cancellation().expect("clear one-shot proof");
        assert!(
            handle
                .with_cancellation_guard(|guard| {
                    guard.validate_cancellation_request(&command, &snapshot)
                })
                .is_err()
        );
    }

    #[test]
    fn exact_task_cancellation_handoff_commits_the_live_collaboration_attempt() {
        let config = SingleHarnessWorkConfig {
            run_id: "run-live-cancel-001".to_owned(),
            attempt_id: "attempt-live-cancel-001".to_owned(),
            dispatch_id: "dispatch-live-cancel-001".to_owned(),
            plan: RunPlan {
                plan_id: "plan-live-cancel-001".to_owned(),
                digest_sha256: "c".repeat(64),
                max_active_attempts: 1,
                steps: vec![StepPlan {
                    step_id: "step-live-cancel-001".to_owned(),
                    step_kind: "implementation".to_owned(),
                    input_bundle_ref: "input-live-cancel-001".to_owned(),
                    expected_output_contract_ref: Some(contract_ref("output")),
                    required_capability_profile_ref: Some(contract_ref("capability")),
                    max_attempts: 2,
                    ..Default::default()
                }],
                budget_profile_ref: Some(contract_ref("budget")),
            },
            harness_id: "codex".to_owned(),
            capability_profile_ref: contract_ref("capability"),
            workspace_ref: "workspace-live-cancel-001".to_owned(),
            lease_policy_ref: contract_ref("lease"),
            owner_instance_id: "owner-live-cancel-001".to_owned(),
            material: DispatchMaterial {
                input_bundle_sha256: "d".repeat(64),
                sandbox_profile_ref: contract_ref("sandbox"),
                tool_policy_ref: contract_ref("tool"),
                data_egress_policy_ref: contract_ref("egress"),
                approval_policy_ref: contract_ref("approval"),
                session_strategy: NativeSessionStrategy::CreateNew,
                native_session_ref: None,
                checkpoint_ref: None,
                route_binding: None,
                evidence_refs: vec!["material:live-cancel".to_owned()],
            },
            task_authority_principal_id: "task-authority:live-cancel".to_owned(),
            collaboration_principal_id: "collaboration-control:live-cancel".to_owned(),
            attempt_supervisor_principal_id: "attempt-supervisor:live-cancel".to_owned(),
            harness_adapter_principal_id: "adapter:live-cancel".to_owned(),
        };
        let active_task = TaskSnapshot {
            task_id: "task-live-cancel-001".to_owned(),
            revision: 1,
            work_revision: 1,
            status: TaskStatus::Active as i32,
            current_run_id: Some(config.run_id.clone()),
            ..Default::default()
        };
        let root =
            std::env::temp_dir().join(format!("egopulse-live-cancel-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("test root");
        let (guard, reference) = TaskActivationGuardSet::new(DenyEvidence);
        let mut control = super::super::CollaborationControl::open(
            super::super::CollaborationControlConfig {
                database_path: root.join("collaboration.sqlite3"),
                store_epoch: "live-cancellation-guard-test-v1".to_owned(),
                key: super::super::CollaborationSqlCipherKey::new([0x92; 32]),
            },
            guard,
            super::super::SystemAuthorityClock,
        )
        .expect("Collaboration Control");
        reference
            .bind(active_task.clone(), &config, 60)
            .expect("bind activation proof");
        let result =
            super::super::start_single_harness_workflow(&mut control, &active_task, &config)
                .expect("real Collaboration activation");
        let snapshot = match control
            .get_collaboration(&result.run_id)
            .expect("read Collaboration")
            .outcome
        {
            Some(super::super::get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
            _ => panic!("live Collaboration snapshot"),
        };
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == result.attempt_id)
            .expect("live attempt")
            .clone();
        let handoff = TaskCancellationHandoff {
            message_id: "task-outbox-cancellation-live-001".to_owned(),
            payload_digest_sha256: "e".repeat(64),
            cancellation_request_id: "task-event-cancellation-live-001".to_owned(),
            requested_at: Timestamp {
                seconds: 234,
                nanos: 0,
            },
            task: TaskSnapshot {
                status: TaskStatus::CancellationPending as i32,
                revision: 2,
                ..active_task
            },
        };
        reference
            .bind_cancellation(handoff.clone(), &snapshot, &attempt)
            .expect("bind exact cancellation proof");
        let request = cancellation_command(&handoff, &snapshot, &attempt);
        let mut command = super::super::CollaborationCommand {
            command: Some(
                super::super::collaboration_command::Command::RequestAttemptCancellation(request),
            ),
        };
        assert!(super::super::seal_request_digest(&mut command).is_some());
        let committed = control
            .execute(
                &command,
                &super::super::AuthenticatedCollaborationPrincipal {
                    kind: super::super::CollaborationPrincipalKind::CollaborationControl,
                    principal_id: "collaboration-control:task-cancellation".to_owned(),
                    authenticated: true,
                },
            )
            .expect("commit cancellation request");
        assert!(committed.committed_event.is_some());
        reference
            .clear_cancellation()
            .expect("clear cancellation proof");
        let after = match control
            .get_collaboration(&result.run_id)
            .expect("read committed Collaboration")
            .outcome
        {
            Some(super::super::get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
            _ => panic!("committed Collaboration snapshot"),
        };
        assert_eq!(
            after.run.expect("run").status,
            super::super::RunStatus::CancellationPending as i32
        );
        assert_eq!(
            after.attempts[0].status,
            AttemptStatus::CancellationPending as i32
        );
        let _ = std::fs::remove_dir_all(root);
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

    #[test]
    fn context_dispatch_material_must_match_task_snapshot_and_plan() {
        let digest = "ab".repeat(32);
        let mut config = config();
        config.material.input_bundle_sha256 = digest.clone();
        config.plan.steps = vec![StepPlan {
            step_id: "step-001".to_owned(),
            input_bundle_ref: format!("ctx-{digest}.json"),
            ..Default::default()
        }];
        let task = TaskSnapshot {
            task_id: "task-001".to_owned(),
            revision: 2,
            work_revision: 1,
            status: TaskStatus::Active as i32,
            current_run_id: Some(config.run_id.clone()),
            input_snapshot_id: format!("ctx:{digest}"),
            ..Default::default()
        };
        let guard = TaskActivationReferenceGuard::new(task, &config, 30);
        let snapshot = CollaborationSnapshot {
            run: Some(RunSnapshot {
                run_id: config.run_id.clone(),
                task_id: "task-001".to_owned(),
                task_revision_at_creation: 2,
                work_revision: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            guard
                .resolve_dispatch_material(&RecordDispatchIntentCommand::default(), &snapshot)
                .is_ok()
        );

        let mut stale_config = config;
        stale_config.material.input_bundle_sha256 = "cd".repeat(32);
        let stale_guard =
            TaskActivationReferenceGuard::new(guard.task().clone(), &stale_config, 30);
        assert_eq!(
            stale_guard
                .resolve_dispatch_material(&RecordDispatchIntentCommand::default(), &snapshot),
            Err(ReferenceGuardRejection::StaleTaskReference)
        );
    }
}
