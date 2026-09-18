use super::{
    ArtifactReturnSource, AuthenticatedCollaborationPrincipal, AuthorityClock,
    CollaborationControl, CollaborationControlError, CollaborationPrincipalKind,
    CollaborationReferenceGuard, DELIVERY_OUTCOME_UNKNOWN_REASON_CODE,
    DeliveredDispatchForObservation, HarnessEvidenceResolver, HarnessFactIngestionDisposition,
    HarnessFactIngestionResult, HeldDispatchRecoveryState, SingleHarnessWorkConfig,
    SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolver, TaskActivationGuardSet,
    TaskActivationReferenceHandle, TaskActivationSource, TaskCancellationHandoff,
    seal_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::get_collaboration_response;
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AttemptCancellationDisposition, AttemptCommandBase, AttemptStatus,
    BeginAttemptReconciliationCommand, CollaborationCommand, CollaborationErrorCode,
    CollaborationSnapshot, CommitStepReturnCommand, MarkAttemptOutcomeUnknownCommand,
    ReconciliationDisposition, RecordAttemptCancellationOutcomeCommand,
    RecordAttemptReconciliationCommand, RecordAttemptReturnCommand,
    RequestAttemptCancellationCommand, RunCommandBase, RunStatus, StepStatus,
    collaboration_command, collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, ApprovalDecisionResult, CancelExecutionResult, DeliveryDisposition,
    DispatchEnvelope, HarnessObservation, LifecycleKind, ObservationCriticality, dispatch_result,
    harness_observation,
};
use egopulse_harness_adapter::{
    AdapterClock, DispatchMaterialResolver, GovernedAdapterError, GovernedHarnessAdapter,
    LegacyExecutionStartRecovery, NativeHarnessDriver, ReconciliationFinding,
};
use prost::Message;
use sha2::Digest;
use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc};
use thiserror::Error;

const NATIVE_DISPATCH_SESSION_NOT_RESIDENT_REASON_CODE: &str =
    "NATIVE_DISPATCH_SESSION_NOT_RESIDENT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRecoveryKind {
    /// The Collaboration run reached a committed Cancelled outcome. The owning
    /// Task may record its cancellation outcome if it is still pending.
    CancellationConfirmed,
    /// Cancellation lost to an independently sealed technical return. The
    /// Task owner must arbitrate the return from its Artifact proof; a native
    /// interrupt delivery receipt cannot promote this finding.
    CancellationReturnFound,
    /// The Harness terminal outcome is unknown or unproven (quarantined run).
    /// The owning Task may need an interruption record if it is still Active.
    OutcomeUnknown,
}

/// An in-cycle, derived observation of a committed collaboration recovery
/// fact. It carries no authority of its own: the owning Task Authority still
/// validates task identity, current run binding, revision and status before
/// any Task mutation is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecoveryFinding {
    pub kind: TaskRecoveryKind,
    pub task_id: String,
    pub run_id: String,
    pub evidence_ref: String,
}

/// Task-local activation material failure observed before the activation
/// outbox can be acknowledged. This is cycle telemetry, not a durable Task or
/// Attempt state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskActivationBlockage {
    pub task_id: String,
    pub dispatch_id: String,
    pub safe_detail_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDispatchMaterialRejection {
    pub safe_detail_code: String,
}

/// Optional Task-scoped material boundary around the durable Collaboration
/// workflow. Implementations may prepare immutable dispatch material before
/// the Run exists and must seal it before the Task activation is acknowledged.
pub trait TaskDispatchMaterialPreparer: Send + Sync {
    fn prepare<'a>(
        &'a self,
        activation: &'a super::TaskActivationHandoff,
        config: SingleHarnessWorkConfig,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SingleHarnessWorkConfig, TaskDispatchMaterialRejection>>
                + Send
                + 'a,
        >,
    >;

    fn seal_before_activation_ack<'a>(
        &'a self,
        activation: &'a super::TaskActivationHandoff,
        config: &'a SingleHarnessWorkConfig,
        result: &'a super::SingleHarnessWorkResult,
    ) -> Pin<Box<dyn Future<Output = Result<(), TaskDispatchMaterialRejection>> + Send + 'a>>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HarnessDispatchCycleReport {
    pub dispatches_seen: u64,
    pub dispatches_delivered: u64,
    pub dispatches_rejected: u64,
    pub observations_seen: u64,
    pub observations_consumed: u64,
    pub observations_deferred: u64,
    pub observations_retained: u64,
    pub observations_quarantined: u64,
    pub terminal_observations: u64,
    pub terminal_output_candidates_seen: u64,
    pub terminal_output_candidates_receipted: u64,
    pub terminal_output_candidates_held: u64,
    /// Number of Artifact returns whose Verification-gated Step return was
    /// durably committed or replayed in this cycle.
    pub return_settlements: u64,
    /// Number of Artifact Authority returns whose Task evidence intake was
    /// durably committed or idempotently replayed in this cycle.
    pub task_evidence_intakes: u64,
    pub activations_seen: u64,
    pub activations_started: u64,
    pub activations_acknowledged: u64,
    pub activation_blockages: Vec<TaskActivationBlockage>,
    pub terminal_dispatch_ids: Vec<String>,
    /// Dispatches held by Collaboration recovery. This is deliberately
    /// separate from terminal observations: a hold proves no terminal fact.
    pub held_dispatch_ids: Vec<String>,
    /// Committed collaboration recovery facts observed this cycle. Derived
    /// telemetry only: durability is owned by the collaboration event log, and
    /// every Task-side settlement re-validates against live Task state.
    pub task_recovery_findings: Vec<TaskRecoveryFinding>,
}

#[derive(Debug, Error)]
pub enum HarnessDispatchCycleError {
    #[error("collaboration control operation failed")]
    Collaboration(#[from] CollaborationControlError),
    #[error("harness adapter operation failed")]
    Adapter(#[from] GovernedAdapterError),
    #[error("task activation source operation failed")]
    TaskActivationSource,
    #[error("task activation resolver rejected the explicit workflow configuration")]
    TaskActivationResolver,
    #[error("task activation workflow failed: {0}")]
    TaskActivationWorkflow(String),
    #[error("governed return collector failed: {0}")]
    ReturnCollector(String),
    #[error("governed Task evidence intake failed: {0}")]
    TaskEvidenceIntake(String),
    #[error("harness recovery failed: {0}")]
    Recovery(String),
}

pub trait HarnessDispatchRunner: Send + Sync {
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    >;
}

/// Delivers an Authority-issued approval through the exact live adapter that
/// owns the matching native dispatch. Implementations retain the adapter's
/// durable delivery receipt boundary, including unknown-outcome replay.
pub trait HarnessApprovalDeliveryTarget: Send + Sync {
    fn deliver_approval<'a>(
        &'a self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> Pin<
        Box<dyn Future<Output = Result<ApprovalDecisionResult, GovernedAdapterError>> + Send + 'a>,
    >;

    /// Records uncertainty through Collaboration's evidence guard. This never
    /// resends the native approval or consumes an unconfirmed Policy decision.
    fn recover_unknown_approval<'a>(
        &'a self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> Pin<Box<dyn Future<Output = Result<(), HarnessDispatchCycleError>> + Send + 'a>> {
        Box::pin(async {
            Err(HarnessDispatchCycleError::Recovery(
                "approval outcome recovery is not configured".to_owned(),
            ))
        })
    }
}

/// Thin delivery port over the already-live Adapter held by a governed task
/// runner. It deliberately exposes no driver construction or session access.
pub trait HarnessCancellationDeliveryTarget: Send + Sync {
    fn owns_task_cancellation<'a>(
        &'a self,
        handoff: &'a TaskCancellationHandoff,
    ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>;

    fn deliver_task_cancellation<'a>(
        &'a self,
        handoff: &'a TaskCancellationHandoff,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                + Send
                + 'a,
        >,
    >;
}

#[derive(Debug, Error)]
pub enum HarnessCancellationDeliveryError {
    #[error("collaboration cancellation state could not be read")]
    DispatchState(#[from] HarnessDispatchCycleError),
    #[error("collaboration control operation failed")]
    Collaboration(#[from] CollaborationControlError),
    #[error("harness adapter operation failed")]
    Adapter(#[from] GovernedAdapterError),
    #[error("Task cancellation does not match one live dispatch")]
    LiveBinding,
    #[error("Task cancellation deadline is invalid")]
    Deadline,
}

/// Runs multiple provider-specific dispatch workers through one daemon
/// scheduling hook. Each child runner must be configured with its own
/// capability-profile filter and Adapter Edge. The composite only sequences
/// the child cycles; it does not select a model or merge provider-owned facts.
pub struct CompositeHarnessDispatchRunner {
    runners: Vec<std::sync::Arc<dyn HarnessDispatchRunner>>,
}

impl CompositeHarnessDispatchRunner {
    pub fn new(
        runners: Vec<std::sync::Arc<dyn HarnessDispatchRunner>>,
    ) -> Result<Self, &'static str> {
        if runners.is_empty() {
            return Err("at least one Harness dispatch runner is required");
        }
        Ok(Self { runners })
    }
}

impl HarnessDispatchRunner for CompositeHarnessDispatchRunner {
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut report = HarnessDispatchCycleReport::default();
            for runner in &self.runners {
                let child = runner.run_once().await?;
                merge_report(&mut report, child);
            }
            Ok(report)
        })
    }
}

struct GovernedDispatchRuntime<G, C, R, D, A> {
    control: CollaborationControl<G, C>,
    adapter: GovernedHarnessAdapter<R, D, A>,
    active_envelopes: Vec<DispatchEnvelope>,
}

pub struct GovernedHarnessDispatchRunner<G, C, R, D, A> {
    runtime: tokio::sync::Mutex<GovernedDispatchRuntime<G, C, R, D, A>>,
    principal: AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<CapabilityProfileFilter>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CapabilityProfileFilter {
    Exact(ContractReference),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurableReplayBarrier {
    Clear,
    PendingBlocked,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationSettlement {
    Settled,
    PendingBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivePumpStep {
    DurableEventAppended,
    Idle,
    Held,
    Retire,
    Blocked(DurableReplayBarrier),
}

impl<G, C, R, D, A> GovernedHarnessDispatchRunner<G, C, R, D, A>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    #[must_use]
    pub fn new(
        control: CollaborationControl<G, C>,
        adapter: GovernedHarnessAdapter<R, D, A>,
        principal: AuthenticatedCollaborationPrincipal,
    ) -> Self {
        Self {
            runtime: tokio::sync::Mutex::new(GovernedDispatchRuntime {
                control,
                adapter,
                active_envelopes: Vec::new(),
            }),
            principal,
            capability_profile_filter: None,
        }
    }

    /// Restricts this runner to one exact reviewed capability reference. The
    /// contract id, version and digest must all match; this prevents two
    /// revisions of the same profile from sharing a dispatch path.
    #[must_use]
    pub fn with_capability_profile_ref(mut self, profile: ContractReference) -> Self {
        self.capability_profile_filter = Some(CapabilityProfileFilter::Exact(profile));
        self
    }
}

impl<G, C, R, D, A> HarnessDispatchRunner for GovernedHarnessDispatchRunner<G, C, R, D, A>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut runtime = self.runtime.lock().await;
            let GovernedDispatchRuntime {
                control,
                adapter,
                active_envelopes,
            } = &mut *runtime;
            let mut report = HarnessDispatchCycleReport::default();
            record_settled_cancellation_findings(
                control,
                self.capability_profile_filter.as_ref(),
                &mut report,
            )?;
            recover_held_dispatches(
                control,
                adapter,
                &self.principal,
                self.capability_profile_filter.as_ref(),
                &mut report,
            )
            .await?;
            let delivered = register_delivered_envelopes(
                control,
                adapter,
                active_envelopes,
                &self.principal,
                self.capability_profile_filter.as_ref(),
            )?;
            let pending = register_pending_envelopes(
                control,
                active_envelopes,
                &self.principal,
                self.capability_profile_filter.as_ref(),
            )?;
            pump_active_envelopes(
                control,
                adapter,
                active_envelopes,
                &delivered,
                &pending,
                &self.principal,
                &mut report,
            )
            .await?;
            let dispatched = dispatch_pending_for_profile(
                control,
                adapter,
                &self.principal,
                self.capability_profile_filter.as_ref(),
                &BTreeSet::new(),
            )
            .await?;
            merge_report(&mut report, dispatched);
            remove_terminal_envelopes(active_envelopes, &report);
            Ok(report)
        })
    }
}

struct GovernedTaskActivationRuntime<S, W, E, C, R, D, A> {
    control: CollaborationControl<TaskActivationGuardSet<E>, C>,
    adapter: GovernedHarnessAdapter<R, D, A>,
    source: S,
    resolver: W,
    reference: TaskActivationReferenceHandle,
    lease_ttl_seconds: u64,
    active_envelopes: Vec<DispatchEnvelope>,
    artifact_return_source: Option<std::sync::Arc<dyn ArtifactReturnSource>>,
    artifact_return_principal: Option<AuthenticatedCollaborationPrincipal>,
    step_return_principal: Option<AuthenticatedCollaborationPrincipal>,
    task_dispatch_material_preparer: Option<Arc<dyn TaskDispatchMaterialPreparer>>,
}

/// The production single-writer worker for the first vertical. It consumes
/// Task activation handoffs, binds the immutable activation reference, starts
/// the explicit single-Harness workflow, acknowledges the Task outbox only
/// after the Collaboration commit, and then dispatches through the same
/// CollaborationControl/Adapter runtime.
pub struct GovernedTaskActivationRunner<S, W, E, C, R, D, A> {
    runtime: tokio::sync::Mutex<GovernedTaskActivationRuntime<S, W, E, C, R, D, A>>,
    principal: AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<CapabilityProfileFilter>,
}

impl<S, W, E, C, R, D, A> GovernedTaskActivationRunner<S, W, E, C, R, D, A>
where
    S: TaskActivationSource + Send,
    W: SingleHarnessWorkflowResolver + Send,
    E: HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    #[must_use]
    pub fn new(
        control: CollaborationControl<TaskActivationGuardSet<E>, C>,
        adapter: GovernedHarnessAdapter<R, D, A>,
        source: S,
        resolver: W,
        principal: AuthenticatedCollaborationPrincipal,
        reference: TaskActivationReferenceHandle,
        lease_ttl_seconds: u64,
    ) -> Self {
        Self {
            runtime: tokio::sync::Mutex::new(GovernedTaskActivationRuntime {
                control,
                adapter,
                source,
                resolver,
                reference,
                lease_ttl_seconds,
                active_envelopes: Vec::new(),
                artifact_return_source: None,
                artifact_return_principal: None,
                step_return_principal: None,
                task_dispatch_material_preparer: None,
            }),
            principal,
            capability_profile_filter: None,
        }
    }

    /// Restricts activation consumption and the subsequent dispatch sweep to
    /// one exact reviewed capability reference. This is required when more
    /// than one provider runner observes the same Task activation outbox.
    #[must_use]
    pub fn with_capability_profile_ref(mut self, profile: ContractReference) -> Self {
        self.capability_profile_filter = Some(CapabilityProfileFilter::Exact(profile));
        self
    }

    #[must_use]
    pub fn with_artifact_return_source(
        mut self,
        source: std::sync::Arc<dyn ArtifactReturnSource>,
        principal: AuthenticatedCollaborationPrincipal,
    ) -> Self {
        let runtime = self.runtime.get_mut();
        runtime.artifact_return_source = Some(source);
        runtime.artifact_return_principal = Some(principal);
        self
    }

    /// Adds the internal Collaboration writer used after the technical
    /// Artifact return has been proven by the configured Verification guard.
    /// This is deliberately separate from the Artifact Authority principal:
    /// the two writes have different owners and cannot be collapsed.
    #[must_use]
    pub fn with_step_return_principal(
        mut self,
        principal: AuthenticatedCollaborationPrincipal,
    ) -> Self {
        self.runtime.get_mut().step_return_principal = Some(principal);
        self
    }

    #[must_use]
    pub fn with_task_dispatch_material_preparer(
        mut self,
        preparer: Arc<dyn TaskDispatchMaterialPreparer>,
    ) -> Self {
        self.runtime.get_mut().task_dispatch_material_preparer = Some(preparer);
        self
    }
}

impl<S, W, E, C, R, D, A> HarnessApprovalDeliveryTarget
    for GovernedTaskActivationRunner<S, W, E, C, R, D, A>
where
    S: TaskActivationSource + Send,
    W: SingleHarnessWorkflowResolver + Send,
    E: HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    fn deliver_approval<'a>(
        &'a self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> Pin<
        Box<dyn Future<Output = Result<ApprovalDecisionResult, GovernedAdapterError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut runtime = self.runtime.lock().await;
            runtime.adapter.decide_approval(envelope).await
        })
    }

    fn recover_unknown_approval<'a>(
        &'a self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> Pin<Box<dyn Future<Output = Result<(), HarnessDispatchCycleError>> + Send + 'a>> {
        Box::pin(async move {
            let mut runtime = self.runtime.lock().await;
            let dispatch = runtime
                .adapter
                .edge()
                .dispatch_envelope(&envelope.dispatch_id)
                .map_err(GovernedAdapterError::from)?
                .ok_or_else(|| {
                    HarnessDispatchCycleError::Recovery(
                        "approval recovery dispatch is not durable".to_owned(),
                    )
                })?;
            if self.capability_profile_filter.is_none()
                || !envelope_matches_profile(&dispatch, self.capability_profile_filter.as_ref())
                || dispatch.attempt_id != envelope.attempt_id
                || dispatch.fencing_token != envelope.fencing_token
            {
                return Err(HarnessDispatchCycleError::Recovery(
                    "approval recovery does not match the adapter route".to_owned(),
                ));
            }
            let snapshot = collaboration_snapshot(&runtime.control, &dispatch.run_id)?;
            let attempt = snapshot
                .attempts
                .iter()
                .find(|attempt| attempt.attempt_id == envelope.attempt_id)
                .filter(|attempt| {
                    attempt.dispatch_id.as_deref() == Some(envelope.dispatch_id.as_str())
                        && attempt
                            .lease
                            .as_ref()
                            .is_some_and(|lease| lease.fencing_token == envelope.fencing_token)
                        && attempt.capability_profile_ref == dispatch.capability_profile_ref
                })
                .ok_or_else(|| {
                    HarnessDispatchCycleError::Recovery(
                        "approval recovery attempt binding changed".to_owned(),
                    )
                })?;
            // A previous cycle may already have committed the hold and begun
            // reconciliation. Do not rebuild the same command with a different
            // revision/digest; the normal recovery runner owns its continuation.
            if snapshot
                .run
                .as_ref()
                .is_some_and(|run| run.status == RunStatus::Held as i32)
                && matches!(
                    AttemptStatus::try_from(attempt.status),
                    Ok(AttemptStatus::OutcomeUnknown
                        | AttemptStatus::Reconciling
                        | AttemptStatus::Held)
                )
            {
                return Ok(());
            }
            let mut command = CollaborationCommand {
                command: Some(collaboration_command::Command::MarkAttemptOutcomeUnknown(
                    MarkAttemptOutcomeUnknownCommand {
                        base: Some(recovery_attempt_base(
                            &snapshot,
                            &envelope.attempt_id,
                            &envelope.authority_decision_ref,
                            "approval-outcome-unknown",
                        )?),
                        reason_code: DELIVERY_OUTCOME_UNKNOWN_REASON_CODE.to_owned(),
                        uncertainty_evidence_id: envelope.authority_decision_ref.clone(),
                    },
                )),
            };
            seal_request_digest(&mut command).ok_or_else(|| {
                HarnessDispatchCycleError::Recovery(
                    "approval recovery command could not be sealed".to_owned(),
                )
            })?;
            require_recovery_commit(
                runtime.control.execute(&command, &recovery_principal())?,
                "approval-outcome-unknown",
            )
        })
    }
}

impl<S, W, E, C, R, D, A> HarnessCancellationDeliveryTarget
    for GovernedTaskActivationRunner<S, W, E, C, R, D, A>
where
    S: TaskActivationSource + Send,
    W: SingleHarnessWorkflowResolver + Send,
    E: HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    fn owns_task_cancellation<'a>(
        &'a self,
        handoff: &'a TaskCancellationHandoff,
    ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>
    {
        Box::pin(async move {
            let runtime = self.runtime.lock().await;
            Ok(cancellation_attempt(
                &runtime.control,
                handoff,
                self.capability_profile_filter.as_ref(),
            )?
            .is_some())
        })
    }

    fn deliver_task_cancellation<'a>(
        &'a self,
        handoff: &'a TaskCancellationHandoff,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let mut runtime = self.runtime.lock().await;
            let attempt = cancellation_attempt(
                &runtime.control,
                handoff,
                self.capability_profile_filter.as_ref(),
            )?
            .ok_or(HarnessCancellationDeliveryError::LiveBinding)?;
            if attempt.status != AttemptStatus::CancellationPending as i32 {
                let snapshot = collaboration_snapshot(
                    &runtime.control,
                    handoff
                        .task
                        .current_run_id
                        .as_deref()
                        .ok_or(HarnessCancellationDeliveryError::LiveBinding)?,
                )?;
                runtime
                    .reference
                    .bind_cancellation(handoff.clone(), &snapshot, &attempt)
                    .map_err(|_| HarnessCancellationDeliveryError::LiveBinding)?;
                let mut command = CollaborationCommand {
                    command: Some(collaboration_command::Command::RequestAttemptCancellation(
                        RequestAttemptCancellationCommand {
                            base: Some(cancellation_attempt_base(&snapshot, &attempt, handoff)?),
                            task_cancellation_request_id: handoff.cancellation_request_id.clone(),
                        },
                    )),
                };
                if seal_request_digest(&mut command).is_none() {
                    runtime
                        .reference
                        .clear_cancellation()
                        .map_err(|_| HarnessCancellationDeliveryError::LiveBinding)?;
                    return Err(HarnessCancellationDeliveryError::LiveBinding);
                }
                // The cancellation proof is one-shot. Clear it even when the
                // Collaboration write rejects or fails, so a later handoff
                // cannot inherit this Task/Attempt authorization.
                let result = runtime.control.execute(&command, &cancellation_principal());
                runtime
                    .reference
                    .clear_cancellation()
                    .map_err(|_| HarnessCancellationDeliveryError::LiveBinding)?;
                require_cancellation_commit(result?)?;
            }

            // Re-read after the Collaboration commit/replay. The dispatch id
            // and state must still be the same live Attempt before the single
            // resident Adapter is allowed to write the native interrupt.
            let attempt = cancellation_attempt(
                &runtime.control,
                handoff,
                self.capability_profile_filter.as_ref(),
            )?
            .ok_or(HarnessCancellationDeliveryError::LiveBinding)?;
            if attempt.status != AttemptStatus::CancellationPending as i32 {
                return Err(HarnessCancellationDeliveryError::LiveBinding);
            }
            runtime
                .adapter
                .cancel_dispatch(
                    &handoff.cancellation_request_id,
                    attempt
                        .dispatch_id
                        .as_deref()
                        .ok_or(HarnessCancellationDeliveryError::LiveBinding)?,
                    cancellation_deadline(handoff)?,
                )
                .await
                .map_err(Into::into)
        })
    }
}

fn cancellation_attempt<G, C>(
    control: &CollaborationControl<G, C>,
    handoff: &TaskCancellationHandoff,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> Result<
    Option<egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot>,
    HarnessCancellationDeliveryError,
>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    // Cancellation may be delivered only by a runner whose reviewed profile
    // exactly owns this Attempt. A missing profile is insufficient evidence to
    // select a live native adapter.
    let capability_profile_filter =
        capability_profile_filter.ok_or(HarnessCancellationDeliveryError::LiveBinding)?;
    let Some(run_id) = handoff.task.current_run_id.as_deref() else {
        return Ok(None);
    };
    let snapshot = match control.get_collaboration(run_id)?.outcome {
        Some(get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
        _ => return Ok(None),
    };
    let Some(run) = snapshot.run.as_ref() else {
        return Err(HarnessCancellationDeliveryError::LiveBinding);
    };
    if handoff.cancellation_request_id.trim().is_empty()
        || handoff.task.task_id.trim().is_empty()
        || handoff.task.status
            != egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::CancellationPending
                as i32
        || run.run_id != run_id
        || run.task_id != handoff.task.task_id
        || run.work_revision != handoff.task.work_revision
    {
        return Err(HarnessCancellationDeliveryError::LiveBinding);
    }
    let matches = snapshot
        .attempts
        .iter()
        .filter(|attempt| {
            attempt_matches_capability_profile(attempt, capability_profile_filter)
                && has_cancellable_dispatch_id(attempt)
                && matches!(
                    AttemptStatus::try_from(attempt.status),
                    Ok(AttemptStatus::DispatchPending
                        | AttemptStatus::Dispatched
                        | AttemptStatus::Acknowledged
                        | AttemptStatus::Running
                        | AttemptStatus::CancellationPending)
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [attempt] => Ok(Some(attempt.clone())),
        [] => Ok(None),
        _ => Err(HarnessCancellationDeliveryError::LiveBinding),
    }
}

fn attempt_matches_capability_profile(
    attempt: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot,
    capability_profile_filter: &CapabilityProfileFilter,
) -> bool {
    attempt
        .capability_profile_ref
        .as_ref()
        .is_some_and(|reference| match capability_profile_filter {
            CapabilityProfileFilter::Exact(expected) => reference == expected,
        })
}

fn has_cancellable_dispatch_id(
    attempt: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot,
) -> bool {
    attempt
        .dispatch_id
        .as_deref()
        .is_some_and(|dispatch_id| !dispatch_id.trim().is_empty())
}

fn cancellation_attempt_base(
    snapshot: &CollaborationSnapshot,
    attempt: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot,
    handoff: &TaskCancellationHandoff,
) -> Result<AttemptCommandBase, HarnessCancellationDeliveryError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(HarnessCancellationDeliveryError::LiveBinding)?;
    let step = snapshot
        .steps
        .iter()
        .find(|step| step.step_id == attempt.step_id)
        .ok_or(HarnessCancellationDeliveryError::LiveBinding)?;
    Ok(AttemptCommandBase {
        meta: Some(CommandMetadata {
            command_id: format!(
                "task-cancellation-delivery:{}",
                handoff.cancellation_request_id
            ),
            idempotency_key: handoff.cancellation_request_id.clone(),
            idempotency_scope: attempt.attempt_id.clone(),
            request_digest_sha256: String::new(),
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
    })
}

fn cancellation_deadline(
    handoff: &TaskCancellationHandoff,
) -> Result<prost_types::Timestamp, HarnessCancellationDeliveryError> {
    if handoff.requested_at.nanos < 0 || handoff.requested_at.nanos >= 1_000_000_000 {
        return Err(HarnessCancellationDeliveryError::Deadline);
    }
    Ok(prost_types::Timestamp {
        seconds: handoff
            .requested_at
            .seconds
            .checked_add(300)
            .ok_or(HarnessCancellationDeliveryError::Deadline)?,
        nanos: handoff.requested_at.nanos,
    })
}

fn cancellation_principal() -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind: CollaborationPrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:task-cancellation".to_owned(),
        authenticated: true,
    }
}

fn require_cancellation_commit(
    result: egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationCommandResult,
) -> Result<(), HarnessCancellationDeliveryError> {
    if result.committed_event.is_some() || result.replayed {
        return Ok(());
    }
    Err(HarnessCancellationDeliveryError::LiveBinding)
}

impl<S, W, E, C, R, D, A> HarnessDispatchRunner
    for GovernedTaskActivationRunner<S, W, E, C, R, D, A>
where
    S: TaskActivationSource + Send,
    W: SingleHarnessWorkflowResolver + Send,
    E: HarnessEvidenceResolver + Send,
    C: AuthorityClock + Send,
    R: DispatchMaterialResolver + Send,
    D: NativeHarnessDriver + Send,
    A: AdapterClock + Send,
{
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut runtime = self.runtime.lock().await;
            let GovernedTaskActivationRuntime {
                control,
                adapter,
                source,
                resolver,
                reference,
                lease_ttl_seconds,
                active_envelopes,
                artifact_return_source,
                artifact_return_principal,
                step_return_principal,
                task_dispatch_material_preparer,
            } = &mut *runtime;
            let mut recovery_findings = Vec::new();
            let return_settlements = consume_artifact_returns(
                control,
                adapter,
                artifact_return_source.as_ref(),
                artifact_return_principal.as_ref(),
                step_return_principal.as_ref(),
                &mut recovery_findings,
            )?;
            let activations = source
                .pending_task_activations()
                .map_err(|_| HarnessDispatchCycleError::TaskActivationSource)?;
            let mut report = HarnessDispatchCycleReport {
                activations_seen: activations.len() as u64,
                return_settlements,
                task_recovery_findings: recovery_findings,
                ..HarnessDispatchCycleReport::default()
            };
            record_settled_cancellation_findings(
                control,
                self.capability_profile_filter.as_ref(),
                &mut report,
            )?;
            recover_held_dispatches(
                control,
                adapter,
                &self.principal,
                self.capability_profile_filter.as_ref(),
                &mut report,
            )
            .await?;
            let delivered = register_delivered_envelopes(
                control,
                adapter,
                active_envelopes,
                &self.principal,
                self.capability_profile_filter.as_ref(),
            )?;
            let pending = register_pending_envelopes(
                control,
                active_envelopes,
                &self.principal,
                self.capability_profile_filter.as_ref(),
            )?;
            pump_active_envelopes(
                control,
                adapter,
                active_envelopes,
                &delivered,
                &pending,
                &self.principal,
                &mut report,
            )
            .await?;
            let mut blocked_dispatch_ids = BTreeSet::new();
            // Do not acquire a lease or create another DispatchPending while
            // this single driver has work, including an older unsent pending
            // intent. At most one matching activation can consume the free
            // slot in a cycle; its dispatch is attempted below before another
            // activation is considered on a later poll.
            if !pending_dispatch_reserves_capacity(control, adapter, &pending)?
                && adapter.is_dispatch_ready()
            {
                for activation in activations {
                    let config = match resolver
                        .resolve(&activation)
                        .map_err(|_| HarnessDispatchCycleError::TaskActivationResolver)?
                    {
                        SingleHarnessWorkflowResolution::NotApplicable => continue,
                        SingleHarnessWorkflowResolution::Resolved(config) => (*config, None),
                        SingleHarnessWorkflowResolution::ResolvedWithRouteBinding {
                            config,
                            route_binding,
                        } => (*config, Some(*route_binding)),
                    };
                    let (mut config, route_binding) = config;
                    if !workflow_matches_profile(&config, self.capability_profile_filter.as_ref()) {
                        continue;
                    }
                    if !source
                        .claim_task_activation(
                            &activation.message_id,
                            &activation.payload_digest_sha256,
                        )
                        .map_err(|_| HarnessDispatchCycleError::TaskActivationSource)?
                    {
                        report.activation_blockages.push(TaskActivationBlockage {
                            task_id: activation.task.task_id.clone(),
                            dispatch_id: config.dispatch_id.clone(),
                            safe_detail_code: "TASK_ACTIVATION_CLAIM_REJECTED".to_owned(),
                        });
                        continue;
                    }
                    if let Some(preparer) = task_dispatch_material_preparer.as_ref() {
                        let dispatch_id = config.dispatch_id.clone();
                        match preparer.prepare(&activation, config).await {
                            Ok(prepared) => config = prepared,
                            Err(rejection) => {
                                blocked_dispatch_ids.insert(dispatch_id.clone());
                                report.activation_blockages.push(TaskActivationBlockage {
                                    task_id: activation.task.task_id.clone(),
                                    dispatch_id,
                                    safe_detail_code: rejection.safe_detail_code,
                                });
                                continue;
                            }
                        }
                    }
                    reference
                        .bind(activation.task.clone(), &config, *lease_ttl_seconds)
                        .map_err(|_| {
                            HarnessDispatchCycleError::TaskActivationWorkflow(
                                "activation reference binding failed".to_owned(),
                            )
                        })?;
                    let result = super::single_harness_workflow::start_single_harness_workflow_with_route_binding(
                    control,
                    &activation.task,
                    &config,
                    route_binding.as_ref(),
                )
                .map_err(|error| {
                    HarnessDispatchCycleError::TaskActivationWorkflow(error.to_string())
                })?;
                    if let Some(preparer) = task_dispatch_material_preparer.as_ref()
                        && let Err(rejection) = preparer
                            .seal_before_activation_ack(&activation, &config, &result)
                            .await
                    {
                        blocked_dispatch_ids.insert(result.dispatch_id.clone());
                        report.activation_blockages.push(TaskActivationBlockage {
                            task_id: activation.task.task_id.clone(),
                            dispatch_id: result.dispatch_id,
                            safe_detail_code: rejection.safe_detail_code,
                        });
                        continue;
                    }
                    if !source
                        .acknowledge_task_activation(
                            &activation.message_id,
                            &activation.payload_digest_sha256,
                        )
                        .map_err(|_| HarnessDispatchCycleError::TaskActivationSource)?
                    {
                        return Err(HarnessDispatchCycleError::TaskActivationSource);
                    }
                    report.activations_started += 1;
                    report.activations_acknowledged += 1;
                    break;
                }
            }
            let dispatched = dispatch_pending_for_profile(
                control,
                adapter,
                &self.principal,
                self.capability_profile_filter.as_ref(),
                &blocked_dispatch_ids,
            )
            .await?;
            merge_report(&mut report, dispatched);
            remove_terminal_envelopes(active_envelopes, &report);
            Ok(report)
        })
    }
}

fn consume_artifact_returns<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    source: Option<&std::sync::Arc<dyn ArtifactReturnSource>>,
    principal: Option<&AuthenticatedCollaborationPrincipal>,
    step_return_principal: Option<&AuthenticatedCollaborationPrincipal>,
    recovery_findings: &mut Vec<TaskRecoveryFinding>,
) -> Result<u64, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let (Some(source), Some(principal)) = (source, principal) else {
        return Ok(0);
    };
    let mut settlements = 0;
    for pending in source
        .pending_returns()
        .map_err(HarnessDispatchCycleError::ReturnCollector)?
    {
        let lineage = pending.receipt.lineage.as_ref().ok_or_else(|| {
            HarnessDispatchCycleError::ReturnCollector(
                "Artifact return receipt has no lineage".to_owned(),
            )
        })?;
        // A pending return whose dispatch has no terminal output candidate yet
        // is a held observation, not a cycle failure. The outbox read is
        // non-destructive (`delivery_state = 'pending'` stays pending), so the
        // item remains eligible for a later cycle once the candidate exists.
        //
        // Treating it as an error used to abort the whole dispatch cycle and
        // terminate the daemon, which also made the daemon crash-loop on the
        // same parked message at every restart and left already-created Tasks
        // unqueryable. Other returns in this batch still settle normally.
        let Some(candidate) =
            adapter.terminal_output_candidate_for_dispatch(&lineage.dispatch_id)?
        else {
            continue;
        };
        let snapshot = match control.get_collaboration(&lineage.run_id)?.outcome {
            Some(get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
            _ => {
                return Err(HarnessDispatchCycleError::ReturnCollector(
                    "Collaboration snapshot for Artifact return is unavailable".to_owned(),
                ));
            }
        };
        let run = snapshot.run.as_ref().ok_or_else(|| {
            HarnessDispatchCycleError::ReturnCollector(
                "Collaboration run is unavailable".to_owned(),
            )
        })?;
        let step = snapshot
            .steps
            .iter()
            .find(|step| step.step_id == lineage.step_id)
            .ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Collaboration step is unavailable".to_owned(),
                )
            })?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == lineage.attempt_id)
            .ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Collaboration attempt is unavailable".to_owned(),
                )
            })?;
        let technical_return_already_recorded = attempt.status == AttemptStatus::Returned as i32
            && step.status == StepStatus::ReturnPending as i32
            && run.status == RunStatus::ReturnPending as i32;
        if technical_return_already_recorded
            && (step.artifact_set_id.as_deref() != Some(pending.receipt.artifact_set_id.as_str())
                || step.return_handoff_id.as_deref()
                    != Some(pending.receipt.return_handoff_id.as_str()))
        {
            return Err(HarnessDispatchCycleError::ReturnCollector(
                "recorded technical return does not match the Artifact receipt".to_owned(),
            ));
        }
        if !technical_return_already_recorded {
            let cancellation_pending = attempt.status == AttemptStatus::CancellationPending as i32;
            let mut command = CollaborationCommand {
                command: Some(collaboration_command::Command::RecordAttemptReturn(
                    RecordAttemptReturnCommand {
                        base: Some(AttemptCommandBase {
                            meta: Some(CommandMetadata {
                                command_id: format!(
                                    "artifact-return:{}",
                                    pending.receipt.receipt_id
                                ),
                                idempotency_key: pending.receipt.receipt_id.clone(),
                                idempotency_scope: attempt.attempt_id.clone(),
                                request_digest_sha256: String::new(),
                                issued_at: pending.receipt.committed_at,
                                correlation_id: pending.receipt.return_handoff_id.clone(),
                                causation_id: None,
                            }),
                            run_id: run.run_id.clone(),
                            expected_run_revision: run.revision,
                            step_id: step.step_id.clone(),
                            expected_step_revision: step.revision,
                            attempt_id: attempt.attempt_id.clone(),
                            expected_attempt_revision: attempt.revision,
                        }),
                        fencing_token: lineage.fencing_token,
                        harness_sequence: candidate.source_revision,
                        artifact_return_receipt_id: pending.receipt.receipt_id.clone(),
                        receipt_digest_sha256: hex::encode(sha2::Sha256::digest(
                            pending.receipt.encode_to_vec(),
                        )),
                    },
                )),
            };
            if cancellation_pending {
                let Some(collaboration_command::Command::RecordAttemptReturn(value)) =
                    command.command.take()
                else {
                    unreachable!("constructed Artifact return command")
                };
                command.command = Some(
                    collaboration_command::Command::RecordAttemptCancellationOutcome(
                        RecordAttemptCancellationOutcomeCommand {
                            base: value.base,
                            disposition: AttemptCancellationDisposition::ReturnFound as i32,
                            cancellation_receipt_id: pending.receipt.receipt_id.clone(),
                        },
                    ),
                );
            }
            seal_request_digest(&mut command).ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Artifact return command could not be sealed".to_owned(),
                )
            })?;
            let recovery = recovery_principal();
            let result = control.execute(
                &command,
                if cancellation_pending {
                    &recovery
                } else {
                    principal
                },
            )?;
            if result.committed_event.is_none() && !result.replayed {
                let detail = match result.outcome.as_ref() {
                    Some(collaboration_command_result::Outcome::Error(error)) => {
                        format!("{}:{}", error.code, error.safe_detail_code)
                    }
                    _ => "missing collaboration error outcome".to_owned(),
                };
                return Err(HarnessDispatchCycleError::ReturnCollector(format!(
                    "Collaboration rejected Artifact return ({detail})"
                )));
            }
        }

        // The receipt remains in the Artifact outbox until step settlement, so
        // this fact can be derived again after a process restart. Only the Task
        // owner may apply it, and only to CancellationPending on this exact run.
        recovery_findings.push(TaskRecoveryFinding {
            kind: TaskRecoveryKind::CancellationReturnFound,
            task_id: run.task_id.clone(),
            run_id: run.run_id.clone(),
            evidence_ref: pending.receipt.receipt_id.clone(),
        });

        let Some(step_return_principal) = step_return_principal else {
            if !source
                .acknowledge_return(&pending.message_id, &pending.payload_digest_sha256)
                .map_err(HarnessDispatchCycleError::ReturnCollector)?
            {
                return Err(HarnessDispatchCycleError::ReturnCollector(
                    "Artifact return outbox acknowledgement was not persisted".to_owned(),
                ));
            }
            continue;
        };

        let snapshot = match control.get_collaboration(&lineage.run_id)?.outcome {
            Some(get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
            _ => {
                return Err(HarnessDispatchCycleError::ReturnCollector(
                    "Collaboration snapshot after Artifact return is unavailable".to_owned(),
                ));
            }
        };
        let run = snapshot.run.as_ref().ok_or_else(|| {
            HarnessDispatchCycleError::ReturnCollector(
                "Collaboration run after Artifact return is unavailable".to_owned(),
            )
        })?;
        let step = snapshot
            .steps
            .iter()
            .find(|step| step.step_id == lineage.step_id)
            .ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Collaboration step after Artifact return is unavailable".to_owned(),
                )
            })?;
        let mut step_command = CollaborationCommand {
            command: Some(collaboration_command::Command::CommitStepReturn(
                CommitStepReturnCommand {
                    base: Some(RunCommandBase {
                        meta: Some(CommandMetadata {
                            command_id: format!("step-return:{}", pending.receipt.receipt_id),
                            idempotency_key: format!("{}:step-return", pending.receipt.receipt_id),
                            idempotency_scope: run.run_id.clone(),
                            request_digest_sha256: String::new(),
                            issued_at: pending.receipt.committed_at,
                            correlation_id: pending.receipt.return_handoff_id.clone(),
                            causation_id: Some(pending.receipt.receipt_id.clone()),
                        }),
                        run_id: run.run_id.clone(),
                        expected_run_revision: run.revision,
                    }),
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: lineage.attempt_id.clone(),
                    artifact_set_id: pending.receipt.artifact_set_id.clone(),
                    return_handoff_id: pending.receipt.return_handoff_id.clone(),
                },
            )),
        };
        seal_request_digest(&mut step_command).ok_or_else(|| {
            HarnessDispatchCycleError::ReturnCollector(
                "Collaboration Step return command could not be sealed".to_owned(),
            )
        })?;
        let step_result = control.execute(&step_command, step_return_principal)?;
        if step_result.committed_event.is_none() && !step_result.replayed {
            let verification_pending = matches!(
                step_result.outcome.as_ref(),
                Some(collaboration_command_result::Outcome::Error(error))
                    if error.code
                        == egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationErrorCode::RecoveryRequired as i32
            );
            if verification_pending {
                continue;
            }
            return Err(HarnessDispatchCycleError::ReturnCollector(format!(
                "Collaboration rejected Verification-gated Step return ({})",
                match step_result.outcome.as_ref() {
                    Some(collaboration_command_result::Outcome::Error(error)) => {
                        format!("{}:{}", error.code, error.safe_detail_code)
                    }
                    _ => "missing collaboration error outcome".to_owned(),
                }
            )));
        }
        if !source
            .acknowledge_return(&pending.message_id, &pending.payload_digest_sha256)
            .map_err(HarnessDispatchCycleError::ReturnCollector)?
        {
            return Err(HarnessDispatchCycleError::ReturnCollector(
                "Artifact return outbox acknowledgement was not persisted".to_owned(),
            ));
        }
        settlements += 1;
    }
    Ok(settlements)
}

/// Delivers all currently pending Collaboration dispatch intents to one
/// provider-neutral Harness Adapter and ingests the resulting receipt plus
/// durable observations back into Collaboration Control.
///
/// The function deliberately has no model-selection behavior. It operates on
/// the already-authorized dispatch envelope and therefore cannot bypass lease,
/// fencing, evidence verification, or Authority ownership.
pub async fn dispatch_pending<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    principal: &AuthenticatedCollaborationPrincipal,
) -> Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    dispatch_pending_for_profile(control, adapter, principal, None, &BTreeSet::new()).await
}

async fn recover_held_dispatches<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    harness_principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
    report: &mut HarnessDispatchCycleReport,
) -> Result<(), HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let recovery_principal = recovery_principal();
    let held = control
        .held_dispatches_for_recovery(&recovery_principal)?
        .into_iter()
        .filter(|candidate| {
            envelope_matches_profile(&candidate.envelope, capability_profile_filter)
        })
        .collect::<Vec<_>>();
    for candidate in held {
        if !report
            .held_dispatch_ids
            .contains(&candidate.envelope.dispatch_id)
        {
            report
                .held_dispatch_ids
                .push(candidate.envelope.dispatch_id.clone());
        }
        let barrier = drain_durable_normal_observations(
            control,
            adapter,
            &candidate.envelope,
            harness_principal,
            report,
        )?;
        let mut current_matches = control
            .held_dispatches_for_recovery(&recovery_principal)?
            .into_iter()
            .filter(|item| item.envelope.dispatch_id == candidate.envelope.dispatch_id);
        let Some(current) = current_matches.next() else {
            report
                .held_dispatch_ids
                .retain(|dispatch_id| dispatch_id != &candidate.envelope.dispatch_id);
            continue;
        };
        if current_matches.next().is_some()
            || current.message_id != candidate.message_id
            || current.source_event_id != candidate.source_event_id
            || current.canonical_payload_digest_sha256 != candidate.canonical_payload_digest_sha256
            || current.envelope != candidate.envelope
        {
            return Err(HarnessDispatchCycleError::Recovery(
                "held dispatch recovery candidate drifted during durable replay".to_owned(),
            ));
        }
        if barrier != DurableReplayBarrier::Clear {
            record_task_recovery_finding_if_still_held(control, &candidate.envelope, report)?;
            continue;
        }
        if current.state == HeldDispatchRecoveryState::CancellationPending
            && adapter.has_resident_dispatch(&candidate.envelope.dispatch_id)
        {
            // Only the Adapter which actually sent this dispatch still owns
            // its live output stream. Cancellation stops further dispatches,
            // not reads of the eventual native interruption or sealed return.
            // A reopened Adapter stays drain-only until durable evidence exists.
            adapter.verify_delivered_recovery_candidate(&candidate.envelope)?;
            if adapter.pump_one(&candidate.envelope).await?.is_some() {
                drain_durable_normal_observations(
                    control,
                    adapter,
                    &candidate.envelope,
                    harness_principal,
                    report,
                )?;
            }
            record_task_recovery_finding_if_still_held(control, &candidate.envelope, report)?;
            continue;
        }
        let mut durable_evidence = None;
        match current.state {
            HeldDispatchRecoveryState::OutcomeUnknown => {
                let reconciliation_id = stable_reconciliation_id(&candidate.envelope.dispatch_id);
                let snapshot = collaboration_snapshot(control, &candidate.envelope.run_id)?;
                let mut begin = CollaborationCommand {
                    command: Some(collaboration_command::Command::BeginAttemptReconciliation(
                        BeginAttemptReconciliationCommand {
                            base: Some(recovery_attempt_base(
                                &snapshot,
                                &candidate.envelope.attempt_id,
                                &reconciliation_id,
                                "begin",
                            )?),
                            reconciliation_id: reconciliation_id.clone(),
                        },
                    )),
                };
                seal_request_digest(&mut begin).ok_or_else(|| {
                    HarnessDispatchCycleError::Recovery(
                        "reconciliation begin command could not be sealed".to_owned(),
                    )
                })?;
                require_recovery_commit(control.execute(&begin, &recovery_principal)?, "begin")?;
                durable_evidence = Some(
                    adapter
                        .reconcile_dispatch(&reconciliation_id, &candidate.envelope.dispatch_id)
                        .await?,
                );
            }
            HeldDispatchRecoveryState::Reconciling { reconciliation_id } => {
                durable_evidence = adapter
                    .reconciliation_evidence(&reconciliation_id, &candidate.envelope.dispatch_id)?;
            }
            HeldDispatchRecoveryState::Held | HeldDispatchRecoveryState::CancellationPending => {}
        }

        if let Some(evidence) = durable_evidence.as_ref() {
            let disposition = match evidence.finding {
                ReconciliationFinding::NoEffectProven { .. } => {
                    ReconciliationDisposition::NoEffectProven
                }
                ReconciliationFinding::NativeExecutionActive { .. }
                | ReconciliationFinding::TerminalObservationRecovered { .. }
                | ReconciliationFinding::OutcomeUnknown { .. } => {
                    ReconciliationDisposition::ManualOnly
                }
            };
            let snapshot = collaboration_snapshot(control, &candidate.envelope.run_id)?;
            let mut record = CollaborationCommand {
                command: Some(collaboration_command::Command::RecordAttemptReconciliation(
                    RecordAttemptReconciliationCommand {
                        base: Some(recovery_attempt_base(
                            &snapshot,
                            &candidate.envelope.attempt_id,
                            &evidence.reconciliation_id,
                            "record",
                        )?),
                        reconciliation_id: evidence.reconciliation_id.clone(),
                        disposition: disposition as i32,
                        evidence_id: evidence.evidence_id.clone(),
                    },
                )),
            };
            seal_request_digest(&mut record).ok_or_else(|| {
                HarnessDispatchCycleError::Recovery(
                    "reconciliation record command could not be sealed".to_owned(),
                )
            })?;
            require_recovery_commit(control.execute(&record, &recovery_principal)?, "record")?;
        }

        record_task_recovery_finding_if_still_held(control, &candidate.envelope, report)?;
    }
    Ok(())
}

fn record_settled_cancellation_findings<G, C>(
    control: &CollaborationControl<G, C>,
    profile_filter: Option<&CapabilityProfileFilter>,
    report: &mut HarnessDispatchCycleReport,
) -> Result<(), HarnessDispatchCycleError> {
    for (finding, profile) in control.settled_cancellation_findings()? {
        let matches_profile = profile_filter.is_none_or(|filter| match filter {
            CapabilityProfileFilter::Exact(expected) => &profile == expected,
        });
        if matches_profile && !report.task_recovery_findings.contains(&finding) {
            report.task_recovery_findings.push(finding);
        }
    }
    Ok(())
}

fn record_task_recovery_finding_if_still_held<G, C>(
    control: &CollaborationControl<G, C>,
    envelope: &DispatchEnvelope,
    report: &mut HarnessDispatchCycleReport,
) -> Result<(), HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    let snapshot = collaboration_snapshot(control, &envelope.run_id)?;
    if snapshot
        .run
        .as_ref()
        .is_some_and(|run| run.status == RunStatus::Held as i32)
    {
        let run = snapshot.run.as_ref().expect("checked held run");
        let finding = TaskRecoveryFinding {
            kind: TaskRecoveryKind::OutcomeUnknown,
            task_id: run.task_id.clone(),
            run_id: run.run_id.clone(),
            evidence_ref: format!("collaboration-held-dispatch:{}", envelope.dispatch_id),
        };
        if !report.task_recovery_findings.contains(&finding) {
            report.task_recovery_findings.push(finding);
        }
    }
    Ok(())
}

fn recovery_principal() -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind: CollaborationPrincipalKind::RecoveryWorker,
        principal_id: "collaboration-control:harness-reconciliation".to_owned(),
        authenticated: true,
    }
}

fn stable_reconciliation_id(dispatch_id: &str) -> String {
    format!("adapter-reconciliation:{dispatch_id}")
}

fn collaboration_snapshot<G, C>(
    control: &CollaborationControl<G, C>,
    run_id: &str,
) -> Result<CollaborationSnapshot, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    match control.get_collaboration(run_id)?.outcome {
        Some(get_collaboration_response::Outcome::Snapshot(snapshot)) => Ok(snapshot),
        _ => Err(CollaborationControlError::Persistence.into()),
    }
}

fn recovery_attempt_base(
    snapshot: &CollaborationSnapshot,
    attempt_id: &str,
    reconciliation_id: &str,
    phase: &str,
) -> Result<AttemptCommandBase, HarnessDispatchCycleError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(CollaborationControlError::Persistence)?;
    let attempt = snapshot
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == attempt_id)
        .ok_or(CollaborationControlError::Persistence)?;
    let step = snapshot
        .steps
        .iter()
        .find(|step| step.step_id == attempt.step_id)
        .ok_or(CollaborationControlError::Persistence)?;
    Ok(AttemptCommandBase {
        meta: Some(CommandMetadata {
            command_id: format!("harness-recovery:{phase}:{reconciliation_id}"),
            idempotency_key: format!("{phase}:{reconciliation_id}"),
            idempotency_scope: attempt.attempt_id.clone(),
            request_digest_sha256: String::new(),
            issued_at: attempt.updated_at.or(run.updated_at),
            correlation_id: reconciliation_id.to_owned(),
            causation_id: attempt.dispatch_id.clone(),
        }),
        run_id: run.run_id.clone(),
        expected_run_revision: run.revision,
        step_id: step.step_id.clone(),
        expected_step_revision: step.revision,
        attempt_id: attempt.attempt_id.clone(),
        expected_attempt_revision: attempt.revision,
    })
}

fn require_recovery_commit(
    result: egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationCommandResult,
    phase: &str,
) -> Result<(), HarnessDispatchCycleError> {
    if result.committed_event.is_some() || result.replayed {
        return Ok(());
    }
    let detail = match result.outcome {
        Some(collaboration_command_result::Outcome::Error(error)) => error.safe_detail_code,
        _ => "COLLABORATION_RECOVERY_RESULT_MISSING".to_owned(),
    };
    Err(HarnessDispatchCycleError::Recovery(format!(
        "{phase} rejected: {detail}"
    )))
}

async fn dispatch_pending_for_profile<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
    blocked_dispatch_ids: &BTreeSet<String>,
) -> Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let pending = control
        .pending_dispatches(principal)?
        .into_iter()
        .filter(|dispatch| envelope_matches_profile(&dispatch.envelope, capability_profile_filter))
        .filter(|dispatch| !blocked_dispatch_ids.contains(&dispatch.envelope.dispatch_id))
        .collect::<Vec<_>>();
    let mut report = HarnessDispatchCycleReport {
        dispatches_seen: pending.len() as u64,
        ..HarnessDispatchCycleReport::default()
    };
    for dispatch in pending {
        // A durable Adapter receipt means dispatch() will take its exact replay
        // path and will not call the native driver. This must remain available
        // while the driver is busy so a lost Collaboration ingestion ACK can
        // converge. Only a genuinely new native send waits for readiness.
        let stored_receipt = adapter.stored_dispatch_receipt(&dispatch.envelope.dispatch_id)?;
        let collaboration = control.get_collaboration(&dispatch.envelope.run_id)?;
        let snapshot = match collaboration.outcome {
            Some(get_collaboration_response::Outcome::Snapshot(snapshot)) => snapshot,
            _ => return Err(CollaborationControlError::Persistence.into()),
        };
        let run = snapshot
            .run
            .as_ref()
            .filter(|run| run.run_id == dispatch.envelope.run_id)
            .ok_or(CollaborationControlError::Persistence)?;
        if stored_receipt.is_none() {
            if let Err(safe_detail_code) = validate_pending_dispatch_for_send(
                &snapshot,
                &dispatch.envelope,
                &control.current_timestamp(),
            ) {
                report.activation_blockages.push(TaskActivationBlockage {
                    task_id: run.task_id.clone(),
                    dispatch_id: dispatch.envelope.dispatch_id.clone(),
                    safe_detail_code: safe_detail_code.to_owned(),
                });
                record_pending_dispatch_recovery_finding(
                    &snapshot,
                    &dispatch.envelope,
                    safe_detail_code,
                    &mut report,
                );
                continue;
            }
            if !adapter.is_dispatch_ready() {
                continue;
            }
        }
        let result = adapter.dispatch(&dispatch.envelope).await?;
        let Some(outcome) = result.outcome else {
            report.dispatches_rejected += 1;
            continue;
        };
        let dispatch_result::Outcome::Receipt(receipt) = outcome else {
            report.dispatches_rejected += 1;
            continue;
        };
        // Adapter dispatch durably creates the envelope row. Bind the
        // Collaboration-owned task lineage immediately afterwards and before
        // any terminal observation can be pumped into the return outbox.
        adapter.bind_dispatch_task_lineage(
            &dispatch.envelope.dispatch_id,
            &run.task_id,
            run.task_revision_at_creation,
            run.work_revision,
        )?;
        let ingested = control.ingest_dispatch_receipt(&receipt, principal)?;
        if receipt.disposition == DeliveryDisposition::Delivered as i32 {
            report.dispatches_delivered += 1;
        } else {
            report.dispatches_rejected += 1;
        }
        let _ = record_ingestion(&mut report, adapter, None, ingested)?;
        match DeliveryDisposition::try_from(receipt.disposition) {
            Ok(DeliveryDisposition::Delivered) => {}
            Ok(DeliveryDisposition::Unknown) => {
                if !report
                    .held_dispatch_ids
                    .contains(&dispatch.envelope.dispatch_id)
                {
                    report
                        .held_dispatch_ids
                        .push(dispatch.envelope.dispatch_id.clone());
                }
                continue;
            }
            _ => continue,
        }
    }
    Ok(report)
}

fn pending_dispatch_reserves_capacity<G, C, R, D, A>(
    control: &CollaborationControl<G, C>,
    adapter: &GovernedHarnessAdapter<R, D, A>,
    pending: &[DispatchEnvelope],
) -> Result<bool, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let now = control.current_timestamp();
    for envelope in pending {
        if adapter
            .stored_dispatch_receipt(&envelope.dispatch_id)?
            .is_some()
        {
            return Ok(true);
        }
        let snapshot = collaboration_snapshot(control, &envelope.run_id)?;
        if validate_pending_dispatch_for_send(&snapshot, envelope, &now).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn record_pending_dispatch_recovery_finding(
    snapshot: &CollaborationSnapshot,
    envelope: &DispatchEnvelope,
    safe_detail_code: &str,
    report: &mut HarnessDispatchCycleReport,
) {
    let Some(run) = snapshot
        .run
        .as_ref()
        .filter(|run| run.run_id == envelope.run_id)
    else {
        return;
    };
    let finding = TaskRecoveryFinding {
        kind: TaskRecoveryKind::OutcomeUnknown,
        task_id: run.task_id.clone(),
        run_id: run.run_id.clone(),
        evidence_ref: format!(
            "collaboration-pending-dispatch:{}:{safe_detail_code}",
            envelope.dispatch_id
        ),
    };
    if !report.task_recovery_findings.contains(&finding) {
        report.task_recovery_findings.push(finding);
    }
}

fn validate_pending_dispatch_for_send(
    snapshot: &CollaborationSnapshot,
    envelope: &DispatchEnvelope,
    now: &prost_types::Timestamp,
) -> Result<(), &'static str> {
    let step = snapshot
        .steps
        .iter()
        .find(|step| step.step_id == envelope.step_id)
        .ok_or("DISPATCH_PENDING_BINDING_STALE")?;
    let attempt = snapshot
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == envelope.attempt_id)
        .ok_or("DISPATCH_PENDING_BINDING_STALE")?;
    let lease = attempt
        .lease
        .as_ref()
        .ok_or("DISPATCH_PENDING_BINDING_STALE")?;
    if step.current_attempt_id.as_deref() != Some(envelope.attempt_id.as_str())
        || attempt.step_id != envelope.step_id
        || attempt.status != AttemptStatus::DispatchPending as i32
        || attempt.revision != envelope.attempt_revision
        || attempt.dispatch_id.as_deref() != Some(envelope.dispatch_id.as_str())
        || attempt.dispatch_fingerprint.as_deref() != Some(envelope.dispatch_fingerprint.as_str())
        || lease.fencing_token != envelope.fencing_token
    {
        return Err("DISPATCH_PENDING_BINDING_STALE");
    }
    let expires_at = lease
        .expires_at
        .as_ref()
        .ok_or("DISPATCH_PENDING_LEASE_EXPIRED")?;
    if (expires_at.seconds, expires_at.nanos) <= (now.seconds, now.nanos) {
        return Err("DISPATCH_PENDING_LEASE_EXPIRED");
    }
    Ok(())
}

/// Replays durable normal observations before polling one immutable dispatch.
/// Every native poll is gated by both the Adapter delivery receipt and the
/// current Collaboration delivered candidate.
pub async fn pump_observations<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    envelope: &DispatchEnvelope,
    principal: &AuthenticatedCollaborationPrincipal,
) -> Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let mut report = HarnessDispatchCycleReport::default();
    let barrier =
        drain_durable_normal_observations(control, adapter, envelope, principal, &mut report)?;
    if barrier != DurableReplayBarrier::Clear {
        return Ok(report);
    }
    adapter.verify_delivered_recovery_candidate(envelope)?;
    let Some(delivered) = current_delivered_candidate(control, principal, &envelope.dispatch_id)?
    else {
        return Ok(report);
    };
    if delivered.envelope != *envelope {
        return Err(HarnessDispatchCycleError::Recovery(
            "public observation pump envelope drifted from Collaboration candidate".to_owned(),
        ));
    }
    while let ActivePumpStep::DurableEventAppended =
        pump_active_step(control, adapter, &delivered, principal, &mut report).await?
    {}
    Ok(report)
}

fn register_delivered_envelopes<G, C, R, D, A>(
    control: &CollaborationControl<G, C>,
    adapter: &GovernedHarnessAdapter<R, D, A>,
    active_envelopes: &mut Vec<DispatchEnvelope>,
    principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> Result<Vec<DeliveredDispatchForObservation>, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let mut registered = Vec::new();
    for delivered in control
        .delivered_dispatches_for_observation(principal)?
        .into_iter()
        .filter(|dispatch| envelope_matches_profile(&dispatch.envelope, capability_profile_filter))
    {
        if registered
            .iter()
            .any(|item: &DeliveredDispatchForObservation| {
                item.envelope.dispatch_id == delivered.envelope.dispatch_id
            })
        {
            return Err(HarnessDispatchCycleError::Recovery(
                "duplicate Collaboration delivered dispatch candidate".to_owned(),
            ));
        }
        adapter.verify_delivered_recovery_candidate(&delivered.envelope)?;
        let mut active_matches = active_envelopes
            .iter()
            .filter(|item| item.dispatch_id == delivered.envelope.dispatch_id);
        if let Some(existing) = active_matches.next() {
            if active_matches.next().is_some() {
                return Err(HarnessDispatchCycleError::Recovery(
                    "duplicate active dispatch identity".to_owned(),
                ));
            }
            if existing != &delivered.envelope {
                return Err(HarnessDispatchCycleError::Recovery(
                    "active dispatch envelope drifted from delivered recovery candidate".to_owned(),
                ));
            }
        } else {
            active_envelopes.push(delivered.envelope.clone());
        }
        registered.push(delivered);
    }
    Ok(registered)
}

fn register_pending_envelopes<G, C>(
    control: &CollaborationControl<G, C>,
    active_envelopes: &mut Vec<DispatchEnvelope>,
    principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> Result<Vec<DispatchEnvelope>, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    let mut registered = Vec::new();
    for pending in control
        .pending_dispatches(principal)?
        .into_iter()
        .filter(|dispatch| envelope_matches_profile(&dispatch.envelope, capability_profile_filter))
    {
        if registered
            .iter()
            .any(|item: &DispatchEnvelope| item.dispatch_id == pending.envelope.dispatch_id)
        {
            return Err(HarnessDispatchCycleError::Recovery(
                "duplicate Collaboration pending dispatch candidate".to_owned(),
            ));
        }
        let mut active_matches = active_envelopes
            .iter()
            .filter(|item| item.dispatch_id == pending.envelope.dispatch_id);
        if let Some(existing) = active_matches.next() {
            if active_matches.next().is_some() {
                return Err(HarnessDispatchCycleError::Recovery(
                    "duplicate active dispatch identity".to_owned(),
                ));
            }
            if existing != &pending.envelope {
                return Err(HarnessDispatchCycleError::Recovery(
                    "active dispatch envelope drifted from pending intent".to_owned(),
                ));
            }
        } else {
            active_envelopes.push(pending.envelope.clone());
        }
        registered.push(pending.envelope);
    }
    Ok(registered)
}

fn envelope_matches_profile(
    envelope: &DispatchEnvelope,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> bool {
    capability_profile_filter.is_none_or(|filter| {
        envelope
            .capability_profile_ref
            .as_ref()
            .is_some_and(|reference| match filter {
                CapabilityProfileFilter::Exact(expected) => reference == expected,
            })
    })
}

fn workflow_matches_profile(
    config: &SingleHarnessWorkConfig,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> bool {
    capability_profile_filter.is_none_or(|filter| match filter {
        CapabilityProfileFilter::Exact(expected) => &config.capability_profile_ref == expected,
    })
}

async fn pump_active_envelopes<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    active_envelopes: &mut Vec<DispatchEnvelope>,
    delivered_dispatches: &[DeliveredDispatchForObservation],
    pending_envelopes: &[DispatchEnvelope],
    principal: &AuthenticatedCollaborationPrincipal,
    report: &mut HarnessDispatchCycleReport,
) -> Result<(), HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let envelopes = std::mem::take(active_envelopes);
    for (index, envelope) in envelopes.iter().enumerate() {
        if envelopes[index + 1..]
            .iter()
            .any(|other| other.dispatch_id == envelope.dispatch_id)
        {
            return Err(HarnessDispatchCycleError::Recovery(
                "duplicate active dispatch identity".to_owned(),
            ));
        }
    }
    for envelope in envelopes {
        if report.held_dispatch_ids.contains(&envelope.dispatch_id) {
            continue;
        }
        let Some(delivered) = delivered_dispatches
            .iter()
            .find(|candidate| candidate.envelope.dispatch_id == envelope.dispatch_id)
        else {
            if let Some(pending) = pending_envelopes
                .iter()
                .find(|candidate| candidate.dispatch_id == envelope.dispatch_id)
            {
                if pending != &envelope {
                    return Err(HarnessDispatchCycleError::Recovery(
                        "pending dispatch changed before active classification".to_owned(),
                    ));
                }
                active_envelopes.push(envelope);
            }
            continue;
        };
        if pending_envelopes
            .iter()
            .any(|candidate| candidate.dispatch_id == envelope.dispatch_id)
        {
            return Err(HarnessDispatchCycleError::Recovery(
                "dispatch appeared in both delivered and pending snapshots".to_owned(),
            ));
        }
        if delivered.envelope != envelope {
            return Err(HarnessDispatchCycleError::Recovery(
                "registered delivered dispatch changed before active polling".to_owned(),
            ));
        }
        loop {
            match pump_active_step(control, adapter, delivered, principal, report).await? {
                ActivePumpStep::DurableEventAppended => continue,
                ActivePumpStep::Idle
                | ActivePumpStep::Blocked(DurableReplayBarrier::PendingBlocked) => {
                    active_envelopes.push(envelope);
                    break;
                }
                ActivePumpStep::Held => break,
                ActivePumpStep::Retire
                | ActivePumpStep::Blocked(DurableReplayBarrier::Terminal) => break,
                ActivePumpStep::Blocked(DurableReplayBarrier::Clear) => {
                    return Err(HarnessDispatchCycleError::Recovery(
                        "clear durable replay barrier cannot block active polling".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn pump_active_step<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    delivered: &DeliveredDispatchForObservation,
    principal: &AuthenticatedCollaborationPrincipal,
    report: &mut HarnessDispatchCycleReport,
) -> Result<ActivePumpStep, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let envelope = &delivered.envelope;
    let barrier = drain_durable_normal_observations(control, adapter, envelope, principal, report)?;
    match barrier {
        DurableReplayBarrier::Clear => {}
        DurableReplayBarrier::PendingBlocked | DurableReplayBarrier::Terminal => {
            return Ok(ActivePumpStep::Blocked(barrier));
        }
    }

    adapter.verify_delivered_recovery_candidate(envelope)?;
    let Some(current) = current_delivered_candidate(control, principal, &envelope.dispatch_id)?
    else {
        return Ok(ActivePumpStep::Retire);
    };
    if current != *delivered {
        return Err(HarnessDispatchCycleError::Recovery(
            "Collaboration delivered dispatch identity drifted during polling".to_owned(),
        ));
    }

    if !adapter.has_resident_dispatch(&envelope.dispatch_id) {
        hold_nonresident_delivered_dispatch(control, adapter, delivered, report)?;
        return Ok(ActivePumpStep::Held);
    }

    let Some(observation) = adapter.pump_one(envelope).await? else {
        return Ok(ActivePumpStep::Idle);
    };
    let view = adapter.normal_observation_recovery_view(&envelope.dispatch_id)?;
    if view
        .pending
        .iter()
        .any(|pending| pending.observation_id == observation.observation_id)
    {
        Ok(ActivePumpStep::DurableEventAppended)
    } else if view.durable_terminal_sequence.is_some() {
        Ok(ActivePumpStep::Blocked(DurableReplayBarrier::Terminal))
    } else {
        // The Adapter replayed an already-consumed durable observation. Do not
        // spin on the native key in this cycle.
        Ok(ActivePumpStep::Idle)
    }
}

fn hold_nonresident_delivered_dispatch<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &GovernedHarnessAdapter<R, D, A>,
    delivered: &DeliveredDispatchForObservation,
    report: &mut HarnessDispatchCycleReport,
) -> Result<(), HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let envelope = &delivered.envelope;
    adapter.verify_delivered_recovery_candidate(envelope)?;
    if adapter.has_resident_dispatch(&envelope.dispatch_id) {
        return Err(HarnessDispatchCycleError::Recovery(
            "nonresident recovery candidate became resident".to_owned(),
        ));
    }
    let receipt = adapter
        .edge()
        .delivered_dispatch_receipt(&envelope.dispatch_id)
        .map_err(GovernedAdapterError::from)?
        .ok_or_else(|| {
            HarnessDispatchCycleError::Recovery(
                "nonresident recovery delivery receipt is missing".to_owned(),
            )
        })?;
    let _nonresident_observation = adapter.observe_nonresident_dispatch(&envelope.dispatch_id)?;
    let snapshot = collaboration_snapshot(control, &envelope.run_id)?;
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::MarkAttemptOutcomeUnknown(
            MarkAttemptOutcomeUnknownCommand {
                base: Some(recovery_attempt_base(
                    &snapshot,
                    &envelope.attempt_id,
                    &receipt.receipt_id,
                    "native-session-not-resident",
                )?),
                reason_code: NATIVE_DISPATCH_SESSION_NOT_RESIDENT_REASON_CODE.to_owned(),
                uncertainty_evidence_id: receipt.receipt_id,
            },
        )),
    };
    seal_request_digest(&mut command).ok_or_else(|| {
        HarnessDispatchCycleError::Recovery(
            "nonresident recovery command could not be sealed".to_owned(),
        )
    })?;
    require_recovery_commit(
        control.execute(&command, &recovery_principal())?,
        "native-session-not-resident",
    )?;
    if !report.held_dispatch_ids.contains(&envelope.dispatch_id) {
        report.held_dispatch_ids.push(envelope.dispatch_id.clone());
    }
    record_task_recovery_finding_if_still_held(control, envelope, report)
}

fn current_delivered_candidate<G, C>(
    control: &CollaborationControl<G, C>,
    principal: &AuthenticatedCollaborationPrincipal,
    dispatch_id: &str,
) -> Result<Option<DeliveredDispatchForObservation>, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    let mut matches = control
        .delivered_dispatches_for_observation(principal)?
        .into_iter()
        .filter(|candidate| candidate.envelope.dispatch_id == dispatch_id);
    let Some(candidate) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(HarnessDispatchCycleError::Recovery(
            "duplicate Collaboration delivered dispatch identity".to_owned(),
        ));
    }
    Ok(Some(candidate))
}

fn drain_durable_normal_observations<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    envelope: &DispatchEnvelope,
    principal: &AuthenticatedCollaborationPrincipal,
    report: &mut HarnessDispatchCycleReport,
) -> Result<DurableReplayBarrier, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let view = adapter.normal_observation_recovery_view(&envelope.dispatch_id)?;
    let mut pending_blocked = false;
    for observation in view.pending {
        if view
            .durable_terminal_sequence
            .is_some_and(|terminal| observation.observation_sequence > terminal)
        {
            break;
        }
        let terminal = observation.criticality == ObservationCriticality::Terminal as i32;
        report.observations_seen += 1;
        let ingested = control.ingest_harness_observation(&observation, principal)?;
        if legacy_execution_start_requires_recovery(&observation, &ingested) {
            let settlement =
                settle_legacy_execution_start(control, adapter, envelope, &observation, report)?;
            if settlement == ObservationSettlement::PendingBlocked {
                pending_blocked = true;
            }
            if pending_blocked || report.held_dispatch_ids.contains(&envelope.dispatch_id) {
                break;
            }
            continue;
        }
        let stop_after_settlement = matches!(
            &ingested.disposition,
            HarnessFactIngestionDisposition::DeferredToArtifactAuthority
                | HarnessFactIngestionDisposition::RetainedForDependency
        );
        let settlement = record_ingestion(report, adapter, Some(&observation), ingested)?;
        if settlement == ObservationSettlement::PendingBlocked {
            pending_blocked = true;
        }
        if terminal || stop_after_settlement || pending_blocked {
            break;
        }
    }

    let current = adapter.normal_observation_recovery_view(&envelope.dispatch_id)?;
    if current.durable_terminal_sequence.is_some() {
        Ok(DurableReplayBarrier::Terminal)
    } else if pending_blocked || !current.pending.is_empty() {
        Ok(DurableReplayBarrier::PendingBlocked)
    } else {
        Ok(DurableReplayBarrier::Clear)
    }
}

fn legacy_execution_start_requires_recovery(
    observation: &HarnessObservation,
    result: &HarnessFactIngestionResult,
) -> bool {
    let is_execution_started = matches!(
        observation.payload.as_ref(),
        Some(harness_observation::Payload::Lifecycle(lifecycle))
            if lifecycle.kind == LifecycleKind::ExecutionStarted as i32
    );
    let is_ack_required = matches!(
        result
            .authority_result
            .as_ref()
            .and_then(|result| result.outcome.as_ref()),
        Some(collaboration_command_result::Outcome::Error(error))
            if CollaborationErrorCode::try_from(error.code)
                == Ok(CollaborationErrorCode::StateConflict)
                && error.safe_detail_code == "HARNESS_ACK_REQUIRED"
    );
    is_execution_started && is_ack_required
}

fn settle_legacy_execution_start<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    envelope: &DispatchEnvelope,
    observation: &HarnessObservation,
    report: &mut HarnessDispatchCycleReport,
) -> Result<ObservationSettlement, HarnessDispatchCycleError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let snapshot = collaboration_snapshot(control, &envelope.run_id)?;
    let current_attempt = snapshot
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == envelope.attempt_id);
    let Some(current_attempt) = current_attempt else {
        adapter.quarantine_observation(
            &observation.observation_id,
            "LEGACY_EXECUTION_START_OWNER_MISMATCH",
        )?;
        report.observations_quarantined += 1;
        return Ok(ObservationSettlement::Settled);
    };
    let current_fence = current_attempt
        .lease
        .as_ref()
        .map(|lease| lease.fencing_token);
    if AttemptStatus::try_from(current_attempt.status) != Ok(AttemptStatus::Running)
        || current_attempt.dispatch_id.as_deref() != Some(envelope.dispatch_id.as_str())
        || current_fence != Some(envelope.fencing_token)
        || observation.attempt_id != current_attempt.attempt_id
        || observation.dispatch_id != envelope.dispatch_id
        || observation.fencing_token != envelope.fencing_token
        || observation.observation_sequence <= current_attempt.last_harness_sequence
    {
        adapter.quarantine_observation(
            &observation.observation_id,
            "LEGACY_EXECUTION_START_OWNER_MISMATCH",
        )?;
        report.observations_quarantined += 1;
        return Ok(ObservationSettlement::Settled);
    }

    let recovery = adapter.classify_legacy_execution_start(
        envelope,
        &observation.observation_id,
        current_attempt.last_harness_sequence,
    )?;
    match recovery {
        LegacyExecutionStartRecovery::Unsupported => {
            report.observations_retained += 1;
            Ok(ObservationSettlement::PendingBlocked)
        }
        LegacyExecutionStartRecovery::OwnerMismatch => {
            adapter.quarantine_observation(
                &observation.observation_id,
                "LEGACY_EXECUTION_START_OWNER_MISMATCH",
            )?;
            report.observations_quarantined += 1;
            Ok(ObservationSettlement::Settled)
        }
        LegacyExecutionStartRecovery::Unverified { reason_code } => {
            let held = control.mark_legacy_execution_start_outcome_unknown(observation)?;
            require_recovery_commit(held.clone(), "legacy execution start hold")?;
            record_task_recovery_finding(
                report,
                observation,
                &HarnessFactIngestionResult {
                    disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                        reason_code: reason_code.to_owned(),
                    },
                    authority_result: Some(held),
                },
            );
            adapter.quarantine_observation(&observation.observation_id, reason_code)?;
            report.observations_quarantined += 1;
            if !report.held_dispatch_ids.contains(&envelope.dispatch_id) {
                report.held_dispatch_ids.push(envelope.dispatch_id.clone());
            }
            Ok(ObservationSettlement::Settled)
        }
        LegacyExecutionStartRecovery::ExactDuplicate(evidence) => {
            if !evidence.durable_terminal_handoff {
                let held = control.mark_legacy_execution_start_outcome_unknown(observation)?;
                require_recovery_commit(held.clone(), "legacy execution start hold")?;
                record_task_recovery_finding(
                    report,
                    observation,
                    &HarnessFactIngestionResult {
                        disposition: HarnessFactIngestionDisposition::Consumed,
                        authority_result: Some(held),
                    },
                );
                if !report.held_dispatch_ids.contains(&envelope.dispatch_id) {
                    report.held_dispatch_ids.push(envelope.dispatch_id.clone());
                }
            }
            if !adapter.consume_legacy_execution_start_duplicate(&evidence)? {
                return Err(HarnessDispatchCycleError::Recovery(
                    "legacy execution start duplicate acknowledgement was not persisted".to_owned(),
                ));
            }
            report.observations_consumed += 1;
            Ok(ObservationSettlement::Settled)
        }
    }
}

fn merge_report(target: &mut HarnessDispatchCycleReport, source: HarnessDispatchCycleReport) {
    target.dispatches_seen += source.dispatches_seen;
    target.dispatches_delivered += source.dispatches_delivered;
    target.dispatches_rejected += source.dispatches_rejected;
    target.observations_seen += source.observations_seen;
    target.observations_consumed += source.observations_consumed;
    target.observations_deferred += source.observations_deferred;
    target.observations_retained += source.observations_retained;
    target.observations_quarantined += source.observations_quarantined;
    target.terminal_observations += source.terminal_observations;
    target.terminal_output_candidates_seen += source.terminal_output_candidates_seen;
    target.terminal_output_candidates_receipted += source.terminal_output_candidates_receipted;
    target.terminal_output_candidates_held += source.terminal_output_candidates_held;
    target.return_settlements += source.return_settlements;
    target.task_evidence_intakes += source.task_evidence_intakes;
    target.activations_seen += source.activations_seen;
    target.activations_started += source.activations_started;
    target.activations_acknowledged += source.activations_acknowledged;
    for blockage in source.activation_blockages {
        if !target.activation_blockages.contains(&blockage) {
            target.activation_blockages.push(blockage);
        }
    }
    for dispatch_id in source.terminal_dispatch_ids {
        if !target
            .terminal_dispatch_ids
            .iter()
            .any(|existing| existing == &dispatch_id)
        {
            target.terminal_dispatch_ids.push(dispatch_id);
        }
    }
    for dispatch_id in source.held_dispatch_ids {
        if !target.held_dispatch_ids.contains(&dispatch_id) {
            target.held_dispatch_ids.push(dispatch_id);
        }
    }
    for finding in source.task_recovery_findings {
        if !target
            .task_recovery_findings
            .iter()
            .any(|existing| existing == &finding)
        {
            target.task_recovery_findings.push(finding);
        }
    }
}

fn remove_terminal_envelopes(
    active_envelopes: &mut Vec<DispatchEnvelope>,
    report: &HarnessDispatchCycleReport,
) {
    active_envelopes.retain(|envelope| {
        !report.terminal_dispatch_ids.contains(&envelope.dispatch_id)
            && !report.held_dispatch_ids.contains(&envelope.dispatch_id)
    });
}

fn record_ingestion<R, D, A>(
    report: &mut HarnessDispatchCycleReport,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    observation: Option<&HarnessObservation>,
    result: HarnessFactIngestionResult,
) -> Result<ObservationSettlement, GovernedAdapterError>
where
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    let Some(observation) = observation else {
        return Ok(ObservationSettlement::Settled);
    };
    if observation.criticality == ObservationCriticality::Terminal as i32 {
        report.terminal_observations += 1;
        if !report
            .terminal_dispatch_ids
            .iter()
            .any(|dispatch_id| dispatch_id == &observation.dispatch_id)
        {
            report
                .terminal_dispatch_ids
                .push(observation.dispatch_id.clone());
        }
    }
    record_task_recovery_finding(report, observation, &result);
    match result.disposition {
        HarnessFactIngestionDisposition::Consumed
        | HarnessFactIngestionDisposition::IgnoredInformational => {
            adapter.mark_observation_consumed(&observation.observation_id)?;
            report.observations_consumed += 1;
            Ok(ObservationSettlement::Settled)
        }
        HarnessFactIngestionDisposition::DeferredToArtifactAuthority => {
            report.observations_deferred += 1;
            let is_completed = matches!(
                observation.payload.as_ref(),
                Some(harness_observation::Payload::Lifecycle(lifecycle))
                    if lifecycle.kind == LifecycleKind::ExecutionCompleted as i32
            );
            let durable_terminal_handoff = is_completed
                && adapter.terminal_output_candidate_is_durable(&observation.dispatch_id)?;
            if durable_terminal_handoff {
                adapter.mark_observation_consumed(&observation.observation_id)?;
                Ok(ObservationSettlement::Settled)
            } else {
                report.observations_retained += 1;
                Ok(ObservationSettlement::PendingBlocked)
            }
        }
        HarnessFactIngestionDisposition::RetainedForDependency => {
            report.observations_retained += 1;
            Ok(ObservationSettlement::PendingBlocked)
        }
        HarnessFactIngestionDisposition::QuarantineRequired { reason_code } => {
            adapter.quarantine_observation(&observation.observation_id, &reason_code)?;
            report.observations_quarantined += 1;
            Ok(ObservationSettlement::Settled)
        }
    }
}

/// Derives an in-cycle recovery finding from a committed collaboration
/// authority result. Only two committed run outcomes are eligible: a run that
/// reached `Cancelled` (cancellation completed), and a run that reached `Held`
/// through a quarantined harness terminal outcome (outcome unknown). The
/// finding never asserts Task state; the Task Authority re-validates task
/// status, revision and current-run binding before accepting any mutation.
fn record_task_recovery_finding(
    report: &mut HarnessDispatchCycleReport,
    observation: &HarnessObservation,
    result: &HarnessFactIngestionResult,
) {
    let Some(authority) = result.authority_result.as_ref() else {
        return;
    };
    if authority.committed_event.is_none() {
        return;
    }
    let Some(collaboration_command_result::Outcome::Snapshot(snapshot)) =
        authority.outcome.as_ref()
    else {
        return;
    };
    let Some(run) = snapshot.run.as_ref() else {
        return;
    };
    let finding = match RunStatus::try_from(run.status) {
        Ok(RunStatus::Cancelled) => Some(TaskRecoveryFinding {
            kind: TaskRecoveryKind::CancellationConfirmed,
            task_id: run.task_id.clone(),
            run_id: run.run_id.clone(),
            evidence_ref: format!("cancellation-receipt:{}", observation.observation_id),
        }),
        Ok(RunStatus::Held)
            if matches!(
                result.disposition,
                HarnessFactIngestionDisposition::QuarantineRequired { .. }
            ) =>
        {
            Some(TaskRecoveryFinding {
                kind: TaskRecoveryKind::OutcomeUnknown,
                task_id: run.task_id.clone(),
                run_id: run.run_id.clone(),
                evidence_ref: format!("uncertainty-evidence:{}", observation.observation_id),
            })
        }
        _ => None,
    };
    let Some(finding) = finding else {
        return;
    };
    if finding.task_id.trim().is_empty()
        || finding.run_id.trim().is_empty()
        || finding.evidence_ref.trim().is_empty()
        || report
            .task_recovery_findings
            .iter()
            .any(|existing| existing == &finding)
    {
        return;
    }
    report.task_recovery_findings.push(finding);
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
    use std::sync::Arc;

    struct FixedRunner {
        report: HarnessDispatchCycleReport,
    }

    impl HarnessDispatchRunner for FixedRunner {
        fn run_once(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                    + Send
                    + '_,
            >,
        > {
            let report = self.report.clone();
            Box::pin(async move { Ok(report) })
        }
    }

    #[tokio::test]
    async fn composite_sequences_runners_and_merges_terminal_and_held_identity_separately() {
        let composite = CompositeHarnessDispatchRunner::new(vec![
            Arc::new(FixedRunner {
                report: HarnessDispatchCycleReport {
                    dispatches_seen: 1,
                    dispatches_delivered: 1,
                    return_settlements: 1,
                    task_evidence_intakes: 1,
                    activations_seen: 1,
                    activations_started: 1,
                    activations_acknowledged: 1,
                    terminal_dispatch_ids: vec!["dispatch:one".to_owned()],
                    held_dispatch_ids: vec!["dispatch:held".to_owned()],
                    ..Default::default()
                },
            }),
            Arc::new(FixedRunner {
                report: HarnessDispatchCycleReport {
                    dispatches_seen: 2,
                    dispatches_rejected: 1,
                    return_settlements: 2,
                    task_evidence_intakes: 2,
                    activations_seen: 2,
                    activations_started: 2,
                    activations_acknowledged: 2,
                    terminal_dispatch_ids: vec![
                        "dispatch:one".to_owned(),
                        "dispatch:two".to_owned(),
                    ],
                    held_dispatch_ids: vec!["dispatch:held".to_owned()],
                    ..Default::default()
                },
            }),
        ])
        .expect("compose two Harness runners");

        let report = composite.run_once().await.expect("composite cycle");
        assert_eq!(report.dispatches_seen, 3);
        assert_eq!(report.dispatches_delivered, 1);
        assert_eq!(report.dispatches_rejected, 1);
        assert_eq!(report.return_settlements, 3);
        assert_eq!(report.task_evidence_intakes, 3);
        assert_eq!(report.activations_seen, 3);
        assert_eq!(report.activations_started, 3);
        assert_eq!(report.activations_acknowledged, 3);
        assert_eq!(
            report.terminal_dispatch_ids,
            vec!["dispatch:one", "dispatch:two"]
        );
        assert_eq!(report.held_dispatch_ids, vec!["dispatch:held"]);
    }

    #[test]
    fn exact_profile_filter_keeps_dispatches_on_their_bound_runner() {
        let envelope = DispatchEnvelope {
            capability_profile_ref: Some(ContractReference {
                contract_id: "profile:codex".to_owned(),
                version: "v1".to_owned(),
                sha256: "a".repeat(64),
            }),
            ..Default::default()
        };
        let codex_id = CapabilityProfileFilter::Exact(ContractReference {
            contract_id: "profile:codex".to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        });
        let dsh_id = CapabilityProfileFilter::Exact(ContractReference {
            contract_id: "profile:dsh".to_owned(),
            version: "v1".to_owned(),
            sha256: "b".repeat(64),
        });
        assert!(envelope_matches_profile(&envelope, None));
        assert!(envelope_matches_profile(&envelope, Some(&codex_id)));
        assert!(!envelope_matches_profile(&envelope, Some(&dsh_id)));
        assert!(!envelope_matches_profile(
            &DispatchEnvelope::default(),
            Some(&codex_id)
        ));
    }

    #[test]
    fn exact_profile_filter_rejects_version_and_digest_drift() {
        let envelope = DispatchEnvelope {
            capability_profile_ref: Some(ContractReference {
                contract_id: "profile:codex".to_owned(),
                version: "v1".to_owned(),
                sha256: "a".repeat(64),
            }),
            ..Default::default()
        };
        let exact = CapabilityProfileFilter::Exact(ContractReference {
            contract_id: "profile:codex".to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        });
        assert!(envelope_matches_profile(&envelope, Some(&exact)));

        let version_drift = CapabilityProfileFilter::Exact(ContractReference {
            contract_id: "profile:codex".to_owned(),
            version: "v2".to_owned(),
            sha256: "a".repeat(64),
        });
        assert!(!envelope_matches_profile(&envelope, Some(&version_drift)));

        let digest_drift = CapabilityProfileFilter::Exact(ContractReference {
            contract_id: "profile:codex".to_owned(),
            version: "v1".to_owned(),
            sha256: "b".repeat(64),
        });
        assert!(!envelope_matches_profile(&envelope, Some(&digest_drift)));
    }

    #[test]
    fn empty_composite_is_rejected_before_daemon_configuration() {
        assert!(matches!(
            CompositeHarnessDispatchRunner::new(Vec::new()),
            Err("at least one Harness dispatch runner is required")
        ));
    }

    #[test]
    fn cancellation_requires_a_present_nonblank_dispatch_id() {
        let mut attempt =
            egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot::default();
        assert!(!has_cancellable_dispatch_id(&attempt));

        attempt.dispatch_id = Some("   ".to_owned());
        assert!(!has_cancellable_dispatch_id(&attempt));

        attempt.dispatch_id = Some("dispatch-live-001".to_owned());
        assert!(has_cancellable_dispatch_id(&attempt));
    }

    #[test]
    fn cancellation_requires_the_live_runner_capability_profile() {
        let profile_a = ContractReference {
            contract_id: "profile:a".to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        };
        let profile_b = ContractReference {
            contract_id: "profile:b".to_owned(),
            version: "v1".to_owned(),
            sha256: "b".repeat(64),
        };
        let attempt =
            egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptSnapshot {
                capability_profile_ref: Some(profile_a.clone()),
                ..Default::default()
            };

        assert!(attempt_matches_capability_profile(
            &attempt,
            &CapabilityProfileFilter::Exact(profile_a)
        ));
        assert!(!attempt_matches_capability_profile(
            &attempt,
            &CapabilityProfileFilter::Exact(profile_b)
        ));
    }
}
