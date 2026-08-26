use super::{
    ArtifactReturnSource, AuthenticatedCollaborationPrincipal, AuthorityClock,
    CollaborationControl, CollaborationControlError, CollaborationReferenceGuard,
    HarnessEvidenceResolver, HarnessFactIngestionDisposition, HarnessFactIngestionResult,
    SingleHarnessWorkflowResolver, TaskActivationGuardSet, TaskActivationReferenceHandle,
    TaskActivationSource, seal_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::get_collaboration_response;
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AttemptCommandBase, AttemptStatus, CollaborationCommand, CommitStepReturnCommand,
    RecordAttemptReturnCommand, RunCommandBase, RunStatus, StepStatus, collaboration_command,
    collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DeliveryDisposition, DispatchEnvelope, HarnessObservation, LifecycleKind,
    ObservationCriticality, dispatch_result, harness_observation,
};
use egopulse_harness_adapter::{
    AdapterClock, DispatchMaterialResolver, GovernedAdapterError, GovernedHarnessAdapter,
    NativeHarnessDriver,
};
use prost::Message;
use sha2::Digest;
use std::{future::Future, pin::Pin};
use thiserror::Error;

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
    pub activations_seen: u64,
    pub activations_started: u64,
    pub activations_acknowledged: u64,
    pub terminal_dispatch_ids: Vec<String>,
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
    ContractId(String),
    Exact(ContractReference),
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

    /// Restricts this runner to dispatch envelopes bound to one reviewed
    /// capability profile. This is required when multiple provider runners
    /// share one Collaboration Control database.
    #[must_use]
    pub fn with_capability_profile_id(mut self, profile_id: impl Into<String>) -> Self {
        self.capability_profile_filter =
            Some(CapabilityProfileFilter::ContractId(profile_id.into()));
        self
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
            register_pending_envelopes(
                control,
                active_envelopes,
                &self.principal,
                self.capability_profile_filter.as_ref(),
            )?;
            let mut report = HarnessDispatchCycleReport::default();
            pump_active_envelopes(
                control,
                adapter,
                active_envelopes,
                &self.principal,
                &mut report,
            )
            .await?;
            let dispatched = dispatch_pending_for_profile(
                control,
                adapter,
                &self.principal,
                self.capability_profile_filter.as_ref(),
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
}

/// The production single-writer worker for the first vertical. It consumes
/// Task activation handoffs, binds the immutable activation reference, starts
/// the explicit single-Harness workflow, acknowledges the Task outbox only
/// after the Collaboration commit, and then dispatches through the same
/// CollaborationControl/Adapter runtime.
pub struct GovernedTaskActivationRunner<S, W, E, C, R, D, A> {
    runtime: tokio::sync::Mutex<GovernedTaskActivationRuntime<S, W, E, C, R, D, A>>,
    principal: AuthenticatedCollaborationPrincipal,
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
            }),
            principal,
        }
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
            } = &mut *runtime;
            let return_settlements = consume_artifact_returns(
                control,
                adapter,
                artifact_return_source.as_ref(),
                artifact_return_principal.as_ref(),
                step_return_principal.as_ref(),
            )?;
            let activations = source
                .pending_task_activations()
                .map_err(|_| HarnessDispatchCycleError::TaskActivationSource)?;
            let mut report = HarnessDispatchCycleReport {
                activations_seen: activations.len() as u64,
                return_settlements,
                ..HarnessDispatchCycleReport::default()
            };
            pump_active_envelopes(
                control,
                adapter,
                active_envelopes,
                &self.principal,
                &mut report,
            )
            .await?;
            for activation in activations {
                let config = resolver
                    .resolve(&activation)
                    .map_err(|_| HarnessDispatchCycleError::TaskActivationResolver)?;
                reference
                    .bind(activation.task.clone(), &config, *lease_ttl_seconds)
                    .map_err(|_| {
                        HarnessDispatchCycleError::TaskActivationWorkflow(
                            "activation reference binding failed".to_owned(),
                        )
                    })?;
                super::start_single_harness_workflow(control, &activation.task, &config).map_err(
                    |error| HarnessDispatchCycleError::TaskActivationWorkflow(error.to_string()),
                )?;
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
                register_pending_envelopes(control, active_envelopes, &self.principal, None)?;
                let dispatched = dispatch_pending(control, adapter, &self.principal).await?;
                merge_report(&mut report, dispatched);
                remove_terminal_envelopes(active_envelopes, &report);
            }
            register_pending_envelopes(control, active_envelopes, &self.principal, None)?;
            let dispatched = dispatch_pending(control, adapter, &self.principal).await?;
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
        let candidate = adapter
            .terminal_output_candidate_for_dispatch(&lineage.dispatch_id)?
            .ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "terminal Adapter evidence for Artifact return is unavailable".to_owned(),
                )
            })?;
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
        if !technical_return_already_recorded {
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
            seal_request_digest(&mut command).ok_or_else(|| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Artifact return command could not be sealed".to_owned(),
                )
            })?;
            let result = control.execute(&command, principal)?;
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
    dispatch_pending_for_profile(control, adapter, principal, None).await
}

async fn dispatch_pending_for_profile<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
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
        .collect::<Vec<_>>();
    let mut report = HarnessDispatchCycleReport {
        dispatches_seen: pending.len() as u64,
        ..HarnessDispatchCycleReport::default()
    };
    for dispatch in pending {
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
        record_ingestion(&mut report, adapter, None, ingested)?;
        let observation_report =
            pump_observations(control, adapter, &dispatch.envelope, principal).await?;
        report.observations_seen += observation_report.observations_seen;
        report.observations_consumed += observation_report.observations_consumed;
        report.observations_deferred += observation_report.observations_deferred;
        report.observations_retained += observation_report.observations_retained;
        report.observations_quarantined += observation_report.observations_quarantined;
    }
    Ok(report)
}

/// Pumps every currently available observation for one immutable dispatch
/// envelope. It is also used after cancellation/recovery, when the original
/// dispatch is no longer present in the Collaboration outbox.
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
    while let Some(observation) = adapter.pump_one(envelope).await? {
        report.observations_seen += 1;
        let ingested = control.ingest_harness_observation(&observation, principal)?;
        record_ingestion(&mut report, adapter, Some(&observation), ingested)?;
    }
    Ok(report)
}

fn register_pending_envelopes<G, C>(
    control: &CollaborationControl<G, C>,
    active_envelopes: &mut Vec<DispatchEnvelope>,
    principal: &AuthenticatedCollaborationPrincipal,
    capability_profile_filter: Option<&CapabilityProfileFilter>,
) -> Result<(), CollaborationControlError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    for pending in control
        .pending_dispatches(principal)?
        .into_iter()
        .filter(|dispatch| envelope_matches_profile(&dispatch.envelope, capability_profile_filter))
    {
        if !active_envelopes
            .iter()
            .any(|item| item.dispatch_id == pending.envelope.dispatch_id)
        {
            active_envelopes.push(pending.envelope);
        }
    }
    Ok(())
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
                CapabilityProfileFilter::ContractId(expected) => reference.contract_id == *expected,
                CapabilityProfileFilter::Exact(expected) => reference == expected,
            })
    })
}

async fn pump_active_envelopes<G, C, R, D, A>(
    control: &mut CollaborationControl<G, C>,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    active_envelopes: &mut Vec<DispatchEnvelope>,
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
    for envelope in envelopes {
        let pumped = pump_observations(control, adapter, &envelope, principal).await?;
        merge_report(report, pumped);
        if !report
            .terminal_dispatch_ids
            .iter()
            .any(|dispatch_id| dispatch_id == &envelope.dispatch_id)
        {
            active_envelopes.push(envelope);
        }
    }
    Ok(())
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
    for dispatch_id in source.terminal_dispatch_ids {
        if !target
            .terminal_dispatch_ids
            .iter()
            .any(|existing| existing == &dispatch_id)
        {
            target.terminal_dispatch_ids.push(dispatch_id);
        }
    }
}

fn remove_terminal_envelopes(
    active_envelopes: &mut Vec<DispatchEnvelope>,
    report: &HarnessDispatchCycleReport,
) {
    active_envelopes.retain(|envelope| {
        !report
            .terminal_dispatch_ids
            .iter()
            .any(|dispatch_id| dispatch_id == &envelope.dispatch_id)
    });
}

fn record_ingestion<R, D, A>(
    report: &mut HarnessDispatchCycleReport,
    adapter: &mut GovernedHarnessAdapter<R, D, A>,
    observation: Option<&HarnessObservation>,
    result: HarnessFactIngestionResult,
) -> Result<(), GovernedAdapterError>
where
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    A: AdapterClock,
{
    if observation.is_none() {
        return Ok(());
    }
    if observation.is_some_and(|value| value.criticality == ObservationCriticality::Terminal as i32)
    {
        report.terminal_observations += 1;
        if let Some(observation) = observation
            && !report
                .terminal_dispatch_ids
                .iter()
                .any(|dispatch_id| dispatch_id == &observation.dispatch_id)
        {
            report
                .terminal_dispatch_ids
                .push(observation.dispatch_id.clone());
        }
    }
    match result.disposition {
        HarnessFactIngestionDisposition::Consumed
        | HarnessFactIngestionDisposition::IgnoredInformational => {
            if let Some(observation) = observation {
                adapter.mark_observation_consumed(&observation.observation_id)?;
            }
            report.observations_consumed += 1;
        }
        HarnessFactIngestionDisposition::DeferredToArtifactAuthority => {
            report.observations_deferred += 1;
            let is_completed = observation.is_some_and(|observation| {
                matches!(
                    observation.payload.as_ref(),
                    Some(harness_observation::Payload::Lifecycle(lifecycle))
                        if lifecycle.kind == LifecycleKind::ExecutionCompleted as i32
                )
            });
            let durable_terminal_handoff = if is_completed {
                adapter.terminal_output_candidate_is_durable(
                    &observation
                        .expect("completed observation exists")
                        .dispatch_id,
                )?
            } else {
                false
            };
            if durable_terminal_handoff {
                if let Some(observation) = observation {
                    adapter.mark_observation_consumed(&observation.observation_id)?;
                }
            } else {
                report.observations_retained += 1;
            }
        }
        HarnessFactIngestionDisposition::RetainedForDependency => {
            report.observations_retained += 1;
        }
        HarnessFactIngestionDisposition::QuarantineRequired { reason_code } => {
            if let Some(observation) = observation {
                adapter.quarantine_observation(&observation.observation_id, &reason_code)?;
            }
            report.observations_quarantined += 1;
        }
    }
    Ok(())
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
    async fn composite_sequences_runners_and_merges_terminal_identity() {
        let composite = CompositeHarnessDispatchRunner::new(vec![
            Arc::new(FixedRunner {
                report: HarnessDispatchCycleReport {
                    dispatches_seen: 1,
                    dispatches_delivered: 1,
                    terminal_dispatch_ids: vec!["dispatch:one".to_owned()],
                    ..Default::default()
                },
            }),
            Arc::new(FixedRunner {
                report: HarnessDispatchCycleReport {
                    dispatches_seen: 2,
                    dispatches_rejected: 1,
                    terminal_dispatch_ids: vec![
                        "dispatch:one".to_owned(),
                        "dispatch:two".to_owned(),
                    ],
                    ..Default::default()
                },
            }),
        ])
        .expect("compose two Harness runners");

        let report = composite.run_once().await.expect("composite cycle");
        assert_eq!(report.dispatches_seen, 3);
        assert_eq!(report.dispatches_delivered, 1);
        assert_eq!(report.dispatches_rejected, 1);
        assert_eq!(
            report.terminal_dispatch_ids,
            vec!["dispatch:one", "dispatch:two"]
        );
    }

    #[test]
    fn profile_filter_keeps_dispatches_on_their_bound_runner() {
        let envelope = DispatchEnvelope {
            capability_profile_ref: Some(ContractReference {
                contract_id: "profile:codex".to_owned(),
                version: "v1".to_owned(),
                sha256: "a".repeat(64),
            }),
            ..Default::default()
        };
        let codex_id = CapabilityProfileFilter::ContractId("profile:codex".to_owned());
        let dsh_id = CapabilityProfileFilter::ContractId("profile:dsh".to_owned());
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
}
