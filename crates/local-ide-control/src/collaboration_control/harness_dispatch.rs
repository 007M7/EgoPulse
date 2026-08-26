use super::{
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlError, CollaborationReferenceGuard, HarnessEvidenceResolver,
    HarnessFactIngestionDisposition, HarnessFactIngestionResult, SingleHarnessWorkflowResolver,
    TaskActivationGuardSet, TaskActivationReferenceHandle, TaskActivationSource,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DeliveryDisposition, DispatchEnvelope, HarnessObservation, ObservationCriticality,
    dispatch_result,
};
use egopulse_harness_adapter::{
    AdapterClock, DispatchMaterialResolver, GovernedAdapterError, GovernedHarnessAdapter,
    NativeHarnessDriver,
};
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
    #[error("task activation workflow failed")]
    TaskActivationWorkflow,
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

struct GovernedDispatchRuntime<G, C, R, D, A> {
    control: CollaborationControl<G, C>,
    adapter: GovernedHarnessAdapter<R, D, A>,
    active_envelopes: Vec<DispatchEnvelope>,
}

pub struct GovernedHarnessDispatchRunner<G, C, R, D, A> {
    runtime: tokio::sync::Mutex<GovernedDispatchRuntime<G, C, R, D, A>>,
    principal: AuthenticatedCollaborationPrincipal,
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
        }
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
            register_pending_envelopes(control, active_envelopes, &self.principal)?;
            let mut report = HarnessDispatchCycleReport::default();
            pump_active_envelopes(
                control,
                adapter,
                active_envelopes,
                &self.principal,
                &mut report,
            )
            .await?;
            let dispatched = dispatch_pending(control, adapter, &self.principal).await?;
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
            }),
            principal,
        }
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
            } = &mut *runtime;
            let activations = source
                .pending_task_activations()
                .map_err(|_| HarnessDispatchCycleError::TaskActivationSource)?;
            let mut report = HarnessDispatchCycleReport {
                activations_seen: activations.len() as u64,
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
                    .map_err(|_| HarnessDispatchCycleError::TaskActivationWorkflow)?;
                super::start_single_harness_workflow(control, &activation.task, &config)
                    .map_err(|_| HarnessDispatchCycleError::TaskActivationWorkflow)?;
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
                register_pending_envelopes(control, active_envelopes, &self.principal)?;
                let dispatched = dispatch_pending(control, adapter, &self.principal).await?;
                merge_report(&mut report, dispatched);
                remove_terminal_envelopes(active_envelopes, &report);
            }
            register_pending_envelopes(control, active_envelopes, &self.principal)?;
            let dispatched = dispatch_pending(control, adapter, &self.principal).await?;
            merge_report(&mut report, dispatched);
            remove_terminal_envelopes(active_envelopes, &report);
            Ok(report)
        })
    }
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
    let pending = control.pending_dispatches(principal)?;
    let mut report = HarnessDispatchCycleReport {
        dispatches_seen: pending.len() as u64,
        ..HarnessDispatchCycleReport::default()
    };
    for dispatch in pending {
        let result = adapter.dispatch(&dispatch.envelope).await?;
        let Some(outcome) = result.outcome else {
            report.dispatches_rejected += 1;
            continue;
        };
        let dispatch_result::Outcome::Receipt(receipt) = outcome else {
            report.dispatches_rejected += 1;
            continue;
        };
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
) -> Result<(), CollaborationControlError>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    for pending in control.pending_dispatches(principal)? {
        if !active_envelopes
            .iter()
            .any(|item| item.dispatch_id == pending.envelope.dispatch_id)
        {
            active_envelopes.push(pending.envelope);
        }
    }
    Ok(())
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
        | HarnessFactIngestionDisposition::IgnoredInformational
        | HarnessFactIngestionDisposition::DeferredToArtifactAuthority => {
            if let Some(observation) = observation {
                adapter.mark_observation_consumed(&observation.observation_id)?;
            }
            if result.disposition == HarnessFactIngestionDisposition::DeferredToArtifactAuthority {
                report.observations_deferred += 1;
            } else {
                report.observations_consumed += 1;
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
