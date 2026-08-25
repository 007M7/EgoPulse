use super::{
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlError, CollaborationReferenceGuard, HarnessEvidenceResolver,
    HarnessFactIngestionDisposition, HarnessFactIngestionResult,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DeliveryDisposition, DispatchEnvelope, HarnessObservation, dispatch_result,
};
use egopulse_harness_adapter::{
    AdapterClock, DispatchMaterialResolver, GovernedAdapterError, GovernedHarnessAdapter,
    NativeHarnessDriver,
};
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
}

#[derive(Debug, Error)]
pub enum HarnessDispatchCycleError {
    #[error("collaboration control operation failed")]
    Collaboration(#[from] CollaborationControlError),
    #[error("harness adapter operation failed")]
    Adapter(#[from] GovernedAdapterError),
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
