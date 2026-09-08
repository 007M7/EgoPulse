use std::sync::Arc;

use egopulse_domain_contracts::v01::egopulse::{
    harness::v1::{
        ApprovalDecisionEnvelope, DeliveryDisposition, approval_decision_result,
        harness_observation,
    },
    policy::v1::{
        HarnessApprovalDecisionRecord, HarnessApprovalDecisionState, HarnessApprovalRequestBinding,
        PolicyDecisionCommandResult, PolicyDecisionErrorCode,
    },
};
use egopulse_harness_adapter::AdapterEdge;
use egopulse_local_ide_control::collaboration_control::HarnessApprovalDeliveryTarget;
use thiserror::Error;

#[derive(Clone, Debug)]
pub(crate) struct PendingApprovalDelivery {
    pub source_event_id: String,
    pub envelope: ApprovalDecisionEnvelope,
    pub request: HarnessApprovalRequestBinding,
    pub expected_state_revision: u64,
    pub expired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldApprovalDelivery {
    pub authority_decision_ref: String,
    pub approval_request_id: String,
    pub safe_reason_code: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ApprovalDeliveryCycleReport {
    pub delivered_and_consumed: usize,
    pub rejected_and_consumed: usize,
    pub held: Vec<HeldApprovalDelivery>,
}

#[derive(Debug, Error)]
pub(crate) enum ApprovalDeliveryCycleError {
    #[error("approval delivery owner is unavailable")]
    OwnerUnavailable,
    #[error("approval delivery owner data failed integrity validation")]
    OwnerIntegrity,
    #[error("approval delivery route data failed integrity validation")]
    RouteIntegrity,
}

pub(crate) type ApprovalPolicyEvidence = (
    HarnessApprovalDecisionRecord,
    HarnessApprovalDecisionState,
    ApprovalDecisionEnvelope,
);

pub(crate) trait ApprovalDeliverySource: Send + Sync + 'static {
    fn pending_approval_deliveries(
        &self,
    ) -> Result<Vec<PendingApprovalDelivery>, ApprovalDeliveryCycleError>;

    /// The exact issued envelope is part of the durable Adapter request
    /// identity; reconstructing it from the decision would change metadata.
    fn approval_policy_evidence(
        &self,
        _authority_decision_ref: &str,
    ) -> Result<Option<ApprovalPolicyEvidence>, ApprovalDeliveryCycleError> {
        Err(ApprovalDeliveryCycleError::OwnerUnavailable)
    }

    fn consume_delivered_approval(
        &self,
        delivery: &PendingApprovalDelivery,
        receipt: egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecisionReceipt,
        harness_adapter_principal_id: &str,
    ) -> Result<PolicyDecisionCommandResult, ApprovalDeliveryCycleError>;
}

pub(crate) struct ApprovalDeliveryRoute {
    adapter_id: String,
    capability_profile_id: String,
    harness_adapter_principal_id: String,
    edge: std::sync::Mutex<AdapterEdge>,
    target: Arc<dyn HarnessApprovalDeliveryTarget>,
}

impl ApprovalDeliveryRoute {
    pub fn new(
        adapter_id: impl Into<String>,
        capability_profile_id: impl Into<String>,
        harness_adapter_principal_id: impl Into<String>,
        edge: AdapterEdge,
        target: Arc<dyn HarnessApprovalDeliveryTarget>,
    ) -> Result<Self, ApprovalDeliveryCycleError> {
        let adapter_id = adapter_id.into();
        let capability_profile_id = capability_profile_id.into();
        let harness_adapter_principal_id = harness_adapter_principal_id.into();
        if adapter_id.trim().is_empty()
            || capability_profile_id.trim().is_empty()
            || harness_adapter_principal_id.trim().is_empty()
        {
            return Err(ApprovalDeliveryCycleError::RouteIntegrity);
        }
        Ok(Self {
            adapter_id,
            capability_profile_id,
            harness_adapter_principal_id,
            edge: std::sync::Mutex::new(edge),
            target,
        })
    }

    fn matches(
        &self,
        delivery: &PendingApprovalDelivery,
    ) -> Result<bool, ApprovalDeliveryCycleError> {
        if self.adapter_id != delivery.request.adapter_id {
            return Ok(false);
        }
        let projections = self
            .edge
            .lock()
            .map_err(|_| ApprovalDeliveryCycleError::RouteIntegrity)?
            .retained_approval_projection_messages_for_rebuild()
            .map_err(|_| ApprovalDeliveryCycleError::RouteIntegrity)?;
        Ok(projections.into_iter().any(|projection| {
            let Some(harness_observation::Payload::ApprovalRequest(request)) =
                projection.observation.payload.as_ref()
            else {
                return false;
            };
            projection.source_observation_id == delivery.request.request_observation_id
                && projection.source_revision == delivery.request.request_observation_sequence
                && projection.observation.adapter_id == delivery.request.adapter_id
                && projection.observation.capability_profile_id == self.capability_profile_id
                && projection.attempt_id == delivery.envelope.attempt_id
                && projection.dispatch_id == delivery.envelope.dispatch_id
                && projection.fencing_token == delivery.envelope.fencing_token
                && request.approval_request_id == delivery.envelope.approval_request_id
                && request.action_digest_sha256 == delivery.envelope.action_digest_sha256
                && request.kind == delivery.request.kind
                && request.requested_scope_ref == delivery.request.requested_scope_ref
                && request.lifecycle == delivery.request.request_lifecycle
                && request.request_revision == delivery.request.request_revision
        }))
    }

    fn persisted_receipt(
        &self,
        approval_request_id: &str,
    ) -> Result<
        Option<egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecisionReceipt>,
        ApprovalDeliveryCycleError,
    > {
        self.edge
            .lock()
            .map_err(|_| ApprovalDeliveryCycleError::RouteIntegrity)?
            .approval_receipt(approval_request_id)
            .map_err(|_| ApprovalDeliveryCycleError::RouteIntegrity)
    }
}

pub(crate) struct ApprovalDeliveryWorker {
    source: Arc<dyn ApprovalDeliverySource>,
    routes: Vec<ApprovalDeliveryRoute>,
}

impl ApprovalDeliveryWorker {
    pub fn new(
        source: Arc<dyn ApprovalDeliverySource>,
        routes: Vec<ApprovalDeliveryRoute>,
    ) -> Result<Self, ApprovalDeliveryCycleError> {
        if routes.is_empty() {
            return Err(ApprovalDeliveryCycleError::RouteIntegrity);
        }
        Ok(Self { source, routes })
    }

    pub async fn run_once(
        &self,
    ) -> Result<ApprovalDeliveryCycleReport, ApprovalDeliveryCycleError> {
        let mut report = ApprovalDeliveryCycleReport::default();
        for delivery in self.source.pending_approval_deliveries()? {
            let matching = self
                .routes
                .iter()
                .filter_map(|route| match route.matches(&delivery) {
                    Ok(true) => Some(Ok(route)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let [route] = matching.as_slice() else {
                report.held.push(held(
                    &delivery,
                    if matching.is_empty() {
                        "APPROVAL_DELIVERY_ROUTE_NOT_FOUND"
                    } else {
                        "APPROVAL_DELIVERY_ROUTE_AMBIGUOUS"
                    },
                ));
                continue;
            };
            // Reconcile from the durable receipt before touching the live
            // adapter, including unexpired decisions after a lost consume ACK.
            let receipt = if let Some(receipt) =
                route.persisted_receipt(&delivery.envelope.approval_request_id)?
            {
                receipt
            } else {
                if delivery.expired {
                    report
                        .held
                        .push(held(&delivery, "APPROVAL_AUTHORITY_DECISION_EXPIRED"));
                    continue;
                }
                let result = match route.target.deliver_approval(&delivery.envelope).await {
                    Ok(result) => result,
                    Err(_) => {
                        report
                            .held
                            .push(held(&delivery, "APPROVAL_DELIVERY_ADAPTER_ERROR"));
                        continue;
                    }
                };
                let Some(approval_decision_result::Outcome::Receipt(receipt)) = result.outcome
                else {
                    report
                        .held
                        .push(held(&delivery, "APPROVAL_DELIVERY_NOT_CONFIRMED"));
                    continue;
                };
                receipt
            };
            let disposition = DeliveryDisposition::try_from(receipt.disposition);
            if disposition == Ok(DeliveryDisposition::Unknown) {
                let recovery = route
                    .target
                    .recover_unknown_approval(&delivery.envelope)
                    .await;
                report.held.push(held(
                    &delivery,
                    if recovery.is_ok() {
                        "APPROVAL_DELIVERY_OUTCOME_UNKNOWN"
                    } else {
                        "APPROVAL_DELIVERY_UNKNOWN_RECOVERY_NOT_COMMITTED"
                    },
                ));
                continue;
            }
            if !matches!(
                disposition,
                Ok(DeliveryDisposition::Delivered | DeliveryDisposition::Rejected)
            ) {
                report.held.push(held(
                    &delivery,
                    "APPROVAL_DELIVERY_REJECTED_OR_LIVE_ROUTING_MISSING",
                ));
                continue;
            }
            if self.consume_delivered(&delivery, receipt, route)? {
                if disposition == Ok(DeliveryDisposition::Delivered) {
                    report.delivered_and_consumed += 1;
                } else {
                    report.rejected_and_consumed += 1;
                }
            } else {
                report.held.push(held(
                    &delivery,
                    if delivery.expired {
                        "APPROVAL_DELIVERED_RECEIPT_POLICY_EXPIRED"
                    } else {
                        "APPROVAL_DELIVERY_CONSUME_NOT_COMMITTED"
                    },
                ));
            }
        }
        Ok(report)
    }

    fn consume_delivered(
        &self,
        delivery: &PendingApprovalDelivery,
        receipt: egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecisionReceipt,
        route: &ApprovalDeliveryRoute,
    ) -> Result<bool, ApprovalDeliveryCycleError> {
        let consumed = self.source.consume_delivered_approval(
            delivery,
            receipt,
            &route.harness_adapter_principal_id,
        )?;
        Ok(consumed.committed
            && PolicyDecisionErrorCode::try_from(consumed.error_code)
                == Ok(PolicyDecisionErrorCode::Unspecified))
    }
}

fn held(
    delivery: &PendingApprovalDelivery,
    safe_reason_code: &'static str,
) -> HeldApprovalDelivery {
    HeldApprovalDelivery {
        authority_decision_ref: delivery.envelope.authority_decision_ref.clone(),
        approval_request_id: delivery.envelope.approval_request_id.clone(),
        safe_reason_code,
    }
}
