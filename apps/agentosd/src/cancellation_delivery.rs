//! Durable Task-cancellation handoff delivery.
//!
//! A delivered native interrupt is deliberately not a Task outcome. This
//! worker only advances the Task Authority outbox after the same live
//! Collaboration/Adapter runner has committed cancellation intent and the
//! Adapter has persisted a delivered interrupt receipt. The dispatch worker
//! later observes `ExecutionInterrupted` and drives the existing structured
//! cancellation settlement.

use std::sync::Arc;

use egopulse_cognition_runtime::task_authority::TaskCancellationReconciliation;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    CancelExecutionReceipt, CancellationDeliveryDisposition, cancel_execution_result,
};
use egopulse_local_ide_control::collaboration_control::{
    HarnessCancellationDeliveryError, HarnessCancellationDeliveryTarget, TaskCancellationHandoff,
    TaskCancellationSource, TaskCancellationSourceError,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldTaskCancellation {
    pub task_id: String,
    pub cancellation_request_id: String,
    pub safe_reason_code: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CancellationDeliveryCycleReport {
    pub delivered_and_acknowledged: u64,
    pub task_settled_and_acknowledged: u64,
    pub held: Vec<HeldTaskCancellation>,
}

#[derive(Debug, Error)]
pub(crate) enum CancellationDeliveryCycleError {
    #[error("Task cancellation source is unavailable")]
    Source(#[from] TaskCancellationSourceError),
    #[error("Task cancellation delivery route is invalid")]
    RouteIntegrity,
}

pub(crate) struct CancellationDeliveryRoute {
    target: Arc<dyn HarnessCancellationDeliveryTarget>,
}

/// App-local extension of the frozen Collaboration cancellation source. It
/// lets the Task owner settle no-run cancellations and consume stale outbox
/// messages before native route discovery without widening the shared Adapter
/// contract.
pub(crate) trait TaskCancellationReconciler: Send + Sync + 'static {
    fn reconcile_task_cancellation(
        &self,
        handoff: &TaskCancellationHandoff,
    ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError>;
}

impl CancellationDeliveryRoute {
    pub(crate) fn new(target: Arc<dyn HarnessCancellationDeliveryTarget>) -> Self {
        Self { target }
    }

    async fn matches(
        &self,
        handoff: &TaskCancellationHandoff,
    ) -> Result<bool, HarnessCancellationDeliveryError> {
        self.target.owns_task_cancellation(handoff).await
    }
}

pub(crate) struct CancellationDeliveryWorker {
    source: Arc<dyn TaskCancellationSource>,
    reconciler: Option<Arc<dyn TaskCancellationReconciler>>,
    routes: Vec<CancellationDeliveryRoute>,
}

impl CancellationDeliveryWorker {
    pub(crate) fn new(
        source: Arc<dyn TaskCancellationSource>,
        routes: Vec<CancellationDeliveryRoute>,
    ) -> Result<Self, CancellationDeliveryCycleError> {
        if routes.is_empty() {
            return Err(CancellationDeliveryCycleError::RouteIntegrity);
        }
        Ok(Self {
            source,
            reconciler: None,
            routes,
        })
    }

    pub(crate) fn with_task_reconciliation(
        mut self,
        reconciler: Arc<dyn TaskCancellationReconciler>,
    ) -> Self {
        self.reconciler = Some(reconciler);
        self
    }

    pub(crate) async fn run_once(
        &self,
    ) -> Result<CancellationDeliveryCycleReport, CancellationDeliveryCycleError> {
        let mut report = CancellationDeliveryCycleReport::default();
        for handoff in self.source.pending_task_cancellations()? {
            if let Some(reconciler) = self.reconciler.as_ref() {
                match reconciler.reconcile_task_cancellation(&handoff) {
                    Err(TaskCancellationSourceError::Unavailable) => {
                        report
                            .held
                            .push(held(&handoff, "CANCELLATION_TASK_OWNER_UNAVAILABLE"));
                        continue;
                    }
                    Err(TaskCancellationSourceError::Integrity) => {
                        report
                            .held
                            .push(held(&handoff, "CANCELLATION_TASK_RECONCILIATION_INVALID"));
                        continue;
                    }
                    Ok(TaskCancellationReconciliation::NeedsNativeDelivery) => {}
                    Ok(TaskCancellationReconciliation::SettledAndAcknowledged { .. }) => {
                        report.task_settled_and_acknowledged += 1;
                        continue;
                    }
                }
            }
            let mut matching = Vec::new();
            let mut route_error = false;
            for route in &self.routes {
                match route.matches(&handoff).await {
                    Ok(true) => matching.push(route),
                    Ok(false) => {}
                    Err(_) => route_error = true,
                }
            }
            // A route that could not establish ownership might be the same
            // live Adapter as a matching route. Do not turn partial discovery
            // into an unproven native interrupt.
            if route_error {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_ROUTE_UNAVAILABLE"));
                continue;
            }
            let [route] = matching.as_slice() else {
                report.held.push(held(
                    &handoff,
                    if matching.is_empty() {
                        "CANCELLATION_ROUTE_NOT_FOUND"
                    } else {
                        "CANCELLATION_ROUTE_AMBIGUOUS"
                    },
                ));
                continue;
            };

            let result = match route.target.deliver_task_cancellation(&handoff).await {
                Ok(result) => result,
                Err(_) => {
                    report
                        .held
                        .push(held(&handoff, "CANCELLATION_DELIVERY_ADAPTER_ERROR"));
                    continue;
                }
            };
            let Some(cancel_execution_result::Outcome::Receipt(receipt)) = result.outcome else {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_NOT_CONFIRMED"));
                continue;
            };
            if receipt.cancellation_request_id != handoff.cancellation_request_id
                || !cancellation_receipt_is_valid(&receipt)
            {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_RECEIPT_MISMATCH"));
                continue;
            }
            if CancellationDeliveryDisposition::try_from(receipt.disposition)
                != Ok(CancellationDeliveryDisposition::Delivered)
            {
                report.held.push(held(
                    &handoff,
                    if CancellationDeliveryDisposition::try_from(receipt.disposition)
                        == Ok(CancellationDeliveryDisposition::Unknown)
                    {
                        "CANCELLATION_DELIVERY_OUTCOME_UNKNOWN"
                    } else {
                        "CANCELLATION_DELIVERY_REJECTED_OR_UNSUPPORTED"
                    },
                ));
                continue;
            }
            if self.source.acknowledge_task_cancellation(
                &handoff.message_id,
                &handoff.payload_digest_sha256,
            )? {
                report.delivered_and_acknowledged += 1;
            } else {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_ACK_REJECTED"));
            }
        }
        Ok(report)
    }
}

fn cancellation_receipt_is_valid(receipt: &CancelExecutionReceipt) -> bool {
    if receipt.receipt_id.trim().is_empty()
        || receipt.receipt_digest_sha256.len() != 64
        || !receipt
            .receipt_digest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let recorded_digest = receipt.receipt_digest_sha256.clone();
    let mut canonical = receipt.clone();
    canonical.receipt_digest_sha256.clear();
    hex::encode(Sha256::digest(canonical.encode_to_vec())) == recorded_digest
}

fn held(handoff: &TaskCancellationHandoff, safe_reason_code: &'static str) -> HeldTaskCancellation {
    HeldTaskCancellation {
        task_id: handoff.task.task_id.clone(),
        cancellation_request_id: handoff.cancellation_request_id.clone(),
        safe_reason_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::harness::v1::CancelExecutionResult;
    use std::{future::Future, pin::Pin, sync::Mutex};

    #[derive(Default)]
    struct Source {
        pending: Mutex<Vec<TaskCancellationHandoff>>,
        acknowledgements: Mutex<u64>,
    }

    impl TaskCancellationSource for Source {
        fn pending_task_cancellations(
            &self,
        ) -> Result<Vec<TaskCancellationHandoff>, TaskCancellationSourceError> {
            Ok(self.pending.lock().expect("pending lock").clone())
        }

        fn acknowledge_task_cancellation(
            &self,
            _message_id: &str,
            _payload_digest_sha256: &str,
        ) -> Result<bool, TaskCancellationSourceError> {
            *self.acknowledgements.lock().expect("ack lock") += 1;
            Ok(true)
        }
    }

    struct Target {
        receipt: CancelExecutionReceipt,
        deliveries: Arc<Mutex<u64>>,
    }

    struct Reconciler(TaskCancellationReconciliation);

    impl TaskCancellationReconciler for Reconciler {
        fn reconcile_task_cancellation(
            &self,
            _handoff: &TaskCancellationHandoff,
        ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError> {
            Ok(self.0)
        }
    }

    impl HarnessCancellationDeliveryTarget for Target {
        fn owns_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>
        {
            Box::pin(async { Ok(true) })
        }

        fn deliver_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                    + Send
                    + 'a,
            >,
        > {
            let receipt = self.receipt.clone();
            let deliveries = Arc::clone(&self.deliveries);
            Box::pin(async move {
                *deliveries.lock().expect("delivery lock") += 1;
                Ok(CancelExecutionResult {
                    outcome: Some(cancel_execution_result::Outcome::Receipt(receipt)),
                })
            })
        }
    }

    struct ErrorTarget;

    impl HarnessCancellationDeliveryTarget for ErrorTarget {
        fn owns_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>
        {
            Box::pin(async { Err(HarnessCancellationDeliveryError::LiveBinding) })
        }

        fn deliver_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(HarnessCancellationDeliveryError::LiveBinding) })
        }
    }

    fn handoff() -> TaskCancellationHandoff {
        TaskCancellationHandoff {
            message_id: "outbox-1".to_owned(),
            payload_digest_sha256: "a".repeat(64),
            cancellation_request_id: "cancel-1".to_owned(),
            requested_at: prost_types::Timestamp {
                seconds: 1,
                nanos: 0,
            },
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                task_id: "task-1".to_owned(),
                ..Default::default()
            },
        }
    }

    fn receipt(disposition: CancellationDeliveryDisposition) -> CancelExecutionReceipt {
        let mut receipt = CancelExecutionReceipt {
            receipt_id: "receipt-1".to_owned(),
            cancellation_request_id: "cancel-1".to_owned(),
            disposition: disposition as i32,
            ..Default::default()
        };
        receipt.receipt_digest_sha256 = hex::encode(Sha256::digest(receipt.encode_to_vec()));
        receipt
    }

    fn target(receipt: CancelExecutionReceipt) -> (Target, Arc<Mutex<u64>>) {
        let deliveries = Arc::new(Mutex::new(0));
        (
            Target {
                receipt,
                deliveries: Arc::clone(&deliveries),
            },
            deliveries,
        )
    }

    #[tokio::test]
    async fn delivered_interrupt_acknowledges_handoff_without_claiming_task_cancellation() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");
        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 1);
        assert!(report.held.is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 1);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn task_owned_settlement_skips_native_route_and_direct_ack() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(Reconciler(
            TaskCancellationReconciliation::SettledAndAcknowledged {
                status: egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::Cancelled,
                committed: true,
                replayed: false,
            },
        )));

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 1);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert!(report.held.is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
    }

    #[tokio::test]
    async fn unknown_delivery_remains_unacknowledged_for_durable_recovery() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Unknown));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");
        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_DELIVERY_OUTCOME_UNKNOWN"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn altered_delivery_receipt_never_acknowledges_the_task_handoff() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let mut altered = receipt(CancellationDeliveryDisposition::Delivered);
        altered.receipt_digest_sha256 = "0".repeat(64);
        let (target, deliveries) = target(altered);
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_DELIVERY_RECEIPT_MISMATCH"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn route_lookup_error_blocks_a_matching_route_without_native_delivery() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![
                CancellationDeliveryRoute::new(Arc::new(ErrorTarget)),
                CancellationDeliveryRoute::new(Arc::new(target)),
            ],
        )
        .expect("worker");

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_ROUTE_UNAVAILABLE"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
    }
}
