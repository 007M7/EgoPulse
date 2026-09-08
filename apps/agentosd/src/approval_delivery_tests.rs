use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
};

use egopulse_domain_contracts::v01::egopulse::{
    harness::v1::{
        ApprovalDecision, ApprovalDecisionEnvelope, ApprovalDecisionReceipt,
        ApprovalDecisionResult, ApprovalKind, ApprovalRequestLifecycleKind,
        ApprovalRequestObservation, DeliveryDisposition, DispatchEnvelope, HarnessObservation,
        ObservationCriticality, approval_decision_result, harness_observation,
    },
    policy::v1::{
        HarnessApprovalRequestBinding, PolicyDecisionCommandResult, PolicyDecisionErrorCode,
    },
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DurableWritePreparation, GovernedAdapterError,
};
use egopulse_local_ide_control::collaboration_control::HarnessApprovalDeliveryTarget;
use prost::Message;
use tempfile::TempDir;

use crate::approval_delivery::{
    ApprovalDeliveryCycleError, ApprovalDeliveryRoute, ApprovalDeliverySource,
    ApprovalDeliveryWorker, PendingApprovalDelivery,
};

struct FixtureSource {
    pending: Vec<PendingApprovalDelivery>,
    consumed: Mutex<Vec<ApprovalDecisionReceipt>>,
    consume_result: PolicyDecisionCommandResult,
}

impl ApprovalDeliverySource for FixtureSource {
    fn pending_approval_deliveries(
        &self,
    ) -> Result<Vec<PendingApprovalDelivery>, ApprovalDeliveryCycleError> {
        let consumed = self.consumed.lock().expect("fixture consumed lock");
        Ok(self
            .pending
            .iter()
            .filter(|delivery| {
                !self.consume_result.committed
                    || !consumed.iter().any(|receipt| {
                        receipt.approval_request_id == delivery.envelope.approval_request_id
                    })
            })
            .cloned()
            .collect())
    }

    fn consume_delivered_approval(
        &self,
        _delivery: &PendingApprovalDelivery,
        receipt: ApprovalDecisionReceipt,
        _harness_adapter_principal_id: &str,
    ) -> Result<PolicyDecisionCommandResult, ApprovalDeliveryCycleError> {
        self.consumed
            .lock()
            .expect("fixture consume lock")
            .push(receipt);
        Ok(self.consume_result.clone())
    }
}

struct FixtureTarget {
    disposition: DeliveryDisposition,
    calls: Mutex<usize>,
}

impl HarnessApprovalDeliveryTarget for FixtureTarget {
    fn deliver_approval<'a>(
        &'a self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> Pin<
        Box<dyn Future<Output = Result<ApprovalDecisionResult, GovernedAdapterError>> + Send + 'a>,
    > {
        Box::pin(async move {
            *self.calls.lock().expect("fixture target lock") += 1;
            Ok(ApprovalDecisionResult {
                outcome: Some(approval_decision_result::Outcome::Receipt(
                    ApprovalDecisionReceipt {
                        receipt_id: "approval-receipt-001".to_owned(),
                        approval_request_id: envelope.approval_request_id.clone(),
                        decision: envelope.decision,
                        disposition: self.disposition as i32,
                        receipt_digest_sha256: "9".repeat(64),
                        delivered_at: Some(prost_types::Timestamp {
                            seconds: 20,
                            nanos: 0,
                        }),
                    },
                )),
            })
        })
    }
}

#[tokio::test]
async fn exact_profile_delivery_consumes_only_confirmed_receipt() {
    let fixture = approval_fixture("profile:codex:review");
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: committed_consume_result(),
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Delivered,
        calls: Mutex::new(0),
    });
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:review",
        "harness-adapter:codex",
        fixture.edge,
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");

    let report = worker.run_once().await.expect("delivery cycle");

    assert_eq!(report.delivered_and_consumed, 1);
    assert!(report.held.is_empty());
    assert_eq!(*target.calls.lock().expect("target calls"), 1);
    assert_eq!(source.consumed.lock().expect("consumed").len(), 1);
}

#[tokio::test]
async fn rejected_receipt_is_consumed_once_without_resending_after_reopen() {
    let mut fixture = approval_fixture("profile:codex:review");
    let receipt = record_durable_receipt(
        &mut fixture.edge,
        &fixture.delivery.envelope,
        DeliveryDisposition::Rejected,
    );
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: committed_consume_result(),
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Delivered,
        calls: Mutex::new(0),
    });
    drop(fixture.edge);
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:review",
        "harness-adapter:codex",
        open_edge(fixture._root.path()),
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("reopened route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");
    let first = worker.run_once().await.expect("consume rejected");
    assert_eq!(first.rejected_and_consumed, 1);
    assert_eq!(first.delivered_and_consumed, 0);
    assert!(first.held.is_empty());
    assert_eq!(
        source.consumed.lock().expect("consumed").as_slice(),
        &[receipt]
    );
    assert_eq!(
        worker
            .run_once()
            .await
            .expect("replay")
            .rejected_and_consumed,
        0
    );
    assert_eq!(*target.calls.lock().expect("native calls"), 0);
}

#[tokio::test]
async fn unknown_delivery_remains_held_and_is_never_consumed() {
    let fixture = approval_fixture("profile:codex:review");
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: committed_consume_result(),
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Unknown,
        calls: Mutex::new(0),
    });
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:review",
        "harness-adapter:codex",
        fixture.edge,
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");

    let first = worker.run_once().await.expect("first held cycle");
    let replay = worker.run_once().await.expect("replayed held cycle");

    assert_eq!(
        first.held[0].safe_reason_code,
        "APPROVAL_DELIVERY_UNKNOWN_RECOVERY_NOT_COMMITTED"
    );
    assert_eq!(
        replay.held[0].safe_reason_code,
        "APPROVAL_DELIVERY_UNKNOWN_RECOVERY_NOT_COMMITTED"
    );
    assert!(source.consumed.lock().expect("consumed").is_empty());
}

#[tokio::test]
async fn profile_mismatch_does_not_reach_native_target() {
    let fixture = approval_fixture("profile:codex:review");
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: committed_consume_result(),
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Delivered,
        calls: Mutex::new(0),
    });
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:other",
        "harness-adapter:codex",
        fixture.edge,
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");

    let report = worker.run_once().await.expect("held cycle");

    assert_eq!(
        report.held[0].safe_reason_code,
        "APPROVAL_DELIVERY_ROUTE_NOT_FOUND"
    );
    assert_eq!(*target.calls.lock().expect("target calls"), 0);
    assert!(source.consumed.lock().expect("consumed").is_empty());
}

#[tokio::test]
async fn expired_after_durable_delivery_never_resends_native_and_reports_policy_boundary() {
    let mut fixture = approval_fixture("profile:codex:review");
    fixture.delivery.expired = true;
    let receipt = record_durable_receipt(
        &mut fixture.edge,
        &fixture.delivery.envelope,
        DeliveryDisposition::Delivered,
    );
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: PolicyDecisionCommandResult {
            error_code: PolicyDecisionErrorCode::Expired as i32,
            safe_error_fingerprint: Some("policy/decision-expired/v1".to_owned()),
            ..PolicyDecisionCommandResult::default()
        },
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Delivered,
        calls: Mutex::new(0),
    });
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:review",
        "harness-adapter:codex",
        fixture.edge,
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");

    let report = worker.run_once().await.expect("expired recovery cycle");

    assert_eq!(*target.calls.lock().expect("target calls"), 0);
    assert_eq!(
        source.consumed.lock().expect("consume attempts").as_slice(),
        &[receipt]
    );
    assert_eq!(
        report.held[0].safe_reason_code,
        "APPROVAL_DELIVERED_RECEIPT_POLICY_EXPIRED"
    );
}

#[tokio::test]
async fn expired_unknown_receipt_is_held_without_native_or_policy_delivery() {
    let mut fixture = approval_fixture("profile:codex:review");
    fixture.delivery.expired = true;
    record_durable_receipt(
        &mut fixture.edge,
        &fixture.delivery.envelope,
        DeliveryDisposition::Unknown,
    );
    let source = Arc::new(FixtureSource {
        pending: vec![fixture.delivery],
        consumed: Mutex::new(Vec::new()),
        consume_result: committed_consume_result(),
    });
    let target = Arc::new(FixtureTarget {
        disposition: DeliveryDisposition::Delivered,
        calls: Mutex::new(0),
    });
    let route = ApprovalDeliveryRoute::new(
        "adapter:codex",
        "profile:codex:review",
        "harness-adapter:codex",
        fixture.edge,
        Arc::clone(&target) as Arc<dyn HarnessApprovalDeliveryTarget>,
    )
    .expect("route");
    let worker = ApprovalDeliveryWorker::new(
        Arc::clone(&source) as Arc<dyn ApprovalDeliverySource>,
        vec![route],
    )
    .expect("worker");

    let report = worker.run_once().await.expect("expired unknown cycle");

    assert_eq!(*target.calls.lock().expect("target calls"), 0);
    assert!(source.consumed.lock().expect("consume attempts").is_empty());
    assert_eq!(
        report.held[0].safe_reason_code,
        "APPROVAL_DELIVERY_UNKNOWN_RECOVERY_NOT_COMMITTED"
    );
}

struct ApprovalFixture {
    edge: AdapterEdge,
    delivery: PendingApprovalDelivery,
    _root: TempDir,
}

fn approval_fixture(capability_profile_id: &str) -> ApprovalFixture {
    let root = tempfile::tempdir().expect("temporary approval edge");
    let mut edge = open_edge(root.path());
    let envelope = DispatchEnvelope {
        dispatch_id: "dispatch-001".to_owned(),
        run_id: "run-001".to_owned(),
        run_revision: 1,
        step_id: "step-001".to_owned(),
        step_revision: 1,
        attempt_id: "attempt-001".to_owned(),
        attempt_revision: 1,
        fencing_token: 7,
        dispatch_fingerprint: "1".repeat(64),
        input_bundle_sha256: "2".repeat(64),
        ..DispatchEnvelope::default()
    };
    edge.prepare_dispatch(&envelope, 10)
        .expect("prepare dispatch");
    edge.append_observation(
        &envelope.dispatch_id,
        "native-approval-001",
        b"approval request",
        HarnessObservation {
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            capability_profile_id: capability_profile_id.to_owned(),
            criticality: ObservationCriticality::Security as i32,
            payload: Some(harness_observation::Payload::ApprovalRequest(
                ApprovalRequestObservation {
                    approval_request_id: "approval-request-001".to_owned(),
                    kind: ApprovalKind::Command as i32,
                    action_digest_sha256: "8".repeat(64),
                    requested_scope_ref: "scope:task:command-001".to_owned(),
                    display_summary_ref: "summary:command-001".to_owned(),
                    display_summary: None,
                    native_routing_ref: "native-routing-001".to_owned(),
                    lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                    request_revision: 1,
                },
            )),
            ..HarnessObservation::default()
        },
        11,
    )
    .expect("append approval observation");
    let projection = edge
        .pending_approval_projection_messages()
        .expect("approval projection")
        .remove(0);
    let decision = ApprovalDecisionEnvelope {
        attempt_id: envelope.attempt_id.clone(),
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
        approval_request_id: "approval-request-001".to_owned(),
        action_digest_sha256: "8".repeat(64),
        decision: ApprovalDecision::AllowOnce as i32,
        authority_decision_ref: "policy-decision-001".to_owned(),
        native_routing_ref: "native-routing-001".to_owned(),
        ..ApprovalDecisionEnvelope::default()
    };
    ApprovalFixture {
        edge,
        delivery: PendingApprovalDelivery {
            source_event_id: "policy-event-001".to_owned(),
            envelope: decision,
            request: HarnessApprovalRequestBinding {
                adapter_id: "adapter:codex".to_owned(),
                attempt_id: envelope.attempt_id,
                dispatch_id: envelope.dispatch_id,
                fencing_token: envelope.fencing_token,
                approval_request_id: "approval-request-001".to_owned(),
                kind: ApprovalKind::Command as i32,
                action_digest_sha256: "8".repeat(64),
                requested_scope_ref: "scope:task:command-001".to_owned(),
                native_routing_ref: "native-routing-001".to_owned(),
                request_observation_id: projection.source_observation_id,
                request_observation_sequence: projection.source_revision,
                request_lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                request_revision: 1,
            },
            expected_state_revision: 1,
            expired: false,
        },
        _root: root,
    }
}

fn open_edge(root: &Path) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.join("approval-edge.db"),
        adapter_id: "adapter:codex".to_owned(),
        store_epoch: "approval-edge-test-v1".to_owned(),
        key: AdapterEdgeKey::new([0x61; 32]),
    })
    .expect("open approval edge")
}

fn committed_consume_result() -> PolicyDecisionCommandResult {
    PolicyDecisionCommandResult {
        committed: true,
        ..PolicyDecisionCommandResult::default()
    }
}

fn record_durable_receipt(
    edge: &mut AdapterEdge,
    envelope: &ApprovalDecisionEnvelope,
    disposition: DeliveryDisposition,
) -> ApprovalDecisionReceipt {
    let receipt = ApprovalDecisionReceipt {
        receipt_id: "approval-receipt-expired-001".to_owned(),
        approval_request_id: envelope.approval_request_id.clone(),
        decision: envelope.decision,
        disposition: disposition as i32,
        receipt_digest_sha256: "9".repeat(64),
        delivered_at: Some(prost_types::Timestamp {
            seconds: 12,
            nanos: 0,
        }),
    };
    assert_eq!(
        edge.prepare_approval(
            &envelope.approval_request_id,
            &envelope.dispatch_id,
            &"7".repeat(64),
            12,
        )
        .expect("prepare durable approval"),
        DurableWritePreparation::Ready
    );
    edge.begin_approval(&envelope.approval_request_id, 12)
        .expect("begin durable approval");
    edge.record_approval_receipt(
        &envelope.approval_request_id,
        match disposition {
            DeliveryDisposition::Delivered => "delivered",
            DeliveryDisposition::Rejected => "rejected",
            _ => "delivery_unknown",
        },
        &receipt.encode_to_vec(),
        b"native delivery evidence",
        12,
    )
    .expect("record durable approval receipt");
    receipt
}
