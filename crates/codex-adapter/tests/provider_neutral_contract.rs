use egopulse_codex_adapter::{
    CODEX_APP_SERVER_SCHEMA_SHA256, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig,
    CodexAppServerDriver, FakeCodexDriver, codex_protocol_fingerprint,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalDecisionEnvelope, CancelExecutionEnvelope,
    CancellationDeliveryDisposition, DeliveryDisposition, DispatchEnvelope, HarnessReadiness,
    LifecycleKind, NativeSessionStrategy, ProbeHarnessRequest, approval_decision_result,
    cancel_execution_result, dispatch_result, harness_observation,
};
use egopulse_harness_adapter::{
    AdapterClock, AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DispatchMaterialResolver,
    GovernedHarnessAdapter, NativeHarnessDriver, ReconciliationFinding, ResolvedDispatchMaterial,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy)]
struct FixedClock;

impl AdapterClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: 1_787_488_000,
            nanos: 0,
        }
    }
}

#[derive(Clone)]
struct FixtureResolver {
    workspace: PathBuf,
    bundle: Vec<u8>,
}

impl DispatchMaterialResolver for FixtureResolver {
    fn resolve(
        &self,
        _envelope: &DispatchEnvelope,
    ) -> Result<
        ResolvedDispatchMaterial,
        egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessError,
    > {
        Ok(ResolvedDispatchMaterial {
            canonical_input_bundle: self.bundle.clone(),
            prompt: "Return the provider-neutral fixture result".to_owned(),
            workspace_root: self.workspace.clone(),
            model: None,
        })
    }
}

struct IsolatedRoot(PathBuf);

impl IsolatedRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create adapter contract fixture directory");
        Self(path)
    }
}

impl Drop for IsolatedRoot {
    fn drop(&mut self) {
        let temp = std::env::temp_dir();
        assert!(self.0.starts_with(&temp));
        if self.0.exists() {
            for _ in 0..10 {
                if fs::remove_dir_all(&self.0).is_ok() || !self.0.exists() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            eprintln!(
                "adapter fixture cleanup deferred because a supervised process still holds {}",
                self.0.display()
            );
        }
    }
}

fn open_edge(path: &Path) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path.join("adapter-edge.sqlcipher"),
        adapter_id: "codex-adapter:test".to_owned(),
        store_epoch: "codex-contract-fixture-v1".to_owned(),
        key: AdapterEdgeKey::new([0x2d; 32]),
    })
    .expect("open fixture adapter edge")
}

fn envelope(bundle: &[u8]) -> DispatchEnvelope {
    DispatchEnvelope {
        run_id: "run-001".to_owned(),
        run_revision: 5,
        step_id: "step-001".to_owned(),
        step_revision: 4,
        attempt_id: "attempt-001".to_owned(),
        attempt_revision: 3,
        dispatch_id: "dispatch-001".to_owned(),
        dispatch_fingerprint: "1".repeat(64),
        fencing_token: 1,
        capability_profile_ref: Some(ContractReference {
            contract_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
            version: "0.1".to_owned(),
            sha256: "2".repeat(64),
        }),
        input_bundle_ref: "bundle-001".to_owned(),
        input_bundle_sha256: hex::encode(Sha256::digest(bundle)),
        workspace_ref: "workspace-001".to_owned(),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        ..DispatchEnvelope::default()
    }
}

#[tokio::test]
async fn fake_codex_consumes_the_same_provider_neutral_contract_and_replays_durably() {
    let root = IsolatedRoot::new("fake-codex-contract");
    let bundle = br#"{"input":"fixture"}"#.to_vec();
    let resolver = FixtureResolver {
        workspace: root.0.clone(),
        bundle: bundle.clone(),
    };
    let dispatch = envelope(&bundle);
    let mut adapter = GovernedHarnessAdapter::new(
        "codex-adapter:test",
        CODEX_CAPABILITY_PROFILE_ID,
        codex_protocol_fingerprint(),
        open_edge(&root.0),
        resolver.clone(),
        FakeCodexDriver::default(),
        FixedClock,
    );

    let first = adapter.dispatch(&dispatch).await.expect("dispatch fixture");
    let first_receipt = match first.outcome.expect("dispatch outcome") {
        dispatch_result::Outcome::Receipt(receipt) => receipt,
        dispatch_result::Outcome::Error(error) => panic!("unexpected dispatch error: {error:?}"),
    };
    assert_eq!(
        first_receipt.disposition,
        DeliveryDisposition::Delivered as i32
    );
    assert_eq!(adapter.driver().dispatch_count(), 1);

    let replay = adapter.dispatch(&dispatch).await.expect("replay dispatch");
    let replay_receipt = match replay.outcome.expect("replay outcome") {
        dispatch_result::Outcome::Receipt(receipt) => receipt,
        dispatch_result::Outcome::Error(error) => panic!("unexpected replay error: {error:?}"),
    };
    assert_eq!(first_receipt.receipt_id, replay_receipt.receipt_id);
    assert_eq!(adapter.driver().dispatch_count(), 1);

    let mut observations = Vec::new();
    for _ in 0..3 {
        observations.push(
            adapter
                .pump_one(&dispatch)
                .await
                .expect("pump fixture event")
                .expect("fixture event"),
        );
    }
    assert_eq!(
        observations
            .iter()
            .map(|value| value.observation_sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(matches!(
        observations[0].payload,
        Some(harness_observation::Payload::Ack(_))
    ));
    assert!(matches!(
        observations[1].payload,
        Some(harness_observation::Payload::Lifecycle(ref value))
            if value.kind == LifecycleKind::ExecutionStarted as i32
    ));
    assert!(matches!(
        observations[2].payload,
        Some(harness_observation::Payload::Lifecycle(ref value))
            if value.kind == LifecycleKind::ExecutionCompleted as i32
    ));

    let approval = adapter
        .decide_approval(&ApprovalDecisionEnvelope {
            attempt_id: dispatch.attempt_id.clone(),
            dispatch_id: dispatch.dispatch_id.clone(),
            fencing_token: dispatch.fencing_token,
            approval_request_id: "approval-001".to_owned(),
            action_digest_sha256: "3".repeat(64),
            decision: ApprovalDecision::AllowOnce as i32,
            authority_decision_ref: "founder-decision:001".to_owned(),
            native_routing_ref: "fake-routing:001".to_owned(),
            ..ApprovalDecisionEnvelope::default()
        })
        .await
        .expect("deliver approval");
    assert!(matches!(
        approval.outcome,
        Some(approval_decision_result::Outcome::Receipt(ref receipt))
            if receipt.disposition == DeliveryDisposition::Delivered as i32
    ));

    let cancellation = adapter
        .cancel_dispatch(
            "cancel-001",
            &dispatch.dispatch_id,
            Timestamp {
                seconds: 1_787_488_010,
                nanos: 0,
            },
        )
        .await
        .expect("deliver cancellation");
    assert!(matches!(
        cancellation.outcome,
        Some(cancel_execution_result::Outcome::Receipt(ref receipt))
            if receipt.disposition == CancellationDeliveryDisposition::Delivered as i32
    ));
    assert_eq!(adapter.driver().cancel_count(), 1);
    let interrupted = adapter
        .pump_one(&dispatch)
        .await
        .expect("pump interruption")
        .expect("interruption event");
    assert!(matches!(
        interrupted.payload,
        Some(harness_observation::Payload::Lifecycle(ref value))
            if value.kind == LifecycleKind::ExecutionInterrupted as i32
    ));

    let reconciliation = adapter
        .reconcile_dispatch("reconcile-001", &dispatch.dispatch_id)
        .await
        .expect("reconcile fixture");
    assert!(matches!(
        reconciliation.finding,
        ReconciliationFinding::TerminalObservationRecovered { .. }
    ));
    assert!(!reconciliation.replayed);
    assert_eq!(adapter.driver().reconcile_count(), 1);
    let replayed_reconciliation = adapter
        .reconcile_dispatch("reconcile-001", &dispatch.dispatch_id)
        .await
        .expect("replay reconciliation fixture");
    assert!(replayed_reconciliation.replayed);
    assert_eq!(
        replayed_reconciliation.evidence_id,
        reconciliation.evidence_id
    );
    assert_eq!(adapter.driver().reconcile_count(), 1);
    assert_eq!(
        adapter
            .reconciliation_evidence("reconcile-001", &dispatch.dispatch_id)
            .expect("resolve reconciliation evidence")
            .expect("durable reconciliation evidence")
            .evidence_id,
        reconciliation.evidence_id
    );
    assert_eq!(
        adapter
            .observations_after(0)
            .expect("read durable events")
            .len(),
        5
    );
    assert!(adapter.edge().integrity_is_ok().expect("edge integrity"));

    let durable_evidence_id = reconciliation.evidence_id;
    drop(adapter);
    let mut recovered = GovernedHarnessAdapter::new(
        "codex-adapter:test",
        CODEX_CAPABILITY_PROFILE_ID,
        codex_protocol_fingerprint(),
        open_edge(&root.0),
        resolver,
        FakeCodexDriver::default(),
        FixedClock,
    );
    let recovered_reconciliation = recovered
        .reconcile_dispatch("reconcile-001", &dispatch.dispatch_id)
        .await
        .expect("recover durable reconciliation evidence");
    assert!(recovered_reconciliation.replayed);
    assert_eq!(recovered_reconciliation.evidence_id, durable_evidence_id);
    assert_eq!(recovered.driver().reconcile_count(), 0);
}

#[tokio::test]
#[ignore = "requires an authenticated local Codex 0.148.0-alpha.15 installation"]
async fn live_codex_app_server_emits_contract_valid_ack_running_and_terminal_observations() {
    let executable = PathBuf::from(
        std::env::var_os("EGOPULSE_CODEX_NATIVE_EXE")
            .expect("EGOPULSE_CODEX_NATIVE_EXE must point to the pinned native Codex executable"),
    );
    assert!(executable.is_absolute());
    let root = IsolatedRoot::new("live-codex-contract");
    let bundle = br#"{"input":"live-contract-probe","tools":"forbidden"}"#.to_vec();
    let resolver = FixtureResolver {
        workspace: root.0.clone(),
        bundle: bundle.clone(),
    };
    let dispatch = envelope(&bundle);
    let mut config = CodexAppServerConfig::new(executable);
    config.request_timeout = Duration::from_secs(30);
    let mut adapter = GovernedHarnessAdapter::new(
        "codex-adapter:live-test",
        CODEX_CAPABILITY_PROFILE_ID,
        codex_protocol_fingerprint(),
        open_edge(&root.0),
        resolver,
        CodexAppServerDriver::new(config),
        FixedClock,
    );

    let probe = adapter
        .probe(&ProbeHarnessRequest {
            adapter_id: "codex-adapter:live-test".to_owned(),
            expected_protocol_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
            ..ProbeHarnessRequest::default()
        })
        .await;
    assert_eq!(probe.readiness, HarnessReadiness::Ready as i32, "{probe:?}");

    let delivered = adapter.dispatch(&dispatch).await.expect("live dispatch");
    assert!(
        matches!(
            &delivered.outcome,
            Some(dispatch_result::Outcome::Receipt(receipt))
                if receipt.disposition == DeliveryDisposition::Delivered as i32
        ),
        "live dispatch was not delivered: {delivered:?}"
    );

    let mut saw_ack = false;
    let mut saw_running = false;
    let mut saw_terminal = false;
    let mut cancel_sent = false;
    let mut native_session_ref = None;
    let mut native_execution_ref = None;
    for _ in 0..100 {
        let Some(observation) = adapter
            .pump_one(&dispatch)
            .await
            .expect("consume live Codex observation")
        else {
            continue;
        };
        match observation.payload {
            Some(harness_observation::Payload::Ack(value)) => {
                eprintln!("live-codex-observation=ack");
                saw_ack |= value.disposition
                    == egopulse_domain_contracts::v01::egopulse::harness::v1::AckDisposition::Accepted
                        as i32;
                native_session_ref = value.native_session_ref;
                native_execution_ref = value.native_execution_ref;
            }
            Some(harness_observation::Payload::Lifecycle(value)) => {
                eprintln!("live-codex-observation=lifecycle:{}", value.kind);
                saw_running |= value.kind == LifecycleKind::ExecutionStarted as i32;
                saw_terminal |= matches!(
                    LifecycleKind::try_from(value.kind),
                    Ok(LifecycleKind::ExecutionCompleted
                        | LifecycleKind::ExecutionInterrupted
                        | LifecycleKind::ExecutionFailed)
                );
            }
            Some(harness_observation::Payload::ApprovalRequest(value)) => {
                eprintln!("live-codex-observation=approval-request");
                let decision = adapter
                    .decide_approval(&ApprovalDecisionEnvelope {
                        attempt_id: dispatch.attempt_id.clone(),
                        dispatch_id: dispatch.dispatch_id.clone(),
                        fencing_token: dispatch.fencing_token,
                        approval_request_id: value.approval_request_id,
                        action_digest_sha256: value.action_digest_sha256,
                        decision: ApprovalDecision::Deny as i32,
                        authority_decision_ref: "live-test-policy:deny".to_owned(),
                        native_routing_ref: value.native_routing_ref,
                        ..ApprovalDecisionEnvelope::default()
                    })
                    .await
                    .expect("deny unexpected live approval request");
                assert!(matches!(
                    decision.outcome,
                    Some(approval_decision_result::Outcome::Receipt(ref receipt))
                        if receipt.disposition == DeliveryDisposition::Delivered as i32
                ));
                if !cancel_sent {
                    let cancellation = adapter
                        .cancel(&CancelExecutionEnvelope {
                            attempt_id: dispatch.attempt_id.clone(),
                            dispatch_id: dispatch.dispatch_id.clone(),
                            fencing_token: dispatch.fencing_token,
                            cancellation_request_id: "live-cancel-after-denial".to_owned(),
                            native_session_ref: native_session_ref
                                .clone()
                                .expect("ACK native session ref before approval"),
                            native_execution_ref: native_execution_ref
                                .clone()
                                .expect("ACK native execution ref before approval"),
                            confirmation_deadline: Some(Timestamp {
                                seconds: 1_787_488_030,
                                nanos: 0,
                            }),
                            ..CancelExecutionEnvelope::default()
                        })
                        .await
                        .expect("deliver live cancellation after approval denial");
                    assert!(matches!(
                        cancellation.outcome,
                        Some(cancel_execution_result::Outcome::Receipt(ref receipt))
                            if receipt.disposition
                                == CancellationDeliveryDisposition::Delivered as i32
                    ));
                    cancel_sent = true;
                }
            }
            Some(harness_observation::Payload::Diagnostic(value)) => {
                eprintln!(
                    "live-codex-observation=diagnostic:{}",
                    value.safe_diagnostic_code
                );
                assert!(
                    !value.recovery_required,
                    "live Codex entered recovery-required diagnostic: {}; native method={:?}",
                    value.safe_diagnostic_code,
                    adapter.driver().last_protocol_diagnostic()
                );
            }
            _ => {}
        }
        if saw_ack && saw_running && saw_terminal {
            break;
        }
    }
    assert!(saw_ack, "live Codex did not emit a contract-valid ACK");
    assert!(saw_running, "live Codex did not emit execution_started");
    assert!(
        cancel_sent,
        "live Codex did not exercise governed cancellation"
    );
    assert!(
        saw_terminal,
        "live Codex did not emit a terminal lifecycle event"
    );
    assert!(
        adapter
            .edge()
            .integrity_is_ok()
            .expect("live edge integrity")
    );
}

#[tokio::test]
#[ignore = "diagnostic companion for the authenticated local Codex installation"]
async fn live_codex_native_driver_accepts_the_pinned_dispatch_shape() {
    let executable = PathBuf::from(
        std::env::var_os("EGOPULSE_CODEX_NATIVE_EXE")
            .expect("EGOPULSE_CODEX_NATIVE_EXE must be set"),
    );
    let root = IsolatedRoot::new("live-codex-driver");
    let bundle = b"live-driver".to_vec();
    let resolver = FixtureResolver {
        workspace: root.0.clone(),
        bundle: bundle.clone(),
    };
    let dispatch = envelope(&bundle);
    let material = resolver.resolve(&dispatch).expect("resolve live material");
    let mut config = CodexAppServerConfig::new(executable);
    config.request_timeout = Duration::from_secs(120);
    let mut driver = CodexAppServerDriver::new(config);
    driver
        .send_dispatch(&dispatch, &material)
        .await
        .expect("native Codex dispatch shape must be accepted");
}
