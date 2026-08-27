use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DeliveryDisposition, DispatchEnvelope, DispatchReceipt, NativeProtocolFingerprint,
};
use egopulse_dsh_adapter::{
    DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF, DshAcpConfig, DshAcpDriver,
};
use egopulse_harness_adapter::{
    AdapterClock, AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DispatchMaterialResolver,
    DispatchPreparation, GovernedHarnessAdapter, ReconciliationFinding, ResolvedDispatchMaterial,
};
use prost_types::Timestamp;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
struct FixedClock;

impl AdapterClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: 1_787_500_000,
            nanos: 0,
        }
    }
}

struct StaticResolver {
    material: ResolvedDispatchMaterial,
}

impl DispatchMaterialResolver for StaticResolver {
    fn resolve(
        &self,
        _envelope: &DispatchEnvelope,
    ) -> Result<
        ResolvedDispatchMaterial,
        egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessError,
    > {
        Ok(self.material.clone())
    }
}

struct Isolated {
    root: PathBuf,
}

impl Isolated {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("egopulse-dsh-recovery-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create isolated DSH recovery root");
        Self { root }
    }

    fn edge_path(&self) -> PathBuf {
        self.root.join("adapter.sqlcipher")
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        assert!(self.root.starts_with(std::env::temp_dir()));
        if self.root.exists() {
            std::fs::remove_dir_all(&self.root).expect("remove isolated DSH recovery root");
        }
    }
}

fn open_edge(path: &Path) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path.to_path_buf(),
        adapter_id: "dsh-adapter".to_owned(),
        store_epoch: "dsh-recovery-hold".to_owned(),
        key: AdapterEdgeKey::new([0x66; 32]),
    })
    .expect("open DSH recovery Adapter Edge")
}

fn envelope() -> DispatchEnvelope {
    DispatchEnvelope {
        run_id: "run-dsh-recovery".to_owned(),
        run_revision: 1,
        step_id: "step-dsh-recovery".to_owned(),
        step_revision: 1,
        attempt_id: "attempt-dsh-recovery".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch-dsh-recovery".to_owned(),
        dispatch_fingerprint: "1".repeat(64),
        capability_profile_ref: Some(
            egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                contract_id: "dsh-candidate-profile".to_owned(),
                version: "v1".to_owned(),
                sha256: "2".repeat(64),
            },
        ),
        input_bundle_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        workspace_ref: "workspace-dsh-recovery".to_owned(),
        fencing_token: 1,
        ..Default::default()
    }
}

fn unknown_delivery_receipt(value: &DispatchEnvelope) -> DispatchReceipt {
    DispatchReceipt {
        receipt_id: "receipt-dsh-recovery-unknown".to_owned(),
        disposition: DeliveryDisposition::Unknown as i32,
        attempt_id: value.attempt_id.clone(),
        dispatch_id: value.dispatch_id.clone(),
        fencing_token: value.fencing_token,
        adapter_id: "dsh-adapter".to_owned(),
        capability_profile_id: "dsh-candidate-profile".to_owned(),
        observed_protocol: Some(NativeProtocolFingerprint {
            protocol_name: "agent-client-protocol".to_owned(),
            protocol_version: "v1".to_owned(),
            schema_sha256: "3".repeat(64),
            adapter_version: "egopulse-dsh-adapter".to_owned(),
            native_executable_version: "dsh-replay".to_owned(),
            native_binary_sha256: None,
        }),
        receipt_digest_sha256: "4".repeat(64),
        evidence_ref: "dsh-delivery-unknown".to_owned(),
        ..Default::default()
    }
}

fn adapter(edge: AdapterEdge) -> GovernedHarnessAdapter<StaticResolver, DshAcpDriver, FixedClock> {
    GovernedHarnessAdapter::new(
        "dsh-adapter",
        "dsh-candidate-profile",
        NativeProtocolFingerprint {
            protocol_name: "agent-client-protocol".to_owned(),
            protocol_version: "v1".to_owned(),
            schema_sha256: "3".repeat(64),
            adapter_version: "egopulse-dsh-adapter".to_owned(),
            native_executable_version: "dsh-replay".to_owned(),
            native_binary_sha256: None,
        },
        edge,
        StaticResolver {
            material: ResolvedDispatchMaterial {
                canonical_input_bundle: Vec::new(),
                prompt: "reconcile without native resume".to_owned(),
                workspace_root: std::env::current_dir().expect("current directory"),
                model: None,
            },
        },
        DshAcpDriver::new(DshAcpConfig::new(
            "dsh-not-started-for-reconcile",
            std::env::current_dir().expect("current directory"),
        )),
        FixedClock,
    )
}

#[tokio::test]
async fn dsh_unknown_recovery_is_durable_and_never_auto_redispatched() {
    let isolated = Isolated::new();
    let value = envelope();

    let mut edge = open_edge(&isolated.edge_path());
    assert!(matches!(
        edge.prepare_dispatch(&value, 1),
        Ok(DispatchPreparation::Ready)
    ));
    edge.begin_delivery(&value.dispatch_id, 2)
        .expect("begin uncertain delivery");
    edge.record_dispatch_receipt(&unknown_delivery_receipt(&value), b"delivery-unknown", 3)
        .expect("record uncertain delivery");

    let first = adapter(edge)
        .reconcile_dispatch("reconcile-dsh-recovery", &value.dispatch_id)
        .await
        .expect("persist explicit recovery hold");
    assert!(!first.replayed);
    assert!(matches!(
        first.finding,
        ReconciliationFinding::OutcomeUnknown { evidence_ref }
            if evidence_ref == DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF
    ));

    let second = adapter(open_edge(&isolated.edge_path()))
        .reconcile_dispatch("reconcile-dsh-recovery", &value.dispatch_id)
        .await
        .expect("replay explicit recovery hold");
    assert!(second.replayed);
    assert!(matches!(
        second.finding,
        ReconciliationFinding::OutcomeUnknown { evidence_ref }
            if evidence_ref == DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF
    ));
}
