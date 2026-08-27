use egopulse_agentosd::{GovernedReturnCollectorConfig, GovernedReturnCollectorRunner};
use egopulse_artifact_authority::{
    AdmissionRejection, ArtifactAdmissionGuard, ArtifactAuthority, ArtifactAuthorityConfig,
    ArtifactClock, ArtifactSqlCipherKey, AuthenticatedArtifactPrincipal,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ArtifactDescriptor, ArtifactSet, Claim, Evidence, ReturnHandoff},
    common::v1::ContractReference,
    harness::v1::{
        DeliveryDisposition, DispatchEnvelope, DispatchReceipt, HarnessError,
        NativeProtocolFingerprint, dispatch_result,
    },
};
use egopulse_dsh_adapter::{DshAcpConfig, DshAcpDriver};
use egopulse_harness_adapter::{
    AdapterClock, AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DispatchMaterialResolver,
    GovernedHarnessAdapter, ResolvedDispatchMaterial,
};
use egopulse_local_ide_control::collaboration_control::{
    HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
};
use prost_types::Timestamp;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy)]
struct FixedClock;

impl ArtifactClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: 1_787_500_000,
            nanos: 0,
        }
    }
}

impl AdapterClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: 1_787_500_000,
            nanos: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct AllowGuard;

impl ArtifactAdmissionGuard for AllowGuard {
    fn validate_artifact(
        &self,
        _artifact: &ArtifactDescriptor,
        bytes: &[u8],
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        (!bytes.is_empty())
            .then_some(())
            .ok_or(AdmissionRejection::InvalidArgument)
    }

    fn validate_claim(
        &self,
        _claim: &Claim,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        Ok(())
    }

    fn validate_evidence(
        &self,
        _evidence: &Evidence,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        Ok(())
    }

    fn validate_artifact_set(
        &self,
        _artifact_set: &ArtifactSet,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        Ok(())
    }

    fn validate_return_handoff(
        &self,
        _handoff: &ReturnHandoff,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        Ok(())
    }
}

struct StaticResolver {
    material: ResolvedDispatchMaterial,
}

impl DispatchMaterialResolver for StaticResolver {
    fn resolve(
        &self,
        _envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError> {
        Ok(self.material.clone())
    }
}

struct NoopHarness;

impl HarnessDispatchRunner for NoopHarness {
    fn run_once(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { Ok(HarnessDispatchCycleReport::default()) })
    }
}

struct Isolated {
    root: PathBuf,
}

impl Isolated {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("egopulse-dsh-return-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create isolated DSH return root");
        Self { root }
    }

    fn edge_path(&self) -> PathBuf {
        self.root.join("adapter.sqlcipher")
    }

    fn artifact_path(&self) -> PathBuf {
        self.root.join("artifact.sqlcipher")
    }

    fn blob_root(&self) -> PathBuf {
        self.root.join("blobs")
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        assert!(self.root.starts_with(std::env::temp_dir()));
        if self.root.exists() {
            let mut last_error = None;
            for _ in 0..20 {
                match std::fs::remove_dir_all(&self.root) {
                    Ok(()) => return,
                    Err(error) => {
                        last_error = Some(error);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            panic!("remove isolated DSH return root: {:?}", last_error);
        }
    }
}

fn reference(id: &str, marker: char) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: marker.to_string().repeat(64),
    }
}

fn collector_config() -> GovernedReturnCollectorConfig {
    GovernedReturnCollectorConfig {
        artifact_type_ref: reference("dsh-output-type", 'a'),
        transformation_contract_ref: reference("governed-capture", 'b'),
        retention_profile_ref: reference("local-retention", 'c'),
        claim_semantic_profile_ref: reference("capture-claim", 'd'),
        claim_acceptance_contract_ref: reference("capture-acceptance", 'e'),
        evidence_profile_ref: reference("capture-evidence", 'f'),
        workspace_ref: "workspace-dsh-return".to_owned(),
        collector_principal_id: "collector:dsh-terminal".to_owned(),
        artifact_authority_principal_id: "authority:artifact".to_owned(),
    }
}

fn replay_config(
    root: &Path,
    node: PathBuf,
    home: &Path,
    working_directory: &Path,
) -> DshAcpConfig {
    let mut config = DshAcpConfig::new(node, working_directory)
        .with_argument(
            root.join("packages/examples/acp-demo/lib/bin.js")
                .display()
                .to_string(),
        )
        .with_argument("--config")
        .with_argument(
            root.join("examples/acp-agent/cordis.yml")
                .display()
                .to_string(),
        )
        .with_environment_override("DSH_SNAPSHOT", "replay")
        .with_environment_override(
            "DSH_SNAPSHOT_FILE",
            root.join("examples/acp-agent/tests/snapshots/multi-turn/session.jsonl")
                .display()
                .to_string(),
        )
        .with_environment_override(
            "DSH_SNAPSHOT_SESSIONS_ROOT",
            home.join("sessions").display().to_string(),
        )
        .with_environment_override("DSH_HOME", home.join(".dsh").display().to_string());
    config.request_timeout = Duration::from_secs(15);
    config
}

fn open_edge(path: PathBuf) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path,
        adapter_id: "dsh-adapter".to_owned(),
        store_epoch: "dsh-return-settlement".to_owned(),
        key: AdapterEdgeKey::new([0x44; 32]),
    })
    .expect("open DSH Adapter Edge")
}

fn open_authority(isolated: &Isolated) -> ArtifactAuthority<AllowGuard, FixedClock> {
    ArtifactAuthority::open_with_clock(
        ArtifactAuthorityConfig {
            database_path: isolated.artifact_path(),
            blob_root: isolated.blob_root(),
            store_epoch: "dsh-return-settlement".to_owned(),
            key: ArtifactSqlCipherKey::new([0x55; 32]),
        },
        AllowGuard,
        FixedClock,
    )
    .expect("open DSH Artifact Authority")
}

fn envelope(workspace_ref: &str) -> DispatchEnvelope {
    DispatchEnvelope {
        run_id: "run-dsh-return".to_owned(),
        run_revision: 1,
        step_id: "step-dsh-return".to_owned(),
        step_revision: 1,
        attempt_id: "attempt-dsh-return".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch-dsh-return".to_owned(),
        dispatch_fingerprint: "1".repeat(64),
        capability_profile_ref: Some(reference("dsh-candidate-profile", '3')),
        input_bundle_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_owned(),
        workspace_ref: workspace_ref.to_owned(),
        fencing_token: 1,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires an explicitly configured local DSH replay workspace"]
async fn dsh_terminal_output_reaches_governed_return_settlement() {
    let root = std::env::var_os("EGOPULSE_DSH_REPLAY_ROOT")
        .map(PathBuf::from)
        .expect("EGOPULSE_DSH_REPLAY_ROOT must point to DSH source");
    let node = std::env::var_os("EGOPULSE_DSH_NODE")
        .map(PathBuf::from)
        .expect("EGOPULSE_DSH_NODE must point to node");
    let isolated = Isolated::new();
    let workspace = isolated.root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create DSH workspace");
    let home = isolated.root.join("dsh-home");
    let envelope = envelope("workspace-dsh-return");
    let material = ResolvedDispatchMaterial {
        canonical_input_bundle: Vec::new(),
        prompt: "Reply with the fixture response. No tools.".to_owned(),
        workspace_root: workspace.clone(),
        model: None,
    };

    let mut writer_edge = open_edge(isolated.edge_path());
    writer_edge
        .prepare_dispatch(&envelope, 1)
        .expect("prepare DSH return dispatch");
    writer_edge
        .bind_dispatch_task_lineage(&envelope.dispatch_id, "task-dsh-return", 1, 1, 1)
        .expect("bind DSH return lineage");
    let driver = DshAcpDriver::new(replay_config(&root, node, &home, &workspace));
    let mut adapter = GovernedHarnessAdapter::new(
        "dsh-adapter",
        "dsh-candidate-profile",
        NativeProtocolFingerprint {
            protocol_name: "agent-client-protocol".to_owned(),
            protocol_version: "v1".to_owned(),
            schema_sha256: "4".repeat(64),
            adapter_version: "egopulse-dsh-adapter".to_owned(),
            native_executable_version: "dsh-replay".to_owned(),
            native_binary_sha256: None,
        },
        writer_edge,
        StaticResolver { material },
        driver,
        FixedClock,
    );

    let dispatch = adapter
        .dispatch(&envelope)
        .await
        .expect("governed DSH dispatch");
    assert!(matches!(
        dispatch.outcome,
        Some(dispatch_result::Outcome::Receipt(DispatchReceipt {
            disposition,
            ..
        })) if disposition == DeliveryDisposition::Delivered as i32
    ));
    let observation = adapter
        .pump_one(&envelope)
        .await
        .expect("pump DSH terminal event")
        .expect("DSH terminal observation");
    assert_eq!(observation.dispatch_id, envelope.dispatch_id);
    drop(adapter);

    let authority = Arc::new(Mutex::new(open_authority(&isolated)));
    let collector = GovernedReturnCollectorRunner::new(
        Arc::new(NoopHarness),
        open_edge(isolated.edge_path()),
        Arc::clone(&authority),
        collector_config(),
    )
    .expect("compose DSH return collector");
    let report = collector.run_once().await.expect("settle DSH return");
    assert_eq!(report.terminal_output_candidates_seen, 1);
    assert_eq!(report.terminal_output_candidates_receipted, 1);
    assert_eq!(report.terminal_output_candidates_held, 0);

    let inspection = authority
        .lock()
        .expect("Artifact Authority lock")
        .inspect_store()
        .expect("inspect DSH return authority");
    assert_eq!(inspection.artifact_count, 1);
    assert_eq!(inspection.claim_count, 1);
    assert_eq!(inspection.evidence_count, 1);
    assert_eq!(inspection.artifact_set_count, 1);
    assert_eq!(inspection.return_handoff_count, 1);
    assert_eq!(inspection.return_receipt_count, 1);
    assert!(
        open_edge(isolated.edge_path())
            .pending_terminal_output_candidates()
            .expect("inspect settled DSH candidate")
            .is_empty()
    );
}
