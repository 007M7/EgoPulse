use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    CancelExecutionEnvelope, DispatchEnvelope, LifecycleKind, harness_observation,
};
use egopulse_dsh_adapter::{DshAcpConfig, DshAcpDriver};
use egopulse_harness_adapter::{NativeHarnessDriver, ResolvedDispatchMaterial};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn required_env(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the isolated DSH replay input"))
}

fn replay_config(
    root: &Path,
    node: PathBuf,
    scenario: &str,
    home: &Path,
    working_directory: &Path,
) -> DshAcpConfig {
    let binary = root.join("packages/examples/acp-demo/lib/bin.js");
    let config = root.join("examples/acp-agent/cordis.yml");
    let fixture = root.join(format!(
        "examples/acp-agent/tests/snapshots/{scenario}/session.jsonl"
    ));
    let mut result = DshAcpConfig::new(node, working_directory)
        .with_argument(binary.display().to_string())
        .with_argument("--config")
        .with_argument(config.display().to_string())
        .with_environment_override("DSH_SNAPSHOT", "replay")
        .with_environment_override("DSH_SNAPSHOT_FILE", fixture.display().to_string())
        .with_environment_override(
            "DSH_SNAPSHOT_SESSIONS_ROOT",
            home.join("sessions").display().to_string(),
        )
        .with_environment_override("DSH_HOME", home.join(".dsh").display().to_string());
    if scenario == "cancel" {
        result = result.with_environment_override(
            "DSH_SNAPSHOT_OVERRIDE",
            root.join("examples/acp-agent/tests/snapshots/cancel/replay.override.json")
                .display()
                .to_string(),
        );
    }
    result.request_timeout = Duration::from_secs(15);
    result
}

fn dispatch(dispatch_id: &str, workspace: &Path) -> (DispatchEnvelope, ResolvedDispatchMaterial) {
    (
        DispatchEnvelope {
            dispatch_id: dispatch_id.to_owned(),
            attempt_id: format!("attempt:{dispatch_id}"),
            ..DispatchEnvelope::default()
        },
        ResolvedDispatchMaterial {
            canonical_input_bundle: Vec::new(),
            prompt: "Reply with the fixture response. No tools.".to_owned(),
            workspace_root: workspace.to_path_buf(),
            model: None,
        },
    )
}

#[tokio::test]
#[ignore = "requires an explicitly configured local DSH replay workspace"]
async fn dsh_replay_driver_emits_terminal_lifecycle() {
    let root = required_env("EGOPULSE_DSH_REPLAY_ROOT");
    let node = required_env("EGOPULSE_DSH_NODE");
    let home =
        std::env::temp_dir().join(format!("egopulse-dsh-rust-replay-{}", std::process::id()));
    let workspace = home.join("workspace");
    std::fs::create_dir_all(&workspace).expect("replay workspace");
    let mut driver = DshAcpDriver::new(replay_config(&root, node, "multi-turn", &home, &workspace));
    let (envelope, material) = dispatch("dispatch:dsh-replay", &workspace);

    let delivery = driver
        .send_dispatch(&envelope, &material)
        .await
        .expect("fresh DSH dispatch");
    assert!(!delivery.native_session_ref.is_empty());
    let event = driver
        .next_event(&envelope)
        .await
        .expect("terminal event")
        .expect("terminal lifecycle exists");
    assert!(matches!(
        event.payload,
        harness_observation::Payload::Lifecycle(value)
            if value.kind == LifecycleKind::ExecutionCompleted as i32
    ));
    assert!(
        driver
            .next_event(&envelope)
            .await
            .expect("event drain")
            .is_none()
    );
    let _ = std::fs::remove_dir_all(home);
}

#[tokio::test]
#[ignore = "requires an explicitly configured local DSH replay workspace"]
async fn dsh_replay_driver_sends_native_cancel_and_observes_interruption() {
    let root = required_env("EGOPULSE_DSH_REPLAY_ROOT");
    let node = required_env("EGOPULSE_DSH_NODE");
    let home =
        std::env::temp_dir().join(format!("egopulse-dsh-rust-cancel-{}", std::process::id()));
    let workspace = home.join("workspace");
    std::fs::create_dir_all(&workspace).expect("cancel workspace");
    let mut driver = DshAcpDriver::new(replay_config(&root, node, "cancel", &home, &workspace));
    let (envelope, material) = dispatch("dispatch:dsh-cancel", &workspace);
    let delivery = driver
        .send_dispatch(&envelope, &material)
        .await
        .expect("fresh DSH dispatch");
    let marker = workspace.join(".dsh-snapshot-stream-ready");
    for _ in 0..150 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        marker.exists(),
        "cancel fixture did not reach its stream marker"
    );
    let cancel = CancelExecutionEnvelope {
        dispatch_id: envelope.dispatch_id.clone(),
        native_session_ref: delivery.native_session_ref,
        native_execution_ref: delivery.native_execution_ref.unwrap_or_default(),
        ..CancelExecutionEnvelope::default()
    };
    let cancel_bytes = driver.cancel(&cancel).await.expect("native cancel");
    assert!(String::from_utf8_lossy(&cancel_bytes).contains("session/cancel"));
    let event = driver
        .next_event(&envelope)
        .await
        .expect("cancel terminal event")
        .expect("cancel lifecycle exists");
    assert!(matches!(
        event.payload,
        harness_observation::Payload::Lifecycle(value)
            if value.kind == LifecycleKind::ExecutionInterrupted as i32
    ));
    let _ = std::fs::remove_dir_all(home);
}
