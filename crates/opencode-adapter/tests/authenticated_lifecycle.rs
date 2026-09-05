use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, LifecycleKind, harness_observation,
};
use egopulse_harness_adapter::{NativeHarnessDriver, ResolvedDispatchMaterial};
use egopulse_opencode_adapter::{OpenCodeAcpConfig, OpenCodeAcpDriver};
use std::path::{Path, PathBuf};

fn authorized(name: &str) {
    assert_eq!(
        std::env::var(name).as_deref(),
        Ok("1"),
        "set {name}=1 to explicitly authorize a real provider inference probe"
    );
}

fn required_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must point to the provider executable"))
}

fn required_text(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must contain the exact configured model"))
}

fn material(workspace: &Path) -> ResolvedDispatchMaterial {
    ResolvedDispatchMaterial {
        canonical_input_bundle: Vec::new(),
        prompt: "Reply with exactly EGOPULSE_PROVIDER_PROBE_OK and no tool calls.".to_owned(),
        workspace_root: workspace.to_path_buf(),
        model: None,
    }
}

#[tokio::test]
#[ignore = "requires explicit authorization, a user-owned OpenCode/Z.AI credential and real inference"]
async fn authenticated_glm_opencode_exact_model_terminal_lifecycle() {
    authorized("EGOPULSE_ALLOW_PROVIDER_INFERENCE");
    authorized("EGOPULSE_PROVIDER_AUTH_READY");
    let executable = required_path("EGOPULSE_OPENCODE_NATIVE_EXE");
    let exact_model = required_text("EGOPULSE_GLM_EXACT_MODEL");
    let root = std::env::temp_dir().join(format!("egopulse-opencode-auth-{}", std::process::id()));
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("isolated provider workspace");
    let config = OpenCodeAcpConfig::new(executable, &workspace, exact_model.clone());
    let mut driver = OpenCodeAcpDriver::new(config);
    let envelope = DispatchEnvelope {
        dispatch_id: "provider-probe:glm".to_owned(),
        attempt_id: "attempt:provider-probe:glm".to_owned(),
        ..DispatchEnvelope::default()
    };
    driver
        .send_dispatch(&envelope, &material(&workspace))
        .await
        .expect("authenticated GLM/OpenCode dispatch with exact model");
    let event = driver
        .next_event(&envelope)
        .await
        .expect("OpenCode terminal event")
        .expect("OpenCode lifecycle must terminate");
    assert!(matches!(
        event.payload,
        harness_observation::Payload::Lifecycle(value)
            if value.kind == LifecycleKind::ExecutionCompleted as i32
    ));
    let output = driver
        .take_terminal_output_candidate(&envelope)
        .await
        .expect("OpenCode terminal output candidate")
        .expect("OpenCode terminal output must be present");
    assert!(!output.content.is_empty());
    println!(
        "{{\"provider\":\"glm\",\"harness\":\"opencode\",\"exact_model\":{exact_model:?},\"prompt_sent\":true,\"terminal\":\"completed\",\"output_bytes\":{}}}",
        output.content.len()
    );
    let _ = std::fs::remove_dir_all(root);
}
