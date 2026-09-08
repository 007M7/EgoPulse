use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_APP_SERVER_SCHEMA_SHA256, CodexAppServerConfig, CodexAppServerDriver,
    codex_protocol_fingerprint,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, HarnessReadiness, NativeSessionStrategy, ProbeHarnessRequest,
};
use egopulse_harness_adapter::{NativeHarnessDriver, ResolvedDispatchMaterial};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the authenticated pinned Codex and an explicit read-only fixture root"]
async fn real_codex_read_only_review_returns_bound_visible_output() {
    use egopulse_codex_adapter::{CodexReadOnlyReviewRequest, CodexReadOnlyReviewTerminalStatus};
    let executable = PathBuf::from(
        std::env::var_os("EGOPULSE_CODEX_EXECUTABLE").expect("explicit pinned Codex"),
    );
    let working_directory = PathBuf::from(
        std::env::var_os("EGOPULSE_CODEX_REVIEW_ROOT").expect("explicit isolated fixture root"),
    );
    assert!(executable.is_file() && working_directory.is_dir());
    let model = std::env::var("EGOPULSE_CODEX_REVIEW_MODEL").expect("explicit review model");
    let execution_id = format!("readonly-review-test:{}", uuid::Uuid::now_v7());
    let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new(executable));
    let result = driver.run_read_only_review(CodexReadOnlyReviewRequest {
        execution_id: execution_id.clone(), working_directory, model: model.clone(),
        prompt: "Reply exactly with EGOPULSE_READ_ONLY_REVIEW_OK. Do not call tools or change files.".into(),
        timeout: Duration::from_secs(120), output_limit_bytes: 64 * 1024,
    }).await.unwrap_or_else(|error| {
        let method = serde_json::from_slice::<serde_json::Value>(&error.raw_evidence)
            .ok().and_then(|value| value.get("method").and_then(serde_json::Value::as_str).map(str::to_owned));
        panic!("native review failed: {:?} {:?} {} method={method:?}", error.certainty, error.code, error.safe_detail_code)
    });
    assert_eq!(
        result.terminal_status,
        CodexReadOnlyReviewTerminalStatus::Completed
    );
    assert_eq!(result.assistant_output, b"EGOPULSE_READ_ONLY_REVIEW_OK");
    assert!(result.delivery_started && !result.thread_id.is_empty() && !result.turn_id.is_empty());
    assert_eq!(result.receipt.execution_id, execution_id);
    assert_eq!(result.receipt.model, model);
    assert_eq!(result.receipt.thread_id, result.thread_id);
    assert_eq!(result.receipt.turn_id, result.turn_id);
    assert_eq!(result.receipt.output_bytes, result.assistant_output.len());
    assert_eq!(
        result.receipt.output_sha256,
        hex::encode(Sha256::digest(&result.assistant_output))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_codex_app_server_dispatch_round_trips_when_configured() {
    let Some(executable) = std::env::var_os("EGOPULSE_CODEX_EXECUTABLE") else {
        eprintln!("skipping real Codex app-server E2E; set EGOPULSE_CODEX_EXECUTABLE to run it");
        return;
    };
    let executable = PathBuf::from(executable);
    assert!(
        executable.is_file(),
        "EGOPULSE_CODEX_EXECUTABLE must point to a file: {}",
        executable.display()
    );

    let workspace_root = std::env::current_dir().expect("workspace root");
    let input_bundle = br#"{"input":"real-codex-adapter-e2e"}"#.to_vec();
    let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new(executable));
    let probe = driver
        .probe(&ProbeHarnessRequest {
            adapter_id: CODEX_ADAPTER_ID.to_owned(),
            expected_protocol_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
            ..Default::default()
        })
        .await
        .expect("real Codex probe should return a result");
    assert_eq!(probe.readiness, HarnessReadiness::Ready as i32);
    assert_eq!(
        probe
            .observed_protocol
            .as_ref()
            .map(|value| value.native_executable_version.as_str()),
        Some(
            codex_protocol_fingerprint()
                .native_executable_version
                .as_str()
        )
    );

    let dispatch_id = "real-codex-adapter-e2e-dispatch";
    let envelope = DispatchEnvelope {
        run_id: "real-codex-adapter-e2e-run".to_owned(),
        step_id: "step-001".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: dispatch_id.to_owned(),
        input_bundle_sha256: hex::encode(Sha256::digest(&input_bundle)),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        ..Default::default()
    };
    let delivery = driver
        .send_dispatch(
            &envelope,
            &ResolvedDispatchMaterial {
                canonical_input_bundle: input_bundle,
                prompt: "Reply exactly with EGOPULSE_CODEX_E2E_OK and do not call tools."
                    .to_owned(),
                workspace_root,
                model: Some("gpt-5.6-sol".to_owned()),
            },
        )
        .await
        .expect("real Codex turn should be accepted");
    assert!(!delivery.native_session_ref.is_empty());

    let mut terminal_seen = false;
    for _ in 0..600 {
        if let Some(event) = driver
            .next_event(&envelope)
            .await
            .expect("real Codex event stream should remain readable")
        {
            if event.criticality
                == egopulse_domain_contracts::v01::egopulse::harness::v1::ObservationCriticality::Terminal
            {
                terminal_seen = true;
                break;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    assert!(
        terminal_seen,
        "real Codex turn should reach a terminal event"
    );
    let candidate = driver
        .take_terminal_output_candidate(&envelope)
        .await
        .expect("real Codex terminal candidate extraction should succeed")
        .expect("real Codex should produce an agent message candidate");
    assert_eq!(candidate.dispatch_id, dispatch_id);
    assert_eq!(candidate.content, b"EGOPULSE_CODEX_E2E_OK");
}
