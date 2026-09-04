#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn content_watch_is_a_real_cli_command_with_source_filter_and_ndjson_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_egopulse"))
        .args(["content", "watch", "--help"])
        .output()
        .expect("content watch help runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(stdout.contains("--attempt-id"));
    assert!(stdout.contains("--frames"));
    assert!(stdout.contains("--json"));
}

#[test]
fn invalid_content_frame_bound_fails_before_daemon_attachment() {
    let output = Command::new(env!("CARGO_BIN_EXE_egopulse"))
        .args(["content", "watch", "task-001", "--frames", "0", "--json"])
        .output()
        .expect("invalid content watch runs");
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("failure is UTF-8");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("one JSON envelope");
    assert_eq!(value["operation"], "content.watch");
    assert_eq!(value["error"]["code"], "LOCAL_API_PROTOCOL_ERROR");
}
