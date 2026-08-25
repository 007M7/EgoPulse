#![cfg(windows)]

use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcessSpec,
    run_governed_framed_process, run_governed_process,
};
use std::path::PathBuf;
use std::time::Duration;

fn powershell_executable() -> PathBuf {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is available");
    let executable = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    assert!(
        executable.is_file(),
        "missing test executable: {executable:?}"
    );
    executable
}

fn powershell_spec(script: &str) -> SupervisedProcessSpec {
    let mut spec = SupervisedProcessSpec::new(
        powershell_executable(),
        std::env::current_dir().expect("test working directory"),
    );
    spec.arguments = vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        script.to_owned(),
    ];
    spec
}

fn budget(timeout: Duration, output_limit_bytes: u64) -> GovernedProcessBudget {
    GovernedProcessBudget {
        timeout,
        output_limit_bytes,
    }
}

#[tokio::test]
async fn framed_process_accepts_one_real_response_frame() {
    let script = r#"$bytes = [byte[]](0,0,0,2,111,107); [Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)"#;
    let receipt = run_governed_framed_process(
        &powershell_spec(script),
        b"request",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect("framed worker succeeds");
    assert_eq!(receipt.stdout, b"ok");
}

#[tokio::test]
async fn framed_process_rejects_a_malformed_real_response() {
    let script = r#"$bytes = [byte[]](0,0,0,2,111); [Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)"#;
    let error = run_governed_framed_process(
        &powershell_spec(script),
        b"request",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect_err("malformed response must fail closed");
    assert_eq!(error, GovernedProcessError::Protocol);
}

#[tokio::test]
async fn governed_process_maps_real_child_crash() {
    let error = run_governed_process(
        &powershell_spec("exit 7"),
        b"request",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect_err("non-zero child must fail");
    assert_eq!(error, GovernedProcessError::Crashed);
}

#[tokio::test]
async fn governed_process_maps_real_child_timeout() {
    let error = run_governed_process(
        &powershell_spec("Start-Sleep -Seconds 2"),
        b"request",
        budget(Duration::from_millis(100), 64),
    )
    .await
    .expect_err("long-running child must time out");
    assert_eq!(error, GovernedProcessError::Timeout);
}

#[tokio::test]
async fn governed_process_maps_real_stdout_limit() {
    let script = r#"$bytes = [byte[]](0..255); [Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)"#;
    let error = run_governed_process(
        &powershell_spec(script),
        b"request",
        budget(Duration::from_secs(5), 32),
    )
    .await
    .expect_err("oversized child output must fail");
    assert_eq!(error, GovernedProcessError::OutputLimit);
}
