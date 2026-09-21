#![cfg(windows)]

use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcess, SupervisedProcessSpec,
    run_governed_framed_process, run_governed_process, run_governed_process_outcome,
};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

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

fn unique_pid_file(test_name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "egopulse-process-supervision-{test_name}-{}-{nonce}.pid",
        std::process::id()
    ))
}

fn unique_command_root(test_name: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "egopulse process supervision & {test_name}-{}-{nonce}",
        std::process::id()
    ))
}

fn pid_writer_script(pid_file: &std::path::Path) -> String {
    let escaped = pid_file.to_string_lossy().replace('\'', "''");
    format!("Set-Content -NoNewline -LiteralPath '{escaped}' -Value $PID; Start-Sleep -Seconds 30")
}

async fn wait_for_pid(pid_file: &std::path::Path) -> u32 {
    for _ in 0..100 {
        if let Ok(value) = std::fs::read_to_string(pid_file)
            && let Ok(pid) = value.trim().parse()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("child did not publish its PID: {pid_file:?}");
}

async fn process_is_running(pid: u32) -> bool {
    let status = Command::new(powershell_executable())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("query child process state");
    status.success()
}

async fn wait_until_process_stops(pid: u32) -> bool {
    for _ in 0..100 {
        if !process_is_running(pid).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

async fn force_stop_process(pid: u32) {
    let _ = Command::new(powershell_executable())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
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
async fn governed_process_closes_stdin_for_an_eof_driven_worker() {
    let script = r#"$stream = [Console]::OpenStandardInput(); $buffer = New-Object byte[] 16; $total = 0; while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $total += $read }; [Console]::Write($total)"#;
    let receipt = run_governed_process(
        &powershell_spec(script),
        b"request",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect("EOF-driven worker succeeds");

    assert_eq!(receipt.stdout, b"7");
}

#[tokio::test]
async fn governed_process_starts_an_absolute_cmd_shim_with_minimal_environment() {
    let command_root = unique_command_root("cmd-shim");
    std::fs::create_dir(&command_root).expect("create command shim directory");
    let command_file = command_root.join("provider shim.cmd");
    std::fs::write(&command_file, "@echo off\r\necho cmd-boundary-ok\r\n")
        .expect("write command shim");
    let executable = std::fs::canonicalize(&command_file).expect("canonical command shim");
    let spec = SupervisedProcessSpec::new(
        executable,
        std::env::current_dir().expect("test working directory"),
    )
    .with_minimal_user_environment();

    let result = run_governed_process(&spec, b"", budget(Duration::from_secs(5), 64)).await;
    let _ = std::fs::remove_file(command_file);
    let _ = std::fs::remove_dir(command_root);

    let receipt = result.expect("absolute command shim succeeds");
    assert_eq!(
        String::from_utf8_lossy(&receipt.stdout).trim(),
        "cmd-boundary-ok"
    );
}

#[tokio::test]
async fn supervised_process_rejects_an_absolute_ordinary_file() {
    let ordinary_file = unique_command_root("ordinary-file").with_extension("txt");
    std::fs::write(&ordinary_file, b"not executable").expect("write ordinary file");
    let executable = std::fs::canonicalize(&ordinary_file).expect("canonical ordinary file");
    let spec = SupervisedProcessSpec::new(
        executable,
        std::env::current_dir().expect("test working directory"),
    );

    let error = match SupervisedProcess::spawn(&spec).await {
        Ok(_) => panic!("ordinary file must fail before process creation"),
        Err(error) => error,
    };
    let _ = std::fs::remove_file(ordinary_file);

    assert!(matches!(
        error,
        egopulse_process_supervision::ProcessSupervisionError::InvalidExecutable
    ));
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
async fn governed_process_outcome_preserves_failed_command_evidence() {
    let script = r#"[Console]::Out.Write('criterion failed'); [Console]::Error.Write('expected 3, got 2'); exit 7"#;
    let receipt = run_governed_process_outcome(
        &powershell_spec(script),
        b"",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect("normal non-zero exit retains its receipt");
    assert_eq!(receipt.exit_code, 7);
    assert_eq!(receipt.stdout, b"criterion failed");
    assert_eq!(receipt.stderr, b"expected 3, got 2");

    let error = run_governed_process(
        &powershell_spec(script),
        b"",
        budget(Duration::from_secs(5), 64),
    )
    .await
    .expect_err("existing success-only callers still reject the same command");
    assert_eq!(error, GovernedProcessError::Crashed);
}

#[tokio::test]
async fn governed_process_outcome_does_not_accept_oversized_failed_output() {
    let script = r#"[Console]::Out.Write('too much evidence'); exit 7"#;
    let error = run_governed_process_outcome(
        &powershell_spec(script),
        b"",
        budget(Duration::from_secs(5), 4),
    )
    .await
    .expect_err("non-zero receipts still obey the output budget");
    assert_eq!(error, GovernedProcessError::OutputLimit);
}

#[tokio::test]
async fn governed_process_maps_real_child_timeout() {
    let pid_file = unique_pid_file("timeout");
    // The child is a PowerShell process, so the budget has to cover its
    // start-up; the script then sleeps far longer, which is what exercises the
    // timeout path. Waiting for the published PID while the run is in flight
    // removes the race between the child reporting itself and the supervisor
    // killing it: with a budget shorter than a cold start under load, the child
    // was killed before it ever wrote the file.
    let spec = powershell_spec(&pid_writer_script(&pid_file));
    let run = tokio::spawn(async move {
        run_governed_process(&spec, b"request", budget(Duration::from_secs(15), 64)).await
    });
    let pid = wait_for_pid(&pid_file).await;
    let error = run
        .await
        .expect("timeout case task")
        .expect_err("long-running child must time out");
    assert_eq!(error, GovernedProcessError::Timeout);
    assert!(
        !process_is_running(pid).await,
        "timed-out child process remained alive: {pid}"
    );
    let _ = std::fs::remove_file(pid_file);
}

#[tokio::test]
async fn dropping_a_governed_exchange_kills_the_real_child() {
    let pid_file = unique_pid_file("cancel");
    let spec = powershell_spec(&pid_writer_script(&pid_file));
    let exchange = tokio::spawn(async move {
        run_governed_process(&spec, b"request", budget(Duration::from_secs(60), 64)).await
    });
    let pid = wait_for_pid(&pid_file).await;
    assert!(
        process_is_running(pid).await,
        "child never became observable"
    );

    exchange.abort();
    let join_error = exchange.await.expect_err("exchange must be cancelled");
    assert!(join_error.is_cancelled());
    assert!(
        wait_until_process_stops(pid).await,
        "cancelled child process remained alive: {pid}"
    );
    let _ = std::fs::remove_file(pid_file);
}

#[tokio::test]
async fn dropping_a_governed_cmd_exchange_kills_its_descendant_tree() {
    let command_root = unique_command_root("cmd-descendant");
    std::fs::create_dir(&command_root).expect("create command tree directory");
    let command_file = command_root.join("provider tree.cmd");
    let pid_file = command_root.join("descendant.pid");
    let command_body = format!(
        "@echo off\r\n\"{}\" -NoProfile -NonInteractive -Command \"{}\"\r\n",
        powershell_executable().display(),
        pid_writer_script(&pid_file)
    );
    std::fs::write(&command_file, command_body).expect("write command tree shim");
    let executable = std::fs::canonicalize(&command_file).expect("canonical command tree shim");
    let spec = SupervisedProcessSpec::new(
        executable,
        std::env::current_dir().expect("test working directory"),
    )
    .with_minimal_user_environment();
    let exchange = tokio::spawn(async move {
        run_governed_process(&spec, b"", budget(Duration::from_secs(60), 64)).await
    });
    let descendant_pid = wait_for_pid(&pid_file).await;
    assert!(
        process_is_running(descendant_pid).await,
        "command descendant never became observable"
    );

    let cancellation_started = std::time::Instant::now();
    exchange.abort();
    let join_error = exchange.await.expect_err("exchange must be cancelled");
    assert!(join_error.is_cancelled());
    let stopped = wait_until_process_stops(descendant_pid).await;
    let cancellation_duration = cancellation_started.elapsed();
    if !stopped {
        force_stop_process(descendant_pid).await;
    }
    let _ = std::fs::remove_file(command_file);
    let _ = std::fs::remove_file(pid_file);
    let _ = std::fs::remove_dir(command_root);
    assert!(stopped, "cancelled command descendant remained alive");
    assert!(
        cancellation_duration < Duration::from_secs(5),
        "command process tree cancellation exceeded five seconds: {cancellation_duration:?}"
    );
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
