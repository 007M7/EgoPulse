#![cfg(windows)]
use egopulse_harness_adapter::{ReadOnlyTurnDriver, ReadOnlyTurnRequest, ReadOnlyTurnStatus};
use egopulse_opencode_adapter::{OpenCodeAcpConfig, OpenCodeAcpDriver};
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

const MOCK: &str = r#"
$ErrorActionPreference = 'Stop'
$policy = $env:OPENCODE_CONFIG_CONTENT | ConvertFrom-Json
if ($policy.permission.'*' -ne 'deny' -or $policy.tools.'*' -ne $false) { exit 10 }
if ((Get-Location).Path -ne $env:OPENCODE_CONFIG_DIR -or $env:OPENCODE_DISABLE_PROJECT_CONFIG -ne 'true') { exit 11 }
function Send($value) { [Console]::Out.WriteLine(($value | ConvertTo-Json -Depth 15 -Compress)); [Console]::Out.Flush() }
while ($line = [Console]::In.ReadLine()) {
  $r = $line | ConvertFrom-Json
  switch ($r.method) {
    'initialize' { Send @{jsonrpc='2.0';id=$r.id;result=@{protocolVersion=1;agentCapabilities=@{}}} }
    'session/new' { Send @{jsonrpc='2.0';id=$r.id;result=@{sessionId='isolated-session'}} }
    'session/set_config_option' {
      $model=$r.params.value
      if ($env:EGOPULSE_READ_ONLY_SCENARIO -eq 'wrong-model') { $model='other/model' }
      Send @{jsonrpc='2.0';id=$r.id;result=@{configOptions=@(@{id='model';currentValue=$model})}}
    }
    'session/prompt' {
      $scenario=$env:EGOPULSE_READ_ONLY_SCENARIO
      if ($scenario -eq 'permission') {
        Send @{jsonrpc='2.0';id=90;method='session/request_permission';params=@{sessionId='isolated-session'}}
        $null=[Console]::In.ReadLine()
        exit 12
      }
      $text='{"reply":"Ready","needs_clarification":false,"intent":null,"sources":[]}'
      if ($scenario -eq 'oversized') { $text='x'*8192 }
      Send @{jsonrpc='2.0';method='session/update';params=@{sessionId='isolated-session';update=@{sessionUpdate='agent_message_chunk';content=@{type='text';text=$text}}}}
      Send @{jsonrpc='2.0';id=$r.id;result=@{stopReason='end_turn'}}
    }
  }
}
"#;

async fn run(
    scenario: &str,
) -> Result<egopulse_harness_adapter::ReadOnlyTurnOutcome, egopulse_harness_adapter::DriverError> {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("mock.ps1");
    fs::write(&script, MOCK).unwrap();
    let powershell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut config = OpenCodeAcpConfig::new(powershell, temp.path(), "test/exact-model");
    config.arguments = vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-File".into(),
        script.display().to_string(),
    ];
    config
        .environment_overrides
        .push(("EGOPULSE_READ_ONLY_SCENARIO".into(), scenario.into()));
    OpenCodeAcpDriver::new(config)
        .run_bounded_read_only_turn(ReadOnlyTurnRequest {
            execution_id: "intent:isolated-test".into(),
            working_directory: temp.path().to_owned(),
            model: "test/exact-model".into(),
            prompt: "Return an ordinary reply without work.".into(),
            output_schema: json!({"type":"object"}),
            timeout: Duration::from_secs(30),
            output_limit_bytes: 4096,
        })
        .await
}

#[tokio::test]
async fn fresh_cognition_uses_exact_model_without_inheriting_workspace_tools() {
    let outcome = run("reply").await.unwrap();
    assert_eq!(outcome.model, "test/exact-model");
    assert_eq!(outcome.terminal_status, ReadOnlyTurnStatus::Completed);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&outcome.assistant_output).unwrap()["reply"],
        "Ready"
    );
}
#[tokio::test]
async fn another_native_model_is_rejected_before_prompt() {
    let error = run("wrong-model").await.unwrap_err();
    assert!(error.safe_detail_code.contains("MODEL_MISMATCH"));
}
#[tokio::test]
async fn permission_request_is_refused_and_the_fresh_process_is_disposed() {
    let error = run("permission").await.unwrap_err();
    assert_eq!(error.safe_detail_code, "READ_ONLY_SERVER_REQUEST_REFUSED");
}
#[tokio::test]
async fn assistant_output_cannot_exceed_the_cognition_budget() {
    let error = run("oversized").await.unwrap_err();
    assert_eq!(error.safe_detail_code, "READ_ONLY_OUTPUT_LIMIT");
}
