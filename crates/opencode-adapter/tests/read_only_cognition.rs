#![cfg(windows)]
use egopulse_harness_adapter::{ReadOnlyTurnDriver, ReadOnlyTurnRequest, ReadOnlyTurnStatus};
use egopulse_opencode_adapter::{OpenCodeAcpConfig, OpenCodeAcpDriver};
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

const MOCK: &str = r#"
import sys, os, json
policy = json.loads(os.environ['OPENCODE_CONFIG_CONTENT'])
assert policy['permission']['*'] == 'deny' and policy['tools']['*'] is False
assert os.path.normcase(os.getcwd()) == os.path.normcase(os.environ['OPENCODE_CONFIG_DIR'])
assert os.environ['OPENCODE_DISABLE_PROJECT_CONFIG'] == 'true'
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    method = request['method']
    response = {'jsonrpc':'2.0', 'id':request['id']}
    if method == 'initialize':
        response['result'] = {'protocolVersion':1, 'agentCapabilities':{}}
    elif method == 'session/new':
        response['result'] = {'sessionId':'isolated-session'}
    elif method == 'session/set_config_option':
        model = 'other/model' if os.environ['EGOPULSE_READ_ONLY_SCENARIO'] == 'wrong-model' else request['params']['value']
        response['result'] = {'configOptions':[{'id':'model','currentValue':model}]}
    elif method == 'session/prompt':
        scenario = os.environ['EGOPULSE_READ_ONLY_SCENARIO']
        if scenario == 'permission':
            send({'jsonrpc':'2.0','id':90,'method':'session/request_permission','params':{'sessionId':'isolated-session'}})
            sys.stdin.readline()
            raise SystemExit(12)
        text = 'x'*8192 if scenario == 'oversized' else json.dumps({'reply':'Ready','needs_clarification':False,'intent':None,'sources':[]})
        send({'jsonrpc':'2.0','method':'session/update','params':{'sessionId':'isolated-session','update':{'sessionUpdate':'agent_message_chunk','content':{'type':'text','text':text}}}})
        response['result'] = {'stopReason':'end_turn'}
    send(response)
"#;

async fn run(
    scenario: &str,
) -> Result<egopulse_harness_adapter::ReadOnlyTurnOutcome, egopulse_harness_adapter::DriverError> {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("mock.py");
    fs::write(&script, MOCK).unwrap();
    // Use the locked interpreter already required by the Rust CI prerequisite.
    // The fixture exercises ACP stdio, not PowerShell's profile/module startup.
    let python = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../workers/memory-rag/.venv/Scripts/python.exe");
    assert!(
        python.is_file(),
        "run setup-memory-worker.ps1 before the Rust gate"
    );
    let mut config = OpenCodeAcpConfig::new(python, temp.path(), "test/exact-model");
    config.arguments = vec!["-u".into(), script.display().to_string()];
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
    assert_eq!(
        error.certainty,
        egopulse_harness_adapter::DriverErrorCertainty::ProvenNotSent
    );
}
#[tokio::test]
async fn permission_request_is_refused_and_the_fresh_process_is_disposed() {
    let error = run("permission").await.unwrap_err();
    assert_eq!(error.safe_detail_code, "READ_ONLY_SERVER_REQUEST_REFUSED");
    assert_eq!(
        error.certainty,
        egopulse_harness_adapter::DriverErrorCertainty::DeliveryUnknown
    );
}
#[tokio::test]
async fn assistant_output_cannot_exceed_the_cognition_budget() {
    let error = run("oversized").await.unwrap_err();
    assert_eq!(error.safe_detail_code, "READ_ONLY_OUTPUT_LIMIT");
    assert_eq!(
        error.certainty,
        egopulse_harness_adapter::DriverErrorCertainty::DeliveryUnknown
    );
}
