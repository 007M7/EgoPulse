#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, CancelExecutionEnvelope, DispatchEnvelope, HarnessErrorCode,
    HarnessReadiness, NativeProtocolFingerprint, ProbeHarnessRequest, ProbeHarnessResult,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
};
use egopulse_process_supervision::{SupervisedProcess, SupervisedProcessSpec};
use prost_types::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;

pub const DSH_ADAPTER_ID: &str = "dsh-adapter";
pub const DSH_ACP_PROTOCOL: &str = "agent-client-protocol";
pub const DSH_ACP_PROTOCOL_VERSION: &str = "v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DshSessionProbeDisposition {
    Created {
        native_session_ref: String,
        evidence_ref: String,
    },
    Rejected {
        safe_detail_code: String,
        evidence_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DshSessionProbeResult {
    pub initialize: ProbeHarnessResult,
    pub session: DshSessionProbeDisposition,
}

#[derive(Clone, Debug)]
pub struct DshAcpConfig {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment_overrides: Vec<(String, String)>,
    pub request_timeout: Duration,
}

impl DshAcpConfig {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, working_directory: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            arguments: Vec::new(),
            working_directory: working_directory.into(),
            environment_overrides: Vec::new(),
            request_timeout: Duration::from_secs(10),
        }
    }

    #[must_use]
    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    #[must_use]
    pub fn with_environment_override(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.environment_overrides.push((name.into(), value.into()));
        self
    }
}

/// Candidate-only DSH ACP driver.
///
/// The native ACP session boundary is now locally observed, but prompt,
/// approval, cancellation and reconciliation semantics are not yet promoted
/// to an EgoPulse capability profile. All execution methods therefore remain
/// fail closed until those rows receive independent evidence.
pub struct DshAcpDriver {
    config: DshAcpConfig,
}

impl DshAcpDriver {
    #[must_use]
    pub fn new(config: DshAcpConfig) -> Self {
        Self { config }
    }

    /// Performs the ACP initialize plus session creation probe without a
    /// prompt. The native session id is returned only as opaque probe evidence.
    pub async fn probe_session(&self) -> Result<DshSessionProbeResult, DriverError> {
        probe_session(&self.config).await
    }
}

impl NativeHarnessDriver for DshAcpDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async move { probe_initialize(&self.config, request).await })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async { Err(unsupported("DSH_ACP_DISPATCH_NOT_ATTESTED")) })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async { Err(unsupported("DSH_ACP_EVENTS_NOT_ATTESTED")) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { Err(unsupported("DSH_ACP_APPROVALS_NOT_ATTESTED")) })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { Err(unsupported("DSH_ACP_CANCELLATION_NOT_ATTESTED")) })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async { Err(unsupported("DSH_ACP_RECONCILIATION_NOT_ATTESTED")) })
    }
}

async fn probe_initialize(
    config: &DshAcpConfig,
    _request: &ProbeHarnessRequest,
) -> Result<ProbeHarnessResult, DriverError> {
    let mut process = spawn_process(config).await?;
    let encoded = initialize_request();
    write_json_line(&mut process, &encoded, "DSH_ACP_INITIALIZE_WRITE_FAILED").await?;
    let line = read_json_line(
        &mut process,
        config.request_timeout,
        "DSH_ACP_INITIALIZE_TIMEOUT",
        "DSH_ACP_INITIALIZE_READ_FAILED",
        &encoded,
    )
    .await?;
    let _ = process.terminate().await;
    let _ = process.wait().await;
    parse_initialize_response(line.as_bytes())
}

async fn probe_session(config: &DshAcpConfig) -> Result<DshSessionProbeResult, DriverError> {
    let mut process = spawn_process(config).await?;
    let initialize = initialize_request();
    write_json_line(&mut process, &initialize, "DSH_ACP_INITIALIZE_WRITE_FAILED").await?;
    let initialize_line = read_json_line(
        &mut process,
        config.request_timeout,
        "DSH_ACP_INITIALIZE_TIMEOUT",
        "DSH_ACP_INITIALIZE_READ_FAILED",
        &initialize,
    )
    .await?;
    let initialize_result = parse_initialize_response(initialize_line.as_bytes())?;

    let session_request = session_new_request(&config.working_directory);
    write_json_line(
        &mut process,
        &session_request,
        "DSH_ACP_SESSION_NEW_WRITE_FAILED",
    )
    .await?;
    let session_line = read_json_line(
        &mut process,
        config.request_timeout,
        "DSH_ACP_SESSION_NEW_TIMEOUT",
        "DSH_ACP_SESSION_NEW_READ_FAILED",
        &session_request,
    )
    .await?;
    let session_result = parse_session_new_response(session_line.as_bytes())?;
    let _ = process.terminate().await;
    let _ = process.wait().await;
    Ok(DshSessionProbeResult {
        initialize: initialize_result,
        session: session_result,
    })
}

async fn spawn_process(config: &DshAcpConfig) -> Result<SupervisedProcess, DriverError> {
    let mut spec = SupervisedProcessSpec::new(&config.executable, &config.working_directory);
    spec.arguments = config.arguments.clone();
    for (name, value) in &config.environment_overrides {
        spec = spec.with_environment_override(name.clone(), value.clone());
    }
    SupervisedProcess::spawn(&spec)
        .await
        .map_err(|error| driver_error("DSH_ACP_SPAWN_FAILED", format!("{error:?}").as_bytes()))
}

fn initialize_request() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": { "name": "egopulse-probe", "version": env!("CARGO_PKG_VERSION") }
        }
    }))
    .unwrap_or_default()
}

fn session_new_request(working_directory: &PathBuf) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "session/new",
        "params": {
            "cwd": working_directory,
            "mcpServers": [],
            "additionalDirectories": []
        }
    }))
    .unwrap_or_default()
}

async fn write_json_line(
    process: &mut SupervisedProcess,
    encoded: &[u8],
    detail_code: &str,
) -> Result<(), DriverError> {
    process
        .stdin
        .write_all(encoded)
        .await
        .map_err(|error| driver_error(detail_code, error.to_string().as_bytes()))?;
    process
        .stdin
        .write_all(b"\n")
        .await
        .map_err(|error| driver_error(detail_code, error.to_string().as_bytes()))?;
    process
        .stdin
        .flush()
        .await
        .map_err(|error| driver_error(detail_code, error.to_string().as_bytes()))
}

async fn read_json_line(
    process: &mut SupervisedProcess,
    request_timeout: Duration,
    timeout_code: &str,
    read_code: &str,
    request: &[u8],
) -> Result<String, DriverError> {
    let mut line = String::new();
    timeout(request_timeout, process.stdout.read_line(&mut line))
        .await
        .map_err(|_| driver_error(timeout_code, request))?
        .map_err(|error| driver_error(read_code, error.to_string().as_bytes()))?;
    Ok(line)
}

fn parse_initialize_response(raw: &[u8]) -> Result<ProbeHarnessResult, DriverError> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        driver_error(
            "DSH_ACP_INITIALIZE_INVALID_JSON",
            error.to_string().as_bytes(),
        )
    })?;
    if value.get("error").is_some() {
        return Err(driver_error("DSH_ACP_INITIALIZE_REJECTED", raw));
    }
    let result = value
        .get("result")
        .ok_or_else(|| driver_error("DSH_ACP_INITIALIZE_RESULT_MISSING", raw))?;
    let agent_name = result
        .pointer("/agentInfo/name")
        .and_then(Value::as_str)
        .unwrap_or("deepseek-harness-acp");
    let version = result
        .pointer("/agentInfo/version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let protocol_version = result
        .get("protocolVersion")
        .and_then(Value::as_u64)
        .map(|value| format!("v{value}"))
        .unwrap_or_else(|| DSH_ACP_PROTOCOL_VERSION.to_owned());
    Ok(ProbeHarnessResult {
        probe_id: Uuid::now_v7().to_string(),
        readiness: HarnessReadiness::Degraded as i32,
        observed_protocol: Some(NativeProtocolFingerprint {
            protocol_name: DSH_ACP_PROTOCOL.to_owned(),
            protocol_version,
            schema_sha256: String::new(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            native_executable_version: format!("{agent_name} {version}"),
            native_binary_sha256: None,
        }),
        safe_diagnostic_codes: vec![
            "DSH_ACP_INITIALIZE_REACHABLE".to_owned(),
            "DSH_ACP_SCHEMA_ATTESTATION_REQUIRED".to_owned(),
        ],
        evidence_refs: vec![format!("dsh-acp-initialize-sha256:{}", sha256(raw))],
        observed_at: Some(now()),
    })
}

fn parse_session_new_response(raw: &[u8]) -> Result<DshSessionProbeDisposition, DriverError> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        driver_error(
            "DSH_ACP_SESSION_NEW_INVALID_JSON",
            error.to_string().as_bytes(),
        )
    })?;
    let evidence_ref = format!("dsh-acp-session-new-sha256:{}", sha256(raw));
    if value.get("error").is_some() {
        return Ok(DshSessionProbeDisposition::Rejected {
            safe_detail_code: "DSH_ACP_SESSION_NEW_REJECTED".to_owned(),
            evidence_ref,
        });
    }
    let session_id = value
        .pointer("/result/sessionId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| driver_error("DSH_ACP_SESSION_ID_MISSING", raw))?;
    Ok(DshSessionProbeDisposition::Created {
        native_session_ref: session_id.to_owned(),
        evidence_ref,
    })
}

fn unsupported(detail: &str) -> DriverError {
    driver_error(detail, &[])
}

fn driver_error(detail: &str, raw: &[u8]) -> DriverError {
    DriverError {
        certainty: DriverErrorCertainty::ProvenNotSent,
        code: HarnessErrorCode::CapabilityMismatch,
        safe_detail_code: detail.to_owned(),
        error_fingerprint: Some(sha256(raw)),
        raw_evidence: raw.to_vec(),
    }
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_is_reachable_but_not_probe_verified_without_schema_digest() {
        let result = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"agentInfo":{"name":"deepseek-harness-acp","version":"0.0.1"},"protocolVersion":1,"agentCapabilities":{"promptCapabilities":{"image":false,"audio":false,"embeddedContext":false}},"authMethods":[]}}"#,
        )
        .expect("parse initialize response");
        assert_eq!(result.readiness, HarnessReadiness::Degraded as i32);
        assert_eq!(
            result
                .observed_protocol
                .expect("observed protocol")
                .schema_sha256,
            ""
        );
        assert!(
            result
                .safe_diagnostic_codes
                .iter()
                .any(|code| code == "DSH_ACP_SCHEMA_ATTESTATION_REQUIRED")
        );
        assert_eq!(result.evidence_refs.len(), 1);
    }

    #[test]
    fn initialize_error_is_not_converted_to_ready() {
        let result = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"invalid request"}}"#,
        );
        assert!(result.is_err());
        assert_eq!(
            result
                .expect_err("initialize error must fail closed")
                .safe_detail_code,
            "DSH_ACP_INITIALIZE_REJECTED"
        );
    }

    #[test]
    fn session_creation_keeps_native_session_reference_opaque() {
        let result = parse_session_new_response(
            br#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"dsh-session-001"}}"#,
        )
        .expect("parse session response");
        assert!(matches!(
            result,
            DshSessionProbeDisposition::Created {
                native_session_ref,
                ..
            } if native_session_ref == "dsh-session-001"
        ));
    }

    #[test]
    fn rejected_session_is_a_controlled_probe_disposition() {
        let result = parse_session_new_response(
            br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"invalid cwd"}}"#,
        )
        .expect("parse rejected session");
        assert!(matches!(
            result,
            DshSessionProbeDisposition::Rejected {
                safe_detail_code,
                ..
            } if safe_detail_code == "DSH_ACP_SESSION_NEW_REJECTED"
        ));
    }

    #[test]
    fn dsh_probe_requests_use_native_acp_method_names() {
        let initialize: Value = serde_json::from_slice(&initialize_request()).expect("JSON");
        let session: Value =
            serde_json::from_slice(&session_new_request(&PathBuf::from(r"C:\workspace")))
                .expect("JSON");
        assert_eq!(initialize["method"], "initialize");
        assert_eq!(session["method"], "session/new");
        assert_eq!(session["params"]["mcpServers"], json!([]));
    }

    #[tokio::test]
    async fn unverified_execution_surface_is_fail_closed_and_proven_not_sent() {
        let mut driver = DshAcpDriver::new(DshAcpConfig::new(
            r"C:\node.exe",
            std::env::current_dir().expect("cwd"),
        ));
        let envelope = DispatchEnvelope::default();
        let material = ResolvedDispatchMaterial {
            canonical_input_bundle: Vec::new(),
            prompt: "not sent".to_owned(),
            workspace_root: std::env::current_dir().expect("cwd"),
            model: None,
        };
        let error = driver
            .send_dispatch(&envelope, &material)
            .await
            .expect_err("dispatch must remain unsupported");
        assert_eq!(
            (error.code, error.certainty),
            (
                HarnessErrorCode::CapabilityMismatch,
                DriverErrorCertainty::ProvenNotSent
            )
        );
        assert_eq!(
            driver
                .cancel(&CancelExecutionEnvelope::default())
                .await
                .expect_err("cancel must remain unsupported")
                .safe_detail_code,
            "DSH_ACP_CANCELLATION_NOT_ATTESTED"
        );
    }
}
