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

pub const KIMI_ADAPTER_ID: &str = "kimi-adapter";
pub const KIMI_ACP_PROTOCOL: &str = "agent-client-protocol";
pub const KIMI_ACP_PROTOCOL_VERSION: &str = "v1";

#[derive(Clone, Debug)]
pub struct KimiAcpConfig {
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub share_directory: Option<PathBuf>,
    pub request_timeout: Duration,
}

impl KimiAcpConfig {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, working_directory: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            working_directory: working_directory.into(),
            share_directory: None,
            request_timeout: Duration::from_secs(10),
        }
    }

    #[must_use]
    pub fn with_share_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.share_directory = Some(directory.into());
        self
    }
}

/// Candidate-only Kimi ACP driver.
///
/// This driver intentionally implements only the no-prompt ACP initialize
/// probe. Until session, lifecycle, approval and recovery semantics are
/// independently attested, every execution method fails closed as a
/// capability mismatch and this crate must not be installed as an active
/// Harness profile.
pub struct KimiAcpDriver {
    config: KimiAcpConfig,
}

impl KimiAcpDriver {
    #[must_use]
    pub fn new(config: KimiAcpConfig) -> Self {
        Self { config }
    }
}

impl NativeHarnessDriver for KimiAcpDriver {
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
        Box::pin(async { Err(unsupported("KIMI_NATIVE_DISPATCH_NOT_ATTESTED")) })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async { Err(unsupported("KIMI_NATIVE_EVENTS_NOT_ATTESTED")) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { Err(unsupported("KIMI_NATIVE_APPROVALS_NOT_ATTESTED")) })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { Err(unsupported("KIMI_NATIVE_CANCELLATION_NOT_ATTESTED")) })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async { Err(unsupported("KIMI_NATIVE_RECONCILIATION_NOT_ATTESTED")) })
    }
}

async fn probe_initialize(
    config: &KimiAcpConfig,
    _request: &ProbeHarnessRequest,
) -> Result<ProbeHarnessResult, DriverError> {
    let mut spec = SupervisedProcessSpec::new(&config.executable, &config.working_directory);
    spec.arguments = vec!["acp".to_owned()];
    if let Some(directory) = &config.share_directory {
        spec = spec.with_environment_override("KIMI_SHARE_DIR", directory.display().to_string());
    }
    let mut process = SupervisedProcess::spawn(&spec)
        .await
        .map_err(|error| driver_error("KIMI_ACP_SPAWN_FAILED", format!("{error:?}").as_bytes()))?;

    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {
                "fs": { "readTextFile": false, "writeTextFile": false },
                "terminal": false
            },
            "clientInfo": { "name": "egopulse-probe", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let encoded = serde_json::to_vec(&request).unwrap_or_default();
    process.stdin.write_all(&encoded).await.map_err(|error| {
        driver_error(
            "KIMI_ACP_INITIALIZE_WRITE_FAILED",
            error.to_string().as_bytes(),
        )
    })?;
    process.stdin.write_all(b"\n").await.map_err(|error| {
        driver_error(
            "KIMI_ACP_INITIALIZE_WRITE_FAILED",
            error.to_string().as_bytes(),
        )
    })?;
    process.stdin.flush().await.map_err(|error| {
        driver_error(
            "KIMI_ACP_INITIALIZE_WRITE_FAILED",
            error.to_string().as_bytes(),
        )
    })?;

    let mut line = String::new();
    timeout(config.request_timeout, process.stdout.read_line(&mut line))
        .await
        .map_err(|_| driver_error("KIMI_ACP_INITIALIZE_TIMEOUT", &encoded))?
        .map_err(|error| {
            driver_error(
                "KIMI_ACP_INITIALIZE_READ_FAILED",
                error.to_string().as_bytes(),
            )
        })?;
    let _ = process.terminate().await;
    let _ = process.wait().await;
    parse_initialize_response(line.as_bytes())
}

fn parse_initialize_response(raw: &[u8]) -> Result<ProbeHarnessResult, DriverError> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        driver_error(
            "KIMI_ACP_INITIALIZE_INVALID_JSON",
            error.to_string().as_bytes(),
        )
    })?;
    if value.get("error").is_some() {
        return Err(driver_error("KIMI_ACP_INITIALIZE_REJECTED", raw));
    }
    let result = value
        .get("result")
        .ok_or_else(|| driver_error("KIMI_ACP_INITIALIZE_RESULT_MISSING", raw))?;
    let version = result
        .pointer("/agentInfo/version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let protocol_version = result
        .get("protocolVersion")
        .and_then(Value::as_u64)
        .map(|value| format!("v{value}"))
        .unwrap_or_else(|| KIMI_ACP_PROTOCOL_VERSION.to_owned());
    Ok(ProbeHarnessResult {
        probe_id: Uuid::now_v7().to_string(),
        readiness: HarnessReadiness::Degraded as i32,
        observed_protocol: Some(NativeProtocolFingerprint {
            protocol_name: KIMI_ACP_PROTOCOL.to_owned(),
            protocol_version,
            schema_sha256: String::new(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            native_executable_version: version,
            native_binary_sha256: None,
        }),
        safe_diagnostic_codes: vec![
            "KIMI_ACP_INITIALIZE_REACHABLE".to_owned(),
            "KIMI_ACP_SCHEMA_ATTESTATION_REQUIRED".to_owned(),
        ],
        evidence_refs: vec![format!("kimi-acp-initialize-sha256:{}", sha256(raw))],
        observed_at: Some(now()),
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
            br#"{"jsonrpc":"2.0","id":1,"result":{"agentInfo":{"name":"Kimi Code CLI","version":"1.49.0"},"protocolVersion":1}}"#,
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
                .any(|code| code == "KIMI_ACP_SCHEMA_ATTESTATION_REQUIRED")
        );
        assert_eq!(result.evidence_refs.len(), 1);
    }

    #[test]
    fn initialize_error_is_not_converted_to_ready() {
        let result = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Authentication required"}}"#,
        );
        assert!(result.is_err());
        assert_eq!(
            result
                .expect_err("authentication error must fail closed")
                .safe_detail_code,
            "KIMI_ACP_INITIALIZE_REJECTED"
        );
    }

    #[tokio::test]
    #[ignore = "requires an authenticated or anonymously probeable local Kimi installation"]
    async fn live_kimi_initialize_probe_is_reachable_without_promoting_capability() {
        let executable = PathBuf::from(
            std::env::var_os("EGOPULSE_KIMI_NATIVE_EXE")
                .expect("EGOPULSE_KIMI_NATIVE_EXE must point to Kimi executable"),
        );
        let share_directory = PathBuf::from(
            std::env::var_os("EGOPULSE_KIMI_PROBE_DIR")
                .expect("EGOPULSE_KIMI_PROBE_DIR must point to an isolated probe directory"),
        );
        let config = KimiAcpConfig::new(executable, std::env::current_dir().expect("cwd"))
            .with_share_directory(share_directory);
        let result = probe_initialize(&config, &ProbeHarnessRequest::default())
            .await
            .expect("Kimi ACP initialize probe");
        assert_eq!(result.readiness, HarnessReadiness::Degraded as i32);
    }
}
