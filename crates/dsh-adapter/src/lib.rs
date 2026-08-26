#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod acp;

use acp::{DshAcpMessage, DshAcpResponse, DshAcpUpdate};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
    ApprovalRequestObservation, CancelExecutionEnvelope, DispatchEnvelope, HarnessErrorCode,
    HarnessReadiness, LifecycleKind, LifecycleObservation, NativeProtocolFingerprint,
    ObservationCriticality, ProbeHarnessRequest, ProbeHarnessResult, harness_observation,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
};
use egopulse_process_supervision::{SupervisedProcess, SupervisedProcessSpec};
use prost_types::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;

pub const DSH_ADAPTER_ID: &str = "dsh-adapter";
pub const DSH_ACP_PROTOCOL: &str = "agent-client-protocol";
pub const DSH_ACP_PROTOCOL_VERSION: &str = "v1";
pub const DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF: &str =
    "dsh-reconcile:native-session-load-resume-unsupported";

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

struct DshSession {
    process: SupervisedProcess,
    next_request_id: u64,
    native_session_ref: String,
}

struct ActiveDispatch {
    dispatch_id: String,
    native_session_ref: String,
    prompt_request_id: u64,
    output_text: String,
}

#[derive(Clone)]
struct PendingApproval {
    request_id: Value,
    params: Value,
    observation: ApprovalRequestObservation,
}

/// Candidate-only DSH ACP driver.
///
/// The driver now exercises the proven fresh-session ACP path, native
/// prompt/cancel messages, and a governed native permission round-trip. It
/// remains candidate-only because DSH has no native session load/resume
/// capability and its ACP surface does not expose EgoPulse Artifact semantics.
/// Those weaker rows remain explicit failures.
pub struct DshAcpDriver {
    config: DshAcpConfig,
    session: Option<DshSession>,
    active: Option<ActiveDispatch>,
    completed_dispatch_id: Option<String>,
    pending_approvals: HashMap<String, PendingApproval>,
}

impl DshAcpDriver {
    #[must_use]
    pub fn new(config: DshAcpConfig) -> Self {
        Self {
            config,
            session: None,
            active: None,
            completed_dispatch_id: None,
            pending_approvals: HashMap::new(),
        }
    }

    /// Performs the ACP initialize plus session creation probe without a
    /// prompt. The native session id is returned only as opaque probe evidence.
    pub async fn probe_session(&self) -> Result<DshSessionProbeResult, DriverError> {
        probe_session(&self.config).await
    }

    async fn ensure_session(&mut self, working_directory: &Path) -> Result<(), DriverError> {
        if self.session.is_some() {
            return Ok(());
        }
        let mut process = spawn_process(&self.config).await?;
        let initialize = acp::initialize_request(env!("CARGO_PKG_VERSION"));
        write_json_value(&mut process, &initialize, "DSH_ACP_INITIALIZE_WRITE_FAILED").await?;
        let initialize_bytes = serde_json::to_vec(&initialize).unwrap_or_default();
        let initialize_raw = read_json_line(
            &mut process,
            self.config.request_timeout,
            "DSH_ACP_INITIALIZE_TIMEOUT",
            "DSH_ACP_INITIALIZE_READ_FAILED",
            &initialize_bytes,
        )
        .await?;
        let initialize_message =
            acp::parse_message(initialize_raw.as_bytes()).map_err(|detail| {
                driver_error("DSH_ACP_INITIALIZE_INVALID_MESSAGE", detail.as_bytes())
            })?;
        if !matches!(
            initialize_message,
            DshAcpMessage::Response(DshAcpResponse::Result { .. })
        ) {
            return Err(driver_error(
                "DSH_ACP_INITIALIZE_REJECTED",
                initialize_raw.as_bytes(),
            ));
        }

        let session_request = acp::session_new_request(&working_directory.display().to_string(), 2);
        let session_bytes = serde_json::to_vec(&session_request).unwrap_or_default();
        write_json_value(
            &mut process,
            &session_request,
            "DSH_ACP_SESSION_NEW_WRITE_FAILED",
        )
        .await?;
        let session_raw = read_json_line(
            &mut process,
            self.config.request_timeout,
            "DSH_ACP_SESSION_NEW_TIMEOUT",
            "DSH_ACP_SESSION_NEW_READ_FAILED",
            &session_bytes,
        )
        .await?;
        let session_id = match acp::parse_message(session_raw.as_bytes()).map_err(|detail| {
            driver_error("DSH_ACP_SESSION_NEW_INVALID_MESSAGE", detail.as_bytes())
        })? {
            DshAcpMessage::Response(DshAcpResponse::Result { result, .. }) => result
                .get("sessionId")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    driver_error("DSH_ACP_SESSION_ID_MISSING", session_raw.as_bytes())
                })?,
            _ => {
                return Err(driver_error(
                    "DSH_ACP_SESSION_NEW_REJECTED",
                    session_raw.as_bytes(),
                ));
            }
        };
        self.session = Some(DshSession {
            process,
            next_request_id: 3,
            native_session_ref: session_id,
        });
        Ok(())
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
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            if self.active.is_some()
                && self.completed_dispatch_id.as_deref()
                    != self.active.as_ref().map(|value| value.dispatch_id.as_str())
            {
                return Err(dependency_error("DSH_ACP_ACTIVE_DISPATCH_EXISTS"));
            }
            self.ensure_session(&material.workspace_root).await?;
            let session = self.session.as_mut().expect("session initialized");
            let request_id = session.next_request_id;
            session.next_request_id = session.next_request_id.saturating_add(1);
            let request = acp::session_prompt_request(
                request_id,
                &session.native_session_ref,
                &material.prompt,
            );
            let raw = serde_json::to_vec(&request).unwrap_or_default();
            write_json_value(
                &mut session.process,
                &request,
                "DSH_ACP_PROMPT_WRITE_FAILED",
            )
            .await
            .map_err(|mut error| {
                error.certainty = DriverErrorCertainty::DeliveryUnknown;
                error
            })?;
            let native_session_ref = session.native_session_ref.clone();
            self.active = Some(ActiveDispatch {
                dispatch_id: envelope.dispatch_id.clone(),
                native_session_ref: native_session_ref.clone(),
                prompt_request_id: request_id,
                output_text: String::new(),
            });
            self.completed_dispatch_id = None;
            Ok(DriverDelivery {
                native_request_ref: format!("dsh-acp-jsonrpc:{request_id}"),
                native_session_ref,
                native_execution_ref: Some(format!("dsh-acp-prompt:{request_id}")),
                raw_evidence: raw,
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            if self.completed_dispatch_id.as_deref() == Some(envelope.dispatch_id.as_str()) {
                return Ok(None);
            }
            // A native permission request is a governance handoff. The worker
            // must yield so the control plane can call decide_approval instead
            // of blocking on the ACP response indefinitely.
            if !self.pending_approvals.is_empty() {
                return Ok(None);
            }
            let (dispatch_id, native_session_ref, prompt_request_id) = self
                .active
                .as_ref()
                .filter(|value| value.dispatch_id == envelope.dispatch_id)
                .map(|value| {
                    (
                        value.dispatch_id.clone(),
                        value.native_session_ref.clone(),
                        value.prompt_request_id,
                    )
                })
                .ok_or_else(|| dependency_error("DSH_ACP_ACTIVE_DISPATCH_NOT_FOUND"))?;
            loop {
                let line = {
                    let session = self
                        .session
                        .as_mut()
                        .ok_or_else(|| dependency_error("DSH_ACP_SESSION_NOT_RUNNING"))?;
                    read_json_line(
                        &mut session.process,
                        self.config.request_timeout,
                        "DSH_ACP_EVENT_TIMEOUT",
                        "DSH_ACP_EVENT_READ_FAILED",
                        b"dsh-acp-event",
                    )
                    .await?
                };
                let message = acp::parse_message(line.as_bytes()).map_err(|detail| {
                    driver_error("DSH_ACP_EVENT_INVALID_MESSAGE", detail.as_bytes())
                })?;
                match message {
                    DshAcpMessage::SessionUpdate { session_id, update } => {
                        if session_id != native_session_ref {
                            return Err(driver_error(
                                "DSH_ACP_SESSION_ID_MISMATCH",
                                line.as_bytes(),
                            ));
                        }
                        if let DshAcpUpdate::AgentMessageChunk { text } = update
                            && let Some(active) = self.active.as_mut()
                        {
                            active.output_text.push_str(&text);
                        }
                        // ACP chunks are content observations, not terminal
                        // truth. The prompt response below closes the event.
                    }
                    DshAcpMessage::Response(DshAcpResponse::Result { id, result })
                        if id.as_u64() == Some(prompt_request_id) =>
                    {
                        let stop_reason = result
                            .get("stopReason")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        let (kind, status) = match stop_reason {
                            "end_turn" => (LifecycleKind::ExecutionCompleted, "end_turn"),
                            "cancelled" | "canceled" => {
                                (LifecycleKind::ExecutionInterrupted, "cancelled")
                            }
                            _ => {
                                return Err(driver_error(
                                    "DSH_ACP_TERMINAL_STATUS_UNKNOWN",
                                    line.as_bytes(),
                                ));
                            }
                        };
                        self.completed_dispatch_id = Some(dispatch_id);
                        return Ok(Some(lifecycle_event(
                            "session/prompt",
                            kind,
                            status,
                            line.into_bytes(),
                        )));
                    }
                    DshAcpMessage::Response(DshAcpResponse::Error { id, .. })
                        if id.as_ref().and_then(Value::as_u64) == Some(prompt_request_id) =>
                    {
                        return Ok(Some(lifecycle_event(
                            "session/prompt",
                            LifecycleKind::ExecutionFailed,
                            "error",
                            line.into_bytes(),
                        )));
                    }
                    DshAcpMessage::ServerRequest { id, method, params }
                        if method == "session/request_permission" =>
                    {
                        let routing_ref = format!("dsh-acp-routing:approval:{}", Uuid::now_v7());
                        let observation = ApprovalRequestObservation {
                            approval_request_id: Uuid::now_v7().to_string(),
                            kind: ApprovalKind::Permission as i32,
                            action_digest_sha256: sha256(params.to_string().as_bytes()),
                            requested_scope_ref: "adapter-edge://dsh-acp/approval/scope".to_owned(),
                            display_summary_ref: "adapter-edge://dsh-acp/approval/summary"
                                .to_owned(),
                            native_routing_ref: routing_ref.clone(),
                            lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                            request_revision: 1,
                        };
                        self.pending_approvals.insert(
                            routing_ref.clone(),
                            PendingApproval {
                                request_id: id,
                                params,
                                observation: observation.clone(),
                            },
                        );
                        return Ok(Some(DriverEvent {
                            native_key: format!("request:{}", observation.approval_request_id),
                            native_event_id: None,
                            native_sequence: None,
                            native_observed_at: now(),
                            criticality: ObservationCriticality::Security,
                            payload: harness_observation::Payload::ApprovalRequest(observation),
                            raw_event: line.into_bytes(),
                        }));
                    }
                    DshAcpMessage::ServerRequest { .. } => {
                        return Err(driver_error(
                            "DSH_ACP_APPROVAL_OR_SERVER_REQUEST_UNATTESTED",
                            line.as_bytes(),
                        ));
                    }
                    DshAcpMessage::Notification { .. } => {}
                    DshAcpMessage::Response(_) => {}
                }
            }
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move { send_approval_response(self, envelope).await })
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| dependency_error("DSH_ACP_SESSION_NOT_RUNNING"))?;
            if envelope.native_session_ref != session.native_session_ref {
                return Err(driver_error(
                    "DSH_ACP_CANCEL_SESSION_MISMATCH",
                    envelope.native_session_ref.as_bytes(),
                ));
            }
            let request = acp::session_cancel_request(&session.native_session_ref);
            let raw = serde_json::to_vec(&request).unwrap_or_default();
            write_json_value(
                &mut session.process,
                &request,
                "DSH_ACP_CANCEL_WRITE_FAILED",
            )
            .await
            .map_err(|mut error| {
                error.certainty = DriverErrorCertainty::DeliveryUnknown;
                error
            })?;
            Ok(raw)
        })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async {
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF.to_owned(),
            })
        })
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

async fn send_approval_response(
    driver: &mut DshAcpDriver,
    envelope: &ApprovalDecisionEnvelope,
) -> Result<Vec<u8>, DriverError> {
    let pending = driver
        .pending_approvals
        .get(&envelope.native_routing_ref)
        .cloned()
        .ok_or_else(|| {
            driver_error(
                "DSH_ACP_APPROVAL_ROUTING_NOT_FOUND",
                envelope.native_routing_ref.as_bytes(),
            )
        })?;
    if envelope.approval_request_id != pending.observation.approval_request_id
        || envelope.action_digest_sha256 != pending.observation.action_digest_sha256
    {
        return Err(driver_error(
            "DSH_ACP_APPROVAL_IDENTITY_MISMATCH",
            envelope.native_routing_ref.as_bytes(),
        ));
    }
    let decision = ApprovalDecision::try_from(envelope.decision)
        .map_err(|_| driver_error("DSH_ACP_APPROVAL_DECISION_INVALID", &[]))?;
    let result = match decision {
        ApprovalDecision::AllowOnce => {
            select_permission_option(&pending.params, &["allow_once", "allow_always"])?
        }
        ApprovalDecision::Deny => {
            select_permission_option(&pending.params, &["reject_once", "reject_always"])?
        }
        ApprovalDecision::CancelAttempt => json!({
            "outcome": { "outcome": "cancelled" }
        }),
        ApprovalDecision::Unspecified => {
            return Err(driver_error("DSH_ACP_APPROVAL_DECISION_INVALID", &[]));
        }
    };
    let response = json!({ "jsonrpc": "2.0", "id": pending.request_id, "result": result });
    let raw = serde_json::to_vec(&response).unwrap_or_default();
    let session = driver
        .session
        .as_mut()
        .ok_or_else(|| dependency_error("DSH_ACP_SESSION_NOT_RUNNING"))?;
    write_json_value(
        &mut session.process,
        &response,
        "DSH_ACP_APPROVAL_RESPONSE_WRITE_FAILED",
    )
    .await
    .map_err(|mut error| {
        error.certainty = DriverErrorCertainty::DeliveryUnknown;
        error
    })?;
    driver
        .pending_approvals
        .remove(&envelope.native_routing_ref);
    Ok(raw)
}

fn select_permission_option(params: &Value, accepted_kinds: &[&str]) -> Result<Value, DriverError> {
    let option = params
        .get("options")
        .and_then(Value::as_array)
        .and_then(|options| {
            options.iter().find(|option| {
                option
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| accepted_kinds.contains(&kind))
            })
        })
        .and_then(|option| option.get("optionId"))
        .and_then(Value::as_str)
        .filter(|option_id| !option_id.is_empty())
        .ok_or_else(|| driver_error("DSH_ACP_PERMISSION_OPTION_UNAVAILABLE", &[]))?;
    Ok(json!({
        "outcome": { "outcome": "selected", "optionId": option }
    }))
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

async fn write_json_value(
    process: &mut SupervisedProcess,
    value: &Value,
    detail_code: &str,
) -> Result<(), DriverError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| driver_error(detail_code, error.to_string().as_bytes()))?;
    write_json_line(process, &encoded, detail_code).await
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

fn dependency_error(detail: &str) -> DriverError {
    DriverError {
        certainty: DriverErrorCertainty::ProvenNotSent,
        code: HarnessErrorCode::DependencyUnavailable,
        safe_detail_code: detail.to_owned(),
        error_fingerprint: None,
        raw_evidence: Vec::new(),
    }
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

fn lifecycle_event(
    native_method: &str,
    kind: LifecycleKind,
    status: &str,
    raw: Vec<u8>,
) -> DriverEvent {
    DriverEvent {
        native_key: format!("{native_method}:{}", sha256(&raw)),
        native_event_id: None,
        native_sequence: None,
        native_observed_at: now(),
        criticality: ObservationCriticality::Terminal,
        payload: harness_observation::Payload::Lifecycle(LifecycleObservation {
            kind: kind as i32,
            native_item_ref: None,
            safe_status_code: Some(status.to_owned()),
            side_effect_certainty: 0,
            native_will_retry: None,
        }),
        raw_event: raw,
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

    #[test]
    fn permission_response_selection_is_explicit_and_fail_closed() {
        let params = json!({
            "options": [
                { "optionId": "yes", "kind": "allow_once" },
                { "optionId": "no", "kind": "reject_once" }
            ]
        });
        assert_eq!(
            select_permission_option(&params, &["allow_once"]).expect("allow option")["outcome"]["optionId"],
            "yes"
        );
        assert_eq!(
            select_permission_option(&params, &["allow_always"])
                .expect_err("missing option must fail closed")
                .safe_detail_code,
            "DSH_ACP_PERMISSION_OPTION_UNAVAILABLE"
        );
    }

    #[tokio::test]
    async fn unavailable_process_is_fail_closed_and_cancel_requires_session() {
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
            .expect_err("unavailable process must fail closed");
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
                .expect_err("cancel without a session must fail closed")
                .safe_detail_code,
            "DSH_ACP_SESSION_NOT_RUNNING"
        );
    }

    #[tokio::test]
    async fn native_recovery_is_explicitly_outcome_unknown_without_synthetic_resume() {
        let mut driver = DshAcpDriver::new(DshAcpConfig::new(
            r"C:\dsh.exe",
            std::env::current_dir().expect("cwd"),
        ));
        let context = ReconciliationContext {
            envelope: DispatchEnvelope {
                dispatch_id: "dispatch:dsh-recovery-hold".to_owned(),
                ..DispatchEnvelope::default()
            },
            delivery_receipt: None,
            material: ResolvedDispatchMaterial {
                canonical_input_bundle: Vec::new(),
                prompt: "reconcile without native resume".to_owned(),
                workspace_root: std::env::current_dir().expect("cwd"),
                model: None,
            },
        };
        let finding = driver
            .reconcile(&context)
            .await
            .expect("unsupported native recovery is a controlled finding");
        assert_eq!(
            finding,
            ReconciliationFinding::OutcomeUnknown {
                evidence_ref: DSH_NATIVE_RECOVERY_UNSUPPORTED_EVIDENCE_REF.to_owned(),
            }
        );
    }
}
