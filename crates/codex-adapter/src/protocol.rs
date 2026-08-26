use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind,
    ApprovalRequestLifecycleKind, ApprovalRequestObservation, CancelExecutionEnvelope,
    DispatchEnvelope, HarnessAckObservation, HarnessErrorCode, HarnessReadiness, LifecycleKind,
    LifecycleObservation, NativeProtocolFingerprint, ObservationCriticality, ProbeHarnessRequest,
    ProbeHarnessResult, SideEffectCertainty, UsageObservation, harness_observation,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
};
use egopulse_process_supervision::{SupervisedProcess, SupervisedProcessSpec};
use prost_types::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use uuid::Uuid;

pub const CODEX_ADAPTER_ID: &str = "codex-adapter";
pub const CODEX_CAPABILITY_PROFILE_ID: &str = "codex-app-server-v2-0.148.0-alpha.15";
pub const CODEX_APP_SERVER_PROTOCOL: &str = "codex-app-server";
pub const CODEX_APP_SERVER_VERSION: &str = "v2";
pub const CODEX_APP_SERVER_SCHEMA_SHA256: &str =
    "b4e8157096dd054c008a4f1b538fb6cd8f1f2cb9577a97a4afef59c2296ed608";
const CODEX_EXECUTABLE_VERSION: &str = "0.148.0-alpha.15";

#[must_use]
pub fn codex_protocol_fingerprint() -> NativeProtocolFingerprint {
    NativeProtocolFingerprint {
        protocol_name: CODEX_APP_SERVER_PROTOCOL.to_owned(),
        protocol_version: CODEX_APP_SERVER_VERSION.to_owned(),
        schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
        adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        native_executable_version: CODEX_EXECUTABLE_VERSION.to_owned(),
        native_binary_sha256: None,
    }
}

#[derive(Clone, Debug)]
pub struct CodexAppServerConfig {
    pub executable: PathBuf,
    pub request_timeout: Duration,
}

impl CodexAppServerConfig {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

struct ActiveDispatch {
    dispatch_id: String,
    thread_id: String,
    turn_id: Option<String>,
    turn_request_id: u64,
}

struct PendingApproval {
    request_id: Value,
    method: String,
    params: Value,
    observation: ApprovalRequestObservation,
}

struct CodexSession {
    process: SupervisedProcess,
    next_request_id: u64,
    pending_messages: VecDeque<(Value, Vec<u8>)>,
}

pub struct CodexAppServerDriver {
    config: CodexAppServerConfig,
    session: Option<CodexSession>,
    active: Option<ActiveDispatch>,
    completed_dispatch_id: Option<String>,
    pending_approvals: HashMap<String, PendingApproval>,
    responded_approvals: HashMap<String, ApprovalRequestObservation>,
    queued_events: VecDeque<DriverEvent>,
    pending_control_requests: HashMap<u64, &'static str>,
    last_protocol_diagnostic: Option<String>,
}

impl CodexAppServerDriver {
    #[must_use]
    pub fn new(config: CodexAppServerConfig) -> Self {
        Self {
            config,
            session: None,
            active: None,
            completed_dispatch_id: None,
            pending_approvals: HashMap::new(),
            responded_approvals: HashMap::new(),
            queued_events: VecDeque::new(),
            pending_control_requests: HashMap::new(),
            last_protocol_diagnostic: None,
        }
    }

    #[must_use]
    pub fn last_protocol_diagnostic(&self) -> Option<&str> {
        self.last_protocol_diagnostic.as_deref()
    }

    async fn ensure_session(&mut self, working_directory: &PathBuf) -> Result<(), DriverError> {
        if self.session.is_some() {
            return Ok(());
        }
        let mut spec = SupervisedProcessSpec::new(&self.config.executable, working_directory);
        spec.arguments = vec!["app-server".to_owned(), "--stdio".to_owned()];
        let mut process = SupervisedProcess::spawn(&spec).await.map_err(|error| {
            driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::DependencyUnavailable,
                "CODEX_APP_SERVER_SPAWN_FAILED",
                format!("{error:?}").as_bytes(),
            )
        })?;
        if let Some(stderr) = process.take_stderr() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut buffer = Vec::new();
                loop {
                    buffer.clear();
                    match reader.read_until(b'\n', &mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            tracing::debug!(
                                codex_stderr_sha256 = %sha256(&buffer),
                                "Codex app-server emitted a redacted diagnostic line"
                            );
                        }
                    }
                }
            });
        }
        let mut session = CodexSession {
            process,
            next_request_id: 1,
            pending_messages: VecDeque::new(),
        };
        let initialize_id = session.next_id();
        session
            .write_value(&json!({
                "id": initialize_id,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "egopulse-codex-adapter",
                        "title": "EgoPulse Codex Adapter",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": { "experimentalApi": true }
                }
            }))
            .await?;
        session
            .read_response(initialize_id, self.config.request_timeout)
            .await?;
        session
            .write_value(&json!({ "method": "initialized" }))
            .await?;
        self.session = Some(session);
        Ok(())
    }

    async fn start_or_resume_thread(
        &mut self,
        envelope: &DispatchEnvelope,
        material: &ResolvedDispatchMaterial,
    ) -> Result<String, DriverError> {
        let session = self.session.as_mut().expect("session initialized");
        let request_id = session.next_id();
        let (method, params) = if let Some(thread_id) = &envelope.native_session_ref {
            (
                "thread/resume",
                json!({
                    "threadId": thread_id,
                    "cwd": material.workspace_root,
                    "approvalPolicy": "untrusted",
                    "sandbox": "workspace-write"
                }),
            )
        } else {
            (
                "thread/start",
                json!({
                    "cwd": material.workspace_root,
                    "approvalPolicy": "untrusted",
                    "sandbox": "workspace-write",
                    "experimentalRawEvents": false,
                    "model": material.model
                }),
            )
        };
        session
            .write_value(&json!({ "id": request_id, "method": method, "params": params }))
            .await?;
        let response = session
            .read_response(request_id, self.config.request_timeout)
            .await?
            .0;
        response
            .pointer("/result/thread/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                driver_error(
                    DriverErrorCertainty::ProvenNotSent,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_THREAD_RESPONSE_INVALID",
                    response.to_string().as_bytes(),
                )
            })
    }

    fn map_value(
        &mut self,
        envelope: &DispatchEnvelope,
        value: Value,
        raw: Vec<u8>,
    ) -> Result<Option<DriverEvent>, DriverError> {
        if value.get("id").is_some() && value.get("method").is_none() {
            return self.map_response(value, raw);
        }
        let Some(method) = value
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            self.last_protocol_diagnostic = Some("unknown-message-shape".to_owned());
            return Err(driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::UnknownCriticalEvent,
                "CODEX_MESSAGE_SHAPE_UNKNOWN",
                &raw,
            ));
        };
        if value.get("id").is_some() {
            return self.map_server_request(&method, value, raw);
        }
        self.map_notification(envelope, &method, value, raw)
    }

    fn map_response(
        &mut self,
        value: Value,
        raw: Vec<u8>,
    ) -> Result<Option<DriverEvent>, DriverError> {
        let response_id = value.get("id").and_then(Value::as_u64);
        if let Some(kind) = response_id.and_then(|id| self.pending_control_requests.remove(&id)) {
            let failed = value.get("error").is_some();
            return Ok(Some(DriverEvent {
                native_key: format!("response:{}:{kind}", response_id.unwrap_or_default()),
                native_event_id: None,
                native_sequence: None,
                native_observed_at: now(),
                criticality: ObservationCriticality::Control,
                payload: harness_observation::Payload::Diagnostic(
                    egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                        safe_diagnostic_code: if failed {
                            "CODEX_CONTROL_REQUEST_REJECTED".to_owned()
                        } else {
                            "CODEX_CONTROL_REQUEST_ACKNOWLEDGED".to_owned()
                        },
                        error_fingerprint: failed.then(|| sha256(&raw)),
                        recovery_required: failed,
                    },
                ),
                raw_event: raw,
            }));
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(None);
        };
        if response_id != Some(active.turn_request_id) {
            return Ok(None);
        }
        if value.get("error").is_some() {
            return Ok(Some(DriverEvent {
                native_key: format!("response:{}:ack", active.turn_request_id),
                native_event_id: None,
                native_sequence: None,
                native_observed_at: now(),
                criticality: ObservationCriticality::Control,
                payload: harness_observation::Payload::Ack(HarnessAckObservation {
                    disposition: AckDisposition::Rejected as i32,
                    ack_receipt_id: Uuid::now_v7().to_string(),
                    native_session_ref: Some(active.thread_id.clone()),
                    native_execution_ref: None,
                }),
                raw_event: raw,
            }));
        }
        let turn_id = value
            .pointer("/result/turn/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_TURN_START_RESPONSE_INVALID",
                    &raw,
                )
            })?;
        active.turn_id = Some(turn_id.clone());
        Ok(Some(DriverEvent {
            native_key: format!("response:{}:ack", active.turn_request_id),
            native_event_id: None,
            native_sequence: None,
            native_observed_at: now(),
            criticality: ObservationCriticality::Control,
            payload: harness_observation::Payload::Ack(HarnessAckObservation {
                disposition: AckDisposition::Accepted as i32,
                ack_receipt_id: Uuid::now_v7().to_string(),
                native_session_ref: Some(active.thread_id.clone()),
                native_execution_ref: Some(turn_id),
            }),
            raw_event: raw,
        }))
    }

    fn map_server_request(
        &mut self,
        method: &str,
        value: Value,
        raw: Vec<u8>,
    ) -> Result<Option<DriverEvent>, DriverError> {
        let kind = match method {
            "item/commandExecution/requestApproval" | "execCommandApproval" => {
                ApprovalKind::Command
            }
            "item/fileChange/requestApproval" | "applyPatchApproval" => ApprovalKind::FileChange,
            "item/permissions/requestApproval" => ApprovalKind::Permission,
            "item/tool/requestUserInput" => ApprovalKind::UserInput,
            "mcpServer/elicitation/request" => ApprovalKind::Tool,
            _ => {
                self.last_protocol_diagnostic = Some(method.to_owned());
                return Err(driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::UnknownCriticalEvent,
                    "CODEX_UNKNOWN_SERVER_REQUEST",
                    &raw,
                ));
            }
        };
        let routing_ref = format!("codex-routing:approval:{}", Uuid::now_v7());
        let request_id = value.get("id").cloned().ok_or_else(|| {
            driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::ProtocolMismatch,
                "CODEX_APPROVAL_REQUEST_ID_MISSING",
                &raw,
            )
        })?;
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let observation = ApprovalRequestObservation {
            approval_request_id: Uuid::now_v7().to_string(),
            kind: kind as i32,
            action_digest_sha256: sha256(params.to_string().as_bytes()),
            requested_scope_ref: "adapter-edge://codex/approval/scope".to_owned(),
            display_summary_ref: "adapter-edge://codex/approval/summary".to_owned(),
            native_routing_ref: routing_ref.clone(),
            lifecycle: ApprovalRequestLifecycleKind::Open as i32,
            request_revision: 1,
        };
        self.pending_approvals.insert(
            routing_ref.clone(),
            PendingApproval {
                request_id,
                method: method.to_owned(),
                params: params.clone(),
                observation: observation.clone(),
            },
        );
        Ok(Some(DriverEvent {
            native_key: format!("request:{}", value["id"]),
            native_event_id: None,
            native_sequence: None,
            native_observed_at: now(),
            criticality: ObservationCriticality::Security,
            payload: harness_observation::Payload::ApprovalRequest(observation),
            raw_event: raw,
        }))
    }

    fn map_notification(
        &mut self,
        envelope: &DispatchEnvelope,
        method: &str,
        value: Value,
        raw: Vec<u8>,
    ) -> Result<Option<DriverEvent>, DriverError> {
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        let event = match method {
            "thread/started" => lifecycle_event(
                method,
                LifecycleKind::SessionCreated,
                None,
                "created",
                None,
                raw,
            ),
            "turn/started" => lifecycle_event(
                method,
                LifecycleKind::ExecutionStarted,
                None,
                "inProgress",
                None,
                raw,
            ),
            "thread/status/changed" => {
                let status = params
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "active" => lifecycle_event(
                        method,
                        LifecycleKind::ExecutionStarted,
                        None,
                        status,
                        None,
                        raw,
                    ),
                    "systemError" => lifecycle_event(
                        method,
                        LifecycleKind::ExecutionFailed,
                        None,
                        status,
                        None,
                        raw,
                    ),
                    "idle" | "notLoaded" => DriverEvent {
                        native_key: native_key(method, &raw),
                        native_event_id: None,
                        native_sequence: None,
                        native_observed_at: now(),
                        criticality: if status == "notLoaded" {
                            ObservationCriticality::Control
                        } else {
                            ObservationCriticality::Informational
                        },
                        payload: harness_observation::Payload::Diagnostic(
                            egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                                safe_diagnostic_code: if status == "notLoaded" {
                                    "CODEX_THREAD_NOT_LOADED"
                                } else {
                                    "CODEX_THREAD_IDLE"
                                }
                                .to_owned(),
                                error_fingerprint: (status == "notLoaded").then(|| sha256(&raw)),
                                recovery_required: status == "notLoaded",
                            },
                        ),
                        raw_event: raw,
                    },
                    _ => {
                        self.last_protocol_diagnostic =
                            Some(format!("thread-status:{status}"));
                        return Err(driver_error(
                            DriverErrorCertainty::DeliveryUnknown,
                            HarnessErrorCode::UnknownCriticalEvent,
                            "CODEX_THREAD_STATUS_UNKNOWN",
                            &raw,
                        ));
                    }
                }
            }
            "hook/started" => {
                let status = params
                    .pointer("/run/status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if status != "running" {
                    self.last_protocol_diagnostic = Some(format!("hook-start-status:{status}"));
                    return Err(driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::UnknownCriticalEvent,
                        "CODEX_HOOK_START_STATUS_UNKNOWN",
                        &raw,
                    ));
                }
                lifecycle_event(
                    method,
                    LifecycleKind::ItemStarted,
                    params.pointer("/run/id").and_then(Value::as_str),
                    status,
                    None,
                    raw,
                )
            }
            "hook/completed" => {
                let status = params
                    .pointer("/run/status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if !matches!(status, "completed" | "failed" | "blocked" | "stopped") {
                    self.last_protocol_diagnostic = Some(format!("hook-complete-status:{status}"));
                    return Err(driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::UnknownCriticalEvent,
                        "CODEX_HOOK_COMPLETION_STATUS_UNKNOWN",
                        &raw,
                    ));
                }
                lifecycle_event(
                    method,
                    LifecycleKind::ItemCompleted,
                    params.pointer("/run/id").and_then(Value::as_str),
                    status,
                    None,
                    raw,
                )
            }
            "item/started" => lifecycle_event(
                method,
                LifecycleKind::ItemStarted,
                params.pointer("/item/id").and_then(Value::as_str),
                "started",
                None,
                raw,
            ),
            "item/completed" => lifecycle_event(
                method,
                LifecycleKind::ItemCompleted,
                params.pointer("/item/id").and_then(Value::as_str),
                "completed",
                None,
                raw,
            ),
            "context/compacted" => lifecycle_event(
                method,
                LifecycleKind::ContextCompacted,
                None,
                "compacted",
                None,
                raw,
            ),
            "thread/tokenUsage/updated" => {
                let total = params.pointer("/tokenUsage/total").unwrap_or(&Value::Null);
                DriverEvent {
                    native_key: native_key(method, &raw),
                    native_event_id: None,
                    native_sequence: None,
                    native_observed_at: now(),
                    criticality: ObservationCriticality::Informational,
                    payload: harness_observation::Payload::Usage(UsageObservation {
                        usage_receipt_ref: format!("codex-usage:{}", Uuid::now_v7()),
                        input_tokens: total["inputTokens"].as_u64().unwrap_or(0),
                        output_tokens: total["outputTokens"].as_u64().unwrap_or(0),
                        cached_input_tokens: total["cachedInputTokens"].as_u64(),
                        cost_receipt_ref: None,
                    }),
                    raw_event: raw,
                }
            }
            "turn/completed" => {
                let status = params
                    .pointer("/turn/status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let kind = match status {
                    "completed" => LifecycleKind::ExecutionCompleted,
                    "interrupted" => LifecycleKind::ExecutionInterrupted,
                    "failed" => LifecycleKind::ExecutionFailed,
                    _ => {
                        self.last_protocol_diagnostic = Some(format!("turn-status:{status}"));
                        return Err(driver_error(
                            DriverErrorCertainty::DeliveryUnknown,
                            HarnessErrorCode::UnknownCriticalEvent,
                            "CODEX_TERMINAL_STATUS_UNKNOWN",
                            &raw,
                        ));
                    }
                };
                lifecycle_event(method, kind, None, status, None, raw)
            }
            "error" => lifecycle_event(
                method,
                LifecycleKind::ExecutionFailed,
                None,
                "error",
                params.get("willRetry").and_then(Value::as_bool),
                raw,
            ),
            "process/exited" => lifecycle_event(
                method,
                LifecycleKind::ProcessExited,
                None,
                "processExited",
                None,
                raw,
            ),
            "mcpServer/startupStatus/updated" => {
                let status = params
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let (safe_diagnostic_code, recovery_required, criticality) = match status {
                    "starting" => (
                        "CODEX_MCP_SERVER_STARTING",
                        false,
                        ObservationCriticality::Informational,
                    ),
                    "ready" => (
                        "CODEX_MCP_SERVER_READY",
                        false,
                        ObservationCriticality::Informational,
                    ),
                    "failed" => (
                        "CODEX_MCP_SERVER_STARTUP_FAILED",
                        true,
                        ObservationCriticality::Control,
                    ),
                    "cancelled" => (
                        "CODEX_MCP_SERVER_STARTUP_CANCELLED",
                        false,
                        ObservationCriticality::Informational,
                    ),
                    _ => {
                        self.last_protocol_diagnostic =
                            Some(format!("mcp-server-startup-status:{status}"));
                        return Err(driver_error(
                            DriverErrorCertainty::DeliveryUnknown,
                            HarnessErrorCode::UnknownCriticalEvent,
                            "CODEX_MCP_SERVER_STARTUP_STATUS_UNKNOWN",
                            &raw,
                        ));
                    }
                };
                DriverEvent {
                    native_key: native_key(method, &raw),
                    native_event_id: None,
                    native_sequence: None,
                    native_observed_at: now(),
                    criticality,
                    payload: harness_observation::Payload::Diagnostic(
                        egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                            safe_diagnostic_code: safe_diagnostic_code.to_owned(),
                            error_fingerprint: recovery_required.then(|| sha256(&raw)),
                            recovery_required,
                        },
                    ),
                    raw_event: raw,
                }
            }
            "account/rateLimits/updated" => {
                let reached = params
                    .pointer("/rateLimits/rateLimitReachedType")
                    .is_some_and(|value| !value.is_null())
                    || params
                        .pointer("/rateLimits/spendControlReached")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    || params
                        .pointer("/rateLimits/primary/usedPercent")
                        .and_then(Value::as_u64)
                        .is_some_and(|used| used >= 100);
                DriverEvent {
                    native_key: native_key(method, &raw),
                    native_event_id: None,
                    native_sequence: None,
                    native_observed_at: now(),
                    criticality: if reached {
                        ObservationCriticality::Control
                    } else {
                        ObservationCriticality::Informational
                    },
                    payload: harness_observation::Payload::Diagnostic(
                        egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                            safe_diagnostic_code: if reached {
                                "HARNESS_CAPACITY_EXHAUSTED"
                            } else {
                                "HARNESS_CAPACITY_UPDATED"
                            }
                            .to_owned(),
                            error_fingerprint: reached.then(|| sha256(&raw)),
                            recovery_required: reached,
                        },
                    ),
                    raw_event: raw,
                }
            }
            "serverRequest/resolved" => {
                let request_id = params.get("requestId").ok_or_else(|| {
                    driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::ProtocolMismatch,
                        "CODEX_RESOLVED_REQUEST_ID_MISSING",
                        &raw,
                    )
                })?;
                let request_key = request_id.to_string();
                let (mut observation, lifecycle) =
                    if let Some(observation) = self.responded_approvals.remove(&request_key) {
                        (observation, ApprovalRequestLifecycleKind::Resolved)
                    } else {
                        let pending_routing_ref =
                            self.pending_approvals.iter().find_map(|(key, value)| {
                                (value.request_id == *request_id).then(|| key.clone())
                            });
                        match pending_routing_ref
                            .as_ref()
                            .and_then(|key| self.pending_approvals.remove(key))
                        {
                            Some(pending) => {
                                (pending.observation, ApprovalRequestLifecycleKind::Withdrawn)
                            }
                            None => {
                                self.last_protocol_diagnostic =
                                    Some("server-request-resolution-without-request".to_owned());
                                return Err(driver_error(
                                    DriverErrorCertainty::DeliveryUnknown,
                                    HarnessErrorCode::UnknownCriticalEvent,
                                    "CODEX_UNKNOWN_SERVER_REQUEST_RESOLUTION",
                                    &raw,
                                ));
                            }
                        }
                    };
                observation.lifecycle = lifecycle as i32;
                observation.request_revision = observation.request_revision.saturating_add(1);
                if observation.request_revision < 2 {
                    observation.request_revision = 2;
                }
                DriverEvent {
                    native_key: native_key(method, &raw),
                    native_event_id: None,
                    native_sequence: None,
                    native_observed_at: now(),
                    criticality: ObservationCriticality::Security,
                    payload: harness_observation::Payload::ApprovalRequest(observation),
                    raw_event: raw,
                }
            }
            "turn/diff/updated"
            | "turn/plan/updated"
            | "item/agentMessage/delta"
            | "item/plan/delta"
            | "item/commandExecution/outputDelta"
            | "item/commandExecution/terminalInteraction"
            | "item/fileChange/outputDelta"
            | "item/fileChange/patchUpdated"
            | "item/mcpToolCall/progress"
            | "item/reasoning/summaryTextDelta"
            | "item/reasoning/summaryPartAdded"
            | "item/reasoning/textDelta"
            | "turn/moderationMetadata"
            | "remoteControl/status/changed" => return Ok(None),
            _ => {
                self.last_protocol_diagnostic = Some(method.to_owned());
                return Err(driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::UnknownCriticalEvent,
                    "CODEX_UNKNOWN_NOTIFICATION",
                    &raw,
                ));
            }
        };
        if event.criticality == ObservationCriticality::Terminal {
            self.completed_dispatch_id = Some(envelope.dispatch_id.clone());
            self.active = None;
        }
        Ok(Some(event))
    }

    async fn send_approval_response(
        &mut self,
        envelope: &ApprovalDecisionEnvelope,
    ) -> Result<Vec<u8>, DriverError> {
        let pending = self
            .pending_approvals
            .remove(&envelope.native_routing_ref)
            .ok_or_else(|| {
                driver_error(
                    DriverErrorCertainty::ProvenNotSent,
                    HarnessErrorCode::NotFound,
                    "CODEX_APPROVAL_ROUTING_NOT_FOUND",
                    envelope.native_routing_ref.as_bytes(),
                )
            })?;
        let decision = ApprovalDecision::try_from(envelope.decision).map_err(|_| {
            driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "APPROVAL_DECISION_INVALID",
                &[],
            )
        })?;
        let result = match pending.method.as_str() {
            "item/commandExecution/requestApproval" | "execCommandApproval" => {
                json!({ "decision": approval_word(decision) })
            }
            "item/fileChange/requestApproval" | "applyPatchApproval" => {
                json!({ "decision": approval_word(decision) })
            }
            "item/permissions/requestApproval" => match decision {
                ApprovalDecision::AllowOnce => json!({
                    "permissions": pending.params["permissions"],
                    "scope": "turn",
                    "strictAutoReview": true
                }),
                _ => json!({
                    "permissions": { "fileSystem": [], "network": [] },
                    "scope": "turn",
                    "strictAutoReview": true
                }),
            },
            _ => {
                return Err(driver_error(
                    DriverErrorCertainty::ProvenNotSent,
                    HarnessErrorCode::InvalidArgument,
                    "APPROVAL_KIND_UNSUPPORTED_V01",
                    &[],
                ));
            }
        };
        let response = json!({ "id": pending.request_id, "result": result });
        let raw = serde_json::to_vec(&response).unwrap_or_default();
        self.session
            .as_mut()
            .ok_or_else(|| dependency_error("CODEX_SESSION_NOT_RUNNING"))?
            .write_value(&response)
            .await?;
        self.responded_approvals
            .insert(pending.request_id.to_string(), pending.observation);
        Ok(raw)
    }
}

impl NativeHarnessDriver for CodexAppServerDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async move {
            let observed_version = probe_version(&self.config).await?;
            let observed_schema = probe_schema(&self.config).await?;
            let expected = request.expected_protocol_schema_sha256.to_ascii_lowercase();
            let ready = observed_version == CODEX_EXECUTABLE_VERSION
                && observed_schema == expected
                && expected == CODEX_APP_SERVER_SCHEMA_SHA256;
            Ok(ProbeHarnessResult {
                probe_id: Uuid::now_v7().to_string(),
                readiness: if ready {
                    HarnessReadiness::Ready
                } else {
                    HarnessReadiness::ProtocolMismatch
                } as i32,
                observed_protocol: Some(NativeProtocolFingerprint {
                    native_executable_version: observed_version,
                    schema_sha256: observed_schema.clone(),
                    ..codex_protocol_fingerprint()
                }),
                safe_diagnostic_codes: vec![if ready {
                    "CODEX_APP_SERVER_READY".to_owned()
                } else {
                    "CODEX_APP_SERVER_FINGERPRINT_MISMATCH".to_owned()
                }],
                evidence_refs: vec![format!("schema-sha256:{observed_schema}")],
                observed_at: Some(now()),
            })
        })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            self.ensure_session(&material.workspace_root).await?;
            let thread_id = self.start_or_resume_thread(envelope, material).await?;
            let session = self.session.as_mut().expect("session initialized");
            let request_id = session.next_id();
            let request = json!({
                "id": request_id,
                "method": "turn/start",
                "params": {
                    "threadId": thread_id,
                    "input": [{ "type": "text", "text": material.prompt }],
                    "cwd": material.workspace_root,
                    "approvalPolicy": "untrusted",
                    "model": material.model
                }
            });
            let raw = serde_json::to_vec(&request).unwrap_or_default();
            session.write_value(&request).await.map_err(|mut error| {
                error.certainty = DriverErrorCertainty::DeliveryUnknown;
                error
            })?;
            self.active = Some(ActiveDispatch {
                dispatch_id: envelope.dispatch_id.clone(),
                thread_id: thread_id.clone(),
                turn_id: None,
                turn_request_id: request_id,
            });
            self.completed_dispatch_id = None;
            Ok(DriverDelivery {
                native_request_ref: format!("codex-jsonrpc:{request_id}"),
                native_session_ref: thread_id,
                native_execution_ref: None,
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
            if let Some(event) = self.queued_events.pop_front() {
                return Ok(Some(event));
            }
            // An unresolved server request is an explicit handoff to the
            // approval authority. Do not block the governed dispatch worker
            // waiting for a native response that requires a separate
            // decide_approval call.
            if !self.pending_approvals.is_empty() {
                return Ok(None);
            }
            if self
                .active
                .as_ref()
                .is_none_or(|active| active.dispatch_id != envelope.dispatch_id)
            {
                return Err(dependency_error("CODEX_ACTIVE_DISPATCH_NOT_FOUND"));
            }
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| dependency_error("CODEX_SESSION_NOT_RUNNING"))?;
            let (value, raw) = session.read_next_value(self.config.request_timeout).await?;
            self.map_value(envelope, value, raw)
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move { self.send_approval_response(envelope).await })
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| dependency_error("CODEX_SESSION_NOT_RUNNING"))?;
            let request_id = session.next_id();
            let request = json!({
                "id": request_id,
                "method": "turn/interrupt",
                "params": {
                    "threadId": envelope.native_session_ref,
                    "turnId": envelope.native_execution_ref
                }
            });
            let raw = serde_json::to_vec(&request).unwrap_or_default();
            session.write_value(&request).await.map_err(|mut error| {
                error.certainty = DriverErrorCertainty::DeliveryUnknown;
                error
            })?;
            self.pending_control_requests
                .insert(request_id, "turn-interrupt");
            Ok(raw)
        })
    }

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async move {
            self.ensure_session(&context.material.workspace_root)
                .await?;
            let active = self
                .active
                .as_ref()
                .filter(|active| active.dispatch_id == context.envelope.dispatch_id);
            let thread_id = active.map(|active| active.thread_id.clone()).or_else(|| {
                context
                    .delivery_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.native_session_ref.clone())
            });
            let Some(thread_id) = thread_id else {
                return Ok(ReconciliationFinding::OutcomeUnknown {
                    evidence_ref: "codex-reconcile:no-durable-thread-reference".to_owned(),
                });
            };
            let expected_turn_id = active
                .and_then(|active| active.turn_id.clone())
                .or_else(|| {
                    context
                        .delivery_receipt
                        .as_ref()
                        .and_then(|receipt| receipt.native_execution_ref.clone())
                });
            let session = self.session.as_mut().expect("session initialized");
            let request_id = session.next_id();
            session
                .write_value(&json!({
                    "id": request_id,
                    "method": "thread/read",
                    "params": { "threadId": thread_id, "includeTurns": true }
                }))
                .await?;
            let (response, raw) = session
                .read_response(request_id, self.config.request_timeout)
                .await?;
            let evidence_ref = format!("codex-thread-read-sha256:{}", sha256(&raw));
            let status = response
                .pointer("/result/thread/status/type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let turns = response
                .pointer("/result/thread/turns")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let turn = expected_turn_id
                .as_ref()
                .and_then(|expected| {
                    turns
                        .iter()
                        .find(|turn| turn.get("id").and_then(Value::as_str) == Some(expected))
                })
                .or_else(|| {
                    (context.envelope.native_session_ref.is_none() && turns.len() == 1)
                        .then(|| turns.first())
                        .flatten()
                });
            if status == "active" {
                return Ok(ReconciliationFinding::NativeExecutionActive { evidence_ref });
            }
            if let Some(turn_status) = turn
                .and_then(|turn| turn.get("status"))
                .and_then(Value::as_str)
            {
                if matches!(turn_status, "completed" | "interrupted" | "failed") {
                    return Ok(ReconciliationFinding::TerminalObservationRecovered {
                        evidence_ref,
                    });
                }
                if turn_status == "inProgress" {
                    return Ok(ReconciliationFinding::NativeExecutionActive { evidence_ref });
                }
            }
            Ok(ReconciliationFinding::OutcomeUnknown { evidence_ref })
        })
    }
}

impl CodexSession {
    fn next_id(&mut self) -> u64 {
        let value = self.next_request_id;
        self.next_request_id += 1;
        value
    }

    async fn write_value(&mut self, value: &Value) -> Result<(), DriverError> {
        let mut bytes = serde_json::to_vec(value).map_err(|error| {
            driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::SchemaInvalid,
                "CODEX_REQUEST_SERIALIZATION_FAILED",
                format!("{error:?}").as_bytes(),
            )
        })?;
        bytes.push(b'\n');
        self.process
            .stdin
            .write_all(&bytes)
            .await
            .map_err(|error| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::DeliveryUnknown,
                    "CODEX_STDIN_WRITE_FAILED",
                    format!("{error:?}").as_bytes(),
                )
            })?;
        self.process.stdin.flush().await.map_err(|error| {
            driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::DeliveryUnknown,
                "CODEX_STDIN_FLUSH_FAILED",
                format!("{error:?}").as_bytes(),
            )
        })
    }

    async fn read_value(&mut self, deadline: Duration) -> Result<(Value, Vec<u8>), DriverError> {
        let mut raw = Vec::new();
        let read = timeout(deadline, self.process.stdout.read_until(b'\n', &mut raw))
            .await
            .map_err(|_| dependency_error("CODEX_RESPONSE_TIMEOUT"))?
            .map_err(|error| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::DependencyUnavailable,
                    "CODEX_STDOUT_READ_FAILED",
                    format!("{error:?}").as_bytes(),
                )
            })?;
        if read == 0 {
            return Err(dependency_error("CODEX_APP_SERVER_EOF"));
        }
        let value = serde_json::from_slice(&raw).map_err(|error| {
            driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::ProtocolMismatch,
                "CODEX_JSONL_INVALID",
                format!("{error:?}").as_bytes(),
            )
        })?;
        Ok((value, raw))
    }

    async fn read_next_value(
        &mut self,
        deadline: Duration,
    ) -> Result<(Value, Vec<u8>), DriverError> {
        if let Some(message) = self.pending_messages.pop_front() {
            return Ok(message);
        }
        self.read_value(deadline).await
    }

    async fn read_response(
        &mut self,
        request_id: u64,
        deadline: Duration,
    ) -> Result<(Value, Vec<u8>), DriverError> {
        loop {
            let (value, raw) = self.read_value(deadline).await?;
            if value.get("id").and_then(Value::as_u64) == Some(request_id)
                && value.get("method").is_none()
            {
                if value.get("error").is_some() {
                    return Err(driver_error(
                        DriverErrorCertainty::ProvenNotSent,
                        HarnessErrorCode::DeliveryRejected,
                        "CODEX_REQUEST_REJECTED",
                        value.to_string().as_bytes(),
                    ));
                }
                return Ok((value, raw));
            }
            self.pending_messages.push_back((value, raw));
        }
    }
}

async fn probe_version(config: &CodexAppServerConfig) -> Result<String, DriverError> {
    let working_directory = std::env::current_dir().map_err(|error| {
        driver_error(
            DriverErrorCertainty::ProvenNotSent,
            HarnessErrorCode::ConfigInvalid,
            "CURRENT_DIRECTORY_UNAVAILABLE",
            format!("{error:?}").as_bytes(),
        )
    })?;
    let mut spec = SupervisedProcessSpec::new(&config.executable, working_directory);
    spec.arguments = vec!["--version".to_owned()];
    let mut process = SupervisedProcess::spawn(&spec)
        .await
        .map_err(|error| dependency_error(&format!("CODEX_VERSION_SPAWN_FAILED:{error:?}")))?;
    let mut stdout = String::new();
    process
        .stdout
        .read_to_string(&mut stdout)
        .await
        .map_err(|error| dependency_error(&format!("CODEX_VERSION_READ_FAILED:{error:?}")))?;
    let status = process
        .wait()
        .await
        .map_err(|error| dependency_error(&format!("CODEX_VERSION_WAIT_FAILED:{error:?}")))?;
    if !status.success() {
        return Err(dependency_error("CODEX_VERSION_COMMAND_FAILED"));
    }
    Ok(stdout
        .trim()
        .strip_prefix("codex-cli ")
        .unwrap_or(stdout.trim())
        .to_owned())
}

async fn probe_schema(config: &CodexAppServerConfig) -> Result<String, DriverError> {
    let root = std::env::temp_dir().join(format!("egopulse-codex-schema-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)
        .map_err(|error| dependency_error(&format!("CODEX_SCHEMA_TEMP_CREATE_FAILED:{error:?}")))?;
    let working_directory = std::env::current_dir()
        .map_err(|error| dependency_error(&format!("CURRENT_DIRECTORY_UNAVAILABLE:{error:?}")))?;
    let mut spec = SupervisedProcessSpec::new(&config.executable, working_directory);
    spec.arguments = vec![
        "app-server".to_owned(),
        "generate-json-schema".to_owned(),
        "--experimental".to_owned(),
        "--out".to_owned(),
        root.to_string_lossy().into_owned(),
    ];
    let mut process = SupervisedProcess::spawn(&spec)
        .await
        .map_err(|error| dependency_error(&format!("CODEX_SCHEMA_SPAWN_FAILED:{error:?}")))?;
    let status = process
        .wait()
        .await
        .map_err(|error| dependency_error(&format!("CODEX_SCHEMA_WAIT_FAILED:{error:?}")))?;
    if !status.success() {
        return Err(dependency_error("CODEX_SCHEMA_COMMAND_FAILED"));
    }
    let path = root.join("codex_app_server_protocol.v2.schemas.json");
    let bytes = std::fs::read(&path)
        .map_err(|error| dependency_error(&format!("CODEX_SCHEMA_READ_FAILED:{error:?}")))?;
    let digest = sha256(&bytes);
    let _ = std::fs::remove_dir_all(&root);
    Ok(digest)
}

fn lifecycle_event(
    method: &str,
    kind: LifecycleKind,
    native_item_ref: Option<&str>,
    status: &str,
    will_retry: Option<bool>,
    raw_event: Vec<u8>,
) -> DriverEvent {
    DriverEvent {
        native_key: format!("{}:{}", method, sha256(&raw_event)),
        native_event_id: None,
        native_sequence: None,
        native_observed_at: now(),
        criticality: if matches!(
            kind,
            LifecycleKind::ExecutionCompleted
                | LifecycleKind::ExecutionInterrupted
                | LifecycleKind::ExecutionFailed
                | LifecycleKind::ProcessExited
        ) {
            ObservationCriticality::Terminal
        } else {
            ObservationCriticality::Control
        },
        payload: harness_observation::Payload::Lifecycle(LifecycleObservation {
            kind: kind as i32,
            native_item_ref: native_item_ref.map(str::to_owned),
            safe_status_code: Some(status.to_owned()),
            side_effect_certainty: SideEffectCertainty::Unknown as i32,
            native_will_retry: will_retry,
        }),
        raw_event,
    }
}

fn native_key(method: &str, raw_event: &[u8]) -> String {
    // Codex app-server v2 notifications do not expose a durable event id or
    // sequence. The exact raw line is therefore the strongest replay identity
    // available: byte-identical redelivery replays, while a later occurrence
    // with different evidence remains a distinct observation.
    format!("{method}:{}", sha256(raw_event))
}

fn approval_word(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::AllowOnce => "accept",
        ApprovalDecision::Deny => "decline",
        ApprovalDecision::CancelAttempt | ApprovalDecision::Unspecified => "cancel",
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

fn driver_error(
    certainty: DriverErrorCertainty,
    code: HarnessErrorCode,
    detail: &str,
    raw: &[u8],
) -> DriverError {
    DriverError {
        certainty,
        code,
        safe_detail_code: detail.to_owned(),
        error_fingerprint: Some(sha256(raw)),
        raw_evidence: raw.to_vec(),
    }
}

fn dependency_error(detail: &str) -> DriverError {
    driver_error(
        DriverErrorCertainty::DeliveryUnknown,
        HarnessErrorCode::DependencyUnavailable,
        detail,
        detail.as_bytes(),
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval_request(id: u64) -> Value {
        json!({
            "id": id,
            "method": "item/commandExecution/requestApproval",
            "params": { "command": "cargo test" }
        })
    }

    fn approval_payload(event: DriverEvent) -> ApprovalRequestObservation {
        match event.payload {
            harness_observation::Payload::ApprovalRequest(value) => value,
            _ => panic!("expected approval request lifecycle observation"),
        }
    }

    #[test]
    fn native_resolution_preserves_request_identity_and_advances_lifecycle_revision() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let request = approval_request(7);
        let raw = serde_json::to_vec(&request).expect("request bytes");
        let opened = driver
            .map_server_request("item/commandExecution/requestApproval", request, raw)
            .expect("map request")
            .map(approval_payload)
            .expect("request event");
        assert_eq!(opened.lifecycle, ApprovalRequestLifecycleKind::Open as i32);
        assert_eq!(opened.request_revision, 1);

        let resolved = json!({
            "method": "serverRequest/resolved",
            "params": { "requestId": 7 }
        });
        let raw = serde_json::to_vec(&resolved).expect("resolved bytes");
        let withdrawn = driver
            .map_notification(
                &DispatchEnvelope::default(),
                "serverRequest/resolved",
                resolved,
                raw,
            )
            .expect("map withdrawal")
            .map(approval_payload)
            .expect("withdrawal event");
        assert_eq!(withdrawn.approval_request_id, opened.approval_request_id);
        assert_eq!(
            withdrawn.lifecycle,
            ApprovalRequestLifecycleKind::Withdrawn as i32
        );
        assert_eq!(withdrawn.request_revision, 2);
    }

    #[test]
    fn responded_request_resolves_without_losing_canonical_request_identity() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let request = approval_request(8);
        let raw = serde_json::to_vec(&request).expect("request bytes");
        let opened = driver
            .map_server_request("item/commandExecution/requestApproval", request, raw)
            .expect("map request")
            .map(approval_payload)
            .expect("request event");
        let routing = opened.native_routing_ref.clone();
        let pending = driver
            .pending_approvals
            .remove(&routing)
            .expect("pending approval");
        driver
            .responded_approvals
            .insert(pending.request_id.to_string(), pending.observation);

        let resolved = json!({
            "method": "serverRequest/resolved",
            "params": { "requestId": 8 }
        });
        let raw = serde_json::to_vec(&resolved).expect("resolved bytes");
        let completed = driver
            .map_notification(
                &DispatchEnvelope::default(),
                "serverRequest/resolved",
                resolved,
                raw,
            )
            .expect("map resolution")
            .map(approval_payload)
            .expect("resolution event");
        assert_eq!(completed.approval_request_id, opened.approval_request_id);
        assert_eq!(
            completed.lifecycle,
            ApprovalRequestLifecycleKind::Resolved as i32
        );
        assert_eq!(completed.request_revision, 2);
    }

    #[tokio::test]
    async fn terminal_notification_closes_dispatch_observation_stream() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-terminal".to_owned(),
            ..Default::default()
        };
        let notification = json!({
            "method": "turn/completed",
            "params": { "turn": { "status": "completed" } }
        });
        let raw = serde_json::to_vec(&notification).expect("notification bytes");
        let event = driver
            .map_notification(&envelope, "turn/completed", notification, raw)
            .expect("map terminal notification")
            .expect("terminal event");
        assert_eq!(event.criticality, ObservationCriticality::Terminal);
        assert!(driver.active.is_none());
        assert_eq!(
            driver.completed_dispatch_id.as_deref(),
            Some("dispatch-terminal")
        );
        assert!(
            driver
                .next_event(&envelope)
                .await
                .expect("terminal stream close")
                .is_none()
        );
    }

    #[tokio::test]
    async fn unresolved_approval_pauses_dispatch_observation_stream() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-approval-pause".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-approval-pause".to_owned(),
            turn_id: Some("turn-approval-pause".to_owned()),
            turn_request_id: 1,
        });
        let request = approval_request(9);
        let raw = serde_json::to_vec(&request).expect("request bytes");
        driver
            .map_server_request("item/commandExecution/requestApproval", request, raw)
            .expect("map request")
            .expect("approval event");

        assert!(
            driver
                .next_event(&envelope)
                .await
                .expect("approval pause must be a clean boundary")
                .is_none()
        );
    }

    #[test]
    fn cancelled_mcp_startup_is_not_a_dispatch_recovery_signal() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-mcp-cancelled".to_owned(),
            ..Default::default()
        };
        let notification = json!({
            "method": "mcpServer/startupStatus/updated",
            "params": { "status": "cancelled" }
        });
        let raw = serde_json::to_vec(&notification).expect("notification bytes");
        let event = driver
            .map_notification(
                &envelope,
                "mcpServer/startupStatus/updated",
                notification,
                raw,
            )
            .expect("map cancelled MCP startup")
            .expect("cancelled MCP startup event");
        assert_eq!(event.criticality, ObservationCriticality::Informational);
        match event.payload {
            harness_observation::Payload::Diagnostic(value) => {
                assert_eq!(
                    value.safe_diagnostic_code,
                    "CODEX_MCP_SERVER_STARTUP_CANCELLED"
                );
                assert!(!value.recovery_required);
                assert!(value.error_fingerprint.is_none());
            }
            _ => panic!("expected diagnostic payload"),
        }
    }
}
