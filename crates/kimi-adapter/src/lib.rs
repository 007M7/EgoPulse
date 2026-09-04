#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod acp;

use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
    ApprovalRequestObservation, CancelExecutionEnvelope, DispatchEnvelope, HarnessErrorCode,
    HarnessReadiness, LifecycleKind, LifecycleObservation, NativeProtocolFingerprint,
    ObservationCriticality, ProbeHarnessRequest, ProbeHarnessResult, harness_observation,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
    TerminalOutputCandidate,
};
use egopulse_process_supervision::{SupervisedProcess, SupervisedProcessSpec};
use prost_types::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use uuid::Uuid;

pub const KIMI_ADAPTER_ID: &str = "kimi-adapter";
pub const KIMI_ACP_PROTOCOL: &str = "agent-client-protocol";
pub const KIMI_ACP_PROTOCOL_VERSION: &str = "v1";
pub const KIMI_NATIVE_RECOVERY_NO_SESSION_REF: &str =
    "kimi-reconcile:no-durable-native-session-reference";
pub const KIMI_NATIVE_RECOVERY_OUTCOME_UNATTESTED: &str =
    "kimi-reconcile:session-resumed-dispatch-outcome-unattested";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KimiSessionProbeDisposition {
    Created {
        native_session_ref: String,
        evidence_ref: String,
    },
    AuthenticationRequired {
        auth_method_ids: Vec<String>,
        evidence_ref: String,
    },
    Rejected {
        safe_detail_code: String,
        evidence_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KimiSessionProbeResult {
    pub initialize: ProbeHarnessResult,
    pub session: KimiSessionProbeDisposition,
}

#[derive(Clone, Debug)]
pub struct KimiAcpConfig {
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub share_directory: Option<PathBuf>,
    pub environment_overrides: Vec<(String, String)>,
    /// Exact ACP model id expected from `session/new` and `session/resume`.
    /// Production composition must set this so a configured Kimi profile
    /// cannot silently route to a different model.
    pub required_model: Option<String>,
    pub request_timeout: Duration,
}

impl KimiAcpConfig {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, working_directory: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            working_directory: working_directory.into(),
            share_directory: None,
            environment_overrides: Vec::new(),
            required_model: None,
            request_timeout: Duration::from_secs(10),
        }
    }

    #[must_use]
    pub fn with_share_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.share_directory = Some(directory.into());
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

    #[must_use]
    pub fn with_required_model(mut self, model: impl Into<String>) -> Self {
        self.required_model = Some(model.into());
        self
    }
}

struct KimiSession {
    process: SupervisedProcess,
    next_request_id: u64,
    native_session_ref: String,
}

struct ActiveDispatch {
    dispatch_id: String,
    native_session_ref: String,
    prompt_request_id: u64,
    output_text: String,
    output_candidate_taken: bool,
}

#[derive(Clone)]
struct PendingApproval {
    request_id: Value,
    params: Value,
    observation: ApprovalRequestObservation,
}

/// Candidate-only Kimi ACP driver.
///
/// The driver supports the native ACP session lifecycle and keeps all
/// resulting execution, approval and output evidence behind the same
/// provider-neutral `NativeHarnessDriver` boundary as the other candidates.
/// It remains candidate-only until an authenticated lifecycle, schema,
/// artifact and recovery matrix is independently attested.
pub struct KimiAcpDriver {
    config: KimiAcpConfig,
    session: Option<KimiSession>,
    active: Option<ActiveDispatch>,
    completed_dispatch_id: Option<String>,
    pending_approvals: HashMap<String, PendingApproval>,
}

impl KimiAcpDriver {
    #[must_use]
    pub fn new(config: KimiAcpConfig) -> Self {
        Self {
            config,
            session: None,
            active: None,
            completed_dispatch_id: None,
            pending_approvals: HashMap::new(),
        }
    }

    /// Performs the ACP initialize plus empty-session setup probe. It does not
    /// send a prompt or invoke model inference. A created session is returned
    /// only as an opaque probe result and is not installed into a production
    /// capability profile.
    pub async fn probe_session(&self) -> Result<KimiSessionProbeResult, DriverError> {
        probe_session(&self.config).await
    }

    async fn ensure_session(&mut self, working_directory: &Path) -> Result<(), DriverError> {
        if self.session.is_some() {
            return Ok(());
        }
        let mut process = spawn_process(&self.config).await?;
        let initialize = initialize_request();
        write_json_line(
            &mut process,
            &initialize,
            "KIMI_ACP_INITIALIZE_WRITE_FAILED",
        )
        .await?;
        let initialize_raw = read_json_line(
            &mut process,
            self.config.request_timeout,
            "KIMI_ACP_INITIALIZE_TIMEOUT",
            "KIMI_ACP_INITIALIZE_READ_FAILED",
            "KIMI_ACP_INITIALIZE_EOF",
            &initialize,
        )
        .await?;
        let initialize_message =
            acp::parse_message(initialize_raw.as_bytes()).map_err(|detail| {
                driver_error("KIMI_ACP_INITIALIZE_INVALID_MESSAGE", detail.as_bytes())
            })?;
        let initialize_result = match initialize_message {
            acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Result { result, .. }) => result,
            _ => {
                return Err(driver_error(
                    "KIMI_ACP_INITIALIZE_REJECTED",
                    initialize_raw.as_bytes(),
                ));
            }
        };
        validate_required_recovery_capabilities(&initialize_result)
            .map_err(|code| driver_error(code, initialize_raw.as_bytes()))?;

        let session_request = session_new_request(working_directory);
        write_json_line(
            &mut process,
            &session_request,
            "KIMI_ACP_SESSION_NEW_WRITE_FAILED",
        )
        .await?;
        let session_raw = read_json_line(
            &mut process,
            self.config.request_timeout,
            "KIMI_ACP_SESSION_NEW_TIMEOUT",
            "KIMI_ACP_SESSION_NEW_READ_FAILED",
            "KIMI_ACP_SESSION_NEW_EOF",
            &session_request,
        )
        .await?;
        let session_id = match acp::parse_message(session_raw.as_bytes()).map_err(|detail| {
            driver_error("KIMI_ACP_SESSION_NEW_INVALID_MESSAGE", detail.as_bytes())
        })? {
            acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Result { result, .. }) => {
                validate_required_session_model(&result, self.config.required_model.as_deref())
                    .map_err(|code| driver_error(code, session_raw.as_bytes()))?;
                result
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        driver_error("KIMI_ACP_SESSION_ID_MISSING", session_raw.as_bytes())
                    })?
            }
            acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Error { .. }) => {
                return Err(driver_error(
                    "KIMI_ACP_SESSION_NEW_REJECTED",
                    session_raw.as_bytes(),
                ));
            }
            _ => {
                return Err(driver_error(
                    "KIMI_ACP_SESSION_NEW_INVALID_MESSAGE",
                    session_raw.as_bytes(),
                ));
            }
        };
        self.session = Some(KimiSession {
            process,
            next_request_id: 3,
            native_session_ref: session_id,
        });
        Ok(())
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
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            if self.active.is_some()
                && self.completed_dispatch_id.as_deref()
                    != self.active.as_ref().map(|value| value.dispatch_id.as_str())
            {
                return Err(dependency_error("KIMI_ACP_ACTIVE_DISPATCH_EXISTS"));
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
                "KIMI_ACP_PROMPT_WRITE_FAILED",
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
                output_candidate_taken: false,
            });
            self.completed_dispatch_id = None;
            Ok(DriverDelivery {
                native_request_ref: format!("kimi-acp-jsonrpc:{request_id}"),
                native_session_ref,
                native_execution_ref: Some(format!("kimi-acp-prompt:{request_id}")),
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
                .ok_or_else(|| dependency_error("KIMI_ACP_ACTIVE_DISPATCH_NOT_FOUND"))?;
            loop {
                let line = {
                    let session = self
                        .session
                        .as_mut()
                        .ok_or_else(|| dependency_error("KIMI_ACP_SESSION_NOT_RUNNING"))?;
                    read_json_line(
                        &mut session.process,
                        self.config.request_timeout,
                        "KIMI_ACP_EVENT_TIMEOUT",
                        "KIMI_ACP_EVENT_READ_FAILED",
                        "KIMI_ACP_EVENT_EOF",
                        b"kimi-acp-event",
                    )
                    .await?
                };
                let message = acp::parse_message(line.as_bytes()).map_err(|detail| {
                    driver_error("KIMI_ACP_EVENT_INVALID_MESSAGE", detail.as_bytes())
                })?;
                match message {
                    acp::KimiAcpMessage::Notification(
                        acp::KimiAcpNotification::SessionUpdate { session_id, update },
                    ) => {
                        if session_id != native_session_ref {
                            return Err(driver_error(
                                "KIMI_ACP_SESSION_ID_MISMATCH",
                                line.as_bytes(),
                            ));
                        }
                        if let acp::KimiAcpUpdate::AgentMessageChunk { text } = update
                            && let Some(active) = self.active.as_mut()
                        {
                            active.output_text.push_str(&text);
                        }
                    }
                    acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Result { id, result })
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
                                    "KIMI_ACP_TERMINAL_STATUS_UNKNOWN",
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
                    acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Error { id, .. })
                        if id.as_ref().and_then(Value::as_u64) == Some(prompt_request_id) =>
                    {
                        self.completed_dispatch_id = Some(dispatch_id);
                        return Ok(Some(lifecycle_event(
                            "session/prompt",
                            LifecycleKind::ExecutionFailed,
                            "error",
                            line.into_bytes(),
                        )));
                    }
                    acp::KimiAcpMessage::ServerRequest(request)
                        if request.method == "session/request_permission" =>
                    {
                        let routing_ref = format!("kimi-acp-routing:approval:{}", Uuid::now_v7());
                        let observation = ApprovalRequestObservation {
                            approval_request_id: Uuid::now_v7().to_string(),
                            kind: ApprovalKind::Permission as i32,
                            action_digest_sha256: sha256(request.params.to_string().as_bytes()),
                            requested_scope_ref: "adapter-edge://kimi-acp/approval/scope"
                                .to_owned(),
                            display_summary_ref: "adapter-edge://kimi-acp/approval/summary"
                                .to_owned(),
                            native_routing_ref: routing_ref.clone(),
                            lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                            request_revision: 1,
                        };
                        self.pending_approvals.insert(
                            routing_ref,
                            PendingApproval {
                                request_id: request.id,
                                params: request.params,
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
                    acp::KimiAcpMessage::ServerRequest(_) => {
                        return Err(driver_error(
                            "KIMI_ACP_APPROVAL_OR_SERVER_REQUEST_UNATTESTED",
                            line.as_bytes(),
                        ));
                    }
                    acp::KimiAcpMessage::Notification(_) => {}
                    acp::KimiAcpMessage::Response(_) => {}
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
                .ok_or_else(|| dependency_error("KIMI_ACP_SESSION_NOT_RUNNING"))?;
            if envelope.native_session_ref != session.native_session_ref {
                return Err(driver_error(
                    "KIMI_ACP_CANCEL_SESSION_MISMATCH",
                    envelope.native_session_ref.as_bytes(),
                ));
            }
            let request_id = session.next_request_id;
            session.next_request_id = session.next_request_id.saturating_add(1);
            let request = acp::session_cancel_request(request_id, &session.native_session_ref);
            let raw = serde_json::to_vec(&request).unwrap_or_default();
            write_json_value(
                &mut session.process,
                &request,
                "KIMI_ACP_CANCEL_WRITE_FAILED",
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
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async move {
            let native_session_ref = self
                .active
                .as_ref()
                .filter(|active| active.dispatch_id == context.envelope.dispatch_id)
                .map(|active| active.native_session_ref.clone())
                .or_else(|| {
                    context
                        .delivery_receipt
                        .as_ref()
                        .and_then(|receipt| receipt.native_session_ref.clone())
                });
            let Some(native_session_ref) = native_session_ref else {
                return Ok(ReconciliationFinding::OutcomeUnknown {
                    evidence_ref: KIMI_NATIVE_RECOVERY_NO_SESSION_REF.to_owned(),
                });
            };

            let mut process = spawn_process(&self.config).await?;
            let initialize = initialize_request();
            write_json_line(
                &mut process,
                &initialize,
                "KIMI_ACP_RECOVERY_INITIALIZE_WRITE_FAILED",
            )
            .await?;
            let initialize_raw = read_json_line(
                &mut process,
                self.config.request_timeout,
                "KIMI_ACP_RECOVERY_INITIALIZE_TIMEOUT",
                "KIMI_ACP_RECOVERY_INITIALIZE_READ_FAILED",
                "KIMI_ACP_RECOVERY_INITIALIZE_EOF",
                &initialize,
            )
            .await?;
            let initialize_result =
                match acp::parse_message(initialize_raw.as_bytes()).map_err(|detail| {
                    driver_error(
                        "KIMI_ACP_RECOVERY_INITIALIZE_INVALID_MESSAGE",
                        detail.as_bytes(),
                    )
                })? {
                    acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Result {
                        result, ..
                    }) => result,
                    _ => {
                        return Err(driver_error(
                            "KIMI_ACP_RECOVERY_INITIALIZE_REJECTED",
                            initialize_raw.as_bytes(),
                        ));
                    }
                };
            validate_required_recovery_capabilities(&initialize_result)
                .map_err(|code| driver_error(code, initialize_raw.as_bytes()))?;

            let resume_request =
                session_resume_request(&context.material.workspace_root, &native_session_ref, 2);
            write_json_value(
                &mut process,
                &resume_request,
                "KIMI_ACP_SESSION_RESUME_WRITE_FAILED",
            )
            .await?;
            let resume_bytes = serde_json::to_vec(&resume_request).unwrap_or_default();
            let resume_raw = read_json_line(
                &mut process,
                self.config.request_timeout,
                "KIMI_ACP_SESSION_RESUME_TIMEOUT",
                "KIMI_ACP_SESSION_RESUME_READ_FAILED",
                "KIMI_ACP_SESSION_RESUME_EOF",
                &resume_bytes,
            )
            .await?;
            let finding = classify_session_resume_response(
                resume_raw.as_bytes(),
                self.config.required_model.as_deref(),
            )?;
            let _ = process.terminate().await;
            let _ = process.wait().await;
            Ok(finding)
        })
    }

    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        Box::pin(async move {
            if self.completed_dispatch_id.as_deref() != Some(envelope.dispatch_id.as_str()) {
                return Ok(None);
            }
            let Some(active) = self
                .active
                .as_mut()
                .filter(|value| value.dispatch_id == envelope.dispatch_id)
            else {
                return Ok(None);
            };
            if active.output_candidate_taken {
                return Ok(None);
            }
            active.output_candidate_taken = true;
            let content = std::mem::take(&mut active.output_text).into_bytes();
            Ok(Some(TerminalOutputCandidate {
                dispatch_id: envelope.dispatch_id.clone(),
                native_completion_ref: format!("kimi-acp-prompt:{}", active.prompt_request_id),
                media_type: "text/plain; charset=utf-8".to_owned(),
                content,
            }))
        })
    }
}

async fn probe_initialize(
    config: &KimiAcpConfig,
    _request: &ProbeHarnessRequest,
) -> Result<ProbeHarnessResult, DriverError> {
    let mut process = spawn_process(config).await?;
    let encoded = initialize_request();
    write_json_line(&mut process, &encoded, "KIMI_ACP_INITIALIZE_WRITE_FAILED").await?;
    let line = read_json_line(
        &mut process,
        config.request_timeout,
        "KIMI_ACP_INITIALIZE_TIMEOUT",
        "KIMI_ACP_INITIALIZE_READ_FAILED",
        "KIMI_ACP_INITIALIZE_EOF",
        &encoded,
    )
    .await?;
    let _ = process.terminate().await;
    let _ = process.wait().await;
    parse_initialize_response(line.as_bytes())
}

async fn probe_session(config: &KimiAcpConfig) -> Result<KimiSessionProbeResult, DriverError> {
    let mut process = spawn_process(config).await?;
    let initialize = initialize_request();
    write_json_line(
        &mut process,
        &initialize,
        "KIMI_ACP_INITIALIZE_WRITE_FAILED",
    )
    .await?;
    let initialize_line = read_json_line(
        &mut process,
        config.request_timeout,
        "KIMI_ACP_INITIALIZE_TIMEOUT",
        "KIMI_ACP_INITIALIZE_READ_FAILED",
        "KIMI_ACP_INITIALIZE_EOF",
        &initialize,
    )
    .await?;
    let initialize_result = parse_initialize_response(initialize_line.as_bytes())?;

    let session_request = session_new_request(&config.working_directory);
    write_json_line(
        &mut process,
        &session_request,
        "KIMI_ACP_SESSION_NEW_WRITE_FAILED",
    )
    .await?;
    let session_line = read_json_line(
        &mut process,
        config.request_timeout,
        "KIMI_ACP_SESSION_NEW_TIMEOUT",
        "KIMI_ACP_SESSION_NEW_READ_FAILED",
        "KIMI_ACP_SESSION_NEW_EOF",
        &session_request,
    )
    .await?;
    let session_result =
        parse_session_new_response(session_line.as_bytes(), config.required_model.as_deref())?;
    let _ = process.terminate().await;
    let _ = process.wait().await;
    Ok(KimiSessionProbeResult {
        initialize: initialize_result,
        session: session_result,
    })
}

async fn send_approval_response(
    driver: &mut KimiAcpDriver,
    envelope: &ApprovalDecisionEnvelope,
) -> Result<Vec<u8>, DriverError> {
    let pending = driver
        .pending_approvals
        .get(&envelope.native_routing_ref)
        .cloned()
        .ok_or_else(|| {
            driver_error(
                "KIMI_ACP_APPROVAL_ROUTING_NOT_FOUND",
                envelope.native_routing_ref.as_bytes(),
            )
        })?;
    if envelope.approval_request_id != pending.observation.approval_request_id
        || envelope.action_digest_sha256 != pending.observation.action_digest_sha256
    {
        return Err(driver_error(
            "KIMI_ACP_APPROVAL_IDENTITY_MISMATCH",
            envelope.native_routing_ref.as_bytes(),
        ));
    }
    let decision = ApprovalDecision::try_from(envelope.decision)
        .map_err(|_| driver_error("KIMI_ACP_APPROVAL_DECISION_INVALID", &[]))?;
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
            return Err(driver_error("KIMI_ACP_APPROVAL_DECISION_INVALID", &[]));
        }
    };
    let response = json!({ "jsonrpc": "2.0", "id": pending.request_id, "result": result });
    let raw = serde_json::to_vec(&response).unwrap_or_default();
    let session = driver
        .session
        .as_mut()
        .ok_or_else(|| dependency_error("KIMI_ACP_SESSION_NOT_RUNNING"))?;
    write_json_value(
        &mut session.process,
        &response,
        "KIMI_ACP_APPROVAL_RESPONSE_WRITE_FAILED",
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
        .ok_or_else(|| driver_error("KIMI_ACP_PERMISSION_OPTION_UNAVAILABLE", &[]))?;
    Ok(json!({
        "outcome": { "outcome": "selected", "optionId": option }
    }))
}

async fn spawn_process(config: &KimiAcpConfig) -> Result<SupervisedProcess, DriverError> {
    SupervisedProcess::spawn(&process_spec(config))
        .await
        .map_err(|error| driver_error("KIMI_ACP_SPAWN_FAILED", format!("{error:?}").as_bytes()))
}

fn process_spec(config: &KimiAcpConfig) -> SupervisedProcessSpec {
    let mut spec = SupervisedProcessSpec::new(&config.executable, &config.working_directory)
        .with_minimal_user_environment()
        .with_inherited_environment("KIMI_HOME");
    spec.arguments = vec!["acp".to_owned()];
    if let Some(directory) = &config.share_directory {
        spec = spec.with_environment_override("KIMI_SHARE_DIR", directory.display().to_string());
    }
    for (name, value) in &config.environment_overrides {
        spec = spec.with_environment_override(name.clone(), value.clone());
    }
    spec
}

fn initialize_request() -> Vec<u8> {
    serde_json::to_vec(&json!({
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
    }))
    .unwrap_or_default()
}

fn session_new_request(working_directory: &Path) -> Vec<u8> {
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

fn session_resume_request(working_directory: &Path, session_id: &str, id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "session/resume",
        "params": {
            "cwd": working_directory,
            "sessionId": session_id,
            "mcpServers": []
        }
    })
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
    eof_code: &str,
    request: &[u8],
) -> Result<String, DriverError> {
    let mut line = String::new();
    let bytes_read = timeout(request_timeout, process.stdout.read_line(&mut line))
        .await
        .map_err(|_| driver_error(timeout_code, request))?
        .map_err(|error| driver_error(read_code, error.to_string().as_bytes()))?;
    if bytes_read == 0 {
        let evidence = collect_process_failure_evidence(process, request).await;
        return Err(driver_error(eof_code, &evidence));
    }
    Ok(line)
}

const MAX_PROCESS_FAILURE_STDERR_BYTES: u64 = 16 * 1024;

async fn collect_process_failure_evidence(
    process: &mut SupervisedProcess,
    request: &[u8],
) -> Vec<u8> {
    let status = match process.try_wait() {
        Ok(Some(status)) => format!("exit_status={status:?}"),
        Ok(None) => {
            let terminate_result = process.terminate().await;
            let wait_result = process.wait().await;
            format!("exit_status_after_terminate={wait_result:?};terminate={terminate_result:?}")
        }
        Err(error) => format!("exit_status_probe_failed={error:?}"),
    };
    let stderr = if let Some(stderr) = process.take_stderr() {
        let mut bounded_stderr = Vec::new();
        let _ = stderr
            .take(MAX_PROCESS_FAILURE_STDERR_BYTES)
            .read_to_end(&mut bounded_stderr)
            .await;
        bounded_stderr
    } else {
        Vec::new()
    };

    let mut evidence = Vec::with_capacity(request.len() + status.len() + stderr.len() + 32);
    evidence.extend_from_slice(request);
    evidence.extend_from_slice(b"\n");
    evidence.extend_from_slice(status.as_bytes());
    evidence.extend_from_slice(b"\nstderr=");
    evidence.extend_from_slice(&stderr);
    evidence
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
    validate_required_recovery_capabilities(result).map_err(|code| driver_error(code, raw))?;
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

fn parse_session_new_response(
    raw: &[u8],
    required_model: Option<&str>,
) -> Result<KimiSessionProbeDisposition, DriverError> {
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        driver_error(
            "KIMI_ACP_SESSION_NEW_INVALID_JSON",
            error.to_string().as_bytes(),
        )
    })?;
    let evidence_ref = format!("kimi-acp-session-new-sha256:{}", sha256(raw));
    if let Some(error) = value.get("error") {
        let auth_method_ids = error
            .pointer("/data/authMethods")
            .and_then(Value::as_array)
            .map(|methods| {
                methods
                    .iter()
                    .filter_map(|method| method.get("id").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !auth_method_ids.is_empty()
            || error
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|message| message.eq_ignore_ascii_case("authentication required"))
        {
            return Ok(KimiSessionProbeDisposition::AuthenticationRequired {
                auth_method_ids,
                evidence_ref,
            });
        }
        return Ok(KimiSessionProbeDisposition::Rejected {
            safe_detail_code: "KIMI_ACP_SESSION_NEW_REJECTED".to_owned(),
            evidence_ref,
        });
    }
    let session_id = value
        .pointer("/result/sessionId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| driver_error("KIMI_ACP_SESSION_ID_MISSING", raw))?;
    validate_required_session_model(value.get("result").unwrap_or(&Value::Null), required_model)
        .map_err(|code| driver_error(code, raw))?;
    Ok(KimiSessionProbeDisposition::Created {
        native_session_ref: session_id.to_owned(),
        evidence_ref,
    })
}

fn validate_required_recovery_capabilities(result: &Value) -> Result<(), &'static str> {
    if result
        .pointer("/agentCapabilities/loadSession")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("KIMI_ACP_LOAD_SESSION_UNATTESTED");
    }
    if !result
        .pointer("/agentCapabilities/sessionCapabilities/resume")
        .is_some_and(Value::is_object)
    {
        return Err("KIMI_ACP_SESSION_RESUME_UNATTESTED");
    }
    Ok(())
}

fn validate_required_session_model(
    result: &Value,
    required_model: Option<&str>,
) -> Result<(), &'static str> {
    let Some(required_model) = required_model else {
        return Ok(());
    };
    let required_model = required_model.trim();
    if required_model.is_empty() {
        return Err("KIMI_ACP_REQUIRED_MODEL_INVALID");
    }
    let current_model = result
        .pointer("/models/currentModelId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("KIMI_ACP_SESSION_MODEL_UNATTESTED")?;
    if current_model != required_model {
        return Err("KIMI_ACP_SESSION_MODEL_MISMATCH");
    }
    Ok(())
}

fn classify_session_resume_response(
    raw: &[u8],
    required_model: Option<&str>,
) -> Result<ReconciliationFinding, DriverError> {
    match acp::parse_message(raw).map_err(|detail| {
        driver_error("KIMI_ACP_SESSION_RESUME_INVALID_MESSAGE", detail.as_bytes())
    })? {
        acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Result { result, .. }) => {
            validate_required_session_model(&result, required_model)
                .map_err(|code| driver_error(code, raw))?;
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: format!(
                    "{}:sha256:{}",
                    KIMI_NATIVE_RECOVERY_OUTCOME_UNATTESTED,
                    sha256(raw)
                ),
            })
        }
        acp::KimiAcpMessage::Response(acp::KimiAcpResponse::Error { .. }) => {
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: format!(
                    "kimi-reconcile:session-resume-rejected:sha256:{}",
                    sha256(raw)
                ),
            })
        }
        _ => Err(driver_error("KIMI_ACP_SESSION_RESUME_INVALID_MESSAGE", raw)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_environment_is_isolated_and_credentials_are_explicit() {
        let config = KimiAcpConfig::new(r"C:\kimi.exe", r"C:\workspace")
            .with_environment_override("KIMI_MODEL_API_KEY", "managed-secret");
        let spec = process_spec(&config);

        assert!(spec.clear_environment);
        assert!(
            spec.inherited_environment
                .iter()
                .all(|name| !name.starts_with("EGOPULSE_") && !name.ends_with("_API_KEY"))
        );
        assert_eq!(
            spec.environment_overrides,
            vec![("KIMI_MODEL_API_KEY".to_owned(), "managed-secret".to_owned())]
        );
    }

    #[test]
    fn initialize_response_is_reachable_but_not_probe_verified_without_schema_digest() {
        let result = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"agentInfo":{"name":"Kimi Code CLI","version":"1.49.0"},"protocolVersion":1,"agentCapabilities":{"loadSession":true,"sessionCapabilities":{"resume":{}}}}}"#,
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

    #[test]
    fn session_authentication_error_is_a_controlled_probe_disposition() {
        let result = parse_session_new_response(
            br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Authentication required","data":{"authMethods":[{"id":"login"}]}}}"#,
            None,
        )
        .expect("parse authentication response");
        assert_eq!(
            result,
            KimiSessionProbeDisposition::AuthenticationRequired {
                auth_method_ids: vec!["login".to_owned()],
                evidence_ref: format!(
                    "kimi-acp-session-new-sha256:{}",
                    sha256(
                        br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"Authentication required","data":{"authMethods":[{"id":"login"}]}}}"#
                    )
                ),
            }
        );
    }

    #[test]
    fn session_creation_keeps_native_session_reference_opaque() {
        let result = parse_session_new_response(
            br#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"kimi-session-001"}}"#,
            None,
        )
        .expect("parse session response");
        assert!(matches!(
            result,
            KimiSessionProbeDisposition::Created {
                native_session_ref,
                ..
            } if native_session_ref == "kimi-session-001"
        ));
    }

    #[test]
    fn initialize_requires_native_load_and_resume_capabilities() {
        let missing_load = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"agentInfo":{"name":"Kimi Code CLI","version":"1.49.0"},"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"resume":{}}}}}"#,
        )
        .expect_err("loadSession is mandatory");
        assert_eq!(
            missing_load.safe_detail_code,
            "KIMI_ACP_LOAD_SESSION_UNATTESTED"
        );

        let missing_resume = parse_initialize_response(
            br#"{"jsonrpc":"2.0","id":1,"result":{"agentInfo":{"name":"Kimi Code CLI","version":"1.49.0"},"protocolVersion":1,"agentCapabilities":{"loadSession":true}}}"#,
        )
        .expect_err("session resume is mandatory");
        assert_eq!(
            missing_resume.safe_detail_code,
            "KIMI_ACP_SESSION_RESUME_UNATTESTED"
        );
    }

    #[test]
    fn exact_session_model_is_required_when_configured() {
        let response = br#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"kimi-session-001","models":{"currentModelId":"kimi-k2.5,thinking"}}}"#;
        assert!(
            parse_session_new_response(response, Some("kimi-k2.5,thinking")).is_ok(),
            "the exact Kimi ACP model id should be accepted"
        );
        assert_eq!(
            parse_session_new_response(response, Some("kimi-k2.5"))
                .expect_err("model fallback must fail closed")
                .safe_detail_code,
            "KIMI_ACP_SESSION_MODEL_MISMATCH"
        );
        assert_eq!(
            parse_session_new_response(
                br#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"kimi-session-001"}}"#,
                Some("kimi-k2.5"),
            )
            .expect_err("an unattested model must fail closed")
            .safe_detail_code,
            "KIMI_ACP_SESSION_MODEL_UNATTESTED"
        );
    }

    #[test]
    fn resume_request_binds_workspace_and_opaque_session_identity() {
        let request =
            session_resume_request(Path::new(r"D:\workspace"), "kimi-session-opaque-001", 9);
        assert_eq!(request["method"], "session/resume");
        assert_eq!(request["id"], 9);
        assert_eq!(request["params"]["sessionId"], "kimi-session-opaque-001");
        assert_eq!(request["params"]["cwd"], r"D:\workspace");
    }

    #[test]
    fn resumed_session_never_claims_dispatch_outcome() {
        let raw = br#"{"jsonrpc":"2.0","id":2,"result":{"models":{"currentModelId":"kimi-k2.5"}}}"#;
        assert!(matches!(
            classify_session_resume_response(raw, Some("kimi-k2.5"))
                .expect("valid native resume response"),
            ReconciliationFinding::OutcomeUnknown { evidence_ref }
                if evidence_ref.starts_with(KIMI_NATIVE_RECOVERY_OUTCOME_UNATTESTED)
        ));
        assert_eq!(
            classify_session_resume_response(raw, Some("other-model"))
                .expect_err("recovery must preserve the exact model route")
                .safe_detail_code,
            "KIMI_ACP_SESSION_MODEL_MISMATCH"
        );

        let rejected =
            br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Session not found"}}"#;
        assert!(matches!(
            classify_session_resume_response(rejected, Some("kimi-k2.5"))
                .expect("a rejection is reconciliation evidence"),
            ReconciliationFinding::OutcomeUnknown { evidence_ref }
                if evidence_ref.starts_with("kimi-reconcile:session-resume-rejected")
        ));
    }

    #[test]
    fn permission_option_selection_requires_an_explicit_compatible_option() {
        let params = json!({
            "options": [
                { "optionId": "allow", "kind": "allow_once" },
                { "optionId": "reject", "kind": "reject_once" }
            ]
        });
        assert_eq!(
            select_permission_option(&params, &["allow_once"]).expect("allow option")["outcome"]["optionId"],
            "allow"
        );
        assert_eq!(
            select_permission_option(&params, &["unsupported"])
                .expect_err("missing option")
                .safe_detail_code,
            "KIMI_ACP_PERMISSION_OPTION_UNAVAILABLE"
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
        let session = KimiAcpDriver::new(config)
            .probe_session()
            .await
            .expect("Kimi ACP session probe");
        let disposition = match &session.session {
            KimiSessionProbeDisposition::Created { .. } => "created",
            KimiSessionProbeDisposition::AuthenticationRequired { .. } => "authentication_required",
            KimiSessionProbeDisposition::Rejected { .. } => "rejected",
        };
        println!(
            "{{\"candidate\":\"kimi-cli\",\"protocol\":\"agent-client-protocol\",\"prompt_sent\":false,\"model_call\":false,\"initialize\":\"passed\",\"session_disposition\":\"{disposition}\"}}"
        );
        assert!(matches!(
            session.session,
            KimiSessionProbeDisposition::Created { .. }
                | KimiSessionProbeDisposition::AuthenticationRequired { .. }
        ));
    }

    #[tokio::test]
    #[ignore = "requires an explicitly authorized local Kimi user profile"]
    async fn live_kimi_default_profile_probe_records_safe_boundary_without_prompt() {
        let executable = PathBuf::from(
            std::env::var_os("EGOPULSE_KIMI_NATIVE_EXE")
                .expect("EGOPULSE_KIMI_NATIVE_EXE must point to Kimi executable"),
        );
        let config = KimiAcpConfig::new(executable, std::env::current_dir().expect("cwd"));
        let result = match probe_initialize(&config, &ProbeHarnessRequest::default()).await {
            Ok(result) => result,
            Err(error) => {
                assert_eq!(error.certainty, DriverErrorCertainty::ProvenNotSent);
                println!(
                    "{{\"candidate\":\"kimi-cli\",\"profile\":\"default-user\",\"protocol\":\"agent-client-protocol\",\"prompt_sent\":false,\"model_call\":false,\"initialize\":\"failed\",\"safe_detail_code\":\"{}\"}}",
                    error.safe_detail_code
                );
                return;
            }
        };
        assert_eq!(result.readiness, HarnessReadiness::Degraded as i32);
        let session = match KimiAcpDriver::new(config).probe_session().await {
            Ok(session) => session,
            Err(error) => {
                assert_eq!(error.certainty, DriverErrorCertainty::ProvenNotSent);
                println!(
                    "{{\"candidate\":\"kimi-cli\",\"profile\":\"default-user\",\"protocol\":\"agent-client-protocol\",\"prompt_sent\":false,\"model_call\":false,\"initialize\":\"passed\",\"session_disposition\":\"probe_failed\",\"safe_detail_code\":\"{}\"}}",
                    error.safe_detail_code
                );
                return;
            }
        };
        let disposition = match &session.session {
            KimiSessionProbeDisposition::Created { .. } => "created",
            KimiSessionProbeDisposition::AuthenticationRequired { .. } => "authentication_required",
            KimiSessionProbeDisposition::Rejected { .. } => "rejected",
        };
        println!(
            "{{\"candidate\":\"kimi-cli\",\"profile\":\"default-user\",\"protocol\":\"agent-client-protocol\",\"prompt_sent\":false,\"model_call\":false,\"initialize\":\"passed\",\"session_disposition\":\"{disposition}\"}}"
        );
    }

    #[tokio::test]
    async fn unstarted_execution_surface_is_fail_closed_and_proven_not_sent() {
        let mut driver = KimiAcpDriver::new(KimiAcpConfig::new(
            r"C:\kimi.exe",
            std::env::current_dir().expect("cwd"),
        ));
        let envelope = DispatchEnvelope::default();
        let material = ResolvedDispatchMaterial {
            canonical_input_bundle: Vec::new(),
            prompt: "not sent".to_owned(),
            workspace_root: std::env::current_dir().expect("cwd"),
            model: None,
        };
        let dispatch_error = driver
            .send_dispatch(&envelope, &material)
            .await
            .expect_err("dispatch must remain unsupported");
        assert_eq!(
            (dispatch_error.code, dispatch_error.certainty),
            (
                HarnessErrorCode::CapabilityMismatch,
                DriverErrorCertainty::ProvenNotSent
            )
        );
        assert_eq!(
            driver
                .next_event(&envelope)
                .await
                .expect_err("events require an active dispatch")
                .safe_detail_code,
            "KIMI_ACP_ACTIVE_DISPATCH_NOT_FOUND"
        );
        assert_eq!(
            driver
                .decide_approval(&ApprovalDecisionEnvelope::default())
                .await
                .expect_err("approvals require a pending native request")
                .safe_detail_code,
            "KIMI_ACP_APPROVAL_ROUTING_NOT_FOUND"
        );
        assert_eq!(
            driver
                .cancel(&CancelExecutionEnvelope::default())
                .await
                .expect_err("cancellation requires an active native session")
                .safe_detail_code,
            "KIMI_ACP_SESSION_NOT_RUNNING"
        );
        let context = ReconciliationContext {
            envelope,
            delivery_receipt: None,
            material,
        };
        assert!(matches!(
            driver.reconcile(&context).await.expect("reconciliation hold"),
            ReconciliationFinding::OutcomeUnknown { evidence_ref }
                if evidence_ref == KIMI_NATIVE_RECOVERY_NO_SESSION_REF
        ));
    }
}
