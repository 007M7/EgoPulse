use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind,
    ApprovalRequestLifecycleKind, ApprovalRequestObservation, CancelExecutionEnvelope,
    ContentMutationOperation, DispatchEnvelope, HarnessAckObservation,
    HarnessContentSignalObservation, HarnessErrorCode, HarnessReadiness, LifecycleKind,
    LifecycleObservation, NativeProtocolFingerprint, ObservationCriticality, ProbeHarnessRequest,
    ProbeHarnessResult, SideEffectCertainty, UsageObservation, harness_observation,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent,
    LegacyExecutionStartRawClassification, LegacyExecutionStartRawContext, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
    TerminalOutputCandidate, assistant_text_content_candidate, assistant_text_mutation_candidate,
};
use egopulse_process_supervision::{SupervisedProcess, SupervisedProcessSpec};
use prost_types::Timestamp;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use uuid::Uuid;

use crate::review::{
    CodexReadOnlyReviewOutcome, CodexReadOnlyReviewRequest, CodexReadOnlyTurnOutcome,
    CodexReadOnlyTurnRequest, ReviewExchange, ReviewMessageAction,
};

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

/// Maps only the Codex App Server channel explicitly documented as a
/// user-visible assistant message. Hidden reasoning, tool, terminal and raw
/// result categories return no candidate and never cross this boundary.
#[must_use]
pub fn codex_user_visible_content_candidate(
    item_type: &str,
    message_id: &str,
    text: &[u8],
) -> Option<egopulse_domain_contracts::v01::egopulse::harness::v1::UserVisibleContentCandidate> {
    (item_type == "agentMessage")
        .then(|| assistant_text_content_candidate(message_id, text.to_vec()))
        .flatten()
}

const CODEX_CONTENT_CANDIDATE_BYTES: usize = 65_536;
const CODEX_PENDING_NATIVE_POLL_TIMEOUT: Duration = Duration::from_millis(5);

#[must_use]
pub fn codex_user_visible_content_mutations(
    item_type: &str,
    message_id: &str,
    previous_revision: u64,
    previous_raw_cumulative: &[u8],
    operation: ContentMutationOperation,
    text: &str,
) -> Option<Vec<egopulse_domain_contracts::v01::egopulse::harness::v1::UserVisibleContentCandidate>>
{
    if item_type != "agentMessage" || message_id.trim().is_empty() {
        return None;
    }
    if operation == ContentMutationOperation::Finalize {
        return assistant_text_mutation_candidate(
            message_id,
            previous_revision.checked_add(1)?,
            previous_revision,
            operation,
            Vec::new(),
            previous_raw_cumulative,
        )
        .map(|candidate| vec![candidate]);
    }
    let chunks = utf8_candidate_chunks(text, CODEX_CONTENT_CANDIDATE_BYTES);
    let mut cumulative = previous_raw_cumulative.to_vec();
    let mut revision = previous_revision;
    let mut candidates = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let chunk_operation = if index == 0 {
            operation
        } else {
            ContentMutationOperation::Append
        };
        let candidate = assistant_text_mutation_candidate(
            message_id,
            revision.checked_add(1)?,
            revision,
            chunk_operation,
            chunk.as_bytes().to_vec(),
            &cumulative,
        )?;
        match chunk_operation {
            ContentMutationOperation::Append => cumulative.extend_from_slice(chunk.as_bytes()),
            ContentMutationOperation::Replace => cumulative = chunk.as_bytes().to_vec(),
            ContentMutationOperation::Finalize | ContentMutationOperation::Unspecified => {
                return None;
            }
        }
        revision = revision.checked_add(1)?;
        candidates.push(candidate);
    }
    Some(candidates)
}

fn utf8_candidate_chunks(value: &str, max_bytes: usize) -> Vec<&str> {
    if value.is_empty() {
        return vec![value];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = value.len().min(start + max_bytes);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(&value[start..end]);
        start = end;
    }
    chunks
}

#[derive(Clone, Debug)]
pub struct CodexAppServerConfig {
    pub executable: PathBuf,
    pub environment_overrides: Vec<(String, String)>,
    pub request_timeout: Duration,
}

impl CodexAppServerConfig {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            environment_overrides: Vec::new(),
            request_timeout: Duration::from_secs(30),
        }
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

fn apply_environment_overrides(
    spec: SupervisedProcessSpec,
    overrides: &[(String, String)],
) -> SupervisedProcessSpec {
    let mut spec = spec
        .with_minimal_user_environment()
        .with_desktop_shell_path()
        .with_inherited_environment("CODEX_HOME");
    for (name, value) in overrides {
        spec = spec.with_environment_override(name.clone(), value.clone());
    }
    spec
}

fn isolated_app_server_arguments(additional_overrides: &[String]) -> Vec<String> {
    let mut overrides = [
        "features.apps=false",
        "features.plugins=false",
        "features.remote_plugin=false",
        "features.multi_agent=false",
        "features.hooks=false",
        "features.shell_tool=false",
        "features.unified_exec=false",
        "features.shell_snapshot=false",
        "features.goals=false",
        "features.memories=false",
        "web_search=\"disabled\"",
        "tools.view_image=false",
        // These empty tables make the discovery process parse independently
        // of malformed inherited entries. They do not clear lower layers;
        // every discovered entry is disabled explicitly in the second pass.
        "mcp_servers={}",
        "plugins={}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    overrides.extend_from_slice(additional_overrides);
    overrides
        .into_iter()
        .flat_map(|value| ["-c".to_owned(), value])
        .chain(["app-server".to_owned(), "--stdio".to_owned()])
        .collect()
}

fn isolated_base_config_matches(config: &Value) -> bool {
    let feature_disabled = |name: &str| {
        config
            .pointer(&format!("/features/{name}"))
            .and_then(Value::as_bool)
            == Some(false)
    };
    [
        "apps",
        "plugins",
        "remote_plugin",
        "multi_agent",
        "hooks",
        "shell_tool",
        "unified_exec",
        "shell_snapshot",
        "goals",
        "memories",
    ]
    .into_iter()
    .all(feature_disabled)
        && config.get("web_search").and_then(Value::as_str) == Some("disabled")
}

#[derive(Default)]
struct ExternalToolInventory {
    mcp_servers: Vec<String>,
    plugins: Vec<String>,
    plugin_mcp_servers: Vec<(String, String)>,
}

impl ExternalToolInventory {
    fn from_config(config: &Value) -> Result<Self, ()> {
        let mut inventory = Self::default();
        if let Some(servers) = config.get("mcp_servers") {
            let servers = servers.as_object().ok_or(())?;
            for name in servers.keys() {
                validate_config_key(name)?;
                inventory.mcp_servers.push(name.clone());
            }
        }
        if let Some(plugins) = config.get("plugins") {
            let plugins = plugins.as_object().ok_or(())?;
            for (plugin_name, plugin) in plugins {
                validate_config_key(plugin_name)?;
                inventory.plugins.push(plugin_name.clone());
                if let Some(servers) = plugin.get("mcp_servers") {
                    let servers = servers.as_object().ok_or(())?;
                    for server_name in servers.keys() {
                        validate_config_key(server_name)?;
                        inventory
                            .plugin_mcp_servers
                            .push((plugin_name.clone(), server_name.clone()));
                    }
                }
            }
        }
        Ok(inventory)
    }

    fn disabling_overrides(&self) -> Vec<String> {
        self.mcp_servers
            .iter()
            .map(|name| format!("mcp_servers.{name}.enabled=false"))
            .chain(
                self.plugins
                    .iter()
                    .map(|name| format!("plugins.{name}.enabled=false")),
            )
            .chain(self.plugin_mcp_servers.iter().map(|(plugin, server)| {
                format!("plugins.{plugin}.mcp_servers.{server}.enabled=false")
            }))
            .collect()
    }

    fn all_disabled(&self, config: &Value) -> bool {
        self.mcp_servers.iter().all(|name| {
            config
                .pointer(&format!("/mcp_servers/{name}/enabled"))
                .and_then(Value::as_bool)
                == Some(false)
        }) && self.plugins.iter().all(|name| {
            config
                .pointer(&format!("/plugins/{name}/enabled"))
                .and_then(Value::as_bool)
                == Some(false)
        }) && self.plugin_mcp_servers.iter().all(|(plugin, server)| {
            config
                .pointer(&format!("/plugins/{plugin}/mcp_servers/{server}/enabled"))
                .and_then(Value::as_bool)
                == Some(false)
        })
    }
}

fn validate_config_key(value: &str) -> Result<(), ()> {
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'@')))
    .then_some(())
    .ok_or(())
}

fn tool_isolation_unverified() -> DriverError {
    driver_error(
        DriverErrorCertainty::ProvenNotSent,
        HarnessErrorCode::DependencyUnavailable,
        "CODEX_READ_ONLY_TOOL_ISOLATION_UNVERIFIED",
        &[],
    )
}

fn is_tool_activity(value: &Value) -> bool {
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if method.starts_with("mcpServer/")
        || method.starts_with("item/tool/")
        || method.starts_with("tool/")
    {
        return true;
    }
    let item_type = value
        .pointer("/params/item/type")
        .or_else(|| value.pointer("/params/type"))
        .and_then(Value::as_str);
    matches!(
        item_type,
        Some(
            "commandExecution"
                | "fileChange"
                | "mcpToolCall"
                | "dynamicToolCall"
                | "collabToolCall"
                | "webSearch"
                | "imageView"
        )
    )
}

struct ActiveDispatch {
    dispatch_id: String,
    thread_id: String,
    turn_id: Option<String>,
    turn_request_id: u64,
    workspace_root: PathBuf,
}

struct PendingApproval {
    request_id: Value,
    method: String,
    params: Value,
    observation: ApprovalRequestObservation,
}

#[derive(Default)]
struct AgentMessageAssembly {
    message_id: String,
    revision: u64,
    raw_cumulative: Vec<u8>,
}

struct CodexSession {
    process: SupervisedProcess,
    next_request_id: u64,
    pending_messages: VecDeque<(Value, Vec<u8>)>,
    partial_frame: Vec<u8>,
}

pub struct CodexAppServerDriver {
    config: CodexAppServerConfig,
    session: Option<CodexSession>,
    active: Option<ActiveDispatch>,
    completed_dispatch_id: Option<String>,
    pending_agent_message: Option<AgentMessageAssembly>,
    terminal_output_candidate: Option<TerminalOutputCandidate>,
    pending_approvals: HashMap<String, PendingApproval>,
    responded_approvals: HashMap<String, ApprovalRequestObservation>,
    queued_events: VecDeque<DriverEvent>,
    pending_control_requests: HashMap<u64, &'static str>,
    deferred_terminal_event: Option<DriverEvent>,
    last_protocol_diagnostic: Option<String>,
    approval_items: crate::approval_display::ApprovalItemCache,
}

impl CodexAppServerDriver {
    #[must_use]
    pub fn new(config: CodexAppServerConfig) -> Self {
        Self {
            config,
            session: None,
            active: None,
            completed_dispatch_id: None,
            pending_agent_message: None,
            terminal_output_candidate: None,
            pending_approvals: HashMap::new(),
            responded_approvals: HashMap::new(),
            queued_events: VecDeque::new(),
            pending_control_requests: HashMap::new(),
            deferred_terminal_event: None,
            last_protocol_diagnostic: None,
            approval_items: crate::approval_display::ApprovalItemCache::default(),
        }
    }

    #[must_use]
    pub fn last_protocol_diagnostic(&self) -> Option<&str> {
        self.last_protocol_diagnostic.as_deref()
    }

    /// Runs one provider-native review on a fresh app-server session and a new
    /// read-only thread. The caller owns durable Start/hold semantics; this
    /// method only reports the real native exchange and never retries it.
    pub async fn run_read_only_review(
        &mut self,
        request: CodexReadOnlyReviewRequest,
    ) -> Result<CodexReadOnlyReviewOutcome, DriverError> {
        if request.execution_id.trim().is_empty()
            || request.model.trim().is_empty()
            || request.prompt.trim().is_empty()
            || !request.working_directory.is_absolute()
            || !request.working_directory.is_dir()
            || request.timeout.is_zero()
            || request.output_limit_bytes == 0
        {
            return Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "CODEX_REVIEW_REQUEST_INVALID",
                &[],
            ));
        }
        if self.session.is_some() || self.active.is_some() {
            return Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "CODEX_REVIEW_DRIVER_NOT_FRESH",
                &[],
            ));
        }
        let result = match timeout(
            request.timeout,
            self.run_read_only_review_inner(&request, false, None),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::DependencyUnavailable,
                "CODEX_REVIEW_TIMEOUT",
                request.execution_id.as_bytes(),
            )),
        };
        self.shutdown_review_session().await;
        result
    }

    /// Runs one cognition-only model turn on a fresh app-server process. The
    /// process receives temporary highest-precedence tool-disable overrides,
    /// and their effective values are verified before the thread is created.
    /// No native delivery is retried by this method.
    pub async fn run_read_only_turn(
        &mut self,
        request: CodexReadOnlyTurnRequest,
    ) -> Result<CodexReadOnlyTurnOutcome, DriverError> {
        let output_schema = request.output_schema.clone();
        let review_request: CodexReadOnlyReviewRequest = request.into();
        if review_request.execution_id.trim().is_empty()
            || review_request.model.trim().is_empty()
            || review_request.prompt.trim().is_empty()
            || !review_request.working_directory.is_absolute()
            || !review_request.working_directory.is_dir()
            || review_request.timeout.is_zero()
            || review_request.output_limit_bytes == 0
        {
            return Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "CODEX_READ_ONLY_TURN_REQUEST_INVALID",
                &[],
            ));
        }
        if self.session.is_some() || self.active.is_some() {
            return Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "CODEX_READ_ONLY_TURN_DRIVER_NOT_FRESH",
                &[],
            ));
        }
        let result = match timeout(
            review_request.timeout,
            self.run_read_only_review_inner(&review_request, true, Some(&output_schema)),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::DependencyUnavailable,
                "CODEX_READ_ONLY_TURN_TIMEOUT",
                review_request.execution_id.as_bytes(),
            )),
        };
        self.shutdown_review_session().await;
        result
    }

    async fn run_read_only_review_inner(
        &mut self,
        request: &CodexReadOnlyReviewRequest,
        isolate_external_tools: bool,
        output_schema: Option<&Value>,
    ) -> Result<CodexReadOnlyReviewOutcome, DriverError> {
        let started = std::time::Instant::now();
        if isolate_external_tools {
            self.ensure_session(&request.working_directory, true, &[])
                .await?;
            let discovery_config = self.read_effective_config().await?;
            if !isolated_base_config_matches(&discovery_config) {
                return Err(tool_isolation_unverified());
            }
            let inventory = ExternalToolInventory::from_config(&discovery_config)
                .map_err(|_| tool_isolation_unverified())?;
            let disabling_overrides = inventory.disabling_overrides();
            self.shutdown_review_session().await;
            self.ensure_session(&request.working_directory, true, &disabling_overrides)
                .await?;
            let isolated_config = self.read_effective_config().await?;
            if !isolated_base_config_matches(&isolated_config)
                || !inventory.all_disabled(&isolated_config)
            {
                return Err(tool_isolation_unverified());
            }
        } else {
            self.ensure_session(&request.working_directory, false, &[])
                .await?;
        }
        let session = self.session.as_mut().expect("review session initialized");

        let thread_request_id = session.next_id();
        let mut thread_params = json!({
            "cwd": request.working_directory,
            "approvalPolicy": "never",
            "sandbox": "read-only",
            "experimentalRawEvents": false,
            "model": request.model,
        });
        if isolate_external_tools {
            thread_params["dynamicTools"] = json!([]);
            thread_params["ephemeral"] = json!(true);
        }
        session
            .write_value(&json!({
                "id": thread_request_id,
                "method": "thread/start",
                "params": thread_params
            }))
            .await?;
        let (thread_response, thread_raw) = session
            .read_response(
                thread_request_id,
                remaining_review_time(started, request.timeout)?,
            )
            .await?;
        if !review_thread_configuration_matches(&thread_response, &request.model) {
            return Err(driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::ProtocolMismatch,
                "CODEX_REVIEW_THREAD_POLICY_MISMATCH",
                &thread_raw,
            ));
        }
        let thread_id = thread_response
            .pointer("/result/thread/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_REVIEW_THREAD_RESPONSE_INVALID",
                    &thread_raw,
                )
            })?;

        let turn_request_id = session.next_id();
        let mut turn_params = json!({
            "threadId": thread_id,
            "input": [{"type": "text", "text": request.prompt}],
            "cwd": request.working_directory,
            "approvalPolicy": "never",
            "sandboxPolicy": {"type": "readOnly", "networkAccess": false},
            "model": request.model,
        });
        if let Some(output_schema) = output_schema {
            turn_params["outputSchema"] = output_schema.clone();
        }
        session
            .write_value(&json!({
                "id": turn_request_id,
                "method": "turn/start",
                "params": turn_params
            }))
            .await?;
        let (turn_response, turn_raw) = session
            .read_response(
                turn_request_id,
                remaining_review_time(started, request.timeout)?,
            )
            .await?;
        let turn_id = turn_response
            .pointer("/result/turn/id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_REVIEW_TURN_RESPONSE_INVALID",
                    &turn_raw,
                )
            })?;

        let mut exchange = ReviewExchange::new(thread_id, turn_id);
        let terminal_status = loop {
            let session = self.session.as_mut().expect("review session initialized");
            let (value, raw) = session
                .read_next_value(remaining_review_time(started, request.timeout)?)
                .await?;
            if value.get("id").is_some() {
                return Err(driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_REVIEW_UNEXPECTED_RESPONSE",
                    &raw,
                ));
            }
            if isolate_external_tools && is_tool_activity(&value) {
                return Err(driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    "CODEX_READ_ONLY_TURN_TOOL_ACTIVITY",
                    &raw,
                ));
            }
            let action = exchange
                .accept_notification(&value, request.output_limit_bytes)
                .map_err(|detail| {
                    driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::ProtocolMismatch,
                        detail,
                        &raw,
                    )
                })?;
            if let ReviewMessageAction::Terminal(status) = action {
                break status;
            }
        };
        exchange
            .finish(
                request.execution_id.clone(),
                request.model.clone(),
                terminal_status,
                started.elapsed(),
            )
            .map_err(|detail| {
                driver_error(
                    DriverErrorCertainty::DeliveryUnknown,
                    HarnessErrorCode::ProtocolMismatch,
                    detail,
                    request.execution_id.as_bytes(),
                )
            })
    }

    async fn shutdown_review_session(&mut self) {
        if let Some(mut session) = self.session.take() {
            let _ = session.process.terminate().await;
            let _ = session.process.wait().await;
        }
    }

    fn queue_agent_message_candidates(
        &mut self,
        message_id: &str,
        candidates: Vec<
            egopulse_domain_contracts::v01::egopulse::harness::v1::UserVisibleContentCandidate,
        >,
        raw: &[u8],
    ) -> Option<DriverEvent> {
        let mut events = candidates.into_iter().map(|candidate| {
            let revision = candidate
                .payload
                .as_ref()
                .and_then(|payload| match payload {
                    egopulse_domain_contracts::v01::egopulse::harness::v1::user_visible_content_candidate::Payload::AssistantText(text) => {
                        Some(text.revision)
                    }
                    _ => None,
                })
                .expect("Codex agent-message mapper only queues assistant text");
            DriverEvent {
                native_key: format!("item/agentMessage/content:{message_id}:{revision}"),
                native_event_id: Some(message_id.to_owned()),
                native_sequence: Some(revision),
                native_observed_at: now(),
                criticality: ObservationCriticality::Informational,
                payload: harness_observation::Payload::ContentSignal(
                    HarnessContentSignalObservation {
                        content_event_id: String::new(),
                        delivered_receipt_id: String::new(),
                        delivered_receipt_digest_sha256: String::new(),
                        dispatch_route_binding_sha256: String::new(),
                        context_consumption_proof: None,
                        candidate: Some(candidate),
                    },
                ),
                raw_event: raw.to_vec(),
            }
        });
        let first = events.next();
        self.queued_events.extend(events);
        first
    }

    async fn ensure_session(
        &mut self,
        working_directory: &PathBuf,
        isolate_external_tools: bool,
        additional_overrides: &[String],
    ) -> Result<(), DriverError> {
        if self.session.is_some() {
            return Ok(());
        }
        let mut spec = apply_environment_overrides(
            SupervisedProcessSpec::new(&self.config.executable, working_directory),
            &self.config.environment_overrides,
        );
        spec.arguments = if isolate_external_tools {
            isolated_app_server_arguments(additional_overrides)
        } else {
            vec!["app-server".to_owned(), "--stdio".to_owned()]
        };
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
            partial_frame: Vec::new(),
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

    async fn read_effective_config(&mut self) -> Result<Value, DriverError> {
        let session = self.session.as_mut().expect("session initialized");
        let request_id = session.next_id();
        session
            .write_value(&json!({
                "id": request_id,
                "method": "config/read",
                "params": { "includeLayers": false }
            }))
            .await?;
        let (response, _) = session
            .read_response(request_id, self.config.request_timeout)
            .await?;
        response
            .pointer("/result/config")
            .cloned()
            .ok_or_else(tool_isolation_unverified)
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
        if active
            .turn_id
            .as_ref()
            .is_some_and(|observed| observed != &turn_id)
        {
            return Err(driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::ProtocolMismatch,
                "CODEX_TURN_START_IDENTITY_CONFLICT",
                &raw,
            ));
        }
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
        let approval_request_id = Uuid::now_v7().to_string();
        let action_digest_sha256 = sha256(params.to_string().as_bytes());
        let context = self
            .active
            .as_ref()
            .map(|active| crate::approval_display::ApprovalContext {
                dispatch_id: &active.dispatch_id,
                thread_id: &active.thread_id,
                turn_id: active.turn_id.as_deref(),
                workspace_root: &active.workspace_root,
            });
        let credentials = self
            .config
            .environment_overrides
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();
        let summary = self.approval_items.summarize(
            context.as_ref(),
            &params,
            &approval_request_id,
            &action_digest_sha256,
            kind,
            &credentials,
        );
        let observation = ApprovalRequestObservation {
            approval_request_id,
            kind: kind as i32,
            action_digest_sha256,
            requested_scope_ref: "adapter-edge://codex/approval/scope".to_owned(),
            display_summary_ref: summary.summary_ref.clone(),
            display_summary: Some(summary),
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
            "turn/started" => {
                // Native notifications may precede the turn/start response.
                // Capture only the exact active thread and reject a later
                // response that tries to replace this observed turn identity.
                if let (Some(active), Some(thread), Some(turn)) = (
                    self.active.as_mut(),
                    params.get("threadId").and_then(Value::as_str),
                    params.pointer("/turn/id").and_then(Value::as_str),
                ) {
                    if thread != active.thread_id {
                        return Ok(None);
                    }
                    if turn.is_empty()
                        || active.turn_id.as_deref().is_some_and(|known| known != turn)
                    {
                        return Err(driver_error(
                            DriverErrorCertainty::DeliveryUnknown,
                            HarnessErrorCode::ProtocolMismatch,
                            "CODEX_TURN_START_IDENTITY_CONFLICT",
                            &raw,
                        ));
                    }
                    active.turn_id = Some(turn.to_owned());
                }
                lifecycle_event(
                    method,
                    LifecycleKind::ExecutionStarted,
                    None,
                    "inProgress",
                    None,
                    raw,
                )
            }
            "thread/status/changed" => {
                let status = params
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                match status {
                    "systemError" => lifecycle_event(
                        method,
                        LifecycleKind::ExecutionFailed,
                        None,
                        status,
                        None,
                        raw,
                    ),
                    "active" | "idle" | "notLoaded" => DriverEvent {
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
                                } else if status == "active" {
                                    // Thread activity is a session-level hint;
                                    // turn/started owns ExecutionStarted.
                                    "CODEX_THREAD_ACTIVE"
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
            "item/started" => {
                if let Some(active) = self.active.as_ref() {
                    self.approval_items.record_started(
                        &crate::approval_display::ApprovalContext {
                            dispatch_id: &active.dispatch_id,
                            thread_id: &active.thread_id,
                            turn_id: active.turn_id.as_deref(),
                            workspace_root: &active.workspace_root,
                        },
                        &params,
                    );
                }
                lifecycle_event(
                    method,
                    LifecycleKind::ItemStarted,
                    params.pointer("/item/id").and_then(Value::as_str),
                    "started",
                    None,
                    raw,
                )
            }
            "item/completed" => {
                if params.pointer("/item/type").and_then(Value::as_str) == Some("agentMessage") {
                    let final_text = params
                        .pointer("/item/text")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let native_completion_ref = params
                        .pointer("/item/id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| self.active.as_ref().and_then(|value| value.turn_id.clone()))
                        .unwrap_or_else(|| format!("codex-dispatch:{}", envelope.dispatch_id));
                    let mut assembly =
                        self.pending_agent_message
                            .take()
                            .unwrap_or_else(|| AgentMessageAssembly {
                                message_id: native_completion_ref.clone(),
                                ..AgentMessageAssembly::default()
                            });
                    if assembly.message_id != native_completion_ref {
                        return Err(dependency_error("CODEX_AGENT_MESSAGE_ID_DRIFT"));
                    }
                    let text = final_text.unwrap_or_else(|| {
                        String::from_utf8_lossy(&assembly.raw_cumulative).into_owned()
                    });
                    let mut queued_candidates = Vec::new();
                    if text.as_bytes() != assembly.raw_cumulative {
                        let operation = if assembly.revision == 0 {
                            ContentMutationOperation::Append
                        } else {
                            ContentMutationOperation::Replace
                        };
                        let candidates = codex_user_visible_content_mutations(
                            "agentMessage",
                            &assembly.message_id,
                            assembly.revision,
                            &assembly.raw_cumulative,
                            operation,
                            &text,
                        )
                        .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_REPLACE_INVALID"))?;
                        assembly.revision = assembly
                            .revision
                            .checked_add(candidates.len() as u64)
                            .ok_or_else(|| {
                                dependency_error("CODEX_AGENT_MESSAGE_REVISION_OVERFLOW")
                            })?;
                        assembly.raw_cumulative = text.as_bytes().to_vec();
                        queued_candidates.extend(candidates);
                    }
                    let finalize = codex_user_visible_content_mutations(
                        "agentMessage",
                        &assembly.message_id,
                        assembly.revision,
                        &assembly.raw_cumulative,
                        ContentMutationOperation::Finalize,
                        "",
                    )
                    .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_FINALIZE_INVALID"))?;
                    queued_candidates.extend(finalize);
                    if let Some(first) = self.queue_agent_message_candidates(
                        &native_completion_ref,
                        queued_candidates,
                        &raw,
                    ) {
                        self.queued_events.push_front(first);
                    }
                    self.terminal_output_candidate = Some(TerminalOutputCandidate {
                        dispatch_id: envelope.dispatch_id.clone(),
                        native_completion_ref,
                        media_type: "text/plain; charset=utf-8".to_owned(),
                        content: text.into_bytes(),
                    });
                }
                lifecycle_event(
                    method,
                    LifecycleKind::ItemCompleted,
                    params.pointer("/item/id").and_then(Value::as_str),
                    "completed",
                    None,
                    raw,
                )
            }
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
                if kind == LifecycleKind::ExecutionCompleted
                    && self.terminal_output_candidate.is_none()
                {
                    let native_completion_ref = params
                        .pointer("/turn/id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| self.active.as_ref().and_then(|value| value.turn_id.clone()))
                        .unwrap_or_else(|| format!("codex-dispatch:{}", envelope.dispatch_id));
                    self.terminal_output_candidate = Some(TerminalOutputCandidate {
                        dispatch_id: envelope.dispatch_id.clone(),
                        native_completion_ref,
                        media_type: "text/plain; charset=utf-8".to_owned(),
                        content: Vec::new(),
                    });
                }
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
                let reached = native_rate_limit_reached(&params);
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
            "item/agentMessage/delta" => {
                let delta = params
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_DELTA_INVALID"))?;
                let message_id = params
                    .get("itemId")
                    .or_else(|| params.pointer("/item/id"))
                    .or_else(|| params.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| {
                        self.pending_agent_message
                            .as_ref()
                            .map(|assembly| assembly.message_id.clone())
                    })
                    .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_ID_MISSING"))?;
                let assembly =
                    self.pending_agent_message
                        .get_or_insert_with(|| AgentMessageAssembly {
                            message_id: message_id.clone(),
                            ..AgentMessageAssembly::default()
                        });
                if assembly.message_id != message_id {
                    return Err(dependency_error("CODEX_AGENT_MESSAGE_ID_DRIFT"));
                }
                let candidates = codex_user_visible_content_mutations(
                    "agentMessage",
                    &message_id,
                    assembly.revision,
                    &assembly.raw_cumulative,
                    ContentMutationOperation::Append,
                    delta,
                )
                .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_DELTA_INVALID"))?;
                assembly.revision = assembly
                    .revision
                    .checked_add(candidates.len() as u64)
                    .ok_or_else(|| dependency_error("CODEX_AGENT_MESSAGE_REVISION_OVERFLOW"))?;
                assembly.raw_cumulative.extend_from_slice(delta.as_bytes());
                return Ok(self.queue_agent_message_candidates(&message_id, candidates, &raw));
            }
            "turn/diff/updated"
            | "turn/plan/updated"
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
            "warning" => DriverEvent {
                native_key: native_key(method, &raw),
                native_event_id: None,
                native_sequence: None,
                native_observed_at: now(),
                criticality: ObservationCriticality::Informational,
                payload: harness_observation::Payload::Diagnostic(
                    egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                        safe_diagnostic_code: "CODEX_WARNING".to_owned(),
                        error_fingerprint: Some(sha256(&raw)),
                        recovery_required: false,
                    },
                ),
                raw_event: raw,
            },
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
            if self.has_pending_native_exchange() || !self.queued_events.is_empty() {
                if self.deferred_terminal_event.is_some() {
                    return Err(driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::ProtocolMismatch,
                        "CODEX_TERMINAL_EVENT_CONFLICT",
                        &event.raw_event,
                    ));
                }
                self.deferred_terminal_event = Some(event);
                return Ok(None);
            }
            self.release_terminal_dispatch(envelope);
        }
        Ok(Some(event))
    }

    fn has_pending_native_exchange(&self) -> bool {
        !self.pending_approvals.is_empty()
            || !self.responded_approvals.is_empty()
            || !self.pending_control_requests.is_empty()
    }

    fn dispatch_lifecycle_is_released(&self) -> bool {
        self.active.is_none()
            && self.pending_agent_message.is_none()
            && self.terminal_output_candidate.is_none()
            && self.pending_approvals.is_empty()
            && self.responded_approvals.is_empty()
            && self.queued_events.is_empty()
            && self.pending_control_requests.is_empty()
            && self.deferred_terminal_event.is_none()
    }

    fn ensure_dispatch_ready(&self) -> Result<(), DriverError> {
        if self.dispatch_lifecycle_is_released() {
            Ok(())
        } else {
            Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::DeliveryRejected,
                "CODEX_DISPATCH_BUSY",
                &[],
            ))
        }
    }

    fn release_terminal_dispatch(&mut self, envelope: &DispatchEnvelope) {
        // A partial assistant assembly is only meaningful while its native
        // turn is active. A terminal notification settles that lifecycle; it
        // must not retain this driver after an interruption or a malformed
        // completion that lacked item/completed.
        self.pending_agent_message = None;
        self.completed_dispatch_id = Some(envelope.dispatch_id.clone());
        self.active = None;
    }

    fn take_ready_deferred_terminal(&mut self, envelope: &DispatchEnvelope) -> Option<DriverEvent> {
        if self.has_pending_native_exchange() || !self.queued_events.is_empty() {
            return None;
        }
        let event = self.deferred_terminal_event.take()?;
        self.release_terminal_dispatch(envelope);
        Some(event)
    }

    async fn send_approval_response(
        &mut self,
        envelope: &ApprovalDecisionEnvelope,
    ) -> Result<Vec<u8>, DriverError> {
        let pending = self
            .pending_approvals
            .get(&envelope.native_routing_ref)
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
        if decision == ApprovalDecision::AllowOnce
            && (pending.observation.approval_request_id != envelope.approval_request_id
                || pending.observation.action_digest_sha256 != envelope.action_digest_sha256
                || self.active.as_ref().is_none_or(|active| {
                    active.dispatch_id != envelope.dispatch_id
                        || pending.params.get("threadId").and_then(Value::as_str)
                            != Some(active.thread_id.as_str())
                        || pending.params.get("turnId").and_then(Value::as_str)
                            != active.turn_id.as_deref()
                })
                || !egopulse_domain_contracts::approval_display::valid_reviewable_approval_summary(
                    pending.observation.display_summary.as_ref(),
                    &pending.observation.display_summary_ref,
                    &pending.observation.action_digest_sha256,
                    pending.observation.kind,
                ))
        {
            return Err(driver_error(
                DriverErrorCertainty::ProvenNotSent,
                HarnessErrorCode::InvalidArgument,
                "CODEX_APPROVAL_DISPLAY_NOT_REVIEWABLE",
                &[],
            ));
        }
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
        // Retain proven-unsent validation failures. Once writing starts, a
        // partial response can be unknown, so the durable adapter receipt owns
        // reconciliation and this pending request must not be sent again.
        let pending = self
            .pending_approvals
            .remove(&envelope.native_routing_ref)
            .ok_or_else(|| dependency_error("CODEX_APPROVAL_ROUTING_NOT_FOUND"))?;
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

impl egopulse_harness_adapter::ReadOnlyTurnDriver for CodexAppServerDriver {
    fn run_bounded_read_only_turn<'a>(
        &'a mut self,
        request: egopulse_harness_adapter::ReadOnlyTurnRequest,
    ) -> NativeHarnessFuture<'a, Result<egopulse_harness_adapter::ReadOnlyTurnOutcome, DriverError>>
    {
        Box::pin(async move {
            use egopulse_harness_adapter::{ReadOnlyTurnOutcome, ReadOnlyTurnStatus};
            let outcome = self
                .run_read_only_turn(CodexReadOnlyTurnRequest {
                    execution_id: request.execution_id,
                    working_directory: request.working_directory,
                    model: request.model,
                    prompt: request.prompt,
                    output_schema: request.output_schema,
                    timeout: request.timeout,
                    output_limit_bytes: request.output_limit_bytes,
                })
                .await?;
            let terminal_status = match outcome.terminal_status {
                crate::CodexReadOnlyReviewTerminalStatus::Completed => {
                    ReadOnlyTurnStatus::Completed
                }
                crate::CodexReadOnlyReviewTerminalStatus::Interrupted => {
                    ReadOnlyTurnStatus::Interrupted
                }
                crate::CodexReadOnlyReviewTerminalStatus::Failed => ReadOnlyTurnStatus::Failed,
            };
            Ok(ReadOnlyTurnOutcome {
                model: outcome.receipt.model,
                terminal_status,
                assistant_output: outcome.assistant_output,
            })
        })
    }
}

impl NativeHarnessDriver for CodexAppServerDriver {
    fn is_dispatch_ready(&self) -> bool {
        self.dispatch_lifecycle_is_released()
    }

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
            // This guard must precede session initialization and thread/turn
            // writes: a shared driver has exactly one native active lifecycle.
            self.ensure_dispatch_ready()?;
            self.ensure_session(&material.workspace_root, false, &[])
                .await?;
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
                workspace_root: material.workspace_root.clone(),
            });
            self.approval_items = crate::approval_display::ApprovalItemCache::default();
            self.completed_dispatch_id = None;
            self.pending_agent_message = None;
            self.terminal_output_candidate = None;
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
            if let Some(event) = self.take_ready_deferred_terminal(envelope) {
                return Ok(Some(event));
            }
            if self
                .active
                .as_ref()
                .is_none_or(|active| active.dispatch_id != envelope.dispatch_id)
            {
                return Err(dependency_error("CODEX_ACTIVE_DISPATCH_NOT_FOUND"));
            }
            let bounded_poll =
                self.has_pending_native_exchange() || self.deferred_terminal_event.is_some();
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| dependency_error("CODEX_SESSION_NOT_RUNNING"))?;
            // An unresolved native request remains an approval/control handoff,
            // but it cannot stop the single framed reader: Codex may withdraw
            // it or finish the turn without a local approval decision. Keep
            // this poll short so the runner releases its mutex for the separate
            // approval/cancellation delivery worker.
            let next = if bounded_poll {
                session
                    .poll_next_value(CODEX_PENDING_NATIVE_POLL_TIMEOUT)
                    .await?
            } else {
                Some(session.read_next_value(self.config.request_timeout).await?)
            };
            let Some((value, raw)) = next else {
                return Ok(None);
            };
            self.map_value(envelope, value, raw)
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
            Ok(self
                .terminal_output_candidate
                .take()
                .filter(|candidate| candidate.dispatch_id == envelope.dispatch_id))
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
            self.ensure_session(&context.material.workspace_root, false, &[])
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
            let turns = response
                .pointer("/result/thread/turns")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let Some(expected_turn_id) = expected_turn_id else {
                return Ok(ReconciliationFinding::OutcomeUnknown { evidence_ref });
            };
            let Some(turn) = turns.iter().find(|turn| {
                turn.get("id").and_then(Value::as_str) == Some(expected_turn_id.as_str())
            }) else {
                return Ok(ReconciliationFinding::OutcomeUnknown { evidence_ref });
            };
            if let Some(turn_status) = turn
                .get("status")
                .and_then(Value::as_str)
                .or_else(|| turn.pointer("/status/type").and_then(Value::as_str))
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

    fn classify_legacy_execution_start(
        &self,
        context: &LegacyExecutionStartRawContext,
    ) -> LegacyExecutionStartRawClassification {
        classify_codex_legacy_execution_start(context)
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
        self.poll_value(deadline)
            .await?
            .ok_or_else(|| dependency_error("CODEX_RESPONSE_TIMEOUT"))
    }

    async fn poll_value(
        &mut self,
        deadline: Duration,
    ) -> Result<Option<(Value, Vec<u8>)>, DriverError> {
        let raw =
            match poll_jsonl_frame(&mut self.process.stdout, &mut self.partial_frame, deadline)
                .await
                .map_err(|error| {
                    driver_error(
                        DriverErrorCertainty::DeliveryUnknown,
                        HarnessErrorCode::DependencyUnavailable,
                        "CODEX_STDOUT_READ_FAILED",
                        format!("{error:?}").as_bytes(),
                    )
                })? {
                JsonlFramePoll::Idle => return Ok(None),
                JsonlFramePoll::Eof => return Err(dependency_error("CODEX_APP_SERVER_EOF")),
                JsonlFramePoll::Frame(raw) => raw,
            };
        let value = serde_json::from_slice(&raw).map_err(|error| {
            driver_error(
                DriverErrorCertainty::DeliveryUnknown,
                HarnessErrorCode::ProtocolMismatch,
                "CODEX_JSONL_INVALID",
                format!("{error:?}").as_bytes(),
            )
        })?;
        Ok(Some((value, raw)))
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

    async fn poll_next_value(
        &mut self,
        deadline: Duration,
    ) -> Result<Option<(Value, Vec<u8>)>, DriverError> {
        if let Some(message) = self.pending_messages.pop_front() {
            return Ok(Some(message));
        }
        self.poll_value(deadline).await
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

#[derive(Debug, Eq, PartialEq)]
enum JsonlFramePoll {
    Idle,
    Eof,
    Frame(Vec<u8>),
}

async fn poll_jsonl_frame<R>(
    reader: &mut R,
    partial_frame: &mut Vec<u8>,
    deadline: Duration,
) -> std::io::Result<JsonlFramePoll>
where
    R: AsyncBufRead + Unpin,
{
    if partial_frame.last() == Some(&b'\n') {
        return Ok(JsonlFramePoll::Frame(std::mem::take(partial_frame)));
    }
    match timeout(deadline, reader.read_until(b'\n', partial_frame)).await {
        Err(_) => Ok(JsonlFramePoll::Idle),
        Ok(Err(error)) => Err(error),
        Ok(Ok(0)) if partial_frame.is_empty() => Ok(JsonlFramePoll::Eof),
        Ok(Ok(_)) => Ok(JsonlFramePoll::Frame(std::mem::take(partial_frame))),
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
    let mut spec = apply_environment_overrides(
        SupervisedProcessSpec::new(&config.executable, working_directory),
        &config.environment_overrides,
    );
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
    let mut spec = apply_environment_overrides(
        SupervisedProcessSpec::new(&config.executable, working_directory),
        &config.environment_overrides,
    );
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
        criticality: if kind == LifecycleKind::ExecutionFailed && will_retry == Some(true) {
            // Retried sampling failures keep the same native turn and dispatch alive.
            ObservationCriticality::Control
        } else if matches!(
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

fn remaining_review_time(
    started: std::time::Instant,
    total: Duration,
) -> Result<Duration, DriverError> {
    total.checked_sub(started.elapsed()).ok_or_else(|| {
        driver_error(
            DriverErrorCertainty::DeliveryUnknown,
            HarnessErrorCode::DependencyUnavailable,
            "CODEX_REVIEW_TIMEOUT",
            &[],
        )
    })
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

fn classify_codex_legacy_execution_start(
    context: &LegacyExecutionStartRawContext,
) -> LegacyExecutionStartRawClassification {
    let Ok(prior) = serde_json::from_slice::<Value>(&context.prior_raw_event) else {
        return LegacyExecutionStartRawClassification::Conflict;
    };
    let Ok(pending) = serde_json::from_slice::<Value>(&context.pending_raw_event) else {
        return LegacyExecutionStartRawClassification::Conflict;
    };
    let prior_is_legacy_active = prior.get("method").and_then(Value::as_str)
        == Some("thread/status/changed")
        && prior.pointer("/params/status/type").and_then(Value::as_str) == Some("active");
    let pending_is_turn_start =
        pending.get("method").and_then(Value::as_str) == Some("turn/started");
    let pending_turn_id = pending.pointer("/params/turn/id").and_then(Value::as_str);
    let session_refs_match = [
        prior.pointer("/params/threadId").and_then(Value::as_str),
        pending.pointer("/params/threadId").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .all(|session_ref| session_ref == context.native_session_ref);
    if prior_is_legacy_active
        && pending_is_turn_start
        && pending_turn_id == Some(context.native_execution_ref.as_str())
        && session_refs_match
    {
        let durable_terminal_handoff = context
            .terminal_raw_event
            .as_ref()
            .zip(context.terminal_native_completion_ref.as_ref())
            .is_some_and(|(raw, item_ref)| {
                let Ok(terminal) = serde_json::from_slice::<Value>(raw) else {
                    return false;
                };
                !item_ref.trim().is_empty()
                    && terminal.get("method").and_then(Value::as_str) == Some("turn/completed")
                    && terminal.pointer("/params/turn/id").and_then(Value::as_str)
                        == Some(context.native_execution_ref.as_str())
                    && terminal
                        .pointer("/params/threadId")
                        .and_then(Value::as_str)
                        .is_none_or(|session_ref| session_ref == context.native_session_ref)
            });
        LegacyExecutionStartRawClassification::ExactDuplicate {
            durable_terminal_handoff,
        }
    } else {
        LegacyExecutionStartRawClassification::Conflict
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn review_thread_configuration_matches(response: &Value, model: &str) -> bool {
    response.pointer("/result/model").and_then(Value::as_str) == Some(model)
        && response
            .pointer("/result/approvalPolicy")
            .and_then(Value::as_str)
            == Some("never")
        && response
            .pointer("/result/sandbox/type")
            .and_then(Value::as_str)
            == Some("readOnly")
        && response
            .pointer("/result/sandbox/networkAccess")
            .and_then(Value::as_bool)
            == Some(false)
}

pub(crate) fn native_rate_limit_reached(params: &Value) -> bool {
    params
        .pointer("/rateLimits/rateLimitReachedType")
        .is_some_and(|value| !value.is_null())
        || params
            .pointer("/rateLimits/spendControlReached")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || params
            .pointer("/rateLimits/primary/usedPercent")
            .and_then(Value::as_u64)
            .is_some_and(|used| used >= 100)
}

#[cfg(test)]
mod tests {
    #[test]
    fn thread_activity_and_turn_started_emit_only_one_execution_start() {
        use super::*;
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope::default();
        let values = [
            json!({"method":"thread/status/changed","params":{"status":{"type":"active"}}}),
            json!({"method":"turn/started","params":{"turn":{"id":"turn-one"}}}),
        ];
        let events: Vec<_> = values
            .into_iter()
            .map(|value| {
                let raw = serde_json::to_vec(&value).unwrap();
                driver.map_value(&envelope, value, raw).unwrap().unwrap()
            })
            .collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(
                    &event.payload,
                    harness_observation::Payload::Lifecycle(lifecycle)
                        if lifecycle.kind == LifecycleKind::ExecutionStarted as i32
                ))
                .count(),
            1
        );
        assert_eq!(events[0].criticality, ObservationCriticality::Informational);
    }
    use super::*;

    #[test]
    fn cognition_isolation_disables_every_discovered_native_extension() {
        let discovery = json!({
            "features": {
                "apps": false, "plugins": false, "remote_plugin": false,
                "multi_agent": false, "hooks": false, "shell_tool": false,
                "unified_exec": false, "shell_snapshot": false,
                "goals": false, "memories": false
            },
            "web_search": "disabled",
            "mcp_servers": {"node_repl": {"enabled": true}},
            "plugins": {
                "@computer-use": {
                    "enabled": true,
                    "mcp_servers": {"desktop": {"enabled": true}}
                }
            }
        });
        let inventory = ExternalToolInventory::from_config(&discovery).expect("valid native names");
        let overrides = inventory.disabling_overrides();
        assert!(overrides.contains(&"mcp_servers.node_repl.enabled=false".to_owned()));
        assert!(overrides.contains(&"plugins.@computer-use.enabled=false".to_owned()));
        assert!(
            overrides
                .contains(&"plugins.@computer-use.mcp_servers.desktop.enabled=false".to_owned())
        );

        let mut isolated = discovery;
        isolated["mcp_servers"]["node_repl"]["enabled"] = json!(false);
        isolated["plugins"]["@computer-use"]["enabled"] = json!(false);
        isolated["plugins"]["@computer-use"]["mcp_servers"]["desktop"]["enabled"] = json!(false);
        assert!(isolated_base_config_matches(&isolated));
        assert!(inventory.all_disabled(&isolated));
    }

    #[test]
    fn cognition_isolation_accepts_at_sign_but_rejects_unsafe_dotted_key_characters() {
        assert_eq!(validate_config_key("@computer-use"), Ok(()));
        for value in ["", "plugin.name", "plugin/name", "plugin name"] {
            assert_eq!(validate_config_key(value), Err(()));
        }
    }

    #[test]
    fn cognition_isolation_rejects_any_tool_activity() {
        for value in [
            json!({"method":"item/started","params":{"item":{"type":"mcpToolCall"}}}),
            json!({"method":"item/started","params":{"item":{"type":"commandExecution"}}}),
            json!({"method":"mcpServer/startupStatus/updated","params":{}}),
        ] {
            assert!(is_tool_activity(&value));
        }
    }

    #[test]
    fn review_checks_effective_read_only_policy_and_exact_model_before_turn() {
        let expected = json!({"result": {"model": "configured-model", "approvalPolicy": "never",
            "sandbox": {"type": "readOnly", "networkAccess": false}}});
        assert!(review_thread_configuration_matches(
            &expected,
            "configured-model"
        ));
        for (path, replacement) in [
            ("/result/model", json!("fallback-model")),
            ("/result/approvalPolicy", json!("on-request")),
            ("/result/sandbox/type", json!("workspaceWrite")),
            ("/result/sandbox/networkAccess", json!(true)),
            ("/result/sandbox/networkAccess", json!(null)),
        ] {
            let mut changed = expected.clone();
            *changed.pointer_mut(path).expect("fixture field") = replacement;
            assert!(!review_thread_configuration_matches(
                &changed,
                "configured-model"
            ));
        }
    }

    #[test]
    fn legacy_execution_start_requires_exact_old_shape_and_ack_turn() {
        let exact = LegacyExecutionStartRawContext {
            prior_raw_event: serde_json::to_vec(&json!({
                "method":"thread/status/changed",
                "params":{"threadId":"thread-one","status":{"type":"active"}}
            }))
            .expect("legacy active raw"),
            pending_raw_event: serde_json::to_vec(&json!({
                "method":"turn/started",
                "params":{"threadId":"thread-one","turn":{"id":"turn-one"}}
            }))
            .expect("turn start raw"),
            native_session_ref: "thread-one".to_owned(),
            native_execution_ref: "turn-one".to_owned(),
            terminal_raw_event: None,
            terminal_native_completion_ref: None,
        };
        assert_eq!(
            classify_codex_legacy_execution_start(&exact),
            LegacyExecutionStartRawClassification::ExactDuplicate {
                durable_terminal_handoff: false
            }
        );

        let mut item_output_terminal = exact.clone();
        item_output_terminal.terminal_raw_event = Some(
            serde_json::to_vec(&json!({
                "method":"turn/completed",
                "params": {
                    "threadId":"thread-one",
                    "turn":{"id":"turn-one","status":"completed"}
                }
            }))
            .expect("terminal turn raw"),
        );
        item_output_terminal.terminal_native_completion_ref = Some("item-output".to_owned());
        assert_eq!(
            classify_codex_legacy_execution_start(&item_output_terminal),
            LegacyExecutionStartRawClassification::ExactDuplicate {
                durable_terminal_handoff: true
            },
            "item identity differs from turn identity while the terminal source stays bound to the exact ACK turn"
        );

        let mut wrong_turn = exact.clone();
        wrong_turn.native_execution_ref = "turn-two".to_owned();
        assert_eq!(
            classify_codex_legacy_execution_start(&wrong_turn),
            LegacyExecutionStartRawClassification::Conflict
        );
        let mut wrong_prior = exact;
        wrong_prior.prior_raw_event = serde_json::to_vec(&json!({
            "method":"turn/started",
            "params":{"turn":{"id":"turn-one"}}
        }))
        .expect("non-legacy prior raw");
        assert_eq!(
            classify_codex_legacy_execution_start(&wrong_prior),
            LegacyExecutionStartRawClassification::Conflict
        );
    }
    #[test]
    fn process_environment_is_isolated_and_credentials_are_explicit() {
        let spec = apply_environment_overrides(
            SupervisedProcessSpec::new(r"C:\codex.exe", r"C:\workspace"),
            &[("OPENAI_API_KEY".to_owned(), "managed-secret".to_owned())],
        );

        assert!(spec.clear_environment);
        assert!(
            spec.inherited_environment
                .iter()
                .all(|name| !name.starts_with("EGOPULSE_") && !name.ends_with("_API_KEY"))
        );
        assert_eq!(
            spec.environment_overrides
                .iter()
                .filter(|(name, _)| name != "PATH")
                .cloned()
                .collect::<Vec<_>>(),
            vec![("OPENAI_API_KEY".to_owned(), "managed-secret".to_owned())]
        );
        assert!(
            spec.environment_overrides
                .iter()
                .all(|(name, _)| name == "PATH" || name == "OPENAI_API_KEY")
        );
    }
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        AssistantTextContentCandidate, user_visible_content_candidate,
    };

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

    #[tokio::test]
    async fn native_allow_once_rejects_unreviewable_details_without_consuming_pending_request() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let request = approval_request(71);
        let event = driver
            .map_server_request(
                "item/commandExecution/requestApproval",
                request.clone(),
                serde_json::to_vec(&request).expect("request bytes"),
            )
            .expect("map approval")
            .expect("approval event");
        let observation = approval_payload(event);
        let envelope = ApprovalDecisionEnvelope {
            approval_request_id: observation.approval_request_id,
            native_routing_ref: observation.native_routing_ref.clone(),
            action_digest_sha256: observation.action_digest_sha256,
            decision: ApprovalDecision::AllowOnce as i32,
            ..Default::default()
        };
        let error = driver
            .send_approval_response(&envelope)
            .await
            .expect_err("summary missing");
        assert_eq!(error.certainty, DriverErrorCertainty::ProvenNotSent);
        assert_eq!(
            error.safe_detail_code,
            "CODEX_APPROVAL_DISPLAY_NOT_REVIEWABLE"
        );
        assert!(
            driver
                .pending_approvals
                .contains_key(&observation.native_routing_ref)
        );
        assert!(driver.responded_approvals.is_empty());
    }

    #[test]
    fn approval_summary_can_join_started_items_before_the_turn_start_response() {
        let root = std::env::current_dir().expect("workspace");
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch:order".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread:order".to_owned(),
            turn_id: None,
            turn_request_id: 1,
            workspace_root: root.clone(),
        });
        for (method, params) in [
            (
                "turn/started",
                json!({"threadId":"thread:order", "turn":{"id":"turn:order"}}),
            ),
            (
                "item/started",
                json!({"threadId":"thread:order", "turnId":"turn:order", "item":{"id":"item:order", "type":"commandExecution", "command":"cargo test", "cwd":root}}),
            ),
        ] {
            let value = json!({"method":method, "params":params});
            driver
                .map_notification(
                    &envelope,
                    method,
                    value.clone(),
                    serde_json::to_vec(&value).expect("notification bytes"),
                )
                .expect("map notification");
        }
        let request = json!({"id":72, "params":{"threadId":"thread:order", "turnId":"turn:order", "itemId":"item:order", "command":"cargo test", "cwd":root}});
        let observation = approval_payload(
            driver
                .map_server_request(
                    "item/commandExecution/requestApproval",
                    request.clone(),
                    serde_json::to_vec(&request).expect("request bytes"),
                )
                .expect("request")
                .expect("approval"),
        );
        assert!(
            egopulse_domain_contracts::approval_display::valid_reviewable_approval_summary(
                observation.display_summary.as_ref(),
                &observation.display_summary_ref,
                &observation.action_digest_sha256,
                observation.kind,
            )
        );
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
    async fn completed_agent_message_becomes_one_governed_terminal_output_candidate() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-output".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-output".to_owned(),
            turn_id: Some("turn-output".to_owned()),
            turn_request_id: 1,
            workspace_root: std::env::current_dir().expect("test workspace"),
        });
        let item = json!({
            "method": "item/completed",
            "params": {
                "item": {
                    "id": "item-output",
                    "type": "agentMessage",
                    "text": "governed Codex answer"
                }
            }
        });
        driver
            .map_notification(
                &envelope,
                "item/completed",
                item.clone(),
                serde_json::to_vec(&item).expect("item bytes"),
            )
            .expect("map completed item")
            .expect("completed item observation");
        let terminal = json!({
            "method": "turn/completed",
            "params": { "turn": { "id": "turn-output", "status": "completed" } }
        });
        assert!(
            driver
                .map_notification(
                    &envelope,
                    "turn/completed",
                    terminal.clone(),
                    serde_json::to_vec(&terminal).expect("terminal bytes"),
                )
                .expect("defer terminal")
                .is_none(),
            "terminal must wait until queued content signals are emitted"
        );
        assert!(driver.deferred_terminal_event.is_some());

        let content = driver
            .next_event(&envelope)
            .await
            .expect("drain content signal")
            .expect("content signal");
        assert!(matches!(
            content.payload,
            harness_observation::Payload::ContentSignal(_)
        ));
        while !driver.queued_events.is_empty() {
            let content = driver
                .next_event(&envelope)
                .await
                .expect("drain remaining content")
                .expect("queued content observation");
            assert!(matches!(
                content.payload,
                harness_observation::Payload::ContentSignal(_)
            ));
            assert!(!driver.is_dispatch_ready());
        }
        let terminal = driver
            .next_event(&envelope)
            .await
            .expect("release deferred terminal")
            .expect("terminal observation");
        assert_eq!(terminal.criticality, ObservationCriticality::Terminal);

        let candidate = driver
            .take_terminal_output_candidate(&envelope)
            .await
            .expect("candidate extraction")
            .expect("candidate exists");
        assert_eq!(candidate.dispatch_id, envelope.dispatch_id);
        assert_eq!(candidate.native_completion_ref, "item-output");
        assert_eq!(candidate.content, b"governed Codex answer");
        assert!(
            driver
                .take_terminal_output_candidate(&envelope)
                .await
                .expect("candidate replay")
                .is_none()
        );
        assert!(driver.is_dispatch_ready());
    }

    #[tokio::test]
    async fn dispatch_readiness_blocks_overwrite_until_terminal_candidate_is_taken() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-busy".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-busy".to_owned(),
            turn_id: Some("turn-busy".to_owned()),
            turn_request_id: 1,
            workspace_root: std::env::current_dir().expect("test workspace"),
        });

        assert!(!driver.is_dispatch_ready());
        let busy = driver
            .ensure_dispatch_ready()
            .expect_err("active dispatch blocks send");
        assert_eq!(busy.certainty, DriverErrorCertainty::ProvenNotSent);
        assert_eq!(busy.code, HarnessErrorCode::DeliveryRejected);
        assert_eq!(busy.safe_detail_code, "CODEX_DISPATCH_BUSY");

        driver.active = None;
        driver.completed_dispatch_id = Some(envelope.dispatch_id.clone());
        driver.terminal_output_candidate = Some(TerminalOutputCandidate {
            dispatch_id: envelope.dispatch_id.clone(),
            native_completion_ref: "item-busy".to_owned(),
            media_type: "text/plain; charset=utf-8".to_owned(),
            content: b"pending collector evidence".to_vec(),
        });
        assert!(!driver.is_dispatch_ready());
        assert!(
            driver
                .take_terminal_output_candidate(&envelope)
                .await
                .expect("candidate extraction")
                .is_some()
        );
        assert!(driver.is_dispatch_ready());
    }

    #[test]
    fn agent_message_delta_and_complete_emit_append_replace_finalize_without_loss() {
        fn content(event: DriverEvent) -> AssistantTextContentCandidate {
            let harness_observation::Payload::ContentSignal(signal) = event.payload else {
                panic!("content signal")
            };
            let Some(user_visible_content_candidate::Payload::AssistantText(candidate)) =
                signal.candidate.and_then(|candidate| candidate.payload)
            else {
                panic!("assistant candidate")
            };
            candidate
        }

        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-stream".to_owned(),
            ..Default::default()
        };
        let delta = json!({
            "method": "item/agentMessage/delta",
            "params": { "itemId": "message-stream", "delta": "hello" }
        });
        let appended = content(
            driver
                .map_notification(
                    &envelope,
                    "item/agentMessage/delta",
                    delta.clone(),
                    serde_json::to_vec(&delta).expect("delta bytes"),
                )
                .expect("map delta")
                .expect("delta candidate"),
        );
        assert_eq!(appended.operation, ContentMutationOperation::Append as i32);
        assert_eq!(appended.revision, 1);
        assert_eq!(appended.text_utf8, b"hello");

        let completed = json!({
            "method": "item/completed",
            "params": { "item": {
                "id": "message-stream", "type": "agentMessage", "text": "hello world"
            }}
        });
        driver
            .map_notification(
                &envelope,
                "item/completed",
                completed.clone(),
                serde_json::to_vec(&completed).expect("complete bytes"),
            )
            .expect("map complete")
            .expect("lifecycle event");
        let replaced = content(driver.queued_events.pop_front().expect("replace candidate"));
        let finalized = content(
            driver
                .queued_events
                .pop_front()
                .expect("finalize candidate"),
        );
        assert_eq!(replaced.operation, ContentMutationOperation::Replace as i32);
        assert_eq!(replaced.revision, 2);
        assert_eq!(replaced.previous_revision, 1);
        assert_eq!(replaced.text_utf8, b"hello world");
        assert_eq!(
            finalized.operation,
            ContentMutationOperation::Finalize as i32
        );
        assert_eq!(finalized.revision, 3);
        assert_eq!(finalized.previous_revision, 2);
        assert!(finalized.text_utf8.is_empty());
        assert!(driver.queued_events.is_empty());
    }

    #[test]
    fn agent_message_large_utf8_delta_and_complete_use_the_real_mapper_without_loss() {
        fn content(event: DriverEvent) -> AssistantTextContentCandidate {
            let harness_observation::Payload::ContentSignal(signal) = event.payload else {
                panic!("content signal")
            };
            let Some(user_visible_content_candidate::Payload::AssistantText(candidate)) =
                signal.candidate.and_then(|candidate| candidate.payload)
            else {
                panic!("assistant candidate")
            };
            candidate
        }

        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-large-stream".to_owned(),
            ..Default::default()
        };
        let delta_text = format!("{}界{}", "a".repeat(65_535), "b".repeat(8_000));
        let delta = json!({
            "method": "item/agentMessage/delta",
            "params": { "itemId": "message-large-stream", "delta": delta_text }
        });
        let first = driver
            .map_notification(
                &envelope,
                "item/agentMessage/delta",
                delta.clone(),
                serde_json::to_vec(&delta).expect("delta bytes"),
            )
            .expect("map large delta")
            .expect("first large delta candidate");
        let mut delta_candidates = vec![content(first)];
        while let Some(event) = driver.queued_events.pop_front() {
            delta_candidates.push(content(event));
        }
        assert!(delta_candidates.len() > 1);
        let mut rebuilt_delta = Vec::new();
        for (index, candidate) in delta_candidates.iter().enumerate() {
            assert_eq!(candidate.operation, ContentMutationOperation::Append as i32);
            assert_eq!(candidate.previous_revision, index as u64);
            assert_eq!(candidate.revision, index as u64 + 1);
            assert!(candidate.text_utf8.len() <= CODEX_CONTENT_CANDIDATE_BYTES);
            std::str::from_utf8(&candidate.text_utf8).expect("UTF-8 candidate boundary");
            rebuilt_delta.extend_from_slice(&candidate.text_utf8);
        }
        assert_eq!(rebuilt_delta, delta_text.as_bytes());

        let final_text = format!("{}界{}", "z".repeat(70_000), "q".repeat(7_000));
        let completed = json!({
            "method": "item/completed",
            "params": { "item": {
                "id": "message-large-stream", "type": "agentMessage", "text": final_text
            }}
        });
        driver
            .map_notification(
                &envelope,
                "item/completed",
                completed.clone(),
                serde_json::to_vec(&completed).expect("complete bytes"),
            )
            .expect("map large completion")
            .expect("completion lifecycle");
        let mut completion_candidates = Vec::new();
        while let Some(event) = driver.queued_events.pop_front() {
            completion_candidates.push(content(event));
        }
        assert!(completion_candidates.len() > 2);
        assert_eq!(
            completion_candidates[0].operation,
            ContentMutationOperation::Replace as i32
        );
        assert_eq!(
            completion_candidates.last().expect("finalize").operation,
            ContentMutationOperation::Finalize as i32
        );
        let mut rebuilt_final = Vec::new();
        for candidate in completion_candidates
            .iter()
            .take(completion_candidates.len() - 1)
        {
            assert!(candidate.text_utf8.len() <= CODEX_CONTENT_CANDIDATE_BYTES);
            std::str::from_utf8(&candidate.text_utf8).expect("UTF-8 completion boundary");
            match ContentMutationOperation::try_from(candidate.operation).expect("operation") {
                ContentMutationOperation::Replace => rebuilt_final = candidate.text_utf8.clone(),
                ContentMutationOperation::Append => {
                    rebuilt_final.extend_from_slice(&candidate.text_utf8);
                }
                other => panic!("unexpected completion mutation {other:?}"),
            }
        }
        assert_eq!(rebuilt_final, final_text.as_bytes());
    }

    #[tokio::test]
    async fn bounded_jsonl_poll_preserves_a_partial_frame_and_returns_complete_frames_in_order() {
        let (mut writer, reader) = tokio::io::duplex(512);
        let mut reader = BufReader::new(reader);
        let mut partial = Vec::new();
        writer
            .write_all(br#"{"method":"serverRequest/res"#)
            .await
            .expect("write partial frame");

        assert_eq!(
            poll_jsonl_frame(&mut reader, &mut partial, Duration::from_millis(1))
                .await
                .expect("bounded partial read"),
            JsonlFramePoll::Idle
        );
        assert!(
            !partial.is_empty(),
            "partial frame must survive the idle poll"
        );

        writer
            .write_all(
                b"olved\",\"params\":{\"requestId\":9}}\n{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"status\":\"interrupted\"}}}\n",
            )
            .await
            .expect("finish framed sequence");
        let first = poll_jsonl_frame(&mut reader, &mut partial, Duration::from_secs(1))
            .await
            .expect("read resolution frame");
        let JsonlFramePoll::Frame(first) = first else {
            panic!("resolution frame")
        };
        assert_eq!(
            serde_json::from_slice::<Value>(&first)
                .expect("resolution json")
                .get("method")
                .and_then(Value::as_str),
            Some("serverRequest/resolved")
        );
        let second = poll_jsonl_frame(&mut reader, &mut partial, Duration::from_secs(1))
            .await
            .expect("read terminal frame");
        let JsonlFramePoll::Frame(second) = second else {
            panic!("terminal frame")
        };
        assert_eq!(
            serde_json::from_slice::<Value>(&second)
                .expect("terminal json")
                .get("method")
                .and_then(Value::as_str),
            Some("turn/completed")
        );
        assert!(partial.is_empty());
    }

    #[test]
    fn terminal_waits_for_pending_control_ack_and_approval_resolution() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-approval-liveness".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-approval-liveness".to_owned(),
            turn_id: Some("turn-approval-liveness".to_owned()),
            turn_request_id: 1,
            workspace_root: std::env::current_dir().expect("test workspace"),
        });
        driver.pending_agent_message = Some(AgentMessageAssembly {
            message_id: "message-interrupted".to_owned(),
            revision: 1,
            raw_cumulative: b"provisional partial output".to_vec(),
        });
        let request = approval_request(9);
        let raw = serde_json::to_vec(&request).expect("request bytes");
        driver
            .map_server_request("item/commandExecution/requestApproval", request, raw)
            .expect("map request")
            .expect("approval event");
        driver.pending_control_requests.insert(44, "turn-interrupt");

        let terminal = json!({
            "method": "turn/completed",
            "params": {
                "threadId": "thread-approval-liveness",
                "turn": {"id": "turn-approval-liveness", "status": "interrupted"}
            }
        });
        assert!(
            driver
                .map_value(
                    &envelope,
                    terminal.clone(),
                    serde_json::to_vec(&terminal).expect("terminal bytes"),
                )
                .expect("defer terminal")
                .is_none(),
            "terminal must wait until the native request lifecycle is drained"
        );
        assert!(driver.active.is_some());
        assert!(driver.deferred_terminal_event.is_some());

        let control_ack = json!({"id": 44, "result": {}});
        let diagnostic = driver
            .map_value(
                &envelope,
                control_ack.clone(),
                serde_json::to_vec(&control_ack).expect("control ACK bytes"),
            )
            .expect("map control ACK")
            .expect("control ACK diagnostic");
        assert!(matches!(
            diagnostic.payload,
            harness_observation::Payload::Diagnostic(ref value)
                if value.safe_diagnostic_code == "CODEX_CONTROL_REQUEST_ACKNOWLEDGED"
        ));
        assert!(driver.pending_control_requests.is_empty());
        assert_eq!(driver.pending_approvals.len(), 1);

        let resolved = json!({
            "method": "serverRequest/resolved",
            "params": {"requestId": 9}
        });
        let withdrawn = driver
            .map_value(
                &envelope,
                resolved.clone(),
                serde_json::to_vec(&resolved).expect("resolution bytes"),
            )
            .expect("map resolution")
            .expect("withdrawal event");
        assert!(matches!(
            withdrawn.payload,
            harness_observation::Payload::ApprovalRequest(ref value)
                if value.lifecycle == ApprovalRequestLifecycleKind::Withdrawn as i32
                    && value.request_revision == 2
        ));
        assert!(driver.pending_approvals.is_empty());
        assert!(driver.responded_approvals.is_empty());

        let terminal = driver
            .take_ready_deferred_terminal(&envelope)
            .expect("terminal after native requests drain");
        assert!(matches!(
            terminal.payload,
            harness_observation::Payload::Lifecycle(ref value)
                if value.kind == LifecycleKind::ExecutionInterrupted as i32
        ));
        assert!(driver.active.is_none());
        assert_eq!(
            driver.completed_dispatch_id.as_deref(),
            Some(envelope.dispatch_id.as_str())
        );
        assert!(driver.pending_agent_message.is_none());
        assert!(driver.is_dispatch_ready());
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

    #[test]
    fn codex_warning_is_audited_as_non_critical_diagnostic() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-warning".to_owned(),
            ..Default::default()
        };
        let notification = json!({
            "method": "warning",
            "params": { "message": "optional host unavailable" }
        });
        let raw = serde_json::to_vec(&notification).expect("notification bytes");
        let event = driver
            .map_notification(&envelope, "warning", notification, raw)
            .expect("map warning")
            .expect("warning event");
        assert_eq!(event.criticality, ObservationCriticality::Informational);
        match event.payload {
            harness_observation::Payload::Diagnostic(value) => {
                assert_eq!(value.safe_diagnostic_code, "CODEX_WARNING");
                assert!(!value.recovery_required);
                assert!(value.error_fingerprint.is_some());
            }
            _ => panic!("expected diagnostic payload"),
        }
    }
    #[tokio::test]
    async fn retryable_codex_error_keeps_the_dispatch_observation_stream_open() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-retryable-error".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-retryable-error".to_owned(),
            turn_id: Some("turn-retryable-error".to_owned()),
            turn_request_id: 1,
            workspace_root: std::env::current_dir().expect("test workspace"),
        });

        // Codex reports a transient sampling failure the same way it reports a
        // fatal one: with an `error` notification. `willRetry` is the only
        // signal that distinguishes a retried turn from an ended turn.
        let notification = json!({
            "method": "error",
            "params": { "willRetry": true, "message": "stream disconnected" }
        });
        let raw = serde_json::to_vec(&notification).expect("error bytes");
        let event = driver
            .map_notification(&envelope, "error", notification, raw)
            .expect("map retryable error")
            .expect("retryable error event");

        assert_eq!(event.criticality, ObservationCriticality::Control);
        match event.payload {
            harness_observation::Payload::Lifecycle(value) => {
                assert_eq!(value.kind, LifecycleKind::ExecutionFailed as i32);
                assert_eq!(value.native_will_retry, Some(true));
            }
            _ => panic!("expected lifecycle payload"),
        }
        // A retried failure does not end the native turn, so the dispatch must
        // remain open; otherwise every later turn event is silently dropped by
        // the completed-dispatch short circuit in next_event.
        assert!(driver.active.is_some());
        assert!(driver.completed_dispatch_id.is_none());

        let delta = json!({
            "method": "item/agentMessage/delta",
            "params": { "itemId": "msg-after-retry", "delta": "continued" }
        });
        let raw = serde_json::to_vec(&delta).expect("delta bytes");
        assert!(
            driver
                .map_notification(&envelope, "item/agentMessage/delta", delta, raw)
                .expect("map post-retry delta")
                .is_some(),
            "post-retry turn content must still be observed"
        );
        // The retry is only transient: the same dispatch must still close normally
        // when the turn really completes.
        let completed = json!({
            "method": "turn/completed",
            "params": { "turn": { "status": "completed" } }
        });
        let raw = serde_json::to_vec(&completed).expect("completion bytes");
        let terminal = driver
            .map_notification(&envelope, "turn/completed", completed, raw)
            .expect("map post-retry completion")
            .expect("terminal event after retry");
        assert_eq!(terminal.criticality, ObservationCriticality::Terminal);
        assert!(driver.active.is_none());
        assert_eq!(
            driver.completed_dispatch_id.as_deref(),
            Some(envelope.dispatch_id.as_str())
        );
        assert!(
            driver
                .next_event(&envelope)
                .await
                .expect("dispatch released after retry")
                .is_none(),
            "a retryable error must not make the dispatch unreleasable"
        );
    }

    #[tokio::test]
    async fn non_retryable_codex_error_still_closes_the_dispatch_stream() {
        let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new("codex"));
        let envelope = DispatchEnvelope {
            dispatch_id: "dispatch-fatal-error".to_owned(),
            ..Default::default()
        };
        driver.active = Some(ActiveDispatch {
            dispatch_id: envelope.dispatch_id.clone(),
            thread_id: "thread-fatal-error".to_owned(),
            turn_id: Some("turn-fatal-error".to_owned()),
            turn_request_id: 1,
            workspace_root: std::env::current_dir().expect("test workspace"),
        });
        let notification = json!({
            "method": "error",
            "params": { "willRetry": false, "message": "fatal" }
        });
        let raw = serde_json::to_vec(&notification).expect("error bytes");
        let event = driver
            .map_notification(&envelope, "error", notification, raw)
            .expect("map fatal error")
            .expect("fatal error event");
        assert_eq!(event.criticality, ObservationCriticality::Terminal);
        assert!(driver.active.is_none());
        assert_eq!(
            driver.completed_dispatch_id.as_deref(),
            Some("dispatch-fatal-error")
        );
    }
}
