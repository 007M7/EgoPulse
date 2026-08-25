#![forbid(unsafe_code)]

use std::{
    io::{self, stdout},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use egopulse_client_kernel::ClientKernel;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::ApprovalDecision,
    harness::v1::ApprovalRequestLifecycleKind,
    localapi::v1::{
        AwaitProjectionRequest, ClientSurface, DecideHarnessApprovalRequest,
        ExecuteTaskCommandRequest, GetProjectionStatusRequest, HarnessApprovalView,
        ListHarnessApprovalViewsRequest, ListTaskViewsRequest, LocalApiErrorCode,
        ProjectionAwaitToken, ProjectionHealth, SourceRevision, TaskView,
        await_projection_response,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, policy_decision_command,
    },
    task::v1::TaskStatus,
    task::v1::{CreateTaskCommand, TaskCommand, task_command, task_command_result},
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use prost::Message;
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "egopulse-tui", version, about = "EgoPulse terminal surface")]
struct Args {
    /// Use a specific local daemon instance.
    #[arg(long, default_value = "default")]
    instance: String,
    /// Print the foundation probe without entering raw terminal mode.
    #[arg(long)]
    foundation_check: bool,
    /// Fetch one snapshot and render it as plain text.
    #[arg(long)]
    once: bool,
    #[command(subcommand)]
    command: Option<TuiCommand>,
}

#[derive(Debug, Subcommand)]
enum TuiCommand {
    /// Submit the user-owned create_task branch through the same kernel as the dashboard.
    TaskCreate {
        #[arg(long)]
        work_type: String,
        #[arg(long)]
        input_snapshot_id: String,
        #[arg(long)]
        target_scope_ref: String,
        #[arg(long)]
        acceptance_contract_id: String,
        #[arg(long)]
        acceptance_contract_version: String,
        #[arg(long)]
        acceptance_contract_sha256: String,
        #[arg(long)]
        budget_profile_id: String,
        #[arg(long)]
        budget_profile_version: String,
        #[arg(long)]
        budget_profile_sha256: String,
        #[arg(long)]
        json: bool,
    },
    /// Submit the user-owned issue_harness_approval_decision branch.
    ApprovalDecide {
        approval_request_id: String,
        #[arg(long)]
        expected_action_digest_sha256: String,
        #[arg(long)]
        expected_request_observation_id: String,
        #[arg(long)]
        expected_request_observation_sequence: u64,
        #[arg(long)]
        expected_request_revision: u64,
        #[arg(long)]
        decision: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        confirmation_proof_ref: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Wait for a write result's projection await token.
    Await {
        #[arg(long)]
        token_json: String,
        #[arg(long, default_value_t = 5000)]
        timeout_milliseconds: u32,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Panel {
    Tasks,
    Approvals,
}

impl Panel {
    const ALL: [Self; 2] = [Self::Tasks, Self::Approvals];

    fn index(self) -> usize {
        match self {
            Self::Tasks => 0,
            Self::Approvals => 1,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Tasks => Self::Approvals,
            Self::Approvals => Self::Tasks,
        }
    }
}

struct AttachedClient {
    connection: LocalApiConnection,
    kernel: ClientKernel,
}

impl AttachedClient {
    async fn open(instance: &str) -> Result<Self, String> {
        let address = LocalIpcAddress::for_instance(instance).map_err(|error| error.to_string())?;
        let connection = LocalApiClient::platform_default()
            .connect(address)
            .await
            .map_err(|error| format!("daemon unavailable: {error}"))?;
        let mut kernel = ClientKernel::new(
            format!("egopulse-tui-{}", Uuid::now_v7()),
            ClientSurface::Tui,
        )
        .map_err(|error| format!("client kernel unavailable: {error}"))?;
        let request = kernel
            .open_session_request(Uuid::now_v7().to_string())
            .map_err(|error| format!("session request invalid: {error}"))?;
        let response = connection
            .session_service()
            .open_session(request)
            .await
            .map_err(|error| format!("open session failed: {error}"))?
            .into_inner();
        kernel
            .accept_open_session(response, SystemTime::now())
            .map_err(|error| format!("session rejected: {error}"))?;
        Ok(Self { connection, kernel })
    }

    fn metadata(
        &self,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata, String>
    {
        self.kernel
            .request_metadata(Uuid::now_v7().to_string(), None, SystemTime::now())
            .map_err(|error| error.to_string())
    }

    fn metadata_with_correlation(
        &self,
        correlation_id: String,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata, String>
    {
        self.kernel
            .request_metadata(
                Uuid::now_v7().to_string(),
                Some(correlation_id),
                SystemTime::now(),
            )
            .map_err(|error| error.to_string())
    }

    fn require_command(&self, rpc: &str, oneof: &str) -> Result<(), String> {
        let session = self
            .kernel
            .session()
            .ok_or_else(|| "session binding missing".to_owned())?;
        self.kernel
            .profiles()
            .authorize_command(rpc, oneof, &session.granted_permission_codes)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn snapshot(&self) -> Result<Snapshot, String> {
        let status = self
            .connection
            .read_model_service()
            .get_projection_status(GetProjectionStatusRequest {
                client: Some(self.metadata()?),
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = status.error {
            return Err(local_error_message(error));
        }
        let metadata = status
            .metadata
            .ok_or_else(|| "projection metadata missing".to_owned())?;

        let tasks = self
            .connection
            .read_model_service()
            .list_task_views(ListTaskViewsRequest {
                client: Some(self.metadata()?),
                status_filter: Vec::new(),
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = tasks.error {
            return Err(local_error_message(error));
        }

        let approvals = self
            .connection
            .read_model_service()
            .list_harness_approval_views(ListHarnessApprovalViewsRequest {
                client: Some(self.metadata()?),
                request_lifecycle_filter: Vec::new(),
                decision_state_filter: Vec::new(),
                task_ids: Vec::new(),
                actionable_only: false,
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = approvals.error {
            return Err(local_error_message(error));
        }

        Ok(Snapshot {
            health: ProjectionHealth::try_from(metadata.health)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned()),
            stale: metadata.stale,
            position: metadata
                .position
                .map(|value| format!("{}:{}", value.epoch, value.sequence))
                .unwrap_or_else(|| "unknown".to_owned()),
            tasks: tasks.views,
            approvals: approvals.views,
        })
    }
}

async fn run_command(instance: &str, command: TuiCommand) -> Result<(), String> {
    match command {
        TuiCommand::TaskCreate {
            work_type,
            input_snapshot_id,
            target_scope_ref,
            acceptance_contract_id,
            acceptance_contract_version,
            acceptance_contract_sha256,
            budget_profile_id,
            budget_profile_version,
            budget_profile_sha256,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/ExecuteTaskCommand",
                "create_task",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = TaskCommand {
                command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                    meta: Some(command_metadata(
                        &correlation_id,
                        "egopulse-tui/task-create",
                    )),
                    work_type,
                    input_snapshot_id,
                    target_scope_ref,
                    acceptance_contract_ref: Some(ContractReference {
                        contract_id: acceptance_contract_id,
                        version: acceptance_contract_version,
                        sha256: acceptance_contract_sha256,
                    }),
                    budget_profile_ref: Some(ContractReference {
                        contract_id: budget_profile_id,
                        version: budget_profile_version,
                        sha256: budget_profile_sha256,
                    }),
                })),
            };
            let digest = canonical_task_digest(&command);
            if let Some(task_command::Command::CreateTask(create)) = command.command.as_mut() {
                create
                    .meta
                    .as_mut()
                    .expect("TUI always supplies command metadata")
                    .request_digest_sha256 = digest;
            }
            let response = attached
                .connection
                .command_gateway_service()
                .execute_task_command(ExecuteTaskCommandRequest {
                    client: Some(attached.metadata_with_correlation(correlation_id.clone())?),
                    command: Some(command),
                })
                .await
                .map_err(|error| error.to_string())?
                .into_inner();
            if let Some(error) = response.gateway_error {
                return Err(local_error_message(error));
            }
            let result = response
                .authority_result
                .ok_or_else(|| "task authority result missing".to_owned())?;
            let task = match result.outcome {
                Some(task_command_result::Outcome::Task(task)) => task,
                Some(task_command_result::Outcome::Error(error)) => {
                    return Err(format!(
                        "task authority rejected: {}",
                        error.safe_detail_code
                    ));
                }
                None => return Err("task authority outcome missing".to_owned()),
            };
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "task.create",
                "data": {
                    "taskId": task.task_id,
                    "revision": task.revision,
                    "status": egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::try_from(task.status)
                        .map(|value| value.as_str_name())
                        .unwrap_or("TASK_STATUS_UNSPECIFIED"),
                    "replayed": result.replayed,
                    "awaitToken": await_token_json(response.await_token),
                },
                "correlationId": correlation_id,
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "TUI task created: {} revision={} status={} replayed={}",
                    payload["data"]["taskId"].as_str().unwrap_or(""),
                    payload["data"]["revision"].as_u64().unwrap_or_default(),
                    payload["data"]["status"].as_str().unwrap_or(""),
                    payload["data"]["replayed"].as_bool().unwrap_or(false),
                );
            }
            Ok(())
        }
        TuiCommand::ApprovalDecide {
            approval_request_id,
            expected_action_digest_sha256,
            expected_request_observation_id,
            expected_request_observation_sequence,
            expected_request_revision,
            decision,
            reason_code,
            confirmation_proof_ref,
            json,
        } => {
            let decision = parse_approval_decision(&decision)?;
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/DecideHarnessApproval",
                "issue_harness_approval_decision",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = PolicyDecisionCommand {
                command: Some(
                    policy_decision_command::Command::IssueHarnessApprovalDecision(
                        IssueHarnessApprovalDecisionCommand {
                            metadata: Some(command_metadata(
                                &correlation_id,
                                "egopulse-tui/approval-decide",
                            )),
                            approval_request_id,
                            expected_action_digest_sha256,
                            expected_request_observation_id,
                            expected_request_observation_sequence,
                            decision,
                            reason_code,
                            confirmation_proof_ref,
                            expected_request_revision,
                        },
                    ),
                ),
            };
            set_policy_digest(&mut command);
            let response = attached
                .connection
                .command_gateway_service()
                .decide_harness_approval(DecideHarnessApprovalRequest {
                    client: Some(attached.metadata_with_correlation(correlation_id.clone())?),
                    command: match command.command {
                        Some(policy_decision_command::Command::IssueHarnessApprovalDecision(
                            command,
                        )) => Some(command),
                        _ => None,
                    },
                })
                .await
                .map_err(|error| error.to_string())?
                .into_inner();
            if let Some(error) = response.gateway_error {
                return Err(local_error_message(error));
            }
            let result = response
                .sanitized_authority_result
                .ok_or_else(|| "sanitized approval result missing".to_owned())?;
            if result.error_code != 0 {
                return Err(format!(
                    "approval authority rejected: {}",
                    result.error_code
                ));
            }
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "approval.decide",
                "data": {
                    "committed": result.committed,
                    "replayed": result.replayed,
                    "authorityDecisionRef": result.authority_decision_ref,
                    "decision": ApprovalDecision::try_from(result.decision)
                        .map(|value| value.as_str_name())
                        .unwrap_or("APPROVAL_DECISION_UNSPECIFIED"),
                    "stateRevision": result.state_revision,
                    "awaitToken": await_token_json(response.await_token),
                },
                "correlationId": correlation_id,
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "TUI approval decided: ref={} committed={} revision={}",
                    payload["data"]["authorityDecisionRef"]
                        .as_str()
                        .unwrap_or(""),
                    payload["data"]["committed"].as_bool().unwrap_or(false),
                    payload["data"]["stateRevision"]
                        .as_u64()
                        .unwrap_or_default(),
                );
            }
            Ok(())
        }
        TuiCommand::Await {
            token_json,
            timeout_milliseconds,
            json,
        } => {
            let token = parse_await_token(&token_json)?;
            let attached = AttachedClient::open(instance).await?;
            let response = attached
                .connection
                .read_model_service()
                .await_projection(AwaitProjectionRequest {
                    client: Some(attached.metadata()?),
                    await_token: Some(token),
                    timeout_milliseconds: timeout_milliseconds.min(60_000),
                })
                .await
                .map_err(|error| error.to_string())?
                .into_inner();
            match response.outcome {
                Some(await_projection_response::Outcome::View(view)) => {
                    let task = view
                        .task
                        .ok_or_else(|| "awaited task is empty".to_owned())?;
                    let payload = json!({
                        "schemaVersion": "egopulse.tui-result/v0.1",
                        "ok": true,
                        "operation": "await",
                        "data": {"kind": "task", "taskId": task.task_id, "revision": task.revision, "status": egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::try_from(task.status).map(|value| value.as_str_name()).unwrap_or("TASK_STATUS_UNSPECIFIED")}
                    });
                    if json {
                        println!("{}", serde_json::to_string(&payload).unwrap());
                    } else {
                        println!(
                            "TUI awaited task: {} revision={} status={}",
                            payload["data"]["taskId"].as_str().unwrap_or(""),
                            payload["data"]["revision"].as_u64().unwrap_or_default(),
                            payload["data"]["status"].as_str().unwrap_or("")
                        );
                    }
                    Ok(())
                }
                Some(await_projection_response::Outcome::ApprovalView(view)) => {
                    let payload = json!({
                        "schemaVersion": "egopulse.tui-result/v0.1",
                        "ok": true,
                        "operation": "await",
                        "data": {"kind": "approval", "approvalRequestId": view.approval_request_id, "revision": view.request_revision, "lifecycle": view.request_lifecycle}
                    });
                    if json {
                        println!("{}", serde_json::to_string(&payload).unwrap());
                    } else {
                        println!(
                            "TUI awaited approval: {} revision={}",
                            payload["data"]["approvalRequestId"].as_str().unwrap_or(""),
                            payload["data"]["revision"].as_u64().unwrap_or_default()
                        );
                    }
                    Ok(())
                }
                Some(await_projection_response::Outcome::Error(error)) => {
                    Err(local_error_message(error))
                }
                None => Err("await outcome missing".to_owned()),
            }
        }
    }
}

fn canonical_task_digest(command: &TaskCommand) -> String {
    let mut canonical = command.clone();
    if let Some(task_command::Command::CreateTask(create)) = canonical.command.as_mut()
        && let Some(meta) = create.meta.as_mut()
    {
        meta.command_id.clear();
        meta.request_digest_sha256.clear();
        meta.issued_at = None;
        meta.correlation_id.clear();
        meta.causation_id = None;
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

fn command_metadata(correlation_id: &str, scope: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: Uuid::now_v7().to_string(),
        idempotency_key: Uuid::now_v7().to_string(),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now_timestamp()),
        correlation_id: correlation_id.to_owned(),
        causation_id: None,
    }
}

fn set_policy_digest(command: &mut PolicyDecisionCommand) {
    let mut canonical = command.clone();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        canonical.command.as_mut()
        && let Some(metadata) = issue.metadata.as_mut()
    {
        metadata.command_id.clear();
        metadata.request_digest_sha256.clear();
        metadata.issued_at = None;
        metadata.correlation_id.clear();
        metadata.causation_id = None;
    }
    let digest = hex::encode(Sha256::digest(canonical.encode_to_vec()));
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        command.command.as_mut()
    {
        issue
            .metadata
            .as_mut()
            .expect("TUI always supplies policy command metadata")
            .request_digest_sha256 = digest;
    }
}

fn parse_approval_decision(value: &str) -> Result<i32, String> {
    match value {
        "allow-once" => Ok(ApprovalDecision::AllowOnce as i32),
        "deny" => Ok(ApprovalDecision::Deny as i32),
        "cancel-attempt" => Ok(ApprovalDecision::CancelAttempt as i32),
        _ => Err("decision must be allow-once, deny, or cancel-attempt".to_owned()),
    }
}

fn parse_await_token(input: &str) -> Result<ProjectionAwaitToken, String> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| format!("token_json must be an awaitToken object: {error}"))?;
    let source = value
        .get("requiredSourceRevision")
        .ok_or_else(|| "awaitToken.requiredSourceRevision is required".to_owned())?;
    Ok(ProjectionAwaitToken {
        token: value
            .get("token")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "awaitToken.token is required".to_owned())?
            .to_owned(),
        required_source_revision: Some(SourceRevision {
            domain: i32::try_from(
                source
                    .get("domain")
                    .and_then(serde_json::Value::as_i64)
                    .ok_or_else(|| {
                        "awaitToken.requiredSourceRevision.domain is required".to_owned()
                    })?,
            )
            .map_err(|_| "awaitToken.requiredSourceRevision.domain is invalid".to_owned())?,
            aggregate_id: source
                .get("aggregateId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    "awaitToken.requiredSourceRevision.aggregateId is required".to_owned()
                })?
                .to_owned(),
            revision: source
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    "awaitToken.requiredSourceRevision.revision is required".to_owned()
                })?,
            last_event_id: source
                .get("lastEventId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    "awaitToken.requiredSourceRevision.lastEventId is required".to_owned()
                })?
                .to_owned(),
        }),
        expires_at: Some(prost_types::Timestamp {
            seconds: value
                .get("expiresAt")
                .and_then(|value| value.get("seconds"))
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(|| "awaitToken.expiresAt.seconds is required".to_owned())?,
            nanos: i32::try_from(
                value
                    .get("expiresAt")
                    .and_then(|value| value.get("nanos"))
                    .and_then(serde_json::Value::as_i64)
                    .ok_or_else(|| "awaitToken.expiresAt.nanos is required".to_owned())?,
            )
            .map_err(|_| "awaitToken.expiresAt.nanos is invalid".to_owned())?,
        }),
    })
}

fn await_token_json(token: Option<ProjectionAwaitToken>) -> serde_json::Value {
    let Some(token) = token else {
        return serde_json::Value::Null;
    };
    let source = token.required_source_revision.as_ref().map(|source| {
        json!({
            "domain": source.domain,
            "aggregateId": source.aggregate_id,
            "revision": source.revision,
            "lastEventId": source.last_event_id,
        })
    });
    let expires_at = token
        .expires_at
        .as_ref()
        .map(|timestamp| json!({ "seconds": timestamp.seconds, "nanos": timestamp.nanos }));
    json!({
        "token": token.token,
        "requiredSourceRevision": source,
        "expiresAt": expires_at,
    })
}

fn now_timestamp() -> prost_types::Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch");
    prost_types::Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    }
}

struct Snapshot {
    health: String,
    stale: bool,
    position: String,
    tasks: Vec<TaskView>,
    approvals: Vec<HarnessApprovalView>,
}

struct App {
    instance: String,
    client: Option<AttachedClient>,
    snapshot: Option<Snapshot>,
    panel: Panel,
    message: String,
    refresh_interval: Duration,
}

impl App {
    fn new(instance: String) -> Self {
        Self {
            instance,
            client: None,
            snapshot: None,
            panel: Panel::Tasks,
            message: "Connecting to local daemon…".to_owned(),
            refresh_interval: Duration::from_secs(2),
        }
    }

    async fn refresh(&mut self) {
        if self.client.is_none() {
            match AttachedClient::open(&self.instance).await {
                Ok(client) => self.client = Some(client),
                Err(error) => {
                    self.message = error;
                    return;
                }
            }
        }
        let result = self
            .client
            .as_ref()
            .expect("client is attached")
            .snapshot()
            .await;
        match result {
            Ok(snapshot) => {
                self.message = format!(
                    "Connected · {} tasks · {} approvals · press r to refresh, q to quit",
                    snapshot.tasks.len(),
                    snapshot.approvals.len()
                );
                self.snapshot = Some(snapshot);
            }
            Err(error) => {
                self.message = format!("Disconnected: {error} · press r to reconnect");
                self.client = None;
            }
        }
    }

    fn render(&self, frame: &mut Frame<'_>) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(2),
            ])
            .split(frame.area());
        let snapshot = self.snapshot.as_ref();
        let title = snapshot.map_or_else(
            || "EgoPulse · TUI · disconnected".to_owned(),
            |value| {
                format!(
                    "EgoPulse · TUI · {} · {} · position {}",
                    value.health,
                    if value.stale { "stale" } else { "fresh" },
                    value.position
                )
            },
        );
        frame.render_widget(
            Paragraph::new(title)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Local control plane"),
                )
                .style(Style::default().fg(Color::Cyan)),
            layout[0],
        );

        let tabs = Tabs::new(
            Panel::ALL
                .iter()
                .map(|panel| match panel {
                    Panel::Tasks => Line::from("Tasks"),
                    Panel::Approvals => Line::from("Approvals"),
                })
                .collect::<Vec<_>>(),
        )
        .select(self.panel.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Governed views"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(layout[1]);
        frame.render_widget(tabs, body[0]);
        match (self.panel, snapshot) {
            (Panel::Tasks, Some(snapshot)) => render_tasks(frame, body[1], &snapshot.tasks),
            (Panel::Approvals, Some(snapshot)) => {
                render_approvals(frame, body[1], &snapshot.approvals)
            }
            (_, None) => frame.render_widget(
                Paragraph::new("No projection snapshot available.")
                    .block(Block::default().borders(Borders::ALL))
                    .wrap(Wrap { trim: true }),
                body[1],
            ),
        }
        frame.render_widget(
            Paragraph::new(self.message.as_str()).style(Style::default().fg(Color::Gray)),
            layout[2],
        );
    }
}

fn render_tasks(frame: &mut Frame<'_>, area: Rect, tasks: &[TaskView]) {
    let rows = tasks.iter().map(|view| {
        let task = view.task.as_ref();
        Row::new([
            Cell::from(task.map_or("-", |value| value.task_id.as_str())),
            Cell::from(
                task.and_then(|value| TaskStatus::try_from(value.status).ok())
                    .map(|value| value.as_str_name())
                    .unwrap_or("TASK_STATUS_UNSPECIFIED"),
            ),
            Cell::from(task.map_or("-".to_owned(), |value| value.revision.to_string())),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(48),
                Constraint::Percentage(32),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(["Task", "Status", "Revision"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Projected Tasks"),
        ),
        area,
    );
}

fn render_approvals(frame: &mut Frame<'_>, area: Rect, approvals: &[HarnessApprovalView]) {
    let rows = approvals.iter().map(|view| {
        Row::new([
            Cell::from(view.approval_request_id.clone()),
            Cell::from(
                ApprovalRequestLifecycleKind::try_from(view.request_lifecycle)
                    .map(|value| value.as_str_name())
                    .unwrap_or("APPROVAL_REQUEST_LIFECYCLE_UNSPECIFIED"),
            ),
            Cell::from(view.request_revision.to_string()),
            Cell::from(view.task_id.clone()),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(34),
                Constraint::Percentage(27),
                Constraint::Length(12),
                Constraint::Percentage(27),
            ],
        )
        .header(
            Row::new(["Approval", "Lifecycle", "Revision", "Task"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Projected Approvals"),
        ),
        area,
    );
}

fn local_error_message(
    error: egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError,
) -> String {
    let code = LocalApiErrorCode::try_from(error.code)
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|_| "LOCAL_API_ERROR_UNKNOWN".to_owned());
    if error.retryable {
        format!("{code} (retryable)")
    } else {
        code
    }
}

async fn run_once(mut app: App) -> Result<(), String> {
    app.refresh().await;
    if let Some(snapshot) = app.snapshot {
        println!(
            "EgoPulse TUI: connected health={} stale={} position={} tasks={} approvals={}",
            snapshot.health,
            snapshot.stale,
            snapshot.position,
            snapshot.tasks.len(),
            snapshot.approvals.len()
        );
        Ok(())
    } else {
        Err(app.message)
    }
}

async fn run_interactive(args: Args) -> Result<(), String> {
    let mut app = App::new(args.instance);
    app.refresh().await;
    let mut terminal = init_terminal().map_err(|error| error.to_string())?;
    let result = run_loop(&mut terminal, &mut app).await;
    restore_terminal(&mut terminal).map_err(|error| error.to_string())?;
    result
}

async fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<(), String> {
    let mut next_refresh = tokio::time::Instant::now();
    loop {
        terminal
            .draw(|frame| app.render(frame))
            .map_err(|error| error.to_string())?;
        if tokio::time::Instant::now() >= next_refresh {
            if app.snapshot.is_some() {
                app.refresh().await;
            }
            next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        if event::poll(Duration::from_millis(150)).map_err(|error| error.to_string())?
            && let Event::Key(key) = event::read().map_err(|error| error.to_string())?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('r') => {
                    app.message = "Refreshing…".to_owned();
                    app.refresh().await;
                    next_refresh = tokio::time::Instant::now() + app.refresh_interval;
                }
                KeyCode::Tab | KeyCode::Right | KeyCode::Left => app.panel = app.panel.next(),
                _ => {}
            }
        }
    }
}

fn init_terminal() -> io::Result<DefaultTerminal> {
    enable_raw_mode()?;
    let mut output = stdout();
    execute!(output, EnterAlternateScreen)?;
    Ok(ratatui::init())
}

fn restore_terminal(terminal: &mut DefaultTerminal) -> io::Result<()> {
    ratatui::restore();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    if args.foundation_check {
        let health = LocalApiClient::platform_default().foundation_health();
        println!("EgoPulse TUI: {}", health.state.as_str());
        return ExitCode::SUCCESS;
    }
    let result = if let Some(command) = args.command {
        run_command(&args.instance, command).await
    } else if args.once {
        run_once(App::new(args.instance)).await
    } else {
        run_interactive(args).await
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("EgoPulse TUI: {error}");
            ExitCode::from(3)
        }
    }
}
