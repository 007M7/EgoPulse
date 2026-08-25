#![forbid(unsafe_code)]

use std::{
    io::{self, stdout},
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use egopulse_client_operations::{
    ClientAttachment, ClientReadError, attach as attach_client, canonical_task_digest,
    command_metadata, set_policy_digest, set_verdict_digest, timestamp_after,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    common::v1::ContractReference,
    harness::v1::ApprovalDecision,
    harness::v1::ApprovalRequestLifecycleKind,
    localapi::v1::{
        AwaitProjectionRequest, DecideHarnessApprovalRequest, ExecuteFounderVerdictRequest,
        ExecuteTaskCommandRequest, GetEvidenceGraphRequest, HarnessApprovalView, LocalApiErrorCode,
        ProjectionAwaitToken, ProjectionHealth, SourceRevision, TaskView,
        await_projection_response, get_evidence_graph_response,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, policy_decision_command,
    },
    task::v1::TaskStatus,
    task::v1::{CreateTaskCommand, TaskCommand, task_command, task_command_result},
    verdict::v1::{
        FounderVerdictDecision, IssueFounderVerdictCommand, RevokeFounderVerdictCommand,
        VerdictCommand, VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_local_api::LocalApiClient;
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs, Wrap},
};
use serde_json::json;
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
    /// Submit the user-owned issue_founder_verdict branch.
    VerdictIssue {
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        task_revision: u64,
        #[arg(long)]
        work_revision: u64,
        #[arg(long)]
        artifact_set_id: String,
        #[arg(long)]
        artifact_set_manifest_sha256: String,
        #[arg(long)]
        artifact_set_manifest_byte_length: u64,
        #[arg(long)]
        verification_artifact_id: String,
        #[arg(long)]
        verification_payload_sha256: String,
        #[arg(long)]
        verification_payload_byte_length: u64,
        #[arg(long)]
        acceptance_contract_id: String,
        #[arg(long)]
        acceptance_contract_version: String,
        #[arg(long)]
        acceptance_contract_sha256: String,
        #[arg(long)]
        decision: String,
        #[arg(long)]
        observed_verification_conclusion: String,
        #[arg(long)]
        reason_code: String,
        #[arg(long, default_value = "explicit")]
        confirmation_class: String,
        #[arg(long)]
        confirmation_proof_ref: String,
        #[arg(long)]
        json: bool,
    },
    /// Submit the user-owned revoke_founder_verdict branch.
    VerdictRevoke {
        founder_verdict_id: String,
        #[arg(long)]
        expected_state_revision: u64,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        confirmation_proof_ref: String,
        #[arg(long)]
        json: bool,
    },
    /// Read a redacted Evidence Graph through the same local read model as the CLI.
    EvidenceGet {
        task_id: String,
        #[arg(long)]
        artifact_set_id: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    TaskCreate,
    ApprovalDecide,
    Await,
    VerdictIssue,
    VerdictRevoke,
    EvidenceGet,
}

impl CommandKind {
    const ALL: [Self; 6] = [
        Self::TaskCreate,
        Self::ApprovalDecide,
        Self::Await,
        Self::VerdictIssue,
        Self::VerdictRevoke,
        Self::EvidenceGet,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::TaskCreate => "Create governed task",
            Self::ApprovalDecide => "Decide harness approval",
            Self::Await => "Await projection",
            Self::VerdictIssue => "Issue Founder Verdict",
            Self::VerdictRevoke => "Revoke Founder Verdict",
            Self::EvidenceGet => "Read Evidence Graph",
        }
    }
}

#[derive(Clone, Debug)]
struct FormField {
    label: &'static str,
    value: String,
    required: bool,
}

impl FormField {
    fn required(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: true,
        }
    }

    fn optional(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: false,
        }
    }

    fn with_value(mut self, value: &'static str) -> Self {
        self.value = value.to_owned();
        self
    }
}

#[derive(Clone, Debug)]
struct CommandForm {
    kind: CommandKind,
    fields: Vec<FormField>,
    active: usize,
    error: Option<String>,
}

impl CommandForm {
    fn new(kind: CommandKind) -> Self {
        let fields = match kind {
            CommandKind::TaskCreate => vec![
                FormField::required("work-type"),
                FormField::required("input-snapshot-id"),
                FormField::required("target-scope-ref"),
                FormField::required("acceptance-contract-id"),
                FormField::required("acceptance-contract-version").with_value("v0.1"),
                FormField::required("acceptance-contract-sha256"),
                FormField::required("budget-profile-id"),
                FormField::required("budget-profile-version").with_value("v0.1"),
                FormField::required("budget-profile-sha256"),
            ],
            CommandKind::ApprovalDecide => vec![
                FormField::required("approval-request-id"),
                FormField::required("expected-action-digest-sha256"),
                FormField::required("expected-request-observation-id"),
                FormField::required("expected-request-observation-sequence"),
                FormField::required("expected-request-revision"),
                FormField::required("decision").with_value("allow-once"),
                FormField::required("reason-code"),
                FormField::optional("confirmation-proof-ref"),
            ],
            CommandKind::Await => vec![
                FormField::required("token-json"),
                FormField::required("timeout-milliseconds").with_value("5000"),
            ],
            CommandKind::VerdictIssue => vec![
                FormField::required("task-id"),
                FormField::required("task-revision"),
                FormField::required("work-revision"),
                FormField::required("artifact-set-id"),
                FormField::required("artifact-set-manifest-sha256"),
                FormField::required("artifact-set-manifest-byte-length"),
                FormField::required("verification-artifact-id"),
                FormField::required("verification-payload-sha256"),
                FormField::required("verification-payload-byte-length"),
                FormField::required("acceptance-contract-id"),
                FormField::required("acceptance-contract-version").with_value("v0.1"),
                FormField::required("acceptance-contract-sha256"),
                FormField::required("decision").with_value("accept"),
                FormField::required("observed-verification-conclusion").with_value("passed"),
                FormField::required("reason-code"),
                FormField::required("confirmation-class").with_value("explicit"),
                FormField::required("confirmation-proof-ref"),
            ],
            CommandKind::VerdictRevoke => vec![
                FormField::required("founder-verdict-id"),
                FormField::required("expected-state-revision").with_value("1"),
                FormField::required("reason-code"),
                FormField::required("confirmation-proof-ref"),
            ],
            CommandKind::EvidenceGet => vec![
                FormField::required("task-id"),
                FormField::required("artifact-set-id"),
            ],
        };
        Self {
            kind,
            fields,
            active: 0,
            error: None,
        }
    }

    fn active_field_mut(&mut self) -> &mut FormField {
        &mut self.fields[self.active]
    }

    fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            if field.required && field.value.trim().is_empty() {
                return Err(format!("{} is required", field.label));
            }
        }
        Ok(())
    }

    fn into_command(self) -> Result<TuiCommand, String> {
        self.validate()?;
        let mut values = self.fields.into_iter().map(|field| field.value);
        let next = |values: &mut dyn Iterator<Item = String>, label: &str| {
            values.next().ok_or_else(|| format!("{label} is missing"))
        };
        match self.kind {
            CommandKind::TaskCreate => Ok(TuiCommand::TaskCreate {
                work_type: next(&mut values, "work-type")?,
                input_snapshot_id: next(&mut values, "input-snapshot-id")?,
                target_scope_ref: next(&mut values, "target-scope-ref")?,
                acceptance_contract_id: next(&mut values, "acceptance-contract-id")?,
                acceptance_contract_version: next(&mut values, "acceptance-contract-version")?,
                acceptance_contract_sha256: next(&mut values, "acceptance-contract-sha256")?,
                budget_profile_id: next(&mut values, "budget-profile-id")?,
                budget_profile_version: next(&mut values, "budget-profile-version")?,
                budget_profile_sha256: next(&mut values, "budget-profile-sha256")?,
                json: false,
            }),
            CommandKind::ApprovalDecide => Ok(TuiCommand::ApprovalDecide {
                approval_request_id: next(&mut values, "approval-request-id")?,
                expected_action_digest_sha256: next(&mut values, "expected-action-digest-sha256")?,
                expected_request_observation_id: next(
                    &mut values,
                    "expected-request-observation-id",
                )?,
                expected_request_observation_sequence: next(
                    &mut values,
                    "expected-request-observation-sequence",
                )?
                .parse()
                .map_err(|_| {
                    "expected-request-observation-sequence must be an integer".to_owned()
                })?,
                expected_request_revision: next(&mut values, "expected-request-revision")?
                    .parse()
                    .map_err(|_| "expected-request-revision must be an integer".to_owned())?,
                decision: next(&mut values, "decision")?,
                reason_code: next(&mut values, "reason-code")?,
                confirmation_proof_ref: {
                    let value = next(&mut values, "confirmation-proof-ref")?;
                    (!value.trim().is_empty()).then_some(value)
                },
                json: false,
            }),
            CommandKind::Await => Ok(TuiCommand::Await {
                token_json: next(&mut values, "token-json")?,
                timeout_milliseconds: next(&mut values, "timeout-milliseconds")?
                    .parse()
                    .map_err(|_| "timeout-milliseconds must be an integer".to_owned())?,
                json: false,
            }),
            CommandKind::VerdictIssue => Ok(TuiCommand::VerdictIssue {
                task_id: next(&mut values, "task-id")?,
                task_revision: next(&mut values, "task-revision")?
                    .parse()
                    .map_err(|_| "task-revision must be an integer".to_owned())?,
                work_revision: next(&mut values, "work-revision")?
                    .parse()
                    .map_err(|_| "work-revision must be an integer".to_owned())?,
                artifact_set_id: next(&mut values, "artifact-set-id")?,
                artifact_set_manifest_sha256: next(&mut values, "artifact-set-manifest-sha256")?,
                artifact_set_manifest_byte_length: next(
                    &mut values,
                    "artifact-set-manifest-byte-length",
                )?
                .parse()
                .map_err(|_| "artifact-set-manifest-byte-length must be an integer".to_owned())?,
                verification_artifact_id: next(&mut values, "verification-artifact-id")?,
                verification_payload_sha256: next(&mut values, "verification-payload-sha256")?,
                verification_payload_byte_length: next(
                    &mut values,
                    "verification-payload-byte-length",
                )?
                .parse()
                .map_err(|_| "verification-payload-byte-length must be an integer".to_owned())?,
                acceptance_contract_id: next(&mut values, "acceptance-contract-id")?,
                acceptance_contract_version: next(&mut values, "acceptance-contract-version")?,
                acceptance_contract_sha256: next(&mut values, "acceptance-contract-sha256")?,
                decision: next(&mut values, "decision")?,
                observed_verification_conclusion: next(
                    &mut values,
                    "observed-verification-conclusion",
                )?,
                reason_code: next(&mut values, "reason-code")?,
                confirmation_class: next(&mut values, "confirmation-class")?,
                confirmation_proof_ref: next(&mut values, "confirmation-proof-ref")?,
                json: false,
            }),
            CommandKind::VerdictRevoke => Ok(TuiCommand::VerdictRevoke {
                founder_verdict_id: next(&mut values, "founder-verdict-id")?,
                expected_state_revision: next(&mut values, "expected-state-revision")?
                    .parse()
                    .map_err(|_| "expected-state-revision must be an integer".to_owned())?,
                reason_code: next(&mut values, "reason-code")?,
                confirmation_proof_ref: next(&mut values, "confirmation-proof-ref")?,
                json: false,
            }),
            CommandKind::EvidenceGet => Ok(TuiCommand::EvidenceGet {
                task_id: next(&mut values, "task-id")?,
                artifact_set_id: next(&mut values, "artifact-set-id")?,
                json: false,
            }),
        }
    }
}

#[derive(Clone, Debug)]
enum InteractiveMode {
    Dashboard,
    Palette { selected: usize },
    Form(CommandForm),
}

struct AttachedClient(ClientAttachment);

impl AttachedClient {
    async fn open(instance: &str) -> Result<Self, String> {
        let attached = attach_client(
            instance,
            egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientSurface::Tui,
            format!("egopulse-tui-{}", Uuid::now_v7()),
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok(Self(attached))
    }

    fn metadata(
        &self,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata, String>
    {
        self.0.metadata(None).map_err(|error| error.to_string())
    }

    fn metadata_with_correlation(
        &self,
        correlation_id: String,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata, String>
    {
        self.0
            .metadata(Some(correlation_id))
            .map_err(|error| error.to_string())
    }

    fn require_command(&self, rpc: &str, oneof: &str) -> Result<(), String> {
        self.0
            .require_command(rpc, oneof)
            .map_err(|error| error.to_string())
    }

    fn require_rpc(&self, rpc: &str, operation: &str) -> Result<(), String> {
        self.0
            .require_rpc(rpc)
            .map_err(|error| format!("{operation}: {error}"))
    }

    async fn snapshot(&self) -> Result<Snapshot, String> {
        let projection = self
            .0
            .read_projection_snapshot()
            .await
            .map_err(|error| match error {
                ClientReadError::Api(error) => local_error_message(*error),
                other => other.to_string(),
            })?;
        Ok(Snapshot {
            health: ProjectionHealth::try_from(projection.metadata.health)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned()),
            stale: projection.metadata.stale,
            position: projection
                .metadata
                .position
                .map(|value| format!("{}:{}", value.epoch, value.sequence))
                .unwrap_or_else(|| "unknown".to_owned()),
            tasks: projection.tasks,
            approvals: projection.approvals,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutput {
    Console,
    Quiet,
}

async fn run_command(instance: &str, command: TuiCommand) -> Result<(), String> {
    run_command_with_output(instance, command, CommandOutput::Console).await
}

async fn run_command_quiet(instance: &str, command: TuiCommand) -> Result<(), String> {
    run_command_with_output(instance, command, CommandOutput::Quiet).await
}

async fn run_command_with_output(
    instance: &str,
    command: TuiCommand,
    output: CommandOutput,
) -> Result<(), String> {
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
                .0
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
            if output == CommandOutput::Console {
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
                .0
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
            if output == CommandOutput::Console {
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
                .0
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
                    if output == CommandOutput::Console {
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
                    if output == CommandOutput::Console {
                        if json {
                            println!("{}", serde_json::to_string(&payload).unwrap());
                        } else {
                            println!(
                                "TUI awaited approval: {} revision={}",
                                payload["data"]["approvalRequestId"].as_str().unwrap_or(""),
                                payload["data"]["revision"].as_u64().unwrap_or_default()
                            );
                        }
                    }
                    Ok(())
                }
                Some(await_projection_response::Outcome::Error(error)) => {
                    Err(local_error_message(error))
                }
                None => Err("await outcome missing".to_owned()),
            }
        }
        TuiCommand::VerdictIssue {
            task_id,
            task_revision,
            work_revision,
            artifact_set_id,
            artifact_set_manifest_sha256,
            artifact_set_manifest_byte_length,
            verification_artifact_id,
            verification_payload_sha256,
            verification_payload_byte_length,
            acceptance_contract_id,
            acceptance_contract_version,
            acceptance_contract_sha256,
            decision,
            observed_verification_conclusion,
            reason_code,
            confirmation_class,
            confirmation_proof_ref,
            json,
        } => {
            let decision = parse_verdict_decision(&decision)?;
            let conclusion = parse_verification_conclusion(&observed_verification_conclusion)?;
            let confirmation_class = parse_confirmation_class(&confirmation_class)?;
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/ExecuteFounderVerdict",
                "issue_founder_verdict",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = VerdictCommand {
                command: Some(verdict_command::Command::IssueFounderVerdict(
                    IssueFounderVerdictCommand {
                        metadata: Some(command_metadata(
                            &correlation_id,
                            "egopulse-tui/verdict-issue",
                        )),
                        scope: Some(VerdictScope {
                            task_id,
                            task_revision,
                            work_revision,
                            artifact_set_id,
                            artifact_set_manifest: Some(ContentAddress {
                                algorithm: HashAlgorithm::Sha256 as i32,
                                digest: artifact_set_manifest_sha256,
                                byte_length: artifact_set_manifest_byte_length,
                            }),
                            verification_artifact_id,
                            verification_payload: Some(ContentAddress {
                                algorithm: HashAlgorithm::Sha256 as i32,
                                digest: verification_payload_sha256,
                                byte_length: verification_payload_byte_length,
                            }),
                            acceptance_contract_ref: Some(ContractReference {
                                contract_id: acceptance_contract_id,
                                version: acceptance_contract_version,
                                sha256: acceptance_contract_sha256,
                            }),
                        }),
                        decision,
                        observed_verification_conclusion: conclusion,
                        risk_acceptances: Vec::new(),
                        rework_directive: None,
                        reason_code,
                        rationale_artifact_id: None,
                        required_confirmation_class: confirmation_class,
                        confirmation_proof_ref,
                        expires_at: Some(timestamp_after(Duration::from_secs(3600))),
                        supersedes_founder_verdict_id: None,
                    },
                )),
            };
            set_verdict_digest(&mut command);
            let response = attached
                .0
                .connection
                .command_gateway_service()
                .execute_founder_verdict(ExecuteFounderVerdictRequest {
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
                .ok_or_else(|| "Founder Verdict authority result missing".to_owned())?;
            if result.error_code != 0 {
                return Err(format!("verdict authority rejected: {}", result.error_code));
            }
            let verdict_id = result
                .verdict
                .as_ref()
                .map(|verdict| verdict.founder_verdict_id.clone());
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "verdict.issue",
                "data": {
                    "committed": result.committed,
                    "replayed": result.replayed,
                    "founderVerdictId": verdict_id,
                    "stateRevision": result.state.as_ref().map(|state| state.revision),
                    "awaitToken": await_token_json(response.await_token),
                },
                "correlationId": correlation_id,
            });
            if output == CommandOutput::Console {
                if json {
                    println!("{}", serde_json::to_string(&payload).unwrap());
                } else {
                    println!(
                        "TUI Founder Verdict issued: id={} committed={} replayed={}",
                        payload["data"]["founderVerdictId"].as_str().unwrap_or(""),
                        payload["data"]["committed"].as_bool().unwrap_or(false),
                        payload["data"]["replayed"].as_bool().unwrap_or(false),
                    );
                }
            }
            Ok(())
        }
        TuiCommand::VerdictRevoke {
            founder_verdict_id,
            expected_state_revision,
            reason_code,
            confirmation_proof_ref,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/ExecuteFounderVerdict",
                "revoke_founder_verdict",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = VerdictCommand {
                command: Some(verdict_command::Command::RevokeFounderVerdict(
                    RevokeFounderVerdictCommand {
                        metadata: Some(command_metadata(
                            &correlation_id,
                            "egopulse-tui/verdict-revoke",
                        )),
                        founder_verdict_id,
                        expected_state_revision,
                        reason_code,
                        confirmation_proof_ref,
                    },
                )),
            };
            set_verdict_digest(&mut command);
            let response = attached
                .0
                .connection
                .command_gateway_service()
                .execute_founder_verdict(ExecuteFounderVerdictRequest {
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
                .ok_or_else(|| "Founder Verdict authority result missing".to_owned())?;
            if result.error_code != 0 {
                return Err(format!("verdict authority rejected: {}", result.error_code));
            }
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "verdict.revoke",
                "data": {
                    "committed": result.committed,
                    "replayed": result.replayed,
                    "founderVerdictId": result.state.as_ref().map(|state| state.founder_verdict_id.clone()),
                    "stateRevision": result.state.as_ref().map(|state| state.revision),
                    "awaitToken": await_token_json(response.await_token),
                },
                "correlationId": correlation_id,
            });
            if output == CommandOutput::Console {
                if json {
                    println!("{}", serde_json::to_string(&payload).unwrap());
                } else {
                    println!(
                        "TUI Founder Verdict revoked: id={} committed={} replayed={}",
                        payload["data"]["founderVerdictId"].as_str().unwrap_or(""),
                        payload["data"]["committed"].as_bool().unwrap_or(false),
                        payload["data"]["replayed"].as_bool().unwrap_or(false),
                    );
                }
            }
            Ok(())
        }
        TuiCommand::EvidenceGet {
            task_id,
            artifact_set_id,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_rpc("LocalReadModelService/GetEvidenceGraph", "evidence.get")?;
            let correlation_id = Uuid::now_v7().to_string();
            let response = attached
                .0
                .connection
                .read_model_service()
                .get_evidence_graph(GetEvidenceGraphRequest {
                    client: Some(attached.metadata_with_correlation(correlation_id.clone())?),
                    task_id,
                    artifact_set_id,
                    minimum_position: None,
                })
                .await
                .map_err(|error| error.to_string())?
                .into_inner();
            let graph = match response.outcome {
                Some(get_evidence_graph_response::Outcome::Graph(graph)) => graph,
                Some(get_evidence_graph_response::Outcome::Error(error)) => {
                    return Err(local_error_message(error));
                }
                None => return Err("evidence graph outcome missing".to_owned()),
            };
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "evidence.get",
                "data": {
                    "taskId": graph.task_id,
                    "artifactSetId": graph.artifact_set_id,
                    "artifactCount": graph.artifacts.len(),
                    "claimCount": graph.claims.len(),
                    "evidenceCount": graph.evidence.len(),
                    "redactions": graph.redactions.iter().map(|item| json!({
                        "fieldPath": item.field_path,
                        "reasonCode": item.reason_code,
                    })).collect::<Vec<_>>(),
                },
                "correlationId": correlation_id,
            });
            if output == CommandOutput::Console {
                if json {
                    println!("{}", serde_json::to_string(&payload).unwrap());
                } else {
                    println!(
                        "TUI Evidence Graph: task={} artifact_set={} artifacts={} claims={} evidence={}",
                        payload["data"]["taskId"].as_str().unwrap_or(""),
                        payload["data"]["artifactSetId"].as_str().unwrap_or(""),
                        payload["data"]["artifactCount"]
                            .as_u64()
                            .unwrap_or_default(),
                        payload["data"]["claimCount"].as_u64().unwrap_or_default(),
                        payload["data"]["evidenceCount"]
                            .as_u64()
                            .unwrap_or_default(),
                    );
                }
            }
            Ok(())
        }
    }
}

fn command_kind(command: &TuiCommand) -> &'static str {
    match command {
        TuiCommand::TaskCreate { .. } => "task.create",
        TuiCommand::ApprovalDecide { .. } => "approval.decide",
        TuiCommand::Await { .. } => "await",
        TuiCommand::VerdictIssue { .. } => "verdict.issue",
        TuiCommand::VerdictRevoke { .. } => "verdict.revoke",
        TuiCommand::EvidenceGet { .. } => "evidence.get",
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

fn parse_verdict_decision(value: &str) -> Result<i32, String> {
    match value {
        "accept" => Ok(FounderVerdictDecision::Accept as i32),
        "rework" => Ok(FounderVerdictDecision::Rework as i32),
        "reject" => Ok(FounderVerdictDecision::Reject as i32),
        _ => Err("decision must be accept, rework, or reject".to_owned()),
    }
}

fn parse_verification_conclusion(value: &str) -> Result<i32, String> {
    match value {
        "passed" => Ok(VerificationConclusion::Passed as i32),
        "failed" => Ok(VerificationConclusion::Failed as i32),
        "partial" => Ok(VerificationConclusion::Partial as i32),
        "indeterminate" => Ok(VerificationConclusion::Indeterminate as i32),
        _ => Err(
            "observed verification conclusion must be passed, failed, partial, or indeterminate"
                .to_owned(),
        ),
    }
}

fn parse_confirmation_class(value: &str) -> Result<i32, String> {
    match value {
        "explicit" => Ok(1),
        "elevated-risk-acceptance" => Ok(2),
        _ => Err("confirmation class must be explicit or elevated-risk-acceptance".to_owned()),
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
    mode: InteractiveMode,
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
            mode: InteractiveMode::Dashboard,
        }
    }

    fn open_palette(&mut self) {
        self.mode = InteractiveMode::Palette { selected: 0 };
        self.message = "Choose a governed command; Esc returns to the dashboard".to_owned();
    }

    fn open_form(&mut self, kind: CommandKind) {
        self.mode = InteractiveMode::Form(CommandForm::new(kind));
        self.message = format!(
            "{}: type a value, Tab/Down advances, Enter submits, Esc cancels",
            kind.label()
        );
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<Option<TuiCommand>, String> {
        match &mut self.mode {
            InteractiveMode::Dashboard => match key.code {
                KeyCode::Char('c') => {
                    self.open_palette();
                    Ok(None)
                }
                KeyCode::Char('r') => Ok(None),
                _ => Ok(None),
            },
            InteractiveMode::Palette { selected } => match key.code {
                KeyCode::Esc => {
                    self.mode = InteractiveMode::Dashboard;
                    self.message = "Command palette cancelled".to_owned();
                    Ok(None)
                }
                KeyCode::Up | KeyCode::Left => {
                    *selected = selected
                        .checked_sub(1)
                        .unwrap_or(CommandKind::ALL.len() - 1);
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Right | KeyCode::Tab => {
                    *selected = (*selected + 1) % CommandKind::ALL.len();
                    Ok(None)
                }
                KeyCode::Enter => {
                    let kind = CommandKind::ALL[*selected];
                    self.open_form(kind);
                    Ok(None)
                }
                _ => Ok(None),
            },
            InteractiveMode::Form(form) => match key.code {
                KeyCode::Esc => {
                    self.mode = InteractiveMode::Palette { selected: 0 };
                    self.message = "Form cancelled; choose another governed command".to_owned();
                    Ok(None)
                }
                KeyCode::Up | KeyCode::Left => {
                    form.active = form.active.saturating_sub(1);
                    form.error = None;
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Tab => {
                    form.active = (form.active + 1) % form.fields.len();
                    form.error = None;
                    Ok(None)
                }
                KeyCode::Backspace => {
                    form.active_field_mut().value.pop();
                    form.error = None;
                    Ok(None)
                }
                KeyCode::Char(character) => {
                    if !key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL)
                    {
                        form.active_field_mut().value.push(character);
                        form.error = None;
                    }
                    Ok(None)
                }
                KeyCode::Enter => {
                    if form.active + 1 < form.fields.len() {
                        form.active += 1;
                        form.error = None;
                        return Ok(None);
                    }
                    match form.clone().into_command() {
                        Ok(command) => {
                            self.mode = InteractiveMode::Dashboard;
                            Ok(Some(command))
                        }
                        Err(error) => {
                            form.error = Some(error.clone());
                            self.message = error;
                            Ok(None)
                        }
                    }
                }
                _ => Ok(None),
            },
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
        match &self.mode {
            InteractiveMode::Dashboard => match (self.panel, snapshot) {
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
            },
            InteractiveMode::Palette { selected } => {
                render_command_palette(frame, body[1], *selected)
            }
            InteractiveMode::Form(form) => render_command_form(frame, body[1], form),
        }
        frame.render_widget(
            Paragraph::new(self.footer_text())
                .style(Style::default().fg(Color::Gray))
                .wrap(Wrap { trim: true }),
            layout[2],
        );
    }

    fn footer_text(&self) -> String {
        match &self.mode {
            InteractiveMode::Dashboard => format!(
                "{} · c command palette · r refresh · Tab/←/→ panel · q quit",
                self.message
            ),
            InteractiveMode::Palette { .. } => {
                format!("{} · ↑/↓ select · Enter open · Esc cancel", self.message)
            }
            InteractiveMode::Form(form) => format!(
                "{}{}",
                self.message,
                form.error
                    .as_deref()
                    .map_or(String::new(), |error| format!(" · error: {error}"))
            ),
        }
    }
}

fn render_command_palette(frame: &mut Frame<'_>, area: Rect, selected: usize) {
    frame.render_widget(Clear, area);
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(selected));
    frame.render_stateful_widget(
        List::new(
            CommandKind::ALL
                .iter()
                .map(|kind| ListItem::new(kind.label())),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Governed command palette"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ "),
        area,
        &mut state,
    );
}

fn render_command_form(frame: &mut Frame<'_>, area: Rect, form: &CommandForm) {
    let height = area.height.saturating_sub(2) as usize;
    let start = form.active.saturating_sub(height.saturating_sub(1));
    let end = (start + height).min(form.fields.len());
    let items = form.fields[start..end]
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let actual = start + index;
            let marker = if actual == form.active { "▶" } else { " " };
            let required = if field.required { "*" } else { " " };
            let value = if field.value.is_empty() {
                "<empty>".to_owned()
            } else {
                field.value.clone()
            };
            ListItem::new(format!("{marker} {required} {:<42} {}", field.label, value))
        })
        .collect::<Vec<_>>();
    frame.render_widget(Clear, area);
    frame.render_widget(
        List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("{} · * required", form.kind.label())),
            )
            .highlight_style(Style::default().fg(Color::Yellow)),
        area,
    );
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
            let dashboard = matches!(app.mode, InteractiveMode::Dashboard);
            if dashboard && matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                return Ok(());
            }
            if dashboard && key.code == KeyCode::Char('r') {
                app.message = "Refreshing…".to_owned();
                app.refresh().await;
                next_refresh = tokio::time::Instant::now() + app.refresh_interval;
                continue;
            }
            if dashboard && matches!(key.code, KeyCode::Tab | KeyCode::Right | KeyCode::Left) {
                app.panel = app.panel.next();
                continue;
            }
            if let Some(command) = app.handle_key(key)? {
                app.message = format!("Executing {}…", command_kind(&command));
                let result = run_command_quiet(&app.instance, command).await;
                app.message = match result {
                    Ok(()) => "Governed command committed; projection will refresh automatically"
                        .to_owned(),
                    Err(error) => format!("Governed command rejected: {error}"),
                };
                app.refresh().await;
                next_refresh = tokio::time::Instant::now() + app.refresh_interval;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};

    #[test]
    fn command_form_rejects_missing_required_values() {
        let form = CommandForm::new(CommandKind::TaskCreate);
        let error = form.into_command().expect_err("empty form must not submit");
        assert_eq!(error, "work-type is required");
    }

    #[test]
    fn command_form_maps_optional_confirmation_and_numeric_fields() {
        let mut form = CommandForm::new(CommandKind::ApprovalDecide);
        for (field, value) in form.fields.iter_mut().zip([
            "approval-1".to_owned(),
            "a".repeat(64),
            "observation-1".to_owned(),
            "7".to_owned(),
            "3".to_owned(),
            "deny".to_owned(),
            "user-denied".to_owned(),
            String::new(),
        ]) {
            field.value = value;
        }
        let command = form.into_command().expect("valid approval form");
        match command {
            TuiCommand::ApprovalDecide {
                expected_request_observation_sequence,
                expected_request_revision,
                confirmation_proof_ref,
                decision,
                ..
            } => {
                assert_eq!(expected_request_observation_sequence, 7);
                assert_eq!(expected_request_revision, 3);
                assert_eq!(confirmation_proof_ref, None);
                assert_eq!(decision, "deny");
            }
            _ => panic!("wrong command kind"),
        }
    }

    #[test]
    fn command_palette_and_form_use_same_command_surface() {
        let mut app = App::new("default".to_owned());
        app.open_palette();
        assert!(matches!(app.mode, InteractiveMode::Palette { selected: 0 }));
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
            .expect("palette navigation");
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("open form");
        assert!(matches!(
            app.mode,
            InteractiveMode::Form(CommandForm {
                kind: CommandKind::ApprovalDecide,
                ..
            })
        ));
    }

    #[test]
    fn evidence_form_maps_to_read_only_operation() {
        let mut form = CommandForm::new(CommandKind::EvidenceGet);
        for (field, value) in form
            .fields
            .iter_mut()
            .zip(["task-1".to_owned(), "artifact-set-1".to_owned()])
        {
            field.value = value;
        }
        let command = form.into_command().expect("valid evidence form");
        assert_eq!(command_kind(&command), "evidence.get");
        assert!(matches!(
            command,
            TuiCommand::EvidenceGet {
                task_id,
                artifact_set_id,
                json: false,
            } if task_id == "task-1" && artifact_set_id == "artifact-set-1"
        ));
    }
}
