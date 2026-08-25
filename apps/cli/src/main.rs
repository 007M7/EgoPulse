#![forbid(unsafe_code)]
// The CLI keeps a structured, owned failure envelope so every surface can
// render the same stable error facts. Its size is intentional at this
// boundary; the process is short-lived and does not cross the kernel ABI.
#![allow(clippy::result_large_err)]

use std::{
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use egopulse_client_kernel::{ClientKernel, SnapshotStreamTracker, StreamApply};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::ApprovalDecision,
    localapi::v1::{
        AwaitProjectionRequest, ClientSurface, DecideHarnessApprovalRequest,
        ExecuteFounderVerdictRequest, ExecuteTaskCommandRequest, GetEvidenceGraphRequest,
        GetHarnessApprovalViewRequest, GetProjectionStatusRequest, GetTaskViewRequest,
        HarnessApprovalViewStreamFrame, ListHarnessApprovalViewsRequest, ListTaskViewsRequest,
        LocalApiError, LocalApiErrorCode, ProjectionAwaitToken, ProjectionHealth,
        ProjectionMetadata, SourceRevision, TaskView, TaskViewStreamFrame,
        WatchHarnessApprovalViewsRequest, WatchTaskViewsRequest, await_projection_response,
        get_evidence_graph_response, get_harness_approval_view_response, get_task_view_response,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, PolicyDecisionErrorCode,
        policy_decision_command,
    },
    task::v1::{
        CreateTaskCommand, TaskCommand, TaskErrorCode, TaskStatus, task_command,
        task_command_result,
    },
    verdict::v1::{
        FounderVerdictDecision, IssueFounderVerdictCommand, RevokeFounderVerdictCommand,
        VerdictCommand, VerdictErrorCode, VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use prost::Message;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DEFAULT_INSTANCE: &str = "default";

#[derive(Debug, Parser)]
#[command(name = "egopulse", version, about = "EgoPulse local client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach to the local daemon and print typed projection status.
    Status {
        /// Emit stable JSON for scripts.
        #[arg(long)]
        json: bool,
    },
    /// Wait for a command's projection await token and return the projected view.
    Await {
        /// JSON object previously emitted as data.awaitToken by a write command.
        #[arg(long)]
        token_json: String,
        #[arg(long, default_value_t = 5000)]
        timeout_milliseconds: u32,
        #[arg(long)]
        json: bool,
    },
    /// Read or create a Task through the local API.
    Task {
        #[command(subcommand)]
        command: TaskCommandCli,
    },
    /// Read a redacted Evidence Graph through the local API.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Read Harness approval projections through the local API.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Submit or revoke a Founder Verdict through its owning Authority.
    Verdict {
        #[command(subcommand)]
        command: VerdictCommandCli,
    },
}

#[derive(Debug, Subcommand)]
enum TaskCommandCli {
    /// Read one projected Task.
    Get {
        task_id: String,
        #[arg(long)]
        json: bool,
    },
    /// List projected Tasks using a bounded page.
    List {
        #[arg(long, default_value_t = 50)]
        page_size: u32,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Consume a bounded governed Task projection stream.
    Watch {
        #[arg(long, default_value_t = 1)]
        frames: u32,
        #[arg(long)]
        resume_epoch: Option<String>,
        #[arg(long)]
        resume_sequence: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Submit the user-owned create_task branch.
    Create {
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
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    /// Read the redacted Evidence Graph for a Task.
    Get {
        task_id: String,
        #[arg(long)]
        artifact_set_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// Read one projected Harness approval request.
    Get {
        approval_request_id: String,
        #[arg(long)]
        json: bool,
    },
    /// List projected Harness approval requests using a bounded page.
    List {
        #[arg(long, default_value_t = 50)]
        page_size: u32,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        actionable_only: bool,
        #[arg(long)]
        json: bool,
    },
    /// Consume a bounded governed Harness Approval projection stream.
    Watch {
        #[arg(long, default_value_t = 1)]
        frames: u32,
        #[arg(long)]
        resume_epoch: Option<String>,
        #[arg(long)]
        resume_sequence: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Submit the user-owned issue_harness_approval_decision branch.
    Decide {
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
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum VerdictCommandCli {
    /// Submit the user-owned issue_founder_verdict branch.
    Issue {
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
    Revoke {
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
}

#[derive(Debug)]
struct CliFailure {
    exit_code: u8,
    reason_code: &'static str,
    message: String,
    category: &'static str,
    retryable: bool,
    required_action_code: Option<String>,
    safe_fingerprint: Option<String>,
    operation: &'static str,
}

struct ProjectionStatusView {
    health: String,
    stale: bool,
    epoch: String,
    sequence: u64,
}

impl ProjectionStatusView {
    fn json(&self) -> serde_json::Value {
        json!({
            "schemaVersion": "egopulse.cli-result/v0.1",
            "ok": true,
            "operation": "status",
            "data": { "state": "connected" },
            "projection": {
                "position": { "epoch": self.epoch, "sequence": self.sequence },
                "health": self.health,
                "stale": self.stale,
            },
            "correlationId": Uuid::now_v7().to_string(),
        })
    }

    fn text(&self) -> String {
        format!(
            "EgoPulse status: connected\nProjection: {}\nPosition: {}:{}\nStale: {}\n",
            self.health, self.epoch, self.sequence, self.stale
        )
    }
}

impl CliFailure {
    fn daemon_unavailable(message: impl Into<String>) -> Self {
        Self {
            exit_code: 3,
            reason_code: "DAEMON_UNAVAILABLE",
            message: message.into(),
            category: "unavailable",
            retryable: true,
            required_action_code: Some("attach_to_daemon".to_owned()),
            safe_fingerprint: None,
            operation: "status",
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            exit_code: 70,
            reason_code: "LOCAL_API_PROTOCOL_ERROR",
            message: message.into(),
            category: "internal",
            retryable: false,
            required_action_code: None,
            safe_fingerprint: None,
            operation: "status",
        }
    }

    fn stream_recovery(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit_code: 7,
            reason_code: "PROJECTION_STREAM_RECOVERY_REQUIRED",
            message: message.into(),
            category: "projection",
            retryable: true,
            required_action_code: Some("REFETCH_PROJECTION".to_owned()),
            safe_fingerprint: None,
            operation,
        }
    }

    fn permission(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit_code: 4,
            reason_code: "PERMISSION_DENIED",
            message: message.into(),
            category: "authentication",
            retryable: false,
            required_action_code: Some("USE_AUTHORIZED_SESSION".to_owned()),
            safe_fingerprint: Some("client_profile_denied".to_owned()),
            operation,
        }
    }

    fn from_local_api_error(error: LocalApiError) -> Self {
        let code = LocalApiErrorCode::try_from(error.code)
            .map(|code| code.as_str_name())
            .unwrap_or("LOCAL_API_ERROR_UNKNOWN");
        let (exit_code, category) = match LocalApiErrorCode::try_from(error.code).ok() {
            Some(LocalApiErrorCode::Unauthenticated | LocalApiErrorCode::PermissionDenied) => {
                (4, "authentication")
            }
            Some(LocalApiErrorCode::ContractIncompatible | LocalApiErrorCode::SessionExpired) => {
                (5, "contract")
            }
            Some(
                LocalApiErrorCode::ProjectionBehind
                | LocalApiErrorCode::ProjectionResetRequired
                | LocalApiErrorCode::CursorExpired
                | LocalApiErrorCode::CursorInvalid,
            ) => (7, "projection"),
            _ => (70, "internal"),
        };
        Self {
            exit_code,
            reason_code: "LOCAL_API_ERROR",
            message: code.to_owned(),
            category,
            retryable: error.retryable,
            required_action_code: error.required_action_code,
            safe_fingerprint: (!error.safe_fingerprint.is_empty())
                .then_some(error.safe_fingerprint),
            operation: "status",
        }
    }

    fn task_authority(
        error_code: i32,
        safe_detail_code: impl Into<String>,
        operation: &'static str,
    ) -> Self {
        let code = TaskErrorCode::try_from(error_code).unwrap_or(TaskErrorCode::Internal);
        let (exit_code, category, retryable, required_action_code) = match code {
            TaskErrorCode::Unauthenticated | TaskErrorCode::PermissionDenied => {
                (4, "authentication", false, Some("USE_AUTHORIZED_SESSION"))
            }
            TaskErrorCode::ContractMismatch => (5, "contract", false, Some("REFRESH_CONTRACT")),
            TaskErrorCode::RevisionConflict
            | TaskErrorCode::StateConflict
            | TaskErrorCode::IdempotencyConflict
            | TaskErrorCode::NotFound
            | TaskErrorCode::StaleReference
            | TaskErrorCode::UnverifiedReference
            | TaskErrorCode::TerminalGateUnsatisfied => {
                (6, "domain_conflict", false, Some("REVIEW_DOMAIN_STATE"))
            }
            TaskErrorCode::RecoveryRequired
            | TaskErrorCode::IntegrityFailure
            | TaskErrorCode::Internal => (8, "recovery", true, Some("RECOVERY_REQUIRED")),
            _ => (70, "invalid_request", false, None),
        };
        Self {
            exit_code,
            reason_code: "TASK_AUTHORITY_REJECTED",
            message: safe_detail_code.into(),
            category,
            retryable,
            required_action_code: required_action_code.map(str::to_owned),
            safe_fingerprint: None,
            operation,
        }
    }

    fn verdict_authority(
        error_code: i32,
        safe_fingerprint: Option<String>,
        operation: &'static str,
    ) -> Self {
        let code =
            VerdictErrorCode::try_from(error_code).unwrap_or(VerdictErrorCode::IntegrityFailure);
        let (exit_code, category, retryable, required_action_code) = match code {
            VerdictErrorCode::Unauthenticated | VerdictErrorCode::PermissionDenied => {
                (4, "authentication", false, Some("USE_AUTHORIZED_SESSION"))
            }
            VerdictErrorCode::RevisionConflict
            | VerdictErrorCode::IdempotencyConflict
            | VerdictErrorCode::NotFound
            | VerdictErrorCode::TaskNotVerdictPending
            | VerdictErrorCode::ScopeStale
            | VerdictErrorCode::VerificationMismatch
            | VerdictErrorCode::ConfirmationRequired
            | VerdictErrorCode::RiskAcceptanceRequired
            | VerdictErrorCode::RiskCoverageIncomplete
            | VerdictErrorCode::NonOverridableGate
            | VerdictErrorCode::ReworkDirectiveRequired
            | VerdictErrorCode::AlreadyActive
            | VerdictErrorCode::AlreadyConsumed
            | VerdictErrorCode::Expired
            | VerdictErrorCode::Revoked
            | VerdictErrorCode::TaskCommitReceiptInvalid => {
                (6, "domain_conflict", false, Some("REVIEW_DOMAIN_STATE"))
            }
            VerdictErrorCode::IntegrityFailure => (8, "recovery", true, Some("RECOVERY_REQUIRED")),
            _ => (70, "invalid_request", false, None),
        };
        Self {
            exit_code,
            reason_code: "VERDICT_AUTHORITY_REJECTED",
            message: "Founder Verdict authority rejected the command".to_owned(),
            category,
            retryable,
            required_action_code: required_action_code.map(str::to_owned),
            safe_fingerprint,
            operation,
        }
    }

    fn policy_authority(
        error_code: i32,
        safe_fingerprint: Option<String>,
        operation: &'static str,
    ) -> Self {
        let code = PolicyDecisionErrorCode::try_from(error_code)
            .unwrap_or(PolicyDecisionErrorCode::IntegrityFailure);
        let (exit_code, category, retryable, required_action_code) = match code {
            PolicyDecisionErrorCode::Unauthenticated
            | PolicyDecisionErrorCode::PermissionDenied => {
                (4, "authentication", false, Some("USE_AUTHORIZED_SESSION"))
            }
            PolicyDecisionErrorCode::RevisionConflict
            | PolicyDecisionErrorCode::IdempotencyConflict
            | PolicyDecisionErrorCode::NotFound
            | PolicyDecisionErrorCode::RequestMismatch
            | PolicyDecisionErrorCode::FencingRejected
            | PolicyDecisionErrorCode::PolicyDenied
            | PolicyDecisionErrorCode::AlreadyConsumed
            | PolicyDecisionErrorCode::Expired
            | PolicyDecisionErrorCode::Revoked
            | PolicyDecisionErrorCode::DeliveryReceiptInvalid => {
                (6, "domain_conflict", false, Some("REVIEW_DOMAIN_STATE"))
            }
            PolicyDecisionErrorCode::IntegrityFailure => {
                (8, "recovery", true, Some("RECOVERY_REQUIRED"))
            }
            _ => (70, "invalid_request", false, None),
        };
        Self {
            exit_code,
            reason_code: "POLICY_AUTHORITY_REJECTED",
            message: "Policy Decision authority rejected the command".to_owned(),
            category,
            retryable,
            required_action_code: required_action_code.map(str::to_owned),
            safe_fingerprint,
            operation,
        }
    }

    fn for_operation(mut self, operation: &'static str) -> Self {
        self.operation = operation;
        self
    }

    fn json_envelope(&self) -> serde_json::Value {
        json!({
            "schemaVersion": "egopulse.cli-result/v0.1",
            "ok": false,
            "operation": self.operation,
            "error": {
                "category": self.category,
                "code": self.reason_code,
                "retryable": self.retryable,
                "requiredActionCode": self.required_action_code,
                "safeFingerprint": self.safe_fingerprint,
            },
            "projection": serde_json::Value::Null,
            "correlationId": Uuid::now_v7().to_string(),
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_output = command_json(&cli.command);
    let result = match cli.command {
        Command::Status { json } => status(json).await,
        Command::Await {
            token_json,
            timeout_milliseconds,
            json,
        } => await_projection(token_json, timeout_milliseconds, json).await,
        Command::Task { command } => task(command).await,
        Command::Evidence { command } => evidence(command).await,
        Command::Approval { command } => approval(command).await,
        Command::Verdict { command } => verdict(command).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json_output {
                println!("{}", serde_json::to_string(&error.json_envelope()).unwrap());
            } else {
                eprintln!("{}: {}", error.reason_code, error.message);
            }
            ExitCode::from(error.exit_code)
        }
    }
}

fn command_json(command: &Command) -> bool {
    match command {
        Command::Status { json }
        | Command::Await { json, .. }
        | Command::Task {
            command:
                TaskCommandCli::Get { json, .. }
                | TaskCommandCli::List { json, .. }
                | TaskCommandCli::Watch { json, .. }
                | TaskCommandCli::Create { json, .. },
        }
        | Command::Evidence {
            command: EvidenceCommand::Get { json, .. },
        }
        | Command::Approval {
            command:
                ApprovalCommand::Get { json, .. }
                | ApprovalCommand::List { json, .. }
                | ApprovalCommand::Watch { json, .. }
                | ApprovalCommand::Decide { json, .. },
        }
        | Command::Verdict {
            command: VerdictCommandCli::Issue { json, .. } | VerdictCommandCli::Revoke { json, .. },
        } => *json,
    }
}

struct AttachedClient {
    connection: LocalApiConnection,
    kernel: ClientKernel,
}

impl AttachedClient {
    fn metadata(
        &self,
        correlation_id: Option<String>,
    ) -> Result<
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata,
        CliFailure,
    > {
        self.kernel
            .request_metadata(
                Uuid::now_v7().to_string(),
                correlation_id,
                SystemTime::now(),
            )
            .map_err(|error| CliFailure::protocol(error.to_string()))
    }

    fn require_rpc(&self, rpc: &str, operation: &'static str) -> Result<(), CliFailure> {
        let session = self.kernel.session().ok_or_else(|| {
            CliFailure::protocol("session binding missing").for_operation(operation)
        })?;
        self.kernel
            .profiles()
            .authorize_rpc(rpc, &session.granted_permission_codes)
            .map_err(|error| CliFailure::permission(operation, error.to_string()))
    }

    fn require_command(
        &self,
        rpc: &str,
        oneof: &str,
        operation: &'static str,
    ) -> Result<(), CliFailure> {
        let session = self.kernel.session().ok_or_else(|| {
            CliFailure::protocol("session binding missing").for_operation(operation)
        })?;
        self.kernel
            .profiles()
            .authorize_command(rpc, oneof, &session.granted_permission_codes)
            .map(|_| ())
            .map_err(|error| CliFailure::permission(operation, error.to_string()))
    }
}

async fn attach(operation: &'static str) -> Result<AttachedClient, CliFailure> {
    let result = async {
        let instance =
            std::env::var("EGOPULSE_IPC_INSTANCE").unwrap_or_else(|_| DEFAULT_INSTANCE.to_owned());
        let address = LocalIpcAddress::for_instance(&instance)
            .map_err(|error| CliFailure::protocol(format!("invalid IPC instance: {error}")))?;
        let connection = LocalApiClient::platform_default()
            .connect(address)
            .await
            .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?;
        let mut kernel = ClientKernel::new("egopulse-cli", ClientSurface::Cli)
            .map_err(|error| CliFailure::protocol(error.to_string()))?;
        let open_request = kernel
            .open_session_request(Uuid::now_v7().to_string())
            .map_err(|error| CliFailure::protocol(error.to_string()))?;
        let open_response = connection
            .session_service()
            .open_session(open_request)
            .await
            .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?
            .into_inner();
        kernel
            .accept_open_session(open_response, SystemTime::now())
            .map_err(|error| CliFailure::protocol(error.to_string()))?;
        Ok::<_, CliFailure>(AttachedClient { connection, kernel })
    }
    .await;
    result.map_err(|mut error| {
        error.operation = operation;
        error
    })
}

async fn status(json: bool) -> Result<(), CliFailure> {
    let attached = attach("status").await?;
    attached.require_rpc("LocalReadModelService/GetProjectionStatus", "status")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .get_projection_status(GetProjectionStatusRequest {
            client: Some(metadata),
        })
        .await
        .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?
        .into_inner();
    if let Some(error) = response.error {
        return Err(CliFailure::from_local_api_error(error).for_operation("status"));
    }
    let metadata = response
        .metadata
        .ok_or_else(|| CliFailure::protocol("projection metadata missing"))?;
    let position = metadata
        .position
        .ok_or_else(|| CliFailure::protocol("projection position missing"))?;
    let health = ProjectionHealth::try_from(metadata.health)
        .map_err(|_| CliFailure::protocol("projection health is unknown"))?;

    let view = ProjectionStatusView {
        health: health.as_str_name().to_owned(),
        stale: metadata.stale,
        epoch: position.epoch,
        sequence: position.sequence,
    };
    if json {
        println!("{}", serde_json::to_string(&view.json()).unwrap());
    } else {
        print!("{}", view.text());
    }
    Ok(())
}

async fn await_projection(
    token_json: String,
    timeout_milliseconds: u32,
    json: bool,
) -> Result<(), CliFailure> {
    let token = parse_await_token(&token_json)
        .map_err(|message| CliFailure::protocol(message).for_operation("await"))?;
    let attached = attach("await").await?;
    attached.require_rpc("LocalReadModelService/AwaitProjection", "await")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .await_projection(AwaitProjectionRequest {
            client: Some(metadata),
            await_token: Some(token),
            timeout_milliseconds: timeout_milliseconds.min(60_000),
        })
        .await
        .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?
        .into_inner();
    match response.outcome {
        Some(await_projection_response::Outcome::View(view)) => {
            let payload = json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "await",
                "data": { "kind": "task", "view": task_summary(&view) },
                "correlationId": Uuid::now_v7().to_string(),
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "Awaited Task: {} revision={} status={}",
                    payload["data"]["view"]["taskId"].as_str().unwrap_or(""),
                    payload["data"]["view"]["revision"]
                        .as_u64()
                        .unwrap_or_default(),
                    payload["data"]["view"]["status"].as_str().unwrap_or(""),
                );
            }
            Ok(())
        }
        Some(await_projection_response::Outcome::ApprovalView(view)) => {
            let payload = approval_json(&view, "await");
            let payload = json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "await",
                "data": { "kind": "approval", "view": payload["data"].clone() },
                "projection": payload["projection"].clone(),
                "correlationId": Uuid::now_v7().to_string(),
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "Awaited Approval: {} revision={} lifecycle={}",
                    payload["data"]["view"]["approvalRequestId"]
                        .as_str()
                        .unwrap_or(""),
                    payload["data"]["view"]["requestRevision"]
                        .as_u64()
                        .unwrap_or_default(),
                    payload["data"]["view"]["requestLifecycle"]
                        .as_str()
                        .unwrap_or(""),
                );
            }
            Ok(())
        }
        Some(await_projection_response::Outcome::Error(error)) => {
            Err(CliFailure::from_local_api_error(error).for_operation("await"))
        }
        None => Err(CliFailure::protocol("await outcome missing").for_operation("await")),
    }
}

async fn task(command: TaskCommandCli) -> Result<(), CliFailure> {
    match command {
        TaskCommandCli::Get { task_id, json } => task_get(task_id, json).await,
        TaskCommandCli::List {
            page_size,
            cursor,
            json,
        } => task_list(page_size, cursor, json).await,
        TaskCommandCli::Watch {
            frames,
            resume_epoch,
            resume_sequence,
            json,
        } => task_watch(frames, resume_epoch, resume_sequence, json).await,
        TaskCommandCli::Create {
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
            task_create(
                work_type,
                input_snapshot_id,
                target_scope_ref,
                ContractReference {
                    contract_id: acceptance_contract_id,
                    version: acceptance_contract_version,
                    sha256: acceptance_contract_sha256,
                },
                ContractReference {
                    contract_id: budget_profile_id,
                    version: budget_profile_version,
                    sha256: budget_profile_sha256,
                },
                json,
            )
            .await
        }
    }
}

async fn task_get(task_id: String, json: bool) -> Result<(), CliFailure> {
    let attached = attach("task.get").await?;
    attached.require_rpc("LocalReadModelService/GetTaskView", "task.get")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .get_task_view(GetTaskViewRequest {
            client: Some(metadata),
            task_id,
            minimum_position: None,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.get")
        })?
        .into_inner();
    let view = match response.outcome {
        Some(get_task_view_response::Outcome::View(view)) => view,
        Some(get_task_view_response::Outcome::Error(error)) => {
            return Err(CliFailure::from_local_api_error(error).for_operation("task.get"));
        }
        None => {
            return Err(CliFailure::protocol("task view outcome missing").for_operation("task.get"));
        }
    };
    render_task_view("task.get", &view, json);
    Ok(())
}

async fn task_list(page_size: u32, cursor: Option<String>, json: bool) -> Result<(), CliFailure> {
    if page_size == 0 {
        return Err(
            CliFailure::protocol("page_size must be greater than zero").for_operation("task.list")
        );
    }
    let attached = attach("task.list").await?;
    attached.require_rpc("LocalReadModelService/ListTaskViews", "task.list")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .list_task_views(ListTaskViewsRequest {
            client: Some(metadata),
            status_filter: Vec::new(),
            page_size: page_size.min(1000),
            page_cursor: cursor,
            minimum_position: None,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.list")
        })?
        .into_inner();
    if let Some(error) = response.error {
        return Err(CliFailure::from_local_api_error(error).for_operation("task.list"));
    }
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.list",
        "data": {
            "views": response.views.iter().map(task_summary).collect::<Vec<_>>(),
            "nextPageCursor": response.next_page_cursor,
        },
        "projection": projection_position_json(response.snapshot_position.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!("Tasks: {}", response.views.len());
        for view in &response.views {
            let summary = task_summary(view);
            println!(
                "- {} [{}] revision={}",
                summary["taskId"].as_str().unwrap_or(""),
                summary["status"].as_str().unwrap_or(""),
                summary["revision"].as_u64().unwrap_or_default()
            );
        }
        if let Some(cursor) = response.next_page_cursor {
            println!("Next cursor: {cursor}");
        }
    }
    Ok(())
}

async fn task_watch(
    frames: u32,
    resume_epoch: Option<String>,
    resume_sequence: Option<u64>,
    json: bool,
) -> Result<(), CliFailure> {
    if frames == 0 {
        return Err(
            CliFailure::protocol("frames must be greater than zero").for_operation("task.watch")
        );
    }
    if resume_epoch.is_some() != resume_sequence.is_some() {
        return Err(CliFailure::protocol(
            "resume_epoch and resume_sequence must be supplied together",
        )
        .for_operation("task.watch"));
    }
    let attached = attach("task.watch").await?;
    attached.require_rpc("LocalReadModelService/WatchTaskViews", "task.watch")?;
    let resume_after = resume_epoch.map(|epoch| {
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition {
            epoch,
            sequence: resume_sequence.expect("validated resume sequence"),
            projected_at: None,
        }
    });
    let metadata = attached.metadata(None)?;
    let mut stream = attached
        .connection
        .read_model_service()
        .watch_task_views(WatchTaskViewsRequest {
            client: Some(metadata),
            resume_after,
            task_ids: Vec::new(),
            status_filter: Vec::new(),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.watch")
        })?
        .into_inner();
    let mut tracker = SnapshotStreamTracker::default();
    let mut emitted = 0_u32;
    while let Some(frame) = stream.message().await.map_err(|error| {
        CliFailure::daemon_unavailable(error.to_string()).for_operation("task.watch")
    })? {
        let applied = tracker
            .apply_task_frame(&frame)
            .map_err(|error| CliFailure::stream_recovery("task.watch", error.to_string()))?;
        if applied == StreamApply::ResetRequired {
            return Err(CliFailure::stream_recovery(
                "task.watch",
                frame
                    .reset_reason_code
                    .as_deref()
                    .unwrap_or("stream reset required"),
            ));
        }
        let payload = task_stream_frame_json(&frame, applied);
        if json {
            println!("{}", serde_json::to_string(&payload).unwrap());
        } else {
            println!(
                "Task watch: kind={} apply={} position={}",
                payload["data"]["kind"].as_str().unwrap_or("unknown"),
                payload["data"]["apply"].as_str().unwrap_or("unknown"),
                payload["projection"]["position"]
            );
        }
        emitted += 1;
        if emitted >= frames.min(1000) {
            break;
        }
    }
    if emitted == 0 {
        return Err(CliFailure::stream_recovery(
            "task.watch",
            "stream ended without frames",
        ));
    }
    Ok(())
}

fn task_stream_frame_json(frame: &TaskViewStreamFrame, applied: StreamApply) -> serde_json::Value {
    let kind = egopulse_domain_contracts::v01::egopulse::localapi::v1::StreamFrameKind::try_from(
        frame.kind,
    )
    .map(|value| value.as_str_name())
    .unwrap_or("STREAM_FRAME_KIND_UNKNOWN");
    let apply = match applied {
        StreamApply::Applied => "applied",
        StreamApply::Replay => "replay",
        StreamApply::Heartbeat => "heartbeat",
        StreamApply::ResetRequired => "reset_required",
    };
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.watch",
        "data": {
            "kind": kind,
            "apply": apply,
            "view": frame.snapshot.as_ref().map(task_summary),
            "resetReasonCode": frame.reset_reason_code,
        },
        "projection": projection_position_json(frame.position.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
    })
}

async fn evidence(command: EvidenceCommand) -> Result<(), CliFailure> {
    match command {
        EvidenceCommand::Get {
            task_id,
            artifact_set_id,
            json,
        } => evidence_get(task_id, artifact_set_id, json).await,
    }
}

async fn evidence_get(
    task_id: String,
    artifact_set_id: String,
    json: bool,
) -> Result<(), CliFailure> {
    let attached = attach("evidence.get").await?;
    attached.require_rpc("LocalReadModelService/GetEvidenceGraph", "evidence.get")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .get_evidence_graph(GetEvidenceGraphRequest {
            client: Some(metadata),
            task_id,
            artifact_set_id,
            minimum_position: None,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("evidence.get")
        })?
        .into_inner();
    let graph = match response.outcome {
        Some(get_evidence_graph_response::Outcome::Graph(graph)) => graph,
        Some(get_evidence_graph_response::Outcome::Error(error)) => {
            return Err(CliFailure::from_local_api_error(error).for_operation("evidence.get"));
        }
        None => {
            return Err(CliFailure::protocol("evidence graph outcome missing")
                .for_operation("evidence.get"));
        }
    };
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "evidence.get",
        "data": {
            "taskId": graph.task_id,
            "artifactSetId": graph.artifact_set_id,
            "artifactCount": graph.artifacts.len(),
            "claimCount": graph.claims.len(),
            "evidenceCount": graph.evidence.len(),
            "redactions": graph.redactions.iter().map(|item| json!({"fieldPath": item.field_path, "reasonCode": item.reason_code})).collect::<Vec<_>>(),
        },
        "projection": projection_json(graph.metadata.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Evidence Graph: task={} artifact_set={} artifacts={} claims={} evidence={}",
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
    Ok(())
}

async fn approval(command: ApprovalCommand) -> Result<(), CliFailure> {
    match command {
        ApprovalCommand::Get {
            approval_request_id,
            json,
        } => approval_get(approval_request_id, json).await,
        ApprovalCommand::List {
            page_size,
            cursor,
            actionable_only,
            json,
        } => approval_list(page_size, cursor, actionable_only, json).await,
        ApprovalCommand::Watch {
            frames,
            resume_epoch,
            resume_sequence,
            json,
        } => approval_watch(frames, resume_epoch, resume_sequence, json).await,
        ApprovalCommand::Decide {
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
            approval_decide(
                approval_request_id,
                expected_action_digest_sha256,
                expected_request_observation_id,
                expected_request_observation_sequence,
                expected_request_revision,
                decision,
                reason_code,
                confirmation_proof_ref,
                json,
            )
            .await
        }
    }
}

async fn approval_get(approval_request_id: String, json: bool) -> Result<(), CliFailure> {
    let attached = attach("approval.get").await?;
    attached.require_rpc(
        "LocalReadModelService/GetHarnessApprovalView",
        "approval.get",
    )?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .get_harness_approval_view(GetHarnessApprovalViewRequest {
            client: Some(metadata),
            approval_request_id,
            minimum_position: None,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("approval.get")
        })?
        .into_inner();
    let view = match response.outcome {
        Some(get_harness_approval_view_response::Outcome::View(view)) => view,
        Some(get_harness_approval_view_response::Outcome::Error(error)) => {
            return Err(CliFailure::from_local_api_error(error).for_operation("approval.get"));
        }
        None => {
            return Err(
                CliFailure::protocol("approval view outcome missing").for_operation("approval.get")
            );
        }
    };
    let payload = approval_json(&view, "approval.get");
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Approval: {} task={} lifecycle={} revision={}",
            payload["data"]["approvalRequestId"].as_str().unwrap_or(""),
            payload["data"]["taskId"].as_str().unwrap_or(""),
            payload["data"]["requestRevision"]
                .as_u64()
                .unwrap_or_default(),
            payload["data"]["requestLifecycle"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}

async fn approval_list(
    page_size: u32,
    cursor: Option<String>,
    actionable_only: bool,
    json: bool,
) -> Result<(), CliFailure> {
    if page_size == 0 {
        return Err(CliFailure::protocol("page_size must be greater than zero")
            .for_operation("approval.list"));
    }
    let attached = attach("approval.list").await?;
    attached.require_rpc(
        "LocalReadModelService/ListHarnessApprovalViews",
        "approval.list",
    )?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .connection
        .read_model_service()
        .list_harness_approval_views(ListHarnessApprovalViewsRequest {
            client: Some(metadata),
            request_lifecycle_filter: Vec::new(),
            decision_state_filter: Vec::new(),
            task_ids: Vec::new(),
            actionable_only,
            page_size: page_size.min(1000),
            page_cursor: cursor,
            minimum_position: None,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("approval.list")
        })?
        .into_inner();
    if let Some(error) = response.error {
        return Err(CliFailure::from_local_api_error(error).for_operation("approval.list"));
    }
    let views = response
        .views
        .iter()
        .map(|view| approval_json(view, "approval.list")["data"].clone())
        .collect::<Vec<_>>();
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "approval.list",
        "data": { "views": views, "nextPageCursor": response.next_page_cursor },
        "projection": projection_position_json(response.snapshot_position.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Approvals: {}",
            payload["data"]["views"].as_array().map_or(0, Vec::len)
        );
    }
    Ok(())
}

async fn approval_watch(
    frames: u32,
    resume_epoch: Option<String>,
    resume_sequence: Option<u64>,
    json: bool,
) -> Result<(), CliFailure> {
    if frames == 0 {
        return Err(CliFailure::protocol("frames must be greater than zero")
            .for_operation("approval.watch"));
    }
    if resume_epoch.is_some() != resume_sequence.is_some() {
        return Err(CliFailure::protocol(
            "resume_epoch and resume_sequence must be supplied together",
        )
        .for_operation("approval.watch"));
    }
    let attached = attach("approval.watch").await?;
    attached.require_rpc(
        "LocalReadModelService/WatchHarnessApprovalViews",
        "approval.watch",
    )?;
    let resume_after = resume_epoch.map(|epoch| {
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition {
            epoch,
            sequence: resume_sequence.expect("validated resume sequence"),
            projected_at: None,
        }
    });
    let metadata = attached.metadata(None)?;
    let mut stream = attached
        .connection
        .read_model_service()
        .watch_harness_approval_views(WatchHarnessApprovalViewsRequest {
            client: Some(metadata),
            resume_after,
            approval_request_ids: Vec::new(),
            task_ids: Vec::new(),
            request_lifecycle_filter: Vec::new(),
            decision_state_filter: Vec::new(),
            actionable_only: false,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("approval.watch")
        })?
        .into_inner();
    let mut tracker = SnapshotStreamTracker::default();
    let mut emitted = 0_u32;
    while let Some(frame) = stream.message().await.map_err(|error| {
        CliFailure::daemon_unavailable(error.to_string()).for_operation("approval.watch")
    })? {
        let applied = tracker
            .apply_harness_approval_frame(&frame)
            .map_err(|error| CliFailure::stream_recovery("approval.watch", error.to_string()))?;
        if applied == StreamApply::ResetRequired {
            return Err(CliFailure::stream_recovery(
                "approval.watch",
                frame
                    .reset_reason_code
                    .as_deref()
                    .unwrap_or("stream reset required"),
            ));
        }
        let payload = approval_stream_frame_json(&frame, applied);
        if json {
            println!("{}", serde_json::to_string(&payload).unwrap());
        } else {
            println!(
                "Approval watch: kind={} apply={} position={}",
                payload["data"]["kind"].as_str().unwrap_or("unknown"),
                payload["data"]["apply"].as_str().unwrap_or("unknown"),
                payload["projection"]["position"]
            );
        }
        emitted += 1;
        if emitted >= frames.min(1000) {
            break;
        }
    }
    if emitted == 0 {
        return Err(CliFailure::stream_recovery(
            "approval.watch",
            "stream ended without frames",
        ));
    }
    Ok(())
}

fn approval_stream_frame_json(
    frame: &HarnessApprovalViewStreamFrame,
    applied: StreamApply,
) -> serde_json::Value {
    let kind = egopulse_domain_contracts::v01::egopulse::localapi::v1::StreamFrameKind::try_from(
        frame.kind,
    )
    .map(|value| value.as_str_name())
    .unwrap_or("STREAM_FRAME_KIND_UNKNOWN");
    let apply = match applied {
        StreamApply::Applied => "applied",
        StreamApply::Replay => "replay",
        StreamApply::Heartbeat => "heartbeat",
        StreamApply::ResetRequired => "reset_required",
    };
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "approval.watch",
        "data": {
            "kind": kind,
            "apply": apply,
            "view": frame.snapshot.as_ref().map(|view| approval_json(view, "approval.watch")["data"].clone()),
            "resetReasonCode": frame.reset_reason_code,
        },
        "projection": projection_position_json(frame.position.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn approval_decide(
    approval_request_id: String,
    expected_action_digest_sha256: String,
    expected_request_observation_id: String,
    expected_request_observation_sequence: u64,
    expected_request_revision: u64,
    decision: String,
    reason_code: String,
    confirmation_proof_ref: Option<String>,
    json: bool,
) -> Result<(), CliFailure> {
    let decision = parse_approval_decision(&decision)
        .map_err(|message| CliFailure::protocol(message).for_operation("approval.decide"))?;
    let attached = attach("approval.decide").await?;
    attached.require_command(
        "LocalCommandGatewayService/DecideHarnessApproval",
        "issue_harness_approval_decision",
        "approval.decide",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(command_metadata(
                        &correlation_id,
                        "egopulse-cli/approval-decide",
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
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    let response = attached
        .connection
        .command_gateway_service()
        .decide_harness_approval(DecideHarnessApprovalRequest {
            client: Some(metadata),
            command: Some(match command.command {
                Some(policy_decision_command::Command::IssueHarnessApprovalDecision(command)) => {
                    command
                }
                _ => unreachable!("CLI always constructs issue approval decision"),
            }),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("approval.decide")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("approval.decide"));
    }
    let result = response.sanitized_authority_result.ok_or_else(|| {
        CliFailure::protocol("sanitized approval result missing").for_operation("approval.decide")
    })?;
    if result.error_code != 0 {
        return Err(CliFailure::policy_authority(
            result.error_code,
            result.safe_error_fingerprint,
            "approval.decide",
        ));
    }
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "approval.decide",
        "data": {
            "committed": result.committed,
            "replayed": result.replayed,
            "authorityDecisionRef": result.authority_decision_ref,
            "decision": ApprovalDecision::try_from(result.decision).map(|value| value.as_str_name()).unwrap_or("APPROVAL_DECISION_UNSPECIFIED"),
            "stateRevision": result.state_revision,
            "awaitToken": await_token_json(response.await_token),
        },
        "correlationId": correlation_id,
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Approval decision: ref={} committed={} replayed={} revision={}",
            payload["data"]["authorityDecisionRef"]
                .as_str()
                .unwrap_or(""),
            payload["data"]["committed"].as_bool().unwrap_or(false),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
            payload["data"]["stateRevision"]
                .as_u64()
                .unwrap_or_default(),
        );
    }
    Ok(())
}

async fn verdict(command: VerdictCommandCli) -> Result<(), CliFailure> {
    match command {
        VerdictCommandCli::Issue {
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
            verdict_issue(
                task_id,
                task_revision,
                work_revision,
                artifact_set_id,
                verification_artifact_id,
                ContentAddress {
                    algorithm: HashAlgorithm::Sha256 as i32,
                    digest: artifact_set_manifest_sha256,
                    byte_length: artifact_set_manifest_byte_length,
                },
                ContentAddress {
                    algorithm: HashAlgorithm::Sha256 as i32,
                    digest: verification_payload_sha256,
                    byte_length: verification_payload_byte_length,
                },
                ContractReference {
                    contract_id: acceptance_contract_id,
                    version: acceptance_contract_version,
                    sha256: acceptance_contract_sha256,
                },
                decision,
                observed_verification_conclusion,
                reason_code,
                confirmation_class,
                confirmation_proof_ref,
                json,
            )
            .await
        }
        VerdictCommandCli::Revoke {
            founder_verdict_id,
            expected_state_revision,
            reason_code,
            confirmation_proof_ref,
            json,
        } => {
            verdict_revoke(
                founder_verdict_id,
                expected_state_revision,
                reason_code,
                confirmation_proof_ref,
                json,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn verdict_issue(
    task_id: String,
    task_revision: u64,
    work_revision: u64,
    artifact_set_id: String,
    verification_artifact_id: String,
    artifact_set_manifest: ContentAddress,
    verification_payload: ContentAddress,
    acceptance_contract_ref: ContractReference,
    decision: String,
    observed_verification_conclusion: String,
    reason_code: String,
    confirmation_class: String,
    confirmation_proof_ref: String,
    json: bool,
) -> Result<(), CliFailure> {
    let decision = parse_verdict_decision(&decision)
        .map_err(|message| CliFailure::protocol(message).for_operation("verdict.issue"))?;
    let conclusion = parse_verification_conclusion(&observed_verification_conclusion)
        .map_err(|message| CliFailure::protocol(message).for_operation("verdict.issue"))?;
    let confirmation_class = parse_confirmation_class(&confirmation_class)
        .map_err(|message| CliFailure::protocol(message).for_operation("verdict.issue"))?;
    let attached = attach("verdict.issue").await?;
    attached.require_command(
        "LocalCommandGatewayService/ExecuteFounderVerdict",
        "issue_founder_verdict",
        "verdict.issue",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(command_metadata(
                    &correlation_id,
                    "egopulse-cli/verdict-issue",
                )),
                scope: Some(VerdictScope {
                    task_id,
                    task_revision,
                    work_revision,
                    artifact_set_id,
                    artifact_set_manifest: Some(artifact_set_manifest),
                    verification_artifact_id,
                    verification_payload: Some(verification_payload),
                    acceptance_contract_ref: Some(acceptance_contract_ref),
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
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    let response = attached
        .connection
        .command_gateway_service()
        .execute_founder_verdict(ExecuteFounderVerdictRequest {
            client: Some(metadata),
            command: Some(command),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("verdict.issue")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("verdict.issue"));
    }
    let result = response.authority_result.ok_or_else(|| {
        CliFailure::protocol("Founder Verdict authority result missing")
            .for_operation("verdict.issue")
    })?;
    if result.error_code != 0 {
        return Err(CliFailure::verdict_authority(
            result.error_code,
            result.safe_error_fingerprint,
            "verdict.issue",
        ));
    }
    let verdict_id = result
        .verdict
        .as_ref()
        .map(|verdict| verdict.founder_verdict_id.clone());
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
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
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Founder Verdict issued: id={} committed={} replayed={}",
            payload["data"]["founderVerdictId"].as_str().unwrap_or(""),
            payload["data"]["committed"].as_bool().unwrap_or(false),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
}

async fn verdict_revoke(
    founder_verdict_id: String,
    expected_state_revision: u64,
    reason_code: String,
    confirmation_proof_ref: String,
    json: bool,
) -> Result<(), CliFailure> {
    let attached = attach("verdict.revoke").await?;
    attached.require_command(
        "LocalCommandGatewayService/ExecuteFounderVerdict",
        "revoke_founder_verdict",
        "verdict.revoke",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::RevokeFounderVerdict(
            RevokeFounderVerdictCommand {
                metadata: Some(command_metadata(
                    &correlation_id,
                    "egopulse-cli/verdict-revoke",
                )),
                founder_verdict_id,
                expected_state_revision,
                reason_code,
                confirmation_proof_ref,
            },
        )),
    };
    set_verdict_digest(&mut command);
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    let response = attached
        .connection
        .command_gateway_service()
        .execute_founder_verdict(ExecuteFounderVerdictRequest {
            client: Some(metadata),
            command: Some(command),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("verdict.revoke")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("verdict.revoke"));
    }
    let result = response.authority_result.ok_or_else(|| {
        CliFailure::protocol("Founder Verdict authority result missing")
            .for_operation("verdict.revoke")
    })?;
    if result.error_code != 0 {
        return Err(CliFailure::verdict_authority(
            result.error_code,
            result.safe_error_fingerprint,
            "verdict.revoke",
        ));
    }
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
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
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Founder Verdict revoked: id={} committed={} replayed={}",
            payload["data"]["founderVerdictId"].as_str().unwrap_or(""),
            payload["data"]["committed"].as_bool().unwrap_or(false),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
}

async fn task_create(
    work_type: String,
    input_snapshot_id: String,
    target_scope_ref: String,
    acceptance_contract_ref: ContractReference,
    budget_profile_ref: ContractReference,
    json: bool,
) -> Result<(), CliFailure> {
    let attached = attach("task.create").await?;
    attached.require_command(
        "LocalCommandGatewayService/ExecuteTaskCommand",
        "create_task",
        "task.create",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(CommandMetadata {
                command_id: Uuid::now_v7().to_string(),
                idempotency_key: Uuid::now_v7().to_string(),
                idempotency_scope: "egopulse-cli/task-create".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(now_timestamp()),
                correlation_id: correlation_id.clone(),
                causation_id: None,
            }),
            work_type,
            input_snapshot_id,
            target_scope_ref,
            acceptance_contract_ref: Some(acceptance_contract_ref),
            budget_profile_ref: Some(budget_profile_ref),
        })),
    };
    let digest = canonical_task_digest(&command);
    if let Some(task_command::Command::CreateTask(create)) = command.command.as_mut() {
        create
            .meta
            .as_mut()
            .expect("CLI always supplies command metadata")
            .request_digest_sha256 = digest;
    }
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    let response = attached
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(metadata),
            command: Some(command),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.create")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("task.create"));
    }
    let result = response.authority_result.ok_or_else(|| {
        CliFailure::protocol("task authority result missing").for_operation("task.create")
    })?;
    let replayed = result.replayed;
    let task = match result.outcome {
        Some(task_command_result::Outcome::Task(task)) => task,
        Some(task_command_result::Outcome::Error(error)) => {
            return Err(CliFailure::task_authority(
                error.code,
                error.safe_detail_code,
                "task.create",
            ));
        }
        None => {
            return Err(
                CliFailure::protocol("task authority outcome missing").for_operation("task.create")
            );
        }
    };
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.create",
        "data": {
            "taskId": task.task_id,
            "revision": task.revision,
            "status": TaskStatus::try_from(task.status).map(|status| status.as_str_name()).unwrap_or("TASK_STATUS_UNSPECIFIED"),
            "replayed": replayed,
            "awaitToken": await_token_json(response.await_token),
        },
        "correlationId": correlation_id,
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Task created: {} revision={} status={} replayed={}",
            payload["data"]["taskId"].as_str().unwrap_or(""),
            payload["data"]["revision"].as_u64().unwrap_or_default(),
            payload["data"]["status"].as_str().unwrap_or(""),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
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
            .expect("CLI always supplies policy command metadata")
            .request_digest_sha256 = digest;
    }
}

fn set_verdict_digest(command: &mut VerdictCommand) {
    let mut canonical = command.clone();
    match canonical.command.as_mut() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => {
            clear_command_metadata(issue.metadata.as_mut());
        }
        Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
            clear_command_metadata(revoke.metadata.as_mut());
        }
        _ => {}
    }
    let digest = hex::encode(Sha256::digest(canonical.encode_to_vec()));
    match command.command.as_mut() {
        Some(verdict_command::Command::IssueFounderVerdict(issue)) => {
            issue
                .metadata
                .as_mut()
                .expect("CLI always supplies verdict command metadata")
                .request_digest_sha256 = digest;
        }
        Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
            revoke
                .metadata
                .as_mut()
                .expect("CLI always supplies verdict command metadata")
                .request_digest_sha256 = digest;
        }
        _ => {}
    }
}

fn clear_command_metadata(metadata: Option<&mut CommandMetadata>) {
    if let Some(metadata) = metadata {
        metadata.command_id.clear();
        metadata.request_digest_sha256.clear();
        metadata.issued_at = None;
        metadata.correlation_id.clear();
        metadata.causation_id = None;
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

fn timestamp_after(duration: Duration) -> prost_types::Timestamp {
    let now = now_timestamp();
    prost_types::Timestamp {
        seconds: now.seconds + duration.as_secs() as i64,
        nanos: now.nanos,
    }
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

fn projection_json(metadata: Option<&ProjectionMetadata>) -> serde_json::Value {
    let Some(metadata) = metadata else {
        return serde_json::Value::Null;
    };
    let position = metadata.position.as_ref();
    json!({
        "health": ProjectionHealth::try_from(metadata.health).map(|health| health.as_str_name()).unwrap_or("PROJECTION_HEALTH_UNSPECIFIED"),
        "stale": metadata.stale,
        "position": position.map(|position| json!({"epoch": position.epoch, "sequence": position.sequence})),
    })
}

fn projection_position_json(
    position: Option<&egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition>,
) -> serde_json::Value {
    position.map_or(serde_json::Value::Null, |position| {
        json!({ "position": { "epoch": position.epoch, "sequence": position.sequence } })
    })
}

fn task_summary(view: &TaskView) -> serde_json::Value {
    let task = view.task.as_ref();
    json!({
        "taskId": task.map(|task| task.task_id.clone()),
        "revision": task.map_or(0, |task| task.revision),
        "status": task.and_then(|task| TaskStatus::try_from(task.status).ok()).map(|status| status.as_str_name()),
        "projection": projection_json(view.metadata.as_ref()),
    })
}

fn render_task_view(operation: &'static str, view: &TaskView, json_output: bool) {
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": operation,
        "data": task_summary(view),
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json_output {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Task: {} revision={} status={}",
            payload["data"]["taskId"].as_str().unwrap_or(""),
            payload["data"]["revision"].as_u64().unwrap_or_default(),
            payload["data"]["status"].as_str().unwrap_or(""),
        );
    }
}

fn approval_json(
    view: &egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessApprovalView,
    operation: &'static str,
) -> serde_json::Value {
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": operation,
        "data": {
            "approvalRequestId": view.approval_request_id,
            "taskId": view.task_id,
            "runId": view.run_id,
            "stepId": view.step_id,
            "requestLifecycle": view.request_lifecycle,
            "requestRevision": view.request_revision,
            "actionDigestSha256": view.action_digest_sha256,
            "redactions": view.redactions.iter().map(|item| json!({"fieldPath": item.field_path, "reasonCode": item.reason_code})).collect::<Vec<_>>(),
        },
        "projection": projection_json(view.metadata.as_ref()),
        "correlationId": Uuid::now_v7().to_string(),
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

fn parse_await_token(input: &str) -> Result<ProjectionAwaitToken, String> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|error| format!("token_json must be a write result awaitToken object: {error}"))?;
    let token = value
        .get("token")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "awaitToken.token is required".to_owned())?
        .to_owned();
    let source = value
        .get("requiredSourceRevision")
        .ok_or_else(|| "awaitToken.requiredSourceRevision is required".to_owned())?;
    let domain = source
        .get("domain")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "awaitToken.requiredSourceRevision.domain is required".to_owned())?;
    let aggregate_id = source
        .get("aggregateId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "awaitToken.requiredSourceRevision.aggregateId is required".to_owned())?;
    let revision = source
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "awaitToken.requiredSourceRevision.revision is required".to_owned())?;
    let last_event_id = source
        .get("lastEventId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "awaitToken.requiredSourceRevision.lastEventId is required".to_owned())?;
    let expires_at = value
        .get("expiresAt")
        .ok_or_else(|| "awaitToken.expiresAt is required".to_owned())?;
    let seconds = expires_at
        .get("seconds")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "awaitToken.expiresAt.seconds is required".to_owned())?;
    let nanos = expires_at
        .get("nanos")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| "awaitToken.expiresAt.nanos is required".to_owned())?;
    let nanos =
        i32::try_from(nanos).map_err(|_| "awaitToken.expiresAt.nanos is invalid".to_owned())?;
    let domain = i32::try_from(domain)
        .map_err(|_| "awaitToken.requiredSourceRevision.domain is invalid".to_owned())?;
    Ok(ProjectionAwaitToken {
        token,
        required_source_revision: Some(SourceRevision {
            domain,
            aggregate_id: aggregate_id.to_owned(),
            revision,
            last_event_id: last_event_id.to_owned(),
        }),
        expires_at: Some(prost_types::Timestamp { seconds, nanos }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_and_json_share_the_same_projection_facts() {
        let view = ProjectionStatusView {
            health: "PROJECTION_HEALTH_READY".to_owned(),
            stale: false,
            epoch: "epoch-test".to_owned(),
            sequence: 7,
        };
        let json = view.json();
        assert_eq!(json["schemaVersion"], "egopulse.cli-result/v0.1");
        assert_eq!(json["ok"], true);
        assert_eq!(json["operation"], "status");
        assert_eq!(json["projection"]["health"], "PROJECTION_HEALTH_READY");
        assert_eq!(json["projection"]["position"]["epoch"], "epoch-test");
        assert_eq!(json["projection"]["position"]["sequence"], 7);
        let text = view.text();
        assert!(text.contains("Projection: PROJECTION_HEALTH_READY"));
        assert!(text.contains("Position: epoch-test:7"));
        assert!(text.contains("Stale: false"));
    }

    #[test]
    fn json_error_envelope_does_not_include_transport_diagnostics() {
        let error = CliFailure::daemon_unavailable("private pipe path");
        let json = error.json_envelope();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["code"], "DAEMON_UNAVAILABLE");
        assert_eq!(json["error"]["requiredActionCode"], "attach_to_daemon");
        assert!(
            serde_json::to_string(&json)
                .unwrap()
                .contains("attach_to_daemon")
        );
        assert!(
            !serde_json::to_string(&json)
                .unwrap()
                .contains("private pipe path")
        );
    }
}
