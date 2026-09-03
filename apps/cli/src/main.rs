#![forbid(unsafe_code)]
// The CLI keeps a structured, owned failure envelope so every surface can
// render the same stable error facts. Its size is intentional at this
// boundary; the process is short-lived and does not cross the kernel ABI.
#![allow(clippy::result_large_err)]

use std::{
    future::Future,
    io::{self, IsTerminal, Write},
    pin::Pin,
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, Subcommand};
use egopulse_client_kernel::KernelError;
use egopulse_client_operations::{
    ApprovalWatch, ApprovalWatchClassification, ApprovalWatchCursor, ApprovalWatchUpdate,
    AttachError, ClientApprovalWatchError, ClientAttachment, ClientContextRevokeError,
    ClientTaskWatchError, ClientWorkError, ContextRevokeInput, TaskWatch, TaskWatchClassification,
    TaskWatchRequest, TaskWatchUpdate, attach as attach_client, command_metadata,
    set_policy_digest, set_task_digest, set_verdict_digest, timestamp_after,
};
use egopulse_director_facade::{
    ContextAuthority, ContextSourceInput, DirectorInput, build_event_packet_preview,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    collaboration::v1::{RunStatus, StepStatus},
    common::v1::ContractReference,
    harness::v1::ApprovalDecision,
    localapi::v1::{
        AwaitProjectionRequest, ClientSurface, ContextGovernanceState,
        DecideHarnessApprovalRequest, ExecuteFounderVerdictRequest, ExecuteMemoryMutationRequest,
        ExecuteTaskCommandRequest, GetEvidenceGraphRequest, GetHarnessApprovalViewRequest,
        GetProjectionStatusRequest, GetTaskViewRequest, ListHarnessApprovalViewsRequest,
        ListTaskViewsRequest, LocalApiError, LocalApiErrorCode, MemoryMutationCommand,
        MemoryMutationReceipt, ProjectionAwaitToken, ProjectionHealth, ProjectionMetadata,
        RetrieveMemoryRequest, SourceRevision, TaskView, await_projection_response,
        get_evidence_graph_response, get_harness_approval_view_response, get_task_view_response,
        memory_mutation_command, retrieve_memory_response,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, PolicyDecisionErrorCode,
        policy_decision_command,
    },
    task::v1::{
        ApplyFounderVerdictCommand, CreateTaskCommand, RequestTaskCancellationCommand, TaskCommand,
        TaskErrorCode, TaskStatus, task_command, task_command_result,
    },
    verdict::v1::{
        FounderVerdictDecision, IssueFounderVerdictCommand, RevokeFounderVerdictCommand,
        VerdictCommand, VerdictErrorCode, VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use serde_json::json;
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
    /// Retrieve references from one authorized accepted Memory scope.
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    /// Build a governed work preview without creating or dispatching a Task.
    Work {
        #[command(subcommand)]
        command: WorkCommand,
    },
    /// Inspect or revoke one governed Context snapshot.
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ContextCommand {
    /// Founder-revoke one Context snapshot after reviewing its full semantic digest.
    Revoke {
        snapshot_id: String,
        #[arg(long)]
        expected_state_revision: u64,
        #[arg(long)]
        reason_code: String,
        /// Ordered evidence references. Repeat the flag to preserve evidence order.
        #[arg(long = "evidence-ref", required = true)]
        evidence_refs: Vec<String>,
        #[arg(long)]
        confirmation_proof_ref: String,
        #[arg(long)]
        idempotency_key: String,
        /// Print the safe confirmation facts and full digest without issuing a mutation RPC.
        #[arg(long, conflicts_with = "confirm_digest")]
        preview: bool,
        /// Exact 64-character lowercase digest printed by preview or the interactive prompt.
        #[arg(long = "confirm-digest")]
        confirm_digest: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum WorkCommand {
    /// Normalize Founder intent and show the context/gate/event-packet preview.
    Plan {
        /// Natural-language work intent from the Founder.
        #[arg(long)]
        intent: String,
        /// Explicit project or workspace scope.
        #[arg(long)]
        scope: String,
        /// Product work classification used by the preparation gate.
        #[arg(long)]
        work_type: String,
        /// Explicit source references to include in the exact-context preview.
        #[arg(long = "context-ref")]
        context_refs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Ask the daemon-owned Context Authority to compile a real preview.
    Prepare {
        #[arg(long)]
        intent: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        work_type: String,
        #[arg(long = "context-ref")]
        context_refs: Vec<String>,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
    },
    /// Confirm the exact binding shown by `work prepare`.
    Confirm {
        snapshot_id: String,
        #[arg(long)]
        confirmation_binding_sha256: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    /// Run bounded read-only retrieval; this never writes or governs Memory.
    Retrieve {
        #[arg(long)]
        query: String,
        #[arg(long)]
        scope: String,
        #[arg(long, default_value_t = 8)]
        max_results: u32,
        #[arg(long, default_value_t = 0.0)]
        min_score: f64,
        #[arg(long)]
        json: bool,
    },
    /// Submit a candidate; the record remains non-authoritative until accepted.
    Candidate {
        #[arg(long)]
        memory_id: String,
        #[arg(long)]
        content: String,
        #[arg(long)]
        source_ref: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
    },
    /// Founder-govern an existing candidate into accepted state.
    Accept {
        memory_id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        evidence_ref: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
    },
    /// Founder-govern a memory into terminal revoked state.
    Revoke {
        memory_id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        evidence_ref: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
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
    /// Apply an issued Founder Verdict to a VerdictPending Task.
    ApplyVerdict {
        task_id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        work_revision: u64,
        founder_verdict_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Request cancellation of a user-owned Task through the Task Authority.
    Cancel {
        task_id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        reason_code: String,
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
            Some(
                LocalApiErrorCode::AuthorityUnavailable
                | LocalApiErrorCode::CognitionWorkerUnavailable
                | LocalApiErrorCode::DeadlineExceeded
                | LocalApiErrorCode::ResourceExhausted,
            ) => (3, "unavailable"),
            Some(LocalApiErrorCode::InvalidArgument) => (2, "invalid_request"),
            Some(
                LocalApiErrorCode::NotFound
                | LocalApiErrorCode::OwnerMismatch
                | LocalApiErrorCode::ContextRevoked
                | LocalApiErrorCode::StateRevisionConflict
                | LocalApiErrorCode::IdempotencyConflict,
            ) => (6, "domain_conflict"),
            Some(
                LocalApiErrorCode::IntegrityFailure | LocalApiErrorCode::UnknownCriticalSemantics,
            ) => (8, "recovery"),
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

    fn context_confirmation(message: impl Into<String>) -> Self {
        Self {
            exit_code: 2,
            reason_code: "CONTEXT_CONFIRMATION_REQUIRED",
            message: message.into(),
            category: "invalid_request",
            retryable: false,
            required_action_code: Some("SUPPLY_EXACT_CONTEXT_DIGEST".to_owned()),
            safe_fingerprint: Some("context_confirmation_rejected".to_owned()),
            operation: "context.revoke",
        }
    }

    fn context_session_changed() -> Self {
        Self {
            exit_code: 5,
            reason_code: "CONTEXT_SESSION_CHANGED",
            message: "the authenticated session changed after Context revoke preparation"
                .to_owned(),
            category: "contract",
            retryable: false,
            required_action_code: Some("REPREPARE_CONTEXT_REVOKE".to_owned()),
            safe_fingerprint: Some("context_session_binding_changed".to_owned()),
            operation: "context.revoke",
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
        Command::Memory { command } => memory(command).await,
        Command::Work { command } => work(command).await,
        Command::Context { command } => context(command).await,
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
                | TaskCommandCli::Create { json, .. }
                | TaskCommandCli::ApplyVerdict { json, .. }
                | TaskCommandCli::Cancel { json, .. },
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
        }
        | Command::Memory {
            command:
                MemoryCommand::Retrieve { json, .. }
                | MemoryCommand::Candidate { json, .. }
                | MemoryCommand::Accept { json, .. }
                | MemoryCommand::Revoke { json, .. },
        } => *json,
        Command::Work {
            command:
                WorkCommand::Plan { json, .. }
                | WorkCommand::Prepare { json, .. }
                | WorkCommand::Confirm { json, .. },
        }
        | Command::Context {
            command: ContextCommand::Revoke { json, .. },
        } => *json,
    }
}

struct AttachedClient(ClientAttachment);

impl AttachedClient {
    fn metadata(
        &self,
        correlation_id: Option<String>,
    ) -> Result<
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata,
        CliFailure,
    > {
        self.0
            .metadata(correlation_id)
            .map_err(|error| CliFailure::protocol(error.to_string()))
    }

    fn require_rpc(&self, rpc: &str, operation: &'static str) -> Result<(), CliFailure> {
        self.0
            .require_rpc(rpc)
            .map_err(|error| CliFailure::permission(operation, error.to_string()))
    }

    fn require_command(
        &self,
        rpc: &str,
        oneof: &str,
        operation: &'static str,
    ) -> Result<(), CliFailure> {
        self.0
            .require_command(rpc, oneof)
            .map_err(|error| CliFailure::permission(operation, error.to_string()))
    }
}

async fn attach(operation: &'static str) -> Result<AttachedClient, CliFailure> {
    let result = async {
        let instance =
            std::env::var("EGOPULSE_IPC_INSTANCE").unwrap_or_else(|_| DEFAULT_INSTANCE.to_owned());
        let attached = attach_client(&instance, ClientSurface::Cli, "egopulse-cli")
            .await
            .map_err(|error| match error {
                AttachError::DaemonUnavailable(detail) => CliFailure::daemon_unavailable(detail),
                AttachError::InvalidInstance(detail) => {
                    CliFailure::protocol(format!("invalid IPC instance: {detail}"))
                }
                AttachError::Kernel(error) => {
                    eprintln!("attach debug: kernel error: {error:?}");
                    CliFailure::protocol(error.to_string())
                }
            })?;
        Ok::<_, CliFailure>(AttachedClient(attached))
    }
    .await;
    result.map_err(|mut error| {
        error.operation = operation;
        error
    })
}

async fn context(command: ContextCommand) -> Result<(), CliFailure> {
    match command {
        ContextCommand::Revoke {
            snapshot_id,
            expected_state_revision,
            reason_code,
            evidence_refs,
            confirmation_proof_ref,
            idempotency_key,
            preview,
            confirm_digest,
            json,
        } => {
            context_revoke(
                ContextRevokeInput {
                    snapshot_id,
                    expected_state_revision,
                    reason_code,
                    evidence_refs,
                    confirmation_proof_ref,
                    idempotency_key,
                },
                preview,
                confirm_digest,
                json,
            )
            .await
        }
    }
}

async fn context_revoke(
    input: ContextRevokeInput,
    preview: bool,
    confirm_digest: Option<String>,
    json_output: bool,
) -> Result<(), CliFailure> {
    let interactive_terminal = io::stdin().is_terminal() && io::stdout().is_terminal();
    if !preview && confirm_digest.is_none() && (json_output || !interactive_terminal) {
        return Err(CliFailure::context_confirmation(
            "non-interactive Context revoke requires --confirm-digest; run --preview first",
        ));
    }

    let attached = attach("context.revoke").await?;
    let prepared = attached
        .0
        .prepare_context_revoke(input)
        .map_err(client_context_revoke_failure)?;
    if preview {
        render_context_revoke_preview(&prepared, json_output);
        return Ok(());
    }

    let supplied_digest = if let Some(digest) = confirm_digest {
        digest
    } else {
        eprintln!(
            "Context revoke confirmation\nSnapshot: {}\nExpected state revision: {}\nEvidence references: {}\nFull semantic digest: {}",
            prepared.snapshot_id(),
            prepared.expected_state_revision(),
            prepared.evidence_count(),
            prepared.request_digest_sha256(),
        );
        eprint!("Type the complete digest to confirm, or press Enter to cancel: ");
        io::stderr().flush().map_err(|error| {
            CliFailure::protocol(format!("confirmation prompt failed: {error}"))
                .for_operation("context.revoke")
        })?;
        let mut confirmation = String::new();
        let bytes_read = io::stdin().read_line(&mut confirmation).map_err(|error| {
            CliFailure::protocol(format!("confirmation input failed: {error}"))
                .for_operation("context.revoke")
        })?;
        let confirmation = remove_terminal_line_ending(confirmation);
        if bytes_read == 0 || confirmation.is_empty() {
            return Err(CliFailure::context_confirmation(
                "Context revoke was cancelled before any mutation was sent",
            ));
        }
        confirmation
    };

    let receipt = attached
        .0
        .execute_context_revoke(prepared, &supplied_digest)
        .await
        .map_err(client_context_revoke_failure)?;
    render_context_revoke_receipt(&receipt, json_output);
    Ok(())
}

fn remove_terminal_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn client_context_revoke_failure(error: ClientContextRevokeError) -> CliFailure {
    match error {
        ClientContextRevokeError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("context.revoke")
        }
        ClientContextRevokeError::InvalidConfirmation => CliFailure::context_confirmation(
            "confirmation digest must be the exact 64-character lowercase digest",
        ),
        ClientContextRevokeError::SessionChanged => CliFailure::context_session_changed(),
        ClientContextRevokeError::Transport(detail) => {
            CliFailure::daemon_unavailable(detail).for_operation("context.revoke")
        }
        ClientContextRevokeError::MalformedResponse(detail) => {
            CliFailure::protocol(detail).for_operation("context.revoke")
        }
        ClientContextRevokeError::Kernel(error) => match error {
            KernelError::PermissionDenied(_) | KernelError::SystemOnlyCommand { .. } => {
                CliFailure::permission("context.revoke", error.to_string())
            }
            KernelError::SessionUnavailable | KernelError::SessionExpired => {
                CliFailure::context_session_changed()
            }
            other => CliFailure::protocol(other.to_string()).for_operation("context.revoke"),
        },
    }
}

fn render_context_revoke_preview(
    prepared: &egopulse_client_operations::PreparedContextRevoke,
    json_output: bool,
) {
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "context.revoke.preview",
        "data": {
            "snapshotId": prepared.snapshot_id(),
            "expectedStateRevision": prepared.expected_state_revision(),
            "evidenceCount": prepared.evidence_count(),
            "requestDigestSha256": prepared.request_digest_sha256(),
            "mutationSent": false,
        },
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json_output {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Context revoke preview: snapshot={} expected_state_revision={} evidence_refs={}",
            prepared.snapshot_id(),
            prepared.expected_state_revision(),
            prepared.evidence_count()
        );
        println!(
            "Full confirmation digest: {}",
            prepared.request_digest_sha256()
        );
        println!("No mutation was sent.");
    }
}

fn render_context_revoke_receipt(
    receipt: &egopulse_domain_contracts::v01::egopulse::localapi::v1::ContextRevokeReceipt,
    json_output: bool,
) {
    let previous_state = ContextGovernanceState::try_from(receipt.previous_state)
        .map(|value| value.as_str_name())
        .unwrap_or("CONTEXT_GOVERNANCE_STATE_UNSPECIFIED");
    let result_state = ContextGovernanceState::try_from(receipt.result_state)
        .map(|value| value.as_str_name())
        .unwrap_or("CONTEXT_GOVERNANCE_STATE_UNSPECIFIED");
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "context.revoke",
        "data": {
            "snapshotId": receipt.snapshot_id,
            "snapshotRevision": receipt.snapshot_revision,
            "contentDigestSha256": receipt.content_digest_sha256,
            "previousStateRevision": receipt.previous_state_revision,
            "resultStateRevision": receipt.result_state_revision,
            "previousState": previous_state,
            "resultState": result_state,
            "requestDigestSha256": receipt.request_digest_sha256,
            "eventId": receipt.event_id,
            "committedAt": receipt.committed_at.as_ref().map(timestamp_json),
            "replayed": receipt.replayed,
            "acknowledgedAfterDurabilityBarrier": receipt.acknowledged_after_durability_barrier,
        },
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json_output {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Context revoked: snapshot={} state_revision={} state={} replayed={}",
            receipt.snapshot_id, receipt.result_state_revision, result_state, receipt.replayed
        );
    }
}

async fn work(command: WorkCommand) -> Result<(), CliFailure> {
    match command {
        WorkCommand::Plan {
            intent,
            scope,
            work_type,
            context_refs,
            json,
        } => {
            let input = DirectorInput {
                intent,
                scope_ref: scope,
                work_type,
                context_sources: context_refs
                    .into_iter()
                    .map(|source_ref| ContextSourceInput {
                        label: source_ref.clone(),
                        source_ref,
                        authority: ContextAuthority::Project,
                    })
                    .collect(),
            };
            let preview = build_event_packet_preview(&input).map_err(|error| {
                CliFailure::protocol(error.to_string()).for_operation("work.plan")
            })?;
            let payload = json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "work.plan",
                "data": preview,
                "correlationId": Uuid::now_v7().to_string(),
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                let gate = &payload["data"]["gate_result"];
                let status = if gate["ready"].as_bool().unwrap_or(false) {
                    "READY"
                } else {
                    "BLOCKED"
                };
                println!(
                    "Work preview: gate={} sources={} founder_confirmable={}",
                    status,
                    payload["data"]["context_pack"]["included_sources"]
                        .as_array()
                        .map(Vec::len)
                        .unwrap_or_default(),
                    payload["data"]["ready_for_founder_confirmation"]
                        .as_bool()
                        .unwrap_or(false),
                );
                if let Some(blockers) = gate["blockers"].as_array() {
                    for blocker in blockers {
                        println!(
                            "Blocker {}: {}",
                            blocker["code"].as_str().unwrap_or("UNKNOWN"),
                            blocker["detail"].as_str().unwrap_or(""),
                        );
                    }
                }
                println!("Intent: {}", payload["data"]["work_request"]["intent"]);
                println!("Next: Founder review is required before task creation.");
            }
            Ok(())
        }
        WorkCommand::Prepare {
            intent,
            scope,
            work_type,
            context_refs,
            idempotency_key,
            json,
        } => {
            let attached = attach("work.prepare").await?;
            attached.require_rpc("LocalCommandGatewayService/PrepareWork", "work.prepare")?;
            let preview = attached
                .0
                .prepare_work(
                    intent,
                    work_type,
                    scope,
                    context_refs
                        .into_iter()
                        .map(|value| (value.clone(), value))
                        .collect(),
                    idempotency_key,
                )
                .await
                .map_err(|error| client_work_failure(error, "work.prepare"))?;
            let payload = json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "work.prepare",
                "data": work_preview_json(&preview),
                "correlationId": Uuid::now_v7().to_string(),
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "Work prepared: snapshot={} context_state_revision={} gate_ready={} sources={} expires_at={}",
                    preview.snapshot_id,
                    preview.context_state_revision,
                    preview.gate_ready,
                    preview.included_sources.len(),
                    preview
                        .expires_at
                        .as_ref()
                        .map(|value| value.seconds.to_string())
                        .unwrap_or_else(|| "-".to_owned()),
                );
                println!("Next: review the preview, then run work confirm with its binding.");
            }
            Ok(())
        }
        WorkCommand::Confirm {
            snapshot_id,
            confirmation_binding_sha256,
            idempotency_key,
            json,
        } => {
            let attached = attach("work.confirm").await?;
            attached.require_rpc("LocalCommandGatewayService/ConfirmWork", "work.confirm")?;
            let confirmed = attached
                .0
                .confirm_work(snapshot_id, confirmation_binding_sha256, idempotency_key)
                .await
                .map_err(|error| client_work_failure(error, "work.confirm"))?;
            let replayed = confirmed.result.replayed;
            let task = match confirmed.result.outcome {
                Some(task_command_result::Outcome::Task(task)) => task,
                Some(task_command_result::Outcome::Error(error)) => {
                    return Err(CliFailure::task_authority(
                        error.code,
                        error.safe_detail_code,
                        "work.confirm",
                    ));
                }
                None => {
                    return Err(
                        CliFailure::protocol("confirmed task authority outcome missing")
                            .for_operation("work.confirm"),
                    );
                }
            };
            let payload = json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "work.confirm",
                "data": {
                    "taskId": task.task_id,
                    "revision": task.revision,
                    "status": TaskStatus::try_from(task.status).map(|status| status.as_str_name()).unwrap_or("TASK_STATUS_UNSPECIFIED"),
                    "replayed": replayed,
                    "awaitToken": await_token_json(confirmed.await_token),
                },
                "correlationId": Uuid::now_v7().to_string(),
            });
            if json {
                println!("{}", serde_json::to_string(&payload).unwrap());
            } else {
                println!(
                    "Work confirmed: task={} revision={} status={} replayed={}",
                    payload["data"]["taskId"].as_str().unwrap_or(""),
                    payload["data"]["revision"].as_u64().unwrap_or_default(),
                    payload["data"]["status"].as_str().unwrap_or(""),
                    payload["data"]["replayed"].as_bool().unwrap_or(false),
                );
            }
            Ok(())
        }
    }
}

fn client_work_failure(error: ClientWorkError, operation: &'static str) -> CliFailure {
    match error {
        ClientWorkError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation(operation)
        }
        ClientWorkError::Transport(detail) => CliFailure::protocol(detail).for_operation(operation),
        ClientWorkError::Kernel(detail) => {
            CliFailure::protocol(detail.to_string()).for_operation(operation)
        }
        ClientWorkError::Protocol(detail) => CliFailure::protocol(detail).for_operation(operation),
    }
}

fn work_preview_json(
    preview: &egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkPreparationPreview,
) -> serde_json::Value {
    json!({
        "snapshotId": preview.snapshot_id,
        "snapshotRevision": preview.snapshot_revision,
        "normalizedIntent": preview.normalized_intent,
        "workType": preview.work_type,
        "targetScopeRef": preview.target_scope_ref,
        "compiledContextSha256": preview.compiled_context_sha256,
        "includedSources": preview.included_sources.iter().map(|source| json!({
            "sourceRef": source.source_ref,
            "label": source.label,
            "authority": source.authority,
            "contentSha256": source.content_sha256,
            "included": source.included,
        })).collect::<Vec<_>>(),
        "excludedSources": preview.excluded_sources.iter().map(|notice| json!({"code": notice.code, "detail": notice.detail, "sourceRef": notice.source_ref})).collect::<Vec<_>>(),
        "nonGoals": preview.non_goals,
        "allowedReadPaths": preview.allowed_read_paths,
        "allowedWritePaths": preview.allowed_write_paths,
        "allowedTools": preview.allowed_tools,
        "externalResources": preview.external_resources,
        "acceptanceContractRef": preview.acceptance_contract_ref.as_ref().map(contract_ref_json),
        "budgetProfileRef": preview.budget_profile_ref.as_ref().map(contract_ref_json),
        "memoryAuthorityRevision": preview.memory_authority_revision,
        "memoryPackSnapshotSha256": preview.memory_pack_snapshot_sha256,
        "contextStateRevision": preview.context_state_revision,
        "recoveryEntry": preview.recovery_entry,
        "visibility": preview.visibility,
        "expiresAt": preview.expires_at.as_ref().map(timestamp_json),
        "confirmationBindingSha256": preview.confirmation_binding_sha256,
        "gateReady": preview.gate_ready,
        "blockers": preview.blockers.iter().map(|notice| json!({"code": notice.code, "detail": notice.detail})).collect::<Vec<_>>(),
        "warnings": preview.warnings.iter().map(|notice| json!({"code": notice.code, "detail": notice.detail})).collect::<Vec<_>>(),
        "requiredConfirmations": preview.required_confirmations,
        "evidenceRequired": preview.evidence_required,
        "readyForFounderConfirmation": preview.ready_for_founder_confirmation,
        "deadline": preview.deadline.as_ref().map(timestamp_json),
    })
}

fn contract_ref_json(
    reference: &egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference,
) -> serde_json::Value {
    json!({
        "contractId": reference.contract_id,
        "version": reference.version,
        "sha256": reference.sha256,
    })
}

fn timestamp_json(timestamp: &prost_types::Timestamp) -> serde_json::Value {
    json!({"seconds": timestamp.seconds, "nanos": timestamp.nanos})
}

async fn memory(command: MemoryCommand) -> Result<(), CliFailure> {
    match command {
        MemoryCommand::Retrieve {
            query,
            scope,
            max_results,
            min_score,
            json,
        } => memory_retrieve(query, scope, max_results, min_score, json).await,
        MemoryCommand::Candidate {
            memory_id,
            content,
            source_ref,
            scope,
            idempotency_key,
            json,
        } => memory_mutation(
            "memory.candidate",
            memory_mutation_command::Command::SubmitMemoryCandidate(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::SubmitMemoryCandidateCommand {
                    metadata: None,
                    memory_id,
                    content,
                    source_ref,
                    scope_ref: scope,
                    idempotency_key,
                },
            ),
            json,
        )
        .await,
        MemoryCommand::Accept {
            memory_id,
            expected_revision,
            evidence_ref,
            idempotency_key,
            json,
        } => memory_mutation(
            "memory.accept",
            memory_mutation_command::Command::AcceptMemory(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::AcceptMemoryCommand {
                    metadata: None,
                    memory_id,
                    expected_revision,
                    evidence_ref,
                    idempotency_key,
                },
            ),
            json,
        )
        .await,
        MemoryCommand::Revoke {
            memory_id,
            expected_revision,
            evidence_ref,
            idempotency_key,
            json,
        } => memory_mutation(
            "memory.revoke",
            memory_mutation_command::Command::RevokeMemory(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeMemoryCommand {
                    metadata: None,
                    memory_id,
                    expected_revision,
                    evidence_ref,
                    idempotency_key,
                },
            ),
            json,
        )
        .await,
    }
}

async fn memory_retrieve(
    query: String,
    scope_ref: String,
    max_results: u32,
    min_score: f64,
    json_output: bool,
) -> Result<(), CliFailure> {
    const OPERATION: &str = "memory.retrieve";
    let attached = attach(OPERATION).await?;
    attached.require_rpc("LocalCognitionService/RetrieveMemory", OPERATION)?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .0
        .connection
        .cognition_service()
        .retrieve_memory(RetrieveMemoryRequest {
            client: Some(metadata),
            query,
            scope_ref: scope_ref.clone(),
            max_results,
            min_score,
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation(OPERATION)
        })?
        .into_inner();
    let result = match response.outcome {
        Some(retrieve_memory_response::Outcome::Result(result)) => result,
        Some(retrieve_memory_response::Outcome::Error(error)) => {
            return Err(CliFailure::from_local_api_error(error).for_operation(OPERATION));
        }
        None => {
            return Err(
                CliFailure::protocol("Memory retrieval outcome missing").for_operation(OPERATION)
            );
        }
    };
    let candidates = result
        .candidates
        .iter()
        .map(|candidate| {
            json!({
                "memoryId": candidate.memory_id,
                "sourceRef": candidate.source_ref,
                "contentSha256": candidate.content_sha256,
                "score": candidate.score,
                "matchedTerms": candidate.matched_terms,
            })
        })
        .collect::<Vec<_>>();
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": OPERATION,
        "data": {
            "scopeRef": scope_ref,
            "algorithmId": result.algorithm_id,
            "querySha256": result.query_sha256,
            "snapshotSha256": result.snapshot_sha256,
            "evidenceRef": result.evidence_ref,
            "resultCount": candidates.len(),
            "candidates": candidates,
        },
        "projection": serde_json::Value::Null,
        "correlationId": Uuid::now_v7().to_string(),
    });
    if json_output {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Memory retrieval: scope={} results={} algorithm={}\nSnapshot: {}\nEvidence: {}",
            payload["data"]["scopeRef"].as_str().unwrap_or(""),
            payload["data"]["resultCount"].as_u64().unwrap_or(0),
            payload["data"]["algorithmId"].as_str().unwrap_or(""),
            payload["data"]["snapshotSha256"].as_str().unwrap_or(""),
            payload["data"]["evidenceRef"].as_str().unwrap_or("")
        );
        for candidate in payload["data"]["candidates"]
            .as_array()
            .into_iter()
            .flatten()
        {
            println!(
                "- {} score={} source={} digest={}",
                candidate["memoryId"].as_str().unwrap_or(""),
                candidate["score"].as_f64().unwrap_or(0.0),
                candidate["sourceRef"].as_str().unwrap_or(""),
                candidate["contentSha256"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}

async fn memory_mutation(
    operation: &'static str,
    mut branch: memory_mutation_command::Command,
    json_output: bool,
) -> Result<(), CliFailure> {
    let attached = attach(operation).await?;
    let oneof = match &branch {
        memory_mutation_command::Command::SubmitMemoryCandidate(_) => "submit_memory_candidate",
        memory_mutation_command::Command::AcceptMemory(_) => "accept_memory",
        memory_mutation_command::Command::RevokeMemory(_) => "revoke_memory",
    };
    attached.require_command(
        "LocalCommandGatewayService/ExecuteMemoryMutation",
        oneof,
        operation,
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    match &mut branch {
        memory_mutation_command::Command::SubmitMemoryCandidate(command) => {
            command.metadata = Some(metadata.clone())
        }
        memory_mutation_command::Command::AcceptMemory(command) => {
            command.metadata = Some(metadata.clone())
        }
        memory_mutation_command::Command::RevokeMemory(command) => {
            command.metadata = Some(metadata.clone())
        }
    }
    let response = attached
        .0
        .connection
        .command_gateway_service()
        .execute_memory_mutation(ExecuteMemoryMutationRequest {
            client: Some(metadata),
            command: Some(MemoryMutationCommand {
                command: Some(branch),
            }),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation(operation)
        })?
        .into_inner();
    let result: MemoryMutationReceipt = match (response.authority_result, response.gateway_error) {
        (Some(result), None) => result,
        (_, Some(error)) => {
            return Err(CliFailure::from_local_api_error(error).for_operation(operation));
        }
        _ => {
            return Err(
                CliFailure::protocol("Memory mutation outcome missing").for_operation(operation)
            );
        }
    };
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": operation,
        "data": {
            "memoryId": result.memory_id,
            "revision": result.revision,
            "state": result.state,
            "eventId": result.event_id,
            "requestDigestSha256": result.request_digest_sha256,
            "acknowledgedAfterDurabilityBarrier": result.acknowledged_after_durability_barrier,
        },
        "correlationId": correlation_id,
    });
    if json_output {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Memory mutation: operation={} id={} revision={} state={}",
            operation,
            payload["data"]["memoryId"].as_str().unwrap_or(""),
            payload["data"]["revision"].as_u64().unwrap_or(0),
            payload["data"]["state"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}

async fn status(json: bool) -> Result<(), CliFailure> {
    let attached = attach("status").await?;
    attached.require_rpc("LocalReadModelService/GetProjectionStatus", "status")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .0
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
        .0
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
        TaskCommandCli::ApplyVerdict {
            task_id,
            expected_revision,
            work_revision,
            founder_verdict_id,
            json,
        } => {
            task_apply_verdict(
                task_id,
                expected_revision,
                work_revision,
                founder_verdict_id,
                json,
            )
            .await
        }
        TaskCommandCli::Cancel {
            task_id,
            expected_revision,
            reason_code,
            json,
        } => task_cancel(task_id, expected_revision, reason_code, json).await,
    }
}

async fn task_get(task_id: String, json: bool) -> Result<(), CliFailure> {
    let attached = attach("task.get").await?;
    attached.require_rpc("LocalReadModelService/GetTaskView", "task.get")?;
    let metadata = attached.metadata(None)?;
    let response = attached
        .0
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
        .0
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
    validate_task_watch_request(frames, &resume_epoch, resume_sequence)?;
    let attached = attach("task.watch").await?;
    let watch = attached
        .0
        .open_task_watch(TaskWatchRequest {
            resume_epoch,
            resume_sequence,
        })
        .await
        .map_err(task_watch_failure)?;
    consume_task_watch(watch, frames, |update| {
        render_task_watch_update(update, json);
    })
    .await
}

trait CliTaskWatchSource {
    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<TaskWatchUpdate>, ClientTaskWatchError>> + '_>>;
}

impl CliTaskWatchSource for TaskWatch {
    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<TaskWatchUpdate>, ClientTaskWatchError>> + '_>>
    {
        Box::pin(TaskWatch::next_update(self))
    }
}

async fn consume_task_watch<S, R>(
    mut watch: S,
    frames: u32,
    mut render: R,
) -> Result<(), CliFailure>
where
    S: CliTaskWatchSource,
    R: FnMut(&TaskWatchUpdate),
{
    validate_task_watch_request(frames, &None, None)?;
    let mut emitted = 0_u32;
    while emitted < frames {
        let Some(update) = watch.next_update().await.map_err(task_watch_failure)? else {
            return ensure_task_watch_complete(frames, emitted);
        };
        if update.classification == TaskWatchClassification::ResetRequired {
            return Err(CliFailure::stream_recovery(
                "task.watch",
                update
                    .reset_reason_code
                    .as_deref()
                    .unwrap_or("stream reset required"),
            ));
        }
        render(&update);
        emitted += 1;
    }
    Ok(())
}

fn validate_task_watch_request(
    frames: u32,
    resume_epoch: &Option<String>,
    resume_sequence: Option<u64>,
) -> Result<(), CliFailure> {
    if frames == 0 {
        return Err(
            CliFailure::protocol("frames must be greater than zero").for_operation("task.watch")
        );
    }
    if frames > 1000 {
        return Err(CliFailure::protocol("frames must not exceed 1000").for_operation("task.watch"));
    }
    if resume_epoch.is_some() != resume_sequence.is_some() {
        return Err(CliFailure::protocol(
            "resume_epoch and resume_sequence must be supplied together",
        )
        .for_operation("task.watch"));
    }
    Ok(())
}

fn ensure_task_watch_complete(requested: u32, received: u32) -> Result<(), CliFailure> {
    if received < requested {
        return Err(task_watch_failure(ClientTaskWatchError::PrematureEof {
            expected: requested,
            received,
        }));
    }
    Ok(())
}

fn task_watch_failure(error: ClientTaskWatchError) -> CliFailure {
    match error {
        ClientTaskWatchError::Transport(detail) => {
            CliFailure::daemon_unavailable(detail).for_operation("task.watch")
        }
        ClientTaskWatchError::Kernel(KernelError::PermissionDenied(permission)) => {
            CliFailure::permission("task.watch", permission)
        }
        invalid @ ClientTaskWatchError::InvalidResumePair => {
            CliFailure::protocol(invalid.to_string()).for_operation("task.watch")
        }
        recovery @ (ClientTaskWatchError::Kernel(_)
        | ClientTaskWatchError::ResetBarrier
        | ClientTaskWatchError::PrematureEof { .. }) => {
            CliFailure::stream_recovery("task.watch", recovery.to_string())
        }
    }
}

fn task_watch_update_json(update: &TaskWatchUpdate) -> serde_json::Value {
    let apply = match update.classification {
        TaskWatchClassification::Applied => "applied",
        TaskWatchClassification::Replay => "replay",
        TaskWatchClassification::Heartbeat => "heartbeat",
        TaskWatchClassification::ResetRequired => "reset_required",
    };
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.watch",
        "data": {
            "kind": update.kind.contract_name(),
            "apply": apply,
            "view": update.view.as_ref().map(task_summary),
            "resetReasonCode": update.reset_reason_code,
        },
        "projection": projection_position_json(Some(&update.position)),
        "correlationId": Uuid::now_v7().to_string(),
    })
}

fn task_watch_update_text(update: &TaskWatchUpdate) -> String {
    let payload = task_watch_update_json(update);
    format!(
        "Task watch: kind={} apply={} position={}",
        payload["data"]["kind"].as_str().unwrap_or("unknown"),
        payload["data"]["apply"].as_str().unwrap_or("unknown"),
        payload["projection"]["position"]
    )
}

fn render_task_watch_update(update: &TaskWatchUpdate, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(&task_watch_update_json(update)).unwrap()
        );
    } else {
        println!("{}", task_watch_update_text(update));
    }
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
        .0
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
        .0
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
        .0
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
    let mut watch = match (resume_epoch, resume_sequence) {
        (Some(epoch), Some(sequence)) => {
            attached
                .0
                .open_approval_watch_resume(ApprovalWatchCursor { epoch, sequence })
                .await
        }
        (None, None) => attached.0.open_approval_watch_current().await,
        _ => unreachable!("approval watch resume pair was validated"),
    }
    .map_err(approval_watch_failure)?;
    consume_approval_watch(&mut watch, frames, |update| {
        let payload = approval_stream_frame_json(update);
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
    })
    .await
}

trait CliApprovalWatchSource {
    fn next_update(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>> + '_,
        >,
    >;
}

impl CliApprovalWatchSource for ApprovalWatch {
    fn next_update(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>> + '_,
        >,
    > {
        Box::pin(ApprovalWatch::next_update(self))
    }
}

async fn consume_approval_watch<S, R>(
    watch: &mut S,
    frames: u32,
    mut render: R,
) -> Result<(), CliFailure>
where
    S: CliApprovalWatchSource,
    R: FnMut(&ApprovalWatchUpdate),
{
    let mut emitted = 0_u32;
    while emitted < frames.min(1000) {
        let update = watch
            .next_update()
            .await
            .map_err(approval_watch_failure)?
            .ok_or_else(|| {
                CliFailure::stream_recovery("approval.watch", "stream ended unexpectedly")
            })?;
        if update.classification == ApprovalWatchClassification::ResetRequired {
            return Err(CliFailure::stream_recovery(
                "approval.watch",
                update
                    .reset_reason_code
                    .as_deref()
                    .unwrap_or("stream reset required"),
            ));
        }
        render(&update);
        emitted += 1;
    }
    Ok(())
}

fn approval_stream_frame_json(update: &ApprovalWatchUpdate) -> serde_json::Value {
    let apply = match update.classification {
        ApprovalWatchClassification::Applied => "applied",
        ApprovalWatchClassification::Replay => "replay",
        ApprovalWatchClassification::Heartbeat => "heartbeat",
        ApprovalWatchClassification::ResetRequired => "reset_required",
    };
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "approval.watch",
        "data": {
            "kind": update.kind.contract_name(),
            "apply": apply,
            "view": update.view.as_ref().map(|view| approval_json(view, "approval.watch")["data"].clone()),
            "resetReasonCode": update.reset_reason_code,
        },
        "projection": projection_position_json(Some(&update.position)),
        "correlationId": Uuid::now_v7().to_string(),
    })
}

fn approval_watch_failure(error: ClientApprovalWatchError) -> CliFailure {
    match error {
        ClientApprovalWatchError::Transport(detail) => {
            CliFailure::daemon_unavailable(detail).for_operation("approval.watch")
        }
        ClientApprovalWatchError::Kernel(KernelError::PermissionDenied(permission)) => {
            CliFailure::permission("approval.watch", permission)
        }
        ClientApprovalWatchError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("approval.watch")
        }
        ClientApprovalWatchError::BaselineLimitExceeded | ClientApprovalWatchError::Protocol(_) => {
            CliFailure::protocol(error.to_string()).for_operation("approval.watch")
        }
        ClientApprovalWatchError::Kernel(_) | ClientApprovalWatchError::ResetBarrier => {
            CliFailure::stream_recovery("approval.watch", error.to_string())
        }
        ClientApprovalWatchError::UnexpectedEof => {
            CliFailure::stream_recovery("approval.watch", error.to_string())
        }
    }
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
        .0
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
        .0
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
        .0
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
            meta: Some(command_metadata(
                &correlation_id,
                "egopulse-cli/task-create",
            )),
            work_type,
            input_snapshot_id,
            target_scope_ref,
            acceptance_contract_ref: Some(acceptance_contract_ref),
            budget_profile_ref: Some(budget_profile_ref),
        })),
    };
    set_task_digest(&mut command);
    let metadata = attached.metadata(Some(correlation_id.clone()))?;
    let response = attached
        .0
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

async fn task_apply_verdict(
    task_id: String,
    expected_revision: u64,
    work_revision: u64,
    founder_verdict_id: String,
    json: bool,
) -> Result<(), CliFailure> {
    let attached = attach("task.apply-verdict").await?;
    attached.require_command(
        "LocalCommandGatewayService/ExecuteTaskCommand",
        "apply_founder_verdict",
        "task.apply-verdict",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(command_metadata(
                    &correlation_id,
                    "egopulse-cli/task-apply-verdict",
                )),
                task_id,
                expected_revision,
                work_revision,
                founder_verdict_id,
            },
        )),
    };
    set_task_digest(&mut command);
    let response = attached
        .0
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(attached.metadata(Some(correlation_id.clone()))?),
            command: Some(command),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.apply-verdict")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("task.apply-verdict"));
    }
    let result = response.authority_result.ok_or_else(|| {
        CliFailure::protocol("task authority result missing").for_operation("task.apply-verdict")
    })?;
    let replayed = result.replayed;
    let task = match result.outcome {
        Some(task_command_result::Outcome::Task(task)) => task,
        Some(task_command_result::Outcome::Error(error)) => {
            return Err(CliFailure::task_authority(
                error.code,
                error.safe_detail_code,
                "task.apply-verdict",
            ));
        }
        None => {
            return Err(CliFailure::protocol("task authority outcome missing")
                .for_operation("task.apply-verdict"));
        }
    };
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.apply-verdict",
        "data": {
            "taskId": task.task_id,
            "revision": task.revision,
            "status": TaskStatus::try_from(task.status).map(|status| status.as_str_name()).unwrap_or("TASK_STATUS_UNSPECIFIED"),
            "founderVerdictId": task.founder_verdict_id,
            "replayed": replayed,
            "awaitToken": await_token_json(response.await_token),
        },
        "correlationId": correlation_id,
    });
    if json {
        println!("{}", serde_json::to_string(&payload).unwrap());
    } else {
        println!(
            "Task Founder Verdict applied: task={} revision={} status={} replayed={}",
            payload["data"]["taskId"].as_str().unwrap_or(""),
            payload["data"]["revision"].as_u64().unwrap_or_default(),
            payload["data"]["status"].as_str().unwrap_or(""),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
}

async fn task_cancel(
    task_id: String,
    expected_revision: u64,
    reason_code: String,
    json: bool,
) -> Result<(), CliFailure> {
    let attached = attach("task.cancel").await?;
    attached.require_command(
        "LocalCommandGatewayService/ExecuteTaskCommand",
        "request_task_cancellation",
        "task.cancel",
    )?;
    let correlation_id = Uuid::now_v7().to_string();
    let mut command = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(command_metadata(
                    &correlation_id,
                    "egopulse-cli/task-cancel",
                )),
                task_id,
                expected_revision,
                reason_code,
            },
        )),
    };
    set_task_digest(&mut command);
    let response = attached
        .0
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(attached.metadata(Some(correlation_id.clone()))?),
            command: Some(command),
        })
        .await
        .map_err(|error| {
            CliFailure::daemon_unavailable(error.to_string()).for_operation("task.cancel")
        })?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(CliFailure::from_local_api_error(error).for_operation("task.cancel"));
    }
    let result = response.authority_result.ok_or_else(|| {
        CliFailure::protocol("task authority result missing").for_operation("task.cancel")
    })?;
    let replayed = result.replayed;
    let task = match result.outcome {
        Some(task_command_result::Outcome::Task(task)) => task,
        Some(task_command_result::Outcome::Error(error)) => {
            return Err(CliFailure::task_authority(
                error.code,
                error.safe_detail_code,
                "task.cancel",
            ));
        }
        None => {
            return Err(
                CliFailure::protocol("task authority outcome missing").for_operation("task.cancel")
            );
        }
    };
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.cancel",
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
            "Task cancellation requested: {} revision={} status={} replayed={}",
            payload["data"]["taskId"].as_str().unwrap_or(""),
            payload["data"]["revision"].as_u64().unwrap_or_default(),
            payload["data"]["status"].as_str().unwrap_or(""),
            payload["data"]["replayed"].as_bool().unwrap_or(false),
        );
    }
    Ok(())
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
    let collaboration = view.collaboration.as_ref();
    let run = collaboration.and_then(|value| value.run.as_ref());
    let return_pending_steps = collaboration.map_or(0, |value| {
        value
            .steps
            .iter()
            .filter(|step| step.status == StepStatus::ReturnPending as i32)
            .count()
    });
    let returned_steps = collaboration.map_or(0, |value| {
        value
            .steps
            .iter()
            .filter(|step| step.status == StepStatus::Returned as i32)
            .count()
    });
    json!({
        "taskId": task.map(|task| task.task_id.clone()),
        "revision": task.map_or(0, |task| task.revision),
        "status": task.and_then(|task| TaskStatus::try_from(task.status).ok()).map(|status| status.as_str_name()),
        "currentRunId": task.and_then(|task| task.current_run_id.clone()),
        "collaboration": {
            "runId": run.map(|run| run.run_id.clone()),
            "runStatus": run.and_then(|run| RunStatus::try_from(run.status).ok()).map(|status| status.as_str_name()),
            "returnPendingSteps": return_pending_steps,
            "returnedSteps": returned_steps,
        },
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
        println!(
            "Workflow: run={} status={} return_pending_steps={} returned_steps={}",
            payload["data"]["collaboration"]["runId"]
                .as_str()
                .unwrap_or(""),
            payload["data"]["collaboration"]["runStatus"]
                .as_str()
                .unwrap_or(""),
            payload["data"]["collaboration"]["returnPendingSteps"]
                .as_u64()
                .unwrap_or_default(),
            payload["data"]["collaboration"]["returnedSteps"]
                .as_u64()
                .unwrap_or_default(),
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
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use super::*;

    struct ScriptedTaskWatchSource {
        outcomes: VecDeque<Result<Option<TaskWatchUpdate>, ClientTaskWatchError>>,
        polls: Rc<Cell<u64>>,
        drops: Rc<Cell<u64>>,
    }

    impl CliTaskWatchSource for ScriptedTaskWatchSource {
        fn next_update(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<Option<TaskWatchUpdate>, ClientTaskWatchError>> + '_>>
        {
            self.polls.set(self.polls.get() + 1);
            let outcome = self.outcomes.pop_front().unwrap_or(Ok(None));
            Box::pin(std::future::ready(outcome))
        }
    }

    impl Drop for ScriptedTaskWatchSource {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    struct ScriptedApprovalWatchSource {
        outcomes: VecDeque<Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>>,
        polls: Rc<Cell<u64>>,
    }

    impl CliApprovalWatchSource for ScriptedApprovalWatchSource {
        fn next_update(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>>
                    + '_,
            >,
        > {
            self.polls.set(self.polls.get() + 1);
            Box::pin(std::future::ready(
                self.outcomes.pop_front().unwrap_or(Ok(None)),
            ))
        }
    }

    fn approval_watch_update(classification: ApprovalWatchClassification) -> ApprovalWatchUpdate {
        ApprovalWatchUpdate {
            classification,
            kind: if classification == ApprovalWatchClassification::ResetRequired {
                egopulse_client_operations::ApprovalWatchFrameKind::ResetRequired
            } else {
                egopulse_client_operations::ApprovalWatchFrameKind::Heartbeat
            },
            position: egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition {
                epoch: "epoch:approval-watch".to_owned(),
                sequence: 9,
                projected_at: None,
            },
            view: None,
            reset_reason_code: (classification == ApprovalWatchClassification::ResetRequired)
                .then(|| "projection_reset".to_owned()),
        }
    }

    fn scripted_watch(
        outcomes: Vec<Result<Option<TaskWatchUpdate>, ClientTaskWatchError>>,
    ) -> (ScriptedTaskWatchSource, Rc<Cell<u64>>, Rc<Cell<u64>>) {
        let polls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        (
            ScriptedTaskWatchSource {
                outcomes: outcomes.into(),
                polls: Rc::clone(&polls),
                drops: Rc::clone(&drops),
            },
            polls,
            drops,
        )
    }

    fn task_watch_update(classification: TaskWatchClassification) -> TaskWatchUpdate {
        TaskWatchUpdate {
            classification,
            kind: egopulse_client_operations::TaskWatchFrameKind::Heartbeat,
            position: egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition {
                epoch: "epoch:watch".to_owned(),
                sequence: 9,
                projected_at: None,
            },
            view: None,
            reset_reason_code: (classification == TaskWatchClassification::ResetRequired)
                .then(|| "projection_reset".to_owned()),
        }
    }

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

    #[test]
    fn task_watch_cli_preserves_bounds_resume_pair_and_premature_eof_failures() {
        assert!(validate_task_watch_request(1, &None, None).is_ok());
        for frames in [0, 1001] {
            let failure = validate_task_watch_request(frames, &None, None).unwrap_err();
            assert_eq!(failure.operation, "task.watch");
            assert_eq!(failure.reason_code, "LOCAL_API_PROTOCOL_ERROR");
        }
        assert!(validate_task_watch_request(1000, &Some("epoch:one".to_owned()), Some(4)).is_ok());
        for (epoch, sequence) in [(Some("epoch:one".to_owned()), None), (None, Some(4))] {
            let failure = validate_task_watch_request(1, &epoch, sequence).unwrap_err();
            assert_eq!(failure.reason_code, "LOCAL_API_PROTOCOL_ERROR");
        }
        assert!(ensure_task_watch_complete(2, 2).is_ok());
        let failure = ensure_task_watch_complete(2, 1).unwrap_err();
        assert_eq!(failure.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert!(failure.message.contains("after 1 frames"));
        assert!(failure.message.contains("requested 2"));
    }

    #[test]
    fn task_watch_cli_keeps_json_schema_and_error_categories_stable() {
        let update = TaskWatchUpdate {
            classification: TaskWatchClassification::Replay,
            kind: egopulse_client_operations::TaskWatchFrameKind::Snapshot,
            position: egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition {
                epoch: "epoch:watch".to_owned(),
                sequence: 9,
                projected_at: None,
            },
            view: Some(TaskView::default()),
            reset_reason_code: None,
        };
        let payload = task_watch_update_json(&update);
        assert_eq!(payload["schemaVersion"], "egopulse.cli-result/v0.1");
        assert_eq!(payload["operation"], "task.watch");
        assert_eq!(payload["data"]["kind"], "STREAM_FRAME_KIND_SNAPSHOT");
        assert_eq!(payload["data"]["apply"], "replay");
        assert_eq!(payload["projection"]["position"]["epoch"], "epoch:watch");
        assert_eq!(payload["projection"]["position"]["sequence"], 9);

        let transport = task_watch_failure(ClientTaskWatchError::Transport("closed".to_owned()));
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        let protocol = task_watch_failure(ClientTaskWatchError::Kernel(
            KernelError::UnknownStreamFrame,
        ));
        assert_eq!(protocol.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        let reset = task_watch_failure(ClientTaskWatchError::ResetBarrier);
        assert_eq!(reset.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert_ne!(transport.message, protocol.message);
        assert_ne!(protocol.message, reset.message);

        let permission = task_watch_failure(ClientTaskWatchError::Kernel(
            KernelError::PermissionDenied("local.task.read".to_owned()),
        ));
        assert_eq!(permission.reason_code, "PERMISSION_DENIED");
        assert_eq!(permission.operation, "task.watch");

        let text = task_watch_update_text(&task_watch_update(TaskWatchClassification::Heartbeat));
        assert_eq!(
            text,
            "Task watch: kind=STREAM_FRAME_KIND_HEARTBEAT apply=heartbeat position={\"epoch\":\"epoch:watch\",\"sequence\":9}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_watch_consume_loop_polls_exactly_n_and_drops_source() {
        let (source, polls, drops) = scripted_watch(vec![
            Ok(Some(task_watch_update(TaskWatchClassification::Applied))),
            Ok(Some(task_watch_update(TaskWatchClassification::Replay))),
            Err(ClientTaskWatchError::Transport(
                "must-not-poll-third".to_owned(),
            )),
        ]);
        let rendered = Rc::new(Cell::new(0_u64));
        let rendered_witness = Rc::clone(&rendered);
        consume_task_watch(source, 2, move |_update| {
            rendered_witness.set(rendered_witness.get() + 1);
        })
        .await
        .unwrap();
        assert_eq!(polls.get(), 2);
        assert_eq!(rendered.get(), 2);
        assert_eq!(drops.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_watch_consume_loop_fails_closed_without_extra_polls() {
        let (zero_source, zero_polls, zero_drops) = scripted_watch(vec![Ok(Some(
            task_watch_update(TaskWatchClassification::Applied),
        ))]);
        assert!(consume_task_watch(zero_source, 0, |_| {}).await.is_err());
        assert_eq!(zero_polls.get(), 0);
        assert_eq!(zero_drops.get(), 1);

        let (partial_source, partial_polls, partial_drops) = scripted_watch(vec![
            Ok(Some(task_watch_update(TaskWatchClassification::Applied))),
            Ok(None),
        ]);
        let partial = consume_task_watch(partial_source, 2, |_| {})
            .await
            .unwrap_err();
        assert_eq!(partial.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert!(partial.message.contains("after 1 frames"));
        assert_eq!(partial_polls.get(), 2);
        assert_eq!(partial_drops.get(), 1);

        let (transport_source, transport_polls, transport_drops) = scripted_watch(vec![Err(
            ClientTaskWatchError::Transport("tonic-status".to_owned()),
        )]);
        let transport = consume_task_watch(transport_source, 1, |_| {})
            .await
            .unwrap_err();
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        assert_eq!(transport_polls.get(), 1);
        assert_eq!(transport_drops.get(), 1);

        let (reset_source, reset_polls, reset_drops) = scripted_watch(vec![
            Ok(Some(task_watch_update(
                TaskWatchClassification::ResetRequired,
            ))),
            Err(ClientTaskWatchError::Transport(
                "must-not-poll-after-reset".to_owned(),
            )),
        ]);
        let reset = consume_task_watch(reset_source, 2, |_| {})
            .await
            .unwrap_err();
        assert_eq!(reset.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert!(reset.message.contains("projection_reset"));
        assert_eq!(reset_polls.get(), 1);
        assert_eq!(reset_drops.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approval_watch_cli_consumes_shared_updates_and_stops_at_reset() {
        let polls = Rc::new(Cell::new(0));
        let mut source = ScriptedApprovalWatchSource {
            outcomes: vec![
                Ok(Some(approval_watch_update(
                    ApprovalWatchClassification::Heartbeat,
                ))),
                Ok(Some(approval_watch_update(
                    ApprovalWatchClassification::Replay,
                ))),
            ]
            .into(),
            polls: Rc::clone(&polls),
        };
        let rendered = Rc::new(Cell::new(0));
        let rendered_witness = Rc::clone(&rendered);
        consume_approval_watch(&mut source, 2, move |_| {
            rendered_witness.set(rendered_witness.get() + 1);
        })
        .await
        .expect("bounded approval watch");
        assert_eq!(polls.get(), 2);
        assert_eq!(rendered.get(), 2);

        let reset_polls = Rc::new(Cell::new(0));
        let mut reset = ScriptedApprovalWatchSource {
            outcomes: vec![
                Ok(Some(approval_watch_update(
                    ApprovalWatchClassification::ResetRequired,
                ))),
                Err(ClientApprovalWatchError::Transport(
                    "must-not-poll".to_owned(),
                )),
            ]
            .into(),
            polls: Rc::clone(&reset_polls),
        };
        let error = consume_approval_watch(&mut reset, 2, |_| {})
            .await
            .expect_err("reset is a recovery barrier");
        assert_eq!(error.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert_eq!(reset_polls.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approval_watch_cli_types_eof_and_transport_failures() {
        let partial_polls = Rc::new(Cell::new(0));
        let mut partial = ScriptedApprovalWatchSource {
            outcomes: vec![
                Ok(Some(approval_watch_update(
                    ApprovalWatchClassification::Heartbeat,
                ))),
                Ok(None),
            ]
            .into(),
            polls: Rc::clone(&partial_polls),
        };
        let eof = consume_approval_watch(&mut partial, 2, |_| {})
            .await
            .expect_err("approval EOF requires recovery");
        assert_eq!(eof.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert_eq!(partial_polls.get(), 2);

        let transport_polls = Rc::new(Cell::new(0));
        let mut transport = ScriptedApprovalWatchSource {
            outcomes: vec![Err(ClientApprovalWatchError::Transport(
                "tonic-status".to_owned(),
            ))]
            .into(),
            polls: Rc::clone(&transport_polls),
        };
        let error = consume_approval_watch(&mut transport, 1, |_| {})
            .await
            .expect_err("transport remains distinct");
        assert_eq!(error.reason_code, "DAEMON_UNAVAILABLE");
        assert_eq!(transport_polls.get(), 1);
    }

    #[test]
    fn approval_watch_json_schema_remains_compatible() {
        let update = approval_watch_update(ApprovalWatchClassification::Replay);
        let payload = approval_stream_frame_json(&update);
        assert_eq!(payload["operation"], "approval.watch");
        assert_eq!(payload["data"]["kind"], "STREAM_FRAME_KIND_HEARTBEAT");
        assert_eq!(payload["data"]["apply"], "replay");
        assert!(payload["data"]["view"].is_null());
        assert_eq!(
            payload["projection"]["position"]["epoch"],
            "epoch:approval-watch"
        );
        assert_eq!(payload["projection"]["position"]["sequence"], 9);
    }

    #[test]
    fn context_revoke_cli_preserves_evidence_order_and_exact_digest_mode() {
        let cli = Cli::try_parse_from([
            "egopulse",
            "context",
            "revoke",
            "ctx:abc",
            "--expected-state-revision",
            "3",
            "--reason-code",
            "founder-withdrew-context",
            "--evidence-ref",
            "evidence:first",
            "--evidence-ref",
            "evidence:second",
            "--confirmation-proof-ref",
            "proof:founder-review",
            "--idempotency-key",
            "idem:context-revoke",
            "--confirm-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--json",
        ])
        .expect("valid Context revoke CLI");
        assert!(matches!(
            cli.command,
            Command::Context {
                command: ContextCommand::Revoke {
                    snapshot_id,
                    expected_state_revision: 3,
                    evidence_refs,
                    preview: false,
                    confirm_digest: Some(digest),
                    json: true,
                    ..
                }
            } if snapshot_id == "ctx:abc"
                && evidence_refs == ["evidence:first", "evidence:second"]
                && digest == "a".repeat(64)
        ));
    }

    #[test]
    fn context_revoke_preview_and_execution_digest_are_mutually_exclusive() {
        let error = Cli::try_parse_from([
            "egopulse",
            "context",
            "revoke",
            "ctx:abc",
            "--expected-state-revision",
            "1",
            "--reason-code",
            "withdrawn",
            "--evidence-ref",
            "evidence:one",
            "--confirmation-proof-ref",
            "proof:one",
            "--idempotency-key",
            "idem:one",
            "--preview",
            "--confirm-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .expect_err("preview must never also execute");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn interactive_context_confirmation_removes_only_the_terminal_line_ending() {
        let digest = "a".repeat(64);
        assert_eq!(remove_terminal_line_ending(format!("{digest}\r\n")), digest);
        assert_eq!(
            remove_terminal_line_ending(format!(" {digest} \n")),
            format!(" {digest} ")
        );
        assert_eq!(remove_terminal_line_ending(" \n".to_owned()), " ");
        assert_eq!(remove_terminal_line_ending(digest.clone()), digest);
    }

    #[test]
    fn context_conflicts_map_to_stable_domain_failures() {
        for code in [
            LocalApiErrorCode::OwnerMismatch,
            LocalApiErrorCode::ContextRevoked,
            LocalApiErrorCode::StateRevisionConflict,
            LocalApiErrorCode::IdempotencyConflict,
        ] {
            let failure = CliFailure::from_local_api_error(LocalApiError {
                code: code as i32,
                retryable: false,
                required_action_code: Some("REVIEW_CONTEXT_STATE".to_owned()),
                safe_fingerprint: "context-conflict".to_owned(),
                ..Default::default()
            })
            .for_operation("context.revoke");
            assert_eq!(failure.exit_code, 6, "{code:?}");
            assert_eq!(failure.category, "domain_conflict", "{code:?}");
            assert_eq!(failure.operation, "context.revoke", "{code:?}");
            assert_eq!(
                failure.required_action_code.as_deref(),
                Some("REVIEW_CONTEXT_STATE")
            );
            assert_eq!(
                failure.safe_fingerprint.as_deref(),
                Some("context-conflict")
            );
        }
    }

    #[test]
    fn task_summary_exposes_governed_return_state_without_adding_write_authority() {
        let view = TaskView {
            task: None,
            collaboration: Some(
                egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationSnapshot {
                    run: Some(
                        egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot {
                            run_id: "run-1".to_owned(),
                            status: RunStatus::ReturnPending as i32,
                            ..Default::default()
                        },
                    ),
                    steps: vec![
                        egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepSnapshot {
                            status: StepStatus::ReturnPending as i32,
                            ..Default::default()
                        },
                        egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepSnapshot {
                            status: StepStatus::Returned as i32,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let summary = task_summary(&view);
        assert_eq!(
            summary["collaboration"]["runStatus"],
            "RUN_STATUS_RETURN_PENDING"
        );
        assert_eq!(summary["collaboration"]["returnPendingSteps"], 1);
        assert_eq!(summary["collaboration"]["returnedSteps"], 1);
    }
}
