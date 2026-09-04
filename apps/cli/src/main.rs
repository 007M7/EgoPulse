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
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use egopulse_client_kernel::KernelError;
use egopulse_client_operations::{
    ApprovalWatch, ApprovalWatchClassification, ApprovalWatchCursor, ApprovalWatchUpdate,
    AttachError, ClientApprovalWatchError, ClientAttachment, ClientContextRevokeError,
    ClientGovernedTaskError, ClientGuidedApprovalDecisionError, ClientGuidedWorkError,
    ClientHarnessContentError, ClientTaskResultReviewError, ClientWorkError, ContextRevokeInput,
    GovernedHoldReason, GovernedProjectionPosition, GovernedProjectionReason,
    GovernedStateComposite, GovernedStateDomain, GovernedStateDomainPhase, GovernedStateReason,
    GovernedStateSession, GovernedTaskBaseline, GovernedTaskSession, GovernedTaskState,
    GovernedTaskUpdate, GuidedApprovalDecision, GuidedApprovalDecisionInput,
    GuidedWorkConfirmationAttempt, GuidedWorkInput, GuidedWorkPreparationAttempt,
    GuidedWorkPreview, GuidedWorkSource, HarnessContentFilter, HarnessContentSession,
    HarnessContentUpdate, HarnessContentUpdateKind, TaskResultReview, TaskResultReviewStage,
    TaskWatchClassification, attach as attach_client, command_metadata, set_task_digest,
    set_verdict_digest, timestamp_after, validate_guided_work_input,
};
use egopulse_director_facade::{
    ContextAuthority, ContextSourceInput, DirectorInput, build_event_packet_preview,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactSemanticClass, ArtifactSetStatus, ArtifactStatus, ClaimSourceType, ClaimStatus,
        ContentAddress, EvidenceProducerClass, EvidenceRelation, EvidenceStatus, HashAlgorithm,
        IntegrityStatus,
    },
    collaboration::v1::{RunStatus, StepStatus},
    common::v1::ContractReference,
    harness::v1::{
        ContentMutationOperation, HarnessContentLimitKind, HarnessContentMarkerKind,
        HarnessContentSafetyFlag, LifecycleKind, SideEffectCertainty,
    },
    localapi::v1::{
        AwaitProjectionRequest, ClientSurface, ContextGovernanceState,
        ExecuteFounderVerdictRequest, ExecuteMemoryMutationRequest, ExecuteTaskCommandRequest,
        GetEvidenceGraphRequest, GetHarnessApprovalViewRequest, GetProjectionStatusRequest,
        GetTaskViewRequest, HarnessContentPosition, HarnessContentRecordView,
        ListHarnessApprovalViewsRequest, ListTaskViewsRequest, LocalApiError, LocalApiErrorCode,
        MemoryMutationCommand, MemoryMutationReceipt, ProjectionAwaitToken, ProjectionHealth,
        ProjectionMetadata, RetrieveMemoryRequest, SourceDomain, SourceRevision, TaskView,
        await_projection_response, get_evidence_graph_response, get_harness_approval_view_response,
        get_task_view_response, harness_artifact_relation_view, harness_content_record_view,
        memory_mutation_command, retrieve_memory_response,
    },
    policy::v1::PolicyDecisionErrorCode,
    task::v1::{
        ApplyFounderVerdictCommand, CreateTaskCommand, RequestTaskCancellationCommand, TaskCommand,
        TaskErrorCode, TaskStatus, task_command, task_command_result,
    },
    verdict::v1::{
        FounderVerdictDecision, FounderVerdictStateKind, IssueFounderVerdictCommand,
        RevokeFounderVerdictCommand, RiskCategory, VerdictCommand, VerdictErrorCode, VerdictScope,
        verdict_command,
    },
    verification::v1::{
        CheckerAssuranceClass, CriterionOutcome, CriterionRequirement, DiscrepancySeverity,
        EvidenceCoverage, UnverifiedReason, VerificationConclusion,
    },
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
    /// Watch the independent governed Task and Approval state domains.
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    /// Read the independent governed Harness-content stream for one Task.
    Content {
        #[command(subcommand)]
        command: ContentCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ContentCommand {
    /// Print the fixed baseline, then stream source-labelled safe records.
    Watch {
        task_id: String,
        /// Restrict to an Attempt. Repeat to select multiple Attempts.
        #[arg(long = "attempt-id")]
        attempt_ids: Vec<String>,
        /// Stop after this many live frames; omit to run until Ctrl+C.
        #[arg(long)]
        frames: Option<u32>,
        /// Emit one stable JSON object per line (NDJSON).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum StateCommand {
    /// Emit an initial safe composite and a bounded number of domain updates.
    Watch {
        #[arg(long)]
        updates: u32,
        #[arg(long)]
        json: bool,
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
    /// Prepare and explicitly confirm one governed work request.
    Start {
        #[arg(long)]
        intent: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        work_type: String,
        #[arg(long = "context-ref", required = true)]
        context_refs: Vec<String>,
        /// Explicitly confirm after the safe preview (required without a TTY).
        #[arg(long, conflicts_with = "cancel")]
        confirm: bool,
        /// Cancel before attachment or preparation; no RPC is sent.
        #[arg(long, conflicts_with = "confirm")]
        cancel: bool,
        #[arg(long)]
        json: bool,
    },
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
    /// Review projected result metadata and governance evidence.
    Review {
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

    fn projection_not_caught_up() -> Self {
        Self {
            exit_code: 7,
            reason_code: "PROJECTION_NOT_CAUGHT_UP",
            message:
                "the current complete Task baseline has not reached the requested minimum position"
                    .to_owned(),
            category: "projection",
            retryable: true,
            required_action_code: Some("WAIT_FOR_PROJECTION".to_owned()),
            safe_fingerprint: None,
            operation: "task.watch",
        }
    }

    fn reset_required() -> Self {
        Self {
            exit_code: 7,
            reason_code: "RESET_REQUIRED",
            message: "Task watch exceeded the bounded projection reset recovery budget; rerun the command"
                .to_owned(),
            category: "projection",
            retryable: true,
            required_action_code: Some("REFETCH_PROJECTION".to_owned()),
            safe_fingerprint: None,
            operation: "task.watch",
        }
    }

    fn task_watch_session_changed() -> Self {
        Self {
            exit_code: 5,
            reason_code: "SESSION_CHANGED",
            message: "the authenticated Task watch session expired; rerun the command".to_owned(),
            category: "contract",
            retryable: false,
            required_action_code: Some("REATTACH_SESSION".to_owned()),
            safe_fingerprint: None,
            operation: "task.watch",
        }
    }

    fn content_reset_required() -> Self {
        Self {
            exit_code: 7,
            reason_code: "CONTENT_RESET_REQUIRED",
            message:
                "Harness content exceeded the bounded reset recovery budget; rerun the command"
                    .to_owned(),
            category: "projection",
            retryable: true,
            required_action_code: Some("REFETCH_CONTENT_BASELINE".to_owned()),
            safe_fingerprint: None,
            operation: "content.watch",
        }
    }

    fn content_session_changed() -> Self {
        Self {
            exit_code: 5,
            reason_code: "SESSION_CHANGED",
            message: "the authenticated Harness-content session expired; rerun the command"
                .to_owned(),
            category: "contract",
            retryable: false,
            required_action_code: Some("REATTACH_SESSION".to_owned()),
            safe_fingerprint: None,
            operation: "content.watch",
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
    let result = dispatch_command(cli.command).await;
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

type CliCommandFuture = Pin<Box<dyn Future<Output = Result<(), CliFailure>>>>;

/// Erase every selected command future before it enters Tokio's main future.
/// This keeps the sum of unrelated CLI state machines from consuming the
/// Windows main-thread stack and makes adding a long-lived stream independent
/// of the stack needs of existing commands.
fn dispatch_command(command: Command) -> CliCommandFuture {
    match command {
        Command::Status { json } => Box::pin(status(json)),
        Command::Await {
            token_json,
            timeout_milliseconds,
            json,
        } => Box::pin(await_projection(token_json, timeout_milliseconds, json)),
        Command::Task { command } => Box::pin(task(command)),
        Command::Evidence { command } => Box::pin(evidence(command)),
        Command::Approval { command } => Box::pin(approval(command)),
        Command::Verdict { command } => Box::pin(verdict(command)),
        Command::Memory { command } => Box::pin(memory(command)),
        Command::Work { command } => Box::pin(work(command)),
        Command::Context { command } => Box::pin(context(command)),
        Command::State { command } => Box::pin(state(command)),
        Command::Content { command } => Box::pin(content(command)),
    }
}

fn command_json(command: &Command) -> bool {
    match command {
        Command::Status { json }
        | Command::Await { json, .. }
        | Command::Task {
            command:
                TaskCommandCli::Get { json, .. }
                | TaskCommandCli::Review { json, .. }
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
                | WorkCommand::Start { json, .. }
                | WorkCommand::Prepare { json, .. }
                | WorkCommand::Confirm { json, .. },
        }
        | Command::Context {
            command: ContextCommand::Revoke { json, .. },
        }
        | Command::State {
            command: StateCommand::Watch { json, .. },
        }
        | Command::Content {
            command: ContentCommand::Watch { json, .. },
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
        WorkCommand::Start {
            intent,
            scope,
            work_type,
            context_refs,
            confirm,
            cancel,
            json,
        } => {
            guided_work_start(
                GuidedWorkInput {
                    intent,
                    work_type,
                    target_scope_ref: scope,
                    sources: context_refs
                        .into_iter()
                        .map(|source_ref| GuidedWorkSource {
                            label: source_ref.clone(),
                            source_ref,
                        })
                        .collect(),
                },
                confirm,
                cancel,
                json,
            )
            .await
        }
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

async fn guided_work_start(
    input: GuidedWorkInput,
    explicit_confirm: bool,
    explicit_cancel: bool,
    json_output: bool,
) -> Result<(), CliFailure> {
    let mode = guided_work_start_mode(
        &input,
        explicit_confirm,
        explicit_cancel,
        json_output,
        io::stdin().is_terminal() && io::stdout().is_terminal(),
    )?;
    if mode == GuidedWorkStartMode::Cancel {
        render_guided_work_cancelled(json_output);
        return Ok(());
    }
    if mode == GuidedWorkStartMode::Interactive
        && !bounded_confirmation_prompt(
            "Type PREVIEW to prepare the governed preview, or press Enter to cancel: ",
            "PREVIEW",
            Duration::from_secs(60),
        )?
    {
        render_guided_work_cancelled(json_output);
        return Ok(());
    }

    let attached = attach("work.start").await?;
    let prepared = match attached
        .0
        .prepare_guided_work(input)
        .await
        .map_err(guided_work_failure)?
    {
        GuidedWorkPreparationAttempt::Prepared(prepared) => *prepared,
        GuidedWorkPreparationAttempt::OutcomeUnknown(recovery) => attached
            .0
            .replay_guided_work_preparation(&recovery)
            .await
            .map_err(guided_work_failure)?,
    };
    render_guided_work_preview(prepared.preview(), false);

    if mode == GuidedWorkStartMode::Interactive
        && !bounded_confirmation_prompt(
            "Type CONFIRM to create the Task, or press Enter to cancel: ",
            "CONFIRM",
            Duration::from_secs(60),
        )?
    {
        render_guided_work_cancelled(json_output);
        return Ok(());
    }

    let confirmed = match attached
        .0
        .confirm_guided_work(prepared)
        .await
        .map_err(guided_work_failure)?
    {
        GuidedWorkConfirmationAttempt::Confirmed(confirmed) => *confirmed,
        GuidedWorkConfirmationAttempt::OutcomeUnknown(recovery) => attached
            .0
            .replay_guided_work_confirmation(&recovery)
            .await
            .map_err(guided_work_failure)?,
    };
    let task = match confirmed.result.outcome {
        Some(task_command_result::Outcome::Task(task)) => task,
        _ => {
            return Err(CliFailure::protocol("guided work task outcome missing")
                .for_operation("work.start"));
        }
    };
    let status = TaskStatus::try_from(task.status)
        .map(|status| status.as_str_name())
        .unwrap_or("TASK_STATUS_UNSPECIFIED");
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "work.start",
                "data": {
                    "createdTaskId": task.task_id,
                    "revision": task.revision,
                    "status": status,
                    "replayed": confirmed.result.replayed,
                    "awaitToken": await_token_json(confirmed.await_token),
                },
                "correlationId": Uuid::now_v7().to_string(),
            }))
            .unwrap()
        );
    } else {
        println!(
            "Work started: task={} revision={} status={} replayed={}",
            task.task_id, task.revision, status, confirmed.result.replayed
        );
        println!("Next: egopulse task watch --frames 1");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuidedWorkStartMode {
    Cancel,
    ExplicitConfirm,
    Interactive,
}

fn guided_work_start_mode(
    input: &GuidedWorkInput,
    explicit_confirm: bool,
    explicit_cancel: bool,
    json_output: bool,
    interactive_terminal: bool,
) -> Result<GuidedWorkStartMode, CliFailure> {
    validate_guided_work_input(input).map_err(guided_work_failure)?;
    if explicit_confirm && explicit_cancel {
        return Err(
            CliFailure::protocol("--confirm and --cancel conflict").for_operation("work.start")
        );
    }
    if explicit_cancel {
        return Ok(GuidedWorkStartMode::Cancel);
    }
    if explicit_confirm {
        return Ok(GuidedWorkStartMode::ExplicitConfirm);
    }
    if json_output || !interactive_terminal {
        return Err(CliFailure::protocol(
            "non-interactive work start requires --confirm or --cancel",
        )
        .for_operation("work.start"));
    }
    Ok(GuidedWorkStartMode::Interactive)
}

fn bounded_confirmation_prompt(
    prompt: &'static str,
    expected: &'static str,
    timeout: Duration,
) -> Result<bool, CliFailure> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|error| {
        CliFailure::protocol(format!("confirmation prompt failed: {error}"))
            .for_operation("work.start")
    })?;
    let _raw_mode = RawModeGuard::enter().map_err(|error| {
        CliFailure::protocol(format!("confirmation terminal setup failed: {error}"))
            .for_operation("work.start")
    })?;
    let deadline = Instant::now() + timeout;
    let mut value = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero()
            || !event::poll(remaining).map_err(|error| {
                CliFailure::protocol(format!("confirmation input polling failed: {error}"))
                    .for_operation("work.start")
            })?
        {
            return Err(CliFailure::protocol(
                "confirmation input timed out before Task confirmation was sent",
            )
            .for_operation("work.start"));
        }
        let Event::Key(key) = event::read().map_err(|error| {
            CliFailure::protocol(format!("confirmation input failed: {error}"))
                .for_operation("work.start")
        })?
        else {
            continue;
        };
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }
        match apply_confirmation_key(&mut value, expected, key) {
            ConfirmationKeyAction::Continue(Some(character)) => {
                eprint!("{character}");
                io::stderr().flush().map_err(|error| {
                    CliFailure::protocol(format!("confirmation prompt failed: {error}"))
                        .for_operation("work.start")
                })?;
            }
            ConfirmationKeyAction::Continue(None) => {}
            ConfirmationKeyAction::Backspace => {
                eprint!("\u{8} \u{8}");
                io::stderr().flush().map_err(|error| {
                    CliFailure::protocol(format!("confirmation prompt failed: {error}"))
                        .for_operation("work.start")
                })?;
            }
            ConfirmationKeyAction::Submit(confirmed) => {
                eprintln!();
                return Ok(confirmed);
            }
            ConfirmationKeyAction::Cancel => {
                eprintln!();
                return Ok(false);
            }
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationKeyAction {
    Continue(Option<char>),
    Backspace,
    Submit(bool),
    Cancel,
}

fn apply_confirmation_key(
    value: &mut String,
    expected: &str,
    key: KeyEvent,
) -> ConfirmationKeyAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return ConfirmationKeyAction::Cancel;
    }
    match key.code {
        KeyCode::Esc => ConfirmationKeyAction::Cancel,
        KeyCode::Enter => ConfirmationKeyAction::Submit(value == expected),
        KeyCode::Backspace => {
            if value.pop().is_some() {
                ConfirmationKeyAction::Backspace
            } else {
                ConfirmationKeyAction::Continue(None)
            }
        }
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                && !character.is_control()
                && value.len() < 64 =>
        {
            value.push(character);
            ConfirmationKeyAction::Continue(Some(character))
        }
        _ => ConfirmationKeyAction::Continue(None),
    }
}

fn render_guided_work_preview(preview: &GuidedWorkPreview, json_output: bool) {
    let value = guided_work_preview_json(preview);
    if json_output {
        println!("{}", serde_json::to_string(&value).unwrap());
    } else {
        eprintln!(
            "Governed preview: intent={} work_type={} scope={} included_sources={} excluded_sources={} gate_ready={} founder_confirmable={}",
            preview.normalized_intent(),
            preview.work_type(),
            preview.target_scope_ref(),
            preview.included_source_count(),
            preview.excluded_source_count(),
            preview.gate_ready(),
            preview.ready_for_founder_confirmation(),
        );
        for non_goal in preview.non_goals() {
            eprintln!("Non-goal: {}", non_goal.as_str());
        }
        for blocker in preview.blockers() {
            eprintln!("Blocker: {}", blocker.as_str());
        }
    }
}

fn guided_work_preview_json(preview: &GuidedWorkPreview) -> serde_json::Value {
    let non_goals = preview
        .non_goals()
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    let blocker_codes = preview
        .blockers()
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    guided_work_preview_value(
        preview.normalized_intent(),
        preview.work_type(),
        preview.target_scope_ref(),
        &non_goals,
        preview.included_source_count(),
        preview.excluded_source_count(),
        preview.gate_ready(),
        preview.ready_for_founder_confirmation(),
        &blocker_codes,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn guided_work_preview_value(
    normalized_intent: &str,
    work_type: &str,
    target_scope_ref: &str,
    non_goals: &[String],
    included_source_count: usize,
    excluded_source_count: usize,
    gate_ready: bool,
    ready_for_founder_confirmation: bool,
    blocker_codes: &[String],
    warning_codes: &[String],
) -> serde_json::Value {
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "work.start.preview",
        "data": {
            "normalizedIntent": normalized_intent,
            "workType": work_type,
            "targetScopeRef": target_scope_ref,
            "nonGoals": non_goals,
            "includedSourceCount": included_source_count,
            "excludedSourceCount": excluded_source_count,
            "gateReady": gate_ready,
            "readyForFounderConfirmation": ready_for_founder_confirmation,
            "blockerCodes": blocker_codes,
            "warningCodes": warning_codes,
        }
    })
}

fn render_guided_work_cancelled(json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "schemaVersion": "egopulse.cli-result/v0.1",
                "ok": true,
                "operation": "work.start",
                "data": { "cancelled": true, "taskCreated": false },
                "correlationId": Uuid::now_v7().to_string(),
            }))
            .unwrap()
        );
    } else {
        println!("Work start cancelled; no Task confirmation was sent.");
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

fn guided_work_failure(error: ClientGuidedWorkError) -> CliFailure {
    match error {
        ClientGuidedWorkError::Kernel(KernelError::PermissionDenied(_)) => {
            CliFailure::permission("work.start", "guided work permission denied")
        }
        ClientGuidedWorkError::Kernel(error) => {
            CliFailure::protocol(error.to_string()).for_operation("work.start")
        }
        ClientGuidedWorkError::InvalidInput(detail) => {
            CliFailure::protocol(detail).for_operation("work.start")
        }
        ClientGuidedWorkError::Blocked => {
            CliFailure::protocol("the governed preview is blocked; no Task confirmation was sent")
                .for_operation("work.start")
        }
        ClientGuidedWorkError::SessionChanged | ClientGuidedWorkError::BindingChanged => {
            CliFailure::protocol("the prepared work binding is stale; prepare a new preview")
                .for_operation("work.start")
        }
        ClientGuidedWorkError::PreparationOutcomeUnknown(_) => CliFailure::daemon_unavailable(
            "guided work preparation outcome remains unknown; do not prepare a replacement",
        )
        .for_operation("work.start"),
        ClientGuidedWorkError::ConfirmationOutcomeUnknown(_) => CliFailure::daemon_unavailable(
            "guided work confirmation outcome remains unknown; do not prepare a replacement",
        )
        .for_operation("work.start"),
        ClientGuidedWorkError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("work.start")
        }
        ClientGuidedWorkError::Authority {
            error_code,
            safe_detail_code,
        } => CliFailure::task_authority(error_code, safe_detail_code, "work.start"),
        ClientGuidedWorkError::Protocol(detail) => {
            CliFailure::protocol(detail).for_operation("work.start")
        }
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedStatePosition {
    epoch: String,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedStateTask {
    task_id: String,
    revision: u64,
    status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedStateApproval {
    approval_request_id: String,
    task_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedTaskDomain {
    phase: GovernedStateDomainPhase,
    reason: Option<GovernedStateReason>,
    position: Option<CliGovernedStatePosition>,
    recovery_remaining: u32,
    recovery_limit: u32,
    generation: u64,
    tasks: Vec<CliGovernedStateTask>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedApprovalDomain {
    phase: GovernedStateDomainPhase,
    reason: Option<GovernedStateReason>,
    position: Option<CliGovernedStatePosition>,
    recovery_remaining: u32,
    recovery_limit: u32,
    generation: u64,
    approvals: Vec<CliGovernedStateApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliGovernedStateView {
    task: CliGovernedTaskDomain,
    approval: CliGovernedApprovalDomain,
}

impl CliGovernedStateView {
    fn from_composite(state: &GovernedStateComposite) -> Self {
        let task = state.task();
        let approval = state.approval();
        Self {
            task: CliGovernedTaskDomain {
                phase: task.phase(),
                reason: task.reason(),
                position: task.position().map(|position| CliGovernedStatePosition {
                    epoch: position.epoch().to_owned(),
                    sequence: position.sequence(),
                }),
                recovery_remaining: task.recovery_remaining(),
                recovery_limit: task.recovery_limit(),
                generation: task.generation(),
                tasks: task
                    .tasks()
                    .into_iter()
                    .map(|task| CliGovernedStateTask {
                        task_id: task.task_id.clone(),
                        revision: task.revision,
                        status: task.status.as_str_name().to_ascii_lowercase(),
                    })
                    .collect(),
            },
            approval: CliGovernedApprovalDomain {
                phase: approval.phase(),
                reason: approval.reason(),
                position: approval
                    .position()
                    .map(|position| CliGovernedStatePosition {
                        epoch: position.epoch().to_owned(),
                        sequence: position.sequence(),
                    }),
                recovery_remaining: approval.recovery_remaining(),
                recovery_limit: approval.recovery_limit(),
                generation: approval.generation(),
                approvals: approval
                    .approvals()
                    .into_iter()
                    .map(|approval| CliGovernedStateApproval {
                        approval_request_id: approval.approval_request_id().to_owned(),
                        task_id: approval.task_id().to_owned(),
                    })
                    .collect(),
            },
        }
    }
}

trait CliGovernedStateSession {
    fn safe_state(&self) -> CliGovernedStateView;

    fn next_domain_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + '_>>;

    fn shutdown(self) -> Pin<Box<dyn Future<Output = ()>>>
    where
        Self: Sized;
}

impl CliGovernedStateSession for GovernedStateSession {
    fn safe_state(&self) -> CliGovernedStateView {
        CliGovernedStateView::from_composite(self.state())
    }

    fn next_domain_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + '_>> {
        Box::pin(async move {
            GovernedStateSession::next_update(self)
                .await
                .map(|update| update.domain())
        })
    }

    fn shutdown(self) -> Pin<Box<dyn Future<Output = ()>>> {
        Box::pin(async move {
            let _ = GovernedStateSession::shutdown(self).await;
        })
    }
}

async fn consume_governed_state_watch<Session, Stop, Render>(
    mut session: Session,
    updates: u32,
    stop: Stop,
    mut render: Render,
) -> Result<(), CliFailure>
where
    Session: CliGovernedStateSession,
    Stop: Future<Output = ()>,
    Render:
        FnMut(u32, Option<GovernedStateDomain>, &CliGovernedStateView) -> Result<(), CliFailure>,
{
    if let Err(error) = render(0, None, &session.safe_state()) {
        session.shutdown().await;
        return Err(error);
    }
    tokio::pin!(stop);
    let mut emitted = 0_u32;
    while emitted < updates {
        let update = tokio::select! {
            biased;
            () = &mut stop => None,
            update = session.next_domain_update() => update,
        };
        let Some(update) = update else {
            break;
        };
        emitted += 1;
        if let Err(error) = render(emitted, Some(update), &session.safe_state()) {
            session.shutdown().await;
            return Err(error);
        }
    }
    session.shutdown().await;
    Ok(())
}

fn validate_governed_state_watch_updates(updates: u32) -> Result<(), CliFailure> {
    if !(1..=1000).contains(&updates) {
        return Err(
            CliFailure::protocol("updates must be between 1 and 1000").for_operation("state.watch")
        );
    }
    Ok(())
}

async fn state(command: StateCommand) -> Result<(), CliFailure> {
    match command {
        StateCommand::Watch { updates, json } => state_watch(updates, json).await,
    }
}

async fn state_watch(updates: u32, json_output: bool) -> Result<(), CliFailure> {
    validate_governed_state_watch_updates(updates)?;
    let attached = attach("state.watch").await?;
    let attachment = Arc::new(attached.0);
    let session = attachment.start_governed_state_session().map_err(|_| {
        CliFailure::daemon_unavailable("governed state runtime is unavailable")
            .for_operation("state.watch")
    })?;
    consume_governed_state_watch(
        session,
        updates,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        |index, changed_domain, state| {
            render_governed_state_record(index, changed_domain, state, json_output)
        },
    )
    .await
}

fn governed_state_domain_name(domain: GovernedStateDomain) -> &'static str {
    match domain {
        GovernedStateDomain::Task => "task",
        GovernedStateDomain::Approval => "approval",
    }
}

fn governed_state_phase_name(phase: GovernedStateDomainPhase) -> &'static str {
    match phase {
        GovernedStateDomainPhase::Connecting => "connecting",
        GovernedStateDomainPhase::Live => "live",
        GovernedStateDomainPhase::Stale => "stale",
        GovernedStateDomainPhase::ResetRequired => "reset_required",
        GovernedStateDomainPhase::Fatal => "fatal",
    }
}

fn governed_state_reason_name(reason: GovernedStateReason) -> &'static str {
    match reason {
        GovernedStateReason::SessionUnavailable => "session_unavailable",
        GovernedStateReason::PermissionDenied => "permission_denied",
        GovernedStateReason::ApiRejected => "api_rejected",
        GovernedStateReason::TransportUnavailable => "transport_unavailable",
        GovernedStateReason::UnexpectedEof => "unexpected_eof",
        GovernedStateReason::ProjectionResetRequired => "projection_reset_required",
        GovernedStateReason::ProjectionIntegrityFailure => "projection_integrity_failure",
        GovernedStateReason::BaselineLimitExceeded => "baseline_limit_exceeded",
        GovernedStateReason::RecoveryExhausted => "recovery_exhausted",
    }
}

fn governed_state_position_json(position: Option<&CliGovernedStatePosition>) -> serde_json::Value {
    position.map_or(
        serde_json::Value::Null,
        |position| json!({"epoch": position.epoch, "sequence": position.sequence}),
    )
}

fn governed_state_record_json(
    index: u32,
    changed_domain: Option<GovernedStateDomain>,
    state: &CliGovernedStateView,
) -> serde_json::Value {
    let kind = if index == 0 && changed_domain.is_none() {
        "initial"
    } else {
        "update"
    };
    json!({
        "schemaVersion": "egopulse.governed-state.v1",
        "kind": kind,
        "updateIndex": index,
        "indexSemantics": "client-local",
        "changedDomain": changed_domain.map(governed_state_domain_name),
        "task": {
            "phase": governed_state_phase_name(state.task.phase),
            "reason": state.task.reason.map(governed_state_reason_name),
            "position": governed_state_position_json(state.task.position.as_ref()),
            "recovery": {
                "remaining": state.task.recovery_remaining,
                "limit": state.task.recovery_limit,
            },
            "generation": state.task.generation,
            "tasks": state.task.tasks.iter().map(|task| json!({
                "taskId": task.task_id,
                "revision": task.revision,
                "status": task.status,
            })).collect::<Vec<_>>(),
        },
        "approval": {
            "phase": governed_state_phase_name(state.approval.phase),
            "reason": state.approval.reason.map(governed_state_reason_name),
            "position": governed_state_position_json(state.approval.position.as_ref()),
            "recovery": {
                "remaining": state.approval.recovery_remaining,
                "limit": state.approval.recovery_limit,
            },
            "generation": state.approval.generation,
            "approvals": state.approval.approvals.iter().map(|approval| json!({
                "approvalRequestId": approval.approval_request_id,
                "taskId": approval.task_id,
            })).collect::<Vec<_>>(),
        },
    })
}

fn governed_state_record_text(
    index: u32,
    changed_domain: Option<GovernedStateDomain>,
    state: &CliGovernedStateView,
) -> String {
    fn position_text(position: Option<&CliGovernedStatePosition>) -> String {
        position.map_or_else(
            || "none".to_owned(),
            |position| format!("{}:{}", position.epoch, position.sequence),
        )
    }

    let kind = if index == 0 && changed_domain.is_none() {
        "initial"
    } else {
        "update"
    };
    let mut output = format!(
        "Governed state kind={kind} update_index={index} changed_domain={}\nIndependent domain positions; this is not an atomic or global cursor.\nTask domain: phase={} reason={} position={} generation={} recovery={}/{}\n",
        changed_domain
            .map(governed_state_domain_name)
            .unwrap_or("none"),
        governed_state_phase_name(state.task.phase),
        state
            .task
            .reason
            .map(governed_state_reason_name)
            .unwrap_or("none"),
        position_text(state.task.position.as_ref()),
        state.task.generation,
        state.task.recovery_remaining,
        state.task.recovery_limit,
    );
    for task in &state.task.tasks {
        output.push_str(&format!(
            "  Task {} revision={} status={}\n",
            task.task_id, task.revision, task.status
        ));
    }
    output.push_str(&format!(
        "Approval domain: phase={} reason={} position={} generation={} recovery={}/{}\n",
        governed_state_phase_name(state.approval.phase),
        state
            .approval
            .reason
            .map(governed_state_reason_name)
            .unwrap_or("none"),
        position_text(state.approval.position.as_ref()),
        state.approval.generation,
        state.approval.recovery_remaining,
        state.approval.recovery_limit,
    ));
    for approval in &state.approval.approvals {
        output.push_str(&format!(
            "  Approval {} task={}\n",
            approval.approval_request_id, approval.task_id
        ));
    }
    output.trim_end().to_owned()
}

fn render_governed_state_record(
    index: u32,
    changed_domain: Option<GovernedStateDomain>,
    state: &CliGovernedStateView,
    json_output: bool,
) -> Result<(), CliFailure> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    write_governed_state_record(&mut writer, index, changed_domain, state, json_output)
}

fn write_governed_state_record<Writer: Write>(
    writer: &mut Writer,
    index: u32,
    changed_domain: Option<GovernedStateDomain>,
    state: &CliGovernedStateView,
    json_output: bool,
) -> Result<(), CliFailure> {
    let rendered = if json_output {
        serde_json::to_string(&governed_state_record_json(index, changed_domain, state)).map_err(
            |_| {
                CliFailure::protocol("governed state record serialization failed")
                    .for_operation("state.watch")
            },
        )?
    } else {
        governed_state_record_text(index, changed_domain, state)
    };
    writeln!(writer, "{rendered}").map_err(|_| {
        CliFailure::protocol("governed state output failed").for_operation("state.watch")
    })
}

const MAX_CONTENT_WATCH_FRAMES: u32 = 1_000;
const MAX_CONTENT_WATCH_REBASES: u32 = 3;

async fn content(command: ContentCommand) -> Result<(), CliFailure> {
    match command {
        ContentCommand::Watch {
            task_id,
            attempt_ids,
            frames,
            json,
        } => Box::pin(content_watch(task_id, attempt_ids, frames, json)).await,
    }
}

async fn content_watch(
    task_id: String,
    attempt_ids: Vec<String>,
    frames: Option<u32>,
    json_output: bool,
) -> Result<(), CliFailure> {
    if frames.is_some_and(|value| value == 0 || value > MAX_CONTENT_WATCH_FRAMES) {
        return Err(CliFailure::protocol("frames must be between 1 and 1000")
            .for_operation("content.watch"));
    }
    let filter =
        HarnessContentFilter::new(task_id, attempt_ids).map_err(harness_content_failure)?;
    let attached = attach("content.watch").await?;
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    let mut emitted = 0_u32;
    let mut rebases = 0_u32;

    loop {
        let mut session = attached
            .0
            .open_harness_content_session(filter.clone())
            .await
            .map_err(harness_content_failure)?;
        render_content_baseline(&session, rebases, json_output)?;

        loop {
            if frames.is_some_and(|limit| emitted >= limit) {
                return Ok(());
            }
            let update = tokio::select! {
                biased;
                _ = &mut stop => return Ok(()),
                result = session.next_update() => result.map_err(harness_content_failure)?,
            };
            render_content_update(&update, rebases, json_output)?;
            emitted += 1;
            if update.kind == HarnessContentUpdateKind::ResetRequired {
                if frames.is_some_and(|limit| emitted >= limit) {
                    return Ok(());
                }
                if rebases == MAX_CONTENT_WATCH_REBASES {
                    return Err(CliFailure::content_reset_required());
                }
                rebases += 1;
                break;
            }
        }
    }
}

fn render_content_baseline(
    session: &HarnessContentSession,
    generation: u32,
    json_output: bool,
) -> Result<(), CliFailure> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    for record in session.records() {
        write_content_record(
            &mut writer,
            "baseline_record",
            generation,
            session.position(),
            record,
            json_output,
        )?;
    }
    write_content_control(
        &mut writer,
        "baseline_complete",
        generation,
        session.position(),
        session.records().len(),
        session.assistant_messages().len(),
        None,
        json_output,
    )
}

fn render_content_update(
    update: &HarnessContentUpdate,
    generation: u32,
    json_output: bool,
) -> Result<(), CliFailure> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    if !update.records.is_empty() {
        for record in &update.records {
            write_content_record(
                &mut writer,
                "record",
                generation,
                &update.position,
                record,
                json_output,
            )?;
        }
        return Ok(());
    }
    let event = match (update.kind, update.disposition) {
        (HarnessContentUpdateKind::Heartbeat, _) => "heartbeat",
        (HarnessContentUpdateKind::ResetRequired, _) => "reset_required",
        (HarnessContentUpdateKind::Records, egopulse_client_kernel::StreamApply::Replay) => {
            "replay"
        }
        _ => "record_applied",
    };
    write_content_control(
        &mut writer,
        event,
        generation,
        &update.position,
        0,
        update.changed_messages.len(),
        update.reset_reason.map(|reason| reason.as_str_name()),
        json_output,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_content_control<Writer: Write>(
    writer: &mut Writer,
    event: &'static str,
    generation: u32,
    position: &HarnessContentPosition,
    record_count: usize,
    message_count: usize,
    reset_reason: Option<&'static str>,
    json_output: bool,
) -> Result<(), CliFailure> {
    if json_output {
        let value = json!({
            "schemaVersion": "egopulse.cli.harness-content/v1",
            "event": event,
            "generation": generation,
            "contentPosition": content_position_json(position),
            "recordCount": record_count,
            "assembledMessageCount": message_count,
            "resetReason": reset_reason,
        });
        writeln!(writer, "{}", serde_json::to_string(&value).unwrap())
    } else {
        writeln!(
            writer,
            "Harness content {event}: generation={generation} position={}:{} records={record_count} messages={message_count}{}",
            position.epoch,
            position.sequence,
            reset_reason.map_or_else(String::new, |reason| format!(" reason={reason}")),
        )
    }
    .map_err(|_| {
        CliFailure::protocol("Harness-content output failed").for_operation("content.watch")
    })
}

fn write_content_record<Writer: Write>(
    writer: &mut Writer,
    event: &'static str,
    generation: u32,
    position: &HarnessContentPosition,
    record: &HarnessContentRecordView,
    json_output: bool,
) -> Result<(), CliFailure> {
    if json_output {
        let value = json!({
            "schemaVersion": "egopulse.cli.harness-content/v1",
            "event": event,
            "generation": generation,
            "contentPosition": content_position_json(position),
            "record": content_record_json(record),
        });
        writeln!(writer, "{}", serde_json::to_string(&value).unwrap())
    } else {
        writeln!(writer, "{}", content_record_text(event, record))
    }
    .map_err(|_| {
        CliFailure::protocol("Harness-content output failed").for_operation("content.watch")
    })
}

fn content_position_json(position: &HarnessContentPosition) -> serde_json::Value {
    json!({
        "epoch": position.epoch,
        "sequence": position.sequence,
        "projectedAt": position.projected_at.as_ref().map(|value| json!({
            "seconds": value.seconds,
            "nanos": value.nanos,
        })),
    })
}

fn content_record_json(record: &HarnessContentRecordView) -> serde_json::Value {
    let payload = match record.payload.as_ref() {
        Some(harness_content_record_view::Payload::AssistantText(value)) => json!({
            "kind": "assistant_text",
            "safeMessageId": value.safe_message_id,
            "revision": value.revision,
            "previousRevision": value.previous_revision,
            "operation": ContentMutationOperation::try_from(value.operation)
                .map(|item| item.as_str_name())
                .unwrap_or("CONTENT_MUTATION_OPERATION_UNKNOWN"),
            "safeText": value.safe_text_utf8,
            "safeCumulativeDigestSha256": value.safe_cumulative_digest_sha256,
            "partIndex": value.part_index,
            "partCount": value.part_count,
            "provisional": value.provisional,
        }),
        Some(harness_content_record_view::Payload::Lifecycle(value)) => json!({
            "kind": "lifecycle",
            "lifecycle": LifecycleKind::try_from(value.kind)
                .map(|item| item.as_str_name())
                .unwrap_or("LIFECYCLE_KIND_UNKNOWN"),
            "sideEffectCertainty": SideEffectCertainty::try_from(value.side_effect_certainty)
                .map(|item| item.as_str_name())
                .unwrap_or("SIDE_EFFECT_CERTAINTY_UNKNOWN"),
            "nativeWillRetry": value.native_will_retry,
        }),
        Some(harness_content_record_view::Payload::Usage(value)) => json!({
            "kind": "usage",
            "inputTokens": value.input_tokens,
            "outputTokens": value.output_tokens,
            "cachedInputTokens": value.cached_input_tokens,
        }),
        Some(harness_content_record_view::Payload::ApprovalRequired(_)) => json!({
            "kind": "approval_required",
        }),
        Some(harness_content_record_view::Payload::ArtifactRelation(value)) => {
            let visibility = match value.visibility.as_ref() {
                Some(harness_artifact_relation_view::Visibility::Available(artifact)) => json!({
                    "kind": "available",
                    "artifactId": artifact.artifact_id,
                    "artifactDigestSha256": artifact.artifact_digest_sha256,
                }),
                Some(harness_artifact_relation_view::Visibility::AvailableRedacted(_)) => json!({
                    "kind": "available_redacted",
                }),
                None => serde_json::Value::Null,
            };
            json!({
                "kind": "artifact_relation",
                "safeContentDiffersFromArtifact": value.safe_content_differs_from_artifact,
                "visibility": visibility,
            })
        }
        Some(harness_content_record_view::Payload::Marker(value)) => json!({
            "kind": "marker",
            "marker": HarnessContentMarkerKind::try_from(value.kind)
                .map(|item| item.as_str_name())
                .unwrap_or("HARNESS_CONTENT_MARKER_KIND_UNKNOWN"),
            "limitKind": HarnessContentLimitKind::try_from(value.limit_kind)
                .map(|item| item.as_str_name())
                .unwrap_or("HARNESS_CONTENT_LIMIT_KIND_UNKNOWN"),
        }),
        None => serde_json::Value::Null,
    };
    json!({
        "recordId": record.record_id,
        "recordDigestSha256": record.record_digest_sha256,
        "contentSequence": record.content_sequence,
        "taskId": record.task_id,
        "attemptId": record.attempt_id,
        "source": {
            "providerFamily": record.provider_family_alias,
            "model": record.model_alias,
            "collaborationRole": record.collaboration_role,
        },
        "disclosureProfile": record.disclosure_profile_ref.as_ref().map(|value| json!({
            "contractId": value.contract_id,
            "version": value.version,
            "sha256": value.sha256,
        })),
        "projectedAt": record.projected_at.as_ref().map(|value| json!({
            "seconds": value.seconds,
            "nanos": value.nanos,
        })),
        "safetyFlags": record.safety_flags.iter().map(|raw| {
            HarnessContentSafetyFlag::try_from(*raw)
                .map(|value| value.as_str_name())
                .unwrap_or("HARNESS_CONTENT_SAFETY_FLAG_UNKNOWN")
        }).collect::<Vec<_>>(),
        "payload": payload,
    })
}

fn content_record_text(event: &str, record: &HarnessContentRecordView) -> String {
    let source = format!(
        "{}/{} role={} attempt={}",
        record.provider_family_alias,
        record.model_alias,
        record.collaboration_role,
        record.attempt_id
    );
    match record.payload.as_ref() {
        Some(harness_content_record_view::Payload::AssistantText(value)) => format!(
            "[{source} provisional={}] {event} seq={} revision={} operation={} part={}/{}\n{}",
            value.provisional,
            record.content_sequence,
            value.revision,
            ContentMutationOperation::try_from(value.operation)
                .map(|item| item.as_str_name())
                .unwrap_or("CONTENT_MUTATION_OPERATION_UNKNOWN"),
            value.part_index + 1,
            value.part_count,
            value.safe_text_utf8,
        ),
        Some(harness_content_record_view::Payload::Lifecycle(value)) => format!(
            "[{source}] {event} seq={} lifecycle={} side_effect_certainty={} retry={}",
            record.content_sequence,
            LifecycleKind::try_from(value.kind)
                .map(|item| item.as_str_name())
                .unwrap_or("LIFECYCLE_KIND_UNKNOWN"),
            SideEffectCertainty::try_from(value.side_effect_certainty)
                .map(|item| item.as_str_name())
                .unwrap_or("SIDE_EFFECT_CERTAINTY_UNKNOWN"),
            value
                .native_will_retry
                .map_or_else(|| "unknown".to_owned(), |retry| retry.to_string()),
        ),
        Some(harness_content_record_view::Payload::Usage(value)) => format!(
            "[{source}] {event} seq={} usage input={} output={} cached={}",
            record.content_sequence,
            value.input_tokens,
            value.output_tokens,
            value
                .cached_input_tokens
                .map_or_else(|| "unknown".to_owned(), |tokens| tokens.to_string()),
        ),
        Some(harness_content_record_view::Payload::ApprovalRequired(_)) => format!(
            "[{source}] {event} seq={} approval_required",
            record.content_sequence
        ),
        Some(harness_content_record_view::Payload::ArtifactRelation(value)) => format!(
            "[{source}] {event} seq={} artifact_relation differs={} visibility={}",
            record.content_sequence,
            value.safe_content_differs_from_artifact,
            match value.visibility.as_ref() {
                Some(harness_artifact_relation_view::Visibility::Available(artifact)) => {
                    format!("available:{}", artifact.artifact_id)
                }
                Some(harness_artifact_relation_view::Visibility::AvailableRedacted(_)) => {
                    "available_redacted".to_owned()
                }
                None => "unknown".to_owned(),
            },
        ),
        Some(harness_content_record_view::Payload::Marker(value)) => format!(
            "[{source}] {event} seq={} marker={} limit={}",
            record.content_sequence,
            HarnessContentMarkerKind::try_from(value.kind)
                .map(|item| item.as_str_name())
                .unwrap_or("HARNESS_CONTENT_MARKER_KIND_UNKNOWN"),
            HarnessContentLimitKind::try_from(value.limit_kind)
                .map(|item| item.as_str_name())
                .unwrap_or("HARNESS_CONTENT_LIMIT_KIND_UNKNOWN"),
        ),
        None => format!(
            "[{source}] {event} seq={} invalid_payload",
            record.content_sequence
        ),
    }
}

fn harness_content_failure(error: ClientHarnessContentError) -> CliFailure {
    match error {
        ClientHarnessContentError::Transport(_) => CliFailure::stream_recovery(
            "content.watch",
            "Harness-content transport ended; rerun the command",
        ),
        ClientHarnessContentError::Kernel(KernelError::PermissionDenied(permission)) => {
            CliFailure::permission("content.watch", permission)
        }
        ClientHarnessContentError::Kernel(KernelError::SessionUnavailable) => {
            CliFailure::daemon_unavailable(
                "Harness-content session is unavailable; rerun the command",
            )
            .for_operation("content.watch")
        }
        ClientHarnessContentError::Kernel(KernelError::SessionExpired) => {
            CliFailure::content_session_changed()
        }
        ClientHarnessContentError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("content.watch")
        }
        ClientHarnessContentError::UnexpectedEof => CliFailure::stream_recovery(
            "content.watch",
            "Harness-content watch ended unexpectedly; rerun the command",
        ),
        ClientHarnessContentError::ResetBarrier => CliFailure::content_reset_required(),
        ClientHarnessContentError::BaselineLimitExceeded => {
            CliFailure::protocol("Harness-content baseline exceeded its bounded page limit")
                .for_operation("content.watch")
        }
        ClientHarnessContentError::InvalidInput(detail) => {
            CliFailure::protocol(format!("invalid Harness-content filter: {detail}"))
                .for_operation("content.watch")
        }
        ClientHarnessContentError::Protocol(_) | ClientHarnessContentError::Kernel(_) => {
            CliFailure::protocol("Harness-content integrity validation failed")
                .for_operation("content.watch")
        }
    }
}

async fn task(command: TaskCommandCli) -> Result<(), CliFailure> {
    match command {
        TaskCommandCli::Get { task_id, json } => task_get(task_id, json).await,
        TaskCommandCli::Review { task_id, json } => task_review(task_id, json).await,
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

async fn task_review(task_id: String, json: bool) -> Result<(), CliFailure> {
    let attached = attach("task.review").await?;
    let review = attached
        .0
        .read_task_result_review(&task_id)
        .await
        .map_err(task_result_review_failure)?;
    render_task_result_review(&review, json);
    Ok(())
}

fn task_result_review_failure(error: ClientTaskResultReviewError) -> CliFailure {
    let (stage, failure) = match error {
        ClientTaskResultReviewError::InvalidInput(detail) => {
            return CliFailure::protocol(detail).for_operation("task.review");
        }
        ClientTaskResultReviewError::Kernel { stage, source } => {
            let failure = match source {
                KernelError::PermissionDenied(_) => {
                    CliFailure::permission("task.review", "request access from an administrator")
                }
                other => CliFailure::protocol(other.to_string()),
            };
            (stage, failure)
        }
        ClientTaskResultReviewError::Transport { stage, detail } => {
            (stage, CliFailure::daemon_unavailable(detail))
        }
        ClientTaskResultReviewError::Api { stage, error } => {
            (stage, CliFailure::from_local_api_error(*error))
        }
        ClientTaskResultReviewError::Integrity { stage, detail } => {
            (stage, CliFailure::protocol(detail))
        }
    };
    failure.for_operation(match stage {
        TaskResultReviewStage::Task => "task.review.task",
        TaskResultReviewStage::Evidence => "task.review.evidence",
    })
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
    let mut attached = attach("task.watch").await?;
    consume_governed_task_watch(
        &mut attached,
        frames,
        resume_epoch,
        resume_sequence,
        |record| render_governed_task_watch_record(record, json),
    )
    .await
}

trait CliGovernedTaskBaseline {
    fn position(&self) -> GovernedProjectionPosition;

    fn tasks(&self) -> Vec<GovernedTaskState>;
}

impl CliGovernedTaskBaseline for GovernedTaskBaseline {
    fn position(&self) -> GovernedProjectionPosition {
        self.position().clone()
    }

    fn tasks(&self) -> Vec<GovernedTaskState> {
        self.tasks().into_iter().cloned().collect()
    }
}

trait CliGovernedTaskSession {
    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<GovernedTaskUpdate, ClientGovernedTaskError>> + '_>>;
}

impl CliGovernedTaskSession for GovernedTaskSession {
    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<GovernedTaskUpdate, ClientGovernedTaskError>> + '_>>
    {
        Box::pin(GovernedTaskSession::next_update(self))
    }
}

trait CliGovernedTaskClient {
    type Baseline: CliGovernedTaskBaseline;
    type Session: CliGovernedTaskSession;

    fn read_baseline(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Baseline, ClientGovernedTaskError>> + '_>>;

    fn open_session(
        &mut self,
        baseline: Self::Baseline,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ClientGovernedTaskError>> + '_>>;
}

impl CliGovernedTaskClient for AttachedClient {
    type Baseline = GovernedTaskBaseline;
    type Session = GovernedTaskSession;

    fn read_baseline(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Baseline, ClientGovernedTaskError>> + '_>> {
        Box::pin(self.0.read_governed_task_baseline())
    }

    fn open_session(
        &mut self,
        baseline: Self::Baseline,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ClientGovernedTaskError>> + '_>> {
        Box::pin(self.0.open_governed_task_session(baseline))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CliGovernedTaskWatchRecord {
    ResumeEpochMismatch {
        requested: GovernedProjectionPosition,
        current: GovernedProjectionPosition,
    },
    Baseline {
        position: GovernedProjectionPosition,
        tasks: Vec<GovernedTaskState>,
    },
    Update(GovernedTaskUpdate),
}

const MAX_TASK_WATCH_REBASES: u32 = 3;

async fn consume_governed_task_watch<C, R>(
    client: &mut C,
    frames: u32,
    resume_epoch: Option<String>,
    resume_sequence: Option<u64>,
    mut render: R,
) -> Result<(), CliFailure>
where
    C: CliGovernedTaskClient,
    R: FnMut(&CliGovernedTaskWatchRecord),
{
    validate_task_watch_request(frames, &resume_epoch, resume_sequence)?;
    let mut baseline = client
        .read_baseline()
        .await
        .map_err(governed_task_watch_failure)?;
    let baseline_position = baseline.position();
    if let (Some(requested_epoch), Some(requested_sequence)) =
        (resume_epoch.as_deref(), resume_sequence)
    {
        if requested_epoch == baseline_position.epoch {
            if baseline_position.sequence < requested_sequence {
                return Err(CliFailure::projection_not_caught_up());
            }
        } else {
            render(&CliGovernedTaskWatchRecord::ResumeEpochMismatch {
                requested: GovernedProjectionPosition {
                    epoch: requested_epoch.to_owned(),
                    sequence: requested_sequence,
                },
                current: baseline_position.clone(),
            });
        }
    }
    render(&CliGovernedTaskWatchRecord::Baseline {
        position: baseline_position,
        tasks: baseline.tasks(),
    });
    let mut session = client
        .open_session(baseline)
        .await
        .map_err(governed_task_watch_failure)?;
    let mut emitted = 0_u32;
    let mut rebases = 0_u32;
    while emitted < frames {
        let update = session
            .next_update()
            .await
            .map_err(governed_task_watch_failure)?;
        let reset_required = update.classification == TaskWatchClassification::ResetRequired;
        render(&CliGovernedTaskWatchRecord::Update(update));
        emitted += 1;
        if reset_required {
            drop(session);
            if emitted == frames {
                return Ok(());
            }
            if rebases == MAX_TASK_WATCH_REBASES {
                return Err(CliFailure::reset_required());
            }
            rebases += 1;
            baseline = client
                .read_baseline()
                .await
                .map_err(governed_task_watch_failure)?;
            render(&CliGovernedTaskWatchRecord::Baseline {
                position: baseline.position(),
                tasks: baseline.tasks(),
            });
            session = client
                .open_session(baseline)
                .await
                .map_err(governed_task_watch_failure)?;
        }
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

fn governed_task_watch_failure(error: ClientGovernedTaskError) -> CliFailure {
    match error {
        ClientGovernedTaskError::Transport(_) => {
            CliFailure::daemon_unavailable("Task watch transport ended; rerun the command")
                .for_operation("task.watch")
        }
        ClientGovernedTaskError::Kernel(KernelError::PermissionDenied(permission)) => {
            CliFailure::permission("task.watch", permission)
        }
        ClientGovernedTaskError::Kernel(KernelError::SessionUnavailable) => {
            CliFailure::daemon_unavailable("Task watch session is unavailable; rerun the command")
                .for_operation("task.watch")
        }
        ClientGovernedTaskError::Kernel(KernelError::SessionExpired) => {
            CliFailure::task_watch_session_changed()
        }
        ClientGovernedTaskError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("task.watch")
        }
        ClientGovernedTaskError::UnexpectedEof => CliFailure::stream_recovery(
            "task.watch",
            "Task watch ended before the requested live frames; rerun the command",
        ),
        ClientGovernedTaskError::ResetBarrier => CliFailure::reset_required(),
        ClientGovernedTaskError::BaselineLimitExceeded => {
            CliFailure::protocol("governed Task baseline exceeded the safe 1000-item limit")
                .for_operation("task.watch")
        }
        ClientGovernedTaskError::Protocol(_) | ClientGovernedTaskError::Kernel(_) => {
            CliFailure::protocol("governed Task projection integrity validation failed")
                .for_operation("task.watch")
        }
    }
}

fn governed_hold_reason_name(reason: GovernedHoldReason) -> &'static str {
    match reason {
        GovernedHoldReason::CancellationOutcomeUnknown => "cancellation_outcome_unknown",
        GovernedHoldReason::CompensationRequired => "compensation_required",
        GovernedHoldReason::ManualRecoveryRequired => "manual_recovery_required",
        GovernedHoldReason::IrreversibleOutcomeUnknown => "irreversible_outcome_unknown",
        GovernedHoldReason::Unclassified => "unclassified",
    }
}

fn governed_projection_reason_name(reason: GovernedProjectionReason) -> &'static str {
    match reason {
        GovernedProjectionReason::DependencyProjectionPending => "dependency_projection_pending",
        GovernedProjectionReason::ProjectionNotReady => "projection_not_ready",
        GovernedProjectionReason::TaskProjectionInvalid => "task_projection_invalid",
        GovernedProjectionReason::Unclassified => "unclassified",
    }
}

fn governed_task_json(task: &GovernedTaskState) -> serde_json::Value {
    let run = task.run.as_ref().map(|run| {
        let steps = run
            .steps
            .iter()
            .map(|step| {
                let attempts = step
                    .attempts
                    .iter()
                    .map(|attempt| {
                        json!({
                            "attemptId": attempt.attempt_id,
                            "revision": attempt.revision,
                            "attemptNumber": attempt.attempt_number,
                            "status": attempt.status.as_str_name(),
                            "recoveryClass": attempt.recovery_class.as_str_name(),
                            "holdReason": attempt.hold_reason.map(governed_hold_reason_name),
                            "lastHarnessSequence": attempt.last_harness_sequence,
                            "checkpointReferenceRecorded": attempt.checkpoint_reference_recorded,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "stepId": step.step_id,
                    "revision": step.revision,
                    "status": step.status.as_str_name(),
                    "holdReason": step.hold_reason.map(governed_hold_reason_name),
                    "currentAttemptId": step.current_attempt_id,
                    "attempts": attempts,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "runId": run.run_id,
            "revision": run.revision,
            "status": run.status.as_str_name(),
            "workRevision": run.work_revision,
            "holdReason": run.hold_reason.map(governed_hold_reason_name),
            "steps": steps,
        })
    });
    json!({
        "taskId": task.task_id,
        "revision": task.revision,
        "status": task.status.as_str_name(),
        "resumeStatus": task.resume_status.map(|status| status.as_str_name()),
        "holdReason": task.hold_reason.map(governed_hold_reason_name),
        "projection": {
            "position": {
                "epoch": task.projection.position.epoch,
                "sequence": task.projection.position.sequence,
            },
            "health": task.projection.health.as_str_name(),
            "stale": task.projection.stale,
            "reason": task.projection.reason.map(governed_projection_reason_name),
        },
        "run": run,
    })
}

fn task_watch_classification_name(classification: TaskWatchClassification) -> &'static str {
    match classification {
        TaskWatchClassification::Applied => "applied",
        TaskWatchClassification::Replay => "replay",
        TaskWatchClassification::Heartbeat => "heartbeat",
        TaskWatchClassification::ResetRequired => "reset_required",
    }
}

fn governed_task_watch_record_json(record: &CliGovernedTaskWatchRecord) -> serde_json::Value {
    let (data, position) = match record {
        CliGovernedTaskWatchRecord::ResumeEpochMismatch { requested, current } => (
            json!({
                "kind": "resume_epoch_mismatch",
                "classification": "reset_required",
                "task": null,
                "tasks": null,
                "requestedFloor": {
                    "epoch": requested.epoch,
                    "sequence": requested.sequence,
                },
                "message": "The requested epoch was reset; continuing from the current complete baseline",
            }),
            current,
        ),
        CliGovernedTaskWatchRecord::Baseline { position, tasks } => (
            json!({
                "kind": "baseline",
                "classification": null,
                "task": null,
                "tasks": tasks.iter().map(governed_task_json).collect::<Vec<_>>(),
            }),
            position,
        ),
        CliGovernedTaskWatchRecord::Update(update) => (
            json!({
                "kind": "update",
                "classification": task_watch_classification_name(update.classification),
                "task": match update.classification {
                    TaskWatchClassification::Heartbeat | TaskWatchClassification::ResetRequired => None,
                    TaskWatchClassification::Applied | TaskWatchClassification::Replay => {
                        update.task.as_ref().map(governed_task_json)
                    }
                },
                "tasks": null,
            }),
            &update.position,
        ),
    };
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "streamSchema": "egopulse.cli.task-watch/v1",
        "ok": true,
        "operation": "task.watch",
        "data": data,
        "projection": {
            "position": {
                "epoch": position.epoch,
                "sequence": position.sequence,
            },
        },
        "correlationId": Uuid::now_v7().to_string(),
    })
}

fn append_governed_task_text(output: &mut String, task: &GovernedTaskState, prefix: &str) {
    output.push_str(&format!(
        "{prefix}Task {} revision={} status={} resume={} hold={} projection={}:{} health={} stale={} reason={}\n",
        task.task_id,
        task.revision,
        task.status.as_str_name(),
        task.resume_status
            .map(|status| status.as_str_name())
            .unwrap_or("none"),
        task.hold_reason
            .map(governed_hold_reason_name)
            .unwrap_or("none"),
        task.projection.position.epoch,
        task.projection.position.sequence,
        task.projection.health.as_str_name(),
        task.projection.stale,
        task.projection
            .reason
            .map(governed_projection_reason_name)
            .unwrap_or("none"),
    ));
    if let Some(run) = &task.run {
        output.push_str(&format!(
            "{prefix}  Run {} revision={} status={} work_revision={} hold={}\n",
            run.run_id,
            run.revision,
            run.status.as_str_name(),
            run.work_revision,
            run.hold_reason
                .map(governed_hold_reason_name)
                .unwrap_or("none"),
        ));
        for step in &run.steps {
            output.push_str(&format!(
                "{prefix}    Step {} revision={} status={} hold={} current_attempt={}\n",
                step.step_id,
                step.revision,
                step.status.as_str_name(),
                step.hold_reason
                    .map(governed_hold_reason_name)
                    .unwrap_or("none"),
                step.current_attempt_id.as_deref().unwrap_or("none"),
            ));
            for attempt in &step.attempts {
                output.push_str(&format!(
                    "{prefix}      Attempt {} revision={} number={} status={} recovery={} hold={} last_harness_sequence={} checkpoint_reference_recorded={}\n",
                    attempt.attempt_id,
                    attempt.revision,
                    attempt.attempt_number,
                    attempt.status.as_str_name(),
                    attempt.recovery_class.as_str_name(),
                    attempt
                        .hold_reason
                        .map(governed_hold_reason_name)
                        .unwrap_or("none"),
                    attempt.last_harness_sequence,
                    attempt.checkpoint_reference_recorded,
                ));
            }
        }
    } else {
        output.push_str(&format!("{prefix}  Run: not projected\n"));
    }
}

fn governed_task_watch_record_text(record: &CliGovernedTaskWatchRecord) -> String {
    match record {
        CliGovernedTaskWatchRecord::ResumeEpochMismatch { requested, current } => format!(
            "Task watch reset compatibility: requested floor {}:{}; current baseline {}:{}; continuing from the current complete baseline",
            requested.epoch, requested.sequence, current.epoch, current.sequence
        ),
        CliGovernedTaskWatchRecord::Baseline { position, tasks } => {
            let mut output = format!(
                "Task watch baseline: position={}:{} tasks={}\n",
                position.epoch,
                position.sequence,
                tasks.len()
            );
            for task in tasks {
                append_governed_task_text(&mut output, task, "  ");
            }
            output.trim_end().to_owned()
        }
        CliGovernedTaskWatchRecord::Update(update) => {
            let mut output = format!(
                "Task watch update: classification={} position={}:{}\n",
                task_watch_classification_name(update.classification),
                update.position.epoch,
                update.position.sequence
            );
            if matches!(
                update.classification,
                TaskWatchClassification::Applied | TaskWatchClassification::Replay
            ) && let Some(task) = &update.task
            {
                append_governed_task_text(&mut output, task, "  ");
            }
            output.trim_end().to_owned()
        }
    }
}

fn render_governed_task_watch_record(record: &CliGovernedTaskWatchRecord, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(&governed_task_watch_record_json(record)).unwrap()
        );
    } else {
        println!("{}", governed_task_watch_record_text(record));
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
            decision,
            reason_code,
            confirmation_proof_ref,
            json,
        } => {
            approval_decide(
                approval_request_id,
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

fn guided_approval_failure(error: ClientGuidedApprovalDecisionError) -> CliFailure {
    match error {
        ClientGuidedApprovalDecisionError::Kernel(KernelError::PermissionDenied(permission)) => {
            CliFailure::permission("approval.decide", permission)
        }
        ClientGuidedApprovalDecisionError::Kernel(error) => {
            CliFailure::protocol(error.to_string()).for_operation("approval.decide")
        }
        ClientGuidedApprovalDecisionError::InvalidInput(detail)
        | ClientGuidedApprovalDecisionError::Protocol(detail) => {
            CliFailure::protocol(detail).for_operation("approval.decide")
        }
        ClientGuidedApprovalDecisionError::NotFound => CliFailure::policy_authority(
            PolicyDecisionErrorCode::NotFound as i32,
            Some("approval_view_not_found".to_owned()),
            "approval.decide",
        ),
        ClientGuidedApprovalDecisionError::NonActionable => CliFailure::policy_authority(
            PolicyDecisionErrorCode::PolicyDenied as i32,
            Some("approval_not_actionable".to_owned()),
            "approval.decide",
        ),
        ClientGuidedApprovalDecisionError::Transport(detail) => {
            CliFailure::daemon_unavailable(detail).for_operation("approval.decide")
        }
        ClientGuidedApprovalDecisionError::Api(error) => {
            CliFailure::from_local_api_error(*error).for_operation("approval.decide")
        }
        ClientGuidedApprovalDecisionError::Authority {
            error_code,
            safe_error_fingerprint,
        } => CliFailure::policy_authority(error_code, safe_error_fingerprint, "approval.decide"),
    }
}

async fn approval_decide(
    approval_request_id: String,
    decision: String,
    reason_code: String,
    confirmation_proof_ref: Option<String>,
    json: bool,
) -> Result<(), CliFailure> {
    let decision = parse_approval_decision(&decision)
        .map_err(|message| CliFailure::protocol(message).for_operation("approval.decide"))?;
    let attached = attach("approval.decide").await?;
    let result = attached
        .0
        .decide_guided_approval(GuidedApprovalDecisionInput {
            approval_request_id,
            decision,
            reason_code,
            confirmation_proof_ref,
        })
        .await
        .map_err(guided_approval_failure)?;
    let payload = json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "approval.decide",
        "data": {
            "committed": result.committed(),
            "replayed": result.replayed(),
            "authorityDecisionRef": result.authority_decision_ref(),
            "decision": result.decision().contract_name(),
            "stateRevision": result.state_revision(),
            "awaitToken": await_token_json(result.await_token().cloned()),
            "projectionWarning": result.projection_warning().map(|warning| json!({
                "code": LocalApiErrorCode::try_from(warning.code).map(|code| code.as_str_name()).unwrap_or("LOCAL_API_ERROR_UNKNOWN"),
                "retryable": warning.retryable,
                "requiredActionCode": warning.required_action_code,
                "safeFingerprint": warning.safe_fingerprint,
            })),
        },
        "correlationId": result.correlation_id(),
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

fn parse_approval_decision(value: &str) -> Result<GuidedApprovalDecision, String> {
    match value {
        "allow-once" => Ok(GuidedApprovalDecision::AllowOnce),
        "deny" => Ok(GuidedApprovalDecision::Deny),
        "cancel-attempt" => Ok(GuidedApprovalDecision::CancelAttempt),
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

fn redactions_json(
    redactions: &[egopulse_domain_contracts::v01::egopulse::localapi::v1::RedactedField],
) -> serde_json::Value {
    json!(
        redactions
            .iter()
            .map(|item| json!({
                "fieldPath": item.field_path,
                "reasonCode": item.reason_code,
            }))
            .collect::<Vec<_>>()
    )
}

fn review_projection_json(metadata: Option<&ProjectionMetadata>) -> serde_json::Value {
    metadata.map_or(serde_json::Value::Null, |metadata| {
        json!({
            "schemaRef": contract_reference_json(metadata.schema_ref.as_ref()),
            "health": ProjectionHealth::try_from(metadata.health).ok().map(|value| value.as_str_name()),
            "stale": metadata.stale,
            "safeHealthReasonCode": metadata.safe_health_reason_code,
            "position": metadata.position.as_ref().map(|position| json!({
                "epoch": position.epoch,
                "sequence": position.sequence,
                "projectedAt": optional_timestamp_json(position.projected_at.as_ref()),
            })),
            "sourceRevisions": metadata.source_revisions.iter().map(|source| json!({
                "domain": SourceDomain::try_from(source.domain).ok().map(|value| value.as_str_name()),
                "aggregateId": source.aggregate_id,
                "revision": source.revision,
                "lastEventId": source.last_event_id,
            })).collect::<Vec<_>>(),
        })
    })
}

fn optional_timestamp_json(value: Option<&prost_types::Timestamp>) -> serde_json::Value {
    value.map_or(
        serde_json::Value::Null,
        |value| json!({ "seconds": value.seconds, "nanos": value.nanos }),
    )
}

fn contract_reference_json(value: Option<&ContractReference>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |value| {
        json!({
            "contractId": value.contract_id,
            "version": value.version,
            "sha256": value.sha256,
        })
    })
}

fn content_address_json(value: Option<&ContentAddress>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |value| {
        json!({
            "algorithm": HashAlgorithm::try_from(value.algorithm)
                .ok()
                .map(|algorithm| algorithm.as_str_name()),
            "digest": value.digest,
            "byteLength": value.byte_length,
        })
    })
}

fn lineage_json(
    value: Option<&egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding>,
) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |value| {
        json!({
            "taskId": value.task_id,
            "taskRevision": value.task_revision,
            "workRevision": value.work_revision,
            "runId": value.run_id,
            "runRevision": value.run_revision,
            "stepId": value.step_id,
            "stepRevision": value.step_revision,
            "attemptId": value.attempt_id,
            "attemptRevision": value.attempt_revision,
            "dispatchId": value.dispatch_id,
            "fencingToken": value.fencing_token,
        })
    })
}

fn safe_producer_json(
    value: Option<&egopulse_domain_contracts::v01::egopulse::artifact::v1::ProducerIdentity>,
) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |value| {
        json!({
            "principalKind": value.principal_kind,
            "componentName": value.component_name,
            "componentVersion": value.component_version,
            "capabilityProfileId": value.capability_profile_id,
        })
    })
}

fn artifact_set_json(
    set: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactSet,
) -> serde_json::Value {
    json!({
        "artifactSetId": set.artifact_set_id,
        "revision": set.revision,
        "status": ArtifactSetStatus::try_from(set.status).ok().map(|value| value.as_str_name()),
        "lineage": lineage_json(set.lineage.as_ref()),
        "artifactIds": set.artifact_ids,
        "claimIds": set.claim_ids,
        "evidenceIds": set.evidence_ids,
        "canonicalManifest": content_address_json(set.canonical_manifest.as_ref()),
        "createdAt": optional_timestamp_json(set.created_at.as_ref()),
        "sealedAt": optional_timestamp_json(set.sealed_at.as_ref()),
        "supersedesArtifactSetId": set.supersedes_artifact_set_id,
    })
}

fn artifact_json(
    artifact: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactDescriptor,
) -> serde_json::Value {
    let provenance = artifact.provenance.as_ref().map(|value| {
        json!({
            "lineage": lineage_json(value.lineage.as_ref()),
            "producer": safe_producer_json(value.producer.as_ref()),
            "inputArtifactIds": value.input_artifact_ids,
            "transformationContractRef": contract_reference_json(value.transformation_contract_ref.as_ref()),
            "observedAt": optional_timestamp_json(value.observed_at.as_ref()),
            "capturedAt": optional_timestamp_json(value.captured_at.as_ref()),
        })
    });
    json!({
        "artifactId": artifact.artifact_id,
        "revision": artifact.revision,
        "status": ArtifactStatus::try_from(artifact.status).ok().map(|value| value.as_str_name()),
        "semanticClass": ArtifactSemanticClass::try_from(artifact.semantic_class).ok().map(|value| value.as_str_name()),
        "typeContractRef": contract_reference_json(artifact.type_contract_ref.as_ref()),
        "mediaType": artifact.media_type,
        "content": content_address_json(artifact.content.as_ref()),
        "integrityStatus": IntegrityStatus::try_from(artifact.integrity_status).ok().map(|value| value.as_str_name()),
        "provenance": provenance,
        "sensitivityClass": artifact.sensitivity_class,
        "retentionProfileRef": contract_reference_json(artifact.retention_profile_ref.as_ref()),
        "createdAt": optional_timestamp_json(artifact.created_at.as_ref()),
        "sealedAt": optional_timestamp_json(artifact.sealed_at.as_ref()),
        "supersedesArtifactId": artifact.supersedes_artifact_id,
        "quarantineReasonCode": artifact.quarantine_reason_code,
    })
}

fn claim_json(
    claim: &egopulse_domain_contracts::v01::egopulse::artifact::v1::Claim,
) -> serde_json::Value {
    json!({
        "claimId": claim.claim_id,
        "revision": claim.revision,
        "status": ClaimStatus::try_from(claim.status).ok().map(|value| value.as_str_name()),
        "sourceType": ClaimSourceType::try_from(claim.source_type).ok().map(|value| value.as_str_name()),
        "semanticProfileRef": contract_reference_json(claim.semantic_profile_ref.as_ref()),
        "lineage": lineage_json(claim.lineage.as_ref()),
        "subjectArtifactIds": claim.subject_artifact_ids,
        "acceptanceContractRef": contract_reference_json(claim.acceptance_contract_ref.as_ref()),
        "statement": content_address_json(claim.statement.as_ref()),
        "proposedAt": optional_timestamp_json(claim.proposed_at.as_ref()),
        "supersedesClaimId": claim.supersedes_claim_id,
    })
}

fn evidence_json(
    evidence: &egopulse_domain_contracts::v01::egopulse::artifact::v1::Evidence,
) -> serde_json::Value {
    json!({
        "evidenceId": evidence.evidence_id,
        "revision": evidence.revision,
        "status": EvidenceStatus::try_from(evidence.status).ok().map(|value| value.as_str_name()),
        "relation": EvidenceRelation::try_from(evidence.relation).ok().map(|value| value.as_str_name()),
        "claimId": evidence.claim_id,
        "artifactIds": evidence.artifact_ids,
        "evidenceProfileRef": contract_reference_json(evidence.evidence_profile_ref.as_ref()),
        "lineage": lineage_json(evidence.lineage.as_ref()),
        "producerClass": EvidenceProducerClass::try_from(evidence.producer_class).ok().map(|value| value.as_str_name()),
        "independentOfClaimProposer": evidence.independent_of_claim_proposer,
        "integrityStatus": IntegrityStatus::try_from(evidence.integrity_status).ok().map(|value| value.as_str_name()),
        "coverageDescriptor": content_address_json(evidence.coverage_descriptor.as_ref()),
        "limitationCodes": evidence.limitation_codes,
        "recordedAt": optional_timestamp_json(evidence.recorded_at.as_ref()),
        "supersedesEvidenceId": evidence.supersedes_evidence_id,
    })
}

fn verification_json(
    verification: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationArtifact,
) -> serde_json::Value {
    let binding = verification.binding.as_ref().map(|value| {
        json!({
            "lineage": lineage_json(value.lineage.as_ref()),
            "artifactSetId": value.artifact_set_id,
            "artifactSetManifest": content_address_json(value.artifact_set_manifest.as_ref()),
            "claimId": value.claim_id,
            "claimSemanticProfileRef": contract_reference_json(value.claim_semantic_profile_ref.as_ref()),
            "acceptanceContractRef": contract_reference_json(value.acceptance_contract_ref.as_ref()),
        })
    });
    let provenance = verification.provenance.as_ref().map(|value| {
        json!({
            "checkerProfileRefs": value.checker_profile_refs.iter().map(|item| contract_reference_json(Some(item))).collect::<Vec<_>>(),
            "toolReceiptArtifactIds": value.tool_receipt_artifact_ids,
            "modelCallReceiptArtifactIds": value.model_call_receipt_artifact_ids,
            "rawOutputArtifactIds": value.raw_output_artifact_ids,
            "durationMs": value.duration_ms,
            "costReceiptArtifactId": value.cost_receipt_artifact_id,
        })
    });
    json!({
        "verificationArtifactId": verification.verification_artifact_id,
        "version": verification.version,
        "verificationRequestId": verification.verification_request_id,
        "verificationRunId": verification.verification_run_id,
        "verificationType": verification.verification_type,
        "binding": binding,
        "conclusion": VerificationConclusion::try_from(verification.conclusion).ok().map(|value| value.as_str_name()),
        "overallEvidenceCoverage": EvidenceCoverage::try_from(verification.overall_evidence_coverage).ok().map(|value| value.as_str_name()),
        "criterionResults": verification.criterion_results.iter().map(|value| json!({
            "criterionResultId": value.criterion_result_id,
            "criterionId": value.criterion_id,
            "requirement": CriterionRequirement::try_from(value.requirement).ok().map(|item| item.as_str_name()),
            "outcome": CriterionOutcome::try_from(value.outcome).ok().map(|item| item.as_str_name()),
            "assuranceClass": CheckerAssuranceClass::try_from(value.assurance_class).ok().map(|item| item.as_str_name()),
            "checkerProfileRef": contract_reference_json(value.checker_profile_ref.as_ref()),
            "evidenceCoverage": EvidenceCoverage::try_from(value.evidence_coverage).ok().map(|item| item.as_str_name()),
            "evidenceIds": value.evidence_ids,
            "discrepancyIds": value.discrepancy_ids,
            "unverifiedItemIds": value.unverified_item_ids,
            "durationMs": value.duration_ms,
            "safeDetailArtifactId": value.safe_detail_artifact_id,
        })).collect::<Vec<_>>(),
        "discrepancies": verification.discrepancies.iter().map(|value| json!({
            "discrepancyId": value.discrepancy_id,
            "criterionId": value.criterion_id,
            "severity": DiscrepancySeverity::try_from(value.severity).ok().map(|item| item.as_str_name()),
            "evidenceIds": value.evidence_ids,
            "descriptionArtifactId": value.description_artifact_id,
            "suggestedFixArtifactId": value.suggested_fix_artifact_id,
        })).collect::<Vec<_>>(),
        "unverifiedItems": verification.unverified_items.iter().map(|value| json!({
            "unverifiedItemId": value.unverified_item_id,
            "criterionId": value.criterion_id,
            "reason": UnverifiedReason::try_from(value.reason).ok().map(|item| item.as_str_name()),
            "evidenceIds": value.evidence_ids,
            "contextArtifactId": value.context_artifact_id,
        })).collect::<Vec<_>>(),
        "provenance": provenance,
        "canonicalPayload": content_address_json(verification.canonical_payload.as_ref()),
        "completedAt": optional_timestamp_json(verification.completed_at.as_ref()),
        "supersedesVerificationArtifactId": verification.supersedes_verification_artifact_id,
    })
}

fn verdict_json(
    verdict: &egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdict,
) -> serde_json::Value {
    let scope = verdict.scope.as_ref().map(|value| {
        json!({
            "taskId": value.task_id,
            "taskRevision": value.task_revision,
            "workRevision": value.work_revision,
            "artifactSetId": value.artifact_set_id,
            "artifactSetManifest": content_address_json(value.artifact_set_manifest.as_ref()),
            "verificationArtifactId": value.verification_artifact_id,
            "verificationPayload": content_address_json(value.verification_payload.as_ref()),
            "acceptanceContractRef": contract_reference_json(value.acceptance_contract_ref.as_ref()),
        })
    });
    json!({
        "founderVerdictId": verdict.founder_verdict_id,
        "version": verdict.version,
        "decision": FounderVerdictDecision::try_from(verdict.decision).ok().map(|value| value.as_str_name()),
        "scope": scope,
        "observedVerificationConclusion": VerificationConclusion::try_from(verdict.observed_verification_conclusion).ok().map(|value| value.as_str_name()),
        "riskAcceptances": verdict.risk_acceptances.iter().map(|value| json!({
            "riskAcceptanceId": value.risk_acceptance_id,
            "category": RiskCategory::try_from(value.category).ok().map(|item| item.as_str_name()),
            "discrepancyIds": value.discrepancy_ids,
            "unverifiedItemIds": value.unverified_item_ids,
            "rationaleArtifactId": value.rationale_artifact_id,
            "compensatingControlArtifactIds": value.compensating_control_artifact_ids,
            "reviewTriggerCode": value.review_trigger_code,
        })).collect::<Vec<_>>(),
        "reworkDirective": verdict.rework_directive.as_ref().map(|value| json!({
            "directiveId": value.directive_id,
            "reasonCode": value.reason_code,
            "requiredChangesArtifactId": value.required_changes_artifact_id,
            "targetDiscrepancyIds": value.target_discrepancy_ids,
            "targetUnverifiedItemIds": value.target_unverified_item_ids,
        })),
        "reasonCode": verdict.reason_code,
        "rationaleArtifactId": verdict.rationale_artifact_id,
        "validFrom": optional_timestamp_json(verdict.valid_from.as_ref()),
        "expiresAt": optional_timestamp_json(verdict.expires_at.as_ref()),
        "issuedAt": optional_timestamp_json(verdict.issued_at.as_ref()),
        "canonicalPayload": content_address_json(verdict.canonical_payload.as_ref()),
        "supersedesFounderVerdictId": verdict.supersedes_founder_verdict_id,
    })
}

fn verdict_state_json(
    state: &egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictState,
) -> serde_json::Value {
    json!({
        "founderVerdictId": state.founder_verdict_id,
        "revision": state.revision,
        "state": FounderVerdictStateKind::try_from(state.state).ok().map(|value| value.as_str_name()),
        "consumptionReceiptId": state.consumption_receipt_id,
        "supersededByVerdictId": state.superseded_by_verdict_id,
        "terminalReasonCode": state.terminal_reason_code,
        "updatedAt": optional_timestamp_json(state.updated_at.as_ref()),
    })
}

fn task_result_review_json(review: &TaskResultReview) -> serde_json::Value {
    let task = review.task_view.task.as_ref();
    let artifact_set = review
        .task_view
        .artifact_set
        .as_ref()
        .map(artifact_set_json);
    let verification = review
        .task_view
        .verification
        .as_ref()
        .map(verification_json);
    let verdict = review.task_view.founder_verdict.as_ref().map(verdict_json);
    let verdict_state = review
        .task_view
        .founder_verdict_state
        .as_ref()
        .map(verdict_state_json);
    let graph = review.evidence_graph.as_ref().map(|graph| {
        json!({
            "taskId": graph.task_id,
            "artifactSetId": graph.artifact_set_id,
            "artifacts": graph.artifacts.iter().map(artifact_json).collect::<Vec<_>>(),
            "claims": graph.claims.iter().map(claim_json).collect::<Vec<_>>(),
            "evidence": graph.evidence.iter().map(evidence_json).collect::<Vec<_>>(),
            "projection": review_projection_json(graph.metadata.as_ref()),
            "redactions": redactions_json(&graph.redactions),
        })
    });
    json!({
        "schemaVersion": "egopulse.cli-result/v0.1",
        "ok": true,
        "operation": "task.review",
        "data": {
            "kind": "projected result metadata/governance evidence",
            "taskId": task.map(|task| task.task_id.clone()),
            "taskRevision": task.map(|task| task.revision),
            "taskStatus": task.and_then(|task| TaskStatus::try_from(task.status).ok()).map(|status| status.as_str_name()),
            "artifactSet": artifact_set,
            "evidenceGraph": graph,
            "verification": verification,
            "founderVerdict": verdict,
            "founderVerdictState": verdict_state,
            "taskProjection": review_projection_json(review.task_view.metadata.as_ref()),
            "redactions": redactions_json(&review.task_view.redactions),
        },
        "correlationId": Uuid::now_v7().to_string(),
    })
}

fn task_result_review_text(review: &TaskResultReview) -> String {
    let payload = task_result_review_json(review);
    let data = &payload["data"];
    let artifact_set = data["artifactSet"]["artifactSetId"]
        .as_str()
        .unwrap_or("none");
    let artifacts = review
        .evidence_graph
        .as_ref()
        .map_or(0, |graph| graph.artifacts.len());
    let quarantined = review.evidence_graph.as_ref().map_or(0, |graph| {
        graph
            .artifacts
            .iter()
            .filter(|item| item.status == ArtifactStatus::Quarantined as i32)
            .count()
    });
    let claims = review
        .evidence_graph
        .as_ref()
        .map_or(0, |graph| graph.claims.len());
    let evidence = review
        .evidence_graph
        .as_ref()
        .map_or(0, |graph| graph.evidence.len());
    let relations = review.evidence_graph.as_ref().map_or_else(
        || "none".to_owned(),
        |graph| {
            let values = graph
                .evidence
                .iter()
                .filter_map(|item| EvidenceRelation::try_from(item.relation).ok())
                .map(|value| value.as_str_name())
                .collect::<Vec<_>>()
                .join(",");
            if values.is_empty() {
                "none".to_owned()
            } else {
                values
            }
        },
    );
    let verification_conclusion = data["verification"]["conclusion"]
        .as_str()
        .unwrap_or("none");
    let verification_coverage = data["verification"]["overallEvidenceCoverage"]
        .as_str()
        .unwrap_or("none");
    let discrepancies = data["verification"]["discrepancies"]
        .as_array()
        .map_or(0, Vec::len);
    let unverified = data["verification"]["unverifiedItems"]
        .as_array()
        .map_or(0, Vec::len);
    let verdict_decision = data["founderVerdict"]["decision"]
        .as_str()
        .unwrap_or("none");
    let verdict_observed = data["founderVerdict"]["observedVerificationConclusion"]
        .as_str()
        .unwrap_or("none");
    let verdict_state = data["founderVerdictState"]["state"]
        .as_str()
        .unwrap_or("none");
    let terminal_reason = data["founderVerdictState"]["terminalReasonCode"]
        .as_str()
        .unwrap_or("none");
    format!(
        "Projected result metadata/governance evidence: task={} revision={} status={}\nArtifactSet: {} artifacts={} quarantined={}\nClaims/Evidence: claims={} evidence={} relations={}\nVerification: conclusion={} coverage={} discrepancies={} unverified={}\nFounder Verdict: observed={} decision={} state={} terminal_reason={}\nRedactions: task={} evidence={}",
        data["taskId"].as_str().unwrap_or(""),
        data["taskRevision"].as_u64().unwrap_or_default(),
        data["taskStatus"].as_str().unwrap_or(""),
        artifact_set,
        artifacts,
        quarantined,
        claims,
        evidence,
        relations,
        verification_conclusion,
        verification_coverage,
        discrepancies,
        unverified,
        verdict_observed,
        verdict_decision,
        verdict_state,
        terminal_reason,
        data["redactions"].as_array().map_or(0, Vec::len),
        data["evidenceGraph"]["redactions"]
            .as_array()
            .map_or(0, Vec::len),
    )
}

fn render_task_result_review(review: &TaskResultReview, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&task_result_review_json(review)).unwrap()
        );
    } else {
        println!("{}", task_result_review_text(review));
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
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        rc::Rc,
    };

    use super::*;
    use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
        AttemptStatus, RecoveryClass,
    };

    struct ScriptedGovernedTaskBaseline {
        position: GovernedProjectionPosition,
        tasks: Vec<GovernedTaskState>,
    }

    impl CliGovernedTaskBaseline for ScriptedGovernedTaskBaseline {
        fn position(&self) -> GovernedProjectionPosition {
            self.position.clone()
        }

        fn tasks(&self) -> Vec<GovernedTaskState> {
            self.tasks.clone()
        }
    }

    struct ScriptedGovernedTaskSession {
        outcomes: VecDeque<Result<GovernedTaskUpdate, ClientGovernedTaskError>>,
        polls: Rc<Cell<u64>>,
        drops: Rc<Cell<u64>>,
    }

    impl CliGovernedTaskSession for ScriptedGovernedTaskSession {
        fn next_update(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<GovernedTaskUpdate, ClientGovernedTaskError>> + '_>>
        {
            self.polls.set(self.polls.get() + 1);
            let outcome = self
                .outcomes
                .pop_front()
                .unwrap_or(Err(ClientGovernedTaskError::UnexpectedEof));
            Box::pin(std::future::ready(outcome))
        }
    }

    impl Drop for ScriptedGovernedTaskSession {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    struct ScriptedGovernedTaskClient {
        baselines: VecDeque<Result<ScriptedGovernedTaskBaseline, ClientGovernedTaskError>>,
        sessions: VecDeque<Result<ScriptedGovernedTaskSession, ClientGovernedTaskError>>,
        baseline_reads: Rc<Cell<u64>>,
        session_opens: Rc<Cell<u64>>,
    }

    impl CliGovernedTaskClient for ScriptedGovernedTaskClient {
        type Baseline = ScriptedGovernedTaskBaseline;
        type Session = ScriptedGovernedTaskSession;

        fn read_baseline(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Baseline, ClientGovernedTaskError>> + '_>>
        {
            self.baseline_reads.set(self.baseline_reads.get() + 1);
            Box::pin(std::future::ready(
                self.baselines
                    .pop_front()
                    .unwrap_or(Err(ClientGovernedTaskError::UnexpectedEof)),
            ))
        }

        fn open_session(
            &mut self,
            _baseline: Self::Baseline,
        ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ClientGovernedTaskError>> + '_>>
        {
            self.session_opens.set(self.session_opens.get() + 1);
            Box::pin(std::future::ready(
                self.sessions
                    .pop_front()
                    .unwrap_or(Err(ClientGovernedTaskError::UnexpectedEof)),
            ))
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

    fn governed_position(epoch: &str, sequence: u64) -> GovernedProjectionPosition {
        GovernedProjectionPosition {
            epoch: epoch.to_owned(),
            sequence,
        }
    }

    fn governed_task(task_id: &str, status: TaskStatus) -> GovernedTaskState {
        GovernedTaskState {
            task_id: task_id.to_owned(),
            revision: 7,
            status,
            resume_status: Some(TaskStatus::Active),
            hold_reason: Some(GovernedHoldReason::ManualRecoveryRequired),
            projection: egopulse_client_operations::GovernedProjectionState {
                position: governed_position("epoch:watch", 9),
                health: ProjectionHealth::Ready,
                stale: false,
                reason: None,
            },
            run: Some(egopulse_client_operations::GovernedRunState {
                run_id: "run:governed".to_owned(),
                revision: 6,
                status: RunStatus::Returned,
                work_revision: 3,
                hold_reason: Some(GovernedHoldReason::CompensationRequired),
                steps: vec![egopulse_client_operations::GovernedStepState {
                    step_id: "step:governed".to_owned(),
                    revision: 5,
                    status: StepStatus::Held,
                    hold_reason: Some(GovernedHoldReason::IrreversibleOutcomeUnknown),
                    current_attempt_id: Some("attempt:governed".to_owned()),
                    attempts: vec![egopulse_client_operations::GovernedAttemptState {
                        attempt_id: "attempt:governed".to_owned(),
                        revision: 4,
                        attempt_number: 2,
                        status: AttemptStatus::Held,
                        recovery_class: RecoveryClass::ManualOnly,
                        hold_reason: Some(GovernedHoldReason::CancellationOutcomeUnknown),
                        last_harness_sequence: 11,
                        checkpoint_reference_recorded: true,
                    }],
                }],
            }),
        }
    }

    fn governed_baseline(
        epoch: &str,
        sequence: u64,
        tasks: Vec<GovernedTaskState>,
    ) -> ScriptedGovernedTaskBaseline {
        ScriptedGovernedTaskBaseline {
            position: governed_position(epoch, sequence),
            tasks,
        }
    }

    fn scripted_governed_session(
        outcomes: Vec<Result<GovernedTaskUpdate, ClientGovernedTaskError>>,
    ) -> (ScriptedGovernedTaskSession, Rc<Cell<u64>>, Rc<Cell<u64>>) {
        let polls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        (
            ScriptedGovernedTaskSession {
                outcomes: outcomes.into(),
                polls: Rc::clone(&polls),
                drops: Rc::clone(&drops),
            },
            polls,
            drops,
        )
    }

    fn governed_task_update(
        classification: TaskWatchClassification,
        sequence: u64,
        task: Option<GovernedTaskState>,
    ) -> GovernedTaskUpdate {
        GovernedTaskUpdate {
            classification,
            position: governed_position("epoch:watch", sequence),
            task,
        }
    }

    fn scripted_governed_client(
        baselines: Vec<Result<ScriptedGovernedTaskBaseline, ClientGovernedTaskError>>,
        sessions: Vec<Result<ScriptedGovernedTaskSession, ClientGovernedTaskError>>,
    ) -> (ScriptedGovernedTaskClient, Rc<Cell<u64>>, Rc<Cell<u64>>) {
        let baseline_reads = Rc::new(Cell::new(0));
        let session_opens = Rc::new(Cell::new(0));
        (
            ScriptedGovernedTaskClient {
                baselines: baselines.into(),
                sessions: sessions.into(),
                baseline_reads: Rc::clone(&baseline_reads),
                session_opens: Rc::clone(&session_opens),
            },
            baseline_reads,
            session_opens,
        )
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
    fn task_watch_cli_preserves_bounds_and_requires_a_complete_resume_floor() {
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
    }

    #[test]
    fn governed_task_watch_json_and_text_expose_only_the_safe_fact_tree() {
        let record = CliGovernedTaskWatchRecord::Update(governed_task_update(
            TaskWatchClassification::Applied,
            10,
            Some(governed_task("task:safe", TaskStatus::Active)),
        ));
        let payload = governed_task_watch_record_json(&record);
        assert_eq!(payload["schemaVersion"], "egopulse.cli-result/v0.1");
        assert_eq!(payload["streamSchema"], "egopulse.cli.task-watch/v1");
        assert_eq!(payload["operation"], "task.watch");
        assert_eq!(payload["data"]["kind"], "update");
        assert_eq!(payload["data"]["classification"], "applied");
        assert_eq!(payload["data"]["task"]["status"], "TASK_STATUS_ACTIVE");
        assert_eq!(
            payload["data"]["task"]["run"]["status"],
            "RUN_STATUS_RETURNED"
        );
        assert_eq!(
            payload["data"]["task"]["run"]["steps"][0]["attempts"][0]["checkpointReferenceRecorded"],
            true
        );
        assert_eq!(
            payload["data"]["task"]["run"]["steps"][0]["attempts"][0]["lastHarnessSequence"],
            11
        );
        assert_eq!(payload["projection"]["position"]["epoch"], "epoch:watch");
        assert_eq!(payload["projection"]["position"]["sequence"], 10);
        let encoded = serde_json::to_string(&payload).unwrap();
        for forbidden in [
            "workspaceRef",
            "harnessId",
            "capabilityProfileRef",
            "dispatchId",
            "dispatchFingerprint",
            "harnessSessionRef",
            "lease",
            "fencingToken",
            "checkpointId",
            "context",
            "artifact",
            "provider",
            "model",
            "content",
        ] {
            assert!(!encoded.contains(forbidden), "leaked field {forbidden}");
        }
        let text = governed_task_watch_record_text(&record);
        assert!(text.contains("Task task:safe revision=7 status=TASK_STATUS_ACTIVE"));
        assert!(text.contains("Run run:governed revision=6 status=RUN_STATUS_RETURNED"));
        assert!(text.contains("checkpoint_reference_recorded=true"));
        assert!(!text.contains("TASK_STATUS_COMPLETED"));

        let heartbeat = governed_task_watch_record_json(&CliGovernedTaskWatchRecord::Update(
            governed_task_update(
                TaskWatchClassification::Heartbeat,
                11,
                Some(governed_task("task:must-not-render", TaskStatus::Completed)),
            ),
        ));
        assert!(heartbeat["data"]["task"].is_null());
        let reset = governed_task_watch_record_json(&CliGovernedTaskWatchRecord::Update(
            governed_task_update(
                TaskWatchClassification::ResetRequired,
                12,
                Some(governed_task("task:must-not-render", TaskStatus::Completed)),
            ),
        ));
        assert!(reset["data"]["task"].is_null());
    }

    #[test]
    fn governed_task_watch_errors_have_stable_safe_categories() {
        let transport = governed_task_watch_failure(ClientGovernedTaskError::Transport(
            "private-pipe-canary".to_owned(),
        ));
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        assert!(!transport.message.contains("private-pipe-canary"));
        let protocol = governed_task_watch_failure(ClientGovernedTaskError::Kernel(
            KernelError::UnknownStreamFrame,
        ));
        assert_eq!(protocol.reason_code, "LOCAL_API_PROTOCOL_ERROR");
        let reset = governed_task_watch_failure(ClientGovernedTaskError::ResetBarrier);
        assert_eq!(reset.reason_code, "RESET_REQUIRED");
        let eof = governed_task_watch_failure(ClientGovernedTaskError::UnexpectedEof);
        assert_eq!(eof.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        let limit = governed_task_watch_failure(ClientGovernedTaskError::BaselineLimitExceeded);
        assert_eq!(limit.reason_code, "LOCAL_API_PROTOCOL_ERROR");

        let permission = governed_task_watch_failure(ClientGovernedTaskError::Kernel(
            KernelError::PermissionDenied("local.task.read".to_owned()),
        ));
        assert_eq!(permission.reason_code, "PERMISSION_DENIED");
        assert_eq!(permission.operation, "task.watch");
        let session = governed_task_watch_failure(ClientGovernedTaskError::Kernel(
            KernelError::SessionExpired,
        ));
        assert_eq!(session.reason_code, "SESSION_CHANGED");
        assert_eq!(session.category, "contract");

        let api =
            governed_task_watch_failure(ClientGovernedTaskError::Api(Box::new(LocalApiError {
                code: LocalApiErrorCode::ProjectionBehind as i32,
                retryable: true,
                required_action_code: Some("WAIT_FOR_PROJECTION".to_owned()),
                safe_fingerprint: "projection-behind".to_owned(),
                ..Default::default()
            })));
        assert_eq!(api.reason_code, "LOCAL_API_ERROR");
        assert_eq!(api.category, "projection");
        assert_eq!(api.operation, "task.watch");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_emits_atomic_baseline_then_exact_live_frames() {
        let (session, polls, drops) = scripted_governed_session(vec![
            Ok(governed_task_update(
                TaskWatchClassification::Applied,
                101,
                Some(governed_task("task:new", TaskStatus::Active)),
            )),
            Ok(governed_task_update(
                TaskWatchClassification::Replay,
                101,
                Some(governed_task("task:new", TaskStatus::Active)),
            )),
            Err(ClientGovernedTaskError::Transport(
                "must-not-poll-third".to_owned(),
            )),
        ]);
        let (mut client, reads, opens) = scripted_governed_client(
            vec![Ok(governed_baseline(
                "epoch:watch",
                100,
                vec![governed_task("task:baseline", TaskStatus::Active)],
            ))],
            vec![Ok(session)],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let witness = Rc::clone(&records);
        consume_governed_task_watch(&mut client, 2, None, None, move |record| {
            witness.borrow_mut().push(record.clone());
        })
        .await
        .unwrap();
        assert_eq!(polls.get(), 2);
        assert_eq!(reads.get(), 1);
        assert_eq!(opens.get(), 1);
        assert_eq!(drops.get(), 1);
        let records = records.borrow();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            records[0],
            CliGovernedTaskWatchRecord::Baseline { .. }
        ));
        assert!(matches!(records[1], CliGovernedTaskWatchRecord::Update(_)));
        assert!(matches!(records[2], CliGovernedTaskWatchRecord::Update(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_resume_floor_is_checked_before_opening_live_watch() {
        let (unused_session, polls, drops) = scripted_governed_session(Vec::new());
        let (mut ahead, reads, opens) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:watch", 99, Vec::new()))],
            vec![Ok(unused_session)],
        );
        let ahead_failure = consume_governed_task_watch(
            &mut ahead,
            1,
            Some("epoch:watch".to_owned()),
            Some(100),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(ahead_failure.reason_code, "PROJECTION_NOT_CAUGHT_UP");
        assert_eq!(reads.get(), 1);
        assert_eq!(opens.get(), 0);
        assert_eq!(polls.get(), 0);
        drop(ahead);
        assert_eq!(drops.get(), 1);

        let (session, polls, _) = scripted_governed_session(vec![Ok(governed_task_update(
            TaskWatchClassification::Heartbeat,
            101,
            None,
        ))]);
        let (mut old_floor, _, opens) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:watch", 100, Vec::new()))],
            vec![Ok(session)],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let witness = Rc::clone(&records);
        consume_governed_task_watch(
            &mut old_floor,
            1,
            Some("epoch:watch".to_owned()),
            Some(80),
            move |record| witness.borrow_mut().push(record.clone()),
        )
        .await
        .unwrap();
        assert_eq!(opens.get(), 1);
        assert_eq!(polls.get(), 1);
        assert_eq!(records.borrow().len(), 2);
        assert!(matches!(
            records.borrow()[0],
            CliGovernedTaskWatchRecord::Baseline { .. }
        ));

        let (session, _, _) = scripted_governed_session(vec![Ok(governed_task_update(
            TaskWatchClassification::Heartbeat,
            101,
            None,
        ))]);
        let (mut epoch_reset, _, _) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:new", 100, Vec::new()))],
            vec![Ok(session)],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let witness = Rc::clone(&records);
        consume_governed_task_watch(
            &mut epoch_reset,
            1,
            Some("epoch:old".to_owned()),
            Some(999),
            move |record| witness.borrow_mut().push(record.clone()),
        )
        .await
        .unwrap();
        let records = records.borrow();
        assert!(matches!(
            records[0],
            CliGovernedTaskWatchRecord::ResumeEpochMismatch { .. }
        ));
        assert!(matches!(
            records[1],
            CliGovernedTaskWatchRecord::Baseline { .. }
        ));
        assert!(matches!(records[2], CliGovernedTaskWatchRecord::Update(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_eof_and_transport_stop_without_reattach_or_extra_poll() {
        let (partial_session, partial_polls, partial_drops) = scripted_governed_session(vec![
            Ok(governed_task_update(
                TaskWatchClassification::Heartbeat,
                10,
                None,
            )),
            Err(ClientGovernedTaskError::UnexpectedEof),
        ]);
        let (mut partial_client, reads, opens) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:watch", 9, Vec::new()))],
            vec![Ok(partial_session)],
        );
        let partial = consume_governed_task_watch(&mut partial_client, 2, None, None, |_| {})
            .await
            .unwrap_err();
        assert_eq!(partial.reason_code, "PROJECTION_STREAM_RECOVERY_REQUIRED");
        assert_eq!(partial_polls.get(), 2);
        assert_eq!(partial_drops.get(), 1);
        assert_eq!(reads.get(), 1);
        assert_eq!(opens.get(), 1);

        let (transport_session, transport_polls, transport_drops) =
            scripted_governed_session(vec![Err(ClientGovernedTaskError::Transport(
                "tonic-status-canary".to_owned(),
            ))]);
        let (mut transport_client, _, _) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:watch", 9, Vec::new()))],
            vec![Ok(transport_session)],
        );
        let transport = consume_governed_task_watch(&mut transport_client, 1, None, None, |_| {})
            .await
            .unwrap_err();
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        assert!(!transport.message.contains("tonic-status-canary"));
        assert_eq!(transport_polls.get(), 1);
        assert_eq!(transport_drops.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_rebases_on_reset_and_enforces_three_rebase_budget() {
        let polls = Rc::new(Cell::new(0_u64));
        let drops = Rc::new(Cell::new(0_u64));
        let sessions = (11..=14)
            .map(|sequence| {
                Ok(ScriptedGovernedTaskSession {
                    outcomes: vec![Ok(governed_task_update(
                        TaskWatchClassification::ResetRequired,
                        sequence,
                        None,
                    ))]
                    .into(),
                    polls: Rc::clone(&polls),
                    drops: Rc::clone(&drops),
                })
            })
            .collect();
        let baselines = (10..=13)
            .map(|sequence| {
                Ok(governed_baseline(
                    "epoch:watch",
                    sequence,
                    vec![governed_task(
                        &format!("task:baseline-{sequence}"),
                        TaskStatus::Active,
                    )],
                ))
            })
            .collect();
        let (mut client, reads, opens) = scripted_governed_client(baselines, sessions);
        let records = Rc::new(RefCell::new(Vec::new()));
        let witness = Rc::clone(&records);
        let failure = consume_governed_task_watch(&mut client, 5, None, None, move |record| {
            witness.borrow_mut().push(record.clone())
        })
        .await
        .unwrap_err();
        assert_eq!(failure.reason_code, "RESET_REQUIRED");
        assert_eq!(reads.get(), 4);
        assert_eq!(opens.get(), 4);
        assert_eq!(polls.get(), 4);
        assert_eq!(drops.get(), 4);
        let records = records.borrow();
        assert_eq!(records.len(), 8);
        for index in [0_usize, 2, 4, 6] {
            assert!(matches!(
                records[index],
                CliGovernedTaskWatchRecord::Baseline { .. }
            ));
        }
        for index in [1_usize, 3, 5, 7] {
            assert!(matches!(
                records[index],
                CliGovernedTaskWatchRecord::Update(GovernedTaskUpdate {
                    classification: TaskWatchClassification::ResetRequired,
                    ..
                })
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_final_reset_drops_session_without_extra_rebaseline() {
        let (session, polls, drops) = scripted_governed_session(vec![Ok(governed_task_update(
            TaskWatchClassification::ResetRequired,
            11,
            None,
        ))]);
        let (mut client, reads, opens) = scripted_governed_client(
            vec![Ok(governed_baseline("epoch:watch", 10, Vec::new()))],
            vec![Ok(session)],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let witness = Rc::clone(&records);
        consume_governed_task_watch(&mut client, 1, None, None, move |record| {
            witness.borrow_mut().push(record.clone())
        })
        .await
        .unwrap();
        assert_eq!(reads.get(), 1);
        assert_eq!(opens.get(), 1);
        assert_eq!(polls.get(), 1);
        assert_eq!(drops.get(), 1);
        assert_eq!(records.borrow().len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_task_watch_baseline_failures_never_open_or_poll_live_watch() {
        let errors = vec![
            (
                ClientGovernedTaskError::Kernel(KernelError::PermissionDenied(
                    "local.task.read".to_owned(),
                )),
                "PERMISSION_DENIED",
            ),
            (
                ClientGovernedTaskError::Protocol("sensitive-integrity-canary"),
                "LOCAL_API_PROTOCOL_ERROR",
            ),
            (
                ClientGovernedTaskError::BaselineLimitExceeded,
                "LOCAL_API_PROTOCOL_ERROR",
            ),
            (
                ClientGovernedTaskError::Api(Box::new(LocalApiError {
                    code: LocalApiErrorCode::ProjectionBehind as i32,
                    retryable: true,
                    required_action_code: Some("WAIT_FOR_PROJECTION".to_owned()),
                    safe_fingerprint: "projection-behind".to_owned(),
                    ..Default::default()
                })),
                "LOCAL_API_ERROR",
            ),
        ];
        for (error, expected_reason) in errors {
            let (mut client, reads, opens) = scripted_governed_client(vec![Err(error)], Vec::new());
            let failure = consume_governed_task_watch(&mut client, 1, None, None, |_| {})
                .await
                .unwrap_err();
            assert_eq!(failure.reason_code, expected_reason);
            assert_eq!(reads.get(), 1);
            assert_eq!(opens.get(), 0);
            assert!(!failure.message.contains("sensitive-integrity-canary"));
        }
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
    fn approval_decide_cli_accepts_only_guided_surface_inputs() {
        let cli = Cli::try_parse_from([
            "egopulse",
            "approval",
            "decide",
            "approval:guided:1",
            "--decision",
            "cancel-attempt",
            "--reason-code",
            "founder-reviewed",
            "--confirmation-proof-ref",
            "proof:approval:1",
            "--json",
        ])
        .expect("guided approval CLI");
        let Command::Approval {
            command:
                ApprovalCommand::Decide {
                    approval_request_id,
                    decision,
                    reason_code,
                    confirmation_proof_ref,
                    json,
                },
        } = cli.command
        else {
            panic!("expected approval decide command")
        };
        assert_eq!(approval_request_id, "approval:guided:1");
        assert_eq!(
            parse_approval_decision(&decision),
            Ok(GuidedApprovalDecision::CancelAttempt)
        );
        assert_eq!(reason_code, "founder-reviewed");
        assert_eq!(confirmation_proof_ref.as_deref(), Some("proof:approval:1"));
        assert!(json);

        assert!(
            Cli::try_parse_from([
                "egopulse",
                "approval",
                "decide",
                "approval:guided:1",
                "--decision",
                "deny",
                "--reason-code",
                "founder-reviewed",
                "--expected-action-digest-sha256",
                &"a".repeat(64),
            ])
            .is_err()
        );
    }

    #[test]
    fn approval_decide_cli_preserves_typed_failure_categories() {
        for (value, expected) in [
            ("allow-once", GuidedApprovalDecision::AllowOnce),
            ("deny", GuidedApprovalDecision::Deny),
            ("cancel-attempt", GuidedApprovalDecision::CancelAttempt),
        ] {
            assert_eq!(parse_approval_decision(value), Ok(expected));
        }
        assert!(parse_approval_decision("allow-always").is_err());

        let permission = guided_approval_failure(ClientGuidedApprovalDecisionError::Kernel(
            KernelError::PermissionDenied("local.approval.decide".to_owned()),
        ));
        assert_eq!(permission.reason_code, "PERMISSION_DENIED");
        let authority = guided_approval_failure(ClientGuidedApprovalDecisionError::Authority {
            error_code: PolicyDecisionErrorCode::RevisionConflict as i32,
            safe_error_fingerprint: Some("approval/revision-conflict/v1".to_owned()),
        });
        assert_eq!(authority.reason_code, "POLICY_AUTHORITY_REJECTED");
        let transport = guided_approval_failure(ClientGuidedApprovalDecisionError::Transport(
            "tonic-status".to_owned(),
        ));
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        let protocol = guided_approval_failure(ClientGuidedApprovalDecisionError::Protocol(
            "sanitized approval result missing",
        ));
        assert_eq!(protocol.reason_code, "LOCAL_API_PROTOCOL_ERROR");
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

    fn guided_cli_input() -> GuidedWorkInput {
        GuidedWorkInput {
            intent: "implement bounded work start".to_owned(),
            work_type: "implementation".to_owned(),
            target_scope_ref: "project:guided".to_owned(),
            sources: vec![GuidedWorkSource {
                source_ref: "docs/brief.md".to_owned(),
                label: "docs/brief.md".to_owned(),
            }],
        }
    }

    #[test]
    fn work_start_cli_accepts_only_high_level_inputs_and_requires_explicit_non_tty_choice() {
        let cli = Cli::try_parse_from([
            "egopulse",
            "work",
            "start",
            "--intent",
            "implement bounded work start",
            "--scope",
            "project:guided",
            "--work-type",
            "implementation",
            "--context-ref",
            "docs/brief.md",
            "--confirm",
            "--json",
        ])
        .expect("guided work start CLI");
        assert!(matches!(
            cli.command,
            Command::Work {
                command: WorkCommand::Start {
                    confirm: true,
                    cancel: false,
                    json: true,
                    ..
                }
            }
        ));
        for forbidden in [
            "--snapshot-id",
            "--confirmation-binding-sha256",
            "--context-state-revision",
            "--idempotency-key",
            "--principal-id",
        ] {
            assert!(
                Cli::try_parse_from([
                    "egopulse",
                    "work",
                    "start",
                    "--intent",
                    "work",
                    "--scope",
                    "project:guided",
                    "--work-type",
                    "implementation",
                    "--context-ref",
                    "docs/brief.md",
                    "--confirm",
                    forbidden,
                    "forged",
                ])
                .is_err()
            );
        }

        assert!(matches!(
            guided_work_start_mode(&guided_cli_input(), false, false, false, false),
            Err(CliFailure {
                reason_code: "LOCAL_API_PROTOCOL_ERROR",
                ..
            })
        ));
        assert_eq!(
            guided_work_start_mode(&guided_cli_input(), false, true, false, false).unwrap(),
            GuidedWorkStartMode::Cancel
        );
        assert_eq!(
            guided_work_start_mode(&guided_cli_input(), true, false, true, false).unwrap(),
            GuidedWorkStartMode::ExplicitConfirm
        );
        assert_eq!(
            guided_work_start_mode(&guided_cli_input(), false, false, false, true).unwrap(),
            GuidedWorkStartMode::Interactive
        );
    }

    #[test]
    fn work_start_safe_preview_excludes_authority_and_sensitive_binding_fields() {
        let value = guided_work_preview_value(
            "normalized safe intent",
            "implementation",
            "project:guided",
            &["not-a-provider-task".to_owned()],
            2,
            1,
            true,
            true,
            &["SOURCE_BLOCKED".to_owned()],
            &["REVIEW_REQUIRED".to_owned()],
        );
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(encoded.contains("implementation"));
        assert!(encoded.contains("project:guided"));
        for forbidden in [
            "snapshotId",
            "confirmationBindingSha256",
            "contextStateRevision",
            "compiledContextSha256",
            "principal",
            "idempotency",
            "sensitive-intent-sentinel",
            "source:sensitive-sentinel",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn work_start_confirmation_keys_are_bounded_and_cancellable_without_a_reader_thread() {
        let mut value = String::new();
        for character in "CONFIRX".chars() {
            assert_eq!(
                apply_confirmation_key(
                    &mut value,
                    "CONFIRM",
                    KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                ),
                ConfirmationKeyAction::Continue(Some(character))
            );
        }
        assert_eq!(
            apply_confirmation_key(
                &mut value,
                "CONFIRM",
                KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
            ),
            ConfirmationKeyAction::Backspace
        );
        assert_eq!(
            apply_confirmation_key(
                &mut value,
                "CONFIRM",
                KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE),
            ),
            ConfirmationKeyAction::Continue(Some('M'))
        );
        assert_eq!(
            apply_confirmation_key(
                &mut value,
                "CONFIRM",
                KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            ),
            ConfirmationKeyAction::Submit(true)
        );
        assert_eq!(
            apply_confirmation_key(
                &mut value,
                "CONFIRM",
                KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            ),
            ConfirmationKeyAction::Cancel
        );
        assert_eq!(
            apply_confirmation_key(
                &mut value,
                "CONFIRM",
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            ),
            ConfirmationKeyAction::Cancel
        );
    }

    #[test]
    fn work_start_failures_preserve_blocked_session_authority_and_transport_categories() {
        let blocked = guided_work_failure(ClientGuidedWorkError::Blocked);
        assert_eq!(blocked.operation, "work.start");
        assert!(blocked.message.contains("no Task confirmation"));
        let session = guided_work_failure(ClientGuidedWorkError::SessionChanged);
        assert!(session.message.contains("stale"));
        let authority = guided_work_failure(ClientGuidedWorkError::Authority {
            error_code: TaskErrorCode::IdempotencyConflict as i32,
            safe_detail_code: "task/idempotency-conflict/v1".to_owned(),
        });
        assert_eq!(authority.reason_code, "TASK_AUTHORITY_REJECTED");
        let preparation_transport =
            guided_work_failure(ClientGuidedWorkError::PreparationOutcomeUnknown(
                "private preparation transport sentinel".to_owned(),
            ));
        assert_eq!(preparation_transport.reason_code, "DAEMON_UNAVAILABLE");
        assert!(
            preparation_transport
                .message
                .contains("preparation outcome")
        );
        assert!(
            !preparation_transport
                .message
                .contains("private preparation transport sentinel")
        );
        let transport = guided_work_failure(ClientGuidedWorkError::ConfirmationOutcomeUnknown(
            "private transport sentinel".to_owned(),
        ));
        assert_eq!(transport.reason_code, "DAEMON_UNAVAILABLE");
        assert!(transport.message.contains("confirmation outcome"));
        assert!(!transport.message.contains("private transport sentinel"));
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

    #[test]
    fn task_review_cli_is_positional_and_existing_task_get_stays_compatible() {
        let review = Cli::try_parse_from(["egopulse", "task", "review", "task:review", "--json"])
            .expect("task review command");
        assert!(matches!(
            review.command,
            Command::Task {
                command: TaskCommandCli::Review {
                    task_id,
                    json: true
                }
            } if task_id == "task:review"
        ));

        let get = Cli::try_parse_from(["egopulse", "task", "get", "task:existing", "--json"])
            .expect("existing task get command");
        assert!(matches!(
            get.command,
            Command::Task {
                command: TaskCommandCli::Get {
                    task_id,
                    json: true
                }
            } if task_id == "task:existing"
        ));
    }

    #[test]
    fn task_review_json_is_projected_redacted_and_never_derives_completion() {
        use egopulse_domain_contracts::v01::egopulse::{
            artifact::v1::{
                ArtifactDescriptor, ArtifactSet, Claim, Evidence, LineageBinding, ProducerIdentity,
                Provenance,
            },
            localapi::v1::{EvidenceGraphView, ProjectionPosition, RedactedField},
            task::v1::TaskSnapshot,
            verdict::v1::{
                FounderAuthorityProof, FounderVerdict, FounderVerdictState, ReworkDirective,
                RiskAcceptance,
            },
            verification::v1::{
                CriterionResult, Discrepancy, UnverifiedItem, VerificationArtifact,
                VerificationBinding, VerificationProvenance,
            },
        };

        let timestamp = || prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 42,
        };
        let contract = |id: &str| ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        };
        let address = |digest: char, byte_length| ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: digest.to_string().repeat(64),
            byte_length,
        };
        let lineage = LineageBinding {
            task_id: "task:review".to_owned(),
            task_revision: 6,
            work_revision: 2,
            run_id: "run:review".to_owned(),
            run_revision: 4,
            step_id: "step:review".to_owned(),
            step_revision: 3,
            attempt_id: "attempt:review".to_owned(),
            attempt_revision: 2,
            dispatch_id: "dispatch:review".to_owned(),
            fencing_token: 9,
        };
        let sensitive_producer = ProducerIdentity {
            principal_kind: "HarnessAdapter".to_owned(),
            principal_id: "SECRET-PRODUCER-PRINCIPAL".to_owned(),
            component_name: "safe-checker".to_owned(),
            component_version: "1.2.3".to_owned(),
            capability_profile_id: Some("capability:safe".to_owned()),
            native_execution_ref: Some("SECRET-NATIVE-REF".to_owned()),
        };
        let artifact_set = ArtifactSet {
            artifact_set_id: "artifact-set:review".to_owned(),
            revision: 3,
            status: ArtifactSetStatus::Sealed as i32,
            lineage: Some(lineage.clone()),
            artifact_ids: vec!["artifact:review".to_owned()],
            claim_ids: vec!["claim:review".to_owned()],
            evidence_ids: vec!["evidence:review".to_owned()],
            canonical_manifest: Some(address('b', 100)),
            created_at: Some(timestamp()),
            sealed_at: Some(timestamp()),
            supersedes_artifact_set_id: Some("artifact-set:previous".to_owned()),
        };
        let verification = VerificationArtifact {
            verification_artifact_id: "verification:review".to_owned(),
            version: 2,
            verification_request_id: "verification-request:review".to_owned(),
            verification_run_id: "verification-run:review".to_owned(),
            verification_type: "acceptance".to_owned(),
            binding: Some(VerificationBinding {
                lineage: Some(lineage.clone()),
                artifact_set_id: artifact_set.artifact_set_id.clone(),
                artifact_set_manifest: artifact_set.canonical_manifest.clone(),
                claim_id: "claim:review".to_owned(),
                claim_semantic_profile_ref: Some(contract("claim-profile:safe")),
                acceptance_contract_ref: Some(contract("acceptance:safe")),
            }),
            conclusion: VerificationConclusion::Partial as i32,
            overall_evidence_coverage: EvidenceCoverage::Partial as i32,
            criterion_results: vec![CriterionResult {
                criterion_result_id: "criterion-result:1".to_owned(),
                criterion_id: "criterion:1".to_owned(),
                requirement: CriterionRequirement::MustPass as i32,
                outcome: CriterionOutcome::Failed as i32,
                assurance_class: CheckerAssuranceClass::Deterministic as i32,
                checker_profile_ref: Some(contract("checker:safe")),
                evidence_coverage: EvidenceCoverage::Partial as i32,
                evidence_ids: vec!["evidence:review".to_owned()],
                discrepancy_ids: vec!["discrepancy:1".to_owned()],
                unverified_item_ids: vec!["unverified:1".to_owned()],
                duration_ms: 25,
                safe_detail_artifact_id: Some("artifact:detail".to_owned()),
            }],
            discrepancies: vec![Discrepancy {
                discrepancy_id: "discrepancy:1".to_owned(),
                criterion_id: "criterion:1".to_owned(),
                severity: DiscrepancySeverity::Major as i32,
                evidence_ids: vec!["evidence:review".to_owned()],
                description_artifact_id: "artifact:description".to_owned(),
                suggested_fix_artifact_id: Some("artifact:fix".to_owned()),
            }],
            unverified_items: vec![UnverifiedItem {
                unverified_item_id: "unverified:1".to_owned(),
                criterion_id: "criterion:1".to_owned(),
                reason: UnverifiedReason::InsufficientEvidence as i32,
                evidence_ids: vec!["evidence:review".to_owned()],
                context_artifact_id: Some("artifact:context".to_owned()),
            }],
            provenance: Some(VerificationProvenance {
                verifier_principal_id: "SECRET-VERIFIER-PRINCIPAL".to_owned(),
                checker_profile_refs: vec![contract("checker:safe")],
                tool_receipt_artifact_ids: vec!["artifact:tool-receipt".to_owned()],
                model_call_receipt_artifact_ids: vec!["artifact:model-receipt".to_owned()],
                raw_output_artifact_ids: vec!["artifact:raw-output".to_owned()],
                duration_ms: 30,
                cost_receipt_artifact_id: Some("artifact:cost".to_owned()),
            }),
            canonical_payload: Some(address('c', 200)),
            completed_at: Some(timestamp()),
            supersedes_verification_artifact_id: Some("verification:previous".to_owned()),
        };
        let review = TaskResultReview {
            task_view: TaskView {
                metadata: Some(ProjectionMetadata {
                    health: ProjectionHealth::Ready as i32,
                    position: Some(ProjectionPosition {
                        epoch: "epoch:review".to_owned(),
                        sequence: 20,
                        projected_at: Some(timestamp()),
                    }),
                    ..Default::default()
                }),
                task: Some(TaskSnapshot {
                    task_id: "task:review".to_owned(),
                    revision: 7,
                    status: TaskStatus::Active as i32,
                    ..Default::default()
                }),
                artifact_set: Some(artifact_set),
                verification: Some(verification),
                founder_verdict: Some(FounderVerdict {
                    founder_verdict_id: "verdict:review".to_owned(),
                    version: 1,
                    decision: FounderVerdictDecision::Rework as i32,
                    scope: Some(VerdictScope {
                        task_id: "task:review".to_owned(),
                        task_revision: 6,
                        work_revision: 2,
                        artifact_set_id: "artifact-set:review".to_owned(),
                        artifact_set_manifest: Some(address('b', 100)),
                        verification_artifact_id: "verification:review".to_owned(),
                        verification_payload: Some(address('c', 200)),
                        acceptance_contract_ref: Some(contract("acceptance:safe")),
                    }),
                    observed_verification_conclusion: VerificationConclusion::Partial as i32,
                    authority_proof: Some(FounderAuthorityProof {
                        authenticated_founder_principal_id: "SECRET-PRINCIPAL".to_owned(),
                        confirmation_proof_ref: "SECRET-PROOF".to_owned(),
                        ..Default::default()
                    }),
                    risk_acceptances: vec![RiskAcceptance {
                        risk_acceptance_id: "risk:1".to_owned(),
                        category: RiskCategory::QualityResidual as i32,
                        discrepancy_ids: vec!["discrepancy:1".to_owned()],
                        unverified_item_ids: vec!["unverified:1".to_owned()],
                        rationale_artifact_id: "artifact:risk-rationale".to_owned(),
                        compensating_control_artifact_ids: vec!["artifact:control".to_owned()],
                        review_trigger_code: Some("review:later".to_owned()),
                    }],
                    rework_directive: Some(ReworkDirective {
                        directive_id: "rework:1".to_owned(),
                        reason_code: "fix-major-discrepancy".to_owned(),
                        required_changes_artifact_id: "artifact:required-changes".to_owned(),
                        target_discrepancy_ids: vec!["discrepancy:1".to_owned()],
                        target_unverified_item_ids: vec!["unverified:1".to_owned()],
                    }),
                    reason_code: "founder-requires-rework".to_owned(),
                    rationale_artifact_id: Some("artifact:verdict-rationale".to_owned()),
                    valid_from: Some(timestamp()),
                    expires_at: Some(timestamp()),
                    issued_at: Some(timestamp()),
                    canonical_payload: Some(address('d', 300)),
                    supersedes_founder_verdict_id: Some("verdict:previous".to_owned()),
                }),
                founder_verdict_state: Some(FounderVerdictState {
                    founder_verdict_id: "verdict:review".to_owned(),
                    revision: 1,
                    state: FounderVerdictStateKind::Issued as i32,
                    consumption_receipt_id: Some("receipt:consumption".to_owned()),
                    superseded_by_verdict_id: Some("verdict:next".to_owned()),
                    terminal_reason_code: Some("terminal:safe".to_owned()),
                    updated_at: Some(timestamp()),
                }),
                redactions: vec![RedactedField {
                    field_path: "founder_verdict.authority_proof".to_owned(),
                    reason_code: "PRIVATE_AUTHORITY_PROOF".to_owned(),
                }],
                ..Default::default()
            },
            evidence_graph: Some(EvidenceGraphView {
                metadata: Some(ProjectionMetadata {
                    health: ProjectionHealth::Ready as i32,
                    position: Some(ProjectionPosition {
                        epoch: "epoch:review".to_owned(),
                        sequence: 10,
                        projected_at: Some(timestamp()),
                    }),
                    ..Default::default()
                }),
                task_id: "task:review".to_owned(),
                artifact_set_id: "artifact-set:review".to_owned(),
                artifacts: vec![ArtifactDescriptor {
                    artifact_id: "artifact:review".to_owned(),
                    revision: 2,
                    status: ArtifactStatus::Quarantined as i32,
                    semantic_class: ArtifactSemanticClass::HarnessOutput as i32,
                    type_contract_ref: Some(contract("artifact-type:safe")),
                    media_type: "application/json".to_owned(),
                    content: Some(address('e', 400)),
                    integrity_status: IntegrityStatus::DigestVerified as i32,
                    provenance: Some(Provenance {
                        lineage: Some(lineage.clone()),
                        producer: Some(sensitive_producer.clone()),
                        input_artifact_ids: vec!["artifact:input".to_owned()],
                        transformation_contract_ref: Some(contract("transform:safe")),
                        workspace_ref: "SECRET-WORKSPACE-REF".to_owned(),
                        observed_at: Some(timestamp()),
                        captured_at: Some(timestamp()),
                        raw_source_ref: Some("SECRET-RAW-REF".to_owned()),
                    }),
                    sensitivity_class: "internal".to_owned(),
                    retention_profile_ref: Some(contract("retention:safe")),
                    created_at: Some(timestamp()),
                    sealed_at: Some(timestamp()),
                    supersedes_artifact_id: Some("artifact:previous".to_owned()),
                    quarantine_reason_code: Some("quarantine:safe".to_owned()),
                }],
                claims: vec![Claim {
                    claim_id: "claim:review".to_owned(),
                    revision: 2,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::HarnessReport as i32,
                    semantic_profile_ref: Some(contract("claim-profile:safe")),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec!["artifact:review".to_owned()],
                    acceptance_contract_ref: Some(contract("acceptance:safe")),
                    statement: Some(address('f', 500)),
                    proposer: Some(sensitive_producer.clone()),
                    proposed_at: Some(timestamp()),
                    supersedes_claim_id: Some("claim:previous".to_owned()),
                }],
                evidence: vec![Evidence {
                    evidence_id: "evidence:review".to_owned(),
                    revision: 2,
                    status: EvidenceStatus::Recorded as i32,
                    relation: EvidenceRelation::Qualifies as i32,
                    claim_id: "claim:review".to_owned(),
                    artifact_ids: vec!["artifact:review".to_owned()],
                    evidence_profile_ref: Some(contract("evidence-profile:safe")),
                    lineage: Some(lineage),
                    producer: Some(sensitive_producer),
                    producer_class: EvidenceProducerClass::DeterministicChecker as i32,
                    independent_of_claim_proposer: true,
                    integrity_status: IntegrityStatus::DigestVerified as i32,
                    coverage_descriptor: Some(address('9', 600)),
                    limitation_codes: vec!["limitation:safe".to_owned()],
                    recorded_at: Some(timestamp()),
                    supersedes_evidence_id: Some("evidence:previous".to_owned()),
                }],
                redactions: vec![RedactedField {
                    field_path: "artifacts.provenance.raw_source_ref".to_owned(),
                    reason_code: "RAW_SOURCE_REDACTED".to_owned(),
                }],
            }),
        };

        let payload = task_result_review_json(&review);
        assert_eq!(payload["schemaVersion"], "egopulse.cli-result/v0.1");
        assert_eq!(payload["operation"], "task.review");
        assert_eq!(
            payload["data"]["kind"],
            "projected result metadata/governance evidence"
        );
        assert_eq!(payload["data"]["taskStatus"], "TASK_STATUS_ACTIVE");
        assert_eq!(
            payload["data"]["artifactSet"]["artifactSetId"],
            "artifact-set:review"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["artifactId"],
            "artifact:review"
        );
        assert_eq!(
            payload["data"]["artifactSet"]["lineage"]["dispatchId"],
            "dispatch:review"
        );
        assert_eq!(
            payload["data"]["artifactSet"]["supersedesArtifactSetId"],
            "artifact-set:previous"
        );
        assert_eq!(
            payload["data"]["artifactSet"]["createdAt"]["seconds"],
            1_700_000_000
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["semanticClass"],
            "ARTIFACT_SEMANTIC_CLASS_HARNESS_OUTPUT"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["content"]["byteLength"],
            400
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["retentionProfileRef"]["contractId"],
            "retention:safe"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["quarantineReasonCode"],
            "quarantine:safe"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["artifacts"][0]["provenance"]["inputArtifactIds"][0],
            "artifact:input"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["claims"][0]["sourceType"],
            "CLAIM_SOURCE_TYPE_HARNESS_REPORT"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["claims"][0]["statement"]["digest"],
            "f".repeat(64)
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["claims"][0]["proposedAt"]["nanos"],
            42
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["evidence"][0]["relation"],
            "EVIDENCE_RELATION_QUALIFIES"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["evidence"][0]["limitationCodes"][0],
            "limitation:safe"
        );
        assert_eq!(
            payload["data"]["evidenceGraph"]["evidence"][0]["independentOfClaimProposer"],
            true
        );
        assert_eq!(
            payload["data"]["verification"]["verificationArtifactId"],
            "verification:review"
        );
        assert_eq!(
            payload["data"]["verification"]["verificationRequestId"],
            "verification-request:review"
        );
        assert_eq!(
            payload["data"]["verification"]["binding"]["lineage"]["attemptId"],
            "attempt:review"
        );
        assert_eq!(
            payload["data"]["verification"]["overallEvidenceCoverage"],
            "EVIDENCE_COVERAGE_PARTIAL"
        );
        assert_eq!(
            payload["data"]["verification"]["criterionResults"][0]["outcome"],
            "CRITERION_OUTCOME_FAILED"
        );
        assert_eq!(
            payload["data"]["verification"]["discrepancies"][0]["severity"],
            "DISCREPANCY_SEVERITY_MAJOR"
        );
        assert_eq!(
            payload["data"]["verification"]["unverifiedItems"][0]["reason"],
            "UNVERIFIED_REASON_INSUFFICIENT_EVIDENCE"
        );
        assert_eq!(
            payload["data"]["verification"]["provenance"]["durationMs"],
            30
        );
        assert_eq!(
            payload["data"]["verification"]["canonicalPayload"]["byteLength"],
            200
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["founderVerdictId"],
            "verdict:review"
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["scope"]["verificationPayload"]["byteLength"],
            200
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["observedVerificationConclusion"],
            "VERIFICATION_CONCLUSION_PARTIAL"
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["riskAcceptances"][0]["category"],
            "RISK_CATEGORY_QUALITY_RESIDUAL"
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["reworkDirective"]["directiveId"],
            "rework:1"
        );
        assert_eq!(
            payload["data"]["founderVerdict"]["issuedAt"]["seconds"],
            1_700_000_000
        );
        assert_eq!(
            payload["data"]["founderVerdictState"]["terminalReasonCode"],
            "terminal:safe"
        );
        assert_eq!(
            payload["data"]["founderVerdictState"]["consumptionReceiptId"],
            "receipt:consumption"
        );
        assert_eq!(
            payload["data"]["taskProjection"]["position"]["sequence"],
            20
        );
        assert_eq!(payload["data"]["redactions"].as_array().unwrap().len(), 1);
        let encoded = serde_json::to_string(&payload).unwrap();
        for forbidden in [
            "SECRET-PRINCIPAL",
            "SECRET-PRODUCER-PRINCIPAL",
            "SECRET-VERIFIER-PRINCIPAL",
            "SECRET-PROOF",
            "SECRET-RAW-REF",
            "SECRET-NATIVE-REF",
            "SECRET-WORKSPACE-REF",
            "authorityProof",
            "principalId",
            "verifierPrincipalId",
            "rawSourceRef",
            "workspaceRef",
            "nativeExecutionRef",
            "artifactBytes",
        ] {
            assert!(!encoded.contains(forbidden), "leaked {forbidden}");
        }
        let text = task_result_review_text(&review);
        assert!(text.starts_with("Projected result metadata/governance evidence:"));
        assert!(text.contains("status=TASK_STATUS_ACTIVE"));
        assert!(text.contains("artifacts=1 quarantined=1"));
        assert!(text.contains("claims=1 evidence=1 relations=EVIDENCE_RELATION_QUALIFIES"));
        assert!(text.contains("coverage=EVIDENCE_COVERAGE_PARTIAL discrepancies=1 unverified=1"));
        assert!(text.contains("observed=VERIFICATION_CONCLUSION_PARTIAL"));
        assert!(text.contains("decision=FOUNDER_VERDICT_DECISION_REWORK"));
        assert!(text.contains("state=FOUNDER_VERDICT_STATE_KIND_ISSUED"));
        assert!(text.contains("terminal_reason=terminal:safe"));
        for forbidden in [
            "SECRET-PRINCIPAL",
            "SECRET-PRODUCER-PRINCIPAL",
            "SECRET-VERIFIER-PRINCIPAL",
            "SECRET-PROOF",
            "SECRET-RAW-REF",
            "SECRET-NATIVE-REF",
            "SECRET-WORKSPACE-REF",
        ] {
            assert!(!text.contains(forbidden), "text leaked {forbidden}");
        }
    }

    #[test]
    fn task_review_missing_result_components_render_as_null() {
        let review = TaskResultReview {
            task_view: TaskView {
                task: Some(
                    egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                        task_id: "task:active".to_owned(),
                        status: TaskStatus::Active as i32,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            },
            evidence_graph: None,
        };
        let payload = task_result_review_json(&review);
        for field in [
            "artifactSet",
            "evidenceGraph",
            "verification",
            "founderVerdict",
            "founderVerdictState",
        ] {
            assert!(payload["data"][field].is_null(), "{field}");
        }
        assert_eq!(payload["data"]["taskStatus"], "TASK_STATUS_ACTIVE");
    }

    struct ScriptedCliGovernedStateSession {
        state: CliGovernedStateView,
        updates: VecDeque<(GovernedStateDomain, CliGovernedStateView)>,
        polls: Rc<Cell<u32>>,
        shutdowns: Rc<Cell<u32>>,
    }

    struct FailingGovernedStateWriter;

    impl std::io::Write for FailingGovernedStateWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test broken pipe",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl CliGovernedStateSession for ScriptedCliGovernedStateSession {
        fn safe_state(&self) -> CliGovernedStateView {
            self.state.clone()
        }

        fn next_domain_update(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + '_>> {
            Box::pin(async move {
                self.polls.set(self.polls.get() + 1);
                let update = self.updates.pop_front();
                if let Some((_, state)) = &update {
                    self.state = state.clone();
                }
                update.map(|(domain, _)| domain)
            })
        }

        fn shutdown(self) -> Pin<Box<dyn Future<Output = ()>>> {
            self.shutdowns.set(self.shutdowns.get() + 1);
            Box::pin(std::future::ready(()))
        }
    }

    fn cli_governed_state_view(task_sequence: u64, approval_sequence: u64) -> CliGovernedStateView {
        CliGovernedStateView {
            task: CliGovernedTaskDomain {
                phase: GovernedStateDomainPhase::Live,
                reason: None,
                position: Some(CliGovernedStatePosition {
                    epoch: "task-epoch:test".to_owned(),
                    sequence: task_sequence,
                }),
                recovery_remaining: 3,
                recovery_limit: 3,
                generation: task_sequence,
                tasks: vec![CliGovernedStateTask {
                    task_id: format!("task:{task_sequence}"),
                    revision: task_sequence,
                    status: "task_status_active".to_owned(),
                }],
            },
            approval: CliGovernedApprovalDomain {
                phase: GovernedStateDomainPhase::Live,
                reason: None,
                position: Some(CliGovernedStatePosition {
                    epoch: "approval-epoch:test".to_owned(),
                    sequence: approval_sequence,
                }),
                recovery_remaining: 3,
                recovery_limit: 3,
                generation: approval_sequence,
                approvals: vec![CliGovernedStateApproval {
                    approval_request_id: format!("approval:{approval_sequence}"),
                    task_id: format!("task:{task_sequence}"),
                }],
            },
        }
    }

    fn cli_connecting_governed_state_view() -> CliGovernedStateView {
        CliGovernedStateView {
            task: CliGovernedTaskDomain {
                phase: GovernedStateDomainPhase::Connecting,
                reason: None,
                position: None,
                recovery_remaining: 3,
                recovery_limit: 3,
                generation: 1,
                tasks: Vec::new(),
            },
            approval: CliGovernedApprovalDomain {
                phase: GovernedStateDomainPhase::Connecting,
                reason: None,
                position: None,
                recovery_remaining: 3,
                recovery_limit: 3,
                generation: 1,
                approvals: Vec::new(),
            },
        }
    }

    fn scripted_governed_state_session(
        initial: CliGovernedStateView,
        updates: Vec<(GovernedStateDomain, CliGovernedStateView)>,
    ) -> (
        ScriptedCliGovernedStateSession,
        Rc<Cell<u32>>,
        Rc<Cell<u32>>,
    ) {
        let polls = Rc::new(Cell::new(0));
        let shutdowns = Rc::new(Cell::new(0));
        (
            ScriptedCliGovernedStateSession {
                state: initial,
                updates: updates.into(),
                polls: Rc::clone(&polls),
                shutdowns: Rc::clone(&shutdowns),
            },
            polls,
            shutdowns,
        )
    }

    #[test]
    fn governed_state_watch_requires_a_bounded_update_count() {
        assert!(validate_governed_state_watch_updates(0).is_err());
        assert!(validate_governed_state_watch_updates(1).is_ok());
        assert!(validate_governed_state_watch_updates(1000).is_ok());
        assert!(validate_governed_state_watch_updates(1001).is_err());
        assert!(Cli::try_parse_from(["egopulse", "state", "watch"]).is_err());

        let parsed =
            Cli::try_parse_from(["egopulse", "state", "watch", "--updates", "2", "--json"])
                .expect("state watch arguments should parse");
        assert!(matches!(
            parsed.command,
            Command::State {
                command: StateCommand::Watch {
                    updates: 2,
                    json: true
                }
            }
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_state_watch_emits_initial_then_independent_domain_updates() {
        let initial = cli_connecting_governed_state_view();
        let after_task = cli_governed_state_view(2, 1);
        let after_approval = cli_governed_state_view(2, 2);
        let (session, polls, shutdowns) = scripted_governed_state_session(
            initial,
            vec![
                (GovernedStateDomain::Task, after_task),
                (GovernedStateDomain::Approval, after_approval),
            ],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let captured = Rc::clone(&records);

        consume_governed_state_watch(
            session,
            3,
            std::future::pending::<()>(),
            move |index, domain, state| {
                captured.borrow_mut().push((index, domain, state.clone()));
                Ok(())
            },
        )
        .await
        .expect("early EOF should close the bounded watch cleanly");

        let records = records.borrow();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].0, 0);
        assert_eq!(records[0].1, None);
        assert_eq!(records[1].0, 1);
        assert_eq!(records[1].1, Some(GovernedStateDomain::Task));
        assert_eq!(records[2].0, 2);
        assert_eq!(records[2].1, Some(GovernedStateDomain::Approval));
        assert_eq!(polls.get(), 3, "initial output must not count as an update");
        assert_eq!(shutdowns.get(), 1);

        let initial_json = governed_state_record_json(0, None, &records[0].2);
        assert_eq!(initial_json["schemaVersion"], "egopulse.governed-state.v1");
        assert_eq!(initial_json["kind"], "initial");
        assert_eq!(initial_json["updateIndex"], 0);
        assert_eq!(initial_json["indexSemantics"], "client-local");
        assert!(initial_json["changedDomain"].is_null());
        assert_eq!(initial_json["task"]["generation"], 1);
        assert_eq!(initial_json["approval"]["generation"], 1);
        assert_eq!(initial_json["task"]["phase"], "connecting");
        assert_eq!(initial_json["approval"]["phase"], "connecting");
        assert!(initial_json["task"]["reason"].is_null());
        assert!(initial_json["approval"]["reason"].is_null());
        assert!(initial_json["task"]["position"].is_null());
        assert!(initial_json["approval"]["position"].is_null());
        assert_eq!(initial_json["task"]["tasks"], json!([]));
        assert_eq!(initial_json["approval"]["approvals"], json!([]));
        for forbidden in [
            "index",
            "cursor",
            "globalCursor",
            "combinedCursor",
            "atomicPosition",
        ] {
            assert!(initial_json.get(forbidden).is_none(), "{forbidden}");
        }
        let update_json =
            governed_state_record_json(1, Some(GovernedStateDomain::Task), &records[1].2);
        assert_eq!(update_json["kind"], "update");
        assert_eq!(update_json["updateIndex"], 1);
        assert_eq!(update_json["changedDomain"], "task");
        assert_eq!(
            update_json["task"]["tasks"][0]["status"],
            "task_status_active"
        );

        let initial_text = governed_state_record_text(0, None, &records[0].2);
        assert!(
            initial_text
                .starts_with("Governed state kind=initial update_index=0 changed_domain=none\n")
        );
        assert!(initial_text.contains("not an atomic or global cursor"));
        assert!(initial_text.contains("generation=1"));
        let update_text =
            governed_state_record_text(1, Some(GovernedStateDomain::Task), &records[1].2);
        assert!(
            update_text
                .starts_with("Governed state kind=update update_index=1 changed_domain=task\n")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_state_watch_keeps_a_fatal_task_domain_while_approval_advances() {
        let mut task_fatal = cli_governed_state_view(2, 1);
        task_fatal.task.phase = GovernedStateDomainPhase::Fatal;
        task_fatal.task.reason = Some(GovernedStateReason::ProjectionIntegrityFailure);
        let mut approval_advanced = task_fatal.clone();
        approval_advanced.approval = cli_governed_state_view(2, 2).approval;
        let (session, polls, shutdowns) = scripted_governed_state_session(
            cli_connecting_governed_state_view(),
            vec![
                (GovernedStateDomain::Task, task_fatal.clone()),
                (GovernedStateDomain::Approval, approval_advanced.clone()),
            ],
        );
        let records = Rc::new(RefCell::new(Vec::new()));
        let captured = Rc::clone(&records);

        consume_governed_state_watch(
            session,
            2,
            std::future::pending::<()>(),
            move |index, domain, state| {
                captured.borrow_mut().push((index, domain, state.clone()));
                Ok(())
            },
        )
        .await
        .expect("a fatal Task domain must not stop Approval observation");

        let records = records.borrow();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].1, Some(GovernedStateDomain::Task));
        assert_eq!(records[1].2.task, task_fatal.task);
        assert_eq!(records[2].1, Some(GovernedStateDomain::Approval));
        assert_eq!(records[2].2.task, task_fatal.task);
        assert_eq!(records[2].2.approval, approval_advanced.approval);
        assert_ne!(records[1].2.approval, records[2].2.approval);
        assert_eq!(polls.get(), 2);
        assert_eq!(shutdowns.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_state_watch_update_budget_stops_before_an_extra_poll() {
        let initial = cli_governed_state_view(1, 1);
        let (session, polls, shutdowns) = scripted_governed_state_session(
            initial,
            vec![
                (GovernedStateDomain::Task, cli_governed_state_view(2, 1)),
                (GovernedStateDomain::Approval, cli_governed_state_view(2, 2)),
                (GovernedStateDomain::Task, cli_governed_state_view(3, 2)),
            ],
        );
        let rendered = Rc::new(Cell::new(0_u32));
        let captured = Rc::clone(&rendered);

        consume_governed_state_watch(session, 2, std::future::pending::<()>(), move |_, _, _| {
            captured.set(captured.get() + 1);
            Ok(())
        })
        .await
        .expect("bounded watch should finish");

        assert_eq!(rendered.get(), 3, "initial plus exactly two updates");
        assert_eq!(polls.get(), 2);
        assert_eq!(shutdowns.get(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn governed_state_watch_stop_and_render_failures_shutdown_exactly_once() {
        let (session, polls, shutdowns) = scripted_governed_state_session(
            cli_governed_state_view(1, 1),
            vec![(GovernedStateDomain::Task, cli_governed_state_view(2, 1))],
        );
        consume_governed_state_watch(session, 1, std::future::ready(()), |_, _, _| Ok(()))
            .await
            .expect("stop should close cleanly");
        assert_eq!(polls.get(), 0);
        assert_eq!(shutdowns.get(), 1);

        let (session, polls, shutdowns) = scripted_governed_state_session(
            cli_governed_state_view(1, 1),
            vec![(GovernedStateDomain::Task, cli_governed_state_view(2, 1))],
        );
        let result = consume_governed_state_watch(
            session,
            1,
            std::future::pending::<()>(),
            |index, domain, state| {
                write_governed_state_record(
                    &mut FailingGovernedStateWriter,
                    index,
                    domain,
                    state,
                    true,
                )
            },
        )
        .await
        .expect_err("broken stdout must be a typed presentation failure");
        assert_eq!(result.operation, "state.watch");
        assert_eq!(result.reason_code, "LOCAL_API_PROTOCOL_ERROR");
        assert_eq!(polls.get(), 0);
        assert_eq!(shutdowns.get(), 1);

        let (session, polls, shutdowns) = scripted_governed_state_session(
            cli_governed_state_view(1, 1),
            vec![(GovernedStateDomain::Task, cli_governed_state_view(2, 1))],
        );
        let render_calls = Rc::new(Cell::new(0_u32));
        let captured = Rc::clone(&render_calls);
        let result = consume_governed_state_watch(
            session,
            1,
            std::future::pending::<()>(),
            move |_, _, _| {
                captured.set(captured.get() + 1);
                if captured.get() == 2 {
                    Err(CliFailure::protocol("update render rejected"))
                } else {
                    Ok(())
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(render_calls.get(), 2);
        assert_eq!(polls.get(), 1);
        assert_eq!(shutdowns.get(), 1);
    }
}
