#![forbid(unsafe_code)]

use std::{
    future::Future,
    io::{self, stdout},
    pin::Pin,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use egopulse_client_operations::{
    ClientAttachment, ClientContextRevokeError, ClientReadError, ClientWorkError,
    ContextRevokeInput, GovernedHoldReason, GovernedProjectionReason, GovernedTaskState,
    GuidedApprovalDecision, GuidedApprovalDecisionInput, HarnessContentFilter,
    PreparedContextRevoke, attach as attach_client, command_metadata, set_task_digest,
    set_verdict_digest, timestamp_after,
};
use egopulse_director_facade::{
    ContextAuthority, ContextSourceInput, DirectorInput, build_event_packet_preview,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    collaboration::v1::RunStatus,
    common::v1::ContractReference,
    harness::v1::ApprovalRequestLifecycleKind,
    localapi::v1::{
        AcceptMemoryCommand, AwaitProjectionRequest, ExecuteFounderVerdictRequest,
        ExecuteMemoryMutationRequest, ExecuteTaskCommandRequest, GetEvidenceGraphRequest,
        HarnessApprovalView, LocalApiErrorCode, MemoryMutationCommand, MemoryMutationReceipt,
        ProjectionAwaitToken, ProjectionHealth, RetrieveMemoryRequest, SourceRevision,
        SubmitMemoryCandidateCommand, TaskView, await_projection_response,
        get_evidence_graph_response, memory_mutation_command, retrieve_memory_response,
    },
    task::v1::TaskStatus,
    task::v1::{
        ApplyFounderVerdictCommand, CreateTaskCommand, RequestTaskCancellationCommand, TaskCommand,
        task_command, task_command_result,
    },
    verdict::v1::{
        FounderVerdictDecision, IssueFounderVerdictCommand, RevokeFounderVerdictCommand,
        VerdictCommand, VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_local_api::LocalApiClient;
use egopulse_tui::approval_queue::{
    ApprovalDecisionReceipt, ApprovalQueueClient, ApprovalQueueController, ApprovalQueueOpenFuture,
    GuidedApprovalFuture,
};
use egopulse_tui::governed_state::{
    GovernedStateClient, GovernedStateController, GovernedStateControllerStartError,
    GovernedStatePageModel, GovernedStateStream, domain_label,
};
use egopulse_tui::harness_content::{HarnessContentController, render_harness_content_page};
use egopulse_tui::result_review::{
    RESULT_REVIEW_NOTICE, ResultReviewController, ResultReviewPageModel, TaskResultReviewClient,
    TaskResultReviewFuture,
};
use egopulse_tui::task_watch::{
    TaskWatchBaselineFuture, TaskWatchClient, TaskWatchController, TaskWatchOpenFuture,
    TaskWatchPageModel, TaskWatchPhase,
};
use egopulse_tui::work_start::{WorkStartController, WorkStartStage, render_work_start_page};
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
    /// Build the same governed work preview as the CLI without creating a Task.
    WorkPlan {
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
    /// Compile a daemon-owned, digest-bound work preview.
    WorkPrepare {
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
    /// Confirm the exact preparation binding and create a Task through the daemon.
    WorkConfirm {
        snapshot_id: String,
        #[arg(long)]
        confirmation_binding_sha256: String,
        #[arg(long)]
        idempotency_key: String,
        #[arg(long)]
        json: bool,
    },
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
    /// Apply an issued Founder Verdict to a VerdictPending Task.
    TaskApplyVerdict {
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
    TaskCancel {
        task_id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        reason_code: String,
        #[arg(long)]
        json: bool,
    },
    /// Submit the user-owned issue_harness_approval_decision branch.
    ApprovalDecide {
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
    /// Retrieve references from one authorized accepted Memory scope.
    MemoryRetrieve {
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
    MemoryCandidate {
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
    MemoryAccept {
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
    MemoryRevoke {
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
    WorkPlan,
    WorkPrepare,
    WorkConfirm,
    TaskCreate,
    TaskApplyVerdict,
    TaskCancel,
    ApprovalDecide,
    Await,
    VerdictIssue,
    VerdictRevoke,
    EvidenceGet,
    MemoryRetrieve,
    MemoryCandidate,
    MemoryAccept,
    MemoryRevoke,
    ContextRevoke,
}

impl CommandKind {
    const ALL: [Self; 16] = [
        Self::WorkPlan,
        Self::WorkPrepare,
        Self::WorkConfirm,
        Self::TaskCreate,
        Self::TaskApplyVerdict,
        Self::TaskCancel,
        Self::ApprovalDecide,
        Self::Await,
        Self::VerdictIssue,
        Self::VerdictRevoke,
        Self::EvidenceGet,
        Self::MemoryRetrieve,
        Self::MemoryCandidate,
        Self::MemoryAccept,
        Self::MemoryRevoke,
        Self::ContextRevoke,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::WorkPlan => "Preview governed work",
            Self::WorkPrepare => "Prepare governed work",
            Self::WorkConfirm => "Confirm and create governed task",
            Self::TaskCreate => "Create governed task",
            Self::TaskApplyVerdict => "Apply Founder Verdict",
            Self::TaskCancel => "Request task cancellation",
            Self::ApprovalDecide => "Decide harness approval",
            Self::Await => "Await projection",
            Self::VerdictIssue => "Issue Founder Verdict",
            Self::VerdictRevoke => "Revoke Founder Verdict",
            Self::EvidenceGet => "Read Evidence Graph",
            Self::MemoryRetrieve => "Retrieve accepted Memory",
            Self::MemoryCandidate => "Submit Memory candidate",
            Self::MemoryAccept => "Accept Memory candidate",
            Self::MemoryRevoke => "Revoke Memory",
            Self::ContextRevoke => "Revoke governed Context",
        }
    }
}

#[derive(Clone, Debug)]
struct FormField {
    label: &'static str,
    value: String,
    required: bool,
    sensitive: bool,
}

impl FormField {
    fn required(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: true,
            sensitive: false,
        }
    }

    fn optional(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            required: false,
            sensitive: false,
        }
    }

    fn with_value(mut self, value: &'static str) -> Self {
        self.value = value.to_owned();
        self
    }

    fn sensitive(mut self) -> Self {
        self.sensitive = true;
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
            CommandKind::WorkPlan => vec![
                FormField::required("intent"),
                FormField::required("scope-ref"),
                FormField::required("work-type").with_value("general"),
                FormField::optional("context-ref"),
            ],
            CommandKind::WorkPrepare => vec![
                FormField::required("intent"),
                FormField::required("scope-ref"),
                FormField::required("work-type"),
                FormField::optional("context-ref"),
                FormField::required("idempotency-key"),
            ],
            CommandKind::WorkConfirm => vec![
                FormField::required("snapshot-id"),
                FormField::required("confirmation-binding-sha256"),
                FormField::required("idempotency-key"),
            ],
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
            CommandKind::TaskApplyVerdict => vec![
                FormField::required("task-id"),
                FormField::required("expected-revision"),
                FormField::required("work-revision"),
                FormField::required("founder-verdict-id"),
            ],
            CommandKind::TaskCancel => vec![
                FormField::required("task-id"),
                FormField::required("expected-revision"),
                FormField::required("reason-code"),
            ],
            CommandKind::ApprovalDecide => vec![
                FormField::required("approval-request-id"),
                FormField::required("decision"),
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
            CommandKind::MemoryRetrieve => vec![
                FormField::required("query"),
                FormField::required("scope-ref"),
                FormField::required("max-results").with_value("8"),
                FormField::required("min-score").with_value("0.0"),
            ],
            CommandKind::MemoryCandidate => vec![
                FormField::required("memory-id"),
                FormField::required("content"),
                FormField::required("source-ref"),
                FormField::required("scope-ref"),
                FormField::required("idempotency-key"),
            ],
            CommandKind::MemoryAccept | CommandKind::MemoryRevoke => vec![
                FormField::required("memory-id"),
                FormField::required("expected-revision"),
                FormField::required("evidence-ref"),
                FormField::required("idempotency-key"),
            ],
            CommandKind::ContextRevoke => vec![
                FormField::required("snapshot-id"),
                FormField::required("expected-state-revision"),
                FormField::required("reason-code").sensitive(),
                FormField::required("evidence-ref").sensitive(),
                FormField::required("confirmation-proof-ref").sensitive(),
                FormField::required("idempotency-key"),
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

    fn add_context_evidence_entry(&mut self) -> bool {
        if self.kind != CommandKind::ContextRevoke {
            return false;
        }
        let insertion = self
            .fields
            .iter()
            .rposition(|field| field.label == "evidence-ref")
            .map_or(3, |index| index + 1);
        self.fields
            .insert(insertion, FormField::required("evidence-ref").sensitive());
        self.active = insertion;
        self.error = None;
        true
    }

    fn remove_active_context_evidence_entry(&mut self) -> bool {
        if self.kind != CommandKind::ContextRevoke
            || self.fields[self.active].label != "evidence-ref"
            || self
                .fields
                .iter()
                .filter(|field| field.label == "evidence-ref")
                .count()
                == 1
        {
            return false;
        }
        self.fields.remove(self.active);
        self.active = self.active.min(self.fields.len().saturating_sub(1));
        self.error = None;
        true
    }

    fn validate(&self) -> Result<(), String> {
        for field in &self.fields {
            if field.required && field.value.trim().is_empty() {
                return Err(format!("{} is required", field.label));
            }
        }
        Ok(())
    }

    fn into_action(self) -> Result<InteractiveAction, String> {
        if self.kind == CommandKind::ContextRevoke {
            return self
                .into_context_revoke_input()
                .map(InteractiveAction::StageContextRevoke);
        }
        self.into_command()
            .map(Box::new)
            .map(InteractiveAction::Command)
    }

    fn into_context_revoke_input(self) -> Result<ContextRevokeInput, String> {
        self.validate()?;
        let mut snapshot_id = None;
        let mut expected_state_revision = None;
        let mut reason_code = None;
        let mut evidence_refs = Vec::new();
        let mut confirmation_proof_ref = None;
        let mut idempotency_key = None;
        for field in self.fields {
            match field.label {
                "snapshot-id" => snapshot_id = Some(field.value),
                "expected-state-revision" => {
                    expected_state_revision = Some(
                        field
                            .value
                            .parse()
                            .map_err(|_| "expected-state-revision must be an integer".to_owned())?,
                    )
                }
                "reason-code" => reason_code = Some(field.value),
                "evidence-ref" => evidence_refs.push(field.value),
                "confirmation-proof-ref" => confirmation_proof_ref = Some(field.value),
                "idempotency-key" => idempotency_key = Some(field.value),
                label => return Err(format!("unexpected Context revoke field: {label}")),
            }
        }
        Ok(ContextRevokeInput {
            snapshot_id: snapshot_id.ok_or_else(|| "snapshot-id is missing".to_owned())?,
            expected_state_revision: expected_state_revision
                .ok_or_else(|| "expected-state-revision is missing".to_owned())?,
            reason_code: reason_code.ok_or_else(|| "reason-code is missing".to_owned())?,
            evidence_refs,
            confirmation_proof_ref: confirmation_proof_ref
                .ok_or_else(|| "confirmation-proof-ref is missing".to_owned())?,
            idempotency_key: idempotency_key
                .ok_or_else(|| "idempotency-key is missing".to_owned())?,
        })
    }

    fn into_command(self) -> Result<TuiCommand, String> {
        self.validate()?;
        let mut values = self.fields.into_iter().map(|field| field.value);
        let next = |values: &mut dyn Iterator<Item = String>, label: &str| {
            values.next().ok_or_else(|| format!("{label} is missing"))
        };
        match self.kind {
            CommandKind::WorkPlan => Ok(TuiCommand::WorkPlan {
                intent: next(&mut values, "intent")?,
                scope: next(&mut values, "scope-ref")?,
                work_type: next(&mut values, "work-type")?,
                context_refs: {
                    let value = next(&mut values, "context-ref")?;
                    (!value.trim().is_empty())
                        .then_some(value)
                        .into_iter()
                        .collect()
                },
                json: false,
            }),
            CommandKind::WorkPrepare => Ok(TuiCommand::WorkPrepare {
                intent: next(&mut values, "intent")?,
                scope: next(&mut values, "scope-ref")?,
                work_type: next(&mut values, "work-type")?,
                context_refs: {
                    let value = next(&mut values, "context-ref")?;
                    (!value.trim().is_empty())
                        .then_some(value)
                        .into_iter()
                        .collect()
                },
                idempotency_key: next(&mut values, "idempotency-key")?,
                json: false,
            }),
            CommandKind::WorkConfirm => Ok(TuiCommand::WorkConfirm {
                snapshot_id: next(&mut values, "snapshot-id")?,
                confirmation_binding_sha256: next(&mut values, "confirmation-binding-sha256")?,
                idempotency_key: next(&mut values, "idempotency-key")?,
                json: false,
            }),
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
            CommandKind::TaskApplyVerdict => Ok(TuiCommand::TaskApplyVerdict {
                task_id: next(&mut values, "task-id")?,
                expected_revision: next(&mut values, "expected-revision")?
                    .parse()
                    .map_err(|_| "expected-revision must be an integer".to_owned())?,
                work_revision: next(&mut values, "work-revision")?
                    .parse()
                    .map_err(|_| "work-revision must be an integer".to_owned())?,
                founder_verdict_id: next(&mut values, "founder-verdict-id")?,
                json: false,
            }),
            CommandKind::TaskCancel => Ok(TuiCommand::TaskCancel {
                task_id: next(&mut values, "task-id")?,
                expected_revision: next(&mut values, "expected-revision")?
                    .parse()
                    .map_err(|_| "expected-revision must be an integer".to_owned())?,
                reason_code: next(&mut values, "reason-code")?,
                json: false,
            }),
            CommandKind::ApprovalDecide => Ok(TuiCommand::ApprovalDecide {
                approval_request_id: next(&mut values, "approval-request-id")?,
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
            CommandKind::MemoryRetrieve => Ok(TuiCommand::MemoryRetrieve {
                query: next(&mut values, "query")?,
                scope: next(&mut values, "scope-ref")?,
                max_results: next(&mut values, "max-results")?
                    .parse()
                    .map_err(|_| "max-results must be an integer".to_owned())?,
                min_score: next(&mut values, "min-score")?
                    .parse()
                    .map_err(|_| "min-score must be a number".to_owned())?,
                json: false,
            }),
            CommandKind::MemoryCandidate => Ok(TuiCommand::MemoryCandidate {
                memory_id: next(&mut values, "memory-id")?,
                content: next(&mut values, "content")?,
                source_ref: next(&mut values, "source-ref")?,
                scope: next(&mut values, "scope-ref")?,
                idempotency_key: next(&mut values, "idempotency-key")?,
                json: false,
            }),
            CommandKind::MemoryAccept => Ok(TuiCommand::MemoryAccept {
                memory_id: next(&mut values, "memory-id")?,
                expected_revision: next(&mut values, "expected-revision")?
                    .parse()
                    .map_err(|_| "expected-revision must be an integer".to_owned())?,
                evidence_ref: next(&mut values, "evidence-ref")?,
                idempotency_key: next(&mut values, "idempotency-key")?,
                json: false,
            }),
            CommandKind::MemoryRevoke => Ok(TuiCommand::MemoryRevoke {
                memory_id: next(&mut values, "memory-id")?,
                expected_revision: next(&mut values, "expected-revision")?
                    .parse()
                    .map_err(|_| "expected-revision must be an integer".to_owned())?,
                evidence_ref: next(&mut values, "evidence-ref")?,
                idempotency_key: next(&mut values, "idempotency-key")?,
                json: false,
            }),
            CommandKind::ContextRevoke => Err(
                "Context revoke must be staged through the interactive confirmation modal"
                    .to_owned(),
            ),
        }
    }
}

enum InteractiveMode {
    Dashboard,
    GovernedState,
    WorkStart,
    TaskWatch,
    HarnessContent,
    ResultReview,
    ApprovalQueue,
    ApprovalDecisionModal(ApprovalDecisionModal),
    Palette { selected: usize },
    Form(CommandForm),
    ContextRevokeConfirmation(PendingContextRevoke),
}

enum InteractiveAction {
    Command(Box<TuiCommand>),
    StageContextRevoke(ContextRevokeInput),
    ConfirmContextRevoke,
    OpenWorkStart,
    OpenGovernedState,
    CloseGovernedState,
    CloseWorkStart,
    PrepareWorkStart,
    ReplayWorkPreparation,
    CancelWorkPreview,
    ConfirmWorkStart,
    ReplayWorkConfirmation,
    OpenTaskWatchForWorkReconciliation,
    OpenTaskWatch,
    RefetchTaskWatch,
    CloseTaskWatch,
    OpenHarnessContent,
    RefetchHarnessContent,
    CloseHarnessContent,
    OpenResultReview,
    RefreshResultReview,
    CloseResultReview,
    OpenApprovalQueue,
    RefetchApprovalQueue,
    CloseApprovalQueue,
    SubmitApprovalDecision,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkStartKeyIntent {
    Ignore,
    Quit,
    Close,
    NextField,
    PreviousField,
    Backspace,
    Push(char),
    Prepare,
    WaitForPreparation,
    Confirm,
    CancelPreview,
    ReplayPreparation,
    KeepPreparationRecovery,
    ConfirmationCannotCancel,
    ReplayConfirmation,
    ReconcileInTaskWatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkStartExitPolicy {
    DropSettled,
    CancelPreview,
    AwaitSettlement,
    PreserveRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkStartMutationAction {
    Prepare,
    ReplayPreparation,
    CancelPreview,
    Confirm,
    ReplayConfirmation,
}

type WorkStartMutationFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

trait WorkStartMutationTarget {
    fn prepare_mutation(&mut self) -> WorkStartMutationFuture<'_>;
    fn replay_preparation_mutation(&mut self) -> WorkStartMutationFuture<'_>;
    fn cancel_preview_mutation(&mut self) -> WorkStartMutationFuture<'_>;
    fn confirm_mutation(&mut self) -> WorkStartMutationFuture<'_>;
    fn replay_confirmation_mutation(&mut self) -> WorkStartMutationFuture<'_>;
}

impl WorkStartMutationTarget for WorkStartController {
    fn prepare_mutation(&mut self) -> WorkStartMutationFuture<'_> {
        Box::pin(self.prepare())
    }

    fn replay_preparation_mutation(&mut self) -> WorkStartMutationFuture<'_> {
        Box::pin(self.replay_preparation())
    }

    fn cancel_preview_mutation(&mut self) -> WorkStartMutationFuture<'_> {
        Box::pin(self.cancel_preview())
    }

    fn confirm_mutation(&mut self) -> WorkStartMutationFuture<'_> {
        Box::pin(self.confirm())
    }

    fn replay_confirmation_mutation(&mut self) -> WorkStartMutationFuture<'_> {
        Box::pin(self.replay_confirmation())
    }
}

async fn execute_work_start_mutation<T: WorkStartMutationTarget + ?Sized>(
    target: &mut T,
    action: WorkStartMutationAction,
) -> Result<(), String> {
    match action {
        WorkStartMutationAction::Prepare => target.prepare_mutation().await,
        WorkStartMutationAction::ReplayPreparation => target.replay_preparation_mutation().await,
        WorkStartMutationAction::CancelPreview => target.cancel_preview_mutation().await,
        WorkStartMutationAction::Confirm => target.confirm_mutation().await,
        WorkStartMutationAction::ReplayConfirmation => target.replay_confirmation_mutation().await,
    }
}

fn work_start_exit_policy(stage: WorkStartStage, running: bool) -> WorkStartExitPolicy {
    if running {
        WorkStartExitPolicy::AwaitSettlement
    } else {
        match stage {
            WorkStartStage::PreviewReady => WorkStartExitPolicy::CancelPreview,
            WorkStartStage::PreparationOutcomeUnknown
            | WorkStartStage::ConfirmationOutcomeUnknown => WorkStartExitPolicy::PreserveRecovery,
            WorkStartStage::Editing
            | WorkStartStage::Preparing
            | WorkStartStage::Confirming
            | WorkStartStage::Failed => WorkStartExitPolicy::DropSettled,
        }
    }
}

fn work_start_key_intent(
    stage: WorkStartStage,
    key: crossterm::event::KeyEvent,
) -> WorkStartKeyIntent {
    match (stage, key.code) {
        (_, KeyCode::Char('q')) => WorkStartKeyIntent::Quit,
        (WorkStartStage::Editing, KeyCode::Esc) | (WorkStartStage::Failed, KeyCode::Esc) => {
            WorkStartKeyIntent::Close
        }
        (WorkStartStage::Editing, KeyCode::Tab) => WorkStartKeyIntent::NextField,
        (WorkStartStage::Editing, KeyCode::BackTab) => WorkStartKeyIntent::PreviousField,
        (WorkStartStage::Editing, KeyCode::Backspace) => WorkStartKeyIntent::Backspace,
        (WorkStartStage::Editing, KeyCode::Char(character))
            if !key
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL) =>
        {
            WorkStartKeyIntent::Push(character)
        }
        (WorkStartStage::Editing | WorkStartStage::Failed, KeyCode::Enter) => {
            WorkStartKeyIntent::Prepare
        }
        (WorkStartStage::Preparing, KeyCode::Esc) => WorkStartKeyIntent::WaitForPreparation,
        (WorkStartStage::PreviewReady, KeyCode::Enter) => WorkStartKeyIntent::Confirm,
        (WorkStartStage::PreviewReady, KeyCode::Esc) => WorkStartKeyIntent::CancelPreview,
        (WorkStartStage::PreparationOutcomeUnknown, KeyCode::Enter) => {
            WorkStartKeyIntent::ReplayPreparation
        }
        (WorkStartStage::PreparationOutcomeUnknown, KeyCode::Esc) => {
            WorkStartKeyIntent::KeepPreparationRecovery
        }
        (WorkStartStage::Confirming, KeyCode::Esc) => WorkStartKeyIntent::ConfirmationCannotCancel,
        (WorkStartStage::ConfirmationOutcomeUnknown, KeyCode::Enter) => {
            WorkStartKeyIntent::ReplayConfirmation
        }
        (WorkStartStage::ConfirmationOutcomeUnknown, KeyCode::Char('w')) => {
            WorkStartKeyIntent::ReconcileInTaskWatch
        }
        _ => WorkStartKeyIntent::Ignore,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovalModalField {
    Reason,
    Proof,
}

struct ApprovalDecisionModal {
    approval_request_id: String,
    decision: Option<GuidedApprovalDecision>,
    reason_code: String,
    confirmation_proof_ref: String,
    active_field: ApprovalModalField,
    submitting: bool,
}

impl ApprovalDecisionModal {
    fn new(approval_request_id: String) -> Self {
        Self {
            approval_request_id,
            decision: None,
            reason_code: String::new(),
            confirmation_proof_ref: String::new(),
            active_field: ApprovalModalField::Reason,
            submitting: false,
        }
    }

    fn cycle_decision(&mut self, forward: bool) {
        const VALUES: [GuidedApprovalDecision; 3] = [
            GuidedApprovalDecision::AllowOnce,
            GuidedApprovalDecision::Deny,
            GuidedApprovalDecision::CancelAttempt,
        ];
        let index = self
            .decision
            .and_then(|value| VALUES.iter().position(|candidate| *candidate == value));
        let next = match (index, forward) {
            (None, _) => 0,
            (Some(index), true) => (index + 1) % VALUES.len(),
            (Some(0), false) => VALUES.len() - 1,
            (Some(index), false) => index - 1,
        };
        self.decision = Some(VALUES[next]);
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.active_field {
            ApprovalModalField::Reason => &mut self.reason_code,
            ApprovalModalField::Proof => &mut self.confirmation_proof_ref,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InteractiveLoopControl {
    Continue,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextRevokeModalKeyAction {
    Confirm,
    Cancel,
    Ignore,
}

fn context_revoke_modal_key_action(key: KeyCode) -> ContextRevokeModalKeyAction {
    match key {
        KeyCode::Enter => ContextRevokeModalKeyAction::Confirm,
        KeyCode::Esc => ContextRevokeModalKeyAction::Cancel,
        _ => ContextRevokeModalKeyAction::Ignore,
    }
}

type ContextRevokeReceipt =
    egopulse_domain_contracts::v01::egopulse::localapi::v1::ContextRevokeReceipt;
type ContextRevokeCommitFuture =
    Pin<Box<dyn Future<Output = Result<ContextRevokeReceipt, String>> + Send>>;
type SnapshotFuture<'a> = Pin<Box<dyn Future<Output = Result<Snapshot, String>> + Send + 'a>>;

trait ContextRevokeCommit: Send {
    fn commit(self: Box<Self>) -> ContextRevokeCommitFuture;
}

struct ProductionContextRevokeCommit {
    attachment: Arc<ClientAttachment>,
    prepared: PreparedContextRevoke,
}

impl ContextRevokeCommit for ProductionContextRevokeCommit {
    fn commit(self: Box<Self>) -> ContextRevokeCommitFuture {
        Box::pin(async move {
            let supplied_digest = self.prepared.request_digest_sha256().to_owned();
            self.attachment
                .execute_context_revoke(self.prepared, &supplied_digest)
                .await
                .map_err(tui_context_revoke_error)
        })
    }
}

struct PendingContextRevoke {
    snapshot_id: String,
    expected_state_revision: u64,
    evidence_count: usize,
    request_digest_sha256: String,
    commit: Box<dyn ContextRevokeCommit>,
}

impl PendingContextRevoke {
    fn production(attachment: Arc<ClientAttachment>, prepared: PreparedContextRevoke) -> Self {
        Self {
            snapshot_id: prepared.snapshot_id().to_owned(),
            expected_state_revision: prepared.expected_state_revision(),
            evidence_count: prepared.evidence_count(),
            request_digest_sha256: prepared.request_digest_sha256().to_owned(),
            commit: Box::new(ProductionContextRevokeCommit {
                attachment,
                prepared,
            }),
        }
    }

    async fn commit(self) -> Result<ContextRevokeReceipt, String> {
        self.commit.commit().await
    }
}

trait InteractiveClient: TaskWatchClient + ApprovalQueueClient + TaskResultReviewClient {
    fn snapshot(&self) -> SnapshotFuture<'_>;
    fn prepare_context_revoke(
        &self,
        input: ContextRevokeInput,
    ) -> Result<PendingContextRevoke, String>;
    fn work_start_controller(&self) -> Result<WorkStartController, String> {
        Err("Work Start is unavailable for this client".to_owned())
    }
}

struct AttachedClient(Arc<ClientAttachment>);

impl AttachedClient {
    async fn open(instance: &str) -> Result<Self, String> {
        let attached = attach_client(
            instance,
            egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientSurface::Tui,
            format!("egopulse-tui-{}", Uuid::now_v7()),
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok(Self(Arc::new(attached)))
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

    async fn read_snapshot(&self) -> Result<Snapshot, String> {
        let projection = self
            .0
            .read_projection_snapshot()
            .await
            .map_err(|error| match error {
                ClientReadError::Api(error) => local_error_message(*error),
                other => other.to_string(),
            })?;
        let position = projection.metadata.position;
        Ok(Snapshot {
            health: ProjectionHealth::try_from(projection.metadata.health)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned()),
            stale: projection.metadata.stale,
            position: position
                .as_ref()
                .map(|value| format!("{}:{}", value.epoch, value.sequence))
                .unwrap_or_else(|| "unknown".to_owned()),
            tasks: projection.tasks,
            approvals: projection.approvals,
        })
    }
}

impl InteractiveClient for AttachedClient {
    fn snapshot(&self) -> SnapshotFuture<'_> {
        Box::pin(self.read_snapshot())
    }

    fn prepare_context_revoke(
        &self,
        input: ContextRevokeInput,
    ) -> Result<PendingContextRevoke, String> {
        let prepared = self
            .0
            .prepare_context_revoke(input)
            .map_err(tui_context_revoke_error)?;
        Ok(PendingContextRevoke::production(
            Arc::clone(&self.0),
            prepared,
        ))
    }

    fn work_start_controller(&self) -> Result<WorkStartController, String> {
        Ok(WorkStartController::new(Arc::clone(&self.0)))
    }
}

impl TaskWatchClient for AttachedClient {
    fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
        TaskWatchClient::read_task_watch_baseline(self.0.as_ref())
    }

    fn open_task_watch_session(
        &self,
        baseline: egopulse_tui::task_watch::TaskWatchBaseline,
    ) -> TaskWatchOpenFuture<'_> {
        TaskWatchClient::open_task_watch_session(self.0.as_ref(), baseline)
    }
}

impl ApprovalQueueClient for AttachedClient {
    fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
        ApprovalQueueClient::open_approval_queue(self.0.as_ref())
    }

    fn decide_guided_approval(
        &self,
        input: GuidedApprovalDecisionInput,
    ) -> GuidedApprovalFuture<'_> {
        ApprovalQueueClient::decide_guided_approval(self.0.as_ref(), input)
    }
}

impl TaskResultReviewClient for AttachedClient {
    fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a> {
        TaskResultReviewClient::read_task_result_review(self.0.as_ref(), task_id)
    }
}

impl GovernedStateClient for AttachedClient {
    fn start_governed_state_stream(
        self: &Arc<Self>,
    ) -> Result<Box<dyn GovernedStateStream>, GovernedStateControllerStartError> {
        GovernedStateClient::start_governed_state_stream(&self.0)
    }
}

fn shared_attached_client_pair<Client>(client: Client) -> (Arc<Client>, Arc<Client>) {
    let client = Arc::new(client);
    (client.clone(), client)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandOutput {
    Console,
    Quiet,
}

enum CommandResult {
    Completed,
    ReadView(String),
}

async fn run_command(instance: &str, command: TuiCommand) -> Result<(), String> {
    Box::pin(run_command_with_output(
        instance,
        command,
        CommandOutput::Console,
    ))
    .await
    .map(|_| ())
}

async fn run_command_quiet(instance: &str, command: TuiCommand) -> Result<CommandResult, String> {
    Box::pin(run_command_with_output(
        instance,
        command,
        CommandOutput::Quiet,
    ))
    .await
}

async fn run_command_with_output(
    instance: &str,
    command: TuiCommand,
    output: CommandOutput,
) -> Result<CommandResult, String> {
    match command {
        TuiCommand::WorkPlan {
            intent,
            scope,
            work_type,
            context_refs,
            json,
        } => {
            let preview = build_event_packet_preview(&DirectorInput {
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
            })
            .map_err(|error| error.to_string())?;
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "work.plan",
                "data": preview,
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
            Ok(CommandResult::Completed)
        }
        TuiCommand::WorkPrepare {
            intent,
            scope,
            work_type,
            context_refs,
            idempotency_key,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
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
                .map_err(tui_work_error)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "schemaVersion": "egopulse.tui-result/v0.1",
                        "ok": true,
                        "operation": "work.prepare",
                        "data": {
                            "snapshotId": preview.snapshot_id,
                            "snapshotRevision": preview.snapshot_revision,
                            "contextStateRevision": preview.context_state_revision,
                            "gateReady": preview.gate_ready,
                            "readyForFounderConfirmation": preview.ready_for_founder_confirmation,
                            "compiledContextSha256": preview.compiled_context_sha256,
                            "confirmationBindingSha256": preview.confirmation_binding_sha256,
                            "includedSources": preview.included_sources.iter().map(|source| json!({"sourceRef": source.source_ref, "label": source.label, "contentSha256": source.content_sha256, "authority": source.authority, "included": source.included})).collect::<Vec<_>>(),
                            "excludedSources": preview.excluded_sources.iter().map(|notice| json!({"code": notice.code, "detail": notice.detail, "sourceRef": notice.source_ref})).collect::<Vec<_>>(),
                            "blockers": preview.blockers.iter().map(|notice| json!({"code": notice.code, "detail": notice.detail, "sourceRef": notice.source_ref})).collect::<Vec<_>>(),
                        }
                    }))
                    .unwrap()
                );
            } else {
                println!(
                    "Work prepared: snapshot={} context_state_revision={} gate_ready={} sources={}",
                    preview.snapshot_id,
                    preview.context_state_revision,
                    preview.gate_ready,
                    preview.included_sources.len()
                );
                println!("Next: review the preview, then run work-confirm with its binding.");
            }
            Ok(CommandResult::Completed)
        }
        TuiCommand::WorkConfirm {
            snapshot_id,
            confirmation_binding_sha256,
            idempotency_key,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_rpc("LocalCommandGatewayService/ConfirmWork", "work.confirm")?;
            let confirmed = attached
                .0
                .confirm_work(snapshot_id, confirmation_binding_sha256, idempotency_key)
                .await
                .map_err(tui_work_error)?;
            let replayed = confirmed.result.replayed;
            let task = match confirmed.result.outcome {
                Some(task_command_result::Outcome::Task(task)) => task,
                Some(task_command_result::Outcome::Error(error)) => {
                    return Err(format!(
                        "TASK_AUTHORITY_REJECTED code={} detail={}",
                        error.code, error.safe_detail_code
                    ));
                }
                None => return Err("confirmed task authority outcome missing".to_owned()),
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "schemaVersion": "egopulse.tui-result/v0.1",
                        "ok": true,
                        "operation": "work.confirm",
                        "data": {
                            "taskId": task.task_id,
                            "revision": task.revision,
                            "status": TaskStatus::try_from(task.status).map(|status| status.as_str_name()).unwrap_or("TASK_STATUS_UNSPECIFIED"),
                            "replayed": replayed,
                            "awaitToken": await_token_json(confirmed.await_token)
                        }
                    }))
                    .unwrap()
                );
            } else {
                println!(
                    "Work confirmed: task={} revision={} status={} replayed={}",
                    task.task_id,
                    task.revision,
                    TaskStatus::try_from(task.status)
                        .map(|status| status.as_str_name())
                        .unwrap_or("TASK_STATUS_UNSPECIFIED"),
                    replayed,
                );
            }
            Ok(CommandResult::Completed)
        }
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
            set_task_digest(&mut command);
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
            Ok(CommandResult::Completed)
        }
        TuiCommand::TaskApplyVerdict {
            task_id,
            expected_revision,
            work_revision,
            founder_verdict_id,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/ExecuteTaskCommand",
                "apply_founder_verdict",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = TaskCommand {
                command: Some(task_command::Command::ApplyFounderVerdict(
                    ApplyFounderVerdictCommand {
                        meta: Some(command_metadata(
                            &correlation_id,
                            "egopulse-tui/task-apply-verdict",
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
                "operation": "task.apply-verdict",
                "data": {
                    "taskId": task.task_id,
                    "revision": task.revision,
                    "status": TaskStatus::try_from(task.status)
                        .map(|value| value.as_str_name())
                        .unwrap_or("TASK_STATUS_UNSPECIFIED"),
                    "founderVerdictId": task.founder_verdict_id,
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
                        "TUI Task Founder Verdict applied: task={} revision={} status={} replayed={}",
                        payload["data"]["taskId"].as_str().unwrap_or(""),
                        payload["data"]["revision"].as_u64().unwrap_or_default(),
                        payload["data"]["status"].as_str().unwrap_or(""),
                        payload["data"]["replayed"].as_bool().unwrap_or(false),
                    );
                }
            }
            Ok(CommandResult::Completed)
        }
        TuiCommand::TaskCancel {
            task_id,
            expected_revision,
            reason_code,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_command(
                "LocalCommandGatewayService/ExecuteTaskCommand",
                "request_task_cancellation",
            )?;
            let correlation_id = Uuid::now_v7().to_string();
            let mut command = TaskCommand {
                command: Some(task_command::Command::RequestTaskCancellation(
                    RequestTaskCancellationCommand {
                        meta: Some(command_metadata(
                            &correlation_id,
                            "egopulse-tui/task-cancel",
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
                "operation": "task.cancel",
                "data": {
                    "taskId": task.task_id,
                    "revision": task.revision,
                    "status": TaskStatus::try_from(task.status)
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
                        "TUI task cancellation requested: {} revision={} status={} replayed={}",
                        payload["data"]["taskId"].as_str().unwrap_or(""),
                        payload["data"]["revision"].as_u64().unwrap_or_default(),
                        payload["data"]["status"].as_str().unwrap_or(""),
                        payload["data"]["replayed"].as_bool().unwrap_or(false),
                    );
                }
            }
            Ok(CommandResult::Completed)
        }
        TuiCommand::ApprovalDecide {
            approval_request_id,
            decision,
            reason_code,
            confirmation_proof_ref,
            json,
        } => {
            let decision = parse_approval_decision(&decision)?;
            let attached = AttachedClient::open(instance).await?;
            let result = attached
                .0
                .decide_guided_approval(GuidedApprovalDecisionInput {
                    approval_request_id,
                    decision,
                    reason_code,
                    confirmation_proof_ref,
                })
                .await
                .map_err(|error| error.to_string())?;
            let payload = json!({
                "schemaVersion": "egopulse.tui-result/v0.1",
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
                        "code": warning.code,
                        "retryable": warning.retryable,
                        "requiredActionCode": warning.required_action_code,
                        "safeFingerprint": warning.safe_fingerprint,
                    })),
                },
                "correlationId": result.correlation_id(),
            });
            if output == CommandOutput::Console {
                if json {
                    println!("{}", serde_json::to_string(&payload).unwrap());
                } else {
                    println!(
                        "TUI approval decided: ref={} - {}",
                        payload["data"]["authorityDecisionRef"]
                            .as_str()
                            .unwrap_or(""),
                        approval_decision_feedback(
                            result.state_revision(),
                            result.replayed(),
                            result.projection_warning().is_some(),
                        )
                    );
                }
            }
            Ok(CommandResult::Completed)
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
                    Ok(CommandResult::Completed)
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
                    Ok(CommandResult::Completed)
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
            Ok(CommandResult::Completed)
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
            Ok(CommandResult::Completed)
        }
        TuiCommand::MemoryRetrieve {
            query,
            scope,
            max_results,
            min_score,
            json,
        } => {
            let attached = AttachedClient::open(instance).await?;
            attached.require_rpc("LocalCognitionService/RetrieveMemory", "memory.retrieve")?;
            let correlation_id = Uuid::now_v7().to_string();
            let response = attached
                .0
                .connection
                .cognition_service()
                .retrieve_memory(RetrieveMemoryRequest {
                    client: Some(attached.metadata_with_correlation(correlation_id.clone())?),
                    query,
                    scope_ref: scope.clone(),
                    max_results,
                    min_score,
                })
                .await
                .map_err(|error| error.to_string())?
                .into_inner();
            let result = match response.outcome {
                Some(retrieve_memory_response::Outcome::Result(result)) => result,
                Some(retrieve_memory_response::Outcome::Error(error)) => {
                    return Err(local_error_message(error));
                }
                None => return Err("Memory retrieval outcome missing".to_owned()),
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
                "schemaVersion": "egopulse.tui-result/v0.1",
                "ok": true,
                "operation": "memory.retrieve",
                "data": {
                    "scopeRef": scope,
                    "algorithmId": result.algorithm_id,
                    "querySha256": result.query_sha256,
                    "snapshotSha256": result.snapshot_sha256,
                    "evidenceRef": result.evidence_ref,
                    "resultCount": candidates.len(),
                    "candidates": candidates,
                },
                "correlationId": correlation_id,
            });
            let view = if json {
                serde_json::to_string(&payload).unwrap()
            } else {
                let mut lines = vec![format!(
                    "Memory retrieval: scope={} results={} algorithm={}",
                    payload["data"]["scopeRef"].as_str().unwrap_or(""),
                    payload["data"]["resultCount"].as_u64().unwrap_or(0),
                    payload["data"]["algorithmId"].as_str().unwrap_or("")
                )];
                lines.push(format!(
                    "Snapshot: {}",
                    payload["data"]["snapshotSha256"].as_str().unwrap_or("")
                ));
                lines.push(format!(
                    "Evidence: {}",
                    payload["data"]["evidenceRef"].as_str().unwrap_or("")
                ));
                for candidate in payload["data"]["candidates"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    lines.push(format!(
                        "- {} score={} source={} digest={}",
                        candidate["memoryId"].as_str().unwrap_or(""),
                        candidate["score"].as_f64().unwrap_or(0.0),
                        candidate["sourceRef"].as_str().unwrap_or(""),
                        candidate["contentSha256"].as_str().unwrap_or("")
                    ));
                }
                lines.join("\n")
            };
            if output == CommandOutput::Console {
                println!("{view}");
            }
            Ok(CommandResult::ReadView(view))
        }
        TuiCommand::MemoryCandidate {
            memory_id,
            content,
            source_ref,
            scope,
            idempotency_key,
            json,
        } => {
            run_memory_mutation(
                instance,
                "memory.candidate",
                memory_mutation_command::Command::SubmitMemoryCandidate(
                    SubmitMemoryCandidateCommand {
                        metadata: None,
                        memory_id,
                        content,
                        source_ref,
                        scope_ref: scope,
                        idempotency_key,
                    },
                ),
                json,
                output,
            )
            .await
        }
        TuiCommand::MemoryAccept {
            memory_id,
            expected_revision,
            evidence_ref,
            idempotency_key,
            json,
        } => {
            run_memory_mutation(
                instance,
                "memory.accept",
                memory_mutation_command::Command::AcceptMemory(AcceptMemoryCommand {
                    metadata: None,
                    memory_id,
                    expected_revision,
                    evidence_ref,
                    idempotency_key,
                }),
                json,
                output,
            )
            .await
        }
        TuiCommand::MemoryRevoke {
            memory_id,
            expected_revision,
            evidence_ref,
            idempotency_key,
            json,
        } => {
            run_memory_mutation(
                instance,
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
                output,
            )
            .await
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
            Ok(CommandResult::Completed)
        }
    }
}

async fn run_memory_mutation(
    instance: &str,
    operation: &'static str,
    mut branch: memory_mutation_command::Command,
    json_output: bool,
    output: CommandOutput,
) -> Result<CommandResult, String> {
    let attached = AttachedClient::open(instance).await?;
    let oneof = match &branch {
        memory_mutation_command::Command::SubmitMemoryCandidate(_) => "submit_memory_candidate",
        memory_mutation_command::Command::AcceptMemory(_) => "accept_memory",
        memory_mutation_command::Command::RevokeMemory(_) => "revoke_memory",
    };
    attached.require_command("LocalCommandGatewayService/ExecuteMemoryMutation", oneof)?;
    let correlation_id = Uuid::now_v7().to_string();
    let metadata = attached.metadata_with_correlation(correlation_id.clone())?;
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
        .map_err(|error| error.to_string())?
        .into_inner();
    if let Some(error) = response.gateway_error {
        return Err(local_error_message(error));
    }
    let result: MemoryMutationReceipt = response
        .authority_result
        .ok_or_else(|| "Memory mutation authority result missing".to_owned())?;
    let payload = json!({
        "schemaVersion": "egopulse.tui-result/v0.1",
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
    if output == CommandOutput::Console {
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
    }
    Ok(CommandResult::Completed)
}

fn command_kind(command: &TuiCommand) -> &'static str {
    match command {
        TuiCommand::WorkPlan { .. } => "work.plan",
        TuiCommand::WorkPrepare { .. } => "work.prepare",
        TuiCommand::WorkConfirm { .. } => "work.confirm",
        TuiCommand::TaskCreate { .. } => "task.create",
        TuiCommand::TaskApplyVerdict { .. } => "task.apply-verdict",
        TuiCommand::TaskCancel { .. } => "task.cancel",
        TuiCommand::ApprovalDecide { .. } => "approval.decide",
        TuiCommand::Await { .. } => "await",
        TuiCommand::VerdictIssue { .. } => "verdict.issue",
        TuiCommand::VerdictRevoke { .. } => "verdict.revoke",
        TuiCommand::EvidenceGet { .. } => "evidence.get",
        TuiCommand::MemoryRetrieve { .. } => "memory.retrieve",
        TuiCommand::MemoryCandidate { .. } => "memory.candidate",
        TuiCommand::MemoryAccept { .. } => "memory.accept",
        TuiCommand::MemoryRevoke { .. } => "memory.revoke",
    }
}

fn tui_work_error(error: ClientWorkError) -> String {
    match error {
        ClientWorkError::Api(error) => local_error_message(*error),
        other => other.to_string(),
    }
}

fn tui_context_revoke_error(error: ClientContextRevokeError) -> String {
    match error {
        ClientContextRevokeError::Api(error) => local_error_message(*error),
        ClientContextRevokeError::InvalidConfirmation => {
            "CONTEXT_CONFIRMATION_REQUIRED: supply the exact full lowercase digest".to_owned()
        }
        ClientContextRevokeError::SessionChanged => {
            "CONTEXT_SESSION_CHANGED: reopen the form and prepare again".to_owned()
        }
        other => other.to_string(),
    }
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

#[derive(Clone)]
struct Snapshot {
    health: String,
    stale: bool,
    position: String,
    tasks: Vec<TaskView>,
    approvals: Vec<HarnessApprovalView>,
}

struct App {
    instance: String,
    client: Option<Arc<dyn InteractiveClient>>,
    governed_state_client: Option<Arc<AttachedClient>>,
    content_attachment: Option<Arc<ClientAttachment>>,
    snapshot: Option<Snapshot>,
    panel: Panel,
    message: String,
    refresh_interval: Duration,
    mode: InteractiveMode,
    task_watch: Option<TaskWatchController<dyn InteractiveClient>>,
    harness_content: Option<HarnessContentController>,
    approval_queue: Option<ApprovalQueueController<dyn InteractiveClient>>,
    result_review: Option<ResultReviewController<dyn InteractiveClient>>,
    work_start: Option<WorkStartController>,
    governed_state: Option<GovernedStateController>,
    pending_task_watch_selection: Option<String>,
}

impl App {
    fn new(instance: String) -> Self {
        Self {
            instance,
            client: None,
            governed_state_client: None,
            content_attachment: None,
            snapshot: None,
            panel: Panel::Tasks,
            message: "Connecting to local daemon…".to_owned(),
            refresh_interval: Duration::from_secs(2),
            mode: InteractiveMode::Dashboard,
            task_watch: None,
            harness_content: None,
            approval_queue: None,
            result_review: None,
            work_start: None,
            governed_state: None,
            pending_task_watch_selection: None,
        }
    }

    fn open_palette(&mut self) {
        self.mode = InteractiveMode::Palette { selected: 0 };
        self.message = "Choose a governed command; Esc returns to the dashboard".to_owned();
    }

    fn open_form(&mut self, kind: CommandKind) {
        self.mode = InteractiveMode::Form(CommandForm::new(kind));
        self.message = if kind == CommandKind::ContextRevoke {
            format!(
                "{}: Tab/Down advances, Ctrl+N adds an evidence entry, Ctrl+D removes one, Enter stages the modal, Esc cancels",
                kind.label()
            )
        } else {
            format!(
                "{}: type a value, Tab/Down advances, Enter submits, Esc cancels",
                kind.label()
            )
        };
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<Option<InteractiveAction>, String> {
        match &mut self.mode {
            InteractiveMode::Dashboard => match key.code {
                KeyCode::Char('c') => {
                    self.open_palette();
                    Ok(None)
                }
                KeyCode::Char('r') => Ok(None),
                KeyCode::Char('w') => Ok(Some(InteractiveAction::OpenTaskWatch)),
                KeyCode::Char('a') => Ok(Some(InteractiveAction::OpenApprovalQueue)),
                KeyCode::Char('n') => Ok(Some(InteractiveAction::OpenWorkStart)),
                KeyCode::Char('g') => Ok(Some(InteractiveAction::OpenGovernedState)),
                KeyCode::Char('q') | KeyCode::Esc => Ok(Some(InteractiveAction::Quit)),
                _ => Ok(None),
            },
            InteractiveMode::GovernedState => match key.code {
                KeyCode::Esc => Ok(Some(InteractiveAction::CloseGovernedState)),
                KeyCode::Char('q') => Ok(Some(InteractiveAction::Quit)),
                _ => Ok(None),
            },
            InteractiveMode::WorkStart => {
                let stage = self
                    .work_start
                    .as_ref()
                    .map(|controller| controller.model().stage())
                    .ok_or_else(|| "Work Start controller is unavailable".to_owned())?;
                match work_start_key_intent(stage, key) {
                    WorkStartKeyIntent::Quit => Ok(Some(InteractiveAction::Quit)),
                    WorkStartKeyIntent::Close => Ok(Some(InteractiveAction::CloseWorkStart)),
                    WorkStartKeyIntent::NextField => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .model_mut()
                            .next_field();
                        Ok(None)
                    }
                    WorkStartKeyIntent::PreviousField => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .model_mut()
                            .previous_field();
                        Ok(None)
                    }
                    WorkStartKeyIntent::Backspace => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .model_mut()
                            .backspace();
                        Ok(None)
                    }
                    WorkStartKeyIntent::Push(character) => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .model_mut()
                            .push(character);
                        Ok(None)
                    }
                    WorkStartKeyIntent::Prepare => Ok(Some(InteractiveAction::PrepareWorkStart)),
                    WorkStartKeyIntent::WaitForPreparation => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .request_return_after_preparation();
                        Ok(None)
                    }
                    WorkStartKeyIntent::Confirm => Ok(Some(InteractiveAction::ConfirmWorkStart)),
                    WorkStartKeyIntent::CancelPreview => {
                        Ok(Some(InteractiveAction::CancelWorkPreview))
                    }
                    WorkStartKeyIntent::ReplayPreparation => {
                        Ok(Some(InteractiveAction::ReplayWorkPreparation))
                    }
                    WorkStartKeyIntent::KeepPreparationRecovery => {
                        self.message = "Preparation outcome remains unknown; Enter exact-replays the sealed request"
                            .to_owned();
                        Ok(None)
                    }
                    WorkStartKeyIntent::ConfirmationCannotCancel => {
                        self.work_start
                            .as_mut()
                            .expect("Work Start controller exists")
                            .note_confirmation_cannot_cancel();
                        Ok(None)
                    }
                    WorkStartKeyIntent::ReplayConfirmation => {
                        Ok(Some(InteractiveAction::ReplayWorkConfirmation))
                    }
                    WorkStartKeyIntent::ReconcileInTaskWatch => {
                        Ok(Some(InteractiveAction::OpenTaskWatchForWorkReconciliation))
                    }
                    WorkStartKeyIntent::Ignore => Ok(None),
                }
            }
            InteractiveMode::TaskWatch => match key.code {
                KeyCode::Esc => Ok(Some(InteractiveAction::CloseTaskWatch)),
                KeyCode::Char('r') => Ok(Some(InteractiveAction::RefetchTaskWatch)),
                KeyCode::Char('h')
                    if self.pending_task_watch_selection.is_none()
                        && self
                            .task_watch
                            .as_ref()
                            .and_then(|controller| controller.model())
                            .and_then(|model| model.selected_task_id.as_ref())
                            .is_some() =>
                {
                    Ok(Some(InteractiveAction::OpenHarnessContent))
                }
                KeyCode::Char('q') => Ok(Some(InteractiveAction::Quit)),
                KeyCode::Up => {
                    if let Some(controller) = &mut self.task_watch {
                        controller.select_previous();
                    }
                    Ok(None)
                }
                KeyCode::Down => {
                    if let Some(controller) = &mut self.task_watch {
                        controller.select_next();
                    }
                    Ok(None)
                }
                KeyCode::PageUp => {
                    if let Some(controller) = &mut self.task_watch {
                        controller.scroll_detail_up();
                    }
                    Ok(None)
                }
                KeyCode::PageDown => {
                    if let Some(controller) = &mut self.task_watch {
                        controller.scroll_detail_down();
                    }
                    Ok(None)
                }
                KeyCode::Enter
                    if self.pending_task_watch_selection.is_none()
                        && self
                            .task_watch
                            .as_ref()
                            .and_then(|controller| controller.model())
                            .and_then(|model| model.selected_task_id.as_ref())
                            .is_some() =>
                {
                    Ok(Some(InteractiveAction::OpenResultReview))
                }
                KeyCode::Enter if self.pending_task_watch_selection.is_some() => {
                    self.message = "Authority confirmed the Task, but its exact projection has not arrived; result review remains blocked"
                        .to_owned();
                    Ok(None)
                }
                _ => Ok(None),
            },
            InteractiveMode::HarnessContent => match key.code {
                KeyCode::Esc => Ok(Some(InteractiveAction::CloseHarnessContent)),
                KeyCode::Char('r') => Ok(Some(InteractiveAction::RefetchHarnessContent)),
                KeyCode::Char('q') => Ok(Some(InteractiveAction::Quit)),
                KeyCode::Up => {
                    if let Some(controller) = self.harness_content.as_mut() {
                        controller.model_mut().select_previous();
                    }
                    Ok(None)
                }
                KeyCode::Down => {
                    if let Some(controller) = self.harness_content.as_mut() {
                        controller.model_mut().select_next();
                    }
                    Ok(None)
                }
                KeyCode::PageUp => {
                    if let Some(controller) = self.harness_content.as_mut() {
                        controller.model_mut().scroll_up(10);
                    }
                    Ok(None)
                }
                KeyCode::PageDown => {
                    if let Some(controller) = self.harness_content.as_mut() {
                        controller.model_mut().scroll_down(10);
                    }
                    Ok(None)
                }
                _ => Ok(None),
            },
            InteractiveMode::ResultReview => match key.code {
                KeyCode::Esc => Ok(Some(InteractiveAction::CloseResultReview)),
                KeyCode::Char('r') => Ok(Some(InteractiveAction::RefreshResultReview)),
                KeyCode::Char('q') => Ok(Some(InteractiveAction::Quit)),
                KeyCode::Tab => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.next_section();
                    }
                    Ok(None)
                }
                KeyCode::BackTab => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.previous_section();
                    }
                    Ok(None)
                }
                KeyCode::Up => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.scroll_up(1);
                    }
                    Ok(None)
                }
                KeyCode::Down => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.scroll_down(1);
                    }
                    Ok(None)
                }
                KeyCode::PageUp => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.scroll_up(10);
                    }
                    Ok(None)
                }
                KeyCode::PageDown => {
                    if let Some(model) = self
                        .result_review
                        .as_mut()
                        .and_then(ResultReviewController::model_mut)
                    {
                        model.scroll_down(10);
                    }
                    Ok(None)
                }
                _ => Ok(None),
            },
            InteractiveMode::ApprovalQueue => match key.code {
                KeyCode::Esc => Ok(Some(InteractiveAction::CloseApprovalQueue)),
                KeyCode::Char('r') => Ok(Some(InteractiveAction::RefetchApprovalQueue)),
                KeyCode::Char('q') => Ok(Some(InteractiveAction::Quit)),
                KeyCode::Up => {
                    if let Some(controller) = &mut self.approval_queue {
                        controller.select_previous();
                    }
                    Ok(None)
                }
                KeyCode::Down => {
                    if let Some(controller) = &mut self.approval_queue {
                        controller.select_next();
                    }
                    Ok(None)
                }
                KeyCode::Enter => {
                    let selected = self
                        .approval_queue
                        .as_ref()
                        .and_then(|controller| controller.model())
                        .and_then(|model| model.selected_id.clone());
                    if let Some(selected) = selected {
                        self.mode = InteractiveMode::ApprovalDecisionModal(
                            ApprovalDecisionModal::new(selected),
                        );
                        self.message = "Choose an explicit decision and enter a reason".to_owned();
                    }
                    Ok(None)
                }
                _ => Ok(None),
            },
            InteractiveMode::ApprovalDecisionModal(modal) => match key.code {
                KeyCode::Esc => {
                    self.mode = InteractiveMode::ApprovalQueue;
                    self.message = "Approval decision cancelled; no command was sent".to_owned();
                    Ok(None)
                }
                KeyCode::Left => {
                    modal.cycle_decision(false);
                    Ok(None)
                }
                KeyCode::Right => {
                    modal.cycle_decision(true);
                    Ok(None)
                }
                KeyCode::Tab => {
                    modal.active_field = match modal.active_field {
                        ApprovalModalField::Reason => ApprovalModalField::Proof,
                        ApprovalModalField::Proof => ApprovalModalField::Reason,
                    };
                    Ok(None)
                }
                KeyCode::Backspace => {
                    modal.active_value_mut().pop();
                    Ok(None)
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    modal.active_value_mut().push(character);
                    Ok(None)
                }
                KeyCode::Enter
                    if !modal.submitting
                        && modal.decision.is_some()
                        && !modal.reason_code.trim().is_empty() =>
                {
                    modal.submitting = true;
                    Ok(Some(InteractiveAction::SubmitApprovalDecision))
                }
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
                KeyCode::Char('n')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    if form.add_context_evidence_entry() {
                        self.message =
                            "Added an ordered evidence entry; its exact bytes will be preserved"
                                .to_owned();
                    }
                    Ok(None)
                }
                KeyCode::Char('d')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    if form.remove_active_context_evidence_entry() {
                        self.message = "Removed the selected evidence entry".to_owned();
                    }
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
                    match form.clone().into_action() {
                        Ok(action) => {
                            self.mode = InteractiveMode::Dashboard;
                            Ok(Some(action))
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
            InteractiveMode::ContextRevokeConfirmation(_) => {
                match context_revoke_modal_key_action(key.code) {
                    ContextRevokeModalKeyAction::Cancel => {
                        self.mode = InteractiveMode::Dashboard;
                        self.message =
                            "Context revoke cancelled before mutation; no command was sent"
                                .to_owned();
                        Ok(None)
                    }
                    ContextRevokeModalKeyAction::Confirm => {
                        Ok(Some(InteractiveAction::ConfirmContextRevoke))
                    }
                    ContextRevokeModalKeyAction::Ignore => Ok(None),
                }
            }
        }
    }

    async fn stage_context_revoke(&mut self, input: ContextRevokeInput) -> Result<(), String> {
        self.ensure_task_watch_client().await?;
        let pending = self
            .client
            .as_ref()
            .expect("Context revoke client is attached")
            .prepare_context_revoke(input)?;
        self.message =
            "Review the complete digest; no mutation is sent until explicit confirmation"
                .to_owned();
        self.mode = InteractiveMode::ContextRevokeConfirmation(pending);
        Ok(())
    }

    async fn confirm_context_revoke(
        &mut self,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ContextRevokeReceipt, String>
    {
        let mode = std::mem::replace(&mut self.mode, InteractiveMode::Dashboard);
        let InteractiveMode::ContextRevokeConfirmation(prepared) = mode else {
            return Err("Context revoke confirmation state is unavailable".to_owned());
        };
        prepared.commit().await
    }

    async fn refresh(&mut self) {
        if self.client.is_none() {
            match AttachedClient::open(&self.instance).await {
                Ok(client) => self.install_attached_client(client),
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
                self.stop_governed_state().await;
                self.client = None;
                self.governed_state_client = None;
                self.content_attachment = None;
            }
        }
    }

    async fn ensure_task_watch_client(&mut self) -> Result<(), String> {
        if self.client.is_none() {
            let client = AttachedClient::open(&self.instance).await?;
            self.install_attached_client(client);
        }
        Ok(())
    }

    fn install_attached_client(&mut self, client: AttachedClient) {
        self.content_attachment = Some(Arc::clone(&client.0));
        let (interactive, governed_state) = shared_attached_client_pair(client);
        self.client = Some(interactive);
        self.governed_state_client = Some(governed_state);
    }

    async fn start_governed_state(&mut self) -> Result<(), String> {
        if self.work_start.is_some() {
            return Err(
                "Work Start must be resumed and settled before opening governed state".to_owned(),
            );
        }
        self.stop_task_watch().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let client = Arc::clone(
            self.governed_state_client
                .as_ref()
                .expect("governed state client is attached"),
        );
        self.install_governed_state_controller(client)?;
        Ok(())
    }

    fn install_governed_state_controller<Client>(
        &mut self,
        client: Arc<Client>,
    ) -> Result<(), String>
    where
        Client: GovernedStateClient + ?Sized + 'static,
    {
        let controller = GovernedStateController::start(client)
            .map_err(|_| "governed state runtime is unavailable".to_owned())?;
        self.message = governed_state_message(controller.model());
        self.governed_state = Some(controller);
        self.mode = InteractiveMode::GovernedState;
        Ok(())
    }

    async fn stop_governed_state(&mut self) {
        if let Some(mut controller) = self.governed_state.take() {
            controller.stop().await;
        }
    }

    fn apply_governed_state_events(&mut self) -> Result<(), String> {
        let controller = self
            .governed_state
            .as_mut()
            .ok_or_else(|| "Governed State controller is unavailable".to_owned())?;
        controller.pump();
        self.message = governed_state_message(controller.model());
        Ok(())
    }

    async fn start_work_start(&mut self) -> Result<(), String> {
        if self.work_start.is_some() {
            self.stop_task_watch().await;
            self.stop_approval_queue().await;
            self.stop_result_review().await;
            self.stop_governed_state().await;
            let controller = self
                .work_start
                .as_ref()
                .expect("retained Work Start controller exists");
            self.message = controller.model().message().to_owned();
            self.mode = InteractiveMode::WorkStart;
            return Ok(());
        }
        self.stop_task_watch().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let controller = self
            .client
            .as_ref()
            .expect("Work Start client is attached")
            .work_start_controller()?;
        self.message = controller.model().message().to_owned();
        self.work_start = Some(controller);
        self.mode = InteractiveMode::WorkStart;
        Ok(())
    }

    async fn close_work_start_if_settled(&mut self) -> bool {
        let Some(controller) = self.work_start.as_mut() else {
            return true;
        };
        if work_start_exit_policy(controller.model().stage(), controller.is_running())
            == WorkStartExitPolicy::AwaitSettlement
            && let Err(error) = controller.wait_for_settlement(Duration::from_secs(1)).await
        {
            self.message = format!("Cannot close Work Start: {error}");
            return false;
        }
        let policy = work_start_exit_policy(controller.model().stage(), controller.is_running());
        if policy == WorkStartExitPolicy::PreserveRecovery {
            self.message = "Work Start has an outcome-unknown recovery capsule; exact replay or Task Watch reconciliation is required before exit"
                .to_owned();
            return false;
        }
        if policy == WorkStartExitPolicy::CancelPreview
            && let Err(error) = controller.cancel_preview().await
        {
            self.message = format!("Work Start preview cannot close: {error}");
            return false;
        }
        self.work_start.take();
        true
    }

    async fn settle_work_start_for_quit(&mut self) -> bool {
        if self
            .work_start
            .as_ref()
            .is_some_and(|controller| controller.model().stage() == WorkStartStage::Preparing)
            && let Some(controller) = self.work_start.as_mut()
        {
            controller.request_return_after_preparation();
        }
        self.close_work_start_if_settled().await
    }

    async fn apply_work_start_events(&mut self) -> Result<(), String> {
        let (navigate_dashboard, confirmed_task_id) = {
            let controller = self
                .work_start
                .as_mut()
                .ok_or_else(|| "Work Start controller is unavailable".to_owned())?;
            controller.pump().await?;
            self.message = controller.model().message().to_owned();
            (
                controller.take_dashboard_navigation(),
                controller.take_confirmed_task_id(),
            )
        };
        if let Some(task_id) = confirmed_task_id {
            debug_assert!(
                !self
                    .work_start
                    .as_ref()
                    .is_some_and(WorkStartController::is_running),
                "a confirmed Work Start runtime must be settled"
            );
            self.work_start.take();
            self.pending_task_watch_selection = Some(task_id);
            if let Err(error) = self.start_task_watch().await {
                self.mode = InteractiveMode::Dashboard;
                self.message = format!(
                    "Task was confirmed, but Task Watch is temporarily unavailable: {error}; the exact Task selection is retained"
                );
            }
        } else if navigate_dashboard {
            debug_assert!(
                !self
                    .work_start
                    .as_ref()
                    .is_some_and(WorkStartController::is_running),
                "dashboard navigation requires a settled Work Start runtime"
            );
            self.work_start.take();
            self.mode = InteractiveMode::Dashboard;
        }
        Ok(())
    }

    async fn start_task_watch(&mut self) -> Result<(), String> {
        self.start_task_watch_inner(false).await
    }

    async fn start_task_watch_for_work_reconciliation(&mut self) -> Result<(), String> {
        self.start_task_watch_inner(true).await
    }

    async fn start_task_watch_inner(&mut self, preserve_unknown_work: bool) -> Result<(), String> {
        if self
            .work_start
            .as_ref()
            .is_some_and(WorkStartController::is_running)
        {
            return Err(
                "Work Start mutation is unresolved; Task Watch cannot replace it".to_owned(),
            );
        }
        if let Some(controller) = self.work_start.as_ref() {
            let unknown = matches!(
                controller.model().stage(),
                WorkStartStage::PreparationOutcomeUnknown
                    | WorkStartStage::ConfirmationOutcomeUnknown
            );
            if unknown && !preserve_unknown_work {
                return Err(
                    "Work Start recovery capsule must be reconciled before changing pages"
                        .to_owned(),
                );
            }
            if !unknown {
                return Err(
                    "Settle or explicitly cancel the current Work Start page first".to_owned(),
                );
            }
        }
        self.stop_task_watch().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let client = Arc::clone(self.client.as_ref().expect("Task watch client is attached"));
        let mut controller = TaskWatchController::new(client);
        controller.start().await?;
        let model = controller
            .model()
            .ok_or_else(|| "Task Watch controller omitted its baseline".to_owned())?;
        self.message = model.message.clone();
        self.task_watch = Some(controller);
        self.mode = InteractiveMode::TaskWatch;
        self.apply_pending_task_watch_selection();
        Ok(())
    }

    async fn stop_task_watch(&mut self) {
        if let Some(mut controller) = self.task_watch.take() {
            controller.stop().await;
        }
    }

    async fn apply_task_watch_events(&mut self) -> Result<(), String> {
        let controller = self
            .task_watch
            .as_mut()
            .ok_or_else(|| "Task Watch controller is unavailable".to_owned())?;
        controller.pump()?;
        let model = controller
            .model()
            .ok_or_else(|| "Task Watch controller omitted its page model".to_owned())?;
        self.message = model.message.clone();
        self.apply_pending_task_watch_selection();
        Ok(())
    }

    async fn handle_task_watch_failure(&mut self, error: String) {
        self.stop_task_watch().await;
        self.message = format!("Task Watch stopped fail-closed: {error}");
    }

    fn apply_pending_task_watch_selection(&mut self) {
        let Some(task_id) = self.pending_task_watch_selection.clone() else {
            return;
        };
        let selected = self
            .task_watch
            .as_mut()
            .is_some_and(|controller| controller.select_task(&task_id));
        if selected {
            self.pending_task_watch_selection = None;
            self.message = format!("Task {task_id} selected from its governed projection");
        } else {
            if let Some(controller) = self.task_watch.as_mut() {
                controller.clear_selection();
            }
            self.message = format!(
                "Task {task_id} is confirmed but not projected yet; Task Watch will retain and refetch this selection"
            );
        }
    }

    async fn start_harness_content(&mut self) -> Result<(), String> {
        if self.work_start.is_some() {
            return Err(
                "Work Start recovery must be settled before opening Harness content".to_owned(),
            );
        }
        let task_id = self
            .task_watch
            .as_ref()
            .and_then(|controller| controller.model())
            .and_then(|model| model.selected_task_id.clone())
            .ok_or_else(|| "Select a Task before opening Harness content".to_owned())?;
        self.start_harness_content_for_task(task_id).await
    }

    async fn start_harness_content_for_task(&mut self, task_id: String) -> Result<(), String> {
        self.stop_task_watch().await;
        self.stop_harness_content().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let filter = HarnessContentFilter::new(task_id.clone(), Vec::new())
            .map_err(|error| error.to_string())?;
        let client = Arc::clone(
            self.content_attachment
                .as_ref()
                .expect("Harness content attachment is installed with the shared client"),
        );
        let controller = HarnessContentController::start(client, filter).map_err(str::to_owned)?;
        self.message = controller.model().message.clone();
        self.pending_task_watch_selection = Some(task_id);
        self.harness_content = Some(controller);
        self.mode = InteractiveMode::HarnessContent;
        Ok(())
    }

    async fn refetch_harness_content(&mut self) -> Result<(), String> {
        let task_id = self
            .harness_content
            .as_ref()
            .map(|controller| controller.task_id().to_owned())
            .ok_or_else(|| "Harness content controller is unavailable".to_owned())?;
        self.start_harness_content_for_task(task_id).await
    }

    async fn stop_harness_content(&mut self) {
        if let Some(mut controller) = self.harness_content.take() {
            controller.stop().await;
        }
    }

    fn apply_harness_content_events(&mut self) {
        let Some(controller) = self.harness_content.as_mut() else {
            self.message = "Harness content controller is unavailable".to_owned();
            return;
        };
        controller.pump();
        self.message = controller.model().message.clone();
    }

    async fn close_harness_content_to_task_watch(&mut self) -> Result<(), String> {
        let task_id = self
            .harness_content
            .as_ref()
            .map(|controller| controller.task_id().to_owned());
        self.stop_harness_content().await;
        self.pending_task_watch_selection = task_id;
        self.start_task_watch().await
    }

    async fn start_approval_queue(&mut self) -> Result<(), String> {
        if self.work_start.is_some() {
            return Err(
                "Work Start must be resumed and settled before opening Approval Queue".to_owned(),
            );
        }
        self.stop_task_watch().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let client = Arc::clone(
            self.client
                .as_ref()
                .expect("Approval Queue client is attached"),
        );
        let mut controller = ApprovalQueueController::new(client);
        controller.start().await?;
        self.message = controller
            .model()
            .ok_or_else(|| "Approval Queue controller omitted its baseline".to_owned())?
            .message
            .clone();
        self.approval_queue = Some(controller);
        self.mode = InteractiveMode::ApprovalQueue;
        Ok(())
    }

    async fn stop_approval_queue(&mut self) {
        if let Some(mut controller) = self.approval_queue.take() {
            controller.stop().await;
        }
    }

    async fn apply_approval_queue_events(&mut self) -> Result<(), String> {
        let controller = self
            .approval_queue
            .as_mut()
            .ok_or_else(|| "Approval Queue controller is unavailable".to_owned())?;
        controller.pump().await?;
        self.message = controller
            .model()
            .ok_or_else(|| "Approval Queue controller omitted its page model".to_owned())?
            .message
            .clone();
        Ok(())
    }

    async fn start_result_review(&mut self) -> Result<(), String> {
        if self.work_start.is_some() {
            return Err(
                "Work Start recovery must be settled before opening result review".to_owned(),
            );
        }
        let selected_task_id = self
            .task_watch
            .as_ref()
            .and_then(|controller| controller.model())
            .and_then(|model| model.selected_task_id.clone())
            .ok_or_else(|| "Select a Task before opening result review".to_owned())?;
        self.stop_task_watch().await;
        self.stop_approval_queue().await;
        self.stop_result_review().await;
        self.stop_governed_state().await;
        self.ensure_task_watch_client().await?;
        let client = Arc::clone(
            self.client
                .as_ref()
                .expect("Result review client is attached"),
        );
        let mut controller = ResultReviewController::new(client, selected_task_id);
        controller.start().await?;
        self.message = "Loading projected result metadata and governance evidence".to_owned();
        self.result_review = Some(controller);
        self.mode = InteractiveMode::ResultReview;
        Ok(())
    }

    async fn stop_result_review(&mut self) {
        if let Some(mut controller) = self.result_review.take() {
            controller.stop().await;
        }
    }

    async fn apply_result_review_events(&mut self) -> Result<(), String> {
        let controller = self
            .result_review
            .as_mut()
            .ok_or_else(|| "Result review controller is unavailable".to_owned())?;
        controller.pump().await?;
        if let Some(model) = controller.model() {
            self.message = model.message.clone();
        }
        Ok(())
    }

    async fn pump_result_review_fail_closed(&mut self) {
        if let Err(error) = self.apply_result_review_events().await {
            self.message = format!("Result review stopped fail-closed: {error}");
        }
    }

    async fn close_result_review_to_task_watch(&mut self) -> Result<(), String> {
        let task_id = self
            .result_review
            .as_ref()
            .map(|controller| controller.task_id().to_owned());
        self.stop_result_review().await;
        self.start_task_watch().await?;
        if let (Some(task_id), Some(controller)) = (task_id, self.task_watch.as_mut())
            && !controller.select_task(&task_id)
        {
            self.message = "Reviewed Task left the projection; selection moved safely".to_owned();
        }
        Ok(())
    }

    async fn submit_approval_decision(&mut self) -> Result<ApprovalDecisionReceipt, String> {
        let mode = std::mem::replace(&mut self.mode, InteractiveMode::ApprovalQueue);
        let InteractiveMode::ApprovalDecisionModal(modal) = mode else {
            return Err("Approval decision modal is unavailable".to_owned());
        };
        let current_selected = self
            .approval_queue
            .as_ref()
            .and_then(|controller| controller.model())
            .and_then(|model| model.selected_id.as_deref());
        if current_selected != Some(modal.approval_request_id.as_str()) {
            return Err("Approval is no longer actionable; refresh before deciding".to_owned());
        }
        let decision = modal
            .decision
            .ok_or_else(|| "An explicit approval decision is required".to_owned())?;
        self.approval_queue
            .as_mut()
            .expect("Approval Queue controller is present")
            .decide_selected(
                decision,
                modal.reason_code,
                (!modal.confirmation_proof_ref.trim().is_empty())
                    .then_some(modal.confirmation_proof_ref),
            )
            .await
            .map_err(|error| error.to_string())
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
            InteractiveMode::GovernedState => match self.governed_state.as_ref() {
                Some(controller) => render_governed_state(frame, body[1], controller.model()),
                None => frame.render_widget(
                    Paragraph::new("Governed State session is unavailable.")
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Governed State"),
                        )
                        .wrap(Wrap { trim: true }),
                    body[1],
                ),
            },
            InteractiveMode::TaskWatch => {
                if let Some(model) = self
                    .task_watch
                    .as_ref()
                    .and_then(TaskWatchController::model)
                {
                    render_task_watch(frame, body[1], model);
                } else {
                    frame.render_widget(
                        Paragraph::new("Task Watch has no complete governed baseline.")
                            .block(Block::default().borders(Borders::ALL))
                            .wrap(Wrap { trim: true }),
                        body[1],
                    );
                }
            }
            InteractiveMode::HarnessContent => match self.harness_content.as_ref() {
                Some(controller) => render_harness_content_page(frame, body[1], controller.model()),
                None => frame.render_widget(
                    Paragraph::new("Harness content session is unavailable.")
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Harness Content"),
                        )
                        .wrap(Wrap { trim: true }),
                    body[1],
                ),
            },
            InteractiveMode::WorkStart => match self.work_start.as_ref() {
                Some(controller) => render_work_start_page(frame, body[1], controller.model()),
                None => frame.render_widget(
                    Paragraph::new("Work Start controller is unavailable.")
                        .block(Block::default().borders(Borders::ALL).title("Work Start")),
                    body[1],
                ),
            },
            InteractiveMode::ResultReview => match self
                .result_review
                .as_ref()
                .and_then(ResultReviewController::model)
            {
                Some(model) => render_result_review(frame, body[1], model),
                None => frame.render_widget(
                    Paragraph::new("Loading projected result metadata and governance evidence...")
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Result Review"),
                        )
                        .wrap(Wrap { trim: true }),
                    body[1],
                ),
            },
            InteractiveMode::ApprovalQueue | InteractiveMode::ApprovalDecisionModal(_) => {
                match self
                    .approval_queue
                    .as_ref()
                    .and_then(|controller| controller.model())
                {
                    Some(model) => render_approval_queue(frame, body[1], model),
                    None => frame.render_widget(
                        Paragraph::new("Approval Queue has no baseline snapshot.")
                            .block(Block::default().borders(Borders::ALL)),
                        body[1],
                    ),
                }
                if let InteractiveMode::ApprovalDecisionModal(modal) = &self.mode {
                    render_approval_decision_modal(frame, body[1], modal);
                }
            }
            InteractiveMode::Palette { selected } => {
                render_command_palette(frame, body[1], *selected)
            }
            InteractiveMode::Form(form) => render_command_form(frame, body[1], form),
            InteractiveMode::ContextRevokeConfirmation(prepared) => {
                render_context_revoke_confirmation(frame, body[1], prepared)
            }
        }
        frame.render_widget(
            Paragraph::new(self.footer_text())
                .style(Style::default().fg(Color::Gray))
                .wrap(Wrap { trim: true }),
            layout[2],
        );
    }

    fn footer_text(&self) -> String {
        if matches!(self.mode, InteractiveMode::Dashboard) {
            return format!(
                "{} - n new work - w task watch - a approval queue - g governed state - c command palette - r refresh - Tab panel - q quit",
                self.message
            );
        }
        match &self.mode {
            InteractiveMode::GovernedState => format!(
                "{} - Esc dashboard - q quit; this page is observation-only",
                self.message
            ),
            InteractiveMode::TaskWatch => {
                format!(
                    "{} - Up/Down select - h live content - Enter review - Esc dashboard - r refetch - q quit",
                    self.message
                )
            }
            InteractiveMode::HarnessContent => format!(
                "{} - Up/Down lane - PgUp/PgDn scroll - r refetch - Esc Task Watch - q quit",
                self.message
            ),
            InteractiveMode::WorkStart => format!(
                "{} - Tab/BackTab field - Enter advance - Esc governed back - q bounded close",
                self.message
            ),
            InteractiveMode::ResultReview => format!(
                "{} - Tab/BackTab section - Up/Down/PgUp/PgDn scroll - r refresh - Esc Task Watch - q quit",
                self.message
            ),
            InteractiveMode::ApprovalQueue => format!(
                "{} - Up/Down select - Enter decide - Esc dashboard - r refetch - q quit",
                self.message
            ),
            InteractiveMode::ApprovalDecisionModal(_) => format!(
                "{} - Left/Right decision - Tab reason/proof - Enter submit - Esc cancel",
                self.message
            ),
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
            InteractiveMode::ContextRevokeConfirmation(_) => format!(
                "{} · Enter confirms this exact full digest · Esc cancels with zero writes",
                self.message
            ),
        }
    }
}

fn approval_decision_feedback(
    state_revision: u64,
    replayed: bool,
    projection_warning: bool,
) -> String {
    if projection_warning {
        format!(
            "Authority committed the approval at revision {state_revision} (replayed={replayed}); projection synchronization reported a warning. Do not retry the decision; refresh the queue instead"
        )
    } else {
        format!("Approval committed at revision {state_revision} (replayed={replayed})")
    }
}

fn render_approval_queue(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &egopulse_tui::approval_queue::ApprovalQueuePageModel,
) {
    let rows = model.items.iter().map(|item| {
        let selected = model.selected_id.as_deref() == Some(item.approval_request_id.as_str());
        Row::new([
            if selected { ">" } else { "" },
            item.approval_request_id.as_str(),
            item.task_id.as_str(),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Percentage(55),
                Constraint::Percentage(45),
            ],
        )
        .header(Row::new(["", "Approval", "Task"]).style(Style::default().fg(Color::Yellow)))
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Approval Queue - {} - position {}",
            if model.stale { "stale" } else { "live" },
            model.position
        ))),
        area,
    );
}

fn render_approval_decision_modal(
    frame: &mut Frame<'_>,
    area: Rect,
    modal: &ApprovalDecisionModal,
) {
    let decision = modal
        .decision
        .map(GuidedApprovalDecision::contract_name)
        .unwrap_or("<choose explicitly>");
    let reason = if modal.reason_code.is_empty() {
        "<empty>"
    } else {
        "<entered>"
    };
    let proof = if modal.confirmation_proof_ref.is_empty() {
        "<none>"
    } else {
        "<entered>"
    };
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("Approval: {}", modal.approval_request_id)),
            Line::from(format!("Decision: {decision}")),
            Line::from(format!("Reason: {reason}")),
            Line::from(format!("Proof: {proof}")),
            Line::from("No decision is selected by default."),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Guided approval decision"),
        ),
        area,
    );
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
            let value = form_field_display_value(field);
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

fn form_field_display_value(field: &FormField) -> String {
    if field.value.is_empty() {
        "<empty>".to_owned()
    } else if field.sensitive {
        "<redacted>".to_owned()
    } else {
        field.value.clone()
    }
}

fn render_context_revoke_confirmation(
    frame: &mut Frame<'_>,
    area: Rect,
    pending: &PendingContextRevoke,
) {
    let lines = context_revoke_confirmation_text(pending)
        .into_iter()
        .map(Line::from)
        .collect::<Vec<_>>();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Founder Context revoke confirmation"),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn context_revoke_confirmation_text(pending: &PendingContextRevoke) -> Vec<String> {
    vec![
        format!("Snapshot: {}", pending.snapshot_id),
        format!(
            "Expected state revision: {}",
            pending.expected_state_revision
        ),
        format!("Evidence references: {}", pending.evidence_count),
        String::new(),
        "Full semantic confirmation digest:".to_owned(),
        pending.request_digest_sha256.clone(),
        String::new(),
        "Press Enter to revoke, or Esc to cancel without sending a mutation.".to_owned(),
    ]
}

fn render_task_watch(frame: &mut Frame<'_>, area: Rect, model: &TaskWatchPageModel) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "position {}:{} - {} - {} tasks",
            model.position.epoch,
            model.position.sequence,
            match model.phase {
                TaskWatchPhase::Connecting => "connecting",
                TaskWatchPhase::Live => "live",
                TaskWatchPhase::Stale => "stale/refetching",
                TaskWatchPhase::FatalStopped => "stopped fail-closed",
            },
            model.tasks.len()
        ))
        .block(Block::default().borders(Borders::ALL).title("Task Watch")),
        sections[0],
    );
    render_task_watch_tasks(frame, sections[1], model);
    frame.render_widget(
        Paragraph::new(format!(
            "{} | Up/Down select  PageUp/PageDown details  Enter review  r refetch  Esc dashboard  q quit",
            model.message
        ))
        .wrap(Wrap { trim: false }),
        sections[2],
    );
}

fn governed_state_message(model: &GovernedStatePageModel) -> String {
    if model.stopped {
        "Governed State stream stopped; displayed facts remain observation-only".to_owned()
    } else {
        format!(
            "Governed State {} record {}",
            model.kind.label(),
            model.update_index
        )
    }
}

fn governed_domain_position(epoch: Option<&str>, sequence: Option<u64>) -> String {
    match (epoch, sequence) {
        (Some(epoch), Some(sequence)) => format!("{epoch}:{sequence}"),
        _ => "none".to_owned(),
    }
}

fn render_governed_state(frame: &mut Frame<'_>, area: Rect, model: &GovernedStatePageModel) {
    let changed_domain = model.changed_domain.map_or("none", domain_label);
    let mut lines = vec![
        format!(
            "kind={}  update_index={}  changed_domain={}  stopped={}",
            model.kind.label(),
            model.update_index,
            changed_domain,
            model.stopped
        ),
        "Task and Approval positions are independent; no atomic snapshot or global cursor is represented."
            .to_owned(),
        String::new(),
        format!(
            "Task domain: phase={} reason={} generation={} recovery={}/{} position={}",
            model.task.view.phase,
            model.task.view.reason.as_deref().unwrap_or("none"),
            model.task.view.generation,
            model.task.view.recovery_remaining,
            model.task.view.recovery_limit,
            governed_domain_position(
                model.task.view.epoch.as_deref(),
                model.task.view.sequence,
            )
        ),
    ];
    if model.task.facts.is_empty() {
        lines.push("  no safe Task facts".to_owned());
    } else {
        lines.extend(model.task.facts.iter().map(|task| {
            format!(
                "  task={} revision={} status={}",
                task.task_id, task.revision, task.status
            )
        }));
    }
    lines.push(String::new());
    lines.push(format!(
        "Approval domain: phase={} reason={} generation={} recovery={}/{} position={}",
        model.approval.view.phase,
        model.approval.view.reason.as_deref().unwrap_or("none"),
        model.approval.view.generation,
        model.approval.view.recovery_remaining,
        model.approval.view.recovery_limit,
        governed_domain_position(
            model.approval.view.epoch.as_deref(),
            model.approval.view.sequence,
        )
    ));
    if model.approval.facts.is_empty() {
        lines.push("  no safe Approval facts".to_owned());
    } else {
        lines.extend(model.approval.facts.iter().map(|approval| {
            format!(
                "  approval={} task={}",
                approval.approval_request_id, approval.task_id
            )
        }));
    }
    frame.render_widget(
        Paragraph::new(lines.join("\n"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Governed State"),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_task_watch_tasks(frame: &mut Frame<'_>, area: Rect, model: &TaskWatchPageModel) {
    let rows = model.tasks.iter().map(|task| {
        let selected = model.selected_task_id.as_deref() == Some(task.task_id.as_str());
        Row::new([
            Cell::from(if selected { ">" } else { " " }),
            Cell::from(task.task_id.clone()),
            Cell::from(task.status.as_str_name()),
            Cell::from(task.revision.to_string()),
        ])
        .style(if selected {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        })
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Percentage(50),
            Constraint::Percentage(32),
            Constraint::Length(10),
        ],
    )
    .header(Row::new(["", "Task", "Status", "Revision"]).style(Style::default().fg(Color::Yellow)))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Projected Tasks"),
    );

    let details = model
        .selected_task_id
        .as_deref()
        .and_then(|selected| model.tasks.iter().find(|task| task.task_id == selected))
        .map(governed_task_detail_lines)
        .unwrap_or_else(|| vec![Line::from("No Task selected")]);
    let detail = Paragraph::new(details)
        .scroll((model.detail_scroll, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Execution / Recovery Facts"),
        );

    if area.width >= 100 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        frame.render_widget(table, columns[0]);
        frame.render_widget(detail, columns[1]);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        frame.render_widget(table, rows[0]);
        frame.render_widget(detail, rows[1]);
    }
}

fn governed_task_detail_lines(task: &GovernedTaskState) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("Task {}", task.task_id)),
        Line::from(format!(
            "  revision={} status={} resume={} hold={}",
            task.revision,
            task.status.as_str_name(),
            task.resume_status
                .map_or("-", |status| status.as_str_name()),
            governed_hold_reason(task.hold_reason)
        )),
        Line::from(format!(
            "  projection={} stale={} reason={}",
            task.projection.health.as_str_name(),
            task.projection.stale,
            governed_projection_reason(task.projection.reason)
        )),
    ];
    match task.run.as_ref() {
        Some(run) => {
            lines.push(Line::from(format!(
                "Run {} revision={} status={} work_revision={} hold={}",
                run.run_id,
                run.revision,
                run.status.as_str_name(),
                run.work_revision,
                governed_hold_reason(run.hold_reason)
            )));
            for step in &run.steps {
                lines.push(Line::from(format!(
                    "  Step {} revision={} status={} current_attempt={} hold={}",
                    step.step_id,
                    step.revision,
                    step.status.as_str_name(),
                    step.current_attempt_id.as_deref().unwrap_or("-"),
                    governed_hold_reason(step.hold_reason)
                )));
                for attempt in &step.attempts {
                    lines.push(Line::from(format!(
                        "    Attempt {} #{} revision={} status={} recovery={} hold={}",
                        attempt.attempt_id,
                        attempt.attempt_number,
                        attempt.revision,
                        attempt.status.as_str_name(),
                        attempt.recovery_class.as_str_name(),
                        governed_hold_reason(attempt.hold_reason)
                    )));
                    lines.push(Line::from(format!(
                        "      last_harness_sequence={} checkpoint_reference_recorded={}",
                        attempt.last_harness_sequence, attempt.checkpoint_reference_recorded
                    )));
                }
            }
        }
        None if task.projection.reason
            == Some(GovernedProjectionReason::DependencyProjectionPending) =>
        {
            lines.push(Line::from("Run facts pending dependency projection"));
        }
        None => lines.push(Line::from("No current Run facts")),
    }
    lines.push(Line::from("Governance evidence does not complete the Task"));
    lines
}

const fn governed_hold_reason(reason: Option<GovernedHoldReason>) -> &'static str {
    match reason {
        None => "-",
        Some(GovernedHoldReason::CancellationOutcomeUnknown) => "cancellation-outcome-unknown",
        Some(GovernedHoldReason::CompensationRequired) => "compensation-required",
        Some(GovernedHoldReason::ManualRecoveryRequired) => "manual-recovery-required",
        Some(GovernedHoldReason::IrreversibleOutcomeUnknown) => "irreversible-outcome-unknown",
        Some(GovernedHoldReason::Unclassified) => "unclassified",
    }
}

const fn governed_projection_reason(reason: Option<GovernedProjectionReason>) -> &'static str {
    match reason {
        None => "-",
        Some(GovernedProjectionReason::DependencyProjectionPending) => {
            "dependency-projection-pending"
        }
        Some(GovernedProjectionReason::ProjectionNotReady) => "projection-not-ready",
        Some(GovernedProjectionReason::TaskProjectionInvalid) => "task-projection-invalid",
        Some(GovernedProjectionReason::Unclassified) => "unclassified",
    }
}

fn render_result_review(frame: &mut Frame<'_>, area: Rect, model: &ResultReviewPageModel) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "task={} status={} - {RESULT_REVIEW_NOTICE}",
            model.task_id, model.task_status
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Projected Result Review"),
        )
        .style(Style::default().fg(Color::Cyan)),
        layout[0],
    );
    let tabs = Tabs::new(
        egopulse_tui::result_review::ResultReviewSection::ALL
            .iter()
            .map(|section| Line::from(section.title()))
            .collect::<Vec<_>>(),
    )
    .select(
        egopulse_tui::result_review::ResultReviewSection::ALL
            .iter()
            .position(|section| *section == model.section)
            .unwrap_or_default(),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Evidence sections"),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(tabs, layout[1]);
    frame.render_widget(
        Paragraph::new(model.lines().join("\n"))
            .scroll((model.scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(model.section.title()),
            )
            .wrap(Wrap { trim: false }),
        layout[2],
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
            Cell::from(
                view.collaboration
                    .as_ref()
                    .and_then(|value| value.run.as_ref())
                    .and_then(|value| RunStatus::try_from(value.status).ok())
                    .map(|value| value.as_str_name())
                    .unwrap_or("RUN_STATUS_UNSPECIFIED"),
            ),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(48),
                Constraint::Percentage(24),
                Constraint::Length(12),
                Constraint::Percentage(28),
            ],
        )
        .header(
            Row::new(["Task", "Status", "Revision", "Workflow"])
                .style(Style::default().fg(Color::Yellow)),
        )
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
    let mut facts = vec![code];
    if error.retryable {
        facts.push("retryable".to_owned());
    }
    if let Some(action) = error.required_action_code.filter(|value| !value.is_empty()) {
        facts.push(format!("action={action}"));
    }
    if !error.safe_fingerprint.is_empty() {
        facts.push(format!("fingerprint={}", error.safe_fingerprint));
    }
    facts.join(" | ")
}

async fn run_once(mut app: App) -> Result<(), String> {
    app.refresh().await;
    if let Some(snapshot) = app.snapshot {
        let return_pending_steps = snapshot
            .tasks
            .iter()
            .filter_map(|view| view.collaboration.as_ref())
            .flat_map(|collaboration| collaboration.steps.iter())
            .filter(|step| {
                step.status
                    == egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepStatus::ReturnPending
                        as i32
            })
            .count();
        let returned_steps = snapshot
            .tasks
            .iter()
            .filter_map(|view| view.collaboration.as_ref())
            .flat_map(|collaboration| collaboration.steps.iter())
            .filter(|step| {
                step.status
                    == egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepStatus::Returned
                        as i32
            })
            .count();
        let workflow = snapshot
            .tasks
            .iter()
            .filter_map(|view| view.collaboration.as_ref())
            .filter_map(|collaboration| collaboration.run.as_ref())
            .find_map(|run| RunStatus::try_from(run.status).ok())
            .map(|status| status.as_str_name())
            .unwrap_or("RUN_STATUS_UNSPECIFIED");
        println!(
            "EgoPulse TUI: connected health={} stale={} position={} tasks={} approvals={} workflow={} return_pending_steps={} returned_steps={}",
            snapshot.health,
            snapshot.stale,
            snapshot.position,
            snapshot.tasks.len(),
            snapshot.approvals.len(),
            workflow,
            return_pending_steps,
            returned_steps,
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
    let result = loop {
        let loop_result = run_loop(&mut terminal, &mut app).await;
        let finished = finish_interactive_session(&mut app, loop_result).await;
        if finished.is_err() && app.work_start.is_some() {
            continue;
        }
        break finished;
    };
    restore_terminal(&mut terminal).map_err(|error| error.to_string())?;
    result
}

async fn finish_interactive_session<T>(
    app: &mut App,
    result: Result<T, String>,
) -> Result<T, String> {
    if !app.settle_work_start_for_quit().await {
        return Err(app.message.clone());
    }
    app.stop_task_watch().await;
    app.stop_harness_content().await;
    app.stop_approval_queue().await;
    app.stop_result_review().await;
    app.stop_governed_state().await;
    result
}

async fn execute_interactive_action(
    app: &mut App,
    action: InteractiveAction,
    next_refresh: &mut tokio::time::Instant,
) -> Result<InteractiveLoopControl, String> {
    match action {
        InteractiveAction::OpenGovernedState => {
            if let Err(error) = app.start_governed_state().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Governed State unavailable: {error}");
            }
        }
        InteractiveAction::CloseGovernedState => {
            app.stop_governed_state().await;
            app.mode = InteractiveMode::Dashboard;
            app.message = "Governed State closed; no Authority state was changed".to_owned();
            *next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        InteractiveAction::OpenWorkStart => {
            if let Err(error) = app.start_work_start().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Work Start unavailable: {error}");
            }
        }
        InteractiveAction::CloseWorkStart => {
            if app.close_work_start_if_settled().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = "Work Start cancelled before preparation; no RPC was sent".to_owned();
            }
        }
        InteractiveAction::PrepareWorkStart => {
            let result = match app.work_start.as_mut() {
                Some(controller) => {
                    execute_work_start_mutation(controller, WorkStartMutationAction::Prepare).await
                }
                None => Err("Work Start controller is unavailable".to_owned()),
            };
            if let Err(error) = result {
                app.message = format!("Work Start preparation rejected: {error}");
            }
        }
        InteractiveAction::ReplayWorkPreparation => {
            let result = match app.work_start.as_mut() {
                Some(controller) => {
                    execute_work_start_mutation(
                        controller,
                        WorkStartMutationAction::ReplayPreparation,
                    )
                    .await
                }
                None => Err("Work Start controller is unavailable".to_owned()),
            };
            if let Err(error) = result {
                app.message = format!("Exact preparation replay rejected: {error}");
            }
        }
        InteractiveAction::CancelWorkPreview => {
            let result = match app.work_start.as_mut() {
                Some(controller) => {
                    execute_work_start_mutation(controller, WorkStartMutationAction::CancelPreview)
                        .await
                }
                None => Err("Work Start controller is unavailable".to_owned()),
            };
            match result {
                Ok(()) => {
                    app.apply_work_start_events().await?;
                }
                Err(error) => app.message = format!("Work Start preview cannot close: {error}"),
            }
        }
        InteractiveAction::ConfirmWorkStart => {
            let result = match app.work_start.as_mut() {
                Some(controller) => {
                    execute_work_start_mutation(controller, WorkStartMutationAction::Confirm).await
                }
                None => Err("Work Start controller is unavailable".to_owned()),
            };
            if let Err(error) = result {
                app.message = format!("Task confirmation was not sent: {error}");
            }
        }
        InteractiveAction::ReplayWorkConfirmation => {
            let result = match app.work_start.as_mut() {
                Some(controller) => {
                    execute_work_start_mutation(
                        controller,
                        WorkStartMutationAction::ReplayConfirmation,
                    )
                    .await
                }
                None => Err("Work Start controller is unavailable".to_owned()),
            };
            if let Err(error) = result {
                app.message = format!("Exact Task confirmation replay rejected: {error}");
            }
        }
        InteractiveAction::OpenTaskWatchForWorkReconciliation => {
            if let Err(error) = app.start_task_watch_for_work_reconciliation().await {
                app.mode = InteractiveMode::WorkStart;
                app.message = format!("Task Watch unavailable for reconciliation: {error}");
            } else {
                app.message = "Task confirmation remains uncertain; Task Watch is observation-only and does not imply cancellation or completion"
                    .to_owned();
            }
        }
        InteractiveAction::OpenTaskWatch | InteractiveAction::RefetchTaskWatch => {
            let result = if app.work_start.is_some() {
                app.start_task_watch_for_work_reconciliation().await
            } else {
                app.start_task_watch().await
            };
            if let Err(error) = result {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Task Watch unavailable: {error}");
            }
        }
        InteractiveAction::CloseTaskWatch => {
            app.stop_task_watch().await;
            app.mode = InteractiveMode::Dashboard;
            app.refresh().await;
            *next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        InteractiveAction::OpenHarnessContent => {
            if let Err(error) = app.start_harness_content().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Harness content unavailable: {error}");
            }
        }
        InteractiveAction::RefetchHarnessContent => {
            if let Err(error) = app.refetch_harness_content().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Harness content unavailable: {error}");
            }
        }
        InteractiveAction::CloseHarnessContent => {
            if let Err(error) = app.close_harness_content_to_task_watch().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Task Watch unavailable after Harness content: {error}");
            }
        }
        InteractiveAction::OpenResultReview => {
            if let Err(error) = app.start_result_review().await {
                app.message = format!("Result review unavailable: {error}");
            }
        }
        InteractiveAction::RefreshResultReview => {
            let result = match app.result_review.as_mut() {
                Some(controller) => controller.refresh().await,
                None => Err("Result review controller is unavailable".to_owned()),
            };
            if let Err(error) = result {
                app.message = format!("Result review unavailable: {error}");
            }
        }
        InteractiveAction::CloseResultReview => {
            if let Err(error) = app.close_result_review_to_task_watch().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Task Watch unavailable after review: {error}");
            }
        }
        InteractiveAction::OpenApprovalQueue | InteractiveAction::RefetchApprovalQueue => {
            if let Err(error) = app.start_approval_queue().await {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Approval Queue unavailable: {error}");
            }
        }
        InteractiveAction::CloseApprovalQueue => {
            app.stop_approval_queue().await;
            app.mode = InteractiveMode::Dashboard;
            app.refresh().await;
            *next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        InteractiveAction::SubmitApprovalDecision => {
            app.message = "Submitting guided approval decision...".to_owned();
            app.message = match app.submit_approval_decision().await {
                Ok(receipt) => approval_decision_feedback(
                    receipt.state_revision,
                    receipt.replayed,
                    receipt.projection_warning.is_some(),
                ),
                Err(error) => format!("Approval rejected: {error}"),
            };
        }
        InteractiveAction::Quit => {
            if !app.settle_work_start_for_quit().await {
                return Ok(InteractiveLoopControl::Continue);
            }
            app.stop_task_watch().await;
            app.stop_harness_content().await;
            app.stop_approval_queue().await;
            app.stop_result_review().await;
            app.stop_governed_state().await;
            return Ok(InteractiveLoopControl::Quit);
        }
        InteractiveAction::StageContextRevoke(input) => {
            let result = app.stage_context_revoke(input).await;
            if let Err(error) = result {
                app.mode = InteractiveMode::Dashboard;
                app.message = format!("Operation rejected before confirmation: {error}");
            }
        }
        InteractiveAction::Command(command) => {
            app.message = format!("Executing {}...", command_kind(&command));
            let result = run_command_quiet(&app.instance, *command).await;
            app.message = match result {
                Ok(CommandResult::Completed) => {
                    "Governed command committed; projection will refresh automatically".to_owned()
                }
                Ok(CommandResult::ReadView(view)) => view,
                Err(error) => format!("Operation rejected: {error}"),
            };
            app.refresh().await;
            *next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        InteractiveAction::ConfirmContextRevoke => {
            app.message = "Submitting the confirmed Context revoke...".to_owned();
            app.message = match app.confirm_context_revoke().await {
                Ok(receipt) => format!(
                    "Context revoked at state revision {} (replayed={})",
                    receipt.result_state_revision, receipt.replayed
                ),
                Err(error) => format!("Operation rejected: {error}"),
            };
            app.refresh().await;
            *next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
    }
    Ok(InteractiveLoopControl::Continue)
}

async fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<(), String> {
    let mut next_refresh = tokio::time::Instant::now();
    loop {
        if matches!(app.mode, InteractiveMode::WorkStart)
            && let Err(error) = app.apply_work_start_events().await
        {
            app.message = format!("Work Start stopped fail-closed: {error}");
        }
        if matches!(app.mode, InteractiveMode::GovernedState)
            && let Err(error) = app.apply_governed_state_events()
        {
            app.message = format!("Governed State stopped fail-closed: {error}");
        }
        if matches!(app.mode, InteractiveMode::TaskWatch)
            && let Err(error) = app.apply_task_watch_events().await
        {
            app.handle_task_watch_failure(error).await;
        }
        if matches!(app.mode, InteractiveMode::HarnessContent) {
            app.apply_harness_content_events();
        }
        if matches!(app.mode, InteractiveMode::ResultReview) {
            app.pump_result_review_fail_closed().await;
        }
        if matches!(
            app.mode,
            InteractiveMode::ApprovalQueue | InteractiveMode::ApprovalDecisionModal(_)
        ) && let Err(error) = app.apply_approval_queue_events().await
        {
            app.stop_approval_queue().await;
            app.mode = InteractiveMode::Dashboard;
            app.message = format!("Approval Queue stopped fail-closed: {error}");
        }
        terminal
            .draw(|frame| app.render(frame))
            .map_err(|error| error.to_string())?;
        if tokio::time::Instant::now() >= next_refresh
            && matches!(app.mode, InteractiveMode::Dashboard)
        {
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
            if let Some(action) = app.handle_key(key)?
                && execute_interactive_action(app, action, &mut next_refresh).await?
                    == InteractiveLoopControl::Quit
            {
                return Ok(());
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
    use egopulse_client_operations::{
        ApprovalWatchClassification, ClientGovernedTaskError, ClientTaskResultReviewError,
        GovernedProjectionPosition, GovernedProjectionState, TaskResultReview,
    };
    use egopulse_tui::approval_queue::{
        ApprovalQueueItem, ApprovalQueueNextFuture, ApprovalQueueOpened, ApprovalQueueStream,
        ApprovalQueueStreamUpdate,
    };
    use egopulse_tui::governed_state::{
        ApprovalDomainPage, ApprovalFactView, DomainView, GovernedStateSnapshot, RecordKind,
        TaskDomainPage, TaskFactView,
    };
    use egopulse_tui::task_watch::{TaskWatchBaseline, TaskWatchNextFuture, TaskWatchStream};
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn governed_snapshot(
        task_phase: &str,
        approval_phase: &str,
        task_sequence: u64,
        approval_sequence: u64,
    ) -> GovernedStateSnapshot {
        GovernedStateSnapshot {
            task: TaskDomainPage {
                view: DomainView {
                    phase: task_phase.to_owned(),
                    reason: None,
                    generation: 1,
                    recovery_limit: 3,
                    recovery_remaining: 3,
                    epoch: Some("epoch:task".to_owned()),
                    sequence: Some(task_sequence),
                },
                facts: vec![TaskFactView {
                    task_id: "task:governed".to_owned(),
                    revision: 7,
                    status: "task_status_active".to_owned(),
                }],
            },
            approval: ApprovalDomainPage {
                view: DomainView {
                    phase: approval_phase.to_owned(),
                    reason: None,
                    generation: 1,
                    recovery_limit: 3,
                    recovery_remaining: 2,
                    epoch: Some("epoch:approval".to_owned()),
                    sequence: Some(approval_sequence),
                },
                facts: vec![ApprovalFactView {
                    approval_request_id: "approval:governed".to_owned(),
                    task_id: "task:governed".to_owned(),
                }],
            },
        }
    }

    struct MainGovernedStateStream {
        snapshot: GovernedStateSnapshot,
        updates: VecDeque<(
            egopulse_client_operations::GovernedStateDomain,
            GovernedStateSnapshot,
        )>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl GovernedStateStream for MainGovernedStateStream {
        fn safe_snapshot(&self) -> GovernedStateSnapshot {
            self.snapshot.clone()
        }

        fn next_update(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<Output = Option<egopulse_client_operations::GovernedStateDomain>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                if let Some((domain, snapshot)) = self.updates.pop_front() {
                    self.snapshot = snapshot;
                    Some(domain)
                } else {
                    pending().await
                }
            })
        }

        fn shutdown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    struct MainGovernedStateClient {
        initial: GovernedStateSnapshot,
        updates: Mutex<
            Option<
                VecDeque<(
                    egopulse_client_operations::GovernedStateDomain,
                    GovernedStateSnapshot,
                )>,
            >,
        >,
        starts: Arc<AtomicUsize>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl GovernedStateClient for MainGovernedStateClient {
        fn start_governed_state_stream(
            self: &Arc<Self>,
        ) -> Result<Box<dyn GovernedStateStream>, GovernedStateControllerStartError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(MainGovernedStateStream {
                snapshot: self.initial.clone(),
                updates: self
                    .updates
                    .lock()
                    .expect("lock governed updates")
                    .take()
                    .unwrap_or_default(),
                shutdowns: Arc::clone(&self.shutdowns),
            }))
        }
    }

    fn governed_client(
        updates: VecDeque<(
            egopulse_client_operations::GovernedStateDomain,
            GovernedStateSnapshot,
        )>,
    ) -> (
        Arc<MainGovernedStateClient>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let starts = Arc::new(AtomicUsize::new(0));
        let shutdowns = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(MainGovernedStateClient {
                initial: governed_snapshot("connecting", "connecting", 10, 20),
                updates: Mutex::new(Some(updates)),
                starts: Arc::clone(&starts),
                shutdowns: Arc::clone(&shutdowns),
            }),
            starts,
            shutdowns,
        )
    }

    #[test]
    fn governed_state_dashboard_keys_open_and_escape_closes() {
        let mut app = App::new("governed-keys".to_owned());
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE))
                .expect("map dashboard key"),
            Some(InteractiveAction::OpenGovernedState)
        ));
        app.mode = InteractiveMode::GovernedState;
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .expect("map governed escape"),
            Some(InteractiveAction::CloseGovernedState)
        ));
        assert!(app.footer_text().contains("Esc dashboard"));
        app.mode = InteractiveMode::Dashboard;
        assert!(app.footer_text().contains("g governed state"));
    }

    #[test]
    fn production_attachment_pair_uses_one_arc_identity() {
        let (interactive, governed) = shared_attached_client_pair("same-attachment");
        assert!(Arc::ptr_eq(&interactive, &governed));
    }

    #[tokio::test]
    async fn governed_state_app_starts_pumps_renders_and_close_shuts_down_once() {
        let (client, starts, shutdowns) = governed_client(VecDeque::from([(
            egopulse_client_operations::GovernedStateDomain::Task,
            governed_snapshot("live", "connecting", 11, 20),
        )]));
        let mut app = App::new("governed-controller".to_owned());
        app.install_governed_state_controller(client)
            .expect("start governed state controller");
        assert!(matches!(app.mode, InteractiveMode::GovernedState));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            app.governed_state
                .as_ref()
                .expect("controller")
                .model()
                .kind,
            RecordKind::Initial
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.apply_governed_state_events().expect("pump update");
                if app
                    .governed_state
                    .as_ref()
                    .expect("controller")
                    .model()
                    .kind
                    == RecordKind::Update
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("governed state update must arrive within one second");
        let model = app.governed_state.as_ref().expect("controller").model();
        assert_eq!(model.kind, RecordKind::Update);
        assert_eq!(model.update_index, 1);
        assert_eq!(model.task.view.phase, "live");
        assert_eq!(model.approval.view.phase, "connecting");

        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = ratatui::Terminal::new(backend).expect("create terminal");
        terminal
            .draw(|frame| app.render(frame))
            .expect("render page");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("kind=update"), "rendered={rendered}");
        assert!(rendered.contains("changed_domain=task"));
        assert!(rendered.contains("Task domain: phase=live"));
        assert!(rendered.contains("Approval domain: phase=connecting"));
        assert!(rendered.contains("positions are independent"));
        assert!(rendered.contains("no atomic snapshot or global cursor"));
        assert!(!rendered.contains("completed"));

        let mut next_refresh = tokio::time::Instant::now();
        execute_interactive_action(
            &mut app,
            InteractiveAction::CloseGovernedState,
            &mut next_refresh,
        )
        .await
        .expect("close governed state");
        assert!(matches!(app.mode, InteractiveMode::Dashboard));
        assert!(app.governed_state.is_none());
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn governed_state_finish_and_quit_each_shutdown_exactly_once() {
        let (finish_client, _, finish_shutdowns) = governed_client(VecDeque::new());
        let mut finished = App::new("governed-finish".to_owned());
        finished
            .install_governed_state_controller(finish_client)
            .expect("start finish controller");
        assert_eq!(
            finish_interactive_session(&mut finished, Ok::<_, String>(7))
                .await
                .expect("finish session"),
            7
        );
        assert_eq!(finish_shutdowns.load(Ordering::SeqCst), 1);

        let (quit_client, _, quit_shutdowns) = governed_client(VecDeque::new());
        let mut quitting = App::new("governed-quit".to_owned());
        quitting
            .install_governed_state_controller(quit_client)
            .expect("start quit controller");
        let mut next_refresh = tokio::time::Instant::now();
        assert_eq!(
            execute_interactive_action(&mut quitting, InteractiveAction::Quit, &mut next_refresh,)
                .await
                .expect("quit"),
            InteractiveLoopControl::Quit
        );
        assert_eq!(quit_shutdowns.load(Ordering::SeqCst), 1);
    }

    #[derive(Clone)]
    enum ScriptedWatchStep {
        Pending,
        WaitUpdate(
            Arc<tokio::sync::Notify>,
            Box<egopulse_client_operations::GovernedTaskUpdate>,
        ),
    }

    struct ScriptedTaskWatch {
        steps: Arc<Mutex<VecDeque<ScriptedWatchStep>>>,
        next_calls: Arc<AtomicUsize>,
    }

    struct CountingWorkStartMutationTarget {
        stage: WorkStartStage,
        ready: bool,
        prepare_calls: usize,
        replay_preparation_calls: usize,
        cancel_preview_calls: usize,
        confirm_calls: usize,
        replay_confirmation_calls: usize,
    }

    impl CountingWorkStartMutationTarget {
        fn new(stage: WorkStartStage, ready: bool) -> Self {
            Self {
                stage,
                ready,
                prepare_calls: 0,
                replay_preparation_calls: 0,
                cancel_preview_calls: 0,
                confirm_calls: 0,
                replay_confirmation_calls: 0,
            }
        }
    }

    impl WorkStartMutationTarget for CountingWorkStartMutationTarget {
        fn prepare_mutation(&mut self) -> WorkStartMutationFuture<'_> {
            self.prepare_calls += 1;
            self.stage = WorkStartStage::Preparing;
            Box::pin(async { Ok(()) })
        }

        fn replay_preparation_mutation(&mut self) -> WorkStartMutationFuture<'_> {
            self.replay_preparation_calls += 1;
            self.stage = WorkStartStage::Preparing;
            Box::pin(async { Ok(()) })
        }

        fn cancel_preview_mutation(&mut self) -> WorkStartMutationFuture<'_> {
            self.cancel_preview_calls += 1;
            self.stage = WorkStartStage::Editing;
            Box::pin(async { Ok(()) })
        }

        fn confirm_mutation(&mut self) -> WorkStartMutationFuture<'_> {
            if !self.ready {
                return Box::pin(async {
                    Err("blocked preview cannot dispatch confirmation".to_owned())
                });
            }
            self.confirm_calls += 1;
            self.stage = WorkStartStage::Confirming;
            Box::pin(async { Ok(()) })
        }

        fn replay_confirmation_mutation(&mut self) -> WorkStartMutationFuture<'_> {
            self.replay_confirmation_calls += 1;
            self.stage = WorkStartStage::Confirming;
            Box::pin(async { Ok(()) })
        }
    }

    impl TaskWatchStream for ScriptedTaskWatch {
        fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
            self.next_calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .steps
                .lock()
                .expect("read scripted Task watch")
                .pop_front()
                .unwrap_or(ScriptedWatchStep::Pending);
            Box::pin(async move {
                match step {
                    ScriptedWatchStep::Pending => std::future::pending().await,
                    ScriptedWatchStep::WaitUpdate(notify, update) => {
                        notify.notified().await;
                        Ok(*update)
                    }
                }
            })
        }
    }

    struct WatchInteractiveClient {
        snapshots: Arc<Mutex<VecDeque<Snapshot>>>,
        sessions: Arc<Mutex<VecDeque<VecDeque<ScriptedWatchStep>>>>,
        snapshot_calls: Arc<AtomicUsize>,
        open_calls: Arc<AtomicUsize>,
        next_calls: Arc<AtomicUsize>,
    }

    impl TaskWatchClient for WatchInteractiveClient {
        fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .snapshots
                .lock()
                .expect("read scripted baselines")
                .pop_front()
                .ok_or(ClientGovernedTaskError::Protocol("no scripted baseline"));
            Box::pin(std::future::ready(result.map(safe_task_watch_baseline)))
        }

        fn open_task_watch_session(&self, _baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            let steps = self
                .sessions
                .lock()
                .expect("read scripted sessions")
                .pop_front()
                .unwrap_or_else(|| VecDeque::from([ScriptedWatchStep::Pending]));
            let next_calls = Arc::clone(&self.next_calls);
            Box::pin(async move {
                Ok(Box::new(ScriptedTaskWatch {
                    steps: Arc::new(Mutex::new(steps)),
                    next_calls,
                }) as Box<dyn TaskWatchStream>)
            })
        }
    }

    impl InteractiveClient for WatchInteractiveClient {
        fn snapshot(&self) -> SnapshotFuture<'_> {
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .snapshots
                .lock()
                .expect("read scripted baselines")
                .pop_front()
                .ok_or_else(|| "no scripted baseline".to_owned());
            Box::pin(std::future::ready(result))
        }

        fn prepare_context_revoke(
            &self,
            _input: ContextRevokeInput,
        ) -> Result<PendingContextRevoke, String> {
            Err("Context revoke not used by Task Watch test".to_owned())
        }
    }

    impl TaskResultReviewClient for WatchInteractiveClient {
        fn read_task_result_review<'a>(&'a self, _task_id: &'a str) -> TaskResultReviewFuture<'a> {
            Box::pin(async {
                Err(ClientTaskResultReviewError::InvalidInput(
                    "result review unavailable in Task Watch fixture",
                ))
            })
        }
    }

    impl ApprovalQueueClient for WatchInteractiveClient {
        fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
            Box::pin(async {
                Err(
                    egopulse_client_operations::ClientApprovalWatchError::Protocol(
                        "Approval Queue not used by Task Watch test",
                    ),
                )
            })
        }

        fn decide_guided_approval(
            &self,
            _input: GuidedApprovalDecisionInput,
        ) -> GuidedApprovalFuture<'_> {
            Box::pin(async {
                Err(
                    egopulse_client_operations::ClientGuidedApprovalDecisionError::InvalidInput(
                        "Approval Queue not used by Task Watch test",
                    ),
                )
            })
        }
    }

    enum MainApprovalStreamStep {
        Update(Vec<ApprovalQueueItem>),
        Pending,
    }

    struct MainApprovalStream {
        steps: VecDeque<MainApprovalStreamStep>,
        next_calls: Arc<AtomicUsize>,
    }

    impl ApprovalQueueStream for MainApprovalStream {
        fn next_update(&mut self) -> ApprovalQueueNextFuture<'_> {
            self.next_calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .steps
                .pop_front()
                .unwrap_or(MainApprovalStreamStep::Pending);
            Box::pin(async move {
                match step {
                    MainApprovalStreamStep::Update(items) => {
                        Ok(Some(ApprovalQueueStreamUpdate::from_safe_projection(
                            ApprovalWatchClassification::Applied,
                            "epoch:approval:2",
                            items,
                        )))
                    }
                    MainApprovalStreamStep::Pending => std::future::pending().await,
                }
            })
        }
    }

    struct CombinedInteractiveClient {
        approval_streams: Mutex<VecDeque<VecDeque<MainApprovalStreamStep>>>,
        approval_next_calls: Arc<AtomicUsize>,
        approval_decide_calls: AtomicUsize,
        task_open_calls: AtomicUsize,
        approval_open_calls: AtomicUsize,
        review_calls: AtomicUsize,
        review_task_ids: Mutex<Vec<String>>,
        task_stream_dropped: Arc<std::sync::atomic::AtomicBool>,
        review_started_after_task_stop: std::sync::atomic::AtomicBool,
        review_steps: Mutex<VecDeque<MainReviewStep>>,
    }

    impl CombinedInteractiveClient {
        fn new(approval_streams: VecDeque<VecDeque<MainApprovalStreamStep>>) -> Self {
            Self {
                approval_streams: Mutex::new(approval_streams),
                approval_next_calls: Arc::new(AtomicUsize::new(0)),
                approval_decide_calls: AtomicUsize::new(0),
                task_open_calls: AtomicUsize::new(0),
                approval_open_calls: AtomicUsize::new(0),
                review_calls: AtomicUsize::new(0),
                review_task_ids: Mutex::new(Vec::new()),
                task_stream_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                review_started_after_task_stop: std::sync::atomic::AtomicBool::new(false),
                review_steps: Mutex::new(VecDeque::new()),
            }
        }

        fn with_review_steps(mut self, steps: VecDeque<MainReviewStep>) -> Self {
            self.review_steps = Mutex::new(steps);
            self
        }
    }

    enum MainReviewStep {
        Success,
        Integrity,
    }

    struct CombinedTaskWatchStream {
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for CombinedTaskWatchStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl TaskWatchStream for CombinedTaskWatchStream {
        fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
            Box::pin(std::future::pending())
        }
    }

    impl TaskWatchClient for CombinedInteractiveClient {
        fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            Box::pin(std::future::ready(Ok(safe_task_watch_baseline(
                watch_snapshot("task:mutual", 1, 10),
            ))))
        }

        fn open_task_watch_session(&self, _baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
            self.task_open_calls.fetch_add(1, Ordering::SeqCst);
            self.task_stream_dropped.store(false, Ordering::SeqCst);
            let dropped = Arc::clone(&self.task_stream_dropped);
            Box::pin(async move {
                Ok(Box::new(CombinedTaskWatchStream { dropped }) as Box<dyn TaskWatchStream>)
            })
        }
    }

    impl ApprovalQueueClient for CombinedInteractiveClient {
        fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
            self.approval_open_calls.fetch_add(1, Ordering::SeqCst);
            let steps = self
                .approval_streams
                .lock()
                .expect("read approval streams")
                .pop_front()
                .unwrap_or_else(|| VecDeque::from([MainApprovalStreamStep::Pending]));
            let next_calls = Arc::clone(&self.approval_next_calls);
            Box::pin(async move {
                Ok(ApprovalQueueOpened::from_safe_projection(
                    "epoch:approval:1",
                    vec![ApprovalQueueItem {
                        approval_request_id: "approval:main".to_owned(),
                        task_id: "task:main".to_owned(),
                    }],
                    Box::new(MainApprovalStream { steps, next_calls }),
                ))
            })
        }

        fn decide_guided_approval(
            &self,
            input: GuidedApprovalDecisionInput,
        ) -> GuidedApprovalFuture<'_> {
            self.approval_decide_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(ApprovalDecisionReceipt {
                    committed: true,
                    replayed: false,
                    authority_decision_ref: "decision:main".to_owned(),
                    decision: input.decision,
                    state_revision: 2,
                    projection_warning: None,
                })
            })
        }
    }

    impl InteractiveClient for CombinedInteractiveClient {
        fn snapshot(&self) -> SnapshotFuture<'_> {
            Box::pin(std::future::ready(Ok(watch_snapshot("task:mutual", 1, 10))))
        }

        fn prepare_context_revoke(
            &self,
            _input: ContextRevokeInput,
        ) -> Result<PendingContextRevoke, String> {
            Err("Context revoke not used by lifecycle tests".to_owned())
        }
    }

    impl TaskResultReviewClient for CombinedInteractiveClient {
        fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a> {
            self.review_calls.fetch_add(1, Ordering::SeqCst);
            self.review_started_after_task_stop.store(
                self.task_stream_dropped.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.review_task_ids
                .lock()
                .unwrap()
                .push(task_id.to_owned());
            let step = self
                .review_steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(MainReviewStep::Success);
            Box::pin(async move {
                if matches!(step, MainReviewStep::Integrity) {
                    return Err(ClientTaskResultReviewError::Integrity {
                        stage: egopulse_client_operations::TaskResultReviewStage::Evidence,
                        detail: "scripted integrity failure",
                    });
                }
                Ok(TaskResultReview {
                    task_view: TaskView {
                        task: Some(
                            egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                                task_id: task_id.to_owned(),
                                revision: 1,
                                status: TaskStatus::Active as i32,
                                ..Default::default()
                            },
                        ),
                        ..Default::default()
                    },
                    evidence_graph: None,
                })
            })
        }
    }

    fn watch_task(task_id: &str, revision: u64) -> TaskView {
        TaskView {
            task: Some(
                egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                    task_id: task_id.to_owned(),
                    revision,
                    status: TaskStatus::Active as i32,
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
    }

    fn watch_snapshot(task_id: &str, revision: u64, sequence: u64) -> Snapshot {
        Snapshot {
            health: "PROJECTION_HEALTH_READY".to_owned(),
            stale: false,
            position: format!("epoch:watch:{sequence}"),
            tasks: vec![watch_task(task_id, revision)],
            approvals: Vec::new(),
        }
    }

    fn safe_task_watch_baseline(snapshot: Snapshot) -> TaskWatchBaseline {
        let (epoch, sequence) = snapshot
            .position
            .rsplit_once(':')
            .map(|(epoch, sequence)| {
                (
                    epoch.to_owned(),
                    sequence.parse::<u64>().expect("test baseline sequence"),
                )
            })
            .expect("test baseline position");
        let position = GovernedProjectionPosition { epoch, sequence };
        let tasks = snapshot
            .tasks
            .into_iter()
            .map(|view| {
                let task = view.task.expect("test Task snapshot");
                watch_governed_task(
                    &task.task_id,
                    task.revision,
                    TaskStatus::try_from(task.status).expect("test Task status"),
                    &position,
                )
            })
            .collect();
        TaskWatchBaseline::from_safe_projection_adapter(position, tasks)
    }

    fn watch_governed_task(
        task_id: &str,
        revision: u64,
        status: TaskStatus,
        position: &GovernedProjectionPosition,
    ) -> GovernedTaskState {
        GovernedTaskState {
            task_id: task_id.to_owned(),
            revision,
            status,
            resume_status: None,
            hold_reason: None,
            projection: GovernedProjectionState {
                position: position.clone(),
                health: ProjectionHealth::Ready,
                stale: false,
                reason: None,
            },
            run: None,
        }
    }

    fn watch_detailed_governed_task(
        task_id: &str,
        position: &GovernedProjectionPosition,
    ) -> GovernedTaskState {
        let mut task = watch_governed_task(task_id, 3, TaskStatus::Active, position);
        task.hold_reason = Some(GovernedHoldReason::ManualRecoveryRequired);
        task.run = Some(egopulse_client_operations::GovernedRunState {
            run_id: "run:safe-review".to_owned(),
            revision: 4,
            status: RunStatus::Returned,
            work_revision: 2,
            hold_reason: Some(GovernedHoldReason::CompensationRequired),
            steps: vec![egopulse_client_operations::GovernedStepState {
                step_id: "step:safe-review".to_owned(),
                revision: 5,
                status: egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepStatus::Held,
                hold_reason: Some(GovernedHoldReason::ManualRecoveryRequired),
                current_attempt_id: Some("attempt:safe-review".to_owned()),
                attempts: vec![egopulse_client_operations::GovernedAttemptState {
                    attempt_id: "attempt:safe-review".to_owned(),
                    revision: 6,
                    attempt_number: 1,
                    status: egopulse_domain_contracts::v01::egopulse::collaboration::v1::AttemptStatus::Held,
                    recovery_class: egopulse_domain_contracts::v01::egopulse::collaboration::v1::RecoveryClass::ManualOnly,
                    hold_reason: Some(GovernedHoldReason::IrreversibleOutcomeUnknown),
                    last_harness_sequence: 9,
                    checkpoint_reference_recorded: true,
                }],
            }],
        });
        task
    }

    fn watch_governed_update(
        classification: egopulse_client_operations::TaskWatchClassification,
        task_id: Option<&str>,
        sequence: u64,
    ) -> egopulse_client_operations::GovernedTaskUpdate {
        let position = GovernedProjectionPosition {
            epoch: "epoch:watch".to_owned(),
            sequence,
        };
        egopulse_client_operations::GovernedTaskUpdate {
            classification,
            position: position.clone(),
            task: task_id
                .map(|task_id| watch_governed_task(task_id, 1, TaskStatus::Active, &position)),
        }
    }

    async fn wait_for_test_count(counter: &AtomicUsize, expected: usize) {
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "counter did not reach {expected}; actual={}",
            counter.load(Ordering::SeqCst)
        );
    }

    struct FakeContextRevokeCommit {
        calls: Arc<AtomicUsize>,
        receipt: ContextRevokeReceipt,
    }

    impl ContextRevokeCommit for FakeContextRevokeCommit {
        fn commit(self: Box<Self>) -> ContextRevokeCommitFuture {
            let Self { calls, receipt } = *self;
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(receipt)
            })
        }
    }

    struct FakeInteractiveClient {
        prepare_calls: Arc<AtomicUsize>,
        commit_calls: Arc<AtomicUsize>,
        captured: Arc<Mutex<Vec<ContextRevokeInput>>>,
    }

    impl InteractiveClient for FakeInteractiveClient {
        fn snapshot(&self) -> SnapshotFuture<'_> {
            Box::pin(async { Err("snapshot not used by Context modal test".to_owned()) })
        }

        fn prepare_context_revoke(
            &self,
            input: ContextRevokeInput,
        ) -> Result<PendingContextRevoke, String> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.captured
                .lock()
                .expect("capture Context input")
                .push(input.clone());
            Ok(PendingContextRevoke {
                snapshot_id: input.snapshot_id,
                expected_state_revision: input.expected_state_revision,
                evidence_count: input.evidence_refs.len(),
                request_digest_sha256: "d".repeat(64),
                commit: Box::new(FakeContextRevokeCommit {
                    calls: Arc::clone(&self.commit_calls),
                    receipt: ContextRevokeReceipt {
                        result_state_revision: 2,
                        acknowledged_after_durability_barrier: true,
                        ..Default::default()
                    },
                }),
            })
        }
    }

    impl TaskResultReviewClient for FakeInteractiveClient {
        fn read_task_result_review<'a>(&'a self, _task_id: &'a str) -> TaskResultReviewFuture<'a> {
            Box::pin(async {
                Err(ClientTaskResultReviewError::InvalidInput(
                    "result review unavailable in fake fixture",
                ))
            })
        }
    }

    impl TaskWatchClient for FakeInteractiveClient {
        fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            Box::pin(async {
                Err(ClientGovernedTaskError::Protocol(
                    "Task watch not used by Context modal test",
                ))
            })
        }

        fn open_task_watch_session(&self, _baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
            Box::pin(async {
                Err(ClientGovernedTaskError::Transport(
                    "Task watch not used by Context modal test".to_owned(),
                ))
            })
        }
    }

    impl ApprovalQueueClient for FakeInteractiveClient {
        fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
            Box::pin(async {
                Err(
                    egopulse_client_operations::ClientApprovalWatchError::Protocol(
                        "Approval Queue not used by Context modal test",
                    ),
                )
            })
        }

        fn decide_guided_approval(
            &self,
            _input: GuidedApprovalDecisionInput,
        ) -> GuidedApprovalFuture<'_> {
            Box::pin(async {
                Err(
                    egopulse_client_operations::ClientGuidedApprovalDecisionError::InvalidInput(
                        "Approval Queue not used by Context modal test",
                    ),
                )
            })
        }
    }

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
            "deny".to_owned(),
            "user-denied".to_owned(),
            String::new(),
        ]) {
            field.value = value;
        }
        let command = form.into_command().expect("valid approval form");
        match command {
            TuiCommand::ApprovalDecide {
                confirmation_proof_ref,
                decision,
                ..
            } => {
                assert_eq!(confirmation_proof_ref, None);
                assert_eq!(decision, "deny");
            }
            _ => panic!("wrong command kind"),
        }
    }

    #[test]
    fn approval_form_and_modal_require_an_explicit_decision_and_single_submit() {
        let mut form = CommandForm::new(CommandKind::ApprovalDecide);
        assert_eq!(
            form.fields
                .iter()
                .find(|field| field.label == "decision")
                .expect("decision field")
                .value,
            ""
        );
        form.fields[0].value = "approval:form:1".to_owned();
        form.fields[2].value = "founder-reviewed".to_owned();
        assert!(matches!(
            form.into_command(),
            Err(error) if error == "decision is required"
        ));

        let mut app = App::new("approval-modal".to_owned());
        app.mode = InteractiveMode::ApprovalDecisionModal(ApprovalDecisionModal::new(
            "approval:modal:1".to_owned(),
        ));
        assert!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .is_none(),
            "Enter without an explicit decision/reason must not submit"
        );
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .unwrap();
        for character in "founder-reviewed".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE))
                .unwrap();
        }
        let first = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        assert!(matches!(
            first,
            Some(InteractiveAction::SubmitApprovalDecision)
        ));
        assert!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .is_none(),
            "a second Enter while submission is in flight must be ignored"
        );
        let InteractiveMode::ApprovalDecisionModal(modal) = &app.mode else {
            panic!("approval modal")
        };
        assert_eq!(modal.decision, Some(GuidedApprovalDecision::AllowOnce));
        assert_eq!(modal.reason_code, "founder-reviewed");
    }

    #[tokio::test]
    async fn app_keeps_task_watch_and_approval_queue_mutually_exclusive() {
        let client = Arc::new(CombinedInteractiveClient::new(VecDeque::from([
            VecDeque::from([MainApprovalStreamStep::Pending]),
        ])));
        let mut app = App::new("mutual-watch".to_owned());
        app.client = Some(Arc::clone(&client) as Arc<dyn InteractiveClient>);

        app.start_task_watch().await.unwrap();
        wait_for_test_count(&client.task_open_calls, 1).await;
        assert!(app.task_watch.is_some());
        assert!(app.approval_queue.is_none());

        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap()
            .expect("selected Task opens review");
        assert!(matches!(action, InteractiveAction::OpenResultReview));
        let mut refresh = tokio::time::Instant::now();
        execute_interactive_action(&mut app, action, &mut refresh)
            .await
            .unwrap();
        assert!(app.task_watch.is_none());
        assert!(app.approval_queue.is_none());
        assert!(app.result_review.is_some());
        wait_for_test_count(&client.review_calls, 1).await;
        assert_eq!(
            client.review_task_ids.lock().unwrap().as_slice(),
            ["task:mutual"]
        );
        assert!(client.review_started_after_task_stop.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(1), async {
            while app.result_review.as_ref().unwrap().model().is_none() {
                app.apply_result_review_events().await.unwrap();
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let backend = ratatui::backend::TestBackend::new(120, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Governance evidence does not complete"));
        assert!(rendered.contains("Task status: Active"));
        assert!(rendered.contains("ArtifactSet: Not projected"));
        assert!(!rendered.contains("Task status: Completed"));

        let close = app
            .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .unwrap()
            .expect("review Esc action");
        assert!(matches!(close, InteractiveAction::CloseResultReview));
        execute_interactive_action(&mut app, close, &mut refresh)
            .await
            .unwrap();
        assert!(app.result_review.is_none());
        assert_eq!(
            app.task_watch
                .as_ref()
                .unwrap()
                .model()
                .unwrap()
                .selected_task_id
                .as_deref(),
            Some("task:mutual")
        );

        app.start_approval_queue().await.unwrap();
        assert!(app.task_watch.is_none());
        assert!(app.approval_queue.is_some());
        assert!(app.result_review.is_none());

        app.start_task_watch().await.unwrap();
        wait_for_test_count(&client.task_open_calls, 2).await;
        assert!(app.task_watch.is_some());
        assert!(app.approval_queue.is_none());
        assert_eq!(client.task_open_calls.load(Ordering::SeqCst), 2);
        assert_eq!(client.approval_open_calls.load(Ordering::SeqCst), 1);
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap()
            .unwrap();
        execute_interactive_action(&mut app, action, &mut refresh)
            .await
            .unwrap();
        let quit = app
            .handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE))
            .unwrap()
            .unwrap();
        assert_eq!(
            execute_interactive_action(&mut app, quit, &mut refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Quit
        );
        assert!(app.task_watch.is_none());
        assert!(app.approval_queue.is_none());
        assert!(app.result_review.is_none());
    }

    #[tokio::test]
    async fn result_review_failure_keeps_stopped_controller_for_one_explicit_refresh() {
        let client = Arc::new(
            CombinedInteractiveClient::new(VecDeque::new()).with_review_steps(VecDeque::from([
                MainReviewStep::Integrity,
                MainReviewStep::Success,
            ])),
        );
        let mut app = App::new("review-recovery".to_owned());
        app.client = Some(Arc::clone(&client) as Arc<dyn InteractiveClient>);
        app.start_task_watch().await.unwrap();
        wait_for_test_count(&client.task_open_calls, 1).await;
        let open = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap()
            .expect("selected Task opens result review");
        let mut next_refresh = tokio::time::Instant::now();
        execute_interactive_action(&mut app, open, &mut next_refresh)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.pump_result_review_fail_closed().await;
                if app
                    .result_review
                    .as_ref()
                    .is_some_and(|controller| !controller.is_running())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(app.mode, InteractiveMode::ResultReview));
        assert!(app.result_review.is_some());
        assert!(!app.result_review.as_ref().unwrap().is_running());
        assert!(app.result_review.as_ref().unwrap().model().is_none());
        assert!(app.message.contains("stopped fail-closed"));
        assert_eq!(client.review_calls.load(Ordering::SeqCst), 1);

        for _ in 0..3 {
            app.pump_result_review_fail_closed().await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            client.review_calls.load(Ordering::SeqCst),
            1,
            "a failed result review must not retry automatically"
        );

        let retry = app
            .handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
            .unwrap()
            .expect("explicit result review refresh");
        assert!(matches!(retry, InteractiveAction::RefreshResultReview));
        execute_interactive_action(&mut app, retry, &mut next_refresh)
            .await
            .unwrap();
        wait_for_test_count(&client.review_calls, 2).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.pump_result_review_fail_closed().await;
                if app
                    .result_review
                    .as_ref()
                    .and_then(ResultReviewController::model)
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(client.review_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            app.result_review.as_ref().unwrap().model().unwrap().task_id,
            "task:mutual"
        );

        let close = app
            .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .unwrap()
            .expect("review Esc returns to Task Watch");
        execute_interactive_action(&mut app, close, &mut next_refresh)
            .await
            .unwrap();
        assert!(matches!(app.mode, InteractiveMode::TaskWatch));
        assert!(app.result_review.is_none());
        assert_eq!(
            app.task_watch
                .as_ref()
                .and_then(TaskWatchController::model)
                .and_then(|model| model.selected_task_id.as_deref()),
            Some("task:mutual")
        );
        app.stop_task_watch().await;
    }

    #[tokio::test]
    async fn production_modal_actions_cancel_once_and_reject_a_disappeared_candidate() {
        let escaped_client = Arc::new(CombinedInteractiveClient::new(VecDeque::from([
            VecDeque::from([MainApprovalStreamStep::Pending]),
        ])));
        let mut escaped = App::new("approval-escape".to_owned());
        escaped.client = Some(Arc::clone(&escaped_client) as Arc<dyn InteractiveClient>);
        escaped.start_approval_queue().await.unwrap();
        assert!(
            escaped
                .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .is_none()
        );
        assert!(
            escaped
                .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            escaped_client.approval_decide_calls.load(Ordering::SeqCst),
            0
        );
        escaped.stop_approval_queue().await;

        let submitted_client = Arc::new(CombinedInteractiveClient::new(VecDeque::from([
            VecDeque::from([MainApprovalStreamStep::Pending]),
        ])));
        let mut submitted = App::new("approval-submit".to_owned());
        submitted.client = Some(Arc::clone(&submitted_client) as Arc<dyn InteractiveClient>);
        submitted.start_approval_queue().await.unwrap();
        submitted
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        submitted
            .handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .unwrap();
        for character in "founder-reviewed".chars() {
            submitted
                .handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE))
                .unwrap();
        }
        let action = submitted
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap()
            .expect("first Enter submits");
        assert!(
            submitted
                .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .is_none(),
            "second Enter while the modal is submitting must not dispatch"
        );
        let mut next_refresh = tokio::time::Instant::now();
        assert_eq!(
            execute_interactive_action(&mut submitted, action, &mut next_refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Continue
        );
        assert_eq!(
            submitted_client
                .approval_decide_calls
                .load(Ordering::SeqCst),
            1
        );
        submitted.stop_approval_queue().await;

        let removed_client = Arc::new(CombinedInteractiveClient::new(VecDeque::from([
            VecDeque::from([
                MainApprovalStreamStep::Update(Vec::new()),
                MainApprovalStreamStep::Pending,
            ]),
        ])));
        let mut removed = App::new("approval-removed".to_owned());
        removed.client = Some(Arc::clone(&removed_client) as Arc<dyn InteractiveClient>);
        removed.start_approval_queue().await.unwrap();
        removed
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap();
        removed
            .handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .unwrap();
        for character in "founder-reviewed".chars() {
            removed
                .handle_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE))
                .unwrap();
        }
        let action = removed
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .unwrap()
            .expect("modal seals one action before projection changes");
        for _ in 0..100 {
            tokio::task::yield_now().await;
            removed.apply_approval_queue_events().await.unwrap();
            if removed
                .approval_queue
                .as_ref()
                .and_then(|controller| controller.model())
                .is_some_and(|model| model.items.is_empty())
            {
                break;
            }
        }
        assert!(
            removed
                .approval_queue
                .as_ref()
                .and_then(|controller| controller.model())
                .is_some_and(|model| model.items.is_empty())
        );
        assert_eq!(
            execute_interactive_action(&mut removed, action, &mut next_refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Continue
        );
        assert!(removed.message.contains("no longer actionable"));
        assert_eq!(
            removed_client.approval_decide_calls.load(Ordering::SeqCst),
            0
        );
        removed.stop_approval_queue().await;
    }

    #[test]
    fn command_palette_and_form_use_same_command_surface() {
        let mut app = App::new("default".to_owned());
        app.open_palette();
        assert!(matches!(app.mode, InteractiveMode::Palette { selected: 0 }));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("open work preview form");
        assert!(matches!(
            app.mode,
            InteractiveMode::Form(CommandForm {
                kind: CommandKind::WorkPlan,
                ..
            })
        ));

        app.open_palette();
        for _ in 0..6 {
            app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE))
                .expect("palette navigation");
        }
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
    fn governed_work_prepare_and_confirm_forms_map_to_kernel_commands() {
        let mut prepare = CommandForm::new(CommandKind::WorkPrepare);
        for (field, value) in prepare.fields.iter_mut().zip([
            "整理当前项目的 Memory 治理".to_owned(),
            "project:egopulse".to_owned(),
            "research_implementation".to_owned(),
            "docs/ARCHITECTURE.md".to_owned(),
            "idem-prepare-1".to_owned(),
        ]) {
            field.value = value;
        }
        assert!(matches!(
            prepare.into_command().expect("valid prepare form"),
            TuiCommand::WorkPrepare {
                intent,
                scope,
                work_type,
                context_refs,
                idempotency_key,
                json: false,
            } if intent == "整理当前项目的 Memory 治理"
                && scope == "project:egopulse"
                && work_type == "research_implementation"
                && context_refs == vec!["docs/ARCHITECTURE.md"]
                && idempotency_key == "idem-prepare-1"
        ));

        let mut confirm = CommandForm::new(CommandKind::WorkConfirm);
        for (field, value) in confirm.fields.iter_mut().zip([
            "ctx:abc".to_owned(),
            "binding-sha256".to_owned(),
            "idem-confirm-1".to_owned(),
        ]) {
            field.value = value;
        }
        assert!(matches!(
            confirm.into_command().expect("valid confirm form"),
            TuiCommand::WorkConfirm {
                snapshot_id,
                confirmation_binding_sha256,
                idempotency_key,
                json: false,
            } if snapshot_id == "ctx:abc"
                && confirmation_binding_sha256 == "binding-sha256"
                && idempotency_key == "idem-confirm-1"
        ));
    }

    #[test]
    fn work_preview_form_preserves_natural_language_and_optional_context() {
        let mut form = CommandForm::new(CommandKind::WorkPlan);
        for (field, value) in form.fields.iter_mut().zip([
            "整理当前项目的 Memory 治理".to_owned(),
            "project:egopulse".to_owned(),
            "research_implementation".to_owned(),
            "docs/ARCHITECTURE.md".to_owned(),
        ]) {
            field.value = value;
        }
        let command = form.into_command().expect("valid work preview form");
        assert!(matches!(
            command,
            TuiCommand::WorkPlan {
                intent,
                scope,
                work_type,
                context_refs,
                json: false,
            } if intent == "整理当前项目的 Memory 治理"
                && scope == "project:egopulse"
                && work_type == "research_implementation"
                && context_refs == vec!["docs/ARCHITECTURE.md"]
        ));
    }

    #[test]
    fn task_apply_verdict_form_preserves_concurrency_and_verdict_binding() {
        let mut form = CommandForm::new(CommandKind::TaskApplyVerdict);
        for (field, value) in form.fields.iter_mut().zip([
            "task-1".to_owned(),
            "7".to_owned(),
            "2".to_owned(),
            "founder-verdict-1".to_owned(),
        ]) {
            field.value = value;
        }
        let command = form.into_command().expect("valid Task verdict form");
        assert_eq!(command_kind(&command), "task.apply-verdict");
        assert!(matches!(
            command,
            TuiCommand::TaskApplyVerdict {
                task_id,
                expected_revision: 7,
                work_revision: 2,
                founder_verdict_id,
                json: false,
            } if task_id == "task-1" && founder_verdict_id == "founder-verdict-1"
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

    #[test]
    fn memory_form_maps_to_shared_cognition_operation() {
        let mut form = CommandForm::new(CommandKind::MemoryRetrieve);
        for (field, value) in form.fields.iter_mut().zip([
            "governed memory".to_owned(),
            "scope:founder".to_owned(),
            "6".to_owned(),
            "0.25".to_owned(),
        ]) {
            field.value = value;
        }
        let command = form.into_command().expect("valid Memory retrieval form");
        assert_eq!(command_kind(&command), "memory.retrieve");
        assert!(matches!(
            command,
            TuiCommand::MemoryRetrieve {
                query,
                scope,
                max_results: 6,
                min_score,
                json: false,
            } if query == "governed memory"
                && scope == "scope:founder"
                && (min_score - 0.25).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn memory_governance_forms_map_to_shared_mutation_operations() {
        let mut candidate = CommandForm::new(CommandKind::MemoryCandidate);
        for (field, value) in candidate.fields.iter_mut().zip([
            "memory-1".to_owned(),
            "durable fact".to_owned(),
            "source:session-1".to_owned(),
            "scope:founder".to_owned(),
            "idem-candidate-1".to_owned(),
        ]) {
            field.value = value;
        }
        assert_eq!(
            command_kind(&candidate.into_command().expect("valid candidate form")),
            "memory.candidate"
        );

        let mut accept = CommandForm::new(CommandKind::MemoryAccept);
        for (field, value) in accept.fields.iter_mut().zip([
            "memory-1".to_owned(),
            "1".to_owned(),
            "evidence:founder-review-1".to_owned(),
            "idem-accept-1".to_owned(),
        ]) {
            field.value = value;
        }
        assert_eq!(
            command_kind(&accept.into_command().expect("valid accept form")),
            "memory.accept"
        );

        let mut revoke = CommandForm::new(CommandKind::MemoryRevoke);
        for (field, value) in revoke.fields.iter_mut().zip([
            "memory-1".to_owned(),
            "2".to_owned(),
            "evidence:founder-revoke-1".to_owned(),
            "idem-revoke-1".to_owned(),
        ]) {
            field.value = value;
        }
        assert_eq!(
            command_kind(&revoke.into_command().expect("valid revoke form")),
            "memory.revoke"
        );
    }

    #[test]
    fn context_revoke_form_preserves_order_and_requires_modal_confirmation() {
        let mut form = CommandForm::new(CommandKind::ContextRevoke);
        assert!(form.add_context_evidence_entry());
        for (field, value) in form.fields.iter_mut().zip([
            "ctx:abc".to_owned(),
            "7".to_owned(),
            "founder-withdrew-context".to_owned(),
            "evidence:first,with-comma".to_owned(),
            " evidence:second ".to_owned(),
            "proof:founder-review".to_owned(),
            "idem:context-revoke".to_owned(),
        ]) {
            field.value = value;
        }
        let action = form.into_action().expect("valid Context revoke form");
        let InteractiveAction::StageContextRevoke(input) = action else {
            panic!("Context form must stage the modal, never produce a headless command");
        };
        assert_eq!(input.snapshot_id, "ctx:abc");
        assert_eq!(input.expected_state_revision, 7);
        assert_eq!(
            input.evidence_refs,
            ["evidence:first,with-comma", " evidence:second "]
        );
    }

    #[test]
    fn context_revoke_has_no_headless_tui_mutation_subcommand() {
        assert!(Args::try_parse_from(["egopulse-tui", "context-revoke"]).is_err());
    }

    #[test]
    fn context_revoke_form_keyboard_manages_independent_evidence_entries() {
        let mut app = App::new("default".to_owned());
        app.open_form(CommandKind::ContextRevoke);
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL))
            .expect("add evidence entry");
        let InteractiveMode::Form(form) = &app.mode else {
            panic!("Context form should stay open");
        };
        assert_eq!(
            form.fields
                .iter()
                .filter(|field| field.label == "evidence-ref")
                .count(),
            2
        );
        assert_eq!(form.fields[form.active].label, "evidence-ref");

        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL))
            .expect("remove evidence entry");
        let InteractiveMode::Form(form) = &app.mode else {
            panic!("Context form should stay open");
        };
        assert_eq!(
            form.fields
                .iter()
                .filter(|field| field.label == "evidence-ref")
                .count(),
            1
        );
    }

    #[test]
    fn context_revoke_form_redacts_private_governance_references() {
        let mut form = CommandForm::new(CommandKind::ContextRevoke);
        for field in &mut form.fields {
            if matches!(
                field.label,
                "reason-code" | "evidence-ref" | "confirmation-proof-ref"
            ) {
                field.value = format!("private-{}-sentinel", field.label);
                let displayed = form_field_display_value(field);
                assert_eq!(displayed, "<redacted>");
                assert!(!displayed.contains("private-"));
            }
        }
    }

    #[test]
    fn context_revoke_modal_render_buffer_contains_the_complete_digest() {
        let digest = "d".repeat(64);
        let pending = PendingContextRevoke {
            snapshot_id: "ctx:safe-display".to_owned(),
            expected_state_revision: 7,
            evidence_count: 2,
            request_digest_sha256: digest.clone(),
            commit: Box::new(FakeContextRevokeCommit {
                calls: Arc::new(AtomicUsize::new(0)),
                receipt: ContextRevokeReceipt::default(),
            }),
        };
        let backend = ratatui::backend::TestBackend::new(100, 20);
        let mut terminal = ratatui::Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_context_revoke_confirmation(frame, area, &pending);
            })
            .expect("render Context confirmation modal");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains(&digest));
        assert!(!rendered.contains("reason"));
        assert!(!rendered.contains("proof"));
        assert!(!rendered.contains("evidence:first"));
    }

    #[tokio::test]
    async fn context_revoke_modal_uses_one_attached_driver_and_has_zero_or_one_commit() {
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let commit_calls = Arc::new(AtomicUsize::new(0));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client: Arc<dyn InteractiveClient> = Arc::new(FakeInteractiveClient {
            prepare_calls: Arc::clone(&prepare_calls),
            commit_calls: Arc::clone(&commit_calls),
            captured: Arc::clone(&captured),
        });
        let mut app = App::new("unused-test-instance".to_owned());
        app.client = Some(Arc::clone(&client));
        app.open_form(CommandKind::ContextRevoke);
        let InteractiveMode::Form(form) = &mut app.mode else {
            panic!("Context form should be open");
        };
        assert!(form.add_context_evidence_entry());
        for (field, value) in form.fields.iter_mut().zip([
            "ctx:modal".to_owned(),
            "7".to_owned(),
            "private-reason-sentinel".to_owned(),
            "evidence:first,with-comma".to_owned(),
            "evidence:second".to_owned(),
            "private-proof-sentinel".to_owned(),
            "idem:modal".to_owned(),
        ]) {
            field.value = value;
        }
        form.active = form.fields.len() - 1;
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("submit Context form")
            .expect("stage Context action");
        let InteractiveAction::StageContextRevoke(input) = action else {
            panic!("Context form must stage the confirmation modal");
        };

        app.stage_context_revoke(input.clone())
            .await
            .expect("stage Context revoke");
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
        let InteractiveMode::ContextRevokeConfirmation(pending) = &app.mode else {
            panic!("prepared Context revoke must enter the modal");
        };
        let modal_text = context_revoke_confirmation_text(pending).join("\n");
        assert!(modal_text.contains(&"d".repeat(64)));
        assert!(!modal_text.contains("private-reason-sentinel"));
        assert!(!modal_text.contains("private-proof-sentinel"));
        assert!(!modal_text.contains("evidence:first"));

        assert!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .expect("cancel modal")
                .is_none()
        );
        assert!(matches!(app.mode, InteractiveMode::Dashboard));
        assert_eq!(commit_calls.load(Ordering::SeqCst), 0);

        app.stage_context_revoke(input.clone())
            .await
            .expect("restage Context revoke");
        let action = app
            .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("confirm modal")
            .expect("confirmation action");
        assert!(matches!(action, InteractiveAction::ConfirmContextRevoke));
        let receipt = app
            .confirm_context_revoke()
            .await
            .expect("commit confirmed Context revoke");
        assert_eq!(receipt.result_state_revision, 2);
        assert_eq!(commit_calls.load(Ordering::SeqCst), 1);
        assert!(app.confirm_context_revoke().await.is_err());
        assert_eq!(commit_calls.load(Ordering::SeqCst), 1);

        let captured = captured.lock().expect("read captured Context inputs");
        assert_eq!(captured.as_slice(), [input.clone(), input]);
    }

    #[test]
    fn context_errors_keep_action_and_safe_fingerprint() {
        let message = local_error_message(
            egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError {
                code: LocalApiErrorCode::StateRevisionConflict as i32,
                retryable: false,
                required_action_code: Some("RELOAD_CONTEXT_STATE".to_owned()),
                safe_fingerprint: "context-cas-conflict".to_owned(),
                ..Default::default()
            },
        );
        assert!(message.contains("LOCAL_API_ERROR_CODE_STATE_REVISION_CONFLICT"));
        assert!(message.contains("action=RELOAD_CONTEXT_STATE"));
        assert!(message.contains("fingerprint=context-cas-conflict"));
    }

    #[test]
    fn task_watch_page_renders_explicit_live_and_stale_state() {
        let position = GovernedProjectionPosition {
            epoch: "epoch:watch".to_owned(),
            sequence: 14,
        };
        let model = TaskWatchPageModel::from_safe_projection_adapter(
            position.clone(),
            vec![watch_detailed_governed_task("task:render", &position)],
        );
        for width in [70, 120] {
            let backend = ratatui::backend::TestBackend::new(width, 36);
            let mut terminal = ratatui::Terminal::new(backend).expect("create test terminal");
            terminal
                .draw(|frame| render_task_watch(frame, frame.area(), &model))
                .expect("render Task Watch page");
            let rendered = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(rendered.contains("Task Watch"));
            assert!(rendered.contains("task:render"));
            assert!(rendered.contains("TASK_STATUS_ACTIVE"));
            assert!(rendered.contains("RUN_STATUS_RETURNED"));
            assert!(rendered.contains("last_harness_sequence=9"));
            assert!(rendered.contains("checkpoint_reference_recorded=true"));
            assert!(rendered.contains("does not complete the Task"));
            assert!(rendered.contains("Esc"), "rendered={rendered}");
            assert!(rendered.contains("dashboard"), "rendered={rendered}");
            for forbidden in [
                "workspace-canary",
                "provider-canary",
                "dispatch-canary",
                "checkpoint-id-canary",
                "sensitive-integrity-canary",
            ] {
                assert!(!rendered.contains(forbidden), "forbidden={forbidden}");
            }
            assert!(!rendered.contains("TASK_STATUS_COMPLETED"));
        }
    }

    #[tokio::test]
    async fn task_watch_production_action_handler_cleans_up_escape_refetch_quit_and_error() {
        let make_client = |snapshots: VecDeque<Snapshot>, session_count: usize| {
            Arc::new(WatchInteractiveClient {
                snapshots: Arc::new(Mutex::new(snapshots)),
                sessions: Arc::new(Mutex::new(VecDeque::from_iter(
                    (0..session_count).map(|_| VecDeque::from([ScriptedWatchStep::Pending])),
                ))),
                snapshot_calls: Arc::new(AtomicUsize::new(0)),
                open_calls: Arc::new(AtomicUsize::new(0)),
                next_calls: Arc::new(AtomicUsize::new(0)),
            }) as Arc<dyn InteractiveClient>
        };

        let mut escaped = App::new("watch-escape".to_owned());
        escaped.client = Some(make_client(
            VecDeque::from([
                watch_snapshot("task:escape", 1, 60),
                watch_snapshot("task:escape", 1, 61),
            ]),
            1,
        ));
        escaped.start_task_watch().await.unwrap();
        let escape = escaped
            .handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .unwrap()
            .unwrap();
        let mut next_refresh = tokio::time::Instant::now();
        assert_eq!(
            execute_interactive_action(&mut escaped, escape, &mut next_refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Continue
        );
        assert!(matches!(escaped.mode, InteractiveMode::Dashboard));
        assert!(escaped.task_watch.is_none());
        assert_eq!(
            escaped.snapshot.as_ref().unwrap().position,
            "epoch:watch:61"
        );

        let mut refetched = App::new("watch-refetch".to_owned());
        refetched.client = Some(make_client(
            VecDeque::from([
                watch_snapshot("task:refetch", 1, 70),
                watch_snapshot("task:refetch", 2, 71),
            ]),
            2,
        ));
        refetched.start_task_watch().await.unwrap();
        let refetch = refetched
            .handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
            .unwrap()
            .unwrap();
        assert_eq!(
            execute_interactive_action(&mut refetched, refetch, &mut next_refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Continue
        );
        assert!(matches!(refetched.mode, InteractiveMode::TaskWatch));
        assert_eq!(
            refetched
                .task_watch
                .as_ref()
                .and_then(TaskWatchController::model)
                .map(|model| model.position.sequence),
            Some(71)
        );

        let quit = refetched
            .handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE))
            .unwrap()
            .unwrap();
        assert_eq!(
            execute_interactive_action(&mut refetched, quit, &mut next_refresh)
                .await
                .unwrap(),
            InteractiveLoopControl::Quit
        );
        assert!(refetched.task_watch.is_none());

        let mut failed = App::new("watch-error".to_owned());
        failed.client = Some(make_client(
            VecDeque::from([watch_snapshot("task:error", 1, 80)]),
            1,
        ));
        failed.start_task_watch().await.unwrap();
        let result = finish_interactive_session(&mut failed, Err::<(), _>("boom".to_owned())).await;
        assert_eq!(result.unwrap_err(), "boom");
        assert!(failed.task_watch.is_none());
    }

    #[tokio::test]
    async fn task_watch_failure_handler_never_mutates_the_dashboard_snapshot() {
        let dashboard = watch_snapshot("task:dashboard-authority-fact", 9, 79);
        let client = Arc::new(WatchInteractiveClient {
            snapshots: Arc::new(Mutex::new(VecDeque::from([watch_snapshot(
                "task:watch-baseline",
                1,
                80,
            )]))),
            sessions: Arc::new(Mutex::new(VecDeque::from([VecDeque::from([
                ScriptedWatchStep::Pending,
            ])]))),
            snapshot_calls: Arc::new(AtomicUsize::new(0)),
            open_calls: Arc::new(AtomicUsize::new(0)),
            next_calls: Arc::new(AtomicUsize::new(0)),
        });
        let mut app = App::new("watch-failure-snapshot".to_owned());
        app.snapshot = Some(dashboard.clone());
        app.client = Some(client as Arc<dyn InteractiveClient>);
        app.start_task_watch().await.unwrap();

        app.handle_task_watch_failure("projection integrity failure".to_owned())
            .await;

        let after = app.snapshot.as_ref().expect("dashboard snapshot retained");
        assert_eq!(after.health, dashboard.health);
        assert_eq!(after.stale, dashboard.stale);
        assert_eq!(after.position, dashboard.position);
        assert_eq!(after.tasks, dashboard.tasks);
        assert_eq!(after.approvals, dashboard.approvals);
        assert!(app.task_watch.is_none());
        assert!(app.message.contains("stopped fail-closed"));
    }

    #[test]
    fn task_watch_reconnect_schedule_and_page_keys_are_frozen() {
        assert_eq!(
            egopulse_tui::task_watch::TASK_WATCH_RECONNECT_DELAYS,
            [
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_millis(1_000),
                Duration::from_millis(2_000),
                Duration::from_millis(2_000),
            ]
        );
        let mut app = App::new("watch-keys".to_owned());
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE))
                .unwrap(),
            Some(InteractiveAction::OpenTaskWatch)
        ));
        app.mode = InteractiveMode::TaskWatch;
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
                .unwrap(),
            Some(InteractiveAction::CloseTaskWatch)
        ));
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE))
                .unwrap(),
            Some(InteractiveAction::RefetchTaskWatch)
        ));
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE))
                .unwrap(),
            Some(InteractiveAction::Quit)
        ));
        assert!(
            app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE))
                .unwrap()
                .is_none()
        );
        assert!(
            app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn dashboard_discovers_both_watch_pages_and_projection_warning_prevents_blind_retry() {
        let app = App::new("approval-feedback".to_owned());
        let footer = app.footer_text();
        assert!(footer.contains("w task watch"));
        assert!(footer.contains("a approval queue"));
        assert!(footer.contains("n new work"));

        assert_eq!(
            approval_decision_feedback(7, false, false),
            "Approval committed at revision 7 (replayed=false)"
        );
        let warning = approval_decision_feedback(8, false, true);
        assert!(warning.contains("Authority committed the approval at revision 8"));
        assert!(warning.contains("projection synchronization reported a warning"));
        assert!(warning.contains("Do not retry the decision"));
        assert!(warning.contains("refresh the queue instead"));
    }

    #[test]
    fn work_start_keyboard_intents_preserve_linear_and_unknown_boundaries() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut app = App::new("work-start-keys".to_owned());
        assert!(matches!(
            app.handle_key(key(KeyCode::Char('n'))).unwrap(),
            Some(InteractiveAction::OpenWorkStart)
        ));
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::Tab)),
            WorkStartKeyIntent::NextField
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::BackTab)),
            WorkStartKeyIntent::PreviousField
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::Char('x'))),
            WorkStartKeyIntent::Push('x')
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::Backspace)),
            WorkStartKeyIntent::Backspace
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::Esc)),
            WorkStartKeyIntent::Close
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Editing, key(KeyCode::Enter)),
            WorkStartKeyIntent::Prepare
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Preparing, key(KeyCode::Esc)),
            WorkStartKeyIntent::WaitForPreparation
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::PreviewReady, key(KeyCode::Enter)),
            WorkStartKeyIntent::Confirm
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::PreviewReady, key(KeyCode::Esc)),
            WorkStartKeyIntent::CancelPreview
        );
        assert_eq!(
            work_start_key_intent(
                WorkStartStage::PreparationOutcomeUnknown,
                key(KeyCode::Enter)
            ),
            WorkStartKeyIntent::ReplayPreparation
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::PreparationOutcomeUnknown, key(KeyCode::Esc)),
            WorkStartKeyIntent::KeepPreparationRecovery
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Confirming, key(KeyCode::Enter)),
            WorkStartKeyIntent::Ignore
        );
        assert_eq!(
            work_start_key_intent(WorkStartStage::Confirming, key(KeyCode::Esc)),
            WorkStartKeyIntent::ConfirmationCannotCancel
        );
        assert_eq!(
            work_start_key_intent(
                WorkStartStage::ConfirmationOutcomeUnknown,
                key(KeyCode::Enter)
            ),
            WorkStartKeyIntent::ReplayConfirmation
        );
        assert_eq!(
            work_start_key_intent(
                WorkStartStage::ConfirmationOutcomeUnknown,
                key(KeyCode::Char('w'))
            ),
            WorkStartKeyIntent::ReconcileInTaskWatch
        );
        for stage in [
            WorkStartStage::Preparing,
            WorkStartStage::PreviewReady,
            WorkStartStage::PreparationOutcomeUnknown,
            WorkStartStage::Confirming,
            WorkStartStage::ConfirmationOutcomeUnknown,
        ] {
            assert_eq!(
                work_start_key_intent(stage, key(KeyCode::Char('q'))),
                WorkStartKeyIntent::Quit
            );
        }
        assert_eq!(
            work_start_exit_policy(WorkStartStage::Preparing, true),
            WorkStartExitPolicy::AwaitSettlement
        );
        assert_eq!(
            work_start_exit_policy(WorkStartStage::Confirming, true),
            WorkStartExitPolicy::AwaitSettlement
        );
        assert_eq!(
            work_start_exit_policy(WorkStartStage::PreviewReady, false),
            WorkStartExitPolicy::CancelPreview
        );
        assert_eq!(
            work_start_exit_policy(WorkStartStage::PreparationOutcomeUnknown, false),
            WorkStartExitPolicy::PreserveRecovery
        );
        assert_eq!(
            work_start_exit_policy(WorkStartStage::ConfirmationOutcomeUnknown, false),
            WorkStartExitPolicy::PreserveRecovery
        );
    }

    #[tokio::test]
    async fn work_start_key_and_execute_seam_never_duplicates_mutations() {
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let escape = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);

        let mut blocked = CountingWorkStartMutationTarget::new(WorkStartStage::PreviewReady, false);
        assert_eq!(
            work_start_key_intent(blocked.stage, enter),
            WorkStartKeyIntent::Confirm
        );
        assert!(
            execute_work_start_mutation(&mut blocked, WorkStartMutationAction::Confirm)
                .await
                .is_err()
        );
        assert_eq!(blocked.confirm_calls, 0);

        let mut confirmation =
            CountingWorkStartMutationTarget::new(WorkStartStage::PreviewReady, true);
        execute_work_start_mutation(&mut confirmation, WorkStartMutationAction::Confirm)
            .await
            .unwrap();
        assert_eq!(confirmation.confirm_calls, 1);
        assert_eq!(
            work_start_key_intent(confirmation.stage, enter),
            WorkStartKeyIntent::Ignore
        );
        assert_eq!(confirmation.confirm_calls, 1);

        let pending = CountingWorkStartMutationTarget::new(WorkStartStage::Preparing, true);
        assert_eq!(
            work_start_key_intent(pending.stage, escape),
            WorkStartKeyIntent::WaitForPreparation
        );
        assert_eq!(pending.prepare_calls, 0);
        assert_eq!(pending.replay_preparation_calls, 0);

        let mut preparation_unknown =
            CountingWorkStartMutationTarget::new(WorkStartStage::PreparationOutcomeUnknown, true);
        assert_eq!(
            work_start_key_intent(preparation_unknown.stage, enter),
            WorkStartKeyIntent::ReplayPreparation
        );
        execute_work_start_mutation(
            &mut preparation_unknown,
            WorkStartMutationAction::ReplayPreparation,
        )
        .await
        .unwrap();
        assert_eq!(preparation_unknown.replay_preparation_calls, 1);
        assert_eq!(
            work_start_key_intent(preparation_unknown.stage, enter),
            WorkStartKeyIntent::Ignore
        );
        assert_eq!(preparation_unknown.replay_preparation_calls, 1);

        let mut confirmation_unknown =
            CountingWorkStartMutationTarget::new(WorkStartStage::ConfirmationOutcomeUnknown, true);
        execute_work_start_mutation(
            &mut confirmation_unknown,
            WorkStartMutationAction::ReplayConfirmation,
        )
        .await
        .unwrap();
        assert_eq!(confirmation_unknown.replay_confirmation_calls, 1);
        assert_eq!(
            work_start_key_intent(confirmation_unknown.stage, enter),
            WorkStartKeyIntent::Ignore
        );
        assert_eq!(confirmation_unknown.replay_confirmation_calls, 1);
    }

    #[tokio::test]
    async fn confirmed_task_projection_lag_blocks_wrong_review_and_keeps_exact_selection() {
        let unrelated = Arc::new(tokio::sync::Notify::new());
        let reset = Arc::new(tokio::sync::Notify::new());
        let target = Arc::new(tokio::sync::Notify::new());
        let typed_client = Arc::new(WatchInteractiveClient {
            snapshots: Arc::new(Mutex::new(VecDeque::from([
                watch_snapshot("task:other", 1, 90),
                watch_snapshot("task:other", 2, 91),
            ]))),
            sessions: Arc::new(Mutex::new(VecDeque::from([
                VecDeque::from([
                    ScriptedWatchStep::WaitUpdate(
                        Arc::clone(&unrelated),
                        Box::new(watch_governed_update(
                            egopulse_client_operations::TaskWatchClassification::Applied,
                            Some("task:unrelated"),
                            91,
                        )),
                    ),
                    ScriptedWatchStep::WaitUpdate(
                        Arc::clone(&reset),
                        Box::new(watch_governed_update(
                            egopulse_client_operations::TaskWatchClassification::ResetRequired,
                            None,
                            91,
                        )),
                    ),
                ]),
                VecDeque::from([
                    ScriptedWatchStep::WaitUpdate(
                        Arc::clone(&target),
                        Box::new(watch_governed_update(
                            egopulse_client_operations::TaskWatchClassification::Applied,
                            Some("task:confirmed"),
                            92,
                        )),
                    ),
                    ScriptedWatchStep::Pending,
                ]),
            ]))),
            snapshot_calls: Arc::new(AtomicUsize::new(0)),
            open_calls: Arc::new(AtomicUsize::new(0)),
            next_calls: Arc::new(AtomicUsize::new(0)),
        });
        let client = Arc::clone(&typed_client) as Arc<dyn InteractiveClient>;
        let mut app = App::new("work-projection-lag".to_owned());
        app.client = Some(client);
        app.pending_task_watch_selection = Some("task:confirmed".to_owned());
        app.start_task_watch().await.unwrap();

        assert_eq!(
            app.task_watch
                .as_ref()
                .and_then(TaskWatchController::model)
                .and_then(|model| model.selected_task_id.as_deref()),
            None
        );
        assert_eq!(
            app.pending_task_watch_selection.as_deref(),
            Some("task:confirmed")
        );
        assert!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .is_none()
        );
        assert!(app.message.contains("exact projection has not arrived"));
        assert_ne!(
            app.task_watch.as_ref().unwrap().model().unwrap().tasks[0].status,
            TaskStatus::Completed
        );

        unrelated.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.apply_task_watch_events().await.unwrap();
                if app
                    .task_watch
                    .as_ref()
                    .unwrap()
                    .model()
                    .unwrap()
                    .position
                    .sequence
                    == 91
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            app.task_watch
                .as_ref()
                .unwrap()
                .model()
                .unwrap()
                .selected_task_id,
            None,
            "an unrelated Applied update cannot consume the confirmed Task target"
        );

        reset.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.apply_task_watch_events().await.unwrap();
                if typed_client.snapshot_calls.load(Ordering::SeqCst) >= 2
                    && typed_client.open_calls.load(Ordering::SeqCst) >= 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            app.task_watch
                .as_ref()
                .unwrap()
                .model()
                .unwrap()
                .selected_task_id,
            None,
            "reset/rebaseline cannot select a different Task while the exact target is pending"
        );

        target.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                app.apply_task_watch_events().await.unwrap();
                if app.pending_task_watch_selection.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(app.pending_task_watch_selection.is_none());
        assert_eq!(
            app.task_watch
                .as_ref()
                .and_then(TaskWatchController::model)
                .and_then(|model| model.selected_task_id.as_deref()),
            Some("task:confirmed")
        );
        app.stop_task_watch().await;
    }

    #[test]
    fn task_render_reads_collaboration_status_from_the_same_task_view() {
        let view = TaskView {
            collaboration: Some(
                egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationSnapshot {
                    run: Some(
                        egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot {
                            status: RunStatus::Returned as i32,
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        assert_eq!(
            view.collaboration
                .as_ref()
                .and_then(|value| value.run.as_ref())
                .and_then(|value| RunStatus::try_from(value.status).ok())
                .expect("run")
                .as_str_name(),
            "RUN_STATUS_RETURNED"
        );
    }
}
