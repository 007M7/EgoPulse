#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    time::SystemTime,
};

use egopulse_client_kernel::{ClientKernel, KernelError, SnapshotStreamTracker, StreamApply};
use egopulse_domain_contracts::{
    context_revoke::ContextRevokeSemanticRequest,
    v01::egopulse::{
        common::v1::CommandMetadata,
        harness::v1::ApprovalDecision,
        localapi::v1::{
            AvailableActionKind, ClientRequestMetadata, ClientSurface, ConfirmWorkRequest,
            ConfirmWorkResponse, ContextGovernanceState, ContextMutationCommand,
            ContextRevokeReceipt, DecideHarnessApprovalRequest, DecideHarnessApprovalResponse,
            ExecuteContextMutationRequest, ExecuteContextMutationResponse,
            GetHarnessApprovalViewRequest, GetHarnessApprovalViewResponse,
            GetProjectionStatusRequest, HarnessApprovalAuthorityResult, HarnessApprovalView,
            HarnessApprovalViewStreamFrame, ListHarnessApprovalViewsRequest,
            ListHarnessApprovalViewsResponse, ListTaskViewsRequest, LocalApiError,
            PrepareWorkRequest, ProjectionAwaitToken, ProjectionMetadata, ProjectionPosition,
            RevokeContextSnapshotCommand, StreamFrameKind, TaskView, TaskViewStreamFrame,
            WatchHarnessApprovalViewsRequest, WatchTaskViewsRequest, WorkPreparationPreview,
            WorkSourceRequest, context_mutation_command, execute_context_mutation_response,
            get_harness_approval_view_response,
        },
        policy::v1::{
            HarnessApprovalDecisionStateKind, IssueHarnessApprovalDecisionCommand,
            PolicyDecisionCommand, PolicyDecisionErrorCode, policy_decision_command,
        },
        task::v1::{TaskCommand, task_command},
        verdict::v1::{VerdictCommand, verdict_command},
    },
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const EXECUTE_CONTEXT_MUTATION_RPC: &str = "LocalCommandGatewayService/ExecuteContextMutation";
const REVOKE_CONTEXT_SNAPSHOT_COMMAND: &str = "revoke_context_snapshot";
const CONTEXT_REVOKE_IDEMPOTENCY_SCOPE: &str = "context-revoke";
const WATCH_TASK_VIEWS_RPC: &str = "LocalReadModelService/WatchTaskViews";
const LIST_HARNESS_APPROVAL_VIEWS_RPC: &str = "LocalReadModelService/ListHarnessApprovalViews";
const WATCH_HARNESS_APPROVAL_VIEWS_RPC: &str = "LocalReadModelService/WatchHarnessApprovalViews";
const GET_HARNESS_APPROVAL_VIEW_RPC: &str = "LocalReadModelService/GetHarnessApprovalView";
const DECIDE_HARNESS_APPROVAL_RPC: &str = "LocalCommandGatewayService/DecideHarnessApproval";
const ISSUE_HARNESS_APPROVAL_DECISION_COMMAND: &str = "issue_harness_approval_decision";
const APPROVAL_DECISION_IDEMPOTENCY_SCOPE: &str = "approval-decision";
const GUIDED_APPROVAL_IDEMPOTENCY_DOMAIN: &[u8] = b"egopulse/guided-approval/v1\0";
const APPROVAL_WATCH_BASELINE_PAGE_SIZE: u32 = 100;
const APPROVAL_WATCH_BASELINE_MAX_PAGES: usize = 100;
const APPROVAL_WATCH_BASELINE_MAX_VIEWS: usize = 1_000;

/// A local client that has completed the frozen session and contract handshake.
///
/// Surfaces own presentation and error policy; they do not own a second attach
/// protocol. All writes made from CLI, TUI, and Desktop start from this object.
pub struct ClientAttachment {
    pub connection: LocalApiConnection,
    pub kernel: ClientKernel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuidedApprovalDecision {
    AllowOnce,
    Deny,
    CancelAttempt,
}

impl GuidedApprovalDecision {
    fn wire_value(self) -> i32 {
        match self {
            Self::AllowOnce => ApprovalDecision::AllowOnce as i32,
            Self::Deny => ApprovalDecision::Deny as i32,
            Self::CancelAttempt => ApprovalDecision::CancelAttempt as i32,
        }
    }

    #[must_use]
    pub fn contract_name(self) -> &'static str {
        match self {
            Self::AllowOnce => "APPROVAL_DECISION_ALLOW_ONCE",
            Self::Deny => "APPROVAL_DECISION_DENY",
            Self::CancelAttempt => "APPROVAL_DECISION_CANCEL_ATTEMPT",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidedApprovalDecisionInput {
    pub approval_request_id: String,
    pub decision: GuidedApprovalDecision,
    pub reason_code: String,
    pub confirmation_proof_ref: Option<String>,
}

#[derive(Debug, Error)]
pub enum ClientGuidedApprovalDecisionError {
    #[error("client kernel rejected the guided approval decision: {0}")]
    Kernel(#[from] KernelError),
    #[error("guided approval decision input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("the requested Harness approval was not found")]
    NotFound,
    #[error("the latest Harness approval is not actionable")]
    NonActionable,
    #[error("local API guided approval transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the guided approval decision: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("Policy Decision Authority rejected the guided approval decision")]
    Authority {
        error_code: i32,
        safe_error_fingerprint: Option<String>,
    },
    #[error("guided approval protocol integrity failed: {0}")]
    Protocol(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidedApprovalDecisionResult {
    authority: HarnessApprovalAuthorityResult,
    await_token: Option<ProjectionAwaitToken>,
    projection_warning: Option<LocalApiError>,
    correlation_id: String,
}

impl GuidedApprovalDecisionResult {
    #[must_use]
    pub fn committed(&self) -> bool {
        self.authority.committed
    }

    #[must_use]
    pub fn replayed(&self) -> bool {
        self.authority.replayed
    }

    #[must_use]
    pub fn authority_decision_ref(&self) -> &str {
        &self.authority.authority_decision_ref
    }

    #[must_use]
    pub fn decision(&self) -> GuidedApprovalDecision {
        match ApprovalDecision::try_from(self.authority.decision)
            .expect("validated guided approval decision")
        {
            ApprovalDecision::AllowOnce => GuidedApprovalDecision::AllowOnce,
            ApprovalDecision::Deny => GuidedApprovalDecision::Deny,
            ApprovalDecision::CancelAttempt => GuidedApprovalDecision::CancelAttempt,
            ApprovalDecision::Unspecified => unreachable!("validated guided approval decision"),
        }
    }

    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.authority.state_revision
    }

    #[must_use]
    pub fn await_token(&self) -> Option<&ProjectionAwaitToken> {
        self.await_token.as_ref()
    }

    #[must_use]
    pub fn projection_warning(&self) -> Option<&LocalApiError> {
        self.projection_warning.as_ref()
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

#[derive(Clone, Debug)]
pub struct ProjectionSnapshot {
    pub metadata: ProjectionMetadata,
    pub tasks: Vec<TaskView>,
    pub approvals: Vec<HarnessApprovalView>,
}

#[derive(Debug, Error)]
pub enum ClientReadError {
    #[error("client kernel rejected the read: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the read: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned an incomplete response: {0}")]
    Protocol(&'static str),
}

#[derive(Debug, Error)]
pub enum ClientTaskWatchError {
    #[error("client kernel rejected the Task watch: {0}")]
    Kernel(#[from] KernelError),
    #[error("Task watch resume epoch and sequence must be supplied together")]
    InvalidResumePair,
    #[error("local API Task watch transport failed: {0}")]
    Transport(String),
    #[error("Task watch reached a reset barrier and requires projection refetch")]
    ResetBarrier,
    #[error("Task watch ended after {received} frames before the requested {expected}")]
    PrematureEof { expected: u32, received: u32 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskWatchRequest {
    pub resume_epoch: Option<String>,
    pub resume_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskWatchClassification {
    Applied,
    Replay,
    Heartbeat,
    ResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskWatchFrameKind {
    Snapshot,
    Heartbeat,
    ResetRequired,
}

impl TaskWatchFrameKind {
    #[must_use]
    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::Snapshot => "STREAM_FRAME_KIND_SNAPSHOT",
            Self::Heartbeat => "STREAM_FRAME_KIND_HEARTBEAT",
            Self::ResetRequired => "STREAM_FRAME_KIND_RESET_REQUIRED",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskWatchUpdate {
    pub classification: TaskWatchClassification,
    pub kind: TaskWatchFrameKind,
    pub position: ProjectionPosition,
    pub view: Option<TaskView>,
    pub reset_reason_code: Option<String>,
}

#[derive(Default)]
struct TaskWatchProcessor {
    tracker: SnapshotStreamTracker,
    reset_barrier: bool,
}

impl TaskWatchProcessor {
    fn process(
        &mut self,
        frame: TaskViewStreamFrame,
    ) -> Result<TaskWatchUpdate, ClientTaskWatchError> {
        if self.reset_barrier {
            return Err(ClientTaskWatchError::ResetBarrier);
        }
        let frame_kind = StreamFrameKind::try_from(frame.kind)
            .map_err(|_| ClientTaskWatchError::Kernel(KernelError::UnknownStreamFrame))?;
        match frame_kind {
            StreamFrameKind::Snapshot | StreamFrameKind::Heartbeat
                if frame.reset_reason_code.is_some() =>
            {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            StreamFrameKind::ResetRequired
                if frame.reset_reason_code.as_deref().is_none_or(|reason| {
                    reason.is_empty()
                        || reason.len() > 128
                        || !reason.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'_' | b':' | b'-')
                        })
                }) =>
            {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            _ => {}
        }
        let applied = self.tracker.apply_task_frame(&frame)?;
        let kind = match frame_kind {
            StreamFrameKind::Snapshot => TaskWatchFrameKind::Snapshot,
            StreamFrameKind::Heartbeat => TaskWatchFrameKind::Heartbeat,
            StreamFrameKind::ResetRequired => TaskWatchFrameKind::ResetRequired,
            StreamFrameKind::Unspecified => {
                return Err(ClientTaskWatchError::Kernel(
                    KernelError::UnknownStreamFrame,
                ));
            }
        };
        let classification = match applied {
            StreamApply::Applied => TaskWatchClassification::Applied,
            StreamApply::Replay => TaskWatchClassification::Replay,
            StreamApply::Heartbeat => TaskWatchClassification::Heartbeat,
            StreamApply::ResetRequired => {
                self.reset_barrier = true;
                TaskWatchClassification::ResetRequired
            }
        };
        let position = frame.position.ok_or(ClientTaskWatchError::Kernel(
            KernelError::StreamPositionInvalid,
        ))?;
        Ok(TaskWatchUpdate {
            classification,
            kind,
            position,
            view: frame.snapshot,
            reset_reason_code: frame.reset_reason_code,
        })
    }
}

/// An attached Task projection watch. The tonic stream and stream tracker are
/// private to the shared operation so CLI/TUI surfaces cannot bypass replay or
/// reset-barrier validation.
pub struct TaskWatch {
    stream: tonic::Streaming<TaskViewStreamFrame>,
    processor: TaskWatchProcessor,
}

#[derive(Debug, Error)]
pub enum ClientApprovalWatchError {
    #[error("client kernel rejected the approval watch: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API approval watch transport failed: {0}")]
    Transport(String),
    #[error("local API approval watch ended unexpectedly")]
    UnexpectedEof,
    #[error("local API rejected the approval baseline: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("approval baseline exceeded the 1000 item integrity limit")]
    BaselineLimitExceeded,
    #[error("approval watch protocol integrity failed: {0}")]
    Protocol(&'static str),
    #[error("approval watch reached a reset barrier and requires baseline refetch")]
    ResetBarrier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalWatchCursor {
    pub epoch: String,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWatchClassification {
    Applied,
    Replay,
    Heartbeat,
    ResetRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWatchFrameKind {
    Snapshot,
    Heartbeat,
    ResetRequired,
}

impl ApprovalWatchFrameKind {
    #[must_use]
    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::Snapshot => "STREAM_FRAME_KIND_SNAPSHOT",
            Self::Heartbeat => "STREAM_FRAME_KIND_HEARTBEAT",
            Self::ResetRequired => "STREAM_FRAME_KIND_RESET_REQUIRED",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalWatchUpdate {
    pub classification: ApprovalWatchClassification,
    pub kind: ApprovalWatchFrameKind,
    pub position: ProjectionPosition,
    pub view: Option<HarnessApprovalView>,
    pub reset_reason_code: Option<String>,
}

/// One daemon-authored approval that is currently actionable. Construction is
/// private so presentation surfaces cannot forge the decision binding.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionableApproval {
    view: HarnessApprovalView,
}

impl ActionableApproval {
    #[must_use]
    pub fn view(&self) -> &HarnessApprovalView {
        &self.view
    }

    #[must_use]
    pub fn approval_request_id(&self) -> &str {
        &self.view.approval_request_id
    }

    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.view.task_id
    }

    #[must_use]
    pub fn action_digest_sha256(&self) -> &str {
        &self.view.action_digest_sha256
    }

    #[must_use]
    pub fn request_observation_id(&self) -> &str {
        &self.view.request_observation_id
    }

    #[must_use]
    pub const fn request_observation_sequence(&self) -> u64 {
        self.view.request_observation_sequence
    }

    #[must_use]
    pub const fn request_revision(&self) -> u64 {
        self.view.request_revision
    }
}

#[derive(Default)]
struct ApprovalWatchProcessor {
    tracker: SnapshotStreamTracker,
    reset_barrier: bool,
}

impl ApprovalWatchProcessor {
    fn process(
        &mut self,
        frame: HarnessApprovalViewStreamFrame,
    ) -> Result<ApprovalWatchUpdate, ClientApprovalWatchError> {
        if self.reset_barrier {
            return Err(ClientApprovalWatchError::ResetBarrier);
        }
        let frame_kind = StreamFrameKind::try_from(frame.kind)
            .map_err(|_| ClientApprovalWatchError::Kernel(KernelError::UnknownStreamFrame))?;
        match frame_kind {
            StreamFrameKind::Snapshot | StreamFrameKind::Heartbeat
                if frame.reset_reason_code.is_some() =>
            {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            StreamFrameKind::ResetRequired
                if frame.reset_reason_code.as_deref().is_none_or(|reason| {
                    reason.is_empty()
                        || reason.len() > 128
                        || !reason.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'_' | b':' | b'-')
                        })
                }) =>
            {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::IncompleteStreamFrame,
                ));
            }
            _ => {}
        }
        let applied = self.tracker.apply_harness_approval_frame(&frame)?;
        let kind = match frame_kind {
            StreamFrameKind::Snapshot => ApprovalWatchFrameKind::Snapshot,
            StreamFrameKind::Heartbeat => ApprovalWatchFrameKind::Heartbeat,
            StreamFrameKind::ResetRequired => ApprovalWatchFrameKind::ResetRequired,
            StreamFrameKind::Unspecified => {
                return Err(ClientApprovalWatchError::Kernel(
                    KernelError::UnknownStreamFrame,
                ));
            }
        };
        let classification = match applied {
            StreamApply::Applied => ApprovalWatchClassification::Applied,
            StreamApply::Replay => ApprovalWatchClassification::Replay,
            StreamApply::Heartbeat => ApprovalWatchClassification::Heartbeat,
            StreamApply::ResetRequired => {
                self.reset_barrier = true;
                ApprovalWatchClassification::ResetRequired
            }
        };
        Ok(ApprovalWatchUpdate {
            classification,
            kind,
            position: frame.position.ok_or(ClientApprovalWatchError::Kernel(
                KernelError::StreamPositionInvalid,
            ))?,
            view: frame.snapshot,
            reset_reason_code: frame.reset_reason_code,
        })
    }
}

/// A stream-only approval watch. It classifies frames but never claims or
/// mutates a complete actionable queue.
pub struct ApprovalWatch {
    stream: tonic::Streaming<HarnessApprovalViewStreamFrame>,
    processor: ApprovalWatchProcessor,
}

/// A complete actionable queue snapshot. Its position and contents are
/// private and it is consumed when opening the corresponding live session.
pub struct ApprovalQueueBaseline {
    actionable: BTreeMap<String, ActionableApproval>,
    position: ProjectionPosition,
}

impl ApprovalQueueBaseline {
    #[must_use]
    pub fn position(&self) -> &ProjectionPosition {
        &self.position
    }

    #[must_use]
    pub fn actionable_approvals(&self) -> Vec<&ActionableApproval> {
        self.actionable.values().collect()
    }
}

/// A complete baseline plus updates that started at exactly that baseline's
/// private position.
pub struct ApprovalQueueSession {
    watch: ApprovalWatch,
    actionable: BTreeMap<String, ActionableApproval>,
    last_position: ProjectionPosition,
}

impl ApprovalWatch {
    pub async fn next_update(
        &mut self,
    ) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError> {
        let Self { stream, processor } = self;
        next_approval_watch_frame_via(processor, || async {
            stream.message().await.map_err(|error| error.to_string())
        })
        .await
    }
}

impl ApprovalQueueSession {
    #[must_use]
    pub fn actionable_approvals(&self) -> Vec<&ActionableApproval> {
        self.actionable.values().collect()
    }

    pub async fn next_update(
        &mut self,
    ) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError> {
        let update = self.watch.next_update().await?;
        if let Some(update) = &update
            && let Err(error) = apply_approval_queue_session_update(
                &mut self.actionable,
                &mut self.last_position,
                update,
            )
        {
            self.watch.processor.reset_barrier = true;
            return Err(error);
        }
        Ok(update)
    }
}

fn apply_approval_queue_session_update(
    actionable: &mut BTreeMap<String, ActionableApproval>,
    last_position: &mut ProjectionPosition,
    update: &ApprovalWatchUpdate,
) -> Result<(), ClientApprovalWatchError> {
    if update.classification != ApprovalWatchClassification::ResetRequired
        && update.position.epoch != last_position.epoch
    {
        return Err(ClientApprovalWatchError::Kernel(
            KernelError::StreamResetMissing,
        ));
    }
    if update.classification == ApprovalWatchClassification::ResetRequired {
        return Ok(());
    }
    if update.position.sequence < last_position.sequence {
        return Err(ClientApprovalWatchError::Kernel(
            KernelError::StreamOutOfOrder,
        ));
    }
    if update.position.sequence == last_position.sequence {
        return match update.classification {
            ApprovalWatchClassification::Applied => apply_approval_watch_update(actionable, update),
            ApprovalWatchClassification::Replay | ApprovalWatchClassification::Heartbeat => Ok(()),
            ApprovalWatchClassification::ResetRequired => unreachable!("handled above"),
        };
    }
    apply_approval_watch_update(actionable, update)?;
    *last_position = update.position.clone();
    Ok(())
}

async fn next_approval_watch_frame_via<F, Fut>(
    processor: &mut ApprovalWatchProcessor,
    next_message: F,
) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<HarnessApprovalViewStreamFrame>, String>>,
{
    if processor.reset_barrier {
        return Err(ClientApprovalWatchError::ResetBarrier);
    }
    let Some(frame) = next_message()
        .await
        .map_err(ClientApprovalWatchError::Transport)?
    else {
        return Err(ClientApprovalWatchError::UnexpectedEof);
    };
    processor.process(frame).map(Some)
}

#[cfg(test)]
async fn next_approval_queue_update_via<F, Fut>(
    processor: &mut ApprovalWatchProcessor,
    actionable: &mut BTreeMap<String, ActionableApproval>,
    next_message: F,
) -> Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<HarnessApprovalViewStreamFrame>, String>>,
{
    let update = next_approval_watch_frame_via(processor, next_message).await?;
    if let Some(update) = &update {
        apply_approval_watch_update(actionable, update)?;
    }
    Ok(update)
}

fn is_actionable_approval(view: &HarnessApprovalView) -> Result<bool, ClientApprovalWatchError> {
    let mut actionable = false;
    for action in &view.available_actions {
        let kind = AvailableActionKind::try_from(action.kind)
            .map_err(|_| ClientApprovalWatchError::Protocol("approval action kind is unknown"))?;
        if kind == AvailableActionKind::Unspecified {
            return Err(ClientApprovalWatchError::Protocol(
                "approval action kind is unspecified",
            ));
        }
        actionable |= kind == AvailableActionKind::DecideHarnessApproval;
    }
    Ok(actionable)
}

fn apply_approval_watch_update(
    actionable: &mut BTreeMap<String, ActionableApproval>,
    update: &ApprovalWatchUpdate,
) -> Result<(), ClientApprovalWatchError> {
    if update.classification != ApprovalWatchClassification::Applied {
        return Ok(());
    }
    let view = update
        .view
        .as_ref()
        .ok_or(ClientApprovalWatchError::Protocol(
            "applied approval frame missing view",
        ))?;
    if view.approval_request_id.is_empty() {
        return Err(ClientApprovalWatchError::Protocol(
            "approval request id missing",
        ));
    }
    if is_actionable_approval(view)? {
        actionable.insert(
            view.approval_request_id.clone(),
            ActionableApproval { view: view.clone() },
        );
    } else {
        actionable.remove(&view.approval_request_id);
    }
    Ok(())
}

impl TaskWatch {
    pub async fn next_update(&mut self) -> Result<Option<TaskWatchUpdate>, ClientTaskWatchError> {
        let Self { stream, processor } = self;
        next_task_watch_update_via(processor, || async {
            stream.message().await.map_err(|error| error.to_string())
        })
        .await
    }
}

async fn next_task_watch_update_via<F, Fut>(
    processor: &mut TaskWatchProcessor,
    next_message: F,
) -> Result<Option<TaskWatchUpdate>, ClientTaskWatchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Option<TaskViewStreamFrame>, String>>,
{
    if processor.reset_barrier {
        return Err(ClientTaskWatchError::ResetBarrier);
    }
    let Some(frame) = next_message()
        .await
        .map_err(ClientTaskWatchError::Transport)?
    else {
        return Ok(None);
    };
    processor.process(frame).map(Some)
}

#[derive(Debug, Error)]
pub enum ClientWorkError {
    #[error("client kernel rejected the work operation: {0}")]
    Kernel(#[from] KernelError),
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the work operation: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned an incomplete work response: {0}")]
    Protocol(&'static str),
}

#[derive(Debug, Error)]
pub enum ClientContextRevokeError {
    #[error("client kernel rejected the Context revoke: {0}")]
    Kernel(#[from] KernelError),
    #[error("Context revoke confirmation digest is invalid")]
    InvalidConfirmation,
    #[error("authenticated Context revoke session changed after preparation")]
    SessionChanged,
    #[error("local API transport failed: {0}")]
    Transport(String),
    #[error("local API rejected the Context revoke: {0:?}")]
    Api(Box<LocalApiError>),
    #[error("local API returned a malformed Context revoke response: {0}")]
    MalformedResponse(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmedWork {
    pub result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
    pub await_token:
        Option<egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionAwaitToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRevokeInput {
    pub snapshot_id: String,
    pub expected_state_revision: u64,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub confirmation_proof_ref: String,
    pub idempotency_key: String,
}

/// A semantic Context revoke bound to the exact authenticated session that
/// prepared it. Sensitive confirmation material remains private so surfaces
/// can display only the frozen digest and safe routing facts.
pub struct PreparedContextRevoke {
    authenticated_principal_id: String,
    session_id: String,
    snapshot_id: String,
    expected_state_revision: u64,
    reason_code: String,
    evidence_refs: Vec<String>,
    confirmation_proof_ref: String,
    idempotency_key: String,
    request_digest_sha256: String,
}

impl PreparedContextRevoke {
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    #[must_use]
    pub const fn expected_state_revision(&self) -> u64 {
        self.expected_state_revision
    }

    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.evidence_refs.len()
    }

    #[must_use]
    pub fn request_digest_sha256(&self) -> &str {
        &self.request_digest_sha256
    }
}

impl ClientAttachment {
    pub fn metadata(
        &self,
        correlation_id: Option<String>,
    ) -> Result<ClientRequestMetadata, KernelError> {
        self.kernel.request_metadata(
            Uuid::now_v7().to_string(),
            correlation_id,
            SystemTime::now(),
        )
    }

    pub fn require_rpc(&self, rpc: &str) -> Result<(), KernelError> {
        let session = self
            .kernel
            .session()
            .ok_or(KernelError::SessionUnavailable)?;
        self.kernel
            .profiles()
            .authorize_rpc(rpc, &session.granted_permission_codes)
            .map(|_| ())
    }

    pub fn require_command(&self, rpc: &str, oneof: &str) -> Result<(), KernelError> {
        let session = self
            .kernel
            .session()
            .ok_or(KernelError::SessionUnavailable)?;
        self.kernel
            .profiles()
            .authorize_command(rpc, oneof, &session.granted_permission_codes)
            .map(|_| ())
    }

    pub async fn open_task_watch(
        &self,
        request: TaskWatchRequest,
    ) -> Result<TaskWatch, ClientTaskWatchError> {
        let mut client = self.connection.read_model_service();
        let stream = open_task_watch_via(
            &self.kernel,
            request,
            SystemTime::now(),
            move |wire_request| async move {
                client
                    .watch_task_views(wire_request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await?;
        Ok(TaskWatch {
            stream,
            processor: TaskWatchProcessor::default(),
        })
    }

    pub async fn read_actionable_approval_queue(
        &self,
    ) -> Result<ApprovalQueueBaseline, ClientApprovalWatchError> {
        let client = self.connection.read_model_service();
        read_actionable_approval_queue_via(&self.kernel, SystemTime::now(), move |request| {
            let mut client = client.clone();
            async move {
                client
                    .list_harness_approval_views(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            }
        })
        .await
    }

    pub async fn decide_guided_approval(
        &self,
        input: GuidedApprovalDecisionInput,
    ) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError> {
        let mut read_client = self.connection.read_model_service();
        let mut command_client = self.connection.command_gateway_service();
        decide_guided_approval_via(
            &self.kernel,
            input,
            SystemTime::now(),
            move |request| async move {
                read_client
                    .get_harness_approval_view(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
            move |request| async move {
                command_client
                    .decide_harness_approval(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn open_approval_queue_from(
        &self,
        baseline: ApprovalQueueBaseline,
    ) -> Result<ApprovalQueueSession, ClientApprovalWatchError> {
        let ApprovalQueueBaseline {
            actionable,
            position,
        } = baseline;
        let watch = self.open_approval_stream(Some(position.clone())).await?;
        Ok(ApprovalQueueSession {
            watch,
            actionable,
            last_position: position,
        })
    }

    pub async fn open_approval_watch_resume(
        &self,
        cursor: ApprovalWatchCursor,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        if cursor.epoch.is_empty() {
            return Err(ClientApprovalWatchError::Protocol(
                "approval watch resume epoch missing",
            ));
        }
        self.open_approval_stream(Some(ProjectionPosition {
            epoch: cursor.epoch,
            sequence: cursor.sequence,
            projected_at: None,
        }))
        .await
    }

    pub async fn open_approval_watch_current(
        &self,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        self.open_approval_stream(None).await
    }

    async fn open_approval_stream(
        &self,
        resume_after: Option<ProjectionPosition>,
    ) -> Result<ApprovalWatch, ClientApprovalWatchError> {
        let mut client = self.connection.read_model_service();
        let stream = open_approval_stream_via(
            &self.kernel,
            resume_after,
            SystemTime::now(),
            move |request| async move {
                client
                    .watch_harness_approval_views(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await?;
        Ok(ApprovalWatch {
            stream,
            processor: ApprovalWatchProcessor::default(),
        })
    }

    /// Prepares the single confirmation digest shared by CLI and TUI without
    /// sending a request. The authenticated Founder identity comes only from
    /// the accepted local session and is frozen into the semantic digest.
    pub fn prepare_context_revoke(
        &self,
        input: ContextRevokeInput,
    ) -> Result<PreparedContextRevoke, ClientContextRevokeError> {
        prepare_context_revoke_with_kernel(&self.kernel, input)
    }

    /// Executes exactly the prepared Context revoke after checking that the
    /// same authenticated session supplied the exact displayed digest.
    pub async fn execute_context_revoke(
        &self,
        prepared: PreparedContextRevoke,
        supplied_digest_sha256: &str,
    ) -> Result<ContextRevokeReceipt, ClientContextRevokeError> {
        let mut client = self.connection.command_gateway_service();
        execute_context_revoke_via(
            &self.kernel,
            prepared,
            supplied_digest_sha256,
            SystemTime::now(),
            move |request| async move {
                client
                    .execute_context_mutation(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| error.to_string())
            },
        )
        .await
    }

    pub async fn read_projection_snapshot(&self) -> Result<ProjectionSnapshot, ClientReadError> {
        let status = self
            .connection
            .read_model_service()
            .get_projection_status(GetProjectionStatusRequest {
                client: Some(self.metadata(None)?),
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = status.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }
        let metadata = status
            .metadata
            .ok_or(ClientReadError::Protocol("projection metadata missing"))?;

        let tasks = self
            .connection
            .read_model_service()
            .list_task_views(ListTaskViewsRequest {
                client: Some(self.metadata(None)?),
                status_filter: Vec::new(),
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = tasks.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }

        let approvals = self
            .connection
            .read_model_service()
            .list_harness_approval_views(ListHarnessApprovalViewsRequest {
                client: Some(self.metadata(None)?),
                request_lifecycle_filter: Vec::new(),
                decision_state_filter: Vec::new(),
                task_ids: Vec::new(),
                actionable_only: false,
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| ClientReadError::Transport(error.to_string()))?
            .into_inner();
        if let Some(error) = approvals.error {
            return Err(ClientReadError::Api(Box::new(error)));
        }

        Ok(ProjectionSnapshot {
            metadata,
            tasks: tasks.views,
            approvals: approvals.views,
        })
    }

    /// The shared client operation for both CLI and TUI. The request contains
    /// only user intent, scope and explicit source references; all governance
    /// facts are returned by the daemon-owned preparation compiler.
    pub async fn prepare_work(
        &self,
        intent: String,
        work_type: String,
        target_scope_ref: String,
        sources: Vec<(String, String)>,
        idempotency_key: String,
    ) -> Result<WorkPreparationPreview, ClientWorkError> {
        let response = self
            .connection
            .command_gateway_service()
            .prepare_work(PrepareWorkRequest {
                client: Some(self.metadata(None)?),
                intent,
                work_type,
                target_scope_ref,
                sources: sources
                    .into_iter()
                    .map(|(source_ref, label)| WorkSourceRequest { source_ref, label })
                    .collect(),
                idempotency_key,
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Preview(preview)) => Ok(preview),
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::prepare_work_response::Outcome::Error(error)) => Err(ClientWorkError::Api(Box::new(error))),
            None => Err(ClientWorkError::Protocol("prepare outcome missing")),
        }
    }

    /// Confirms exactly the binding displayed in the preparation preview. The
    /// daemon—not this client—creates the Task command through Task Authority.
    pub async fn confirm_work(
        &self,
        snapshot_id: String,
        confirmation_binding_sha256: String,
        idempotency_key: String,
    ) -> Result<ConfirmedWork, ClientWorkError> {
        let response: ConfirmWorkResponse = self
            .connection
            .command_gateway_service()
            .confirm_work(ConfirmWorkRequest {
                client: Some(self.metadata(None)?),
                snapshot_id,
                confirmation_binding_sha256,
                idempotency_key,
            })
            .await
            .map_err(|error| ClientWorkError::Transport(error.to_string()))?
            .into_inner();
        match response.outcome {
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Accepted(accepted)) => Ok(ConfirmedWork {
                result: accepted.authority_result.ok_or(ClientWorkError::Protocol("confirmed task result missing"))?,
                await_token: accepted.await_token,
            }),
            Some(egopulse_domain_contracts::v01::egopulse::localapi::v1::confirm_work_response::Outcome::Error(error)) => Err(ClientWorkError::Api(Box::new(error))),
            None => Err(ClientWorkError::Protocol("confirm outcome missing")),
        }
    }
}

async fn open_approval_stream_via<F, Fut, S>(
    kernel: &ClientKernel,
    resume_after: Option<ProjectionPosition>,
    now: SystemTime,
    dispatch: F,
) -> Result<S, ClientApprovalWatchError>
where
    F: FnOnce(WatchHarnessApprovalViewsRequest) -> Fut,
    Fut: Future<Output = Result<S, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        WATCH_HARNESS_APPROVAL_VIEWS_RPC,
        &session.granted_permission_codes,
    )?;
    let metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    dispatch(approval_watch_wire_request(metadata, resume_after))
        .await
        .map_err(ClientApprovalWatchError::Transport)
}

async fn read_actionable_approval_queue_via<F, Fut>(
    kernel: &ClientKernel,
    now: SystemTime,
    mut dispatch: F,
) -> Result<ApprovalQueueBaseline, ClientApprovalWatchError>
where
    F: FnMut(ListHarnessApprovalViewsRequest) -> Fut,
    Fut: Future<Output = Result<ListHarnessApprovalViewsResponse, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        LIST_HARNESS_APPROVAL_VIEWS_RPC,
        &session.granted_permission_codes,
    )?;
    let metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let mut pages = Vec::new();
    let mut page_cursor = None;
    let mut cursors = BTreeSet::new();
    let mut baseline_views = 0_usize;
    loop {
        if pages.len() >= APPROVAL_WATCH_BASELINE_MAX_PAGES {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline page limit exceeded",
            ));
        }
        let response = dispatch(approval_baseline_wire_request(
            metadata.clone(),
            page_cursor.clone(),
        ))
        .await
        .map_err(ClientApprovalWatchError::Transport)?;
        if let Some(error) = response.error.as_ref() {
            return Err(ClientApprovalWatchError::Api(Box::new(error.clone())));
        }
        baseline_views = baseline_views
            .checked_add(response.views.len())
            .ok_or(ClientApprovalWatchError::BaselineLimitExceeded)?;
        if baseline_views > APPROVAL_WATCH_BASELINE_MAX_VIEWS {
            return Err(ClientApprovalWatchError::BaselineLimitExceeded);
        }
        let next_cursor = response.next_page_cursor.clone();
        if let Some(next) = next_cursor.as_deref()
            && (next.is_empty() || response.views.is_empty() || !cursors.insert(next.to_owned()))
        {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance",
            ));
        }
        pages.push(response);
        let Some(next) = next_cursor else {
            break;
        };
        page_cursor = Some(next);
    }
    let (position, actionable) = compile_approval_baseline(pages)?;
    Ok(ApprovalQueueBaseline {
        actionable,
        position,
    })
}

async fn decide_guided_approval_via<Get, GetFuture, Decide, DecideFuture>(
    kernel: &ClientKernel,
    input: GuidedApprovalDecisionInput,
    now: SystemTime,
    get_latest: Get,
    decide: Decide,
) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError>
where
    Get: FnOnce(GetHarnessApprovalViewRequest) -> GetFuture,
    GetFuture: Future<Output = Result<GetHarnessApprovalViewResponse, String>>,
    Decide: FnOnce(DecideHarnessApprovalRequest) -> DecideFuture,
    DecideFuture: Future<Output = Result<DecideHarnessApprovalResponse, String>>,
{
    if input.approval_request_id.trim().is_empty() {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "approval request id missing",
        ));
    }
    if input.reason_code.trim().is_empty() {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "reason code missing",
        ));
    }
    if input
        .confirmation_proof_ref
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(ClientGuidedApprovalDecisionError::InvalidInput(
            "confirmation proof reference empty",
        ));
    }
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_rpc(
        GET_HARNESS_APPROVAL_VIEW_RPC,
        &session.granted_permission_codes,
    )?;
    kernel.profiles().authorize_command(
        DECIDE_HARNESS_APPROVAL_RPC,
        ISSUE_HARNESS_APPROVAL_DECISION_COMMAND,
        &session.granted_permission_codes,
    )?;

    let read_metadata = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    let response = get_latest(GetHarnessApprovalViewRequest {
        client: Some(read_metadata),
        approval_request_id: input.approval_request_id.clone(),
        minimum_position: None,
    })
    .await
    .map_err(ClientGuidedApprovalDecisionError::Transport)?;
    let view = match response.outcome {
        Some(get_harness_approval_view_response::Outcome::View(view)) => view,
        Some(get_harness_approval_view_response::Outcome::Error(error))
            if error.code == egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode::NotFound as i32 =>
        {
            return Err(ClientGuidedApprovalDecisionError::NotFound);
        }
        Some(get_harness_approval_view_response::Outcome::Error(error)) => {
            return Err(ClientGuidedApprovalDecisionError::Api(Box::new(error)));
        }
        None => {
            return Err(ClientGuidedApprovalDecisionError::Protocol(
                "approval view outcome missing",
            ));
        }
    };
    validate_guided_approval_view(&view, &input.approval_request_id)?;
    if !is_actionable_approval(&view).map_err(|error| match error {
        ClientApprovalWatchError::Kernel(error) => ClientGuidedApprovalDecisionError::Kernel(error),
        ClientApprovalWatchError::Protocol(detail) => {
            ClientGuidedApprovalDecisionError::Protocol(detail)
        }
        _ => ClientGuidedApprovalDecisionError::Protocol("approval actionability invalid"),
    })? {
        return Err(ClientGuidedApprovalDecisionError::NonActionable);
    }

    let correlation_id = Uuid::now_v7().to_string();
    let mut command = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(CommandMetadata {
                        command_id: Uuid::now_v7().to_string(),
                        idempotency_key: guided_approval_idempotency_key(
                            &input.approval_request_id,
                        ),
                        idempotency_scope: APPROVAL_DECISION_IDEMPOTENCY_SCOPE.to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(timestamp_from_system_time(now)?),
                        correlation_id: correlation_id.clone(),
                        causation_id: None,
                    }),
                    approval_request_id: view.approval_request_id,
                    expected_action_digest_sha256: view.action_digest_sha256,
                    expected_request_observation_id: view.request_observation_id,
                    expected_request_observation_sequence: view.request_observation_sequence,
                    decision: input.decision.wire_value(),
                    reason_code: input.reason_code,
                    confirmation_proof_ref: input.confirmation_proof_ref,
                    expected_request_revision: view.request_revision,
                },
            ),
        ),
    };
    set_policy_digest(&mut command);
    let policy_decision_command::Command::IssueHarnessApprovalDecision(command) =
        command.command.expect("guided approval command")
    else {
        unreachable!("guided approval constructs the issue branch")
    };
    let response = decide(DecideHarnessApprovalRequest {
        client: Some(kernel.request_metadata(
            Uuid::now_v7().to_string(),
            Some(correlation_id.clone()),
            now,
        )?),
        command: Some(command),
    })
    .await
    .map_err(ClientGuidedApprovalDecisionError::Transport)?;
    parse_guided_approval_response(response, input.decision, correlation_id)
}

fn guided_approval_idempotency_key(approval_request_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(GUIDED_APPROVAL_IDEMPOTENCY_DOMAIN);
    hasher.update(approval_request_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_guided_approval_view(
    view: &HarnessApprovalView,
    expected_approval_request_id: &str,
) -> Result<(), ClientGuidedApprovalDecisionError> {
    if view.approval_request_id != expected_approval_request_id
        || !is_canonical_sha256(&view.action_digest_sha256)
        || view.request_observation_id.is_empty()
        || view.request_observation_sequence == 0
        || view.request_revision == 0
    {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "approval view binding invalid",
        ));
    }
    let position = view
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.position.clone())
        .ok_or(ClientGuidedApprovalDecisionError::Protocol(
            "approval view position missing",
        ))?;
    SnapshotStreamTracker::default().apply_harness_approval_frame(
        &HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::Snapshot as i32,
            position: Some(position),
            snapshot: Some(view.clone()),
            reset_reason_code: None,
        },
    )?;
    Ok(())
}

#[allow(deprecated)]
fn parse_guided_approval_response(
    response: DecideHarnessApprovalResponse,
    expected_decision: GuidedApprovalDecision,
    correlation_id: String,
) -> Result<GuidedApprovalDecisionResult, ClientGuidedApprovalDecisionError> {
    if response.policy_authority_result.is_some() {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "unsanitized authority result exposed",
        ));
    }
    let Some(authority) = response.sanitized_authority_result else {
        return match response.gateway_error {
            Some(error) => Err(ClientGuidedApprovalDecisionError::Api(Box::new(error))),
            None => Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result missing",
            )),
        };
    };
    let error_code = PolicyDecisionErrorCode::try_from(authority.error_code)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority error code unknown"))?;
    if error_code != PolicyDecisionErrorCode::Unspecified {
        return Err(ClientGuidedApprovalDecisionError::Authority {
            error_code: authority.error_code,
            safe_error_fingerprint: authority.safe_error_fingerprint,
        });
    }
    let decision = ApprovalDecision::try_from(authority.decision)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority decision unknown"))?;
    let state = HarnessApprovalDecisionStateKind::try_from(authority.state)
        .map_err(|_| ClientGuidedApprovalDecisionError::Protocol("authority state unknown"))?;
    if !authority.committed
        || authority.authority_decision_ref.is_empty()
        || decision == ApprovalDecision::Unspecified
        || authority.decision != expected_decision.wire_value()
        || state != HarnessApprovalDecisionStateKind::Issued
        || authority.state_revision == 0
    {
        return Err(ClientGuidedApprovalDecisionError::Protocol(
            "sanitized approval result invalid",
        ));
    }
    Ok(GuidedApprovalDecisionResult {
        authority,
        await_token: response.await_token,
        projection_warning: response.gateway_error,
        correlation_id,
    })
}

fn timestamp_from_system_time(
    value: SystemTime,
) -> Result<Timestamp, ClientGuidedApprovalDecisionError> {
    let duration = value.duration_since(std::time::UNIX_EPOCH).map_err(|_| {
        ClientGuidedApprovalDecisionError::Protocol("client clock before Unix epoch")
    })?;
    Ok(Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    })
}

fn approval_baseline_wire_request(
    metadata: ClientRequestMetadata,
    page_cursor: Option<String>,
) -> ListHarnessApprovalViewsRequest {
    ListHarnessApprovalViewsRequest {
        client: Some(metadata),
        request_lifecycle_filter: Vec::new(),
        decision_state_filter: Vec::new(),
        task_ids: Vec::new(),
        actionable_only: true,
        page_size: APPROVAL_WATCH_BASELINE_PAGE_SIZE,
        page_cursor,
        minimum_position: None,
    }
}

fn approval_watch_wire_request(
    metadata: ClientRequestMetadata,
    resume_after: Option<ProjectionPosition>,
) -> WatchHarnessApprovalViewsRequest {
    WatchHarnessApprovalViewsRequest {
        client: Some(metadata),
        resume_after,
        approval_request_ids: Vec::new(),
        task_ids: Vec::new(),
        request_lifecycle_filter: Vec::new(),
        decision_state_filter: Vec::new(),
        actionable_only: false,
    }
}

fn compile_approval_baseline(
    pages: Vec<ListHarnessApprovalViewsResponse>,
) -> Result<(ProjectionPosition, BTreeMap<String, ActionableApproval>), ClientApprovalWatchError> {
    if pages.is_empty() {
        return Err(ClientApprovalWatchError::Protocol(
            "approval baseline returned no page",
        ));
    }
    let mut position: Option<ProjectionPosition> = None;
    let mut actionable = BTreeMap::new();
    let mut seen_ids = BTreeSet::new();
    let mut seen_cursors = BTreeSet::new();
    let mut total = 0_usize;
    let page_count = pages.len();
    for (page_index, page) in pages.into_iter().enumerate() {
        if let Some(error) = page.error {
            return Err(ClientApprovalWatchError::Api(Box::new(error)));
        }
        let page_position = page
            .snapshot_position
            .ok_or(ClientApprovalWatchError::Protocol(
                "approval baseline position missing",
            ))?;
        if page_position.epoch.is_empty() {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline epoch missing",
            ));
        }
        if let Some(expected) = &position {
            if expected != &page_position {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline position changed across pages",
                ));
            }
        } else {
            position = Some(page_position.clone());
        }
        total = total
            .checked_add(page.views.len())
            .ok_or(ClientApprovalWatchError::BaselineLimitExceeded)?;
        if total > APPROVAL_WATCH_BASELINE_MAX_VIEWS {
            return Err(ClientApprovalWatchError::BaselineLimitExceeded);
        }
        if let Some(cursor) = page.next_page_cursor.as_deref() {
            if cursor.is_empty() || page.views.is_empty() || !seen_cursors.insert(cursor.to_owned())
            {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline cursor did not advance",
                ));
            }
            if page_index + 1 == page_count {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline pagination incomplete",
                ));
            }
        } else if page_index + 1 != page_count {
            return Err(ClientApprovalWatchError::Protocol(
                "approval baseline contained pages after completion",
            ));
        }
        let mut tracker = SnapshotStreamTracker::default();
        for view in page.views {
            if view.approval_request_id.is_empty()
                || !seen_ids.insert(view.approval_request_id.clone())
            {
                return Err(ClientApprovalWatchError::Protocol(
                    "approval baseline identity missing or duplicated",
                ));
            }
            tracker.apply_harness_approval_frame(&HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(page_position.clone()),
                snapshot: Some(view.clone()),
                reset_reason_code: None,
            })?;
            if is_actionable_approval(&view)? {
                actionable.insert(
                    view.approval_request_id.clone(),
                    ActionableApproval { view },
                );
            }
        }
    }
    Ok((
        position.expect("non-empty pages establish a position"),
        actionable,
    ))
}

fn task_watch_resume_after(
    request: TaskWatchRequest,
) -> Result<Option<ProjectionPosition>, ClientTaskWatchError> {
    if request.resume_epoch.is_some() != request.resume_sequence.is_some() {
        return Err(ClientTaskWatchError::InvalidResumePair);
    }
    Ok(request.resume_epoch.map(|epoch| ProjectionPosition {
        epoch,
        sequence: request
            .resume_sequence
            .expect("validated Task watch resume sequence"),
        projected_at: None,
    }))
}

async fn open_task_watch_via<T, F, Fut>(
    kernel: &ClientKernel,
    request: TaskWatchRequest,
    now: SystemTime,
    dispatch: F,
) -> Result<T, ClientTaskWatchError>
where
    F: FnOnce(WatchTaskViewsRequest) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel
        .profiles()
        .authorize_rpc(WATCH_TASK_VIEWS_RPC, &session.granted_permission_codes)?;
    let resume_after = task_watch_resume_after(request)?;
    let client = kernel.request_metadata(Uuid::now_v7().to_string(), None, now)?;
    dispatch(WatchTaskViewsRequest {
        client: Some(client),
        resume_after,
        task_ids: Vec::new(),
        status_filter: Vec::new(),
    })
    .await
    .map_err(ClientTaskWatchError::Transport)
}

fn prepare_context_revoke_with_kernel(
    kernel: &ClientKernel,
    input: ContextRevokeInput,
) -> Result<PreparedContextRevoke, ClientContextRevokeError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_CONTEXT_MUTATION_RPC,
        REVOKE_CONTEXT_SNAPSHOT_COMMAND,
        &session.granted_permission_codes,
    )?;

    let request_digest_sha256 = ContextRevokeSemanticRequest {
        founder_principal_id: &session.authenticated_principal_id,
        snapshot_id: &input.snapshot_id,
        expected_state_revision: input.expected_state_revision,
        reason_code: &input.reason_code,
        evidence_refs: &input.evidence_refs,
        confirmation_proof_ref: &input.confirmation_proof_ref,
    }
    .digest_sha256();
    if !is_canonical_sha256(&request_digest_sha256) {
        return Err(ClientContextRevokeError::MalformedResponse(
            "prepared request digest",
        ));
    }

    Ok(PreparedContextRevoke {
        authenticated_principal_id: session.authenticated_principal_id.clone(),
        session_id: session.session_id.clone(),
        snapshot_id: input.snapshot_id,
        expected_state_revision: input.expected_state_revision,
        reason_code: input.reason_code,
        evidence_refs: input.evidence_refs,
        confirmation_proof_ref: input.confirmation_proof_ref,
        idempotency_key: input.idempotency_key,
        request_digest_sha256,
    })
}

async fn execute_context_revoke_via<F, Fut>(
    kernel: &ClientKernel,
    prepared: PreparedContextRevoke,
    supplied_digest_sha256: &str,
    now: SystemTime,
    send: F,
) -> Result<ContextRevokeReceipt, ClientContextRevokeError>
where
    F: FnOnce(ExecuteContextMutationRequest) -> Fut,
    Fut: Future<Output = Result<ExecuteContextMutationResponse, String>>,
{
    let request = build_context_revoke_request(kernel, &prepared, supplied_digest_sha256, now)?;
    let response = send(request)
        .await
        .map_err(ClientContextRevokeError::Transport)?;
    parse_context_revoke_response(response, &prepared)
}

fn build_context_revoke_request(
    kernel: &ClientKernel,
    prepared: &PreparedContextRevoke,
    supplied_digest_sha256: &str,
    now: SystemTime,
) -> Result<ExecuteContextMutationRequest, ClientContextRevokeError> {
    let session = kernel.session().ok_or(KernelError::SessionUnavailable)?;
    kernel.profiles().authorize_command(
        EXECUTE_CONTEXT_MUTATION_RPC,
        REVOKE_CONTEXT_SNAPSHOT_COMMAND,
        &session.granted_permission_codes,
    )?;
    if session.session_id != prepared.session_id
        || session.authenticated_principal_id != prepared.authenticated_principal_id
    {
        return Err(ClientContextRevokeError::SessionChanged);
    }
    if !is_canonical_sha256(supplied_digest_sha256)
        || supplied_digest_sha256 != prepared.request_digest_sha256
    {
        return Err(ClientContextRevokeError::InvalidConfirmation);
    }

    let correlation_id = Uuid::now_v7().to_string();
    let client = kernel.request_metadata(
        Uuid::now_v7().to_string(),
        Some(correlation_id.clone()),
        now,
    )?;
    Ok(ExecuteContextMutationRequest {
        client: Some(client),
        command: Some(ContextMutationCommand {
            command: Some(context_mutation_command::Command::RevokeContextSnapshot(
                RevokeContextSnapshotCommand {
                    metadata: Some(CommandMetadata {
                        command_id: Uuid::now_v7().to_string(),
                        idempotency_key: prepared.idempotency_key.clone(),
                        idempotency_scope: CONTEXT_REVOKE_IDEMPOTENCY_SCOPE.to_owned(),
                        request_digest_sha256: prepared.request_digest_sha256.clone(),
                        issued_at: Some(now_timestamp()),
                        correlation_id,
                        causation_id: None,
                    }),
                    snapshot_id: prepared.snapshot_id.clone(),
                    expected_state_revision: prepared.expected_state_revision,
                    reason_code: prepared.reason_code.clone(),
                    evidence_refs: prepared.evidence_refs.clone(),
                    confirmation_proof_ref: prepared.confirmation_proof_ref.clone(),
                },
            )),
        }),
    })
}

fn parse_context_revoke_response(
    response: ExecuteContextMutationResponse,
    prepared: &PreparedContextRevoke,
) -> Result<ContextRevokeReceipt, ClientContextRevokeError> {
    let receipt = match response.outcome {
        Some(execute_context_mutation_response::Outcome::AuthorityResult(receipt)) => receipt,
        Some(execute_context_mutation_response::Outcome::Error(error)) => {
            return Err(ClientContextRevokeError::Api(Box::new(error)));
        }
        None => {
            return Err(ClientContextRevokeError::MalformedResponse(
                "outcome missing",
            ));
        }
    };
    let Some(expected_result_state_revision) = prepared.expected_state_revision.checked_add(1)
    else {
        return Err(ClientContextRevokeError::MalformedResponse(
            "state revision overflow",
        ));
    };
    let committed_at_is_valid = receipt
        .committed_at
        .as_ref()
        .is_some_and(|value| value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos));
    if receipt.snapshot_id != prepared.snapshot_id
        || receipt.snapshot_revision == 0
        || !is_canonical_sha256(&receipt.content_digest_sha256)
        || receipt.previous_state_revision != prepared.expected_state_revision
        || receipt.result_state_revision != expected_result_state_revision
        || receipt.previous_state != ContextGovernanceState::Issued as i32
        || receipt.result_state != ContextGovernanceState::Revoked as i32
        || !is_canonical_sha256(&receipt.request_digest_sha256)
        || receipt.request_digest_sha256 != prepared.request_digest_sha256
        || receipt.event_id.is_empty()
        || !committed_at_is_valid
        || !receipt.acknowledged_after_durability_barrier
    {
        return Err(ClientContextRevokeError::MalformedResponse(
            "authority receipt integrity",
        ));
    }
    Ok(receipt)
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Error)]
pub enum AttachError {
    #[error("invalid IPC instance: {0}")]
    InvalidInstance(String),
    #[error("local daemon unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("client kernel rejected the session: {0}")]
    Kernel(#[from] KernelError),
}

/// Attach to a running local daemon and complete the session handshake.
///
/// This function never starts, supervises, or restarts a daemon. Lifecycle
/// ownership remains with the application/daemon boundary.
pub async fn attach(
    instance: &str,
    surface: ClientSurface,
    client_instance_id: impl Into<String>,
) -> Result<ClientAttachment, AttachError> {
    let address = LocalIpcAddress::for_instance(instance)
        .map_err(|error| AttachError::InvalidInstance(error.to_string()))?;
    let connection = LocalApiClient::platform_default()
        .connect(address)
        .await
        .map_err(|error| AttachError::DaemonUnavailable(error.to_string()))?;
    let mut kernel = ClientKernel::new(client_instance_id, surface)?;
    let request = kernel.open_session_request(Uuid::now_v7().to_string())?;
    let response = connection
        .session_service()
        .open_session(request)
        .await
        .map_err(|error| AttachError::DaemonUnavailable(error.to_string()))?
        .into_inner();
    kernel.accept_open_session(response, SystemTime::now())?;
    Ok(ClientAttachment { connection, kernel })
}

#[must_use]
pub fn command_metadata(correlation_id: &str, scope: &str) -> CommandMetadata {
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

#[must_use]
pub fn canonical_task_digest(command: &TaskCommand) -> String {
    let mut canonical = command.clone();
    if let Some(metadata) = task_metadata_mut(&mut canonical) {
        clear_command_metadata(Some(metadata));
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

/// Seals any client-originated Task command with the same canonical digest
/// rule used by Task Authority. CLI, TUI and Desktop can therefore submit the
/// same governed write without maintaining separate digest implementations.
pub fn set_task_digest(command: &mut TaskCommand) {
    let digest = canonical_task_digest(command);
    if let Some(metadata) = task_metadata_mut(command) {
        metadata.request_digest_sha256 = digest;
    }
}

pub fn set_policy_digest(command: &mut PolicyDecisionCommand) {
    let mut canonical = command.clone();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        canonical.command.as_mut()
        && let Some(metadata) = issue.metadata.as_mut()
    {
        clear_command_metadata(Some(metadata));
    }
    let digest = hex::encode(Sha256::digest(canonical.encode_to_vec()));
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        command.command.as_mut()
    {
        issue
            .metadata
            .as_mut()
            .expect("policy command metadata must be supplied")
            .request_digest_sha256 = digest;
    }
}

pub fn set_verdict_digest(command: &mut VerdictCommand) {
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
                .expect("verdict command metadata must be supplied")
                .request_digest_sha256 = digest;
        }
        Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
            revoke
                .metadata
                .as_mut()
                .expect("verdict command metadata must be supplied")
                .request_digest_sha256 = digest;
        }
        _ => {}
    }
}

pub fn timestamp_after(duration: std::time::Duration) -> Timestamp {
    let now = now_timestamp();
    Timestamp {
        seconds: now.seconds + duration.as_secs() as i64,
        nanos: now.nanos,
    }
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after Unix epoch");
    Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
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

fn task_metadata_mut(command: &mut TaskCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_mut(),
        task_command::Command::ApplyFounderVerdict(value) => value.meta.as_mut(),
        task_command::Command::ReviseTask(value) => value.meta.as_mut(),
        task_command::Command::InterruptTask(value) => value.meta.as_mut(),
        task_command::Command::HoldTask(value) => value.meta.as_mut(),
        task_command::Command::ResumeTask(value) => value.meta.as_mut(),
        task_command::Command::RequestTaskCancellation(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskCancellationOutcome(value) => value.meta.as_mut(),
        task_command::Command::SupersedeTask(value) => value.meta.as_mut(),
        task_command::Command::ExpireTask(value) => value.meta.as_mut(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::VecDeque,
        pin::pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use egopulse_client_kernel::{
        api_contract_ref, authorization_contract_ref, client_kernel_contract_ref,
    };
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        AvailableAction, LocalApiErrorCode, OpenSessionResponse, ProjectionHealth,
        ProjectionPosition, SourceDomain, SourceRevision, StreamFrameKind,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        common::v1::ContractReference, localapi::v1::ProjectionMetadata, task::v1::TaskSnapshot,
    };

    use super::*;

    const FIXED_CONTEXT_REVOKE_DIGEST: &str =
        "dc1242cf2e4c83e32ee5f95ef8cd6a5b3d8b2e64d8ab875d21ccfbb7604b9a35";
    const FIXED_CONTEXT_REVOKE_CANONICAL_HEX: &str = concat!(
        "1a0000000000000065676f70756c73652f636f6e746578742d7265766f6b652f7631",
        "0d00000000000000666f756e6465723a616c696365",
        "07000000000000006374783a303031",
        "08000000000000000200000000000000",
        "090000000000000077697468647261776e",
        "08000000000000000200000000000000",
        "0a0000000000000065766964656e63653a31",
        "0a0000000000000065766964656e63653a32",
        "0d0000000000000070726f6f663a6c6f63616c3a31",
    );
    const FIXED_CONTEXT_REVOKE_MUTATION_HEX: &str = concat!(
        "0aaf010a70121c6964656d706f74656e63793a636f6e746578742d7265766f6b653a31",
        "1a0e636f6e746578742d7265766f6b65",
        "2240646331323432636632653463383365333265653566393565663863643661356233",
        "64386232653634643861623837356432316363666262373630346239613335",
        "12076374783a3030311802",
        "220977697468647261776e",
        "2a0a65766964656e63653a31",
        "2a0a65766964656e63653a32",
        "320d70726f6f663a6c6f63616c3a31",
    );

    fn context_revoke_input() -> ContextRevokeInput {
        ContextRevokeInput {
            snapshot_id: "ctx:001".to_owned(),
            expected_state_revision: 2,
            reason_code: "withdrawn".to_owned(),
            evidence_refs: vec!["evidence:1".to_owned(), "evidence:2".to_owned()],
            confirmation_proof_ref: "proof:local:1".to_owned(),
            idempotency_key: "idempotency:context-revoke:1".to_owned(),
        }
    }

    fn authenticated_kernel(
        principal_id: &str,
        session_id: &str,
        permission_code: &str,
        now: SystemTime,
    ) -> ClientKernel {
        authenticated_kernel_for_surface(
            principal_id,
            session_id,
            permission_code,
            ClientSurface::Cli,
            now,
        )
    }

    fn authenticated_kernel_for_surface(
        principal_id: &str,
        session_id: &str,
        permission_code: &str,
        surface: ClientSurface,
        now: SystemTime,
    ) -> ClientKernel {
        authenticated_kernel_with_permissions(
            principal_id,
            session_id,
            &[permission_code],
            surface,
            now,
        )
    }

    fn authenticated_kernel_with_permissions(
        principal_id: &str,
        session_id: &str,
        permission_codes: &[&str],
        surface: ClientSurface,
        now: SystemTime,
    ) -> ClientKernel {
        let expires_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock after epoch")
            + Duration::from_secs(60);
        let mut kernel =
            ClientKernel::new("client:context-revoke", surface).expect("client kernel");
        kernel
            .accept_open_session(
                OpenSessionResponse {
                    session_id: session_id.to_owned(),
                    authenticated_principal_id: principal_id.to_owned(),
                    negotiated_contract_ref: Some(api_contract_ref()),
                    granted_permission_codes: permission_codes
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    expires_at: Some(Timestamp {
                        seconds: expires_at.as_secs() as i64,
                        nanos: expires_at.subsec_nanos() as i32,
                    }),
                    current_position: Some(ProjectionPosition {
                        epoch: "epoch:context-revoke".to_owned(),
                        sequence: 1,
                        projected_at: Some(Timestamp {
                            seconds: 1,
                            nanos: 0,
                        }),
                    }),
                    error: None,
                    client_kernel_contract_ref: Some(client_kernel_contract_ref()),
                    authorization_policy_ref: Some(authorization_contract_ref()),
                },
                now,
            )
            .expect("accepted session");
        kernel
    }

    fn normalized_context_revoke_mutation_bytes(request: ExecuteContextMutationRequest) -> Vec<u8> {
        let mut mutation = request.command.expect("Context mutation envelope");
        let context_mutation_command::Command::RevokeContextSnapshot(command) =
            mutation.command.as_mut().expect("Context revoke command");
        let metadata = command.metadata.as_mut().expect("command metadata");
        metadata.command_id.clear();
        metadata.issued_at = None;
        metadata.correlation_id.clear();
        metadata.causation_id = None;
        mutation.encode_to_vec()
    }

    fn success_context_revoke_receipt() -> ContextRevokeReceipt {
        ContextRevokeReceipt {
            snapshot_id: "ctx:001".to_owned(),
            snapshot_revision: 1,
            content_digest_sha256: "b".repeat(64),
            previous_state_revision: 2,
            result_state_revision: 3,
            previous_state: ContextGovernanceState::Issued as i32,
            result_state: ContextGovernanceState::Revoked as i32,
            request_digest_sha256: FIXED_CONTEXT_REVOKE_DIGEST.to_owned(),
            event_id: "context-event:revoke:1".to_owned(),
            committed_at: Some(Timestamp {
                seconds: 100,
                nanos: 7,
            }),
            replayed: false,
            acknowledged_after_durability_barrier: true,
        }
    }

    fn approval_position(sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: "epoch:approval-watch".to_owned(),
            sequence,
            projected_at: Some(Timestamp {
                seconds: sequence as i64,
                nanos: 0,
            }),
        }
    }

    fn approval_view(
        approval_request_id: impl Into<String>,
        position: &ProjectionPosition,
        action_kind: Option<i32>,
    ) -> HarnessApprovalView {
        let approval_request_id = approval_request_id.into();
        HarnessApprovalView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1.HarnessApprovalView".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::PolicyDecision as i32,
                    aggregate_id: approval_request_id.clone(),
                    revision: 1,
                    last_event_id: format!("event:{approval_request_id}"),
                }],
                health: ProjectionHealth::Ready as i32,
                stale: false,
                safe_health_reason_code: None,
            }),
            approval_request_id: approval_request_id.clone(),
            task_id: format!("task:{approval_request_id}"),
            run_id: format!("run:{approval_request_id}"),
            step_id: format!("step:{approval_request_id}"),
            attempt_id: format!("attempt:{approval_request_id}"),
            dispatch_id: format!("dispatch:{approval_request_id}"),
            fencing_token: 1,
            kind: 1,
            action_digest_sha256: "b".repeat(64),
            requested_scope_ref: "scope:test".to_owned(),
            display_summary_ref: "summary:test".to_owned(),
            request_observation_id: format!("observation:{approval_request_id}"),
            request_observation_sequence: 1,
            request_lifecycle: 1,
            request_revision: 1,
            policy_decision: None,
            available_actions: action_kind
                .map(|kind| AvailableAction {
                    kind,
                    owning_authority: "PolicyDecisionAuthority".to_owned(),
                    derivation_rule_ref: "rule:approval-actionability".to_owned(),
                    explicit_confirmation_required: true,
                    reason_code: None,
                })
                .into_iter()
                .collect(),
            redactions: Vec::new(),
        }
    }

    fn approval_page(
        position: &ProjectionPosition,
        views: Vec<HarnessApprovalView>,
        next_page_cursor: Option<&str>,
    ) -> ListHarnessApprovalViewsResponse {
        ListHarnessApprovalViewsResponse {
            views,
            next_page_cursor: next_page_cursor.map(str::to_owned),
            snapshot_position: Some(position.clone()),
            error: None,
        }
    }

    fn guided_approval_input(decision: GuidedApprovalDecision) -> GuidedApprovalDecisionInput {
        GuidedApprovalDecisionInput {
            approval_request_id: "approval:guided:1".to_owned(),
            decision,
            reason_code: "  founder-reviewed  ".to_owned(),
            confirmation_proof_ref: Some("proof:approval:1".to_owned()),
        }
    }

    fn local_api_error(code: LocalApiErrorCode) -> LocalApiError {
        LocalApiError {
            code: code as i32,
            safe_fingerprint: "approval/guided/test/v1".to_owned(),
            retryable: false,
            required_action_code: Some("REFRESH_APPROVAL".to_owned()),
            current_position: None,
            correlation_id: "correlation:approval:guided".to_owned(),
        }
    }

    #[allow(deprecated)]
    fn guided_approval_response(
        decision: GuidedApprovalDecision,
        replayed: bool,
        gateway_error: Option<LocalApiError>,
    ) -> DecideHarnessApprovalResponse {
        DecideHarnessApprovalResponse {
            await_token: None,
            gateway_error,
            policy_authority_result: None,
            sanitized_authority_result: Some(HarnessApprovalAuthorityResult {
                committed: true,
                replayed,
                authority_decision_ref: "policy-decision:guided:1".to_owned(),
                decision: decision.wire_value(),
                state: HarnessApprovalDecisionStateKind::Issued as i32,
                state_revision: 1,
                expires_at: None,
                error_code: PolicyDecisionErrorCode::Unspecified as i32,
                safe_error_fingerprint: None,
            }),
        }
    }

    fn sealed_guided_approval_command(
        kernel: &ClientKernel,
        position: &ProjectionPosition,
        input: GuidedApprovalDecisionInput,
        now: SystemTime,
    ) -> IssueHarnessApprovalDecisionCommand {
        use std::cell::RefCell;

        let decision = input.decision;
        let request = RefCell::new(None);
        block_on_ready(decide_guided_approval_via(
            kernel,
            input,
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view(
                            "approval:guided:1",
                            position,
                            Some(AvailableActionKind::DecideHarnessApproval as i32),
                        ),
                    )),
                }))
            },
            |value| {
                request.replace(Some(value));
                std::future::ready(Ok(guided_approval_response(decision, false, None)))
            },
        ))
        .expect("guided approval command");
        request
            .into_inner()
            .expect("Decide request")
            .command
            .expect("sealed command")
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn watch_position(epoch: &str, sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: epoch.to_owned(),
            sequence,
            projected_at: Some(Timestamp {
                seconds: sequence as i64,
                nanos: 0,
            }),
        }
    }

    fn watch_view(position: &ProjectionPosition, task_id: &str, revision: u64) -> TaskView {
        TaskView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1/TaskView".to_owned(),
                    version: "0.1.0".to_owned(),
                    sha256: "a".repeat(64),
                }),
                position: Some(position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::Task as i32,
                    aggregate_id: task_id.to_owned(),
                    revision,
                    last_event_id: format!("event:{task_id}:{revision}"),
                }],
                health: 1,
                stale: false,
                safe_health_reason_code: None,
            }),
            task: Some(TaskSnapshot {
                task_id: task_id.to_owned(),
                revision,
                ..TaskSnapshot::default()
            }),
            ..TaskView::default()
        }
    }

    fn watch_frame(
        kind: StreamFrameKind,
        position: ProjectionPosition,
        view: Option<TaskView>,
        reset_reason_code: Option<&str>,
    ) -> TaskViewStreamFrame {
        TaskViewStreamFrame {
            kind: kind as i32,
            position: Some(position),
            snapshot: view,
            reset_reason_code: reset_reason_code.map(str::to_owned),
        }
    }

    #[test]
    fn task_watch_processor_classifies_replay_and_enforces_reset_barrier() {
        let mut processor = TaskWatchProcessor::default();
        let position = watch_position("epoch:watch", 7);
        let first = watch_frame(
            StreamFrameKind::Snapshot,
            position.clone(),
            Some(watch_view(&position, "task:one", 1)),
            None,
        );
        assert_eq!(
            processor.process(first.clone()).unwrap().classification,
            TaskWatchClassification::Applied
        );
        assert_eq!(
            processor.process(first).unwrap().classification,
            TaskWatchClassification::Replay
        );
        let second = watch_frame(
            StreamFrameKind::Snapshot,
            position.clone(),
            Some(watch_view(&position, "task:two", 1)),
            None,
        );
        assert_eq!(
            processor.process(second).unwrap().classification,
            TaskWatchClassification::Applied
        );
        assert_eq!(
            processor
                .process(watch_frame(
                    StreamFrameKind::Heartbeat,
                    position.clone(),
                    None,
                    None,
                ))
                .unwrap()
                .classification,
            TaskWatchClassification::Heartbeat
        );
        let reset_position = watch_position("epoch:watch", 8);
        let reset = processor
            .process(watch_frame(
                StreamFrameKind::ResetRequired,
                reset_position,
                None,
                Some("projection_compacted"),
            ))
            .unwrap();
        assert_eq!(reset.classification, TaskWatchClassification::ResetRequired);
        assert_eq!(
            reset.reset_reason_code.as_deref(),
            Some("projection_compacted")
        );
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                position,
                None,
                None,
            )),
            Err(ClientTaskWatchError::ResetBarrier)
        ));
    }

    #[test]
    fn task_watch_next_seam_blocks_message_after_reset_and_types_eof_and_transport() {
        let calls = Cell::new(0_u64);
        let mut processor = TaskWatchProcessor::default();
        let reset = watch_frame(
            StreamFrameKind::ResetRequired,
            watch_position("epoch:watch", 30),
            None,
            Some("projection_reset"),
        );
        let update = block_on_ready(next_task_watch_update_via(&mut processor, || {
            calls.set(calls.get() + 1);
            std::future::ready(Ok(Some(reset)))
        }))
        .unwrap()
        .unwrap();
        assert_eq!(
            update.classification,
            TaskWatchClassification::ResetRequired
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(None))
            })),
            Err(ClientTaskWatchError::ResetBarrier)
        ));
        assert_eq!(calls.get(), 1, "reset barrier polled the underlying stream");

        let mut processor = TaskWatchProcessor::default();
        assert!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(None))
            }))
            .unwrap()
            .is_none()
        );
        assert_eq!(calls.get(), 2);

        let mut processor = TaskWatchProcessor::default();
        assert!(matches!(
            block_on_ready(next_task_watch_update_via(&mut processor, || {
                calls.set(calls.get() + 1);
                std::future::ready(Err("tonic-status-unavailable".to_owned()))
            })),
            Err(ClientTaskWatchError::Transport(detail))
                if detail == "tonic-status-unavailable"
        ));
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn task_watch_processor_rejects_invalid_shapes_and_tracker_drift() {
        let position = watch_position("epoch:watch", 10);
        let view = watch_view(&position, "task:one", 1);
        for invalid in [
            watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view.clone()),
                Some("unexpected"),
            ),
            watch_frame(
                StreamFrameKind::Heartbeat,
                position.clone(),
                None,
                Some("unexpected"),
            ),
            watch_frame(StreamFrameKind::ResetRequired, position.clone(), None, None),
            watch_frame(
                StreamFrameKind::ResetRequired,
                position.clone(),
                None,
                Some("unsafe reason"),
            ),
            watch_frame(
                StreamFrameKind::ResetRequired,
                position.clone(),
                Some(view.clone()),
                Some("projection_reset"),
            ),
        ] {
            assert!(matches!(
                TaskWatchProcessor::default().process(invalid),
                Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame
                ))
            ));
        }
        for unsafe_reason in [
            "x".repeat(129),
            "line\nbreak".to_owned(),
            "reset-原因".to_owned(),
        ] {
            assert!(matches!(
                TaskWatchProcessor::default().process(watch_frame(
                    StreamFrameKind::ResetRequired,
                    position.clone(),
                    None,
                    Some(&unsafe_reason),
                )),
                Err(ClientTaskWatchError::Kernel(
                    KernelError::IncompleteStreamFrame
                ))
            ));
        }

        let mut missing_position =
            watch_frame(StreamFrameKind::Heartbeat, position.clone(), None, None);
        missing_position.position = None;
        assert!(matches!(
            TaskWatchProcessor::default().process(missing_position),
            Err(ClientTaskWatchError::Kernel(
                KernelError::StreamPositionInvalid
            ))
        ));

        let mut unknown = watch_frame(StreamFrameKind::Heartbeat, position.clone(), None, None);
        unknown.kind = 999;
        assert!(matches!(
            TaskWatchProcessor::default().process(unknown),
            Err(ClientTaskWatchError::Kernel(
                KernelError::UnknownStreamFrame
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view.clone()),
                None,
            ))
            .unwrap();
        let changed = watch_view(&position, "task:one", 2);
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(changed),
                None,
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Snapshot,
                position.clone(),
                Some(view),
                None,
            ))
            .unwrap();
        let other_epoch = watch_position("epoch:other", 11);
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                other_epoch,
                None,
                None,
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::StreamResetMissing
            ))
        ));

        let mut processor = TaskWatchProcessor::default();
        processor
            .process(watch_frame(
                StreamFrameKind::Heartbeat,
                watch_position("epoch:watch", 20),
                None,
                None,
            ))
            .unwrap();
        assert!(matches!(
            processor.process(watch_frame(
                StreamFrameKind::Heartbeat,
                watch_position("epoch:watch", 19),
                None,
                None,
            )),
            Err(ClientTaskWatchError::Kernel(KernelError::StreamOutOfOrder))
        ));
    }

    #[test]
    fn task_watch_resume_pair_is_all_or_nothing() {
        assert_eq!(
            task_watch_resume_after(TaskWatchRequest::default()).unwrap(),
            None
        );
        assert_eq!(
            task_watch_resume_after(TaskWatchRequest {
                resume_epoch: Some("epoch:watch".to_owned()),
                resume_sequence: Some(12),
            })
            .unwrap(),
            Some(ProjectionPosition {
                epoch: "epoch:watch".to_owned(),
                sequence: 12,
                projected_at: None,
            })
        );
        for request in [
            TaskWatchRequest {
                resume_epoch: Some("epoch:watch".to_owned()),
                resume_sequence: None,
            },
            TaskWatchRequest {
                resume_epoch: None,
                resume_sequence: Some(12),
            },
        ] {
            assert!(matches!(
                task_watch_resume_after(request),
                Err(ClientTaskWatchError::InvalidResumePair)
            ));
        }
    }

    #[test]
    fn task_watch_open_seam_authorizes_once_and_dispatches_complete_session_request() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:watch",
            "session:watch",
            "local.task.read",
            ClientSurface::Tui,
            now,
        );
        let calls = Cell::new(0_u64);
        let captured = RefCell::new(None);
        let opened = block_on_ready(open_task_watch_via(
            &kernel,
            TaskWatchRequest {
                resume_epoch: Some("epoch:resume".to_owned()),
                resume_sequence: Some(44),
            },
            now,
            |request| {
                calls.set(calls.get() + 1);
                captured.replace(Some(request));
                std::future::ready(Ok("opened"))
            },
        ))
        .unwrap();
        assert_eq!(opened, "opened");
        assert_eq!(calls.get(), 1);
        let request = captured.borrow_mut().take().unwrap();
        let client = request.client.unwrap();
        assert!(!client.request_id.is_empty());
        assert_eq!(client.client_instance_id, "client:context-revoke");
        assert_eq!(client.surface, ClientSurface::Tui as i32);
        assert_eq!(client.session_id, "session:watch");
        assert_eq!(client.api_contract_ref, Some(api_contract_ref()));
        assert!(client.correlation_id.is_none());
        assert_eq!(
            request.resume_after,
            Some(ProjectionPosition {
                epoch: "epoch:resume".to_owned(),
                sequence: 44,
                projected_at: None,
            })
        );
        assert!(request.task_ids.is_empty());
        assert!(request.status_filter.is_empty());

        let denied = authenticated_kernel_for_surface(
            "founder:watch",
            "session:watch-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let denied_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(open_task_watch_via(
                &denied,
                TaskWatchRequest::default(),
                now,
                |_request| {
                    denied_calls.set(denied_calls.get() + 1);
                    std::future::ready(Ok(()))
                },
            )),
            Err(ClientTaskWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.task.read"
        ));
        assert_eq!(denied_calls.get(), 0);
    }

    #[test]
    fn attachment_keeps_surface_in_the_shared_kernel_boundary() {
        let kernel =
            ClientKernel::new("egopulse-test", ClientSurface::Tui).expect("valid client kernel");
        assert_eq!(kernel.surface(), ClientSurface::Tui);
    }

    #[test]
    fn task_digest_covers_apply_founder_verdict_with_authority_compatible_metadata_clearing() {
        let mut command = TaskCommand {
            command: Some(task_command::Command::ApplyFounderVerdict(
                egopulse_domain_contracts::v01::egopulse::task::v1::ApplyFounderVerdictCommand {
                    meta: Some(command_metadata("correlation", "client/task-apply")),
                    task_id: "task-1".to_owned(),
                    expected_revision: 7,
                    work_revision: 2,
                    founder_verdict_id: "founder-verdict-1".to_owned(),
                },
            )),
        };
        let expected = canonical_task_digest(&command);
        set_task_digest(&mut command);
        let actual = match command.command.as_ref().expect("command") {
            task_command::Command::ApplyFounderVerdict(value) => value
                .meta
                .as_ref()
                .expect("metadata")
                .request_digest_sha256
                .clone(),
            _ => unreachable!(),
        };
        assert_eq!(actual, expected);
        assert_eq!(canonical_task_digest(&command), expected);
    }

    #[test]
    fn context_revoke_prepare_matches_fixed_canonical_and_protobuf_oracles() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let input = context_revoke_input();
        let canonical_bytes = ContextRevokeSemanticRequest {
            founder_principal_id: "founder:alice",
            snapshot_id: &input.snapshot_id,
            expected_state_revision: input.expected_state_revision,
            reason_code: &input.reason_code,
            evidence_refs: &input.evidence_refs,
            confirmation_proof_ref: &input.confirmation_proof_ref,
        }
        .canonical_bytes();
        assert_eq!(
            hex::encode(canonical_bytes),
            FIXED_CONTEXT_REVOKE_CANONICAL_HEX
        );

        let prepared =
            prepare_context_revoke_with_kernel(&kernel, input).expect("prepare Context revoke");

        assert_eq!(prepared.snapshot_id(), "ctx:001");
        assert_eq!(prepared.expected_state_revision(), 2);
        assert_eq!(prepared.evidence_count(), 2);
        assert_eq!(
            prepared.request_digest_sha256(),
            FIXED_CONTEXT_REVOKE_DIGEST
        );
        let request =
            build_context_revoke_request(&kernel, &prepared, FIXED_CONTEXT_REVOKE_DIGEST, now)
                .expect("build Context revoke request");
        assert_eq!(
            hex::encode(normalized_context_revoke_mutation_bytes(request)),
            FIXED_CONTEXT_REVOKE_MUTATION_HEX
        );
    }

    #[test]
    fn context_revoke_cli_and_tui_share_identical_semantic_command_bytes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let cli_kernel = authenticated_kernel_for_surface(
            "founder:alice",
            "session:context-revoke:surface",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let tui_kernel = authenticated_kernel_for_surface(
            "founder:alice",
            "session:context-revoke:surface",
            "local.context.revoke",
            ClientSurface::Tui,
            now,
        );
        let cli_prepared = prepare_context_revoke_with_kernel(&cli_kernel, context_revoke_input())
            .expect("prepare CLI Context revoke");
        let tui_prepared = prepare_context_revoke_with_kernel(&tui_kernel, context_revoke_input())
            .expect("prepare TUI Context revoke");
        let cli_request = build_context_revoke_request(
            &cli_kernel,
            &cli_prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
        )
        .expect("build CLI Context revoke request");
        let tui_request = build_context_revoke_request(
            &tui_kernel,
            &tui_prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
        )
        .expect("build TUI Context revoke request");

        let cli_client = cli_request.client.as_ref().expect("CLI client metadata");
        let tui_client = tui_request.client.as_ref().expect("TUI client metadata");
        assert_eq!(cli_client.surface, ClientSurface::Cli as i32);
        assert_eq!(tui_client.surface, ClientSurface::Tui as i32);
        assert_ne!(cli_client.request_id, tui_client.request_id);

        let cli_semantic_bytes = normalized_context_revoke_mutation_bytes(cli_request);
        let tui_semantic_bytes = normalized_context_revoke_mutation_bytes(tui_request);
        assert_eq!(cli_semantic_bytes, tui_semantic_bytes);
        assert_eq!(
            hex::encode(cli_semantic_bytes),
            FIXED_CONTEXT_REVOKE_MUTATION_HEX
        );
    }

    #[test]
    fn context_revoke_permission_denial_happens_during_prepare() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:denied",
            "local.task.read",
            now,
        );

        assert!(matches!(
            prepare_context_revoke_with_kernel(&kernel, context_revoke_input()),
            Err(ClientContextRevokeError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.context.revoke"
        ));
    }

    #[test]
    fn context_revoke_invalid_confirmation_never_calls_transport() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let transport_calls = Cell::new(0_u64);

        for supplied_digest in [
            String::new(),
            FIXED_CONTEXT_REVOKE_DIGEST[..63].to_owned(),
            format!("{FIXED_CONTEXT_REVOKE_DIGEST}0"),
            format!(" {FIXED_CONTEXT_REVOKE_DIGEST}"),
            format!("{FIXED_CONTEXT_REVOKE_DIGEST} "),
            FIXED_CONTEXT_REVOKE_DIGEST.to_uppercase(),
            "a".repeat(64),
        ] {
            let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
                .expect("prepare Context revoke");
            let result = block_on_ready(execute_context_revoke_via(
                &kernel,
                prepared,
                &supplied_digest,
                now,
                |_request| {
                    transport_calls.set(transport_calls.get() + 1);
                    std::future::ready(Err("transport must not run".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientContextRevokeError::InvalidConfirmation)
            ));
        }
        assert_eq!(transport_calls.get(), 0);
    }

    #[test]
    fn context_revoke_prepare_is_bound_to_session_and_principal_without_rpc() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let preparation_kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let transport_calls = Cell::new(0_u64);

        for execution_kernel in [
            authenticated_kernel(
                "founder:alice",
                "session:context-revoke:2",
                "local.context.revoke",
                now,
            ),
            authenticated_kernel(
                "founder:bob",
                "session:context-revoke:1",
                "local.context.revoke",
                now,
            ),
        ] {
            let prepared =
                prepare_context_revoke_with_kernel(&preparation_kernel, context_revoke_input())
                    .expect("prepare Context revoke");
            let result = block_on_ready(execute_context_revoke_via(
                &execution_kernel,
                prepared,
                FIXED_CONTEXT_REVOKE_DIGEST,
                now,
                |_request| {
                    transport_calls.set(transport_calls.get() + 1);
                    std::future::ready(Err("transport must not run".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientContextRevokeError::SessionChanged)
            ));
        }
        assert_eq!(transport_calls.get(), 0);
    }

    #[test]
    fn context_revoke_execute_preserves_semantics_idempotency_and_sanitized_receipt() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let transport_calls = Cell::new(0_u64);

        let receipt = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |request| {
                transport_calls.set(transport_calls.get() + 1);
                let client = request.client.expect("client metadata");
                assert_eq!(client.session_id, "session:context-revoke:1");
                let context_mutation_command::Command::RevokeContextSnapshot(command) = request
                    .command
                    .and_then(|command| command.command)
                    .expect("Context mutation command");
                let metadata = command.metadata.expect("command metadata");
                assert_eq!(metadata.idempotency_key, "idempotency:context-revoke:1");
                assert_eq!(metadata.idempotency_scope, CONTEXT_REVOKE_IDEMPOTENCY_SCOPE);
                assert_eq!(metadata.request_digest_sha256, FIXED_CONTEXT_REVOKE_DIGEST);
                assert_eq!(command.snapshot_id, "ctx:001");
                assert_eq!(command.expected_state_revision, 2);
                assert_eq!(command.reason_code, "withdrawn");
                assert_eq!(command.evidence_refs, ["evidence:1", "evidence:2"]);
                assert_eq!(command.confirmation_proof_ref, "proof:local:1");
                std::future::ready(Ok(ExecuteContextMutationResponse {
                    outcome: Some(execute_context_mutation_response::Outcome::AuthorityResult(
                        success_context_revoke_receipt(),
                    )),
                }))
            },
        ))
        .expect("execute Context revoke");

        assert_eq!(transport_calls.get(), 1);
        assert_eq!(receipt, success_context_revoke_receipt());
    }

    #[test]
    fn context_revoke_response_errors_and_missing_outcomes_remain_typed() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel(
            "founder:alice",
            "session:context-revoke:1",
            "local.context.revoke",
            now,
        );
        let api_error = LocalApiError {
            code: LocalApiErrorCode::StateRevisionConflict as i32,
            safe_fingerprint: "context-revoke/cas-conflict/v1".to_owned(),
            retryable: false,
            required_action_code: Some("refresh-context-state".to_owned()),
            current_position: None,
            correlation_id: "correlation:context-revoke".to_owned(),
        };
        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let result = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |_request| {
                std::future::ready(Ok(ExecuteContextMutationResponse {
                    outcome: Some(execute_context_mutation_response::Outcome::Error(
                        api_error.clone(),
                    )),
                }))
            },
        ));
        assert!(matches!(
            result,
            Err(ClientContextRevokeError::Api(error)) if *error == api_error
        ));

        let prepared = prepare_context_revoke_with_kernel(&kernel, context_revoke_input())
            .expect("prepare Context revoke");
        let result = block_on_ready(execute_context_revoke_via(
            &kernel,
            prepared,
            FIXED_CONTEXT_REVOKE_DIGEST,
            now,
            |_request| std::future::ready(Ok(ExecuteContextMutationResponse { outcome: None })),
        ));
        assert!(matches!(
            result,
            Err(ClientContextRevokeError::MalformedResponse(
                "outcome missing"
            ))
        ));
    }

    #[test]
    fn approval_baseline_is_complete_actionable_sorted_and_capped() {
        let position = approval_position(7);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let (actual_position, approvals) = compile_approval_baseline(vec![
            approval_page(
                &position,
                vec![
                    approval_view("approval:z", &position, Some(decide)),
                    approval_view("approval:closed", &position, None),
                ],
                Some("cursor:2"),
            ),
            approval_page(
                &position,
                vec![approval_view("approval:a", &position, Some(decide))],
                None,
            ),
        ])
        .expect("complete approval baseline");
        assert_eq!(actual_position, position);
        assert_eq!(
            approvals.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:a", "approval:z"]
        );

        let views: Vec<_> = (0..=APPROVAL_WATCH_BASELINE_MAX_VIEWS)
            .map(|index| approval_view(format!("approval:{index:04}"), &position, Some(decide)))
            .collect();
        let pages = views
            .chunks(APPROVAL_WATCH_BASELINE_PAGE_SIZE as usize)
            .enumerate()
            .map(|(index, chunk)| {
                let next = (index + 1
                    < views
                        .len()
                        .div_ceil(APPROVAL_WATCH_BASELINE_PAGE_SIZE as usize))
                .then(|| format!("cursor:{}", index + 1));
                approval_page(&position, chunk.to_vec(), next.as_deref())
            })
            .collect();
        assert!(matches!(
            compile_approval_baseline(pages),
            Err(ClientApprovalWatchError::BaselineLimitExceeded)
        ));
    }

    #[test]
    fn guided_approval_reads_latest_view_and_seals_all_three_decisions() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(13_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-approval",
            "session:guided-approval",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(12);
        for (decision, replayed) in [
            (GuidedApprovalDecision::AllowOnce, false),
            (GuidedApprovalDecision::Deny, false),
            (GuidedApprovalDecision::CancelAttempt, true),
        ] {
            let get_request = RefCell::new(None);
            let decide_request = RefCell::new(None);
            let warning = (decision == GuidedApprovalDecision::CancelAttempt)
                .then(|| local_api_error(LocalApiErrorCode::ProjectionBehind));
            let result = block_on_ready(decide_guided_approval_via(
                &kernel,
                guided_approval_input(decision),
                now,
                |request| {
                    get_request.replace(Some(request));
                    std::future::ready(Ok(GetHarnessApprovalViewResponse {
                        outcome: Some(get_harness_approval_view_response::Outcome::View(
                            approval_view(
                                "approval:guided:1",
                                &position,
                                Some(AvailableActionKind::DecideHarnessApproval as i32),
                            ),
                        )),
                    }))
                },
                |request| {
                    decide_request.replace(Some(request));
                    std::future::ready(Ok(guided_approval_response(
                        decision,
                        replayed,
                        warning.clone(),
                    )))
                },
            ))
            .expect("guided approval decision");
            assert!(result.committed());
            assert_eq!(result.replayed(), replayed);
            assert_eq!(result.decision(), decision);
            assert_eq!(result.authority_decision_ref(), "policy-decision:guided:1");
            assert_eq!(result.projection_warning(), warning.as_ref());

            let get = get_request.into_inner().expect("Get request");
            assert_eq!(get.approval_request_id, "approval:guided:1");
            assert!(get.minimum_position.is_none());
            let request = decide_request.into_inner().expect("Decide request");
            let client = request.client.expect("command client metadata");
            assert_eq!(client.session_id, "session:guided-approval");
            assert_eq!(
                client.correlation_id.as_deref(),
                Some(result.correlation_id())
            );
            let command = request.command.expect("sealed approval command");
            assert_eq!(command.approval_request_id, "approval:guided:1");
            assert_eq!(command.expected_action_digest_sha256, "b".repeat(64));
            assert_eq!(
                command.expected_request_observation_id,
                "observation:approval:guided:1"
            );
            assert_eq!(command.expected_request_observation_sequence, 1);
            assert_eq!(command.expected_request_revision, 1);
            assert_eq!(command.decision, decision.wire_value());
            assert_eq!(command.reason_code, "  founder-reviewed  ");
            assert_eq!(
                command.confirmation_proof_ref.as_deref(),
                Some("proof:approval:1")
            );
            let sealed_digest = command
                .metadata
                .as_ref()
                .expect("command metadata")
                .request_digest_sha256
                .clone();
            assert!(is_canonical_sha256(&sealed_digest));
            let mut wrapped = PolicyDecisionCommand {
                command: Some(
                    policy_decision_command::Command::IssueHarnessApprovalDecision(command),
                ),
            };
            set_policy_digest(&mut wrapped);
            let policy_decision_command::Command::IssueHarnessApprovalDecision(recomputed) =
                wrapped.command.expect("issue command")
            else {
                unreachable!("test command branch")
            };
            assert_eq!(
                recomputed
                    .metadata
                    .expect("recomputed metadata")
                    .request_digest_sha256,
                sealed_digest
            );
        }
    }

    #[test]
    fn guided_approval_uses_stable_idempotency_and_semantic_digest() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(13_500);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-idempotency",
            "session:guided-idempotency",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(13);
        let base = guided_approval_input(GuidedApprovalDecision::AllowOnce);
        let first = sealed_guided_approval_command(&kernel, &position, base.clone(), now);
        let replay = sealed_guided_approval_command(
            &kernel,
            &position,
            base.clone(),
            now + Duration::from_secs(1),
        );
        let changed_decision = sealed_guided_approval_command(
            &kernel,
            &position,
            GuidedApprovalDecisionInput {
                decision: GuidedApprovalDecision::Deny,
                ..base.clone()
            },
            now + Duration::from_secs(2),
        );
        let changed_reason = sealed_guided_approval_command(
            &kernel,
            &position,
            GuidedApprovalDecisionInput {
                reason_code: "founder-reconsidered".to_owned(),
                ..base
            },
            now + Duration::from_secs(3),
        );

        fn metadata(command: &IssueHarnessApprovalDecisionCommand) -> &CommandMetadata {
            command.metadata.as_ref().expect("command metadata")
        }
        assert_eq!(
            metadata(&first).idempotency_key,
            guided_approval_idempotency_key("approval:guided:1")
        );
        assert_eq!(
            metadata(&first).idempotency_key,
            metadata(&replay).idempotency_key
        );
        assert_eq!(
            metadata(&first).request_digest_sha256,
            metadata(&replay).request_digest_sha256
        );
        assert_ne!(metadata(&first).command_id, metadata(&replay).command_id);
        for changed in [&changed_decision, &changed_reason] {
            assert_eq!(
                metadata(&first).idempotency_key,
                metadata(changed).idempotency_key
            );
            assert_ne!(
                metadata(&first).request_digest_sha256,
                metadata(changed).request_digest_sha256
            );
        }
    }

    #[test]
    fn guided_approval_preflights_both_permissions_and_input_before_rpc() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(14_000);
        for permissions in [&["local.approval.read"][..], &["local.approval.decide"][..]] {
            let kernel = authenticated_kernel_with_permissions(
                "founder:guided-denied",
                "session:guided-denied",
                permissions,
                ClientSurface::Cli,
                now,
            );
            let gets = Cell::new(0_u64);
            let decisions = Cell::new(0_u64);
            let result = block_on_ready(decide_guided_approval_via(
                &kernel,
                guided_approval_input(GuidedApprovalDecision::Deny),
                now,
                |_request| {
                    gets.set(gets.get() + 1);
                    std::future::ready(Err("must-not-get".to_owned()))
                },
                |_request| {
                    decisions.set(decisions.get() + 1);
                    std::future::ready(Err("must-not-decide".to_owned()))
                },
            ));
            assert!(matches!(
                result,
                Err(ClientGuidedApprovalDecisionError::Kernel(
                    KernelError::PermissionDenied(_)
                ))
            ));
            assert_eq!(gets.get(), 0);
            assert_eq!(decisions.get(), 0);
        }

        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-invalid",
            "session:guided-invalid",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        for input in [
            GuidedApprovalDecisionInput {
                approval_request_id: " \t ".to_owned(),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
            GuidedApprovalDecisionInput {
                reason_code: " \t ".to_owned(),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
            GuidedApprovalDecisionInput {
                confirmation_proof_ref: Some("  ".to_owned()),
                ..guided_approval_input(GuidedApprovalDecision::AllowOnce)
            },
        ] {
            let gets = Cell::new(0_u64);
            let decisions = Cell::new(0_u64);
            assert!(matches!(
                block_on_ready(decide_guided_approval_via(
                    &kernel,
                    input,
                    now,
                    |_request| {
                        gets.set(gets.get() + 1);
                        std::future::ready(Err("must-not-get".to_owned()))
                    },
                    |_request| {
                        decisions.set(decisions.get() + 1);
                        std::future::ready(Err("must-not-decide".to_owned()))
                    },
                )),
                Err(ClientGuidedApprovalDecisionError::InvalidInput(_))
            ));
            assert_eq!(gets.get(), 0);
            assert_eq!(decisions.get(), 0);
        }
    }

    #[test]
    fn guided_approval_rejects_missing_non_actionable_and_mismatched_latest_views() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(15_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-view",
            "session:guided-view",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(15);
        let decisions = Cell::new(0_u64);
        let not_found = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::Error(
                        local_api_error(LocalApiErrorCode::NotFound),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            not_found,
            Err(ClientGuidedApprovalDecisionError::NotFound)
        ));

        let non_actionable = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view("approval:guided:1", &position, None),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            non_actionable,
            Err(ClientGuidedApprovalDecisionError::NonActionable)
        ));

        let mismatch = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::Deny),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::View(
                        approval_view(
                            "approval:different",
                            &position,
                            Some(AvailableActionKind::DecideHarnessApproval as i32),
                        ),
                    )),
                }))
            },
            |_request| {
                decisions.set(decisions.get() + 1);
                std::future::ready(Err("must-not-decide".to_owned()))
            },
        ));
        assert!(matches!(
            mismatch,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "approval view binding invalid"
            ))
        ));
        assert_eq!(decisions.get(), 0);
    }

    #[test]
    #[allow(deprecated)]
    fn guided_approval_preserves_api_authority_transport_and_protocol_failures() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(16_000);
        let kernel = authenticated_kernel_with_permissions(
            "founder:guided-failures",
            "session:guided-failures",
            &["local.approval.read", "local.approval.decide"],
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(16);
        let latest = || GetHarnessApprovalViewResponse {
            outcome: Some(get_harness_approval_view_response::Outcome::View(
                approval_view(
                    "approval:guided:1",
                    &position,
                    Some(AvailableActionKind::DecideHarnessApproval as i32),
                ),
            )),
        };

        let api = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| {
                std::future::ready(Ok(GetHarnessApprovalViewResponse {
                    outcome: Some(get_harness_approval_view_response::Outcome::Error(
                        local_api_error(LocalApiErrorCode::ProjectionBehind),
                    )),
                }))
            },
            |_request| std::future::ready(Err("must-not-decide".to_owned())),
        ));
        assert!(matches!(
            api,
            Err(ClientGuidedApprovalDecisionError::Api(_))
        ));

        let get_transport = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Err("get-status".to_owned())),
            |_request| std::future::ready(Err("must-not-decide".to_owned())),
        ));
        assert!(matches!(
            get_transport,
            Err(ClientGuidedApprovalDecisionError::Transport(detail)) if detail == "get-status"
        ));

        let decide_transport = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Err("decide-status".to_owned())),
        ));
        assert!(matches!(
            decide_transport,
            Err(ClientGuidedApprovalDecisionError::Transport(detail)) if detail == "decide-status"
        ));

        let mut authority_failure =
            guided_approval_response(GuidedApprovalDecision::AllowOnce, false, None);
        let authority = authority_failure
            .sanitized_authority_result
            .as_mut()
            .expect("sanitized result");
        authority.committed = false;
        authority.error_code = PolicyDecisionErrorCode::RevisionConflict as i32;
        authority.safe_error_fingerprint = Some("approval/revision-conflict/v1".to_owned());
        let authority = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Ok(authority_failure)),
        ));
        assert!(matches!(
            authority,
            Err(ClientGuidedApprovalDecisionError::Authority {
                error_code,
                ..
            }) if error_code == PolicyDecisionErrorCode::RevisionConflict as i32
        ));

        let protocol = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| {
                std::future::ready(Ok(DecideHarnessApprovalResponse {
                    await_token: None,
                    gateway_error: None,
                    policy_authority_result: None,
                    sanitized_authority_result: None,
                }))
            },
        ));
        assert!(matches!(
            protocol,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result missing"
            ))
        ));

        let mut wrong_state =
            guided_approval_response(GuidedApprovalDecision::AllowOnce, false, None);
        wrong_state
            .sanitized_authority_result
            .as_mut()
            .expect("sanitized result")
            .state = HarnessApprovalDecisionStateKind::Revoked as i32;
        let wrong_state = block_on_ready(decide_guided_approval_via(
            &kernel,
            guided_approval_input(GuidedApprovalDecision::AllowOnce),
            now,
            |_request| std::future::ready(Ok(latest())),
            |_request| std::future::ready(Ok(wrong_state)),
        ));
        assert!(matches!(
            wrong_state,
            Err(ClientGuidedApprovalDecisionError::Protocol(
                "sanitized approval result invalid"
            ))
        ));
    }

    #[test]
    fn approval_baseline_rejects_position_cursor_and_identity_drift() {
        let position = approval_position(7);
        let other_position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let valid = || approval_view("approval:1", &position, Some(decide));

        let cases = [
            vec![
                approval_page(&position, vec![valid()], Some("cursor:2")),
                approval_page(
                    &other_position,
                    vec![approval_view("approval:2", &other_position, Some(decide))],
                    None,
                ),
            ],
            vec![approval_page(&position, Vec::new(), Some("cursor:2"))],
            vec![
                approval_page(&position, vec![valid()], Some("cursor:same")),
                approval_page(
                    &position,
                    vec![approval_view("approval:2", &position, Some(decide))],
                    Some("cursor:same"),
                ),
            ],
            vec![approval_page(
                &position,
                vec![
                    valid(),
                    approval_view("approval:1", &position, Some(decide)),
                ],
                None,
            )],
            vec![approval_page(
                &position,
                vec![approval_view("", &position, Some(decide))],
                None,
            )],
        ];
        for pages in cases {
            assert!(compile_approval_baseline(pages).is_err());
        }

        let unknown_action = approval_view("approval:unknown", &position, Some(i32::MAX));
        assert!(matches!(
            compile_approval_baseline(vec![approval_page(&position, vec![unknown_action], None,)]),
            Err(ClientApprovalWatchError::Protocol(
                "approval action kind is unknown"
            ))
        ));
    }

    #[test]
    fn approval_baseline_read_seam_authorizes_once_and_follows_the_cursor_chain() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(11_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-baseline",
            "session:approval-baseline",
            "local.approval.read",
            ClientSurface::Cli,
            now,
        );
        let position = approval_position(100);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut replies = VecDeque::from([
            Ok(approval_page(
                &position,
                vec![approval_view("approval:b", &position, Some(decide))],
                Some("cursor:2"),
            )),
            Ok(approval_page(
                &position,
                vec![approval_view("approval:a", &position, Some(decide))],
                None,
            )),
        ]);
        let mut requests = Vec::new();
        let baseline = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |request| {
                requests.push(request);
                std::future::ready(replies.pop_front().expect("scripted page"))
            },
        ))
        .expect("complete production pagination seam");
        assert!(replies.is_empty());
        assert_eq!(baseline.position(), &position);
        assert_eq!(
            baseline
                .actionable_approvals()
                .into_iter()
                .map(ActionableApproval::approval_request_id)
                .collect::<Vec<_>>(),
            ["approval:a", "approval:b"]
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].page_cursor, None);
        assert_eq!(requests[1].page_cursor.as_deref(), Some("cursor:2"));
        for request in &requests {
            assert!(request.actionable_only);
            assert_eq!(request.page_size, 100);
            assert!(request.minimum_position.is_none());
            assert!(request.task_ids.is_empty());
        }
        assert_eq!(requests[0].client, requests[1].client);
        let metadata = requests[0].client.as_ref().expect("session metadata");
        assert_eq!(metadata.session_id, "session:approval-baseline");
        assert_eq!(metadata.surface, ClientSurface::Cli as i32);

        let denied = authenticated_kernel_for_surface(
            "founder:approval-baseline",
            "session:approval-baseline-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let dispatches = Cell::new(0_u64);
        let denied = block_on_ready(read_actionable_approval_queue_via(
            &denied,
            now,
            |_request| {
                dispatches.set(dispatches.get() + 1);
                std::future::ready(Err("must-not-dispatch".to_owned()))
            },
        ));
        assert!(matches!(
            denied,
            Err(ClientApprovalWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.approval.read"
        ));
        assert_eq!(dispatches.get(), 0);
    }

    #[test]
    fn approval_baseline_read_seam_fails_atomically_for_remote_and_pagination_drift() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(12_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-baseline-failure",
            "session:approval-baseline-failure",
            "local.approval.read",
            ClientSurface::Tui,
            now,
        );
        let position = approval_position(100);
        let other_position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let one = || approval_view("approval:1", &position, Some(decide));

        let mut position_drift = VecDeque::from([
            Ok(approval_page(&position, vec![one()], Some("cursor:2"))),
            Ok(approval_page(
                &other_position,
                vec![approval_view("approval:2", &other_position, Some(decide))],
                None,
            )),
        ]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    position_drift.pop_front().expect("position drift page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline position changed across pages"
            ))
        ));

        let mut repeated_cursor = VecDeque::from([
            Ok(approval_page(&position, vec![one()], Some("cursor:same"))),
            Ok(approval_page(
                &position,
                vec![approval_view("approval:2", &position, Some(decide))],
                Some("cursor:same"),
            )),
        ]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    repeated_cursor.pop_front().expect("repeated cursor page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance"
            ))
        ));

        let mut empty_with_cursor = VecDeque::from([Ok(approval_page(
            &position,
            Vec::new(),
            Some("cursor:next"),
        ))]);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| std::future::ready(
                    empty_with_cursor.pop_front().expect("empty cursor page")
                ),
            )),
            Err(ClientApprovalWatchError::Protocol(
                "approval baseline cursor did not advance"
            ))
        ));

        let mut oversized_pages = VecDeque::new();
        for page_index in 0..=10 {
            let item_count = if page_index == 10 { 1 } else { 100 };
            let views = (0..item_count)
                .map(|item_index| {
                    approval_view(
                        format!("approval:{page_index:02}:{item_index:03}"),
                        &position,
                        Some(decide),
                    )
                })
                .collect();
            let next = (page_index < 10).then(|| format!("cursor:{}", page_index + 1));
            oversized_pages.push_back(Ok(approval_page(&position, views, next.as_deref())));
        }
        let oversized_dispatches = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(read_actionable_approval_queue_via(
                &kernel,
                now,
                |_request| {
                    oversized_dispatches.set(oversized_dispatches.get() + 1);
                    std::future::ready(oversized_pages.pop_front().expect("oversized page"))
                },
            )),
            Err(ClientApprovalWatchError::BaselineLimitExceeded)
        ));
        assert_eq!(oversized_dispatches.get(), 11);

        let api_error = LocalApiError {
            code: LocalApiErrorCode::StateRevisionConflict as i32,
            safe_fingerprint: "approval-baseline/unavailable/v1".to_owned(),
            retryable: true,
            required_action_code: Some("retry-read".to_owned()),
            current_position: None,
            correlation_id: "correlation:approval-baseline".to_owned(),
        };
        let api_dispatches = Cell::new(0_u64);
        let api_result = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |_request| {
                api_dispatches.set(api_dispatches.get() + 1);
                std::future::ready(Ok(ListHarnessApprovalViewsResponse {
                    views: vec![one()],
                    next_page_cursor: None,
                    snapshot_position: Some(position.clone()),
                    error: Some(api_error.clone()),
                }))
            },
        ));
        assert!(matches!(api_result, Err(ClientApprovalWatchError::Api(_))));
        assert_eq!(api_dispatches.get(), 1);

        let transport_dispatches = Cell::new(0_u64);
        let transport = block_on_ready(read_actionable_approval_queue_via(
            &kernel,
            now,
            |_request| {
                transport_dispatches.set(transport_dispatches.get() + 1);
                std::future::ready(Err("tonic-status".to_owned()))
            },
        ));
        assert!(matches!(
            transport,
            Err(ClientApprovalWatchError::Transport(detail)) if detail == "tonic-status"
        ));
        assert_eq!(transport_dispatches.get(), 1);
    }

    #[test]
    fn approval_watch_wire_requests_freeze_baseline_and_live_filters() {
        let metadata = ClientRequestMetadata {
            client_instance_id: "client:approval-watch".to_owned(),
            surface: ClientSurface::Cli as i32,
            session_id: "session:approval-watch".to_owned(),
            request_id: "request:approval-watch".to_owned(),
            api_contract_ref: Some(api_contract_ref()),
            correlation_id: None,
        };
        let baseline =
            approval_baseline_wire_request(metadata.clone(), Some("cursor:next".to_owned()));
        assert_eq!(baseline.client, Some(metadata.clone()));
        assert!(baseline.actionable_only);
        assert_eq!(baseline.page_size, 100);
        assert_eq!(baseline.page_cursor.as_deref(), Some("cursor:next"));
        assert!(baseline.minimum_position.is_none());
        assert!(baseline.task_ids.is_empty());
        assert!(baseline.request_lifecycle_filter.is_empty());
        assert!(baseline.decision_state_filter.is_empty());

        let position = approval_position(11);
        let watch = approval_watch_wire_request(metadata.clone(), Some(position.clone()));
        assert_eq!(watch.client, Some(metadata));
        assert_eq!(watch.resume_after, Some(position));
        assert!(!watch.actionable_only);
        assert!(watch.approval_request_ids.is_empty());
        assert!(watch.task_ids.is_empty());
        assert!(watch.request_lifecycle_filter.is_empty());
        assert!(watch.decision_state_filter.is_empty());
    }

    #[test]
    fn approval_watch_open_seam_authorizes_before_stream_dispatch() {
        use std::cell::RefCell;

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let kernel = authenticated_kernel_for_surface(
            "founder:approval-watch",
            "session:approval-watch",
            "local.approval.read",
            ClientSurface::Cli,
            now,
        );
        let calls = Cell::new(0_u64);
        let captured = RefCell::new(None);
        let position = approval_position(80);
        let opened = block_on_ready(open_approval_stream_via(
            &kernel,
            Some(position.clone()),
            now,
            |request| {
                calls.set(calls.get() + 1);
                captured.replace(Some(request));
                std::future::ready(Ok("opened"))
            },
        ))
        .expect("authorized approval stream");
        assert_eq!(opened, "opened");
        assert_eq!(calls.get(), 1);
        let request = captured.borrow_mut().take().expect("captured request");
        assert_eq!(request.resume_after, Some(position));
        assert!(!request.actionable_only);
        let client = request.client.expect("session metadata");
        assert_eq!(client.session_id, "session:approval-watch");
        assert_eq!(client.surface, ClientSurface::Cli as i32);
        assert_eq!(client.api_contract_ref, Some(api_contract_ref()));

        let denied = authenticated_kernel_for_surface(
            "founder:approval-watch",
            "session:approval-watch-denied",
            "local.context.revoke",
            ClientSurface::Cli,
            now,
        );
        let denied_calls = Cell::new(0_u64);
        assert!(matches!(
            block_on_ready(open_approval_stream_via(&denied, None, now, |_request| {
                denied_calls.set(denied_calls.get() + 1);
                std::future::ready(Ok(()))
            })),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::PermissionDenied(permission)
            )) if permission == "local.approval.read"
        ));
        assert_eq!(denied_calls.get(), 0);
    }

    #[test]
    fn approval_watch_applied_upserts_and_removes_without_fake_remove() {
        let position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let original = approval_view("approval:1", &position, Some(decide));
        let mut actionable = BTreeMap::from([(
            original.approval_request_id.clone(),
            ActionableApproval {
                view: original.clone(),
            },
        )]);
        let mut processor = ApprovalWatchProcessor::default();

        let unknown = approval_view("approval:1", &position, Some(i32::MAX));
        let error = processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position.clone()),
                snapshot: Some(unknown),
                reset_reason_code: None,
            })
            .and_then(|update| apply_approval_watch_update(&mut actionable, &update));
        assert!(matches!(error, Err(ClientApprovalWatchError::Protocol(_))));
        assert_eq!(actionable["approval:1"].view(), &original);

        let later = approval_position(9);
        let closed = approval_view("approval:1", &later, None);
        let update = processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(later),
                snapshot: Some(closed),
                reset_reason_code: None,
            })
            .expect("valid leaving-filter update");
        apply_approval_watch_update(&mut actionable, &update).expect("remove by authoritative id");
        assert!(actionable.is_empty());
        assert_eq!(original.task_id, "task:approval:1");
    }

    #[test]
    fn approval_queue_session_uses_only_its_consumed_baseline_floor() {
        let floor = approval_position(100);
        let mut last_position = floor.clone();
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let current = approval_view("approval:current", &floor, Some(decide));
        let mut actionable = BTreeMap::from([(
            current.approval_request_id.clone(),
            ActionableApproval {
                view: current.clone(),
            },
        )]);

        let old_position = approval_position(80);
        let old = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: old_position.clone(),
            view: Some(approval_view("approval:old", &old_position, Some(decide))),
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &old),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));
        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable["approval:current"].view(), &current);

        let same_position_applied = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: floor.clone(),
            view: Some(approval_view("approval:same", &floor, Some(decide))),
            reset_reason_code: None,
        };
        apply_approval_queue_session_update(
            &mut actionable,
            &mut last_position,
            &same_position_applied,
        )
        .expect("processor-classified same-position identity is applied");

        let next_position = approval_position(101);
        let next = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: next_position.clone(),
            view: Some(approval_view("approval:next", &next_position, Some(decide))),
            reset_reason_code: None,
        };
        apply_approval_queue_session_update(&mut actionable, &mut last_position, &next)
            .expect("post-baseline update");
        assert_eq!(
            actionable.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:current", "approval:next", "approval:same"]
        );

        let other_epoch = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Applied,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: ProjectionPosition {
                epoch: "epoch:other".to_owned(),
                sequence: 101,
                projected_at: None,
            },
            view: None,
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &other_epoch,),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamResetMissing
            ))
        ));
        assert_eq!(actionable.len(), 3);

        let back_to_floor = ApprovalWatchUpdate {
            classification: ApprovalWatchClassification::Replay,
            kind: ApprovalWatchFrameKind::Snapshot,
            position: floor,
            view: Some(current),
            reset_reason_code: None,
        };
        assert!(matches!(
            apply_approval_queue_session_update(
                &mut actionable,
                &mut last_position,
                &back_to_floor,
            ),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));
    }

    #[test]
    fn approval_queue_session_accepts_distinct_same_position_entities_and_rejects_conflicts() {
        let position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut processor = ApprovalWatchProcessor::default();
        let mut actionable = BTreeMap::new();
        let mut last_position = approval_position(100);

        for approval_request_id in ["approval:101:a", "approval:101:b"] {
            let update = processor
                .process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Snapshot as i32,
                    position: Some(position.clone()),
                    snapshot: Some(approval_view(approval_request_id, &position, Some(decide))),
                    reset_reason_code: None,
                })
                .expect("distinct same-position approval is valid");
            assert_eq!(update.classification, ApprovalWatchClassification::Applied);
            apply_approval_queue_session_update(&mut actionable, &mut last_position, &update)
                .expect("session trusts processor classification");
        }
        assert_eq!(last_position, position);
        assert_eq!(
            actionable.keys().map(String::as_str).collect::<Vec<_>>(),
            ["approval:101:a", "approval:101:b"]
        );

        let mut conflicting = approval_view("approval:101:a", &position, Some(decide));
        conflicting.action_digest_sha256 = "c".repeat(64);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position),
                snapshot: Some(conflicting),
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));
        assert_eq!(actionable.len(), 2);
    }

    #[test]
    fn approval_watch_replay_heartbeat_reset_eof_and_transport_are_non_destructive() {
        let position = approval_position(8);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let original = approval_view("approval:1", &position, Some(decide));
        let mut actionable = BTreeMap::new();
        let mut processor = ApprovalWatchProcessor::default();
        let frame = HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::Snapshot as i32,
            position: Some(position.clone()),
            snapshot: Some(original.clone()),
            reset_reason_code: None,
        };
        let first = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(frame.clone()))),
        ))
        .expect("first update")
        .expect("frame");
        assert_eq!(first.classification, ApprovalWatchClassification::Applied);
        let replay = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(frame))),
        ))
        .expect("replay")
        .expect("frame");
        assert_eq!(replay.classification, ApprovalWatchClassification::Replay);

        let heartbeat_position = approval_position(9);
        let heartbeat = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || {
                std::future::ready(Ok(Some(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(heartbeat_position),
                    snapshot: None,
                    reset_reason_code: None,
                })))
            },
        ))
        .expect("heartbeat")
        .expect("frame");
        assert_eq!(
            heartbeat.classification,
            ApprovalWatchClassification::Heartbeat
        );
        assert_eq!(actionable["approval:1"].view(), &original);

        let eof = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(None)),
        ));
        assert!(matches!(eof, Err(ClientApprovalWatchError::UnexpectedEof)));
        let transport = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Err("tonic-status".to_owned())),
        ));
        assert!(matches!(
            transport,
            Err(ClientApprovalWatchError::Transport(_))
        ));
        assert_eq!(actionable["approval:1"].view(), &original);

        let reset = HarnessApprovalViewStreamFrame {
            kind: StreamFrameKind::ResetRequired as i32,
            position: Some(approval_position(10)),
            snapshot: None,
            reset_reason_code: Some("projection_reset".to_owned()),
        };
        let reset = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || std::future::ready(Ok(Some(reset))),
        ))
        .expect("reset frame")
        .expect("frame");
        assert_eq!(
            reset.classification,
            ApprovalWatchClassification::ResetRequired
        );
        let polls = Cell::new(0);
        let blocked = block_on_ready(next_approval_queue_update_via(
            &mut processor,
            &mut actionable,
            || {
                polls.set(polls.get() + 1);
                std::future::ready(Ok(None))
            },
        ));
        assert!(matches!(
            blocked,
            Err(ClientApprovalWatchError::ResetBarrier)
        ));
        assert_eq!(polls.get(), 0);
        assert_eq!(actionable["approval:1"].view(), &original);
    }

    #[test]
    fn approval_watch_rejects_out_of_order_and_same_position_conflicts() {
        let position = approval_position(101);
        let decide = AvailableActionKind::DecideHarnessApproval as i32;
        let mut processor = ApprovalWatchProcessor::default();
        let mut view = approval_view("approval:1", &position, Some(decide));
        processor
            .process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position.clone()),
                snapshot: Some(view.clone()),
                reset_reason_code: None,
            })
            .expect("first frame");
        view.action_digest_sha256 = "c".repeat(64);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Snapshot as i32,
                position: Some(position),
                snapshot: Some(view),
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::ConflictingStreamReplay
            ))
        ));

        let older = approval_position(100);
        assert!(matches!(
            processor.process(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Heartbeat as i32,
                position: Some(older),
                snapshot: None,
                reset_reason_code: None,
            }),
            Err(ClientApprovalWatchError::Kernel(
                KernelError::StreamOutOfOrder
            ))
        ));

        for reason in ["epoch_changed", "cursor_before_retention", "cursor_ahead"] {
            let mut reset_processor = ApprovalWatchProcessor::default();
            let reset = reset_processor
                .process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::ResetRequired as i32,
                    position: Some(approval_position(102)),
                    snapshot: None,
                    reset_reason_code: Some(reason.to_owned()),
                })
                .expect("well-formed reset barrier");
            assert_eq!(
                reset.classification,
                ApprovalWatchClassification::ResetRequired
            );
            assert!(matches!(
                reset_processor.process(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(approval_position(103)),
                    snapshot: None,
                    reset_reason_code: None,
                }),
                Err(ClientApprovalWatchError::ResetBarrier)
            ));
        }
    }
}
