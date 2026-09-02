#![forbid(unsafe_code)]

use std::{future::Future, time::SystemTime};

use egopulse_client_kernel::{ClientKernel, KernelError, SnapshotStreamTracker, StreamApply};
use egopulse_domain_contracts::{
    context_revoke::ContextRevokeSemanticRequest,
    v01::egopulse::{
        common::v1::CommandMetadata,
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, ConfirmWorkRequest, ConfirmWorkResponse,
            ContextGovernanceState, ContextMutationCommand, ContextRevokeReceipt,
            ExecuteContextMutationRequest, ExecuteContextMutationResponse,
            GetProjectionStatusRequest, HarnessApprovalView, ListHarnessApprovalViewsRequest,
            ListTaskViewsRequest, LocalApiError, PrepareWorkRequest, ProjectionMetadata,
            ProjectionPosition, RevokeContextSnapshotCommand, StreamFrameKind, TaskView,
            TaskViewStreamFrame, WatchTaskViewsRequest, WorkPreparationPreview, WorkSourceRequest,
            context_mutation_command, execute_context_mutation_response,
        },
        policy::v1::{PolicyDecisionCommand, policy_decision_command},
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

/// A local client that has completed the frozen session and contract handshake.
///
/// Surfaces own presentation and error policy; they do not own a second attach
/// protocol. All writes made from CLI, TUI, and Desktop start from this object.
pub struct ClientAttachment {
    pub connection: LocalApiConnection,
    pub kernel: ClientKernel,
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
        pin::pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use egopulse_client_kernel::{
        api_contract_ref, authorization_contract_ref, client_kernel_contract_ref,
    };
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        LocalApiErrorCode, OpenSessionResponse, ProjectionPosition, SourceDomain, SourceRevision,
        StreamFrameKind,
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
                    granted_permission_codes: vec![permission_code.to_owned()],
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
}
