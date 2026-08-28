#![forbid(unsafe_code)]

use std::time::SystemTime;

use egopulse_client_kernel::{ClientKernel, KernelError};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::CommandMetadata,
    localapi::v1::{
        ClientRequestMetadata, ClientSurface, ConfirmWorkRequest, ConfirmWorkResponse,
        GetProjectionStatusRequest, HarnessApprovalView, ListHarnessApprovalViewsRequest,
        ListTaskViewsRequest, LocalApiError, PrepareWorkRequest, ProjectionMetadata, TaskView,
        WorkPreparationPreview, WorkSourceRequest,
    },
    policy::v1::{PolicyDecisionCommand, policy_decision_command},
    task::v1::{TaskCommand, task_command},
    verdict::v1::{VerdictCommand, verdict_command},
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

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

#[derive(Clone, Debug, PartialEq)]
pub struct ConfirmedWork {
    pub result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
    pub await_token:
        Option<egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionAwaitToken>,
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
    use super::*;

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
}
