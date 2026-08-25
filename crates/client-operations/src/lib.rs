#![forbid(unsafe_code)]

use std::time::SystemTime;

use egopulse_client_kernel::{ClientKernel, KernelError};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::CommandMetadata,
    localapi::v1::ClientSurface,
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
    if let Some(task_command::Command::CreateTask(create)) = canonical.command.as_mut()
        && let Some(metadata) = create.meta.as_mut()
    {
        clear_command_metadata(Some(metadata));
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_keeps_surface_in_the_shared_kernel_boundary() {
        let kernel =
            ClientKernel::new("egopulse-test", ClientSurface::Tui).expect("valid client kernel");
        assert_eq!(kernel.surface(), ClientSurface::Tui);
    }
}
