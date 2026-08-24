#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    ops::Deref,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::{
    profiles::{ContractProfileError, ContractProfiles as SharedContractProfiles},
    v01::egopulse::{
        common::v1::ContractReference,
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, HarnessApprovalView,
            HarnessApprovalViewStreamFrame, LocalApiError, LocalApiErrorCode, OpenSessionRequest,
            OpenSessionResponse, ProjectionMetadata, ProjectionPosition, SourceDomain,
            StreamFrameKind, TaskView, TaskViewStreamFrame,
        },
    },
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use egopulse_domain_contracts::profiles::{
    API_CONTRACT_DIGEST_SHA256, API_CONTRACT_ID, API_CONTRACT_VERSION, AUTHORIZATION_CONTRACT_ID,
    AUTHORIZATION_CONTRACT_VERSION, AUTHORIZATION_PROFILE_DIGEST_SHA256, AuthorizationDefaults,
    AuthorizationProfile, AuthorizedCommand, CLIENT_KERNEL_CONTRACT_ID,
    CLIENT_KERNEL_CONTRACT_VERSION, CLIENT_KERNEL_PROFILE_DIGEST_SHA256, ClientKernelInvariants,
    ClientKernelProfile, CommandAccess, CommandRule, ConfirmationClass, ImplementationBoundary,
    LocalApiCompatibility, PermissionDefinition, RpcAccess, RpcRule,
};

#[derive(Clone, Debug)]
pub struct ContractProfiles(SharedContractProfiles);

impl ContractProfiles {
    pub fn embedded() -> Result<Self, KernelError> {
        SharedContractProfiles::embedded()
            .map(Self)
            .map_err(map_profile_error)
    }

    #[must_use]
    pub fn permission_codes(&self) -> &BTreeSet<String> {
        self.0.permission_codes()
    }

    pub fn authorize_rpc(&self, rpc: &str, granted: &BTreeSet<String>) -> Result<(), KernelError> {
        self.0
            .authorize_rpc(rpc, granted)
            .map_err(map_profile_error)
    }

    pub fn authorize_command(
        &self,
        rpc: &str,
        oneof: &str,
        granted: &BTreeSet<String>,
    ) -> Result<AuthorizedCommand, KernelError> {
        self.0
            .authorize_command(rpc, oneof, granted)
            .map_err(map_profile_error)
    }
}

impl Deref for ContractProfiles {
    type Target = SharedContractProfiles;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct SessionBinding {
    pub session_id: String,
    pub authenticated_principal_id: String,
    pub granted_permission_codes: BTreeSet<String>,
    pub negotiated_contract_ref: ContractReference,
    pub client_kernel_contract_ref: ContractReference,
    pub authorization_policy_ref: ContractReference,
    pub expires_at: SystemTime,
    pub current_position: ProjectionPosition,
}

#[derive(Clone, Debug)]
pub struct ClientKernel {
    profiles: ContractProfiles,
    client_instance_id: String,
    surface: ClientSurface,
    session: Option<SessionBinding>,
}

impl ClientKernel {
    pub fn new(
        client_instance_id: impl Into<String>,
        surface: ClientSurface,
    ) -> Result<Self, KernelError> {
        let client_instance_id = client_instance_id.into();
        validate_identifier(&client_instance_id)?;
        if !matches!(
            surface,
            ClientSurface::Cli | ClientSurface::Tui | ClientSurface::Desktop
        ) {
            return Err(KernelError::InvalidSurface);
        }
        Ok(Self {
            profiles: ContractProfiles::embedded()?,
            client_instance_id,
            surface,
            session: None,
        })
    }

    #[must_use]
    pub fn profiles(&self) -> &ContractProfiles {
        &self.profiles
    }

    #[must_use]
    pub fn session(&self) -> Option<&SessionBinding> {
        self.session.as_ref()
    }

    pub fn open_session_request(
        &self,
        request_id: impl Into<String>,
    ) -> Result<OpenSessionRequest, KernelError> {
        let request_id = request_id.into();
        validate_identifier(&request_id)?;
        Ok(OpenSessionRequest {
            request_id,
            client_instance_id: self.client_instance_id.clone(),
            surface: self.surface as i32,
            supported_contracts: vec![api_contract_ref()],
        })
    }

    pub fn accept_open_session(
        &mut self,
        response: OpenSessionResponse,
        now: SystemTime,
    ) -> Result<&SessionBinding, KernelError> {
        if let Some(error) = response.error {
            return Err(parse_server_error(error));
        }
        validate_identifier(&response.session_id)?;
        validate_identifier(&response.authenticated_principal_id)?;
        let negotiated =
            exact_contract(response.negotiated_contract_ref, &api_contract_ref(), "api")?;
        let client_kernel = exact_contract(
            response.client_kernel_contract_ref,
            &client_kernel_contract_ref(),
            "client_kernel",
        )?;
        let authorization = exact_contract(
            response.authorization_policy_ref,
            &authorization_contract_ref(),
            "authorization",
        )?;
        let expires_at = response
            .expires_at
            .as_ref()
            .and_then(timestamp_to_system_time)
            .ok_or(KernelError::SessionMalformed("expires_at"))?;
        if expires_at <= now {
            return Err(KernelError::SessionExpired);
        }
        let current_position = response
            .current_position
            .filter(valid_position)
            .ok_or(KernelError::SessionMalformed("current_position"))?;
        if response.granted_permission_codes.is_empty() {
            return Err(KernelError::SessionMalformed("permission_codes"));
        }
        let mut granted = BTreeSet::new();
        for permission in response.granted_permission_codes {
            if !self.profiles.permission_codes().contains(&permission) {
                return Err(KernelError::UnknownPermission(permission));
            }
            if !granted.insert(permission.clone()) {
                return Err(KernelError::DuplicatePermission(permission));
            }
        }
        self.session = Some(SessionBinding {
            session_id: response.session_id,
            authenticated_principal_id: response.authenticated_principal_id,
            granted_permission_codes: granted,
            negotiated_contract_ref: negotiated,
            client_kernel_contract_ref: client_kernel,
            authorization_policy_ref: authorization,
            expires_at,
            current_position,
        });
        self.session
            .as_ref()
            .ok_or(KernelError::SessionMalformed("session"))
    }

    pub fn request_metadata(
        &self,
        request_id: impl Into<String>,
        correlation_id: Option<String>,
        now: SystemTime,
    ) -> Result<ClientRequestMetadata, KernelError> {
        let request_id = request_id.into();
        validate_identifier(&request_id)?;
        if let Some(value) = correlation_id.as_deref() {
            validate_identifier(value)?;
        }
        let session = self
            .session
            .as_ref()
            .ok_or(KernelError::SessionUnavailable)?;
        if session.expires_at <= now {
            return Err(KernelError::SessionExpired);
        }
        Ok(ClientRequestMetadata {
            request_id,
            client_instance_id: self.client_instance_id.clone(),
            surface: self.surface as i32,
            session_id: session.session_id.clone(),
            api_contract_ref: Some(session.negotiated_contract_ref.clone()),
            correlation_id,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SnapshotStreamTracker {
    last_position: Option<ProjectionPosition>,
    last_payload_digest: Option<String>,
    refetch_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamApply {
    Applied,
    Replay,
    Heartbeat,
    ResetRequired,
}

impl SnapshotStreamTracker {
    #[must_use]
    pub fn last_position(&self) -> Option<&ProjectionPosition> {
        self.last_position.as_ref()
    }

    #[must_use]
    pub const fn refetch_required(&self) -> bool {
        self.refetch_required
    }

    pub fn apply_task_frame(
        &mut self,
        frame: &TaskViewStreamFrame,
    ) -> Result<StreamApply, KernelError> {
        if frame.kind == StreamFrameKind::Snapshot as i32
            && frame
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| !valid_task_view(snapshot, frame.position.as_ref()))
        {
            return Err(KernelError::IncompleteStreamFrame);
        }
        self.apply_message(frame.kind, frame.position.clone(), frame.snapshot.as_ref())
    }

    pub fn apply_harness_approval_frame(
        &mut self,
        frame: &HarnessApprovalViewStreamFrame,
    ) -> Result<StreamApply, KernelError> {
        if frame.kind == StreamFrameKind::Snapshot as i32
            && frame.snapshot.as_ref().is_none_or(|snapshot| {
                !valid_harness_approval_view(snapshot, frame.position.as_ref())
            })
        {
            return Err(KernelError::IncompleteStreamFrame);
        }
        self.apply_message(frame.kind, frame.position.clone(), frame.snapshot.as_ref())
    }

    fn apply_message<M: Message>(
        &mut self,
        kind: i32,
        position: Option<ProjectionPosition>,
        snapshot: Option<&M>,
    ) -> Result<StreamApply, KernelError> {
        let kind = StreamFrameKind::try_from(kind).map_err(|_| KernelError::UnknownStreamFrame)?;
        let position = position
            .filter(valid_position)
            .ok_or(KernelError::StreamPositionInvalid)?;
        if kind == StreamFrameKind::Unspecified {
            return Err(KernelError::UnknownStreamFrame);
        }
        if kind == StreamFrameKind::ResetRequired {
            if snapshot.is_some() {
                return Err(KernelError::IncompleteStreamFrame);
            }
            self.last_position = Some(position);
            self.last_payload_digest = None;
            self.refetch_required = true;
            return Ok(StreamApply::ResetRequired);
        }
        if self.refetch_required {
            return Err(KernelError::RefetchRequired);
        }
        if let Some(last) = self.last_position.as_ref() {
            if last.epoch != position.epoch {
                return Err(KernelError::StreamResetMissing);
            }
            if position.sequence < last.sequence {
                return Err(KernelError::StreamOutOfOrder);
            }
        }
        match kind {
            StreamFrameKind::Snapshot => {
                let snapshot = snapshot.ok_or(KernelError::IncompleteStreamFrame)?;
                let digest = sha256_hex(&snapshot.encode_to_vec());
                if self.last_position.as_ref().is_some_and(|last| {
                    last.epoch == position.epoch && last.sequence == position.sequence
                }) {
                    if self.last_payload_digest.as_deref() == Some(digest.as_str()) {
                        return Ok(StreamApply::Replay);
                    }
                    return Err(KernelError::ConflictingStreamReplay);
                }
                self.last_position = Some(position);
                self.last_payload_digest = Some(digest);
                Ok(StreamApply::Applied)
            }
            StreamFrameKind::Heartbeat => {
                if snapshot.is_some() {
                    return Err(KernelError::IncompleteStreamFrame);
                }
                if self
                    .last_position
                    .as_ref()
                    .is_none_or(|last| position.sequence > last.sequence)
                {
                    self.last_position = Some(position);
                    self.last_payload_digest = None;
                }
                Ok(StreamApply::Heartbeat)
            }
            StreamFrameKind::ResetRequired | StreamFrameKind::Unspecified => {
                Err(KernelError::UnknownStreamFrame)
            }
        }
    }

    pub fn mark_refetched(&mut self, position: ProjectionPosition) -> Result<(), KernelError> {
        if !valid_position(&position) {
            return Err(KernelError::StreamPositionInvalid);
        }
        if !self.refetch_required {
            return Err(KernelError::RefetchNotRequired);
        }
        self.last_position = Some(position);
        self.last_payload_digest = None;
        self.refetch_required = false;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct KernelServerError {
    pub code: LocalApiErrorCode,
    pub safe_fingerprint: String,
    pub retryable: bool,
    pub required_action_code: Option<String>,
    pub current_position: Option<ProjectionPosition>,
    pub correlation_id: String,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("embedded contract profile is invalid: {0}")]
    ProfileInvalid(&'static str),
    #[error("embedded contract profile digest does not match the frozen manifest")]
    ProfileDigestMismatch,
    #[error("client surface is invalid")]
    InvalidSurface,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("session is unavailable")]
    SessionUnavailable,
    #[error("session expired")]
    SessionExpired,
    #[error("session response is malformed: {0}")]
    SessionMalformed(&'static str),
    #[error("session contract does not match: {0}")]
    ContractMismatch(&'static str),
    #[error("server rejected the request: {0:?}")]
    ServerRejected(Box<KernelServerError>),
    #[error("server returned an unknown critical error code")]
    UnknownServerError,
    #[error("permission is unknown: {0}")]
    UnknownPermission(String),
    #[error("permission is duplicated: {0}")]
    DuplicatePermission(String),
    #[error("required permission is missing: {0}")]
    PermissionDenied(String),
    #[error("RPC is unknown: {0}")]
    UnknownRpc(String),
    #[error("RPC requires a different authorization path: {0}")]
    WrongAuthorizationPath(String),
    #[error("command oneof is unknown: {rpc}/{oneof}")]
    UnknownCommandOneof { rpc: String, oneof: String },
    #[error("command is system-only: {rpc}/{oneof}")]
    SystemOnlyCommand { rpc: String, oneof: String },
    #[error("stream frame kind is unknown")]
    UnknownStreamFrame,
    #[error("stream frame is incomplete or contradictory")]
    IncompleteStreamFrame,
    #[error("stream position is invalid")]
    StreamPositionInvalid,
    #[error("stream changed epoch without a reset frame")]
    StreamResetMissing,
    #[error("stream frame is out of order")]
    StreamOutOfOrder,
    #[error("same stream position carried a different snapshot")]
    ConflictingStreamReplay,
    #[error("stream reset requires refetch")]
    RefetchRequired,
    #[error("stream refetch was not requested")]
    RefetchNotRequired,
}

#[must_use]
pub fn api_contract_ref() -> ContractReference {
    contract_ref(
        API_CONTRACT_ID,
        API_CONTRACT_VERSION,
        API_CONTRACT_DIGEST_SHA256,
    )
}

#[must_use]
pub fn client_kernel_contract_ref() -> ContractReference {
    contract_ref(
        CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION,
        CLIENT_KERNEL_PROFILE_DIGEST_SHA256,
    )
}

#[must_use]
pub fn authorization_contract_ref() -> ContractReference {
    contract_ref(
        AUTHORIZATION_CONTRACT_ID,
        AUTHORIZATION_CONTRACT_VERSION,
        AUTHORIZATION_PROFILE_DIGEST_SHA256,
    )
}

fn contract_ref(id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn sha256_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn map_profile_error(error: ContractProfileError) -> KernelError {
    match error {
        ContractProfileError::Invalid(section) => KernelError::ProfileInvalid(section),
        ContractProfileError::DigestMismatch => KernelError::ProfileDigestMismatch,
        ContractProfileError::UnknownPermission(permission) => {
            KernelError::UnknownPermission(permission)
        }
        ContractProfileError::PermissionDenied(permission) => {
            KernelError::PermissionDenied(permission)
        }
        ContractProfileError::UnknownRpc(rpc) => KernelError::UnknownRpc(rpc),
        ContractProfileError::WrongAuthorizationPath(rpc) => {
            KernelError::WrongAuthorizationPath(rpc)
        }
        ContractProfileError::UnknownCommandOneof { rpc, oneof } => {
            KernelError::UnknownCommandOneof { rpc, oneof }
        }
        ContractProfileError::SystemOnlyCommand { rpc, oneof } => {
            KernelError::SystemOnlyCommand { rpc, oneof }
        }
    }
}

fn exact_contract(
    actual: Option<ContractReference>,
    expected: &ContractReference,
    kind: &'static str,
) -> Result<ContractReference, KernelError> {
    let actual = actual.ok_or(KernelError::ContractMismatch(kind))?;
    if &actual != expected {
        return Err(KernelError::ContractMismatch(kind));
    }
    Ok(actual)
}

fn parse_server_error(error: LocalApiError) -> KernelError {
    let Ok(code) = LocalApiErrorCode::try_from(error.code) else {
        return KernelError::UnknownServerError;
    };
    if code == LocalApiErrorCode::Unspecified || error.safe_fingerprint.is_empty() {
        return KernelError::UnknownServerError;
    }
    if error
        .current_position
        .as_ref()
        .is_some_and(|value| !valid_position(value))
    {
        return KernelError::UnknownServerError;
    }
    KernelError::ServerRejected(Box::new(KernelServerError {
        code,
        safe_fingerprint: error.safe_fingerprint,
        retryable: error.retryable,
        required_action_code: error.required_action_code,
        current_position: error.current_position,
        correlation_id: error.correlation_id,
    }))
}

fn validate_identifier(value: &str) -> Result<(), KernelError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        Err(KernelError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn valid_position(position: &ProjectionPosition) -> bool {
    !position.epoch.is_empty()
        && position.epoch.len() <= 256
        && position
            .epoch
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn valid_projection_metadata(
    metadata: Option<&ProjectionMetadata>,
    frame_position: Option<&ProjectionPosition>,
) -> bool {
    let (Some(metadata), Some(frame_position)) = (metadata, frame_position) else {
        return false;
    };
    metadata.position.as_ref() == Some(frame_position)
        && metadata.schema_ref.as_ref().is_some_and(valid_contract_ref)
        && metadata.health != 0
        && !metadata.source_revisions.is_empty()
        && metadata.source_revisions.iter().all(|source| {
            SourceDomain::try_from(source.domain)
                .is_ok_and(|domain| domain != SourceDomain::Unspecified)
                && !source.aggregate_id.is_empty()
                && source.revision > 0
                && !source.last_event_id.is_empty()
        })
}

fn valid_task_view(view: &TaskView, frame_position: Option<&ProjectionPosition>) -> bool {
    valid_projection_metadata(view.metadata.as_ref(), frame_position)
        && view
            .task
            .as_ref()
            .is_some_and(|task| !task.task_id.is_empty() && task.revision > 0)
}

fn valid_harness_approval_view(
    view: &HarnessApprovalView,
    frame_position: Option<&ProjectionPosition>,
) -> bool {
    valid_projection_metadata(view.metadata.as_ref(), frame_position)
        && !view.approval_request_id.is_empty()
        && !view.task_id.is_empty()
        && !view.run_id.is_empty()
        && !view.step_id.is_empty()
        && !view.attempt_id.is_empty()
        && !view.dispatch_id.is_empty()
        && view.fencing_token > 0
        && view.action_digest_sha256.len() == 64
        && !view.request_observation_id.is_empty()
        && view.request_observation_sequence > 0
        && view.request_revision > 0
        && view.request_lifecycle != 0
}

fn valid_contract_ref(reference: &ContractReference) -> bool {
    !reference.contract_id.is_empty()
        && !reference.version.is_empty()
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn timestamp_to_system_time(timestamp: &prost_types::Timestamp) -> Option<SystemTime> {
    if timestamp.seconds < 0 || !(0..1_000_000_000).contains(&timestamp.nanos) {
        return None;
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp.seconds as u64))?
        .checked_add(Duration::from_nanos(timestamp.nanos as u64))
}
