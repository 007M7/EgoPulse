#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{
        ClientRequestMetadata, ClientSurface, HarnessApprovalView, HarnessApprovalViewStreamFrame,
        LocalApiError, LocalApiErrorCode, OpenSessionRequest, OpenSessionResponse,
        ProjectionMetadata, ProjectionPosition, SourceDomain, StreamFrameKind, TaskView,
        TaskViewStreamFrame,
    },
};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const API_CONTRACT_ID: &str = "egopulse.localapi.v1";
pub const API_CONTRACT_VERSION: &str = "0.1.0-draft.14";
pub const API_CONTRACT_DIGEST_SHA256: &str =
    "8eadb3686c8dfe76bf8b56fa48d8a76bd7fa57c177804b132eac793d33b7379e";
pub const CLIENT_KERNEL_CONTRACT_ID: &str = "egopulse.client-kernel.v1";
pub const CLIENT_KERNEL_CONTRACT_VERSION: &str = "0.1.0";
pub const CLIENT_KERNEL_PROFILE_DIGEST_SHA256: &str =
    "367ad4210c499d7501acd060f5b544255521cefefca86b8d69a2cea022166c11";
pub const AUTHORIZATION_CONTRACT_ID: &str = "egopulse.authorization.v1";
pub const AUTHORIZATION_CONTRACT_VERSION: &str = "0.1.0";
pub const AUTHORIZATION_PROFILE_DIGEST_SHA256: &str =
    "5ae8cff8552910c780cdde9e29f1a5a3a95e40803ebcbb1de26544de5f6ac29f";

const CLIENT_KERNEL_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/client-kernel/v1/v01-default.json");
const AUTHORIZATION_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/authorization/v1/v01-default.json");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientKernelProfile {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub authority_ref: String,
    pub local_api_compatibility: LocalApiCompatibility,
    pub implementation_boundary: ImplementationBoundary,
    pub capabilities: BTreeSet<String>,
    pub invariants: ClientKernelInvariants,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalApiCompatibility {
    pub contract_id: String,
    pub minimum_version: String,
    pub maximum_version_exclusive: String,
    pub runtime_reference_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImplementationBoundary {
    pub shared_kernel_language: String,
    pub surfaces: BTreeSet<String>,
    pub typescript_business_kernel_allowed: bool,
    pub transport: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientKernelInvariants {
    pub surface_neutral: bool,
    pub complete_snapshot_streams: bool,
    pub ordered_within_epoch: bool,
    pub at_least_once_delivery: bool,
    pub unknown_frame_fail_closed: bool,
    pub gap_requires_reset: bool,
    pub authority_result_preserved: bool,
    pub client_never_becomes_authority: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationProfile {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub authority_ref: String,
    pub local_api_contract_id: String,
    pub defaults: AuthorizationDefaults,
    pub permissions: Vec<PermissionDefinition>,
    pub rpc_rules: Vec<RpcRule>,
    pub command_rules: Vec<CommandRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationDefaults {
    pub unknown_permission: String,
    pub unknown_rpc: String,
    pub unknown_command_oneof: String,
    pub surface_neutral: bool,
    pub session_grant_is_final_authorization: bool,
    pub owning_authority_revalidation_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionDefinition {
    pub code: String,
    pub kind: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RpcAccess {
    AuthenticatedPeerBootstrap,
    GrantedPermission,
    PerCommandOneof,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRule {
    pub rpc: String,
    pub access: RpcAccess,
    pub required_permission_codes: Vec<String>,
    #[serde(default)]
    pub token_scope_enforced: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CommandAccess {
    User,
    SystemOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationClass {
    None,
    AuthorityContract,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandRule {
    pub rpc: String,
    pub oneof: String,
    pub access: CommandAccess,
    pub required_permission_codes: Vec<String>,
    pub confirmation_class: ConfirmationClass,
    pub write_owner: String,
    pub required_authority_principal_kinds: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ContractProfiles {
    pub client_kernel: ClientKernelProfile,
    pub authorization: AuthorizationProfile,
    permission_codes: BTreeSet<String>,
    rpc_rules: BTreeMap<String, RpcRule>,
    command_rules: BTreeMap<(String, String), CommandRule>,
}

impl ContractProfiles {
    pub fn embedded() -> Result<Self, KernelError> {
        verify_digest(
            CLIENT_KERNEL_PROFILE_BYTES,
            CLIENT_KERNEL_PROFILE_DIGEST_SHA256,
        )?;
        verify_digest(
            AUTHORIZATION_PROFILE_BYTES,
            AUTHORIZATION_PROFILE_DIGEST_SHA256,
        )?;
        let client_kernel: ClientKernelProfile =
            serde_json::from_slice(CLIENT_KERNEL_PROFILE_BYTES)
                .map_err(|_| KernelError::ProfileInvalid("client_kernel"))?;
        let authorization: AuthorizationProfile =
            serde_json::from_slice(AUTHORIZATION_PROFILE_BYTES)
                .map_err(|_| KernelError::ProfileInvalid("authorization"))?;
        validate_client_kernel_profile(&client_kernel)?;
        validate_authorization_profile(client_kernel.contract_id.as_str(), &authorization)?;

        let mut permission_codes = BTreeSet::new();
        for permission in &authorization.permissions {
            if permission.code.is_empty()
                || !permission_codes.insert(permission.code.clone())
                || !matches!(permission.kind.as_str(), "read" | "write")
                || permission.description.is_empty()
            {
                return Err(KernelError::ProfileInvalid("authorization_permissions"));
            }
        }

        let mut rpc_rules = BTreeMap::new();
        for rule in &authorization.rpc_rules {
            validate_permission_references(&permission_codes, &rule.required_permission_codes)?;
            if rule.rpc.is_empty() || rpc_rules.insert(rule.rpc.clone(), rule.clone()).is_some() {
                return Err(KernelError::ProfileInvalid("authorization_rpc_rules"));
            }
        }

        let mut command_rules = BTreeMap::new();
        for rule in &authorization.command_rules {
            validate_permission_references(&permission_codes, &rule.required_permission_codes)?;
            if rule.rpc.is_empty()
                || rule.oneof.is_empty()
                || rule.write_owner.is_empty()
                || rule.required_authority_principal_kinds.is_empty()
                || command_rules
                    .insert((rule.rpc.clone(), rule.oneof.clone()), rule.clone())
                    .is_some()
            {
                return Err(KernelError::ProfileInvalid("authorization_command_rules"));
            }
        }

        Ok(Self {
            client_kernel,
            authorization,
            permission_codes,
            rpc_rules,
            command_rules,
        })
    }

    #[must_use]
    pub fn permission_codes(&self) -> &BTreeSet<String> {
        &self.permission_codes
    }

    pub fn authorize_rpc(&self, rpc: &str, granted: &BTreeSet<String>) -> Result<(), KernelError> {
        self.validate_grants(granted)?;
        let rule = self
            .rpc_rules
            .get(rpc)
            .ok_or_else(|| KernelError::UnknownRpc(rpc.to_owned()))?;
        if rule.access != RpcAccess::GrantedPermission {
            return Err(KernelError::WrongAuthorizationPath(rpc.to_owned()));
        }
        require_permissions(granted, &rule.required_permission_codes)
    }

    pub fn authorize_command(
        &self,
        rpc: &str,
        oneof: &str,
        granted: &BTreeSet<String>,
    ) -> Result<AuthorizedCommand, KernelError> {
        self.validate_grants(granted)?;
        let rpc_rule = self
            .rpc_rules
            .get(rpc)
            .ok_or_else(|| KernelError::UnknownRpc(rpc.to_owned()))?;
        if rpc_rule.access != RpcAccess::PerCommandOneof {
            return Err(KernelError::WrongAuthorizationPath(rpc.to_owned()));
        }
        let rule = self
            .command_rules
            .get(&(rpc.to_owned(), oneof.to_owned()))
            .ok_or_else(|| KernelError::UnknownCommandOneof {
                rpc: rpc.to_owned(),
                oneof: oneof.to_owned(),
            })?;
        if rule.access == CommandAccess::SystemOnly {
            return Err(KernelError::SystemOnlyCommand {
                rpc: rpc.to_owned(),
                oneof: oneof.to_owned(),
            });
        }
        require_permissions(granted, &rule.required_permission_codes)?;
        Ok(AuthorizedCommand {
            write_owner: rule.write_owner.clone(),
            confirmation_class: rule.confirmation_class,
            required_authority_principal_kinds: rule.required_authority_principal_kinds.clone(),
        })
    }

    fn validate_grants(&self, granted: &BTreeSet<String>) -> Result<(), KernelError> {
        for permission in granted {
            if !self.permission_codes.contains(permission) {
                return Err(KernelError::UnknownPermission(permission.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCommand {
    pub write_owner: String,
    pub confirmation_class: ConfirmationClass,
    pub required_authority_principal_kinds: Vec<String>,
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
            if !self.profiles.permission_codes.contains(&permission) {
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

fn verify_digest(payload: &[u8], expected: &str) -> Result<(), KernelError> {
    if sha256_hex(payload) == expected {
        Ok(())
    } else {
        Err(KernelError::ProfileDigestMismatch)
    }
}

fn sha256_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

fn validate_client_kernel_profile(profile: &ClientKernelProfile) -> Result<(), KernelError> {
    let required_capabilities = [
        "session_negotiation",
        "query",
        "list",
        "watch_complete_snapshots",
        "await_projection",
        "typed_command",
        "stable_cursor",
        "reset_and_refetch",
        "read_your_write",
        "typed_error",
        "frame_deduplication",
    ];
    let required_surfaces = ["cli", "tui", "desktop_tauri_backend"];
    if profile.schema_version != "egopulse.client-kernel-profile/v0.1"
        || profile.contract_id != CLIENT_KERNEL_CONTRACT_ID
        || profile.contract_version != CLIENT_KERNEL_CONTRACT_VERSION
        || profile.authority_ref.is_empty()
        || profile.local_api_compatibility.contract_id != API_CONTRACT_ID
        || !profile.local_api_compatibility.runtime_reference_required
        || profile.local_api_compatibility.minimum_version.is_empty()
        || profile
            .local_api_compatibility
            .maximum_version_exclusive
            .is_empty()
        || profile.implementation_boundary.shared_kernel_language != "rust"
        || profile
            .implementation_boundary
            .typescript_business_kernel_allowed
        || profile.implementation_boundary.transport
            != "tonic_grpc_http2_semantics_over_named_pipe_or_uds_no_tcp"
        || required_surfaces
            .iter()
            .any(|value| !profile.implementation_boundary.surfaces.contains(*value))
        || required_capabilities
            .iter()
            .any(|value| !profile.capabilities.contains(*value))
        || !profile.invariants.surface_neutral
        || !profile.invariants.complete_snapshot_streams
        || !profile.invariants.ordered_within_epoch
        || !profile.invariants.at_least_once_delivery
        || !profile.invariants.unknown_frame_fail_closed
        || !profile.invariants.gap_requires_reset
        || !profile.invariants.authority_result_preserved
        || !profile.invariants.client_never_becomes_authority
    {
        return Err(KernelError::ProfileInvalid("client_kernel_invariants"));
    }
    Ok(())
}

fn validate_authorization_profile(
    client_kernel_contract_id: &str,
    profile: &AuthorizationProfile,
) -> Result<(), KernelError> {
    let defaults = &profile.defaults;
    if client_kernel_contract_id != CLIENT_KERNEL_CONTRACT_ID
        || profile.schema_version != "egopulse.authorization-capability-profile/v0.1"
        || profile.contract_id != AUTHORIZATION_CONTRACT_ID
        || profile.contract_version != AUTHORIZATION_CONTRACT_VERSION
        || profile.authority_ref.is_empty()
        || profile.local_api_contract_id != API_CONTRACT_ID
        || defaults.unknown_permission != "fail_closed"
        || defaults.unknown_rpc != "fail_closed"
        || defaults.unknown_command_oneof != "fail_closed"
        || !defaults.surface_neutral
        || defaults.session_grant_is_final_authorization
        || !defaults.owning_authority_revalidation_required
    {
        return Err(KernelError::ProfileInvalid("authorization_defaults"));
    }
    Ok(())
}

fn validate_permission_references(
    known: &BTreeSet<String>,
    required: &[String],
) -> Result<(), KernelError> {
    let mut unique = BTreeSet::new();
    if required
        .iter()
        .any(|value| !known.contains(value) || !unique.insert(value))
    {
        return Err(KernelError::ProfileInvalid("permission_reference"));
    }
    Ok(())
}

fn require_permissions(granted: &BTreeSet<String>, required: &[String]) -> Result<(), KernelError> {
    for permission in required {
        if !granted.contains(permission) {
            return Err(KernelError::PermissionDenied(permission.clone()));
        }
    }
    Ok(())
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
