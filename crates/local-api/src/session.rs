use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{
        ClientRequestMetadata, ClientSurface, LocalApiError, LocalApiErrorCode, OpenSessionRequest,
        OpenSessionResponse, ProjectionPosition, local_session_service_server::LocalSessionService,
    },
};
use egopulse_local_ipc_platform::{OsPrincipal, PeerConnectionInfo};
use prost_types::Timestamp;
use thiserror::Error;
use tonic::{Request, Response, Status};
use uuid::Uuid;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PERMISSION_CODE_BYTES: usize = 128;
const MAX_SUPPORTED_CONTRACTS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalGrant {
    pub authenticated_principal_id: String,
    pub permission_codes: BTreeSet<String>,
    pub authorization_policy_ref: ContractReference,
}

impl PrincipalGrant {
    pub fn validate(&self) -> Result<(), SessionConfigurationError> {
        validate_identifier("authenticated principal", &self.authenticated_principal_id)?;
        validate_contract_ref(&self.authorization_policy_ref)?;
        if self.permission_codes.is_empty() {
            return Err(SessionConfigurationError::EmptyPermissionSet);
        }
        for code in &self.permission_codes {
            if code.is_empty()
                || code.len() > MAX_PERMISSION_CODE_BYTES
                || !code.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-')
                })
            {
                return Err(SessionConfigurationError::InvalidPermissionCode);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalResolutionFailure {
    Unauthenticated,
    PermissionDenied,
    PolicyUnavailable,
}

pub trait TrustedPrincipalResolver: Send + Sync + 'static {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure>;
}

#[derive(Default)]
pub struct DenyAllPrincipalResolver;

impl TrustedPrincipalResolver for DenyAllPrincipalResolver {
    fn resolve(
        &self,
        _principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        Err(PrincipalResolutionFailure::PermissionDenied)
    }
}

pub trait SessionClock: Send + Sync + 'static {
    fn now(&self) -> SystemTime;
}

#[derive(Default)]
pub struct SystemSessionClock;

impl SessionClock for SystemSessionClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait ProjectionPositionProvider: Send + Sync + 'static {
    fn current_position(&self) -> ProjectionPosition;
}

#[derive(Clone)]
pub struct FixedProjectionPosition(pub ProjectionPosition);

impl ProjectionPositionProvider for FixedProjectionPosition {
    fn current_position(&self) -> ProjectionPosition {
        self.0.clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAuditKind {
    Opened,
    Rejected,
    Expired,
    Revoked,
    PolicyDrift,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAuditEvent {
    pub kind: SessionAuditKind,
    pub safe_reason_code: &'static str,
    pub connection_id: String,
    pub peer_fingerprint: String,
    pub session_id: Option<String>,
}

pub trait SessionAuditSink: Send + Sync + 'static {
    fn record(&self, event: SessionAuditEvent);
}

#[derive(Default)]
pub struct NoopSessionAuditSink;

impl SessionAuditSink for NoopSessionAuditSink {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Clone)]
pub struct SessionConfig {
    accepted_api_contracts: Arc<[ContractReference]>,
    client_kernel_contract_ref: ContractReference,
    session_ttl: Duration,
}

impl SessionConfig {
    pub fn new(
        accepted_api_contracts: Vec<ContractReference>,
        client_kernel_contract_ref: ContractReference,
        session_ttl: Duration,
    ) -> Result<Self, SessionConfigurationError> {
        if accepted_api_contracts.is_empty()
            || accepted_api_contracts.len() > MAX_SUPPORTED_CONTRACTS
        {
            return Err(SessionConfigurationError::InvalidContractSet);
        }
        for reference in &accepted_api_contracts {
            validate_contract_ref(reference)?;
        }
        validate_contract_ref(&client_kernel_contract_ref)?;
        if session_ttl.is_zero() || session_ttl > Duration::from_secs(24 * 60 * 60) {
            return Err(SessionConfigurationError::InvalidSessionTtl);
        }
        Ok(Self {
            accepted_api_contracts: accepted_api_contracts.into(),
            client_kernel_contract_ref,
            session_ttl,
        })
    }
}

#[derive(Debug, Error)]
pub enum SessionConfigurationError {
    #[error("contract set is empty or too large")]
    InvalidContractSet,
    #[error("contract reference is invalid")]
    InvalidContractReference,
    #[error("session TTL is invalid")]
    InvalidSessionTtl,
    #[error("principal grant contains an invalid identifier")]
    InvalidIdentifier,
    #[error("principal grant contains no permissions")]
    EmptyPermissionSet,
    #[error("principal grant contains an invalid permission code")]
    InvalidPermissionCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSession {
    pub session_id: String,
    pub authenticated_principal_id: String,
    pub permission_codes: BTreeSet<String>,
    pub authorization_policy_ref: ContractReference,
    pub negotiated_contract_ref: ContractReference,
    pub client_kernel_contract_ref: ContractReference,
    pub client_instance_id: String,
    pub surface: ClientSurface,
    pub expires_at: SystemTime,
    pub generation: u64,
}

#[derive(Clone)]
struct SessionRecord {
    public: AuthenticatedSession,
    peer_principal: OsPrincipal,
    revoked: bool,
}

struct SessionDraft {
    grant: PrincipalGrant,
    negotiated_contract_ref: ContractReference,
    client_kernel_contract_ref: ContractReference,
    client_instance_id: String,
    surface: ClientSurface,
    expires_at: SystemTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAuthenticationFailure {
    MissingMetadata,
    NotFound,
    PeerMismatch,
    ClientBindingMismatch,
    ContractMismatch,
    Expired,
    Revoked,
    PolicyDrift,
    PolicyUnavailable,
    IntegrityFailure,
}

pub struct SessionRegistry {
    sessions: RwLock<HashMap<String, SessionRecord>>,
    generation: AtomicU64,
    resolver: Arc<dyn TrustedPrincipalResolver>,
    clock: Arc<dyn SessionClock>,
    audit: Arc<dyn SessionAuditSink>,
}

impl SessionRegistry {
    fn new(
        resolver: Arc<dyn TrustedPrincipalResolver>,
        clock: Arc<dyn SessionClock>,
        audit: Arc<dyn SessionAuditSink>,
    ) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            generation: AtomicU64::new(0),
            resolver,
            clock,
            audit,
        }
    }

    fn insert(
        &self,
        peer: &PeerConnectionInfo,
        draft: SessionDraft,
    ) -> Result<AuthenticatedSession, SessionAuthenticationFailure> {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let session = AuthenticatedSession {
            session_id: Uuid::now_v7().to_string(),
            authenticated_principal_id: draft.grant.authenticated_principal_id,
            permission_codes: draft.grant.permission_codes,
            authorization_policy_ref: draft.grant.authorization_policy_ref,
            negotiated_contract_ref: draft.negotiated_contract_ref,
            client_kernel_contract_ref: draft.client_kernel_contract_ref,
            client_instance_id: draft.client_instance_id,
            surface: draft.surface,
            expires_at: draft.expires_at,
            generation,
        };
        let record = SessionRecord {
            public: session.clone(),
            peer_principal: peer.principal().clone(),
            revoked: false,
        };
        self.sessions
            .write()
            .map_err(|_| SessionAuthenticationFailure::IntegrityFailure)?
            .insert(session.session_id.clone(), record);
        Ok(session)
    }

    pub fn authenticate(
        &self,
        metadata: Option<&ClientRequestMetadata>,
        peer: &PeerConnectionInfo,
    ) -> Result<AuthenticatedSession, SessionAuthenticationFailure> {
        let metadata = metadata.ok_or(SessionAuthenticationFailure::MissingMetadata)?;
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionAuthenticationFailure::IntegrityFailure)?;
        let Some(record) = sessions.get(&metadata.session_id).cloned() else {
            return Err(SessionAuthenticationFailure::NotFound);
        };
        if record.revoked {
            return Err(SessionAuthenticationFailure::Revoked);
        }
        if self.clock.now() >= record.public.expires_at {
            sessions.remove(&metadata.session_id);
            self.audit.record(audit_event(
                SessionAuditKind::Expired,
                "session_expired",
                peer,
                Some(metadata.session_id.clone()),
            ));
            return Err(SessionAuthenticationFailure::Expired);
        }
        drop(sessions);
        if &record.peer_principal != peer.principal() {
            return Err(SessionAuthenticationFailure::PeerMismatch);
        }
        if record.public.client_instance_id != metadata.client_instance_id
            || record.public.surface as i32 != metadata.surface
        {
            return Err(SessionAuthenticationFailure::ClientBindingMismatch);
        }
        if metadata.api_contract_ref.as_ref() != Some(&record.public.negotiated_contract_ref) {
            return Err(SessionAuthenticationFailure::ContractMismatch);
        }
        let current_grant =
            self.resolver
                .resolve(peer.principal())
                .map_err(|failure| match failure {
                    PrincipalResolutionFailure::PolicyUnavailable => {
                        SessionAuthenticationFailure::PolicyUnavailable
                    }
                    PrincipalResolutionFailure::Unauthenticated
                    | PrincipalResolutionFailure::PermissionDenied => {
                        SessionAuthenticationFailure::PolicyDrift
                    }
                })?;
        if current_grant.validate().is_err()
            || current_grant.authenticated_principal_id != record.public.authenticated_principal_id
            || current_grant.permission_codes != record.public.permission_codes
            || current_grant.authorization_policy_ref != record.public.authorization_policy_ref
        {
            self.audit.record(audit_event(
                SessionAuditKind::PolicyDrift,
                "session_policy_drift",
                peer,
                Some(metadata.session_id.clone()),
            ));
            return Err(SessionAuthenticationFailure::PolicyDrift);
        }
        let sessions = self
            .sessions
            .read()
            .map_err(|_| SessionAuthenticationFailure::IntegrityFailure)?;
        let Some(current) = sessions.get(&metadata.session_id) else {
            return Err(SessionAuthenticationFailure::NotFound);
        };
        if current.public.generation != record.public.generation || current.revoked {
            return Err(SessionAuthenticationFailure::Revoked);
        }
        if self.clock.now() >= current.public.expires_at {
            return Err(SessionAuthenticationFailure::Expired);
        }
        Ok(record.public)
    }

    pub fn revoke(&self, session_id: &str) -> Result<bool, SessionAuthenticationFailure> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| SessionAuthenticationFailure::IntegrityFailure)?;
        let Some(record) = sessions.get_mut(session_id) else {
            return Ok(false);
        };
        record.revoked = true;
        self.audit.record(SessionAuditEvent {
            kind: SessionAuditKind::Revoked,
            safe_reason_code: "session_revoked",
            connection_id: String::new(),
            peer_fingerprint: record.peer_principal.fingerprint_hex(),
            session_id: Some(session_id.to_owned()),
        });
        Ok(true)
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.read().map_or(0, |sessions| {
            sessions
                .values()
                .filter(|record| !record.revoked && self.clock.now() < record.public.expires_at)
                .count()
        })
    }
}

pub struct LocalSessionEndpoint {
    config: SessionConfig,
    registry: Arc<SessionRegistry>,
    position: Arc<dyn ProjectionPositionProvider>,
}

impl LocalSessionEndpoint {
    #[must_use]
    pub fn new(
        config: SessionConfig,
        resolver: Arc<dyn TrustedPrincipalResolver>,
        clock: Arc<dyn SessionClock>,
        position: Arc<dyn ProjectionPositionProvider>,
        audit: Arc<dyn SessionAuditSink>,
    ) -> Self {
        Self {
            config,
            registry: Arc::new(SessionRegistry::new(resolver, clock, audit)),
            position,
        }
    }

    #[must_use]
    pub fn registry(&self) -> Arc<SessionRegistry> {
        Arc::clone(&self.registry)
    }

    fn rejected(
        &self,
        peer: Option<&PeerConnectionInfo>,
        code: LocalApiErrorCode,
        reason: &'static str,
    ) -> OpenSessionResponse {
        if let Some(peer) = peer {
            self.registry
                .audit
                .record(audit_event(SessionAuditKind::Rejected, reason, peer, None));
        }
        OpenSessionResponse {
            error: Some(LocalApiError {
                code: code as i32,
                safe_fingerprint: format!("local-session/{reason}/v1"),
                retryable: matches!(code, LocalApiErrorCode::AuthorityUnavailable),
                required_action_code: None,
                current_position: Some(self.position.current_position()),
                correlation_id: Uuid::now_v7().to_string(),
            }),
            ..OpenSessionResponse::default()
        }
    }
}

#[tonic::async_trait]
impl LocalSessionService for LocalSessionEndpoint {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        let peer = request.extensions().get::<PeerConnectionInfo>().cloned();
        let Some(peer) = peer else {
            return Ok(Response::new(self.rejected(
                None,
                LocalApiErrorCode::Unauthenticated,
                "peer_metadata_missing",
            )));
        };
        let input = request.into_inner();
        if validate_identifier("request", &input.request_id).is_err()
            || validate_identifier("client instance", &input.client_instance_id).is_err()
            || input.supported_contracts.is_empty()
            || input.supported_contracts.len() > MAX_SUPPORTED_CONTRACTS
        {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::InvalidArgument,
                "open_session_input_invalid",
            )));
        }
        let Ok(surface) = ClientSurface::try_from(input.surface) else {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::UnknownCriticalSemantics,
                "surface_unknown",
            )));
        };
        if surface == ClientSurface::Unspecified {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::UnknownCriticalSemantics,
                "surface_unspecified",
            )));
        }
        let negotiated = self
            .config
            .accepted_api_contracts
            .iter()
            .find(|server| {
                input
                    .supported_contracts
                    .iter()
                    .any(|client| client == *server)
            })
            .cloned();
        let Some(negotiated_contract_ref) = negotiated else {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::ContractIncompatible,
                "contract_incompatible",
            )));
        };
        let grant = match self.registry.resolver.resolve(peer.principal()) {
            Ok(grant) if grant.validate().is_ok() => grant,
            Ok(_) => {
                return Ok(Response::new(self.rejected(
                    Some(&peer),
                    LocalApiErrorCode::IntegrityFailure,
                    "resolver_grant_invalid",
                )));
            }
            Err(PrincipalResolutionFailure::Unauthenticated) => {
                return Ok(Response::new(self.rejected(
                    Some(&peer),
                    LocalApiErrorCode::Unauthenticated,
                    "peer_unauthenticated",
                )));
            }
            Err(PrincipalResolutionFailure::PermissionDenied) => {
                return Ok(Response::new(self.rejected(
                    Some(&peer),
                    LocalApiErrorCode::PermissionDenied,
                    "peer_not_allowed",
                )));
            }
            Err(PrincipalResolutionFailure::PolicyUnavailable) => {
                return Ok(Response::new(self.rejected(
                    Some(&peer),
                    LocalApiErrorCode::AuthorityUnavailable,
                    "authorization_policy_unavailable",
                )));
            }
        };
        let Some(expires_at) = self
            .registry
            .clock
            .now()
            .checked_add(self.config.session_ttl)
        else {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::IntegrityFailure,
                "session_expiry_overflow",
            )));
        };
        let Some(expires_timestamp) = system_time_to_timestamp(expires_at) else {
            return Ok(Response::new(self.rejected(
                Some(&peer),
                LocalApiErrorCode::IntegrityFailure,
                "session_expiry_invalid",
            )));
        };
        let session = match self.registry.insert(
            &peer,
            SessionDraft {
                grant,
                negotiated_contract_ref: negotiated_contract_ref.clone(),
                client_kernel_contract_ref: self.config.client_kernel_contract_ref.clone(),
                client_instance_id: input.client_instance_id,
                surface,
                expires_at,
            },
        ) {
            Ok(session) => session,
            Err(_) => {
                return Ok(Response::new(self.rejected(
                    Some(&peer),
                    LocalApiErrorCode::IntegrityFailure,
                    "session_registry_failed",
                )));
            }
        };
        self.registry.audit.record(audit_event(
            SessionAuditKind::Opened,
            "session_opened",
            &peer,
            Some(session.session_id.clone()),
        ));
        Ok(Response::new(OpenSessionResponse {
            session_id: session.session_id,
            authenticated_principal_id: session.authenticated_principal_id,
            negotiated_contract_ref: Some(negotiated_contract_ref),
            granted_permission_codes: session.permission_codes.into_iter().collect(),
            expires_at: Some(expires_timestamp),
            current_position: Some(self.position.current_position()),
            error: None,
            client_kernel_contract_ref: Some(session.client_kernel_contract_ref),
            authorization_policy_ref: Some(session.authorization_policy_ref),
        }))
    }
}

fn validate_identifier(_kind: &'static str, value: &str) -> Result<(), SessionConfigurationError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        Err(SessionConfigurationError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_contract_ref(reference: &ContractReference) -> Result<(), SessionConfigurationError> {
    if reference.contract_id.is_empty()
        || reference.contract_id.len() > MAX_IDENTIFIER_BYTES
        || reference.version.is_empty()
        || reference.version.len() > MAX_IDENTIFIER_BYTES
        || reference.sha256.len() != 64
        || !reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        Err(SessionConfigurationError::InvalidContractReference)
    } else {
        Ok(())
    }
}

fn system_time_to_timestamp(time: SystemTime) -> Option<Timestamp> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    Some(Timestamp {
        seconds: i64::try_from(duration.as_secs()).ok()?,
        nanos: i32::try_from(duration.subsec_nanos()).ok()?,
    })
}

fn audit_event(
    kind: SessionAuditKind,
    reason: &'static str,
    peer: &PeerConnectionInfo,
    session_id: Option<String>,
) -> SessionAuditEvent {
    SessionAuditEvent {
        kind,
        safe_reason_code: reason,
        connection_id: peer.connection_id().to_owned(),
        peer_fingerprint: peer.principal().fingerprint_hex(),
        session_id,
    }
}
