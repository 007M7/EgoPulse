//! Governed read-only cognition gateway.
//!
//! This boundary owns Local API authentication, capability authorization,
//! bounded public input validation and privacy-safe audit projection. The
//! owning daemon adapter must still revalidate principal-to-scope access
//! before materializing an accepted Memory snapshot.

use std::sync::Arc;

use egopulse_domain_contracts::{
    memory::{MEMORY_MAX_QUERY_BYTES, MEMORY_MAX_RESULTS, MEMORY_MAX_ROUTING_FIELD_BYTES},
    profiles::{ContractProfileError, ContractProfiles},
    v01::egopulse::{
        localapi::v1::{
            ClientRequestMetadata, LocalApiError, LocalApiErrorCode, RetrieveMemoryRequest,
            RetrieveMemoryResponse, local_cognition_service_server::LocalCognitionService,
            retrieve_memory_response,
        },
        memory::v1::RetrievalResponse,
    },
};
use egopulse_local_ipc_platform::PeerConnectionInfo;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::session::{AuthenticatedSession, SessionAuthenticationFailure, SessionRegistry};

const RPC_RETRIEVE_MEMORY: &str = "LocalCognitionService/RetrieveMemory";
const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq)]
pub struct MemoryRetrievalInput {
    pub authenticated_principal_id: String,
    pub request_id: String,
    pub correlation_id: String,
    pub query: String,
    pub scope_ref: String,
    pub max_results: u32,
    pub min_score: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryRetrievalPortError {
    InvalidArgument,
    ScopeDenied,
    AuthorityUnavailable,
    DeadlineExceeded,
    ResourceExhausted,
    WorkerUnavailable,
    IntegrityFailure,
}

#[tonic::async_trait]
pub trait MemoryRetrievalPort: Send + Sync + 'static {
    async fn retrieve(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<RetrievalResponse, MemoryRetrievalPortError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRetrievalAuditEvent {
    pub authenticated_principal_id: String,
    pub request_id: String,
    pub correlation_id: String,
    pub scope_ref: String,
    pub query_sha256: String,
    pub snapshot_sha256: Option<String>,
    pub result_count: Option<usize>,
    pub algorithm_id: Option<String>,
    pub evidence_ref: Option<String>,
    pub safe_outcome_code: &'static str,
}

pub trait MemoryRetrievalAuditSink: Send + Sync + 'static {
    fn record(&self, event: MemoryRetrievalAuditEvent);
}

#[derive(Default)]
pub struct NoopMemoryRetrievalAuditSink;

impl MemoryRetrievalAuditSink for NoopMemoryRetrievalAuditSink {
    fn record(&self, _event: MemoryRetrievalAuditEvent) {}
}

pub struct CognitionGatewayApplication {
    registry: Arc<SessionRegistry>,
    profiles: Arc<ContractProfiles>,
    port: Arc<dyn MemoryRetrievalPort>,
    audit: Arc<dyn MemoryRetrievalAuditSink>,
}

impl CognitionGatewayApplication {
    #[must_use]
    pub fn new(
        registry: Arc<SessionRegistry>,
        profiles: Arc<ContractProfiles>,
        port: Arc<dyn MemoryRetrievalPort>,
        audit: Arc<dyn MemoryRetrievalAuditSink>,
    ) -> Self {
        Self {
            registry,
            profiles,
            port,
            audit,
        }
    }

    pub async fn retrieve_memory(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: RetrieveMemoryRequest,
    ) -> RetrieveMemoryResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref()) {
            Ok(value) => value,
            Err(failure) => {
                return error_response(failure.into_error(correlation_id));
            }
        };
        if !valid_retrieval_request(&request) {
            self.audit_failure(
                &context.session,
                request.client.as_ref(),
                &correlation_id,
                &request.scope_ref,
                &request.query,
                "invalid_argument",
            );
            return error_response(api_error(
                LocalApiErrorCode::InvalidArgument,
                "memory_retrieval_input_invalid",
                false,
                None,
                correlation_id,
            ));
        }

        let metadata = request.client.as_ref().expect("authorized metadata");
        let input = MemoryRetrievalInput {
            authenticated_principal_id: context.session.authenticated_principal_id.clone(),
            request_id: metadata.request_id.clone(),
            correlation_id: correlation_id.clone(),
            query: request.query.clone(),
            scope_ref: request.scope_ref.clone(),
            max_results: request.max_results,
            min_score: request.min_score,
        };
        match self.port.retrieve(input).await {
            Ok(result) => {
                self.audit.record(MemoryRetrievalAuditEvent {
                    authenticated_principal_id: context.session.authenticated_principal_id,
                    request_id: metadata.request_id.clone(),
                    correlation_id,
                    scope_ref: request.scope_ref,
                    query_sha256: digest_text(&request.query),
                    snapshot_sha256: Some(result.snapshot_sha256.clone()),
                    result_count: Some(result.candidates.len()),
                    algorithm_id: Some(result.algorithm_id.clone()),
                    evidence_ref: Some(result.evidence_ref.clone()),
                    safe_outcome_code: "succeeded",
                });
                RetrieveMemoryResponse {
                    outcome: Some(retrieve_memory_response::Outcome::Result(result)),
                }
            }
            Err(failure) => {
                self.audit_failure(
                    &context.session,
                    Some(metadata),
                    &correlation_id,
                    &request.scope_ref,
                    &request.query,
                    failure.safe_outcome_code(),
                );
                error_response(failure.into_error(correlation_id))
            }
        }
    }

    fn authorize(
        &self,
        peer: Option<&PeerConnectionInfo>,
        metadata: Option<&ClientRequestMetadata>,
    ) -> Result<CognitionRequestContext, AuthorizationFailure> {
        let peer = peer.ok_or(AuthorizationFailure::Unauthenticated)?;
        if !valid_client_metadata(metadata) {
            return Err(AuthorizationFailure::InvalidArgument);
        }
        let session = self
            .registry
            .authenticate(metadata, peer)
            .map_err(AuthorizationFailure::Session)?;
        self.profiles
            .authorize_rpc(RPC_RETRIEVE_MEMORY, &session.permission_codes)
            .map_err(AuthorizationFailure::Profile)?;
        Ok(CognitionRequestContext { session })
    }

    fn audit_failure(
        &self,
        session: &AuthenticatedSession,
        metadata: Option<&ClientRequestMetadata>,
        correlation_id: &str,
        scope_ref: &str,
        query: &str,
        safe_outcome_code: &'static str,
    ) {
        self.audit.record(MemoryRetrievalAuditEvent {
            authenticated_principal_id: session.authenticated_principal_id.clone(),
            request_id: metadata.map_or_else(String::new, |value| value.request_id.clone()),
            correlation_id: correlation_id.to_owned(),
            scope_ref: scope_ref.to_owned(),
            query_sha256: digest_text(query),
            snapshot_sha256: None,
            result_count: None,
            algorithm_id: None,
            evidence_ref: None,
            safe_outcome_code,
        });
    }
}

pub struct LocalCognitionEndpoint {
    application: Arc<CognitionGatewayApplication>,
}

impl LocalCognitionEndpoint {
    #[must_use]
    pub fn new(application: Arc<CognitionGatewayApplication>) -> Self {
        Self { application }
    }
}

#[tonic::async_trait]
impl LocalCognitionService for LocalCognitionEndpoint {
    async fn retrieve_memory(
        &self,
        request: Request<RetrieveMemoryRequest>,
    ) -> Result<Response<RetrieveMemoryResponse>, Status> {
        let peer = request.extensions().get::<PeerConnectionInfo>().cloned();
        Ok(Response::new(
            self.application
                .retrieve_memory(peer.as_ref(), request.into_inner())
                .await,
        ))
    }
}

struct CognitionRequestContext {
    session: AuthenticatedSession,
}

enum AuthorizationFailure {
    InvalidArgument,
    Unauthenticated,
    Session(SessionAuthenticationFailure),
    Profile(ContractProfileError),
}

impl AuthorizationFailure {
    fn into_error(self, correlation_id: String) -> LocalApiError {
        let (code, fingerprint, retryable, action) = match self {
            Self::InvalidArgument => (
                LocalApiErrorCode::InvalidArgument,
                "invalid_client_metadata",
                false,
                None,
            ),
            Self::Unauthenticated => (
                LocalApiErrorCode::Unauthenticated,
                "peer_identity_missing",
                false,
                Some("REOPEN_SESSION"),
            ),
            Self::Session(SessionAuthenticationFailure::ContractMismatch) => (
                LocalApiErrorCode::ContractIncompatible,
                "session_contract_mismatch",
                false,
                Some("RENEGOTIATE_CONTRACT"),
            ),
            Self::Session(SessionAuthenticationFailure::Expired) => (
                LocalApiErrorCode::SessionExpired,
                "session_expired",
                true,
                Some("REOPEN_SESSION"),
            ),
            Self::Session(SessionAuthenticationFailure::PolicyUnavailable) => (
                LocalApiErrorCode::AuthorityUnavailable,
                "authorization_policy_unavailable",
                true,
                Some("RETRY"),
            ),
            Self::Session(SessionAuthenticationFailure::IntegrityFailure) => (
                LocalApiErrorCode::IntegrityFailure,
                "session_registry_integrity_failure",
                false,
                Some("RESTART_DAEMON"),
            ),
            Self::Session(
                SessionAuthenticationFailure::Revoked | SessionAuthenticationFailure::PolicyDrift,
            ) => (
                LocalApiErrorCode::PermissionDenied,
                "session_authorization_changed",
                false,
                Some("REOPEN_SESSION"),
            ),
            Self::Session(
                SessionAuthenticationFailure::MissingMetadata
                | SessionAuthenticationFailure::NotFound
                | SessionAuthenticationFailure::PeerMismatch
                | SessionAuthenticationFailure::ClientBindingMismatch,
            ) => (
                LocalApiErrorCode::Unauthenticated,
                "session_authentication_failed",
                false,
                Some("REOPEN_SESSION"),
            ),
            Self::Profile(ContractProfileError::PermissionDenied(_)) => (
                LocalApiErrorCode::PermissionDenied,
                "rpc_permission_denied",
                false,
                None,
            ),
            Self::Profile(_) => (
                LocalApiErrorCode::UnknownCriticalSemantics,
                "authorization_profile_semantics_unknown",
                false,
                Some("UPDATE_OR_REPAIR"),
            ),
        };
        api_error(code, fingerprint, retryable, action, correlation_id)
    }
}

impl MemoryRetrievalPortError {
    fn safe_outcome_code(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::ScopeDenied => "scope_denied",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ResourceExhausted => "resource_exhausted",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::IntegrityFailure => "integrity_failure",
        }
    }

    fn into_error(self, correlation_id: String) -> LocalApiError {
        let (code, fingerprint, retryable, action) = match self {
            Self::InvalidArgument => (
                LocalApiErrorCode::InvalidArgument,
                "memory_retrieval_input_invalid",
                false,
                None,
            ),
            Self::ScopeDenied => (
                LocalApiErrorCode::PermissionDenied,
                "memory_scope_denied",
                false,
                None,
            ),
            Self::AuthorityUnavailable => (
                LocalApiErrorCode::AuthorityUnavailable,
                "memory_authority_unavailable",
                true,
                Some("RETRY"),
            ),
            Self::DeadlineExceeded => (
                LocalApiErrorCode::DeadlineExceeded,
                "memory_worker_deadline_exceeded",
                true,
                Some("RETRY"),
            ),
            Self::ResourceExhausted => (
                LocalApiErrorCode::ResourceExhausted,
                "memory_retrieval_busy",
                true,
                Some("RETRY"),
            ),
            Self::WorkerUnavailable => (
                LocalApiErrorCode::CognitionWorkerUnavailable,
                "memory_worker_unavailable",
                true,
                Some("RETRY"),
            ),
            Self::IntegrityFailure => (
                LocalApiErrorCode::IntegrityFailure,
                "memory_retrieval_integrity_failure",
                false,
                Some("REPAIR_OR_UPDATE"),
            ),
        };
        api_error(code, fingerprint, retryable, action, correlation_id)
    }
}

fn valid_client_metadata(metadata: Option<&ClientRequestMetadata>) -> bool {
    let Some(metadata) = metadata else {
        return false;
    };
    valid_identifier(&metadata.request_id)
        && metadata
            .correlation_id
            .as_deref()
            .is_none_or(valid_identifier)
}

fn valid_retrieval_request(request: &RetrieveMemoryRequest) -> bool {
    !request.query.trim().is_empty()
        && request.query.len() <= MEMORY_MAX_QUERY_BYTES
        && !request.scope_ref.trim().is_empty()
        && request.scope_ref.len() <= MEMORY_MAX_ROUTING_FIELD_BYTES
        && (1..=MEMORY_MAX_RESULTS as u32).contains(&request.max_results)
        && request.min_score.is_finite()
        && (0.0..=1.0).contains(&request.min_score)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b'/')
        })
}

fn correlation_id(metadata: Option<&ClientRequestMetadata>) -> String {
    metadata
        .and_then(|value| value.correlation_id.as_deref())
        .filter(|value| valid_identifier(value))
        .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned)
}

fn digest_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn api_error(
    code: LocalApiErrorCode,
    fingerprint: &str,
    retryable: bool,
    required_action: Option<&str>,
    correlation_id: String,
) -> LocalApiError {
    LocalApiError {
        code: code as i32,
        safe_fingerprint: fingerprint.to_owned(),
        retryable,
        required_action_code: required_action.map(str::to_owned),
        current_position: None,
        correlation_id,
    }
}

fn error_response(error: LocalApiError) -> RetrieveMemoryResponse {
    RetrieveMemoryResponse {
        outcome: Some(retrieve_memory_response::Outcome::Error(error)),
    }
}
