#![cfg(windows)]

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::{
    profiles::{
        API_CONTRACT_DIGEST_SHA256, API_CONTRACT_ID, API_CONTRACT_VERSION,
        AUTHORIZATION_CONTRACT_ID, AUTHORIZATION_CONTRACT_VERSION,
        AUTHORIZATION_PROFILE_DIGEST_SHA256, CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION, CLIENT_KERNEL_PROFILE_DIGEST_SHA256, ContractProfiles,
    },
    v01::egopulse::{
        common::v1::ContractReference,
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, LocalApiErrorCode, OpenSessionRequest,
            ProjectionPosition, RetrieveMemoryRequest,
            local_session_service_server::LocalSessionService, retrieve_memory_response,
        },
        memory::v1::{RetrievalCandidate, RetrievalResponse},
    },
};
use egopulse_local_api::{
    cognition_gateway::{
        CognitionGatewayApplication, MemoryRetrievalAuditEvent, MemoryRetrievalAuditSink,
        MemoryRetrievalInput, MemoryRetrievalPort, MemoryRetrievalPortError,
    },
    session::{
        FixedProjectionPosition, LocalSessionEndpoint, PrincipalGrant, PrincipalResolutionFailure,
        ProjectionPositionProvider, SessionAuditEvent, SessionAuditSink, SessionClock,
        SessionConfig, TrustedPrincipalResolver,
    },
};
use egopulse_local_ipc_platform::{
    LocalIpcAddress, LocalIpcClient, LocalIpcListener, OsPrincipal, PeerConnectionInfo,
};
use tonic::Request;
use uuid::Uuid;

#[derive(Clone)]
struct FixedClock(SystemTime);

impl SessionClock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[derive(Clone)]
struct Resolver {
    peer: OsPrincipal,
    permissions: BTreeSet<String>,
}

impl TrustedPrincipalResolver for Resolver {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        if principal != &self.peer {
            return Err(PrincipalResolutionFailure::PermissionDenied);
        }
        Ok(PrincipalGrant {
            authenticated_principal_id: "os-user:founder".to_owned(),
            permission_codes: self.permissions.clone(),
            authorization_policy_ref: contract_ref(
                AUTHORIZATION_CONTRACT_ID,
                AUTHORIZATION_CONTRACT_VERSION,
                AUTHORIZATION_PROFILE_DIGEST_SHA256,
            ),
        })
    }
}

#[derive(Default)]
struct NoopSessionAudit;

impl SessionAuditSink for NoopSessionAudit {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Clone)]
struct RecordingPort {
    calls: Arc<AtomicUsize>,
    input: Arc<Mutex<Option<MemoryRetrievalInput>>>,
    result: Result<RetrievalResponse, MemoryRetrievalPortError>,
}

#[tonic::async_trait]
impl MemoryRetrievalPort for RecordingPort {
    async fn retrieve(
        &self,
        request: MemoryRetrievalInput,
    ) -> Result<RetrievalResponse, MemoryRetrievalPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.input.lock().expect("input lock") = Some(request);
        self.result.clone()
    }
}

#[derive(Clone, Default)]
struct RecordingAudit(Arc<Mutex<Vec<MemoryRetrievalAuditEvent>>>);

impl MemoryRetrievalAuditSink for RecordingAudit {
    fn record(&self, event: MemoryRetrievalAuditEvent) {
        self.0.lock().expect("audit lock").push(event);
    }
}

fn contract_ref(id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn api_contract() -> ContractReference {
    contract_ref(
        API_CONTRACT_ID,
        API_CONTRACT_VERSION,
        API_CONTRACT_DIGEST_SHA256,
    )
}

fn kernel_contract() -> ContractReference {
    contract_ref(
        CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION,
        CLIENT_KERNEL_PROFILE_DIGEST_SHA256,
    )
}

fn result() -> RetrievalResponse {
    RetrievalResponse {
        algorithm_id: "lexical-overlap-v0".to_owned(),
        query_sha256: "a".repeat(64),
        snapshot_sha256: "b".repeat(64),
        candidates: vec![RetrievalCandidate {
            memory_id: "memory-01".to_owned(),
            source_ref: "source:memory-01".to_owned(),
            content_sha256: "c".repeat(64),
            score: 1.0,
            matched_terms: vec!["memory".to_owned()],
        }],
        evidence_ref: format!("memory-rag-evidence-sha256:{}", "d".repeat(64)),
    }
}

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address =
        LocalIpcAddress::for_instance(&format!("cognition-{}", Uuid::now_v7())).expect("address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind");
    let client = LocalIpcClient::connect(&address).await.expect("connect");
    let connection = listener.accept().await.expect("accept");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

async fn application(
    permissions: BTreeSet<String>,
    result: Result<RetrievalResponse, MemoryRetrievalPortError>,
) -> (
    PeerConnectionInfo,
    ClientRequestMetadata,
    CognitionGatewayApplication,
    Arc<AtomicUsize>,
    Arc<Mutex<Option<MemoryRetrievalInput>>>,
    RecordingAudit,
) {
    let peer = real_peer().await;
    let endpoint = LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .expect("session config"),
        Arc::new(Resolver {
            peer: peer.principal().clone(),
            permissions,
        }),
        Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs(100))),
        Arc::new(FixedProjectionPosition(ProjectionPosition {
            epoch: "memory-test".to_owned(),
            sequence: 1,
            projected_at: None,
        })) as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopSessionAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "memory-client".to_owned(),
        surface: ClientSurface::Cli as i32,
        supported_contracts: vec![api_contract()],
    };
    let mut request = Request::new(open.clone());
    request.extensions_mut().insert(peer.clone());
    let opened = endpoint
        .open_session(request)
        .await
        .expect("open session")
        .into_inner();
    assert!(opened.error.is_none());
    let metadata = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("memory-correlation".to_owned()),
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let input = Arc::new(Mutex::new(None));
    let port = Arc::new(RecordingPort {
        calls: Arc::clone(&calls),
        input: Arc::clone(&input),
        result,
    });
    let audit = RecordingAudit::default();
    let app = CognitionGatewayApplication::new(
        endpoint.registry(),
        Arc::new(ContractProfiles::embedded().expect("profiles")),
        port,
        Arc::new(audit.clone()),
    );
    (peer, metadata, app, calls, input, audit)
}

fn request(client: ClientRequestMetadata) -> RetrieveMemoryRequest {
    RetrieveMemoryRequest {
        client: Some(client),
        query: "accepted Memory".to_owned(),
        scope_ref: "scope:founder".to_owned(),
        max_results: 8,
        min_score: 0.0,
    }
}

#[tokio::test]
async fn authorized_retrieval_propagates_principal_scope_and_privacy_safe_audit() {
    let (peer, metadata, app, calls, input, audit) = application(
        BTreeSet::from(["local.memory.retrieve".to_owned()]),
        Ok(result()),
    )
    .await;
    let response = app.retrieve_memory(Some(&peer), request(metadata)).await;
    assert!(matches!(
        response.outcome,
        Some(retrieve_memory_response::Outcome::Result(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let input = input.lock().expect("input lock").clone().expect("input");
    assert_eq!(input.authenticated_principal_id, "os-user:founder");
    assert_eq!(input.scope_ref, "scope:founder");
    let events = audit.0.lock().expect("audit lock");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].query_sha256.len(), 64);
    let expected_snapshot = "b".repeat(64);
    assert_eq!(
        events[0].snapshot_sha256.as_deref(),
        Some(expected_snapshot.as_str())
    );
    assert_eq!(events[0].result_count, Some(1));
    assert_eq!(events[0].safe_outcome_code, "succeeded");
}

#[tokio::test]
async fn permission_and_input_fail_closed_before_the_port() {
    let (peer, metadata, app, calls, _, _) =
        application(BTreeSet::from(["local.task.read".to_owned()]), Ok(result())).await;
    let denied = app.retrieve_memory(Some(&peer), request(metadata)).await;
    let Some(retrieve_memory_response::Outcome::Error(error)) = denied.outcome else {
        panic!("permission error");
    };
    assert_eq!(error.code, LocalApiErrorCode::PermissionDenied as i32);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (peer, metadata, app, calls, _, audit) = application(
        BTreeSet::from(["local.memory.retrieve".to_owned()]),
        Ok(result()),
    )
    .await;
    let mut invalid = request(metadata);
    invalid.max_results = 0;
    let response = app.retrieve_memory(Some(&peer), invalid).await;
    let Some(retrieve_memory_response::Outcome::Error(error)) = response.outcome else {
        panic!("input error");
    };
    assert_eq!(error.code, LocalApiErrorCode::InvalidArgument as i32);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        audit.0.lock().expect("audit lock")[0].safe_outcome_code,
        "invalid_argument"
    );
}

#[tokio::test]
async fn frozen_port_failures_keep_exact_retry_semantics() {
    let cases = [
        (
            MemoryRetrievalPortError::ResourceExhausted,
            LocalApiErrorCode::ResourceExhausted,
            true,
        ),
        (
            MemoryRetrievalPortError::WorkerUnavailable,
            LocalApiErrorCode::CognitionWorkerUnavailable,
            true,
        ),
        (
            MemoryRetrievalPortError::IntegrityFailure,
            LocalApiErrorCode::IntegrityFailure,
            false,
        ),
    ];
    for (failure, expected_code, expected_retryable) in cases {
        let (peer, metadata, app, _, _, _) = application(
            BTreeSet::from(["local.memory.retrieve".to_owned()]),
            Err(failure),
        )
        .await;
        let response = app.retrieve_memory(Some(&peer), request(metadata)).await;
        let Some(retrieve_memory_response::Outcome::Error(error)) = response.outcome else {
            panic!("port error");
        };
        assert_eq!(error.code, expected_code as i32);
        assert_eq!(error.retryable, expected_retryable);
    }
}
