#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{
        ClientRequestMetadata, ClientSurface, LocalApiErrorCode, OpenSessionRequest,
        ProjectionPosition,
        local_session_service_client::LocalSessionServiceClient,
        local_session_service_server::{LocalSessionService, LocalSessionServiceServer},
    },
};
use egopulse_local_api::session::{
    DenyAllPrincipalResolver, FixedProjectionPosition, LocalSessionEndpoint, PrincipalGrant,
    PrincipalResolutionFailure, ProjectionPositionProvider, SessionAuditEvent, SessionAuditKind,
    SessionAuditSink, SessionAuthenticationFailure, SessionClock, SessionConfig,
    TrustedPrincipalResolver,
};
use egopulse_local_ipc_platform::{
    LocalIpcAddress, LocalIpcClient, LocalIpcListener, OsPrincipal, PeerConnectionInfo,
};
use hyper_util::rt::TokioIo;
use tonic::{Request, transport::Endpoint};
use tower::service_fn;
use uuid::Uuid;

const CONTRACT_DIGEST: &str = "28d05e2533ea7650d8fedbc44abfa21d33c2845f8d105650e3287676e789e7bb";
const KERNEL_DIGEST: &str = "500d1421381ea3929e6cd92c0ce7bc0e849a93f32d941366ff35037915aaea3d";
const POLICY_DIGEST: &str = "5d17887f8e6555d0e4c973583dd07590a68a4be99c8b80a9e31877b9b2ed99b1";

#[derive(Clone)]
struct MutableClock(Arc<Mutex<SystemTime>>);

impl MutableClock {
    fn new(now: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.0.lock().unwrap();
        *now = now.checked_add(duration).unwrap();
    }
}

impl SessionClock for MutableClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

#[derive(Clone)]
struct MutableResolver {
    expected_peer: OsPrincipal,
    outcome: Arc<Mutex<Result<PrincipalGrant, PrincipalResolutionFailure>>>,
}

impl MutableResolver {
    fn allow(expected_peer: OsPrincipal, grant: PrincipalGrant) -> Self {
        Self {
            expected_peer,
            outcome: Arc::new(Mutex::new(Ok(grant))),
        }
    }

    fn set(&self, outcome: Result<PrincipalGrant, PrincipalResolutionFailure>) {
        *self.outcome.lock().unwrap() = outcome;
    }
}

impl TrustedPrincipalResolver for MutableResolver {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        if principal != &self.expected_peer {
            return Err(PrincipalResolutionFailure::PermissionDenied);
        }
        self.outcome.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct RecordingAudit(Mutex<Vec<SessionAuditEvent>>);

impl SessionAuditSink for RecordingAudit {
    fn record(&self, event: SessionAuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn contract_ref(id: &str, version: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: digest.to_owned(),
    }
}

fn api_contract() -> ContractReference {
    contract_ref("egopulse.localapi.v1", "0.1.0-draft.16", CONTRACT_DIGEST)
}

fn kernel_contract() -> ContractReference {
    contract_ref("egopulse.client-kernel.v1", "0.1.0", KERNEL_DIGEST)
}

fn policy_contract() -> ContractReference {
    contract_ref("egopulse.authorization.v1", "0.1.0", POLICY_DIGEST)
}

fn founder_grant() -> PrincipalGrant {
    PrincipalGrant {
        authenticated_principal_id: "os-user:founder".to_owned(),
        permission_codes: BTreeSet::from([
            "local.approval.decide".to_owned(),
            "local.approval.read".to_owned(),
            "local.evidence.read".to_owned(),
            "local.founder-verdict.issue".to_owned(),
            "local.founder-verdict.revoke".to_owned(),
            "local.projection.await".to_owned(),
            "local.projection.status.read".to_owned(),
            "local.task.cancellation.request".to_owned(),
            "local.task.create".to_owned(),
            "local.task.read".to_owned(),
        ]),
        authorization_policy_ref: policy_contract(),
    }
}

fn position() -> Arc<dyn ProjectionPositionProvider> {
    Arc::new(FixedProjectionPosition(ProjectionPosition {
        epoch: "epoch-g4-08b".to_owned(),
        sequence: 41,
        projected_at: None,
    }))
}

fn open_request(surface: ClientSurface) -> OpenSessionRequest {
    OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: format!("{}-client", surface.as_str_name().to_ascii_lowercase()),
        surface: surface as i32,
        supported_contracts: vec![api_contract()],
    }
}

fn metadata(response_session_id: &str, request: &OpenSessionRequest) -> ClientRequestMetadata {
    ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: request.client_instance_id.clone(),
        surface: request.surface,
        session_id: response_session_id.to_owned(),
        api_contract_ref: Some(api_contract()),
        correlation_id: None,
    }
}

#[cfg(windows)]
async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address =
        LocalIpcAddress::for_instance(&format!("session-peer-{}", Uuid::now_v7())).unwrap();
    let mut listener = LocalIpcListener::bind(address.clone()).unwrap();
    let client = LocalIpcClient::connect(&address).await.unwrap();
    let connection = listener.accept().await.unwrap();
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

fn build_endpoint(
    resolver: Arc<dyn TrustedPrincipalResolver>,
    clock: Arc<dyn SessionClock>,
    audit: Arc<dyn SessionAuditSink>,
) -> LocalSessionEndpoint {
    LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .unwrap(),
        resolver,
        clock,
        position(),
        audit,
    )
}

#[cfg(windows)]
#[tokio::test]
async fn open_session_binds_kernel_peer_and_surface_without_changing_capabilities() {
    let peer = real_peer().await;
    let resolver = Arc::new(MutableResolver::allow(
        peer.principal().clone(),
        founder_grant(),
    ));
    let audit = Arc::new(RecordingAudit::default());
    let endpoint = build_endpoint(
        resolver,
        Arc::new(MutableClock::new(UNIX_EPOCH + Duration::from_secs(10))),
        audit.clone(),
    );

    let mut permissions = None;
    for surface in [
        ClientSurface::Desktop,
        ClientSurface::Cli,
        ClientSurface::Tui,
    ] {
        let input = open_request(surface);
        let mut request = Request::new(input);
        request.extensions_mut().insert(peer.clone());
        let response = endpoint.open_session(request).await.unwrap().into_inner();
        assert!(response.error.is_none());
        assert_eq!(response.authenticated_principal_id, "os-user:founder");
        assert_eq!(response.negotiated_contract_ref, Some(api_contract()));
        assert_eq!(response.client_kernel_contract_ref, Some(kernel_contract()));
        assert_eq!(response.authorization_policy_ref, Some(policy_contract()));
        assert_eq!(response.current_position.unwrap().sequence, 41);
        assert!(!response.session_id.is_empty());
        if let Some(expected) = &permissions {
            assert_eq!(expected, &response.granted_permission_codes);
        } else {
            permissions = Some(response.granted_permission_codes);
        }
    }
    assert_eq!(endpoint.registry().active_count(), 3);
    assert_eq!(
        audit
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == SessionAuditKind::Opened)
            .count(),
        3
    );
}

#[cfg(windows)]
#[tokio::test]
async fn session_fails_closed_for_missing_peer_bad_contract_and_resolver_denial() {
    let peer = real_peer().await;
    let resolver = Arc::new(MutableResolver::allow(
        peer.principal().clone(),
        founder_grant(),
    ));
    let endpoint = build_endpoint(
        resolver.clone(),
        Arc::new(MutableClock::new(UNIX_EPOCH + Duration::from_secs(10))),
        Arc::new(RecordingAudit::default()),
    );

    let missing_peer = endpoint
        .open_session(Request::new(open_request(ClientSurface::Cli)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        missing_peer.error.unwrap().code,
        LocalApiErrorCode::Unauthenticated as i32
    );

    let mut bad_contract_input = open_request(ClientSurface::Cli);
    bad_contract_input.supported_contracts[0].sha256 = "f".repeat(64);
    let mut bad_contract_request = Request::new(bad_contract_input);
    bad_contract_request.extensions_mut().insert(peer.clone());
    let bad_contract = endpoint
        .open_session(bad_contract_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        bad_contract.error.unwrap().code,
        LocalApiErrorCode::ContractIncompatible as i32
    );

    resolver.set(Err(PrincipalResolutionFailure::PermissionDenied));
    let mut denied_request = Request::new(open_request(ClientSurface::Desktop));
    denied_request.extensions_mut().insert(peer.clone());
    let denied = endpoint
        .open_session(denied_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        denied.error.unwrap().code,
        LocalApiErrorCode::PermissionDenied as i32
    );
    assert_eq!(endpoint.registry().active_count(), 0);

    let mut unknown_surface_input = open_request(ClientSurface::Cli);
    unknown_surface_input.surface = i32::MAX;
    let mut unknown_surface_request = Request::new(unknown_surface_input);
    unknown_surface_request
        .extensions_mut()
        .insert(real_peer().await);
    let unknown_surface = endpoint
        .open_session(unknown_surface_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        unknown_surface.error.unwrap().code,
        LocalApiErrorCode::UnknownCriticalSemantics as i32
    );

    resolver.set(Err(PrincipalResolutionFailure::PolicyUnavailable));
    let mut unavailable_request = Request::new(open_request(ClientSurface::Tui));
    unavailable_request.extensions_mut().insert(peer);
    let unavailable = endpoint
        .open_session(unavailable_request)
        .await
        .unwrap()
        .into_inner();
    let unavailable_error = unavailable.error.unwrap();
    assert_eq!(
        unavailable_error.code,
        LocalApiErrorCode::AuthorityUnavailable as i32
    );
    assert!(unavailable_error.retryable);

    let deny_all = build_endpoint(
        Arc::new(DenyAllPrincipalResolver),
        Arc::new(MutableClock::new(UNIX_EPOCH + Duration::from_secs(10))),
        Arc::new(RecordingAudit::default()),
    );
    let mut default_denied_request = Request::new(open_request(ClientSurface::Cli));
    default_denied_request
        .extensions_mut()
        .insert(real_peer().await);
    let default_denied = deny_all
        .open_session(default_denied_request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        default_denied.error.unwrap().code,
        LocalApiErrorCode::PermissionDenied as i32
    );
    assert_eq!(deny_all.registry().active_count(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn session_authentication_rechecks_binding_expiry_revoke_and_policy_drift() {
    let peer = real_peer().await;
    let clock = MutableClock::new(UNIX_EPOCH + Duration::from_secs(10));
    let resolver = Arc::new(MutableResolver::allow(
        peer.principal().clone(),
        founder_grant(),
    ));
    let endpoint = build_endpoint(
        resolver.clone(),
        Arc::new(clock.clone()),
        Arc::new(RecordingAudit::default()),
    );
    let input = open_request(ClientSurface::Cli);
    let mut request = Request::new(input.clone());
    request.extensions_mut().insert(peer.clone());
    let opened = endpoint.open_session(request).await.unwrap().into_inner();
    let registry = endpoint.registry();
    let valid_metadata = metadata(&opened.session_id, &input);
    assert!(registry.authenticate(Some(&valid_metadata), &peer).is_ok());

    let restarted_endpoint = build_endpoint(
        resolver.clone(),
        Arc::new(clock.clone()),
        Arc::new(RecordingAudit::default()),
    );
    assert_eq!(
        restarted_endpoint
            .registry()
            .authenticate(Some(&valid_metadata), &peer),
        Err(SessionAuthenticationFailure::NotFound)
    );

    let mut forged_surface = valid_metadata.clone();
    forged_surface.surface = ClientSurface::Desktop as i32;
    assert_eq!(
        registry.authenticate(Some(&forged_surface), &peer),
        Err(SessionAuthenticationFailure::ClientBindingMismatch)
    );

    let mut changed_grant = founder_grant();
    changed_grant
        .permission_codes
        .remove("local.approval.decide");
    resolver.set(Ok(changed_grant));
    assert_eq!(
        registry.authenticate(Some(&valid_metadata), &peer),
        Err(SessionAuthenticationFailure::PolicyDrift)
    );
    resolver.set(Ok(founder_grant()));

    assert!(registry.revoke(&opened.session_id).unwrap());
    assert_eq!(
        registry.authenticate(Some(&valid_metadata), &peer),
        Err(SessionAuthenticationFailure::Revoked)
    );

    let mut second_request = Request::new(input.clone());
    second_request.extensions_mut().insert(peer.clone());
    let second = endpoint
        .open_session(second_request)
        .await
        .unwrap()
        .into_inner();
    clock.advance(Duration::from_secs(61));
    assert_eq!(
        registry.authenticate(Some(&metadata(&second.session_id, &input)), &peer),
        Err(SessionAuthenticationFailure::Expired)
    );
}

#[cfg(windows)]
#[tokio::test]
async fn tonic_open_session_runs_over_real_named_pipe_without_tcp() {
    let address =
        LocalIpcAddress::for_instance(&format!("tonic-session-{}", Uuid::now_v7())).unwrap();
    let listener = LocalIpcListener::bind(address.clone()).unwrap();
    let resolver = Arc::new(MutableResolver::allow(
        listener.owner_principal().clone(),
        founder_grant(),
    ));
    let endpoint = build_endpoint(
        resolver,
        Arc::new(MutableClock::new(UNIX_EPOCH + Duration::from_secs(10))),
        Arc::new(RecordingAudit::default()),
    );
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LocalSessionServiceServer::new(endpoint))
            .serve_with_incoming_shutdown(listener.into_incoming(), async {
                let _ = shutdown_receiver.await;
            })
            .await
            .unwrap();
    });

    let connector_address = address.clone();
    let channel = Endpoint::try_from("http://egopulse.local")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let address = connector_address.clone();
            async move { LocalIpcClient::connect(&address).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut client = LocalSessionServiceClient::new(channel);
    let response = client
        .open_session(open_request(ClientSurface::Cli))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none());
    assert_eq!(response.authenticated_principal_id, "os-user:founder");
    assert_eq!(response.negotiated_contract_ref, Some(api_contract()));

    shutdown_sender.send(()).unwrap();
    server.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn child_named_pipe_session_and_abort() {
    let Ok(instance) = std::env::var("EGOPULSE_G4_08B_CHILD_INSTANCE") else {
        return;
    };
    let address = LocalIpcAddress::for_instance(&instance).unwrap();
    let connector_address = address.clone();
    let channel = Endpoint::try_from("http://egopulse.local")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let address = connector_address.clone();
            async move { LocalIpcClient::connect(&address).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut client = LocalSessionServiceClient::new(channel);
    let response = client
        .open_session(open_request(ClientSurface::Cli))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none());
    std::process::abort();
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_process_abort_does_not_corrupt_listener_or_session_registry() {
    let instance = format!("abort-session-{}", Uuid::now_v7());
    let address = LocalIpcAddress::for_instance(&instance).unwrap();
    let listener = LocalIpcListener::bind(address.clone()).unwrap();
    let resolver = Arc::new(MutableResolver::allow(
        listener.owner_principal().clone(),
        founder_grant(),
    ));
    let endpoint = build_endpoint(
        resolver,
        Arc::new(MutableClock::new(UNIX_EPOCH + Duration::from_secs(10))),
        Arc::new(RecordingAudit::default()),
    );
    let registry = endpoint.registry();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LocalSessionServiceServer::new(endpoint))
            .serve_with_incoming_shutdown(listener.into_incoming(), async {
                let _ = shutdown_receiver.await;
            })
            .await
            .unwrap();
    });

    let executable = std::env::current_exe().unwrap();
    let child_status = tokio::task::spawn_blocking(move || {
        Command::new(executable)
            .arg("--exact")
            .arg("child_named_pipe_session_and_abort")
            .arg("--nocapture")
            .env("EGOPULSE_G4_08B_CHILD_INSTANCE", instance)
            .status()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!child_status.success());

    let connector_address = address.clone();
    let channel = Endpoint::try_from("http://egopulse.local")
        .unwrap()
        .connect_with_connector(service_fn(move |_| {
            let address = connector_address.clone();
            async move { LocalIpcClient::connect(&address).await.map(TokioIo::new) }
        }))
        .await
        .unwrap();
    let mut client = LocalSessionServiceClient::new(channel);
    let response = client
        .open_session(open_request(ClientSurface::Desktop))
        .await
        .unwrap()
        .into_inner();
    assert!(response.error.is_none());
    assert_eq!(registry.active_count(), 2);

    shutdown_sender.send(()).unwrap();
    server.await.unwrap();
}
