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
        common::v1::{CommandMetadata, ContractReference},
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, ContextGovernanceState, ContextMutationCommand,
            ContextRevokeReceipt, ExecuteContextMutationRequest, LocalApiErrorCode,
            OpenSessionRequest, ProjectionPosition, context_mutation_command,
            execute_context_mutation_response, local_session_service_server::LocalSessionService,
        },
        policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
        task::v1::{TaskCommand, TaskCommandResult},
        verdict::v1::{VerdictCommand, VerdictCommandResult},
    },
};
use egopulse_local_api::{
    command_gateway::{
        CommandExtensionPorts, CommandGatewayApplication, CommandPortFailure, CommandPortResult,
        CommandPrincipal, ContextMutationPort, ContextMutationPortFailure,
        FailClosedMemoryMutationPort, FailClosedWorkPreparationPort, PolicyCommandPort,
        TaskCommandPort, VerdictCommandPort, VerifiedContextRevokeCommand,
    },
    read_gateway_policy::ReadGatewayPolicy,
    read_tokens::{ReadTokenCodec, TokenMacKey},
    session::{
        FixedProjectionPosition, LocalSessionEndpoint, PrincipalGrant, PrincipalResolutionFailure,
        ProjectionPositionProvider, SessionAuditEvent, SessionAuditSink, SessionClock,
        SessionConfig, SessionRegistry, TrustedPrincipalResolver,
    },
};
use egopulse_local_ipc_platform::{
    LocalIpcAddress, LocalIpcClient, LocalIpcListener, OsPrincipal, PeerConnectionInfo,
};
use prost::Message;
use prost_types::Timestamp;
use tonic::Request;
use uuid::Uuid;

const FOUNDER: &str = "os-user:founder";
const SNAPSHOT_ID: &str = "ctx:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FIXED_DIGEST: &str = "08d5c9f548acdef1cf739b73205510084c6c3ecd010ece536881a155eff3befc";

#[derive(Clone)]
struct FixedClock(Arc<Mutex<SystemTime>>);

impl FixedClock {
    fn new(now: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn set(&self, now: SystemTime) {
        *self.0.lock().expect("clock lock") = now;
    }
}

impl SessionClock for FixedClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().expect("clock lock")
    }
}

#[derive(Clone)]
struct Resolver {
    peer: OsPrincipal,
    grant: PrincipalGrant,
}

impl TrustedPrincipalResolver for Resolver {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        if principal == &self.peer {
            Ok(self.grant.clone())
        } else {
            Err(PrincipalResolutionFailure::PermissionDenied)
        }
    }
}

#[derive(Default)]
struct NoopAudit;

impl SessionAuditSink for NoopAudit {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Clone)]
struct UnexpectedCommandPort(Arc<AtomicUsize>);

impl TaskCommandPort for UnexpectedCommandPort {
    fn execute(
        &self,
        _command: &TaskCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandPortFailure::IntegrityFailure)
    }
}

impl PolicyCommandPort for UnexpectedCommandPort {
    fn execute(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandPortFailure::IntegrityFailure)
    }
}

impl VerdictCommandPort for UnexpectedCommandPort {
    fn execute(
        &self,
        _command: &VerdictCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CommandPortFailure::IntegrityFailure)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedRevoke {
    principal: CommandPrincipal,
    command_id: String,
    snapshot_id: String,
    expected_state_revision: u64,
    reason_code: String,
    evidence_refs: Vec<String>,
    confirmation_proof_ref: String,
    idempotency_key: String,
    correlation_id: String,
    causation_id: Option<String>,
    request_digest_sha256: String,
}

#[derive(Clone)]
struct RecordingContextPort {
    calls: Arc<AtomicUsize>,
    observed: Arc<Mutex<Option<ObservedRevoke>>>,
    outcome: Arc<Mutex<Result<ContextRevokeReceipt, ContextMutationPortFailure>>>,
}

impl ContextMutationPort for RecordingContextPort {
    fn revoke(
        &self,
        command: &VerifiedContextRevokeCommand,
        principal: &CommandPrincipal,
    ) -> Result<ContextRevokeReceipt, ContextMutationPortFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.observed.lock().expect("observed context lock") = Some(ObservedRevoke {
            principal: principal.clone(),
            command_id: command.command_id().to_owned(),
            snapshot_id: command.snapshot_id().to_owned(),
            expected_state_revision: command.expected_state_revision(),
            reason_code: command.reason_code().to_owned(),
            evidence_refs: command.evidence_refs().to_vec(),
            confirmation_proof_ref: command.confirmation_proof_ref().to_owned(),
            idempotency_key: command.idempotency_key().to_owned(),
            correlation_id: command.correlation_id().to_owned(),
            causation_id: command.causation_id().map(str::to_owned),
            request_digest_sha256: command.request_digest_sha256().to_owned(),
        });
        self.outcome.lock().expect("context outcome lock").clone()
    }
}

struct Harness {
    peer: PeerConnectionInfo,
    client: ClientRequestMetadata,
    app: Arc<CommandGatewayApplication>,
    registry: Arc<SessionRegistry>,
    clock: FixedClock,
    context_calls: Arc<AtomicUsize>,
    other_command_calls: Arc<AtomicUsize>,
    observed: Arc<Mutex<Option<ObservedRevoke>>>,
    outcome: Arc<Mutex<Result<ContextRevokeReceipt, ContextMutationPortFailure>>>,
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

fn founder_grant(can_revoke: bool) -> PrincipalGrant {
    PrincipalGrant {
        authenticated_principal_id: FOUNDER.to_owned(),
        permission_codes: if can_revoke {
            BTreeSet::from(["local.context.revoke".to_owned()])
        } else {
            BTreeSet::from(["local.task.create".to_owned()])
        },
        authorization_policy_ref: contract_ref(
            AUTHORIZATION_CONTRACT_ID,
            AUTHORIZATION_CONTRACT_VERSION,
            AUTHORIZATION_PROFILE_DIGEST_SHA256,
        ),
    }
}

fn success_receipt() -> ContextRevokeReceipt {
    ContextRevokeReceipt {
        snapshot_id: SNAPSHOT_ID.to_owned(),
        snapshot_revision: 1,
        content_digest_sha256: "a".repeat(64),
        previous_state_revision: 1,
        result_state_revision: 2,
        previous_state: ContextGovernanceState::Issued as i32,
        result_state: ContextGovernanceState::Revoked as i32,
        request_digest_sha256: FIXED_DIGEST.to_owned(),
        event_id: "context-event:1".to_owned(),
        committed_at: Some(Timestamp {
            seconds: 101,
            nanos: 0,
        }),
        replayed: false,
        acknowledged_after_durability_barrier: true,
    }
}

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address = LocalIpcAddress::for_instance(&format!("r9a2b-gateway-{}", Uuid::now_v7()))
        .expect("IPC address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind IPC");
    let client = LocalIpcClient::connect(&address)
        .await
        .expect("connect IPC");
    let connection = listener.accept().await.expect("accept IPC");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

async fn harness(can_revoke: bool) -> Harness {
    let peer = real_peer().await;
    let clock_handle = FixedClock::new(UNIX_EPOCH + Duration::from_secs(100));
    let clock: Arc<dyn SessionClock> = Arc::new(clock_handle.clone());
    let endpoint = LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .expect("session config"),
        Arc::new(Resolver {
            peer: peer.principal().clone(),
            grant: founder_grant(can_revoke),
        }),
        Arc::clone(&clock),
        Arc::new(FixedProjectionPosition(ProjectionPosition {
            epoch: "r9a2b-gateway".to_owned(),
            sequence: 1,
            projected_at: None,
        })) as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "r9a2b-client".to_owned(),
        surface: ClientSurface::Cli as i32,
        supported_contracts: vec![api_contract()],
    };
    let mut open_request = Request::new(open.clone());
    open_request.extensions_mut().insert(peer.clone());
    let opened = endpoint
        .open_session(open_request)
        .await
        .expect("open session transport")
        .into_inner();
    assert!(opened.error.is_none(), "session must open");
    let client = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("r9a2b-correlation".to_owned()),
    };
    let context_calls = Arc::new(AtomicUsize::new(0));
    let other_command_calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::new(Mutex::new(None));
    let outcome = Arc::new(Mutex::new(Ok(success_receipt())));
    let unexpected = Arc::new(UnexpectedCommandPort(Arc::clone(&other_command_calls)));
    let registry = endpoint.registry();
    let app = Arc::new(CommandGatewayApplication::new_with_memory_and_work(
        Arc::clone(&registry),
        Arc::new(ContractProfiles::embedded().expect("embedded profiles")),
        Arc::new(ReadTokenCodec::new(
            TokenMacKey::new([42; 32]).expect("token key"),
            ReadGatewayPolicy::v01(),
            clock,
        )),
        unexpected.clone(),
        unexpected.clone(),
        unexpected,
        CommandExtensionPorts::new(
            Arc::new(FailClosedMemoryMutationPort),
            Arc::new(FailClosedWorkPreparationPort),
        )
        .with_context(Arc::new(RecordingContextPort {
            calls: Arc::clone(&context_calls),
            observed: Arc::clone(&observed),
            outcome: Arc::clone(&outcome),
        })),
    ));
    Harness {
        peer,
        client,
        app,
        registry,
        clock: clock_handle,
        context_calls,
        other_command_calls,
        observed,
        outcome,
    }
}

fn revoke_request(client: &ClientRequestMetadata) -> ExecuteContextMutationRequest {
    let correlation_id = client.correlation_id.clone().expect("test correlation id");
    ExecuteContextMutationRequest {
        client: Some(client.clone()),
        command: Some(ContextMutationCommand {
            command: Some(context_mutation_command::Command::RevokeContextSnapshot(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeContextSnapshotCommand {
                    metadata: Some(CommandMetadata {
                        command_id: Uuid::now_v7().to_string(),
                        idempotency_key: Uuid::now_v7().to_string(),
                        idempotency_scope: "context-revoke".to_owned(),
                        request_digest_sha256: FIXED_DIGEST.to_owned(),
                        issued_at: Some(Timestamp {
                            seconds: 100,
                            nanos: 0,
                        }),
                        correlation_id,
                        causation_id: Some("cause:r9a2b".to_owned()),
                    }),
                    snapshot_id: SNAPSHOT_ID.to_owned(),
                    expected_state_revision: 1,
                    reason_code: "founder-withdrawn".to_owned(),
                    evidence_refs: vec!["evidence:review:42".to_owned()],
                    confirmation_proof_ref: "confirmation:cli:01".to_owned(),
                },
            )),
        }),
    }
}

fn response_error(
    response: egopulse_domain_contracts::v01::egopulse::localapi::v1::ExecuteContextMutationResponse,
) -> egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError {
    match response.outcome.expect("response outcome") {
        execute_context_mutation_response::Outcome::Error(error) => error,
        execute_context_mutation_response::Outcome::AuthorityResult(_) => {
            panic!("expected an error-only outcome")
        }
    }
}

fn assert_private_request_fields_absent_from_wire(
    response: &egopulse_domain_contracts::v01::egopulse::localapi::v1::ExecuteContextMutationResponse,
) {
    let encoded = response.encode_to_vec();
    for forbidden in [
        "founder-withdrawn",
        "evidence:review:42",
        "confirmation:cli:01",
    ] {
        assert!(
            !encoded
                .windows(forbidden.len())
                .any(|window| window == forbidden.as_bytes()),
            "private request field leaked into encoded response: {forbidden}"
        );
    }
}

#[tokio::test]
async fn r9a2b_gateway_valid_fixed_digest_derives_founder_and_calls_context_once() {
    let harness = harness(true).await;
    let request = revoke_request(&harness.client);
    let expected_command_id = request
        .command
        .as_ref()
        .and_then(|value| value.command.as_ref())
        .map(|value| match value {
            context_mutation_command::Command::RevokeContextSnapshot(command) => command
                .metadata
                .as_ref()
                .expect("metadata")
                .command_id
                .clone(),
        })
        .expect("command");
    let response = harness
        .app
        .execute_context_mutation(Some(&harness.peer), request);
    assert_private_request_fields_absent_from_wire(&response);
    let receipt = match response.outcome.expect("response outcome") {
        execute_context_mutation_response::Outcome::AuthorityResult(receipt) => receipt,
        execute_context_mutation_response::Outcome::Error(error) => {
            panic!("unexpected gateway error: {error:?}")
        }
    };
    assert_eq!(receipt, success_receipt());
    assert_eq!(harness.context_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.other_command_calls.load(Ordering::SeqCst), 0);
    let observed = harness
        .observed
        .lock()
        .expect("observed lock")
        .clone()
        .expect("observed command");
    assert_eq!(observed.principal.principal_id, FOUNDER);
    assert_eq!(
        observed.principal.required_authority_principal_kinds,
        vec!["ContextAuthority.Founder"]
    );
    assert_eq!(observed.command_id, expected_command_id);
    assert_eq!(observed.snapshot_id, SNAPSHOT_ID);
    assert_eq!(observed.expected_state_revision, 1);
    assert_eq!(observed.reason_code, "founder-withdrawn");
    assert_eq!(observed.evidence_refs, vec!["evidence:review:42"]);
    assert_eq!(observed.confirmation_proof_ref, "confirmation:cli:01");
    assert_eq!(observed.correlation_id, "r9a2b-correlation");
    assert_eq!(observed.causation_id.as_deref(), Some("cause:r9a2b"));
    assert_eq!(observed.request_digest_sha256, FIXED_DIGEST);

    let mut replay_receipt = success_receipt();
    replay_receipt.replayed = true;
    *harness.outcome.lock().expect("context outcome lock") = Ok(replay_receipt.clone());
    let replay_response = harness
        .app
        .execute_context_mutation(Some(&harness.peer), revoke_request(&harness.client));
    assert_private_request_fields_absent_from_wire(&replay_response);
    let replay = match replay_response.outcome.expect("replay outcome") {
        execute_context_mutation_response::Outcome::AuthorityResult(receipt) => receipt,
        execute_context_mutation_response::Outcome::Error(error) => {
            panic!("unexpected replay error: {error:?}")
        }
    };
    assert_eq!(replay, replay_receipt);
    assert_eq!(harness.context_calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.other_command_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn r9a2b_gateway_invalid_digest_matrix_stops_before_context() {
    let harness = harness(true).await;
    let mut cases = Vec::new();

    let mut missing_metadata = revoke_request(&harness.client);
    let context_mutation_command::Command::RevokeContextSnapshot(command) = missing_metadata
        .command
        .as_mut()
        .and_then(|value| value.command.as_mut())
        .expect("revoke command");
    command.metadata = None;
    cases.push((
        "missing_metadata",
        missing_metadata,
        LocalApiErrorCode::InvalidArgument,
    ));

    for (name, digest, code) in [
        ("empty", String::new(), LocalApiErrorCode::InvalidArgument),
        (
            "truncated",
            FIXED_DIGEST[..63].to_owned(),
            LocalApiErrorCode::InvalidArgument,
        ),
        (
            "uppercase",
            FIXED_DIGEST.to_uppercase(),
            LocalApiErrorCode::InvalidArgument,
        ),
        (
            "mismatch",
            "0".repeat(64),
            LocalApiErrorCode::IntegrityFailure,
        ),
    ] {
        let mut request = revoke_request(&harness.client);
        let context_mutation_command::Command::RevokeContextSnapshot(command) = request
            .command
            .as_mut()
            .and_then(|value| value.command.as_mut())
            .expect("revoke command");
        command
            .metadata
            .as_mut()
            .expect("command metadata")
            .request_digest_sha256 = digest;
        cases.push((name, request, code));
    }

    for (name, request, expected_code) in cases {
        let error = response_error(
            harness
                .app
                .execute_context_mutation(Some(&harness.peer), request),
        );
        assert_eq!(error.code, expected_code as i32, "case {name}");
        assert_eq!(
            harness.context_calls.load(Ordering::SeqCst),
            0,
            "case {name} must stop before Context Authority"
        );
        assert_eq!(harness.other_command_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn r9a2b_gateway_context_metadata_bounds_stop_before_context() {
    let harness = harness(true).await;
    let mut cases = Vec::new();

    let mut oversized = revoke_request(&harness.client);
    let context_mutation_command::Command::RevokeContextSnapshot(command) = oversized
        .command
        .as_mut()
        .and_then(|value| value.command.as_mut())
        .expect("revoke command");
    command.metadata.as_mut().expect("metadata").command_id = "x".repeat(257);
    cases.push(("oversized_command_id", oversized));

    let mut controlled = revoke_request(&harness.client);
    let context_mutation_command::Command::RevokeContextSnapshot(command) = controlled
        .command
        .as_mut()
        .and_then(|value| value.command.as_mut())
        .expect("revoke command");
    command.metadata.as_mut().expect("metadata").causation_id = Some("cause:invalid\n".to_owned());
    cases.push(("control_causation_id", controlled));

    let mut padded = revoke_request(&harness.client);
    let context_mutation_command::Command::RevokeContextSnapshot(command) = padded
        .command
        .as_mut()
        .and_then(|value| value.command.as_mut())
        .expect("revoke command");
    command
        .metadata
        .as_mut()
        .expect("metadata")
        .idempotency_scope = " context-revoke ".to_owned();
    cases.push(("padded_idempotency_scope", padded));

    for (name, request) in cases {
        let error = response_error(
            harness
                .app
                .execute_context_mutation(Some(&harness.peer), request),
        );
        assert_eq!(
            error.code,
            LocalApiErrorCode::InvalidArgument as i32,
            "case {name}"
        );
        assert_eq!(
            error.safe_fingerprint, "context_command_metadata_invalid",
            "case {name}"
        );
        assert_eq!(harness.context_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.other_command_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn r9a2b_gateway_session_permission_and_peer_fail_before_context() {
    let denied = harness(false).await;
    let error = response_error(
        denied
            .app
            .execute_context_mutation(Some(&denied.peer), revoke_request(&denied.client)),
    );
    assert_eq!(error.code, LocalApiErrorCode::PermissionDenied as i32);
    assert_eq!(denied.context_calls.load(Ordering::SeqCst), 0);

    let allowed = harness(true).await;
    let error = response_error(
        allowed
            .app
            .execute_context_mutation(None, revoke_request(&allowed.client)),
    );
    assert_eq!(error.code, LocalApiErrorCode::Unauthenticated as i32);
    assert_eq!(allowed.context_calls.load(Ordering::SeqCst), 0);
    assert_eq!(allowed.other_command_calls.load(Ordering::SeqCst), 0);

    let mut forged = allowed.client.clone();
    forged.session_id = Uuid::now_v7().to_string();
    let error = response_error(
        allowed
            .app
            .execute_context_mutation(Some(&allowed.peer), revoke_request(&forged)),
    );
    assert_eq!(error.code, LocalApiErrorCode::Unauthenticated as i32);
    assert_eq!(allowed.context_calls.load(Ordering::SeqCst), 0);

    let mut wrong_binding = allowed.client.clone();
    wrong_binding.client_instance_id = "forged-client-instance".to_owned();
    let error = response_error(
        allowed
            .app
            .execute_context_mutation(Some(&allowed.peer), revoke_request(&wrong_binding)),
    );
    assert_eq!(error.code, LocalApiErrorCode::Unauthenticated as i32);
    assert_eq!(allowed.context_calls.load(Ordering::SeqCst), 0);

    let expired = harness(true).await;
    expired.clock.set(UNIX_EPOCH + Duration::from_secs(161));
    let error = response_error(
        expired
            .app
            .execute_context_mutation(Some(&expired.peer), revoke_request(&expired.client)),
    );
    assert_eq!(error.code, LocalApiErrorCode::SessionExpired as i32);
    assert_eq!(expired.context_calls.load(Ordering::SeqCst), 0);

    let revoked = harness(true).await;
    assert!(
        revoked
            .registry
            .revoke(&revoked.client.session_id)
            .expect("revoke session")
    );
    let error = response_error(
        revoked
            .app
            .execute_context_mutation(Some(&revoked.peer), revoke_request(&revoked.client)),
    );
    assert_eq!(error.code, LocalApiErrorCode::PermissionDenied as i32);
    assert_eq!(revoked.context_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn r9a2b_gateway_maps_context_failures_without_partial_receipt() {
    let harness = harness(true).await;
    let cases = [
        (
            ContextMutationPortFailure::InvalidArgument,
            LocalApiErrorCode::InvalidArgument,
            "context_authority_invalid_argument",
        ),
        (
            ContextMutationPortFailure::PermissionDenied,
            LocalApiErrorCode::PermissionDenied,
            "context_authority_permission_denied",
        ),
        (
            ContextMutationPortFailure::OwnerMismatch,
            LocalApiErrorCode::OwnerMismatch,
            "context_owner_mismatch",
        ),
        (
            ContextMutationPortFailure::NotFound,
            LocalApiErrorCode::NotFound,
            "context_snapshot_not_found",
        ),
        (
            ContextMutationPortFailure::ContextRevoked,
            LocalApiErrorCode::ContextRevoked,
            "context_snapshot_revoked",
        ),
        (
            ContextMutationPortFailure::StateRevisionConflict,
            LocalApiErrorCode::StateRevisionConflict,
            "context_state_revision_conflict",
        ),
        (
            ContextMutationPortFailure::IdempotencyConflict,
            LocalApiErrorCode::IdempotencyConflict,
            "context_idempotency_conflict",
        ),
        (
            ContextMutationPortFailure::IntegrityFailure,
            LocalApiErrorCode::IntegrityFailure,
            "context_authority_integrity_failure",
        ),
        (
            ContextMutationPortFailure::AuthorityUnavailable,
            LocalApiErrorCode::AuthorityUnavailable,
            "context_authority_unavailable",
        ),
        (
            ContextMutationPortFailure::UnknownCriticalSemantics,
            LocalApiErrorCode::UnknownCriticalSemantics,
            "context_authority_semantics_unknown",
        ),
    ];
    for (index, (failure, code, fingerprint)) in cases.into_iter().enumerate() {
        *harness.outcome.lock().expect("context outcome lock") = Err(failure);
        let response = harness
            .app
            .execute_context_mutation(Some(&harness.peer), revoke_request(&harness.client));
        assert_private_request_fields_absent_from_wire(&response);
        let error = response_error(response);
        assert_eq!(error.code, code as i32);
        assert_eq!(error.safe_fingerprint, fingerprint);
        assert_eq!(harness.context_calls.load(Ordering::SeqCst), index + 1);
        assert_eq!(harness.other_command_calls.load(Ordering::SeqCst), 0);
    }
}
