#![cfg(windows)]

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_agentosd::{
    AuthorityPrincipalBinding, ConfiguredAuthorityPrincipalResolver, ContextMutationPortAdapter,
};
use egopulse_cognition_runtime::{
    context_authority::{
        AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityConfig,
        ContextGovernanceState as AuthorityContextGovernanceState, ContextPrincipalKind,
        IssueContextSnapshot,
    },
    task_authority::SqlCipherKey,
};
use egopulse_domain_contracts::{
    context_revoke::ContextRevokeSemanticRequest,
    profiles::{
        API_CONTRACT_DIGEST_SHA256, API_CONTRACT_ID, API_CONTRACT_VERSION,
        AUTHORIZATION_CONTRACT_ID, AUTHORIZATION_CONTRACT_VERSION,
        AUTHORIZATION_PROFILE_DIGEST_SHA256, CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION, CLIENT_KERNEL_PROFILE_DIGEST_SHA256, ContractProfiles,
    },
    v01::egopulse::{
        common::v1::{CommandMetadata, ContractReference},
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, ConfirmWorkRequest, ContextGovernanceState,
            ContextMutationCommand, ContextRevokeReceipt, ExecuteContextMutationRequest,
            ExecuteContextMutationResponse, MemoryMutationCommand, MemoryMutationReceipt,
            OpenSessionRequest, PrepareWorkRequest, ProjectionPosition, WorkPreparationPreview,
            context_mutation_command, execute_context_mutation_response,
            local_session_service_server::LocalSessionService,
        },
        policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
        task::v1::{TaskCommand, TaskCommandResult},
        verdict::v1::{VerdictCommand, VerdictCommandResult},
    },
};
use egopulse_local_api::{
    command_gateway::{
        CommandExtensionPorts, CommandGatewayApplication, CommandPortFailure, CommandPortResult,
        CommandPrincipal, MemoryMutationPort, PolicyCommandPort, TaskCommandPort,
        VerdictCommandPort, WorkPreparationPort,
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

const FOUNDER_ID: &str = "founder:r9a2b-real-gateway";
const REASON_CODE: &str = "founder-withdrawn";
const CONFIRMATION_PROOF_REF: &str = "confirmation:local:r9a2b";

#[derive(Clone, Copy)]
struct FixedClock(SystemTime);

impl SessionClock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[derive(Clone)]
struct SessionPrincipalResolver {
    peer: OsPrincipal,
    grant: PrincipalGrant,
}

impl TrustedPrincipalResolver for SessionPrincipalResolver {
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
struct NoopSessionAudit;

impl SessionAuditSink for NoopSessionAudit {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Clone)]
struct UnexpectedCommandPorts(Arc<AtomicUsize>);

impl UnexpectedCommandPorts {
    fn called(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl TaskCommandPort for UnexpectedCommandPorts {
    fn execute(
        &self,
        _command: &TaskCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }
}

impl PolicyCommandPort for UnexpectedCommandPorts {
    fn execute(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }
}

impl VerdictCommandPort for UnexpectedCommandPorts {
    fn execute(
        &self,
        _command: &VerdictCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }
}

impl MemoryMutationPort for UnexpectedCommandPorts {
    fn execute(
        &self,
        _command: &MemoryMutationCommand,
        _principal: &CommandPrincipal,
    ) -> Result<MemoryMutationReceipt, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }
}

#[tonic::async_trait]
impl WorkPreparationPort for UnexpectedCommandPorts {
    async fn prepare(
        &self,
        _request: &PrepareWorkRequest,
        _principal: &CommandPrincipal,
    ) -> Result<WorkPreparationPreview, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }

    fn confirm(
        &self,
        _request: &ConfirmWorkRequest,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        self.called();
        Err(CommandPortFailure::IntegrityFailure)
    }
}

fn test_root() -> PathBuf {
    std::env::temp_dir().join(format!("egopulse-r9a2b-real-gateway-{}", Uuid::now_v7()))
}

fn open_authority(root: &Path) -> ContextAuthority {
    fs::create_dir_all(root).expect("create Context Authority test root");
    ContextAuthority::open(ContextAuthorityConfig {
        database_path: root.join("context-authority.db"),
        store_epoch: "r9a2b-real-gateway".to_owned(),
        key: SqlCipherKey::new([0x79; 32]),
    })
    .expect("open Context Authority")
}

fn issue_snapshot(
    authority: &mut ContextAuthority,
) -> egopulse_cognition_runtime::context_authority::ContextSnapshot {
    authority
        .issue(
            &IssueContextSnapshot {
                owner_principal_id: FOUNDER_ID.to_owned(),
                intent: "prove the real Context revoke gateway path".to_owned(),
                work_type: "governed_repository_change".to_owned(),
                target_scope_ref: "scope:repository".to_owned(),
                compiled_context: br#"{"prompt":"r9a2b-real-gateway"}"#.to_vec(),
                sources: Vec::new(),
                memory_pack: None,
                allowed_read_paths: vec!["workspace".to_owned()],
                allowed_write_paths: vec!["workspace".to_owned()],
                allowed_tools: Vec::new(),
                external_resources: Vec::new(),
                non_goals: Vec::new(),
                acceptance_contract_ref: "acceptance:r9a2b".to_owned(),
                budget_profile_ref: "budget:r9a2b".to_owned(),
                deadline_seconds: None,
                recovery_entry: "hold-and-reconcile".to_owned(),
                visibility: "founder-only".to_owned(),
                redactions: Vec::new(),
                expires_at_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock")
                    .as_secs() as i64
                    + 600,
                idempotency_key: "issue:r9a2b-real-gateway".to_owned(),
            },
            &AuthenticatedContextPrincipal {
                kind: ContextPrincipalKind::ContextCompiler,
                principal_id: "context-compiler:r9a2b".to_owned(),
                authenticated: true,
            },
        )
        .expect("issue Context snapshot")
        .1
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

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address = LocalIpcAddress::for_instance(&format!("r9a2b-real-{}", Uuid::now_v7()))
        .expect("IPC address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind IPC listener");
    let client = LocalIpcClient::connect(&address)
        .await
        .expect("connect IPC client");
    let connection = listener.accept().await.expect("accept IPC peer");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

async fn open_founder_session() -> (
    PeerConnectionInfo,
    Arc<SessionRegistry>,
    ClientRequestMetadata,
    Arc<dyn SessionClock>,
) {
    let peer = real_peer().await;
    let clock: Arc<dyn SessionClock> =
        Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs(1_000)));
    let endpoint = LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .expect("session config"),
        Arc::new(SessionPrincipalResolver {
            peer: peer.principal().clone(),
            grant: PrincipalGrant {
                authenticated_principal_id: FOUNDER_ID.to_owned(),
                permission_codes: BTreeSet::from(["local.context.revoke".to_owned()]),
                authorization_policy_ref: contract_ref(
                    AUTHORIZATION_CONTRACT_ID,
                    AUTHORIZATION_CONTRACT_VERSION,
                    AUTHORIZATION_PROFILE_DIGEST_SHA256,
                ),
            },
        }),
        Arc::clone(&clock),
        Arc::new(FixedProjectionPosition(ProjectionPosition {
            epoch: "r9a2b-real-gateway".to_owned(),
            sequence: 1,
            projected_at: None,
        })) as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopSessionAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "r9a2b-real-client".to_owned(),
        surface: ClientSurface::Cli as i32,
        supported_contracts: vec![api_contract()],
    };
    let mut request = Request::new(open.clone());
    request.extensions_mut().insert(peer.clone());
    let opened = endpoint
        .open_session(request)
        .await
        .expect("open session transport")
        .into_inner();
    assert!(opened.error.is_none(), "Founder session must open");
    let registry = endpoint.registry();
    let client = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("correlation:r9a2b-real".to_owned()),
    };
    (peer, registry, client, clock)
}

fn revoke_request(
    client: &ClientRequestMetadata,
    snapshot_id: &str,
    evidence_refs: &[String],
    request_digest_sha256: &str,
) -> ExecuteContextMutationRequest {
    ExecuteContextMutationRequest {
        client: Some(client.clone()),
        command: Some(ContextMutationCommand {
            command: Some(context_mutation_command::Command::RevokeContextSnapshot(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeContextSnapshotCommand {
                    metadata: Some(CommandMetadata {
                        command_id: "command:r9a2b-real-revoke".to_owned(),
                        idempotency_key: "revoke:r9a2b-real".to_owned(),
                        idempotency_scope: "context-revoke".to_owned(),
                        request_digest_sha256: request_digest_sha256.to_owned(),
                        issued_at: Some(Timestamp {
                            seconds: 1_000,
                            nanos: 0,
                        }),
                        correlation_id: client
                            .correlation_id
                            .clone()
                            .expect("test correlation ID"),
                        causation_id: Some("causation:r9a2b-real".to_owned()),
                    }),
                    snapshot_id: snapshot_id.to_owned(),
                    expected_state_revision: 1,
                    reason_code: REASON_CODE.to_owned(),
                    evidence_refs: evidence_refs.to_vec(),
                    confirmation_proof_ref: CONFIRMATION_PROOF_REF.to_owned(),
                },
            )),
        }),
    }
}

fn authority_receipt(response: ExecuteContextMutationResponse) -> ContextRevokeReceipt {
    match response.outcome.expect("Context mutation outcome") {
        execute_context_mutation_response::Outcome::AuthorityResult(receipt) => receipt,
        execute_context_mutation_response::Outcome::Error(error) => {
            panic!("unexpected Context gateway error: {error:?}")
        }
    }
}

fn assert_private_semantics_are_sanitized(response: &ExecuteContextMutationResponse) {
    let encoded = response.encode_to_vec();
    for private in [
        REASON_CODE,
        "evidence:r9a2b:1",
        "evidence:r9a2b:2",
        CONFIRMATION_PROOF_REF,
    ] {
        assert!(
            !encoded
                .windows(private.len())
                .any(|window| window == private.as_bytes()),
            "private Context revoke field leaked into receipt: {private}"
        );
    }
}

#[tokio::test]
async fn r9a2b_real_gateway_constructs_verified_revoke_and_commits_durable_replay() {
    let root = test_root();
    let mut context_authority = open_authority(&root);
    let snapshot = issue_snapshot(&mut context_authority);
    let issued = context_authority
        .governance(&snapshot.snapshot_id)
        .expect("read issued governance")
        .expect("issued governance exists");
    assert_eq!(issued.state, AuthorityContextGovernanceState::Issued);
    assert_eq!(issued.state_revision, 1);
    assert_eq!(issued.snapshot_revision, 1);
    let before = context_authority
        .inspect_store()
        .expect("inspect store before revoke");
    assert_eq!(before.snapshot_count, 1);
    assert_eq!(before.event_count, 1);
    assert_eq!(before.idempotency_count, 1);
    assert_eq!(before.revoke_receipt_count, 0);
    assert_eq!(before.revoke_idempotency_count, 0);

    let authority = Arc::new(Mutex::new(context_authority));
    let authority_principals =
        ConfiguredAuthorityPrincipalResolver::new([AuthorityPrincipalBinding {
            principal_id: FOUNDER_ID.to_owned(),
            task: None,
            policy: None,
            verdict: None,
            memory: None,
            context: Some(ContextPrincipalKind::Founder),
        }])
        .expect("explicit Founder Context binding");
    let context_port = Arc::new(ContextMutationPortAdapter::new(
        Arc::clone(&authority),
        Arc::new(authority_principals),
    ));
    let (peer, registry, client, clock) = open_founder_session().await;
    let other_calls = Arc::new(AtomicUsize::new(0));
    let other_ports = Arc::new(UnexpectedCommandPorts(Arc::clone(&other_calls)));
    let app = CommandGatewayApplication::new_with_memory_and_work(
        registry,
        Arc::new(ContractProfiles::embedded().expect("embedded contract profiles")),
        Arc::new(ReadTokenCodec::new(
            TokenMacKey::new([0x2a; 32]).expect("read token key"),
            ReadGatewayPolicy::v01(),
            clock,
        )),
        other_ports.clone(),
        other_ports.clone(),
        other_ports.clone(),
        CommandExtensionPorts::new(other_ports.clone(), other_ports).with_context(context_port),
    );

    let evidence_refs = vec!["evidence:r9a2b:1".to_owned(), "evidence:r9a2b:2".to_owned()];
    let semantic_digest = ContextRevokeSemanticRequest {
        founder_principal_id: FOUNDER_ID,
        snapshot_id: &snapshot.snapshot_id,
        expected_state_revision: 1,
        reason_code: REASON_CODE,
        evidence_refs: &evidence_refs,
        confirmation_proof_ref: CONFIRMATION_PROOF_REF,
    }
    .digest_sha256();
    let request = revoke_request(
        &client,
        &snapshot.snapshot_id,
        &evidence_refs,
        &semantic_digest,
    );

    let first_response = app.execute_context_mutation(Some(&peer), request.clone());
    assert_private_semantics_are_sanitized(&first_response);
    let first = authority_receipt(first_response);
    assert_eq!(first.snapshot_id, snapshot.snapshot_id);
    assert_eq!(first.snapshot_revision, 1);
    assert_eq!(
        first.content_digest_sha256,
        snapshot.compiled_context_sha256
    );
    assert_eq!(first.previous_state_revision, 1);
    assert_eq!(first.result_state_revision, 2);
    assert_eq!(first.previous_state, ContextGovernanceState::Issued as i32);
    assert_eq!(first.result_state, ContextGovernanceState::Revoked as i32);
    assert_eq!(first.request_digest_sha256, semantic_digest);
    assert!(!first.event_id.is_empty());
    assert!(first.committed_at.is_some());
    assert!(!first.replayed);
    assert!(first.acknowledged_after_durability_barrier);
    assert_eq!(other_calls.load(Ordering::SeqCst), 0);

    let committed = authority
        .lock()
        .expect("Context Authority lock")
        .inspect_store()
        .expect("inspect store after revoke");
    assert_eq!(committed.snapshot_count, before.snapshot_count);
    assert_eq!(committed.event_count, before.event_count + 1);
    assert_eq!(committed.idempotency_count, before.idempotency_count);
    assert_eq!(committed.revoke_receipt_count, 1);
    assert_eq!(committed.revoke_idempotency_count, 1);
    assert_eq!(committed.dispatch_authorization_count, 0);
    assert_eq!(committed.dispatch_authorization_idempotency_count, 0);
    let revoked = authority
        .lock()
        .expect("Context Authority lock")
        .governance(&snapshot.snapshot_id)
        .expect("read revoked governance")
        .expect("revoked governance exists");
    assert_eq!(revoked.state, AuthorityContextGovernanceState::Revoked);
    assert_eq!(revoked.state_revision, 2);
    assert_eq!(revoked.snapshot_revision, 1);
    assert_eq!(
        revoked.content_digest_sha256,
        snapshot.compiled_context_sha256
    );

    let replay_response = app.execute_context_mutation(Some(&peer), request);
    assert_private_semantics_are_sanitized(&replay_response);
    let replay = authority_receipt(replay_response);
    let mut expected_replay = first;
    expected_replay.replayed = true;
    assert_eq!(replay, expected_replay);
    let after_replay = authority
        .lock()
        .expect("Context Authority lock")
        .inspect_store()
        .expect("inspect store after exact replay");
    assert_eq!(after_replay, committed);
    assert_eq!(other_calls.load(Ordering::SeqCst), 0);

    drop(app);
    drop(authority);
    fs::remove_dir_all(root).expect("remove Context Authority test root");
}
