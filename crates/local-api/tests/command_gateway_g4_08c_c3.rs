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
    profiles::ContractProfiles,
    v01::egopulse::{
        common::v1::{CommandMetadata, ContractReference},
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, ExecuteFounderVerdictRequest,
            ExecuteTaskCommandRequest, LocalApiErrorCode, OpenSessionRequest, ProjectionPosition,
            SourceDomain, SourceRevision, local_session_service_server::LocalSessionService,
        },
        policy::v1::{
            HarnessApprovalDecisionRecord, HarnessApprovalDecisionState,
            IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult,
            PolicyDecisionErrorCode,
        },
        task::v1::{
            CreateTaskCommand, TaskCommand, TaskCommandResult, TaskError, TaskErrorCode,
            task_command, task_command_result,
        },
        verdict::v1::{
            IssueFounderVerdictCommand, VerdictCommand, VerdictCommandResult, VerdictErrorCode,
            verdict_command,
        },
    },
};
use egopulse_local_api::{
    command_gateway::{
        CommandGatewayApplication, CommandPortFailure, CommandPortResult, CommandPrincipal,
        PolicyCommandPort, TaskCommandPort, VerdictCommandPort,
    },
    read_gateway_policy::ReadGatewayPolicy,
    read_tokens::{AwaitTarget, ReadTokenCodec, TokenMacKey},
    session::{
        FixedProjectionPosition, LocalSessionEndpoint, PrincipalGrant, PrincipalResolutionFailure,
        ProjectionPositionProvider, SessionAuditEvent, SessionAuditSink, SessionClock,
        SessionConfig, TrustedPrincipalResolver,
    },
};
use egopulse_local_ipc_platform::{
    LocalIpcAddress, LocalIpcClient, LocalIpcListener, OsPrincipal, PeerConnectionInfo,
};
use prost_types::Timestamp;
use tonic::Request;
use uuid::Uuid;

const CONTRACT_DIGEST: &str = "28d05e2533ea7650d8fedbc44abfa21d33c2845f8d105650e3287676e789e7bb";
const KERNEL_DIGEST: &str = "10a0f4b05d2f799667c08af3514f855315076ac85785f59c81e1b9b60e2350e4";
const POLICY_DIGEST: &str = "5d17887f8e6555d0e4c973583dd07590a68a4be99c8b80a9e31877b9b2ed99b1";

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
struct NoopSessionAudit;

impl SessionAuditSink for NoopSessionAudit {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Clone)]
struct RecordingTaskPort {
    calls: Arc<AtomicUsize>,
    last_principal: Arc<Mutex<Option<CommandPrincipal>>>,
    last_metadata: Arc<Mutex<Option<CommandMetadata>>>,
    outcome: Arc<Mutex<Result<CommandPortResult<TaskCommandResult>, CommandPortFailure>>>,
}

impl TaskCommandPort for RecordingTaskPort {
    fn execute(
        &self,
        command: &TaskCommand,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_principal.lock().expect("principal lock") = Some(principal.clone());
        *self.last_metadata.lock().expect("metadata lock") = task_metadata(command).cloned();
        self.outcome.lock().expect("task port lock").clone()
    }
}

#[derive(Clone)]
struct RecordingPolicyPort {
    outcome: Arc<Mutex<Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure>>>,
}

impl PolicyCommandPort for RecordingPolicyPort {
    fn execute(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &egopulse_local_api::command_gateway::CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure> {
        self.outcome.lock().expect("policy port lock").clone()
    }
}

#[derive(Clone)]
struct RecordingVerdictPort {
    outcome: Arc<Mutex<Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure>>>,
}

impl VerdictCommandPort for RecordingVerdictPort {
    fn execute(
        &self,
        _command: &VerdictCommand,
        _principal: &egopulse_local_api::command_gateway::CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        self.outcome.lock().expect("verdict port lock").clone()
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
    contract_ref("egopulse.localapi.v1", "0.1.0-draft.16", CONTRACT_DIGEST)
}

fn kernel_contract() -> ContractReference {
    contract_ref("egopulse.client-kernel.v1", "0.1.0", KERNEL_DIGEST)
}

fn founder_grant() -> PrincipalGrant {
    PrincipalGrant {
        authenticated_principal_id: "os-user:founder".to_owned(),
        permission_codes: BTreeSet::from([
            "local.approval.decide".to_owned(),
            "local.founder-verdict.issue".to_owned(),
            "local.founder-verdict.revoke".to_owned(),
            "local.task.create".to_owned(),
        ]),
        authorization_policy_ref: contract_ref("egopulse.authorization.v1", "0.1.0", POLICY_DIGEST),
    }
}

fn metadata(correlation_id: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: Uuid::now_v7().to_string(),
        idempotency_key: Uuid::now_v7().to_string(),
        idempotency_scope: "local-api-test".to_owned(),
        request_digest_sha256: "digest".to_owned(),
        correlation_id: correlation_id.to_owned(),
        ..CommandMetadata::default()
    }
}

fn position() -> ProjectionPosition {
    ProjectionPosition {
        epoch: "epoch-command-gateway".to_owned(),
        sequence: 10,
        projected_at: None,
    }
}

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address = LocalIpcAddress::for_instance(&format!("command-gateway-{}", Uuid::now_v7()))
        .expect("address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind");
    let client = LocalIpcClient::connect(&address).await.expect("connect");
    let connection = listener.accept().await.expect("accept");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

async fn test_context(
    task_outcome: Result<CommandPortResult<TaskCommandResult>, CommandPortFailure>,
    policy_outcome: Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure>,
    verdict_outcome: Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure>,
) -> (
    PeerConnectionInfo,
    ClientRequestMetadata,
    Arc<CommandGatewayApplication>,
    Arc<AtomicUsize>,
    Arc<Mutex<Option<CommandPrincipal>>>,
    Arc<Mutex<Option<CommandMetadata>>>,
) {
    let peer = real_peer().await;
    let clock: Arc<dyn SessionClock> = Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs(100)));
    let endpoint = LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .expect("session config"),
        Arc::new(Resolver {
            peer: peer.principal().clone(),
            grant: founder_grant(),
        }),
        Arc::clone(&clock),
        Arc::new(FixedProjectionPosition(position())) as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopSessionAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "command-gateway-test".to_owned(),
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
    assert!(opened.error.is_none());
    let client = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("c3-correlation".to_owned()),
    };
    let task_calls = Arc::new(AtomicUsize::new(0));
    let last_principal = Arc::new(Mutex::new(None));
    let last_metadata = Arc::new(Mutex::new(None));
    let app = Arc::new(CommandGatewayApplication::new(
        endpoint.registry(),
        Arc::new(ContractProfiles::embedded().expect("profiles")),
        Arc::new(ReadTokenCodec::new(
            TokenMacKey::new([9; 32]).expect("key"),
            ReadGatewayPolicy::v01(),
            clock,
        )),
        Arc::new(RecordingTaskPort {
            calls: Arc::clone(&task_calls),
            last_principal: Arc::clone(&last_principal),
            last_metadata: Arc::clone(&last_metadata),
            outcome: Arc::new(Mutex::new(task_outcome)),
        }),
        Arc::new(RecordingPolicyPort {
            outcome: Arc::new(Mutex::new(policy_outcome)),
        }),
        Arc::new(RecordingVerdictPort {
            outcome: Arc::new(Mutex::new(verdict_outcome)),
        }),
    ));
    (peer, client, app, task_calls, last_principal, last_metadata)
}

fn task_metadata(command: &TaskCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        task_command::Command::CreateTask(value) => value.meta.as_ref(),
        task_command::Command::ActivateTask(value) => value.meta.as_ref(),
        _ => None,
    }
}

fn task_command(oneof: task_command::Command) -> TaskCommand {
    TaskCommand {
        command: Some(oneof),
    }
}

fn create_task_command() -> TaskCommand {
    task_command(task_command::Command::CreateTask(CreateTaskCommand {
        meta: Some(metadata("c3-correlation")),
        ..CreateTaskCommand::default()
    }))
}

fn activate_task_command() -> TaskCommand {
    task_command(task_command::Command::ActivateTask(
        egopulse_domain_contracts::v01::egopulse::task::v1::ActivateTaskCommand {
            meta: Some(metadata("c3-correlation")),
            ..Default::default()
        },
    ))
}

fn task_result_with_await() -> CommandPortResult<TaskCommandResult> {
    CommandPortResult {
        result: TaskCommandResult::default(),
        source_revision: Some(SourceRevision {
            domain: SourceDomain::Task as i32,
            aggregate_id: "task-1".to_owned(),
            revision: 1,
            last_event_id: "event-1".to_owned(),
        }),
        await_target: Some(AwaitTarget::Task {
            task_id: "task-1".to_owned(),
        }),
    }
}

fn task_result_with_error(
    code: TaskErrorCode,
    detail: &str,
) -> CommandPortResult<TaskCommandResult> {
    CommandPortResult {
        result: TaskCommandResult {
            replayed: false,
            committed_event: None,
            outcome: Some(task_command_result::Outcome::Error(TaskError {
                code: code as i32,
                safe_detail_code: detail.to_owned(),
                retryable: false,
                recovery_required: false,
                current_revision: None,
                audit_ref: None,
            })),
        },
        source_revision: None,
        await_target: None,
    }
}

fn replayed_task_result() -> CommandPortResult<TaskCommandResult> {
    let mut result = task_result_with_await();
    result.result.replayed = true;
    result
}

#[tokio::test]
async fn task_success_propagates_result_and_typed_await_token() {
    let (peer, client, app, calls, last_principal, last_metadata) = test_context(
        Ok(task_result_with_await()),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let request = ExecuteTaskCommandRequest {
        client: Some(client),
        command: Some(create_task_command()),
    };
    let response = app.execute_task_command(Some(&peer), request);
    assert!(response.gateway_error.is_none());
    assert!(response.authority_result.is_some());
    assert!(response.await_token.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        last_principal
            .lock()
            .expect("principal lock")
            .as_ref()
            .map(|value| value.required_authority_principal_kinds.clone()),
        Some(vec!["TaskAuthority.Founder".to_owned()])
    );
    assert_eq!(
        last_metadata
            .lock()
            .expect("metadata lock")
            .as_ref()
            .map(|value| value.correlation_id.as_str()),
        Some("c3-correlation")
    );
}

#[tokio::test]
async fn system_only_task_branch_is_denied_before_owner_port() {
    let (peer, client, app, calls, _last_principal, _last_metadata) = test_context(
        Ok(task_result_with_await()),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.execute_task_command(
        Some(&peer),
        ExecuteTaskCommandRequest {
            client: Some(client),
            command: Some(activate_task_command()),
        },
    );
    assert_eq!(
        response.gateway_error.as_ref().map(|error| error.code),
        Some(LocalApiErrorCode::PermissionDenied as i32)
    );
    assert!(response.authority_result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn authority_unavailable_is_returned_without_fabricating_success() {
    let (peer, client, app, calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.execute_task_command(
        Some(&peer),
        ExecuteTaskCommandRequest {
            client: Some(client),
            command: Some(create_task_command()),
        },
    );
    assert_eq!(
        response.gateway_error.as_ref().map(|error| error.code),
        Some(LocalApiErrorCode::AuthorityUnavailable as i32)
    );
    assert!(response.authority_result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn identical_request_identity_returns_owner_replay_without_gateway_rewrite() {
    let (peer, client, app, calls, _last_principal, _last_metadata) = test_context(
        Ok(replayed_task_result()),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let command = create_task_command();
    let request = ExecuteTaskCommandRequest {
        client: Some(client.clone()),
        command: Some(command.clone()),
    };
    let first = app.execute_task_command(Some(&peer), request.clone());
    let second = app.execute_task_command(Some(&peer), request);
    assert!(first.gateway_error.is_none());
    assert!(second.gateway_error.is_none());
    assert_eq!(first.authority_result, second.authority_result);
    assert_eq!(first.await_token, second.await_token);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn idempotency_conflict_is_preserved_as_owner_result() {
    let (peer, client, app, calls, _last_principal, _last_metadata) = test_context(
        Ok(task_result_with_error(
            TaskErrorCode::IdempotencyConflict,
            "task_idempotency_conflict",
        )),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.execute_task_command(
        Some(&peer),
        ExecuteTaskCommandRequest {
            client: Some(client),
            command: Some(create_task_command()),
        },
    );
    assert!(response.gateway_error.is_none());
    let authority_result = response.authority_result.expect("owner result");
    assert!(matches!(
        authority_result.outcome,
        Some(task_command_result::Outcome::Error(TaskError {
            code,
            ..
        })) if code == TaskErrorCode::IdempotencyConflict as i32
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[allow(deprecated)]
#[tokio::test]
async fn authority_denial_is_preserved_in_sanitized_approval_result() {
    let (peer, client, app, _calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::Unavailable),
        Ok(CommandPortResult {
            result: PolicyDecisionCommandResult {
                error_code: PolicyDecisionErrorCode::PolicyDenied as i32,
                safe_error_fingerprint: Some("policy_denied".to_owned()),
                ..Default::default()
            },
            source_revision: None,
            await_target: None,
        }),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.decide_harness_approval(
        Some(&peer),
        egopulse_domain_contracts::v01::egopulse::localapi::v1::DecideHarnessApprovalRequest {
            client: Some(client),
            command: Some(IssueHarnessApprovalDecisionCommand {
                metadata: Some(metadata("c3-correlation")),
                ..Default::default()
            }),
        },
    );
    assert!(response.gateway_error.is_none());
    let sanitized = response
        .sanitized_authority_result
        .expect("sanitized owner result");
    assert_eq!(
        sanitized.error_code,
        PolicyDecisionErrorCode::PolicyDenied as i32
    );
    assert_eq!(
        sanitized.safe_error_fingerprint.as_deref(),
        Some("policy_denied")
    );
}

#[tokio::test]
async fn authority_expiry_is_preserved_in_founder_verdict_result() {
    let (peer, client, app, _calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
        Ok(CommandPortResult {
            result: VerdictCommandResult {
                error_code: VerdictErrorCode::Expired as i32,
                safe_error_fingerprint: Some("verdict_expired".to_owned()),
                ..Default::default()
            },
            source_revision: None,
            await_target: None,
        }),
    )
    .await;
    let response = app.execute_founder_verdict(
        Some(&peer),
        ExecuteFounderVerdictRequest {
            client: Some(client),
            command: Some(VerdictCommand {
                command: Some(verdict_command::Command::IssueFounderVerdict(
                    IssueFounderVerdictCommand {
                        metadata: Some(metadata("c3-correlation")),
                        ..Default::default()
                    },
                )),
            }),
        },
    );
    assert!(response.gateway_error.is_none());
    let result = response.authority_result.expect("owner result");
    assert_eq!(result.error_code, VerdictErrorCode::Expired as i32);
    assert_eq!(
        result.safe_error_fingerprint.as_deref(),
        Some("verdict_expired")
    );
}

#[tokio::test]
async fn delivery_unknown_is_held_for_reconciliation_without_success() {
    let (peer, client, app, calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::DeliveryUnknown),
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.execute_task_command(
        Some(&peer),
        ExecuteTaskCommandRequest {
            client: Some(client),
            command: Some(create_task_command()),
        },
    );
    let error = response.gateway_error.expect("delivery unknown error");
    assert_eq!(error.code, LocalApiErrorCode::AuthorityUnavailable as i32);
    assert_eq!(error.safe_fingerprint, "authority_delivery_unknown");
    assert_eq!(
        error.required_action_code.as_deref(),
        Some("RECONCILE_BEFORE_RETRY")
    );
    assert!(!error.retryable);
    assert!(response.authority_result.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn founder_verdict_returns_authority_result_without_unsupported_await_token() {
    let (peer, client, app, _calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::Unavailable),
        Err(CommandPortFailure::Unavailable),
        Ok(CommandPortResult {
            result: VerdictCommandResult::default(),
            source_revision: None,
            await_target: None,
        }),
    )
    .await;
    let response = app.execute_founder_verdict(
        Some(&peer),
        ExecuteFounderVerdictRequest {
            client: Some(client),
            command: Some(VerdictCommand {
                command: Some(verdict_command::Command::IssueFounderVerdict(
                    IssueFounderVerdictCommand {
                        metadata: Some(metadata("c3-correlation")),
                        ..Default::default()
                    },
                )),
            }),
        },
    );
    assert!(response.gateway_error.is_none());
    assert!(response.authority_result.is_some());
    assert!(response.await_token.is_none());
}

#[allow(deprecated)]
#[tokio::test]
async fn approval_success_returns_only_sanitized_authority_result() {
    let (peer, client, app, _calls, _last_principal, _last_metadata) = test_context(
        Err(CommandPortFailure::Unavailable),
        Ok(CommandPortResult {
            result: PolicyDecisionCommandResult {
                committed: true,
                decision_record: Some(HarnessApprovalDecisionRecord {
                    authority_decision_ref: "decision-1".to_owned(),
                    decision: 1,
                    expires_at: Some(Timestamp {
                        seconds: 200,
                        nanos: 0,
                    }),
                    ..Default::default()
                }),
                state: Some(HarnessApprovalDecisionState {
                    authority_decision_ref: "decision-1".to_owned(),
                    revision: 1,
                    state: 1,
                    ..Default::default()
                }),
                ..Default::default()
            },
            source_revision: None,
            await_target: None,
        }),
        Err(CommandPortFailure::Unavailable),
    )
    .await;
    let response = app.decide_harness_approval(
        Some(&peer),
        egopulse_domain_contracts::v01::egopulse::localapi::v1::DecideHarnessApprovalRequest {
            client: Some(client),
            command: Some(IssueHarnessApprovalDecisionCommand {
                metadata: Some(metadata("c3-correlation")),
                ..Default::default()
            }),
        },
    );
    assert!(response.gateway_error.is_none());
    assert!(response.policy_authority_result.is_none());
    let sanitized = response
        .sanitized_authority_result
        .expect("sanitized result");
    assert_eq!(sanitized.authority_decision_ref, "decision-1");
    assert_eq!(sanitized.state_revision, 1);
}
