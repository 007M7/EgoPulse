#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use egopulse_agentosd::{
    AuthorityCompositionInputs, AuthorityPrincipalResolver, DaemonComposition, DaemonConfig,
    DaemonProviders, OwnerProjectionSource, PendingOwnerProjection, ProjectionSourceFailure,
};
use egopulse_client_kernel::{ClientKernel, api_contract_ref, authorization_contract_ref};
use egopulse_cognition_runtime::task_authority::{
    CreationAuthorization, CreationGuardRejection, PrincipalKind as TaskPrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
};
use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{
        AttemptSnapshot, CollaborationEvent, CollaborationSnapshot, Lease, RunSnapshot,
        collaboration_command_result,
    },
    harness::v1::{
        ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation, HarnessObservation,
        harness_observation,
    },
    localapi::v1::{
        ClientSurface, OpenSessionRequest, local_session_service_client::LocalSessionServiceClient,
    },
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        IssueHarnessApprovalDecisionCommand,
    },
    verdict::v1::{ConsumeFounderVerdictCommand, IssueFounderVerdictCommand},
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictSqlCipherKey,
};
use egopulse_local_api::session::{
    NoopSessionAuditSink, PrincipalGrant, PrincipalResolutionFailure, TrustedPrincipalResolver,
};
use egopulse_local_api::{
    LocalApiClient,
    command_gateway::{CommandPortFailure, CommandPrincipal},
};
use egopulse_local_ipc_platform::LocalIpcAddress;
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityConfig, PolicyDecisionAuthority,
    PolicyPrincipalKind, PolicyReferenceRejection, PolicySqlCipherKey,
    ResolvedApprovalAuthorization,
};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    time::sleep,
};
use uuid::Uuid;

const FIXTURE_ROOT_ENV: &str = "EGOPULSE_C5_FIXTURE_ROOT";
const FIXTURE_INSTANCE_ENV: &str = "EGOPULSE_C5_FIXTURE_INSTANCE";
const FIXTURE_MODE_ENV: &str = "EGOPULSE_C5_FIXTURE_MODE";

#[derive(Clone, Copy, Debug, Default)]
struct DenyTaskReferences;

impl TaskCreationGuard for DenyTaskReferences {
    fn validate(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::task::v1::CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Err(CreationGuardRejection::UnverifiedReference)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllowTaskReferences;

impl TaskCreationGuard for AllowTaskReferences {
    fn validate(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::task::v1::CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["c5-03-task-creation-proof".to_owned()],
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DenyPolicyReferences;

impl egopulse_policy_decision_authority::PolicyReferenceResolver for DenyPolicyReferences {
    fn resolve_issue(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }

    fn validate_adapter_receipt(
        &self,
        _command: &ConsumeHarnessApprovalDecisionCommand,
        _record: &HarnessApprovalDecisionRecord,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllowPolicyReferences;

impl egopulse_policy_decision_authority::PolicyReferenceResolver for AllowPolicyReferences {
    fn resolve_issue(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        Ok(ResolvedApprovalAuthorization {
            request: egopulse_domain_contracts::v01::egopulse::policy::v1::HarnessApprovalRequestBinding {
                adapter_id: "c5-adapter".to_owned(),
                attempt_id: "c5-attempt".to_owned(),
                dispatch_id: "c5-dispatch".to_owned(),
                fencing_token: 7,
                approval_request_id: "approval-c5-03".to_owned(),
                kind: egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalKind::Command as i32,
                action_digest_sha256: "33".repeat(32),
                requested_scope_ref: "scope-c5-03".to_owned(),
                native_routing_ref: "native-route-c5-03".to_owned(),
                request_observation_id: "observation-c5-03".to_owned(),
                request_observation_sequence: 1,
                request_lifecycle: egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalRequestLifecycleKind::Open as i32,
                request_revision: 1,
            },
            authority_proof: egopulse_domain_contracts::v01::egopulse::policy::v1::PolicyAuthorityProof {
                authenticated_principal_id: principal.principal_id.clone(),
                authentication_context_ref: "ipc-session:c5-fixture".to_owned(),
                authorization_policy_ref: Some(
                    egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                        contract_id: "c5-policy-contract".to_owned(),
                        version: "v0.1".to_owned(),
                        sha256: "66".repeat(32),
                    },
                ),
                authorization_decision_id: "c5-policy-allow".to_owned(),
                verified_at: Some(prost_types::Timestamp { seconds: 1_700_000_000, nanos: 0 }),
            },
            evidence_refs: vec!["c5-03-policy-proof".to_owned()],
            expires_at: prost_types::Timestamp { seconds: 4_102_444_800, nanos: 0 },
        })
    }

    fn validate_adapter_receipt(
        &self,
        _command: &ConsumeHarnessApprovalDecisionCommand,
        _record: &HarnessApprovalDecisionRecord,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Ok(vec!["c5-03-adapter-receipt".to_owned()])
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DenyVerdictReferences;

impl egopulse_founder_verdict_authority::VerdictReferenceResolver for DenyVerdictReferences {
    fn resolve_issue(
        &self,
        _command: &IssueFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_task_commit(
        &self,
        _command: &ConsumeFounderVerdictCommand,
    ) -> Result<(), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AllowVerdictReferences;

impl egopulse_founder_verdict_authority::VerdictReferenceResolver for AllowVerdictReferences {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        Ok((
            ResolvedVerdictContext {
                scope: command.scope.clone().ok_or(VerdictReferenceRejection::NotFound)?,
                verification_conclusion: egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationConclusion::Passed,
                open_discrepancy_ids: Vec::new(),
                open_unverified_item_ids: Vec::new(),
                non_overridable_gate_ids: Vec::new(),
            },
            FounderAuthorization {
                authenticated_founder_principal_id: principal.principal_id.clone(),
                authority_ref: "founder-authority:c5-fixture".to_owned(),
                confirmation_class: egopulse_domain_contracts::v01::egopulse::verdict::v1::ConfirmationClass::Explicit,
                confirmation_proof_ref: "confirmation-c5-03".to_owned(),
                verified_at: prost_types::Timestamp { seconds: 1_700_000_000, nanos: 0 },
                valid_until: prost_types::Timestamp { seconds: 4_102_444_800, nanos: 0 },
                authority_policy_ref: egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                    contract_id: "c5-founder-policy".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "44".repeat(32),
                },
                evidence_refs: vec!["c5-03-founder-confirmation".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        _command: &ConsumeFounderVerdictCommand,
    ) -> Result<(), VerdictReferenceRejection> {
        Ok(())
    }

    fn validate_revoke(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::RevokeFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Ok(vec!["c5-03-founder-revoke-proof".to_owned()])
    }
}

struct StaticApprovalProjectionSource {
    messages: std::sync::Mutex<Vec<PendingOwnerProjection>>,
}

impl StaticApprovalProjectionSource {
    fn new() -> Self {
        let action_digest = "33".repeat(32);
        let observation = HarnessObservation {
            observation_id: "observation-c5-03".to_owned(),
            adapter_id: "c5-adapter".to_owned(),
            attempt_id: "c5-attempt".to_owned(),
            dispatch_id: "c5-dispatch".to_owned(),
            fencing_token: 7,
            observation_sequence: 1,
            payload: Some(harness_observation::Payload::ApprovalRequest(
                ApprovalRequestObservation {
                    approval_request_id: "approval-c5-03".to_owned(),
                    kind: ApprovalKind::Command as i32,
                    action_digest_sha256: action_digest,
                    requested_scope_ref: "scope-c5-03".to_owned(),
                    display_summary_ref: "summary-c5-03".to_owned(),
                    native_routing_ref: String::new(),
                    lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                    request_revision: 1,
                },
            )),
            ..Default::default()
        };
        let collaboration_snapshot = CollaborationSnapshot {
            run: Some(RunSnapshot {
                run_id: "c5-run".to_owned(),
                revision: 1,
                task_id: "task-c5-03".to_owned(),
                ..Default::default()
            }),
            attempts: vec![AttemptSnapshot {
                attempt_id: "c5-attempt".to_owned(),
                run_id: "c5-run".to_owned(),
                step_id: "c5-step".to_owned(),
                revision: 1,
                dispatch_id: Some("c5-dispatch".to_owned()),
                lease: Some(Lease {
                    fencing_token: 7,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let collaboration_event = CollaborationEvent {
            event_id: "collaboration-event-c5-03".to_owned(),
            run_id: "c5-run".to_owned(),
            resulting_run_revision: 1,
            ..Default::default()
        };
        let collaboration_result = egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationCommandResult {
            replayed: false,
            outcome: Some(collaboration_command_result::Outcome::Snapshot(
                collaboration_snapshot.clone(),
            )),
            committed_event: Some(collaboration_event.clone()),
        };
        let collaboration_payload_digest =
            hex::encode(Sha256::digest(collaboration_result.encode_to_vec()));
        let adapter_payload_digest = hex::encode(Sha256::digest(observation.encode_to_vec()));
        Self {
            messages: std::sync::Mutex::new(vec![
                PendingOwnerProjection::Collaboration(Box::new(
                    egopulse_local_ide_control::collaboration_control::PendingCollaborationProjection {
                        message_id: "c5-collaboration-projection".to_owned(),
                        source_event_id: collaboration_event.event_id.clone(),
                        source_revision: 1,
                        canonical_payload_digest_sha256: collaboration_payload_digest,
                        rebuild_baseline: false,
                        snapshot: collaboration_snapshot,
                        event: collaboration_event,
                    },
                )),
                PendingOwnerProjection::AdapterApproval(Box::new(
                    egopulse_harness_adapter::PendingAdapterApprovalProjection {
                        message_id: "c5-adapter-projection".to_owned(),
                        source_observation_id: observation.observation_id.clone(),
                        source_revision: 1,
                        payload_digest_sha256: adapter_payload_digest,
                        run_id: "c5-run".to_owned(),
                        step_id: "c5-step".to_owned(),
                        attempt_id: "c5-attempt".to_owned(),
                        dispatch_id: "c5-dispatch".to_owned(),
                        fencing_token: 7,
                        observation,
                    },
                )),
            ]),
        }
    }
}

impl OwnerProjectionSource for StaticApprovalProjectionSource {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.messages
            .lock()
            .map_err(|_| ProjectionSourceFailure::Acknowledgement)
            .map(|messages| messages.clone())
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let message_id = match message {
            PendingOwnerProjection::Collaboration(value) => &value.message_id,
            PendingOwnerProjection::AdapterApproval(value) => &value.message_id,
            _ => return Ok(false),
        };
        let mut messages = self
            .messages
            .lock()
            .map_err(|_| ProjectionSourceFailure::Acknowledgement)?;
        let before = messages.len();
        messages.retain(|candidate| match candidate {
            PendingOwnerProjection::Collaboration(value) => value.message_id != *message_id,
            PendingOwnerProjection::AdapterApproval(value) => value.message_id != *message_id,
            _ => true,
        });
        Ok(messages.len() != before)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FixtureAuthorityPrincipalResolver;

impl AuthorityPrincipalResolver for FixtureAuthorityPrincipalResolver {
    fn resolve_task(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure> {
        Ok(TaskPrincipalKind::Founder)
    }

    fn resolve_policy(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<PolicyPrincipalKind, CommandPortFailure> {
        Ok(PolicyPrincipalKind::LocalUser)
    }

    fn resolve_verdict(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<VerdictPrincipalKind, CommandPortFailure> {
        Ok(VerdictPrincipalKind::FounderAuthority)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FixtureSessionResolver;

impl TrustedPrincipalResolver for FixtureSessionResolver {
    fn resolve(
        &self,
        _principal: &egopulse_local_ipc_platform::OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        let profiles = egopulse_client_kernel::ContractProfiles::embedded()
            .map_err(|_| PrincipalResolutionFailure::PolicyUnavailable)?;
        Ok(PrincipalGrant {
            authenticated_principal_id: "os-user:c5-fixture".to_owned(),
            permission_codes: profiles.permission_codes().clone(),
            authorization_policy_ref: authorization_contract_ref(),
        })
    }
}

fn fixture_root() -> PathBuf {
    std::env::var_os(FIXTURE_ROOT_ENV)
        .map(PathBuf::from)
        .expect("C5 fixture root must be supplied to the child process")
}

fn fixture_instance() -> String {
    std::env::var(FIXTURE_INSTANCE_ENV)
        .expect("C5 fixture instance must be supplied to the child process")
}

fn fixture_mode() -> String {
    std::env::var(FIXTURE_MODE_ENV).unwrap_or_else(|_| "deny".to_owned())
}

fn fixture_config(root: &Path, instance: &str) -> DaemonConfig {
    DaemonConfig {
        instance: instance.to_owned(),
        read_model_database_path: root.join("read-model.db"),
        read_model_epoch: "c5-00-fixture-epoch".to_owned(),
        read_model_key: [0x41; 32],
        token_mac_key: [0x42; 32],
        session_ttl: Duration::from_secs(60),
    }
}

fn open_fixture_providers(root: &Path) -> DaemonProviders {
    if fixture_mode() == "allow" {
        open_fixture_providers_with_guards(
            root,
            AllowTaskReferences,
            AllowPolicyReferences,
            AllowVerdictReferences,
            vec![Arc::new(StaticApprovalProjectionSource::new())],
        )
    } else {
        open_fixture_providers_with_guards(
            root,
            DenyTaskReferences,
            DenyPolicyReferences,
            DenyVerdictReferences,
            Vec::new(),
        )
    }
}

fn open_fixture_providers_with_guards<T, P, V>(
    root: &Path,
    task_guard: T,
    policy_guard: P,
    verdict_guard: V,
    additional_projection_sources: Vec<Arc<dyn OwnerProjectionSource>>,
) -> DaemonProviders
where
    T: TaskCreationGuard,
    P: egopulse_policy_decision_authority::PolicyReferenceResolver,
    V: egopulse_founder_verdict_authority::VerdictReferenceResolver,
{
    let task = TaskAuthority::open(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        task_guard,
    )
    .expect("fixture task authority should open");
    let policy = PolicyDecisionAuthority::open(
        PolicyAuthorityConfig {
            database_path: root.join("policy-authority.db"),
            store_epoch: "c5-00-policy-epoch".to_owned(),
            key: PolicySqlCipherKey::new([0x12; 32]),
        },
        policy_guard,
    )
    .expect("fixture policy authority should open");
    let verdict = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.join("verdict-authority.db"),
            store_epoch: "c5-00-verdict-epoch".to_owned(),
            key: VerdictSqlCipherKey::new([0x13; 32]),
        },
        verdict_guard,
    )
    .expect("fixture verdict authority should open");

    DaemonProviders::from_authority_inputs(AuthorityCompositionInputs {
        task,
        policy,
        verdict,
        principal_resolver: Arc::new(FixtureAuthorityPrincipalResolver),
        session_principal_resolver: Arc::new(FixtureSessionResolver),
        session_clock: Arc::new(egopulse_local_api::session::SystemSessionClock),
        session_audit: Arc::new(NoopSessionAuditSink),
        additional_projection_sources,
    })
}

async fn connect_session(
    address: LocalIpcAddress,
) -> Result<
    LocalSessionServiceClient<tonic::transport::Channel>,
    egopulse_local_api::LocalApiConnectError,
> {
    Ok(LocalApiClient::platform_default()
        .connect(address)
        .await?
        .session_service())
}

async fn spawn_fixture(root: &Path, instance: &str) -> Child {
    spawn_fixture_with_mode(root, instance, "deny").await
}

async fn spawn_fixture_with_mode(root: &Path, instance: &str, mode: &str) -> Child {
    let executable = std::env::current_exe().expect("test executable path");
    Command::new(executable)
        .args(["--exact", "c5_00_daemon_fixture_child", "--nocapture"])
        .env(FIXTURE_ROOT_ENV, root)
        .env(FIXTURE_INSTANCE_ENV, instance)
        .env(FIXTURE_MODE_ENV, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn C5 fixture child")
}

fn cli_executable() -> PathBuf {
    let test_executable = std::env::current_exe().expect("CLI E2E test executable path");
    let target_debug = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("CLI E2E test must run below target/debug");
    let executable = target_debug.join("egopulse.exe");
    assert!(
        executable.is_file(),
        "CLI E2E requires the normal egopulse binary at {}",
        executable.display()
    );
    executable
}

async fn run_cli(instance: &str, arguments: &[&str]) -> std::process::Output {
    Command::new(cli_executable())
        .env("EGOPULSE_IPC_INSTANCE", instance)
        .args(arguments)
        .output()
        .await
        .expect("run real egopulse CLI process")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_00_real_daemon_fixture_opens_session_over_local_ipc() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-00-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 fixture root");
    let instance = format!("c5-00-{}", Uuid::now_v7());
    let address = LocalIpcAddress::for_instance(&instance).expect("fixture IPC address");
    let mut child = spawn_fixture(&root, &instance).await;
    let mut last_error = String::from("fixture did not become ready");

    for _ in 0..80 {
        match connect_session(address.clone()).await {
            Ok(mut client) => {
                let mut kernel = ClientKernel::new("c5-00-cli", ClientSurface::Cli)
                    .expect("fixture client kernel");
                let request: OpenSessionRequest = kernel
                    .open_session_request(Uuid::now_v7().to_string())
                    .expect("fixture OpenSession request");
                match client.open_session(request).await {
                    Ok(response) => {
                        let binding = kernel
                            .accept_open_session(
                                response.into_inner(),
                                std::time::SystemTime::now(),
                            )
                            .expect("real OpenSession response should satisfy ClientKernel");
                        assert_eq!(binding.authenticated_principal_id, "os-user:c5-fixture");
                        assert!(binding.granted_permission_codes.contains("local.task.read"));
                        assert_eq!(binding.negotiated_contract_ref, api_contract_ref());
                        assert_eq!(
                            binding.authorization_policy_ref,
                            authorization_contract_ref()
                        );
                        drop(child.stdin.take());
                        let status = child.wait().await.expect("fixture child exit");
                        assert!(status.success(), "fixture child failed: {status}");
                        fs::remove_dir_all(&root).expect("remove C5 fixture root");
                        return;
                    }
                    Err(error) => last_error = format!("OpenSession: {error}"),
                }
            }
            Err(error) => last_error = format!("connect: {error}"),
        }
        sleep(Duration::from_millis(50)).await;
    }

    drop(child.stdin.take());
    let status = child
        .wait()
        .await
        .expect("fixture child exit after timeout");
    panic!("{last_error}; child status: {status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_00_daemon_fixture_child() {
    if std::env::var_os(FIXTURE_ROOT_ENV).is_none() {
        return;
    }

    let root = fixture_root();
    let instance = fixture_instance();
    let composition = DaemonComposition::build(
        fixture_config(&root, &instance),
        open_fixture_providers(&root),
    )
    .expect("real fixture daemon composition");
    let shutdown = async {
        let _ = tokio::task::spawn_blocking(|| {
            let mut stdin = std::io::stdin();
            let mut buffer = [0_u8; 1];
            let _ = stdin.read(&mut buffer);
        })
        .await;
    };
    composition
        .serve(shutdown)
        .await
        .expect("fixture daemon serve");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_03_real_cli_process_attaches_and_preserves_authority_rejections() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-03-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 CLI fixture root");
    let instance = format!("c5-03-{}", Uuid::now_v7());
    let mut child = spawn_fixture(&root, &instance).await;

    let mut status_output = None;
    for _ in 0..80 {
        let output = run_cli(&instance, &["status", "--json"]).await;
        if output.status.success() {
            status_output = Some(output);
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let status_output = status_output.expect("CLI should attach to the real fixture daemon");
    let status_json: serde_json::Value =
        serde_json::from_slice(&status_output.stdout).expect("status JSON envelope");
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["operation"], "status");

    let acceptance_sha = "11".repeat(32);
    let budget_sha = "22".repeat(32);
    let task_output = run_cli(
        &instance,
        &[
            "task",
            "create",
            "--work-type",
            "c5-03",
            "--input-snapshot-id",
            "input-001",
            "--target-scope-ref",
            "scope-001",
            "--acceptance-contract-id",
            "acceptance",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            acceptance_sha.as_str(),
            "--budget-profile-id",
            "budget",
            "--budget-profile-version",
            "v0.1",
            "--budget-profile-sha256",
            budget_sha.as_str(),
            "--json",
        ],
    )
    .await;
    assert_eq!(
        task_output.status.code(),
        Some(6),
        "task CLI stdout={} stderr={}",
        String::from_utf8_lossy(&task_output.stdout),
        String::from_utf8_lossy(&task_output.stderr)
    );
    let task_json: serde_json::Value =
        serde_json::from_slice(&task_output.stdout).expect("task rejection JSON envelope");
    assert_eq!(task_json["operation"], "task.create");
    assert_eq!(task_json["error"]["code"], "TASK_AUTHORITY_REJECTED");

    let verdict_output = run_cli(
        &instance,
        &[
            "verdict",
            "revoke",
            "verdict-001",
            "--expected-state-revision",
            "1",
            "--reason-code",
            "c5-03",
            "--confirmation-proof-ref",
            "proof-001",
            "--json",
        ],
    )
    .await;
    assert_eq!(
        verdict_output.status.code(),
        Some(6),
        "verdict CLI stdout={} stderr={}",
        String::from_utf8_lossy(&verdict_output.stdout),
        String::from_utf8_lossy(&verdict_output.stderr)
    );
    let verdict_json: serde_json::Value =
        serde_json::from_slice(&verdict_output.stdout).expect("verdict rejection JSON envelope");
    assert_eq!(verdict_json["operation"], "verdict.revoke");
    assert_eq!(verdict_json["error"]["code"], "VERDICT_AUTHORITY_REJECTED");

    drop(child.stdin.take());
    let status = child.wait().await.expect("fixture child exit");
    assert!(status.success(), "fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove C5 CLI fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_03_real_cli_process_completes_owner_writes_and_awaits_projection() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-03-allow-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 successful CLI fixture root");
    let instance = format!("c5-03-allow-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;

    let mut status_output = None;
    for _ in 0..80 {
        let output = run_cli(&instance, &["status", "--json"]).await;
        if output.status.success() {
            status_output = Some(output);
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        status_output.is_some(),
        "successful fixture daemon must become ready"
    );

    let acceptance_sha = "11".repeat(32);
    let budget_sha = "22".repeat(32);
    let task_output = run_cli(
        &instance,
        &[
            "task",
            "create",
            "--work-type",
            "c5-03-allow",
            "--input-snapshot-id",
            "input-c5-03",
            "--target-scope-ref",
            "scope-c5-03",
            "--acceptance-contract-id",
            "acceptance-c5-03",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            acceptance_sha.as_str(),
            "--budget-profile-id",
            "budget-c5-03",
            "--budget-profile-version",
            "v0.1",
            "--budget-profile-sha256",
            budget_sha.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        task_output.status.success(),
        "task create stdout={} stderr={}",
        String::from_utf8_lossy(&task_output.stdout),
        String::from_utf8_lossy(&task_output.stderr)
    );
    let task_json: serde_json::Value =
        serde_json::from_slice(&task_output.stdout).expect("task success JSON envelope");
    assert_eq!(task_json["operation"], "task.create");
    assert_eq!(task_json["data"]["replayed"], false);
    let task_id = task_json["data"]["taskId"]
        .as_str()
        .expect("created task id");
    let task_await_token = task_json["data"]["awaitToken"].to_string();
    assert_ne!(task_await_token, "null");

    let task_await_output = run_cli(
        &instance,
        &["await", "--token-json", task_await_token.as_str(), "--json"],
    )
    .await;
    assert!(
        task_await_output.status.success(),
        "task await stdout={} stderr={}",
        String::from_utf8_lossy(&task_await_output.stdout),
        String::from_utf8_lossy(&task_await_output.stderr)
    );
    let task_await_json: serde_json::Value =
        serde_json::from_slice(&task_await_output.stdout).expect("task await JSON envelope");
    assert_eq!(task_await_json["data"]["kind"], "task");
    assert_eq!(task_await_json["data"]["view"]["taskId"], task_id);

    let approval_action_sha = "33".repeat(32);
    let approval_output = run_cli(
        &instance,
        &[
            "approval",
            "decide",
            "approval-c5-03",
            "--expected-action-digest-sha256",
            approval_action_sha.as_str(),
            "--expected-request-observation-id",
            "observation-c5-03",
            "--expected-request-observation-sequence",
            "1",
            "--expected-request-revision",
            "1",
            "--decision",
            "allow-once",
            "--reason-code",
            "c5-03-approved",
            "--confirmation-proof-ref",
            "confirmation-c5-03",
            "--json",
        ],
    )
    .await;
    assert!(
        approval_output.status.success(),
        "approval stdout={} stderr={}",
        String::from_utf8_lossy(&approval_output.stdout),
        String::from_utf8_lossy(&approval_output.stderr)
    );
    let approval_json: serde_json::Value =
        serde_json::from_slice(&approval_output.stdout).expect("approval success JSON envelope");
    assert_eq!(approval_json["operation"], "approval.decide");
    assert_eq!(approval_json["data"]["committed"], true);
    let approval_await_token = approval_json["data"]["awaitToken"].to_string();
    assert_ne!(approval_await_token, "null");

    let approval_await_output = run_cli(
        &instance,
        &[
            "await",
            "--token-json",
            approval_await_token.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        approval_await_output.status.success(),
        "approval await stdout={} stderr={}",
        String::from_utf8_lossy(&approval_await_output.stdout),
        String::from_utf8_lossy(&approval_await_output.stderr)
    );
    let approval_await_json: serde_json::Value =
        serde_json::from_slice(&approval_await_output.stdout)
            .expect("approval await JSON envelope");
    assert_eq!(approval_await_json["data"]["kind"], "approval");
    assert_eq!(
        approval_await_json["data"]["view"]["approvalRequestId"],
        "approval-c5-03"
    );

    let verdict_acceptance_sha = "55".repeat(32);
    let verdict_output = run_cli(
        &instance,
        &[
            "verdict",
            "issue",
            "--task-id",
            "task-c5-03",
            "--task-revision",
            "1",
            "--work-revision",
            "1",
            "--artifact-set-id",
            "artifact-c5-03",
            "--artifact-set-manifest-sha256",
            "66c5a1f0a0fbcdbb7f47c8a3fbe2f31e3a6a6b5f8e3f5c0b8b5d86b5c9a4e102",
            "--artifact-set-manifest-byte-length",
            "128",
            "--verification-artifact-id",
            "verification-c5-03",
            "--verification-payload-sha256",
            "77c5a1f0a0fbcdbb7f47c8a3fbe2f31e3a6a6b5f8e3f5c0b8b5d86b5c9a4e102",
            "--verification-payload-byte-length",
            "256",
            "--acceptance-contract-id",
            "acceptance-c5-03",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            verdict_acceptance_sha.as_str(),
            "--decision",
            "accept",
            "--observed-verification-conclusion",
            "passed",
            "--reason-code",
            "c5-03-accepted",
            "--confirmation-class",
            "explicit",
            "--confirmation-proof-ref",
            "confirmation-c5-03",
            "--json",
        ],
    )
    .await;
    assert!(
        verdict_output.status.success(),
        "verdict stdout={} stderr={}",
        String::from_utf8_lossy(&verdict_output.stdout),
        String::from_utf8_lossy(&verdict_output.stderr)
    );
    let verdict_json: serde_json::Value =
        serde_json::from_slice(&verdict_output.stdout).expect("verdict success JSON envelope");
    assert_eq!(verdict_json["operation"], "verdict.issue");
    assert_eq!(verdict_json["data"]["committed"], true);
    let verdict_id = verdict_json["data"]["founderVerdictId"]
        .as_str()
        .expect("issued Founder Verdict id");
    let verdict_revoke_output = run_cli(
        &instance,
        &[
            "verdict",
            "revoke",
            verdict_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "c5-03-revoked",
            "--confirmation-proof-ref",
            "c5-03-founder-revoke-proof",
            "--json",
        ],
    )
    .await;
    assert!(
        verdict_revoke_output.status.success(),
        "verdict revoke stdout={} stderr={}",
        String::from_utf8_lossy(&verdict_revoke_output.stdout),
        String::from_utf8_lossy(&verdict_revoke_output.stderr)
    );
    let verdict_revoke_json: serde_json::Value =
        serde_json::from_slice(&verdict_revoke_output.stdout)
            .expect("verdict revoke success JSON envelope");
    assert_eq!(verdict_revoke_json["operation"], "verdict.revoke");
    assert_eq!(verdict_revoke_json["data"]["committed"], true);

    drop(child.stdin.take());
    let status = child.wait().await.expect("fixture child exit");
    assert!(status.success(), "fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove successful C5 CLI fixture root");
}
