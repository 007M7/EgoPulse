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
    DaemonProviders,
};
use egopulse_client_kernel::{ClientKernel, api_contract_ref, authorization_contract_ref};
use egopulse_cognition_runtime::task_authority::{
    CreationAuthorization, CreationGuardRejection, PrincipalKind as TaskPrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
};
use egopulse_domain_contracts::v01::egopulse::{
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
use tokio::{
    process::{Child, Command},
    time::sleep,
};
use uuid::Uuid;

const FIXTURE_ROOT_ENV: &str = "EGOPULSE_C5_FIXTURE_ROOT";
const FIXTURE_INSTANCE_ENV: &str = "EGOPULSE_C5_FIXTURE_INSTANCE";

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
    let task = TaskAuthority::open(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        DenyTaskReferences,
    )
    .expect("fixture task authority should open");
    let policy = PolicyDecisionAuthority::open(
        PolicyAuthorityConfig {
            database_path: root.join("policy-authority.db"),
            store_epoch: "c5-00-policy-epoch".to_owned(),
            key: PolicySqlCipherKey::new([0x12; 32]),
        },
        DenyPolicyReferences,
    )
    .expect("fixture policy authority should open");
    let verdict = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.join("verdict-authority.db"),
            store_epoch: "c5-00-verdict-epoch".to_owned(),
            key: VerdictSqlCipherKey::new([0x13; 32]),
        },
        DenyVerdictReferences,
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
        additional_projection_sources: Vec::new(),
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
    let executable = std::env::current_exe().expect("test executable path");
    Command::new(executable)
        .args(["--exact", "c5_00_daemon_fixture_child", "--nocapture"])
        .env(FIXTURE_ROOT_ENV, root)
        .env(FIXTURE_INSTANCE_ENV, instance)
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
