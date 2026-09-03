#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command as StdCommand, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use egopulse_agentosd::{
    AuthorityCompositionInputs, AuthorityPrincipalResolver, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredTaskTransitionGuard,
    ConfiguredWorkPreparationPort, ContextMutationPortAdapter, DaemonComposition, DaemonConfig,
    DaemonProviders, DenyVerificationReferences, GovernedReturnCollectorConfig,
    MemoryRetrievalCompositionConfig, NativeHarnessCompositionConfig, OwnerProjectionSource,
    PendingOwnerProjection, ProjectionSourceFailure, SharedAuthorityCompositionInputs,
};
use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactSqlCipherKey,
};
use egopulse_client_kernel::{ClientKernel, api_contract_ref, authorization_contract_ref};
use egopulse_client_operations::attach as attach_client_operation;
use egopulse_codex_adapter::{CODEX_ADAPTER_ID, CODEX_CAPABILITY_PROFILE_ID, FakeCodexDriver};
use egopulse_cognition_runtime::{
    context_authority::{
        AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityConfig,
        ContextPrincipalKind, IssueContextSnapshot,
    },
    memory_authority::{
        AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority, MemoryAuthorityConfig,
        MemoryPrincipalKind, SubmitMemoryCandidate,
    },
    task_authority::{
        CreationAuthorization, CreationGuardRejection, PrincipalKind as TaskPrincipalKind,
        SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskProjectionMessage,
    },
};
use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{
        AttemptSnapshot, AttemptStatus, CollaborationEvent, CollaborationSnapshot, Lease,
        RecoveryClass, RunPlan, RunSnapshot, RunStatus, StepPlan, StepSnapshot, StepStatus,
        collaboration_command_result,
    },
    common::v1::ContractReference,
    harness::v1::{
        ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
        ApprovalRequestObservation, CancelExecutionEnvelope, DeliveryDisposition, DispatchEnvelope,
        HarnessErrorCode, HarnessObservation, NativeSessionStrategy, ObservationCriticality,
        ProbeHarnessRequest, ProbeHarnessResult, harness_observation,
    },
    localapi::v1::{
        ClientSurface, ExecuteMemoryMutationRequest, ExecuteTaskCommandRequest,
        MemoryMutationCommand, OpenSessionRequest, RetrieveMemoryRequest,
        local_session_service_client::LocalSessionServiceClient, memory_mutation_command,
        retrieve_memory_response,
    },
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        IssueHarnessApprovalDecisionCommand,
    },
    task::v1::{
        CreateTaskCommand, RequestTaskCancellationCommand, TaskCommand, TaskEvent, TaskSnapshot,
        TaskStatus, task_command,
    },
    verdict::v1::{ConsumeFounderVerdictCommand, IssueFounderVerdictCommand},
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictSqlCipherKey,
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DriverDelivery, DriverError,
    DriverErrorCertainty, DriverEvent, NativeHarnessDriver, NativeHarnessFuture,
    ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
};
use egopulse_local_api::session::{
    NoopSessionAuditSink, PrincipalGrant, PrincipalResolutionFailure, TrustedPrincipalResolver,
};
use egopulse_local_api::{
    LocalApiClient,
    command_gateway::{CommandPortFailure, CommandPrincipal},
};
use egopulse_local_ide_control::collaboration_control::{
    DispatchMaterial, HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
    SingleHarnessWorkConfig,
};
use egopulse_local_ipc_platform::LocalIpcAddress;
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityConfig, PolicyDecisionAuthority,
    PolicyPrincipalKind, PolicyReferenceRejection, PolicySqlCipherKey,
    ResolvedApprovalAuthorization,
};
use egopulse_tui::task_watch::TaskWatchController;
use egopulse_v01_fault_conformance::memory_restart_oracle::MemoryRestartOracle;
use egopulse_v01_fault_conformance::r8b2c::{
    R8b2cNativeEventRecord, R8b2cWitnessReader, R8b2cWitnessWriter, read_r8b2c_adapter_store,
    read_r8b2c_collaboration_store, read_r8b2c_task_store,
};
use egopulse_v01_fault_conformance::r9a3::{
    PROTOCOL_VERSION as R9A3_PROTOCOL_VERSION, SendAck as R9a3SendAck,
    SendRequest as R9a3SendRequest, SideEffectReader as R9a3SideEffectReader,
    SideEffectWriter as R9a3SideEffectWriter, read_send_ack_frame as read_r9a3_send_ack_frame,
    read_send_request_frame as read_r9a3_send_request_frame,
    write_send_ack_frame as write_r9a3_send_ack_frame,
    write_send_request_frame as write_r9a3_send_request_frame,
};
use egopulse_v01_fault_conformance::r9a3_context::{
    R9a3ContextGovernanceState, R9a3VerdictAuthorityCounts, read_r9a3_context_authority_store,
    read_r9a3_verdict_authority_counts,
};
use egopulse_verification_authority::{
    VerificationAuthority, VerificationAuthorityConfig, VerificationSqlCipherKey,
};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    time::{sleep, timeout},
};
use uuid::Uuid;

const FIXTURE_ROOT_ENV: &str = "EGOPULSE_C5_FIXTURE_ROOT";
const FIXTURE_INSTANCE_ENV: &str = "EGOPULSE_C5_FIXTURE_INSTANCE";
const FIXTURE_MODE_ENV: &str = "EGOPULSE_C5_FIXTURE_MODE";
const R8A_FIXTURE_MODE: &str = "dynamic";
const R8B_PAUSE_BEFORE_RUNNER_MODE: &str = "dynamic-pause-before-runner";
const R8B2C_BEGIN_DELIVERY_MODE: &str = "dynamic-r8b2c-begin-delivery";
const R8B2C_UNKNOWN_RECOVERY_MODE: &str = "dynamic-r8b2c-unknown-recovery";
const R8B2C_DELIVERED_BEFORE_POLL_MODE: &str = "dynamic-r8b2c-delivered-before-poll";
const R8B2C_ACK_RECOVERY_MODE: &str = "dynamic-r8b2c-ack-recovery";
const R9A3D_EXTERNAL_SEND_MODE: &str = "dynamic-r9a3d-external-send";
const R9A3D_EXTERNAL_RECOVERY_MODE: &str = "dynamic-r9a3d-external-recovery";
const R9A3E_PREAUTH_UNAVAILABLE_MODE: &str = "dynamic-r9a3e-preauth-unavailable";
const R9A3E_REVOKED_READY_MODE: &str = "dynamic-r9a3e-revoked-ready";
const R8A_ACTIVATION_RUN_ID: &str = "r8a-activation-run";
const R8A_DRIVER_RECORD: &str = "r8a-driver-record.json";
const R8B_FIRST_RUNNER_CYCLE_RECORD: &str = "r8b-first-runner-cycle-complete";
const R8B2C_BEGIN_DELIVERY_PHASE: &str = "begin-delivery-before-receipt";
const R8B2C_DELIVERED_BEFORE_POLL_PHASE: &str = "delivered-before-poll";
const R8B2C_UNKNOWN_RECOVERED_PHASE: &str = "unknown-recovered";
const R8B2C_ACK_REHYDRATED_PHASE: &str = "ack-rehydrated";
const R9A2C_CLI_CONTEXT_BYTES: &[u8] =
    br#"{"surface":"cli","private":"r9a2c-context-bytes-sentinel"}"#;
const R9A2C_CONTEXT_EXPIRES_AT_SECONDS: i64 = 4_102_444_800;
const R9A3_WITNESS_ROOT_ENV: &str = "EGOPULSE_C5_R9A3_WITNESS_ROOT";
const R9A3_WITNESS_INSTANCE_ENV: &str = "EGOPULSE_C5_R9A3_WITNESS_INSTANCE";
const R9A3_WITNESS_WITHHOLD_ACK_ENV: &str = "EGOPULSE_C5_R9A3_WITHHOLD_ACK";
const R9A3_WITNESS_READY_FILE: &str = "r9a3-witness-ready.json";
const R9A3_WITNESS_CHECKPOINT_FILE: &str = "r9a3-effect-committed.json";
const R9A3_WITNESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const R9A3_WITNESS_REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const R9A3D_WITNESS_ROOT_ENV: &str = "EGOPULSE_C5_R9A3D_WITNESS_ROOT";
const R9A3D_WITNESS_INSTANCE_ENV: &str = "EGOPULSE_C5_R9A3D_WITNESS_INSTANCE";
const R9A3D_SEND_ENDPOINT_ENV: &str = "EGOPULSE_C5_R9A3D_SEND_ENDPOINT";
const R9A3D_READY_FILE: &str = "r9a3d-witness-ready.json";
const R9A3D_COMMITTED_FILE: &str = "r9a3d-effect-committed-before-ack.json";
const R9A3D_DISCONNECTED_FILE: &str = "r9a3d-first-sender-disconnected.json";
const R9A3D_FORBIDDEN_CONNECTION_FILE: &str = "r9a3d-forbidden-second-connection.json";
const R9A3D_FORBIDDEN_SEND_FILE: &str = "r9a3d-forbidden-second-send-request.json";
const R9A3D_RECOVERY_CHECKPOINT_FILE: &str = "r9a3d-recovery-settled.json";
const R9A3D_STABLE_CHECKPOINT_FILE: &str = "r9a3d-stable-cycle.json";
const R9A3E_PREAUTH_UNAVAILABLE_PHASE: &str = "preauthorization-material-unavailable";
const R9A3E_REVOKED_READY_PHASE: &str = "revoked-ready-rejected";
const R9A3D_IO_TIMEOUT: Duration = Duration::from_secs(5);
const R9A3D_PHASE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct R9a3WitnessReady {
    process_id: u32,
    instance: String,
    endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct R9a3WitnessCheckpoint {
    process_id: u32,
    instance: String,
    dispatch_id: String,
    phase: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct R9a3dWitnessReady {
    process_id: u32,
    fixture_root: String,
    fixture_instance: String,
    send_endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct R9a3dRequestEvidence {
    process_id: u32,
    fixture_instance: String,
    phase: String,
    operation_id: String,
    dispatch_id: String,
    attempt_id: String,
    fencing_token: u64,
    request_digest_sha256: String,
    payload_digest_sha256: String,
    send_count: u64,
}

impl R9a3dRequestEvidence {
    fn new(instance: &str, phase: &str, request: &R9a3SendRequest, send_count: u64) -> Self {
        Self {
            process_id: std::process::id(),
            fixture_instance: instance.to_owned(),
            phase: phase.to_owned(),
            operation_id: request.operation_id.clone(),
            dispatch_id: request.dispatch_id.clone(),
            attempt_id: request.attempt_id.clone(),
            fencing_token: request.fencing_token,
            request_digest_sha256: request.request_digest_sha256.clone(),
            payload_digest_sha256: request.payload_digest_sha256.clone(),
            send_count,
        }
    }

    fn assert_request(&self, request: &R9a3SendRequest) {
        assert_eq!(self.operation_id, request.operation_id);
        assert_eq!(self.dispatch_id, request.dispatch_id);
        assert_eq!(self.attempt_id, request.attempt_id);
        assert_eq!(self.fencing_token, request.fencing_token);
        assert_eq!(self.request_digest_sha256, request.request_digest_sha256);
        assert_eq!(self.payload_digest_sha256, request.payload_digest_sha256);
    }

    fn request(&self) -> R9a3SendRequest {
        R9a3SendRequest {
            protocol_version: R9A3_PROTOCOL_VERSION,
            operation_id: self.operation_id.clone(),
            dispatch_id: self.dispatch_id.clone(),
            attempt_id: self.attempt_id.clone(),
            fencing_token: self.fencing_token,
            request_digest_sha256: self.request_digest_sha256.clone(),
            payload_digest_sha256: self.payload_digest_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct R9a3dForbiddenConnection {
    process_id: u32,
    fixture_instance: String,
    phase: String,
}

fn r9a3_witness_ready_path(root: &Path) -> PathBuf {
    root.join(R9A3_WITNESS_READY_FILE)
}

fn r9a3_witness_checkpoint_path(root: &Path) -> PathBuf {
    root.join(R9A3_WITNESS_CHECKPOINT_FILE)
}

fn publish_r9a3_json_atomically<T: serde::Serialize>(path: &Path, value: &T, label: &str) {
    let payload = serde_json::to_vec(value).unwrap_or_else(|error| {
        panic!("serialize {label}: {error}");
    });
    let temporary = path.with_extension(format!("tmp-{}-{}", std::process::id(), Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap_or_else(|error| panic!("create temporary {label}: {error}"));
    file.write_all(&payload)
        .unwrap_or_else(|error| panic!("write temporary {label}: {error}"));
    file.flush()
        .unwrap_or_else(|error| panic!("flush temporary {label}: {error}"));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync temporary {label}: {error}"));
    drop(file);
    fs::rename(&temporary, path).unwrap_or_else(|error| panic!("publish {label}: {error}"));
}

struct R9a3WitnessTempRoot(PathBuf);

impl R9a3WitnessTempRoot {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("egopulse-c5-r9a3-witness-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create R-9A.3 witness test root");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for R9a3WitnessTempRoot {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        let is_scoped = self.0.parent() == Some(temp_root.as_path())
            && self
                .0
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("egopulse-c5-r9a3-witness-"));
        if is_scoped {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct R9a3WitnessProcess {
    child: std::process::Child,
}

impl R9a3WitnessProcess {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    fn bounded_reap(
        &mut self,
        deadline: Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(Some(status));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            thread::sleep(remaining.min(R9A3_WITNESS_REAP_POLL_INTERVAL));
        }
    }

    fn hard_kill(&mut self) -> std::process::ExitStatus {
        assert!(
            self.try_wait()
                .expect("inspect R-9A.3 witness helper before kill")
                .is_none(),
            "R-9A.3 witness helper must be alive before hard kill"
        );
        self.child.kill().expect("hard-kill R-9A.3 witness helper");
        self.bounded_reap(Instant::now() + R9A3_WITNESS_REAP_TIMEOUT)
            .expect("reap hard-killed R-9A.3 witness helper")
            .expect("hard-killed R-9A.3 witness helper must exit before reap deadline")
    }
}

impl Drop for R9a3WitnessProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.bounded_reap(Instant::now() + R9A3_WITNESS_REAP_TIMEOUT);
        }
    }
}

fn spawn_r9a3_witness_helper(root: &Path, instance: &str) -> R9a3WitnessProcess {
    let executable = std::env::current_exe().expect("R-9A.3 test executable path");
    let child = StdCommand::new(executable)
        .args([
            "--exact",
            "r9a3_external_side_effect_witness_helper_child",
            "--nocapture",
        ])
        .env(R9A3_WITNESS_ROOT_ENV, root)
        .env(R9A3_WITNESS_INSTANCE_ENV, instance)
        .env(R9A3_WITNESS_WITHHOLD_ACK_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn independent R-9A.3 witness helper");
    assert_ne!(
        child.id(),
        std::process::id(),
        "R-9A.3 witness helper must be a distinct process"
    );
    R9a3WitnessProcess { child }
}

fn wait_for_r9a3_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    child: &mut R9a3WitnessProcess,
    label: &str,
) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(payload) = fs::read(path)
            && let Ok(value) = serde_json::from_slice(&payload)
        {
            return value;
        }
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect helper while waiting for {label}: {error}"))
        {
            panic!("R-9A.3 witness helper exited before {label}: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3 witness helper did not publish {label} within timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn r9a3_external_side_effect_witness_helper_child() {
    let Some(root) = std::env::var_os(R9A3_WITNESS_ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let instance =
        std::env::var(R9A3_WITNESS_INSTANCE_ENV).expect("R-9A.3 witness helper instance");
    let withhold_ack = std::env::var(R9A3_WITNESS_WITHHOLD_ACK_ENV).as_deref() == Ok("1");
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("bind independent R-9A.3 witness helper");
    let endpoint = listener
        .local_addr()
        .expect("read R-9A.3 witness helper endpoint");
    let writer = R9a3SideEffectWriter::initialize(&root, &instance)
        .expect("initialize exclusive R-9A.3 side-effect writer");
    publish_r9a3_json_atomically(
        &r9a3_witness_ready_path(&root),
        &R9a3WitnessReady {
            process_id: std::process::id(),
            instance: instance.clone(),
            endpoint: endpoint.to_string(),
        },
        "R-9A.3 witness ready file",
    );

    let (mut stream, _) = listener.accept().expect("accept R-9A.3 witness request");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bound helper read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("bound helper write timeout");
    let request =
        read_r9a3_send_request_frame(&mut stream).expect("read bounded R-9A.3 send request frame");
    let ack = writer
        .commit_effect(&request)
        .expect("durably commit external R-9A.3 side effect");
    publish_r9a3_json_atomically(
        &r9a3_witness_checkpoint_path(&root),
        &R9a3WitnessCheckpoint {
            process_id: std::process::id(),
            instance,
            dispatch_id: request.dispatch_id,
            phase: "effect-committed-before-ack".to_owned(),
        },
        "R-9A.3 durable effect checkpoint",
    );
    if withhold_ack {
        loop {
            thread::park();
        }
    }
    write_r9a3_send_ack_frame(&mut stream, &ack).expect("write bounded R-9A.3 ACK frame");
    stream.flush().expect("flush R-9A.3 ACK frame");
}

#[test]
fn r9a3_external_side_effect_witness_is_durable_before_withheld_ack() {
    let root = R9a3WitnessTempRoot::new();
    let instance = format!("r9a3-witness-{}", Uuid::now_v7());
    let mut helper = spawn_r9a3_witness_helper(root.path(), &instance);
    let ready: R9a3WitnessReady = wait_for_r9a3_json(
        &r9a3_witness_ready_path(root.path()),
        &mut helper,
        "ready file",
    );
    assert_eq!(ready.process_id, helper.id());
    assert_ne!(ready.process_id, std::process::id());
    assert_eq!(ready.instance, instance);
    let endpoint: SocketAddr = ready.endpoint.parse().expect("parse helper endpoint");
    assert_eq!(endpoint.ip().to_string(), "127.0.0.1");
    assert_ne!(endpoint.port(), 0);

    let request = R9a3SendRequest {
        protocol_version: R9A3_PROTOCOL_VERSION,
        operation_id: "operation-external-01".to_owned(),
        dispatch_id: "dispatch-external-01".to_owned(),
        attempt_id: "attempt-external-01".to_owned(),
        fencing_token: 17,
        request_digest_sha256: "a".repeat(64),
        payload_digest_sha256: "b".repeat(64),
    };
    let client_request = request.clone();
    let (result_sender, result_receiver) = mpsc::sync_channel::<Result<R9a3SendAck, String>>(1);
    let client = thread::spawn(move || {
        let result = (|| {
            let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))
                .map_err(|error| format!("connect to R-9A.3 witness: {error}"))?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|error| format!("set R-9A.3 client read timeout: {error}"))?;
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .map_err(|error| format!("set R-9A.3 client write timeout: {error}"))?;
            write_r9a3_send_request_frame(&mut stream, &client_request)
                .map_err(|error| format!("write R-9A.3 request: {error}"))?;
            stream
                .flush()
                .map_err(|error| format!("flush R-9A.3 request: {error}"))?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| format!("finish R-9A.3 request: {error}"))?;
            read_r9a3_send_ack_frame(&mut stream)
                .map_err(|error| format!("read withheld R-9A.3 ACK: {error}"))
        })();
        let _ = result_sender.send(result);
    });

    let checkpoint: R9a3WitnessCheckpoint = wait_for_r9a3_json(
        &r9a3_witness_checkpoint_path(root.path()),
        &mut helper,
        "durable checkpoint",
    );
    assert_eq!(checkpoint.process_id, helper.id());
    assert_eq!(checkpoint.instance, instance);
    assert_eq!(checkpoint.dispatch_id, request.dispatch_id);
    assert_eq!(checkpoint.phase, "effect-committed-before-ack");

    let reader = R9a3SideEffectReader::open_existing(root.path(), &instance)
        .expect("open independent R-9A.3 witness read-only");
    assert_eq!(reader.effect_count().expect("read side-effect count"), 1);
    let effect = reader
        .effect_for_dispatch(&request.dispatch_id)
        .expect("read external side effect")
        .expect("external side effect must exist");
    assert_eq!(effect.request, request);
    let original_ack = effect.original_ack();
    assert!(!original_ack.replayed);
    assert!(!root.path().join(R8A_DRIVER_RECORD).exists());
    assert!(!root.path().join("r8b2c-native-witness.db").exists());

    let status = helper.hard_kill();
    assert!(
        !status.success(),
        "hard-killed R-9A.3 witness helper must not report success: {status}"
    );
    let client_result = result_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("R-9A.3 client must exit after helper hard kill");
    assert!(
        client_result.is_err(),
        "withheld ACK must not be fabricated after helper hard kill"
    );
    client.join().expect("join bounded R-9A.3 client");

    drop(reader);
    let reopened_reader = R9a3SideEffectReader::open_existing(root.path(), &instance)
        .expect("reopen R-9A.3 witness read-only after helper hard kill");
    assert_eq!(
        reopened_reader
            .effect_count()
            .expect("read post-kill side-effect count"),
        1
    );
    let reopened_effect = reopened_reader
        .effect_for_dispatch(&request.dispatch_id)
        .expect("read post-kill external side effect")
        .expect("post-kill external side effect must exist");
    assert_eq!(reopened_effect.request, request);
    assert_eq!(reopened_effect.original_ack(), original_ack);
    assert!(!reopened_effect.original_ack().replayed);
}

fn r9a3d_path(root: &Path, file_name: &str) -> PathBuf {
    root.join(file_name)
}

fn accept_r9a3d_connection(listener: &TcpListener, label: &str) -> TcpStream {
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept R-9A.3d {label}: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3d {label} connection was not received before deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn configure_r9a3d_stream(stream: &TcpStream, label: &str) {
    stream
        .set_read_timeout(Some(R9A3D_IO_TIMEOUT))
        .unwrap_or_else(|error| panic!("set R-9A.3d {label} read timeout: {error}"));
    stream
        .set_write_timeout(Some(R9A3D_IO_TIMEOUT))
        .unwrap_or_else(|error| panic!("set R-9A.3d {label} write timeout: {error}"));
}

fn wait_for_r9a3d_sender_disconnect(stream: &mut TcpStream) {
    stream
        .set_nonblocking(true)
        .expect("make R-9A.3d first sender nonblocking");
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    let mut trailing = [0_u8; 1];
    loop {
        match stream.read(&mut trailing) {
            Ok(0) => return,
            Ok(_) => panic!("R-9A.3d first sender wrote trailing bytes after its request"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
            Err(error) => panic!("observe R-9A.3d first sender disconnect: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3d first sender did not disconnect before deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn publish_r9a3d_request(
    root: &Path,
    file_name: &str,
    instance: &str,
    phase: &str,
    request: &R9a3SendRequest,
    send_count: u64,
) {
    publish_r9a3_json_atomically(
        &r9a3d_path(root, file_name),
        &R9a3dRequestEvidence::new(instance, phase, request, send_count),
        phase,
    );
}

#[test]
fn r9a3d_external_side_effect_witness_helper_child() {
    let Some(root) = std::env::var_os(R9A3D_WITNESS_ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let instance = std::env::var(R9A3D_WITNESS_INSTANCE_ENV).expect("R-9A.3d witness instance");
    let send_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind R-9A.3d send listener");
    send_listener
        .set_nonblocking(true)
        .expect("make R-9A.3d send listener nonblocking");
    let writer = R9a3SideEffectWriter::initialize(&root, &instance)
        .expect("initialize R-9A.3d external effect writer");
    let ready = R9a3dWitnessReady {
        process_id: std::process::id(),
        fixture_root: root.display().to_string(),
        fixture_instance: instance.clone(),
        send_endpoint: send_listener
            .local_addr()
            .expect("R-9A.3d send endpoint")
            .to_string(),
    };
    publish_r9a3_json_atomically(
        &r9a3d_path(&root, R9A3D_READY_FILE),
        &ready,
        "R-9A.3d witness ready",
    );

    let mut first = accept_r9a3d_connection(&send_listener, "first send");
    configure_r9a3d_stream(&first, "first send");
    let first_request =
        read_r9a3_send_request_frame(&mut first).expect("read R-9A.3d first send request");
    let _original_ack = writer
        .commit_effect(&first_request)
        .expect("commit R-9A.3d external effect before ACK");
    let send_count = 1_u64;
    publish_r9a3d_request(
        &root,
        R9A3D_COMMITTED_FILE,
        &instance,
        "effect-committed-before-ack",
        &first_request,
        send_count,
    );
    wait_for_r9a3d_sender_disconnect(&mut first);
    publish_r9a3d_request(
        &root,
        R9A3D_DISCONNECTED_FILE,
        &instance,
        "first-sender-disconnected-without-ack",
        &first_request,
        send_count,
    );

    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        match send_listener.accept() {
            Ok((mut stream, _)) => {
                if !r9a3d_path(&root, R9A3D_FORBIDDEN_CONNECTION_FILE).exists() {
                    publish_r9a3_json_atomically(
                        &r9a3d_path(&root, R9A3D_FORBIDDEN_CONNECTION_FILE),
                        &R9a3dForbiddenConnection {
                            process_id: std::process::id(),
                            fixture_instance: instance.clone(),
                            phase: "forbidden-second-connection".to_owned(),
                        },
                        "R-9A.3d forbidden second connection",
                    );
                }
                configure_r9a3d_stream(&stream, "forbidden second send");
                if let Ok(request) = read_r9a3_send_request_frame(&mut stream)
                    && !r9a3d_path(&root, R9A3D_FORBIDDEN_SEND_FILE).exists()
                {
                    publish_r9a3d_request(
                        &root,
                        R9A3D_FORBIDDEN_SEND_FILE,
                        &instance,
                        "forbidden-second-send-request",
                        &request,
                        send_count + 1,
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("monitor R-9A.3d second send: {error}"),
        }

        assert!(
            Instant::now() < deadline,
            "R-9A.3d witness monitoring deadline elapsed before parent cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_r9a3d_witness_helper(root: &Path, instance: &str) -> R9a3WitnessProcess {
    let executable = std::env::current_exe().expect("R-9A.3d test executable path");
    let child = StdCommand::new(executable)
        .args([
            "--exact",
            "r9a3d_external_side_effect_witness_helper_child",
            "--nocapture",
        ])
        .env(R9A3D_WITNESS_ROOT_ENV, root)
        .env(R9A3D_WITNESS_INSTANCE_ENV, instance)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn independent R-9A.3d witness helper");
    R9a3WitnessProcess { child }
}

fn r9a3d_request(
    envelope: &DispatchEnvelope,
    material: &ResolvedDispatchMaterial,
) -> R9a3SendRequest {
    R9a3SendRequest {
        protocol_version: R9A3_PROTOCOL_VERSION,
        operation_id: format!("operation-r9a3d-{}", envelope.dispatch_id),
        dispatch_id: envelope.dispatch_id.clone(),
        attempt_id: envelope.attempt_id.clone(),
        fencing_token: envelope.fencing_token,
        request_digest_sha256: format!("{:x}", Sha256::digest(envelope.encode_to_vec())),
        payload_digest_sha256: format!(
            "{:x}",
            Sha256::digest(material.canonical_input_bundle.as_slice())
        ),
    }
}

fn r9a3d_driver_error(detail: &str, error: impl std::fmt::Display) -> DriverError {
    DriverError {
        certainty: DriverErrorCertainty::DeliveryUnknown,
        code: HarnessErrorCode::DependencyUnavailable,
        safe_detail_code: detail.to_owned(),
        error_fingerprint: None,
        raw_evidence: format!("{detail}:{error}").into_bytes(),
    }
}

struct R9a3dFixtureDriver {
    probe_driver: FakeCodexDriver,
    send_endpoint: SocketAddr,
    witness_root: PathBuf,
    witness_instance: String,
}

impl R9a3dFixtureDriver {
    fn from_environment() -> Self {
        Self {
            probe_driver: FakeCodexDriver::default(),
            send_endpoint: std::env::var(R9A3D_SEND_ENDPOINT_ENV)
                .expect("R-9A.3d daemon send endpoint")
                .parse()
                .expect("parse R-9A.3d daemon send endpoint"),
            witness_root: std::env::var_os(R9A3D_WITNESS_ROOT_ENV)
                .map(PathBuf::from)
                .expect("R-9A.3d daemon witness root"),
            witness_instance: std::env::var(R9A3D_WITNESS_INSTANCE_ENV)
                .expect("R-9A.3d daemon witness instance"),
        }
    }

    fn exchange(
        endpoint: SocketAddr,
        request: &R9a3SendRequest,
        detail: &str,
    ) -> Result<R9a3SendAck, DriverError> {
        let mut stream = TcpStream::connect_timeout(&endpoint, R9A3D_IO_TIMEOUT)
            .map_err(|error| r9a3d_driver_error(detail, error))?;
        configure_r9a3d_stream(&stream, detail);
        write_r9a3_send_request_frame(&mut stream, request)
            .map_err(|error| r9a3d_driver_error(detail, error))?;
        stream
            .flush()
            .map_err(|error| r9a3d_driver_error(detail, error))?;
        stream
            .set_read_timeout(Some(R9A3D_PHASE_TIMEOUT))
            .map_err(|error| r9a3d_driver_error(detail, error))?;
        read_r9a3_send_ack_frame(&mut stream).map_err(|error| r9a3d_driver_error(detail, error))
    }

    fn require_ack(
        request: &R9a3SendRequest,
        ack: &R9a3SendAck,
        replayed: bool,
    ) -> Result<(), DriverError> {
        let valid = ack.protocol_version == request.protocol_version
            && ack.operation_id == request.operation_id
            && ack.dispatch_id == request.dispatch_id
            && ack.attempt_id == request.attempt_id
            && ack.fencing_token == request.fencing_token
            && ack.request_digest_sha256 == request.request_digest_sha256
            && ack.payload_digest_sha256 == request.payload_digest_sha256
            && ack.replayed == replayed;
        if valid {
            Ok(())
        } else {
            Err(r9a3d_driver_error(
                "R9A3D_ACK_BINDING_INVALID",
                "witness ACK drifted",
            ))
        }
    }
}

impl NativeHarnessDriver for R9a3dFixtureDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        self.probe_driver.probe(request)
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            let request = r9a3d_request(envelope, material);
            let ack = Self::exchange(self.send_endpoint, &request, "R9A3D_SEND_FAILED")?;
            Self::require_ack(&request, &ack, false)?;
            Ok(DriverDelivery {
                native_request_ref: format!("r9a3d-request:{}", ack.effect_id),
                native_session_ref: "r9a3d-session".to_owned(),
                native_execution_ref: Some(format!("r9a3d-effect:{}", ack.effect_id)),
                raw_evidence: ack.effect_id.into_bytes(),
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move { Ok(None) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            Err(r9a3d_driver_error(
                "R9A3D_APPROVAL_FORBIDDEN",
                "approval is outside this fixture",
            ))
        })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            Err(r9a3d_driver_error(
                "R9A3D_CANCEL_FORBIDDEN",
                "cancellation is outside this fixture",
            ))
        })
    }

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async move {
            let request = r9a3d_request(&context.envelope, &context.material);
            let reader =
                R9a3SideEffectReader::open_existing(&self.witness_root, &self.witness_instance)
                    .map_err(|error| r9a3d_driver_error("R9A3D_RECOVERY_OPEN_FAILED", error))?;
            let effect = reader
                .effect_for_dispatch(&request.dispatch_id)
                .map_err(|error| r9a3d_driver_error("R9A3D_RECOVERY_READ_FAILED", error))?
                .ok_or_else(|| {
                    r9a3d_driver_error("R9A3D_RECOVERY_EFFECT_MISSING", "effect missing")
                })?;
            if effect.request != request {
                return Err(r9a3d_driver_error(
                    "R9A3D_RECOVERY_REQUEST_DRIFT",
                    "stored effect request drifted",
                ));
            }
            let ack = effect.original_ack();
            Self::require_ack(&request, &ack, false)?;
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: format!("r9a3d-effect:{}", ack.effect_id),
            })
        })
    }
}

struct FirstRunnerCycleMarker {
    inner: Arc<dyn HarnessDispatchRunner>,
    marker_path: PathBuf,
}

impl FirstRunnerCycleMarker {
    fn new(inner: Arc<dyn HarnessDispatchRunner>, root: &Path) -> Self {
        Self {
            inner,
            marker_path: root.join(R8B_FIRST_RUNNER_CYCLE_RECORD),
        }
    }
}

impl HarnessDispatchRunner for FirstRunnerCycleMarker {
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let report = self.inner.run_once().await?;
            fs::write(&self.marker_path, b"complete").map_err(|error| {
                HarnessDispatchCycleError::TaskActivationWorkflow(format!(
                    "R-8B first runner cycle marker failed: {error}"
                ))
            })?;
            Ok(report)
        })
    }
}

struct RecordingFixtureDriver {
    inner: FakeCodexDriver,
    record_path: PathBuf,
    dispatch_count: u64,
    observation_forwarded: bool,
}

impl RecordingFixtureDriver {
    fn new(root: &Path) -> Self {
        Self {
            inner: FakeCodexDriver::default(),
            record_path: root.join(R8A_DRIVER_RECORD),
            dispatch_count: 0,
            observation_forwarded: false,
        }
    }

    fn new_for_r8b2c(root: &Path) -> Self {
        Self {
            inner: FakeCodexDriver::default().with_reconciliation_finding(
                ReconciliationFinding::OutcomeUnknown {
                    evidence_ref: "fixture://codex/r8b2c/outcome-unknown".to_owned(),
                },
            ),
            record_path: root.join(R8A_DRIVER_RECORD),
            dispatch_count: 0,
            observation_forwarded: false,
        }
    }
}

impl NativeHarnessDriver for RecordingFixtureDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        self.inner.probe(request)
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            self.dispatch_count += 1;
            let delivery = self.inner.send_dispatch(envelope, material).await?;
            let compiled_bytes_sha256 = format!(
                "{:x}",
                Sha256::digest(material.canonical_input_bundle.as_slice())
            );
            let record = serde_json::json!({
                "dispatchCount": self.dispatch_count,
                "dispatchId": envelope.dispatch_id,
                "runId": envelope.run_id,
                "stepId": envelope.step_id,
                "attemptId": envelope.attempt_id,
                "inputBundleRef": envelope.input_bundle_ref,
                "envelopeInputBundleSha256": envelope.input_bundle_sha256,
                "workspaceRef": envelope.workspace_ref,
                "compiledBytesSha256": compiled_bytes_sha256,
                "canonicalInputBundleUtf8": String::from_utf8_lossy(&material.canonical_input_bundle),
                "prompt": material.prompt,
                "workspaceRoot": material.workspace_root.display().to_string(),
                "model": material.model,
            });
            fs::write(
                &self.record_path,
                serde_json::to_vec(&record).expect("serialize R-8A driver record"),
            )
            .expect("persist R-8A driver record");
            Ok(delivery)
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            if self.observation_forwarded {
                return Ok(None);
            }
            let observation = self.inner.next_event(envelope).await?;
            self.observation_forwarded = observation.is_some();
            Ok(observation)
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        self.inner.decide_approval(envelope)
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        self.inner.cancel(envelope)
    }

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        self.inner.reconcile(context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R8b2cDriverMode {
    BeginDeliveryBlock,
    Recover,
}

fn native_event_record(event: &DriverEvent) -> R8b2cNativeEventRecord {
    assert!(matches!(
        &event.payload,
        harness_observation::Payload::Ack(_)
    ));
    R8b2cNativeEventRecord {
        native_key: event.native_key.clone(),
        native_event_id: event.native_event_id.clone(),
        native_sequence: event.native_sequence,
        observed_seconds: event.native_observed_at.seconds,
        observed_nanos: event.native_observed_at.nanos,
        criticality: event.criticality as i32,
        payload: HarnessObservation {
            payload: Some(event.payload.clone()),
            ..HarnessObservation::default()
        }
        .encode_to_vec(),
        raw_event: event.raw_event.clone(),
    }
}

fn driver_event(record: R8b2cNativeEventRecord) -> DriverEvent {
    let carrier = HarnessObservation::decode(record.payload.as_slice())
        .expect("decode R-8B.2c native ACK carrier");
    DriverEvent {
        native_key: record.native_key,
        native_event_id: record.native_event_id,
        native_sequence: record.native_sequence,
        native_observed_at: prost_types::Timestamp {
            seconds: record.observed_seconds,
            nanos: record.observed_nanos,
        },
        criticality: ObservationCriticality::try_from(record.criticality)
            .expect("R-8B.2c native criticality"),
        payload: carrier.payload.expect("R-8B.2c native ACK payload"),
        raw_event: record.raw_event,
    }
}

struct R8b2cWitnessOracle {
    reader: R8b2cWitnessReader,
}

impl R8b2cWitnessOracle {
    fn open_existing(root: &Path, instance: &str) -> Self {
        Self {
            reader: R8b2cWitnessReader::open_existing(root, instance)
                .expect("open existing R-8B.2c witness read-only"),
        }
    }

    fn ledger_count(&self, operation: &str) -> u64 {
        self.reader
            .ledger_count(operation)
            .expect("count R-8B.2c witness ledger")
    }

    fn native_event_state(&self, dispatch_id: &str) -> Option<(String, u64)> {
        self.reader
            .native_event_state(dispatch_id)
            .expect("read R-8B.2c native event state")
    }
}

struct R8b2cFixtureDriver {
    inner: RecordingFixtureDriver,
    witness: R8b2cWitnessWriter,
    root: PathBuf,
    instance: String,
    mode: R8b2cDriverMode,
}

impl R8b2cFixtureDriver {
    fn new(root: &Path, instance: &str, mode: R8b2cDriverMode) -> Self {
        Self {
            inner: RecordingFixtureDriver::new_for_r8b2c(root),
            witness: R8b2cWitnessWriter::initialize(root, instance)
                .expect("initialize R-8B.2c native witness"),
            root: root.to_owned(),
            instance: instance.to_owned(),
            mode,
        }
    }
}

impl NativeHarnessDriver for R8b2cFixtureDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        self.inner.probe(request)
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            self.witness
                .append("send_dispatch", &envelope.dispatch_id, "native side effect")
                .expect("append R-8B.2c native send");
            let delivery = self.inner.send_dispatch(envelope, material).await?;
            let ack = self
                .inner
                .next_event(envelope)
                .await?
                .expect("FakeCodexDriver must produce its original ACK after send");
            self.witness
                .persist_native_event(&envelope.dispatch_id, &native_event_record(&ack))
                .expect("persist R-8B.2c native ACK");
            if self.mode == R8b2cDriverMode::BeginDeliveryBlock {
                publish_r8b2c_checkpoint(
                    &self.root,
                    &self.instance,
                    &envelope.dispatch_id,
                    R8B2C_BEGIN_DELIVERY_PHASE,
                );
                std::future::pending::<()>().await;
                unreachable!("R-8B.2c begin-delivery checkpoint is permanently blocked");
            }
            Ok(delivery)
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            Ok(self
                .witness
                .next_native_event(&envelope.dispatch_id)
                .expect("poll R-8B.2c native witness")
                .map(driver_event))
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        self.inner.decide_approval(envelope)
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        self.inner.cancel(envelope)
    }

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async move {
            self.witness
                .append("reconcile", &context.envelope.dispatch_id, "OutcomeUnknown")
                .expect("append R-8B.2c reconcile");
            self.inner.reconcile(context).await
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R8b2cRunnerCheckpoint {
    DeliveredBeforePoll,
    UnknownRecovered,
    AckRehydrated,
    PreAuthorizationUnavailable,
    RevokedReadyRejected,
}

struct R8b2cCheckpointRunner {
    inner: Arc<dyn HarnessDispatchRunner>,
    root: PathBuf,
    instance: String,
    checkpoint: R8b2cRunnerCheckpoint,
}

impl HarnessDispatchRunner for R8b2cCheckpointRunner {
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let report = self.inner.run_once().await?;
            let (reached, phase, block) = match self.checkpoint {
                R8b2cRunnerCheckpoint::DeliveredBeforePoll => (
                    report.dispatches_delivered > 0,
                    R8B2C_DELIVERED_BEFORE_POLL_PHASE,
                    true,
                ),
                R8b2cRunnerCheckpoint::UnknownRecovered => (
                    report.task_recovery_findings.iter().any(|finding| {
                        finding.kind
                            == egopulse_local_ide_control::collaboration_control::TaskRecoveryKind::OutcomeUnknown
                    }),
                    R8B2C_UNKNOWN_RECOVERED_PHASE,
                    false,
                ),
                R8b2cRunnerCheckpoint::AckRehydrated => (
                    report.observations_consumed > 0,
                    R8B2C_ACK_REHYDRATED_PHASE,
                    false,
                ),
                R8b2cRunnerCheckpoint::PreAuthorizationUnavailable => (
                    report.dispatches_seen > 0
                        && report.dispatches_rejected > 0
                        && report.dispatches_delivered == 0,
                    R9A3E_PREAUTH_UNAVAILABLE_PHASE,
                    true,
                ),
                R8b2cRunnerCheckpoint::RevokedReadyRejected => (
                    report.dispatches_seen > 0
                        && report.dispatches_rejected > 0
                        && report.dispatches_delivered == 0,
                    R9A3E_REVOKED_READY_PHASE,
                    true,
                ),
            };
            if reached {
                publish_r8b2c_checkpoint(&self.root, &self.instance, "r8a-dispatch", phase);
                if block {
                    std::future::pending::<()>().await;
                    unreachable!("R-8B.2c runner checkpoint is permanently blocked");
                }
            }
            Ok(report)
        })
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct R9a3dRunnerCheckpoint {
    process_id: u32,
    fixture_root: String,
    fixture_instance: String,
    phase: String,
}

struct R9a3dRecoveryRunner {
    inner: Arc<dyn HarnessDispatchRunner>,
    root: PathBuf,
    instance: String,
    recovery_seen: AtomicBool,
    stable_published: AtomicBool,
}

impl HarnessDispatchRunner for R9a3dRecoveryRunner {
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let report = self.inner.run_once().await?;
            if !report.task_recovery_findings.is_empty()
                && !self.recovery_seen.swap(true, Ordering::SeqCst)
            {
                publish_r9a3_json_atomically(
                    &r9a3d_path(&self.root, R9A3D_RECOVERY_CHECKPOINT_FILE),
                    &R9a3dRunnerCheckpoint {
                        process_id: std::process::id(),
                        fixture_root: self.root.display().to_string(),
                        fixture_instance: self.instance.clone(),
                        phase: "recovery-settled".to_owned(),
                    },
                    "R-9A.3d recovery checkpoint",
                );
            } else if self.recovery_seen.load(Ordering::SeqCst)
                && !self.stable_published.swap(true, Ordering::SeqCst)
            {
                publish_r9a3_json_atomically(
                    &r9a3d_path(&self.root, R9A3D_STABLE_CHECKPOINT_FILE),
                    &R9a3dRunnerCheckpoint {
                        process_id: std::process::id(),
                        fixture_root: self.root.display().to_string(),
                        fixture_instance: self.instance.clone(),
                        phase: "stable-cycle".to_owned(),
                    },
                    "R-9A.3d stable checkpoint",
                );
            }
            Ok(report)
        })
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct R8b2cCheckpoint {
    process_id: u32,
    fixture_root: String,
    fixture_instance: String,
    dispatch_id: String,
    phase: String,
}

fn r8b2c_checkpoint_path(root: &Path, phase: &str) -> PathBuf {
    root.join(format!("r8b2c-checkpoint-{phase}.json"))
}

fn publish_r8b2c_checkpoint(root: &Path, instance: &str, dispatch_id: &str, phase: &str) {
    let checkpoint = R8b2cCheckpoint {
        process_id: std::process::id(),
        fixture_root: root.display().to_string(),
        fixture_instance: instance.to_owned(),
        dispatch_id: dispatch_id.to_owned(),
        phase: phase.to_owned(),
    };
    let payload = serde_json::to_vec(&checkpoint).expect("serialize R-8B.2c checkpoint");
    let path = r8b2c_checkpoint_path(root, phase);
    if path.exists() {
        let existing: R8b2cCheckpoint =
            serde_json::from_slice(&fs::read(&path).expect("read existing R-8B.2c checkpoint"))
                .expect("decode existing R-8B.2c checkpoint");
        assert_eq!(existing.process_id, checkpoint.process_id);
        assert_eq!(existing.fixture_root, checkpoint.fixture_root);
        assert_eq!(existing.fixture_instance, checkpoint.fixture_instance);
        assert_eq!(existing.dispatch_id, checkpoint.dispatch_id);
        assert_eq!(existing.phase, checkpoint.phase);
        return;
    }
    let temporary = root.join(format!(
        ".r8b2c-checkpoint-{phase}-{}-{}.tmp",
        std::process::id(),
        Uuid::now_v7()
    ));
    let mut file = File::create(&temporary).expect("create R-8B.2c checkpoint temp file");
    file.write_all(&payload).expect("write R-8B.2c checkpoint");
    file.flush().expect("flush R-8B.2c checkpoint");
    file.sync_all().expect("sync R-8B.2c checkpoint");
    drop(file);
    fs::rename(&temporary, &path).expect("publish R-8B.2c checkpoint");
}

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
        _scope: &egopulse_domain_contracts::v01::egopulse::verdict::v1::VerdictScope,
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
        _scope: &egopulse_domain_contracts::v01::egopulse::verdict::v1::VerdictScope,
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
                work_revision: 1,
                status: RunStatus::ReturnPending as i32,
                ..Default::default()
            }),
            steps: vec![StepSnapshot {
                step_id: "c5-step".to_owned(),
                run_id: "c5-run".to_owned(),
                revision: 1,
                status: StepStatus::ReturnPending as i32,
                ..Default::default()
            }],
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
        let task_event = TaskEvent {
            event_id: "task-event-c5-03".to_owned(),
            task_id: "task-c5-03".to_owned(),
            resulting_revision: 1,
            work_revision: 1,
            snapshot: Some(TaskSnapshot {
                task_id: "task-c5-03".to_owned(),
                revision: 1,
                work_revision: 1,
                status: TaskStatus::Active as i32,
                work_type: "c5-03-real-return-view".to_owned(),
                input_snapshot_id: "input-c5-03".to_owned(),
                target_scope_ref: "scope-c5-03".to_owned(),
                current_run_id: Some("c5-run".to_owned()),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                }),
                updated_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        Self {
            messages: std::sync::Mutex::new(vec![
                PendingOwnerProjection::Task(Box::new(TaskProjectionMessage {
                    message_id: "c5-task-projection".to_owned(),
                    source_event_id: task_event.event_id.clone(),
                    source_revision: 1,
                    payload_digest_sha256: hex::encode(Sha256::digest(task_event.encode_to_vec())),
                    event: task_event,
                })),
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
            PendingOwnerProjection::Task(value) => &value.message_id,
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
            PendingOwnerProjection::Task(value) => value.message_id != *message_id,
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

    fn resolve_memory(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<MemoryPrincipalKind, CommandPortFailure> {
        Ok(MemoryPrincipalKind::Founder)
    }

    fn resolve_context(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<ContextPrincipalKind, CommandPortFailure> {
        Ok(ContextPrincipalKind::Founder)
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

fn dynamic_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R8A_FIXTURE_MODE
            | R8B_PAUSE_BEFORE_RUNNER_MODE
            | R8B2C_BEGIN_DELIVERY_MODE
            | R8B2C_UNKNOWN_RECOVERY_MODE
            | R8B2C_DELIVERED_BEFORE_POLL_MODE
            | R8B2C_ACK_RECOVERY_MODE
            | R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
    )
}

fn r8b2c_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R8B2C_BEGIN_DELIVERY_MODE
            | R8B2C_UNKNOWN_RECOVERY_MODE
            | R8B2C_DELIVERED_BEFORE_POLL_MODE
            | R8B2C_ACK_RECOVERY_MODE
    )
}

fn r9a3d_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
    )
}

fn r8a_reference(contract_id: &str) -> ContractReference {
    ContractReference {
        contract_id: contract_id.to_owned(),
        version: "v0.1".to_owned(),
        sha256: "66".repeat(32),
    }
}

fn r8a_native_config(root: &Path) -> NativeHarnessCompositionConfig {
    let capability_profile_ref = r8a_reference(CODEX_CAPABILITY_PROFILE_ID);
    let workspace_ref = "workspace-r8a".to_owned();
    NativeHarnessCompositionConfig {
        collaboration_database_path: root.join("r8a-collaboration.db"),
        collaboration_store_epoch: "r8a-collaboration-epoch".to_owned(),
        collaboration_key: [0x31; 32],
        adapter_database_path: root.join("r8a-adapter.db"),
        adapter_store_epoch: "r8a-adapter-epoch".to_owned(),
        adapter_key: [0x32; 32],
        input_bundle_root: root.join("input-bundles"),
        workspace_root: root.to_owned(),
        default_model: Some("fixture/model".to_owned()),
        workflow: SingleHarnessWorkConfig {
            run_id: R8A_ACTIVATION_RUN_ID.to_owned(),
            attempt_id: "r8a-attempt".to_owned(),
            dispatch_id: "r8a-dispatch".to_owned(),
            plan: RunPlan {
                plan_id: "r8a-reviewed-plan".to_owned(),
                digest_sha256: "61".repeat(32),
                max_active_attempts: 1,
                steps: vec![StepPlan {
                    step_id: "r8a-step".to_owned(),
                    step_kind: "governed_repository_change".to_owned(),
                    depends_on_step_ids: Vec::new(),
                    input_bundle_ref: "static-r8a.json".to_owned(),
                    expected_output_contract_ref: Some(r8a_reference("r8a-output")),
                    required_capability_profile_ref: Some(capability_profile_ref.clone()),
                    max_attempts: 2,
                }],
                budget_profile_ref: Some(ContractReference {
                    contract_id: "c5-budget".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "55".repeat(32),
                }),
            },
            harness_id: "codex-r8a-fixture".to_owned(),
            capability_profile_ref,
            workspace_ref: workspace_ref.clone(),
            lease_policy_ref: r8a_reference("r8a-lease"),
            owner_instance_id: "r8a-owner".to_owned(),
            material: DispatchMaterial {
                input_bundle_sha256: "62".repeat(32),
                sandbox_profile_ref: r8a_reference("r8a-sandbox"),
                tool_policy_ref: r8a_reference("r8a-tool-policy"),
                data_egress_policy_ref: r8a_reference("r8a-egress-policy"),
                approval_policy_ref: r8a_reference("r8a-approval-policy"),
                session_strategy: NativeSessionStrategy::CreateNew,
                native_session_ref: None,
                checkpoint_ref: None,
                evidence_refs: vec!["fixture:r8a-reviewed-material".to_owned()],
            },
            task_authority_principal_id: "task-authority:r8a".to_owned(),
            collaboration_principal_id: "collaboration-control:r8a".to_owned(),
            attempt_supervisor_principal_id: "attempt-supervisor:r8a".to_owned(),
            harness_adapter_principal_id: "harness-adapter:r8a".to_owned(),
        },
        lease_ttl_seconds: 30,
        return_collector: GovernedReturnCollectorConfig {
            artifact_type_ref: r8a_reference("r8a-artifact-type"),
            transformation_contract_ref: r8a_reference("r8a-transformation"),
            retention_profile_ref: r8a_reference("r8a-retention"),
            claim_semantic_profile_ref: r8a_reference("r8a-claim-semantic"),
            claim_acceptance_contract_ref: r8a_reference("r8a-claim-acceptance"),
            evidence_profile_ref: r8a_reference("r8a-evidence-profile"),
            workspace_ref,
            collector_principal_id: "collector:r8a".to_owned(),
            artifact_authority_principal_id: "artifact-authority:r8a".to_owned(),
        },
    }
}

fn r8a_authorities(
    root: &Path,
    collector: &GovernedReturnCollectorConfig,
) -> (
    Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    Arc<Mutex<VerificationAuthority>>,
) {
    let artifact_guard =
        ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
            allowed_workspace_refs: [collector.workspace_ref.clone()].into_iter().collect(),
            allowed_artifact_type_refs: vec![collector.artifact_type_ref.clone()],
            allowed_transformation_contract_refs: vec![
                collector.transformation_contract_ref.clone(),
            ],
            allowed_retention_profile_refs: vec![collector.retention_profile_ref.clone()],
            allowed_claim_semantic_profile_refs: vec![collector.claim_semantic_profile_ref.clone()],
            allowed_claim_acceptance_contract_refs: vec![
                collector.claim_acceptance_contract_ref.clone(),
            ],
            allowed_evidence_profile_refs: vec![collector.evidence_profile_ref.clone()],
        })
        .expect("R-8A artifact admission guard");
    let artifact = ArtifactAuthority::open(
        ArtifactAuthorityConfig {
            database_path: root.join("r8a-artifact-authority.db"),
            blob_root: root.join("r8a-artifact-blobs"),
            store_epoch: "r8a-artifact-epoch".to_owned(),
            key: ArtifactSqlCipherKey::new([0x41; 32]),
        },
        artifact_guard,
    )
    .expect("R-8A Artifact Authority");
    let verification = VerificationAuthority::open(
        VerificationAuthorityConfig {
            database_path: root.join("r8a-verification-authority.db"),
            store_epoch: "r8a-verification-epoch".to_owned(),
            key: VerificationSqlCipherKey::new([0x42; 32]),
        },
        DenyVerificationReferences,
    )
    .expect("R-8A Verification Authority");
    (
        Arc::new(Mutex::new(artifact)),
        Arc::new(Mutex::new(verification)),
    )
}

fn fixture_config(root: &Path, instance: &str) -> DaemonConfig {
    DaemonConfig {
        instance: instance.to_owned(),
        read_model_database_path: root.join("read-model.db"),
        read_model_epoch: "c5-00-fixture-epoch".to_owned(),
        read_model_key: [0x41; 32],
        token_mac_key: [0x42; 32],
        session_ttl: Duration::from_secs(60),
        harness_dispatch_interval: if fixture_mode() == R8B_PAUSE_BEFORE_RUNNER_MODE {
            Duration::from_secs(60)
        } else {
            Duration::from_millis(25)
        },
        verification_interval: Duration::from_millis(25),
        verdict_consumption_interval: Duration::from_millis(25),
    }
}

fn r9a2c_snapshot_id(compiled_context: &[u8]) -> String {
    format!("ctx:{:x}", Sha256::digest(compiled_context))
}

fn issue_r9a2c_context_snapshot(
    authority: &mut ContextAuthority,
    compiled_context: &[u8],
    idempotency_key: &str,
) {
    let (_, snapshot) = authority
        .issue(
            &IssueContextSnapshot {
                owner_principal_id: "os-user:c5-fixture".to_owned(),
                intent: "prove governed Context revoke through a real user surface".to_owned(),
                work_type: "governed_repository_change".to_owned(),
                target_scope_ref: "scope:r9a2c".to_owned(),
                compiled_context: compiled_context.to_vec(),
                sources: Vec::new(),
                memory_pack: None,
                allowed_read_paths: vec!["docs".to_owned()],
                allowed_write_paths: Vec::new(),
                allowed_tools: Vec::new(),
                external_resources: Vec::new(),
                non_goals: vec!["do not disclose private Context bytes".to_owned()],
                acceptance_contract_ref: "acceptance:r9a2c".to_owned(),
                budget_profile_ref: "budget:r9a2c".to_owned(),
                deadline_seconds: None,
                recovery_entry: "hold-and-reconcile".to_owned(),
                visibility: "founder-only".to_owned(),
                redactions: Vec::new(),
                expires_at_seconds: R9A2C_CONTEXT_EXPIRES_AT_SECONDS,
                idempotency_key: idempotency_key.to_owned(),
            },
            &AuthenticatedContextPrincipal {
                kind: ContextPrincipalKind::ContextCompiler,
                principal_id: "context-compiler:c5-fixture".to_owned(),
                authenticated: true,
            },
        )
        .expect("issue deterministic R9A.2c Context fixture");
    assert_eq!(snapshot.snapshot_id, r9a2c_snapshot_id(compiled_context));
}

fn open_fixture_providers(root: &Path) -> DaemonProviders {
    if matches!(
        fixture_mode().as_str(),
        "allow"
            | R8A_FIXTURE_MODE
            | R8B_PAUSE_BEFORE_RUNNER_MODE
            | R8B2C_BEGIN_DELIVERY_MODE
            | R8B2C_UNKNOWN_RECOVERY_MODE
            | R8B2C_DELIVERED_BEFORE_POLL_MODE
            | R8B2C_ACK_RECOVERY_MODE
            | R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
    ) {
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
    let mut context = ContextAuthority::open(ContextAuthorityConfig {
        database_path: root.join("context-authority.db"),
        store_epoch: "c5-context-epoch".to_owned(),
        key: SqlCipherKey::new([0x15; 32]),
    })
    .expect("fixture Context Authority should open");
    issue_r9a2c_context_snapshot(&mut context, R9A2C_CLI_CONTEXT_BYTES, "r9a2c-cli-issue");
    let context = Arc::new(Mutex::new(context));
    let task = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        task_guard,
        ConfiguredTaskTransitionGuard::new().with_context_authority(Arc::clone(&context)),
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

    let (providers, shared_task) = if dynamic_fixture_mode() {
        let task = Arc::new(Mutex::new(task));
        let verdict = Arc::new(Mutex::new(Some(verdict)));
        (
            DaemonProviders::from_shared_authority_inputs(SharedAuthorityCompositionInputs {
                task: Arc::clone(&task),
                policy,
                verdict,
                principal_resolver: Arc::new(FixtureAuthorityPrincipalResolver),
                session_principal_resolver: Arc::new(FixtureSessionResolver),
                session_clock: Arc::new(egopulse_local_api::session::SystemSessionClock),
                session_audit: Arc::new(NoopSessionAuditSink),
                additional_projection_sources,
            }),
            Some(task),
        )
    } else {
        (
            DaemonProviders::from_authority_inputs(AuthorityCompositionInputs {
                task,
                policy,
                verdict,
                principal_resolver: Arc::new(FixtureAuthorityPrincipalResolver),
                session_principal_resolver: Arc::new(FixtureSessionResolver),
                session_clock: Arc::new(egopulse_local_api::session::SystemSessionClock),
                session_audit: Arc::new(NoopSessionAuditSink),
                additional_projection_sources,
            }),
            None,
        )
    };
    let mut memory = MemoryAuthority::open(MemoryAuthorityConfig {
        database_path: root.join("memory-authority.db"),
        store_epoch: "c5-memory-epoch".to_owned(),
        key: SqlCipherKey::new([0x14; 32]),
    })
    .expect("fixture Memory Authority should open");
    let founder = AuthenticatedMemoryPrincipal {
        kind: MemoryPrincipalKind::Founder,
        principal_id: "founder:c5-fixture".to_owned(),
        authenticated: true,
    };
    memory
        .submit_candidate(
            &SubmitMemoryCandidate {
                memory_id: "memory-c5-accepted".to_owned(),
                content: "EgoPulse governed Memory is Founder accepted.".to_owned(),
                source_ref: "source:c5-memory".to_owned(),
                scope_ref: "scope:founder".to_owned(),
                idempotency_key: "c5-memory-submit".to_owned(),
            },
            &founder,
        )
        .expect("fixture Memory candidate should submit or replay");
    memory
        .accept(
            &GovernMemory {
                memory_id: "memory-c5-accepted".to_owned(),
                expected_revision: 1,
                evidence_ref: "evidence:c5-founder-acceptance".to_owned(),
                idempotency_key: "c5-memory-accept".to_owned(),
            },
            &founder,
        )
        .expect("fixture Memory candidate should be accepted or replayed");
    let memory = Arc::new(std::sync::Mutex::new(memory));
    let providers = providers
        .with_memory_retrieval(Arc::clone(&memory), memory_worker_config())
        .expect("fixture Memory retrieval should configure")
        .with_memory_mutation(memory, Arc::new(FixtureAuthorityPrincipalResolver));
    let mut work_port = ConfiguredWorkPreparationPort::new(
        Arc::clone(&context),
        Arc::clone(&providers.task_port),
        root.to_owned(),
        BTreeSet::from(["governed_repository_change".to_owned()]),
        ContractReference {
            contract_id: "c5-acceptance".to_owned(),
            version: "v0.1".to_owned(),
            sha256: "44".repeat(32),
        },
        ContractReference {
            contract_id: "c5-budget".to_owned(),
            version: "v0.1".to_owned(),
            sha256: "55".repeat(32),
        },
    )
    .expect("fixture Work Preparation should configure");
    if dynamic_fixture_mode() {
        work_port = work_port
            .with_input_bundle_root(root.join("input-bundles"))
            .and_then(|port| port.with_activation_run_id(R8A_ACTIVATION_RUN_ID.to_owned()))
            .expect("R-8A Work Preparation dispatch binding");
    }
    let providers = providers
        .with_work_preparation_port(Arc::new(work_port))
        .with_context_authority(Arc::clone(&context))
        .with_context_mutation(Arc::new(ContextMutationPortAdapter::new(
            Arc::clone(&context),
            Arc::new(FixtureAuthorityPrincipalResolver),
        )));
    if !dynamic_fixture_mode() {
        return providers;
    }

    let native = r8a_native_config(root);
    fs::create_dir_all(root.join(&native.workflow.workspace_ref))
        .expect("R-8A governed workspace should exist");
    let (artifact, verification) = r8a_authorities(root, &native.return_collector);
    let mode = fixture_mode();
    let providers = if r8b2c_fixture_mode() {
        let driver_mode = if mode == R8B2C_BEGIN_DELIVERY_MODE {
            R8b2cDriverMode::BeginDeliveryBlock
        } else {
            R8b2cDriverMode::Recover
        };
        providers
            .with_native_harness_driver(
                native,
                artifact,
                verification,
                R8b2cFixtureDriver::new(root, &fixture_instance(), driver_mode),
            )
            .expect("R-8B.2c native Harness composition")
    } else if r9a3d_fixture_mode() {
        providers
            .with_native_harness_driver(
                native,
                artifact,
                verification,
                R9a3dFixtureDriver::from_environment(),
            )
            .expect("R-9A.3d native Harness composition")
    } else {
        providers
            .with_native_harness_driver(
                native,
                artifact,
                verification,
                RecordingFixtureDriver::new(root),
            )
            .expect("R-8A native Harness composition")
    };
    let mut providers = providers
        .with_task_recovery_settlement(
            shared_task.expect("dynamic fixture must retain the shared Task Authority"),
        )
        .expect("dynamic fixture Task recovery settlement");
    if mode == R8B_PAUSE_BEFORE_RUNNER_MODE {
        let runner = providers
            .harness_dispatch_runner
            .take()
            .expect("R-8B production Harness runner");
        providers.harness_dispatch_runner =
            Some(Arc::new(FirstRunnerCycleMarker::new(runner, root)));
    } else if let Some(checkpoint) = match mode.as_str() {
        R8B2C_DELIVERED_BEFORE_POLL_MODE => Some(R8b2cRunnerCheckpoint::DeliveredBeforePoll),
        R8B2C_UNKNOWN_RECOVERY_MODE => Some(R8b2cRunnerCheckpoint::UnknownRecovered),
        R8B2C_ACK_RECOVERY_MODE => Some(R8b2cRunnerCheckpoint::AckRehydrated),
        R9A3E_PREAUTH_UNAVAILABLE_MODE => Some(R8b2cRunnerCheckpoint::PreAuthorizationUnavailable),
        R9A3E_REVOKED_READY_MODE => Some(R8b2cRunnerCheckpoint::RevokedReadyRejected),
        _ => None,
    } {
        let runner = providers
            .harness_dispatch_runner
            .take()
            .expect("R-8B.2c production Harness runner");
        providers.harness_dispatch_runner = Some(Arc::new(R8b2cCheckpointRunner {
            inner: runner,
            root: root.to_owned(),
            instance: fixture_instance(),
            checkpoint,
        }));
    }
    if mode == R9A3D_EXTERNAL_RECOVERY_MODE {
        let runner = providers
            .harness_dispatch_runner
            .take()
            .expect("R-9A.3d production Harness runner");
        providers.harness_dispatch_runner = Some(Arc::new(R9a3dRecoveryRunner {
            inner: runner,
            root: root.to_owned(),
            instance: fixture_instance(),
            recovery_seen: AtomicBool::new(false),
            stable_published: AtomicBool::new(false),
        }));
    }
    providers
}

fn memory_worker_config() -> MemoryRetrievalCompositionConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned();
    MemoryRetrievalCompositionConfig {
        worker_executable: root.join("workers/memory-rag/.venv/Scripts/python.exe"),
        worker_arguments: vec!["-m".to_owned(), "egopulse_memory_rag".to_owned()],
        working_directory: root.clone(),
        inherited_environment: BTreeSet::from(["SystemRoot".to_owned(), "WINDIR".to_owned()]),
        environment_overrides: BTreeMap::from([(
            "PYTHONPATH".to_owned(),
            format!(
                "{};{}",
                root.join("workers/memory-rag/src").display(),
                root.join("workers/contract-bindings/src").display()
            ),
        )]),
        timeout: Duration::from_secs(15),
        output_limit_bytes: 16 * 1024 * 1024,
        principal_scope_allowlist: BTreeMap::from([(
            "os-user:c5-fixture".to_owned(),
            BTreeSet::from(["scope:founder".to_owned()]),
        )]),
    }
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
    let mut command = Command::new(executable);
    command
        .args(["--exact", "c5_00_daemon_fixture_child", "--nocapture"])
        .env(FIXTURE_ROOT_ENV, root)
        .env(FIXTURE_INSTANCE_ENV, instance)
        .env(FIXTURE_MODE_ENV, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(
            if matches!(
                mode,
                R8A_FIXTURE_MODE
                    | R8B_PAUSE_BEFORE_RUNNER_MODE
                    | R8B2C_BEGIN_DELIVERY_MODE
                    | R8B2C_UNKNOWN_RECOVERY_MODE
                    | R8B2C_DELIVERED_BEFORE_POLL_MODE
                    | R8B2C_ACK_RECOVERY_MODE
                    | R9A3D_EXTERNAL_SEND_MODE
                    | R9A3D_EXTERNAL_RECOVERY_MODE
                    | R9A3E_PREAUTH_UNAVAILABLE_MODE
                    | R9A3E_REVOKED_READY_MODE
            ) {
                Stdio::inherit()
            } else {
                Stdio::null()
            },
        )
        .kill_on_drop(true);
    command.spawn().expect("spawn C5 fixture child")
}

async fn spawn_r9a3d_fixture(
    root: &Path,
    instance: &str,
    mode: &str,
    witness_instance: &str,
    send_endpoint: &str,
) -> Child {
    let executable = std::env::current_exe().expect("R-9A.3d daemon executable path");
    let mut command = Command::new(executable);
    command
        .args(["--exact", "c5_00_daemon_fixture_child", "--nocapture"])
        .env(FIXTURE_ROOT_ENV, root)
        .env(FIXTURE_INSTANCE_ENV, instance)
        .env(FIXTURE_MODE_ENV, mode)
        .env(R9A3D_WITNESS_ROOT_ENV, root)
        .env(R9A3D_WITNESS_INSTANCE_ENV, witness_instance)
        .env(R9A3D_SEND_ENDPOINT_ENV, send_endpoint)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    command.spawn().expect("spawn R-9A.3d daemon child")
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

fn tui_executable() -> PathBuf {
    let test_executable = std::env::current_exe().expect("TUI E2E test executable path");
    let target_debug = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("TUI E2E test must run below target/debug");
    let executable = target_debug.join("egopulse-tui.exe");
    assert!(
        executable.is_file(),
        "TUI E2E requires the normal egopulse-tui binary at {}",
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

async fn run_tui_once(instance: &str) -> std::process::Output {
    Command::new(tui_executable())
        .args(["--instance", instance, "--once"])
        .output()
        .await
        .expect("run real egopulse TUI process")
}

async fn run_tui(instance: &str, arguments: &[&str]) -> std::process::Output {
    Command::new(tui_executable())
        .env("EGOPULSE_IPC_INSTANCE", instance)
        .args(arguments)
        .output()
        .await
        .expect("run real egopulse TUI command")
}

async fn run_bounded_fixture_command(
    executable: PathBuf,
    instance: &str,
    arguments: &[&str],
    label: &str,
) -> std::process::Output {
    let mut command = Command::new(executable);
    command
        .env("EGOPULSE_IPC_INSTANCE", instance)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn {label}: {error}"));
    let mut stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("capture {label} stdout"));
    let mut stderr = child
        .stderr
        .take()
        .unwrap_or_else(|| panic!("capture {label} stderr"));
    let stdout_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let stderr_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match timeout(R9A3D_IO_TIMEOUT, child.wait()).await {
        Ok(result) => result.unwrap_or_else(|error| panic!("wait for {label}: {error}")),
        Err(_) => {
            child
                .start_kill()
                .unwrap_or_else(|error| panic!("kill timed-out {label}: {error}"));
            let _ = bounded_reap_fixture_child(
                &mut child,
                label,
                Instant::now() + R9A3_WITNESS_REAP_TIMEOUT,
            )
            .await;
            panic!("{label} exceeded hard timeout");
        }
    };
    let stdout = stdout_reader
        .await
        .unwrap_or_else(|error| panic!("join {label} stdout reader: {error}"))
        .unwrap_or_else(|error| panic!("read {label} stdout: {error}"));
    let stderr = stderr_reader
        .await
        .unwrap_or_else(|error| panic!("join {label} stderr reader: {error}"))
        .unwrap_or_else(|error| panic!("read {label} stderr: {error}"));
    std::process::Output {
        status,
        stdout,
        stderr,
    }
}

async fn run_m12_cli(instance: &str, arguments: &[&str]) -> std::process::Output {
    run_bounded_fixture_command(cli_executable(), instance, arguments, "M-12 CLI subprocess").await
}

async fn run_m12_tui(instance: &str, arguments: &[&str]) -> std::process::Output {
    run_bounded_fixture_command(tui_executable(), instance, arguments, "M-12 TUI subprocess").await
}

async fn wait_for_m12_daemon(instance: &str, child: &mut Child, label: &str) {
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        let output = run_m12_cli(instance, &["status", "--json"]).await;
        if output.status.success() {
            return;
        }
        let failure = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect {label} during startup: {error}"))
        {
            panic!("{label} exited before IPC became ready: {status}; {failure}");
        }
        assert!(
            Instant::now() < deadline,
            "{label} IPC did not become ready before deadline: {failure}"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_cli_status(instance: &str) -> std::process::Output {
    let mut last_failure = String::new();
    for _ in 0..80 {
        let output = run_cli(instance, &["status", "--json"]).await;
        if output.status.success() {
            return output;
        }
        last_failure = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        sleep(Duration::from_millis(50)).await;
    }
    panic!("CLI should attach to the real fixture daemon: {last_failure}");
}

async fn wait_for_cli_status_with_child(instance: &str, child: &mut Child) -> std::process::Output {
    let mut last_failure = String::new();
    for _ in 0..80 {
        let output = run_cli(instance, &["status", "--json"]).await;
        if output.status.success() {
            return output;
        }
        last_failure = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Ok(Some(status)) = child.try_wait() {
            panic!("fixture daemon exited before IPC became ready: {status}");
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("CLI should attach to the real fixture daemon: {last_failure}");
}

async fn wait_for_r8b2c_checkpoint(
    root: &Path,
    instance: &str,
    dispatch_id: &str,
    phase: &str,
    child: &mut Child,
) -> R8b2cCheckpoint {
    let path = r8b2c_checkpoint_path(root, phase);
    for _ in 0..200 {
        if let Ok(payload) = fs::read(&path)
            && let Ok(checkpoint) = serde_json::from_slice::<R8b2cCheckpoint>(&payload)
        {
            assert_eq!(
                checkpoint.process_id,
                child.id().expect("R-8B.2c child PID")
            );
            assert_eq!(checkpoint.fixture_root, root.display().to_string());
            assert_eq!(checkpoint.fixture_instance, instance);
            assert_eq!(checkpoint.dispatch_id, dispatch_id);
            assert_eq!(checkpoint.phase, phase);
            return checkpoint;
        }
        if let Some(status) = child
            .try_wait()
            .expect("inspect R-8B.2c child while waiting for checkpoint")
        {
            panic!("R-8B.2c child exited before {phase} checkpoint: {status}");
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("R-8B.2c checkpoint {phase} was not published");
}

async fn hard_kill_r8b2c_child(child: &mut Child, phase: &str) {
    assert!(
        child
            .try_wait()
            .expect("inspect R-8B.2c child before hard kill")
            .is_none(),
        "R-8B.2c child must still be alive at {phase} checkpoint"
    );
    child.kill().await.expect("hard-kill R-8B.2c child");
    let status = child
        .wait()
        .await
        .expect("wait for hard-killed R-8B.2c child");
    assert!(
        !status.success(),
        "R-8B.2c child killed at {phase} must not report success: {status}"
    );
}

async fn run_r9a3d_cli(instance: &str, arguments: &[&str]) -> std::process::Output {
    run_bounded_fixture_command(
        cli_executable(),
        instance,
        arguments,
        "R-9A.3d CLI subprocess",
    )
    .await
}

async fn run_r9a3d_tui(instance: &str, arguments: &[&str]) -> std::process::Output {
    run_bounded_fixture_command(
        tui_executable(),
        instance,
        arguments,
        "R-9A.3d TUI subprocess",
    )
    .await
}

async fn wait_for_r9a3d_daemon(instance: &str, child: &mut Child) {
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        let output = run_r9a3d_cli(instance, &["status", "--json"]).await;
        if output.status.success() {
            return;
        }
        let last = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(status) = child
            .try_wait()
            .expect("inspect R-9A.3d daemon while waiting for IPC")
        {
            panic!("R-9A.3d daemon exited before IPC readiness: {status}; {last}");
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3d daemon did not become ready before deadline: {last}"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_r9a3d_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    witness: &mut R9a3WitnessProcess,
    daemon: &mut Child,
    label: &str,
) -> T {
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        if let Ok(payload) = fs::read(path)
            && let Ok(value) = serde_json::from_slice(&payload)
        {
            return value;
        }
        if let Some(status) = witness
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect R-9A.3d witness for {label}: {error}"))
        {
            panic!("R-9A.3d witness exited before {label}: {status}");
        }
        if let Some(status) = daemon
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect R-9A.3d daemon for {label}: {error}"))
        {
            panic!("R-9A.3d daemon exited before {label}: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3d {label} was not durable before deadline"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn bounded_reap_fixture_child(
    child: &mut Child,
    label: &str,
    deadline: Instant,
) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect {label} while reaping: {error}"))
        {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "{label} was not reaped before deadline"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn hard_kill_r9a3d_child(child: &mut Child, phase: &str) -> std::process::ExitStatus {
    assert!(
        child
            .try_wait()
            .expect("inspect R-9A.3d daemon before hard kill")
            .is_none(),
        "R-9A.3d daemon must remain alive at {phase}"
    );
    child
        .start_kill()
        .unwrap_or_else(|error| panic!("hard-kill R-9A.3d daemon at {phase}: {error}"));
    let status = bounded_reap_fixture_child(
        child,
        "R-9A.3d daemon",
        Instant::now() + R9A3_WITNESS_REAP_TIMEOUT,
    )
    .await;
    assert!(
        !status.success(),
        "hard-killed R-9A.3d daemon at {phase} must not report success: {status}"
    );
    status
}

async fn shutdown_fixture_child(child: &mut Child, label: &str) -> std::process::ExitStatus {
    drop(child.stdin.take());
    let graceful_deadline = Instant::now() + R9A3D_IO_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect {label} during graceful shutdown: {error}"))
        {
            assert!(
                status.success(),
                "{label} graceful shutdown failed: {status}"
            );
            return status;
        }
        if Instant::now() >= graceful_deadline {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    child
        .start_kill()
        .unwrap_or_else(|error| panic!("kill {label} after graceful shutdown deadline: {error}"));
    let status =
        bounded_reap_fixture_child(child, label, Instant::now() + R9A3_WITNESS_REAP_TIMEOUT).await;
    assert!(
        !status.success(),
        "{label} killed after graceful shutdown timeout must not report success: {status}"
    );
    status
}

async fn wait_for_r9a3d_task(
    instance: &str,
    task_id: &str,
    expected: TaskStatus,
    child: &mut Child,
) -> serde_json::Value {
    let deadline = Instant::now() + R9A3D_PHASE_TIMEOUT;
    loop {
        let output = run_r9a3d_cli(instance, &["task", "get", task_id, "--json"]).await;
        let last = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success()
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            && value["data"]["status"] == expected.as_str_name()
        {
            return value;
        }
        if let Some(status) = child
            .try_wait()
            .expect("inspect R-9A.3d daemon while waiting for Task")
        {
            panic!("R-9A.3d daemon exited before Task {expected:?}: {status}; {last}");
        }
        assert!(
            Instant::now() < deadline,
            "R-9A.3d Task did not reach {expected:?} before deadline: {last}"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

struct R8b2cPreparedWork {
    task_id: String,
    snapshot_id: String,
}

async fn prepare_and_confirm_r8b2c_work(
    root: &Path,
    instance: &str,
    label: &str,
) -> R8b2cPreparedWork {
    fs::write(
        root.join("context.md"),
        format!("R-8B.2c governed crash-window context for {label}."),
    )
    .expect("write R-8B.2c context source");
    let prepare_key = format!("{label}-prepare");
    let prepare = run_cli(
        instance,
        &[
            "work",
            "prepare",
            "--intent",
            "exercise a governed R-8B.2c crash recovery window",
            "--scope",
            "scope:r8a",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            &prepare_key,
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-8B.2c prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepared: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("decode R-8B.2c prepare response");
    let snapshot_id = prepared["data"]["snapshotId"]
        .as_str()
        .expect("R-8B.2c snapshot id")
        .to_owned();
    let confirmation_binding = prepared["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-8B.2c confirmation binding")
        .to_owned();
    let confirm_key = format!("{label}-confirm");
    let confirm = run_tui(
        instance,
        &[
            "--instance",
            instance,
            "work-confirm",
            &snapshot_id,
            "--confirmation-binding-sha256",
            &confirmation_binding,
            "--idempotency-key",
            &confirm_key,
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-8B.2c confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirmed: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("decode R-8B.2c confirm response");
    assert_eq!(
        confirmed["data"]["status"],
        TaskStatus::Active.as_str_name()
    );
    let task_id = confirmed["data"]["taskId"]
        .as_str()
        .expect("R-8B.2c Task id")
        .to_owned();
    R8b2cPreparedWork {
        task_id,
        snapshot_id,
    }
}

async fn wait_for_r8b2c_task_status(
    instance: &str,
    task_id: &str,
    expected: TaskStatus,
    child: &mut Child,
) -> serde_json::Value {
    let mut last = String::new();
    for _ in 0..120 {
        let output = run_cli(instance, &["task", "get", task_id, "--json"]).await;
        last = format!(
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success()
            && let Ok(view) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            && view["data"]["status"] == expected.as_str_name()
        {
            assert_eq!(view["data"]["taskId"], task_id);
            return view;
        }
        if let Some(status) = child
            .try_wait()
            .expect("inspect R-8B.2c child while waiting for Task")
        {
            panic!("R-8B.2c child exited while waiting for Task {expected:?}: {status}");
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("R-8B.2c Task did not reach {expected:?}: {last}");
}

#[derive(Clone, Debug, PartialEq)]
struct R8b2cCollaborationOracle {
    run: RunSnapshot,
    step: StepSnapshot,
    attempt: AttemptSnapshot,
    outbox_state: String,
    envelope: DispatchEnvelope,
    event_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct R8b2cTaskOracle {
    snapshot: TaskSnapshot,
    event_count: u64,
}

fn read_r8b2c_collaboration_oracle(root: &Path) -> R8b2cCollaborationOracle {
    let stored = read_r8b2c_collaboration_store(
        &root.join("r8a-collaboration.db"),
        &[0x31; 32],
        R8A_ACTIVATION_RUN_ID,
        "r8a-step",
        "r8a-attempt",
    )
    .expect("read R-8B.2c Collaboration store through conformance boundary");
    let run =
        RunSnapshot::decode(stored.run_snapshot.as_slice()).expect("decode R-8B.2c run snapshot");
    assert_eq!(run.revision, stored.run_revision);
    assert_eq!(run.status, stored.run_status);
    let step = StepSnapshot::decode(stored.step_snapshot.as_slice())
        .expect("decode R-8B.2c step snapshot");
    assert_eq!(step.revision, stored.step_revision);
    assert_eq!(step.status, stored.step_status);
    let attempt = AttemptSnapshot::decode(stored.attempt_snapshot.as_slice())
        .expect("decode R-8B.2c attempt snapshot");
    assert_eq!(attempt.revision, stored.attempt_revision);
    assert_eq!(attempt.status, stored.attempt_status);
    let envelope =
        DispatchEnvelope::decode(stored.envelope.as_slice()).expect("decode R-8B.2c envelope");
    assert_eq!(envelope.run_id, R8A_ACTIVATION_RUN_ID);
    assert_eq!(envelope.step_id, "r8a-step");
    assert_eq!(envelope.attempt_id, "r8a-attempt");
    assert_eq!(envelope.dispatch_id, "r8a-dispatch");
    R8b2cCollaborationOracle {
        run,
        step,
        attempt,
        outbox_state: stored.outbox_state,
        envelope,
        event_count: stored.event_count,
    }
}

fn read_r8b2c_task_oracle(root: &Path, task_id: &str) -> R8b2cTaskOracle {
    let stored = read_r8b2c_task_store(&root.join("task-authority.db"), &[0x11; 32], task_id)
        .expect("read R-8B.2c Task store through conformance boundary");
    let snapshot =
        TaskSnapshot::decode(stored.snapshot.as_slice()).expect("decode R-8B.2c Task snapshot");
    assert_eq!(snapshot.task_id, task_id);
    assert_eq!(snapshot.revision, stored.revision);
    assert_eq!(snapshot.status, stored.status);
    R8b2cTaskOracle {
        snapshot,
        event_count: stored.event_count,
    }
}

fn read_empty_r9a3_verdict_oracle(root: &Path) -> R9a3VerdictAuthorityCounts {
    let counts = read_r9a3_verdict_authority_counts(
        &root.join("verdict-authority.db"),
        &[0x13; 32],
        "c5-00-verdict-epoch",
    )
    .expect("read R-9A Verdict Authority through conformance boundary");
    assert_eq!(counts.last_event_sequence, 0);
    assert_eq!(counts.verdict_count, 0);
    assert_eq!(counts.state_count, 0);
    assert_eq!(counts.event_count, 0);
    assert_eq!(counts.idempotency_count, 0);
    assert_eq!(counts.outbox_count, 0);
    assert_eq!(counts.consumption_receipt_count, 0);
    assert_eq!(counts.commit_receipt_count, 0);
    assert_eq!(counts.projection_outbox_count, 0);
    counts
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct R8b2cAdapterObservationOracle {
    observation_id: String,
    dispatch_id: String,
    native_key: String,
    native_event_digest_sha256: String,
    raw_evidence_ref: String,
    ingestion_state: String,
    observation: HarnessObservation,
    raw_event: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct R8b2cAdapterOracle {
    dispatch_count: u64,
    delivery_unknown_count: u64,
    observation_count: u64,
    pending_observation_count: u64,
    dispatch_state: String,
    dispatch_attempt_id: String,
    dispatch_fencing_token: u64,
    dispatch_fingerprint: String,
    envelope_digest_sha256: String,
    envelope: DispatchEnvelope,
    envelope_bytes: Vec<u8>,
    receipt: Option<egopulse_domain_contracts::v01::egopulse::harness::v1::DispatchReceipt>,
    receipt_bytes: Option<Vec<u8>>,
    observations: Vec<R8b2cAdapterObservationOracle>,
}

fn read_r8b2c_adapter_oracle(root: &Path) -> R8b2cAdapterOracle {
    let stored =
        read_r8b2c_adapter_store(&root.join("r8a-adapter.db"), &[0x32; 32], "r8a-dispatch")
            .expect("read R-8B.2c Adapter store through conformance boundary");
    let envelope_bytes = stored.envelope.clone();
    let envelope = DispatchEnvelope::decode(envelope_bytes.as_slice())
        .expect("decode R-8B.2c Adapter dispatch envelope");
    assert_eq!(envelope.attempt_id, stored.attempt_id);
    assert_eq!(envelope.fencing_token, stored.fencing_token);
    assert_eq!(envelope.dispatch_fingerprint, stored.dispatch_fingerprint);
    assert_eq!(
        stored.envelope_digest_sha256,
        format!("{:x}", Sha256::digest(envelope_bytes.as_slice()))
    );
    let receipt_bytes = stored.receipt.clone();
    let receipt = receipt_bytes.as_deref().map(|bytes| {
        egopulse_domain_contracts::v01::egopulse::harness::v1::DispatchReceipt::decode(bytes)
            .expect("decode R-8B.2c Adapter receipt")
    });
    if let (Some(receipt), Some(receipt_bytes)) = (receipt.as_ref(), receipt_bytes.as_ref()) {
        assert_eq!(receipt.encode_to_vec().as_slice(), receipt_bytes.as_slice());
    }
    let observations = stored
        .observations
        .into_iter()
        .map(|row| {
            let observation = HarnessObservation::decode(row.observation.as_slice())
                .expect("decode R-8B.2c Adapter observation");
            assert_eq!(row.dispatch_id, observation.dispatch_id);
            assert_eq!(row.observation_id, observation.observation_id);
            assert_eq!(row.raw_evidence_ref, observation.raw_evidence_ref);
            assert_eq!(
                row.native_event_digest_sha256,
                observation.native_event_digest_sha256
            );
            assert_eq!(
                row.native_event_digest_sha256,
                format!("{:x}", Sha256::digest(row.raw_event.as_slice()))
            );
            assert!(matches!(
                row.ingestion_state.as_str(),
                "pending" | "consumed"
            ));
            R8b2cAdapterObservationOracle {
                observation_id: row.observation_id,
                dispatch_id: row.dispatch_id,
                native_key: row.native_key,
                native_event_digest_sha256: row.native_event_digest_sha256,
                raw_evidence_ref: row.raw_evidence_ref,
                ingestion_state: row.ingestion_state,
                observation,
                raw_event: row.raw_event,
            }
        })
        .collect();
    R8b2cAdapterOracle {
        dispatch_count: stored.dispatch_count,
        delivery_unknown_count: stored.delivery_unknown_count,
        observation_count: stored.observation_count,
        pending_observation_count: stored.pending_observation_count,
        dispatch_state: stored.dispatch_state,
        dispatch_attempt_id: stored.attempt_id,
        dispatch_fencing_token: stored.fencing_token,
        dispatch_fingerprint: stored.dispatch_fingerprint,
        envelope_digest_sha256: stored.envelope_digest_sha256,
        envelope,
        envelope_bytes,
        receipt,
        receipt_bytes,
        observations,
    }
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
async fn r9a2c_noninteractive_cli_requires_digest_before_daemon_attach() {
    let absent_instance = format!("r9a2c-absent-{}", Uuid::now_v7());
    let shared_arguments = [
        "ctx:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--expected-state-revision",
        "1",
        "--reason-code",
        "withdrawn",
        "--evidence-ref",
        "evidence:one",
        "--confirmation-proof-ref",
        "proof:one",
        "--idempotency-key",
        "idem:one",
        "--json",
    ];
    let mut cli_arguments = vec!["context", "revoke"];
    cli_arguments.extend(shared_arguments);
    let cli = run_cli(&absent_instance, &cli_arguments).await;
    assert_eq!(cli.status.code(), Some(2));
    let cli_json: serde_json::Value =
        serde_json::from_slice(&cli.stdout).expect("CLI pre-attach confirmation error JSON");
    assert_eq!(cli_json["error"]["code"], "CONTEXT_CONFIRMATION_REQUIRED");
    assert_eq!(
        cli_json["error"]["requiredActionCode"],
        "SUPPLY_EXACT_CONTEXT_DIGEST"
    );
    assert!(!String::from_utf8_lossy(&cli.stdout).contains("DAEMON_UNAVAILABLE"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9a2c_real_cli_digest_confirmed_context_revoke_over_local_ipc() {
    let root = std::env::temp_dir().join(format!("egopulse-r9a2c-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R9A.2c fixture root");
    let instance = format!("r9a2c-{}", Uuid::now_v7());
    let mut child = spawn_fixture(&root, &instance).await;
    wait_for_cli_status(&instance).await;

    let cli_snapshot = r9a2c_snapshot_id(R9A2C_CLI_CONTEXT_BYTES);
    let cli_preview = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            cli_snapshot.as_str(),
            "--expected-state-revision",
            "1",
            "--reason-code",
            "r9a2c-reason-sentinel",
            "--evidence-ref",
            "evidence:r9a2c-private-sentinel",
            "--confirmation-proof-ref",
            "proof:r9a2c-private-sentinel",
            "--idempotency-key",
            "r9a2c-cli-revoke",
            "--preview",
            "--json",
        ],
    )
    .await;
    assert!(
        cli_preview.status.success(),
        "CLI Context preview stdout={} stderr={}",
        String::from_utf8_lossy(&cli_preview.stdout),
        String::from_utf8_lossy(&cli_preview.stderr)
    );
    let cli_preview_json: serde_json::Value =
        serde_json::from_slice(&cli_preview.stdout).expect("CLI Context preview JSON");
    assert_eq!(cli_preview_json["operation"], "context.revoke.preview");
    assert_eq!(cli_preview_json["data"]["mutationSent"], false);
    let cli_digest = cli_preview_json["data"]["requestDigestSha256"]
        .as_str()
        .expect("CLI Context full digest")
        .to_owned();
    assert_eq!(cli_digest.len(), 64);
    assert!(
        cli_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let cli_revoke = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            cli_snapshot.as_str(),
            "--expected-state-revision",
            "1",
            "--reason-code",
            "r9a2c-reason-sentinel",
            "--evidence-ref",
            "evidence:r9a2c-private-sentinel",
            "--confirmation-proof-ref",
            "proof:r9a2c-private-sentinel",
            "--idempotency-key",
            "r9a2c-cli-revoke",
            "--confirm-digest",
            cli_digest.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        cli_revoke.status.success(),
        "CLI Context revoke stdout={} stderr={}",
        String::from_utf8_lossy(&cli_revoke.stdout),
        String::from_utf8_lossy(&cli_revoke.stderr)
    );
    let cli_json: serde_json::Value =
        serde_json::from_slice(&cli_revoke.stdout).expect("CLI Context receipt JSON");
    assert_eq!(cli_json["operation"], "context.revoke");
    assert_eq!(cli_json["data"]["previousStateRevision"], 1);
    assert_eq!(cli_json["data"]["resultStateRevision"], 2);
    assert_eq!(
        cli_json["data"]["resultState"],
        "CONTEXT_GOVERNANCE_STATE_REVOKED"
    );
    assert_eq!(cli_json["data"]["requestDigestSha256"], cli_digest);
    assert_eq!(cli_json["data"]["acknowledgedAfterDurabilityBarrier"], true);
    assert_eq!(cli_json["data"]["replayed"], false);

    let cli_replay = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            cli_snapshot.as_str(),
            "--expected-state-revision",
            "1",
            "--reason-code",
            "r9a2c-reason-sentinel",
            "--evidence-ref",
            "evidence:r9a2c-private-sentinel",
            "--confirmation-proof-ref",
            "proof:r9a2c-private-sentinel",
            "--idempotency-key",
            "r9a2c-cli-revoke",
            "--confirm-digest",
            cli_digest.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(cli_replay.status.success());
    let cli_replay_json: serde_json::Value =
        serde_json::from_slice(&cli_replay.stdout).expect("CLI Context replay JSON");
    let mut expected_replay_data = cli_json["data"].clone();
    expected_replay_data["replayed"] = serde_json::Value::Bool(true);
    assert_eq!(cli_replay_json["data"], expected_replay_data);

    let all_cli_output = format!(
        "{}{}{}{}{}{}",
        String::from_utf8_lossy(&cli_preview.stdout),
        String::from_utf8_lossy(&cli_preview.stderr),
        String::from_utf8_lossy(&cli_revoke.stdout),
        String::from_utf8_lossy(&cli_revoke.stderr),
        String::from_utf8_lossy(&cli_replay.stdout),
        String::from_utf8_lossy(&cli_replay.stderr),
    );
    for forbidden in [
        "r9a2c-context-bytes-sentinel",
        "r9a2c-reason-sentinel",
        "evidence:r9a2c-private-sentinel",
        "proof:r9a2c-private-sentinel",
        "os-user:c5-fixture",
    ] {
        assert!(
            !all_cli_output.contains(forbidden),
            "sanitized Context output leaked {forbidden}"
        );
    }

    drop(child.stdin.take());
    let status = child.wait().await.expect("R9A.2c fixture child exit");
    assert!(status.success(), "R9A.2c fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove R9A.2c fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m10_real_cli_and_tui_share_governed_memory_retrieval_over_local_ipc() {
    let root = std::env::temp_dir().join(format!("egopulse-m10-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create M-10 fixture root");
    let instance = format!("m10-{}", Uuid::now_v7());
    let mut child = spawn_fixture(&root, &instance).await;
    wait_for_cli_status(&instance).await;

    let cli = run_cli(
        &instance,
        &[
            "memory",
            "retrieve",
            "--query",
            "governed Founder Memory",
            "--scope",
            "scope:founder",
            "--max-results",
            "4",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    assert!(
        cli.status.success(),
        "Memory CLI stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_json: serde_json::Value =
        serde_json::from_slice(&cli.stdout).expect("Memory CLI JSON envelope");
    assert_eq!(cli_json["operation"], "memory.retrieve");
    assert_eq!(cli_json["data"]["scopeRef"], "scope:founder");
    assert_eq!(cli_json["data"]["resultCount"], 1);
    assert_eq!(
        cli_json["data"]["candidates"][0]["memoryId"],
        "memory-c5-accepted"
    );
    assert!(cli_json["data"]["candidates"][0].get("content").is_none());

    let tui = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-retrieve",
            "--query",
            "governed Founder Memory",
            "--scope",
            "scope:founder",
            "--max-results",
            "4",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    assert!(
        tui.status.success(),
        "Memory TUI stdout={} stderr={}",
        String::from_utf8_lossy(&tui.stdout),
        String::from_utf8_lossy(&tui.stderr)
    );
    let tui_json: serde_json::Value =
        serde_json::from_slice(&tui.stdout).expect("Memory TUI JSON envelope");
    assert_eq!(tui_json["operation"], "memory.retrieve");
    assert_eq!(
        tui_json["data"]["snapshotSha256"],
        cli_json["data"]["snapshotSha256"]
    );
    assert_eq!(
        tui_json["data"]["candidates"],
        cli_json["data"]["candidates"]
    );

    drop(child.stdin.take());
    let status = child.wait().await.expect("M-10 fixture child exit");
    assert!(status.success(), "M-10 fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove M-10 fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m11_real_cli_and_tui_share_governed_memory_mutations_over_local_ipc() {
    let root = std::env::temp_dir().join(format!("egopulse-m11-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create M-11 fixture root");
    let instance = format!("m11-{}", Uuid::now_v7());
    let mut child = spawn_fixture(&root, &instance).await;
    wait_for_cli_status(&instance).await;

    let candidate = run_cli(
        &instance,
        &[
            "memory",
            "candidate",
            "--memory-id",
            "memory-m11-cross-ipc",
            "--content",
            "m11 unique governed mutation sentinel",
            "--source-ref",
            "source:m11-cross-ipc",
            "--scope",
            "scope:founder",
            "--idempotency-key",
            "m11-candidate",
            "--json",
        ],
    )
    .await;
    assert!(
        candidate.status.success(),
        "Memory candidate CLI stdout={} stderr={}",
        String::from_utf8_lossy(&candidate.stdout),
        String::from_utf8_lossy(&candidate.stderr)
    );
    let candidate_json: serde_json::Value =
        serde_json::from_slice(&candidate.stdout).expect("M-11 candidate JSON envelope");
    assert_eq!(candidate_json["operation"], "memory.candidate");
    assert_eq!(candidate_json["data"]["memoryId"], "memory-m11-cross-ipc");
    assert_eq!(candidate_json["data"]["revision"], 1);
    assert_eq!(candidate_json["data"]["state"], "candidate");

    let accepted = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-accept",
            "memory-m11-cross-ipc",
            "--expected-revision",
            "1",
            "--evidence-ref",
            "evidence:m11-founder-acceptance",
            "--idempotency-key",
            "m11-accept",
            "--json",
        ],
    )
    .await;
    assert!(
        accepted.status.success(),
        "Memory accept TUI stdout={} stderr={}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted_json: serde_json::Value =
        serde_json::from_slice(&accepted.stdout).expect("M-11 accept JSON envelope");
    assert_eq!(accepted_json["operation"], "memory.accept");
    assert_eq!(accepted_json["data"]["revision"], 2);
    assert_eq!(accepted_json["data"]["state"], "accepted");

    let retrieved = run_cli(
        &instance,
        &[
            "memory",
            "retrieve",
            "--query",
            "m11 unique governed mutation sentinel",
            "--scope",
            "scope:founder",
            "--max-results",
            "4",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    assert!(
        retrieved.status.success(),
        "Memory retrieve CLI stdout={} stderr={}",
        String::from_utf8_lossy(&retrieved.stdout),
        String::from_utf8_lossy(&retrieved.stderr)
    );
    let retrieved_json: serde_json::Value =
        serde_json::from_slice(&retrieved.stdout).expect("M-11 retrieve JSON envelope");
    let retrieved_candidates = retrieved_json["data"]["candidates"]
        .as_array()
        .expect("M-11 retrieve candidates");
    let retrieved_target = retrieved_candidates
        .iter()
        .find(|candidate| candidate["memoryId"] == "memory-m11-cross-ipc")
        .expect("M-11 accepted memory must be retrievable");
    assert!(retrieved_target.get("content").is_none());

    let revoked = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-revoke",
            "memory-m11-cross-ipc",
            "--expected-revision",
            "2",
            "--evidence-ref",
            "evidence:m11-founder-revocation",
            "--idempotency-key",
            "m11-revoke",
            "--json",
        ],
    )
    .await;
    assert!(
        revoked.status.success(),
        "Memory revoke TUI stdout={} stderr={}",
        String::from_utf8_lossy(&revoked.stdout),
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoked_json: serde_json::Value =
        serde_json::from_slice(&revoked.stdout).expect("M-11 revoke JSON envelope");
    assert_eq!(revoked_json["operation"], "memory.revoke");
    assert_eq!(revoked_json["data"]["revision"], 3);
    assert_eq!(revoked_json["data"]["state"], "revoked");

    let after_revoke = run_cli(
        &instance,
        &[
            "memory",
            "retrieve",
            "--query",
            "m11 unique governed mutation sentinel",
            "--scope",
            "scope:founder",
            "--max-results",
            "4",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    assert!(
        after_revoke.status.success(),
        "Memory post-revoke retrieve CLI stdout={} stderr={}",
        String::from_utf8_lossy(&after_revoke.stdout),
        String::from_utf8_lossy(&after_revoke.stderr)
    );
    let after_revoke_json: serde_json::Value =
        serde_json::from_slice(&after_revoke.stdout).expect("M-11 post-revoke JSON envelope");
    let post_revoke_candidates = after_revoke_json["data"]["candidates"]
        .as_array()
        .expect("M-11 post-revoke candidates");
    assert!(
        !post_revoke_candidates
            .iter()
            .any(|candidate| candidate["memoryId"] == "memory-m11-cross-ipc")
    );

    drop(child.stdin.take());
    let status = child.wait().await.expect("M-11 fixture child exit");
    assert!(status.success(), "M-11 fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove M-11 fixture root");
}

fn m12_memory_json(output: &std::process::Output, label: &str) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{label} stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("decode {label} JSON envelope: {error}"))
}

struct M12RootGuard(Option<PathBuf>);

impl M12RootGuard {
    fn new(path: PathBuf) -> Self {
        fs::create_dir_all(&path).expect("create M-12 fixture root");
        Self(Some(path))
    }

    fn path(&self) -> &Path {
        self.0.as_deref().expect("M-12 root remains available")
    }

    fn remove(mut self) {
        let path = self.0.take().expect("M-12 root remains available");
        fs::remove_dir_all(path).expect("remove M-12 fixture root");
    }
}

impl Drop for M12RootGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct M12DaemonGuard {
    child: Child,
    label: &'static str,
}

impl M12DaemonGuard {
    fn new(child: Child, label: &'static str) -> Self {
        Self { child, label }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for M12DaemonGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = self.child.start_kill();
        let deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            if Instant::now() >= deadline {
                eprintln!("{} could not be reaped during panic cleanup", self.label);
                return;
            }
            thread::sleep(R9A3_WITNESS_REAP_POLL_INTERVAL);
        }
    }
}

fn assert_m12_retrieval(
    output: &std::process::Output,
    label: &str,
    kept_memory_id: &str,
    revoked_memory_id: &str,
    kept_content: &str,
    revoked_content: &str,
) -> serde_json::Value {
    let value = m12_memory_json(output, label);
    assert_eq!(value["operation"], "memory.retrieve");
    let evidence_ref = value["data"]["evidenceRef"]
        .as_str()
        .unwrap_or_else(|| panic!("{label} evidence reference"));
    assert!(
        evidence_ref.starts_with("memory-rag-evidence-sha256:"),
        "{label} must retain governed retrieval evidence"
    );
    let snapshot_sha256 = value["data"]["snapshotSha256"]
        .as_str()
        .unwrap_or_else(|| panic!("{label} snapshot digest"));
    assert!(
        snapshot_sha256.len() == 64
            && snapshot_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} snapshot digest must be lowercase SHA-256"
    );
    let candidates = value["data"]["candidates"]
        .as_array()
        .unwrap_or_else(|| panic!("{label} candidates"));
    let kept = candidates
        .iter()
        .find(|candidate| candidate["memoryId"] == kept_memory_id)
        .unwrap_or_else(|| panic!("{label} must include kept Memory"));
    assert!(
        kept.get("content").is_none(),
        "{label} leaked Memory content"
    );
    assert!(
        !candidates
            .iter()
            .any(|candidate| candidate["memoryId"] == revoked_memory_id),
        "{label} exposed revoked Memory"
    );
    let serialized = serde_json::to_string(&value).expect("serialize M-12 retrieval response");
    assert!(!serialized.contains(kept_content));
    assert!(!serialized.contains(revoked_content));
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m12_memory_survives_daemon_restart_with_revocation_replay_and_read_only_retrieval() {
    const SCOPE: &str = "scope:founder";
    const KEPT_ID: &str = "memory-m12-kept";
    const REVOKED_ID: &str = "memory-m12-revoked";
    const KEPT_CONTENT: &str = "m12 durable kept memory sentinel";
    const REVOKED_CONTENT: &str = "m12 durable revoked memory sentinel";

    let root =
        M12RootGuard::new(std::env::temp_dir().join(format!("egopulse-m12-{}", Uuid::now_v7())));
    let instance = format!("m12-{}", Uuid::now_v7());
    let mut daemon_one = M12DaemonGuard::new(
        spawn_fixture(root.path(), &instance).await,
        "M-12 D1 daemon",
    );
    let daemon_one_pid = daemon_one.child.id().expect("M-12 D1 PID");
    assert_ne!(daemon_one_pid, std::process::id());
    wait_for_m12_daemon(&instance, daemon_one.child_mut(), "M-12 D1 daemon").await;

    let kept_candidate = run_m12_cli(
        &instance,
        &[
            "memory",
            "candidate",
            "--memory-id",
            KEPT_ID,
            "--content",
            KEPT_CONTENT,
            "--source-ref",
            "source:m12-kept",
            "--scope",
            SCOPE,
            "--idempotency-key",
            "m12-kept-candidate",
            "--json",
        ],
    )
    .await;
    let kept_candidate_json = m12_memory_json(&kept_candidate, "M-12 kept candidate");
    assert_eq!(kept_candidate_json["data"]["memoryId"], KEPT_ID);
    assert_eq!(kept_candidate_json["data"]["revision"], 1);
    assert_eq!(kept_candidate_json["data"]["state"], "candidate");

    let kept_accept = run_m12_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-accept",
            KEPT_ID,
            "--expected-revision",
            "1",
            "--evidence-ref",
            "evidence:m12-kept-acceptance",
            "--idempotency-key",
            "m12-kept-accept",
            "--json",
        ],
    )
    .await;
    let kept_accept_json = m12_memory_json(&kept_accept, "M-12 kept acceptance");
    assert_eq!(kept_accept_json["data"]["revision"], 2);
    assert_eq!(kept_accept_json["data"]["state"], "accepted");
    assert_eq!(
        kept_accept_json["data"]["acknowledgedAfterDurabilityBarrier"],
        true
    );

    let revoked_candidate = run_m12_cli(
        &instance,
        &[
            "memory",
            "candidate",
            "--memory-id",
            REVOKED_ID,
            "--content",
            REVOKED_CONTENT,
            "--source-ref",
            "source:m12-revoked",
            "--scope",
            SCOPE,
            "--idempotency-key",
            "m12-revoked-candidate",
            "--json",
        ],
    )
    .await;
    let revoked_candidate_json = m12_memory_json(&revoked_candidate, "M-12 revoked candidate");
    assert_eq!(revoked_candidate_json["data"]["memoryId"], REVOKED_ID);
    assert_eq!(revoked_candidate_json["data"]["revision"], 1);

    let revoked_accept = run_m12_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-accept",
            REVOKED_ID,
            "--expected-revision",
            "1",
            "--evidence-ref",
            "evidence:m12-revoked-acceptance",
            "--idempotency-key",
            "m12-revoked-accept",
            "--json",
        ],
    )
    .await;
    let revoked_accept_json = m12_memory_json(&revoked_accept, "M-12 revoked acceptance");
    assert_eq!(revoked_accept_json["data"]["revision"], 2);
    assert_eq!(revoked_accept_json["data"]["state"], "accepted");

    let revoked = run_m12_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-revoke",
            REVOKED_ID,
            "--expected-revision",
            "2",
            "--evidence-ref",
            "evidence:m12-revocation",
            "--idempotency-key",
            "m12-revoke",
            "--json",
        ],
    )
    .await;
    let revoked_json = m12_memory_json(&revoked, "M-12 revocation");
    assert_eq!(revoked_json["data"]["revision"], 3);
    assert_eq!(revoked_json["data"]["state"], "revoked");
    assert_eq!(
        revoked_json["data"]["acknowledgedAfterDurabilityBarrier"],
        true
    );

    let mut memory_oracle = MemoryRestartOracle::open_existing(
        &root.path().join("memory-authority.db"),
        &[0x14; 32],
        "c5-memory-epoch",
    )
    .expect("open M-12 Memory conformance oracle");
    let before_d1_retrieval = memory_oracle
        .snapshot(KEPT_ID, REVOKED_ID)
        .expect("read M-12 D1 durable snapshot");
    assert_eq!(before_d1_retrieval.kept.memory_id, KEPT_ID);
    assert_eq!(before_d1_retrieval.kept.revision, 2);
    assert_eq!(before_d1_retrieval.kept.content, KEPT_CONTENT);
    assert_eq!(
        before_d1_retrieval.kept.content_sha256,
        hex::encode(Sha256::digest(KEPT_CONTENT.as_bytes()))
    );
    assert_eq!(before_d1_retrieval.kept.source_ref, "source:m12-kept");
    assert_eq!(before_d1_retrieval.kept.scope_ref, SCOPE);
    assert_eq!(before_d1_retrieval.kept.state, "accepted");
    assert_eq!(before_d1_retrieval.revoked.memory_id, REVOKED_ID);
    assert_eq!(before_d1_retrieval.revoked.revision, 3);
    assert_eq!(before_d1_retrieval.revoked.content, REVOKED_CONTENT);
    assert_eq!(
        before_d1_retrieval.revoked.content_sha256,
        hex::encode(Sha256::digest(REVOKED_CONTENT.as_bytes()))
    );
    assert_eq!(before_d1_retrieval.revoked.source_ref, "source:m12-revoked");
    assert_eq!(before_d1_retrieval.revoked.scope_ref, SCOPE);
    assert_eq!(before_d1_retrieval.revoked.state, "revoked");

    let d1_retrieval = run_m12_cli(
        &instance,
        &[
            "memory",
            "retrieve",
            "--query",
            "m12 durable memory sentinel",
            "--scope",
            SCOPE,
            "--max-results",
            "8",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    let d1_retrieval_json = assert_m12_retrieval(
        &d1_retrieval,
        "M-12 D1 CLI retrieval",
        KEPT_ID,
        REVOKED_ID,
        KEPT_CONTENT,
        REVOKED_CONTENT,
    );
    assert_eq!(
        memory_oracle
            .snapshot(KEPT_ID, REVOKED_ID)
            .expect("read M-12 D1 post-retrieval durable snapshot"),
        before_d1_retrieval,
        "D1 retrieval must not write Memory state, events or idempotency records"
    );
    drop(memory_oracle);

    let d1_status = shutdown_fixture_child(daemon_one.child_mut(), "M-12 D1 daemon").await;
    assert!(d1_status.success());
    assert!(
        daemon_one
            .child
            .try_wait()
            .expect("confirm M-12 D1 reap")
            .is_some()
    );

    let mut daemon_two = M12DaemonGuard::new(
        spawn_fixture(root.path(), &instance).await,
        "M-12 D2 daemon",
    );
    let daemon_two_pid = daemon_two.child.id().expect("M-12 D2 PID");
    assert_ne!(daemon_two_pid, std::process::id());
    assert_ne!(
        daemon_two_pid, daemon_one_pid,
        "D2 must be a new daemon process"
    );
    wait_for_m12_daemon(&instance, daemon_two.child_mut(), "M-12 D2 daemon").await;

    let mut memory_oracle = MemoryRestartOracle::open_existing(
        &root.path().join("memory-authority.db"),
        &[0x14; 32],
        "c5-memory-epoch",
    )
    .expect("reopen M-12 Memory conformance oracle after daemon restart");
    assert_eq!(
        memory_oracle
            .snapshot(KEPT_ID, REVOKED_ID)
            .expect("read M-12 D2 initial durable snapshot"),
        before_d1_retrieval,
        "daemon restart and fixture seed replay must not grow durable Memory facts"
    );
    let before_d2_retrieval = memory_oracle
        .snapshot(KEPT_ID, REVOKED_ID)
        .expect("read M-12 D2 pre-retrieval durable snapshot");

    let d2_cli = run_m12_cli(
        &instance,
        &[
            "memory",
            "retrieve",
            "--query",
            "m12 durable memory sentinel",
            "--scope",
            SCOPE,
            "--max-results",
            "8",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    let d2_cli_json = assert_m12_retrieval(
        &d2_cli,
        "M-12 D2 CLI retrieval",
        KEPT_ID,
        REVOKED_ID,
        KEPT_CONTENT,
        REVOKED_CONTENT,
    );
    let d2_tui = run_m12_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-retrieve",
            "--query",
            "m12 durable memory sentinel",
            "--scope",
            SCOPE,
            "--max-results",
            "8",
            "--min-score",
            "0",
            "--json",
        ],
    )
    .await;
    let d2_tui_json = assert_m12_retrieval(
        &d2_tui,
        "M-12 D2 TUI retrieval",
        KEPT_ID,
        REVOKED_ID,
        KEPT_CONTENT,
        REVOKED_CONTENT,
    );
    assert_eq!(
        d2_tui_json["data"]["snapshotSha256"],
        d2_cli_json["data"]["snapshotSha256"]
    );
    assert_eq!(
        d2_cli_json["data"]["snapshotSha256"],
        d1_retrieval_json["data"]["snapshotSha256"]
    );
    assert_eq!(
        d2_cli_json["data"]["evidenceRef"],
        d1_retrieval_json["data"]["evidenceRef"]
    );
    assert_eq!(
        d2_tui_json["data"]["evidenceRef"],
        d1_retrieval_json["data"]["evidenceRef"]
    );
    assert_eq!(
        memory_oracle
            .snapshot(KEPT_ID, REVOKED_ID)
            .expect("read M-12 D2 post-retrieval durable snapshot"),
        before_d2_retrieval,
        "CLI/TUI retrieval after restart must remain read-only"
    );

    let replay = run_m12_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "memory-revoke",
            REVOKED_ID,
            "--expected-revision",
            "2",
            "--evidence-ref",
            "evidence:m12-revocation",
            "--idempotency-key",
            "m12-revoke",
            "--json",
        ],
    )
    .await;
    let replay_json = m12_memory_json(&replay, "M-12 restart exact revoke replay");
    assert_eq!(replay_json["data"], revoked_json["data"]);
    assert_eq!(
        memory_oracle
            .snapshot(KEPT_ID, REVOKED_ID)
            .expect("read M-12 D2 post-replay durable snapshot"),
        before_d2_retrieval,
        "exact replay after restart must not grow durable Memory facts"
    );
    drop(memory_oracle);

    let d2_status = shutdown_fixture_child(daemon_two.child_mut(), "M-12 D2 daemon").await;
    assert!(d2_status.success());
    assert!(
        daemon_two
            .child
            .try_wait()
            .expect("confirm M-12 D2 reap")
            .is_some()
    );
    let unavailable = run_m12_cli(&instance, &["status", "--json"]).await;
    assert_eq!(unavailable.status.code(), Some(3));
    drop(daemon_two);
    drop(daemon_one);
    root.remove();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_06_real_cli_prepare_confirm_creates_task_only_after_founder_binding() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-06-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5-06 fixture root");
    fs::write(
        root.join("context.md"),
        "reviewed context for a governed repository change",
    )
    .expect("write C5-06 context source");
    let instance = format!("c5-06-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    wait_for_cli_status_with_child(&instance, &mut child).await;

    let prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "review the current repository change",
            "--scope",
            "scope:c5-06",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "c5-06-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "prepare must succeed before confirmation: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepare_json: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("C5-06 prepare JSON envelope");
    assert_eq!(prepare_json["operation"], "work.prepare");
    assert_eq!(prepare_json["data"]["gateReady"], true);
    assert_eq!(prepare_json["data"]["readyForFounderConfirmation"], true);
    assert_eq!(
        prepare_json["data"]["includedSources"][0]["sourceRef"],
        "context.md"
    );
    let snapshot_id = prepare_json["data"]["snapshotId"]
        .as_str()
        .expect("C5-06 context snapshot id")
        .to_owned();
    let binding = prepare_json["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("C5-06 confirmation binding")
        .to_owned();

    let confirm = run_cli(
        &instance,
        &[
            "work",
            "confirm",
            snapshot_id.as_str(),
            "--confirmation-binding-sha256",
            binding.as_str(),
            "--idempotency-key",
            "c5-06-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "confirm must delegate to Task Authority: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirm_json: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("C5-06 confirm JSON envelope");
    assert_eq!(confirm_json["operation"], "work.confirm");
    assert!(confirm_json["data"]["taskId"].as_str().is_some());
    assert_eq!(confirm_json["data"]["replayed"], false);

    let replay = run_cli(
        &instance,
        &[
            "work",
            "confirm",
            snapshot_id.as_str(),
            "--confirmation-binding-sha256",
            binding.as_str(),
            "--idempotency-key",
            "c5-06-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        replay.status.success(),
        "identical confirm must replay: stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay_json: serde_json::Value =
        serde_json::from_slice(&replay.stdout).expect("C5-06 replay JSON envelope");
    assert_eq!(replay_json["data"]["replayed"], true);

    drop(child.stdin.take());
    let status = child.wait().await.expect("C5-06 fixture child exit");
    assert!(status.success(), "C5-06 fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove C5-06 fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8a_cli_prepare_tui_confirm_dispatches_context_material_once() {
    const SOURCE_TEXT: &str = "R-8A governed context reaches the native Harness prompt.";

    let root = std::env::temp_dir().join(format!("egopulse-r8a-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-8A fixture root");
    fs::write(root.join("context.md"), SOURCE_TEXT).expect("write R-8A context source");
    let instance = format!("r8a-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, R8A_FIXTURE_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut child).await;

    let prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "dispatch the reviewed R-8A context",
            "--scope",
            "scope:r8a",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "r8a-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-8A CLI prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepare_json: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("R-8A prepare JSON envelope");
    let snapshot_id = prepare_json["data"]["snapshotId"]
        .as_str()
        .expect("R-8A snapshot id")
        .to_owned();
    let compiled_digest = prepare_json["data"]["compiledContextSha256"]
        .as_str()
        .expect("R-8A compiled context digest")
        .to_owned();
    let confirmation_binding = prepare_json["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-8A confirmation binding")
        .to_owned();
    assert_eq!(snapshot_id, format!("ctx:{compiled_digest}"));

    let confirm = run_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-confirm",
            snapshot_id.as_str(),
            "--confirmation-binding-sha256",
            confirmation_binding.as_str(),
            "--idempotency-key",
            "r8a-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-8A TUI confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirm_json: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("R-8A confirm JSON envelope");
    assert_eq!(confirm_json["operation"], "work.confirm");
    let task_id = confirm_json["data"]["taskId"]
        .as_str()
        .expect("R-8A confirmed task id")
        .to_owned();
    assert_eq!(
        confirm_json["data"]["status"],
        TaskStatus::Active.as_str_name()
    );

    let record_path = root.join(R8A_DRIVER_RECORD);
    let mut driver_record = None;
    for _ in 0..100 {
        if let Ok(bytes) = fs::read(&record_path)
            && let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            driver_record = Some(record);
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("R-8A fixture daemon exited before dispatch evidence: {status}");
        }
        sleep(Duration::from_millis(50)).await;
    }
    let driver_record =
        driver_record.expect("R-8A driver must receive a governed dispatch after activation");
    let expected_bundle_ref = format!("ctx-{compiled_digest}.json");
    assert_eq!(driver_record["dispatchCount"], 1);
    assert_eq!(driver_record["runId"], R8A_ACTIVATION_RUN_ID);
    assert_eq!(driver_record["stepId"], "r8a-step");
    assert_eq!(driver_record["attemptId"], "r8a-attempt");
    assert_eq!(driver_record["dispatchId"], "r8a-dispatch");
    assert_eq!(driver_record["inputBundleRef"], expected_bundle_ref);
    assert_eq!(driver_record["workspaceRef"], "workspace-r8a");
    assert_eq!(driver_record["envelopeInputBundleSha256"], compiled_digest);
    assert_eq!(driver_record["compiledBytesSha256"], compiled_digest);
    assert!(
        driver_record["canonicalInputBundleUtf8"]
            .as_str()
            .is_some_and(|value| value.contains(SOURCE_TEXT)),
        "compiled bytes must contain the reviewed source"
    );
    assert!(
        driver_record["prompt"]
            .as_str()
            .is_some_and(|value| value.contains(SOURCE_TEXT)),
        "native prompt must contain the reviewed source"
    );

    sleep(Duration::from_millis(150)).await;
    let stable_record: serde_json::Value =
        serde_json::from_slice(&fs::read(&record_path).expect("read stable R-8A driver record"))
            .expect("parse stable R-8A driver record");
    assert_eq!(stable_record["dispatchCount"], 1);

    let mut task_view = None;
    for _ in 0..80 {
        let output = run_cli(&instance, &["task", "get", task_id.as_str(), "--json"]).await;
        if output.status.success()
            && let Ok(view) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        {
            task_view = Some(view);
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let task_view = task_view.expect("R-8A active Task projection");
    assert_eq!(task_view["data"]["taskId"], task_id);
    assert_eq!(
        task_view["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID,
        "Task activation and governed dispatch must share the same run identity"
    );
    assert_eq!(
        task_view["data"]["status"],
        TaskStatus::Active.as_str_name(),
        "no native terminal event means the Task must remain non-completed"
    );

    drop(child.stdin.take());
    let status = child.wait().await.expect("R-8A fixture child exit");
    assert!(status.success(), "R-8A fixture child failed: {status}");
    let adapter = AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.join("r8a-adapter.db"),
        adapter_id: CODEX_ADAPTER_ID.to_owned(),
        store_epoch: "r8a-adapter-epoch".to_owned(),
        key: AdapterEdgeKey::new([0x32; 32]),
    })
    .expect("reopen R-8A Adapter Edge evidence");
    let adapter_inspection = adapter.inspect().expect("inspect R-8A Adapter Edge");
    assert_eq!(adapter_inspection.dispatch_count, 1);
    assert_eq!(
        adapter_inspection.observation_count, 1,
        "one non-terminal native acknowledgement must cross the governed observation edge"
    );
    let observations = adapter
        .observations_after(0)
        .expect("read R-8A governed observation evidence");
    assert!(matches!(
        observations.as_slice(),
        [HarnessObservation {
            payload: Some(harness_observation::Payload::Ack(_)),
            ..
        }]
    ));
    drop(adapter);
    fs::remove_dir_all(&root).expect("remove R-8A fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8b_activation_outbox_survives_daemon_kill_and_dispatches_once_after_restart() {
    const SOURCE_TEXT: &str = "R-8B pending activation survives a daemon restart.";

    let root = std::env::temp_dir().join(format!("egopulse-r8b-1-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-8B.1 fixture root");
    fs::write(root.join("context.md"), SOURCE_TEXT).expect("write R-8B.1 context source");
    let instance = format!("r8b-1-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, R8B_PAUSE_BEFORE_RUNNER_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut child).await;

    let first_cycle_marker = root.join(R8B_FIRST_RUNNER_CYCLE_RECORD);
    for _ in 0..100 {
        if first_cycle_marker.is_file() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("R-8B.1 fixture daemon exited before its first empty runner cycle: {status}");
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        first_cycle_marker.is_file(),
        "R-8B.1 must observe the first empty production runner cycle before activation"
    );

    let prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "dispatch the pending R-8B context after restart",
            "--scope",
            "scope:r8a",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "r8b-1-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-8B.1 CLI prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepare_json: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("R-8B.1 prepare JSON envelope");
    let snapshot_id = prepare_json["data"]["snapshotId"]
        .as_str()
        .expect("R-8B.1 snapshot id")
        .to_owned();
    let compiled_digest = prepare_json["data"]["compiledContextSha256"]
        .as_str()
        .expect("R-8B.1 compiled context digest")
        .to_owned();
    let confirmation_binding = prepare_json["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-8B.1 confirmation binding")
        .to_owned();
    assert_eq!(snapshot_id, format!("ctx:{compiled_digest}"));

    let confirm = run_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-confirm",
            snapshot_id.as_str(),
            "--confirmation-binding-sha256",
            confirmation_binding.as_str(),
            "--idempotency-key",
            "r8b-1-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-8B.1 TUI confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirm_json: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("R-8B.1 confirm JSON envelope");
    let task_id = confirm_json["data"]["taskId"]
        .as_str()
        .expect("R-8B.1 confirmed task id")
        .to_owned();
    assert_eq!(
        confirm_json["data"]["status"],
        TaskStatus::Active.as_str_name()
    );

    let mut active_before_restart = None;
    for _ in 0..80 {
        let output = run_cli(&instance, &["task", "get", task_id.as_str(), "--json"]).await;
        if output.status.success()
            && let Ok(view) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            && view["data"]["status"] == TaskStatus::Active.as_str_name()
        {
            active_before_restart = Some(view);
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let active_before_restart =
        active_before_restart.expect("R-8B.1 Task must be Active before daemon termination");
    assert_eq!(
        active_before_restart["data"]["currentRunId"],
        R8A_ACTIVATION_RUN_ID
    );
    let driver_record_path = root.join(R8A_DRIVER_RECORD);
    assert!(
        !driver_record_path.exists(),
        "the paused runner must not call the native driver before termination"
    );

    child
        .kill()
        .await
        .expect("force-stop R-8B.1 fixture daemon");
    let killed = child.wait().await.expect("observe R-8B.1 forced stop");
    assert!(!killed.success(), "R-8B.1 first daemon must be killed");

    let mut restarted = spawn_fixture_with_mode(&root, &instance, R8A_FIXTURE_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;

    let mut driver_record = None;
    for _ in 0..100 {
        if let Ok(bytes) = fs::read(&driver_record_path)
            && let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            driver_record = Some(record);
            break;
        }
        if let Ok(Some(status)) = restarted.try_wait() {
            panic!("R-8B.1 restarted daemon exited before dispatch evidence: {status}");
        }
        sleep(Duration::from_millis(50)).await;
    }
    let driver_record = driver_record.expect("R-8B.1 restart must dispatch the pending activation");
    assert_eq!(driver_record["dispatchCount"], 1);
    assert_eq!(driver_record["runId"], R8A_ACTIVATION_RUN_ID);
    assert_eq!(driver_record["stepId"], "r8a-step");
    assert_eq!(driver_record["attemptId"], "r8a-attempt");
    assert_eq!(driver_record["dispatchId"], "r8a-dispatch");
    assert_eq!(
        driver_record["inputBundleRef"],
        format!("ctx-{compiled_digest}.json")
    );
    assert_eq!(driver_record["envelopeInputBundleSha256"], compiled_digest);

    sleep(Duration::from_millis(150)).await;
    let stable_record: serde_json::Value = serde_json::from_slice(
        &fs::read(&driver_record_path).expect("read stable R-8B.1 driver record"),
    )
    .expect("parse stable R-8B.1 driver record");
    assert_eq!(stable_record["dispatchCount"], 1);

    let mut active_after_restart = None;
    for _ in 0..80 {
        let output = run_cli(&instance, &["task", "get", task_id.as_str(), "--json"]).await;
        if output.status.success()
            && let Ok(view) = serde_json::from_slice::<serde_json::Value>(&output.stdout)
            && view["data"]["status"] == TaskStatus::Active.as_str_name()
        {
            active_after_restart = Some(view);
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let active_after_restart =
        active_after_restart.expect("R-8B.1 Task must remain Active after dispatch");
    assert_eq!(active_after_restart["data"]["taskId"], task_id);
    assert_eq!(
        active_after_restart["data"]["currentRunId"],
        R8A_ACTIVATION_RUN_ID
    );

    drop(restarted.stdin.take());
    let status = restarted
        .wait()
        .await
        .expect("R-8B.1 restarted fixture child exit");
    assert!(status.success(), "R-8B.1 restarted daemon failed: {status}");

    let adapter = AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.join("r8a-adapter.db"),
        adapter_id: CODEX_ADAPTER_ID.to_owned(),
        store_epoch: "r8a-adapter-epoch".to_owned(),
        key: AdapterEdgeKey::new([0x32; 32]),
    })
    .expect("reopen R-8B.1 Adapter Edge evidence");
    let inspection = adapter.inspect().expect("inspect R-8B.1 Adapter Edge");
    assert_eq!(inspection.dispatch_count, 1);
    assert_eq!(inspection.observation_count, 1);
    let observations = adapter
        .observations_after(0)
        .expect("read R-8B.1 non-terminal observation evidence");
    assert!(matches!(
        observations.as_slice(),
        [HarnessObservation {
            payload: Some(harness_observation::Payload::Ack(_)),
            ..
        }]
    ));
    drop(adapter);
    fs::remove_dir_all(&root).expect("remove R-8B.1 fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9a3e_revoke_before_context_authorization_blocks_ready_dispatch_without_writes() {
    const SOURCE_TEXT: &str =
        "R-9A.3e revoke-first must reject a durable prepared dispatch without side effects.";

    let root = std::env::temp_dir().join(format!("egopulse-r9a3e-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-9A.3e fixture root");
    fs::write(root.join("context.md"), SOURCE_TEXT).expect("write R-9A.3e Context source");
    let instance = format!("r9a3e-daemon-{}", Uuid::now_v7());
    let witness_instance = format!("r9a3e-witness-{}", Uuid::now_v7());
    let parent_pid = std::process::id();
    let mut witness = spawn_r9a3d_witness_helper(&root, &witness_instance);
    let ready: R9a3dWitnessReady = wait_for_r9a3_json(
        &r9a3d_path(&root, R9A3D_READY_FILE),
        &mut witness,
        "R-9A.3e witness ready",
    );
    assert_eq!(ready.process_id, witness.id());
    assert_ne!(ready.process_id, parent_pid);
    assert_eq!(ready.fixture_root, root.display().to_string());
    assert_eq!(ready.fixture_instance, witness_instance);
    let send_endpoint: SocketAddr = ready
        .send_endpoint
        .parse()
        .expect("parse R-9A.3e send endpoint");
    let send_endpoint = send_endpoint.to_string();

    let mut daemon_zero =
        spawn_fixture_with_mode(&root, &instance, R8B_PAUSE_BEFORE_RUNNER_MODE).await;
    let daemon_zero_pid = daemon_zero.id().expect("R-9A.3e daemon D0 PID");
    assert_ne!(daemon_zero_pid, parent_pid);
    assert_ne!(daemon_zero_pid, ready.process_id);
    wait_for_cli_status_with_child(&instance, &mut daemon_zero).await;
    let first_cycle_marker = root.join(R8B_FIRST_RUNNER_CYCLE_RECORD);
    for _ in 0..120 {
        if first_cycle_marker.is_file() {
            break;
        }
        assert!(
            daemon_zero
                .try_wait()
                .expect("inspect R-9A.3e D0")
                .is_none(),
            "R-9A.3e D0 exited before the initial empty runner cycle"
        );
        sleep(Duration::from_millis(25)).await;
    }
    assert!(first_cycle_marker.is_file());

    let prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "prove revoke-first dispatch consumption",
            "--scope",
            "scope:r8a",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "r9a3e-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-9A.3e prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepared: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("decode R-9A.3e prepare response");
    let snapshot_id = prepared["data"]["snapshotId"]
        .as_str()
        .expect("R-9A.3e snapshot id")
        .to_owned();
    let compiled_digest = prepared["data"]["compiledContextSha256"]
        .as_str()
        .expect("R-9A.3e compiled digest")
        .to_owned();
    let confirmation_binding = prepared["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-9A.3e confirmation binding")
        .to_owned();
    assert_eq!(snapshot_id, format!("ctx:{compiled_digest}"));
    let bundle_path = root
        .join("input-bundles")
        .join(format!("ctx-{compiled_digest}.json"));
    let bundle_bytes = fs::read(&bundle_path).expect("read prepared R-9A.3e input bundle");
    assert_eq!(
        format!("{:x}", Sha256::digest(&bundle_bytes)),
        compiled_digest
    );
    let withheld_bundle_path = root
        .join("input-bundles")
        .join(format!(".r9a3e-{compiled_digest}.withheld"));
    fs::rename(&bundle_path, &withheld_bundle_path)
        .expect("atomically withhold R-9A.3e input bundle before confirm");
    assert!(!bundle_path.exists());

    let confirm = run_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-confirm",
            &snapshot_id,
            "--confirmation-binding-sha256",
            &confirmation_binding,
            "--idempotency-key",
            "r9a3e-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-9A.3e confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirmed: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("decode R-9A.3e confirm response");
    let task_id = confirmed["data"]["taskId"]
        .as_str()
        .expect("R-9A.3e task id")
        .to_owned();
    assert_eq!(
        confirmed["data"]["status"],
        TaskStatus::Active.as_str_name()
    );
    assert!(!root.join(R8A_DRIVER_RECORD).exists());
    hard_kill_r8b2c_child(&mut daemon_zero, "R-9A.3e pre-runner pause").await;

    let mut daemon_one = spawn_r9a3d_fixture(
        &root,
        &instance,
        R9A3E_PREAUTH_UNAVAILABLE_MODE,
        &witness_instance,
        &send_endpoint,
    )
    .await;
    let daemon_one_pid = daemon_one.id().expect("R-9A.3e daemon D1 PID");
    assert_ne!(daemon_one_pid, parent_pid);
    assert_ne!(daemon_one_pid, ready.process_id);
    assert_ne!(daemon_one_pid, daemon_zero_pid);
    wait_for_cli_status_with_child(&instance, &mut daemon_one).await;
    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R9A3E_PREAUTH_UNAVAILABLE_PHASE,
        &mut daemon_one,
    )
    .await;
    assert!(!bundle_path.exists());
    assert!(!root.join(R8A_DRIVER_RECORD).exists());

    let adapter_before_revoke = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter_before_revoke.dispatch_count, 1);
    assert_eq!(adapter_before_revoke.dispatch_state, "prepared");
    assert_eq!(adapter_before_revoke.delivery_unknown_count, 0);
    assert_eq!(adapter_before_revoke.observation_count, 0);
    assert_eq!(adapter_before_revoke.pending_observation_count, 0);
    assert!(adapter_before_revoke.receipt.is_none());
    assert!(adapter_before_revoke.receipt_bytes.is_none());
    let collaboration_before_revoke = read_r8b2c_collaboration_oracle(&root);
    assert_eq!(collaboration_before_revoke.outbox_state, "pending");
    assert_eq!(
        collaboration_before_revoke.attempt.status,
        AttemptStatus::DispatchPending as i32
    );
    let task_before_revoke = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(
        task_before_revoke.snapshot.status,
        TaskStatus::Active as i32
    );
    assert_eq!(
        task_before_revoke.snapshot.current_run_id.as_deref(),
        Some(R8A_ACTIVATION_RUN_ID)
    );
    let verdict_before_revoke = read_empty_r9a3_verdict_oracle(&root);
    let context_before_revoke = read_r9a3_context_authority_store(
        &root.join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("read R-9A.3e Context before revoke");
    assert_eq!(
        context_before_revoke.snapshot.governance_state,
        R9a3ContextGovernanceState::Issued
    );
    assert_eq!(context_before_revoke.snapshot.state_revision, 1);
    assert!(context_before_revoke.dispatch_authorization.is_none());
    assert_eq!(context_before_revoke.counts.authorization_count, 0);
    let side_effects_before_revoke = R9a3SideEffectReader::open_existing(&root, &witness_instance)
        .expect("open R-9A.3e external oracle before revoke");
    assert_eq!(
        side_effects_before_revoke
            .effect_count()
            .expect("effect count"),
        0
    );
    drop(side_effects_before_revoke);
    assert!(!r9a3d_path(&root, R9A3D_COMMITTED_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_CONNECTION_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_SEND_FILE).exists());

    let preview = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "dispatch-material-withheld",
            "--evidence-ref",
            "evidence:r9a3e:prepared-dispatch",
            "--confirmation-proof-ref",
            "proof:r9a3e:founder-confirmation",
            "--idempotency-key",
            "r9a3e-revoke",
            "--preview",
            "--json",
        ],
    )
    .await;
    assert!(preview.status.success());
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("decode R-9A.3e revoke preview");
    let revoke_digest = preview_json["data"]["requestDigestSha256"]
        .as_str()
        .expect("R-9A.3e revoke digest")
        .to_owned();
    let revoke = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "dispatch-material-withheld",
            "--evidence-ref",
            "evidence:r9a3e:prepared-dispatch",
            "--confirmation-proof-ref",
            "proof:r9a3e:founder-confirmation",
            "--idempotency-key",
            "r9a3e-revoke",
            "--confirm-digest",
            &revoke_digest,
            "--json",
        ],
    )
    .await;
    assert!(
        revoke.status.success(),
        "R-9A.3e revoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );
    let context_after_revoke = read_r9a3_context_authority_store(
        &root.join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("read R-9A.3e Context after revoke");
    assert_eq!(
        context_after_revoke.snapshot.governance_state,
        R9a3ContextGovernanceState::Revoked
    );
    assert_eq!(context_after_revoke.snapshot.state_revision, 2);
    assert_eq!(
        context_after_revoke
            .revoke
            .as_ref()
            .expect("R-9A.3e revoke fact")
            .request_digest_sha256,
        revoke_digest
    );
    assert!(context_after_revoke.dispatch_authorization.is_none());
    assert_eq!(context_after_revoke.counts.authorization_count, 0);
    assert_eq!(read_r8b2c_adapter_oracle(&root), adapter_before_revoke);
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root),
        collaboration_before_revoke
    );
    assert_eq!(read_r8b2c_task_oracle(&root, &task_id), task_before_revoke);
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    assert!(!root.join(R8A_DRIVER_RECORD).exists());
    let side_effects_after_revoke = R9a3SideEffectReader::open_existing(&root, &witness_instance)
        .expect("open R-9A.3e external oracle after revoke");
    assert_eq!(
        side_effects_after_revoke
            .effect_count()
            .expect("effect count"),
        0
    );
    drop(side_effects_after_revoke);
    assert!(!r9a3d_path(&root, R9A3D_COMMITTED_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_CONNECTION_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_SEND_FILE).exists());
    hard_kill_r8b2c_child(&mut daemon_one, R9A3E_PREAUTH_UNAVAILABLE_PHASE).await;

    fs::rename(&withheld_bundle_path, &bundle_path)
        .expect("atomically restore exact R-9A.3e input bundle");
    assert_eq!(
        fs::read(&bundle_path).expect("read restored bundle"),
        bundle_bytes
    );
    let mut daemon_two = spawn_r9a3d_fixture(
        &root,
        &instance,
        R9A3E_REVOKED_READY_MODE,
        &witness_instance,
        &send_endpoint,
    )
    .await;
    let daemon_two_pid = daemon_two.id().expect("R-9A.3e daemon D2 PID");
    assert_ne!(daemon_two_pid, parent_pid);
    assert_ne!(daemon_two_pid, ready.process_id);
    assert_ne!(daemon_two_pid, daemon_zero_pid);
    assert_ne!(daemon_two_pid, daemon_one_pid);
    wait_for_cli_status_with_child(&instance, &mut daemon_two).await;
    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R9A3E_REVOKED_READY_PHASE,
        &mut daemon_two,
    )
    .await;

    assert_eq!(
        read_r9a3_context_authority_store(
            &root.join("context-authority.db"),
            &[0x15; 32],
            "c5-context-epoch",
            &snapshot_id,
            "r8a-dispatch",
        )
        .expect("read R-9A.3e Context after D2 Ready rejection"),
        context_after_revoke
    );
    assert_eq!(read_r8b2c_adapter_oracle(&root), adapter_before_revoke);
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root),
        collaboration_before_revoke
    );
    let task_after_ready_rejection = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(task_after_ready_rejection, task_before_revoke);
    assert_ne!(
        task_after_ready_rejection.snapshot.status,
        TaskStatus::Completed as i32
    );
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    assert!(!root.join(R8A_DRIVER_RECORD).exists());
    let side_effects_after_ready = R9a3SideEffectReader::open_existing(&root, &witness_instance)
        .expect("open R-9A.3e external oracle after D2 Ready rejection");
    assert_eq!(
        side_effects_after_ready
            .effect_count()
            .expect("effect count"),
        0
    );
    drop(side_effects_after_ready);
    assert!(!r9a3d_path(&root, R9A3D_COMMITTED_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_CONNECTION_FILE).exists());
    assert!(!r9a3d_path(&root, R9A3D_FORBIDDEN_SEND_FILE).exists());

    hard_kill_r8b2c_child(&mut daemon_two, R9A3E_REVOKED_READY_PHASE).await;
    assert!(
        witness
            .try_wait()
            .expect("inspect R-9A.3e witness before cleanup")
            .is_none()
    );
    let witness_status = witness.hard_kill();
    assert!(!witness_status.success());
    fs::remove_dir_all(root).expect("remove R-9A.3e fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9a3d_daemon_crash_after_external_commit_recovers_without_resend() {
    const SOURCE_TEXT: &str = "R-9A.3d authorized Context survives revoke and crash recovery.";

    let root = R9a3WitnessTempRoot::new();
    fs::write(root.path().join("context.md"), SOURCE_TEXT)
        .expect("write R-9A.3d governed Context source");
    let instance = format!("r9a3d-daemon-{}", Uuid::now_v7());
    let witness_instance = format!("r9a3d-witness-{}", Uuid::now_v7());
    let parent_pid = std::process::id();
    let mut witness = spawn_r9a3d_witness_helper(root.path(), &witness_instance);
    let ready: R9a3dWitnessReady = wait_for_r9a3_json(
        &r9a3d_path(root.path(), R9A3D_READY_FILE),
        &mut witness,
        "R-9A.3d witness ready",
    );
    assert_eq!(ready.process_id, witness.id());
    assert_ne!(ready.process_id, parent_pid);
    assert_eq!(ready.fixture_root, root.path().display().to_string());
    assert_eq!(ready.fixture_instance, witness_instance);
    let send_endpoint: SocketAddr = ready
        .send_endpoint
        .parse()
        .expect("parse R-9A.3d send endpoint");
    assert_eq!(send_endpoint.ip().to_string(), "127.0.0.1");
    assert_ne!(send_endpoint.port(), 0);

    let mut daemon_one = spawn_r9a3d_fixture(
        root.path(),
        &instance,
        R9A3D_EXTERNAL_SEND_MODE,
        &witness_instance,
        &ready.send_endpoint,
    )
    .await;
    let daemon_one_pid = daemon_one.id().expect("R-9A.3d daemon D1 PID");
    assert_ne!(daemon_one_pid, parent_pid);
    assert_ne!(daemon_one_pid, ready.process_id);
    wait_for_r9a3d_daemon(&instance, &mut daemon_one).await;

    let prepare = run_r9a3d_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "prove R-9A.3d external effect recovery",
            "--scope",
            "scope:r8a",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "r9a3d-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-9A.3d CLI prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepared: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("decode R-9A.3d prepare response");
    let snapshot_id = prepared["data"]["snapshotId"]
        .as_str()
        .expect("R-9A.3d snapshot id")
        .to_owned();
    let compiled_digest = prepared["data"]["compiledContextSha256"]
        .as_str()
        .expect("R-9A.3d compiled Context digest")
        .to_owned();
    let confirmation_binding = prepared["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-9A.3d confirmation binding")
        .to_owned();
    assert_eq!(snapshot_id, format!("ctx:{compiled_digest}"));

    let confirm = run_r9a3d_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-confirm",
            &snapshot_id,
            "--confirmation-binding-sha256",
            &confirmation_binding,
            "--idempotency-key",
            "r9a3d-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-9A.3d TUI confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirmed: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("decode R-9A.3d confirm response");
    let task_id = confirmed["data"]["taskId"]
        .as_str()
        .expect("R-9A.3d Task id")
        .to_owned();
    assert!(
        confirmed["data"]["status"] == TaskStatus::Ready.as_str_name()
            || confirmed["data"]["status"] == TaskStatus::Active.as_str_name(),
        "R-9A.3d confirmation response must be Ready or already Active: {}",
        confirmed["data"]["status"]
    );

    let active =
        wait_for_r9a3d_task(&instance, &task_id, TaskStatus::Active, &mut daemon_one).await;
    assert_eq!(active["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID);

    let committed: R9a3dRequestEvidence = wait_for_r9a3d_json(
        &r9a3d_path(root.path(), R9A3D_COMMITTED_FILE),
        &mut witness,
        &mut daemon_one,
        "external effect commit before ACK",
    )
    .await;
    assert_eq!(committed.process_id, ready.process_id);
    assert_eq!(committed.fixture_instance, witness_instance);
    assert_eq!(committed.phase, "effect-committed-before-ack");
    assert_eq!(committed.send_count, 1);
    assert_eq!(committed.dispatch_id, "r8a-dispatch");
    assert_eq!(committed.attempt_id, "r8a-attempt");
    assert_eq!(committed.payload_digest_sha256, compiled_digest);
    let request = committed.request();

    let prekill_reader = R9a3SideEffectReader::open_existing(root.path(), &witness_instance)
        .expect("open R-9A.3d external effect before daemon kill");
    assert_eq!(
        prekill_reader
            .effect_count()
            .expect("pre-kill effect count"),
        1
    );
    let prekill_effect = prekill_reader
        .effect_for_dispatch(&request.dispatch_id)
        .expect("read pre-kill external effect")
        .expect("pre-kill external effect exists");
    assert_eq!(prekill_effect.request, request);
    let original_ack = prekill_effect.original_ack();
    assert!(!original_ack.replayed);

    let preview = run_r9a3d_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "r9a3d-authorized-effect-exists",
            "--evidence-ref",
            "evidence:r9a3d-external-effect",
            "--confirmation-proof-ref",
            "proof:r9a3d-revoke",
            "--idempotency-key",
            "r9a3d-revoke",
            "--preview",
            "--json",
        ],
    )
    .await;
    assert!(preview.status.success(), "R-9A.3d revoke preview failed");
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("decode R-9A.3d revoke preview");
    let revoke_digest = preview_json["data"]["requestDigestSha256"]
        .as_str()
        .expect("R-9A.3d revoke digest")
        .to_owned();
    let revoke = run_r9a3d_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "r9a3d-authorized-effect-exists",
            "--evidence-ref",
            "evidence:r9a3d-external-effect",
            "--confirmation-proof-ref",
            "proof:r9a3d-revoke",
            "--idempotency-key",
            "r9a3d-revoke",
            "--confirm-digest",
            &revoke_digest,
            "--json",
        ],
    )
    .await;
    assert!(
        revoke.status.success(),
        "R-9A.3d Context revoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );
    let revoke_json: serde_json::Value =
        serde_json::from_slice(&revoke.stdout).expect("decode R-9A.3d revoke receipt");
    assert_eq!(
        revoke_json["data"]["resultState"],
        "CONTEXT_GOVERNANCE_STATE_REVOKED"
    );
    assert_eq!(revoke_json["data"]["resultStateRevision"], 2);

    let context_before_restart = read_r9a3_context_authority_store(
        &root.path().join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("read R-9A.3d Context authority before restart");
    assert_eq!(
        context_before_restart.snapshot.governance_state,
        R9a3ContextGovernanceState::Revoked
    );
    assert_eq!(context_before_restart.snapshot.state_revision, 2);
    let revoke_before_restart = context_before_restart
        .revoke
        .as_ref()
        .expect("R-9A.3d durable revoke fact exists before restart");
    assert_eq!(revoke_before_restart.request_digest_sha256, revoke_digest);
    assert_eq!(revoke_before_restart.content_digest_sha256, compiled_digest);
    assert_eq!(revoke_before_restart.previous_state_revision, 1);
    assert_eq!(revoke_before_restart.result_state_revision, 2);
    let authorization_before_restart = context_before_restart
        .dispatch_authorization
        .as_ref()
        .expect("R-9A.3d dispatch authorization exists before restart");
    assert_eq!(authorization_before_restart.snapshot_id, snapshot_id);
    assert_eq!(authorization_before_restart.dispatch_id, "r8a-dispatch");
    assert_eq!(authorization_before_restart.attempt_id, "r8a-attempt");
    assert_eq!(
        authorization_before_restart.input_digest_sha256,
        compiled_digest
    );
    assert_eq!(authorization_before_restart.observed_state_revision, 1);
    assert_eq!(authorization_before_restart.expected_scope_ref, "scope:r8a");
    assert_eq!(context_before_restart.counts.authorization_count, 1);

    assert!(
        witness
            .try_wait()
            .expect("inspect R-9A.3d witness before D1 kill")
            .is_none()
    );
    hard_kill_r9a3d_child(&mut daemon_one, "effect committed before ACK").await;
    let disconnected: R9a3dRequestEvidence = wait_for_r9a3_json(
        &r9a3d_path(root.path(), R9A3D_DISCONNECTED_FILE),
        &mut witness,
        "D1 disconnect without ACK",
    );
    disconnected.assert_request(&request);
    assert_eq!(disconnected.send_count, 1);
    assert!(
        witness
            .try_wait()
            .expect("inspect R-9A.3d witness after D1 kill")
            .is_none(),
        "witness must survive daemon D1"
    );

    drop(prekill_reader);
    let postkill_reader = R9a3SideEffectReader::open_existing(root.path(), &witness_instance)
        .expect("reopen R-9A.3d external effect after D1 kill");
    assert_eq!(
        postkill_reader
            .effect_count()
            .expect("post-kill effect count"),
        1
    );
    let postkill_effect = postkill_reader
        .effect_for_dispatch(&request.dispatch_id)
        .expect("read post-kill external effect")
        .expect("post-kill external effect exists");
    assert_eq!(postkill_effect.request, request);
    assert_eq!(postkill_effect.original_ack(), original_ack);
    drop(postkill_reader);

    let context_after_kill = read_r9a3_context_authority_store(
        &root.path().join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("reopen R-9A.3d Context authority after D1 kill");
    assert_eq!(context_after_kill, context_before_restart);

    let adapter_after_kill = read_r8b2c_adapter_oracle(root.path());
    assert_eq!(adapter_after_kill.dispatch_count, 1);
    assert_eq!(adapter_after_kill.delivery_unknown_count, 1);
    assert_eq!(adapter_after_kill.observation_count, 0);
    assert_eq!(adapter_after_kill.pending_observation_count, 0);
    assert_eq!(adapter_after_kill.dispatch_state, "delivery_unknown");
    assert_eq!(adapter_after_kill.dispatch_attempt_id, "r8a-attempt");
    assert!(adapter_after_kill.receipt.is_none());
    assert!(adapter_after_kill.receipt_bytes.is_none());

    let collaboration_after_kill = read_r8b2c_collaboration_oracle(root.path());
    assert_eq!(collaboration_after_kill.outbox_state, "pending");
    assert_eq!(
        collaboration_after_kill.run.status,
        RunStatus::Active as i32
    );
    assert_eq!(
        collaboration_after_kill.step.status,
        StepStatus::Active as i32
    );
    assert_eq!(
        collaboration_after_kill.step.attempt_ids,
        vec!["r8a-attempt"]
    );
    assert_eq!(
        collaboration_after_kill.step.current_attempt_id.as_deref(),
        Some("r8a-attempt")
    );
    assert_eq!(collaboration_after_kill.attempt.attempt_id, "r8a-attempt");
    assert_eq!(
        collaboration_after_kill.attempt.run_id,
        R8A_ACTIVATION_RUN_ID
    );
    assert_eq!(collaboration_after_kill.attempt.step_id, "r8a-step");
    assert!(collaboration_after_kill.attempt.attempt_number > 0);
    assert_eq!(
        collaboration_after_kill.attempt.status,
        AttemptStatus::DispatchPending as i32
    );
    assert_eq!(
        collaboration_after_kill.attempt.dispatch_id.as_deref(),
        Some("r8a-dispatch")
    );
    let original_attempt_number = collaboration_after_kill.attempt.attempt_number;

    let task_after_kill = read_r8b2c_task_oracle(root.path(), &task_id);
    assert_eq!(task_after_kill.snapshot.status, TaskStatus::Active as i32);
    assert_eq!(
        task_after_kill.snapshot.current_run_id.as_deref(),
        Some(R8A_ACTIVATION_RUN_ID)
    );
    assert_ne!(
        task_after_kill.snapshot.status,
        TaskStatus::Completed as i32
    );
    let verdict_after_kill = read_empty_r9a3_verdict_oracle(root.path());

    let mut daemon_two = spawn_r9a3d_fixture(
        root.path(),
        &instance,
        R9A3D_EXTERNAL_RECOVERY_MODE,
        &witness_instance,
        &ready.send_endpoint,
    )
    .await;
    let daemon_two_pid = daemon_two.id().expect("R-9A.3d daemon D2 PID");
    assert_ne!(daemon_two_pid, parent_pid);
    assert_ne!(daemon_two_pid, ready.process_id);
    assert_ne!(daemon_two_pid, daemon_one_pid);
    wait_for_r9a3d_daemon(&instance, &mut daemon_two).await;

    let recovered: R9a3dRunnerCheckpoint = wait_for_r9a3d_json(
        &r9a3d_path(root.path(), R9A3D_RECOVERY_CHECKPOINT_FILE),
        &mut witness,
        &mut daemon_two,
        "conservative recovery settlement",
    )
    .await;
    assert_eq!(recovered.process_id, daemon_two_pid);
    assert_eq!(recovered.fixture_root, root.path().display().to_string());
    assert_eq!(recovered.fixture_instance, instance);
    assert_eq!(recovered.phase, "recovery-settled");

    let interrupted = wait_for_r9a3d_task(
        &instance,
        &task_id,
        TaskStatus::Interrupted,
        &mut daemon_two,
    )
    .await;
    assert_eq!(interrupted["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID);
    assert_ne!(
        interrupted["data"]["status"],
        TaskStatus::Completed.as_str_name()
    );

    let adapter_after_recovery = read_r8b2c_adapter_oracle(root.path());
    assert_eq!(adapter_after_recovery.dispatch_count, 1);
    assert_eq!(adapter_after_recovery.delivery_unknown_count, 1);
    assert_eq!(adapter_after_recovery.observation_count, 1);
    assert_eq!(adapter_after_recovery.observations.len(), 1);
    let reconciliation_observation = &adapter_after_recovery.observations[0];
    assert_eq!(
        reconciliation_observation.native_key,
        "reconciliation:adapter-reconciliation:r8a-dispatch"
    );
    assert_eq!(reconciliation_observation.dispatch_id, "r8a-dispatch");
    assert!(!reconciliation_observation.raw_event.is_empty());
    assert!(matches!(
        reconciliation_observation.observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code == "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN"
    ));
    let collaboration_after_recovery = read_r8b2c_collaboration_oracle(root.path());
    assert_eq!(collaboration_after_recovery.outbox_state, "held");
    assert_eq!(
        collaboration_after_recovery.run.status,
        RunStatus::Held as i32
    );
    assert_eq!(
        collaboration_after_recovery.step.status,
        StepStatus::Held as i32
    );
    assert_eq!(
        collaboration_after_recovery.attempt.status,
        AttemptStatus::Held as i32
    );
    assert_eq!(
        collaboration_after_recovery.attempt.recovery_class,
        RecoveryClass::ManualOnly as i32
    );
    assert_eq!(
        collaboration_after_recovery.step.attempt_ids,
        vec!["r8a-attempt"]
    );
    assert_eq!(
        collaboration_after_recovery
            .step
            .current_attempt_id
            .as_deref(),
        Some("r8a-attempt")
    );
    assert_eq!(
        collaboration_after_recovery.attempt.attempt_id,
        "r8a-attempt"
    );
    assert_eq!(
        collaboration_after_recovery.attempt.run_id,
        R8A_ACTIVATION_RUN_ID
    );
    assert_eq!(collaboration_after_recovery.attempt.step_id, "r8a-step");
    assert_eq!(
        collaboration_after_recovery.attempt.attempt_number,
        original_attempt_number
    );
    let task_after_recovery = read_r8b2c_task_oracle(root.path(), &task_id);
    assert_eq!(
        task_after_recovery.snapshot.status,
        TaskStatus::Interrupted as i32
    );
    assert_ne!(
        task_after_recovery.snapshot.status,
        TaskStatus::Completed as i32
    );
    assert_eq!(
        read_empty_r9a3_verdict_oracle(root.path()),
        verdict_after_kill
    );

    let context_after_recovery = read_r9a3_context_authority_store(
        &root.path().join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("read R-9A.3d Context authority after recovery");
    assert_eq!(
        context_after_recovery.snapshot.governance_state,
        R9a3ContextGovernanceState::Revoked
    );
    assert_eq!(context_after_recovery.snapshot.state_revision, 2);
    assert_eq!(context_after_recovery, context_after_kill);

    let stable: R9a3dRunnerCheckpoint = wait_for_r9a3d_json(
        &r9a3d_path(root.path(), R9A3D_STABLE_CHECKPOINT_FILE),
        &mut witness,
        &mut daemon_two,
        "stable recovery cycle",
    )
    .await;
    assert_eq!(stable.process_id, daemon_two_pid);
    assert_eq!(stable.fixture_root, root.path().display().to_string());
    assert_eq!(stable.fixture_instance, instance);
    assert_eq!(stable.phase, "stable-cycle");
    assert_eq!(
        read_r8b2c_adapter_oracle(root.path()),
        adapter_after_recovery
    );
    let collaboration_after_stable = read_r8b2c_collaboration_oracle(root.path());
    assert_eq!(collaboration_after_stable, collaboration_after_recovery);
    assert_eq!(
        collaboration_after_stable.step.attempt_ids,
        vec!["r8a-attempt"]
    );
    assert_eq!(
        collaboration_after_stable
            .step
            .current_attempt_id
            .as_deref(),
        Some("r8a-attempt")
    );
    assert_eq!(collaboration_after_stable.attempt.attempt_id, "r8a-attempt");
    assert_eq!(
        collaboration_after_stable.attempt.run_id,
        R8A_ACTIVATION_RUN_ID
    );
    assert_eq!(collaboration_after_stable.attempt.step_id, "r8a-step");
    assert_eq!(
        collaboration_after_stable.attempt.attempt_number,
        original_attempt_number
    );
    assert_eq!(
        read_r8b2c_task_oracle(root.path(), &task_id),
        task_after_recovery
    );
    let context_after_stable = read_r9a3_context_authority_store(
        &root.path().join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        "r8a-dispatch",
    )
    .expect("read R-9A.3d Context authority after stable recovery cycle");
    assert_eq!(context_after_stable, context_after_recovery);
    assert_eq!(
        read_empty_r9a3_verdict_oracle(root.path()),
        verdict_after_kill
    );
    assert!(
        !r9a3d_path(root.path(), R9A3D_FORBIDDEN_CONNECTION_FILE).exists(),
        "D2 must not open any second native send connection"
    );
    assert!(
        !r9a3d_path(root.path(), R9A3D_FORBIDDEN_SEND_FILE).exists(),
        "D2 must not emit any second complete send request"
    );

    shutdown_fixture_child(&mut daemon_two, "R-9A.3d D2 daemon").await;
    assert!(
        witness
            .try_wait()
            .expect("inspect R-9A.3d witness before cleanup")
            .is_none()
    );
    let witness_status = witness.hard_kill();
    assert!(!witness_status.success());
    let final_reader = R9a3SideEffectReader::open_existing(root.path(), &witness_instance)
        .expect("open final R-9A.3d external effect oracle");
    assert_eq!(final_reader.effect_count().expect("final effect count"), 1);
    let final_effect = final_reader
        .effect_for_dispatch(&request.dispatch_id)
        .expect("read final R-9A.3d effect")
        .expect("final R-9A.3d effect exists");
    assert_eq!(final_effect.request, request);
    assert_eq!(final_effect.original_ack(), original_ack);
    assert!(!r9a3d_path(root.path(), R9A3D_FORBIDDEN_CONNECTION_FILE).exists());
    assert!(!r9a3d_path(root.path(), R9A3D_FORBIDDEN_SEND_FILE).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8b2c_begin_delivery_hard_kill_recovers_unknown_without_resend_or_poll() {
    let root = std::env::temp_dir().join(format!("egopulse-r8b2c-begin-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-8B.2c begin-delivery fixture root");
    let instance = format!("r8b2c-begin-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, R8B2C_BEGIN_DELIVERY_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut child).await;
    let prepared = prepare_and_confirm_r8b2c_work(&root, &instance, "r8b2c-begin").await;
    let task_id = prepared.task_id;

    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R8B2C_BEGIN_DELIVERY_PHASE,
        &mut child,
    )
    .await;
    let task_before_kill =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Active, &mut child).await;
    assert_eq!(
        task_before_kill["data"]["currentRunId"],
        R8A_ACTIVATION_RUN_ID
    );

    let witness = R8b2cWitnessOracle::open_existing(&root, &instance);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 0);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state("r8a-dispatch"),
        Some(("pending".to_owned(), 0))
    );

    let adapter = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter.dispatch_count, 1);
    assert_eq!(adapter.delivery_unknown_count, 1);
    assert_eq!(adapter.observation_count, 0);
    assert_eq!(adapter.pending_observation_count, 0);
    assert_eq!(adapter.dispatch_state, "delivery_unknown");
    assert!(adapter.receipt.is_none());
    assert!(adapter.receipt_bytes.is_none());
    assert_eq!(adapter.envelope.dispatch_id, "r8a-dispatch");

    let collaboration = read_r8b2c_collaboration_oracle(&root);
    assert_eq!(collaboration.outbox_state, "pending");
    assert_eq!(collaboration.run.status, RunStatus::Active as i32);
    assert_eq!(collaboration.step.status, StepStatus::Active as i32);
    assert_eq!(
        collaboration.attempt.status,
        AttemptStatus::DispatchPending as i32
    );
    assert_eq!(
        collaboration.attempt.dispatch_id.as_deref(),
        Some(collaboration.envelope.dispatch_id.as_str())
    );

    hard_kill_r8b2c_child(&mut child, R8B2C_BEGIN_DELIVERY_PHASE).await;

    let mut restarted =
        spawn_fixture_with_mode(&root, &instance, R8B2C_UNKNOWN_RECOVERY_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;
    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R8B2C_UNKNOWN_RECOVERED_PHASE,
        &mut restarted,
    )
    .await;

    let interrupted =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Interrupted, &mut restarted)
            .await;
    assert_eq!(interrupted["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 1);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state("r8a-dispatch"),
        Some(("pending".to_owned(), 0))
    );

    let adapter = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter.dispatch_count, 1);
    assert_eq!(adapter.delivery_unknown_count, 1);
    assert_eq!(adapter.observation_count, 1);
    assert_eq!(adapter.pending_observation_count, 1);
    let unknown_receipt = adapter
        .receipt
        .as_ref()
        .expect("Unknown recovery must persist an Adapter receipt");
    assert_eq!(
        DeliveryDisposition::try_from(unknown_receipt.disposition),
        Ok(DeliveryDisposition::Unknown)
    );
    let reconciliation_key = "reconciliation:adapter-reconciliation:r8a-dispatch";
    let reconciliation = adapter
        .observations
        .iter()
        .find(|observation| observation.native_key == reconciliation_key)
        .expect("OutcomeUnknown reconciliation evidence must be durable");
    assert_eq!(reconciliation.dispatch_id, "r8a-dispatch");
    assert_eq!(reconciliation.ingestion_state, "pending");
    assert!(!reconciliation.raw_event.is_empty());
    assert!(matches!(
        reconciliation.observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code == "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN"
    ));
    let collaboration = read_r8b2c_collaboration_oracle(&root);
    assert_eq!(collaboration.outbox_state, "held");
    assert_eq!(collaboration.run.status, RunStatus::Held as i32);
    assert_eq!(collaboration.step.status, StepStatus::Held as i32);
    assert_eq!(collaboration.attempt.status, AttemptStatus::Held as i32);
    assert_eq!(
        collaboration.attempt.recovery_class,
        RecoveryClass::ManualOnly as i32
    );
    assert_eq!(
        collaboration.run.hold_reason_code.as_deref(),
        Some("MANUAL_RECOVERY_REQUIRED")
    );
    assert_eq!(
        collaboration.step.hold_reason_code.as_deref(),
        Some("MANUAL_RECOVERY_REQUIRED")
    );
    assert_eq!(
        collaboration.attempt.hold_reason_code.as_deref(),
        Some("MANUAL_RECOVERY_REQUIRED")
    );

    let stable_counts = (
        witness.ledger_count("send_dispatch"),
        witness.ledger_count("next_event"),
        witness.ledger_count("reconcile"),
        witness.ledger_count("ack_emitted"),
    );
    sleep(Duration::from_millis(175)).await;
    assert_eq!(
        (
            witness.ledger_count("send_dispatch"),
            witness.ledger_count("next_event"),
            witness.ledger_count("reconcile"),
            witness.ledger_count("ack_emitted"),
        ),
        stable_counts,
        "Held ManualOnly recovery must not resend, poll, reconcile again, or emit the native ACK"
    );

    drop(restarted.stdin.take());
    let status = restarted
        .wait()
        .await
        .expect("wait for R-8B.2c Unknown recovery child");
    assert!(status.success(), "R-8B.2c recovery child failed: {status}");
    let owner_oracle = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(owner_oracle.snapshot.task_id, task_id);
    assert_eq!(owner_oracle.snapshot.status, TaskStatus::Interrupted as i32);
    assert_eq!(
        owner_oracle.snapshot.current_run_id.as_deref(),
        Some(R8A_ACTIVATION_RUN_ID)
    );
    fs::remove_dir_all(&root).expect("remove R-8B.2c begin-delivery fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8b2c_delivered_before_poll_hard_kill_rehydrates_ack_without_resend() {
    let root = std::env::temp_dir().join(format!("egopulse-r8b2c-delivered-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-8B.2c delivered fixture root");
    let instance = format!("r8b2c-delivered-{}", Uuid::now_v7());
    let mut child =
        spawn_fixture_with_mode(&root, &instance, R8B2C_DELIVERED_BEFORE_POLL_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut child).await;
    let prepared = prepare_and_confirm_r8b2c_work(&root, &instance, "r8b2c-delivered").await;
    let task_id = prepared.task_id;
    let snapshot_id = prepared.snapshot_id;

    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R8B2C_DELIVERED_BEFORE_POLL_PHASE,
        &mut child,
    )
    .await;
    let active =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Active, &mut child).await;
    assert_eq!(active["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID);

    let witness = R8b2cWitnessOracle::open_existing(&root, &instance);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 0);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state("r8a-dispatch"),
        Some(("pending".to_owned(), 0))
    );

    let adapter_before_revoke = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter_before_revoke.dispatch_count, 1);
    assert_eq!(adapter_before_revoke.delivery_unknown_count, 0);
    assert_eq!(adapter_before_revoke.observation_count, 0);
    assert_eq!(adapter_before_revoke.pending_observation_count, 0);
    assert_eq!(adapter_before_revoke.dispatch_state, "delivered");
    let receipt_bytes_before_revoke = adapter_before_revoke
        .receipt_bytes
        .clone()
        .expect("Delivered receipt bytes must exist before Context revoke");
    let receipt_before_kill = adapter_before_revoke
        .receipt
        .clone()
        .expect("Delivered receipt must exist before checkpoint");
    assert_eq!(
        DeliveryDisposition::try_from(receipt_before_kill.disposition),
        Ok(DeliveryDisposition::Delivered)
    );
    let collaboration_before_revoke = read_r8b2c_collaboration_oracle(&root);
    assert_eq!(collaboration_before_revoke.outbox_state, "delivered");
    assert_eq!(
        collaboration_before_revoke.run.status,
        RunStatus::Active as i32
    );
    assert_eq!(
        collaboration_before_revoke.step.status,
        StepStatus::Active as i32
    );
    assert_eq!(
        collaboration_before_revoke.attempt.status,
        AttemptStatus::Dispatched as i32
    );
    let task_before_revoke = read_r8b2c_task_oracle(&root, &task_id);
    let verdict_before_revoke = read_empty_r9a3_verdict_oracle(&root);

    let preview = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "delivered-dispatch-revoked",
            "--evidence-ref",
            "evidence:r9a:delivered-before-poll",
            "--confirmation-proof-ref",
            "proof:r9a:founder-confirmation",
            "--idempotency-key",
            "r9a-gate7-delivered-revoke",
            "--preview",
            "--json",
        ],
    )
    .await;
    assert!(preview.status.success());
    let preview_json: serde_json::Value =
        serde_json::from_slice(&preview.stdout).expect("decode Gate 7 revoke preview");
    let revoke_digest = preview_json["data"]["requestDigestSha256"]
        .as_str()
        .expect("Gate 7 revoke digest")
        .to_owned();
    let revoke = run_cli(
        &instance,
        &[
            "context",
            "revoke",
            &snapshot_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "delivered-dispatch-revoked",
            "--evidence-ref",
            "evidence:r9a:delivered-before-poll",
            "--confirmation-proof-ref",
            "proof:r9a:founder-confirmation",
            "--idempotency-key",
            "r9a-gate7-delivered-revoke",
            "--confirm-digest",
            &revoke_digest,
            "--json",
        ],
    )
    .await;
    assert!(
        revoke.status.success(),
        "Gate 7 revoke failed: stdout={} stderr={}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );
    let adapter_after_revoke = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter_after_revoke, adapter_before_revoke);
    assert_eq!(
        adapter_after_revoke.receipt_bytes.as_deref(),
        Some(receipt_bytes_before_revoke.as_slice())
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root),
        collaboration_before_revoke
    );
    assert_eq!(read_r8b2c_task_oracle(&root, &task_id), task_before_revoke);
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);

    hard_kill_r8b2c_child(&mut child, R8B2C_DELIVERED_BEFORE_POLL_PHASE).await;

    let mut restarted = spawn_fixture_with_mode(&root, &instance, R8B2C_ACK_RECOVERY_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;
    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        "r8a-dispatch",
        R8B2C_ACK_REHYDRATED_PHASE,
        &mut restarted,
    )
    .await;

    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("reconcile"), 0);
    assert_eq!(witness.ledger_count("ack_emitted"), 1);
    assert!(witness.ledger_count("next_event") >= 1);
    assert_eq!(
        witness.native_event_state("r8a-dispatch"),
        Some(("emitted".to_owned(), 1))
    );

    let adapter = read_r8b2c_adapter_oracle(&root);
    assert_eq!(adapter.dispatch_count, 1);
    assert_eq!(adapter.delivery_unknown_count, 0);
    assert_eq!(adapter.observation_count, 1);
    assert_eq!(adapter.pending_observation_count, 0);
    assert_eq!(adapter.dispatch_state, "delivered");
    let receipt_after_restart = adapter
        .receipt
        .clone()
        .expect("Delivered receipt remains durable");
    assert_eq!(
        DeliveryDisposition::try_from(receipt_after_restart.disposition),
        Ok(DeliveryDisposition::Delivered)
    );
    assert_eq!(receipt_after_restart, receipt_before_kill);
    assert_eq!(
        receipt_after_restart.encode_to_vec(),
        receipt_before_kill.encode_to_vec(),
        "restart must preserve the exact protobuf bytes of the original Delivered receipt"
    );

    let observation = adapter
        .observations
        .iter()
        .find(|observation| observation.native_key == "fake-ack")
        .expect("original FakeCodexDriver ACK row must remain durable");
    let observation_id = &observation.observation_id;
    assert_eq!(observation.dispatch_id, "r8a-dispatch");
    assert_eq!(observation.ingestion_state, "consumed");
    assert_eq!(observation.observation.observation_id, *observation_id);
    assert_eq!(observation.observation.dispatch_id, observation.dispatch_id);
    assert!(matches!(
        observation.observation.payload,
        Some(harness_observation::Payload::Ack(ref ack))
            if ack.ack_receipt_id == "fake-ack-r8a-dispatch"
    ));
    assert_eq!(observation.raw_event, b"fake-ack");
    assert_eq!(
        observation.native_event_digest_sha256,
        format!("{:x}", Sha256::digest(observation.raw_event.as_slice()))
    );
    assert!(!observation.raw_evidence_ref.trim().is_empty());

    let collaboration = read_r8b2c_collaboration_oracle(&root);
    assert_eq!(collaboration.outbox_state, "delivered");
    assert_eq!(collaboration.run.status, RunStatus::Active as i32);
    assert_eq!(collaboration.step.status, StepStatus::Active as i32);
    assert_eq!(
        collaboration.attempt.status,
        AttemptStatus::Acknowledged as i32
    );
    assert_eq!(collaboration.attempt.last_harness_sequence, 1);
    let task_before_stable = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(
        task_before_stable.snapshot.status,
        TaskStatus::Active as i32
    );
    assert_eq!(
        task_before_stable.snapshot.current_run_id,
        Some(R8A_ACTIVATION_RUN_ID.to_string())
    );
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    let stable_counts = (
        witness.ledger_count("send_dispatch"),
        witness.ledger_count("reconcile"),
        witness.ledger_count("ack_emitted"),
    );
    sleep(Duration::from_millis(175)).await;
    let adapter_after_stable = read_r8b2c_adapter_oracle(&root);
    let collaboration_after_stable = read_r8b2c_collaboration_oracle(&root);
    let task_after_stable = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(adapter_after_stable, adapter);
    assert_eq!(collaboration_after_stable, collaboration);
    assert_eq!(task_after_stable, task_before_stable);
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    assert_eq!(
        (
            witness.ledger_count("send_dispatch"),
            witness.ledger_count("reconcile"),
            witness.ledger_count("ack_emitted"),
        ),
        stable_counts,
        "Delivered recovery stable window must not resend, reconcile, or emit another ACK"
    );
    let active =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Active, &mut restarted).await;
    assert_eq!(active["data"]["currentRunId"], R8A_ACTIVATION_RUN_ID);

    drop(restarted.stdin.take());
    let status = restarted
        .wait()
        .await
        .expect("wait for R-8B.2c ACK recovery child");
    assert!(
        status.success(),
        "R-8B.2c ACK recovery child failed: {status}"
    );
    fs::remove_dir_all(&root).expect("remove R-8B.2c delivered fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_05_real_desktop_surface_uses_shared_kernel_for_read_and_writes() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-05-desktop-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 Desktop fixture root");
    let instance = format!("c5-05-desktop-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    wait_for_cli_status(&instance).await;

    let mut attachment = None;
    let mut last_attach_error = String::from("Desktop attachment did not start");
    for _ in 0..80 {
        match egopulse_client_operations::attach(
            &instance,
            ClientSurface::Desktop,
            format!("egopulse-desktop-test-{}", Uuid::now_v7()),
        )
        .await
        {
            Ok(value) => {
                attachment = Some(value);
                break;
            }
            Err(error) => {
                last_attach_error = error.to_string();
                assert!(
                    !last_attach_error.contains("permission"),
                    "Desktop session must not fail because of surface-specific permissions: {last_attach_error}"
                );
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let attachment = match attachment {
        Some(value) => value,
        None => {
            panic!("Desktop attachment should become ready within timeout: {last_attach_error}")
        }
    };
    assert!(
        !last_attach_error.contains("permission"),
        "Desktop attachment failed with a permission error: {last_attach_error}"
    );
    let projection = attachment
        .read_projection_snapshot()
        .await
        .expect("Desktop must read the same authenticated projection as CLI/TUI");
    assert_eq!(
        projection.metadata.health, 1,
        "Desktop projection must be ready"
    );
    assert!(
        projection
            .tasks
            .iter()
            .filter_map(|view| view.task.as_ref())
            .any(|task| task.task_id == "task-c5-03"),
        "Desktop projection must include the seeded governed task"
    );

    let desktop_task_id = format!("c5-05-desktop-task-{}", Uuid::now_v7());
    let correlation_id = Uuid::now_v7().to_string();
    let mut task_command = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(egopulse_client_operations::command_metadata(
                &correlation_id,
                "egopulse-desktop-test/task-create",
            )),
            work_type: desktop_task_id.clone(),
            input_snapshot_id: "input-c5-05-desktop".to_owned(),
            target_scope_ref: "scope-c5-05-desktop".to_owned(),
            acceptance_contract_ref: Some(
                egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                    contract_id: "acceptance-c5-05-desktop".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "44".repeat(32),
                },
            ),
            budget_profile_ref: Some(
                egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                    contract_id: "budget-c5-05-desktop".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "55".repeat(32),
                },
            ),
        })),
    };
    egopulse_client_operations::set_task_digest(&mut task_command);
    let task_metadata = attachment
        .metadata(Some(correlation_id))
        .expect("Desktop task metadata");
    let task_response = attachment
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(task_metadata),
            command: Some(task_command),
        })
        .await
        .expect("Desktop TaskCreate RPC")
        .into_inner();
    assert!(task_response.gateway_error.is_none());
    let task_result = task_response
        .authority_result
        .expect("Desktop TaskCreate authority result");
    let (created_task_id, task_revision) = match task_result.outcome {
        Some(
            egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(
                task,
            ),
        ) => (task.task_id, task.revision),
        _ => panic!("Desktop TaskCreate must return a task snapshot"),
    };
    let cancellation_correlation_id = Uuid::now_v7().to_string();
    let mut cancellation_command = TaskCommand {
        command: Some(task_command::Command::RequestTaskCancellation(
            RequestTaskCancellationCommand {
                meta: Some(egopulse_client_operations::command_metadata(
                    &cancellation_correlation_id,
                    "egopulse-desktop-test/task-cancel",
                )),
                task_id: created_task_id,
                expected_revision: task_revision,
                reason_code: "desktop-test-cancel".to_owned(),
            },
        )),
    };
    egopulse_client_operations::set_task_digest(&mut cancellation_command);
    let cancellation_response = attachment
        .connection
        .command_gateway_service()
        .execute_task_command(ExecuteTaskCommandRequest {
            client: Some(
                attachment
                    .metadata(Some(cancellation_correlation_id))
                    .expect("Desktop cancellation metadata"),
            ),
            command: Some(cancellation_command),
        })
        .await
        .expect("Desktop Task cancellation RPC")
        .into_inner();
    assert!(cancellation_response.gateway_error.is_none());
    let cancellation_result = cancellation_response
        .authority_result
        .expect("Desktop Task cancellation authority result");
    let cancellation_task = match cancellation_result.outcome {
        Some(
            egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(
                task,
            ),
        ) => task,
        Some(
            egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Error(
                error,
            ),
        ) => panic!(
            "Desktop Task cancellation must return a task snapshot, got {}",
            error.safe_detail_code
        ),
        _ => panic!("Desktop Task cancellation must return a task snapshot"),
    };
    assert_eq!(
        cancellation_task.status,
        TaskStatus::CancellationPending as i32
    );

    let retrieval_response = attachment
        .connection
        .cognition_service()
        .retrieve_memory(RetrieveMemoryRequest {
            client: Some(
                attachment
                    .metadata(Some(Uuid::now_v7().to_string()))
                    .expect("Desktop Memory retrieval metadata"),
            ),
            query: "Founder accepted governed Memory".to_owned(),
            scope_ref: "scope:founder".to_owned(),
            max_results: 8,
            min_score: 0.0,
        })
        .await
        .expect("Desktop Memory retrieval RPC")
        .into_inner();
    let retrieval_result = match retrieval_response.outcome {
        Some(retrieve_memory_response::Outcome::Result(result)) => result,
        Some(retrieve_memory_response::Outcome::Error(error)) => {
            panic!(
                "Desktop Memory retrieval was rejected: {}",
                error.safe_fingerprint
            )
        }
        None => panic!("Desktop Memory retrieval outcome is missing"),
    };
    assert_eq!(retrieval_result.algorithm_id, "lexical-overlap-v0");
    assert!(
        retrieval_result
            .candidates
            .iter()
            .any(|candidate| candidate.memory_id == "memory-c5-accepted")
    );
    assert!(
        retrieval_result
            .evidence_ref
            .starts_with("memory-rag-evidence-sha256:")
    );

    let memory_id = format!("c5-05-desktop-memory-{}", Uuid::now_v7());
    let memory_metadata = attachment
        .metadata(Some(Uuid::now_v7().to_string()))
        .expect("Desktop Memory metadata");
    let memory_response = attachment
        .connection
        .command_gateway_service()
        .execute_memory_mutation(ExecuteMemoryMutationRequest {
            client: Some(memory_metadata.clone()),
            command: Some(MemoryMutationCommand {
                command: Some(memory_mutation_command::Command::SubmitMemoryCandidate(
                    egopulse_domain_contracts::v01::egopulse::localapi::v1::SubmitMemoryCandidateCommand {
                        metadata: Some(memory_metadata),
                        memory_id: memory_id.clone(),
                        content: "Desktop shared-kernel memory candidate".to_owned(),
                        source_ref: "source:c5-05-desktop".to_owned(),
                        scope_ref: "scope:founder".to_owned(),
                        idempotency_key: "c5-05-desktop-memory-candidate".to_owned(),
                    },
                )),
            }),
        })
        .await
        .expect("Desktop Memory candidate RPC")
        .into_inner();
    assert!(memory_response.gateway_error.is_none());
    let memory_receipt = memory_response
        .authority_result
        .expect("Desktop Memory candidate receipt");
    assert_eq!(memory_receipt.memory_id, memory_id);
    assert_eq!(memory_receipt.revision, 1);
    assert_eq!(memory_receipt.state, "candidate");
    assert!(memory_receipt.acknowledged_after_durability_barrier);

    drop(child.stdin.take());
    let status = child.wait().await.expect("C5 Desktop fixture child exit");
    assert!(
        status.success(),
        "C5 Desktop fixture child failed: {status}"
    );
    fs::remove_dir_all(&root).expect("remove C5 Desktop fixture root");
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
async fn c5_04_real_cli_fails_closed_on_daemon_restart_and_reconnects() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-04-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 recovery fixture root");
    let instance = format!("c5-04-{}", Uuid::now_v7());
    let mut child = spawn_fixture(&root, &instance).await;

    let first_status = wait_for_cli_status(&instance).await;
    let first_json: serde_json::Value =
        serde_json::from_slice(&first_status.stdout).expect("first status JSON envelope");
    assert_eq!(first_json["ok"], true);

    child.kill().await.expect("terminate fixture daemon");
    let child_status = child.wait().await.expect("fixture daemon termination");
    assert!(
        !child_status.success(),
        "fixture must be externally terminated"
    );

    let unavailable = run_cli(&instance, &["status", "--json"]).await;
    assert_eq!(unavailable.status.code(), Some(3));
    let unavailable_json: serde_json::Value =
        serde_json::from_slice(&unavailable.stdout).expect("daemon unavailable JSON envelope");
    assert_eq!(unavailable_json["ok"], false);
    assert_eq!(unavailable_json["operation"], "status");
    assert_eq!(unavailable_json["error"]["code"], "DAEMON_UNAVAILABLE");
    assert_eq!(unavailable_json["data"], serde_json::Value::Null);

    let mut restarted = spawn_fixture(&root, &instance).await;
    let restarted_status = wait_for_cli_status(&instance).await;
    let restarted_json: serde_json::Value =
        serde_json::from_slice(&restarted_status.stdout).expect("restarted status JSON envelope");
    assert_eq!(restarted_json["ok"], true);
    assert_eq!(restarted_json["operation"], "status");

    drop(restarted.stdin.take());
    let status = restarted
        .wait()
        .await
        .expect("restarted fixture child exit");
    assert!(status.success(), "restarted fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove C5 recovery fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_04_real_cli_rejects_malformed_await_and_stale_approval_without_partial_commit() {
    let root = std::env::temp_dir().join(format!(
        "egopulse-c5-04-contract-recovery-{}",
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root).expect("create C5 contract recovery fixture root");
    let instance = format!("c5-04-contract-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    let ready = wait_for_cli_status(&instance).await;
    assert!(ready.status.success());

    let malformed = run_cli(
        &instance,
        &["await", "--token-json", r#"{"token":"broken"}"#, "--json"],
    )
    .await;
    assert_eq!(malformed.status.code(), Some(70));
    let malformed_json: serde_json::Value =
        serde_json::from_slice(&malformed.stdout).expect("malformed await JSON envelope");
    assert_eq!(malformed_json["operation"], "await");
    assert_eq!(malformed_json["error"]["code"], "LOCAL_API_PROTOCOL_ERROR");
    assert_eq!(malformed_json["data"], serde_json::Value::Null);

    let stale = run_cli(
        &instance,
        &[
            "approval",
            "decide",
            "approval-c5-03",
            "--expected-action-digest-sha256",
            &"33".repeat(32),
            "--expected-request-observation-id",
            "observation-c5-03",
            "--expected-request-observation-sequence",
            "1",
            "--expected-request-revision",
            "2",
            "--decision",
            "allow-once",
            "--reason-code",
            "c5-04-stale",
            "--confirmation-proof-ref",
            "confirmation-c5-04-stale",
            "--json",
        ],
    )
    .await;
    assert_eq!(stale.status.code(), Some(6));
    let stale_json: serde_json::Value =
        serde_json::from_slice(&stale.stdout).expect("stale approval JSON envelope");
    assert_eq!(stale_json["operation"], "approval.decide");
    assert_eq!(stale_json["error"]["code"], "POLICY_AUTHORITY_REJECTED");
    assert_eq!(stale_json["data"], serde_json::Value::Null);

    let accepted = run_cli(
        &instance,
        &[
            "approval",
            "decide",
            "approval-c5-03",
            "--expected-action-digest-sha256",
            &"33".repeat(32),
            "--expected-request-observation-id",
            "observation-c5-03",
            "--expected-request-observation-sequence",
            "1",
            "--expected-request-revision",
            "1",
            "--decision",
            "allow-once",
            "--reason-code",
            "c5-04-accepted-after-stale",
            "--confirmation-proof-ref",
            "confirmation-c5-04-accepted",
            "--json",
        ],
    )
    .await;
    assert!(
        accepted.status.success(),
        "stale rejection must not consume the approval: stdout={} stderr={}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted_json: serde_json::Value =
        serde_json::from_slice(&accepted.stdout).expect("accepted approval JSON envelope");
    assert_eq!(accepted_json["data"]["committed"], true);
    assert_eq!(accepted_json["data"]["replayed"], false);

    drop(child.stdin.take());
    let status = child.wait().await.expect("fixture child exit");
    assert!(status.success(), "fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove C5 contract recovery fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u01b_real_daemon_production_controller_observes_without_task_mutation() {
    let root = std::env::temp_dir().join(format!("egopulse-u01b-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-01b fixture root");
    let instance = format!("u01b-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    let _status_output = wait_for_cli_status_with_child(&instance, &mut child).await;

    let tui_output = run_tui_once(&instance).await;
    assert!(
        tui_output.status.success(),
        "TUI baseline must use the real daemon: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_output.stdout),
        String::from_utf8_lossy(&tui_output.stderr)
    );

    let attachment = Arc::new(
        attach_client_operation(
            &instance,
            ClientSurface::Tui,
            format!("egopulse-tui-u01b-{}", Uuid::now_v7()),
        )
        .await
        .expect("attach the production TUI client kernel"),
    );
    let mut controller = TaskWatchController::new(Arc::clone(&attachment));
    controller
        .start()
        .await
        .expect("production controller installs a complete baseline and resumes from it");
    assert!(controller.is_running());

    let acceptance_sha = "91".repeat(32);
    let budget_sha = "92".repeat(32);
    let mutation = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "task-create",
            "--work-type",
            "u01b-tui-watch",
            "--input-snapshot-id",
            "input-u01b-tui-watch",
            "--target-scope-ref",
            "scope-u01b-tui-watch",
            "--acceptance-contract-id",
            "acceptance-u01b-tui-watch",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            acceptance_sha.as_str(),
            "--budget-profile-id",
            "budget-u01b-tui-watch",
            "--budget-profile-version",
            "v0.1",
            "--budget-profile-sha256",
            budget_sha.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        mutation.status.success(),
        "governed TUI mutation must trigger the projection: stdout={} stderr={}",
        String::from_utf8_lossy(&mutation.stdout),
        String::from_utf8_lossy(&mutation.stderr)
    );
    let mutation_json: serde_json::Value =
        serde_json::from_slice(&mutation.stdout).expect("TUI mutation JSON envelope");
    let created_task_id = mutation_json["data"]["taskId"]
        .as_str()
        .expect("created Task id")
        .to_owned();
    let after_external_write = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = attachment
                .read_projection_snapshot()
                .await
                .expect("read projection after governed external mutation");
            if snapshot.tasks.iter().any(|view| {
                view.task
                    .as_ref()
                    .is_some_and(|task| task.task_id == created_task_id)
            }) {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("governed Task becomes visible in the complete projection");
    let durable_before_controller_pump = read_r8b2c_task_oracle(&root, &created_task_id);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            controller
                .pump()
                .await
                .expect("production controller validates the daemon update");
            if controller.model().is_some_and(|model| {
                model.tasks.iter().any(|view| {
                    view.task
                        .as_ref()
                        .is_some_and(|task| task.task_id == created_task_id)
                })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production controller receives the governed Task projection update");
    let controller_model = controller
        .model()
        .expect("controller retains its authoritative page model");
    let controller_target = controller_model
        .tasks
        .iter()
        .filter_map(|view| view.task.as_ref())
        .find(|task| task.task_id == created_task_id)
        .expect("controller page contains the governed Task");
    assert_ne!(
        controller_target.status,
        TaskStatus::Completed as i32,
        "observation-only production controller must not false-complete the target Task"
    );
    assert_eq!(
        controller_target, &durable_before_controller_pump.snapshot,
        "controller page must render the exact durable Task Authority snapshot"
    );
    let after = attachment
        .read_projection_snapshot()
        .await
        .expect("read Task projection after observation-only watch");
    assert_eq!(
        after.tasks, after_external_write.tasks,
        "consuming Task Watch must not mutate Tasks beyond the separately committed governed command"
    );
    assert_eq!(
        controller_model.tasks, after.tasks,
        "production controller page facts must equal the Authority-backed projection"
    );
    let target = after
        .tasks
        .iter()
        .filter_map(|view| view.task.as_ref())
        .find(|task| task.task_id == created_task_id)
        .expect("target Task remains in the post-watch projection");
    assert_ne!(target.status, TaskStatus::Completed as i32);
    assert_eq!(
        read_r8b2c_task_oracle(&root, &created_task_id),
        durable_before_controller_pump,
        "baseline/start/pump/stop observation must not change the durable Task snapshot or event count"
    );
    controller.stop().await;
    assert!(!controller.is_running());

    drop(child.stdin.take());
    let status = child.wait().await.expect("U-01b fixture child exit");
    assert!(status.success(), "U-01b fixture child failed: {status}");
    fs::remove_dir_all(&root).expect("remove U-01b fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_03_real_cli_process_completes_owner_writes_and_awaits_projection() {
    let root = std::env::temp_dir().join(format!("egopulse-c5-03-allow-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create C5 successful CLI fixture root");
    let instance = format!("c5-03-allow-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    let _status_output = wait_for_cli_status_with_child(&instance, &mut child).await;

    let tui_output = run_tui_once(&instance).await;
    assert!(
        tui_output.status.success(),
        "TUI must attach to the same daemon kernel: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_output.stdout),
        String::from_utf8_lossy(&tui_output.stderr)
    );
    let tui_stdout = String::from_utf8_lossy(&tui_output.stdout);
    assert!(tui_stdout.contains("EgoPulse TUI: connected"));
    assert!(
        tui_stdout.contains("workflow=RUN_STATUS_RETURN_PENDING"),
        "TUI must render the governed workflow state from TaskView: {tui_stdout}"
    );
    assert!(
        tui_stdout.contains("return_pending_steps=1"),
        "TUI must render the pending return count from TaskView: {tui_stdout}"
    );
    assert!(
        tui_stdout.contains("returned_steps=0"),
        "TUI must render the returned-step count from TaskView: {tui_stdout}"
    );

    let cli_task_output = run_cli(&instance, &["task", "get", "task-c5-03", "--json"]).await;
    assert!(
        cli_task_output.status.success(),
        "CLI must read the seeded governed TaskView: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_task_output.stdout),
        String::from_utf8_lossy(&cli_task_output.stderr)
    );
    let cli_task_json: serde_json::Value =
        serde_json::from_slice(&cli_task_output.stdout).expect("CLI TaskView JSON envelope");
    assert_eq!(
        cli_task_json["data"]["collaboration"]["runStatus"],
        "RUN_STATUS_RETURN_PENDING"
    );
    assert_eq!(
        cli_task_json["data"]["collaboration"]["returnPendingSteps"],
        1
    );
    assert_eq!(cli_task_json["data"]["collaboration"]["returnedSteps"], 0);
    assert_eq!(cli_task_json["data"]["currentRunId"], "c5-run");

    let tui_acceptance_sha = "44".repeat(32);
    let tui_budget_sha = "55".repeat(32);
    let tui_task_output = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "task-create",
            "--work-type",
            "c5-03-tui",
            "--input-snapshot-id",
            "input-c5-03-tui",
            "--target-scope-ref",
            "scope-c5-03-tui",
            "--acceptance-contract-id",
            "acceptance-c5-03-tui",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            tui_acceptance_sha.as_str(),
            "--budget-profile-id",
            "budget-c5-03-tui",
            "--budget-profile-version",
            "v0.1",
            "--budget-profile-sha256",
            tui_budget_sha.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        tui_task_output.status.success(),
        "TUI task create must use the governed client kernel: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_task_output.stdout),
        String::from_utf8_lossy(&tui_task_output.stderr)
    );
    let tui_task_json: serde_json::Value =
        serde_json::from_slice(&tui_task_output.stdout).expect("TUI task JSON envelope");
    assert_eq!(tui_task_json["operation"], "task.create");
    assert_eq!(tui_task_json["data"]["replayed"], false);
    let tui_task_id = tui_task_json["data"]["taskId"]
        .as_str()
        .expect("TUI created task id");

    let tui_apply_output = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "task-apply-verdict",
            tui_task_id,
            "--expected-revision",
            "1",
            "--work-revision",
            "1",
            "missing-founder-verdict-c5-03-tui",
            "--json",
        ],
    )
    .await;
    assert_eq!(
        tui_apply_output.status.code(),
        Some(3),
        "TUI apply-verdict must reach the real daemon and fail closed for a Draft Task: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_apply_output.stdout),
        String::from_utf8_lossy(&tui_apply_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&tui_apply_output.stderr).contains("TASK_STATUS_INVALID")
            || String::from_utf8_lossy(&tui_apply_output.stderr)
                .contains("TASK_NOT_VERDICT_PENDING")
            || String::from_utf8_lossy(&tui_apply_output.stderr)
                .contains("TRANSITION_STATE_CONFLICT")
            || String::from_utf8_lossy(&tui_apply_output.stderr)
                .contains("TRANSITION_REFERENCE_UNVERIFIED"),
        "TUI apply-verdict must preserve the typed Task rejection: stderr={}",
        String::from_utf8_lossy(&tui_apply_output.stderr)
    );

    let tui_evidence_output = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "evidence-get",
            tui_task_id,
            "--artifact-set-id",
            "missing-c5-03-tui-evidence",
            "--json",
        ],
    )
    .await;
    assert_eq!(
        tui_evidence_output.status.code(),
        Some(3),
        "TUI evidence read must fail closed for a missing graph: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_evidence_output.stdout),
        String::from_utf8_lossy(&tui_evidence_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&tui_evidence_output.stderr).contains("NOT_FOUND"),
        "TUI evidence read must preserve the typed not-found error: stderr={}",
        String::from_utf8_lossy(&tui_evidence_output.stderr)
    );

    let task_watch = run_cli(&instance, &["task", "watch", "--frames", "1", "--json"]).await;
    assert!(
        task_watch.status.success(),
        "Task watch must consume the frozen stream: stdout={} stderr={}",
        String::from_utf8_lossy(&task_watch.stdout),
        String::from_utf8_lossy(&task_watch.stderr)
    );
    let task_watch_json: serde_json::Value =
        serde_json::from_slice(&task_watch.stdout).expect("Task watch JSON envelope");
    assert_eq!(task_watch_json["operation"], "task.watch");
    assert_eq!(
        task_watch_json["data"]["kind"],
        "STREAM_FRAME_KIND_HEARTBEAT"
    );

    let approval_watch =
        run_cli(&instance, &["approval", "watch", "--frames", "1", "--json"]).await;
    assert!(
        approval_watch.status.success(),
        "Approval watch must consume the frozen stream: stdout={} stderr={}",
        String::from_utf8_lossy(&approval_watch.stdout),
        String::from_utf8_lossy(&approval_watch.stderr)
    );
    let approval_watch_json: serde_json::Value =
        serde_json::from_slice(&approval_watch.stdout).expect("Approval watch JSON envelope");
    assert_eq!(approval_watch_json["operation"], "approval.watch");
    assert_eq!(
        approval_watch_json["data"]["kind"],
        "STREAM_FRAME_KIND_HEARTBEAT"
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

    let cli_apply_output = run_cli(
        &instance,
        &[
            "task",
            "apply-verdict",
            task_id,
            "--expected-revision",
            "1",
            "--work-revision",
            "1",
            "missing-founder-verdict-c5-03-cli",
            "--json",
        ],
    )
    .await;
    assert_eq!(
        cli_apply_output.status.code(),
        Some(6),
        "CLI apply-verdict must reach the real daemon and fail closed for a Draft Task: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_apply_output.stdout),
        String::from_utf8_lossy(&cli_apply_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&cli_apply_output.stdout).contains("TASK_STATUS_INVALID")
            || String::from_utf8_lossy(&cli_apply_output.stdout)
                .contains("TASK_NOT_VERDICT_PENDING")
            || String::from_utf8_lossy(&cli_apply_output.stdout)
                .contains("TRANSITION_STATE_CONFLICT")
            || String::from_utf8_lossy(&cli_apply_output.stdout)
                .contains("TRANSITION_REFERENCE_UNVERIFIED")
            || String::from_utf8_lossy(&cli_apply_output.stdout)
                .contains("TASK_AUTHORITY_REJECTED"),
        "CLI apply-verdict must preserve the typed Task rejection: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_apply_output.stdout),
        String::from_utf8_lossy(&cli_apply_output.stderr)
    );
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

    let tui_verdict_output = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "verdict-issue",
            "--task-id",
            "task-c5-03",
            "--task-revision",
            "1",
            "--work-revision",
            "1",
            "--artifact-set-id",
            "artifact-c5-03-tui",
            "--artifact-set-manifest-sha256",
            "66c5a1f0a0fbcdbb7f47c8a3fbe2f31e3a6a6b5f8e3f5c0b8b5d86b5c9a4e102",
            "--artifact-set-manifest-byte-length",
            "128",
            "--verification-artifact-id",
            "verification-c5-03-tui",
            "--verification-payload-sha256",
            "77c5a1f0a0fbcdbb7f47c8a3fbe2f31e3a6a6b5f8e3f5c0b8b5d86b5c9a4e102",
            "--verification-payload-byte-length",
            "256",
            "--acceptance-contract-id",
            "acceptance-c5-03-tui",
            "--acceptance-contract-version",
            "v0.1",
            "--acceptance-contract-sha256",
            "88c5a1f0a0fbcdbb7f47c8a3fbe2f31e3a6a6b5f8e3f5c0b8b5d86b5c9a4e102",
            "--decision",
            "accept",
            "--observed-verification-conclusion",
            "passed",
            "--reason-code",
            "c5-03-tui-accepted",
            "--confirmation-class",
            "explicit",
            "--confirmation-proof-ref",
            "confirmation-c5-03",
            "--json",
        ],
    )
    .await;
    assert!(
        tui_verdict_output.status.success(),
        "TUI verdict issue must use the governed client kernel: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_verdict_output.stdout),
        String::from_utf8_lossy(&tui_verdict_output.stderr)
    );
    let tui_verdict_json: serde_json::Value =
        serde_json::from_slice(&tui_verdict_output.stdout).expect("TUI verdict JSON envelope");
    assert_eq!(tui_verdict_json["operation"], "verdict.issue");
    assert_eq!(tui_verdict_json["data"]["committed"], true);
    let tui_verdict_id = tui_verdict_json["data"]["founderVerdictId"]
        .as_str()
        .expect("TUI issued Founder Verdict id");
    let tui_verdict_revoke_output = run_tui(
        &instance,
        &[
            "--instance",
            instance.as_str(),
            "verdict-revoke",
            tui_verdict_id,
            "--expected-state-revision",
            "1",
            "--reason-code",
            "c5-03-tui-revoked",
            "--confirmation-proof-ref",
            "c5-03-founder-revoke-proof",
            "--json",
        ],
    )
    .await;
    assert!(
        tui_verdict_revoke_output.status.success(),
        "TUI verdict revoke must use the governed client kernel: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_verdict_revoke_output.stdout),
        String::from_utf8_lossy(&tui_verdict_revoke_output.stderr)
    );
    let tui_verdict_revoke_json: serde_json::Value =
        serde_json::from_slice(&tui_verdict_revoke_output.stdout)
            .expect("TUI verdict revoke JSON envelope");
    assert_eq!(tui_verdict_revoke_json["operation"], "verdict.revoke");
    assert_eq!(tui_verdict_revoke_json["data"]["committed"], true);

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
