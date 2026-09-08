#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command as StdCommand, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use egopulse_agentosd::{
    ArtifactAuthorityReferenceSource, ArtifactProjectionSource, AuthorityCompositionInputs,
    AuthorityPrincipalResolver, CollaborationProjectionSource, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredTaskTransitionGuard,
    ConfiguredWorkPreparationPort, ContextMutationPortAdapter, DaemonComposition, DaemonConfig,
    DaemonProviders, DenyVerificationReferences, GovernedReturnCollectorConfig,
    MemoryRetrievalCompositionConfig, NativeHarnessCompositionConfig,
    NativeHarnessCompositionProfile, OwnerProjectionSource, PendingOwnerProjection,
    ProfiledNativeHarnessComposition, ProjectionPump, ProjectionSourceFailure, ProviderAdmission,
    ProviderBootstrapProfile, ProviderCatalogSnapshot, ProviderCredentialReference,
    ProviderHarnessKind, ProviderId, ProviderModelBinding, SharedAuthorityCompositionInputs,
    VerificationProjectionSource, WorkCapabilityRegistry,
};
use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactPrincipalKind, ArtifactSqlCipherKey,
    AuthenticatedArtifactPrincipal, canonical_artifact_set_manifest,
    canonical_request_digest as canonical_artifact_request_digest, content_address,
};
use egopulse_client_kernel::{
    ClientKernel, KernelError, api_contract_ref, authorization_contract_ref,
};
use egopulse_client_operations::{
    ClientTaskResultReviewError, GovernedStateDomain, GuidedApprovalDecision,
    TaskResultReviewStage, attach as attach_client_operation,
};
use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_CAPABILITY_PROFILE_ID, FakeCodexDriver, codex_protocol_fingerprint,
    codex_user_visible_content_mutations,
};
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
        AuthenticatedPrincipal as AuthenticatedTaskPrincipal, CreationAuthorization,
        CreationGuardRejection, PrincipalKind as TaskPrincipalKind, SqlCipherKey, TaskAuthority,
        TaskAuthorityConfig, TaskCreationGuard, TaskProjectionMessage,
    },
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus,
        ArtifactStatus, Claim, ClaimSourceType, ClaimStatus, Evidence, EvidenceProducerClass,
        EvidenceRelation, EvidenceStatus, IntegrityStatus, LineageBinding, ProducerIdentity,
        Provenance, ReturnHandoff, ReturnHandoffStatus, SealArtifactCommand,
        SealArtifactSetCommand, StageArtifactCommand, SubmitReturnHandoffCommand, artifact_command,
    },
    collaboration::v1::{
        AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptCommandBase, AttemptSnapshot,
        AttemptStatus, CollaborationCommand, CollaborationEvent, CollaborationSnapshot,
        CommitStepReturnCommand, CreateAttemptCommand, CreateRunCommand, Lease,
        RecordAttemptReturnCommand, RecordDeliveryReceiptCommand, RecordDispatchIntentCommand,
        RecordHarnessAckCommand, RecordRunningObservationCommand, RecoveryClass, RunCommandBase,
        RunPlan, RunSnapshot, RunStatus, StepPlan, StepSnapshot, StepStatus, collaboration_command,
        collaboration_command_result,
    },
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::{
        AckDisposition, ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
        ApprovalRequestObservation, AttestationLevel, CancelExecutionEnvelope,
        CapabilityDeclaration, CapabilityProfile, CapabilityProfileStatus,
        ContentMutationOperation, DeliveryDisposition, DispatchEnvelope, HarnessAckObservation,
        HarnessContentSignalObservation, HarnessErrorCode, HarnessObservation, LifecycleKind,
        LifecycleObservation, NativeSessionStrategy, ObservationCriticality, ProbeHarnessRequest,
        ProbeHarnessResult, SideEffectCertainty, harness_observation,
    },
    localapi::v1::{
        ClientSurface, ConfirmWorkRequest, EvidenceGraphView, ExecuteMemoryMutationRequest,
        ExecuteTaskCommandRequest, HarnessApprovalView, LocalApiErrorCode, MemoryMutationCommand,
        OpenSessionRequest, PrepareWorkRequest, ProjectionPosition, RetrieveMemoryRequest,
        SourceRevision, StreamFrameKind, TaskView, WorkPreparationPreview,
        local_read_model_service_server::LocalReadModelServiceServer,
        local_session_service_client::LocalSessionServiceClient,
        local_session_service_server::LocalSessionServiceServer, memory_mutation_command,
        retrieve_memory_response,
    },
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        IssueHarnessApprovalDecisionCommand,
    },
    task::v1::{
        ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand,
        RecordTaskVerificationCommand, RequestTaskCancellationCommand, SubmitTaskEvidenceCommand,
        TaskCommand, TaskCommandResult, TaskEvent, TaskSnapshot, TaskStatus,
        WorkCapabilityRouteBinding, task_command,
    },
    verdict::v1::{
        ConfirmationClass, ConsumeFounderVerdictCommand, FounderVerdictDecision,
        FounderVerdictState, FounderVerdictStateKind, IssueFounderVerdictCommand, ReworkDirective,
        RiskAcceptance, RiskCategory, VerdictCommand, VerdictScope, verdict_command,
    },
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
        CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
        CriterionRequirement, CriterionResult, Discrepancy, DiscrepancySeverity, EvidenceCoverage,
        RecordCriterionResultCommand, StartVerificationRunCommand, UnverifiedItem,
        UnverifiedReason, VerificationArtifact, VerificationBinding, VerificationCommand,
        VerificationConclusion, VerificationProvenance, VerificationRequest, VerificationStatus,
        verification_command,
    },
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictSqlCipherKey,
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DriverDelivery, DriverError,
    DriverErrorCertainty, DriverEvent, ManagedDisclosureCredentials, NativeHarnessDriver,
    NativeHarnessFuture, ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
    TerminalOutputCandidate,
};
use egopulse_local_api::session::{
    FixedProjectionPosition, LocalSessionEndpoint, NoopSessionAuditSink, PrincipalGrant,
    PrincipalResolutionFailure, SessionConfig, TrustedPrincipalResolver,
};
use egopulse_local_api::{
    LocalApiClient,
    command_gateway::{
        CommandPortFailure, CommandPortResult, CommandPrincipal, WorkPreparationPort,
    },
    read_gateway::{NoopReadGatewayAuditSink, ReadGatewayApplication},
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{
        BlockingLocalReadModelReader, ProjectionCommitNotifier, ProjectionStatusReader,
        ReadModelAccessError, ReadModelReader, ReadModelStatus,
    },
    read_service::LocalReadModelEndpoint,
    read_tokens::{ReadTokenCodec, TokenMacKey},
};
use egopulse_local_ide_control::collaboration_control::{
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlConfig, CollaborationPrincipalKind, CollaborationReferenceGuard,
    CollaborationSqlCipherKey, DispatchMaterial, HarnessDispatchCycleError,
    HarnessDispatchCycleReport, HarnessDispatchRunner, HarnessEvidenceResolver, LeaseAuthorization,
    ReferenceAuthorization, ReferenceGuardRejection, ResolvedArtifactReturn,
    ResolvedHarnessEvidence, ResolvedStepReturn, SingleHarnessWorkConfig,
    TrustedDispatchRouteProfile, canonical_dispatch_fingerprint,
};
use egopulse_local_ipc_platform::{LocalIpcAddress, LocalIpcListener};
use egopulse_local_read_model::{
    ApprovalListFilter, ApprovalViewAccess, EvidenceGraphAccess, HistoricalPage, LocalReadModel,
    LocalReadModelConfig, LocalReadModelKey, StreamBatch, TaskListFilter, TaskViewAccess,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityConfig, PolicyDecisionAuthority,
    PolicyPrincipalKind, PolicyReferenceRejection, PolicySqlCipherKey,
    ResolvedApprovalAuthorization,
};
use egopulse_tui::{
    approval_queue::ApprovalQueueController,
    governed_state::{DomainView, GovernedStateController, GovernedStatePageModel},
    result_review::ResultReviewController,
    task_watch::{TaskWatchController, TaskWatchPhase},
    work_start::{WorkStartController, WorkStartStage},
};
use egopulse_v01_fault_conformance::memory_restart_oracle::MemoryRestartOracle;
use egopulse_v01_fault_conformance::r8b2c::{
    R8b2cNativeEventRecord, R8b2cWitnessReader, R8b2cWitnessWriter, read_r8b2c_adapter_store,
    read_r8b2c_collaboration_store, read_r8b2c_task_store, read_single_r8b2c_adapter_dispatch_id,
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
    R9a3ContextGovernanceState, R9a3VerdictAuthorityCounts, read_m13_memory_dispatch_pair,
    read_r9a3_context_authority_store, read_r9a3_verdict_authority_counts,
};
use egopulse_v01_fault_conformance::r9b_governed_state::read_r9b_governed_state_authorities;
use egopulse_v01_fault_conformance::u03c_result_review::{
    ExpectedStoreProfile, GovernedResultDurabilitySnapshot, GovernedResultOracleRequest,
    discover_single_task_id, read_governed_result_durability,
};
use egopulse_v01_fault_conformance::u04c_work_start::{
    U04cContextRecord, U04cTaskRecord, U04cWorkStartDurabilitySnapshot, U04cWorkStartOracleRequest,
    read_u04c_work_start_durability,
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, AuthenticatedVerificationPrincipal, CriterionPolicySnapshot,
    VerificationAuthority, VerificationAuthorityConfig, VerificationPrincipalKind,
    VerificationSqlCipherKey, canonical_checker_profile_digest,
    canonical_request_digest as canonical_verification_request_digest,
};
use portable_pty::{CommandBuilder as PtyCommandBuilder, PtySize, native_pty_system};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};
use tonic::transport::Server;
use uuid::Uuid;

const FIXTURE_ROOT_ENV: &str = "EGOPULSE_C5_FIXTURE_ROOT";
const FIXTURE_INSTANCE_ENV: &str = "EGOPULSE_C5_FIXTURE_INSTANCE";
const FIXTURE_MODE_ENV: &str = "EGOPULSE_C5_FIXTURE_MODE";
const R8A_FIXTURE_MODE: &str = "dynamic";
const R8B_PAUSE_BEFORE_RUNNER_MODE: &str = "dynamic-pause-before-runner";
const R8B2C_BEGIN_DELIVERY_MODE: &str = "dynamic-r8b2c-begin-delivery";
const R8B2C_UNKNOWN_RECOVERY_MODE: &str = "dynamic-r8b2c-unknown-recovery";
const R8B2C_DELIVERED_BEFORE_POLL_MODE: &str = "dynamic-r8b2c-delivered-before-poll";
const R9A3D_EXTERNAL_SEND_MODE: &str = "dynamic-r9a3d-external-send";
const R9A3D_EXTERNAL_RECOVERY_MODE: &str = "dynamic-r9a3d-external-recovery";
const R9A3E_PREAUTH_UNAVAILABLE_MODE: &str = "dynamic-r9a3e-preauth-unavailable";
const R9A3E_REVOKED_READY_MODE: &str = "dynamic-r9a3e-revoked-ready";
const R9C_CONTENT_MODE: &str = "dynamic-r9c-content";
const M13_MEMORY_DISPATCH_MODE: &str = "dynamic-m13-memory-dispatch";
const PHASE_ONE_MULTI_TASK_MODE: &str = "dynamic-phase-one-multi-task";
const PHASE_ONE_DRIVER_LEDGER: &str = "phase-one-driver-ledger.json";
const R9C_CONTENT_RELEASE_FILE: &str = "r9c-content-release";
const R9C_VISIBLE_PREFIX: &str = "R9C governed stream ";
const R9C_VISIBLE_SUFFIX: &str = "reaches both clients.";
const R9C_RAW_ONLY_CANARY: &str = "R9C_RAW_NATIVE_EVENT_NEVER_RENDER";
const R9C_MESSAGE_ID: &str = "r9c-agent-message";
const U03C_RESULT_REVIEW_MODE: &str = "u03c-result-review";
const U03C_RESULT_REVIEW_DENY_MODE: &str = "u03c-result-review-deny";
const U03C_RESULT_REVIEW_STALE_MODE: &str = "u03c-result-review-stale";
const R9B_GOVERNED_STATE_MODE: &str = "r9b-governed-state";
const R9B_DENY_TASK_READ_MODE: &str = "r9b-deny-task-read";
const R9B_DENY_APPROVAL_READ_MODE: &str = "r9b-deny-approval-read";
const R9B_TASK_SINGLE_DISCONNECT_MODE: &str = "r9b-task-single-disconnect";
const R9B_RETENTION_RESET_MODE: &str = "r9b-retention-reset";
const R9B_TASK_READER_CALLS_FILE: &str = "r9b-task-reader-calls.log";
const R9B_TASK_DISCONNECT_ARM_FILE: &str = "r9b-task-disconnect-arm";
const R9B_APPROVAL_ADVANCE_FILE: &str = "r9b-approval-advance";
const R9B_TASK_REBASELINE_RELEASE_FILE: &str = "r9b-task-rebaseline-release";
const R9B_ADVANCED_APPROVAL_ID: &str = "approval-r9b-task-disconnect";
const R9B_RETENTION_WITNESS_FILE: &str = "r9b-retention-witness.log";
const R9B_RETENTION_TASK_HOLD_ARM_FILE: &str = "r9b-retention-task-hold-arm";
const R9B_RETENTION_TASK_LIVE_RELEASE_FILE: &str = "r9b-retention-task-live-release";
const R9B_RETENTION_APPROVAL_OBSERVED_FILE: &str = "r9b-retention-approval-observed";
const R9B_RETENTION_COMPACT_REQUEST_FILE: &str = "r9b-retention-compact-request";
const R9B_RETENTION_COMPACTED_FILE: &str = "r9b-retention-compacted";
const R9B_RETENTION_REBASELINE_RELEASE_FILE: &str = "r9b-retention-rebaseline-release";
const U03C_RUN_ID: &str = "run-u03c-result";
const U03C_STEP_ID: &str = "step-u03c-result";
const U03C_ATTEMPT_ID: &str = "attempt-u03c-result";
const U03C_DISPATCH_ID: &str = "dispatch-u03c-result";
const U03C_ARTIFACT_ID: &str = "artifact-u03c-result";
const U03C_CLAIM_ID: &str = "claim-u03c-result";
const U03C_EVIDENCE_ID: &str = "evidence-u03c-result";
const U03C_ARTIFACT_SET_ID: &str = "artifact-set-u03c-result";
const U03C_RETURN_HANDOFF_ID: &str = "return-handoff-u03c-result";
const U03C_VERIFICATION_ID: &str = "verification-u03c-result";
const U03C_VERIFICATION_REQUEST_ID: &str = "verification-request-u03c-result";
const U03C_VERIFICATION_RUN_ID: &str = "verification-run-u03c-result";
const U03C_CHECKER_PROFILE_ID: &str = "checker-u03c-result";
const U03C_SENSITIVE_PRINCIPAL: &str = "sensitive-principal-u03c-never-render";
const U03C_SENSITIVE_PROOF: &str = "proof:u03c:never-render";
const U03C_SENSITIVE_WORKSPACE: &str = "workspace-u03c-never-render";
const U03C_SENSITIVE_RAW: &str = "raw-u03c-provider-harness-never-render";
const U03C_TASK_SCHEMA_SHA256: &str =
    "468a3d02b5c0703eb1e7626fb70f1067905a603a98f959aabdf6c4b5961b0e32";
const U04C_CONTEXT_SCHEMA_SHA256: &str =
    "3aa12bbc894776e03fc1e732619b8cd5b318651316536f098e698a5695607d54";
const U04C_PREPARE_POST_COMMIT_MODE: &str = "u04c-prepare-post-commit-unavailable";
const U04C_CONFIRM_POST_COMMIT_MODE: &str = "u04c-confirm-post-commit-unavailable";
const U04C_REPLAY_WITNESS_FILE: &str = "u04c-exact-replay.json";
const U03C_COLLABORATION_SCHEMA_SHA256: &str =
    "c57c09247f94762b3a931d43c1e4db8b321abfea308e0493d729ecee771d1873";
const U03C_ARTIFACT_SCHEMA_SHA256: &str =
    "45f3045e75eb1bd44e234dd0e6bb09c3125916f650d72cc88e233422e3995f8e";
const U03C_VERIFICATION_SCHEMA_SHA256: &str =
    "dc1244bdbb588fe3d00cebe43bf7d8ad9178a07d10a5ae6f5add8c70628c01f6";
const U03C_VERDICT_SCHEMA_SHA256: &str =
    "05eee228072a7a81353bb952ab4b8799fa3432503cc3a20c93f20c8057931f59";
const R8A_ACTIVATION_RUN_ID: &str = "r8a-activation-run";
const R8A_DRIVER_RECORD: &str = "r8a-driver-record.json";
const R8B_FIRST_RUNNER_CYCLE_RECORD: &str = "r8b-first-runner-cycle-complete";
const R8B2C_BEGIN_DELIVERY_PHASE: &str = "begin-delivery-before-receipt";
const R8B2C_DELIVERED_BEFORE_POLL_PHASE: &str = "delivered-before-poll";
const R8B2C_UNKNOWN_RECOVERED_PHASE: &str = "unknown-recovered";
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
        operation_id: format!(
            "operation:r9a3d:{:x}",
            Sha256::digest(envelope.dispatch_id.as_bytes())
        ),
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
                "processId": std::process::id(),
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

struct R9cContentFixtureDriver {
    inner: RecordingFixtureDriver,
    release_path: PathBuf,
    events: VecDeque<DriverEvent>,
}

impl R9cContentFixtureDriver {
    fn new(root: &Path) -> Self {
        let first = codex_user_visible_content_mutations(
            "agentMessage",
            R9C_MESSAGE_ID,
            0,
            &[],
            ContentMutationOperation::Append,
            R9C_VISIBLE_PREFIX,
        )
        .expect("R-9C first Codex content mutation");
        let second = codex_user_visible_content_mutations(
            "agentMessage",
            R9C_MESSAGE_ID,
            1,
            R9C_VISIBLE_PREFIX.as_bytes(),
            ContentMutationOperation::Append,
            R9C_VISIBLE_SUFFIX,
        )
        .expect("R-9C second Codex content mutation");
        let full_text = format!("{R9C_VISIBLE_PREFIX}{R9C_VISIBLE_SUFFIX}");
        let finalized = codex_user_visible_content_mutations(
            "agentMessage",
            R9C_MESSAGE_ID,
            2,
            full_text.as_bytes(),
            ContentMutationOperation::Finalize,
            "",
        )
        .expect("R-9C Codex content finalization");
        let candidates = first
            .into_iter()
            .chain(second)
            .chain(finalized)
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 3);
        let events = candidates
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                let sequence = u64::try_from(index + 1).expect("R-9C native sequence");
                DriverEvent {
                    native_key: format!("item/agentMessage/content:{R9C_MESSAGE_ID}:{sequence}"),
                    native_event_id: Some(R9C_MESSAGE_ID.to_owned()),
                    native_sequence: Some(sequence),
                    native_observed_at: prost_types::Timestamp {
                        seconds: 1_788_547_200,
                        nanos: 0,
                    },
                    criticality: ObservationCriticality::Informational,
                    payload: harness_observation::Payload::ContentSignal(
                        HarnessContentSignalObservation {
                            candidate: Some(candidate),
                            ..HarnessContentSignalObservation::default()
                        },
                    ),
                    raw_event: format!(
                        "{{\"method\":\"item/agentMessage/content\",\"rawOnly\":\"{R9C_RAW_ONLY_CANARY}\",\"sequence\":{sequence}}}"
                    )
                    .into_bytes(),
                }
            })
            .collect();
        Self {
            inner: RecordingFixtureDriver::new(root),
            release_path: root.join(R9C_CONTENT_RELEASE_FILE),
            events,
        }
    }
}

impl NativeHarnessDriver for R9cContentFixtureDriver {
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
        self.inner.send_dispatch(envelope, material)
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            if !self.inner.observation_forwarded {
                return self.inner.next_event(envelope).await;
            }
            if !self.release_path.is_file() {
                return Ok(None);
            }
            Ok(self.events.pop_front())
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct PhaseOneDriverRecord {
    dispatch_id: String,
    run_id: String,
    step_id: String,
    attempt_id: String,
    native_execution_ref: String,
}

struct PhaseOneMultiTaskDriver {
    inner: FakeCodexDriver,
    record_path: PathBuf,
    records: Vec<PhaseOneDriverRecord>,
    events: BTreeMap<String, VecDeque<DriverEvent>>,
    terminal_outputs: BTreeMap<String, TerminalOutputCandidate>,
}

impl PhaseOneMultiTaskDriver {
    fn new(root: &Path) -> Self {
        let record_path = root.join(PHASE_ONE_DRIVER_LEDGER);
        let records = fs::read(&record_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            inner: FakeCodexDriver::default(),
            record_path,
            records,
            events: BTreeMap::new(),
            terminal_outputs: BTreeMap::new(),
        }
    }

    fn persist_records(&self) {
        fs::write(
            &self.record_path,
            serde_json::to_vec(&self.records).expect("serialize phase-one driver ledger"),
        )
        .expect("persist phase-one driver ledger");
    }

    fn event(
        dispatch_id: &str,
        sequence: u64,
        label: &str,
        criticality: ObservationCriticality,
        payload: harness_observation::Payload,
    ) -> DriverEvent {
        let native_key = format!("phase-one:{dispatch_id}:{sequence}:{label}");
        DriverEvent {
            native_event_id: Some(native_key.clone()),
            native_key: native_key.clone(),
            native_sequence: Some(sequence),
            native_observed_at: prost_types::Timestamp {
                seconds: 1_788_633_600,
                nanos: 0,
            },
            criticality,
            payload,
            raw_event: native_key.into_bytes(),
        }
    }
}

impl NativeHarnessDriver for PhaseOneMultiTaskDriver {
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
            assert!(
                self.records
                    .iter()
                    .all(|record| record.dispatch_id != envelope.dispatch_id),
                "restart or exact replay must not redeliver dispatch {}",
                envelope.dispatch_id
            );
            let delivery = self.inner.send_dispatch(envelope, material).await?;
            let native_execution_ref = delivery
                .native_execution_ref
                .clone()
                .expect("phase-one fixture native execution reference");
            self.records.push(PhaseOneDriverRecord {
                dispatch_id: envelope.dispatch_id.clone(),
                run_id: envelope.run_id.clone(),
                step_id: envelope.step_id.clone(),
                attempt_id: envelope.attempt_id.clone(),
                native_execution_ref: native_execution_ref.clone(),
            });
            self.persist_records();

            let events = VecDeque::from([
                Self::event(
                    &envelope.dispatch_id,
                    1,
                    "ack",
                    ObservationCriticality::Control,
                    harness_observation::Payload::Ack(HarnessAckObservation {
                        disposition: AckDisposition::Accepted as i32,
                        ack_receipt_id: format!("phase-one-ack-{}", envelope.dispatch_id),
                        native_session_ref: Some(delivery.native_session_ref.clone()),
                        native_execution_ref: Some(native_execution_ref.clone()),
                    }),
                ),
                Self::event(
                    &envelope.dispatch_id,
                    2,
                    "running",
                    ObservationCriticality::Control,
                    harness_observation::Payload::Lifecycle(LifecycleObservation {
                        kind: LifecycleKind::ExecutionStarted as i32,
                        native_item_ref: None,
                        safe_status_code: Some("inProgress".to_owned()),
                        side_effect_certainty: SideEffectCertainty::Unknown as i32,
                        native_will_retry: None,
                    }),
                ),
                Self::event(
                    &envelope.dispatch_id,
                    3,
                    "completed",
                    ObservationCriticality::Terminal,
                    harness_observation::Payload::Lifecycle(LifecycleObservation {
                        kind: LifecycleKind::ExecutionCompleted as i32,
                        native_item_ref: None,
                        safe_status_code: Some("completed".to_owned()),
                        side_effect_certainty: SideEffectCertainty::Unknown as i32,
                        native_will_retry: None,
                    }),
                ),
            ]);
            self.events.insert(envelope.dispatch_id.clone(), events);
            self.terminal_outputs.insert(
                envelope.dispatch_id.clone(),
                TerminalOutputCandidate {
                    dispatch_id: envelope.dispatch_id.clone(),
                    native_completion_ref: native_execution_ref,
                    media_type: "text/plain; charset=utf-8".to_owned(),
                    content: format!("phase-one governed return for {}", envelope.dispatch_id)
                        .into_bytes(),
                },
            );
            Ok(delivery)
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            Ok(self
                .events
                .get_mut(&envelope.dispatch_id)
                .and_then(VecDeque::pop_front))
        })
    }

    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        Box::pin(async move { Ok(self.terminal_outputs.remove(&envelope.dispatch_id)) })
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
                let dispatch_id = read_single_r8b2c_adapter_dispatch_id(
                    &self.root.join("r8a-adapter.db"),
                    &[0x32; 32],
                )
                .expect("read the sole routed dispatch for the runner checkpoint");
                publish_r8b2c_checkpoint(&self.root, &self.instance, &dispatch_id, phase);
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

#[derive(Clone, Copy, Debug, Default)]
struct U03cVerdictReferences;

impl egopulse_founder_verdict_authority::VerdictReferenceResolver for U03cVerdictReferences {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        Ok((
            ResolvedVerdictContext {
                scope: command
                    .scope
                    .clone()
                    .ok_or(VerdictReferenceRejection::NotFound)?,
                verification_conclusion: egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationConclusion::Passed,
                open_discrepancy_ids: vec!["discrepancy-u03c".to_owned()],
                open_unverified_item_ids: vec!["unverified-u03c".to_owned()],
                non_overridable_gate_ids: Vec::new(),
            },
            FounderAuthorization {
                authenticated_founder_principal_id: principal.principal_id.clone(),
                authority_ref: "founder-authority:u03c-fixture".to_owned(),
                confirmation_class: ConfirmationClass::Explicit,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: prost_types::Timestamp {
                    seconds: 1_788_220_800,
                    nanos: 0,
                },
                valid_until: prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 0,
                },
                authority_policy_ref: ContractReference {
                    contract_id: "u03c-founder-policy".to_owned(),
                    version: "v0.1".to_owned(),
                    sha256: "44".repeat(32),
                },
                evidence_refs: vec!["evidence:u03c:founder-confirmation".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        _command: &ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        Ok(())
    }

    fn validate_revoke(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::RevokeFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Ok(vec!["evidence:u03c:founder-revoke".to_owned()])
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct U03cCollaborationGuard;

#[derive(Clone, Copy, Debug, Default)]
struct U03cAuthorityClock;

impl AuthorityClock for U03cAuthorityClock {
    fn now(&self) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: 1_788_220_800,
            nanos: 0,
        }
    }
}

impl CollaborationReferenceGuard for U03cCollaborationGuard {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        (!command.task_id.is_empty() && command.task_revision == 2 && command.work_revision == 1)
            .then_some(ReferenceAuthorization {
                evidence_refs: vec!["task-authority:u03c@revision:2".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::StaleTaskReference)
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        (command.confirmed_task_revision == 2 && !run.task_id.is_empty())
            .then_some(ReferenceAuthorization {
                evidence_refs: vec!["task-authority:u03c@active".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::StaleTaskReference)
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        _run: &RunSnapshot,
        _step: &StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        (command.attempt_id == U03C_ATTEMPT_ID
            && command.harness_id == "codex-u03c"
            && command.workspace_ref == U03C_SENSITIVE_WORKSPACE)
            .then_some(ReferenceAuthorization {
                evidence_refs: vec!["capability:u03c@verified".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        _attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        (command.owner_instance_id == "attempt-supervisor:u03c")
            .then_some(LeaseAuthorization {
                ttl_seconds: 300,
                evidence_refs: vec!["lease-policy:u03c@reviewed".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn resolve_dispatch_material(
        &self,
        _command: &RecordDispatchIntentCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        Ok(DispatchMaterial {
            input_bundle_sha256: "71".repeat(32),
            sandbox_profile_ref: r8a_reference("u03c-sandbox"),
            tool_policy_ref: r8a_reference("u03c-tools"),
            data_egress_policy_ref: r8a_reference("u03c-egress"),
            approval_policy_ref: r8a_reference("u03c-approval"),
            session_strategy: NativeSessionStrategy::CreateNew,
            native_session_ref: None,
            checkpoint_ref: None,
            route_binding: None,
            evidence_refs: vec!["dispatch-material:u03c@reviewed".to_owned()],
        })
    }

    fn validate_unknown_outcome(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::MarkAttemptOutcomeUnknownCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    fn validate_cancellation_request(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RequestAttemptCancellationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }
}

impl HarnessEvidenceResolver for U03cCollaborationGuard {
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        (command.delivery_receipt_id == "delivery-u03c")
            .then_some(ResolvedHarnessEvidence {
                harness_session_ref: Some("session-u03c-never-render".to_owned()),
                evidence_refs: vec!["adapter-receipt:u03c@durable".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        (command.ack_receipt_id == "ack-u03c")
            .then_some(ResolvedHarnessEvidence {
                harness_session_ref: Some("session-u03c-never-render".to_owned()),
                evidence_refs: vec!["adapter-ack:u03c@durable".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        (command.lifecycle_event_id == "running-u03c")
            .then_some(ReferenceAuthorization {
                evidence_refs: vec!["adapter-observation:u03c@durable".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn validate_cancellation_outcome(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RecordAttemptCancellationOutcomeCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    fn validate_reconciliation(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RecordAttemptReconciliationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        Err(ReferenceGuardRejection::UnverifiedReference)
    }

    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        (command.artifact_return_receipt_id == "return-receipt-u03c")
            .then_some(ResolvedArtifactReturn {
                artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
                return_handoff_id: U03C_RETURN_HANDOFF_ID.to_owned(),
                dispatch_id: U03C_DISPATCH_ID.to_owned(),
                evidence_refs: vec!["artifact-return:u03c@durable".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }

    fn resolve_step_return(
        &self,
        command: &CommitStepReturnCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        (command.artifact_set_id == U03C_ARTIFACT_SET_ID
            && command.return_handoff_id == U03C_RETURN_HANDOFF_ID)
            .then_some(ResolvedStepReturn {
                artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
                return_handoff_id: U03C_RETURN_HANDOFF_ID.to_owned(),
                verification_artifact_id: U03C_VERIFICATION_ID.to_owned(),
                evidence_refs: vec!["verification:u03c@durable".to_owned()],
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)
    }
}

struct StaticApprovalProjectionSource {
    messages: std::sync::Mutex<Vec<PendingOwnerProjection>>,
}

impl StaticApprovalProjectionSource {
    fn new() -> Self {
        let action_digest = "33".repeat(32);
        let summary = egopulse_domain_contracts::approval_display::seal_approval_display_summary(
            egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDisplaySummary {
                state: 1,
                summary_ref: "summary-c5-03".to_owned(),
                action_digest_sha256: action_digest.clone(),
                source_binding_sha256: "c".repeat(64),
                command_preview: "cargo test".to_owned(),
                working_directory_label: ".".to_owned(),
                policy_code: "egopulse.approval-display/v1".to_owned(),
                ..Default::default()
            },
        );
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
                    display_summary: Some(summary),
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
                step_ids: vec!["c5-step".to_owned()],
                ..Default::default()
            }),
            steps: vec![StepSnapshot {
                step_id: "c5-step".to_owned(),
                run_id: "c5-run".to_owned(),
                revision: 1,
                status: StepStatus::ReturnPending as i32,
                attempt_ids: vec!["c5-attempt".to_owned()],
                current_attempt_id: Some("c5-attempt".to_owned()),
                ..Default::default()
            }],
            attempts: vec![AttemptSnapshot {
                attempt_id: "c5-attempt".to_owned(),
                run_id: "c5-run".to_owned(),
                step_id: "c5-step".to_owned(),
                revision: 1,
                attempt_number: 1,
                status: AttemptStatus::Returned as i32,
                recovery_class: RecoveryClass::ResumeSafe as i32,
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

struct R9bTaskDisconnectProjectionSource {
    initial: StaticApprovalProjectionSource,
    trigger_path: PathBuf,
    advanced_acknowledged: Mutex<bool>,
}

impl R9bTaskDisconnectProjectionSource {
    fn new(root: &Path) -> Self {
        Self {
            initial: StaticApprovalProjectionSource::new(),
            trigger_path: root.join(R9B_APPROVAL_ADVANCE_FILE),
            advanced_acknowledged: Mutex::new(false),
        }
    }

    fn advanced_projection() -> PendingOwnerProjection {
        let observation = HarnessObservation {
            observation_id: "observation-r9b-task-disconnect".to_owned(),
            adapter_id: "c5-adapter".to_owned(),
            attempt_id: "c5-attempt".to_owned(),
            dispatch_id: "c5-dispatch".to_owned(),
            fencing_token: 7,
            observation_sequence: 2,
            payload: Some(harness_observation::Payload::ApprovalRequest(
                ApprovalRequestObservation {
                    approval_request_id: R9B_ADVANCED_APPROVAL_ID.to_owned(),
                    kind: ApprovalKind::Command as i32,
                    action_digest_sha256: "44".repeat(32),
                    requested_scope_ref: "scope-r9b-task-disconnect".to_owned(),
                    display_summary_ref: "summary-r9b-task-disconnect".to_owned(),
                    display_summary: None,
                    native_routing_ref: String::new(),
                    lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                    request_revision: 1,
                },
            )),
            ..Default::default()
        };
        PendingOwnerProjection::AdapterApproval(Box::new(
            egopulse_harness_adapter::PendingAdapterApprovalProjection {
                message_id: "projection-r9b-task-disconnect".to_owned(),
                source_observation_id: observation.observation_id.clone(),
                source_revision: observation.observation_sequence,
                payload_digest_sha256: hex::encode(Sha256::digest(observation.encode_to_vec())),
                run_id: "c5-run".to_owned(),
                step_id: "c5-step".to_owned(),
                attempt_id: observation.attempt_id.clone(),
                dispatch_id: observation.dispatch_id.clone(),
                fencing_token: observation.fencing_token,
                observation,
            },
        ))
    }
}

impl OwnerProjectionSource for R9bTaskDisconnectProjectionSource {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        let mut pending = self.initial.pending()?;
        let advanced_acknowledged = *self
            .advanced_acknowledged
            .lock()
            .map_err(|_| ProjectionSourceFailure::Acknowledgement)?;
        if self.trigger_path.is_file() && !advanced_acknowledged {
            pending.push(Self::advanced_projection());
        }
        Ok(pending)
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let is_advanced = matches!(
            message,
            PendingOwnerProjection::AdapterApproval(value)
                if value.message_id == "projection-r9b-task-disconnect"
        );
        if is_advanced {
            let mut acknowledged = self
                .advanced_acknowledged
                .lock()
                .map_err(|_| ProjectionSourceFailure::Acknowledgement)?;
            if *acknowledged {
                return Ok(false);
            }
            *acknowledged = true;
            return Ok(true);
        }
        self.initial.acknowledge(message)
    }
}

struct R9bTaskFramesReader {
    inner: Arc<dyn ReadModelReader>,
    task_frame_calls: AtomicU64,
    task_operation_calls: AtomicU64,
    injected: AtomicBool,
    baseline_hold_recorded: AtomicBool,
    arm_path: PathBuf,
    calls_path: PathBuf,
    release_path: PathBuf,
}

impl R9bTaskFramesReader {
    fn new(inner: Arc<dyn ReadModelReader>, root: &Path) -> Self {
        Self {
            inner,
            task_frame_calls: AtomicU64::new(0),
            task_operation_calls: AtomicU64::new(0),
            injected: AtomicBool::new(false),
            baseline_hold_recorded: AtomicBool::new(false),
            arm_path: root.join(R9B_TASK_DISCONNECT_ARM_FILE),
            calls_path: root.join(R9B_TASK_READER_CALLS_FILE),
            release_path: root.join(R9B_TASK_REBASELINE_RELEASE_FILE),
        }
    }

    fn record_task_operation(
        &self,
        operation: &str,
        outcome: &str,
    ) -> Result<(), ReadModelAccessError> {
        let call = self.task_operation_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.calls_path)
            .map_err(|_| ReadModelAccessError::WorkerFailed)?;
        writeln!(file, "{call} {operation} {outcome}")
            .and_then(|()| file.sync_all())
            .map_err(|_| ReadModelAccessError::WorkerFailed)
    }

    async fn wait_for_rebaseline_release(&self) -> Result<(), ReadModelAccessError> {
        if !self.injected.load(Ordering::SeqCst) || self.release_path.is_file() {
            return Ok(());
        }
        if self
            .baseline_hold_recorded
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.record_task_operation("task_baseline", "held")?;
        }
        timeout(Duration::from_secs(8), async {
            while !self.release_path.is_file() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| ReadModelAccessError::Unavailable)
    }
}

#[tonic::async_trait]
impl ProjectionStatusReader for R9bTaskFramesReader {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
        self.wait_for_rebaseline_release().await?;
        self.inner.status().await
    }
}

#[tonic::async_trait]
impl ReadModelReader for R9bTaskFramesReader {
    async fn task_frames_after(
        &self,
        after: ProjectionPosition,
        filter: TaskListFilter,
        task_ids: Vec<String>,
        access: TaskViewAccess,
    ) -> Result<
        StreamBatch<egopulse_domain_contracts::v01::egopulse::localapi::v1::TaskViewStreamFrame>,
        ReadModelAccessError,
    > {
        let frame_call = self.task_frame_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.arm_path.is_file()
            && self
                .injected
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.record_task_operation("task_frames_after", "unavailable")?;
            return Err(ReadModelAccessError::Unavailable);
        }
        self.record_task_operation("task_frames_after", &format!("delegated-{frame_call}"))?;
        self.inner
            .task_frames_after(after, filter, task_ids, access)
            .await
    }

    async fn approval_frames_after(
        &self,
        after: ProjectionPosition,
        filter: ApprovalListFilter,
        approval_request_ids: Vec<String>,
        access: ApprovalViewAccess,
    ) -> Result<
        StreamBatch<
            egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessApprovalViewStreamFrame,
        >,
        ReadModelAccessError,
    > {
        self.inner
            .approval_frames_after(after, filter, approval_request_ids, access)
            .await
    }

    async fn has_projected_source(
        &self,
        required: SourceRevision,
    ) -> Result<bool, ReadModelAccessError> {
        self.inner.has_projected_source(required).await
    }

    async fn get_task_view(
        &self,
        task_id: String,
        access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError> {
        self.record_task_operation("get_task_view", "delegated")?;
        self.inner.get_task_view(task_id, access).await
    }

    async fn list_task_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: TaskListFilter,
        access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError> {
        self.record_task_operation("list_task_views_at", "delegated")?;
        self.inner
            .list_task_views_at(snapshot, filter, access)
            .await
    }

    async fn get_evidence_graph(
        &self,
        task_id: String,
        artifact_set_id: String,
        access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError> {
        self.inner
            .get_evidence_graph(task_id, artifact_set_id, access)
            .await
    }

    async fn get_harness_approval_view(
        &self,
        approval_request_id: String,
        access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError> {
        self.inner
            .get_harness_approval_view(approval_request_id, access)
            .await
    }

    async fn list_harness_approval_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: ApprovalListFilter,
        access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError> {
        self.inner
            .list_harness_approval_views_at(snapshot, filter, access)
            .await
    }
}

struct R9bRetentionWitness {
    path: PathBuf,
    sequence: AtomicU64,
}

impl R9bRetentionWitness {
    fn new(root: &Path) -> Self {
        Self {
            path: root.join(R9B_RETENTION_WITNESS_FILE),
            sequence: AtomicU64::new(0),
        }
    }

    fn record(&self, event: &str) -> std::io::Result<()> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{sequence} {event}")?;
        file.sync_all()
    }
}

struct R9bRetentionReader {
    inner: Arc<dyn ReadModelReader>,
    witness: Arc<R9bRetentionWitness>,
    task_hold_arm_path: PathBuf,
    task_live_release_path: PathBuf,
    task_rebaseline_release_path: PathBuf,
    task_live_held: AtomicBool,
    task_reset_observed: AtomicBool,
    task_rebaseline_held: AtomicBool,
    task_rebaseline_released: AtomicBool,
}

impl R9bRetentionReader {
    fn new(
        inner: Arc<dyn ReadModelReader>,
        witness: Arc<R9bRetentionWitness>,
        root: &Path,
    ) -> Self {
        Self {
            inner,
            witness,
            task_hold_arm_path: root.join(R9B_RETENTION_TASK_HOLD_ARM_FILE),
            task_live_release_path: root.join(R9B_RETENTION_TASK_LIVE_RELEASE_FILE),
            task_rebaseline_release_path: root.join(R9B_RETENTION_REBASELINE_RELEASE_FILE),
            task_live_held: AtomicBool::new(false),
            task_reset_observed: AtomicBool::new(false),
            task_rebaseline_held: AtomicBool::new(false),
            task_rebaseline_released: AtomicBool::new(false),
        }
    }

    async fn wait_for_control(&self, path: &Path) -> Result<(), ReadModelAccessError> {
        timeout(Duration::from_secs(8), async {
            while !path.is_file() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| ReadModelAccessError::Unavailable)
    }

    async fn hold_task_live_read(
        &self,
        after: &ProjectionPosition,
    ) -> Result<(), ReadModelAccessError> {
        if !self.task_hold_arm_path.is_file()
            || self
                .task_live_held
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Ok(());
        }
        self.witness
            .record(&format!(
                "task-live-read-held epoch={} sequence={}",
                after.epoch, after.sequence
            ))
            .map_err(|_| ReadModelAccessError::WorkerFailed)?;
        self.wait_for_control(&self.task_live_release_path).await?;
        self.witness
            .record("task-live-read-released")
            .map_err(|_| ReadModelAccessError::WorkerFailed)
    }

    async fn hold_task_rebaseline(&self) -> Result<(), ReadModelAccessError> {
        if !self.task_reset_observed.load(Ordering::SeqCst)
            || self.task_rebaseline_release_path.is_file()
        {
            return Ok(());
        }
        if self
            .task_rebaseline_held
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.witness
                .record("task-rebaseline-held")
                .map_err(|_| ReadModelAccessError::WorkerFailed)?;
        }
        self.wait_for_control(&self.task_rebaseline_release_path)
            .await?;
        if self
            .task_rebaseline_released
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.witness
                .record("task-rebaseline-released")
                .map_err(|_| ReadModelAccessError::WorkerFailed)?;
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl ProjectionStatusReader for R9bRetentionReader {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
        self.hold_task_rebaseline().await?;
        self.inner.status().await
    }
}

#[tonic::async_trait]
impl ReadModelReader for R9bRetentionReader {
    async fn task_frames_after(
        &self,
        after: ProjectionPosition,
        filter: TaskListFilter,
        task_ids: Vec<String>,
        access: TaskViewAccess,
    ) -> Result<
        StreamBatch<egopulse_domain_contracts::v01::egopulse::localapi::v1::TaskViewStreamFrame>,
        ReadModelAccessError,
    > {
        self.hold_task_live_read(&after).await?;
        let batch = self
            .inner
            .task_frames_after(after, filter, task_ids, access)
            .await?;
        let reset_frames = batch
            .frames
            .iter()
            .filter(|frame| frame.kind == StreamFrameKind::ResetRequired as i32)
            .collect::<Vec<_>>();
        if !reset_frames.is_empty() {
            self.witness
                .record(&format!("task-raw-reset count={}", reset_frames.len()))
                .map_err(|_| ReadModelAccessError::WorkerFailed)?;
            if reset_frames.len() != 1
                || reset_frames[0].reset_reason_code.as_deref() != Some("PROJECTION_RETENTION_GAP")
                || self.task_reset_observed.swap(true, Ordering::SeqCst)
            {
                return Err(ReadModelAccessError::WorkerFailed);
            }
        }
        Ok(batch)
    }

    async fn approval_frames_after(
        &self,
        after: ProjectionPosition,
        filter: ApprovalListFilter,
        approval_request_ids: Vec<String>,
        access: ApprovalViewAccess,
    ) -> Result<
        StreamBatch<
            egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessApprovalViewStreamFrame,
        >,
        ReadModelAccessError,
    > {
        let batch = self
            .inner
            .approval_frames_after(after, filter, approval_request_ids, access)
            .await?;
        let reset_count = batch
            .frames
            .iter()
            .filter(|frame| frame.kind == StreamFrameKind::ResetRequired as i32)
            .count();
        if reset_count > 0 {
            self.witness
                .record(&format!("approval-raw-reset count={reset_count}"))
                .map_err(|_| ReadModelAccessError::WorkerFailed)?;
        }
        Ok(batch)
    }

    async fn has_projected_source(
        &self,
        required: SourceRevision,
    ) -> Result<bool, ReadModelAccessError> {
        self.inner.has_projected_source(required).await
    }

    async fn get_task_view(
        &self,
        task_id: String,
        access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError> {
        self.inner.get_task_view(task_id, access).await
    }

    async fn list_task_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: TaskListFilter,
        access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError> {
        self.inner
            .list_task_views_at(snapshot, filter, access)
            .await
    }

    async fn get_evidence_graph(
        &self,
        task_id: String,
        artifact_set_id: String,
        access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError> {
        self.inner
            .get_evidence_graph(task_id, artifact_set_id, access)
            .await
    }

    async fn get_harness_approval_view(
        &self,
        approval_request_id: String,
        access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError> {
        self.inner
            .get_harness_approval_view(approval_request_id, access)
            .await
    }

    async fn list_harness_approval_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: ApprovalListFilter,
        access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError> {
        self.inner
            .list_harness_approval_views_at(snapshot, filter, access)
            .await
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

#[derive(Clone, Copy, Debug)]
struct R9bDenyPermissionSessionResolver {
    denied_permission: &'static str,
}

impl TrustedPrincipalResolver for R9bDenyPermissionSessionResolver {
    fn resolve(
        &self,
        _principal: &egopulse_local_ipc_platform::OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        let profiles = egopulse_client_kernel::ContractProfiles::embedded()
            .map_err(|_| PrincipalResolutionFailure::PolicyUnavailable)?;
        let mut permissions = profiles.permission_codes().clone();
        let retained_permission = match self.denied_permission {
            "local.task.read" => "local.approval.read",
            "local.approval.read" => "local.task.read",
            _ => return Err(PrincipalResolutionFailure::PolicyUnavailable),
        };
        if !permissions.remove(self.denied_permission) || !permissions.contains(retained_permission)
        {
            return Err(PrincipalResolutionFailure::PolicyUnavailable);
        }
        Ok(PrincipalGrant {
            authenticated_principal_id: "os-user:c5-fixture".to_owned(),
            permission_codes: permissions,
            authorization_policy_ref: authorization_contract_ref(),
        })
    }
}

fn fixture_session_principal_resolver() -> Arc<dyn TrustedPrincipalResolver> {
    match fixture_mode().as_str() {
        R9B_DENY_TASK_READ_MODE => Arc::new(R9bDenyPermissionSessionResolver {
            denied_permission: "local.task.read",
        }),
        R9B_DENY_APPROVAL_READ_MODE => Arc::new(R9bDenyPermissionSessionResolver {
            denied_permission: "local.approval.read",
        }),
        _ => Arc::new(FixtureSessionResolver),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct U03cDenyResultReadSessionResolver;

impl TrustedPrincipalResolver for U03cDenyResultReadSessionResolver {
    fn resolve(
        &self,
        _principal: &egopulse_local_ipc_platform::OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        let profiles = egopulse_client_kernel::ContractProfiles::embedded()
            .map_err(|_| PrincipalResolutionFailure::PolicyUnavailable)?;
        let mut permissions = profiles.permission_codes().clone();
        permissions.remove("local.evidence.read");
        Ok(PrincipalGrant {
            authenticated_principal_id: "os-user:c5-fixture".to_owned(),
            permission_codes: permissions,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum U04cInjectedOperation {
    Prepare,
    Confirm,
}

#[derive(Clone)]
enum U04cFirstResponse {
    Prepare(Box<WorkPreparationPreview>),
    Confirm(Box<CommandPortResult<TaskCommandResult>>),
}

#[derive(Default)]
struct U04cWorkPortState {
    calls: u8,
    request: Vec<u8>,
    principal: Option<CommandPrincipal>,
    response: Option<U04cFirstResponse>,
    durability: Option<U04cWorkStartDurabilitySnapshot>,
}

#[derive(serde::Serialize)]
struct U04cReplayWitness<'a> {
    operation: &'a str,
    process_id: u32,
    request_sha256: String,
    principal_id: &'a str,
    calls: u8,
    authority_tables_unchanged: bool,
}

struct U04cPostCommitUnavailableWorkPort {
    inner: Arc<dyn WorkPreparationPort>,
    root: PathBuf,
    operation: U04cInjectedOperation,
    state: Mutex<U04cWorkPortState>,
}

fn u04c_replay_has_no_authority_growth(
    first: &U04cWorkStartDurabilitySnapshot,
    replay: &U04cWorkStartDurabilitySnapshot,
) -> bool {
    let mut first = first.clone();
    let mut replay = replay.clone();
    for snapshot in [&mut first, &mut replay] {
        if let Some(outbox) = snapshot
            .task
            .table_digests
            .iter_mut()
            .find(|table| table.table_name == "task_outbox")
        {
            // The daemon may acknowledge the already-created outbox row
            // between the injected post-commit failure and the exact replay.
            // Preserve its row-count check while excluding only that mutable
            // delivery-state digest from the no-growth comparison.
            outbox.content_sha256.clear();
        }
    }
    first == replay
}

impl U04cPostCommitUnavailableWorkPort {
    fn new(
        inner: Arc<dyn WorkPreparationPort>,
        root: PathBuf,
        operation: U04cInjectedOperation,
    ) -> Self {
        Self {
            inner,
            root,
            operation,
            state: Mutex::new(U04cWorkPortState::default()),
        }
    }

    fn durability(
        &self,
        snapshot_id: Option<&str>,
        task_id: Option<&str>,
    ) -> U04cWorkStartDurabilitySnapshot {
        read_u04c_work_start_durability(&U04cWorkStartOracleRequest {
            root: &self.root,
            context_key: &[0x15; 32],
            context_store_epoch: "c5-context-epoch",
            context_schema_sha256: U04C_CONTEXT_SCHEMA_SHA256,
            task_key: &[0x11; 32],
            task_store_epoch: "c5-00-task-epoch",
            task_schema_sha256: U03C_TASK_SCHEMA_SHA256,
            snapshot_id,
            task_id,
        })
        .expect("read U-04c Authority durability through the strict read-only oracle")
    }

    fn verify_replay(
        &self,
        state: &mut U04cWorkPortState,
        request: &[u8],
        principal: &CommandPrincipal,
        response: U04cFirstResponse,
        durability: U04cWorkStartDurabilitySnapshot,
    ) -> Result<(), CommandPortFailure> {
        let response_matches =
            state
                .response
                .as_ref()
                .is_some_and(|first| match (first, &response) {
                    (U04cFirstResponse::Prepare(first), U04cFirstResponse::Prepare(second)) => {
                        first == second
                    }
                    (U04cFirstResponse::Confirm(first), U04cFirstResponse::Confirm(second)) => {
                        let mut normalized = second.clone();
                        let replayed = normalized.result.replayed;
                        normalized.result.replayed = first.result.replayed;
                        replayed && first.result == normalized.result
                    }
                    _ => false,
                });
        let durability_matches = state
            .durability
            .as_ref()
            .is_some_and(|first| u04c_replay_has_no_authority_growth(first, &durability));
        if state.calls != 1
            || state.request != request
            || state.principal.as_ref() != Some(principal)
            || !response_matches
            || !durability_matches
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        state.calls = 2;
        let operation = match self.operation {
            U04cInjectedOperation::Prepare => "prepare",
            U04cInjectedOperation::Confirm => "confirm",
        };
        publish_r9a3_json_atomically(
            &self.root.join(U04C_REPLAY_WITNESS_FILE),
            &U04cReplayWitness {
                operation,
                process_id: std::process::id(),
                request_sha256: format!("{:x}", Sha256::digest(request)),
                principal_id: principal.principal_id.as_str(),
                calls: state.calls,
                authority_tables_unchanged: true,
            },
            "U-04c exact replay witness",
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl WorkPreparationPort for U04cPostCommitUnavailableWorkPort {
    async fn prepare(
        &self,
        request: &PrepareWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<WorkPreparationPreview, CommandPortFailure> {
        if self.operation != U04cInjectedOperation::Prepare {
            return self.inner.prepare(request, principal).await;
        }
        let encoded = request.encode_to_vec();
        {
            let state = self
                .state
                .lock()
                .map_err(|_| CommandPortFailure::IntegrityFailure)?;
            if state.calls >= 2 {
                return Err(CommandPortFailure::IntegrityFailure);
            }
        }
        let response = self.inner.prepare(request, principal).await?;
        let durability = self.durability(Some(response.snapshot_id.as_str()), None);
        let mut state = self
            .state
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        if state.calls >= 2 {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        if state.calls == 0 {
            state.calls = 1;
            state.request = encoded;
            state.principal = Some(principal.clone());
            state.response = Some(U04cFirstResponse::Prepare(Box::new(response)));
            state.durability = Some(durability);
            return Err(CommandPortFailure::Unavailable);
        }
        self.verify_replay(
            &mut state,
            &encoded,
            principal,
            U04cFirstResponse::Prepare(Box::new(response.clone())),
            durability,
        )?;
        Ok(response)
    }

    fn confirm(
        &self,
        request: &ConfirmWorkRequest,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        if self.operation != U04cInjectedOperation::Confirm {
            return self.inner.confirm(request, principal);
        }
        let encoded = request.encode_to_vec();
        let mut state = self
            .state
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        if state.calls >= 2 {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let response = self.inner.confirm(request, principal)?;
        let task_id = match response.result.outcome.as_ref() {
            Some(egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(task)) => task.task_id.as_str(),
            _ => return Err(CommandPortFailure::IntegrityFailure),
        };
        let durability = self.durability(Some(request.snapshot_id.as_str()), Some(task_id));
        if state.calls == 0 {
            if response.result.replayed {
                return Err(CommandPortFailure::IntegrityFailure);
            }
            state.calls = 1;
            state.request = encoded;
            state.principal = Some(principal.clone());
            state.response = Some(U04cFirstResponse::Confirm(Box::new(response)));
            state.durability = Some(durability);
            return Err(CommandPortFailure::Unavailable);
        }
        self.verify_replay(
            &mut state,
            &encoded,
            principal,
            U04cFirstResponse::Confirm(Box::new(response.clone())),
            durability,
        )?;
        Ok(response)
    }
}

fn dynamic_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R8A_FIXTURE_MODE
            | M13_MEMORY_DISPATCH_MODE
            | PHASE_ONE_MULTI_TASK_MODE
            | R8B_PAUSE_BEFORE_RUNNER_MODE
            | R8B2C_BEGIN_DELIVERY_MODE
            | R8B2C_UNKNOWN_RECOVERY_MODE
            | R8B2C_DELIVERED_BEFORE_POLL_MODE
            | R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
            | R9C_CONTENT_MODE
    )
}

fn r8b2c_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R8B2C_BEGIN_DELIVERY_MODE | R8B2C_UNKNOWN_RECOVERY_MODE | R8B2C_DELIVERED_BEFORE_POLL_MODE
    )
}

fn r9a3d_fixture_mode() -> bool {
    matches!(
        fixture_mode().as_str(),
        R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
            | U04C_PREPARE_POST_COMMIT_MODE
            | U04C_CONFIRM_POST_COMMIT_MODE
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
                route_binding: None,
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

fn fixture_work_capability(
    root: &Path,
    native: &NativeHarnessCompositionConfig,
) -> (Arc<WorkCapabilityRegistry>, WorkCapabilityRouteBinding) {
    let (provider_profile_id, catalog_digest) = match fixture_mode().as_str() {
        M13_MEMORY_DISPATCH_MODE => ("gpt-codex-m13-fixture", "68".repeat(32)),
        R9C_CONTENT_MODE => ("gpt-codex-r9c-fixture", "67".repeat(32)),
        _ => ("gpt-codex-r8a-fixture", "66".repeat(32)),
    };
    let model = native
        .default_model
        .clone()
        .expect("C5 native fixture exact model");
    let route = egopulse_domain_contracts::work_capability::seal_work_capability_route_binding(
        WorkCapabilityRouteBinding {
            route_id: format!("route:{provider_profile_id}:v1"),
            route_generation: 1,
            provider_profile_id: provider_profile_id.to_owned(),
            provider_id: "gpt".to_owned(),
            harness_id: "codex_app_server".to_owned(),
            harness_model_id: model.clone(),
            provider_model_id: model.clone(),
            capability_profile_ref: Some(native.workflow.capability_profile_ref.clone()),
            catalog_snapshot_sha256: Some(catalog_digest.clone()),
            native_composition_generation: native.workflow.run_id.clone(),
            route_binding_sha256: String::new(),
        },
    )
    .expect("seal C5 fixture work-capability route");
    let profile = ProviderBootstrapProfile {
        profile_id: provider_profile_id.to_owned(),
        provider: ProviderId::Gpt,
        harness: ProviderHarnessKind::CodexAppServer,
        admission: ProviderAdmission::Production,
        models: vec![ProviderModelBinding {
            harness_model_id: model.clone(),
            provider_model_id: model.clone(),
        }],
        catalog_snapshot: Some(ProviderCatalogSnapshot {
            source: "fixture://c5/provider-catalog".to_owned(),
            fetched_at: "2026-09-05T00:00:00Z".to_owned(),
            harness_version: "fixture".to_owned(),
            evidence_digest_sha256: catalog_digest,
        }),
        exact_model: model,
        executable: PathBuf::from("fixture-codex.exe"),
        credential: ProviderCredentialReference::HarnessAccount,
        hold_reason: None,
    };
    let registry = WorkCapabilityRegistry::new(
        root.join("fixture-agentos-config.json"),
        &[profile],
        route.clone(),
        "fixture-codex".to_owned(),
        1,
        false,
    )
    .expect("build C5 fixture work-capability registry");
    (Arc::new(registry), route)
}

fn routed_fixture_composition<D>(
    native: NativeHarnessCompositionConfig,
    driver: D,
    route: WorkCapabilityRouteBinding,
) -> ProfiledNativeHarnessComposition
where
    D: NativeHarnessDriver + Send + 'static,
{
    let profile = r9c_native_profile(&native);
    ProfiledNativeHarnessComposition::new(native, profile, driver).with_work_capability_route(route)
}

fn r9c_native_profile(native: &NativeHarnessCompositionConfig) -> NativeHarnessCompositionProfile {
    let required = native.workflow.capability_profile_ref.clone();
    let observed_protocol = codex_protocol_fingerprint();
    let capability = CapabilityProfile {
        profile_id: required.contract_id.clone(),
        revision: 1,
        digest_sha256: required.sha256.clone(),
        status: CapabilityProfileStatus::Active as i32,
        declaration: Some(CapabilityDeclaration {
            adapter_id: CODEX_ADAPTER_ID.to_owned(),
            harness_id: "codex_app_server".to_owned(),
            model_family_selectors: vec!["codex".to_owned()],
            native_protocol: Some(observed_protocol.clone()),
            semantics: Some(
                egopulse_domain_contracts::v01::egopulse::harness::v1::CapabilitySemantics {
                    governed_user_visible_content:
                        egopulse_domain_contracts::v01::egopulse::harness::v1::SupportLevel::AdapterEmulated
                            as i32,
                    ..Default::default()
                },
            ),
            ..CapabilityDeclaration::default()
        }),
        attestation_level: AttestationLevel::ProbeVerified as i32,
        attestation_evidence_refs: vec!["fixture://r9c/codex-probe".to_owned()],
        ..CapabilityProfile::default()
    };
    NativeHarnessCompositionProfile::from_attested_capability(
        &required,
        "codex",
        &capability,
        observed_protocol,
        &prost_types::Timestamp::default(),
    )
    .expect("R-9C probe-attested Codex composition profile")
}

fn r9c_profiled_composition(
    native: NativeHarnessCompositionConfig,
    root: &Path,
) -> ProfiledNativeHarnessComposition {
    let profile = r9c_native_profile(&native);
    let provider_model_id = native
        .default_model
        .clone()
        .expect("R-9C exact fixture model");
    ProfiledNativeHarnessComposition::new(native, profile, R9cContentFixtureDriver::new(root))
        .with_trusted_dispatch_route_profile(TrustedDispatchRouteProfile {
            provider_bootstrap_profile_id: "gpt-codex-r9c-fixture".to_owned(),
            selected_harness_id: "codex_app_server".to_owned(),
            provider_model_id,
            catalog_snapshot_sha256: Some("67".repeat(32)),
            capability_profile_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
        })
        .with_disclosure_credentials(ManagedDisclosureCredentials::harness_account())
}

fn m13_profiled_composition(
    native: NativeHarnessCompositionConfig,
    root: &Path,
) -> ProfiledNativeHarnessComposition {
    let profile = r9c_native_profile(&native);
    let provider_model_id = native
        .default_model
        .clone()
        .expect("M-13 exact fixture model");
    ProfiledNativeHarnessComposition::new(native, profile, RecordingFixtureDriver::new(root))
        .with_trusted_dispatch_route_profile(TrustedDispatchRouteProfile {
            provider_bootstrap_profile_id: "gpt-codex-m13-fixture".to_owned(),
            selected_harness_id: "codex_app_server".to_owned(),
            provider_model_id,
            catalog_snapshot_sha256: Some("68".repeat(32)),
            capability_profile_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
        })
        .with_disclosure_credentials(ManagedDisclosureCredentials::harness_account())
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

fn u03c_metadata(operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("u03c-command-{operation}"),
        idempotency_key: format!("u03c-idempotency-{operation}"),
        idempotency_scope: "u03c-result-review".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(prost_types::Timestamp {
            seconds: 1_788_220_800,
            nanos: 0,
        }),
        correlation_id: "u03c-result-review".to_owned(),
        causation_id: None,
    }
}

fn u03c_task_principal(kind: TaskPrincipalKind, principal_id: &str) -> AuthenticatedTaskPrincipal {
    AuthenticatedTaskPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
    }
}

fn u03c_execute_task(
    authority: &mut TaskAuthority,
    mut command: TaskCommand,
    principal: &AuthenticatedTaskPrincipal,
) -> TaskSnapshot {
    egopulse_client_operations::set_task_digest(&mut command);
    let result = authority
        .execute(&command, principal)
        .expect("U-03c Task Authority command");
    match result.outcome.expect("U-03c Task command outcome") {
        egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(
            snapshot,
        ) => snapshot,
        egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Error(
            error,
        ) => panic!("U-03c Task command rejected: {}", error.safe_detail_code),
    }
}

fn u03c_seed_task_ready(authority: &mut TaskAuthority) -> TaskSnapshot {
    let mut snapshot = u03c_execute_task(
        authority,
        TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(u03c_metadata("create-task")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-u03c-result".to_owned(),
                target_scope_ref: "scope:u03c-result".to_owned(),
                acceptance_contract_ref: Some(r8a_reference("u03c-acceptance")),
                budget_profile_ref: Some(r8a_reference("u03c-budget")),
                work_capability_route: None,
            })),
        },
        &u03c_task_principal(TaskPrincipalKind::Founder, "founder:u03c"),
    );
    snapshot = u03c_execute_task(
        authority,
        TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(u03c_metadata("activate-task")),
                task_id: snapshot.task_id.clone(),
                expected_revision: snapshot.revision,
                work_revision: snapshot.work_revision,
                run_id: U03C_RUN_ID.to_owned(),
            })),
        },
        &u03c_task_principal(
            TaskPrincipalKind::CollaborationControl,
            "collaboration-control:u03c",
        ),
    );
    assert_eq!(snapshot.status, TaskStatus::Active as i32);
    snapshot
}

fn u03c_collaboration_principal(
    kind: CollaborationPrincipalKind,
    id: &str,
) -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn u03c_collaboration_snapshot(
    control: &mut CollaborationControl<U03cCollaborationGuard, U03cAuthorityClock>,
    mut command: CollaborationCommand,
    principal: &AuthenticatedCollaborationPrincipal,
) -> CollaborationSnapshot {
    egopulse_local_ide_control::collaboration_control::seal_request_digest(&mut command)
        .expect("seal U-03c Collaboration command");
    let result = control
        .execute(&command, principal)
        .expect("U-03c Collaboration command");
    match result.outcome.expect("U-03c Collaboration outcome") {
        collaboration_command_result::Outcome::Snapshot(snapshot) => snapshot,
        collaboration_command_result::Outcome::Error(error) => {
            panic!(
                "U-03c Collaboration command rejected: {}",
                error.safe_detail_code
            )
        }
    }
}

fn u03c_run_plan() -> RunPlan {
    RunPlan {
        plan_id: "plan-u03c-result".to_owned(),
        digest_sha256: "61".repeat(32),
        max_active_attempts: 1,
        steps: vec![StepPlan {
            step_id: U03C_STEP_ID.to_owned(),
            step_kind: "governed_repository_change".to_owned(),
            depends_on_step_ids: Vec::new(),
            input_bundle_ref: "input-u03c-result.json".to_owned(),
            expected_output_contract_ref: Some(r8a_reference("u03c-output")),
            required_capability_profile_ref: Some(r8a_reference("u03c-capability")),
            max_attempts: 2,
        }],
        budget_profile_ref: Some(r8a_reference("u03c-budget")),
    }
}

fn u03c_attempt_base(snapshot: &CollaborationSnapshot, operation: &str) -> AttemptCommandBase {
    let run = snapshot.run.as_ref().expect("U-03c run");
    let step = snapshot.steps.first().expect("U-03c step");
    let attempt = snapshot.attempts.first().expect("U-03c attempt");
    AttemptCommandBase {
        meta: Some(u03c_metadata(operation)),
        run_id: run.run_id.clone(),
        expected_run_revision: run.revision,
        step_id: step.step_id.clone(),
        expected_step_revision: step.revision,
        attempt_id: attempt.attempt_id.clone(),
        expected_attempt_revision: attempt.revision,
    }
}

fn u03c_seed_collaboration(
    root: &Path,
    task: &TaskSnapshot,
) -> (
    CollaborationControl<U03cCollaborationGuard, U03cAuthorityClock>,
    CollaborationSnapshot,
) {
    let mut control = CollaborationControl::open(
        CollaborationControlConfig {
            database_path: root.join("u03c-collaboration.db"),
            store_epoch: "u03c-collaboration-epoch".to_owned(),
            key: CollaborationSqlCipherKey::new([0x73; 32]),
        },
        U03cCollaborationGuard,
        U03cAuthorityClock,
    )
    .expect("open U-03c Collaboration Control");
    let task_principal = u03c_collaboration_principal(
        CollaborationPrincipalKind::TaskAuthority,
        "task-authority:u03c",
    );
    let control_principal = u03c_collaboration_principal(
        CollaborationPrincipalKind::CollaborationControl,
        "collaboration-control:u03c",
    );
    let adapter_principal = u03c_collaboration_principal(
        CollaborationPrincipalKind::HarnessAdapter,
        "harness-adapter:u03c",
    );
    let artifact_principal = u03c_collaboration_principal(
        CollaborationPrincipalKind::ArtifactAuthority,
        "artifact-authority:u03c",
    );
    let mut snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::CreateRun(
                CreateRunCommand {
                    meta: Some(u03c_metadata("create-run")),
                    run_id: U03C_RUN_ID.to_owned(),
                    task_id: task.task_id.clone(),
                    task_revision: task.revision,
                    work_revision: task.work_revision,
                    plan: Some(u03c_run_plan()),
                },
            )),
        },
        &task_principal,
    );
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::ActivateRun(
                ActivateRunCommand {
                    base: Some(RunCommandBase {
                        meta: Some(u03c_metadata("activate-run")),
                        run_id: U03C_RUN_ID.to_owned(),
                        expected_run_revision: snapshot.run.as_ref().expect("run").revision,
                    }),
                    confirmed_task_revision: task.revision,
                },
            )),
        },
        &task_principal,
    );
    let run_revision = snapshot.run.as_ref().expect("run").revision;
    let step_revision = snapshot.steps.first().expect("step").revision;
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::CreateAttempt(
                CreateAttemptCommand {
                    base: Some(RunCommandBase {
                        meta: Some(u03c_metadata("create-attempt")),
                        run_id: U03C_RUN_ID.to_owned(),
                        expected_run_revision: run_revision,
                    }),
                    step_id: U03C_STEP_ID.to_owned(),
                    expected_step_revision: step_revision,
                    attempt_id: U03C_ATTEMPT_ID.to_owned(),
                    harness_id: "codex-u03c".to_owned(),
                    capability_profile_ref: Some(r8a_reference("u03c-capability")),
                    workspace_ref: U03C_SENSITIVE_WORKSPACE.to_owned(),
                },
            )),
        },
        &control_principal,
    );
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::AcquireAttemptLease(
                AcquireAttemptLeaseCommand {
                    base: Some(u03c_attempt_base(&snapshot, "acquire-lease")),
                    owner_instance_id: "attempt-supervisor:u03c".to_owned(),
                    lease_policy_ref: Some(r8a_reference("u03c-lease")),
                },
            )),
        },
        &control_principal,
    );
    let lease = snapshot.attempts[0]
        .lease
        .as_ref()
        .expect("U-03c lease")
        .clone();
    let run = snapshot.run.as_ref().expect("run");
    let step = &snapshot.steps[0];
    let attempt = &snapshot.attempts[0];
    let source_meta = u03c_metadata("record-dispatch");
    let mut envelope = DispatchEnvelope {
        meta: Some(CommandMetadata {
            command_id: U03C_DISPATCH_ID.to_owned(),
            idempotency_key: U03C_DISPATCH_ID.to_owned(),
            idempotency_scope: attempt.attempt_id.clone(),
            request_digest_sha256: String::new(),
            issued_at: Some(U03cAuthorityClock.now()),
            correlation_id: source_meta.correlation_id.clone(),
            causation_id: Some(source_meta.command_id.clone()),
        }),
        run_id: run.run_id.clone(),
        run_revision: run.revision + 1,
        step_id: step.step_id.clone(),
        step_revision: step.revision + 1,
        attempt_id: attempt.attempt_id.clone(),
        attempt_revision: attempt.revision + 1,
        dispatch_id: U03C_DISPATCH_ID.to_owned(),
        dispatch_fingerprint: String::new(),
        fencing_token: lease.fencing_token,
        capability_profile_ref: attempt.capability_profile_ref.clone(),
        input_bundle_ref: "input-u03c-result.json".to_owned(),
        input_bundle_sha256: "71".repeat(32),
        workspace_ref: attempt.workspace_ref.clone(),
        budget_profile_ref: run.plan.as_ref().expect("plan").budget_profile_ref.clone(),
        sandbox_profile_ref: Some(r8a_reference("u03c-sandbox")),
        tool_policy_ref: Some(r8a_reference("u03c-tools")),
        data_egress_policy_ref: Some(r8a_reference("u03c-egress")),
        approval_policy_ref: Some(r8a_reference("u03c-approval")),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        native_session_ref: None,
        checkpoint_ref: None,
        route_binding: None,
    };
    envelope.dispatch_fingerprint = canonical_dispatch_fingerprint(&envelope);
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::RecordDispatchIntent(
                RecordDispatchIntentCommand {
                    base: Some(u03c_attempt_base(&snapshot, "record-dispatch")),
                    lease_id: lease.lease_id.clone(),
                    fencing_token: lease.fencing_token,
                    dispatch_id: U03C_DISPATCH_ID.to_owned(),
                    dispatch_fingerprint: envelope.dispatch_fingerprint.clone(),
                },
            )),
        },
        &control_principal,
    );
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::RecordDeliveryReceipt(
                RecordDeliveryReceiptCommand {
                    base: Some(u03c_attempt_base(&snapshot, "record-delivery")),
                    dispatch_id: U03C_DISPATCH_ID.to_owned(),
                    fencing_token: lease.fencing_token,
                    delivery_receipt_id: "delivery-u03c".to_owned(),
                    receipt_digest_sha256: "72".repeat(32),
                },
            )),
        },
        &adapter_principal,
    );
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::RecordHarnessAck(
                RecordHarnessAckCommand {
                    base: Some(u03c_attempt_base(&snapshot, "record-ack")),
                    dispatch_id: U03C_DISPATCH_ID.to_owned(),
                    fencing_token: lease.fencing_token,
                    harness_sequence: 1,
                    ack_receipt_id: "ack-u03c".to_owned(),
                    receipt_digest_sha256: "73".repeat(32),
                },
            )),
        },
        &adapter_principal,
    );
    snapshot = u03c_collaboration_snapshot(
        &mut control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::RecordRunningObservation(
                RecordRunningObservationCommand {
                    base: Some(u03c_attempt_base(&snapshot, "record-running")),
                    fencing_token: lease.fencing_token,
                    harness_sequence: 2,
                    lifecycle_event_id: "running-u03c".to_owned(),
                    event_digest_sha256: "74".repeat(32),
                },
            )),
        },
        &adapter_principal,
    );
    assert_eq!(snapshot.attempts[0].status, AttemptStatus::Running as i32);
    let _ = artifact_principal;
    (control, snapshot)
}

fn u03c_artifact_principal(
    kind: ArtifactPrincipalKind,
    principal_id: &str,
) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
    }
}

fn u03c_artifact_command(command: artifact_command::Command) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(command),
    };
    let digest = canonical_artifact_request_digest(&command)
        .expect("canonical U-03c Artifact request digest");
    let metadata = match command.command.as_mut().expect("Artifact command") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_mut(),
        _ => None,
    }
    .expect("U-03c Artifact command metadata");
    metadata.request_digest_sha256 = digest;
    command
}

fn u03c_execute_artifact(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    command: artifact_command::Command,
    principal: &AuthenticatedArtifactPrincipal,
) {
    let operation = match &command {
        artifact_command::Command::StageArtifact(_) => "stage_artifact",
        artifact_command::Command::SealArtifact(_) => "seal_artifact",
        artifact_command::Command::ProposeClaim(_) => "propose_claim",
        artifact_command::Command::RecordEvidence(_) => "record_evidence",
        artifact_command::Command::CreateArtifactSet(_) => "create_artifact_set",
        artifact_command::Command::SealArtifactSet(_) => "seal_artifact_set",
        artifact_command::Command::SubmitReturnHandoff(_) => "submit_return_handoff",
        _ => "other",
    };
    let result = authority
        .execute(&u03c_artifact_command(command), principal)
        .expect("U-03c Artifact Authority command");
    assert!(
        result.committed || result.replayed,
        "U-03c Artifact {operation} must commit or exact-replay: code={} fingerprint={:?}",
        result.error_code,
        result.safe_error_fingerprint
    );
}

fn u03c_lineage(task: &TaskSnapshot, collaboration: &CollaborationSnapshot) -> LineageBinding {
    let run = collaboration.run.as_ref().expect("U-03c run");
    let step = collaboration.steps.first().expect("U-03c step");
    let attempt = collaboration.attempts.first().expect("U-03c attempt");
    LineageBinding {
        task_id: task.task_id.clone(),
        task_revision: task.revision,
        work_revision: task.work_revision,
        run_id: run.run_id.clone(),
        run_revision: run.revision,
        step_id: step.step_id.clone(),
        step_revision: step.revision,
        attempt_id: attempt.attempt_id.clone(),
        attempt_revision: attempt.revision,
        dispatch_id: attempt.dispatch_id.clone().expect("U-03c dispatch"),
        fencing_token: attempt
            .lease
            .as_ref()
            .expect("U-03c attempt lease")
            .fencing_token,
    }
}

fn u03c_seed_artifact(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    task: &TaskSnapshot,
    collaboration: &CollaborationSnapshot,
) -> (ArtifactSet, ReturnHandoff) {
    let lineage = u03c_lineage(task, collaboration);
    let producer = ProducerIdentity {
        principal_kind: ArtifactPrincipalKind::Harness.as_str().to_owned(),
        principal_id: U03C_SENSITIVE_PRINCIPAL.to_owned(),
        component_name: "u03c-governed-harness".to_owned(),
        component_version: "1".to_owned(),
        capability_profile_id: Some("u03c-capability".to_owned()),
        native_execution_ref: Some("native-u03c-never-render".to_owned()),
    };
    let content_bytes = format!("U-03c governed artifact bytes {U03C_SENSITIVE_RAW}").into_bytes();
    let content = content_address(&content_bytes);
    authority
        .put_blob(&content_bytes, &content)
        .expect("persist U-03c Artifact blob");
    u03c_execute_artifact(
        authority,
        artifact_command::Command::StageArtifact(StageArtifactCommand {
            metadata: Some(u03c_metadata("stage-artifact")),
            candidate: Some(ArtifactDescriptor {
                artifact_id: U03C_ARTIFACT_ID.to_owned(),
                revision: 1,
                status: ArtifactStatus::Staged as i32,
                semantic_class: ArtifactSemanticClass::FinalMessage as i32,
                type_contract_ref: Some(r8a_reference("r8a-artifact-type")),
                media_type: "text/plain; charset=utf-8".to_owned(),
                content: Some(content.clone()),
                integrity_status: IntegrityStatus::Unverified as i32,
                provenance: Some(Provenance {
                    lineage: Some(lineage.clone()),
                    producer: Some(producer.clone()),
                    input_artifact_ids: vec!["input-artifact-u03c".to_owned()],
                    transformation_contract_ref: Some(r8a_reference("r8a-transformation")),
                    workspace_ref: U03C_SENSITIVE_WORKSPACE.to_owned(),
                    observed_at: Some(prost_types::Timestamp {
                        seconds: 1_788_220_801,
                        nanos: 0,
                    }),
                    captured_at: Some(prost_types::Timestamp {
                        seconds: 1_788_220_802,
                        nanos: 0,
                    }),
                    raw_source_ref: Some(U03C_SENSITIVE_RAW.to_owned()),
                }),
                sensitivity_class: "internal".to_owned(),
                retention_profile_ref: Some(r8a_reference("r8a-retention")),
                created_at: None,
                sealed_at: None,
                supersedes_artifact_id: None,
                quarantine_reason_code: None,
            }),
        }),
        &u03c_artifact_principal(ArtifactPrincipalKind::Harness, U03C_SENSITIVE_PRINCIPAL),
    );
    u03c_execute_artifact(
        authority,
        artifact_command::Command::SealArtifact(SealArtifactCommand {
            metadata: Some(u03c_metadata("seal-artifact")),
            artifact_id: U03C_ARTIFACT_ID.to_owned(),
            expected_revision: 1,
            observed_content: Some(content),
        }),
        &u03c_artifact_principal(
            ArtifactPrincipalKind::ArtifactAuthority,
            "artifact-authority:u03c",
        ),
    );

    let statement_bytes = b"U-03c safe claim statement".to_vec();
    let statement = content_address(&statement_bytes);
    authority
        .put_blob(&statement_bytes, &statement)
        .expect("persist U-03c Claim statement");
    u03c_execute_artifact(
        authority,
        artifact_command::Command::ProposeClaim(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::ProposeClaimCommand {
                metadata: Some(u03c_metadata("propose-claim")),
                claim: Some(Claim {
                    claim_id: U03C_CLAIM_ID.to_owned(),
                    revision: 1,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(r8a_reference("r8a-claim-semantic")),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
                    acceptance_contract_ref: task.acceptance_contract_ref.clone(),
                    statement: Some(statement),
                    proposer: Some(producer.clone()),
                    proposed_at: None,
                    supersedes_claim_id: None,
                }),
            },
        ),
        &u03c_artifact_principal(ArtifactPrincipalKind::Harness, U03C_SENSITIVE_PRINCIPAL),
    );

    let coverage_bytes = b"U-03c complete governed evidence coverage".to_vec();
    let coverage = content_address(&coverage_bytes);
    authority
        .put_blob(&coverage_bytes, &coverage)
        .expect("persist U-03c Evidence coverage");
    u03c_execute_artifact(
        authority,
        artifact_command::Command::RecordEvidence(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::RecordEvidenceCommand {
                metadata: Some(u03c_metadata("record-evidence")),
                evidence: Some(Evidence {
                    evidence_id: U03C_EVIDENCE_ID.to_owned(),
                    revision: 1,
                    status: EvidenceStatus::Recorded as i32,
                    relation: EvidenceRelation::Supports as i32,
                    claim_id: U03C_CLAIM_ID.to_owned(),
                    artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
                    evidence_profile_ref: Some(r8a_reference("r8a-evidence-profile")),
                    lineage: Some(lineage.clone()),
                    producer: Some(producer.clone()),
                    producer_class: EvidenceProducerClass::Harness as i32,
                    independent_of_claim_proposer: false,
                    integrity_status: IntegrityStatus::DigestVerified as i32,
                    coverage_descriptor: Some(coverage),
                    limitation_codes: vec!["SAFE_LIMITATION_U03C".to_owned()],
                    recorded_at: None,
                    supersedes_evidence_id: None,
                }),
            },
        ),
        &u03c_artifact_principal(ArtifactPrincipalKind::Harness, U03C_SENSITIVE_PRINCIPAL),
    );

    let mut set = ArtifactSet {
        artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
        revision: 1,
        status: ArtifactSetStatus::Draft as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
        claim_ids: vec![U03C_CLAIM_ID.to_owned()],
        evidence_ids: vec![U03C_EVIDENCE_ID.to_owned()],
        canonical_manifest: None,
        created_at: None,
        sealed_at: None,
        supersedes_artifact_set_id: None,
    };
    let manifest_bytes = canonical_artifact_set_manifest(&set);
    let manifest = content_address(&manifest_bytes);
    set.canonical_manifest = Some(manifest.clone());
    authority
        .put_blob(&manifest_bytes, &manifest)
        .expect("persist U-03c ArtifactSet manifest");
    u03c_execute_artifact(
        authority,
        artifact_command::Command::CreateArtifactSet(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::CreateArtifactSetCommand {
                metadata: Some(u03c_metadata("create-artifact-set")),
                artifact_set: Some(set.clone()),
            },
        ),
        &u03c_artifact_principal(ArtifactPrincipalKind::GovernedCollector, "collector:u03c"),
    );
    u03c_execute_artifact(
        authority,
        artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
            metadata: Some(u03c_metadata("seal-artifact-set")),
            artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
            expected_revision: 1,
            observed_manifest: Some(manifest.clone()),
        }),
        &u03c_artifact_principal(
            ArtifactPrincipalKind::ArtifactAuthority,
            "artifact-authority:u03c",
        ),
    );
    set.revision = 2;
    set.status = ArtifactSetStatus::Sealed as i32;
    let handoff = ReturnHandoff {
        return_handoff_id: U03C_RETURN_HANDOFF_ID.to_owned(),
        revision: 1,
        status: ReturnHandoffStatus::Submitted as i32,
        lineage: Some(lineage),
        artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
        artifact_set_manifest: Some(manifest),
        primary_claim_ids: vec![U03C_CLAIM_ID.to_owned()],
        evidence_ids: vec![U03C_EVIDENCE_ID.to_owned()],
        limitation_artifact_ids: Vec::new(),
        unknown_artifact_ids: Vec::new(),
        final_message_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
        submitted_by: Some(ProducerIdentity {
            principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
            principal_id: "collector:u03c".to_owned(),
            component_name: "u03c-governed-collector".to_owned(),
            component_version: "1".to_owned(),
            capability_profile_id: None,
            native_execution_ref: None,
        }),
        submitted_at: None,
        supersedes_return_handoff_id: None,
    };
    u03c_execute_artifact(
        authority,
        artifact_command::Command::SubmitReturnHandoff(SubmitReturnHandoffCommand {
            metadata: Some(u03c_metadata("submit-return-handoff")),
            return_handoff: Some(handoff.clone()),
            expected_artifact_set_revision: 2,
        }),
        &u03c_artifact_principal(ArtifactPrincipalKind::GovernedCollector, "collector:u03c"),
    );
    (set, handoff)
}

fn u03c_verification_principal(
    kind: VerificationPrincipalKind,
    principal_id: &str,
    checker_profile_id: Option<&str>,
) -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
        checker_profile_id: checker_profile_id.map(str::to_owned),
    }
}

fn u03c_verification_command(command: verification_command::Command) -> VerificationCommand {
    let mut command = VerificationCommand {
        command: Some(command),
    };
    let digest = canonical_verification_request_digest(&command)
        .expect("canonical U-03c Verification request digest");
    let metadata = match command.command.as_mut().expect("Verification command") {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        verification_command::Command::CreateVerificationRequest(value) => value.metadata.as_mut(),
        verification_command::Command::StartVerificationRun(value) => value.metadata.as_mut(),
        verification_command::Command::RecordCriterionResult(value) => value.metadata.as_mut(),
        verification_command::Command::CompleteVerification(value) => value.metadata.as_mut(),
        _ => None,
    }
    .expect("U-03c Verification command metadata");
    metadata.request_digest_sha256 = digest;
    command
}

fn u03c_execute_verification(
    authority: &mut VerificationAuthority,
    command: verification_command::Command,
    principal: &AuthenticatedVerificationPrincipal,
) -> egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationCommandResult {
    let operation = match &command {
        verification_command::Command::AttestCheckerProfile(_) => "attest_checker_profile",
        verification_command::Command::CreateVerificationRequest(_) => "create_request",
        verification_command::Command::StartVerificationRun(_) => "start_run",
        verification_command::Command::RecordCriterionResult(_) => "record_criterion",
        verification_command::Command::CompleteVerification(_) => "complete_verification",
        _ => "other",
    };
    let result = authority
        .execute(&u03c_verification_command(command), principal)
        .expect("U-03c Verification Authority command");
    assert!(
        result.committed || result.replayed,
        "U-03c Verification {operation} rejected: {:?}",
        result.safe_error_fingerprint
    );
    result
}

fn u03c_seed_verification(
    authority: &mut VerificationAuthority,
    task: &TaskSnapshot,
    set: &ArtifactSet,
) -> VerificationArtifact {
    let binding = VerificationBinding {
        lineage: set.lineage.clone(),
        artifact_set_id: set.artifact_set_id.clone(),
        artifact_set_manifest: set.canonical_manifest.clone(),
        claim_id: U03C_CLAIM_ID.to_owned(),
        claim_semantic_profile_ref: Some(r8a_reference("r8a-claim-semantic")),
        acceptance_contract_ref: task.acceptance_contract_ref.clone(),
    };
    let mut profile = CheckerProfile {
        checker_profile_id: U03C_CHECKER_PROFILE_ID.to_owned(),
        revision: 1,
        status: CheckerProfileStatus::Active as i32,
        checker_id: "deterministic:u03c".to_owned(),
        checker_version: "1".to_owned(),
        input_contract_ref: Some(r8a_reference("u03c-verification-input")),
        output_contract_ref: Some(r8a_reference("u03c-verification-output")),
        supported_criterion_types: vec!["criterion-u03c".to_owned()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(r8a_reference("u03c-verification-sandbox")),
        tool_policy_ref: Some(r8a_reference("u03c-verification-tools")),
        data_egress_policy_ref: Some(r8a_reference("u03c-verification-egress")),
        timeout_ms: 1_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    let profile_ref = ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    };
    let authority_principal = u03c_verification_principal(
        VerificationPrincipalKind::VerificationAuthority,
        U03C_SENSITIVE_PRINCIPAL,
        None,
    );
    u03c_execute_verification(
        authority,
        verification_command::Command::AttestCheckerProfile(AttestCheckerProfileCommand {
            metadata: Some(u03c_metadata("attest-checker")),
            profile: Some(profile),
        }),
        &authority_principal,
    );
    let request = VerificationRequest {
        verification_request_id: U03C_VERIFICATION_REQUEST_ID.to_owned(),
        revision: 1,
        status: VerificationStatus::Queued as i32,
        verification_type: "task_acceptance".to_owned(),
        binding: Some(binding.clone()),
        criterion_ids: vec!["criterion-u03c".to_owned()],
        checker_profile_refs: vec![profile_ref.clone()],
        created_at: None,
        hold_reason_code: None,
    };
    u03c_execute_verification(
        authority,
        verification_command::Command::CreateVerificationRequest(
            CreateVerificationRequestCommand {
                metadata: Some(u03c_metadata("create-verification-request")),
                request: Some(request.clone()),
            },
        ),
        &u03c_verification_principal(
            VerificationPrincipalKind::TaskAuthority,
            "task-authority:u03c",
            None,
        ),
    );
    u03c_execute_verification(
        authority,
        verification_command::Command::StartVerificationRun(StartVerificationRunCommand {
            metadata: Some(u03c_metadata("start-verification-run")),
            verification_request_id: request.verification_request_id.clone(),
            expected_request_revision: 1,
            verification_run_id: U03C_VERIFICATION_RUN_ID.to_owned(),
        }),
        &authority_principal,
    );
    let result = CriterionResult {
        criterion_result_id: "criterion-result-u03c".to_owned(),
        criterion_id: "criterion-u03c".to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        outcome: CriterionOutcome::Passed as i32,
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        checker_profile_ref: Some(profile_ref.clone()),
        evidence_coverage: EvidenceCoverage::Complete as i32,
        evidence_ids: vec![U03C_EVIDENCE_ID.to_owned()],
        discrepancy_ids: vec!["discrepancy-u03c".to_owned()],
        unverified_item_ids: vec!["unverified-u03c".to_owned()],
        duration_ms: 17,
        safe_detail_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
    };
    let checker_principal = u03c_verification_principal(
        VerificationPrincipalKind::DeterministicChecker,
        U03C_SENSITIVE_PRINCIPAL,
        Some(U03C_CHECKER_PROFILE_ID),
    );
    u03c_execute_verification(
        authority,
        verification_command::Command::RecordCriterionResult(RecordCriterionResultCommand {
            metadata: Some(u03c_metadata("record-criterion")),
            verification_run_id: U03C_VERIFICATION_RUN_ID.to_owned(),
            expected_run_revision: 1,
            result: Some(result.clone()),
        }),
        &checker_principal,
    );
    let candidate = VerificationArtifact {
        verification_artifact_id: U03C_VERIFICATION_ID.to_owned(),
        version: 1,
        verification_request_id: request.verification_request_id,
        verification_run_id: U03C_VERIFICATION_RUN_ID.to_owned(),
        verification_type: request.verification_type,
        binding: Some(binding),
        conclusion: VerificationConclusion::Passed as i32,
        overall_evidence_coverage: EvidenceCoverage::Complete as i32,
        criterion_results: vec![result],
        discrepancies: vec![Discrepancy {
            discrepancy_id: "discrepancy-u03c".to_owned(),
            criterion_id: "criterion-u03c".to_owned(),
            severity: DiscrepancySeverity::Info as i32,
            evidence_ids: vec![U03C_EVIDENCE_ID.to_owned()],
            description_artifact_id: U03C_ARTIFACT_ID.to_owned(),
            suggested_fix_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
        }],
        unverified_items: vec![UnverifiedItem {
            unverified_item_id: "unverified-u03c".to_owned(),
            criterion_id: "criterion-u03c".to_owned(),
            reason: UnverifiedReason::RequiresJudgement as i32,
            evidence_ids: vec![U03C_EVIDENCE_ID.to_owned()],
            context_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
        }],
        provenance: Some(VerificationProvenance {
            verifier_principal_id: U03C_SENSITIVE_PRINCIPAL.to_owned(),
            checker_profile_refs: vec![profile_ref],
            tool_receipt_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
            model_call_receipt_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
            raw_output_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
            duration_ms: 17,
            cost_receipt_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
        }),
        canonical_payload: None,
        completed_at: None,
        supersedes_verification_artifact_id: None,
    };
    let completed = u03c_execute_verification(
        authority,
        verification_command::Command::CompleteVerification(CompleteVerificationCommand {
            metadata: Some(u03c_metadata("complete-verification")),
            verification_run_id: U03C_VERIFICATION_RUN_ID.to_owned(),
            expected_run_revision: 2,
            artifact: Some(candidate),
        }),
        &authority_principal,
    );
    completed
        .artifact
        .expect("U-03c committed Verification artifact")
}

fn u03c_submit_task_evidence(
    authority: &mut TaskAuthority,
    current: &TaskSnapshot,
) -> TaskSnapshot {
    u03c_execute_task(
        authority,
        TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    meta: Some(u03c_metadata("submit-task-evidence")),
                    task_id: current.task_id.clone(),
                    expected_revision: current.revision,
                    work_revision: current.work_revision,
                    return_handoff_id: U03C_RETURN_HANDOFF_ID.to_owned(),
                    artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
                },
            )),
        },
        &u03c_task_principal(
            TaskPrincipalKind::CollaborationControl,
            "collaboration-control:u03c",
        ),
    )
}

fn u03c_record_task_verification(
    authority: &mut TaskAuthority,
    current: &TaskSnapshot,
) -> TaskSnapshot {
    u03c_execute_task(
        authority,
        TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    meta: Some(u03c_metadata("record-task-verification")),
                    task_id: current.task_id.clone(),
                    expected_revision: current.revision,
                    work_revision: current.work_revision,
                    verification_artifact_id: U03C_VERIFICATION_ID.to_owned(),
                },
            )),
        },
        &u03c_task_principal(
            TaskPrincipalKind::SegoVerification,
            "verification-authority:u03c",
        ),
    )
}

fn u03c_issue_rework_verdict(
    authority: &mut FounderVerdictAuthority,
    task: &TaskSnapshot,
    set: &ArtifactSet,
    verification: &VerificationArtifact,
) -> (
    egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdict,
    FounderVerdictState,
) {
    let mut command = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(u03c_metadata("issue-rework-verdict")),
                scope: Some(VerdictScope {
                    task_id: task.task_id.clone(),
                    task_revision: task.revision,
                    work_revision: task.work_revision,
                    artifact_set_id: set.artifact_set_id.clone(),
                    artifact_set_manifest: set.canonical_manifest.clone(),
                    verification_artifact_id: verification.verification_artifact_id.clone(),
                    verification_payload: verification.canonical_payload.clone(),
                    acceptance_contract_ref: task.acceptance_contract_ref.clone(),
                }),
                decision: FounderVerdictDecision::Rework as i32,
                observed_verification_conclusion: verification.conclusion,
                risk_acceptances: vec![RiskAcceptance {
                    risk_acceptance_id: "risk-u03c".to_owned(),
                    category: RiskCategory::QualityResidual as i32,
                    discrepancy_ids: vec!["discrepancy-u03c".to_owned()],
                    unverified_item_ids: vec!["unverified-u03c".to_owned()],
                    rationale_artifact_id: U03C_ARTIFACT_ID.to_owned(),
                    compensating_control_artifact_ids: vec![U03C_ARTIFACT_ID.to_owned()],
                    review_trigger_code: Some("review:u03c".to_owned()),
                }],
                rework_directive: Some(ReworkDirective {
                    directive_id: "rework-u03c".to_owned(),
                    reason_code: "acceptance-followup-required".to_owned(),
                    required_changes_artifact_id: U03C_ARTIFACT_ID.to_owned(),
                    target_discrepancy_ids: vec!["discrepancy-u03c".to_owned()],
                    target_unverified_item_ids: vec!["unverified-u03c".to_owned()],
                }),
                reason_code: "review-rework".to_owned(),
                rationale_artifact_id: Some(U03C_ARTIFACT_ID.to_owned()),
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: U03C_SENSITIVE_PROOF.to_owned(),
                expires_at: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 0,
                }),
                supersedes_founder_verdict_id: None,
            },
        )),
    };
    let digest = egopulse_founder_verdict_authority::canonical_request_digest(&command);
    if let Some(verdict_command::Command::IssueFounderVerdict(issue)) = command.command.as_mut() {
        issue
            .metadata
            .as_mut()
            .expect("U-03c verdict metadata")
            .request_digest_sha256 = digest;
    }
    let result = authority
        .execute(
            &command,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::FounderAuthority,
                principal_id: U03C_SENSITIVE_PRINCIPAL.to_owned(),
                authenticated: true,
            },
        )
        .expect("issue U-03c Founder REWORK verdict");
    assert!(
        result.committed || result.replayed,
        "U-03c verdict rejected: code={} fingerprint={:?}",
        result.error_code,
        result.safe_error_fingerprint
    );
    (
        result.verdict.expect("U-03c Founder verdict"),
        result.state.expect("U-03c Founder verdict state"),
    )
}

fn u03c_apply_rework_verdict(
    authority: &mut TaskAuthority,
    current: &TaskSnapshot,
    founder_verdict_id: &str,
) -> TaskSnapshot {
    let snapshot = u03c_execute_task(
        authority,
        TaskCommand {
            command: Some(task_command::Command::ApplyFounderVerdict(
                ApplyFounderVerdictCommand {
                    meta: Some(u03c_metadata("apply-rework-verdict")),
                    task_id: current.task_id.clone(),
                    expected_revision: current.revision,
                    work_revision: current.work_revision,
                    founder_verdict_id: founder_verdict_id.to_owned(),
                },
            )),
        },
        &u03c_task_principal(
            TaskPrincipalKind::FounderAuthority,
            "founder-authority:u03c",
        ),
    );
    assert_eq!(snapshot.status, TaskStatus::Rework as i32);
    assert_eq!(
        snapshot.founder_verdict_id.as_deref(),
        Some(founder_verdict_id)
    );
    snapshot
}

fn u03c_complete_collaboration_return(
    control: &mut CollaborationControl<U03cCollaborationGuard, U03cAuthorityClock>,
    mut snapshot: CollaborationSnapshot,
) -> CollaborationSnapshot {
    let attempt = snapshot.attempts.first().expect("U-03c attempt").clone();
    let returned = u03c_collaboration_snapshot(
        control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::RecordAttemptReturn(
                RecordAttemptReturnCommand {
                    base: Some(u03c_attempt_base(&snapshot, "record-return")),
                    fencing_token: attempt.lease.as_ref().expect("U-03c lease").fencing_token,
                    harness_sequence: 3,
                    artifact_return_receipt_id: "return-receipt-u03c".to_owned(),
                    receipt_digest_sha256: "93".repeat(32),
                },
            )),
        },
        &u03c_collaboration_principal(
            CollaborationPrincipalKind::ArtifactAuthority,
            "artifact-authority:u03c",
        ),
    );
    snapshot = returned;
    let step = snapshot.steps.first().expect("U-03c step");
    u03c_collaboration_snapshot(
        control,
        CollaborationCommand {
            command: Some(collaboration_command::Command::CommitStepReturn(
                CommitStepReturnCommand {
                    base: Some(RunCommandBase {
                        meta: Some(u03c_metadata("commit-step-return")),
                        run_id: snapshot.run.as_ref().expect("U-03c run").run_id.clone(),
                        expected_run_revision: snapshot.run.as_ref().expect("U-03c run").revision,
                    }),
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: U03C_ATTEMPT_ID.to_owned(),
                    artifact_set_id: U03C_ARTIFACT_SET_ID.to_owned(),
                    return_handoff_id: U03C_RETURN_HANDOFF_ID.to_owned(),
                },
            )),
        },
        &u03c_collaboration_principal(
            CollaborationPrincipalKind::CollaborationControl,
            "collaboration-control:u03c",
        ),
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

fn open_u03c_fixture_providers(root: &Path) -> DaemonProviders {
    let verdict_handle = Arc::new(Mutex::new(None));
    let task_guard =
        ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(&verdict_handle));
    let mut task = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        AllowTaskReferences,
        task_guard,
    )
    .expect("open U-03c Task Authority");
    let active_task = u03c_seed_task_ready(&mut task);
    let (mut collaboration, running_collaboration) = u03c_seed_collaboration(root, &active_task);

    let collector = r8a_native_config(root).return_collector;
    let artifact_guard =
        ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
            allowed_workspace_refs: [
                collector.workspace_ref.clone(),
                U03C_SENSITIVE_WORKSPACE.to_owned(),
            ]
            .into_iter()
            .collect(),
            allowed_artifact_type_refs: vec![collector.artifact_type_ref.clone()],
            allowed_transformation_contract_refs: vec![
                collector.transformation_contract_ref.clone(),
            ],
            allowed_retention_profile_refs: vec![collector.retention_profile_ref.clone()],
            allowed_claim_semantic_profile_refs: vec![collector.claim_semantic_profile_ref.clone()],
            allowed_claim_acceptance_contract_refs: vec![
                collector.claim_acceptance_contract_ref.clone(),
                active_task
                    .acceptance_contract_ref
                    .clone()
                    .expect("U-03c Task acceptance contract"),
            ],
            allowed_evidence_profile_refs: vec![collector.evidence_profile_ref.clone()],
        })
        .expect("U-03c Artifact admission guard");
    let mut artifact = ArtifactAuthority::open(
        ArtifactAuthorityConfig {
            database_path: root.join("u03c-artifact-authority.db"),
            blob_root: root.join("u03c-artifact-blobs"),
            store_epoch: "u03c-artifact-epoch".to_owned(),
            key: ArtifactSqlCipherKey::new([0x74; 32]),
        },
        artifact_guard,
    )
    .expect("open U-03c Artifact Authority");
    let (artifact_set, _handoff) =
        u03c_seed_artifact(&mut artifact, &active_task, &running_collaboration);
    let evidence_pending = u03c_submit_task_evidence(&mut task, &active_task);

    let artifact = Arc::new(Mutex::new(artifact));
    let verification_resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(Arc::clone(&artifact)),
        vec![CriterionPolicySnapshot {
            criterion_id: "criterion-u03c".to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::Deterministic as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![U03C_CHECKER_PROFILE_ID.to_owned()],
        }],
    )
    .expect("U-03c Verification resolver");
    let mut verification = VerificationAuthority::open(
        VerificationAuthorityConfig {
            database_path: root.join("u03c-verification-authority.db"),
            store_epoch: "u03c-verification-epoch".to_owned(),
            key: VerificationSqlCipherKey::new([0x75; 32]),
        },
        verification_resolver,
    )
    .expect("open U-03c Verification Authority");
    let verification_artifact =
        u03c_seed_verification(&mut verification, &evidence_pending, &artifact_set);
    let verdict_pending = u03c_record_task_verification(&mut task, &evidence_pending);
    assert_eq!(verdict_pending.status, TaskStatus::VerdictPending as i32);
    assert!(verdict_pending.founder_verdict_id.is_none());

    let mut verdict = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.join("verdict-authority.db"),
            store_epoch: "c5-00-verdict-epoch".to_owned(),
            key: VerdictSqlCipherKey::new([0x13; 32]),
        },
        U03cVerdictReferences,
    )
    .expect("open U-03c Founder Verdict Authority");
    let (founder_verdict, _founder_state) = u03c_issue_rework_verdict(
        &mut verdict,
        &verdict_pending,
        &artifact_set,
        &verification_artifact,
    );
    *verdict_handle.lock().expect("U-03c verdict handle") = Some(verdict);
    let rework = u03c_apply_rework_verdict(
        &mut task,
        &verdict_pending,
        &founder_verdict.founder_verdict_id,
    );
    assert_eq!(rework.status, TaskStatus::Rework as i32);

    let returned_collaboration =
        u03c_complete_collaboration_return(&mut collaboration, running_collaboration);
    assert_eq!(
        returned_collaboration
            .run
            .as_ref()
            .expect("U-03c run")
            .status,
        RunStatus::Returned as i32
    );

    let verification = Arc::new(Mutex::new(verification));
    let mut additional_projection_sources: Vec<Arc<dyn OwnerProjectionSource>> = vec![
        Arc::new(CollaborationProjectionSource::new(collaboration)),
        Arc::new(ArtifactProjectionSource::new_shared(Arc::clone(&artifact))),
    ];
    if fixture_mode() != U03C_RESULT_REVIEW_STALE_MODE {
        additional_projection_sources.push(Arc::new(VerificationProjectionSource::new_shared(
            Arc::clone(&verification),
        )));
    }
    let policy = PolicyDecisionAuthority::open(
        PolicyAuthorityConfig {
            database_path: root.join("policy-authority.db"),
            store_epoch: "c5-00-policy-epoch".to_owned(),
            key: PolicySqlCipherKey::new([0x12; 32]),
        },
        AllowPolicyReferences,
    )
    .expect("open U-03c Policy Authority");
    let session_principal_resolver: Arc<dyn TrustedPrincipalResolver> =
        if fixture_mode() == U03C_RESULT_REVIEW_DENY_MODE {
            Arc::new(U03cDenyResultReadSessionResolver)
        } else {
            Arc::new(FixtureSessionResolver)
        };
    DaemonProviders::from_shared_authority_inputs(SharedAuthorityCompositionInputs {
        task: Arc::new(Mutex::new(task)),
        policy,
        verdict: verdict_handle,
        principal_resolver: Arc::new(FixtureAuthorityPrincipalResolver),
        session_principal_resolver,
        session_clock: Arc::new(egopulse_local_api::session::SystemSessionClock),
        session_audit: Arc::new(NoopSessionAuditSink),
        additional_projection_sources,
    })
}

fn open_fixture_providers(root: &Path) -> DaemonProviders {
    if matches!(
        fixture_mode().as_str(),
        U03C_RESULT_REVIEW_MODE | U03C_RESULT_REVIEW_DENY_MODE | U03C_RESULT_REVIEW_STALE_MODE
    ) {
        return open_u03c_fixture_providers(root);
    }
    if matches!(
        fixture_mode().as_str(),
        R9B_TASK_SINGLE_DISCONNECT_MODE | R9B_RETENTION_RESET_MODE
    ) {
        return open_fixture_providers_with_guards(
            root,
            AllowTaskReferences,
            AllowPolicyReferences,
            AllowVerdictReferences,
            vec![Arc::new(R9bTaskDisconnectProjectionSource::new(root))],
        );
    }
    if matches!(
        fixture_mode().as_str(),
        "allow"
            | R9B_GOVERNED_STATE_MODE
            | R9B_DENY_TASK_READ_MODE
            | R9B_DENY_APPROVAL_READ_MODE
            | R8A_FIXTURE_MODE
            | M13_MEMORY_DISPATCH_MODE
            | PHASE_ONE_MULTI_TASK_MODE
            | R8B_PAUSE_BEFORE_RUNNER_MODE
            | R8B2C_BEGIN_DELIVERY_MODE
            | R8B2C_UNKNOWN_RECOVERY_MODE
            | R8B2C_DELIVERED_BEFORE_POLL_MODE
            | R9A3D_EXTERNAL_SEND_MODE
            | R9A3D_EXTERNAL_RECOVERY_MODE
            | R9A3E_PREAUTH_UNAVAILABLE_MODE
            | R9A3E_REVOKED_READY_MODE
            | R9C_CONTENT_MODE
            | U04C_PREPARE_POST_COMMIT_MODE
            | U04C_CONFIRM_POST_COMMIT_MODE
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
                session_principal_resolver: fixture_session_principal_resolver(),
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
                session_principal_resolver: fixture_session_principal_resolver(),
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
    let native = r8a_native_config(root);
    let (work_capability_registry, work_capability_route) = fixture_work_capability(root, &native);
    let mut work_port = ConfiguredWorkPreparationPort::new(
        Arc::clone(&context),
        Arc::clone(&providers.task_port),
        providers.work_memory_retrieval_port(),
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
    .expect("fixture Work Preparation should configure")
    .with_work_capability_registry(Arc::clone(&work_capability_registry));
    if dynamic_fixture_mode() {
        work_port = work_port
            .with_input_bundle_root(root.join("input-bundles"))
            .and_then(|port| port.with_activation_run_id(R8A_ACTIVATION_RUN_ID.to_owned()))
            .expect("R-8A Work Preparation dispatch binding");
    }
    let work_port: Arc<dyn WorkPreparationPort> = match fixture_mode().as_str() {
        U04C_PREPARE_POST_COMMIT_MODE => Arc::new(U04cPostCommitUnavailableWorkPort::new(
            Arc::new(work_port),
            root.to_owned(),
            U04cInjectedOperation::Prepare,
        )),
        U04C_CONFIRM_POST_COMMIT_MODE => Arc::new(U04cPostCommitUnavailableWorkPort::new(
            Arc::new(work_port),
            root.to_owned(),
            U04cInjectedOperation::Confirm,
        )),
        _ => Arc::new(work_port),
    };
    let providers = providers
        .with_work_preparation_port(work_port)
        .with_work_capability_port(work_capability_registry)
        .with_context_authority(Arc::clone(&context))
        .with_context_mutation(Arc::new(ContextMutationPortAdapter::new(
            Arc::clone(&context),
            Arc::new(FixtureAuthorityPrincipalResolver),
        )));
    if !dynamic_fixture_mode() {
        return providers;
    }

    fs::create_dir_all(root.join(&native.workflow.workspace_ref))
        .expect("R-8A governed workspace should exist");
    let (artifact, verification) = r8a_authorities(root, &native.return_collector);
    let mode = fixture_mode();
    let providers = if mode == M13_MEMORY_DISPATCH_MODE {
        providers
            .with_profiled_native_harness_drivers(
                vec![
                    m13_profiled_composition(native, root)
                        .with_work_capability_route(work_capability_route.clone()),
                ],
                artifact,
                verification,
            )
            .expect("M-13 routed native Harness composition")
    } else if mode == R9C_CONTENT_MODE {
        providers
            .with_profiled_native_harness_drivers(
                vec![
                    r9c_profiled_composition(native, root)
                        .with_work_capability_route(work_capability_route.clone()),
                ],
                artifact,
                verification,
            )
            .expect("R-9C native Harness content composition")
    } else if mode == PHASE_ONE_MULTI_TASK_MODE {
        providers
            .with_profiled_native_harness_drivers(
                vec![routed_fixture_composition(
                    native,
                    PhaseOneMultiTaskDriver::new(root),
                    work_capability_route,
                )],
                artifact,
                verification,
            )
            .expect("phase-one multi-task native Harness composition")
    } else if r8b2c_fixture_mode() {
        let driver_mode = if mode == R8B2C_BEGIN_DELIVERY_MODE {
            R8b2cDriverMode::BeginDeliveryBlock
        } else {
            R8b2cDriverMode::Recover
        };
        providers
            .with_profiled_native_harness_drivers(
                vec![routed_fixture_composition(
                    native,
                    R8b2cFixtureDriver::new(root, &fixture_instance(), driver_mode),
                    work_capability_route.clone(),
                )],
                artifact,
                verification,
            )
            .expect("R-8B.2c native Harness composition")
    } else if r9a3d_fixture_mode() {
        providers
            .with_profiled_native_harness_drivers(
                vec![routed_fixture_composition(
                    native,
                    R9a3dFixtureDriver::from_environment(),
                    work_capability_route.clone(),
                )],
                artifact,
                verification,
            )
            .expect("R-9A.3d native Harness composition")
    } else {
        providers
            .with_profiled_native_harness_drivers(
                vec![routed_fixture_composition(
                    native,
                    RecordingFixtureDriver::new(root),
                    work_capability_route,
                )],
                artifact,
                verification,
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
                    | M13_MEMORY_DISPATCH_MODE
                    | PHASE_ONE_MULTI_TASK_MODE
                    | R8B_PAUSE_BEFORE_RUNNER_MODE
                    | R8B2C_BEGIN_DELIVERY_MODE
                    | R8B2C_UNKNOWN_RECOVERY_MODE
                    | R8B2C_DELIVERED_BEFORE_POLL_MODE
                    | R9A3D_EXTERNAL_SEND_MODE
                    | R9A3D_EXTERNAL_RECOVERY_MODE
                    | R9A3E_PREAUTH_UNAVAILABLE_MODE
                    | R9A3E_REVOKED_READY_MODE
                    | R9C_CONTENT_MODE
                    | U03C_RESULT_REVIEW_MODE
                    | U03C_RESULT_REVIEW_DENY_MODE
                    | U03C_RESULT_REVIEW_STALE_MODE
                    | U04C_PREPARE_POST_COMMIT_MODE
                    | U04C_CONFIRM_POST_COMMIT_MODE
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

async fn reviewed_approval_summary_digest(instance: &str, approval_request_id: &str) -> String {
    let output = run_cli(
        instance,
        &["approval", "get", approval_request_id, "--json"],
    )
    .await;
    assert!(
        output.status.success(),
        "approval get must return the current trusted summary: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("approval get JSON envelope");
    assert_eq!(payload["operation"], "approval.get");
    assert_eq!(payload["data"]["approvalRequestId"], approval_request_id);
    assert_eq!(
        payload["data"]["operationSummary"]["reviewable"], true,
        "AllowOnce fixture requires a validated reviewable summary"
    );
    payload["data"]["operationSummary"]["summaryDigestSha256"]
        .as_str()
        .filter(|digest| digest.len() == 64)
        .expect("trusted approval summary digest")
        .to_owned()
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
    run_bounded_fixture_command_with_timeout(
        executable,
        instance,
        arguments,
        label,
        R9A3D_IO_TIMEOUT,
    )
    .await
}

async fn run_bounded_fixture_command_with_timeout(
    executable: PathBuf,
    instance: &str,
    arguments: &[&str],
    label: &str,
    wait: Duration,
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
    let status = match timeout(wait, child.wait()).await {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct RoutedWorkIds {
    run_id: String,
    step_id: String,
    attempt_id: String,
    dispatch_id: String,
}

impl RoutedWorkIds {
    fn from_preview(preview: &serde_json::Value, task_id: &str) -> Self {
        let route_binding_sha256 = preview["data"]["workCapability"]["routeBindingSha256"]
            .as_str()
            .expect("admitted work-capability route binding");
        assert_eq!(route_binding_sha256.len(), 64);
        assert!(
            route_binding_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        Self {
            run_id: format!("run:work:{task_id}:{route_binding_sha256}"),
            step_id: format!("step:work:{task_id}:{route_binding_sha256}"),
            attempt_id: format!("attempt:work:{task_id}:{route_binding_sha256}"),
            dispatch_id: format!("dispatch:work:{task_id}:{route_binding_sha256}"),
        }
    }
}

struct R8b2cPreparedWork {
    task_id: String,
    snapshot_id: String,
    confirmation_binding: String,
    confirm_key: String,
    routed_ids: RoutedWorkIds,
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
            "--no-memory",
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
    let routed_ids = RoutedWorkIds::from_preview(&prepared, &task_id);
    R8b2cPreparedWork {
        task_id,
        snapshot_id,
        confirmation_binding,
        confirm_key,
        routed_ids,
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

fn read_r8b2c_collaboration_oracle(
    root: &Path,
    routed_ids: &RoutedWorkIds,
) -> R8b2cCollaborationOracle {
    let stored = read_r8b2c_collaboration_store(
        &root.join("r8a-collaboration.db"),
        &[0x31; 32],
        &routed_ids.run_id,
        &routed_ids.step_id,
        &routed_ids.attempt_id,
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
    assert_eq!(envelope.run_id, routed_ids.run_id);
    assert_eq!(envelope.step_id, routed_ids.step_id);
    assert_eq!(envelope.attempt_id, routed_ids.attempt_id);
    assert_eq!(envelope.dispatch_id, routed_ids.dispatch_id);
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

fn read_r8b2c_adapter_oracle(root: &Path, routed_ids: &RoutedWorkIds) -> R8b2cAdapterOracle {
    let stored = read_r8b2c_adapter_store(
        &root.join("r8a-adapter.db"),
        &[0x32; 32],
        &routed_ids.dispatch_id,
    )
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

fn phase_one_observation_summary(oracle: &R8b2cAdapterOracle) -> Vec<String> {
    oracle
        .observations
        .iter()
        .map(|observation| {
            format!(
                "observation_id={} native_key={} payload={:?}",
                observation.observation_id, observation.native_key, observation.observation.payload
            )
        })
        .collect()
}

fn u03c_oracle_request<'a>(root: &'a Path, task_id: &'a str) -> GovernedResultOracleRequest<'a> {
    GovernedResultOracleRequest {
        root,
        task_id,
        run_id: U03C_RUN_ID,
        step_id: U03C_STEP_ID,
        attempt_id: U03C_ATTEMPT_ID,
        artifact_id: U03C_ARTIFACT_ID,
        claim_id: U03C_CLAIM_ID,
        evidence_id: U03C_EVIDENCE_ID,
        artifact_set_id: U03C_ARTIFACT_SET_ID,
        return_handoff_id: U03C_RETURN_HANDOFF_ID,
        checker_profile_id: U03C_CHECKER_PROFILE_ID,
        verification_request_id: U03C_VERIFICATION_REQUEST_ID,
        verification_run_id: U03C_VERIFICATION_RUN_ID,
        verification_artifact_id: U03C_VERIFICATION_ID,
        task_profile: ExpectedStoreProfile {
            schema_profile_id: "egopulse/task-authority-store/v1",
            schema_profile_sha256: U03C_TASK_SCHEMA_SHA256,
        },
        collaboration_profile: ExpectedStoreProfile {
            schema_profile_id: "egopulse/collaboration-control-store/v1",
            schema_profile_sha256: U03C_COLLABORATION_SCHEMA_SHA256,
        },
        artifact_profile: ExpectedStoreProfile {
            schema_profile_id: "egopulse/artifact-authority-store/v1",
            schema_profile_sha256: U03C_ARTIFACT_SCHEMA_SHA256,
        },
        verification_profile: ExpectedStoreProfile {
            schema_profile_id: "egopulse/verification-authority-store/v1",
            schema_profile_sha256: U03C_VERIFICATION_SCHEMA_SHA256,
        },
        verdict_profile: ExpectedStoreProfile {
            schema_profile_id: "egopulse/founder-verdict-authority-store/v1",
            schema_profile_sha256: U03C_VERDICT_SCHEMA_SHA256,
        },
    }
}

fn u03c_durability_oracle(root: &Path, task_id: &str) -> GovernedResultDurabilitySnapshot {
    let snapshot = read_governed_result_durability(&u03c_oracle_request(root, task_id))
        .expect("read U-03c Authorities through the strict conformance oracle");
    assert_eq!(snapshot.task.metadata.table_digests.len(), 9);
    assert_eq!(snapshot.collaboration.metadata.table_digests.len(), 11);
    assert_eq!(snapshot.artifact.metadata.table_digests.len(), 12);
    assert_eq!(snapshot.verification.metadata.table_digests.len(), 11);
    assert_eq!(snapshot.verdict.metadata.table_digests.len(), 10);
    let task = TaskSnapshot::decode(snapshot.task.task_snapshot.as_slice())
        .expect("decode U-03c durable Task");
    assert_eq!(task.task_id, task_id);
    assert_eq!(task.status, TaskStatus::Rework as i32);
    assert_eq!(task.artifact_set_id.as_deref(), Some(U03C_ARTIFACT_SET_ID));
    assert_eq!(
        task.verification_artifact_id.as_deref(),
        Some(U03C_VERIFICATION_ID)
    );
    assert!(
        task.founder_verdict_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
    );

    let run = RunSnapshot::decode(snapshot.collaboration.run_snapshot.as_slice())
        .expect("decode U-03c durable Run");
    let step = StepSnapshot::decode(snapshot.collaboration.step_snapshot.as_slice())
        .expect("decode U-03c durable Step");
    let attempt = AttemptSnapshot::decode(snapshot.collaboration.attempt_snapshot.as_slice())
        .expect("decode U-03c durable Attempt");
    assert_eq!(run.task_id, task_id);
    assert_eq!(run.status, RunStatus::Returned as i32);
    assert_eq!(step.status, StepStatus::Returned as i32);
    assert_eq!(attempt.status, AttemptStatus::Returned as i32);
    assert_eq!(attempt.dispatch_id.as_deref(), Some(U03C_DISPATCH_ID));
    let fence = attempt
        .lease
        .as_ref()
        .expect("U-03c durable lease")
        .fencing_token;

    let artifact = ArtifactDescriptor::decode(snapshot.artifact.artifact_snapshot.as_slice())
        .expect("decode U-03c durable Artifact");
    let claim = Claim::decode(snapshot.artifact.claim_snapshot.as_slice())
        .expect("decode U-03c durable Claim");
    let evidence = Evidence::decode(snapshot.artifact.evidence_snapshot.as_slice())
        .expect("decode U-03c durable Evidence");
    let set = ArtifactSet::decode(snapshot.artifact.artifact_set_snapshot.as_slice())
        .expect("decode U-03c durable ArtifactSet");
    let handoff = ReturnHandoff::decode(snapshot.artifact.return_handoff_snapshot.as_slice())
        .expect("decode U-03c durable ReturnHandoff");
    assert_eq!(artifact.artifact_id, U03C_ARTIFACT_ID);
    assert_eq!(claim.claim_id, U03C_CLAIM_ID);
    assert_eq!(evidence.evidence_id, U03C_EVIDENCE_ID);
    assert!(artifact.revision > 0);
    assert_eq!(artifact.status, ArtifactStatus::Sealed as i32);
    assert!(
        artifact
            .content
            .as_ref()
            .is_some_and(|value| { value.digest.len() == 64 && value.byte_length > 0 })
    );
    assert_eq!(claim.status, ClaimStatus::Proposed as i32);
    assert_eq!(claim.subject_artifact_ids, [U03C_ARTIFACT_ID]);
    assert_eq!(evidence.status, EvidenceStatus::Recorded as i32);
    assert_eq!(evidence.claim_id, U03C_CLAIM_ID);
    assert_eq!(evidence.artifact_ids, [U03C_ARTIFACT_ID]);
    assert_eq!(set.status, ArtifactSetStatus::Sealed as i32);
    assert_eq!(set.artifact_ids, [U03C_ARTIFACT_ID]);
    assert_eq!(set.claim_ids, [U03C_CLAIM_ID]);
    assert_eq!(set.evidence_ids, [U03C_EVIDENCE_ID]);
    assert_eq!(handoff.status, ReturnHandoffStatus::Receipted as i32);
    let lineage = set.lineage.as_ref().expect("U-03c ArtifactSet lineage");
    assert_eq!(lineage.task_id, task_id);
    assert_eq!(lineage.run_id, U03C_RUN_ID);
    assert_eq!(lineage.step_id, U03C_STEP_ID);
    assert_eq!(lineage.attempt_id, U03C_ATTEMPT_ID);
    assert_eq!(lineage.dispatch_id, U03C_DISPATCH_ID);
    assert_eq!(lineage.fencing_token, fence);
    assert_eq!(
        Some(lineage),
        artifact
            .provenance
            .as_ref()
            .and_then(|value| value.lineage.as_ref())
    );
    assert_eq!(claim.lineage.as_ref(), Some(lineage));
    assert_eq!(evidence.lineage.as_ref(), Some(lineage));

    let verification =
        VerificationArtifact::decode(snapshot.verification.artifact_snapshot.as_slice())
            .expect("decode U-03c durable Verification artifact");
    assert_eq!(verification.verification_artifact_id, U03C_VERIFICATION_ID);
    assert_eq!(
        verification.conclusion,
        VerificationConclusion::Passed as i32
    );
    assert_eq!(verification.criterion_results.len(), 1);
    assert_eq!(verification.discrepancies.len(), 1);
    assert_eq!(verification.unverified_items.len(), 1);
    assert_eq!(
        verification.criterion_results[0].criterion_id,
        "criterion-u03c"
    );
    assert_eq!(
        verification.criterion_results[0].outcome,
        CriterionOutcome::Passed as i32
    );
    assert_eq!(
        verification.discrepancies[0].discrepancy_id,
        "discrepancy-u03c"
    );
    assert_eq!(
        verification.unverified_items[0].unverified_item_id,
        "unverified-u03c"
    );
    assert_eq!(
        verification
            .binding
            .as_ref()
            .map(|binding| binding.artifact_set_id.as_str()),
        Some(U03C_ARTIFACT_SET_ID)
    );

    let verdict = egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdict::decode(
        snapshot.verdict.verdict_snapshot.as_slice(),
    )
    .expect("decode U-03c durable Founder Verdict");
    let state = FounderVerdictState::decode(snapshot.verdict.state_snapshot.as_slice())
        .expect("decode U-03c durable Founder Verdict state");
    assert!(verdict.version > 0);
    assert_eq!(verdict.decision, FounderVerdictDecision::Rework as i32);
    assert_eq!(verdict.founder_verdict_id, state.founder_verdict_id);
    assert_eq!(state.state, FounderVerdictStateKind::Consumed as i32);
    assert_eq!(state.revision, 2);
    assert_eq!(snapshot.verdict.consumption_receipt_count, 1);
    assert_eq!(
        task.founder_verdict_id.as_deref(),
        Some(verdict.founder_verdict_id.as_str())
    );
    assert_eq!(
        verdict.scope.as_ref().map(|scope| scope.task_id.as_str()),
        Some(task_id)
    );
    snapshot
}

fn u03c_discover_single_task_id(root: &Path) -> String {
    discover_single_task_id(
        root,
        &ExpectedStoreProfile {
            schema_profile_id: "egopulse/task-authority-store/v1",
            schema_profile_sha256: U03C_TASK_SCHEMA_SHA256,
        },
    )
    .expect("discover the sole U-03c Task through the strict read-only conformance oracle")
}

async fn wait_for_u03c_ready(instance: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let output = run_bounded_fixture_command(
            cli_executable(),
            instance,
            &["status", "--json"],
            "U-03c CLI readiness",
        )
        .await;
        if output.status.success() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect U-03c daemon") {
            panic!(
                "U-03c daemon exited before readiness: {status}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "U-03c daemon readiness timed out"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn u03c_selected_task(
    instance: &str,
) -> Result<
    (
        Arc<egopulse_client_operations::ClientAttachment>,
        TaskWatchController<egopulse_client_operations::ClientAttachment>,
        String,
    ),
    String,
> {
    timeout(Duration::from_secs(5), async {
        let attachment = Arc::new(
            attach_client_operation(
                instance,
                ClientSurface::Tui,
                format!("egopulse-tui-u03c-{}", Uuid::now_v7()),
            )
            .await
            .map_err(|error| format!("attach production U-03c TUI client: {error}"))?,
        );
        let mut controller = TaskWatchController::new(Arc::clone(&attachment));
        controller
            .start()
            .await
            .map_err(|error| format!("start U-03c Task Watch baseline: {error}"))?;
        loop {
            controller
                .pump()
                .map_err(|error| format!("pump U-03c Task Watch: {error}"))?;
            let task_id = controller
                .model()
                .filter(|model| model.phase == TaskWatchPhase::Live)
                .and_then(|model| model.selected_task_id.clone());
            if let Some(task_id) = task_id {
                assert!(controller.select_task(&task_id));
                break Ok((attachment, controller, task_id));
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "U-03c attach and Task Watch baseline timed out".to_owned())?
}

async fn u03c_selected_task_or_reap(
    instance: &str,
    child: &mut Child,
) -> (
    Arc<egopulse_client_operations::ClientAttachment>,
    TaskWatchController<egopulse_client_operations::ClientAttachment>,
    String,
) {
    match u03c_selected_task(instance).await {
        Ok(selected) => selected,
        Err(error) => {
            let _ = shutdown_fixture_child(child, "U-03c daemon after Task Watch failure").await;
            panic!("{error}");
        }
    }
}

async fn wait_for_u03c_projection(
    attachment: &egopulse_client_operations::ClientAttachment,
    task_id: &str,
    require_complete_review: bool,
) {
    timeout(Duration::from_secs(5), async {
        loop {
            let projection = attachment
                .read_projection_snapshot()
                .await
                .expect("read U-03c projection convergence");
            if projection.tasks.iter().any(|view| {
                view.task.as_ref().is_some_and(|task| {
                    task.task_id == task_id && task.status == TaskStatus::Rework as i32
                }) && view.founder_verdict_state.as_ref().is_some_and(|state| {
                    state.state == FounderVerdictStateKind::Consumed as i32 && state.revision == 2
                }) && (!require_complete_review
                    || (view.artifact_set.is_some()
                        && view.verification.is_some()
                        && view.founder_verdict.is_some()))
            }) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-03c governed projection converges");
}

async fn u03c_cli_review_json(instance: &str, task_id: &str) -> serde_json::Value {
    let output = run_bounded_fixture_command(
        cli_executable(),
        instance,
        &["task", "review", task_id, "--json"],
        "U-03c CLI task review",
    )
    .await;
    assert!(
        output.status.success(),
        "U-03c CLI review failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("U-03c CLI review JSON")
}

fn normalized_u03c_cli_review(mut value: serde_json::Value) -> serde_json::Value {
    value
        .as_object_mut()
        .expect("U-03c CLI review object")
        .remove("correlationId");
    value
}

async fn assert_u03c_tui_review_fails(
    attachment: Arc<egopulse_client_operations::ClientAttachment>,
    task_id: &str,
    expected_safe_error: &str,
) {
    let mut controller = ResultReviewController::new(attachment, task_id.to_owned());
    controller
        .start()
        .await
        .expect("start fail-closed U-03c TUI review");
    let failure = timeout(Duration::from_secs(5), async {
        loop {
            if let Err(error) = controller.pump().await {
                break error;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-03c TUI failure is bounded");
    assert_eq!(failure, expected_safe_error);
    assert!(controller.model().is_none());
    assert!(!controller.is_running());
    controller.stop().await;
}

async fn assert_u03c_shared_review_failure(
    attachment: &egopulse_client_operations::ClientAttachment,
    task_id: &str,
    scenario: &str,
) {
    let error = attachment
        .read_task_result_review(task_id)
        .await
        .expect_err("U-03c shared review operation must fail closed");
    match (scenario, error) {
        (
            "missing",
            ClientTaskResultReviewError::Api {
                stage: TaskResultReviewStage::Task,
                error,
            },
        ) => {
            assert_eq!(error.code, LocalApiErrorCode::NotFound as i32);
            assert!(!error.retryable);
        }
        (
            "permission",
            ClientTaskResultReviewError::Kernel {
                stage: TaskResultReviewStage::Evidence,
                source: KernelError::PermissionDenied(permission),
            },
        ) => assert_eq!(permission, "local.evidence.read"),
        (
            "stale",
            ClientTaskResultReviewError::Integrity {
                stage: TaskResultReviewStage::Task,
                detail: "projection is not ready and current",
            },
        ) => {}
        (scenario, error) => panic!("unexpected U-03c {scenario} shared failure: {error:?}"),
    }
}

fn assert_u03c_cli_review_failure(scenario: &str, output: &std::process::Output) {
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("U-03c fail-closed CLI JSON envelope");
    let (operation, category, code) = match scenario {
        "missing" => ("task.review.task", "domain_conflict", "LOCAL_API_ERROR"),
        "permission" => (
            "task.review.evidence",
            "authentication",
            "PERMISSION_DENIED",
        ),
        "stale" => ("task.review.task", "internal", "LOCAL_API_PROTOCOL_ERROR"),
        other => panic!("unknown U-03c failure scenario: {other}"),
    };
    assert_eq!(value["ok"], false);
    assert_eq!(value["operation"], operation);
    assert_eq!(value["error"]["category"], category);
    assert_eq!(value["error"]["code"], code);
    assert_eq!(value["error"]["retryable"], false);
    assert!(value.get("data").is_none() || value["data"].is_null());
}

fn u03c_expected_tui_failure(scenario: &str) -> String {
    match scenario {
        "missing" => format!(
            "task review API rejected code={} retryable=false",
            LocalApiErrorCode::NotFound as i32
        ),
        "permission" => "evidence review permission or session rejected".to_owned(),
        "stale" => "task review integrity failed".to_owned(),
        other => panic!("unknown U-03c failure scenario: {other}"),
    }
}

async fn u03c_tui_review_lines(
    attachment: Arc<egopulse_client_operations::ClientAttachment>,
    task_watch: &mut TaskWatchController<egopulse_client_operations::ClientAttachment>,
    task_id: &str,
) -> Vec<String> {
    assert_eq!(
        task_watch
            .model()
            .and_then(|model| model.selected_task_id.as_deref()),
        Some(task_id)
    );
    task_watch.stop().await;
    let mut controller = ResultReviewController::new(attachment, task_id.to_owned());
    controller
        .start()
        .await
        .expect("start production U-03c result review");
    timeout(Duration::from_secs(5), async {
        loop {
            controller.pump().await.expect("pump U-03c result review");
            if controller.model().is_some() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-03c result review becomes ready");
    let mut model = controller.model().expect("U-03c TUI review model").clone();
    assert_eq!(model.task_id, task_id);
    assert_eq!(model.task_status, "Rework");
    let mut lines = Vec::new();
    for _ in 0..egopulse_tui::result_review::ResultReviewSection::ALL.len() {
        lines.extend(model.lines().iter().cloned());
        model.next_section();
    }
    controller.stop().await;
    lines
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
async fn u03c_real_daemon_cli_and_tui_review_complete_governed_result_without_authority_writes() {
    let root = std::env::temp_dir().join(format!("egopulse-u03c-review-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-03c fixture root");
    let instance = format!("u03c-review-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, U03C_RESULT_REVIEW_MODE).await;
    assert_ne!(child.id(), Some(std::process::id()));
    wait_for_u03c_ready(&instance, &mut child).await;

    let (discovery_attachment, mut discovery_watch, task_id) =
        u03c_selected_task_or_reap(&instance, &mut child).await;
    wait_for_u03c_projection(&discovery_attachment, &task_id, true).await;
    discovery_watch.stop().await;
    drop(discovery_watch);
    drop(discovery_attachment);
    let baseline = u03c_durability_oracle(&root, &task_id);
    let mut wrong_profile = u03c_oracle_request(&root, &task_id);
    wrong_profile.task_profile.schema_profile_sha256 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    assert!(
        read_governed_result_durability(&wrong_profile).is_err(),
        "U-03c oracle must fail closed on an unexpected owner schema profile"
    );

    let cli = run_bounded_fixture_command(
        cli_executable(),
        &instance,
        &["task", "review", task_id.as_str(), "--json"],
        "U-03c CLI task review",
    )
    .await;
    assert!(
        cli.status.success(),
        "U-03c CLI review failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_text = String::from_utf8(cli.stdout).expect("U-03c CLI UTF-8");
    let cli_json: serde_json::Value =
        serde_json::from_str(&cli_text).expect("U-03c CLI review JSON");
    assert_eq!(cli_json["operation"], "task.review");
    assert_eq!(cli_json["data"]["taskId"], task_id);
    assert_eq!(cli_json["data"]["taskStatus"], "TASK_STATUS_REWORK");
    assert_eq!(
        cli_json["data"]["artifactSet"]["artifactSetId"],
        U03C_ARTIFACT_SET_ID
    );
    assert_eq!(
        cli_json["data"]["verification"]["verificationArtifactId"],
        U03C_VERIFICATION_ID
    );
    assert_eq!(
        cli_json["data"]["founderVerdict"]["decision"],
        "FOUNDER_VERDICT_DECISION_REWORK"
    );
    assert_eq!(
        cli_json["data"]["verification"]["criterionResults"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        cli_json["data"]["verification"]["discrepancies"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        cli_json["data"]["verification"]["unverifiedItems"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    for sentinel in [
        U03C_SENSITIVE_PRINCIPAL,
        U03C_SENSITIVE_PROOF,
        U03C_SENSITIVE_WORKSPACE,
        U03C_SENSITIVE_RAW,
        "native-u03c-never-render",
        "session-u03c-never-render",
    ] {
        assert!(!cli_text.contains(sentinel), "CLI leaked {sentinel}");
    }

    let (attachment, mut task_watch, selected_task_id) =
        u03c_selected_task_or_reap(&instance, &mut child).await;
    assert_eq!(selected_task_id, task_id);
    let tui_lines = u03c_tui_review_lines(Arc::clone(&attachment), &mut task_watch, &task_id).await;
    let tui_text = tui_lines.join("\n");
    for expected in [
        task_id.as_str(),
        U03C_ARTIFACT_SET_ID,
        U03C_VERIFICATION_ID,
        "Rework",
        "discrepancy-u03c",
        "unverified-u03c",
    ] {
        assert!(tui_text.contains(expected), "TUI omitted {expected}");
    }
    for sentinel in [
        U03C_SENSITIVE_PRINCIPAL,
        U03C_SENSITIVE_PROOF,
        U03C_SENSITIVE_WORKSPACE,
        U03C_SENSITIVE_RAW,
        "native-u03c-never-render",
        "session-u03c-never-render",
    ] {
        assert!(!tui_text.contains(sentinel), "TUI leaked {sentinel}");
    }
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);

    task_watch.stop().await;
    drop(task_watch);
    drop(attachment);
    let status = shutdown_fixture_child(&mut child, "U-03c result review daemon").await;
    assert!(status.success(), "U-03c daemon shutdown failed: {status}");
    fs::remove_dir_all(&root).expect("remove U-03c fixture root");
}

async fn start_r9b_governed_state_controller(
    instance: &str,
) -> (
    Arc<egopulse_client_operations::ClientAttachment>,
    GovernedStateController,
) {
    timeout(Duration::from_secs(5), async {
        let attachment = Arc::new(
            attach_client_operation(
                instance,
                ClientSurface::Tui,
                format!("egopulse-tui-r9b-{}", Uuid::now_v7()),
            )
            .await
            .expect("attach production R-9B TUI client"),
        );
        let controller = GovernedStateController::start(Arc::clone(&attachment))
            .expect("start production R-9B governed-state controller");
        (attachment, controller)
    })
    .await
    .expect("R-9B attachment and controller start timed out")
}

async fn wait_for_r9b_governed_state(
    controller: &mut GovernedStateController,
    child: &mut Child,
    label: &str,
    predicate: impl Fn(&GovernedStatePageModel) -> bool,
) -> GovernedStatePageModel {
    timeout(Duration::from_secs(8), async {
        loop {
            controller.pump();
            if predicate(controller.model()) {
                break controller.model().clone();
            }
            if let Some(status) = child
                .try_wait()
                .unwrap_or_else(|error| panic!("inspect {label} daemon: {error}"))
            {
                panic!("{label} daemon exited before governed state settled: {status}");
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} governed state did not settle before its deadline"))
}

async fn collect_r9b_governed_state_initial_trace(
    controller: &mut GovernedStateController,
    child: &mut Child,
    label: &str,
) -> Vec<GovernedStatePageModel> {
    timeout(Duration::from_secs(8), async {
        let mut trace = vec![controller.model().clone()];
        while trace.len() < 3 {
            controller.pump();
            let current = controller.model();
            let previous = trace.last().expect("R-9B TUI trace has initial model");
            if current.update_index != previous.update_index {
                assert_eq!(current.update_index, previous.update_index + 1);
                trace.push(current.clone());
                continue;
            }
            assert!(!current.stopped, "{label} TUI controller stopped early");
            if let Some(status) = child
                .try_wait()
                .unwrap_or_else(|error| panic!("inspect {label} daemon: {error}"))
            {
                panic!("{label} daemon exited before its two domain updates: {status}");
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            r9b_model_is_dual_live(trace.last().expect("R-9B TUI final trace model")),
            "{label} did not publish exactly one live update per domain"
        );
        trace
    })
    .await
    .unwrap_or_else(|_| panic!("{label} TUI trace did not settle before its deadline"))
}

fn r9b_model_is_dual_live(model: &GovernedStatePageModel) -> bool {
    model.task.view.phase == "live"
        && model.approval.view.phase == "live"
        && !model.task.facts.is_empty()
        && !model.approval.facts.is_empty()
}

fn assert_r9b_tui_local_trace(trace: &[GovernedStatePageModel]) {
    assert_eq!(trace.len(), 3);
    let initial = &trace[0];
    assert_eq!(initial.kind.label(), "initial");
    assert_eq!(initial.update_index, 0);
    assert_eq!(initial.changed_domain, None);
    assert_eq!(initial.task.view.phase, "connecting");
    assert_eq!(initial.approval.view.phase, "connecting");
    assert!(initial.task.view.epoch.is_none());
    assert!(initial.task.view.sequence.is_none());
    assert!(initial.approval.view.epoch.is_none());
    assert!(initial.approval.view.sequence.is_none());
    assert!(initial.task.facts.is_empty());
    assert!(initial.approval.facts.is_empty());

    let mut task_seen = false;
    let mut approval_seen = false;
    for (index, pair) in trace.windows(2).enumerate() {
        let previous = &pair[0];
        let current = &pair[1];
        assert_eq!(current.kind.label(), "update");
        assert_eq!(current.update_index, u64::try_from(index + 1).unwrap());
        match current
            .changed_domain
            .expect("R-9B TUI update declares one changed domain")
        {
            GovernedStateDomain::Task => {
                assert!(!task_seen, "R-9B TUI repeated Task initial update");
                task_seen = true;
                assert_ne!(current.task, previous.task);
                assert_eq!(current.approval, previous.approval);
            }
            GovernedStateDomain::Approval => {
                assert!(!approval_seen, "R-9B TUI repeated Approval initial update");
                approval_seen = true;
                assert_ne!(current.approval, previous.approval);
                assert_eq!(current.task, previous.task);
            }
        }
    }
    assert!(task_seen && approval_seen);
}

fn assert_r9b_json_keys(value: &serde_json::Value, expected: &[&str], label: &str) {
    let actual = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be a JSON object"))
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "unexpected keys in {label}");
}

fn assert_r9b_cli_record_shape(record: &serde_json::Value) {
    assert_r9b_json_keys(
        record,
        &[
            "approval",
            "changedDomain",
            "indexSemantics",
            "kind",
            "schemaVersion",
            "task",
            "updateIndex",
        ],
        "R-9B CLI record",
    );
    for (domain, facts_key) in [("task", "tasks"), ("approval", "approvals")] {
        assert_r9b_json_keys(
            &record[domain],
            &[
                "generation",
                "phase",
                "position",
                "reason",
                "recovery",
                facts_key,
            ],
            &format!("R-9B CLI {domain} domain"),
        );
        assert_r9b_json_keys(
            &record[domain]["recovery"],
            &["limit", "remaining"],
            &format!("R-9B CLI {domain} recovery"),
        );
        if !record[domain]["position"].is_null() {
            assert_r9b_json_keys(
                &record[domain]["position"],
                &["epoch", "sequence"],
                &format!("R-9B CLI {domain} position"),
            );
        }
    }
}

fn assert_r9b_cli_local_trace(records: &[serde_json::Value]) {
    assert_eq!(records.len(), 3);
    for record in records {
        assert_r9b_cli_record_shape(record);
    }
    assert_eq!(records[0]["kind"], "initial");
    assert_eq!(records[0]["updateIndex"], 0);
    assert!(records[0]["changedDomain"].is_null());

    let mut task_seen = false;
    let mut approval_seen = false;
    for index in 1..=2 {
        let previous = &records[index - 1];
        let current = &records[index];
        assert_eq!(current["kind"], "update");
        assert_eq!(current["updateIndex"].as_u64(), Some(index as u64));
        match current["changedDomain"]
            .as_str()
            .expect("R-9B CLI update declares one changed domain")
        {
            "task" => {
                assert!(!task_seen, "R-9B CLI repeated Task initial update");
                task_seen = true;
                assert_ne!(current["task"], previous["task"]);
                assert_eq!(current["approval"], previous["approval"]);
            }
            "approval" => {
                assert!(!approval_seen, "R-9B CLI repeated Approval initial update");
                approval_seen = true;
                assert_ne!(current["approval"], previous["approval"]);
                assert_eq!(current["task"], previous["task"]);
            }
            domain => panic!("unexpected R-9B CLI changed domain: {domain}"),
        }
    }
    assert!(task_seen && approval_seen);
}

fn assert_r9b_cli_domain_matches_tui(cli: &serde_json::Value, tui: &DomainView) {
    assert_eq!(cli["phase"].as_str(), Some(tui.phase.as_str()));
    assert_eq!(cli["reason"].as_str(), tui.reason.as_deref());
    assert_eq!(cli["generation"].as_u64(), Some(tui.generation));
    assert_eq!(
        cli["recovery"]["remaining"].as_u64(),
        Some(u64::from(tui.recovery_remaining))
    );
    assert_eq!(
        cli["recovery"]["limit"].as_u64(),
        Some(u64::from(tui.recovery_limit))
    );
    match (tui.epoch.as_deref(), tui.sequence) {
        (Some(epoch), Some(sequence)) => {
            assert_eq!(cli["position"]["epoch"].as_str(), Some(epoch));
            assert_eq!(cli["position"]["sequence"].as_u64(), Some(sequence));
        }
        (None, None) => assert!(cli["position"].is_null()),
        _ => panic!("TUI R-9B position must be either complete or absent"),
    }
}

fn assert_r9b_cli_domains_match_tui(record: &serde_json::Value, model: &GovernedStatePageModel) {
    assert_eq!(record["schemaVersion"], "egopulse.governed-state.v1");
    assert_eq!(record["indexSemantics"], "client-local");
    assert!(record.get("cursor").is_none());
    assert!(record.get("combinedCursor").is_none());
    assert!(record.get("globalCursor").is_none());

    assert_r9b_cli_domain_matches_tui(&record["task"], &model.task.view);
    assert_r9b_cli_domain_matches_tui(&record["approval"], &model.approval.view);

    let cli_tasks = record["task"]["tasks"]
        .as_array()
        .expect("R-9B CLI Task facts");
    assert_eq!(cli_tasks.len(), model.task.facts.len());
    for (cli, tui) in cli_tasks.iter().zip(&model.task.facts) {
        assert_eq!(cli["taskId"].as_str(), Some(tui.task_id.as_str()));
        assert_eq!(cli["revision"].as_u64(), Some(tui.revision));
        assert_eq!(cli["status"].as_str(), Some(tui.status.as_str()));
    }
    assert!(cli_tasks.windows(2).all(|pair| {
        pair[0]["taskId"]
            .as_str()
            .zip(pair[1]["taskId"].as_str())
            .is_some_and(|(left, right)| left < right)
    }));

    let cli_approvals = record["approval"]["approvals"]
        .as_array()
        .expect("R-9B CLI Approval facts");
    assert_eq!(cli_approvals.len(), model.approval.facts.len());
    for (cli, tui) in cli_approvals.iter().zip(&model.approval.facts) {
        assert_eq!(
            cli["approvalRequestId"].as_str(),
            Some(tui.approval_request_id.as_str())
        );
        assert_eq!(cli["taskId"].as_str(), Some(tui.task_id.as_str()));
    }
    assert!(cli_approvals.windows(2).all(|pair| {
        pair[0]["approvalRequestId"]
            .as_str()
            .zip(pair[1]["approvalRequestId"].as_str())
            .is_some_and(|(left, right)| left < right)
    }));
}

fn assert_r9b_cli_initial_matches_tui(record: &serde_json::Value, model: &GovernedStatePageModel) {
    assert_eq!(record["kind"].as_str(), Some(model.kind.label()));
    assert_eq!(record["updateIndex"].as_u64(), Some(model.update_index));
    assert!(record["changedDomain"].is_null());
    assert_r9b_cli_domains_match_tui(record, model);
}

fn assert_r9b_cli_live_domains_match_tui(
    record: &serde_json::Value,
    model: &GovernedStatePageModel,
) {
    assert_eq!(record["task"]["phase"], "live");
    assert_eq!(record["approval"]["phase"], "live");
    assert_eq!(model.task.view.phase, "live");
    assert_eq!(model.approval.view.phase, "live");
    assert_r9b_cli_domains_match_tui(record, model);
}

fn assert_r9b_safe_facts_equal(expected: &GovernedStatePageModel, actual: &GovernedStatePageModel) {
    assert_eq!(actual.task.view.phase, "live");
    assert_eq!(actual.approval.view.phase, "live");
    assert_eq!(actual.task.view.reason, expected.task.view.reason);
    assert_eq!(actual.approval.view.reason, expected.approval.view.reason);
    assert_eq!(actual.task.view.generation, expected.task.view.generation);
    assert_eq!(
        actual.approval.view.generation,
        expected.approval.view.generation
    );
    assert_eq!(actual.task.view.epoch, expected.task.view.epoch);
    assert_eq!(actual.task.view.sequence, expected.task.view.sequence);
    assert_eq!(actual.approval.view.epoch, expected.approval.view.epoch);
    assert_eq!(
        actual.approval.view.sequence,
        expected.approval.view.sequence
    );
    assert_eq!(actual.task.facts, expected.task.facts);
    assert_eq!(actual.approval.facts, expected.approval.facts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9b_real_windows_dual_state_cli_tui_and_same_root_restart_are_consistent() {
    let root = std::env::temp_dir().join(format!("egopulse-r9b-dual-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-9B dual-state fixture root");
    let instance = format!("r9b-dual-{}", Uuid::now_v7());

    let mut d1 = spawn_fixture_with_mode(&root, &instance, R9B_GOVERNED_STATE_MODE).await;
    let d1_pid = d1.id().expect("R-9B D1 PID");
    assert_ne!(d1_pid, std::process::id());
    wait_for_m12_daemon(&instance, &mut d1, "R-9B D1 readiness").await;
    let before = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot before D1 observations");
    let (d1_attachment, mut d1_controller) = start_r9b_governed_state_controller(&instance).await;
    let d1_trace =
        collect_r9b_governed_state_initial_trace(&mut d1_controller, &mut d1, "R-9B D1").await;
    assert_r9b_tui_local_trace(&d1_trace);
    let d1_initial_model = d1_trace[0].clone();
    let d1_model = d1_trace[2].clone();
    let cli = run_bounded_fixture_command_with_timeout(
        cli_executable(),
        &instance,
        &["state", "watch", "--updates", "2", "--json"],
        "R-9B governed-state CLI",
        Duration::from_secs(15),
    )
    .await;
    assert!(
        cli.status.success(),
        "R-9B governed-state CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_stdout = String::from_utf8(cli.stdout).expect("R-9B CLI stdout UTF-8");
    let records: Vec<serde_json::Value> = cli_stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("R-9B CLI NDJSON record"))
        .collect();
    assert_eq!(records.len(), 3, "R-9B CLI output: {cli_stdout}");
    assert_r9b_cli_local_trace(&records);
    assert_r9b_cli_initial_matches_tui(&records[0], &d1_initial_model);
    assert_r9b_cli_live_domains_match_tui(
        records.last().expect("R-9B final CLI record"),
        &d1_model,
    );

    assert_u04c_conpty_host_available(&instance).await;
    let mut conpty = U04cConptySession::spawn(&instance);
    assert_ne!(conpty.process_id(), std::process::id());
    assert_ne!(conpty.process_id(), d1_pid);
    conpty.wait_for_checkpoint("g governed state").await;
    conpty.send_keys(b"g");
    conpty
        .wait_for_checkpoint("Task and Approval positions are independent")
        .await;
    conpty
        .wait_for_checkpoint("this page is observation-only")
        .await;
    conpty.wait_for_checkpoint("Task domain: phase=live").await;
    conpty
        .wait_for_checkpoint("Approval domain: phase=live")
        .await;
    let governed_screen = conpty.screen_text();
    assert!(
        governed_screen.contains("no atomic snapshot or global cursor"),
        "R-9B Governed State screen:\n{governed_screen}"
    );
    assert!(
        governed_screen.contains("Task domain: phase=live"),
        "R-9B Governed State screen:\n{governed_screen}"
    );
    assert!(
        governed_screen.contains("Approval domain: phase=live"),
        "R-9B Governed State screen:\n{governed_screen}"
    );
    conpty.finish_successfully().await;

    timeout(Duration::from_secs(5), d1_controller.stop())
        .await
        .expect("stop R-9B D1 controller before deadline");
    let after_d1 = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot after D1 observations");
    assert_eq!(after_d1, before);
    drop(d1_controller);
    drop(d1_attachment);
    let d1_status = shutdown_fixture_child(&mut d1, "R-9B D1").await;
    assert!(d1_status.success(), "R-9B D1 shutdown failed: {d1_status}");
    let after_d1_reap = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot after D1 process reap");
    assert_eq!(after_d1_reap, before);

    let mut d2 = spawn_fixture_with_mode(&root, &instance, R9B_GOVERNED_STATE_MODE).await;
    let d2_pid = d2.id().expect("R-9B D2 PID");
    assert_ne!(d2_pid, std::process::id());
    assert_ne!(d2_pid, d1_pid);
    wait_for_m12_daemon(&instance, &mut d2, "R-9B D2 readiness").await;
    let before_d2 = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot before D2 observations");
    assert_eq!(before_d2, before);
    let (d2_attachment, mut d2_controller) = start_r9b_governed_state_controller(&instance).await;
    let d2_model = wait_for_r9b_governed_state(
        &mut d2_controller,
        &mut d2,
        "R-9B D2",
        r9b_model_is_dual_live,
    )
    .await;
    assert_r9b_safe_facts_equal(&d1_model, &d2_model);

    timeout(Duration::from_secs(5), d2_controller.stop())
        .await
        .expect("stop R-9B D2 controller before deadline");
    let after_d2 = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot after D2 observations");
    assert_eq!(after_d2, before);
    drop(d2_controller);
    drop(d2_attachment);
    let d2_status = shutdown_fixture_child(&mut d2, "R-9B D2").await;
    assert!(d2_status.success(), "R-9B D2 shutdown failed: {d2_status}");
    let after_d2_reap = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B authority snapshot after D2 process reap");
    assert_eq!(after_d2_reap, before);
    fs::remove_dir_all(&root).expect("remove R-9B dual-state fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9b_read_permission_rejection_is_isolated_to_one_domain() {
    for (case, mode, denied_domain) in [
        ("task", R9B_DENY_TASK_READ_MODE, GovernedStateDomain::Task),
        (
            "approval",
            R9B_DENY_APPROVAL_READ_MODE,
            GovernedStateDomain::Approval,
        ),
    ] {
        let root =
            std::env::temp_dir().join(format!("egopulse-r9b-deny-{case}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create R-9B permission fixture root");
        let instance = format!("r9b-deny-{case}-{}", Uuid::now_v7());
        let mut child = spawn_fixture_with_mode(&root, &instance, mode).await;
        assert_ne!(child.id(), Some(std::process::id()));
        wait_for_m12_daemon(&instance, &mut child, "R-9B permission readiness").await;
        let before = read_r9b_governed_state_authorities(&root)
            .unwrap_or_else(|error| panic!("read R-9B {case} authority snapshot before: {error}"));
        let (attachment, mut controller) = start_r9b_governed_state_controller(&instance).await;
        let model = wait_for_r9b_governed_state(
            &mut controller,
            &mut child,
            "R-9B permission isolation",
            |model| match denied_domain {
                GovernedStateDomain::Task => {
                    model.task.view.phase == "fatal"
                        && model.task.view.reason.as_deref() == Some("permission_denied")
                        && model.approval.view.phase == "live"
                        && !model.approval.facts.is_empty()
                }
                GovernedStateDomain::Approval => {
                    model.approval.view.phase == "fatal"
                        && model.approval.view.reason.as_deref() == Some("permission_denied")
                        && model.task.view.phase == "live"
                        && !model.task.facts.is_empty()
                }
            },
        )
        .await;
        match denied_domain {
            GovernedStateDomain::Task => {
                assert!(model.task.facts.is_empty());
                assert!(model.task.view.epoch.is_none());
                assert!(model.task.view.sequence.is_none());
                assert_eq!(model.approval.view.reason, None);
            }
            GovernedStateDomain::Approval => {
                assert!(model.approval.facts.is_empty());
                assert!(model.approval.view.epoch.is_none());
                assert!(model.approval.view.sequence.is_none());
                assert_eq!(model.task.view.reason, None);
            }
        }

        timeout(Duration::from_secs(5), controller.stop())
            .await
            .unwrap_or_else(|_| panic!("stop R-9B {case} permission controller before deadline"));
        let after = read_r9b_governed_state_authorities(&root)
            .unwrap_or_else(|error| panic!("read R-9B {case} authority snapshot after: {error}"));
        assert_eq!(after, before, "R-9B {case} observation mutated Authority");
        drop(controller);
        drop(attachment);
        let status = shutdown_fixture_child(&mut child, "R-9B permission daemon").await;
        assert!(
            status.success(),
            "R-9B {case} daemon shutdown failed: {status}"
        );
        let after_reap = read_r9b_governed_state_authorities(&root).unwrap_or_else(|error| {
            panic!("read R-9B {case} authority snapshot after process reap: {error}")
        });
        assert_eq!(
            after_reap, before,
            "R-9B {case} process shutdown mutated Authority"
        );
        fs::remove_dir_all(&root).expect("remove R-9B permission fixture root");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9b_task_stream_single_disconnect_keeps_approval_live_and_recovers_bounded() {
    let root =
        std::env::temp_dir().join(format!("egopulse-r9b-task-disconnect-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-9B C5-C fixture root");
    let instance = format!("r9b-task-disconnect-{}", Uuid::now_v7());
    let mut child =
        spawn_fixture_with_mode(&root, &instance, R9B_TASK_SINGLE_DISCONNECT_MODE).await;
    assert_ne!(child.id(), Some(std::process::id()));
    wait_for_m12_daemon(&instance, &mut child, "R-9B C5-C readiness").await;
    let authority_before = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-C Authority snapshot before attachment");

    let attachment = Arc::new(
        timeout(
            Duration::from_secs(5),
            attach_client_operation(
                &instance,
                ClientSurface::Tui,
                format!("egopulse-tui-r9b-c5c-{}", Uuid::now_v7()),
            ),
        )
        .await
        .expect("R-9B C5-C attachment deadline")
        .expect("attach R-9B C5-C production client"),
    );
    let controller_attachment = Arc::clone(&attachment);
    assert!(Arc::ptr_eq(&attachment, &controller_attachment));
    let mut controller = GovernedStateController::start(controller_attachment)
        .expect("start R-9B C5-C production controller");
    assert!(
        Arc::strong_count(&attachment) > 1,
        "R-9B C5-C controller must retain the same attachment"
    );
    let baseline = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-C pre-fault",
        r9b_model_is_dual_live,
    )
    .await;
    assert_eq!(baseline.task.view.reason, None);
    assert_eq!(baseline.approval.view.reason, None);
    assert!(!baseline.task.facts.is_empty());
    assert!(!baseline.approval.facts.is_empty());
    let baseline_task_generation = baseline.task.view.generation;
    let baseline_approval = baseline.approval.clone();
    let calls_path = root.join(R9B_TASK_READER_CALLS_FILE);
    let append_parent_stage = |stage: &str| {
        let mut witness = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&calls_path)
            .expect("open R-9B C5-C ordered witness");
        writeln!(witness, "parent {stage}")
            .and_then(|()| witness.sync_all())
            .expect("persist R-9B C5-C ordered witness");
    };
    let approval_advance_path = root.join(R9B_APPROVAL_ADVANCE_FILE);
    let release_path = root.join(R9B_TASK_REBASELINE_RELEASE_FILE);
    assert!(!approval_advance_path.exists());
    assert!(!release_path.exists());

    let arm_path = root.join(R9B_TASK_DISCONNECT_ARM_FILE);
    let mut arm = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&arm_path)
        .expect("create R-9B C5-C atomic arm command");
    arm.write_all(b"arm-task-disconnect\n")
        .and_then(|()| arm.sync_all())
        .expect("persist R-9B C5-C arm command");
    drop(arm);

    let degraded = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-C isolated Task failure",
        |model| {
            model.task.view.phase == "stale"
                && model.approval.view.phase == "live"
                && fs::read_to_string(&calls_path).is_ok_and(|calls| {
                    let lines = calls.lines().collect::<Vec<_>>();
                    lines
                        .iter()
                        .any(|line| line.ends_with("task_frames_after unavailable"))
                        && lines
                            .iter()
                            .any(|line| line.ends_with("task_baseline held"))
                })
        },
    )
    .await;
    assert_eq!(
        degraded.task.view.reason.as_deref(),
        Some("transport_unavailable")
    );
    assert_eq!(degraded.task.view.generation, baseline_task_generation + 1);
    assert_eq!(degraded.task.view.epoch, baseline.task.view.epoch);
    assert_eq!(degraded.task.view.sequence, baseline.task.view.sequence);
    assert_eq!(degraded.task.facts, baseline.task.facts);
    assert_eq!(
        degraded.task.view.recovery_remaining,
        baseline
            .task
            .view
            .recovery_remaining
            .checked_sub(1)
            .expect("R-9B C5-C Task recovery budget")
    );
    assert_eq!(
        degraded.task.view.recovery_limit,
        baseline.task.view.recovery_limit
    );
    assert_eq!(degraded.approval, baseline_approval);
    assert!(!approval_advance_path.exists());
    assert!(!release_path.exists());

    let mut approval_advance = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&approval_advance_path)
        .expect("create R-9B C5-C Approval advance command");
    approval_advance
        .write_all(b"advance-approval-through-projection-pump\n")
        .and_then(|()| approval_advance.sync_all())
        .expect("persist R-9B C5-C Approval advance command");
    drop(approval_advance);

    let advanced = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-C Approval advancement during Task hold",
        |model| {
            model.task == degraded.task
                && model.approval.view.phase == "live"
                && model
                    .approval
                    .facts
                    .iter()
                    .any(|approval| approval.approval_request_id == R9B_ADVANCED_APPROVAL_ID)
        },
    )
    .await;
    assert_eq!(advanced.task, degraded.task);
    assert_eq!(
        advanced.approval.view.generation,
        baseline_approval.view.generation
    );
    assert_eq!(
        advanced.approval.view.recovery_remaining,
        baseline_approval.view.recovery_remaining
    );
    assert_eq!(
        advanced.approval.view.recovery_limit,
        baseline_approval.view.recovery_limit
    );
    assert_eq!(advanced.approval.view.epoch, baseline_approval.view.epoch);
    assert!(
        advanced.approval.view.sequence > baseline_approval.view.sequence,
        "R-9B C5-C Approval position must advance within its own domain"
    );
    assert_eq!(
        advanced.approval.facts.len(),
        baseline_approval.facts.len() + 1
    );
    assert!(!release_path.exists());
    append_parent_stage("approval-advance-observed");

    let mut release = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&release_path)
        .expect("create R-9B C5-C Task rebaseline release command");
    release
        .write_all(b"release-task-rebaseline\n")
        .and_then(|()| release.sync_all())
        .expect("persist R-9B C5-C Task rebaseline release command");
    drop(release);
    append_parent_stage("release-command-created");

    let recovered = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-C Task recovery",
        |model| {
            model.task.view.phase == "live"
                && model.task.view.generation == degraded.task.view.generation
                && model.task.view.epoch == baseline.task.view.epoch
                && model.task.view.sequence > baseline.task.view.sequence
                && model.approval.facts == advanced.approval.facts
        },
    )
    .await;
    assert_eq!(recovered.task.view.phase, "live");
    assert_eq!(recovered.task.view.reason, None);
    assert_eq!(recovered.task.view.epoch, baseline.task.view.epoch);
    assert!(
        recovered.task.view.sequence > baseline.task.view.sequence,
        "R-9B C5-C Task rebaseline then live catch-up must advance within the Task domain"
    );
    assert_eq!(
        recovered.task.view.generation,
        degraded.task.view.generation
    );
    assert_eq!(recovered.task.facts, baseline.task.facts);
    assert_eq!(
        recovered.task.view.recovery_remaining,
        degraded.task.view.recovery_remaining
    );
    assert_eq!(
        recovered.task.view.recovery_limit,
        degraded.task.view.recovery_limit
    );
    assert_eq!(
        recovered.task.view.recovery_limit,
        baseline.task.view.recovery_limit
    );
    assert_eq!(recovered.approval, advanced.approval);

    timeout(Duration::from_secs(5), controller.stop())
        .await
        .expect("stop R-9B C5-C controller before deadline");
    drop(controller);
    drop(attachment);
    let status = shutdown_fixture_child(&mut child, "R-9B C5-C daemon").await;
    assert!(status.success(), "R-9B C5-C daemon failed: {status}");

    let calls = fs::read_to_string(root.join(R9B_TASK_READER_CALLS_FILE))
        .expect("read R-9B C5-C Task reader call witness");
    let call_lines = calls.lines().collect::<Vec<_>>();
    assert_eq!(
        call_lines
            .iter()
            .filter(|line| line.ends_with("task_frames_after unavailable"))
            .count(),
        1,
        "R-9B C5-C must inject exactly one Task stream failure: {calls}"
    );
    assert_eq!(
        call_lines
            .iter()
            .filter(|line| line.ends_with("task_baseline held"))
            .count(),
        1,
        "R-9B C5-C must hold exactly one Task rebaseline: {calls}"
    );
    let witness_index = |suffix: &str| {
        call_lines
            .iter()
            .position(|line| line.ends_with(suffix))
            .unwrap_or_else(|| panic!("R-9B C5-C witness omitted {suffix}: {calls}"))
    };
    let unavailable_index = witness_index("task_frames_after unavailable");
    let held_index = witness_index("task_baseline held");
    let approval_observed_index = witness_index("parent approval-advance-observed");
    let release_index = witness_index("parent release-command-created");
    assert!(
        unavailable_index < held_index
            && held_index < approval_observed_index
            && approval_observed_index < release_index,
        "R-9B C5-C witness order must be unavailable < held < approval observed < release: {calls}"
    );
    let task_operation_count = call_lines
        .iter()
        .filter(|line| {
            line.split_once(' ')
                .and_then(|(sequence, _)| sequence.parse::<u64>().ok())
                .is_some()
        })
        .count();
    assert!(
        task_operation_count <= 12,
        "R-9B C5-C Task operations must remain finite: {calls}"
    );
    assert!(
        call_lines
            .iter()
            .filter(|line| line.contains("task_frames_after delegated"))
            .count()
            >= 2,
        "R-9B C5-C must delegate before and after its one failure: {calls}"
    );
    let authority_after = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-C Authority snapshot after process reap");
    assert_eq!(authority_after, authority_before);
    fs::remove_dir_all(&root).expect("remove R-9B C5-C fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9b_retention_gap_resets_only_task_and_rebaselines_bounded() {
    let root = std::env::temp_dir().join(format!("egopulse-r9b-retention-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-9B C5-D fixture root");
    let instance = format!("r9b-retention-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, R9B_RETENTION_RESET_MODE).await;
    assert_ne!(child.id(), Some(std::process::id()));
    wait_for_m12_daemon(&instance, &mut child, "R-9B C5-D readiness").await;
    let authority_o0 = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority O0 before attachment");

    let attachment = Arc::new(
        timeout(
            Duration::from_secs(5),
            attach_client_operation(
                &instance,
                ClientSurface::Tui,
                format!("egopulse-tui-r9b-c5d-{}", Uuid::now_v7()),
            ),
        )
        .await
        .expect("R-9B C5-D attachment deadline")
        .expect("attach R-9B C5-D production client"),
    );
    let controller_attachment = Arc::clone(&attachment);
    assert!(Arc::ptr_eq(&attachment, &controller_attachment));
    let mut controller = GovernedStateController::start(controller_attachment)
        .expect("start R-9B C5-D production controller");
    let baseline = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D dual-Live baseline",
        r9b_model_is_dual_live,
    )
    .await;
    assert_eq!(baseline.task.view.reason, None);
    assert_eq!(baseline.approval.view.reason, None);
    assert!(!baseline.task.facts.is_empty());
    assert!(!baseline.approval.facts.is_empty());
    let task_t0_epoch = baseline
        .task
        .view
        .epoch
        .clone()
        .expect("R-9B C5-D Task T0 epoch");
    let task_t0_sequence = baseline
        .task
        .view
        .sequence
        .expect("R-9B C5-D Task T0 sequence");
    let baseline_task_generation = baseline.task.view.generation;
    let witness_path = root.join(R9B_RETENTION_WITNESS_FILE);
    let create_control = |path: &Path, content: &str, label: &str| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap_or_else(|error| panic!("create {label}: {error}"));
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .unwrap_or_else(|error| panic!("persist {label}: {error}"));
    };
    let append_parent_witness = |event: &str| {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&witness_path)
            .expect("open R-9B C5-D parent witness");
        writeln!(file, "parent {event}")
            .and_then(|()| file.sync_all())
            .expect("persist R-9B C5-D parent witness");
    };

    let task_hold_arm_path = root.join(R9B_RETENTION_TASK_HOLD_ARM_FILE);
    create_control(
        &task_hold_arm_path,
        "hold-task-live-read\n",
        "R-9B C5-D Task hold arm",
    );
    let held = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D Task live-read hold",
        |model| {
            model.task == baseline.task
                && model.approval == baseline.approval
                && fs::read_to_string(&witness_path)
                    .is_ok_and(|witness| witness.contains("task-live-read-held"))
        },
    )
    .await;
    assert_eq!(held.task, baseline.task);
    assert_eq!(held.approval, baseline.approval);
    let held_witness = fs::read_to_string(&witness_path).expect("read R-9B C5-D held Task witness");
    let expected_held_task =
        format!("task-live-read-held epoch={task_t0_epoch} sequence={task_t0_sequence}");
    assert_eq!(
        held_witness
            .lines()
            .filter(|line| line.ends_with(&expected_held_task))
            .count(),
        1,
        "R-9B C5-D held Task witness must bind exactly to T0: {held_witness}"
    );

    let approval_advance_path = root.join(R9B_APPROVAL_ADVANCE_FILE);
    create_control(
        &approval_advance_path,
        "advance-approval-through-production-projection-pump\n",
        "R-9B C5-D Approval advance",
    );
    let approval_a1 = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D Approval A1",
        |model| {
            model.task == baseline.task
                && model.approval.view.phase == "live"
                && model
                    .approval
                    .facts
                    .iter()
                    .any(|approval| approval.approval_request_id == R9B_ADVANCED_APPROVAL_ID)
        },
    )
    .await;
    assert_eq!(approval_a1.task, baseline.task);
    assert_eq!(
        approval_a1.approval.view.generation,
        baseline.approval.view.generation
    );
    assert_eq!(
        approval_a1.approval.view.recovery_limit,
        baseline.approval.view.recovery_limit
    );
    assert_eq!(
        approval_a1.approval.view.recovery_remaining,
        baseline.approval.view.recovery_remaining
    );
    let approval_a1_sequence = approval_a1
        .approval
        .view
        .sequence
        .expect("R-9B C5-D Approval A1 sequence");
    assert!(
        approval_a1_sequence
            > baseline
                .approval
                .view
                .sequence
                .expect("R-9B C5-D Approval A0 sequence"),
        "R-9B C5-D Approval must advance within its own domain"
    );

    let approval_observed_path = root.join(R9B_RETENTION_APPROVAL_OBSERVED_FILE);
    create_control(
        &approval_observed_path,
        "approval-a1-observed\n",
        "R-9B C5-D Approval observation",
    );
    append_parent_witness("approval-a1-observed");
    let compact_request_path = root.join(R9B_RETENTION_COMPACT_REQUEST_FILE);
    append_parent_witness("compact-request-created");
    create_control(
        &compact_request_path,
        "compact-at-current\n",
        "R-9B C5-D compact request",
    );
    let compacted_path = root.join(R9B_RETENTION_COMPACTED_FILE);
    let compacted_model = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D retention compaction",
        |model| {
            compacted_path.is_file()
                && model.task == baseline.task
                && model.approval == approval_a1.approval
        },
    )
    .await;
    assert_eq!(compacted_model.task, baseline.task);
    assert_eq!(compacted_model.approval, approval_a1.approval);
    let compacted =
        fs::read_to_string(&compacted_path).expect("read R-9B C5-D persisted compaction fact");
    let compact_fields = compacted
        .split_whitespace()
        .map(|field| {
            field
                .split_once('=')
                .unwrap_or_else(|| panic!("invalid R-9B C5-D compact field: {field}"))
        })
        .collect::<BTreeMap<_, _>>();
    let retention_floor_epoch = *compact_fields
        .get("floor_epoch")
        .expect("R-9B C5-D neutral retention floor epoch");
    let retention_floor_sequence = compact_fields
        .get("floor_sequence")
        .expect("R-9B C5-D neutral retention floor sequence")
        .parse::<u64>()
        .expect("parse R-9B C5-D neutral retention floor sequence");
    assert_eq!(
        compact_fields.get("current_epoch"),
        Some(&retention_floor_epoch),
        "R-9B C5-D current epoch must still equal the child-fixed neutral floor"
    );
    assert_eq!(
        compact_fields
            .get("current_sequence")
            .expect("R-9B C5-D compact current sequence")
            .parse::<u64>()
            .expect("parse R-9B C5-D compact current sequence"),
        retention_floor_sequence
    );
    assert_eq!(
        compact_fields.get("old_floor_epoch"),
        Some(&retention_floor_epoch),
        "R-9B C5-D old floor epoch must equal the neutral floor epoch"
    );
    assert_eq!(
        compact_fields.get("returned_floor_epoch"),
        Some(&retention_floor_epoch),
        "R-9B C5-D returned floor epoch must equal the neutral floor epoch"
    );
    assert_eq!(
        compact_fields
            .get("returned_floor_sequence")
            .expect("R-9B C5-D returned floor sequence")
            .parse::<u64>()
            .expect("parse R-9B C5-D returned floor sequence"),
        retention_floor_sequence
    );
    assert!(
        compact_fields
            .get("old_floor_sequence")
            .expect("R-9B C5-D old floor sequence")
            .parse::<u64>()
            .expect("parse R-9B C5-D old floor sequence")
            < retention_floor_sequence
    );
    assert_eq!(task_t0_epoch, retention_floor_epoch);
    assert!(
        task_t0_sequence < retention_floor_sequence,
        "R-9B C5-D Task T0 must precede the independently fixed neutral floor"
    );
    let authority_after_compaction = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority snapshot immediately after compaction");
    assert_eq!(authority_after_compaction, authority_o0);

    append_parent_witness("task-live-read-release-created");
    let task_live_release_path = root.join(R9B_RETENTION_TASK_LIVE_RELEASE_FILE);
    create_control(
        &task_live_release_path,
        "release-old-task-live-read\n",
        "R-9B C5-D Task live-read release",
    );
    let reset = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D Task retention reset",
        |model| {
            model.task.view.phase == "reset_required"
                && model.task.view.reason.as_deref() == Some("projection_reset_required")
                && model.approval == approval_a1.approval
                && fs::read_to_string(&witness_path).is_ok_and(|witness| {
                    witness.contains("task-raw-reset count=1")
                        && witness.contains("task-rebaseline-held")
                })
        },
    )
    .await;
    assert_eq!(reset.task.view.phase, "reset_required");
    assert_eq!(
        reset.task.view.reason.as_deref(),
        Some("projection_reset_required")
    );
    assert_eq!(reset.task.view.generation, baseline_task_generation + 1);
    assert_eq!(
        reset.task.view.epoch.as_deref(),
        Some(task_t0_epoch.as_str())
    );
    assert_eq!(reset.task.view.sequence, Some(task_t0_sequence));
    assert_eq!(reset.task.facts, baseline.task.facts);
    assert_eq!(
        reset.task.view.recovery_remaining, baseline.task.view.recovery_remaining,
        "R-9B C5-D retention reset must not consume transport recovery budget"
    );
    assert_eq!(
        reset.task.view.recovery_limit,
        baseline.task.view.recovery_limit
    );
    assert_eq!(reset.approval, approval_a1.approval);
    let authority_at_reset = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority snapshot at ResetRequired");
    assert_eq!(authority_at_reset, authority_o0);

    append_parent_witness("task-rebaseline-release-created");
    let rebaseline_release_path = root.join(R9B_RETENTION_REBASELINE_RELEASE_FILE);
    create_control(
        &rebaseline_release_path,
        "release-task-rebaseline\n",
        "R-9B C5-D Task rebaseline release",
    );
    let recovered = wait_for_r9b_governed_state(
        &mut controller,
        &mut child,
        "R-9B C5-D Task retention recovery",
        |model| {
            model.task.view.phase == "live"
                && model.task.view.reason.is_none()
                && model.task.view.generation == reset.task.view.generation
                && model.task.view.epoch.as_deref() == Some(task_t0_epoch.as_str())
                && model.task.view.sequence.is_some_and(|sequence| {
                    sequence > task_t0_sequence && sequence >= retention_floor_sequence
                })
                && model.approval == approval_a1.approval
        },
    )
    .await;
    assert_eq!(recovered.task.view.phase, "live");
    assert_eq!(recovered.task.view.reason, None);
    assert_eq!(recovered.task.view.generation, reset.task.view.generation);
    assert_eq!(
        recovered.task.view.epoch.as_deref(),
        Some(task_t0_epoch.as_str())
    );
    assert!(recovered.task.view.sequence.is_some_and(|sequence| {
        sequence > task_t0_sequence && sequence >= retention_floor_sequence
    }));
    assert_eq!(recovered.task.facts, baseline.task.facts);
    assert_eq!(
        recovered.task.view.recovery_remaining,
        baseline.task.view.recovery_remaining
    );
    assert_eq!(
        recovered.task.view.recovery_limit,
        baseline.task.view.recovery_limit
    );
    assert_eq!(recovered.approval, approval_a1.approval);

    let authority_at_recovery = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority snapshot at recovered Live");
    assert_eq!(authority_at_recovery, authority_o0);
    timeout(Duration::from_secs(5), controller.stop())
        .await
        .expect("stop R-9B C5-D controller before deadline");
    drop(controller);
    drop(attachment);
    let authority_after_stop = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority snapshot after controller stop");
    assert_eq!(authority_after_stop, authority_o0);
    let status = shutdown_fixture_child(&mut child, "R-9B C5-D daemon").await;
    assert!(status.success(), "R-9B C5-D daemon failed: {status}");
    let authority_after_reap = read_r9b_governed_state_authorities(&root)
        .expect("read R-9B C5-D Authority snapshot after process reap");
    assert_eq!(authority_after_reap, authority_o0);

    let witness = fs::read_to_string(&witness_path).expect("read R-9B C5-D witness");
    let witness_lines = witness.lines().collect::<Vec<_>>();
    let count = |needle: &str| {
        witness_lines
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    };
    assert_eq!(count("retention-compacted"), 1, "{witness}");
    assert_eq!(count("task-raw-reset count=1"), 1, "{witness}");
    assert_eq!(count("approval-raw-reset"), 0, "{witness}");
    assert_eq!(count("task-live-read-held"), 1, "{witness}");
    assert_eq!(count("task-rebaseline-held"), 1, "{witness}");
    assert_eq!(count("task-rebaseline-released"), 1, "{witness}");
    let witness_index = |needle: &str| {
        witness_lines
            .iter()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("R-9B C5-D witness omitted {needle}: {witness}"))
    };
    let held_index = witness_index("task-live-read-held");
    let approval_observed_index = witness_index("parent approval-a1-observed");
    let compact_index = witness_index("retention-compacted");
    let live_release_index = witness_index("parent task-live-read-release-created");
    let reset_index = witness_index("task-raw-reset count=1");
    let rebaseline_held_index = witness_index("task-rebaseline-held");
    let rebaseline_release_index = witness_index("parent task-rebaseline-release-created");
    let rebaseline_released_index = witness_index("task-rebaseline-released");
    assert!(
        held_index < approval_observed_index
            && approval_observed_index < compact_index
            && compact_index < live_release_index
            && live_release_index < reset_index
            && reset_index < rebaseline_held_index
            && rebaseline_held_index < rebaseline_release_index
            && rebaseline_release_index < rebaseline_released_index,
        "R-9B C5-D witness order must be hold < Approval observed < compact < old-read release < reset < rebaseline hold < rebaseline release: {witness}"
    );
    fs::remove_dir_all(&root).expect("remove R-9B C5-D fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u05d_real_daemon_tui_baseline_is_read_only() {
    let root = std::env::temp_dir().join(format!("egopulse-u05d-tui-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-05d fixture root");
    let instance = format!("u05d-tui-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, U03C_RESULT_REVIEW_MODE).await;
    assert_ne!(child.id(), Some(std::process::id()));
    wait_for_u03c_ready(&instance, &mut child).await;

    let task_id = u03c_discover_single_task_id(&root);
    let quiescence_deadline = Instant::now() + Duration::from_secs(8);
    loop {
        assert!(
            child
                .try_wait()
                .expect("inspect U-05d daemon while awaiting worker quiescence")
                .is_none(),
            "U-05d daemon exited before its durable workers became quiescent"
        );
        let durable = read_governed_result_durability(&u03c_oracle_request(&root, &task_id))
            .expect("read U-05d durable worker delivery state");
        let pending = [
            durable.task.pending_local_read_model_outbox_count,
            durable.task.pending_founder_verdict_cross_outbox_count,
            durable.collaboration.pending_local_read_model_outbox_count,
            durable.artifact.pending_local_read_model_outbox_count,
            durable.verification.pending_local_read_model_outbox_count,
            durable.verdict.pending_projection_outbox_count,
        ];
        if durable.verdict.consumption_receipt_count == 1 && pending.iter().all(|count| *count == 0)
        {
            break;
        }
        assert!(
            Instant::now() < quiescence_deadline,
            "U-05d durable workers did not quiesce: consumption_receipts={} pending={pending:?}",
            durable.verdict.consumption_receipt_count
        );
        sleep(Duration::from_millis(10)).await;
    }
    let before = u03c_durability_oracle(&root, &task_id);

    let (attachment, mut controller, selected_task_id) =
        u03c_selected_task_or_reap(&instance, &mut child).await;
    assert_eq!(selected_task_id, task_id);
    wait_for_u03c_projection(&attachment, &task_id, true).await;
    timeout(Duration::from_secs(5), async {
        loop {
            controller
                .pump()
                .expect("pump the production U-05d Task Watch controller");
            let settled = controller.model().is_some_and(|model| {
                model.phase == TaskWatchPhase::Live
                    && model.tasks.iter().any(|task| {
                        task.task_id == task_id
                            && task.status == TaskStatus::Rework
                            && task.run.as_ref().is_some_and(|run| {
                                run.run_id == U03C_RUN_ID
                                    && run.status == RunStatus::Returned
                                    && run.steps.iter().any(|step| {
                                        step.step_id == U03C_STEP_ID
                                            && step.status == StepStatus::Returned
                                            && step.attempts.iter().any(|attempt| {
                                                attempt.attempt_id == U03C_ATTEMPT_ID
                                                    && attempt.status == AttemptStatus::Returned
                                            })
                                    })
                            })
                    })
            });
            if settled {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-05d governed Task tree becomes live");

    let model = controller
        .model()
        .expect("production U-05d Task Watch model");
    assert_eq!(model.phase, TaskWatchPhase::Live);
    let task = model
        .tasks
        .iter()
        .find(|task| task.task_id == task_id)
        .expect("U-05d governed Task");
    assert_eq!(task.status, TaskStatus::Rework);
    assert_ne!(task.status, TaskStatus::Completed);
    let run = task.run.as_ref().expect("U-05d governed Run");
    assert_eq!(run.run_id, U03C_RUN_ID);
    assert_eq!(run.status, RunStatus::Returned);
    let step = run
        .steps
        .iter()
        .find(|step| step.step_id == U03C_STEP_ID)
        .expect("U-05d governed Step");
    assert_eq!(step.status, StepStatus::Returned);
    let attempt = step
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == U03C_ATTEMPT_ID)
        .expect("U-05d governed Attempt");
    assert_eq!(attempt.status, AttemptStatus::Returned);
    let d1_task = task.clone();

    let cli = run_bounded_fixture_command_with_timeout(
        cli_executable(),
        &instance,
        &["task", "watch", "--frames", "1", "--json"],
        "U-05d CLI Task Watch",
        Duration::from_secs(30),
    )
    .await;
    assert!(
        cli.status.success(),
        "U-05d CLI Task Watch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_stdout = String::from_utf8(cli.stdout).expect("U-05d CLI Task Watch UTF-8");
    let envelopes: Vec<serde_json::Value> = cli_stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("U-05d CLI Task Watch NDJSON envelope"))
        .collect();
    assert_eq!(
        envelopes.len(),
        2,
        "U-05d CLI must emit exactly one baseline and one live update: {cli_stdout}"
    );
    assert_eq!(envelopes[0]["operation"], "task.watch");
    assert_eq!(envelopes[0]["streamSchema"], "egopulse.cli.task-watch/v1");
    assert_eq!(envelopes[0]["data"]["kind"], "baseline");
    let cli_task = envelopes[0]["data"]["tasks"]
        .as_array()
        .expect("U-05d CLI baseline tasks")
        .iter()
        .find(|task| task["taskId"].as_str() == Some(task_id.as_str()))
        .expect("U-05d CLI baseline contains the governed Task");
    assert_eq!(cli_task["status"], "TASK_STATUS_REWORK");
    assert_eq!(cli_task["run"]["runId"], U03C_RUN_ID);
    assert_eq!(cli_task["run"]["status"], "RUN_STATUS_RETURNED");
    let cli_step = cli_task["run"]["steps"]
        .as_array()
        .expect("U-05d CLI governed Steps")
        .iter()
        .find(|step| step["stepId"] == U03C_STEP_ID)
        .expect("U-05d CLI governed Step");
    assert_eq!(cli_step["status"], "STEP_STATUS_RETURNED");
    let cli_attempt = cli_step["attempts"]
        .as_array()
        .expect("U-05d CLI governed Attempts")
        .iter()
        .find(|attempt| attempt["attemptId"] == U03C_ATTEMPT_ID)
        .expect("U-05d CLI governed Attempt");
    assert_eq!(cli_attempt["status"], "ATTEMPT_STATUS_RETURNED");
    assert_eq!(envelopes[1]["operation"], "task.watch");
    assert_eq!(envelopes[1]["streamSchema"], "egopulse.cli.task-watch/v1");
    assert_eq!(envelopes[1]["data"]["kind"], "update");
    assert_eq!(envelopes[1]["data"]["classification"], "heartbeat");
    assert!(envelopes[1]["data"]["task"].is_null());
    for sentinel in [
        U03C_SENSITIVE_PRINCIPAL,
        U03C_SENSITIVE_PROOF,
        U03C_SENSITIVE_WORKSPACE,
        U03C_SENSITIVE_RAW,
        "native-u03c-never-render",
        "session-u03c-never-render",
    ] {
        assert!(!cli_stdout.contains(sentinel), "CLI leaked {sentinel}");
    }
    assert_eq!(u03c_durability_oracle(&root, &task_id), before);

    let d1_pid = child.id().expect("U-05d D1 PID");
    let status = shutdown_fixture_child(&mut child, "U-05d D1 daemon").await;
    assert!(status.success(), "U-05d D1 shutdown failed: {status}");
    timeout(Duration::from_secs(8), async {
        loop {
            controller
                .pump()
                .expect("pump U-05d Task Watch after D1 shutdown");
            if controller
                .model()
                .is_some_and(|model| model.phase == TaskWatchPhase::FatalStopped)
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-05d Task Watch exhausts its bounded reconnect budget");
    let stopped_model = controller.model().expect("U-05d stopped Task Watch model");
    assert_eq!(
        stopped_model.message,
        "Task Watch stopped after bounded reconnect attempts"
    );
    assert_eq!(
        stopped_model
            .tasks
            .iter()
            .find(|task| task.task_id == task_id),
        Some(&d1_task),
        "D1 disconnect must not rewrite the last safe Task facts"
    );
    for sentinel in [
        root.to_string_lossy().as_ref(),
        U03C_SENSITIVE_PRINCIPAL,
        U03C_SENSITIVE_PROOF,
        U03C_SENSITIVE_WORKSPACE,
        U03C_SENSITIVE_RAW,
        "native-u03c-never-render",
        "session-u03c-never-render",
    ] {
        assert!(
            !stopped_model.message.contains(sentinel),
            "Task Watch stop message leaked {sentinel}"
        );
    }
    timeout(Duration::from_secs(5), controller.stop())
        .await
        .expect("stop U-05d Task Watch controller within the bound");
    assert!(!controller.is_running());
    drop(controller);
    drop(attachment);
    assert_eq!(u03c_durability_oracle(&root, &task_id), before);

    let mut second = spawn_fixture_with_mode(&root, &instance, U03C_RESULT_REVIEW_MODE).await;
    let d2_pid = second.id().expect("U-05d D2 PID");
    assert_ne!(d2_pid, std::process::id());
    assert_ne!(d2_pid, d1_pid, "U-05d restart must use a new process");
    wait_for_u03c_ready(&instance, &mut second).await;
    assert_eq!(u03c_discover_single_task_id(&root), task_id);
    assert_eq!(
        u03c_durability_oracle(&root, &task_id),
        before,
        "D2 production replay must leave the full Authority baseline unchanged before any client read"
    );
    let (second_attachment, mut second_controller, second_task_id) =
        u03c_selected_task_or_reap(&instance, &mut second).await;
    assert_eq!(second_task_id, task_id);
    assert_eq!(
        second_controller
            .model()
            .expect("U-05d D2 Task Watch model")
            .phase,
        TaskWatchPhase::Live
    );
    let d2_task = second_controller
        .model()
        .expect("U-05d D2 Task Watch model")
        .tasks
        .iter()
        .find(|task| task.task_id == task_id)
        .expect("U-05d D2 governed Task");
    assert_eq!(d2_task.task_id, d1_task.task_id);
    assert_eq!(d2_task.revision, d1_task.revision);
    assert_eq!(d2_task.status, d1_task.status);
    let d1_run = d1_task.run.as_ref().expect("U-05d D1 governed Run");
    let d2_run = d2_task.run.as_ref().expect("U-05d D2 governed Run");
    assert_eq!(d2_run.run_id, d1_run.run_id);
    assert_eq!(d2_run.revision, d1_run.revision);
    assert_eq!(d2_run.status, d1_run.status);
    let d1_step = d1_run
        .steps
        .iter()
        .find(|step| step.step_id == U03C_STEP_ID)
        .expect("U-05d D1 governed Step");
    let d2_step = d2_run
        .steps
        .iter()
        .find(|step| step.step_id == U03C_STEP_ID)
        .expect("U-05d D2 governed Step");
    assert_eq!(d2_step.step_id, d1_step.step_id);
    assert_eq!(d2_step.revision, d1_step.revision);
    assert_eq!(d2_step.status, d1_step.status);
    let d1_attempt = d1_step
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == U03C_ATTEMPT_ID)
        .expect("U-05d D1 governed Attempt");
    let d2_attempt = d2_step
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == U03C_ATTEMPT_ID)
        .expect("U-05d D2 governed Attempt");
    assert_eq!(d2_attempt.attempt_id, d1_attempt.attempt_id);
    assert_eq!(d2_attempt.revision, d1_attempt.revision);
    assert_eq!(d2_attempt.status, d1_attempt.status);
    assert_eq!(u03c_durability_oracle(&root, &task_id), before);

    timeout(Duration::from_secs(5), second_controller.stop())
        .await
        .expect("stop U-05d D2 Task Watch controller within the bound");
    drop(second_controller);
    drop(second_attachment);
    let second_status = shutdown_fixture_child(&mut second, "U-05d D2 daemon").await;
    assert!(
        second_status.success(),
        "U-05d D2 shutdown failed: {second_status}"
    );
    assert_eq!(u03c_durability_oracle(&root, &task_id), before);
    fs::remove_dir_all(&root).expect("remove U-05d fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u03c_same_root_restart_preserves_result_review_and_authority_snapshots() {
    let root = std::env::temp_dir().join(format!("egopulse-u03c-restart-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-03c restart root");
    let instance = format!("u03c-restart-{}", Uuid::now_v7());

    let mut first = spawn_fixture_with_mode(&root, &instance, U03C_RESULT_REVIEW_MODE).await;
    let first_pid = first.id().expect("U-03c D1 PID");
    assert_ne!(first_pid, std::process::id());
    wait_for_u03c_ready(&instance, &mut first).await;
    let (first_discovery_attachment, mut first_discovery_watch, task_id) =
        u03c_selected_task_or_reap(&instance, &mut first).await;
    wait_for_u03c_projection(&first_discovery_attachment, &task_id, true).await;
    first_discovery_watch.stop().await;
    drop(first_discovery_watch);
    drop(first_discovery_attachment);
    let baseline = u03c_durability_oracle(&root, &task_id);
    let first_cli = normalized_u03c_cli_review(u03c_cli_review_json(&instance, &task_id).await);
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
    let (first_attachment, mut first_watch, first_selected_task_id) =
        u03c_selected_task_or_reap(&instance, &mut first).await;
    assert_eq!(first_selected_task_id, task_id);
    let first_tui =
        u03c_tui_review_lines(Arc::clone(&first_attachment), &mut first_watch, &task_id).await;
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
    first_watch.stop().await;
    drop(first_watch);
    drop(first_attachment);
    let first_status = shutdown_fixture_child(&mut first, "U-03c D1").await;
    assert!(
        first_status.success(),
        "U-03c D1 shutdown failed: {first_status}"
    );

    // D2 deliberately executes the same production seeding commands again. Authority exact
    // replay, proven by the unchanged fixed-table digests below, prevents any additional write.
    let mut second = spawn_fixture_with_mode(&root, &instance, U03C_RESULT_REVIEW_MODE).await;
    let second_pid = second.id().expect("U-03c D2 PID");
    assert_ne!(second_pid, std::process::id());
    assert_ne!(
        first_pid, second_pid,
        "U-03c restart must use a new process"
    );
    wait_for_u03c_ready(&instance, &mut second).await;
    let (second_discovery_attachment, mut second_discovery_watch, second_task_id) =
        u03c_selected_task_or_reap(&instance, &mut second).await;
    assert_eq!(second_task_id, task_id);
    wait_for_u03c_projection(&second_discovery_attachment, &task_id, true).await;
    second_discovery_watch.stop().await;
    drop(second_discovery_watch);
    drop(second_discovery_attachment);
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
    let second_cli = normalized_u03c_cli_review(u03c_cli_review_json(&instance, &task_id).await);
    assert_eq!(second_cli, first_cli);
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
    let (second_attachment, mut second_watch, second_selected_task_id) =
        u03c_selected_task_or_reap(&instance, &mut second).await;
    assert_eq!(second_selected_task_id, task_id);
    let second_tui =
        u03c_tui_review_lines(Arc::clone(&second_attachment), &mut second_watch, &task_id).await;
    assert_eq!(second_tui, first_tui);
    assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
    second_watch.stop().await;
    drop(second_watch);
    drop(second_attachment);
    let second_status = shutdown_fixture_child(&mut second, "U-03c D2").await;
    assert!(
        second_status.success(),
        "U-03c D2 shutdown failed: {second_status}"
    );
    fs::remove_dir_all(&root).expect("remove U-03c restart root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u03c_real_clients_fail_closed_for_missing_permission_and_stale_review() {
    for (label, mode) in [
        ("missing", U03C_RESULT_REVIEW_MODE),
        ("permission", U03C_RESULT_REVIEW_DENY_MODE),
        ("stale", U03C_RESULT_REVIEW_STALE_MODE),
    ] {
        let root = std::env::temp_dir().join(format!("egopulse-u03c-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create U-03c failure root");
        let instance = format!("u03c-{label}-{}", Uuid::now_v7());
        let mut child = spawn_fixture_with_mode(&root, &instance, mode).await;
        assert_ne!(child.id(), Some(std::process::id()));
        wait_for_u03c_ready(&instance, &mut child).await;
        let (attachment, mut watch, task_id) =
            u03c_selected_task_or_reap(&instance, &mut child).await;
        wait_for_u03c_projection(&attachment, &task_id, mode != U03C_RESULT_REVIEW_STALE_MODE)
            .await;
        let baseline = u03c_durability_oracle(&root, &task_id);
        let requested_task_id = if label == "missing" {
            "task:u03c-missing"
        } else {
            task_id.as_str()
        };
        assert_u03c_shared_review_failure(&attachment, requested_task_id, label).await;
        let cli = run_bounded_fixture_command(
            cli_executable(),
            &instance,
            &["task", "review", requested_task_id, "--json"],
            "U-03c fail-closed CLI review",
        )
        .await;
        assert!(
            !cli.status.success(),
            "U-03c {label} CLI review unexpectedly succeeded"
        );
        assert_u03c_cli_review_failure(label, &cli);
        let cli_stdout = String::from_utf8_lossy(&cli.stdout);
        let cli_stderr = String::from_utf8_lossy(&cli.stderr);
        let failure_output = format!("{cli_stdout}\n{cli_stderr}");
        for forbidden in [
            U03C_ARTIFACT_SET_ID,
            U03C_VERIFICATION_RUN_ID,
            U03C_SENSITIVE_PRINCIPAL,
            U03C_SENSITIVE_PROOF,
            U03C_SENSITIVE_WORKSPACE,
            U03C_SENSITIVE_RAW,
            "native-u03c-never-render",
        ] {
            assert!(
                !failure_output.contains(forbidden),
                "U-03c {label} failure response leaked governed review data: {forbidden}"
            );
        }
        assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
        watch.stop().await;
        assert_u03c_tui_review_fails(
            Arc::clone(&attachment),
            requested_task_id,
            &u03c_expected_tui_failure(label),
        )
        .await;
        assert_eq!(u03c_durability_oracle(&root, &task_id), baseline);
        drop(watch);
        drop(attachment);
        let status = shutdown_fixture_child(&mut child, "U-03c fail-closed daemon").await;
        assert!(status.success(), "U-03c {label} daemon failed: {status}");
        fs::remove_dir_all(&root).expect("remove U-03c failure root");
    }
}

async fn serve_r9b_task_disconnect_fixture(
    root: &Path,
    instance: &str,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let config = fixture_config(root, instance);
    let providers = open_fixture_providers(root);
    let address = LocalIpcAddress::for_instance(&config.instance).expect("R-9B C5-C IPC address");
    let listener = LocalIpcListener::bind(address).expect("R-9B C5-C IPC listener");
    let model = LocalReadModel::open(LocalReadModelConfig {
        database_path: config.read_model_database_path,
        epoch: config.read_model_epoch,
        key: LocalReadModelKey::new(config.read_model_key),
    })
    .expect("R-9B C5-C read model");
    let initial_position = model.position().expect("R-9B C5-C initial position");
    let model = Arc::new(Mutex::new(model));
    let inner: Arc<dyn ReadModelReader> =
        Arc::new(BlockingLocalReadModelReader::new(Arc::clone(&model)));
    let reader: Arc<dyn ReadModelReader> = Arc::new(R9bTaskFramesReader::new(inner, root));
    let notifier = ProjectionCommitNotifier::new(initial_position.clone());
    let position_provider = Arc::new(FixedProjectionPosition(initial_position));
    let profiles = Arc::new(
        egopulse_domain_contracts::profiles::ContractProfiles::embedded()
            .expect("R-9B C5-C profiles"),
    );
    let token_key = TokenMacKey::new(config.token_mac_key).expect("R-9B C5-C token key");
    let token_codec = Arc::new(ReadTokenCodec::new(
        token_key,
        ReadGatewayPolicy::v01(),
        Arc::clone(&providers.session_clock),
    ));
    let session_config = SessionConfig::new(
        vec![api_contract_ref()],
        egopulse_client_kernel::client_kernel_contract_ref(),
        config.session_ttl,
    )
    .expect("R-9B C5-C session config");
    let session = LocalSessionEndpoint::new(
        session_config,
        Arc::clone(&providers.principal_resolver),
        Arc::clone(&providers.session_clock),
        position_provider,
        Arc::clone(&providers.session_audit),
    );
    let registry = session.registry();
    let read_application = Arc::new(ReadGatewayApplication::new(
        registry,
        profiles,
        reader,
        notifier.clone(),
        token_codec,
        Arc::new(NoopReadGatewayAuditSink),
    ));
    let read_model = LocalReadModelEndpoint::new(read_application);
    let projection_source = providers
        .projection_source
        .clone()
        .expect("R-9B C5-C projection source");
    let arm_notifier = notifier.clone();
    let projection_pump = ProjectionPump::new(model, notifier, projection_source);
    let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
    let mut server_stop = stop_receiver.clone();
    let mut arm_stop = stop_receiver.clone();
    let arm_path = root.join(R9B_TASK_DISCONNECT_ARM_FILE);
    let mut arm_wake = Box::pin(async move {
        let arm_position = arm_notifier.subscribe();
        loop {
            if arm_path.is_file() {
                let current_position = arm_position.borrow().clone();
                arm_notifier.publish(current_position);
                break;
            }
            tokio::select! {
                changed = arm_stop.changed() => {
                    if changed.is_err() || *arm_stop.borrow() {
                        return;
                    }
                }
                _ = sleep(Duration::from_millis(5)) => {}
            }
        }
        while !*arm_stop.borrow() {
            if arm_stop.changed().await.is_err() {
                break;
            }
        }
    });
    let server_shutdown = async move {
        tokio::select! {
            _ = shutdown => {}
            _ = server_stop.changed() => {}
        }
    };
    let mut server = Box::pin(
        Server::builder()
            .add_service(LocalSessionServiceServer::new(session))
            .add_service(LocalReadModelServiceServer::new(read_model))
            .serve_with_incoming_shutdown(listener.into_incoming(), server_shutdown),
    );
    let mut projection = Box::pin(projection_pump.run(stop_receiver));
    tokio::select! {
        result = &mut server => {
            let _ = stop_sender.send(true);
            projection.await.expect("R-9B C5-C projection shutdown");
            arm_wake.await;
            result.expect("R-9B C5-C server");
        }
        result = &mut projection => {
            result.expect("R-9B C5-C projection pump");
            let _ = stop_sender.send(true);
            arm_wake.await;
            server.await.expect("R-9B C5-C server shutdown");
            panic!("R-9B C5-C projection pump stopped before fixture shutdown");
        }
        () = &mut arm_wake => {
            let _ = stop_sender.send(true);
            projection.await.expect("R-9B C5-C projection shutdown after arm wake");
            server.await.expect("R-9B C5-C server shutdown after arm wake");
            panic!("R-9B C5-C arm notifier stopped before fixture shutdown");
        }
    }
}

async fn serve_r9b_retention_reset_fixture(
    root: &Path,
    instance: &str,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let config = fixture_config(root, instance);
    let providers = open_fixture_providers(root);
    let address = LocalIpcAddress::for_instance(&config.instance).expect("R-9B C5-D IPC address");
    let listener = LocalIpcListener::bind(address).expect("R-9B C5-D IPC listener");
    let model = LocalReadModel::open(LocalReadModelConfig {
        database_path: config.read_model_database_path,
        epoch: config.read_model_epoch,
        key: LocalReadModelKey::new(config.read_model_key),
    })
    .expect("R-9B C5-D read model");
    let initial_position = model.position().expect("R-9B C5-D initial position");
    let model = Arc::new(Mutex::new(model));
    let witness = Arc::new(R9bRetentionWitness::new(root));
    let inner: Arc<dyn ReadModelReader> =
        Arc::new(BlockingLocalReadModelReader::new(Arc::clone(&model)));
    let reader: Arc<dyn ReadModelReader> =
        Arc::new(R9bRetentionReader::new(inner, Arc::clone(&witness), root));
    let notifier = ProjectionCommitNotifier::new(initial_position.clone());
    let position_provider = Arc::new(FixedProjectionPosition(initial_position));
    let profiles = Arc::new(
        egopulse_domain_contracts::profiles::ContractProfiles::embedded()
            .expect("R-9B C5-D profiles"),
    );
    let token_key = TokenMacKey::new(config.token_mac_key).expect("R-9B C5-D token key");
    let token_codec = Arc::new(ReadTokenCodec::new(
        token_key,
        ReadGatewayPolicy::v01(),
        Arc::clone(&providers.session_clock),
    ));
    let session_config = SessionConfig::new(
        vec![api_contract_ref()],
        egopulse_client_kernel::client_kernel_contract_ref(),
        config.session_ttl,
    )
    .expect("R-9B C5-D session config");
    let session = LocalSessionEndpoint::new(
        session_config,
        Arc::clone(&providers.principal_resolver),
        Arc::clone(&providers.session_clock),
        position_provider,
        Arc::clone(&providers.session_audit),
    );
    let registry = session.registry();
    let read_application = Arc::new(ReadGatewayApplication::new(
        registry,
        profiles,
        reader,
        notifier.clone(),
        token_codec,
        Arc::new(NoopReadGatewayAuditSink),
    ));
    let read_model = LocalReadModelEndpoint::new(read_application);
    let projection_source = providers
        .projection_source
        .clone()
        .expect("R-9B C5-D projection source");
    let projection_pump =
        ProjectionPump::new(Arc::clone(&model), notifier.clone(), projection_source);
    let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
    let mut server_stop = stop_receiver.clone();

    let mut arm_stop = stop_receiver.clone();
    let arm_path = root.join(R9B_RETENTION_TASK_HOLD_ARM_FILE);
    let arm_witness = Arc::clone(&witness);
    let arm_notifier = notifier.clone();
    let arm_wake = async move {
        let arm_position = arm_notifier.subscribe();
        let arm_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if arm_path.is_file() {
                let current_position = arm_position.borrow().clone();
                arm_witness
                    .record(&format!(
                        "task-hold-wake epoch={} sequence={}",
                        current_position.epoch, current_position.sequence
                    ))
                    .expect("persist R-9B C5-D Task hold wake");
                arm_notifier.publish(current_position);
                break;
            }
            assert!(
                Instant::now() < arm_deadline,
                "R-9B C5-D Task hold arm exceeded its deadline"
            );
            tokio::select! {
                changed = arm_stop.changed() => {
                    if changed.is_err() || *arm_stop.borrow() {
                        return;
                    }
                }
                _ = sleep(Duration::from_millis(5)) => {}
            }
        }
        while !*arm_stop.borrow() {
            if arm_stop.changed().await.is_err() {
                break;
            }
        }
    };

    let mut compact_stop = stop_receiver.clone();
    let compact_model = Arc::clone(&model);
    let compact_witness = Arc::clone(&witness);
    let compact_request_path = root.join(R9B_RETENTION_COMPACT_REQUEST_FILE);
    let compacted_path = root.join(R9B_RETENTION_COMPACTED_FILE);
    let approval_observed_path = root.join(R9B_RETENTION_APPROVAL_OBSERVED_FILE);
    let compactor = async move {
        let compact_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if compact_request_path.is_file() {
                assert!(
                    approval_observed_path.is_file(),
                    "R-9B C5-D compaction requires persisted Approval observation"
                );
                let request = fs::read_to_string(&compact_request_path)
                    .expect("read R-9B C5-D compaction request");
                assert_eq!(
                    request, "compact-at-current\n",
                    "R-9B C5-D compact request must carry no domain position"
                );
                let (old_floor, fixed_floor, current, returned_floor) = {
                    let mut model = compact_model
                        .lock()
                        .expect("lock R-9B C5-D read model for compaction");
                    let old_floor = model
                        .retention_floor()
                        .expect("read R-9B C5-D old retention floor");
                    let fixed_floor = model
                        .position()
                        .expect("fix R-9B C5-D neutral current retention floor");
                    let current = model.position().expect("read R-9B C5-D current position");
                    assert_eq!(current, fixed_floor);
                    assert_eq!(old_floor.epoch, fixed_floor.epoch);
                    let returned_floor = model
                        .compact_history(fixed_floor.sequence)
                        .expect("compact R-9B C5-D projection history");
                    assert_eq!(returned_floor.epoch, fixed_floor.epoch);
                    (old_floor, fixed_floor, current, returned_floor)
                };
                let compact_fact = format!(
                    "floor_epoch={} floor_sequence={} old_floor_epoch={} old_floor_sequence={} current_epoch={} current_sequence={} returned_floor_epoch={} returned_floor_sequence={}",
                    fixed_floor.epoch,
                    fixed_floor.sequence,
                    old_floor.epoch,
                    old_floor.sequence,
                    current.epoch,
                    current.sequence,
                    returned_floor.epoch,
                    returned_floor.sequence
                );
                compact_witness
                    .record(&format!("retention-compacted {compact_fact}"))
                    .expect("persist R-9B C5-D compaction witness");
                let mut compacted = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&compacted_path)
                    .expect("create R-9B C5-D compacted fact");
                writeln!(compacted, "{compact_fact}")
                    .and_then(|()| compacted.sync_all())
                    .expect("persist R-9B C5-D compacted fact");
                drop(compacted);
                break;
            }
            assert!(
                Instant::now() < compact_deadline,
                "R-9B C5-D compaction request exceeded its deadline"
            );
            tokio::select! {
                changed = compact_stop.changed() => {
                    if changed.is_err() || *compact_stop.borrow() {
                        return;
                    }
                }
                _ = sleep(Duration::from_millis(5)) => {}
            }
        }
        while !*compact_stop.borrow() {
            if compact_stop.changed().await.is_err() {
                break;
            }
        }
    };

    let mut control = Box::pin(async move {
        tokio::join!(arm_wake, compactor);
    });
    let server_shutdown = async move {
        tokio::select! {
            _ = shutdown => {}
            _ = server_stop.changed() => {}
        }
    };
    let mut server = Box::pin(
        Server::builder()
            .add_service(LocalSessionServiceServer::new(session))
            .add_service(LocalReadModelServiceServer::new(read_model))
            .serve_with_incoming_shutdown(listener.into_incoming(), server_shutdown),
    );
    let mut projection = Box::pin(projection_pump.run(stop_receiver));
    tokio::select! {
        result = &mut server => {
            let _ = stop_sender.send(true);
            projection.await.expect("R-9B C5-D projection shutdown");
            control.await;
            result.expect("R-9B C5-D server");
        }
        result = &mut projection => {
            result.expect("R-9B C5-D projection pump");
            let _ = stop_sender.send(true);
            control.await;
            server.await.expect("R-9B C5-D server shutdown");
            panic!("R-9B C5-D projection pump stopped before fixture shutdown");
        }
        () = &mut control => {
            let _ = stop_sender.send(true);
            projection.await.expect("R-9B C5-D projection shutdown after control plane");
            server.await.expect("R-9B C5-D server shutdown after control plane");
            panic!("R-9B C5-D control plane stopped before fixture shutdown");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_00_daemon_fixture_child() {
    if std::env::var_os(FIXTURE_ROOT_ENV).is_none() {
        return;
    }

    let root = fixture_root();
    let instance = fixture_instance();
    let shutdown = async {
        let _ = tokio::task::spawn_blocking(|| {
            let mut stdin = std::io::stdin();
            let mut buffer = [0_u8; 1];
            let _ = stdin.read(&mut buffer);
        })
        .await;
    };
    if fixture_mode() == R9B_TASK_SINGLE_DISCONNECT_MODE {
        serve_r9b_task_disconnect_fixture(&root, &instance, shutdown).await;
        return;
    }
    if fixture_mode() == R9B_RETENTION_RESET_MODE {
        serve_r9b_retention_reset_fixture(&root, &instance, shutdown).await;
        return;
    }
    let composition = DaemonComposition::build(
        fixture_config(&root, &instance),
        open_fixture_providers(&root),
    )
    .expect("real fixture daemon composition");
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
            "--no-memory",
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
            "--no-memory",
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
    let routed_ids = RoutedWorkIds::from_preview(&prepare_json, &task_id);
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
    assert_eq!(driver_record["runId"], routed_ids.run_id);
    assert_eq!(driver_record["stepId"], routed_ids.step_id);
    assert_eq!(driver_record["attemptId"], routed_ids.attempt_id);
    assert_eq!(driver_record["dispatchId"], routed_ids.dispatch_id);
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
        task_view["data"]["currentRunId"], routed_ids.run_id,
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
            "--no-memory",
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
    let routed_ids = RoutedWorkIds::from_preview(&prepare_json, &task_id);
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
        routed_ids.run_id
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
    assert_eq!(driver_record["runId"], routed_ids.run_id);
    assert_eq!(driver_record["stepId"], routed_ids.step_id);
    assert_eq!(driver_record["attemptId"], routed_ids.attempt_id);
    assert_eq!(driver_record["dispatchId"], routed_ids.dispatch_id);
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
        routed_ids.run_id
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
            "--no-memory",
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
    let routed_ids = RoutedWorkIds::from_preview(&prepared, &task_id);
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
        &routed_ids.dispatch_id,
        R9A3E_PREAUTH_UNAVAILABLE_PHASE,
        &mut daemon_one,
    )
    .await;
    assert!(!bundle_path.exists());
    assert!(!root.join(R8A_DRIVER_RECORD).exists());

    let adapter_before_revoke = read_r8b2c_adapter_oracle(&root, &routed_ids);
    assert_eq!(adapter_before_revoke.dispatch_count, 1);
    assert_eq!(adapter_before_revoke.dispatch_state, "prepared");
    assert_eq!(adapter_before_revoke.delivery_unknown_count, 0);
    assert_eq!(adapter_before_revoke.observation_count, 0);
    assert_eq!(adapter_before_revoke.pending_observation_count, 0);
    assert!(adapter_before_revoke.receipt.is_none());
    assert!(adapter_before_revoke.receipt_bytes.is_none());
    let collaboration_before_revoke = read_r8b2c_collaboration_oracle(&root, &routed_ids);
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
        Some(routed_ids.run_id.as_str())
    );
    let verdict_before_revoke = read_empty_r9a3_verdict_oracle(&root);
    let context_before_revoke = read_r9a3_context_authority_store(
        &root.join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        &routed_ids.dispatch_id,
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
        &routed_ids.dispatch_id,
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
    assert_eq!(
        read_r8b2c_adapter_oracle(&root, &routed_ids),
        adapter_before_revoke
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root, &routed_ids),
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
        &routed_ids.dispatch_id,
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
            &routed_ids.dispatch_id,
        )
        .expect("read R-9A.3e Context after D2 Ready rejection"),
        context_after_revoke
    );
    assert_eq!(
        read_r8b2c_adapter_oracle(&root, &routed_ids),
        adapter_before_revoke
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root, &routed_ids),
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
            "--no-memory",
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
    let routed_ids = RoutedWorkIds::from_preview(&prepared, &task_id);
    assert!(
        confirmed["data"]["status"] == TaskStatus::Ready.as_str_name()
            || confirmed["data"]["status"] == TaskStatus::Active.as_str_name(),
        "R-9A.3d confirmation response must be Ready or already Active: {}",
        confirmed["data"]["status"]
    );

    let active =
        wait_for_r9a3d_task(&instance, &task_id, TaskStatus::Active, &mut daemon_one).await;
    assert_eq!(active["data"]["currentRunId"], routed_ids.run_id);

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
    assert_eq!(committed.dispatch_id, routed_ids.dispatch_id);
    assert_eq!(committed.attempt_id, routed_ids.attempt_id);
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
        &routed_ids.dispatch_id,
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
    assert_eq!(
        authorization_before_restart.dispatch_id,
        routed_ids.dispatch_id
    );
    assert_eq!(
        authorization_before_restart.attempt_id,
        routed_ids.attempt_id
    );
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
        &routed_ids.dispatch_id,
    )
    .expect("reopen R-9A.3d Context authority after D1 kill");
    assert_eq!(context_after_kill, context_before_restart);

    let adapter_after_kill = read_r8b2c_adapter_oracle(root.path(), &routed_ids);
    assert_eq!(adapter_after_kill.dispatch_count, 1);
    assert_eq!(adapter_after_kill.delivery_unknown_count, 1);
    assert_eq!(adapter_after_kill.observation_count, 0);
    assert_eq!(adapter_after_kill.pending_observation_count, 0);
    assert_eq!(adapter_after_kill.dispatch_state, "delivery_unknown");
    assert_eq!(
        adapter_after_kill.dispatch_attempt_id,
        routed_ids.attempt_id
    );
    assert!(adapter_after_kill.receipt.is_none());
    assert!(adapter_after_kill.receipt_bytes.is_none());

    let collaboration_after_kill = read_r8b2c_collaboration_oracle(root.path(), &routed_ids);
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
        vec![routed_ids.attempt_id.clone()]
    );
    assert_eq!(
        collaboration_after_kill.step.current_attempt_id.as_deref(),
        Some(routed_ids.attempt_id.as_str())
    );
    assert_eq!(
        collaboration_after_kill.attempt.attempt_id,
        routed_ids.attempt_id
    );
    assert_eq!(collaboration_after_kill.attempt.run_id, routed_ids.run_id);
    assert_eq!(collaboration_after_kill.attempt.step_id, routed_ids.step_id);
    assert!(collaboration_after_kill.attempt.attempt_number > 0);
    assert_eq!(
        collaboration_after_kill.attempt.status,
        AttemptStatus::DispatchPending as i32
    );
    assert_eq!(
        collaboration_after_kill.attempt.dispatch_id.as_deref(),
        Some(routed_ids.dispatch_id.as_str())
    );
    let original_attempt_number = collaboration_after_kill.attempt.attempt_number;

    let task_after_kill = read_r8b2c_task_oracle(root.path(), &task_id);
    assert_eq!(task_after_kill.snapshot.status, TaskStatus::Active as i32);
    assert_eq!(
        task_after_kill.snapshot.current_run_id.as_deref(),
        Some(routed_ids.run_id.as_str())
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
    assert_eq!(interrupted["data"]["currentRunId"], routed_ids.run_id);
    assert_ne!(
        interrupted["data"]["status"],
        TaskStatus::Completed.as_str_name()
    );

    let adapter_after_recovery = read_r8b2c_adapter_oracle(root.path(), &routed_ids);
    assert_eq!(adapter_after_recovery.dispatch_count, 1);
    assert_eq!(adapter_after_recovery.delivery_unknown_count, 1);
    assert_eq!(adapter_after_recovery.observation_count, 1);
    assert_eq!(adapter_after_recovery.observations.len(), 1);
    let reconciliation_observation = &adapter_after_recovery.observations[0];
    assert_eq!(
        reconciliation_observation.native_key,
        format!(
            "reconciliation:adapter-reconciliation:{}",
            routed_ids.dispatch_id
        )
    );
    assert_eq!(
        reconciliation_observation.dispatch_id,
        routed_ids.dispatch_id
    );
    assert!(!reconciliation_observation.raw_event.is_empty());
    assert!(matches!(
        reconciliation_observation.observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code == "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN"
    ));
    let collaboration_after_recovery = read_r8b2c_collaboration_oracle(root.path(), &routed_ids);
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
        vec![routed_ids.attempt_id.clone()]
    );
    assert_eq!(
        collaboration_after_recovery
            .step
            .current_attempt_id
            .as_deref(),
        Some(routed_ids.attempt_id.as_str())
    );
    assert_eq!(
        collaboration_after_recovery.attempt.attempt_id,
        routed_ids.attempt_id
    );
    assert_eq!(
        collaboration_after_recovery.attempt.run_id,
        routed_ids.run_id
    );
    assert_eq!(
        collaboration_after_recovery.attempt.step_id,
        routed_ids.step_id
    );
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
        &routed_ids.dispatch_id,
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
        read_r8b2c_adapter_oracle(root.path(), &routed_ids),
        adapter_after_recovery
    );
    let collaboration_after_stable = read_r8b2c_collaboration_oracle(root.path(), &routed_ids);
    assert_eq!(collaboration_after_stable, collaboration_after_recovery);
    assert_eq!(
        collaboration_after_stable.step.attempt_ids,
        vec![routed_ids.attempt_id.clone()]
    );
    assert_eq!(
        collaboration_after_stable
            .step
            .current_attempt_id
            .as_deref(),
        Some(routed_ids.attempt_id.as_str())
    );
    assert_eq!(
        collaboration_after_stable.attempt.attempt_id,
        routed_ids.attempt_id
    );
    assert_eq!(collaboration_after_stable.attempt.run_id, routed_ids.run_id);
    assert_eq!(
        collaboration_after_stable.attempt.step_id,
        routed_ids.step_id
    );
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
        &routed_ids.dispatch_id,
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
    let R8b2cPreparedWork {
        task_id,
        snapshot_id: _,
        routed_ids,
        ..
    } = prepare_and_confirm_r8b2c_work(&root, &instance, "r8b2c-begin").await;

    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        &routed_ids.dispatch_id,
        R8B2C_BEGIN_DELIVERY_PHASE,
        &mut child,
    )
    .await;
    let task_before_kill =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Active, &mut child).await;
    assert_eq!(task_before_kill["data"]["currentRunId"], routed_ids.run_id);

    let witness = R8b2cWitnessOracle::open_existing(&root, &instance);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 0);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state(&routed_ids.dispatch_id),
        Some(("pending".to_owned(), 0))
    );

    let adapter = read_r8b2c_adapter_oracle(&root, &routed_ids);
    assert_eq!(adapter.dispatch_count, 1);
    assert_eq!(adapter.delivery_unknown_count, 1);
    assert_eq!(adapter.observation_count, 0);
    assert_eq!(adapter.pending_observation_count, 0);
    assert_eq!(adapter.dispatch_state, "delivery_unknown");
    assert!(adapter.receipt.is_none());
    assert!(adapter.receipt_bytes.is_none());
    assert_eq!(adapter.envelope.dispatch_id, routed_ids.dispatch_id);

    let collaboration = read_r8b2c_collaboration_oracle(&root, &routed_ids);
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
        &routed_ids.dispatch_id,
        R8B2C_UNKNOWN_RECOVERED_PHASE,
        &mut restarted,
    )
    .await;

    let interrupted =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Interrupted, &mut restarted)
            .await;
    assert_eq!(interrupted["data"]["currentRunId"], routed_ids.run_id);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 1);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state(&routed_ids.dispatch_id),
        Some(("pending".to_owned(), 0))
    );

    let adapter = read_r8b2c_adapter_oracle(&root, &routed_ids);
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
    let reconciliation_key = format!(
        "reconciliation:adapter-reconciliation:{}",
        routed_ids.dispatch_id
    );
    let reconciliation = adapter
        .observations
        .iter()
        .find(|observation| observation.native_key == reconciliation_key)
        .expect("OutcomeUnknown reconciliation evidence must be durable");
    assert_eq!(reconciliation.dispatch_id, routed_ids.dispatch_id);
    assert_eq!(reconciliation.ingestion_state, "pending");
    assert!(!reconciliation.raw_event.is_empty());
    assert!(matches!(
        reconciliation.observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code == "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN"
    ));
    let collaboration = read_r8b2c_collaboration_oracle(&root, &routed_ids);
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
        Some(routed_ids.run_id.as_str())
    );
    fs::remove_dir_all(&root).expect("remove R-8B.2c begin-delivery fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r8b2c_delivered_before_poll_hard_kill_holds_without_resend_or_poll() {
    let root = std::env::temp_dir().join(format!("egopulse-r8b2c-delivered-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-8B.2c delivered fixture root");
    let instance = format!("r8b2c-delivered-{}", Uuid::now_v7());
    let mut child =
        spawn_fixture_with_mode(&root, &instance, R8B2C_DELIVERED_BEFORE_POLL_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut child).await;
    let R8b2cPreparedWork {
        task_id,
        snapshot_id,
        routed_ids,
        ..
    } = prepare_and_confirm_r8b2c_work(&root, &instance, "r8b2c-delivered").await;

    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        &routed_ids.dispatch_id,
        R8B2C_DELIVERED_BEFORE_POLL_PHASE,
        &mut child,
    )
    .await;
    let active =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Active, &mut child).await;
    assert_eq!(active["data"]["currentRunId"], routed_ids.run_id);

    let witness = R8b2cWitnessOracle::open_existing(&root, &instance);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 0);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state(&routed_ids.dispatch_id),
        Some(("pending".to_owned(), 0))
    );

    let adapter_before_revoke = read_r8b2c_adapter_oracle(&root, &routed_ids);
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
    let collaboration_before_revoke = read_r8b2c_collaboration_oracle(&root, &routed_ids);
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
    let adapter_after_revoke = read_r8b2c_adapter_oracle(&root, &routed_ids);
    assert_eq!(adapter_after_revoke, adapter_before_revoke);
    assert_eq!(
        adapter_after_revoke.receipt_bytes.as_deref(),
        Some(receipt_bytes_before_revoke.as_slice())
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root, &routed_ids),
        collaboration_before_revoke
    );
    assert_eq!(read_r8b2c_task_oracle(&root, &task_id), task_before_revoke);
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);

    hard_kill_r8b2c_child(&mut child, R8B2C_DELIVERED_BEFORE_POLL_PHASE).await;

    let mut restarted =
        spawn_fixture_with_mode(&root, &instance, R8B2C_UNKNOWN_RECOVERY_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;
    wait_for_r8b2c_checkpoint(
        &root,
        &instance,
        &routed_ids.dispatch_id,
        R8B2C_UNKNOWN_RECOVERED_PHASE,
        &mut restarted,
    )
    .await;

    let interrupted =
        wait_for_r8b2c_task_status(&instance, &task_id, TaskStatus::Interrupted, &mut restarted)
            .await;
    assert_eq!(interrupted["data"]["currentRunId"], routed_ids.run_id);
    assert_eq!(witness.ledger_count("send_dispatch"), 1);
    assert_eq!(witness.ledger_count("next_event"), 0);
    assert_eq!(witness.ledger_count("reconcile"), 1);
    assert_eq!(witness.ledger_count("ack_emitted"), 0);
    assert_eq!(
        witness.native_event_state(&routed_ids.dispatch_id),
        Some(("pending".to_owned(), 0))
    );

    let adapter = read_r8b2c_adapter_oracle(&root, &routed_ids);
    assert_eq!(adapter.dispatch_count, 1);
    assert_eq!(adapter.delivery_unknown_count, 0);
    assert_eq!(adapter.observation_count, 1);
    assert_eq!(adapter.pending_observation_count, 1);
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

    let reconciliation_key = format!(
        "reconciliation:adapter-reconciliation:{}",
        routed_ids.dispatch_id
    );
    let observation = adapter
        .observations
        .iter()
        .find(|observation| observation.native_key == reconciliation_key)
        .expect("nonresident Delivered recovery must persist reconciliation evidence");
    let observation_id = &observation.observation_id;
    assert_eq!(observation.dispatch_id, routed_ids.dispatch_id);
    assert_eq!(observation.ingestion_state, "pending");
    assert_eq!(observation.observation.observation_id, *observation_id);
    assert_eq!(observation.observation.dispatch_id, observation.dispatch_id);
    assert!(matches!(
        observation.observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code == "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN"
    ));
    assert!(!observation.raw_event.is_empty());
    assert_eq!(
        observation.native_event_digest_sha256,
        format!("{:x}", Sha256::digest(observation.raw_event.as_slice()))
    );
    assert!(!observation.raw_evidence_ref.trim().is_empty());

    let collaboration = read_r8b2c_collaboration_oracle(&root, &routed_ids);
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
    let task_before_stable = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(
        task_before_stable.snapshot.status,
        TaskStatus::Interrupted as i32
    );
    assert_eq!(
        task_before_stable.snapshot.current_run_id,
        Some(routed_ids.run_id.clone())
    );
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    let stable_counts = (
        witness.ledger_count("send_dispatch"),
        witness.ledger_count("next_event"),
        witness.ledger_count("reconcile"),
        witness.ledger_count("ack_emitted"),
    );
    sleep(Duration::from_millis(175)).await;
    let adapter_after_stable = read_r8b2c_adapter_oracle(&root, &routed_ids);
    let collaboration_after_stable = read_r8b2c_collaboration_oracle(&root, &routed_ids);
    let task_after_stable = read_r8b2c_task_oracle(&root, &task_id);
    assert_eq!(adapter_after_stable, adapter);
    assert_eq!(collaboration_after_stable, collaboration);
    assert_eq!(task_after_stable, task_before_stable);
    assert_eq!(read_empty_r9a3_verdict_oracle(&root), verdict_before_revoke);
    assert_eq!(
        (
            witness.ledger_count("send_dispatch"),
            witness.ledger_count("next_event"),
            witness.ledger_count("reconcile"),
            witness.ledger_count("ack_emitted"),
        ),
        stable_counts,
        "Delivered nonresident recovery must not resend, poll, reconcile again, or emit the pending ACK"
    );

    drop(restarted.stdin.take());
    let status = restarted
        .wait()
        .await
        .expect("wait for R-8B.2c Delivered nonresident recovery child");
    assert!(
        status.success(),
        "R-8B.2c Delivered nonresident recovery child failed: {status}"
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
            work_capability_route: None,
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
async fn c5_04_real_cli_rejects_malformed_await_and_submits_guided_approval() {
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

    let reviewed_summary_digest =
        reviewed_approval_summary_digest(&instance, "approval-c5-03").await;
    let accepted = run_cli(
        &instance,
        &[
            "approval",
            "decide",
            "approval-c5-03",
            "--decision",
            "allow-once",
            "--reason-code",
            "c5-04-guided-accepted",
            "--confirmation-proof-ref",
            "proof:c5-04:guided-accepted",
            "--reviewed-summary-digest",
            reviewed_summary_digest.as_str(),
            "--json",
        ],
    )
    .await;
    assert!(
        accepted.status.success(),
        "guided approval must commit: stdout={} stderr={}",
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
async fn u02c_real_daemon_seeded_projection_uses_production_approval_queue_controller() {
    let root = std::env::temp_dir().join(format!("egopulse-u02c-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-02c fixture root");
    let instance = format!("u02c-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    let _status = wait_for_cli_status_with_child(&instance, &mut child).await;

    let attachment = Arc::new(
        attach_client_operation(
            &instance,
            ClientSurface::Tui,
            format!("egopulse-u02c-controller-{}", Uuid::now_v7()),
        )
        .await
        .expect("attach production TUI controller to real daemon"),
    );
    let mut controller = ApprovalQueueController::new(Arc::clone(&attachment));
    controller
        .start()
        .await
        .expect("open atomic approval baseline/session");
    assert!(
        controller
            .model()
            .expect("approval model")
            .items
            .iter()
            .any(|item| {
                item.approval_request_id == "approval-c5-03" && item.task_id == "task-c5-03"
            })
    );

    let reviewed_summary_digest = controller
        .model()
        .expect("approval model")
        .items
        .iter()
        .find(|item| item.approval_request_id == "approval-c5-03")
        .and_then(|item| item.summary_digest.clone());
    let receipt = controller
        .decide_selected(
            GuidedApprovalDecision::AllowOnce,
            "u02c-founder-approved".to_owned(),
            Some("proof:u02c:approval".to_owned()),
            reviewed_summary_digest,
        )
        .await
        .expect("submit guided approval through shared operation");
    assert!(receipt.committed);
    assert!(
        controller
            .model()
            .expect("approval model after commit")
            .items
            .iter()
            .any(|item| { item.approval_request_id == "approval-c5-03" }),
        "controller must not optimistically remove a committed approval"
    );

    timeout(Duration::from_secs(8), async {
        loop {
            controller.pump().await.expect("pump approval projection");
            if !controller
                .model()
                .expect("approval model")
                .items
                .iter()
                .any(|item| item.approval_request_id == "approval-c5-03")
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("approval projection must remove the no-longer-actionable item");

    let projection = attachment
        .read_projection_snapshot()
        .await
        .expect("read projection after approval decision");
    let task = projection
        .tasks
        .iter()
        .filter_map(|view| view.task.as_ref())
        .find(|task| task.task_id == "task-c5-03")
        .expect("seeded Task projection");
    assert_eq!(task.status, TaskStatus::Active as i32);
    assert_ne!(task.status, TaskStatus::Completed as i32);

    controller.stop().await;
    drop(child.stdin.take());
    let status = child.wait().await.expect("U-02c fixture child exit");
    assert!(status.success(), "U-02c fixture child failed: {status}");

    let policy = PolicyDecisionAuthority::open(
        PolicyAuthorityConfig {
            database_path: root.join("policy-authority.db"),
            store_epoch: "c5-00-policy-epoch".to_owned(),
            key: PolicySqlCipherKey::new([0x12; 32]),
        },
        AllowPolicyReferences,
    )
    .expect("reopen Policy Authority for typed persistence oracle");
    let (record, state) = policy
        .get(&receipt.authority_decision_ref)
        .expect("read persisted Policy decision")
        .expect("persisted Policy decision exists");
    assert_eq!(
        record
            .request
            .as_ref()
            .expect("persisted approval request binding")
            .approval_request_id,
        "approval-c5-03"
    );
    assert_eq!(
        record.decision,
        egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecision::AllowOnce as i32
    );
    assert_eq!(state.revision, receipt.state_revision);
    let inspection = policy.inspect_store().expect("inspect Policy persistence");
    assert!(inspection.decision_count >= 1);
    assert!(inspection.event_count >= 1);
    assert!(inspection.idempotency_count >= 1);

    drop(policy);
    drop(projection);
    drop(receipt);
    drop(controller);
    drop(attachment);
    fs::remove_dir_all(&root).expect("remove U-02c fixture root");
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
                .expect("production controller validates the daemon update");
            if controller.model().is_some_and(|model| {
                model
                    .tasks
                    .iter()
                    .any(|task| task.task_id == created_task_id)
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
        .find(|task| task.task_id == created_task_id)
        .expect("controller page contains the governed Task");
    assert_ne!(
        controller_target.status,
        TaskStatus::Completed,
        "observation-only production controller must not false-complete the target Task"
    );
    assert_eq!(
        controller_target.task_id, durable_before_controller_pump.snapshot.task_id,
        "controller page must preserve the durable Task identity"
    );
    assert_eq!(
        controller_target.revision, durable_before_controller_pump.snapshot.revision,
        "controller page must preserve the durable Task revision"
    );
    assert_eq!(
        controller_target.status as i32, durable_before_controller_pump.snapshot.status,
        "controller page must preserve the durable Task status"
    );
    let after = attachment
        .read_projection_snapshot()
        .await
        .expect("read Task projection after observation-only watch");
    assert_eq!(
        after.tasks, after_external_write.tasks,
        "consuming Task Watch must not mutate Tasks beyond the separately committed governed command"
    );
    assert_eq!(controller_model.tasks.len(), after.tasks.len());
    for governed in &controller_model.tasks {
        let projected = after
            .tasks
            .iter()
            .filter_map(|view| view.task.as_ref())
            .find(|task| task.task_id == governed.task_id)
            .expect("safe controller Task must exist in the Authority-backed projection");
        assert_eq!(governed.revision, projected.revision);
        assert_eq!(governed.status as i32, projected.status);
    }
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
    let task_watch_stdout = String::from_utf8(task_watch.stdout).expect("Task watch UTF-8");
    let task_watch_envelopes: Vec<serde_json::Value> = task_watch_stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("Task watch NDJSON envelope"))
        .collect();
    assert_eq!(
        task_watch_envelopes.len(),
        2,
        "Task watch must emit exactly one baseline and one live envelope: {task_watch_stdout}"
    );
    assert_eq!(task_watch_envelopes[0]["operation"], "task.watch");
    assert_eq!(
        task_watch_envelopes[0]["streamSchema"],
        "egopulse.cli.task-watch/v1"
    );
    assert_eq!(task_watch_envelopes[0]["data"]["kind"], "baseline");
    assert_eq!(task_watch_envelopes[1]["operation"], "task.watch");
    assert_eq!(
        task_watch_envelopes[1]["streamSchema"],
        "egopulse.cli.task-watch/v1"
    );
    assert_eq!(task_watch_envelopes[1]["data"]["kind"], "update");
    assert_eq!(
        task_watch_envelopes[1]["data"]["classification"],
        "heartbeat"
    );
    assert!(
        task_watch_envelopes[1]["data"]["task"].is_null(),
        "heartbeat update must not carry Task facts"
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

    let reviewed_summary_digest =
        reviewed_approval_summary_digest(&instance, "approval-c5-03").await;
    let approval_output = run_cli(
        &instance,
        &[
            "approval",
            "decide",
            "approval-c5-03",
            "--decision",
            "allow-once",
            "--reason-code",
            "c5-03-approved",
            "--confirmation-proof-ref",
            "confirmation-c5-03",
            "--reviewed-summary-digest",
            reviewed_summary_digest.as_str(),
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

fn u04c_durability(
    root: &Path,
    snapshot_id: Option<&str>,
    task_id: Option<&str>,
) -> U04cWorkStartDurabilitySnapshot {
    read_u04c_work_start_durability(&U04cWorkStartOracleRequest {
        root,
        context_key: &[0x15; 32],
        context_store_epoch: "c5-context-epoch",
        context_schema_sha256: U04C_CONTEXT_SCHEMA_SHA256,
        task_key: &[0x11; 32],
        task_store_epoch: "c5-00-task-epoch",
        task_schema_sha256: U03C_TASK_SCHEMA_SHA256,
        snapshot_id,
        task_id,
    })
    .expect("read U-04c durability snapshot")
}

fn u04c_assert_task_context_binding(
    root: &Path,
    task_record: &U04cTaskRecord,
) -> U04cContextRecord {
    let task_snapshot =
        TaskSnapshot::decode(task_record.snapshot.as_slice()).expect("decode durable U-04c Task");
    assert_eq!(task_snapshot.task_id, task_record.task_id);
    assert_eq!(task_snapshot.revision, task_record.revision);
    assert_eq!(task_snapshot.status, task_record.status);
    assert!(
        !task_snapshot.input_snapshot_id.is_empty(),
        "durable U-04c Task must bind an input snapshot"
    );
    let bound = u04c_durability(
        root,
        Some(task_snapshot.input_snapshot_id.as_str()),
        Some(task_record.task_id.as_str()),
    );
    assert_eq!(bound.task_record.as_ref(), Some(task_record));
    let context = bound
        .context_record
        .expect("Task-bound U-04c Context snapshot must exist uniquely");
    assert_eq!(context.snapshot_id, task_snapshot.input_snapshot_id);
    assert_eq!(context.state, "issued");
    context
}

async fn run_u04c_cli(instance: &str, arguments: &[&str]) -> std::process::Output {
    run_bounded_fixture_command(
        cli_executable(),
        instance,
        arguments,
        "U-04c CLI subprocess",
    )
    .await
}

const U04C_CONPTY_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const U04C_CONPTY_CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(12);

struct U04cConptyOutput {
    bytes: Vec<u8>,
    screen: vt100::Parser,
    overflowed: bool,
    reader_error: Option<String>,
}

impl Default for U04cConptyOutput {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            screen: vt100::Parser::new(32, 140, 0),
            overflowed: false,
            reader_error: None,
        }
    }
}

struct U04cConptySession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    master: Option<Box<dyn portable_pty::MasterPty + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    output: Arc<Mutex<U04cConptyOutput>>,
    reader: Option<thread::JoinHandle<()>>,
    cursor_queries_answered: usize,
}

impl U04cConptySession {
    fn spawn(instance: &str) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 32,
                cols: 140,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open U-04c Windows ConPTY");
        let command = u04c_conpty_command(
            tui_executable(),
            &["--instance".to_owned(), instance.to_owned()],
            instance,
        );
        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn normal egopulse-tui in U-04c ConPTY");
        let mut reader = pair
            .master
            .try_clone_reader()
            .expect("clone U-04c ConPTY reader");
        let writer = pair.master.take_writer().expect("take U-04c ConPTY writer");
        drop(pair.slave);

        let output = Arc::new(Mutex::new(U04cConptyOutput::default()));
        let reader_output = Arc::clone(&output);
        let reader = thread::spawn(move || {
            let mut chunk = [0_u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        let mut output = reader_output.lock().expect("lock U-04c ConPTY output");
                        let remaining = U04C_CONPTY_OUTPUT_LIMIT.saturating_sub(output.bytes.len());
                        let retained = read.min(remaining);
                        output.bytes.extend_from_slice(&chunk[..retained]);
                        output.screen.process(&chunk[..retained]);
                        if retained != read {
                            output.overflowed = true;
                        }
                    }
                    Err(error) => {
                        reader_output
                            .lock()
                            .expect("lock U-04c ConPTY reader error")
                            .reader_error = Some(error.to_string());
                        break;
                    }
                }
            }
        });
        Self {
            child,
            master: Some(pair.master),
            writer: Some(writer),
            output,
            reader: Some(reader),
            cursor_queries_answered: 0,
        }
    }

    fn process_id(&self) -> u32 {
        self.child
            .process_id()
            .expect("U-04c ConPTY child must expose its PID")
    }

    fn send_keys(&mut self, keys: &[u8]) {
        let writer = self.writer.as_mut().expect("U-04c ConPTY writer");
        writer.write_all(keys).expect("write U-04c ConPTY keys");
        writer.flush().expect("flush U-04c ConPTY keys");
    }

    fn output_text(&self) -> String {
        let output = self.output.lock().expect("lock U-04c ConPTY output");
        assert!(!output.overflowed, "U-04c ConPTY output exceeded its cap");
        assert!(
            output.reader_error.is_none(),
            "U-04c ConPTY reader failed: {:?}",
            output.reader_error
        );
        String::from_utf8_lossy(&output.bytes).into_owned()
    }

    fn screen_text(&self) -> String {
        let output = self.output.lock().expect("lock U-04c ConPTY screen");
        assert!(!output.overflowed, "U-04c ConPTY output exceeded its cap");
        assert!(
            output.reader_error.is_none(),
            "U-04c ConPTY reader failed: {:?}",
            output.reader_error
        );
        output.screen.screen().contents()
    }

    async fn wait_for_checkpoint(&mut self, checkpoint: &str) {
        let deadline = Instant::now() + U04C_CONPTY_CHECKPOINT_TIMEOUT;
        loop {
            let raw_output = self.output_text();
            let cursor_queries = raw_output.matches("\u{1b}[6n").count();
            while self.cursor_queries_answered < cursor_queries {
                self.send_keys(b"\x1b[1;1R");
                self.cursor_queries_answered += 1;
            }
            let screen = self.screen_text();
            if screen.contains(checkpoint) {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("inspect U-04c ConPTY child") {
                panic!(
                    "U-04c ConPTY exited before checkpoint {checkpoint:?}: {status:?}; screen={screen}; raw_output={raw_output}"
                );
            }
            assert!(
                Instant::now() < deadline,
                "U-04c ConPTY missed checkpoint {checkpoint:?}; DSR={}/{}; screen={}; raw_tail={}",
                cursor_queries,
                self.cursor_queries_answered,
                screen,
                raw_output
                    .chars()
                    .rev()
                    .take(4_000)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>(),
            );
            sleep(Duration::from_millis(25)).await;
        }
    }

    async fn finish_successfully(&mut self) {
        self.send_keys(b"q");
        let deadline = Instant::now() + U04C_CONPTY_CHECKPOINT_TIMEOUT;
        let status = loop {
            if let Some(status) = self
                .child
                .try_wait()
                .expect("inspect completed U-04c ConPTY child")
            {
                break status;
            }
            if Instant::now() >= deadline {
                self.child
                    .kill()
                    .expect("kill timed-out U-04c ConPTY child");
                let reap_deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
                while self
                    .child
                    .try_wait()
                    .expect("reap killed U-04c ConPTY child")
                    .is_none()
                {
                    assert!(
                        Instant::now() < reap_deadline,
                        "U-04c ConPTY child did not reap after timeout"
                    );
                    sleep(Duration::from_millis(25)).await;
                }
                panic!("U-04c ConPTY did not exit after q before its deadline");
            }
            sleep(Duration::from_millis(25)).await;
        };
        assert!(status.success(), "U-04c ConPTY failed: {status:?}");
        self.writer.take();
        // Close the pseudoconsole while its reader still drains output. Keeping
        // the master alive can prevent EOF even after the TUI exits successfully.
        self.master.take();
        let reader_deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
        while self
            .reader
            .as_ref()
            .is_some_and(|reader| !reader.is_finished())
        {
            assert!(
                Instant::now() < reader_deadline,
                "U-04c ConPTY reader did not finish"
            );
            sleep(Duration::from_millis(25)).await;
        }
        if let Some(reader) = self.reader.take() {
            reader.join().expect("join U-04c ConPTY reader");
        }
    }
}

fn u04c_conpty_command(
    program: impl AsRef<std::ffi::OsStr>,
    arguments: &[String],
    instance: &str,
) -> PtyCommandBuilder {
    const INHERITED_ENVIRONMENT: [&str; 9] = [
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    ];
    let mut command = PtyCommandBuilder::new(program);
    command.env_clear();
    for name in INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("EGOPULSE_IPC_INSTANCE", instance);
    command.args(arguments);
    command
}

async fn assert_u04c_conpty_host_available(instance: &str) {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot for ConPTY canary");
    let cmd = PathBuf::from(system_root).join("System32").join("cmd.exe");
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 8,
            cols: 40,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open U-04c ConPTY canary");
    let command = u04c_conpty_command(
        cmd,
        &[
            "/d".to_owned(),
            "/c".to_owned(),
            "exit".to_owned(),
            "/b".to_owned(),
            "0".to_owned(),
        ],
        instance,
    );
    let mut reader = pair
        .master
        .try_clone_reader()
        .expect("clone U-04c ConPTY canary reader");
    let mut writer = pair
        .master
        .take_writer()
        .expect("take U-04c ConPTY canary writer");
    let canary_output = Arc::new(Mutex::new(Vec::new()));
    let reader_output = Arc::clone(&canary_output);
    let reader = thread::spawn(move || {
        let mut chunk = [0_u8; 1024];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(read) => reader_output
                    .lock()
                    .expect("lock U-04c ConPTY canary output")
                    .extend_from_slice(&chunk[..read]),
                Err(error) => return Err(error),
            }
        }
    });
    let mut child = pair
        .slave
        .spawn_command(command)
        .expect("spawn U-04c ConPTY cmd canary");
    drop(pair.slave);
    let master = pair.master;
    let deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
    let mut answered_cursor_query = false;
    let status = loop {
        if !answered_cursor_query
            && String::from_utf8_lossy(
                &canary_output
                    .lock()
                    .expect("read U-04c ConPTY canary checkpoint"),
            )
            .contains("\u{1b}[6n")
        {
            writer
                .write_all(b"\x1b[1;1R")
                .expect("answer U-04c ConPTY canary cursor query");
            writer
                .flush()
                .expect("flush U-04c ConPTY canary cursor answer");
            answered_cursor_query = true;
        }
        if let Some(status) = child.try_wait().expect("inspect U-04c ConPTY cmd canary") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill U-04c ConPTY cmd canary");
            let reap_deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
            while child
                .try_wait()
                .expect("reap U-04c ConPTY cmd canary")
                .is_none()
            {
                assert!(
                    Instant::now() < reap_deadline,
                    "U-04c ConPTY cmd canary did not reap"
                );
                sleep(Duration::from_millis(25)).await;
            }
            drop(writer);
            drop(master);
            let _ = reader.join();
            let output = canary_output
                .lock()
                .expect("read timed-out U-04c ConPTY canary output")
                .clone();
            panic!(
                "U-04c ConPTY cmd canary exceeded its deadline; output={}",
                String::from_utf8_lossy(&output)
            );
        }
        sleep(Duration::from_millis(25)).await;
    };
    drop(writer);
    drop(master);
    let read_result = reader.join().expect("join U-04c ConPTY canary reader");
    read_result.expect("read U-04c ConPTY canary output");
    let output = canary_output
        .lock()
        .expect("read U-04c ConPTY canary output")
        .clone();
    assert!(
        status.success(),
        "U-04c ConPTY cmd canary failed: {status:?}; output={}",
        String::from_utf8_lossy(&output)
    );
}

impl Drop for U04cConptySession {
    fn drop(&mut self) {
        self.writer.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let deadline = Instant::now() + R9A3_WITNESS_REAP_TIMEOUT;
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        self.master.take();
        if self
            .reader
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            && let Some(reader) = self.reader.take()
        {
            let _ = reader.join();
        }
    }
}

fn selected_u04c_task_id(screen: &str) -> Option<String> {
    let valid_identity_character = |character: char| {
        character.is_ascii_alphanumeric() || matches!(character, ':' | '-' | '_' | '.')
    };
    let visible_task_id = screen.split('>').skip(1).find_map(|selected| {
        let selected = selected.trim_start();
        let visible_task_id = selected.split_ascii_whitespace().next()?;
        (!visible_task_id.is_empty()
            && visible_task_id.starts_with("task")
            && visible_task_id.chars().all(valid_identity_character))
        .then_some(visible_task_id)
    })?;
    let governed_detail = screen.split_once("Execution / Recovery Facts")?.1;
    let full_task_id = governed_detail
        .split_once("Task task")?
        .1
        .chars()
        .take_while(|character| valid_identity_character(*character))
        .fold(String::from("task"), |mut task_id, character| {
            task_id.push(character);
            task_id
        });
    (full_task_id.starts_with(visible_task_id)
        && !visible_task_id.is_empty()
        && !full_task_id.is_empty())
    .then_some(full_task_id)
}

async fn stop_u04c_fixture(child: &mut Child, label: &str) {
    let status = shutdown_fixture_child(child, label).await;
    assert!(status.success(), "{label} failed: {status}");
    assert!(
        child
            .try_wait()
            .unwrap_or_else(|error| panic!("inspect reaped {label}: {error}"))
            .is_some(),
        "{label} must be reaped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u04c_real_cli_cancel_blocked_and_happy_have_exact_task_durability() {
    for (case, source_exists, action, expect_success) in [
        ("cancel", true, "--cancel", true),
        ("blocked", false, "--confirm", false),
        ("happy", true, "--confirm", true),
    ] {
        let root = std::env::temp_dir().join(format!("egopulse-u04c-{case}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create U-04c CLI fixture root");
        if source_exists {
            fs::write(root.join("context.md"), "U-04c safe governed input")
                .expect("write U-04c Context source");
        }
        let instance = format!("u04c-{case}-{}", Uuid::now_v7());
        let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
        wait_for_cli_status_with_child(&instance, &mut child).await;
        let before = u04c_durability(&root, None, None);
        let output = run_u04c_cli(
            &instance,
            &[
                "work",
                "start",
                "--intent",
                "start one governed U-04c task",
                "--scope",
                "scope:u04c",
                "--work-type",
                "governed_repository_change",
                "--context-ref",
                "context.md",
                "--no-memory",
                action,
                "--json",
            ],
        )
        .await;
        assert_eq!(
            output.status.success(),
            expect_success,
            "{case}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("U-04c CLI JSON envelope");
        let task_id = envelope["data"]["createdTaskId"].as_str();
        let after = u04c_durability(&root, None, task_id);
        if case == "happy" {
            let task = after.task_record.as_ref().expect("happy path durable Task");
            assert_eq!(task.task_id, task_id.expect("happy Task id"));
            assert_ne!(task.status, TaskStatus::Completed as i32);
            let context = u04c_assert_task_context_binding(&root, task);
            assert_eq!(
                context.snapshot_id,
                TaskSnapshot::decode(task.snapshot.as_slice())
                    .expect("decode happy Task")
                    .input_snapshot_id
            );
            assert_eq!(
                after
                    .task
                    .table_digests
                    .iter()
                    .find(|table| table.table_name == "tasks")
                    .expect("Task table digest")
                    .row_count,
                1
            );
        } else {
            assert_eq!(after.task, before.task, "{case} must write no Task tables");
            assert!(after.task_record.is_none());
            if case == "cancel" {
                assert_eq!(
                    after.context, before.context,
                    "editing cancellation must not write Context tables"
                );
                assert!(after.context_record.is_none());
            }
        }
        stop_u04c_fixture(&mut child, case).await;
        fs::remove_dir_all(&root).expect("remove U-04c CLI fixture root");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u04c_post_commit_unavailable_exact_replays_without_authority_growth() {
    for (case, mode) in [
        ("prepare", U04C_PREPARE_POST_COMMIT_MODE),
        ("confirm", U04C_CONFIRM_POST_COMMIT_MODE),
    ] {
        let root = std::env::temp_dir().join(format!("egopulse-u04c-{case}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create U-04c replay fixture root");
        fs::write(root.join("context.md"), "U-04c exact replay source")
            .expect("write U-04c replay Context source");
        let instance = format!("u04c-replay-{case}-{}", Uuid::now_v7());
        let mut child = spawn_fixture_with_mode(&root, &instance, mode).await;
        wait_for_cli_status_with_child(&instance, &mut child).await;
        let task_id = if case == "prepare" {
            let attachment = Arc::new(
                attach_client_operation(
                    &instance,
                    ClientSurface::Tui,
                    format!("u04c-prepare-replay-{}", Uuid::now_v7()),
                )
                .await
                .expect("attach U-04c prepare recovery client"),
            );
            let mut controller = WorkStartController::new(attachment);
            {
                let draft = controller.model_mut().draft_mut();
                draft.intent = "recover the exact U-04c request".to_owned();
                draft.work_type = "governed_repository_change".to_owned();
                draft.target_scope_ref = "scope:u04c-replay".to_owned();
                draft.context_references = "context.md".to_owned();
                draft.memory_enabled = false;
            }
            controller.prepare().await.expect("start U-04c prepare");
            timeout(Duration::from_secs(8), async {
                while controller.model().stage() == WorkStartStage::Preparing {
                    controller.pump().await.expect("pump unknown preparation");
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("unknown preparation deadline");
            assert_eq!(
                controller.model().stage(),
                WorkStartStage::PreparationOutcomeUnknown
            );
            controller
                .replay_preparation()
                .await
                .expect("start exact preparation replay");
            timeout(Duration::from_secs(8), async {
                while controller.model().stage() == WorkStartStage::Preparing {
                    controller.pump().await.expect("pump preparation replay");
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("preparation replay deadline");
            assert_eq!(controller.model().stage(), WorkStartStage::PreviewReady);
            controller
                .cancel_preview()
                .await
                .expect("discard prepared preview");
            None
        } else {
            let output = run_u04c_cli(
                &instance,
                &[
                    "work",
                    "start",
                    "--intent",
                    "recover the exact U-04c request",
                    "--scope",
                    "scope:u04c-replay",
                    "--work-type",
                    "governed_repository_change",
                    "--context-ref",
                    "context.md",
                    "--no-memory",
                    "--confirm",
                    "--json",
                ],
            )
            .await;
            assert!(
                output.status.success(),
                "{case}: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let envelope: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("U-04c replay CLI JSON");
            Some(
                envelope["data"]["createdTaskId"]
                    .as_str()
                    .expect("U-04c replay Task id")
                    .to_owned(),
            )
        };
        let witness: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join(U04C_REPLAY_WITNESS_FILE)).expect("read U-04c replay witness"),
        )
        .expect("decode U-04c replay witness");
        assert_eq!(witness["operation"], case);
        assert_eq!(witness["calls"], 2);
        assert_eq!(witness["authority_tables_unchanged"], true);
        assert_eq!(
            witness["process_id"],
            u64::from(child.id().expect("daemon pid"))
        );
        assert_eq!(witness["principal_id"], "os-user:c5-fixture");
        assert_eq!(witness["request_sha256"].as_str().map(str::len), Some(64));
        if let Some(task_id) = task_id.as_deref() {
            assert!(
                u04c_durability(&root, None, Some(task_id))
                    .task_record
                    .is_some()
            );
        } else {
            assert_eq!(
                u04c_durability(&root, None, None)
                    .task
                    .table_digests
                    .iter()
                    .find(|table| table.table_name == "tasks")
                    .expect("Task table digest")
                    .row_count,
                0
            );
        }
        stop_u04c_fixture(&mut child, case).await;
        fs::remove_dir_all(&root).expect("remove U-04c replay fixture root");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u04c_production_tui_controllers_share_attachment_and_select_exact_confirmed_task() {
    let root = std::env::temp_dir().join(format!("egopulse-u04c-controller-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-04c controller fixture root");
    fs::write(root.join("context.md"), "U-04c controller Context")
        .expect("write U-04c controller Context source");
    let instance = format!("u04c-controller-{}", Uuid::now_v7());
    let mut child = spawn_fixture_with_mode(&root, &instance, "allow").await;
    wait_for_cli_status_with_child(&instance, &mut child).await;

    let attachment = Arc::new(
        attach_client_operation(
            &instance,
            ClientSurface::Tui,
            format!("u04c-controller-{}", Uuid::now_v7()),
        )
        .await
        .expect("attach U-04c production TUI client"),
    );
    let work_attachment = Arc::clone(&attachment);
    let watch_attachment = Arc::clone(&attachment);
    assert!(Arc::ptr_eq(&work_attachment, &watch_attachment));
    let mut work = WorkStartController::new(work_attachment);
    let mut watch = TaskWatchController::new(watch_attachment);
    watch
        .start()
        .await
        .expect("open pre-confirm Task Watch baseline");
    {
        let draft = work.model_mut().draft_mut();
        draft.intent = "start from the U-04c TUI controller".to_owned();
        draft.work_type = "governed_repository_change".to_owned();
        draft.target_scope_ref = "scope:u04c-controller".to_owned();
        draft.context_references = "context.md".to_owned();
        draft.memory_enabled = false;
    }
    work.prepare().await.expect("start U-04c preparation");
    timeout(Duration::from_secs(8), async {
        while work.model().stage() == WorkStartStage::Preparing {
            work.pump().await.expect("pump U-04c preparation");
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-04c preparation deadline");
    assert_eq!(work.model().stage(), WorkStartStage::PreviewReady);
    work.confirm().await.expect("start U-04c confirmation");
    let task_id = timeout(Duration::from_secs(8), async {
        loop {
            work.pump().await.expect("pump U-04c confirmation");
            if let Some(task_id) = work.take_confirmed_task_id() {
                break task_id;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("U-04c confirmation deadline");

    assert!(!watch.select_task(&task_id));
    watch.clear_selection();
    assert_eq!(
        watch
            .model()
            .and_then(|model| model.selected_task_id.as_deref()),
        None,
        "projection lag must not select an unrelated Task"
    );
    timeout(Duration::from_secs(8), async {
        loop {
            watch.pump().expect("pump exact U-04c Task projection");
            if watch.select_task(&task_id) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("exact U-04c Task projection deadline");
    let selected = watch
        .model()
        .and_then(|model| model.selected_task_id.as_deref())
        .expect("exact U-04c selected Task");
    assert_eq!(selected, task_id);
    let projected = watch
        .model()
        .expect("U-04c Task Watch model")
        .tasks
        .iter()
        .find(|task| task.task_id == task_id)
        .expect("U-04c confirmed Task projection");
    assert_ne!(projected.status, TaskStatus::Completed);
    let durable = u04c_durability(&root, None, Some(&task_id));
    let task_record = durable.task_record.expect("U-04c durable Task");
    assert_eq!(task_record.task_id, task_id);
    assert_eq!(task_record.status, projected.status as i32);

    watch.stop().await;
    stop_u04c_fixture(&mut child, "U-04c controller daemon").await;
    drop(work);
    drop(watch);
    drop(attachment);
    fs::remove_dir_all(&root).expect("remove U-04c controller fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn u04c_real_windows_conpty_drives_normal_tui_from_dashboard_to_exact_task_watch() {
    const DAEMON_ONLY_CANARY: &str = "U04C_DAEMON_ONLY_CONTEXT_CANARY_NEVER_RENDER";
    let root = std::env::temp_dir().join(format!("egopulse-u04c-conpty-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create U-04c ConPTY fixture root");
    fs::write(root.join("context.md"), DAEMON_ONLY_CANARY)
        .expect("write U-04c ConPTY Context source");
    let instance = format!("u04c-conpty-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, "allow").await;
    let daemon_pid = daemon.id().expect("U-04c ConPTY daemon PID");
    wait_for_cli_status_with_child(&instance, &mut daemon).await;
    let before = u04c_durability(&root, None, None);

    assert_u04c_conpty_host_available(&instance).await;
    let mut terminal = U04cConptySession::spawn(&instance);
    assert_ne!(terminal.process_id(), std::process::id());
    assert_ne!(terminal.process_id(), daemon_pid);
    terminal.wait_for_checkpoint("n new work").await;
    terminal.send_keys(b"n");
    terminal.wait_for_checkpoint("Stage: Editing").await;
    terminal.send_keys(
        b"start one governed U-04c ConPTY task\tgoverned_repository_change\tscope:u04c-conpty\t\tcontext.md\x1bOQ\r",
    );
    terminal
        .wait_for_checkpoint("Review the governed preview; Enter")
        .await;
    terminal.send_keys(b"\r");
    terminal.wait_for_checkpoint("Task Watch").await;
    let task_id = timeout(Duration::from_secs(8), async {
        loop {
            let task_watch_screen = terminal.screen_text();
            if let Some(task_id) = selected_u04c_task_id(&task_watch_screen) {
                break task_id;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Task Watch selected Task identity deadline");
    let rendered = terminal.output_text();
    let task_watch_screen = terminal.screen_text();
    assert!(
        task_watch_screen.contains("Task Watch"),
        "the current ConPTY screen must be the post-confirmation Task Watch"
    );
    assert!(
        !rendered.contains(DAEMON_ONLY_CANARY),
        "the TUI must not render daemon-only Context contents"
    );
    assert!(!rendered.contains("TASK_STATUS_COMPLETED"));
    terminal.finish_successfully().await;

    let after = u04c_durability(&root, None, Some(&task_id));
    let task = after
        .task_record
        .as_ref()
        .expect("U-04c ConPTY durable Task");
    assert_eq!(task.task_id, task_id);
    assert_ne!(task.status, TaskStatus::Completed as i32);
    let context = u04c_assert_task_context_binding(&root, task);
    assert_eq!(
        context.snapshot_id,
        TaskSnapshot::decode(task.snapshot.as_slice())
            .expect("decode ConPTY Task")
            .input_snapshot_id
    );
    assert_eq!(
        after
            .task
            .table_digests
            .iter()
            .find(|table| table.table_name == "tasks")
            .expect("U-04c ConPTY tasks table")
            .row_count,
        before
            .task
            .table_digests
            .iter()
            .find(|table| table.table_name == "tasks")
            .expect("U-04c pre-ConPTY tasks table")
            .row_count
            + 1
    );

    drop(terminal);
    stop_u04c_fixture(&mut daemon, "U-04c ConPTY daemon").await;
    fs::remove_dir_all(&root).expect("remove U-04c ConPTY fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r9c_real_daemon_cli_and_tui_share_one_governed_harness_content_stream() {
    let root = std::env::temp_dir().join(format!("egopulse-r9c-c5-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create R-9C C5 fixture root");
    fs::write(
        root.join("context.md"),
        "R-9C reviewed input that never becomes a client content source",
    )
    .expect("write R-9C Context source");
    let instance = format!("r9c-c5-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, R9C_CONTENT_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;

    let prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "stream one governed Codex assistant message",
            "--scope",
            "scope:r9c-c5",
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--no-memory",
            "--idempotency-key",
            "r9c-c5-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        prepare.status.success(),
        "R-9C prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&prepare.stdout),
        String::from_utf8_lossy(&prepare.stderr)
    );
    let prepared: serde_json::Value =
        serde_json::from_slice(&prepare.stdout).expect("R-9C prepare JSON");
    let snapshot_id = prepared["data"]["snapshotId"]
        .as_str()
        .expect("R-9C snapshot id")
        .to_owned();
    let confirmation_binding = prepared["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("R-9C confirmation binding")
        .to_owned();

    let confirm = run_cli(
        &instance,
        &[
            "work",
            "confirm",
            snapshot_id.as_str(),
            "--confirmation-binding-sha256",
            confirmation_binding.as_str(),
            "--idempotency-key",
            "r9c-c5-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "R-9C confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirmed: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("R-9C confirm JSON");
    let task_id = confirmed["data"]["taskId"]
        .as_str()
        .expect("R-9C Task identity")
        .to_owned();
    let routed_ids = RoutedWorkIds::from_preview(&prepared, &task_id);
    assert_eq!(
        confirmed["data"]["status"],
        TaskStatus::Active.as_str_name()
    );

    let driver_record_path = root.join(R8A_DRIVER_RECORD);
    timeout(Duration::from_secs(8), async {
        loop {
            if driver_record_path.is_file() {
                break;
            }
            if let Some(status) = daemon
                .try_wait()
                .expect("inspect R-9C daemon before dispatch")
            {
                panic!("R-9C daemon exited before dispatch: {status}");
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("R-9C governed dispatch deadline");

    let mut content_command = Command::new(cli_executable());
    content_command
        .env("EGOPULSE_IPC_INSTANCE", &instance)
        .args([
            "content",
            "watch",
            task_id.as_str(),
            "--frames",
            "1",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut content_cli = content_command
        .spawn()
        .expect("spawn real R-9C content CLI");
    let stdout = content_cli.stdout.take().expect("capture R-9C CLI stdout");
    let stderr = content_cli.stderr.take().expect("capture R-9C CLI stderr");
    let mut stdout = BufReader::new(stdout);
    let mut baseline_line = String::new();
    timeout(Duration::from_secs(8), stdout.read_line(&mut baseline_line))
        .await
        .expect("R-9C CLI baseline deadline")
        .expect("read R-9C CLI baseline");
    let baseline: serde_json::Value =
        serde_json::from_str(baseline_line.trim()).expect("R-9C CLI baseline JSON");
    assert_eq!(baseline["event"], "baseline_complete");
    assert_eq!(baseline["recordCount"], 0);
    assert!(
        content_cli
            .try_wait()
            .expect("inspect waiting R-9C CLI")
            .is_none(),
        "content CLI must be attached and waiting before native content is released"
    );

    let authority_before = read_r9b_governed_state_authorities(&root)
        .expect("read R-9C Authority state before content release");
    fs::write(root.join(R9C_CONTENT_RELEASE_FILE), b"release")
        .expect("release R-9C native content events");

    let stdout_reader = tokio::spawn(async move {
        let mut tail = Vec::new();
        stdout.read_to_end(&mut tail).await.map(|_| tail)
    });
    let stderr_reader = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let cli_status = timeout(Duration::from_secs(10), content_cli.wait())
        .await
        .expect("R-9C content CLI completion deadline")
        .expect("wait for R-9C content CLI");
    let mut cli_stdout = baseline_line.into_bytes();
    cli_stdout.extend(
        stdout_reader
            .await
            .expect("join R-9C CLI stdout reader")
            .expect("read R-9C CLI stdout tail"),
    );
    let cli_stderr = stderr_reader
        .await
        .expect("join R-9C CLI stderr reader")
        .expect("read R-9C CLI stderr");
    assert!(
        cli_status.success(),
        "R-9C content CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_stdout),
        String::from_utf8_lossy(&cli_stderr)
    );
    let cli_text = String::from_utf8(cli_stdout).expect("R-9C CLI stdout UTF-8");
    assert!(!cli_text.contains(R9C_RAW_ONLY_CANARY));
    assert!(!String::from_utf8_lossy(&cli_stderr).contains(R9C_RAW_ONLY_CANARY));
    let records = cli_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("R-9C CLI NDJSON"))
        .filter(|value| value["record"]["payload"]["kind"] == "assistant_text")
        .collect::<Vec<_>>();
    let streamed = records
        .first()
        .expect("R-9C CLI must receive a live safe assistant record");
    assert_eq!(streamed["event"], "record");
    assert_eq!(streamed["record"]["taskId"], task_id);
    assert_eq!(streamed["record"]["attemptId"], routed_ids.attempt_id);
    assert_eq!(streamed["record"]["source"]["providerFamily"], "openai");
    assert_eq!(streamed["record"]["source"]["model"], "fixture/model");
    assert_eq!(streamed["record"]["source"]["collaborationRole"], "primary");
    assert!(
        streamed["record"]["payload"]["safeText"]
            .as_str()
            .is_some_and(|text| text.contains(R9C_VISIBLE_PREFIX))
    );
    let safe_message_id = streamed["record"]["payload"]["safeMessageId"]
        .as_str()
        .expect("R-9C CLI safe message identity")
        .to_owned();
    assert!(safe_message_id.starts_with("hcm_"));

    assert_u04c_conpty_host_available(&instance).await;
    let mut terminal = U04cConptySession::spawn(&instance);
    terminal.wait_for_checkpoint("w task watch").await;
    terminal.send_keys(b"w");
    terminal.wait_for_checkpoint("Task Watch").await;
    terminal.wait_for_checkpoint(&task_id).await;
    terminal.send_keys(b"h");
    terminal.wait_for_checkpoint("Harness content - live").await;
    let full_text = format!("{R9C_VISIBLE_PREFIX}{R9C_VISIBLE_SUFFIX}");
    terminal.wait_for_checkpoint(&full_text).await;
    let tui_screen = terminal.screen_text();
    let compact_screen = tui_screen
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(
        tui_screen.contains("openai / fixture/model"),
        "{tui_screen}"
    );
    assert!(
        tui_screen.contains("primary / attempt:work:"),
        "{tui_screen}"
    );
    assert!(
        tui_screen.contains("[finalized | revision 3"),
        "{tui_screen}"
    );
    assert!(
        compact_screen.contains(&safe_message_id),
        "the real TUI must display the same safe message identity as the CLI: {tui_screen}"
    );
    assert!(!terminal.output_text().contains(R9C_RAW_ONLY_CANARY));
    terminal.finish_successfully().await;

    let task = run_cli(&instance, &["task", "get", task_id.as_str(), "--json"]).await;
    assert!(task.status.success());
    let task: serde_json::Value =
        serde_json::from_slice(&task.stdout).expect("R-9C Task projection JSON");
    assert_eq!(task["data"]["status"], TaskStatus::Active.as_str_name());
    let authority_after = read_r9b_governed_state_authorities(&root)
        .expect("read R-9C Authority state after client observations");
    assert_eq!(authority_after, authority_before);

    stop_u04c_fixture(&mut daemon, "R-9C content daemon").await;
    let adapter = AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.join("r8a-adapter.db"),
        adapter_id: CODEX_ADAPTER_ID.to_owned(),
        store_epoch: "r8a-adapter-epoch".to_owned(),
        key: AdapterEdgeKey::new([0x32; 32]),
    })
    .expect("reopen R-9C Adapter Edge");
    let inspection = adapter.inspect().expect("inspect R-9C Adapter Edge");
    assert_eq!(inspection.dispatch_count, 1);
    assert_eq!(inspection.observation_count, 4);
    assert_eq!(inspection.content_candidate_count, 3);
    assert_eq!(inspection.pending_content_candidate_count, 0);
    assert_eq!(inspection.quarantined_content_candidate_count, 0);
    assert_eq!(inspection.safe_content_ledger_count, 3);
    assert_eq!(inspection.pending_content_projection_count, 0);
    assert!(adapter.integrity_is_ok().expect("R-9C Adapter integrity"));
    drop(adapter);
    fs::remove_dir_all(&root).expect("remove R-9C C5 fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m13_real_daemon_cli_tui_dispatch_and_restart_preserve_one_memory_pair() {
    const MEMORY_TEXT: &str = "EgoPulse governed Memory is Founder accepted.";
    const INTENT: &str = "Use EgoPulse governed Memory for this repository change";
    const SCOPE: &str = "scope:founder";

    let root = std::env::temp_dir().join(format!("egopulse-m13-c5-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create M-13 C5 fixture root");
    fs::write(
        root.join("context.md"),
        "M-13 reviewed project context remains separate from governed Memory.",
    )
    .expect("write M-13 project source");
    let instance = format!("m13-c5-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, M13_MEMORY_DISPATCH_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;

    let cli_prepare = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            INTENT,
            "--scope",
            SCOPE,
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "m13-cli-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        cli_prepare.status.success(),
        "M-13 CLI prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_prepare.stdout),
        String::from_utf8_lossy(&cli_prepare.stderr)
    );
    let cli_preview: serde_json::Value =
        serde_json::from_slice(&cli_prepare.stdout).expect("M-13 CLI preview JSON");
    assert_eq!(cli_preview["data"]["gateReady"], true);
    assert_eq!(cli_preview["data"]["readyForFounderConfirmation"], true);
    assert!(
        cli_preview["data"]["includedSources"]
            .as_array()
            .is_some_and(|sources| sources.iter().any(|source| {
                source["authority"] == "memory" && source["sourceRef"] == "memory-c5-accepted"
            }))
    );
    let snapshot_id = cli_preview["data"]["snapshotId"]
        .as_str()
        .expect("M-13 snapshot id")
        .to_owned();
    let compiled_digest = cli_preview["data"]["compiledContextSha256"]
        .as_str()
        .expect("M-13 compiled Context digest")
        .to_owned();
    let confirmation_binding = cli_preview["data"]["confirmationBindingSha256"]
        .as_str()
        .expect("M-13 confirmation binding")
        .to_owned();
    let memory_revision = cli_preview["data"]["memoryAuthorityRevision"]
        .as_u64()
        .expect("M-13 Memory Authority revision");
    let memory_pack = cli_preview["data"]["memoryPackSnapshotSha256"]
        .as_str()
        .expect("M-13 Memory pack digest")
        .to_owned();
    assert_eq!(snapshot_id, format!("ctx:{compiled_digest}"));
    assert_eq!(memory_pack.len(), 64);

    let tui_prepare = run_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-prepare",
            "--intent",
            INTENT,
            "--scope",
            SCOPE,
            "--work-type",
            "governed_repository_change",
            "--context-ref",
            "context.md",
            "--idempotency-key",
            "m13-cli-prepare",
            "--json",
        ],
    )
    .await;
    assert!(
        tui_prepare.status.success(),
        "M-13 TUI prepare failed: stdout={} stderr={}",
        String::from_utf8_lossy(&tui_prepare.stdout),
        String::from_utf8_lossy(&tui_prepare.stderr)
    );
    let tui_preview: serde_json::Value =
        serde_json::from_slice(&tui_prepare.stdout).expect("M-13 TUI preview JSON");
    assert_eq!(tui_preview["data"]["snapshotId"], snapshot_id);
    assert_eq!(
        tui_preview["data"]["memoryAuthorityRevision"],
        memory_revision
    );
    assert_eq!(tui_preview["data"]["memoryPackSnapshotSha256"], memory_pack);
    assert_eq!(
        tui_preview["data"]["includedSources"],
        cli_preview["data"]["includedSources"]
    );

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
            "m13-tui-confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        confirm.status.success(),
        "M-13 TUI confirm failed: stdout={} stderr={}",
        String::from_utf8_lossy(&confirm.stdout),
        String::from_utf8_lossy(&confirm.stderr)
    );
    let confirmed: serde_json::Value =
        serde_json::from_slice(&confirm.stdout).expect("M-13 confirmation JSON");
    assert_eq!(
        confirmed["data"]["status"],
        TaskStatus::Active.as_str_name()
    );
    let task_id = confirmed["data"]["taskId"]
        .as_str()
        .expect("M-13 Task identity");
    let routed_ids = RoutedWorkIds::from_preview(&cli_preview, task_id);

    let record_path = root.join(R8A_DRIVER_RECORD);
    timeout(Duration::from_secs(10), async {
        loop {
            if record_path.is_file() {
                break;
            }
            if let Some(status) = daemon
                .try_wait()
                .expect("inspect M-13 daemon before dispatch")
            {
                panic!("M-13 daemon exited before dispatch evidence: {status}");
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("M-13 governed dispatch deadline");
    let first_driver_bytes = fs::read(&record_path).expect("read M-13 driver evidence");
    let driver: serde_json::Value =
        serde_json::from_slice(&first_driver_bytes).expect("decode M-13 driver evidence");
    assert_eq!(driver["dispatchCount"], 1);
    assert_eq!(driver["model"], "fixture/model");
    assert!(
        driver["canonicalInputBundleUtf8"]
            .as_str()
            .is_some_and(|value| value.contains(MEMORY_TEXT))
    );
    assert!(driver["prompt"].as_str().is_some_and(|value| {
        value.contains("GOVERNED MEMORY REFERENCE DATA (UNTRUSTED)") && value.contains(MEMORY_TEXT)
    }));

    // The driver's record is written before the Adapter observation is
    // durably appended and consumed. Wait for that boundary before stopping
    // the daemon; a successful native dispatch alone is not the receipt.
    timeout(Duration::from_secs(10), async {
        loop {
            let adapter = read_r8b2c_adapter_store(
                &root.join("r8a-adapter.db"),
                &[0x32; 32],
                &routed_ids.dispatch_id,
            )
            .expect("read M-13 observation before stopping daemon");
            if adapter.observation_count == 1 && adapter.pending_observation_count == 0 {
                break;
            }
            if let Some(status) = daemon
                .try_wait()
                .expect("inspect M-13 daemon before durable observation")
            {
                panic!("M-13 daemon exited before durable observation: {status}");
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("M-13 durable observation deadline");
    stop_u04c_fixture(&mut daemon, "M-13 first daemon").await;
    let first_pair = read_m13_memory_dispatch_pair(
        &root.join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        &routed_ids.dispatch_id,
    )
    .expect("read first M-13 Context/Memory pair");
    assert_eq!(first_pair.content_digest_sha256, compiled_digest);
    assert_eq!(first_pair.target_scope_ref, SCOPE);
    assert_eq!(first_pair.memory_scope_ref, SCOPE);
    assert_eq!(first_pair.memory_authority_revision, memory_revision);
    assert_eq!(first_pair.memory_pack_snapshot_sha256, memory_pack);
    assert_eq!(first_pair.consumer_principal_id, "codex_app_server");
    assert_eq!(first_pair.model_ref, "fixture/model");
    assert_eq!(first_pair.attempt_id, routed_ids.attempt_id);
    assert_eq!(first_pair.dispatch_id, routed_ids.dispatch_id);
    let first_adapter = read_r8b2c_adapter_store(
        &root.join("r8a-adapter.db"),
        &[0x32; 32],
        &routed_ids.dispatch_id,
    )
    .expect("read first M-13 Adapter evidence");
    assert_eq!(first_adapter.dispatch_count, 1);
    assert_eq!(first_adapter.delivery_unknown_count, 0);
    assert_eq!(first_adapter.observation_count, 1);
    assert_eq!(first_adapter.pending_observation_count, 0);

    let mut restarted = spawn_fixture_with_mode(&root, &instance, M13_MEMORY_DISPATCH_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;
    sleep(Duration::from_millis(500)).await;
    assert!(
        restarted
            .try_wait()
            .expect("inspect restarted M-13 daemon")
            .is_none()
    );
    stop_u04c_fixture(&mut restarted, "M-13 restarted daemon").await;

    let second_pair = read_m13_memory_dispatch_pair(
        &root.join("context-authority.db"),
        &[0x15; 32],
        "c5-context-epoch",
        &snapshot_id,
        &routed_ids.dispatch_id,
    )
    .expect("read restarted M-13 Context/Memory pair");
    let second_adapter = read_r8b2c_adapter_store(
        &root.join("r8a-adapter.db"),
        &[0x32; 32],
        &routed_ids.dispatch_id,
    )
    .expect("read restarted M-13 Adapter evidence");
    assert_eq!(second_pair, first_pair);
    assert_eq!(second_adapter.dispatch_count, first_adapter.dispatch_count);
    assert_eq!(
        second_adapter.delivery_unknown_count,
        first_adapter.delivery_unknown_count
    );
    assert_eq!(
        second_adapter.observation_count,
        first_adapter.observation_count + 1
    );
    assert_eq!(
        second_adapter.pending_observation_count,
        first_adapter.pending_observation_count + 1
    );
    assert_eq!(second_adapter.dispatch_state, first_adapter.dispatch_state);
    assert_eq!(second_adapter.attempt_id, first_adapter.attempt_id);
    assert_eq!(second_adapter.fencing_token, first_adapter.fencing_token);
    assert_eq!(
        second_adapter.dispatch_fingerprint,
        first_adapter.dispatch_fingerprint
    );
    assert_eq!(
        second_adapter.envelope_digest_sha256,
        first_adapter.envelope_digest_sha256
    );
    assert_eq!(second_adapter.envelope, first_adapter.envelope);
    assert_eq!(second_adapter.receipt, first_adapter.receipt);
    let first_ack = first_adapter
        .observations
        .iter()
        .find(|row| row.native_key == "fake-ack")
        .expect("read first M-13 native ACK");
    let restarted_ack = second_adapter
        .observations
        .iter()
        .find(|row| row.native_key == "fake-ack")
        .expect("restart must retain the original M-13 native ACK");
    assert_eq!(restarted_ack.observation_id, first_ack.observation_id);
    assert_eq!(restarted_ack.dispatch_id, first_ack.dispatch_id);
    assert_eq!(
        restarted_ack.native_event_digest_sha256,
        first_ack.native_event_digest_sha256
    );
    assert_eq!(restarted_ack.raw_evidence_ref, first_ack.raw_evidence_ref);
    assert_eq!(restarted_ack.ingestion_state, first_ack.ingestion_state);
    assert_eq!(restarted_ack.observation, first_ack.observation);
    assert_eq!(restarted_ack.raw_event, first_ack.raw_event);
    let reconciliation_key = format!(
        "reconciliation:adapter-reconciliation:{}",
        routed_ids.dispatch_id
    );
    let reconciliation = second_adapter
        .observations
        .iter()
        .find(|row| row.native_key == reconciliation_key)
        .expect("M-13 restart must retain its nonresident reconciliation fact");
    assert_eq!(reconciliation.dispatch_id, routed_ids.dispatch_id);
    assert_eq!(reconciliation.ingestion_state, "pending");
    assert!(!reconciliation.raw_event.is_empty());
    let reconciliation_observation =
        HarnessObservation::decode(reconciliation.observation.as_slice())
            .expect("decode M-13 nonresident reconciliation observation");
    assert!(matches!(
        reconciliation_observation.payload,
        Some(harness_observation::Payload::Diagnostic(ref diagnostic))
            if diagnostic.safe_diagnostic_code
                == "ADAPTER_RECONCILIATION_TERMINAL_OBSERVATION_RECOVERED"
    ));
    assert_eq!(
        fs::read(&record_path).expect("read stable M-13 driver evidence"),
        first_driver_bytes,
        "restart recovery must not call the native driver again"
    );

    fs::remove_dir_all(&root).expect("remove M-13 C5 fixture root");
}

fn phase_one_seed_restart_tasks(root: &Path) -> (TaskSnapshot, TaskSnapshot) {
    let verdict_handle = Arc::new(Mutex::new(None));
    let transition_guard =
        ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(&verdict_handle));
    let mut authority = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        AllowTaskReferences,
        transition_guard,
    )
    .expect("open isolated phase-one Task Authority");
    let founder = u03c_task_principal(TaskPrincipalKind::Founder, "founder:phase-one-restart");
    let collaboration = u03c_task_principal(
        TaskPrincipalKind::CollaborationControl,
        "collaboration-control:phase-one-restart",
    );
    let mut seed = |label: &str| {
        let mut created = u03c_execute_task(
            &mut authority,
            TaskCommand {
                command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                    meta: Some(CommandMetadata {
                        command_id: format!("phase-one-create-{label}"),
                        idempotency_key: format!("phase-one-create-{label}"),
                        idempotency_scope: "phase-one-restart".to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(prost_types::Timestamp {
                            seconds: 1_788_633_600,
                            nanos: 0,
                        }),
                        correlation_id: format!("phase-one-{label}"),
                        causation_id: None,
                    }),
                    work_type: "governed_repository_change".to_owned(),
                    input_snapshot_id: format!("input-phase-one-{label}"),
                    target_scope_ref: "scope:phase-one-restart".to_owned(),
                    acceptance_contract_ref: Some(r8a_reference("phase-one-acceptance")),
                    budget_profile_ref: Some(r8a_reference("phase-one-budget")),
                    work_capability_route: None,
                })),
            },
            &founder,
        );
        created = u03c_execute_task(
            &mut authority,
            TaskCommand {
                command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                    meta: Some(CommandMetadata {
                        command_id: format!("phase-one-activate-{label}"),
                        idempotency_key: format!("phase-one-activate-{label}"),
                        idempotency_scope: "phase-one-restart".to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(prost_types::Timestamp {
                            seconds: 1_788_633_601,
                            nanos: 0,
                        }),
                        correlation_id: format!("phase-one-{label}"),
                        causation_id: None,
                    }),
                    task_id: created.task_id.clone(),
                    expected_revision: created.revision,
                    work_revision: created.work_revision,
                    run_id: format!("run:phase-one:{label}"),
                })),
            },
            &collaboration,
        );
        created
    };
    let active = seed("active");
    let cancellation_active = seed("cancellation-pending");
    let cancellation_pending = u03c_execute_task(
        &mut authority,
        TaskCommand {
            command: Some(task_command::Command::RequestTaskCancellation(
                RequestTaskCancellationCommand {
                    meta: Some(CommandMetadata {
                        command_id: "phase-one-cancel-pending".to_owned(),
                        idempotency_key: "phase-one-cancel-pending".to_owned(),
                        idempotency_scope: "phase-one-restart".to_owned(),
                        request_digest_sha256: String::new(),
                        issued_at: Some(prost_types::Timestamp {
                            seconds: 1_788_633_602,
                            nanos: 0,
                        }),
                        correlation_id: "phase-one-cancellation-pending".to_owned(),
                        causation_id: None,
                    }),
                    task_id: cancellation_active.task_id.clone(),
                    expected_revision: cancellation_active.revision,
                    reason_code: "restart-read-fixture".to_owned(),
                },
            )),
        },
        &founder,
    );
    assert_eq!(active.status, TaskStatus::Active as i32);
    assert_eq!(
        cancellation_pending.status,
        TaskStatus::CancellationPending as i32
    );
    (active, cancellation_pending)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_one_two_tasks_exact_replay_return_and_restart_remain_isolated() {
    let root = std::env::temp_dir().join(format!("egopulse-phase-one-multi-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create phase-one multi-task fixture root");
    let instance = format!("phase-one-multi-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, PHASE_ONE_MULTI_TASK_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;

    let first = prepare_and_confirm_r8b2c_work(&root, &instance, "phase-one-first").await;
    // Wait for the driver's return to commit before comparing replay snapshots:
    // Active can legitimately advance while the replay CLI process starts.
    wait_for_r8b2c_task_status(
        &instance,
        &first.task_id,
        TaskStatus::VerificationPending,
        &mut daemon,
    )
    .await;
    let first_task_before_replay = read_r8b2c_task_oracle(&root, &first.task_id);
    let replay = run_tui(
        &instance,
        &[
            "--instance",
            &instance,
            "work-confirm",
            &first.snapshot_id,
            "--confirmation-binding-sha256",
            &first.confirmation_binding,
            "--idempotency-key",
            &first.confirm_key,
            "--json",
        ],
    )
    .await;
    assert!(
        replay.status.success(),
        "phase-one exact replay failed: stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay: serde_json::Value =
        serde_json::from_slice(&replay.stdout).expect("decode phase-one replay");
    assert_eq!(replay["data"]["taskId"], first.task_id);
    assert_eq!(replay["data"]["replayed"], true);
    assert_eq!(
        read_r8b2c_task_oracle(&root, &first.task_id),
        first_task_before_replay
    );

    let second = prepare_and_confirm_r8b2c_work(&root, &instance, "phase-one-second").await;
    assert_ne!(first.task_id, second.task_id);
    assert_ne!(first.routed_ids.run_id, second.routed_ids.run_id);
    assert_ne!(first.routed_ids.step_id, second.routed_ids.step_id);
    assert_ne!(first.routed_ids.attempt_id, second.routed_ids.attempt_id);
    assert_ne!(first.routed_ids.dispatch_id, second.routed_ids.dispatch_id);

    timeout(Duration::from_secs(15), async {
        loop {
            let records = fs::read(root.join(PHASE_ONE_DRIVER_LEDGER))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Vec<PhaseOneDriverRecord>>(&bytes).ok());
            let returned = [&first, &second].iter().all(|work| {
                read_r8b2c_collaboration_store(
                    &root.join("r8a-collaboration.db"),
                    &[0x31; 32],
                    &work.routed_ids.run_id,
                    &work.routed_ids.step_id,
                    &work.routed_ids.attempt_id,
                )
                .ok()
                .is_some_and(|stored| stored.attempt_status == AttemptStatus::Returned as i32)
            });
            if records.as_ref().is_some_and(|records| records.len() == 2) && returned {
                break;
            }
            if let Some(status) = daemon
                .try_wait()
                .expect("inspect phase-one multi-task daemon")
            {
                panic!("phase-one multi-task daemon exited before return: {status}");
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("phase-one two-task governed return deadline");

    let ledger_before = fs::read(root.join(PHASE_ONE_DRIVER_LEDGER))
        .expect("read phase-one driver ledger before restart");
    let records: Vec<PhaseOneDriverRecord> =
        serde_json::from_slice(&ledger_before).expect("decode phase-one driver ledger");
    assert_eq!(records.len(), 2);
    for work in [&first, &second] {
        let record = records
            .iter()
            .find(|record| record.dispatch_id == work.routed_ids.dispatch_id)
            .expect("one driver record for each phase-one task");
        assert_eq!(record.run_id, work.routed_ids.run_id);
        assert_eq!(record.step_id, work.routed_ids.step_id);
        assert_eq!(record.attempt_id, work.routed_ids.attempt_id);
    }
    let first_collaboration = read_r8b2c_collaboration_oracle(&root, &first.routed_ids);
    let second_collaboration = read_r8b2c_collaboration_oracle(&root, &second.routed_ids);
    for collaboration in [&first_collaboration, &second_collaboration] {
        assert_eq!(collaboration.run.status, RunStatus::ReturnPending as i32);
        assert_eq!(collaboration.step.status, StepStatus::ReturnPending as i32);
        assert_eq!(collaboration.attempt.status, AttemptStatus::Returned as i32);
    }
    let first_adapter = read_r8b2c_adapter_oracle(&root, &first.routed_ids);
    let second_adapter = read_r8b2c_adapter_oracle(&root, &second.routed_ids);
    let first_observations = phase_one_observation_summary(&first_adapter);
    let second_observations = phase_one_observation_summary(&second_adapter);
    assert_eq!(
        first_adapter.observations.len(),
        3,
        "first dispatch observation sequence: {first_observations:#?}"
    );
    assert_eq!(
        second_adapter.observations.len(),
        3,
        "second dispatch observation sequence: {second_observations:#?}"
    );
    stop_u04c_fixture(&mut daemon, "phase-one multi-task daemon").await;

    let adapter = AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.join("r8a-adapter.db"),
        adapter_id: CODEX_ADAPTER_ID.to_owned(),
        store_epoch: "r8a-adapter-epoch".to_owned(),
        key: AdapterEdgeKey::new([0x32; 32]),
    })
    .expect("reopen phase-one Adapter Edge");
    let adapter_before = adapter.inspect().expect("inspect phase-one Adapter Edge");
    assert_eq!(adapter_before.dispatch_count, 2);
    assert_eq!(
        adapter_before.observation_count, 6,
        "first dispatch observations={first_observations:#?}; second dispatch observations={second_observations:#?}"
    );
    assert_eq!(adapter_before.terminal_output_outbox_count, 2);
    assert_eq!(adapter_before.pending_terminal_output_count, 0);
    drop(adapter);
    let (artifact, _) = r8a_authorities(&root, &r8a_native_config(&root).return_collector);
    let artifact_before = artifact
        .lock()
        .expect("lock phase-one Artifact Authority")
        .inspect_store()
        .expect("inspect phase-one Artifact Authority");
    assert_eq!(artifact_before.return_handoff_count, 2);
    assert_eq!(artifact_before.return_receipt_count, 2);
    drop(artifact);

    let mut restarted = spawn_fixture_with_mode(&root, &instance, PHASE_ONE_MULTI_TASK_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut restarted).await;
    sleep(Duration::from_millis(500)).await;
    assert!(
        restarted
            .try_wait()
            .expect("inspect restarted phase-one daemon")
            .is_none()
    );
    stop_u04c_fixture(&mut restarted, "restarted phase-one multi-task daemon").await;
    assert_eq!(
        fs::read(root.join(PHASE_ONE_DRIVER_LEDGER)).expect("read restarted driver ledger"),
        ledger_before
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root, &first.routed_ids),
        first_collaboration
    );
    assert_eq!(
        read_r8b2c_collaboration_oracle(&root, &second.routed_ids),
        second_collaboration
    );
    fs::remove_dir_all(&root).expect("remove phase-one multi-task fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_one_no_context_defaults_to_memory() {
    let root = std::env::temp_dir().join(format!("egopulse-phase-one-memory-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create phase-one memory fixture root");
    let instance = format!("phase-one-memory-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, M13_MEMORY_DISPATCH_MODE).await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;

    let memory = run_cli(
        &instance,
        &[
            "work",
            "prepare",
            "--intent",
            "use accepted Memory without an explicit context reference",
            "--scope",
            "scope:founder",
            "--work-type",
            "governed_repository_change",
            "--idempotency-key",
            "phase-one-memory-default",
            "--json",
        ],
    )
    .await;
    assert!(
        memory.status.success(),
        "default Memory preparation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&memory.stdout),
        String::from_utf8_lossy(&memory.stderr)
    );
    let memory: serde_json::Value =
        serde_json::from_slice(&memory.stdout).expect("decode default Memory preparation");
    assert!(
        memory["data"]["memoryPackSnapshotSha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    assert!(
        memory["data"]["includedSources"]
            .as_array()
            .is_some_and(|sources| sources.iter().any(|source| source["authority"] == "memory"))
    );

    stop_u04c_fixture(&mut daemon, "phase-one memory-default daemon").await;
    fs::remove_dir_all(&root).expect("remove phase-one memory fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_one_no_memory_without_sources_is_blocked_and_creates_no_task() {
    let root =
        std::env::temp_dir().join(format!("egopulse-phase-one-no-source-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create phase-one no-source fixture root");
    let instance = format!("phase-one-no-source-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, "allow").await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;
    let task_before_start = u04c_durability(&root, None, None).task;
    let start = run_cli(
        &instance,
        &[
            "work",
            "start",
            "--intent",
            "reject an empty governed work start",
            "--scope",
            "scope:founder",
            "--work-type",
            "governed_repository_change",
            "--no-memory",
            "--confirm",
            "--json",
        ],
    )
    .await;
    assert!(
        !start.status.success(),
        "no-source work start must fail: stdout={} stderr={}",
        String::from_utf8_lossy(&start.stdout),
        String::from_utf8_lossy(&start.stderr)
    );
    let start: serde_json::Value =
        serde_json::from_slice(&start.stdout).expect("decode no-source work start failure");
    assert_eq!(start["error"]["code"], "GUIDED_WORK_INPUT_INVALID");
    assert_eq!(u04c_durability(&root, None, None).task, task_before_start);

    stop_u04c_fixture(&mut daemon, "phase-one no-source daemon").await;
    fs::remove_dir_all(&root).expect("remove phase-one no-source fixture root");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_one_restart_reads_existing_active_and_cancellation_pending_tasks_without_writes() {
    let root = std::env::temp_dir().join(format!("egopulse-phase-one-restart-{}", Uuid::now_v7()));
    fs::create_dir_all(&root).expect("create phase-one restart fixture root");
    let (active, cancellation_pending) = phase_one_seed_restart_tasks(&root);
    let active_before = read_r8b2c_task_oracle(&root, &active.task_id);
    let cancellation_before = read_r8b2c_task_oracle(&root, &cancellation_pending.task_id);
    let instance = format!("phase-one-restart-{}", Uuid::now_v7());
    let mut daemon = spawn_fixture_with_mode(&root, &instance, "allow").await;
    wait_for_cli_status_with_child(&instance, &mut daemon).await;

    let active_read = run_cli(&instance, &["task", "get", &active.task_id, "--json"]).await;
    assert!(active_read.status.success());
    let active_read: serde_json::Value =
        serde_json::from_slice(&active_read.stdout).expect("decode restarted Active task");
    assert_eq!(
        active_read["data"]["status"],
        TaskStatus::Active.as_str_name()
    );
    let cancellation_read = run_cli(
        &instance,
        &["task", "get", &cancellation_pending.task_id, "--json"],
    )
    .await;
    assert!(cancellation_read.status.success());
    let cancellation_read: serde_json::Value = serde_json::from_slice(&cancellation_read.stdout)
        .expect("decode restarted CancellationPending task");
    assert_eq!(
        cancellation_read["data"]["status"],
        TaskStatus::CancellationPending.as_str_name()
    );
    stop_u04c_fixture(&mut daemon, "phase-one restart-read daemon").await;
    assert_eq!(
        read_r8b2c_task_oracle(&root, &active.task_id),
        active_before
    );
    assert_eq!(
        read_r8b2c_task_oracle(&root, &cancellation_pending.task_id),
        cancellation_before
    );
    fs::remove_dir_all(&root).expect("remove phase-one restart fixture root");
}
