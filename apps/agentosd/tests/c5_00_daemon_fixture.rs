#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use egopulse_agentosd::{
    AuthorityCompositionInputs, AuthorityPrincipalResolver, ConfiguredTaskTransitionGuard,
    ConfiguredWorkPreparationPort, DaemonComposition, DaemonConfig, DaemonProviders,
    MemoryRetrievalCompositionConfig, OwnerProjectionSource, PendingOwnerProjection,
    ProjectionSourceFailure,
};
use egopulse_client_kernel::{ClientKernel, api_contract_ref, authorization_contract_ref};
use egopulse_cognition_runtime::{
    context_authority::{ContextAuthority, ContextAuthorityConfig},
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
        AttemptSnapshot, CollaborationEvent, CollaborationSnapshot, Lease, RunSnapshot, RunStatus,
        StepSnapshot, StepStatus, collaboration_command_result,
    },
    harness::v1::{
        ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation, HarnessObservation,
        harness_observation,
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
        harness_dispatch_interval: Duration::from_millis(25),
        verification_interval: Duration::from_millis(25),
        verdict_consumption_interval: Duration::from_millis(25),
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
    let task = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task-authority.db"),
            store_epoch: "c5-00-task-epoch".to_owned(),
            key: SqlCipherKey::new([0x11; 32]),
        },
        task_guard,
        ConfiguredTaskTransitionGuard::new(),
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

    let providers = DaemonProviders::from_authority_inputs(AuthorityCompositionInputs {
        task,
        policy,
        verdict,
        principal_resolver: Arc::new(FixtureAuthorityPrincipalResolver),
        session_principal_resolver: Arc::new(FixtureSessionResolver),
        session_clock: Arc::new(egopulse_local_api::session::SystemSessionClock),
        session_audit: Arc::new(NoopSessionAuditSink),
        additional_projection_sources,
    });
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
    let task_port = Arc::clone(&providers.task_port);
    let context = ContextAuthority::open(ContextAuthorityConfig {
        database_path: root.join("context-authority.db"),
        store_epoch: "c5-context-epoch".to_owned(),
        key: SqlCipherKey::new([0x15; 32]),
    })
    .expect("fixture Context Authority should open");
    providers.with_work_preparation_port(Arc::new(
        ConfiguredWorkPreparationPort::new(
            Arc::new(std::sync::Mutex::new(context)),
            task_port,
            root.to_owned(),
            BTreeSet::from(["governed_repository_change".to_owned()]),
            egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                contract_id: "c5-acceptance".to_owned(),
                version: "v0.1".to_owned(),
                sha256: "44".repeat(32),
            },
            egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
                contract_id: "c5-budget".to_owned(),
                version: "v0.1".to_owned(),
                sha256: "55".repeat(32),
            },
        )
        .expect("fixture Work Preparation should configure"),
    ))
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
