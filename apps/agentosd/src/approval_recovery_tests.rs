use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    ConfiguredSingleHarnessWorkflow,
    approval_delivery::{ApprovalDeliveryRoute, ApprovalDeliverySource, ApprovalDeliveryWorker},
    owners::{AuthorityCommandPorts, AuthorityPrincipalResolver},
    policy::{LocalUserPolicyResolver, LocalUserPolicyResolverConfig},
    task_recovery::GovernedTaskRecoveryRunner,
};
use egopulse_client_kernel::authorization_contract_ref;
use egopulse_codex_adapter::codex_protocol_fingerprint;
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection,
    PrincipalKind as TaskPrincipalKind, SqlCipherKey, TaskAuthority, TaskAuthorityConfig,
    TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization, TransitionGuardRejection,
    canonical_request_digest as task_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{RunPlan, StepPlan},
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::{
        ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
        ApprovalRequestObservation, CancelExecutionEnvelope, DeliveryDisposition, DispatchEnvelope,
        HarnessError, HarnessErrorCode, HarnessObservation, ObservationCriticality,
        ProbeHarnessRequest, ProbeHarnessResult, harness_observation,
    },
    policy::v1::{
        IssueHarnessApprovalDecisionCommand, PolicyDecisionCommand, policy_decision_command,
    },
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, GetTaskResponse, TaskCommand, TaskSnapshot,
        TaskStatus, get_task_response, task_command, task_command_result,
    },
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, ApprovalDeliveryState,
    DispatchMaterialResolver, DriverDelivery, DriverError, DriverErrorCertainty,
    GovernedHarnessAdapter, NativeHarnessDriver, NativeHarnessFuture, ReconciliationContext,
    ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, PolicyCommandPort,
};
use egopulse_local_ide_control::collaboration_control::{
    AdapterBackedHarnessEvidenceResolver, AuthenticatedCollaborationPrincipal,
    CollaborationControl, CollaborationControlConfig, CollaborationPrincipalKind,
    CollaborationSqlCipherKey, DispatchMaterial, GovernedTaskActivationRunner,
    HarnessApprovalDeliveryTarget, HarnessDispatchRunner, SingleHarnessWorkConfig,
    SystemAuthorityClock, TaskActivationGuardSet, TrustedDispatchRouteProfile,
    build_dispatch_route_binding,
};
use egopulse_policy_decision_authority::{
    PolicyAuthorityConfig, PolicyDecisionAuthority, PolicyPrincipalKind, PolicySqlCipherKey,
    canonical_request_digest,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};

const RUN_ID: &str = "run-approval-recovery-001";
const STEP_ID: &str = "step-approval-recovery-001";
const ATTEMPT_ID: &str = "attempt-approval-recovery-001";
const DISPATCH_ID: &str = "dispatch-approval-recovery-001";
const ADAPTER_ID: &str = "adapter:codex";
const PROFILE_ID: &str = "profile:codex:approval-recovery";
const SCOPE_REF: &str = "scope:task:approval-recovery";
const APPROVAL_REQUEST_ID: &str = "approval-request-recovery-001";

#[derive(Clone, Copy)]
struct AllowTaskReferences;

impl TaskCreationGuard for AllowTaskReferences {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["fixture:approval-recovery-input".to_owned()],
        })
    }
}

impl TaskTransitionGuard for AllowTaskReferences {
    fn validate(
        &self,
        _command: &TaskCommand,
        _current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        Ok(TransitionAuthorization {
            evidence_refs: vec!["fixture:approval-recovery-transition".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

#[derive(Clone, Copy)]
struct LocalUserPrincipalResolver;

impl AuthorityPrincipalResolver for LocalUserPrincipalResolver {
    fn resolve_task(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
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
    ) -> Result<egopulse_founder_verdict_authority::VerdictPrincipalKind, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }

    fn resolve_memory(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<egopulse_cognition_runtime::memory_authority::MemoryPrincipalKind, CommandPortFailure>
    {
        Err(CommandPortFailure::Unavailable)
    }
}

#[derive(Clone)]
struct StaticMaterial {
    root: PathBuf,
    bytes: Vec<u8>,
}

impl DispatchMaterialResolver for StaticMaterial {
    fn resolve(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError> {
        assert_eq!(
            envelope.input_bundle_sha256,
            hex::encode(Sha256::digest(&self.bytes))
        );
        Ok(ResolvedDispatchMaterial {
            canonical_input_bundle: self.bytes.clone(),
            prompt: "approval recovery fixture".to_owned(),
            workspace_root: self.root.clone(),
            model: Some("fixture-model".to_owned()),
        })
    }
}

struct CountingDriver {
    dispatch_sends: Arc<AtomicUsize>,
    approval_sends: Arc<AtomicUsize>,
    reconciliations: Arc<AtomicUsize>,
}

impl NativeHarnessDriver for CountingDriver {
    fn probe<'a>(
        &'a mut self,
        _request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async { panic!("approval recovery does not probe the native driver") })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        self.dispatch_sends.fetch_add(1, Ordering::SeqCst);
        let dispatch_id = envelope.dispatch_id.clone();
        Box::pin(async move {
            Ok(DriverDelivery {
                native_request_ref: format!("native-request:{dispatch_id}"),
                native_session_ref: format!("native-session:{dispatch_id}"),
                native_execution_ref: Some(format!("native-execution:{dispatch_id}")),
                raw_evidence: b"native dispatch delivered".to_vec(),
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<egopulse_harness_adapter::DriverEvent>, DriverError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        self.approval_sends.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(DriverError {
                certainty: DriverErrorCertainty::DeliveryUnknown,
                code: HarnessErrorCode::DeliveryUnknown,
                safe_detail_code: "NATIVE_APPROVAL_DELIVERY_UNKNOWN".to_owned(),
                error_fingerprint: Some("fixture:approval-delivery-unknown".to_owned()),
                raw_evidence: b"opaque native approval delivery uncertainty".to_vec(),
            })
        })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("approval recovery does not cancel native execution") })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: "native:approval-outcome-still-unknown".to_owned(),
            })
        })
    }
}

#[tokio::test]
async fn durable_approval_unknown_interrupts_task_without_native_resend_after_reopen() {
    let root = tempfile::tempdir().expect("approval recovery root");
    let adapter_path = root.path().join("adapter.db");
    let task = open_task(root.path());
    let active_task = create_and_activate_task(&task);

    let ports = open_ports(root.path(), &adapter_path, Arc::clone(&task));

    let bundle = br#"{"task":"approval recovery"}"#.to_vec();
    let dispatch_sends = Arc::new(AtomicUsize::new(0));
    let approval_sends = Arc::new(AtomicUsize::new(0));
    let reconciliations = Arc::new(AtomicUsize::new(0));
    let runner = build_runner(
        root.path(),
        &adapter_path,
        Arc::clone(&ports),
        bundle.clone(),
        Arc::clone(&dispatch_sends),
        Arc::clone(&approval_sends),
        Arc::clone(&reconciliations),
    );

    let started = runner.run_once().await.expect("initial dispatch cycle");
    assert_eq!(started.dispatches_delivered, 1);
    assert_eq!(dispatch_sends.load(Ordering::SeqCst), 1);

    let projection = append_and_ack_approval_request(&adapter_path);
    let issued = PolicyCommandPort::execute(
        &*ports,
        &issue_approval_command(&projection),
        &CommandPrincipal {
            principal_id: "os-user:approval-recovery".to_owned(),
            required_authority_principal_kinds: vec![
                "PolicyDecisionAuthority.LocalUser".to_owned(),
            ],
        },
    )
    .expect("issue approval through production owner port")
    .result;
    assert!(issued.committed, "Policy decision must commit");
    let decision_ref = issued
        .decision_record
        .as_ref()
        .expect("issued decision")
        .authority_decision_ref
        .clone();
    let production_evidence =
        ApprovalDeliverySource::approval_policy_evidence(&*ports, &decision_ref)
            .expect("read real Policy evidence port")
            .expect("issued Policy evidence");
    assert_eq!(production_evidence.0.authority_decision_ref, decision_ref);
    assert_eq!(production_evidence.2.authority_decision_ref, decision_ref);

    let target: Arc<dyn HarnessApprovalDeliveryTarget> = runner.clone();
    let first_worker = ApprovalDeliveryWorker::new(
        Arc::clone(&ports) as Arc<dyn ApprovalDeliverySource>,
        vec![
            ApprovalDeliveryRoute::new(
                ADAPTER_ID,
                PROFILE_ID,
                "harness-adapter:codex",
                open_edge(&adapter_path),
                Arc::clone(&target),
            )
            .expect("approval route"),
        ],
    )
    .expect("approval worker");
    let recovered = first_worker
        .run_once()
        .await
        .expect("recover durable unknown");
    assert_eq!(
        recovered.held[0].safe_reason_code,
        "APPROVAL_DELIVERY_OUTCOME_UNKNOWN"
    );
    assert_eq!(approval_sends.load(Ordering::SeqCst), 1);
    let persisted = open_edge(&adapter_path)
        .approval_record(APPROVAL_REQUEST_ID)
        .expect("read real adapter approval record")
        .expect("real adapter must persist unknown receipt");
    assert_eq!(
        persisted.delivery_state,
        ApprovalDeliveryState::DeliveryUnknown
    );
    assert_eq!(
        persisted
            .receipt
            .expect("unknown receipt must be durable")
            .disposition,
        DeliveryDisposition::Unknown as i32
    );
    first_worker
        .run_once()
        .await
        .expect("exact unknown recovery replay");
    assert_eq!(approval_sends.load(Ordering::SeqCst), 1);
    drop(first_worker);

    let dispatch_runner: Arc<dyn HarnessDispatchRunner> = runner.clone();
    let settlement = GovernedTaskRecoveryRunner::new(
        dispatch_runner,
        Arc::clone(&task),
        "collaboration-control:task-recovery",
    )
    .expect("Task recovery settlement");
    settlement
        .run_once()
        .await
        .expect("next scheduling cycle settles interruption");
    assert_eq!(
        current_task(&task, &active_task.task_id).status,
        TaskStatus::Interrupted as i32
    );
    drop(settlement);
    drop(target);
    drop(runner);
    drop(ports);
    drop(task);

    let reopened_task = open_task(root.path());
    let reopened_ports = open_ports(root.path(), &adapter_path, Arc::clone(&reopened_task));
    let reopened_runner = build_runner(
        root.path(),
        &adapter_path,
        Arc::clone(&reopened_ports),
        bundle,
        Arc::clone(&dispatch_sends),
        Arc::clone(&approval_sends),
        Arc::clone(&reconciliations),
    );
    let reopened_target: Arc<dyn HarnessApprovalDeliveryTarget> = reopened_runner;
    let reopened_worker = ApprovalDeliveryWorker::new(
        Arc::clone(&reopened_ports) as Arc<dyn ApprovalDeliverySource>,
        vec![
            ApprovalDeliveryRoute::new(
                ADAPTER_ID,
                PROFILE_ID,
                "harness-adapter:codex",
                open_edge(&adapter_path),
                reopened_target,
            )
            .expect("reopened approval route"),
        ],
    )
    .expect("reopened approval worker");
    reopened_worker
        .run_once()
        .await
        .expect("reopened exact unknown recovery");
    assert_eq!(dispatch_sends.load(Ordering::SeqCst), 1);
    assert_eq!(approval_sends.load(Ordering::SeqCst), 1);
    assert_eq!(reconciliations.load(Ordering::SeqCst), 1);
    assert_eq!(
        current_task(&reopened_task, &active_task.task_id).status,
        TaskStatus::Interrupted as i32
    );
    assert!(
        ApprovalDeliverySource::approval_policy_evidence(&*reopened_ports, &decision_ref)
            .expect("reopen real Policy evidence port")
            .is_some(),
        "unknown approval receipt must not consume the Policy decision"
    );
}

fn build_runner(
    root: &Path,
    adapter_path: &Path,
    ports: Arc<AuthorityCommandPorts>,
    bundle: Vec<u8>,
    dispatch_sends: Arc<AtomicUsize>,
    approval_sends: Arc<AtomicUsize>,
    reconciliations: Arc<AtomicUsize>,
) -> Arc<impl HarnessDispatchRunner + HarnessApprovalDeliveryTarget + use<>> {
    let evidence_source = Arc::clone(&ports);
    let evidence = AdapterBackedHarnessEvidenceResolver::new(open_edge(adapter_path))
        .with_approval_policy_evidence(move |decision_ref| {
            ApprovalDeliverySource::approval_policy_evidence(&*evidence_source, decision_ref)
                .map_err(|_| ())
        });
    let (guard, reference) = TaskActivationGuardSet::new(evidence);
    let control = CollaborationControl::open(
        CollaborationControlConfig {
            database_path: root.join("collaboration.db"),
            store_epoch: "approval-recovery-collaboration-v1".to_owned(),
            key: CollaborationSqlCipherKey::new([0x53; 32]),
        },
        guard,
        SystemAuthorityClock,
    )
    .expect("Collaboration Control");
    let profile = contract_ref(PROFILE_ID, '3');
    let route_profile = TrustedDispatchRouteProfile {
        provider_bootstrap_profile_id: "bootstrap:codex:fixture".to_owned(),
        selected_harness_id: "codex".to_owned(),
        provider_model_id: "fixture-model".to_owned(),
        catalog_snapshot_sha256: None,
        capability_profile_id: PROFILE_ID.to_owned(),
    };
    let route_binding = build_dispatch_route_binding(&route_profile).expect("route binding");
    let workflow = ConfiguredSingleHarnessWorkflow::new(workflow_config(&bundle, profile.clone()))
        .with_trusted_dispatch_route_profile(route_profile);
    let adapter = GovernedHarnessAdapter::new(
        ADAPTER_ID,
        PROFILE_ID,
        codex_protocol_fingerprint(),
        open_edge(adapter_path),
        StaticMaterial {
            root: root.to_owned(),
            bytes: bundle,
        },
        CountingDriver {
            dispatch_sends,
            approval_sends,
            reconciliations,
        },
        SystemAdapterClock,
    )
    .with_dispatch_route_binding(route_binding, "fixture-model");
    Arc::new(
        GovernedTaskActivationRunner::new(
            control,
            adapter,
            ports,
            workflow,
            collaboration_principal(CollaborationPrincipalKind::HarnessAdapter, ADAPTER_ID),
            reference,
            300,
        )
        .with_capability_profile_ref(profile),
    )
}

fn open_task(root: &Path) -> Arc<Mutex<TaskAuthority>> {
    Arc::new(Mutex::new(
        TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "approval-recovery-task-v1".to_owned(),
                key: SqlCipherKey::new([0x51; 32]),
            },
            AllowTaskReferences,
            AllowTaskReferences,
        )
        .expect("Task Authority"),
    ))
}

fn open_ports(
    root: &Path,
    adapter_path: &Path,
    task: Arc<Mutex<TaskAuthority>>,
) -> Arc<AuthorityCommandPorts> {
    let policy_resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
        edge: open_edge(adapter_path),
        adapter_id: ADAPTER_ID.to_owned(),
        authorization_policy_ref: authorization_contract_ref(),
        authentication_context_ref: "local-ipc:approval-recovery".to_owned(),
        allowed_scope_refs: BTreeSet::from([SCOPE_REF.to_owned()]),
        decision_ttl: Duration::from_secs(300),
    })
    .expect("production policy resolver");
    let policy = PolicyDecisionAuthority::open(
        PolicyAuthorityConfig {
            database_path: root.join("policy.db"),
            store_epoch: "approval-recovery-policy-v1".to_owned(),
            key: PolicySqlCipherKey::new([0x52; 32]),
        },
        policy_resolver,
    )
    .expect("Policy Authority");
    Arc::new(AuthorityCommandPorts::new_shared_handles(
        task,
        policy,
        Arc::new(Mutex::new(None)),
        Arc::new(LocalUserPrincipalResolver),
    ))
}

fn create_and_activate_task(task: &Arc<Mutex<TaskAuthority>>) -> TaskSnapshot {
    let mut create = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata("task-create", "task-create")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input:approval-recovery".to_owned(),
            target_scope_ref: SCOPE_REF.to_owned(),
            acceptance_contract_ref: Some(contract_ref("repository_change_acceptance", 'a')),
            budget_profile_ref: Some(contract_ref("budget:approval-recovery", 'b')),
            work_capability_route: None,
        })),
    };
    seal_task(&mut create);
    let created = task
        .lock()
        .expect("Task lock")
        .execute(
            &create,
            &task_principal(TaskPrincipalKind::Founder, "founder:test"),
        )
        .expect("create Task");
    let created = task_snapshot(created.outcome.expect("create outcome"));
    let mut activate = TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(metadata("task-activate", "task-activate")),
            task_id: created.task_id.clone(),
            expected_revision: created.revision,
            work_revision: created.work_revision,
            run_id: RUN_ID.to_owned(),
        })),
    };
    seal_task(&mut activate);
    let activated = task
        .lock()
        .expect("Task lock")
        .execute(
            &activate,
            &task_principal(
                TaskPrincipalKind::CollaborationControl,
                "collaboration-control:test",
            ),
        )
        .expect("activate Task");
    task_snapshot(activated.outcome.expect("activate outcome"))
}

fn task_snapshot(outcome: task_command_result::Outcome) -> TaskSnapshot {
    match outcome {
        task_command_result::Outcome::Task(snapshot) => snapshot,
        task_command_result::Outcome::Error(error) => {
            panic!("Task command rejected: {}", error.safe_detail_code)
        }
    }
}

fn current_task(task: &Arc<Mutex<TaskAuthority>>, task_id: &str) -> TaskSnapshot {
    match task
        .lock()
        .expect("Task lock")
        .get_task(task_id)
        .expect("read Task")
    {
        GetTaskResponse {
            outcome: Some(get_task_response::Outcome::Task(snapshot)),
        } => snapshot,
        _ => panic!("Task snapshot missing"),
    }
}

fn workflow_config(bundle: &[u8], profile: ContractReference) -> SingleHarnessWorkConfig {
    SingleHarnessWorkConfig {
        run_id: RUN_ID.to_owned(),
        attempt_id: ATTEMPT_ID.to_owned(),
        dispatch_id: DISPATCH_ID.to_owned(),
        plan: RunPlan {
            plan_id: "plan:approval-recovery".to_owned(),
            digest_sha256: "c".repeat(64),
            max_active_attempts: 1,
            steps: vec![StepPlan {
                step_id: STEP_ID.to_owned(),
                step_kind: "implementation".to_owned(),
                input_bundle_ref: "input:approval-recovery".to_owned(),
                expected_output_contract_ref: Some(contract_ref("output:approval-recovery", 'd')),
                required_capability_profile_ref: Some(profile.clone()),
                max_attempts: 2,
                ..StepPlan::default()
            }],
            budget_profile_ref: Some(contract_ref("budget:approval-recovery", 'b')),
        },
        harness_id: "codex".to_owned(),
        capability_profile_ref: profile,
        workspace_ref: "workspace:approval-recovery".to_owned(),
        lease_policy_ref: contract_ref("lease:approval-recovery", 'e'),
        owner_instance_id: "attempt-supervisor:approval-recovery".to_owned(),
        material: DispatchMaterial {
            input_bundle_sha256: hex::encode(Sha256::digest(bundle)),
            sandbox_profile_ref: contract_ref("sandbox:approval-recovery", 'f'),
            tool_policy_ref: contract_ref("tools:approval-recovery", '1'),
            data_egress_policy_ref: contract_ref("egress:approval-recovery", '2'),
            approval_policy_ref: contract_ref("approval:approval-recovery", '3'),
            session_strategy: egopulse_domain_contracts::v01::egopulse::harness::v1::NativeSessionStrategy::CreateNew,
            native_session_ref: None,
            checkpoint_ref: None,
            route_binding: None,
            evidence_refs: vec!["fixture:dispatch-material".to_owned()],
        },
        task_authority_principal_id: "task-authority:approval-recovery".to_owned(),
        collaboration_principal_id: "collaboration-control:approval-recovery".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:approval-recovery".to_owned(),
        harness_adapter_principal_id: ADAPTER_ID.to_owned(),
    }
}

fn append_and_ack_approval_request(
    adapter_path: &Path,
) -> egopulse_harness_adapter::PendingAdapterApprovalProjection {
    let mut edge = open_edge(adapter_path);
    let dispatch = edge
        .dispatch_envelope(DISPATCH_ID)
        .expect("read durable dispatch")
        .expect("durable dispatch");
    edge.append_observation(
        DISPATCH_ID,
        "native-approval-request-recovery-001",
        b"private native approval request",
        HarnessObservation {
            attempt_id: dispatch.attempt_id,
            dispatch_id: dispatch.dispatch_id,
            fencing_token: dispatch.fencing_token,
            capability_profile_id: dispatch
                .capability_profile_ref
                .expect("dispatch capability profile")
                .contract_id,
            criticality: ObservationCriticality::Security as i32,
            payload: Some(harness_observation::Payload::ApprovalRequest(
                ApprovalRequestObservation {
                    approval_request_id: APPROVAL_REQUEST_ID.to_owned(),
                    kind: ApprovalKind::Command as i32,
                    action_digest_sha256: "8".repeat(64),
                    requested_scope_ref: SCOPE_REF.to_owned(),
                    display_summary_ref: "summary:approval-recovery".to_owned(),
                    display_summary: None,
                    native_routing_ref: "native-private:approval-recovery".to_owned(),
                    lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                    request_revision: 1,
                },
            )),
            ..HarnessObservation::default()
        },
        20,
    )
    .expect("append approval request");
    let projection = edge
        .pending_approval_projection_messages()
        .expect("approval projection")
        .remove(0);
    assert!(
        edge.acknowledge_approval_projection_message(
            &projection.message_id,
            &projection.payload_digest_sha256,
        )
        .expect("ack approval projection")
    );
    projection
}

fn issue_approval_command(
    projection: &egopulse_harness_adapter::PendingAdapterApprovalProjection,
) -> IssueHarnessApprovalDecisionCommand {
    let request = match projection.observation.payload.as_ref() {
        Some(harness_observation::Payload::ApprovalRequest(request)) => request,
        _ => panic!("approval projection payload"),
    };
    let mut wrapper = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(metadata("policy-issue", "policy-issue")),
                    approval_request_id: request.approval_request_id.clone(),
                    expected_action_digest_sha256: request.action_digest_sha256.clone(),
                    expected_request_observation_id: projection.source_observation_id.clone(),
                    expected_request_observation_sequence: projection.source_revision,
                    decision: ApprovalDecision::AllowOnce as i32,
                    reason_code: "FOUNDER_APPROVED_SCOPED_COMMAND".to_owned(),
                    confirmation_proof_ref: Some("local-confirmation:approval-recovery".to_owned()),
                    expected_request_revision: request.request_revision,
                },
            ),
        ),
    };
    let digest = canonical_request_digest(&wrapper);
    let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(command)) =
        wrapper.command.as_mut()
    else {
        unreachable!()
    };
    command
        .metadata
        .as_mut()
        .expect("Policy metadata")
        .request_digest_sha256 = digest;
    command.clone()
}

fn open_edge(path: &Path) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path.to_owned(),
        adapter_id: ADAPTER_ID.to_owned(),
        store_epoch: "approval-recovery-adapter-v1".to_owned(),
        key: AdapterEdgeKey::new([0x54; 32]),
    })
    .expect("Adapter Edge")
}

fn metadata(command_id: &str, key: &str) -> CommandMetadata {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch");
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: key.to_owned(),
        idempotency_scope: "approval-recovery-test/v1".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }),
        correlation_id: format!("correlation:{command_id}"),
        causation_id: None,
    }
}

fn contract_ref(id: &str, digest_byte: char) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "1".to_owned(),
        sha256: digest_byte.to_string().repeat(64),
    }
}

fn seal_task(command: &mut TaskCommand) {
    let digest = task_request_digest(command).expect("Task request digest");
    match command.command.as_mut().expect("Task command") {
        task_command::Command::CreateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::ActivateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        _ => unreachable!(),
    }
}

fn task_principal(kind: TaskPrincipalKind, id: &str) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn collaboration_principal(
    kind: CollaborationPrincipalKind,
    id: &str,
) -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}
