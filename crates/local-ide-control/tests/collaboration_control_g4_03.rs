use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptCommandBase, AttemptSnapshot,
    AttemptStatus, CollaborationCommand, CollaborationCommandResult, CollaborationErrorCode,
    CollaborationSnapshot, CreateAttemptCommand, CreateRunCommand,
    MarkAttemptOutcomeUnknownCommand, RecordDeliveryReceiptCommand, RecordDispatchIntentCommand,
    RecordHarnessAckCommand, RecordRunningObservationCommand, RunCommandBase, RunPlan, RunStatus,
    StepPlan, StepStatus, collaboration_command, collaboration_command_result,
    get_collaboration_response,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, NativeSessionStrategy,
};
use egopulse_local_ide_control::collaboration_control::{
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlConfig, CollaborationControlError, CollaborationPrincipalKind,
    CollaborationReferenceGuard, CollaborationSqlCipherKey, DispatchMaterial,
    HarnessEvidenceResolver, LeaseAuthorization, ReferenceAuthorization, ReferenceGuardRejection,
    ResolvedHarnessEvidence, canonical_dispatch_fingerprint, canonical_request_digest,
};
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const STORE_EPOCH: &str = "collaboration-store-g4-03-test";
const TEST_KEY: [u8; 32] = [0x63; 32];
const FIXED_TIME: i64 = 1_777_073_600;

#[derive(Clone)]
struct FixedClock(Arc<Mutex<Timestamp>>);

impl FixedClock {
    fn new(seconds: i64) -> Self {
        Self(Arc::new(Mutex::new(Timestamp { seconds, nanos: 0 })))
    }

    fn set_seconds(&self, seconds: i64) {
        self.0.lock().expect("clock mutex").seconds = seconds;
    }
}

impl AuthorityClock for FixedClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().expect("clock mutex")
    }
}

#[derive(Clone, Copy)]
struct FixtureGuard;

impl CollaborationReferenceGuard for FixtureGuard {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.task_id != "task-001" || command.task_revision != 2 || command.work_revision != 1
        {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["task-receipt:task-001@2".to_owned()],
        })
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.confirmed_task_revision != 2 || run.task_id != "task-001" {
            return Err(ReferenceGuardRejection::StaleTaskReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["task-active-receipt:task-001@2".to_owned()],
        })
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        _run: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot,
        _step: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.harness_id != "codex" || command.workspace_ref != "workspace-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![
                "capability-profile:single-harness-capability@0.1".to_owned(),
                "workspace:workspace-001@isolated".to_owned(),
            ],
        })
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        _attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        if command.owner_instance_id != "attempt-supervisor-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(LeaseAuthorization {
            ttl_seconds: 30,
            evidence_refs: vec!["lease-policy:v01-attempt-lease@0.1".to_owned()],
        })
    }

    fn resolve_dispatch_material(
        &self,
        _command: &RecordDispatchIntentCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        Ok(dispatch_material())
    }

    fn validate_unknown_outcome(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.uncertainty_evidence_id != "uncertainty-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["lease-expired:external-stop-not-proven".to_owned()],
        })
    }
}

impl HarnessEvidenceResolver for FixtureGuard {
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        if command.delivery_receipt_id != "delivery-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: Some("codex-thread-001".to_owned()),
            evidence_refs: vec!["adapter-receipt:delivery-001@durable".to_owned()],
        })
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        if command.ack_receipt_id != "ack-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: Some("codex-thread-001".to_owned()),
            evidence_refs: vec!["adapter-observation:ack-001@durable".to_owned()],
        })
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.lifecycle_event_id != "running-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["adapter-observation:running-001@durable".to_owned()],
        })
    }
}

struct IsolatedStore {
    root: PathBuf,
}

impl IsolatedStore {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create Collaboration test directory");
        Self { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("collaboration-control.sqlcipher")
    }
}

impl Drop for IsolatedStore {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        assert!(self.root.starts_with(&temp_root));
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove Collaboration test directory");
        }
    }
}

fn open_control(path: &Path, clock: FixedClock) -> CollaborationControl<FixtureGuard, FixedClock> {
    CollaborationControl::open(
        CollaborationControlConfig {
            database_path: path.to_owned(),
            store_epoch: STORE_EPOCH.to_owned(),
            key: CollaborationSqlCipherKey::new(TEST_KEY),
        },
        FixtureGuard,
        clock,
    )
    .expect("open encrypted Collaboration Control")
}

fn principal(kind: CollaborationPrincipalKind, id: &str) -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn task_authority() -> AuthenticatedCollaborationPrincipal {
    principal(
        CollaborationPrincipalKind::TaskAuthority,
        "task-authority:test",
    )
}

fn collaboration_control() -> AuthenticatedCollaborationPrincipal {
    principal(
        CollaborationPrincipalKind::CollaborationControl,
        "collaboration-control:test",
    )
}

fn attempt_supervisor() -> AuthenticatedCollaborationPrincipal {
    principal(
        CollaborationPrincipalKind::AttemptSupervisor,
        "attempt-supervisor:test",
    )
}

fn recovery_worker() -> AuthenticatedCollaborationPrincipal {
    principal(
        CollaborationPrincipalKind::RecoveryWorker,
        "recovery-worker:test",
    )
}

fn harness_adapter() -> AuthenticatedCollaborationPrincipal {
    principal(CollaborationPrincipalKind::HarnessAdapter, "adapter:codex")
}

fn metadata(command_id: &str, key: &str, scope: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: key.to_owned(),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        correlation_id: "corr-v01".to_owned(),
        causation_id: None,
    }
}

fn contract_ref(id: &str, digest_byte: char) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "0.1".to_owned(),
        sha256: digest_byte.to_string().repeat(64),
    }
}

fn run_plan() -> RunPlan {
    RunPlan {
        plan_id: "plan-001".to_owned(),
        digest_sha256: "1".repeat(64),
        max_active_attempts: 1,
        steps: vec![StepPlan {
            step_id: "step-001".to_owned(),
            step_kind: "governed_harness_work".to_owned(),
            depends_on_step_ids: Vec::new(),
            input_bundle_ref: "input-001".to_owned(),
            expected_output_contract_ref: Some(contract_ref("repository-change-return", '2')),
            required_capability_profile_ref: Some(contract_ref("single-harness-capability", '3')),
            max_attempts: 2,
        }],
        budget_profile_ref: Some(contract_ref("v01-budget", '4')),
    }
}

fn dispatch_material() -> DispatchMaterial {
    DispatchMaterial {
        input_bundle_sha256: "5".repeat(64),
        sandbox_profile_ref: contract_ref("sandbox-policy", '6'),
        tool_policy_ref: contract_ref("tool-policy", '7'),
        data_egress_policy_ref: contract_ref("data-egress-policy", '8'),
        approval_policy_ref: contract_ref("approval-policy", '9'),
        session_strategy: NativeSessionStrategy::CreateNew,
        native_session_ref: None,
        checkpoint_ref: None,
        evidence_refs: vec!["dispatch-material:verified".to_owned()],
    }
}

fn set_digest(command: &mut CollaborationCommand) {
    let digest = canonical_request_digest(command).expect("canonical Collaboration digest");
    match command.command.as_mut().expect("command variant") {
        collaboration_command::Command::CreateRun(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        collaboration_command::Command::ActivateRun(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::CreateAttempt(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::AcquireAttemptLease(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordDispatchIntent(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordDeliveryReceipt(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordHarnessAck(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordRunningObservation(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        _ => panic!("test helper does not support command"),
    }
}

fn create_run_command() -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateRun(
            CreateRunCommand {
                meta: Some(metadata(
                    "cmd-run-create-001",
                    "run-create-001",
                    "task-001/work-1",
                )),
                run_id: "run-001".to_owned(),
                task_id: "task-001".to_owned(),
                task_revision: 2,
                work_revision: 1,
                plan: Some(run_plan()),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn activate_run_command() -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::ActivateRun(
            ActivateRunCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        "cmd-run-activate-001",
                        "run-activate-001",
                        "run-001",
                    )),
                    run_id: "run-001".to_owned(),
                    expected_run_revision: 1,
                }),
                confirmed_task_revision: 2,
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn create_attempt_command(
    run_revision: u64,
    step_revision: u64,
    attempt_id: &str,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateAttempt(
            CreateAttemptCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        &format!("cmd-{attempt_id}"),
                        &format!("create-{attempt_id}"),
                        "run-001/step-001",
                    )),
                    run_id: "run-001".to_owned(),
                    expected_run_revision: run_revision,
                }),
                step_id: "step-001".to_owned(),
                expected_step_revision: step_revision,
                attempt_id: attempt_id.to_owned(),
                harness_id: "codex".to_owned(),
                capability_profile_ref: Some(contract_ref("single-harness-capability", '3')),
                workspace_ref: "workspace-001".to_owned(),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn acquire_lease_command(
    run_revision: u64,
    step_revision: u64,
    attempt_revision: u64,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::AcquireAttemptLease(
            AcquireAttemptLeaseCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(metadata("cmd-lease-001", "lease-001", "attempt-001")),
                    run_id: "run-001".to_owned(),
                    expected_run_revision: run_revision,
                    step_id: "step-001".to_owned(),
                    expected_step_revision: step_revision,
                    attempt_id: "attempt-001".to_owned(),
                    expected_attempt_revision: attempt_revision,
                }),
                owner_instance_id: "attempt-supervisor-001".to_owned(),
                lease_policy_ref: Some(contract_ref("v01-attempt-lease", 'a')),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn dispatch_command(snapshot: &CollaborationSnapshot) -> CollaborationCommand {
    let run = snapshot.run.as_ref().expect("run");
    let step = snapshot.steps.first().expect("step");
    let attempt = snapshot.attempts.first().expect("attempt");
    let lease = attempt.lease.as_ref().expect("lease");
    let source_meta = metadata("cmd-dispatch-001", "dispatch-intent-001", "attempt-001");
    let mut envelope = DispatchEnvelope {
        meta: Some(CommandMetadata {
            command_id: "dispatch-001".to_owned(),
            idempotency_key: "dispatch-001".to_owned(),
            idempotency_scope: "attempt-001".to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(Timestamp {
                seconds: FIXED_TIME,
                nanos: 0,
            }),
            correlation_id: source_meta.correlation_id.clone(),
            causation_id: Some(source_meta.command_id.clone()),
        }),
        run_id: run.run_id.clone(),
        run_revision: run.revision + 1,
        step_id: step.step_id.clone(),
        step_revision: step.revision + 1,
        attempt_id: attempt.attempt_id.clone(),
        attempt_revision: attempt.revision + 1,
        dispatch_id: "dispatch-001".to_owned(),
        dispatch_fingerprint: String::new(),
        fencing_token: lease.fencing_token,
        capability_profile_ref: attempt.capability_profile_ref.clone(),
        input_bundle_ref: "input-001".to_owned(),
        input_bundle_sha256: "5".repeat(64),
        workspace_ref: attempt.workspace_ref.clone(),
        budget_profile_ref: run.plan.as_ref().expect("plan").budget_profile_ref.clone(),
        sandbox_profile_ref: Some(contract_ref("sandbox-policy", '6')),
        tool_policy_ref: Some(contract_ref("tool-policy", '7')),
        data_egress_policy_ref: Some(contract_ref("data-egress-policy", '8')),
        approval_policy_ref: Some(contract_ref("approval-policy", '9')),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        native_session_ref: None,
        checkpoint_ref: None,
    };
    let fingerprint = canonical_dispatch_fingerprint(&envelope);
    envelope.dispatch_fingerprint = fingerprint.clone();
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordDispatchIntent(
            RecordDispatchIntentCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(source_meta),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: attempt.attempt_id.clone(),
                    expected_attempt_revision: attempt.revision,
                }),
                lease_id: lease.lease_id.clone(),
                fencing_token: lease.fencing_token,
                dispatch_id: "dispatch-001".to_owned(),
                dispatch_fingerprint: fingerprint,
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn recovered_dispatch_command(
    snapshot: &CollaborationSnapshot,
    envelope: &DispatchEnvelope,
) -> CollaborationCommand {
    let attempt = snapshot.attempts.first().expect("attempt");
    let lease = attempt.lease.as_ref().expect("lease");
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordDispatchIntent(
            RecordDispatchIntentCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(metadata(
                        "cmd-dispatch-001",
                        "dispatch-intent-001",
                        "attempt-001",
                    )),
                    run_id: envelope.run_id.clone(),
                    expected_run_revision: envelope.run_revision - 1,
                    step_id: envelope.step_id.clone(),
                    expected_step_revision: envelope.step_revision - 1,
                    attempt_id: envelope.attempt_id.clone(),
                    expected_attempt_revision: envelope.attempt_revision - 1,
                }),
                lease_id: lease.lease_id.clone(),
                fencing_token: envelope.fencing_token,
                dispatch_id: envelope.dispatch_id.clone(),
                dispatch_fingerprint: envelope.dispatch_fingerprint.clone(),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn unknown_command(snapshot: &CollaborationSnapshot) -> CollaborationCommand {
    let run = snapshot.run.as_ref().expect("run");
    let step = snapshot.steps.first().expect("step");
    let attempt = snapshot.attempts.first().expect("attempt");
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::MarkAttemptOutcomeUnknown(
            MarkAttemptOutcomeUnknownCommand {
                base: Some(AttemptCommandBase {
                    meta: Some(metadata("cmd-unknown-001", "unknown-001", "attempt-001")),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                    step_id: step.step_id.clone(),
                    expected_step_revision: step.revision,
                    attempt_id: attempt.attempt_id.clone(),
                    expected_attempt_revision: attempt.revision,
                }),
                reason_code: "LEASE_EXPIRED_EXTERNAL_OUTCOME_UNKNOWN".to_owned(),
                uncertainty_evidence_id: "uncertainty-001".to_owned(),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn attempt_base(snapshot: &CollaborationSnapshot, command_id: &str) -> AttemptCommandBase {
    let run = snapshot.run.as_ref().expect("run");
    let step = snapshot.steps.first().expect("step");
    let attempt = snapshot.attempts.first().expect("attempt");
    AttemptCommandBase {
        meta: Some(metadata(command_id, command_id, &attempt.attempt_id)),
        run_id: run.run_id.clone(),
        expected_run_revision: run.revision,
        step_id: step.step_id.clone(),
        expected_step_revision: step.revision,
        attempt_id: attempt.attempt_id.clone(),
        expected_attempt_revision: attempt.revision,
    }
}

fn delivery_command(snapshot: &CollaborationSnapshot, fencing_token: u64) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordDeliveryReceipt(
            RecordDeliveryReceiptCommand {
                base: Some(attempt_base(snapshot, "cmd-delivery-001")),
                dispatch_id: "dispatch-001".to_owned(),
                fencing_token,
                delivery_receipt_id: "delivery-001".to_owned(),
                receipt_digest_sha256: "d".repeat(64),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn ack_command(
    snapshot: &CollaborationSnapshot,
    fencing_token: u64,
    harness_sequence: u64,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordHarnessAck(
            RecordHarnessAckCommand {
                base: Some(attempt_base(snapshot, "cmd-ack-001")),
                dispatch_id: "dispatch-001".to_owned(),
                fencing_token,
                harness_sequence,
                ack_receipt_id: "ack-001".to_owned(),
                receipt_digest_sha256: "e".repeat(64),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn running_command(
    snapshot: &CollaborationSnapshot,
    fencing_token: u64,
    harness_sequence: u64,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordRunningObservation(
            RecordRunningObservationCommand {
                base: Some(attempt_base(snapshot, "cmd-running-001")),
                fencing_token,
                harness_sequence,
                lifecycle_event_id: "running-001".to_owned(),
                event_digest_sha256: "f".repeat(64),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn committed_snapshot(result: &CollaborationCommandResult) -> CollaborationSnapshot {
    match result.outcome.clone().expect("result outcome") {
        collaboration_command_result::Outcome::Snapshot(snapshot) => snapshot,
        collaboration_command_result::Outcome::Error(error) => {
            panic!("expected snapshot, got {}", error.safe_detail_code)
        }
    }
}

fn error_code(result: &CollaborationCommandResult) -> CollaborationErrorCode {
    match result.outcome.as_ref().expect("result outcome") {
        collaboration_command_result::Outcome::Error(error) => {
            CollaborationErrorCode::try_from(error.code).expect("known error code")
        }
        collaboration_command_result::Outcome::Snapshot(_) => panic!("expected error"),
    }
}

fn load_snapshot(
    control: &CollaborationControl<FixtureGuard, FixedClock>,
) -> CollaborationSnapshot {
    match control
        .get_collaboration("run-001")
        .expect("get collaboration")
        .outcome
        .expect("get outcome")
    {
        get_collaboration_response::Outcome::Snapshot(snapshot) => snapshot,
        get_collaboration_response::Outcome::Error(error) => {
            panic!("missing collaboration: {}", error.safe_detail_code)
        }
    }
}

fn advance_through_lease(
    control: &mut CollaborationControl<FixtureGuard, FixedClock>,
) -> CollaborationSnapshot {
    control
        .execute(&create_run_command(), &task_authority())
        .expect("create Run");
    control
        .execute(&activate_run_command(), &task_authority())
        .expect("activate Run");
    control
        .execute(
            &create_attempt_command(2, 1, "attempt-001"),
            &collaboration_control(),
        )
        .expect("create Attempt");
    let leased = control
        .execute(&acquire_lease_command(3, 2, 1), &attempt_supervisor())
        .expect("acquire lease");
    committed_snapshot(&leased)
}

fn advance_through_dispatch(
    control: &mut CollaborationControl<FixtureGuard, FixedClock>,
) -> (CollaborationSnapshot, CollaborationCommand) {
    let leased = advance_through_lease(control);
    let command = dispatch_command(&leased);
    let dispatched = control
        .execute(&command, &attempt_supervisor())
        .expect("record dispatch intent");
    (committed_snapshot(&dispatched), command)
}

#[test]
fn delivery_ack_and_running_are_separate_durable_monotonic_facts() {
    let isolated = IsolatedStore::new("collaboration-harness-facts");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    let (dispatch_pending, _) = advance_through_dispatch(&mut control);
    let fence = dispatch_pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    assert_eq!(
        control
            .inspect_store()
            .expect("inspect")
            .pending_dispatch_count,
        1
    );

    let delivery_command = delivery_command(&dispatch_pending, fence);
    let delivered_result = control
        .execute(&delivery_command, &harness_adapter())
        .expect("record delivery");
    let delivered = committed_snapshot(&delivered_result);
    assert_eq!(
        delivered.attempts[0].status,
        AttemptStatus::Dispatched as i32
    );
    assert_eq!(
        delivered.attempts[0].harness_session_ref.as_deref(),
        Some("codex-thread-001")
    );
    assert_eq!(
        control
            .inspect_store()
            .expect("inspect")
            .pending_dispatch_count,
        0
    );
    let event_count = control.inspect_store().expect("inspect").event_count;
    let replay = control
        .execute(&delivery_command, &harness_adapter())
        .expect("replay delivery");
    assert!(replay.replayed);
    assert_eq!(
        control.inspect_store().expect("inspect").event_count,
        event_count
    );

    let acknowledged = committed_snapshot(
        &control
            .execute(&ack_command(&delivered, fence, 1), &harness_adapter())
            .expect("record ACK"),
    );
    assert_eq!(
        acknowledged.attempts[0].status,
        AttemptStatus::Acknowledged as i32
    );
    assert_eq!(acknowledged.attempts[0].last_harness_sequence, 1);

    let running = committed_snapshot(
        &control
            .execute(
                &running_command(&acknowledged, fence, 2),
                &harness_adapter(),
            )
            .expect("record running"),
    );
    assert_eq!(running.attempts[0].status, AttemptStatus::Running as i32);
    assert_eq!(running.attempts[0].last_harness_sequence, 2);
    assert!(control.integrity_is_ok().expect("integrity"));
}

#[test]
fn ack_before_delivery_stale_fence_and_out_of_order_sequence_are_zero_write_failures() {
    let isolated = IsolatedStore::new("collaboration-harness-rejections");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    let (dispatch_pending, _) = advance_through_dispatch(&mut control);
    let fence = dispatch_pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let before = control.inspect_store().expect("inspect");
    let early_ack = control
        .execute(
            &ack_command(&dispatch_pending, fence, 1),
            &harness_adapter(),
        )
        .expect("reject early ACK");
    assert_eq!(
        error_code(&early_ack),
        CollaborationErrorCode::StateConflict
    );
    assert_eq!(control.inspect_store().expect("inspect"), before);

    let delivered = committed_snapshot(
        &control
            .execute(
                &delivery_command(&dispatch_pending, fence),
                &harness_adapter(),
            )
            .expect("record delivery"),
    );
    let before_stale = control.inspect_store().expect("inspect");
    let stale_ack = control
        .execute(&ack_command(&delivered, fence + 1, 1), &harness_adapter())
        .expect("reject stale ACK");
    assert_eq!(
        error_code(&stale_ack),
        CollaborationErrorCode::FencingRejected
    );
    assert_eq!(control.inspect_store().expect("inspect"), before_stale);

    let acknowledged = committed_snapshot(
        &control
            .execute(&ack_command(&delivered, fence, 1), &harness_adapter())
            .expect("record ACK"),
    );
    let before_sequence = control.inspect_store().expect("inspect");
    let out_of_order = control
        .execute(
            &running_command(&acknowledged, fence, 1),
            &harness_adapter(),
        )
        .expect("reject out-of-order running");
    assert_eq!(
        error_code(&out_of_order),
        CollaborationErrorCode::SequenceConflict
    );
    assert_eq!(control.inspect_store().expect("inspect"), before_sequence);
}

#[test]
fn hierarchy_lease_dispatch_and_duplicate_are_one_durable_sequence() {
    let isolated = IsolatedStore::new("collaboration-sequence");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    let (snapshot, dispatch) = advance_through_dispatch(&mut control);

    let run = snapshot.run.as_ref().expect("run");
    let step = snapshot.steps.first().expect("step");
    let attempt = snapshot.attempts.first().expect("attempt");
    assert_eq!(run.revision, 5);
    assert_eq!(run.status, RunStatus::Active as i32);
    assert_eq!(step.revision, 4);
    assert_eq!(step.status, StepStatus::Active as i32);
    assert_eq!(attempt.revision, 3);
    assert_eq!(attempt.status, AttemptStatus::DispatchPending as i32);

    let pending = control
        .pending_dispatches(&harness_adapter())
        .expect("pending dispatch");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelope.dispatch_id, "dispatch-001");
    assert_eq!(pending[0].envelope.run_revision, 5);
    assert_eq!(pending[0].envelope.step_revision, 4);
    assert_eq!(pending[0].envelope.attempt_revision, 3);
    assert!(matches!(
        control.pending_dispatches(&recovery_worker()),
        Err(CollaborationControlError::DispatchPollNotAuthorized)
    ));
    let baseline = control.inspect_store().expect("inspect dispatch store");
    assert_eq!(baseline.run_count, 1);
    assert_eq!(baseline.step_count, 1);
    assert_eq!(baseline.attempt_count, 1);
    assert_eq!(baseline.event_count, 5);
    assert_eq!(baseline.idempotency_count, 5);
    assert_eq!(baseline.outbox_count, 6);
    assert_eq!(baseline.pending_dispatch_count, 1);
    assert_eq!(baseline.commit_receipt_count, 5);
    assert_eq!(baseline.last_event_sequence, 5);

    let mut duplicate = dispatch;
    if let Some(collaboration_command::Command::RecordDispatchIntent(value)) =
        duplicate.command.as_mut()
    {
        let meta = value
            .base
            .as_mut()
            .expect("base")
            .meta
            .as_mut()
            .expect("meta");
        meta.command_id = "cmd-dispatch-retry-001".to_owned();
        meta.correlation_id = "corr-retry".to_owned();
        meta.issued_at = Some(Timestamp {
            seconds: FIXED_TIME + 1,
            nanos: 0,
        });
    }
    let replayed = control
        .execute(&duplicate, &attempt_supervisor())
        .expect("replay dispatch intent");
    assert!(replayed.replayed);
    assert_eq!(control.inspect_store().expect("inspect replay"), baseline);

    let mut conflict = duplicate;
    if let Some(collaboration_command::Command::RecordDispatchIntent(value)) =
        conflict.command.as_mut()
    {
        value.dispatch_id = "dispatch-conflict".to_owned();
    }
    set_digest(&mut conflict);
    let rejected = control
        .execute(&conflict, &attempt_supervisor())
        .expect("reject idempotency conflict");
    assert_eq!(
        error_code(&rejected),
        CollaborationErrorCode::IdempotencyConflict
    );
    assert_eq!(control.inspect_store().expect("inspect conflict"), baseline);
}

#[test]
fn capacity_and_stale_cas_fail_with_zero_business_writes() {
    let isolated = IsolatedStore::new("collaboration-cas");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    control
        .execute(&create_run_command(), &task_authority())
        .expect("create Run");
    control
        .execute(&activate_run_command(), &task_authority())
        .expect("activate Run");
    control
        .execute(
            &create_attempt_command(2, 1, "attempt-001"),
            &collaboration_control(),
        )
        .expect("create first Attempt");
    let baseline = control.inspect_store().expect("baseline counts");

    let overlap = control
        .execute(
            &create_attempt_command(3, 2, "attempt-002"),
            &collaboration_control(),
        )
        .expect("reject overlap");
    assert_eq!(
        error_code(&overlap),
        CollaborationErrorCode::CapacityExhausted
    );
    assert_eq!(control.inspect_store().expect("after overlap"), baseline);

    let stale = control
        .execute(&acquire_lease_command(2, 2, 1), &attempt_supervisor())
        .expect("reject stale Run CAS");
    assert_eq!(
        error_code(&stale),
        CollaborationErrorCode::RunRevisionConflict
    );
    assert_eq!(control.inspect_store().expect("after stale"), baseline);

    let stale_step = control
        .execute(&acquire_lease_command(3, 1, 1), &attempt_supervisor())
        .expect("reject stale Step CAS");
    assert_eq!(
        error_code(&stale_step),
        CollaborationErrorCode::EntityRevisionConflict
    );
    assert_eq!(control.inspect_store().expect("after stale Step"), baseline);

    let stale_attempt = control
        .execute(&acquire_lease_command(3, 2, 0), &attempt_supervisor())
        .expect("reject stale Attempt CAS");
    assert_eq!(
        error_code(&stale_attempt),
        CollaborationErrorCode::EntityRevisionConflict
    );
    assert_eq!(
        control.inspect_store().expect("after stale Attempt"),
        baseline
    );

    let harness = principal(CollaborationPrincipalKind::HarnessAdapter, "adapter:codex");
    let unauthorized = control
        .execute(&create_attempt_command(3, 2, "attempt-002"), &harness)
        .expect("reject Harness authority write");
    assert_eq!(
        error_code(&unauthorized),
        CollaborationErrorCode::PermissionDenied
    );
    assert_eq!(
        control.inspect_store().expect("after unauthorized"),
        baseline
    );

    let artifact = principal(
        CollaborationPrincipalKind::ArtifactAuthority,
        "artifact-authority:test",
    );
    let unauthorized = control
        .execute(&create_attempt_command(3, 2, "attempt-002"), &artifact)
        .expect("reject Artifact authority retry creation");
    assert_eq!(
        error_code(&unauthorized),
        CollaborationErrorCode::PermissionDenied
    );
    assert_eq!(
        control.inspect_store().expect("after Artifact attempt"),
        baseline
    );
}

#[test]
fn expired_lease_rejects_dispatch_without_a_write() {
    let isolated = IsolatedStore::new("collaboration-expired-fence");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let leased = advance_through_lease(&mut control);
    let dispatch = dispatch_command(&leased);
    let baseline = control.inspect_store().expect("lease baseline");

    let mut stale_fence = dispatch.clone();
    if let Some(collaboration_command::Command::RecordDispatchIntent(value)) =
        stale_fence.command.as_mut()
    {
        value.fencing_token = value.fencing_token.saturating_sub(1);
    }
    set_digest(&mut stale_fence);
    let stale = control
        .execute(&stale_fence, &attempt_supervisor())
        .expect("reject stale fence");
    assert_eq!(error_code(&stale), CollaborationErrorCode::FencingRejected);
    assert_eq!(
        control.inspect_store().expect("after stale fence"),
        baseline
    );

    let unauthorized = control
        .execute(&dispatch, &recovery_worker())
        .expect("Recovery worker cannot dispatch");
    assert_eq!(
        error_code(&unauthorized),
        CollaborationErrorCode::PermissionDenied
    );
    assert_eq!(
        control.inspect_store().expect("after Recovery dispatch"),
        baseline
    );
    clock.set_seconds(FIXED_TIME + 31);

    let rejected = control
        .execute(&dispatch, &attempt_supervisor())
        .expect("reject expired lease");
    assert_eq!(
        error_code(&rejected),
        CollaborationErrorCode::FencingRejected
    );
    assert_eq!(control.inspect_store().expect("after expired"), baseline);
    assert!(
        control
            .pending_dispatches(&harness_adapter())
            .expect("no dispatches")
            .is_empty()
    );
}

#[test]
fn unknown_outcome_holds_the_attempt_and_existing_dispatch_outbox() {
    let isolated = IsolatedStore::new("collaboration-unknown");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let (dispatched, _) = advance_through_dispatch(&mut control);
    assert_eq!(
        control
            .inspect_store()
            .expect("dispatch counts")
            .pending_dispatch_count,
        1
    );
    clock.set_seconds(FIXED_TIME + 31);

    let unknown = unknown_command(&dispatched);
    let result = control
        .execute(&unknown, &recovery_worker())
        .expect("mark unknown outcome");
    let snapshot = committed_snapshot(&result);
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Held as i32
    );
    assert_eq!(snapshot.steps[0].status, StepStatus::Held as i32);
    assert_eq!(
        snapshot.attempts[0].status,
        AttemptStatus::OutcomeUnknown as i32
    );
    let counts = control.inspect_store().expect("unknown counts");
    assert_eq!(counts.event_count, 6);
    assert_eq!(counts.outbox_count, 7);
    assert_eq!(counts.pending_dispatch_count, 0);
    assert!(
        control
            .pending_dispatches(&harness_adapter())
            .expect("held dispatches")
            .is_empty()
    );

    let replayed = control
        .execute(&unknown, &recovery_worker())
        .expect("replay unknown outcome");
    assert!(replayed.replayed);
    assert_eq!(control.inspect_store().expect("unknown replay"), counts);
}

#[test]
fn dispatch_intent_survives_abort_before_adapter_delivery() {
    let isolated = IsolatedStore::new("collaboration-abort");
    let path = isolated.database_path();
    let status =
        Command::new(std::env::current_exe().expect("current integration test executable"))
            .arg("--exact")
            .arg("crash_probe_child")
            .arg("--nocapture")
            .env("EGOPULSE_G4_03_CRASH_PROBE", "1")
            .env("EGOPULSE_G4_03_CRASH_DB", &path)
            .status()
            .expect("launch crash probe child");
    assert!(!status.success(), "crash probe must abort after commit");

    let bytes = fs::read(&path).expect("read encrypted Collaboration store");
    assert!(bytes.len() >= 16);
    assert_ne!(&bytes[..16], b"SQLite format 3\0");

    let clock = FixedClock::new(FIXED_TIME);
    let mut recovered = open_control(&path, clock);
    assert!(recovered.integrity_is_ok().expect("integrity after abort"));
    let pending = recovered
        .pending_dispatches(&harness_adapter())
        .expect("recovered dispatch");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].envelope.dispatch_id, "dispatch-001");

    let snapshot = load_snapshot(&recovered);
    let replayed = recovered
        .execute(
            &recovered_dispatch_command(&snapshot, &pending[0].envelope),
            &attempt_supervisor(),
        )
        .expect("replay committed dispatch after abort");
    assert!(replayed.replayed);
    let counts = recovered.inspect_store().expect("recovered counts");
    assert_eq!(counts.event_count, 5);
    assert_eq!(counts.outbox_count, 6);
    assert_eq!(counts.pending_dispatch_count, 1);
}

#[test]
fn crash_probe_child() {
    if std::env::var("EGOPULSE_G4_03_CRASH_PROBE").as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(
        std::env::var_os("EGOPULSE_G4_03_CRASH_DB").expect("crash probe database path"),
    );
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&path, clock);
    let (_, _) = advance_through_dispatch(&mut control);
    std::process::abort();
}
