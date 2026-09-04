use egopulse_codex_adapter::{FakeCodexDriver, codex_protocol_fingerprint};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{LineageBinding, ReturnReceipt};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptCancellationDisposition,
    AttemptCommandBase, AttemptSnapshot, AttemptStatus, BeginAttemptReconciliationCommand,
    CollaborationCommand, CollaborationCommandResult, CollaborationErrorCode,
    CollaborationSnapshot, CommitStepReturnCommand, CreateAttemptCommand, CreateRunCommand,
    MarkAttemptOutcomeUnknownCommand, ReconciliationDisposition,
    RecordAttemptCancellationOutcomeCommand, RecordAttemptReconciliationCommand,
    RecordAttemptReturnCommand, RecordDeliveryReceiptCommand, RecordDispatchIntentCommand,
    RecordHarnessAckCommand, RecordRunningObservationCommand, RecoveryClass,
    RequestAttemptCancellationCommand, RunCommandBase, RunPlan, RunSnapshot, RunStatus, StepPlan,
    StepSnapshot, StepStatus, collaboration_command, collaboration_command_result,
    get_collaboration_response,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, ApprovalDecisionEnvelope, CancelExecutionEnvelope, DeliveryDisposition,
    DispatchEnvelope, DispatchReceipt, HarnessAckObservation, HarnessErrorCode, HarnessObservation,
    LifecycleKind, LifecycleObservation, NativeSessionStrategy, ObservationCriticality,
    ProbeHarnessRequest, ProbeHarnessResult, SideEffectCertainty, dispatch_result,
    harness_observation,
};
use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskSnapshot, TaskStatus};
use egopulse_harness_adapter::{
    AdapterClock, AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, DispatchMaterialResolver,
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, GovernedHarnessAdapter,
    NativeHarnessDriver, NativeHarnessFuture, ReconciliationContext, ReconciliationFinding,
    ResolvedDispatchMaterial,
};
use egopulse_local_ide_control::collaboration_control::{
    AdapterBackedHarnessEvidenceResolver, ArtifactReturnSource,
    AuthenticatedCollaborationPrincipal, AuthorityClock, CollaborationControl,
    CollaborationControlConfig, CollaborationControlError, CollaborationLineageReader,
    CollaborationLineageReaderConfig, CollaborationPrincipalKind, CollaborationReferenceGuard,
    CollaborationSqlCipherKey, CompositeCollaborationGuard, DELIVERY_OUTCOME_UNKNOWN_REASON_CODE,
    DispatchMaterial, GovernedHarnessDispatchRunner, GovernedTaskActivationRunner,
    HarnessDispatchRunner, HarnessEvidenceResolver, HarnessFactIngestionDisposition,
    HeldDispatchRecoveryState, LeaseAuthorization, PendingArtifactReturn, ReferenceAuthorization,
    ReferenceGuardRejection, ResolvedArtifactReturn, ResolvedHarnessEvidence, ResolvedStepReturn,
    SingleHarnessWorkConfig, SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolver,
    SingleHarnessWorkflowResolverError, TaskActivationGuardSet, TaskActivationHandoff,
    TaskActivationReferenceGuard, TaskActivationSource, TaskActivationSourceError,
    canonical_dispatch_fingerprint, canonical_request_digest, dispatch_pending, pump_observations,
    start_single_harness_workflow,
};
use prost::Message;
use prost_types::Timestamp;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const STORE_EPOCH: &str = "collaboration-store-g4-03-test";
const TEST_KEY: [u8; 32] = [0x63; 32];
const ADAPTER_TEST_KEY: [u8; 32] = [0x64; 32];
const FIXED_TIME: i64 = 1_777_073_600;
const MIGRATION_CRASH_PROBE: &str = "EGOPULSE_G4_08A_COLLABORATION_MIGRATION_CRASH_PROBE";
const MIGRATION_CRASH_DB: &str = "EGOPULSE_G4_08A_COLLABORATION_MIGRATION_CRASH_DB";

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

impl AdapterClock for FixedClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().expect("clock mutex")
    }
}

struct CountingRecoveryDriver {
    reconcile_count: Arc<AtomicU64>,
    finding: ReconciliationFinding,
}

#[derive(Clone, Default)]
struct DriverCallCounts {
    send: Arc<AtomicU64>,
    next: Arc<AtomicU64>,
    reconcile: Arc<AtomicU64>,
    order: Arc<Mutex<Vec<String>>>,
}

struct ScriptedCountingDriver {
    counts: DriverCallCounts,
    events: VecDeque<DriverEvent>,
    required_consumed: Option<(PathBuf, String, String)>,
    reconciliation_finding: ReconciliationFinding,
}

impl ScriptedCountingDriver {
    fn new(counts: DriverCallCounts, events: Vec<DriverEvent>) -> Self {
        Self {
            counts,
            events: events.into(),
            required_consumed: None,
            reconciliation_finding: ReconciliationFinding::OutcomeUnknown {
                evidence_ref: "fixture://scripted/outcome-unknown".to_owned(),
            },
        }
    }

    fn requiring_consumed(
        mut self,
        database_path: &Path,
        dispatch_id: &str,
        observation_id: &str,
    ) -> Self {
        self.required_consumed = Some((
            database_path.to_owned(),
            dispatch_id.to_owned(),
            observation_id.to_owned(),
        ));
        self
    }

    fn assert_required_observation_consumed(&self) {
        let Some((database_path, dispatch_id, observation_id)) = self.required_consumed.as_ref()
        else {
            return;
        };
        let edge = open_loop_adapter_edge(database_path);
        let evidence = edge
            .observation_evidence(observation_id)
            .expect("read durable observation evidence")
            .expect("consumed observation row must remain durable");
        assert_eq!(evidence.observation.observation_id, *observation_id);
        assert_eq!(evidence.observation.dispatch_id, *dispatch_id);
        assert_eq!(
            evidence.observation.native_event_digest_sha256,
            hex::encode(Sha256::digest(&evidence.raw_event)),
            "consumed observation raw evidence digest drifted"
        );
        let ingestion_state: String = open_raw_adapter_store(database_path)
            .query_row(
                "SELECT ingestion_state FROM adapter_observations
                 WHERE observation_id = ?1 AND dispatch_id = ?2",
                params![observation_id, dispatch_id],
                |row| row.get(0),
            )
            .expect("read consumed observation ingestion state");
        assert_eq!(ingestion_state, "consumed");
        let view = edge
            .normal_observation_recovery_view(dispatch_id, "single-harness-capability")
            .expect("read durable observation precondition");
        assert!(
            !view
                .pending
                .iter()
                .any(|observation| observation.observation_id == *observation_id),
            "native side effect ran before the durable observation settled"
        );
    }
}

impl NativeHarnessDriver for ScriptedCountingDriver {
    fn probe<'a>(
        &'a mut self,
        _request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async { panic!("probe not expected") })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        self.assert_required_observation_consumed();
        self.counts.send.fetch_add(1, Ordering::SeqCst);
        self.counts
            .order
            .lock()
            .expect("driver order mutex")
            .push(format!("send:{}", envelope.dispatch_id));
        let dispatch_id = envelope.dispatch_id.clone();
        Box::pin(async move {
            Ok(DriverDelivery {
                native_request_ref: format!("scripted-request:{dispatch_id}"),
                native_session_ref: format!("scripted-session:{dispatch_id}"),
                native_execution_ref: Some(format!("scripted-execution:{dispatch_id}")),
                raw_evidence: format!("scripted-delivery:{dispatch_id}").into_bytes(),
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        self.assert_required_observation_consumed();
        self.counts.next.fetch_add(1, Ordering::SeqCst);
        self.counts
            .order
            .lock()
            .expect("driver order mutex")
            .push(format!("next:{}", envelope.dispatch_id));
        let event = self.events.pop_front();
        Box::pin(async move { Ok(event) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("approval not expected") })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("cancel not expected") })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        self.counts.reconcile.fetch_add(1, Ordering::SeqCst);
        self.counts
            .order
            .lock()
            .expect("driver order mutex")
            .push("reconcile".to_owned());
        let finding = self.reconciliation_finding.clone();
        Box::pin(async move { Ok(finding) })
    }
}

impl NativeHarnessDriver for CountingRecoveryDriver {
    fn probe<'a>(
        &'a mut self,
        _request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async { panic!("probe not expected") })
    }
    fn send_dispatch<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async { panic!("held dispatch must never be sent") })
    }
    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async { panic!("held dispatch must never pump native observations") })
    }
    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("approval not expected") })
    }
    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("cancel not expected") })
    }
    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        self.reconcile_count.fetch_add(1, Ordering::SeqCst);
        let finding = self.finding.clone();
        Box::pin(async move { Ok(finding) })
    }
}

struct ProvenNotSentDriver {
    send_count: Arc<AtomicU64>,
    next_event_count: Arc<AtomicU64>,
}

impl NativeHarnessDriver for ProvenNotSentDriver {
    fn probe<'a>(
        &'a mut self,
        _request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async { panic!("probe not expected") })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        self.send_count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(DriverError {
                certainty: DriverErrorCertainty::ProvenNotSent,
                code: HarnessErrorCode::DependencyUnavailable,
                safe_detail_code: "FIXTURE_PROVEN_NOT_SENT".to_owned(),
                error_fingerprint: None,
                raw_evidence: b"fixture-proven-not-sent".to_vec(),
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        self.next_event_count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("approval not expected") })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async { panic!("cancel not expected") })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async { panic!("reconciliation not expected") })
    }
}

struct FixtureActivationSource {
    pending: Mutex<Vec<TaskActivationHandoff>>,
    acknowledged: Mutex<Vec<String>>,
}

impl TaskActivationSource for FixtureActivationSource {
    fn pending_task_activations(
        &self,
    ) -> Result<Vec<TaskActivationHandoff>, TaskActivationSourceError> {
        Ok(self
            .pending
            .lock()
            .expect("activation source mutex")
            .clone())
    }

    fn acknowledge_task_activation(
        &self,
        message_id: &str,
        _payload_digest_sha256: &str,
    ) -> Result<bool, TaskActivationSourceError> {
        self.acknowledged
            .lock()
            .expect("activation acknowledgement mutex")
            .push(message_id.to_owned());
        self.pending
            .lock()
            .expect("activation source mutex")
            .retain(|value| value.message_id != message_id);
        Ok(true)
    }
}

struct FixtureArtifactReturnSource {
    pending: Mutex<Vec<PendingArtifactReturn>>,
    acknowledged: Mutex<Vec<String>>,
}

impl ArtifactReturnSource for FixtureArtifactReturnSource {
    fn pending_returns(&self) -> Result<Vec<PendingArtifactReturn>, String> {
        Ok(self.pending.lock().expect("return source mutex").clone())
    }

    fn acknowledge_return(
        &self,
        message_id: &str,
        _payload_digest_sha256: &str,
    ) -> Result<bool, String> {
        self.acknowledged
            .lock()
            .expect("return acknowledgement mutex")
            .push(message_id.to_owned());
        self.pending
            .lock()
            .expect("return source mutex")
            .retain(|value| value.message_id != message_id);
        Ok(true)
    }
}

struct FixtureReturnEvidence {
    adapter: AdapterBackedHarnessEvidenceResolver,
    verification_available: Arc<Mutex<bool>>,
}

impl HarnessEvidenceResolver for FixtureReturnEvidence {
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.adapter.resolve_delivery_receipt(command, snapshot)
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.adapter.resolve_harness_ack(command, snapshot)
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.adapter.validate_running_observation(command, snapshot)
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.adapter
            .validate_cancellation_outcome(command, snapshot)
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.adapter.validate_reconciliation(command, snapshot)
    }

    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        if command.artifact_return_receipt_id != "return-receipt-runner-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedArtifactReturn {
            artifact_set_id: "artifact-set-runner-001".to_owned(),
            return_handoff_id: "return-handoff-runner-001".to_owned(),
            dispatch_id: snapshot
                .attempts
                .iter()
                .find_map(|attempt| attempt.dispatch_id.clone())
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?,
            evidence_refs: vec!["fixture:artifact-return@durable".to_owned()],
        })
    }

    fn resolve_step_return(
        &self,
        command: &CommitStepReturnCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        if !*self
            .verification_available
            .lock()
            .expect("Verification availability mutex")
            || command.artifact_set_id != "artifact-set-runner-001"
            || command.return_handoff_id != "return-handoff-runner-001"
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedStepReturn {
            artifact_set_id: command.artifact_set_id.clone(),
            return_handoff_id: command.return_handoff_id.clone(),
            verification_artifact_id: "verification-artifact-runner-001".to_owned(),
            evidence_refs: vec!["fixture:verification@durable".to_owned()],
        })
    }
}

#[derive(Clone)]
struct FixtureWorkflowResolver(SingleHarnessWorkConfig);

impl SingleHarnessWorkflowResolver for FixtureWorkflowResolver {
    fn resolve(
        &self,
        activation: &TaskActivationHandoff,
    ) -> Result<SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolverError> {
        if activation.task.current_run_id.as_deref() != Some(self.0.run_id.as_str()) {
            return Ok(SingleHarnessWorkflowResolution::NotApplicable);
        }
        Ok(SingleHarnessWorkflowResolution::Resolved(Box::new(
            self.0.clone(),
        )))
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
        if !matches!(
            command.uncertainty_evidence_id.as_str(),
            "uncertainty-001" | "unknown-terminal-001"
        ) {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["lease-expired:external-stop-not-proven".to_owned()],
        })
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.task_cancellation_request_id != "task-cancel-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["task-cancellation:verified".to_owned()],
        })
    }
}

impl HarnessEvidenceResolver for FixtureGuard {
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        if !matches!(
            command.delivery_receipt_id.as_str(),
            "delivery-001" | "delivery-dispatch-002"
        ) {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: Some("codex-thread-001".to_owned()),
            evidence_refs: vec![format!(
                "adapter-receipt:{}@durable",
                command.delivery_receipt_id
            )],
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

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if !matches!(
            command.cancellation_receipt_id.as_str(),
            "cancel-receipt-001" | "interrupted-001"
        ) {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["adapter-cancellation:durable".to_owned()],
        })
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        if command.evidence_id != "reconcile-evidence-001" {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec!["adapter-reconciliation:durable".to_owned()],
        })
    }

    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        if command.artifact_return_receipt_id != "return-receipt-001"
            || command.receipt_digest_sha256 != "a".repeat(64)
            || command.harness_sequence != 3
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedArtifactReturn {
            artifact_set_id: "artifact-set-001".to_owned(),
            return_handoff_id: "return-handoff-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            evidence_refs: vec![
                "artifact-return-receipt:return-receipt-001@durable".to_owned(),
                "adapter-terminal-observation:terminal-001@durable".to_owned(),
            ],
        })
    }

    fn resolve_step_return(
        &self,
        command: &CommitStepReturnCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        if command.artifact_set_id != "artifact-set-001"
            || command.return_handoff_id != "return-handoff-001"
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedStepReturn {
            artifact_set_id: command.artifact_set_id.clone(),
            return_handoff_id: command.return_handoff_id.clone(),
            verification_artifact_id: "verification-artifact-001".to_owned(),
            evidence_refs: vec![
                "verification-artifact:verification-artifact-001@durable".to_owned(),
            ],
        })
    }
}

#[test]
fn task_activation_guard_set_delegates_verification_step_evidence() {
    let (guard, _reference) = TaskActivationGuardSet::new(FixtureGuard);
    let command = CommitStepReturnCommand {
        artifact_set_id: "artifact-set-001".to_owned(),
        return_handoff_id: "return-handoff-001".to_owned(),
        ..CommitStepReturnCommand::default()
    };

    let resolved = guard
        .resolve_step_return(&command, &CollaborationSnapshot::default())
        .expect("Verification evidence must cross the activation guard boundary");
    assert_eq!(
        resolved.verification_artifact_id,
        "verification-artifact-001"
    );
}

struct AdapterBackedFixtureGuard {
    edge: AdapterEdge,
    input_bundle_sha256: String,
}

impl CollaborationReferenceGuard for AdapterBackedFixtureGuard {
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        FixtureGuard.validate_create_run(command)
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        FixtureGuard.validate_activate_run(command, run)
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        run: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot,
        step: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        FixtureGuard.validate_create_attempt(command, run, step)
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        FixtureGuard.authorize_lease(command, attempt)
    }

    fn resolve_dispatch_material(
        &self,
        _command: &RecordDispatchIntentCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        let mut material = dispatch_material();
        material.input_bundle_sha256 = self.input_bundle_sha256.clone();
        Ok(material)
    }

    fn validate_unknown_outcome(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        FixtureGuard.validate_unknown_outcome(command, snapshot)
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        FixtureGuard.validate_cancellation_request(command, snapshot)
    }
}

impl HarnessEvidenceResolver for AdapterBackedFixtureGuard {
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        let receipt = self
            .edge
            .dispatch_receipt(&command.dispatch_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt_id = command
            .base
            .as_ref()
            .map(|value| value.attempt_id.as_str())
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if receipt.receipt_id != command.delivery_receipt_id
            || receipt.receipt_digest_sha256 != command.receipt_digest_sha256
            || receipt.attempt_id != attempt_id
            || receipt.fencing_token != command.fencing_token
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: receipt.native_session_ref,
            evidence_refs: vec![format!(
                "adapter-receipt:{}@durable",
                command.delivery_receipt_id
            )],
        })
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence_by_sequence(&command.dispatch_id, command.harness_sequence)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let ack = match evidence.observation.payload.as_ref() {
            Some(harness_observation::Payload::Ack(value)) => value,
            _ => return Err(ReferenceGuardRejection::UnverifiedReference),
        };
        if evidence.observation.native_event_digest_sha256 != command.receipt_digest_sha256
            || evidence.observation.fencing_token != command.fencing_token
            || ack.ack_receipt_id != command.ack_receipt_id
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: ack.native_session_ref.clone(),
            evidence_refs: vec![format!(
                "adapter-observation:{}@durable",
                evidence.observation.observation_id
            )],
        })
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.lifecycle_event_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|value| {
                Some(value.attempt_id.as_str())
                    == command.base.as_ref().map(|base| base.attempt_id.as_str())
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if evidence.observation.dispatch_id != attempt.dispatch_id.clone().unwrap_or_default()
            || evidence.observation.observation_sequence != command.harness_sequence
            || evidence.observation.fencing_token != command.fencing_token
            || evidence.observation.native_event_digest_sha256 != command.event_digest_sha256
            || !matches!(
                evidence.observation.payload,
                Some(harness_observation::Payload::Lifecycle(ref value))
                    if value.kind == LifecycleKind::ExecutionStarted as i32
            )
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-observation:{}@durable",
                command.lifecycle_event_id
            )],
        })
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.cancellation_receipt_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if !matches!(
            evidence.observation.payload,
            Some(harness_observation::Payload::Lifecycle(ref value))
                if value.kind == LifecycleKind::ExecutionInterrupted as i32
        ) {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-cancellation-observation:{}@durable",
                command.cancellation_receipt_id
            )],
        })
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.evidence_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let diagnostic = match evidence.observation.payload {
            Some(harness_observation::Payload::Diagnostic(value)) => value,
            _ => return Err(ReferenceGuardRejection::UnverifiedReference),
        };
        let disposition = ReconciliationDisposition::try_from(command.disposition)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        if evidence.observation.native_event_id.as_deref()
            != Some(command.reconciliation_id.as_str())
            || !matches!(
                (diagnostic.safe_diagnostic_code.as_str(), disposition),
                (
                    "ADAPTER_RECONCILIATION_NO_EFFECT_PROVEN",
                    ReconciliationDisposition::NoEffectProven
                )
            )
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-reconciliation:{}@durable",
                command.evidence_id
            )],
        })
    }
}

#[derive(Clone)]
struct LoopMaterialResolver {
    bundle: Vec<u8>,
    workspace_root: PathBuf,
}

impl DispatchMaterialResolver for LoopMaterialResolver {
    fn resolve(
        &self,
        _envelope: &DispatchEnvelope,
    ) -> Result<
        ResolvedDispatchMaterial,
        egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessError,
    > {
        Ok(ResolvedDispatchMaterial {
            canonical_input_bundle: self.bundle.clone(),
            prompt: "provider-neutral collaboration loop fixture".to_owned(),
            workspace_root: self.workspace_root.clone(),
            model: None,
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
    open_control_with_guard(path, clock, FixtureGuard)
}

fn open_raw_collaboration_store(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open encrypted Collaboration store");
    connection
        .pragma_update(None, "key", format!("x'{}'", hex::encode(TEST_KEY)))
        .expect("apply Collaboration SQLCipher key");
    connection
}

fn open_raw_adapter_store(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open encrypted Adapter store");
    connection
        .pragma_update(None, "key", format!("x'{}'", hex::encode(ADAPTER_TEST_KEY)))
        .expect("apply Adapter SQLCipher key");
    connection
}

fn open_loop_adapter_edge(path: &Path) -> AdapterEdge {
    open_loop_adapter_edge_for(path, "adapter:codex", "collaboration-loop-adapter-edge-v1")
}

fn open_loop_adapter_edge_for(path: &Path, adapter_id: &str, store_epoch: &str) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path.to_owned(),
        adapter_id: adapter_id.to_owned(),
        store_epoch: store_epoch.to_owned(),
        key: AdapterEdgeKey::new(ADAPTER_TEST_KEY),
    })
    .expect("open Collaboration loop Adapter edge")
}

fn open_control_with_guard<G>(
    path: &Path,
    clock: FixedClock,
    guard: G,
) -> CollaborationControl<G, FixedClock>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
{
    CollaborationControl::open(
        CollaborationControlConfig {
            database_path: path.to_owned(),
            store_epoch: STORE_EPOCH.to_owned(),
            key: CollaborationSqlCipherKey::new(TEST_KEY),
        },
        guard,
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

fn artifact_authority() -> AuthenticatedCollaborationPrincipal {
    principal(
        CollaborationPrincipalKind::ArtifactAuthority,
        "artifact-authority:test",
    )
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

fn scripted_event(
    native_key: &str,
    criticality: ObservationCriticality,
    payload: harness_observation::Payload,
) -> DriverEvent {
    DriverEvent {
        native_key: native_key.to_owned(),
        native_event_id: Some(format!("native:{native_key}")),
        native_sequence: None,
        native_observed_at: Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        },
        criticality,
        payload,
        raw_event: format!("raw:{native_key}").into_bytes(),
    }
}

fn scripted_ack_event(native_key: &str) -> DriverEvent {
    scripted_ack_event_for(native_key, "dispatch-001")
}

fn scripted_ack_event_for(native_key: &str, dispatch_id: &str) -> DriverEvent {
    scripted_event(
        native_key,
        ObservationCriticality::Control,
        harness_observation::Payload::Ack(HarnessAckObservation {
            disposition: AckDisposition::Accepted as i32,
            ack_receipt_id: format!("ack:{native_key}"),
            native_session_ref: Some(format!("scripted-session:{dispatch_id}")),
            native_execution_ref: Some(format!("scripted-execution:{dispatch_id}")),
        }),
    )
}

fn scripted_lifecycle_event(
    native_key: &str,
    criticality: ObservationCriticality,
    kind: LifecycleKind,
) -> DriverEvent {
    scripted_event(
        native_key,
        criticality,
        harness_observation::Payload::Lifecycle(LifecycleObservation {
            kind: kind as i32,
            native_item_ref: None,
            safe_status_code: Some(format!("fixture:{native_key}")),
            side_effect_certainty: SideEffectCertainty::Unknown as i32,
            native_will_retry: None,
        }),
    )
}

fn adapter_observation(
    envelope: &DispatchEnvelope,
    criticality: ObservationCriticality,
    payload: harness_observation::Payload,
) -> HarnessObservation {
    HarnessObservation {
        adapter_id: "adapter:codex".to_owned(),
        attempt_id: envelope.attempt_id.clone(),
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
        capability_profile_id: "single-harness-capability".to_owned(),
        criticality: criticality as i32,
        native_observed_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        adapter_received_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        payload: Some(payload),
        ..HarnessObservation::default()
    }
}

async fn persist_scripted_delivered_dispatch(
    collaboration_path: &Path,
    adapter_path: &Path,
    workspace_root: &Path,
    events: Vec<DriverEvent>,
    pump_count: usize,
) -> (DispatchEnvelope, Vec<HarnessObservation>, Vec<u8>) {
    let bundle = br#"{"input":"c2b-durable-recovery"}"#.to_vec();
    let bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(adapter_path),
        input_bundle_sha256: bundle_sha256.clone(),
    };
    let mut control = open_control_with_guard(collaboration_path, clock.clone(), guard);
    let leased = advance_through_lease(&mut control);
    let dispatch = dispatch_command_with_bundle(&leased, &bundle_sha256);
    control
        .execute(&dispatch, &attempt_supervisor())
        .expect("commit scripted dispatch intent");
    let envelope = control
        .pending_dispatches(&harness_adapter())
        .expect("read scripted pending dispatch")
        .into_iter()
        .next()
        .expect("scripted dispatch envelope")
        .envelope;
    let mut adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(adapter_path),
        LoopMaterialResolver {
            bundle: bundle.clone(),
            workspace_root: workspace_root.to_owned(),
        },
        ScriptedCountingDriver::new(DriverCallCounts::default(), events),
        clock,
    );
    let dispatched = dispatch_pending(&mut control, &mut adapter, &harness_adapter())
        .await
        .expect("persist scripted Delivered receipt");
    assert_eq!(dispatched.dispatches_delivered, 1);
    assert_eq!(dispatched.observations_seen, 0);
    let mut observations = Vec::new();
    for _ in 0..pump_count {
        observations.push(
            adapter
                .pump_one(&envelope)
                .await
                .expect("append scripted durable observation")
                .expect("scripted observation"),
        );
    }
    (envelope, observations, bundle)
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
        route_binding: None,
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
        collaboration_command::Command::RequestAttemptCancellation(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordAttemptCancellationOutcome(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::BeginAttemptReconciliation(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::RecordAttemptReconciliation(value) => {
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
        collaboration_command::Command::RecordAttemptReturn(value) => {
            value
                .base
                .as_mut()
                .expect("base")
                .meta
                .as_mut()
                .expect("metadata")
                .request_digest_sha256 = digest;
        }
        collaboration_command::Command::CommitStepReturn(value) => {
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
    dispatch_command_with_bundle(snapshot, &"5".repeat(64))
}

fn dispatch_command_with_bundle(
    snapshot: &CollaborationSnapshot,
    input_bundle_sha256: &str,
) -> CollaborationCommand {
    dispatch_command_with_ids(
        snapshot,
        input_bundle_sha256,
        "dispatch-001",
        "cmd-dispatch-001",
        "dispatch-intent-001",
    )
}

fn dispatch_command_with_ids(
    snapshot: &CollaborationSnapshot,
    input_bundle_sha256: &str,
    dispatch_id: &str,
    command_id: &str,
    idempotency_key: &str,
) -> CollaborationCommand {
    let run = snapshot.run.as_ref().expect("run");
    let step = snapshot.steps.first().expect("step");
    let attempt = snapshot.attempts.first().expect("attempt");
    let lease = attempt.lease.as_ref().expect("lease");
    let source_meta = metadata(command_id, idempotency_key, &attempt.attempt_id);
    let mut envelope = DispatchEnvelope {
        meta: Some(CommandMetadata {
            command_id: dispatch_id.to_owned(),
            idempotency_key: dispatch_id.to_owned(),
            idempotency_scope: attempt.attempt_id.clone(),
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
        dispatch_id: dispatch_id.to_owned(),
        dispatch_fingerprint: String::new(),
        fencing_token: lease.fencing_token,
        capability_profile_ref: attempt.capability_profile_ref.clone(),
        input_bundle_ref: "input-001".to_owned(),
        input_bundle_sha256: input_bundle_sha256.to_owned(),
        workspace_ref: attempt.workspace_ref.clone(),
        budget_profile_ref: run.plan.as_ref().expect("plan").budget_profile_ref.clone(),
        sandbox_profile_ref: Some(contract_ref("sandbox-policy", '6')),
        tool_policy_ref: Some(contract_ref("tool-policy", '7')),
        data_egress_policy_ref: Some(contract_ref("data-egress-policy", '8')),
        approval_policy_ref: Some(contract_ref("approval-policy", '9')),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        native_session_ref: None,
        checkpoint_ref: None,
        route_binding: None,
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
                dispatch_id: dispatch_id.to_owned(),
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

fn unknown_terminal_observation(snapshot: &CollaborationSnapshot) -> HarnessObservation {
    let attempt = snapshot.attempts.first().expect("attempt");
    HarnessObservation {
        observation_id: "unknown-terminal-001".to_owned(),
        adapter_id: "adapter:codex".to_owned(),
        attempt_id: attempt.attempt_id.clone(),
        dispatch_id: attempt.dispatch_id.clone().expect("dispatch ID"),
        fencing_token: attempt.lease.as_ref().expect("lease").fencing_token,
        observation_sequence: attempt.last_harness_sequence + 1,
        native_event_digest_sha256: "a".repeat(64),
        capability_profile_id: attempt
            .capability_profile_ref
            .as_ref()
            .expect("capability profile")
            .contract_id
            .clone(),
        criticality: ObservationCriticality::Control as i32,
        raw_evidence_ref: "adapter-edge://unknown-terminal-001".to_owned(),
        payload: Some(harness_observation::Payload::Lifecycle(
            LifecycleObservation {
                kind: LifecycleKind::ExecutionFailed as i32,
                side_effect_certainty: SideEffectCertainty::Unknown as i32,
                ..LifecycleObservation::default()
            },
        )),
        ..HarnessObservation::default()
    }
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
    delivery_command_with_ids(snapshot, fencing_token, "cmd-delivery-001", "delivery-001")
}

fn delivery_command_with_ids(
    snapshot: &CollaborationSnapshot,
    fencing_token: u64,
    command_id: &str,
    delivery_receipt_id: &str,
) -> CollaborationCommand {
    let dispatch_id = snapshot
        .attempts
        .first()
        .and_then(|attempt| attempt.dispatch_id.clone())
        .expect("delivery dispatch ID");
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordDeliveryReceipt(
            RecordDeliveryReceiptCommand {
                base: Some(attempt_base(snapshot, command_id)),
                dispatch_id,
                fencing_token,
                delivery_receipt_id: delivery_receipt_id.to_owned(),
                receipt_digest_sha256: "d".repeat(64),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn acquire_lease_from_snapshot(
    snapshot: &CollaborationSnapshot,
    command_id: &str,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::AcquireAttemptLease(
            AcquireAttemptLeaseCommand {
                base: Some(attempt_base(snapshot, command_id)),
                owner_instance_id: "attempt-supervisor-001".to_owned(),
                lease_policy_ref: Some(contract_ref("v01-attempt-lease", 'a')),
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

fn attempt_return_command(
    snapshot: &CollaborationSnapshot,
    fencing_token: u64,
    harness_sequence: u64,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordAttemptReturn(
            RecordAttemptReturnCommand {
                base: Some(attempt_base(snapshot, "cmd-return-001")),
                fencing_token,
                harness_sequence,
                artifact_return_receipt_id: "return-receipt-001".to_owned(),
                receipt_digest_sha256: "a".repeat(64),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn commit_step_return_command(snapshot: &CollaborationSnapshot) -> CollaborationCommand {
    let run = snapshot.run.as_ref().expect("run snapshot");
    let step = &snapshot.steps[0];
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::CommitStepReturn(
            CommitStepReturnCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        "cmd-step-return-commit-001",
                        "step-return-commit-001",
                        "run-001",
                    )),
                    run_id: run.run_id.clone(),
                    expected_run_revision: run.revision,
                }),
                step_id: step.step_id.clone(),
                expected_step_revision: step.revision,
                attempt_id: step.current_attempt_id.clone().expect("current attempt"),
                artifact_set_id: step.artifact_set_id.clone().expect("artifact set"),
                return_handoff_id: step.return_handoff_id.clone().expect("return handoff"),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn cancellation_request(snapshot: &CollaborationSnapshot) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RequestAttemptCancellation(
            RequestAttemptCancellationCommand {
                base: Some(attempt_base(snapshot, "cmd-cancel-request-001")),
                task_cancellation_request_id: "task-cancel-001".to_owned(),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn cancellation_unknown(snapshot: &CollaborationSnapshot) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(
            collaboration_command::Command::RecordAttemptCancellationOutcome(
                RecordAttemptCancellationOutcomeCommand {
                    base: Some(attempt_base(snapshot, "cmd-cancel-outcome-001")),
                    disposition: AttemptCancellationDisposition::OutcomeUnknown as i32,
                    cancellation_receipt_id: "cancel-receipt-001".to_owned(),
                },
            ),
        ),
    };
    set_digest(&mut command);
    command
}

fn begin_reconciliation(snapshot: &CollaborationSnapshot, id: &str) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::BeginAttemptReconciliation(
            BeginAttemptReconciliationCommand {
                base: Some(attempt_base(snapshot, "cmd-reconcile-begin-001")),
                reconciliation_id: id.to_owned(),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn reconciliation_result(snapshot: &CollaborationSnapshot, id: &str) -> CollaborationCommand {
    reconciliation_result_with_evidence(
        snapshot,
        id,
        "reconcile-evidence-001",
        ReconciliationDisposition::RetryIdempotent,
    )
}

fn reconciliation_result_with_evidence(
    snapshot: &CollaborationSnapshot,
    id: &str,
    evidence_id: &str,
    disposition: ReconciliationDisposition,
) -> CollaborationCommand {
    let mut command = CollaborationCommand {
        command: Some(collaboration_command::Command::RecordAttemptReconciliation(
            RecordAttemptReconciliationCommand {
                base: Some(attempt_base(snapshot, "cmd-reconcile-result-001")),
                reconciliation_id: id.to_owned(),
                disposition: disposition as i32,
                evidence_id: evidence_id.to_owned(),
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

fn load_snapshot<G>(control: &CollaborationControl<G, FixedClock>) -> CollaborationSnapshot
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
{
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

fn advance_through_lease<G>(
    control: &mut CollaborationControl<G, FixedClock>,
) -> CollaborationSnapshot
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
{
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

fn advance_through_dispatch<G>(
    control: &mut CollaborationControl<G, FixedClock>,
) -> (CollaborationSnapshot, CollaborationCommand)
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
{
    let leased = advance_through_lease(control);
    let command = dispatch_command(&leased);
    let dispatched = control
        .execute(&command, &attempt_supervisor())
        .expect("record dispatch intent");
    (committed_snapshot(&dispatched), command)
}

fn advance_through_running(
    control: &mut CollaborationControl<FixtureGuard, FixedClock>,
) -> CollaborationSnapshot {
    let (pending, _) = advance_through_dispatch(control);
    let fence = pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let delivered = committed_snapshot(
        &control
            .execute(&delivery_command(&pending, fence), &harness_adapter())
            .expect("delivery"),
    );
    let acknowledged = committed_snapshot(
        &control
            .execute(&ack_command(&delivered, fence, 1), &harness_adapter())
            .expect("ack"),
    );
    committed_snapshot(
        &control
            .execute(
                &running_command(&acknowledged, fence, 2),
                &harness_adapter(),
            )
            .expect("running"),
    )
}

fn advance_unique_run_through_delivery(
    control: &mut CollaborationControl<FixtureGuard, FixedClock>,
    run_id: &str,
    step_id: &str,
    attempt_id: &str,
    dispatch_id: &str,
) -> CollaborationSnapshot {
    let mut plan = run_plan();
    plan.plan_id = format!("plan-{run_id}");
    plan.steps[0].step_id = step_id.to_owned();
    let mut create_run = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateRun(
            CreateRunCommand {
                meta: Some(metadata(
                    &format!("cmd-create-{run_id}"),
                    &format!("create-{run_id}"),
                    &format!("task-001/work-1/{run_id}"),
                )),
                run_id: run_id.to_owned(),
                task_id: "task-001".to_owned(),
                task_revision: 2,
                work_revision: 1,
                plan: Some(plan),
            },
        )),
    };
    set_digest(&mut create_run);
    let created = committed_snapshot(
        &control
            .execute(&create_run, &task_authority())
            .expect("create unique Run"),
    );

    let mut activate_run = CollaborationCommand {
        command: Some(collaboration_command::Command::ActivateRun(
            ActivateRunCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        &format!("cmd-activate-{run_id}"),
                        &format!("activate-{run_id}"),
                        run_id,
                    )),
                    run_id: run_id.to_owned(),
                    expected_run_revision: created.run.as_ref().expect("created run").revision,
                }),
                confirmed_task_revision: 2,
            },
        )),
    };
    set_digest(&mut activate_run);
    let activated = committed_snapshot(
        &control
            .execute(&activate_run, &task_authority())
            .expect("activate unique Run"),
    );

    let activated_run = activated.run.as_ref().expect("activated run");
    let activated_step = activated.steps.first().expect("activated step");
    let mut create_attempt = CollaborationCommand {
        command: Some(collaboration_command::Command::CreateAttempt(
            CreateAttemptCommand {
                base: Some(RunCommandBase {
                    meta: Some(metadata(
                        &format!("cmd-create-{attempt_id}"),
                        &format!("create-{attempt_id}"),
                        &format!("{run_id}/{step_id}"),
                    )),
                    run_id: run_id.to_owned(),
                    expected_run_revision: activated_run.revision,
                }),
                step_id: step_id.to_owned(),
                expected_step_revision: activated_step.revision,
                attempt_id: attempt_id.to_owned(),
                harness_id: "codex".to_owned(),
                capability_profile_ref: Some(contract_ref("single-harness-capability", '3')),
                workspace_ref: "workspace-001".to_owned(),
            },
        )),
    };
    set_digest(&mut create_attempt);
    let attempt_created = committed_snapshot(
        &control
            .execute(&create_attempt, &collaboration_control())
            .expect("create unique Attempt"),
    );

    let leased = committed_snapshot(
        &control
            .execute(
                &acquire_lease_from_snapshot(&attempt_created, &format!("cmd-lease-{attempt_id}")),
                &attempt_supervisor(),
            )
            .expect("acquire unique Attempt lease"),
    );
    let dispatched = committed_snapshot(
        &control
            .execute(
                &dispatch_command_with_ids(
                    &leased,
                    &"5".repeat(64),
                    dispatch_id,
                    &format!("cmd-{dispatch_id}"),
                    &format!("intent-{dispatch_id}"),
                ),
                &attempt_supervisor(),
            )
            .expect("record unique dispatch intent"),
    );
    let fence = dispatched.attempts[0]
        .lease
        .as_ref()
        .expect("unique Attempt lease")
        .fencing_token;
    committed_snapshot(
        &control
            .execute(
                &delivery_command_with_ids(
                    &dispatched,
                    fence,
                    &format!("cmd-delivery-{dispatch_id}"),
                    &format!("delivery-{dispatch_id}"),
                ),
                &harness_adapter(),
            )
            .expect("record unique delivery"),
    )
}

fn persist_delivered_dispatch(label: &str) -> (IsolatedStore, FixedClock) {
    let isolated = IsolatedStore::new(label);
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let (pending, _) = advance_through_dispatch(&mut control);
    let fence = pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    control
        .execute(&delivery_command(&pending, fence), &harness_adapter())
        .expect("record durable delivery");
    assert_eq!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("read delivered dispatch")
            .len(),
        1
    );
    drop(control);
    (isolated, clock)
}

fn rewrite_delivered_envelope(path: &Path, mutate: impl FnOnce(&mut DispatchEnvelope)) {
    let connection = open_raw_collaboration_store(path);
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM collaboration_outbox
             WHERE destination_domain='harness-adapter'
               AND payload_kind='dispatch-envelope'
               AND delivery_state='delivered'",
            [],
            |row| row.get(0),
        )
        .expect("read delivered envelope");
    let mut envelope = DispatchEnvelope::decode(payload.as_slice()).expect("decode envelope");
    mutate(&mut envelope);
    let payload = envelope.encode_to_vec();
    let digest = hex::encode(Sha256::digest(payload.as_slice()));
    assert_eq!(
        connection
            .execute(
                "UPDATE collaboration_outbox
                 SET payload=?1, canonical_payload_digest_sha256=?2
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='delivered'",
                params![payload, digest],
            )
            .expect("rewrite delivered envelope"),
        1
    );
}

fn rewrite_delivered_envelope_and_attempt(
    path: &Path,
    mutate: impl FnOnce(&mut DispatchEnvelope, &mut AttemptSnapshot),
) {
    let mut connection = open_raw_collaboration_store(path);
    let (attempt_id, payload): (String, Vec<u8>) = connection
        .query_row(
            "SELECT attempt_id, payload FROM collaboration_outbox
             WHERE destination_domain='harness-adapter'
               AND payload_kind='dispatch-envelope'
               AND delivery_state='delivered'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read delivered envelope and attempt identity");
    let attempt_payload: Vec<u8> = connection
        .query_row(
            "SELECT snapshot FROM collaboration_attempts WHERE attempt_id=?1",
            [&attempt_id],
            |row| row.get(0),
        )
        .expect("read delivered attempt snapshot");
    let mut envelope = DispatchEnvelope::decode(payload.as_slice()).expect("decode envelope");
    let mut attempt =
        AttemptSnapshot::decode(attempt_payload.as_slice()).expect("decode attempt snapshot");
    mutate(&mut envelope, &mut attempt);

    let envelope_payload = envelope.encode_to_vec();
    let envelope_digest = hex::encode(Sha256::digest(envelope_payload.as_slice()));
    let attempt_payload = attempt.encode_to_vec();
    let transaction = connection.transaction().expect("begin fault injection");
    assert_eq!(
        transaction
            .execute(
                "UPDATE collaboration_outbox
                 SET payload=?1, canonical_payload_digest_sha256=?2
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='delivered'
                   AND attempt_id=?3",
                params![envelope_payload, envelope_digest, attempt_id],
            )
            .expect("rewrite delivered envelope"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE collaboration_attempts
                 SET revision=?1, status=?2, snapshot=?3
                 WHERE attempt_id=?4",
                params![
                    i64::try_from(attempt.revision).expect("attempt revision fits SQLite"),
                    attempt.status,
                    attempt_payload,
                    attempt.attempt_id
                ],
            )
            .expect("rewrite delivered attempt"),
        1
    );
    transaction.commit().expect("commit fault injection");
}

fn rewrite_delivered_hierarchy(
    path: &Path,
    mutate: impl FnOnce(&mut RunSnapshot, &mut StepSnapshot),
) {
    let mut connection = open_raw_collaboration_store(path);
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM collaboration_outbox
             WHERE destination_domain='harness-adapter'
               AND payload_kind='dispatch-envelope'
               AND delivery_state='delivered'",
            [],
            |row| row.get(0),
        )
        .expect("read delivered hierarchy envelope");
    let envelope = DispatchEnvelope::decode(payload.as_slice()).expect("decode envelope");
    let run_payload: Vec<u8> = connection
        .query_row(
            "SELECT snapshot FROM collaboration_runs WHERE run_id=?1",
            [&envelope.run_id],
            |row| row.get(0),
        )
        .expect("read delivered run snapshot");
    let step_payload: Vec<u8> = connection
        .query_row(
            "SELECT snapshot FROM collaboration_steps WHERE step_id=?1 AND run_id=?2",
            params![envelope.step_id, envelope.run_id],
            |row| row.get(0),
        )
        .expect("read delivered step snapshot");
    let mut run = RunSnapshot::decode(run_payload.as_slice()).expect("decode run snapshot");
    let mut step = StepSnapshot::decode(step_payload.as_slice()).expect("decode step snapshot");
    mutate(&mut run, &mut step);

    let transaction = connection
        .transaction()
        .expect("begin hierarchy fault injection");
    assert_eq!(
        transaction
            .execute(
                "UPDATE collaboration_runs SET snapshot=?1 WHERE run_id=?2",
                params![run.encode_to_vec(), run.run_id],
            )
            .expect("rewrite delivered run hierarchy"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE collaboration_steps SET snapshot=?1
                 WHERE step_id=?2 AND run_id=?3",
                params![step.encode_to_vec(), step.step_id, step.run_id],
            )
            .expect("rewrite delivered step hierarchy"),
        1
    );
    transaction
        .commit()
        .expect("commit hierarchy fault injection");
}

fn synchronize_dispatch_fingerprint(
    envelope: &mut DispatchEnvelope,
    attempt: &mut AttemptSnapshot,
) {
    envelope.dispatch_fingerprint.clear();
    envelope
        .meta
        .as_mut()
        .expect("dispatch metadata")
        .request_digest_sha256
        .clear();
    let fingerprint = canonical_dispatch_fingerprint(envelope);
    envelope.dispatch_fingerprint = fingerprint.clone();
    envelope
        .meta
        .as_mut()
        .expect("dispatch metadata")
        .request_digest_sha256 = fingerprint.clone();
    attempt.dispatch_fingerprint = Some(fingerprint);
}

#[test]
fn single_harness_workflow_builds_run_attempt_lease_and_dispatch_outbox() {
    let collaboration_store = IsolatedStore::new("collaboration-single-harness-workflow");
    let adapter_store = IsolatedStore::new("collaboration-single-harness-workflow-edge");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: "5".repeat(64),
    };
    let mut control = open_control_with_guard(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
        guard,
    );
    let task = TaskSnapshot {
        task_id: "task-001".to_owned(),
        revision: 2,
        work_revision: 1,
        ..Default::default()
    };
    let config = SingleHarnessWorkConfig {
        run_id: "run-workflow-001".to_owned(),
        attempt_id: "attempt-workflow-001".to_owned(),
        dispatch_id: "dispatch-workflow-001".to_owned(),
        plan: run_plan(),
        harness_id: "codex".to_owned(),
        capability_profile_ref: contract_ref("single-harness-capability", '3'),
        workspace_ref: "workspace-001".to_owned(),
        lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
        owner_instance_id: "attempt-supervisor-001".to_owned(),
        material: dispatch_material(),
        task_authority_principal_id: "task-authority:workflow".to_owned(),
        collaboration_principal_id: "collaboration-control:workflow".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:workflow".to_owned(),
        harness_adapter_principal_id: "adapter:codex".to_owned(),
    };

    let result = start_single_harness_workflow(&mut control, &task, &config)
        .expect("start governed single harness workflow");
    assert_eq!(result.run_id, config.run_id);
    assert_eq!(result.attempt_id, config.attempt_id);
    assert_eq!(result.dispatch_id, config.dispatch_id);
    assert_eq!(result.envelope.dispatch_id, config.dispatch_id);
    assert_eq!(result.envelope.input_bundle_ref, "input-001");
    assert_eq!(result.envelope.input_bundle_sha256, "5".repeat(64));
    let lineage_reader = CollaborationLineageReader::open(CollaborationLineageReaderConfig {
        database_path: collaboration_store.database_path(),
        store_epoch: STORE_EPOCH.to_owned(),
        key: CollaborationSqlCipherKey::new(TEST_KEY),
    })
    .expect("open query-only Collaboration lineage reader");
    assert_eq!(
        lineage_reader
            .task_id_for_attempt(&config.attempt_id)
            .expect("resolve trusted Attempt lineage")
            .as_deref(),
        Some(task.task_id.as_str())
    );
    assert_eq!(
        lineage_reader
            .task_id_for_attempt("attempt-missing")
            .expect("missing Attempt lineage is not fabricated"),
        None
    );
    assert_eq!(
        control
            .pending_dispatches(&harness_adapter())
            .expect("read pending dispatch outbox")
            .len(),
        1
    );

    let retry = start_single_harness_workflow(&mut control, &task, &config)
        .expect("retry governed single harness workflow idempotently");
    assert_eq!(retry, result);
    assert_eq!(
        control
            .pending_dispatches(&harness_adapter())
            .expect("read pending dispatch outbox after retry")
            .len(),
        1
    );
}

#[test]
fn single_harness_workflow_accepts_only_task_activation_guard_evidence() {
    let collaboration_store = IsolatedStore::new("collaboration-task-activation-guard");
    let adapter_store = IsolatedStore::new("collaboration-task-activation-guard-edge");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let config = SingleHarnessWorkConfig {
        run_id: "run-guarded-001".to_owned(),
        attempt_id: "attempt-guarded-001".to_owned(),
        dispatch_id: "dispatch-guarded-001".to_owned(),
        plan: run_plan(),
        harness_id: "codex".to_owned(),
        capability_profile_ref: contract_ref("single-harness-capability", '3'),
        workspace_ref: "workspace-001".to_owned(),
        lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
        owner_instance_id: "attempt-supervisor-001".to_owned(),
        material: dispatch_material(),
        task_authority_principal_id: "task-authority:guarded".to_owned(),
        collaboration_principal_id: "collaboration-control:guarded".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:guarded".to_owned(),
        harness_adapter_principal_id: "adapter:codex".to_owned(),
    };
    let task = TaskSnapshot {
        task_id: "task-guarded-001".to_owned(),
        revision: 4,
        work_revision: 2,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config.run_id.clone()),
        ..Default::default()
    };
    let reference = TaskActivationReferenceGuard::new(task.clone(), &config, 30);
    let guard = CompositeCollaborationGuard::new(
        reference,
        AdapterBackedHarnessEvidenceResolver::new(open_loop_adapter_edge(&adapter_database)),
    );
    let mut control = open_control_with_guard(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
        guard,
    );

    let result = start_single_harness_workflow(&mut control, &task, &config)
        .expect("start Task-activation-governed workflow");
    assert_eq!(result.run_id, config.run_id);
    assert_eq!(result.envelope.dispatch_id, config.dispatch_id);
    assert_eq!(
        control
            .pending_dispatches(&harness_adapter())
            .expect("read guarded dispatch")
            .len(),
        1
    );
}

#[tokio::test]
async fn task_activation_runner_leaves_other_routes_pending_and_dispatches_its_match() {
    let collaboration_store = IsolatedStore::new("task-activation-runner-collaboration");
    let adapter_store = IsolatedStore::new("task-activation-runner-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let bundle = br#"{"input":"activation-runner"}"#.to_vec();
    let mut material = dispatch_material();
    material.input_bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let config = SingleHarnessWorkConfig {
        run_id: "run-activation-runner-001".to_owned(),
        attempt_id: "attempt-activation-runner-001".to_owned(),
        dispatch_id: "dispatch-activation-runner-001".to_owned(),
        plan: run_plan(),
        harness_id: "codex".to_owned(),
        capability_profile_ref: contract_ref("single-harness-capability", '3'),
        workspace_ref: "workspace-001".to_owned(),
        lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
        owner_instance_id: "attempt-supervisor-001".to_owned(),
        material,
        task_authority_principal_id: "task-authority:runner".to_owned(),
        collaboration_principal_id: "collaboration-control:runner".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:runner".to_owned(),
        harness_adapter_principal_id: "adapter:codex".to_owned(),
    };
    let task = TaskSnapshot {
        task_id: "task-activation-runner-001".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config.run_id.clone()),
        ..Default::default()
    };
    let foreign_task = TaskSnapshot {
        task_id: "task-activation-runner-foreign".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some("run-activation-runner-foreign".to_owned()),
        ..Default::default()
    };
    let source = Arc::new(FixtureActivationSource {
        pending: Mutex::new(vec![
            TaskActivationHandoff {
                message_id: "task-outbox-activation-runner-foreign".to_owned(),
                payload_digest_sha256: "e".repeat(64),
                task: foreign_task,
            },
            TaskActivationHandoff {
                message_id: "task-outbox-activation-runner-001".to_owned(),
                payload_digest_sha256: "d".repeat(64),
                task: task.clone(),
            },
        ]),
        acknowledged: Mutex::new(Vec::new()),
    });
    let (guard, binding) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let clock = FixedClock::new(FIXED_TIME);
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        FakeCodexDriver::default().with_deferred_terminal(),
        clock,
    );
    let dispatch_id = config.dispatch_id.clone();
    let capability_profile_ref = config.capability_profile_ref.clone();
    let runner = GovernedTaskActivationRunner::new(
        control,
        adapter,
        Arc::clone(&source),
        FixtureWorkflowResolver(config),
        harness_adapter(),
        binding,
        30,
    )
    .with_capability_profile_ref(capability_profile_ref);
    let cycle = runner.run_once().await.expect("activation runner cycle");
    assert_eq!(cycle.activations_seen, 2);
    assert_eq!(cycle.activations_started, 1);
    assert_eq!(cycle.activations_acknowledged, 1);
    assert_eq!(cycle.dispatches_delivered, 1);
    assert_eq!(cycle.terminal_observations, 0);
    let resumed = runner
        .run_once()
        .await
        .expect("resume activation runner cycle");
    assert_eq!(resumed.terminal_observations, 0);
    let terminal = runner
        .run_once()
        .await
        .expect("resume deferred terminal activation cycle");
    assert_eq!(terminal.terminal_observations, 1);
    assert_eq!(terminal.terminal_dispatch_ids, [dispatch_id]);
    assert_eq!(
        source
            .acknowledged
            .lock()
            .expect("activation acknowledgement mutex")
            .as_slice(),
        ["task-outbox-activation-runner-001"]
    );
    let pending = source.pending.lock().expect("activation source mutex");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].message_id,
        "task-outbox-activation-runner-foreign"
    );
}

#[tokio::test]
async fn two_profile_bound_runners_share_activation_source_without_cross_ack_or_dispatch() {
    let make_config = |suffix: &str, profile_id: &str, digest_byte: char| {
        let profile_ref = contract_ref(profile_id, digest_byte);
        let mut plan = run_plan();
        plan.steps[0].required_capability_profile_ref = Some(profile_ref.clone());
        let bundle = format!("{{\"input\":\"{suffix}\"}}").into_bytes();
        let mut material = dispatch_material();
        material.input_bundle_sha256 = hex::encode(Sha256::digest(&bundle));
        SingleHarnessWorkConfig {
            run_id: format!("run-profile-{suffix}"),
            attempt_id: format!("attempt-profile-{suffix}"),
            dispatch_id: format!("dispatch-profile-{suffix}"),
            plan,
            harness_id: format!("harness-{suffix}"),
            capability_profile_ref: profile_ref,
            workspace_ref: format!("workspace-profile-{suffix}"),
            lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
            owner_instance_id: format!("attempt-supervisor-{suffix}"),
            material,
            task_authority_principal_id: format!("task-authority:{suffix}"),
            collaboration_principal_id: format!("collaboration-control:{suffix}"),
            attempt_supervisor_principal_id: format!("attempt-supervisor:{suffix}"),
            harness_adapter_principal_id: format!("adapter:{suffix}"),
        }
    };
    let config_a = make_config("a", "profile:a", 'a');
    let config_b = make_config("b", "profile:b", 'b');
    let task_a = TaskSnapshot {
        task_id: "task-profile-a".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config_a.run_id.clone()),
        ..Default::default()
    };
    let task_b = TaskSnapshot {
        task_id: "task-profile-b".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config_b.run_id.clone()),
        ..Default::default()
    };
    let source = Arc::new(FixtureActivationSource {
        pending: Mutex::new(vec![
            TaskActivationHandoff {
                message_id: "task-outbox-profile-a".to_owned(),
                payload_digest_sha256: "a".repeat(64),
                task: task_a,
            },
            TaskActivationHandoff {
                message_id: "task-outbox-profile-b".to_owned(),
                payload_digest_sha256: "b".repeat(64),
                task: task_b,
            },
        ]),
        acknowledged: Mutex::new(Vec::new()),
    });

    let make_runner = |config: SingleHarnessWorkConfig, adapter_id: &str, store_suffix: &str| {
        let collaboration_store =
            IsolatedStore::new(&format!("shared-activation-{store_suffix}-collaboration"));
        let adapter_store =
            IsolatedStore::new(&format!("shared-activation-{store_suffix}-adapter"));
        let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
        let (guard, binding) = TaskActivationGuardSet::new(
            AdapterBackedHarnessEvidenceResolver::new(open_loop_adapter_edge_for(
                &adapter_database,
                adapter_id,
                &format!("shared-activation-{store_suffix}-edge"),
            )),
        );
        let control = open_control_with_guard(
            &collaboration_store.database_path(),
            FixedClock::new(FIXED_TIME),
            guard,
        );
        let bundle = format!("{{\"input\":\"{store_suffix}\"}}").into_bytes();
        let adapter = GovernedHarnessAdapter::new(
            adapter_id,
            &config.capability_profile_ref.contract_id,
            codex_protocol_fingerprint(),
            open_loop_adapter_edge_for(
                &adapter_database,
                adapter_id,
                &format!("shared-activation-{store_suffix}-edge"),
            ),
            LoopMaterialResolver {
                bundle,
                workspace_root: adapter_store.root.clone(),
            },
            FakeCodexDriver::default(),
            FixedClock::new(FIXED_TIME),
        );
        let profile_ref = config.capability_profile_ref.clone();
        let runner = GovernedTaskActivationRunner::new(
            control,
            adapter,
            Arc::clone(&source),
            FixtureWorkflowResolver(config),
            principal(CollaborationPrincipalKind::HarnessAdapter, adapter_id),
            binding,
            30,
        )
        .with_capability_profile_ref(profile_ref);
        (runner, adapter_database, collaboration_store, adapter_store)
    };

    let (runner_a, adapter_database_a, _collaboration_store_a, _adapter_store_a) =
        make_runner(config_a, "adapter:profile-a", "a");
    let cycle_a = runner_a.run_once().await.expect("profile A cycle");
    assert_eq!(cycle_a.activations_seen, 2);
    assert_eq!(cycle_a.activations_started, 1);
    assert_eq!(cycle_a.activations_acknowledged, 1);
    assert_eq!(cycle_a.dispatches_delivered, 1);
    assert_eq!(
        source
            .acknowledged
            .lock()
            .expect("shared activation acknowledgement mutex")
            .as_slice(),
        ["task-outbox-profile-a"]
    );
    assert_eq!(
        source
            .pending
            .lock()
            .expect("shared activation source mutex")
            .iter()
            .map(|handoff| handoff.message_id.as_str())
            .collect::<Vec<_>>(),
        ["task-outbox-profile-b"]
    );
    drop(runner_a);

    let (runner_b, adapter_database_b, _collaboration_store_b, _adapter_store_b) =
        make_runner(config_b, "adapter:profile-b", "b");
    let cycle_b = runner_b.run_once().await.expect("profile B cycle");
    assert_eq!(cycle_b.activations_seen, 1);
    assert_eq!(cycle_b.activations_started, 1);
    assert_eq!(cycle_b.activations_acknowledged, 1);
    assert_eq!(cycle_b.dispatches_delivered, 1);
    drop(runner_b);

    assert_eq!(
        source
            .acknowledged
            .lock()
            .expect("final activation acknowledgement mutex")
            .as_slice(),
        ["task-outbox-profile-a", "task-outbox-profile-b"]
    );
    assert!(
        source
            .pending
            .lock()
            .expect("final activation source mutex")
            .is_empty()
    );

    let edge_a = open_loop_adapter_edge_for(
        &adapter_database_a,
        "adapter:profile-a",
        "shared-activation-a-edge",
    );
    let envelope_a = edge_a
        .dispatch_envelope("dispatch-profile-a")
        .expect("inspect profile A edge")
        .expect("profile A dispatch");
    assert_eq!(
        envelope_a.capability_profile_ref.expect("profile A route"),
        contract_ref("profile:a", 'a')
    );
    assert_eq!(
        edge_a
            .inspect()
            .expect("inspect profile A counts")
            .dispatch_count,
        1
    );
    drop(edge_a);

    let edge_b = open_loop_adapter_edge_for(
        &adapter_database_b,
        "adapter:profile-b",
        "shared-activation-b-edge",
    );
    let envelope_b = edge_b
        .dispatch_envelope("dispatch-profile-b")
        .expect("inspect profile B edge")
        .expect("profile B dispatch");
    assert_eq!(
        envelope_b.capability_profile_ref.expect("profile B route"),
        contract_ref("profile:b", 'b')
    );
    assert_eq!(
        edge_b
            .inspect()
            .expect("inspect profile B counts")
            .dispatch_count,
        1
    );
}

#[tokio::test]
async fn task_activation_runner_retries_verification_gated_return_before_ack() {
    let collaboration_store = IsolatedStore::new("task-activation-return-retry-collaboration");
    let adapter_store = IsolatedStore::new("task-activation-return-retry-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let bundle = br#"{"input":"return-retry"}"#.to_vec();
    let mut material = dispatch_material();
    material.input_bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let config = SingleHarnessWorkConfig {
        run_id: "run-return-retry-001".to_owned(),
        attempt_id: "attempt-return-retry-001".to_owned(),
        dispatch_id: "dispatch-return-retry-001".to_owned(),
        plan: run_plan(),
        harness_id: "codex".to_owned(),
        capability_profile_ref: contract_ref("single-harness-capability", '3'),
        workspace_ref: "workspace-001".to_owned(),
        lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
        owner_instance_id: "attempt-supervisor:return-retry".to_owned(),
        material,
        task_authority_principal_id: "task-authority:return-retry".to_owned(),
        collaboration_principal_id: "collaboration-control:return-retry".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:return-retry".to_owned(),
        harness_adapter_principal_id: "adapter:codex".to_owned(),
    };
    let task = TaskSnapshot {
        task_id: "task-return-retry-001".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config.run_id.clone()),
        ..Default::default()
    };
    let activation_source = Arc::new(FixtureActivationSource {
        pending: Mutex::new(vec![TaskActivationHandoff {
            message_id: "task-outbox-return-retry-001".to_owned(),
            payload_digest_sha256: "d".repeat(64),
            task: task.clone(),
        }]),
        acknowledged: Mutex::new(Vec::new()),
    });
    let artifact_source = Arc::new(FixtureArtifactReturnSource {
        pending: Mutex::new(Vec::new()),
        acknowledged: Mutex::new(Vec::new()),
    });
    let verification_available = Arc::new(Mutex::new(false));
    let (guard, binding) = TaskActivationGuardSet::new(FixtureReturnEvidence {
        adapter: AdapterBackedHarnessEvidenceResolver::new(open_loop_adapter_edge(
            &adapter_database,
        )),
        verification_available: Arc::clone(&verification_available),
    });
    let clock = FixedClock::new(FIXED_TIME);
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        FakeCodexDriver::default().with_deferred_terminal(),
        clock,
    );
    let runner = GovernedTaskActivationRunner::new(
        control,
        adapter,
        Arc::clone(&activation_source),
        FixtureWorkflowResolver(config.clone()),
        harness_adapter(),
        binding,
        30,
    )
    .with_artifact_return_source(
        artifact_source.clone() as Arc<dyn ArtifactReturnSource>,
        artifact_authority(),
    )
    .with_step_return_principal(collaboration_control());

    runner
        .run_once()
        .await
        .expect("start governed return retry run");
    runner
        .run_once()
        .await
        .expect("produce durable terminal Harness candidate");
    runner
        .run_once()
        .await
        .expect("resume deferred terminal Harness candidate");
    artifact_source
        .pending
        .lock()
        .expect("return source mutex")
        .push(PendingArtifactReturn {
            message_id: "artifact-outbox-return-retry-001".to_owned(),
            payload_digest_sha256: "e".repeat(64),
            receipt: ReturnReceipt {
                receipt_id: "return-receipt-runner-001".to_owned(),
                artifact_set_id: "artifact-set-runner-001".to_owned(),
                return_handoff_id: "return-handoff-runner-001".to_owned(),
                accepted_for_evidence_intake: true,
                verification_performed: false,
                task_completion_decided: false,
                committed_at: Some(Timestamp {
                    seconds: FIXED_TIME,
                    nanos: 0,
                }),
                lineage: Some(LineageBinding {
                    task_id: task.task_id,
                    task_revision: task.revision,
                    work_revision: task.work_revision,
                    run_id: config.run_id,
                    run_revision: 5,
                    step_id: "step-001".to_owned(),
                    step_revision: 4,
                    attempt_id: config.attempt_id,
                    attempt_revision: 3,
                    dispatch_id: config.dispatch_id,
                    fencing_token: 1,
                }),
                ..ReturnReceipt::default()
            },
        });

    runner
        .run_once()
        .await
        .expect("hold return while Verification proof is unavailable");
    assert!(
        artifact_source
            .acknowledged
            .lock()
            .expect("return acknowledgement mutex")
            .is_empty()
    );

    *verification_available
        .lock()
        .expect("Verification availability mutex") = true;
    runner
        .run_once()
        .await
        .expect("retry and commit Verification-gated Step return");
    assert_eq!(
        artifact_source
            .acknowledged
            .lock()
            .expect("return acknowledgement mutex")
            .as_slice(),
        ["artifact-outbox-return-retry-001"]
    );
}

#[tokio::test]
async fn c2b_generic_restart_drains_durable_ack_before_native_poll_without_resend() {
    let collaboration_store = IsolatedStore::new("c2b-generic-restart-collaboration");
    let adapter_store = IsolatedStore::new("c2b-generic-restart-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let (envelope, observations, bundle) = persist_scripted_delivered_dispatch(
        &collaboration_store.database_path(),
        &adapter_database,
        &adapter_store.root,
        vec![scripted_ack_event("c2b-old-ack")],
        1,
    )
    .await;
    let durable_ack = &observations[0];
    assert_eq!(
        open_loop_adapter_edge(&adapter_database)
            .normal_observation_recovery_view(&envelope.dispatch_id, "single-harness-capability")
            .expect("read pending durable ACK")
            .pending,
        observations
    );

    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(counts.clone(), Vec::new()).requiring_consumed(
            &adapter_database,
            &envelope.dispatch_id,
            &durable_ack.observation_id,
        ),
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let report = runner
        .run_once()
        .await
        .expect("restart durable-first cycle");
    assert_eq!(report.observations_seen, 1);
    assert_eq!(report.observations_consumed, 1);
    assert_eq!(counts.send.load(Ordering::SeqCst), 0);
    assert_eq!(counts.next.load(Ordering::SeqCst), 1);
    assert_eq!(counts.reconcile.load(Ordering::SeqCst), 0);
    drop(runner);

    let control = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    assert_eq!(
        load_snapshot(&control).attempts[0].status,
        AttemptStatus::Acknowledged as i32
    );
    let view = open_loop_adapter_edge(&adapter_database)
        .normal_observation_recovery_view(&envelope.dispatch_id, "single-harness-capability")
        .expect("reopen consumed ACK view");
    assert!(view.pending.is_empty());
}

#[tokio::test]
async fn c2b_new_dispatch_is_sent_without_poll_and_rehydrates_delivered_next_cycle() {
    let collaboration_store = IsolatedStore::new("c2b-new-dispatch-collaboration");
    let adapter_store = IsolatedStore::new("c2b-new-dispatch-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let bundle = br#"{"input":"c2b-new-dispatch"}"#.to_vec();
    let bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: bundle_sha256.clone(),
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let leased = advance_through_lease(&mut control);
    control
        .execute(
            &dispatch_command_with_bundle(&leased, &bundle_sha256),
            &attempt_supervisor(),
        )
        .expect("record C2b new dispatch intent");
    let counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(
            counts.clone(),
            vec![scripted_ack_event("c2b-next-cycle-ack")],
        ),
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let first = runner.run_once().await.expect("send new dispatch");
    assert_eq!(first.dispatches_delivered, 1);
    assert_eq!(first.observations_seen, 0);
    assert_eq!(counts.send.load(Ordering::SeqCst), 1);
    assert_eq!(counts.next.load(Ordering::SeqCst), 0);

    let second = runner
        .run_once()
        .await
        .expect("rehydrate delivered dispatch");
    assert_eq!(second.dispatches_seen, 0);
    assert_eq!(second.observations_seen, 1);
    assert_eq!(second.observations_consumed, 1);
    assert_eq!(counts.send.load(Ordering::SeqCst), 1);
    assert_eq!(counts.next.load(Ordering::SeqCst), 2);
    assert_eq!(counts.reconcile.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn c2b_task_runner_consumes_old_durable_ack_before_new_activation_send() {
    let collaboration_store = IsolatedStore::new("c2b-task-order-collaboration");
    let adapter_store = IsolatedStore::new("c2b-task-order-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let (old_envelope, old_observations, bundle) = persist_scripted_delivered_dispatch(
        &collaboration_store.database_path(),
        &adapter_database,
        &adapter_store.root,
        vec![scripted_ack_event("c2b-task-old-ack")],
        1,
    )
    .await;
    let old_ack = &old_observations[0];

    let mut plan = run_plan();
    plan.steps[0].step_id = "step-c2b-task-new".to_owned();
    let mut material = dispatch_material();
    material.input_bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let config = SingleHarnessWorkConfig {
        run_id: "run-c2b-task-new".to_owned(),
        attempt_id: "attempt-c2b-task-new".to_owned(),
        dispatch_id: "dispatch-c2b-task-new".to_owned(),
        plan,
        harness_id: "codex".to_owned(),
        capability_profile_ref: contract_ref("single-harness-capability", '3'),
        workspace_ref: "workspace-c2b-task-new".to_owned(),
        lease_policy_ref: contract_ref("v01-attempt-lease", 'a'),
        owner_instance_id: "attempt-supervisor-c2b-task-new".to_owned(),
        material,
        task_authority_principal_id: "task-authority:c2b-task-new".to_owned(),
        collaboration_principal_id: "collaboration-control:c2b-task-new".to_owned(),
        attempt_supervisor_principal_id: "attempt-supervisor:c2b-task-new".to_owned(),
        harness_adapter_principal_id: "adapter:codex".to_owned(),
    };
    let task = TaskSnapshot {
        task_id: "task-c2b-task-new".to_owned(),
        revision: 2,
        work_revision: 1,
        status: TaskStatus::Active as i32,
        current_run_id: Some(config.run_id.clone()),
        ..TaskSnapshot::default()
    };
    let source = Arc::new(FixtureActivationSource {
        pending: Mutex::new(vec![TaskActivationHandoff {
            message_id: "task-outbox-c2b-task-new".to_owned(),
            payload_digest_sha256: "e".repeat(64),
            task,
        }]),
        acknowledged: Mutex::new(Vec::new()),
    });
    let (guard, binding) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let clock = FixedClock::new(FIXED_TIME);
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(counts.clone(), Vec::new()).requiring_consumed(
            &adapter_database,
            &old_envelope.dispatch_id,
            &old_ack.observation_id,
        ),
        clock,
    );
    let runner = GovernedTaskActivationRunner::new(
        control,
        adapter,
        Arc::clone(&source),
        FixtureWorkflowResolver(config.clone()),
        harness_adapter(),
        binding,
        30,
    );
    let report = runner
        .run_once()
        .await
        .expect("drain old ACK before new activation dispatch");
    assert_eq!(report.observations_seen, 1);
    assert_eq!(report.observations_consumed, 1);
    assert_eq!(report.activations_started, 1);
    assert_eq!(report.dispatches_delivered, 1);
    assert_eq!(counts.next.load(Ordering::SeqCst), 1);
    assert_eq!(counts.send.load(Ordering::SeqCst), 1);
    assert_eq!(counts.reconcile.load(Ordering::SeqCst), 0);
    assert_eq!(
        counts.order.lock().expect("driver order mutex").as_slice(),
        [
            "next:dispatch-001".to_owned(),
            format!("send:{}", config.dispatch_id)
        ]
    );
    assert_eq!(
        source
            .acknowledged
            .lock()
            .expect("activation acknowledgement mutex")
            .as_slice(),
        ["task-outbox-c2b-task-new"]
    );
}

#[tokio::test]
async fn c2b_retained_and_deferred_observations_do_not_cross_later_sequence() {
    for (label, first) in [
        (
            "retained",
            scripted_lifecycle_event(
                "c2b-retained",
                ObservationCriticality::Control,
                LifecycleKind::ExecutionInterrupted,
            ),
        ),
        (
            "deferred",
            scripted_lifecycle_event(
                "c2b-deferred",
                ObservationCriticality::Control,
                LifecycleKind::ExecutionCompleted,
            ),
        ),
    ] {
        let collaboration_store = IsolatedStore::new(&format!("c2b-{label}-collaboration"));
        let adapter_store = IsolatedStore::new(&format!("c2b-{label}-adapter"));
        let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
        let (envelope, observations, bundle) = persist_scripted_delivered_dispatch(
            &collaboration_store.database_path(),
            &adapter_database,
            &adapter_store.root,
            vec![first, scripted_ack_event(&format!("c2b-{label}-later"))],
            2,
        )
        .await;
        let clock = FixedClock::new(FIXED_TIME);
        let guard = AdapterBackedFixtureGuard {
            edge: open_loop_adapter_edge(&adapter_database),
            input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
        };
        let control =
            open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
        let counts = DriverCallCounts::default();
        let adapter = GovernedHarnessAdapter::new(
            "adapter:codex",
            "single-harness-capability",
            codex_protocol_fingerprint(),
            open_loop_adapter_edge(&adapter_database),
            LoopMaterialResolver {
                bundle,
                workspace_root: adapter_store.root.clone(),
            },
            ScriptedCountingDriver::new(counts.clone(), Vec::new()),
            clock,
        );
        let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
        let report = runner.run_once().await.expect("durable replay barrier");
        assert_eq!(report.observations_seen, 1, "{label}");
        assert_eq!(report.observations_retained, 1, "{label}");
        assert_eq!(counts.next.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(counts.send.load(Ordering::SeqCst), 0, "{label}");
        drop(runner);

        let view = open_loop_adapter_edge(&adapter_database)
            .normal_observation_recovery_view(&envelope.dispatch_id, "single-harness-capability")
            .expect("reopen blocked observation view");
        assert_eq!(view.pending, observations, "{label}");
    }
}

#[tokio::test]
async fn c2b_earliest_terminal_barrier_survives_reopen_pending_or_consumed() {
    for terminal_consumed in [false, true] {
        let label = if terminal_consumed {
            "consumed"
        } else {
            "pending"
        };
        let collaboration_store =
            IsolatedStore::new(&format!("c2b-terminal-{label}-collaboration"));
        let adapter_store = IsolatedStore::new(&format!("c2b-terminal-{label}-adapter"));
        let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
        let (envelope, observations, bundle) = persist_scripted_delivered_dispatch(
            &collaboration_store.database_path(),
            &adapter_database,
            &adapter_store.root,
            vec![
                scripted_lifecycle_event(
                    &format!("c2b-terminal-{label}"),
                    ObservationCriticality::Terminal,
                    LifecycleKind::ExecutionCompleted,
                ),
                scripted_ack_event(&format!("c2b-after-terminal-{label}")),
            ],
            2,
        )
        .await;
        if terminal_consumed {
            let mut edge = open_loop_adapter_edge(&adapter_database);
            edge.mark_observation_consumed(&observations[0].observation_id)
                .expect("fault fixture consumes terminal before restart");
        }

        let clock = FixedClock::new(FIXED_TIME);
        let guard = AdapterBackedFixtureGuard {
            edge: open_loop_adapter_edge(&adapter_database),
            input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
        };
        let control =
            open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
        let counts = DriverCallCounts::default();
        let adapter = GovernedHarnessAdapter::new(
            "adapter:codex",
            "single-harness-capability",
            codex_protocol_fingerprint(),
            open_loop_adapter_edge(&adapter_database),
            LoopMaterialResolver {
                bundle,
                workspace_root: adapter_store.root.clone(),
            },
            ScriptedCountingDriver::new(counts.clone(), Vec::new()),
            clock,
        );
        let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
        let report = runner.run_once().await.expect("terminal durable barrier");
        assert_eq!(
            report.observations_seen,
            u64::from(!terminal_consumed),
            "{label}"
        );
        assert_eq!(counts.next.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(counts.reconcile.load(Ordering::SeqCst), 0, "{label}");
        drop(runner);

        let view = open_loop_adapter_edge(&adapter_database)
            .normal_observation_recovery_view(&envelope.dispatch_id, "single-harness-capability")
            .expect("reopen terminal barrier");
        assert_eq!(
            view.durable_terminal_sequence,
            Some(observations[0].observation_sequence)
        );
        assert!(
            view.pending
                .iter()
                .any(|observation| observation.observation_id == observations[1].observation_id),
            "later observation crossed the terminal barrier"
        );
    }
}

#[tokio::test]
async fn fake_adapter_consumes_collaboration_outbox_and_settles_durable_candidates() {
    let collaboration_store = IsolatedStore::new("collaboration-adapter-loop-authority");
    let adapter_store = IsolatedStore::new("collaboration-adapter-loop-edge");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let bundle = br#"{"input":"governed-loop"}"#.to_vec();
    let bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let writer_edge = open_loop_adapter_edge(&adapter_database);
    let reader_edge = open_loop_adapter_edge(&adapter_database);
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: reader_edge,
        input_bundle_sha256: bundle_sha256,
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let leased = advance_through_lease(&mut control);
    let dispatch = dispatch_command_with_bundle(&leased, &hex::encode(Sha256::digest(&bundle)));
    control
        .execute(&dispatch, &attempt_supervisor())
        .expect("commit Adapter loop dispatch intent");
    let outbox = control
        .pending_dispatches(&harness_adapter())
        .expect("poll committed Collaboration dispatch outbox");
    assert_eq!(outbox.len(), 1);
    let envelope = outbox[0].envelope.clone();
    let resolver = LoopMaterialResolver {
        bundle,
        workspace_root: adapter_store.root.clone(),
    };
    let mut adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        writer_edge,
        resolver,
        FakeCodexDriver::default(),
        clock,
    );

    let cycle = dispatch_pending(&mut control, &mut adapter, &harness_adapter())
        .await
        .expect("run provider-neutral dispatch cycle");
    assert_eq!(cycle.dispatches_seen, 1);
    assert_eq!(cycle.dispatches_delivered, 1);
    assert_eq!(cycle.observations_seen, 0);
    let observation_cycle =
        pump_observations(&mut control, &mut adapter, &envelope, &harness_adapter())
            .await
            .expect("replay and poll delivered observations");
    assert_eq!(observation_cycle.observations_seen, 3);
    assert_eq!(observation_cycle.observations_deferred, 1);

    let snapshot = load_snapshot(&control);
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Active as i32
    );
    assert_eq!(snapshot.steps[0].status, StepStatus::Active as i32);
    assert_eq!(snapshot.attempts[0].status, AttemptStatus::Running as i32);
    assert_eq!(
        snapshot.attempts[0].harness_session_ref.as_deref(),
        Some("fake-thread-dispatch-001")
    );
    let cancellation_pending = committed_snapshot(
        &control
            .execute(&cancellation_request(&snapshot), &attempt_supervisor())
            .expect("commit governed cancellation request"),
    );
    assert_eq!(
        cancellation_pending.attempts[0].status,
        AttemptStatus::CancellationPending as i32
    );
    adapter
        .cancel_dispatch(
            "task-cancel-001",
            &envelope.dispatch_id,
            Timestamp {
                seconds: FIXED_TIME + 30,
                nanos: 0,
            },
        )
        .await
        .expect("deliver cancellation by dispatch ID");
    assert_eq!(
        load_snapshot(&control).attempts[0].status,
        AttemptStatus::CancellationPending as i32
    );
    assert_eq!(adapter.driver().dispatch_count(), 1);
    assert_eq!(adapter.driver().cancel_count(), 1);
    assert_eq!(
        open_loop_adapter_edge(&adapter_database)
            .inspect()
            .expect("inspect durable cancellation transport")
            .cancellation_count,
        1
    );
}

#[tokio::test]
async fn c2b_cancellation_held_is_drain_only_and_interruption_disappears_after_settlement() {
    let collaboration_store = IsolatedStore::new("c2b-cancellation-collaboration");
    let adapter_store = IsolatedStore::new("c2b-cancellation-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let (envelope, _, bundle) = persist_scripted_delivered_dispatch(
        &collaboration_store.database_path(),
        &adapter_database,
        &adapter_store.root,
        Vec::new(),
        0,
    )
    .await;
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let cancellation = committed_snapshot(
        &control
            .execute(
                &cancellation_request(&load_snapshot(&control)),
                &attempt_supervisor(),
            )
            .expect("request C2b cancellation"),
    );
    assert_eq!(
        cancellation.attempts[0].status,
        AttemptStatus::CancellationPending as i32
    );
    let held = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("read cancellation held candidate");
    assert_eq!(held.len(), 1);
    assert_eq!(
        held[0].state,
        HeldDispatchRecoveryState::CancellationPending
    );
    drop(control);

    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let empty_counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle: bundle.clone(),
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(empty_counts.clone(), Vec::new()),
        clock.clone(),
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let empty = runner
        .run_once()
        .await
        .expect("drain empty cancellation hold");
    assert_eq!(empty.observations_seen, 0);
    assert_eq!(empty_counts.next.load(Ordering::SeqCst), 0);
    assert_eq!(empty_counts.reconcile.load(Ordering::SeqCst), 0);
    drop(runner);
    let control = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    assert_eq!(
        load_snapshot(&control).attempts[0].status,
        AttemptStatus::CancellationPending as i32
    );
    drop(control);

    let append_counts = DriverCallCounts::default();
    let mut adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle: bundle.clone(),
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(
            append_counts,
            vec![scripted_lifecycle_event(
                "c2b-cancellation-interrupted",
                ObservationCriticality::Terminal,
                LifecycleKind::ExecutionInterrupted,
            )],
        ),
        clock.clone(),
    );
    adapter
        .pump_one(&envelope)
        .await
        .expect("append cancellation interruption")
        .expect("durable cancellation interruption");
    drop(adapter);

    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let drain_counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(drain_counts.clone(), Vec::new()),
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let settled = runner
        .run_once()
        .await
        .expect("settle durable cancellation interruption");
    assert_eq!(settled.observations_seen, 1);
    assert_eq!(settled.observations_consumed, 1);
    assert_eq!(drain_counts.next.load(Ordering::SeqCst), 0);
    assert_eq!(drain_counts.reconcile.load(Ordering::SeqCst), 0);
    drop(runner);

    let control = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    assert_eq!(
        load_snapshot(&control).attempts[0].status,
        AttemptStatus::Cancelled as i32
    );
    assert!(
        control
            .held_dispatches_for_recovery(&recovery_worker())
            .expect("cancellation candidate disappeared")
            .is_empty()
    );
}

#[tokio::test]
async fn c2b_adapter_proof_drift_and_stale_collaboration_candidate_never_poll_or_write() {
    let collaboration_store = IsolatedStore::new("c2b-proof-drift-collaboration");
    let adapter_store = IsolatedStore::new("c2b-proof-drift-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let (_envelope, _, bundle) = persist_scripted_delivered_dispatch(
        &collaboration_store.database_path(),
        &adapter_database,
        &adapter_store.root,
        Vec::new(),
        0,
    )
    .await;
    assert_eq!(
        open_raw_adapter_store(&adapter_database)
            .execute(
                "UPDATE adapter_dispatches SET fencing_token = fencing_token + 1
                 WHERE dispatch_id = 'dispatch-001'",
                [],
            )
            .expect("tamper Adapter delivered proof"),
        1
    );
    let before = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    )
    .inspect_store()
    .expect("inspect before Adapter proof rejection");
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let drift_counts = DriverCallCounts::default();
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(drift_counts.clone(), Vec::new()),
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    assert!(runner.run_once().await.is_err());
    assert_eq!(drift_counts.next.load(Ordering::SeqCst), 0);
    assert_eq!(drift_counts.send.load(Ordering::SeqCst), 0);
    assert_eq!(drift_counts.reconcile.load(Ordering::SeqCst), 0);
    drop(runner);
    assert_eq!(
        open_control(
            &collaboration_store.database_path(),
            FixedClock::new(FIXED_TIME),
        )
        .inspect_store()
        .expect("inspect after Adapter proof rejection"),
        before
    );

    let collaboration_store = IsolatedStore::new("c2b-stale-candidate-collaboration");
    let adapter_store = IsolatedStore::new("c2b-stale-candidate-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let (envelope, _, bundle) = persist_scripted_delivered_dispatch(
        &collaboration_store.database_path(),
        &adapter_database,
        &adapter_store.root,
        Vec::new(),
        0,
    )
    .await;
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: hex::encode(Sha256::digest(&bundle)),
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let snapshot = load_snapshot(&control);
    control
        .execute(&cancellation_request(&snapshot), &attempt_supervisor())
        .expect("make Collaboration delivered candidate stale");
    let before = control
        .inspect_store()
        .expect("inspect stale candidate baseline");
    let stale_counts = DriverCallCounts::default();
    let mut adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ScriptedCountingDriver::new(stale_counts.clone(), Vec::new()),
        clock,
    );
    let report = pump_observations(&mut control, &mut adapter, &envelope, &harness_adapter())
        .await
        .expect("retire stale Collaboration candidate");
    assert_eq!(report.observations_seen, 0);
    assert_eq!(stale_counts.next.load(Ordering::SeqCst), 0);
    assert_eq!(stale_counts.send.load(Ordering::SeqCst), 0);
    assert_eq!(stale_counts.reconcile.load(Ordering::SeqCst), 0);
    assert_eq!(
        control
            .inspect_store()
            .expect("inspect after stale candidate retirement"),
        before
    );
}

#[tokio::test]
async fn durable_adapter_reconciliation_evidence_recovers_outcome_unknown_authority() {
    let collaboration_store = IsolatedStore::new("collaboration-adapter-reconciliation");
    let adapter_store = IsolatedStore::new("collaboration-adapter-reconciliation-edge");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let bundle = br#"{"input":"reconcile-governed-loop"}"#.to_vec();
    let bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let writer_edge = open_loop_adapter_edge(&adapter_database);
    let reader_edge = open_loop_adapter_edge(&adapter_database);
    let clock = FixedClock::new(FIXED_TIME);
    let guard = AdapterBackedFixtureGuard {
        edge: reader_edge,
        input_bundle_sha256: bundle_sha256.clone(),
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let leased = advance_through_lease(&mut control);
    let dispatch = dispatch_command_with_bundle(&leased, &bundle_sha256);
    control
        .execute(&dispatch, &attempt_supervisor())
        .expect("commit reconciliation dispatch intent");
    let envelope = control
        .pending_dispatches(&harness_adapter())
        .expect("poll reconciliation dispatch")
        .into_iter()
        .next()
        .expect("pending reconciliation envelope")
        .envelope;
    let resolver = LoopMaterialResolver {
        bundle,
        workspace_root: adapter_store.root.clone(),
    };
    let mut adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        writer_edge,
        resolver,
        FakeCodexDriver::default().with_reconciliation_finding(
            ReconciliationFinding::NoEffectProven {
                evidence_ref: "fixture://codex/fake/no-effect-proven".to_owned(),
            },
        ),
        clock,
    );
    let dispatched = adapter.dispatch(&envelope).await.expect("dispatch fixture");
    let receipt = match dispatched.outcome.expect("dispatch outcome") {
        dispatch_result::Outcome::Receipt(value) => value,
        dispatch_result::Outcome::Error(error) => panic!("unexpected dispatch error: {error:?}"),
    };
    control
        .ingest_dispatch_receipt(&receipt, &harness_adapter())
        .expect("ingest reconciliation delivery");
    for expected in ["ACK", "running"] {
        let observation = adapter
            .pump_one(&envelope)
            .await
            .expect("pump fixture event")
            .unwrap_or_else(|| panic!("missing {expected} observation"));
        let ingested = control
            .ingest_harness_observation(&observation, &harness_adapter())
            .unwrap_or_else(|error| panic!("ingest {expected}: {error}"));
        assert_eq!(
            ingested.disposition,
            HarnessFactIngestionDisposition::Consumed
        );
        adapter
            .mark_observation_consumed(&observation.observation_id)
            .expect("settle fixture observation");
    }

    let running = load_snapshot(&control);
    let unknown = committed_snapshot(
        &control
            .execute(&unknown_command(&running), &recovery_worker())
            .expect("mark external outcome unknown"),
    );
    let reconciling = committed_snapshot(
        &control
            .execute(
                &begin_reconciliation(&unknown, "reconcile-adapter-001"),
                &recovery_worker(),
            )
            .expect("begin Adapter reconciliation"),
    );
    let evidence = adapter
        .reconcile_dispatch("reconcile-adapter-001", &envelope.dispatch_id)
        .await
        .expect("persist Adapter reconciliation evidence");
    let unsafe_retry = reconciliation_result_with_evidence(
        &reconciling,
        "reconcile-adapter-001",
        &evidence.evidence_id,
        ReconciliationDisposition::RetryIdempotent,
    );
    let unsafe_retry = match unsafe_retry.command.as_ref().expect("unsafe retry command") {
        collaboration_command::Command::RecordAttemptReconciliation(value) => value,
        _ => panic!("expected reconciliation command"),
    };
    let audit_guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: bundle_sha256,
    };
    assert_eq!(
        audit_guard.validate_reconciliation(unsafe_retry, &reconciling),
        Err(ReferenceGuardRejection::UnverifiedReference),
        "no-effect evidence must not authorize a caller-selected retry disposition"
    );
    let recovered = committed_snapshot(
        &control
            .execute(
                &reconciliation_result_with_evidence(
                    &reconciling,
                    "reconcile-adapter-001",
                    &evidence.evidence_id,
                    ReconciliationDisposition::NoEffectProven,
                ),
                &recovery_worker(),
            )
            .expect("commit verified reconciliation result"),
    );
    assert_eq!(
        recovered.run.as_ref().expect("run").status,
        RunStatus::Active as i32
    );
    assert_eq!(
        recovered.attempts[0].status,
        AttemptStatus::Interrupted as i32
    );
    assert_eq!(
        recovered.attempts[0].recovery_class,
        RecoveryClass::RetryIdempotent as i32
    );
    assert_eq!(adapter.driver().reconcile_count(), 1);
    let replayed = adapter
        .reconcile_dispatch("reconcile-adapter-001", &envelope.dispatch_id)
        .await
        .expect("replay durable reconciliation evidence");
    assert!(replayed.replayed);
    assert_eq!(replayed.evidence_id, evidence.evidence_id);
    assert_eq!(adapter.driver().reconcile_count(), 1);
}

fn unknown_dispatch_receipt(envelope: &DispatchEnvelope, receipt_id: &str) -> DispatchReceipt {
    DispatchReceipt {
        receipt_id: receipt_id.to_owned(),
        disposition: DeliveryDisposition::Unknown as i32,
        attempt_id: envelope.attempt_id.clone(),
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
        adapter_id: "adapter:codex".to_owned(),
        capability_profile_id: "single-harness-capability".to_owned(),
        observed_protocol: Some(codex_protocol_fingerprint()),
        receipt_digest_sha256: "9".repeat(64),
        evidence_ref: "fixture://delivery-unknown".to_owned(),
        delivered_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        ..Default::default()
    }
}

async fn assert_runner_recovers_held_dispatch(
    finding: ReconciliationFinding,
    expected_run_status: RunStatus,
    expected_attempt_status: AttemptStatus,
    expected_task_finding: bool,
    prebegin_without_evidence: bool,
    block_with_pending_observation: bool,
    expected_reconcile_count: u64,
) {
    let collaboration_store = IsolatedStore::new("runner-held-recovery-collaboration");
    let adapter_store = IsolatedStore::new("runner-held-recovery-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let clock = FixedClock::new(FIXED_TIME);
    let mut setup = open_control(&collaboration_store.database_path(), clock.clone());
    let (pending, _) = advance_through_dispatch(&mut setup);
    let envelope = setup
        .pending_dispatches(&harness_adapter())
        .expect("pending dispatch")
        .into_iter()
        .next()
        .expect("dispatch envelope")
        .envelope;
    let run = pending.run.as_ref().expect("run");
    let mut edge = open_loop_adapter_edge(&adapter_database);
    edge.prepare_dispatch(&envelope, FIXED_TIME)
        .expect("prepare unknown dispatch");
    edge.begin_delivery(&envelope.dispatch_id, FIXED_TIME)
        .expect("begin unknown dispatch");
    edge.bind_dispatch_task_lineage(
        &envelope.dispatch_id,
        &run.task_id,
        run.task_revision_at_creation,
        run.work_revision,
        FIXED_TIME,
    )
    .expect("bind task lineage");
    let receipt = unknown_dispatch_receipt(&envelope, "receipt-runner-delivery-unknown");
    edge.record_dispatch_receipt(&receipt, b"delivery-unknown", FIXED_TIME)
        .expect("persist unknown receipt");
    drop(edge);
    drop(setup);

    let verifier =
        AdapterBackedHarnessEvidenceResolver::new(open_loop_adapter_edge(&adapter_database));
    let mut forged = CollaborationCommand {
        command: Some(collaboration_command::Command::MarkAttemptOutcomeUnknown(
            MarkAttemptOutcomeUnknownCommand {
                base: Some(attempt_base(&pending, "forged-delivery-unknown")),
                reason_code: DELIVERY_OUTCOME_UNKNOWN_REASON_CODE.to_owned(),
                uncertainty_evidence_id: "forged-receipt".to_owned(),
            },
        )),
    };
    set_digest(&mut forged);
    let forged = match forged.command.as_ref().expect("forged command") {
        collaboration_command::Command::MarkAttemptOutcomeUnknown(value) => value,
        _ => unreachable!(),
    };
    assert_eq!(
        verifier.validate_delivery_unknown(forged, &pending),
        Err(ReferenceGuardRejection::UnverifiedReference)
    );
    drop(verifier);

    let (guard, _) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let first = control
        .ingest_dispatch_receipt(&receipt, &harness_adapter())
        .expect("mark unknown delivery");
    assert!(
        first
            .authority_result
            .as_ref()
            .is_some_and(|result| result.committed_event.is_some())
    );
    let replay = control
        .ingest_dispatch_receipt(&receipt, &harness_adapter())
        .expect("replay unknown delivery");
    assert!(
        replay
            .authority_result
            .as_ref()
            .is_some_and(|result| result.replayed)
    );
    let held = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("held dispatches");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].state, HeldDispatchRecoveryState::OutcomeUnknown);
    assert!(
        control
            .held_dispatches_for_recovery(&harness_adapter())
            .is_err()
    );
    if prebegin_without_evidence {
        let unknown = load_snapshot(&control);
        control
            .execute(
                &begin_reconciliation(&unknown, "adapter-reconciliation:dispatch-001"),
                &recovery_worker(),
            )
            .expect("prebegin reconciliation");
    }
    if block_with_pending_observation {
        let mut edge = open_loop_adapter_edge(&adapter_database);
        edge.append_observation(
            &envelope.dispatch_id,
            "c2b-held-retained-barrier",
            b"c2b-held-retained-barrier",
            adapter_observation(
                &envelope,
                ObservationCriticality::Control,
                harness_observation::Payload::Lifecycle(LifecycleObservation {
                    kind: LifecycleKind::ExecutionInterrupted as i32,
                    native_item_ref: None,
                    safe_status_code: Some("fixture:held-barrier".to_owned()),
                    side_effect_certainty: SideEffectCertainty::Unknown as i32,
                    native_will_retry: None,
                }),
            ),
            FIXED_TIME,
        )
        .expect("append held durable replay barrier");
    }
    drop(control);

    let (guard, _) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let reopened = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("reopen held dispatches");
    assert_eq!(reopened.len(), 1);
    if prebegin_without_evidence {
        assert!(matches!(
            reopened[0].state,
            HeldDispatchRecoveryState::Reconciling { .. }
        ));
    }
    let reconcile_count = Arc::new(AtomicU64::new(0));
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle: Vec::new(),
            workspace_root: adapter_store.root.clone(),
        },
        CountingRecoveryDriver {
            reconcile_count: Arc::clone(&reconcile_count),
            finding,
        },
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let first_cycle = runner.run_once().await.expect("recover held dispatch");
    assert!(first_cycle.terminal_dispatch_ids.is_empty());
    assert_eq!(
        first_cycle.held_dispatch_ids.as_slice(),
        std::slice::from_ref(&envelope.dispatch_id)
    );
    if block_with_pending_observation {
        assert_eq!(first_cycle.observations_seen, u64::from(true));
        assert_eq!(first_cycle.observations_retained, u64::from(true));
    } else {
        assert_eq!(first_cycle.observations_seen, u64::from(false));
        assert_eq!(first_cycle.observations_retained, u64::from(false));
    }
    assert_eq!(
        first_cycle.task_recovery_findings.len(),
        usize::from(expected_task_finding)
    );
    let second_cycle = runner.run_once().await.expect("replay held recovery");
    assert!(second_cycle.terminal_dispatch_ids.is_empty());
    if block_with_pending_observation {
        assert_eq!(
            second_cycle.observations_seen,
            u64::from(true),
            "the retained normal barrier is retried once per recovery cycle"
        );
        assert_eq!(second_cycle.observations_retained, u64::from(true));
    } else {
        assert_eq!(
            second_cycle.observations_seen,
            u64::from(false),
            "reconciliation:* evidence must not enter normal replay"
        );
        assert_eq!(second_cycle.observations_retained, u64::from(false));
    }
    assert_eq!(
        reconcile_count.load(Ordering::SeqCst),
        expected_reconcile_count
    );
    drop(runner);

    let reopened = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    let snapshot = load_snapshot(&reopened);
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        expected_run_status as i32
    );
    assert_eq!(snapshot.attempts[0].status, expected_attempt_status as i32);
}

#[derive(Clone, Copy)]
enum UnknownEvidenceTamper {
    AdapterId,
    FencingToken,
    TaskLineage,
}

fn assert_unknown_evidence_tamper_is_zero_authority_write(
    label: &str,
    tamper: UnknownEvidenceTamper,
) {
    let collaboration_store = IsolatedStore::new(label);
    let adapter_store = IsolatedStore::new(&format!("{label}-adapter"));
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let clock = FixedClock::new(FIXED_TIME);
    let mut setup = open_control(&collaboration_store.database_path(), clock.clone());
    let (pending, _) = advance_through_dispatch(&mut setup);
    let envelope = setup
        .pending_dispatches(&harness_adapter())
        .expect("pending dispatch")
        .into_iter()
        .next()
        .expect("dispatch envelope")
        .envelope;
    let run = pending.run.as_ref().expect("run");
    let mut edge = open_loop_adapter_edge(&adapter_database);
    edge.prepare_dispatch(&envelope, FIXED_TIME)
        .expect("prepare unknown dispatch");
    edge.begin_delivery(&envelope.dispatch_id, FIXED_TIME)
        .expect("begin unknown dispatch");
    let lineage_task_id = if matches!(tamper, UnknownEvidenceTamper::TaskLineage) {
        "task-wrong"
    } else {
        &run.task_id
    };
    edge.bind_dispatch_task_lineage(
        &envelope.dispatch_id,
        lineage_task_id,
        run.task_revision_at_creation,
        run.work_revision,
        FIXED_TIME,
    )
    .expect("bind task lineage fixture");
    let mut receipt = unknown_dispatch_receipt(&envelope, "receipt-tampered-delivery-unknown");
    match tamper {
        UnknownEvidenceTamper::AdapterId => receipt.adapter_id = "adapter:wrong".to_owned(),
        UnknownEvidenceTamper::FencingToken => receipt.fencing_token += 1,
        UnknownEvidenceTamper::TaskLineage => {}
    }
    edge.record_dispatch_receipt(&receipt, b"tampered-delivery-unknown", FIXED_TIME)
        .expect("persist tampered receipt fixture");
    drop(edge);
    drop(setup);

    let (guard, _) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let mut control = open_control_with_guard(&collaboration_store.database_path(), clock, guard);
    let before = control.inspect_store().expect("inspect before rejection");
    let rejected = control
        .ingest_dispatch_receipt(&receipt, &harness_adapter())
        .expect("reject tampered unknown evidence");
    let authority_result = rejected
        .authority_result
        .as_ref()
        .expect("authority rejection");
    assert_eq!(
        error_code(authority_result),
        CollaborationErrorCode::RecoveryRequired
    );
    assert!(authority_result.committed_event.is_none());
    assert_eq!(
        control.inspect_store().expect("inspect after rejection"),
        before,
        "unverified Adapter evidence must perform zero Authority writes"
    );
}

#[test]
fn delivery_unknown_with_wrong_adapter_id_is_zero_authority_write() {
    assert_unknown_evidence_tamper_is_zero_authority_write(
        "unknown-wrong-adapter",
        UnknownEvidenceTamper::AdapterId,
    );
}

#[test]
fn delivery_unknown_with_wrong_fencing_token_is_zero_authority_write() {
    assert_unknown_evidence_tamper_is_zero_authority_write(
        "unknown-wrong-fence",
        UnknownEvidenceTamper::FencingToken,
    );
}

#[test]
fn delivery_unknown_with_wrong_task_lineage_is_zero_authority_write() {
    assert_unknown_evidence_tamper_is_zero_authority_write(
        "unknown-wrong-task-lineage",
        UnknownEvidenceTamper::TaskLineage,
    );
}

#[tokio::test]
async fn proven_not_sent_receipt_never_pumps_or_forges_terminal_or_held_state() {
    let collaboration_store = IsolatedStore::new("runner-proven-not-sent-collaboration");
    let adapter_store = IsolatedStore::new("runner-proven-not-sent-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let clock = FixedClock::new(FIXED_TIME);
    let bundle = br#"{"input":"proven-not-sent"}"#.to_vec();
    let bundle_sha256 = hex::encode(Sha256::digest(&bundle));
    let guard = AdapterBackedFixtureGuard {
        edge: open_loop_adapter_edge(&adapter_database),
        input_bundle_sha256: bundle_sha256.clone(),
    };
    let mut control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let leased = advance_through_lease(&mut control);
    let dispatch = dispatch_command_with_bundle(&leased, &bundle_sha256);
    let before = committed_snapshot(
        &control
            .execute(&dispatch, &attempt_supervisor())
            .expect("record dispatch intent"),
    );
    let envelope = control
        .pending_dispatches(&harness_adapter())
        .expect("pending dispatch")
        .into_iter()
        .next()
        .expect("dispatch envelope")
        .envelope;
    let send_count = Arc::new(AtomicU64::new(0));
    let next_event_count = Arc::new(AtomicU64::new(0));
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle,
            workspace_root: adapter_store.root.clone(),
        },
        ProvenNotSentDriver {
            send_count: Arc::clone(&send_count),
            next_event_count: Arc::clone(&next_event_count),
        },
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());

    let first = runner.run_once().await.expect("reject initial dispatch");
    assert_eq!(first.dispatches_seen, 1);
    assert_eq!(first.dispatches_delivered, 0);
    assert_eq!(first.dispatches_rejected, 1);
    assert_eq!(first.observations_seen, 0);
    assert!(first.terminal_dispatch_ids.is_empty());
    assert!(first.held_dispatch_ids.is_empty());
    assert_eq!(send_count.load(Ordering::SeqCst), 1);
    assert_eq!(next_event_count.load(Ordering::SeqCst), 0);

    let replay = runner.run_once().await.expect("replay rejected receipt");
    assert_eq!(replay.dispatches_seen, 1);
    assert_eq!(replay.dispatches_delivered, 0);
    assert_eq!(replay.dispatches_rejected, 1);
    assert_eq!(replay.observations_seen, 0);
    assert!(replay.terminal_dispatch_ids.is_empty());
    assert!(replay.held_dispatch_ids.is_empty());
    assert_eq!(send_count.load(Ordering::SeqCst), 1);
    assert_eq!(next_event_count.load(Ordering::SeqCst), 0);
    drop(runner);

    let edge = open_loop_adapter_edge(&adapter_database);
    let receipt = edge
        .dispatch_receipt(&envelope.dispatch_id)
        .expect("read rejected receipt")
        .expect("durable rejected receipt");
    assert_eq!(
        DeliveryDisposition::try_from(receipt.disposition),
        Ok(DeliveryDisposition::Rejected)
    );
    assert_eq!(
        edge.inspect().expect("inspect Adapter edge").dispatch_count,
        1
    );
    drop(edge);

    let control = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    assert_eq!(load_snapshot(&control), before);
}

#[tokio::test]
async fn begin_delivery_without_receipt_recovers_unknown_without_resend_or_pump() {
    let collaboration_store = IsolatedStore::new("runner-begin-only-collaboration");
    let adapter_store = IsolatedStore::new("runner-begin-only-adapter");
    let adapter_database = adapter_store.root.join("adapter-edge.sqlcipher");
    let clock = FixedClock::new(FIXED_TIME);
    let mut setup = open_control(&collaboration_store.database_path(), clock.clone());
    advance_through_dispatch(&mut setup);
    let envelope = setup
        .pending_dispatches(&harness_adapter())
        .expect("pending dispatch")
        .into_iter()
        .next()
        .expect("dispatch envelope")
        .envelope;
    let mut edge = open_loop_adapter_edge(&adapter_database);
    edge.prepare_dispatch(&envelope, FIXED_TIME)
        .expect("prepare dispatch before crash");
    edge.begin_delivery(&envelope.dispatch_id, FIXED_TIME)
        .expect("begin delivery before crash");
    assert!(
        edge.dispatch_receipt(&envelope.dispatch_id)
            .expect("read absent receipt")
            .is_none()
    );
    drop(edge);
    drop(setup);

    let (guard, _) = TaskActivationGuardSet::new(AdapterBackedHarnessEvidenceResolver::new(
        open_loop_adapter_edge(&adapter_database),
    ));
    let control =
        open_control_with_guard(&collaboration_store.database_path(), clock.clone(), guard);
    let reconcile_count = Arc::new(AtomicU64::new(0));
    let adapter = GovernedHarnessAdapter::new(
        "adapter:codex",
        "single-harness-capability",
        codex_protocol_fingerprint(),
        open_loop_adapter_edge(&adapter_database),
        LoopMaterialResolver {
            bundle: Vec::new(),
            workspace_root: adapter_store.root.clone(),
        },
        CountingRecoveryDriver {
            reconcile_count: Arc::clone(&reconcile_count),
            finding: ReconciliationFinding::OutcomeUnknown {
                evidence_ref: "fixture://begin-only-still-unknown".to_owned(),
            },
        },
        clock,
    );
    let runner = GovernedHarnessDispatchRunner::new(control, adapter, harness_adapter());
    let first = runner
        .run_once()
        .await
        .expect("recover begin-only dispatch");
    assert_eq!(first.dispatches_seen, 1);
    assert_eq!(
        first.held_dispatch_ids.as_slice(),
        std::slice::from_ref(&envelope.dispatch_id)
    );
    assert!(first.terminal_dispatch_ids.is_empty());
    assert_eq!(first.observations_seen, 0);
    assert!(first.task_recovery_findings.is_empty());
    assert_eq!(reconcile_count.load(Ordering::SeqCst), 0);
    let replay = runner
        .run_once()
        .await
        .expect("replay recovered begin-only dispatch");
    assert_eq!(replay.dispatches_seen, 0);
    assert!(replay.terminal_dispatch_ids.is_empty());
    assert_eq!(replay.observations_seen, 0);
    assert_eq!(replay.task_recovery_findings.len(), 1);
    assert_eq!(reconcile_count.load(Ordering::SeqCst), 1);
    drop(runner);

    let edge = open_loop_adapter_edge(&adapter_database);
    let receipt = edge
        .dispatch_receipt(&envelope.dispatch_id)
        .expect("read recovered receipt")
        .expect("recovered Unknown receipt");
    assert_eq!(
        DeliveryDisposition::try_from(receipt.disposition),
        Ok(DeliveryDisposition::Unknown)
    );
    assert_eq!(receipt.adapter_id, edge.adapter_id());
    let inspection = edge.inspect().expect("inspect recovered Adapter edge");
    assert_eq!(inspection.dispatch_count, 1);
    assert_eq!(inspection.delivery_unknown_count, 1);
    drop(edge);

    let control = open_control(
        &collaboration_store.database_path(),
        FixedClock::new(FIXED_TIME),
    );
    let snapshot = load_snapshot(&control);
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Held as i32
    );
    assert_eq!(snapshot.attempts[0].status, AttemptStatus::Held as i32);
    assert_eq!(
        control
            .held_dispatches_for_recovery(&recovery_worker())
            .expect("durable held dispatches")
            .len(),
        1
    );
}

#[tokio::test]
async fn runner_records_no_effect_without_task_interruption_or_redispatch() {
    assert_runner_recovers_held_dispatch(
        ReconciliationFinding::NoEffectProven {
            evidence_ref: "fixture://no-effect".to_owned(),
        },
        RunStatus::Active,
        AttemptStatus::Interrupted,
        false,
        false,
        false,
        1,
    )
    .await;
}

#[tokio::test]
async fn runner_maps_unknown_reconciliation_to_manual_hold_and_durable_task_finding() {
    assert_runner_recovers_held_dispatch(
        ReconciliationFinding::OutcomeUnknown {
            evidence_ref: "fixture://still-unknown".to_owned(),
        },
        RunStatus::Held,
        AttemptStatus::Held,
        true,
        false,
        false,
        1,
    )
    .await;
}

#[tokio::test]
async fn reconciling_without_durable_evidence_stays_held_without_native_reconcile() {
    assert_runner_recovers_held_dispatch(
        ReconciliationFinding::OutcomeUnknown {
            evidence_ref: "unused".to_owned(),
        },
        RunStatus::Held,
        AttemptStatus::Reconciling,
        true,
        true,
        false,
        0,
    )
    .await;
}

#[tokio::test]
async fn held_outcome_unknown_with_pending_barrier_never_reconciles_or_polls() {
    assert_runner_recovers_held_dispatch(
        ReconciliationFinding::OutcomeUnknown {
            evidence_ref: "unused-behind-durable-barrier".to_owned(),
        },
        RunStatus::Held,
        AttemptStatus::OutcomeUnknown,
        true,
        false,
        true,
        0,
    )
    .await;
}

#[test]
fn adapter_candidate_facts_ingest_at_least_once_and_stale_facts_require_quarantine() {
    let isolated = IsolatedStore::new("collaboration-harness-ingestion");
    let mut control = open_control(&isolated.database_path(), FixedClock::new(FIXED_TIME));
    let (pending, _) = advance_through_dispatch(&mut control);
    let fence = pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let delivery = DispatchReceipt {
        receipt_id: "delivery-001".to_owned(),
        disposition: DeliveryDisposition::Delivered as i32,
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: "dispatch-001".to_owned(),
        fencing_token: fence,
        adapter_id: "adapter:codex".to_owned(),
        capability_profile_id: "codex-profile".to_owned(),
        native_session_ref: Some("codex-thread-001".to_owned()),
        native_execution_ref: Some("codex-turn-001".to_owned()),
        receipt_digest_sha256: "d".repeat(64),
        delivered_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        ..DispatchReceipt::default()
    };
    let delivered = control
        .ingest_dispatch_receipt(&delivery, &harness_adapter())
        .expect("ingest delivery");
    assert_eq!(
        delivered.disposition,
        HarnessFactIngestionDisposition::Consumed
    );

    let ack = HarnessObservation {
        observation_id: "ack-observation-001".to_owned(),
        adapter_id: "adapter:codex".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: "dispatch-001".to_owned(),
        fencing_token: fence,
        observation_sequence: 1,
        native_event_digest_sha256: "e".repeat(64),
        capability_profile_id: "codex-profile".to_owned(),
        criticality: ObservationCriticality::Control as i32,
        raw_evidence_ref: "adapter-edge://ack-observation-001".to_owned(),
        payload: Some(harness_observation::Payload::Ack(HarnessAckObservation {
            disposition: AckDisposition::Accepted as i32,
            ack_receipt_id: "ack-001".to_owned(),
            native_session_ref: Some("codex-thread-001".to_owned()),
            native_execution_ref: Some("codex-turn-001".to_owned()),
        })),
        ..HarnessObservation::default()
    };
    let before_stale = control.inspect_store().expect("inspect");
    let stale = HarnessObservation {
        observation_id: "stale-ack-001".to_owned(),
        fencing_token: fence + 1,
        ..ack.clone()
    };
    let rejected = control
        .ingest_harness_observation(&stale, &harness_adapter())
        .expect("reject stale observation");
    assert!(matches!(
        rejected.disposition,
        HarnessFactIngestionDisposition::QuarantineRequired { .. }
    ));
    assert_eq!(control.inspect_store().expect("inspect"), before_stale);

    let acknowledged = control
        .ingest_harness_observation(&ack, &harness_adapter())
        .expect("ingest ack");
    assert_eq!(
        acknowledged.disposition,
        HarnessFactIngestionDisposition::Consumed
    );

    let running = HarnessObservation {
        observation_id: "running-001".to_owned(),
        observation_sequence: 2,
        native_event_digest_sha256: "f".repeat(64),
        payload: Some(harness_observation::Payload::Lifecycle(
            LifecycleObservation {
                kind: LifecycleKind::ExecutionStarted as i32,
                side_effect_certainty: SideEffectCertainty::Unknown as i32,
                ..LifecycleObservation::default()
            },
        )),
        ..ack.clone()
    };
    let started = control
        .ingest_harness_observation(&running, &harness_adapter())
        .expect("ingest running");
    assert_eq!(
        started.disposition,
        HarnessFactIngestionDisposition::Consumed
    );
    let replayed = control
        .ingest_harness_observation(&ack, &harness_adapter())
        .expect("replay ack after later revision");
    assert!(
        replayed
            .authority_result
            .as_ref()
            .expect("replayed result")
            .replayed
    );

    let before_conflict = control.inspect_store().expect("inspect before conflict");
    let conflicting_ack = HarnessObservation {
        native_event_digest_sha256: "a".repeat(64),
        ..ack
    };
    let conflict = control
        .ingest_harness_observation(&conflicting_ack, &harness_adapter())
        .expect("classify source identity conflict");
    assert!(matches!(
        conflict.disposition,
        HarnessFactIngestionDisposition::QuarantineRequired { .. }
    ));
    assert_eq!(
        control.inspect_store().expect("inspect after conflict"),
        before_conflict
    );
}

#[test]
fn unknown_critical_harness_fact_holds_authority_and_requires_quarantine() {
    let isolated = IsolatedStore::new("collaboration-unknown-critical-ingestion");
    let mut control = open_control(&isolated.database_path(), FixedClock::new(FIXED_TIME));
    let running = advance_through_running(&mut control);
    let fence = running.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let observation = HarnessObservation {
        observation_id: "unknown-terminal-001".to_owned(),
        adapter_id: "adapter:codex".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: "dispatch-001".to_owned(),
        fencing_token: fence,
        observation_sequence: 3,
        native_event_digest_sha256: "7".repeat(64),
        capability_profile_id: "codex-profile".to_owned(),
        criticality: ObservationCriticality::Terminal as i32,
        raw_evidence_ref: "adapter-edge://unknown-terminal-001".to_owned(),
        payload: None,
        ..HarnessObservation::default()
    };

    let held = control
        .ingest_harness_observation(&observation, &harness_adapter())
        .expect("hold unknown critical observation");
    assert!(matches!(
        held.disposition,
        HarnessFactIngestionDisposition::QuarantineRequired { .. }
    ));
    let snapshot = committed_snapshot(held.authority_result.as_ref().expect("authority result"));
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Held as i32
    );
    assert_eq!(snapshot.steps[0].status, StepStatus::Held as i32);
    assert_eq!(
        snapshot.attempts[0].status,
        AttemptStatus::OutcomeUnknown as i32
    );

    let replayed = control
        .ingest_harness_observation(&observation, &harness_adapter())
        .expect("replay unknown critical observation");
    assert!(matches!(
        replayed.disposition,
        HarnessFactIngestionDisposition::QuarantineRequired { .. }
    ));
    assert!(
        replayed
            .authority_result
            .as_ref()
            .expect("replayed authority result")
            .replayed
    );
}

#[test]
fn cancellation_is_confirmed_only_by_structured_interruption_observation() {
    let isolated = IsolatedStore::new("collaboration-interrupted-ingestion");
    let mut control = open_control(&isolated.database_path(), FixedClock::new(FIXED_TIME));
    let running = advance_through_running(&mut control);
    let pending = committed_snapshot(
        &control
            .execute(&cancellation_request(&running), &attempt_supervisor())
            .expect("request cancellation"),
    );
    let fence = pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let interrupted = HarnessObservation {
        observation_id: "interrupted-001".to_owned(),
        adapter_id: "adapter:codex".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: "dispatch-001".to_owned(),
        fencing_token: fence,
        observation_sequence: 3,
        native_event_digest_sha256: "8".repeat(64),
        capability_profile_id: "codex-profile".to_owned(),
        criticality: ObservationCriticality::Terminal as i32,
        raw_evidence_ref: "adapter-edge://interrupted-001".to_owned(),
        payload: Some(harness_observation::Payload::Lifecycle(
            LifecycleObservation {
                kind: LifecycleKind::ExecutionInterrupted as i32,
                side_effect_certainty: SideEffectCertainty::NoneProven as i32,
                ..LifecycleObservation::default()
            },
        )),
        ..HarnessObservation::default()
    };

    let confirmed = control
        .ingest_harness_observation(&interrupted, &harness_adapter())
        .expect("confirm cancellation from interruption");
    assert_eq!(
        confirmed.disposition,
        HarnessFactIngestionDisposition::Consumed
    );
    let snapshot = committed_snapshot(
        confirmed
            .authority_result
            .as_ref()
            .expect("authority result"),
    );
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Cancelled as i32
    );
    assert_eq!(snapshot.steps[0].status, StepStatus::Cancelled as i32);
    assert_eq!(snapshot.attempts[0].status, AttemptStatus::Cancelled as i32);
}

#[test]
fn cancellation_delivery_unknown_reconciliation_and_retry_are_distinct_facts() {
    let isolated = IsolatedStore::new("collaboration-cancel-reconcile");
    let mut control = open_control(&isolated.database_path(), FixedClock::new(FIXED_TIME));
    let running = advance_through_running(&mut control);
    let pending = committed_snapshot(
        &control
            .execute(&cancellation_request(&running), &attempt_supervisor())
            .expect("request cancellation"),
    );
    assert_eq!(
        pending.run.as_ref().expect("run").status,
        RunStatus::CancellationPending as i32
    );
    assert_eq!(
        pending.attempts[0].status,
        AttemptStatus::CancellationPending as i32
    );

    let unknown = committed_snapshot(
        &control
            .execute(&cancellation_unknown(&pending), &recovery_worker())
            .expect("unknown cancellation"),
    );
    assert_eq!(
        unknown.run.as_ref().expect("run").status,
        RunStatus::Held as i32
    );
    assert_eq!(
        unknown.attempts[0].status,
        AttemptStatus::OutcomeUnknown as i32
    );

    let reconciling = committed_snapshot(
        &control
            .execute(
                &begin_reconciliation(&unknown, "reconcile-001"),
                &recovery_worker(),
            )
            .expect("begin reconciliation"),
    );
    assert_eq!(
        reconciling.attempts[0].status,
        AttemptStatus::Reconciling as i32
    );
    let before = control.inspect_store().expect("inspect");
    let wrong = control
        .execute(
            &reconciliation_result(&reconciling, "reconcile-wrong"),
            &recovery_worker(),
        )
        .expect("reject wrong reconciliation");
    assert_eq!(error_code(&wrong), CollaborationErrorCode::StateConflict);
    assert_eq!(control.inspect_store().expect("inspect"), before);

    let recovered = committed_snapshot(
        &control
            .execute(
                &reconciliation_result(&reconciling, "reconcile-001"),
                &recovery_worker(),
            )
            .expect("record reconciliation"),
    );
    assert_eq!(
        recovered.run.as_ref().expect("run").status,
        RunStatus::Active as i32
    );
    assert_eq!(
        recovered.attempts[0].status,
        AttemptStatus::Interrupted as i32
    );
    assert_eq!(
        recovered.attempts[0].recovery_class,
        RecoveryClass::RetryIdempotent as i32
    );
}

#[test]
fn governed_artifact_return_records_attempt_once_and_not_step_completion() {
    let isolated = IsolatedStore::new("collaboration-artifact-return");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    let running = advance_through_running(&mut control);
    let fence = running.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let before_unauthorized = control.inspect_store().expect("before unauthorized return");
    let unauthorized = control
        .execute(
            &attempt_return_command(&running, fence, 3),
            &harness_adapter(),
        )
        .expect("reject Harness return authority");
    assert_eq!(
        error_code(&unauthorized),
        CollaborationErrorCode::PermissionDenied
    );
    assert_eq!(
        control.inspect_store().expect("after unauthorized return"),
        before_unauthorized
    );

    let committed = control
        .execute(
            &attempt_return_command(&running, fence, 3),
            &artifact_authority(),
        )
        .expect("record governed Artifact return");
    let returned = committed_snapshot(&committed);
    assert_eq!(returned.attempts[0].status, AttemptStatus::Returned as i32);
    assert_eq!(returned.attempts[0].last_harness_sequence, 3);
    assert_eq!(returned.steps[0].status, StepStatus::ReturnPending as i32);
    assert_eq!(
        returned.run.as_ref().expect("run").status,
        RunStatus::ReturnPending as i32
    );
    let durable_returned = load_snapshot(&control);
    assert_eq!(durable_returned, returned);

    let replayed = control
        .execute(
            &attempt_return_command(&running, fence, 3),
            &artifact_authority(),
        )
        .expect("replay governed Artifact return");
    assert!(replayed.replayed);
    assert_eq!(committed_snapshot(&replayed), returned);

    let committed_step = control
        .execute(
            &commit_step_return_command(&durable_returned),
            &collaboration_control(),
        )
        .expect("commit verified Step return");
    let completed = committed_snapshot(&committed_step);
    assert_eq!(completed.steps[0].status, StepStatus::Returned as i32);
    assert_eq!(
        completed.run.as_ref().expect("run").status,
        RunStatus::Returned as i32
    );
    let commit_replay = control
        .execute(
            &commit_step_return_command(&durable_returned),
            &collaboration_control(),
        )
        .expect("replay verified Step return");
    assert!(commit_replay.replayed);
    assert_eq!(committed_snapshot(&commit_replay), completed);
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
    let projections = control
        .pending_projection_messages()
        .expect("pending typed Collaboration projections");
    assert_eq!(projections.len(), 5);
    assert_eq!(
        projections
            .last()
            .and_then(|value| value.snapshot.run.as_ref())
            .map(|value| value.revision),
        Some(5)
    );
    assert!(
        control
            .acknowledge_projection_message(
                &projections[0].message_id,
                &projections[0].canonical_payload_digest_sha256,
            )
            .expect("ack projection after projector commit")
    );
    assert!(
        control
            .acknowledge_projection_message(
                &projections[0].message_id,
                &projections[0].canonical_payload_digest_sha256,
            )
            .expect("idempotent projection ack replay")
    );
    assert_eq!(
        control
            .pending_projection_messages()
            .expect("remaining projections")
            .len(),
        4
    );
    assert_eq!(
        control
            .retained_projection_messages_for_rebuild()
            .expect("acknowledged projections remain rebuildable")
            .len(),
        5
    );
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
fn existing_collaboration_facts_generate_one_deterministic_rebuild_bootstrap() {
    let isolated = IsolatedStore::new("collaboration-projection-bootstrap");
    let path = isolated.database_path();
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&path, clock.clone());
    let (snapshot, _) = advance_through_dispatch(&mut control);
    let revision = snapshot.run.as_ref().expect("run").revision;
    let before = control.inspect_store().expect("before migration");
    drop(control);

    let connection = Connection::open(&path).expect("open encrypted store");
    connection
        .pragma_update(None, "key", format!("x'{}'", hex::encode(TEST_KEY)))
        .expect("apply SQLCipher key");
    connection
        .execute(
            "UPDATE collaboration_projection_migrations
             SET state='pending',completed_at_seconds=NULL
             WHERE migration_id='g4-08a-bootstrap-v1'",
            [],
        )
        .expect("simulate pre-bootstrap migrated store");
    drop(connection);

    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg("projection_migration_crash_probe_child")
        .arg("--nocapture")
        .env(MIGRATION_CRASH_PROBE, "1")
        .env(MIGRATION_CRASH_DB, &path)
        .status()
        .expect("launch migration crash probe");
    assert!(!status.success(), "migration probe must terminate by abort");

    let control = open_control(&path, clock.clone());
    let after = control.inspect_store().expect("after migration");
    assert_eq!(after.run_count, before.run_count);
    assert_eq!(after.event_count, before.event_count);
    assert_eq!(after.commit_receipt_count, before.commit_receipt_count);
    assert_eq!(after.outbox_count, before.outbox_count + 1);
    let retained = control
        .retained_projection_messages_for_rebuild()
        .expect("canonical rebuild feed");
    assert_eq!(retained.len(), 1);
    assert!(retained[0].rebuild_baseline);
    assert_eq!(retained[0].source_revision, revision);
    assert_eq!(
        retained[0].snapshot.run.as_ref().map(|run| run.revision),
        Some(revision)
    );
    let message_id = retained[0].message_id.clone();
    drop(control);

    let control = open_control(&path, clock);
    let reopened = control
        .retained_projection_messages_for_rebuild()
        .expect("idempotent reopen");
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened[0].message_id, message_id);
    assert_eq!(
        control.inspect_store().expect("reopen counts").outbox_count,
        after.outbox_count
    );
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
    let held = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("held recovery dispatches");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].state, HeldDispatchRecoveryState::OutcomeUnknown);

    let replayed = control
        .execute(&unknown, &recovery_worker())
        .expect("replay unknown outcome");
    assert!(replayed.replayed);
    assert_eq!(control.inspect_store().expect("unknown replay"), counts);
}

#[test]
fn delivered_terminal_unknown_atomically_holds_outbox_and_reopens_for_recovery() {
    let isolated = IsolatedStore::new("collaboration-delivered-terminal-unknown");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let running = advance_through_running(&mut control);
    assert_eq!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("read delivered observation candidate")
            .len(),
        1
    );

    let observation = unknown_terminal_observation(&running);
    let ingested = control
        .ingest_harness_observation(&observation, &harness_adapter())
        .expect("ingest terminal unknown observation");
    assert!(matches!(
        ingested.disposition,
        HarnessFactIngestionDisposition::QuarantineRequired { ref reason_code }
            if reason_code == "HARNESS_TERMINAL_OUTCOME_UNKNOWN"
    ));
    let snapshot = committed_snapshot(
        ingested
            .authority_result
            .as_ref()
            .expect("unknown Authority result"),
    );
    assert_eq!(
        snapshot.run.as_ref().expect("run").status,
        RunStatus::Held as i32
    );
    assert_eq!(snapshot.steps[0].status, StepStatus::Held as i32);
    assert_eq!(
        snapshot.attempts[0].status,
        AttemptStatus::OutcomeUnknown as i32
    );
    assert!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("exclude held delivered candidate")
            .is_empty()
    );
    let held = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("read held recovery candidate");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].state, HeldDispatchRecoveryState::OutcomeUnknown);
    let before_reopen = control.inspect_store().expect("inspect held Authority");
    let revision = snapshot.run.as_ref().expect("run").revision;
    drop(control);

    let mut reopened = open_control(&isolated.database_path(), clock);
    assert_eq!(
        reopened
            .held_dispatches_for_recovery(&recovery_worker())
            .expect("read reopened held recovery candidate")
            .len(),
        1
    );
    assert!(
        reopened
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("exclude reopened held candidate")
            .is_empty()
    );
    let replay = reopened
        .ingest_harness_observation(&observation, &harness_adapter())
        .expect("replay terminal unknown observation");
    assert!(
        replay
            .authority_result
            .as_ref()
            .is_some_and(|result| result.replayed)
    );
    assert_eq!(
        reopened.inspect_store().expect("inspect replay"),
        before_reopen
    );
    assert_eq!(
        load_snapshot(&reopened).run.as_ref().expect("run").revision,
        revision
    );
}

#[test]
fn delivered_observation_read_is_authorized_and_filters_attempt_state() {
    let isolated = IsolatedStore::new("collaboration-delivered-observation-read");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock);
    let (pending, _) = advance_through_dispatch(&mut control);
    let fence = pending.attempts[0]
        .lease
        .as_ref()
        .expect("lease")
        .fencing_token;
    let delivered = committed_snapshot(
        &control
            .execute(&delivery_command(&pending, fence), &harness_adapter())
            .expect("record delivery"),
    );
    let candidates = control
        .delivered_dispatches_for_observation(&harness_adapter())
        .expect("read dispatched candidate");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].envelope.dispatch_id, "dispatch-001");
    assert!(matches!(
        control.delivered_dispatches_for_observation(&recovery_worker()),
        Err(CollaborationControlError::DispatchPollNotAuthorized)
    ));
    let mut unauthenticated = harness_adapter();
    unauthenticated.authenticated = false;
    assert!(matches!(
        control.delivered_dispatches_for_observation(&unauthenticated),
        Err(CollaborationControlError::DispatchPollNotAuthorized)
    ));
    let empty_principal = principal(CollaborationPrincipalKind::HarnessAdapter, "");
    assert!(matches!(
        control.delivered_dispatches_for_observation(&empty_principal),
        Err(CollaborationControlError::DispatchPollNotAuthorized)
    ));

    let acknowledged = committed_snapshot(
        &control
            .execute(&ack_command(&delivered, fence, 1), &harness_adapter())
            .expect("record acknowledgement"),
    );
    assert_eq!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("read acknowledged candidate")
            .len(),
        1
    );
    let running = committed_snapshot(
        &control
            .execute(
                &running_command(&acknowledged, fence, 2),
                &harness_adapter(),
            )
            .expect("record running observation"),
    );
    assert_eq!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("read running candidate")
            .len(),
        1
    );
    control
        .execute(&cancellation_request(&running), &attempt_supervisor())
        .expect("request cancellation");
    assert!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("exclude cancellation candidate")
            .is_empty()
    );
}

#[test]
fn delivered_observation_batch_skips_non_live_history_with_a_stale_fence() {
    let isolated = IsolatedStore::new("collaboration-delivered-live-and-history-batch");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let running = advance_through_running(&mut control);
    let historical_fence = running.attempts[0]
        .lease
        .as_ref()
        .expect("historical attempt lease")
        .fencing_token;
    clock.set_seconds(FIXED_TIME + 31);
    let outcome_unknown = committed_snapshot(
        &control
            .execute(&unknown_command(&running), &recovery_worker())
            .expect("mark historical outcome unknown"),
    );
    assert_eq!(
        outcome_unknown.attempts[0].status,
        AttemptStatus::OutcomeUnknown as i32
    );
    assert_eq!(
        control
            .held_dispatches_for_recovery(&recovery_worker())
            .expect("historical dispatch held by Authority")
            .len(),
        1
    );
    drop(control);

    let connection = open_raw_collaboration_store(&isolated.database_path());
    assert_eq!(
        connection
            .execute(
                "UPDATE collaboration_outbox
                 SET delivery_state='delivered'
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND attempt_id='attempt-001'
                   AND delivery_state='held'",
                [],
            )
            .expect("inject legacy held-to-delivered outbox defect"),
        1
    );
    drop(connection);

    let mut control = open_control(&isolated.database_path(), clock);
    let reconciling = committed_snapshot(
        &control
            .execute(
                &begin_reconciliation(&outcome_unknown, "reconcile-history-001"),
                &recovery_worker(),
            )
            .expect("begin historical reconciliation"),
    );
    let interrupted = committed_snapshot(
        &control
            .execute(
                &reconciliation_result(&reconciling, "reconcile-history-001"),
                &recovery_worker(),
            )
            .expect("record historical retry-idempotent reconciliation"),
    );
    assert_eq!(
        interrupted.attempts[0].status,
        AttemptStatus::Interrupted as i32
    );
    let reacquired = committed_snapshot(
        &control
            .execute(
                &acquire_lease_from_snapshot(&interrupted, "cmd-reacquire-history-001"),
                &attempt_supervisor(),
            )
            .expect("reacquire historical Attempt lease"),
    );
    assert_eq!(reacquired.attempts[0].status, AttemptStatus::Leased as i32);
    assert_eq!(
        reacquired.attempts[0]
            .lease
            .as_ref()
            .expect("reacquired historical lease")
            .fencing_token,
        historical_fence + 1
    );

    let live = advance_unique_run_through_delivery(
        &mut control,
        "run-002",
        "step-002",
        "attempt-002",
        "dispatch-002",
    );
    assert_eq!(live.attempts[0].status, AttemptStatus::Dispatched as i32);

    let connection = open_raw_collaboration_store(&isolated.database_path());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM collaboration_outbox
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='delivered'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count mixed delivered batch"),
        2
    );
    drop(connection);

    let candidates = control
        .delivered_dispatches_for_observation(&harness_adapter())
        .expect("non-live stale fence must not poison live candidate");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].envelope.dispatch_id, "dispatch-002");
    assert_eq!(candidates[0].envelope.run_id, "run-002");
}

#[test]
fn terminal_unknown_keeps_an_already_held_dispatch_held() {
    let isolated = IsolatedStore::new("collaboration-already-held-terminal-unknown");
    let mut control = open_control(&isolated.database_path(), FixedClock::new(FIXED_TIME));
    let running = advance_through_running(&mut control);
    let cancellation_pending = committed_snapshot(
        &control
            .execute(&cancellation_request(&running), &attempt_supervisor())
            .expect("request cancellation"),
    );
    assert!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("normal queue excludes held cancellation")
            .is_empty()
    );
    let ingested = control
        .ingest_harness_observation(
            &unknown_terminal_observation(&cancellation_pending),
            &harness_adapter(),
        )
        .expect("hold already-held dispatch");
    assert!(
        ingested
            .authority_result
            .as_ref()
            .is_some_and(|result| result.committed_event.is_some())
    );
    let held = control
        .held_dispatches_for_recovery(&recovery_worker())
        .expect("read held dispatch");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].state, HeldDispatchRecoveryState::OutcomeUnknown);
}

#[test]
fn stale_delivered_outbox_for_outcome_unknown_is_not_an_observation_candidate() {
    let isolated = IsolatedStore::new("collaboration-stale-delivered-outcome-unknown");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    let running = advance_through_running(&mut control);
    control
        .ingest_harness_observation(&unknown_terminal_observation(&running), &harness_adapter())
        .expect("hold delivered dispatch after unknown terminal observation");
    drop(control);

    let connection = open_raw_collaboration_store(&isolated.database_path());
    assert_eq!(
        connection
            .execute(
                "UPDATE collaboration_outbox
                 SET delivery_state='delivered'
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='held'",
                [],
            )
            .expect("inject stale delivered recovery candidate"),
        1
    );
    drop(connection);

    let control = open_control(&isolated.database_path(), clock);
    assert!(
        control
            .delivered_dispatches_for_observation(&harness_adapter())
            .expect("filter stale delivered recovery candidate")
            .is_empty()
    );
}

#[test]
fn delivered_observation_read_fails_closed_on_digest_attempt_and_fingerprint_tampering() {
    let (digest_store, digest_clock) =
        persist_delivered_dispatch("collaboration-delivered-bad-digest");
    let digest_connection = open_raw_collaboration_store(&digest_store.database_path());
    assert_eq!(
        digest_connection
            .execute(
                "UPDATE collaboration_outbox
                 SET canonical_payload_digest_sha256=?1
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='delivered'",
                ["0".repeat(64)],
            )
            .expect("tamper digest"),
        1
    );
    drop(digest_connection);
    let digest_control = open_control(&digest_store.database_path(), digest_clock);
    assert!(matches!(
        digest_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (attempt_store, attempt_clock) =
        persist_delivered_dispatch("collaboration-delivered-bad-attempt-lineage");
    let attempt_connection = open_raw_collaboration_store(&attempt_store.database_path());
    assert_eq!(
        attempt_connection
            .execute(
                "UPDATE collaboration_outbox
                 SET attempt_id='attempt-tampered'
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'
                   AND delivery_state='delivered'",
                [],
            )
            .expect("tamper outbox attempt lineage"),
        1
    );
    drop(attempt_connection);
    let attempt_control = open_control(&attempt_store.database_path(), attempt_clock);
    assert!(matches!(
        attempt_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (fingerprint_store, fingerprint_clock) =
        persist_delivered_dispatch("collaboration-delivered-bad-fingerprint");
    rewrite_delivered_envelope(&fingerprint_store.database_path(), |envelope| {
        envelope.dispatch_fingerprint = "b".repeat(64);
        envelope
            .meta
            .as_mut()
            .expect("dispatch metadata")
            .request_digest_sha256 = envelope.dispatch_fingerprint.clone();
    });
    let fingerprint_control = open_control(&fingerprint_store.database_path(), fingerprint_clock);
    assert!(matches!(
        fingerprint_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (canonical_store, canonical_clock) =
        persist_delivered_dispatch("collaboration-delivered-bad-canonical-fingerprint");
    rewrite_delivered_envelope(&canonical_store.database_path(), |envelope| {
        envelope.workspace_ref = "workspace-tampered".to_owned();
    });
    let canonical_control = open_control(&canonical_store.database_path(), canonical_clock);
    assert!(matches!(
        canonical_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (meta_store, meta_clock) =
        persist_delivered_dispatch("collaboration-delivered-bad-meta-request-digest");
    rewrite_delivered_envelope(&meta_store.database_path(), |envelope| {
        envelope
            .meta
            .as_mut()
            .expect("dispatch metadata")
            .request_digest_sha256 = "c".repeat(64);
    });
    let meta_control = open_control(&meta_store.database_path(), meta_clock);
    assert!(matches!(
        meta_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));
}

#[test]
fn live_delivered_observation_requires_current_fence_and_complete_structure() {
    let (fence_store, fence_clock) =
        persist_delivered_dispatch("collaboration-delivered-stale-live-fence");
    rewrite_delivered_envelope_and_attempt(&fence_store.database_path(), |_envelope, attempt| {
        attempt
            .lease
            .as_mut()
            .expect("live attempt lease")
            .fencing_token += 1;
    });
    let fence_control = open_control(&fence_store.database_path(), fence_clock);
    assert!(matches!(
        fence_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (profile_store, profile_clock) =
        persist_delivered_dispatch("collaboration-delivered-malformed-live-profile");
    rewrite_delivered_envelope_and_attempt(&profile_store.database_path(), |envelope, attempt| {
        let mut malformed = contract_ref("single-harness-capability", '3');
        malformed.contract_id.clear();
        envelope.capability_profile_ref = Some(malformed.clone());
        attempt.capability_profile_ref = Some(malformed);
        synchronize_dispatch_fingerprint(envelope, attempt);
    });
    let profile_control = open_control(&profile_store.database_path(), profile_clock);
    assert!(matches!(
        profile_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (zero_fence_store, zero_fence_clock) =
        persist_delivered_dispatch("collaboration-delivered-zero-live-fence");
    rewrite_delivered_envelope_and_attempt(
        &zero_fence_store.database_path(),
        |envelope, attempt| {
            envelope.fencing_token = 0;
            attempt
                .lease
                .as_mut()
                .expect("live attempt lease")
                .fencing_token = 0;
            synchronize_dispatch_fingerprint(envelope, attempt);
        },
    );
    let zero_fence_control = open_control(&zero_fence_store.database_path(), zero_fence_clock);
    assert!(matches!(
        zero_fence_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (identity_store, identity_clock) =
        persist_delivered_dispatch("collaboration-delivered-empty-live-dispatch-id");
    rewrite_delivered_envelope_and_attempt(&identity_store.database_path(), |envelope, attempt| {
        envelope.dispatch_id.clear();
        attempt.dispatch_id = Some(String::new());
        synchronize_dispatch_fingerprint(envelope, attempt);
    });
    let identity_control = open_control(&identity_store.database_path(), identity_clock);
    assert!(matches!(
        identity_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (run_membership_store, run_membership_clock) =
        persist_delivered_dispatch("collaboration-delivered-missing-live-step-membership");
    rewrite_delivered_hierarchy(&run_membership_store.database_path(), |run, _step| {
        run.step_ids.clear()
    });
    let run_membership_control =
        open_control(&run_membership_store.database_path(), run_membership_clock);
    assert!(matches!(
        run_membership_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (attempt_membership_store, attempt_membership_clock) =
        persist_delivered_dispatch("collaboration-delivered-missing-live-attempt-membership");
    rewrite_delivered_hierarchy(&attempt_membership_store.database_path(), |_run, step| {
        step.attempt_ids.clear()
    });
    let attempt_membership_control = open_control(
        &attempt_membership_store.database_path(),
        attempt_membership_clock,
    );
    assert!(matches!(
        attempt_membership_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));

    let (current_attempt_store, current_attempt_clock) =
        persist_delivered_dispatch("collaboration-delivered-wrong-live-current-attempt");
    rewrite_delivered_hierarchy(&current_attempt_store.database_path(), |_run, step| {
        step.current_attempt_id = Some("attempt-other".to_owned())
    });
    let current_attempt_control = open_control(
        &current_attempt_store.database_path(),
        current_attempt_clock,
    );
    assert!(matches!(
        current_attempt_control.delivered_dispatches_for_observation(&harness_adapter()),
        Err(CollaborationControlError::Persistence)
    ));
}

#[test]
fn outcome_unknown_hold_cas_failure_rolls_back_the_authority_commit() {
    let isolated = IsolatedStore::new("collaboration-hold-cas-rollback");
    let clock = FixedClock::new(FIXED_TIME);
    let mut control = open_control(&isolated.database_path(), clock.clone());
    advance_through_dispatch(&mut control);
    drop(control);

    let connection = open_raw_collaboration_store(&isolated.database_path());
    assert_eq!(
        connection
            .execute(
                "UPDATE collaboration_outbox
                 SET delivery_state='consumed'
                 WHERE destination_domain='harness-adapter'
                   AND payload_kind='dispatch-envelope'",
                [],
            )
            .expect("inject impossible dispatch outbox state"),
        1
    );
    drop(connection);

    let mut control = open_control(&isolated.database_path(), clock);
    let before_store = control.inspect_store().expect("inspect before failed CAS");
    let before_snapshot = load_snapshot(&control);
    assert!(matches!(
        control.execute(&unknown_command(&before_snapshot), &recovery_worker()),
        Err(CollaborationControlError::Persistence)
    ));
    assert_eq!(
        control.inspect_store().expect("inspect after failed CAS"),
        before_store
    );
    assert_eq!(load_snapshot(&control), before_snapshot);
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

#[test]
fn projection_migration_crash_probe_child() {
    if std::env::var(MIGRATION_CRASH_PROBE).as_deref() != Ok("1") {
        return;
    }
    let path =
        PathBuf::from(std::env::var_os(MIGRATION_CRASH_DB).expect("migration crash database path"));
    let control = open_control(&path, FixedClock::new(FIXED_TIME));
    let retained = control
        .retained_projection_messages_for_rebuild()
        .expect("bootstrap committed before abort");
    assert_eq!(retained.len(), 1);
    assert!(retained[0].rebuild_baseline);
    std::process::abort();
}
