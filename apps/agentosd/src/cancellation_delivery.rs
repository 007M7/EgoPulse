//! Durable Task-cancellation handoff delivery.
//!
//! A delivered native interrupt is deliberately not a Task outcome. This
//! worker only advances the Task Authority outbox after the same live
//! Collaboration/Adapter runner has committed cancellation intent and the
//! Adapter has persisted a delivered interrupt receipt. The dispatch worker
//! later observes `ExecutionInterrupted` and drives the existing structured
//! cancellation settlement.

use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::task_authority::{
    NoRunTaskCancellationProof, TaskCancellationReconciliation, UnclaimedTaskActivation,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    CancelExecutionReceipt, CancellationDeliveryDisposition, cancel_execution_result,
};
use egopulse_local_ide_control::collaboration_control::{
    CollaborationLineageReader, HarnessCancellationDeliveryError,
    HarnessCancellationDeliveryTarget, TaskCancellationHandoff, TaskCancellationSource,
    TaskCancellationSourceError,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeldTaskCancellation {
    pub task_id: String,
    pub cancellation_request_id: String,
    pub safe_reason_code: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CancellationDeliveryCycleReport {
    pub delivered_and_acknowledged: u64,
    pub task_settled_and_acknowledged: u64,
    pub held: Vec<HeldTaskCancellation>,
}

#[derive(Debug, Error)]
pub(crate) enum CancellationDeliveryCycleError {
    #[error("Task cancellation source is unavailable")]
    Source(#[from] TaskCancellationSourceError),
    #[error("Task cancellation delivery route is invalid")]
    RouteIntegrity,
}

pub(crate) struct CancellationDeliveryRoute {
    target: Arc<dyn HarnessCancellationDeliveryTarget>,
}

/// App-local extension of the frozen Collaboration cancellation source. It
/// lets the Task owner settle no-run cancellations and consume stale outbox
/// messages before native route discovery without widening the shared Adapter
/// contract.
pub(crate) trait TaskCancellationReconciler: Send + Sync + 'static {
    fn reconcile_task_cancellation(
        &self,
        handoff: &TaskCancellationHandoff,
    ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError>;

    fn settle_no_run_task_cancellation(
        &self,
        _proof: &NoRunTaskCancellationProof,
    ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError> {
        Err(TaskCancellationSourceError::Integrity)
    }
}

impl CancellationDeliveryRoute {
    pub(crate) fn new(target: Arc<dyn HarnessCancellationDeliveryTarget>) -> Self {
        Self { target }
    }

    async fn matches(
        &self,
        handoff: &TaskCancellationHandoff,
    ) -> Result<bool, HarnessCancellationDeliveryError> {
        self.target.owns_task_cancellation(handoff).await
    }
}

pub(crate) struct CancellationDeliveryWorker {
    source: Arc<dyn TaskCancellationSource>,
    reconciler: Option<Arc<dyn TaskCancellationReconciler>>,
    routes: Vec<CancellationDeliveryRoute>,
    lineage_readers: Vec<Arc<Mutex<CollaborationLineageReader>>>,
}

impl CancellationDeliveryWorker {
    pub(crate) fn new(
        source: Arc<dyn TaskCancellationSource>,
        routes: Vec<CancellationDeliveryRoute>,
    ) -> Result<Self, CancellationDeliveryCycleError> {
        if routes.is_empty() {
            return Err(CancellationDeliveryCycleError::RouteIntegrity);
        }
        Ok(Self {
            source,
            reconciler: None,
            routes,
            lineage_readers: Vec::new(),
        })
    }

    pub(crate) fn with_task_reconciliation(
        mut self,
        reconciler: Arc<dyn TaskCancellationReconciler>,
    ) -> Self {
        self.reconciler = Some(reconciler);
        self
    }

    pub(crate) fn with_lineage_readers(
        mut self,
        readers: Vec<Arc<Mutex<CollaborationLineageReader>>>,
    ) -> Self {
        self.lineage_readers = readers;
        self
    }

    fn no_run_proof(
        &self,
        handoff: &TaskCancellationHandoff,
        activation: UnclaimedTaskActivation,
    ) -> Result<NoRunTaskCancellationProof, &'static str> {
        if self.lineage_readers.is_empty() {
            return Err("CANCELLATION_COLLABORATION_READERS_UNAVAILABLE");
        }
        if activation.task_id != handoff.task.task_id
            || activation.work_revision != handoff.task.work_revision
            || handoff.task.current_run_id.as_deref() != Some(activation.reserved_run_id.as_str())
        {
            return Err("CANCELLATION_UNCLAIMED_ACTIVATION_MISMATCH");
        }
        for reader in &self.lineage_readers {
            let reader = reader
                .lock()
                .map_err(|_| "CANCELLATION_COLLABORATION_READER_UNAVAILABLE")?;
            if reader
                .run_exists(&activation.reserved_run_id)
                .map_err(|_| "CANCELLATION_COLLABORATION_READER_UNAVAILABLE")?
            {
                return Err("CANCELLATION_COLLABORATION_RUN_EXISTS");
            }
        }
        // Task Authority has already held this exact unclaimed activation.
        // All configured Collaboration owners now confirm the reserved run is
        // absent, so no concurrent activation can invalidate this observation.
        let evidence = format!(
            "collaboration-run-absent:{}:cancellation:{}",
            activation.reserved_run_id, handoff.cancellation_request_id
        );
        Ok(NoRunTaskCancellationProof {
            activation,
            cancellation_message_id: handoff.message_id.clone(),
            cancellation_payload_digest_sha256: handoff.payload_digest_sha256.clone(),
            collaboration_absence_evidence_id: evidence,
        })
    }

    pub(crate) async fn run_once(
        &self,
    ) -> Result<CancellationDeliveryCycleReport, CancellationDeliveryCycleError> {
        let mut report = CancellationDeliveryCycleReport::default();
        for handoff in self.source.pending_task_cancellations()? {
            if let Some(reconciler) = self.reconciler.as_ref() {
                match reconciler.reconcile_task_cancellation(&handoff) {
                    Err(TaskCancellationSourceError::Unavailable) => {
                        report
                            .held
                            .push(held(&handoff, "CANCELLATION_TASK_OWNER_UNAVAILABLE"));
                        continue;
                    }
                    Err(TaskCancellationSourceError::Integrity) => {
                        report
                            .held
                            .push(held(&handoff, "CANCELLATION_TASK_RECONCILIATION_INVALID"));
                        continue;
                    }
                    Ok(TaskCancellationReconciliation::NeedsNativeDelivery) => {}
                    Ok(TaskCancellationReconciliation::NeedsNoRunProof(activation)) => {
                        let proof = match self.no_run_proof(&handoff, activation) {
                            Ok(proof) => proof,
                            Err(reason) => {
                                report.held.push(held(&handoff, reason));
                                continue;
                            }
                        };
                        match reconciler.settle_no_run_task_cancellation(&proof) {
                            Ok(TaskCancellationReconciliation::SettledAndAcknowledged {
                                ..
                            }) => {
                                report.task_settled_and_acknowledged += 1;
                            }
                            _ => report
                                .held
                                .push(held(&handoff, "CANCELLATION_NO_RUN_SETTLEMENT_UNCONFIRMED")),
                        }
                        continue;
                    }
                    Ok(TaskCancellationReconciliation::SettledAndAcknowledged { .. }) => {
                        report.task_settled_and_acknowledged += 1;
                        continue;
                    }
                }
            }
            let mut matching = Vec::new();
            let mut route_error = false;
            for route in &self.routes {
                match route.matches(&handoff).await {
                    Ok(true) => matching.push(route),
                    Ok(false) => {}
                    Err(_) => route_error = true,
                }
            }
            // A route that could not establish ownership might be the same
            // live Adapter as a matching route. Do not turn partial discovery
            // into an unproven native interrupt.
            if route_error {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_ROUTE_UNAVAILABLE"));
                continue;
            }
            let [route] = matching.as_slice() else {
                report.held.push(held(
                    &handoff,
                    if matching.is_empty() {
                        "CANCELLATION_ROUTE_NOT_FOUND"
                    } else {
                        "CANCELLATION_ROUTE_AMBIGUOUS"
                    },
                ));
                continue;
            };

            let result = match route.target.deliver_task_cancellation(&handoff).await {
                Ok(result) => result,
                Err(_) => {
                    report
                        .held
                        .push(held(&handoff, "CANCELLATION_DELIVERY_ADAPTER_ERROR"));
                    continue;
                }
            };
            let Some(cancel_execution_result::Outcome::Receipt(receipt)) = result.outcome else {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_NOT_CONFIRMED"));
                continue;
            };
            if receipt.cancellation_request_id != handoff.cancellation_request_id
                || !cancellation_receipt_is_valid(&receipt)
            {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_RECEIPT_MISMATCH"));
                continue;
            }
            if CancellationDeliveryDisposition::try_from(receipt.disposition)
                != Ok(CancellationDeliveryDisposition::Delivered)
            {
                report.held.push(held(
                    &handoff,
                    if CancellationDeliveryDisposition::try_from(receipt.disposition)
                        == Ok(CancellationDeliveryDisposition::Unknown)
                    {
                        "CANCELLATION_DELIVERY_OUTCOME_UNKNOWN"
                    } else {
                        "CANCELLATION_DELIVERY_REJECTED_OR_UNSUPPORTED"
                    },
                ));
                continue;
            }
            if self.source.acknowledge_task_cancellation(
                &handoff.message_id,
                &handoff.payload_digest_sha256,
            )? {
                report.delivered_and_acknowledged += 1;
            } else {
                report
                    .held
                    .push(held(&handoff, "CANCELLATION_DELIVERY_ACK_REJECTED"));
            }
        }
        Ok(report)
    }
}

fn cancellation_receipt_is_valid(receipt: &CancelExecutionReceipt) -> bool {
    if receipt.receipt_id.trim().is_empty()
        || receipt.receipt_digest_sha256.len() != 64
        || !receipt
            .receipt_digest_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let recorded_digest = receipt.receipt_digest_sha256.clone();
    let mut canonical = receipt.clone();
    canonical.receipt_digest_sha256.clear();
    hex::encode(Sha256::digest(canonical.encode_to_vec())) == recorded_digest
}

fn held(handoff: &TaskCancellationHandoff, safe_reason_code: &'static str) -> HeldTaskCancellation {
    HeldTaskCancellation {
        task_id: handoff.task.task_id.clone(),
        cancellation_request_id: handoff.cancellation_request_id.clone(),
        safe_reason_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        collaboration::v1::{
            AcquireAttemptLeaseCommand, ActivateRunCommand, AttemptSnapshot, CollaborationCommand,
            CollaborationSnapshot, CreateAttemptCommand, CreateRunCommand,
            MarkAttemptOutcomeUnknownCommand, RecordAttemptCancellationOutcomeCommand,
            RecordAttemptReconciliationCommand, RecordDeliveryReceiptCommand,
            RecordDispatchIntentCommand, RecordHarnessAckCommand, RecordRunningObservationCommand,
            RunPlan, RunSnapshot, StepPlan, StepSnapshot, collaboration_command,
        },
        common::v1::{CommandMetadata, ContractReference},
        harness::v1::CancelExecutionResult,
    };
    use egopulse_local_ide_control::collaboration_control::{
        AuthenticatedCollaborationPrincipal, CollaborationControl, CollaborationControlConfig,
        CollaborationLineageReaderConfig, CollaborationPrincipalKind, CollaborationReferenceGuard,
        CollaborationSqlCipherKey, DispatchMaterial, HarnessEvidenceResolver, LeaseAuthorization,
        ReferenceAuthorization, ReferenceGuardRejection, ResolvedHarnessEvidence,
        SystemAuthorityClock, seal_request_digest,
    };
    use std::{
        fs,
        future::Future,
        panic::AssertUnwindSafe,
        path::PathBuf,
        pin::Pin,
        sync::{Arc, Mutex},
    };
    use uuid::Uuid;

    #[derive(Default)]
    struct Source {
        pending: Mutex<Vec<TaskCancellationHandoff>>,
        acknowledgements: Mutex<u64>,
    }

    impl TaskCancellationSource for Source {
        fn pending_task_cancellations(
            &self,
        ) -> Result<Vec<TaskCancellationHandoff>, TaskCancellationSourceError> {
            Ok(self.pending.lock().expect("pending lock").clone())
        }

        fn acknowledge_task_cancellation(
            &self,
            _message_id: &str,
            _payload_digest_sha256: &str,
        ) -> Result<bool, TaskCancellationSourceError> {
            *self.acknowledgements.lock().expect("ack lock") += 1;
            Ok(true)
        }
    }

    struct Target {
        receipt: CancelExecutionReceipt,
        deliveries: Arc<Mutex<u64>>,
    }

    struct Reconciler(TaskCancellationReconciliation);

    impl TaskCancellationReconciler for Reconciler {
        fn reconcile_task_cancellation(
            &self,
            _handoff: &TaskCancellationHandoff,
        ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError> {
            Ok(self.0.clone())
        }
    }

    impl HarnessCancellationDeliveryTarget for Target {
        fn owns_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>
        {
            Box::pin(async { Ok(true) })
        }

        fn deliver_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                    + Send
                    + 'a,
            >,
        > {
            let receipt = self.receipt.clone();
            let deliveries = Arc::clone(&self.deliveries);
            Box::pin(async move {
                *deliveries.lock().expect("delivery lock") += 1;
                Ok(CancelExecutionResult {
                    outcome: Some(cancel_execution_result::Outcome::Receipt(receipt)),
                })
            })
        }
    }

    struct ErrorTarget;

    impl HarnessCancellationDeliveryTarget for ErrorTarget {
        fn owns_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<Box<dyn Future<Output = Result<bool, HarnessCancellationDeliveryError>> + Send + 'a>>
        {
            Box::pin(async { Err(HarnessCancellationDeliveryError::LiveBinding) })
        }

        fn deliver_task_cancellation<'a>(
            &'a self,
            _handoff: &'a TaskCancellationHandoff,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<CancelExecutionResult, HarnessCancellationDeliveryError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(HarnessCancellationDeliveryError::LiveBinding) })
        }
    }

    fn handoff() -> TaskCancellationHandoff {
        TaskCancellationHandoff {
            message_id: "outbox-1".to_owned(),
            payload_digest_sha256: "a".repeat(64),
            cancellation_request_id: "cancel-1".to_owned(),
            requested_at: prost_types::Timestamp {
                seconds: 1,
                nanos: 0,
            },
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                task_id: "task-1".to_owned(),
                ..Default::default()
            },
        }
    }

    fn receipt(disposition: CancellationDeliveryDisposition) -> CancelExecutionReceipt {
        let mut receipt = CancelExecutionReceipt {
            receipt_id: "receipt-1".to_owned(),
            cancellation_request_id: "cancel-1".to_owned(),
            disposition: disposition as i32,
            ..Default::default()
        };
        receipt.receipt_digest_sha256 = hex::encode(Sha256::digest(receipt.encode_to_vec()));
        receipt
    }

    fn target(receipt: CancelExecutionReceipt) -> (Target, Arc<Mutex<u64>>) {
        let deliveries = Arc::new(Mutex::new(0));
        (
            Target {
                receipt,
                deliveries: Arc::clone(&deliveries),
            },
            deliveries,
        )
    }

    #[derive(Clone, Copy)]
    struct LineageBootstrapGuard;

    impl CollaborationReferenceGuard for LineageBootstrapGuard {
        fn validate_create_run(
            &self,
            _command: &CreateRunCommand,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Ok(ReferenceAuthorization {
                evidence_refs: vec!["lineage-bootstrap:create-run".to_owned()],
            })
        }

        fn validate_activate_run(
            &self,
            _command: &ActivateRunCommand,
            _run: &RunSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_create_attempt(
            &self,
            _command: &CreateAttemptCommand,
            _run: &RunSnapshot,
            _step: &StepSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn authorize_lease(
            &self,
            _command: &AcquireAttemptLeaseCommand,
            _attempt: &AttemptSnapshot,
        ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn resolve_dispatch_material(
            &self,
            _command: &RecordDispatchIntentCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_unknown_outcome(
            &self,
            _command: &MarkAttemptOutcomeUnknownCommand,
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

    impl HarnessEvidenceResolver for LineageBootstrapGuard {
        fn resolve_delivery_receipt(
            &self,
            _command: &RecordDeliveryReceiptCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn resolve_harness_ack(
            &self,
            _command: &RecordHarnessAckCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_running_observation(
            &self,
            _command: &RecordRunningObservationCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_cancellation_outcome(
            &self,
            _command: &RecordAttemptCancellationOutcomeCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }

        fn validate_reconciliation(
            &self,
            _command: &RecordAttemptReconciliationCommand,
            _snapshot: &CollaborationSnapshot,
        ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
            Err(ReferenceGuardRejection::UnverifiedReference)
        }
    }

    struct CollaborationLineageFixture {
        root: PathBuf,
        database_path: PathBuf,
    }

    impl CollaborationLineageFixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "egopulse-cancellation-lineage-{label}-{}",
                Uuid::now_v7()
            ));
            fs::create_dir_all(&root).expect("create Collaboration lineage fixture directory");
            let database_path = root.join("collaboration.sqlcipher");
            let _owner = CollaborationControl::open(
                CollaborationControlConfig {
                    database_path: database_path.clone(),
                    store_epoch: "cancellation-lineage-test-v1".to_owned(),
                    key: CollaborationSqlCipherKey::new([0x51; 32]),
                },
                LineageBootstrapGuard,
                SystemAuthorityClock,
            )
            .expect("initialize owner-managed Collaboration store");
            Self {
                root,
                database_path,
            }
        }

        fn reader(&self) -> Arc<Mutex<CollaborationLineageReader>> {
            Arc::new(Mutex::new(
                CollaborationLineageReader::open(CollaborationLineageReaderConfig {
                    database_path: self.database_path.clone(),
                    store_epoch: "cancellation-lineage-test-v1".to_owned(),
                    key: CollaborationSqlCipherKey::new([0x51; 32]),
                })
                .expect("open query-only Collaboration lineage reader"),
            ))
        }

        fn create_run(&self, run_id: &str) {
            let mut owner = CollaborationControl::open(
                CollaborationControlConfig {
                    database_path: self.database_path.clone(),
                    store_epoch: "cancellation-lineage-test-v1".to_owned(),
                    key: CollaborationSqlCipherKey::new([0x51; 32]),
                },
                LineageBootstrapGuard,
                SystemAuthorityClock,
            )
            .expect("reopen owner-managed Collaboration store");
            let mut command = CollaborationCommand {
                command: Some(collaboration_command::Command::CreateRun(
                    CreateRunCommand {
                        meta: Some(CommandMetadata {
                            command_id: format!("lineage-create:{run_id}"),
                            idempotency_key: format!("lineage-create:{run_id}"),
                            idempotency_scope: "task-1/work-1".to_owned(),
                            request_digest_sha256: String::new(),
                            issued_at: Some(prost_types::Timestamp {
                                seconds: 1,
                                nanos: 0,
                            }),
                            correlation_id: "lineage-fixture".to_owned(),
                            causation_id: None,
                        }),
                        run_id: run_id.to_owned(),
                        task_id: "task-1".to_owned(),
                        task_revision: 1,
                        work_revision: 1,
                        plan: Some(RunPlan {
                            plan_id: "lineage-plan".to_owned(),
                            digest_sha256: "1".repeat(64),
                            max_active_attempts: 1,
                            steps: vec![StepPlan {
                                step_id: "lineage-step".to_owned(),
                                step_kind: "governed_harness_work".to_owned(),
                                depends_on_step_ids: Vec::new(),
                                input_bundle_ref: "lineage-input".to_owned(),
                                expected_output_contract_ref: Some(ContractReference {
                                    contract_id: "lineage-output".to_owned(),
                                    version: "v1".to_owned(),
                                    sha256: "2".repeat(64),
                                }),
                                required_capability_profile_ref: Some(ContractReference {
                                    contract_id: "lineage-capability".to_owned(),
                                    version: "v1".to_owned(),
                                    sha256: "3".repeat(64),
                                }),
                                max_attempts: 2,
                            }],
                            budget_profile_ref: Some(ContractReference {
                                contract_id: "lineage-budget".to_owned(),
                                version: "v1".to_owned(),
                                sha256: "4".repeat(64),
                            }),
                        }),
                    },
                )),
            };
            seal_request_digest(&mut command).expect("seal owner CreateRun request");
            let result = owner
                .execute(
                    &command,
                    &AuthenticatedCollaborationPrincipal {
                        kind: CollaborationPrincipalKind::TaskAuthority,
                        principal_id: "task-authority:lineage-fixture".to_owned(),
                        authenticated: true,
                    },
                )
                .expect("create Collaboration Run through owner");
            assert!(
                result.committed_event.is_some(),
                "owner must commit test Run"
            );
        }
    }

    impl Drop for CollaborationLineageFixture {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove Collaboration lineage fixture");
            }
        }
    }

    struct NoRunReconciler {
        activation: UnclaimedTaskActivation,
        settled: Arc<Mutex<Vec<NoRunTaskCancellationProof>>>,
    }

    impl TaskCancellationReconciler for NoRunReconciler {
        fn reconcile_task_cancellation(
            &self,
            _handoff: &TaskCancellationHandoff,
        ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError> {
            Ok(TaskCancellationReconciliation::NeedsNoRunProof(
                self.activation.clone(),
            ))
        }

        fn settle_no_run_task_cancellation(
            &self,
            proof: &NoRunTaskCancellationProof,
        ) -> Result<TaskCancellationReconciliation, TaskCancellationSourceError> {
            self.settled
                .lock()
                .expect("settled lock")
                .push(proof.clone());
            Ok(TaskCancellationReconciliation::SettledAndAcknowledged {
                status: egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::Cancelled,
                committed: true,
                replayed: false,
            })
        }
    }

    fn no_run_handoff() -> TaskCancellationHandoff {
        let mut handoff = handoff();
        handoff.task.current_run_id = Some("reserved-run".to_owned());
        handoff.task.work_revision = 1;
        handoff
    }

    fn unclaimed_activation(handoff: &TaskCancellationHandoff) -> UnclaimedTaskActivation {
        UnclaimedTaskActivation {
            message_id: "activation-message".to_owned(),
            payload_digest_sha256: "b".repeat(64),
            task_id: handoff.task.task_id.clone(),
            task_revision: 1,
            work_revision: handoff.task.work_revision,
            reserved_run_id: handoff
                .task
                .current_run_id
                .clone()
                .expect("reserved run fixture"),
        }
    }

    #[tokio::test]
    async fn delivered_interrupt_acknowledges_handoff_without_claiming_task_cancellation() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");
        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 1);
        assert!(report.held.is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 1);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn task_owned_settlement_skips_native_route_and_direct_ack() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(Reconciler(
            TaskCancellationReconciliation::SettledAndAcknowledged {
                status: egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::Cancelled,
                committed: true,
                replayed: false,
            },
        )));

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 1);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert!(report.held.is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
    }

    #[tokio::test]
    async fn queued_cancellation_without_owner_readers_cannot_claim_no_native_effect() {
        let mut handoff = handoff();
        handoff.task.current_run_id = Some("reserved-run".to_owned());
        handoff.task.work_revision = 1;
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff.clone()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(Reconciler(
            TaskCancellationReconciliation::NeedsNoRunProof(UnclaimedTaskActivation {
                message_id: "activation-message".to_owned(),
                payload_digest_sha256: "b".repeat(64),
                task_id: handoff.task.task_id.clone(),
                task_revision: 2,
                work_revision: 1,
                reserved_run_id: "reserved-run".to_owned(),
            }),
        )));
        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 0);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(report.held.len(), 1);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_COLLABORATION_READERS_UNAVAILABLE"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
    }

    #[tokio::test]
    async fn no_run_proof_from_all_query_only_collaboration_readers_settles_without_native_delivery()
     {
        let handoff = no_run_handoff();
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff.clone()]),
            acknowledgements: Mutex::new(0),
        });
        let first_owner = CollaborationLineageFixture::new("no-run-first");
        let second_owner = CollaborationLineageFixture::new("no-run-second");
        let first_reader = first_owner.reader();
        let second_reader = second_owner.reader();
        assert!(
            !first_reader
                .lock()
                .expect("first query-only reader lock")
                .run_exists("reserved-run")
                .expect("query first owner"),
            "the first owner must not fabricate a Collaboration Run"
        );
        assert!(
            !second_reader
                .lock()
                .expect("second query-only reader lock")
                .run_exists("reserved-run")
                .expect("query second owner"),
            "the second owner must not fabricate a Collaboration Run"
        );
        let settled = Arc::new(Mutex::new(Vec::new()));
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(NoRunReconciler {
            activation: unclaimed_activation(&handoff),
            settled: Arc::clone(&settled),
        }))
        .with_lineage_readers(vec![first_reader, second_reader]);

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 1);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert!(report.held.is_empty());
        let proofs = settled.lock().expect("settled proof lock");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].activation.reserved_run_id, "reserved-run");
        assert_eq!(
            proofs[0].collaboration_absence_evidence_id,
            "collaboration-run-absent:reserved-run:cancellation:cancel-1"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
        drop(proofs);
        drop(worker);
        drop(first_owner);
        drop(second_owner);
    }

    #[tokio::test]
    async fn no_run_proof_refuses_settlement_when_any_query_only_owner_has_the_reserved_run() {
        let handoff = no_run_handoff();
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff.clone()]),
            acknowledgements: Mutex::new(0),
        });
        let absent_owner = CollaborationLineageFixture::new("run-absent");
        let existing_owner = CollaborationLineageFixture::new("run-exists");
        existing_owner.create_run("reserved-run");
        let absent_reader = absent_owner.reader();
        let existing_reader = existing_owner.reader();
        assert!(
            existing_reader
                .lock()
                .expect("existing query-only reader lock")
                .run_exists("reserved-run")
                .expect("query owner-created Run"),
            "the fixture must prove a real owner-created Collaboration Run"
        );
        let settled = Arc::new(Mutex::new(Vec::new()));
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(NoRunReconciler {
            activation: unclaimed_activation(&handoff),
            settled: Arc::clone(&settled),
        }))
        .with_lineage_readers(vec![absent_reader, existing_reader]);

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 0);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held,
            vec![held(&handoff, "CANCELLATION_COLLABORATION_RUN_EXISTS")]
        );
        assert!(settled.lock().expect("settled proof lock").is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
        drop(worker);
        drop(absent_owner);
        drop(existing_owner);
    }

    #[tokio::test]
    async fn no_run_proof_refuses_settlement_when_any_query_only_owner_cannot_be_read() {
        let handoff = no_run_handoff();
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff.clone()]),
            acknowledgements: Mutex::new(0),
        });
        let readable_owner = CollaborationLineageFixture::new("reader-available");
        let unavailable_owner = CollaborationLineageFixture::new("reader-unavailable");
        let readable_reader = readable_owner.reader();
        let unavailable_reader = unavailable_owner.reader();
        let poison_target = Arc::clone(&unavailable_reader);
        let poisoned = std::panic::catch_unwind(AssertUnwindSafe(move || {
            let _guard = poison_target.lock().expect("reader lock before poison");
            panic!("poison query-only Collaboration lineage reader");
        }));
        assert!(poisoned.is_err(), "fixture must poison the reader mutex");
        let settled = Arc::new(Mutex::new(Vec::new()));
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker")
        .with_task_reconciliation(Arc::new(NoRunReconciler {
            activation: unclaimed_activation(&handoff),
            settled: Arc::clone(&settled),
        }))
        .with_lineage_readers(vec![readable_reader, unavailable_reader]);

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.task_settled_and_acknowledged, 0);
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held,
            vec![held(
                &handoff,
                "CANCELLATION_COLLABORATION_READER_UNAVAILABLE"
            )]
        );
        assert!(settled.lock().expect("settled proof lock").is_empty());
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
        drop(worker);
        drop(readable_owner);
        drop(unavailable_owner);
    }

    #[tokio::test]
    async fn unknown_delivery_remains_unacknowledged_for_durable_recovery() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Unknown));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");
        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_DELIVERY_OUTCOME_UNKNOWN"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn altered_delivery_receipt_never_acknowledges_the_task_handoff() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let mut altered = receipt(CancellationDeliveryDisposition::Delivered);
        altered.receipt_digest_sha256 = "0".repeat(64);
        let (target, deliveries) = target(altered);
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![CancellationDeliveryRoute::new(Arc::new(target))],
        )
        .expect("worker");

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_DELIVERY_RECEIPT_MISMATCH"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 1);
    }

    #[tokio::test]
    async fn route_lookup_error_blocks_a_matching_route_without_native_delivery() {
        let source = Arc::new(Source {
            pending: Mutex::new(vec![handoff()]),
            acknowledgements: Mutex::new(0),
        });
        let (target, deliveries) = target(receipt(CancellationDeliveryDisposition::Delivered));
        let worker = CancellationDeliveryWorker::new(
            Arc::clone(&source) as Arc<dyn TaskCancellationSource>,
            vec![
                CancellationDeliveryRoute::new(Arc::new(ErrorTarget)),
                CancellationDeliveryRoute::new(Arc::new(target)),
            ],
        )
        .expect("worker");

        let report = worker.run_once().await.expect("cycle");
        assert_eq!(report.delivered_and_acknowledged, 0);
        assert_eq!(
            report.held[0].safe_reason_code,
            "CANCELLATION_ROUTE_UNAVAILABLE"
        );
        assert_eq!(*source.acknowledgements.lock().expect("ack lock"), 0);
        assert_eq!(*deliveries.lock().expect("delivery lock"), 0);
    }
}
