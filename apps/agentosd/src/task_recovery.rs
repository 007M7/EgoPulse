use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, PrincipalKind as TaskPrincipalKind, TaskAuthority,
    TaskAuthorityFailure, canonical_request_digest as task_canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::CommandMetadata;
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    GetTaskResponse, InterruptTaskCommand, RecordTaskCancellationOutcomeCommand, TaskCommand,
    TaskStatus, get_task_response, task_command, task_command_result,
};
use egopulse_local_ide_control::collaboration_control::{
    HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
    TaskRecoveryFinding, TaskRecoveryKind,
};
use thiserror::Error;

const TASK_RECOVERY_SETTLEMENT_SCOPE: &str = "collaboration-task-recovery-settlement-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecoverySettlement {
    pub kind: TaskRecoveryKind,
    pub task_id: String,
    pub task_revision: u64,
    pub committed: bool,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum TaskRecoverySettlementError {
    #[error("Task Authority is unavailable")]
    TaskAuthority(#[from] TaskAuthorityFailure),
    #[error("Task Authority lock is poisoned")]
    TaskAuthorityLock,
}

/// The daemon-owned settlement wrapper over the Harness dispatch cycle.
///
/// It consumes the cycle's derived recovery findings and converts only those
/// that still match the live Task snapshot into the two existing governed Task
/// commands: a committed collaboration `Cancelled` run records the Task
/// cancellation outcome, and a quarantined unknown harness outcome interrupts
/// the Task. Every settlement proves, in order: the Task exists, the finding's
/// run is still the Task's current run, the Task status is exactly the
/// precondition state, and the command revision is the live revision. Any
/// mismatch skips fail-closed; harness observations never assert completion.
pub struct GovernedTaskRecoveryRunner {
    inner: Arc<dyn HarnessDispatchRunner>,
    task: Arc<Mutex<TaskAuthority>>,
    principal: AuthenticatedPrincipal,
}

impl GovernedTaskRecoveryRunner {
    pub fn new(
        inner: Arc<dyn HarnessDispatchRunner>,
        task: Arc<Mutex<TaskAuthority>>,
        principal_id: &str,
    ) -> Result<Self, &'static str> {
        if principal_id.trim().is_empty() {
            return Err("task recovery settlement principal id is empty");
        }
        Ok(Self {
            inner,
            task,
            principal: AuthenticatedPrincipal {
                kind: TaskPrincipalKind::CollaborationControl,
                principal_id: principal_id.to_owned(),
                authenticated: true,
            },
        })
    }

    fn settle(
        &self,
        finding: &TaskRecoveryFinding,
        settlements: &mut Vec<TaskRecoverySettlement>,
    ) -> Result<(), TaskRecoverySettlementError> {
        let snapshot = {
            let task = self
                .task
                .lock()
                .map_err(|_| TaskRecoverySettlementError::TaskAuthorityLock)?;
            match task.get_task(&finding.task_id)? {
                GetTaskResponse {
                    outcome: Some(get_task_response::Outcome::Task(snapshot)),
                } => snapshot,
                _ => return Ok(()),
            }
        };
        // The finding must still belong to the Task's current run. A task that
        // moved on (revised, superseded, new activation) is never written.
        if snapshot.current_run_id.as_deref() != Some(finding.run_id.as_str()) {
            return Ok(());
        }
        let now = current_timestamp();
        let (command, expected_revision) = match finding.kind {
            TaskRecoveryKind::CancellationConfirmed => {
                if snapshot.status != TaskStatus::CancellationPending as i32 {
                    return Ok(());
                }
                (
                    task_command::Command::RecordTaskCancellationOutcome(
                        RecordTaskCancellationOutcomeCommand {
                            meta: recovery_metadata(finding, now),
                            task_id: finding.task_id.clone(),
                            expected_revision: snapshot.revision,
                            outcome: TaskStatus::Cancelled as i32,
                            cancellation_receipt_id: finding.evidence_ref.clone(),
                        },
                    ),
                    snapshot.revision,
                )
            }
            TaskRecoveryKind::OutcomeUnknown => {
                if snapshot.status != TaskStatus::Active as i32 {
                    return Ok(());
                }
                (
                    task_command::Command::InterruptTask(InterruptTaskCommand {
                        meta: recovery_metadata(finding, now),
                        task_id: finding.task_id.clone(),
                        expected_revision: snapshot.revision,
                        interruption_evidence_id: finding.evidence_ref.clone(),
                    }),
                    snapshot.revision,
                )
            }
        };
        let mut command = TaskCommand {
            command: Some(command),
        };
        let digest = task_canonical_request_digest(&command)?;
        set_command_digest(&mut command, digest);
        let result = {
            let mut task = self
                .task
                .lock()
                .map_err(|_| TaskRecoverySettlementError::TaskAuthorityLock)?;
            task.execute(&command, &self.principal)?
        };
        if let Some(task_command_result::Outcome::Error(_)) = result.outcome.as_ref() {
            // A safe domain rejection (stale revision, status moved on, guard
            // rejection) leaves the task untouched; the durable collaboration
            // fact remains and a later reconciliation path can pick it up.
            return Ok(());
        }
        settlements.push(TaskRecoverySettlement {
            kind: finding.kind,
            task_id: finding.task_id.clone(),
            task_revision: expected_revision + 1,
            committed: result.committed_event.is_some(),
            replayed: result.replayed,
        });
        Ok(())
    }
}

fn current_timestamp() -> prost_types::Timestamp {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch");
    prost_types::Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    }
}

fn recovery_metadata(
    finding: &TaskRecoveryFinding,
    issued_at: prost_types::Timestamp,
) -> Option<CommandMetadata> {
    let idempotency_key = format!(
        "{}:{}:{}:{}",
        match finding.kind {
            TaskRecoveryKind::CancellationConfirmed => "cancellation-outcome",
            TaskRecoveryKind::OutcomeUnknown => "interrupt",
        },
        finding.task_id,
        finding.run_id,
        finding.evidence_ref,
    );
    Some(CommandMetadata {
        command_id: format!("task-recovery-{idempotency_key}"),
        idempotency_key,
        idempotency_scope: TASK_RECOVERY_SETTLEMENT_SCOPE.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(issued_at),
        correlation_id: finding.evidence_ref.clone(),
        causation_id: Some(finding.run_id.clone()),
    })
}

fn set_command_digest(command: &mut TaskCommand, digest: String) {
    match command.command.as_mut().expect("task recovery command") {
        task_command::Command::RecordTaskCancellationOutcome(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::InterruptTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        _ => unreachable!("settlement builds exactly these two commands"),
    }
}

impl HarnessDispatchRunner for GovernedTaskRecoveryRunner {
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
            if !report.task_recovery_findings.is_empty() {
                let mut settlements = Vec::new();
                for finding in &report.task_recovery_findings {
                    self.settle(finding, &mut settlements).map_err(|error| {
                        HarnessDispatchCycleError::ReturnCollector(format!(
                            "task recovery settlement failed: {error}"
                        ))
                    })?;
                }
            }
            Ok(report)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_cognition_runtime::task_authority::{
        CreationAuthorization, CreationGuardRejection, SqlCipherKey, TaskAuthorityConfig,
        TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization, TransitionGuardRejection,
    };
    use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
    use egopulse_domain_contracts::v01::egopulse::task::v1::{
        ActivateTaskCommand, CreateTaskCommand, RequestTaskCancellationCommand, TaskSnapshot,
    };
    use prost_types::Timestamp;
    use std::fs;
    use std::path::PathBuf;
    use uuid::Uuid;

    struct FixtureCreationGuard;

    impl TaskCreationGuard for FixtureCreationGuard {
        fn validate(
            &self,
            _command: &CreateTaskCommand,
        ) -> Result<CreationAuthorization, CreationGuardRejection> {
            Ok(CreationAuthorization {
                evidence_refs: vec!["input-snapshot:fixture@verified".to_owned()],
            })
        }
    }

    struct FixtureTransitionGuard;

    impl TaskTransitionGuard for FixtureTransitionGuard {
        fn validate(
            &self,
            _command: &TaskCommand,
            _current: &TaskSnapshot,
        ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
            Ok(TransitionAuthorization {
                evidence_refs: vec!["transition-proof:fixture".to_owned()],
                founder_decision: None,
                founder_verdict_state_revision: None,
            })
        }
    }

    struct IsolatedStore {
        root: PathBuf,
    }

    impl IsolatedStore {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).expect("create isolated Task Authority test directory");
            Self { root }
        }
    }

    impl Drop for IsolatedStore {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove test directory");
            }
        }
    }

    struct FixedRunner {
        findings: Vec<TaskRecoveryFinding>,
    }

    impl HarnessDispatchRunner for FixedRunner {
        fn run_once(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                    + Send
                    + '_,
            >,
        > {
            let findings = self.findings.clone();
            Box::pin(async move {
                Ok(HarnessDispatchCycleReport {
                    task_recovery_findings: findings,
                    ..HarnessDispatchCycleReport::default()
                })
            })
        }
    }

    fn founder_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            kind: TaskPrincipalKind::Founder,
            principal_id: "founder:test".to_owned(),
            authenticated: true,
        }
    }

    fn collaboration_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            kind: TaskPrincipalKind::CollaborationControl,
            principal_id: "collaboration-control:test".to_owned(),
            authenticated: true,
        }
    }

    fn metadata(command_id: &str, idempotency_key: &str) -> CommandMetadata {
        CommandMetadata {
            command_id: command_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            idempotency_scope: "task-recovery-test/v01".to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(Timestamp {
                seconds: 1_777_073_600,
                nanos: 0,
            }),
            correlation_id: command_id.to_owned(),
            causation_id: None,
        }
    }

    fn seal(command: &mut TaskCommand) {
        let digest = task_canonical_request_digest(command).expect("canonical task request digest");
        match command.command.as_mut().expect("task command") {
            task_command::Command::CreateTask(value) => {
                value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
            }
            task_command::Command::ActivateTask(value) => {
                value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
            }
            task_command::Command::RequestTaskCancellation(value) => {
                value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
            }
            _ => panic!("unsupported fixture command"),
        }
    }

    fn open_task_authority(root: &std::path::Path) -> Arc<Mutex<TaskAuthority>> {
        Arc::new(Mutex::new(
            TaskAuthority::open_with_transition_guard(
                TaskAuthorityConfig {
                    database_path: root.join("recovery-fixture.sqlcipher"),
                    store_epoch: "task-recovery-settlement-test".to_owned(),
                    key: SqlCipherKey::new([0x44; 32]),
                },
                FixtureCreationGuard,
                FixtureTransitionGuard,
            )
            .expect("open Task Authority"),
        ))
    }

    fn create_and_activate(task: &Arc<Mutex<TaskAuthority>>) -> TaskSnapshot {
        let mut create = TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(metadata("cmd-create", "create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-001".to_owned(),
                target_scope_ref: "repo-scope-001".to_owned(),
                acceptance_contract_ref: Some(ContractReference {
                    contract_id: "repository_change_acceptance".to_owned(),
                    version: "1".to_owned(),
                    sha256: "a".repeat(64),
                }),
                budget_profile_ref: Some(ContractReference {
                    contract_id: "v01-quality-budget".to_owned(),
                    version: "0.1".to_owned(),
                    sha256: "b".repeat(64),
                }),
            })),
        };
        seal(&mut create);
        let created = task
            .lock()
            .expect("task lock")
            .execute(&create, &founder_principal())
            .expect("create Task");
        let snapshot = match created.outcome.expect("outcome") {
            task_command_result::Outcome::Task(snapshot) => snapshot,
            task_command_result::Outcome::Error(error) => {
                panic!("expected created Task, got {}", error.safe_detail_code)
            }
        };
        let mut activate = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(metadata("cmd-activate", "activate")),
                task_id: snapshot.task_id.clone(),
                expected_revision: snapshot.revision,
                work_revision: snapshot.work_revision,
                run_id: "run-001".to_owned(),
            })),
        };
        seal(&mut activate);
        let activated = task
            .lock()
            .expect("task lock")
            .execute(&activate, &collaboration_principal())
            .expect("activate Task");
        match activated.outcome.expect("outcome") {
            task_command_result::Outcome::Task(snapshot) => snapshot,
            task_command_result::Outcome::Error(error) => {
                panic!("expected active Task, got {}", error.safe_detail_code)
            }
        }
    }

    fn current_snapshot(task: &Arc<Mutex<TaskAuthority>>, task_id: &str) -> TaskSnapshot {
        match task
            .lock()
            .expect("task lock")
            .get_task(task_id)
            .expect("read Task")
            .outcome
            .expect("outcome")
        {
            get_task_response::Outcome::Task(snapshot) => snapshot,
            get_task_response::Outcome::Error(error) => {
                panic!("expected Task snapshot, got {}", error.safe_detail_code)
            }
        }
    }

    #[tokio::test]
    async fn cancellation_finding_records_task_outcome_idempotently() {
        let isolated = IsolatedStore::new("recovery-cancellation");
        let task = open_task_authority(&isolated.root);
        let active = create_and_activate(&task);
        let mut request = TaskCommand {
            command: Some(task_command::Command::RequestTaskCancellation(
                RequestTaskCancellationCommand {
                    meta: Some(metadata("cmd-cancel", "cancel")),
                    task_id: active.task_id.clone(),
                    expected_revision: active.revision,
                    reason_code: "founder_abandoned".to_owned(),
                },
            )),
        };
        seal(&mut request);
        task.lock()
            .expect("task lock")
            .execute(&request, &founder_principal())
            .expect("request cancellation");

        let runner = GovernedTaskRecoveryRunner::new(
            Arc::new(FixedRunner {
                findings: vec![TaskRecoveryFinding {
                    kind: TaskRecoveryKind::CancellationConfirmed,
                    task_id: active.task_id.clone(),
                    run_id: "run-001".to_owned(),
                    evidence_ref: "cancellation-receipt:observation-001".to_owned(),
                }],
            }),
            Arc::clone(&task),
            "collaboration-control:task-recovery",
        )
        .expect("build recovery runner");

        runner.run_once().await.expect("cycle with settlement");
        let snapshot = current_snapshot(&task, &active.task_id);
        assert_eq!(snapshot.status, TaskStatus::Cancelled as i32);
        assert_eq!(
            snapshot.current_run_id.as_deref(),
            Some("run-001"),
            "settlement must not rewrite run identity"
        );

        // The same finding replayed after the fact is an idempotent no-op.
        runner.run_once().await.expect("replay cycle");
        let replayed = current_snapshot(&task, &active.task_id);
        assert_eq!(replayed.status, TaskStatus::Cancelled as i32);
        assert_eq!(replayed.revision, snapshot.revision);
    }

    #[tokio::test]
    async fn unknown_outcome_finding_interrupts_active_task_only() {
        let isolated = IsolatedStore::new("recovery-interrupt");
        let task = open_task_authority(&isolated.root);
        let active = create_and_activate(&task);

        let runner = GovernedTaskRecoveryRunner::new(
            Arc::new(FixedRunner {
                findings: vec![TaskRecoveryFinding {
                    kind: TaskRecoveryKind::OutcomeUnknown,
                    task_id: active.task_id.clone(),
                    run_id: "run-001".to_owned(),
                    evidence_ref: "uncertainty-evidence:observation-002".to_owned(),
                }],
            }),
            Arc::clone(&task),
            "collaboration-control:task-recovery",
        )
        .expect("build recovery runner");

        runner.run_once().await.expect("cycle with interruption");
        let snapshot = current_snapshot(&task, &active.task_id);
        assert_eq!(snapshot.status, TaskStatus::Interrupted as i32);
        assert_ne!(
            snapshot.status,
            TaskStatus::Completed as i32,
            "a harness observation must never complete a Task"
        );
    }

    #[tokio::test]
    async fn findings_for_stale_run_or_wrong_status_are_skipped_fail_closed() {
        let isolated = IsolatedStore::new("recovery-skip");
        let task = open_task_authority(&isolated.root);
        let active = create_and_activate(&task);

        let stale_run = GovernedTaskRecoveryRunner::new(
            Arc::new(FixedRunner {
                findings: vec![TaskRecoveryFinding {
                    kind: TaskRecoveryKind::CancellationConfirmed,
                    task_id: active.task_id.clone(),
                    run_id: "run-superseded".to_owned(),
                    evidence_ref: "cancellation-receipt:observation-003".to_owned(),
                }],
            }),
            Arc::clone(&task),
            "collaboration-control:task-recovery",
        )
        .expect("build recovery runner");
        stale_run.run_once().await.expect("stale-run cycle");
        let snapshot = current_snapshot(&task, &active.task_id);
        assert_eq!(
            snapshot.status,
            TaskStatus::Active as i32,
            "a finding for a non-current run must not write the Task"
        );

        // An Active task never receives a cancellation outcome: the
        // Founder-requested CancellationPending precondition is absent.
        let wrong_status = GovernedTaskRecoveryRunner::new(
            Arc::new(FixedRunner {
                findings: vec![TaskRecoveryFinding {
                    kind: TaskRecoveryKind::CancellationConfirmed,
                    task_id: active.task_id.clone(),
                    run_id: "run-001".to_owned(),
                    evidence_ref: "cancellation-receipt:observation-004".to_owned(),
                }],
            }),
            Arc::clone(&task),
            "collaboration-control:task-recovery",
        )
        .expect("build recovery runner");
        wrong_status.run_once().await.expect("wrong-status cycle");
        let snapshot = current_snapshot(&task, &active.task_id);
        assert_eq!(snapshot.status, TaskStatus::Active as i32);
    }

    #[test]
    fn settlement_metadata_is_digest_bound_and_idempotent() {
        let finding = TaskRecoveryFinding {
            kind: TaskRecoveryKind::OutcomeUnknown,
            task_id: "task-1".to_owned(),
            run_id: "run-1".to_owned(),
            evidence_ref: "uncertainty-evidence:obs-1".to_owned(),
        };
        let meta = recovery_metadata(&finding, current_timestamp()).expect("metadata");
        assert_eq!(meta.idempotency_scope, TASK_RECOVERY_SETTLEMENT_SCOPE);
        assert_eq!(
            meta.idempotency_key,
            "interrupt:task-1:run-1:uncertainty-evidence:obs-1"
        );
        assert_eq!(meta.correlation_id, finding.evidence_ref);
        assert_eq!(meta.causation_id.as_deref(), Some("run-1"));
        assert!(meta.issued_at.is_some());
    }

    #[tokio::test]
    async fn production_builder_installs_the_settlement_wrapper_over_the_runner() {
        use crate::DaemonProviders;

        let isolated = IsolatedStore::new("recovery-composition");
        let task = open_task_authority(&isolated.root);
        let active = create_and_activate(&task);

        let providers = DaemonProviders::fail_closed()
            .with_harness_dispatch_runner(Arc::new(FixedRunner {
                findings: vec![TaskRecoveryFinding {
                    kind: TaskRecoveryKind::OutcomeUnknown,
                    task_id: active.task_id.clone(),
                    run_id: "run-001".to_owned(),
                    evidence_ref: "uncertainty-evidence:observation-005".to_owned(),
                }],
            }))
            .with_task_recovery_settlement(Arc::clone(&task))
            .expect("install settlement wrapper");

        // The installed dispatch cycle is the settlement wrapper: running it
        // through the daemon's own runner handle settles the finding into the
        // Task Authority, which the bare FixedRunner could never do.
        let runner = providers
            .harness_dispatch_runner
            .as_ref()
            .expect("dispatch runner installed");
        runner.run_once().await.expect("wrapped cycle");
        let snapshot = current_snapshot(&task, &active.task_id);
        assert_eq!(snapshot.status, TaskStatus::Interrupted as i32);
    }
}
