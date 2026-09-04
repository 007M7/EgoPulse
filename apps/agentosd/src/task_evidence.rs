use std::{future::Future, pin::Pin, sync::Arc};

use egopulse_cognition_runtime::task_authority::canonical_request_digest;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::CommandMetadata,
    task::v1::{
        SubmitTaskEvidenceCommand, TaskCommand, TaskStatus, task_command, task_command_result,
    },
};
use egopulse_local_api::command_gateway::TaskCommandPort;
use egopulse_local_ide_control::collaboration_control::{
    ArtifactReturnSource, HarnessDispatchCycleError, HarnessDispatchCycleReport,
    HarnessDispatchRunner, PendingArtifactReturn,
};

/// Application-level bridge from an Artifact Authority technical return to
/// Task Authority evidence intake.
///
/// The bridge never acknowledges the Artifact outbox, performs Verification,
/// commits a Collaboration Step, or decides Task completion. Those remain
/// independently owned stages. It only submits the already-frozen
/// SubmitTaskEvidence command through a fixed daemon-owned Collaboration
/// principal, using the ReturnReceipt identity as the idempotency boundary.
pub struct GovernedTaskEvidenceIntakeRunner {
    inner: Arc<dyn HarnessDispatchRunner>,
    returns: Arc<dyn ArtifactReturnSource>,
    task: Arc<dyn TaskCommandPort>,
}

impl GovernedTaskEvidenceIntakeRunner {
    #[must_use]
    pub fn new(
        inner: Arc<dyn HarnessDispatchRunner>,
        returns: Arc<dyn ArtifactReturnSource>,
        task: Arc<dyn TaskCommandPort>,
    ) -> Self {
        Self {
            inner,
            returns,
            task,
        }
    }

    fn ingest_pending(
        &self,
        report: &mut HarnessDispatchCycleReport,
    ) -> Result<(), HarnessDispatchCycleError> {
        let pending = self.returns.pending_returns().map_err(|_| {
            HarnessDispatchCycleError::TaskEvidenceIntake(
                "Artifact Authority return outbox unavailable".to_owned(),
            )
        })?;
        for returned in pending {
            let command = evidence_command(&returned)?;
            let result = self
                .task
                .execute_system_evidence_intake(&command)
                .map_err(|_| {
                    HarnessDispatchCycleError::TaskEvidenceIntake(
                        "Task Authority evidence command unavailable or uncertain".to_owned(),
                    )
                })?;
            let lineage = returned
                .receipt
                .lineage
                .as_ref()
                .expect("evidence_command validated lineage");
            let expected_revision = lineage.task_revision.checked_add(1).ok_or_else(|| {
                HarnessDispatchCycleError::TaskEvidenceIntake(
                    "Task evidence revision overflow".to_owned(),
                )
            })?;
            let accepted = matches!(
                result.result.outcome.as_ref(),
                Some(task_command_result::Outcome::Task(task))
                    if task.task_id == lineage.task_id
                        && task.revision == expected_revision
                        && task.work_revision == lineage.work_revision
                        && task.status == TaskStatus::VerificationPending as i32
                        && task.artifact_set_id.as_deref()
                            == Some(returned.receipt.artifact_set_id.as_str())
            );
            if !accepted || (result.result.committed_event.is_none() && !result.result.replayed) {
                return Err(HarnessDispatchCycleError::TaskEvidenceIntake(
                    "Task Authority rejected or returned incoherent evidence intake".to_owned(),
                ));
            }
            report.task_evidence_intakes += 1;
        }
        Ok(())
    }
}

impl HarnessDispatchRunner for GovernedTaskEvidenceIntakeRunner {
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
            let mut report = self.inner.run_once().await?;
            self.ingest_pending(&mut report)?;
            Ok(report)
        })
    }
}

fn evidence_command(
    returned: &PendingArtifactReturn,
) -> Result<TaskCommand, HarnessDispatchCycleError> {
    let receipt = &returned.receipt;
    let lineage = receipt.lineage.as_ref().ok_or_else(|| {
        HarnessDispatchCycleError::TaskEvidenceIntake(
            "Artifact ReturnReceipt lineage missing".to_owned(),
        )
    })?;
    if returned.message_id.trim().is_empty()
        || !is_sha256(&returned.payload_digest_sha256)
        || receipt.receipt_id.trim().is_empty()
        || receipt.return_handoff_id.trim().is_empty()
        || receipt.artifact_set_id.trim().is_empty()
        || !receipt.accepted_for_evidence_intake
        || receipt.verification_performed
        || receipt.task_completion_decided
        || receipt.committed_at.is_none()
        || lineage.task_id.trim().is_empty()
        || lineage.task_revision == 0
        || lineage.work_revision == 0
    {
        return Err(HarnessDispatchCycleError::TaskEvidenceIntake(
            "Artifact ReturnReceipt is not admissible for Task evidence".to_owned(),
        ));
    }

    let command_id = format!("task-evidence:{}", receipt.receipt_id);
    let mut command = TaskCommand {
        command: Some(task_command::Command::SubmitTaskEvidence(
            SubmitTaskEvidenceCommand {
                meta: Some(CommandMetadata {
                    command_id: command_id.clone(),
                    idempotency_key: command_id,
                    idempotency_scope: lineage.task_id.clone(),
                    request_digest_sha256: String::new(),
                    issued_at: receipt.committed_at,
                    correlation_id: receipt.return_handoff_id.clone(),
                    causation_id: Some(receipt.receipt_id.clone()),
                }),
                task_id: lineage.task_id.clone(),
                expected_revision: lineage.task_revision,
                work_revision: lineage.work_revision,
                return_handoff_id: receipt.return_handoff_id.clone(),
                artifact_set_id: receipt.artifact_set_id.clone(),
            },
        )),
    };
    let digest = canonical_request_digest(&command).map_err(|_| {
        HarnessDispatchCycleError::TaskEvidenceIntake(
            "Task evidence command could not be sealed".to_owned(),
        )
    })?;
    let Some(task_command::Command::SubmitTaskEvidence(evidence)) = command.command.as_mut() else {
        unreachable!("Task evidence command branch was constructed above");
    };
    evidence
        .meta
        .as_mut()
        .expect("Task evidence metadata was constructed above")
        .request_digest_sha256 = digest;
    Ok(command)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{LineageBinding, ReturnReceipt},
        task::v1::{TaskCommandResult, TaskEvent, TaskSnapshot},
    };
    use egopulse_local_api::command_gateway::{
        CommandPortFailure, CommandPortResult, CommandPrincipal,
    };
    use prost_types::Timestamp;
    use std::sync::Mutex;

    struct FixedRunner;

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
            Box::pin(async {
                Ok(HarnessDispatchCycleReport {
                    dispatches_seen: 2,
                    ..Default::default()
                })
            })
        }
    }

    struct StaticReturns {
        pending: Vec<PendingArtifactReturn>,
        acknowledgements: Mutex<u64>,
    }

    impl ArtifactReturnSource for StaticReturns {
        fn pending_returns(&self) -> Result<Vec<PendingArtifactReturn>, String> {
            Ok(self.pending.clone())
        }

        fn acknowledge_return(
            &self,
            _message_id: &str,
            _payload_digest_sha256: &str,
        ) -> Result<bool, String> {
            *self.acknowledgements.lock().expect("ack lock") += 1;
            Ok(true)
        }
    }

    struct RecordingTaskPort {
        commands: Mutex<Vec<TaskCommand>>,
        fail: bool,
    }

    impl TaskCommandPort for RecordingTaskPort {
        fn execute(
            &self,
            _command: &TaskCommand,
            _principal: &CommandPrincipal,
        ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
            Err(CommandPortFailure::IntegrityFailure)
        }

        fn execute_system_evidence_intake(
            &self,
            command: &TaskCommand,
        ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
            if self.fail {
                return Err(CommandPortFailure::Unavailable);
            }
            let mut commands = self.commands.lock().expect("commands lock");
            commands.push(command.clone());
            let Some(task_command::Command::SubmitTaskEvidence(evidence)) =
                command.command.as_ref()
            else {
                return Err(CommandPortFailure::IntegrityFailure);
            };
            let replayed = commands.len() > 1;
            Ok(CommandPortResult {
                result: TaskCommandResult {
                    outcome: Some(task_command_result::Outcome::Task(TaskSnapshot {
                        task_id: evidence.task_id.clone(),
                        revision: evidence.expected_revision + 1,
                        work_revision: evidence.work_revision,
                        status: TaskStatus::VerificationPending as i32,
                        artifact_set_id: Some(evidence.artifact_set_id.clone()),
                        ..Default::default()
                    })),
                    committed_event: (!replayed).then(TaskEvent::default),
                    replayed,
                },
                source_revision: None,
                await_target: None,
            })
        }
    }

    fn pending_return() -> PendingArtifactReturn {
        PendingArtifactReturn {
            message_id: "artifact-return-outbox-1".to_owned(),
            payload_digest_sha256: "a".repeat(64),
            receipt: ReturnReceipt {
                receipt_id: "return-receipt-1".to_owned(),
                return_handoff_id: "return-handoff-1".to_owned(),
                artifact_set_id: "artifact-set-1".to_owned(),
                lineage: Some(LineageBinding {
                    task_id: "task-1".to_owned(),
                    task_revision: 2,
                    work_revision: 1,
                    ..Default::default()
                }),
                accepted_for_evidence_intake: true,
                verification_performed: false,
                task_completion_decided: false,
                committed_at: Some(Timestamp {
                    seconds: 1_788_000_000,
                    nanos: 0,
                }),
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn bridge_submits_sealed_idempotent_evidence_without_acknowledging_artifact_outbox() {
        let returns = Arc::new(StaticReturns {
            pending: vec![pending_return()],
            acknowledgements: Mutex::new(0),
        });
        let task = Arc::new(RecordingTaskPort {
            commands: Mutex::new(Vec::new()),
            fail: false,
        });
        let runner = GovernedTaskEvidenceIntakeRunner::new(
            Arc::new(FixedRunner),
            Arc::clone(&returns) as Arc<dyn ArtifactReturnSource>,
            Arc::clone(&task) as Arc<dyn TaskCommandPort>,
        );

        let first = runner.run_once().await.expect("first evidence intake");
        let replay = runner.run_once().await.expect("replayed evidence intake");
        assert_eq!(first.dispatches_seen, 2);
        assert_eq!(first.task_evidence_intakes, 1);
        assert_eq!(replay.task_evidence_intakes, 1);
        assert_eq!(*returns.acknowledgements.lock().expect("ack lock"), 0);

        let commands = task.commands.lock().expect("commands lock");
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], commands[1]);
        let expected_digest = canonical_request_digest(&commands[0]).expect("sealed digest");
        let Some(task_command::Command::SubmitTaskEvidence(evidence)) =
            commands[0].command.as_ref()
        else {
            panic!("Task evidence command expected");
        };
        assert_eq!(
            evidence
                .meta
                .as_ref()
                .expect("metadata")
                .request_digest_sha256,
            expected_digest
        );
    }

    #[tokio::test]
    async fn bridge_fails_closed_for_inadmissible_receipt_and_task_port_failure() {
        let mut invalid = pending_return();
        invalid.receipt.accepted_for_evidence_intake = false;
        let invalid_runner = GovernedTaskEvidenceIntakeRunner::new(
            Arc::new(FixedRunner),
            Arc::new(StaticReturns {
                pending: vec![invalid],
                acknowledgements: Mutex::new(0),
            }),
            Arc::new(RecordingTaskPort {
                commands: Mutex::new(Vec::new()),
                fail: false,
            }),
        );
        assert!(matches!(
            invalid_runner.run_once().await,
            Err(HarnessDispatchCycleError::TaskEvidenceIntake(_))
        ));

        let unavailable_runner = GovernedTaskEvidenceIntakeRunner::new(
            Arc::new(FixedRunner),
            Arc::new(StaticReturns {
                pending: vec![pending_return()],
                acknowledgements: Mutex::new(0),
            }),
            Arc::new(RecordingTaskPort {
                commands: Mutex::new(Vec::new()),
                fail: true,
            }),
        );
        assert!(matches!(
            unavailable_runner.run_once().await,
            Err(HarnessDispatchCycleError::TaskEvidenceIntake(_))
        ));
    }
}
