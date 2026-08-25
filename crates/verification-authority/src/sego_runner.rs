use crate::{
    CheckerExecutionError, CheckerExecutionReceipt, CheckerProcessFailure,
    GovernedCheckerSupervisor, SegoMapError, SegoMappedResult, SegoMapperPolicy,
    checker_failure_result, map_sego_review,
};
use std::path::Path;
use thiserror::Error;

/// The outcome of one explicitly configured Sego/checker attempt. A process
/// failure or untrusted output is still returned as a governed Verification
/// result; callers must not turn an error into a missing or passing result.
#[derive(Clone, Debug, PartialEq)]
pub struct GovernedSegoRunResult {
    pub execution_id: String,
    pub receipt: Option<CheckerExecutionReceipt>,
    pub mapped: SegoMappedResult,
    pub failure: Option<CheckerProcessFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GovernedSegoRunError {
    #[error("Sego execution ID is empty")]
    InvalidExecutionId,
}

/// Provider-neutral orchestration around the existing process supervisor and
/// Sego mapper. It owns no Authority store and performs no Task or Verdict
/// write; those remain explicit composition steps at the application boundary.
pub struct GovernedSegoRunner {
    supervisor: GovernedCheckerSupervisor,
}

impl GovernedSegoRunner {
    #[must_use]
    pub fn new(supervisor: GovernedCheckerSupervisor) -> Self {
        Self { supervisor }
    }

    pub async fn run(
        &self,
        working_directory: &Path,
        request: &[u8],
        execution_id: &str,
        policy: &SegoMapperPolicy,
    ) -> Result<GovernedSegoRunResult, GovernedSegoRunError> {
        if execution_id.trim().is_empty() {
            return Err(GovernedSegoRunError::InvalidExecutionId);
        }

        match self.supervisor.run(working_directory, request).await {
            Ok(receipt) => match map_sego_review(&receipt.stdout, policy) {
                Ok(mapped) => Ok(GovernedSegoRunResult {
                    execution_id: execution_id.to_owned(),
                    receipt: Some(receipt),
                    mapped,
                    failure: None,
                }),
                Err(SegoMapError::InvalidJson)
                | Err(SegoMapError::ProfileMismatch)
                | Err(SegoMapError::BindingMismatch)
                | Err(SegoMapError::InconsistentArtifact) => Ok(GovernedSegoRunResult {
                    execution_id: execution_id.to_owned(),
                    receipt: Some(receipt),
                    mapped: checker_failure_result(
                        policy,
                        execution_id,
                        CheckerProcessFailure::OutputUntrusted,
                    ),
                    failure: Some(CheckerProcessFailure::OutputUntrusted),
                }),
            },
            Err(error) => {
                let failure = map_process_failure(error);
                Ok(GovernedSegoRunResult {
                    execution_id: execution_id.to_owned(),
                    receipt: None,
                    mapped: checker_failure_result(policy, execution_id, failure),
                    failure: Some(failure),
                })
            }
        }
    }
}

fn map_process_failure(error: CheckerExecutionError) -> CheckerProcessFailure {
    match error {
        CheckerExecutionError::Timeout => CheckerProcessFailure::Timeout,
        CheckerExecutionError::Crashed => CheckerProcessFailure::Crashed,
        CheckerExecutionError::OutputLimit => CheckerProcessFailure::OutputUntrusted,
        CheckerExecutionError::InvalidSpecification
        | CheckerExecutionError::Spawn
        | CheckerExecutionError::InputDelivery
        | CheckerExecutionError::Io => CheckerProcessFailure::Unavailable,
    }
}
