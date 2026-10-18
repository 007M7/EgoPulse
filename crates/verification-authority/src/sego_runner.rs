use crate::{
    CheckerExecutionError, CheckerExecutionReceipt, CheckerFailureOutput, CheckerOutputSource,
    CheckerProcessFailure, GovernedCheckerSupervisor, MAX_CHECKER_ARTIFACT_BYTES,
    captured_failure_code, read_envelope_artifact,
};
use std::path::Path;
use thiserror::Error;

/// One governed checker process exchange, before any criterion is decided.
/// The bytes to map, the failure classification and the bytes kept as evidence
/// stay separate: a non-zero exit never becomes a mapped pass, and a mapped
/// artifact is never inferred from a process that failed.
#[derive(Clone, Debug, PartialEq)]
pub struct GovernedCheckerProcessOutcome {
    pub execution_id: String,
    pub receipt: Option<CheckerExecutionReceipt>,
    /// The bytes the mapper reads as the review artifact. Empty when the
    /// process failed or its envelope could not be read.
    pub output: Vec<u8>,
    /// The checker output kept as evidence because stdout was not mapped
    /// directly: a non-zero exit's output, or the envelope this environment
    /// could not read an artifact from.
    pub captured: Option<CheckerFailureOutput>,
    pub failure: Option<CheckerProcessFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GovernedSegoRunError {
    #[error("Sego execution ID is empty")]
    InvalidExecutionId,
}

/// Provider-neutral orchestration around the existing process supervisor. It
/// owns no Authority store and performs no Task or Verdict write; mapping and
/// sealing remain explicit composition steps at the application boundary.
pub struct GovernedSegoRunner {
    supervisor: GovernedCheckerSupervisor,
}

impl GovernedSegoRunner {
    #[must_use]
    pub fn new(supervisor: GovernedCheckerSupervisor) -> Self {
        Self { supervisor }
    }

    /// Runs the configured checker once. A checker that exits zero has its
    /// review artifact read from the configured source; a checker that exits
    /// non-zero is a failure whose output is preserved for attribution.
    pub async fn run_checker(
        &self,
        working_directory: &Path,
        request: &[u8],
        execution_id: &str,
        source: CheckerOutputSource,
    ) -> Result<GovernedCheckerProcessOutcome, GovernedSegoRunError> {
        if execution_id.trim().is_empty() {
            return Err(GovernedSegoRunError::InvalidExecutionId);
        }
        let receipt = match self.supervisor.run(working_directory, request).await {
            Ok(receipt) => receipt,
            Err(error) => {
                return Ok(GovernedCheckerProcessOutcome {
                    execution_id: execution_id.to_owned(),
                    receipt: None,
                    output: Vec::new(),
                    captured: None,
                    failure: Some(map_process_failure(error)),
                });
            }
        };
        if receipt.exit_code != 0 {
            let captured = CheckerFailureOutput {
                exit_code: receipt.exit_code,
                safe_reason_code: captured_failure_code(&receipt.stdout),
                bytes: receipt.stdout.clone(),
            };
            return Ok(GovernedCheckerProcessOutcome {
                execution_id: execution_id.to_owned(),
                receipt: Some(receipt),
                output: Vec::new(),
                captured: Some(captured),
                failure: Some(CheckerProcessFailure::Crashed),
            });
        }
        let output = match source {
            CheckerOutputSource::Stdout => receipt.stdout.clone(),
            CheckerOutputSource::EnvelopeArtifactPath => {
                match read_envelope_artifact(
                    working_directory,
                    &receipt.stdout,
                    MAX_CHECKER_ARTIFACT_BYTES,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // stdout answered but no artifact could be read from
                        // it. Keep the answer and refuse the criterion instead
                        // of mapping bytes this environment cannot vouch for.
                        let captured = CheckerFailureOutput {
                            exit_code: receipt.exit_code,
                            safe_reason_code: None,
                            bytes: receipt.stdout.clone(),
                        };
                        return Ok(GovernedCheckerProcessOutcome {
                            execution_id: execution_id.to_owned(),
                            receipt: Some(receipt),
                            output: Vec::new(),
                            captured: Some(captured),
                            failure: Some(CheckerProcessFailure::OutputUntrusted),
                        });
                    }
                }
            }
        };
        Ok(GovernedCheckerProcessOutcome {
            execution_id: execution_id.to_owned(),
            receipt: Some(receipt),
            output,
            captured: None,
            failure: None,
        })
    }
}

fn map_process_failure(error: CheckerExecutionError) -> CheckerProcessFailure {
    match error {
        CheckerExecutionError::Timeout => CheckerProcessFailure::Timeout,
        CheckerExecutionError::Crashed => CheckerProcessFailure::Crashed,
        CheckerExecutionError::OutputLimit | CheckerExecutionError::Protocol => {
            CheckerProcessFailure::OutputUntrusted
        }
        CheckerExecutionError::InvalidSpecification
        | CheckerExecutionError::Spawn
        | CheckerExecutionError::InputDelivery
        | CheckerExecutionError::Io => CheckerProcessFailure::Unavailable,
    }
}
