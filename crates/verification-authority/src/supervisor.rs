use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, GovernedProcessReceipt, SupervisedProcessSpec,
    run_governed_process,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerExecutionReceipt {
    pub stdout: Vec<u8>,
    pub stderr_sha256: String,
    pub stderr_byte_length: u64,
    pub exit_code: i32,
    pub duration_ms: u64,
}

pub type CheckerExecutionError = GovernedProcessError;

pub struct GovernedCheckerSupervisor {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    output_limit: u64,
}

impl GovernedCheckerSupervisor {
    pub fn new(
        executable: PathBuf,
        arguments: Vec<String>,
        timeout: Duration,
        output_limit: u64,
    ) -> Result<Self, CheckerExecutionError> {
        if !executable.is_absolute()
            || !executable.is_file()
            || timeout.is_zero()
            || output_limit == 0
        {
            return Err(CheckerExecutionError::InvalidSpecification);
        }
        Ok(Self {
            executable,
            arguments,
            timeout,
            output_limit,
        })
    }

    pub async fn run(
        &self,
        working_directory: &Path,
        request: &[u8],
    ) -> Result<CheckerExecutionReceipt, CheckerExecutionError> {
        let mut spec = SupervisedProcessSpec::new(&self.executable, working_directory);
        spec.arguments.clone_from(&self.arguments);
        spec.clear_environment = true;
        spec.inherited_environment = vec!["PATH".to_owned(), "SYSTEMROOT".to_owned()];
        let receipt = run_governed_process(
            &spec,
            request,
            GovernedProcessBudget {
                timeout: self.timeout,
                output_limit_bytes: self.output_limit,
            },
        )
        .await?;
        Ok(map_receipt(receipt))
    }
}

fn map_receipt(receipt: GovernedProcessReceipt) -> CheckerExecutionReceipt {
    CheckerExecutionReceipt {
        stdout: receipt.stdout,
        stderr_sha256: hex::encode(Sha256::digest(&receipt.stderr)),
        stderr_byte_length: receipt.stderr.len() as u64,
        exit_code: receipt.exit_code,
        duration_ms: receipt.duration_ms,
    }
}
