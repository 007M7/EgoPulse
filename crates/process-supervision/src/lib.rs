#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptBudget {
    pub timeout_seconds: u64,
    pub max_restarts: u8,
}

impl Default for AttemptBudget {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_restarts: 0,
        }
    }
}

pub async fn foundation_probe() -> FoundationHealth {
    tracing::trace!("running process supervision foundation probe");
    tokio::task::yield_now().await;
    FoundationHealth::foundation_only("process-supervision")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisedProcessSpec {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub clear_environment: bool,
    pub inherited_environment: Vec<String>,
}

impl SupervisedProcessSpec {
    #[must_use]
    pub fn new(executable: impl Into<PathBuf>, working_directory: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            arguments: Vec::new(),
            working_directory: working_directory.into(),
            clear_environment: false,
            inherited_environment: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProcessSupervisionError {
    #[error("supervised executable is not an absolute file path")]
    InvalidExecutable,
    #[error("supervised working directory is not an absolute directory path")]
    InvalidWorkingDirectory,
    #[error("supervised process could not be started")]
    Spawn(#[source] std::io::Error),
    #[error("supervised process did not expose the required stdio handles")]
    MissingStdio,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernedProcessBudget {
    pub timeout: std::time::Duration,
    pub output_limit_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedProcessReceipt {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    pub duration_ms: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GovernedProcessError {
    #[error("governed process specification is invalid")]
    InvalidSpecification,
    #[error("governed process could not be started")]
    Spawn,
    #[error("governed process input could not be delivered")]
    InputDelivery,
    #[error("governed process exceeded its timeout")]
    Timeout,
    #[error("governed process exited unsuccessfully")]
    Crashed,
    #[error("governed process output exceeded its byte limit")]
    OutputLimit,
    #[error("governed process I/O failed")]
    Io,
}

pub struct SupervisedProcess {
    child: Child,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl SupervisedProcess {
    pub async fn spawn(spec: &SupervisedProcessSpec) -> Result<Self, ProcessSupervisionError> {
        if !absolute_file_candidate(&spec.executable) {
            return Err(ProcessSupervisionError::InvalidExecutable);
        }
        if !absolute_directory_candidate(&spec.working_directory) {
            return Err(ProcessSupervisionError::InvalidWorkingDirectory);
        }

        let mut command = Command::new(&spec.executable);
        command
            .args(&spec.arguments)
            .current_dir(&spec.working_directory)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if spec.clear_environment {
            let inherited = spec
                .inherited_environment
                .iter()
                .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
                .collect::<Vec<_>>();
            command.env_clear();
            for (name, value) in inherited {
                command.env(name, value);
            }
        }

        let mut child = command.spawn().map_err(ProcessSupervisionError::Spawn)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(ProcessSupervisionError::MissingStdio)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessSupervisionError::MissingStdio)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessSupervisionError::MissingStdio)?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr: Some(stderr),
        })
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.stderr.take()
    }

    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    pub async fn terminate(&mut self) -> Result<(), std::io::Error> {
        self.child.kill().await
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        self.child.wait().await
    }
}

pub async fn run_governed_process(
    spec: &SupervisedProcessSpec,
    request: &[u8],
    budget: GovernedProcessBudget,
) -> Result<GovernedProcessReceipt, GovernedProcessError> {
    if budget.timeout.is_zero() || budget.output_limit_bytes == 0 {
        return Err(GovernedProcessError::InvalidSpecification);
    }
    let started = std::time::Instant::now();
    let process = SupervisedProcess::spawn(spec)
        .await
        .map_err(|_| GovernedProcessError::Spawn)?;
    let SupervisedProcess {
        mut child,
        mut stdin,
        mut stdout,
        stderr,
    } = process;
    let mut stderr = stderr.ok_or(GovernedProcessError::Spawn)?;
    if stdin.write_all(request).await.is_err() || stdin.shutdown().await.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(GovernedProcessError::InputDelivery);
    }
    drop(stdin);

    let operation = async {
        let (stdout, stderr, status) = tokio::try_join!(
            read_bounded(&mut stdout, budget.output_limit_bytes),
            read_bounded(&mut stderr, budget.output_limit_bytes),
            child.wait(),
        )
        .map_err(|_| GovernedProcessError::Io)?;
        if stdout.len() as u64 > budget.output_limit_bytes
            || stderr.len() as u64 > budget.output_limit_bytes
        {
            return Err(GovernedProcessError::OutputLimit);
        }
        if !status.success() {
            return Err(GovernedProcessError::Crashed);
        }
        Ok(GovernedProcessReceipt {
            stdout,
            stderr,
            exit_code: status.code().unwrap_or_default(),
            duration_ms: started.elapsed().as_millis() as u64,
        })
    };
    tokio::time::timeout(budget.timeout, operation)
        .await
        .map_err(|_| GovernedProcessError::Timeout)?
}

async fn read_bounded(
    reader: &mut (impl AsyncRead + Unpin),
    output_limit_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(output_limit_bytes + 1)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

fn absolute_file_candidate(path: &Path) -> bool {
    path.is_absolute() && path.file_name().is_some()
}

fn absolute_directory_candidate(path: &Path) -> bool {
    path.is_absolute()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn foundation_probe_is_non_serving() {
        assert_eq!(foundation_probe().await.state.as_str(), "foundation-only");
    }

    #[test]
    fn supervised_process_requires_explicit_absolute_boundaries() {
        assert!(!absolute_file_candidate(Path::new("codex")));
        assert!(!absolute_directory_candidate(Path::new(".")));
    }
}
