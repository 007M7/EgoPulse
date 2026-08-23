#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::BufReader;
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
