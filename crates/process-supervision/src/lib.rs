#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

pub const FRAME_HEADER_BYTES: usize = 4;
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("frame size limit is invalid")]
    InvalidLimit,
    #[error("frame payload exceeds the size limit")]
    PayloadTooLarge,
    #[error("frame header ended before four bytes were received")]
    HeaderTruncated,
    #[error("frame payload ended before the declared length was received")]
    PayloadTruncated,
    #[error("frame input contains trailing bytes after one frame")]
    TrailingBytes,
    #[error("frame stream ended before another frame began")]
    EndOfStream,
    #[error("frame I/O failed")]
    Io,
}

pub fn encode_frame(payload: &[u8], max_frame_bytes: u32) -> Result<Vec<u8>, FrameError> {
    if max_frame_bytes == 0 {
        return Err(FrameError::InvalidLimit);
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
    if payload_length > max_frame_bytes {
        return Err(FrameError::PayloadTooLarge);
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8], max_frame_bytes: u32) -> Result<Vec<u8>, FrameError> {
    if max_frame_bytes == 0 {
        return Err(FrameError::InvalidLimit);
    }
    if frame.len() < FRAME_HEADER_BYTES {
        return Err(FrameError::HeaderTruncated);
    }
    let payload_length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if payload_length > max_frame_bytes {
        return Err(FrameError::PayloadTooLarge);
    }
    let total_length = FRAME_HEADER_BYTES + payload_length as usize;
    if frame.len() < total_length {
        return Err(FrameError::PayloadTruncated);
    }
    if frame.len() > total_length {
        return Err(FrameError::TrailingBytes);
    }
    Ok(frame[FRAME_HEADER_BYTES..].to_vec())
}

pub async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
    max_frame_bytes: u32,
) -> Result<Vec<u8>, FrameError> {
    if max_frame_bytes == 0 {
        return Err(FrameError::InvalidLimit);
    }
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let first_read = reader.read(&mut header).await.map_err(|_| FrameError::Io)?;
    if first_read == 0 {
        return Err(FrameError::EndOfStream);
    }
    if first_read < FRAME_HEADER_BYTES {
        reader
            .read_exact(&mut header[first_read..])
            .await
            .map_err(|_| FrameError::HeaderTruncated)?;
    }
    let payload_length = u32::from_be_bytes(header);
    if payload_length > max_frame_bytes {
        return Err(FrameError::PayloadTooLarge);
    }
    let mut payload = vec![0_u8; payload_length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| FrameError::PayloadTruncated)?;
    Ok(payload)
}

pub async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    payload: &[u8],
    max_frame_bytes: u32,
) -> Result<(), FrameError> {
    let frame = encode_frame(payload, max_frame_bytes)?;
    writer.write_all(&frame).await.map_err(|_| FrameError::Io)
}

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
    pub environment_overrides: Vec<(String, String)>,
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
            environment_overrides: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_environment_override(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.environment_overrides.push((name.into(), value.into()));
        self
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
    #[error("governed process frame protocol failed")]
    Protocol,
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
        for (name, value) in &spec.environment_overrides {
            command.env(name, value);
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
    match tokio::time::timeout(budget.timeout, operation).await {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(error)) => {
            terminate_and_reap(&mut child).await;
            Err(error)
        }
        Err(_) => {
            terminate_and_reap(&mut child).await;
            Err(GovernedProcessError::Timeout)
        }
    }
}

/// Runs one request/response exchange using a fixed 4-byte big-endian length
/// prefix. The process remains governed by the same timeout, crash and output
/// limits as the raw-byte runner; framing adds exactly-one-response checks.
pub async fn run_governed_framed_process(
    spec: &SupervisedProcessSpec,
    request: &[u8],
    budget: GovernedProcessBudget,
) -> Result<GovernedProcessReceipt, GovernedProcessError> {
    let request = encode_frame(request, DEFAULT_MAX_FRAME_BYTES)
        .map_err(|_| GovernedProcessError::InvalidSpecification)?;
    let receipt = run_governed_process(spec, &request, budget).await?;
    let max_response_bytes = budget
        .output_limit_bytes
        .checked_sub(FRAME_HEADER_BYTES as u64)
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or(GovernedProcessError::InvalidSpecification)?;
    let stdout = decode_frame(&receipt.stdout, max_response_bytes)
        .map_err(|_| GovernedProcessError::Protocol)?;
    Ok(GovernedProcessReceipt { stdout, ..receipt })
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

async fn terminate_and_reap(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill().await;
    }
    let _ = child.wait().await;
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

    #[test]
    fn frame_encoding_is_big_endian_and_round_trips_exactly_one_payload() {
        let frame = encode_frame(b"abc", DEFAULT_MAX_FRAME_BYTES).expect("encode frame");
        assert_eq!(&frame[..FRAME_HEADER_BYTES], &[0, 0, 0, 3]);
        assert_eq!(
            decode_frame(&frame, DEFAULT_MAX_FRAME_BYTES),
            Ok(b"abc".to_vec())
        );
    }

    #[test]
    fn frame_decoder_rejects_limits_truncation_and_trailing_bytes() {
        assert_eq!(encode_frame(b"x", 0), Err(FrameError::InvalidLimit));
        assert_eq!(encode_frame(b"long", 3), Err(FrameError::PayloadTooLarge));
        assert_eq!(
            decode_frame(&[0, 0, 0], DEFAULT_MAX_FRAME_BYTES),
            Err(FrameError::HeaderTruncated)
        );
        assert_eq!(
            decode_frame(&[0, 0, 0, 3, b'a'], DEFAULT_MAX_FRAME_BYTES),
            Err(FrameError::PayloadTruncated)
        );
        assert_eq!(
            decode_frame(&[0, 0, 0, 1, b'a', b'e'], DEFAULT_MAX_FRAME_BYTES),
            Err(FrameError::TrailingBytes)
        );
    }

    #[tokio::test]
    async fn async_frame_reader_rejects_clean_eof_and_accepts_one_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_frame(&mut writer, b"payload", DEFAULT_MAX_FRAME_BYTES)
            .await
            .expect("write frame");
        writer.shutdown().await.expect("close frame stream");
        assert_eq!(
            read_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES).await,
            Ok(b"payload".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader, DEFAULT_MAX_FRAME_BYTES).await,
            Err(FrameError::EndOfStream)
        );
    }
}
