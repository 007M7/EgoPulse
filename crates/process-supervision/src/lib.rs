#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

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

/// Bounded user and operating-system environment names required by a locally
/// installed interactive executable. Harness processes opt into this list
/// instead of inheriting the daemon's complete environment, which may contain
/// Authority database keys and other EgoPulse-only secrets.
const MINIMAL_USER_ENVIRONMENT: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "COLORTERM",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

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

    /// Clears the parent environment and inherits only the bounded user/OS
    /// variables needed by a local executable. Provider credentials must still
    /// be added explicitly with `with_environment_override`.
    #[must_use]
    pub fn with_minimal_user_environment(mut self) -> Self {
        self.clear_environment = true;
        self.inherited_environment = MINIMAL_USER_ENVIRONMENT
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        self
    }

    /// Prefer an installed desktop PowerShell on Windows for the child only.
    /// Keep this separate from provider credentials and from inherited names.
    #[must_use]
    pub fn with_desktop_shell_path(self) -> Self {
        #[cfg(windows)]
        if let Some(path) = egopulse_local_ipc_platform::desktop_powershell_path()
            .and_then(|value| value.into_string().ok())
        {
            return self.with_environment_override("PATH", path);
        }
        self
    }

    /// Adds one explicitly reviewed environment name to an isolated process.
    /// Duplicate names are ignored so composition order cannot widen the
    /// inherited set accidentally.
    #[must_use]
    pub fn with_inherited_environment(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !self.inherited_environment.contains(&name) {
            self.inherited_environment.push(name);
        }
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
    #[error("supervised process could not be assigned to its operating-system process tree")]
    ProcessTree(#[source] std::io::Error),
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

struct SupervisedChild {
    // Kept before `child` so cancellation closes the Windows Job Object before
    // the direct child handle is dropped. KILL_ON_JOB_CLOSE then reaches every
    // descendant inherited from the supervised root.
    process_tree: ProcessTreeGuard,
    child: Child,
}

impl SupervisedChild {
    fn process_id(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
        self.child.try_wait()
    }

    async fn terminate(&mut self) -> Result<(), std::io::Error> {
        #[cfg(windows)]
        {
            self.process_tree.terminate()
        }

        #[cfg(not(windows))]
        {
            let _ = &self.process_tree;
            self.child.kill().await
        }
    }

    async fn wait(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        self.child.wait().await
    }
}

pub struct SupervisedProcess {
    // The process tree and direct child remain one drop unit even when a
    // one-shot exchange takes and closes stdin before waiting for completion.
    supervised_child: SupervisedChild,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl SupervisedProcess {
    pub async fn spawn(spec: &SupervisedProcessSpec) -> Result<Self, ProcessSupervisionError> {
        if !is_supported_executable_file(&spec.executable) {
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
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);

        let mut child = command.spawn().map_err(ProcessSupervisionError::Spawn)?;
        let process_tree =
            ProcessTreeGuard::new(&child).map_err(ProcessSupervisionError::ProcessTree)?;
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
            supervised_child: SupervisedChild {
                process_tree,
                child,
            },
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
        self.supervised_child.process_id()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, std::io::Error> {
        self.supervised_child.try_wait()
    }

    pub async fn terminate(&mut self) -> Result<(), std::io::Error> {
        self.supervised_child.terminate().await
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        self.supervised_child.wait().await
    }
}

pub async fn run_governed_process(
    spec: &SupervisedProcessSpec,
    request: &[u8],
    budget: GovernedProcessBudget,
) -> Result<GovernedProcessReceipt, GovernedProcessError> {
    let receipt = run_governed_process_outcome(spec, request, budget).await?;
    if receipt.exit_code != 0 {
        return Err(GovernedProcessError::Crashed);
    }
    Ok(receipt)
}

/// Captures a bounded receipt for a normally exited process, including a
/// non-zero exit code. Acceptance commands use this to retain failure evidence;
/// a returned receipt does not imply that the command or its criterion passed.
/// Spawn, timeout, output-limit and abnormal termination failures remain errors.
pub async fn run_governed_process_outcome(
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
        mut supervised_child,
        mut stdin,
        mut stdout,
        stderr,
    } = process;
    let mut stderr = stderr.ok_or(GovernedProcessError::Spawn)?;
    if stdin.write_all(request).await.is_err() || stdin.shutdown().await.is_err() {
        terminate_and_reap(&mut supervised_child).await;
        return Err(GovernedProcessError::InputDelivery);
    }
    // `shutdown` flushes pending bytes but does not guarantee the Windows pipe
    // handle is closed. Drop it explicitly so EOF-driven Workers can finish.
    drop(stdin);

    let operation = async {
        let (stdout, stderr, status) = tokio::try_join!(
            read_bounded(&mut stdout, budget.output_limit_bytes),
            read_bounded(&mut stderr, budget.output_limit_bytes),
            supervised_child.wait(),
        )
        .map_err(|_| GovernedProcessError::Io)?;
        if stdout.len() as u64 > budget.output_limit_bytes
            || stderr.len() as u64 > budget.output_limit_bytes
        {
            return Err(GovernedProcessError::OutputLimit);
        }
        // A signal termination has no portable exit code. Never encode it as
        // zero: doing so would turn missing execution evidence into success.
        let exit_code = status.code().ok_or(GovernedProcessError::Crashed)?;
        Ok(GovernedProcessReceipt {
            stdout,
            stderr,
            exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    };
    match tokio::time::timeout(budget.timeout, operation).await {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(error)) => {
            terminate_and_reap(&mut supervised_child).await;
            Err(error)
        }
        Err(_) => {
            terminate_and_reap(&mut supervised_child).await;
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

async fn terminate_and_reap(process: &mut SupervisedChild) {
    if process.try_wait().ok().flatten().is_none() {
        let _ = process.terminate().await;
    }
    let _ = process.wait().await;
}

#[cfg(windows)]
use egopulse_local_ipc_platform::WindowsProcessTree as ProcessTreeGuard;

#[cfg(not(windows))]
#[derive(Debug)]
struct ProcessTreeGuard;

#[cfg(not(windows))]
impl ProcessTreeGuard {
    fn new(_child: &Child) -> std::io::Result<Self> {
        Ok(Self)
    }
}

/// Returns whether an exact absolute path currently names a file type that the
/// operating system can start directly. This is repeated immediately before
/// every spawn; an earlier installer/bootstrap preflight is never treated as a
/// permanent capability attestation.
#[must_use]
pub fn is_supported_executable_file(path: &Path) -> bool {
    if !path.is_absolute() || path.file_name().is_none() || !path.is_file() {
        return false;
    }

    #[cfg(windows)]
    {
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            return false;
        };
        matches!(
            extension.to_ascii_lowercase().as_str(),
            "exe" | "com" | "cmd" | "bat"
        )
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    true
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
        assert!(!is_supported_executable_file(Path::new("codex")));
        assert!(!absolute_directory_candidate(Path::new(".")));
    }

    #[test]
    fn minimal_user_environment_excludes_daemon_authority_secrets() {
        let spec = SupervisedProcessSpec::new("codex", ".")
            .with_minimal_user_environment()
            .with_inherited_environment("CODEX_HOME")
            .with_inherited_environment("CODEX_HOME");

        assert!(spec.clear_environment);
        assert!(spec.inherited_environment.iter().any(|name| name == "PATH"));
        assert!(
            spec.inherited_environment
                .iter()
                .any(|name| name == "USERPROFILE")
        );
        assert_eq!(
            spec.inherited_environment
                .iter()
                .filter(|name| name.as_str() == "CODEX_HOME")
                .count(),
            1
        );
        assert!(
            spec.inherited_environment
                .iter()
                .all(|name| !name.starts_with("EGOPULSE_") && !name.ends_with("_API_KEY"))
        );
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
