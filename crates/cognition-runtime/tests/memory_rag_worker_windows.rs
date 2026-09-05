#![cfg(windows)]

use egopulse_cognition_runtime::memory_authority::{
    AcceptedMemorySnapshot, MemoryRecord, MemoryState,
};
use egopulse_cognition_runtime::memory_rag::{MemoryRagWorker, MemoryRagWorkerFailure};
use egopulse_domain_contracts::memory::MemoryResponseError;
use egopulse_domain_contracts::v01::egopulse::memory::v1::{RetrievalCandidate, RetrievalResponse};
use egopulse_process_supervision::{GovernedProcessBudget, SupervisedProcessSpec};
use prost::Message;
use std::path::PathBuf;
use std::time::Duration;

fn powershell_executable() -> PathBuf {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is available");
    let executable = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    assert!(executable.is_file(), "missing PowerShell: {executable:?}");
    executable
}

fn python_worker_spec() -> SupervisedProcessSpec {
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_owned();
    let memory_src = repository_root
        .join("workers")
        .join("memory-rag")
        .join("src");
    let bindings_src = repository_root
        .join("workers")
        .join("contract-bindings")
        .join("src");
    let python_executable = repository_root
        .join("workers")
        .join("memory-rag")
        .join(".venv")
        .join("Scripts")
        .join("python.exe");
    let python_path = format!(
        "{};{}",
        memory_src.to_string_lossy(),
        bindings_src.to_string_lossy()
    )
    .replace('\'', "''");
    let python_executable = python_executable.to_string_lossy().replace('\'', "''");
    let command =
        format!("$env:PYTHONPATH='{python_path}'; & '{python_executable}' -m egopulse_memory_rag");
    let mut spec = SupervisedProcessSpec::new(powershell_executable(), repository_root);
    spec.arguments = vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        command,
    ];
    spec
}

fn powershell_spec(command: &str) -> SupervisedProcessSpec {
    let mut spec = SupervisedProcessSpec::new(
        powershell_executable(),
        std::env::current_dir().expect("test working directory"),
    );
    spec.arguments = vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        command.to_owned(),
    ];
    spec
}

fn powershell_bytes_spec(bytes: &[u8]) -> SupervisedProcessSpec {
    let values = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    powershell_spec(&format!(
        "$bytes = [byte[]]({values}); [Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)"
    ))
}

fn worker(spec: SupervisedProcessSpec, timeout: Duration) -> MemoryRagWorker {
    MemoryRagWorker::new(
        spec,
        GovernedProcessBudget {
            timeout,
            output_limit_bytes: 16 * 1024 * 1024,
        },
    )
}

fn snapshot() -> AcceptedMemorySnapshot {
    let content = "Rust owns accepted Memory facts.".to_owned();
    AcceptedMemorySnapshot {
        scope_ref: "scope:founder".to_owned(),
        authority_revision: 8,
        records: vec![MemoryRecord {
            memory_id: "memory-01".to_owned(),
            revision: 7,
            content,
            content_sha256: "259cf9c9405104b2a60b6bb446bdb0fd95a29b39202e7ce16650c116b6652ccc"
                .to_owned(),
            source_ref: "source:memory-01".to_owned(),
            scope_ref: "scope:founder".to_owned(),
            state: MemoryState::Accepted,
            created_at_seconds: 1,
            updated_at_seconds: 1,
        }],
        snapshot_sha256: "a".repeat(64),
    }
}

#[tokio::test]
async fn real_python_worker_round_trips_a_governed_snapshot() {
    let response = worker(python_worker_spec(), Duration::from_secs(15))
        .retrieve(&snapshot(), "accepted Memory", 8, 0.0)
        .await
        .expect("real Python Worker response");
    assert_eq!(response.algorithm_id, "lexical-overlap-v0");
    assert_eq!(response.snapshot_sha256, "a".repeat(64));
    assert_eq!(response.candidates.len(), 1);
    assert_eq!(response.candidates[0].memory_id, "memory-01");
}

#[tokio::test]
async fn real_worker_crash_is_not_a_memory_result() {
    let error = worker(powershell_spec("exit 7"), Duration::from_secs(5))
        .retrieve(&snapshot(), "accepted Memory", 8, 0.0)
        .await
        .expect_err("crashed Worker must fail closed");
    assert!(matches!(error, MemoryRagWorkerFailure::Process(_)));
}

#[tokio::test]
async fn real_worker_timeout_is_reaped_and_not_a_memory_result() {
    let error = worker(
        powershell_spec("Start-Sleep -Seconds 30"),
        Duration::from_secs(1),
    )
    .retrieve(&snapshot(), "accepted Memory", 8, 0.0)
    .await
    .expect_err("timed-out Worker must fail closed");
    assert!(matches!(error, MemoryRagWorkerFailure::Process(_)));
}

#[tokio::test]
async fn real_worker_response_snapshot_drift_is_rejected_by_rust() {
    let response = RetrievalResponse {
        algorithm_id: "lexical-overlap-v0".to_owned(),
        query_sha256: "7a3fef9b61fbd5de91ea00d25deb47a7df6587c72fff3b1257e3d482b2ad5534".to_owned(),
        snapshot_sha256: "b".repeat(64),
        candidates: vec![RetrievalCandidate {
            memory_id: "memory-01".to_owned(),
            source_ref: "source:memory-01".to_owned(),
            content_sha256: "259cf9c9405104b2a60b6bb446bdb0fd95a29b39202e7ce16650c116b6652ccc"
                .to_owned(),
            score: 1.0,
            matched_terms: vec!["memory".to_owned()],
        }],
        evidence_ref: format!("memory-rag-evidence-sha256:{}", "c".repeat(64)),
    };
    let response_bytes = response.encode_to_vec();
    let mut framed = (response_bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&response_bytes);

    let error = worker(powershell_bytes_spec(&framed), Duration::from_secs(5))
        .retrieve(&snapshot(), "accepted Memory", 8, 0.0)
        .await
        .expect_err("snapshot drift must fail closed");
    assert!(
        matches!(
            error,
            MemoryRagWorkerFailure::Contract(MemoryResponseError::SnapshotMismatch)
        ),
        "unexpected error: {error:?}"
    );
}
