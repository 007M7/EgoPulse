#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_agentosd::{ConfiguredMemoryRetrievalPort, MemoryRetrievalCompositionConfig};
use egopulse_cognition_runtime::{
    memory_authority::{
        AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority, MemoryAuthorityConfig,
        MemoryPrincipalKind, SubmitMemoryCandidate,
    },
    task_authority::SqlCipherKey,
};
use egopulse_local_api::cognition_gateway::{
    MemoryRetrievalInput, MemoryRetrievalPort, MemoryRetrievalPortError,
};
use uuid::Uuid;

struct TestStore(PathBuf);

impl Drop for TestStore {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", self.0.display(), suffix));
            let _ = fs::remove_file(path);
        }
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

fn real_worker_config() -> MemoryRetrievalCompositionConfig {
    let root = repository_root();
    let python = root
        .join("workers")
        .join("memory-rag")
        .join(".venv")
        .join("Scripts")
        .join("python.exe");
    assert!(python.is_file(), "missing Memory Worker Python: {python:?}");
    let python_path = format!(
        "{};{}",
        root.join("workers/memory-rag/src").display(),
        root.join("workers/contract-bindings/src").display()
    );
    MemoryRetrievalCompositionConfig {
        worker_executable: python,
        worker_arguments: vec!["-m".to_owned(), "egopulse_memory_rag".to_owned()],
        working_directory: root,
        inherited_environment: BTreeSet::from(["SystemRoot".to_owned(), "WINDIR".to_owned()]),
        environment_overrides: BTreeMap::from([("PYTHONPATH".to_owned(), python_path)]),
        timeout: Duration::from_secs(15),
        output_limit_bytes: 16 * 1024 * 1024,
        principal_scope_allowlist: BTreeMap::from([(
            "os-user:founder".to_owned(),
            BTreeSet::from(["scope:founder".to_owned()]),
        )]),
    }
}

// Use the already provisioned Worker interpreter. PowerShell cold startup can
// consume the crash fixture's deadline before its explicit exit is executed.
fn python_config(command: &str, timeout: Duration) -> MemoryRetrievalCompositionConfig {
    let mut config = real_worker_config();
    config.worker_arguments = vec!["-c".to_owned(), command.to_owned()];
    config.timeout = timeout;
    config
}

fn authority() -> (TestStore, Arc<Mutex<MemoryAuthority>>) {
    let path = std::env::temp_dir().join(format!("egopulse-memory-{}.db", Uuid::now_v7()));
    let store = TestStore(path.clone());
    let mut authority = MemoryAuthority::open(MemoryAuthorityConfig {
        database_path: path,
        store_epoch: Uuid::now_v7().to_string(),
        key: SqlCipherKey::new([0x5a; 32]),
    })
    .expect("open Memory Authority");
    let founder = AuthenticatedMemoryPrincipal {
        kind: MemoryPrincipalKind::Founder,
        principal_id: "founder:test".to_owned(),
        authenticated: true,
    };
    authority
        .submit_candidate(
            &SubmitMemoryCandidate {
                memory_id: "memory-01".to_owned(),
                content: "Rust owns accepted Memory facts.".to_owned(),
                source_ref: "source:memory-01".to_owned(),
                scope_ref: "scope:founder".to_owned(),
                idempotency_key: Uuid::now_v7().to_string(),
            },
            &founder,
        )
        .expect("submit candidate");
    authority
        .accept(
            &GovernMemory {
                memory_id: "memory-01".to_owned(),
                expected_revision: 1,
                evidence_ref: "evidence:founder-acceptance".to_owned(),
                idempotency_key: Uuid::now_v7().to_string(),
            },
            &founder,
        )
        .expect("accept candidate");
    (store, Arc::new(Mutex::new(authority)))
}

fn input(scope_ref: &str) -> MemoryRetrievalInput {
    MemoryRetrievalInput {
        authenticated_principal_id: "os-user:founder".to_owned(),
        request_id: Uuid::now_v7().to_string(),
        correlation_id: Uuid::now_v7().to_string(),
        query: "accepted Memory".to_owned(),
        scope_ref: scope_ref.to_owned(),
        max_results: 8,
        min_score: 0.0,
    }
}

#[tokio::test]
async fn configured_port_runs_real_python_only_over_an_authorized_accepted_snapshot() {
    let (_store, authority) = authority();
    let port = ConfiguredMemoryRetrievalPort::new(authority, real_worker_config())
        .expect("configured port");
    let response = port
        .retrieve(input("scope:founder"))
        .await
        .expect("real retrieval");
    assert_eq!(response.algorithm_id, "lexical-overlap-v0");
    assert_eq!(response.candidates.len(), 1);
    assert_eq!(response.candidates[0].memory_id, "memory-01");
    assert_eq!(response.candidates[0].source_ref, "source:memory-01");
}

#[tokio::test]
async fn principal_scope_revalidation_happens_before_worker_execution() {
    let (_store, authority) = authority();
    let port = ConfiguredMemoryRetrievalPort::new(authority, real_worker_config())
        .expect("configured port");
    assert_eq!(
        port.retrieve(input("scope:denied")).await,
        Err(MemoryRetrievalPortError::ScopeDenied)
    );
}

#[tokio::test]
async fn timeout_crash_and_concurrency_preserve_frozen_error_semantics() {
    let (_store, authority) = authority();
    let timeout = ConfiguredMemoryRetrievalPort::new(
        Arc::clone(&authority),
        python_config("import time; time.sleep(30)", Duration::from_millis(100)),
    )
    .expect("timeout port");
    assert_eq!(
        timeout.retrieve(input("scope:founder")).await,
        Err(MemoryRetrievalPortError::DeadlineExceeded)
    );

    let crash = ConfiguredMemoryRetrievalPort::new(
        Arc::clone(&authority),
        python_config("import sys; sys.exit(7)", Duration::from_secs(5)),
    )
    .expect("crash port");
    assert_eq!(
        crash.retrieve(input("scope:founder")).await,
        Err(MemoryRetrievalPortError::WorkerUnavailable)
    );

    let busy = Arc::new(
        ConfiguredMemoryRetrievalPort::new(
            authority,
            python_config(
                "import sys, time; time.sleep(2); sys.exit(7)",
                Duration::from_secs(5),
            ),
        )
        .expect("busy port"),
    );
    let first_port = Arc::clone(&busy);
    let first = tokio::spawn(async move { first_port.retrieve(input("scope:founder")).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        busy.retrieve(input("scope:founder")).await,
        Err(MemoryRetrievalPortError::ResourceExhausted)
    );
    assert_eq!(
        first.await.expect("first task"),
        Err(MemoryRetrievalPortError::WorkerUnavailable)
    );
}
