#![cfg(windows)]
#![forbid(unsafe_code)]

use egopulse_agentosd::{
    MemoryCandidateProducerBinding, MemoryCandidateProducerRegistry, MemoryCandidateProposal,
};
use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_APP_SERVER_SCHEMA_SHA256, CodexAppServerConfig, CodexAppServerDriver,
    codex_protocol_fingerprint,
};
use egopulse_cognition_runtime::{
    memory_authority::{
        AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority, MemoryAuthorityConfig,
        MemoryPrincipalKind, MemoryState,
    },
    task_authority::SqlCipherKey,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, HarnessReadiness, NativeSessionStrategy, ObservationCriticality,
    ProbeHarnessRequest,
};
use egopulse_harness_adapter::{NativeHarnessDriver, ResolvedDispatchMaterial};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_codex_candidate_can_only_enter_memory_as_explicit_candidate() {
    let Some(executable) = std::env::var_os("EGOPULSE_CODEX_EXECUTABLE") else {
        eprintln!("skipping real Codex/Memory E2E; set EGOPULSE_CODEX_EXECUTABLE to run it");
        return;
    };
    let executable = PathBuf::from(executable);
    assert!(
        executable.is_file(),
        "EGOPULSE_CODEX_EXECUTABLE must point to a file: {}",
        executable.display()
    );

    let workspace_root = std::env::current_dir().expect("workspace root");
    let input_bundle = br#"{"input":"real-codex-memory-e2e"}"#.to_vec();
    let dispatch_id = "real-codex-memory-e2e-dispatch";
    let envelope = DispatchEnvelope {
        run_id: "real-codex-memory-e2e-run".to_owned(),
        step_id: "step-001".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        dispatch_id: dispatch_id.to_owned(),
        input_bundle_sha256: hex::encode(Sha256::digest(&input_bundle)),
        session_strategy: NativeSessionStrategy::CreateNew as i32,
        ..Default::default()
    };
    let mut driver = CodexAppServerDriver::new(CodexAppServerConfig::new(executable));
    let probe = driver
        .probe(&ProbeHarnessRequest {
            adapter_id: CODEX_ADAPTER_ID.to_owned(),
            expected_protocol_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
            ..Default::default()
        })
        .await
        .expect("real Codex probe should return a result");
    assert_eq!(probe.readiness, HarnessReadiness::Ready as i32);
    assert_eq!(
        probe
            .observed_protocol
            .as_ref()
            .map(|value| value.native_executable_version.as_str()),
        Some(
            codex_protocol_fingerprint()
                .native_executable_version
                .as_str()
        )
    );

    let delivery = driver
        .send_dispatch(
            &envelope,
            &ResolvedDispatchMaterial {
                canonical_input_bundle: input_bundle,
                prompt: "Reply exactly with EGOPULSE_CODEX_MEMORY_E2E_OK and do not call tools."
                    .to_owned(),
                workspace_root,
                model: Some("gpt-5.6-sol".to_owned()),
            },
        )
        .await
        .expect("real Codex turn should be accepted");
    assert!(!delivery.native_session_ref.is_empty());

    let mut terminal_seen = false;
    for _ in 0..600 {
        if let Some(event) = driver
            .next_event(&envelope)
            .await
            .expect("real Codex event stream should remain readable")
        {
            if event.criticality == ObservationCriticality::Terminal {
                terminal_seen = true;
                break;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    assert!(
        terminal_seen,
        "real Codex turn should reach a terminal event"
    );
    let terminal = driver
        .take_terminal_output_candidate(&envelope)
        .await
        .expect("real Codex terminal candidate extraction should succeed")
        .expect("real Codex should produce an agent message candidate");
    assert_eq!(terminal.content, b"EGOPULSE_CODEX_MEMORY_E2E_OK");

    let path = std::env::temp_dir().join(format!("egopulse-codex-memory-{}.db", Uuid::now_v7()));
    let _store = TestStore(path.clone());
    let authority = Arc::new(Mutex::new(
        MemoryAuthority::open(MemoryAuthorityConfig {
            database_path: path,
            store_epoch: Uuid::now_v7().to_string(),
            key: SqlCipherKey::new([0x6b; 32]),
        })
        .expect("open Memory Authority"),
    ));
    let registry = MemoryCandidateProducerRegistry::new(
        Arc::clone(&authority),
        [MemoryCandidateProducerBinding::new(
            "harness:codex",
            "harness:codex",
            MemoryPrincipalKind::Harness,
            "scope:founder",
        )
        .expect("valid Codex producer binding")],
    )
    .expect("compose Codex producer registry");
    let codex_handle = registry
        .bind_producer("harness:codex")
        .expect("bind fixed Codex producer handle");

    // The conversion below is intentionally explicit test/application
    // policy. The Codex driver only returns a terminal output candidate; it
    // does not choose a Memory scope, producer identity or authority state.
    let receipt = codex_handle
        .submit_proposal(&MemoryCandidateProposal {
            memory_id: "memory:codex-e2e".to_owned(),
            content: String::from_utf8(terminal.content).expect("candidate is UTF-8"),
            source_ref: format!("harness:{}", terminal.native_completion_ref),
            idempotency_key: format!("memory-candidate:{dispatch_id}"),
        })
        .expect("Codex candidate should enter Memory Authority");
    assert_eq!(receipt.state, MemoryState::Candidate);

    let founder = AuthenticatedMemoryPrincipal {
        kind: MemoryPrincipalKind::Founder,
        principal_id: "founder:e2e".to_owned(),
        authenticated: true,
    };
    let accepted = authority
        .lock()
        .expect("Memory Authority lock")
        .accept(
            &GovernMemory {
                memory_id: "memory:codex-e2e".to_owned(),
                expected_revision: 1,
                evidence_ref: "evidence:codex-memory-e2e".to_owned(),
                idempotency_key: Uuid::now_v7().to_string(),
            },
            &founder,
        )
        .expect("Founder acceptance should remain a separate write");
    assert_eq!(accepted.state, MemoryState::Accepted);
    let record = authority
        .lock()
        .expect("Memory Authority lock")
        .get("memory:codex-e2e")
        .expect("read Memory Authority")
        .expect("accepted memory exists");
    assert_eq!(record.state, MemoryState::Accepted);
    assert_eq!(
        record.source_ref,
        format!("harness:{}", terminal.native_completion_ref)
    );
}
