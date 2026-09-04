#![forbid(unsafe_code)]

//! Authenticated, user-configured production composition evidence for G4-04.
//!
//! This test is intentionally ignored: it starts the locally installed Codex
//! app-server and therefore depends on a user-owned Codex login/API key. The
//! Task activation is seeded through Task Authority's test-only transition
//! guard; no client-facing activation bypass is introduced.

use egopulse_agentosd::{
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, ProductionBootstrapConfig,
};
use egopulse_codex_adapter::CODEX_CAPABILITY_PROFILE_ID;
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, TaskCommand as DomainTaskCommand, TaskSnapshot,
        TaskStatus, task_command,
    },
    verification::v1::{CheckerAssuranceClass, CheckerProfile},
};
use egopulse_verification_authority::canonical_checker_profile_digest;
use prost_types::Timestamp;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

const RUN_ID: &str = "run:g4-04-production";
const ATTEMPT_ID: &str = "attempt:g4-04-production";
const DISPATCH_ID: &str = "dispatch:g4-04-production";
const INPUT_SNAPSHOT_ID: &str = "input-snapshot-001";
const TARGET_SCOPE_REF: &str = "target-scope-001";
const WORKSPACE_REF: &str = "workspace-001";

struct ActivationOnlyTransitionGuard {
    run_id: String,
}

impl TaskTransitionGuard for ActivationOnlyTransitionGuard {
    fn validate(
        &self,
        command: &DomainTaskCommand,
        current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        let Some(task_command::Command::ActivateTask(activate)) = command.command.as_ref() else {
            return Err(TransitionGuardRejection::UnverifiedReference);
        };
        if current.status != TaskStatus::Ready as i32
            || activate.expected_revision != current.revision
            || activate.work_revision != current.work_revision
            || activate.run_id != self.run_id
        {
            return Err(TransitionGuardRejection::StateConflict);
        }
        Ok(TransitionAuthorization {
            evidence_refs: vec!["g4-04-test:founder-reviewed-activation".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

struct ConfiguredCreateGuard {
    inner: ConfiguredTaskCreationGuard,
}

impl TaskCreationGuard for ConfiguredCreateGuard {
    fn validate(
        &self,
        command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        self.inner.validate(command)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("egopulse-g4-04-production-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create G4-04 temporary root");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let temp = env::temp_dir();
        assert!(self.0.starts_with(&temp));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn contract(contract_id: &str, byte: u8) -> ContractReference {
    ContractReference {
        contract_id: contract_id.to_owned(),
        version: "v1".to_owned(),
        sha256: hex::encode([byte; 32]),
    }
}

fn acceptance_checker_profile() -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: "checker-profile:g4-04".to_owned(),
        revision: 0,
        status: 0,
        checker_id: "deterministic:g4-04-acceptance".to_owned(),
        checker_version: "v1".to_owned(),
        input_contract_ref: Some(contract("verification-input", 0x01)),
        output_contract_ref: Some(contract("verification-output", 0x02)),
        supported_criterion_types: vec!["criterion:g4-04".to_owned()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(contract("verification-sandbox", 0x03)),
        tool_policy_ref: Some(contract("verification-tool-policy", 0x04)),
        data_egress_policy_ref: Some(contract("verification-egress-policy", 0x05)),
        timeout_ms: 2_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![
            "artifact:harness-output:dispatch:g4-04-production".to_owned(),
        ],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

fn reference_value(reference: &ContractReference) -> Value {
    serde_json::json!({
        "contract_id": reference.contract_id,
        "version": reference.version,
        "sha256": reference.sha256,
    })
}

fn metadata(command_id: &str, idempotency_key: &str, correlation_id: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        idempotency_scope: "g4-04-production-test".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_777_073_600,
            nanos: 0,
        }),
        correlation_id: correlation_id.to_owned(),
        causation_id: None,
    }
}

fn seal(mut command: DomainTaskCommand) -> DomainTaskCommand {
    let digest = canonical_request_digest(&command).expect("canonical Task digest");
    match command.command.as_mut() {
        Some(task_command::Command::CreateTask(value)) => {
            value
                .meta
                .as_mut()
                .expect("create metadata")
                .request_digest_sha256 = digest;
        }
        Some(task_command::Command::ActivateTask(value)) => {
            value
                .meta
                .as_mut()
                .expect("activate metadata")
                .request_digest_sha256 = digest;
        }
        _ => panic!("unexpected Task command in G4-04 fixture"),
    }
    command
}

fn key_from_env(name: &str) -> [u8; 32] {
    let raw = env::var(name).unwrap_or_else(|_| panic!("{name} must be set for live G4-04"));
    let bytes = hex::decode(raw).expect("hex authority key");
    bytes.try_into().expect("32-byte authority key")
}

fn set_string(root: &mut Value, pointer: &str, value: impl Into<String>) {
    *root
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("missing config pointer {pointer}")) =
        Value::String(value.into());
}

fn set_value(root: &mut Value, pointer: &str, value: Value) {
    *root
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("missing config pointer {pointer}")) = value;
}

fn user_config(root: &TempRoot, input_digest: &str, codex_executable: &Path) -> PathBuf {
    let template = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
        .join("agentos-config.example.json");
    let mut config: Value = serde_json::from_str(
        &fs::read_to_string(template).expect("read production config template"),
    )
    .expect("parse production config template");

    let data_root = root.path().join("data");
    let bundle_root = data_root.join("input-bundles");
    let workspace_root = root.path().join("workspaces");
    let workspace = workspace_root.join(WORKSPACE_REF);
    fs::create_dir_all(&bundle_root).expect("create input bundle root");
    fs::create_dir_all(&workspace).expect("create workspace root");
    let bundle = br#"{"prompt":"Reply with exactly EGO_PULSE_G4_04_OK and do not use tools."}"#;
    fs::write(bundle_root.join("bundle.json"), bundle).expect("write input bundle");

    for store in [
        "task",
        "memory",
        "artifact",
        "verification",
        "policy",
        "verdict",
        "adapter",
        "collaboration",
    ] {
        set_string(
            &mut config,
            &format!("/stores/{store}/database_path"),
            data_root.join(format!("{store}.db")).display().to_string(),
        );
        let epoch = if store == "task" {
            "g4-04-task-seed".to_owned()
        } else {
            format!("g4-04-{}-{}", store, Uuid::now_v7())
        };
        set_string(&mut config, &format!("/stores/{store}/store_epoch"), epoch);
    }
    set_string(
        &mut config,
        "/stores/artifact/blob_root",
        data_root.join("artifact-blobs").display().to_string(),
    );
    set_string(
        &mut config,
        "/task_guard/allowed_input_snapshot_ids/0",
        INPUT_SNAPSHOT_ID,
    );
    set_string(
        &mut config,
        "/task_guard/allowed_target_scope_refs/0",
        TARGET_SCOPE_REF,
    );
    set_string(
        &mut config,
        "/artifact/allowed_workspace_refs/0",
        WORKSPACE_REF,
    );
    // The collector's claim acceptance contract must be the same reviewed
    // contract carried by the Task; the Verification resolver rejects any
    // cross-authority drift here.
    set_string(
        &mut config,
        "/artifact/allowed_claim_acceptance_contract_refs/0/contract_id",
        "replace-acceptance-contract",
    );
    set_string(
        &mut config,
        "/artifact/allowed_claim_acceptance_contract_refs/0/sha256",
        "cc".repeat(32),
    );
    set_string(
        &mut config,
        "/codex/input_bundle_root",
        bundle_root.display().to_string(),
    );
    set_string(
        &mut config,
        "/codex/workspace_root",
        workspace_root.display().to_string(),
    );
    set_string(
        &mut config,
        "/codex/codex_executable",
        codex_executable.display().to_string(),
    );
    set_string(&mut config, "/codex/workflow/run_id", RUN_ID);
    set_string(&mut config, "/codex/workflow/attempt_id", ATTEMPT_ID);
    set_string(&mut config, "/codex/workflow/dispatch_id", DISPATCH_ID);
    set_string(
        &mut config,
        "/codex/workflow/capability_profile_ref/contract_id",
        CODEX_CAPABILITY_PROFILE_ID,
    );
    set_string(
        &mut config,
        "/codex/workflow/capability_profile_ref/version",
        "v1",
    );
    set_string(
        &mut config,
        "/codex/workflow/capability_profile_ref/sha256",
        "f".repeat(64),
    );
    set_string(&mut config, "/codex/workflow/workspace_ref", WORKSPACE_REF);
    set_string(
        &mut config,
        "/codex/workflow/plan/step/input_bundle_ref",
        "bundle.json",
    );
    set_string(
        &mut config,
        "/codex/workflow/material/input_bundle_sha256",
        input_digest,
    );
    set_string(
        &mut config,
        "/identity/principal_id",
        "local-user:g4-04-test",
    );
    set_string(&mut config, "/identity/task_kind", "CollaborationControl");
    set_string(
        &mut config,
        "/founder/allowed_founder_principal_ids/0",
        "local-user:g4-04-test",
    );
    set_value(
        &mut config,
        "/memory_retrieval/worker_executable",
        Value::String("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_owned()),
    );
    set_string(
        &mut config,
        "/memory_retrieval/working_directory",
        root.path().display().to_string(),
    );
    set_string(
        &mut config,
        "/memory_retrieval/environment_overrides/PYTHONPATH",
        root.path().display().to_string(),
    );

    let profile = acceptance_checker_profile();
    let review = serde_json::json!({
        "schema_version": 1,
        "id": "review:g4-04-acceptance",
        "scope": "g4-04",
        "diff_hash": "a".repeat(64),
        "finding_count": 0,
        "highest_severity": Value::Null,
        "parse_status": "structured",
        "findings": [],
        "reviewer": "g4-04-acceptance-checker",
        "engine_version": "g4-04-v1",
        "review_mode": "deterministic_acceptance"
    });
    let review_bytes = serde_json::to_vec(&review).expect("serialize acceptance review");
    let checker_script = root.path().join("g4-04-acceptance-checker.ps1");
    let review_text = String::from_utf8(review_bytes.clone()).expect("review JSON UTF-8");
    fs::write(
        &checker_script,
        format!(
            "[Console]::Out.Write('{}')",
            review_text.replace('\'', "''")
        ),
    )
    .expect("write deterministic acceptance checker");
    let raw_output_address = hex::encode(Sha256::digest(&review_bytes));
    let checker_executable =
        PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    let profile_ref = ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    };
    set_value(
        &mut config,
        "/verification/criteria/0/criterion_id",
        Value::String("criterion:g4-04".to_owned()),
    );
    set_value(
        &mut config,
        "/verification/criteria/0/checker_profile_ids",
        serde_json::json!([profile.checker_profile_id.clone()]),
    );
    config["verification_worker"] = serde_json::json!({
        "handoff": {
            "claim_id": "claim:harness-output-captured:dispatch:g4-04-production",
            "claim_semantic_profile_ref": reference_value(&contract("replace-claim-semantic-profile", 0x22)),
            "criterion_ids": ["criterion:g4-04"],
            "checker_profile_refs": [reference_value(&profile_ref)]
        },
        "checker_profile": {
            "checker_profile_id": profile.checker_profile_id,
            "revision": 0,
            "status": 1,
            "checker_id": profile.checker_id,
            "checker_version": profile.checker_version,
            "input_contract_ref": profile.input_contract_ref.as_ref().map(reference_value),
            "output_contract_ref": profile.output_contract_ref.as_ref().map(reference_value),
            "supported_criterion_types": profile.supported_criterion_types,
            "assurance_class": profile.assurance_class,
            "sandbox_profile_ref": profile.sandbox_profile_ref.as_ref().map(reference_value),
            "tool_policy_ref": profile.tool_policy_ref.as_ref().map(reference_value),
            "data_egress_policy_ref": profile.data_egress_policy_ref.as_ref().map(reference_value),
            "timeout_ms": profile.timeout_ms,
            "network_allowed": profile.network_allowed,
            "profile_digest_sha256": profile.profile_digest_sha256,
            "attestation_evidence_artifact_ids": profile.attestation_evidence_artifact_ids,
            "attested_at": Value::Null
        },
        "checker_executable": checker_executable.display().to_string(),
        "checker_arguments": ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", checker_script.display().to_string()],
        "working_directory": root.path().display().to_string(),
        "checker_request_hex": "7b7d",
        "mapper": {
            "criterion_id": "criterion:g4-04",
            "requirement": 1,
            "checker_profile_ref": reference_value(&profile_ref),
            "expected_scope": "g4-04",
            "expected_diff_hash": "a".repeat(64),
            "expected_reviewer": "g4-04-acceptance-checker",
            "expected_engine_version": "g4-04-v1",
            "expected_review_mode": "deterministic_acceptance",
            "positive_acceptance": true,
            "failure_threshold": 2,
            "raw_output_artifact_id": "artifact:harness-output:dispatch:g4-04-production",
            "raw_output_address": {
                "algorithm": 1,
                "digest": raw_output_address,
                "byte_length": review_bytes.len()
            },
            "finding_evidence": {}
        },
        "verification_run_id_prefix": "worker-run-",
        "verification_artifact_id_prefix": "worker-artifact-",
        "execution_id_prefix": "worker-execution-",
        "tool_receipt_artifact_ids": [],
        "model_call_receipt_artifact_ids": [],
        "checker_timeout_ms": 2_000,
        "checker_output_limit": 64 * 1024
    });

    let path = root.path().join("agentos-config.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&config).expect("serialize production config"),
    )
    .expect("write production config");
    path
}

fn seed_activation(root: &TempRoot) -> (String, u64, u64) {
    let task_db = root.path().join("data").join("task.db");
    let creation_guard = ConfiguredTaskCreationGuard::new(ConfiguredTaskCreationGuardConfig {
        allowed_work_types: BTreeSet::from(["governed_repository_change".to_owned()]),
        allowed_input_snapshot_ids: BTreeSet::from([INPUT_SNAPSHOT_ID.to_owned()]),
        allowed_target_scope_refs: BTreeSet::from([TARGET_SCOPE_REF.to_owned()]),
        acceptance_contract_ref: contract("replace-acceptance-contract", 0xcc),
        budget_profile_ref: contract("replace-budget-profile", 0xdd),
    })
    .expect("production creation guard");
    let mut authority = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: task_db,
            store_epoch: "g4-04-task-seed".to_owned(),
            key: SqlCipherKey::new(key_from_env("EGOPULSE_TASK_KEY_HEX")),
        },
        ConfiguredCreateGuard {
            inner: creation_guard,
        },
        ActivationOnlyTransitionGuard {
            run_id: RUN_ID.to_owned(),
        },
    )
    .expect("open Task Authority for activation seed");

    let create = seal(DomainTaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata("g4-04-create", "g4-04-create", "g4-04")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: INPUT_SNAPSHOT_ID.to_owned(),
            target_scope_ref: TARGET_SCOPE_REF.to_owned(),
            acceptance_contract_ref: Some(contract("replace-acceptance-contract", 0xcc)),
            budget_profile_ref: Some(contract("replace-budget-profile", 0xdd)),
        })),
    });
    let founder = AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "local-user:g4-04-test".to_owned(),
        authenticated: true,
    };
    let created = authority
        .execute(&create, &founder)
        .expect("create seeded Task");
    let task = match created.outcome.expect("created Task outcome") {
        egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(
            task,
        ) => task,
        other => panic!("unexpected create outcome: {other:?}"),
    };
    let activate = seal(DomainTaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(metadata("g4-04-activate", "g4-04-activate", "g4-04")),
            task_id: task.task_id,
            expected_revision: task.revision,
            work_revision: task.work_revision,
            run_id: RUN_ID.to_owned(),
        })),
    });
    let system = AuthenticatedPrincipal {
        kind: PrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:production".to_owned(),
        authenticated: true,
    };
    let activated = authority
        .execute(&activate, &system)
        .expect("activate seeded Task");
    let activated_task = match activated.outcome.expect("activated Task outcome") {
        egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result::Outcome::Task(
            task,
        ) => task,
        other => panic!("unexpected activate outcome: {other:?}"),
    };
    assert!(activated.committed_event.is_some());
    (
        activated_task.task_id,
        activated_task.revision,
        activated_task.work_revision,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a user-owned authenticated Codex app-server"]
async fn user_configured_production_runner_completes_real_codex_dispatch() {
    let Some(codex_executable) = env::var_os("EGOPULSE_CODEX_NATIVE_EXE") else {
        eprintln!("EGOPULSE_CODEX_NATIVE_EXE is not set; skipping live G4-04 evidence");
        return;
    };
    let codex_executable = PathBuf::from(codex_executable);
    let root = TempRoot::new();
    eprintln!("g4-04: temp root created");
    let bundle = br#"{"prompt":"Reply with exactly EGO_PULSE_G4_04_OK and do not use tools."}"#;
    let input_digest = hex::encode(Sha256::digest(bundle));
    let config_path = user_config(&root, &input_digest, &codex_executable);
    eprintln!("g4-04: user config written");
    seed_activation(&root);
    eprintln!("g4-04: task activated");

    let mut providers = ProductionBootstrapConfig::from_user_file(&config_path)
        .expect("load user-owned production config")
        .build()
        .expect("build production providers");
    eprintln!("g4-04: production providers built");
    let runner = providers
        .harness_dispatch_runner
        .take()
        .expect("production Codex runner");
    let verification_worker = providers
        .verification_worker
        .take()
        .expect("production Verification worker");
    eprintln!("g4-04: runner and worker taken");

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut terminal_dispatch_ids = Vec::new();
    let mut terminal_seen = false;
    while Instant::now() < deadline {
        eprintln!("g4-04: dispatch cycle");
        let report = tokio::time::timeout(Duration::from_secs(45), runner.run_once())
            .await
            .expect("production runner cycle timed out")
            .expect("production runner cycle");
        terminal_dispatch_ids.extend(report.terminal_dispatch_ids);
        if report.terminal_observations > 0 {
            assert_eq!(terminal_dispatch_ids, vec![DISPATCH_ID.to_owned()]);
            assert_eq!(report.terminal_output_candidates_seen, 1);
            assert_eq!(report.terminal_output_candidates_receipted, 1);
            assert_eq!(report.terminal_output_candidates_held, 0);
            assert_eq!(report.task_evidence_intakes, 1);
            terminal_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        terminal_seen,
        "Codex production dispatch did not reach a terminal observation"
    );
    eprintln!("g4-04: terminal dispatch observed");

    let verification = verification_worker
        .run_once()
        .await
        .expect("run production Verification worker");
    assert!(matches!(
        verification,
        egopulse_agentosd::VerificationWorkerCycleResult::Completed {
            execution_replayed: false,
            write_back_replayed: false,
            ..
        }
    ));
    eprintln!("g4-04: verification completed");

    let settlement = tokio::time::timeout(Duration::from_secs(20), runner.run_once())
        .await
        .expect("production return settlement timed out")
        .expect("production return settlement");
    assert_eq!(settlement.terminal_observations, 0);
    assert_eq!(settlement.return_settlements, 1);
    eprintln!("g4-04: return settlement completed");
}
