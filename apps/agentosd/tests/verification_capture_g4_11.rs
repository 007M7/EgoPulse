#![forbid(unsafe_code)]

//! Application-level closure evidence for a configured checker's output
//! capture: a non-repository Verification worker is started from a user JSON
//! configuration, its checker output is sealed by the real Artifact Authority
//! through the governed collector, the resolver validates collector,
//! execution, profile and transformation, and the result is written back and
//! read again from the Verification Authority.
//!
//! Task activation is seeded through Task Authority's test-only transition
//! guard, as in the other production composition tests. Every store is opened
//! by its real owner; no test writes owner tables directly.

use egopulse_agentosd::{
    ArtifactAuthorityReferenceSource, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ProductionBootstrapConfig,
};
use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactPrincipalKind,
    ArtifactSqlCipherKey as ArtifactKey, AuthenticatedArtifactPrincipal,
    canonical_artifact_set_manifest, canonical_request_digest as artifact_request_digest,
    content_address,
};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization,
    TransitionGuardRejection, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus,
        ArtifactStatus, Claim, ClaimSourceType, ClaimStatus, ContentAddress,
        CreateArtifactSetCommand, Evidence, EvidenceProducerClass, EvidenceRelation,
        EvidenceStatus, IntegrityStatus, LineageBinding, ProducerIdentity, ProposeClaimCommand,
        Provenance, RecordEvidenceCommand, SealArtifactCommand, SealArtifactSetCommand,
        StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, SubmitTaskEvidenceCommand, TaskCommand,
        TaskSnapshot, TaskStatus, task_command, task_command_result,
    },
    verification::v1::{
        CheckerAssuranceClass, CheckerProfile, CriterionRequirement, VerificationArtifact,
        VerificationConclusion,
    },
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, CriterionPolicySnapshot, VerificationAuthority,
    VerificationAuthorityConfig, VerificationSqlCipherKey, canonical_checker_profile_digest,
    checker_output_execution_ref,
};
use prost_types::Timestamp;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const WORKSPACE_REF: &str = "workspace:g4-11";
const RUN_ID: &str = "run:replace-me";
const CHECKER_ID: &str = "g4-11-acceptance-checker";
const CHECKER_VERSION: &str = "1";
const REVIEW_SCOPE: &str = "staged";
const REVIEW_MODE: &str = "deterministic_acceptance";
const COLLECTOR_PRINCIPAL: &str = "collector:checker-output";
const ARTIFACT_AUTHORITY_PRINCIPAL: &str = "authority:artifact";
const RAW_OUTPUT_TYPE: &str = "verification-raw-output";
const RETENTION_PROFILE: &str = "verification-records";
const TRANSFORMATION: &str = "checker-output-capture";
const CLAIM_SEMANTIC: &str = "claim-semantic:g4-11";
const ACCEPTANCE_CONTRACT: &str = "acceptance-contract:g4-11";
const INPUT_TYPE: &str = "repository-input";
const INPUT_TRANSFORMATION: &str = "repository-capture";
const EVIDENCE_PROFILE: &str = "verification-evidence";
const DEPLOYMENT_TYPE: &str = "checker-profile-attestation";
const DEPLOYMENT_TRANSFORMATION: &str = "checker-profile-deployment";
/// The contracts this installation admitted. The daemon's guard and the
/// test's own seeding guard are built from these, so both agree by
/// construction.
const ALLOWED_TYPES: &[&str] = &[INPUT_TYPE, RAW_OUTPUT_TYPE, DEPLOYMENT_TYPE];
const ALLOWED_TRANSFORMATIONS: &[&str] = &[
    INPUT_TRANSFORMATION,
    TRANSFORMATION,
    DEPLOYMENT_TRANSFORMATION,
];
/// One verification environment inside a scenario: the identities a Task's
/// artifact set, its criterion and its checker profile are created under. A
/// second case in the same environment is a second independent task, not a
/// second cycle of the first.
struct Case {
    suffix: String,
    run_id: String,
    criterion: String,
    profile: String,
    baseline: String,
    output: String,
    artifact_set: String,
    claim: String,
    evidence: String,
}

impl Case {
    fn first() -> Self {
        Self::suffixed("", RUN_ID)
    }

    fn second() -> Self {
        Self::suffixed("-2", "run:g4-11-2")
    }

    fn suffixed(suffix: &str, run_id: &str) -> Self {
        Self {
            suffix: suffix.to_owned(),
            run_id: run_id.to_owned(),
            criterion: format!("criterion:g4-11{suffix}"),
            profile: format!("checker-profile:g4-11{suffix}"),
            baseline: format!("g4-11-baseline{suffix}"),
            output: format!("g4-11-harness-output{suffix}"),
            artifact_set: format!("artifact-set:g4-11{suffix}"),
            claim: format!("claim:g4-11{suffix}"),
            evidence: format!("evidence:g4-11{suffix}"),
        }
    }
}
const ARTIFACT_EPOCH: &str = "g4-11-artifact";
const VERIFICATION_EPOCH: &str = "g4-11-verification";
const TASK_EPOCH: &str = "g4-11-task";

fn reference(contract_id: &str) -> ContractReference {
    ContractReference {
        contract_id: contract_id.to_owned(),
        version: "v1".to_owned(),
        sha256: hex::encode(Sha256::digest(contract_id.as_bytes())),
    }
}

fn reference_value(contract_id: &str) -> Value {
    let reference = reference(contract_id);
    serde_json::json!({
        "contract_id": reference.contract_id,
        "version": reference.version,
        "sha256": reference.sha256,
    })
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let root = env::temp_dir().join(format!("egopulse-g4-11-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create G4-11 temporary root");
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

/// The keys each scenario runs with. The configuration keeps reading its keys
/// through the same environment-variable indirection as a real installation;
/// the spawner in this file supplies the test's own values to a child process,
/// so the suite also runs where no installation has set them.
fn test_keys() -> Vec<(&'static str, String)> {
    [
        ("EGOPULSE_TASK_KEY_HEX", 0x11u8),
        ("EGOPULSE_MEMORY_KEY_HEX", 0x12),
        ("EGOPULSE_ARTIFACT_KEY_HEX", 0x13),
        ("EGOPULSE_VERIFICATION_KEY_HEX", 0x14),
        ("EGOPULSE_POLICY_KEY_HEX", 0x15),
        ("EGOPULSE_VERDICT_KEY_HEX", 0x16),
        ("EGOPULSE_ADAPTER_KEY_HEX", 0x17),
        ("EGOPULSE_COLLABORATION_KEY_HEX", 0x18),
        ("EGOPULSE_READ_MODEL_KEY_HEX", 0x19),
        ("EGOPULSE_TOKEN_MAC_KEY_HEX", 0x1a),
    ]
    .into_iter()
    .map(|(name, byte)| (name, hex::encode([byte; 32])))
    .collect()
}

/// Every scenario below opens real stores and composes the daemon from a JSON
/// configuration, so each one runs in its own child process with its own keys:
/// no scenario can see another's environment, and the suite runs without a
/// machine-wide installation.
#[test]
fn g4_11_capture_scenarios_run_in_isolated_processes() {
    // Each row: the scenario, and the daemon event fields it must have written
    // to stderr (`None` means it must have written no failure event at all).
    let scenarios: [(&str, &[&str]); 7] = [
        (
            "scenario_capture_seals_the_checker_output_and_reads_back",
            &["NO_FAILURE_EVENT"],
        ),
        (
            "scenario_stopped_checker_records_its_declared_code",
            &[
                "\"event\":\"verification_checker_failed\"",
                "\"safe_failure_code\":\"CHECKER_CRASHED\"",
                "\"checker_declared_code\":\"budget_exceeded\"",
                "\"captured_artifact_id\":\"artifact:verification-output:",
            ],
        ),
        (
            "scenario_unmappable_output_is_recorded_without_passing",
            &[
                "\"safe_failure_code\":\"CHECKER_OUTPUT_UNTRUSTED\"",
                "\"captured_artifact_id\":\"artifact:verification-output:",
            ],
        ),
        (
            "scenario_refused_capture_blocks_a_positive_result",
            &[
                "\"safe_failure_code\":\"CHECKER_OUTPUT_CAPTURE_REFUSED\"",
                "\"capture_failure_code\":\"CHECKER_OUTPUT_CAPTURE_TOO_LARGE\"",
                "\"captured_artifact_id\":null",
            ],
        ),
        (
            "scenario_two_independent_tasks_are_served",
            &["NO_FAILURE_EVENT"],
        ),
        (
            "scenario_fabricated_capture_references_are_rejected",
            &["NO_EXECUTION_FAILURE_EVENT"],
        ),
        (
            "scenario_zero_byte_output_cites_nothing",
            &[
                "\"safe_failure_code\":\"CHECKER_OUTPUT_UNTRUSTED\"",
                "\"capture_failure_code\":\"CHECKER_OUTPUT_CAPTURE_EMPTY\"",
                "\"captured_artifact_id\":null",
            ],
        ),
    ];
    let executable = env::current_exe().expect("current test executable");
    for (scenario, expected) in scenarios {
        let mut command = Command::new(&executable);
        command.args(["--exact", scenario, "--ignored", "--nocapture"]);
        for (name, value) in test_keys() {
            command.env(name, value);
        }
        let output = command.output().expect("spawn scenario");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The exit status is the result; the stdout text alone is not.
        assert!(
            output.status.success(),
            "scenario {scenario} exited with {status}: {stdout}\n{stderr}",
            status = output.status
        );
        assert!(
            stdout.contains("1 passed; 0 failed"),
            "scenario {scenario} did not report one passing test: {stdout}"
        );
        for needle in expected {
            if *needle == "NO_FAILURE_EVENT" {
                assert!(
                    !stderr.contains("verification_checker_failed"),
                    "scenario {scenario} reported a failure it did not have: {stderr}"
                );
                continue;
            }
            if *needle == "NO_EXECUTION_FAILURE_EVENT" {
                // A rejection is not an execution failure: the scenario
                // asserts the hold itself, so only a completed pass would be
                // wrong here.
                assert!(
                    !stderr.contains("\"event\":\"verification_checker_failed\""),
                    "scenario {scenario} reported an execution failure it did not have: {stderr}"
                );
                continue;
            }
            assert!(
                stderr.contains(needle),
                "scenario {scenario} did not report {needle}: {stderr}"
            );
        }
    }
}

fn key_from_env(name: &str) -> [u8; 32] {
    let raw = env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    hex::decode(raw)
        .expect("hex key")
        .try_into()
        .expect("32-byte key")
}

/// The lineage a scenario's artifact set is bound to. The Task seed uses the
/// same values, so the sealed inputs and the Task agree.
fn expected_lineage(case: &Case) -> LineageBinding {
    LineageBinding {
        task_id: "pending".to_owned(),
        task_revision: 1,
        work_revision: 1,
        run_id: case.run_id.clone(),
        run_revision: 1,
        step_id: "step:g4-11".to_owned(),
        step_revision: 1,
        attempt_id: "attempt:g4-11".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch:g4-11".to_owned(),
        fencing_token: 1,
    }
}

fn subject_digest(case: &Case) -> String {
    artifact_set(&expected_lineage(case), case).1.digest
}

fn metadata(command_id: &str, key: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: key.to_owned(),
        idempotency_scope: "g4-11-test".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }),
        correlation_id: key.to_owned(),
        causation_id: None,
    }
}

fn artifact_principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn execute_artifact(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    kind: artifact_command::Command,
    principal: &AuthenticatedArtifactPrincipal,
) {
    let mut command = ArtifactCommand {
        command: Some(kind),
    };
    let digest = artifact_request_digest(&command).expect("canonical artifact command");
    match command.command.as_mut().expect("command") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        _ => panic!("unexpected artifact command"),
    }
    .expect("metadata")
    .request_digest_sha256 = digest;
    let result = authority
        .execute(&command, principal)
        .expect("artifact command");
    assert!(
        result.committed || result.replayed,
        "artifact command rejected: {result:?}"
    );
}

fn guard_config() -> ConfiguredArtifactAdmissionGuardConfig {
    ConfiguredArtifactAdmissionGuardConfig {
        allowed_workspace_refs: BTreeSet::from([WORKSPACE_REF.to_owned()]),
        allowed_artifact_type_refs: ALLOWED_TYPES.iter().map(|id| reference(id)).collect(),
        allowed_transformation_contract_refs: ALLOWED_TRANSFORMATIONS
            .iter()
            .map(|id| reference(id))
            .collect(),
        allowed_retention_profile_refs: vec![reference(RETENTION_PROFILE)],
        allowed_claim_semantic_profile_refs: vec![reference(CLAIM_SEMANTIC)],
        allowed_claim_acceptance_contract_refs: vec![reference(ACCEPTANCE_CONTRACT)],
        allowed_evidence_profile_refs: vec![reference(EVIDENCE_PROFILE)],
    }
}

fn open_artifact_authority(root: &Path) -> ArtifactAuthority<ConfiguredArtifactAdmissionGuard> {
    ArtifactAuthority::open(
        ArtifactAuthorityConfig {
            database_path: root.join("data").join("artifact.db"),
            blob_root: root.join("data").join("artifact-blobs"),
            store_epoch: ARTIFACT_EPOCH.to_owned(),
            key: ArtifactKey::new(key_from_env("EGOPULSE_ARTIFACT_KEY_HEX")),
        },
        ConfiguredArtifactAdmissionGuard::new(guard_config()).expect("configured admission"),
    )
    .expect("open Artifact SQLCipher owner")
}

fn open_task_authority(root: &Path) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        egopulse_cognition_runtime::task_authority::TaskAuthorityConfig {
            database_path: root.join("data").join("task.db"),
            store_epoch: TASK_EPOCH.to_owned(),
            key: SqlCipherKey::new(key_from_env("EGOPULSE_TASK_KEY_HEX")),
        },
        AllowCreation,
        AllowActivation,
    )
    .expect("open Task SQLCipher owner")
}

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["g4-11-test:reviewed-creation".to_owned()],
        })
    }
}

/// Test-only transition guard: it admits the creation, activation and evidence
/// steps of the seeded work, and nothing else.
struct AllowActivation;

impl TaskTransitionGuard for AllowActivation {
    fn validate(
        &self,
        command: &TaskCommand,
        current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        let accepted = match command.command.as_ref() {
            Some(task_command::Command::ActivateTask(activate)) => {
                current.status == TaskStatus::Ready as i32
                    && activate.expected_revision == current.revision
                    && activate.work_revision == current.work_revision
                    && !activate.run_id.trim().is_empty()
            }
            // The returned artifact set is the one the checker reviews; the
            // test-only guard accepts the evidence step of the same work.
            Some(task_command::Command::SubmitTaskEvidence(submit)) => {
                current.status == TaskStatus::Active as i32
                    && submit.expected_revision == current.revision
                    && submit.work_revision == current.work_revision
                    && submit.artifact_set_id.starts_with("artifact-set:g4-11")
            }
            _ => false,
        };
        if !accepted {
            return Err(TransitionGuardRejection::StateConflict);
        }
        Ok(TransitionAuthorization {
            evidence_refs: vec!["g4-11-test:founder-reviewed-transition".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

fn signed_task_command(mut command: TaskCommand) -> TaskCommand {
    let digest = canonical_request_digest(&command).expect("task command digest");
    match command.command.as_mut().expect("task operation") {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        _ => panic!("unexpected task command"),
    }
    .expect("task metadata")
    .request_digest_sha256 = digest;
    command
}

fn task_snapshot(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("task outcome") {
        task_command_result::Outcome::Task(task) => task,
        other => panic!("unexpected task outcome: {other:?}"),
    }
}

fn profile(case: &Case) -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: case.profile.clone(),
        revision: 0,
        status: 0,
        checker_id: CHECKER_ID.to_owned(),
        checker_version: CHECKER_VERSION.to_owned(),
        input_contract_ref: Some(reference(ACCEPTANCE_CONTRACT)),
        output_contract_ref: Some(reference(TRANSFORMATION)),
        supported_criterion_types: vec![case.criterion.clone()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(reference("verification_read_only")),
        tool_policy_ref: Some(reference("verification_tools")),
        data_egress_policy_ref: Some(reference("local_only")),
        timeout_ms: 30_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![format!(
            "artifact:checker-profile-attestation:{}",
            case.profile
        )],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

/// The frozen artifact set the checker reviews: one repository baseline and one
/// captured harness output, plus the claim and evidence that bind them to the
/// Task lineage.
fn artifact_set(lineage: &LineageBinding, case: &Case) -> (ArtifactSet, ContentAddress) {
    let mut set = ArtifactSet {
        artifact_set_id: case.artifact_set.clone(),
        revision: 1,
        status: ArtifactSetStatus::Sealed as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec![case.baseline.clone(), case.output.clone()],
        claim_ids: vec![case.claim.clone()],
        evidence_ids: vec![case.evidence.clone()],
        canonical_manifest: None,
        ..ArtifactSet::default()
    };
    let manifest = content_address(&canonical_artifact_set_manifest(&set));
    set.canonical_manifest = Some(manifest.clone());
    (set, manifest)
}

/// Seals the input set through the real Artifact Authority and activates one
/// Task whose verification handoff the worker will consume.
struct Seeded {
    task_id: String,
    lineage: LineageBinding,
    /// The verification request this Task's handoff will create, derived the
    /// same way its owner derives it.
    request_id: String,
    /// The run id the configured worker will use for that request.
    run_id: String,
}

fn seed(root: &Path, case: &Case) -> Seeded {
    let mut task_authority = open_task_authority(root);
    let founder = AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "local-user:g4-11".to_owned(),
        authenticated: true,
    };
    let collaboration = AuthenticatedPrincipal {
        kind: PrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:g4-11".to_owned(),
        authenticated: true,
    };
    let created = task_snapshot(
        task_authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                        meta: Some(metadata(
                            &format!("g4-11-create{}", case.artifact_set),
                            &format!("g4-11-create{}", case.artifact_set),
                        )),
                        work_type: "governed_repository_change".to_owned(),
                        input_snapshot_id: "input:g4-11".to_owned(),
                        target_scope_ref: "scope:g4-11".to_owned(),
                        acceptance_contract_ref: Some(reference(ACCEPTANCE_CONTRACT)),
                        budget_profile_ref: Some(reference("budget:g4-11")),
                        work_capability_route: None,
                    })),
                }),
                &founder,
            )
            .expect("create Task"),
    );
    let active = task_snapshot(
        task_authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                        meta: Some(metadata(
                            &format!("g4-11-activate{}", case.artifact_set),
                            &format!("g4-11-activate{}", case.artifact_set),
                        )),
                        task_id: created.task_id.clone(),
                        expected_revision: created.revision,
                        work_revision: created.work_revision,
                        run_id: case.run_id.clone(),
                    })),
                }),
                &collaboration,
            )
            .expect("activate Task"),
    );
    let lineage = LineageBinding {
        task_id: created.task_id.clone(),
        task_revision: active.revision,
        work_revision: active.work_revision,
        run_id: case.run_id.clone(),
        run_revision: 1,
        step_id: "step:g4-11".to_owned(),
        step_revision: 1,
        attempt_id: "attempt:g4-11".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch:g4-11".to_owned(),
        fencing_token: 1,
    };

    let mut artifact = open_artifact_authority(root);
    let collector = artifact_principal(ArtifactPrincipalKind::GovernedCollector, "collector:input");
    let supervisor =
        artifact_principal(ArtifactPrincipalKind::AttemptSupervisor, "supervisor:input");
    let owner = artifact_principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        ARTIFACT_AUTHORITY_PRINCIPAL,
    );
    for (id, semantic, bytes) in [
        (
            case.baseline.as_str(),
            ArtifactSemanticClass::RepositoryBaseline,
            b"sealed repository baseline".as_slice(),
        ),
        (
            case.output.as_str(),
            ArtifactSemanticClass::CommandReceipt,
            b"captured harness output".as_slice(),
        ),
    ] {
        let content = content_address(bytes);
        artifact.put_blob(bytes, &content).expect("input blob");
        execute_artifact(
            &mut artifact,
            artifact_command::Command::StageArtifact(StageArtifactCommand {
                metadata: Some(metadata(
                    &format!("g4-11-stage-{id}"),
                    &format!("stage:{id}"),
                )),
                candidate: Some(ArtifactDescriptor {
                    artifact_id: id.to_owned(),
                    semantic_class: semantic as i32,
                    type_contract_ref: Some(reference(INPUT_TYPE)),
                    media_type: "application/json".to_owned(),
                    content: Some(content.clone()),
                    provenance: Some(Provenance {
                        lineage: Some(lineage.clone()),
                        producer: Some(producer(
                            ArtifactPrincipalKind::AttemptSupervisor,
                            &supervisor.principal_id,
                        )),
                        transformation_contract_ref: Some(reference(INPUT_TRANSFORMATION)),
                        workspace_ref: WORKSPACE_REF.to_owned(),
                        raw_source_ref: Some("g4-11-dispatch-source".to_owned()),
                        ..Default::default()
                    }),
                    sensitivity_class: "local-user-data".to_owned(),
                    retention_profile_ref: Some(reference(RETENTION_PROFILE)),
                    ..Default::default()
                }),
            }),
            &supervisor,
        );
        execute_artifact(
            &mut artifact,
            artifact_command::Command::SealArtifact(SealArtifactCommand {
                metadata: Some(metadata(&format!("g4-11-seal-{id}"), &format!("seal:{id}"))),
                artifact_id: id.to_owned(),
                expected_revision: 1,
                observed_content: Some(content),
            }),
            &owner,
        );
    }
    let statement_bytes =
        b"g4-11: the frozen artifact set satisfies the acceptance contract".to_vec();
    let statement = content_address(&statement_bytes);
    artifact
        .put_blob(&statement_bytes, &statement)
        .expect("claim statement blob");
    let coverage_bytes = b"g4-11 evidence coverage".to_vec();
    let coverage = content_address(&coverage_bytes);
    artifact
        .put_blob(&coverage_bytes, &coverage)
        .expect("evidence coverage blob");
    execute_artifact(
        &mut artifact,
        artifact_command::Command::ProposeClaim(ProposeClaimCommand {
            metadata: Some(metadata(
                &format!("g4-11-claim{}", case.artifact_set),
                &format!("claim{}", case.artifact_set),
            )),
            claim: Some(Claim {
                claim_id: case.claim.clone(),
                revision: 1,
                status: ClaimStatus::Proposed as i32,
                source_type: ClaimSourceType::CodeChange as i32,
                semantic_profile_ref: Some(reference(CLAIM_SEMANTIC)),
                lineage: Some(lineage.clone()),
                acceptance_contract_ref: Some(reference(ACCEPTANCE_CONTRACT)),
                subject_artifact_ids: vec![case.output.clone()],
                statement: Some(statement.clone()),
                proposer: Some(producer(
                    ArtifactPrincipalKind::GovernedCollector,
                    &collector.principal_id,
                )),
                ..Claim::default()
            }),
        }),
        &collector,
    );
    execute_artifact(
        &mut artifact,
        artifact_command::Command::RecordEvidence(RecordEvidenceCommand {
            metadata: Some(metadata(
                &format!("g4-11-evidence{}", case.artifact_set),
                &format!("evidence{}", case.artifact_set),
            )),
            evidence: Some(Evidence {
                evidence_id: case.evidence.clone(),
                revision: 1,
                status: EvidenceStatus::Recorded as i32,
                relation: EvidenceRelation::Supports as i32,
                claim_id: case.claim.clone(),
                artifact_ids: vec![case.baseline.clone(), case.output.clone()],
                lineage: Some(lineage.clone()),
                producer_class: EvidenceProducerClass::GovernedCollector as i32,
                integrity_status: IntegrityStatus::DigestVerified as i32,
                evidence_profile_ref: Some(reference(EVIDENCE_PROFILE)),
                coverage_descriptor: Some(coverage),
                producer: Some(producer(
                    ArtifactPrincipalKind::GovernedCollector,
                    &collector.principal_id,
                )),
                ..Evidence::default()
            }),
        }),
        &collector,
    );
    let (set, manifest) = artifact_set(&lineage, case);
    artifact
        .put_blob(&canonical_artifact_set_manifest(&set), &manifest)
        .expect("artifact set manifest blob");
    execute_artifact(
        &mut artifact,
        artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
            metadata: Some(metadata(
                &format!("g4-11-set{}", case.artifact_set),
                &format!("set{}", case.artifact_set),
            )),
            artifact_set: Some(set.clone()),
        }),
        &collector,
    );
    execute_artifact(
        &mut artifact,
        artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
            metadata: Some(metadata(
                &format!("g4-11-seal-set{}", case.artifact_set),
                &format!("seal-set{}", case.artifact_set),
            )),
            artifact_set_id: case.artifact_set.clone(),
            expected_revision: 1,
            observed_manifest: Some(manifest.clone()),
        }),
        &owner,
    );

    let pending = task_snapshot(
        task_authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::SubmitTaskEvidence(
                        SubmitTaskEvidenceCommand {
                            meta: Some(metadata(
                                &format!("g4-11-evidence-handoff{}", case.artifact_set),
                                &format!("handoff{}", case.artifact_set),
                            )),
                            task_id: active.task_id.clone(),
                            expected_revision: active.revision,
                            work_revision: active.work_revision,
                            return_handoff_id: format!("return-handoff:g4-11{}", case.output),
                            artifact_set_id: case.artifact_set.clone(),
                        },
                    )),
                }),
                &collaboration,
            )
            .expect("submit Task evidence"),
    );
    assert_eq!(pending.status, TaskStatus::VerificationPending as i32);
    let request_id = format!(
        "verification-request-{}",
        hex::encode(Sha256::digest(
            format!(
                "{}:{}:{}",
                created.task_id, pending.revision, pending.work_revision
            )
            .as_bytes()
        ))
    );
    Seeded {
        task_id: created.task_id,
        lineage,
        run_id: format!("verification-run:{request_id}"),
        request_id,
    }
}

fn producer(kind: ArtifactPrincipalKind, id: &str) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: kind.as_str().to_owned(),
        principal_id: id.to_owned(),
        component_name: "g4-11-input-capture".to_owned(),
        component_version: "1".to_owned(),
        capability_profile_id: None,
        native_execution_ref: None,
    }
}

/// A checker made of the parts a real sidecar replacement has: an executable,
/// arguments, a JSON request and a stdout review artifact.
fn write_checker(root: &Path, name: &str, script: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, script).expect("write checker script");
    path
}

fn review_json(manifest_digest: &str) -> String {
    serde_json::json!({
        "schema_version": 1,
        "id": "review:g4-11",
        "scope": REVIEW_SCOPE,
        "diff_hash": manifest_digest,
        "finding_count": 0,
        "highest_severity": Value::Null,
        "parse_status": "structured",
        "findings": [],
        "reviewer": CHECKER_ID,
        "engine_version": CHECKER_VERSION,
        "review_mode": REVIEW_MODE,
        "data_egress_class": "none",
        "compute_boundary": "local",
    })
    .to_string()
}

fn powershell_printing(body: &str) -> String {
    format!("[Console]::Out.Write('{}')", body.replace('\'', "''"))
}

/// What one scenario declares about its checker's output: the frozen subject
/// it reviews, the reader it uses, whether a capture is declared, and which
/// artifact a successful run cites when no capture is declared.
struct ConfigSpec<'a> {
    manifest_digest: &'a str,
    max_output_bytes: u64,
    output_source: &'a str,
    capture: bool,
    raw_output_artifact_id: &'a str,
}

fn user_config(
    root: &TempRoot,
    checker_script: &Path,
    spec: &ConfigSpec<'_>,
    case: &Case,
) -> PathBuf {
    let ConfigSpec {
        manifest_digest,
        max_output_bytes,
        output_source,
        capture,
        raw_output_artifact_id,
    } = *spec;
    let template = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("config")
        .join("agentos-config.example.json");
    let mut config: Value = serde_json::from_str(
        &fs::read_to_string(template).expect("read production config template"),
    )
    .expect("parse production config template");
    let data = root.path().join("data");
    fs::create_dir_all(data.join("artifact-blobs")).expect("create artifact blob root");
    fs::create_dir_all(data.join("workspace")).expect("create workspace root");
    fs::create_dir_all(data.join("bundles")).expect("create input bundle root");
    fs::write(data.join("bundles").join("input-bundle:replace-me"), b"{}")
        .expect("write input bundle");
    let powershell = PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
    for (store, epoch) in [
        ("task", TASK_EPOCH),
        ("memory", "g4-11-memory"),
        ("artifact", ARTIFACT_EPOCH),
        ("verification", VERIFICATION_EPOCH),
        ("policy", "g4-11-policy"),
        ("verdict", "g4-11-verdict"),
        ("adapter", "g4-11-adapter"),
        ("collaboration", "g4-11-collaboration"),
    ] {
        set_string(
            &mut config,
            &format!("/stores/{store}/database_path"),
            data.join(format!("{store}.db")).display().to_string(),
        );
        set_string(&mut config, &format!("/stores/{store}/store_epoch"), epoch);
    }
    set_string(
        &mut config,
        "/stores/artifact/blob_root",
        data.join("artifact-blobs").display().to_string(),
    );
    // The installation's admission lists come from the same constants the
    // test's own seeding guard uses.
    set_value(
        &mut config,
        "/artifact",
        serde_json::json!({
            "allowed_workspace_refs": [WORKSPACE_REF],
            "allowed_artifact_type_refs": ALLOWED_TYPES
                .iter()
                .map(|id| reference_value(id))
                .collect::<Vec<_>>(),
            "allowed_transformation_contract_refs": ALLOWED_TRANSFORMATIONS
                .iter()
                .map(|id| reference_value(id))
                .collect::<Vec<_>>(),
            "allowed_retention_profile_refs": [reference_value(RETENTION_PROFILE)],
            "allowed_claim_semantic_profile_refs": [reference_value(CLAIM_SEMANTIC)],
            "allowed_claim_acceptance_contract_refs": [reference_value(ACCEPTANCE_CONTRACT)],
            "allowed_evidence_profile_refs": [reference_value(EVIDENCE_PROFILE)],
        }),
    );
    set_string(
        &mut config,
        "/codex/codex_executable",
        powershell.display().to_string(),
    );
    // The production Provider profile and the runtime block must name the same
    // executable; this environment's Harness is the checker's own runner.
    set_string(
        &mut config,
        "/provider_profiles/0/executable",
        powershell.display().to_string(),
    );
    set_string(
        &mut config,
        "/codex/workspace_root",
        data.join("workspace").display().to_string(),
    );
    set_string(
        &mut config,
        "/codex/input_bundle_root",
        data.join("bundles").display().to_string(),
    );
    set_string(&mut config, "/codex/workflow/workspace_ref", WORKSPACE_REF);
    set_string(&mut config, "/codex/workflow/run_id", RUN_ID);
    set_string(
        &mut config,
        "/codex/workflow/plan/step/input_bundle_ref",
        "input-bundle:replace-me",
    );
    set_string(&mut config, "/codex/workflow/attempt_id", "attempt:g4-11");
    set_string(&mut config, "/codex/workflow/dispatch_id", "dispatch:g4-11");
    set_string(&mut config, "/identity/principal_id", "local-user:g4-11");
    set_string(
        &mut config,
        "/task_guard/allowed_input_snapshot_ids/0",
        "input:g4-11",
    );
    set_string(
        &mut config,
        "/task_guard/allowed_target_scope_refs/0",
        "scope:g4-11",
    );
    set_value(
        &mut config,
        "/task_guard/allowed_work_types/0",
        Value::String("governed_repository_change".to_owned()),
    );
    set_value(
        &mut config,
        "/task_guard/acceptance_contract_ref",
        reference_value(ACCEPTANCE_CONTRACT),
    );
    set_value(
        &mut config,
        "/task_guard/budget_profile_ref",
        reference_value("budget:g4-11"),
    );
    set_value(
        &mut config,
        "/verification/criteria/0/criterion_id",
        Value::String(case.criterion.clone()),
    );
    set_value(
        &mut config,
        "/verification/criteria/0/checker_profile_ids",
        serde_json::json!([case.profile]),
    );
    let profile = profile(case);
    config["verification_worker"] = serde_json::json!({
        "handoff": {
            "claim_id": case.claim,
            "claim_semantic_profile_ref": reference_value(CLAIM_SEMANTIC),
            "criterion_ids": [case.criterion],
            "checker_profile_refs": [{
                "contract_id": case.profile,
                "version": CHECKER_VERSION,
                "sha256": profile.profile_digest_sha256,
            }],
        },
        "checker_profile": {
            "checker_profile_id": case.profile,
            "revision": 1,
            "status": 1,
            "checker_id": CHECKER_ID,
            "checker_version": CHECKER_VERSION,
            "input_contract_ref": reference_value(ACCEPTANCE_CONTRACT),
            "output_contract_ref": reference_value(TRANSFORMATION),
            "supported_criterion_types": [case.criterion],
            "assurance_class": 1,
            "sandbox_profile_ref": reference_value("verification_read_only"),
            "tool_policy_ref": reference_value("verification_tools"),
            "data_egress_policy_ref": reference_value("local_only"),
            "timeout_ms": 30000,
            "network_allowed": false,
            "profile_digest_sha256": profile.profile_digest_sha256,
            "attestation_evidence_artifact_ids": [
                format!("artifact:checker-profile-attestation:{}", case.profile)
            ],
            "attested_at": Value::Null,
        },
        "checker_profile_deployment": {
            "workspace_ref": WORKSPACE_REF,
            "artifact_type_ref": reference_value("checker-profile-attestation"),
            "transformation_contract_ref": reference_value("checker-profile-deployment"),
            "retention_profile_ref": reference_value(RETENTION_PROFILE),
            "collector_principal_id": "collector:checker-profile-deployment",
            "artifact_authority_principal_id": ARTIFACT_AUTHORITY_PRINCIPAL,
            "sensitivity_class": "local-user-data",
        },
        "checker_executable": powershell.display().to_string(),
        "checker_arguments": [
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", checker_script.display().to_string(),
        ],
        "working_directory": root.path().display().to_string(),
        "checker_request_hex": hex::encode(b"{\"action\":\"review\"}"),
        "checker_output_source": output_source,
        "checker_output_capture": if capture {
            serde_json::json!({
                "raw_output_type_ref": reference_value(RAW_OUTPUT_TYPE),
                "retention_profile_ref": reference_value(RETENTION_PROFILE),
                "collector_principal_id": COLLECTOR_PRINCIPAL,
                "artifact_authority_principal_id": ARTIFACT_AUTHORITY_PRINCIPAL,
                "max_output_bytes": max_output_bytes,
            })
        } else {
            Value::Null
        },
        "mapper": {
            "criterion_id": case.criterion,
            "requirement": 1,
            "checker_profile_ref": {
                "contract_id": case.profile,
                "version": CHECKER_VERSION,
                "sha256": profile.profile_digest_sha256,
            },
            "contract_id": "sego.review.artifact/v1",
            "contract_revision": 3,
            "expected_scope": REVIEW_SCOPE,
            "expected_diff_hash": manifest_digest,
            "expected_reviewer": CHECKER_ID,
            "expected_engine_version": CHECKER_VERSION,
            "expected_review_mode": REVIEW_MODE,
            "positive_acceptance": true,
            "failure_threshold": 2,
            "raw_output_artifact_id": raw_output_artifact_id,
            "raw_output_address": {
                "algorithm": 1,
                "digest": hex::encode(Sha256::digest(b"captured harness output")),
                "byte_length": 22,
            },
            "finding_evidence": {},
        },
        "verification_run_id_prefix": "verification-run:",
        "verification_artifact_id_prefix": "verification-artifact:",
        "execution_id_prefix": "execution:",
        "tool_receipt_artifact_ids": [],
        "model_call_receipt_artifact_ids": [],
        "checker_timeout_ms": 30000,
        "checker_output_limit": 65536,
    });
    // One configuration file per case: two environments in one root must not
    // overwrite each other's declaration.
    let path = root
        .path()
        .join(format!("agentos-config{}.json", case.suffix));
    fs::write(
        &path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .expect("write config");
    path
}

fn verification_authority(root: &Path, cases: &[&Case]) -> VerificationAuthority {
    let artifact = Arc::new(Mutex::new(open_artifact_authority(root)));
    let resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(artifact),
        cases
            .iter()
            .map(|case| CriterionPolicySnapshot {
                criterion_id: case.criterion.clone(),
                requirement: CriterionRequirement::MustPass as i32,
                minimum_assurance: CheckerAssuranceClass::Deterministic as i32,
                not_applicable_allowed: false,
                checker_profile_ids: vec![case.profile.clone()],
            })
            .collect(),
    )
    .expect("reference resolver")
    .with_checker_output_collector(COLLECTOR_PRINCIPAL.to_owned())
    .expect("collector");
    VerificationAuthority::open(
        VerificationAuthorityConfig {
            database_path: root.join("data").join("verification.db"),
            store_epoch: VERIFICATION_EPOCH.to_owned(),
            key: VerificationSqlCipherKey::new(key_from_env("EGOPULSE_VERIFICATION_KEY_HEX")),
        },
        resolver,
    )
    .expect("open Verification SQLCipher owner")
}

struct Run {
    artifact: VerificationArtifact,
    captured: Option<ArtifactDescriptor>,
    verified_evidence_ids: Vec<String>,
}

/// Builds the daemon from the JSON configuration and runs one worker cycle.
/// Every call composes a fresh set of owners over the same stores, so a second
/// call is the process-restart case as well as the replay case.
async fn run_worker_once(config_path: &Path) -> String {
    let mut providers = ProductionBootstrapConfig::from_user_file(config_path)
        .expect("load user-owned production config")
        .build()
        .expect("build production providers");
    let worker = providers
        .verification_worker
        .take()
        .expect("production Verification worker");
    let cycle = format!("{:?}", worker.run_once().await);
    eprintln!("g4-11: worker cycle {cycle}");
    cycle
}

/// Runs one worker cycle and reads the resulting artifact back from both
/// owners.
async fn run_cycle(root: &TempRoot, config_path: &Path, cases: &[&Case]) -> Run {
    let cycle = run_worker_once(config_path).await;
    assert!(
        cycle.contains("Completed"),
        "worker cycle did not complete: {cycle}"
    );
    read_run(root, cases)
}

/// Reads the completed verification artifact of the given case and the
/// artifact it cites. A second case in the same environment keeps its own
/// request, so a reading for one case can never be satisfied by the other.
fn read_run(root: &TempRoot, cases: &[&Case]) -> Run {
    let authority = verification_authority(root.path(), cases);
    let requests = authority.execution_requests().expect("execution requests");
    let artifact = requests
        .iter()
        .filter(|request| {
            request
                .criterion_ids
                .iter()
                .any(|id| cases.iter().any(|case| case.criterion == *id))
        })
        .filter_map(|request| {
            authority
                .verification_artifact(&format!(
                    "verification-artifact:{}",
                    request.verification_request_id
                ))
                .expect("artifact read")
        })
        .next()
        .expect("one completed verification artifact");
    let captured_artifact_id = artifact
        .provenance
        .as_ref()
        .expect("provenance")
        .raw_output_artifact_ids
        .first()
        .cloned();
    let captured = captured_artifact_id.as_ref().and_then(|id| {
        open_artifact_authority(root.path())
            .read_artifact(id)
            .expect("artifact read")
    });
    let verified_evidence_ids = artifact
        .criterion_results
        .iter()
        .flat_map(|result| result.evidence_ids.clone())
        .collect();
    Run {
        artifact,
        captured,
        verified_evidence_ids,
    }
}

fn capture_is_bound_to_its_execution(root: &TempRoot, run: &Run, case: &Case) {
    let descriptor = run.captured.as_ref().expect("sealed capture artifact");
    let provenance = descriptor.provenance.as_ref().expect("capture provenance");
    let producer = provenance.producer.as_ref().expect("capture producer");
    let request_id = run.artifact.verification_request_id.clone();
    let run_id = run.artifact.verification_run_id.clone();
    assert_eq!(descriptor.status, ArtifactStatus::Sealed as i32);
    assert_eq!(
        descriptor.integrity_status,
        IntegrityStatus::DigestVerified as i32
    );
    assert_eq!(
        descriptor.semantic_class,
        ArtifactSemanticClass::LogBundle as i32
    );
    assert_eq!(producer.principal_kind, "governed_collector");
    assert_eq!(producer.principal_id, COLLECTOR_PRINCIPAL);
    assert_eq!(producer.component_name, "verification-raw-output");
    assert_eq!(producer.component_version, CHECKER_VERSION);
    assert_eq!(
        producer.capability_profile_id.as_deref(),
        Some(case.profile.as_str())
    );
    assert_eq!(
        producer.native_execution_ref.as_deref(),
        Some(checker_output_execution_ref(&request_id, &run_id, &case.profile).as_str())
    );
    assert_eq!(
        provenance.transformation_contract_ref,
        Some(reference(TRANSFORMATION))
    );
    assert_eq!(provenance.workspace_ref, WORKSPACE_REF);
    let inputs = provenance.input_artifact_ids.clone();
    assert_eq!(
        inputs.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([case.baseline.clone(), case.output.clone()])
    );
    let descriptor = open_artifact_authority(root.path())
        .read_artifact(&descriptor.artifact_id)
        .expect("artifact read")
        .expect("sealed capture is durable");
    assert_eq!(descriptor.status, ArtifactStatus::Sealed as i32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_capture_seals_the_checker_output_and_reads_back() {
    let root = TempRoot::new("capture-success");
    let case = Case::first();
    let subject = subject_digest(&case);
    let script = write_checker(
        root.path(),
        "checker.ps1",
        &format!(
            "Add-Content -Path '.g4-11-runs' -Value 'run'\n{}",
            powershell_printing(&review_json(&subject))
        ),
    );
    let config = user_config(
        &root,
        &script,
        &ConfigSpec {
            manifest_digest: &subject,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &case.output,
        },
        &case,
    );
    seed(root.path(), &case);

    let run = run_cycle(&root, &config, &[&case]).await;
    assert_eq!(
        run.artifact.conclusion,
        VerificationConclusion::Passed as i32,
        "a deterministic acceptance checker with a sealed capture passes"
    );
    assert_eq!(
        run.artifact.criterion_results[0].outcome,
        egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionOutcome::Passed as i32
    );
    let cited = run
        .artifact
        .provenance
        .as_ref()
        .expect("provenance")
        .raw_output_artifact_ids
        .first()
        .cloned()
        .expect("raw output citation");
    assert!(
        cited.starts_with("artifact:verification-output:"),
        "the citation is the sealed checker output, not a configured input: {cited}"
    );
    capture_is_bound_to_its_execution(&root, &run, &case);
    assert!(
        run.verified_evidence_ids.is_empty(),
        "deterministic positive acceptance cites the artifact, not Evidence"
    );
    assert_eq!(checker_runs(&root), 1, "the checker ran once");

    // A second cycle over the same stores is a replay, not a second execution:
    // the completed request is served once and its checker is never re-run.
    let replay = run_worker_once(&config).await;
    assert!(
        replay.contains("Idle"),
        "a completed verification request is not served twice: {replay}"
    );
    assert_eq!(
        checker_runs(&root),
        1,
        "the checker is not executed again for a completed request"
    );
    let replayed = read_run(&root, &[&case]);
    assert_eq!(replayed.artifact, run.artifact);
}

/// A checker whose output is marked for review, in the shape the collector
/// would produce — except for the one field the caller overrides.
fn seal_fabricated_capture(
    root: &Path,
    lineage: &LineageBinding,
    case: &Case,
    artifact_id: &str,
    producer_id: &str,
    component_version: &str,
    execution_ref: &str,
) {
    let mut artifact = open_artifact_authority(root);
    let bytes = b"fabricated checker output".to_vec();
    let content = content_address(&bytes);
    artifact
        .put_blob(&bytes, &content)
        .expect("fabricated blob");
    let collector = artifact_principal(ArtifactPrincipalKind::GovernedCollector, producer_id);
    let owner = artifact_principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        ARTIFACT_AUTHORITY_PRINCIPAL,
    );
    execute_artifact(
        &mut artifact,
        artifact_command::Command::StageArtifact(StageArtifactCommand {
            metadata: Some(metadata(
                &format!("fabricated-stage-{artifact_id}"),
                "stage",
            )),
            candidate: Some(ArtifactDescriptor {
                artifact_id: artifact_id.to_owned(),
                semantic_class: ArtifactSemanticClass::LogBundle as i32,
                type_contract_ref: Some(reference(RAW_OUTPUT_TYPE)),
                media_type: "application/json".to_owned(),
                content: Some(content.clone()),
                provenance: Some(Provenance {
                    lineage: Some(lineage.clone()),
                    producer: Some(ProducerIdentity {
                        principal_kind: ArtifactPrincipalKind::GovernedCollector
                            .as_str()
                            .to_owned(),
                        principal_id: producer_id.to_owned(),
                        component_name: "verification-raw-output".to_owned(),
                        component_version: component_version.to_owned(),
                        capability_profile_id: Some(case.profile.clone()),
                        native_execution_ref: Some(execution_ref.to_owned()),
                    }),
                    input_artifact_ids: vec![case.baseline.clone()],
                    transformation_contract_ref: Some(reference(TRANSFORMATION)),
                    workspace_ref: WORKSPACE_REF.to_owned(),
                    raw_source_ref: Some("g4-11-fabricated".to_owned()),
                    ..Default::default()
                }),
                sensitivity_class: "local-user-data".to_owned(),
                retention_profile_ref: Some(reference(RETENTION_PROFILE)),
                ..Default::default()
            }),
        }),
        &collector,
    );
    execute_artifact(
        &mut artifact,
        artifact_command::Command::SealArtifact(SealArtifactCommand {
            metadata: Some(metadata(&format!("fabricated-seal-{artifact_id}"), "seal")),
            artifact_id: artifact_id.to_owned(),
            expected_revision: 1,
            observed_content: Some(content),
        }),
        &owner,
    );
}

/// Two tasks in one environment keep their own artifact set, criterion and
/// profile: the second is served on its own identity, not as a replay of the
/// first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_two_independent_tasks_are_served() {
    let root = TempRoot::new("capture-two-tasks");
    let first = Case::first();
    let second = Case::second();
    let first_digest = subject_digest(&first);
    let second_digest = subject_digest(&second);
    let marked = |digest: &str| {
        format!(
            "Add-Content -Path '.g4-11-runs' -Value 'run'\n{}",
            powershell_printing(&review_json(digest))
        )
    };
    let first_script = write_checker(root.path(), "checker-1.ps1", &marked(&first_digest));
    let second_script = write_checker(root.path(), "checker-2.ps1", &marked(&second_digest));
    let first_config = user_config(
        &root,
        &first_script,
        &ConfigSpec {
            manifest_digest: &first_digest,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &first.output,
        },
        &first,
    );
    let second_config = user_config(
        &root,
        &second_script,
        &ConfigSpec {
            manifest_digest: &second_digest,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &second.output,
        },
        &second,
    );
    let first_seeded = seed(root.path(), &first);
    let second_seeded = seed(root.path(), &second);
    eprintln!(
        "g4-11: first task={} request={} claim={}; second task={} request={} claim={}",
        first_seeded.task_id,
        first_seeded.request_id,
        first.claim,
        second_seeded.task_id,
        second_seeded.request_id,
        second.claim
    );

    let first_run = run_cycle(&root, &first_config, &[&first]).await;
    assert_eq!(
        first_run.artifact.criterion_results[0].criterion_id,
        first.criterion
    );
    assert_eq!(
        first_run.artifact.conclusion,
        VerificationConclusion::Passed as i32
    );
    capture_is_bound_to_its_execution(&root, &first_run, &first);
    assert_eq!(checker_runs(&root), 1, "only the first task's checker ran");

    let second_run = run_cycle(&root, &second_config, &[&second]).await;
    assert_eq!(
        second_run.artifact.criterion_results[0].criterion_id,
        second.criterion
    );
    assert_eq!(
        second_run.artifact.conclusion,
        VerificationConclusion::Passed as i32
    );
    capture_is_bound_to_its_execution(&root, &second_run, &second);
    assert_eq!(
        checker_runs(&root),
        2,
        "the second task ran its own checker"
    );

    // The first task's completed result is untouched by the second task.
    let first_again = read_run(&root, &[&first]);
    assert_eq!(first_again.artifact, first_run.artifact);
}

/// A citation this environment did not produce is refused by the reference
/// resolver, and the run is held instead of completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_fabricated_capture_references_are_rejected() {
    for (artifact_id, producer_id, component_version, wrong_execution_ref) in [
        (
            "g4-11-fabricated-execution",
            COLLECTOR_PRINCIPAL,
            CHECKER_VERSION,
            true,
        ),
        (
            "g4-11-fabricated-collector",
            "collector:not-configured",
            CHECKER_VERSION,
            false,
        ),
        (
            "g4-11-fabricated-version",
            COLLECTOR_PRINCIPAL,
            "999",
            false,
        ),
    ] {
        let root = TempRoot::new(&format!("capture-fabricated-{artifact_id}"));
        let case = Case::first();
        let subject = subject_digest(&case);
        let script = write_checker(
            root.path(),
            "checker.ps1",
            &powershell_printing(&review_json(&subject)),
        );
        let seeded = seed(root.path(), &case);
        let execution_ref = if wrong_execution_ref {
            "verification-output-execution:not-this-run".to_owned()
        } else {
            checker_output_execution_ref(&seeded.request_id, &seeded.run_id, &case.profile)
        };
        seal_fabricated_capture(
            root.path(),
            &seeded.lineage,
            &case,
            artifact_id,
            producer_id,
            component_version,
            &execution_ref,
        );
        let config = user_config(
            &root,
            &script,
            &ConfigSpec {
                manifest_digest: &subject,
                max_output_bytes: 65_536,
                output_source: "stdout",
                capture: false,
                raw_output_artifact_id: artifact_id,
            },
            &case,
        );
        let cycle = run_worker_once(&config).await;
        // The reference gate refuses the citation, so the cycle reports a
        // rejection instead of a completion. The field-level classes (profile,
        // collector principal, component version, execution reference, role,
        // workspace, inputs, transformation) each have their own rejection case
        // in `reference_resolver`'s substitution test.
        assert!(
            cycle.contains("Rejected"),
            "{artifact_id}: a citation this environment did not produce must not complete: {cycle}"
        );
        let authority = verification_authority(root.path(), &[&case]);
        let completed = authority
            .execution_requests()
            .expect("execution requests")
            .iter()
            .filter_map(|request| {
                authority
                    .verification_artifact(&format!(
                        "verification-artifact:{}",
                        request.verification_request_id
                    ))
                    .expect("artifact read")
            })
            .next();
        assert!(
            completed.is_none(),
            "{artifact_id}: nothing may be completed from a fabricated citation"
        );
    }
}

/// A declared capture over an answer that never came: nothing of this
/// execution may be cited, and the refusal is typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_zero_byte_output_cites_nothing() {
    let root = TempRoot::new("capture-zero-byte");
    let case = Case::first();
    let subject = subject_digest(&case);
    let script = write_checker(root.path(), "empty.ps1", "[Console]::Out.Write('')\n");
    let config = user_config(
        &root,
        &script,
        &ConfigSpec {
            manifest_digest: &subject,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &case.output,
        },
        &case,
    );
    seed(root.path(), &case);

    let run = run_cycle(&root, &config, &[&case]).await;
    assert_ne!(
        run.artifact.conclusion,
        VerificationConclusion::Passed as i32,
        "an execution that sealed nothing must not pass"
    );
    assert_eq!(
        run.artifact.criterion_results[0].safe_detail_artifact_id,
        None
    );
    assert_eq!(
        run.artifact
            .provenance
            .as_ref()
            .expect("provenance")
            .raw_output_artifact_ids,
        Vec::<String>::new()
    );
    assert!(run.captured.is_none());
}

/// A checker that stops and says why: the stop reason becomes durable
/// evidence, and the criterion is an error rather than a pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_stopped_checker_records_its_declared_code() {
    let root = TempRoot::new("capture-stopped");
    let case = Case::first();
    let subject = subject_digest(&case);
    let script = write_checker(
        root.path(),
        "checker-stop.ps1",
        "[Console]::Out.Write('{\"schema_version\":1,\"status\":\"budget_exceeded\"}')\n\
         [Console]::Out.Flush()\nexit 1\n",
    );
    let config = user_config(
        &root,
        &script,
        &ConfigSpec {
            manifest_digest: &subject,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &case.output,
        },
        &case,
    );
    seed(root.path(), &case);

    let run = run_cycle(&root, &config, &[&case]).await;
    assert_eq!(
        run.artifact.conclusion,
        VerificationConclusion::Indeterminate as i32,
        "a stopped checker never passes"
    );
    let result = &run.artifact.criterion_results[0];
    assert_eq!(
        result.outcome,
        egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionOutcome::Error as i32
    );
    let cited = run
        .artifact
        .provenance
        .as_ref()
        .expect("provenance")
        .raw_output_artifact_ids
        .first()
        .cloned()
        .expect("raw output citation");
    assert!(
        cited.starts_with("artifact:verification-output:"),
        "the stop output itself is sealed: {cited}"
    );
    assert_eq!(
        result.safe_detail_artifact_id.as_deref(),
        Some(cited.as_str())
    );
    assert!(run.captured.is_some());
}

/// An answer this environment cannot read is recorded as an error, not as a
/// pass, and its own bytes are still the citation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_unmappable_output_is_recorded_without_passing() {
    let root = TempRoot::new("capture-untrusted");
    let case = Case::first();
    let subject = subject_digest(&case);
    let script = write_checker(
        root.path(),
        "checker-invalid.ps1",
        &powershell_printing("not-a-review-artifact"),
    );
    let config = user_config(
        &root,
        &script,
        &ConfigSpec {
            manifest_digest: &subject,
            max_output_bytes: 65_536,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &case.output,
        },
        &case,
    );
    seed(root.path(), &case);

    let run = run_cycle(&root, &config, &[&case]).await;
    assert_eq!(
        run.artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
    assert_eq!(
        run.artifact.criterion_results[0].outcome,
        egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionOutcome::Error as i32
    );
    assert!(run.captured.is_some());
}

/// A declared capture that refuses the output blocks a positive result: the
/// criterion cites nothing instead of falling back to an input artifact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_refused_capture_blocks_a_positive_result() {
    let root = TempRoot::new("capture-refused");
    let case = Case::first();
    let subject = subject_digest(&case);
    let script = write_checker(
        root.path(),
        "checker.ps1",
        &powershell_printing(&review_json(&subject)),
    );
    // The declared capture refuses anything above 32 bytes, so the review
    // artifact cannot become evidence in this environment.
    let config = user_config(
        &root,
        &script,
        &ConfigSpec {
            manifest_digest: &subject,
            max_output_bytes: 32,
            output_source: "stdout",
            capture: true,
            raw_output_artifact_id: &case.output,
        },
        &case,
    );
    seed(root.path(), &case);

    let run = run_cycle(&root, &config, &[&case]).await;
    assert_ne!(
        run.artifact.conclusion,
        VerificationConclusion::Passed as i32,
        "an unsealed execution must not pass on an artifact of its own input set"
    );
    assert_eq!(
        run.artifact.criterion_results[0].outcome,
        egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionOutcome::Error as i32
    );
    assert_eq!(
        run.artifact.criterion_results[0].safe_detail_artifact_id,
        None
    );
    assert_eq!(
        run.artifact
            .provenance
            .as_ref()
            .expect("provenance")
            .raw_output_artifact_ids,
        Vec::<String>::new()
    );
}

fn checker_runs(root: &TempRoot) -> usize {
    fs::read_to_string(root.path().join(".g4-11-runs"))
        .expect("checker run marker")
        .lines()
        .count()
}
