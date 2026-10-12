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
const CRITERION_ID: &str = "criterion:g4-11";
const PROFILE_ID: &str = "checker-profile:g4-11";
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
const BASELINE_ARTIFACT: &str = "g4-11-baseline";
const OUTPUT_ARTIFACT: &str = "g4-11-harness-output";
const ARTIFACT_SET_ID: &str = "artifact-set:g4-11";
const CLAIM_ID: &str = "claim:g4-11";
const EVIDENCE_ID: &str = "evidence:g4-11";
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
    let scenarios = [
        "scenario_capture_seals_the_checker_output_and_reads_back",
        "scenario_stopped_checker_records_its_declared_code",
        "scenario_unmappable_output_is_recorded_without_passing",
        "scenario_refused_capture_blocks_a_positive_result",
    ];
    let executable = env::current_exe().expect("current test executable");
    for scenario in scenarios {
        let mut command = Command::new(&executable);
        command.args(["--exact", scenario, "--ignored", "--nocapture"]);
        for (name, value) in test_keys() {
            command.env(name, value);
        }
        let output = command.output().expect("spawn scenario");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("1 passed; 0 failed"),
            "scenario {scenario} did not report one passing test: {text}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
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
fn expected_lineage() -> LineageBinding {
    LineageBinding {
        task_id: "pending".to_owned(),
        task_revision: 1,
        work_revision: 1,
        run_id: RUN_ID.to_owned(),
        run_revision: 1,
        step_id: "step:g4-11".to_owned(),
        step_revision: 1,
        attempt_id: "attempt:g4-11".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch:g4-11".to_owned(),
        fencing_token: 1,
    }
}

fn subject_digest() -> String {
    artifact_set(&expected_lineage()).1.digest
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
        AllowActivation {
            run_id: RUN_ID.to_owned(),
        },
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

struct AllowActivation {
    run_id: String,
}

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
                    && activate.run_id == self.run_id
            }
            // The returned artifact set is the one the checker reviews; the
            // test-only guard accepts the evidence step of the same work.
            Some(task_command::Command::SubmitTaskEvidence(submit)) => {
                current.status == TaskStatus::Active as i32
                    && submit.expected_revision == current.revision
                    && submit.work_revision == current.work_revision
                    && submit.artifact_set_id == ARTIFACT_SET_ID
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

fn profile() -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: PROFILE_ID.to_owned(),
        revision: 0,
        status: 0,
        checker_id: CHECKER_ID.to_owned(),
        checker_version: CHECKER_VERSION.to_owned(),
        input_contract_ref: Some(reference(ACCEPTANCE_CONTRACT)),
        output_contract_ref: Some(reference(TRANSFORMATION)),
        supported_criterion_types: vec![CRITERION_ID.to_owned()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(reference("verification_read_only")),
        tool_policy_ref: Some(reference("verification_tools")),
        data_egress_policy_ref: Some(reference("local_only")),
        timeout_ms: 30_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![
            "artifact:checker-profile-attestation:checker-profile:g4-11".to_owned(),
        ],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

/// The frozen artifact set the checker reviews: one repository baseline and one
/// captured harness output, plus the claim and evidence that bind them to the
/// Task lineage.
fn artifact_set(lineage: &LineageBinding) -> (ArtifactSet, ContentAddress) {
    let mut set = ArtifactSet {
        artifact_set_id: ARTIFACT_SET_ID.to_owned(),
        revision: 1,
        status: ArtifactSetStatus::Sealed as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec![BASELINE_ARTIFACT.to_owned(), OUTPUT_ARTIFACT.to_owned()],
        claim_ids: vec![CLAIM_ID.to_owned()],
        evidence_ids: vec![EVIDENCE_ID.to_owned()],
        canonical_manifest: None,
        ..ArtifactSet::default()
    };
    let manifest = content_address(&canonical_artifact_set_manifest(&set));
    set.canonical_manifest = Some(manifest.clone());
    (set, manifest)
}

/// Seals the input set through the real Artifact Authority and activates one
/// Task whose verification handoff the worker will consume.
fn seed(root: &Path) -> (String, String) {
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
                        meta: Some(metadata("g4-11-create", "g4-11-create")),
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
                        meta: Some(metadata("g4-11-activate", "g4-11-activate")),
                        task_id: created.task_id.clone(),
                        expected_revision: created.revision,
                        work_revision: created.work_revision,
                        run_id: RUN_ID.to_owned(),
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
        run_id: RUN_ID.to_owned(),
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
            BASELINE_ARTIFACT,
            ArtifactSemanticClass::RepositoryBaseline,
            b"sealed repository baseline".as_slice(),
        ),
        (
            OUTPUT_ARTIFACT,
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
            metadata: Some(metadata("g4-11-claim", "claim")),
            claim: Some(Claim {
                claim_id: CLAIM_ID.to_owned(),
                revision: 1,
                status: ClaimStatus::Proposed as i32,
                source_type: ClaimSourceType::CodeChange as i32,
                semantic_profile_ref: Some(reference(CLAIM_SEMANTIC)),
                lineage: Some(lineage.clone()),
                acceptance_contract_ref: Some(reference(ACCEPTANCE_CONTRACT)),
                subject_artifact_ids: vec![OUTPUT_ARTIFACT.to_owned()],
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
            metadata: Some(metadata("g4-11-evidence", "evidence")),
            evidence: Some(Evidence {
                evidence_id: EVIDENCE_ID.to_owned(),
                revision: 1,
                status: EvidenceStatus::Recorded as i32,
                relation: EvidenceRelation::Supports as i32,
                claim_id: CLAIM_ID.to_owned(),
                artifact_ids: vec![BASELINE_ARTIFACT.to_owned(), OUTPUT_ARTIFACT.to_owned()],
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
    let (set, manifest) = artifact_set(&lineage);
    artifact
        .put_blob(&canonical_artifact_set_manifest(&set), &manifest)
        .expect("artifact set manifest blob");
    execute_artifact(
        &mut artifact,
        artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
            metadata: Some(metadata("g4-11-set", "set")),
            artifact_set: Some(set.clone()),
        }),
        &collector,
    );
    execute_artifact(
        &mut artifact,
        artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
            metadata: Some(metadata("g4-11-seal-set", "seal-set")),
            artifact_set_id: ARTIFACT_SET_ID.to_owned(),
            expected_revision: 1,
            observed_manifest: Some(manifest.clone()),
        }),
        &owner,
    );

    assert!(
        task_snapshot(
            task_authority
                .execute(
                    &signed_task_command(TaskCommand {
                        command: Some(task_command::Command::SubmitTaskEvidence(
                            SubmitTaskEvidenceCommand {
                                meta: Some(metadata("g4-11-evidence-handoff", "handoff")),
                                task_id: active.task_id.clone(),
                                expected_revision: active.revision,
                                work_revision: active.work_revision,
                                return_handoff_id: "return-handoff:g4-11".to_owned(),
                                artifact_set_id: ARTIFACT_SET_ID.to_owned(),
                            },
                        )),
                    }),
                    &collaboration,
                )
                .expect("submit Task evidence"),
        )
        .status
            == TaskStatus::VerificationPending as i32
    );
    (created.task_id, manifest.digest)
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

fn user_config(
    root: &TempRoot,
    checker_script: &Path,
    manifest_digest: &str,
    max_output_bytes: u64,
    output_source: &str,
) -> PathBuf {
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
        Value::String(CRITERION_ID.to_owned()),
    );
    set_value(
        &mut config,
        "/verification/criteria/0/checker_profile_ids",
        serde_json::json!([PROFILE_ID]),
    );
    let profile = profile();
    config["verification_worker"] = serde_json::json!({
        "handoff": {
            "claim_id": CLAIM_ID,
            "claim_semantic_profile_ref": reference_value(CLAIM_SEMANTIC),
            "criterion_ids": [CRITERION_ID],
            "checker_profile_refs": [{
                "contract_id": PROFILE_ID,
                "version": CHECKER_VERSION,
                "sha256": profile.profile_digest_sha256,
            }],
        },
        "checker_profile": {
            "checker_profile_id": PROFILE_ID,
            "revision": 1,
            "status": 1,
            "checker_id": CHECKER_ID,
            "checker_version": CHECKER_VERSION,
            "input_contract_ref": reference_value(ACCEPTANCE_CONTRACT),
            "output_contract_ref": reference_value(TRANSFORMATION),
            "supported_criterion_types": [CRITERION_ID],
            "assurance_class": 1,
            "sandbox_profile_ref": reference_value("verification_read_only"),
            "tool_policy_ref": reference_value("verification_tools"),
            "data_egress_policy_ref": reference_value("local_only"),
            "timeout_ms": 30000,
            "network_allowed": false,
            "profile_digest_sha256": profile.profile_digest_sha256,
            "attestation_evidence_artifact_ids": [
                "artifact:checker-profile-attestation:checker-profile:g4-11"
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
        "checker_output_capture": {
            "raw_output_type_ref": reference_value(RAW_OUTPUT_TYPE),
            "retention_profile_ref": reference_value(RETENTION_PROFILE),
            "collector_principal_id": COLLECTOR_PRINCIPAL,
            "artifact_authority_principal_id": ARTIFACT_AUTHORITY_PRINCIPAL,
            "max_output_bytes": max_output_bytes,
        },
        "mapper": {
            "criterion_id": CRITERION_ID,
            "requirement": 1,
            "checker_profile_ref": {
                "contract_id": PROFILE_ID,
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
            "raw_output_artifact_id": OUTPUT_ARTIFACT,
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
    let path = root.path().join("agentos-config.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&config).expect("serialize config"),
    )
    .expect("write config");
    path
}

fn verification_authority(root: &Path) -> VerificationAuthority {
    let artifact = Arc::new(Mutex::new(open_artifact_authority(root)));
    let resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(artifact),
        vec![CriterionPolicySnapshot {
            criterion_id: CRITERION_ID.to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::Deterministic as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![PROFILE_ID.to_owned()],
        }],
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
async fn run_cycle(root: &TempRoot, config_path: &Path) -> Run {
    let cycle = run_worker_once(config_path).await;
    assert!(
        cycle.contains("Completed"),
        "worker cycle did not complete: {cycle}"
    );
    read_run(root)
}

/// Reads the one completed verification artifact and the artifact it cites.
fn read_run(root: &TempRoot) -> Run {
    let authority = verification_authority(root.path());
    let requests = authority.execution_requests().expect("execution requests");
    let artifact = requests
        .iter()
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

fn capture_is_bound_to_its_execution(root: &TempRoot, run: &Run) {
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
    assert_eq!(producer.capability_profile_id.as_deref(), Some(PROFILE_ID));
    assert_eq!(
        producer.native_execution_ref.as_deref(),
        Some(checker_output_execution_ref(&request_id, &run_id, PROFILE_ID).as_str())
    );
    assert_eq!(
        provenance.transformation_contract_ref,
        Some(reference(TRANSFORMATION))
    );
    assert_eq!(provenance.workspace_ref, WORKSPACE_REF);
    let inputs = provenance.input_artifact_ids.clone();
    assert_eq!(
        inputs.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([BASELINE_ARTIFACT.to_owned(), OUTPUT_ARTIFACT.to_owned()])
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
    let subject = subject_digest();
    let script = write_checker(
        root.path(),
        "checker.ps1",
        &format!(
            "Add-Content -Path '.g4-11-runs' -Value 'run'\n{}",
            powershell_printing(&review_json(&subject))
        ),
    );
    let config = user_config(&root, &script, &subject, 65_536, "stdout");
    seed(root.path());

    let run = run_cycle(&root, &config).await;
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
    capture_is_bound_to_its_execution(&root, &run);
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
    let replayed = read_run(&root);
    assert_eq!(replayed.artifact, run.artifact);
}

fn checker_runs(root: &TempRoot) -> usize {
    fs::read_to_string(root.path().join(".g4-11-runs"))
        .expect("checker run marker")
        .lines()
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_stopped_checker_records_its_declared_code() {
    let root = TempRoot::new("capture-stopped");
    let subject = subject_digest();
    let script = write_checker(
        root.path(),
        "checker-stop.ps1",
        "[Console]::Out.Write('{\"schema_version\":1,\"status\":\"budget_exceeded\"}')\n\
         [Console]::Out.Flush()\nexit 1\n",
    );
    let config = user_config(&root, &script, &subject, 65_536, "stdout");
    seed(root.path());

    let run = run_cycle(&root, &config).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_unmappable_output_is_recorded_without_passing() {
    let root = TempRoot::new("capture-untrusted");
    let subject = subject_digest();
    let script = write_checker(
        root.path(),
        "checker-invalid.ps1",
        &powershell_printing("not-a-review-artifact"),
    );
    let config = user_config(&root, &script, &subject, 65_536, "stdout");
    seed(root.path());

    let run = run_cycle(&root, &config).await;
    assert_eq!(
        run.artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
    assert_eq!(
        run.artifact.criterion_results[0].outcome,
        egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionOutcome::Error as i32
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run by g4_11_capture_scenarios_run_in_isolated_processes with test keys"]
async fn scenario_refused_capture_blocks_a_positive_result() {
    let root = TempRoot::new("capture-refused");
    let subject = subject_digest();
    let script = write_checker(
        root.path(),
        "checker.ps1",
        &powershell_printing(&review_json(&subject)),
    );
    // The declared capture refuses anything above 32 bytes, so the review
    // artifact cannot become evidence in this environment.
    let config = user_config(&root, &script, &subject, 32, "stdout");
    seed(root.path());

    let run = run_cycle(&root, &config).await;
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
