use egopulse_agentosd::{
    ConfiguredVerificationWorker, VerificationBindingTemplate, VerificationHandoffIntake,
    VerificationHandoffPlan, VerificationWorker, VerificationWorkerConfig,
};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskCreationGuard, TaskTransitionGuard, TransitionAuthorization,
    TransitionGuardRejection, canonical_request_digest as canonical_task_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactDescriptor, ArtifactSet, ArtifactSetStatus, ArtifactStatus, Claim, ClaimSourceType,
        ClaimStatus, ContentAddress, Evidence, EvidenceProducerClass, EvidenceRelation,
        EvidenceStatus, HashAlgorithm, IntegrityStatus, LineageBinding, Provenance,
    },
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, SubmitTaskEvidenceCommand, TaskCommand,
        TaskSnapshot, TaskStatus, get_task_response, task_command, task_command_result,
    },
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
        CriterionRequirement, DiscrepancySeverity, VerificationCommand, verification_command,
    },
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, ArtifactReferenceSource, ArtifactReferenceSourceError,
    AuthenticatedVerificationPrincipal, CriterionPolicySnapshot, VerificationAuthority,
    VerificationAuthorityConfig, VerificationPrincipalKind, VerificationSqlCipherKey,
    canonical_checker_profile_digest, canonical_request_digest,
};
use prost_types::Timestamp;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["creation-proof-g4-10".to_owned()],
        })
    }
}

struct AllowTransitions;

impl TaskTransitionGuard for AllowTransitions {
    fn validate(
        &self,
        _command: &TaskCommand,
        _current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        Ok(TransitionAuthorization {
            evidence_refs: vec!["transition-proof-g4-10".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

#[derive(Clone)]
struct StaticArtifactSource {
    artifact_set: ArtifactSet,
    artifact: ArtifactDescriptor,
    claim: Claim,
    evidence: Evidence,
}

impl ArtifactReferenceSource for StaticArtifactSource {
    fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
        Ok((artifact_id == self.artifact.artifact_id).then(|| self.artifact.clone()))
    }

    fn read_claim(&self, claim_id: &str) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
        Ok((claim_id == self.claim.claim_id).then(|| self.claim.clone()))
    }

    fn read_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
        Ok((evidence_id == self.evidence.evidence_id).then(|| self.evidence.clone()))
    }

    fn read_artifact_set(
        &self,
        artifact_set_id: &str,
    ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
        Ok((artifact_set_id == self.artifact_set.artifact_set_id)
            .then(|| self.artifact_set.clone()))
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-10-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("egopulse-g4-10-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn task_handoff_reads_artifacts_commits_verification_and_acks_task_outbox() {
    let root = TempRoot::new();
    let acceptance = contract("task-acceptance", SHA_A);
    let mut task = TaskAuthority::open_with_transition_guard(
        egopulse_cognition_runtime::task_authority::TaskAuthorityConfig {
            database_path: root.path().join("task.db"),
            store_epoch: "g4-10-task".to_owned(),
            key: SqlCipherKey::new([31; 32]),
        },
        AllowCreation,
        AllowTransitions,
    )
    .expect("open task authority");
    let created = task_snapshot(
        task.execute(
            &signed_task_command(create_command(&acceptance)),
            &founder(),
        )
        .expect("create task"),
    );
    let active = task_snapshot(
        task.execute(
            &signed_task_command(activate_command(&created)),
            &collaboration_control(),
        )
        .expect("activate task"),
    );
    let activation_handoff = task
        .pending_cross_authority_outbox()
        .expect("read activation outbox")
        .into_iter()
        .find(|message| message.destination_domain == "collaboration-control")
        .expect("activation handoff");
    assert!(
        task.acknowledge_cross_authority_outbox(
            &activation_handoff.message_id,
            &activation_handoff.payload_digest_sha256,
        )
        .expect("ack activation handoff")
    );
    let lineage = LineageBinding {
        task_id: created.task_id.clone(),
        task_revision: 3,
        work_revision: 1,
        run_id: "run-g4-10".to_owned(),
        run_revision: 1,
        step_id: "step-g4-10".to_owned(),
        step_revision: 1,
        attempt_id: "attempt-g4-10".to_owned(),
        attempt_revision: 1,
        dispatch_id: "dispatch-g4-10".to_owned(),
        fencing_token: 1,
    };
    let semantic = contract("claim-semantic", SHA_B);
    let manifest = ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: "c".repeat(64),
        byte_length: 128,
    };
    let artifact_set = ArtifactSet {
        artifact_set_id: "artifact-set-g4-10".to_owned(),
        revision: 1,
        status: ArtifactSetStatus::Sealed as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec!["attestation-artifact-g4-10".to_owned()],
        claim_ids: vec!["claim-g4-10".to_owned()],
        evidence_ids: vec!["evidence-g4-10".to_owned()],
        canonical_manifest: Some(manifest.clone()),
        ..ArtifactSet::default()
    };
    let artifact = ArtifactDescriptor {
        artifact_id: "attestation-artifact-g4-10".to_owned(),
        revision: 1,
        status: ArtifactStatus::Sealed as i32,
        integrity_status: IntegrityStatus::DigestVerified as i32,
        content: Some(ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: "d".repeat(64),
            byte_length: 32,
        }),
        provenance: Some(Provenance {
            lineage: Some(lineage.clone()),
            ..Provenance::default()
        }),
        ..ArtifactDescriptor::default()
    };
    let claim = Claim {
        claim_id: "claim-g4-10".to_owned(),
        revision: 1,
        status: ClaimStatus::Proposed as i32,
        source_type: ClaimSourceType::CodeChange as i32,
        semantic_profile_ref: Some(semantic.clone()),
        lineage: Some(lineage.clone()),
        acceptance_contract_ref: Some(acceptance.clone()),
        ..Claim::default()
    };
    let evidence = Evidence {
        evidence_id: "evidence-g4-10".to_owned(),
        revision: 1,
        status: EvidenceStatus::Recorded as i32,
        relation: EvidenceRelation::Supports as i32,
        claim_id: claim.claim_id.clone(),
        artifact_ids: artifact_set.artifact_ids.clone(),
        lineage: Some(lineage.clone()),
        producer_class: EvidenceProducerClass::DeterministicChecker as i32,
        integrity_status: IntegrityStatus::DigestVerified as i32,
        ..Evidence::default()
    };
    let source = StaticArtifactSource {
        artifact_set,
        artifact,
        claim,
        evidence,
    };
    let profile = checker_profile();
    let profile_ref = ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    };
    let resolver = ArtifactBackedReferenceResolver::new(
        source.clone(),
        vec![CriterionPolicySnapshot {
            criterion_id: "criterion-g4-10".to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::ModelAssisted as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![profile.checker_profile_id.clone()],
        }],
    )
    .expect("valid artifact-backed verification resolver");
    let mut verification = VerificationAuthority::open(
        VerificationAuthorityConfig {
            database_path: root.path().join("verification.db"),
            store_epoch: "g4-10-verification".to_owned(),
            key: VerificationSqlCipherKey::new([73; 32]),
        },
        resolver,
    )
    .expect("open verification authority");
    let verification_principal = AuthenticatedVerificationPrincipal {
        kind: VerificationPrincipalKind::VerificationAuthority,
        principal_id: "verification-authority:g4-10".to_owned(),
        authenticated: true,
        checker_profile_id: None,
    };
    let attest = signed_verification_command(VerificationCommand {
        command: Some(verification_command::Command::AttestCheckerProfile(
            AttestCheckerProfileCommand {
                metadata: Some(metadata("attest-profile", "verification")),
                profile: Some(profile.clone()),
            },
        )),
    });
    assert!(
        verification
            .execute(&attest, &verification_principal)
            .expect("attest checker profile")
            .committed
    );

    let pending = task_snapshot(
        task.execute(
            &signed_task_command(evidence_command(&active)),
            &collaboration_control(),
        )
        .expect("submit task evidence"),
    );
    assert_eq!(pending.status, TaskStatus::VerificationPending as i32);
    assert_eq!(pending.revision, 3);

    let task = Arc::new(Mutex::new(task));
    let verification = Arc::new(Mutex::new(verification));
    let intake = VerificationHandoffIntake::new(
        Arc::clone(&task),
        Box::new(source.clone()),
        Arc::clone(&verification),
        VerificationHandoffPlan {
            binding: VerificationBindingTemplate {
                claim_id: "claim-g4-10".to_owned(),
                claim_semantic_profile_ref: semantic,
            },
            criterion_ids: vec!["criterion-g4-10".to_owned()],
            checker_profile_refs: vec![profile_ref.clone()],
        },
        AuthenticatedVerificationPrincipal {
            kind: VerificationPrincipalKind::TaskAuthority,
            principal_id: "task-authority:g4-10".to_owned(),
            authenticated: true,
            checker_profile_id: None,
        },
    )
    .expect("valid handoff intake");
    let result = intake
        .consume_one(timestamp())
        .expect("consume task verification handoff")
        .expect("one pending handoff");
    assert!(result.committed);
    assert!(!result.replayed);
    assert!(result.task_outbox_acknowledged);
    assert_eq!(
        verification
            .lock()
            .expect("verification lock")
            .inspect_store()
            .expect("verification inspection")
            .request_count,
        1
    );
    assert!(
        task.lock()
            .expect("task lock")
            .pending_task_verifications()
            .expect("pending handoffs")
            .is_empty()
    );
    assert!(
        intake
            .consume_one(timestamp())
            .expect("replay-safe empty poll")
            .is_none()
    );

    let mapper_profile_ref = profile_ref.clone();
    let worker = ConfiguredVerificationWorker::new(
        Arc::clone(&task),
        Box::new(source),
        Arc::clone(&verification),
        VerificationWorkerConfig {
            handoff_plan: VerificationHandoffPlan {
                binding: VerificationBindingTemplate {
                    claim_id: "claim-g4-10".to_owned(),
                    claim_semantic_profile_ref: contract("claim-semantic", SHA_B),
                },
                criterion_ids: vec!["criterion-g4-10".to_owned()],
                checker_profile_refs: vec![mapper_profile_ref.clone()],
            },
            checker_profile: profile,
            checker_executable: std::env::current_exe().expect("current test executable"),
            checker_arguments: vec![
                "--exact".to_owned(),
                "checker_invalid_output_probe".to_owned(),
                "--nocapture".to_owned(),
            ],
            working_directory: root.path().to_owned(),
            checker_request: b"{}".to_vec(),
            mapper_policy: egopulse_verification_authority::SegoMapperPolicy {
                criterion_id: "criterion-g4-10".to_owned(),
                requirement: CriterionRequirement::MustPass,
                checker_profile_ref: mapper_profile_ref,
                expected_scope: "g4-10".to_owned(),
                expected_diff_hash: SHA_A.to_owned(),
                expected_reviewer: "sego".to_owned(),
                expected_engine_version: "v1".to_owned(),
                expected_review_mode: "model_code_review".to_owned(),
                failure_threshold: DiscrepancySeverity::Major,
                raw_output_artifact_id: "attestation-artifact-g4-10".to_owned(),
                raw_output_address: ContentAddress {
                    algorithm: HashAlgorithm::Sha256 as i32,
                    digest: "e".repeat(64),
                    byte_length: 16,
                },
                finding_evidence: BTreeMap::new(),
            },
            verification_run_id_prefix: "worker-run-".to_owned(),
            verification_artifact_id_prefix: "worker-artifact-".to_owned(),
            execution_id_prefix: "worker-execution-".to_owned(),
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: Vec::new(),
            checker_timeout: std::time::Duration::from_secs(2),
            checker_output_limit: 64 * 1024,
        },
    )
    .expect("compose configured verification worker");
    let first = worker
        .run_once()
        .await
        .expect("run governed verification worker");
    assert!(matches!(
        first,
        egopulse_agentosd::VerificationWorkerCycleResult::Completed {
            execution_replayed: false,
            write_back_replayed: false,
            ..
        }
    ));
    let written = task
        .lock()
        .expect("task lock")
        .get_task(&created.task_id)
        .expect("read written task");
    let task_after_write = match written.outcome.expect("task outcome") {
        get_task_response::Outcome::Task(snapshot) => snapshot,
        get_task_response::Outcome::Error(error) => panic!("unexpected task error: {error:?}"),
    };
    assert_eq!(task_after_write.status, TaskStatus::VerdictPending as i32);
    assert!(
        task_after_write
            .verification_artifact_id
            .as_deref()
            .is_some_and(|value| value.starts_with("worker-artifact-verification-request-"))
    );
    let second = worker
        .run_once()
        .await
        .expect("replay completed worker and write-back");
    assert!(matches!(
        second,
        egopulse_agentosd::VerificationWorkerCycleResult::Completed {
            execution_replayed: true,
            write_back_replayed: true,
            ..
        }
    ));
}

fn contract(id: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: digest.to_owned(),
    }
}

fn metadata(label: &str, scope: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command-{label}"),
        idempotency_key: format!("key-{label}"),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(timestamp()),
        correlation_id: format!("correlation-{label}"),
        causation_id: None,
    }
}

fn timestamp() -> Timestamp {
    Timestamp {
        seconds: 1_782_000_000,
        nanos: 0,
    }
}

fn create_command(acceptance: &ContractReference) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata("create-task", "g4-10-task")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-g4-10".to_owned(),
            target_scope_ref: "scope-g4-10".to_owned(),
            acceptance_contract_ref: Some(acceptance.clone()),
            budget_profile_ref: Some(contract("budget", SHA_B)),
        })),
    }
}

fn activate_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(metadata("activate-task", "g4-10-task")),
            task_id: task.task_id.clone(),
            expected_revision: task.revision,
            work_revision: task.work_revision,
            run_id: "run-g4-10".to_owned(),
        })),
    }
}

fn evidence_command(task: &TaskSnapshot) -> TaskCommand {
    TaskCommand {
        command: Some(task_command::Command::SubmitTaskEvidence(
            SubmitTaskEvidenceCommand {
                meta: Some(metadata("submit-evidence", "g4-10-task")),
                task_id: task.task_id.clone(),
                expected_revision: task.revision,
                work_revision: task.work_revision,
                return_handoff_id: "return-handoff-g4-10".to_owned(),
                artifact_set_id: "artifact-set-g4-10".to_owned(),
            },
        )),
    }
}

fn signed_task_command(mut command: TaskCommand) -> TaskCommand {
    let digest = canonical_task_request_digest(&command).expect("task command digest");
    match command.command.as_mut().expect("task operation") {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        _ => unreachable!("G4-10 uses only task handoff operations"),
    }
    .expect("task metadata")
    .request_digest_sha256 = digest;
    command
}

fn signed_verification_command(mut command: VerificationCommand) -> VerificationCommand {
    let digest = canonical_request_digest(&command).expect("verification command digest");
    match command.command.as_mut().expect("verification operation") {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        _ => unreachable!("G4-10 signs only the checker profile attestation"),
    }
    .expect("verification metadata")
    .request_digest_sha256 = digest;
    command
}

fn task_snapshot(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("task command outcome") {
        task_command_result::Outcome::Task(task) => task,
        task_command_result::Outcome::Error(error) => panic!("unexpected task error: {error:?}"),
    }
}

fn founder() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "founder:g4-10".to_owned(),
        authenticated: true,
    }
}

fn collaboration_control() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:g4-10".to_owned(),
        authenticated: true,
    }
}

fn checker_profile() -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: "contract-checker-g4-10".to_owned(),
        revision: 0,
        status: CheckerProfileStatus::Unspecified as i32,
        checker_id: "deterministic:contract-checker".to_owned(),
        checker_version: "v1".to_owned(),
        input_contract_ref: Some(contract("verification-input", SHA_A)),
        output_contract_ref: Some(contract("verification-output", SHA_B)),
        supported_criterion_types: vec!["criterion-g4-10".to_owned()],
        assurance_class: CheckerAssuranceClass::ModelAssisted as i32,
        sandbox_profile_ref: Some(contract("verification-sandbox", SHA_A)),
        tool_policy_ref: Some(contract("verification-tools", SHA_B)),
        data_egress_policy_ref: Some(contract("local-only", SHA_A)),
        timeout_ms: 1_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec!["attestation-artifact-g4-10".to_owned()],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}
