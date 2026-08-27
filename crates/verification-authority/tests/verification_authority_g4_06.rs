use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
    CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
    CriterionRequirement, CriterionResult, DiscrepancySeverity, EvidenceCoverage,
    RecordCriterionResultCommand, StartVerificationRunCommand, VerificationArtifact,
    VerificationBinding, VerificationCommand, VerificationConclusion, VerificationErrorCode,
    VerificationProvenance, VerificationRequest, VerificationStatus, verification_command,
};
use egopulse_verification_authority::{
    AuthenticatedVerificationPrincipal, CheckerExecutionError, CheckerProcessFailure,
    CriterionPolicySnapshot, GovernedCheckerSupervisor, GovernedSegoRunner,
    GovernedVerificationExecutionCoordinator, GovernedVerificationExecutionPlan,
    ReferenceRejection, ResolvedVerificationInput, SegoFindingEvidenceBinding, SegoMapError,
    SegoMapperPolicy, VerificationAuthority, VerificationAuthorityConfig, VerificationClock,
    VerificationPrincipalKind, VerificationReferenceResolver, VerificationSqlCipherKey,
    canonical_checker_profile_digest, canonical_request_digest, checker_failure_result,
    map_sego_review,
};
use prost_types::Timestamp;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Clone, Copy)]
struct FixedClock;

impl VerificationClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }
    }
}

#[derive(Clone)]
struct StaticResolver {
    binding: VerificationBinding,
    criteria: Vec<CriterionPolicySnapshot>,
    evidence_ids: BTreeSet<String>,
    artifact_ids: BTreeSet<String>,
}

impl VerificationReferenceResolver for StaticResolver {
    fn validate_checker_profile(&self, profile: &CheckerProfile) -> Result<(), ReferenceRejection> {
        if profile
            .attestation_evidence_artifact_ids
            .iter()
            .all(|id| self.evidence_ids.contains(id))
        {
            Ok(())
        } else {
            Err(ReferenceRejection::EvidenceIncomplete)
        }
    }

    fn resolve_request(
        &self,
        request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        if request.binding.as_ref() != Some(&self.binding) {
            return Err(ReferenceRejection::BindingStale);
        }
        Ok(ResolvedVerificationInput {
            artifact_set_status: ArtifactSetStatus::Sealed,
            binding: self.binding.clone(),
            criteria: self.criteria.clone(),
            evidence_ids: self.evidence_ids.clone(),
        })
    }

    fn revalidate_binding(&self, binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        if binding == &self.binding {
            Ok(())
        } else {
            Err(ReferenceRejection::BindingStale)
        }
    }

    fn validate_result_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        if evidence_ids.iter().all(|id| self.evidence_ids.contains(id))
            && artifact_ids.iter().all(|id| self.artifact_ids.contains(id))
        {
            Ok(())
        } else {
            Err(ReferenceRejection::EvidenceIncomplete)
        }
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-06-{name}-{}", Uuid::now_v7()));
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
            .is_some_and(|value| value.starts_with("egopulse-g4-06-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

struct RunningFixture {
    _root: TempRoot,
    authority: VerificationAuthority<FixedClock>,
    authority_principal: AuthenticatedVerificationPrincipal,
    checker_principal: AuthenticatedVerificationPrincipal,
    profile_ref: ContractReference,
    request: VerificationRequest,
    run_id: String,
}

#[test]
fn sego_mapper_preserves_failed_unverified_and_parser_error_as_distinct_states() {
    let policy = mapper_policy();
    let failed = map_sego_review(&sego_review_with_verified_major(), &policy)
        .expect("valid Sego artifact maps");
    assert_eq!(
        failed.criterion_result.outcome,
        CriterionOutcome::Failed as i32
    );
    assert_eq!(
        failed.criterion_result.evidence_coverage,
        EvidenceCoverage::Complete as i32
    );
    assert_eq!(failed.discrepancies.len(), 1);
    assert!(failed.unverified_items.is_empty());

    let zero_findings = map_sego_review(&sego_review_with_zero_findings(), &policy)
        .expect("zero findings remains explicit");
    assert_eq!(
        zero_findings.criterion_result.outcome,
        CriterionOutcome::Unverified as i32
    );
    assert_eq!(zero_findings.unverified_items.len(), 1);

    let parser_error = map_sego_review(&sego_review_with_parser_error(), &policy)
        .expect("parser error maps to checker error");
    assert_eq!(
        parser_error.criterion_result.outcome,
        CriterionOutcome::Error as i32
    );
    assert_ne!(
        parser_error.criterion_result.outcome,
        CriterionOutcome::Failed as i32
    );

    for failure in [
        CheckerProcessFailure::Unavailable,
        CheckerProcessFailure::Timeout,
        CheckerProcessFailure::Crashed,
        CheckerProcessFailure::OutputUntrusted,
    ] {
        let checker_error = checker_failure_result(&policy, "execution-01", failure);
        assert_eq!(
            checker_error.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
        assert_ne!(
            checker_error.criterion_result.outcome,
            CriterionOutcome::Failed as i32
        );
    }
}

#[test]
fn explicit_positive_acceptance_mode_maps_structured_zero_findings_to_passed() {
    let mut policy = mapper_policy();
    policy.positive_acceptance = true;
    let mapped = map_sego_review(&sego_review_with_zero_findings(), &policy)
        .expect("positive acceptance output maps");
    assert_eq!(
        mapped.criterion_result.outcome,
        CriterionOutcome::Passed as i32
    );
    assert_eq!(
        mapped.criterion_result.evidence_coverage,
        EvidenceCoverage::Complete as i32
    );
    assert!(mapped.criterion_result.unverified_item_ids.is_empty());
}

#[test]
fn sego_mapper_rejects_unattested_version_and_stale_input_binding() {
    let policy = mapper_policy();
    let mut stale_version: serde_json::Value =
        serde_json::from_slice(&sego_review_with_zero_findings()).expect("review JSON");
    stale_version["engine_version"] = json!("0.1.8");
    let stale_version = serde_json::to_vec(&stale_version).expect("stale version JSON");
    assert_eq!(
        map_sego_review(&stale_version, &policy),
        Err(SegoMapError::ProfileMismatch)
    );

    let mut stale_binding: serde_json::Value =
        serde_json::from_slice(&sego_review_with_zero_findings()).expect("review JSON");
    stale_binding["diff_hash"] = json!(SHA_B);
    let stale_binding = serde_json::to_vec(&stale_binding).expect("stale binding JSON");
    assert_eq!(
        map_sego_review(&stale_binding, &policy),
        Err(SegoMapError::BindingMismatch)
    );
}

#[test]
fn immutable_verification_artifact_commit_is_atomic_and_duplicate_safe() {
    let mut fixture = running_fixture("atomic", CheckerAssuranceClass::ModelAssisted);
    let mapped = map_sego_review(&sego_review_with_verified_major(), &mapper_policy())
        .expect("Sego output maps");
    let record = record_command(&fixture, mapped.criterion_result.clone(), "record-1");
    let record_result = fixture
        .authority
        .execute(&record, &fixture.checker_principal)
        .expect("record criterion");
    assert!(record_result.committed);
    assert_eq!(record_result.run.as_ref().expect("run").revision, 2);

    let complete = complete_command(
        &fixture,
        mapped.criterion_result,
        mapped.discrepancies,
        mapped.unverified_items,
        VerificationConclusion::Failed,
        EvidenceCoverage::Complete,
        "complete-1",
    );
    let completed = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete verification");
    assert!(completed.committed);
    assert_eq!(
        completed.artifact.as_ref().expect("artifact").conclusion,
        VerificationConclusion::Failed as i32
    );
    assert!(
        completed
            .artifact
            .as_ref()
            .expect("artifact")
            .canonical_payload
            .is_some()
    );
    assert_eq!(
        fixture
            .authority
            .verification_request(&fixture.request.verification_request_id)
            .expect("read request snapshot")
            .expect("request exists")
            .status,
        VerificationStatus::Completed as i32
    );
    assert_eq!(
        fixture
            .authority
            .verification_run(&fixture.run_id)
            .expect("read run snapshot")
            .expect("run exists")
            .status,
        VerificationStatus::Completed as i32
    );

    let replay = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("replay completion");
    assert!(replay.replayed);
    assert_eq!(replay.artifact, completed.artifact);

    let mut conflicting = complete.clone();
    if let Some(verification_command::Command::CompleteVerification(value)) =
        conflicting.command.as_mut()
    {
        value
            .artifact
            .as_mut()
            .expect("artifact")
            .verification_artifact_id = "verification-artifact-conflict".to_owned();
        value
            .metadata
            .as_mut()
            .expect("metadata")
            .request_digest_sha256
            .clear();
    }
    let conflicting = seal_command(conflicting, "complete-1");
    let conflict = fixture
        .authority
        .execute(&conflicting, &fixture.authority_principal)
        .expect("idempotency conflict");
    assert!(!conflict.committed);
    assert_eq!(
        conflict.error_code,
        VerificationErrorCode::IdempotencyConflict as i32
    );

    let inspection = fixture.authority.inspect_store().expect("inspect store");
    assert_eq!(inspection.checker_profile_count, 1);
    assert_eq!(inspection.request_count, 1);
    assert_eq!(inspection.run_count, 1);
    assert_eq!(inspection.criterion_result_count, 1);
    assert_eq!(inspection.verification_artifact_count, 1);
    assert_eq!(inspection.event_count, 5);
    assert_eq!(inspection.idempotency_count, 5);
    assert_eq!(inspection.commit_receipt_count, 5);
    assert_eq!(inspection.outbox_count, 7);
}

#[test]
fn verification_projection_feed_is_typed_and_ack_is_commit_ordered() {
    let mut fixture = running_fixture("projection-feed", CheckerAssuranceClass::Deterministic);
    let pending = fixture
        .authority
        .drain_projection_outbox()
        .expect("drain Verification projection outbox");
    assert!(!pending.is_empty());
    assert!(pending.iter().all(|message| message.result.committed));
    let first = &pending[0];
    assert!(
        !fixture
            .authority
            .acknowledge_projection(&first.message_id, &"0".repeat(64))
            .expect("reject mismatched Verification ACK")
    );
    assert!(
        fixture
            .authority
            .acknowledge_projection(&first.message_id, &first.payload_digest_sha256)
            .expect("ack Verification projection")
    );
    assert_eq!(
        fixture
            .authority
            .drain_projection_outbox()
            .expect("Verification projection after ACK")
            .len(),
        pending.len() - 1
    );
    let baselines = fixture
        .authority
        .projection_baselines()
        .expect("Verification projection baselines");
    assert_eq!(baselines.len(), 3);
    assert!(baselines.iter().all(|message| message.result.committed));
}

#[test]
fn deterministic_complete_evidence_can_produce_strict_passed() {
    let mut fixture = running_fixture("passed", CheckerAssuranceClass::Deterministic);
    let result = CriterionResult {
        criterion_result_id: "criterion-result-passed".to_owned(),
        criterion_id: "review".to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        outcome: CriterionOutcome::Passed as i32,
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        checker_profile_ref: Some(fixture.profile_ref.clone()),
        evidence_coverage: EvidenceCoverage::Complete as i32,
        evidence_ids: vec!["evidence-review".to_owned()],
        discrepancy_ids: Vec::new(),
        unverified_item_ids: Vec::new(),
        duration_ms: 12,
        safe_detail_artifact_id: Some("raw-sego-output".to_owned()),
    };
    let record = record_command(&fixture, result.clone(), "record-passed");
    assert!(
        fixture
            .authority
            .execute(&record, &fixture.checker_principal)
            .expect("record deterministic result")
            .committed
    );
    let complete = complete_command(
        &fixture,
        result,
        Vec::new(),
        Vec::new(),
        VerificationConclusion::Passed,
        EvidenceCoverage::Complete,
        "complete-passed",
    );
    let completed = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete passed");
    assert_eq!(
        completed.artifact.expect("artifact").conclusion,
        VerificationConclusion::Passed as i32
    );
}

#[test]
fn sego_zero_findings_completes_as_indeterminate_not_passed() {
    let mut fixture = running_fixture("unverified", CheckerAssuranceClass::ModelAssisted);
    let mapped = map_sego_review(&sego_review_with_zero_findings(), &mapper_policy())
        .expect("zero findings maps");
    let record = record_command(
        &fixture,
        mapped.criterion_result.clone(),
        "record-unverified",
    );
    assert!(
        fixture
            .authority
            .execute(&record, &fixture.checker_principal)
            .expect("record unverified")
            .committed
    );
    let complete = complete_command(
        &fixture,
        mapped.criterion_result,
        mapped.discrepancies,
        mapped.unverified_items,
        VerificationConclusion::Indeterminate,
        EvidenceCoverage::Missing,
        "complete-unverified",
    );
    let completed = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete indeterminate");
    assert_eq!(
        completed.artifact.expect("artifact").conclusion,
        VerificationConclusion::Indeterminate as i32
    );
}

#[test]
fn checker_cannot_rewrite_acceptance_requirement_or_gain_terminal_authority() {
    let mut fixture = running_fixture("policy", CheckerAssuranceClass::ModelAssisted);
    let mut forged = map_sego_review(&sego_review_with_verified_major(), &mapper_policy())
        .expect("Sego output maps")
        .criterion_result;
    forged.requirement = CriterionRequirement::ShouldPass as i32;
    let record = record_command(&fixture, forged, "record-forged");
    let rejected = fixture
        .authority
        .execute(&record, &fixture.checker_principal)
        .expect("domain rejection");
    assert!(!rejected.committed);
    assert_eq!(
        rejected.error_code,
        VerificationErrorCode::CheckerProfileMismatch as i32
    );

    let mapped = map_sego_review(&sego_review_with_verified_major(), &mapper_policy())
        .expect("Sego output maps");
    let forged_complete = complete_command(
        &fixture,
        mapped.criterion_result,
        mapped.discrepancies,
        mapped.unverified_items,
        VerificationConclusion::Failed,
        EvidenceCoverage::Complete,
        "checker-terminal-write",
    );
    let checker_terminal = fixture
        .authority
        .execute(&forged_complete, &fixture.checker_principal)
        .expect("permission rejection");
    assert!(!checker_terminal.committed);
    assert_eq!(
        checker_terminal.error_code,
        VerificationErrorCode::PermissionDenied as i32
    );

    let inspection = fixture.authority.inspect_store().expect("inspect store");
    assert_eq!(inspection.criterion_result_count, 0);
    assert_eq!(inspection.verification_artifact_count, 0);
    assert_eq!(inspection.event_count, 3);
}

#[test]
fn checker_error_completes_as_indeterminate_not_claim_failure() {
    let mut fixture = running_fixture("checker-error", CheckerAssuranceClass::ModelAssisted);
    let mapped = map_sego_review(&sego_review_with_parser_error(), &mapper_policy())
        .expect("parser failure maps");
    let record = record_command(&fixture, mapped.criterion_result.clone(), "record-error");
    assert!(
        fixture
            .authority
            .execute(&record, &fixture.checker_principal)
            .expect("record checker error")
            .committed
    );
    let complete = complete_command(
        &fixture,
        mapped.criterion_result,
        mapped.discrepancies,
        mapped.unverified_items,
        VerificationConclusion::Indeterminate,
        EvidenceCoverage::Missing,
        "complete-indeterminate",
    );
    let result = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete indeterminate");
    assert_eq!(
        result.artifact.expect("artifact").conclusion,
        VerificationConclusion::Indeterminate as i32
    );
}

#[test]
fn private_verification_store_does_not_escape_the_owner_crate() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_root
        .parent()
        .and_then(Path::parent)
        .expect("workspace");
    let mut leaks = Vec::new();
    for root in [workspace.join("apps"), workspace.join("crates")] {
        scan_rust_sources(&root, &crate_root, &mut leaks);
    }
    assert!(leaks.is_empty(), "private store leaked: {leaks:?}");
}

#[tokio::test]
async fn governed_checker_supervisor_distinguishes_timeout_crash_and_output_limit() {
    let executable = std::env::current_exe().expect("test executable");

    let timeout_root = TempRoot::new("checker-timeout");
    fs::write(timeout_root.path().join("timeout.marker"), b"1").expect("marker");
    let timeout = GovernedCheckerSupervisor::new(
        executable.clone(),
        vec![
            "--exact".to_owned(),
            "checker_timeout_probe".to_owned(),
            "--nocapture".to_owned(),
        ],
        Duration::from_millis(100),
        64 * 1024,
    )
    .expect("supervisor");
    assert_eq!(
        timeout.run(timeout_root.path(), b"{}").await,
        Err(CheckerExecutionError::Timeout)
    );

    let crash_root = TempRoot::new("checker-crash");
    fs::write(crash_root.path().join("crash.marker"), b"1").expect("marker");
    let crash = GovernedCheckerSupervisor::new(
        executable,
        vec![
            "--exact".to_owned(),
            "checker_crash_probe".to_owned(),
            "--nocapture".to_owned(),
        ],
        Duration::from_secs(2),
        64 * 1024,
    )
    .expect("supervisor");
    assert_eq!(
        crash.run(crash_root.path(), b"{}").await,
        Err(CheckerExecutionError::Crashed)
    );

    let output_root = TempRoot::new("checker-output-limit");
    fs::write(output_root.path().join("output-limit.marker"), b"1").expect("marker");
    let output_limited = GovernedCheckerSupervisor::new(
        std::env::current_exe().expect("test executable"),
        vec![
            "--exact".to_owned(),
            "checker_output_limit_probe".to_owned(),
            "--nocapture".to_owned(),
        ],
        Duration::from_secs(2),
        128,
    )
    .expect("supervisor");
    assert_eq!(
        output_limited.run(output_root.path(), b"{}").await,
        Err(CheckerExecutionError::OutputLimit)
    );
}

#[tokio::test]
async fn governed_sego_runner_maps_untrusted_output_without_dropping_receipt() {
    let root = TempRoot::new("sego-runner-untrusted");
    let runner = GovernedSegoRunner::new(
        GovernedCheckerSupervisor::new(
            std::env::current_exe().expect("test executable"),
            vec![
                "--exact".to_owned(),
                "checker_invalid_output_probe".to_owned(),
                "--nocapture".to_owned(),
            ],
            Duration::from_secs(2),
            64 * 1024,
        )
        .expect("supervisor"),
    );

    let result = runner
        .run(
            root.path(),
            b"{}",
            "execution-untrusted-01",
            &mapper_policy(),
        )
        .await
        .expect("runner result");
    assert_eq!(result.failure, Some(CheckerProcessFailure::OutputUntrusted));
    assert!(result.receipt.is_some());
    assert_eq!(
        result.mapped.criterion_result.outcome,
        CriterionOutcome::Error as i32
    );
}

#[tokio::test]
async fn governed_execution_coordinator_records_completes_and_replays() {
    let fixture = running_fixture(
        "execution-coordinator",
        CheckerAssuranceClass::ModelAssisted,
    );
    let mut authority = fixture.authority;
    let mut request = fixture.request.clone();
    request.verification_request_id = "verification-request-coordinator".to_owned();
    let create = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata("coordinator-create")),
                    request: Some(request.clone()),
                },
            )),
        },
        "coordinator-create",
    );
    assert!(
        authority
            .execute(
                &create,
                &principal(
                    VerificationPrincipalKind::TaskAuthority,
                    "agentosd:task-authority",
                    None,
                ),
            )
            .expect("create coordinator request")
            .committed
    );
    let authority = Arc::new(Mutex::new(authority));
    let runner = GovernedSegoRunner::new(
        GovernedCheckerSupervisor::new(
            std::env::current_exe().expect("test executable"),
            vec![
                "--exact".to_owned(),
                "checker_invalid_output_probe".to_owned(),
                "--nocapture".to_owned(),
            ],
            Duration::from_secs(2),
            64 * 1024,
        )
        .expect("supervisor"),
    );
    let coordinator = GovernedVerificationExecutionCoordinator::new(Arc::clone(&authority), runner);
    let plan = GovernedVerificationExecutionPlan {
        verification_request_id: request.verification_request_id.clone(),
        verification_run_id: "verification-run-coordinator".to_owned(),
        execution_id: "execution-coordinator-01".to_owned(),
        working_directory: fixture._root.path().to_owned(),
        checker_request: b"{}".to_vec(),
        mapper_policy: mapper_policy(),
        verification_artifact_id: "verification-artifact-coordinator".to_owned(),
        tool_receipt_artifact_ids: Vec::new(),
        model_call_receipt_artifact_ids: vec!["model-call-receipt".to_owned()],
        issued_at: Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        },
    };
    let completed = coordinator
        .execute_one(plan.clone())
        .await
        .expect("coordinator completes verification");
    assert!(!completed.replayed);
    assert!(!completed.recovered_existing_result);
    assert_eq!(
        completed.verification_artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );

    let replay = coordinator
        .execute_one(plan)
        .await
        .expect("completed execution is recoverable");
    assert!(replay.replayed);
    assert!(replay.recovered_existing_result);
    assert_eq!(
        replay.verification_artifact,
        completed.verification_artifact
    );
    let authority = authority.lock().expect("authority lock");
    assert_eq!(
        authority
            .verification_run("verification-run-coordinator")
            .expect("run snapshot")
            .expect("run")
            .status,
        VerificationStatus::Completed as i32
    );
}

#[test]
fn checker_timeout_probe() {
    if Path::new("timeout.marker").exists() {
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[test]
fn checker_crash_probe() {
    if Path::new("crash.marker").exists() {
        panic!("intentional checker crash probe");
    }
}

#[test]
fn checker_output_limit_probe() {
    if Path::new("output-limit.marker").exists() {
        print!("{}", "x".repeat(4096));
    }
}

#[test]
fn checker_invalid_output_probe() {
    print!("not-a-review-artifact");
}

fn running_fixture(name: &str, assurance: CheckerAssuranceClass) -> RunningFixture {
    let root = TempRoot::new(name);
    let binding = binding();
    let profile = checker_profile(assurance);
    let profile_ref = profile_ref(&profile);
    let policy = CriterionPolicySnapshot {
        criterion_id: "review".to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        minimum_assurance: assurance as i32,
        not_applicable_allowed: false,
        checker_profile_ids: vec![profile.checker_profile_id.clone()],
    };
    let resolver = StaticResolver {
        binding: binding.clone(),
        criteria: vec![policy],
        evidence_ids: ["attest-evidence", "evidence-review"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        artifact_ids: [
            "raw-sego-output",
            "finding-description",
            "finding-fix",
            "model-call-receipt",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    };
    let mut authority = VerificationAuthority::open_with_clock(
        VerificationAuthorityConfig {
            database_path: root.path().join("verification.db"),
            store_epoch: "g4-06-test-epoch".to_owned(),
            key: VerificationSqlCipherKey::new([0x46; 32]),
        },
        resolver,
        FixedClock,
    )
    .expect("open authority");
    let authority_principal = principal(
        VerificationPrincipalKind::VerificationAuthority,
        "agentosd:verification-authority",
        None,
    );
    let checker_kind = if assurance == CheckerAssuranceClass::Deterministic {
        VerificationPrincipalKind::DeterministicChecker
    } else {
        VerificationPrincipalKind::SegoChecker
    };
    let checker_principal = principal(
        checker_kind,
        "checker:sego-review",
        Some(profile.checker_profile_id.clone()),
    );
    let attest = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::AttestCheckerProfile(
                AttestCheckerProfileCommand {
                    metadata: Some(metadata("attest-profile")),
                    profile: Some(profile),
                },
            )),
        },
        "attest-profile",
    );
    assert!(
        authority
            .execute(&attest, &authority_principal)
            .expect("attest profile")
            .committed
    );

    let request = VerificationRequest {
        verification_request_id: "verification-request-01".to_owned(),
        revision: 1,
        status: VerificationStatus::Queued as i32,
        verification_type: "task_acceptance".to_owned(),
        binding: Some(binding),
        criterion_ids: vec!["review".to_owned()],
        checker_profile_refs: vec![profile_ref.clone()],
        created_at: None,
        hold_reason_code: None,
    };
    let create = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata("create-request")),
                    request: Some(request.clone()),
                },
            )),
        },
        "create-request",
    );
    assert!(
        authority
            .execute(
                &create,
                &principal(
                    VerificationPrincipalKind::TaskAuthority,
                    "agentosd:task-authority",
                    None,
                ),
            )
            .expect("create request")
            .committed
    );
    let run_id = "verification-run-01".to_owned();
    let start = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::StartVerificationRun(
                StartVerificationRunCommand {
                    metadata: Some(metadata("start-run")),
                    verification_request_id: request.verification_request_id.clone(),
                    expected_request_revision: 1,
                    verification_run_id: run_id.clone(),
                },
            )),
        },
        "start-run",
    );
    assert!(
        authority
            .execute(&start, &authority_principal)
            .expect("start run")
            .committed
    );
    RunningFixture {
        _root: root,
        authority,
        authority_principal,
        checker_principal,
        profile_ref,
        request,
        run_id,
    }
}

fn record_command(
    fixture: &RunningFixture,
    result: CriterionResult,
    id: &str,
) -> VerificationCommand {
    seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::RecordCriterionResult(
                RecordCriterionResultCommand {
                    metadata: Some(metadata(id)),
                    verification_run_id: fixture.run_id.clone(),
                    expected_run_revision: 1,
                    result: Some(result),
                },
            )),
        },
        id,
    )
}

fn complete_command(
    fixture: &RunningFixture,
    result: CriterionResult,
    discrepancies: Vec<egopulse_domain_contracts::v01::egopulse::verification::v1::Discrepancy>,
    unverified_items: Vec<
        egopulse_domain_contracts::v01::egopulse::verification::v1::UnverifiedItem,
    >,
    conclusion: VerificationConclusion,
    coverage: EvidenceCoverage,
    id: &str,
) -> VerificationCommand {
    let artifact = VerificationArtifact {
        verification_artifact_id: "verification-artifact-01".to_owned(),
        version: 1,
        verification_request_id: fixture.request.verification_request_id.clone(),
        verification_run_id: fixture.run_id.clone(),
        verification_type: fixture.request.verification_type.clone(),
        binding: fixture.request.binding.clone(),
        conclusion: conclusion as i32,
        overall_evidence_coverage: coverage as i32,
        criterion_results: vec![result],
        discrepancies,
        unverified_items,
        provenance: Some(VerificationProvenance {
            verifier_principal_id: fixture.authority_principal.principal_id.clone(),
            checker_profile_refs: vec![fixture.profile_ref.clone()],
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: vec!["model-call-receipt".to_owned()],
            raw_output_artifact_ids: vec!["raw-sego-output".to_owned()],
            duration_ms: 42,
            cost_receipt_artifact_id: None,
        }),
        canonical_payload: None,
        completed_at: None,
        supersedes_verification_artifact_id: None,
    };
    seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CompleteVerification(
                CompleteVerificationCommand {
                    metadata: Some(metadata(id)),
                    verification_run_id: fixture.run_id.clone(),
                    expected_run_revision: 2,
                    artifact: Some(artifact),
                },
            )),
        },
        id,
    )
}

fn checker_profile(assurance: CheckerAssuranceClass) -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: "checker-sego-review-v1".to_owned(),
        revision: 0,
        status: CheckerProfileStatus::Unspecified as i32,
        checker_id: "sego:repository-change".to_owned(),
        checker_version: "0.1.9".to_owned(),
        input_contract_ref: Some(contract_ref("repository_change_acceptance", "v1", SHA_A)),
        output_contract_ref: Some(contract_ref("verification_criterion_result", "v1", SHA_B)),
        supported_criterion_types: vec!["review".to_owned()],
        assurance_class: assurance as i32,
        sandbox_profile_ref: Some(contract_ref("verification_read_only", "v1", SHA_A)),
        tool_policy_ref: Some(contract_ref("verification_tools", "v1", SHA_B)),
        data_egress_policy_ref: Some(contract_ref("local_only", "v1", SHA_C)),
        timeout_ms: 120_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec!["attest-evidence".to_owned()],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

fn profile_ref(profile: &CheckerProfile) -> ContractReference {
    contract_ref(
        &profile.checker_profile_id,
        &profile.checker_version,
        &profile.profile_digest_sha256,
    )
}

fn mapper_policy() -> SegoMapperPolicy {
    let profile = checker_profile(CheckerAssuranceClass::ModelAssisted);
    SegoMapperPolicy {
        criterion_id: "review".to_owned(),
        requirement: CriterionRequirement::MustPass,
        checker_profile_ref: profile_ref(&profile),
        expected_scope: "staged".to_owned(),
        expected_diff_hash: SHA_C.to_owned(),
        expected_reviewer: "sego".to_owned(),
        expected_engine_version: "0.1.9".to_owned(),
        expected_review_mode: "model_code_review".to_owned(),
        positive_acceptance: false,
        failure_threshold: DiscrepancySeverity::Major,
        raw_output_artifact_id: "raw-sego-output".to_owned(),
        raw_output_address: address(SHA_A, 512),
        finding_evidence: BTreeMap::from([(
            "finding-1".to_owned(),
            SegoFindingEvidenceBinding {
                evidence_id: "evidence-review".to_owned(),
                description_artifact_id: "finding-description".to_owned(),
                suggested_fix_artifact_id: Some("finding-fix".to_owned()),
            },
        )]),
    }
}

fn sego_review_with_verified_major() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "id": "review-01",
        "created_at_epoch_seconds": 1782000000,
        "scope": "staged",
        "diff_hash": SHA_C,
        "finding_count": 1,
        "highest_severity": "high",
        "parse_status": "structured",
        "git_status": "## feature",
        "findings": [{
            "id": "finding-1",
            "severity": "high",
            "file": "src/auth.rs",
            "line": 42,
            "title": "Missing authorization check",
            "evidence": "write occurs before role check",
            "risk": "unauthorized update",
            "suggestion": "check role first",
            "confidence": 0.92,
            "evidence_status": "verified"
        }],
        "raw_text": "raw",
        "reviewer": "sego",
        "engine_version": "0.1.9",
        "review_mode": "model_code_review"
    }))
    .expect("serialize review")
}

fn sego_review_with_zero_findings() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "id": "review-zero",
        "created_at_epoch_seconds": 1782000000,
        "scope": "staged",
        "diff_hash": SHA_C,
        "finding_count": 0,
        "highest_severity": null,
        "parse_status": "structured",
        "git_status": "## feature",
        "findings": [],
        "raw_text": "no findings",
        "reviewer": "sego",
        "engine_version": "0.1.9",
        "review_mode": "model_code_review"
    }))
    .expect("serialize review")
}

fn sego_review_with_parser_error() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "id": "review-error",
        "created_at_epoch_seconds": 1782000000,
        "scope": "staged",
        "diff_hash": SHA_C,
        "finding_count": 0,
        "highest_severity": null,
        "parse_status": "parse_attempted_but_failed",
        "git_status": "## feature",
        "findings": [],
        "raw_text": "malformed model output",
        "reviewer": "sego",
        "engine_version": "0.1.9",
        "review_mode": "model_code_review"
    }))
    .expect("serialize review")
}

fn binding() -> VerificationBinding {
    VerificationBinding {
        lineage: Some(LineageBinding {
            task_id: "task-01".to_owned(),
            task_revision: 4,
            work_revision: 2,
            run_id: "run-01".to_owned(),
            run_revision: 2,
            step_id: "step-01".to_owned(),
            step_revision: 2,
            attempt_id: "attempt-01".to_owned(),
            attempt_revision: 2,
            dispatch_id: "dispatch-01".to_owned(),
            fencing_token: 7,
        }),
        artifact_set_id: "artifact-set-01".to_owned(),
        artifact_set_manifest: Some(address(SHA_C, 128)),
        claim_id: "claim-change-01".to_owned(),
        claim_semantic_profile_ref: Some(contract_ref("repository_change_acceptance", "v1", SHA_A)),
        acceptance_contract_ref: Some(contract_ref("acceptance-contract-01", "v3", SHA_B)),
    }
}

fn contract_ref(id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn address(digest: &str, byte_length: u64) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: digest.to_owned(),
        byte_length,
    }
}

fn principal(
    kind: VerificationPrincipalKind,
    id: &str,
    checker_profile_id: Option<String>,
) -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
        checker_profile_id,
    }
}

fn metadata(id: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command-{id}"),
        idempotency_key: format!("idempotency-{id}"),
        idempotency_scope: "g4-06-test".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }),
        correlation_id: "correlation-g4-06".to_owned(),
        causation_id: None,
    }
}

fn seal_command(mut command: VerificationCommand, _id: &str) -> VerificationCommand {
    let digest = canonical_request_digest(&command).expect("canonical command");
    command_metadata_mut(&mut command).request_digest_sha256 = digest;
    command
}

fn command_metadata_mut(command: &mut VerificationCommand) -> &mut CommandMetadata {
    match command.command.as_mut().expect("command") {
        verification_command::Command::AttestCheckerProfile(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::CreateVerificationRequest(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::StartVerificationRun(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::RecordCriterionResult(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::CompleteVerification(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::RequestVerificationCancellation(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::RecordVerificationCancellation(value) => {
            value.metadata.as_mut().expect("metadata")
        }
        verification_command::Command::HoldVerification(value) => {
            value.metadata.as_mut().expect("metadata")
        }
    }
}

fn scan_rust_sources(root: &Path, owner: &Path, leaks: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.starts_with(owner) {
            continue;
        }
        if path.is_dir() {
            scan_rust_sources(&path, owner, leaks);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            let source = fs::read_to_string(&path).unwrap_or_default();
            if source.contains("verification_authority::store")
                || source.contains("verification_authority::supervisor")
            {
                leaks.push(path);
            }
        }
    }
}
