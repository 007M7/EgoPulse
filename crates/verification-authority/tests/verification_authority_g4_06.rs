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
    AuthenticatedVerificationPrincipal, CheckerExecutionError, CheckerOutputSink,
    CheckerOutputSource, CheckerProcessFailure, CriterionPolicySnapshot,
    GovernedCheckerFailureKind, GovernedCheckerSupervisor, GovernedSegoRunner,
    GovernedVerificationBatchPlan, GovernedVerificationCheckOutput, GovernedVerificationChecker,
    GovernedVerificationCheckerError, GovernedVerificationExecutionCoordinator,
    GovernedVerificationExecutionError, GovernedVerificationExecutionPlan, ReferenceRejection,
    ResolvedVerificationInput, SealedCheckerOutput, SegoFindingEvidenceBinding, SegoMapError,
    SegoMappedResult, SegoMapperPolicy, VerificationAuthority, VerificationAuthorityConfig,
    VerificationClock, VerificationPrincipalKind, VerificationReferenceResolver,
    VerificationSqlCipherKey, canonical_checker_profile_digest, canonical_request_digest,
    checker_failure_result, map_sego_review,
};
use prost_types::Timestamp;
use serde_json::json;
use sha2::{Digest, Sha256};
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
    // A failed run is a receipt, not a lost payload: the panic exit code and
    // everything the process wrote are preserved for the caller's
    // classification. Only timeout, output-limit and spawn failures stay
    // errors at this layer.
    let crash_receipt = crash
        .run(crash_root.path(), b"{}")
        .await
        .expect("a non-zero exit is still a receipt");
    assert_ne!(crash_receipt.exit_code, 0);
    assert!(
        String::from_utf8_lossy(&crash_receipt.stdout).contains("checker_crash_probe"),
        "captured stdout: {}",
        String::from_utf8_lossy(&crash_receipt.stdout)
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
        .run_checker(
            root.path(),
            b"{}",
            "execution-untrusted-01",
            CheckerOutputSource::Stdout,
        )
        .await
        .expect("runner result");
    // The process exited zero: the runner hands the bytes to the mapper and
    // does not decide the criterion itself.
    assert_eq!(result.failure, None);
    assert!(
        String::from_utf8_lossy(&result.output).contains("not-a-review-artifact"),
        "runner output: {}",
        String::from_utf8_lossy(&result.output)
    );
    assert_eq!(
        result.receipt.as_ref().map(|receipt| receipt.exit_code),
        Some(0)
    );
}

#[tokio::test]
async fn governed_sego_runner_keeps_a_nonzero_exit_and_its_declared_code() {
    let root = TempRoot::new("sego-runner-budget-stop");
    fs::write(root.path().join("budget-stop.marker"), b"stop").expect("write marker");
    let runner = GovernedSegoRunner::new(
        GovernedCheckerSupervisor::new(
            std::env::current_exe().expect("test executable"),
            vec![
                "--exact".to_owned(),
                "checker_budget_stop_probe".to_owned(),
                "--nocapture".to_owned(),
            ],
            Duration::from_secs(5),
            64 * 1024,
        )
        .expect("supervisor"),
    );

    let result = runner
        .run_checker(
            root.path(),
            b"{}",
            "execution-budget-stop-01",
            CheckerOutputSource::Stdout,
        )
        .await
        .expect("runner result");
    assert_eq!(result.failure, Some(CheckerProcessFailure::Crashed));
    assert!(result.output.is_empty());
    assert_eq!(
        result.receipt.as_ref().map(|receipt| receipt.exit_code),
        Some(1)
    );
    let captured = result.captured.expect("captured output");
    assert_eq!(captured.exit_code, 1);
    assert_eq!(
        captured.safe_reason_code.as_deref(),
        Some("budget_exceeded")
    );
    assert!(
        String::from_utf8_lossy(&captured.bytes).contains("budget_exceeded"),
        "captured bytes: {}",
        String::from_utf8_lossy(&captured.bytes)
    );
}

#[derive(Default)]
struct RecordingSink {
    sealed: String,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl RecordingSink {
    fn new(sealed: &str) -> Self {
        Self {
            sealed: sealed.to_owned(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn captured(&self, output_key: &str) -> Option<Vec<u8>> {
        let calls = self.calls.lock().expect("sink lock");
        calls
            .iter()
            .find(|(key, _)| key == output_key)
            .map(|(_, bytes)| bytes.clone())
    }
}

impl CheckerOutputSink for RecordingSink {
    fn capture(
        &self,
        _request: &VerificationRequest,
        _run_id: &str,
        _profile: &CheckerProfile,
        output_key: &str,
        bytes: &[u8],
    ) -> Result<SealedCheckerOutput, String> {
        self.calls
            .lock()
            .map_err(|_| "TEST_SINK_POISONED".to_owned())?
            .push((output_key.to_owned(), bytes.to_vec()));
        Ok(SealedCheckerOutput {
            artifact_id: self.sealed.clone(),
            address: ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: hex::encode(Sha256::digest(bytes)),
                byte_length: bytes.len() as u64,
            },
        })
    }
}

async fn create_request_for<C: VerificationClock>(
    authority: &mut VerificationAuthority<C>,
    request: &VerificationRequest,
    key: &str,
) {
    let create = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata(key)),
                    request: Some(request.clone()),
                },
            )),
        },
        key,
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
}

fn probe_supervisor(test: &str) -> GovernedCheckerSupervisor {
    GovernedCheckerSupervisor::new(
        std::env::current_exe().expect("test executable"),
        vec![
            "--exact".to_owned(),
            test.to_owned(),
            "--nocapture".to_owned(),
        ],
        Duration::from_secs(5),
        64 * 1024,
    )
    .expect("supervisor")
}

#[tokio::test]
async fn coordinator_cites_the_sealed_bytes_of_a_stopped_checker() {
    let fixture = running_fixture(
        "execution-failure-capture",
        CheckerAssuranceClass::ModelAssisted,
    );
    let mut authority = fixture.authority;
    let mut request = fixture.request.clone();
    request.verification_request_id = "verification-request-failure-capture".to_owned();
    create_request_for(&mut authority, &request, "failure-capture-create").await;
    let authority = Arc::new(Mutex::new(authority));
    fs::write(fixture._root.path().join("budget-stop.marker"), b"stop").expect("write marker");
    let coordinator = GovernedVerificationExecutionCoordinator::new(
        Arc::clone(&authority),
        GovernedSegoRunner::new(probe_supervisor("checker_budget_stop_probe")),
    );
    let sink = Arc::new(RecordingSink::new("sealed-checker-output"));
    let plan = GovernedVerificationExecutionPlan {
        verification_request_id: request.verification_request_id.clone(),
        verification_run_id: "verification-run-failure-capture".to_owned(),
        execution_id: "execution-failure-capture-01".to_owned(),
        working_directory: fixture._root.path().to_owned(),
        checker_request: b"{}".to_vec(),
        mapper_policy: mapper_policy(),
        verification_artifact_id: "verification-artifact-failure-capture".to_owned(),
        tool_receipt_artifact_ids: Vec::new(),
        model_call_receipt_artifact_ids: Vec::new(),
        issued_at: Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        },
        output_source: CheckerOutputSource::Stdout,
        checker_output_sink: Some(Arc::clone(&sink) as Arc<dyn CheckerOutputSink>),
    };
    let completed = coordinator
        .execute_one(plan)
        .await
        .expect("a stopped checker still records a criterion result");
    let report = completed.checker_failure.expect("failure report");
    assert_eq!(
        report.kind,
        GovernedCheckerFailureKind::Process(CheckerProcessFailure::Crashed)
    );
    assert_eq!(report.exit_code, Some(1));
    assert_eq!(
        report.checker_declared_code.as_deref(),
        Some("budget_exceeded")
    );
    assert_eq!(
        report.captured_artifact_id.as_deref(),
        Some("sealed-checker-output")
    );
    assert_eq!(report.capture_failure_code, None);
    assert_eq!(report.cited_configured_input_artifact_id, None);
    assert_eq!(
        report.output_sha256,
        Some(hex::encode(Sha256::digest(
            sink.captured("checker-failure-output")
                .expect("captured bytes")
        )))
    );
    // The criterion failed and cites the bytes the checker itself wrote.
    let artifact = &completed.verification_artifact;
    assert_eq!(
        artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
    assert_eq!(
        artifact.criterion_results[0].outcome,
        CriterionOutcome::Error as i32
    );
    assert_eq!(
        artifact.criterion_results[0]
            .safe_detail_artifact_id
            .as_deref(),
        Some("sealed-checker-output")
    );
    assert_eq!(
        artifact
            .provenance
            .as_ref()
            .expect("provenance")
            .raw_output_artifact_ids,
        vec!["sealed-checker-output".to_owned()]
    );
}

struct RefusingSink;

impl CheckerOutputSink for RefusingSink {
    fn capture(
        &self,
        _request: &VerificationRequest,
        _run_id: &str,
        _profile: &CheckerProfile,
        _output_key: &str,
        _bytes: &[u8],
    ) -> Result<SealedCheckerOutput, String> {
        Err("CHECKER_OUTPUT_CAPTURE_UNAVAILABLE".to_owned())
    }
}

#[tokio::test]
async fn a_refused_capture_never_passes_on_an_input_artifact() {
    let fixture = running_fixture(
        "execution-refused-capture",
        CheckerAssuranceClass::Deterministic,
    );
    let mut authority = fixture.authority;
    let mut request = fixture.request.clone();
    request.verification_request_id = "verification-request-refused-capture".to_owned();
    create_request_for(&mut authority, &request, "refused-capture-create").await;
    let authority = Arc::new(Mutex::new(authority));
    fs::write(fixture._root.path().join("envelope.marker"), b"envelope").expect("write marker");
    let coordinator = GovernedVerificationExecutionCoordinator::new(
        Arc::clone(&authority),
        GovernedSegoRunner::new(probe_supervisor("checker_envelope_probe")),
    );
    // A deterministic acceptance checker that would pass on its own output,
    // deployed with a declared capture that refuses to seal it.
    let mut policy = mapper_policy();
    policy.positive_acceptance = true;
    policy.checker_profile_ref = fixture.profile_ref.clone();
    let completed = coordinator
        .execute_one(GovernedVerificationExecutionPlan {
            verification_request_id: request.verification_request_id.clone(),
            verification_run_id: "verification-run-refused-capture".to_owned(),
            execution_id: "execution-refused-capture-01".to_owned(),
            working_directory: fixture._root.path().to_owned(),
            checker_request: b"{}".to_vec(),
            mapper_policy: policy,
            verification_artifact_id: "verification-artifact-refused-capture".to_owned(),
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: Vec::new(),
            issued_at: Timestamp {
                seconds: 1_782_000_000,
                nanos: 0,
            },
            output_source: CheckerOutputSource::EnvelopeArtifactPath,
            checker_output_sink: Some(Arc::new(RefusingSink) as Arc<dyn CheckerOutputSink>),
        })
        .await
        .expect("a refused capture still records a criterion result");
    let artifact = &completed.verification_artifact;
    assert_ne!(
        artifact.conclusion,
        VerificationConclusion::Passed as i32,
        "an unsealed execution must not pass on an artifact of its own input set"
    );
    assert_eq!(
        artifact.criterion_results[0].outcome,
        CriterionOutcome::Error as i32
    );
    assert_eq!(artifact.criterion_results[0].safe_detail_artifact_id, None);
    assert_eq!(
        artifact
            .provenance
            .as_ref()
            .expect("provenance")
            .raw_output_artifact_ids,
        Vec::<String>::new()
    );
    let report = completed.checker_failure.expect("failure report");
    assert_eq!(report.kind, GovernedCheckerFailureKind::CaptureRefused);
    assert_eq!(
        report.capture_failure_code.as_deref(),
        Some("CHECKER_OUTPUT_CAPTURE_UNAVAILABLE")
    );
    assert_eq!(report.captured_artifact_id, None);
    assert_eq!(report.cited_configured_input_artifact_id, None);
    assert!(report.output_byte_length > 0);
}

#[tokio::test]
async fn a_refused_mapping_reports_output_untrusted() {
    let fixture = running_fixture(
        "execution-untrusted-report",
        CheckerAssuranceClass::ModelAssisted,
    );
    let mut authority = fixture.authority;
    let mut request = fixture.request.clone();
    request.verification_request_id = "verification-request-untrusted-report".to_owned();
    create_request_for(&mut authority, &request, "untrusted-report-create").await;
    let authority = Arc::new(Mutex::new(authority));
    let coordinator = GovernedVerificationExecutionCoordinator::new(
        Arc::clone(&authority),
        GovernedSegoRunner::new(probe_supervisor("checker_invalid_output_probe")),
    );
    let completed = coordinator
        .execute_one(GovernedVerificationExecutionPlan {
            verification_request_id: request.verification_request_id.clone(),
            verification_run_id: "verification-run-untrusted-report".to_owned(),
            execution_id: "execution-untrusted-report-01".to_owned(),
            working_directory: fixture._root.path().to_owned(),
            checker_request: b"{}".to_vec(),
            mapper_policy: mapper_policy(),
            verification_artifact_id: "verification-artifact-untrusted-report".to_owned(),
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: Vec::new(),
            issued_at: Timestamp {
                seconds: 1_782_000_000,
                nanos: 0,
            },
            output_source: CheckerOutputSource::Stdout,
            checker_output_sink: None,
        })
        .await
        .expect("an unmappable exit-zero output still records a result");
    assert_eq!(
        completed.verification_artifact.criterion_results[0].outcome,
        CriterionOutcome::Error as i32
    );
    let report = completed
        .checker_failure
        .expect("a mapper rejection is reported like any other execution failure");
    assert_eq!(report.kind, GovernedCheckerFailureKind::OutputUntrusted);
    assert_eq!(report.exit_code, Some(0));
    assert!(report.output_byte_length > 0);
    assert_eq!(
        report.cited_configured_input_artifact_id.as_deref(),
        Some("raw-sego-output")
    );
}

#[tokio::test]
async fn envelope_output_source_maps_the_artifact_named_by_stdout() {
    let fixture = running_fixture("execution-envelope", CheckerAssuranceClass::ModelAssisted);
    let mut authority = fixture.authority;
    let mut request = fixture.request.clone();
    request.verification_request_id = "verification-request-envelope".to_owned();
    create_request_for(&mut authority, &request, "envelope-create").await;
    let authority = Arc::new(Mutex::new(authority));
    fs::write(fixture._root.path().join("envelope.marker"), b"envelope").expect("write marker");
    let coordinator = GovernedVerificationExecutionCoordinator::new(
        Arc::clone(&authority),
        GovernedSegoRunner::new(probe_supervisor("checker_envelope_probe")),
    );
    let sink = Arc::new(RecordingSink::new("sealed-checker-output"));
    let plan = GovernedVerificationExecutionPlan {
        verification_request_id: request.verification_request_id.clone(),
        verification_run_id: "verification-run-envelope".to_owned(),
        execution_id: "execution-envelope-01".to_owned(),
        working_directory: fixture._root.path().to_owned(),
        checker_request: b"{}".to_vec(),
        mapper_policy: mapper_policy(),
        verification_artifact_id: "verification-artifact-envelope".to_owned(),
        tool_receipt_artifact_ids: Vec::new(),
        model_call_receipt_artifact_ids: Vec::new(),
        issued_at: Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        },
        output_source: CheckerOutputSource::EnvelopeArtifactPath,
        checker_output_sink: Some(Arc::clone(&sink) as Arc<dyn CheckerOutputSink>),
    };
    let completed = coordinator
        .execute_one(plan)
        .await
        .expect("envelope artifact is mapped");
    assert!(completed.checker_failure.is_none());
    // Zero findings under model review stay explicitly unverified, and the
    // sealed bytes are the artifact file, not the envelope that named it.
    let artifact = &completed.verification_artifact;
    assert_eq!(
        artifact.criterion_results[0].outcome,
        CriterionOutcome::Unverified as i32
    );
    assert_eq!(
        artifact.criterion_results[0]
            .safe_detail_artifact_id
            .as_deref(),
        Some("sealed-checker-output")
    );
    let sealed_bytes = sink.captured("review").expect("sealed review artifact");
    let review: serde_json::Value = serde_json::from_slice(&sealed_bytes).expect("sealed JSON");
    assert_eq!(review["scope"], "staged");
    assert!(review.get("artifact_path").is_none());
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
        output_source: CheckerOutputSource::Stdout,
        checker_output_sink: None,
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

#[derive(Default)]
struct BatchChecker {
    calls: std::sync::atomic::AtomicUsize,
    unavailable: bool,
    invalid_results: bool,
    invalid_completion_reference: bool,
}

impl GovernedVerificationChecker for BatchChecker {
    fn check<'a>(
        &'a self,
        request: &'a VerificationRequest,
        _run_id: &'a str,
        profiles: &'a [CheckerProfile],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        GovernedVerificationCheckOutput,
                        GovernedVerificationCheckerError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.unavailable {
                return Err(GovernedVerificationCheckerError);
            }
            let mut results = request
                .criterion_ids
                .iter()
                .map(|criterion| {
                    let profile = profiles
                        .iter()
                        .find(|profile| profile.supported_criterion_types.contains(criterion))
                        .expect("attested profile for criterion");
                    if criterion == "review" {
                        let mut policy = mapper_policy();
                        policy.checker_profile_ref = profile_ref(profile);
                        let mut mapped =
                            map_sego_review(&sego_review_with_zero_findings(), &policy)
                                .expect("map model review");
                        mapped.criterion_result.duration_ms = 1;
                        mapped
                    } else {
                        SegoMappedResult {
                            review_id: format!(
                                "check-{}-{criterion}",
                                request.verification_request_id
                            ),
                            criterion_result: CriterionResult {
                                criterion_result_id: format!(
                                    "result-{}-{criterion}",
                                    request.verification_request_id
                                ),
                                criterion_id: criterion.clone(),
                                requirement: CriterionRequirement::MustPass as i32,
                                outcome: CriterionOutcome::Passed as i32,
                                evidence_coverage: EvidenceCoverage::Complete as i32,
                                checker_profile_ref: Some(profile_ref(profile)),
                                assurance_class: CheckerAssuranceClass::Deterministic as i32,
                                evidence_ids: vec!["evidence-review".to_owned()],
                                safe_detail_artifact_id: Some("raw-sego-output".to_owned()),
                                duration_ms: 1,
                                ..Default::default()
                            },
                            discrepancies: vec![],
                            unverified_items: vec![],
                        }
                    }
                })
                .collect::<Vec<_>>();
            if self.invalid_results {
                results.pop();
            }
            Ok(GovernedVerificationCheckOutput {
                results,
                tool_receipt_artifact_ids: vec![],
                model_call_receipt_artifact_ids: vec![if self.invalid_completion_reference {
                    "not-a-sealed-model-receipt".to_owned()
                } else {
                    "model-call-receipt".to_owned()
                }],
                raw_output_artifact_ids: vec!["raw-sego-output".to_owned()],
            })
        })
    }
}

fn batch_fixture(
    name: &str,
) -> (
    TempRoot,
    StaticResolver,
    Arc<Mutex<VerificationAuthority<FixedClock>>>,
    GovernedVerificationBatchPlan,
) {
    let root = TempRoot::new(name);
    let profiles = ["scope", "tests", "review"].map(|criterion| {
        let mut profile = checker_profile(if criterion == "review" {
            CheckerAssuranceClass::ModelAssisted
        } else {
            CheckerAssuranceClass::Deterministic
        });
        profile.checker_profile_id = format!("checker-{criterion}");
        profile.supported_criterion_types = vec![criterion.to_owned()];
        profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
        profile
    });
    let resolver = StaticResolver {
        binding: binding(),
        criteria: profiles
            .iter()
            .map(|profile| CriterionPolicySnapshot {
                criterion_id: profile.supported_criterion_types[0].clone(),
                requirement: CriterionRequirement::MustPass as i32,
                minimum_assurance: profile.assurance_class,
                not_applicable_allowed: false,
                checker_profile_ids: vec![profile.checker_profile_id.clone()],
            })
            .collect(),
        evidence_ids: ["attest-evidence", "evidence-review"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        artifact_ids: ["raw-sego-output", "model-call-receipt"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    };
    let mut authority = VerificationAuthority::open_with_clock(
        VerificationAuthorityConfig {
            database_path: root.path().join("verification.db"),
            store_epoch: "batch-test".to_owned(),
            key: VerificationSqlCipherKey::new([0x46; 32]),
        },
        resolver.clone(),
        FixedClock,
    )
    .expect("open batch authority");
    for profile in &profiles {
        let id = format!("attest-{}", profile.checker_profile_id);
        let command = seal_command(
            VerificationCommand {
                command: Some(verification_command::Command::AttestCheckerProfile(
                    AttestCheckerProfileCommand {
                        metadata: Some(metadata(&id)),
                        profile: Some(profile.clone()),
                    },
                )),
            },
            &id,
        );
        assert!(
            authority
                .execute(
                    &command,
                    &principal(
                        VerificationPrincipalKind::VerificationAuthority,
                        "profile-authority",
                        None
                    )
                )
                .expect("attest batch profile")
                .committed
        );
    }
    let request = VerificationRequest {
        verification_request_id: "batch-request".to_owned(),
        revision: 1,
        status: VerificationStatus::Queued as i32,
        verification_type: "task_acceptance".to_owned(),
        binding: Some(binding()),
        criterion_ids: vec!["scope".to_owned(), "tests".to_owned(), "review".to_owned()],
        checker_profile_refs: profiles.iter().map(profile_ref).collect(),
        ..Default::default()
    };
    let command = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata("batch-create")),
                    request: Some(request),
                },
            )),
        },
        "batch-create",
    );
    let created = authority
        .execute(
            &command,
            &principal(
                VerificationPrincipalKind::TaskAuthority,
                "task-authority",
                None,
            ),
        )
        .expect("create batch request");
    assert!(created.committed, "{created:?}");
    let plan = GovernedVerificationBatchPlan {
        verification_request_id: "batch-request".to_owned(),
        verification_run_id: "batch-run".to_owned(),
        verification_artifact_id: "batch-artifact".to_owned(),
        issued_at: FixedClock.now(),
    };
    (root, resolver, Arc::new(Mutex::new(authority)), plan)
}

#[tokio::test]
async fn governed_batch_combines_three_criteria_and_replays_after_sqlcipher_reopen() {
    let (root, resolver, authority, plan) = batch_fixture("batch-complete");
    let checker = BatchChecker {
        unavailable: false,
        ..Default::default()
    };
    let coordinator =
        GovernedVerificationExecutionCoordinator::from_authority(Arc::clone(&authority));
    let outcome = coordinator
        .execute_prepared(plan.clone(), &checker)
        .await
        .expect("complete batch");
    assert_eq!(outcome.verification_artifact.criterion_results.len(), 3);
    assert_eq!(
        outcome.verification_artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
    assert_eq!(
        outcome
            .verification_artifact
            .criterion_results
            .iter()
            .filter(|result| result.outcome == CriterionOutcome::Passed as i32)
            .count(),
        2
    );
    let before = authority
        .lock()
        .expect("authority")
        .inspect_store()
        .expect("inspection");
    drop(coordinator);
    drop(authority);
    let authority = Arc::new(Mutex::new(
        VerificationAuthority::open_with_clock(
            VerificationAuthorityConfig {
                database_path: root.path().join("verification.db"),
                store_epoch: "batch-test".to_owned(),
                key: VerificationSqlCipherKey::new([0x46; 32]),
            },
            resolver,
            FixedClock,
        )
        .expect("reopen batch authority"),
    ));
    let coordinator =
        GovernedVerificationExecutionCoordinator::from_authority(Arc::clone(&authority));
    let replay = coordinator
        .execute_prepared(plan, &checker)
        .await
        .expect("replay completed batch");
    assert!(replay.replayed);
    assert_eq!(replay.verification_artifact, outcome.verification_artifact);
    assert_eq!(checker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        authority
            .lock()
            .expect("authority")
            .inspect_store()
            .expect("inspection"),
        before
    );
}

#[tokio::test]
async fn governed_batch_holds_when_output_capture_is_unavailable_without_retrying_checker() {
    let (_root, _resolver, authority, plan) = batch_fixture("batch-output-unknown");
    let checker = BatchChecker {
        unavailable: true,
        ..Default::default()
    };
    let coordinator =
        GovernedVerificationExecutionCoordinator::from_authority(Arc::clone(&authority));
    for _ in 0..2 {
        assert!(
            matches!(coordinator.execute_prepared(plan.clone(), &checker).await,
            Err(GovernedVerificationExecutionError::HeldForRecovery { reason_code, .. })
                if reason_code == "CHECKER_OUTPUT_CAPTURE_INCOMPLETE")
        );
    }
    assert_eq!(checker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        authority
            .lock()
            .expect("authority")
            .inspect_store()
            .expect("inspection")
            .verification_artifact_count,
        0
    );
}

#[tokio::test]
async fn coordinator_holds_unfinished_durable_runs_without_invoking_checker() {
    for has_criterion in [false, true] {
        let mut fixture =
            running_fixture("coordinator-recovery", CheckerAssuranceClass::ModelAssisted);
        if has_criterion {
            let result = map_sego_review(&sego_review_with_verified_major(), &mapper_policy())
                .expect("valid result")
                .criterion_result;
            let command = record_command(&fixture, result, "before-crash-result");
            assert!(
                fixture
                    .authority
                    .execute(&command, &fixture.checker_principal)
                    .expect("record before crash")
                    .committed
            );
        }
        let RunningFixture {
            _root: root,
            authority,
            request,
            run_id,
            ..
        } = fixture;
        drop(authority);
        let resolver = StaticResolver {
            binding: request.binding.clone().expect("binding"),
            criteria: vec![CriterionPolicySnapshot {
                criterion_id: "review".to_owned(),
                requirement: CriterionRequirement::MustPass as i32,
                minimum_assurance: CheckerAssuranceClass::ModelAssisted as i32,
                not_applicable_allowed: false,
                checker_profile_ids: request
                    .checker_profile_refs
                    .iter()
                    .map(|p| p.contract_id.clone())
                    .collect(),
            }],
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
        let open = || {
            VerificationAuthority::open_with_clock(
                VerificationAuthorityConfig {
                    database_path: root.path().join("verification.db"),
                    store_epoch: "g4-06-test-epoch".to_owned(),
                    key: VerificationSqlCipherKey::new([0x46; 32]),
                },
                resolver.clone(),
                FixedClock,
            )
            .expect("reopen durable authority")
        };
        fs::write(root.path().join("reexecution.marker"), b"armed").expect("arm probe");
        let plan = GovernedVerificationExecutionPlan {
            verification_request_id: request.verification_request_id.clone(),
            verification_run_id: run_id.clone(),
            execution_id: "execution-recovery".to_owned(),
            working_directory: root.path().to_owned(),
            checker_request: b"{}".to_vec(),
            mapper_policy: mapper_policy(),
            verification_artifact_id: "verification-artifact-recovery".to_owned(),
            tool_receipt_artifact_ids: vec![],
            model_call_receipt_artifact_ids: vec![],
            issued_at: FixedClock.now(),
            output_source: CheckerOutputSource::Stdout,
            checker_output_sink: None,
        };
        let mut held_inspection = None;
        for _ in 0..2 {
            let authority = Arc::new(Mutex::new(open()));
            let before = authority
                .lock()
                .expect("lock")
                .inspect_store()
                .expect("inspection");
            let runner = GovernedSegoRunner::new(
                GovernedCheckerSupervisor::new(
                    std::env::current_exe().expect("test executable"),
                    vec![
                        "--exact".to_owned(),
                        "checker_reexecution_probe".to_owned(),
                        "--nocapture".to_owned(),
                    ],
                    Duration::from_secs(2),
                    64 * 1024,
                )
                .expect("supervisor"),
            );
            let coordinator =
                GovernedVerificationExecutionCoordinator::new(Arc::clone(&authority), runner);
            let outcome = coordinator.execute_one(plan.clone()).await;
            assert!(
                !root.path().join("checker-was-reexecuted.marker").exists(),
                "an unfinished durable run must never blindly execute its checker again"
            );
            assert!(
                matches!(outcome, Err(GovernedVerificationExecutionError::HeldForRecovery {
                verification_run_id, reason_code,
            }) if verification_run_id == run_id && reason_code == "CHECKER_EXECUTION_OUTCOME_UNKNOWN_AFTER_RESTART"),
                "held recovery must return the nonfatal application outcome"
            );
            let authority = authority.lock().expect("lock");
            let run = authority
                .verification_run(&run_id)
                .expect("run read")
                .expect("run");
            assert_eq!(run.status, VerificationStatus::Held as i32);
            assert_eq!(run.criterion_results.len(), usize::from(has_criterion));
            let after = authority.inspect_store().expect("inspection");
            assert_eq!(after.verification_artifact_count, 0);
            if let Some(previous) = held_inspection.as_ref() {
                assert_eq!(&after, previous, "restart must not add another hold");
            } else {
                assert_eq!(after.event_count, before.event_count + 1);
            }
            held_inspection = Some(after);
        }
    }
}

#[test]
fn checker_reexecution_probe() {
    if Path::new("reexecution.marker").exists() {
        fs::write("checker-was-reexecuted.marker", b"invoked").expect("record invocation");
    }
}

#[test]
fn checker_crash_probe() {
    if Path::new("crash.marker").exists() {
        panic!("intentional checker crash probe");
    }
}

#[tokio::test]
async fn governed_batch_persists_hold_after_invalid_results_or_completion_rejection() {
    for invalid_results in [true, false] {
        let (_root, _resolver, authority, plan) = batch_fixture("batch-commit-failed");
        let checker = BatchChecker {
            invalid_results,
            invalid_completion_reference: !invalid_results,
            ..Default::default()
        };
        let coordinator =
            GovernedVerificationExecutionCoordinator::from_authority(Arc::clone(&authority));
        for _ in 0..2 {
            assert!(
                matches!(coordinator.execute_prepared(plan.clone(), &checker).await,
                Err(GovernedVerificationExecutionError::HeldForRecovery { reason_code, .. })
                    if reason_code == "CHECKER_RESULT_COMMIT_INCOMPLETE")
            );
        }
        assert_eq!(checker.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let authority = authority.lock().expect("authority");
        let run = authority
            .verification_run(&plan.verification_run_id)
            .expect("read run")
            .expect("run");
        assert_eq!(run.status, VerificationStatus::Held as i32);
        assert_eq!(
            run.criterion_results.len(),
            if invalid_results { 0 } else { 3 }
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection")
                .verification_artifact_count,
            0
        );
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

#[test]
fn checker_budget_stop_probe() {
    if Path::new("budget-stop.marker").exists() {
        println!(r#"{{"schema_version":1,"status":"budget_exceeded","artifact_path":null}}"#);
        std::io::Write::flush(&mut std::io::stdout()).expect("flush stop answer");
        std::process::exit(1);
    }
}

#[test]
fn checker_envelope_probe() {
    if !Path::new("envelope.marker").exists() {
        return;
    }
    let reviews = Path::new(".sego").join("reviews");
    fs::create_dir_all(&reviews).expect("create reviews directory");
    let artifact = serde_json::json!({
        "schema_version": 1,
        "id": "review:envelope-01",
        "scope": "staged",
        "diff_hash": SHA_C,
        "finding_count": 0,
        "highest_severity": serde_json::Value::Null,
        "parse_status": "structured",
        "findings": [],
        "reviewer": "sego",
        "engine_version": "0.1.9",
        "review_mode": "model_code_review",
        "data_egress_class": "none",
        "compute_boundary": "local",
    });
    let artifact_path = reviews.join("r-envelope-01.json");
    fs::write(
        &artifact_path,
        serde_json::to_vec(&artifact).expect("serialize review artifact"),
    )
    .expect("write review artifact");
    let envelope = serde_json::json!({
        "schema_version": 1,
        "action": "review",
        "status": "ok",
        "artifact_path": artifact_path.display().to_string(),
    });
    print!(
        "{}",
        serde_json::to_string(&envelope).expect("serialize envelope")
    );
    std::io::Write::flush(&mut std::io::stdout()).expect("flush envelope");
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
            "sealed-checker-output",
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

#[test]
fn mapper_policy_pins_sego_review_artifact_contract() {
    assert_eq!(
        egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_ID,
        "sego.review.artifact/v1"
    );
    assert_eq!(
        egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION,
        3
    );
    let policy = mapper_policy();
    assert_eq!(
        policy.contract_id,
        egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_ID
    );
    assert_eq!(
        policy.contract_revision,
        egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION
    );
}

fn mapper_policy() -> SegoMapperPolicy {
    let profile = checker_profile(CheckerAssuranceClass::ModelAssisted);
    SegoMapperPolicy {
        criterion_id: "review".to_owned(),
        requirement: CriterionRequirement::MustPass,
        checker_profile_ref: profile_ref(&profile),
        contract_id: egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_ID.to_owned(),
        contract_revision: egopulse_verification_authority::SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION,
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
        "review_mode": "model_code_review",
        "data_egress_class": "none",
        "compute_boundary": "local"
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
        "review_mode": "model_code_review",
        "data_egress_class": "none",
        "compute_boundary": "local"
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
        "review_mode": "model_code_review",
        "data_egress_class": "none",
        "compute_boundary": "local"
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
