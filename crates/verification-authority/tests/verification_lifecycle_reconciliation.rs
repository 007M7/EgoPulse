//! Lifecycle reconciliation cases for the Sego↔EgoPulse protocol
//! (SEGO-TO-EGOPULSE-REQUIRED-CLOSURES-20260916 §5.2):
//! 1. a review arriving after the verification run reached a terminal state is
//!    rejected fail-closed (`VERIFICATION_RUN_STALE_OR_NOT_RUNNING`) and the
//!    terminal state is left untouched;
//! 2. a `DependencyNotCaptured` degradation recorded before a SQLCipher
//!    close/reopen survives the restart unchanged, and a tombstoned
//!    cross-domain reference is rejected (`EVIDENCE_INCOMPLETE`) for new
//!    records instead of silently passing.

use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
    CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
    CriterionRequirement, CriterionResult, Discrepancy, DiscrepancySeverity, EvidenceCoverage,
    RecordCriterionResultCommand, StartVerificationRunCommand, UnverifiedReason,
    VerificationArtifact, VerificationBinding, VerificationCommand, VerificationConclusion,
    VerificationErrorCode, VerificationProvenance, VerificationRequest, VerificationStatus,
    verification_command,
};
use egopulse_verification_authority::{
    AuthenticatedVerificationPrincipal, CriterionPolicySnapshot, ReferenceRejection,
    ResolvedVerificationInput, SegoFindingEvidenceBinding, SegoMapperPolicy, VerificationAuthority,
    VerificationAuthorityConfig, VerificationClock, VerificationPrincipalKind,
    VerificationReferenceResolver, VerificationSqlCipherKey, canonical_checker_profile_digest,
    canonical_request_digest, map_sego_review,
};
use prost_types::Timestamp;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
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
        let path = std::env::temp_dir().join(format!("egopulse-recon-{name}-{}", Uuid::now_v7()));
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
            .is_some_and(|value| value.starts_with("egopulse-recon-"))
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
fn late_review_after_terminal_run_is_rejected_and_state_is_frozen() {
    let mut fixture = running_fixture("late-review", CheckerAssuranceClass::ModelAssisted);
    let first = map_sego_review(&sego_review_with_zero_findings(), &mapper_policy())
        .expect("zero findings maps");
    let record = record_command_at(&fixture, first.criterion_result.clone(), "record-first", 1);
    assert!(
        fixture
            .authority
            .execute(&record, &fixture.checker_principal)
            .expect("record first result")
            .committed
    );
    let complete = complete_command(
        &fixture,
        first.criterion_result.clone(),
        Vec::new(),
        first.unverified_items.clone(),
        VerificationConclusion::Indeterminate,
        EvidenceCoverage::Missing,
        "complete-late-0",
    );
    let completed = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete run");
    assert_eq!(
        completed
            .artifact
            .as_ref()
            .expect("artifact committed")
            .conclusion,
        VerificationConclusion::Indeterminate as i32
    );

    let run_revision = fixture
        .authority
        .verification_run(&fixture.run_id)
        .expect("read run")
        .expect("run")
        .revision;
    let before = fixture
        .authority
        .inspect_store()
        .expect("inspection before");

    // The late review: a valid, freshly mapped review arriving after the run
    // already reached its terminal state. The revision matches, so rejection
    // can only come from the terminal-status guard.
    let late = map_sego_review(&sego_review_with_verified_major(), &mapper_policy())
        .expect("late review maps");
    assert_ne!(
        late.criterion_result.criterion_result_id,
        first.criterion_result.criterion_result_id
    );
    let late_record =
        record_command_at(&fixture, late.criterion_result, "record-late", run_revision);
    let outcome = fixture
        .authority
        .execute(&late_record, &fixture.checker_principal)
        .expect("late record executes as a typed rejection");
    assert!(!outcome.committed);
    assert_eq!(
        outcome.error_code,
        VerificationErrorCode::RevisionConflict as i32
    );
    assert_eq!(
        outcome.safe_error_fingerprint.as_deref(),
        Some("VERIFICATION_RUN_STALE_OR_NOT_RUNNING")
    );

    // The terminal state is frozen: run status, recorded results and every
    // store counter are exactly as before the late arrival.
    let run = fixture
        .authority
        .verification_run(&fixture.run_id)
        .expect("read run after late")
        .expect("run");
    assert_eq!(run.status, VerificationStatus::Completed as i32);
    assert_eq!(run.criterion_results.len(), 1);
    assert_eq!(
        run.criterion_results[0].criterion_result_id,
        first.criterion_result.criterion_result_id
    );
    assert_eq!(
        fixture.authority.inspect_store().expect("inspection"),
        before
    );
    let artifact = fixture
        .authority
        .verification_artifact("verification-artifact-01")
        .expect("read artifact")
        .expect("artifact kept");
    assert_eq!(
        artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
}

#[test]
fn restart_preserves_dependency_not_captured_and_rejects_tombstoned_evidence() {
    let mut fixture = running_fixture("recon-restart", CheckerAssuranceClass::ModelAssisted);
    let mapped = map_sego_review(&sego_review_with_unverified_dependency(), &mapper_policy())
        .expect("unverified dependency review maps");
    assert_eq!(
        mapped.criterion_result.outcome,
        CriterionOutcome::Unverified as i32
    );
    assert_eq!(
        mapped.criterion_result.evidence_coverage,
        EvidenceCoverage::Partial as i32
    );
    assert_eq!(mapped.unverified_items.len(), 1);
    assert_eq!(
        mapped.unverified_items[0].reason,
        UnverifiedReason::DependencyNotCaptured as i32
    );

    let record = record_command_at(&fixture, mapped.criterion_result.clone(), "record-dep", 1);
    assert!(
        fixture
            .authority
            .execute(&record, &fixture.checker_principal)
            .expect("record dependency result")
            .committed
    );
    let complete = complete_command(
        &fixture,
        mapped.criterion_result.clone(),
        mapped.discrepancies.clone(),
        mapped.unverified_items.clone(),
        VerificationConclusion::Indeterminate,
        EvidenceCoverage::Partial,
        "complete-dep",
    );
    let completed = fixture
        .authority
        .execute(&complete, &fixture.authority_principal)
        .expect("complete indeterminate run");
    assert_eq!(
        completed
            .artifact
            .as_ref()
            .expect("artifact committed")
            .conclusion,
        VerificationConclusion::Indeterminate as i32
    );

    // Restart: drop the authority and reopen the same SQLCipher store. The
    // peer domain meanwhile tombstones the evidence and raw output artifacts,
    // so the reopened authority resolves references against a shrunk set.
    let RunningFixture {
        _root: root,
        request,
        run_id,
        profile_ref,
        authority_principal,
        checker_principal,
        ..
    } = fixture;
    // A new run whose result still references the tombstoned artifacts is
    // rejected fail-closed instead of silently passing. The new governed run
    // gets a fresh binding (a new task lineage), only its cross-domain
    // evidence/raw-output references point at the tombstoned artifacts.
    let binding2 = {
        let mut value = request.binding.clone().expect("binding");
        if let Some(lineage) = value.lineage.as_mut() {
            lineage.task_id = "task-restart-2".to_owned();
            lineage.run_id = "run-restart-2".to_owned();
            lineage.dispatch_id = "dispatch-restart-2".to_owned();
        }
        value.claim_id = "claim-change-02".to_owned();
        value.artifact_set_id = "artifact-set-02".to_owned();
        value
    };
    let resolver = StaticResolver {
        binding: binding2.clone(),
        criteria: vec![CriterionPolicySnapshot {
            criterion_id: "review".to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::ModelAssisted as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![profile_ref.contract_id.clone()],
        }],
        evidence_ids: BTreeSet::from(["attest-evidence".to_owned()]),
        artifact_ids: BTreeSet::from([
            "finding-description".to_owned(),
            "finding-fix".to_owned(),
            "model-call-receipt".to_owned(),
        ]),
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
    .expect("reopen authority after restart");

    // Durability: the recorded degradation survives the restart unchanged.
    let run = authority
        .verification_run(&run_id)
        .expect("read run after restart")
        .expect("run");
    assert_eq!(run.status, VerificationStatus::Completed as i32);
    assert_eq!(run.criterion_results.len(), 1);
    assert_eq!(
        run.criterion_results[0].outcome,
        CriterionOutcome::Unverified as i32
    );
    let artifact = authority
        .verification_artifact("verification-artifact-01")
        .expect("read artifact after restart")
        .expect("artifact kept");
    assert_eq!(
        artifact.conclusion,
        VerificationConclusion::Indeterminate as i32
    );
    assert_eq!(artifact.unverified_items.len(), 1);
    assert_eq!(
        artifact.unverified_items[0].reason,
        UnverifiedReason::DependencyNotCaptured as i32
    );

    // A new run whose result still references the tombstoned artifacts is
    // rejected fail-closed instead of silently passing.
    let request2 = VerificationRequest {
        verification_request_id: "verification-request-restart-2".to_owned(),
        revision: 1,
        status: VerificationStatus::Queued as i32,
        verification_type: "task_acceptance".to_owned(),
        binding: Some(binding2),
        criterion_ids: vec!["review".to_owned()],
        checker_profile_refs: vec![profile_ref.clone()],
        created_at: None,
        hold_reason_code: None,
    };
    let create = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata("create-restart-2")),
                    request: Some(request2),
                },
            )),
        },
        "create-restart-2",
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
            .expect("create restart request")
            .committed
    );
    let start = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::StartVerificationRun(
                StartVerificationRunCommand {
                    metadata: Some(metadata("start-restart-2")),
                    verification_request_id: "verification-request-restart-2".to_owned(),
                    expected_request_revision: 1,
                    verification_run_id: "verification-run-restart-2".to_owned(),
                },
            )),
        },
        "start-restart-2",
    );
    assert!(
        authority
            .execute(&start, &authority_principal)
            .expect("start restart run")
            .committed
    );
    let record2 = seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::RecordCriterionResult(
                RecordCriterionResultCommand {
                    metadata: Some(metadata("record-restart-2")),
                    verification_run_id: "verification-run-restart-2".to_owned(),
                    expected_run_revision: 1,
                    result: Some(mapped.criterion_result),
                },
            )),
        },
        "record-restart-2",
    );
    let outcome = authority
        .execute(&record2, &checker_principal)
        .expect("tombstoned record executes as a typed rejection");
    assert!(!outcome.committed);
    assert_eq!(
        outcome.error_code,
        VerificationErrorCode::EvidenceIncomplete as i32
    );
    assert_eq!(
        outcome.safe_error_fingerprint.as_deref(),
        Some("EVIDENCE_INCOMPLETE")
    );
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

fn sego_review_with_unverified_dependency() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "id": "review-dep-01",
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
            "evidence_status": "unverified_dependency"
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

fn record_command_at(
    fixture: &RunningFixture,
    result: CriterionResult,
    id: &str,
    expected_run_revision: u64,
) -> VerificationCommand {
    seal_command(
        VerificationCommand {
            command: Some(verification_command::Command::RecordCriterionResult(
                RecordCriterionResultCommand {
                    metadata: Some(metadata(id)),
                    verification_run_id: fixture.run_id.clone(),
                    expected_run_revision,
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
    discrepancies: Vec<Discrepancy>,
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
        idempotency_scope: "recon-test".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        }),
        correlation_id: "correlation-recon".to_owned(),
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
