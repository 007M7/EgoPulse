use egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress;
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CheckerAssuranceClass, CriterionOutcome, CriterionRequirement, CriterionResult, Discrepancy,
    DiscrepancySeverity, EvidenceCoverage, UnverifiedItem, UnverifiedReason,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// The Sego review contract this mapper is written against. The review
/// artifact payload carries no contract-id or revision field, so the contract
/// identity cannot be read back from the artifact; it is pinned here and in
/// mapper configuration. A Sego contract revision bump must update both pins
/// deliberately and re-run the fixture-backed mapper tests.
pub const SEGO_REVIEW_ARTIFACT_CONTRACT_ID: &str = "sego.review.artifact/v1";
pub const SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION: u64 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegoFindingEvidenceBinding {
    pub evidence_id: String,
    pub description_artifact_id: String,
    pub suggested_fix_artifact_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegoMapperPolicy {
    pub criterion_id: String,
    pub requirement: CriterionRequirement,
    pub checker_profile_ref: ContractReference,
    pub contract_id: String,
    pub contract_revision: u64,
    pub expected_scope: String,
    pub expected_diff_hash: String,
    pub expected_reviewer: String,
    pub expected_engine_version: String,
    pub expected_review_mode: String,
    /// Allows an explicitly configured deterministic acceptance checker to
    /// treat a structurally valid zero-finding review as positive proof. This
    /// is false for normal Sego/model review, where absence of a finding is
    /// deliberately only `Unverified`.
    pub positive_acceptance: bool,
    pub failure_threshold: DiscrepancySeverity,
    pub raw_output_artifact_id: String,
    pub raw_output_address: ContentAddress,
    pub finding_evidence: BTreeMap<String, SegoFindingEvidenceBinding>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SegoMappedResult {
    pub criterion_result: CriterionResult,
    pub discrepancies: Vec<Discrepancy>,
    pub unverified_items: Vec<UnverifiedItem>,
    pub review_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerProcessFailure {
    Unavailable,
    Timeout,
    Crashed,
    OutputUntrusted,
}

impl CheckerProcessFailure {
    /// Stable code for operator-facing records, so a failed checker is
    /// attributed by code instead of by message text.
    #[must_use]
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Unavailable => "CHECKER_UNAVAILABLE",
            Self::Timeout => "CHECKER_TIMEOUT",
            Self::Crashed => "CHECKER_CRASHED",
            Self::OutputUntrusted => "CHECKER_OUTPUT_UNTRUSTED",
        }
    }
}

/// What a checker process left behind when it exited non-zero. The bytes are
/// kept so a stop or error is attributed from the checker's own machine
/// readable output instead of being discarded; a non-zero exit still never
/// becomes a pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerFailureOutput {
    pub exit_code: i32,
    pub bytes: Vec<u8>,
    /// A stable code read out of the captured output, when it declares one.
    pub safe_reason_code: Option<String>,
}

/// Largest captured failure output that is parsed for a stable code. Larger
/// output is still preserved as bytes, only the code extraction gives up.
pub const MAX_FAILURE_CODE_PARSE_BYTES: usize = 64 * 1024;

/// Keys a governed checker may use to declare why it stopped. The extractor
/// reads only these and accepts only values shaped like a stable code, so free
/// text can never be promoted into an attribution.
const FAILURE_CODE_KEYS: &[&str] = &[
    "safe_reason_code",
    "reason_code",
    "safe_detail_code",
    "error_code",
    "status",
];

#[must_use]
pub fn captured_failure_code(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_FAILURE_CODE_PARSE_BYTES {
        return None;
    }
    // A failed checker may share stdout with a wrapper process, so the answer
    // is found among the captured output instead of assumed to be all of it.
    crate::checker_output::json_object_candidates(bytes)
        .into_iter()
        .find_map(failure_code_in_json)
}

fn failure_code_in_json(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    for key in FAILURE_CODE_KEYS {
        let Some(code) = object.get(*key).and_then(|value| value.as_str()) else {
            continue;
        };
        if stable_code(code) {
            return Some(code.to_owned());
        }
    }
    None
}

fn stable_code(code: &str) -> bool {
    (3..=64).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SegoMapError {
    #[error("Sego output is not valid ReviewArtifact v1 JSON")]
    InvalidJson,
    #[error("Sego output identity does not match the attested checker profile")]
    ProfileMismatch,
    #[error("Sego output does not bind the frozen review input")]
    BindingMismatch,
    #[error("Sego output contains inconsistent or duplicate findings")]
    InconsistentArtifact,
}

#[derive(Debug, Deserialize)]
struct ReviewArtifact {
    schema_version: u64,
    id: String,
    scope: String,
    diff_hash: String,
    finding_count: usize,
    highest_severity: Option<String>,
    parse_status: String,
    findings: Vec<ReviewFinding>,
    reviewer: Option<String>,
    engine_version: Option<String>,
    review_mode: Option<String>,
    #[serde(default)]
    data_egress_class: Option<String>,
    #[serde(default)]
    compute_boundary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewFinding {
    #[serde(default)]
    id: String,
    severity: String,
    file: String,
    line: Option<u64>,
    title: String,
    evidence: String,
    risk: String,
    suggestion: String,
    confidence: f64,
    evidence_status: Option<String>,
}

pub fn map_sego_review(
    bytes: &[u8],
    policy: &SegoMapperPolicy,
) -> Result<SegoMappedResult, SegoMapError> {
    let review: ReviewArtifact =
        serde_json::from_slice(bytes).map_err(|_| SegoMapError::InvalidJson)?;
    validate_review(&review, policy)?;

    let result_id = stable_id(
        "criterion",
        &format!("{}:{}", review.id, policy.criterion_id),
    );
    match review.parse_status.as_str() {
        "parse_attempted_but_failed" => Ok(SegoMappedResult {
            criterion_result: base_result(
                result_id,
                policy,
                CriterionOutcome::Error,
                EvidenceCoverage::Missing,
                Vec::new(),
                Vec::new(),
                &policy.raw_output_artifact_id,
            ),
            discrepancies: Vec::new(),
            unverified_items: Vec::new(),
            review_id: review.id,
        }),
        "fallback_raw_text" => {
            let item = unverified_item(
                &review.id,
                &policy.criterion_id,
                UnverifiedReason::InsufficientEvidence,
                Vec::new(),
                Some(policy.raw_output_artifact_id.clone()),
            );
            Ok(SegoMappedResult {
                criterion_result: base_result(
                    result_id,
                    policy,
                    CriterionOutcome::Unverified,
                    EvidenceCoverage::Missing,
                    Vec::new(),
                    vec![item.unverified_item_id.clone()],
                    &policy.raw_output_artifact_id,
                ),
                discrepancies: Vec::new(),
                unverified_items: vec![item],
                review_id: review.id,
            })
        }
        "structured" => map_structured(review, policy, result_id),
        _ => Err(SegoMapError::InconsistentArtifact),
    }
}

#[must_use]
pub fn checker_failure_result(
    policy: &SegoMapperPolicy,
    execution_id: &str,
    failure: CheckerProcessFailure,
) -> SegoMappedResult {
    checker_failure_result_with_detail(policy, execution_id, failure, None)
}

/// Fails one criterion for a checker process failure. `detail_artifact_id`
/// names the sealed bytes the checker actually produced (a non-zero exit's
/// captured output); when it is absent the configured raw output artifact is
/// cited, which is what a checker that never wrote anything leaves behind.
#[must_use]
pub fn checker_failure_result_with_detail(
    policy: &SegoMapperPolicy,
    execution_id: &str,
    failure: CheckerProcessFailure,
    detail_artifact_id: Option<&str>,
) -> SegoMappedResult {
    let detail = detail_artifact_id
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&policy.raw_output_artifact_id);
    let result_id = stable_id(
        "criterion",
        &format!("{execution_id}:{}", policy.criterion_id),
    );
    let (outcome, reason) = match failure {
        CheckerProcessFailure::Unavailable | CheckerProcessFailure::Timeout => (
            CriterionOutcome::Error,
            Some(UnverifiedReason::CheckerUnavailable),
        ),
        CheckerProcessFailure::Crashed | CheckerProcessFailure::OutputUntrusted => {
            (CriterionOutcome::Error, None)
        }
    };
    let item = reason.map(|reason| {
        unverified_item(
            execution_id,
            &policy.criterion_id,
            reason,
            Vec::new(),
            Some(detail.to_owned()),
        )
    });
    let item_ids = item
        .as_ref()
        .map(|value| vec![value.unverified_item_id.clone()])
        .unwrap_or_default();
    SegoMappedResult {
        criterion_result: base_result(
            result_id,
            policy,
            outcome,
            EvidenceCoverage::Missing,
            Vec::new(),
            item_ids,
            detail,
        ),
        discrepancies: Vec::new(),
        unverified_items: item.into_iter().collect(),
        review_id: execution_id.to_owned(),
    }
}

/// The result of an execution whose declared output capture was refused. No
/// outcome and no citation is claimed from bytes this environment could not
/// seal, so the criterion is an explicit error instead of a positive result
/// carried by an artifact of the Task's own input set. The refusal code is
/// reported with the execution, not as a checker declaration.
#[must_use]
pub fn checker_capture_refused_result(
    policy: &SegoMapperPolicy,
    execution_id: &str,
) -> SegoMappedResult {
    let result_id = stable_id(
        "criterion",
        &format!("{execution_id}:{}", policy.criterion_id),
    );
    let item = unverified_item(
        execution_id,
        &policy.criterion_id,
        UnverifiedReason::InsufficientEvidence,
        Vec::new(),
        None,
    );
    let mut criterion_result = base_result(
        result_id,
        policy,
        CriterionOutcome::Error,
        EvidenceCoverage::Missing,
        Vec::new(),
        vec![item.unverified_item_id.clone()],
        &policy.raw_output_artifact_id,
    );
    criterion_result.safe_detail_artifact_id = None;
    SegoMappedResult {
        criterion_result,
        discrepancies: Vec::new(),
        unverified_items: vec![item],
        review_id: execution_id.to_owned(),
    }
}

fn map_structured(
    review: ReviewArtifact,
    policy: &SegoMapperPolicy,
    result_id: String,
) -> Result<SegoMappedResult, SegoMapError> {
    if review.findings.is_empty() {
        if policy.positive_acceptance {
            return Ok(SegoMappedResult {
                criterion_result: base_result(
                    result_id,
                    policy,
                    CriterionOutcome::Passed,
                    EvidenceCoverage::Complete,
                    // The raw checker output is an Artifact, not an
                    // Evidence aggregate. It is carried through
                    // `safe_detail_artifact_id`; putting it in evidence_ids
                    // would make Verification Authority reject the result
                    // as an evidence/artifact type confusion.
                    Vec::new(),
                    Vec::new(),
                    &policy.raw_output_artifact_id,
                ),
                discrepancies: Vec::new(),
                unverified_items: Vec::new(),
                review_id: review.id,
            });
        }
        let item = unverified_item(
            &review.id,
            &policy.criterion_id,
            UnverifiedReason::RequiresJudgement,
            Vec::new(),
            Some(policy.raw_output_artifact_id.clone()),
        );
        return Ok(SegoMappedResult {
            criterion_result: base_result(
                result_id,
                policy,
                CriterionOutcome::Unverified,
                EvidenceCoverage::Missing,
                Vec::new(),
                vec![item.unverified_item_id.clone()],
                &policy.raw_output_artifact_id,
            ),
            discrepancies: Vec::new(),
            unverified_items: vec![item],
            review_id: review.id,
        });
    }

    let mut discrepancies = Vec::with_capacity(review.findings.len());
    let mut unverified = Vec::new();
    let mut evidence_ids = BTreeSet::new();
    let mut all_evidence_verified = true;
    let mut verified_failure = false;

    for (index, finding) in review.findings.iter().enumerate() {
        let finding_key = if finding.id.trim().is_empty() {
            format!("legacy-{index}")
        } else {
            finding.id.clone()
        };
        let severity = map_severity(&finding.severity)?;
        let binding = policy.finding_evidence.get(&finding_key);
        let evidence_verified =
            finding.evidence_status.as_deref() == Some("verified") && binding.is_some();
        let bound_evidence = binding
            .map(|value| vec![value.evidence_id.clone()])
            .unwrap_or_default();
        evidence_ids.extend(bound_evidence.iter().cloned());
        let discrepancy_id = stable_id("discrepancy", &format!("{}:{}", review.id, finding_key));
        discrepancies.push(Discrepancy {
            discrepancy_id: discrepancy_id.clone(),
            criterion_id: policy.criterion_id.clone(),
            severity: severity as i32,
            evidence_ids: bound_evidence.clone(),
            description_artifact_id: binding
                .map(|value| value.description_artifact_id.clone())
                .unwrap_or_else(|| policy.raw_output_artifact_id.clone()),
            suggested_fix_artifact_id: binding
                .and_then(|value| value.suggested_fix_artifact_id.clone()),
        });
        if evidence_verified && severity_rank(severity) <= severity_rank(policy.failure_threshold) {
            verified_failure = true;
        }
        if !evidence_verified {
            all_evidence_verified = false;
            let reason = evidence_reason(finding.evidence_status.as_deref());
            unverified.push(unverified_item(
                &format!("{}:{finding_key}", review.id),
                &policy.criterion_id,
                reason,
                bound_evidence,
                Some(policy.raw_output_artifact_id.clone()),
            ));
        }
    }

    let coverage = if all_evidence_verified {
        EvidenceCoverage::Complete
    } else {
        EvidenceCoverage::Partial
    };
    // Sego model review may prove a policy-defined discrepancy, but absence of a
    // finding is not positive proof. A non-failing review therefore remains
    // explicitly unverified.
    let outcome = if verified_failure {
        CriterionOutcome::Failed
    } else {
        CriterionOutcome::Unverified
    };
    let discrepancy_ids = discrepancies
        .iter()
        .map(|value| value.discrepancy_id.clone())
        .collect();
    let unverified_ids = unverified
        .iter()
        .map(|value| value.unverified_item_id.clone())
        .collect();
    Ok(SegoMappedResult {
        criterion_result: base_result(
            result_id,
            policy,
            outcome,
            coverage,
            evidence_ids.into_iter().collect(),
            unverified_ids,
            &policy.raw_output_artifact_id,
        )
        .with_discrepancies(discrepancy_ids),
        discrepancies,
        unverified_items: unverified,
        review_id: review.id,
    })
}

trait CriterionResultExt {
    fn with_discrepancies(self, ids: Vec<String>) -> Self;
}

impl CriterionResultExt for CriterionResult {
    fn with_discrepancies(mut self, ids: Vec<String>) -> Self {
        self.discrepancy_ids = ids;
        self
    }
}

fn base_result(
    id: String,
    policy: &SegoMapperPolicy,
    outcome: CriterionOutcome,
    coverage: EvidenceCoverage,
    evidence_ids: Vec<String>,
    unverified_item_ids: Vec<String>,
    detail_artifact_id: &str,
) -> CriterionResult {
    CriterionResult {
        criterion_result_id: id,
        criterion_id: policy.criterion_id.clone(),
        requirement: policy.requirement as i32,
        outcome: outcome as i32,
        assurance_class: CheckerAssuranceClass::ModelAssisted as i32,
        checker_profile_ref: Some(policy.checker_profile_ref.clone()),
        evidence_coverage: coverage as i32,
        evidence_ids,
        discrepancy_ids: Vec::new(),
        unverified_item_ids,
        duration_ms: 0,
        safe_detail_artifact_id: Some(detail_artifact_id.to_owned()),
    }
}

fn unverified_item(
    seed: &str,
    criterion_id: &str,
    reason: UnverifiedReason,
    evidence_ids: Vec<String>,
    context_artifact_id: Option<String>,
) -> UnverifiedItem {
    UnverifiedItem {
        unverified_item_id: stable_id("unverified", seed),
        criterion_id: criterion_id.to_owned(),
        reason: reason as i32,
        evidence_ids,
        context_artifact_id,
    }
}

fn validate_review(review: &ReviewArtifact, policy: &SegoMapperPolicy) -> Result<(), SegoMapError> {
    if review.schema_version != 1
        || review.id.trim().is_empty()
        || review.finding_count != review.findings.len()
        || !matches!(
            review.parse_status.as_str(),
            "structured" | "fallback_raw_text" | "parse_attempted_but_failed"
        )
    {
        return Err(SegoMapError::InconsistentArtifact);
    }
    if review.reviewer.as_deref() != Some(policy.expected_reviewer.as_str())
        || review.engine_version.as_deref() != Some(policy.expected_engine_version.as_str())
        || review.review_mode.as_deref() != Some(policy.expected_review_mode.as_str())
    {
        return Err(SegoMapError::ProfileMismatch);
    }
    if review.scope != policy.expected_scope || review.diff_hash != policy.expected_diff_hash {
        return Err(SegoMapError::BindingMismatch);
    }
    let mut ids = BTreeSet::new();
    for (index, finding) in review.findings.iter().enumerate() {
        let key = if finding.id.trim().is_empty() {
            format!("legacy-{index}")
        } else {
            finding.id.clone()
        };
        if !ids.insert(key)
            || finding.file.trim().is_empty()
            || finding.title.trim().is_empty()
            || finding.evidence.trim().is_empty()
            || finding.risk.trim().is_empty()
            || finding.suggestion.trim().is_empty()
            || !(0.0..=1.0).contains(&finding.confidence)
            || finding.line == Some(0)
        {
            return Err(SegoMapError::InconsistentArtifact);
        }
        map_severity(&finding.severity)?;
    }
    let expected_highest = review
        .findings
        .iter()
        .map(|finding| finding.severity.as_str())
        .min_by_key(|severity| severity_rank_string(severity));
    if review.highest_severity.as_deref() != expected_highest {
        return Err(SegoMapError::InconsistentArtifact);
    }
    // Consumer-side disposition for the rev 3 observation fields: an
    // unnamable data-egress destination or compute boundary is refused
    // outright (fail-closed); it is never read as `none`, and a missing
    // field (an unobserving producer path) is refused the same way.
    match (
        review.data_egress_class.as_deref(),
        review.compute_boundary.as_deref(),
    ) {
        (
            Some("none") | Some("provider") | Some("provider_and_fetch"),
            Some("local") | Some("remote"),
        ) => {}
        _ => return Err(SegoMapError::InconsistentArtifact),
    }
    Ok(())
}

fn evidence_reason(value: Option<&str>) -> UnverifiedReason {
    match value {
        Some("unverified_dependency") => UnverifiedReason::DependencyNotCaptured,
        Some("scope_not_captured") => UnverifiedReason::ScopeNotCaptured,
        Some("unverified_file") | Some("unverified_line") | None => {
            UnverifiedReason::InsufficientEvidence
        }
        Some("verified") => UnverifiedReason::InsufficientEvidence,
        Some(_) => UnverifiedReason::PolicyAmbiguous,
    }
}

fn map_severity(value: &str) -> Result<DiscrepancySeverity, SegoMapError> {
    match value {
        "critical" => Ok(DiscrepancySeverity::Blocker),
        "high" => Ok(DiscrepancySeverity::Major),
        "medium" => Ok(DiscrepancySeverity::Minor),
        "low" => Ok(DiscrepancySeverity::Nit),
        "info" => Ok(DiscrepancySeverity::Info),
        _ => Err(SegoMapError::InconsistentArtifact),
    }
}

const fn severity_rank(value: DiscrepancySeverity) -> u8 {
    match value {
        DiscrepancySeverity::Blocker => 1,
        DiscrepancySeverity::Major => 2,
        DiscrepancySeverity::Minor => 3,
        DiscrepancySeverity::Nit => 4,
        DiscrepancySeverity::Info => 5,
        DiscrepancySeverity::Unspecified => 255,
    }
}

const fn severity_rank_string(value: &str) -> u8 {
    match value.as_bytes() {
        b"critical" => 1,
        b"high" => 2,
        b"medium" => 3,
        b"low" => 4,
        b"info" => 5,
        _ => 255,
    }
}

fn stable_id(prefix: &str, seed: &str) -> String {
    let digest = hex::encode(Sha256::digest(seed.as_bytes()));
    format!("{prefix}_{}", &digest[..24])
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::artifact::v1::HashAlgorithm;

    fn policy(positive_acceptance: bool) -> SegoMapperPolicy {
        SegoMapperPolicy {
            criterion_id: "criterion:local".to_owned(),
            requirement: CriterionRequirement::MustPass,
            checker_profile_ref: ContractReference {
                contract_id: "profile:local".to_owned(),
                version: "1".to_owned(),
                sha256: "a".repeat(64),
            },
            contract_id: SEGO_REVIEW_ARTIFACT_CONTRACT_ID.to_owned(),
            contract_revision: SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION,
            expected_scope: "staged".to_owned(),
            expected_diff_hash: "b".repeat(64),
            expected_reviewer: "sego".to_owned(),
            expected_engine_version: "0.1.9".to_owned(),
            expected_review_mode: "model_code_review".to_owned(),
            positive_acceptance,
            failure_threshold: DiscrepancySeverity::Major,
            raw_output_artifact_id: "artifact:configured-raw-output".to_owned(),
            raw_output_address: ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "c".repeat(64),
                byte_length: 1,
            },
            finding_evidence: BTreeMap::new(),
        }
    }

    #[test]
    fn a_declared_stable_code_is_read_from_a_single_line_answer() {
        assert_eq!(
            captured_failure_code(br#"{"schema_version":1,"status":"budget_exceeded"}"#),
            Some("budget_exceeded".to_owned())
        );
        assert_eq!(
            captured_failure_code(br#"{"safe_reason_code":"model_unavailable"}"#),
            Some("model_unavailable".to_owned())
        );
        assert_eq!(
            captured_failure_code(b"warning: retrying\n{\"reason_code\":\"budget_exceeded\"}\n"),
            Some("budget_exceeded".to_owned())
        );
    }

    #[test]
    fn free_text_and_unstable_values_are_not_promoted_to_codes() {
        for bytes in [
            b"".as_slice(),
            b"review stopped: the declared budget of 4000 tokens was reached",
            br#"{"message":"review stopped: budget reached"}"#,
            br#"{"status":"FAILED"}"#,
            br#"{"status":"no spaces allowed here"}"#,
            br#"{"status":42}"#,
        ] {
            assert_eq!(
                captured_failure_code(bytes),
                None,
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn a_cited_detail_artifact_replaces_the_configured_raw_output() {
        let configured = checker_failure_result_with_detail(
            &policy(false),
            "execution-1",
            CheckerProcessFailure::Crashed,
            None,
        );
        assert_eq!(
            configured
                .criterion_result
                .safe_detail_artifact_id
                .as_deref(),
            Some("artifact:configured-raw-output")
        );
        let captured = checker_failure_result_with_detail(
            &policy(false),
            "execution-1",
            CheckerProcessFailure::Crashed,
            Some("artifact:verification-output:sealed-failure"),
        );
        assert_eq!(
            captured.criterion_result.safe_detail_artifact_id.as_deref(),
            Some("artifact:verification-output:sealed-failure")
        );
        // A failed checker never becomes a pass, cited capture or not.
        assert_eq!(
            captured.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
        assert_eq!(
            configured.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
    }

    #[test]
    fn an_answer_glued_to_wrapper_text_is_still_one_object() {
        assert_eq!(
            captured_failure_code(
                b"running 1 test
{\"schema_version\":1,\"status\":\"budget_exceeded\"}test ok"
            ),
            Some("budget_exceeded".to_owned())
        );
        assert_eq!(
            captured_failure_code(br#"prefix {"status":"budget_exceeded"#),
            None,
            "a truncated object is never read as an answer"
        );
    }
}
