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
            Some(policy.raw_output_artifact_id.clone()),
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
        ),
        discrepancies: Vec::new(),
        unverified_items: item.into_iter().collect(),
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
                    vec![policy.raw_output_artifact_id.clone()],
                    Vec::new(),
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
        safe_detail_artifact_id: Some(policy.raw_output_artifact_id.clone()),
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
