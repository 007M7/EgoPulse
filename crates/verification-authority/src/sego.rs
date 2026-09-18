use egopulse_domain_contracts::v01::egopulse::artifact::v1::{ContentAddress, HashAlgorithm};
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
    /// The identity-evidence strength the checker itself reported for the
    /// route it actually called, carried through to the persisted authority
    /// record. `None` means no artifact reported one (a process-level checker
    /// failure, or a deterministically observed review that has no checker
    /// route to attest to). This is a *claim by the checker*, never a
    /// provider-side attestation, and it never raises an outcome.
    pub identity_evidence: Option<String>,
    /// The named reason the checker could not report its endpoint, when it
    /// declared one. Carried alongside `identity_evidence` so the gap is
    /// visible downstream instead of looking like an omission.
    pub identity_evidence_gap: Option<String>,
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

/// The only identity-evidence strength a checker can produce today: the route
/// was derived from the model name and confirmed against the endpoint actually
/// called. It is self-reported resolution, never provider-side attestation.
const IDENTITY_EVIDENCE_SELF_REPORTED: &str = "self_reported_resolution";

/// Cross-party reconciliation reason codes. Each names one way the
/// coordinating party and the checker disagree about a delivered review.
/// Holding is the only response any of them permits: none authorizes a
/// re-run, a re-identification or an automatic acceptance.
pub const RECON_INVOCATION_MISMATCH: &str = "SEGO_RECON_INVOCATION_MISMATCH";
pub const RECON_REVIEW_ID_MISMATCH: &str = "SEGO_RECON_REVIEW_ID_MISMATCH";
pub const RECON_CONTENT_DIGEST_MISMATCH: &str = "SEGO_RECON_CONTENT_DIGEST_MISMATCH";
pub const RECON_NOT_AN_ARTIFACT: &str = "SEGO_RECON_NOT_AN_ARTIFACT";

/// One party's record of a review it believes exists for an invocation.
///
/// All three fields are needed together. The invocation binds the delivery to
/// the work the coordinator still holds open; the review identity binds it to
/// the artifact the checker says it produced; the content address binds it to
/// the exact bytes. Any two agreeing is not enough — a rewritten artifact keeps
/// its name, and a renamed artifact keeps its bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewReceipt {
    pub invocation_id: String,
    pub review_id: String,
    pub content: ContentAddress,
}

/// Reads the review identity out of the artifact bytes and computes the content
/// address of those same bytes, so the receipt describes exactly this delivery.
///
/// Bytes that carry no usable review identity yield no receipt. Synthesising an
/// empty one would let a non-answer compare equal to a record that is also
/// empty, which is the opposite of what reconciliation is for.
pub fn review_receipt_from_bytes(
    invocation_id: &str,
    raw: &[u8],
) -> Result<ReviewReceipt, &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| RECON_NOT_AN_ARTIFACT)?;
    let review_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(RECON_NOT_AN_ARTIFACT)?;
    Ok(ReviewReceipt {
        invocation_id: invocation_id.to_owned(),
        review_id: review_id.to_owned(),
        content: ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: hex::encode(Sha256::digest(raw)),
            byte_length: u64::try_from(raw.len()).unwrap_or(u64::MAX),
        },
    })
}

/// What the coordinating party may do with one delivery from the checker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    /// The held and arriving records agree on all three identities. The
    /// `review_id` is the *held* one, so a duplicate delivery resolves to the
    /// identity already held rather than minting a second one.
    Consistent { review_id: String },
    /// The records disagree, or nothing proves they agree. The run holds. This
    /// variant deliberately carries no identity, so a caller cannot persist a
    /// fresh id and hide the disagreement behind it.
    Held { reason_code: &'static str },
}

/// Reconciles one arriving receipt against the record the coordinator holds.
///
/// This is the single place the two parties' views are compared. A
/// disagreement never yields an artifact identity, never triggers a re-run and
/// never accepts the arriving bytes, because an unknown external outcome
/// belongs to its owner to settle rather than to repeat.
pub fn reconcile_receipt(
    held: Option<&ReviewReceipt>,
    arrived: &ReviewReceipt,
) -> ReconciliationOutcome {
    let Some(held) = held else {
        // No dispatch record exists for this invocation. A late or foreign
        // artifact is not evidence that the held work finished, and adopting it
        // would let a previous life's output settle this one.
        return ReconciliationOutcome::Held {
            reason_code: RECON_INVOCATION_MISMATCH,
        };
    };
    if held.invocation_id != arrived.invocation_id {
        return ReconciliationOutcome::Held {
            reason_code: RECON_INVOCATION_MISMATCH,
        };
    }
    if held.review_id != arrived.review_id {
        return ReconciliationOutcome::Held {
            reason_code: RECON_REVIEW_ID_MISMATCH,
        };
    }
    if held.content != arrived.content {
        return ReconciliationOutcome::Held {
            reason_code: RECON_CONTENT_DIGEST_MISMATCH,
        };
    }
    ReconciliationOutcome::Consistent {
        review_id: held.review_id.clone(),
    }
}

/// The dispatch record this coordinator holds for one review invocation, or
/// `None` when it holds none. Only a held record can make a delivery
/// consistent.
#[must_use]
pub fn held_review_receipt(
    invocation_id: &str,
    raw_output_address: &ContentAddress,
) -> ReviewReceipt {
    ReviewReceipt {
        invocation_id: invocation_id.to_owned(),
        // The checker is required to name its review with the invocation it was
        // given, so the expected review identity is the invocation identity.
        review_id: invocation_id.to_owned(),
        content: raw_output_address.clone(),
    }
}

/// The one identity gap this contract names: the checker had no base-URL
/// accessor for the provider, so it could not report the endpoint it called.
const IDENTITY_GAP_NO_ENDPOINT_ACCESSOR: &str = "no_endpoint_accessor_for_provider";

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
    /// How strongly the reported identity is evidenced. Only
    /// `self_reported_resolution` is producible today: the checker derived the
    /// route from the model name and confirmed it against the endpoint it
    /// actually called. It is *not* provider-side attestation, so it must never
    /// be read as a verified identity. Absent on artifacts written before the
    /// field existed.
    #[serde(default)]
    identity_evidence: Option<String>,
    /// Named evidence gap when the checker could not observe the endpoint at
    /// all. A non-null value means identity verification is impossible for this
    /// run and the gap is recorded instead of being hidden.
    #[serde(default)]
    identity_evidence_gap: Option<String>,
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
            identity_evidence: review.identity_evidence.clone(),
            identity_evidence_gap: review.identity_evidence_gap.clone(),
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
                identity_evidence: review.identity_evidence.clone(),
                identity_evidence_gap: review.identity_evidence_gap.clone(),
                review_id: review.id,
            })
        }
        "no_diff" => {
            // The checker found no reviewable diff in the selected scope. That is
            // neither a checker failure nor a pass: there is simply no material a
            // review could attest to, so the criterion stays unverified and names
            // the missing coverage instead of inheriting an outcome from silence.
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
                identity_evidence: review.identity_evidence.clone(),
                identity_evidence_gap: review.identity_evidence_gap.clone(),
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
        // A checker that never produced a review artifact has no route to
        // report, so there is no identity evidence and no declared gap. This is
        // `None`, not an inferred value.
        identity_evidence: None,
        identity_evidence_gap: None,
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
                ),
                discrepancies: Vec::new(),
                unverified_items: Vec::new(),
                identity_evidence: review.identity_evidence.clone(),
                identity_evidence_gap: review.identity_evidence_gap.clone(),
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
            identity_evidence: review.identity_evidence.clone(),
            identity_evidence_gap: review.identity_evidence_gap.clone(),
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
        identity_evidence: review.identity_evidence.clone(),
        identity_evidence_gap: review.identity_evidence_gap.clone(),
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
            "structured" | "fallback_raw_text" | "parse_attempted_but_failed" | "no_diff"
        )
    {
        return Err(SegoMapError::InconsistentArtifact);
    }
    // Identity evidence is either absent (artifacts written before the field
    // existed) or the single strength the checker can actually produce.
    // Anything else claims evidence the checker cannot have, so it is refused
    // instead of being recorded as if the identity had been verified.
    if review
        .identity_evidence
        .as_deref()
        .is_some_and(|evidence| evidence != IDENTITY_EVIDENCE_SELF_REPORTED)
    {
        return Err(SegoMapError::InconsistentArtifact);
    }
    // A named gap must be one this contract knows about. An unrecognised gap
    // would silently read as "no gap worth naming", so it is refused instead.
    if review
        .identity_evidence_gap
        .as_deref()
        .is_some_and(|gap| gap != IDENTITY_GAP_NO_ENDPOINT_ACCESSOR)
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

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::HashAlgorithm, common::v1::ContractReference,
    };

    fn profile_ref() -> ContractReference {
        ContractReference {
            contract_id: "repository-review".to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn policy() -> SegoMapperPolicy {
        SegoMapperPolicy {
            criterion_id: "review".to_owned(),
            requirement: CriterionRequirement::MustPass,
            checker_profile_ref: profile_ref(),
            expected_scope: "scope:one".to_owned(),
            expected_diff_hash: "b".repeat(64),
            expected_reviewer: "codex-review".to_owned(),
            expected_engine_version: "1".to_owned(),
            expected_review_mode: "model_code_review".to_owned(),
            positive_acceptance: false,
            failure_threshold: DiscrepancySeverity::Major,
            raw_output_artifact_id: "artifact:review-output".to_owned(),
            raw_output_address: ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "c".repeat(64),
                byte_length: 1,
            },
            finding_evidence: BTreeMap::new(),
        }
    }

    /// A well-formed review body; individual tests mutate one field to build the
    /// counter-example they need.
    fn review_json(parse_status: &str, findings: &str, finding_count: usize) -> Vec<u8> {
        format!(
            r#"{{
  "schema_version": 1,
  "id": "review-1",
  "scope": "scope:one",
  "diff_hash": "{}",
  "finding_count": {finding_count},
  "highest_severity": null,
  "parse_status": "{parse_status}",
  "findings": [{findings}],
  "reviewer": "codex-review",
  "engine_version": "1",
  "review_mode": "model_code_review"
}}"#,
            "b".repeat(64)
        )
        .into_bytes()
    }

    /// `parse_attempted_but_failed` must not be mistaken for "no findings": it is
    /// an error outcome with no unverified item of its own.
    #[test]
    fn parse_attempted_but_failed_maps_to_error_without_unverified_items() {
        let mapped = map_sego_review(&review_json("parse_attempted_but_failed", "", 0), &policy())
            .expect("parse-failed review maps");
        assert_eq!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
        assert_eq!(
            mapped.criterion_result.evidence_coverage,
            EvidenceCoverage::Missing as i32
        );
        assert!(mapped.unverified_items.is_empty());
        assert!(mapped.discrepancies.is_empty());
    }

    /// `fallback_raw_text` keeps the review unverified and points its unverified
    /// item at the sealed raw output rather than inventing findings.
    #[test]
    fn fallback_raw_text_stays_unverified_and_references_raw_output() {
        let mapped = map_sego_review(&review_json("fallback_raw_text", "", 0), &policy())
            .expect("fallback review maps");
        assert_eq!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Unverified as i32
        );
        assert_eq!(mapped.unverified_items.len(), 1);
        assert_eq!(
            mapped.unverified_items[0].reason,
            UnverifiedReason::InsufficientEvidence as i32
        );
        assert_eq!(
            mapped.unverified_items[0].context_artifact_id.as_deref(),
            Some("artifact:review-output")
        );
        assert!(mapped.discrepancies.is_empty());
    }

    /// `no_diff` means there was no reviewable material, which is neither a
    /// checker failure nor a pass: the criterion must stay unverified and name
    /// the missing coverage rather than inherit an outcome from silence.
    #[test]
    fn no_diff_stays_unverified_and_never_becomes_passed_or_error() {
        let mapped = map_sego_review(&review_json("no_diff", "", 0), &policy())
            .expect("no-diff review maps");
        assert_eq!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Unverified as i32
        );
        assert_ne!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Passed as i32
        );
        assert_ne!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
        assert_eq!(
            mapped.criterion_result.evidence_coverage,
            EvidenceCoverage::Missing as i32
        );
        assert_eq!(mapped.unverified_items.len(), 1);
        assert_eq!(
            mapped.unverified_items[0].reason,
            UnverifiedReason::InsufficientEvidence as i32
        );
        assert_eq!(
            mapped.unverified_items[0].context_artifact_id.as_deref(),
            Some("artifact:review-output")
        );
        assert!(mapped.discrepancies.is_empty());
    }

    /// The real artifacts Sego delivered for C-3
    /// (`SEGO-TO-EGOPULSE-C3-INPUTS-20260912.md`, `c3-samples/artifacts/`) map
    /// through this mapper. The bytes are the delivered files, copied verbatim;
    /// they pin the consumer-side mapping against the producer's real output
    /// instead of against a synthetic fixture of our own shape.
    #[test]
    fn real_c3_artifacts_from_sego_map_as_unverified() {
        let delivered: [(&str, &[u8]); 3] = [
            (
                "normal",
                include_bytes!(
                    "../tests/fixtures/sego-c3/normal-review-1789229112-15daf69af550.json"
                )
                .as_slice(),
            ),
            (
                "consume",
                include_bytes!(
                    "../tests/fixtures/sego-c3/consume-review-1789229113-eccdef7c9226.json"
                )
                .as_slice(),
            ),
            (
                "corr",
                include_bytes!(
                    "../tests/fixtures/sego-c3/corr-review-1789229112-dc168607b517.json"
                )
                .as_slice(),
            ),
        ];
        for (name, bytes) in delivered {
            // The mapper binds a review to the checker profile and input binding
            // that produced it, and refuses a mismatch. So the policy the test
            // supplies must carry the profile the artifact itself reports —
            // exactly what the production path has to do from the sealed profile.
            // Only those five binding/profile fields are taken from the artifact;
            // everything else (identity policy, threshold, acceptance) stays ours.
            let reported: serde_json::Value =
                serde_json::from_slice(bytes).expect("delivered artifact is JSON");
            let mut bound = policy();
            bound.expected_scope = reported["scope"].as_str().expect("scope").to_owned();
            bound.expected_diff_hash = reported["diff_hash"]
                .as_str()
                .expect("diff_hash")
                .to_owned();
            bound.expected_reviewer = reported["reviewer"].as_str().expect("reviewer").to_owned();
            bound.expected_engine_version = reported["engine_version"]
                .as_str()
                .expect("engine_version")
                .to_owned();
            bound.expected_review_mode = reported["review_mode"]
                .as_str()
                .expect("review_mode")
                .to_owned();

            let mapped = map_sego_review(bytes, &bound)
                .unwrap_or_else(|error| panic!("real C-3 artifact {name} did not map: {error:?}"));
            // Every delivered artifact reports `fallback_raw_text`, so the review
            // is unverified with missing coverage: never Passed, never Error. An
            // absent `identity_evidence_gap` key must read the same as an explicit
            // null, which the delivered artifacts exercise.
            assert_eq!(
                mapped.criterion_result.outcome,
                CriterionOutcome::Unverified as i32,
                "{name}"
            );
            assert_ne!(
                mapped.criterion_result.outcome,
                CriterionOutcome::Passed as i32,
                "{name}"
            );
            assert_eq!(
                mapped.criterion_result.evidence_coverage,
                EvidenceCoverage::Missing as i32,
                "{name}"
            );
            assert_eq!(mapped.unverified_items.len(), 1, "{name}");
            assert_eq!(
                mapped.unverified_items[0].reason,
                UnverifiedReason::InsufficientEvidence as i32,
                "{name}"
            );
            assert!(mapped.discrepancies.is_empty(), "{name}");
        }
    }

    /// The one strength a checker can produce is recorded as-is. It is carried
    /// from the artifact, never upgraded: nothing here may turn a derived route
    /// into a verified identity.
    #[test]
    fn self_reported_resolution_is_the_only_accepted_identity_evidence() {
        let mut body = String::from_utf8(review_json("structured", "", 0)).expect("utf8 body");
        body = body.replacen(
            "\"parse_status\"",
            "\"identity_evidence\":\"self_reported_resolution\",\"parse_status\"",
            1,
        );
        let mapped = map_sego_review(body.as_bytes(), &policy()).expect("allowed value maps");
        // Recording the identity strength must not upgrade the outcome: without
        // positive acceptance a structured zero-finding review stays unverified,
        // and a valid `self_reported_resolution` must not change that.
        assert_eq!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Unverified as i32
        );
        assert_ne!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Passed as i32
        );
    }

    /// Any other strength claims evidence the checker cannot have, so it is
    /// refused instead of being recorded as a stronger identity.
    #[test]
    fn unproducible_identity_evidence_is_rejected() {
        for claimed in ["provider_attested", "attested", "verified"] {
            let mut body = String::from_utf8(review_json("structured", "", 0)).expect("utf8 body");
            body = body.replacen(
                "\"parse_status\"",
                &format!("\"identity_evidence\":\"{claimed}\",\"parse_status\""),
                1,
            );
            assert!(
                matches!(
                    map_sego_review(body.as_bytes(), &policy()),
                    Err(SegoMapError::InconsistentArtifact)
                ),
                "claimed identity evidence {claimed} must be refused"
            );
        }
    }

    /// An unknown named gap would read as "no gap worth naming", so it fails
    /// closed; the one gap this contract knows stays acceptable.
    #[test]
    fn unknown_identity_evidence_gap_is_rejected() {
        let mut body = String::from_utf8(review_json("structured", "", 0)).expect("utf8 body");
        body = body.replacen(
            "\"parse_status\"",
            "\"identity_evidence_gap\":\"no_endpoint_accessor_for_provider\",\"parse_status\"",
            1,
        );
        assert!(map_sego_review(body.as_bytes(), &policy()).is_ok());

        let mut bad = String::from_utf8(review_json("structured", "", 0)).expect("utf8 body");
        bad = bad.replacen(
            "\"parse_status\"",
            "\"identity_evidence_gap\":\"something_else\",\"parse_status\"",
            1,
        );
        assert!(matches!(
            map_sego_review(bad.as_bytes(), &policy()),
            Err(SegoMapError::InconsistentArtifact)
        ));
    }

    /// An unknown `parse_status` is rejected instead of being treated as a pass.
    #[test]
    fn unknown_parse_status_is_rejected() {
        assert!(matches!(
            map_sego_review(&review_json("succeeded", "", 0), &policy()),
            Err(SegoMapError::InconsistentArtifact)
        ));
    }

    /// A finding count that disagrees with the findings array is inconsistent.
    #[test]
    fn finding_count_mismatch_is_rejected() {
        let one_finding = r#"{"id":"f1","severity":"low","file":"a.rs","line":1,
            "title":"t","evidence":"e","risk":"r","suggestion":"s","confidence":0.5,
            "evidence_status":"unverified"}"#;
        assert!(matches!(
            map_sego_review(&review_json("structured", one_finding, 2), &policy()),
            Err(SegoMapError::InconsistentArtifact)
        ));
    }

    /// A different reviewer, engine or review mode must not be accepted as this
    /// policy's result.
    #[test]
    fn profile_drift_is_rejected() {
        let mut body = String::from_utf8(review_json("structured", "", 0)).expect("utf8");
        body = body.replace("\"reviewer\": \"codex-review\"", "\"reviewer\": \"other\"");
        assert!(matches!(
            map_sego_review(body.as_bytes(), &policy()),
            Err(SegoMapError::ProfileMismatch)
        ));

        let mut engine = String::from_utf8(review_json("structured", "", 0)).expect("utf8");
        engine = engine.replace("\"engine_version\": \"1\"", "\"engine_version\": \"2\"");
        assert!(matches!(
            map_sego_review(engine.as_bytes(), &policy()),
            Err(SegoMapError::ProfileMismatch)
        ));
    }

    /// A result that is not bound to this scope and diff must not be accepted.
    #[test]
    fn binding_drift_is_rejected() {
        let body = String::from_utf8(review_json("structured", "", 0))
            .expect("utf8")
            .replace(&"b".repeat(64), &"d".repeat(64));
        assert!(matches!(
            map_sego_review(body.as_bytes(), &policy()),
            Err(SegoMapError::BindingMismatch)
        ));
    }

    /// Malformed bytes are refused before any status handling.
    #[test]
    fn malformed_json_is_rejected() {
        assert!(matches!(
            map_sego_review(b"{ not json", &policy()),
            Err(SegoMapError::InvalidJson)
        ));
    }

    /// Zero findings under a non-positive-acceptance policy must stay unverified:
    /// no findings is not a pass.
    #[test]
    fn structured_zero_findings_never_becomes_passed_without_positive_acceptance() {
        let mapped = map_sego_review(&review_json("structured", "", 0), &policy())
            .expect("structured review maps");
        assert_ne!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Passed as i32
        );
        assert_eq!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Unverified as i32
        );
        assert_eq!(mapped.unverified_items.len(), 1);
        assert_eq!(
            mapped.unverified_items[0].reason,
            UnverifiedReason::RequiresJudgement as i32
        );
    }

    /// An artifact carries the checker's own identity claim into the consumption
    /// object. The claim is recorded as stated and changes no outcome.
    #[test]
    fn identity_evidence_is_carried_to_the_consumption_object() {
        let claimed = String::from_utf8(review_json("structured", "", 0))
            .expect("utf8")
            .replace(
                "\"parse_status\"",
                "\"identity_evidence\": \"self_reported_resolution\", \"parse_status\"",
            );
        let mapped = map_sego_review(claimed.as_bytes(), &policy()).expect("mapped");
        assert_eq!(
            mapped.identity_evidence.as_deref(),
            Some(IDENTITY_EVIDENCE_SELF_REPORTED)
        );
        assert!(mapped.identity_evidence_gap.is_none());
        assert_ne!(
            mapped.criterion_result.outcome,
            CriterionOutcome::Passed as i32
        );

        let declared_gap = String::from_utf8(review_json("structured", "", 0))
            .expect("utf8")
            .replace(
                "\"parse_status\"",
                "\"identity_evidence_gap\": \"no_endpoint_accessor_for_provider\", \"parse_status\"",
            );
        let mapped = map_sego_review(declared_gap.as_bytes(), &policy()).expect("mapped");
        assert!(mapped.identity_evidence.is_none());
        assert_eq!(
            mapped.identity_evidence_gap.as_deref(),
            Some(IDENTITY_GAP_NO_ENDPOINT_ACCESSOR)
        );

        // An artifact that states neither claim carries neither. Absence is not
        // upgraded into a claim.
        let mapped = map_sego_review(&review_json("structured", "", 0), &policy()).expect("mapped");
        assert!(mapped.identity_evidence.is_none());
        assert!(mapped.identity_evidence_gap.is_none());
    }

    fn receipt_for(invocation_id: &str, body: &[u8]) -> ReviewReceipt {
        review_receipt_from_bytes(invocation_id, body).expect("review receipt")
    }

    /// A redelivery of the same artifact settles on the identity already held.
    /// It must not read as a second review, which is what would let duplicate
    /// delivery inflate one invocation into two results.
    #[test]
    fn duplicate_delivery_resolves_to_the_held_identity() {
        let body = review_json("structured", "", 0);
        let held = held_review_receipt("review-1", &receipt_for("review-1", &body).content);
        let arrived = receipt_for("review-1", &body);
        for _ in 0..3 {
            assert_eq!(
                reconcile_receipt(Some(&held), &arrived),
                ReconciliationOutcome::Consistent {
                    review_id: "review-1".to_owned()
                }
            );
        }
        // Mapping the same bytes twice is equally idempotent: the second pass
        // produces the same criterion and item identities, not new ones.
        let first = map_sego_review(&body, &policy()).expect("first mapping");
        let second = map_sego_review(&body, &policy()).expect("second mapping");
        assert_eq!(first.criterion_result, second.criterion_result);
        assert_eq!(first.discrepancies, second.discrepancies);
        assert_eq!(first.unverified_items, second.unverified_items);
        assert_eq!(first.review_id, second.review_id);
    }

    /// An artifact for an invocation this coordinator never opened is not
    /// evidence that held work finished, and no identity may be minted from it.
    #[test]
    fn late_artifact_without_a_held_dispatch_holds() {
        let arrived = receipt_for(
            "review-from-a-previous-life",
            &review_json("structured", "", 0),
        );
        let outcome = reconcile_receipt(None, &arrived);
        assert_eq!(
            outcome,
            ReconciliationOutcome::Held {
                reason_code: RECON_INVOCATION_MISMATCH
            }
        );
        assert!(
            !matches!(outcome, ReconciliationOutcome::Consistent { .. }),
            "a late artifact must never produce an artifact identity"
        );
    }

    /// An artifact delivered against another invocation must not be adopted by
    /// this one even when its bytes are well formed and mappable.
    #[test]
    fn artifact_for_another_invocation_holds() {
        let body = review_json("structured", "", 0);
        let held = held_review_receipt("review-1", &receipt_for("review-1", &body).content);
        let arrived = receipt_for("review-2", &body);
        assert_eq!(
            reconcile_receipt(Some(&held), &arrived),
            ReconciliationOutcome::Held {
                reason_code: RECON_INVOCATION_MISMATCH
            }
        );
    }

    /// Keeping the invocation but renaming the review is still a disagreement:
    /// the held invocation names exactly one review, not a family of them.
    #[test]
    fn renamed_review_cannot_substitute_for_the_held_one() {
        let body = review_json("structured", "", 0);
        let held = held_review_receipt("review-1", &receipt_for("review-1", &body).content);
        let renamed = String::from_utf8(body)
            .expect("utf8")
            .replace("\"id\": \"review-1\"", "\"id\": \"review-2\"")
            .into_bytes();
        assert_eq!(
            reconcile_receipt(Some(&held), &receipt_for("review-1", &renamed)),
            ReconciliationOutcome::Held {
                reason_code: RECON_REVIEW_ID_MISMATCH
            }
        );
    }

    /// A rewrite that keeps the review name is only detectable by content
    /// address. Both deliveries map cleanly on their own, which is precisely
    /// why the name cannot be the only thing compared.
    #[test]
    fn rewritten_bytes_that_keep_the_review_id_hold_on_the_content_address() {
        let body = review_json("structured", "", 0);
        let held = held_review_receipt("review-1", &receipt_for("review-1", &body).content);
        let rewritten = String::from_utf8(body.clone())
            .expect("utf8")
            .replace(
                "\"review_mode\": \"model_code_review\"",
                "\"review_mode\": \"model_code_review\", \"note\": \"rewritten\"",
            )
            .into_bytes();
        let arrived = receipt_for("review-1", &rewritten);
        assert_eq!(arrived.invocation_id, held.invocation_id);
        assert_eq!(arrived.review_id, held.review_id);
        assert_ne!(arrived.content, held.content);
        assert_eq!(
            reconcile_receipt(Some(&held), &arrived),
            ReconciliationOutcome::Held {
                reason_code: RECON_CONTENT_DIGEST_MISMATCH
            }
        );
        assert!(map_sego_review(&body, &policy()).is_ok());
        assert!(map_sego_review(&rewritten, &policy()).is_ok());
    }

    /// Bytes carrying no usable review identity produce no receipt. Synthesising
    /// one would let a non-answer compare equal to another non-answer.
    #[test]
    fn bytes_without_a_review_identity_yield_no_receipt() {
        for body in [
            b"".as_slice(),
            b"{ not json",
            b"{\"id\": \"  \"}",
            b"{\"id\": 3}",
            b"[]",
        ] {
            assert_eq!(
                review_receipt_from_bytes("review-1", body),
                Err(RECON_NOT_AN_ARTIFACT)
            );
        }
    }

    /// A checker that never returned a review has no route to report and no
    /// outcome to promote. Repeating the failure reproduces the same record
    /// rather than allocating a second identity.
    #[test]
    fn checker_timeout_is_an_error_that_never_becomes_a_pass() {
        let first = checker_failure_result(&policy(), "run:one", CheckerProcessFailure::Timeout);
        let second = checker_failure_result(&policy(), "run:one", CheckerProcessFailure::Timeout);
        assert_eq!(
            first.criterion_result.outcome,
            CriterionOutcome::Error as i32
        );
        assert_ne!(
            first.criterion_result.outcome,
            CriterionOutcome::Passed as i32
        );
        assert_eq!(
            first.criterion_result.evidence_coverage,
            EvidenceCoverage::Missing as i32
        );
        assert!(first.criterion_result.evidence_ids.is_empty());
        assert_eq!(
            first.unverified_items[0].reason,
            UnverifiedReason::CheckerUnavailable as i32
        );
        assert!(first.identity_evidence.is_none());
        assert!(first.identity_evidence_gap.is_none());
        assert_eq!(first, second);
    }

    /// Every reconciliation reason code is distinct, so a hold can always be
    /// attributed to one disagreement instead of a generic failure.
    #[test]
    fn reconciliation_reason_codes_are_distinct() {
        let codes = [
            RECON_INVOCATION_MISMATCH,
            RECON_REVIEW_ID_MISMATCH,
            RECON_CONTENT_DIGEST_MISMATCH,
            RECON_NOT_AN_ARTIFACT,
        ];
        let unique = codes.iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), codes.len());
    }
}
