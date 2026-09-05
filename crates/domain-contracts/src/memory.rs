use crate::v01::egopulse::memory::v1::{AcceptedMemoryInput, RetrievalRequest, RetrievalResponse};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MEMORY_ALGORITHM_ID: &str = "lexical-overlap-v0";
pub const MEMORY_MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MEMORY_MAX_ROUTING_FIELD_BYTES: usize = 4 * 1024;
pub const MEMORY_MAX_RECORDS: usize = 2_048;
pub const MEMORY_MAX_RESULTS: usize = 64;
pub const MEMORY_MAX_TOTAL_CONTENT_BYTES: usize = 8 * 1024 * 1024;
pub const WORK_MEMORY_PACK_PROFILE_ID: &str = "egopulse/governed-memory-pack/v1";
pub const WORK_MEMORY_MAX_RESULTS: u32 = 8;
pub const WORK_MEMORY_MIN_SCORE: f64 = 0.0;
pub const WORK_MEMORY_MAX_SELECTED_CONTENT_BYTES: usize = 64 * 1024;
const EVIDENCE_PREFIX: &str = "memory-rag-evidence-sha256:";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemoryResponseError {
    #[error("retrieval query is required")]
    MissingQuery,
    #[error("retrieval scope is required")]
    MissingScope,
    #[error("retrieval snapshot digest is invalid")]
    InvalidSnapshot,
    #[error("retrieval algorithm profile is unsupported")]
    UnsupportedAlgorithm,
    #[error("retrieval max_results is outside the worker limit")]
    InvalidMaxResults,
    #[error("retrieval min_score is outside the worker limit")]
    InvalidMinScore,
    #[error("retrieval query exceeds the worker limit")]
    QueryTooLarge,
    #[error("accepted memory record count exceeds the worker limit")]
    TooManyRecords,
    #[error("accepted memory content exceeds the worker limit")]
    ContentTooLarge,
    #[error("accepted memory record is invalid")]
    InvalidRecord,
    #[error("accepted memory record digest does not match its content")]
    RecordDigestMismatch,
    #[error("accepted memory record scope does not match the request")]
    ScopeMismatch,
    #[error("accepted memory record identity is duplicated")]
    DuplicateRecord,
    #[error("retrieval response algorithm is invalid")]
    InvalidResponseAlgorithm,
    #[error("retrieval response query digest does not match the request")]
    QueryDigestMismatch,
    #[error("retrieval response snapshot digest does not match the request")]
    SnapshotMismatch,
    #[error("retrieval response candidate count is invalid")]
    InvalidCandidateCount,
    #[error("retrieval response candidate is invalid")]
    InvalidCandidate,
    #[error("retrieval response candidate identity is duplicated")]
    DuplicateCandidate,
    #[error("retrieval response candidate is not in the accepted snapshot")]
    UnknownCandidate,
    #[error("retrieval response candidate is not deterministically ordered")]
    NonDeterministicOrder,
    #[error("retrieval response evidence reference is invalid")]
    InvalidEvidence,
}

pub fn validate_retrieval_response(
    request: &RetrievalRequest,
    accepted_records: &[AcceptedMemoryInput],
    response: &RetrievalResponse,
) -> Result<(), MemoryResponseError> {
    validate_retrieval_input(request, accepted_records)?;

    if response.algorithm_id != MEMORY_ALGORITHM_ID {
        return Err(MemoryResponseError::InvalidResponseAlgorithm);
    }
    if response.query_sha256 != digest_text(&request.query) {
        return Err(MemoryResponseError::QueryDigestMismatch);
    }
    if response.snapshot_sha256 != request.snapshot_sha256 {
        return Err(MemoryResponseError::SnapshotMismatch);
    }
    if response.candidates.len() > request.max_results as usize
        || response.candidates.len() > MEMORY_MAX_RESULTS
    {
        return Err(MemoryResponseError::InvalidCandidateCount);
    }
    if !valid_evidence_ref(&response.evidence_ref) {
        return Err(MemoryResponseError::InvalidEvidence);
    }

    let mut previous: Option<(&str, f64)> = None;
    let mut seen = std::collections::HashSet::new();
    for candidate in &response.candidates {
        if !seen.insert(candidate.memory_id.as_str()) {
            return Err(MemoryResponseError::DuplicateCandidate);
        }
        let Some(record) = accepted_records
            .iter()
            .find(|record| record.memory_id == candidate.memory_id)
        else {
            return Err(MemoryResponseError::UnknownCandidate);
        };
        if candidate.source_ref != record.source_ref
            || candidate.content_sha256 != record.content_sha256
            || !valid_sha256(&candidate.content_sha256)
            || !candidate.score.is_finite()
            || !(0.0..=1.0).contains(&candidate.score)
            || candidate.matched_terms.is_empty()
        {
            return Err(MemoryResponseError::InvalidCandidate);
        }
        if let Some((previous_id, previous_score)) = previous
            && (candidate.score > previous_score
                || (candidate.score == previous_score
                    && candidate.memory_id.as_str() < previous_id))
        {
            return Err(MemoryResponseError::NonDeterministicOrder);
        }
        previous = Some((&candidate.memory_id, candidate.score));
    }
    Ok(())
}

pub fn validate_retrieval_input(
    request: &RetrievalRequest,
    accepted_records: &[AcceptedMemoryInput],
) -> Result<(), MemoryResponseError> {
    validate_request(request)?;
    validate_records(request, accepted_records)
}

fn validate_request(request: &RetrievalRequest) -> Result<(), MemoryResponseError> {
    if request.query.trim().is_empty() {
        return Err(MemoryResponseError::MissingQuery);
    }
    if request.scope_ref.trim().is_empty() {
        return Err(MemoryResponseError::MissingScope);
    }
    if request.query.len() > MEMORY_MAX_QUERY_BYTES
        || request.scope_ref.len() > MEMORY_MAX_ROUTING_FIELD_BYTES
    {
        return Err(MemoryResponseError::QueryTooLarge);
    }
    if !valid_sha256(&request.snapshot_sha256) {
        return Err(MemoryResponseError::InvalidSnapshot);
    }
    if request.algorithm_profile != MEMORY_ALGORITHM_ID {
        return Err(MemoryResponseError::UnsupportedAlgorithm);
    }
    if !(1..=MEMORY_MAX_RESULTS as u32).contains(&request.max_results) {
        return Err(MemoryResponseError::InvalidMaxResults);
    }
    if !request.min_score.is_finite() || !(0.0..=1.0).contains(&request.min_score) {
        return Err(MemoryResponseError::InvalidMinScore);
    }
    Ok(())
}

fn validate_records(
    request: &RetrievalRequest,
    records: &[AcceptedMemoryInput],
) -> Result<(), MemoryResponseError> {
    if records.len() > MEMORY_MAX_RECORDS {
        return Err(MemoryResponseError::TooManyRecords);
    }
    let mut total_content_bytes = 0;
    let mut seen = std::collections::HashSet::new();
    for record in records {
        if record.memory_id.trim().is_empty()
            || record.source_ref.trim().is_empty()
            || record.scope_ref.trim().is_empty()
            || record.memory_id.len() > MEMORY_MAX_ROUTING_FIELD_BYTES
            || record.source_ref.len() > MEMORY_MAX_ROUTING_FIELD_BYTES
            || record.scope_ref.len() > MEMORY_MAX_ROUTING_FIELD_BYTES
            || record.revision == 0
        {
            return Err(MemoryResponseError::InvalidRecord);
        }
        total_content_bytes += record.content.len();
        if total_content_bytes > MEMORY_MAX_TOTAL_CONTENT_BYTES {
            return Err(MemoryResponseError::ContentTooLarge);
        }
        if record.scope_ref != request.scope_ref {
            return Err(MemoryResponseError::ScopeMismatch);
        }
        if !seen.insert(record.memory_id.as_str()) {
            return Err(MemoryResponseError::DuplicateRecord);
        }
        if !valid_sha256(&record.content_sha256) {
            return Err(MemoryResponseError::RecordDigestMismatch);
        }
        if digest_text(&record.content) != record.content_sha256 {
            return Err(MemoryResponseError::RecordDigestMismatch);
        }
    }
    Ok(())
}

fn digest_text(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    hex::encode(digest.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_evidence_ref(value: &str) -> bool {
    value
        .strip_prefix(EVIDENCE_PREFIX)
        .is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v01::egopulse::memory::v1::RetrievalCandidate;

    fn request() -> RetrievalRequest {
        RetrievalRequest {
            query: "accepted Memory".to_owned(),
            scope_ref: "scope:founder".to_owned(),
            snapshot_sha256: "a".repeat(64),
            max_results: 8,
            min_score: 0.0,
            algorithm_profile: MEMORY_ALGORITHM_ID.to_owned(),
        }
    }

    fn record(memory_id: &str, content: &str) -> AcceptedMemoryInput {
        AcceptedMemoryInput {
            memory_id: memory_id.to_owned(),
            content: content.to_owned(),
            content_sha256: digest_text(content),
            source_ref: format!("source:{memory_id}"),
            scope_ref: "scope:founder".to_owned(),
            revision: 7,
        }
    }

    fn response(memory_id: &str, content: &str, score: f64) -> RetrievalResponse {
        RetrievalResponse {
            algorithm_id: MEMORY_ALGORITHM_ID.to_owned(),
            query_sha256: digest_text("accepted Memory"),
            snapshot_sha256: "a".repeat(64),
            candidates: vec![RetrievalCandidate {
                memory_id: memory_id.to_owned(),
                source_ref: format!("source:{memory_id}"),
                content_sha256: digest_text(content),
                score,
                matched_terms: vec!["memory".to_owned()],
            }],
            evidence_ref: format!("{EVIDENCE_PREFIX}{}", "b".repeat(64)),
        }
    }

    #[test]
    fn accepted_response_passes_all_authority_checks() {
        let request = request();
        let records = vec![record("memory-01", "Rust owns accepted Memory facts.")];
        let response = response("memory-01", "Rust owns accepted Memory facts.", 1.0);

        validate_retrieval_response(&request, &records, &response)
            .expect("valid Worker response is accepted");
    }

    #[test]
    fn response_rejects_snapshot_digest_drift() {
        let request = request();
        let records = vec![record("memory-01", "Rust owns accepted Memory facts.")];
        let mut response = response("memory-01", "Rust owns accepted Memory facts.", 1.0);
        response.snapshot_sha256 = "c".repeat(64);

        assert_eq!(
            validate_retrieval_response(&request, &records, &response),
            Err(MemoryResponseError::SnapshotMismatch)
        );
    }

    #[test]
    fn input_rejects_noncanonical_uppercase_snapshot_digest() {
        let mut request = request();
        request.snapshot_sha256 = "A".repeat(64);

        assert_eq!(
            validate_retrieval_input(&request, &[]),
            Err(MemoryResponseError::InvalidSnapshot)
        );
    }

    #[test]
    fn response_rejects_unknown_and_out_of_order_candidates() {
        let request = request();
        let records = vec![
            record("memory-01", "Rust owns accepted Memory facts."),
            record("memory-02", "The Worker returns references only."),
        ];
        let mut unknown = response("memory-unknown", "Unknown content.", 1.0);
        assert_eq!(
            validate_retrieval_response(&request, &records, &unknown),
            Err(MemoryResponseError::UnknownCandidate)
        );

        let first = response("memory-01", "Rust owns accepted Memory facts.", 0.9)
            .candidates
            .pop()
            .expect("candidate");
        unknown = response("memory-02", "The Worker returns references only.", 0.2);
        unknown.candidates.push(first);
        assert_eq!(
            validate_retrieval_response(&request, &records, &unknown),
            Err(MemoryResponseError::NonDeterministicOrder)
        );
    }
}
