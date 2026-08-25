from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Literal


MAX_QUERY_BYTES = 16 * 1024
MAX_ROUTING_FIELD_BYTES = 4 * 1024
MAX_RECORDS = 2_048
MAX_RESULTS = 64
MAX_TOTAL_CONTENT_BYTES = 8 * 1024 * 1024
ALGORITHM_ID = "lexical-overlap-v0"
MemoryState = Literal["accepted", "candidate", "revoked"]
_TOKEN_PATTERN = re.compile(r"[0-9a-zA-Z_]+|[\u4e00-\u9fff]")


class RetrievalWorkerError(ValueError):
    """Input is outside the read-only worker's declared boundary."""


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    """A governed record supplied by the Rust authority.

    The worker verifies the content digest but does not decide whether a
    record is authoritative. Only records already marked ``accepted`` and in
    the requested scope can participate in retrieval.
    """

    memory_id: str
    content: str
    content_sha256: str
    source_ref: str
    scope_ref: str
    state: MemoryState = "accepted"

    def validate(self) -> None:
        if not self.memory_id.strip():
            raise RetrievalWorkerError("memory_id is required")
        if not self.source_ref.strip() or not self.scope_ref.strip():
            raise RetrievalWorkerError("source_ref and scope_ref are required")
        if len(self.memory_id.encode("utf-8")) > MAX_ROUTING_FIELD_BYTES:
            raise RetrievalWorkerError("memory_id exceeds the worker limit")
        if len(self.source_ref.encode("utf-8")) > MAX_ROUTING_FIELD_BYTES:
            raise RetrievalWorkerError("source_ref exceeds the worker limit")
        if len(self.scope_ref.encode("utf-8")) > MAX_ROUTING_FIELD_BYTES:
            raise RetrievalWorkerError("scope_ref exceeds the worker limit")
        if self.state not in {"accepted", "candidate", "revoked"}:
            raise RetrievalWorkerError("memory state is unknown")
        if digest_text(self.content) != self.content_sha256.lower():
            raise RetrievalWorkerError("memory content digest mismatch")


@dataclass(frozen=True, slots=True)
class RetrievalRequest:
    query: str
    scope_ref: str
    max_results: int = 8
    min_score: float = 0.0

    def validate(self) -> None:
        if not self.query.strip():
            raise RetrievalWorkerError("query is required")
        if len(self.query.encode("utf-8")) > MAX_QUERY_BYTES:
            raise RetrievalWorkerError("query exceeds the worker limit")
        if not self.scope_ref.strip():
            raise RetrievalWorkerError("scope_ref is required")
        if len(self.scope_ref.encode("utf-8")) > MAX_ROUTING_FIELD_BYTES:
            raise RetrievalWorkerError("scope_ref exceeds the worker limit")
        if not 1 <= self.max_results <= MAX_RESULTS:
            raise RetrievalWorkerError("max_results is outside the worker limit")
        if not 0.0 <= self.min_score <= 1.0:
            raise RetrievalWorkerError("min_score must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class RetrievalCandidate:
    memory_id: str
    source_ref: str
    content_sha256: str
    score: float
    matched_terms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    algorithm_id: str
    query_sha256: str
    candidates: tuple[RetrievalCandidate, ...]
    evidence_ref: str


def retrieve(
    request: RetrievalRequest,
    records: tuple[MemoryRecord, ...] | list[MemoryRecord],
) -> RetrievalResult:
    """Rank accepted records without creating or mutating Memory facts.

    This is deliberately a lexical baseline. Embedding and reranking models
    can be added behind the same read-only input/output boundary after their
    cost, model identity and evaluation evidence are separately reviewed.
    """

    request.validate()
    if len(records) > MAX_RECORDS:
        raise RetrievalWorkerError("record count exceeds the worker limit")

    query_terms = _tokens(request.query)
    if not query_terms:
        raise RetrievalWorkerError("query contains no searchable terms")

    seen_ids: set[str] = set()
    accepted: list[MemoryRecord] = []
    total_content_bytes = 0
    for record in records:
        record.validate()
        total_content_bytes += len(record.content.encode("utf-8"))
        if total_content_bytes > MAX_TOTAL_CONTENT_BYTES:
            raise RetrievalWorkerError("total content exceeds the worker limit")
        if record.memory_id in seen_ids:
            raise RetrievalWorkerError("duplicate memory_id in input")
        seen_ids.add(record.memory_id)
        if record.state != "accepted":
            raise RetrievalWorkerError("memory state is not accepted")
        if record.scope_ref != request.scope_ref:
            raise RetrievalWorkerError("memory scope does not match the request")
        accepted.append(record)

    document_terms = [_tokens(record.content) for record in accepted]
    document_frequency: dict[str, int] = {}
    for terms in document_terms:
        for term in set(terms):
            document_frequency[term] = document_frequency.get(term, 0) + 1

    scored: list[RetrievalCandidate] = []
    for record, terms in zip(accepted, document_terms, strict=True):
        matched = tuple(sorted(query_terms.intersection(terms)))
        if not matched:
            continue
        weighted_matches = sum(
            _inverse_document_frequency(document_frequency[term], len(accepted))
            for term in matched
        )
        query_weight = sum(
            _inverse_document_frequency(document_frequency.get(term, 0), len(accepted))
            for term in query_terms
        )
        lexical_score = weighted_matches / query_weight if query_weight else 0.0
        score = lexical_score
        if score >= request.min_score:
            scored.append(
                RetrievalCandidate(
                    memory_id=record.memory_id,
                    source_ref=record.source_ref,
                    content_sha256=record.content_sha256.lower(),
                    score=round(score, 8),
                    matched_terms=matched,
                )
            )

    scored.sort(key=lambda candidate: (-candidate.score, candidate.memory_id))
    candidates = tuple(scored[: request.max_results])
    query_sha256 = digest_text(request.query)
    evidence_payload = {
        "algorithm_id": ALGORITHM_ID,
        "candidates": [
            {
                "memory_id": candidate.memory_id,
                "source_ref": candidate.source_ref,
                "content_sha256": candidate.content_sha256,
                "score": candidate.score,
                "matched_terms": list(candidate.matched_terms),
            }
            for candidate in candidates
        ],
        "max_results": request.max_results,
        "min_score": request.min_score,
        "query_sha256": query_sha256,
        "scope_ref": request.scope_ref,
    }
    evidence_ref = "memory-rag-evidence-sha256:" + sha256(
        json.dumps(evidence_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return RetrievalResult(
        algorithm_id=ALGORITHM_ID,
        query_sha256=query_sha256,
        candidates=candidates,
        evidence_ref=evidence_ref,
    )


def digest_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _tokens(value: str) -> set[str]:
    return {match.group(0).casefold() for match in _TOKEN_PATTERN.finditer(value)}


def _inverse_document_frequency(document_count: int, total_documents: int) -> float:
    # Smooth IDF keeps unseen query terms useful without allowing them to
    # dominate a result. The denominator is always positive for a candidate.
    import math

    return math.log((total_documents + 1) / (document_count + 1)) + 1.0
