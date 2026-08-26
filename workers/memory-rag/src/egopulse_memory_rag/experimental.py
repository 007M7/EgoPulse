from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
from math import isfinite, sqrt
from typing import Protocol

from .retrieval import (
    MAX_RESULTS,
    MemoryRecord,
    RetrievalCandidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalWorkerError,
    digest_text,
    validate_retrieval_input,
)


Vector = tuple[float, ...]
Retriever = Callable[[RetrievalRequest, Sequence[MemoryRecord]], RetrievalResult]


class Embedder(Protocol):
    """Keep query and document preprocessing distinct across model families."""

    def embed_query(self, text: str) -> Sequence[float]: ...

    def embed_documents(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...


@dataclass(frozen=True, slots=True)
class EmbeddingProfile:
    """Explicit identity for an evaluation-only embedding implementation."""

    provider: str
    model: str
    revision: str
    preprocessing: str
    dimensions: int

    def validate(self) -> None:
        for field, value in (
            ("provider", self.provider),
            ("model", self.model),
            ("revision", self.revision),
            ("preprocessing", self.preprocessing),
        ):
            if not value.strip():
                raise RetrievalWorkerError(f"embedding {field} is required")
            if len(value.encode("utf-8")) > 4 * 1024:
                raise RetrievalWorkerError(f"embedding {field} exceeds the worker limit")
        if not 1 <= self.dimensions <= 65_536:
            raise RetrievalWorkerError("embedding dimensions are outside the worker limit")

    @property
    def profile_sha256(self) -> str:
        self.validate()
        return _payload_sha256(
            {
                "dimensions": self.dimensions,
                "model": self.model,
                "preprocessing": self.preprocessing,
                "provider": self.provider,
                "revision": self.revision,
            }
        )


@dataclass(frozen=True, slots=True)
class ExactVectorRetriever:
    """Evaluation adapter using exhaustive cosine scoring over one snapshot.

    The embedder is injected so model selection remains outside the stable
    Memory ownership and protocol boundaries. This adapter creates no index
    and persists no vectors.
    """

    profile: EmbeddingProfile
    embedder: Embedder

    @property
    def algorithm_id(self) -> str:
        return f"exact-cosine-v0:{self.profile.profile_sha256[:16]}"

    def __call__(
        self, request: RetrievalRequest, records: Sequence[MemoryRecord]
    ) -> RetrievalResult:
        accepted = validate_retrieval_input(request, list(records))
        query_vector, document_vectors = self._embed(
            request.query, [record.content for record in accepted]
        )
        scored: list[RetrievalCandidate] = []
        for record, vector in zip(accepted, document_vectors, strict=True):
            score = min(1.0, max(0.0, _cosine_similarity(query_vector, vector)))
            if score <= 0.0 or score < request.min_score:
                continue
            scored.append(
                RetrievalCandidate(
                    memory_id=record.memory_id,
                    source_ref=record.source_ref,
                    content_sha256=record.content_sha256.lower(),
                    score=round(score, 8),
                    matched_terms=(),
                )
            )

        scored.sort(key=lambda candidate: (-candidate.score, candidate.memory_id))
        candidates = tuple(scored[: request.max_results])
        query_sha256 = digest_text(request.query)
        evidence_ref = "memory-rag-evidence-sha256:" + _payload_sha256(
            {
                "algorithm_id": self.algorithm_id,
                "candidates": [_candidate_payload(candidate) for candidate in candidates],
                "embedding_profile_sha256": self.profile.profile_sha256,
                "max_results": request.max_results,
                "min_score": request.min_score,
                "query_sha256": query_sha256,
                "scope_ref": request.scope_ref,
            }
        )
        return RetrievalResult(
            algorithm_id=self.algorithm_id,
            query_sha256=query_sha256,
            candidates=candidates,
            evidence_ref=evidence_ref,
        )

    def _embed(
        self, query: str, documents: Sequence[str]
    ) -> tuple[Vector, tuple[Vector, ...]]:
        self.profile.validate()
        try:
            raw_query = self.embedder.embed_query(query)
            raw_documents = self.embedder.embed_documents(documents)
        except Exception as error:
            raise RetrievalWorkerError("embedding provider failed") from error
        if len(raw_documents) != len(documents):
            raise RetrievalWorkerError("embedding provider returned the wrong vector count")

        vectors: list[Vector] = []
        for raw_vector in (raw_query, *raw_documents):
            if len(raw_vector) != self.profile.dimensions:
                raise RetrievalWorkerError("embedding vector dimensions drifted")
            values: list[float] = []
            for value in raw_vector:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise RetrievalWorkerError("embedding vector contains a non-number")
                number = float(value)
                if not isfinite(number):
                    raise RetrievalWorkerError("embedding vector contains a non-finite value")
                values.append(number)
            vector = tuple(values)
            if _magnitude(vector) == 0.0:
                raise RetrievalWorkerError("embedding vector has zero magnitude")
            vectors.append(vector)
        return vectors[0], tuple(vectors[1:])


@dataclass(frozen=True, slots=True)
class ReciprocalRankFusionRetriever:
    """Fuse two validated child rankings without coupling their score scales."""

    left: Retriever
    left_algorithm_id: str
    right: Retriever
    right_algorithm_id: str
    left_weight: float = 1.0
    right_weight: float = 1.0
    rank_constant: int = 60
    candidate_pool: int = MAX_RESULTS

    def validate(self) -> None:
        if not self.left_algorithm_id.strip() or not self.right_algorithm_id.strip():
            raise RetrievalWorkerError("RRF child algorithm identity is required")
        if self.left_algorithm_id == self.right_algorithm_id:
            raise RetrievalWorkerError("RRF child algorithm identities must differ")
        if (
            not isfinite(self.left_weight)
            or not isfinite(self.right_weight)
            or self.left_weight <= 0.0
            or self.right_weight <= 0.0
        ):
            raise RetrievalWorkerError("RRF child weights must be finite and positive")
        if not 1 <= self.rank_constant <= 10_000:
            raise RetrievalWorkerError("RRF rank constant is outside the worker limit")
        if not 1 <= self.candidate_pool <= MAX_RESULTS:
            raise RetrievalWorkerError("RRF candidate pool is outside the worker limit")

    @property
    def algorithm_id(self) -> str:
        self.validate()
        identity = _payload_sha256(
            {
                "candidate_pool": self.candidate_pool,
                "left_algorithm_id": self.left_algorithm_id,
                "left_weight": self.left_weight,
                "rank_constant": self.rank_constant,
                "right_algorithm_id": self.right_algorithm_id,
                "right_weight": self.right_weight,
            }
        )
        return f"rrf-hybrid-v0:{identity[:16]}"

    def __call__(
        self, request: RetrievalRequest, records: Sequence[MemoryRecord]
    ) -> RetrievalResult:
        self.validate()
        accepted = validate_retrieval_input(request, list(records))
        child_request = RetrievalRequest(
            query=request.query,
            scope_ref=request.scope_ref,
            max_results=min(self.candidate_pool, max(1, len(accepted)), MAX_RESULTS),
            min_score=0.0,
        )
        left_result = self.left(child_request, accepted)
        right_result = self.right(child_request, accepted)
        sources = {record.memory_id: record for record in accepted}
        _validate_child_result(
            left_result, expected_algorithm_id=self.left_algorithm_id, request=child_request, sources=sources
        )
        _validate_child_result(
            right_result, expected_algorithm_id=self.right_algorithm_id, request=child_request, sources=sources
        )

        ranks: dict[str, float] = {}
        terms: dict[str, set[str]] = {}
        for result, weight in (
            (left_result, self.left_weight),
            (right_result, self.right_weight),
        ):
            for rank, candidate in enumerate(result.candidates, start=1):
                ranks[candidate.memory_id] = ranks.get(
                    candidate.memory_id, 0.0
                ) + weight / (self.rank_constant + rank)
                terms.setdefault(candidate.memory_id, set()).update(candidate.matched_terms)

        maximum_score = (self.left_weight + self.right_weight) / (
            self.rank_constant + 1
        )
        fused: list[RetrievalCandidate] = []
        for memory_id, raw_score in ranks.items():
            score = raw_score / maximum_score
            if score < request.min_score:
                continue
            source = sources[memory_id]
            fused.append(
                RetrievalCandidate(
                    memory_id=memory_id,
                    source_ref=source.source_ref,
                    content_sha256=source.content_sha256.lower(),
                    score=round(score, 8),
                    matched_terms=tuple(sorted(terms[memory_id])),
                )
            )
        fused.sort(key=lambda candidate: (-candidate.score, candidate.memory_id))
        candidates = tuple(fused[: request.max_results])
        query_sha256 = digest_text(request.query)
        evidence_ref = "memory-rag-evidence-sha256:" + _payload_sha256(
            {
                "algorithm_id": self.algorithm_id,
                "candidates": [_candidate_payload(candidate) for candidate in candidates],
                "child_evidence_refs": [
                    left_result.evidence_ref,
                    right_result.evidence_ref,
                ],
                "max_results": request.max_results,
                "min_score": request.min_score,
                "query_sha256": query_sha256,
                "scope_ref": request.scope_ref,
            }
        )
        return RetrievalResult(
            algorithm_id=self.algorithm_id,
            query_sha256=query_sha256,
            candidates=candidates,
            evidence_ref=evidence_ref,
        )


def _validate_child_result(
    result: RetrievalResult,
    *,
    expected_algorithm_id: str,
    request: RetrievalRequest,
    sources: dict[str, MemoryRecord],
) -> None:
    if result.algorithm_id != expected_algorithm_id:
        raise RetrievalWorkerError("RRF child algorithm identity drifted")
    if result.query_sha256 != digest_text(request.query):
        raise RetrievalWorkerError("RRF child query digest drifted")
    if len(result.candidates) > request.max_results:
        raise RetrievalWorkerError("RRF child exceeded the candidate pool")
    if not result.evidence_ref.strip():
        raise RetrievalWorkerError("RRF child evidence reference is required")

    seen: set[str] = set()
    for candidate in result.candidates:
        if candidate.memory_id in seen:
            raise RetrievalWorkerError("RRF child returned a duplicate Memory reference")
        seen.add(candidate.memory_id)
        source = sources.get(candidate.memory_id)
        if source is None:
            raise RetrievalWorkerError("RRF child returned an unknown Memory reference")
        if (
            candidate.source_ref != source.source_ref
            or candidate.content_sha256 != source.content_sha256.lower()
        ):
            raise RetrievalWorkerError("RRF child reference integrity drifted")
        if not 0.0 <= candidate.score <= 1.0:
            raise RetrievalWorkerError("RRF child score is outside the frozen range")


def _cosine_similarity(left: Vector, right: Vector) -> float:
    denominator = _magnitude(left) * _magnitude(right)
    if denominator == 0.0:
        raise RetrievalWorkerError("embedding vector has zero magnitude")
    return sum(a * b for a, b in zip(left, right, strict=True)) / denominator


def _magnitude(vector: Vector) -> float:
    return sqrt(sum(value * value for value in vector))


def _candidate_payload(candidate: RetrievalCandidate) -> dict[str, object]:
    return {
        "content_sha256": candidate.content_sha256,
        "matched_terms": list(candidate.matched_terms),
        "memory_id": candidate.memory_id,
        "score": candidate.score,
        "source_ref": candidate.source_ref,
    }


def _payload_sha256(payload: object) -> str:
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
