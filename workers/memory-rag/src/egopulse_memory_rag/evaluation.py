from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from math import log2
from pathlib import Path
from typing import Any

from .retrieval import (
    ALGORITHM_ID,
    MAX_RESULTS,
    MemoryRecord,
    RetrievalRequest,
    RetrievalResult,
    RetrievalWorkerError,
    digest_text,
    retrieve,
)


Retriever = Callable[[RetrievalRequest, Sequence[MemoryRecord]], RetrievalResult]


class RetrievalEvaluationError(ValueError):
    """The dataset or candidate result violates the evaluation boundary."""


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    request: RetrievalRequest
    records: tuple[MemoryRecord, ...]
    relevant_memory_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class CaseMetrics:
    case_id: str
    recall_at_k: float
    reciprocal_rank: float
    ndcg_at_k: float
    returned_count: int


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    dataset_id: str
    dataset_sha256: str
    algorithm_id: str
    case_count: int
    k: int
    recall_at_k: float
    mean_reciprocal_rank: float
    ndcg_at_k: float
    cases: tuple[CaseMetrics, ...]

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def load_dataset(path: Path) -> tuple[str, str, tuple[EvaluationCase, ...]]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise RetrievalEvaluationError("dataset is not readable canonical JSON") from error
    if not isinstance(payload, dict):
        raise RetrievalEvaluationError("dataset root must be an object")
    dataset_id = _required_text(payload, "dataset_id")
    wire_cases = payload.get("cases")
    if not isinstance(wire_cases, list) or not wire_cases:
        raise RetrievalEvaluationError("dataset cases must be a non-empty array")
    cases = tuple(_parse_case(value) for value in wire_cases)
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise RetrievalEvaluationError("dataset case_id values must be unique")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return dataset_id, sha256(canonical).hexdigest(), cases


def evaluate_retriever(
    *,
    dataset_id: str,
    dataset_sha256: str,
    algorithm_id: str,
    cases: Sequence[EvaluationCase],
    retriever: Retriever,
    k: int,
) -> EvaluationReport:
    if not dataset_id.strip() or not _is_sha256(dataset_sha256):
        raise RetrievalEvaluationError("dataset identity is incomplete")
    if not algorithm_id.strip():
        raise RetrievalEvaluationError("algorithm_id is required")
    if not cases:
        raise RetrievalEvaluationError("at least one evaluation case is required")
    if not 1 <= k <= MAX_RESULTS:
        raise RetrievalEvaluationError("k is outside the worker result limit")

    case_metrics: list[CaseMetrics] = []
    for case in cases:
        _validate_case(case)
        first = _run_candidate(retriever, case)
        second = _run_candidate(retriever, case)
        if first != second:
            raise RetrievalEvaluationError(
                f"candidate result is nondeterministic for case {case.case_id}"
            )
        _validate_result(case, first, algorithm_id)
        ranked_ids = [candidate.memory_id for candidate in first.candidates[:k]]
        relevant_ranks = [
            rank
            for rank, memory_id in enumerate(ranked_ids, start=1)
            if memory_id in case.relevant_memory_ids
        ]
        recall = len(relevant_ranks) / len(case.relevant_memory_ids)
        reciprocal_rank = 1.0 / relevant_ranks[0] if relevant_ranks else 0.0
        dcg = sum(1.0 / log2(rank + 1) for rank in relevant_ranks)
        ideal_count = min(len(case.relevant_memory_ids), k)
        ideal_dcg = sum(1.0 / log2(rank + 1) for rank in range(1, ideal_count + 1))
        case_metrics.append(
            CaseMetrics(
                case_id=case.case_id,
                recall_at_k=round(recall, 8),
                reciprocal_rank=round(reciprocal_rank, 8),
                ndcg_at_k=round(dcg / ideal_dcg, 8),
                returned_count=len(first.candidates),
            )
        )

    count = len(case_metrics)
    return EvaluationReport(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=algorithm_id,
        case_count=count,
        k=k,
        recall_at_k=round(sum(value.recall_at_k for value in case_metrics) / count, 8),
        mean_reciprocal_rank=round(
            sum(value.reciprocal_rank for value in case_metrics) / count, 8
        ),
        ndcg_at_k=round(sum(value.ndcg_at_k for value in case_metrics) / count, 8),
        cases=tuple(case_metrics),
    )


def evaluate_lexical_dataset(path: Path, *, k: int) -> EvaluationReport:
    dataset_id, dataset_sha256, cases = load_dataset(path)
    return evaluate_retriever(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=ALGORITHM_ID,
        cases=cases,
        retriever=retrieve,
        k=k,
    )


def _parse_case(value: Any) -> EvaluationCase:
    if not isinstance(value, dict):
        raise RetrievalEvaluationError("each dataset case must be an object")
    case_id = _required_text(value, "case_id")
    query = _required_text(value, "query")
    scope_ref = _required_text(value, "scope_ref")
    relevant = value.get("relevant_memory_ids")
    if not isinstance(relevant, list) or not relevant:
        raise RetrievalEvaluationError(
            f"case {case_id} relevant_memory_ids must be non-empty"
        )
    relevant_ids = frozenset(_text_item(item, "relevant_memory_ids") for item in relevant)
    if len(relevant_ids) != len(relevant):
        raise RetrievalEvaluationError(f"case {case_id} has duplicate relevance ids")
    wire_records = value.get("records")
    if not isinstance(wire_records, list) or not wire_records:
        raise RetrievalEvaluationError(f"case {case_id} records must be non-empty")
    records: list[MemoryRecord] = []
    for wire_record in wire_records:
        if not isinstance(wire_record, dict):
            raise RetrievalEvaluationError(f"case {case_id} record must be an object")
        memory_id = _required_text(wire_record, "memory_id")
        content = _required_text(wire_record, "content")
        record_scope = str(wire_record.get("scope_ref", scope_ref)).strip()
        records.append(
            MemoryRecord(
                memory_id=memory_id,
                content=content,
                content_sha256=digest_text(content),
                source_ref=f"evaluation:{case_id}:{memory_id}",
                scope_ref=record_scope,
            )
        )
    return EvaluationCase(
        case_id=case_id,
        request=RetrievalRequest(
            query=query,
            scope_ref=scope_ref,
            max_results=min(MAX_RESULTS, len(records)),
        ),
        records=tuple(records),
        relevant_memory_ids=relevant_ids,
    )


def _validate_case(case: EvaluationCase) -> None:
    try:
        case.request.validate()
        for record in case.records:
            record.validate()
    except RetrievalWorkerError as error:
        raise RetrievalEvaluationError(f"case {case.case_id} is invalid: {error}") from error
    record_ids = {record.memory_id for record in case.records}
    if len(record_ids) != len(case.records):
        raise RetrievalEvaluationError(f"case {case.case_id} has duplicate memory ids")
    if not case.relevant_memory_ids.issubset(record_ids):
        raise RetrievalEvaluationError(f"case {case.case_id} relevance references are unknown")
    if any(record.scope_ref != case.request.scope_ref for record in case.records):
        raise RetrievalEvaluationError(f"case {case.case_id} crosses a Memory scope")


def _run_candidate(retriever: Retriever, case: EvaluationCase) -> RetrievalResult:
    try:
        return retriever(case.request, case.records)
    except RetrievalWorkerError as error:
        raise RetrievalEvaluationError(
            f"candidate rejected evaluation case {case.case_id}: {error}"
        ) from error


def _validate_result(
    case: EvaluationCase, result: RetrievalResult, algorithm_id: str
) -> None:
    if result.algorithm_id != algorithm_id:
        raise RetrievalEvaluationError("candidate algorithm identity drifted")
    if result.query_sha256 != digest_text(case.request.query):
        raise RetrievalEvaluationError("candidate query digest drifted")
    if len(result.candidates) > case.request.max_results:
        raise RetrievalEvaluationError("candidate exceeded the request result limit")
    records = {record.memory_id: record for record in case.records}
    seen: set[str] = set()
    for candidate in result.candidates:
        if candidate.memory_id in seen:
            raise RetrievalEvaluationError("candidate returned a duplicate Memory reference")
        seen.add(candidate.memory_id)
        source = records.get(candidate.memory_id)
        if source is None:
            raise RetrievalEvaluationError("candidate returned an unknown Memory reference")
        if (
            candidate.source_ref != source.source_ref
            or candidate.content_sha256 != source.content_sha256
        ):
            raise RetrievalEvaluationError("candidate reference integrity drifted")
        if not 0.0 <= candidate.score <= 1.0:
            raise RetrievalEvaluationError("candidate score is outside the frozen range")
    if not result.evidence_ref.strip():
        raise RetrievalEvaluationError("candidate evidence_ref is required")


def _required_text(value: dict[str, Any], field: str) -> str:
    return _text_item(value.get(field), field)


def _text_item(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RetrievalEvaluationError(f"{field} must be non-empty text")
    return value.strip()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate an EgoPulse retrieval candidate")
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--k", type=int, default=8)
    arguments = parser.parse_args(argv)
    report = evaluate_lexical_dataset(arguments.dataset, k=arguments.k)
    print(report.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
