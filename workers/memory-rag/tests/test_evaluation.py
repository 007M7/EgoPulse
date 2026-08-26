from __future__ import annotations

from pathlib import Path

import pytest

from egopulse_memory_rag.evaluation import (
    EvaluationCase,
    RetrievalEvaluationError,
    evaluate_lexical_dataset,
    evaluate_retriever,
    load_dataset,
)
from egopulse_memory_rag.retrieval import (
    ALGORITHM_ID,
    MemoryRecord,
    RetrievalCandidate,
    RetrievalRequest,
    RetrievalResult,
    digest_text,
)


DATASET = Path(__file__).parents[1] / "evaluation" / "baseline-v0.json"


def test_lexical_baseline_records_the_semantic_recall_gap() -> None:
    report = evaluate_lexical_dataset(DATASET, k=2)

    assert report.dataset_id == "egopulse-memory-retrieval-smoke-v0"
    assert len(report.dataset_sha256) == 64
    assert report.algorithm_id == ALGORITHM_ID
    assert report.case_count == 2
    assert report.recall_at_k == 0.5
    assert report.mean_reciprocal_rank == 0.5
    assert report.ndcg_at_k == 0.5
    assert report.cases[0].recall_at_k == 1.0
    assert report.cases[1].recall_at_k == 0.0
    assert "query" not in report.to_json()
    assert "content" not in report.to_json()


def test_dataset_and_report_are_deterministic() -> None:
    first = evaluate_lexical_dataset(DATASET, k=2)
    second = evaluate_lexical_dataset(DATASET, k=2)

    assert first == second
    assert first.to_json() == second.to_json()


def test_candidate_cannot_return_an_unknown_memory_reference() -> None:
    dataset_id, dataset_sha256, cases = load_dataset(DATASET)

    def invalid_candidate(
        request: RetrievalRequest, records: tuple[MemoryRecord, ...]
    ) -> RetrievalResult:
        del records
        return RetrievalResult(
            algorithm_id="candidate-v0",
            query_sha256=digest_text(request.query),
            candidates=(
                RetrievalCandidate(
                    memory_id="unknown",
                    source_ref="evaluation:unknown",
                    content_sha256="0" * 64,
                    score=1.0,
                    matched_terms=(),
                ),
            ),
            evidence_ref="evaluation-only",
        )

    with pytest.raises(RetrievalEvaluationError, match="unknown Memory reference"):
        evaluate_retriever(
            dataset_id=dataset_id,
            dataset_sha256=dataset_sha256,
            algorithm_id="candidate-v0",
            cases=cases,
            retriever=invalid_candidate,
            k=2,
        )


def test_candidate_must_replay_the_exact_same_result() -> None:
    record = MemoryRecord(
        memory_id="memory-01",
        content="deterministic retrieval",
        content_sha256=digest_text("deterministic retrieval"),
        source_ref="evaluation:memory-01",
        scope_ref="scope:founder",
    )
    case = EvaluationCase(
        case_id="nondeterministic",
        request=RetrievalRequest("deterministic", "scope:founder", max_results=1),
        records=(record,),
        relevant_memory_ids=frozenset({record.memory_id}),
    )
    calls = 0

    def nondeterministic_candidate(
        request: RetrievalRequest, records: tuple[MemoryRecord, ...]
    ) -> RetrievalResult:
        nonlocal calls
        calls += 1
        source = records[0]
        return RetrievalResult(
            algorithm_id="candidate-v0",
            query_sha256=digest_text(request.query),
            candidates=(
                RetrievalCandidate(
                    memory_id=source.memory_id,
                    source_ref=source.source_ref,
                    content_sha256=source.content_sha256,
                    score=1.0 if calls == 1 else 0.5,
                    matched_terms=("deterministic",),
                ),
            ),
            evidence_ref=f"evaluation:{calls}",
        )

    with pytest.raises(RetrievalEvaluationError, match="nondeterministic"):
        evaluate_retriever(
            dataset_id="dataset",
            dataset_sha256="a" * 64,
            algorithm_id="candidate-v0",
            cases=(case,),
            retriever=nondeterministic_candidate,
            k=1,
        )
