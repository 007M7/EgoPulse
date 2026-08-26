from __future__ import annotations

from collections.abc import Sequence
from math import nan
from pathlib import Path

import pytest

from egopulse_memory_rag.evaluation import evaluate_retriever, load_dataset
from egopulse_memory_rag.experimental import (
    EmbeddingProfile,
    ExactVectorRetriever,
    ReciprocalRankFusionRetriever,
)
from egopulse_memory_rag.retrieval import (
    ALGORITHM_ID,
    MemoryRecord,
    RetrievalCandidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalWorkerError,
    digest_text,
    retrieve,
)


DATASET = Path(__file__).parents[1] / "evaluation" / "baseline-v0.json"


def record(memory_id: str, content: str) -> MemoryRecord:
    return MemoryRecord(
        memory_id=memory_id,
        content=content,
        content_sha256=digest_text(content),
        source_ref=f"source:{memory_id}",
        scope_ref="scope:founder",
    )


class FixtureEmbedder:
    def __init__(self, vectors: dict[str, tuple[float, ...]]) -> None:
        self._vectors = vectors

    def __call__(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        return tuple(self._vectors[text] for text in texts)


def profile() -> EmbeddingProfile:
    return EmbeddingProfile(
        provider="evaluation-fixture",
        model="semantic-boundary-fixture",
        revision="sha256:fixture-v0",
        dimensions=2,
    )


def test_exact_vector_retriever_recovers_a_paraphrase_without_persistence() -> None:
    authority = record("mem-authority", "Rust owns accepted Memory state.")
    algorithm = record(
        "mem-algorithm", "Python performs replaceable retrieval algorithms."
    )
    query = "Who controls durable facts?"
    retriever = ExactVectorRetriever(
        profile(),
        FixtureEmbedder(
            {
                query: (1.0, 0.0),
                authority.content: (1.0, 0.0),
                algorithm.content: (0.0, 1.0),
            }
        ),
    )

    result = retriever(
        RetrievalRequest(query=query, scope_ref="scope:founder"),
        (authority, algorithm),
    )

    assert result.algorithm_id == retriever.algorithm_id
    assert [candidate.memory_id for candidate in result.candidates] == ["mem-authority"]
    assert result.candidates[0].score == 1.0
    assert result.candidates[0].matched_terms == ()
    assert result.evidence_ref.startswith("memory-rag-evidence-sha256:")


def test_rrf_fuses_rankings_and_preserves_reference_integrity() -> None:
    authority = record("mem-authority", "Rust authority owns accepted Memory state.")
    algorithm = record(
        "mem-algorithm", "Python performs replaceable retrieval algorithms."
    )
    query = "Rust authority boundary"
    semantic = ExactVectorRetriever(
        profile(),
        FixtureEmbedder(
            {
                query: (1.0, 0.0),
                authority.content: (1.0, 0.0),
                algorithm.content: (0.5, 0.5),
            }
        ),
    )
    hybrid = ReciprocalRankFusionRetriever(
        left=retrieve,
        left_algorithm_id=ALGORITHM_ID,
        right=semantic,
        right_algorithm_id=semantic.algorithm_id,
    )

    result = hybrid(
        RetrievalRequest(query=query, scope_ref="scope:founder", max_results=2),
        (authority, algorithm),
    )

    assert result.algorithm_id == hybrid.algorithm_id
    assert [candidate.memory_id for candidate in result.candidates] == [
        "mem-authority",
        "mem-algorithm",
    ]
    assert result.candidates[0].score == 1.0
    assert result.candidates[0].source_ref == authority.source_ref
    assert result.candidates[0].content_sha256 == authority.content_sha256
    assert result.candidates[0].matched_terms == ("authority", "rust")


def test_fixture_semantic_and_hybrid_candidates_pass_the_evaluation_gate() -> None:
    dataset_id, dataset_sha256, cases = load_dataset(DATASET)
    vectors = {
        "Rust authority boundary": (1.0, 0.0),
        "Rust owns the deterministic authority boundary.": (1.0, 0.0),
        "Rust owns accepted Memory state.": (1.0, 0.0),
        "Python performs replaceable retrieval algorithms.": (0.0, 1.0),
        "Who controls durable facts?": (1.0, 0.0),
        "The control plane records a durable dispatch.": (0.0, 1.0),
    }
    semantic = ExactVectorRetriever(profile(), FixtureEmbedder(vectors))
    hybrid = ReciprocalRankFusionRetriever(
        left=retrieve,
        left_algorithm_id=ALGORITHM_ID,
        right=semantic,
        right_algorithm_id=semantic.algorithm_id,
    )

    semantic_report = evaluate_retriever(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=semantic.algorithm_id,
        cases=cases,
        retriever=semantic,
        k=2,
    )
    hybrid_report = evaluate_retriever(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=hybrid.algorithm_id,
        cases=cases,
        retriever=hybrid,
        k=2,
    )

    assert semantic_report.recall_at_k == 1.0
    assert semantic_report.mean_reciprocal_rank == 1.0
    assert hybrid_report.recall_at_k == 1.0
    assert hybrid_report.mean_reciprocal_rank == 1.0


def test_rrf_accepts_an_empty_bounded_snapshot() -> None:
    semantic = ExactVectorRetriever(
        profile(), FixtureEmbedder({"authority": (1.0, 0.0)})
    )
    hybrid = ReciprocalRankFusionRetriever(
        left=retrieve,
        left_algorithm_id=ALGORITHM_ID,
        right=semantic,
        right_algorithm_id=semantic.algorithm_id,
    )

    result = hybrid(
        RetrievalRequest(query="authority", scope_ref="scope:founder"),
        (),
    )

    assert result.candidates == ()
    assert result.evidence_ref.startswith("memory-rag-evidence-sha256:")


@pytest.mark.parametrize(
    ("embedder", "message"),
    [
        (lambda texts: ((1.0, 0.0),), "wrong vector count"),
        (lambda texts: tuple((1.0,) for _ in texts), "dimensions drifted"),
        (lambda texts: tuple((nan, 1.0) for _ in texts), "non-finite"),
        (lambda texts: tuple((0.0, 0.0) for _ in texts), "zero magnitude"),
    ],
)
def test_exact_vector_retriever_fails_closed_on_embedding_drift(
    embedder: object, message: str
) -> None:
    memory = record("mem-authority", "Rust owns accepted Memory state.")
    retriever = ExactVectorRetriever(profile(), embedder)  # type: ignore[arg-type]

    with pytest.raises(RetrievalWorkerError, match=message):
        retriever(
            RetrievalRequest(query="authority", scope_ref="scope:founder"),
            (memory,),
        )


def test_rrf_rejects_child_reference_drift() -> None:
    memory = record("mem-authority", "Rust authority owns accepted Memory state.")

    def drifting_child(
        request: RetrievalRequest, records: Sequence[MemoryRecord]
    ) -> RetrievalResult:
        result = retrieve(request, list(records))
        candidate = result.candidates[0]
        return RetrievalResult(
            algorithm_id="drifting-child-v0",
            query_sha256=result.query_sha256,
            candidates=(
                RetrievalCandidate(
                    memory_id=candidate.memory_id,
                    source_ref="source:tampered",
                    content_sha256=candidate.content_sha256,
                    score=candidate.score,
                    matched_terms=candidate.matched_terms,
                ),
            ),
            evidence_ref=result.evidence_ref,
        )

    hybrid = ReciprocalRankFusionRetriever(
        left=retrieve,
        left_algorithm_id=ALGORITHM_ID,
        right=drifting_child,
        right_algorithm_id="drifting-child-v0",
    )

    with pytest.raises(RetrievalWorkerError, match="reference integrity drifted"):
        hybrid(
            RetrievalRequest(query="Rust authority", scope_ref="scope:founder"),
            (memory,),
        )
