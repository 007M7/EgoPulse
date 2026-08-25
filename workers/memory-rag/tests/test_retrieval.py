from __future__ import annotations

import pytest

from egopulse_memory_rag import (
    MAX_QUERY_BYTES,
    MAX_TOTAL_CONTENT_BYTES,
    MemoryRecord,
    RetrievalRequest,
    RetrievalWorkerError,
    digest_text,
    retrieve,
)


def record(
    memory_id: str,
    content: str,
    *,
    state: str = "accepted",
    scope_ref: str = "scope:founder",
    salience: float = 0.0,
) -> MemoryRecord:
    return MemoryRecord(
        memory_id=memory_id,
        content=content,
        content_sha256=digest_text(content),
        source_ref=f"source:{memory_id}",
        scope_ref=scope_ref,
        state=state,  # type: ignore[arg-type]
        salience=salience,
    )


def test_retrieval_returns_references_without_returning_memory_content() -> None:
    result = retrieve(
        RetrievalRequest(query="Rust authority boundary", scope_ref="scope:founder"),
        [
            record("m-02", "The Python worker cannot own Rust authority facts."),
            record("m-01", "Rust owns the deterministic authority boundary.", salience=1.0),
        ],
    )

    assert result.algorithm_id == "lexical-overlap-v0"
    assert [candidate.memory_id for candidate in result.candidates] == ["m-01", "m-02"]
    assert not hasattr(result.candidates[0], "content")
    assert result.evidence_ref.startswith("memory-rag-evidence-sha256:")


def test_candidate_revoked_and_out_of_scope_records_are_not_retrieved() -> None:
    result = retrieve(
        RetrievalRequest(query="memory governance", scope_ref="scope:founder"),
        [
            record("accepted", "Memory governance is founder controlled."),
            record("candidate", "Memory governance is only a proposal.", state="candidate"),
            record("revoked", "Memory governance was revoked.", state="revoked"),
            record("other-scope", "Memory governance for another scope.", scope_ref="scope:other"),
        ],
    )

    assert [candidate.memory_id for candidate in result.candidates] == ["accepted"]


def test_input_digest_and_duplicate_identity_fail_closed() -> None:
    bad = record("bad", "original")
    bad = MemoryRecord(
        memory_id=bad.memory_id,
        content="tampered",
        content_sha256=bad.content_sha256,
        source_ref=bad.source_ref,
        scope_ref=bad.scope_ref,
    )
    with pytest.raises(RetrievalWorkerError, match="digest mismatch"):
        retrieve(RetrievalRequest("original", "scope:founder"), [bad])

    duplicate = record("same", "same")
    with pytest.raises(RetrievalWorkerError, match="duplicate"):
        retrieve(RetrievalRequest("same", "scope:founder"), [duplicate, duplicate])


@pytest.mark.parametrize(
    "retrieval_request",
    [
        RetrievalRequest("", "scope:founder"),
        RetrievalRequest("query", ""),
        RetrievalRequest("query", "scope:founder", max_results=0),
        RetrievalRequest("query", "scope:founder", min_score=1.1),
    ],
)
def test_invalid_request_is_rejected(retrieval_request: RetrievalRequest) -> None:
    with pytest.raises(RetrievalWorkerError):
        retrieve(retrieval_request, [])


def test_utf8_query_limit_is_measured_in_bytes() -> None:
    query = "界" * (MAX_QUERY_BYTES // len("界".encode("utf-8")) + 1)
    with pytest.raises(RetrievalWorkerError, match="query exceeds"):
        retrieve(RetrievalRequest(query, "scope:founder"), [])


def test_total_supplied_content_limit_fails_closed() -> None:
    content = "x" * (MAX_TOTAL_CONTENT_BYTES + 1)
    with pytest.raises(RetrievalWorkerError, match="total content exceeds"):
        retrieve(
            RetrievalRequest("x", "scope:founder"),
            [record("oversized", content)],
        )


def test_tie_break_and_evidence_are_deterministic() -> None:
    records = [
        record("b", "same term"),
        record("a", "same term"),
    ]
    request = RetrievalRequest("same term", "scope:founder")
    first = retrieve(request, records)
    second = retrieve(request, list(reversed(records)))

    assert [candidate.memory_id for candidate in first.candidates] == ["a", "b"]
    assert first == second
