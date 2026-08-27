from __future__ import annotations

import pytest

from egopulse_memory_rag import (
    MAX_QUERY_BYTES,
    MAX_RECORDS,
    MAX_RESULTS,
    MAX_ROUTING_FIELD_BYTES,
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
) -> MemoryRecord:
    return MemoryRecord(
        memory_id=memory_id,
        content=content,
        content_sha256=digest_text(content),
        source_ref=f"source:{memory_id}",
        scope_ref=scope_ref,
        state=state,  # type: ignore[arg-type]
    )


def test_retrieval_returns_references_without_returning_memory_content() -> None:
    result = retrieve(
        RetrievalRequest(query="Rust authority boundary", scope_ref="scope:founder"),
        [
            record("m-02", "The Python worker cannot own Rust authority facts."),
            record("m-01", "Rust owns the deterministic authority boundary."),
        ],
    )

    assert result.algorithm_id == "lexical-overlap-v0"
    assert [candidate.memory_id for candidate in result.candidates] == ["m-01", "m-02"]
    assert not hasattr(result.candidates[0], "content")
    assert result.query_sha256 == (
        "f569a1af01e40d1065be4369029f6a64c0b1ac5fb9bcad6dfcb0e41920fbcb52"
    )
    assert [
        (candidate.memory_id, candidate.content_sha256, candidate.score, candidate.matched_terms)
        for candidate in result.candidates
    ] == [
        (
            "m-01",
            "a3fe7f4a473dd1cdcea1ab86dfc4382f2918b11c498909f48cd5d40934e766d2",
            1.0,
            ("authority", "boundary", "rust"),
        ),
        (
            "m-02",
            "0d2951eb451b0535a50fc662d39a06ca48e977fd8f7dacb6ef68e9943627fc3d",
            0.58729129,
            ("authority", "rust"),
        ),
    ]
    assert (
        result.evidence_ref
        == "memory-rag-evidence-sha256:f698cda5b72eae1f7b155e42f9a4d63d0b3a235d8ac9134fb44b08a99843d958"
    )


@pytest.mark.parametrize(
    ("invalid_record", "error"),
    [
        (record("candidate", "Memory proposal.", state="candidate"), "not accepted"),
        (record("revoked", "Revoked memory.", state="revoked"), "not accepted"),
        (record("future", "Unknown state.", state="future"), "state is unknown"),
        (
            record("other-scope", "Other scope.", scope_ref="scope:other"),
            "scope does not match",
        ),
    ],
)
def test_candidate_revoked_and_out_of_scope_records_fail_closed(
    invalid_record: MemoryRecord,
    error: str,
) -> None:
    with pytest.raises(RetrievalWorkerError, match=error):
        retrieve(
            RetrievalRequest(query="memory", scope_ref="scope:founder"),
            [record("accepted", "Accepted memory."), invalid_record],
        )


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


def test_query_must_contain_a_searchable_term() -> None:
    with pytest.raises(RetrievalWorkerError, match="no searchable terms"):
        retrieve(RetrievalRequest("!?…", "scope:founder"), [])


def test_routing_fields_and_record_count_are_bounded() -> None:
    oversized_scope = "界" * (MAX_ROUTING_FIELD_BYTES // len("界".encode("utf-8")) + 1)
    with pytest.raises(RetrievalWorkerError, match="scope_ref exceeds"):
        retrieve(RetrievalRequest("query", oversized_scope), [])

    records = [record(f"m-{index}", "query") for index in range(MAX_RECORDS + 1)]
    with pytest.raises(RetrievalWorkerError, match="record count exceeds"):
        retrieve(RetrievalRequest("query", "scope:founder"), records)


def test_candidate_count_is_bounded_by_the_request_and_worker_ceiling() -> None:
    records = [record(f"m-{index:03d}", "same term") for index in range(MAX_RESULTS + 1)]
    result = retrieve(
        RetrievalRequest("same term", "scope:founder", max_results=MAX_RESULTS),
        records,
    )

    assert len(result.candidates) == MAX_RESULTS
    assert result.candidates[0].memory_id == "m-000"
    assert result.candidates[-1].memory_id == f"m-{MAX_RESULTS - 1:03d}"


def test_lexical_profile_has_no_undeclared_salience_input() -> None:
    assert not hasattr(record("m-01", "lexical only"), "salience")


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


def test_evidence_binds_request_result_limits() -> None:
    records = [record("m-01", "same term")]
    default = retrieve(RetrievalRequest("same term", "scope:founder"), records)
    different_max = retrieve(
        RetrievalRequest("same term", "scope:founder", max_results=1),
        records,
    )
    different_threshold = retrieve(
        RetrievalRequest("same term", "scope:founder", min_score=0.5),
        records,
    )

    assert default.candidates == different_max.candidates == different_threshold.candidates
    assert len({default.evidence_ref, different_max.evidence_ref, different_threshold.evidence_ref}) == 3
