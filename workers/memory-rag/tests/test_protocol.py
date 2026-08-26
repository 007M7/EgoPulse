from __future__ import annotations

from io import BytesIO
import hashlib

import pytest

from egopulse.memory.v1 import memory_pb2
from egopulse_memory_rag import (
    ALGORITHM_ID,
    ProtocolWorkerError,
    digest_text,
    handle_request,
    serve,
)


SNAPSHOT_SHA256 = "a" * 64


def wire_request(
    *,
    content: str = "Rust owns accepted Memory facts.",
    scope_ref: str = "scope:founder",
    record_scope_ref: str | None = None,
    revision: int = 7,
    algorithm_profile: str = ALGORITHM_ID,
) -> memory_pb2.MemoryRetrievalRequest:
    return memory_pb2.MemoryRetrievalRequest(
        retrieval=memory_pb2.RetrievalRequest(
            query="accepted Memory",
            scope_ref=scope_ref,
            snapshot_sha256=SNAPSHOT_SHA256,
            max_results=8,
            min_score=0.0,
            algorithm_profile=algorithm_profile,
        ),
        accepted_records=[
            memory_pb2.AcceptedMemoryInput(
                memory_id="memory-01",
                content=content,
                content_sha256=digest_text(content),
                source_ref="source:memory-01",
                scope_ref=record_scope_ref or scope_ref,
                revision=revision,
            )
        ],
    )


def test_protocol_round_trip_echoes_snapshot_and_returns_references_only() -> None:
    response = memory_pb2.RetrievalResponse()
    response.ParseFromString(handle_request(wire_request().SerializeToString()))

    assert response.algorithm_id == ALGORITHM_ID
    assert response.query_sha256 == hashlib.sha256(b"accepted Memory").hexdigest()
    assert response.snapshot_sha256 == SNAPSHOT_SHA256
    assert len(response.candidates) == 1
    assert response.candidates[0].memory_id == "memory-01"
    assert response.candidates[0].source_ref == "source:memory-01"
    assert response.candidates[0].content_sha256 == digest_text(
        "Rust owns accepted Memory facts."
    )
    assert response.candidates[0].matched_terms
    assert response.evidence_ref.startswith("memory-rag-evidence-sha256:")
    assert len(response.evidence_ref.rsplit(":", 1)[1]) == 64


def test_protocol_response_is_deterministic_for_record_order() -> None:
    equivalent_a = wire_request()
    second_content = "Memory facts remain scope bound."
    equivalent_a.accepted_records.add(
        memory_id="memory-02",
        content=second_content,
        content_sha256=digest_text(second_content),
        source_ref="source:memory-02",
        scope_ref="scope:founder",
        revision=8,
    )
    equivalent_b = memory_pb2.MemoryRetrievalRequest()
    equivalent_b.CopyFrom(equivalent_a)
    equivalent_b.accepted_records.reverse()
    assert handle_request(equivalent_a.SerializeToString()) == handle_request(
        equivalent_b.SerializeToString()
    )


@pytest.mark.parametrize(
    ("wire_message", "message"),
    [
        (wire_request(algorithm_profile="embedding-v1"), "unsupported algorithm_profile"),
        (wire_request(record_scope_ref="scope:other"), "scope"),
        (wire_request(revision=0), "revision"),
    ],
)
def test_protocol_rejects_boundary_violations(
    wire_message: memory_pb2.MemoryRetrievalRequest, message: str
) -> None:
    with pytest.raises(ProtocolWorkerError, match=message):
        handle_request(wire_message.SerializeToString())


def test_protocol_rejects_invalid_snapshot_and_malformed_protobuf() -> None:
    invalid = wire_request()
    invalid.retrieval.snapshot_sha256 = "not-a-digest"
    with pytest.raises(ProtocolWorkerError, match="snapshot_sha256"):
        handle_request(invalid.SerializeToString())

    with pytest.raises(ProtocolWorkerError, match="valid Memory Protobuf"):
        handle_request(b"not-protobuf")


def test_framed_worker_reads_one_request_and_writes_one_response() -> None:
    request = wire_request().SerializeToString(deterministic=True)
    input_stream = BytesIO(len(request).to_bytes(4, "big") + request)
    output_stream = BytesIO()

    serve(input_stream, output_stream)

    output = output_stream.getvalue()
    response_length = int.from_bytes(output[:4], "big")
    assert response_length == len(output) - 4
    response = memory_pb2.RetrievalResponse()
    response.ParseFromString(output[4:])
    assert response.snapshot_sha256 == SNAPSHOT_SHA256


def test_framed_worker_rejects_truncated_header() -> None:
    with pytest.raises(ProtocolWorkerError, match="header is truncated"):
        serve(BytesIO(b"\x00\x00\x00"), BytesIO())
