from __future__ import annotations

from hashlib import sha256
import json
import re
import sys
from typing import BinaryIO

from google.protobuf.message import DecodeError

from egopulse.memory.v1 import memory_pb2

from .retrieval import (
    ALGORITHM_ID,
    MAX_RESULTS,
    MemoryRecord,
    RetrievalRequest,
    RetrievalWorkerError,
    retrieve,
)


MAX_FRAME_BYTES = 16 * 1024 * 1024
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_PREFIX = "memory-rag-evidence-sha256:"


class ProtocolWorkerError(ValueError):
    """A framed Protobuf request is outside the approved Worker boundary."""


def handle_request(payload: bytes) -> bytes:
    """Decode one request, run the pure retrieval core, and encode one response.

    The adapter has no persistence or authority handle. Every accepted record
    is supplied by the Rust Memory Authority in the request snapshot.
    """

    request_message = memory_pb2.MemoryRetrievalRequest()
    try:
        request_message.ParseFromString(payload)
    except DecodeError as error:
        raise ProtocolWorkerError("request is not valid Memory Protobuf") from error

    if not request_message.HasField("retrieval"):
        raise ProtocolWorkerError("retrieval request is required")

    wire_request = request_message.retrieval
    _validate_sha256(wire_request.snapshot_sha256, "snapshot_sha256")
    if wire_request.algorithm_profile != ALGORITHM_ID:
        raise ProtocolWorkerError("unsupported algorithm_profile")
    if wire_request.max_results > MAX_RESULTS:
        raise ProtocolWorkerError("max_results exceeds the worker limit")

    records: list[MemoryRecord] = []
    for wire_record in request_message.accepted_records:
        if wire_record.revision == 0:
            raise ProtocolWorkerError("accepted memory revision must be positive")
        records.append(
            MemoryRecord(
                memory_id=wire_record.memory_id,
                content=wire_record.content,
                content_sha256=wire_record.content_sha256,
                source_ref=wire_record.source_ref,
                scope_ref=wire_record.scope_ref,
            )
        )

    retrieval_request = RetrievalRequest(
        query=wire_request.query,
        scope_ref=wire_request.scope_ref,
        max_results=wire_request.max_results,
        min_score=wire_request.min_score,
    )
    try:
        result = retrieve(retrieval_request, records)
    except RetrievalWorkerError as error:
        raise ProtocolWorkerError(str(error)) from error

    response = memory_pb2.RetrievalResponse(
        algorithm_id=result.algorithm_id,
        query_sha256=result.query_sha256,
        snapshot_sha256=wire_request.snapshot_sha256,
        evidence_ref=_bind_evidence_to_snapshot(
            result.evidence_ref, wire_request.snapshot_sha256
        ),
    )
    response.candidates.extend(
        memory_pb2.RetrievalCandidate(
            memory_id=candidate.memory_id,
            source_ref=candidate.source_ref,
            content_sha256=candidate.content_sha256,
            score=candidate.score,
            matched_terms=candidate.matched_terms,
        )
        for candidate in result.candidates
    )
    encoded = response.SerializeToString(deterministic=True)
    if len(encoded) > MAX_FRAME_BYTES:
        raise ProtocolWorkerError("response exceeds the frame limit")
    return encoded


def serve(stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
    """Serve one or more length-delimited requests until clean EOF."""

    input_stream = stdin or sys.stdin.buffer
    output_stream = stdout or sys.stdout.buffer
    while True:
        header = _read_exact(input_stream, 4)
        if header == b"":
            return
        if len(header) != 4:
            raise ProtocolWorkerError("request frame header is truncated")
        payload_length = int.from_bytes(header, "big")
        if payload_length > MAX_FRAME_BYTES:
            raise ProtocolWorkerError("request exceeds the frame limit")
        payload = _read_exact(input_stream, payload_length)
        if len(payload) != payload_length:
            raise ProtocolWorkerError("request frame is truncated")
        response = handle_request(payload)
        output_stream.write(len(response).to_bytes(4, "big"))
        output_stream.write(response)
        output_stream.flush()


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_sha256(value: str, field_name: str) -> None:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ProtocolWorkerError(f"{field_name} must be a lowercase SHA-256 digest")


def _bind_evidence_to_snapshot(base_evidence_ref: str, snapshot_sha256: str) -> str:
    payload = json.dumps(
        {
            "base_evidence_ref": base_evidence_ref,
            "snapshot_sha256": snapshot_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _EVIDENCE_PREFIX + sha256(payload).hexdigest()
