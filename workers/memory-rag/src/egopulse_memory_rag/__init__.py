"""Read-only candidate retrieval for the EgoPulse cognition boundary.

The module consumes already-governed memory records. It does not persist,
mutate, approve, revoke, or promote memory facts.
"""

from .retrieval import (
    MAX_QUERY_BYTES,
    MAX_RECORDS,
    MAX_RESULTS,
    MAX_ROUTING_FIELD_BYTES,
    MAX_TOTAL_CONTENT_BYTES,
    MemoryRecord,
    RetrievalCandidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalWorkerError,
    digest_text,
    retrieve,
)

__all__ = [
    "MAX_QUERY_BYTES",
    "MAX_RECORDS",
    "MAX_RESULTS",
    "MAX_ROUTING_FIELD_BYTES",
    "MAX_TOTAL_CONTENT_BYTES",
    "MemoryRecord",
    "RetrievalCandidate",
    "RetrievalRequest",
    "RetrievalResult",
    "RetrievalWorkerError",
    "digest_text",
    "retrieve",
]
