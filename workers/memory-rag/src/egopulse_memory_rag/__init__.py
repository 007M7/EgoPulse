"""Read-only candidate retrieval for the EgoPulse cognition boundary.

The module consumes already-governed memory records. It does not persist,
mutate, approve, revoke, or promote memory facts.
"""

from .retrieval import (
    MemoryRecord,
    RetrievalCandidate,
    RetrievalRequest,
    RetrievalResult,
    RetrievalWorkerError,
    digest_text,
    retrieve,
)

__all__ = [
    "MemoryRecord",
    "RetrievalCandidate",
    "RetrievalRequest",
    "RetrievalResult",
    "RetrievalWorkerError",
    "digest_text",
    "retrieve",
]
