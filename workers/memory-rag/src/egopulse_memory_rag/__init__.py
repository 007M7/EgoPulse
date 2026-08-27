"""Read-only candidate retrieval for the EgoPulse cognition boundary.

The module consumes already-governed memory records. It does not persist,
mutate, approve, revoke, or promote memory facts.
"""

from .retrieval import (
    ALGORITHM_ID,
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
from .protocol import (
    MAX_FRAME_BYTES,
    ProtocolWorkerError,
    handle_request,
    serve,
)
from .admission import (
    EvaluationAdmissionError,
    EvaluationGateDecision,
    EvaluationGateLimits,
    ROLLBACK_ALGORITHM_ID,
    evaluate_candidate_gate,
)

__all__ = [
    "MAX_QUERY_BYTES",
    "ALGORITHM_ID",
    "MAX_RECORDS",
    "MAX_RESULTS",
    "MAX_ROUTING_FIELD_BYTES",
    "MAX_TOTAL_CONTENT_BYTES",
    "MAX_FRAME_BYTES",
    "MemoryRecord",
    "RetrievalCandidate",
    "RetrievalRequest",
    "RetrievalResult",
    "RetrievalWorkerError",
    "ProtocolWorkerError",
    "digest_text",
    "retrieve",
    "handle_request",
    "serve",
    "EvaluationAdmissionError",
    "EvaluationGateDecision",
    "EvaluationGateLimits",
    "ROLLBACK_ALGORITHM_ID",
    "evaluate_candidate_gate",
]
