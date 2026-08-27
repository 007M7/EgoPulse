from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RetrievalRequest(_message.Message):
    __slots__ = ("query", "scope_ref", "snapshot_sha256", "max_results", "min_score", "algorithm_profile")
    QUERY_FIELD_NUMBER: _ClassVar[int]
    SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_SHA256_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    MIN_SCORE_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_PROFILE_FIELD_NUMBER: _ClassVar[int]
    query: str
    scope_ref: str
    snapshot_sha256: str
    max_results: int
    min_score: float
    algorithm_profile: str
    def __init__(self, query: _Optional[str] = ..., scope_ref: _Optional[str] = ..., snapshot_sha256: _Optional[str] = ..., max_results: _Optional[int] = ..., min_score: _Optional[float] = ..., algorithm_profile: _Optional[str] = ...) -> None: ...

class AcceptedMemoryInput(_message.Message):
    __slots__ = ("memory_id", "content", "content_sha256", "source_ref", "scope_ref", "revision")
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SHA256_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    memory_id: str
    content: str
    content_sha256: str
    source_ref: str
    scope_ref: str
    revision: int
    def __init__(self, memory_id: _Optional[str] = ..., content: _Optional[str] = ..., content_sha256: _Optional[str] = ..., source_ref: _Optional[str] = ..., scope_ref: _Optional[str] = ..., revision: _Optional[int] = ...) -> None: ...

class RetrievalCandidate(_message.Message):
    __slots__ = ("memory_id", "source_ref", "content_sha256", "score", "matched_terms")
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SHA256_FIELD_NUMBER: _ClassVar[int]
    SCORE_FIELD_NUMBER: _ClassVar[int]
    MATCHED_TERMS_FIELD_NUMBER: _ClassVar[int]
    memory_id: str
    source_ref: str
    content_sha256: str
    score: float
    matched_terms: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, memory_id: _Optional[str] = ..., source_ref: _Optional[str] = ..., content_sha256: _Optional[str] = ..., score: _Optional[float] = ..., matched_terms: _Optional[_Iterable[str]] = ...) -> None: ...

class RetrievalResponse(_message.Message):
    __slots__ = ("algorithm_id", "query_sha256", "snapshot_sha256", "candidates", "evidence_ref")
    ALGORITHM_ID_FIELD_NUMBER: _ClassVar[int]
    QUERY_SHA256_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_SHA256_FIELD_NUMBER: _ClassVar[int]
    CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    algorithm_id: str
    query_sha256: str
    snapshot_sha256: str
    candidates: _containers.RepeatedCompositeFieldContainer[RetrievalCandidate]
    evidence_ref: str
    def __init__(self, algorithm_id: _Optional[str] = ..., query_sha256: _Optional[str] = ..., snapshot_sha256: _Optional[str] = ..., candidates: _Optional[_Iterable[_Union[RetrievalCandidate, _Mapping]]] = ..., evidence_ref: _Optional[str] = ...) -> None: ...

class MemoryRetrievalRequest(_message.Message):
    __slots__ = ("retrieval", "accepted_records")
    RETRIEVAL_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_RECORDS_FIELD_NUMBER: _ClassVar[int]
    retrieval: RetrievalRequest
    accepted_records: _containers.RepeatedCompositeFieldContainer[AcceptedMemoryInput]
    def __init__(self, retrieval: _Optional[_Union[RetrievalRequest, _Mapping]] = ..., accepted_records: _Optional[_Iterable[_Union[AcceptedMemoryInput, _Mapping]]] = ...) -> None: ...
