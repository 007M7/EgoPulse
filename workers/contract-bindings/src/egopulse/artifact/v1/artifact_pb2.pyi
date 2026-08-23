import datetime

from egopulse.common.v1 import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HashAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HASH_ALGORITHM_UNSPECIFIED: _ClassVar[HashAlgorithm]
    HASH_ALGORITHM_SHA256: _ClassVar[HashAlgorithm]

class ArtifactStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_STATUS_UNSPECIFIED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_STAGED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_SEALED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_QUARANTINED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_TOMBSTONED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_SUPERSEDED: _ClassVar[ArtifactStatus]

class ArtifactSemanticClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_SEMANTIC_CLASS_UNSPECIFIED: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_HARNESS_OUTPUT: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_REPOSITORY_BASELINE: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_REPOSITORY_PATCH: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_WORKSPACE_MANIFEST: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_COMMAND_RECEIPT: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_TOOL_RECEIPT: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_SIDE_EFFECT_LEDGER: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_USAGE_RECEIPT: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_LOG_BUNDLE: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_FINAL_MESSAGE: _ClassVar[ArtifactSemanticClass]
    ARTIFACT_SEMANTIC_CLASS_TYPED_EXTENSION: _ClassVar[ArtifactSemanticClass]

class IntegrityStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INTEGRITY_STATUS_UNSPECIFIED: _ClassVar[IntegrityStatus]
    INTEGRITY_STATUS_UNVERIFIED: _ClassVar[IntegrityStatus]
    INTEGRITY_STATUS_DIGEST_VERIFIED: _ClassVar[IntegrityStatus]
    INTEGRITY_STATUS_FAILED: _ClassVar[IntegrityStatus]

class ClaimSourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CLAIM_SOURCE_TYPE_UNSPECIFIED: _ClassVar[ClaimSourceType]
    CLAIM_SOURCE_TYPE_CODE_CHANGE: _ClassVar[ClaimSourceType]
    CLAIM_SOURCE_TYPE_HARNESS_REPORT: _ClassVar[ClaimSourceType]
    CLAIM_SOURCE_TYPE_GOVERNED_COLLECTOR: _ClassVar[ClaimSourceType]
    CLAIM_SOURCE_TYPE_TYPED_EXTENSION: _ClassVar[ClaimSourceType]

class ClaimStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CLAIM_STATUS_UNSPECIFIED: _ClassVar[ClaimStatus]
    CLAIM_STATUS_PROPOSED: _ClassVar[ClaimStatus]
    CLAIM_STATUS_WITHDRAWN: _ClassVar[ClaimStatus]
    CLAIM_STATUS_SUPERSEDED: _ClassVar[ClaimStatus]

class EvidenceRelation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVIDENCE_RELATION_UNSPECIFIED: _ClassVar[EvidenceRelation]
    EVIDENCE_RELATION_SUPPORTS: _ClassVar[EvidenceRelation]
    EVIDENCE_RELATION_REFUTES: _ClassVar[EvidenceRelation]
    EVIDENCE_RELATION_QUALIFIES: _ClassVar[EvidenceRelation]
    EVIDENCE_RELATION_CONTEXT: _ClassVar[EvidenceRelation]

class EvidenceProducerClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVIDENCE_PRODUCER_CLASS_UNSPECIFIED: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_HARNESS: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_ATTEMPT_SUPERVISOR: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_GOVERNED_COLLECTOR: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_DETERMINISTIC_CHECKER: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_SUPERVISED_RUNNER: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_EXTERNAL_VERIFIER: _ClassVar[EvidenceProducerClass]
    EVIDENCE_PRODUCER_CLASS_TYPED_EXTENSION: _ClassVar[EvidenceProducerClass]

class EvidenceStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVIDENCE_STATUS_UNSPECIFIED: _ClassVar[EvidenceStatus]
    EVIDENCE_STATUS_RECORDED: _ClassVar[EvidenceStatus]
    EVIDENCE_STATUS_QUARANTINED: _ClassVar[EvidenceStatus]
    EVIDENCE_STATUS_TOMBSTONED: _ClassVar[EvidenceStatus]
    EVIDENCE_STATUS_SUPERSEDED: _ClassVar[EvidenceStatus]

class ArtifactSetStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_SET_STATUS_UNSPECIFIED: _ClassVar[ArtifactSetStatus]
    ARTIFACT_SET_STATUS_DRAFT: _ClassVar[ArtifactSetStatus]
    ARTIFACT_SET_STATUS_SEALED: _ClassVar[ArtifactSetStatus]
    ARTIFACT_SET_STATUS_QUARANTINED: _ClassVar[ArtifactSetStatus]
    ARTIFACT_SET_STATUS_TOMBSTONED: _ClassVar[ArtifactSetStatus]
    ARTIFACT_SET_STATUS_SUPERSEDED: _ClassVar[ArtifactSetStatus]

class ReturnHandoffStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RETURN_HANDOFF_STATUS_UNSPECIFIED: _ClassVar[ReturnHandoffStatus]
    RETURN_HANDOFF_STATUS_SUBMITTED: _ClassVar[ReturnHandoffStatus]
    RETURN_HANDOFF_STATUS_RECEIPTED: _ClassVar[ReturnHandoffStatus]
    RETURN_HANDOFF_STATUS_QUARANTINED: _ClassVar[ReturnHandoffStatus]
    RETURN_HANDOFF_STATUS_SUPERSEDED: _ClassVar[ReturnHandoffStatus]

class ArtifactEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_EVENT_KIND_UNSPECIFIED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_ARTIFACT_STAGED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_ARTIFACT_SEALED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_OBJECT_QUARANTINED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_CLAIM_PROPOSED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_CLAIM_WITHDRAWN: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_EVIDENCE_RECORDED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_SET_CREATED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_SET_SEALED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_RETURN_SUBMITTED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_RETURN_RECEIPTED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_OBJECT_SUPERSEDED: _ClassVar[ArtifactEventKind]
    ARTIFACT_EVENT_KIND_OBJECT_TOMBSTONED: _ClassVar[ArtifactEventKind]

class ArtifactErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_ERROR_CODE_UNSPECIFIED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_UNAUTHENTICATED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_PERMISSION_DENIED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_NOT_FOUND: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_REVISION_CONFLICT: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_DIGEST_MISMATCH: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_LENGTH_MISMATCH: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_SCHEMA_INVALID: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_LINEAGE_MISMATCH: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_SCOPE_VIOLATION: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_SECRET_DETECTED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_MEMBER_NOT_SEALED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_INDEPENDENCE_VIOLATION: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_QUARANTINED: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_RETENTION_CONFLICT: _ClassVar[ArtifactErrorCode]
    ARTIFACT_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[ArtifactErrorCode]
HASH_ALGORITHM_UNSPECIFIED: HashAlgorithm
HASH_ALGORITHM_SHA256: HashAlgorithm
ARTIFACT_STATUS_UNSPECIFIED: ArtifactStatus
ARTIFACT_STATUS_STAGED: ArtifactStatus
ARTIFACT_STATUS_SEALED: ArtifactStatus
ARTIFACT_STATUS_QUARANTINED: ArtifactStatus
ARTIFACT_STATUS_TOMBSTONED: ArtifactStatus
ARTIFACT_STATUS_SUPERSEDED: ArtifactStatus
ARTIFACT_SEMANTIC_CLASS_UNSPECIFIED: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_HARNESS_OUTPUT: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_REPOSITORY_BASELINE: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_REPOSITORY_PATCH: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_WORKSPACE_MANIFEST: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_COMMAND_RECEIPT: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_TOOL_RECEIPT: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_SIDE_EFFECT_LEDGER: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_USAGE_RECEIPT: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_LOG_BUNDLE: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_FINAL_MESSAGE: ArtifactSemanticClass
ARTIFACT_SEMANTIC_CLASS_TYPED_EXTENSION: ArtifactSemanticClass
INTEGRITY_STATUS_UNSPECIFIED: IntegrityStatus
INTEGRITY_STATUS_UNVERIFIED: IntegrityStatus
INTEGRITY_STATUS_DIGEST_VERIFIED: IntegrityStatus
INTEGRITY_STATUS_FAILED: IntegrityStatus
CLAIM_SOURCE_TYPE_UNSPECIFIED: ClaimSourceType
CLAIM_SOURCE_TYPE_CODE_CHANGE: ClaimSourceType
CLAIM_SOURCE_TYPE_HARNESS_REPORT: ClaimSourceType
CLAIM_SOURCE_TYPE_GOVERNED_COLLECTOR: ClaimSourceType
CLAIM_SOURCE_TYPE_TYPED_EXTENSION: ClaimSourceType
CLAIM_STATUS_UNSPECIFIED: ClaimStatus
CLAIM_STATUS_PROPOSED: ClaimStatus
CLAIM_STATUS_WITHDRAWN: ClaimStatus
CLAIM_STATUS_SUPERSEDED: ClaimStatus
EVIDENCE_RELATION_UNSPECIFIED: EvidenceRelation
EVIDENCE_RELATION_SUPPORTS: EvidenceRelation
EVIDENCE_RELATION_REFUTES: EvidenceRelation
EVIDENCE_RELATION_QUALIFIES: EvidenceRelation
EVIDENCE_RELATION_CONTEXT: EvidenceRelation
EVIDENCE_PRODUCER_CLASS_UNSPECIFIED: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_HARNESS: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_ATTEMPT_SUPERVISOR: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_GOVERNED_COLLECTOR: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_DETERMINISTIC_CHECKER: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_SUPERVISED_RUNNER: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_EXTERNAL_VERIFIER: EvidenceProducerClass
EVIDENCE_PRODUCER_CLASS_TYPED_EXTENSION: EvidenceProducerClass
EVIDENCE_STATUS_UNSPECIFIED: EvidenceStatus
EVIDENCE_STATUS_RECORDED: EvidenceStatus
EVIDENCE_STATUS_QUARANTINED: EvidenceStatus
EVIDENCE_STATUS_TOMBSTONED: EvidenceStatus
EVIDENCE_STATUS_SUPERSEDED: EvidenceStatus
ARTIFACT_SET_STATUS_UNSPECIFIED: ArtifactSetStatus
ARTIFACT_SET_STATUS_DRAFT: ArtifactSetStatus
ARTIFACT_SET_STATUS_SEALED: ArtifactSetStatus
ARTIFACT_SET_STATUS_QUARANTINED: ArtifactSetStatus
ARTIFACT_SET_STATUS_TOMBSTONED: ArtifactSetStatus
ARTIFACT_SET_STATUS_SUPERSEDED: ArtifactSetStatus
RETURN_HANDOFF_STATUS_UNSPECIFIED: ReturnHandoffStatus
RETURN_HANDOFF_STATUS_SUBMITTED: ReturnHandoffStatus
RETURN_HANDOFF_STATUS_RECEIPTED: ReturnHandoffStatus
RETURN_HANDOFF_STATUS_QUARANTINED: ReturnHandoffStatus
RETURN_HANDOFF_STATUS_SUPERSEDED: ReturnHandoffStatus
ARTIFACT_EVENT_KIND_UNSPECIFIED: ArtifactEventKind
ARTIFACT_EVENT_KIND_ARTIFACT_STAGED: ArtifactEventKind
ARTIFACT_EVENT_KIND_ARTIFACT_SEALED: ArtifactEventKind
ARTIFACT_EVENT_KIND_OBJECT_QUARANTINED: ArtifactEventKind
ARTIFACT_EVENT_KIND_CLAIM_PROPOSED: ArtifactEventKind
ARTIFACT_EVENT_KIND_CLAIM_WITHDRAWN: ArtifactEventKind
ARTIFACT_EVENT_KIND_EVIDENCE_RECORDED: ArtifactEventKind
ARTIFACT_EVENT_KIND_SET_CREATED: ArtifactEventKind
ARTIFACT_EVENT_KIND_SET_SEALED: ArtifactEventKind
ARTIFACT_EVENT_KIND_RETURN_SUBMITTED: ArtifactEventKind
ARTIFACT_EVENT_KIND_RETURN_RECEIPTED: ArtifactEventKind
ARTIFACT_EVENT_KIND_OBJECT_SUPERSEDED: ArtifactEventKind
ARTIFACT_EVENT_KIND_OBJECT_TOMBSTONED: ArtifactEventKind
ARTIFACT_ERROR_CODE_UNSPECIFIED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_INVALID_ARGUMENT: ArtifactErrorCode
ARTIFACT_ERROR_CODE_UNAUTHENTICATED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_PERMISSION_DENIED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_NOT_FOUND: ArtifactErrorCode
ARTIFACT_ERROR_CODE_REVISION_CONFLICT: ArtifactErrorCode
ARTIFACT_ERROR_CODE_IDEMPOTENCY_CONFLICT: ArtifactErrorCode
ARTIFACT_ERROR_CODE_DIGEST_MISMATCH: ArtifactErrorCode
ARTIFACT_ERROR_CODE_LENGTH_MISMATCH: ArtifactErrorCode
ARTIFACT_ERROR_CODE_SCHEMA_INVALID: ArtifactErrorCode
ARTIFACT_ERROR_CODE_LINEAGE_MISMATCH: ArtifactErrorCode
ARTIFACT_ERROR_CODE_SCOPE_VIOLATION: ArtifactErrorCode
ARTIFACT_ERROR_CODE_SECRET_DETECTED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_MEMBER_NOT_SEALED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_INDEPENDENCE_VIOLATION: ArtifactErrorCode
ARTIFACT_ERROR_CODE_QUARANTINED: ArtifactErrorCode
ARTIFACT_ERROR_CODE_RETENTION_CONFLICT: ArtifactErrorCode
ARTIFACT_ERROR_CODE_INTEGRITY_FAILURE: ArtifactErrorCode

class ContentAddress(_message.Message):
    __slots__ = ("algorithm", "digest", "byte_length")
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    BYTE_LENGTH_FIELD_NUMBER: _ClassVar[int]
    algorithm: HashAlgorithm
    digest: str
    byte_length: int
    def __init__(self, algorithm: _Optional[_Union[HashAlgorithm, str]] = ..., digest: _Optional[str] = ..., byte_length: _Optional[int] = ...) -> None: ...

class LineageBinding(_message.Message):
    __slots__ = ("task_id", "task_revision", "work_revision", "run_id", "run_revision", "step_id", "step_revision", "attempt_id", "attempt_revision", "dispatch_id", "fencing_token")
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_REVISION_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    task_id: str
    task_revision: int
    work_revision: int
    run_id: str
    run_revision: int
    step_id: str
    step_revision: int
    attempt_id: str
    attempt_revision: int
    dispatch_id: str
    fencing_token: int
    def __init__(self, task_id: _Optional[str] = ..., task_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., run_id: _Optional[str] = ..., run_revision: _Optional[int] = ..., step_id: _Optional[str] = ..., step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., attempt_revision: _Optional[int] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ...) -> None: ...

class ProducerIdentity(_message.Message):
    __slots__ = ("principal_kind", "principal_id", "component_name", "component_version", "capability_profile_id", "native_execution_ref")
    PRINCIPAL_KIND_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_NAME_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EXECUTION_REF_FIELD_NUMBER: _ClassVar[int]
    principal_kind: str
    principal_id: str
    component_name: str
    component_version: str
    capability_profile_id: str
    native_execution_ref: str
    def __init__(self, principal_kind: _Optional[str] = ..., principal_id: _Optional[str] = ..., component_name: _Optional[str] = ..., component_version: _Optional[str] = ..., capability_profile_id: _Optional[str] = ..., native_execution_ref: _Optional[str] = ...) -> None: ...

class Provenance(_message.Message):
    __slots__ = ("lineage", "producer", "input_artifact_ids", "transformation_contract_ref", "workspace_ref", "observed_at", "captured_at", "raw_source_ref")
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    PRODUCER_FIELD_NUMBER: _ClassVar[int]
    INPUT_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    TRANSFORMATION_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_REF_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_AT_FIELD_NUMBER: _ClassVar[int]
    CAPTURED_AT_FIELD_NUMBER: _ClassVar[int]
    RAW_SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    lineage: LineageBinding
    producer: ProducerIdentity
    input_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    transformation_contract_ref: _common_pb2.ContractReference
    workspace_ref: str
    observed_at: _timestamp_pb2.Timestamp
    captured_at: _timestamp_pb2.Timestamp
    raw_source_ref: str
    def __init__(self, lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., producer: _Optional[_Union[ProducerIdentity, _Mapping]] = ..., input_artifact_ids: _Optional[_Iterable[str]] = ..., transformation_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., workspace_ref: _Optional[str] = ..., observed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., captured_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., raw_source_ref: _Optional[str] = ...) -> None: ...

class ArtifactDescriptor(_message.Message):
    __slots__ = ("artifact_id", "revision", "status", "semantic_class", "type_contract_ref", "media_type", "content", "integrity_status", "provenance", "sensitivity_class", "retention_profile_ref", "created_at", "sealed_at", "supersedes_artifact_id", "quarantine_reason_code")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SEMANTIC_CLASS_FIELD_NUMBER: _ClassVar[int]
    TYPE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_STATUS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    SENSITIVITY_CLASS_FIELD_NUMBER: _ClassVar[int]
    RETENTION_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    SEALED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    QUARANTINE_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    artifact_id: str
    revision: int
    status: ArtifactStatus
    semantic_class: ArtifactSemanticClass
    type_contract_ref: _common_pb2.ContractReference
    media_type: str
    content: ContentAddress
    integrity_status: IntegrityStatus
    provenance: Provenance
    sensitivity_class: str
    retention_profile_ref: _common_pb2.ContractReference
    created_at: _timestamp_pb2.Timestamp
    sealed_at: _timestamp_pb2.Timestamp
    supersedes_artifact_id: str
    quarantine_reason_code: str
    def __init__(self, artifact_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[ArtifactStatus, str]] = ..., semantic_class: _Optional[_Union[ArtifactSemanticClass, str]] = ..., type_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., media_type: _Optional[str] = ..., content: _Optional[_Union[ContentAddress, _Mapping]] = ..., integrity_status: _Optional[_Union[IntegrityStatus, str]] = ..., provenance: _Optional[_Union[Provenance, _Mapping]] = ..., sensitivity_class: _Optional[str] = ..., retention_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., sealed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_artifact_id: _Optional[str] = ..., quarantine_reason_code: _Optional[str] = ...) -> None: ...

class Claim(_message.Message):
    __slots__ = ("claim_id", "revision", "status", "source_type", "semantic_profile_ref", "lineage", "subject_artifact_ids", "acceptance_contract_ref", "statement", "proposer", "proposed_at", "supersedes_claim_id")
    CLAIM_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    SEMANTIC_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    STATEMENT_FIELD_NUMBER: _ClassVar[int]
    PROPOSER_FIELD_NUMBER: _ClassVar[int]
    PROPOSED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_CLAIM_ID_FIELD_NUMBER: _ClassVar[int]
    claim_id: str
    revision: int
    status: ClaimStatus
    source_type: ClaimSourceType
    semantic_profile_ref: _common_pb2.ContractReference
    lineage: LineageBinding
    subject_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    acceptance_contract_ref: _common_pb2.ContractReference
    statement: ContentAddress
    proposer: ProducerIdentity
    proposed_at: _timestamp_pb2.Timestamp
    supersedes_claim_id: str
    def __init__(self, claim_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[ClaimStatus, str]] = ..., source_type: _Optional[_Union[ClaimSourceType, str]] = ..., semantic_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., subject_artifact_ids: _Optional[_Iterable[str]] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., statement: _Optional[_Union[ContentAddress, _Mapping]] = ..., proposer: _Optional[_Union[ProducerIdentity, _Mapping]] = ..., proposed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_claim_id: _Optional[str] = ...) -> None: ...

class Evidence(_message.Message):
    __slots__ = ("evidence_id", "revision", "status", "relation", "claim_id", "artifact_ids", "evidence_profile_ref", "lineage", "producer", "producer_class", "independent_of_claim_proposer", "integrity_status", "coverage_descriptor", "limitation_codes", "recorded_at", "supersedes_evidence_id")
    EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RELATION_FIELD_NUMBER: _ClassVar[int]
    CLAIM_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    PRODUCER_FIELD_NUMBER: _ClassVar[int]
    PRODUCER_CLASS_FIELD_NUMBER: _ClassVar[int]
    INDEPENDENT_OF_CLAIM_PROPOSER_FIELD_NUMBER: _ClassVar[int]
    INTEGRITY_STATUS_FIELD_NUMBER: _ClassVar[int]
    COVERAGE_DESCRIPTOR_FIELD_NUMBER: _ClassVar[int]
    LIMITATION_CODES_FIELD_NUMBER: _ClassVar[int]
    RECORDED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    evidence_id: str
    revision: int
    status: EvidenceStatus
    relation: EvidenceRelation
    claim_id: str
    artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    evidence_profile_ref: _common_pb2.ContractReference
    lineage: LineageBinding
    producer: ProducerIdentity
    producer_class: EvidenceProducerClass
    independent_of_claim_proposer: bool
    integrity_status: IntegrityStatus
    coverage_descriptor: ContentAddress
    limitation_codes: _containers.RepeatedScalarFieldContainer[str]
    recorded_at: _timestamp_pb2.Timestamp
    supersedes_evidence_id: str
    def __init__(self, evidence_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[EvidenceStatus, str]] = ..., relation: _Optional[_Union[EvidenceRelation, str]] = ..., claim_id: _Optional[str] = ..., artifact_ids: _Optional[_Iterable[str]] = ..., evidence_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., producer: _Optional[_Union[ProducerIdentity, _Mapping]] = ..., producer_class: _Optional[_Union[EvidenceProducerClass, str]] = ..., independent_of_claim_proposer: _Optional[bool] = ..., integrity_status: _Optional[_Union[IntegrityStatus, str]] = ..., coverage_descriptor: _Optional[_Union[ContentAddress, _Mapping]] = ..., limitation_codes: _Optional[_Iterable[str]] = ..., recorded_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_evidence_id: _Optional[str] = ...) -> None: ...

class ArtifactSet(_message.Message):
    __slots__ = ("artifact_set_id", "revision", "status", "lineage", "artifact_ids", "claim_ids", "evidence_ids", "canonical_manifest", "created_at", "sealed_at", "supersedes_artifact_set_id")
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    CLAIM_IDS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    SEALED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    artifact_set_id: str
    revision: int
    status: ArtifactSetStatus
    lineage: LineageBinding
    artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    claim_ids: _containers.RepeatedScalarFieldContainer[str]
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    canonical_manifest: ContentAddress
    created_at: _timestamp_pb2.Timestamp
    sealed_at: _timestamp_pb2.Timestamp
    supersedes_artifact_set_id: str
    def __init__(self, artifact_set_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[ArtifactSetStatus, str]] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., artifact_ids: _Optional[_Iterable[str]] = ..., claim_ids: _Optional[_Iterable[str]] = ..., evidence_ids: _Optional[_Iterable[str]] = ..., canonical_manifest: _Optional[_Union[ContentAddress, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., sealed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_artifact_set_id: _Optional[str] = ...) -> None: ...

class ReturnHandoff(_message.Message):
    __slots__ = ("return_handoff_id", "revision", "status", "lineage", "artifact_set_id", "artifact_set_manifest", "primary_claim_ids", "evidence_ids", "limitation_artifact_ids", "unknown_artifact_ids", "final_message_artifact_id", "submitted_by", "submitted_at", "supersedes_return_handoff_id")
    RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_CLAIM_IDS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    LIMITATION_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    UNKNOWN_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    FINAL_MESSAGE_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    SUBMITTED_BY_FIELD_NUMBER: _ClassVar[int]
    SUBMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    return_handoff_id: str
    revision: int
    status: ReturnHandoffStatus
    lineage: LineageBinding
    artifact_set_id: str
    artifact_set_manifest: ContentAddress
    primary_claim_ids: _containers.RepeatedScalarFieldContainer[str]
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    limitation_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    unknown_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    final_message_artifact_id: str
    submitted_by: ProducerIdentity
    submitted_at: _timestamp_pb2.Timestamp
    supersedes_return_handoff_id: str
    def __init__(self, return_handoff_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[ReturnHandoffStatus, str]] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., artifact_set_id: _Optional[str] = ..., artifact_set_manifest: _Optional[_Union[ContentAddress, _Mapping]] = ..., primary_claim_ids: _Optional[_Iterable[str]] = ..., evidence_ids: _Optional[_Iterable[str]] = ..., limitation_artifact_ids: _Optional[_Iterable[str]] = ..., unknown_artifact_ids: _Optional[_Iterable[str]] = ..., final_message_artifact_id: _Optional[str] = ..., submitted_by: _Optional[_Union[ProducerIdentity, _Mapping]] = ..., submitted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_return_handoff_id: _Optional[str] = ...) -> None: ...

class ReturnReceipt(_message.Message):
    __slots__ = ("receipt_id", "return_handoff_id", "return_handoff_digest", "artifact_set_id", "artifact_set_manifest", "lineage", "accepted_for_evidence_intake", "verification_performed", "task_completion_decided", "committed_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_DIGEST_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_FOR_EVIDENCE_INTAKE_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_PERFORMED_FIELD_NUMBER: _ClassVar[int]
    TASK_COMPLETION_DECIDED_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    return_handoff_id: str
    return_handoff_digest: ContentAddress
    artifact_set_id: str
    artifact_set_manifest: ContentAddress
    lineage: LineageBinding
    accepted_for_evidence_intake: bool
    verification_performed: bool
    task_completion_decided: bool
    committed_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., return_handoff_id: _Optional[str] = ..., return_handoff_digest: _Optional[_Union[ContentAddress, _Mapping]] = ..., artifact_set_id: _Optional[str] = ..., artifact_set_manifest: _Optional[_Union[ContentAddress, _Mapping]] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., accepted_for_evidence_intake: _Optional[bool] = ..., verification_performed: _Optional[bool] = ..., task_completion_decided: _Optional[bool] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class StageArtifactCommand(_message.Message):
    __slots__ = ("metadata", "candidate")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    candidate: ArtifactDescriptor
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., candidate: _Optional[_Union[ArtifactDescriptor, _Mapping]] = ...) -> None: ...

class SealArtifactCommand(_message.Message):
    __slots__ = ("metadata", "artifact_id", "expected_revision", "observed_content")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_CONTENT_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    artifact_id: str
    expected_revision: int
    observed_content: ContentAddress
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., artifact_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., observed_content: _Optional[_Union[ContentAddress, _Mapping]] = ...) -> None: ...

class QuarantineObjectCommand(_message.Message):
    __slots__ = ("metadata", "object_type", "object_id", "expected_revision", "reason_code")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    OBJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    object_type: str
    object_id: str
    expected_revision: int
    reason_code: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., object_type: _Optional[str] = ..., object_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., reason_code: _Optional[str] = ...) -> None: ...

class ProposeClaimCommand(_message.Message):
    __slots__ = ("metadata", "claim")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CLAIM_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    claim: Claim
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., claim: _Optional[_Union[Claim, _Mapping]] = ...) -> None: ...

class WithdrawClaimCommand(_message.Message):
    __slots__ = ("metadata", "claim_id", "expected_revision", "reason_code")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CLAIM_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    claim_id: str
    expected_revision: int
    reason_code: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., claim_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., reason_code: _Optional[str] = ...) -> None: ...

class RecordEvidenceCommand(_message.Message):
    __slots__ = ("metadata", "evidence")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    evidence: Evidence
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., evidence: _Optional[_Union[Evidence, _Mapping]] = ...) -> None: ...

class CreateArtifactSetCommand(_message.Message):
    __slots__ = ("metadata", "artifact_set")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    artifact_set: ArtifactSet
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., artifact_set: _Optional[_Union[ArtifactSet, _Mapping]] = ...) -> None: ...

class SealArtifactSetCommand(_message.Message):
    __slots__ = ("metadata", "artifact_set_id", "expected_revision", "observed_manifest")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    artifact_set_id: str
    expected_revision: int
    observed_manifest: ContentAddress
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., artifact_set_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., observed_manifest: _Optional[_Union[ContentAddress, _Mapping]] = ...) -> None: ...

class SubmitReturnHandoffCommand(_message.Message):
    __slots__ = ("metadata", "return_handoff", "expected_artifact_set_revision")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_ARTIFACT_SET_REVISION_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    return_handoff: ReturnHandoff
    expected_artifact_set_revision: int
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., return_handoff: _Optional[_Union[ReturnHandoff, _Mapping]] = ..., expected_artifact_set_revision: _Optional[int] = ...) -> None: ...

class TombstoneObjectCommand(_message.Message):
    __slots__ = ("metadata", "object_type", "object_id", "expected_revision", "retention_authority_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    OBJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    OBJECT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    RETENTION_AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    object_type: str
    object_id: str
    expected_revision: int
    retention_authority_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., object_type: _Optional[str] = ..., object_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., retention_authority_ref: _Optional[str] = ...) -> None: ...

class ArtifactCommand(_message.Message):
    __slots__ = ("stage_artifact", "seal_artifact", "quarantine_object", "propose_claim", "withdraw_claim", "record_evidence", "create_artifact_set", "seal_artifact_set", "submit_return_handoff", "tombstone_object")
    STAGE_ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    SEAL_ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    QUARANTINE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    PROPOSE_CLAIM_FIELD_NUMBER: _ClassVar[int]
    WITHDRAW_CLAIM_FIELD_NUMBER: _ClassVar[int]
    RECORD_EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    CREATE_ARTIFACT_SET_FIELD_NUMBER: _ClassVar[int]
    SEAL_ARTIFACT_SET_FIELD_NUMBER: _ClassVar[int]
    SUBMIT_RETURN_HANDOFF_FIELD_NUMBER: _ClassVar[int]
    TOMBSTONE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    stage_artifact: StageArtifactCommand
    seal_artifact: SealArtifactCommand
    quarantine_object: QuarantineObjectCommand
    propose_claim: ProposeClaimCommand
    withdraw_claim: WithdrawClaimCommand
    record_evidence: RecordEvidenceCommand
    create_artifact_set: CreateArtifactSetCommand
    seal_artifact_set: SealArtifactSetCommand
    submit_return_handoff: SubmitReturnHandoffCommand
    tombstone_object: TombstoneObjectCommand
    def __init__(self, stage_artifact: _Optional[_Union[StageArtifactCommand, _Mapping]] = ..., seal_artifact: _Optional[_Union[SealArtifactCommand, _Mapping]] = ..., quarantine_object: _Optional[_Union[QuarantineObjectCommand, _Mapping]] = ..., propose_claim: _Optional[_Union[ProposeClaimCommand, _Mapping]] = ..., withdraw_claim: _Optional[_Union[WithdrawClaimCommand, _Mapping]] = ..., record_evidence: _Optional[_Union[RecordEvidenceCommand, _Mapping]] = ..., create_artifact_set: _Optional[_Union[CreateArtifactSetCommand, _Mapping]] = ..., seal_artifact_set: _Optional[_Union[SealArtifactSetCommand, _Mapping]] = ..., submit_return_handoff: _Optional[_Union[SubmitReturnHandoffCommand, _Mapping]] = ..., tombstone_object: _Optional[_Union[TombstoneObjectCommand, _Mapping]] = ...) -> None: ...

class ArtifactEvent(_message.Message):
    __slots__ = ("event_id", "kind", "aggregate_type", "aggregate_id", "aggregate_revision", "lineage", "committed_at", "authenticated_principal_id", "command_id", "payload")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_TYPE_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    kind: ArtifactEventKind
    aggregate_type: str
    aggregate_id: str
    aggregate_revision: int
    lineage: LineageBinding
    committed_at: _timestamp_pb2.Timestamp
    authenticated_principal_id: str
    command_id: str
    payload: ContentAddress
    def __init__(self, event_id: _Optional[str] = ..., kind: _Optional[_Union[ArtifactEventKind, str]] = ..., aggregate_type: _Optional[str] = ..., aggregate_id: _Optional[str] = ..., aggregate_revision: _Optional[int] = ..., lineage: _Optional[_Union[LineageBinding, _Mapping]] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., authenticated_principal_id: _Optional[str] = ..., command_id: _Optional[str] = ..., payload: _Optional[_Union[ContentAddress, _Mapping]] = ...) -> None: ...

class ArtifactCommandResult(_message.Message):
    __slots__ = ("committed", "replayed", "artifact", "claim", "evidence", "artifact_set", "return_handoff", "return_receipt", "event", "error_code", "safe_error_fingerprint")
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    CLAIM_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_FIELD_NUMBER: _ClassVar[int]
    RETURN_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    committed: bool
    replayed: bool
    artifact: ArtifactDescriptor
    claim: Claim
    evidence: Evidence
    artifact_set: ArtifactSet
    return_handoff: ReturnHandoff
    return_receipt: ReturnReceipt
    event: ArtifactEvent
    error_code: ArtifactErrorCode
    safe_error_fingerprint: str
    def __init__(self, committed: _Optional[bool] = ..., replayed: _Optional[bool] = ..., artifact: _Optional[_Union[ArtifactDescriptor, _Mapping]] = ..., claim: _Optional[_Union[Claim, _Mapping]] = ..., evidence: _Optional[_Union[Evidence, _Mapping]] = ..., artifact_set: _Optional[_Union[ArtifactSet, _Mapping]] = ..., return_handoff: _Optional[_Union[ReturnHandoff, _Mapping]] = ..., return_receipt: _Optional[_Union[ReturnReceipt, _Mapping]] = ..., event: _Optional[_Union[ArtifactEvent, _Mapping]] = ..., error_code: _Optional[_Union[ArtifactErrorCode, str]] = ..., safe_error_fingerprint: _Optional[str] = ...) -> None: ...
