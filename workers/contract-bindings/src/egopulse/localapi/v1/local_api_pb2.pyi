import datetime

from egopulse.artifact.v1 import artifact_pb2 as _artifact_pb2
from egopulse.collaboration.v1 import collaboration_pb2 as _collaboration_pb2
from egopulse.common.v1 import common_pb2 as _common_pb2
from egopulse.harness.v1 import harness_pb2 as _harness_pb2
from egopulse.memory.v1 import memory_pb2 as _memory_pb2
from egopulse.policy.v1 import policy_pb2 as _policy_pb2
from egopulse.task.v1 import task_pb2 as _task_pb2
from egopulse.verdict.v1 import verdict_pb2 as _verdict_pb2
from egopulse.verification.v1 import verification_pb2 as _verification_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ClientSurface(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CLIENT_SURFACE_UNSPECIFIED: _ClassVar[ClientSurface]
    CLIENT_SURFACE_DESKTOP: _ClassVar[ClientSurface]
    CLIENT_SURFACE_CLI: _ClassVar[ClientSurface]
    CLIENT_SURFACE_TUI: _ClassVar[ClientSurface]

class ProjectionHealth(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECTION_HEALTH_UNSPECIFIED: _ClassVar[ProjectionHealth]
    PROJECTION_HEALTH_READY: _ClassVar[ProjectionHealth]
    PROJECTION_HEALTH_CATCHING_UP: _ClassVar[ProjectionHealth]
    PROJECTION_HEALTH_REBUILDING: _ClassVar[ProjectionHealth]
    PROJECTION_HEALTH_HELD: _ClassVar[ProjectionHealth]
    PROJECTION_HEALTH_INTEGRITY_FAILED: _ClassVar[ProjectionHealth]

class SourceDomain(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SOURCE_DOMAIN_UNSPECIFIED: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_TASK: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_COLLABORATION: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_ARTIFACT: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_VERIFICATION: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_FOUNDER_VERDICT: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_POLICY_DECISION: _ClassVar[SourceDomain]
    SOURCE_DOMAIN_HARNESS_ADAPTER: _ClassVar[SourceDomain]

class StreamFrameKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STREAM_FRAME_KIND_UNSPECIFIED: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_SNAPSHOT: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_HEARTBEAT: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_RESET_REQUIRED: _ClassVar[StreamFrameKind]

class HarnessContentResetReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_CONTENT_RESET_REASON_UNSPECIFIED: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_CURSOR_EXPIRED: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_EPOCH_CHANGED: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_PROFILE_CHANGED: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_RETENTION_COMPACTED: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_BASELINE_UNAVAILABLE: _ClassVar[HarnessContentResetReason]
    HARNESS_CONTENT_RESET_REASON_INTEGRITY_RECOVERY: _ClassVar[HarnessContentResetReason]

class AvailableActionKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AVAILABLE_ACTION_KIND_UNSPECIFIED: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_CREATE_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_REQUEST_CANCELLATION: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_RESUME_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_REVISE_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_DECIDE_HARNESS_APPROVAL: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_SUBMIT_FOUNDER_VERDICT: _ClassVar[AvailableActionKind]

class ContextGovernanceState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTEXT_GOVERNANCE_STATE_UNSPECIFIED: _ClassVar[ContextGovernanceState]
    CONTEXT_GOVERNANCE_STATE_ISSUED: _ClassVar[ContextGovernanceState]
    CONTEXT_GOVERNANCE_STATE_REVOKED: _ClassVar[ContextGovernanceState]

class LocalApiErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LOCAL_API_ERROR_CODE_UNSPECIFIED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_UNAUTHENTICATED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_PERMISSION_DENIED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_NOT_FOUND: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_CONTRACT_INCOMPATIBLE: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_SESSION_EXPIRED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_CURSOR_INVALID: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_CURSOR_EXPIRED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_PROJECTION_BEHIND: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_PROJECTION_RESET_REQUIRED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_PROJECTION_HELD: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_DEADLINE_EXCEEDED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_AUTHORITY_UNAVAILABLE: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_UNKNOWN_CRITICAL_SEMANTICS: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_RESOURCE_EXHAUSTED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_COGNITION_WORKER_UNAVAILABLE: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_OWNER_MISMATCH: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_CONTEXT_REVOKED: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_STATE_REVISION_CONFLICT: _ClassVar[LocalApiErrorCode]
    LOCAL_API_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[LocalApiErrorCode]
CLIENT_SURFACE_UNSPECIFIED: ClientSurface
CLIENT_SURFACE_DESKTOP: ClientSurface
CLIENT_SURFACE_CLI: ClientSurface
CLIENT_SURFACE_TUI: ClientSurface
PROJECTION_HEALTH_UNSPECIFIED: ProjectionHealth
PROJECTION_HEALTH_READY: ProjectionHealth
PROJECTION_HEALTH_CATCHING_UP: ProjectionHealth
PROJECTION_HEALTH_REBUILDING: ProjectionHealth
PROJECTION_HEALTH_HELD: ProjectionHealth
PROJECTION_HEALTH_INTEGRITY_FAILED: ProjectionHealth
SOURCE_DOMAIN_UNSPECIFIED: SourceDomain
SOURCE_DOMAIN_TASK: SourceDomain
SOURCE_DOMAIN_COLLABORATION: SourceDomain
SOURCE_DOMAIN_ARTIFACT: SourceDomain
SOURCE_DOMAIN_VERIFICATION: SourceDomain
SOURCE_DOMAIN_FOUNDER_VERDICT: SourceDomain
SOURCE_DOMAIN_POLICY_DECISION: SourceDomain
SOURCE_DOMAIN_HARNESS_ADAPTER: SourceDomain
STREAM_FRAME_KIND_UNSPECIFIED: StreamFrameKind
STREAM_FRAME_KIND_SNAPSHOT: StreamFrameKind
STREAM_FRAME_KIND_HEARTBEAT: StreamFrameKind
STREAM_FRAME_KIND_RESET_REQUIRED: StreamFrameKind
HARNESS_CONTENT_RESET_REASON_UNSPECIFIED: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_CURSOR_EXPIRED: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_EPOCH_CHANGED: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_PROFILE_CHANGED: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_RETENTION_COMPACTED: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_BASELINE_UNAVAILABLE: HarnessContentResetReason
HARNESS_CONTENT_RESET_REASON_INTEGRITY_RECOVERY: HarnessContentResetReason
AVAILABLE_ACTION_KIND_UNSPECIFIED: AvailableActionKind
AVAILABLE_ACTION_KIND_CREATE_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_REQUEST_CANCELLATION: AvailableActionKind
AVAILABLE_ACTION_KIND_RESUME_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_REVISE_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_DECIDE_HARNESS_APPROVAL: AvailableActionKind
AVAILABLE_ACTION_KIND_SUBMIT_FOUNDER_VERDICT: AvailableActionKind
CONTEXT_GOVERNANCE_STATE_UNSPECIFIED: ContextGovernanceState
CONTEXT_GOVERNANCE_STATE_ISSUED: ContextGovernanceState
CONTEXT_GOVERNANCE_STATE_REVOKED: ContextGovernanceState
LOCAL_API_ERROR_CODE_UNSPECIFIED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_INVALID_ARGUMENT: LocalApiErrorCode
LOCAL_API_ERROR_CODE_UNAUTHENTICATED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_PERMISSION_DENIED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_NOT_FOUND: LocalApiErrorCode
LOCAL_API_ERROR_CODE_CONTRACT_INCOMPATIBLE: LocalApiErrorCode
LOCAL_API_ERROR_CODE_SESSION_EXPIRED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_CURSOR_INVALID: LocalApiErrorCode
LOCAL_API_ERROR_CODE_CURSOR_EXPIRED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_PROJECTION_BEHIND: LocalApiErrorCode
LOCAL_API_ERROR_CODE_PROJECTION_RESET_REQUIRED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_PROJECTION_HELD: LocalApiErrorCode
LOCAL_API_ERROR_CODE_INTEGRITY_FAILURE: LocalApiErrorCode
LOCAL_API_ERROR_CODE_DEADLINE_EXCEEDED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_AUTHORITY_UNAVAILABLE: LocalApiErrorCode
LOCAL_API_ERROR_CODE_UNKNOWN_CRITICAL_SEMANTICS: LocalApiErrorCode
LOCAL_API_ERROR_CODE_RESOURCE_EXHAUSTED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_COGNITION_WORKER_UNAVAILABLE: LocalApiErrorCode
LOCAL_API_ERROR_CODE_OWNER_MISMATCH: LocalApiErrorCode
LOCAL_API_ERROR_CODE_CONTEXT_REVOKED: LocalApiErrorCode
LOCAL_API_ERROR_CODE_STATE_REVISION_CONFLICT: LocalApiErrorCode
LOCAL_API_ERROR_CODE_IDEMPOTENCY_CONFLICT: LocalApiErrorCode

class ClientRequestMetadata(_message.Message):
    __slots__ = ("request_id", "client_instance_id", "surface", "session_id", "api_contract_ref", "correlation_id")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    SURFACE_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    API_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    client_instance_id: str
    surface: ClientSurface
    session_id: str
    api_contract_ref: _common_pb2.ContractReference
    correlation_id: str
    def __init__(self, request_id: _Optional[str] = ..., client_instance_id: _Optional[str] = ..., surface: _Optional[_Union[ClientSurface, str]] = ..., session_id: _Optional[str] = ..., api_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., correlation_id: _Optional[str] = ...) -> None: ...

class ProjectionPosition(_message.Message):
    __slots__ = ("epoch", "sequence", "projected_at")
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    PROJECTED_AT_FIELD_NUMBER: _ClassVar[int]
    epoch: str
    sequence: int
    projected_at: _timestamp_pb2.Timestamp
    def __init__(self, epoch: _Optional[str] = ..., sequence: _Optional[int] = ..., projected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SourceRevision(_message.Message):
    __slots__ = ("domain", "aggregate_id", "revision", "last_event_id")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    LAST_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    domain: SourceDomain
    aggregate_id: str
    revision: int
    last_event_id: str
    def __init__(self, domain: _Optional[_Union[SourceDomain, str]] = ..., aggregate_id: _Optional[str] = ..., revision: _Optional[int] = ..., last_event_id: _Optional[str] = ...) -> None: ...

class ProjectionMetadata(_message.Message):
    __slots__ = ("schema_ref", "position", "source_revisions", "health", "stale", "safe_health_reason_code")
    SCHEMA_REF_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REVISIONS_FIELD_NUMBER: _ClassVar[int]
    HEALTH_FIELD_NUMBER: _ClassVar[int]
    STALE_FIELD_NUMBER: _ClassVar[int]
    SAFE_HEALTH_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    schema_ref: _common_pb2.ContractReference
    position: ProjectionPosition
    source_revisions: _containers.RepeatedCompositeFieldContainer[SourceRevision]
    health: ProjectionHealth
    stale: bool
    safe_health_reason_code: str
    def __init__(self, schema_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., source_revisions: _Optional[_Iterable[_Union[SourceRevision, _Mapping]]] = ..., health: _Optional[_Union[ProjectionHealth, str]] = ..., stale: _Optional[bool] = ..., safe_health_reason_code: _Optional[str] = ...) -> None: ...

class RedactedField(_message.Message):
    __slots__ = ("field_path", "reason_code")
    FIELD_PATH_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    field_path: str
    reason_code: str
    def __init__(self, field_path: _Optional[str] = ..., reason_code: _Optional[str] = ...) -> None: ...

class AvailableAction(_message.Message):
    __slots__ = ("kind", "owning_authority", "derivation_rule_ref", "explicit_confirmation_required", "reason_code")
    KIND_FIELD_NUMBER: _ClassVar[int]
    OWNING_AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    DERIVATION_RULE_REF_FIELD_NUMBER: _ClassVar[int]
    EXPLICIT_CONFIRMATION_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    kind: AvailableActionKind
    owning_authority: str
    derivation_rule_ref: str
    explicit_confirmation_required: bool
    reason_code: str
    def __init__(self, kind: _Optional[_Union[AvailableActionKind, str]] = ..., owning_authority: _Optional[str] = ..., derivation_rule_ref: _Optional[str] = ..., explicit_confirmation_required: _Optional[bool] = ..., reason_code: _Optional[str] = ...) -> None: ...

class TaskView(_message.Message):
    __slots__ = ("metadata", "task", "collaboration", "artifact_set", "verification", "founder_verdict", "founder_verdict_state", "available_actions", "redactions")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    TASK_FIELD_NUMBER: _ClassVar[int]
    COLLABORATION_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_STATE_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    REDACTIONS_FIELD_NUMBER: _ClassVar[int]
    metadata: ProjectionMetadata
    task: _task_pb2.TaskSnapshot
    collaboration: _collaboration_pb2.CollaborationSnapshot
    artifact_set: _artifact_pb2.ArtifactSet
    verification: _verification_pb2.VerificationArtifact
    founder_verdict: _verdict_pb2.FounderVerdict
    founder_verdict_state: _verdict_pb2.FounderVerdictState
    available_actions: _containers.RepeatedCompositeFieldContainer[AvailableAction]
    redactions: _containers.RepeatedCompositeFieldContainer[RedactedField]
    def __init__(self, metadata: _Optional[_Union[ProjectionMetadata, _Mapping]] = ..., task: _Optional[_Union[_task_pb2.TaskSnapshot, _Mapping]] = ..., collaboration: _Optional[_Union[_collaboration_pb2.CollaborationSnapshot, _Mapping]] = ..., artifact_set: _Optional[_Union[_artifact_pb2.ArtifactSet, _Mapping]] = ..., verification: _Optional[_Union[_verification_pb2.VerificationArtifact, _Mapping]] = ..., founder_verdict: _Optional[_Union[_verdict_pb2.FounderVerdict, _Mapping]] = ..., founder_verdict_state: _Optional[_Union[_verdict_pb2.FounderVerdictState, _Mapping]] = ..., available_actions: _Optional[_Iterable[_Union[AvailableAction, _Mapping]]] = ..., redactions: _Optional[_Iterable[_Union[RedactedField, _Mapping]]] = ...) -> None: ...

class EvidenceGraphView(_message.Message):
    __slots__ = ("metadata", "task_id", "artifact_set_id", "artifacts", "claims", "evidence", "redactions")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACTS_FIELD_NUMBER: _ClassVar[int]
    CLAIMS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    REDACTIONS_FIELD_NUMBER: _ClassVar[int]
    metadata: ProjectionMetadata
    task_id: str
    artifact_set_id: str
    artifacts: _containers.RepeatedCompositeFieldContainer[_artifact_pb2.ArtifactDescriptor]
    claims: _containers.RepeatedCompositeFieldContainer[_artifact_pb2.Claim]
    evidence: _containers.RepeatedCompositeFieldContainer[_artifact_pb2.Evidence]
    redactions: _containers.RepeatedCompositeFieldContainer[RedactedField]
    def __init__(self, metadata: _Optional[_Union[ProjectionMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ..., artifacts: _Optional[_Iterable[_Union[_artifact_pb2.ArtifactDescriptor, _Mapping]]] = ..., claims: _Optional[_Iterable[_Union[_artifact_pb2.Claim, _Mapping]]] = ..., evidence: _Optional[_Iterable[_Union[_artifact_pb2.Evidence, _Mapping]]] = ..., redactions: _Optional[_Iterable[_Union[RedactedField, _Mapping]]] = ...) -> None: ...

class WorkSourceRequest(_message.Message):
    __slots__ = ("source_ref", "label")
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    source_ref: str
    label: str
    def __init__(self, source_ref: _Optional[str] = ..., label: _Optional[str] = ...) -> None: ...

class WorkSourceFact(_message.Message):
    __slots__ = ("source_ref", "label", "authority", "content_sha256", "included")
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SHA256_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_FIELD_NUMBER: _ClassVar[int]
    source_ref: str
    label: str
    authority: str
    content_sha256: str
    included: bool
    def __init__(self, source_ref: _Optional[str] = ..., label: _Optional[str] = ..., authority: _Optional[str] = ..., content_sha256: _Optional[str] = ..., included: _Optional[bool] = ...) -> None: ...

class WorkGateNotice(_message.Message):
    __slots__ = ("code", "detail", "source_ref")
    CODE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    code: str
    detail: str
    source_ref: str
    def __init__(self, code: _Optional[str] = ..., detail: _Optional[str] = ..., source_ref: _Optional[str] = ...) -> None: ...

class WorkPreparationPreview(_message.Message):
    __slots__ = ("snapshot_id", "snapshot_revision", "normalized_intent", "work_type", "target_scope_ref", "compiled_context_sha256", "included_sources", "excluded_sources", "non_goals", "allowed_read_paths", "allowed_write_paths", "allowed_tools", "external_resources", "acceptance_contract_ref", "budget_profile_ref", "memory_authority_revision", "memory_pack_snapshot_sha256", "recovery_entry", "visibility", "redactions", "expires_at", "confirmation_binding_sha256", "gate_ready", "blockers", "warnings", "required_confirmations", "evidence_required", "ready_for_founder_confirmation", "deadline", "context_state_revision")
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_REVISION_FIELD_NUMBER: _ClassVar[int]
    NORMALIZED_INTENT_FIELD_NUMBER: _ClassVar[int]
    WORK_TYPE_FIELD_NUMBER: _ClassVar[int]
    TARGET_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    COMPILED_CONTEXT_SHA256_FIELD_NUMBER: _ClassVar[int]
    INCLUDED_SOURCES_FIELD_NUMBER: _ClassVar[int]
    EXCLUDED_SOURCES_FIELD_NUMBER: _ClassVar[int]
    NON_GOALS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_READ_PATHS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_WRITE_PATHS_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_TOOLS_FIELD_NUMBER: _ClassVar[int]
    EXTERNAL_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    MEMORY_AUTHORITY_REVISION_FIELD_NUMBER: _ClassVar[int]
    MEMORY_PACK_SNAPSHOT_SHA256_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_ENTRY_FIELD_NUMBER: _ClassVar[int]
    VISIBILITY_FIELD_NUMBER: _ClassVar[int]
    REDACTIONS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    GATE_READY_FIELD_NUMBER: _ClassVar[int]
    BLOCKERS_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CONFIRMATIONS_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    READY_FOR_FOUNDER_CONFIRMATION_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    snapshot_revision: int
    normalized_intent: str
    work_type: str
    target_scope_ref: str
    compiled_context_sha256: str
    included_sources: _containers.RepeatedCompositeFieldContainer[WorkSourceFact]
    excluded_sources: _containers.RepeatedCompositeFieldContainer[WorkGateNotice]
    non_goals: _containers.RepeatedScalarFieldContainer[str]
    allowed_read_paths: _containers.RepeatedScalarFieldContainer[str]
    allowed_write_paths: _containers.RepeatedScalarFieldContainer[str]
    allowed_tools: _containers.RepeatedScalarFieldContainer[str]
    external_resources: _containers.RepeatedScalarFieldContainer[str]
    acceptance_contract_ref: _common_pb2.ContractReference
    budget_profile_ref: _common_pb2.ContractReference
    memory_authority_revision: int
    memory_pack_snapshot_sha256: str
    recovery_entry: str
    visibility: str
    redactions: _containers.RepeatedCompositeFieldContainer[RedactedField]
    expires_at: _timestamp_pb2.Timestamp
    confirmation_binding_sha256: str
    gate_ready: bool
    blockers: _containers.RepeatedCompositeFieldContainer[WorkGateNotice]
    warnings: _containers.RepeatedCompositeFieldContainer[WorkGateNotice]
    required_confirmations: _containers.RepeatedScalarFieldContainer[str]
    evidence_required: _containers.RepeatedScalarFieldContainer[str]
    ready_for_founder_confirmation: bool
    deadline: _timestamp_pb2.Timestamp
    context_state_revision: int
    def __init__(self, snapshot_id: _Optional[str] = ..., snapshot_revision: _Optional[int] = ..., normalized_intent: _Optional[str] = ..., work_type: _Optional[str] = ..., target_scope_ref: _Optional[str] = ..., compiled_context_sha256: _Optional[str] = ..., included_sources: _Optional[_Iterable[_Union[WorkSourceFact, _Mapping]]] = ..., excluded_sources: _Optional[_Iterable[_Union[WorkGateNotice, _Mapping]]] = ..., non_goals: _Optional[_Iterable[str]] = ..., allowed_read_paths: _Optional[_Iterable[str]] = ..., allowed_write_paths: _Optional[_Iterable[str]] = ..., allowed_tools: _Optional[_Iterable[str]] = ..., external_resources: _Optional[_Iterable[str]] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., budget_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., memory_authority_revision: _Optional[int] = ..., memory_pack_snapshot_sha256: _Optional[str] = ..., recovery_entry: _Optional[str] = ..., visibility: _Optional[str] = ..., redactions: _Optional[_Iterable[_Union[RedactedField, _Mapping]]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., confirmation_binding_sha256: _Optional[str] = ..., gate_ready: _Optional[bool] = ..., blockers: _Optional[_Iterable[_Union[WorkGateNotice, _Mapping]]] = ..., warnings: _Optional[_Iterable[_Union[WorkGateNotice, _Mapping]]] = ..., required_confirmations: _Optional[_Iterable[str]] = ..., evidence_required: _Optional[_Iterable[str]] = ..., ready_for_founder_confirmation: _Optional[bool] = ..., deadline: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., context_state_revision: _Optional[int] = ...) -> None: ...

class PrepareWorkRequest(_message.Message):
    __slots__ = ("client", "intent", "work_type", "target_scope_ref", "sources", "idempotency_key")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    INTENT_FIELD_NUMBER: _ClassVar[int]
    WORK_TYPE_FIELD_NUMBER: _ClassVar[int]
    TARGET_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    SOURCES_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    intent: str
    work_type: str
    target_scope_ref: str
    sources: _containers.RepeatedCompositeFieldContainer[WorkSourceRequest]
    idempotency_key: str
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., intent: _Optional[str] = ..., work_type: _Optional[str] = ..., target_scope_ref: _Optional[str] = ..., sources: _Optional[_Iterable[_Union[WorkSourceRequest, _Mapping]]] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class PrepareWorkResponse(_message.Message):
    __slots__ = ("preview", "error")
    PREVIEW_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    preview: WorkPreparationPreview
    error: LocalApiError
    def __init__(self, preview: _Optional[_Union[WorkPreparationPreview, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class ConfirmWorkRequest(_message.Message):
    __slots__ = ("client", "snapshot_id", "confirmation_binding_sha256", "idempotency_key")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    snapshot_id: str
    confirmation_binding_sha256: str
    idempotency_key: str
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., snapshot_id: _Optional[str] = ..., confirmation_binding_sha256: _Optional[str] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class ConfirmWorkAccepted(_message.Message):
    __slots__ = ("authority_result", "await_token")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    authority_result: _task_pb2.TaskCommandResult
    await_token: ProjectionAwaitToken
    def __init__(self, authority_result: _Optional[_Union[_task_pb2.TaskCommandResult, _Mapping]] = ..., await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ...) -> None: ...

class ConfirmWorkResponse(_message.Message):
    __slots__ = ("accepted", "error")
    ACCEPTED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    accepted: ConfirmWorkAccepted
    error: LocalApiError
    def __init__(self, accepted: _Optional[_Union[ConfirmWorkAccepted, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class HarnessApprovalAuthorityResult(_message.Message):
    __slots__ = ("committed", "replayed", "authority_decision_ref", "decision", "state", "state_revision", "expires_at", "error_code", "safe_error_fingerprint")
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    committed: bool
    replayed: bool
    authority_decision_ref: str
    decision: _harness_pb2.ApprovalDecision
    state: _policy_pb2.HarnessApprovalDecisionStateKind
    state_revision: int
    expires_at: _timestamp_pb2.Timestamp
    error_code: _policy_pb2.PolicyDecisionErrorCode
    safe_error_fingerprint: str
    def __init__(self, committed: _Optional[bool] = ..., replayed: _Optional[bool] = ..., authority_decision_ref: _Optional[str] = ..., decision: _Optional[_Union[_harness_pb2.ApprovalDecision, str]] = ..., state: _Optional[_Union[_policy_pb2.HarnessApprovalDecisionStateKind, str]] = ..., state_revision: _Optional[int] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., error_code: _Optional[_Union[_policy_pb2.PolicyDecisionErrorCode, str]] = ..., safe_error_fingerprint: _Optional[str] = ...) -> None: ...

class HarnessApprovalDecisionView(_message.Message):
    __slots__ = ("authority_decision_ref", "decision", "reason_code", "state", "state_revision", "issued_at", "expires_at", "updated_at")
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    authority_decision_ref: str
    decision: _harness_pb2.ApprovalDecision
    reason_code: str
    state: _policy_pb2.HarnessApprovalDecisionStateKind
    state_revision: int
    issued_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, authority_decision_ref: _Optional[str] = ..., decision: _Optional[_Union[_harness_pb2.ApprovalDecision, str]] = ..., reason_code: _Optional[str] = ..., state: _Optional[_Union[_policy_pb2.HarnessApprovalDecisionStateKind, str]] = ..., state_revision: _Optional[int] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HarnessApprovalView(_message.Message):
    __slots__ = ("metadata", "approval_request_id", "task_id", "run_id", "step_id", "attempt_id", "dispatch_id", "fencing_token", "kind", "action_digest_sha256", "requested_scope_ref", "display_summary_ref", "request_observation_id", "request_observation_sequence", "request_lifecycle", "request_revision", "policy_decision", "available_actions", "redactions")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ACTION_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_SUMMARY_REF_FIELD_NUMBER: _ClassVar[int]
    REQUEST_OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_OBSERVATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    REDACTIONS_FIELD_NUMBER: _ClassVar[int]
    metadata: ProjectionMetadata
    approval_request_id: str
    task_id: str
    run_id: str
    step_id: str
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    kind: _harness_pb2.ApprovalKind
    action_digest_sha256: str
    requested_scope_ref: str
    display_summary_ref: str
    request_observation_id: str
    request_observation_sequence: int
    request_lifecycle: _harness_pb2.ApprovalRequestLifecycleKind
    request_revision: int
    policy_decision: HarnessApprovalDecisionView
    available_actions: _containers.RepeatedCompositeFieldContainer[AvailableAction]
    redactions: _containers.RepeatedCompositeFieldContainer[RedactedField]
    def __init__(self, metadata: _Optional[_Union[ProjectionMetadata, _Mapping]] = ..., approval_request_id: _Optional[str] = ..., task_id: _Optional[str] = ..., run_id: _Optional[str] = ..., step_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., kind: _Optional[_Union[_harness_pb2.ApprovalKind, str]] = ..., action_digest_sha256: _Optional[str] = ..., requested_scope_ref: _Optional[str] = ..., display_summary_ref: _Optional[str] = ..., request_observation_id: _Optional[str] = ..., request_observation_sequence: _Optional[int] = ..., request_lifecycle: _Optional[_Union[_harness_pb2.ApprovalRequestLifecycleKind, str]] = ..., request_revision: _Optional[int] = ..., policy_decision: _Optional[_Union[HarnessApprovalDecisionView, _Mapping]] = ..., available_actions: _Optional[_Iterable[_Union[AvailableAction, _Mapping]]] = ..., redactions: _Optional[_Iterable[_Union[RedactedField, _Mapping]]] = ...) -> None: ...

class HarnessContentPosition(_message.Message):
    __slots__ = ("epoch", "sequence", "projected_at")
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    PROJECTED_AT_FIELD_NUMBER: _ClassVar[int]
    epoch: str
    sequence: int
    projected_at: _timestamp_pb2.Timestamp
    def __init__(self, epoch: _Optional[str] = ..., sequence: _Optional[int] = ..., projected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HarnessAssistantTextView(_message.Message):
    __slots__ = ("safe_message_id", "revision", "previous_revision", "operation", "safe_text_utf8", "safe_cumulative_digest_sha256", "part_index", "part_count", "provisional")
    SAFE_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    SAFE_TEXT_UTF8_FIELD_NUMBER: _ClassVar[int]
    SAFE_CUMULATIVE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    PART_INDEX_FIELD_NUMBER: _ClassVar[int]
    PART_COUNT_FIELD_NUMBER: _ClassVar[int]
    PROVISIONAL_FIELD_NUMBER: _ClassVar[int]
    safe_message_id: str
    revision: int
    previous_revision: int
    operation: _harness_pb2.ContentMutationOperation
    safe_text_utf8: str
    safe_cumulative_digest_sha256: str
    part_index: int
    part_count: int
    provisional: bool
    def __init__(self, safe_message_id: _Optional[str] = ..., revision: _Optional[int] = ..., previous_revision: _Optional[int] = ..., operation: _Optional[_Union[_harness_pb2.ContentMutationOperation, str]] = ..., safe_text_utf8: _Optional[str] = ..., safe_cumulative_digest_sha256: _Optional[str] = ..., part_index: _Optional[int] = ..., part_count: _Optional[int] = ..., provisional: _Optional[bool] = ...) -> None: ...

class HarnessLifecycleContentView(_message.Message):
    __slots__ = ("kind", "side_effect_certainty", "native_will_retry")
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    NATIVE_WILL_RETRY_FIELD_NUMBER: _ClassVar[int]
    kind: _harness_pb2.LifecycleKind
    side_effect_certainty: _harness_pb2.SideEffectCertainty
    native_will_retry: bool
    def __init__(self, kind: _Optional[_Union[_harness_pb2.LifecycleKind, str]] = ..., side_effect_certainty: _Optional[_Union[_harness_pb2.SideEffectCertainty, str]] = ..., native_will_retry: _Optional[bool] = ...) -> None: ...

class HarnessUsageContentView(_message.Message):
    __slots__ = ("input_tokens", "output_tokens", "cached_input_tokens")
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    CACHED_INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    def __init__(self, input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., cached_input_tokens: _Optional[int] = ...) -> None: ...

class HarnessApprovalRequiredContentView(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HarnessArtifactIdentityView(_message.Message):
    __slots__ = ("artifact_id", "artifact_digest_sha256")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    artifact_id: str
    artifact_digest_sha256: str
    def __init__(self, artifact_id: _Optional[str] = ..., artifact_digest_sha256: _Optional[str] = ...) -> None: ...

class HarnessArtifactAvailableRedactedView(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HarnessArtifactRelationView(_message.Message):
    __slots__ = ("safe_content_differs_from_artifact", "available", "available_redacted")
    SAFE_CONTENT_DIFFERS_FROM_ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    AVAILABLE_REDACTED_FIELD_NUMBER: _ClassVar[int]
    safe_content_differs_from_artifact: bool
    available: HarnessArtifactIdentityView
    available_redacted: HarnessArtifactAvailableRedactedView
    def __init__(self, safe_content_differs_from_artifact: _Optional[bool] = ..., available: _Optional[_Union[HarnessArtifactIdentityView, _Mapping]] = ..., available_redacted: _Optional[_Union[HarnessArtifactAvailableRedactedView, _Mapping]] = ...) -> None: ...

class HarnessContentMarkerView(_message.Message):
    __slots__ = ("kind", "limit_kind")
    KIND_FIELD_NUMBER: _ClassVar[int]
    LIMIT_KIND_FIELD_NUMBER: _ClassVar[int]
    kind: _harness_pb2.HarnessContentMarkerKind
    limit_kind: _harness_pb2.HarnessContentLimitKind
    def __init__(self, kind: _Optional[_Union[_harness_pb2.HarnessContentMarkerKind, str]] = ..., limit_kind: _Optional[_Union[_harness_pb2.HarnessContentLimitKind, str]] = ...) -> None: ...

class HarnessContentRecordView(_message.Message):
    __slots__ = ("record_id", "record_digest_sha256", "content_sequence", "task_id", "attempt_id", "provider_family_alias", "model_alias", "collaboration_role", "disclosure_profile_ref", "projected_at", "safety_flags", "assistant_text", "lifecycle", "usage", "approval_required", "artifact_relation", "marker")
    RECORD_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FAMILY_ALIAS_FIELD_NUMBER: _ClassVar[int]
    MODEL_ALIAS_FIELD_NUMBER: _ClassVar[int]
    COLLABORATION_ROLE_FIELD_NUMBER: _ClassVar[int]
    DISCLOSURE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    PROJECTED_AT_FIELD_NUMBER: _ClassVar[int]
    SAFETY_FLAGS_FIELD_NUMBER: _ClassVar[int]
    ASSISTANT_TEXT_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_RELATION_FIELD_NUMBER: _ClassVar[int]
    MARKER_FIELD_NUMBER: _ClassVar[int]
    record_id: str
    record_digest_sha256: str
    content_sequence: int
    task_id: str
    attempt_id: str
    provider_family_alias: str
    model_alias: str
    collaboration_role: str
    disclosure_profile_ref: _common_pb2.ContractReference
    projected_at: _timestamp_pb2.Timestamp
    safety_flags: _containers.RepeatedScalarFieldContainer[_harness_pb2.HarnessContentSafetyFlag]
    assistant_text: HarnessAssistantTextView
    lifecycle: HarnessLifecycleContentView
    usage: HarnessUsageContentView
    approval_required: HarnessApprovalRequiredContentView
    artifact_relation: HarnessArtifactRelationView
    marker: HarnessContentMarkerView
    def __init__(self, record_id: _Optional[str] = ..., record_digest_sha256: _Optional[str] = ..., content_sequence: _Optional[int] = ..., task_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., provider_family_alias: _Optional[str] = ..., model_alias: _Optional[str] = ..., collaboration_role: _Optional[str] = ..., disclosure_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., projected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., safety_flags: _Optional[_Iterable[_Union[_harness_pb2.HarnessContentSafetyFlag, str]]] = ..., assistant_text: _Optional[_Union[HarnessAssistantTextView, _Mapping]] = ..., lifecycle: _Optional[_Union[HarnessLifecycleContentView, _Mapping]] = ..., usage: _Optional[_Union[HarnessUsageContentView, _Mapping]] = ..., approval_required: _Optional[_Union[HarnessApprovalRequiredContentView, _Mapping]] = ..., artifact_relation: _Optional[_Union[HarnessArtifactRelationView, _Mapping]] = ..., marker: _Optional[_Union[HarnessContentMarkerView, _Mapping]] = ...) -> None: ...

class ListHarnessContentRequest(_message.Message):
    __slots__ = ("client", "task_id", "attempt_ids", "page_size", "page_cursor", "snapshot_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_IDS_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    task_id: str
    attempt_ids: _containers.RepeatedScalarFieldContainer[str]
    page_size: int
    page_cursor: str
    snapshot_position: HarnessContentPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., attempt_ids: _Optional[_Iterable[str]] = ..., page_size: _Optional[int] = ..., page_cursor: _Optional[str] = ..., snapshot_position: _Optional[_Union[HarnessContentPosition, _Mapping]] = ...) -> None: ...

class HarnessContentBaselinePage(_message.Message):
    __slots__ = ("records", "next_page_cursor", "has_more", "snapshot_position", "retained_from_sequence", "disclosure_profile_ref")
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    HAS_MORE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_POSITION_FIELD_NUMBER: _ClassVar[int]
    RETAINED_FROM_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    DISCLOSURE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[HarnessContentRecordView]
    next_page_cursor: str
    has_more: bool
    snapshot_position: HarnessContentPosition
    retained_from_sequence: int
    disclosure_profile_ref: _common_pb2.ContractReference
    def __init__(self, records: _Optional[_Iterable[_Union[HarnessContentRecordView, _Mapping]]] = ..., next_page_cursor: _Optional[str] = ..., has_more: _Optional[bool] = ..., snapshot_position: _Optional[_Union[HarnessContentPosition, _Mapping]] = ..., retained_from_sequence: _Optional[int] = ..., disclosure_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class ListHarnessContentResponse(_message.Message):
    __slots__ = ("page", "error")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    page: HarnessContentBaselinePage
    error: LocalApiError
    def __init__(self, page: _Optional[_Union[HarnessContentBaselinePage, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class WatchHarnessContentRequest(_message.Message):
    __slots__ = ("client", "task_id", "attempt_ids", "resume_after")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_IDS_FIELD_NUMBER: _ClassVar[int]
    RESUME_AFTER_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    task_id: str
    attempt_ids: _containers.RepeatedScalarFieldContainer[str]
    resume_after: HarnessContentPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., attempt_ids: _Optional[_Iterable[str]] = ..., resume_after: _Optional[_Union[HarnessContentPosition, _Mapping]] = ...) -> None: ...

class HarnessContentRecordsFrame(_message.Message):
    __slots__ = ("records",)
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[HarnessContentRecordView]
    def __init__(self, records: _Optional[_Iterable[_Union[HarnessContentRecordView, _Mapping]]] = ...) -> None: ...

class HarnessContentHeartbeatFrame(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HarnessContentResetRequiredFrame(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: HarnessContentResetReason
    def __init__(self, reason: _Optional[_Union[HarnessContentResetReason, str]] = ...) -> None: ...

class HarnessContentStreamFrame(_message.Message):
    __slots__ = ("position", "records", "heartbeat", "reset_required")
    POSITION_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    RESET_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    position: HarnessContentPosition
    records: HarnessContentRecordsFrame
    heartbeat: HarnessContentHeartbeatFrame
    reset_required: HarnessContentResetRequiredFrame
    def __init__(self, position: _Optional[_Union[HarnessContentPosition, _Mapping]] = ..., records: _Optional[_Union[HarnessContentRecordsFrame, _Mapping]] = ..., heartbeat: _Optional[_Union[HarnessContentHeartbeatFrame, _Mapping]] = ..., reset_required: _Optional[_Union[HarnessContentResetRequiredFrame, _Mapping]] = ...) -> None: ...

class LocalApiError(_message.Message):
    __slots__ = ("code", "safe_fingerprint", "retryable", "required_action_code", "current_position", "correlation_id")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_ACTION_CODE_FIELD_NUMBER: _ClassVar[int]
    CURRENT_POSITION_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    code: LocalApiErrorCode
    safe_fingerprint: str
    retryable: bool
    required_action_code: str
    current_position: ProjectionPosition
    correlation_id: str
    def __init__(self, code: _Optional[_Union[LocalApiErrorCode, str]] = ..., safe_fingerprint: _Optional[str] = ..., retryable: _Optional[bool] = ..., required_action_code: _Optional[str] = ..., current_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., correlation_id: _Optional[str] = ...) -> None: ...

class OpenSessionRequest(_message.Message):
    __slots__ = ("request_id", "client_instance_id", "surface", "supported_contracts")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    SURFACE_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_CONTRACTS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    client_instance_id: str
    surface: ClientSurface
    supported_contracts: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    def __init__(self, request_id: _Optional[str] = ..., client_instance_id: _Optional[str] = ..., surface: _Optional[_Union[ClientSurface, str]] = ..., supported_contracts: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ...) -> None: ...

class OpenSessionResponse(_message.Message):
    __slots__ = ("session_id", "authenticated_principal_id", "negotiated_contract_ref", "granted_permission_codes", "expires_at", "current_position", "error", "client_kernel_contract_ref", "authorization_policy_ref")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    NEGOTIATED_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    GRANTED_PERMISSION_CODES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CURRENT_POSITION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    CLIENT_KERNEL_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    session_id: str
    authenticated_principal_id: str
    negotiated_contract_ref: _common_pb2.ContractReference
    granted_permission_codes: _containers.RepeatedScalarFieldContainer[str]
    expires_at: _timestamp_pb2.Timestamp
    current_position: ProjectionPosition
    error: LocalApiError
    client_kernel_contract_ref: _common_pb2.ContractReference
    authorization_policy_ref: _common_pb2.ContractReference
    def __init__(self, session_id: _Optional[str] = ..., authenticated_principal_id: _Optional[str] = ..., negotiated_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., granted_permission_codes: _Optional[_Iterable[str]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., current_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ..., client_kernel_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., authorization_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class GetTaskViewRequest(_message.Message):
    __slots__ = ("client", "task_id", "minimum_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    task_id: str
    minimum_position: ProjectionPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., minimum_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ...) -> None: ...

class GetTaskViewResponse(_message.Message):
    __slots__ = ("view", "error")
    VIEW_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    view: TaskView
    error: LocalApiError
    def __init__(self, view: _Optional[_Union[TaskView, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class ListTaskViewsRequest(_message.Message):
    __slots__ = ("client", "status_filter", "page_size", "page_cursor", "minimum_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FILTER_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    status_filter: _containers.RepeatedScalarFieldContainer[_task_pb2.TaskStatus]
    page_size: int
    page_cursor: str
    minimum_position: ProjectionPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., status_filter: _Optional[_Iterable[_Union[_task_pb2.TaskStatus, str]]] = ..., page_size: _Optional[int] = ..., page_cursor: _Optional[str] = ..., minimum_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ...) -> None: ...

class ListTaskViewsResponse(_message.Message):
    __slots__ = ("views", "next_page_cursor", "snapshot_position", "error")
    VIEWS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_POSITION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    views: _containers.RepeatedCompositeFieldContainer[TaskView]
    next_page_cursor: str
    snapshot_position: ProjectionPosition
    error: LocalApiError
    def __init__(self, views: _Optional[_Iterable[_Union[TaskView, _Mapping]]] = ..., next_page_cursor: _Optional[str] = ..., snapshot_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class GetEvidenceGraphRequest(_message.Message):
    __slots__ = ("client", "task_id", "artifact_set_id", "minimum_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    task_id: str
    artifact_set_id: str
    minimum_position: ProjectionPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ..., minimum_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ...) -> None: ...

class GetEvidenceGraphResponse(_message.Message):
    __slots__ = ("graph", "error")
    GRAPH_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    graph: EvidenceGraphView
    error: LocalApiError
    def __init__(self, graph: _Optional[_Union[EvidenceGraphView, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class GetHarnessApprovalViewRequest(_message.Message):
    __slots__ = ("client", "approval_request_id", "minimum_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    approval_request_id: str
    minimum_position: ProjectionPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., approval_request_id: _Optional[str] = ..., minimum_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ...) -> None: ...

class GetHarnessApprovalViewResponse(_message.Message):
    __slots__ = ("view", "error")
    VIEW_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    view: HarnessApprovalView
    error: LocalApiError
    def __init__(self, view: _Optional[_Union[HarnessApprovalView, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class ListHarnessApprovalViewsRequest(_message.Message):
    __slots__ = ("client", "request_lifecycle_filter", "decision_state_filter", "task_ids", "actionable_only", "page_size", "page_cursor", "minimum_position")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_LIFECYCLE_FILTER_FIELD_NUMBER: _ClassVar[int]
    DECISION_STATE_FILTER_FIELD_NUMBER: _ClassVar[int]
    TASK_IDS_FIELD_NUMBER: _ClassVar[int]
    ACTIONABLE_ONLY_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_POSITION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    request_lifecycle_filter: _containers.RepeatedScalarFieldContainer[_harness_pb2.ApprovalRequestLifecycleKind]
    decision_state_filter: _containers.RepeatedScalarFieldContainer[_policy_pb2.HarnessApprovalDecisionStateKind]
    task_ids: _containers.RepeatedScalarFieldContainer[str]
    actionable_only: bool
    page_size: int
    page_cursor: str
    minimum_position: ProjectionPosition
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., request_lifecycle_filter: _Optional[_Iterable[_Union[_harness_pb2.ApprovalRequestLifecycleKind, str]]] = ..., decision_state_filter: _Optional[_Iterable[_Union[_policy_pb2.HarnessApprovalDecisionStateKind, str]]] = ..., task_ids: _Optional[_Iterable[str]] = ..., actionable_only: _Optional[bool] = ..., page_size: _Optional[int] = ..., page_cursor: _Optional[str] = ..., minimum_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ...) -> None: ...

class ListHarnessApprovalViewsResponse(_message.Message):
    __slots__ = ("views", "next_page_cursor", "snapshot_position", "error")
    VIEWS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_CURSOR_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_POSITION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    views: _containers.RepeatedCompositeFieldContainer[HarnessApprovalView]
    next_page_cursor: str
    snapshot_position: ProjectionPosition
    error: LocalApiError
    def __init__(self, views: _Optional[_Iterable[_Union[HarnessApprovalView, _Mapping]]] = ..., next_page_cursor: _Optional[str] = ..., snapshot_position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class GetProjectionStatusRequest(_message.Message):
    __slots__ = ("client",)
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ...) -> None: ...

class GetProjectionStatusResponse(_message.Message):
    __slots__ = ("metadata", "error")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    metadata: ProjectionMetadata
    error: LocalApiError
    def __init__(self, metadata: _Optional[_Union[ProjectionMetadata, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class WatchTaskViewsRequest(_message.Message):
    __slots__ = ("client", "resume_after", "task_ids", "status_filter")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    RESUME_AFTER_FIELD_NUMBER: _ClassVar[int]
    TASK_IDS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FILTER_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    resume_after: ProjectionPosition
    task_ids: _containers.RepeatedScalarFieldContainer[str]
    status_filter: _containers.RepeatedScalarFieldContainer[_task_pb2.TaskStatus]
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., resume_after: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., task_ids: _Optional[_Iterable[str]] = ..., status_filter: _Optional[_Iterable[_Union[_task_pb2.TaskStatus, str]]] = ...) -> None: ...

class TaskViewStreamFrame(_message.Message):
    __slots__ = ("kind", "position", "snapshot", "reset_reason_code")
    KIND_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RESET_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    kind: StreamFrameKind
    position: ProjectionPosition
    snapshot: TaskView
    reset_reason_code: str
    def __init__(self, kind: _Optional[_Union[StreamFrameKind, str]] = ..., position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., snapshot: _Optional[_Union[TaskView, _Mapping]] = ..., reset_reason_code: _Optional[str] = ...) -> None: ...

class WatchHarnessApprovalViewsRequest(_message.Message):
    __slots__ = ("client", "resume_after", "approval_request_ids", "task_ids", "request_lifecycle_filter", "decision_state_filter", "actionable_only")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    RESUME_AFTER_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_IDS_FIELD_NUMBER: _ClassVar[int]
    TASK_IDS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_LIFECYCLE_FILTER_FIELD_NUMBER: _ClassVar[int]
    DECISION_STATE_FILTER_FIELD_NUMBER: _ClassVar[int]
    ACTIONABLE_ONLY_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    resume_after: ProjectionPosition
    approval_request_ids: _containers.RepeatedScalarFieldContainer[str]
    task_ids: _containers.RepeatedScalarFieldContainer[str]
    request_lifecycle_filter: _containers.RepeatedScalarFieldContainer[_harness_pb2.ApprovalRequestLifecycleKind]
    decision_state_filter: _containers.RepeatedScalarFieldContainer[_policy_pb2.HarnessApprovalDecisionStateKind]
    actionable_only: bool
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., resume_after: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., approval_request_ids: _Optional[_Iterable[str]] = ..., task_ids: _Optional[_Iterable[str]] = ..., request_lifecycle_filter: _Optional[_Iterable[_Union[_harness_pb2.ApprovalRequestLifecycleKind, str]]] = ..., decision_state_filter: _Optional[_Iterable[_Union[_policy_pb2.HarnessApprovalDecisionStateKind, str]]] = ..., actionable_only: _Optional[bool] = ...) -> None: ...

class HarnessApprovalViewStreamFrame(_message.Message):
    __slots__ = ("kind", "position", "snapshot", "reset_reason_code")
    KIND_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    RESET_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    kind: StreamFrameKind
    position: ProjectionPosition
    snapshot: HarnessApprovalView
    reset_reason_code: str
    def __init__(self, kind: _Optional[_Union[StreamFrameKind, str]] = ..., position: _Optional[_Union[ProjectionPosition, _Mapping]] = ..., snapshot: _Optional[_Union[HarnessApprovalView, _Mapping]] = ..., reset_reason_code: _Optional[str] = ...) -> None: ...

class ProjectionAwaitToken(_message.Message):
    __slots__ = ("token", "required_source_revision", "expires_at")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_SOURCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    token: str
    required_source_revision: SourceRevision
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, token: _Optional[str] = ..., required_source_revision: _Optional[_Union[SourceRevision, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ExecuteTaskCommandRequest(_message.Message):
    __slots__ = ("client", "command")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    command: _task_pb2.TaskCommand
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., command: _Optional[_Union[_task_pb2.TaskCommand, _Mapping]] = ...) -> None: ...

class ExecuteTaskCommandResponse(_message.Message):
    __slots__ = ("authority_result", "await_token", "gateway_error")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_ERROR_FIELD_NUMBER: _ClassVar[int]
    authority_result: _task_pb2.TaskCommandResult
    await_token: ProjectionAwaitToken
    gateway_error: LocalApiError
    def __init__(self, authority_result: _Optional[_Union[_task_pb2.TaskCommandResult, _Mapping]] = ..., await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ..., gateway_error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class DecideHarnessApprovalRequest(_message.Message):
    __slots__ = ("client", "command")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    command: _policy_pb2.IssueHarnessApprovalDecisionCommand
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., command: _Optional[_Union[_policy_pb2.IssueHarnessApprovalDecisionCommand, _Mapping]] = ...) -> None: ...

class DecideHarnessApprovalResponse(_message.Message):
    __slots__ = ("await_token", "gateway_error", "policy_authority_result", "sanitized_authority_result")
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_ERROR_FIELD_NUMBER: _ClassVar[int]
    POLICY_AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    SANITIZED_AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    await_token: ProjectionAwaitToken
    gateway_error: LocalApiError
    policy_authority_result: _policy_pb2.PolicyDecisionCommandResult
    sanitized_authority_result: HarnessApprovalAuthorityResult
    def __init__(self, await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ..., gateway_error: _Optional[_Union[LocalApiError, _Mapping]] = ..., policy_authority_result: _Optional[_Union[_policy_pb2.PolicyDecisionCommandResult, _Mapping]] = ..., sanitized_authority_result: _Optional[_Union[HarnessApprovalAuthorityResult, _Mapping]] = ...) -> None: ...

class ExecuteFounderVerdictRequest(_message.Message):
    __slots__ = ("client", "command")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    command: _verdict_pb2.VerdictCommand
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., command: _Optional[_Union[_verdict_pb2.VerdictCommand, _Mapping]] = ...) -> None: ...

class ExecuteFounderVerdictResponse(_message.Message):
    __slots__ = ("authority_result", "await_token", "gateway_error")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_ERROR_FIELD_NUMBER: _ClassVar[int]
    authority_result: _verdict_pb2.VerdictCommandResult
    await_token: ProjectionAwaitToken
    gateway_error: LocalApiError
    def __init__(self, authority_result: _Optional[_Union[_verdict_pb2.VerdictCommandResult, _Mapping]] = ..., await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ..., gateway_error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class SubmitMemoryCandidateCommand(_message.Message):
    __slots__ = ("metadata", "memory_id", "content", "source_ref", "scope_ref", "idempotency_key")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REF_FIELD_NUMBER: _ClassVar[int]
    SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    metadata: ClientRequestMetadata
    memory_id: str
    content: str
    source_ref: str
    scope_ref: str
    idempotency_key: str
    def __init__(self, metadata: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., memory_id: _Optional[str] = ..., content: _Optional[str] = ..., source_ref: _Optional[str] = ..., scope_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class AcceptMemoryCommand(_message.Message):
    __slots__ = ("metadata", "memory_id", "expected_revision", "evidence_ref", "idempotency_key")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    metadata: ClientRequestMetadata
    memory_id: str
    expected_revision: int
    evidence_ref: str
    idempotency_key: str
    def __init__(self, metadata: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., memory_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., evidence_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class RevokeMemoryCommand(_message.Message):
    __slots__ = ("metadata", "memory_id", "expected_revision", "evidence_ref", "idempotency_key")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    metadata: ClientRequestMetadata
    memory_id: str
    expected_revision: int
    evidence_ref: str
    idempotency_key: str
    def __init__(self, metadata: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., memory_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., evidence_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class MemoryMutationCommand(_message.Message):
    __slots__ = ("submit_memory_candidate", "accept_memory", "revoke_memory")
    SUBMIT_MEMORY_CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    ACCEPT_MEMORY_FIELD_NUMBER: _ClassVar[int]
    REVOKE_MEMORY_FIELD_NUMBER: _ClassVar[int]
    submit_memory_candidate: SubmitMemoryCandidateCommand
    accept_memory: AcceptMemoryCommand
    revoke_memory: RevokeMemoryCommand
    def __init__(self, submit_memory_candidate: _Optional[_Union[SubmitMemoryCandidateCommand, _Mapping]] = ..., accept_memory: _Optional[_Union[AcceptMemoryCommand, _Mapping]] = ..., revoke_memory: _Optional[_Union[RevokeMemoryCommand, _Mapping]] = ...) -> None: ...

class MemoryMutationReceipt(_message.Message):
    __slots__ = ("memory_id", "revision", "state", "event_id", "request_digest_sha256", "acknowledged_after_durability_barrier")
    MEMORY_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGED_AFTER_DURABILITY_BARRIER_FIELD_NUMBER: _ClassVar[int]
    memory_id: str
    revision: int
    state: str
    event_id: str
    request_digest_sha256: str
    acknowledged_after_durability_barrier: bool
    def __init__(self, memory_id: _Optional[str] = ..., revision: _Optional[int] = ..., state: _Optional[str] = ..., event_id: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., acknowledged_after_durability_barrier: _Optional[bool] = ...) -> None: ...

class ExecuteMemoryMutationRequest(_message.Message):
    __slots__ = ("client", "command")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    command: MemoryMutationCommand
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., command: _Optional[_Union[MemoryMutationCommand, _Mapping]] = ...) -> None: ...

class ExecuteMemoryMutationResponse(_message.Message):
    __slots__ = ("authority_result", "gateway_error")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_ERROR_FIELD_NUMBER: _ClassVar[int]
    authority_result: MemoryMutationReceipt
    gateway_error: LocalApiError
    def __init__(self, authority_result: _Optional[_Union[MemoryMutationReceipt, _Mapping]] = ..., gateway_error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class RevokeContextSnapshotCommand(_message.Message):
    __slots__ = ("metadata", "snapshot_id", "expected_state_revision", "reason_code", "evidence_refs", "confirmation_proof_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    snapshot_id: str
    expected_state_revision: int
    reason_code: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    confirmation_proof_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., snapshot_id: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., reason_code: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., confirmation_proof_ref: _Optional[str] = ...) -> None: ...

class ContextMutationCommand(_message.Message):
    __slots__ = ("revoke_context_snapshot",)
    REVOKE_CONTEXT_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    revoke_context_snapshot: RevokeContextSnapshotCommand
    def __init__(self, revoke_context_snapshot: _Optional[_Union[RevokeContextSnapshotCommand, _Mapping]] = ...) -> None: ...

class ContextRevokeReceipt(_message.Message):
    __slots__ = ("snapshot_id", "snapshot_revision", "content_digest_sha256", "previous_state_revision", "result_state_revision", "previous_state", "result_state", "request_digest_sha256", "event_id", "committed_at", "replayed", "acknowledged_after_durability_barrier")
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_REVISION_FIELD_NUMBER: _ClassVar[int]
    CONTENT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULT_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_STATE_FIELD_NUMBER: _ClassVar[int]
    RESULT_STATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGED_AFTER_DURABILITY_BARRIER_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    snapshot_revision: int
    content_digest_sha256: str
    previous_state_revision: int
    result_state_revision: int
    previous_state: ContextGovernanceState
    result_state: ContextGovernanceState
    request_digest_sha256: str
    event_id: str
    committed_at: _timestamp_pb2.Timestamp
    replayed: bool
    acknowledged_after_durability_barrier: bool
    def __init__(self, snapshot_id: _Optional[str] = ..., snapshot_revision: _Optional[int] = ..., content_digest_sha256: _Optional[str] = ..., previous_state_revision: _Optional[int] = ..., result_state_revision: _Optional[int] = ..., previous_state: _Optional[_Union[ContextGovernanceState, str]] = ..., result_state: _Optional[_Union[ContextGovernanceState, str]] = ..., request_digest_sha256: _Optional[str] = ..., event_id: _Optional[str] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., replayed: _Optional[bool] = ..., acknowledged_after_durability_barrier: _Optional[bool] = ...) -> None: ...

class ExecuteContextMutationRequest(_message.Message):
    __slots__ = ("client", "command")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    command: ContextMutationCommand
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., command: _Optional[_Union[ContextMutationCommand, _Mapping]] = ...) -> None: ...

class ExecuteContextMutationResponse(_message.Message):
    __slots__ = ("authority_result", "error")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    authority_result: ContextRevokeReceipt
    error: LocalApiError
    def __init__(self, authority_result: _Optional[_Union[ContextRevokeReceipt, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

class AwaitProjectionRequest(_message.Message):
    __slots__ = ("client", "await_token", "timeout_milliseconds")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MILLISECONDS_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    await_token: ProjectionAwaitToken
    timeout_milliseconds: int
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ..., timeout_milliseconds: _Optional[int] = ...) -> None: ...

class AwaitProjectionResponse(_message.Message):
    __slots__ = ("view", "error", "approval_view")
    VIEW_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_VIEW_FIELD_NUMBER: _ClassVar[int]
    view: TaskView
    error: LocalApiError
    approval_view: HarnessApprovalView
    def __init__(self, view: _Optional[_Union[TaskView, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ..., approval_view: _Optional[_Union[HarnessApprovalView, _Mapping]] = ...) -> None: ...

class RetrieveMemoryRequest(_message.Message):
    __slots__ = ("client", "query", "scope_ref", "max_results", "min_score")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    MAX_RESULTS_FIELD_NUMBER: _ClassVar[int]
    MIN_SCORE_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    query: str
    scope_ref: str
    max_results: int
    min_score: float
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., query: _Optional[str] = ..., scope_ref: _Optional[str] = ..., max_results: _Optional[int] = ..., min_score: _Optional[float] = ...) -> None: ...

class RetrieveMemoryResponse(_message.Message):
    __slots__ = ("result", "error")
    RESULT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    result: _memory_pb2.RetrievalResponse
    error: LocalApiError
    def __init__(self, result: _Optional[_Union[_memory_pb2.RetrievalResponse, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...
