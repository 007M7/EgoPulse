import datetime

from egopulse.artifact.v1 import artifact_pb2 as _artifact_pb2
from egopulse.collaboration.v1 import collaboration_pb2 as _collaboration_pb2
from egopulse.common.v1 import common_pb2 as _common_pb2
from egopulse.harness.v1 import harness_pb2 as _harness_pb2
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

class StreamFrameKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STREAM_FRAME_KIND_UNSPECIFIED: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_SNAPSHOT: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_HEARTBEAT: _ClassVar[StreamFrameKind]
    STREAM_FRAME_KIND_RESET_REQUIRED: _ClassVar[StreamFrameKind]

class AvailableActionKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AVAILABLE_ACTION_KIND_UNSPECIFIED: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_CREATE_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_REQUEST_CANCELLATION: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_RESUME_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_REVISE_TASK: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_DECIDE_HARNESS_APPROVAL: _ClassVar[AvailableActionKind]
    AVAILABLE_ACTION_KIND_SUBMIT_FOUNDER_VERDICT: _ClassVar[AvailableActionKind]

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
STREAM_FRAME_KIND_UNSPECIFIED: StreamFrameKind
STREAM_FRAME_KIND_SNAPSHOT: StreamFrameKind
STREAM_FRAME_KIND_HEARTBEAT: StreamFrameKind
STREAM_FRAME_KIND_RESET_REQUIRED: StreamFrameKind
AVAILABLE_ACTION_KIND_UNSPECIFIED: AvailableActionKind
AVAILABLE_ACTION_KIND_CREATE_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_REQUEST_CANCELLATION: AvailableActionKind
AVAILABLE_ACTION_KIND_RESUME_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_REVISE_TASK: AvailableActionKind
AVAILABLE_ACTION_KIND_DECIDE_HARNESS_APPROVAL: AvailableActionKind
AVAILABLE_ACTION_KIND_SUBMIT_FOUNDER_VERDICT: AvailableActionKind
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
    __slots__ = ("client", "decision")
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    client: ClientRequestMetadata
    decision: _harness_pb2.ApprovalDecisionEnvelope
    def __init__(self, client: _Optional[_Union[ClientRequestMetadata, _Mapping]] = ..., decision: _Optional[_Union[_harness_pb2.ApprovalDecisionEnvelope, _Mapping]] = ...) -> None: ...

class DecideHarnessApprovalResponse(_message.Message):
    __slots__ = ("authority_result", "await_token", "gateway_error")
    AUTHORITY_RESULT_FIELD_NUMBER: _ClassVar[int]
    AWAIT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_ERROR_FIELD_NUMBER: _ClassVar[int]
    authority_result: _harness_pb2.ApprovalDecisionResult
    await_token: ProjectionAwaitToken
    gateway_error: LocalApiError
    def __init__(self, authority_result: _Optional[_Union[_harness_pb2.ApprovalDecisionResult, _Mapping]] = ..., await_token: _Optional[_Union[ProjectionAwaitToken, _Mapping]] = ..., gateway_error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...

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
    __slots__ = ("view", "error")
    VIEW_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    view: TaskView
    error: LocalApiError
    def __init__(self, view: _Optional[_Union[TaskView, _Mapping]] = ..., error: _Optional[_Union[LocalApiError, _Mapping]] = ...) -> None: ...
