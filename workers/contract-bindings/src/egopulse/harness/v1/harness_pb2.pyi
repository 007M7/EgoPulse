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

class HarnessResourceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_RESOURCE_TYPE_UNSPECIFIED: _ClassVar[HarnessResourceType]
    HARNESS_RESOURCE_TYPE_NATIVE_MODEL_HARNESS: _ClassVar[HarnessResourceType]
    HARNESS_RESOURCE_TYPE_AGENTOS_NATIVE_HARNESS: _ClassVar[HarnessResourceType]
    HARNESS_RESOURCE_TYPE_COGNITIVE_WORKER: _ClassVar[HarnessResourceType]

class CapabilityProfileStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CAPABILITY_PROFILE_STATUS_UNSPECIFIED: _ClassVar[CapabilityProfileStatus]
    CAPABILITY_PROFILE_STATUS_CANDIDATE: _ClassVar[CapabilityProfileStatus]
    CAPABILITY_PROFILE_STATUS_ACTIVE: _ClassVar[CapabilityProfileStatus]
    CAPABILITY_PROFILE_STATUS_DEPRECATED: _ClassVar[CapabilityProfileStatus]
    CAPABILITY_PROFILE_STATUS_REVOKED: _ClassVar[CapabilityProfileStatus]
    CAPABILITY_PROFILE_STATUS_EXPIRED: _ClassVar[CapabilityProfileStatus]

class AttestationLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ATTESTATION_LEVEL_UNSPECIFIED: _ClassVar[AttestationLevel]
    ATTESTATION_LEVEL_DECLARED: _ClassVar[AttestationLevel]
    ATTESTATION_LEVEL_STATICALLY_VERIFIED: _ClassVar[AttestationLevel]
    ATTESTATION_LEVEL_PROBE_VERIFIED: _ClassVar[AttestationLevel]

class SupportLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SUPPORT_LEVEL_UNSPECIFIED: _ClassVar[SupportLevel]
    SUPPORT_LEVEL_NATIVE_STRUCTURED: _ClassVar[SupportLevel]
    SUPPORT_LEVEL_ADAPTER_EMULATED: _ClassVar[SupportLevel]
    SUPPORT_LEVEL_PROCESS_ONLY: _ClassVar[SupportLevel]
    SUPPORT_LEVEL_UNSUPPORTED: _ClassVar[SupportLevel]
    SUPPORT_LEVEL_UNKNOWN: _ClassVar[SupportLevel]

class CancellationSemantics(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CANCELLATION_SEMANTICS_UNSPECIFIED: _ClassVar[CancellationSemantics]
    CANCELLATION_SEMANTICS_NATIVE_COOPERATIVE: _ClassVar[CancellationSemantics]
    CANCELLATION_SEMANTICS_PROCESS_TERMINATION: _ClassVar[CancellationSemantics]
    CANCELLATION_SEMANTICS_UNSUPPORTED: _ClassVar[CancellationSemantics]
    CANCELLATION_SEMANTICS_UNKNOWN: _ClassVar[CancellationSemantics]

class ResumeSemantics(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESUME_SEMANTICS_UNSPECIFIED: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_SESSION_CONTINUE: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_PARTIAL_EXECUTION_RESUME: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_CHECKPOINT_RESTORE: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_REPLAY_ONLY: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_UNSUPPORTED: _ClassVar[ResumeSemantics]
    RESUME_SEMANTICS_UNKNOWN: _ClassVar[ResumeSemantics]

class EventOrderingGuarantee(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVENT_ORDERING_GUARANTEE_UNSPECIFIED: _ClassVar[EventOrderingGuarantee]
    EVENT_ORDERING_GUARANTEE_NATIVE_MONOTONIC: _ClassVar[EventOrderingGuarantee]
    EVENT_ORDERING_GUARANTEE_ADAPTER_DURABLE_MONOTONIC: _ClassVar[EventOrderingGuarantee]
    EVENT_ORDERING_GUARANTEE_BEST_EFFORT: _ClassVar[EventOrderingGuarantee]
    EVENT_ORDERING_GUARANTEE_FINAL_ONLY: _ClassVar[EventOrderingGuarantee]

class HarnessReadiness(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_READINESS_UNSPECIFIED: _ClassVar[HarnessReadiness]
    HARNESS_READINESS_READY: _ClassVar[HarnessReadiness]
    HARNESS_READINESS_DEGRADED: _ClassVar[HarnessReadiness]
    HARNESS_READINESS_UNAVAILABLE: _ClassVar[HarnessReadiness]
    HARNESS_READINESS_PROTOCOL_MISMATCH: _ClassVar[HarnessReadiness]

class NativeSessionStrategy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NATIVE_SESSION_STRATEGY_UNSPECIFIED: _ClassVar[NativeSessionStrategy]
    NATIVE_SESSION_STRATEGY_CREATE_NEW: _ClassVar[NativeSessionStrategy]
    NATIVE_SESSION_STRATEGY_CONTINUE_EXISTING: _ClassVar[NativeSessionStrategy]

class DeliveryDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DELIVERY_DISPOSITION_UNSPECIFIED: _ClassVar[DeliveryDisposition]
    DELIVERY_DISPOSITION_DELIVERED: _ClassVar[DeliveryDisposition]
    DELIVERY_DISPOSITION_REJECTED: _ClassVar[DeliveryDisposition]
    DELIVERY_DISPOSITION_UNKNOWN: _ClassVar[DeliveryDisposition]

class AckDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACK_DISPOSITION_UNSPECIFIED: _ClassVar[AckDisposition]
    ACK_DISPOSITION_ACCEPTED: _ClassVar[AckDisposition]
    ACK_DISPOSITION_REJECTED: _ClassVar[AckDisposition]
    ACK_DISPOSITION_UNKNOWN: _ClassVar[AckDisposition]

class ObservationCriticality(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OBSERVATION_CRITICALITY_UNSPECIFIED: _ClassVar[ObservationCriticality]
    OBSERVATION_CRITICALITY_INFORMATIONAL: _ClassVar[ObservationCriticality]
    OBSERVATION_CRITICALITY_CONTROL: _ClassVar[ObservationCriticality]
    OBSERVATION_CRITICALITY_SECURITY: _ClassVar[ObservationCriticality]
    OBSERVATION_CRITICALITY_TERMINAL: _ClassVar[ObservationCriticality]
    OBSERVATION_CRITICALITY_ARTIFACT: _ClassVar[ObservationCriticality]

class LifecycleKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LIFECYCLE_KIND_UNSPECIFIED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_SESSION_CREATED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_EXECUTION_STARTED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_ITEM_STARTED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_ITEM_COMPLETED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_CONTEXT_COMPACTED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_USAGE_UPDATED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_EXECUTION_COMPLETED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_EXECUTION_INTERRUPTED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_EXECUTION_FAILED: _ClassVar[LifecycleKind]
    LIFECYCLE_KIND_PROCESS_EXITED: _ClassVar[LifecycleKind]

class SideEffectCertainty(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIDE_EFFECT_CERTAINTY_UNSPECIFIED: _ClassVar[SideEffectCertainty]
    SIDE_EFFECT_CERTAINTY_NONE_PROVEN: _ClassVar[SideEffectCertainty]
    SIDE_EFFECT_CERTAINTY_KNOWN_AND_RECORDED: _ClassVar[SideEffectCertainty]
    SIDE_EFFECT_CERTAINTY_UNKNOWN: _ClassVar[SideEffectCertainty]

class ApprovalKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    APPROVAL_KIND_UNSPECIFIED: _ClassVar[ApprovalKind]
    APPROVAL_KIND_COMMAND: _ClassVar[ApprovalKind]
    APPROVAL_KIND_FILE_CHANGE: _ClassVar[ApprovalKind]
    APPROVAL_KIND_NETWORK: _ClassVar[ApprovalKind]
    APPROVAL_KIND_TOOL: _ClassVar[ApprovalKind]
    APPROVAL_KIND_PERMISSION: _ClassVar[ApprovalKind]
    APPROVAL_KIND_USER_INPUT: _ClassVar[ApprovalKind]

class ApprovalDecision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    APPROVAL_DECISION_UNSPECIFIED: _ClassVar[ApprovalDecision]
    APPROVAL_DECISION_ALLOW_ONCE: _ClassVar[ApprovalDecision]
    APPROVAL_DECISION_DENY: _ClassVar[ApprovalDecision]
    APPROVAL_DECISION_CANCEL_ATTEMPT: _ClassVar[ApprovalDecision]

class ApprovalRequestLifecycleKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    APPROVAL_REQUEST_LIFECYCLE_KIND_UNSPECIFIED: _ClassVar[ApprovalRequestLifecycleKind]
    APPROVAL_REQUEST_LIFECYCLE_KIND_OPEN: _ClassVar[ApprovalRequestLifecycleKind]
    APPROVAL_REQUEST_LIFECYCLE_KIND_WITHDRAWN: _ClassVar[ApprovalRequestLifecycleKind]
    APPROVAL_REQUEST_LIFECYCLE_KIND_RESOLVED: _ClassVar[ApprovalRequestLifecycleKind]

class CancellationDeliveryDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CANCELLATION_DELIVERY_DISPOSITION_UNSPECIFIED: _ClassVar[CancellationDeliveryDisposition]
    CANCELLATION_DELIVERY_DISPOSITION_DELIVERED: _ClassVar[CancellationDeliveryDisposition]
    CANCELLATION_DELIVERY_DISPOSITION_REJECTED: _ClassVar[CancellationDeliveryDisposition]
    CANCELLATION_DELIVERY_DISPOSITION_UNKNOWN: _ClassVar[CancellationDeliveryDisposition]
    CANCELLATION_DELIVERY_DISPOSITION_UNSUPPORTED: _ClassVar[CancellationDeliveryDisposition]

class ResumeDeliveryDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESUME_DELIVERY_DISPOSITION_UNSPECIFIED: _ClassVar[ResumeDeliveryDisposition]
    RESUME_DELIVERY_DISPOSITION_DELIVERED: _ClassVar[ResumeDeliveryDisposition]
    RESUME_DELIVERY_DISPOSITION_REJECTED: _ClassVar[ResumeDeliveryDisposition]
    RESUME_DELIVERY_DISPOSITION_UNKNOWN: _ClassVar[ResumeDeliveryDisposition]
    RESUME_DELIVERY_DISPOSITION_UNSUPPORTED: _ClassVar[ResumeDeliveryDisposition]

class HarnessErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_ERROR_CODE_UNSPECIFIED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_UNAUTHENTICATED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_PERMISSION_DENIED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_CONFIG_INVALID: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_PROTOCOL_MISMATCH: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_CAPABILITY_MISMATCH: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_DELIVERY_REJECTED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_DELIVERY_UNKNOWN: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_ACK_TIMEOUT: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_FENCING_REJECTED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_SEQUENCE_CONFLICT: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_APPROVAL_REQUIRED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_CANCEL_OUTCOME_UNKNOWN: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_RESUME_UNSUPPORTED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_SCHEMA_INVALID: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_BUDGET_EXHAUSTED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_SANDBOX_VIOLATION: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_DEPENDENCY_UNAVAILABLE: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_PROCESS_EXITED: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_UNKNOWN_CRITICAL_EVENT: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_PROFILE_REVISION_CONFLICT: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_PROFILE_NOT_ACTIVE: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_NOT_FOUND: _ClassVar[HarnessErrorCode]
    HARNESS_ERROR_CODE_INTERNAL: _ClassVar[HarnessErrorCode]

class ContentMutationOperation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONTENT_MUTATION_OPERATION_UNSPECIFIED: _ClassVar[ContentMutationOperation]
    CONTENT_MUTATION_OPERATION_APPEND: _ClassVar[ContentMutationOperation]
    CONTENT_MUTATION_OPERATION_REPLACE: _ClassVar[ContentMutationOperation]
    CONTENT_MUTATION_OPERATION_FINALIZE: _ClassVar[ContentMutationOperation]

class HarnessContentSafetyFlag(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_CONTENT_SAFETY_FLAG_UNSPECIFIED: _ClassVar[HarnessContentSafetyFlag]
    HARNESS_CONTENT_SAFETY_FLAG_CONTROL_REDACTED: _ClassVar[HarnessContentSafetyFlag]
    HARNESS_CONTENT_SAFETY_FLAG_CREDENTIAL_REDACTED: _ClassVar[HarnessContentSafetyFlag]
    HARNESS_CONTENT_SAFETY_FLAG_TRUNCATED: _ClassVar[HarnessContentSafetyFlag]
    HARNESS_CONTENT_SAFETY_FLAG_PROVISIONAL: _ClassVar[HarnessContentSafetyFlag]

class HarnessContentMarkerKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_CONTENT_MARKER_KIND_UNSPECIFIED: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_INVALID_TEXT: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_FORBIDDEN_CATEGORY: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_UNKNOWN_CATEGORY: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_REDACTION_INPUT_UNAVAILABLE: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_LIMIT_REACHED: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_PROFILE_CHANGED_HISTORY_UNAVAILABLE: _ClassVar[HarnessContentMarkerKind]
    HARNESS_CONTENT_MARKER_KIND_COMPACTED: _ClassVar[HarnessContentMarkerKind]

class HarnessContentCompactionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_CONTENT_COMPACTION_REASON_UNSPECIFIED: _ClassVar[HarnessContentCompactionReason]
    HARNESS_CONTENT_COMPACTION_REASON_OWNER_HISTORY_FLOOR_ADVANCED: _ClassVar[HarnessContentCompactionReason]

class HarnessContentRetentionReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_CONTENT_RETENTION_REASON_UNSPECIFIED: _ClassVar[HarnessContentRetentionReason]
    HARNESS_CONTENT_RETENTION_REASON_TERMINAL_MINIMUM_EXPIRED: _ClassVar[HarnessContentRetentionReason]
HARNESS_RESOURCE_TYPE_UNSPECIFIED: HarnessResourceType
HARNESS_RESOURCE_TYPE_NATIVE_MODEL_HARNESS: HarnessResourceType
HARNESS_RESOURCE_TYPE_AGENTOS_NATIVE_HARNESS: HarnessResourceType
HARNESS_RESOURCE_TYPE_COGNITIVE_WORKER: HarnessResourceType
CAPABILITY_PROFILE_STATUS_UNSPECIFIED: CapabilityProfileStatus
CAPABILITY_PROFILE_STATUS_CANDIDATE: CapabilityProfileStatus
CAPABILITY_PROFILE_STATUS_ACTIVE: CapabilityProfileStatus
CAPABILITY_PROFILE_STATUS_DEPRECATED: CapabilityProfileStatus
CAPABILITY_PROFILE_STATUS_REVOKED: CapabilityProfileStatus
CAPABILITY_PROFILE_STATUS_EXPIRED: CapabilityProfileStatus
ATTESTATION_LEVEL_UNSPECIFIED: AttestationLevel
ATTESTATION_LEVEL_DECLARED: AttestationLevel
ATTESTATION_LEVEL_STATICALLY_VERIFIED: AttestationLevel
ATTESTATION_LEVEL_PROBE_VERIFIED: AttestationLevel
SUPPORT_LEVEL_UNSPECIFIED: SupportLevel
SUPPORT_LEVEL_NATIVE_STRUCTURED: SupportLevel
SUPPORT_LEVEL_ADAPTER_EMULATED: SupportLevel
SUPPORT_LEVEL_PROCESS_ONLY: SupportLevel
SUPPORT_LEVEL_UNSUPPORTED: SupportLevel
SUPPORT_LEVEL_UNKNOWN: SupportLevel
CANCELLATION_SEMANTICS_UNSPECIFIED: CancellationSemantics
CANCELLATION_SEMANTICS_NATIVE_COOPERATIVE: CancellationSemantics
CANCELLATION_SEMANTICS_PROCESS_TERMINATION: CancellationSemantics
CANCELLATION_SEMANTICS_UNSUPPORTED: CancellationSemantics
CANCELLATION_SEMANTICS_UNKNOWN: CancellationSemantics
RESUME_SEMANTICS_UNSPECIFIED: ResumeSemantics
RESUME_SEMANTICS_SESSION_CONTINUE: ResumeSemantics
RESUME_SEMANTICS_PARTIAL_EXECUTION_RESUME: ResumeSemantics
RESUME_SEMANTICS_CHECKPOINT_RESTORE: ResumeSemantics
RESUME_SEMANTICS_REPLAY_ONLY: ResumeSemantics
RESUME_SEMANTICS_UNSUPPORTED: ResumeSemantics
RESUME_SEMANTICS_UNKNOWN: ResumeSemantics
EVENT_ORDERING_GUARANTEE_UNSPECIFIED: EventOrderingGuarantee
EVENT_ORDERING_GUARANTEE_NATIVE_MONOTONIC: EventOrderingGuarantee
EVENT_ORDERING_GUARANTEE_ADAPTER_DURABLE_MONOTONIC: EventOrderingGuarantee
EVENT_ORDERING_GUARANTEE_BEST_EFFORT: EventOrderingGuarantee
EVENT_ORDERING_GUARANTEE_FINAL_ONLY: EventOrderingGuarantee
HARNESS_READINESS_UNSPECIFIED: HarnessReadiness
HARNESS_READINESS_READY: HarnessReadiness
HARNESS_READINESS_DEGRADED: HarnessReadiness
HARNESS_READINESS_UNAVAILABLE: HarnessReadiness
HARNESS_READINESS_PROTOCOL_MISMATCH: HarnessReadiness
NATIVE_SESSION_STRATEGY_UNSPECIFIED: NativeSessionStrategy
NATIVE_SESSION_STRATEGY_CREATE_NEW: NativeSessionStrategy
NATIVE_SESSION_STRATEGY_CONTINUE_EXISTING: NativeSessionStrategy
DELIVERY_DISPOSITION_UNSPECIFIED: DeliveryDisposition
DELIVERY_DISPOSITION_DELIVERED: DeliveryDisposition
DELIVERY_DISPOSITION_REJECTED: DeliveryDisposition
DELIVERY_DISPOSITION_UNKNOWN: DeliveryDisposition
ACK_DISPOSITION_UNSPECIFIED: AckDisposition
ACK_DISPOSITION_ACCEPTED: AckDisposition
ACK_DISPOSITION_REJECTED: AckDisposition
ACK_DISPOSITION_UNKNOWN: AckDisposition
OBSERVATION_CRITICALITY_UNSPECIFIED: ObservationCriticality
OBSERVATION_CRITICALITY_INFORMATIONAL: ObservationCriticality
OBSERVATION_CRITICALITY_CONTROL: ObservationCriticality
OBSERVATION_CRITICALITY_SECURITY: ObservationCriticality
OBSERVATION_CRITICALITY_TERMINAL: ObservationCriticality
OBSERVATION_CRITICALITY_ARTIFACT: ObservationCriticality
LIFECYCLE_KIND_UNSPECIFIED: LifecycleKind
LIFECYCLE_KIND_SESSION_CREATED: LifecycleKind
LIFECYCLE_KIND_EXECUTION_STARTED: LifecycleKind
LIFECYCLE_KIND_ITEM_STARTED: LifecycleKind
LIFECYCLE_KIND_ITEM_COMPLETED: LifecycleKind
LIFECYCLE_KIND_CONTEXT_COMPACTED: LifecycleKind
LIFECYCLE_KIND_USAGE_UPDATED: LifecycleKind
LIFECYCLE_KIND_EXECUTION_COMPLETED: LifecycleKind
LIFECYCLE_KIND_EXECUTION_INTERRUPTED: LifecycleKind
LIFECYCLE_KIND_EXECUTION_FAILED: LifecycleKind
LIFECYCLE_KIND_PROCESS_EXITED: LifecycleKind
SIDE_EFFECT_CERTAINTY_UNSPECIFIED: SideEffectCertainty
SIDE_EFFECT_CERTAINTY_NONE_PROVEN: SideEffectCertainty
SIDE_EFFECT_CERTAINTY_KNOWN_AND_RECORDED: SideEffectCertainty
SIDE_EFFECT_CERTAINTY_UNKNOWN: SideEffectCertainty
APPROVAL_KIND_UNSPECIFIED: ApprovalKind
APPROVAL_KIND_COMMAND: ApprovalKind
APPROVAL_KIND_FILE_CHANGE: ApprovalKind
APPROVAL_KIND_NETWORK: ApprovalKind
APPROVAL_KIND_TOOL: ApprovalKind
APPROVAL_KIND_PERMISSION: ApprovalKind
APPROVAL_KIND_USER_INPUT: ApprovalKind
APPROVAL_DECISION_UNSPECIFIED: ApprovalDecision
APPROVAL_DECISION_ALLOW_ONCE: ApprovalDecision
APPROVAL_DECISION_DENY: ApprovalDecision
APPROVAL_DECISION_CANCEL_ATTEMPT: ApprovalDecision
APPROVAL_REQUEST_LIFECYCLE_KIND_UNSPECIFIED: ApprovalRequestLifecycleKind
APPROVAL_REQUEST_LIFECYCLE_KIND_OPEN: ApprovalRequestLifecycleKind
APPROVAL_REQUEST_LIFECYCLE_KIND_WITHDRAWN: ApprovalRequestLifecycleKind
APPROVAL_REQUEST_LIFECYCLE_KIND_RESOLVED: ApprovalRequestLifecycleKind
CANCELLATION_DELIVERY_DISPOSITION_UNSPECIFIED: CancellationDeliveryDisposition
CANCELLATION_DELIVERY_DISPOSITION_DELIVERED: CancellationDeliveryDisposition
CANCELLATION_DELIVERY_DISPOSITION_REJECTED: CancellationDeliveryDisposition
CANCELLATION_DELIVERY_DISPOSITION_UNKNOWN: CancellationDeliveryDisposition
CANCELLATION_DELIVERY_DISPOSITION_UNSUPPORTED: CancellationDeliveryDisposition
RESUME_DELIVERY_DISPOSITION_UNSPECIFIED: ResumeDeliveryDisposition
RESUME_DELIVERY_DISPOSITION_DELIVERED: ResumeDeliveryDisposition
RESUME_DELIVERY_DISPOSITION_REJECTED: ResumeDeliveryDisposition
RESUME_DELIVERY_DISPOSITION_UNKNOWN: ResumeDeliveryDisposition
RESUME_DELIVERY_DISPOSITION_UNSUPPORTED: ResumeDeliveryDisposition
HARNESS_ERROR_CODE_UNSPECIFIED: HarnessErrorCode
HARNESS_ERROR_CODE_INVALID_ARGUMENT: HarnessErrorCode
HARNESS_ERROR_CODE_UNAUTHENTICATED: HarnessErrorCode
HARNESS_ERROR_CODE_PERMISSION_DENIED: HarnessErrorCode
HARNESS_ERROR_CODE_CONFIG_INVALID: HarnessErrorCode
HARNESS_ERROR_CODE_PROTOCOL_MISMATCH: HarnessErrorCode
HARNESS_ERROR_CODE_CAPABILITY_MISMATCH: HarnessErrorCode
HARNESS_ERROR_CODE_DELIVERY_REJECTED: HarnessErrorCode
HARNESS_ERROR_CODE_DELIVERY_UNKNOWN: HarnessErrorCode
HARNESS_ERROR_CODE_ACK_TIMEOUT: HarnessErrorCode
HARNESS_ERROR_CODE_FENCING_REJECTED: HarnessErrorCode
HARNESS_ERROR_CODE_SEQUENCE_CONFLICT: HarnessErrorCode
HARNESS_ERROR_CODE_APPROVAL_REQUIRED: HarnessErrorCode
HARNESS_ERROR_CODE_CANCEL_OUTCOME_UNKNOWN: HarnessErrorCode
HARNESS_ERROR_CODE_RESUME_UNSUPPORTED: HarnessErrorCode
HARNESS_ERROR_CODE_SCHEMA_INVALID: HarnessErrorCode
HARNESS_ERROR_CODE_INTEGRITY_FAILURE: HarnessErrorCode
HARNESS_ERROR_CODE_BUDGET_EXHAUSTED: HarnessErrorCode
HARNESS_ERROR_CODE_SANDBOX_VIOLATION: HarnessErrorCode
HARNESS_ERROR_CODE_DEPENDENCY_UNAVAILABLE: HarnessErrorCode
HARNESS_ERROR_CODE_PROCESS_EXITED: HarnessErrorCode
HARNESS_ERROR_CODE_UNKNOWN_CRITICAL_EVENT: HarnessErrorCode
HARNESS_ERROR_CODE_PROFILE_REVISION_CONFLICT: HarnessErrorCode
HARNESS_ERROR_CODE_PROFILE_NOT_ACTIVE: HarnessErrorCode
HARNESS_ERROR_CODE_NOT_FOUND: HarnessErrorCode
HARNESS_ERROR_CODE_INTERNAL: HarnessErrorCode
CONTENT_MUTATION_OPERATION_UNSPECIFIED: ContentMutationOperation
CONTENT_MUTATION_OPERATION_APPEND: ContentMutationOperation
CONTENT_MUTATION_OPERATION_REPLACE: ContentMutationOperation
CONTENT_MUTATION_OPERATION_FINALIZE: ContentMutationOperation
HARNESS_CONTENT_SAFETY_FLAG_UNSPECIFIED: HarnessContentSafetyFlag
HARNESS_CONTENT_SAFETY_FLAG_CONTROL_REDACTED: HarnessContentSafetyFlag
HARNESS_CONTENT_SAFETY_FLAG_CREDENTIAL_REDACTED: HarnessContentSafetyFlag
HARNESS_CONTENT_SAFETY_FLAG_TRUNCATED: HarnessContentSafetyFlag
HARNESS_CONTENT_SAFETY_FLAG_PROVISIONAL: HarnessContentSafetyFlag
HARNESS_CONTENT_MARKER_KIND_UNSPECIFIED: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_INVALID_TEXT: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_FORBIDDEN_CATEGORY: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_UNKNOWN_CATEGORY: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_REDACTION_INPUT_UNAVAILABLE: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_LIMIT_REACHED: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_PROFILE_CHANGED_HISTORY_UNAVAILABLE: HarnessContentMarkerKind
HARNESS_CONTENT_MARKER_KIND_COMPACTED: HarnessContentMarkerKind
HARNESS_CONTENT_COMPACTION_REASON_UNSPECIFIED: HarnessContentCompactionReason
HARNESS_CONTENT_COMPACTION_REASON_OWNER_HISTORY_FLOOR_ADVANCED: HarnessContentCompactionReason
HARNESS_CONTENT_RETENTION_REASON_UNSPECIFIED: HarnessContentRetentionReason
HARNESS_CONTENT_RETENTION_REASON_TERMINAL_MINIMUM_EXPIRED: HarnessContentRetentionReason

class NativeProtocolFingerprint(_message.Message):
    __slots__ = ("protocol_name", "protocol_version", "schema_sha256", "adapter_version", "native_executable_version", "native_binary_sha256")
    PROTOCOL_NAME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_SHA256_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_VERSION_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EXECUTABLE_VERSION_FIELD_NUMBER: _ClassVar[int]
    NATIVE_BINARY_SHA256_FIELD_NUMBER: _ClassVar[int]
    protocol_name: str
    protocol_version: str
    schema_sha256: str
    adapter_version: str
    native_executable_version: str
    native_binary_sha256: str
    def __init__(self, protocol_name: _Optional[str] = ..., protocol_version: _Optional[str] = ..., schema_sha256: _Optional[str] = ..., adapter_version: _Optional[str] = ..., native_executable_version: _Optional[str] = ..., native_binary_sha256: _Optional[str] = ...) -> None: ...

class CapabilitySemantics(_message.Message):
    __slots__ = ("structured_dispatch", "structured_events", "approval_requests", "artifact_return", "usage_receipts", "checkpoint_refs", "side_effect_receipts", "cancellation", "resume", "event_ordering", "governed_user_visible_content")
    STRUCTURED_DISPATCH_FIELD_NUMBER: _ClassVar[int]
    STRUCTURED_EVENTS_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_RETURN_FIELD_NUMBER: _ClassVar[int]
    USAGE_RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_REFS_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    RESUME_FIELD_NUMBER: _ClassVar[int]
    EVENT_ORDERING_FIELD_NUMBER: _ClassVar[int]
    GOVERNED_USER_VISIBLE_CONTENT_FIELD_NUMBER: _ClassVar[int]
    structured_dispatch: SupportLevel
    structured_events: SupportLevel
    approval_requests: SupportLevel
    artifact_return: SupportLevel
    usage_receipts: SupportLevel
    checkpoint_refs: SupportLevel
    side_effect_receipts: SupportLevel
    cancellation: CancellationSemantics
    resume: _containers.RepeatedScalarFieldContainer[ResumeSemantics]
    event_ordering: EventOrderingGuarantee
    governed_user_visible_content: SupportLevel
    def __init__(self, structured_dispatch: _Optional[_Union[SupportLevel, str]] = ..., structured_events: _Optional[_Union[SupportLevel, str]] = ..., approval_requests: _Optional[_Union[SupportLevel, str]] = ..., artifact_return: _Optional[_Union[SupportLevel, str]] = ..., usage_receipts: _Optional[_Union[SupportLevel, str]] = ..., checkpoint_refs: _Optional[_Union[SupportLevel, str]] = ..., side_effect_receipts: _Optional[_Union[SupportLevel, str]] = ..., cancellation: _Optional[_Union[CancellationSemantics, str]] = ..., resume: _Optional[_Iterable[_Union[ResumeSemantics, str]]] = ..., event_ordering: _Optional[_Union[EventOrderingGuarantee, str]] = ..., governed_user_visible_content: _Optional[_Union[SupportLevel, str]] = ...) -> None: ...

class CapabilityDeclaration(_message.Message):
    __slots__ = ("declaration_id", "adapter_id", "harness_id", "resource_type", "native_protocol", "provider_selectors", "model_family_selectors", "input_contract_refs", "output_contract_refs", "approval_kinds", "semantics", "sandbox_profile_ref", "tool_policy_ref", "data_egress_policy_ref", "trust_profile_ref", "declared_at")
    DECLARATION_ID_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    HARNESS_ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    NATIVE_PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_SELECTORS_FIELD_NUMBER: _ClassVar[int]
    MODEL_FAMILY_SELECTORS_FIELD_NUMBER: _ClassVar[int]
    INPUT_CONTRACT_REFS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_CONTRACT_REFS_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_KINDS_FIELD_NUMBER: _ClassVar[int]
    SEMANTICS_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    TOOL_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    DATA_EGRESS_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    TRUST_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    DECLARED_AT_FIELD_NUMBER: _ClassVar[int]
    declaration_id: str
    adapter_id: str
    harness_id: str
    resource_type: HarnessResourceType
    native_protocol: NativeProtocolFingerprint
    provider_selectors: _containers.RepeatedScalarFieldContainer[str]
    model_family_selectors: _containers.RepeatedScalarFieldContainer[str]
    input_contract_refs: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    output_contract_refs: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    approval_kinds: _containers.RepeatedScalarFieldContainer[ApprovalKind]
    semantics: CapabilitySemantics
    sandbox_profile_ref: _common_pb2.ContractReference
    tool_policy_ref: _common_pb2.ContractReference
    data_egress_policy_ref: _common_pb2.ContractReference
    trust_profile_ref: _common_pb2.ContractReference
    declared_at: _timestamp_pb2.Timestamp
    def __init__(self, declaration_id: _Optional[str] = ..., adapter_id: _Optional[str] = ..., harness_id: _Optional[str] = ..., resource_type: _Optional[_Union[HarnessResourceType, str]] = ..., native_protocol: _Optional[_Union[NativeProtocolFingerprint, _Mapping]] = ..., provider_selectors: _Optional[_Iterable[str]] = ..., model_family_selectors: _Optional[_Iterable[str]] = ..., input_contract_refs: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ..., output_contract_refs: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ..., approval_kinds: _Optional[_Iterable[_Union[ApprovalKind, str]]] = ..., semantics: _Optional[_Union[CapabilitySemantics, _Mapping]] = ..., sandbox_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., tool_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., data_egress_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., trust_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., declared_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CapabilityProfile(_message.Message):
    __slots__ = ("profile_id", "revision", "digest_sha256", "status", "declaration", "attestation_level", "attestation_evidence_refs", "activated_at", "valid_until")
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DECLARATION_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    ACTIVATED_AT_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    profile_id: str
    revision: int
    digest_sha256: str
    status: CapabilityProfileStatus
    declaration: CapabilityDeclaration
    attestation_level: AttestationLevel
    attestation_evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    activated_at: _timestamp_pb2.Timestamp
    valid_until: _timestamp_pb2.Timestamp
    def __init__(self, profile_id: _Optional[str] = ..., revision: _Optional[int] = ..., digest_sha256: _Optional[str] = ..., status: _Optional[_Union[CapabilityProfileStatus, str]] = ..., declaration: _Optional[_Union[CapabilityDeclaration, _Mapping]] = ..., attestation_level: _Optional[_Union[AttestationLevel, str]] = ..., attestation_evidence_refs: _Optional[_Iterable[str]] = ..., activated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AttestCapabilityCommand(_message.Message):
    __slots__ = ("meta", "expected_registry_revision", "profile_id", "declaration", "attestation_level", "attestation_evidence_refs", "valid_until")
    META_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REGISTRY_REVISION_FIELD_NUMBER: _ClassVar[int]
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    DECLARATION_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_LEVEL_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    expected_registry_revision: int
    profile_id: str
    declaration: CapabilityDeclaration
    attestation_level: AttestationLevel
    attestation_evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    valid_until: _timestamp_pb2.Timestamp
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., expected_registry_revision: _Optional[int] = ..., profile_id: _Optional[str] = ..., declaration: _Optional[_Union[CapabilityDeclaration, _Mapping]] = ..., attestation_level: _Optional[_Union[AttestationLevel, str]] = ..., attestation_evidence_refs: _Optional[_Iterable[str]] = ..., valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CapabilityProfileEvent(_message.Message):
    __slots__ = ("event_id", "command_id", "expected_registry_revision", "resulting_registry_revision", "profile_id", "profile_digest_sha256", "authenticated_principal_id", "authority_ref", "idempotency_key", "request_digest_sha256", "occurred_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REGISTRY_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_REGISTRY_REVISION_FIELD_NUMBER: _ClassVar[int]
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    PROFILE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    command_id: str
    expected_registry_revision: int
    resulting_registry_revision: int
    profile_id: str
    profile_digest_sha256: str
    authenticated_principal_id: str
    authority_ref: str
    idempotency_key: str
    request_digest_sha256: str
    occurred_at: _timestamp_pb2.Timestamp
    def __init__(self, event_id: _Optional[str] = ..., command_id: _Optional[str] = ..., expected_registry_revision: _Optional[int] = ..., resulting_registry_revision: _Optional[int] = ..., profile_id: _Optional[str] = ..., profile_digest_sha256: _Optional[str] = ..., authenticated_principal_id: _Optional[str] = ..., authority_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., occurred_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AttestCapabilityResult(_message.Message):
    __slots__ = ("replayed", "profile", "error", "committed_event")
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_EVENT_FIELD_NUMBER: _ClassVar[int]
    replayed: bool
    profile: CapabilityProfile
    error: HarnessError
    committed_event: CapabilityProfileEvent
    def __init__(self, replayed: _Optional[bool] = ..., profile: _Optional[_Union[CapabilityProfile, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ..., committed_event: _Optional[_Union[CapabilityProfileEvent, _Mapping]] = ...) -> None: ...

class GetCapabilityProfileRequest(_message.Message):
    __slots__ = ("profile_id",)
    PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    profile_id: str
    def __init__(self, profile_id: _Optional[str] = ...) -> None: ...

class GetCapabilityProfileResponse(_message.Message):
    __slots__ = ("profile", "error")
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    profile: CapabilityProfile
    error: HarnessError
    def __init__(self, profile: _Optional[_Union[CapabilityProfile, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ...) -> None: ...

class ProbeHarnessRequest(_message.Message):
    __slots__ = ("meta", "adapter_id", "expected_protocol_schema_sha256", "probe_profile_ref")
    META_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PROTOCOL_SCHEMA_SHA256_FIELD_NUMBER: _ClassVar[int]
    PROBE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    adapter_id: str
    expected_protocol_schema_sha256: str
    probe_profile_ref: _common_pb2.ContractReference
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., adapter_id: _Optional[str] = ..., expected_protocol_schema_sha256: _Optional[str] = ..., probe_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class ProbeHarnessResult(_message.Message):
    __slots__ = ("probe_id", "readiness", "observed_protocol", "safe_diagnostic_codes", "evidence_refs", "observed_at")
    PROBE_ID_FIELD_NUMBER: _ClassVar[int]
    READINESS_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    SAFE_DIAGNOSTIC_CODES_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_AT_FIELD_NUMBER: _ClassVar[int]
    probe_id: str
    readiness: HarnessReadiness
    observed_protocol: NativeProtocolFingerprint
    safe_diagnostic_codes: _containers.RepeatedScalarFieldContainer[str]
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    observed_at: _timestamp_pb2.Timestamp
    def __init__(self, probe_id: _Optional[str] = ..., readiness: _Optional[_Union[HarnessReadiness, str]] = ..., observed_protocol: _Optional[_Union[NativeProtocolFingerprint, _Mapping]] = ..., safe_diagnostic_codes: _Optional[_Iterable[str]] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., observed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class NoCatalogSnapshot(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DispatchRouteBinding(_message.Message):
    __slots__ = ("provider_bootstrap_profile_id", "selected_harness_id", "provider_model_id", "catalog_snapshot_sha256", "no_catalog_snapshot", "capability_profile_id", "route_binding_sha256")
    PROVIDER_BOOTSTRAP_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    SELECTED_HARNESS_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    CATALOG_SNAPSHOT_SHA256_FIELD_NUMBER: _ClassVar[int]
    NO_CATALOG_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    ROUTE_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    provider_bootstrap_profile_id: str
    selected_harness_id: str
    provider_model_id: str
    catalog_snapshot_sha256: str
    no_catalog_snapshot: NoCatalogSnapshot
    capability_profile_id: str
    route_binding_sha256: str
    def __init__(self, provider_bootstrap_profile_id: _Optional[str] = ..., selected_harness_id: _Optional[str] = ..., provider_model_id: _Optional[str] = ..., catalog_snapshot_sha256: _Optional[str] = ..., no_catalog_snapshot: _Optional[_Union[NoCatalogSnapshot, _Mapping]] = ..., capability_profile_id: _Optional[str] = ..., route_binding_sha256: _Optional[str] = ...) -> None: ...

class DispatchEnvelope(_message.Message):
    __slots__ = ("meta", "run_id", "run_revision", "step_id", "step_revision", "attempt_id", "attempt_revision", "dispatch_id", "dispatch_fingerprint", "fencing_token", "capability_profile_ref", "input_bundle_ref", "input_bundle_sha256", "workspace_ref", "budget_profile_ref", "sandbox_profile_ref", "tool_policy_ref", "data_egress_policy_ref", "approval_policy_ref", "session_strategy", "native_session_ref", "checkpoint_ref", "route_binding")
    META_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_REVISION_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    INPUT_BUNDLE_REF_FIELD_NUMBER: _ClassVar[int]
    INPUT_BUNDLE_SHA256_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    TOOL_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    DATA_EGRESS_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    SESSION_STRATEGY_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_REF_FIELD_NUMBER: _ClassVar[int]
    ROUTE_BINDING_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    run_id: str
    run_revision: int
    step_id: str
    step_revision: int
    attempt_id: str
    attempt_revision: int
    dispatch_id: str
    dispatch_fingerprint: str
    fencing_token: int
    capability_profile_ref: _common_pb2.ContractReference
    input_bundle_ref: str
    input_bundle_sha256: str
    workspace_ref: str
    budget_profile_ref: _common_pb2.ContractReference
    sandbox_profile_ref: _common_pb2.ContractReference
    tool_policy_ref: _common_pb2.ContractReference
    data_egress_policy_ref: _common_pb2.ContractReference
    approval_policy_ref: _common_pb2.ContractReference
    session_strategy: NativeSessionStrategy
    native_session_ref: str
    checkpoint_ref: str
    route_binding: DispatchRouteBinding
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., run_id: _Optional[str] = ..., run_revision: _Optional[int] = ..., step_id: _Optional[str] = ..., step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., attempt_revision: _Optional[int] = ..., dispatch_id: _Optional[str] = ..., dispatch_fingerprint: _Optional[str] = ..., fencing_token: _Optional[int] = ..., capability_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., input_bundle_ref: _Optional[str] = ..., input_bundle_sha256: _Optional[str] = ..., workspace_ref: _Optional[str] = ..., budget_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., sandbox_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., tool_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., data_egress_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., approval_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., session_strategy: _Optional[_Union[NativeSessionStrategy, str]] = ..., native_session_ref: _Optional[str] = ..., checkpoint_ref: _Optional[str] = ..., route_binding: _Optional[_Union[DispatchRouteBinding, _Mapping]] = ...) -> None: ...

class DispatchReceipt(_message.Message):
    __slots__ = ("receipt_id", "disposition", "attempt_id", "dispatch_id", "fencing_token", "adapter_id", "capability_profile_id", "observed_protocol", "native_request_ref", "native_session_ref", "native_execution_ref", "receipt_digest_sha256", "evidence_ref", "delivered_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    NATIVE_REQUEST_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EXECUTION_REF_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    disposition: DeliveryDisposition
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    adapter_id: str
    capability_profile_id: str
    observed_protocol: NativeProtocolFingerprint
    native_request_ref: str
    native_session_ref: str
    native_execution_ref: str
    receipt_digest_sha256: str
    evidence_ref: str
    delivered_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., disposition: _Optional[_Union[DeliveryDisposition, str]] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., adapter_id: _Optional[str] = ..., capability_profile_id: _Optional[str] = ..., observed_protocol: _Optional[_Union[NativeProtocolFingerprint, _Mapping]] = ..., native_request_ref: _Optional[str] = ..., native_session_ref: _Optional[str] = ..., native_execution_ref: _Optional[str] = ..., receipt_digest_sha256: _Optional[str] = ..., evidence_ref: _Optional[str] = ..., delivered_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HarnessAckObservation(_message.Message):
    __slots__ = ("disposition", "ack_receipt_id", "native_session_ref", "native_execution_ref")
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    ACK_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EXECUTION_REF_FIELD_NUMBER: _ClassVar[int]
    disposition: AckDisposition
    ack_receipt_id: str
    native_session_ref: str
    native_execution_ref: str
    def __init__(self, disposition: _Optional[_Union[AckDisposition, str]] = ..., ack_receipt_id: _Optional[str] = ..., native_session_ref: _Optional[str] = ..., native_execution_ref: _Optional[str] = ...) -> None: ...

class LifecycleObservation(_message.Message):
    __slots__ = ("kind", "native_item_ref", "safe_status_code", "side_effect_certainty", "native_will_retry")
    KIND_FIELD_NUMBER: _ClassVar[int]
    NATIVE_ITEM_REF_FIELD_NUMBER: _ClassVar[int]
    SAFE_STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    NATIVE_WILL_RETRY_FIELD_NUMBER: _ClassVar[int]
    kind: LifecycleKind
    native_item_ref: str
    safe_status_code: str
    side_effect_certainty: SideEffectCertainty
    native_will_retry: bool
    def __init__(self, kind: _Optional[_Union[LifecycleKind, str]] = ..., native_item_ref: _Optional[str] = ..., safe_status_code: _Optional[str] = ..., side_effect_certainty: _Optional[_Union[SideEffectCertainty, str]] = ..., native_will_retry: _Optional[bool] = ...) -> None: ...

class ApprovalRequestObservation(_message.Message):
    __slots__ = ("approval_request_id", "kind", "action_digest_sha256", "requested_scope_ref", "display_summary_ref", "native_routing_ref", "lifecycle", "request_revision")
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ACTION_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_SUMMARY_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_ROUTING_REF_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_REVISION_FIELD_NUMBER: _ClassVar[int]
    approval_request_id: str
    kind: ApprovalKind
    action_digest_sha256: str
    requested_scope_ref: str
    display_summary_ref: str
    native_routing_ref: str
    lifecycle: ApprovalRequestLifecycleKind
    request_revision: int
    def __init__(self, approval_request_id: _Optional[str] = ..., kind: _Optional[_Union[ApprovalKind, str]] = ..., action_digest_sha256: _Optional[str] = ..., requested_scope_ref: _Optional[str] = ..., display_summary_ref: _Optional[str] = ..., native_routing_ref: _Optional[str] = ..., lifecycle: _Optional[_Union[ApprovalRequestLifecycleKind, str]] = ..., request_revision: _Optional[int] = ...) -> None: ...

class UsageObservation(_message.Message):
    __slots__ = ("usage_receipt_ref", "input_tokens", "output_tokens", "cached_input_tokens", "cost_receipt_ref")
    USAGE_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    CACHED_INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    COST_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    usage_receipt_ref: str
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    cost_receipt_ref: str
    def __init__(self, usage_receipt_ref: _Optional[str] = ..., input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., cached_input_tokens: _Optional[int] = ..., cost_receipt_ref: _Optional[str] = ...) -> None: ...

class CheckpointObservation(_message.Message):
    __slots__ = ("checkpoint_candidate_ref", "checkpoint_digest_sha256", "resume_semantics")
    CHECKPOINT_CANDIDATE_REF_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    RESUME_SEMANTICS_FIELD_NUMBER: _ClassVar[int]
    checkpoint_candidate_ref: str
    checkpoint_digest_sha256: str
    resume_semantics: ResumeSemantics
    def __init__(self, checkpoint_candidate_ref: _Optional[str] = ..., checkpoint_digest_sha256: _Optional[str] = ..., resume_semantics: _Optional[_Union[ResumeSemantics, str]] = ...) -> None: ...

class ArtifactReturnObservation(_message.Message):
    __slots__ = ("return_receipt_id", "return_digest_sha256", "native_completion_ref", "output_manifest_ref", "output_manifest_sha256", "workspace_delta_ref", "side_effect_ledger_ref", "usage_receipt_ref", "final_message_ref")
    RETURN_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    NATIVE_COMPLETION_REF_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_MANIFEST_REF_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_MANIFEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_DELTA_REF_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_LEDGER_REF_FIELD_NUMBER: _ClassVar[int]
    USAGE_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    FINAL_MESSAGE_REF_FIELD_NUMBER: _ClassVar[int]
    return_receipt_id: str
    return_digest_sha256: str
    native_completion_ref: str
    output_manifest_ref: str
    output_manifest_sha256: str
    workspace_delta_ref: str
    side_effect_ledger_ref: str
    usage_receipt_ref: str
    final_message_ref: str
    def __init__(self, return_receipt_id: _Optional[str] = ..., return_digest_sha256: _Optional[str] = ..., native_completion_ref: _Optional[str] = ..., output_manifest_ref: _Optional[str] = ..., output_manifest_sha256: _Optional[str] = ..., workspace_delta_ref: _Optional[str] = ..., side_effect_ledger_ref: _Optional[str] = ..., usage_receipt_ref: _Optional[str] = ..., final_message_ref: _Optional[str] = ...) -> None: ...

class DiagnosticObservation(_message.Message):
    __slots__ = ("safe_diagnostic_code", "error_fingerprint", "recovery_required")
    SAFE_DIAGNOSTIC_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    safe_diagnostic_code: str
    error_fingerprint: str
    recovery_required: bool
    def __init__(self, safe_diagnostic_code: _Optional[str] = ..., error_fingerprint: _Optional[str] = ..., recovery_required: _Optional[bool] = ...) -> None: ...

class NotContextBoundProof(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AuthorizedContextConsumptionProof(_message.Message):
    __slots__ = ("authorization_id", "committed_request_digest_sha256")
    AUTHORIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    authorization_id: str
    committed_request_digest_sha256: str
    def __init__(self, authorization_id: _Optional[str] = ..., committed_request_digest_sha256: _Optional[str] = ...) -> None: ...

class DispatchContextConsumptionProof(_message.Message):
    __slots__ = ("not_context_bound", "authorized_context")
    NOT_CONTEXT_BOUND_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZED_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    not_context_bound: NotContextBoundProof
    authorized_context: AuthorizedContextConsumptionProof
    def __init__(self, not_context_bound: _Optional[_Union[NotContextBoundProof, _Mapping]] = ..., authorized_context: _Optional[_Union[AuthorizedContextConsumptionProof, _Mapping]] = ...) -> None: ...

class AssistantTextContentCandidate(_message.Message):
    __slots__ = ("message_id", "revision", "previous_revision", "operation", "text_utf8", "delta_or_snapshot_digest_sha256", "previous_raw_cumulative_digest_sha256", "raw_cumulative_digest_sha256")
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    TEXT_UTF8_FIELD_NUMBER: _ClassVar[int]
    DELTA_OR_SNAPSHOT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_RAW_CUMULATIVE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    RAW_CUMULATIVE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    message_id: str
    revision: int
    previous_revision: int
    operation: ContentMutationOperation
    text_utf8: bytes
    delta_or_snapshot_digest_sha256: str
    previous_raw_cumulative_digest_sha256: str
    raw_cumulative_digest_sha256: str
    def __init__(self, message_id: _Optional[str] = ..., revision: _Optional[int] = ..., previous_revision: _Optional[int] = ..., operation: _Optional[_Union[ContentMutationOperation, str]] = ..., text_utf8: _Optional[bytes] = ..., delta_or_snapshot_digest_sha256: _Optional[str] = ..., previous_raw_cumulative_digest_sha256: _Optional[str] = ..., raw_cumulative_digest_sha256: _Optional[str] = ...) -> None: ...

class LifecycleContentCandidate(_message.Message):
    __slots__ = ("kind", "side_effect_certainty", "native_will_retry")
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    NATIVE_WILL_RETRY_FIELD_NUMBER: _ClassVar[int]
    kind: LifecycleKind
    side_effect_certainty: SideEffectCertainty
    native_will_retry: bool
    def __init__(self, kind: _Optional[_Union[LifecycleKind, str]] = ..., side_effect_certainty: _Optional[_Union[SideEffectCertainty, str]] = ..., native_will_retry: _Optional[bool] = ...) -> None: ...

class UsageContentCandidate(_message.Message):
    __slots__ = ("input_tokens", "output_tokens", "cached_input_tokens")
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    CACHED_INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    def __init__(self, input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., cached_input_tokens: _Optional[int] = ...) -> None: ...

class ApprovalRequiredContentCandidate(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BlockedSourceContentCandidate(_message.Message):
    __slots__ = ("reason",)
    REASON_FIELD_NUMBER: _ClassVar[int]
    reason: HarnessContentMarkerKind
    def __init__(self, reason: _Optional[_Union[HarnessContentMarkerKind, str]] = ...) -> None: ...

class UserVisibleContentCandidate(_message.Message):
    __slots__ = ("assistant_text", "lifecycle", "usage", "approval_required", "blocked_source", "candidate_digest_sha256")
    ASSISTANT_TEXT_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    BLOCKED_SOURCE_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    assistant_text: AssistantTextContentCandidate
    lifecycle: LifecycleContentCandidate
    usage: UsageContentCandidate
    approval_required: ApprovalRequiredContentCandidate
    blocked_source: BlockedSourceContentCandidate
    candidate_digest_sha256: str
    def __init__(self, assistant_text: _Optional[_Union[AssistantTextContentCandidate, _Mapping]] = ..., lifecycle: _Optional[_Union[LifecycleContentCandidate, _Mapping]] = ..., usage: _Optional[_Union[UsageContentCandidate, _Mapping]] = ..., approval_required: _Optional[_Union[ApprovalRequiredContentCandidate, _Mapping]] = ..., blocked_source: _Optional[_Union[BlockedSourceContentCandidate, _Mapping]] = ..., candidate_digest_sha256: _Optional[str] = ...) -> None: ...

class HarnessContentSignalObservation(_message.Message):
    __slots__ = ("content_event_id", "delivered_receipt_id", "delivered_receipt_digest_sha256", "dispatch_route_binding_sha256", "context_consumption_proof", "candidate")
    CONTENT_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ROUTE_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_CONSUMPTION_PROOF_FIELD_NUMBER: _ClassVar[int]
    CANDIDATE_FIELD_NUMBER: _ClassVar[int]
    content_event_id: str
    delivered_receipt_id: str
    delivered_receipt_digest_sha256: str
    dispatch_route_binding_sha256: str
    context_consumption_proof: DispatchContextConsumptionProof
    candidate: UserVisibleContentCandidate
    def __init__(self, content_event_id: _Optional[str] = ..., delivered_receipt_id: _Optional[str] = ..., delivered_receipt_digest_sha256: _Optional[str] = ..., dispatch_route_binding_sha256: _Optional[str] = ..., context_consumption_proof: _Optional[_Union[DispatchContextConsumptionProof, _Mapping]] = ..., candidate: _Optional[_Union[UserVisibleContentCandidate, _Mapping]] = ...) -> None: ...

class SafeAssistantTextContent(_message.Message):
    __slots__ = ("safe_message_id", "revision", "previous_revision", "operation", "safe_text_utf8", "safe_cumulative_digest_sha256", "part_index", "part_count")
    SAFE_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_REVISION_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    SAFE_TEXT_UTF8_FIELD_NUMBER: _ClassVar[int]
    SAFE_CUMULATIVE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    PART_INDEX_FIELD_NUMBER: _ClassVar[int]
    PART_COUNT_FIELD_NUMBER: _ClassVar[int]
    safe_message_id: str
    revision: int
    previous_revision: int
    operation: ContentMutationOperation
    safe_text_utf8: str
    safe_cumulative_digest_sha256: str
    part_index: int
    part_count: int
    def __init__(self, safe_message_id: _Optional[str] = ..., revision: _Optional[int] = ..., previous_revision: _Optional[int] = ..., operation: _Optional[_Union[ContentMutationOperation, str]] = ..., safe_text_utf8: _Optional[str] = ..., safe_cumulative_digest_sha256: _Optional[str] = ..., part_index: _Optional[int] = ..., part_count: _Optional[int] = ...) -> None: ...

class SafeLifecycleContent(_message.Message):
    __slots__ = ("kind", "side_effect_certainty", "native_will_retry")
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_CERTAINTY_FIELD_NUMBER: _ClassVar[int]
    NATIVE_WILL_RETRY_FIELD_NUMBER: _ClassVar[int]
    kind: LifecycleKind
    side_effect_certainty: SideEffectCertainty
    native_will_retry: bool
    def __init__(self, kind: _Optional[_Union[LifecycleKind, str]] = ..., side_effect_certainty: _Optional[_Union[SideEffectCertainty, str]] = ..., native_will_retry: _Optional[bool] = ...) -> None: ...

class SafeUsageContent(_message.Message):
    __slots__ = ("input_tokens", "output_tokens", "cached_input_tokens")
    INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    CACHED_INPUT_TOKENS_FIELD_NUMBER: _ClassVar[int]
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    def __init__(self, input_tokens: _Optional[int] = ..., output_tokens: _Optional[int] = ..., cached_input_tokens: _Optional[int] = ...) -> None: ...

class SafeApprovalRequiredContent(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SafeArtifactIdentity(_message.Message):
    __slots__ = ("artifact_id", "artifact_digest_sha256")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    artifact_id: str
    artifact_digest_sha256: str
    def __init__(self, artifact_id: _Optional[str] = ..., artifact_digest_sha256: _Optional[str] = ...) -> None: ...

class SafeArtifactRelationContent(_message.Message):
    __slots__ = ("safe_content_differs_from_artifact", "artifact")
    SAFE_CONTENT_DIFFERS_FROM_ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    safe_content_differs_from_artifact: bool
    artifact: SafeArtifactIdentity
    def __init__(self, safe_content_differs_from_artifact: _Optional[bool] = ..., artifact: _Optional[_Union[SafeArtifactIdentity, _Mapping]] = ...) -> None: ...

class SafeContentMarker(_message.Message):
    __slots__ = ("kind",)
    KIND_FIELD_NUMBER: _ClassVar[int]
    kind: HarnessContentMarkerKind
    def __init__(self, kind: _Optional[_Union[HarnessContentMarkerKind, str]] = ...) -> None: ...

class SafeHarnessContentRecord(_message.Message):
    __slots__ = ("record_id", "record_digest_sha256", "content_event_id", "task_id", "run_id", "step_id", "attempt_id", "dispatch_id", "fencing_token", "route_binding_sha256", "disclosure_profile_ref", "provider_family_alias", "model_alias", "collaboration_role", "safety_flags", "assistant_text", "lifecycle", "usage", "approval_required", "artifact_relation", "marker")
    RECORD_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    CONTENT_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ROUTE_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    DISCLOSURE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FAMILY_ALIAS_FIELD_NUMBER: _ClassVar[int]
    MODEL_ALIAS_FIELD_NUMBER: _ClassVar[int]
    COLLABORATION_ROLE_FIELD_NUMBER: _ClassVar[int]
    SAFETY_FLAGS_FIELD_NUMBER: _ClassVar[int]
    ASSISTANT_TEXT_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_RELATION_FIELD_NUMBER: _ClassVar[int]
    MARKER_FIELD_NUMBER: _ClassVar[int]
    record_id: str
    record_digest_sha256: str
    content_event_id: str
    task_id: str
    run_id: str
    step_id: str
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    route_binding_sha256: str
    disclosure_profile_ref: _common_pb2.ContractReference
    provider_family_alias: str
    model_alias: str
    collaboration_role: str
    safety_flags: _containers.RepeatedScalarFieldContainer[HarnessContentSafetyFlag]
    assistant_text: SafeAssistantTextContent
    lifecycle: SafeLifecycleContent
    usage: SafeUsageContent
    approval_required: SafeApprovalRequiredContent
    artifact_relation: SafeArtifactRelationContent
    marker: SafeContentMarker
    def __init__(self, record_id: _Optional[str] = ..., record_digest_sha256: _Optional[str] = ..., content_event_id: _Optional[str] = ..., task_id: _Optional[str] = ..., run_id: _Optional[str] = ..., step_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., route_binding_sha256: _Optional[str] = ..., disclosure_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., provider_family_alias: _Optional[str] = ..., model_alias: _Optional[str] = ..., collaboration_role: _Optional[str] = ..., safety_flags: _Optional[_Iterable[_Union[HarnessContentSafetyFlag, str]]] = ..., assistant_text: _Optional[_Union[SafeAssistantTextContent, _Mapping]] = ..., lifecycle: _Optional[_Union[SafeLifecycleContent, _Mapping]] = ..., usage: _Optional[_Union[SafeUsageContent, _Mapping]] = ..., approval_required: _Optional[_Union[SafeApprovalRequiredContent, _Mapping]] = ..., artifact_relation: _Optional[_Union[SafeArtifactRelationContent, _Mapping]] = ..., marker: _Optional[_Union[SafeContentMarker, _Mapping]] = ...) -> None: ...

class HarnessContentHistoryCompactionRecord(_message.Message):
    __slots__ = ("compaction_record_id", "compaction_record_digest_sha256", "task_id", "attempt_id", "final_epoch", "final_sequence", "final_safe_content_digest_sha256", "owner_snapshot_digest_sha256", "disclosure_profile_ref", "compacted_at", "reason")
    COMPACTION_RECORD_ID_FIELD_NUMBER: _ClassVar[int]
    COMPACTION_RECORD_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    FINAL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    FINAL_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    FINAL_SAFE_CONTENT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    OWNER_SNAPSHOT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DISCLOSURE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    COMPACTED_AT_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    compaction_record_id: str
    compaction_record_digest_sha256: str
    task_id: str
    attempt_id: str
    final_epoch: str
    final_sequence: int
    final_safe_content_digest_sha256: str
    owner_snapshot_digest_sha256: str
    disclosure_profile_ref: _common_pb2.ContractReference
    compacted_at: _timestamp_pb2.Timestamp
    reason: HarnessContentCompactionReason
    def __init__(self, compaction_record_id: _Optional[str] = ..., compaction_record_digest_sha256: _Optional[str] = ..., task_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., final_epoch: _Optional[str] = ..., final_sequence: _Optional[int] = ..., final_safe_content_digest_sha256: _Optional[str] = ..., owner_snapshot_digest_sha256: _Optional[str] = ..., disclosure_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., compacted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., reason: _Optional[_Union[HarnessContentCompactionReason, str]] = ...) -> None: ...

class HarnessContentRetentionTombstone(_message.Message):
    __slots__ = ("tombstone_id", "tombstone_digest_sha256", "task_id", "attempt_id", "final_epoch", "final_sequence", "final_safe_content_digest_sha256", "disclosure_profile_ref", "terminal_committed_at", "compacted_at", "reason")
    TOMBSTONE_ID_FIELD_NUMBER: _ClassVar[int]
    TOMBSTONE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    FINAL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    FINAL_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    FINAL_SAFE_CONTENT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DISCLOSURE_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    TERMINAL_COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    COMPACTED_AT_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    tombstone_id: str
    tombstone_digest_sha256: str
    task_id: str
    attempt_id: str
    final_epoch: str
    final_sequence: int
    final_safe_content_digest_sha256: str
    disclosure_profile_ref: _common_pb2.ContractReference
    terminal_committed_at: _timestamp_pb2.Timestamp
    compacted_at: _timestamp_pb2.Timestamp
    reason: HarnessContentRetentionReason
    def __init__(self, tombstone_id: _Optional[str] = ..., tombstone_digest_sha256: _Optional[str] = ..., task_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., final_epoch: _Optional[str] = ..., final_sequence: _Optional[int] = ..., final_safe_content_digest_sha256: _Optional[str] = ..., disclosure_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., terminal_committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., compacted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., reason: _Optional[_Union[HarnessContentRetentionReason, str]] = ...) -> None: ...

class SafeHarnessContentProjectionEvent(_message.Message):
    __slots__ = ("content_record", "history_compaction", "retention_tombstone")
    CONTENT_RECORD_FIELD_NUMBER: _ClassVar[int]
    HISTORY_COMPACTION_FIELD_NUMBER: _ClassVar[int]
    RETENTION_TOMBSTONE_FIELD_NUMBER: _ClassVar[int]
    content_record: SafeHarnessContentRecord
    history_compaction: HarnessContentHistoryCompactionRecord
    retention_tombstone: HarnessContentRetentionTombstone
    def __init__(self, content_record: _Optional[_Union[SafeHarnessContentRecord, _Mapping]] = ..., history_compaction: _Optional[_Union[HarnessContentHistoryCompactionRecord, _Mapping]] = ..., retention_tombstone: _Optional[_Union[HarnessContentRetentionTombstone, _Mapping]] = ...) -> None: ...

class HarnessObservation(_message.Message):
    __slots__ = ("observation_id", "adapter_id", "attempt_id", "dispatch_id", "fencing_token", "observation_sequence", "native_event_id", "native_sequence", "native_event_digest_sha256", "capability_profile_id", "criticality", "raw_evidence_ref", "native_observed_at", "adapter_received_at", "ack", "lifecycle", "approval_request", "usage", "checkpoint", "artifact_return", "diagnostic", "content_signal")
    OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    OBSERVATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EVENT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    CRITICALITY_FIELD_NUMBER: _ClassVar[int]
    RAW_EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_OBSERVED_AT_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_RECEIVED_AT_FIELD_NUMBER: _ClassVar[int]
    ACK_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_RETURN_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTIC_FIELD_NUMBER: _ClassVar[int]
    CONTENT_SIGNAL_FIELD_NUMBER: _ClassVar[int]
    observation_id: str
    adapter_id: str
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    observation_sequence: int
    native_event_id: str
    native_sequence: int
    native_event_digest_sha256: str
    capability_profile_id: str
    criticality: ObservationCriticality
    raw_evidence_ref: str
    native_observed_at: _timestamp_pb2.Timestamp
    adapter_received_at: _timestamp_pb2.Timestamp
    ack: HarnessAckObservation
    lifecycle: LifecycleObservation
    approval_request: ApprovalRequestObservation
    usage: UsageObservation
    checkpoint: CheckpointObservation
    artifact_return: ArtifactReturnObservation
    diagnostic: DiagnosticObservation
    content_signal: HarnessContentSignalObservation
    def __init__(self, observation_id: _Optional[str] = ..., adapter_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., observation_sequence: _Optional[int] = ..., native_event_id: _Optional[str] = ..., native_sequence: _Optional[int] = ..., native_event_digest_sha256: _Optional[str] = ..., capability_profile_id: _Optional[str] = ..., criticality: _Optional[_Union[ObservationCriticality, str]] = ..., raw_evidence_ref: _Optional[str] = ..., native_observed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., adapter_received_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ack: _Optional[_Union[HarnessAckObservation, _Mapping]] = ..., lifecycle: _Optional[_Union[LifecycleObservation, _Mapping]] = ..., approval_request: _Optional[_Union[ApprovalRequestObservation, _Mapping]] = ..., usage: _Optional[_Union[UsageObservation, _Mapping]] = ..., checkpoint: _Optional[_Union[CheckpointObservation, _Mapping]] = ..., artifact_return: _Optional[_Union[ArtifactReturnObservation, _Mapping]] = ..., diagnostic: _Optional[_Union[DiagnosticObservation, _Mapping]] = ..., content_signal: _Optional[_Union[HarnessContentSignalObservation, _Mapping]] = ...) -> None: ...

class ApprovalDecisionEnvelope(_message.Message):
    __slots__ = ("meta", "attempt_id", "dispatch_id", "fencing_token", "approval_request_id", "action_digest_sha256", "decision", "authority_decision_ref", "native_routing_ref")
    META_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_ROUTING_REF_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    approval_request_id: str
    action_digest_sha256: str
    decision: ApprovalDecision
    authority_decision_ref: str
    native_routing_ref: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., approval_request_id: _Optional[str] = ..., action_digest_sha256: _Optional[str] = ..., decision: _Optional[_Union[ApprovalDecision, str]] = ..., authority_decision_ref: _Optional[str] = ..., native_routing_ref: _Optional[str] = ...) -> None: ...

class ApprovalDecisionReceipt(_message.Message):
    __slots__ = ("receipt_id", "approval_request_id", "decision", "disposition", "receipt_digest_sha256", "delivered_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    approval_request_id: str
    decision: ApprovalDecision
    disposition: DeliveryDisposition
    receipt_digest_sha256: str
    delivered_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., approval_request_id: _Optional[str] = ..., decision: _Optional[_Union[ApprovalDecision, str]] = ..., disposition: _Optional[_Union[DeliveryDisposition, str]] = ..., receipt_digest_sha256: _Optional[str] = ..., delivered_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CancelExecutionEnvelope(_message.Message):
    __slots__ = ("meta", "attempt_id", "dispatch_id", "fencing_token", "cancellation_request_id", "native_session_ref", "native_execution_ref", "confirmation_deadline")
    META_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_EXECUTION_REF_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_DEADLINE_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    cancellation_request_id: str
    native_session_ref: str
    native_execution_ref: str
    confirmation_deadline: _timestamp_pb2.Timestamp
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., cancellation_request_id: _Optional[str] = ..., native_session_ref: _Optional[str] = ..., native_execution_ref: _Optional[str] = ..., confirmation_deadline: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CancelExecutionReceipt(_message.Message):
    __slots__ = ("receipt_id", "cancellation_request_id", "disposition", "receipt_digest_sha256", "evidence_ref", "delivered_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    cancellation_request_id: str
    disposition: CancellationDeliveryDisposition
    receipt_digest_sha256: str
    evidence_ref: str
    delivered_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., cancellation_request_id: _Optional[str] = ..., disposition: _Optional[_Union[CancellationDeliveryDisposition, str]] = ..., receipt_digest_sha256: _Optional[str] = ..., evidence_ref: _Optional[str] = ..., delivered_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ResumeExecutionEnvelope(_message.Message):
    __slots__ = ("meta", "attempt_id", "dispatch_id", "fencing_token", "resume_request_id", "required_semantics", "native_session_ref", "checkpoint_ref", "recovery_evidence_ref")
    META_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    RESUME_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_SEMANTICS_FIELD_NUMBER: _ClassVar[int]
    NATIVE_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_REF_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    resume_request_id: str
    required_semantics: ResumeSemantics
    native_session_ref: str
    checkpoint_ref: str
    recovery_evidence_ref: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., resume_request_id: _Optional[str] = ..., required_semantics: _Optional[_Union[ResumeSemantics, str]] = ..., native_session_ref: _Optional[str] = ..., checkpoint_ref: _Optional[str] = ..., recovery_evidence_ref: _Optional[str] = ...) -> None: ...

class ResumeExecutionReceipt(_message.Message):
    __slots__ = ("receipt_id", "resume_request_id", "disposition", "delivered_semantics", "receipt_digest_sha256", "evidence_ref", "delivered_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RESUME_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_SEMANTICS_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REF_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    resume_request_id: str
    disposition: ResumeDeliveryDisposition
    delivered_semantics: ResumeSemantics
    receipt_digest_sha256: str
    evidence_ref: str
    delivered_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., resume_request_id: _Optional[str] = ..., disposition: _Optional[_Union[ResumeDeliveryDisposition, str]] = ..., delivered_semantics: _Optional[_Union[ResumeSemantics, str]] = ..., receipt_digest_sha256: _Optional[str] = ..., evidence_ref: _Optional[str] = ..., delivered_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SubscribeObservationsRequest(_message.Message):
    __slots__ = ("adapter_id", "attempt_id", "after_observation_sequence", "fencing_token")
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    AFTER_OBSERVATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    adapter_id: str
    attempt_id: str
    after_observation_sequence: int
    fencing_token: int
    def __init__(self, adapter_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., after_observation_sequence: _Optional[int] = ..., fencing_token: _Optional[int] = ...) -> None: ...

class HarnessError(_message.Message):
    __slots__ = ("code", "safe_detail_code", "retryable_delivery", "recovery_required", "error_fingerprint", "audit_ref")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_DETAIL_CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_DELIVERY_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    AUDIT_REF_FIELD_NUMBER: _ClassVar[int]
    code: HarnessErrorCode
    safe_detail_code: str
    retryable_delivery: bool
    recovery_required: bool
    error_fingerprint: str
    audit_ref: str
    def __init__(self, code: _Optional[_Union[HarnessErrorCode, str]] = ..., safe_detail_code: _Optional[str] = ..., retryable_delivery: _Optional[bool] = ..., recovery_required: _Optional[bool] = ..., error_fingerprint: _Optional[str] = ..., audit_ref: _Optional[str] = ...) -> None: ...

class DispatchResult(_message.Message):
    __slots__ = ("receipt", "error")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    receipt: DispatchReceipt
    error: HarnessError
    def __init__(self, receipt: _Optional[_Union[DispatchReceipt, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ...) -> None: ...

class ApprovalDecisionResult(_message.Message):
    __slots__ = ("receipt", "error")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    receipt: ApprovalDecisionReceipt
    error: HarnessError
    def __init__(self, receipt: _Optional[_Union[ApprovalDecisionReceipt, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ...) -> None: ...

class CancelExecutionResult(_message.Message):
    __slots__ = ("receipt", "error")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    receipt: CancelExecutionReceipt
    error: HarnessError
    def __init__(self, receipt: _Optional[_Union[CancelExecutionReceipt, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ...) -> None: ...

class ResumeExecutionResult(_message.Message):
    __slots__ = ("receipt", "error")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    receipt: ResumeExecutionReceipt
    error: HarnessError
    def __init__(self, receipt: _Optional[_Union[ResumeExecutionReceipt, _Mapping]] = ..., error: _Optional[_Union[HarnessError, _Mapping]] = ...) -> None: ...
