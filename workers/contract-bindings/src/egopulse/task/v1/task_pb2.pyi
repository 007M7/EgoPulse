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

class TaskStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TASK_STATUS_UNSPECIFIED: _ClassVar[TaskStatus]
    TASK_STATUS_READY: _ClassVar[TaskStatus]
    TASK_STATUS_ACTIVE: _ClassVar[TaskStatus]
    TASK_STATUS_VERIFICATION_PENDING: _ClassVar[TaskStatus]
    TASK_STATUS_VERDICT_PENDING: _ClassVar[TaskStatus]
    TASK_STATUS_REWORK: _ClassVar[TaskStatus]
    TASK_STATUS_CANCELLATION_PENDING: _ClassVar[TaskStatus]
    TASK_STATUS_INTERRUPTED: _ClassVar[TaskStatus]
    TASK_STATUS_HELD: _ClassVar[TaskStatus]
    TASK_STATUS_COMPLETED: _ClassVar[TaskStatus]
    TASK_STATUS_REJECTED: _ClassVar[TaskStatus]
    TASK_STATUS_CANCELLED: _ClassVar[TaskStatus]
    TASK_STATUS_SUPERSEDED: _ClassVar[TaskStatus]
    TASK_STATUS_EXPIRED: _ClassVar[TaskStatus]

class FounderDecision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FOUNDER_DECISION_UNSPECIFIED: _ClassVar[FounderDecision]
    FOUNDER_DECISION_ACCEPT: _ClassVar[FounderDecision]
    FOUNDER_DECISION_REWORK: _ClassVar[FounderDecision]
    FOUNDER_DECISION_REJECT: _ClassVar[FounderDecision]

class TaskEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TASK_EVENT_KIND_UNSPECIFIED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_CREATED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_ACTIVATED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_EVIDENCE_SUBMITTED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_VERIFICATION_RECORDED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_VERDICT_APPLIED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_REVISED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_INTERRUPTED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_HELD: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_RESUMED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_CANCELLATION_REQUESTED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_CANCELLATION_RECORDED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_SUPERSEDED: _ClassVar[TaskEventKind]
    TASK_EVENT_KIND_EXPIRED: _ClassVar[TaskEventKind]

class TaskErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TASK_ERROR_CODE_UNSPECIFIED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_UNAUTHENTICATED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_PERMISSION_DENIED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_NOT_FOUND: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_REVISION_CONFLICT: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_STATE_CONFLICT: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_CONTRACT_MISMATCH: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_STALE_REFERENCE: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_UNVERIFIED_REFERENCE: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_TERMINAL_GATE_UNSATISFIED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_RESOURCE_EXHAUSTED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_RECOVERY_REQUIRED: _ClassVar[TaskErrorCode]
    TASK_ERROR_CODE_INTERNAL: _ClassVar[TaskErrorCode]
TASK_STATUS_UNSPECIFIED: TaskStatus
TASK_STATUS_READY: TaskStatus
TASK_STATUS_ACTIVE: TaskStatus
TASK_STATUS_VERIFICATION_PENDING: TaskStatus
TASK_STATUS_VERDICT_PENDING: TaskStatus
TASK_STATUS_REWORK: TaskStatus
TASK_STATUS_CANCELLATION_PENDING: TaskStatus
TASK_STATUS_INTERRUPTED: TaskStatus
TASK_STATUS_HELD: TaskStatus
TASK_STATUS_COMPLETED: TaskStatus
TASK_STATUS_REJECTED: TaskStatus
TASK_STATUS_CANCELLED: TaskStatus
TASK_STATUS_SUPERSEDED: TaskStatus
TASK_STATUS_EXPIRED: TaskStatus
FOUNDER_DECISION_UNSPECIFIED: FounderDecision
FOUNDER_DECISION_ACCEPT: FounderDecision
FOUNDER_DECISION_REWORK: FounderDecision
FOUNDER_DECISION_REJECT: FounderDecision
TASK_EVENT_KIND_UNSPECIFIED: TaskEventKind
TASK_EVENT_KIND_CREATED: TaskEventKind
TASK_EVENT_KIND_ACTIVATED: TaskEventKind
TASK_EVENT_KIND_EVIDENCE_SUBMITTED: TaskEventKind
TASK_EVENT_KIND_VERIFICATION_RECORDED: TaskEventKind
TASK_EVENT_KIND_VERDICT_APPLIED: TaskEventKind
TASK_EVENT_KIND_REVISED: TaskEventKind
TASK_EVENT_KIND_INTERRUPTED: TaskEventKind
TASK_EVENT_KIND_HELD: TaskEventKind
TASK_EVENT_KIND_RESUMED: TaskEventKind
TASK_EVENT_KIND_CANCELLATION_REQUESTED: TaskEventKind
TASK_EVENT_KIND_CANCELLATION_RECORDED: TaskEventKind
TASK_EVENT_KIND_SUPERSEDED: TaskEventKind
TASK_EVENT_KIND_EXPIRED: TaskEventKind
TASK_ERROR_CODE_UNSPECIFIED: TaskErrorCode
TASK_ERROR_CODE_INVALID_ARGUMENT: TaskErrorCode
TASK_ERROR_CODE_UNAUTHENTICATED: TaskErrorCode
TASK_ERROR_CODE_PERMISSION_DENIED: TaskErrorCode
TASK_ERROR_CODE_NOT_FOUND: TaskErrorCode
TASK_ERROR_CODE_REVISION_CONFLICT: TaskErrorCode
TASK_ERROR_CODE_STATE_CONFLICT: TaskErrorCode
TASK_ERROR_CODE_IDEMPOTENCY_CONFLICT: TaskErrorCode
TASK_ERROR_CODE_CONTRACT_MISMATCH: TaskErrorCode
TASK_ERROR_CODE_STALE_REFERENCE: TaskErrorCode
TASK_ERROR_CODE_UNVERIFIED_REFERENCE: TaskErrorCode
TASK_ERROR_CODE_TERMINAL_GATE_UNSATISFIED: TaskErrorCode
TASK_ERROR_CODE_INTEGRITY_FAILURE: TaskErrorCode
TASK_ERROR_CODE_RESOURCE_EXHAUSTED: TaskErrorCode
TASK_ERROR_CODE_RECOVERY_REQUIRED: TaskErrorCode
TASK_ERROR_CODE_INTERNAL: TaskErrorCode

class WorkCapabilityRouteBinding(_message.Message):
    __slots__ = ("route_id", "route_generation", "provider_profile_id", "provider_id", "harness_id", "harness_model_id", "provider_model_id", "capability_profile_ref", "catalog_snapshot_sha256", "native_composition_generation", "route_binding_sha256")
    ROUTE_ID_FIELD_NUMBER: _ClassVar[int]
    ROUTE_GENERATION_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    HARNESS_ID_FIELD_NUMBER: _ClassVar[int]
    HARNESS_MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_MODEL_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    CATALOG_SNAPSHOT_SHA256_FIELD_NUMBER: _ClassVar[int]
    NATIVE_COMPOSITION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    ROUTE_BINDING_SHA256_FIELD_NUMBER: _ClassVar[int]
    route_id: str
    route_generation: int
    provider_profile_id: str
    provider_id: str
    harness_id: str
    harness_model_id: str
    provider_model_id: str
    capability_profile_ref: _common_pb2.ContractReference
    catalog_snapshot_sha256: str
    native_composition_generation: str
    route_binding_sha256: str
    def __init__(self, route_id: _Optional[str] = ..., route_generation: _Optional[int] = ..., provider_profile_id: _Optional[str] = ..., provider_id: _Optional[str] = ..., harness_id: _Optional[str] = ..., harness_model_id: _Optional[str] = ..., provider_model_id: _Optional[str] = ..., capability_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., catalog_snapshot_sha256: _Optional[str] = ..., native_composition_generation: _Optional[str] = ..., route_binding_sha256: _Optional[str] = ...) -> None: ...

class TaskSnapshot(_message.Message):
    __slots__ = ("task_id", "revision", "work_revision", "status", "resume_status", "work_type", "input_snapshot_id", "target_scope_ref", "acceptance_contract_ref", "budget_profile_ref", "current_run_id", "artifact_set_id", "verification_artifact_id", "founder_verdict_id", "hold_reason_code", "created_at", "updated_at", "work_capability_route")
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESUME_STATUS_FIELD_NUMBER: _ClassVar[int]
    WORK_TYPE_FIELD_NUMBER: _ClassVar[int]
    INPUT_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    CURRENT_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    WORK_CAPABILITY_ROUTE_FIELD_NUMBER: _ClassVar[int]
    task_id: str
    revision: int
    work_revision: int
    status: TaskStatus
    resume_status: TaskStatus
    work_type: str
    input_snapshot_id: str
    target_scope_ref: str
    acceptance_contract_ref: _common_pb2.ContractReference
    budget_profile_ref: _common_pb2.ContractReference
    current_run_id: str
    artifact_set_id: str
    verification_artifact_id: str
    founder_verdict_id: str
    hold_reason_code: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    work_capability_route: WorkCapabilityRouteBinding
    def __init__(self, task_id: _Optional[str] = ..., revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., status: _Optional[_Union[TaskStatus, str]] = ..., resume_status: _Optional[_Union[TaskStatus, str]] = ..., work_type: _Optional[str] = ..., input_snapshot_id: _Optional[str] = ..., target_scope_ref: _Optional[str] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., budget_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., current_run_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ..., verification_artifact_id: _Optional[str] = ..., founder_verdict_id: _Optional[str] = ..., hold_reason_code: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., work_capability_route: _Optional[_Union[WorkCapabilityRouteBinding, _Mapping]] = ...) -> None: ...

class CreateTaskCommand(_message.Message):
    __slots__ = ("meta", "work_type", "input_snapshot_id", "target_scope_ref", "acceptance_contract_ref", "budget_profile_ref", "work_capability_route")
    META_FIELD_NUMBER: _ClassVar[int]
    WORK_TYPE_FIELD_NUMBER: _ClassVar[int]
    INPUT_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    WORK_CAPABILITY_ROUTE_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    work_type: str
    input_snapshot_id: str
    target_scope_ref: str
    acceptance_contract_ref: _common_pb2.ContractReference
    budget_profile_ref: _common_pb2.ContractReference
    work_capability_route: WorkCapabilityRouteBinding
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., work_type: _Optional[str] = ..., input_snapshot_id: _Optional[str] = ..., target_scope_ref: _Optional[str] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., budget_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., work_capability_route: _Optional[_Union[WorkCapabilityRouteBinding, _Mapping]] = ...) -> None: ...

class ActivateTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "work_revision", "run_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    work_revision: int
    run_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., run_id: _Optional[str] = ...) -> None: ...

class SubmitTaskEvidenceCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "work_revision", "return_handoff_id", "artifact_set_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    work_revision: int
    return_handoff_id: str
    artifact_set_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., return_handoff_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ...) -> None: ...

class RecordTaskVerificationCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "work_revision", "verification_artifact_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    work_revision: int
    verification_artifact_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., verification_artifact_id: _Optional[str] = ...) -> None: ...

class ApplyFounderVerdictCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "work_revision", "founder_verdict_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    work_revision: int
    founder_verdict_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., founder_verdict_id: _Optional[str] = ...) -> None: ...

class ReviseTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "expected_work_revision", "new_input_snapshot_id", "new_target_scope_ref", "new_acceptance_contract_ref")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    NEW_INPUT_SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    NEW_TARGET_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    NEW_ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    expected_work_revision: int
    new_input_snapshot_id: str
    new_target_scope_ref: str
    new_acceptance_contract_ref: _common_pb2.ContractReference
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., expected_work_revision: _Optional[int] = ..., new_input_snapshot_id: _Optional[str] = ..., new_target_scope_ref: _Optional[str] = ..., new_acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class InterruptTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "interruption_evidence_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    INTERRUPTION_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    interruption_evidence_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., interruption_evidence_id: _Optional[str] = ...) -> None: ...

class HoldTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "hold_reason_code", "recovery_evidence_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    hold_reason_code: str
    recovery_evidence_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., hold_reason_code: _Optional[str] = ..., recovery_evidence_id: _Optional[str] = ...) -> None: ...

class ResumeTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "expected_resume_status", "recovery_evidence_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RESUME_STATUS_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    expected_resume_status: TaskStatus
    recovery_evidence_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., expected_resume_status: _Optional[_Union[TaskStatus, str]] = ..., recovery_evidence_id: _Optional[str] = ...) -> None: ...

class RequestTaskCancellationCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "reason_code")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    reason_code: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., reason_code: _Optional[str] = ...) -> None: ...

class RecordTaskCancellationOutcomeCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "outcome", "cancellation_receipt_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    OUTCOME_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    outcome: TaskStatus
    cancellation_receipt_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., outcome: _Optional[_Union[TaskStatus, str]] = ..., cancellation_receipt_id: _Optional[str] = ...) -> None: ...

class SupersedeTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "replacement_task_id", "reason_code")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    REPLACEMENT_TASK_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    replacement_task_id: str
    reason_code: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., replacement_task_id: _Optional[str] = ..., reason_code: _Optional[str] = ...) -> None: ...

class ExpireTaskCommand(_message.Message):
    __slots__ = ("meta", "task_id", "expected_revision", "policy_decision_id")
    META_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    task_id: str
    expected_revision: int
    policy_decision_id: str
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., policy_decision_id: _Optional[str] = ...) -> None: ...

class TaskCommand(_message.Message):
    __slots__ = ("create_task", "activate_task", "submit_task_evidence", "record_task_verification", "apply_founder_verdict", "revise_task", "interrupt_task", "hold_task", "resume_task", "request_task_cancellation", "record_task_cancellation_outcome", "supersede_task", "expire_task")
    CREATE_TASK_FIELD_NUMBER: _ClassVar[int]
    ACTIVATE_TASK_FIELD_NUMBER: _ClassVar[int]
    SUBMIT_TASK_EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    RECORD_TASK_VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    APPLY_FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    REVISE_TASK_FIELD_NUMBER: _ClassVar[int]
    INTERRUPT_TASK_FIELD_NUMBER: _ClassVar[int]
    HOLD_TASK_FIELD_NUMBER: _ClassVar[int]
    RESUME_TASK_FIELD_NUMBER: _ClassVar[int]
    REQUEST_TASK_CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_TASK_CANCELLATION_OUTCOME_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDE_TASK_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_TASK_FIELD_NUMBER: _ClassVar[int]
    create_task: CreateTaskCommand
    activate_task: ActivateTaskCommand
    submit_task_evidence: SubmitTaskEvidenceCommand
    record_task_verification: RecordTaskVerificationCommand
    apply_founder_verdict: ApplyFounderVerdictCommand
    revise_task: ReviseTaskCommand
    interrupt_task: InterruptTaskCommand
    hold_task: HoldTaskCommand
    resume_task: ResumeTaskCommand
    request_task_cancellation: RequestTaskCancellationCommand
    record_task_cancellation_outcome: RecordTaskCancellationOutcomeCommand
    supersede_task: SupersedeTaskCommand
    expire_task: ExpireTaskCommand
    def __init__(self, create_task: _Optional[_Union[CreateTaskCommand, _Mapping]] = ..., activate_task: _Optional[_Union[ActivateTaskCommand, _Mapping]] = ..., submit_task_evidence: _Optional[_Union[SubmitTaskEvidenceCommand, _Mapping]] = ..., record_task_verification: _Optional[_Union[RecordTaskVerificationCommand, _Mapping]] = ..., apply_founder_verdict: _Optional[_Union[ApplyFounderVerdictCommand, _Mapping]] = ..., revise_task: _Optional[_Union[ReviseTaskCommand, _Mapping]] = ..., interrupt_task: _Optional[_Union[InterruptTaskCommand, _Mapping]] = ..., hold_task: _Optional[_Union[HoldTaskCommand, _Mapping]] = ..., resume_task: _Optional[_Union[ResumeTaskCommand, _Mapping]] = ..., request_task_cancellation: _Optional[_Union[RequestTaskCancellationCommand, _Mapping]] = ..., record_task_cancellation_outcome: _Optional[_Union[RecordTaskCancellationOutcomeCommand, _Mapping]] = ..., supersede_task: _Optional[_Union[SupersedeTaskCommand, _Mapping]] = ..., expire_task: _Optional[_Union[ExpireTaskCommand, _Mapping]] = ...) -> None: ...

class TaskEvent(_message.Message):
    __slots__ = ("event_id", "command_id", "kind", "task_id", "expected_revision", "resulting_revision", "work_revision", "authenticated_principal_id", "authority_ref", "idempotency_key", "request_digest_sha256", "correlation_id", "causation_id", "evidence_refs", "occurred_at", "snapshot")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAUSATION_ID_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    command_id: str
    kind: TaskEventKind
    task_id: str
    expected_revision: int
    resulting_revision: int
    work_revision: int
    authenticated_principal_id: str
    authority_ref: str
    idempotency_key: str
    request_digest_sha256: str
    correlation_id: str
    causation_id: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    occurred_at: _timestamp_pb2.Timestamp
    snapshot: TaskSnapshot
    def __init__(self, event_id: _Optional[str] = ..., command_id: _Optional[str] = ..., kind: _Optional[_Union[TaskEventKind, str]] = ..., task_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., resulting_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., authenticated_principal_id: _Optional[str] = ..., authority_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., correlation_id: _Optional[str] = ..., causation_id: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., occurred_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., snapshot: _Optional[_Union[TaskSnapshot, _Mapping]] = ...) -> None: ...

class TaskError(_message.Message):
    __slots__ = ("code", "safe_detail_code", "retryable", "recovery_required", "current_revision", "audit_ref")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_DETAIL_CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    CURRENT_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUDIT_REF_FIELD_NUMBER: _ClassVar[int]
    code: TaskErrorCode
    safe_detail_code: str
    retryable: bool
    recovery_required: bool
    current_revision: int
    audit_ref: str
    def __init__(self, code: _Optional[_Union[TaskErrorCode, str]] = ..., safe_detail_code: _Optional[str] = ..., retryable: _Optional[bool] = ..., recovery_required: _Optional[bool] = ..., current_revision: _Optional[int] = ..., audit_ref: _Optional[str] = ...) -> None: ...

class TaskCommandResult(_message.Message):
    __slots__ = ("replayed", "task", "error", "committed_event")
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    TASK_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_EVENT_FIELD_NUMBER: _ClassVar[int]
    replayed: bool
    task: TaskSnapshot
    error: TaskError
    committed_event: TaskEvent
    def __init__(self, replayed: _Optional[bool] = ..., task: _Optional[_Union[TaskSnapshot, _Mapping]] = ..., error: _Optional[_Union[TaskError, _Mapping]] = ..., committed_event: _Optional[_Union[TaskEvent, _Mapping]] = ...) -> None: ...

class GetTaskRequest(_message.Message):
    __slots__ = ("task_id",)
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    task_id: str
    def __init__(self, task_id: _Optional[str] = ...) -> None: ...

class GetTaskResponse(_message.Message):
    __slots__ = ("task", "error")
    TASK_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    task: TaskSnapshot
    error: TaskError
    def __init__(self, task: _Optional[_Union[TaskSnapshot, _Mapping]] = ..., error: _Optional[_Union[TaskError, _Mapping]] = ...) -> None: ...
