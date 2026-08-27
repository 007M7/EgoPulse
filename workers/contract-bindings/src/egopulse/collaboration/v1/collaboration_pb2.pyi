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

class RunStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RUN_STATUS_UNSPECIFIED: _ClassVar[RunStatus]
    RUN_STATUS_PLANNED: _ClassVar[RunStatus]
    RUN_STATUS_ACTIVE: _ClassVar[RunStatus]
    RUN_STATUS_RETURN_PENDING: _ClassVar[RunStatus]
    RUN_STATUS_HELD: _ClassVar[RunStatus]
    RUN_STATUS_CANCELLATION_PENDING: _ClassVar[RunStatus]
    RUN_STATUS_RETURNED: _ClassVar[RunStatus]
    RUN_STATUS_FAILED: _ClassVar[RunStatus]
    RUN_STATUS_CANCELLED: _ClassVar[RunStatus]
    RUN_STATUS_SUPERSEDED: _ClassVar[RunStatus]
    RUN_STATUS_EXPIRED: _ClassVar[RunStatus]

class StepStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STEP_STATUS_UNSPECIFIED: _ClassVar[StepStatus]
    STEP_STATUS_BLOCKED: _ClassVar[StepStatus]
    STEP_STATUS_READY: _ClassVar[StepStatus]
    STEP_STATUS_ACTIVE: _ClassVar[StepStatus]
    STEP_STATUS_RETURN_PENDING: _ClassVar[StepStatus]
    STEP_STATUS_HELD: _ClassVar[StepStatus]
    STEP_STATUS_RETURNED: _ClassVar[StepStatus]
    STEP_STATUS_FAILED: _ClassVar[StepStatus]
    STEP_STATUS_CANCELLED: _ClassVar[StepStatus]
    STEP_STATUS_SKIPPED: _ClassVar[StepStatus]
    STEP_STATUS_SUPERSEDED: _ClassVar[StepStatus]

class AttemptStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ATTEMPT_STATUS_UNSPECIFIED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_CREATED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_LEASED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_DISPATCH_PENDING: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_DISPATCHED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_ACKNOWLEDGED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_RUNNING: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_CANCELLATION_PENDING: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_OUTCOME_UNKNOWN: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_RECONCILING: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_INTERRUPTED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_HELD: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_RETURNED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_FAILED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_CANCELLED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_SUPERSEDED: _ClassVar[AttemptStatus]
    ATTEMPT_STATUS_EXPIRED: _ClassVar[AttemptStatus]

class RecoveryClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECOVERY_CLASS_UNSPECIFIED: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_RESUME_SAFE: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_RETRY_IDEMPOTENT: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_RECONCILE_BEFORE_RETRY: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_COMPENSATABLE: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_MANUAL_ONLY: _ClassVar[RecoveryClass]
    RECOVERY_CLASS_IRREVERSIBLE: _ClassVar[RecoveryClass]

class ReconciliationDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECONCILIATION_DISPOSITION_UNSPECIFIED: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_RETURN_FOUND: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_NO_EFFECT_PROVEN: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_RESUME_SAFE: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_RETRY_IDEMPOTENT: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_COMPENSATE: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_MANUAL_ONLY: _ClassVar[ReconciliationDisposition]
    RECONCILIATION_DISPOSITION_IRREVERSIBLE_UNKNOWN: _ClassVar[ReconciliationDisposition]

class AttemptCancellationDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ATTEMPT_CANCELLATION_DISPOSITION_UNSPECIFIED: _ClassVar[AttemptCancellationDisposition]
    ATTEMPT_CANCELLATION_DISPOSITION_CANCELLED_CONFIRMED: _ClassVar[AttemptCancellationDisposition]
    ATTEMPT_CANCELLATION_DISPOSITION_RETURN_FOUND: _ClassVar[AttemptCancellationDisposition]
    ATTEMPT_CANCELLATION_DISPOSITION_OUTCOME_UNKNOWN: _ClassVar[AttemptCancellationDisposition]

class CollaborationEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COLLABORATION_EVENT_KIND_UNSPECIFIED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RUN_CREATED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RUN_ACTIVATED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_ATTEMPT_CREATED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_LEASE_ACQUIRED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_LEASE_RENEWED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_DISPATCH_INTENT_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_DELIVERY_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_ACK_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RUNNING_OBSERVED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RETURN_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_OUTCOME_MARKED_UNKNOWN: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RECONCILIATION_STARTED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RECONCILIATION_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_CHECKPOINT_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_CANCELLATION_REQUESTED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_CANCELLATION_RECORDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_ATTEMPT_HELD: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_ATTEMPT_RESUMED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_STEP_RETURN_COMMITTED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RUN_SUPERSEDED: _ClassVar[CollaborationEventKind]
    COLLABORATION_EVENT_KIND_RUN_EXPIRED: _ClassVar[CollaborationEventKind]

class CollaborationErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    COLLABORATION_ERROR_CODE_UNSPECIFIED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_UNAUTHENTICATED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_PERMISSION_DENIED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_NOT_FOUND: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_RUN_REVISION_CONFLICT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_ENTITY_REVISION_CONFLICT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_STATE_CONFLICT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_FENCING_REJECTED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_SEQUENCE_CONFLICT: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_CAPACITY_EXHAUSTED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_STALE_TASK_REFERENCE: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_CONTRACT_MISMATCH: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_OUTCOME_UNKNOWN: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_RECOVERY_REQUIRED: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[CollaborationErrorCode]
    COLLABORATION_ERROR_CODE_INTERNAL: _ClassVar[CollaborationErrorCode]
RUN_STATUS_UNSPECIFIED: RunStatus
RUN_STATUS_PLANNED: RunStatus
RUN_STATUS_ACTIVE: RunStatus
RUN_STATUS_RETURN_PENDING: RunStatus
RUN_STATUS_HELD: RunStatus
RUN_STATUS_CANCELLATION_PENDING: RunStatus
RUN_STATUS_RETURNED: RunStatus
RUN_STATUS_FAILED: RunStatus
RUN_STATUS_CANCELLED: RunStatus
RUN_STATUS_SUPERSEDED: RunStatus
RUN_STATUS_EXPIRED: RunStatus
STEP_STATUS_UNSPECIFIED: StepStatus
STEP_STATUS_BLOCKED: StepStatus
STEP_STATUS_READY: StepStatus
STEP_STATUS_ACTIVE: StepStatus
STEP_STATUS_RETURN_PENDING: StepStatus
STEP_STATUS_HELD: StepStatus
STEP_STATUS_RETURNED: StepStatus
STEP_STATUS_FAILED: StepStatus
STEP_STATUS_CANCELLED: StepStatus
STEP_STATUS_SKIPPED: StepStatus
STEP_STATUS_SUPERSEDED: StepStatus
ATTEMPT_STATUS_UNSPECIFIED: AttemptStatus
ATTEMPT_STATUS_CREATED: AttemptStatus
ATTEMPT_STATUS_LEASED: AttemptStatus
ATTEMPT_STATUS_DISPATCH_PENDING: AttemptStatus
ATTEMPT_STATUS_DISPATCHED: AttemptStatus
ATTEMPT_STATUS_ACKNOWLEDGED: AttemptStatus
ATTEMPT_STATUS_RUNNING: AttemptStatus
ATTEMPT_STATUS_CANCELLATION_PENDING: AttemptStatus
ATTEMPT_STATUS_OUTCOME_UNKNOWN: AttemptStatus
ATTEMPT_STATUS_RECONCILING: AttemptStatus
ATTEMPT_STATUS_INTERRUPTED: AttemptStatus
ATTEMPT_STATUS_HELD: AttemptStatus
ATTEMPT_STATUS_RETURNED: AttemptStatus
ATTEMPT_STATUS_FAILED: AttemptStatus
ATTEMPT_STATUS_CANCELLED: AttemptStatus
ATTEMPT_STATUS_SUPERSEDED: AttemptStatus
ATTEMPT_STATUS_EXPIRED: AttemptStatus
RECOVERY_CLASS_UNSPECIFIED: RecoveryClass
RECOVERY_CLASS_RESUME_SAFE: RecoveryClass
RECOVERY_CLASS_RETRY_IDEMPOTENT: RecoveryClass
RECOVERY_CLASS_RECONCILE_BEFORE_RETRY: RecoveryClass
RECOVERY_CLASS_COMPENSATABLE: RecoveryClass
RECOVERY_CLASS_MANUAL_ONLY: RecoveryClass
RECOVERY_CLASS_IRREVERSIBLE: RecoveryClass
RECONCILIATION_DISPOSITION_UNSPECIFIED: ReconciliationDisposition
RECONCILIATION_DISPOSITION_RETURN_FOUND: ReconciliationDisposition
RECONCILIATION_DISPOSITION_NO_EFFECT_PROVEN: ReconciliationDisposition
RECONCILIATION_DISPOSITION_RESUME_SAFE: ReconciliationDisposition
RECONCILIATION_DISPOSITION_RETRY_IDEMPOTENT: ReconciliationDisposition
RECONCILIATION_DISPOSITION_COMPENSATE: ReconciliationDisposition
RECONCILIATION_DISPOSITION_MANUAL_ONLY: ReconciliationDisposition
RECONCILIATION_DISPOSITION_IRREVERSIBLE_UNKNOWN: ReconciliationDisposition
ATTEMPT_CANCELLATION_DISPOSITION_UNSPECIFIED: AttemptCancellationDisposition
ATTEMPT_CANCELLATION_DISPOSITION_CANCELLED_CONFIRMED: AttemptCancellationDisposition
ATTEMPT_CANCELLATION_DISPOSITION_RETURN_FOUND: AttemptCancellationDisposition
ATTEMPT_CANCELLATION_DISPOSITION_OUTCOME_UNKNOWN: AttemptCancellationDisposition
COLLABORATION_EVENT_KIND_UNSPECIFIED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RUN_CREATED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RUN_ACTIVATED: CollaborationEventKind
COLLABORATION_EVENT_KIND_ATTEMPT_CREATED: CollaborationEventKind
COLLABORATION_EVENT_KIND_LEASE_ACQUIRED: CollaborationEventKind
COLLABORATION_EVENT_KIND_LEASE_RENEWED: CollaborationEventKind
COLLABORATION_EVENT_KIND_DISPATCH_INTENT_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_DELIVERY_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_ACK_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RUNNING_OBSERVED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RETURN_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_OUTCOME_MARKED_UNKNOWN: CollaborationEventKind
COLLABORATION_EVENT_KIND_RECONCILIATION_STARTED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RECONCILIATION_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_CHECKPOINT_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_CANCELLATION_REQUESTED: CollaborationEventKind
COLLABORATION_EVENT_KIND_CANCELLATION_RECORDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_ATTEMPT_HELD: CollaborationEventKind
COLLABORATION_EVENT_KIND_ATTEMPT_RESUMED: CollaborationEventKind
COLLABORATION_EVENT_KIND_STEP_RETURN_COMMITTED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RUN_SUPERSEDED: CollaborationEventKind
COLLABORATION_EVENT_KIND_RUN_EXPIRED: CollaborationEventKind
COLLABORATION_ERROR_CODE_UNSPECIFIED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_INVALID_ARGUMENT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_UNAUTHENTICATED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_PERMISSION_DENIED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_NOT_FOUND: CollaborationErrorCode
COLLABORATION_ERROR_CODE_RUN_REVISION_CONFLICT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_ENTITY_REVISION_CONFLICT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_STATE_CONFLICT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_IDEMPOTENCY_CONFLICT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_FENCING_REJECTED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_SEQUENCE_CONFLICT: CollaborationErrorCode
COLLABORATION_ERROR_CODE_CAPACITY_EXHAUSTED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_STALE_TASK_REFERENCE: CollaborationErrorCode
COLLABORATION_ERROR_CODE_CONTRACT_MISMATCH: CollaborationErrorCode
COLLABORATION_ERROR_CODE_OUTCOME_UNKNOWN: CollaborationErrorCode
COLLABORATION_ERROR_CODE_RECOVERY_REQUIRED: CollaborationErrorCode
COLLABORATION_ERROR_CODE_INTEGRITY_FAILURE: CollaborationErrorCode
COLLABORATION_ERROR_CODE_INTERNAL: CollaborationErrorCode

class Lease(_message.Message):
    __slots__ = ("lease_id", "owner_instance_id", "fencing_token", "acquired_at", "expires_at", "heartbeat_at", "lease_policy_ref")
    LEASE_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ACQUIRED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_AT_FIELD_NUMBER: _ClassVar[int]
    LEASE_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    lease_id: str
    owner_instance_id: str
    fencing_token: int
    acquired_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    heartbeat_at: _timestamp_pb2.Timestamp
    lease_policy_ref: _common_pb2.ContractReference
    def __init__(self, lease_id: _Optional[str] = ..., owner_instance_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., acquired_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., heartbeat_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., lease_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class CheckpointReference(_message.Message):
    __slots__ = ("checkpoint_id", "digest_sha256", "attempt_id", "attempt_revision", "fencing_token", "last_collaboration_sequence", "harness_checkpoint_ref", "harness_session_ref", "workspace_snapshot_ref", "side_effect_ledger_ref", "budget_receipt_ref", "recovery_class", "created_at", "task_id", "work_revision", "run_id", "step_id")
    CHECKPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_REVISION_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    LAST_COLLABORATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    HARNESS_CHECKPOINT_REF_FIELD_NUMBER: _ClassVar[int]
    HARNESS_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_SNAPSHOT_REF_FIELD_NUMBER: _ClassVar[int]
    SIDE_EFFECT_LEDGER_REF_FIELD_NUMBER: _ClassVar[int]
    BUDGET_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_CLASS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    checkpoint_id: str
    digest_sha256: str
    attempt_id: str
    attempt_revision: int
    fencing_token: int
    last_collaboration_sequence: int
    harness_checkpoint_ref: str
    harness_session_ref: str
    workspace_snapshot_ref: str
    side_effect_ledger_ref: str
    budget_receipt_ref: str
    recovery_class: RecoveryClass
    created_at: _timestamp_pb2.Timestamp
    task_id: str
    work_revision: int
    run_id: str
    step_id: str
    def __init__(self, checkpoint_id: _Optional[str] = ..., digest_sha256: _Optional[str] = ..., attempt_id: _Optional[str] = ..., attempt_revision: _Optional[int] = ..., fencing_token: _Optional[int] = ..., last_collaboration_sequence: _Optional[int] = ..., harness_checkpoint_ref: _Optional[str] = ..., harness_session_ref: _Optional[str] = ..., workspace_snapshot_ref: _Optional[str] = ..., side_effect_ledger_ref: _Optional[str] = ..., budget_receipt_ref: _Optional[str] = ..., recovery_class: _Optional[_Union[RecoveryClass, str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., task_id: _Optional[str] = ..., work_revision: _Optional[int] = ..., run_id: _Optional[str] = ..., step_id: _Optional[str] = ...) -> None: ...

class StepPlan(_message.Message):
    __slots__ = ("step_id", "step_kind", "depends_on_step_ids", "input_bundle_ref", "expected_output_contract_ref", "required_capability_profile_ref", "max_attempts")
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_KIND_FIELD_NUMBER: _ClassVar[int]
    DEPENDS_ON_STEP_IDS_FIELD_NUMBER: _ClassVar[int]
    INPUT_BUNDLE_REF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_OUTPUT_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CAPABILITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    MAX_ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    step_id: str
    step_kind: str
    depends_on_step_ids: _containers.RepeatedScalarFieldContainer[str]
    input_bundle_ref: str
    expected_output_contract_ref: _common_pb2.ContractReference
    required_capability_profile_ref: _common_pb2.ContractReference
    max_attempts: int
    def __init__(self, step_id: _Optional[str] = ..., step_kind: _Optional[str] = ..., depends_on_step_ids: _Optional[_Iterable[str]] = ..., input_bundle_ref: _Optional[str] = ..., expected_output_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., required_capability_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., max_attempts: _Optional[int] = ...) -> None: ...

class RunPlan(_message.Message):
    __slots__ = ("plan_id", "digest_sha256", "max_active_attempts", "steps", "budget_profile_ref")
    PLAN_ID_FIELD_NUMBER: _ClassVar[int]
    DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    MAX_ACTIVE_ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    BUDGET_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    plan_id: str
    digest_sha256: str
    max_active_attempts: int
    steps: _containers.RepeatedCompositeFieldContainer[StepPlan]
    budget_profile_ref: _common_pb2.ContractReference
    def __init__(self, plan_id: _Optional[str] = ..., digest_sha256: _Optional[str] = ..., max_active_attempts: _Optional[int] = ..., steps: _Optional[_Iterable[_Union[StepPlan, _Mapping]]] = ..., budget_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class RunSnapshot(_message.Message):
    __slots__ = ("run_id", "revision", "task_id", "task_revision_at_creation", "work_revision", "status", "plan", "step_ids", "hold_reason_code", "created_at", "updated_at")
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_REVISION_AT_CREATION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    STEP_IDS_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    revision: int
    task_id: str
    task_revision_at_creation: int
    work_revision: int
    status: RunStatus
    plan: RunPlan
    step_ids: _containers.RepeatedScalarFieldContainer[str]
    hold_reason_code: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, run_id: _Optional[str] = ..., revision: _Optional[int] = ..., task_id: _Optional[str] = ..., task_revision_at_creation: _Optional[int] = ..., work_revision: _Optional[int] = ..., status: _Optional[_Union[RunStatus, str]] = ..., plan: _Optional[_Union[RunPlan, _Mapping]] = ..., step_ids: _Optional[_Iterable[str]] = ..., hold_reason_code: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class StepSnapshot(_message.Message):
    __slots__ = ("step_id", "run_id", "revision", "status", "attempt_ids", "current_attempt_id", "artifact_set_id", "return_handoff_id", "hold_reason_code", "updated_at")
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_IDS_FIELD_NUMBER: _ClassVar[int]
    CURRENT_ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    step_id: str
    run_id: str
    revision: int
    status: StepStatus
    attempt_ids: _containers.RepeatedScalarFieldContainer[str]
    current_attempt_id: str
    artifact_set_id: str
    return_handoff_id: str
    hold_reason_code: str
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, step_id: _Optional[str] = ..., run_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[StepStatus, str]] = ..., attempt_ids: _Optional[_Iterable[str]] = ..., current_attempt_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ..., return_handoff_id: _Optional[str] = ..., hold_reason_code: _Optional[str] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AttemptSnapshot(_message.Message):
    __slots__ = ("attempt_id", "run_id", "step_id", "revision", "attempt_number", "status", "harness_id", "capability_profile_ref", "workspace_ref", "dispatch_id", "dispatch_fingerprint", "harness_session_ref", "last_harness_sequence", "lease", "latest_checkpoint_id", "recovery_class", "hold_reason_code", "created_at", "updated_at")
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_NUMBER_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    HARNESS_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_REF_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    HARNESS_SESSION_REF_FIELD_NUMBER: _ClassVar[int]
    LAST_HARNESS_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    LEASE_FIELD_NUMBER: _ClassVar[int]
    LATEST_CHECKPOINT_ID_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_CLASS_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    attempt_id: str
    run_id: str
    step_id: str
    revision: int
    attempt_number: int
    status: AttemptStatus
    harness_id: str
    capability_profile_ref: _common_pb2.ContractReference
    workspace_ref: str
    dispatch_id: str
    dispatch_fingerprint: str
    harness_session_ref: str
    last_harness_sequence: int
    lease: Lease
    latest_checkpoint_id: str
    recovery_class: RecoveryClass
    hold_reason_code: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, attempt_id: _Optional[str] = ..., run_id: _Optional[str] = ..., step_id: _Optional[str] = ..., revision: _Optional[int] = ..., attempt_number: _Optional[int] = ..., status: _Optional[_Union[AttemptStatus, str]] = ..., harness_id: _Optional[str] = ..., capability_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., workspace_ref: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., dispatch_fingerprint: _Optional[str] = ..., harness_session_ref: _Optional[str] = ..., last_harness_sequence: _Optional[int] = ..., lease: _Optional[_Union[Lease, _Mapping]] = ..., latest_checkpoint_id: _Optional[str] = ..., recovery_class: _Optional[_Union[RecoveryClass, str]] = ..., hold_reason_code: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CollaborationSnapshot(_message.Message):
    __slots__ = ("run", "steps", "attempts")
    RUN_FIELD_NUMBER: _ClassVar[int]
    STEPS_FIELD_NUMBER: _ClassVar[int]
    ATTEMPTS_FIELD_NUMBER: _ClassVar[int]
    run: RunSnapshot
    steps: _containers.RepeatedCompositeFieldContainer[StepSnapshot]
    attempts: _containers.RepeatedCompositeFieldContainer[AttemptSnapshot]
    def __init__(self, run: _Optional[_Union[RunSnapshot, _Mapping]] = ..., steps: _Optional[_Iterable[_Union[StepSnapshot, _Mapping]]] = ..., attempts: _Optional[_Iterable[_Union[AttemptSnapshot, _Mapping]]] = ...) -> None: ...

class RunCommandBase(_message.Message):
    __slots__ = ("meta", "run_id", "expected_run_revision")
    META_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    run_id: str
    expected_run_revision: int
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ...) -> None: ...

class AttemptCommandBase(_message.Message):
    __slots__ = ("meta", "run_id", "expected_run_revision", "step_id", "expected_step_revision", "attempt_id", "expected_attempt_revision")
    META_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_ATTEMPT_REVISION_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    run_id: str
    expected_run_revision: int
    step_id: str
    expected_step_revision: int
    attempt_id: str
    expected_attempt_revision: int
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., step_id: _Optional[str] = ..., expected_step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., expected_attempt_revision: _Optional[int] = ...) -> None: ...

class CreateRunCommand(_message.Message):
    __slots__ = ("meta", "run_id", "task_id", "task_revision", "work_revision", "plan")
    META_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    meta: _common_pb2.CommandMetadata
    run_id: str
    task_id: str
    task_revision: int
    work_revision: int
    plan: RunPlan
    def __init__(self, meta: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., run_id: _Optional[str] = ..., task_id: _Optional[str] = ..., task_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., plan: _Optional[_Union[RunPlan, _Mapping]] = ...) -> None: ...

class ActivateRunCommand(_message.Message):
    __slots__ = ("base", "confirmed_task_revision")
    BASE_FIELD_NUMBER: _ClassVar[int]
    CONFIRMED_TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    base: RunCommandBase
    confirmed_task_revision: int
    def __init__(self, base: _Optional[_Union[RunCommandBase, _Mapping]] = ..., confirmed_task_revision: _Optional[int] = ...) -> None: ...

class CreateAttemptCommand(_message.Message):
    __slots__ = ("base", "step_id", "expected_step_revision", "attempt_id", "harness_id", "capability_profile_ref", "workspace_ref")
    BASE_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    HARNESS_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_REF_FIELD_NUMBER: _ClassVar[int]
    base: RunCommandBase
    step_id: str
    expected_step_revision: int
    attempt_id: str
    harness_id: str
    capability_profile_ref: _common_pb2.ContractReference
    workspace_ref: str
    def __init__(self, base: _Optional[_Union[RunCommandBase, _Mapping]] = ..., step_id: _Optional[str] = ..., expected_step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., harness_id: _Optional[str] = ..., capability_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., workspace_ref: _Optional[str] = ...) -> None: ...

class AcquireAttemptLeaseCommand(_message.Message):
    __slots__ = ("base", "owner_instance_id", "lease_policy_ref")
    BASE_FIELD_NUMBER: _ClassVar[int]
    OWNER_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    LEASE_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    owner_instance_id: str
    lease_policy_ref: _common_pb2.ContractReference
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., owner_instance_id: _Optional[str] = ..., lease_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class RenewAttemptLeaseCommand(_message.Message):
    __slots__ = ("base", "lease_id", "fencing_token")
    BASE_FIELD_NUMBER: _ClassVar[int]
    LEASE_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    lease_id: str
    fencing_token: int
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., lease_id: _Optional[str] = ..., fencing_token: _Optional[int] = ...) -> None: ...

class RecordDispatchIntentCommand(_message.Message):
    __slots__ = ("base", "lease_id", "fencing_token", "dispatch_id", "dispatch_fingerprint")
    BASE_FIELD_NUMBER: _ClassVar[int]
    LEASE_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    lease_id: str
    fencing_token: int
    dispatch_id: str
    dispatch_fingerprint: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., lease_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., dispatch_id: _Optional[str] = ..., dispatch_fingerprint: _Optional[str] = ...) -> None: ...

class RecordDeliveryReceiptCommand(_message.Message):
    __slots__ = ("base", "dispatch_id", "fencing_token", "delivery_receipt_id", "receipt_digest_sha256")
    BASE_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    dispatch_id: str
    fencing_token: int
    delivery_receipt_id: str
    receipt_digest_sha256: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., delivery_receipt_id: _Optional[str] = ..., receipt_digest_sha256: _Optional[str] = ...) -> None: ...

class RecordHarnessAckCommand(_message.Message):
    __slots__ = ("base", "dispatch_id", "fencing_token", "harness_sequence", "ack_receipt_id", "receipt_digest_sha256")
    BASE_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    HARNESS_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    ACK_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    dispatch_id: str
    fencing_token: int
    harness_sequence: int
    ack_receipt_id: str
    receipt_digest_sha256: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., harness_sequence: _Optional[int] = ..., ack_receipt_id: _Optional[str] = ..., receipt_digest_sha256: _Optional[str] = ...) -> None: ...

class RecordRunningObservationCommand(_message.Message):
    __slots__ = ("base", "fencing_token", "harness_sequence", "lifecycle_event_id", "event_digest_sha256")
    BASE_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    HARNESS_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    EVENT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    fencing_token: int
    harness_sequence: int
    lifecycle_event_id: str
    event_digest_sha256: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., fencing_token: _Optional[int] = ..., harness_sequence: _Optional[int] = ..., lifecycle_event_id: _Optional[str] = ..., event_digest_sha256: _Optional[str] = ...) -> None: ...

class RecordAttemptReturnCommand(_message.Message):
    __slots__ = ("base", "fencing_token", "harness_sequence", "artifact_return_receipt_id", "receipt_digest_sha256")
    BASE_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    HARNESS_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_RETURN_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    RECEIPT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    fencing_token: int
    harness_sequence: int
    artifact_return_receipt_id: str
    receipt_digest_sha256: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., fencing_token: _Optional[int] = ..., harness_sequence: _Optional[int] = ..., artifact_return_receipt_id: _Optional[str] = ..., receipt_digest_sha256: _Optional[str] = ...) -> None: ...

class MarkAttemptOutcomeUnknownCommand(_message.Message):
    __slots__ = ("base", "reason_code", "uncertainty_evidence_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    UNCERTAINTY_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    reason_code: str
    uncertainty_evidence_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., reason_code: _Optional[str] = ..., uncertainty_evidence_id: _Optional[str] = ...) -> None: ...

class BeginAttemptReconciliationCommand(_message.Message):
    __slots__ = ("base", "reconciliation_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    RECONCILIATION_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    reconciliation_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., reconciliation_id: _Optional[str] = ...) -> None: ...

class RecordAttemptReconciliationCommand(_message.Message):
    __slots__ = ("base", "reconciliation_id", "disposition", "evidence_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    RECONCILIATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    reconciliation_id: str
    disposition: ReconciliationDisposition
    evidence_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., reconciliation_id: _Optional[str] = ..., disposition: _Optional[_Union[ReconciliationDisposition, str]] = ..., evidence_id: _Optional[str] = ...) -> None: ...

class RecordCheckpointCommand(_message.Message):
    __slots__ = ("base", "checkpoint")
    BASE_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    checkpoint: CheckpointReference
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., checkpoint: _Optional[_Union[CheckpointReference, _Mapping]] = ...) -> None: ...

class RequestAttemptCancellationCommand(_message.Message):
    __slots__ = ("base", "task_cancellation_request_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    TASK_CANCELLATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    task_cancellation_request_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., task_cancellation_request_id: _Optional[str] = ...) -> None: ...

class RecordAttemptCancellationOutcomeCommand(_message.Message):
    __slots__ = ("base", "disposition", "cancellation_receipt_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    disposition: AttemptCancellationDisposition
    cancellation_receipt_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., disposition: _Optional[_Union[AttemptCancellationDisposition, str]] = ..., cancellation_receipt_id: _Optional[str] = ...) -> None: ...

class HoldAttemptCommand(_message.Message):
    __slots__ = ("base", "hold_reason_code", "evidence_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    hold_reason_code: str
    evidence_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., hold_reason_code: _Optional[str] = ..., evidence_id: _Optional[str] = ...) -> None: ...

class ResumeAttemptCommand(_message.Message):
    __slots__ = ("base", "recovery_evidence_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_EVIDENCE_ID_FIELD_NUMBER: _ClassVar[int]
    base: AttemptCommandBase
    recovery_evidence_id: str
    def __init__(self, base: _Optional[_Union[AttemptCommandBase, _Mapping]] = ..., recovery_evidence_id: _Optional[str] = ...) -> None: ...

class CommitStepReturnCommand(_message.Message):
    __slots__ = ("base", "step_id", "expected_step_revision", "attempt_id", "artifact_set_id", "return_handoff_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    RETURN_HANDOFF_ID_FIELD_NUMBER: _ClassVar[int]
    base: RunCommandBase
    step_id: str
    expected_step_revision: int
    attempt_id: str
    artifact_set_id: str
    return_handoff_id: str
    def __init__(self, base: _Optional[_Union[RunCommandBase, _Mapping]] = ..., step_id: _Optional[str] = ..., expected_step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., artifact_set_id: _Optional[str] = ..., return_handoff_id: _Optional[str] = ...) -> None: ...

class SupersedeRunCommand(_message.Message):
    __slots__ = ("base", "replacement_run_id", "reason_code")
    BASE_FIELD_NUMBER: _ClassVar[int]
    REPLACEMENT_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    base: RunCommandBase
    replacement_run_id: str
    reason_code: str
    def __init__(self, base: _Optional[_Union[RunCommandBase, _Mapping]] = ..., replacement_run_id: _Optional[str] = ..., reason_code: _Optional[str] = ...) -> None: ...

class ExpireRunCommand(_message.Message):
    __slots__ = ("base", "policy_decision_id")
    BASE_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    base: RunCommandBase
    policy_decision_id: str
    def __init__(self, base: _Optional[_Union[RunCommandBase, _Mapping]] = ..., policy_decision_id: _Optional[str] = ...) -> None: ...

class CollaborationCommand(_message.Message):
    __slots__ = ("create_run", "activate_run", "create_attempt", "acquire_attempt_lease", "renew_attempt_lease", "record_dispatch_intent", "record_delivery_receipt", "record_harness_ack", "record_running_observation", "record_attempt_return", "mark_attempt_outcome_unknown", "begin_attempt_reconciliation", "record_attempt_reconciliation", "record_checkpoint", "request_attempt_cancellation", "record_attempt_cancellation_outcome", "hold_attempt", "resume_attempt", "commit_step_return", "supersede_run", "expire_run")
    CREATE_RUN_FIELD_NUMBER: _ClassVar[int]
    ACTIVATE_RUN_FIELD_NUMBER: _ClassVar[int]
    CREATE_ATTEMPT_FIELD_NUMBER: _ClassVar[int]
    ACQUIRE_ATTEMPT_LEASE_FIELD_NUMBER: _ClassVar[int]
    RENEW_ATTEMPT_LEASE_FIELD_NUMBER: _ClassVar[int]
    RECORD_DISPATCH_INTENT_FIELD_NUMBER: _ClassVar[int]
    RECORD_DELIVERY_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    RECORD_HARNESS_ACK_FIELD_NUMBER: _ClassVar[int]
    RECORD_RUNNING_OBSERVATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_ATTEMPT_RETURN_FIELD_NUMBER: _ClassVar[int]
    MARK_ATTEMPT_OUTCOME_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    BEGIN_ATTEMPT_RECONCILIATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_ATTEMPT_RECONCILIATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ATTEMPT_CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_ATTEMPT_CANCELLATION_OUTCOME_FIELD_NUMBER: _ClassVar[int]
    HOLD_ATTEMPT_FIELD_NUMBER: _ClassVar[int]
    RESUME_ATTEMPT_FIELD_NUMBER: _ClassVar[int]
    COMMIT_STEP_RETURN_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDE_RUN_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_RUN_FIELD_NUMBER: _ClassVar[int]
    create_run: CreateRunCommand
    activate_run: ActivateRunCommand
    create_attempt: CreateAttemptCommand
    acquire_attempt_lease: AcquireAttemptLeaseCommand
    renew_attempt_lease: RenewAttemptLeaseCommand
    record_dispatch_intent: RecordDispatchIntentCommand
    record_delivery_receipt: RecordDeliveryReceiptCommand
    record_harness_ack: RecordHarnessAckCommand
    record_running_observation: RecordRunningObservationCommand
    record_attempt_return: RecordAttemptReturnCommand
    mark_attempt_outcome_unknown: MarkAttemptOutcomeUnknownCommand
    begin_attempt_reconciliation: BeginAttemptReconciliationCommand
    record_attempt_reconciliation: RecordAttemptReconciliationCommand
    record_checkpoint: RecordCheckpointCommand
    request_attempt_cancellation: RequestAttemptCancellationCommand
    record_attempt_cancellation_outcome: RecordAttemptCancellationOutcomeCommand
    hold_attempt: HoldAttemptCommand
    resume_attempt: ResumeAttemptCommand
    commit_step_return: CommitStepReturnCommand
    supersede_run: SupersedeRunCommand
    expire_run: ExpireRunCommand
    def __init__(self, create_run: _Optional[_Union[CreateRunCommand, _Mapping]] = ..., activate_run: _Optional[_Union[ActivateRunCommand, _Mapping]] = ..., create_attempt: _Optional[_Union[CreateAttemptCommand, _Mapping]] = ..., acquire_attempt_lease: _Optional[_Union[AcquireAttemptLeaseCommand, _Mapping]] = ..., renew_attempt_lease: _Optional[_Union[RenewAttemptLeaseCommand, _Mapping]] = ..., record_dispatch_intent: _Optional[_Union[RecordDispatchIntentCommand, _Mapping]] = ..., record_delivery_receipt: _Optional[_Union[RecordDeliveryReceiptCommand, _Mapping]] = ..., record_harness_ack: _Optional[_Union[RecordHarnessAckCommand, _Mapping]] = ..., record_running_observation: _Optional[_Union[RecordRunningObservationCommand, _Mapping]] = ..., record_attempt_return: _Optional[_Union[RecordAttemptReturnCommand, _Mapping]] = ..., mark_attempt_outcome_unknown: _Optional[_Union[MarkAttemptOutcomeUnknownCommand, _Mapping]] = ..., begin_attempt_reconciliation: _Optional[_Union[BeginAttemptReconciliationCommand, _Mapping]] = ..., record_attempt_reconciliation: _Optional[_Union[RecordAttemptReconciliationCommand, _Mapping]] = ..., record_checkpoint: _Optional[_Union[RecordCheckpointCommand, _Mapping]] = ..., request_attempt_cancellation: _Optional[_Union[RequestAttemptCancellationCommand, _Mapping]] = ..., record_attempt_cancellation_outcome: _Optional[_Union[RecordAttemptCancellationOutcomeCommand, _Mapping]] = ..., hold_attempt: _Optional[_Union[HoldAttemptCommand, _Mapping]] = ..., resume_attempt: _Optional[_Union[ResumeAttemptCommand, _Mapping]] = ..., commit_step_return: _Optional[_Union[CommitStepReturnCommand, _Mapping]] = ..., supersede_run: _Optional[_Union[SupersedeRunCommand, _Mapping]] = ..., expire_run: _Optional[_Union[ExpireRunCommand, _Mapping]] = ...) -> None: ...

class CollaborationEvent(_message.Message):
    __slots__ = ("event_id", "command_id", "kind", "run_id", "expected_run_revision", "resulting_run_revision", "step_id", "resulting_step_revision", "attempt_id", "resulting_attempt_revision", "authenticated_principal_id", "authority_ref", "idempotency_key", "request_digest_sha256", "correlation_id", "causation_id", "evidence_refs", "occurred_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    STEP_ID_FIELD_NUMBER: _ClassVar[int]
    RESULTING_STEP_REVISION_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    RESULTING_ATTEMPT_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAUSATION_ID_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    command_id: str
    kind: CollaborationEventKind
    run_id: str
    expected_run_revision: int
    resulting_run_revision: int
    step_id: str
    resulting_step_revision: int
    attempt_id: str
    resulting_attempt_revision: int
    authenticated_principal_id: str
    authority_ref: str
    idempotency_key: str
    request_digest_sha256: str
    correlation_id: str
    causation_id: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    occurred_at: _timestamp_pb2.Timestamp
    def __init__(self, event_id: _Optional[str] = ..., command_id: _Optional[str] = ..., kind: _Optional[_Union[CollaborationEventKind, str]] = ..., run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., resulting_run_revision: _Optional[int] = ..., step_id: _Optional[str] = ..., resulting_step_revision: _Optional[int] = ..., attempt_id: _Optional[str] = ..., resulting_attempt_revision: _Optional[int] = ..., authenticated_principal_id: _Optional[str] = ..., authority_ref: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., correlation_id: _Optional[str] = ..., causation_id: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., occurred_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CollaborationError(_message.Message):
    __slots__ = ("code", "safe_detail_code", "retryable", "recovery_required", "current_run_revision", "current_entity_revision", "audit_ref")
    CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_DETAIL_CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    CURRENT_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_ENTITY_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUDIT_REF_FIELD_NUMBER: _ClassVar[int]
    code: CollaborationErrorCode
    safe_detail_code: str
    retryable: bool
    recovery_required: bool
    current_run_revision: int
    current_entity_revision: int
    audit_ref: str
    def __init__(self, code: _Optional[_Union[CollaborationErrorCode, str]] = ..., safe_detail_code: _Optional[str] = ..., retryable: _Optional[bool] = ..., recovery_required: _Optional[bool] = ..., current_run_revision: _Optional[int] = ..., current_entity_revision: _Optional[int] = ..., audit_ref: _Optional[str] = ...) -> None: ...

class CollaborationCommandResult(_message.Message):
    __slots__ = ("replayed", "snapshot", "error", "committed_event")
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_EVENT_FIELD_NUMBER: _ClassVar[int]
    replayed: bool
    snapshot: CollaborationSnapshot
    error: CollaborationError
    committed_event: CollaborationEvent
    def __init__(self, replayed: _Optional[bool] = ..., snapshot: _Optional[_Union[CollaborationSnapshot, _Mapping]] = ..., error: _Optional[_Union[CollaborationError, _Mapping]] = ..., committed_event: _Optional[_Union[CollaborationEvent, _Mapping]] = ...) -> None: ...

class GetCollaborationRequest(_message.Message):
    __slots__ = ("run_id",)
    RUN_ID_FIELD_NUMBER: _ClassVar[int]
    run_id: str
    def __init__(self, run_id: _Optional[str] = ...) -> None: ...

class GetCollaborationResponse(_message.Message):
    __slots__ = ("snapshot", "error")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    snapshot: CollaborationSnapshot
    error: CollaborationError
    def __init__(self, snapshot: _Optional[_Union[CollaborationSnapshot, _Mapping]] = ..., error: _Optional[_Union[CollaborationError, _Mapping]] = ...) -> None: ...
