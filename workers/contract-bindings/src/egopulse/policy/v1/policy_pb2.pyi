import datetime

from egopulse.common.v1 import common_pb2 as _common_pb2
from egopulse.harness.v1 import harness_pb2 as _harness_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HarnessApprovalDecisionStateKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HARNESS_APPROVAL_DECISION_STATE_KIND_UNSPECIFIED: _ClassVar[HarnessApprovalDecisionStateKind]
    HARNESS_APPROVAL_DECISION_STATE_KIND_ISSUED: _ClassVar[HarnessApprovalDecisionStateKind]
    HARNESS_APPROVAL_DECISION_STATE_KIND_CONSUMED: _ClassVar[HarnessApprovalDecisionStateKind]
    HARNESS_APPROVAL_DECISION_STATE_KIND_REVOKED: _ClassVar[HarnessApprovalDecisionStateKind]
    HARNESS_APPROVAL_DECISION_STATE_KIND_EXPIRED: _ClassVar[HarnessApprovalDecisionStateKind]
    HARNESS_APPROVAL_DECISION_STATE_KIND_SUPERSEDED: _ClassVar[HarnessApprovalDecisionStateKind]

class PolicyDecisionEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_DECISION_EVENT_KIND_UNSPECIFIED: _ClassVar[PolicyDecisionEventKind]
    POLICY_DECISION_EVENT_KIND_ISSUED: _ClassVar[PolicyDecisionEventKind]
    POLICY_DECISION_EVENT_KIND_CONSUMED: _ClassVar[PolicyDecisionEventKind]
    POLICY_DECISION_EVENT_KIND_REVOKED: _ClassVar[PolicyDecisionEventKind]
    POLICY_DECISION_EVENT_KIND_EXPIRED: _ClassVar[PolicyDecisionEventKind]
    POLICY_DECISION_EVENT_KIND_SUPERSEDED: _ClassVar[PolicyDecisionEventKind]

class PolicyDecisionErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_DECISION_ERROR_CODE_UNSPECIFIED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_UNAUTHENTICATED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_PERMISSION_DENIED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_NOT_FOUND: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_REVISION_CONFLICT: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_REQUEST_MISMATCH: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_FENCING_REJECTED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_POLICY_DENIED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_ALREADY_CONSUMED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_EXPIRED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_REVOKED: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[PolicyDecisionErrorCode]
    POLICY_DECISION_ERROR_CODE_DELIVERY_RECEIPT_INVALID: _ClassVar[PolicyDecisionErrorCode]
HARNESS_APPROVAL_DECISION_STATE_KIND_UNSPECIFIED: HarnessApprovalDecisionStateKind
HARNESS_APPROVAL_DECISION_STATE_KIND_ISSUED: HarnessApprovalDecisionStateKind
HARNESS_APPROVAL_DECISION_STATE_KIND_CONSUMED: HarnessApprovalDecisionStateKind
HARNESS_APPROVAL_DECISION_STATE_KIND_REVOKED: HarnessApprovalDecisionStateKind
HARNESS_APPROVAL_DECISION_STATE_KIND_EXPIRED: HarnessApprovalDecisionStateKind
HARNESS_APPROVAL_DECISION_STATE_KIND_SUPERSEDED: HarnessApprovalDecisionStateKind
POLICY_DECISION_EVENT_KIND_UNSPECIFIED: PolicyDecisionEventKind
POLICY_DECISION_EVENT_KIND_ISSUED: PolicyDecisionEventKind
POLICY_DECISION_EVENT_KIND_CONSUMED: PolicyDecisionEventKind
POLICY_DECISION_EVENT_KIND_REVOKED: PolicyDecisionEventKind
POLICY_DECISION_EVENT_KIND_EXPIRED: PolicyDecisionEventKind
POLICY_DECISION_EVENT_KIND_SUPERSEDED: PolicyDecisionEventKind
POLICY_DECISION_ERROR_CODE_UNSPECIFIED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_INVALID_ARGUMENT: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_UNAUTHENTICATED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_PERMISSION_DENIED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_NOT_FOUND: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_REVISION_CONFLICT: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_IDEMPOTENCY_CONFLICT: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_REQUEST_MISMATCH: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_FENCING_REJECTED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_POLICY_DENIED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_ALREADY_CONSUMED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_EXPIRED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_REVOKED: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_INTEGRITY_FAILURE: PolicyDecisionErrorCode
POLICY_DECISION_ERROR_CODE_DELIVERY_RECEIPT_INVALID: PolicyDecisionErrorCode

class HarnessApprovalRequestBinding(_message.Message):
    __slots__ = ("adapter_id", "attempt_id", "dispatch_id", "fencing_token", "approval_request_id", "kind", "action_digest_sha256", "requested_scope_ref", "native_routing_ref", "request_observation_id", "request_observation_sequence", "request_lifecycle", "request_revision")
    ADAPTER_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ACTION_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_SCOPE_REF_FIELD_NUMBER: _ClassVar[int]
    NATIVE_ROUTING_REF_FIELD_NUMBER: _ClassVar[int]
    REQUEST_OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_OBSERVATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_REVISION_FIELD_NUMBER: _ClassVar[int]
    adapter_id: str
    attempt_id: str
    dispatch_id: str
    fencing_token: int
    approval_request_id: str
    kind: _harness_pb2.ApprovalKind
    action_digest_sha256: str
    requested_scope_ref: str
    native_routing_ref: str
    request_observation_id: str
    request_observation_sequence: int
    request_lifecycle: _harness_pb2.ApprovalRequestLifecycleKind
    request_revision: int
    def __init__(self, adapter_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., dispatch_id: _Optional[str] = ..., fencing_token: _Optional[int] = ..., approval_request_id: _Optional[str] = ..., kind: _Optional[_Union[_harness_pb2.ApprovalKind, str]] = ..., action_digest_sha256: _Optional[str] = ..., requested_scope_ref: _Optional[str] = ..., native_routing_ref: _Optional[str] = ..., request_observation_id: _Optional[str] = ..., request_observation_sequence: _Optional[int] = ..., request_lifecycle: _Optional[_Union[_harness_pb2.ApprovalRequestLifecycleKind, str]] = ..., request_revision: _Optional[int] = ...) -> None: ...

class PolicyAuthorityProof(_message.Message):
    __slots__ = ("authenticated_principal_id", "authentication_context_ref", "authorization_policy_ref", "authorization_decision_id", "verified_at")
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_CONTEXT_REF_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZATION_DECISION_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_AT_FIELD_NUMBER: _ClassVar[int]
    authenticated_principal_id: str
    authentication_context_ref: str
    authorization_policy_ref: _common_pb2.ContractReference
    authorization_decision_id: str
    verified_at: _timestamp_pb2.Timestamp
    def __init__(self, authenticated_principal_id: _Optional[str] = ..., authentication_context_ref: _Optional[str] = ..., authorization_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., authorization_decision_id: _Optional[str] = ..., verified_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HarnessApprovalDecisionRecord(_message.Message):
    __slots__ = ("authority_decision_ref", "version", "request", "decision", "reason_code", "authority_proof", "issued_at", "expires_at", "canonical_payload_digest_sha256", "supersedes_authority_decision_ref")
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_PROOF_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_PAYLOAD_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    authority_decision_ref: str
    version: int
    request: HarnessApprovalRequestBinding
    decision: _harness_pb2.ApprovalDecision
    reason_code: str
    authority_proof: PolicyAuthorityProof
    issued_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    canonical_payload_digest_sha256: str
    supersedes_authority_decision_ref: str
    def __init__(self, authority_decision_ref: _Optional[str] = ..., version: _Optional[int] = ..., request: _Optional[_Union[HarnessApprovalRequestBinding, _Mapping]] = ..., decision: _Optional[_Union[_harness_pb2.ApprovalDecision, str]] = ..., reason_code: _Optional[str] = ..., authority_proof: _Optional[_Union[PolicyAuthorityProof, _Mapping]] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., canonical_payload_digest_sha256: _Optional[str] = ..., supersedes_authority_decision_ref: _Optional[str] = ...) -> None: ...

class HarnessApprovalDecisionState(_message.Message):
    __slots__ = ("authority_decision_ref", "revision", "state", "consumption_receipt_id", "superseded_by_authority_decision_ref", "terminal_reason_code", "updated_at")
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CONSUMPTION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDED_BY_AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    TERMINAL_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    authority_decision_ref: str
    revision: int
    state: HarnessApprovalDecisionStateKind
    consumption_receipt_id: str
    superseded_by_authority_decision_ref: str
    terminal_reason_code: str
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, authority_decision_ref: _Optional[str] = ..., revision: _Optional[int] = ..., state: _Optional[_Union[HarnessApprovalDecisionStateKind, str]] = ..., consumption_receipt_id: _Optional[str] = ..., superseded_by_authority_decision_ref: _Optional[str] = ..., terminal_reason_code: _Optional[str] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class HarnessApprovalConsumptionReceipt(_message.Message):
    __slots__ = ("consumption_receipt_id", "authority_decision_ref", "adapter_receipt", "consumed_at")
    CONSUMPTION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_AT_FIELD_NUMBER: _ClassVar[int]
    consumption_receipt_id: str
    authority_decision_ref: str
    adapter_receipt: _harness_pb2.ApprovalDecisionReceipt
    consumed_at: _timestamp_pb2.Timestamp
    def __init__(self, consumption_receipt_id: _Optional[str] = ..., authority_decision_ref: _Optional[str] = ..., adapter_receipt: _Optional[_Union[_harness_pb2.ApprovalDecisionReceipt, _Mapping]] = ..., consumed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class IssueHarnessApprovalDecisionCommand(_message.Message):
    __slots__ = ("metadata", "approval_request_id", "expected_action_digest_sha256", "expected_request_observation_id", "expected_request_observation_sequence", "decision", "reason_code", "confirmation_proof_ref", "expected_request_revision")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_ACTION_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REQUEST_OBSERVATION_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REQUEST_OBSERVATION_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REQUEST_REVISION_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    approval_request_id: str
    expected_action_digest_sha256: str
    expected_request_observation_id: str
    expected_request_observation_sequence: int
    decision: _harness_pb2.ApprovalDecision
    reason_code: str
    confirmation_proof_ref: str
    expected_request_revision: int
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., approval_request_id: _Optional[str] = ..., expected_action_digest_sha256: _Optional[str] = ..., expected_request_observation_id: _Optional[str] = ..., expected_request_observation_sequence: _Optional[int] = ..., decision: _Optional[_Union[_harness_pb2.ApprovalDecision, str]] = ..., reason_code: _Optional[str] = ..., confirmation_proof_ref: _Optional[str] = ..., expected_request_revision: _Optional[int] = ...) -> None: ...

class ConsumeHarnessApprovalDecisionCommand(_message.Message):
    __slots__ = ("metadata", "authority_decision_ref", "expected_state_revision", "adapter_receipt")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    authority_decision_ref: str
    expected_state_revision: int
    adapter_receipt: _harness_pb2.ApprovalDecisionReceipt
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., authority_decision_ref: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., adapter_receipt: _Optional[_Union[_harness_pb2.ApprovalDecisionReceipt, _Mapping]] = ...) -> None: ...

class RevokeHarnessApprovalDecisionCommand(_message.Message):
    __slots__ = ("metadata", "authority_decision_ref", "expected_state_revision", "reason_code", "confirmation_proof_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    authority_decision_ref: str
    expected_state_revision: int
    reason_code: str
    confirmation_proof_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., authority_decision_ref: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., reason_code: _Optional[str] = ..., confirmation_proof_ref: _Optional[str] = ...) -> None: ...

class ExpireHarnessApprovalDecisionCommand(_message.Message):
    __slots__ = ("metadata", "authority_decision_ref", "expected_state_revision", "policy_evaluation_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_EVALUATION_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    authority_decision_ref: str
    expected_state_revision: int
    policy_evaluation_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., authority_decision_ref: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., policy_evaluation_ref: _Optional[str] = ...) -> None: ...

class PolicyDecisionCommand(_message.Message):
    __slots__ = ("issue_harness_approval_decision", "consume_harness_approval_decision", "revoke_harness_approval_decision", "expire_harness_approval_decision")
    ISSUE_HARNESS_APPROVAL_DECISION_FIELD_NUMBER: _ClassVar[int]
    CONSUME_HARNESS_APPROVAL_DECISION_FIELD_NUMBER: _ClassVar[int]
    REVOKE_HARNESS_APPROVAL_DECISION_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_HARNESS_APPROVAL_DECISION_FIELD_NUMBER: _ClassVar[int]
    issue_harness_approval_decision: IssueHarnessApprovalDecisionCommand
    consume_harness_approval_decision: ConsumeHarnessApprovalDecisionCommand
    revoke_harness_approval_decision: RevokeHarnessApprovalDecisionCommand
    expire_harness_approval_decision: ExpireHarnessApprovalDecisionCommand
    def __init__(self, issue_harness_approval_decision: _Optional[_Union[IssueHarnessApprovalDecisionCommand, _Mapping]] = ..., consume_harness_approval_decision: _Optional[_Union[ConsumeHarnessApprovalDecisionCommand, _Mapping]] = ..., revoke_harness_approval_decision: _Optional[_Union[RevokeHarnessApprovalDecisionCommand, _Mapping]] = ..., expire_harness_approval_decision: _Optional[_Union[ExpireHarnessApprovalDecisionCommand, _Mapping]] = ...) -> None: ...

class PolicyDecisionEvent(_message.Message):
    __slots__ = ("event_id", "kind", "authority_decision_ref", "resulting_state_revision", "authenticated_principal_id", "command_id", "evidence_refs", "committed_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    RESULTING_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    kind: PolicyDecisionEventKind
    authority_decision_ref: str
    resulting_state_revision: int
    authenticated_principal_id: str
    command_id: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    committed_at: _timestamp_pb2.Timestamp
    def __init__(self, event_id: _Optional[str] = ..., kind: _Optional[_Union[PolicyDecisionEventKind, str]] = ..., authority_decision_ref: _Optional[str] = ..., resulting_state_revision: _Optional[int] = ..., authenticated_principal_id: _Optional[str] = ..., command_id: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class PolicyDecisionCommandResult(_message.Message):
    __slots__ = ("committed", "replayed", "decision_record", "state", "consumption_receipt", "event", "error_code", "safe_error_fingerprint")
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    DECISION_RECORD_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CONSUMPTION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    committed: bool
    replayed: bool
    decision_record: HarnessApprovalDecisionRecord
    state: HarnessApprovalDecisionState
    consumption_receipt: HarnessApprovalConsumptionReceipt
    event: PolicyDecisionEvent
    error_code: PolicyDecisionErrorCode
    safe_error_fingerprint: str
    def __init__(self, committed: _Optional[bool] = ..., replayed: _Optional[bool] = ..., decision_record: _Optional[_Union[HarnessApprovalDecisionRecord, _Mapping]] = ..., state: _Optional[_Union[HarnessApprovalDecisionState, _Mapping]] = ..., consumption_receipt: _Optional[_Union[HarnessApprovalConsumptionReceipt, _Mapping]] = ..., event: _Optional[_Union[PolicyDecisionEvent, _Mapping]] = ..., error_code: _Optional[_Union[PolicyDecisionErrorCode, str]] = ..., safe_error_fingerprint: _Optional[str] = ...) -> None: ...
