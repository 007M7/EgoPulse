import datetime

from egopulse.artifact.v1 import artifact_pb2 as _artifact_pb2
from egopulse.common.v1 import common_pb2 as _common_pb2
from egopulse.verification.v1 import verification_pb2 as _verification_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FounderVerdictDecision(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FOUNDER_VERDICT_DECISION_UNSPECIFIED: _ClassVar[FounderVerdictDecision]
    FOUNDER_VERDICT_DECISION_ACCEPT: _ClassVar[FounderVerdictDecision]
    FOUNDER_VERDICT_DECISION_REWORK: _ClassVar[FounderVerdictDecision]
    FOUNDER_VERDICT_DECISION_REJECT: _ClassVar[FounderVerdictDecision]

class FounderVerdictStateKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FOUNDER_VERDICT_STATE_KIND_UNSPECIFIED: _ClassVar[FounderVerdictStateKind]
    FOUNDER_VERDICT_STATE_KIND_ISSUED: _ClassVar[FounderVerdictStateKind]
    FOUNDER_VERDICT_STATE_KIND_CONSUMED: _ClassVar[FounderVerdictStateKind]
    FOUNDER_VERDICT_STATE_KIND_REVOKED: _ClassVar[FounderVerdictStateKind]
    FOUNDER_VERDICT_STATE_KIND_EXPIRED: _ClassVar[FounderVerdictStateKind]
    FOUNDER_VERDICT_STATE_KIND_SUPERSEDED: _ClassVar[FounderVerdictStateKind]

class ConfirmationClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CONFIRMATION_CLASS_UNSPECIFIED: _ClassVar[ConfirmationClass]
    CONFIRMATION_CLASS_EXPLICIT: _ClassVar[ConfirmationClass]
    CONFIRMATION_CLASS_ELEVATED_RISK_ACCEPTANCE: _ClassVar[ConfirmationClass]

class RiskCategory(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RISK_CATEGORY_UNSPECIFIED: _ClassVar[RiskCategory]
    RISK_CATEGORY_QUALITY_RESIDUAL: _ClassVar[RiskCategory]
    RISK_CATEGORY_BUSINESS_RESIDUAL: _ClassVar[RiskCategory]
    RISK_CATEGORY_OPERATIONAL_RESIDUAL: _ClassVar[RiskCategory]

class VerdictEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_EVENT_KIND_UNSPECIFIED: _ClassVar[VerdictEventKind]
    VERDICT_EVENT_KIND_ISSUED: _ClassVar[VerdictEventKind]
    VERDICT_EVENT_KIND_CONSUMED: _ClassVar[VerdictEventKind]
    VERDICT_EVENT_KIND_REVOKED: _ClassVar[VerdictEventKind]
    VERDICT_EVENT_KIND_EXPIRED: _ClassVar[VerdictEventKind]
    VERDICT_EVENT_KIND_SUPERSEDED: _ClassVar[VerdictEventKind]

class VerdictErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERDICT_ERROR_CODE_UNSPECIFIED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_UNAUTHENTICATED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_PERMISSION_DENIED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_NOT_FOUND: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_REVISION_CONFLICT: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_TASK_NOT_VERDICT_PENDING: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_SCOPE_STALE: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_VERIFICATION_MISMATCH: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_CONFIRMATION_REQUIRED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_RISK_ACCEPTANCE_REQUIRED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_RISK_COVERAGE_INCOMPLETE: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_NON_OVERRIDABLE_GATE: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_REWORK_DIRECTIVE_REQUIRED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_ALREADY_ACTIVE: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_ALREADY_CONSUMED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_EXPIRED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_REVOKED: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_TASK_COMMIT_RECEIPT_INVALID: _ClassVar[VerdictErrorCode]
    VERDICT_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[VerdictErrorCode]
FOUNDER_VERDICT_DECISION_UNSPECIFIED: FounderVerdictDecision
FOUNDER_VERDICT_DECISION_ACCEPT: FounderVerdictDecision
FOUNDER_VERDICT_DECISION_REWORK: FounderVerdictDecision
FOUNDER_VERDICT_DECISION_REJECT: FounderVerdictDecision
FOUNDER_VERDICT_STATE_KIND_UNSPECIFIED: FounderVerdictStateKind
FOUNDER_VERDICT_STATE_KIND_ISSUED: FounderVerdictStateKind
FOUNDER_VERDICT_STATE_KIND_CONSUMED: FounderVerdictStateKind
FOUNDER_VERDICT_STATE_KIND_REVOKED: FounderVerdictStateKind
FOUNDER_VERDICT_STATE_KIND_EXPIRED: FounderVerdictStateKind
FOUNDER_VERDICT_STATE_KIND_SUPERSEDED: FounderVerdictStateKind
CONFIRMATION_CLASS_UNSPECIFIED: ConfirmationClass
CONFIRMATION_CLASS_EXPLICIT: ConfirmationClass
CONFIRMATION_CLASS_ELEVATED_RISK_ACCEPTANCE: ConfirmationClass
RISK_CATEGORY_UNSPECIFIED: RiskCategory
RISK_CATEGORY_QUALITY_RESIDUAL: RiskCategory
RISK_CATEGORY_BUSINESS_RESIDUAL: RiskCategory
RISK_CATEGORY_OPERATIONAL_RESIDUAL: RiskCategory
VERDICT_EVENT_KIND_UNSPECIFIED: VerdictEventKind
VERDICT_EVENT_KIND_ISSUED: VerdictEventKind
VERDICT_EVENT_KIND_CONSUMED: VerdictEventKind
VERDICT_EVENT_KIND_REVOKED: VerdictEventKind
VERDICT_EVENT_KIND_EXPIRED: VerdictEventKind
VERDICT_EVENT_KIND_SUPERSEDED: VerdictEventKind
VERDICT_ERROR_CODE_UNSPECIFIED: VerdictErrorCode
VERDICT_ERROR_CODE_INVALID_ARGUMENT: VerdictErrorCode
VERDICT_ERROR_CODE_UNAUTHENTICATED: VerdictErrorCode
VERDICT_ERROR_CODE_PERMISSION_DENIED: VerdictErrorCode
VERDICT_ERROR_CODE_NOT_FOUND: VerdictErrorCode
VERDICT_ERROR_CODE_REVISION_CONFLICT: VerdictErrorCode
VERDICT_ERROR_CODE_IDEMPOTENCY_CONFLICT: VerdictErrorCode
VERDICT_ERROR_CODE_TASK_NOT_VERDICT_PENDING: VerdictErrorCode
VERDICT_ERROR_CODE_SCOPE_STALE: VerdictErrorCode
VERDICT_ERROR_CODE_VERIFICATION_MISMATCH: VerdictErrorCode
VERDICT_ERROR_CODE_CONFIRMATION_REQUIRED: VerdictErrorCode
VERDICT_ERROR_CODE_RISK_ACCEPTANCE_REQUIRED: VerdictErrorCode
VERDICT_ERROR_CODE_RISK_COVERAGE_INCOMPLETE: VerdictErrorCode
VERDICT_ERROR_CODE_NON_OVERRIDABLE_GATE: VerdictErrorCode
VERDICT_ERROR_CODE_REWORK_DIRECTIVE_REQUIRED: VerdictErrorCode
VERDICT_ERROR_CODE_ALREADY_ACTIVE: VerdictErrorCode
VERDICT_ERROR_CODE_ALREADY_CONSUMED: VerdictErrorCode
VERDICT_ERROR_CODE_EXPIRED: VerdictErrorCode
VERDICT_ERROR_CODE_REVOKED: VerdictErrorCode
VERDICT_ERROR_CODE_TASK_COMMIT_RECEIPT_INVALID: VerdictErrorCode
VERDICT_ERROR_CODE_INTEGRITY_FAILURE: VerdictErrorCode

class VerdictScope(_message.Message):
    __slots__ = ("task_id", "task_revision", "work_revision", "artifact_set_id", "artifact_set_manifest", "verification_artifact_id", "verification_payload", "acceptance_contract_ref")
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    WORK_REVISION_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    task_id: str
    task_revision: int
    work_revision: int
    artifact_set_id: str
    artifact_set_manifest: _artifact_pb2.ContentAddress
    verification_artifact_id: str
    verification_payload: _artifact_pb2.ContentAddress
    acceptance_contract_ref: _common_pb2.ContractReference
    def __init__(self, task_id: _Optional[str] = ..., task_revision: _Optional[int] = ..., work_revision: _Optional[int] = ..., artifact_set_id: _Optional[str] = ..., artifact_set_manifest: _Optional[_Union[_artifact_pb2.ContentAddress, _Mapping]] = ..., verification_artifact_id: _Optional[str] = ..., verification_payload: _Optional[_Union[_artifact_pb2.ContentAddress, _Mapping]] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class FounderAuthorityProof(_message.Message):
    __slots__ = ("authenticated_founder_principal_id", "authority_ref", "confirmation_class", "confirmation_proof_ref", "verified_at", "valid_until", "authority_policy_ref")
    AUTHENTICATED_FOUNDER_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_CLASS_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_AT_FIELD_NUMBER: _ClassVar[int]
    VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    authenticated_founder_principal_id: str
    authority_ref: str
    confirmation_class: ConfirmationClass
    confirmation_proof_ref: str
    verified_at: _timestamp_pb2.Timestamp
    valid_until: _timestamp_pb2.Timestamp
    authority_policy_ref: _common_pb2.ContractReference
    def __init__(self, authenticated_founder_principal_id: _Optional[str] = ..., authority_ref: _Optional[str] = ..., confirmation_class: _Optional[_Union[ConfirmationClass, str]] = ..., confirmation_proof_ref: _Optional[str] = ..., verified_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., authority_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class RiskAcceptance(_message.Message):
    __slots__ = ("risk_acceptance_id", "category", "discrepancy_ids", "unverified_item_ids", "rationale_artifact_id", "compensating_control_artifact_ids", "review_trigger_code")
    RISK_ACCEPTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    DISCREPANCY_IDS_FIELD_NUMBER: _ClassVar[int]
    UNVERIFIED_ITEM_IDS_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    COMPENSATING_CONTROL_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    REVIEW_TRIGGER_CODE_FIELD_NUMBER: _ClassVar[int]
    risk_acceptance_id: str
    category: RiskCategory
    discrepancy_ids: _containers.RepeatedScalarFieldContainer[str]
    unverified_item_ids: _containers.RepeatedScalarFieldContainer[str]
    rationale_artifact_id: str
    compensating_control_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    review_trigger_code: str
    def __init__(self, risk_acceptance_id: _Optional[str] = ..., category: _Optional[_Union[RiskCategory, str]] = ..., discrepancy_ids: _Optional[_Iterable[str]] = ..., unverified_item_ids: _Optional[_Iterable[str]] = ..., rationale_artifact_id: _Optional[str] = ..., compensating_control_artifact_ids: _Optional[_Iterable[str]] = ..., review_trigger_code: _Optional[str] = ...) -> None: ...

class ReworkDirective(_message.Message):
    __slots__ = ("directive_id", "reason_code", "required_changes_artifact_id", "target_discrepancy_ids", "target_unverified_item_ids")
    DIRECTIVE_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CHANGES_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_DISCREPANCY_IDS_FIELD_NUMBER: _ClassVar[int]
    TARGET_UNVERIFIED_ITEM_IDS_FIELD_NUMBER: _ClassVar[int]
    directive_id: str
    reason_code: str
    required_changes_artifact_id: str
    target_discrepancy_ids: _containers.RepeatedScalarFieldContainer[str]
    target_unverified_item_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, directive_id: _Optional[str] = ..., reason_code: _Optional[str] = ..., required_changes_artifact_id: _Optional[str] = ..., target_discrepancy_ids: _Optional[_Iterable[str]] = ..., target_unverified_item_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class FounderVerdict(_message.Message):
    __slots__ = ("founder_verdict_id", "version", "decision", "scope", "observed_verification_conclusion", "authority_proof", "risk_acceptances", "rework_directive", "reason_code", "rationale_artifact_id", "valid_from", "expires_at", "issued_at", "canonical_payload", "supersedes_founder_verdict_id")
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_VERIFICATION_CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_PROOF_FIELD_NUMBER: _ClassVar[int]
    RISK_ACCEPTANCES_FIELD_NUMBER: _ClassVar[int]
    REWORK_DIRECTIVE_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    VALID_FROM_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    founder_verdict_id: str
    version: int
    decision: FounderVerdictDecision
    scope: VerdictScope
    observed_verification_conclusion: _verification_pb2.VerificationConclusion
    authority_proof: FounderAuthorityProof
    risk_acceptances: _containers.RepeatedCompositeFieldContainer[RiskAcceptance]
    rework_directive: ReworkDirective
    reason_code: str
    rationale_artifact_id: str
    valid_from: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    issued_at: _timestamp_pb2.Timestamp
    canonical_payload: _artifact_pb2.ContentAddress
    supersedes_founder_verdict_id: str
    def __init__(self, founder_verdict_id: _Optional[str] = ..., version: _Optional[int] = ..., decision: _Optional[_Union[FounderVerdictDecision, str]] = ..., scope: _Optional[_Union[VerdictScope, _Mapping]] = ..., observed_verification_conclusion: _Optional[_Union[_verification_pb2.VerificationConclusion, str]] = ..., authority_proof: _Optional[_Union[FounderAuthorityProof, _Mapping]] = ..., risk_acceptances: _Optional[_Iterable[_Union[RiskAcceptance, _Mapping]]] = ..., rework_directive: _Optional[_Union[ReworkDirective, _Mapping]] = ..., reason_code: _Optional[str] = ..., rationale_artifact_id: _Optional[str] = ..., valid_from: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., canonical_payload: _Optional[_Union[_artifact_pb2.ContentAddress, _Mapping]] = ..., supersedes_founder_verdict_id: _Optional[str] = ...) -> None: ...

class FounderVerdictState(_message.Message):
    __slots__ = ("founder_verdict_id", "revision", "state", "consumption_receipt_id", "superseded_by_verdict_id", "terminal_reason_code", "updated_at")
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CONSUMPTION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDED_BY_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    TERMINAL_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    founder_verdict_id: str
    revision: int
    state: FounderVerdictStateKind
    consumption_receipt_id: str
    superseded_by_verdict_id: str
    terminal_reason_code: str
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, founder_verdict_id: _Optional[str] = ..., revision: _Optional[int] = ..., state: _Optional[_Union[FounderVerdictStateKind, str]] = ..., consumption_receipt_id: _Optional[str] = ..., superseded_by_verdict_id: _Optional[str] = ..., terminal_reason_code: _Optional[str] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class VerdictConsumptionReceipt(_message.Message):
    __slots__ = ("consumption_receipt_id", "founder_verdict_id", "task_id", "consumed_task_revision", "resulting_task_revision", "task_event_id", "resulting_task_status", "consumed_at")
    CONSUMPTION_RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    TASK_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    TASK_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    RESULTING_TASK_STATUS_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_AT_FIELD_NUMBER: _ClassVar[int]
    consumption_receipt_id: str
    founder_verdict_id: str
    task_id: str
    consumed_task_revision: int
    resulting_task_revision: int
    task_event_id: str
    resulting_task_status: str
    consumed_at: _timestamp_pb2.Timestamp
    def __init__(self, consumption_receipt_id: _Optional[str] = ..., founder_verdict_id: _Optional[str] = ..., task_id: _Optional[str] = ..., consumed_task_revision: _Optional[int] = ..., resulting_task_revision: _Optional[int] = ..., task_event_id: _Optional[str] = ..., resulting_task_status: _Optional[str] = ..., consumed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class IssueFounderVerdictCommand(_message.Message):
    __slots__ = ("metadata", "scope", "decision", "observed_verification_conclusion", "risk_acceptances", "rework_directive", "reason_code", "rationale_artifact_id", "required_confirmation_class", "confirmation_proof_ref", "expires_at", "supersedes_founder_verdict_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    DECISION_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_VERIFICATION_CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    RISK_ACCEPTANCES_FIELD_NUMBER: _ClassVar[int]
    REWORK_DIRECTIVE_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    RATIONALE_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CONFIRMATION_CLASS_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    scope: VerdictScope
    decision: FounderVerdictDecision
    observed_verification_conclusion: _verification_pb2.VerificationConclusion
    risk_acceptances: _containers.RepeatedCompositeFieldContainer[RiskAcceptance]
    rework_directive: ReworkDirective
    reason_code: str
    rationale_artifact_id: str
    required_confirmation_class: ConfirmationClass
    confirmation_proof_ref: str
    expires_at: _timestamp_pb2.Timestamp
    supersedes_founder_verdict_id: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., scope: _Optional[_Union[VerdictScope, _Mapping]] = ..., decision: _Optional[_Union[FounderVerdictDecision, str]] = ..., observed_verification_conclusion: _Optional[_Union[_verification_pb2.VerificationConclusion, str]] = ..., risk_acceptances: _Optional[_Iterable[_Union[RiskAcceptance, _Mapping]]] = ..., rework_directive: _Optional[_Union[ReworkDirective, _Mapping]] = ..., reason_code: _Optional[str] = ..., rationale_artifact_id: _Optional[str] = ..., required_confirmation_class: _Optional[_Union[ConfirmationClass, str]] = ..., confirmation_proof_ref: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_founder_verdict_id: _Optional[str] = ...) -> None: ...

class ConsumeFounderVerdictCommand(_message.Message):
    __slots__ = ("metadata", "founder_verdict_id", "expected_state_revision", "task_event_id", "consumed_task_revision", "resulting_task_revision", "resulting_task_status", "task_commit_receipt_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    TASK_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_TASK_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULTING_TASK_STATUS_FIELD_NUMBER: _ClassVar[int]
    TASK_COMMIT_RECEIPT_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    founder_verdict_id: str
    expected_state_revision: int
    task_event_id: str
    consumed_task_revision: int
    resulting_task_revision: int
    resulting_task_status: str
    task_commit_receipt_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., founder_verdict_id: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., task_event_id: _Optional[str] = ..., consumed_task_revision: _Optional[int] = ..., resulting_task_revision: _Optional[int] = ..., resulting_task_status: _Optional[str] = ..., task_commit_receipt_ref: _Optional[str] = ...) -> None: ...

class RevokeFounderVerdictCommand(_message.Message):
    __slots__ = ("metadata", "founder_verdict_id", "expected_state_revision", "reason_code", "confirmation_proof_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CONFIRMATION_PROOF_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    founder_verdict_id: str
    expected_state_revision: int
    reason_code: str
    confirmation_proof_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., founder_verdict_id: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., reason_code: _Optional[str] = ..., confirmation_proof_ref: _Optional[str] = ...) -> None: ...

class ExpireFounderVerdictCommand(_message.Message):
    __slots__ = ("metadata", "founder_verdict_id", "expected_state_revision", "policy_decision_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_DECISION_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    founder_verdict_id: str
    expected_state_revision: int
    policy_decision_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., founder_verdict_id: _Optional[str] = ..., expected_state_revision: _Optional[int] = ..., policy_decision_ref: _Optional[str] = ...) -> None: ...

class VerdictCommand(_message.Message):
    __slots__ = ("issue_founder_verdict", "consume_founder_verdict", "revoke_founder_verdict", "expire_founder_verdict")
    ISSUE_FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    CONSUME_FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    REVOKE_FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    EXPIRE_FOUNDER_VERDICT_FIELD_NUMBER: _ClassVar[int]
    issue_founder_verdict: IssueFounderVerdictCommand
    consume_founder_verdict: ConsumeFounderVerdictCommand
    revoke_founder_verdict: RevokeFounderVerdictCommand
    expire_founder_verdict: ExpireFounderVerdictCommand
    def __init__(self, issue_founder_verdict: _Optional[_Union[IssueFounderVerdictCommand, _Mapping]] = ..., consume_founder_verdict: _Optional[_Union[ConsumeFounderVerdictCommand, _Mapping]] = ..., revoke_founder_verdict: _Optional[_Union[RevokeFounderVerdictCommand, _Mapping]] = ..., expire_founder_verdict: _Optional[_Union[ExpireFounderVerdictCommand, _Mapping]] = ...) -> None: ...

class VerdictEvent(_message.Message):
    __slots__ = ("event_id", "kind", "founder_verdict_id", "resulting_state_revision", "authenticated_principal_id", "command_id", "evidence_artifact_ids", "committed_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    FOUNDER_VERDICT_ID_FIELD_NUMBER: _ClassVar[int]
    RESULTING_STATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    kind: VerdictEventKind
    founder_verdict_id: str
    resulting_state_revision: int
    authenticated_principal_id: str
    command_id: str
    evidence_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    committed_at: _timestamp_pb2.Timestamp
    def __init__(self, event_id: _Optional[str] = ..., kind: _Optional[_Union[VerdictEventKind, str]] = ..., founder_verdict_id: _Optional[str] = ..., resulting_state_revision: _Optional[int] = ..., authenticated_principal_id: _Optional[str] = ..., command_id: _Optional[str] = ..., evidence_artifact_ids: _Optional[_Iterable[str]] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class VerdictCommandResult(_message.Message):
    __slots__ = ("committed", "replayed", "verdict", "state", "consumption_receipt", "event", "error_code", "safe_error_fingerprint")
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CONSUMPTION_RECEIPT_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    committed: bool
    replayed: bool
    verdict: FounderVerdict
    state: FounderVerdictState
    consumption_receipt: VerdictConsumptionReceipt
    event: VerdictEvent
    error_code: VerdictErrorCode
    safe_error_fingerprint: str
    def __init__(self, committed: _Optional[bool] = ..., replayed: _Optional[bool] = ..., verdict: _Optional[_Union[FounderVerdict, _Mapping]] = ..., state: _Optional[_Union[FounderVerdictState, _Mapping]] = ..., consumption_receipt: _Optional[_Union[VerdictConsumptionReceipt, _Mapping]] = ..., event: _Optional[_Union[VerdictEvent, _Mapping]] = ..., error_code: _Optional[_Union[VerdictErrorCode, str]] = ..., safe_error_fingerprint: _Optional[str] = ...) -> None: ...
