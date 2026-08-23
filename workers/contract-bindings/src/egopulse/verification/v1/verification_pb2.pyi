import datetime

from egopulse.artifact.v1 import artifact_pb2 as _artifact_pb2
from egopulse.common.v1 import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CheckerProfileStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHECKER_PROFILE_STATUS_UNSPECIFIED: _ClassVar[CheckerProfileStatus]
    CHECKER_PROFILE_STATUS_ACTIVE: _ClassVar[CheckerProfileStatus]
    CHECKER_PROFILE_STATUS_RETIRED: _ClassVar[CheckerProfileStatus]
    CHECKER_PROFILE_STATUS_REVOKED: _ClassVar[CheckerProfileStatus]
    CHECKER_PROFILE_STATUS_QUARANTINED: _ClassVar[CheckerProfileStatus]

class CheckerAssuranceClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHECKER_ASSURANCE_CLASS_UNSPECIFIED: _ClassVar[CheckerAssuranceClass]
    CHECKER_ASSURANCE_CLASS_DETERMINISTIC: _ClassVar[CheckerAssuranceClass]
    CHECKER_ASSURANCE_CLASS_MODEL_ASSISTED: _ClassVar[CheckerAssuranceClass]
    CHECKER_ASSURANCE_CLASS_HUMAN_REQUIRED: _ClassVar[CheckerAssuranceClass]

class VerificationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERIFICATION_STATUS_UNSPECIFIED: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_QUEUED: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_RUNNING: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_CANCELLATION_PENDING: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_COMPLETED: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_HELD: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_CANCELLED: _ClassVar[VerificationStatus]
    VERIFICATION_STATUS_SUPERSEDED: _ClassVar[VerificationStatus]

class VerificationConclusion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERIFICATION_CONCLUSION_UNSPECIFIED: _ClassVar[VerificationConclusion]
    VERIFICATION_CONCLUSION_PASSED: _ClassVar[VerificationConclusion]
    VERIFICATION_CONCLUSION_FAILED: _ClassVar[VerificationConclusion]
    VERIFICATION_CONCLUSION_PARTIAL: _ClassVar[VerificationConclusion]
    VERIFICATION_CONCLUSION_INDETERMINATE: _ClassVar[VerificationConclusion]

class CriterionRequirement(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CRITERION_REQUIREMENT_UNSPECIFIED: _ClassVar[CriterionRequirement]
    CRITERION_REQUIREMENT_MUST_PASS: _ClassVar[CriterionRequirement]
    CRITERION_REQUIREMENT_SHOULD_PASS: _ClassVar[CriterionRequirement]
    CRITERION_REQUIREMENT_INFORMATIONAL: _ClassVar[CriterionRequirement]

class CriterionOutcome(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CRITERION_OUTCOME_UNSPECIFIED: _ClassVar[CriterionOutcome]
    CRITERION_OUTCOME_PASSED: _ClassVar[CriterionOutcome]
    CRITERION_OUTCOME_FAILED: _ClassVar[CriterionOutcome]
    CRITERION_OUTCOME_UNVERIFIED: _ClassVar[CriterionOutcome]
    CRITERION_OUTCOME_ERROR: _ClassVar[CriterionOutcome]
    CRITERION_OUTCOME_NOT_APPLICABLE: _ClassVar[CriterionOutcome]

class EvidenceCoverage(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVIDENCE_COVERAGE_UNSPECIFIED: _ClassVar[EvidenceCoverage]
    EVIDENCE_COVERAGE_COMPLETE: _ClassVar[EvidenceCoverage]
    EVIDENCE_COVERAGE_PARTIAL: _ClassVar[EvidenceCoverage]
    EVIDENCE_COVERAGE_MISSING: _ClassVar[EvidenceCoverage]
    EVIDENCE_COVERAGE_INTEGRITY_FAILED: _ClassVar[EvidenceCoverage]

class DiscrepancySeverity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DISCREPANCY_SEVERITY_UNSPECIFIED: _ClassVar[DiscrepancySeverity]
    DISCREPANCY_SEVERITY_BLOCKER: _ClassVar[DiscrepancySeverity]
    DISCREPANCY_SEVERITY_MAJOR: _ClassVar[DiscrepancySeverity]
    DISCREPANCY_SEVERITY_MINOR: _ClassVar[DiscrepancySeverity]
    DISCREPANCY_SEVERITY_NIT: _ClassVar[DiscrepancySeverity]
    DISCREPANCY_SEVERITY_INFO: _ClassVar[DiscrepancySeverity]

class UnverifiedReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNVERIFIED_REASON_UNSPECIFIED: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_REQUIRES_JUDGEMENT: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_INSUFFICIENT_EVIDENCE: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_SUBJECTIVE: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_POLICY_AMBIGUOUS: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_SCOPE_NOT_CAPTURED: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_DEPENDENCY_NOT_CAPTURED: _ClassVar[UnverifiedReason]
    UNVERIFIED_REASON_CHECKER_UNAVAILABLE: _ClassVar[UnverifiedReason]

class VerificationEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERIFICATION_EVENT_KIND_UNSPECIFIED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_CHECKER_PROFILE_ATTESTED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_REQUEST_CREATED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_RUN_STARTED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_CRITERION_RECORDED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_ARTIFACT_COMMITTED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_CANCELLATION_REQUESTED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_CANCELLED: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_HELD: _ClassVar[VerificationEventKind]
    VERIFICATION_EVENT_KIND_SUPERSEDED: _ClassVar[VerificationEventKind]

class VerificationErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERIFICATION_ERROR_CODE_UNSPECIFIED: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_UNAUTHENTICATED: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_PERMISSION_DENIED: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_NOT_FOUND: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_REVISION_CONFLICT: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_BINDING_STALE: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_ARTIFACT_SET_NOT_SEALED: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_MANIFEST_MISMATCH: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_CLAIM_MISMATCH: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_ACCEPTANCE_CONTRACT_MISMATCH: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_CHECKER_PROFILE_MISMATCH: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_EVIDENCE_INCOMPLETE: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_SCHEMA_INVALID: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_CHECKER_UNAVAILABLE: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_CHECKER_TIMEOUT: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_OUTPUT_UNTRUSTED: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_CANCELLATION_OUTCOME_UNKNOWN: _ClassVar[VerificationErrorCode]
    VERIFICATION_ERROR_CODE_UNKNOWN_CRITICAL_RESULT: _ClassVar[VerificationErrorCode]
CHECKER_PROFILE_STATUS_UNSPECIFIED: CheckerProfileStatus
CHECKER_PROFILE_STATUS_ACTIVE: CheckerProfileStatus
CHECKER_PROFILE_STATUS_RETIRED: CheckerProfileStatus
CHECKER_PROFILE_STATUS_REVOKED: CheckerProfileStatus
CHECKER_PROFILE_STATUS_QUARANTINED: CheckerProfileStatus
CHECKER_ASSURANCE_CLASS_UNSPECIFIED: CheckerAssuranceClass
CHECKER_ASSURANCE_CLASS_DETERMINISTIC: CheckerAssuranceClass
CHECKER_ASSURANCE_CLASS_MODEL_ASSISTED: CheckerAssuranceClass
CHECKER_ASSURANCE_CLASS_HUMAN_REQUIRED: CheckerAssuranceClass
VERIFICATION_STATUS_UNSPECIFIED: VerificationStatus
VERIFICATION_STATUS_QUEUED: VerificationStatus
VERIFICATION_STATUS_RUNNING: VerificationStatus
VERIFICATION_STATUS_CANCELLATION_PENDING: VerificationStatus
VERIFICATION_STATUS_COMPLETED: VerificationStatus
VERIFICATION_STATUS_HELD: VerificationStatus
VERIFICATION_STATUS_CANCELLED: VerificationStatus
VERIFICATION_STATUS_SUPERSEDED: VerificationStatus
VERIFICATION_CONCLUSION_UNSPECIFIED: VerificationConclusion
VERIFICATION_CONCLUSION_PASSED: VerificationConclusion
VERIFICATION_CONCLUSION_FAILED: VerificationConclusion
VERIFICATION_CONCLUSION_PARTIAL: VerificationConclusion
VERIFICATION_CONCLUSION_INDETERMINATE: VerificationConclusion
CRITERION_REQUIREMENT_UNSPECIFIED: CriterionRequirement
CRITERION_REQUIREMENT_MUST_PASS: CriterionRequirement
CRITERION_REQUIREMENT_SHOULD_PASS: CriterionRequirement
CRITERION_REQUIREMENT_INFORMATIONAL: CriterionRequirement
CRITERION_OUTCOME_UNSPECIFIED: CriterionOutcome
CRITERION_OUTCOME_PASSED: CriterionOutcome
CRITERION_OUTCOME_FAILED: CriterionOutcome
CRITERION_OUTCOME_UNVERIFIED: CriterionOutcome
CRITERION_OUTCOME_ERROR: CriterionOutcome
CRITERION_OUTCOME_NOT_APPLICABLE: CriterionOutcome
EVIDENCE_COVERAGE_UNSPECIFIED: EvidenceCoverage
EVIDENCE_COVERAGE_COMPLETE: EvidenceCoverage
EVIDENCE_COVERAGE_PARTIAL: EvidenceCoverage
EVIDENCE_COVERAGE_MISSING: EvidenceCoverage
EVIDENCE_COVERAGE_INTEGRITY_FAILED: EvidenceCoverage
DISCREPANCY_SEVERITY_UNSPECIFIED: DiscrepancySeverity
DISCREPANCY_SEVERITY_BLOCKER: DiscrepancySeverity
DISCREPANCY_SEVERITY_MAJOR: DiscrepancySeverity
DISCREPANCY_SEVERITY_MINOR: DiscrepancySeverity
DISCREPANCY_SEVERITY_NIT: DiscrepancySeverity
DISCREPANCY_SEVERITY_INFO: DiscrepancySeverity
UNVERIFIED_REASON_UNSPECIFIED: UnverifiedReason
UNVERIFIED_REASON_REQUIRES_JUDGEMENT: UnverifiedReason
UNVERIFIED_REASON_INSUFFICIENT_EVIDENCE: UnverifiedReason
UNVERIFIED_REASON_SUBJECTIVE: UnverifiedReason
UNVERIFIED_REASON_POLICY_AMBIGUOUS: UnverifiedReason
UNVERIFIED_REASON_SCOPE_NOT_CAPTURED: UnverifiedReason
UNVERIFIED_REASON_DEPENDENCY_NOT_CAPTURED: UnverifiedReason
UNVERIFIED_REASON_CHECKER_UNAVAILABLE: UnverifiedReason
VERIFICATION_EVENT_KIND_UNSPECIFIED: VerificationEventKind
VERIFICATION_EVENT_KIND_CHECKER_PROFILE_ATTESTED: VerificationEventKind
VERIFICATION_EVENT_KIND_REQUEST_CREATED: VerificationEventKind
VERIFICATION_EVENT_KIND_RUN_STARTED: VerificationEventKind
VERIFICATION_EVENT_KIND_CRITERION_RECORDED: VerificationEventKind
VERIFICATION_EVENT_KIND_ARTIFACT_COMMITTED: VerificationEventKind
VERIFICATION_EVENT_KIND_CANCELLATION_REQUESTED: VerificationEventKind
VERIFICATION_EVENT_KIND_CANCELLED: VerificationEventKind
VERIFICATION_EVENT_KIND_HELD: VerificationEventKind
VERIFICATION_EVENT_KIND_SUPERSEDED: VerificationEventKind
VERIFICATION_ERROR_CODE_UNSPECIFIED: VerificationErrorCode
VERIFICATION_ERROR_CODE_INVALID_ARGUMENT: VerificationErrorCode
VERIFICATION_ERROR_CODE_UNAUTHENTICATED: VerificationErrorCode
VERIFICATION_ERROR_CODE_PERMISSION_DENIED: VerificationErrorCode
VERIFICATION_ERROR_CODE_NOT_FOUND: VerificationErrorCode
VERIFICATION_ERROR_CODE_REVISION_CONFLICT: VerificationErrorCode
VERIFICATION_ERROR_CODE_IDEMPOTENCY_CONFLICT: VerificationErrorCode
VERIFICATION_ERROR_CODE_BINDING_STALE: VerificationErrorCode
VERIFICATION_ERROR_CODE_ARTIFACT_SET_NOT_SEALED: VerificationErrorCode
VERIFICATION_ERROR_CODE_MANIFEST_MISMATCH: VerificationErrorCode
VERIFICATION_ERROR_CODE_CLAIM_MISMATCH: VerificationErrorCode
VERIFICATION_ERROR_CODE_ACCEPTANCE_CONTRACT_MISMATCH: VerificationErrorCode
VERIFICATION_ERROR_CODE_CHECKER_PROFILE_MISMATCH: VerificationErrorCode
VERIFICATION_ERROR_CODE_EVIDENCE_INCOMPLETE: VerificationErrorCode
VERIFICATION_ERROR_CODE_SCHEMA_INVALID: VerificationErrorCode
VERIFICATION_ERROR_CODE_INTEGRITY_FAILURE: VerificationErrorCode
VERIFICATION_ERROR_CODE_CHECKER_UNAVAILABLE: VerificationErrorCode
VERIFICATION_ERROR_CODE_CHECKER_TIMEOUT: VerificationErrorCode
VERIFICATION_ERROR_CODE_OUTPUT_UNTRUSTED: VerificationErrorCode
VERIFICATION_ERROR_CODE_CANCELLATION_OUTCOME_UNKNOWN: VerificationErrorCode
VERIFICATION_ERROR_CODE_UNKNOWN_CRITICAL_RESULT: VerificationErrorCode

class CheckerProfile(_message.Message):
    __slots__ = ("checker_profile_id", "revision", "status", "checker_id", "checker_version", "input_contract_ref", "output_contract_ref", "supported_criterion_types", "assurance_class", "sandbox_profile_ref", "tool_policy_ref", "data_egress_policy_ref", "timeout_ms", "network_allowed", "profile_digest_sha256", "attestation_evidence_artifact_ids", "attested_at")
    CHECKER_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CHECKER_ID_FIELD_NUMBER: _ClassVar[int]
    CHECKER_VERSION_FIELD_NUMBER: _ClassVar[int]
    INPUT_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_CRITERION_TYPES_FIELD_NUMBER: _ClassVar[int]
    ASSURANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    TOOL_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    DATA_EGRESS_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ALLOWED_FIELD_NUMBER: _ClassVar[int]
    PROFILE_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_EVIDENCE_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    ATTESTED_AT_FIELD_NUMBER: _ClassVar[int]
    checker_profile_id: str
    revision: int
    status: CheckerProfileStatus
    checker_id: str
    checker_version: str
    input_contract_ref: _common_pb2.ContractReference
    output_contract_ref: _common_pb2.ContractReference
    supported_criterion_types: _containers.RepeatedScalarFieldContainer[str]
    assurance_class: CheckerAssuranceClass
    sandbox_profile_ref: _common_pb2.ContractReference
    tool_policy_ref: _common_pb2.ContractReference
    data_egress_policy_ref: _common_pb2.ContractReference
    timeout_ms: int
    network_allowed: bool
    profile_digest_sha256: str
    attestation_evidence_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    attested_at: _timestamp_pb2.Timestamp
    def __init__(self, checker_profile_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[CheckerProfileStatus, str]] = ..., checker_id: _Optional[str] = ..., checker_version: _Optional[str] = ..., input_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., output_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., supported_criterion_types: _Optional[_Iterable[str]] = ..., assurance_class: _Optional[_Union[CheckerAssuranceClass, str]] = ..., sandbox_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., tool_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., data_egress_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., timeout_ms: _Optional[int] = ..., network_allowed: _Optional[bool] = ..., profile_digest_sha256: _Optional[str] = ..., attestation_evidence_artifact_ids: _Optional[_Iterable[str]] = ..., attested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class VerificationBinding(_message.Message):
    __slots__ = ("lineage", "artifact_set_id", "artifact_set_manifest", "claim_id", "claim_semantic_profile_ref", "acceptance_contract_ref")
    LINEAGE_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_SET_MANIFEST_FIELD_NUMBER: _ClassVar[int]
    CLAIM_ID_FIELD_NUMBER: _ClassVar[int]
    CLAIM_SEMANTIC_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    lineage: _artifact_pb2.LineageBinding
    artifact_set_id: str
    artifact_set_manifest: _artifact_pb2.ContentAddress
    claim_id: str
    claim_semantic_profile_ref: _common_pb2.ContractReference
    acceptance_contract_ref: _common_pb2.ContractReference
    def __init__(self, lineage: _Optional[_Union[_artifact_pb2.LineageBinding, _Mapping]] = ..., artifact_set_id: _Optional[str] = ..., artifact_set_manifest: _Optional[_Union[_artifact_pb2.ContentAddress, _Mapping]] = ..., claim_id: _Optional[str] = ..., claim_semantic_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., acceptance_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class VerificationRequest(_message.Message):
    __slots__ = ("verification_request_id", "revision", "status", "verification_type", "binding", "criterion_ids", "checker_profile_refs", "created_at", "hold_reason_code")
    VERIFICATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    BINDING_FIELD_NUMBER: _ClassVar[int]
    CRITERION_IDS_FIELD_NUMBER: _ClassVar[int]
    CHECKER_PROFILE_REFS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    verification_request_id: str
    revision: int
    status: VerificationStatus
    verification_type: str
    binding: VerificationBinding
    criterion_ids: _containers.RepeatedScalarFieldContainer[str]
    checker_profile_refs: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    created_at: _timestamp_pb2.Timestamp
    hold_reason_code: str
    def __init__(self, verification_request_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[VerificationStatus, str]] = ..., verification_type: _Optional[str] = ..., binding: _Optional[_Union[VerificationBinding, _Mapping]] = ..., criterion_ids: _Optional[_Iterable[str]] = ..., checker_profile_refs: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., hold_reason_code: _Optional[str] = ...) -> None: ...

class CriterionResult(_message.Message):
    __slots__ = ("criterion_result_id", "criterion_id", "requirement", "outcome", "assurance_class", "checker_profile_ref", "evidence_coverage", "evidence_ids", "discrepancy_ids", "unverified_item_ids", "duration_ms", "safe_detail_artifact_id")
    CRITERION_RESULT_ID_FIELD_NUMBER: _ClassVar[int]
    CRITERION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUIREMENT_FIELD_NUMBER: _ClassVar[int]
    OUTCOME_FIELD_NUMBER: _ClassVar[int]
    ASSURANCE_CLASS_FIELD_NUMBER: _ClassVar[int]
    CHECKER_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_COVERAGE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    DISCREPANCY_IDS_FIELD_NUMBER: _ClassVar[int]
    UNVERIFIED_ITEM_IDS_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    SAFE_DETAIL_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    criterion_result_id: str
    criterion_id: str
    requirement: CriterionRequirement
    outcome: CriterionOutcome
    assurance_class: CheckerAssuranceClass
    checker_profile_ref: _common_pb2.ContractReference
    evidence_coverage: EvidenceCoverage
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    discrepancy_ids: _containers.RepeatedScalarFieldContainer[str]
    unverified_item_ids: _containers.RepeatedScalarFieldContainer[str]
    duration_ms: int
    safe_detail_artifact_id: str
    def __init__(self, criterion_result_id: _Optional[str] = ..., criterion_id: _Optional[str] = ..., requirement: _Optional[_Union[CriterionRequirement, str]] = ..., outcome: _Optional[_Union[CriterionOutcome, str]] = ..., assurance_class: _Optional[_Union[CheckerAssuranceClass, str]] = ..., checker_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., evidence_coverage: _Optional[_Union[EvidenceCoverage, str]] = ..., evidence_ids: _Optional[_Iterable[str]] = ..., discrepancy_ids: _Optional[_Iterable[str]] = ..., unverified_item_ids: _Optional[_Iterable[str]] = ..., duration_ms: _Optional[int] = ..., safe_detail_artifact_id: _Optional[str] = ...) -> None: ...

class Discrepancy(_message.Message):
    __slots__ = ("discrepancy_id", "criterion_id", "severity", "evidence_ids", "description_artifact_id", "suggested_fix_artifact_id")
    DISCREPANCY_ID_FIELD_NUMBER: _ClassVar[int]
    CRITERION_ID_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    SUGGESTED_FIX_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    discrepancy_id: str
    criterion_id: str
    severity: DiscrepancySeverity
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    description_artifact_id: str
    suggested_fix_artifact_id: str
    def __init__(self, discrepancy_id: _Optional[str] = ..., criterion_id: _Optional[str] = ..., severity: _Optional[_Union[DiscrepancySeverity, str]] = ..., evidence_ids: _Optional[_Iterable[str]] = ..., description_artifact_id: _Optional[str] = ..., suggested_fix_artifact_id: _Optional[str] = ...) -> None: ...

class UnverifiedItem(_message.Message):
    __slots__ = ("unverified_item_id", "criterion_id", "reason", "evidence_ids", "context_artifact_id")
    UNVERIFIED_ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    CRITERION_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_IDS_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    unverified_item_id: str
    criterion_id: str
    reason: UnverifiedReason
    evidence_ids: _containers.RepeatedScalarFieldContainer[str]
    context_artifact_id: str
    def __init__(self, unverified_item_id: _Optional[str] = ..., criterion_id: _Optional[str] = ..., reason: _Optional[_Union[UnverifiedReason, str]] = ..., evidence_ids: _Optional[_Iterable[str]] = ..., context_artifact_id: _Optional[str] = ...) -> None: ...

class VerificationProvenance(_message.Message):
    __slots__ = ("verifier_principal_id", "checker_profile_refs", "tool_receipt_artifact_ids", "model_call_receipt_artifact_ids", "raw_output_artifact_ids", "duration_ms", "cost_receipt_artifact_id")
    VERIFIER_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    CHECKER_PROFILE_REFS_FIELD_NUMBER: _ClassVar[int]
    TOOL_RECEIPT_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    MODEL_CALL_RECEIPT_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    RAW_OUTPUT_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    COST_RECEIPT_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    verifier_principal_id: str
    checker_profile_refs: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    tool_receipt_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    model_call_receipt_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    raw_output_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    duration_ms: int
    cost_receipt_artifact_id: str
    def __init__(self, verifier_principal_id: _Optional[str] = ..., checker_profile_refs: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ..., tool_receipt_artifact_ids: _Optional[_Iterable[str]] = ..., model_call_receipt_artifact_ids: _Optional[_Iterable[str]] = ..., raw_output_artifact_ids: _Optional[_Iterable[str]] = ..., duration_ms: _Optional[int] = ..., cost_receipt_artifact_id: _Optional[str] = ...) -> None: ...

class VerificationArtifact(_message.Message):
    __slots__ = ("verification_artifact_id", "version", "verification_request_id", "verification_run_id", "verification_type", "binding", "conclusion", "overall_evidence_coverage", "criterion_results", "discrepancies", "unverified_items", "provenance", "canonical_payload", "completed_at", "supersedes_verification_artifact_id")
    VERIFICATION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_TYPE_FIELD_NUMBER: _ClassVar[int]
    BINDING_FIELD_NUMBER: _ClassVar[int]
    CONCLUSION_FIELD_NUMBER: _ClassVar[int]
    OVERALL_EVIDENCE_COVERAGE_FIELD_NUMBER: _ClassVar[int]
    CRITERION_RESULTS_FIELD_NUMBER: _ClassVar[int]
    DISCREPANCIES_FIELD_NUMBER: _ClassVar[int]
    UNVERIFIED_ITEMS_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_AT_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDES_VERIFICATION_ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    verification_artifact_id: str
    version: int
    verification_request_id: str
    verification_run_id: str
    verification_type: str
    binding: VerificationBinding
    conclusion: VerificationConclusion
    overall_evidence_coverage: EvidenceCoverage
    criterion_results: _containers.RepeatedCompositeFieldContainer[CriterionResult]
    discrepancies: _containers.RepeatedCompositeFieldContainer[Discrepancy]
    unverified_items: _containers.RepeatedCompositeFieldContainer[UnverifiedItem]
    provenance: VerificationProvenance
    canonical_payload: _artifact_pb2.ContentAddress
    completed_at: _timestamp_pb2.Timestamp
    supersedes_verification_artifact_id: str
    def __init__(self, verification_artifact_id: _Optional[str] = ..., version: _Optional[int] = ..., verification_request_id: _Optional[str] = ..., verification_run_id: _Optional[str] = ..., verification_type: _Optional[str] = ..., binding: _Optional[_Union[VerificationBinding, _Mapping]] = ..., conclusion: _Optional[_Union[VerificationConclusion, str]] = ..., overall_evidence_coverage: _Optional[_Union[EvidenceCoverage, str]] = ..., criterion_results: _Optional[_Iterable[_Union[CriterionResult, _Mapping]]] = ..., discrepancies: _Optional[_Iterable[_Union[Discrepancy, _Mapping]]] = ..., unverified_items: _Optional[_Iterable[_Union[UnverifiedItem, _Mapping]]] = ..., provenance: _Optional[_Union[VerificationProvenance, _Mapping]] = ..., canonical_payload: _Optional[_Union[_artifact_pb2.ContentAddress, _Mapping]] = ..., completed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., supersedes_verification_artifact_id: _Optional[str] = ...) -> None: ...

class VerificationRun(_message.Message):
    __slots__ = ("verification_run_id", "verification_request_id", "revision", "status", "criterion_results", "started_at", "ended_at", "hold_reason_code")
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    CRITERION_RESULTS_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    ENDED_AT_FIELD_NUMBER: _ClassVar[int]
    HOLD_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    verification_run_id: str
    verification_request_id: str
    revision: int
    status: VerificationStatus
    criterion_results: _containers.RepeatedCompositeFieldContainer[CriterionResult]
    started_at: _timestamp_pb2.Timestamp
    ended_at: _timestamp_pb2.Timestamp
    hold_reason_code: str
    def __init__(self, verification_run_id: _Optional[str] = ..., verification_request_id: _Optional[str] = ..., revision: _Optional[int] = ..., status: _Optional[_Union[VerificationStatus, str]] = ..., criterion_results: _Optional[_Iterable[_Union[CriterionResult, _Mapping]]] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., ended_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., hold_reason_code: _Optional[str] = ...) -> None: ...

class AttestCheckerProfileCommand(_message.Message):
    __slots__ = ("metadata", "profile")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    profile: CheckerProfile
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., profile: _Optional[_Union[CheckerProfile, _Mapping]] = ...) -> None: ...

class CreateVerificationRequestCommand(_message.Message):
    __slots__ = ("metadata", "request")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    request: VerificationRequest
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., request: _Optional[_Union[VerificationRequest, _Mapping]] = ...) -> None: ...

class StartVerificationRunCommand(_message.Message):
    __slots__ = ("metadata", "verification_request_id", "expected_request_revision", "verification_run_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REQUEST_REVISION_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_request_id: str
    expected_request_revision: int
    verification_run_id: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_request_id: _Optional[str] = ..., expected_request_revision: _Optional[int] = ..., verification_run_id: _Optional[str] = ...) -> None: ...

class RecordCriterionResultCommand(_message.Message):
    __slots__ = ("metadata", "verification_run_id", "expected_run_revision", "result")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_run_id: str
    expected_run_revision: int
    result: CriterionResult
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., result: _Optional[_Union[CriterionResult, _Mapping]] = ...) -> None: ...

class CompleteVerificationCommand(_message.Message):
    __slots__ = ("metadata", "verification_run_id", "expected_run_revision", "artifact")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_run_id: str
    expected_run_revision: int
    artifact: VerificationArtifact
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., artifact: _Optional[_Union[VerificationArtifact, _Mapping]] = ...) -> None: ...

class RequestVerificationCancellationCommand(_message.Message):
    __slots__ = ("metadata", "verification_run_id", "expected_run_revision", "authority_ref")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_REF_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_run_id: str
    expected_run_revision: int
    authority_ref: str
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., authority_ref: _Optional[str] = ...) -> None: ...

class RecordVerificationCancellationCommand(_message.Message):
    __slots__ = ("metadata", "verification_run_id", "expected_run_revision", "cancellation_confirmed", "evidence_artifact_ids")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_CONFIRMED_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_run_id: str
    expected_run_revision: int
    cancellation_confirmed: bool
    evidence_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., cancellation_confirmed: _Optional[bool] = ..., evidence_artifact_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class HoldVerificationCommand(_message.Message):
    __slots__ = ("metadata", "verification_run_id", "expected_run_revision", "reason_code", "evidence_artifact_ids")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_RUN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_RUN_REVISION_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    metadata: _common_pb2.CommandMetadata
    verification_run_id: str
    expected_run_revision: int
    reason_code: str
    evidence_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, metadata: _Optional[_Union[_common_pb2.CommandMetadata, _Mapping]] = ..., verification_run_id: _Optional[str] = ..., expected_run_revision: _Optional[int] = ..., reason_code: _Optional[str] = ..., evidence_artifact_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class VerificationCommand(_message.Message):
    __slots__ = ("attest_checker_profile", "create_verification_request", "start_verification_run", "record_criterion_result", "complete_verification", "request_verification_cancellation", "record_verification_cancellation", "hold_verification")
    ATTEST_CHECKER_PROFILE_FIELD_NUMBER: _ClassVar[int]
    CREATE_VERIFICATION_REQUEST_FIELD_NUMBER: _ClassVar[int]
    START_VERIFICATION_RUN_FIELD_NUMBER: _ClassVar[int]
    RECORD_CRITERION_RESULT_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    REQUEST_VERIFICATION_CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    RECORD_VERIFICATION_CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    HOLD_VERIFICATION_FIELD_NUMBER: _ClassVar[int]
    attest_checker_profile: AttestCheckerProfileCommand
    create_verification_request: CreateVerificationRequestCommand
    start_verification_run: StartVerificationRunCommand
    record_criterion_result: RecordCriterionResultCommand
    complete_verification: CompleteVerificationCommand
    request_verification_cancellation: RequestVerificationCancellationCommand
    record_verification_cancellation: RecordVerificationCancellationCommand
    hold_verification: HoldVerificationCommand
    def __init__(self, attest_checker_profile: _Optional[_Union[AttestCheckerProfileCommand, _Mapping]] = ..., create_verification_request: _Optional[_Union[CreateVerificationRequestCommand, _Mapping]] = ..., start_verification_run: _Optional[_Union[StartVerificationRunCommand, _Mapping]] = ..., record_criterion_result: _Optional[_Union[RecordCriterionResultCommand, _Mapping]] = ..., complete_verification: _Optional[_Union[CompleteVerificationCommand, _Mapping]] = ..., request_verification_cancellation: _Optional[_Union[RequestVerificationCancellationCommand, _Mapping]] = ..., record_verification_cancellation: _Optional[_Union[RecordVerificationCancellationCommand, _Mapping]] = ..., hold_verification: _Optional[_Union[HoldVerificationCommand, _Mapping]] = ...) -> None: ...

class VerificationEvent(_message.Message):
    __slots__ = ("event_id", "kind", "aggregate_id", "aggregate_revision", "authenticated_principal_id", "command_id", "evidence_artifact_ids", "committed_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ARTIFACT_IDS_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    kind: VerificationEventKind
    aggregate_id: str
    aggregate_revision: int
    authenticated_principal_id: str
    command_id: str
    evidence_artifact_ids: _containers.RepeatedScalarFieldContainer[str]
    committed_at: _timestamp_pb2.Timestamp
    def __init__(self, event_id: _Optional[str] = ..., kind: _Optional[_Union[VerificationEventKind, str]] = ..., aggregate_id: _Optional[str] = ..., aggregate_revision: _Optional[int] = ..., authenticated_principal_id: _Optional[str] = ..., command_id: _Optional[str] = ..., evidence_artifact_ids: _Optional[_Iterable[str]] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class VerificationCommandResult(_message.Message):
    __slots__ = ("committed", "replayed", "checker_profile", "request", "run", "artifact", "event", "error_code", "safe_error_fingerprint")
    COMMITTED_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FIELD_NUMBER: _ClassVar[int]
    CHECKER_PROFILE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    RUN_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    SAFE_ERROR_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    committed: bool
    replayed: bool
    checker_profile: CheckerProfile
    request: VerificationRequest
    run: VerificationRun
    artifact: VerificationArtifact
    event: VerificationEvent
    error_code: VerificationErrorCode
    safe_error_fingerprint: str
    def __init__(self, committed: _Optional[bool] = ..., replayed: _Optional[bool] = ..., checker_profile: _Optional[_Union[CheckerProfile, _Mapping]] = ..., request: _Optional[_Union[VerificationRequest, _Mapping]] = ..., run: _Optional[_Union[VerificationRun, _Mapping]] = ..., artifact: _Optional[_Union[VerificationArtifact, _Mapping]] = ..., event: _Optional[_Union[VerificationEvent, _Mapping]] = ..., error_code: _Optional[_Union[VerificationErrorCode, str]] = ..., safe_error_fingerprint: _Optional[str] = ...) -> None: ...
