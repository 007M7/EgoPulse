import datetime

from egopulse.collaboration.v1 import collaboration_pb2 as _collaboration_pb2
from egopulse.common.v1 import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PersistenceDomain(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PERSISTENCE_DOMAIN_UNSPECIFIED: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_TASK: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_COLLABORATION: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_HARNESS_ADAPTER: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_ARTIFACT_METADATA: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_ARTIFACT_BLOB: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_VERIFICATION: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_FOUNDER_VERDICT: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_LOCAL_READ_MODEL: _ClassVar[PersistenceDomain]
    PERSISTENCE_DOMAIN_RECOVERY_COORDINATOR: _ClassVar[PersistenceDomain]

class StoreRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STORE_ROLE_UNSPECIFIED: _ClassVar[StoreRole]
    STORE_ROLE_AUTHORITY: _ClassVar[StoreRole]
    STORE_ROLE_ADAPTER_DURABLE_EDGE: _ClassVar[StoreRole]
    STORE_ROLE_IMMUTABLE_BLOB: _ClassVar[StoreRole]
    STORE_ROLE_DERIVED_REBUILDABLE: _ClassVar[StoreRole]
    STORE_ROLE_RECOVERY_METADATA: _ClassVar[StoreRole]

class StoreHealth(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STORE_HEALTH_UNSPECIFIED: _ClassVar[StoreHealth]
    STORE_HEALTH_HEALTHY: _ClassVar[StoreHealth]
    STORE_HEALTH_RECOVERING: _ClassVar[StoreHealth]
    STORE_HEALTH_READ_ONLY_DEGRADED: _ClassVar[StoreHealth]
    STORE_HEALTH_HELD: _ClassVar[StoreHealth]
    STORE_HEALTH_INTEGRITY_FAILED: _ClassVar[StoreHealth]
    STORE_HEALTH_SCHEMA_INCOMPATIBLE: _ClassVar[StoreHealth]

class OutboxDeliveryState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OUTBOX_DELIVERY_STATE_UNSPECIFIED: _ClassVar[OutboxDeliveryState]
    OUTBOX_DELIVERY_STATE_PENDING: _ClassVar[OutboxDeliveryState]
    OUTBOX_DELIVERY_STATE_DELIVERED: _ClassVar[OutboxDeliveryState]
    OUTBOX_DELIVERY_STATE_CONSUMED: _ClassVar[OutboxDeliveryState]
    OUTBOX_DELIVERY_STATE_HELD: _ClassVar[OutboxDeliveryState]

class BackupStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BACKUP_STATUS_UNSPECIFIED: _ClassVar[BackupStatus]
    BACKUP_STATUS_PREPARING: _ClassVar[BackupStatus]
    BACKUP_STATUS_COMPLETE: _ClassVar[BackupStatus]
    BACKUP_STATUS_INCOMPLETE: _ClassVar[BackupStatus]
    BACKUP_STATUS_REJECTED: _ClassVar[BackupStatus]
    BACKUP_STATUS_EXPIRED: _ClassVar[BackupStatus]

class RecoveryPhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECOVERY_PHASE_UNSPECIFIED: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_FENCED: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_INSPECTING: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_DOMAIN_CONTINUITY_VERIFIED: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_OUTBOX_REPLAY: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_SIDE_EFFECT_RECONCILIATION: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_READ_MODEL_REBUILD: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_READY: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_READ_ONLY_DEGRADED: _ClassVar[RecoveryPhase]
    RECOVERY_PHASE_HELD: _ClassVar[RecoveryPhase]

class PersistenceErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PERSISTENCE_ERROR_CODE_UNSPECIFIED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_INVALID_ARGUMENT: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_UNAUTHENTICATED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_PERMISSION_DENIED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_REVISION_CONFLICT: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_FENCE_STALE: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_DURABILITY_NOT_PROVEN: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_ATOMIC_COMMIT_VIOLATION: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_INTEGRITY_FAILURE: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_SCHEMA_INCOMPATIBLE: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_BACKUP_INCOMPLETE: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_BLOB_COVERAGE_INCOMPLETE: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_RESTORE_NOT_VERIFIED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_RECOVERY_REQUIRED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_MEDIA_LOSS_NOT_COVERED: _ClassVar[PersistenceErrorCode]
    PERSISTENCE_ERROR_CODE_MIGRATION_NOT_AUTHORIZED: _ClassVar[PersistenceErrorCode]
PERSISTENCE_DOMAIN_UNSPECIFIED: PersistenceDomain
PERSISTENCE_DOMAIN_TASK: PersistenceDomain
PERSISTENCE_DOMAIN_COLLABORATION: PersistenceDomain
PERSISTENCE_DOMAIN_HARNESS_ADAPTER: PersistenceDomain
PERSISTENCE_DOMAIN_ARTIFACT_METADATA: PersistenceDomain
PERSISTENCE_DOMAIN_ARTIFACT_BLOB: PersistenceDomain
PERSISTENCE_DOMAIN_VERIFICATION: PersistenceDomain
PERSISTENCE_DOMAIN_FOUNDER_VERDICT: PersistenceDomain
PERSISTENCE_DOMAIN_LOCAL_READ_MODEL: PersistenceDomain
PERSISTENCE_DOMAIN_RECOVERY_COORDINATOR: PersistenceDomain
STORE_ROLE_UNSPECIFIED: StoreRole
STORE_ROLE_AUTHORITY: StoreRole
STORE_ROLE_ADAPTER_DURABLE_EDGE: StoreRole
STORE_ROLE_IMMUTABLE_BLOB: StoreRole
STORE_ROLE_DERIVED_REBUILDABLE: StoreRole
STORE_ROLE_RECOVERY_METADATA: StoreRole
STORE_HEALTH_UNSPECIFIED: StoreHealth
STORE_HEALTH_HEALTHY: StoreHealth
STORE_HEALTH_RECOVERING: StoreHealth
STORE_HEALTH_READ_ONLY_DEGRADED: StoreHealth
STORE_HEALTH_HELD: StoreHealth
STORE_HEALTH_INTEGRITY_FAILED: StoreHealth
STORE_HEALTH_SCHEMA_INCOMPATIBLE: StoreHealth
OUTBOX_DELIVERY_STATE_UNSPECIFIED: OutboxDeliveryState
OUTBOX_DELIVERY_STATE_PENDING: OutboxDeliveryState
OUTBOX_DELIVERY_STATE_DELIVERED: OutboxDeliveryState
OUTBOX_DELIVERY_STATE_CONSUMED: OutboxDeliveryState
OUTBOX_DELIVERY_STATE_HELD: OutboxDeliveryState
BACKUP_STATUS_UNSPECIFIED: BackupStatus
BACKUP_STATUS_PREPARING: BackupStatus
BACKUP_STATUS_COMPLETE: BackupStatus
BACKUP_STATUS_INCOMPLETE: BackupStatus
BACKUP_STATUS_REJECTED: BackupStatus
BACKUP_STATUS_EXPIRED: BackupStatus
RECOVERY_PHASE_UNSPECIFIED: RecoveryPhase
RECOVERY_PHASE_FENCED: RecoveryPhase
RECOVERY_PHASE_INSPECTING: RecoveryPhase
RECOVERY_PHASE_DOMAIN_CONTINUITY_VERIFIED: RecoveryPhase
RECOVERY_PHASE_OUTBOX_REPLAY: RecoveryPhase
RECOVERY_PHASE_SIDE_EFFECT_RECONCILIATION: RecoveryPhase
RECOVERY_PHASE_READ_MODEL_REBUILD: RecoveryPhase
RECOVERY_PHASE_READY: RecoveryPhase
RECOVERY_PHASE_READ_ONLY_DEGRADED: RecoveryPhase
RECOVERY_PHASE_HELD: RecoveryPhase
PERSISTENCE_ERROR_CODE_UNSPECIFIED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_INVALID_ARGUMENT: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_UNAUTHENTICATED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_PERMISSION_DENIED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_REVISION_CONFLICT: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_FENCE_STALE: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_DURABILITY_NOT_PROVEN: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_ATOMIC_COMMIT_VIOLATION: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_INTEGRITY_FAILURE: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_SCHEMA_INCOMPATIBLE: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_BACKUP_INCOMPLETE: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_BLOB_COVERAGE_INCOMPLETE: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_RESTORE_NOT_VERIFIED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_RECOVERY_REQUIRED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_MEDIA_LOSS_NOT_COVERED: PersistenceErrorCode
PERSISTENCE_ERROR_CODE_MIGRATION_NOT_AUTHORIZED: PersistenceErrorCode

class DurabilityFence(_message.Message):
    __slots__ = ("store_epoch", "fencing_token", "holder_instance_id")
    STORE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    HOLDER_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    store_epoch: str
    fencing_token: int
    holder_instance_id: str
    def __init__(self, store_epoch: _Optional[str] = ..., fencing_token: _Optional[int] = ..., holder_instance_id: _Optional[str] = ...) -> None: ...

class DomainWatermark(_message.Message):
    __slots__ = ("domain", "store_role", "store_instance_id", "store_epoch", "schema_ref", "last_committed_revision", "last_event_sequence", "last_event_id", "pending_outbox_count", "last_consumed_inbox_sequence", "durable_at")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    STORE_ROLE_FIELD_NUMBER: _ClassVar[int]
    STORE_INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    STORE_EPOCH_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_REF_FIELD_NUMBER: _ClassVar[int]
    LAST_COMMITTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    LAST_EVENT_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    LAST_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    PENDING_OUTBOX_COUNT_FIELD_NUMBER: _ClassVar[int]
    LAST_CONSUMED_INBOX_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    DURABLE_AT_FIELD_NUMBER: _ClassVar[int]
    domain: PersistenceDomain
    store_role: StoreRole
    store_instance_id: str
    store_epoch: str
    schema_ref: _common_pb2.ContractReference
    last_committed_revision: int
    last_event_sequence: int
    last_event_id: str
    pending_outbox_count: int
    last_consumed_inbox_sequence: int
    durable_at: _timestamp_pb2.Timestamp
    def __init__(self, domain: _Optional[_Union[PersistenceDomain, str]] = ..., store_role: _Optional[_Union[StoreRole, str]] = ..., store_instance_id: _Optional[str] = ..., store_epoch: _Optional[str] = ..., schema_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., last_committed_revision: _Optional[int] = ..., last_event_sequence: _Optional[int] = ..., last_event_id: _Optional[str] = ..., pending_outbox_count: _Optional[int] = ..., last_consumed_inbox_sequence: _Optional[int] = ..., durable_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class DurableCommitReceipt(_message.Message):
    __slots__ = ("owner_domain", "aggregate_id", "aggregate_revision", "committed_event_id", "committed_outbox_message_ids", "idempotency_key", "request_digest_sha256", "durability_fence", "committed_at", "acknowledged_after_durability_barrier")
    OWNER_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_REVISION_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_OUTBOX_MESSAGE_IDS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    DURABILITY_FENCE_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGED_AFTER_DURABILITY_BARRIER_FIELD_NUMBER: _ClassVar[int]
    owner_domain: PersistenceDomain
    aggregate_id: str
    aggregate_revision: int
    committed_event_id: str
    committed_outbox_message_ids: _containers.RepeatedScalarFieldContainer[str]
    idempotency_key: str
    request_digest_sha256: str
    durability_fence: DurabilityFence
    committed_at: _timestamp_pb2.Timestamp
    acknowledged_after_durability_barrier: bool
    def __init__(self, owner_domain: _Optional[_Union[PersistenceDomain, str]] = ..., aggregate_id: _Optional[str] = ..., aggregate_revision: _Optional[int] = ..., committed_event_id: _Optional[str] = ..., committed_outbox_message_ids: _Optional[_Iterable[str]] = ..., idempotency_key: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., durability_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ..., committed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., acknowledged_after_durability_barrier: _Optional[bool] = ...) -> None: ...

class OutboxEnvelope(_message.Message):
    __slots__ = ("message_id", "source_domain", "source_event_id", "source_revision", "destination_domain", "command_contract_ref", "canonical_payload_digest_sha256", "idempotency_key", "correlation_id", "causation_id", "state", "created_at")
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    SOURCE_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    COMMAND_CONTRACT_REF_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_PAYLOAD_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAUSATION_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    message_id: str
    source_domain: PersistenceDomain
    source_event_id: str
    source_revision: int
    destination_domain: PersistenceDomain
    command_contract_ref: _common_pb2.ContractReference
    canonical_payload_digest_sha256: str
    idempotency_key: str
    correlation_id: str
    causation_id: str
    state: OutboxDeliveryState
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, message_id: _Optional[str] = ..., source_domain: _Optional[_Union[PersistenceDomain, str]] = ..., source_event_id: _Optional[str] = ..., source_revision: _Optional[int] = ..., destination_domain: _Optional[_Union[PersistenceDomain, str]] = ..., command_contract_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., canonical_payload_digest_sha256: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., correlation_id: _Optional[str] = ..., causation_id: _Optional[str] = ..., state: _Optional[_Union[OutboxDeliveryState, str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class InboxConsumptionReceipt(_message.Message):
    __slots__ = ("receipt_id", "source_message_id", "consumer_domain", "consumer_event_id", "consumer_revision", "duplicate_delivery", "consumed_at")
    RECEIPT_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_REVISION_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_DELIVERY_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_AT_FIELD_NUMBER: _ClassVar[int]
    receipt_id: str
    source_message_id: str
    consumer_domain: PersistenceDomain
    consumer_event_id: str
    consumer_revision: int
    duplicate_delivery: bool
    consumed_at: _timestamp_pb2.Timestamp
    def __init__(self, receipt_id: _Optional[str] = ..., source_message_id: _Optional[str] = ..., consumer_domain: _Optional[_Union[PersistenceDomain, str]] = ..., consumer_event_id: _Optional[str] = ..., consumer_revision: _Optional[int] = ..., duplicate_delivery: _Optional[bool] = ..., consumed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class DomainStoreInspection(_message.Message):
    __slots__ = ("watermark", "health", "state_event_continuity_verified", "idempotency_index_verified", "outbox_inbox_continuity_verified", "referenced_blob_coverage_verified", "safe_reason_code", "evidence_refs")
    WATERMARK_FIELD_NUMBER: _ClassVar[int]
    HEALTH_FIELD_NUMBER: _ClassVar[int]
    STATE_EVENT_CONTINUITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_INDEX_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    OUTBOX_INBOX_CONTINUITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    REFERENCED_BLOB_COVERAGE_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    SAFE_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    watermark: DomainWatermark
    health: StoreHealth
    state_event_continuity_verified: bool
    idempotency_index_verified: bool
    outbox_inbox_continuity_verified: bool
    referenced_blob_coverage_verified: bool
    safe_reason_code: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, watermark: _Optional[_Union[DomainWatermark, _Mapping]] = ..., health: _Optional[_Union[StoreHealth, str]] = ..., state_event_continuity_verified: _Optional[bool] = ..., idempotency_index_verified: _Optional[bool] = ..., outbox_inbox_continuity_verified: _Optional[bool] = ..., referenced_blob_coverage_verified: _Optional[bool] = ..., safe_reason_code: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ...) -> None: ...

class DomainSnapshotDescriptor(_message.Message):
    __slots__ = ("snapshot_id", "domain", "store_role", "watermark", "snapshot_digest_sha256", "byte_length", "encryption_profile_ref", "contains_current_state", "contains_authority_events", "contains_idempotency_results", "contains_pending_outbox", "contains_inbox_receipts", "created_at")
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    STORE_ROLE_FIELD_NUMBER: _ClassVar[int]
    WATERMARK_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    BYTE_LENGTH_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_PROFILE_REF_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_CURRENT_STATE_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_AUTHORITY_EVENTS_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_IDEMPOTENCY_RESULTS_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_PENDING_OUTBOX_FIELD_NUMBER: _ClassVar[int]
    CONTAINS_INBOX_RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    domain: PersistenceDomain
    store_role: StoreRole
    watermark: DomainWatermark
    snapshot_digest_sha256: str
    byte_length: int
    encryption_profile_ref: _common_pb2.ContractReference
    contains_current_state: bool
    contains_authority_events: bool
    contains_idempotency_results: bool
    contains_pending_outbox: bool
    contains_inbox_receipts: bool
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, snapshot_id: _Optional[str] = ..., domain: _Optional[_Union[PersistenceDomain, str]] = ..., store_role: _Optional[_Union[StoreRole, str]] = ..., watermark: _Optional[_Union[DomainWatermark, _Mapping]] = ..., snapshot_digest_sha256: _Optional[str] = ..., byte_length: _Optional[int] = ..., encryption_profile_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., contains_current_state: _Optional[bool] = ..., contains_authority_events: _Optional[bool] = ..., contains_idempotency_results: _Optional[bool] = ..., contains_pending_outbox: _Optional[bool] = ..., contains_inbox_receipts: _Optional[bool] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ArtifactBlobCoverage(_message.Message):
    __slots__ = ("coverage_manifest_digest_sha256", "live_reference_count", "covered_blob_count", "missing_blob_count")
    COVERAGE_MANIFEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    LIVE_REFERENCE_COUNT_FIELD_NUMBER: _ClassVar[int]
    COVERED_BLOB_COUNT_FIELD_NUMBER: _ClassVar[int]
    MISSING_BLOB_COUNT_FIELD_NUMBER: _ClassVar[int]
    coverage_manifest_digest_sha256: str
    live_reference_count: int
    covered_blob_count: int
    missing_blob_count: int
    def __init__(self, coverage_manifest_digest_sha256: _Optional[str] = ..., live_reference_count: _Optional[int] = ..., covered_blob_count: _Optional[int] = ..., missing_blob_count: _Optional[int] = ...) -> None: ...

class BackupManifest(_message.Message):
    __slots__ = ("backup_id", "backup_epoch", "quiescence_barrier_id", "status", "domain_snapshots", "artifact_blob_coverage", "retention_policy_ref", "canonical_manifest_digest_sha256", "all_required_domains_covered", "pending_outbox_preserved", "created_at")
    BACKUP_ID_FIELD_NUMBER: _ClassVar[int]
    BACKUP_EPOCH_FIELD_NUMBER: _ClassVar[int]
    QUIESCENCE_BARRIER_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_BLOB_COVERAGE_FIELD_NUMBER: _ClassVar[int]
    RETENTION_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    CANONICAL_MANIFEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    ALL_REQUIRED_DOMAINS_COVERED_FIELD_NUMBER: _ClassVar[int]
    PENDING_OUTBOX_PRESERVED_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    backup_id: str
    backup_epoch: str
    quiescence_barrier_id: str
    status: BackupStatus
    domain_snapshots: _containers.RepeatedCompositeFieldContainer[DomainSnapshotDescriptor]
    artifact_blob_coverage: ArtifactBlobCoverage
    retention_policy_ref: _common_pb2.ContractReference
    canonical_manifest_digest_sha256: str
    all_required_domains_covered: bool
    pending_outbox_preserved: bool
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, backup_id: _Optional[str] = ..., backup_epoch: _Optional[str] = ..., quiescence_barrier_id: _Optional[str] = ..., status: _Optional[_Union[BackupStatus, str]] = ..., domain_snapshots: _Optional[_Iterable[_Union[DomainSnapshotDescriptor, _Mapping]]] = ..., artifact_blob_coverage: _Optional[_Union[ArtifactBlobCoverage, _Mapping]] = ..., retention_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ..., canonical_manifest_digest_sha256: _Optional[str] = ..., all_required_domains_covered: _Optional[bool] = ..., pending_outbox_preserved: _Optional[bool] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class RestoreVerificationReport(_message.Message):
    __slots__ = ("report_id", "backup_id", "verified_in_isolation", "manifest_digest_verified", "schema_compatibility_verified", "domain_revision_continuity_verified", "event_continuity_verified", "outbox_inbox_continuity_verified", "artifact_blob_coverage_verified", "valid_for_cutover", "evidence_refs", "safe_failure_reason_codes", "verified_at")
    REPORT_ID_FIELD_NUMBER: _ClassVar[int]
    BACKUP_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_IN_ISOLATION_FIELD_NUMBER: _ClassVar[int]
    MANIFEST_DIGEST_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_COMPATIBILITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_REVISION_CONTINUITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    EVENT_CONTINUITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    OUTBOX_INBOX_CONTINUITY_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_BLOB_COVERAGE_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    VALID_FOR_CUTOVER_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    SAFE_FAILURE_REASON_CODES_FIELD_NUMBER: _ClassVar[int]
    VERIFIED_AT_FIELD_NUMBER: _ClassVar[int]
    report_id: str
    backup_id: str
    verified_in_isolation: bool
    manifest_digest_verified: bool
    schema_compatibility_verified: bool
    domain_revision_continuity_verified: bool
    event_continuity_verified: bool
    outbox_inbox_continuity_verified: bool
    artifact_blob_coverage_verified: bool
    valid_for_cutover: bool
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    safe_failure_reason_codes: _containers.RepeatedScalarFieldContainer[str]
    verified_at: _timestamp_pb2.Timestamp
    def __init__(self, report_id: _Optional[str] = ..., backup_id: _Optional[str] = ..., verified_in_isolation: _Optional[bool] = ..., manifest_digest_verified: _Optional[bool] = ..., schema_compatibility_verified: _Optional[bool] = ..., domain_revision_continuity_verified: _Optional[bool] = ..., event_continuity_verified: _Optional[bool] = ..., outbox_inbox_continuity_verified: _Optional[bool] = ..., artifact_blob_coverage_verified: _Optional[bool] = ..., valid_for_cutover: _Optional[bool] = ..., evidence_refs: _Optional[_Iterable[str]] = ..., safe_failure_reason_codes: _Optional[_Iterable[str]] = ..., verified_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class RecoveryItem(_message.Message):
    __slots__ = ("item_id", "domain", "aggregate_id", "attempt_id", "recovery_class", "safe_reason_code", "evidence_refs")
    ITEM_ID_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    AGGREGATE_ID_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    RECOVERY_CLASS_FIELD_NUMBER: _ClassVar[int]
    SAFE_REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_REFS_FIELD_NUMBER: _ClassVar[int]
    item_id: str
    domain: PersistenceDomain
    aggregate_id: str
    attempt_id: str
    recovery_class: _collaboration_pb2.RecoveryClass
    safe_reason_code: str
    evidence_refs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, item_id: _Optional[str] = ..., domain: _Optional[_Union[PersistenceDomain, str]] = ..., aggregate_id: _Optional[str] = ..., attempt_id: _Optional[str] = ..., recovery_class: _Optional[_Union[_collaboration_pb2.RecoveryClass, str]] = ..., safe_reason_code: _Optional[str] = ..., evidence_refs: _Optional[_Iterable[str]] = ...) -> None: ...

class RecoveryPlan(_message.Message):
    __slots__ = ("recovery_plan_id", "coordinator_fence", "phase", "required_domains", "inspections", "items", "command_gateway_enabled", "read_model_rebuild_required", "target_projection_epoch", "created_at", "updated_at")
    RECOVERY_PLAN_ID_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_DOMAINS_FIELD_NUMBER: _ClassVar[int]
    INSPECTIONS_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    COMMAND_GATEWAY_ENABLED_FIELD_NUMBER: _ClassVar[int]
    READ_MODEL_REBUILD_REQUIRED_FIELD_NUMBER: _ClassVar[int]
    TARGET_PROJECTION_EPOCH_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    recovery_plan_id: str
    coordinator_fence: DurabilityFence
    phase: RecoveryPhase
    required_domains: _containers.RepeatedScalarFieldContainer[PersistenceDomain]
    inspections: _containers.RepeatedCompositeFieldContainer[DomainStoreInspection]
    items: _containers.RepeatedCompositeFieldContainer[RecoveryItem]
    command_gateway_enabled: bool
    read_model_rebuild_required: bool
    target_projection_epoch: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, recovery_plan_id: _Optional[str] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ..., phase: _Optional[_Union[RecoveryPhase, str]] = ..., required_domains: _Optional[_Iterable[_Union[PersistenceDomain, str]]] = ..., inspections: _Optional[_Iterable[_Union[DomainStoreInspection, _Mapping]]] = ..., items: _Optional[_Iterable[_Union[RecoveryItem, _Mapping]]] = ..., command_gateway_enabled: _Optional[bool] = ..., read_model_rebuild_required: _Optional[bool] = ..., target_projection_epoch: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class InspectDomainRequest(_message.Message):
    __slots__ = ("domain", "coordinator_fence")
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    domain: PersistenceDomain
    coordinator_fence: DurabilityFence
    def __init__(self, domain: _Optional[_Union[PersistenceDomain, str]] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ...) -> None: ...

class InspectDomainResponse(_message.Message):
    __slots__ = ("inspection", "error_code")
    INSPECTION_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    inspection: DomainStoreInspection
    error_code: PersistenceErrorCode
    def __init__(self, inspection: _Optional[_Union[DomainStoreInspection, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class PrepareDomainSnapshotRequest(_message.Message):
    __slots__ = ("backup_id", "quiescence_barrier_id", "domain", "coordinator_fence")
    BACKUP_ID_FIELD_NUMBER: _ClassVar[int]
    QUIESCENCE_BARRIER_ID_FIELD_NUMBER: _ClassVar[int]
    DOMAIN_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    backup_id: str
    quiescence_barrier_id: str
    domain: PersistenceDomain
    coordinator_fence: DurabilityFence
    def __init__(self, backup_id: _Optional[str] = ..., quiescence_barrier_id: _Optional[str] = ..., domain: _Optional[_Union[PersistenceDomain, str]] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ...) -> None: ...

class PrepareDomainSnapshotResponse(_message.Message):
    __slots__ = ("snapshot", "error_code")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    snapshot: DomainSnapshotDescriptor
    error_code: PersistenceErrorCode
    def __init__(self, snapshot: _Optional[_Union[DomainSnapshotDescriptor, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class ReplayOutboxRequest(_message.Message):
    __slots__ = ("source_domain", "after_message_id", "coordinator_fence")
    SOURCE_DOMAIN_FIELD_NUMBER: _ClassVar[int]
    AFTER_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    source_domain: PersistenceDomain
    after_message_id: str
    coordinator_fence: DurabilityFence
    def __init__(self, source_domain: _Optional[_Union[PersistenceDomain, str]] = ..., after_message_id: _Optional[str] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ...) -> None: ...

class ReplayOutboxResponse(_message.Message):
    __slots__ = ("inspected_count", "delivered_count", "consumed_count", "held_count", "error_code")
    INSPECTED_COUNT_FIELD_NUMBER: _ClassVar[int]
    DELIVERED_COUNT_FIELD_NUMBER: _ClassVar[int]
    CONSUMED_COUNT_FIELD_NUMBER: _ClassVar[int]
    HELD_COUNT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    inspected_count: int
    delivered_count: int
    consumed_count: int
    held_count: int
    error_code: PersistenceErrorCode
    def __init__(self, inspected_count: _Optional[int] = ..., delivered_count: _Optional[int] = ..., consumed_count: _Optional[int] = ..., held_count: _Optional[int] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class CreateBackupManifestRequest(_message.Message):
    __slots__ = ("backup_id", "quiescence_barrier_id", "snapshots", "artifact_blob_coverage", "retention_policy_ref")
    BACKUP_ID_FIELD_NUMBER: _ClassVar[int]
    QUIESCENCE_BARRIER_ID_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOTS_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_BLOB_COVERAGE_FIELD_NUMBER: _ClassVar[int]
    RETENTION_POLICY_REF_FIELD_NUMBER: _ClassVar[int]
    backup_id: str
    quiescence_barrier_id: str
    snapshots: _containers.RepeatedCompositeFieldContainer[DomainSnapshotDescriptor]
    artifact_blob_coverage: ArtifactBlobCoverage
    retention_policy_ref: _common_pb2.ContractReference
    def __init__(self, backup_id: _Optional[str] = ..., quiescence_barrier_id: _Optional[str] = ..., snapshots: _Optional[_Iterable[_Union[DomainSnapshotDescriptor, _Mapping]]] = ..., artifact_blob_coverage: _Optional[_Union[ArtifactBlobCoverage, _Mapping]] = ..., retention_policy_ref: _Optional[_Union[_common_pb2.ContractReference, _Mapping]] = ...) -> None: ...

class CreateBackupManifestResponse(_message.Message):
    __slots__ = ("manifest", "error_code")
    MANIFEST_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    manifest: BackupManifest
    error_code: PersistenceErrorCode
    def __init__(self, manifest: _Optional[_Union[BackupManifest, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class VerifyRestoreCandidateRequest(_message.Message):
    __slots__ = ("manifest", "isolated_restore_location_ref", "supported_schema_refs")
    MANIFEST_FIELD_NUMBER: _ClassVar[int]
    ISOLATED_RESTORE_LOCATION_REF_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_SCHEMA_REFS_FIELD_NUMBER: _ClassVar[int]
    manifest: BackupManifest
    isolated_restore_location_ref: str
    supported_schema_refs: _containers.RepeatedCompositeFieldContainer[_common_pb2.ContractReference]
    def __init__(self, manifest: _Optional[_Union[BackupManifest, _Mapping]] = ..., isolated_restore_location_ref: _Optional[str] = ..., supported_schema_refs: _Optional[_Iterable[_Union[_common_pb2.ContractReference, _Mapping]]] = ...) -> None: ...

class VerifyRestoreCandidateResponse(_message.Message):
    __slots__ = ("report", "error_code")
    REPORT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    report: RestoreVerificationReport
    error_code: PersistenceErrorCode
    def __init__(self, report: _Optional[_Union[RestoreVerificationReport, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class BeginRecoveryRequest(_message.Message):
    __slots__ = ("recovery_plan_id", "coordinator_fence", "required_domains")
    RECOVERY_PLAN_ID_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_DOMAINS_FIELD_NUMBER: _ClassVar[int]
    recovery_plan_id: str
    coordinator_fence: DurabilityFence
    required_domains: _containers.RepeatedScalarFieldContainer[PersistenceDomain]
    def __init__(self, recovery_plan_id: _Optional[str] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ..., required_domains: _Optional[_Iterable[_Union[PersistenceDomain, str]]] = ...) -> None: ...

class BeginRecoveryResponse(_message.Message):
    __slots__ = ("plan", "error_code")
    PLAN_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    plan: RecoveryPlan
    error_code: PersistenceErrorCode
    def __init__(self, plan: _Optional[_Union[RecoveryPlan, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...

class CommitRestoreCutoverRequest(_message.Message):
    __slots__ = ("recovery_plan_id", "restore_verification_report_id", "coordinator_fence", "authenticated_principal_id")
    RECOVERY_PLAN_ID_FIELD_NUMBER: _ClassVar[int]
    RESTORE_VERIFICATION_REPORT_ID_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_FENCE_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATED_PRINCIPAL_ID_FIELD_NUMBER: _ClassVar[int]
    recovery_plan_id: str
    restore_verification_report_id: str
    coordinator_fence: DurabilityFence
    authenticated_principal_id: str
    def __init__(self, recovery_plan_id: _Optional[str] = ..., restore_verification_report_id: _Optional[str] = ..., coordinator_fence: _Optional[_Union[DurabilityFence, _Mapping]] = ..., authenticated_principal_id: _Optional[str] = ...) -> None: ...

class CommitRestoreCutoverResponse(_message.Message):
    __slots__ = ("plan", "error_code")
    PLAN_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    plan: RecoveryPlan
    error_code: PersistenceErrorCode
    def __init__(self, plan: _Optional[_Union[RecoveryPlan, _Mapping]] = ..., error_code: _Optional[_Union[PersistenceErrorCode, str]] = ...) -> None: ...
