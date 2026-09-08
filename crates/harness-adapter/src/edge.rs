use crate::disclosure::{
    ContentAssemblyCheckpoint, SafeContentProjection, canonical_credential_variants,
    canonical_safe_record_digest, canonical_safe_record_id,
};
use crate::runtime::TerminalOutputCandidate;
use egopulse_domain_contracts::profiles::{
    HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
    HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, ApprovalDecisionReceipt, CancelExecutionReceipt, DeliveryDisposition,
    DispatchEnvelope, DispatchReceipt, DispatchRouteBinding, HarnessContentCompactionReason,
    HarnessContentHistoryCompactionRecord, HarnessContentLimitKind, HarnessContentMarkerKind,
    HarnessContentRetentionReason, HarnessContentRetentionTombstone,
    HarnessContentSignalObservation, HarnessObservation, LifecycleKind, ObservationCriticality,
    SafeArtifactIdentity, SafeArtifactRelationContent, SafeContentMarker,
    SafeHarnessContentProjectionEvent, SafeHarnessContentRecord, harness_observation,
    safe_harness_content_projection_event, safe_harness_content_record,
};
use hmac::{Hmac, Mac};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

#[path = "edge/approval_authorization.rs"]
mod approval_authorization;
pub use approval_authorization::{ApprovalAuthorizationSnapshot, RetainedApprovalAuthorization};

const SCHEMA_PROFILE_ID: &str = "egopulse/harness-adapter-edge/v1";

const SCHEMA_V1: &str = r#"
CREATE TABLE adapter_edge_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  adapter_id TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  next_observation_sequence INTEGER NOT NULL CHECK (next_observation_sequence >= 1)
) STRICT;

CREATE TABLE adapter_dispatches (
  dispatch_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL,
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  dispatch_fingerprint TEXT NOT NULL,
  envelope_digest_sha256 TEXT NOT NULL,
  envelope BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('prepared', 'delivery_unknown', 'delivered', 'rejected')),
  receipt BLOB,
  delivery_raw_evidence BLOB,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  UNIQUE(attempt_id, dispatch_id, fencing_token)
) STRICT;

CREATE TABLE adapter_observations (
  observation_id TEXT PRIMARY KEY,
  dispatch_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  observation_sequence INTEGER NOT NULL UNIQUE CHECK (observation_sequence >= 1),
  native_key TEXT NOT NULL,
  native_event_digest_sha256 TEXT NOT NULL,
  raw_evidence_ref TEXT NOT NULL,
  raw_event BLOB NOT NULL,
  observation BLOB NOT NULL,
  ingestion_state TEXT NOT NULL CHECK (ingestion_state IN ('pending', 'consumed')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(dispatch_id, native_key),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_quarantine (
  quarantine_id TEXT PRIMARY KEY,
  dispatch_id TEXT NOT NULL,
  native_key TEXT NOT NULL,
  prior_digest_sha256 TEXT,
  conflicting_digest_sha256 TEXT NOT NULL,
  raw_event BLOB NOT NULL,
  reason_code TEXT NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_cancellations (
  cancellation_request_id TEXT PRIMARY KEY,
  dispatch_id TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('prepared', 'delivery_unknown', 'delivered', 'rejected', 'unsupported')),
  receipt BLOB,
  raw_evidence BLOB,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_approvals (
  approval_request_id TEXT PRIMARY KEY,
  dispatch_id TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('prepared', 'delivery_unknown', 'delivered', 'rejected')),
  receipt BLOB,
  raw_evidence BLOB,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;
"#;

const SCHEMA_V2: &str = r#"
CREATE TABLE adapter_projection_outbox (
  message_id TEXT PRIMARY KEY,
  source_observation_id TEXT NOT NULL UNIQUE,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (source_observation_id) REFERENCES adapter_observations(observation_id)
) STRICT;
"#;

const SCHEMA_V3: &str = r#"
CREATE TABLE adapter_dispatch_task_lineage (
  dispatch_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  task_revision INTEGER NOT NULL CHECK (task_revision >= 1),
  work_revision INTEGER NOT NULL CHECK (work_revision >= 1),
  bound_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_terminal_output_outbox (
  message_id TEXT PRIMARY KEY,
  source_observation_id TEXT NOT NULL UNIQUE,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  dispatch_id TEXT NOT NULL UNIQUE,
  native_completion_ref TEXT NOT NULL,
  media_type TEXT NOT NULL,
  content_digest_sha256 TEXT NOT NULL,
  original_content_bytes INTEGER NOT NULL CHECK (original_content_bytes >= 0),
  captured_content BLOB NOT NULL,
  captured_content_digest_sha256 TEXT NOT NULL,
  content_complete INTEGER NOT NULL CHECK (content_complete IN (0, 1)),
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (source_observation_id) REFERENCES adapter_observations(observation_id),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;
"#;

const SCHEMA_V4: &str = r#"
ALTER TABLE adapter_edge_metadata ADD COLUMN next_content_sequence INTEGER NOT NULL DEFAULT 1
  CHECK (next_content_sequence >= 1);

CREATE TABLE adapter_dispatch_route_bindings (
  dispatch_id TEXT PRIMARY KEY,
  route_binding_digest_sha256 TEXT NOT NULL,
  route_binding BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_content_candidates (
  content_event_id TEXT PRIMARY KEY,
  source_observation_id TEXT NOT NULL UNIQUE,
  dispatch_id TEXT NOT NULL,
  candidate_digest_sha256 TEXT NOT NULL,
  content_signal BLOB NOT NULL,
  projection_state TEXT NOT NULL CHECK (projection_state IN ('pending', 'projected', 'quarantined')),
  safe_projection_digest_sha256 TEXT,
  committed_records_digest_sha256 TEXT,
  limit_kind TEXT,
  quarantine_reason_code TEXT,
  created_at_seconds INTEGER NOT NULL,
  projected_at_seconds INTEGER,
  FOREIGN KEY (source_observation_id) REFERENCES adapter_observations(observation_id),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_content_assemblies (
  dispatch_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  current_revision INTEGER NOT NULL CHECK (current_revision >= 1),
  finalized INTEGER NOT NULL CHECK (finalized IN (0, 1)),
  raw_cumulative_digest_sha256 TEXT NOT NULL,
  safe_cumulative_digest_sha256 TEXT NOT NULL,
  credential_commitment_hmac_sha256 TEXT,
  assembly_state BLOB NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  PRIMARY KEY(dispatch_id, message_id),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_safe_content_ledger (
  record_id TEXT PRIMARY KEY,
  content_event_id TEXT NOT NULL,
  part_index INTEGER NOT NULL CHECK (part_index >= 0),
  task_id TEXT NOT NULL,
  record_digest_sha256 TEXT NOT NULL,
  content_sequence INTEGER NOT NULL UNIQUE CHECK (content_sequence >= 1),
  safe_record BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (content_event_id) REFERENCES adapter_content_candidates(content_event_id),
  UNIQUE(content_event_id, part_index)
) STRICT;

CREATE INDEX adapter_safe_content_ledger_task_sequence
  ON adapter_safe_content_ledger(task_id, content_sequence);

CREATE TABLE adapter_content_owner_snapshots (
  task_id TEXT PRIMARY KEY,
  owner_sequence INTEGER NOT NULL CHECK (owner_sequence >= 0),
  floor_sequence INTEGER NOT NULL CHECK (floor_sequence >= 0),
  disclosure_profile_digest_sha256 TEXT NOT NULL,
  baseline_state BLOB NOT NULL,
  baseline_digest_sha256 TEXT NOT NULL,
  snapshot_digest_sha256 TEXT NOT NULL,
  updated_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE adapter_content_history_floors (
  task_id TEXT PRIMARY KEY,
  floor_sequence INTEGER NOT NULL CHECK (floor_sequence >= 0),
  floor_digest_sha256 TEXT NOT NULL,
  updated_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE adapter_content_retention_tombstones (
  tombstone_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  tombstone_digest_sha256 TEXT NOT NULL,
  tombstone BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE adapter_content_redaction_bindings (
  dispatch_id TEXT PRIMARY KEY,
  disclosure_profile_digest_sha256 TEXT NOT NULL,
  credential_commitment_hmac_sha256 TEXT,
  structured_only INTEGER NOT NULL CHECK (structured_only IN (0, 1)),
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_content_budgets (
  scope_kind TEXT NOT NULL CHECK (scope_kind IN ('attempt', 'task')),
  scope_id TEXT NOT NULL,
  safe_text_bytes INTEGER NOT NULL CHECK (safe_text_bytes >= 0),
  safe_record_count INTEGER NOT NULL CHECK (safe_record_count >= 0),
  limit_reached INTEGER NOT NULL CHECK (limit_reached IN (0, 1)),
  limit_kind TEXT CHECK (limit_kind IN (
    'ATTEMPT_TEXT_BYTES', 'ATTEMPT_RECORDS', 'TASK_TEXT_BYTES', 'TASK_RECORDS'
  )),
  updated_at_seconds INTEGER NOT NULL,
  CHECK ((limit_reached = 0 AND limit_kind IS NULL)
      OR (limit_reached = 1 AND limit_kind IS NOT NULL)),
  PRIMARY KEY(scope_kind, scope_id)
) STRICT;

CREATE TABLE adapter_content_projection_outbox (
  message_id TEXT PRIMARY KEY,
  source_record_id TEXT NOT NULL UNIQUE,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL
) STRICT;
"#;

const SCHEMA_V5: &str = r#"
CREATE TABLE adapter_dispatch_relation_policy (
  dispatch_id TEXT PRIMARY KEY,
  policy TEXT NOT NULL CHECK (policy IN ('legacy_not_required', 'required_governed_content')),
  policy_version INTEGER NOT NULL CHECK (policy_version = 1),
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

INSERT INTO adapter_dispatch_relation_policy(dispatch_id, policy, policy_version, created_at_seconds)
  SELECT dispatch_id, 'legacy_not_required', 1, created_at_seconds FROM adapter_dispatches;

CREATE TABLE adapter_final_artifact_relation_intents (
  terminal_message_id TEXT PRIMARY KEY,
  terminal_payload_digest_sha256 TEXT NOT NULL,
  dispatch_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  artifact_digest_sha256 TEXT NOT NULL,
  relation_state TEXT NOT NULL CHECK (relation_state IN ('pending', 'projected', 'quarantined', 'skipped')),
  safe_reason_code TEXT,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (terminal_message_id) REFERENCES adapter_terminal_output_outbox(message_id),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

CREATE TABLE adapter_derived_content_sources (
  content_event_id TEXT PRIMARY KEY,
  source_observation_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK (source_kind = 'final_artifact_relation'),
  source_identity_digest_sha256 TEXT NOT NULL,
  source_payload BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (source_observation_id) REFERENCES adapter_observations(observation_id),
  FOREIGN KEY (dispatch_id) REFERENCES adapter_dispatches(dispatch_id)
) STRICT;

ALTER TABLE adapter_safe_content_ledger RENAME TO adapter_safe_content_ledger_v4;
CREATE TABLE adapter_safe_content_ledger (
  record_id TEXT PRIMARY KEY,
  content_event_id TEXT NOT NULL,
  part_index INTEGER NOT NULL CHECK (part_index >= 0),
  task_id TEXT NOT NULL,
  record_digest_sha256 TEXT NOT NULL,
  content_sequence INTEGER NOT NULL UNIQUE CHECK (content_sequence >= 1),
  safe_record BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(content_event_id, part_index)
) STRICT;
INSERT INTO adapter_safe_content_ledger
  SELECT * FROM adapter_safe_content_ledger_v4;
DROP TABLE adapter_safe_content_ledger_v4;
CREATE INDEX adapter_safe_content_ledger_task_sequence
  ON adapter_safe_content_ledger(task_id, content_sequence);
CREATE TRIGGER adapter_safe_content_ledger_source_required
BEFORE INSERT ON adapter_safe_content_ledger
WHEN NOT EXISTS (
  SELECT 1 FROM adapter_content_candidates WHERE content_event_id = NEW.content_event_id
) AND NOT EXISTS (
  SELECT 1 FROM adapter_derived_content_sources WHERE content_event_id = NEW.content_event_id
)
BEGIN
  SELECT RAISE(ABORT, 'safe content source missing');
END;
"#;

const SCHEMA_V6: &str = r#"
ALTER TABLE adapter_final_artifact_relation_intents
  ADD COLUMN projected_record BLOB;
"#;

/// QR-04 durable attempt-output budget. Oversized output keeps a bounded
/// preview plus the digest and original byte count; it is never presented as
/// a complete Artifact candidate.
const TERMINAL_OUTPUT_FULL_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_OUTPUT_PREVIEW_BYTES: usize = 64 * 1024;
const CONTENT_SAFE_PART_BYTES: usize = 65_536;
const ATTEMPT_SAFE_TEXT_BYTES: u64 = 16 * 1024 * 1024;
const ATTEMPT_SAFE_RECORDS: u64 = 16_384;
const TASK_SAFE_TEXT_BYTES: u64 = 64 * 1024 * 1024;
const TASK_SAFE_RECORDS: u64 = 65_536;
const CONTENT_MINIMUM_RETENTION_SECONDS: i64 = 2_592_000;

type StoredContentCandidateState = (String, Option<String>, Option<String>, Option<String>);

pub struct AdapterEdgeKey([u8; 32]);

impl AdapterEdgeKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for AdapterEdgeKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct AdapterEdgeConfig {
    pub database_path: PathBuf,
    pub adapter_id: String,
    pub store_epoch: String,
    pub key: AdapterEdgeKey,
}

#[derive(Debug, Error)]
pub enum AdapterEdgeError {
    #[error("adapter edge storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("adapter edge migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("adapter edge directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("adapter edge SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("adapter edge store generation does not match configuration")]
    StoreGenerationMismatch,
    #[error("adapter edge integrity check failed")]
    IntegrityFailure,
    #[error("dispatch identity was reused with different content")]
    DispatchConflict,
    #[error("dispatch is not in a state that permits this transition")]
    DispatchStateConflict,
    #[error("observation references a dispatch that is not durably registered: {0}")]
    DispatchNotFound(String),
    #[error("native event key or observation sequence conflicts with durable evidence")]
    SequenceConflict,
    #[error("durable adapter record could not be decoded")]
    Decode(#[from] prost::DecodeError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchPreparation {
    Ready,
    Replay(Box<DispatchReceipt>),
    DeliveryUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableWritePreparation {
    Ready,
    Replay(Vec<u8>),
    DeliveryUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDeliveryState {
    Prepared,
    DeliveryUnknown,
    Delivered,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableApprovalRecord {
    pub approval_request_id: String,
    pub dispatch_id: String,
    pub request_digest_sha256: String,
    pub delivery_state: ApprovalDeliveryState,
    pub receipt: Option<ApprovalDecisionReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationAppend {
    Committed(HarnessObservation),
    Replay(HarnessObservation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingContentCandidate {
    pub observation: HarnessObservation,
    pub signal: HarnessContentSignalObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SafeContentCommit {
    Committed {
        records: Vec<SafeHarnessContentRecord>,
        first_sequence: u64,
        last_sequence: u64,
    },
    Replay {
        records: Vec<SafeHarnessContentRecord>,
        first_sequence: u64,
        last_sequence: u64,
    },
    Suppressed {
        content_event_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalArtifactRelationRequest {
    pub terminal_message_id: String,
    pub terminal_payload_digest_sha256: String,
    pub artifact_id: String,
    pub artifact_digest_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalArtifactRelationRegistration {
    Registered,
    Replay,
    SkippedLegacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalArtifactRelationPolicy {
    NotRequiredLegacyOrLifecycleOnly,
    RequiredGovernedContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinalArtifactRelationCommit {
    Committed(SafeHarnessContentRecord),
    Replay(SafeHarnessContentRecord),
    PendingContent,
    Ambiguous,
    RawMismatch,
    Skipped(FinalArtifactRelationSkipReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalArtifactRelationSkipReason {
    NoSafeAssistantContent,
    ScopeTerminal,
    NoRecordSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalArtifactRelationState {
    Pending,
    Projected,
    Quarantined,
    Skipped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalArtifactRelationStatus {
    pub request: FinalArtifactRelationRequest,
    pub dispatch_id: String,
    pub state: FinalArtifactRelationState,
    pub safe_reason_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeContentBudgetUsage {
    pub safe_text_bytes: u64,
    pub safe_record_count: u64,
    pub limit_reached: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeContentBudgetSnapshot {
    pub attempt: SafeContentBudgetUsage,
    pub task: SafeContentBudgetUsage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentRetentionCompactionRequest {
    pub task_id: String,
    pub attempt_id: String,
    pub final_epoch: String,
    pub expected_owner_sequence: u64,
    pub terminal_committed_at: prost_types::Timestamp,
    pub compacted_at: prost_types::Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentRetentionCompactionReceipt {
    pub owner_snapshot: SafeContentOwnerSnapshot,
    pub compaction: HarnessContentHistoryCompactionRecord,
    pub tombstone: HarnessContentRetentionTombstone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeContentProjectionMessage {
    pub message_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub event: SafeHarnessContentProjectionEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentDisclosureMode {
    Full,
    StructuredOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeContentAssemblyCheckpoint {
    pub dispatch_id: String,
    pub message_id: String,
    pub current_revision: u64,
    pub finalized: bool,
    pub raw_cumulative_digest_sha256: String,
    pub safe_cumulative_digest_sha256: String,
    pub safe_records: Vec<SafeHarnessContentRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeContentOwnerRecord {
    pub sequence: u64,
    pub record: SafeHarnessContentRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeContentOwnerSnapshot {
    pub task_id: String,
    pub owner_sequence: u64,
    pub floor_sequence: u64,
    pub disclosure_profile_digest_sha256: String,
    pub snapshot_digest_sha256: String,
    pub records: Vec<SafeContentOwnerRecord>,
    pub tombstones: Vec<HarnessContentRetentionTombstone>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainedSafeContent {
    Records(SafeContentOwnerSnapshot),
    ResetRequired(SafeContentOwnerSnapshot),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeExecutionBinding {
    pub attempt_id: String,
    pub dispatch_id: String,
    pub fencing_token: u64,
    pub native_session_ref: String,
    pub native_execution_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterObservationEvidence {
    pub observation: HarnessObservation,
    pub raw_event: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalObservationRecoveryView {
    pub pending: Vec<HarnessObservation>,
    pub durable_terminal_sequence: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyExecutionStartEvidenceRejection {
    OwnerMismatch,
    PriorStartMissing,
    NativeBindingMissing,
    NativeBindingConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyExecutionStartEvidence {
    pub prior_start: AdapterObservationEvidence,
    pub pending_start: AdapterObservationEvidence,
    pub native_binding: NativeExecutionBinding,
    pub durable_terminal_handoff: bool,
    pub terminal_raw_event: Option<Vec<u8>>,
    pub terminal_native_completion_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyExecutionStartEvidenceResolution {
    Verified(Box<LegacyExecutionStartEvidence>),
    Rejected(LegacyExecutionStartEvidenceRejection),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredDeliveredDispatchEvidence {
    pub dispatch_id: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub dispatch_fingerprint: String,
    pub envelope_digest_sha256: String,
    pub envelope: Vec<u8>,
    pub delivery_state: String,
    pub receipt: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchTaskLineage {
    pub task_id: String,
    pub task_revision: u64,
    pub work_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAdapterApprovalProjection {
    pub message_id: String,
    pub source_observation_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub run_id: String,
    pub step_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub fencing_token: u64,
    pub observation: HarnessObservation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTerminalOutputCandidate {
    pub message_id: String,
    pub source_observation_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub run_id: String,
    pub task_id: String,
    pub task_revision: u64,
    pub work_revision: u64,
    pub run_revision: u64,
    pub step_id: String,
    pub step_revision: u64,
    pub attempt_id: String,
    pub attempt_revision: u64,
    pub dispatch_id: String,
    pub fencing_token: u64,
    pub native_completion_ref: String,
    pub media_type: String,
    pub content_digest_sha256: String,
    pub original_content_bytes: u64,
    pub content: Vec<u8>,
    pub content_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterEdgeInspection {
    pub dispatch_count: u64,
    pub delivery_unknown_count: u64,
    pub observation_count: u64,
    pub pending_observation_count: u64,
    pub quarantine_count: u64,
    pub cancellation_count: u64,
    pub approval_count: u64,
    pub projection_outbox_count: u64,
    pub pending_projection_count: u64,
    pub terminal_output_outbox_count: u64,
    pub pending_terminal_output_count: u64,
    pub dispatch_route_binding_count: u64,
    pub content_candidate_count: u64,
    pub pending_content_candidate_count: u64,
    pub quarantined_content_candidate_count: u64,
    pub safe_content_ledger_count: u64,
    pub content_projection_outbox_count: u64,
    pub pending_content_projection_count: u64,
    pub next_observation_sequence: u64,
    pub next_content_sequence: u64,
}

pub struct AdapterEdge {
    connection: Connection,
    adapter_id: String,
    content_commitment_key: [u8; 32],
}

type StoredObservationRow = (
    String,
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
);

impl Drop for AdapterEdge {
    fn drop(&mut self) {
        self.content_commitment_key.zeroize();
    }
}

impl AdapterEdge {
    pub fn open(config: AdapterEdgeConfig) -> Result<Self, AdapterEdgeError> {
        if config.adapter_id.trim().is_empty() || config.store_epoch.trim().is_empty() {
            return Err(AdapterEdgeError::StoreGenerationMismatch);
        }
        if let Some(parent) = config.database_path.parent() {
            fs::create_dir_all(parent).map_err(AdapterEdgeError::Directory)?;
        }
        let content_commitment_key = hmac_sha256_bytes(
            &config.key.0,
            b"egopulse/harness-content/credential-commitment-key/v1",
        )?;
        let mut connection = Connection::open(&config.database_path)?;
        connection.pragma_update(None, "key", format!("x'{}'", hex::encode(config.key.0)))?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_| AdapterEdgeError::CipherUnavailable)?;
        if cipher_version.trim().is_empty() {
            return Err(AdapterEdgeError::CipherUnavailable);
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        Migrations::new(vec![
            M::up(SCHEMA_V1),
            M::up(SCHEMA_V2),
            M::up(SCHEMA_V3),
            M::up(SCHEMA_V4),
            M::up(SCHEMA_V5),
            M::up(SCHEMA_V6),
        ])
        .to_latest(&mut connection)?;

        backfill_approval_projection_outbox(&mut connection)?;
        let schema_digest = sha256(
            format!("{SCHEMA_V1}\n{SCHEMA_V2}\n{SCHEMA_V3}\n{SCHEMA_V4}\n{SCHEMA_V5}\n{SCHEMA_V6}")
                .as_bytes(),
        );
        let prior_v5_schema_digest = sha256(
            format!("{SCHEMA_V1}\n{SCHEMA_V2}\n{SCHEMA_V3}\n{SCHEMA_V4}\n{SCHEMA_V5}").as_bytes(),
        );
        let prior_v4_schema_digest =
            sha256(format!("{SCHEMA_V1}\n{SCHEMA_V2}\n{SCHEMA_V3}\n{SCHEMA_V4}").as_bytes());
        let prior_v3_schema_digest =
            sha256(format!("{SCHEMA_V1}\n{SCHEMA_V2}\n{SCHEMA_V3}").as_bytes());
        let prior_v2_schema_digest = sha256(format!("{SCHEMA_V1}\n{SCHEMA_V2}").as_bytes());
        let prior_v1_schema_digest = sha256(SCHEMA_V1.as_bytes());
        connection.execute(
            "UPDATE adapter_edge_metadata SET schema_profile_sha256 = ?1
             WHERE singleton = 1 AND schema_profile_id = ?2
               AND schema_profile_sha256 IN (?3, ?4, ?5, ?6, ?7)",
            params![
                schema_digest,
                SCHEMA_PROFILE_ID,
                prior_v5_schema_digest,
                prior_v4_schema_digest,
                prior_v3_schema_digest,
                prior_v2_schema_digest,
                prior_v1_schema_digest
            ],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO adapter_edge_metadata(
               singleton, adapter_id, store_epoch, schema_profile_id,
               schema_profile_sha256, next_observation_sequence
             ) VALUES(1, ?1, ?2, ?3, ?4, 1)",
            params![
                config.adapter_id,
                config.store_epoch,
                SCHEMA_PROFILE_ID,
                schema_digest
            ],
        )?;
        let metadata: (String, String, String, String) = connection.query_row(
            "SELECT adapter_id, store_epoch, schema_profile_id, schema_profile_sha256
             FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if metadata.0 != config.adapter_id
            || metadata.1 != config.store_epoch
            || metadata.2 != SCHEMA_PROFILE_ID
            || metadata.3 != schema_digest
        {
            return Err(AdapterEdgeError::StoreGenerationMismatch);
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        Ok(Self {
            connection,
            adapter_id: config.adapter_id,
            content_commitment_key,
        })
    }

    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub fn prepare_dispatch(
        &mut self,
        envelope: &DispatchEnvelope,
        now_seconds: i64,
    ) -> Result<DispatchPreparation, AdapterEdgeError> {
        self.prepare_dispatch_with_relation_policy(
            envelope,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
            now_seconds,
        )
    }

    pub fn prepare_dispatch_with_relation_policy(
        &mut self,
        envelope: &DispatchEnvelope,
        relation_policy: FinalArtifactRelationPolicy,
        now_seconds: i64,
    ) -> Result<DispatchPreparation, AdapterEdgeError> {
        let encoded = envelope.encode_to_vec();
        let envelope_digest = sha256(&encoded);
        let existing: Option<(String, Option<Vec<u8>>, String)> = self
            .connection
            .query_row(
                "SELECT delivery_state, receipt, envelope_digest_sha256
                 FROM adapter_dispatches WHERE dispatch_id = ?1",
                [&envelope.dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((state, receipt, prior_digest)) = existing {
            if prior_digest != envelope_digest {
                return Err(AdapterEdgeError::DispatchConflict);
            }
            let stored_policy: String = self.connection.query_row(
                "SELECT policy FROM adapter_dispatch_relation_policy WHERE dispatch_id = ?1",
                [&envelope.dispatch_id],
                |row| row.get(0),
            )?;
            if stored_policy != relation_policy_name(relation_policy) {
                return Err(AdapterEdgeError::DispatchConflict);
            }
            if let Some(receipt) = receipt {
                return Ok(DispatchPreparation::Replay(Box::new(
                    DispatchReceipt::decode(receipt.as_slice())?,
                )));
            }
            return Ok(if state == "prepared" {
                DispatchPreparation::Ready
            } else {
                DispatchPreparation::DeliveryUnknown
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO adapter_dispatches(
               dispatch_id, attempt_id, fencing_token, dispatch_fingerprint,
               envelope_digest_sha256, envelope, delivery_state,
               created_at_seconds, updated_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'prepared', ?7, ?7)",
            params![
                envelope.dispatch_id,
                envelope.attempt_id,
                envelope.fencing_token as i64,
                envelope.dispatch_fingerprint,
                envelope_digest,
                encoded,
                now_seconds
            ],
        )?;
        transaction.execute(
            "INSERT INTO adapter_dispatch_relation_policy(
               dispatch_id, policy, policy_version, created_at_seconds
             ) VALUES(?1, ?2, 1, ?3)",
            params![
                envelope.dispatch_id,
                relation_policy_name(relation_policy),
                now_seconds
            ],
        )?;
        if let Some(binding) = envelope.route_binding.as_ref() {
            transaction.execute(
                "INSERT INTO adapter_dispatch_route_bindings(
                   dispatch_id, route_binding_digest_sha256, route_binding, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![
                    envelope.dispatch_id,
                    binding.route_binding_sha256,
                    binding.encode_to_vec(),
                    now_seconds
                ],
            )?;
        }
        transaction.commit()?;
        Ok(DispatchPreparation::Ready)
    }

    pub fn dispatch_route_binding(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchRouteBinding>, AdapterEdgeError> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT route_binding FROM adapter_dispatch_route_bindings WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| DispatchRouteBinding::decode(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    pub fn delivered_dispatch_receipt(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchReceipt>, AdapterEdgeError> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM adapter_dispatches
                 WHERE dispatch_id = ?1 AND delivery_state = 'delivered' AND receipt IS NOT NULL",
                [dispatch_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| DispatchReceipt::decode(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    pub fn begin_delivery(
        &mut self,
        dispatch_id: &str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        let changed = self.connection.execute(
            "UPDATE adapter_dispatches
             SET delivery_state = 'delivery_unknown', updated_at_seconds = ?1
             WHERE dispatch_id = ?2 AND delivery_state = 'prepared' AND receipt IS NULL",
            params![now_seconds, dispatch_id],
        )?;
        if changed != 1 {
            return Err(AdapterEdgeError::DispatchStateConflict);
        }
        Ok(())
    }

    pub fn record_dispatch_receipt(
        &mut self,
        receipt: &DispatchReceipt,
        raw_evidence: &[u8],
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        let state = match DeliveryDisposition::try_from(receipt.disposition) {
            Ok(DeliveryDisposition::Delivered) => "delivered",
            Ok(DeliveryDisposition::Rejected) => "rejected",
            _ => "delivery_unknown",
        };
        let changed = self.connection.execute(
            "UPDATE adapter_dispatches
             SET delivery_state = ?1, receipt = ?2, delivery_raw_evidence = ?3,
                 updated_at_seconds = ?4
             WHERE dispatch_id = ?5 AND delivery_state = 'delivery_unknown'",
            params![
                state,
                receipt.encode_to_vec(),
                raw_evidence,
                now_seconds,
                receipt.dispatch_id
            ],
        )?;
        if changed != 1 {
            let existing: Option<Vec<u8>> = self
                .connection
                .query_row(
                    "SELECT receipt FROM adapter_dispatches WHERE dispatch_id = ?1",
                    [&receipt.dispatch_id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            if existing.as_deref() != Some(receipt.encode_to_vec().as_slice()) {
                return Err(AdapterEdgeError::DispatchStateConflict);
            }
        }
        Ok(())
    }

    pub fn append_observation(
        &mut self,
        dispatch_id: &str,
        native_key: &str,
        raw_event: &[u8],
        observation: HarnessObservation,
        now_seconds: i64,
    ) -> Result<ObservationAppend, AdapterEdgeError> {
        self.append_observation_with_terminal_output(
            dispatch_id,
            native_key,
            raw_event,
            observation,
            None,
            now_seconds,
        )
    }

    pub fn bind_dispatch_task_lineage(
        &mut self,
        dispatch_id: &str,
        task_id: &str,
        task_revision: u64,
        work_revision: u64,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        if task_id.trim().is_empty() || task_revision == 0 || work_revision == 0 {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let task_revision =
            i64::try_from(task_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        let work_revision =
            i64::try_from(work_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO adapter_dispatch_task_lineage(
               dispatch_id, task_id, task_revision, work_revision, bound_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                dispatch_id,
                task_id,
                task_revision,
                work_revision,
                now_seconds
            ],
        )?;
        if changed == 1 {
            return Ok(());
        }
        let existing: Option<(String, i64, i64)> = self
            .connection
            .query_row(
                "SELECT task_id, task_revision, work_revision
                 FROM adapter_dispatch_task_lineage WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if existing == Some((task_id.to_owned(), task_revision, work_revision)) {
            Ok(())
        } else {
            Err(AdapterEdgeError::DispatchConflict)
        }
    }

    pub fn dispatch_task_lineage(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchTaskLineage>, AdapterEdgeError> {
        let value: Option<(String, i64, i64)> = self
            .connection
            .query_row(
                "SELECT task_id, task_revision, work_revision
                 FROM adapter_dispatch_task_lineage WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        value
            .map(|(task_id, task_revision, work_revision)| {
                let task_revision =
                    u64::try_from(task_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
                let work_revision =
                    u64::try_from(work_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
                if task_id.trim().is_empty() || task_revision == 0 || work_revision == 0 {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                Ok(DispatchTaskLineage {
                    task_id,
                    task_revision,
                    work_revision,
                })
            })
            .transpose()
    }

    pub fn append_observation_with_terminal_output(
        &mut self,
        dispatch_id: &str,
        native_key: &str,
        raw_event: &[u8],
        mut observation: HarnessObservation,
        terminal_output: Option<&TerminalOutputCandidate>,
        now_seconds: i64,
    ) -> Result<ObservationAppend, AdapterEdgeError> {
        let digest = sha256(raw_event);
        let content_signal = match observation.payload.as_ref() {
            Some(harness_observation::Payload::ContentSignal(signal)) => {
                let candidate = signal
                    .candidate
                    .as_ref()
                    .ok_or(AdapterEdgeError::IntegrityFailure)?;
                if signal.content_event_id.trim().is_empty()
                    || !is_sha256(&signal.delivered_receipt_digest_sha256)
                    || !is_sha256(&signal.dispatch_route_binding_sha256)
                    || !is_sha256(&candidate.candidate_digest_sha256)
                    || signal.context_consumption_proof.is_none()
                {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                Some(signal.clone())
            }
            _ => None,
        };
        if terminal_output.is_some_and(|candidate| {
            candidate.dispatch_id != dispatch_id
                || candidate.native_completion_ref.trim().is_empty()
                || candidate.media_type.trim().is_empty()
        }) {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let dispatch_registered: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM adapter_dispatches WHERE dispatch_id = ?1)",
            [dispatch_id],
            |row| row.get(0),
        )?;
        if !dispatch_registered {
            return Err(AdapterEdgeError::DispatchNotFound(dispatch_id.to_owned()));
        }
        let existing: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT native_event_digest_sha256, observation
                 FROM adapter_observations
                 WHERE dispatch_id = ?1 AND native_key = ?2",
                params![dispatch_id, native_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((prior_digest, prior_observation)) = existing {
            if prior_digest == digest {
                if let Some(signal) = content_signal.as_ref() {
                    let prior = HarnessObservation::decode(prior_observation.as_slice())?;
                    if prior.payload.as_ref()
                        != Some(&harness_observation::Payload::ContentSignal(signal.clone()))
                    {
                        return Err(AdapterEdgeError::SequenceConflict);
                    }
                }
                if let Some(candidate) = terminal_output {
                    let prior_candidate_digest: Option<String> = transaction
                        .query_row(
                            "SELECT payload_digest_sha256
                             FROM adapter_terminal_output_outbox
                             WHERE source_observation_id = (
                               SELECT observation_id FROM adapter_observations
                               WHERE dispatch_id = ?1 AND native_key = ?2
                             )",
                            params![dispatch_id, native_key],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if prior_candidate_digest.as_deref()
                        != Some(terminal_output_payload_digest(candidate).as_str())
                    {
                        return Err(AdapterEdgeError::SequenceConflict);
                    }
                }
                transaction.commit()?;
                return Ok(ObservationAppend::Replay(HarnessObservation::decode(
                    prior_observation.as_slice(),
                )?));
            }
            transaction.execute(
                "INSERT INTO adapter_quarantine(
                   quarantine_id, dispatch_id, native_key, prior_digest_sha256,
                   conflicting_digest_sha256, raw_event, reason_code, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'SEQUENCE_CONFLICT', ?7)",
                params![
                    Uuid::now_v7().to_string(),
                    dispatch_id,
                    native_key,
                    prior_digest,
                    digest,
                    raw_event,
                    now_seconds
                ],
            )?;
            transaction.commit()?;
            return Err(AdapterEdgeError::SequenceConflict);
        }

        let sequence: i64 = transaction.query_row(
            "SELECT next_observation_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE adapter_edge_metadata
             SET next_observation_sequence = next_observation_sequence + 1
             WHERE singleton = 1",
            [],
        )?;
        let observation_id = if observation.observation_id.trim().is_empty() {
            Uuid::now_v7().to_string()
        } else {
            observation.observation_id.clone()
        };
        let raw_evidence_ref = format!("adapter-edge://{}/raw/{observation_id}", self.adapter_id);
        observation.observation_id = observation_id.clone();
        observation.adapter_id = self.adapter_id.clone();
        observation.observation_sequence = sequence as u64;
        observation.native_event_digest_sha256 = digest.clone();
        observation.raw_evidence_ref = raw_evidence_ref.clone();
        let encoded = observation.encode_to_vec();
        let is_approval = matches!(
            observation.payload.as_ref(),
            Some(harness_observation::Payload::ApprovalRequest(_))
        );
        let approval_projection = is_approval
            .then(|| sanitized_approval_projection(&observation))
            .transpose()?;
        transaction.execute(
            "INSERT INTO adapter_observations(
               observation_id, dispatch_id, attempt_id, fencing_token,
               observation_sequence, native_key, native_event_digest_sha256,
               raw_evidence_ref, raw_event, observation, ingestion_state,
               created_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11)",
            params![
                observation_id,
                dispatch_id,
                observation.attempt_id,
                observation.fencing_token as i64,
                sequence,
                native_key,
                digest,
                raw_evidence_ref,
                raw_event,
                encoded,
                now_seconds
            ],
        )?;
        if let Some(signal) = content_signal.as_ref() {
            let candidate = signal
                .candidate
                .as_ref()
                .expect("validated content signal has candidate");
            transaction.execute(
                "INSERT INTO adapter_content_candidates(
                   content_event_id, source_observation_id, dispatch_id,
                   candidate_digest_sha256, content_signal, projection_state,
                   created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![
                    signal.content_event_id,
                    observation_id,
                    dispatch_id,
                    candidate.candidate_digest_sha256,
                    signal.encode_to_vec(),
                    now_seconds
                ],
            )?;
        }
        if is_approval {
            let projection_payload = approval_projection
                .as_ref()
                .expect("approval projection created after typed match");
            transaction.execute(
                "INSERT INTO adapter_projection_outbox(
                   message_id, source_observation_id, source_revision,
                   payload_digest_sha256, payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![
                    format!("adapter-projection-{observation_id}"),
                    observation_id,
                    sequence,
                    sha256(projection_payload),
                    projection_payload,
                    now_seconds
                ],
            )?;
        }
        if let Some(candidate) = terminal_output {
            let original_content_bytes = i64::try_from(candidate.content.len())
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let content_complete = candidate.content.len() <= TERMINAL_OUTPUT_FULL_BYTES;
            let captured_content = if content_complete {
                candidate.content.as_slice()
            } else {
                &candidate.content[..TERMINAL_OUTPUT_PREVIEW_BYTES]
            };
            transaction.execute(
                "INSERT INTO adapter_terminal_output_outbox(
                   message_id, source_observation_id, source_revision,
                   payload_digest_sha256, dispatch_id, native_completion_ref,
                   media_type, content_digest_sha256, original_content_bytes,
                   captured_content, captured_content_digest_sha256, content_complete,
                   delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'pending', ?13)",
                params![
                    format!("adapter-terminal-output-{observation_id}"),
                    observation_id,
                    sequence,
                    terminal_output_payload_digest(candidate),
                    dispatch_id,
                    candidate.native_completion_ref,
                    candidate.media_type,
                    sha256(&candidate.content),
                    original_content_bytes,
                    captured_content,
                    sha256(captured_content),
                    i64::from(content_complete),
                    now_seconds
                ],
            )?;
        }
        transaction.commit()?;
        Ok(ObservationAppend::Committed(observation))
    }

    pub fn pending_content_candidates(
        &self,
    ) -> Result<Vec<PendingContentCandidate>, AdapterEdgeError> {
        let mut statement = self.connection.prepare(
            "SELECT o.observation, c.content_signal
             FROM adapter_content_candidates c
             JOIN adapter_observations o ON o.observation_id = c.source_observation_id
             WHERE c.projection_state = 'pending'
             ORDER BY o.observation_sequence",
        )?;
        let encoded = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        encoded
            .into_iter()
            .map(|(observation, signal)| {
                Ok(PendingContentCandidate {
                    observation: HarnessObservation::decode(observation.as_slice())?,
                    signal: HarnessContentSignalObservation::decode(signal.as_slice())?,
                })
            })
            .collect()
    }

    pub(crate) fn settle_replayed_content_candidate(
        &mut self,
        content_event_id: &str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        if self.connection.execute(
            "UPDATE adapter_content_candidates
             SET projection_state = 'projected', projected_at_seconds = ?1
             WHERE content_event_id = ?2 AND projection_state = 'pending'",
            params![now_seconds, content_event_id],
        )? == 1
        {
            Ok(())
        } else {
            Err(AdapterEdgeError::SequenceConflict)
        }
    }

    pub(crate) fn content_scope_limit_kind(
        &self,
        task_id: &str,
        attempt_id: &str,
    ) -> Result<Option<HarnessContentLimitKind>, AdapterEdgeError> {
        if task_id.trim().is_empty() || attempt_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let transaction = self.connection.unchecked_transaction()?;
        let (attempt, task) =
            verified_content_budgets_from_owner_history(&transaction, task_id, attempt_id)?;
        transaction.commit()?;
        Ok(winning_limit_kind([
            task.terminal_kind,
            attempt.terminal_kind,
        ]))
    }

    pub(crate) fn settle_limited_content_candidate(
        &mut self,
        content_event_id: &str,
        candidate_digest_sha256: &str,
        limit_kind: HarnessContentLimitKind,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        if content_event_id.trim().is_empty()
            || !is_sha256(candidate_digest_sha256)
            || limit_kind == HarnessContentLimitKind::Unspecified
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let mut bytes = Vec::new();
        frame_bytes(
            &mut bytes,
            b"egopulse/harness-content/suppressed-candidate/v1",
        );
        frame_bytes(&mut bytes, content_event_id.as_bytes());
        frame_bytes(&mut bytes, candidate_digest_sha256.as_bytes());
        let projection_digest = sha256(&bytes);
        let empty_digest = committed_records_digest(&[]);
        let changed = self.connection.execute(
            "UPDATE adapter_content_candidates
             SET projection_state = 'projected', safe_projection_digest_sha256 = ?1,
                 committed_records_digest_sha256 = ?2, limit_kind = ?3,
                 projected_at_seconds = ?4
             WHERE content_event_id = ?5 AND candidate_digest_sha256 = ?6
               AND projection_state = 'pending'",
            params![
                projection_digest,
                empty_digest,
                limit_kind_name(limit_kind),
                now_seconds,
                content_event_id,
                candidate_digest_sha256,
            ],
        )?;
        if changed != 1 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        Ok(())
    }

    pub(crate) fn quarantine_content_candidate(
        &mut self,
        content_event_id: &str,
        reason_code: &'static str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        if self.connection.execute(
            "UPDATE adapter_content_candidates
             SET projection_state = 'quarantined', quarantine_reason_code = ?1,
                 projected_at_seconds = ?2
             WHERE content_event_id = ?3 AND projection_state = 'pending'",
            params![reason_code, now_seconds, content_event_id],
        )? == 1
        {
            Ok(())
        } else {
            Err(AdapterEdgeError::SequenceConflict)
        }
    }

    /// Binds the ephemeral managed-credential variant set to the first safe
    /// projection for a dispatch. Only the keyed commitment is persisted.
    /// A later profile/credential mismatch permanently narrows the remaining
    /// dispatch projection to structured-only without rewriting safe records.
    pub fn verify_or_bind_content_disclosure(
        &mut self,
        dispatch_id: &str,
        managed_credentials: Option<&[String]>,
        now_seconds: i64,
    ) -> Result<ContentDisclosureMode, AdapterEdgeError> {
        if dispatch_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let variants =
            managed_credentials.and_then(|values| canonical_credential_variants(values).ok());
        let commitment = variants
            .as_ref()
            .map(|variants| {
                let mut input = Vec::new();
                frame_bytes(&mut input, b"egopulse/harness-content/credential-set/v1");
                frame_bytes(&mut input, &(variants.len() as u64).to_le_bytes());
                for variant in variants {
                    frame_bytes(&mut input, variant.as_bytes());
                }
                hmac_sha256_bytes(&self.content_commitment_key, &input).map(hex::encode)
            })
            .transpose()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let dispatch_exists: bool = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM adapter_dispatches d
               JOIN adapter_dispatch_route_bindings r ON r.dispatch_id = d.dispatch_id
               WHERE d.dispatch_id = ?1
             )",
            [dispatch_id],
            |row| row.get(0),
        )?;
        if !dispatch_exists {
            return Err(AdapterEdgeError::DispatchNotFound(dispatch_id.to_owned()));
        }
        let existing: Option<(String, Option<String>, bool)> = transaction
            .query_row(
                "SELECT disclosure_profile_digest_sha256,
                        credential_commitment_hmac_sha256, structured_only
                 FROM adapter_content_redaction_bindings WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let mode = match existing {
            None => {
                let structured_only = commitment.is_none();
                transaction.execute(
                    "INSERT INTO adapter_content_redaction_bindings(
                       dispatch_id, disclosure_profile_digest_sha256,
                       credential_commitment_hmac_sha256, structured_only,
                       created_at_seconds, updated_at_seconds
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
                    params![
                        dispatch_id,
                        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
                        commitment,
                        structured_only,
                        now_seconds
                    ],
                )?;
                if structured_only {
                    ContentDisclosureMode::StructuredOnly
                } else {
                    ContentDisclosureMode::Full
                }
            }
            Some((profile, stored_commitment, already_structured_only)) => {
                let exact = profile == HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
                    && stored_commitment == commitment
                    && commitment.is_some();
                if already_structured_only || !exact {
                    transaction.execute(
                        "UPDATE adapter_content_redaction_bindings
                         SET structured_only = 1, updated_at_seconds = ?1
                         WHERE dispatch_id = ?2",
                        params![now_seconds, dispatch_id],
                    )?;
                    ContentDisclosureMode::StructuredOnly
                } else {
                    ContentDisclosureMode::Full
                }
            }
        };
        transaction.commit()?;
        Ok(mode)
    }

    pub fn commit_safe_content_projection(
        &mut self,
        projection: &SafeContentProjection,
        now_seconds: i64,
    ) -> Result<SafeContentCommit, AdapterEdgeError> {
        let source_records = projection.records();
        let Some(first_record) = source_records.first() else {
            return Err(AdapterEdgeError::IntegrityFailure);
        };
        for (expected_part, record) in source_records.iter().enumerate() {
            if record.record_id.trim().is_empty()
                || record.content_event_id.trim().is_empty()
                || record.task_id.trim().is_empty()
                || record.attempt_id.trim().is_empty()
                || record.content_event_id != first_record.content_event_id
                || record.task_id != first_record.task_id
                || record.attempt_id != first_record.attempt_id
                || record.dispatch_id != first_record.dispatch_id
                || !projection_record_position_is_valid(record, expected_part, source_records.len())
                || safe_record_text_bytes(record) > CONTENT_SAFE_PART_BYTES as u64
                || !is_sha256(&record.record_digest_sha256)
                || canonical_safe_record_digest(record).as_deref()
                    != Some(record.record_digest_sha256.as_str())
                || record
                    .disclosure_profile_ref
                    .as_ref()
                    .is_none_or(|profile| {
                        profile.sha256 != HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
                    })
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
        }
        let input_digest = safe_projection_input_digest(projection);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate_state: Option<StoredContentCandidateState> = transaction
            .query_row(
                "SELECT projection_state, safe_projection_digest_sha256,
                            committed_records_digest_sha256, limit_kind
                     FROM adapter_content_candidates WHERE content_event_id = ?1",
                [&first_record.content_event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((candidate_state, stored_input_digest, stored_records_digest, stored_limit_kind)) =
            candidate_state
        else {
            return Err(AdapterEdgeError::IntegrityFailure);
        };
        if candidate_state == "projected" {
            if stored_input_digest.as_deref() != Some(input_digest.as_str())
                || stored_records_digest
                    .as_deref()
                    .is_none_or(|digest| !is_sha256(digest))
            {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            let existing = {
                let mut statement = transaction.prepare(
                    "SELECT part_index, safe_record, content_sequence
                     FROM adapter_safe_content_ledger WHERE content_event_id = ?1
                     ORDER BY part_index",
                )?;
                statement
                    .query_map([&first_record.content_event_id], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let mut replay_records = Vec::with_capacity(existing.len());
            for (expected_part, (part_index, bytes, _)) in existing.iter().enumerate() {
                let record = SafeHarnessContentRecord::decode(bytes.as_slice())?;
                if *part_index != expected_part as i64
                    || !projection_record_position_is_valid(&record, expected_part, existing.len())
                    || canonical_safe_record_digest(&record).as_deref()
                        != Some(record.record_digest_sha256.as_str())
                {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                replay_records.push(record);
            }
            let stored_limit_kind = decode_stored_limit_kind(stored_limit_kind.as_deref())?;
            if stored_records_digest.as_deref()
                != Some(committed_records_digest(&replay_records).as_str())
                || (!replay_records.is_empty()
                    && stored_limit_kind != committed_limit_kind(&replay_records)?)
                || !assembly_checkpoint_matches(
                    &transaction,
                    &first_record.dispatch_id,
                    projection.checkpoint.as_ref(),
                    &replay_records,
                )?
            {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            if replay_records.is_empty() {
                if stored_limit_kind.is_none() {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                transaction.commit()?;
                return Ok(SafeContentCommit::Suppressed {
                    content_event_id: first_record.content_event_id.clone(),
                });
            }
            let first_sequence =
                u64::try_from(existing[0].2).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let last_sequence = u64::try_from(existing[existing.len() - 1].2)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            transaction.commit()?;
            return Ok(SafeContentCommit::Replay {
                records: replay_records,
                first_sequence,
                last_sequence,
            });
        }
        if candidate_state != "pending"
            || stored_input_digest.is_some()
            || stored_records_digest.is_some()
            || stored_limit_kind.is_some()
        {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        let (attempt_budget, task_budget) = verified_content_budgets_from_owner_history(
            &transaction,
            &first_record.task_id,
            &first_record.attempt_id,
        )?;
        let admission = admit_content_records(
            source_records,
            attempt_budget,
            task_budget,
            CONTENT_BUDGET_LIMITS,
        )?;
        let committed_digest = committed_records_digest(&admission.records);
        if admission.records.is_empty() {
            let changed = transaction.execute(
                "UPDATE adapter_content_candidates
                 SET projection_state = 'projected', safe_projection_digest_sha256 = ?1,
                     committed_records_digest_sha256 = ?2, limit_kind = ?3,
                     projected_at_seconds = ?4
                 WHERE content_event_id = ?5 AND projection_state = 'pending'",
                params![
                    input_digest,
                    committed_digest,
                    admission.limit_kind.map(limit_kind_name),
                    now_seconds,
                    first_record.content_event_id,
                ],
            )?;
            if changed != 1 || admission.limit_kind.is_none() {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            transaction.commit()?;
            return Ok(SafeContentCommit::Suppressed {
                content_event_id: first_record.content_event_id.clone(),
            });
        }
        let records = admission.records;
        let mut encoded = Vec::with_capacity(records.len());
        for (expected_part, record) in records.iter().enumerate() {
            if !projection_record_position_is_valid(record, expected_part, records.len())
                || canonical_safe_record_digest(record).as_deref()
                    != Some(record.record_digest_sha256.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            encoded.push(record.encode_to_vec());
        }
        let first_sequence: i64 = transaction.query_row(
            "SELECT next_content_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let mut sequenced = Vec::with_capacity(records.len());
        for (index, (record, encoded)) in records.iter().zip(encoded).enumerate() {
            let sequence = first_sequence
                .checked_add(i64::try_from(index).map_err(|_| AdapterEdgeError::IntegrityFailure)?)
                .ok_or(AdapterEdgeError::IntegrityFailure)?;
            let event = SafeHarnessContentProjectionEvent {
                payload: Some(
                    egopulse_domain_contracts::v01::egopulse::harness::v1::safe_harness_content_projection_event::Payload::ContentRecord(
                        record.clone(),
                    ),
                ),
            };
            let event_bytes = event.encode_to_vec();
            transaction.execute(
                "INSERT INTO adapter_safe_content_ledger(
                   record_id, content_event_id, part_index, task_id, record_digest_sha256,
                   content_sequence, safe_record, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    record.record_id,
                    record.content_event_id,
                    i64::try_from(index).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                    record.task_id,
                    record.record_digest_sha256,
                    sequence,
                    encoded,
                    now_seconds
                ],
            )?;
            transaction.execute(
                "INSERT INTO adapter_content_projection_outbox(
                   message_id, source_record_id, source_revision, payload_digest_sha256,
                   payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![
                    format!("adapter-content-{}", record.record_id),
                    record.record_id,
                    sequence,
                    sha256(&event_bytes),
                    event_bytes,
                    now_seconds
                ],
            )?;
            sequenced.push((sequence, record));
        }
        let changed = transaction.execute(
            "UPDATE adapter_content_candidates
             SET projection_state = 'projected', safe_projection_digest_sha256 = ?1,
                 committed_records_digest_sha256 = ?2, limit_kind = ?3,
                 projected_at_seconds = ?4
             WHERE content_event_id = ?5 AND projection_state = 'pending'",
            params![
                input_digest,
                committed_digest,
                admission.limit_kind.map(limit_kind_name),
                now_seconds,
                first_record.content_event_id,
            ],
        )?;
        if changed != 1 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        upsert_content_assembly_checkpoint(
            &transaction,
            projection.checkpoint.as_ref(),
            &records,
            now_seconds,
        )?;
        update_content_owner_metadata(
            &transaction,
            &first_record.task_id,
            &sequenced,
            now_seconds,
        )?;
        let record_count_u64 = records.len() as u64;
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "attempt",
                scope_id: &first_record.attempt_id,
                previous: attempt_budget,
                added_text_bytes: admission.text_bytes,
                added_records: record_count_u64,
                terminal_kind: admission.attempt_terminal_kind,
            },
            now_seconds,
        )?;
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "task",
                scope_id: &first_record.task_id,
                previous: task_budget,
                added_text_bytes: admission.text_bytes,
                added_records: record_count_u64,
                terminal_kind: admission.task_terminal_kind,
            },
            now_seconds,
        )?;
        let record_count =
            i64::try_from(records.len()).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        transaction.execute(
            "UPDATE adapter_edge_metadata
             SET next_content_sequence = next_content_sequence + ?1 WHERE singleton = 1",
            [record_count],
        )?;
        let last_sequence = first_sequence
            .checked_add(record_count - 1)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        transaction.commit()?;
        Ok(SafeContentCommit::Committed {
            records,
            first_sequence: u64::try_from(first_sequence)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            last_sequence: u64::try_from(last_sequence)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
        })
    }

    pub fn pending_safe_content_projection(
        &self,
    ) -> Result<Vec<SafeContentProjectionMessage>, AdapterEdgeError> {
        self.safe_content_projection_messages(false)
    }

    pub fn safe_content_budget_snapshot(
        &self,
        task_id: &str,
        attempt_id: &str,
    ) -> Result<SafeContentBudgetSnapshot, AdapterEdgeError> {
        if task_id.trim().is_empty() || attempt_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let transaction = self.connection.unchecked_transaction()?;
        let attempt = load_content_budget(&transaction, "attempt", attempt_id)?;
        let task = load_content_budget(&transaction, "task", task_id)?;
        transaction.commit()?;
        Ok(SafeContentBudgetSnapshot {
            attempt: attempt.into(),
            task: task.into(),
        })
    }

    /// Returns both pending and acknowledged safe events for Local Read Model
    /// rebuild. The bytes come only from the Adapter-owned safe outbox and do
    /// not revisit raw candidates or the current redaction configuration.
    pub fn retained_safe_content_projection_for_rebuild(
        &self,
    ) -> Result<Vec<SafeContentProjectionMessage>, AdapterEdgeError> {
        self.safe_content_projection_messages(true)
    }

    fn safe_content_projection_messages(
        &self,
        include_consumed: bool,
    ) -> Result<Vec<SafeContentProjectionMessage>, AdapterEdgeError> {
        let transaction = self.connection.unchecked_transaction()?;
        let mut statement = transaction.prepare(
            "SELECT message_id, source_record_id, source_revision, payload_digest_sha256, payload
             FROM adapter_content_projection_outbox
             WHERE ((?1 = 0 AND delivery_state = 'pending')
                OR (?1 = 1 AND delivery_state IN ('pending', 'consumed')))
             ORDER BY source_revision",
        )?;
        let rows = statement
            .query_map([i64::from(include_consumed)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let messages = rows
            .into_iter()
            .map(
                |(
                    message_id,
                    source_record_id,
                    source_revision,
                    payload_digest_sha256,
                    payload,
                )| {
                    let source_revision = u64::try_from(source_revision)
                        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
                    let event = validate_safe_projection_outbox_payload(
                        &transaction,
                        &message_id,
                        &source_record_id,
                        source_revision,
                        &payload_digest_sha256,
                        &payload,
                    )?;
                    Ok(SafeContentProjectionMessage {
                        message_id,
                        source_revision,
                        payload_digest_sha256,
                        event,
                    })
                },
            )
            .collect::<Result<Vec<_>, AdapterEdgeError>>()?;
        transaction.commit()?;
        Ok(messages)
    }

    pub fn acknowledge_safe_content_projection(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, AdapterEdgeError> {
        if message_id.trim().is_empty() || !is_sha256(payload_digest_sha256) {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<(String, i64, String, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT source_record_id, source_revision, payload_digest_sha256, payload,
                        delivery_state
                 FROM adapter_content_projection_outbox WHERE message_id = ?1",
                [message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((source_record_id, source_revision, stored_digest, payload, state)) = row else {
            return Err(AdapterEdgeError::SequenceConflict);
        };
        let source_revision =
            u64::try_from(source_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        validate_safe_projection_outbox_payload(
            &transaction,
            message_id,
            &source_record_id,
            source_revision,
            &stored_digest,
            &payload,
        )?;
        if stored_digest != payload_digest_sha256 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        if state == "consumed" {
            transaction.commit()?;
            return Ok(false);
        }
        if state != "pending" {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        let changed = transaction.execute(
            "UPDATE adapter_content_projection_outbox SET delivery_state = 'consumed'
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2
                AND delivery_state = 'pending'",
            params![message_id, payload_digest_sha256],
        )?;
        if changed != 1 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn content_assembly_checkpoint(
        &self,
        dispatch_id: &str,
        message_id: &str,
    ) -> Result<Option<SafeContentAssemblyCheckpoint>, AdapterEdgeError> {
        let value: Option<(i64, bool, String, String, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT current_revision, finalized, raw_cumulative_digest_sha256,
                        safe_cumulative_digest_sha256, assembly_state
                 FROM adapter_content_assemblies
                 WHERE dispatch_id = ?1 AND message_id = ?2",
                params![dispatch_id, message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        value
            .map(|(revision, finalized, raw_digest, safe_digest, bytes)| {
                let (checkpoint, safe_records) = decode_assembly_state(&bytes)?;
                let revision =
                    u64::try_from(revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
                let valid = revision > 0
                    && is_sha256(&raw_digest)
                    && is_sha256(&safe_digest)
                    && checkpoint.message_id == message_id
                    && checkpoint.current_revision == revision
                    && checkpoint.finalized == finalized
                    && checkpoint.raw_cumulative_digest_sha256 == raw_digest
                    && checkpoint.safe_cumulative_digest_sha256 == safe_digest
                    && safe_records
                        .iter()
                        .all(|record| record.dispatch_id == dispatch_id);
                if !valid {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                Ok(SafeContentAssemblyCheckpoint {
                    dispatch_id: dispatch_id.to_owned(),
                    message_id: message_id.to_owned(),
                    current_revision: revision,
                    finalized,
                    raw_cumulative_digest_sha256: raw_digest,
                    safe_cumulative_digest_sha256: safe_digest,
                    safe_records,
                })
            })
            .transpose()
    }

    pub(crate) fn content_projection_checkpoint(
        &self,
        dispatch_id: &str,
        signal: &HarnessContentSignalObservation,
    ) -> Result<Option<ContentAssemblyCheckpoint>, AdapterEdgeError> {
        let Some(
            egopulse_domain_contracts::v01::egopulse::harness::v1::user_visible_content_candidate::Payload::AssistantText(
                assistant,
            ),
        ) = signal.candidate.as_ref().and_then(|candidate| candidate.payload.as_ref())
        else {
            return Ok(None);
        };
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT assembly_state FROM adapter_content_assemblies
                 WHERE dispatch_id = ?1 AND message_id = ?2",
                params![dispatch_id, assistant.message_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| decode_assembly_state(&bytes).map(|(checkpoint, _)| checkpoint))
            .transpose()
    }

    pub fn content_owner_snapshot(
        &self,
        task_id: &str,
    ) -> Result<Option<SafeContentOwnerSnapshot>, AdapterEdgeError> {
        let transaction = self.connection.unchecked_transaction()?;
        let snapshot = load_content_owner_snapshot(&transaction, task_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    /// Atomically installs an Adapter-owned terminal baseline, advances the
    /// history floor, deletes the compacted ledger/outbox range, and emits the
    /// typed compaction and tombstone events. Scheduling and terminal
    /// eligibility discovery remain the caller's responsibility.
    pub fn compact_terminal_safe_content(
        &mut self,
        request: &ContentRetentionCompactionRequest,
    ) -> Result<ContentRetentionCompactionReceipt, AdapterEdgeError> {
        if request.task_id.trim().is_empty()
            || request.attempt_id.trim().is_empty()
            || request.final_epoch.trim().is_empty()
            || request.expected_owner_sequence == 0
            || !valid_timestamp(Some(&request.terminal_committed_at))
            || !valid_timestamp(Some(&request.compacted_at))
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let eligible_seconds = request
            .terminal_committed_at
            .seconds
            .checked_add(CONTENT_MINIMUM_RETENTION_SECONDS)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        if request.compacted_at.seconds < eligible_seconds
            || (request.compacted_at.seconds == eligible_seconds
                && request.compacted_at.nanos < request.terminal_committed_at.nanos)
        {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        let compaction_id = history_compaction_id(
            &request.task_id,
            &request.attempt_id,
            &request.final_epoch,
            request.expected_owner_sequence,
        );
        let tombstone_id = retention_tombstone_id(
            &request.task_id,
            &request.attempt_id,
            &request.final_epoch,
            request.expected_owner_sequence,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let pending_relation: bool = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM adapter_final_artifact_relation_intents i
               JOIN adapter_dispatch_task_lineage l ON l.dispatch_id = i.dispatch_id
               WHERE l.task_id = ?1 AND i.relation_state = 'pending'
             )",
            [&request.task_id],
            |row| row.get(0),
        )?;
        if pending_relation {
            return Err(AdapterEdgeError::SequenceConflict);
        }

        let existing_tombstone: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT tombstone FROM adapter_content_retention_tombstones
                 WHERE tombstone_id = ?1",
                [&tombstone_id],
                |row| row.get(0),
            )
            .optional()?;
        let existing_compaction: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT payload FROM adapter_content_projection_outbox
                 WHERE source_record_id = ?1",
                [&compaction_id],
                |row| row.get(0),
            )
            .optional()?;
        if existing_tombstone.is_some() || existing_compaction.is_some() {
            let (Some(tombstone_bytes), Some(compaction_bytes)) =
                (existing_tombstone, existing_compaction)
            else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            let tombstone = HarnessContentRetentionTombstone::decode(tombstone_bytes.as_slice())?;
            let compaction_event =
                SafeHarnessContentProjectionEvent::decode(compaction_bytes.as_slice())?;
            let Some(safe_harness_content_projection_event::Payload::HistoryCompaction(compaction)) =
                compaction_event.payload
            else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            if canonical_retention_tombstone_digest(&tombstone).as_deref()
                != Some(tombstone.tombstone_digest_sha256.as_str())
                || canonical_history_compaction_digest(&compaction).as_deref()
                    != Some(compaction.compaction_record_digest_sha256.as_str())
                || tombstone.task_id != request.task_id
                || tombstone.attempt_id != request.attempt_id
                || tombstone.final_epoch != request.final_epoch
                || tombstone.final_sequence != request.expected_owner_sequence
                || tombstone.terminal_committed_at.as_ref() != Some(&request.terminal_committed_at)
                || tombstone.compacted_at.as_ref() != Some(&request.compacted_at)
                || compaction.compacted_at.as_ref() != Some(&request.compacted_at)
            {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            let owner_snapshot = load_content_owner_snapshot(&transaction, &request.task_id)?
                .ok_or(AdapterEdgeError::IntegrityFailure)?;
            if owner_snapshot.floor_sequence != request.expected_owner_sequence
                || owner_snapshot.owner_sequence != request.expected_owner_sequence
                || owner_snapshot.tombstones != [tombstone.clone()]
                || !owner_snapshot.records.is_empty()
                || compaction.owner_snapshot_digest_sha256 != owner_snapshot.snapshot_digest_sha256
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            transaction.commit()?;
            return Ok(ContentRetentionCompactionReceipt {
                owner_snapshot,
                compaction,
                tombstone,
            });
        }

        let current = load_content_owner_snapshot(&transaction, &request.task_id)?
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        if current.owner_sequence != request.expected_owner_sequence
            || current.floor_sequence >= request.expected_owner_sequence
            || current.records.is_empty()
        {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        let unsettled_outbox: i64 = transaction.query_row(
            "SELECT count(*) FROM adapter_content_projection_outbox o
             JOIN adapter_safe_content_ledger l ON l.record_id = o.source_record_id
             WHERE l.task_id = ?1 AND l.content_sequence <= ?2
               AND o.delivery_state != 'consumed'",
            params![
                request.task_id,
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            ],
            |row| row.get(0),
        )?;
        if unsettled_outbox != 0 {
            return Err(AdapterEdgeError::SequenceConflict);
        }

        let final_safe_content_digest_sha256 = current.snapshot_digest_sha256.clone();
        let mut tombstone = HarnessContentRetentionTombstone {
            tombstone_id,
            tombstone_digest_sha256: String::new(),
            task_id: request.task_id.clone(),
            attempt_id: request.attempt_id.clone(),
            final_epoch: request.final_epoch.clone(),
            final_sequence: request.expected_owner_sequence,
            final_safe_content_digest_sha256: final_safe_content_digest_sha256.clone(),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            terminal_committed_at: Some(request.terminal_committed_at),
            compacted_at: Some(request.compacted_at),
            reason: HarnessContentRetentionReason::TerminalMinimumExpired as i32,
        };
        tombstone.tombstone_digest_sha256 = canonical_retention_tombstone_digest(&tombstone)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let baseline_records = Vec::new();
        let baseline_tombstones = vec![tombstone.clone()];
        let baseline_state = encode_content_owner_baseline(&baseline_records, &baseline_tombstones);
        let owner_snapshot_digest_sha256 = content_owner_snapshot_digest(
            &request.task_id,
            request.expected_owner_sequence,
            request.expected_owner_sequence,
            &baseline_records,
            &baseline_tombstones,
        );
        let mut compaction = HarnessContentHistoryCompactionRecord {
            compaction_record_id: compaction_id,
            compaction_record_digest_sha256: String::new(),
            task_id: request.task_id.clone(),
            attempt_id: request.attempt_id.clone(),
            final_epoch: request.final_epoch.clone(),
            final_sequence: request.expected_owner_sequence,
            final_safe_content_digest_sha256,
            owner_snapshot_digest_sha256: owner_snapshot_digest_sha256.clone(),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            compacted_at: Some(request.compacted_at),
            reason: HarnessContentCompactionReason::OwnerHistoryFloorAdvanced as i32,
        };
        compaction.compaction_record_digest_sha256 =
            canonical_history_compaction_digest(&compaction)
                .ok_or(AdapterEdgeError::IntegrityFailure)?;

        let owner_changed = transaction.execute(
            "UPDATE adapter_content_owner_snapshots
             SET owner_sequence = ?1, floor_sequence = ?1, baseline_state = ?2,
                 baseline_digest_sha256 = ?3, snapshot_digest_sha256 = ?3,
                 updated_at_seconds = ?4
             WHERE task_id = ?5 AND owner_sequence = ?1 AND floor_sequence = ?6
               AND snapshot_digest_sha256 = ?7",
            params![
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                baseline_state,
                owner_snapshot_digest_sha256,
                request.compacted_at.seconds,
                request.task_id,
                i64::try_from(current.floor_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                current.snapshot_digest_sha256,
            ],
        )?;
        let floor_changed = transaction.execute(
            "UPDATE adapter_content_history_floors
             SET floor_sequence = ?1, floor_digest_sha256 = ?2, updated_at_seconds = ?3
             WHERE task_id = ?4 AND floor_sequence = ?5",
            params![
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                content_floor_digest(&request.task_id, request.expected_owner_sequence),
                request.compacted_at.seconds,
                request.task_id,
                i64::try_from(current.floor_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            ],
        )?;
        if owner_changed != 1 || floor_changed != 1 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        transaction.execute(
            "INSERT INTO adapter_content_retention_tombstones(
               tombstone_id, task_id, tombstone_digest_sha256, tombstone, created_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                tombstone.tombstone_id,
                request.task_id,
                tombstone.tombstone_digest_sha256,
                tombstone.encode_to_vec(),
                request.compacted_at.seconds,
            ],
        )?;
        transaction.execute(
            "DELETE FROM adapter_content_projection_outbox
             WHERE source_record_id IN (
               SELECT record_id FROM adapter_safe_content_ledger
               WHERE task_id = ?1 AND content_sequence <= ?2
             )",
            params![
                request.task_id,
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM adapter_derived_content_sources
             WHERE content_event_id IN (
               SELECT content_event_id FROM adapter_safe_content_ledger
               WHERE task_id = ?1 AND content_sequence <= ?2
             )",
            params![
                request.task_id,
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM adapter_safe_content_ledger
             WHERE task_id = ?1 AND content_sequence <= ?2",
            params![
                request.task_id,
                i64::try_from(request.expected_owner_sequence)
                    .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM adapter_content_assemblies
             WHERE dispatch_id IN (
               SELECT dispatch_id FROM adapter_dispatch_task_lineage WHERE task_id = ?1
             )",
            [&request.task_id],
        )?;

        let first_event_sequence: i64 = transaction.query_row(
            "SELECT next_content_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let events = [
            (
                compaction.compaction_record_id.as_str(),
                SafeHarnessContentProjectionEvent {
                    payload: Some(
                        safe_harness_content_projection_event::Payload::HistoryCompaction(
                            compaction.clone(),
                        ),
                    ),
                },
            ),
            (
                tombstone.tombstone_id.as_str(),
                SafeHarnessContentProjectionEvent {
                    payload: Some(
                        safe_harness_content_projection_event::Payload::RetentionTombstone(
                            tombstone.clone(),
                        ),
                    ),
                },
            ),
        ];
        for (index, (source_record_id, event)) in events.iter().enumerate() {
            let source_revision = first_event_sequence
                .checked_add(i64::try_from(index).map_err(|_| AdapterEdgeError::IntegrityFailure)?)
                .ok_or(AdapterEdgeError::IntegrityFailure)?;
            let payload = event.encode_to_vec();
            transaction.execute(
                "INSERT INTO adapter_content_projection_outbox(
                   message_id, source_record_id, source_revision, payload_digest_sha256,
                   payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![
                    format!("adapter-content-{source_record_id}"),
                    source_record_id,
                    source_revision,
                    sha256(&payload),
                    payload,
                    request.compacted_at.seconds,
                ],
            )?;
        }
        transaction.execute(
            "UPDATE adapter_edge_metadata
             SET next_content_sequence = next_content_sequence + 2 WHERE singleton = 1",
            [],
        )?;
        let owner_snapshot = SafeContentOwnerSnapshot {
            task_id: request.task_id.clone(),
            owner_sequence: request.expected_owner_sequence,
            floor_sequence: request.expected_owner_sequence,
            disclosure_profile_digest_sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
                .to_owned(),
            snapshot_digest_sha256: owner_snapshot_digest_sha256,
            records: baseline_records,
            tombstones: baseline_tombstones,
        };
        transaction.commit()?;
        Ok(ContentRetentionCompactionReceipt {
            owner_snapshot,
            compaction,
            tombstone,
        })
    }

    pub fn retained_safe_content_for_rebuild(
        &self,
        task_id: &str,
        after_sequence: u64,
    ) -> Result<Option<RetainedSafeContent>, AdapterEdgeError> {
        let Some(mut snapshot) = self.content_owner_snapshot(task_id)? else {
            return Ok(None);
        };
        if after_sequence < snapshot.floor_sequence {
            return Ok(Some(RetainedSafeContent::ResetRequired(snapshot)));
        }
        snapshot
            .records
            .retain(|record| record.sequence > after_sequence);
        Ok(Some(RetainedSafeContent::Records(snapshot)))
    }

    pub fn observations_after(
        &self,
        after_sequence: u64,
    ) -> Result<Vec<HarnessObservation>, AdapterEdgeError> {
        let mut statement = self.connection.prepare(
            "SELECT observation FROM adapter_observations
             WHERE observation_sequence > ?1
             ORDER BY observation_sequence",
        )?;
        let records = statement
            .query_map([after_sequence as i64], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        records
            .into_iter()
            .map(|record| HarnessObservation::decode(record.as_slice()).map_err(Into::into))
            .collect()
    }

    pub fn pending_observations(&self) -> Result<Vec<HarnessObservation>, AdapterEdgeError> {
        let mut statement = self.connection.prepare(
            "SELECT observation FROM adapter_observations
             WHERE ingestion_state = 'pending'
             ORDER BY observation_sequence",
        )?;
        let records = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        records
            .into_iter()
            .map(|record| HarnessObservation::decode(record.as_slice()).map_err(Into::into))
            .collect()
    }

    fn decode_verified_observation_row(
        &self,
        expected_dispatch_id: &str,
        expected_capability_profile_id: &str,
        row: StoredObservationRow,
    ) -> Result<(AdapterObservationEvidence, String), AdapterEdgeError> {
        let (
            observation_id,
            dispatch_id,
            attempt_id,
            fencing_token,
            observation_sequence,
            native_key,
            native_event_digest_sha256,
            raw_evidence_ref,
            raw_event,
            observation,
            ingestion_state,
        ) = row;
        let fencing_token =
            u64::try_from(fencing_token).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        let observation_sequence =
            u64::try_from(observation_sequence).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        let observation = HarnessObservation::decode(observation.as_slice())?;
        ObservationCriticality::try_from(observation.criticality)
            .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        if observation_id.trim().is_empty()
            || dispatch_id.trim().is_empty()
            || attempt_id.trim().is_empty()
            || native_key.trim().is_empty()
            || fencing_token == 0
            || observation_sequence == 0
            || dispatch_id != expected_dispatch_id
            || observation.observation_id != observation_id
            || observation.dispatch_id != dispatch_id
            || observation.attempt_id != attempt_id
            || observation.fencing_token != fencing_token
            || observation.observation_sequence != observation_sequence
            || observation.adapter_id != self.adapter_id
            || observation.capability_profile_id != expected_capability_profile_id
            || observation.native_event_digest_sha256 != native_event_digest_sha256
            || observation.raw_evidence_ref != raw_evidence_ref
            || sha256(&raw_event) != native_event_digest_sha256
            || !matches!(ingestion_state.as_str(), "pending" | "consumed")
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        Ok((
            AdapterObservationEvidence {
                observation,
                raw_event,
            },
            ingestion_state,
        ))
    }

    fn verified_observation_evidence_by_id(
        &self,
        dispatch_id: &str,
        observation_id: &str,
        expected_capability_profile_id: &str,
    ) -> Result<Option<(AdapterObservationEvidence, String)>, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT observation_id, dispatch_id, attempt_id, fencing_token,
                        observation_sequence, native_key, native_event_digest_sha256,
                        raw_evidence_ref, raw_event, observation, ingestion_state
                 FROM adapter_observations
                 WHERE dispatch_id = ?1 AND observation_id = ?2",
                params![dispatch_id, observation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?
            .map(|row| {
                self.decode_verified_observation_row(
                    dispatch_id,
                    expected_capability_profile_id,
                    row,
                )
            })
            .transpose()
    }

    fn verified_observation_evidence_by_sequence(
        &self,
        dispatch_id: &str,
        observation_sequence: u64,
        expected_capability_profile_id: &str,
    ) -> Result<Option<(AdapterObservationEvidence, String)>, AdapterEdgeError> {
        let observation_sequence =
            i64::try_from(observation_sequence).map_err(|_| AdapterEdgeError::SequenceConflict)?;
        self.connection
            .query_row(
                "SELECT observation_id, dispatch_id, attempt_id, fencing_token,
                        observation_sequence, native_key, native_event_digest_sha256,
                        raw_evidence_ref, raw_event, observation, ingestion_state
                 FROM adapter_observations
                 WHERE dispatch_id = ?1 AND observation_sequence = ?2",
                params![dispatch_id, observation_sequence],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()?
            .map(|row| {
                self.decode_verified_observation_row(
                    dispatch_id,
                    expected_capability_profile_id,
                    row,
                )
            })
            .transpose()
    }

    pub fn normal_observation_recovery_view(
        &self,
        dispatch_id: &str,
        expected_capability_profile_id: &str,
    ) -> Result<NormalObservationRecoveryView, AdapterEdgeError> {
        if expected_capability_profile_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let mut statement = self.connection.prepare(
            "SELECT observation_id, dispatch_id, attempt_id, fencing_token,
                    observation_sequence, ingestion_state,
                    native_event_digest_sha256, raw_evidence_ref, raw_event, observation
             FROM adapter_observations
             WHERE dispatch_id = ?1
               AND instr(native_key, 'reconciliation:') <> 1
             ORDER BY observation_sequence",
        )?;
        let records = statement
            .query_map([dispatch_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut pending = Vec::new();
        let mut durable_terminal_sequence = None;
        for (
            observation_id,
            row_dispatch_id,
            attempt_id,
            fencing_token,
            observation_sequence,
            ingestion_state,
            native_event_digest_sha256,
            raw_evidence_ref,
            raw_event,
            observation,
        ) in records
        {
            let fencing_token =
                u64::try_from(fencing_token).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let observation_sequence = u64::try_from(observation_sequence)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let observation = HarnessObservation::decode(observation.as_slice())?;
            let criticality = ObservationCriticality::try_from(observation.criticality)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            if observation_id.trim().is_empty()
                || row_dispatch_id.trim().is_empty()
                || attempt_id.trim().is_empty()
                || fencing_token == 0
                || observation_sequence == 0
                || row_dispatch_id != dispatch_id
                || observation.observation_id != observation_id
                || observation.dispatch_id != row_dispatch_id
                || observation.attempt_id != attempt_id
                || observation.fencing_token != fencing_token
                || observation.observation_sequence != observation_sequence
                || observation.adapter_id != self.adapter_id
                || observation.capability_profile_id != expected_capability_profile_id
                || observation.native_event_digest_sha256 != native_event_digest_sha256
                || observation.raw_evidence_ref != raw_evidence_ref
                || sha256(&raw_event) != native_event_digest_sha256
                || !matches!(ingestion_state.as_str(), "pending" | "consumed")
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            if criticality == ObservationCriticality::Terminal
                && durable_terminal_sequence.is_none()
            {
                durable_terminal_sequence = Some(observation_sequence);
            }
            if ingestion_state == "pending" {
                pending.push(observation);
            }
        }
        Ok(NormalObservationRecoveryView {
            pending,
            durable_terminal_sequence,
        })
    }

    pub fn legacy_execution_start_recovery_evidence(
        &self,
        dispatch_id: &str,
        attempt_id: &str,
        fencing_token: u64,
        expected_capability_profile_id: &str,
        pending_observation_id: &str,
        prior_start_sequence: u64,
    ) -> Result<LegacyExecutionStartEvidenceResolution, AdapterEdgeError> {
        if dispatch_id.trim().is_empty()
            || attempt_id.trim().is_empty()
            || fencing_token == 0
            || expected_capability_profile_id.trim().is_empty()
            || pending_observation_id.trim().is_empty()
            || prior_start_sequence == 0
        {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::OwnerMismatch,
            ));
        }
        let view =
            self.normal_observation_recovery_view(dispatch_id, expected_capability_profile_id)?;
        let Some((pending_start, pending_state)) = self.verified_observation_evidence_by_id(
            dispatch_id,
            pending_observation_id,
            expected_capability_profile_id,
        )?
        else {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::PriorStartMissing,
            ));
        };
        let Some((prior_start, prior_state)) = self.verified_observation_evidence_by_sequence(
            dispatch_id,
            prior_start_sequence,
            expected_capability_profile_id,
        )?
        else {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::PriorStartMissing,
            ));
        };
        let pending = &pending_start.observation;
        let prior = &prior_start.observation;
        let both_started = [prior, pending].into_iter().all(|observation| {
            matches!(
                observation.payload.as_ref(),
                Some(harness_observation::Payload::Lifecycle(lifecycle))
                    if lifecycle.kind == LifecycleKind::ExecutionStarted as i32
            )
        });
        if pending_state != "pending"
            || prior_state != "consumed"
            || pending.observation_sequence <= prior.observation_sequence
            || prior.observation_sequence != prior_start_sequence
            || !both_started
            || !view
                .pending
                .iter()
                .any(|observation| observation == pending)
        {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::PriorStartMissing,
            ));
        }

        let envelope = self
            .dispatch_envelope(dispatch_id)?
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let receipt = self
            .dispatch_receipt(dispatch_id)?
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let mut canonical_receipt = receipt.clone();
        let receipt_digest_sha256 = std::mem::take(&mut canonical_receipt.receipt_digest_sha256);
        let owner_matches = envelope.dispatch_id == dispatch_id
            && envelope.attempt_id == attempt_id
            && envelope.fencing_token == fencing_token
            && envelope
                .capability_profile_ref
                .as_ref()
                .is_some_and(|profile| profile.contract_id == expected_capability_profile_id)
            && receipt.dispatch_id == dispatch_id
            && receipt.attempt_id == attempt_id
            && receipt.fencing_token == fencing_token
            && receipt.adapter_id == self.adapter_id
            && receipt.capability_profile_id == expected_capability_profile_id
            && DeliveryDisposition::try_from(receipt.disposition)
                == Ok(DeliveryDisposition::Delivered)
            && is_sha256(&receipt_digest_sha256)
            && sha256(&canonical_receipt.encode_to_vec()) == receipt_digest_sha256
            && [prior, pending].into_iter().all(|observation| {
                observation.dispatch_id == dispatch_id
                    && observation.attempt_id == attempt_id
                    && observation.fencing_token == fencing_token
                    && observation.capability_profile_id == expected_capability_profile_id
            });
        if !owner_matches {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::OwnerMismatch,
            ));
        }

        let mut statement = self.connection.prepare(
            "SELECT observation_id FROM adapter_observations
             WHERE dispatch_id = ?1 ORDER BY observation_sequence",
        )?;
        let observation_ids = statement
            .query_map([dispatch_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut bindings = Vec::new();
        for observation_id in observation_ids {
            let Some((evidence, _)) = self.verified_observation_evidence_by_id(
                dispatch_id,
                &observation_id,
                expected_capability_profile_id,
            )?
            else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            let Some(harness_observation::Payload::Ack(ack)) =
                evidence.observation.payload.as_ref()
            else {
                continue;
            };
            if AckDisposition::try_from(ack.disposition) != Ok(AckDisposition::Accepted) {
                continue;
            }
            let (Some(native_session_ref), Some(native_execution_ref)) = (
                ack.native_session_ref.as_ref(),
                ack.native_execution_ref.as_ref(),
            ) else {
                return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                    LegacyExecutionStartEvidenceRejection::NativeBindingConflict,
                ));
            };
            if ack.ack_receipt_id.trim().is_empty()
                || native_session_ref.trim().is_empty()
                || native_execution_ref.trim().is_empty()
                || evidence.observation.attempt_id != attempt_id
                || evidence.observation.fencing_token != fencing_token
                || evidence.observation.observation_sequence >= prior_start_sequence
            {
                return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                    LegacyExecutionStartEvidenceRejection::NativeBindingConflict,
                ));
            }
            bindings.push((native_session_ref.clone(), native_execution_ref.clone()));
        }
        if bindings.is_empty() {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::NativeBindingMissing,
            ));
        }
        if bindings.len() != 1
            || receipt
                .native_session_ref
                .as_ref()
                .is_some_and(|value| value != &bindings[0].0)
            || receipt
                .native_execution_ref
                .as_ref()
                .is_some_and(|value| value != &bindings[0].1)
        {
            return Ok(LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::NativeBindingConflict,
            ));
        }
        let native_binding = NativeExecutionBinding {
            attempt_id: attempt_id.to_owned(),
            dispatch_id: dispatch_id.to_owned(),
            fencing_token,
            native_session_ref: bindings[0].0.clone(),
            native_execution_ref: bindings[0].1.clone(),
        };
        let terminal_handoff = match self.terminal_output_candidate_for_dispatch(dispatch_id)? {
            Some(candidate) => {
                let structurally_valid = candidate.source_revision > pending.observation_sequence
                    && view.durable_terminal_sequence == Some(candidate.source_revision)
                    && candidate.attempt_id == attempt_id
                    && candidate.fencing_token == fencing_token
                    && candidate.content_complete
                    && candidate.original_content_bytes == candidate.content.len() as u64
                    && sha256(&candidate.content) == candidate.content_digest_sha256;
                if !structurally_valid {
                    None
                } else {
                    let terminal = self
                        .verified_observation_evidence_by_sequence(
                            dispatch_id,
                            candidate.source_revision,
                            expected_capability_profile_id,
                        )?
                        .filter(|(evidence, _)| {
                            evidence.observation.observation_id == candidate.source_observation_id
                                && evidence.observation.attempt_id == attempt_id
                                && evidence.observation.fencing_token == fencing_token
                                && matches!(
                                    evidence.observation.payload.as_ref(),
                                    Some(harness_observation::Payload::Lifecycle(lifecycle))
                                        if lifecycle.kind == LifecycleKind::ExecutionCompleted as i32
                                )
                        });
                    terminal
                        .map(|(evidence, _)| (evidence.raw_event, candidate.native_completion_ref))
                }
            }
            None => None,
        };
        Ok(LegacyExecutionStartEvidenceResolution::Verified(Box::new(
            LegacyExecutionStartEvidence {
                prior_start,
                pending_start,
                native_binding,
                durable_terminal_handoff: terminal_handoff.is_some(),
                terminal_raw_event: terminal_handoff
                    .as_ref()
                    .map(|(raw_event, _)| raw_event.clone()),
                terminal_native_completion_ref: terminal_handoff
                    .map(|(_, native_completion_ref)| native_completion_ref),
            },
        )))
    }

    pub fn pending_approval_projection_messages(
        &self,
    ) -> Result<Vec<PendingAdapterApprovalProjection>, AdapterEdgeError> {
        self.approval_projection_messages(false)
    }

    pub fn retained_approval_projection_messages_for_rebuild(
        &self,
    ) -> Result<Vec<PendingAdapterApprovalProjection>, AdapterEdgeError> {
        self.approval_projection_messages(true)
    }

    fn approval_projection_messages(
        &self,
        include_consumed: bool,
    ) -> Result<Vec<PendingAdapterApprovalProjection>, AdapterEdgeError> {
        let state_filter = if include_consumed {
            "o.delivery_state IN ('pending','consumed')"
        } else {
            "o.delivery_state = 'pending'"
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT o.message_id, o.source_observation_id, o.source_revision,
                    o.payload_digest_sha256, o.payload, d.envelope
             FROM adapter_projection_outbox o
             JOIN adapter_observations a ON a.observation_id = o.source_observation_id
             JOIN adapter_dispatches d ON d.dispatch_id = a.dispatch_id
             WHERE {state_filter}
             ORDER BY o.source_revision"
        ))?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (
                message_id,
                source_observation_id,
                source_revision,
                digest,
                payload,
                envelope_payload,
            ) = row?;
            let observation = HarnessObservation::decode(payload.as_slice())?;
            let envelope = DispatchEnvelope::decode(envelope_payload.as_slice())?;
            if observation.observation_id != source_observation_id
                || observation.observation_sequence != source_revision as u64
                || observation.attempt_id != envelope.attempt_id
                || observation.dispatch_id != envelope.dispatch_id
                || observation.fencing_token != envelope.fencing_token
                || !matches!(
                    observation.payload.as_ref(),
                    Some(harness_observation::Payload::ApprovalRequest(_))
                )
                || observation.payload.as_ref().is_some_and(|payload| {
                    matches!(
                        payload,
                        harness_observation::Payload::ApprovalRequest(request)
                            if !request.native_routing_ref.is_empty()
                    )
                })
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            Ok(PendingAdapterApprovalProjection {
                message_id,
                source_observation_id,
                source_revision: source_revision as u64,
                payload_digest_sha256: digest,
                run_id: envelope.run_id,
                step_id: envelope.step_id,
                attempt_id: envelope.attempt_id,
                dispatch_id: envelope.dispatch_id,
                fencing_token: envelope.fencing_token,
                observation,
            })
        })
        .collect()
    }

    pub fn acknowledge_approval_projection_message(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, AdapterEdgeError> {
        let changed = self.connection.execute(
            "UPDATE adapter_projection_outbox SET delivery_state = 'consumed'
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2
               AND delivery_state = 'pending'",
            params![message_id, payload_digest_sha256],
        )?;
        if changed == 1 {
            return Ok(true);
        }
        let replay: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest_sha256, delivery_state
                 FROM adapter_projection_outbox WHERE message_id = ?1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(
            matches!(replay, Some((digest, state)) if digest == payload_digest_sha256 && state == "consumed"),
        )
    }

    pub fn pending_terminal_output_candidates(
        &self,
    ) -> Result<Vec<PendingTerminalOutputCandidate>, AdapterEdgeError> {
        self.terminal_output_candidates(None)
    }

    /// Resolves the durable terminal candidate for a dispatch after either
    /// pending or consumed delivery. This is a read-only evidence port for
    /// binding an Artifact Authority receipt back to the exact Harness
    /// sequence; held candidates are deliberately ineligible.
    pub fn terminal_output_candidate_for_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<PendingTerminalOutputCandidate>, AdapterEdgeError> {
        if dispatch_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let mut candidates = self.terminal_output_candidates(Some(dispatch_id))?;
        if candidates.len() > 1 {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        Ok(candidates.pop())
    }

    fn terminal_output_candidates(
        &self,
        dispatch_id: Option<&str>,
    ) -> Result<Vec<PendingTerminalOutputCandidate>, AdapterEdgeError> {
        let mut statement = self.connection.prepare(
            "SELECT o.message_id, o.source_observation_id, o.source_revision,
                    o.payload_digest_sha256, o.dispatch_id, o.native_completion_ref,
                    o.media_type, o.content_digest_sha256, o.original_content_bytes,
                    o.captured_content, o.captured_content_digest_sha256,
                    o.content_complete, a.observation, d.envelope,
                    l.task_id, l.task_revision, l.work_revision
             FROM adapter_terminal_output_outbox o
             JOIN adapter_observations a ON a.observation_id = o.source_observation_id
             JOIN adapter_dispatches d ON d.dispatch_id = o.dispatch_id
             JOIN adapter_dispatch_task_lineage l ON l.dispatch_id = o.dispatch_id
             WHERE ((?1 IS NULL AND o.delivery_state = 'pending')
                OR (?1 IS NOT NULL AND o.dispatch_id = ?1
                    AND o.delivery_state IN ('pending', 'consumed')))
             ORDER BY o.source_revision",
        )?;
        let rows = statement.query_map([dispatch_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, Vec<u8>>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, i64>(16)?,
            ))
        })?;
        rows.map(|row| {
            let (
                message_id,
                source_observation_id,
                source_revision,
                payload_digest_sha256,
                dispatch_id,
                native_completion_ref,
                media_type,
                content_digest_sha256,
                original_content_bytes,
                content,
                captured_content_digest_sha256,
                content_complete,
                observation_bytes,
                envelope_bytes,
                task_id,
                task_revision,
                work_revision,
            ) = row?;
            let observation = HarnessObservation::decode(observation_bytes.as_slice())?;
            let envelope = DispatchEnvelope::decode(envelope_bytes.as_slice())?;
            let is_completed = matches!(
                observation.payload.as_ref(),
                Some(harness_observation::Payload::Lifecycle(lifecycle))
                    if lifecycle.kind == LifecycleKind::ExecutionCompleted as i32
            );
            let original_content_bytes = u64::try_from(original_content_bytes)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let content_complete = content_complete == 1;
            let task_revision =
                u64::try_from(task_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let work_revision =
                u64::try_from(work_revision).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            if observation.observation_id != source_observation_id
                || observation.observation_sequence != source_revision as u64
                || observation.criticality != ObservationCriticality::Terminal as i32
                || !is_completed
                || observation.attempt_id != envelope.attempt_id
                || observation.dispatch_id != envelope.dispatch_id
                || observation.fencing_token != envelope.fencing_token
                || dispatch_id != envelope.dispatch_id
                || envelope.run_id.trim().is_empty()
                || envelope.run_revision == 0
                || envelope.step_id.trim().is_empty()
                || envelope.step_revision == 0
                || envelope.attempt_id.trim().is_empty()
                || envelope.attempt_revision == 0
                || envelope.fencing_token == 0
                || task_id.trim().is_empty()
                || task_revision == 0
                || work_revision == 0
                || native_completion_ref.trim().is_empty()
                || media_type.trim().is_empty()
                || !is_sha256(&content_digest_sha256)
                || !is_sha256(&captured_content_digest_sha256)
                || sha256(&content) != captured_content_digest_sha256
                || (content_complete
                    && (original_content_bytes != content.len() as u64
                        || sha256(&content) != content_digest_sha256))
                || (!content_complete
                    && (content.len() != TERMINAL_OUTPUT_PREVIEW_BYTES
                        || original_content_bytes <= TERMINAL_OUTPUT_FULL_BYTES as u64))
                || terminal_output_payload_digest_parts(
                    &dispatch_id,
                    &native_completion_ref,
                    &media_type,
                    &content_digest_sha256,
                    original_content_bytes,
                ) != payload_digest_sha256
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            Ok(PendingTerminalOutputCandidate {
                message_id,
                source_observation_id,
                source_revision: source_revision as u64,
                payload_digest_sha256,
                run_id: envelope.run_id,
                task_id,
                task_revision,
                work_revision,
                run_revision: envelope.run_revision,
                step_id: envelope.step_id,
                step_revision: envelope.step_revision,
                attempt_id: envelope.attempt_id,
                attempt_revision: envelope.attempt_revision,
                dispatch_id,
                fencing_token: envelope.fencing_token,
                native_completion_ref,
                media_type,
                content_digest_sha256,
                original_content_bytes,
                content,
                content_complete,
            })
        })
        .collect()
    }

    pub fn terminal_output_candidate_is_durable(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM adapter_terminal_output_outbox
                   WHERE dispatch_id = ?1 AND delivery_state IN ('pending', 'consumed')
                 )",
                [dispatch_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Registers the trusted Artifact relation work item and consumes the
    /// technical-return candidate in one Edge transaction. Content projection
    /// settles the intent independently after this boundary.
    pub fn register_final_artifact_relation_intent_and_ack(
        &mut self,
        request: &FinalArtifactRelationRequest,
        now_seconds: i64,
    ) -> Result<FinalArtifactRelationRegistration, AdapterEdgeError> {
        if request.terminal_message_id.trim().is_empty()
            || !is_sha256(&request.terminal_payload_digest_sha256)
            || request.artifact_id.trim().is_empty()
            || !is_sha256(&request.artifact_digest_sha256)
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let dispatch_id: String = self.connection.query_row(
            "SELECT dispatch_id FROM adapter_terminal_output_outbox
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2",
            params![
                request.terminal_message_id,
                request.terminal_payload_digest_sha256
            ],
            |row| row.get(0),
        )?;
        let candidate = self
            .terminal_output_candidate_for_dispatch(&dispatch_id)?
            .filter(|candidate| candidate.message_id == request.terminal_message_id)
            .ok_or(AdapterEdgeError::SequenceConflict)?;
        if !candidate.content_complete
            || candidate.original_content_bytes != candidate.content.len() as u64
            || sha256(&candidate.content) != candidate.content_digest_sha256
            || candidate.content_digest_sha256 != request.artifact_digest_sha256
        {
            return Err(AdapterEdgeError::SequenceConflict);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let relation_policy: String = transaction.query_row(
            "SELECT policy FROM adapter_dispatch_relation_policy WHERE dispatch_id = ?1",
            [&dispatch_id],
            |row| row.get(0),
        )?;
        let existing: Option<(String, String, String, String)> = transaction
            .query_row(
                "SELECT terminal_payload_digest_sha256, dispatch_id, artifact_id,
                        artifact_digest_sha256
                 FROM adapter_final_artifact_relation_intents
                 WHERE terminal_message_id = ?1",
                [&request.terminal_message_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let result = if relation_policy
            == relation_policy_name(FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly)
        {
            if existing.is_some() {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            FinalArtifactRelationRegistration::SkippedLegacy
        } else if relation_policy
            == relation_policy_name(FinalArtifactRelationPolicy::RequiredGovernedContent)
        {
            match existing {
                Some((payload_digest, stored_dispatch, artifact_id, artifact_digest)) => {
                    if payload_digest != request.terminal_payload_digest_sha256
                        || stored_dispatch != dispatch_id
                        || artifact_id != request.artifact_id
                        || artifact_digest != request.artifact_digest_sha256
                    {
                        return Err(AdapterEdgeError::SequenceConflict);
                    }
                    FinalArtifactRelationRegistration::Replay
                }
                None => {
                    transaction.execute(
                        "INSERT INTO adapter_final_artifact_relation_intents(
                           terminal_message_id, terminal_payload_digest_sha256, dispatch_id,
                           artifact_id, artifact_digest_sha256, relation_state, safe_reason_code,
                           created_at_seconds, updated_at_seconds
                         ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', NULL, ?6, ?6)",
                        params![
                            request.terminal_message_id,
                            request.terminal_payload_digest_sha256,
                            dispatch_id,
                            request.artifact_id,
                            request.artifact_digest_sha256,
                            now_seconds
                        ],
                    )?;
                    FinalArtifactRelationRegistration::Registered
                }
            }
        } else {
            return Err(AdapterEdgeError::IntegrityFailure);
        };
        let changed = transaction.execute(
            "UPDATE adapter_terminal_output_outbox SET delivery_state = 'consumed'
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2
               AND delivery_state = 'pending'",
            params![
                request.terminal_message_id,
                request.terminal_payload_digest_sha256
            ],
        )?;
        if changed == 0 {
            let state: Option<String> = transaction
                .query_row(
                    "SELECT delivery_state FROM adapter_terminal_output_outbox
                     WHERE message_id = ?1 AND payload_digest_sha256 = ?2",
                    params![
                        request.terminal_message_id,
                        request.terminal_payload_digest_sha256
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if state.as_deref() != Some("consumed") {
                return Err(AdapterEdgeError::SequenceConflict);
            }
        }
        transaction.commit()?;
        Ok(result)
    }

    pub fn commit_final_artifact_relation(
        &mut self,
        request: &FinalArtifactRelationRequest,
        now_seconds: i64,
    ) -> Result<FinalArtifactRelationCommit, AdapterEdgeError> {
        self.commit_final_artifact_relation_with_limits(request, now_seconds, CONTENT_BUDGET_LIMITS)
    }

    fn commit_final_artifact_relation_with_limits(
        &mut self,
        request: &FinalArtifactRelationRequest,
        now_seconds: i64,
        budget_limits: ContentBudgetLimits,
    ) -> Result<FinalArtifactRelationCommit, AdapterEdgeError> {
        if request.terminal_message_id.trim().is_empty()
            || !is_sha256(&request.terminal_payload_digest_sha256)
            || request.artifact_id.trim().is_empty()
            || !is_sha256(&request.artifact_digest_sha256)
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let intent: Option<(String, String, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT dispatch_id, relation_state, projected_record
             FROM adapter_final_artifact_relation_intents
             WHERE terminal_message_id = ?1
               AND terminal_payload_digest_sha256 = ?2
               AND artifact_id = ?3 AND artifact_digest_sha256 = ?4",
                params![
                    request.terminal_message_id,
                    request.terminal_payload_digest_sha256,
                    request.artifact_id,
                    request.artifact_digest_sha256
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (dispatch_id, relation_state, projected_record) =
            intent.ok_or(AdapterEdgeError::SequenceConflict)?;
        if !matches!(relation_state.as_str(), "pending" | "projected") {
            return Err(AdapterEdgeError::DispatchStateConflict);
        }
        if relation_state == "projected" {
            let bytes = projected_record.ok_or(AdapterEdgeError::IntegrityFailure)?;
            let record = SafeHarnessContentRecord::decode(bytes.as_slice())?;
            let artifact = match record.payload.as_ref() {
                Some(safe_harness_content_record::Payload::ArtifactRelation(relation)) => {
                    relation.artifact.as_ref()
                }
                _ => None,
            }
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
            if record.dispatch_id != dispatch_id
                || artifact.artifact_id != request.artifact_id
                || artifact.artifact_digest_sha256 != request.artifact_digest_sha256
                || canonical_safe_record_digest(&record).as_deref()
                    != Some(record.record_digest_sha256.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            return Ok(FinalArtifactRelationCommit::Replay(record));
        }
        if projected_record.is_some() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let candidate = self
            .terminal_output_candidate_for_dispatch(&dispatch_id)?
            .filter(|candidate| candidate.message_id == request.terminal_message_id)
            .ok_or(AdapterEdgeError::SequenceConflict)?;
        if candidate.payload_digest_sha256 != request.terminal_payload_digest_sha256
            || candidate.content_digest_sha256 != request.artifact_digest_sha256
            || !candidate.content_complete
            || candidate.original_content_bytes != candidate.content.len() as u64
            || sha256(&candidate.content) != candidate.content_digest_sha256
        {
            return Err(AdapterEdgeError::SequenceConflict);
        }

        let relation_policy: String = self.connection.query_row(
            "SELECT policy FROM adapter_dispatch_relation_policy WHERE dispatch_id = ?1",
            [&candidate.dispatch_id],
            |row| row.get(0),
        )?;
        if relation_policy
            != relation_policy_name(FinalArtifactRelationPolicy::RequiredGovernedContent)
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let pending_content: bool = self.connection.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM adapter_content_candidates
               WHERE dispatch_id = ?1 AND projection_state = 'pending'
             )",
            [&candidate.dispatch_id],
            |row| row.get(0),
        )?;

        let assemblies = {
            let mut statement = self.connection.prepare(
                "SELECT assembly_state FROM adapter_content_assemblies
                 WHERE dispatch_id = ?1 AND finalized = 1
                 ORDER BY message_id",
            )?;
            statement
                .query_map([&candidate.dispatch_id], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        if assemblies.is_empty() {
            if pending_content {
                return Ok(FinalArtifactRelationCommit::PendingContent);
            }
            self.quarantine_final_artifact_relation_intent(
                &request.terminal_message_id,
                "FINAL_ARTIFACT_RELATION_RAW_MISMATCH",
                now_seconds,
            )?;
            return Ok(FinalArtifactRelationCommit::RawMismatch);
        }

        let mut raw_matches = Vec::new();
        for bytes in assemblies {
            let (checkpoint, records) = decode_assembly_state(&bytes)?;
            if !checkpoint.finalized {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            let Some(template) = records.first() else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            if records.iter().any(|record| {
                record.task_id != candidate.task_id
                    || record.run_id != candidate.run_id
                    || record.step_id != candidate.step_id
                    || record.attempt_id != candidate.attempt_id
                    || record.dispatch_id != candidate.dispatch_id
                    || record.fencing_token != candidate.fencing_token
                    || record.route_binding_sha256 != template.route_binding_sha256
            }) {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            if checkpoint.raw_cumulative != candidate.content
                || checkpoint.raw_cumulative.len() as u64 != candidate.original_content_bytes
                || sha256(&checkpoint.raw_cumulative) != candidate.content_digest_sha256
                || checkpoint.raw_cumulative_digest_sha256
                    != framed_content_digest(
                        b"egopulse/harness-content/raw-cumulative/v1",
                        &checkpoint.raw_cumulative,
                    )
            {
                continue;
            }
            raw_matches.push((checkpoint, records));
        }
        if raw_matches.is_empty() {
            if pending_content {
                return Ok(FinalArtifactRelationCommit::PendingContent);
            }
            self.quarantine_final_artifact_relation_intent(
                &request.terminal_message_id,
                "FINAL_ARTIFACT_RELATION_RAW_MISMATCH",
                now_seconds,
            )?;
            return Ok(FinalArtifactRelationCommit::RawMismatch);
        }
        if raw_matches.len() != 1 {
            self.quarantine_final_artifact_relation_intent(
                &request.terminal_message_id,
                "FINAL_ARTIFACT_RELATION_AMBIGUOUS",
                now_seconds,
            )?;
            return Ok(FinalArtifactRelationCommit::Ambiguous);
        }
        let (checkpoint, records) = raw_matches.pop().expect("one exact raw match");
        let Some((mut record, safe_message_id)) =
            records
                .iter()
                .find_map(|record| match record.payload.as_ref() {
                    Some(safe_harness_content_record::Payload::AssistantText(assistant)) => {
                        Some((record.clone(), assistant.safe_message_id.clone()))
                    }
                    _ => None,
                })
        else {
            self.connection.execute(
                "UPDATE adapter_final_artifact_relation_intents
                 SET relation_state = 'skipped', safe_reason_code = ?1,
                     updated_at_seconds = ?2
                 WHERE terminal_message_id = ?3 AND relation_state = 'pending'",
                params![
                    "FINAL_ARTIFACT_RELATION_NO_SAFE_ASSISTANT_CONTENT",
                    now_seconds,
                    request.terminal_message_id
                ],
            )?;
            return Ok(FinalArtifactRelationCommit::Skipped(
                FinalArtifactRelationSkipReason::NoSafeAssistantContent,
            ));
        };

        let mut identity = Vec::new();
        for value in [
            b"egopulse/harness-content/final-artifact-relation/v1".as_slice(),
            candidate.dispatch_id.as_bytes(),
            candidate.attempt_id.as_bytes(),
            request.terminal_message_id.as_bytes(),
            safe_message_id.as_bytes(),
        ] {
            frame_bytes(&mut identity, value);
        }
        let content_event_id = sha256(&identity);
        record.content_event_id = content_event_id.clone();
        record.record_id = canonical_safe_record_id(
            &content_event_id,
            "ARTIFACT_RELATION",
            HarnessContentLimitKind::Unspecified,
            0,
        );
        record.record_digest_sha256.clear();
        record.safety_flags.clear();
        record.payload = Some(safe_harness_content_record::Payload::ArtifactRelation(
            SafeArtifactRelationContent {
                safe_content_differs_from_artifact: checkpoint.safe_cumulative.as_bytes()
                    != candidate.content,
                artifact: Some(SafeArtifactIdentity {
                    artifact_id: request.artifact_id.clone(),
                    artifact_digest_sha256: request.artifact_digest_sha256.clone(),
                }),
            },
        ));
        record.record_digest_sha256 =
            canonical_safe_record_digest(&record).ok_or(AdapterEdgeError::IntegrityFailure)?;
        let encoded = record.encode_to_vec();
        let mut source_identity = Vec::new();
        for value in [
            b"egopulse/harness-content/final-artifact-relation-source/v1".as_slice(),
            request.terminal_message_id.as_bytes(),
            request.terminal_payload_digest_sha256.as_bytes(),
            checkpoint.message_id.as_bytes(),
            request.artifact_id.as_bytes(),
            request.artifact_digest_sha256.as_bytes(),
            b"1".as_slice(),
        ] {
            frame_bytes(&mut source_identity, value);
        }
        let source_identity_digest_sha256 = sha256(&source_identity);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT source_kind, source_identity_digest_sha256, source_payload
                 FROM adapter_derived_content_sources
                 WHERE content_event_id = ?1",
                [&content_event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((source_kind, stored_identity, stored_payload)) = existing {
            if source_kind != "final_artifact_relation"
                || stored_identity != source_identity_digest_sha256
                || stored_payload != encoded
            {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            let stored_record: Vec<u8> = transaction.query_row(
                "SELECT safe_record FROM adapter_safe_content_ledger WHERE record_id = ?1",
                [&record.record_id],
                |row| row.get(0),
            )?;
            if stored_record != encoded {
                return Err(AdapterEdgeError::SequenceConflict);
            }
            transaction.commit()?;
            return Ok(FinalArtifactRelationCommit::Replay(record));
        }

        let owner = load_content_owner_snapshot(&transaction, &record.task_id)?;
        if owner
            .as_ref()
            .is_some_and(|snapshot| !snapshot.tombstones.is_empty())
        {
            mark_final_artifact_relation_skipped(
                &transaction,
                &request.terminal_message_id,
                "FINAL_ARTIFACT_RELATION_SCOPE_TERMINAL",
                now_seconds,
            )?;
            transaction.commit()?;
            return Ok(FinalArtifactRelationCommit::Skipped(
                FinalArtifactRelationSkipReason::ScopeTerminal,
            ));
        }
        let (attempt_budget, task_budget) = verified_content_budgets_from_owner_history(
            &transaction,
            &record.task_id,
            &record.attempt_id,
        )?;
        if let Some(reason) = final_artifact_relation_budget_skip_reason(
            &record,
            attempt_budget,
            task_budget,
            budget_limits,
        )? {
            mark_final_artifact_relation_skipped(
                &transaction,
                &request.terminal_message_id,
                final_artifact_relation_skip_reason_code(reason),
                now_seconds,
            )?;
            transaction.commit()?;
            return Ok(FinalArtifactRelationCommit::Skipped(reason));
        }

        let sequence: i64 = transaction.query_row(
            "SELECT next_content_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let event = SafeHarnessContentProjectionEvent {
            payload: Some(
                safe_harness_content_projection_event::Payload::ContentRecord(record.clone()),
            ),
        };
        let event_bytes = event.encode_to_vec();
        transaction.execute(
            "INSERT INTO adapter_derived_content_sources(
               content_event_id, source_observation_id, dispatch_id, source_kind,
               source_identity_digest_sha256, source_payload, created_at_seconds
             ) VALUES(?1, ?2, ?3, 'final_artifact_relation', ?4, ?5, ?6)",
            params![
                content_event_id,
                candidate.source_observation_id,
                candidate.dispatch_id,
                source_identity_digest_sha256,
                encoded,
                now_seconds
            ],
        )?;
        transaction.execute(
            "INSERT INTO adapter_safe_content_ledger(
               record_id, content_event_id, part_index, task_id, record_digest_sha256,
               content_sequence, safe_record, created_at_seconds
             ) VALUES(?1, ?2, 0, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.record_id,
                record.content_event_id,
                record.task_id,
                record.record_digest_sha256,
                sequence,
                encoded,
                now_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO adapter_content_projection_outbox(
               message_id, source_record_id, source_revision, payload_digest_sha256,
               payload, delivery_state, created_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
            params![
                format!("adapter-content-{}", record.record_id),
                record.record_id,
                sequence,
                sha256(&event_bytes),
                event_bytes,
                now_seconds,
            ],
        )?;
        update_content_owner_metadata(
            &transaction,
            &record.task_id,
            &[(sequence, &record)],
            now_seconds,
        )?;
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "attempt",
                scope_id: &record.attempt_id,
                previous: attempt_budget,
                added_text_bytes: 0,
                added_records: 1,
                terminal_kind: None,
            },
            now_seconds,
        )?;
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "task",
                scope_id: &record.task_id,
                previous: task_budget,
                added_text_bytes: 0,
                added_records: 1,
                terminal_kind: None,
            },
            now_seconds,
        )?;
        transaction.execute(
            "UPDATE adapter_edge_metadata SET next_content_sequence = next_content_sequence + 1
             WHERE singleton = 1",
            [],
        )?;
        transaction.execute(
            "UPDATE adapter_final_artifact_relation_intents
             SET relation_state = 'projected', safe_reason_code = NULL,
                 projected_record = ?1, updated_at_seconds = ?2
             WHERE terminal_message_id = ?3 AND relation_state = 'pending'",
            params![encoded, now_seconds, request.terminal_message_id],
        )?;
        transaction.commit()?;
        Ok(FinalArtifactRelationCommit::Committed(record))
    }

    pub fn pending_final_artifact_relation_intent(
        &self,
    ) -> Result<Option<FinalArtifactRelationRequest>, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT terminal_message_id, terminal_payload_digest_sha256,
                        artifact_id, artifact_digest_sha256
                 FROM adapter_final_artifact_relation_intents
                 WHERE relation_state = 'pending'
                 ORDER BY created_at_seconds, terminal_message_id LIMIT 1",
                [],
                |row| {
                    Ok(FinalArtifactRelationRequest {
                        terminal_message_id: row.get(0)?,
                        terminal_payload_digest_sha256: row.get(1)?,
                        artifact_id: row.get(2)?,
                        artifact_digest_sha256: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn final_artifact_relation_status(
        &self,
        terminal_message_id: &str,
    ) -> Result<Option<FinalArtifactRelationStatus>, AdapterEdgeError> {
        if terminal_message_id.trim().is_empty() {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let stored: Option<(String, String, String, String, String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT terminal_payload_digest_sha256, dispatch_id, artifact_id,
                        artifact_digest_sha256, relation_state, safe_reason_code
                 FROM adapter_final_artifact_relation_intents
                 WHERE terminal_message_id = ?1",
                [terminal_message_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((payload_digest, dispatch_id, artifact_id, artifact_digest, state, reason)) =
            stored
        else {
            return Ok(None);
        };
        let state = match state.as_str() {
            "pending" => FinalArtifactRelationState::Pending,
            "projected" => FinalArtifactRelationState::Projected,
            "quarantined" => FinalArtifactRelationState::Quarantined,
            "skipped" => FinalArtifactRelationState::Skipped,
            _ => return Err(AdapterEdgeError::IntegrityFailure),
        };
        Ok(Some(FinalArtifactRelationStatus {
            request: FinalArtifactRelationRequest {
                terminal_message_id: terminal_message_id.to_owned(),
                terminal_payload_digest_sha256: payload_digest,
                artifact_id,
                artifact_digest_sha256: artifact_digest,
            },
            dispatch_id,
            state,
            safe_reason_code: reason,
        }))
    }

    fn quarantine_final_artifact_relation_intent(
        &self,
        terminal_message_id: &str,
        safe_reason_code: &'static str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        let changed = self.connection.execute(
            "UPDATE adapter_final_artifact_relation_intents
             SET relation_state = 'quarantined', safe_reason_code = ?1,
                 updated_at_seconds = ?2
             WHERE terminal_message_id = ?3 AND relation_state = 'pending'",
            params![safe_reason_code, now_seconds, terminal_message_id],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(AdapterEdgeError::SequenceConflict)
        }
    }

    pub fn acknowledge_terminal_output_candidate(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, AdapterEdgeError> {
        let changed = self.connection.execute(
            "UPDATE adapter_terminal_output_outbox SET delivery_state = 'consumed'
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2
               AND delivery_state = 'pending'",
            params![message_id, payload_digest_sha256],
        )?;
        if changed == 1 {
            return Ok(true);
        }
        let replay: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest_sha256, delivery_state
                 FROM adapter_terminal_output_outbox WHERE message_id = ?1",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(matches!(
            replay,
            Some((digest, state)) if digest == payload_digest_sha256 && state == "consumed"
        ))
    }

    pub fn hold_terminal_output_candidate(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, AdapterEdgeError> {
        Ok(self.connection.execute(
            "UPDATE adapter_terminal_output_outbox SET delivery_state = 'held'
             WHERE message_id = ?1 AND payload_digest_sha256 = ?2
               AND delivery_state = 'pending'",
            params![message_id, payload_digest_sha256],
        )? == 1)
    }

    pub fn resolve_native_execution_binding(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<NativeExecutionBinding>, AdapterEdgeError> {
        let Some(stored) = self.stored_delivered_dispatch_evidence(dispatch_id)? else {
            return Ok(None);
        };
        if sha256(&stored.envelope) != stored.envelope_digest_sha256 {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let envelope = DispatchEnvelope::decode(stored.envelope.as_slice())?;
        if stored.dispatch_id != dispatch_id
            || stored.attempt_id != envelope.attempt_id
            || stored.fencing_token != envelope.fencing_token
            || stored.dispatch_fingerprint != envelope.dispatch_fingerprint
            || envelope.dispatch_id != dispatch_id
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let Some(receipt) = stored.receipt else {
            return if matches!(
                stored.delivery_state.as_str(),
                "prepared" | "delivery_unknown"
            ) {
                Ok(None)
            } else {
                Err(AdapterEdgeError::IntegrityFailure)
            };
        };
        let receipt = DispatchReceipt::decode(receipt.as_slice())?;
        let mut canonical_receipt = receipt.clone();
        let receipt_digest_sha256 = std::mem::take(&mut canonical_receipt.receipt_digest_sha256);
        if receipt.dispatch_id != dispatch_id
            || receipt.attempt_id != envelope.attempt_id
            || receipt.fencing_token != envelope.fencing_token
            || receipt.adapter_id != self.adapter_id
            || envelope
                .capability_profile_ref
                .as_ref()
                .is_none_or(|profile| profile.contract_id != receipt.capability_profile_id)
            || !is_sha256(&receipt_digest_sha256)
            || sha256(&canonical_receipt.encode_to_vec()) != receipt_digest_sha256
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        let disposition = DeliveryDisposition::try_from(receipt.disposition)
            .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
        let expected_state = match disposition {
            DeliveryDisposition::Delivered => "delivered",
            DeliveryDisposition::Rejected => "rejected",
            DeliveryDisposition::Unknown => "delivery_unknown",
            DeliveryDisposition::Unspecified => return Err(AdapterEdgeError::IntegrityFailure),
        };
        if stored.delivery_state != expected_state {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        if disposition != DeliveryDisposition::Delivered {
            return Ok(None);
        }
        let mut bindings = Vec::new();
        match (
            receipt.native_session_ref.as_ref(),
            receipt.native_execution_ref.as_ref(),
        ) {
            (Some(session), Some(execution))
                if !session.trim().is_empty() && !execution.trim().is_empty() =>
            {
                bindings.push((session.clone(), execution.clone()));
            }
            (None, None) | (Some(_), None) => {}
            _ => return Err(AdapterEdgeError::IntegrityFailure),
        }
        let mut statement = self.connection.prepare(
            "SELECT observation_id FROM adapter_observations
             WHERE dispatch_id = ?1 ORDER BY observation_sequence",
        )?;
        let observation_ids = statement
            .query_map([dispatch_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for observation_id in observation_ids {
            let Some((evidence, _)) = self.verified_observation_evidence_by_id(
                dispatch_id,
                &observation_id,
                &receipt.capability_profile_id,
            )?
            else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            let Some(harness_observation::Payload::Ack(ack)) =
                evidence.observation.payload.as_ref()
            else {
                continue;
            };
            if AckDisposition::try_from(ack.disposition) != Ok(AckDisposition::Accepted) {
                continue;
            }
            let (Some(session), Some(execution)) = (
                ack.native_session_ref.as_ref(),
                ack.native_execution_ref.as_ref(),
            ) else {
                return Err(AdapterEdgeError::IntegrityFailure);
            };
            if ack.ack_receipt_id.trim().is_empty()
                || session.trim().is_empty()
                || execution.trim().is_empty()
                || evidence.observation.attempt_id != receipt.attempt_id
                || evidence.observation.fencing_token != receipt.fencing_token
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            bindings.push((session.clone(), execution.clone()));
        }
        bindings.sort();
        bindings.dedup();
        if bindings.len() > 1 {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        Ok(bindings
            .pop()
            .map(
                |(native_session_ref, native_execution_ref)| NativeExecutionBinding {
                    attempt_id: receipt.attempt_id,
                    dispatch_id: receipt.dispatch_id,
                    fencing_token: receipt.fencing_token,
                    native_session_ref,
                    native_execution_ref,
                },
            ))
    }

    pub fn dispatch_receipt(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchReceipt>, AdapterEdgeError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM adapter_dispatches WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        bytes
            .map(|value| DispatchReceipt::decode(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn stored_delivered_dispatch_evidence(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<StoredDeliveredDispatchEvidence>, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT dispatch_id, attempt_id, fencing_token, dispatch_fingerprint,
                        envelope_digest_sha256, envelope, delivery_state, receipt
                 FROM adapter_dispatches WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| {
                    let fencing_token = row.get::<_, i64>(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        fencing_token,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    dispatch_id,
                    attempt_id,
                    fencing_token,
                    dispatch_fingerprint,
                    envelope_digest_sha256,
                    envelope,
                    delivery_state,
                    receipt,
                )| {
                    let fencing_token = u64::try_from(fencing_token)
                        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
                    Ok(StoredDeliveredDispatchEvidence {
                        dispatch_id,
                        attempt_id,
                        fencing_token,
                        dispatch_fingerprint,
                        envelope_digest_sha256,
                        envelope,
                        delivery_state,
                        receipt,
                    })
                },
            )
            .transpose()
    }

    pub fn dispatch_envelope(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchEnvelope>, AdapterEdgeError> {
        let stored: Option<(Vec<u8>, String)> = self
            .connection
            .query_row(
                "SELECT envelope, envelope_digest_sha256
                 FROM adapter_dispatches WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        stored
            .map(|(value, digest)| {
                if sha256(&value) != digest {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                let envelope = DispatchEnvelope::decode(value.as_slice())?;
                if envelope.dispatch_id != dispatch_id {
                    return Err(AdapterEdgeError::IntegrityFailure);
                }
                Ok(envelope)
            })
            .transpose()
    }

    pub fn observation_evidence(
        &self,
        observation_id: &str,
    ) -> Result<Option<AdapterObservationEvidence>, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT observation, raw_event FROM adapter_observations
                 WHERE observation_id = ?1",
                [observation_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(observation, raw_event)| {
                Ok(AdapterObservationEvidence {
                    observation: HarnessObservation::decode(observation.as_slice())?,
                    raw_event,
                })
            })
            .transpose()
    }

    pub fn observation_evidence_by_native_key(
        &self,
        dispatch_id: &str,
        native_key: &str,
    ) -> Result<Option<AdapterObservationEvidence>, AdapterEdgeError> {
        self.connection
            .query_row(
                "SELECT observation, raw_event FROM adapter_observations
                 WHERE dispatch_id = ?1 AND native_key = ?2",
                params![dispatch_id, native_key],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(observation, raw_event)| {
                Ok(AdapterObservationEvidence {
                    observation: HarnessObservation::decode(observation.as_slice())?,
                    raw_event,
                })
            })
            .transpose()
    }

    pub fn observation_evidence_by_sequence(
        &self,
        dispatch_id: &str,
        observation_sequence: u64,
    ) -> Result<Option<AdapterObservationEvidence>, AdapterEdgeError> {
        let observation_sequence =
            i64::try_from(observation_sequence).map_err(|_| AdapterEdgeError::SequenceConflict)?;
        self.connection
            .query_row(
                "SELECT observation, raw_event FROM adapter_observations
                 WHERE dispatch_id = ?1 AND observation_sequence = ?2",
                params![dispatch_id, observation_sequence],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(observation, raw_event)| {
                Ok(AdapterObservationEvidence {
                    observation: HarnessObservation::decode(observation.as_slice())?,
                    raw_event,
                })
            })
            .transpose()
    }

    pub fn cancellation_receipt(
        &self,
        cancellation_request_id: &str,
    ) -> Result<Option<CancelExecutionReceipt>, AdapterEdgeError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM adapter_cancellations
                 WHERE cancellation_request_id = ?1",
                [cancellation_request_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        bytes
            .map(|value| CancelExecutionReceipt::decode(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    pub fn mark_observation_consumed(
        &mut self,
        observation_id: &str,
    ) -> Result<(), AdapterEdgeError> {
        let changed = self.connection.execute(
            "UPDATE adapter_observations SET ingestion_state = 'consumed'
             WHERE observation_id = ?1",
            [observation_id],
        )?;
        if changed != 1 {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        Ok(())
    }

    pub fn consume_legacy_execution_start_duplicate(
        &mut self,
        evidence: &LegacyExecutionStartEvidence,
    ) -> Result<bool, AdapterEdgeError> {
        let observation = &evidence.pending_start.observation;
        let fencing_token = i64::try_from(observation.fencing_token)
            .map_err(|_| AdapterEdgeError::SequenceConflict)?;
        let observation_sequence = i64::try_from(observation.observation_sequence)
            .map_err(|_| AdapterEdgeError::SequenceConflict)?;
        let changed = self.connection.execute(
            "UPDATE adapter_observations SET ingestion_state = 'consumed'
             WHERE observation_id = ?1 AND dispatch_id = ?2 AND attempt_id = ?3
               AND fencing_token = ?4 AND observation_sequence = ?5
               AND native_event_digest_sha256 = ?6 AND ingestion_state = 'pending'",
            params![
                observation.observation_id,
                observation.dispatch_id,
                observation.attempt_id,
                fencing_token,
                observation_sequence,
                observation.native_event_digest_sha256,
            ],
        )?;
        if changed == 1 {
            return Ok(true);
        }
        let replay: Option<(String, String, i64, i64, String, String)> = self
            .connection
            .query_row(
                "SELECT dispatch_id, attempt_id, fencing_token, observation_sequence,
                        native_event_digest_sha256, ingestion_state
                 FROM adapter_observations WHERE observation_id = ?1",
                [&observation.observation_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        Ok(matches!(
            replay,
            Some((dispatch_id, attempt_id, fence, sequence, digest, state))
                if dispatch_id == observation.dispatch_id
                    && attempt_id == observation.attempt_id
                    && fence == fencing_token
                    && sequence == observation_sequence
                    && digest == observation.native_event_digest_sha256
                    && state == "consumed"
        ))
    }

    pub fn quarantine_observation(
        &mut self,
        observation_id: &str,
        reason_code: &str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<(String, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT dispatch_id, native_key, native_event_digest_sha256, raw_event
                 FROM adapter_observations WHERE observation_id = ?1",
                [observation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((dispatch_id, native_key, digest, raw_event)) = record else {
            return Err(AdapterEdgeError::SequenceConflict);
        };
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM adapter_quarantine
               WHERE dispatch_id = ?1 AND native_key = ?2
                 AND conflicting_digest_sha256 = ?3 AND reason_code = ?4
             )",
            params![dispatch_id, native_key, digest, reason_code],
            |row| row.get(0),
        )?;
        if !exists {
            transaction.execute(
                "INSERT INTO adapter_quarantine(
                   quarantine_id, dispatch_id, native_key, prior_digest_sha256,
                   conflicting_digest_sha256, raw_event, reason_code, created_at_seconds
                 ) VALUES(?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
                params![
                    Uuid::now_v7().to_string(),
                    dispatch_id,
                    native_key,
                    digest,
                    raw_event,
                    reason_code,
                    now_seconds
                ],
            )?;
        }
        transaction.execute(
            "UPDATE adapter_observations SET ingestion_state = 'consumed'
             WHERE observation_id = ?1",
            [observation_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn prepare_approval(
        &mut self,
        approval_request_id: &str,
        dispatch_id: &str,
        request_digest_sha256: &str,
        now_seconds: i64,
    ) -> Result<DurableWritePreparation, AdapterEdgeError> {
        prepare_durable_write(
            &self.connection,
            "adapter_approvals",
            "approval_request_id",
            approval_request_id,
            dispatch_id,
            request_digest_sha256,
            now_seconds,
        )
    }

    pub fn begin_approval(
        &mut self,
        approval_request_id: &str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        begin_durable_write(
            &self.connection,
            "adapter_approvals",
            "approval_request_id",
            approval_request_id,
            now_seconds,
        )
    }

    pub fn record_approval_receipt(
        &mut self,
        approval_request_id: &str,
        state: &str,
        receipt: &[u8],
        raw_evidence: &[u8],
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        record_durable_write(
            &self.connection,
            "adapter_approvals",
            "approval_request_id",
            approval_request_id,
            state,
            receipt,
            raw_evidence,
            now_seconds,
            &["delivered", "rejected", "delivery_unknown"],
        )
    }

    /// Reads the provider-neutral approval receipt owned by this Adapter
    /// edge. The Policy Authority uses this only as delivery evidence; it
    /// never writes or repairs the Adapter record through this method.
    pub fn approval_receipt(
        &self,
        approval_request_id: &str,
    ) -> Result<Option<ApprovalDecisionReceipt>, AdapterEdgeError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM adapter_approvals
                 WHERE approval_request_id = ?1",
                [approval_request_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        bytes
            .map(|value| ApprovalDecisionReceipt::decode(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    /// Reads the complete provider-neutral approval delivery record without
    /// exposing the Adapter's raw native evidence.
    pub fn approval_record(
        &self,
        approval_request_id: &str,
    ) -> Result<Option<DurableApprovalRecord>, AdapterEdgeError> {
        let row: Option<(String, String, String, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT dispatch_id, request_digest_sha256, delivery_state, receipt
                 FROM adapter_approvals WHERE approval_request_id = ?1",
                [approval_request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(dispatch_id, request_digest_sha256, state, receipt)| {
            let delivery_state = match state.as_str() {
                "prepared" => ApprovalDeliveryState::Prepared,
                "delivery_unknown" => ApprovalDeliveryState::DeliveryUnknown,
                "delivered" => ApprovalDeliveryState::Delivered,
                "rejected" => ApprovalDeliveryState::Rejected,
                _ => return Err(AdapterEdgeError::IntegrityFailure),
            };
            let receipt = receipt
                .map(|value| ApprovalDecisionReceipt::decode(value.as_slice()))
                .transpose()?;
            if dispatch_id.trim().is_empty()
                || request_digest_sha256.trim().is_empty()
                || (matches!(
                    delivery_state,
                    ApprovalDeliveryState::Delivered | ApprovalDeliveryState::Rejected
                ) && receipt.is_none())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            Ok(DurableApprovalRecord {
                approval_request_id: approval_request_id.to_owned(),
                dispatch_id,
                request_digest_sha256,
                delivery_state,
                receipt,
            })
        })
        .transpose()
    }

    pub fn prepare_cancellation(
        &mut self,
        cancellation_request_id: &str,
        dispatch_id: &str,
        request_digest_sha256: &str,
        now_seconds: i64,
    ) -> Result<DurableWritePreparation, AdapterEdgeError> {
        prepare_durable_write(
            &self.connection,
            "adapter_cancellations",
            "cancellation_request_id",
            cancellation_request_id,
            dispatch_id,
            request_digest_sha256,
            now_seconds,
        )
    }

    pub fn begin_cancellation(
        &mut self,
        cancellation_request_id: &str,
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        begin_durable_write(
            &self.connection,
            "adapter_cancellations",
            "cancellation_request_id",
            cancellation_request_id,
            now_seconds,
        )
    }

    pub fn record_cancellation_receipt(
        &mut self,
        cancellation_request_id: &str,
        state: &str,
        receipt: &[u8],
        raw_evidence: &[u8],
        now_seconds: i64,
    ) -> Result<(), AdapterEdgeError> {
        record_durable_write(
            &self.connection,
            "adapter_cancellations",
            "cancellation_request_id",
            cancellation_request_id,
            state,
            receipt,
            raw_evidence,
            now_seconds,
            &["delivered", "rejected", "unsupported", "delivery_unknown"],
        )
    }

    pub fn inspect(&self) -> Result<AdapterEdgeInspection, AdapterEdgeError> {
        let scalar = |sql: &str| -> Result<u64, AdapterEdgeError> {
            let value: i64 = self.connection.query_row(sql, [], |row| row.get(0))?;
            Ok(value as u64)
        };
        let next: i64 = self.connection.query_row(
            "SELECT next_observation_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let next_content: i64 = self.connection.query_row(
            "SELECT next_content_sequence FROM adapter_edge_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(AdapterEdgeInspection {
            dispatch_count: scalar("SELECT count(*) FROM adapter_dispatches")?,
            delivery_unknown_count: scalar(
                "SELECT count(*) FROM adapter_dispatches WHERE delivery_state = 'delivery_unknown'",
            )?,
            observation_count: scalar("SELECT count(*) FROM adapter_observations")?,
            pending_observation_count: scalar(
                "SELECT count(*) FROM adapter_observations WHERE ingestion_state = 'pending'",
            )?,
            quarantine_count: scalar("SELECT count(*) FROM adapter_quarantine")?,
            cancellation_count: scalar("SELECT count(*) FROM adapter_cancellations")?,
            approval_count: scalar("SELECT count(*) FROM adapter_approvals")?,
            projection_outbox_count: scalar("SELECT count(*) FROM adapter_projection_outbox")?,
            pending_projection_count: scalar(
                "SELECT count(*) FROM adapter_projection_outbox WHERE delivery_state = 'pending'",
            )?,
            terminal_output_outbox_count: scalar(
                "SELECT count(*) FROM adapter_terminal_output_outbox",
            )?,
            pending_terminal_output_count: scalar(
                "SELECT count(*) FROM adapter_terminal_output_outbox WHERE delivery_state = 'pending'",
            )?,
            dispatch_route_binding_count: scalar(
                "SELECT count(*) FROM adapter_dispatch_route_bindings",
            )?,
            content_candidate_count: scalar("SELECT count(*) FROM adapter_content_candidates")?,
            pending_content_candidate_count: scalar(
                "SELECT count(*) FROM adapter_content_candidates WHERE projection_state = 'pending'",
            )?,
            quarantined_content_candidate_count: scalar(
                "SELECT count(*) FROM adapter_content_candidates WHERE projection_state = 'quarantined'",
            )?,
            safe_content_ledger_count: scalar("SELECT count(*) FROM adapter_safe_content_ledger")?,
            content_projection_outbox_count: scalar(
                "SELECT count(*) FROM adapter_content_projection_outbox",
            )?,
            pending_content_projection_count: scalar(
                "SELECT count(*) FROM adapter_content_projection_outbox WHERE delivery_state = 'pending'",
            )?,
            next_observation_sequence: next as u64,
            next_content_sequence: next_content as u64,
        })
    }

    pub fn integrity_is_ok(&self) -> Result<bool, AdapterEdgeError> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(integrity == "ok")
    }
}

fn backfill_approval_projection_outbox(
    connection: &mut Connection,
) -> Result<(), AdapterEdgeError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let records = {
        let mut statement = transaction.prepare(
            "SELECT observation_id, observation_sequence, observation, created_at_seconds
             FROM adapter_observations ORDER BY observation_sequence",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (observation_id, sequence, payload, created_at) in records {
        let observation = HarnessObservation::decode(payload.as_slice())?;
        if matches!(
            observation.payload.as_ref(),
            Some(harness_observation::Payload::ApprovalRequest(_))
        ) {
            let projection_payload = sanitized_approval_projection(&observation)?;
            transaction.execute(
                "INSERT OR IGNORE INTO adapter_projection_outbox(
                   message_id, source_observation_id, source_revision,
                   payload_digest_sha256, payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![
                    format!("adapter-projection-{observation_id}"),
                    observation_id,
                    sequence,
                    sha256(&projection_payload),
                    projection_payload,
                    created_at
                ],
            )?;
        }
    }
    transaction.commit()?;
    Ok(())
}

fn sanitized_approval_projection(
    observation: &HarnessObservation,
) -> Result<Vec<u8>, AdapterEdgeError> {
    let mut projection = observation.clone();
    let request = match projection.payload.as_mut() {
        Some(harness_observation::Payload::ApprovalRequest(request)) => request,
        _ => return Err(AdapterEdgeError::IntegrityFailure),
    };
    request.native_routing_ref.clear();
    Ok(projection.encode_to_vec())
}

fn prepare_durable_write(
    connection: &Connection,
    table: &str,
    identity_column: &str,
    identity: &str,
    dispatch_id: &str,
    request_digest_sha256: &str,
    now_seconds: i64,
) -> Result<DurableWritePreparation, AdapterEdgeError> {
    let select = format!(
        "SELECT request_digest_sha256, delivery_state, receipt FROM {table} WHERE {identity_column} = ?1"
    );
    let existing: Option<(String, String, Option<Vec<u8>>)> = connection
        .query_row(&select, [identity], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()?;
    if let Some((prior_digest, state, receipt)) = existing {
        if prior_digest != request_digest_sha256 {
            return Err(AdapterEdgeError::DispatchConflict);
        }
        if let Some(receipt) = receipt {
            return Ok(DurableWritePreparation::Replay(receipt));
        }
        return Ok(if state == "prepared" {
            DurableWritePreparation::Ready
        } else {
            DurableWritePreparation::DeliveryUnknown
        });
    }
    let insert = format!(
        "INSERT INTO {table}({identity_column}, dispatch_id, request_digest_sha256, delivery_state, created_at_seconds, updated_at_seconds) VALUES(?1, ?2, ?3, 'prepared', ?4, ?4)"
    );
    connection.execute(
        &insert,
        params![identity, dispatch_id, request_digest_sha256, now_seconds],
    )?;
    Ok(DurableWritePreparation::Ready)
}

fn begin_durable_write(
    connection: &Connection,
    table: &str,
    identity_column: &str,
    identity: &str,
    now_seconds: i64,
) -> Result<(), AdapterEdgeError> {
    let update = format!(
        "UPDATE {table} SET delivery_state = 'delivery_unknown', updated_at_seconds = ?1 WHERE {identity_column} = ?2 AND delivery_state = 'prepared' AND receipt IS NULL"
    );
    if connection.execute(&update, params![now_seconds, identity])? != 1 {
        return Err(AdapterEdgeError::DispatchStateConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_durable_write(
    connection: &Connection,
    table: &str,
    identity_column: &str,
    identity: &str,
    state: &str,
    receipt: &[u8],
    raw_evidence: &[u8],
    now_seconds: i64,
    allowed_states: &[&str],
) -> Result<(), AdapterEdgeError> {
    if !allowed_states.contains(&state) {
        return Err(AdapterEdgeError::DispatchStateConflict);
    }
    let update = format!(
        "UPDATE {table} SET delivery_state = ?1, receipt = ?2, raw_evidence = ?3, updated_at_seconds = ?4 WHERE {identity_column} = ?5 AND delivery_state = 'delivery_unknown'"
    );
    if connection.execute(
        &update,
        params![state, receipt, raw_evidence, now_seconds, identity],
    )? == 1
    {
        return Ok(());
    }
    let select = format!("SELECT receipt FROM {table} WHERE {identity_column} = ?1");
    let existing: Option<Vec<u8>> = connection
        .query_row(&select, [identity], |row| row.get(0))
        .optional()?
        .flatten();
    if existing.as_deref() == Some(receipt) {
        Ok(())
    } else {
        Err(AdapterEdgeError::DispatchStateConflict)
    }
}

fn upsert_content_assembly_checkpoint(
    transaction: &Transaction<'_>,
    checkpoint: Option<&ContentAssemblyCheckpoint>,
    records: &[SafeHarnessContentRecord],
    now_seconds: i64,
) -> Result<(), AdapterEdgeError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    let Some(record) = records.first() else {
        return Err(AdapterEdgeError::IntegrityFailure);
    };
    if checkpoint.message_id.trim().is_empty()
        || checkpoint.current_revision == 0
        || !is_sha256(&checkpoint.raw_cumulative_digest_sha256)
        || !is_sha256(&checkpoint.safe_cumulative_digest_sha256)
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    for (index, record) in records.iter().enumerate() {
        match record.payload.as_ref() {
            Some(safe_harness_content_record::Payload::AssistantText(safe))
                if safe.revision == checkpoint.current_revision
                    && safe.safe_cumulative_digest_sha256
                        == checkpoint.safe_cumulative_digest_sha256 => {}
            Some(safe_harness_content_record::Payload::Marker(marker))
                if index.saturating_add(1) == records.len()
                    && marker.kind == HarnessContentMarkerKind::LimitReached as i32 => {}
            _ => return Err(AdapterEdgeError::IntegrityFailure),
        }
    }
    let revision = i64::try_from(checkpoint.current_revision)
        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
    let encoded = encode_assembly_state(checkpoint, records);
    let existing: Option<(i64, String, String, Vec<u8>)> = transaction
        .query_row(
            "SELECT current_revision, raw_cumulative_digest_sha256,
                    safe_cumulative_digest_sha256, assembly_state
             FROM adapter_content_assemblies
             WHERE dispatch_id = ?1 AND message_id = ?2",
            params![record.dispatch_id, checkpoint.message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    match existing {
        None if checkpoint.current_revision == 1 => {
            transaction.execute(
                "INSERT INTO adapter_content_assemblies(
                   dispatch_id, message_id, current_revision, finalized,
                   raw_cumulative_digest_sha256, safe_cumulative_digest_sha256,
                   credential_commitment_hmac_sha256, assembly_state,
                   updated_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6,
                   (SELECT credential_commitment_hmac_sha256
                    FROM adapter_content_redaction_bindings WHERE dispatch_id = ?1),
                   ?7, ?8)",
                params![
                    record.dispatch_id,
                    checkpoint.message_id,
                    revision,
                    checkpoint.finalized,
                    checkpoint.raw_cumulative_digest_sha256,
                    checkpoint.safe_cumulative_digest_sha256,
                    encoded,
                    now_seconds
                ],
            )?;
        }
        Some((current, _, _, _)) if checkpoint.current_revision == current as u64 + 1 => {
            transaction.execute(
                "UPDATE adapter_content_assemblies
                 SET current_revision = ?1, finalized = ?2,
                     raw_cumulative_digest_sha256 = ?3,
                     safe_cumulative_digest_sha256 = ?4, assembly_state = ?5,
                     updated_at_seconds = ?6
                 WHERE dispatch_id = ?7 AND message_id = ?8 AND current_revision = ?9",
                params![
                    revision,
                    checkpoint.finalized,
                    checkpoint.raw_cumulative_digest_sha256,
                    checkpoint.safe_cumulative_digest_sha256,
                    encoded,
                    now_seconds,
                    record.dispatch_id,
                    checkpoint.message_id,
                    current
                ],
            )?;
        }
        Some((current, raw, safe, prior))
            if current == revision
                && raw == checkpoint.raw_cumulative_digest_sha256
                && safe == checkpoint.safe_cumulative_digest_sha256
                && prior == encoded => {}
        _ => return Err(AdapterEdgeError::SequenceConflict),
    }
    Ok(())
}

fn assembly_checkpoint_matches(
    transaction: &Transaction<'_>,
    dispatch_id: &str,
    checkpoint: Option<&ContentAssemblyCheckpoint>,
    records: &[SafeHarnessContentRecord],
) -> Result<bool, AdapterEdgeError> {
    let Some(checkpoint) = checkpoint else {
        return Ok(true);
    };
    let stored: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT assembly_state FROM adapter_content_assemblies
             WHERE dispatch_id = ?1 AND message_id = ?2",
            params![dispatch_id, checkpoint.message_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(stored.as_deref() == Some(encode_assembly_state(checkpoint, records).as_slice()))
}

fn encode_assembly_state(
    checkpoint: &ContentAssemblyCheckpoint,
    records: &[SafeHarnessContentRecord],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        b"egopulse/harness-content/assembly-checkpoint/v1".as_slice(),
        checkpoint.message_id.as_bytes(),
        &checkpoint.current_revision.to_le_bytes(),
        checkpoint.candidate_digest_sha256.as_bytes(),
        &[u8::from(checkpoint.finalized)],
        checkpoint.raw_cumulative.as_slice(),
        checkpoint.raw_cumulative_digest_sha256.as_bytes(),
        checkpoint.safe_cumulative.as_bytes(),
        checkpoint.safe_cumulative_digest_sha256.as_bytes(),
        checkpoint.withheld_suffix.as_bytes(),
    ] {
        frame_bytes(&mut bytes, value);
    }
    frame_bytes(&mut bytes, &(records.len() as u64).to_le_bytes());
    for record in records {
        frame_bytes(&mut bytes, &record.encode_to_vec());
    }
    bytes
}

fn decode_assembly_state(
    bytes: &[u8],
) -> Result<(ContentAssemblyCheckpoint, Vec<SafeHarnessContentRecord>), AdapterEdgeError> {
    let mut cursor = 0_usize;
    let domain = take_frame(bytes, &mut cursor)?;
    let message_id = frame_string(bytes, &mut cursor)?;
    let revision = frame_u64(bytes, &mut cursor)?;
    let candidate_digest_sha256 = frame_string(bytes, &mut cursor)?;
    let finalized = match take_frame(bytes, &mut cursor)? {
        [0] => false,
        [1] => true,
        _ => return Err(AdapterEdgeError::IntegrityFailure),
    };
    let raw_cumulative = take_frame(bytes, &mut cursor)?.to_vec();
    let raw_digest = frame_string(bytes, &mut cursor)?;
    let safe_cumulative = frame_string(bytes, &mut cursor)?;
    let safe_digest = frame_string(bytes, &mut cursor)?;
    let withheld_suffix = frame_string(bytes, &mut cursor)?;
    let record_count = frame_u64(bytes, &mut cursor)?;
    if domain != b"egopulse/harness-content/assembly-checkpoint/v1"
        || record_count == 0
        || record_count > 65_536
        || message_id.trim().is_empty()
        || revision == 0
        || !is_sha256(&candidate_digest_sha256)
        || withheld_suffix.len() > 3_071
        || raw_digest
            != framed_content_digest(
                b"egopulse/harness-content/raw-cumulative/v1",
                &raw_cumulative,
            )
        || safe_digest
            != framed_content_digest(
                b"egopulse/harness-content/safe-cumulative/v1",
                safe_cumulative.as_bytes(),
            )
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let mut records = Vec::with_capacity(
        usize::try_from(record_count).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
    );
    for expected_part in 0..record_count {
        let record = SafeHarnessContentRecord::decode(take_frame(bytes, &mut cursor)?)?;
        if canonical_safe_record_digest(&record).as_deref()
            != Some(record.record_digest_sha256.as_str())
            || !projection_record_position_is_valid(
                &record,
                usize::try_from(expected_part).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                usize::try_from(record_count).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            )
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        records.push(record);
    }
    if cursor != bytes.len() || records.is_empty() {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    Ok((
        ContentAssemblyCheckpoint {
            message_id,
            current_revision: revision,
            candidate_digest_sha256,
            finalized,
            raw_cumulative,
            raw_cumulative_digest_sha256: raw_digest,
            safe_cumulative,
            safe_cumulative_digest_sha256: safe_digest,
            withheld_suffix,
        },
        records,
    ))
}

fn take_frame<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], AdapterEdgeError> {
    let length_bytes: [u8; 8] = bytes
        .get(*cursor..(*cursor).saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    *cursor = (*cursor).saturating_add(8);
    let length = usize::try_from(u64::from_le_bytes(length_bytes))
        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
    let end = (*cursor)
        .checked_add(length)
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    *cursor = end;
    Ok(value)
}

fn frame_string(bytes: &[u8], cursor: &mut usize) -> Result<String, AdapterEdgeError> {
    String::from_utf8(take_frame(bytes, cursor)?.to_vec())
        .map_err(|_| AdapterEdgeError::IntegrityFailure)
}

fn frame_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, AdapterEdgeError> {
    let value: [u8; 8] = take_frame(bytes, cursor)?
        .try_into()
        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
    Ok(u64::from_le_bytes(value))
}

fn framed_content_digest(domain: &[u8], value: &[u8]) -> String {
    let mut bytes = Vec::new();
    frame_bytes(&mut bytes, domain);
    frame_bytes(&mut bytes, value);
    sha256(&bytes)
}

const fn relation_policy_name(policy: FinalArtifactRelationPolicy) -> &'static str {
    match policy {
        FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly => "legacy_not_required",
        FinalArtifactRelationPolicy::RequiredGovernedContent => "required_governed_content",
    }
}

fn mark_final_artifact_relation_skipped(
    transaction: &Transaction<'_>,
    terminal_message_id: &str,
    safe_reason_code: &'static str,
    now_seconds: i64,
) -> Result<(), AdapterEdgeError> {
    let changed = transaction.execute(
        "UPDATE adapter_final_artifact_relation_intents
         SET relation_state = 'skipped', safe_reason_code = ?1,
             updated_at_seconds = ?2
         WHERE terminal_message_id = ?3 AND relation_state = 'pending'",
        params![safe_reason_code, now_seconds, terminal_message_id],
    )?;
    if changed != 1 {
        return Err(AdapterEdgeError::SequenceConflict);
    }
    Ok(())
}

fn final_artifact_relation_budget_skip_reason(
    record: &SafeHarnessContentRecord,
    attempt_budget: ContentBudgetState,
    task_budget: ContentBudgetState,
    limits: ContentBudgetLimits,
) -> Result<Option<FinalArtifactRelationSkipReason>, AdapterEdgeError> {
    let admission = admit_content_records(
        std::slice::from_ref(record),
        attempt_budget,
        task_budget,
        limits,
    )?;
    if admission.records.as_slice() == std::slice::from_ref(record)
        && admission.text_bytes == 0
        && admission.limit_kind.is_none()
    {
        return Ok(None);
    }
    if attempt_budget.terminal_kind.is_some() || task_budget.terminal_kind.is_some() {
        Ok(Some(FinalArtifactRelationSkipReason::ScopeTerminal))
    } else {
        Ok(Some(FinalArtifactRelationSkipReason::NoRecordSlot))
    }
}

const fn final_artifact_relation_skip_reason_code(
    reason: FinalArtifactRelationSkipReason,
) -> &'static str {
    match reason {
        FinalArtifactRelationSkipReason::NoSafeAssistantContent => {
            "FINAL_ARTIFACT_RELATION_NO_SAFE_ASSISTANT_CONTENT"
        }
        FinalArtifactRelationSkipReason::ScopeTerminal => "FINAL_ARTIFACT_RELATION_SCOPE_TERMINAL",
        FinalArtifactRelationSkipReason::NoRecordSlot => "FINAL_ARTIFACT_RELATION_NO_RECORD_SLOT",
    }
}

#[derive(Clone, Copy)]
struct ContentBudgetLimits {
    attempt_text_bytes: u64,
    attempt_records: u64,
    task_text_bytes: u64,
    task_records: u64,
}

const CONTENT_BUDGET_LIMITS: ContentBudgetLimits = ContentBudgetLimits {
    attempt_text_bytes: ATTEMPT_SAFE_TEXT_BYTES,
    attempt_records: ATTEMPT_SAFE_RECORDS,
    task_text_bytes: TASK_SAFE_TEXT_BYTES,
    task_records: TASK_SAFE_RECORDS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContentBudgetState {
    text_bytes: u64,
    record_count: u64,
    terminal_kind: Option<HarnessContentLimitKind>,
}

impl From<ContentBudgetState> for SafeContentBudgetUsage {
    fn from(value: ContentBudgetState) -> Self {
        Self {
            safe_text_bytes: value.text_bytes,
            safe_record_count: value.record_count,
            limit_reached: value.terminal_kind.is_some(),
        }
    }
}

struct ContentAdmission {
    records: Vec<SafeHarnessContentRecord>,
    text_bytes: u64,
    limit_kind: Option<HarnessContentLimitKind>,
    attempt_terminal_kind: Option<HarnessContentLimitKind>,
    task_terminal_kind: Option<HarnessContentLimitKind>,
}

fn safe_record_text_bytes(record: &SafeHarnessContentRecord) -> u64 {
    match record.payload.as_ref() {
        Some(safe_harness_content_record::Payload::AssistantText(text)) => {
            text.safe_text_utf8.len() as u64
        }
        _ => 0,
    }
}

fn load_content_budget(
    transaction: &Transaction<'_>,
    scope_kind: &str,
    scope_id: &str,
) -> Result<ContentBudgetState, AdapterEdgeError> {
    let stored: Option<(i64, i64, bool, Option<String>)> = transaction
        .query_row(
            "SELECT safe_text_bytes, safe_record_count, limit_reached, limit_kind
             FROM adapter_content_budgets WHERE scope_kind = ?1 AND scope_id = ?2",
            params![scope_kind, scope_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((text_bytes, record_count, limit_reached, limit_kind)) = stored else {
        return Ok(ContentBudgetState {
            text_bytes: 0,
            record_count: 0,
            terminal_kind: None,
        });
    };
    let terminal_kind = match (limit_reached, limit_kind.as_deref()) {
        (false, None) => None,
        (true, Some(value)) => {
            Some(parse_limit_kind(value).ok_or(AdapterEdgeError::IntegrityFailure)?)
        }
        _ => return Err(AdapterEdgeError::IntegrityFailure),
    };
    Ok(ContentBudgetState {
        text_bytes: u64::try_from(text_bytes).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
        record_count: u64::try_from(record_count)
            .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
        terminal_kind,
    })
}

fn load_stored_content_budget(
    transaction: &Transaction<'_>,
    scope_kind: &str,
    scope_id: &str,
) -> Result<Option<ContentBudgetState>, AdapterEdgeError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM adapter_content_budgets
             WHERE scope_kind = ?1 AND scope_id = ?2",
            params![scope_kind, scope_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    exists
        .then(|| load_content_budget(transaction, scope_kind, scope_id))
        .transpose()
}

fn verified_content_budgets_from_owner_history(
    transaction: &Transaction<'_>,
    task_id: &str,
    attempt_id: &str,
) -> Result<(ContentBudgetState, ContentBudgetState), AdapterEdgeError> {
    let empty = ContentBudgetState {
        text_bytes: 0,
        record_count: 0,
        terminal_kind: None,
    };
    let Some(owner) = load_content_owner_snapshot(transaction, task_id)? else {
        if load_stored_content_budget(transaction, "task", task_id)?.is_some()
            || load_stored_content_budget(transaction, "attempt", attempt_id)?.is_some()
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        return Ok((empty, empty));
    };
    // Terminal retention intentionally deletes the old ledger. A tombstone is
    // sufficient to prove that this owner can never accept new content, but it
    // cannot be used to fabricate the deleted budget history.
    if !owner.tombstones.is_empty() {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    if owner.records.is_empty() || owner.records.len() as u64 > TASK_SAFE_RECORDS {
        return Err(AdapterEdgeError::IntegrityFailure);
    }

    let task = content_budget_from_owner_records(&owner.records, None)?;
    let attempt = content_budget_from_owner_records(&owner.records, Some(attempt_id))?;
    let stored_task = load_stored_content_budget(transaction, "task", task_id)?
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    if stored_task != task {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    match load_stored_content_budget(transaction, "attempt", attempt_id)? {
        Some(stored_attempt)
            if stored_attempt.text_bytes == attempt.text_bytes
                && stored_attempt.record_count == attempt.record_count
                && (stored_attempt.terminal_kind == attempt.terminal_kind
                    || task.terminal_kind.is_some()
                        && matches!(
                            stored_attempt.terminal_kind,
                            Some(
                                HarnessContentLimitKind::AttemptRecords
                                    | HarnessContentLimitKind::AttemptTextBytes
                            )
                        )) => {}
        None if attempt == empty => {}
        _ => return Err(AdapterEdgeError::IntegrityFailure),
    }
    Ok((attempt, task))
}

fn content_budget_from_owner_records(
    records: &[SafeContentOwnerRecord],
    attempt_id: Option<&str>,
) -> Result<ContentBudgetState, AdapterEdgeError> {
    let mut text_bytes = 0_u64;
    let mut record_count = 0_u64;
    let mut terminal_kinds = Vec::new();
    for owner_record in records {
        let record = &owner_record.record;
        if attempt_id.is_some_and(|expected| record.attempt_id != expected) {
            continue;
        }
        if record.attempt_id.trim().is_empty()
            || safe_record_text_bytes(record) > CONTENT_SAFE_PART_BYTES as u64
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        record_count = record_count
            .checked_add(1)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        text_bytes = text_bytes
            .checked_add(safe_record_text_bytes(record))
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        if let Some(kind) = committed_limit_kind(std::slice::from_ref(record))?
            && match attempt_id {
                Some(_) => matches!(
                    kind,
                    HarnessContentLimitKind::AttemptRecords
                        | HarnessContentLimitKind::AttemptTextBytes
                ),
                None => matches!(
                    kind,
                    HarnessContentLimitKind::TaskRecords | HarnessContentLimitKind::TaskTextBytes
                ),
            }
        {
            terminal_kinds.push(Some(kind));
        }
    }
    let (record_limit, text_limit) = if attempt_id.is_some() {
        (ATTEMPT_SAFE_RECORDS, ATTEMPT_SAFE_TEXT_BYTES)
    } else {
        (TASK_SAFE_RECORDS, TASK_SAFE_TEXT_BYTES)
    };
    if record_count > record_limit || text_bytes > text_limit {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    Ok(ContentBudgetState {
        text_bytes,
        record_count,
        terminal_kind: winning_limit_kind(terminal_kinds),
    })
}

fn utf8_prefix_at_most(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn safe_projection_input_digest(projection: &SafeContentProjection) -> String {
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/safe-projection-input/v1",
    );
    frame_bytes(
        &mut bytes,
        &(projection.records().len() as u64).to_le_bytes(),
    );
    for record in projection.records() {
        frame_bytes(&mut bytes, &record.encode_to_vec());
    }
    match projection.checkpoint.as_ref() {
        Some(checkpoint) => {
            frame_bytes(&mut bytes, &[1]);
            frame_bytes(
                &mut bytes,
                &encode_assembly_state(checkpoint, projection.records()),
            );
        }
        None => frame_bytes(&mut bytes, &[0]),
    }
    sha256(&bytes)
}

fn committed_records_digest(records: &[SafeHarnessContentRecord]) -> String {
    let mut bytes = Vec::new();
    frame_bytes(&mut bytes, b"egopulse/harness-content/committed-records/v1");
    frame_bytes(&mut bytes, &(records.len() as u64).to_le_bytes());
    for record in records {
        frame_bytes(&mut bytes, &record.encode_to_vec());
    }
    sha256(&bytes)
}

fn limit_marker_record(
    template: &SafeHarnessContentRecord,
    limit_kind: HarnessContentLimitKind,
) -> Result<SafeHarnessContentRecord, AdapterEdgeError> {
    if limit_kind == HarnessContentLimitKind::Unspecified {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let mut marker = template.clone();
    marker.record_id =
        canonical_safe_record_id(&template.content_event_id, "MARKER", limit_kind, 0);
    marker.record_digest_sha256.clear();
    marker.safety_flags.clear();
    marker.payload = Some(safe_harness_content_record::Payload::Marker(
        SafeContentMarker {
            kind: HarnessContentMarkerKind::LimitReached as i32,
            limit_kind: limit_kind as i32,
        },
    ));
    marker.record_digest_sha256 =
        canonical_safe_record_digest(&marker).ok_or(AdapterEdgeError::IntegrityFailure)?;
    Ok(marker)
}

fn admit_content_records(
    records: &[SafeHarnessContentRecord],
    attempt: ContentBudgetState,
    task: ContentBudgetState,
    limits: ContentBudgetLimits,
) -> Result<ContentAdmission, AdapterEdgeError> {
    if attempt.record_count > limits.attempt_records
        || task.record_count > limits.task_records
        || attempt.text_bytes > limits.attempt_text_bytes
        || task.text_bytes > limits.task_text_bytes
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    if attempt.terminal_kind.is_some() || task.terminal_kind.is_some() {
        return Ok(ContentAdmission {
            records: Vec::new(),
            text_bytes: 0,
            limit_kind: winning_limit_kind([task.terminal_kind, attempt.terminal_kind]),
            attempt_terminal_kind: attempt.terminal_kind,
            task_terminal_kind: task.terminal_kind,
        });
    }
    let attempt_record_capacity = limits
        .attempt_records
        .saturating_sub(1)
        .saturating_sub(attempt.record_count);
    let task_record_capacity = limits
        .task_records
        .saturating_sub(1)
        .saturating_sub(task.record_count);
    let mut admitted = Vec::new();
    let mut text_bytes = 0_u64;
    let mut attempt_text_remaining = limits.attempt_text_bytes.saturating_sub(attempt.text_bytes);
    let mut task_text_remaining = limits.task_text_bytes.saturating_sub(task.text_bytes);
    for record in records {
        let record_text_bytes = safe_record_text_bytes(record);
        let admitted_count = admitted.len() as u64;
        let attempt_record_blocked = admitted_count >= attempt_record_capacity;
        let task_record_blocked = admitted_count >= task_record_capacity;
        let attempt_text_blocked = record_text_bytes > attempt_text_remaining;
        let task_text_blocked = record_text_bytes > task_text_remaining;
        if !attempt_record_blocked
            && !task_record_blocked
            && !attempt_text_blocked
            && !task_text_blocked
        {
            admitted.push(record.clone());
            attempt_text_remaining -= record_text_bytes;
            task_text_remaining -= record_text_bytes;
            text_bytes += record_text_bytes;
            continue;
        }
        if !attempt_record_blocked
            && !task_record_blocked
            && let Some(safe_harness_content_record::Payload::AssistantText(text)) =
                record.payload.as_ref()
        {
            let text_capacity = attempt_text_remaining.min(task_text_remaining);
            let prefix = utf8_prefix_at_most(&text.safe_text_utf8, text_capacity as usize);
            if !prefix.is_empty() {
                let mut partial = record.clone();
                let Some(safe_harness_content_record::Payload::AssistantText(value)) =
                    partial.payload.as_mut()
                else {
                    unreachable!()
                };
                value.safe_text_utf8 = prefix.to_owned();
                partial.record_digest_sha256.clear();
                partial.record_digest_sha256 = canonical_safe_record_digest(&partial)
                    .ok_or(AdapterEdgeError::IntegrityFailure)?;
                text_bytes += prefix.len() as u64;
                attempt_text_remaining -= prefix.len() as u64;
                task_text_remaining -= prefix.len() as u64;
                admitted.push(partial);
            }
        }
        let added_record_count = (admitted.len() as u64)
            .checked_add(1)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let attempt_record_count = attempt
            .record_count
            .checked_add(added_record_count)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let task_record_count = task
            .record_count
            .checked_add(added_record_count)
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        let attempt_record_terminal =
            attempt_record_blocked || attempt_record_count >= limits.attempt_records;
        let task_record_terminal = task_record_blocked || task_record_count >= limits.task_records;
        let attempt_text_terminal = attempt_text_blocked || attempt_text_remaining == 0;
        let task_text_terminal = task_text_blocked || task_text_remaining == 0;
        let attempt_terminal_kind = scope_terminal_kind(
            attempt_record_terminal,
            attempt_text_terminal,
            HarnessContentLimitKind::AttemptRecords,
            HarnessContentLimitKind::AttemptTextBytes,
        );
        let task_terminal_kind = scope_terminal_kind(
            task_record_terminal,
            task_text_terminal,
            HarnessContentLimitKind::TaskRecords,
            HarnessContentLimitKind::TaskTextBytes,
        );
        let limit_kind = winning_limit_kind([task_terminal_kind, attempt_terminal_kind])
            .ok_or(AdapterEdgeError::IntegrityFailure)?;
        admitted.push(limit_marker_record(&records[0], limit_kind)?);
        return Ok(ContentAdmission {
            records: admitted,
            text_bytes,
            limit_kind: Some(limit_kind),
            attempt_terminal_kind,
            task_terminal_kind,
        });
    }
    Ok(ContentAdmission {
        records: admitted,
        text_bytes,
        limit_kind: None,
        attempt_terminal_kind: None,
        task_terminal_kind: None,
    })
}

fn scope_terminal_kind(
    records: bool,
    text_bytes: bool,
    records_kind: HarnessContentLimitKind,
    text_kind: HarnessContentLimitKind,
) -> Option<HarnessContentLimitKind> {
    records
        .then_some(records_kind)
        .or_else(|| text_bytes.then_some(text_kind))
}

fn winning_limit_kind(
    kinds: impl IntoIterator<Item = Option<HarnessContentLimitKind>>,
) -> Option<HarnessContentLimitKind> {
    kinds.into_iter().flatten().max_by_key(|kind| match kind {
        HarnessContentLimitKind::TaskRecords => 4,
        HarnessContentLimitKind::TaskTextBytes => 3,
        HarnessContentLimitKind::AttemptRecords => 2,
        HarnessContentLimitKind::AttemptTextBytes => 1,
        HarnessContentLimitKind::Unspecified => 0,
    })
}

fn limit_kind_name(kind: HarnessContentLimitKind) -> &'static str {
    kind.as_str_name()
        .strip_prefix("HARNESS_CONTENT_LIMIT_KIND_")
        .expect("generated limit kind uses the frozen prefix")
}

fn parse_limit_kind(value: &str) -> Option<HarnessContentLimitKind> {
    match value {
        "ATTEMPT_TEXT_BYTES" => Some(HarnessContentLimitKind::AttemptTextBytes),
        "ATTEMPT_RECORDS" => Some(HarnessContentLimitKind::AttemptRecords),
        "TASK_TEXT_BYTES" => Some(HarnessContentLimitKind::TaskTextBytes),
        "TASK_RECORDS" => Some(HarnessContentLimitKind::TaskRecords),
        _ => None,
    }
}

fn decode_stored_limit_kind(
    value: Option<&str>,
) -> Result<Option<HarnessContentLimitKind>, AdapterEdgeError> {
    value
        .map(|value| parse_limit_kind(value).ok_or(AdapterEdgeError::IntegrityFailure))
        .transpose()
}

fn committed_limit_kind(
    records: &[SafeHarnessContentRecord],
) -> Result<Option<HarnessContentLimitKind>, AdapterEdgeError> {
    let Some(last) = records.last() else {
        return Ok(None);
    };
    let Some(safe_harness_content_record::Payload::Marker(marker)) = last.payload.as_ref() else {
        return Ok(None);
    };
    if marker.kind != HarnessContentMarkerKind::LimitReached as i32 {
        return Ok(None);
    }
    let kind = HarnessContentLimitKind::try_from(marker.limit_kind)
        .map_err(|_| AdapterEdgeError::IntegrityFailure)?;
    (kind != HarnessContentLimitKind::Unspecified)
        .then_some(kind)
        .ok_or(AdapterEdgeError::IntegrityFailure)
        .map(Some)
}

struct ContentBudgetUpdate<'a> {
    scope_kind: &'a str,
    scope_id: &'a str,
    previous: ContentBudgetState,
    added_text_bytes: u64,
    added_records: u64,
    terminal_kind: Option<HarnessContentLimitKind>,
}

fn update_content_budget(
    transaction: &Transaction<'_>,
    update: ContentBudgetUpdate<'_>,
    now_seconds: i64,
) -> Result<(), AdapterEdgeError> {
    let next_text = update
        .previous
        .text_bytes
        .checked_add(update.added_text_bytes)
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    let next_records = update
        .previous
        .record_count
        .checked_add(update.added_records)
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    if update.terminal_kind == Some(HarnessContentLimitKind::Unspecified) {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let next_terminal_kind = update.terminal_kind.or(update.previous.terminal_kind);
    let changed = transaction.execute(
        "INSERT INTO adapter_content_budgets(
           scope_kind, scope_id, safe_text_bytes, safe_record_count,
           limit_reached, limit_kind, updated_at_seconds
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(scope_kind, scope_id) DO UPDATE SET
           safe_text_bytes = excluded.safe_text_bytes,
           safe_record_count = excluded.safe_record_count,
           limit_reached = excluded.limit_reached,
           limit_kind = excluded.limit_kind,
           updated_at_seconds = excluded.updated_at_seconds
         WHERE adapter_content_budgets.safe_text_bytes = ?8
           AND adapter_content_budgets.safe_record_count = ?9
           AND adapter_content_budgets.limit_reached = ?10
           AND adapter_content_budgets.limit_kind IS ?11",
        params![
            update.scope_kind,
            update.scope_id,
            i64::try_from(next_text).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            i64::try_from(next_records).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            next_terminal_kind.is_some(),
            next_terminal_kind.map(limit_kind_name),
            now_seconds,
            i64::try_from(update.previous.text_bytes)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            i64::try_from(update.previous.record_count)
                .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            update.previous.terminal_kind.is_some(),
            update.previous.terminal_kind.map(limit_kind_name),
        ],
    )?;
    if changed != 1 {
        return Err(AdapterEdgeError::SequenceConflict);
    }
    Ok(())
}

fn update_content_owner_metadata(
    transaction: &Transaction<'_>,
    task_id: &str,
    sequenced: &[(i64, &SafeHarnessContentRecord)],
    now_seconds: i64,
) -> Result<(), AdapterEdgeError> {
    if sequenced.is_empty() {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    transaction.execute(
        "INSERT OR IGNORE INTO adapter_content_history_floors(
           task_id, floor_sequence, floor_digest_sha256, updated_at_seconds
         ) VALUES(?1, 0, ?2, ?3)",
        params![task_id, content_floor_digest(task_id, 0), now_seconds],
    )?;
    let empty_records = Vec::new();
    let empty_tombstones = Vec::new();
    let baseline_state = encode_content_owner_baseline(&empty_records, &empty_tombstones);
    let baseline_digest =
        content_owner_snapshot_digest(task_id, 0, 0, &empty_records, &empty_tombstones);
    transaction.execute(
        "INSERT INTO adapter_content_owner_snapshots(
           task_id, owner_sequence, floor_sequence,
           disclosure_profile_digest_sha256, baseline_state,
           baseline_digest_sha256, snapshot_digest_sha256, updated_at_seconds
         ) VALUES(?1, 0, 0, ?2, ?3, ?4, ?4, ?5)
         ON CONFLICT(task_id) DO NOTHING",
        params![
            task_id,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
            baseline_state,
            baseline_digest,
            now_seconds
        ],
    )?;
    let (owner_sequence, mut snapshot_digest): (i64, String) = transaction.query_row(
        "SELECT owner_sequence, snapshot_digest_sha256
         FROM adapter_content_owner_snapshots WHERE task_id = ?1",
        [task_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut previous_sequence = owner_sequence;
    for (sequence, record) in sequenced {
        if *sequence <= previous_sequence || record.task_id != task_id {
            return Err(AdapterEdgeError::SequenceConflict);
        }
        snapshot_digest = content_owner_incremental_digest(
            &snapshot_digest,
            u64::try_from(*sequence).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
            &record.record_digest_sha256,
        );
        previous_sequence = *sequence;
    }
    transaction.execute(
        "UPDATE adapter_content_owner_snapshots
         SET owner_sequence = ?1, snapshot_digest_sha256 = ?2,
             updated_at_seconds = ?3
         WHERE task_id = ?4 AND owner_sequence = ?5",
        params![
            previous_sequence,
            snapshot_digest,
            now_seconds,
            task_id,
            owner_sequence
        ],
    )?;
    Ok(())
}

fn load_content_owner_snapshot(
    transaction: &Transaction<'_>,
    task_id: &str,
) -> Result<Option<SafeContentOwnerSnapshot>, AdapterEdgeError> {
    let metadata: Option<(i64, i64, String, Vec<u8>, String, String)> = transaction
        .query_row(
            "SELECT owner_sequence, floor_sequence,
                    disclosure_profile_digest_sha256, baseline_state,
                    baseline_digest_sha256, snapshot_digest_sha256
             FROM adapter_content_owner_snapshots WHERE task_id = ?1",
            [task_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        owner_sequence,
        floor_sequence,
        profile_digest,
        baseline_state,
        baseline_digest,
        snapshot_digest,
    )) = metadata
    else {
        return Ok(None);
    };
    let floor_row: Option<(i64, String)> = transaction
        .query_row(
            "SELECT floor_sequence, floor_digest_sha256
             FROM adapter_content_history_floors WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let valid_numbers =
        owner_sequence >= 0 && floor_sequence >= 0 && owner_sequence >= floor_sequence;
    if !valid_numbers
        || profile_digest != HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
        || !is_sha256(&baseline_digest)
        || !is_sha256(&snapshot_digest)
        || floor_row
            != Some((
                floor_sequence,
                content_floor_digest(task_id, floor_sequence as u64),
            ))
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let (mut records, tombstones) = decode_content_owner_baseline(&baseline_state, task_id)?;
    if content_owner_snapshot_digest(
        task_id,
        floor_sequence as u64,
        floor_sequence as u64,
        &records,
        &tombstones,
    ) != baseline_digest
        || !records.last().map_or_else(
            || {
                floor_sequence == 0
                    || tombstones
                        .iter()
                        .any(|tombstone| tombstone.final_sequence == floor_sequence as u64)
            },
            |record| record.sequence <= floor_sequence as u64,
        )
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let delta = load_owner_records(transaction, task_id, floor_sequence, owner_sequence)?;
    let mut expected = baseline_digest;
    for record in &delta {
        expected = content_owner_incremental_digest(
            &expected,
            record.sequence,
            &record.record.record_digest_sha256,
        );
    }
    if expected != snapshot_digest
        || delta
            .last()
            .map_or(floor_sequence as u64, |record| record.sequence)
            != owner_sequence as u64
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    records.extend(delta);
    Ok(Some(SafeContentOwnerSnapshot {
        task_id: task_id.to_owned(),
        owner_sequence: owner_sequence as u64,
        floor_sequence: floor_sequence as u64,
        disclosure_profile_digest_sha256: profile_digest,
        snapshot_digest_sha256: snapshot_digest,
        records,
        tombstones,
    }))
}

fn load_owner_records(
    transaction: &Transaction<'_>,
    task_id: &str,
    floor_sequence: i64,
    owner_sequence: i64,
) -> Result<Vec<SafeContentOwnerRecord>, AdapterEdgeError> {
    let mut statement = transaction.prepare(
        "SELECT content_sequence, record_digest_sha256, safe_record
         FROM adapter_safe_content_ledger
         WHERE task_id = ?1 AND content_sequence > ?2 AND content_sequence <= ?3
         ORDER BY content_sequence",
    )?;
    let rows = statement
        .query_map(params![task_id, floor_sequence, owner_sequence], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(sequence, stored_digest, bytes)| {
            let sequence =
                u64::try_from(sequence).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
            let record = SafeHarnessContentRecord::decode(bytes.as_slice())?;
            if sequence == 0
                || record.task_id != task_id
                || record.record_digest_sha256 != stored_digest
                || canonical_safe_record_digest(&record).as_deref() != Some(stored_digest.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            Ok(SafeContentOwnerRecord { sequence, record })
        })
        .collect()
}

fn content_floor_digest(task_id: &str, floor_sequence: u64) -> String {
    let mut bytes = Vec::new();
    frame_bytes(&mut bytes, b"egopulse/harness-content/owner-floor/v1");
    frame_bytes(&mut bytes, task_id.as_bytes());
    frame_bytes(&mut bytes, &floor_sequence.to_le_bytes());
    sha256(&bytes)
}

fn content_owner_snapshot_digest(
    task_id: &str,
    owner_sequence: u64,
    floor_sequence: u64,
    records: &[SafeContentOwnerRecord],
    tombstones: &[HarnessContentRetentionTombstone],
) -> String {
    let mut bytes = Vec::new();
    frame_bytes(&mut bytes, b"egopulse/harness-content/owner-snapshot/v1");
    frame_bytes(&mut bytes, task_id.as_bytes());
    frame_bytes(&mut bytes, &owner_sequence.to_le_bytes());
    frame_bytes(&mut bytes, &floor_sequence.to_le_bytes());
    frame_bytes(
        &mut bytes,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.as_bytes(),
    );
    frame_bytes(&mut bytes, &(records.len() as u64).to_le_bytes());
    for record in records {
        frame_bytes(&mut bytes, &record.sequence.to_le_bytes());
        frame_bytes(&mut bytes, &record.record.encode_to_vec());
    }
    frame_bytes(&mut bytes, &(tombstones.len() as u64).to_le_bytes());
    for tombstone in tombstones {
        frame_bytes(&mut bytes, &tombstone.encode_to_vec());
    }
    sha256(&bytes)
}

fn content_owner_incremental_digest(
    previous_digest_sha256: &str,
    sequence: u64,
    record_digest_sha256: &str,
) -> String {
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/owner-snapshot-increment/v1",
    );
    frame_bytes(&mut bytes, previous_digest_sha256.as_bytes());
    frame_bytes(&mut bytes, &sequence.to_le_bytes());
    frame_bytes(&mut bytes, record_digest_sha256.as_bytes());
    sha256(&bytes)
}

fn encode_content_owner_baseline(
    records: &[SafeContentOwnerRecord],
    tombstones: &[HarnessContentRetentionTombstone],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame_bytes(&mut bytes, b"egopulse/harness-content/owner-baseline/v1");
    frame_bytes(&mut bytes, &(records.len() as u64).to_le_bytes());
    for record in records {
        frame_bytes(&mut bytes, &record.sequence.to_le_bytes());
        frame_bytes(&mut bytes, &record.record.encode_to_vec());
    }
    frame_bytes(&mut bytes, &(tombstones.len() as u64).to_le_bytes());
    for tombstone in tombstones {
        frame_bytes(&mut bytes, &tombstone.encode_to_vec());
    }
    bytes
}

fn decode_content_owner_baseline(
    bytes: &[u8],
    task_id: &str,
) -> Result<
    (
        Vec<SafeContentOwnerRecord>,
        Vec<HarnessContentRetentionTombstone>,
    ),
    AdapterEdgeError,
> {
    let mut cursor = 0_usize;
    if take_frame(bytes, &mut cursor)? != b"egopulse/harness-content/owner-baseline/v1" {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let record_count = frame_u64(bytes, &mut cursor)?;
    if record_count > TASK_SAFE_RECORDS {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let mut records = Vec::with_capacity(
        usize::try_from(record_count).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
    );
    let mut last_sequence = 0;
    for _ in 0..record_count {
        let sequence = frame_u64(bytes, &mut cursor)?;
        let record = SafeHarnessContentRecord::decode(take_frame(bytes, &mut cursor)?)?;
        if sequence == 0
            || sequence <= last_sequence
            || record.task_id != task_id
            || canonical_safe_record_digest(&record).as_deref()
                != Some(record.record_digest_sha256.as_str())
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        last_sequence = sequence;
        records.push(SafeContentOwnerRecord { sequence, record });
    }
    let tombstone_count = frame_u64(bytes, &mut cursor)?;
    if tombstone_count > 1 {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let mut tombstones = Vec::with_capacity(
        usize::try_from(tombstone_count).map_err(|_| AdapterEdgeError::IntegrityFailure)?,
    );
    for _ in 0..tombstone_count {
        let tombstone = HarnessContentRetentionTombstone::decode(take_frame(bytes, &mut cursor)?)?;
        if tombstone.task_id != task_id
            || canonical_retention_tombstone_digest(&tombstone).as_deref()
                != Some(tombstone.tombstone_digest_sha256.as_str())
        {
            return Err(AdapterEdgeError::IntegrityFailure);
        }
        tombstones.push(tombstone);
    }
    if cursor != bytes.len() {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    Ok((records, tombstones))
}

fn projection_record_position_is_valid(
    record: &SafeHarnessContentRecord,
    expected_part: usize,
    record_count: usize,
) -> bool {
    match record.payload.as_ref() {
        Some(safe_harness_content_record::Payload::AssistantText(text)) => {
            usize::try_from(text.part_index).ok() == Some(expected_part)
                && text.part_count > text.part_index
        }
        Some(safe_harness_content_record::Payload::Marker(marker))
            if marker.kind == HarnessContentMarkerKind::LimitReached as i32 =>
        {
            expected_part.saturating_add(1) == record_count
        }
        Some(_) => expected_part == 0 && record_count == 1,
        None => false,
    }
}

fn disclosure_profile_reference() -> ContractReference {
    ContractReference {
        contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
        version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
        sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
    }
}

fn valid_disclosure_profile_reference(reference: Option<&ContractReference>) -> bool {
    reference == Some(&disclosure_profile_reference())
}

fn valid_timestamp(value: Option<&prost_types::Timestamp>) -> bool {
    value.is_some_and(|value| (0..1_000_000_000).contains(&value.nanos))
}

fn frame_timestamp(
    bytes: &mut Vec<u8>,
    value: Option<&prost_types::Timestamp>,
) -> Result<(), AdapterEdgeError> {
    let value = value
        .filter(|value| (0..1_000_000_000).contains(&value.nanos))
        .ok_or(AdapterEdgeError::IntegrityFailure)?;
    frame_bytes(bytes, &value.seconds.to_le_bytes());
    frame_bytes(
        bytes,
        &u32::try_from(value.nanos)
            .map_err(|_| AdapterEdgeError::IntegrityFailure)?
            .to_le_bytes(),
    );
    Ok(())
}

fn history_compaction_id(
    task_id: &str,
    attempt_id: &str,
    final_epoch: &str,
    final_sequence: u64,
) -> String {
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/history-compaction-id/v1",
    );
    frame_bytes(&mut bytes, task_id.as_bytes());
    frame_bytes(&mut bytes, attempt_id.as_bytes());
    frame_bytes(&mut bytes, final_epoch.as_bytes());
    frame_bytes(&mut bytes, &final_sequence.to_le_bytes());
    frame_bytes(
        &mut bytes,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.as_bytes(),
    );
    frame_bytes(&mut bytes, b"OWNER_HISTORY_FLOOR_ADVANCED");
    format!("hcc_{}", sha256(&bytes))
}

fn retention_tombstone_id(
    task_id: &str,
    attempt_id: &str,
    final_epoch: &str,
    final_sequence: u64,
) -> String {
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/retention-tombstone-id/v1",
    );
    frame_bytes(&mut bytes, task_id.as_bytes());
    frame_bytes(&mut bytes, attempt_id.as_bytes());
    frame_bytes(&mut bytes, final_epoch.as_bytes());
    frame_bytes(&mut bytes, &final_sequence.to_le_bytes());
    frame_bytes(
        &mut bytes,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.as_bytes(),
    );
    frame_bytes(&mut bytes, b"TERMINAL_MINIMUM_EXPIRED");
    format!("hrt_{}", sha256(&bytes))
}

fn canonical_history_compaction_digest(
    record: &HarnessContentHistoryCompactionRecord,
) -> Option<String> {
    if record.compaction_record_id
        != history_compaction_id(
            &record.task_id,
            &record.attempt_id,
            &record.final_epoch,
            record.final_sequence,
        )
        || record.task_id.trim().is_empty()
        || record.attempt_id.trim().is_empty()
        || record.final_epoch.trim().is_empty()
        || !is_sha256(&record.final_safe_content_digest_sha256)
        || !is_sha256(&record.owner_snapshot_digest_sha256)
        || !valid_disclosure_profile_reference(record.disclosure_profile_ref.as_ref())
        || !valid_timestamp(record.compacted_at.as_ref())
        || record.reason != HarnessContentCompactionReason::OwnerHistoryFloorAdvanced as i32
    {
        return None;
    }
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/history-compaction/v1",
    );
    frame_bytes(&mut bytes, record.compaction_record_id.as_bytes());
    frame_bytes(&mut bytes, record.task_id.as_bytes());
    frame_bytes(&mut bytes, record.attempt_id.as_bytes());
    frame_bytes(&mut bytes, record.final_epoch.as_bytes());
    frame_bytes(&mut bytes, &record.final_sequence.to_le_bytes());
    frame_bytes(
        &mut bytes,
        record.final_safe_content_digest_sha256.as_bytes(),
    );
    frame_bytes(&mut bytes, record.owner_snapshot_digest_sha256.as_bytes());
    let profile = record.disclosure_profile_ref.as_ref()?;
    frame_bytes(&mut bytes, profile.contract_id.as_bytes());
    frame_bytes(&mut bytes, profile.version.as_bytes());
    frame_bytes(&mut bytes, profile.sha256.as_bytes());
    frame_timestamp(&mut bytes, record.compacted_at.as_ref()).ok()?;
    frame_bytes(&mut bytes, b"OWNER_HISTORY_FLOOR_ADVANCED");
    Some(sha256(&bytes))
}

fn canonical_retention_tombstone_digest(
    tombstone: &HarnessContentRetentionTombstone,
) -> Option<String> {
    if tombstone.tombstone_id
        != retention_tombstone_id(
            &tombstone.task_id,
            &tombstone.attempt_id,
            &tombstone.final_epoch,
            tombstone.final_sequence,
        )
        || tombstone.task_id.trim().is_empty()
        || tombstone.attempt_id.trim().is_empty()
        || tombstone.final_epoch.trim().is_empty()
        || !is_sha256(&tombstone.final_safe_content_digest_sha256)
        || !valid_disclosure_profile_reference(tombstone.disclosure_profile_ref.as_ref())
        || !valid_timestamp(tombstone.terminal_committed_at.as_ref())
        || !valid_timestamp(tombstone.compacted_at.as_ref())
        || tombstone.reason != HarnessContentRetentionReason::TerminalMinimumExpired as i32
    {
        return None;
    }
    let mut bytes = Vec::new();
    frame_bytes(
        &mut bytes,
        b"egopulse/harness-content/retention-tombstone/v1",
    );
    frame_bytes(&mut bytes, tombstone.tombstone_id.as_bytes());
    frame_bytes(&mut bytes, tombstone.task_id.as_bytes());
    frame_bytes(&mut bytes, tombstone.attempt_id.as_bytes());
    frame_bytes(&mut bytes, tombstone.final_epoch.as_bytes());
    frame_bytes(&mut bytes, &tombstone.final_sequence.to_le_bytes());
    frame_bytes(
        &mut bytes,
        tombstone.final_safe_content_digest_sha256.as_bytes(),
    );
    let profile = tombstone.disclosure_profile_ref.as_ref()?;
    frame_bytes(&mut bytes, profile.contract_id.as_bytes());
    frame_bytes(&mut bytes, profile.version.as_bytes());
    frame_bytes(&mut bytes, profile.sha256.as_bytes());
    frame_timestamp(&mut bytes, tombstone.terminal_committed_at.as_ref()).ok()?;
    frame_timestamp(&mut bytes, tombstone.compacted_at.as_ref()).ok()?;
    frame_bytes(&mut bytes, b"TERMINAL_MINIMUM_EXPIRED");
    Some(sha256(&bytes))
}

fn validate_safe_projection_outbox_payload(
    transaction: &Transaction<'_>,
    message_id: &str,
    source_record_id: &str,
    source_revision: u64,
    payload_digest_sha256: &str,
    payload: &[u8],
) -> Result<SafeHarnessContentProjectionEvent, AdapterEdgeError> {
    if source_revision == 0
        || message_id != format!("adapter-content-{source_record_id}")
        || !is_sha256(payload_digest_sha256)
        || sha256(payload) != payload_digest_sha256
    {
        return Err(AdapterEdgeError::IntegrityFailure);
    }
    let event = SafeHarnessContentProjectionEvent::decode(payload)?;
    match event.payload.as_ref() {
        Some(safe_harness_content_projection_event::Payload::ContentRecord(record)) => {
            if record.record_id != source_record_id
                || canonical_safe_record_digest(record).as_deref()
                    != Some(record.record_digest_sha256.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            let stored: Option<(i64, String, Vec<u8>)> = transaction
                .query_row(
                    "SELECT content_sequence, record_digest_sha256, safe_record
                     FROM adapter_safe_content_ledger WHERE record_id = ?1",
                    [source_record_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if stored
                != Some((
                    i64::try_from(source_revision)
                        .map_err(|_| AdapterEdgeError::IntegrityFailure)?,
                    record.record_digest_sha256.clone(),
                    record.encode_to_vec(),
                ))
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
        }
        Some(safe_harness_content_projection_event::Payload::HistoryCompaction(record)) => {
            if record.compaction_record_id != source_record_id
                || canonical_history_compaction_digest(record).as_deref()
                    != Some(record.compaction_record_digest_sha256.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
        }
        Some(safe_harness_content_projection_event::Payload::RetentionTombstone(tombstone)) => {
            if tombstone.tombstone_id != source_record_id
                || canonical_retention_tombstone_digest(tombstone).as_deref()
                    != Some(tombstone.tombstone_digest_sha256.as_str())
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
            let stored: Option<(String, Vec<u8>)> = transaction
                .query_row(
                    "SELECT tombstone_digest_sha256, tombstone
                     FROM adapter_content_retention_tombstones WHERE tombstone_id = ?1",
                    [source_record_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if stored
                != Some((
                    tombstone.tombstone_digest_sha256.clone(),
                    tombstone.encode_to_vec(),
                ))
            {
                return Err(AdapterEdgeError::IntegrityFailure);
            }
        }
        None => return Err(AdapterEdgeError::IntegrityFailure),
    }
    Ok(event)
}

fn frame_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn hmac_sha256_bytes(key: &[u8], message: &[u8]) -> Result<[u8; 32], AdapterEdgeError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| AdapterEdgeError::IntegrityFailure)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn terminal_output_payload_digest(candidate: &TerminalOutputCandidate) -> String {
    terminal_output_payload_digest_parts(
        &candidate.dispatch_id,
        &candidate.native_completion_ref,
        &candidate.media_type,
        &sha256(&candidate.content),
        candidate.content.len() as u64,
    )
}

fn terminal_output_payload_digest_parts(
    dispatch_id: &str,
    native_completion_ref: &str,
    media_type: &str,
    content_digest_sha256: &str,
    original_content_bytes: u64,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        dispatch_id.as_bytes(),
        native_completion_ref.as_bytes(),
        media_type.as_bytes(),
        content_digest_sha256.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(original_content_bytes.to_be_bytes());
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::{
        TrustedContentLineage, assistant_text_content_candidate, bind_content_signal,
        canonical_dispatch_route_binding_digest, project_safe_content,
    };
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation,
        ContentMutationOperation, DiagnosticObservation, DispatchContextConsumptionProof,
        HarnessAckObservation, HarnessContentSignalObservation, HarnessObservation,
        LifecycleObservation, NotContextBoundProof, ObservationCriticality,
        SafeAssistantTextContent, SideEffectCertainty, dispatch_context_consumption_proof,
        dispatch_route_binding, harness_observation,
    };
    use std::path::Path;
    use std::process::Command;

    const ABORT_HELPER_ENV: &str = "EGOPULSE_ADAPTER_EDGE_ABORT_HELPER";
    const ABORT_PATH_ENV: &str = "EGOPULSE_ADAPTER_EDGE_ABORT_PATH";
    const TEST_CAPABILITY_PROFILE_ID: &str = "profile:test";

    struct IsolatedEdge {
        root: PathBuf,
    }

    impl IsolatedEdge {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).expect("create adapter edge test directory");
            Self { root }
        }

        fn path(&self) -> PathBuf {
            self.root.join("adapter-edge.sqlcipher")
        }
    }

    impl Drop for IsolatedEdge {
        fn drop(&mut self) {
            let temp = std::env::temp_dir();
            assert!(self.root.starts_with(&temp));
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove adapter edge test directory");
            }
        }
    }

    fn open_edge(path: &Path) -> AdapterEdge {
        open_edge_with_id(path, "adapter:test")
    }

    fn open_edge_with_id(path: &Path, adapter_id: &str) -> AdapterEdge {
        AdapterEdge::open(AdapterEdgeConfig {
            database_path: path.to_owned(),
            adapter_id: adapter_id.to_owned(),
            store_epoch: "adapter-edge-test-v1".to_owned(),
            key: AdapterEdgeKey::new([0x7a; 32]),
        })
        .expect("open adapter edge")
    }

    fn dispatch() -> DispatchEnvelope {
        dispatch_with_id("dispatch-001", "attempt-001")
    }

    fn dispatch_with_id(dispatch_id: &str, attempt_id: &str) -> DispatchEnvelope {
        DispatchEnvelope {
            dispatch_id: dispatch_id.to_owned(),
            run_id: "run-001".to_owned(),
            run_revision: 1,
            step_id: "step-001".to_owned(),
            step_revision: 1,
            attempt_id: attempt_id.to_owned(),
            attempt_revision: 1,
            fencing_token: 1,
            dispatch_fingerprint: "1".repeat(64),
            input_bundle_sha256: "2".repeat(64),
            ..DispatchEnvelope::default()
        }
    }

    fn receipt() -> DispatchReceipt {
        DispatchReceipt {
            receipt_id: "receipt-001".to_owned(),
            disposition: DeliveryDisposition::Unknown as i32,
            dispatch_id: "dispatch-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            fencing_token: 1,
            receipt_digest_sha256: "3".repeat(64),
            ..DispatchReceipt::default()
        }
    }

    fn observation() -> HarnessObservation {
        observation_for("dispatch-001", "attempt-001")
    }

    fn observation_for(dispatch_id: &str, attempt_id: &str) -> HarnessObservation {
        HarnessObservation {
            attempt_id: attempt_id.to_owned(),
            dispatch_id: dispatch_id.to_owned(),
            fencing_token: 1,
            capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
            criticality: ObservationCriticality::Control as i32,
            payload: Some(harness_observation::Payload::Diagnostic(
                DiagnosticObservation {
                    safe_diagnostic_code: "TEST_EVENT".to_owned(),
                    error_fingerprint: None,
                    recovery_required: false,
                },
            )),
            ..HarnessObservation::default()
        }
    }

    fn terminal_observation() -> HarnessObservation {
        HarnessObservation {
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 1,
            capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
            criticality: ObservationCriticality::Terminal as i32,
            payload: Some(harness_observation::Payload::Lifecycle(
                egopulse_domain_contracts::v01::egopulse::harness::v1::LifecycleObservation {
                    kind: LifecycleKind::ExecutionCompleted as i32,
                    ..Default::default()
                },
            )),
            ..HarnessObservation::default()
        }
    }

    fn terminal_candidate(content: Vec<u8>) -> TerminalOutputCandidate {
        TerminalOutputCandidate {
            dispatch_id: "dispatch-001".to_owned(),
            native_completion_ref: "native-turn-001".to_owned(),
            media_type: "text/plain; charset=utf-8".to_owned(),
            content,
        }
    }

    fn persist_terminal_candidate(
        edge: &mut AdapterEdge,
        content: Vec<u8>,
        relation_policy: FinalArtifactRelationPolicy,
    ) {
        edge.prepare_dispatch_with_relation_policy(&dispatch(), relation_policy, 10)
            .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage("dispatch-001", "task-001", 2, 1, 10)
            .expect("bind task lineage");
        edge.append_observation_with_terminal_output(
            "dispatch-001",
            "native:terminal:001",
            b"terminal-event",
            terminal_observation(),
            Some(&terminal_candidate(content)),
            11,
        )
        .expect("persist terminal candidate");
    }

    fn install_finalized_assembly(
        edge: &mut AdapterEdge,
        message_id: &str,
        raw: &[u8],
        safe: &str,
    ) {
        let checkpoint = ContentAssemblyCheckpoint {
            message_id: message_id.to_owned(),
            current_revision: 2,
            candidate_digest_sha256: sha256(message_id.as_bytes()),
            finalized: true,
            raw_cumulative: raw.to_vec(),
            raw_cumulative_digest_sha256: framed_content_digest(
                b"egopulse/harness-content/raw-cumulative/v1",
                raw,
            ),
            safe_cumulative: safe.to_owned(),
            safe_cumulative_digest_sha256: framed_content_digest(
                b"egopulse/harness-content/safe-cumulative/v1",
                safe.as_bytes(),
            ),
            withheld_suffix: String::new(),
        };
        let content_event_id = sha256(format!("finalize:{message_id}").as_bytes());
        let mut record = SafeHarnessContentRecord {
            record_id: canonical_safe_record_id(
                &content_event_id,
                "ASSISTANT_TEXT",
                HarnessContentLimitKind::Unspecified,
                0,
            ),
            content_event_id,
            task_id: "task-001".to_owned(),
            run_id: "run-001".to_owned(),
            step_id: "step-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 1,
            route_binding_sha256: "a".repeat(64),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            provider_family_alias: "openai".to_owned(),
            model_alias: "gpt-test".to_owned(),
            collaboration_role: "primary".to_owned(),
            safety_flags: vec![
                egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessContentSafetyFlag::Provisional
                    as i32,
            ],
            payload: Some(safe_harness_content_record::Payload::AssistantText(
                SafeAssistantTextContent {
                    safe_message_id: format!("hcm_{}", sha256(message_id.as_bytes())),
                    revision: 2,
                    previous_revision: 1,
                    operation: ContentMutationOperation::Finalize as i32,
                    safe_text_utf8: String::new(),
                    safe_cumulative_digest_sha256: checkpoint
                        .safe_cumulative_digest_sha256
                        .clone(),
                    part_index: 0,
                    part_count: 1,
                },
            )),
            ..SafeHarnessContentRecord::default()
        };
        record.record_digest_sha256 =
            canonical_safe_record_digest(&record).expect("canonical finalized record");
        edge.connection
            .execute(
                "INSERT INTO adapter_content_assemblies(
                   dispatch_id, message_id, current_revision, finalized,
                   raw_cumulative_digest_sha256, safe_cumulative_digest_sha256,
                   assembly_state, updated_at_seconds
                 ) VALUES('dispatch-001', ?1, 2, 1, ?2, ?3, ?4, 12)",
                params![
                    message_id,
                    checkpoint.raw_cumulative_digest_sha256,
                    checkpoint.safe_cumulative_digest_sha256,
                    encode_assembly_state(&checkpoint, &[record]),
                ],
            )
            .expect("install finalized assembly");
    }

    fn install_pending_content_marker(edge: &mut AdapterEdge) {
        let source_observation_id: String = edge
            .connection
            .query_row(
                "SELECT source_observation_id FROM adapter_terminal_output_outbox
                 WHERE dispatch_id = 'dispatch-001'",
                [],
                |row| row.get(0),
            )
            .expect("terminal source observation");
        edge.connection
            .execute(
                "INSERT INTO adapter_content_candidates(
                   content_event_id, source_observation_id, dispatch_id,
                   candidate_digest_sha256, content_signal, projection_state,
                   created_at_seconds
                 ) VALUES(?1, ?2, 'dispatch-001', ?3, X'', 'pending', 12)",
                params![
                    sha256(b"pending-content-marker"),
                    source_observation_id,
                    sha256(b"pending-content-signal")
                ],
            )
            .expect("install pending content marker");
    }

    fn install_finalized_marker_assembly(edge: &mut AdapterEdge, message_id: &str, raw: &[u8]) {
        install_finalized_assembly(edge, message_id, raw, "");
        let state: Vec<u8> = edge
            .connection
            .query_row(
                "SELECT assembly_state FROM adapter_content_assemblies
                 WHERE dispatch_id = 'dispatch-001' AND message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .expect("read marker assembly");
        let (checkpoint, mut records) = decode_assembly_state(&state).expect("decode assembly");
        let record = records.first_mut().expect("assembly record");
        record.record_id = canonical_safe_record_id(
            &record.content_event_id,
            "MARKER",
            HarnessContentLimitKind::Unspecified,
            0,
        );
        record.payload = Some(safe_harness_content_record::Payload::Marker(
            SafeContentMarker {
                kind: HarnessContentMarkerKind::InvalidText as i32,
                limit_kind: HarnessContentLimitKind::Unspecified as i32,
            },
        ));
        record.record_digest_sha256.clear();
        record.record_digest_sha256 =
            canonical_safe_record_digest(record).expect("canonical marker record");
        edge.connection
            .execute(
                "UPDATE adapter_content_assemblies SET assembly_state = ?1
                 WHERE dispatch_id = 'dispatch-001' AND message_id = ?2",
                params![encode_assembly_state(&checkpoint, &records), message_id],
            )
            .expect("write marker assembly");
    }

    fn install_owner_budget_history(
        edge: &mut AdapterEdge,
        mut record: SafeHarnessContentRecord,
        task_terminal_kind: Option<HarnessContentLimitKind>,
    ) {
        record.record_digest_sha256.clear();
        record.record_digest_sha256 =
            canonical_safe_record_digest(&record).expect("canonical owner history record");
        let owner_records = vec![SafeContentOwnerRecord {
            sequence: 1,
            record: record.clone(),
        }];
        let baseline = encode_content_owner_baseline(&owner_records, &[]);
        let snapshot_digest =
            content_owner_snapshot_digest(&record.task_id, 1, 1, &owner_records, &[]);
        let text_bytes = safe_record_text_bytes(&record);
        let transaction = edge
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("owner history transaction");
        transaction
            .execute(
                "INSERT INTO adapter_content_history_floors(
                   task_id, floor_sequence, floor_digest_sha256, updated_at_seconds
                 ) VALUES(?1, 1, ?2, 10)",
                params![record.task_id, content_floor_digest(&record.task_id, 1)],
            )
            .expect("owner history floor");
        transaction
            .execute(
                "INSERT INTO adapter_content_owner_snapshots(
                   task_id, owner_sequence, floor_sequence,
                   disclosure_profile_digest_sha256, baseline_state,
                   baseline_digest_sha256, snapshot_digest_sha256, updated_at_seconds
                 ) VALUES(?1, 1, 1, ?2, ?3, ?4, ?4, 10)",
                params![
                    record.task_id,
                    HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
                    baseline,
                    snapshot_digest,
                ],
            )
            .expect("owner baseline snapshot");
        let empty = ContentBudgetState {
            text_bytes: 0,
            record_count: 0,
            terminal_kind: None,
        };
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "attempt",
                scope_id: &record.attempt_id,
                previous: empty,
                added_text_bytes: text_bytes,
                added_records: 1,
                terminal_kind: None,
            },
            10,
        )
        .expect("attempt budget");
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "task",
                scope_id: &record.task_id,
                previous: empty,
                added_text_bytes: text_bytes,
                added_records: 1,
                terminal_kind: task_terminal_kind,
            },
            10,
        )
        .expect("task budget");
        transaction.commit().expect("commit owner budget history");
    }

    fn pending_projection_for_budget_drift(
        edge: &mut AdapterEdge,
        task_id: &str,
        attempt_id: &str,
        suffix: &str,
    ) -> SafeContentProjection {
        let dispatch_id = format!("dispatch-budget-drift-{suffix}");
        let dispatch = dispatch_with_id(&dispatch_id, attempt_id);
        edge.prepare_dispatch(&dispatch, 20)
            .expect("prepare drift dispatch");
        let ObservationAppend::Committed(source) = edge
            .append_observation(
                &dispatch_id,
                &format!("native-budget-drift-{suffix}"),
                suffix.as_bytes(),
                observation_for(&dispatch_id, attempt_id),
                21,
            )
            .expect("persist candidate source observation")
        else {
            panic!("new source observation")
        };
        let mut binding = DispatchRouteBinding {
            provider_bootstrap_profile_id: "provider-budget-integrity".to_owned(),
            selected_harness_id: "harness-budget-integrity".to_owned(),
            provider_model_id: "model-budget-integrity".to_owned(),
            catalog_snapshot: Some(
                dispatch_route_binding::CatalogSnapshot::CatalogSnapshotSha256("d".repeat(64)),
            ),
            capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
            route_binding_sha256: String::new(),
        };
        binding.route_binding_sha256 =
            canonical_dispatch_route_binding_digest(&binding).expect("route binding");
        let mut observation = HarnessObservation {
            attempt_id: attempt_id.to_owned(),
            dispatch_id: dispatch_id.clone(),
            fencing_token: 1,
            native_event_id: Some(format!("native-content-budget-drift-{suffix}")),
            native_sequence: Some(1),
            native_event_digest_sha256: sha256(suffix.as_bytes()),
            capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
            criticality: ObservationCriticality::Informational as i32,
            payload: Some(harness_observation::Payload::ContentSignal(
                HarnessContentSignalObservation {
                    candidate: assistant_text_content_candidate(
                        &format!("message-budget-drift-{suffix}"),
                        b"next".to_vec(),
                    ),
                    ..HarnessContentSignalObservation::default()
                },
            )),
            ..HarnessObservation::default()
        };
        let unbound = observation.clone();
        let Some(harness_observation::Payload::ContentSignal(signal)) =
            observation.payload.as_mut()
        else {
            panic!("content signal")
        };
        bind_content_signal(
            &unbound,
            signal,
            &format!("receipt-budget-drift-{suffix}"),
            &"e".repeat(64),
            &binding.route_binding_sha256,
            DispatchContextConsumptionProof {
                branch: Some(dispatch_context_consumption_proof::Branch::NotContextBound(
                    NotContextBoundProof {},
                )),
            },
        )
        .expect("bind drift content signal");
        let Some(harness_observation::Payload::ContentSignal(signal)) =
            observation.payload.as_ref()
        else {
            panic!("bound content signal")
        };
        let projection = project_safe_content(
            &observation,
            signal,
            &binding,
            &TrustedContentLineage {
                task_id: task_id.to_owned(),
                run_id: "run-budget-integrity".to_owned(),
                step_id: "step-budget-integrity".to_owned(),
            },
            &[],
            None,
        )
        .expect("valid pending projection");
        edge.connection
            .execute(
                "INSERT INTO adapter_content_candidates(
                   content_event_id, source_observation_id, dispatch_id,
                   candidate_digest_sha256, content_signal, projection_state,
                   created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, 'pending', 22)",
                params![
                    projection.record().content_event_id,
                    source.observation_id,
                    dispatch_id,
                    "f".repeat(64),
                    signal.encode_to_vec(),
                ],
            )
            .expect("insert pending candidate");
        projection
    }

    fn safe_content_write_state(
        edge: &AdapterEdge,
        content_event_id: &str,
    ) -> (i64, i64, i64, String) {
        let ledger: i64 = edge
            .connection
            .query_row(
                "SELECT COUNT(*) FROM adapter_safe_content_ledger",
                [],
                |row| row.get(0),
            )
            .expect("safe ledger count");
        let outbox: i64 = edge
            .connection
            .query_row(
                "SELECT COUNT(*) FROM adapter_content_projection_outbox",
                [],
                |row| row.get(0),
            )
            .expect("safe outbox count");
        let next_sequence = edge
            .connection
            .query_row(
                "SELECT next_content_sequence FROM adapter_edge_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("next safe sequence");
        let candidate_state = edge
            .connection
            .query_row(
                "SELECT projection_state FROM adapter_content_candidates
                 WHERE content_event_id = ?1",
                [content_event_id],
                |row| row.get(0),
            )
            .expect("pending candidate state");
        (ledger, outbox, next_sequence, candidate_state)
    }

    #[test]
    fn terminal_output_handoff_is_atomic_recoverable_and_acknowledged_idempotently() {
        let isolated = IsolatedEdge::new("terminal-output-outbox");
        let path = isolated.path();
        let mut edge = open_edge(&path);
        edge.prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage("dispatch-001", "task-001", 2, 1, 10)
            .expect("bind task lineage");
        let candidate = terminal_candidate(b"governed final answer".to_vec());
        let appended = edge
            .append_observation_with_terminal_output(
                "dispatch-001",
                "native:terminal:001",
                b"terminal-event",
                terminal_observation(),
                Some(&candidate),
                11,
            )
            .expect("persist terminal observation and output in one transaction");
        assert!(matches!(appended, ObservationAppend::Committed(_)));
        assert!(
            edge.terminal_output_candidate_is_durable("dispatch-001")
                .expect("durable candidate lookup")
        );
        drop(edge);

        let mut reopened = open_edge(&path);
        let pending = reopened
            .pending_terminal_output_candidates()
            .expect("recover pending candidate");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].content, b"governed final answer");
        assert!(pending[0].content_complete);
        assert_eq!(pending[0].original_content_bytes, 21);
        assert_eq!(
            reopened
                .inspect()
                .expect("inspect edge")
                .pending_observation_count,
            1
        );
        assert!(
            reopened
                .acknowledge_terminal_output_candidate(
                    &pending[0].message_id,
                    &pending[0].payload_digest_sha256,
                )
                .expect("ack candidate")
        );
        assert!(
            reopened
                .acknowledge_terminal_output_candidate(
                    &pending[0].message_id,
                    &pending[0].payload_digest_sha256,
                )
                .expect("replay ack candidate")
        );
        assert!(
            reopened
                .pending_terminal_output_candidates()
                .expect("candidate is settled")
                .is_empty()
        );
        let durable = reopened
            .terminal_output_candidate_for_dispatch("dispatch-001")
            .expect("resolve consumed candidate")
            .expect("consumed candidate remains evidence-readable");
        assert_eq!(durable.source_revision, 1);
        assert_eq!(durable.dispatch_id, "dispatch-001");
    }

    #[test]
    fn final_artifact_relation_selects_unique_matching_finalize_and_replays_exactly() {
        let isolated = IsolatedEdge::new("final-artifact-relation");
        let mut edge = open_edge(&isolated.path());
        let output = b"governed final answer".to_vec();
        persist_terminal_candidate(
            &mut edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        install_finalized_assembly(
            &mut edge,
            "message-progress",
            b"I will read it",
            "I will read it",
        );
        install_finalized_assembly(
            &mut edge,
            "message-answer",
            &output,
            "governed [redacted] answer",
        );
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate");
        let request = FinalArtifactRelationRequest {
            terminal_message_id: pending[0].message_id.clone(),
            terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:001".to_owned(),
            artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
        };
        assert_eq!(
            edge.register_final_artifact_relation_intent_and_ack(&request, 12)
                .expect("register relation intent"),
            FinalArtifactRelationRegistration::Registered
        );
        assert_eq!(
            edge.register_final_artifact_relation_intent_and_ack(&request, 12)
                .expect("lost response replay"),
            FinalArtifactRelationRegistration::Replay
        );
        assert!(
            edge.pending_terminal_output_candidates()
                .expect("technical return ACK")
                .is_empty()
        );

        let committed = edge
            .commit_final_artifact_relation(&request, 13)
            .expect("commit relation");
        let FinalArtifactRelationCommit::Committed(record) = committed else {
            panic!("new relation must commit")
        };
        assert!(matches!(
            record.payload,
            Some(safe_harness_content_record::Payload::ArtifactRelation(
                SafeArtifactRelationContent {
                    safe_content_differs_from_artifact: true,
                    artifact: Some(SafeArtifactIdentity { ref artifact_id, .. }),
                }
            )) if artifact_id == "artifact:final:001"
        ));
        let before = edge.inspect().expect("inspect after relation");
        assert_eq!(before.safe_content_ledger_count, 1);
        assert_eq!(before.content_projection_outbox_count, 1);
        assert!(matches!(
            edge.commit_final_artifact_relation(&request, 14),
            Ok(FinalArtifactRelationCommit::Replay(_))
        ));
        assert_eq!(edge.inspect().expect("inspect replay"), before);

        let mut conflict = request;
        conflict.artifact_id = "artifact:conflicting:002".to_owned();
        assert!(matches!(
            edge.commit_final_artifact_relation(&conflict, 15),
            Err(AdapterEdgeError::SequenceConflict)
        ));
        assert_eq!(edge.inspect().expect("inspect conflict"), before);
    }

    #[test]
    fn final_artifact_relation_updates_budgets_and_allows_following_content() {
        let isolated = IsolatedEdge::new("final-artifact-relation-budget");
        let mut edge = open_edge(&isolated.path());
        let output = b"governed budget answer".to_vec();
        persist_terminal_candidate(
            &mut edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let prior = budget_history_record(
            "task-001",
            "attempt-001",
            safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
                safe_message_id: "message-budget-prior".to_owned(),
                revision: 1,
                operation: ContentMutationOperation::Append as i32,
                safe_text_utf8: "safe".to_owned(),
                safe_cumulative_digest_sha256: "b".repeat(64),
                part_count: 1,
                ..SafeAssistantTextContent::default()
            }),
        );
        install_owner_budget_history(&mut edge, prior, None);
        edge.connection
            .execute(
                "UPDATE adapter_edge_metadata SET next_content_sequence = 2 WHERE singleton = 1",
                [],
            )
            .expect("align content sequence with installed owner history");
        install_finalized_assembly(&mut edge, "message-answer", &output, "safe answer");
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate");
        let request = FinalArtifactRelationRequest {
            terminal_message_id: pending[0].message_id.clone(),
            terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:budget".to_owned(),
            artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
        };
        edge.register_final_artifact_relation_intent_and_ack(&request, 12)
            .expect("register budget relation");
        assert!(matches!(
            edge.commit_final_artifact_relation(&request, 13),
            Ok(FinalArtifactRelationCommit::Committed(_))
        ));
        let budget = edge
            .safe_content_budget_snapshot("task-001", "attempt-001")
            .expect("relation budget snapshot");
        assert_eq!(budget.attempt.safe_record_count, 2);
        assert_eq!(budget.task.safe_record_count, 2);
        assert_eq!(budget.attempt.safe_text_bytes, 4);
        assert_eq!(budget.task.safe_text_bytes, 4);

        let projection = pending_projection_for_budget_drift(
            &mut edge,
            "task-001",
            "attempt-001",
            "after-relation",
        );
        assert!(matches!(
            edge.commit_safe_content_projection(&projection, 23),
            Ok(SafeContentCommit::Committed { .. })
        ));
    }

    #[test]
    fn final_artifact_relation_persists_no_record_slot_skip_after_technical_ack() {
        let isolated = IsolatedEdge::new("final-artifact-relation-no-slot");
        let mut edge = open_edge(&isolated.path());
        let output = b"governed no-slot answer".to_vec();
        persist_terminal_candidate(
            &mut edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let prior = budget_history_record(
            "task-001",
            "attempt-001",
            safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
                safe_message_id: "message-no-slot-prior".to_owned(),
                revision: 1,
                operation: ContentMutationOperation::Append as i32,
                safe_text_utf8: "safe".to_owned(),
                safe_cumulative_digest_sha256: "b".repeat(64),
                part_count: 1,
                ..SafeAssistantTextContent::default()
            }),
        );
        install_owner_budget_history(&mut edge, prior, None);
        edge.connection
            .execute(
                "UPDATE adapter_edge_metadata SET next_content_sequence = 2 WHERE singleton = 1",
                [],
            )
            .expect("align content sequence with installed owner history");
        install_finalized_assembly(&mut edge, "message-answer", &output, "safe answer");
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate");
        let request = FinalArtifactRelationRequest {
            terminal_message_id: pending[0].message_id.clone(),
            terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:no-slot".to_owned(),
            artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
        };
        edge.register_final_artifact_relation_intent_and_ack(&request, 12)
            .expect("register no-slot relation");
        assert_eq!(
            edge.commit_final_artifact_relation_with_limits(
                &request,
                13,
                ContentBudgetLimits {
                    attempt_text_bytes: 10,
                    attempt_records: 2,
                    task_text_bytes: 10,
                    task_records: 3,
                },
            )
            .expect("persist exhausted relation slot"),
            FinalArtifactRelationCommit::Skipped(FinalArtifactRelationSkipReason::NoRecordSlot)
        );
        assert!(
            edge.pending_terminal_output_candidates()
                .expect("technical ACK remains consumed")
                .is_empty()
        );
        let inspection = edge.inspect().expect("no synthetic limit marker");
        assert_eq!(inspection.safe_content_ledger_count, 0);
        assert_eq!(inspection.content_projection_outbox_count, 0);
        let status = edge
            .final_artifact_relation_status(&request.terminal_message_id)
            .expect("read no-slot status")
            .expect("stored no-slot status");
        assert_eq!(status.state, FinalArtifactRelationState::Skipped);
        assert_eq!(
            status.safe_reason_code.as_deref(),
            Some("FINAL_ARTIFACT_RELATION_NO_RECORD_SLOT")
        );
    }

    #[test]
    fn final_artifact_relation_persists_terminal_budget_skip_after_technical_ack() {
        let isolated = IsolatedEdge::new("final-artifact-relation-terminal-budget");
        let mut edge = open_edge(&isolated.path());
        let output = b"governed terminal answer".to_vec();
        persist_terminal_candidate(
            &mut edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let marker = budget_history_record(
            "task-001",
            "attempt-001",
            safe_harness_content_record::Payload::Marker(SafeContentMarker {
                kind: HarnessContentMarkerKind::LimitReached as i32,
                limit_kind: HarnessContentLimitKind::TaskRecords as i32,
            }),
        );
        install_owner_budget_history(
            &mut edge,
            marker,
            Some(HarnessContentLimitKind::TaskRecords),
        );
        edge.connection
            .execute(
                "UPDATE adapter_edge_metadata SET next_content_sequence = 2 WHERE singleton = 1",
                [],
            )
            .expect("align content sequence with terminal owner history");
        install_finalized_assembly(&mut edge, "message-answer", &output, "safe answer");
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate");
        let request = FinalArtifactRelationRequest {
            terminal_message_id: pending[0].message_id.clone(),
            terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:terminal-budget".to_owned(),
            artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
        };
        edge.register_final_artifact_relation_intent_and_ack(&request, 12)
            .expect("register terminal budget relation");
        assert!(
            edge.pending_terminal_output_candidates()
                .expect("technical ACK remains consumed")
                .is_empty()
        );
        assert_eq!(
            edge.commit_final_artifact_relation(&request, 13)
                .expect("terminal scope becomes stable skip"),
            FinalArtifactRelationCommit::Skipped(FinalArtifactRelationSkipReason::ScopeTerminal)
        );
        let inspection = edge.inspect().expect("no relation projection");
        assert_eq!(inspection.safe_content_ledger_count, 0);
        assert_eq!(inspection.content_projection_outbox_count, 0);
        let status = edge
            .final_artifact_relation_status(&request.terminal_message_id)
            .expect("read terminal relation status")
            .expect("stored relation status");
        assert_eq!(status.state, FinalArtifactRelationState::Skipped);
        assert_eq!(
            status.safe_reason_code.as_deref(),
            Some("FINAL_ARTIFACT_RELATION_SCOPE_TERMINAL")
        );
    }

    #[test]
    fn pending_relation_blocks_compaction_and_projected_replay_survives_compaction() {
        let isolated = IsolatedEdge::new("final-artifact-relation-compaction");
        let output = b"governed compacted answer".to_vec();
        let request = {
            let mut edge = open_edge(&isolated.path());
            persist_terminal_candidate(
                &mut edge,
                output.clone(),
                FinalArtifactRelationPolicy::RequiredGovernedContent,
            );
            let prior = budget_history_record(
                "task-001",
                "attempt-001",
                safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
                    safe_message_id: "message-compaction-prior".to_owned(),
                    revision: 1,
                    operation: ContentMutationOperation::Append as i32,
                    safe_text_utf8: "safe".to_owned(),
                    safe_cumulative_digest_sha256: "b".repeat(64),
                    part_count: 1,
                    ..SafeAssistantTextContent::default()
                }),
            );
            install_owner_budget_history(&mut edge, prior, None);
            edge.connection
                .execute(
                    "UPDATE adapter_edge_metadata SET next_content_sequence = 2 WHERE singleton = 1",
                    [],
                )
                .expect("align content sequence with installed owner history");
            install_finalized_assembly(&mut edge, "message-answer", &output, "safe answer");
            let pending = edge
                .pending_terminal_output_candidates()
                .expect("pending terminal candidate");
            let request = FinalArtifactRelationRequest {
                terminal_message_id: pending[0].message_id.clone(),
                terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
                artifact_id: "artifact:final:compaction".to_owned(),
                artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
            };
            edge.register_final_artifact_relation_intent_and_ack(&request, 12)
                .expect("register relation before restart");
            request
        };

        let mut reopened = open_edge(&isolated.path());
        assert_eq!(
            reopened
                .pending_final_artifact_relation_intent()
                .expect("recover pending relation"),
            Some(request.clone())
        );
        assert!(
            reopened
                .pending_terminal_output_candidates()
                .expect("technical ACK recovered")
                .is_empty()
        );
        let pending_compaction = ContentRetentionCompactionRequest {
            task_id: "task-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            final_epoch: "epoch-pending".to_owned(),
            expected_owner_sequence: 1,
            terminal_committed_at: prost_types::Timestamp {
                seconds: 100,
                nanos: 0,
            },
            compacted_at: prost_types::Timestamp {
                seconds: 100 + CONTENT_MINIMUM_RETENTION_SECONDS,
                nanos: 0,
            },
        };
        assert!(matches!(
            reopened.compact_terminal_safe_content(&pending_compaction),
            Err(AdapterEdgeError::SequenceConflict)
        ));
        let assembly_count: i64 = reopened
            .connection
            .query_row(
                "SELECT count(*) FROM adapter_content_assemblies",
                [],
                |row| row.get(0),
            )
            .expect("pending compaction preserves assembly");
        assert_eq!(assembly_count, 1);

        let committed = reopened
            .commit_final_artifact_relation(&request, 13)
            .expect("complete relation after restart");
        let FinalArtifactRelationCommit::Committed(expected_record) = committed else {
            panic!("relation must commit after restart")
        };
        let messages = reopened
            .pending_safe_content_projection()
            .expect("relation projection outbox");
        assert_eq!(messages.len(), 1);
        assert!(
            reopened
                .acknowledge_safe_content_projection(
                    &messages[0].message_id,
                    &messages[0].payload_digest_sha256,
                )
                .expect("settle relation projection")
        );
        let compaction = ContentRetentionCompactionRequest {
            final_epoch: "epoch-projected".to_owned(),
            expected_owner_sequence: 2,
            ..pending_compaction
        };
        reopened
            .compact_terminal_safe_content(&compaction)
            .expect("projected relation permits compaction");
        assert_eq!(
            reopened
                .commit_final_artifact_relation(&request, 14)
                .expect("compacted exact replay"),
            FinalArtifactRelationCommit::Replay(expected_record)
        );
        let status = reopened
            .final_artifact_relation_status(&request.terminal_message_id)
            .expect("read projected relation status")
            .expect("projected relation remains auditable");
        assert_eq!(status.state, FinalArtifactRelationState::Projected);
        assert_eq!(status.safe_reason_code, None);
    }

    #[test]
    fn final_artifact_relation_skips_legacy_and_rejects_ambiguous_or_unmatched_content() {
        let isolated = IsolatedEdge::new("final-artifact-relation-compat");
        let mut edge = open_edge(&isolated.path());
        let output = b"same final answer".to_vec();
        persist_terminal_candidate(
            &mut edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate");
        let request = FinalArtifactRelationRequest {
            terminal_message_id: pending[0].message_id.clone(),
            terminal_payload_digest_sha256: pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:compat".to_owned(),
            artifact_digest_sha256: pending[0].content_digest_sha256.clone(),
        };
        assert_eq!(
            edge.register_final_artifact_relation_intent_and_ack(&request, 12)
                .expect("register relation intent"),
            FinalArtifactRelationRegistration::Registered
        );
        install_pending_content_marker(&mut edge);
        assert_eq!(
            edge.commit_final_artifact_relation(&request, 12)
                .expect("content pending"),
            FinalArtifactRelationCommit::PendingContent
        );
        edge.connection
            .execute("DELETE FROM adapter_content_candidates", [])
            .expect("settle pending marker");

        install_finalized_assembly(&mut edge, "message-other", b"other", "other");
        install_finalized_assembly(&mut edge, "message-match-1", &output, "same final answer");
        install_finalized_marker_assembly(&mut edge, "message-match-2", &output);
        assert!(matches!(
            edge.commit_final_artifact_relation(&request, 14),
            Ok(FinalArtifactRelationCommit::Ambiguous)
        ));
        assert_eq!(
            edge.inspect()
                .expect("no relation on conflicts")
                .safe_content_ledger_count,
            0
        );

        let mismatch = IsolatedEdge::new("final-artifact-relation-mismatch");
        let mut mismatch_edge = open_edge(&mismatch.path());
        persist_terminal_candidate(
            &mut mismatch_edge,
            output.clone(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let mismatch_pending = mismatch_edge
            .pending_terminal_output_candidates()
            .expect("mismatch terminal candidate");
        let mismatch_request = FinalArtifactRelationRequest {
            terminal_message_id: mismatch_pending[0].message_id.clone(),
            terminal_payload_digest_sha256: mismatch_pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:mismatch".to_owned(),
            artifact_digest_sha256: mismatch_pending[0].content_digest_sha256.clone(),
        };
        mismatch_edge
            .register_final_artifact_relation_intent_and_ack(&mismatch_request, 12)
            .expect("register mismatch intent");
        install_finalized_assembly(&mut mismatch_edge, "message-other", b"other", "other");
        assert_eq!(
            mismatch_edge
                .commit_final_artifact_relation(&mismatch_request, 13)
                .expect("quarantine mismatch"),
            FinalArtifactRelationCommit::RawMismatch
        );
        drop(mismatch_edge);
        let mismatch_edge = open_edge(&mismatch.path());
        let mismatch_status = mismatch_edge
            .final_artifact_relation_status(&mismatch_request.terminal_message_id)
            .expect("read mismatch status after restart")
            .expect("mismatch remains auditable");
        assert_eq!(
            mismatch_status.state,
            FinalArtifactRelationState::Quarantined
        );
        assert_eq!(
            mismatch_status.safe_reason_code.as_deref(),
            Some("FINAL_ARTIFACT_RELATION_RAW_MISMATCH")
        );

        let legacy = IsolatedEdge::new("final-artifact-relation-legacy");
        let mut legacy_edge = open_edge(&legacy.path());
        persist_terminal_candidate(
            &mut legacy_edge,
            output,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
        );
        let legacy_pending = legacy_edge
            .pending_terminal_output_candidates()
            .expect("legacy terminal candidate");
        let legacy_request = FinalArtifactRelationRequest {
            terminal_message_id: legacy_pending[0].message_id.clone(),
            terminal_payload_digest_sha256: legacy_pending[0].payload_digest_sha256.clone(),
            artifact_id: "artifact:final:legacy".to_owned(),
            artifact_digest_sha256: legacy_pending[0].content_digest_sha256.clone(),
        };
        assert_eq!(
            legacy_edge
                .register_final_artifact_relation_intent_and_ack(&legacy_request, 12)
                .expect("trusted legacy ACK"),
            FinalArtifactRelationRegistration::SkippedLegacy
        );
    }

    #[test]
    fn terminal_output_replay_conflict_and_tamper_fail_closed() {
        let isolated = IsolatedEdge::new("terminal-output-integrity");
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage("dispatch-001", "task-001", 2, 1, 10)
            .expect("bind task lineage");
        let candidate = terminal_candidate(b"original".to_vec());
        edge.append_observation_with_terminal_output(
            "dispatch-001",
            "native:terminal:001",
            b"terminal-event",
            terminal_observation(),
            Some(&candidate),
            11,
        )
        .expect("persist candidate");
        let conflicting = terminal_candidate(b"forged".to_vec());
        assert!(matches!(
            edge.append_observation_with_terminal_output(
                "dispatch-001",
                "native:terminal:001",
                b"terminal-event",
                terminal_observation(),
                Some(&conflicting),
                12,
            ),
            Err(AdapterEdgeError::SequenceConflict)
        ));
        edge.connection
            .execute(
                "UPDATE adapter_terminal_output_outbox SET captured_content = ?1",
                [b"tampered".as_slice()],
            )
            .expect("inject storage tamper");
        assert!(matches!(
            edge.pending_terminal_output_candidates(),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
    }

    #[test]
    fn oversized_terminal_output_preserves_bounded_preview_digest_and_marker() {
        let isolated = IsolatedEdge::new("terminal-output-budget");
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage("dispatch-001", "task-001", 2, 1, 10)
            .expect("bind task lineage");
        let content = vec![0x5a; TERMINAL_OUTPUT_FULL_BYTES + 1];
        let expected_digest = sha256(&content);
        let candidate = terminal_candidate(content);
        edge.append_observation_with_terminal_output(
            "dispatch-001",
            "native:terminal:001",
            b"terminal-event",
            terminal_observation(),
            Some(&candidate),
            11,
        )
        .expect("persist bounded terminal preview");
        let pending = edge
            .pending_terminal_output_candidates()
            .expect("read bounded terminal preview");
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].content_complete);
        assert_eq!(pending[0].content.len(), TERMINAL_OUTPUT_PREVIEW_BYTES);
        assert_eq!(
            pending[0].original_content_bytes,
            (TERMINAL_OUTPUT_FULL_BYTES + 1) as u64
        );
        assert_eq!(pending[0].content_digest_sha256, expected_digest);
    }

    #[test]
    fn reviewed_harness_edges_are_isolated_and_cannot_cross_write() {
        let codex_root = IsolatedEdge::new("g4-09-codex-edge");
        let dsh_root = IsolatedEdge::new("g4-09-dsh-edge");
        let mut codex = open_edge_with_id(&codex_root.path(), "codex-adapter");
        let mut dsh = open_edge_with_id(&dsh_root.path(), "dsh-adapter");
        let codex_dispatch = dispatch_with_id("dispatch-codex", "attempt-codex");
        let dsh_dispatch = dispatch_with_id("dispatch-dsh", "attempt-dsh");

        assert!(matches!(
            codex.prepare_dispatch(&codex_dispatch, 10),
            Ok(DispatchPreparation::Ready)
        ));
        assert!(matches!(
            dsh.prepare_dispatch(&dsh_dispatch, 10),
            Ok(DispatchPreparation::Ready)
        ));
        codex
            .append_observation(
                &codex_dispatch.dispatch_id,
                "native:codex:terminal",
                b"codex-terminal",
                observation_for(&codex_dispatch.dispatch_id, &codex_dispatch.attempt_id),
                11,
            )
            .expect("codex observation stays in codex edge");
        dsh.append_observation(
            &dsh_dispatch.dispatch_id,
            "native:dsh:terminal",
            b"dsh-terminal",
            observation_for(&dsh_dispatch.dispatch_id, &dsh_dispatch.attempt_id),
            11,
        )
        .expect("dsh observation stays in dsh edge");

        assert!(
            codex
                .dispatch_envelope(&dsh_dispatch.dispatch_id)
                .expect("read codex edge")
                .is_none()
        );
        assert!(
            dsh.dispatch_envelope(&codex_dispatch.dispatch_id)
                .expect("read dsh edge")
                .is_none()
        );
        assert_eq!(
            codex.inspect().expect("inspect codex edge").dispatch_count,
            1
        );
        assert_eq!(dsh.inspect().expect("inspect dsh edge").dispatch_count, 1);
        assert_eq!(
            codex
                .inspect()
                .expect("inspect codex edge")
                .observation_count,
            1
        );
        assert_eq!(
            dsh.inspect().expect("inspect dsh edge").observation_count,
            1
        );
    }

    fn approval_observation() -> HarnessObservation {
        HarnessObservation {
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 1,
            criticality: ObservationCriticality::Control as i32,
            payload: Some(harness_observation::Payload::ApprovalRequest(
                ApprovalRequestObservation {
                    approval_request_id: "approval-request-001".to_owned(),
                    kind: ApprovalKind::Command as i32,
                    action_digest_sha256: "8".repeat(64),
                    requested_scope_ref: "safe://scope/001".to_owned(),
                    display_summary_ref: "safe://summary/001".to_owned(),
                    display_summary: None,
                    native_routing_ref: "adapter-private://route/001".to_owned(),
                    lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                    request_revision: 1,
                },
            )),
            ..HarnessObservation::default()
        }
    }

    #[test]
    fn durable_edge_replays_and_quarantines_conflicting_native_events() {
        let isolated = IsolatedEdge::new("adapter-edge-replay");
        let mut edge = open_edge(&isolated.path());
        assert_eq!(
            edge.prepare_dispatch(&dispatch(), 10).expect("prepare"),
            DispatchPreparation::Ready
        );
        edge.begin_delivery("dispatch-001", 11)
            .expect("begin delivery");
        edge.record_dispatch_receipt(&receipt(), b"delivery-raw", 12)
            .expect("record receipt");

        assert_eq!(
            edge.prepare_approval("approval-001", "dispatch-001", &"4".repeat(64), 12)
                .expect("prepare approval"),
            DurableWritePreparation::Ready
        );
        edge.begin_approval("approval-001", 12)
            .expect("begin approval");
        edge.record_approval_receipt(
            "approval-001",
            "delivered",
            b"approval-receipt",
            b"approval-raw",
            12,
        )
        .expect("record approval");
        assert!(matches!(
            edge.prepare_approval("approval-001", "dispatch-001", &"4".repeat(64), 12)
                .expect("replay approval"),
            DurableWritePreparation::Replay(_)
        ));

        assert_eq!(
            edge.prepare_cancellation("cancel-001", "dispatch-001", &"5".repeat(64), 12)
                .expect("prepare cancellation"),
            DurableWritePreparation::Ready
        );
        edge.begin_cancellation("cancel-001", 12)
            .expect("begin cancellation");
        edge.record_cancellation_receipt(
            "cancel-001",
            "delivered",
            b"cancel-receipt",
            b"cancel-raw",
            12,
        )
        .expect("record cancellation");

        let first = edge
            .append_observation("dispatch-001", "native-1", b"raw-1", observation(), 13)
            .expect("append observation");
        let replay = edge
            .append_observation("dispatch-001", "native-1", b"raw-1", observation(), 14)
            .expect("replay observation");
        let (ObservationAppend::Committed(first), ObservationAppend::Replay(replay)) =
            (first, replay)
        else {
            panic!("expected committed then replayed observations");
        };
        assert_eq!(first.observation_id, replay.observation_id);
        assert_eq!(first.observation_sequence, 1);
        assert_eq!(replay.observation_sequence, 1);
        assert!(matches!(
            edge.append_observation(
                "dispatch-001",
                "native-1",
                b"conflicting-raw",
                observation(),
                15
            ),
            Err(AdapterEdgeError::SequenceConflict)
        ));
        let inspection = edge.inspect().expect("inspect edge");
        assert_eq!(inspection.observation_count, 1);
        assert_eq!(inspection.quarantine_count, 1);
        assert_eq!(edge.pending_observations().expect("pending").len(), 1);
        edge.quarantine_observation(&first.observation_id, "STALE_FENCING_TOKEN", 16)
            .expect("quarantine stale observation");
        edge.quarantine_observation(&first.observation_id, "STALE_FENCING_TOKEN", 17)
            .expect("replay quarantine");
        assert!(edge.pending_observations().expect("pending").is_empty());
        assert_eq!(edge.inspect().expect("inspect").quarantine_count, 2);
        assert_eq!(inspection.approval_count, 1);
        assert_eq!(inspection.cancellation_count, 1);
        assert_eq!(inspection.next_observation_sequence, 2);
        assert!(edge.integrity_is_ok().expect("edge integrity"));
    }

    #[test]
    fn normal_observation_recovery_excludes_reconciliation_and_retains_terminal_barrier() {
        let isolated = IsolatedEdge::new("normal-observation-recovery");
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch");

        let ObservationAppend::Committed(first) = edge
            .append_observation(
                "dispatch-001",
                "normal:control",
                b"normal-control",
                observation(),
                11,
            )
            .expect("append first normal observation")
        else {
            panic!("first normal observation must commit");
        };
        let ObservationAppend::Committed(reconciliation) = edge
            .append_observation(
                "dispatch-001",
                "reconciliation:r1",
                b"reconciliation",
                observation(),
                12,
            )
            .expect("append reconciliation observation")
        else {
            panic!("reconciliation observation must commit");
        };
        let ObservationAppend::Committed(case_variant) = edge
            .append_observation(
                "dispatch-001",
                "Reconciliation:r2",
                b"case-variant-normal",
                observation(),
                13,
            )
            .expect("append case-variant normal observation")
        else {
            panic!("case-variant normal observation must commit");
        };
        let ObservationAppend::Committed(first_terminal) = edge
            .append_observation(
                "dispatch-001",
                "normal:terminal:first",
                b"normal-terminal-first",
                terminal_observation(),
                14,
            )
            .expect("append first terminal normal observation")
        else {
            panic!("first terminal normal observation must commit");
        };
        let ObservationAppend::Committed(second_terminal) = edge
            .append_observation(
                "dispatch-001",
                "normal:terminal:second",
                b"normal-terminal-second",
                terminal_observation(),
                15,
            )
            .expect("append second terminal normal observation")
        else {
            panic!("second terminal normal observation must commit");
        };
        assert_eq!(
            (
                first.observation_sequence,
                reconciliation.observation_sequence,
                case_variant.observation_sequence,
                first_terminal.observation_sequence,
                second_terminal.observation_sequence
            ),
            (1, 2, 3, 4, 5)
        );
        assert!(matches!(
            edge.normal_observation_recovery_view("dispatch-001", ""),
            Err(AdapterEdgeError::IntegrityFailure)
        ));

        let view = edge
            .normal_observation_recovery_view("dispatch-001", TEST_CAPABILITY_PROFILE_ID)
            .expect("read normal recovery view");
        assert_eq!(
            view.pending
                .iter()
                .map(|observation| observation.observation_sequence)
                .collect::<Vec<_>>(),
            vec![1, 3, 4, 5]
        );
        assert_eq!(view.durable_terminal_sequence, Some(4));
        assert!(
            view.pending
                .iter()
                .all(|observation| observation.observation_id != reconciliation.observation_id)
        );
        assert!(
            view.pending
                .iter()
                .any(|observation| observation.observation_id == case_variant.observation_id)
        );

        edge.mark_observation_consumed(&first_terminal.observation_id)
            .expect("consume first terminal observation");
        drop(edge);
        let reopened = open_edge(&isolated.path());
        let consumed_view = reopened
            .normal_observation_recovery_view("dispatch-001", TEST_CAPABILITY_PROFILE_ID)
            .expect("read recovery view after reopen");
        assert_eq!(
            consumed_view
                .pending
                .iter()
                .map(|observation| observation.observation_sequence)
                .collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
        assert_eq!(consumed_view.durable_terminal_sequence, Some(4));
    }

    #[test]
    fn normal_observation_recovery_fails_closed_on_row_sequence_or_state_drift() {
        let isolated = IsolatedEdge::new("normal-observation-recovery-sequence-drift");
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch");
        let ObservationAppend::Committed(committed_observation) = edge
            .append_observation(
                "dispatch-001",
                "normal:control",
                b"normal-control",
                observation(),
                11,
            )
            .expect("append normal observation")
        else {
            panic!("normal observation must commit");
        };
        assert_eq!(
            edge.connection
                .execute(
                    "UPDATE adapter_observations SET observation_sequence = 7
                     WHERE observation_id = ?1",
                    [&committed_observation.observation_id],
                )
                .expect("inject row sequence drift"),
            1
        );

        assert!(matches!(
            edge.normal_observation_recovery_view("dispatch-001", TEST_CAPABILITY_PROFILE_ID),
            Err(AdapterEdgeError::IntegrityFailure)
        ));

        let state_isolated = IsolatedEdge::new("normal-observation-recovery-ingestion-state-drift");
        let mut state_edge = open_edge(&state_isolated.path());
        state_edge
            .prepare_dispatch(&dispatch(), 10)
            .expect("prepare dispatch for state drift");
        let ObservationAppend::Committed(state_observation) = state_edge
            .append_observation(
                "dispatch-001",
                "normal:control",
                b"normal-control",
                observation(),
                11,
            )
            .expect("append observation for state drift")
        else {
            panic!("normal observation must commit");
        };
        state_edge
            .connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .expect("allow controlled ingestion state fault injection");
        assert_eq!(
            state_edge
                .connection
                .execute(
                    "UPDATE adapter_observations SET ingestion_state = 'invalid'
                     WHERE observation_id = ?1",
                    [&state_observation.observation_id],
                )
                .expect("inject ingestion state drift"),
            1
        );
        assert!(matches!(
            state_edge.normal_observation_recovery_view("dispatch-001", TEST_CAPABILITY_PROFILE_ID),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
    }

    #[test]
    fn normal_observation_recovery_fails_closed_on_digest_raw_ref_or_profile_drift() {
        for tamper in ["digest", "raw-ref", "profile"] {
            let isolated =
                IsolatedEdge::new(&format!("normal-observation-recovery-{tamper}-drift"));
            let mut edge = open_edge(&isolated.path());
            edge.prepare_dispatch(&dispatch(), 10)
                .expect("prepare dispatch");
            let ObservationAppend::Committed(observation) = edge
                .append_observation(
                    "dispatch-001",
                    "normal:control",
                    b"normal-control",
                    observation(),
                    11,
                )
                .expect("append normal observation")
            else {
                panic!("normal observation must commit");
            };

            match tamper {
                "digest" => {
                    let bytes: Vec<u8> = edge
                        .connection
                        .query_row(
                            "SELECT observation FROM adapter_observations
                             WHERE observation_id = ?1",
                            [&observation.observation_id],
                            |row| row.get(0),
                        )
                        .expect("read observation for digest drift");
                    let mut stored = HarnessObservation::decode(bytes.as_slice())
                        .expect("decode observation for digest drift");
                    stored.native_event_digest_sha256 = "0".repeat(64);
                    assert_eq!(
                        edge.connection
                            .execute(
                                "UPDATE adapter_observations
                                 SET native_event_digest_sha256 = ?1, observation = ?2
                                 WHERE observation_id = ?3",
                                params![
                                    stored.native_event_digest_sha256,
                                    stored.encode_to_vec(),
                                    observation.observation_id
                                ],
                            )
                            .expect("inject digest drift"),
                        1
                    );
                }
                "raw-ref" => {
                    assert_eq!(
                        edge.connection
                            .execute(
                                "UPDATE adapter_observations
                                 SET raw_evidence_ref = 'adapter-edge://drift/raw/ref'
                                 WHERE observation_id = ?1",
                                [&observation.observation_id],
                            )
                            .expect("inject raw evidence ref drift"),
                        1
                    );
                }
                "profile" => {
                    let bytes: Vec<u8> = edge
                        .connection
                        .query_row(
                            "SELECT observation FROM adapter_observations
                             WHERE observation_id = ?1",
                            [&observation.observation_id],
                            |row| row.get(0),
                        )
                        .expect("read observation for profile drift");
                    let mut stored = HarnessObservation::decode(bytes.as_slice())
                        .expect("decode observation for profile drift");
                    stored.capability_profile_id = "profile:other".to_owned();
                    assert_eq!(
                        edge.connection
                            .execute(
                                "UPDATE adapter_observations SET observation = ?1
                                 WHERE observation_id = ?2",
                                params![stored.encode_to_vec(), observation.observation_id],
                            )
                            .expect("inject profile drift"),
                        1
                    );
                }
                _ => unreachable!("fixed tamper matrix"),
            }

            assert!(matches!(
                edge.normal_observation_recovery_view("dispatch-001", TEST_CAPABILITY_PROFILE_ID),
                Err(AdapterEdgeError::IntegrityFailure)
            ));
        }
    }

    #[test]
    fn legacy_execution_start_requires_one_ack_and_conditionally_consumes_exact_row() {
        fn delivered_edge(label: &str) -> (IsolatedEdge, AdapterEdge, DispatchEnvelope) {
            let isolated = IsolatedEdge::new(label);
            let mut edge = open_edge(&isolated.path());
            let mut envelope = dispatch();
            envelope.capability_profile_ref = Some(ContractReference {
                contract_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
                version: "0.1".to_owned(),
                sha256: "3".repeat(64),
            });
            envelope.dispatch_fingerprint = "4".repeat(64);
            edge.prepare_dispatch(&envelope, 10)
                .expect("prepare V02 dispatch");
            edge.begin_delivery(&envelope.dispatch_id, 11)
                .expect("begin V02 delivery");
            let mut receipt = DispatchReceipt {
                receipt_id: "receipt-v02".to_owned(),
                disposition: DeliveryDisposition::Delivered as i32,
                dispatch_id: envelope.dispatch_id.clone(),
                attempt_id: envelope.attempt_id.clone(),
                fencing_token: envelope.fencing_token,
                adapter_id: "adapter:test".to_owned(),
                capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
                native_session_ref: Some("thread-v02".to_owned()),
                native_execution_ref: Some("turn-v02".to_owned()),
                ..DispatchReceipt::default()
            };
            receipt.receipt_digest_sha256 = sha256(&receipt.encode_to_vec());
            edge.record_dispatch_receipt(&receipt, b"delivery-v02", 12)
                .expect("record V02 delivery");
            (isolated, edge, envelope)
        }

        fn ack_observation(envelope: &DispatchEnvelope, receipt_id: &str) -> HarnessObservation {
            HarnessObservation {
                attempt_id: envelope.attempt_id.clone(),
                dispatch_id: envelope.dispatch_id.clone(),
                fencing_token: envelope.fencing_token,
                capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
                criticality: ObservationCriticality::Control as i32,
                payload: Some(harness_observation::Payload::Ack(HarnessAckObservation {
                    disposition: AckDisposition::Accepted as i32,
                    ack_receipt_id: receipt_id.to_owned(),
                    native_session_ref: Some("thread-v02".to_owned()),
                    native_execution_ref: Some("turn-v02".to_owned()),
                })),
                ..HarnessObservation::default()
            }
        }

        fn started_observation(envelope: &DispatchEnvelope) -> HarnessObservation {
            HarnessObservation {
                attempt_id: envelope.attempt_id.clone(),
                dispatch_id: envelope.dispatch_id.clone(),
                fencing_token: envelope.fencing_token,
                capability_profile_id: TEST_CAPABILITY_PROFILE_ID.to_owned(),
                criticality: ObservationCriticality::Control as i32,
                payload: Some(harness_observation::Payload::Lifecycle(
                    LifecycleObservation {
                        kind: LifecycleKind::ExecutionStarted as i32,
                        safe_status_code: Some("inProgress".to_owned()),
                        side_effect_certainty: SideEffectCertainty::Unknown as i32,
                        ..LifecycleObservation::default()
                    },
                )),
                ..HarnessObservation::default()
            }
        }

        let (_isolated, mut edge, envelope) = delivered_edge("v02-exact-edge");
        let ObservationAppend::Committed(ack) = edge
            .append_observation(
                &envelope.dispatch_id,
                "v02:ack",
                b"ack-v02",
                ack_observation(&envelope, "ack-v02"),
                13,
            )
            .expect("append V02 ACK")
        else {
            panic!("V02 ACK must commit");
        };
        let ObservationAppend::Committed(prior) = edge
            .append_observation(
                &envelope.dispatch_id,
                "v02:legacy-active",
                b"opaque legacy active event",
                started_observation(&envelope),
                14,
            )
            .expect("append legacy active start")
        else {
            panic!("legacy active start must commit");
        };
        edge.mark_observation_consumed(&ack.observation_id)
            .expect("consume V02 ACK");
        edge.mark_observation_consumed(&prior.observation_id)
            .expect("consume first V02 start");
        let ObservationAppend::Committed(pending) = edge
            .append_observation(
                &envelope.dispatch_id,
                "v02:turn-start",
                b"opaque execution started event",
                started_observation(&envelope),
                15,
            )
            .expect("append duplicate V02 start")
        else {
            panic!("duplicate V02 start must commit");
        };
        edge.bind_dispatch_task_lineage(&envelope.dispatch_id, "task-v02", 1, 1, 15)
            .expect("bind V02 terminal lineage");
        let terminal_raw = b"opaque terminal evidence";
        let terminal_candidate = TerminalOutputCandidate {
            dispatch_id: envelope.dispatch_id.clone(),
            native_completion_ref: "item-output".to_owned(),
            media_type: "text/plain; charset=utf-8".to_owned(),
            content: b"V02 terminal output".to_vec(),
        };
        let ObservationAppend::Committed(terminal) = edge
            .append_observation_with_terminal_output(
                &envelope.dispatch_id,
                "v02:turn-completed",
                terminal_raw,
                terminal_observation(),
                Some(&terminal_candidate),
                16,
            )
            .expect("append exact-turn terminal candidate")
        else {
            panic!("V02 terminal candidate must commit");
        };
        let LegacyExecutionStartEvidenceResolution::Verified(evidence) = edge
            .legacy_execution_start_recovery_evidence(
                &envelope.dispatch_id,
                &envelope.attempt_id,
                envelope.fencing_token,
                TEST_CAPABILITY_PROFILE_ID,
                &pending.observation_id,
                prior.observation_sequence,
            )
            .expect("verify exact V02 evidence")
        else {
            panic!("exact V02 evidence must verify");
        };
        assert!(evidence.durable_terminal_handoff);
        assert_eq!(
            evidence.terminal_raw_event.as_deref(),
            Some(&terminal_raw[..])
        );
        assert_eq!(
            evidence.terminal_native_completion_ref.as_deref(),
            Some("item-output")
        );
        assert_ne!(
            evidence.terminal_native_completion_ref.as_deref(),
            Some(evidence.native_binding.native_execution_ref.as_str()),
            "native output identity must not be treated as the ACK execution identity"
        );
        assert_eq!(
            terminal.observation_sequence,
            pending.observation_sequence + 1
        );
        assert!(
            edge.consume_legacy_execution_start_duplicate(&evidence)
                .expect("consume exact V02 duplicate")
        );
        assert!(
            edge.consume_legacy_execution_start_duplicate(&evidence)
                .expect("replay exact V02 duplicate consume")
        );
        let pending_after_duplicate = edge
            .normal_observation_recovery_view(&envelope.dispatch_id, TEST_CAPABILITY_PROFILE_ID)
            .expect("inspect V02 terminal handoff after duplicate consume");
        assert_eq!(pending_after_duplicate.pending, vec![terminal]);

        let (_conflict_isolated, mut conflict_edge, conflict_envelope) =
            delivered_edge("v02-multiple-ack-edge");
        let ObservationAppend::Committed(first_ack) = conflict_edge
            .append_observation(
                &conflict_envelope.dispatch_id,
                "v02:ack:first",
                b"ack-first",
                ack_observation(&conflict_envelope, "ack-first"),
                13,
            )
            .expect("append first V02 ACK")
        else {
            panic!("first V02 ACK must commit");
        };
        let ObservationAppend::Committed(second_ack) = conflict_edge
            .append_observation(
                &conflict_envelope.dispatch_id,
                "v02:ack:second",
                b"ack-second",
                ack_observation(&conflict_envelope, "ack-second"),
                14,
            )
            .expect("append second V02 ACK")
        else {
            panic!("second V02 ACK must commit");
        };
        let ObservationAppend::Committed(conflict_prior) = conflict_edge
            .append_observation(
                &conflict_envelope.dispatch_id,
                "v02:legacy-active",
                b"legacy-active",
                started_observation(&conflict_envelope),
                15,
            )
            .expect("append conflict prior start")
        else {
            panic!("conflict prior start must commit");
        };
        for observation_id in [
            &first_ack.observation_id,
            &second_ack.observation_id,
            &conflict_prior.observation_id,
        ] {
            conflict_edge
                .mark_observation_consumed(observation_id)
                .expect("consume conflict prerequisite");
        }
        let ObservationAppend::Committed(conflict_pending) = conflict_edge
            .append_observation(
                &conflict_envelope.dispatch_id,
                "v02:turn-start",
                b"turn-start",
                started_observation(&conflict_envelope),
                16,
            )
            .expect("append conflict pending start")
        else {
            panic!("conflict pending start must commit");
        };
        assert_eq!(
            conflict_edge
                .legacy_execution_start_recovery_evidence(
                    &conflict_envelope.dispatch_id,
                    &conflict_envelope.attempt_id,
                    conflict_envelope.fencing_token,
                    TEST_CAPABILITY_PROFILE_ID,
                    &conflict_pending.observation_id,
                    conflict_prior.observation_sequence,
                )
                .expect("classify duplicate ACK evidence"),
            LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::NativeBindingConflict
            )
        );
        assert_eq!(
            conflict_edge
                .inspect()
                .expect("inspect duplicate ACK edge")
                .pending_observation_count,
            1
        );
    }

    #[test]
    fn abort_after_delivery_begins_recovers_as_unknown_without_redispatch() {
        if std::env::var_os(ABORT_HELPER_ENV).is_some() {
            let path = PathBuf::from(
                std::env::var_os(ABORT_PATH_ENV).expect("abort helper database path"),
            );
            let mut edge = open_edge(&path);
            edge.prepare_dispatch(&dispatch(), 20)
                .expect("helper prepare dispatch");
            edge.begin_delivery("dispatch-001", 21)
                .expect("helper begin delivery");
            std::process::abort();
        }

        let isolated = IsolatedEdge::new("adapter-edge-abort");
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("edge::tests::abort_after_delivery_begins_recovers_as_unknown_without_redispatch")
            .arg("--nocapture")
            .env(ABORT_HELPER_ENV, "1")
            .env(ABORT_PATH_ENV, isolated.path())
            .status()
            .expect("run abort helper");
        assert!(!status.success());

        let mut recovered = open_edge(&isolated.path());
        assert_eq!(
            recovered
                .prepare_dispatch(&dispatch(), 22)
                .expect("recover dispatch"),
            DispatchPreparation::DeliveryUnknown
        );
        recovered
            .record_dispatch_receipt(&receipt(), b"recovered-unknown", 23)
            .expect("durably close unknown receipt");
        assert!(matches!(
            recovered
                .prepare_dispatch(&dispatch(), 24)
                .expect("replay unknown receipt"),
            DispatchPreparation::Replay(_)
        ));
        assert_eq!(
            recovered
                .inspect()
                .expect("inspect recovered edge")
                .dispatch_count,
            1
        );
    }

    #[test]
    fn approval_projection_outbox_is_typed_durable_and_acknowledged_idempotently() {
        let isolated = IsolatedEdge::new("adapter-approval-projection");
        let mut envelope = dispatch();
        envelope.run_id = "run-001".to_owned();
        envelope.step_id = "step-001".to_owned();
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&envelope, 10)
            .expect("prepare projection dispatch");
        let appended = edge
            .append_observation(
                "dispatch-001",
                "native-approval-001",
                b"approval-raw",
                approval_observation(),
                11,
            )
            .expect("append approval observation");
        let ObservationAppend::Committed(observation) = appended else {
            panic!("expected committed approval observation");
        };
        let pending = edge
            .pending_approval_projection_messages()
            .expect("pending approval projection");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_observation_id, observation.observation_id);
        assert_eq!(pending[0].run_id, "run-001");
        assert_eq!(pending[0].step_id, "step-001");
        assert_eq!(pending[0].attempt_id, "attempt-001");
        assert_eq!(pending[0].dispatch_id, "dispatch-001");
        assert_eq!(pending[0].fencing_token, 1);
        let projected_request = match pending[0].observation.payload.as_ref() {
            Some(harness_observation::Payload::ApprovalRequest(request)) => request,
            _ => panic!("typed approval projection"),
        };
        assert!(projected_request.native_routing_ref.is_empty());
        assert_eq!(edge.inspect().expect("inspect").projection_outbox_count, 1);
        assert!(
            edge.acknowledge_approval_projection_message(
                &pending[0].message_id,
                &pending[0].payload_digest_sha256,
            )
            .expect("ack projection")
        );
        assert!(
            edge.acknowledge_approval_projection_message(
                &pending[0].message_id,
                &pending[0].payload_digest_sha256,
            )
            .expect("idempotent projection ack")
        );
        assert!(
            edge.pending_approval_projection_messages()
                .expect("projection drained")
                .is_empty()
        );
        assert_eq!(
            edge.retained_approval_projection_messages_for_rebuild()
                .expect("acknowledged projection remains rebuildable")
                .len(),
            1
        );
        drop(edge);
        let recovered = open_edge(&isolated.path());
        assert_eq!(
            recovered
                .inspect()
                .expect("inspect recovered projection")
                .pending_projection_count,
            0
        );
        assert_eq!(
            recovered
                .retained_approval_projection_messages_for_rebuild()
                .expect("recovered retained projection")
                .len(),
            1
        );
    }

    #[test]
    fn r9c_compaction_and_tombstone_canonical_vectors_match_the_frozen_profile() {
        let profile = disclosure_profile_reference();
        let mut tombstone = HarnessContentRetentionTombstone {
            tombstone_id: retention_tombstone_id("task-001", "attempt-001", "content-epoch-02", 4),
            tombstone_digest_sha256: String::new(),
            task_id: "task-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            final_epoch: "content-epoch-02".to_owned(),
            final_sequence: 4,
            final_safe_content_digest_sha256: "d".repeat(64),
            disclosure_profile_ref: Some(profile.clone()),
            terminal_committed_at: Some(prost_types::Timestamp {
                seconds: 1_785_888_000,
                nanos: 0,
            }),
            compacted_at: Some(prost_types::Timestamp {
                seconds: 1_788_480_000,
                nanos: 0,
            }),
            reason: HarnessContentRetentionReason::TerminalMinimumExpired as i32,
        };
        assert_eq!(
            tombstone.tombstone_id,
            "hrt_a5ea102e29b1eeac1fa461732090071030bae1bc1fc3ab80970c39ca428c3365"
        );
        tombstone.tombstone_digest_sha256 =
            canonical_retention_tombstone_digest(&tombstone).expect("canonical tombstone");
        assert_eq!(
            tombstone.tombstone_digest_sha256,
            "d0ea91476deef69179199243da72410861300ea4698e033460a5e5c18e07f68e"
        );

        let mut compaction = HarnessContentHistoryCompactionRecord {
            compaction_record_id: history_compaction_id(
                "task-001",
                "attempt-001",
                "content-epoch-01",
                13,
            ),
            compaction_record_digest_sha256: String::new(),
            task_id: "task-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            final_epoch: "content-epoch-01".to_owned(),
            final_sequence: 13,
            final_safe_content_digest_sha256: "f".repeat(64),
            owner_snapshot_digest_sha256: "e".repeat(64),
            disclosure_profile_ref: Some(profile),
            compacted_at: Some(prost_types::Timestamp {
                seconds: 1_788_480_000,
                nanos: 0,
            }),
            reason: HarnessContentCompactionReason::OwnerHistoryFloorAdvanced as i32,
        };
        assert_eq!(
            compaction.compaction_record_id,
            "hcc_86ee58c2c699af284440e94a3a4fbcea0e5acbf44f47d971eef5a5cf4b2499ce"
        );
        compaction.compaction_record_digest_sha256 =
            canonical_history_compaction_digest(&compaction).expect("canonical compaction");
        assert_eq!(
            compaction.compaction_record_digest_sha256,
            "9d4289be5038e132b948c0b125ce2051f05d0a169f586d2d29d30d97f38013c0"
        );
    }

    fn budget_history_record(
        task_id: &str,
        attempt_id: &str,
        payload: safe_harness_content_record::Payload,
    ) -> SafeHarnessContentRecord {
        let content_event_id = format!("event-{task_id}-{attempt_id}");
        let (payload_kind, limit_kind) = match &payload {
            safe_harness_content_record::Payload::AssistantText(_) => {
                ("ASSISTANT_TEXT", HarnessContentLimitKind::Unspecified)
            }
            safe_harness_content_record::Payload::Marker(marker) => (
                "MARKER",
                HarnessContentLimitKind::try_from(marker.limit_kind)
                    .expect("typed budget marker kind"),
            ),
            _ => panic!("budget history fixture payload"),
        };
        SafeHarnessContentRecord {
            record_id: canonical_safe_record_id(&content_event_id, payload_kind, limit_kind, 0),
            content_event_id,
            task_id: task_id.to_owned(),
            run_id: "run-budget-integrity".to_owned(),
            step_id: "step-budget-integrity".to_owned(),
            attempt_id: attempt_id.to_owned(),
            dispatch_id: "dispatch-budget-integrity".to_owned(),
            fencing_token: 1,
            route_binding_sha256: "a".repeat(64),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            provider_family_alias: "provider".to_owned(),
            model_alias: "model".to_owned(),
            collaboration_role: "role".to_owned(),
            payload: Some(payload),
            ..SafeHarnessContentRecord::default()
        }
    }

    #[test]
    fn r9c_owner_history_rejects_lowered_budget_counts_without_safe_writes() {
        let isolated = IsolatedEdge::new("r9c-budget-count-drift");
        let mut edge = open_edge(&isolated.path());
        let record = budget_history_record(
            "task-budget-count",
            "attempt-budget-count",
            safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
                safe_message_id: "message-budget-count".to_owned(),
                revision: 1,
                operation: ContentMutationOperation::Append as i32,
                safe_text_utf8: "safe".to_owned(),
                safe_cumulative_digest_sha256: "b".repeat(64),
                part_count: 1,
                ..SafeAssistantTextContent::default()
            }),
        );
        install_owner_budget_history(&mut edge, record, None);
        edge.connection
            .execute(
                "UPDATE adapter_content_budgets SET safe_record_count = 0
                 WHERE scope_kind = 'task' AND scope_id = 'task-budget-count'",
                [],
            )
            .expect("corrupt persisted task count");
        let projection = pending_projection_for_budget_drift(
            &mut edge,
            "task-budget-count",
            "attempt-budget-count",
            "count",
        );
        let before = safe_content_write_state(&edge, &projection.record().content_event_id);
        assert!(matches!(
            edge.commit_safe_content_projection(&projection, 23),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
        assert_eq!(
            safe_content_write_state(&edge, &projection.record().content_event_id),
            before
        );
        assert_eq!(before.3, "pending");
    }

    #[test]
    fn r9c_owner_history_rejects_cleared_terminal_budget_without_safe_writes() {
        let isolated = IsolatedEdge::new("r9c-budget-terminal-drift");
        let mut edge = open_edge(&isolated.path());
        let record = budget_history_record(
            "task-budget-terminal",
            "attempt-budget-terminal",
            safe_harness_content_record::Payload::Marker(SafeContentMarker {
                kind: HarnessContentMarkerKind::LimitReached as i32,
                limit_kind: HarnessContentLimitKind::TaskTextBytes as i32,
            }),
        );
        install_owner_budget_history(
            &mut edge,
            record,
            Some(HarnessContentLimitKind::TaskTextBytes),
        );
        edge.connection
            .execute(
                "UPDATE adapter_content_budgets
                 SET limit_reached = 0, limit_kind = NULL
                 WHERE scope_kind = 'task' AND scope_id = 'task-budget-terminal'",
                [],
            )
            .expect("clear persisted terminal state");
        let projection = pending_projection_for_budget_drift(
            &mut edge,
            "task-budget-terminal",
            "attempt-budget-terminal",
            "terminal",
        );
        let before = safe_content_write_state(&edge, &projection.record().content_event_id);
        assert!(matches!(
            edge.commit_safe_content_projection(&projection, 23),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
        assert_eq!(
            safe_content_write_state(&edge, &projection.record().content_event_id),
            before
        );
        assert_eq!(before.3, "pending");
    }

    #[test]
    fn r9c_exact_text_capacity_without_limit_marker_remains_nonterminal() {
        let safe_text = "x".repeat(CONTENT_SAFE_PART_BYTES);
        let records = (1..=ATTEMPT_SAFE_TEXT_BYTES / CONTENT_SAFE_PART_BYTES as u64)
            .map(|sequence| SafeContentOwnerRecord {
                sequence,
                record: budget_history_record(
                    "task-exact-fill",
                    "attempt-exact-fill",
                    safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
                        safe_message_id: format!("message-exact-fill-{sequence}"),
                        revision: sequence,
                        operation: ContentMutationOperation::Append as i32,
                        safe_text_utf8: safe_text.clone(),
                        safe_cumulative_digest_sha256: "c".repeat(64),
                        part_count: 1,
                        ..SafeAssistantTextContent::default()
                    }),
                ),
            })
            .collect::<Vec<_>>();
        let budget = content_budget_from_owner_records(&records, Some("attempt-exact-fill"))
            .expect("exact text fill remains valid");
        assert_eq!(budget.text_bytes, ATTEMPT_SAFE_TEXT_BYTES);
        assert_eq!(budget.record_count, records.len() as u64);
        assert_eq!(budget.terminal_kind, None);
    }

    #[test]
    fn r9c_owner_baseline_rejects_oversized_framed_count_before_allocation() {
        let mut bytes = Vec::new();
        frame_bytes(&mut bytes, b"egopulse/harness-content/owner-baseline/v1");
        frame_bytes(&mut bytes, &(TASK_SAFE_RECORDS + 1).to_le_bytes());
        assert!(matches!(
            decode_content_owner_baseline(&bytes, "task-oversized-baseline"),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
    }

    #[test]
    fn r9c_content_budget_reserves_limit_record_and_splits_only_at_utf8_boundaries() {
        let mut record = SafeHarnessContentRecord {
            record_id: canonical_safe_record_id(
                "content-event-limit",
                "ASSISTANT_TEXT",
                HarnessContentLimitKind::Unspecified,
                0,
            ),
            content_event_id: "content-event-limit".to_owned(),
            task_id: "task-limit".to_owned(),
            run_id: "run-limit".to_owned(),
            step_id: "step-limit".to_owned(),
            attempt_id: "attempt-limit".to_owned(),
            dispatch_id: "dispatch-limit".to_owned(),
            fencing_token: 1,
            route_binding_sha256: "a".repeat(64),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            provider_family_alias: "provider".to_owned(),
            model_alias: "model".to_owned(),
            collaboration_role: "role".to_owned(),
            payload: Some(safe_harness_content_record::Payload::AssistantText(
                SafeAssistantTextContent {
                    safe_message_id: "hcm_test".to_owned(),
                    revision: 1,
                    previous_revision: 0,
                    operation: ContentMutationOperation::Append as i32,
                    safe_text_utf8: "ab鐣畞d".to_owned(),
                    safe_cumulative_digest_sha256: "b".repeat(64),
                    part_index: 0,
                    part_count: 1,
                },
            )),
            ..SafeHarnessContentRecord::default()
        };
        record.record_digest_sha256 =
            canonical_safe_record_digest(&record).expect("canonical source record");
        let empty = ContentBudgetState {
            text_bytes: 0,
            record_count: 0,
            terminal_kind: None,
        };
        let admission = admit_content_records(
            &[record.clone()],
            empty,
            empty,
            ContentBudgetLimits {
                attempt_text_bytes: 4,
                attempt_records: 3,
                task_text_bytes: 100,
                task_records: 3,
            },
        )
        .expect("bounded UTF-8 admission");
        assert_eq!(admission.text_bytes, 2);
        assert_eq!(
            admission.limit_kind,
            Some(HarnessContentLimitKind::AttemptTextBytes)
        );
        assert_eq!(
            admission.attempt_terminal_kind,
            Some(HarnessContentLimitKind::AttemptTextBytes)
        );
        assert_eq!(admission.task_terminal_kind, None);
        assert_eq!(admission.records.len(), 2);
        let Some(safe_harness_content_record::Payload::AssistantText(text)) =
            admission.records[0].payload.as_ref()
        else {
            panic!("bounded assistant prefix")
        };
        assert_eq!(text.safe_text_utf8, "ab");
        assert!(matches!(
            admission.records[1].payload,
            Some(safe_harness_content_record::Payload::Marker(SafeContentMarker {
                kind,
                limit_kind,
            })) if kind == HarnessContentMarkerKind::LimitReached as i32
                && limit_kind == HarnessContentLimitKind::AttemptTextBytes as i32
        ));
        assert_eq!(
            canonical_safe_record_digest(&admission.records[1]).as_deref(),
            Some(admission.records[1].record_digest_sha256.as_str())
        );

        let records_only = admit_content_records(
            &[record.clone()],
            empty,
            empty,
            ContentBudgetLimits {
                attempt_text_bytes: 100,
                attempt_records: 1,
                task_text_bytes: 100,
                task_records: 1,
            },
        )
        .expect("reserved record capacity");
        assert_eq!(records_only.records.len(), 1);
        assert_eq!(
            records_only.limit_kind,
            Some(HarnessContentLimitKind::TaskRecords)
        );
        assert_eq!(
            records_only.attempt_terminal_kind,
            Some(HarnessContentLimitKind::AttemptRecords)
        );
        assert_eq!(
            records_only.task_terminal_kind,
            Some(HarnessContentLimitKind::TaskRecords)
        );
        assert!(matches!(
            records_only.records[0].payload,
            Some(safe_harness_content_record::Payload::Marker(_))
        ));

        assert_eq!(
            winning_limit_kind([
                Some(HarnessContentLimitKind::AttemptTextBytes),
                Some(HarnessContentLimitKind::AttemptRecords),
                Some(HarnessContentLimitKind::TaskTextBytes),
                Some(HarnessContentLimitKind::TaskRecords),
            ]),
            Some(HarnessContentLimitKind::TaskRecords)
        );
        assert_eq!(
            winning_limit_kind([
                Some(HarnessContentLimitKind::AttemptRecords),
                Some(HarnessContentLimitKind::TaskTextBytes),
            ]),
            Some(HarnessContentLimitKind::TaskTextBytes)
        );

        let mut scalar_record = record;
        let Some(safe_harness_content_record::Payload::AssistantText(text)) =
            scalar_record.payload.as_mut()
        else {
            panic!("assistant text fixture")
        };
        text.safe_text_utf8 = "界".to_owned();
        scalar_record.record_digest_sha256.clear();
        scalar_record.record_digest_sha256 =
            canonical_safe_record_digest(&scalar_record).expect("scalar record digest");
        let simultaneous = admit_content_records(
            &[scalar_record],
            empty,
            empty,
            ContentBudgetLimits {
                attempt_text_bytes: 100,
                attempt_records: 1,
                task_text_bytes: 1,
                task_records: 10,
            },
        )
        .expect("incomplete scalar and record exhaustion");
        assert_eq!(simultaneous.text_bytes, 0);
        assert_eq!(simultaneous.records.len(), 1);
        assert_eq!(
            simultaneous.limit_kind,
            Some(HarnessContentLimitKind::TaskTextBytes)
        );
        assert_eq!(
            simultaneous.attempt_terminal_kind,
            Some(HarnessContentLimitKind::AttemptRecords)
        );
        assert_eq!(
            simultaneous.task_terminal_kind,
            Some(HarnessContentLimitKind::TaskTextBytes)
        );
        let Some(safe_harness_content_record::Payload::Marker(marker)) =
            simultaneous.records[0].payload.as_ref()
        else {
            panic!("typed terminal marker")
        };
        assert_eq!(
            marker.limit_kind,
            HarnessContentLimitKind::TaskTextBytes as i32
        );

        let isolated = IsolatedEdge::new("r9c-typed-content-budget-atomicity");
        let mut edge = open_edge(&isolated.path());
        let transaction = edge.connection.transaction().expect("budget transaction");
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "attempt",
                scope_id: "attempt-limit",
                previous: empty,
                added_text_bytes: simultaneous.text_bytes,
                added_records: simultaneous.records.len() as u64,
                terminal_kind: simultaneous.attempt_terminal_kind,
            },
            10,
        )
        .expect("terminal attempt budget");
        update_content_budget(
            &transaction,
            ContentBudgetUpdate {
                scope_kind: "task",
                scope_id: "task-limit",
                previous: empty,
                added_text_bytes: simultaneous.text_bytes,
                added_records: simultaneous.records.len() as u64,
                terminal_kind: simultaneous.task_terminal_kind,
            },
            10,
        )
        .expect("terminal task budget");
        transaction.commit().expect("commit both terminal scopes");
        let persisted: Vec<(String, String)> = {
            let mut statement = edge
                .connection
                .prepare(
                    "SELECT scope_kind, limit_kind FROM adapter_content_budgets ORDER BY scope_kind",
                )
                .expect("typed terminal budget query");
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("typed terminal budget rows")
                .collect::<Result<_, _>>()
                .expect("collect typed terminal budgets")
        };
        assert_eq!(
            persisted,
            vec![
                ("attempt".to_owned(), "ATTEMPT_RECORDS".to_owned()),
                ("task".to_owned(), "TASK_TEXT_BYTES".to_owned()),
            ]
        );
    }

    #[test]
    fn r9c_safe_outbox_read_and_ack_recompute_payload_and_ledger_identity() {
        let isolated = IsolatedEdge::new("r9c-safe-outbox-tamper");
        let mut edge = open_edge(&isolated.path());
        edge.prepare_dispatch(&dispatch(), 10).expect("prepare");
        let ObservationAppend::Committed(observation) = edge
            .append_observation(
                "dispatch-001",
                "native-safe-outbox",
                b"native-safe-outbox",
                observation(),
                11,
            )
            .expect("source observation")
        else {
            panic!("committed source observation")
        };
        edge.connection
            .execute(
                "INSERT INTO adapter_content_candidates(
                   content_event_id, source_observation_id, dispatch_id,
                   candidate_digest_sha256, content_signal, projection_state,
                   safe_projection_digest_sha256, committed_records_digest_sha256,
                   created_at_seconds, projected_at_seconds
                 ) VALUES(?1, ?2, 'dispatch-001', ?3, ?4, 'projected', ?5, ?6, 12, 12)",
                params![
                    "content-event-outbox",
                    observation.observation_id,
                    "a".repeat(64),
                    HarnessContentSignalObservation::default().encode_to_vec(),
                    "b".repeat(64),
                    "c".repeat(64),
                ],
            )
            .expect("candidate fixture");
        let mut record = SafeHarnessContentRecord {
            record_id: canonical_safe_record_id(
                "content-event-outbox",
                "ASSISTANT_TEXT",
                HarnessContentLimitKind::Unspecified,
                0,
            ),
            content_event_id: "content-event-outbox".to_owned(),
            task_id: "task-outbox".to_owned(),
            run_id: "run-001".to_owned(),
            step_id: "step-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 1,
            route_binding_sha256: "d".repeat(64),
            disclosure_profile_ref: Some(disclosure_profile_reference()),
            provider_family_alias: "provider".to_owned(),
            model_alias: "model".to_owned(),
            collaboration_role: "role".to_owned(),
            payload: Some(safe_harness_content_record::Payload::AssistantText(
                SafeAssistantTextContent {
                    safe_message_id: "hcm_outbox".to_owned(),
                    revision: 1,
                    previous_revision: 0,
                    operation: ContentMutationOperation::Append as i32,
                    safe_text_utf8: "safe".to_owned(),
                    safe_cumulative_digest_sha256: "e".repeat(64),
                    part_index: 0,
                    part_count: 1,
                },
            )),
            ..SafeHarnessContentRecord::default()
        };
        record.record_digest_sha256 = canonical_safe_record_digest(&record).expect("record digest");
        let record_bytes = record.encode_to_vec();
        edge.connection
            .execute(
                "INSERT INTO adapter_safe_content_ledger(
                   record_id, content_event_id, part_index, task_id,
                   record_digest_sha256, content_sequence, safe_record, created_at_seconds
                 ) VALUES(?1, ?2, 0, ?3, ?4, 1, ?5, 12)",
                params![
                    record.record_id,
                    record.content_event_id,
                    record.task_id,
                    record.record_digest_sha256,
                    record_bytes,
                ],
            )
            .expect("ledger fixture");
        let event = SafeHarnessContentProjectionEvent {
            payload: Some(
                safe_harness_content_projection_event::Payload::ContentRecord(record.clone()),
            ),
        };
        let payload = event.encode_to_vec();
        let message_id = format!("adapter-content-{}", record.record_id);
        let payload_digest = sha256(&payload);
        edge.connection
            .execute(
                "INSERT INTO adapter_content_projection_outbox(
                   message_id, source_record_id, source_revision, payload_digest_sha256,
                   payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, 1, ?3, ?4, 'pending', 12)",
                params![message_id, record.record_id, payload_digest, payload],
            )
            .expect("outbox fixture");
        assert_eq!(edge.pending_safe_content_projection().unwrap().len(), 1);

        edge.connection
            .execute(
                "UPDATE adapter_content_projection_outbox SET payload = ?1 WHERE message_id = ?2",
                params![b"tampered-payload".as_slice(), message_id],
            )
            .expect("tamper payload");
        assert!(matches!(
            edge.pending_safe_content_projection(),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
        assert!(matches!(
            edge.acknowledge_safe_content_projection(&message_id, &payload_digest),
            Err(AdapterEdgeError::IntegrityFailure)
        ));
        let state: String = edge
            .connection
            .query_row(
                "SELECT delivery_state FROM adapter_content_projection_outbox WHERE message_id = ?1",
                [&message_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "pending");

        edge.connection
            .execute(
                "UPDATE adapter_content_projection_outbox SET payload = ?1 WHERE message_id = ?2",
                params![event.encode_to_vec(), message_id],
            )
            .expect("restore outbox payload");
        edge.connection
            .execute(
                "UPDATE adapter_safe_content_ledger SET safe_record = ?1 WHERE record_id = ?2",
                params![b"tampered-ledger".as_slice(), record.record_id],
            )
            .expect("tamper ledger");
        assert!(matches!(
            edge.pending_safe_content_projection(),
            Err(AdapterEdgeError::Decode(_)) | Err(AdapterEdgeError::IntegrityFailure)
        ));
        assert!(matches!(
            edge.acknowledge_safe_content_projection(&message_id, &payload_digest),
            Err(AdapterEdgeError::Decode(_)) | Err(AdapterEdgeError::IntegrityFailure)
        ));
    }
}
