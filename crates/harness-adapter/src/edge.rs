use crate::runtime::TerminalOutputCandidate;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionReceipt, CancelExecutionReceipt, DeliveryDisposition, DispatchEnvelope,
    DispatchReceipt, HarnessObservation, LifecycleKind, ObservationCriticality,
    harness_observation,
};
use prost::Message;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

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

/// QR-04 durable attempt-output budget. Oversized output keeps a bounded
/// preview plus the digest and original byte count; it is never presented as
/// a complete Artifact candidate.
const TERMINAL_OUTPUT_FULL_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_OUTPUT_PREVIEW_BYTES: usize = 64 * 1024;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationAppend {
    Committed(HarnessObservation),
    Replay(HarnessObservation),
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
    pub next_observation_sequence: u64,
}

pub struct AdapterEdge {
    connection: Connection,
    adapter_id: String,
}

impl AdapterEdge {
    pub fn open(config: AdapterEdgeConfig) -> Result<Self, AdapterEdgeError> {
        if config.adapter_id.trim().is_empty() || config.store_epoch.trim().is_empty() {
            return Err(AdapterEdgeError::StoreGenerationMismatch);
        }
        if let Some(parent) = config.database_path.parent() {
            fs::create_dir_all(parent).map_err(AdapterEdgeError::Directory)?;
        }
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
        Migrations::new(vec![M::up(SCHEMA_V1), M::up(SCHEMA_V2), M::up(SCHEMA_V3)])
            .to_latest(&mut connection)?;

        backfill_approval_projection_outbox(&mut connection)?;
        let schema_digest = sha256(format!("{SCHEMA_V1}\n{SCHEMA_V2}\n{SCHEMA_V3}").as_bytes());
        let prior_v2_schema_digest = sha256(format!("{SCHEMA_V1}\n{SCHEMA_V2}").as_bytes());
        let prior_v1_schema_digest = sha256(SCHEMA_V1.as_bytes());
        connection.execute(
            "UPDATE adapter_edge_metadata SET schema_profile_sha256 = ?1
             WHERE singleton = 1 AND schema_profile_id = ?2
               AND schema_profile_sha256 IN (?3, ?4)",
            params![
                schema_digest,
                SCHEMA_PROFILE_ID,
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
        })
    }

    pub fn prepare_dispatch(
        &mut self,
        envelope: &DispatchEnvelope,
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
        self.connection.execute(
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
        Ok(DispatchPreparation::Ready)
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
        let receipt: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM adapter_dispatches WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        let receipt = DispatchReceipt::decode(receipt.as_slice())?;
        let mut session_ref = receipt.native_session_ref;
        let mut execution_ref = receipt.native_execution_ref;
        let mut statement = self.connection.prepare(
            "SELECT observation FROM adapter_observations
             WHERE dispatch_id = ?1 ORDER BY observation_sequence DESC",
        )?;
        let rows = statement.query_map([dispatch_id], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let observation = HarnessObservation::decode(row?.as_slice())?;
            if let Some(harness_observation::Payload::Ack(ack)) = observation.payload {
                session_ref = ack.native_session_ref.or(session_ref);
                execution_ref = ack.native_execution_ref.or(execution_ref);
                if session_ref.is_some() && execution_ref.is_some() {
                    break;
                }
            }
        }
        Ok(match (session_ref, execution_ref) {
            (Some(native_session_ref), Some(native_execution_ref)) => {
                Some(NativeExecutionBinding {
                    attempt_id: receipt.attempt_id,
                    dispatch_id: receipt.dispatch_id,
                    fencing_token: receipt.fencing_token,
                    native_session_ref,
                    native_execution_ref,
                })
            }
            _ => None,
        })
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

    pub fn dispatch_envelope(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchEnvelope>, AdapterEdgeError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT envelope FROM adapter_dispatches WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|value| DispatchEnvelope::decode(value.as_slice()).map_err(Into::into))
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
            next_observation_sequence: next as u64,
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
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation,
        DiagnosticObservation, HarnessObservation, ObservationCriticality, harness_observation,
    };
    use std::path::Path;
    use std::process::Command;

    const ABORT_HELPER_ENV: &str = "EGOPULSE_ADAPTER_EDGE_ABORT_HELPER";
    const ABORT_PATH_ENV: &str = "EGOPULSE_ADAPTER_EDGE_ABORT_PATH";

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
}
