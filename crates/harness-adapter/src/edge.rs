use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DeliveryDisposition, DispatchEnvelope, DispatchReceipt, HarnessObservation,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterEdgeInspection {
    pub dispatch_count: u64,
    pub delivery_unknown_count: u64,
    pub observation_count: u64,
    pub pending_observation_count: u64,
    pub quarantine_count: u64,
    pub cancellation_count: u64,
    pub approval_count: u64,
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
        Migrations::new(vec![M::up(SCHEMA_V1)]).to_latest(&mut connection)?;

        let schema_digest = sha256(SCHEMA_V1.as_bytes());
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
        mut observation: HarnessObservation,
        now_seconds: i64,
    ) -> Result<ObservationAppend, AdapterEdgeError> {
        let digest = sha256(raw_event);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
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
        AdapterEdge::open(AdapterEdgeConfig {
            database_path: path.to_owned(),
            adapter_id: "adapter:test".to_owned(),
            store_epoch: "adapter-edge-test-v1".to_owned(),
            key: AdapterEdgeKey::new([0x7a; 32]),
        })
        .expect("open adapter edge")
    }

    fn dispatch() -> DispatchEnvelope {
        DispatchEnvelope {
            dispatch_id: "dispatch-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
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
        HarnessObservation {
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
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
}
