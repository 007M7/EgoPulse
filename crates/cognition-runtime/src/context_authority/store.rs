use super::{ContextSnapshot, ContextStoreInspection, MemoryUseReceipt};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/context-authority-store/v1";
const LEGACY_SCHEMA: &str = r#"
CREATE TABLE context_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE context_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  descriptor TEXT NOT NULL,
  compiled_context BLOB NOT NULL,
  compiled_context_sha256 TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('issued', 'revoked')),
  expires_at_seconds INTEGER NOT NULL,
  created_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE context_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  snapshot_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (snapshot_id) REFERENCES context_snapshots(snapshot_id)
) STRICT;

CREATE TABLE context_idempotency_results (
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  snapshot_revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  PRIMARY KEY (principal_id, idempotency_key),
  FOREIGN KEY (snapshot_id) REFERENCES context_snapshots(snapshot_id),
  FOREIGN KEY (event_id) REFERENCES context_events(event_id)
) STRICT;
"#;

const MEMORY_USE_SCHEMA: &str = r#"

CREATE TABLE context_memory_use_receipts (
  receipt_id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  snapshot_revision INTEGER NOT NULL,
  consumer_principal_id TEXT NOT NULL,
  model_ref TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL,
  memory_authority_revision INTEGER NOT NULL,
  memory_pack_snapshot_sha256 TEXT NOT NULL,
  committed_at_seconds INTEGER NOT NULL,
  UNIQUE(snapshot_id, model_ref, attempt_id, dispatch_id),
  FOREIGN KEY (snapshot_id) REFERENCES context_snapshots(snapshot_id)
) STRICT;

CREATE TABLE context_memory_use_idempotency (
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  PRIMARY KEY (principal_id, idempotency_key),
  FOREIGN KEY (receipt_id) REFERENCES context_memory_use_receipts(receipt_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("context authority SQL operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("context authority migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("context authority store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("context authority SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("context authority store metadata does not match the active generation")]
    StoreGenerationMismatch,
    #[error("context authority store integrity check failed")]
    IntegrityFailure,
    #[error("context snapshot descriptor could not be decoded")]
    DescriptorDecode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub snapshot_id: String,
    pub revision: u64,
    pub event_id: String,
}

pub(super) struct StoredSnapshot {
    pub(super) snapshot: ContextSnapshot,
    pub(super) compiled_context: Vec<u8>,
    pub(super) state: String,
}

pub(super) struct ContextInsert<'a> {
    pub(super) snapshot: &'a ContextSnapshot,
    pub(super) compiled_context: &'a [u8],
    pub(super) event_id: &'a str,
    pub(super) principal_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) request_digest_sha256: &'a str,
    pub(super) committed_at_seconds: i64,
}

pub(super) struct ContextStore {
    connection: Connection,
}

impl ContextStore {
    pub(super) fn open(path: &Path, key: &[u8; 32], store_epoch: &str) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StoreError::Directory)?;
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
        let cipher_version: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_| StoreError::CipherUnavailable)?;
        if cipher_version.trim().is_empty() {
            return Err(StoreError::CipherUnavailable);
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        Migrations::new(vec![M::up(LEGACY_SCHEMA), M::up(MEMORY_USE_SCHEMA)])
            .to_latest(&mut connection)?;
        let schema_digest = schema_digest();
        let legacy_schema_digest = hex::encode(Sha256::digest(LEGACY_SCHEMA.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO context_store_metadata(singleton, store_epoch, schema_profile_id, schema_profile_sha256)
             VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        connection.execute(
            "UPDATE context_store_metadata SET schema_profile_sha256=?1
             WHERE singleton=1 AND schema_profile_sha256=?2",
            params![schema_digest, legacy_schema_digest],
        )?;
        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM context_store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if metadata.0 != store_epoch
            || metadata.1 != SCHEMA_PROFILE_ID
            || metadata.2 != schema_digest
        {
            return Err(StoreError::StoreGenerationMismatch);
        }
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(StoreError::IntegrityFailure);
        }
        Ok(Self { connection })
    }

    pub(super) fn idempotency_record(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<IdempotencyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT request_digest_sha256, snapshot_id, snapshot_revision, event_id
                 FROM context_idempotency_results WHERE principal_id=?1 AND idempotency_key=?2",
                params![principal_id, idempotency_key],
                |row| {
                    Ok(IdempotencyRecord {
                        request_digest_sha256: row.get(0)?,
                        snapshot_id: row.get(1)?,
                        revision: row.get::<_, i64>(2)? as u64,
                        event_id: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<ContextSnapshot>, StoreError> {
        self.snapshot_with_bytes(snapshot_id)
            .map(|value| value.map(|stored| stored.snapshot))
    }

    pub(super) fn snapshot_with_bytes(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<StoredSnapshot>, StoreError> {
        self.connection
            .query_row(
                "SELECT descriptor, compiled_context, state FROM context_snapshots WHERE snapshot_id=?1",
                [snapshot_id],
                |row| {
                    let descriptor: String = row.get(0)?;
                    let snapshot = serde_json::from_str(&descriptor).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok(StoredSnapshot {
                        snapshot,
                        compiled_context: row.get(1)?,
                        state: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|error| match error {
                rusqlite::Error::InvalidQuery => StoreError::DescriptorDecode,
                other => StoreError::Sql(other),
            })
    }

    pub(super) fn issue_record(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<(u64, String)>, StoreError> {
        self.connection
            .query_row(
                "SELECT s.revision, e.event_id
                 FROM context_snapshots s
                 JOIN context_events e ON e.snapshot_id=s.snapshot_id
                 WHERE s.snapshot_id=?1 AND e.operation='issue'
                 ORDER BY e.sequence ASC LIMIT 1",
                [snapshot_id],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn bind_idempotency(
        &mut self,
        principal_id: &str,
        idempotency_key: &str,
        request_digest_sha256: &str,
        snapshot_id: &str,
        revision: u64,
        event_id: &str,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO context_idempotency_results(principal_id,idempotency_key,
             request_digest_sha256,snapshot_id,snapshot_revision,event_id)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                principal_id,
                idempotency_key,
                request_digest_sha256,
                snapshot_id,
                revision as i64,
                event_id,
            ],
        )?;
        Ok(())
    }

    pub(super) fn memory_use_idempotency_record(
        &self,
        principal_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        self.connection
            .query_row(
                "SELECT request_digest_sha256, receipt_id
                 FROM context_memory_use_idempotency
                 WHERE principal_id=?1 AND idempotency_key=?2",
                params![principal_id, idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn memory_use_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<MemoryUseReceipt>, StoreError> {
        self.connection
            .query_row(
                "SELECT receipt_id, snapshot_id, snapshot_revision,
                        consumer_principal_id, model_ref, attempt_id, dispatch_id,
                        memory_authority_revision, memory_pack_snapshot_sha256
                 FROM context_memory_use_receipts WHERE receipt_id=?1",
                [receipt_id],
                |row| {
                    Ok(MemoryUseReceipt {
                        receipt_id: row.get(0)?,
                        snapshot_id: row.get(1)?,
                        snapshot_revision: row.get::<_, i64>(2)? as u64,
                        consumer_principal_id: row.get(3)?,
                        model_ref: row.get(4)?,
                        attempt_id: row.get(5)?,
                        dispatch_id: row.get(6)?,
                        memory_authority_revision: row.get::<_, i64>(7)? as u64,
                        memory_pack_snapshot_sha256: row.get(8)?,
                        request_digest_sha256: String::new(),
                        replayed: false,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn memory_use_receipt_by_tuple(
        &self,
        snapshot_id: &str,
        model_ref: &str,
        attempt_id: &str,
        dispatch_id: &str,
    ) -> Result<Option<MemoryUseReceipt>, StoreError> {
        let receipt_id: Option<String> = self
            .connection
            .query_row(
                "SELECT receipt_id FROM context_memory_use_receipts
                 WHERE snapshot_id=?1 AND model_ref=?2 AND attempt_id=?3 AND dispatch_id=?4",
                params![snapshot_id, model_ref, attempt_id, dispatch_id],
                |row| row.get(0),
            )
            .optional()?;
        receipt_id
            .map(|value| self.memory_use_receipt(&value))
            .transpose()
            .map(|value| value.flatten())
    }

    pub(super) fn bind_memory_use_idempotency(
        &mut self,
        principal_id: &str,
        idempotency_key: &str,
        request_digest_sha256: &str,
        receipt_id: &str,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO context_memory_use_idempotency(
             principal_id,idempotency_key,request_digest_sha256,receipt_id)
             VALUES(?1,?2,?3,?4)",
            params![
                principal_id,
                idempotency_key,
                request_digest_sha256,
                receipt_id
            ],
        )?;
        Ok(())
    }

    pub(super) fn insert_memory_use_receipt(
        &mut self,
        receipt: &MemoryUseReceipt,
        principal_id: &str,
        idempotency_key: &str,
        committed_at_seconds: i64,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO context_memory_use_receipts(
             receipt_id,snapshot_id,snapshot_revision,consumer_principal_id,model_ref,
             attempt_id,dispatch_id,memory_authority_revision,memory_pack_snapshot_sha256,
             committed_at_seconds)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                receipt.receipt_id,
                receipt.snapshot_id,
                receipt.snapshot_revision as i64,
                receipt.consumer_principal_id,
                receipt.model_ref,
                receipt.attempt_id,
                receipt.dispatch_id,
                receipt.memory_authority_revision as i64,
                receipt.memory_pack_snapshot_sha256,
                committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_memory_use_idempotency(
             principal_id,idempotency_key,request_digest_sha256,receipt_id)
             VALUES(?1,?2,?3,?4)",
            params![
                principal_id,
                idempotency_key,
                receipt.request_digest_sha256,
                receipt.receipt_id,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn insert(&mut self, input: ContextInsert<'_>) -> Result<(), StoreError> {
        let descriptor =
            serde_json::to_string(input.snapshot).map_err(|_| StoreError::DescriptorDecode)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO context_snapshots(snapshot_id, revision, descriptor, compiled_context,
             compiled_context_sha256, state, expires_at_seconds, created_at_seconds)
             VALUES(?1,?2,?3,?4,?5,'issued',?6,?7)",
            params![
                input.snapshot.snapshot_id,
                input.snapshot.revision as i64,
                descriptor,
                input.compiled_context,
                input.snapshot.compiled_context_sha256,
                input.snapshot.expires_at_seconds,
                input.committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_events(event_id, snapshot_id, operation, principal_id,
             idempotency_key, request_digest_sha256, committed_at_seconds)
             VALUES(?1,?2,'issue',?3,?4,?5,?6)",
            params![
                input.event_id,
                input.snapshot.snapshot_id,
                input.principal_id,
                input.idempotency_key,
                input.request_digest_sha256,
                input.committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_idempotency_results(principal_id,idempotency_key,
             request_digest_sha256,snapshot_id,snapshot_revision,event_id)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                input.principal_id,
                input.idempotency_key,
                input.request_digest_sha256,
                input.snapshot.snapshot_id,
                input.snapshot.revision as i64,
                input.event_id,
            ],
        )?;
        transaction.execute(
            "UPDATE context_store_metadata SET last_event_sequence=last_insert_rowid()
             WHERE singleton=1",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn inspect(&self) -> Result<ContextStoreInspection, StoreError> {
        let scalar = |sql: &str| -> Result<u64, StoreError> {
            Ok(self
                .connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))? as u64)
        };
        let last_event_sequence = self.connection.query_row(
            "SELECT last_event_sequence FROM context_store_metadata WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )? as u64;
        Ok(ContextStoreInspection {
            snapshot_count: scalar("SELECT count(*) FROM context_snapshots")?,
            event_count: scalar("SELECT count(*) FROM context_events")?,
            idempotency_count: scalar("SELECT count(*) FROM context_idempotency_results")?,
            last_event_sequence,
        })
    }

    pub(super) fn integrity_is_ok(&self) -> Result<bool, StoreError> {
        let result: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result == "ok")
    }
}

fn schema_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_SCHEMA.as_bytes());
    hasher.update(MEMORY_USE_SCHEMA.as_bytes());
    hex::encode(hasher.finalize())
}
