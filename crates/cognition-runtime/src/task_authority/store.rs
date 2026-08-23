use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/task-authority-store/v1";

const SCHEMA_V1: &str = r#"
CREATE TABLE task_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_committed_revision INTEGER NOT NULL DEFAULT 0,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  work_revision INTEGER NOT NULL CHECK (work_revision >= 1),
  status INTEGER NOT NULL,
  snapshot BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE task_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  task_id TEXT NOT NULL,
  resulting_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL,
  FOREIGN KEY (task_id) REFERENCES tasks(task_id)
) STRICT;

CREATE TABLE task_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  task_id TEXT NOT NULL,
  task_revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (
    authenticated_principal_id,
    operation,
    idempotency_scope,
    idempotency_key
  ),
  FOREIGN KEY (task_id) REFERENCES tasks(task_id),
  FOREIGN KEY (event_id) REFERENCES task_events(event_id)
) STRICT;

CREATE TABLE task_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL UNIQUE,
  source_revision INTEGER NOT NULL,
  destination_domain TEXT NOT NULL,
  canonical_payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'delivered', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (source_event_id) REFERENCES task_events(event_id)
) STRICT;

CREATE TABLE task_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  outbox_message_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES task_events(event_id),
  FOREIGN KEY (outbox_message_id) REFERENCES task_outbox(message_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("task authority storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("task authority migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("task authority store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("task authority SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("task authority store metadata does not match the active generation")]
    StoreGenerationMismatch,
    #[error("task authority store integrity check failed")]
    IntegrityFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub task_revision: u64,
    pub result: Vec<u8>,
}

pub(super) struct CreateCommit<'a> {
    pub task_id: &'a str,
    pub revision: u64,
    pub work_revision: u64,
    pub status: i32,
    pub snapshot: &'a [u8],
    pub created_at_seconds: i64,
    pub event_id: &'a str,
    pub command_id: &'a str,
    pub request_digest_sha256: &'a str,
    pub event: &'a [u8],
    pub authenticated_principal_id: &'a str,
    pub operation: &'a str,
    pub idempotency_scope: &'a str,
    pub idempotency_key: &'a str,
    pub result: &'a [u8],
    pub outbox_message_id: &'a str,
    pub outbox_payload_digest_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskStoreInspection {
    pub task_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub commit_receipt_count: u64,
    pub last_committed_revision: u64,
    pub last_event_sequence: u64,
}

pub(super) struct TaskStore {
    connection: Connection,
    store_epoch: String,
}

impl TaskStore {
    pub fn open(path: &Path, key: &[u8; 32], store_epoch: &str) -> Result<Self, StoreError> {
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

        let migrations = Migrations::new(vec![M::up(SCHEMA_V1)]);
        migrations.to_latest(&mut connection)?;

        let schema_digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO task_store_metadata(
               singleton, store_epoch, schema_profile_id, schema_profile_sha256
             ) VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;

        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM task_store_metadata WHERE singleton = 1",
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

        Ok(Self {
            connection,
            store_epoch: store_epoch.to_owned(),
        })
    }

    pub fn idempotency_record(
        &self,
        principal_id: &str,
        operation: &str,
        scope: &str,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT request_digest_sha256, task_revision, result
                 FROM task_idempotency_results
                 WHERE authenticated_principal_id = ?1
                   AND operation = ?2
                   AND idempotency_scope = ?3
                   AND idempotency_key = ?4",
                params![principal_id, operation, scope, key],
                |row| {
                    let revision: i64 = row.get(1)?;
                    Ok(IdempotencyRecord {
                        request_digest_sha256: row.get(0)?,
                        task_revision: revision as u64,
                        result: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn task_snapshot(&self, task_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.connection
            .query_row(
                "SELECT snapshot FROM tasks WHERE task_id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn current_revision(&self, task_id: &str) -> Result<Option<u64>, StoreError> {
        self.connection
            .query_row(
                "SELECT revision FROM tasks WHERE task_id = ?1",
                [task_id],
                |row| {
                    let revision: i64 = row.get(0)?;
                    Ok(revision as u64)
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn commit_create(&mut self, commit: &CreateCommit<'_>) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO tasks(
               task_id, revision, work_revision, status, snapshot,
               created_at_seconds, updated_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                commit.task_id,
                commit.revision as i64,
                commit.work_revision as i64,
                commit.status,
                commit.snapshot,
                commit.created_at_seconds
            ],
        )?;
        transaction.execute(
            "INSERT INTO task_events(
               event_id, command_id, task_id, resulting_revision,
               request_digest_sha256, event
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                commit.event_id,
                commit.command_id,
                commit.task_id,
                commit.revision as i64,
                commit.request_digest_sha256,
                commit.event
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO task_idempotency_results(
               authenticated_principal_id, operation, idempotency_scope,
               idempotency_key, request_digest_sha256, task_id, task_revision,
               event_id, result
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.authenticated_principal_id,
                commit.operation,
                commit.idempotency_scope,
                commit.idempotency_key,
                commit.request_digest_sha256,
                commit.task_id,
                commit.revision as i64,
                commit.event_id,
                commit.result
            ],
        )?;
        transaction.execute(
            "INSERT INTO task_outbox(
               message_id, source_event_id, source_revision, destination_domain,
               canonical_payload_digest_sha256, payload, delivery_state,
               created_at_seconds
             ) VALUES(?1, ?2, ?3, 'local-read-model', ?4, ?5, 'pending', ?6)",
            params![
                commit.outbox_message_id,
                commit.event_id,
                commit.revision as i64,
                commit.outbox_payload_digest_sha256,
                commit.event,
                commit.created_at_seconds
            ],
        )?;
        transaction.execute(
            "INSERT INTO task_commit_receipts(
               event_id, aggregate_id, aggregate_revision, outbox_message_id,
               idempotency_key, request_digest_sha256, store_epoch,
               acknowledged_after_durability_barrier, committed_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            params![
                commit.event_id,
                commit.task_id,
                commit.revision as i64,
                commit.outbox_message_id,
                commit.idempotency_key,
                commit.request_digest_sha256,
                self.store_epoch,
                commit.created_at_seconds
            ],
        )?;
        transaction.execute(
            "UPDATE task_store_metadata
             SET last_committed_revision = ?1, last_event_sequence = ?2
             WHERE singleton = 1",
            params![event_sequence, event_sequence],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn inspect(&self) -> Result<TaskStoreInspection, StoreError> {
        let scalar = |sql: &str| -> Result<u64, StoreError> {
            let value: i64 = self.connection.query_row(sql, [], |row| row.get(0))?;
            Ok(value as u64)
        };
        let (last_revision, last_sequence): (i64, i64) = self.connection.query_row(
            "SELECT last_committed_revision, last_event_sequence
             FROM task_store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(TaskStoreInspection {
            task_count: scalar("SELECT count(*) FROM tasks")?,
            event_count: scalar("SELECT count(*) FROM task_events")?,
            idempotency_count: scalar("SELECT count(*) FROM task_idempotency_results")?,
            outbox_count: scalar("SELECT count(*) FROM task_outbox")?,
            commit_receipt_count: scalar("SELECT count(*) FROM task_commit_receipts")?,
            last_committed_revision: last_revision as u64,
            last_event_sequence: last_sequence as u64,
        })
    }

    pub fn integrity_is_ok(&self) -> Result<bool, StoreError> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(integrity == "ok")
    }
}
