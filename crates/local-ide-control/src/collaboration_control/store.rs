use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/collaboration-control-store/v1";

const SCHEMA_V1: &str = r#"
CREATE TABLE collaboration_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_committed_revision INTEGER NOT NULL DEFAULT 0,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE collaboration_runs (
  run_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  task_id TEXT NOT NULL,
  work_revision INTEGER NOT NULL CHECK (work_revision >= 1),
  status INTEGER NOT NULL,
  snapshot BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE collaboration_steps (
  step_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  snapshot BLOB NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (run_id) REFERENCES collaboration_runs(run_id)
) STRICT;

CREATE TABLE collaboration_attempts (
  attempt_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  snapshot BLOB NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (run_id) REFERENCES collaboration_runs(run_id),
  FOREIGN KEY (step_id) REFERENCES collaboration_steps(step_id)
) STRICT;

CREATE TABLE collaboration_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  run_id TEXT NOT NULL,
  resulting_run_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL,
  FOREIGN KEY (run_id) REFERENCES collaboration_runs(run_id)
) STRICT;

CREATE TABLE collaboration_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  run_id TEXT NOT NULL,
  run_revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (
    authenticated_principal_id,
    operation,
    idempotency_scope,
    idempotency_key
  ),
  FOREIGN KEY (run_id) REFERENCES collaboration_runs(run_id),
  FOREIGN KEY (event_id) REFERENCES collaboration_events(event_id)
) STRICT;

CREATE TABLE collaboration_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL,
  attempt_id TEXT,
  destination_domain TEXT NOT NULL,
  payload_kind TEXT NOT NULL,
  canonical_payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'delivered', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain, payload_kind),
  FOREIGN KEY (source_event_id) REFERENCES collaboration_events(event_id)
) STRICT;

CREATE TABLE collaboration_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES collaboration_events(event_id)
) STRICT;

CREATE TABLE collaboration_commit_outboxes (
  event_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  PRIMARY KEY (event_id, message_id),
  UNIQUE(event_id, ordinal),
  FOREIGN KEY (event_id) REFERENCES collaboration_commit_receipts(event_id),
  FOREIGN KEY (message_id) REFERENCES collaboration_outbox(message_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("collaboration control storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("collaboration control migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("collaboration control store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("collaboration control SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("collaboration control store metadata does not match the active generation")]
    StoreGenerationMismatch,
    #[error("collaboration control store integrity check failed")]
    IntegrityFailure,
    #[error("collaboration control compare-and-swap failed for {0}")]
    CasConflict(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub run_revision: u64,
    pub result: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct SnapshotBlobs {
    pub run: Vec<u8>,
    pub steps: Vec<Vec<u8>>,
    pub attempts: Vec<Vec<u8>>,
}

pub(super) struct RunWrite {
    pub run_id: String,
    pub task_id: String,
    pub work_revision: u64,
    pub revision: u64,
    pub status: i32,
    pub snapshot: Vec<u8>,
    pub expected_revision: Option<u64>,
}

pub(super) struct StepWrite {
    pub step_id: String,
    pub run_id: String,
    pub revision: u64,
    pub status: i32,
    pub snapshot: Vec<u8>,
    pub expected_revision: Option<u64>,
}

pub(super) struct AttemptWrite {
    pub attempt_id: String,
    pub run_id: String,
    pub step_id: String,
    pub revision: u64,
    pub status: i32,
    pub snapshot: Vec<u8>,
    pub expected_revision: Option<u64>,
}

pub(super) struct OutboxWrite {
    pub message_id: String,
    pub attempt_id: Option<String>,
    pub destination_domain: String,
    pub payload_kind: String,
    pub canonical_payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(super) struct CollaborationCommit {
    pub run: RunWrite,
    pub step: Option<StepWrite>,
    pub attempt: Option<AttemptWrite>,
    pub event_id: String,
    pub command_id: String,
    pub request_digest_sha256: String,
    pub event: Vec<u8>,
    pub authenticated_principal_id: String,
    pub operation: String,
    pub idempotency_scope: String,
    pub idempotency_key: String,
    pub result: Vec<u8>,
    pub outboxes: Vec<OutboxWrite>,
    pub hold_dispatch_for_attempt: Option<String>,
    pub deliver_dispatch_for_attempt: Option<String>,
    pub committed_at_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollaborationStoreInspection {
    pub run_count: u64,
    pub step_count: u64,
    pub attempt_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub pending_dispatch_count: u64,
    pub commit_receipt_count: u64,
    pub last_committed_revision: u64,
    pub last_event_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingDispatchRecord {
    pub message_id: String,
    pub source_event_id: String,
    pub canonical_payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(super) struct CollaborationStore {
    connection: Connection,
    store_epoch: String,
}

impl CollaborationStore {
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

        Migrations::new(vec![M::up(SCHEMA_V1)]).to_latest(&mut connection)?;

        let schema_digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO collaboration_store_metadata(
               singleton, store_epoch, schema_profile_id, schema_profile_sha256
             ) VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM collaboration_store_metadata WHERE singleton = 1",
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
                "SELECT request_digest_sha256, run_revision, result
                 FROM collaboration_idempotency_results
                 WHERE authenticated_principal_id = ?1
                   AND operation = ?2
                   AND idempotency_scope = ?3
                   AND idempotency_key = ?4",
                params![principal_id, operation, scope, key],
                |row| {
                    let revision: i64 = row.get(1)?;
                    Ok(IdempotencyRecord {
                        request_digest_sha256: row.get(0)?,
                        run_revision: revision as u64,
                        result: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn snapshot_blobs(&self, run_id: &str) -> Result<Option<SnapshotBlobs>, StoreError> {
        let run = self
            .connection
            .query_row(
                "SELECT snapshot FROM collaboration_runs WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(run) = run else {
            return Ok(None);
        };

        let mut step_statement = self.connection.prepare(
            "SELECT snapshot FROM collaboration_steps WHERE run_id = ?1 ORDER BY step_id",
        )?;
        let steps = step_statement
            .query_map([run_id], |row| row.get(0))?
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        let mut attempt_statement = self.connection.prepare(
            "SELECT snapshot FROM collaboration_attempts WHERE run_id = ?1
             ORDER BY step_id, attempt_id",
        )?;
        let attempts = attempt_statement
            .query_map([run_id], |row| row.get(0))?
            .collect::<Result<Vec<Vec<u8>>, _>>()?;
        Ok(Some(SnapshotBlobs {
            run,
            steps,
            attempts,
        }))
    }

    pub fn commit(&mut self, commit: &CollaborationCommit) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        match commit.run.expected_revision {
            None => {
                transaction.execute(
                    "INSERT INTO collaboration_runs(
                       run_id, revision, task_id, work_revision, status, snapshot,
                       created_at_seconds, updated_at_seconds
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                    params![
                        commit.run.run_id,
                        commit.run.revision as i64,
                        commit.run.task_id,
                        commit.run.work_revision as i64,
                        commit.run.status,
                        commit.run.snapshot,
                        commit.committed_at_seconds
                    ],
                )?;
            }
            Some(expected) => {
                let changed = transaction.execute(
                    "UPDATE collaboration_runs
                     SET revision = ?1, status = ?2, snapshot = ?3, updated_at_seconds = ?4
                     WHERE run_id = ?5 AND revision = ?6",
                    params![
                        commit.run.revision as i64,
                        commit.run.status,
                        commit.run.snapshot,
                        commit.committed_at_seconds,
                        commit.run.run_id,
                        expected as i64
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::CasConflict("run"));
                }
            }
        }

        if let Some(step) = &commit.step {
            match step.expected_revision {
                None => {
                    transaction.execute(
                        "INSERT INTO collaboration_steps(
                           step_id, run_id, revision, status, snapshot, updated_at_seconds
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            step.step_id,
                            step.run_id,
                            step.revision as i64,
                            step.status,
                            step.snapshot,
                            commit.committed_at_seconds
                        ],
                    )?;
                }
                Some(expected) => {
                    let changed = transaction.execute(
                        "UPDATE collaboration_steps
                         SET revision = ?1, status = ?2, snapshot = ?3, updated_at_seconds = ?4
                         WHERE step_id = ?5 AND run_id = ?6 AND revision = ?7",
                        params![
                            step.revision as i64,
                            step.status,
                            step.snapshot,
                            commit.committed_at_seconds,
                            step.step_id,
                            step.run_id,
                            expected as i64
                        ],
                    )?;
                    if changed != 1 {
                        return Err(StoreError::CasConflict("step"));
                    }
                }
            }
        }

        if let Some(attempt) = &commit.attempt {
            match attempt.expected_revision {
                None => {
                    transaction.execute(
                        "INSERT INTO collaboration_attempts(
                           attempt_id, run_id, step_id, revision, status, snapshot,
                           updated_at_seconds
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            attempt.attempt_id,
                            attempt.run_id,
                            attempt.step_id,
                            attempt.revision as i64,
                            attempt.status,
                            attempt.snapshot,
                            commit.committed_at_seconds
                        ],
                    )?;
                }
                Some(expected) => {
                    let changed = transaction.execute(
                        "UPDATE collaboration_attempts
                         SET revision = ?1, status = ?2, snapshot = ?3, updated_at_seconds = ?4
                         WHERE attempt_id = ?5 AND run_id = ?6 AND step_id = ?7 AND revision = ?8",
                        params![
                            attempt.revision as i64,
                            attempt.status,
                            attempt.snapshot,
                            commit.committed_at_seconds,
                            attempt.attempt_id,
                            attempt.run_id,
                            attempt.step_id,
                            expected as i64
                        ],
                    )?;
                    if changed != 1 {
                        return Err(StoreError::CasConflict("attempt"));
                    }
                }
            }
        }

        transaction.execute(
            "INSERT INTO collaboration_events(
               event_id, command_id, run_id, resulting_run_revision,
               request_digest_sha256, event
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                commit.event_id,
                commit.command_id,
                commit.run.run_id,
                commit.run.revision as i64,
                commit.request_digest_sha256,
                commit.event
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO collaboration_idempotency_results(
               authenticated_principal_id, operation, idempotency_scope,
               idempotency_key, request_digest_sha256, run_id, run_revision,
               event_id, result
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.authenticated_principal_id,
                commit.operation,
                commit.idempotency_scope,
                commit.idempotency_key,
                commit.request_digest_sha256,
                commit.run.run_id,
                commit.run.revision as i64,
                commit.event_id,
                commit.result
            ],
        )?;

        if let Some(attempt_id) = &commit.hold_dispatch_for_attempt {
            transaction.execute(
                "UPDATE collaboration_outbox
                 SET delivery_state = 'held'
                 WHERE attempt_id = ?1
                   AND destination_domain = 'harness-adapter'
                   AND payload_kind = 'dispatch-envelope'
                   AND delivery_state = 'pending'",
                [attempt_id],
            )?;
        }

        if let Some(attempt_id) = &commit.deliver_dispatch_for_attempt {
            let changed = transaction.execute(
                "UPDATE collaboration_outbox
                 SET delivery_state = 'delivered'
                 WHERE attempt_id = ?1
                   AND destination_domain = 'harness-adapter'
                   AND payload_kind = 'dispatch-envelope'
                   AND delivery_state = 'pending'",
                [attempt_id],
            )?;
            if changed != 1 {
                return Err(StoreError::CasConflict("dispatch-outbox"));
            }
        }

        for outbox in &commit.outboxes {
            transaction.execute(
                "INSERT INTO collaboration_outbox(
                   message_id, source_event_id, source_revision, attempt_id,
                   destination_domain, payload_kind, canonical_payload_digest_sha256,
                   payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9)",
                params![
                    outbox.message_id,
                    commit.event_id,
                    commit.run.revision as i64,
                    outbox.attempt_id,
                    outbox.destination_domain,
                    outbox.payload_kind,
                    outbox.canonical_payload_digest_sha256,
                    outbox.payload,
                    commit.committed_at_seconds
                ],
            )?;
        }

        transaction.execute(
            "INSERT INTO collaboration_commit_receipts(
               event_id, aggregate_id, aggregate_revision, idempotency_key,
               request_digest_sha256, store_epoch,
               acknowledged_after_durability_barrier, committed_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                commit.event_id,
                commit.run.run_id,
                commit.run.revision as i64,
                commit.idempotency_key,
                commit.request_digest_sha256,
                self.store_epoch,
                commit.committed_at_seconds
            ],
        )?;
        for (ordinal, outbox) in commit.outboxes.iter().enumerate() {
            transaction.execute(
                "INSERT INTO collaboration_commit_outboxes(event_id, message_id, ordinal)
                 VALUES(?1, ?2, ?3)",
                params![commit.event_id, outbox.message_id, ordinal as i64],
            )?;
        }
        transaction.execute(
            "UPDATE collaboration_store_metadata
             SET last_committed_revision = ?1, last_event_sequence = ?1
             WHERE singleton = 1",
            [event_sequence],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn pending_dispatches(&self) -> Result<Vec<PendingDispatchRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT message_id, source_event_id, canonical_payload_digest_sha256, payload
             FROM collaboration_outbox
             WHERE destination_domain = 'harness-adapter'
               AND payload_kind = 'dispatch-envelope'
               AND delivery_state = 'pending'
             ORDER BY rowid",
        )?;
        statement
            .query_map([], |row| {
                Ok(PendingDispatchRecord {
                    message_id: row.get(0)?,
                    source_event_id: row.get(1)?,
                    canonical_payload_digest_sha256: row.get(2)?,
                    payload: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn inspect(&self) -> Result<CollaborationStoreInspection, StoreError> {
        let scalar = |sql: &str| -> Result<u64, StoreError> {
            let value: i64 = self.connection.query_row(sql, [], |row| row.get(0))?;
            Ok(value as u64)
        };
        let (last_revision, last_sequence): (i64, i64) = self.connection.query_row(
            "SELECT last_committed_revision, last_event_sequence
             FROM collaboration_store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(CollaborationStoreInspection {
            run_count: scalar("SELECT count(*) FROM collaboration_runs")?,
            step_count: scalar("SELECT count(*) FROM collaboration_steps")?,
            attempt_count: scalar("SELECT count(*) FROM collaboration_attempts")?,
            event_count: scalar("SELECT count(*) FROM collaboration_events")?,
            idempotency_count: scalar("SELECT count(*) FROM collaboration_idempotency_results")?,
            outbox_count: scalar("SELECT count(*) FROM collaboration_outbox")?,
            pending_dispatch_count: scalar(
                "SELECT count(*) FROM collaboration_outbox
                 WHERE destination_domain = 'harness-adapter'
                   AND payload_kind = 'dispatch-envelope'
                   AND delivery_state = 'pending'",
            )?,
            commit_receipt_count: scalar("SELECT count(*) FROM collaboration_commit_receipts")?,
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
