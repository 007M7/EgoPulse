use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

use egopulse_domain_contracts::memory::{
    MEMORY_MAX_RECORDS, MEMORY_MAX_ROUTING_FIELD_BYTES, MEMORY_MAX_TOTAL_CONTENT_BYTES,
};

const SCHEMA_PROFILE_ID: &str = "egopulse/memory-authority-store/v1";
const SCHEMA: &str = r#"
CREATE TABLE memory_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE memories (
  memory_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  content TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  scope_ref TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('candidate', 'accepted', 'revoked')),
  created_at_seconds INTEGER NOT NULL,
  updated_at_seconds INTEGER NOT NULL
) STRICT;

CREATE TABLE memory_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  memory_id TEXT NOT NULL,
  resulting_revision INTEGER NOT NULL,
  operation TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  evidence_ref TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  resulting_state TEXT NOT NULL,
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (memory_id) REFERENCES memories(memory_id)
) STRICT;

CREATE TABLE memory_idempotency_results (
  principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  memory_id TEXT NOT NULL,
  memory_revision INTEGER NOT NULL,
  resulting_state TEXT NOT NULL,
  event_id TEXT NOT NULL,
  PRIMARY KEY (principal_id, operation, idempotency_key),
  FOREIGN KEY (memory_id) REFERENCES memories(memory_id),
  FOREIGN KEY (event_id) REFERENCES memory_events(event_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("memory authority storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("memory authority migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("memory authority store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("memory authority SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("memory authority store metadata does not match the active generation")]
    StoreGenerationMismatch,
    #[error("memory authority store integrity check failed")]
    IntegrityFailure,
    #[error("accepted memory snapshot exceeds the retrieval boundary")]
    SnapshotBounds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredState(String);

impl StoredState {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for StoredState {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredMemory {
    pub memory_id: String,
    pub revision: u64,
    pub content: String,
    pub content_sha256: String,
    pub source_ref: String,
    pub scope_ref: String,
    pub state: StoredState,
    pub created_at_seconds: i64,
    pub updated_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub memory_id: String,
    pub revision: u64,
    pub state: StoredState,
    pub event_id: String,
}

pub(super) struct EventCommit<'a> {
    pub memory: &'a StoredMemory,
    pub event_id: &'a str,
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub evidence_ref: &'a str,
    pub request_digest_sha256: &'a str,
}

pub(super) struct IdempotencyCommit<'a> {
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub idempotency_key: &'a str,
    pub request_digest_sha256: &'a str,
    pub memory_id: &'a str,
    pub revision: u64,
    pub state: &'a str,
    pub event_id: &'a str,
}

pub(super) struct TransitionCommit<'a> {
    pub current: &'a StoredMemory,
    pub next_state: &'a str,
    pub resulting_revision: u64,
    pub committed_at_seconds: i64,
    pub event_id: &'a str,
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub evidence_ref: &'a str,
    pub idempotency_key: &'a str,
    pub request_digest_sha256: &'a str,
}

pub(super) struct MemoryStore {
    connection: Connection,
}

impl MemoryStore {
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

        Migrations::new(vec![M::up(SCHEMA)]).to_latest(&mut connection)?;
        let schema_digest = hex::encode(Sha256::digest(SCHEMA.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO memory_store_metadata(
               singleton, store_epoch, schema_profile_id, schema_profile_sha256
             ) VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM memory_store_metadata WHERE singleton = 1",
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
        operation: &str,
        idempotency_key: &str,
    ) -> Result<Option<IdempotencyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT request_digest_sha256,memory_id,memory_revision,resulting_state,event_id
                 FROM memory_idempotency_results
                 WHERE principal_id=?1 AND operation=?2 AND idempotency_key=?3",
                params![principal_id, operation, idempotency_key],
                |row| {
                    let revision: i64 = row.get(2)?;
                    Ok(IdempotencyRecord {
                        request_digest_sha256: row.get(0)?,
                        memory_id: row.get(1)?,
                        revision: revision as u64,
                        state: StoredState::from(row.get::<_, String>(3)?.as_str()),
                        event_id: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn memory(&self, memory_id: &str) -> Result<Option<StoredMemory>, StoreError> {
        self.connection
            .query_row(
                "SELECT memory_id,revision,content,content_sha256,source_ref,scope_ref,state,
                        created_at_seconds,updated_at_seconds
                 FROM memories WHERE memory_id=?1",
                [memory_id],
                memory_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub(super) fn insert_candidate(
        &mut self,
        memory: &StoredMemory,
        event_id: &str,
        principal_id: &str,
        idempotency_key: &str,
        request_digest_sha256: &str,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO memories(memory_id,revision,content,content_sha256,source_ref,scope_ref,state,created_at_seconds,updated_at_seconds)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)",
            params![
                memory.memory_id,
                memory.revision as i64,
                memory.content,
                memory.content_sha256,
                memory.source_ref,
                memory.scope_ref,
                memory.state.as_str(),
                memory.created_at_seconds
            ],
        )?;
        let sequence = insert_event(
            &transaction,
            &EventCommit {
                memory,
                event_id,
                principal_id,
                operation: "submit-candidate",
                evidence_ref: "",
                request_digest_sha256,
            },
        )?;
        insert_idempotency(
            &transaction,
            &IdempotencyCommit {
                principal_id,
                operation: "submit-candidate",
                idempotency_key,
                request_digest_sha256,
                memory_id: &memory.memory_id,
                revision: memory.revision,
                state: memory.state.as_str(),
                event_id,
            },
        )?;
        update_sequence(&transaction, sequence)?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn transition(&mut self, commit: &TransitionCommit<'_>) -> Result<bool, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE memories SET revision=?2,state=?3,updated_at_seconds=?4
             WHERE memory_id=?1 AND revision=?5 AND state=?6",
            params![
                commit.current.memory_id,
                commit.resulting_revision as i64,
                commit.next_state,
                commit.committed_at_seconds,
                commit.current.revision as i64,
                commit.current.state.as_str()
            ],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let mut resulting = commit.current.clone();
        resulting.revision = commit.resulting_revision;
        resulting.state = StoredState::from(commit.next_state);
        resulting.updated_at_seconds = commit.committed_at_seconds;
        let sequence = insert_event(
            &transaction,
            &EventCommit {
                memory: &resulting,
                event_id: commit.event_id,
                principal_id: commit.principal_id,
                operation: commit.operation,
                evidence_ref: commit.evidence_ref,
                request_digest_sha256: commit.request_digest_sha256,
            },
        )?;
        insert_idempotency(
            &transaction,
            &IdempotencyCommit {
                principal_id: commit.principal_id,
                operation: commit.operation,
                idempotency_key: commit.idempotency_key,
                request_digest_sha256: commit.request_digest_sha256,
                memory_id: &commit.current.memory_id,
                revision: commit.resulting_revision,
                state: commit.next_state,
                event_id: commit.event_id,
            },
        )?;
        update_sequence(&transaction, sequence)?;
        transaction.commit()?;
        Ok(true)
    }

    pub(super) fn accepted_memories(
        &self,
        scope_ref: &str,
    ) -> Result<Vec<StoredMemory>, StoreError> {
        let bounds: (i64, i64, i64, i64, i64) = self.connection.query_row(
            "SELECT count(*),
                    COALESCE(sum(length(CAST(content AS BLOB))), 0),
                    COALESCE(max(length(CAST(memory_id AS BLOB))), 0),
                    COALESCE(max(length(CAST(source_ref AS BLOB))), 0),
                    COALESCE(max(length(CAST(scope_ref AS BLOB))), 0)
             FROM memories WHERE scope_ref=?1 AND state='accepted'",
            [scope_ref],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if bounds.0 < 0
            || bounds.0 as usize > MEMORY_MAX_RECORDS
            || bounds.1 < 0
            || bounds.1 as usize > MEMORY_MAX_TOTAL_CONTENT_BYTES
            || bounds.2 < 0
            || bounds.2 as usize > MEMORY_MAX_ROUTING_FIELD_BYTES
            || bounds.3 < 0
            || bounds.3 as usize > MEMORY_MAX_ROUTING_FIELD_BYTES
            || bounds.4 < 0
            || bounds.4 as usize > MEMORY_MAX_ROUTING_FIELD_BYTES
        {
            return Err(StoreError::SnapshotBounds);
        }

        let mut statement = self.connection.prepare(
            "SELECT memory_id,revision,content,content_sha256,source_ref,scope_ref,state,
                    created_at_seconds,updated_at_seconds
             FROM memories WHERE scope_ref=?1 AND state='accepted'
             ORDER BY memory_id",
        )?;
        let rows = statement.query_map([scope_ref], memory_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub(super) fn inspect(&self) -> Result<super::MemoryStoreInspection, StoreError> {
        let scalar = |sql: &str| -> Result<u64, StoreError> {
            let value: i64 = self.connection.query_row(sql, [], |row| row.get(0))?;
            Ok(value as u64)
        };
        let last_sequence: i64 = self.connection.query_row(
            "SELECT last_event_sequence FROM memory_store_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        Ok(super::MemoryStoreInspection {
            memory_count: scalar("SELECT count(*) FROM memories")?,
            event_count: scalar("SELECT count(*) FROM memory_events")?,
            idempotency_count: scalar("SELECT count(*) FROM memory_idempotency_results")?,
            last_event_sequence: last_sequence as u64,
        })
    }

    pub(super) fn integrity_is_ok(&self) -> Result<bool, StoreError> {
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(integrity == "ok")
    }
}

fn memory_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMemory> {
    let revision: i64 = row.get(1)?;
    Ok(StoredMemory {
        memory_id: row.get(0)?,
        revision: revision as u64,
        content: row.get(2)?,
        content_sha256: row.get(3)?,
        source_ref: row.get(4)?,
        scope_ref: row.get(5)?,
        state: StoredState::from(row.get::<_, String>(6)?.as_str()),
        created_at_seconds: row.get(7)?,
        updated_at_seconds: row.get(8)?,
    })
}

fn insert_event(
    transaction: &rusqlite::Transaction<'_>,
    commit: &EventCommit<'_>,
) -> Result<i64, StoreError> {
    transaction.execute(
        "INSERT INTO memory_events(event_id,memory_id,resulting_revision,operation,principal_id,evidence_ref,request_digest_sha256,resulting_state,committed_at_seconds)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            commit.event_id,
            commit.memory.memory_id,
            commit.memory.revision as i64,
            commit.operation,
            commit.principal_id,
            commit.evidence_ref,
            commit.request_digest_sha256,
            commit.memory.state.as_str(),
            commit.memory.updated_at_seconds
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn insert_idempotency(
    transaction: &rusqlite::Transaction<'_>,
    commit: &IdempotencyCommit<'_>,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO memory_idempotency_results(principal_id,operation,idempotency_key,request_digest_sha256,memory_id,memory_revision,resulting_state,event_id)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            commit.principal_id,
            commit.operation,
            commit.idempotency_key,
            commit.request_digest_sha256,
            commit.memory_id,
            commit.revision as i64,
            commit.state,
            commit.event_id
        ],
    )?;
    Ok(())
}

fn update_sequence(
    transaction: &rusqlite::Transaction<'_>,
    sequence: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE memory_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
        [sequence],
    )?;
    Ok(())
}
