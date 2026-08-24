use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/founder-verdict-authority-store/v1";
const SCHEMA_V1: &str = r#"
CREATE TABLE verdict_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE founder_verdicts (
  founder_verdict_id TEXT PRIMARY KEY,
  scope_digest_sha256 TEXT NOT NULL,
  payload_digest_sha256 TEXT NOT NULL UNIQUE,
  verdict BLOB NOT NULL,
  issued_at_seconds INTEGER NOT NULL
) STRICT;
CREATE TABLE founder_verdict_states (
  founder_verdict_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  state INTEGER NOT NULL,
  state_blob BLOB NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (founder_verdict_id) REFERENCES founder_verdicts(founder_verdict_id)
) STRICT;
CREATE TABLE verdict_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  founder_verdict_id TEXT NOT NULL,
  resulting_state_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL,
  FOREIGN KEY (founder_verdict_id) REFERENCES founder_verdicts(founder_verdict_id)
) STRICT;
CREATE TABLE verdict_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  founder_verdict_id TEXT NOT NULL,
  state_revision INTEGER NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (authenticated_principal_id, operation, idempotency_scope, idempotency_key)
) STRICT;
CREATE TABLE verdict_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  destination_domain TEXT NOT NULL,
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending','delivered','consumed','held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain),
  FOREIGN KEY (source_event_id) REFERENCES verdict_events(event_id)
) STRICT;
CREATE TABLE verdict_consumption_receipts (
  consumption_receipt_id TEXT PRIMARY KEY,
  founder_verdict_id TEXT NOT NULL UNIQUE,
  task_event_id TEXT NOT NULL UNIQUE,
  receipt BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (founder_verdict_id) REFERENCES founder_verdicts(founder_verdict_id)
) STRICT;
CREATE TABLE verdict_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES verdict_events(event_id)
) STRICT;
"#;

const SCHEMA_V2: &str = r#"
CREATE TABLE verdict_projection_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL UNIQUE,
  source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending','consumed','held')),
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (source_event_id) REFERENCES verdict_events(event_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("founder verdict storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("founder verdict migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("founder verdict store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("store generation mismatch")]
    StoreGenerationMismatch,
    #[error("store integrity check failed")]
    IntegrityFailure,
}

pub(crate) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub result: Vec<u8>,
}

pub(crate) struct StoredVerdict {
    pub verdict: Vec<u8>,
    pub state: Vec<u8>,
}

pub(crate) struct IssueCommit<'a> {
    pub verdict_id: &'a str,
    pub scope_digest: &'a str,
    pub payload_digest: &'a str,
    pub verdict: &'a [u8],
    pub state: &'a [u8],
    pub state_kind: i32,
    pub event_id: &'a str,
    pub command_id: &'a str,
    pub request_digest: &'a str,
    pub event: &'a [u8],
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub idempotency_scope: &'a str,
    pub idempotency_key: &'a str,
    pub result: &'a [u8],
    pub read_outbox_id: &'a str,
    pub task_outbox_id: &'a str,
    pub outbox_digest: &'a str,
    pub projection_outbox_id: &'a str,
    pub projection_payload_digest: &'a str,
    pub projection_payload: &'a [u8],
    pub committed_at: i64,
    pub supersede: Option<SupersedeCommit<'a>>,
}

pub(crate) struct SupersedeCommit<'a> {
    pub verdict_id: &'a str,
    pub expected_revision: u64,
    pub state: &'a [u8],
    pub state_kind: i32,
    pub event_id: &'a str,
    pub command_id: &'a str,
    pub event: &'a [u8],
    pub outbox_id: &'a str,
    pub outbox_digest: &'a str,
    pub projection_outbox_id: &'a str,
    pub projection_payload_digest: &'a str,
    pub projection_payload: &'a [u8],
}

pub(crate) struct ConsumeCommit<'a> {
    pub verdict_id: &'a str,
    pub expected_revision: u64,
    pub state: &'a [u8],
    pub state_kind: i32,
    pub receipt_id: &'a str,
    pub task_event_id: &'a str,
    pub receipt: &'a [u8],
    pub event_id: &'a str,
    pub command_id: &'a str,
    pub request_digest: &'a str,
    pub event: &'a [u8],
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub idempotency_scope: &'a str,
    pub idempotency_key: &'a str,
    pub result: &'a [u8],
    pub outbox_id: &'a str,
    pub outbox_digest: &'a str,
    pub projection_outbox_id: &'a str,
    pub projection_payload_digest: &'a str,
    pub projection_payload: &'a [u8],
    pub committed_at: i64,
}

pub(crate) struct StateCommit<'a> {
    pub verdict_id: &'a str,
    pub expected_revision: u64,
    pub state: &'a [u8],
    pub state_kind: i32,
    pub event_id: &'a str,
    pub command_id: &'a str,
    pub request_digest: &'a str,
    pub event: &'a [u8],
    pub principal_id: &'a str,
    pub operation: &'a str,
    pub idempotency_scope: &'a str,
    pub idempotency_key: &'a str,
    pub result: &'a [u8],
    pub outbox_id: &'a str,
    pub outbox_digest: &'a str,
    pub projection_outbox_id: &'a str,
    pub projection_payload_digest: &'a str,
    pub projection_payload: &'a [u8],
    pub committed_at: i64,
}

struct EventInsert<'a> {
    event_id: &'a str,
    command_id: &'a str,
    verdict_id: &'a str,
    revision: u64,
    digest: &'a str,
    event: &'a [u8],
    principal: &'a str,
    operation: &'a str,
    scope: &'a str,
    key: &'a str,
    result: &'a [u8],
}

struct ReceiptInsert<'a> {
    event_id: &'a str,
    verdict_id: &'a str,
    revision: u64,
    key: &'a str,
    digest: &'a str,
    epoch: &'a str,
    at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerdictStoreInspection {
    pub verdict_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub consumption_receipt_count: u64,
    pub commit_receipt_count: u64,
}

pub(crate) struct PendingProjectionOutbox {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(crate) struct VerdictProjectionBaseline {
    pub source_event_id: String,
    pub source_revision: u64,
    pub verdict: Vec<u8>,
    pub state: Vec<u8>,
    pub event: Vec<u8>,
}

pub(crate) struct VerdictStore {
    connection: Connection,
    store_epoch: String,
}

impl VerdictStore {
    pub fn open(path: &Path, key: &[u8; 32], store_epoch: &str) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(StoreError::Directory)?;
        }
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
        let cipher: String = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .map_err(|_| StoreError::CipherUnavailable)?;
        if cipher.trim().is_empty() {
            return Err(StoreError::CipherUnavailable);
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        Migrations::new(vec![M::up(SCHEMA_V1), M::up(SCHEMA_V2)]).to_latest(&mut connection)?;
        let legacy_digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
        let digest = hex::encode(Sha256::digest(
            format!("{SCHEMA_V1}\n{SCHEMA_V2}").as_bytes(),
        ));
        connection.execute(
            "INSERT OR IGNORE INTO verdict_store_metadata(singleton,store_epoch,schema_profile_id,schema_profile_sha256) VALUES(1,?1,?2,?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, digest],
        )?;
        let actual: (String, String, String) = connection.query_row(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256 FROM verdict_store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if actual.0 != store_epoch || actual.1 != SCHEMA_PROFILE_ID {
            return Err(StoreError::StoreGenerationMismatch);
        }
        if actual.2 == legacy_digest {
            connection.execute(
                "UPDATE verdict_store_metadata SET schema_profile_sha256=?1
                 WHERE singleton=1 AND schema_profile_sha256=?2",
                params![digest, legacy_digest],
            )?;
        } else if actual.2 != digest {
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
        principal: &str,
        operation: &str,
        scope: &str,
        key: &str,
    ) -> Result<Option<IdempotencyRecord>, StoreError> {
        self.connection.query_row(
            "SELECT request_digest_sha256,result FROM verdict_idempotency_results WHERE authenticated_principal_id=?1 AND operation=?2 AND idempotency_scope=?3 AND idempotency_key=?4",
            params![principal, operation, scope, key],
            |row| Ok(IdempotencyRecord { request_digest_sha256: row.get(0)?, result: row.get(1)? }),
        ).optional().map_err(StoreError::from)
    }

    pub fn stored_verdict(&self, id: &str) -> Result<Option<StoredVerdict>, StoreError> {
        self.connection.query_row(
            "SELECT v.verdict,s.state_blob FROM founder_verdicts v JOIN founder_verdict_states s USING(founder_verdict_id) WHERE v.founder_verdict_id=?1",
            [id],
            |row| Ok(StoredVerdict { verdict: row.get(0)?, state: row.get(1)? }),
        ).optional().map_err(StoreError::from)
    }

    pub fn issue(&mut self, c: &IssueCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active_verdict_id: Option<String> = tx
            .query_row(
                "SELECT v.founder_verdict_id FROM founder_verdicts v JOIN founder_verdict_states s USING(founder_verdict_id) WHERE v.scope_digest_sha256=?1 AND s.state=?2",
                params![c.scope_digest, 1_i32],
                |row| row.get(0),
            )
            .optional()?;
        match (&active_verdict_id, &c.supersede) {
            (None, None) => {}
            (Some(active), Some(supersede)) if active == supersede.verdict_id => {}
            _ => return Ok(false),
        }
        if let Some(supersede) = &c.supersede {
            let changed = tx.execute(
                "UPDATE founder_verdict_states SET revision=?2,state=?3,state_blob=?4,updated_at_seconds=?5 WHERE founder_verdict_id=?1 AND revision=?6 AND state=?7",
                params![
                    supersede.verdict_id,
                    (supersede.expected_revision + 1) as i64,
                    supersede.state_kind,
                    supersede.state,
                    c.committed_at,
                    supersede.expected_revision as i64,
                    1_i32
                ],
            )?;
            if changed != 1 {
                return Ok(false);
            }
            let supersede_sequence = insert_event(
                &tx,
                supersede.event_id,
                supersede.command_id,
                supersede.verdict_id,
                supersede.expected_revision + 1,
                c.request_digest,
                supersede.event,
            )?;
            tx.execute(
                "INSERT INTO verdict_outbox VALUES(?1,?2,'local-read-model',?3,?4,'pending',?5)",
                params![
                    supersede.outbox_id,
                    supersede.event_id,
                    supersede.outbox_digest,
                    supersede.event,
                    c.committed_at
                ],
            )?;
            insert_projection_outbox(
                &tx,
                supersede.projection_outbox_id,
                supersede.event_id,
                supersede.expected_revision + 1,
                supersede.projection_payload_digest,
                supersede.projection_payload,
                c.committed_at,
            )?;
            insert_commit_receipt(
                &tx,
                &ReceiptInsert {
                    event_id: supersede.event_id,
                    verdict_id: supersede.verdict_id,
                    revision: supersede.expected_revision + 1,
                    key: c.idempotency_key,
                    digest: c.request_digest,
                    epoch: &self.store_epoch,
                    at: c.committed_at,
                },
            )?;
            tx.execute(
                "UPDATE verdict_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
                [supersede_sequence],
            )?;
        }
        tx.execute(
            "INSERT INTO founder_verdicts VALUES(?1,?2,?3,?4,?5)",
            params![
                c.verdict_id,
                c.scope_digest,
                c.payload_digest,
                c.verdict,
                c.committed_at
            ],
        )?;
        tx.execute(
            "INSERT INTO founder_verdict_states VALUES(?1,1,?2,?3,?4)",
            params![c.verdict_id, c.state_kind, c.state, c.committed_at],
        )?;
        let event_sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                verdict_id: c.verdict_id,
                revision: 1,
                digest: c.request_digest,
                event: c.event,
                principal: c.principal_id,
                operation: c.operation,
                scope: c.idempotency_scope,
                key: c.idempotency_key,
                result: c.result,
            },
        )?;
        for (id, destination) in [
            (c.read_outbox_id, "local-read-model"),
            (c.task_outbox_id, "task-authority"),
        ] {
            tx.execute(
                "INSERT INTO verdict_outbox VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                params![
                    id,
                    c.event_id,
                    destination,
                    c.outbox_digest,
                    c.event,
                    c.committed_at
                ],
            )?;
        }
        insert_projection_outbox(
            &tx,
            c.projection_outbox_id,
            c.event_id,
            1,
            c.projection_payload_digest,
            c.projection_payload,
            c.committed_at,
        )?;
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                verdict_id: c.verdict_id,
                revision: 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE verdict_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [event_sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn consume(&mut self, c: &ConsumeCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE founder_verdict_states SET revision=?2,state=?3,state_blob=?4,updated_at_seconds=?5 WHERE founder_verdict_id=?1 AND revision=?6",
            params![c.verdict_id,(c.expected_revision+1) as i64,c.state_kind,c.state,c.committed_at,c.expected_revision as i64],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO verdict_consumption_receipts VALUES(?1,?2,?3,?4,?5)",
            params![
                c.receipt_id,
                c.verdict_id,
                c.task_event_id,
                c.receipt,
                c.committed_at
            ],
        )?;
        let event_sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                verdict_id: c.verdict_id,
                revision: c.expected_revision + 1,
                digest: c.request_digest,
                event: c.event,
                principal: c.principal_id,
                operation: c.operation,
                scope: c.idempotency_scope,
                key: c.idempotency_key,
                result: c.result,
            },
        )?;
        tx.execute(
            "INSERT INTO verdict_outbox VALUES(?1,?2,'local-read-model',?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.event,
                c.committed_at
            ],
        )?;
        insert_projection_outbox(
            &tx,
            c.projection_outbox_id,
            c.event_id,
            c.expected_revision + 1,
            c.projection_payload_digest,
            c.projection_payload,
            c.committed_at,
        )?;
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                verdict_id: c.verdict_id,
                revision: c.expected_revision + 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE verdict_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [event_sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn transition(&mut self, c: &StateCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE founder_verdict_states SET revision=?2,state=?3,state_blob=?4,updated_at_seconds=?5 WHERE founder_verdict_id=?1 AND revision=?6 AND state=?7",
            params![
                c.verdict_id,
                (c.expected_revision + 1) as i64,
                c.state_kind,
                c.state,
                c.committed_at,
                c.expected_revision as i64,
                1_i32
            ],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let event_sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                verdict_id: c.verdict_id,
                revision: c.expected_revision + 1,
                digest: c.request_digest,
                event: c.event,
                principal: c.principal_id,
                operation: c.operation,
                scope: c.idempotency_scope,
                key: c.idempotency_key,
                result: c.result,
            },
        )?;
        tx.execute(
            "INSERT INTO verdict_outbox VALUES(?1,?2,'local-read-model',?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.event,
                c.committed_at
            ],
        )?;
        insert_projection_outbox(
            &tx,
            c.projection_outbox_id,
            c.event_id,
            c.expected_revision + 1,
            c.projection_payload_digest,
            c.projection_payload,
            c.committed_at,
        )?;
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                verdict_id: c.verdict_id,
                revision: c.expected_revision + 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE verdict_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [event_sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn inspect(&self) -> Result<VerdictStoreInspection, StoreError> {
        let count = |sql: &str| -> Result<u64, StoreError> {
            Ok(self.connection.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        Ok(VerdictStoreInspection {
            verdict_count: count("SELECT count(*) FROM founder_verdicts")?,
            event_count: count("SELECT count(*) FROM verdict_events")?,
            idempotency_count: count("SELECT count(*) FROM verdict_idempotency_results")?,
            outbox_count: count("SELECT count(*) FROM verdict_outbox")?,
            consumption_receipt_count: count("SELECT count(*) FROM verdict_consumption_receipts")?,
            commit_receipt_count: count("SELECT count(*) FROM verdict_commit_receipts")?,
        })
    }

    pub fn pending_projection_outbox(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT message_id,source_event_id,source_revision,payload_digest_sha256,payload
             FROM verdict_projection_outbox WHERE delivery_state='pending'
             ORDER BY created_at_seconds,message_id",
        )?;
        let rows = statement.query_map([], |row| {
            let revision: i64 = row.get(2)?;
            Ok(PendingProjectionOutbox {
                message_id: row.get(0)?,
                source_event_id: row.get(1)?,
                source_revision: revision as u64,
                payload_digest_sha256: row.get(3)?,
                payload: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn acknowledge_projection_outbox(
        &mut self,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.connection.execute(
            "UPDATE verdict_projection_outbox SET delivery_state='consumed'
             WHERE message_id=?1 AND payload_digest_sha256=?2 AND delivery_state='pending'",
            params![message_id, expected_payload_digest_sha256],
        )?;
        Ok(changed == 1)
    }

    pub fn projection_baselines(&self) -> Result<Vec<VerdictProjectionBaseline>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT e.event_id,e.resulting_state_revision,v.verdict,s.state_blob,e.event
             FROM founder_verdicts v
             JOIN founder_verdict_states s USING(founder_verdict_id)
             JOIN verdict_events e ON e.founder_verdict_id=v.founder_verdict_id
             WHERE e.sequence=(
               SELECT max(latest.sequence) FROM verdict_events latest
               WHERE latest.founder_verdict_id=v.founder_verdict_id
             )
             ORDER BY v.founder_verdict_id",
        )?;
        let rows = statement.query_map([], |row| {
            let revision: i64 = row.get(1)?;
            Ok(VerdictProjectionBaseline {
                source_event_id: row.get(0)?,
                source_revision: revision as u64,
                verdict: row.get(2)?,
                state: row.get(3)?,
                event: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

fn insert_projection_outbox(
    tx: &rusqlite::Transaction<'_>,
    message_id: &str,
    source_event_id: &str,
    source_revision: u64,
    payload_digest_sha256: &str,
    payload: &[u8],
    created_at_seconds: i64,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO verdict_projection_outbox(
           message_id,source_event_id,source_revision,payload_digest_sha256,payload,
           delivery_state,created_at_seconds
         ) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
        params![
            message_id,
            source_event_id,
            source_revision as i64,
            payload_digest_sha256,
            payload,
            created_at_seconds
        ],
    )?;
    Ok(())
}

fn insert_event_and_idempotency(
    tx: &rusqlite::Transaction<'_>,
    insert: &EventInsert<'_>,
) -> Result<i64, rusqlite::Error> {
    let event_sequence = insert_event(
        tx,
        insert.event_id,
        insert.command_id,
        insert.verdict_id,
        insert.revision,
        insert.digest,
        insert.event,
    )?;
    tx.execute(
        "INSERT INTO verdict_idempotency_results VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            insert.principal,
            insert.operation,
            insert.scope,
            insert.key,
            insert.digest,
            insert.verdict_id,
            insert.revision as i64,
            insert.result
        ],
    )?;
    Ok(event_sequence)
}

fn insert_event(
    tx: &rusqlite::Transaction<'_>,
    event_id: &str,
    command_id: &str,
    verdict_id: &str,
    revision: u64,
    digest: &str,
    event: &[u8],
) -> Result<i64, rusqlite::Error> {
    tx.execute(
        "INSERT INTO verdict_events(event_id,command_id,founder_verdict_id,resulting_state_revision,request_digest_sha256,event) VALUES(?1,?2,?3,?4,?5,?6)",
        params![event_id, command_id, verdict_id, revision as i64, digest, event],
    )?;
    Ok(tx.last_insert_rowid())
}

fn insert_commit_receipt(
    tx: &rusqlite::Transaction<'_>,
    insert: &ReceiptInsert<'_>,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO verdict_commit_receipts VALUES(?1,?2,?3,?4,?5,?6,1,?7)",
        params![
            insert.event_id,
            insert.verdict_id,
            insert.revision as i64,
            insert.key,
            insert.digest,
            insert.epoch,
            insert.at
        ],
    )?;
    Ok(())
}
