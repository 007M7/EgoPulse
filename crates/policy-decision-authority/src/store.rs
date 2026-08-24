use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/policy-decision-authority-store/v1";
const SCHEMA_V1: &str = r#"
CREATE TABLE policy_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE policy_decisions (
  authority_decision_ref TEXT PRIMARY KEY,
  approval_request_id TEXT NOT NULL UNIQUE,
  payload_digest_sha256 TEXT NOT NULL UNIQUE,
  decision_record BLOB NOT NULL,
  issued_at_seconds INTEGER NOT NULL
) STRICT;
CREATE TABLE policy_decision_states (
  authority_decision_ref TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  state INTEGER NOT NULL,
  state_blob BLOB NOT NULL,
  updated_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (authority_decision_ref) REFERENCES policy_decisions(authority_decision_ref)
) STRICT;
CREATE TABLE policy_decision_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  authority_decision_ref TEXT NOT NULL,
  resulting_state_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL,
  FOREIGN KEY (authority_decision_ref) REFERENCES policy_decisions(authority_decision_ref)
) STRICT;
CREATE TABLE policy_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  authority_decision_ref TEXT NOT NULL,
  state_revision INTEGER NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (authenticated_principal_id, operation, idempotency_scope, idempotency_key)
) STRICT;
CREATE TABLE policy_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  destination_domain TEXT NOT NULL,
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending','delivered','consumed','held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain),
  FOREIGN KEY (source_event_id) REFERENCES policy_decision_events(event_id)
) STRICT;
CREATE TABLE policy_consumption_receipts (
  consumption_receipt_id TEXT PRIMARY KEY,
  authority_decision_ref TEXT NOT NULL UNIQUE,
  adapter_receipt_id TEXT NOT NULL UNIQUE,
  receipt BLOB NOT NULL,
  created_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (authority_decision_ref) REFERENCES policy_decisions(authority_decision_ref)
) STRICT;
CREATE TABLE policy_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES policy_decision_events(event_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("policy decision storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("policy decision migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("policy decision store directory could not be created")]
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

pub(crate) struct StoredDecision {
    pub decision_record: Vec<u8>,
    pub state: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPolicyOutbox {
    pub message_id: String,
    pub source_event_id: String,
    pub destination_domain: String,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(crate) struct IssueCommit<'a> {
    pub decision_ref: &'a str,
    pub approval_request_id: &'a str,
    pub payload_digest: &'a str,
    pub decision_record: &'a [u8],
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
    pub adapter_outbox_id: &'a str,
    pub adapter_payload_digest: &'a str,
    pub adapter_payload: &'a [u8],
    pub read_outbox_id: &'a str,
    pub read_payload_digest: &'a str,
    pub committed_at: i64,
}

pub(crate) struct ConsumeCommit<'a> {
    pub decision_ref: &'a str,
    pub expected_revision: u64,
    pub state: &'a [u8],
    pub state_kind: i32,
    pub receipt_id: &'a str,
    pub adapter_receipt_id: &'a str,
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
    pub committed_at: i64,
}

pub(crate) struct StateCommit<'a> {
    pub decision_ref: &'a str,
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
    pub committed_at: i64,
}

struct ReceiptInsert<'a> {
    event_id: &'a str,
    decision_ref: &'a str,
    revision: u64,
    key: &'a str,
    digest: &'a str,
    epoch: &'a str,
    at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyStoreInspection {
    pub decision_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub consumption_receipt_count: u64,
    pub commit_receipt_count: u64,
}

pub(crate) struct PolicyStore {
    connection: Connection,
    store_epoch: String,
}

impl PolicyStore {
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
        Migrations::new(vec![M::up(SCHEMA_V1)]).to_latest(&mut connection)?;
        let digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO policy_store_metadata(singleton,store_epoch,schema_profile_id,schema_profile_sha256) VALUES(1,?1,?2,?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, digest],
        )?;
        let actual: (String, String, String) = connection.query_row(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256 FROM policy_store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if actual != (store_epoch.to_owned(), SCHEMA_PROFILE_ID.to_owned(), digest) {
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
            "SELECT request_digest_sha256,result FROM policy_idempotency_results WHERE authenticated_principal_id=?1 AND operation=?2 AND idempotency_scope=?3 AND idempotency_key=?4",
            params![principal, operation, scope, key],
            |row| Ok(IdempotencyRecord { request_digest_sha256: row.get(0)?, result: row.get(1)? }),
        ).optional().map_err(StoreError::from)
    }

    pub fn stored_decision(
        &self,
        decision_ref: &str,
    ) -> Result<Option<StoredDecision>, StoreError> {
        self.connection.query_row(
            "SELECT d.decision_record,s.state_blob FROM policy_decisions d JOIN policy_decision_states s USING(authority_decision_ref) WHERE d.authority_decision_ref=?1",
            [decision_ref],
            |row| Ok(StoredDecision { decision_record: row.get(0)?, state: row.get(1)? }),
        ).optional().map_err(StoreError::from)
    }

    pub fn issue(&mut self, c: &IssueCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT authority_decision_ref FROM policy_decisions WHERE approval_request_id=?1",
                [c.approval_request_id],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO policy_decisions VALUES(?1,?2,?3,?4,?5)",
            params![
                c.decision_ref,
                c.approval_request_id,
                c.payload_digest,
                c.decision_record,
                c.committed_at
            ],
        )?;
        tx.execute(
            "INSERT INTO policy_decision_states VALUES(?1,1,?2,?3,?4)",
            params![c.decision_ref, c.state_kind, c.state, c.committed_at],
        )?;
        let sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                decision_ref: c.decision_ref,
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
        for (id, destination, digest, payload) in [
            (
                c.adapter_outbox_id,
                "harness-adapter",
                c.adapter_payload_digest,
                c.adapter_payload,
            ),
            (
                c.read_outbox_id,
                "local-read-model",
                c.read_payload_digest,
                c.event,
            ),
        ] {
            tx.execute(
                "INSERT INTO policy_outbox VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                params![id, c.event_id, destination, digest, payload, c.committed_at],
            )?;
        }
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                decision_ref: c.decision_ref,
                revision: 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE policy_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn consume(&mut self, c: &ConsumeCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE policy_decision_states SET revision=?2,state=?3,state_blob=?4,updated_at_seconds=?5 WHERE authority_decision_ref=?1 AND revision=?6 AND state=?7",
            params![c.decision_ref,(c.expected_revision+1) as i64,c.state_kind,c.state,c.committed_at,c.expected_revision as i64,1_i32],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO policy_consumption_receipts VALUES(?1,?2,?3,?4,?5)",
            params![
                c.receipt_id,
                c.decision_ref,
                c.adapter_receipt_id,
                c.receipt,
                c.committed_at
            ],
        )?;
        let sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                decision_ref: c.decision_ref,
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
            "INSERT INTO policy_outbox VALUES(?1,?2,'local-read-model',?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.event,
                c.committed_at
            ],
        )?;
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                decision_ref: c.decision_ref,
                revision: c.expected_revision + 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE policy_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn transition(&mut self, c: &StateCommit<'_>) -> Result<bool, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE policy_decision_states SET revision=?2,state=?3,state_blob=?4,updated_at_seconds=?5 WHERE authority_decision_ref=?1 AND revision=?6 AND state=?7",
            params![c.decision_ref,(c.expected_revision+1) as i64,c.state_kind,c.state,c.committed_at,c.expected_revision as i64,1_i32],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let sequence = insert_event_and_idempotency(
            &tx,
            &EventInsert {
                event_id: c.event_id,
                command_id: c.command_id,
                decision_ref: c.decision_ref,
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
            "INSERT INTO policy_outbox VALUES(?1,?2,'local-read-model',?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.event,
                c.committed_at
            ],
        )?;
        insert_commit_receipt(
            &tx,
            &ReceiptInsert {
                event_id: c.event_id,
                decision_ref: c.decision_ref,
                revision: c.expected_revision + 1,
                key: c.idempotency_key,
                digest: c.request_digest,
                epoch: &self.store_epoch,
                at: c.committed_at,
            },
        )?;
        tx.execute(
            "UPDATE policy_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
            [sequence],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn pending_outbox(&self) -> Result<Vec<PendingPolicyOutbox>, StoreError> {
        let mut statement = self.connection.prepare("SELECT message_id,source_event_id,destination_domain,payload_digest_sha256,payload FROM policy_outbox WHERE delivery_state='pending' ORDER BY rowid")?;
        let rows = statement.query_map([], |row| {
            Ok(PendingPolicyOutbox {
                message_id: row.get(0)?,
                source_event_id: row.get(1)?,
                destination_domain: row.get(2)?,
                payload_digest_sha256: row.get(3)?,
                payload: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn inspect(&self) -> Result<PolicyStoreInspection, StoreError> {
        let count = |sql: &str| -> Result<u64, StoreError> {
            Ok(self
                .connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))? as u64)
        };
        Ok(PolicyStoreInspection {
            decision_count: count("SELECT count(*) FROM policy_decisions")?,
            event_count: count("SELECT count(*) FROM policy_decision_events")?,
            idempotency_count: count("SELECT count(*) FROM policy_idempotency_results")?,
            outbox_count: count("SELECT count(*) FROM policy_outbox")?,
            consumption_receipt_count: count("SELECT count(*) FROM policy_consumption_receipts")?,
            commit_receipt_count: count("SELECT count(*) FROM policy_commit_receipts")?,
        })
    }
}

struct EventInsert<'a> {
    event_id: &'a str,
    command_id: &'a str,
    decision_ref: &'a str,
    revision: u64,
    digest: &'a str,
    event: &'a [u8],
    principal: &'a str,
    operation: &'a str,
    scope: &'a str,
    key: &'a str,
    result: &'a [u8],
}

fn insert_event_and_idempotency(
    tx: &rusqlite::Transaction<'_>,
    c: &EventInsert<'_>,
) -> Result<i64, rusqlite::Error> {
    tx.execute("INSERT INTO policy_decision_events(event_id,command_id,authority_decision_ref,resulting_state_revision,request_digest_sha256,event) VALUES(?1,?2,?3,?4,?5,?6)", params![c.event_id,c.command_id,c.decision_ref,c.revision as i64,c.digest,c.event])?;
    let sequence = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO policy_idempotency_results VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            c.principal,
            c.operation,
            c.scope,
            c.key,
            c.digest,
            c.decision_ref,
            c.revision as i64,
            c.result
        ],
    )?;
    Ok(sequence)
}

fn insert_commit_receipt(
    tx: &rusqlite::Transaction<'_>,
    insert: &ReceiptInsert<'_>,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO policy_commit_receipts VALUES(?1,?2,?3,?4,?5,?6,1,?7)",
        params![
            insert.event_id,
            insert.decision_ref,
            insert.revision as i64,
            insert.key,
            insert.digest,
            insert.epoch,
            insert.at
        ],
    )?;
    Ok(())
}
