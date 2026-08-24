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

const SCHEMA_V2: &str = r#"
ALTER TABLE policy_outbox RENAME TO policy_outbox_v1;
CREATE TABLE policy_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  destination_domain TEXT NOT NULL,
  payload_kind TEXT NOT NULL,
  payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending','delivered','consumed','held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain, payload_kind),
  FOREIGN KEY (source_event_id) REFERENCES policy_decision_events(event_id)
) STRICT;
INSERT INTO policy_outbox(
  message_id,source_event_id,destination_domain,payload_kind,
  payload_digest_sha256,payload,delivery_state,created_at_seconds
)
SELECT message_id,source_event_id,destination_domain,'policy-event-v1',
       payload_digest_sha256,payload,delivery_state,created_at_seconds
FROM policy_outbox_v1;
DROP TABLE policy_outbox_v1;
CREATE TABLE policy_projection_migrations (
  migration_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('pending','completed')),
  completed_at_seconds INTEGER
) STRICT;
INSERT INTO policy_projection_migrations(migration_id,state)
VALUES('g4-08a-bootstrap-v1','pending');
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
    pub payload_kind: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
    pub rebuild_baseline: bool,
}

pub(crate) struct ProjectionBootstrapCandidate {
    pub decision_ref: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub decision_record: Vec<u8>,
    pub state: Vec<u8>,
    pub event: Vec<u8>,
    pub consumption_receipt: Option<Vec<u8>>,
    pub created_at_seconds: i64,
}

pub(crate) struct ProjectionBootstrapWrite {
    pub decision_ref: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub message_id: String,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
    pub created_at_seconds: i64,
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
    pub read_payload: &'a [u8],
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
    pub outbox_payload: &'a [u8],
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
    pub outbox_payload: &'a [u8],
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
        Migrations::new(vec![M::up(SCHEMA_V1), M::up(SCHEMA_V2)]).to_latest(&mut connection)?;
        let digest = hex::encode(Sha256::digest(
            format!("{SCHEMA_V1}\n{SCHEMA_V2}").as_bytes(),
        ));
        let prior_digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
        connection.execute(
            "INSERT OR IGNORE INTO policy_store_metadata(singleton,store_epoch,schema_profile_id,schema_profile_sha256) VALUES(1,?1,?2,?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, digest],
        )?;
        let actual: (String, String, String) = connection.query_row(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256 FROM policy_store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if actual
            == (
                store_epoch.to_owned(),
                SCHEMA_PROFILE_ID.to_owned(),
                prior_digest,
            )
        {
            connection.execute(
                "UPDATE policy_store_metadata SET schema_profile_sha256=?1 WHERE singleton=1",
                [&digest],
            )?;
        }
        let actual: (String, String, String) = connection.query_row(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256
             FROM policy_store_metadata WHERE singleton=1",
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

    pub fn projection_bootstrap_candidates(
        &self,
    ) -> Result<Vec<ProjectionBootstrapCandidate>, StoreError> {
        let state: String = self.connection.query_row(
            "SELECT state FROM policy_projection_migrations
             WHERE migration_id='g4-08a-bootstrap-v1'",
            [],
            |row| row.get(0),
        )?;
        if state == "completed" {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "SELECT d.authority_decision_ref,e.event_id,s.revision,d.decision_record,
                    s.state_blob,e.event,r.receipt,s.updated_at_seconds
             FROM policy_decisions d
             JOIN policy_decision_states s USING(authority_decision_ref)
             JOIN policy_decision_events e
               ON e.authority_decision_ref=d.authority_decision_ref
              AND e.resulting_state_revision=s.revision
             LEFT JOIN policy_consumption_receipts r
               ON r.authority_decision_ref=d.authority_decision_ref
             ORDER BY d.authority_decision_ref",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ProjectionBootstrapCandidate {
                decision_ref: row.get(0)?,
                source_event_id: row.get(1)?,
                source_revision: row.get::<_, i64>(2)? as u64,
                decision_record: row.get(3)?,
                state: row.get(4)?,
                event: row.get(5)?,
                consumption_receipt: row.get(6)?,
                created_at_seconds: row.get(7)?,
            })
        })?;
        let candidates = rows.collect::<Result<Vec<_>, _>>()?;
        let decision_count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM policy_decisions", [], |row| {
                    row.get(0)
                })?;
        if candidates.len() != decision_count as usize {
            return Err(StoreError::IntegrityFailure);
        }
        Ok(candidates)
    }

    pub fn complete_projection_bootstrap(
        &mut self,
        writes: &[ProjectionBootstrapWrite],
    ) -> Result<(), StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: String = tx.query_row(
            "SELECT state FROM policy_projection_migrations
             WHERE migration_id='g4-08a-bootstrap-v1'",
            [],
            |row| row.get(0),
        )?;
        if state == "completed" {
            tx.commit()?;
            return Ok(());
        }
        let decision_count: i64 =
            tx.query_row("SELECT count(*) FROM policy_decisions", [], |row| {
                row.get(0)
            })?;
        if writes.len() != decision_count as usize {
            return Err(StoreError::IntegrityFailure);
        }
        for write in writes {
            let current: Option<(String, i64)> = tx
                .query_row(
                    "SELECT e.event_id,s.revision
                     FROM policy_decision_states s
                     JOIN policy_decision_events e
                       ON e.authority_decision_ref=s.authority_decision_ref
                      AND e.resulting_state_revision=s.revision
                     WHERE s.authority_decision_ref=?1",
                    [&write.decision_ref],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if current != Some((write.source_event_id.clone(), write.source_revision as i64)) {
                return Err(StoreError::IntegrityFailure);
            }
            tx.execute(
                "INSERT OR IGNORE INTO policy_outbox(
                   message_id,source_event_id,destination_domain,payload_kind,
                   payload_digest_sha256,payload,delivery_state,created_at_seconds
                 ) VALUES(?1,?2,'local-read-model','policy-decision-bootstrap-v1',
                          ?3,?4,'consumed',?5)",
                params![
                    write.message_id,
                    write.source_event_id,
                    write.payload_digest_sha256,
                    write.payload,
                    write.created_at_seconds
                ],
            )?;
            let persisted: Option<(String, String, Vec<u8>, String)> = tx
                .query_row(
                    "SELECT message_id,payload_digest_sha256,payload,delivery_state
                     FROM policy_outbox
                     WHERE source_event_id=?1
                       AND destination_domain='local-read-model'
                       AND payload_kind='policy-decision-bootstrap-v1'",
                    [&write.source_event_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if persisted
                != Some((
                    write.message_id.clone(),
                    write.payload_digest_sha256.clone(),
                    write.payload.clone(),
                    "consumed".to_owned(),
                ))
            {
                return Err(StoreError::IntegrityFailure);
            }
        }
        tx.execute(
            "UPDATE policy_projection_migrations
             SET state='completed',completed_at_seconds=(unixepoch())
             WHERE migration_id='g4-08a-bootstrap-v1' AND state='pending'",
            [],
        )?;
        tx.commit()?;
        Ok(())
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
                c.read_payload,
            ),
        ] {
            let payload_kind = if destination == "harness-adapter" {
                "approval-decision-envelope-v1"
            } else {
                "policy-decision-snapshot-v1"
            };
            tx.execute(
                "INSERT INTO policy_outbox(
                   message_id,source_event_id,destination_domain,payload_kind,
                   payload_digest_sha256,payload,delivery_state,created_at_seconds
                 ) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7)",
                params![
                    id,
                    c.event_id,
                    destination,
                    payload_kind,
                    digest,
                    payload,
                    c.committed_at
                ],
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
            "INSERT INTO policy_outbox(
               message_id,source_event_id,destination_domain,payload_kind,
               payload_digest_sha256,payload,delivery_state,created_at_seconds
             ) VALUES(?1,?2,'local-read-model','policy-decision-snapshot-v1',
                      ?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.outbox_payload,
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
            "INSERT INTO policy_outbox(
               message_id,source_event_id,destination_domain,payload_kind,
               payload_digest_sha256,payload,delivery_state,created_at_seconds
             ) VALUES(?1,?2,'local-read-model','policy-decision-snapshot-v1',
                      ?3,?4,'pending',?5)",
            params![
                c.outbox_id,
                c.event_id,
                c.outbox_digest,
                c.outbox_payload,
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
        let mut statement = self.connection.prepare(
            "SELECT o.message_id,o.source_event_id,o.destination_domain,o.payload_kind,
                    e.resulting_state_revision,o.payload_digest_sha256,o.payload
             FROM policy_outbox o JOIN policy_decision_events e ON e.event_id=o.source_event_id
             WHERE o.delivery_state='pending' ORDER BY o.rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(PendingPolicyOutbox {
                message_id: row.get(0)?,
                source_event_id: row.get(1)?,
                destination_domain: row.get(2)?,
                payload_kind: row.get(3)?,
                source_revision: row.get::<_, i64>(4)? as u64,
                payload_digest_sha256: row.get(5)?,
                payload: row.get(6)?,
                rebuild_baseline: false,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn pending_projection_outbox(&self) -> Result<Vec<PendingPolicyOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT o.message_id,o.source_event_id,o.destination_domain,o.payload_kind,
                    e.resulting_state_revision,o.payload_digest_sha256,o.payload
             FROM policy_outbox o JOIN policy_decision_events e ON e.event_id=o.source_event_id
             WHERE o.delivery_state='pending'
               AND o.destination_domain='local-read-model'
               AND o.payload_kind='policy-decision-snapshot-v1'
             ORDER BY o.rowid",
        )?;
        let rows = statement.query_map([], pending_policy_outbox_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn retained_projection_outbox(&self) -> Result<Vec<PendingPolicyOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT o.message_id,o.source_event_id,o.destination_domain,o.payload_kind,
                    e.resulting_state_revision,o.payload_digest_sha256,o.payload
             FROM policy_outbox o
             JOIN policy_decision_events e ON e.event_id=o.source_event_id
             LEFT JOIN (
               SELECT be.authority_decision_ref,MAX(bse.resulting_state_revision) baseline_revision
               FROM policy_outbox b
               JOIN policy_decision_events bse ON bse.event_id=b.source_event_id
               JOIN policy_decision_events be ON be.event_id=b.source_event_id
               WHERE b.destination_domain='local-read-model'
                 AND b.payload_kind='policy-decision-bootstrap-v1'
               GROUP BY be.authority_decision_ref
             ) baseline ON baseline.authority_decision_ref=e.authority_decision_ref
             WHERE o.destination_domain='local-read-model'
               AND o.delivery_state IN ('pending','consumed')
               AND (
                 o.payload_kind='policy-decision-bootstrap-v1'
                 OR (
                   o.payload_kind='policy-decision-snapshot-v1'
                   AND (baseline.baseline_revision IS NULL
                        OR e.resulting_state_revision>baseline.baseline_revision)
                 )
               )
             ORDER BY e.authority_decision_ref,e.resulting_state_revision,o.rowid",
        )?;
        let rows = statement.query_map([], pending_policy_outbox_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn acknowledge_projection_outbox(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.connection.execute(
            "UPDATE policy_outbox SET delivery_state='consumed'
             WHERE message_id=?1 AND destination_domain='local-read-model'
               AND payload_kind='policy-decision-snapshot-v1'
               AND payload_digest_sha256=?2 AND delivery_state='pending'",
            params![message_id, payload_digest_sha256],
        )?;
        if changed == 1 {
            return Ok(true);
        }
        let replay: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT payload_digest_sha256,delivery_state FROM policy_outbox
                 WHERE message_id=?1 AND destination_domain='local-read-model'
                   AND payload_kind='policy-decision-snapshot-v1'",
                [message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(
            matches!(replay, Some((digest, state)) if digest == payload_digest_sha256 && state == "consumed"),
        )
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

fn pending_policy_outbox_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<PendingPolicyOutbox, rusqlite::Error> {
    let payload_kind: String = row.get(3)?;
    Ok(PendingPolicyOutbox {
        message_id: row.get(0)?,
        source_event_id: row.get(1)?,
        destination_domain: row.get(2)?,
        rebuild_baseline: payload_kind == "policy-decision-bootstrap-v1",
        payload_kind,
        source_revision: row.get::<_, i64>(4)? as u64,
        payload_digest_sha256: row.get(5)?,
        payload: row.get(6)?,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn legacy_v1_store_migrates_without_losing_authority_facts_or_old_outbox() {
        let root =
            std::env::temp_dir().join(format!("egopulse-policy-v1-migration-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create migration root");
        let path = root.join("policy.db");
        let key = [92_u8; 32];
        let epoch = "policy-v1-epoch";
        {
            let mut connection = Connection::open(&path).expect("open legacy store");
            connection
                .pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                .expect("configure SQLCipher key");
            Migrations::new(vec![M::up(SCHEMA_V1)])
                .to_latest(&mut connection)
                .expect("create v1 schema");
            let digest = hex::encode(Sha256::digest(SCHEMA_V1.as_bytes()));
            connection
                .execute(
                    "INSERT INTO policy_store_metadata(
                       singleton,store_epoch,schema_profile_id,schema_profile_sha256,
                       last_event_sequence
                     ) VALUES(1,?1,?2,?3,1)",
                    params![epoch, SCHEMA_PROFILE_ID, digest],
                )
                .expect("insert metadata");
            connection
                .execute(
                    "INSERT INTO policy_decisions VALUES(
                       'decision-v1','approval-v1','payload-digest-v1',x'01',10
                     )",
                    [],
                )
                .expect("insert decision fact");
            connection
                .execute(
                    "INSERT INTO policy_decision_states VALUES(
                       'decision-v1',2,2,x'02',20
                     )",
                    [],
                )
                .expect("insert state fact");
            connection
                .execute(
                    "INSERT INTO policy_decision_events(
                       event_id,command_id,authority_decision_ref,resulting_state_revision,
                       request_digest_sha256,event
                     ) VALUES('event-v1','command-v1','decision-v1',2,'request-digest-v1',x'03')",
                    [],
                )
                .expect("insert event fact");
            connection
                .execute(
                    "INSERT INTO policy_outbox VALUES(
                       'read-v1','event-v1','local-read-model','read-digest-v1',
                       x'04','pending',20
                     )",
                    [],
                )
                .expect("insert legacy read outbox");
            connection
                .execute(
                    "INSERT INTO policy_commit_receipts VALUES(
                       'event-v1','decision-v1',2,'key-v1','request-digest-v1',?1,1,20
                     )",
                    [epoch],
                )
                .expect("insert receipt");
        }

        let mut store = PolicyStore::open(&path, &key, epoch).expect("migrate v1 store");
        let inspection = store.inspect().expect("inspect migrated store");
        assert_eq!(inspection.decision_count, 1);
        assert_eq!(inspection.event_count, 1);
        assert_eq!(inspection.outbox_count, 1);
        assert_eq!(inspection.commit_receipt_count, 1);
        let old_kind: String = store
            .connection
            .query_row(
                "SELECT payload_kind FROM policy_outbox WHERE message_id='read-v1'",
                [],
                |row| row.get(0),
            )
            .expect("legacy outbox preserved");
        assert_eq!(old_kind, "policy-event-v1");
        let candidates = store
            .projection_bootstrap_candidates()
            .expect("bootstrap candidates");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source_revision, 2);
        store
            .complete_projection_bootstrap(&[ProjectionBootstrapWrite {
                decision_ref: "decision-v1".to_owned(),
                source_event_id: "event-v1".to_owned(),
                source_revision: 2,
                message_id: "bootstrap-v1".to_owned(),
                payload_digest_sha256: "bootstrap-digest-v1".to_owned(),
                payload: vec![5],
                created_at_seconds: 20,
            }])
            .expect("complete bootstrap atomically");
        assert_eq!(store.inspect().expect("post bootstrap").outbox_count, 2);
        drop(store);
        let store = PolicyStore::open(&path, &key, epoch).expect("idempotent reopen");
        assert!(
            store
                .projection_bootstrap_candidates()
                .expect("completed migration")
                .is_empty()
        );
        assert_eq!(store.inspect().expect("reopen inspection").outbox_count, 2);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
