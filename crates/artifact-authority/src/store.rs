use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/artifact-authority-store/v1";

const SCHEMA_V1: &str = r#"
CREATE TABLE artifact_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_committed_revision INTEGER NOT NULL DEFAULT 0,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE artifacts (
  artifact_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  content_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE claims (
  claim_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  proposer_principal_id TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE evidence (
  evidence_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  claim_id TEXT NOT NULL,
  producer_principal_id TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
) STRICT;

CREATE TABLE artifact_sets (
  artifact_set_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  manifest_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE return_handoffs (
  return_handoff_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  artifact_set_id TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  FOREIGN KEY (artifact_set_id) REFERENCES artifact_sets(artifact_set_id)
) STRICT;

CREATE TABLE return_receipts (
  receipt_id TEXT PRIMARY KEY,
  return_handoff_id TEXT NOT NULL UNIQUE,
  artifact_set_id TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  FOREIGN KEY (return_handoff_id) REFERENCES return_handoffs(return_handoff_id),
  FOREIGN KEY (artifact_set_id) REFERENCES artifact_sets(artifact_set_id)
) STRICT;

CREATE TABLE artifact_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL
) STRICT;

CREATE TABLE artifact_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (
    authenticated_principal_id,
    operation,
    idempotency_scope,
    idempotency_key
  ),
  FOREIGN KEY (event_id) REFERENCES artifact_events(event_id)
) STRICT;

CREATE TABLE artifact_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL,
  destination_domain TEXT NOT NULL,
  canonical_payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'delivered', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain),
  FOREIGN KEY (source_event_id) REFERENCES artifact_events(event_id)
) STRICT;

CREATE TABLE artifact_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  primary_outbox_message_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES artifact_events(event_id),
  FOREIGN KEY (primary_outbox_message_id) REFERENCES artifact_outbox(message_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("artifact authority storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("artifact authority migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("artifact authority store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("artifact authority SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("artifact authority store metadata does not match the active generation")]
    StoreGenerationMismatch,
    #[error("artifact authority store integrity check failed")]
    IntegrityFailure,
    #[error("artifact authority revision precondition failed")]
    RevisionConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub result: Vec<u8>,
}

pub(super) enum Mutation {
    InsertArtifact {
        id: String,
        revision: u64,
        status: i32,
        content_digest: String,
        snapshot: Vec<u8>,
    },
    UpdateArtifact {
        id: String,
        expected_revision: u64,
        revision: u64,
        status: i32,
        snapshot: Vec<u8>,
    },
    InsertClaim {
        id: String,
        revision: u64,
        status: i32,
        proposer_principal_id: String,
        snapshot: Vec<u8>,
    },
    InsertEvidence {
        id: String,
        revision: u64,
        status: i32,
        claim_id: String,
        producer_principal_id: String,
        snapshot: Vec<u8>,
    },
    InsertArtifactSet {
        id: String,
        revision: u64,
        status: i32,
        manifest_digest: String,
        snapshot: Vec<u8>,
    },
    UpdateArtifactSet {
        id: String,
        expected_revision: u64,
        revision: u64,
        status: i32,
        snapshot: Vec<u8>,
    },
    InsertReturn {
        handoff_id: String,
        handoff_revision: u64,
        handoff_status: i32,
        artifact_set_id: String,
        handoff_snapshot: Vec<u8>,
        receipt_id: String,
        receipt_snapshot: Vec<u8>,
    },
}

pub(super) struct OutboxWrite {
    pub message_id: String,
    pub destination_domain: String,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(super) struct PendingProjectionOutbox {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub payload: Vec<u8>,
}

pub(super) struct AuthorityCommit {
    pub mutation: Mutation,
    pub event_id: String,
    pub command_id: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub aggregate_revision: u64,
    pub request_digest_sha256: String,
    pub event: Vec<u8>,
    pub authenticated_principal_id: String,
    pub operation: String,
    pub idempotency_scope: String,
    pub idempotency_key: String,
    pub result: Vec<u8>,
    pub outbox: Vec<OutboxWrite>,
    pub committed_at_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactStoreInspection {
    pub artifact_count: u64,
    pub claim_count: u64,
    pub evidence_count: u64,
    pub artifact_set_count: u64,
    pub return_handoff_count: u64,
    pub return_receipt_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub commit_receipt_count: u64,
    pub last_committed_revision: u64,
    pub last_event_sequence: u64,
}

pub(super) struct ArtifactStore {
    connection: Connection,
    store_epoch: String,
}

impl ArtifactStore {
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
            "INSERT OR IGNORE INTO artifact_store_metadata(
               singleton, store_epoch, schema_profile_id, schema_profile_sha256
             ) VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM artifact_store_metadata WHERE singleton = 1",
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
                "SELECT request_digest_sha256, result
                 FROM artifact_idempotency_results
                 WHERE authenticated_principal_id = ?1
                   AND operation = ?2
                   AND idempotency_scope = ?3
                   AND idempotency_key = ?4",
                params![principal_id, operation, scope, key],
                |row| {
                    Ok(IdempotencyRecord {
                        request_digest_sha256: row.get(0)?,
                        result: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn artifact(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("artifacts", "artifact_id", id)
    }

    pub fn claim(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("claims", "claim_id", id)
    }

    pub fn evidence(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("evidence", "evidence_id", id)
    }

    pub fn artifact_set(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("artifact_sets", "artifact_set_id", id)
    }

    pub fn return_handoff(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("return_handoffs", "return_handoff_id", id)
    }

    pub fn return_receipt(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("return_receipts", "receipt_id", id)
    }

    fn snapshot(
        &self,
        table: &str,
        id_column: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let sql = format!("SELECT snapshot FROM {table} WHERE {id_column} = ?1");
        self.connection
            .query_row(&sql, [id], |row| row.get(0))
            .optional()
            .map_err(StoreError::from)
    }

    pub fn commit(&mut self, commit: AuthorityCommit) -> Result<(), StoreError> {
        debug_assert!(!commit.outbox.is_empty());
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        match commit.mutation {
            Mutation::InsertArtifact {
                id,
                revision,
                status,
                content_digest,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO artifacts(artifact_id, revision, status, content_digest_sha256, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![id, revision as i64, status, content_digest, snapshot],
                )?;
            }
            Mutation::UpdateArtifact {
                id,
                expected_revision,
                revision,
                status,
                snapshot,
            } => {
                let changed = transaction.execute(
                    "UPDATE artifacts SET revision = ?2, status = ?3, snapshot = ?4
                     WHERE artifact_id = ?1 AND revision = ?5",
                    params![
                        id,
                        revision as i64,
                        status,
                        snapshot,
                        expected_revision as i64
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::RevisionConflict);
                }
            }
            Mutation::InsertClaim {
                id,
                revision,
                status,
                proposer_principal_id,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO claims(claim_id, revision, status, proposer_principal_id, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![id, revision as i64, status, proposer_principal_id, snapshot],
                )?;
            }
            Mutation::InsertEvidence {
                id,
                revision,
                status,
                claim_id,
                producer_principal_id,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO evidence(evidence_id, revision, status, claim_id, producer_principal_id, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, revision as i64, status, claim_id, producer_principal_id, snapshot],
                )?;
            }
            Mutation::InsertArtifactSet {
                id,
                revision,
                status,
                manifest_digest,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO artifact_sets(artifact_set_id, revision, status, manifest_digest_sha256, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![id, revision as i64, status, manifest_digest, snapshot],
                )?;
            }
            Mutation::UpdateArtifactSet {
                id,
                expected_revision,
                revision,
                status,
                snapshot,
            } => {
                let changed = transaction.execute(
                    "UPDATE artifact_sets SET revision = ?2, status = ?3, snapshot = ?4
                     WHERE artifact_set_id = ?1 AND revision = ?5",
                    params![
                        id,
                        revision as i64,
                        status,
                        snapshot,
                        expected_revision as i64
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::RevisionConflict);
                }
            }
            Mutation::InsertReturn {
                handoff_id,
                handoff_revision,
                handoff_status,
                artifact_set_id,
                handoff_snapshot,
                receipt_id,
                receipt_snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO return_handoffs(return_handoff_id, revision, status, artifact_set_id, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        handoff_id,
                        handoff_revision as i64,
                        handoff_status,
                        artifact_set_id,
                        handoff_snapshot
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO return_receipts(receipt_id, return_handoff_id, artifact_set_id, snapshot)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![receipt_id, handoff_id, artifact_set_id, receipt_snapshot],
                )?;
            }
        }

        transaction.execute(
            "INSERT INTO artifact_events(
               event_id, command_id, aggregate_type, aggregate_id, aggregate_revision,
               request_digest_sha256, event
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                commit.event_id,
                commit.command_id,
                commit.aggregate_type,
                commit.aggregate_id,
                commit.aggregate_revision as i64,
                commit.request_digest_sha256,
                commit.event
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO artifact_idempotency_results(
               authenticated_principal_id, operation, idempotency_scope, idempotency_key,
               request_digest_sha256, aggregate_id, aggregate_revision, event_id, result
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                commit.authenticated_principal_id,
                commit.operation,
                commit.idempotency_scope,
                commit.idempotency_key,
                commit.request_digest_sha256,
                commit.aggregate_id,
                commit.aggregate_revision as i64,
                commit.event_id,
                commit.result
            ],
        )?;

        let primary_outbox_message_id = commit.outbox[0].message_id.clone();
        for outbox in commit.outbox {
            transaction.execute(
                "INSERT INTO artifact_outbox(
                   message_id, source_event_id, source_revision, destination_domain,
                   canonical_payload_digest_sha256, payload, delivery_state, created_at_seconds
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
                params![
                    outbox.message_id,
                    commit.event_id,
                    commit.aggregate_revision as i64,
                    outbox.destination_domain,
                    outbox.payload_digest_sha256,
                    outbox.payload,
                    commit.committed_at_seconds
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO artifact_commit_receipts(
               event_id, aggregate_type, aggregate_id, aggregate_revision,
               primary_outbox_message_id, idempotency_key, request_digest_sha256,
               store_epoch, acknowledged_after_durability_barrier, committed_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
            params![
                commit.event_id,
                commit.aggregate_type,
                commit.aggregate_id,
                commit.aggregate_revision as i64,
                primary_outbox_message_id,
                commit.idempotency_key,
                commit.request_digest_sha256,
                self.store_epoch,
                commit.committed_at_seconds
            ],
        )?;
        transaction.execute(
            "UPDATE artifact_store_metadata
             SET last_committed_revision = ?1, last_event_sequence = ?1
             WHERE singleton = 1",
            [event_sequence],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn pending_projection_outbox(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        self.pending_outbox_for_destination("local-read-model")
    }

    pub fn pending_collaboration_outbox(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        self.pending_outbox_for_destination("collaboration-control")
    }

    fn pending_outbox_for_destination(
        &self,
        destination_domain: &str,
    ) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT message_id,source_event_id,source_revision,canonical_payload_digest_sha256,payload
             FROM artifact_outbox
             WHERE destination_domain=?1 AND delivery_state='pending'
             ORDER BY created_at_seconds,message_id",
        )?;
        let rows = statement.query_map([destination_domain], |row| {
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

    pub fn projection_baselines(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT o.message_id,o.source_event_id,o.source_revision,
                    o.canonical_payload_digest_sha256,o.payload
             FROM artifact_outbox o
             JOIN artifact_events e ON e.event_id=o.source_event_id
             WHERE o.destination_domain='local-read-model'
               AND e.sequence=(
                 SELECT max(latest.sequence) FROM artifact_events latest
                 WHERE latest.aggregate_type=e.aggregate_type
                   AND latest.aggregate_id=e.aggregate_id
               )
             ORDER BY e.aggregate_type,e.aggregate_id",
        )?;
        let rows = statement.query_map([], |row| {
            let revision: i64 = row.get(2)?;
            Ok(PendingProjectionOutbox {
                message_id: format!("bootstrap:{}", row.get::<_, String>(0)?),
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
        self.acknowledge_outbox_for_destination(
            "local-read-model",
            message_id,
            expected_payload_digest_sha256,
        )
    }

    pub fn acknowledge_collaboration_outbox(
        &mut self,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, StoreError> {
        self.acknowledge_outbox_for_destination(
            "collaboration-control",
            message_id,
            expected_payload_digest_sha256,
        )
    }

    fn acknowledge_outbox_for_destination(
        &mut self,
        destination_domain: &str,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.connection.execute(
            "UPDATE artifact_outbox SET delivery_state='consumed'
             WHERE message_id=?1 AND destination_domain=?2
               AND canonical_payload_digest_sha256=?3 AND delivery_state='pending'",
            params![
                message_id,
                destination_domain,
                expected_payload_digest_sha256
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn inspect(&self) -> Result<ArtifactStoreInspection, StoreError> {
        let scalar = |sql: &str| -> Result<u64, StoreError> {
            let value: i64 = self.connection.query_row(sql, [], |row| row.get(0))?;
            Ok(value as u64)
        };
        let (last_revision, last_sequence): (i64, i64) = self.connection.query_row(
            "SELECT last_committed_revision, last_event_sequence
             FROM artifact_store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(ArtifactStoreInspection {
            artifact_count: scalar("SELECT count(*) FROM artifacts")?,
            claim_count: scalar("SELECT count(*) FROM claims")?,
            evidence_count: scalar("SELECT count(*) FROM evidence")?,
            artifact_set_count: scalar("SELECT count(*) FROM artifact_sets")?,
            return_handoff_count: scalar("SELECT count(*) FROM return_handoffs")?,
            return_receipt_count: scalar("SELECT count(*) FROM return_receipts")?,
            event_count: scalar("SELECT count(*) FROM artifact_events")?,
            idempotency_count: scalar("SELECT count(*) FROM artifact_idempotency_results")?,
            outbox_count: scalar("SELECT count(*) FROM artifact_outbox")?,
            commit_receipt_count: scalar("SELECT count(*) FROM artifact_commit_receipts")?,
            last_committed_revision: last_revision as u64,
            last_event_sequence: last_sequence as u64,
        })
    }

    pub fn integrity_is_ok(&self) -> Result<bool, StoreError> {
        let value: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(value == "ok")
    }
}
