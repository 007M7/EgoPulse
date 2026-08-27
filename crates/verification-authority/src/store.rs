use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/verification-authority-store/v1";
const VERIFICATION_STATUS_QUEUED: i32 = 1;
const VERIFICATION_STATUS_RUNNING: i32 = 2;
const VERIFICATION_STATUS_COMPLETED: i32 = 4;

const SCHEMA_V1: &str = r#"
CREATE TABLE verification_store_metadata (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  store_epoch TEXT NOT NULL,
  schema_profile_id TEXT NOT NULL,
  schema_profile_sha256 TEXT NOT NULL,
  last_committed_revision INTEGER NOT NULL DEFAULT 0,
  last_event_sequence INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE checker_profiles (
  checker_profile_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  profile_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE verification_requests (
  verification_request_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  binding_digest_sha256 TEXT NOT NULL,
  policy_snapshot BLOB NOT NULL,
  snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE verification_runs (
  verification_run_id TEXT PRIMARY KEY,
  verification_request_id TEXT NOT NULL UNIQUE,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status INTEGER NOT NULL,
  snapshot BLOB NOT NULL,
  FOREIGN KEY (verification_request_id) REFERENCES verification_requests(verification_request_id)
) STRICT;

CREATE TABLE criterion_results (
  criterion_result_id TEXT PRIMARY KEY,
  verification_run_id TEXT NOT NULL,
  criterion_id TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  UNIQUE(verification_run_id, criterion_id),
  FOREIGN KEY (verification_run_id) REFERENCES verification_runs(verification_run_id)
) STRICT;

CREATE TABLE verification_artifacts (
  verification_artifact_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version >= 1),
  verification_request_id TEXT NOT NULL,
  verification_run_id TEXT NOT NULL UNIQUE,
  conclusion INTEGER NOT NULL,
  canonical_payload_digest_sha256 TEXT NOT NULL,
  snapshot BLOB NOT NULL,
  FOREIGN KEY (verification_request_id) REFERENCES verification_requests(verification_request_id),
  FOREIGN KEY (verification_run_id) REFERENCES verification_runs(verification_run_id)
) STRICT;

CREATE TABLE verification_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  command_id TEXT NOT NULL UNIQUE,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event BLOB NOT NULL
) STRICT;

CREATE TABLE verification_idempotency_results (
  authenticated_principal_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  idempotency_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  event_id TEXT NOT NULL,
  result BLOB NOT NULL,
  PRIMARY KEY (authenticated_principal_id, operation, idempotency_scope, idempotency_key),
  FOREIGN KEY (event_id) REFERENCES verification_events(event_id)
) STRICT;

CREATE TABLE verification_outbox (
  message_id TEXT PRIMARY KEY,
  source_event_id TEXT NOT NULL,
  source_revision INTEGER NOT NULL,
  destination_domain TEXT NOT NULL,
  canonical_payload_digest_sha256 TEXT NOT NULL,
  payload BLOB NOT NULL,
  delivery_state TEXT NOT NULL CHECK (delivery_state IN ('pending', 'delivered', 'consumed', 'held')),
  created_at_seconds INTEGER NOT NULL,
  UNIQUE(source_event_id, destination_domain),
  FOREIGN KEY (source_event_id) REFERENCES verification_events(event_id)
) STRICT;

CREATE TABLE verification_commit_receipts (
  event_id TEXT PRIMARY KEY,
  aggregate_id TEXT NOT NULL,
  aggregate_revision INTEGER NOT NULL,
  primary_outbox_message_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  store_epoch TEXT NOT NULL,
  acknowledged_after_durability_barrier INTEGER NOT NULL CHECK (acknowledged_after_durability_barrier = 1),
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (event_id) REFERENCES verification_events(event_id),
  FOREIGN KEY (primary_outbox_message_id) REFERENCES verification_outbox(message_id)
) STRICT;
"#;

#[derive(Debug, Error)]
pub(super) enum StoreError {
    #[error("verification authority storage operation failed")]
    Sql(#[from] rusqlite::Error),
    #[error("verification authority migration failed")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("verification authority store directory could not be created")]
    Directory(#[source] std::io::Error),
    #[error("verification authority SQLCipher support is unavailable")]
    CipherUnavailable,
    #[error("verification authority store generation mismatch")]
    StoreGenerationMismatch,
    #[error("verification authority store integrity check failed")]
    IntegrityFailure,
    #[error("verification authority revision precondition failed")]
    RevisionConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IdempotencyRecord {
    pub request_digest_sha256: String,
    pub result: Vec<u8>,
}

pub(super) enum Mutation {
    InsertProfile {
        id: String,
        revision: u64,
        status: i32,
        digest: String,
        snapshot: Vec<u8>,
    },
    InsertRequest {
        id: String,
        revision: u64,
        status: i32,
        binding_digest: String,
        policy_snapshot: Vec<u8>,
        snapshot: Vec<u8>,
    },
    StartRun {
        request_id: String,
        expected_request_revision: u64,
        request_revision: u64,
        request_status: i32,
        request_snapshot: Vec<u8>,
        run_id: String,
        run_revision: u64,
        run_status: i32,
        run_snapshot: Vec<u8>,
    },
    RecordCriterion {
        run_id: String,
        expected_run_revision: u64,
        run_revision: u64,
        run_status: i32,
        run_snapshot: Vec<u8>,
        criterion_result_id: String,
        criterion_id: String,
        criterion_snapshot: Vec<u8>,
    },
    Complete {
        request_id: String,
        expected_request_revision: u64,
        request_revision: u64,
        request_status: i32,
        request_snapshot: Vec<u8>,
        run_id: String,
        expected_run_revision: u64,
        run_revision: u64,
        run_status: i32,
        run_snapshot: Vec<u8>,
        artifact_id: String,
        artifact_version: u64,
        conclusion: i32,
        payload_digest: String,
        artifact_snapshot: Vec<u8>,
    },
    Hold {
        request_id: String,
        expected_request_revision: u64,
        request_revision: u64,
        request_status: i32,
        request_snapshot: Vec<u8>,
        run_id: String,
        expected_run_revision: u64,
        run_revision: u64,
        run_status: i32,
        run_snapshot: Vec<u8>,
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
pub struct VerificationStoreInspection {
    pub checker_profile_count: u64,
    pub request_count: u64,
    pub run_count: u64,
    pub criterion_result_count: u64,
    pub verification_artifact_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub commit_receipt_count: u64,
}

pub(super) struct VerificationStore {
    connection: Connection,
    store_epoch: String,
}

impl VerificationStore {
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
            "INSERT OR IGNORE INTO verification_store_metadata(
               singleton, store_epoch, schema_profile_id, schema_profile_sha256
             ) VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        let metadata: (String, String, String) = connection.query_row(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256
             FROM verification_store_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if metadata.0 != store_epoch
            || metadata.1 != SCHEMA_PROFILE_ID
            || metadata.2 != schema_digest
        {
            return Err(StoreError::StoreGenerationMismatch);
        }
        if !Self::integrity(&connection)? {
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
                 FROM verification_idempotency_results
                 WHERE authenticated_principal_id=?1 AND operation=?2
                   AND idempotency_scope=?3 AND idempotency_key=?4",
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

    pub fn profile(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("checker_profiles", "checker_profile_id", id)
    }

    pub fn request(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("verification_requests", "verification_request_id", id)
    }

    pub fn execution_requests(&self) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot FROM verification_requests
             WHERE status IN (?1, ?2, ?3)
             ORDER BY revision ASC, verification_request_id ASC",
        )?;
        let rows = statement.query_map(
            params![
                VERIFICATION_STATUS_QUEUED,
                VERIFICATION_STATUS_RUNNING,
                VERIFICATION_STATUS_COMPLETED
            ],
            |row| row.get(0),
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn request_policy(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.connection
            .query_row(
                "SELECT policy_snapshot FROM verification_requests WHERE verification_request_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn run(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("verification_runs", "verification_run_id", id)
    }

    pub fn artifact(&self, id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.snapshot("verification_artifacts", "verification_artifact_id", id)
    }

    pub fn artifacts(&self) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot FROM verification_artifacts
             ORDER BY version DESC, verification_artifact_id ASC",
        )?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn criterion_results(&self, run_id: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot FROM criterion_results
             WHERE verification_run_id=?1 ORDER BY criterion_id ASC",
        )?;
        let rows = statement.query_map([run_id], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn commit(&mut self, commit: AuthorityCommit) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::apply_mutation(&transaction, &commit.mutation)?;
        transaction.execute(
            "INSERT INTO verification_events(
               event_id, command_id, aggregate_id, aggregate_revision,
               request_digest_sha256, event
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                commit.event_id,
                commit.command_id,
                commit.aggregate_id,
                commit.aggregate_revision as i64,
                commit.request_digest_sha256,
                commit.event,
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO verification_idempotency_results(
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
                commit.result,
            ],
        )?;
        let primary_outbox = commit
            .outbox
            .first()
            .ok_or(StoreError::IntegrityFailure)?
            .message_id
            .clone();
        for outbox in commit.outbox {
            transaction.execute(
                "INSERT INTO verification_outbox(
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
                    commit.committed_at_seconds,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO verification_commit_receipts(
               event_id, aggregate_id, aggregate_revision, primary_outbox_message_id,
               idempotency_key, request_digest_sha256, store_epoch,
               acknowledged_after_durability_barrier, committed_at_seconds
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            params![
                commit.event_id,
                commit.aggregate_id,
                commit.aggregate_revision as i64,
                primary_outbox,
                commit.idempotency_key,
                commit.request_digest_sha256,
                self.store_epoch,
                commit.committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "UPDATE verification_store_metadata
             SET last_committed_revision=?1, last_event_sequence=?2 WHERE singleton=1",
            params![commit.aggregate_revision as i64, event_sequence],
        )?;
        transaction.commit()?;
        self.connection
            .pragma_update(None, "wal_checkpoint", "FULL")?;
        Ok(())
    }

    pub fn pending_projection_outbox(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT message_id,source_event_id,source_revision,canonical_payload_digest_sha256,payload
             FROM verification_outbox
             WHERE destination_domain='local-read-model' AND delivery_state='pending'
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

    pub fn projection_baselines(&self) -> Result<Vec<PendingProjectionOutbox>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT o.message_id,o.source_event_id,o.source_revision,
                    o.canonical_payload_digest_sha256,o.payload
             FROM verification_outbox o
             JOIN verification_events e ON e.event_id=o.source_event_id
             WHERE o.destination_domain='local-read-model'
               AND e.sequence=(
                 SELECT max(latest.sequence) FROM verification_events latest
                 WHERE latest.aggregate_id=e.aggregate_id
               )
             ORDER BY e.aggregate_id",
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
        let changed = self.connection.execute(
            "UPDATE verification_outbox SET delivery_state='consumed'
             WHERE message_id=?1 AND destination_domain='local-read-model'
               AND canonical_payload_digest_sha256=?2 AND delivery_state='pending'",
            params![message_id, expected_payload_digest_sha256],
        )?;
        Ok(changed == 1)
    }

    pub fn inspect(&self) -> Result<VerificationStoreInspection, StoreError> {
        Ok(VerificationStoreInspection {
            checker_profile_count: self.count("checker_profiles")?,
            request_count: self.count("verification_requests")?,
            run_count: self.count("verification_runs")?,
            criterion_result_count: self.count("criterion_results")?,
            verification_artifact_count: self.count("verification_artifacts")?,
            event_count: self.count("verification_events")?,
            idempotency_count: self.count("verification_idempotency_results")?,
            outbox_count: self.count("verification_outbox")?,
            commit_receipt_count: self.count("verification_commit_receipts")?,
        })
    }

    pub fn integrity_is_ok(&self) -> Result<bool, StoreError> {
        Self::integrity(&self.connection)
    }

    fn snapshot(
        &self,
        table: &str,
        id_column: &str,
        id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let sql = format!("SELECT snapshot FROM {table} WHERE {id_column}=?1");
        self.connection
            .query_row(&sql, [id], |row| row.get(0))
            .optional()
            .map_err(StoreError::from)
    }

    fn count(&self, table: &str) -> Result<u64, StoreError> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = self.connection.query_row(&sql, [], |row| row.get(0))?;
        Ok(count as u64)
    }

    fn integrity(connection: &Connection) -> Result<bool, StoreError> {
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(integrity == "ok")
    }

    fn apply_mutation(
        transaction: &Transaction<'_>,
        mutation: &Mutation,
    ) -> Result<(), StoreError> {
        match mutation {
            Mutation::InsertProfile {
                id,
                revision,
                status,
                digest,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO checker_profiles(checker_profile_id, revision, status, profile_digest_sha256, snapshot)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![id, *revision as i64, status, digest, snapshot],
                )?;
            }
            Mutation::InsertRequest {
                id,
                revision,
                status,
                binding_digest,
                policy_snapshot,
                snapshot,
            } => {
                transaction.execute(
                    "INSERT INTO verification_requests(
                       verification_request_id, revision, status, binding_digest_sha256, policy_snapshot, snapshot
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, *revision as i64, status, binding_digest, policy_snapshot, snapshot],
                )?;
            }
            Mutation::StartRun {
                request_id,
                expected_request_revision,
                request_revision,
                request_status,
                request_snapshot,
                run_id,
                run_revision,
                run_status,
                run_snapshot,
            } => {
                let changed = transaction.execute(
                    "UPDATE verification_requests SET revision=?1, status=?2, snapshot=?3
                     WHERE verification_request_id=?4 AND revision=?5",
                    params![
                        *request_revision as i64,
                        request_status,
                        request_snapshot,
                        request_id,
                        *expected_request_revision as i64
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::RevisionConflict);
                }
                transaction.execute(
                    "INSERT INTO verification_runs(
                       verification_run_id, verification_request_id, revision, status, snapshot
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        run_id,
                        request_id,
                        *run_revision as i64,
                        run_status,
                        run_snapshot
                    ],
                )?;
            }
            Mutation::RecordCriterion {
                run_id,
                expected_run_revision,
                run_revision,
                run_status,
                run_snapshot,
                criterion_result_id,
                criterion_id,
                criterion_snapshot,
            } => {
                Self::update_run(
                    transaction,
                    run_id,
                    *expected_run_revision,
                    *run_revision,
                    *run_status,
                    run_snapshot,
                )?;
                transaction.execute(
                    "INSERT INTO criterion_results(
                       criterion_result_id, verification_run_id, criterion_id, snapshot
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![
                        criterion_result_id,
                        run_id,
                        criterion_id,
                        criterion_snapshot
                    ],
                )?;
            }
            Mutation::Complete {
                request_id,
                expected_request_revision,
                request_revision,
                request_status,
                request_snapshot,
                run_id,
                expected_run_revision,
                run_revision,
                run_status,
                run_snapshot,
                artifact_id,
                artifact_version,
                conclusion,
                payload_digest,
                artifact_snapshot,
            } => {
                Self::update_request(
                    transaction,
                    request_id,
                    *expected_request_revision,
                    *request_revision,
                    *request_status,
                    request_snapshot,
                )?;
                Self::update_run(
                    transaction,
                    run_id,
                    *expected_run_revision,
                    *run_revision,
                    *run_status,
                    run_snapshot,
                )?;
                transaction.execute(
                    "INSERT INTO verification_artifacts(
                       verification_artifact_id, version, verification_request_id,
                       verification_run_id, conclusion, canonical_payload_digest_sha256, snapshot
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        artifact_id,
                        *artifact_version as i64,
                        request_id,
                        run_id,
                        conclusion,
                        payload_digest,
                        artifact_snapshot
                    ],
                )?;
            }
            Mutation::Hold {
                request_id,
                expected_request_revision,
                request_revision,
                request_status,
                request_snapshot,
                run_id,
                expected_run_revision,
                run_revision,
                run_status,
                run_snapshot,
            } => {
                Self::update_request(
                    transaction,
                    request_id,
                    *expected_request_revision,
                    *request_revision,
                    *request_status,
                    request_snapshot,
                )?;
                Self::update_run(
                    transaction,
                    run_id,
                    *expected_run_revision,
                    *run_revision,
                    *run_status,
                    run_snapshot,
                )?;
            }
        }
        Ok(())
    }

    fn update_run(
        transaction: &Transaction<'_>,
        run_id: &str,
        expected_revision: u64,
        revision: u64,
        status: i32,
        snapshot: &[u8],
    ) -> Result<(), StoreError> {
        let changed = transaction.execute(
            "UPDATE verification_runs SET revision=?1, status=?2, snapshot=?3
             WHERE verification_run_id=?4 AND revision=?5",
            params![
                revision as i64,
                status,
                snapshot,
                run_id,
                expected_revision as i64
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }

    fn update_request(
        transaction: &Transaction<'_>,
        request_id: &str,
        expected_revision: u64,
        revision: u64,
        status: i32,
        snapshot: &[u8],
    ) -> Result<(), StoreError> {
        let changed = transaction.execute(
            "UPDATE verification_requests SET revision=?1, status=?2, snapshot=?3
             WHERE verification_request_id=?4 AND revision=?5",
            params![
                revision as i64,
                status,
                snapshot,
                request_id,
                expected_revision as i64
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }
}
