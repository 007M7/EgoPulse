use super::{
    ContextGovernanceState, ContextRevokeReceipt, ContextSnapshot, ContextStoreInspection,
    DispatchContextConsumptionAuthorizationReceipt, MemoryUseReceipt,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use rusqlite_migration::{M, Migrations};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::RefCell;
use std::fs;
use std::path::Path;
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const SCHEMA_PROFILE_ID: &str = "egopulse/context-authority-store/v1";
const WRITER_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
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
const R9A_SCHEMA: &str = r#"
ALTER TABLE context_snapshots ADD COLUMN state_revision INTEGER NOT NULL DEFAULT 1
  CHECK (state_revision >= 1);

CREATE TABLE context_revoke_receipts (
  event_id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  snapshot_revision INTEGER NOT NULL,
  content_digest_sha256 TEXT NOT NULL,
  previous_state_revision INTEGER NOT NULL,
  result_state_revision INTEGER NOT NULL,
  reason_code TEXT NOT NULL,
  evidence_refs TEXT NOT NULL,
  confirmation_proof_ref TEXT NOT NULL,
  command_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  causation_id TEXT,
  request_digest_sha256 TEXT NOT NULL,
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (snapshot_id) REFERENCES context_snapshots(snapshot_id),
  FOREIGN KEY (event_id) REFERENCES context_events(event_id)
) STRICT;

CREATE TABLE context_revoke_idempotency (
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  event_id TEXT NOT NULL,
  PRIMARY KEY (principal_id, idempotency_key),
  FOREIGN KEY (event_id) REFERENCES context_revoke_receipts(event_id)
) STRICT;

CREATE TABLE context_dispatch_authorizations (
  authorization_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  snapshot_id TEXT NOT NULL,
  snapshot_revision INTEGER NOT NULL,
  observed_state_revision INTEGER NOT NULL,
  principal_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL UNIQUE,
  input_digest_sha256 TEXT NOT NULL,
  expected_scope_ref TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  causation_id TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  committed_at_seconds INTEGER NOT NULL,
  FOREIGN KEY (snapshot_id) REFERENCES context_snapshots(snapshot_id),
  FOREIGN KEY (event_id) REFERENCES context_events(event_id)
) STRICT;

CREATE TABLE context_dispatch_authorization_idempotency (
  principal_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest_sha256 TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  PRIMARY KEY (principal_id, idempotency_key),
  FOREIGN KEY (authorization_id)
    REFERENCES context_dispatch_authorizations(authorization_id)
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
    #[error("context snapshot was not found")]
    NotFound,
    #[error("context snapshot owner does not match")]
    OwnerMismatch,
    #[error("context snapshot is revoked")]
    Revoked,
    #[error("context snapshot has expired")]
    Expired,
    #[error("context snapshot scope does not match")]
    ScopeMismatch,
    #[error("context governance state revision does not match")]
    StateRevisionConflict,
    #[error("context idempotency key conflicts")]
    IdempotencyConflict,
    #[error("context dispatch authorization tuple conflicts")]
    AuthorizationTupleConflict,
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
    pub(super) state_revision: u64,
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

pub(super) struct ContextRevokeCommit<'a> {
    pub(super) snapshot_id: &'a str,
    pub(super) expected_state_revision: u64,
    pub(super) principal_id: &'a str,
    pub(super) command_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) reason_code: &'a str,
    pub(super) evidence_refs: &'a [String],
    pub(super) confirmation_proof_ref: &'a str,
    pub(super) correlation_id: &'a str,
    pub(super) causation_id: Option<&'a str>,
    pub(super) request_digest_sha256: &'a str,
    pub(super) event_id: &'a str,
    pub(super) committed_at_seconds: i64,
}

pub(super) struct DispatchAuthorizationCommit<'a> {
    pub(super) snapshot_id: &'a str,
    pub(super) expected_state_revision: u64,
    pub(super) principal_id: &'a str,
    pub(super) command_id: &'a str,
    pub(super) idempotency_key: &'a str,
    pub(super) attempt_id: &'a str,
    pub(super) dispatch_id: &'a str,
    pub(super) input_digest_sha256: &'a str,
    pub(super) expected_scope_ref: &'a str,
    pub(super) correlation_id: &'a str,
    pub(super) causation_id: &'a str,
    pub(super) request_digest_sha256: &'a str,
    pub(super) authorization_id: &'a str,
    pub(super) event_id: &'a str,
    pub(super) committed_at_seconds: i64,
}

pub(super) struct RecoveryLineageRequest<'a> {
    pub(super) snapshot_id: &'a str,
    pub(super) attempt_id: &'a str,
    pub(super) dispatch_id: &'a str,
    pub(super) input_digest_sha256: &'a str,
    pub(super) expected_scope_ref: &'a str,
}

struct ContextEventInsert<'a> {
    event_id: &'a str,
    snapshot_id: &'a str,
    operation: &'a str,
    principal_id: &'a str,
    idempotency_key: &'a str,
    request_digest_sha256: &'a str,
    committed_at_seconds: i64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestWriteOperation {
    Revoke,
    AuthorizeDispatchConsumption,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestWritePhase {
    BeforeBeginImmediate,
    AfterBeginImmediate,
    Busy,
}

#[cfg(test)]
type TestWriteHook = Arc<dyn Fn(TestWriteOperation, TestWritePhase) + Send + Sync>;

#[cfg(test)]
thread_local! {
    static TEST_BUSY_CONTEXT: RefCell<Option<(TestWriteHook, TestWriteOperation)>> =
        RefCell::new(None);
}

#[cfg(test)]
struct TestBusyContextGuard;

#[cfg(test)]
impl TestBusyContextGuard {
    fn install(hook: Option<TestWriteHook>, operation: TestWriteOperation) -> Self {
        TEST_BUSY_CONTEXT.with(|context| {
            *context.borrow_mut() = hook.map(|hook| (hook, operation));
        });
        Self
    }
}

#[cfg(test)]
impl Drop for TestBusyContextGuard {
    fn drop(&mut self) {
        TEST_BUSY_CONTEXT.with(|context| {
            context.borrow_mut().take();
        });
    }
}

pub(super) struct ContextStore {
    connection: Connection,
    #[cfg(test)]
    test_write_hook: Option<TestWriteHook>,
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
        connection.busy_timeout(WRITER_BUSY_TIMEOUT)?;
        Migrations::new(vec![
            M::up(LEGACY_SCHEMA),
            M::up(MEMORY_USE_SCHEMA),
            M::up(R9A_SCHEMA),
        ])
        .to_latest(&mut connection)?;
        let schema_digest = schema_digest();
        let legacy_schema_digest = hex::encode(Sha256::digest(LEGACY_SCHEMA.as_bytes()));
        let pre_r9a_schema_digest = pre_r9a_schema_digest();
        connection.execute(
            "INSERT OR IGNORE INTO context_store_metadata(singleton, store_epoch, schema_profile_id, schema_profile_sha256)
             VALUES(1, ?1, ?2, ?3)",
            params![store_epoch, SCHEMA_PROFILE_ID, schema_digest],
        )?;
        connection.execute(
            "UPDATE context_store_metadata SET schema_profile_sha256=?1
             WHERE singleton=1 AND schema_profile_sha256 IN (?2,?3)",
            params![schema_digest, legacy_schema_digest, pre_r9a_schema_digest],
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
        Ok(Self {
            connection,
            #[cfg(test)]
            test_write_hook: None,
        })
    }

    #[cfg(test)]
    pub(super) fn set_test_write_hook(&mut self, hook: TestWriteHook) -> Result<(), StoreError> {
        self.connection.busy_handler(Some(test_busy_handler))?;
        self.test_write_hook = Some(hook);
        Ok(())
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
        let raw = self
            .connection
            .query_row(
                "SELECT descriptor,compiled_context,state,state_revision,revision,
                        compiled_context_sha256,expires_at_seconds
                 FROM context_snapshots WHERE snapshot_id=?1",
                [snapshot_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        raw.map(|value| decode_stored_snapshot(snapshot_id, value))
            .transpose()
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
        let event_sequence = transaction.last_insert_rowid() as u64;
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
        update_event_sequence(&transaction, event_sequence)?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn revoke(
        &mut self,
        commit: ContextRevokeCommit<'_>,
    ) -> Result<ContextRevokeReceipt, StoreError> {
        #[cfg(test)]
        let test_write_hook = self.test_write_hook.clone();
        #[cfg(test)]
        let _test_busy_context =
            TestBusyContextGuard::install(test_write_hook.clone(), TestWriteOperation::Revoke);
        #[cfg(test)]
        notify_test_write_hook(
            &test_write_hook,
            TestWriteOperation::Revoke,
            TestWritePhase::BeforeBeginImmediate,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(test)]
        notify_test_write_hook(
            &test_write_hook,
            TestWriteOperation::Revoke,
            TestWritePhase::AfterBeginImmediate,
        );

        if let Some((request_digest, event_id)) = transaction
            .query_row(
                "SELECT request_digest_sha256,event_id
                 FROM context_revoke_idempotency
                 WHERE principal_id=?1 AND idempotency_key=?2",
                params![commit.principal_id, commit.idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if request_digest != commit.request_digest_sha256 {
                return Err(StoreError::IdempotencyConflict);
            }
            let receipt = revoke_receipt(&transaction, &event_id, true)?
                .ok_or(StoreError::IntegrityFailure)?;
            if receipt.request_digest_sha256 != request_digest {
                return Err(StoreError::IntegrityFailure);
            }
            let stored = snapshot_in_transaction(&transaction, &receipt.snapshot_id)?
                .ok_or(StoreError::IntegrityFailure)?;
            if stored.snapshot.revision != receipt.snapshot_revision
                || stored.snapshot.compiled_context_sha256 != receipt.content_digest_sha256
                || stored.state != "revoked"
                || stored.state_revision != receipt.result_state_revision
            {
                return Err(StoreError::IntegrityFailure);
            }
            transaction.commit()?;
            return Ok(receipt);
        }

        let stored = snapshot_in_transaction(&transaction, commit.snapshot_id)?
            .ok_or(StoreError::NotFound)?;
        if stored.snapshot.owner_principal_id != commit.principal_id {
            return Err(StoreError::OwnerMismatch);
        }
        if stored.state == "revoked" {
            return Err(StoreError::Revoked);
        }
        if stored.state_revision != commit.expected_state_revision {
            return Err(StoreError::StateRevisionConflict);
        }
        let result_state_revision = stored
            .state_revision
            .checked_add(1)
            .ok_or(StoreError::IntegrityFailure)?;
        let changed = transaction.execute(
            "UPDATE context_snapshots
             SET state='revoked',state_revision=?2
             WHERE snapshot_id=?1 AND state='issued' AND state_revision=?3",
            params![
                commit.snapshot_id,
                result_state_revision as i64,
                stored.state_revision as i64
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StateRevisionConflict);
        }

        let sequence = insert_context_event(
            &transaction,
            ContextEventInsert {
                event_id: commit.event_id,
                snapshot_id: commit.snapshot_id,
                operation: "revoke",
                principal_id: commit.principal_id,
                idempotency_key: commit.idempotency_key,
                request_digest_sha256: commit.request_digest_sha256,
                committed_at_seconds: commit.committed_at_seconds,
            },
        )?;
        let evidence_refs = serde_json::to_string(commit.evidence_refs)
            .map_err(|_| StoreError::DescriptorDecode)?;
        transaction.execute(
            "INSERT INTO context_revoke_receipts(
               event_id,snapshot_id,snapshot_revision,content_digest_sha256,
               previous_state_revision,result_state_revision,reason_code,evidence_refs,
               confirmation_proof_ref,command_id,correlation_id,causation_id,
               request_digest_sha256,committed_at_seconds)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                commit.event_id,
                commit.snapshot_id,
                stored.snapshot.revision as i64,
                stored.snapshot.compiled_context_sha256,
                stored.state_revision as i64,
                result_state_revision as i64,
                commit.reason_code,
                evidence_refs,
                commit.confirmation_proof_ref,
                commit.command_id,
                commit.correlation_id,
                commit.causation_id,
                commit.request_digest_sha256,
                commit.committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_revoke_idempotency(
               principal_id,idempotency_key,request_digest_sha256,event_id)
             VALUES(?1,?2,?3,?4)",
            params![
                commit.principal_id,
                commit.idempotency_key,
                commit.request_digest_sha256,
                commit.event_id,
            ],
        )?;
        update_event_sequence(&transaction, sequence)?;
        transaction.commit()?;
        Ok(ContextRevokeReceipt {
            snapshot_id: commit.snapshot_id.to_owned(),
            snapshot_revision: stored.snapshot.revision,
            content_digest_sha256: stored.snapshot.compiled_context_sha256,
            previous_state_revision: stored.state_revision,
            result_state_revision,
            previous_state: ContextGovernanceState::Issued,
            result_state: ContextGovernanceState::Revoked,
            request_digest_sha256: commit.request_digest_sha256.to_owned(),
            event_id: commit.event_id.to_owned(),
            committed_at_seconds: commit.committed_at_seconds,
            replayed: false,
        })
    }

    pub(super) fn authorize_dispatch_consumption(
        &mut self,
        commit: DispatchAuthorizationCommit<'_>,
    ) -> Result<DispatchContextConsumptionAuthorizationReceipt, StoreError> {
        #[cfg(test)]
        let test_write_hook = self.test_write_hook.clone();
        #[cfg(test)]
        let _test_busy_context = TestBusyContextGuard::install(
            test_write_hook.clone(),
            TestWriteOperation::AuthorizeDispatchConsumption,
        );
        #[cfg(test)]
        notify_test_write_hook(
            &test_write_hook,
            TestWriteOperation::AuthorizeDispatchConsumption,
            TestWritePhase::BeforeBeginImmediate,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(test)]
        notify_test_write_hook(
            &test_write_hook,
            TestWriteOperation::AuthorizeDispatchConsumption,
            TestWritePhase::AfterBeginImmediate,
        );

        if let Some((request_digest, authorization_id)) = transaction
            .query_row(
                "SELECT request_digest_sha256,authorization_id
                 FROM context_dispatch_authorization_idempotency
                 WHERE principal_id=?1 AND idempotency_key=?2",
                params![commit.principal_id, commit.idempotency_key],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if request_digest != commit.request_digest_sha256 {
                return Err(StoreError::IdempotencyConflict);
            }
            let receipt = dispatch_authorization_receipt(&transaction, &authorization_id, true)?
                .ok_or(StoreError::IntegrityFailure)?;
            if receipt.request_digest_sha256 != request_digest {
                return Err(StoreError::IntegrityFailure);
            }
            let stored = snapshot_in_transaction(&transaction, &receipt.snapshot_id)?
                .ok_or(StoreError::IntegrityFailure)?;
            let current_state_is_valid = match stored.state.as_str() {
                "issued" => stored.state_revision == receipt.observed_state_revision,
                "revoked" => {
                    stored.state_revision == receipt.observed_state_revision.saturating_add(1)
                }
                _ => false,
            };
            if stored.snapshot.revision != receipt.snapshot_revision
                || stored.snapshot.target_scope_ref != receipt.expected_scope_ref
                || !current_state_is_valid
            {
                return Err(StoreError::IntegrityFailure);
            }
            transaction.commit()?;
            return Ok(receipt);
        }

        if transaction
            .query_row(
                "SELECT 1 FROM context_dispatch_authorizations WHERE dispatch_id=?1",
                [commit.dispatch_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(StoreError::AuthorizationTupleConflict);
        }

        let stored = snapshot_in_transaction(&transaction, commit.snapshot_id)?
            .ok_or(StoreError::NotFound)?;
        if stored.state == "revoked" {
            return Err(StoreError::Revoked);
        }
        if stored.state_revision != commit.expected_state_revision {
            return Err(StoreError::StateRevisionConflict);
        }
        if stored.snapshot.expires_at_seconds <= commit.committed_at_seconds {
            return Err(StoreError::Expired);
        }
        if stored.snapshot.target_scope_ref != commit.expected_scope_ref {
            return Err(StoreError::ScopeMismatch);
        }

        let sequence = insert_context_event(
            &transaction,
            ContextEventInsert {
                event_id: commit.event_id,
                snapshot_id: commit.snapshot_id,
                operation: "authorize-dispatch-consumption",
                principal_id: commit.principal_id,
                idempotency_key: commit.idempotency_key,
                request_digest_sha256: commit.request_digest_sha256,
                committed_at_seconds: commit.committed_at_seconds,
            },
        )?;
        transaction.execute(
            "INSERT INTO context_dispatch_authorizations(
               authorization_id,event_id,snapshot_id,snapshot_revision,
               observed_state_revision,principal_id,command_id,attempt_id,dispatch_id,
               input_digest_sha256,expected_scope_ref,correlation_id,causation_id,
               request_digest_sha256,committed_at_seconds)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                commit.authorization_id,
                commit.event_id,
                commit.snapshot_id,
                stored.snapshot.revision as i64,
                stored.state_revision as i64,
                commit.principal_id,
                commit.command_id,
                commit.attempt_id,
                commit.dispatch_id,
                commit.input_digest_sha256,
                commit.expected_scope_ref,
                commit.correlation_id,
                commit.causation_id,
                commit.request_digest_sha256,
                commit.committed_at_seconds,
            ],
        )?;
        transaction.execute(
            "INSERT INTO context_dispatch_authorization_idempotency(
               principal_id,idempotency_key,request_digest_sha256,authorization_id)
             VALUES(?1,?2,?3,?4)",
            params![
                commit.principal_id,
                commit.idempotency_key,
                commit.request_digest_sha256,
                commit.authorization_id,
            ],
        )?;
        update_event_sequence(&transaction, sequence)?;
        transaction.commit()?;
        Ok(DispatchContextConsumptionAuthorizationReceipt {
            authorization_id: commit.authorization_id.to_owned(),
            snapshot_id: commit.snapshot_id.to_owned(),
            snapshot_revision: stored.snapshot.revision,
            observed_state_revision: stored.state_revision,
            attempt_id: commit.attempt_id.to_owned(),
            dispatch_id: commit.dispatch_id.to_owned(),
            input_digest_sha256: commit.input_digest_sha256.to_owned(),
            expected_scope_ref: commit.expected_scope_ref.to_owned(),
            request_digest_sha256: commit.request_digest_sha256.to_owned(),
            event_id: commit.event_id.to_owned(),
            committed_at_seconds: commit.committed_at_seconds,
            replayed: false,
        })
    }

    pub(super) fn recovery_material(
        &self,
        request: RecoveryLineageRequest<'_>,
    ) -> Result<StoredSnapshot, StoreError> {
        let lineage: Option<(String, String, String, String, String)> = self
            .connection
            .query_row(
                "SELECT snapshot_id,attempt_id,input_digest_sha256,expected_scope_ref,
                        authorization_id
                 FROM context_dispatch_authorizations WHERE dispatch_id=?1",
                [request.dispatch_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let lineage = lineage.ok_or(StoreError::NotFound)?;
        if lineage.0 != request.snapshot_id
            || lineage.1 != request.attempt_id
            || lineage.2 != request.input_digest_sha256
            || lineage.3 != request.expected_scope_ref
            || lineage.4.trim().is_empty()
        {
            return Err(StoreError::AuthorizationTupleConflict);
        }
        let receipt = dispatch_authorization_receipt(&self.connection, &lineage.4, false)?
            .ok_or(StoreError::IntegrityFailure)?;
        if receipt.snapshot_id != request.snapshot_id
            || receipt.attempt_id != request.attempt_id
            || receipt.dispatch_id != request.dispatch_id
            || receipt.input_digest_sha256 != request.input_digest_sha256
            || receipt.expected_scope_ref != request.expected_scope_ref
        {
            return Err(StoreError::AuthorizationTupleConflict);
        }
        self.snapshot_with_bytes(request.snapshot_id)?
            .ok_or(StoreError::IntegrityFailure)
    }

    pub(super) fn verify_dispatch_authorization(
        &self,
        receipt: &DispatchContextConsumptionAuthorizationReceipt,
    ) -> Result<(), StoreError> {
        let stored = dispatch_authorization_receipt(
            &self.connection,
            &receipt.authorization_id,
            receipt.replayed,
        )?
        .ok_or(StoreError::NotFound)?;
        if stored != *receipt {
            return Err(StoreError::AuthorizationTupleConflict);
        }
        let snapshot = self
            .snapshot_with_bytes(&receipt.snapshot_id)?
            .ok_or(StoreError::IntegrityFailure)?;
        let current_state_is_valid = match snapshot.state.as_str() {
            "issued" => snapshot.state_revision == receipt.observed_state_revision,
            "revoked" => {
                snapshot.state_revision == receipt.observed_state_revision.saturating_add(1)
            }
            _ => false,
        };
        if snapshot.snapshot.revision != receipt.snapshot_revision
            || snapshot.snapshot.target_scope_ref != receipt.expected_scope_ref
            || !current_state_is_valid
        {
            return Err(StoreError::IntegrityFailure);
        }
        let event: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT operation,snapshot_id,request_digest_sha256
                 FROM context_events WHERE event_id=?1",
                [&receipt.event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if event
            != Some((
                "authorize-dispatch-consumption".to_owned(),
                receipt.snapshot_id.clone(),
                receipt.request_digest_sha256.clone(),
            ))
        {
            return Err(StoreError::IntegrityFailure);
        }
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
            revoke_receipt_count: scalar("SELECT count(*) FROM context_revoke_receipts")?,
            revoke_idempotency_count: scalar("SELECT count(*) FROM context_revoke_idempotency")?,
            dispatch_authorization_count: scalar(
                "SELECT count(*) FROM context_dispatch_authorizations",
            )?,
            dispatch_authorization_idempotency_count: scalar(
                "SELECT count(*) FROM context_dispatch_authorization_idempotency",
            )?,
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

#[cfg(test)]
fn notify_test_write_hook(
    hook: &Option<TestWriteHook>,
    operation: TestWriteOperation,
    phase: TestWritePhase,
) {
    if let Some(hook) = hook {
        hook(operation, phase);
    }
}

#[cfg(test)]
fn test_busy_handler(_retry_count: i32) -> bool {
    TEST_BUSY_CONTEXT.with(|context| {
        if let Some((hook, operation)) = context.borrow().as_ref() {
            hook(*operation, TestWritePhase::Busy);
            true
        } else {
            false
        }
    })
}

fn snapshot_in_transaction(
    transaction: &Transaction<'_>,
    snapshot_id: &str,
) -> Result<Option<StoredSnapshot>, StoreError> {
    let raw: Option<RawStoredSnapshot> = transaction
        .query_row(
            "SELECT descriptor,compiled_context,state,state_revision,revision,
                    compiled_context_sha256,expires_at_seconds
             FROM context_snapshots WHERE snapshot_id=?1",
            [snapshot_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    raw.map(|value| decode_stored_snapshot(snapshot_id, value))
        .transpose()
}

fn revoke_receipt(
    connection: &Connection,
    event_id: &str,
    replayed: bool,
) -> Result<Option<ContextRevokeReceipt>, StoreError> {
    let raw: Option<RawRevokeReceipt> = connection
        .query_row(
            "SELECT snapshot_id,snapshot_revision,content_digest_sha256,
                    previous_state_revision,result_state_revision,
                    request_digest_sha256,committed_at_seconds,reason_code,
                    evidence_refs,confirmation_proof_ref
             FROM context_revoke_receipts WHERE event_id=?1",
            [event_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    let Some(value) = raw else {
        return Ok(None);
    };
    let event: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT operation,snapshot_id,request_digest_sha256,principal_id
             FROM context_events WHERE event_id=?1",
            [event_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some(event) = event else {
        return Err(StoreError::IntegrityFailure);
    };
    let evidence_refs: Vec<String> =
        serde_json::from_str(&value.8).map_err(|_| StoreError::IntegrityFailure)?;
    let canonical_digest = super::context_revoke_semantic_digest(
        &event.3,
        &value.0,
        value.3.max(0) as u64,
        &value.7,
        &evidence_refs,
        &value.9,
    );
    if value.1 < 1
        || value.3 < 1
        || value.4 != value.3 + 1
        || canonical_digest != value.5
        || event.0 != "revoke"
        || event.1 != value.0
        || event.2 != value.5
    {
        return Err(StoreError::IntegrityFailure);
    }
    Ok(Some(ContextRevokeReceipt {
        snapshot_id: value.0,
        snapshot_revision: value.1 as u64,
        content_digest_sha256: value.2,
        previous_state_revision: value.3 as u64,
        result_state_revision: value.4 as u64,
        previous_state: ContextGovernanceState::Issued,
        result_state: ContextGovernanceState::Revoked,
        request_digest_sha256: value.5,
        event_id: event_id.to_owned(),
        committed_at_seconds: value.6,
        replayed,
    }))
}

fn dispatch_authorization_receipt(
    connection: &Connection,
    authorization_id: &str,
    replayed: bool,
) -> Result<Option<DispatchContextConsumptionAuthorizationReceipt>, StoreError> {
    let raw: Option<RawDispatchAuthorizationReceipt> = connection
        .query_row(
            "SELECT snapshot_id,snapshot_revision,observed_state_revision,
                    attempt_id,dispatch_id,input_digest_sha256,expected_scope_ref,
                    request_digest_sha256,event_id,committed_at_seconds
             FROM context_dispatch_authorizations WHERE authorization_id=?1",
            [authorization_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    let Some(value) = raw else {
        return Ok(None);
    };
    let event: Option<(String, String, String)> = connection
        .query_row(
            "SELECT operation,snapshot_id,request_digest_sha256
             FROM context_events WHERE event_id=?1",
            [&value.8],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let canonical_digest = super::dispatch_authorization_semantic_digest(
        &value.0,
        value.2.max(0) as u64,
        &value.3,
        &value.4,
        &value.5,
        &value.6,
    );
    if value.1 < 1
        || value.2 < 1
        || value.7 != canonical_digest
        || event
            != Some((
                "authorize-dispatch-consumption".to_owned(),
                value.0.clone(),
                value.7.clone(),
            ))
    {
        return Err(StoreError::IntegrityFailure);
    }
    Ok(Some(DispatchContextConsumptionAuthorizationReceipt {
        authorization_id: authorization_id.to_owned(),
        snapshot_id: value.0,
        snapshot_revision: value.1 as u64,
        observed_state_revision: value.2 as u64,
        attempt_id: value.3,
        dispatch_id: value.4,
        input_digest_sha256: value.5,
        expected_scope_ref: value.6,
        request_digest_sha256: value.7,
        event_id: value.8,
        committed_at_seconds: value.9,
        replayed,
    }))
}

fn insert_context_event(
    transaction: &Transaction<'_>,
    event: ContextEventInsert<'_>,
) -> Result<u64, StoreError> {
    transaction.execute(
        "INSERT INTO context_events(event_id,snapshot_id,operation,principal_id,
         idempotency_key,request_digest_sha256,committed_at_seconds)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            event.event_id,
            event.snapshot_id,
            event.operation,
            event.principal_id,
            event.idempotency_key,
            event.request_digest_sha256,
            event.committed_at_seconds,
        ],
    )?;
    Ok(transaction.last_insert_rowid() as u64)
}

fn update_event_sequence(transaction: &Transaction<'_>, sequence: u64) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE context_store_metadata SET last_event_sequence=?1 WHERE singleton=1",
        [sequence as i64],
    )?;
    Ok(())
}

fn schema_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_SCHEMA.as_bytes());
    hasher.update(MEMORY_USE_SCHEMA.as_bytes());
    hasher.update(R9A_SCHEMA.as_bytes());
    hex::encode(hasher.finalize())
}

fn pre_r9a_schema_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_SCHEMA.as_bytes());
    hasher.update(MEMORY_USE_SCHEMA.as_bytes());
    hex::encode(hasher.finalize())
}

type RawStoredSnapshot = (String, Vec<u8>, String, i64, i64, String, i64);
type RawRevokeReceipt = (
    String,
    i64,
    String,
    i64,
    i64,
    String,
    i64,
    String,
    String,
    String,
);
type RawDispatchAuthorizationReceipt = (
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
);

fn decode_stored_snapshot(
    expected_snapshot_id: &str,
    raw: RawStoredSnapshot,
) -> Result<StoredSnapshot, StoreError> {
    let snapshot: ContextSnapshot =
        serde_json::from_str(&raw.0).map_err(|_| StoreError::DescriptorDecode)?;
    if raw.3 < 1
        || raw.4 < 1
        || !matches!(raw.2.as_str(), "issued" | "revoked")
        || snapshot.snapshot_id != expected_snapshot_id
        || snapshot.revision != raw.4 as u64
        || snapshot.compiled_context_sha256 != raw.5
        || snapshot.expires_at_seconds != raw.6
        || format!("ctx:{}", raw.5) != expected_snapshot_id
        || hex::encode(Sha256::digest(&raw.1)) != raw.5
    {
        return Err(StoreError::IntegrityFailure);
    }
    Ok(StoredSnapshot {
        snapshot,
        compiled_context: raw.1,
        state: raw.2,
        state_revision: raw.3 as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_authority::ContextSnapshot;
    use uuid::Uuid;

    #[test]
    fn r9a_migrates_pre_r9a_store_without_mutating_existing_facts() {
        let root =
            std::env::temp_dir().join(format!("egopulse-context-migration-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("migration test root");
        let path = root.join("context.sqlcipher");
        let key = [41_u8; 32];
        let compiled_context = br#"{"prompt":"legacy-r9a"}"#.to_vec();
        let content_digest = hex::encode(Sha256::digest(&compiled_context));
        let snapshot_id = format!("ctx:{content_digest}");
        let snapshot = ContextSnapshot {
            snapshot_id: snapshot_id.clone(),
            revision: 1,
            owner_principal_id: "founder:migration".to_owned(),
            intent: "preserve pre-r9a facts".to_owned(),
            intent_sha256: "a".repeat(64),
            work_type: "migration_test".to_owned(),
            target_scope_ref: "scope:migration".to_owned(),
            compiled_context_sha256: content_digest.clone(),
            sources: Vec::new(),
            memory_pack: None,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_tools: Vec::new(),
            external_resources: Vec::new(),
            non_goals: Vec::new(),
            acceptance_contract_ref: "acceptance:migration".to_owned(),
            budget_profile_ref: "budget:migration".to_owned(),
            deadline_seconds: None,
            recovery_entry: "hold".to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: Vec::new(),
            expires_at_seconds: i64::MAX - 1,
            confirmation_binding_sha256: "b".repeat(64),
        };
        let descriptor = serde_json::to_string(&snapshot).expect("legacy descriptor");

        {
            let mut connection = Connection::open(&path).expect("open legacy store");
            connection
                .pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                .expect("apply key");
            let cipher_version: String = connection
                .query_row("PRAGMA cipher_version", [], |row| row.get(0))
                .expect("SQLCipher available");
            assert!(!cipher_version.trim().is_empty());
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("foreign keys");
            Migrations::new(vec![M::up(LEGACY_SCHEMA), M::up(MEMORY_USE_SCHEMA)])
                .to_latest(&mut connection)
                .expect("create pre-r9a schema");
            connection
                .execute(
                    "INSERT INTO context_store_metadata(
                       singleton,store_epoch,schema_profile_id,schema_profile_sha256,
                       last_event_sequence) VALUES(1,?1,?2,?3,1)",
                    params![
                        "migration-epoch",
                        SCHEMA_PROFILE_ID,
                        pre_r9a_schema_digest()
                    ],
                )
                .expect("legacy metadata");
            connection
                .execute(
                    "INSERT INTO context_snapshots(
                       snapshot_id,revision,descriptor,compiled_context,
                       compiled_context_sha256,state,expires_at_seconds,created_at_seconds)
                     VALUES(?1,1,?2,?3,?4,'issued',?5,1)",
                    params![
                        snapshot_id,
                        descriptor,
                        compiled_context,
                        content_digest,
                        snapshot.expires_at_seconds
                    ],
                )
                .expect("legacy snapshot");
            connection
                .execute(
                    "INSERT INTO context_events(
                       sequence,event_id,snapshot_id,operation,principal_id,idempotency_key,
                       request_digest_sha256,committed_at_seconds)
                     VALUES(1,'legacy-issue',?1,'issue','context-compiler','legacy-issue',?2,1)",
                    params![snapshot_id, "c".repeat(64)],
                )
                .expect("legacy event");
            connection
                .execute(
                    "INSERT INTO context_idempotency_results(
                       principal_id,idempotency_key,request_digest_sha256,snapshot_id,
                       snapshot_revision,event_id)
                     VALUES('context-compiler','legacy-issue',?1,?2,1,'legacy-issue')",
                    params!["c".repeat(64), snapshot_id],
                )
                .expect("legacy idempotency");
            connection
                .execute(
                    "INSERT INTO context_memory_use_receipts(
                       receipt_id,snapshot_id,snapshot_revision,consumer_principal_id,
                       model_ref,attempt_id,dispatch_id,memory_authority_revision,
                       memory_pack_snapshot_sha256,committed_at_seconds)
                     VALUES('legacy-memory-use',?1,1,'governance-kernel','model:test',
                            'attempt:legacy','dispatch:legacy',7,?2,2)",
                    params![snapshot_id, "d".repeat(64)],
                )
                .expect("legacy memory-use receipt");
        }

        let store = ContextStore::open(&path, &key, "migration-epoch").expect("migrate store");
        let migrated = store
            .snapshot_with_bytes(&snapshot_id)
            .expect("read migrated snapshot")
            .expect("snapshot exists");
        assert_eq!(migrated.snapshot, snapshot);
        assert_eq!(migrated.compiled_context, compiled_context);
        assert_eq!(migrated.state, "issued");
        assert_eq!(migrated.state_revision, 1);
        assert_eq!(
            store
                .memory_use_receipt("legacy-memory-use")
                .expect("read memory use")
                .expect("memory use exists")
                .dispatch_id,
            "dispatch:legacy"
        );
        let metadata_digest: String = store
            .connection
            .query_row(
                "SELECT schema_profile_sha256 FROM context_store_metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("metadata digest");
        assert_eq!(metadata_digest, schema_digest());
        let inspection = store.inspect().expect("inspection");
        assert_eq!(inspection.snapshot_count, 1);
        assert_eq!(inspection.event_count, 1);
        assert_eq!(inspection.revoke_receipt_count, 0);
        assert_eq!(inspection.dispatch_authorization_count, 0);
        drop(store);
        let _ = fs::remove_dir_all(root);
    }
}
