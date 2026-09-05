use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const MEMORY_SCHEMA_PROFILE_ID: &str = "egopulse/memory-authority-store/v1";
const MEMORY_SCHEMA_SHA256: &str =
    "b1a916cbf390ef96790f07820bc83a6ca30432206a7ee57ab1bdd0a7471304d8";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRestartRecord {
    pub memory_id: String,
    pub revision: u64,
    pub content: String,
    pub content_sha256: String,
    pub source_ref: String,
    pub scope_ref: String,
    pub state: String,
    pub created_at_seconds: i64,
    pub updated_at_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRestartCounts {
    pub memory_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub last_event_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRestartSnapshot {
    pub kept: MemoryRestartRecord,
    pub revoked: MemoryRestartRecord,
    pub counts: MemoryRestartCounts,
}

pub struct MemoryRestartOracle {
    connection: Connection,
    expected_store_epoch: String,
}

impl MemoryRestartOracle {
    pub fn open_existing(
        database_path: &Path,
        key: &[u8; 32],
        expected_store_epoch: &str,
    ) -> FaultConformanceResult<Self> {
        let connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(FaultConformanceError::invariant(
                "Memory restart oracle requires SQLCipher",
            ));
        }
        connection.pragma_update(None, "query_only", "ON")?;
        let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        if query_only != 1 {
            return Err(FaultConformanceError::invariant(
                "Memory restart oracle is not query-only",
            ));
        }

        let mut cipher_integrity = connection.prepare("PRAGMA cipher_integrity_check")?;
        let cipher_findings = cipher_integrity
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if !cipher_findings.is_empty() {
            return Err(FaultConformanceError::invariant(format!(
                "Memory SQLCipher integrity findings: {cipher_findings:?}"
            )));
        }
        drop(cipher_integrity);

        let mut structural_integrity = connection.prepare("PRAGMA integrity_check")?;
        let structural_findings = structural_integrity
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if structural_findings.as_slice() != ["ok"] {
            return Err(FaultConformanceError::invariant(format!(
                "Memory SQLite integrity findings: {structural_findings:?}"
            )));
        }
        drop(structural_integrity);

        Ok(Self {
            connection,
            expected_store_epoch: expected_store_epoch.to_owned(),
        })
    }

    pub fn snapshot(
        &mut self,
        kept_id: &str,
        revoked_id: &str,
    ) -> FaultConformanceResult<MemoryRestartSnapshot> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;

        // This is deliberately the first business read in the snapshot transaction.
        let metadata: (String, String, String, i64) = transaction.query_row(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256,last_event_sequence
             FROM memory_store_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if metadata.0 != self.expected_store_epoch
            || metadata.1 != MEMORY_SCHEMA_PROFILE_ID
            || metadata.2 != MEMORY_SCHEMA_SHA256
        {
            return Err(FaultConformanceError::invariant(
                "Memory store metadata identity mismatch",
            ));
        }
        let last_event_sequence = nonnegative(metadata.3, "last_event_sequence")?;

        let kept = read_record(&transaction, kept_id)?;
        let revoked = read_record(&transaction, revoked_id)?;
        for record in [&kept, &revoked] {
            let actual_digest = hex::encode(Sha256::digest(record.content.as_bytes()));
            if actual_digest != record.content_sha256 {
                return Err(FaultConformanceError::invariant(format!(
                    "Memory content digest mismatch for {}",
                    record.memory_id
                )));
            }
        }

        let memory_count = scalar_count(&transaction, "SELECT count(*) FROM memories")?;
        let event_count = scalar_count(&transaction, "SELECT count(*) FROM memory_events")?;
        let idempotency_count = scalar_count(
            &transaction,
            "SELECT count(*) FROM memory_idempotency_results",
        )?;
        let maximum_event_sequence: i64 = transaction.query_row(
            "SELECT COALESCE(max(sequence),0) FROM memory_events",
            [],
            |row| row.get(0),
        )?;
        let maximum_event_sequence = nonnegative(maximum_event_sequence, "maximum event sequence")?;
        if last_event_sequence != maximum_event_sequence {
            return Err(FaultConformanceError::invariant(
                "Memory metadata last_event_sequence does not match the event log",
            ));
        }

        transaction.commit()?;
        Ok(MemoryRestartSnapshot {
            kept,
            revoked,
            counts: MemoryRestartCounts {
                memory_count,
                event_count,
                idempotency_count,
                last_event_sequence,
            },
        })
    }
}

fn read_record(
    transaction: &Transaction<'_>,
    memory_id: &str,
) -> FaultConformanceResult<MemoryRestartRecord> {
    let raw = transaction
        .query_row(
            "SELECT memory_id,revision,content,content_sha256,source_ref,scope_ref,state,
                    created_at_seconds,updated_at_seconds
             FROM memories WHERE memory_id=?1",
            [memory_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            FaultConformanceError::invariant(format!(
                "Memory restart oracle record is missing: {memory_id}"
            ))
        })?;
    Ok(MemoryRestartRecord {
        memory_id: raw.0,
        revision: nonnegative(raw.1, "memory revision")?,
        content: raw.2,
        content_sha256: raw.3,
        source_ref: raw.4,
        scope_ref: raw.5,
        state: raw.6,
        created_at_seconds: raw.7,
        updated_at_seconds: raw.8,
    })
}

fn scalar_count(transaction: &Transaction<'_>, sql: &str) -> FaultConformanceResult<u64> {
    let value: i64 = transaction.query_row(sql, [], |row| row.get(0))?;
    nonnegative(value, "Memory store count")
}

fn nonnegative(value: i64, label: &str) -> FaultConformanceResult<u64> {
    u64::try_from(value).map_err(|_| {
        FaultConformanceError::invariant(format!("{label} must be non-negative, got {value}"))
    })
}
