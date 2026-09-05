use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const WITNESS_FILE_NAME: &str = "r8b2c-native-witness.db";

fn canonical_root(root: &Path) -> FaultConformanceResult<String> {
    Ok(fs::canonicalize(root)?.display().to_string())
}

fn witness_path(root: &Path) -> PathBuf {
    root.join(WITNESS_FILE_NAME)
}

fn configure_witness_writer(connection: &Connection) -> FaultConformanceResult<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(())
}

fn open_read_only(path: &Path) -> FaultConformanceResult<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    enforce_query_only(&connection)?;
    Ok(connection)
}

fn enforce_query_only(connection: &Connection) -> FaultConformanceResult<()> {
    connection.pragma_update(None, "query_only", "ON")?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 {
        return Err(FaultConformanceError::invariant(
            "conformance reader did not enter query-only mode",
        ));
    }
    Ok(())
}

fn open_sqlcipher_read_only(path: &Path, key: &[u8; 32]) -> FaultConformanceResult<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
    let cipher_version: String =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(FaultConformanceError::invariant(
            "SQLCipher conformance reader did not report a cipher version",
        ));
    }
    enforce_query_only(&connection)?;
    Ok(connection)
}

fn non_negative(value: i64, label: &str) -> FaultConformanceResult<u64> {
    u64::try_from(value)
        .map_err(|_| FaultConformanceError::invariant(format!("{label} must be non-negative")))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R8b2cNativeEventRecord {
    pub native_key: String,
    pub native_event_id: Option<String>,
    pub native_sequence: Option<u64>,
    pub observed_seconds: i64,
    pub observed_nanos: i32,
    pub criticality: i32,
    pub payload: Vec<u8>,
    pub raw_event: Vec<u8>,
}

type StoredNativeEvent = (
    String,
    Option<String>,
    Option<i64>,
    i64,
    i32,
    i32,
    Vec<u8>,
    Vec<u8>,
);

#[derive(Clone, Debug)]
pub struct R8b2cWitnessWriter {
    database_path: PathBuf,
}

impl R8b2cWitnessWriter {
    pub fn initialize(root: &Path, instance: &str) -> FaultConformanceResult<Self> {
        let identity = canonical_root(root)?;
        let database_path = witness_path(root);
        let connection = Connection::open(&database_path)?;
        configure_witness_writer(&connection)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS fixture_identity(
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               fixture_root TEXT NOT NULL,
               fixture_instance TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS driver_ledger(
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               process_id INTEGER NOT NULL,
               operation TEXT NOT NULL,
               dispatch_id TEXT NOT NULL,
               detail TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS native_events(
               dispatch_id TEXT PRIMARY KEY,
               native_key TEXT NOT NULL,
               native_event_id TEXT,
               native_sequence INTEGER,
               observed_seconds INTEGER NOT NULL,
               observed_nanos INTEGER NOT NULL,
               criticality INTEGER NOT NULL,
               payload BLOB NOT NULL,
               raw_event BLOB NOT NULL,
               emission_state TEXT NOT NULL CHECK(emission_state IN ('pending','emitted')),
               emission_count INTEGER NOT NULL CHECK(emission_count IN (0,1))
             ) STRICT;",
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO fixture_identity(
               singleton, fixture_root, fixture_instance
             ) VALUES(1, ?1, ?2)",
            params![identity, instance],
        )?;
        let stored: (String, String) = connection.query_row(
            "SELECT fixture_root, fixture_instance
             FROM fixture_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if stored != (identity, instance.to_owned()) {
            return Err(FaultConformanceError::invariant(
                "R-8B.2c witness identity does not match root and instance",
            ));
        }
        Ok(Self { database_path })
    }

    fn open(&self) -> FaultConformanceResult<Connection> {
        let connection = Connection::open(&self.database_path)?;
        configure_witness_writer(&connection)?;
        Ok(connection)
    }

    pub fn append(
        &self,
        operation: &str,
        dispatch_id: &str,
        detail: &str,
    ) -> FaultConformanceResult<()> {
        let mut connection = self.open()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO driver_ledger(process_id, operation, dispatch_id, detail)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                i64::from(std::process::id()),
                operation,
                dispatch_id,
                detail
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_native_event(
        &self,
        dispatch_id: &str,
        event: &R8b2cNativeEventRecord,
    ) -> FaultConformanceResult<()> {
        let native_sequence = event
            .native_sequence
            .map(i64::try_from)
            .transpose()
            .map_err(|_| FaultConformanceError::invariant("native sequence exceeds SQLite"))?;
        let mut connection = self.open()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO native_events(
               dispatch_id, native_key, native_event_id, native_sequence,
               observed_seconds, observed_nanos, criticality, payload,
               raw_event, emission_state, emission_count
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', 0)",
            params![
                dispatch_id,
                event.native_key,
                event.native_event_id,
                native_sequence,
                event.observed_seconds,
                event.observed_nanos,
                event.criticality,
                event.payload,
                event.raw_event,
            ],
        )?;
        let stored: StoredNativeEvent = transaction.query_row(
            "SELECT native_key, native_event_id, native_sequence, observed_seconds,
                        observed_nanos, criticality, payload, raw_event
                 FROM native_events WHERE dispatch_id = ?1",
            [dispatch_id],
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
                ))
            },
        )?;
        let expected = (
            event.native_key.clone(),
            event.native_event_id.clone(),
            native_sequence,
            event.observed_seconds,
            event.observed_nanos,
            event.criticality,
            event.payload.clone(),
            event.raw_event.clone(),
        );
        if stored != expected {
            return Err(FaultConformanceError::invariant(
                "R-8B.2c native event replay does not match the original event",
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn next_native_event(
        &self,
        dispatch_id: &str,
    ) -> FaultConformanceResult<Option<R8b2cNativeEventRecord>> {
        type NativeRow = (
            String,
            Option<String>,
            Option<i64>,
            i64,
            i32,
            i32,
            Vec<u8>,
            Vec<u8>,
            String,
            i64,
        );

        let mut connection = self.open()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO driver_ledger(process_id, operation, dispatch_id, detail)
             VALUES(?1, 'next_event', ?2, 'production poll')",
            params![i64::from(std::process::id()), dispatch_id],
        )?;
        let row: Option<NativeRow> = transaction
            .query_row(
                "SELECT native_key, native_event_id, native_sequence, observed_seconds,
                        observed_nanos, criticality, payload, raw_event,
                        emission_state, emission_count
                 FROM native_events WHERE dispatch_id = ?1",
                [dispatch_id],
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
        let Some(row) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        if (row.8.as_str(), row.9) == ("emitted", 1) {
            transaction.commit()?;
            return Ok(None);
        }
        if (row.8.as_str(), row.9) != ("pending", 0) {
            return Err(FaultConformanceError::invariant(
                "R-8B.2c native event has an invalid emission state",
            ));
        }
        let changed = transaction.execute(
            "UPDATE native_events
             SET emission_state = 'emitted', emission_count = 1
             WHERE dispatch_id = ?1 AND emission_state = 'pending' AND emission_count = 0",
            [dispatch_id],
        )?;
        if changed != 1 {
            return Err(FaultConformanceError::invariant(
                "R-8B.2c native event was not emitted exactly once",
            ));
        }
        transaction.execute(
            "INSERT INTO driver_ledger(process_id, operation, dispatch_id, detail)
             VALUES(?1, 'ack_emitted', ?2, 'durable native ACK')",
            params![i64::from(std::process::id()), dispatch_id],
        )?;
        transaction.commit()?;
        Ok(Some(R8b2cNativeEventRecord {
            native_key: row.0,
            native_event_id: row.1,
            native_sequence: row
                .2
                .map(|value| non_negative(value, "native sequence"))
                .transpose()?,
            observed_seconds: row.3,
            observed_nanos: row.4,
            criticality: row.5,
            payload: row.6,
            raw_event: row.7,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct R8b2cWitnessReader {
    database_path: PathBuf,
}

impl R8b2cWitnessReader {
    pub fn open_existing(root: &Path, instance: &str) -> FaultConformanceResult<Self> {
        let database_path = witness_path(root);
        let connection = open_read_only(&database_path)?;
        let identity: (String, String) = connection.query_row(
            "SELECT fixture_root, fixture_instance
             FROM fixture_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if identity != (canonical_root(root)?, instance.to_owned()) {
            return Err(FaultConformanceError::invariant(
                "existing R-8B.2c witness identity does not match root and instance",
            ));
        }
        Ok(Self { database_path })
    }

    pub fn ledger_count(&self, operation: &str) -> FaultConformanceResult<u64> {
        let connection = open_read_only(&self.database_path)?;
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM driver_ledger WHERE operation = ?1",
            [operation],
            |row| row.get(0),
        )?;
        non_negative(count, "witness ledger count")
    }

    pub fn native_event_state(
        &self,
        dispatch_id: &str,
    ) -> FaultConformanceResult<Option<(String, u64)>> {
        let connection = open_read_only(&self.database_path)?;
        connection
            .query_row(
                "SELECT emission_state, emission_count
                 FROM native_events WHERE dispatch_id = ?1",
                [dispatch_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(state, count)| Ok((state, non_negative(count, "emission count")?)))
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R8b2cCollaborationStoreSnapshot {
    pub run_revision: u64,
    pub run_status: i32,
    pub run_snapshot: Vec<u8>,
    pub step_revision: u64,
    pub step_status: i32,
    pub step_snapshot: Vec<u8>,
    pub attempt_revision: u64,
    pub attempt_status: i32,
    pub attempt_snapshot: Vec<u8>,
    pub outbox_state: String,
    pub envelope: Vec<u8>,
    pub event_count: u64,
}

pub fn read_r8b2c_collaboration_store(
    path: &Path,
    key: &[u8; 32],
    run_id: &str,
    step_id: &str,
    attempt_id: &str,
) -> FaultConformanceResult<R8b2cCollaborationStoreSnapshot> {
    let mut connection = open_sqlcipher_read_only(path, key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let (run_revision, run_status, run_snapshot): (i64, i32, Vec<u8>) = transaction.query_row(
        "SELECT revision, status, snapshot FROM collaboration_runs WHERE run_id = ?1",
        [run_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (step_revision, step_status, step_snapshot): (i64, i32, Vec<u8>) = transaction.query_row(
        "SELECT revision, status, snapshot FROM collaboration_steps WHERE step_id = ?1",
        [step_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (attempt_revision, attempt_status, attempt_snapshot): (i64, i32, Vec<u8>) = transaction
        .query_row(
            "SELECT revision, status, snapshot
             FROM collaboration_attempts WHERE attempt_id = ?1",
            [attempt_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let outbox_count: i64 = transaction.query_row(
        "SELECT count(*) FROM collaboration_outbox
         WHERE attempt_id = ?1
           AND destination_domain = 'harness-adapter'
           AND payload_kind = 'dispatch-envelope'",
        [attempt_id],
        |row| row.get(0),
    )?;
    if outbox_count != 1 {
        return Err(FaultConformanceError::invariant(
            "R-8B.2c collaboration dispatch outbox must contain exactly one row",
        ));
    }
    let (outbox_state, envelope): (String, Vec<u8>) = transaction.query_row(
        "SELECT delivery_state, payload FROM collaboration_outbox
         WHERE attempt_id = ?1
           AND destination_domain = 'harness-adapter'
           AND payload_kind = 'dispatch-envelope'",
        [attempt_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let event_count: i64 =
        transaction.query_row("SELECT count(*) FROM collaboration_events", [], |row| {
            row.get(0)
        })?;
    let snapshot = R8b2cCollaborationStoreSnapshot {
        run_revision: non_negative(run_revision, "run revision")?,
        run_status,
        run_snapshot,
        step_revision: non_negative(step_revision, "step revision")?,
        step_status,
        step_snapshot,
        attempt_revision: non_negative(attempt_revision, "attempt revision")?,
        attempt_status,
        attempt_snapshot,
        outbox_state,
        envelope,
        event_count: non_negative(event_count, "collaboration event count")?,
    };
    transaction.commit()?;
    Ok(snapshot)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R8b2cTaskStoreSnapshot {
    pub revision: u64,
    pub status: i32,
    pub snapshot: Vec<u8>,
    pub event_count: u64,
}

pub fn read_r8b2c_task_store(
    path: &Path,
    key: &[u8; 32],
    task_id: &str,
) -> FaultConformanceResult<R8b2cTaskStoreSnapshot> {
    let mut connection = open_sqlcipher_read_only(path, key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let (revision, status, snapshot): (i64, i32, Vec<u8>) = transaction.query_row(
        "SELECT revision, status, snapshot FROM tasks WHERE task_id = ?1",
        [task_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let event_count: i64 = transaction.query_row(
        "SELECT count(*) FROM task_events WHERE task_id = ?1",
        [task_id],
        |row| row.get(0),
    )?;
    let snapshot = R8b2cTaskStoreSnapshot {
        revision: non_negative(revision, "task revision")?,
        status,
        snapshot,
        event_count: non_negative(event_count, "task event count")?,
    };
    transaction.commit()?;
    Ok(snapshot)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R8b2cAdapterObservationRow {
    pub observation_id: String,
    pub dispatch_id: String,
    pub native_key: String,
    pub native_event_digest_sha256: String,
    pub raw_evidence_ref: String,
    pub ingestion_state: String,
    pub observation: Vec<u8>,
    pub raw_event: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R8b2cAdapterStoreSnapshot {
    pub dispatch_count: u64,
    pub delivery_unknown_count: u64,
    pub observation_count: u64,
    pub pending_observation_count: u64,
    pub dispatch_state: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub dispatch_fingerprint: String,
    pub envelope_digest_sha256: String,
    pub envelope: Vec<u8>,
    pub receipt: Option<Vec<u8>>,
    pub observations: Vec<R8b2cAdapterObservationRow>,
}

/// Reads the sole durable dispatch identity through the same query-only,
/// SQLCipher-authenticated conformance boundary used by the detailed oracle.
/// Crash-window fixtures intentionally admit exactly one dispatch.
pub fn read_single_r8b2c_adapter_dispatch_id(
    path: &Path,
    key: &[u8; 32],
) -> FaultConformanceResult<String> {
    let connection = open_sqlcipher_read_only(path, key)?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM adapter_dispatches", [], |row| {
            row.get(0)
        })?;
    if count != 1 {
        return Err(FaultConformanceError::invariant(
            "R-8B.2c adapter store must contain exactly one dispatch identity",
        ));
    }
    connection
        .query_row("SELECT dispatch_id FROM adapter_dispatches", [], |row| {
            row.get(0)
        })
        .map_err(Into::into)
}

pub fn read_r8b2c_adapter_store(
    path: &Path,
    key: &[u8; 32],
    dispatch_id: &str,
) -> FaultConformanceResult<R8b2cAdapterStoreSnapshot> {
    let mut connection = open_sqlcipher_read_only(path, key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let (
        dispatch_state,
        attempt_id,
        fencing_token,
        dispatch_fingerprint,
        envelope_digest_sha256,
        envelope,
        receipt,
    ): (
        String,
        String,
        i64,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = transaction.query_row(
        "SELECT delivery_state, attempt_id, fencing_token, dispatch_fingerprint,
                    envelope_digest_sha256, envelope, receipt
             FROM adapter_dispatches WHERE dispatch_id = ?1",
        [dispatch_id],
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
    )?;
    let observations = {
        let mut statement = transaction.prepare(
            "SELECT observation_id, dispatch_id, native_key,
                    native_event_digest_sha256, raw_evidence_ref, ingestion_state,
                    observation, raw_event
             FROM adapter_observations WHERE dispatch_id = ?1
             ORDER BY observation_sequence",
        )?;
        statement
            .query_map([dispatch_id], |row| {
                Ok(R8b2cAdapterObservationRow {
                    observation_id: row.get(0)?,
                    dispatch_id: row.get(1)?,
                    native_key: row.get(2)?,
                    native_event_digest_sha256: row.get(3)?,
                    raw_evidence_ref: row.get(4)?,
                    ingestion_state: row.get(5)?,
                    observation: row.get(6)?,
                    raw_event: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let (dispatch_count, delivery_unknown_count, observation_count, pending_observation_count) = {
        let scalar = |sql: &str| -> FaultConformanceResult<u64> {
            let value: i64 = transaction.query_row(sql, [], |row| row.get(0))?;
            non_negative(value, "adapter count")
        };
        (
            scalar("SELECT count(*) FROM adapter_dispatches")?,
            scalar(
                "SELECT count(*) FROM adapter_dispatches WHERE delivery_state = 'delivery_unknown'",
            )?,
            scalar("SELECT count(*) FROM adapter_observations")?,
            scalar("SELECT count(*) FROM adapter_observations WHERE ingestion_state = 'pending'")?,
        )
    };
    let snapshot = R8b2cAdapterStoreSnapshot {
        dispatch_count,
        delivery_unknown_count,
        observation_count,
        pending_observation_count,
        dispatch_state,
        attempt_id,
        fencing_token: non_negative(fencing_token, "adapter fencing token")?,
        dispatch_fingerprint,
        envelope_digest_sha256,
        envelope,
        receipt,
        observations,
    };
    transaction.commit()?;
    Ok(snapshot)
}
