#![forbid(unsafe_code)]

pub mod r8b2c;
pub mod r9a3;
pub mod r9a3_context;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FaultConformanceError {
    message: String,
}

impl FaultConformanceError {
    pub(crate) fn invariant(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for FaultConformanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FaultConformanceError {}

impl From<rusqlite::Error> for FaultConformanceError {
    fn from(error: rusqlite::Error) -> Self {
        Self::invariant(format!("SQLite conformance failure: {error}"))
    }
}

impl From<std::io::Error> for FaultConformanceError {
    fn from(error: std::io::Error) -> Self {
        Self::invariant(format!("filesystem conformance failure: {error}"))
    }
}

pub type FaultConformanceResult<T> = Result<T, FaultConformanceError>;

pub const BOUNDARIES: [&str; 8] = [
    "command_commit",
    "outbox_publish",
    "dispatch",
    "harness_ack",
    "artifact_return",
    "verification",
    "founder_verdict",
    "policy_decision",
];

const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn database_path(root: &Path) -> PathBuf {
    root.join("authority.sqlcipher")
}

fn open_database(root: &Path) -> rusqlite::Result<Connection> {
    fs::create_dir_all(root)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    let connection = Connection::open(database_path(root))?;
    connection.pragma_update(None, "key", format!("x'{TEST_KEY}'"))?;
    let cipher_version: String =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS authority_facts (
          authority TEXT NOT NULL,
          fact_key TEXT NOT NULL,
          revision INTEGER NOT NULL,
          value TEXT NOT NULL,
          PRIMARY KEY(authority, fact_key)
        );
        CREATE TABLE IF NOT EXISTS authority_events (
          event_id TEXT PRIMARY KEY,
          authority TEXT NOT NULL,
          revision INTEGER NOT NULL,
          event_kind TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS idempotency_receipts (
          scope TEXT NOT NULL,
          request_key TEXT NOT NULL,
          result_ref TEXT NOT NULL,
          PRIMARY KEY(scope, request_key)
        );
        CREATE TABLE IF NOT EXISTS outbox (
          message_id TEXT PRIMARY KEY,
          source_authority TEXT NOT NULL,
          message_kind TEXT NOT NULL,
          delivered INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS inbox (
          consumer_authority TEXT NOT NULL,
          message_id TEXT NOT NULL,
          receipt_ref TEXT NOT NULL,
          PRIMARY KEY(consumer_authority, message_id)
        );
        CREATE TABLE IF NOT EXISTS artifact_metadata (
          artifact_id TEXT PRIMARY KEY,
          digest TEXT NOT NULL,
          sealed INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_audit (
          boundary TEXT PRIMARY KEY,
          classification TEXT NOT NULL
        );
        ",
    )?;
    Ok(connection)
}

// This fixture helper keeps the persisted fact, event, and outbox fields explicit so crash
// boundary cases cannot accidentally share or omit identifiers while being assembled.
#[allow(clippy::too_many_arguments)]
fn commit_fact_event_outbox(
    tx: &Transaction<'_>,
    authority: &str,
    fact_key: &str,
    revision: i64,
    value: &str,
    event_id: &str,
    event_kind: &str,
    message_id: &str,
    message_kind: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO authority_facts(authority, fact_key, revision, value) VALUES(?1, ?2, ?3, ?4)",
        params![authority, fact_key, revision, value],
    )?;
    tx.execute(
        "INSERT INTO authority_events(event_id, authority, revision, event_kind) VALUES(?1, ?2, ?3, ?4)",
        params![event_id, authority, revision, event_kind],
    )?;
    tx.execute(
        "INSERT INTO outbox(message_id, source_authority, message_kind) VALUES(?1, ?2, ?3)",
        params![message_id, authority, message_kind],
    )?;
    Ok(())
}

fn consume_once(
    connection: &mut Connection,
    consumer: &str,
    message_id: &str,
    fact_key: &str,
    value: &str,
    event_id: &str,
    event_kind: &str,
) -> rusqlite::Result<bool> {
    let tx = connection.transaction()?;
    let already_consumed: bool = tx
        .query_row(
            "SELECT 1 FROM inbox WHERE consumer_authority = ?1 AND message_id = ?2",
            params![consumer, message_id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if already_consumed {
        tx.commit()?;
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO authority_facts(authority, fact_key, revision, value) VALUES(?1, ?2, 1, ?3)
         ON CONFLICT(authority, fact_key) DO UPDATE SET value = excluded.value",
        params![consumer, fact_key, value],
    )?;
    tx.execute(
        "INSERT INTO authority_events(event_id, authority, revision, event_kind) VALUES(?1, ?2, 1, ?3)",
        params![event_id, consumer, event_kind],
    )?;
    tx.execute(
        "INSERT INTO inbox(consumer_authority, message_id, receipt_ref) VALUES(?1, ?2, ?3)",
        params![consumer, message_id, format!("receipt:{message_id}")],
    )?;
    tx.commit()?;
    Ok(true)
}

pub fn inject_and_abort(boundary: &str, root: &Path) -> FaultConformanceResult<()> {
    let mut connection = open_database(root)?;
    match boundary {
        "command_commit" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "task",
                "task-1",
                1,
                "ready",
                "task-event-1",
                "task_created",
                "task-outbox-1",
                "task_created",
            )?;
            tx.execute(
                "INSERT INTO idempotency_receipts(scope, request_key, result_ref) VALUES('task', 'create-1', 'task-1@1')",
                [],
            )?;
            tx.commit()?;
        }
        "outbox_publish" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "collaboration",
                "run-1",
                1,
                "active",
                "run-event-1",
                "run_activated",
                "run-outbox-1",
                "run_activated",
            )?;
            tx.commit()?;
        }
        "dispatch" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "collaboration",
                "attempt-1",
                1,
                "dispatch_pending",
                "attempt-event-1",
                "dispatch_intent_recorded",
                "dispatch-1",
                "dispatch_requested",
            )?;
            tx.commit()?;
        }
        "harness_ack" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "collaboration",
                "attempt-1",
                2,
                "acknowledged",
                "attempt-event-2",
                "harness_ack_recorded",
                "ack-outbox-1",
                "harness_ack_recorded",
            )?;
            tx.execute(
                "INSERT INTO idempotency_receipts(scope, request_key, result_ref) VALUES('dispatch', 'dispatch-1', 'ack-1')",
                [],
            )?;
            tx.commit()?;
        }
        "artifact_return" => {
            let bytes = b"immutable-artifact-return-v1";
            let blob_path = root.join("artifact-1.blob");
            let mut blob = File::create(&blob_path)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            blob.write_all(bytes)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            blob.sync_all()
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let digest = hex::encode(Sha256::digest(bytes));
            let tx = connection.transaction()?;
            tx.execute(
                "INSERT INTO artifact_metadata(artifact_id, digest, sealed) VALUES('artifact-1', ?1, 1)",
                params![digest],
            )?;
            commit_fact_event_outbox(
                &tx,
                "artifact",
                "artifact-set-1",
                1,
                "sealed",
                "artifact-event-1",
                "artifact_return_sealed",
                "artifact-outbox-1",
                "artifact_returned",
            )?;
            tx.commit()?;
        }
        "verification" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "verification",
                "verification-1",
                1,
                "passed",
                "verification-event-1",
                "verification_completed",
                "verification-outbox-1",
                "verification_completed",
            )?;
            tx.commit()?;
        }
        "founder_verdict" => {
            connection.execute(
                "INSERT INTO authority_facts(authority, fact_key, revision, value) VALUES('task', 'task-1', 1, 'verdict_pending')",
                [],
            )?;
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "verdict",
                "verdict-1",
                1,
                "accept",
                "verdict-event-1",
                "founder_verdict_issued",
                "verdict-outbox-1",
                "founder_verdict_issued",
            )?;
            tx.commit()?;
            consume_once(
                &mut connection,
                "task",
                "verdict-outbox-1",
                "task-1",
                "completed",
                "task-verdict-event-1",
                "founder_verdict_applied",
            )?;
        }
        "policy_decision" => {
            let tx = connection.transaction()?;
            commit_fact_event_outbox(
                &tx,
                "policy",
                "policy-decision-1",
                1,
                "issued",
                "policy-event-1",
                "harness_approval_decision_issued",
                "policy-outbox-1",
                "harness_approval_decision_requested",
            )?;
            tx.execute(
                "INSERT INTO idempotency_receipts(scope, request_key, result_ref) VALUES('policy', 'approval-1', 'policy-decision-1@1')",
                [],
            )?;
            tx.commit()?;
        }
        _ => return Err(rusqlite::Error::InvalidQuery.into()),
    }
    std::process::abort();
}

fn scalar_i64(connection: &Connection, sql: &str) -> rusqlite::Result<i64> {
    connection.query_row(sql, [], |row| row.get(0))
}

fn scalar_string(connection: &Connection, sql: &str) -> rusqlite::Result<String> {
    connection.query_row(sql, [], |row| row.get(0))
}

pub fn recover_and_verify(boundary: &str, root: &Path) -> FaultConformanceResult<()> {
    let encrypted_bytes = fs::read(database_path(root))
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    assert!(
        encrypted_bytes.len() >= 16,
        "SQLCipher database is unexpectedly short"
    );
    assert_ne!(
        &encrypted_bytes[..16],
        b"SQLite format 3\0",
        "database retained the plaintext SQLite header instead of a SQLCipher header"
    );

    let mut connection = open_database(root)?;
    match boundary {
        "command_commit" => {
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='task' AND fact_key='task-1'"
                )?,
                "ready"
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM authority_events WHERE event_id='task-event-1'"
                )?,
                1
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM outbox WHERE message_id='task-outbox-1'"
                )?,
                1
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM idempotency_receipts WHERE request_key='create-1'"
                )?,
                1
            );
        }
        "outbox_publish" => {
            assert!(consume_once(
                &mut connection,
                "task",
                "run-outbox-1",
                "task-1",
                "active",
                "task-run-event-1",
                "run_activated_consumed"
            )?);
            assert!(!consume_once(
                &mut connection,
                "task",
                "run-outbox-1",
                "task-1",
                "active",
                "task-run-event-duplicate",
                "run_activated_consumed"
            )?);
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM inbox WHERE message_id='run-outbox-1'"
                )?,
                1
            );
        }
        "dispatch" => {
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='collaboration' AND fact_key='attempt-1'"
                )?,
                "dispatch_pending"
            );
            connection.execute(
                "INSERT OR REPLACE INTO recovery_audit(boundary, classification) VALUES('dispatch', 'reconcile_before_retry')",
                [],
            )?;
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM outbox WHERE message_id='dispatch-1'"
                )?,
                1
            );
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT classification FROM recovery_audit WHERE boundary='dispatch'"
                )?,
                "reconcile_before_retry"
            );
        }
        "harness_ack" => {
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='collaboration' AND fact_key='attempt-1'"
                )?,
                "acknowledged"
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM idempotency_receipts WHERE scope='dispatch' AND request_key='dispatch-1'"
                )?,
                1
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM authority_events WHERE event_id='attempt-event-2'"
                )?,
                1
            );
        }
        "artifact_return" => {
            let bytes = fs::read(root.join("artifact-1.blob"))
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
            let actual = hex::encode(Sha256::digest(bytes));
            let expected = scalar_string(
                &connection,
                "SELECT digest FROM artifact_metadata WHERE artifact_id='artifact-1' AND sealed=1",
            )?;
            assert_eq!(actual, expected);
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM outbox WHERE message_id='artifact-outbox-1'"
                )?,
                1
            );
        }
        "verification" => {
            assert!(consume_once(
                &mut connection,
                "task",
                "verification-outbox-1",
                "task-1",
                "verdict_pending",
                "task-verification-event-1",
                "verification_recorded"
            )?);
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='task' AND fact_key='task-1'"
                )?,
                "verdict_pending"
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM authority_facts WHERE authority='task' AND value='completed'"
                )?,
                0
            );
        }
        "founder_verdict" => {
            assert!(!consume_once(
                &mut connection,
                "task",
                "verdict-outbox-1",
                "task-1",
                "completed",
                "task-verdict-event-duplicate",
                "founder_verdict_applied"
            )?);
            connection.execute(
                "UPDATE outbox SET delivered=1 WHERE message_id='verdict-outbox-1'",
                [],
            )?;
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='task' AND fact_key='task-1'"
                )?,
                "completed"
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM authority_events WHERE event_kind='founder_verdict_applied'"
                )?,
                1
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM inbox WHERE message_id='verdict-outbox-1'"
                )?,
                1
            );
        }
        "policy_decision" => {
            assert_eq!(
                scalar_string(
                    &connection,
                    "SELECT value FROM authority_facts WHERE authority='policy' AND fact_key='policy-decision-1'",
                )?,
                "issued"
            );
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM idempotency_receipts WHERE scope='policy' AND request_key='approval-1'",
                )?,
                1
            );
            assert!(consume_once(
                &mut connection,
                "harness-adapter",
                "policy-outbox-1",
                "approval-1",
                "allow_once",
                "adapter-policy-event-1",
                "approval_decision_delivered",
            )?);
            assert!(!consume_once(
                &mut connection,
                "harness-adapter",
                "policy-outbox-1",
                "approval-1",
                "allow_once",
                "adapter-policy-event-duplicate",
                "approval_decision_delivered",
            )?);
            assert_eq!(
                scalar_i64(
                    &connection,
                    "SELECT count(*) FROM inbox WHERE consumer_authority='harness-adapter' AND message_id='policy-outbox-1'",
                )?,
                1
            );
        }
        _ => return Err(rusqlite::Error::InvalidQuery.into()),
    }
    let integrity = scalar_string(&connection, "PRAGMA integrity_check")?;
    assert_eq!(
        integrity, "ok",
        "SQLCipher integrity check failed after crash recovery"
    );
    Ok(())
}
