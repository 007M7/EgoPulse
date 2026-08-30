use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const CONTEXT_STORE_PROFILE_ID: &str = "egopulse/context-authority-store/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R9a3ContextGovernanceState {
    Issued,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3ContextSnapshotState {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub governance_state: R9a3ContextGovernanceState,
    pub state_revision: u64,
    pub expires_at_seconds: i64,
    pub created_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3DispatchAuthorizationReceipt {
    pub authorization_id: String,
    pub event_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub observed_state_revision: u64,
    pub principal_id: String,
    pub command_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub input_digest_sha256: String,
    pub expected_scope_ref: String,
    pub correlation_id: String,
    pub causation_id: String,
    pub request_digest_sha256: String,
    pub committed_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3ContextAuthorityCounts {
    pub snapshot_count: u64,
    pub event_count: u64,
    pub authorization_count: u64,
    /// Total rows across issue, memory-use, revoke, and dispatch-authorization
    /// idempotency tables.
    pub idempotency_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3ContextRevokeFact {
    pub event_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub previous_state_revision: u64,
    pub result_state_revision: u64,
    pub principal_id: String,
    pub request_digest_sha256: String,
    pub committed_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3ContextAuthoritySnapshot {
    pub snapshot: R9a3ContextSnapshotState,
    pub revoke: Option<R9a3ContextRevokeFact>,
    pub dispatch_authorization: Option<R9a3DispatchAuthorizationReceipt>,
    pub counts: R9a3ContextAuthorityCounts,
}

type RawSnapshot = (i64, Vec<u8>, String, String, i64, i64, i64);
type RawAuthorization = (
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
);
type RawRevokeFact = (String, String, i64, String, i64, i64, String, i64);

pub fn read_r9a3_context_authority_store(
    path: &Path,
    key: &[u8; 32],
    expected_store_epoch: &str,
    snapshot_id: &str,
    dispatch_id: &str,
) -> FaultConformanceResult<R9a3ContextAuthoritySnapshot> {
    validate_identity("expected_store_epoch", expected_store_epoch)?;
    validate_identity("snapshot_id", snapshot_id)?;
    validate_identity("dispatch_id", dispatch_id)?;

    let mut connection = open_context_store_read_only(path, key)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;

    let metadata: (i64, String, String, String) = transaction.query_row(
        "SELECT count(*), min(store_epoch), min(schema_profile_id),
                min(schema_profile_sha256)
         FROM context_store_metadata WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if metadata.0 != 1
        || metadata.1 != expected_store_epoch
        || metadata.2 != CONTEXT_STORE_PROFILE_ID
        || !is_sha256(&metadata.3)
    {
        return Err(FaultConformanceError::invariant(
            "Context Authority store metadata is invalid",
        ));
    }

    let raw_snapshot: RawSnapshot = transaction
        .query_row(
            "SELECT revision, compiled_context, compiled_context_sha256, state,
                    state_revision, expires_at_seconds, created_at_seconds
             FROM context_snapshots WHERE snapshot_id = ?1",
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
        .optional()?
        .ok_or_else(|| FaultConformanceError::invariant("Context snapshot was not found"))?;
    let snapshot = decode_snapshot(snapshot_id, raw_snapshot)?;
    let revoke = read_revoke_fact(&transaction, &snapshot)?;

    let raw_authorization: Option<RawAuthorization> = transaction
        .query_row(
            "SELECT authorization_id, event_id, snapshot_revision,
                    observed_state_revision, snapshot_id, principal_id, command_id,
                    attempt_id, dispatch_id, input_digest_sha256, expected_scope_ref,
                    correlation_id, causation_id, committed_at_seconds
             FROM context_dispatch_authorizations WHERE dispatch_id = ?1",
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
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .optional()?;
    let dispatch_authorization = raw_authorization
        .map(|raw| decode_authorization(&transaction, &snapshot, snapshot_id, dispatch_id, raw))
        .transpose()?;

    let raw_counts: (i64, i64, i64, i64) = transaction.query_row(
        "SELECT
           (SELECT count(*) FROM context_snapshots),
           (SELECT count(*) FROM context_events),
           (SELECT count(*) FROM context_dispatch_authorizations),
           (SELECT count(*) FROM context_idempotency_results)
             + (SELECT count(*) FROM context_memory_use_idempotency)
             + (SELECT count(*) FROM context_revoke_idempotency)
             + (SELECT count(*) FROM context_dispatch_authorization_idempotency)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let counts = R9a3ContextAuthorityCounts {
        snapshot_count: non_negative(raw_counts.0, "snapshot count")?,
        event_count: non_negative(raw_counts.1, "event count")?,
        authorization_count: non_negative(raw_counts.2, "authorization count")?,
        idempotency_count: non_negative(raw_counts.3, "idempotency count")?,
    };

    transaction.commit()?;
    Ok(R9a3ContextAuthoritySnapshot {
        snapshot,
        revoke,
        dispatch_authorization,
        counts,
    })
}

fn open_context_store_read_only(path: &Path, key: &[u8; 32]) -> FaultConformanceResult<Connection> {
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
            "Context Authority conformance reader did not report SQLCipher",
        ));
    }
    connection.pragma_update(None, "query_only", "ON")?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 {
        return Err(FaultConformanceError::invariant(
            "Context Authority conformance reader did not enter query-only mode",
        ));
    }
    Ok(connection)
}

fn decode_snapshot(
    snapshot_id: &str,
    raw: RawSnapshot,
) -> FaultConformanceResult<R9a3ContextSnapshotState> {
    let snapshot_revision = positive(raw.0, "snapshot revision")?;
    let state_revision = positive(raw.4, "snapshot state revision")?;
    if !is_sha256(&raw.2)
        || hex::encode(Sha256::digest(&raw.1)) != raw.2
        || snapshot_id != format!("ctx:{}", raw.2)
    {
        return Err(FaultConformanceError::invariant(
            "Context snapshot content binding is invalid",
        ));
    }
    let governance_state = match raw.3.as_str() {
        "issued" => R9a3ContextGovernanceState::Issued,
        "revoked" => R9a3ContextGovernanceState::Revoked,
        _ => {
            return Err(FaultConformanceError::invariant(
                "Context snapshot governance state is invalid",
            ));
        }
    };
    Ok(R9a3ContextSnapshotState {
        snapshot_id: snapshot_id.to_owned(),
        snapshot_revision,
        content_digest_sha256: raw.2,
        governance_state,
        state_revision,
        expires_at_seconds: raw.5,
        created_at_seconds: raw.6,
    })
}

fn decode_authorization(
    transaction: &rusqlite::Transaction<'_>,
    snapshot: &R9a3ContextSnapshotState,
    expected_snapshot_id: &str,
    expected_dispatch_id: &str,
    raw: RawAuthorization,
) -> FaultConformanceResult<R9a3DispatchAuthorizationReceipt> {
    let snapshot_revision = positive(raw.2, "authorization snapshot revision")?;
    let observed_state_revision = positive(raw.3, "authorization state revision")?;
    for (label, value) in [
        ("authorization_id", raw.0.as_str()),
        ("event_id", raw.1.as_str()),
        ("snapshot_id", raw.4.as_str()),
        ("principal_id", raw.5.as_str()),
        ("command_id", raw.6.as_str()),
        ("attempt_id", raw.7.as_str()),
        ("dispatch_id", raw.8.as_str()),
        ("expected_scope_ref", raw.10.as_str()),
        ("correlation_id", raw.11.as_str()),
        ("causation_id", raw.12.as_str()),
    ] {
        validate_identity(label, value)?;
    }
    if !is_sha256(&raw.9) {
        return Err(FaultConformanceError::invariant(
            "authorization input digest is invalid",
        ));
    }

    let request_digest_sha256: String = transaction.query_row(
        "SELECT request_digest_sha256
         FROM context_dispatch_authorizations WHERE authorization_id = ?1",
        [&raw.0],
        |row| row.get(0),
    )?;
    if !is_sha256(&request_digest_sha256) {
        return Err(FaultConformanceError::invariant(
            "authorization request digest is invalid",
        ));
    }

    let expected_current_state_revision = match snapshot.governance_state {
        R9a3ContextGovernanceState::Issued => observed_state_revision,
        R9a3ContextGovernanceState::Revoked => {
            observed_state_revision.checked_add(1).ok_or_else(|| {
                FaultConformanceError::invariant("authorization state revision overflowed")
            })?
        }
    };
    if raw.4 != expected_snapshot_id
        || raw.8 != expected_dispatch_id
        || snapshot_revision != snapshot.snapshot_revision
        || raw.9 != snapshot.content_digest_sha256
        || snapshot.state_revision != expected_current_state_revision
    {
        return Err(FaultConformanceError::invariant(
            "dispatch authorization does not match the requested Context lineage",
        ));
    }

    let event: Option<(String, String, String, String)> = transaction
        .query_row(
            "SELECT operation, snapshot_id, principal_id, request_digest_sha256
             FROM context_events WHERE event_id = ?1",
            [&raw.1],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if event
        != Some((
            "authorize-dispatch-consumption".to_owned(),
            raw.4.clone(),
            raw.5.clone(),
            request_digest_sha256.clone(),
        ))
    {
        return Err(FaultConformanceError::invariant(
            "dispatch authorization event binding is invalid",
        ));
    }

    let idempotency_rows: Vec<(String, String, String)> = {
        let mut statement = transaction.prepare(
            "SELECT principal_id, request_digest_sha256, authorization_id
             FROM context_dispatch_authorization_idempotency
             WHERE authorization_id = ?1",
        )?;
        statement
            .query_map([&raw.0], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?
    };
    if idempotency_rows != vec![(raw.5.clone(), request_digest_sha256.clone(), raw.0.clone())] {
        return Err(FaultConformanceError::invariant(
            "dispatch authorization idempotency binding is invalid",
        ));
    }

    Ok(R9a3DispatchAuthorizationReceipt {
        authorization_id: raw.0,
        event_id: raw.1,
        snapshot_id: raw.4,
        snapshot_revision,
        observed_state_revision,
        principal_id: raw.5,
        command_id: raw.6,
        attempt_id: raw.7,
        dispatch_id: raw.8,
        input_digest_sha256: raw.9,
        expected_scope_ref: raw.10,
        correlation_id: raw.11,
        causation_id: raw.12,
        request_digest_sha256,
        committed_at_seconds: raw.13,
    })
}

fn read_revoke_fact(
    transaction: &rusqlite::Transaction<'_>,
    snapshot: &R9a3ContextSnapshotState,
) -> FaultConformanceResult<Option<R9a3ContextRevokeFact>> {
    let raw_rows: Vec<RawRevokeFact> = {
        let mut statement = transaction.prepare(
            "SELECT event_id, snapshot_id, snapshot_revision,
                    content_digest_sha256, previous_state_revision,
                    result_state_revision, request_digest_sha256,
                    committed_at_seconds
             FROM context_revoke_receipts WHERE snapshot_id = ?1",
        )?;
        statement
            .query_map([&snapshot.snapshot_id], |row| {
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
            })?
            .collect::<Result<_, _>>()?
    };

    match snapshot.governance_state {
        R9a3ContextGovernanceState::Issued => {
            if !raw_rows.is_empty() {
                return Err(FaultConformanceError::invariant(
                    "issued Context snapshot has a revoke receipt",
                ));
            }
            Ok(None)
        }
        R9a3ContextGovernanceState::Revoked => {
            let [raw] = raw_rows.as_slice() else {
                return Err(FaultConformanceError::invariant(
                    "revoked Context snapshot must have exactly one revoke receipt",
                ));
            };
            let snapshot_revision = positive(raw.2, "revoke snapshot revision")?;
            let previous_state_revision = positive(raw.4, "revoke previous state revision")?;
            let result_state_revision = positive(raw.5, "revoke result state revision")?;
            validate_identity("revoke event_id", &raw.0)?;
            if !is_sha256(&raw.3) || !is_sha256(&raw.6) {
                return Err(FaultConformanceError::invariant(
                    "revoke receipt digest binding is invalid",
                ));
            }
            if raw.1 != snapshot.snapshot_id
                || snapshot_revision != snapshot.snapshot_revision
                || raw.3 != snapshot.content_digest_sha256
                || result_state_revision != snapshot.state_revision
                || result_state_revision != previous_state_revision.saturating_add(1)
            {
                return Err(FaultConformanceError::invariant(
                    "revoke receipt does not match the Context snapshot",
                ));
            }

            let event: Option<(String, String, String, String, String, i64)> = transaction
                .query_row(
                    "SELECT operation, snapshot_id, principal_id, idempotency_key,
                            request_digest_sha256, committed_at_seconds
                     FROM context_events WHERE event_id = ?1",
                    [&raw.0],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()?;
            let Some(event) = event else {
                return Err(FaultConformanceError::invariant(
                    "revoke receipt event is missing",
                ));
            };
            validate_identity("revoke principal_id", &event.2)?;
            validate_identity("revoke idempotency_key", &event.3)?;
            if event.0 != "revoke"
                || event.1 != snapshot.snapshot_id
                || event.4 != raw.6
                || event.5 != raw.7
            {
                return Err(FaultConformanceError::invariant(
                    "revoke event binding is invalid",
                ));
            }

            let idempotency_rows: Vec<(String, String, String, String)> = {
                let mut statement = transaction.prepare(
                    "SELECT principal_id, idempotency_key,
                            request_digest_sha256, event_id
                     FROM context_revoke_idempotency WHERE event_id = ?1",
                )?;
                statement
                    .query_map([&raw.0], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                    })?
                    .collect::<Result<_, _>>()?
            };
            if idempotency_rows != vec![(event.2.clone(), event.3, raw.6.clone(), raw.0.clone())] {
                return Err(FaultConformanceError::invariant(
                    "revoke idempotency binding is invalid",
                ));
            }

            Ok(Some(R9a3ContextRevokeFact {
                event_id: raw.0.clone(),
                snapshot_id: raw.1.clone(),
                snapshot_revision,
                content_digest_sha256: raw.3.clone(),
                previous_state_revision,
                result_state_revision,
                principal_id: event.2,
                request_digest_sha256: raw.6.clone(),
                committed_at_seconds: raw.7,
            }))
        }
    }
}

fn validate_identity(label: &str, value: &str) -> FaultConformanceResult<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(FaultConformanceError::invariant(format!(
            "{label} is not a complete bounded identity"
        )));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn non_negative(value: i64, label: &str) -> FaultConformanceResult<u64> {
    u64::try_from(value)
        .map_err(|_| FaultConformanceError::invariant(format!("{label} must be non-negative")))
}

fn positive(value: i64, label: &str) -> FaultConformanceResult<u64> {
    let value = non_negative(value, label)?;
    if value == 0 {
        return Err(FaultConformanceError::invariant(format!(
            "{label} must be positive"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_KEY: [u8; 32] = [0x5a; 32];
    const TEST_SCHEMA: &str = r#"
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
  created_at_seconds INTEGER NOT NULL,
  state_revision INTEGER NOT NULL CHECK (state_revision >= 1)
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

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestStore {
        root: PathBuf,
        path: PathBuf,
        snapshot_id: String,
        content_digest: String,
    }

    impl TestStore {
        fn create() -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "egopulse-r9a3-context-oracle-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create test root");
            let path = root.join("context.sqlcipher");
            let compiled_context = b"immutable compiled Context";
            let content_digest = hex::encode(Sha256::digest(compiled_context));
            let snapshot_id = format!("ctx:{content_digest}");
            let connection = Connection::open(&path).expect("open test store");
            connection
                .pragma_update(None, "key", format!("x'{}'", hex::encode(TEST_KEY)))
                .expect("set SQLCipher key");
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("enable foreign keys");
            connection
                .execute_batch(TEST_SCHEMA)
                .expect("create schema");
            connection
                .execute(
                    "INSERT INTO context_store_metadata(
                       singleton, store_epoch, schema_profile_id,
                       schema_profile_sha256, last_event_sequence
                     ) VALUES(1, 'epoch-1', ?1, ?2, 3)",
                    params![CONTEXT_STORE_PROFILE_ID, "1".repeat(64)],
                )
                .expect("insert metadata");
            connection
                .execute(
                    "INSERT INTO context_snapshots(
                       snapshot_id, revision, descriptor, compiled_context,
                       compiled_context_sha256, state, expires_at_seconds,
                       created_at_seconds, state_revision
                     ) VALUES(?1, 1, '{}', ?2, ?3, 'revoked', 2000, 1000, 2)",
                    params![snapshot_id, compiled_context, content_digest],
                )
                .expect("insert snapshot");
            for event in [
                (
                    1_i64,
                    "event-issue",
                    "issue",
                    "founder:1",
                    "idem-issue",
                    "2".repeat(64),
                    1100_i64,
                ),
                (
                    2,
                    "event-authorize",
                    "authorize-dispatch-consumption",
                    "governance-kernel",
                    "idem-authorize",
                    "3".repeat(64),
                    1200,
                ),
                (
                    3,
                    "event-revoke",
                    "revoke",
                    "founder:1",
                    "idem-revoke",
                    "4".repeat(64),
                    1300,
                ),
            ] {
                connection
                    .execute(
                        "INSERT INTO context_events(
                           sequence, event_id, snapshot_id, operation, principal_id,
                           idempotency_key, request_digest_sha256, committed_at_seconds
                         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            event.0,
                            event.1,
                            snapshot_id,
                            event.2,
                            event.3,
                            event.4,
                            event.5,
                            event.6
                        ],
                    )
                    .expect("insert event");
            }
            connection
                .execute(
                    "INSERT INTO context_idempotency_results(
                       principal_id, idempotency_key, request_digest_sha256,
                       snapshot_id, snapshot_revision, event_id
                     ) VALUES('founder:1', 'idem-issue', ?1, ?2, 1, 'event-issue')",
                    params!["2".repeat(64), snapshot_id],
                )
                .expect("insert issue idempotency");
            connection
                .execute(
                    "INSERT INTO context_dispatch_authorizations(
                       authorization_id, event_id, snapshot_id, snapshot_revision,
                       observed_state_revision, principal_id, command_id, attempt_id,
                       dispatch_id, input_digest_sha256, expected_scope_ref,
                       correlation_id, causation_id, request_digest_sha256,
                       committed_at_seconds
                     ) VALUES(
                       'authorization-1', 'event-authorize', ?1, 1, 1,
                       'governance-kernel', 'command-authorize', 'attempt-1',
                       'dispatch-1', ?2, 'workspace:1', 'correlation-1',
                       'causation-1', ?3, 1200
                     )",
                    params![snapshot_id, content_digest, "3".repeat(64)],
                )
                .expect("insert authorization");
            connection
                .execute(
                    "INSERT INTO context_dispatch_authorization_idempotency(
                       principal_id, idempotency_key, request_digest_sha256,
                       authorization_id
                     ) VALUES(
                       'governance-kernel', 'idem-authorize', ?1, 'authorization-1'
                     )",
                    ["3".repeat(64)],
                )
                .expect("insert authorization idempotency");
            connection
                .execute(
                    "INSERT INTO context_revoke_receipts(
                       event_id, snapshot_id, snapshot_revision, content_digest_sha256,
                       previous_state_revision, result_state_revision, reason_code,
                       evidence_refs, confirmation_proof_ref, command_id,
                       correlation_id, causation_id, request_digest_sha256,
                       committed_at_seconds
                     ) VALUES(
                       'event-revoke', ?1, 1, ?2, 1, 2, 'withdrawn', '[]',
                       'proof:1', 'command-revoke', 'correlation-2', NULL, ?3, 1300
                     )",
                    params![snapshot_id, content_digest, "4".repeat(64)],
                )
                .expect("insert revoke receipt");
            connection
                .execute(
                    "INSERT INTO context_revoke_idempotency(
                       principal_id, idempotency_key, request_digest_sha256, event_id
                     ) VALUES('founder:1', 'idem-revoke', ?1, 'event-revoke')",
                    ["4".repeat(64)],
                )
                .expect("insert revoke idempotency");
            drop(connection);
            Self {
                root,
                path,
                snapshot_id,
                content_digest,
            }
        }

        fn write_connection(&self) -> Connection {
            let connection = Connection::open(&self.path).expect("reopen test store");
            connection
                .pragma_update(None, "key", format!("x'{}'", hex::encode(TEST_KEY)))
                .expect("set SQLCipher key");
            connection
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).expect("remove test store");
        }
    }

    fn read(store: &TestStore, dispatch_id: &str) -> R9a3ContextAuthoritySnapshot {
        read_r9a3_context_authority_store(
            &store.path,
            &TEST_KEY,
            "epoch-1",
            &store.snapshot_id,
            dispatch_id,
        )
        .expect("read Context Authority oracle")
    }

    #[test]
    fn reads_revoked_snapshot_exact_authorization_and_total_counts() {
        let store = TestStore::create();
        let actual = read(&store, "dispatch-1");

        assert_eq!(
            actual.snapshot,
            R9a3ContextSnapshotState {
                snapshot_id: store.snapshot_id.clone(),
                snapshot_revision: 1,
                content_digest_sha256: store.content_digest.clone(),
                governance_state: R9a3ContextGovernanceState::Revoked,
                state_revision: 2,
                expires_at_seconds: 2000,
                created_at_seconds: 1000,
            }
        );
        assert_eq!(
            actual.revoke,
            Some(R9a3ContextRevokeFact {
                event_id: "event-revoke".to_owned(),
                snapshot_id: store.snapshot_id.clone(),
                snapshot_revision: 1,
                content_digest_sha256: store.content_digest.clone(),
                previous_state_revision: 1,
                result_state_revision: 2,
                principal_id: "founder:1".to_owned(),
                request_digest_sha256: "4".repeat(64),
                committed_at_seconds: 1300,
            })
        );
        assert_eq!(
            actual.dispatch_authorization,
            Some(R9a3DispatchAuthorizationReceipt {
                authorization_id: "authorization-1".to_owned(),
                event_id: "event-authorize".to_owned(),
                snapshot_id: store.snapshot_id.clone(),
                snapshot_revision: 1,
                observed_state_revision: 1,
                principal_id: "governance-kernel".to_owned(),
                command_id: "command-authorize".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                dispatch_id: "dispatch-1".to_owned(),
                input_digest_sha256: store.content_digest.clone(),
                expected_scope_ref: "workspace:1".to_owned(),
                correlation_id: "correlation-1".to_owned(),
                causation_id: "causation-1".to_owned(),
                request_digest_sha256: "3".repeat(64),
                committed_at_seconds: 1200,
            })
        );
        assert_eq!(
            actual.counts,
            R9a3ContextAuthorityCounts {
                snapshot_count: 1,
                event_count: 3,
                authorization_count: 1,
                idempotency_count: 3,
            }
        );
    }

    #[test]
    fn missing_dispatch_is_reported_without_mutating_the_store() {
        let store = TestStore::create();
        let before = read(&store, "missing-dispatch");
        let after = read(&store, "missing-dispatch");

        assert_eq!(before, after);
        assert_eq!(before.dispatch_authorization, None);
        assert_eq!(before.counts.authorization_count, 1);
    }

    #[test]
    fn reader_is_sqlcipher_read_only_and_query_only() {
        let store = TestStore::create();
        let connection = open_context_store_read_only(&store.path, &TEST_KEY).expect("open reader");

        assert!(
            connection
                .execute("DELETE FROM context_dispatch_authorizations", [])
                .is_err()
        );
        assert_eq!(read(&store, "dispatch-1").counts.authorization_count, 1);
    }

    #[test]
    fn wrong_store_epoch_fails_closed() {
        let store = TestStore::create();
        assert!(
            read_r9a3_context_authority_store(
                &store.path,
                &TEST_KEY,
                "wrong-epoch",
                &store.snapshot_id,
                "dispatch-1",
            )
            .is_err()
        );
    }

    #[test]
    fn authorization_lineage_drift_fails_closed() {
        let store = TestStore::create();
        let connection = store.write_connection();
        connection
            .execute(
                "UPDATE context_dispatch_authorizations
                 SET observed_state_revision = 2 WHERE dispatch_id = 'dispatch-1'",
                [],
            )
            .expect("inject lineage drift");
        drop(connection);

        let error = read_r9a3_context_authority_store(
            &store.path,
            &TEST_KEY,
            "epoch-1",
            &store.snapshot_id,
            "dispatch-1",
        )
        .expect_err("lineage drift must fail closed");
        assert!(error.to_string().contains("requested Context lineage"));
    }

    #[test]
    fn authorization_event_or_idempotency_drift_fails_closed() {
        for statement in [
            "UPDATE context_events SET request_digest_sha256 = '5555555555555555555555555555555555555555555555555555555555555555' WHERE event_id = 'event-authorize'",
            "UPDATE context_dispatch_authorization_idempotency SET principal_id = 'other-principal' WHERE authorization_id = 'authorization-1'",
        ] {
            let store = TestStore::create();
            let connection = store.write_connection();
            connection
                .execute(statement, [])
                .expect("inject binding drift");
            drop(connection);

            assert!(
                read_r9a3_context_authority_store(
                    &store.path,
                    &TEST_KEY,
                    "epoch-1",
                    &store.snapshot_id,
                    "dispatch-1",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn snapshot_content_tamper_fails_closed() {
        let store = TestStore::create();
        let connection = store.write_connection();
        connection
            .execute(
                "UPDATE context_snapshots SET compiled_context = x'00' WHERE snapshot_id = ?1",
                [&store.snapshot_id],
            )
            .expect("inject snapshot tamper");
        drop(connection);

        assert!(
            read_r9a3_context_authority_store(
                &store.path,
                &TEST_KEY,
                "epoch-1",
                &store.snapshot_id,
                "dispatch-1",
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_key_cannot_read_context_store() {
        let store = TestStore::create();
        assert!(
            read_r9a3_context_authority_store(
                Path::new(&store.path),
                &[0x6b; 32],
                "epoch-1",
                &store.snapshot_id,
                "dispatch-1",
            )
            .is_err()
        );
    }

    #[test]
    fn missing_or_drifted_revoke_audit_chain_fails_closed() {
        for statement in [
            "DELETE FROM context_revoke_idempotency WHERE event_id = 'event-revoke';
             DELETE FROM context_revoke_receipts WHERE event_id = 'event-revoke';",
            "UPDATE context_events SET principal_id = 'other-founder' WHERE event_id = 'event-revoke'",
            "INSERT INTO context_revoke_idempotency(principal_id, idempotency_key, request_digest_sha256, event_id) VALUES('other-founder', 'other-idempotency', '4444444444444444444444444444444444444444444444444444444444444444', 'event-revoke')",
        ] {
            let store = TestStore::create();
            let connection = store.write_connection();
            connection
                .execute_batch(statement)
                .expect("inject revoke audit drift");
            drop(connection);

            assert!(
                read_r9a3_context_authority_store(
                    &store.path,
                    &TEST_KEY,
                    "epoch-1",
                    &store.snapshot_id,
                    "dispatch-1",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn issued_snapshot_requires_absent_revoke_receipt() {
        let store = TestStore::create();
        let connection = store.write_connection();
        connection
            .execute(
                "UPDATE context_snapshots SET state = 'issued', state_revision = 1
                 WHERE snapshot_id = ?1",
                [&store.snapshot_id],
            )
            .expect("restore issued snapshot");
        drop(connection);

        assert!(
            read_r9a3_context_authority_store(
                &store.path,
                &TEST_KEY,
                "epoch-1",
                &store.snapshot_id,
                "dispatch-1",
            )
            .is_err()
        );

        let connection = store.write_connection();
        connection
            .execute(
                "DELETE FROM context_revoke_idempotency WHERE event_id = 'event-revoke'",
                [],
            )
            .expect("delete revoke idempotency");
        connection
            .execute(
                "DELETE FROM context_revoke_receipts WHERE event_id = 'event-revoke'",
                [],
            )
            .expect("delete revoke receipt");
        connection
            .execute(
                "DELETE FROM context_events WHERE event_id = 'event-revoke'",
                [],
            )
            .expect("delete revoke event");
        drop(connection);

        let actual = read(&store, "dispatch-1");
        assert_eq!(
            actual.snapshot.governance_state,
            R9a3ContextGovernanceState::Issued
        );
        assert_eq!(actual.snapshot.state_revision, 1);
        assert_eq!(actual.revoke, None);
    }
}
