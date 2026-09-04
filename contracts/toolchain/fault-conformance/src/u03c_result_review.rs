//! Strict read-only durability oracle for the U-03c daemon fixture.
//!
//! This module deliberately returns opaque protobuf bytes and primitive counts.
//! Product crates remain responsible for typed decoding and this conformance
//! surface cannot migrate or write any owner database.

use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, params, types::ValueRef};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const TABLE_DIGEST_DOMAIN: &[u8] = b"egopulse/fault-conformance/table-snapshot/v1";

const TASK_TABLES: &[&str] = &[
    "sqlite_sequence",
    "task_store_metadata",
    "tasks",
    "task_events",
    "task_idempotency_results",
    "task_outbox",
    "task_commit_receipts",
    "task_cross_authority_outbox",
    "task_commit_outbox_links",
];
const COLLABORATION_TABLES: &[&str] = &[
    "sqlite_sequence",
    "collaboration_store_metadata",
    "collaboration_runs",
    "collaboration_steps",
    "collaboration_attempts",
    "collaboration_events",
    "collaboration_idempotency_results",
    "collaboration_outbox",
    "collaboration_commit_receipts",
    "collaboration_commit_outboxes",
    "collaboration_projection_migrations",
];
const ARTIFACT_TABLES: &[&str] = &[
    "sqlite_sequence",
    "artifact_store_metadata",
    "artifacts",
    "claims",
    "evidence",
    "artifact_sets",
    "return_handoffs",
    "return_receipts",
    "artifact_events",
    "artifact_idempotency_results",
    "artifact_outbox",
    "artifact_commit_receipts",
];
const VERIFICATION_TABLES: &[&str] = &[
    "sqlite_sequence",
    "verification_store_metadata",
    "checker_profiles",
    "verification_requests",
    "verification_runs",
    "criterion_results",
    "verification_artifacts",
    "verification_events",
    "verification_idempotency_results",
    "verification_outbox",
    "verification_commit_receipts",
];
const VERDICT_TABLES: &[&str] = &[
    "sqlite_sequence",
    "verdict_store_metadata",
    "founder_verdicts",
    "founder_verdict_states",
    "verdict_events",
    "verdict_idempotency_results",
    "verdict_outbox",
    "verdict_consumption_receipts",
    "verdict_commit_receipts",
    "verdict_projection_outbox",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedStoreProfile<'a> {
    pub schema_profile_id: &'a str,
    pub schema_profile_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableDurabilityDigest {
    pub table_name: String,
    pub row_count: u64,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerMetadata {
    pub store_epoch: String,
    pub schema_profile_id: String,
    pub schema_profile_sha256: String,
    pub last_committed_revision: Option<u64>,
    pub last_event_sequence: u64,
    /// Deterministic full-row digests for the owner's exact fixed table set.
    pub table_digests: Vec<TableDurabilityDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDurabilitySnapshot {
    pub metadata: OwnerMetadata,
    pub task_snapshot: Vec<u8>,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub cross_authority_outbox_count: u64,
    pub pending_local_read_model_outbox_count: u64,
    pub pending_founder_verdict_cross_outbox_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollaborationDurabilitySnapshot {
    pub metadata: OwnerMetadata,
    pub run_snapshot: Vec<u8>,
    pub step_snapshot: Vec<u8>,
    pub attempt_snapshot: Vec<u8>,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub pending_local_read_model_outbox_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDurabilitySnapshot {
    pub metadata: OwnerMetadata,
    pub artifact_snapshot: Vec<u8>,
    pub claim_snapshot: Vec<u8>,
    pub evidence_snapshot: Vec<u8>,
    pub artifact_set_snapshot: Vec<u8>,
    pub return_handoff_snapshot: Vec<u8>,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub pending_local_read_model_outbox_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationDurabilitySnapshot {
    pub metadata: OwnerMetadata,
    pub checker_profile_snapshot: Vec<u8>,
    pub request_snapshot: Vec<u8>,
    pub run_snapshot: Vec<u8>,
    pub artifact_snapshot: Vec<u8>,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub pending_local_read_model_outbox_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerdictDurabilitySnapshot {
    pub metadata: OwnerMetadata,
    pub verdict_snapshot: Vec<u8>,
    pub state_snapshot: Vec<u8>,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub outbox_count: u64,
    pub consumption_receipt_count: u64,
    pub pending_projection_outbox_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedResultDurabilitySnapshot {
    pub task: TaskDurabilitySnapshot,
    pub collaboration: CollaborationDurabilitySnapshot,
    pub artifact: ArtifactDurabilitySnapshot,
    pub verification: VerificationDurabilitySnapshot,
    pub verdict: VerdictDurabilitySnapshot,
}

#[derive(Clone, Debug)]
pub struct GovernedResultOracleRequest<'a> {
    pub root: &'a Path,
    pub task_id: &'a str,
    pub run_id: &'a str,
    pub step_id: &'a str,
    pub attempt_id: &'a str,
    pub artifact_id: &'a str,
    pub claim_id: &'a str,
    pub evidence_id: &'a str,
    pub artifact_set_id: &'a str,
    pub return_handoff_id: &'a str,
    pub checker_profile_id: &'a str,
    pub verification_request_id: &'a str,
    pub verification_run_id: &'a str,
    pub verification_artifact_id: &'a str,
    pub task_profile: ExpectedStoreProfile<'a>,
    pub collaboration_profile: ExpectedStoreProfile<'a>,
    pub artifact_profile: ExpectedStoreProfile<'a>,
    pub verification_profile: ExpectedStoreProfile<'a>,
    pub verdict_profile: ExpectedStoreProfile<'a>,
}

pub fn read_governed_result_durability(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<GovernedResultDurabilitySnapshot> {
    Ok(GovernedResultDurabilitySnapshot {
        task: read_task(request)?,
        collaboration: read_collaboration(request)?,
        artifact: read_artifact(request)?,
        verification: read_verification(request)?,
        verdict: read_verdict(request)?,
    })
}

/// Discovers the sole durable Task identity without opening a product writer.
///
/// The read is bound to the U-03c fixture store identity and validates the
/// complete fixed Task table set before publishing the identity.
pub fn discover_single_task_id(
    root: &Path,
    expected_profile: &ExpectedStoreProfile<'_>,
) -> FaultConformanceResult<String> {
    let mut connection = open_read_only(root.join("task-authority.db"), [0x11; 32])?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut owner = metadata(
        &tx,
        "task_store_metadata",
        "c5-00-task-epoch",
        expected_profile,
        true,
    )?;
    require_sequence(&owner, &tx, "task_events")?;
    owner.table_digests = table_digests(&tx, TASK_TABLES)?;
    if count(&tx, "tasks")? != 1 {
        return Err(FaultConformanceError::invariant(
            "U-03c Task identity is not unique",
        ));
    }
    let task_id: String = tx.query_row("SELECT task_id FROM tasks", [], |row| row.get(0))?;
    if task_id.is_empty() || task_id.chars().any(char::is_control) {
        return Err(FaultConformanceError::invariant(
            "U-03c Task identity is invalid",
        ));
    }
    tx.commit()?;
    Ok(task_id)
}

fn open_read_only(path: PathBuf, key: [u8; 32]) -> FaultConformanceResult<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;
    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 {
        return Err(FaultConformanceError::invariant(
            "U-03c oracle failed to enter query-only mode",
        ));
    }
    let mut cipher = connection.prepare("PRAGMA cipher_integrity_check")?;
    let findings = cipher
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(cipher);
    if !findings.is_empty() {
        return Err(FaultConformanceError::invariant(
            "U-03c SQLCipher integrity check reported findings",
        ));
    }
    let integrity = connection
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if integrity != ["ok"] {
        return Err(FaultConformanceError::invariant(
            "U-03c SQLite integrity check failed",
        ));
    }
    Ok(connection)
}

fn metadata(
    tx: &Transaction<'_>,
    table: &str,
    expected_epoch: &str,
    expected_profile: &ExpectedStoreProfile<'_>,
    has_revision: bool,
) -> FaultConformanceResult<OwnerMetadata> {
    let sql = if has_revision {
        format!(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256, last_committed_revision, last_event_sequence FROM {table} WHERE singleton=1"
        )
    } else {
        format!(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256, NULL, last_event_sequence FROM {table} WHERE singleton=1"
        )
    };
    let (store_epoch, schema_profile_id, schema_profile_sha256, revision, sequence): (
        String,
        String,
        String,
        Option<i64>,
        i64,
    ) = tx.query_row(&sql, [], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    let value = OwnerMetadata {
        store_epoch,
        schema_profile_id,
        schema_profile_sha256,
        last_committed_revision: revision
            .map(u64::try_from)
            .transpose()
            .map_err(|_| FaultConformanceError::invariant("negative owner revision"))?,
        last_event_sequence: u64::try_from(sequence)
            .map_err(|_| FaultConformanceError::invariant("negative event sequence"))?,
        table_digests: Vec::new(),
    };
    if value.store_epoch != expected_epoch
        || expected_profile.schema_profile_id.is_empty()
        || !is_sha256(expected_profile.schema_profile_sha256)
        || value.schema_profile_id != expected_profile.schema_profile_id
        || value.schema_profile_sha256 != expected_profile.schema_profile_sha256
    {
        return Err(FaultConformanceError::invariant(
            "U-03c owner metadata does not match the fixture identity",
        ));
    }
    Ok(value)
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}

fn table_digests(
    tx: &Transaction<'_>,
    expected_tables: &[&str],
) -> FaultConformanceResult<Vec<TableDurabilityDigest>> {
    let mut actual_tables = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected_sorted = expected_tables
        .iter()
        .map(|table| (*table).to_owned())
        .collect::<Vec<_>>();
    actual_tables.sort();
    expected_sorted.sort();
    if actual_tables != expected_sorted {
        return Err(FaultConformanceError::invariant(
            "U-03c owner table set does not match the fixed allowlist",
        ));
    }

    let mut result = Vec::with_capacity(expected_tables.len());
    for table in expected_tables {
        let mut statement = tx.prepare(&format!("SELECT * FROM \"{table}\""))?;
        let column_count = statement.column_count();
        let mut rows = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = rows.next()? {
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&(column_count as u64).to_le_bytes());
            for index in 0..column_count {
                match row.get_ref(index)? {
                    ValueRef::Null => encoded.push(0),
                    ValueRef::Integer(value) => {
                        encoded.push(1);
                        encoded.extend_from_slice(&value.to_le_bytes());
                    }
                    ValueRef::Real(value) => {
                        encoded.push(2);
                        encoded.extend_from_slice(&value.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) => {
                        encoded.push(3);
                        append_framed(&mut encoded, value);
                    }
                    ValueRef::Blob(value) => {
                        encoded.push(4);
                        append_framed(&mut encoded, value);
                    }
                }
            }
            encoded_rows.push(encoded);
        }
        encoded_rows.sort();
        let mut digest_input = Vec::new();
        append_framed(&mut digest_input, TABLE_DIGEST_DOMAIN);
        append_framed(&mut digest_input, table.as_bytes());
        digest_input.extend_from_slice(&(encoded_rows.len() as u64).to_le_bytes());
        for row in &encoded_rows {
            append_framed(&mut digest_input, row);
        }
        result.push(TableDurabilityDigest {
            table_name: (*table).to_owned(),
            row_count: encoded_rows.len() as u64,
            content_sha256: hex::encode(Sha256::digest(digest_input)),
        });
    }
    Ok(result)
}

fn blob(tx: &Transaction<'_>, sql: &str, identity: &str) -> FaultConformanceResult<Vec<u8>> {
    let value = tx.query_row(sql, params![identity], |row| row.get(0))?;
    Ok(value)
}

fn count(tx: &Transaction<'_>, table: &str) -> FaultConformanceResult<u64> {
    let value: i64 = tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    u64::try_from(value).map_err(|_| FaultConformanceError::invariant("negative U-03c row count"))
}

fn count_query(tx: &Transaction<'_>, sql: &str) -> FaultConformanceResult<u64> {
    let value: i64 = tx.query_row(sql, [], |row| row.get(0))?;
    u64::try_from(value).map_err(|_| FaultConformanceError::invariant("negative pending row count"))
}

fn require_sequence(
    metadata: &OwnerMetadata,
    tx: &Transaction<'_>,
    table: &str,
) -> FaultConformanceResult<()> {
    let maximum: i64 = tx.query_row(
        &format!("SELECT COALESCE(MAX(sequence), 0) FROM {table}"),
        [],
        |row| row.get(0),
    )?;
    if metadata.last_event_sequence != u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(FaultConformanceError::invariant(
            "U-03c metadata/event sequence mismatch",
        ));
    }
    Ok(())
}

fn read_task(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<TaskDurabilitySnapshot> {
    let mut connection = open_read_only(request.root.join("task-authority.db"), [0x11; 32])?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut metadata = metadata(
        &tx,
        "task_store_metadata",
        "c5-00-task-epoch",
        &request.task_profile,
        true,
    )?;
    require_sequence(&metadata, &tx, "task_events")?;
    metadata.table_digests = table_digests(&tx, TASK_TABLES)?;
    let result = TaskDurabilitySnapshot {
        task_snapshot: blob(
            &tx,
            "SELECT snapshot FROM tasks WHERE task_id=?1",
            request.task_id,
        )?,
        event_count: count(&tx, "task_events")?,
        idempotency_count: count(&tx, "task_idempotency_results")?,
        outbox_count: count(&tx, "task_outbox")?,
        cross_authority_outbox_count: count(&tx, "task_cross_authority_outbox")?,
        pending_local_read_model_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM task_outbox WHERE destination_domain='local-read-model' AND delivery_state='pending'",
        )?,
        pending_founder_verdict_cross_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM task_cross_authority_outbox WHERE destination_domain='founder-verdict-authority' AND delivery_state='pending'",
        )?,
        metadata,
    };
    tx.commit()?;
    Ok(result)
}

fn read_collaboration(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<CollaborationDurabilitySnapshot> {
    let mut connection = open_read_only(request.root.join("u03c-collaboration.db"), [0x73; 32])?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut metadata = metadata(
        &tx,
        "collaboration_store_metadata",
        "u03c-collaboration-epoch",
        &request.collaboration_profile,
        true,
    )?;
    require_sequence(&metadata, &tx, "collaboration_events")?;
    metadata.table_digests = table_digests(&tx, COLLABORATION_TABLES)?;
    let result = CollaborationDurabilitySnapshot {
        run_snapshot: blob(
            &tx,
            "SELECT snapshot FROM collaboration_runs WHERE run_id=?1",
            request.run_id,
        )?,
        step_snapshot: blob(
            &tx,
            "SELECT snapshot FROM collaboration_steps WHERE step_id=?1",
            request.step_id,
        )?,
        attempt_snapshot: blob(
            &tx,
            "SELECT snapshot FROM collaboration_attempts WHERE attempt_id=?1",
            request.attempt_id,
        )?,
        event_count: count(&tx, "collaboration_events")?,
        idempotency_count: count(&tx, "collaboration_idempotency_results")?,
        outbox_count: count(&tx, "collaboration_outbox")?,
        pending_local_read_model_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM collaboration_outbox WHERE destination_domain='local-read-model' AND payload_kind='collaboration-snapshot-v1' AND delivery_state='pending'",
        )?,
        metadata,
    };
    tx.commit()?;
    Ok(result)
}

fn read_artifact(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<ArtifactDurabilitySnapshot> {
    let mut connection =
        open_read_only(request.root.join("u03c-artifact-authority.db"), [0x74; 32])?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut metadata = metadata(
        &tx,
        "artifact_store_metadata",
        "u03c-artifact-epoch",
        &request.artifact_profile,
        true,
    )?;
    require_sequence(&metadata, &tx, "artifact_events")?;
    metadata.table_digests = table_digests(&tx, ARTIFACT_TABLES)?;
    let result = ArtifactDurabilitySnapshot {
        artifact_snapshot: blob(
            &tx,
            "SELECT snapshot FROM artifacts WHERE artifact_id=?1",
            request.artifact_id,
        )?,
        claim_snapshot: blob(
            &tx,
            "SELECT snapshot FROM claims WHERE claim_id=?1",
            request.claim_id,
        )?,
        evidence_snapshot: blob(
            &tx,
            "SELECT snapshot FROM evidence WHERE evidence_id=?1",
            request.evidence_id,
        )?,
        artifact_set_snapshot: blob(
            &tx,
            "SELECT snapshot FROM artifact_sets WHERE artifact_set_id=?1",
            request.artifact_set_id,
        )?,
        return_handoff_snapshot: blob(
            &tx,
            "SELECT snapshot FROM return_handoffs WHERE return_handoff_id=?1",
            request.return_handoff_id,
        )?,
        event_count: count(&tx, "artifact_events")?,
        idempotency_count: count(&tx, "artifact_idempotency_results")?,
        outbox_count: count(&tx, "artifact_outbox")?,
        pending_local_read_model_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM artifact_outbox WHERE destination_domain='local-read-model' AND delivery_state='pending'",
        )?,
        metadata,
    };
    tx.commit()?;
    Ok(result)
}

fn read_verification(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<VerificationDurabilitySnapshot> {
    let mut connection = open_read_only(
        request.root.join("u03c-verification-authority.db"),
        [0x75; 32],
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut metadata = metadata(
        &tx,
        "verification_store_metadata",
        "u03c-verification-epoch",
        &request.verification_profile,
        true,
    )?;
    require_sequence(&metadata, &tx, "verification_events")?;
    metadata.table_digests = table_digests(&tx, VERIFICATION_TABLES)?;
    let result = VerificationDurabilitySnapshot {
        checker_profile_snapshot: blob(
            &tx,
            "SELECT snapshot FROM checker_profiles WHERE checker_profile_id=?1",
            request.checker_profile_id,
        )?,
        request_snapshot: blob(
            &tx,
            "SELECT snapshot FROM verification_requests WHERE verification_request_id=?1",
            request.verification_request_id,
        )?,
        run_snapshot: blob(
            &tx,
            "SELECT snapshot FROM verification_runs WHERE verification_run_id=?1",
            request.verification_run_id,
        )?,
        artifact_snapshot: blob(
            &tx,
            "SELECT snapshot FROM verification_artifacts WHERE verification_artifact_id=?1",
            request.verification_artifact_id,
        )?,
        event_count: count(&tx, "verification_events")?,
        idempotency_count: count(&tx, "verification_idempotency_results")?,
        outbox_count: count(&tx, "verification_outbox")?,
        pending_local_read_model_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM verification_outbox WHERE destination_domain='local-read-model' AND delivery_state='pending'",
        )?,
        metadata,
    };
    tx.commit()?;
    Ok(result)
}

fn read_verdict(
    request: &GovernedResultOracleRequest<'_>,
) -> FaultConformanceResult<VerdictDurabilitySnapshot> {
    let mut connection = open_read_only(request.root.join("verdict-authority.db"), [0x13; 32])?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut metadata = metadata(
        &tx,
        "verdict_store_metadata",
        "c5-00-verdict-epoch",
        &request.verdict_profile,
        false,
    )?;
    require_sequence(&metadata, &tx, "verdict_events")?;
    metadata.table_digests = table_digests(&tx, VERDICT_TABLES)?;
    if count(&tx, "founder_verdicts")? != 1 || count(&tx, "founder_verdict_states")? != 1 {
        return Err(FaultConformanceError::invariant(
            "U-03c verdict identity is not unique",
        ));
    }
    let result = VerdictDurabilitySnapshot {
        verdict_snapshot: tx
            .query_row("SELECT verdict FROM founder_verdicts", [], |row| row.get(0))?,
        state_snapshot: tx.query_row(
            "SELECT state_blob FROM founder_verdict_states",
            [],
            |row| row.get(0),
        )?,
        event_count: count(&tx, "verdict_events")?,
        idempotency_count: count(&tx, "verdict_idempotency_results")?,
        outbox_count: count(&tx, "verdict_outbox")?,
        consumption_receipt_count: count(&tx, "verdict_consumption_receipts")?,
        pending_projection_outbox_count: count_query(
            &tx,
            "SELECT count(*) FROM verdict_projection_outbox WHERE delivery_state='pending'",
        )?,
        metadata,
    };
    tx.commit()?;
    Ok(result)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
