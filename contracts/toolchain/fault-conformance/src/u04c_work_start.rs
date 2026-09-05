use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, types::ValueRef};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const TABLE_DIGEST_DOMAIN: &[u8] = b"egopulse/u04c/table-durability/v1";
const CONTEXT_PROFILE_ID: &str = "egopulse/context-authority-store/v1";
const TASK_PROFILE_ID: &str = "egopulse/task-authority-store/v1";
const CONTEXT_TABLES: &[&str] = &[
    "sqlite_sequence",
    "context_store_metadata",
    "context_snapshots",
    "context_events",
    "context_idempotency_results",
    "context_memory_use_receipts",
    "context_memory_use_idempotency",
    "context_revoke_receipts",
    "context_revoke_idempotency",
    "context_dispatch_authorizations",
    "context_dispatch_authorization_idempotency",
];
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U04cTableDigest {
    pub table_name: String,
    pub row_count: u64,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U04cStoreSnapshot {
    pub store_epoch: String,
    pub schema_profile_id: String,
    pub schema_profile_sha256: String,
    pub last_committed_revision: Option<u64>,
    pub last_event_sequence: u64,
    pub table_digests: Vec<U04cTableDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U04cContextRecord {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub state_revision: u64,
    pub state: String,
    pub compiled_context_sha256: String,
    pub immutable_row_sha256: String,
    pub issue_receipt_row_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U04cTaskRecord {
    pub task_id: String,
    pub revision: u64,
    pub status: i32,
    pub snapshot: Vec<u8>,
    pub snapshot_sha256: String,
    pub idempotency_receipt_row_sha256: String,
    pub commit_receipt_row_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct U04cWorkStartDurabilitySnapshot {
    pub context: U04cStoreSnapshot,
    pub context_record: Option<U04cContextRecord>,
    pub task: U04cStoreSnapshot,
    pub task_record: Option<U04cTaskRecord>,
}

pub struct U04cWorkStartOracleRequest<'a> {
    pub root: &'a Path,
    pub context_key: &'a [u8; 32],
    pub context_store_epoch: &'a str,
    pub context_schema_sha256: &'a str,
    pub task_key: &'a [u8; 32],
    pub task_store_epoch: &'a str,
    pub task_schema_sha256: &'a str,
    pub snapshot_id: Option<&'a str>,
    pub task_id: Option<&'a str>,
}

pub fn read_u04c_work_start_durability(
    request: &U04cWorkStartOracleRequest<'_>,
) -> FaultConformanceResult<U04cWorkStartDurabilitySnapshot> {
    validate_request(request)?;
    let (context, context_record) = read_context(request)?;
    let (task, task_record) = read_task(request)?;
    Ok(U04cWorkStartDurabilitySnapshot {
        context,
        context_record,
        task,
        task_record,
    })
}

fn validate_request(request: &U04cWorkStartOracleRequest<'_>) -> FaultConformanceResult<()> {
    for (name, value) in [
        ("context store epoch", request.context_store_epoch),
        ("task store epoch", request.task_store_epoch),
    ] {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(FaultConformanceError::invariant(format!(
                "invalid U-04c {name}"
            )));
        }
    }
    if !is_sha256(request.context_schema_sha256)
        || !is_sha256(request.task_schema_sha256)
        || request.snapshot_id.is_some_and(str::is_empty)
        || request.task_id.is_some_and(str::is_empty)
    {
        return Err(FaultConformanceError::invariant(
            "invalid U-04c oracle identity",
        ));
    }
    Ok(())
}

fn read_context(
    request: &U04cWorkStartOracleRequest<'_>,
) -> FaultConformanceResult<(U04cStoreSnapshot, Option<U04cContextRecord>)> {
    let mut connection = open_read_only(
        &request.root.join("context-authority.db"),
        request.context_key,
    )?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut store = read_metadata(
        &tx,
        "context_store_metadata",
        request.context_store_epoch,
        CONTEXT_PROFILE_ID,
        request.context_schema_sha256,
        false,
    )?;
    require_sequence(&tx, "context_events", store.last_event_sequence)?;
    store.table_digests = table_digests(&tx, CONTEXT_TABLES)?;
    let record = request
        .snapshot_id
        .map(|snapshot_id| read_context_record(&tx, snapshot_id))
        .transpose()?;
    tx.commit()?;
    Ok((store, record.flatten()))
}

fn read_task(
    request: &U04cWorkStartOracleRequest<'_>,
) -> FaultConformanceResult<(U04cStoreSnapshot, Option<U04cTaskRecord>)> {
    let mut connection = open_read_only(&request.root.join("task-authority.db"), request.task_key)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut store = read_metadata(
        &tx,
        "task_store_metadata",
        request.task_store_epoch,
        TASK_PROFILE_ID,
        request.task_schema_sha256,
        true,
    )?;
    require_sequence(&tx, "task_events", store.last_event_sequence)?;
    store.table_digests = table_digests(&tx, TASK_TABLES)?;
    let record = request
        .task_id
        .map(|task_id| read_task_record(&tx, task_id))
        .transpose()?;
    tx.commit()?;
    Ok((store, record.flatten()))
}

fn open_read_only(path: &Path, key: &[u8; 32]) -> FaultConformanceResult<Connection> {
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
            "U-04c SQLCipher support is unavailable",
        ));
    }
    connection.pragma_update(None, "query_only", "ON")?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 {
        return Err(FaultConformanceError::invariant(
            "U-04c connection is not query-only",
        ));
    }
    let findings = connection
        .prepare("PRAGMA cipher_integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if !findings.is_empty() {
        return Err(FaultConformanceError::invariant(
            "U-04c SQLCipher integrity check failed",
        ));
    }
    let integrity = connection
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if integrity != ["ok"] {
        return Err(FaultConformanceError::invariant(
            "U-04c SQLite integrity check failed",
        ));
    }
    Ok(connection)
}

fn read_metadata(
    tx: &Transaction<'_>,
    table: &str,
    expected_epoch: &str,
    expected_profile: &str,
    expected_sha256: &str,
    has_revision: bool,
) -> FaultConformanceResult<U04cStoreSnapshot> {
    let sql = if has_revision {
        format!(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256,last_committed_revision,last_event_sequence FROM {table} WHERE singleton=1"
        )
    } else {
        format!(
            "SELECT store_epoch,schema_profile_id,schema_profile_sha256,NULL,last_event_sequence FROM {table} WHERE singleton=1"
        )
    };
    let raw: (String, String, String, Option<i64>, i64) = tx.query_row(&sql, [], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    if raw.0 != expected_epoch || raw.1 != expected_profile || raw.2 != expected_sha256 {
        return Err(FaultConformanceError::invariant(
            "U-04c store metadata does not match the expected identity",
        ));
    }
    Ok(U04cStoreSnapshot {
        store_epoch: raw.0,
        schema_profile_id: raw.1,
        schema_profile_sha256: raw.2,
        last_committed_revision: raw
            .3
            .map(|value| non_negative(value, "revision"))
            .transpose()?,
        last_event_sequence: non_negative(raw.4, "event sequence")?,
        table_digests: Vec::new(),
    })
}

fn read_context_record(
    tx: &Transaction<'_>,
    snapshot_id: &str,
) -> FaultConformanceResult<Option<U04cContextRecord>> {
    let mut statement = tx.prepare(
        "SELECT revision,state_revision,state,compiled_context_sha256,compiled_context,descriptor,expires_at_seconds,created_at_seconds FROM context_snapshots WHERE snapshot_id=?1",
    )?;
    let mut rows = statement.query([snapshot_id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let revision: i64 = row.get(0)?;
    let state_revision: i64 = row.get(1)?;
    let state: String = row.get(2)?;
    let digest: String = row.get(3)?;
    let compiled: Vec<u8> = row.get(4)?;
    let descriptor: String = row.get(5)?;
    let expires: i64 = row.get(6)?;
    let created: i64 = row.get(7)?;
    if rows.next()?.is_some()
        || !is_sha256(&digest)
        || hex::encode(Sha256::digest(&compiled)) != digest
    {
        return Err(FaultConformanceError::invariant(
            "invalid U-04c Context snapshot",
        ));
    }
    let immutable_row_sha256 = digest_fields(&[
        snapshot_id.as_bytes(),
        &revision.to_le_bytes(),
        descriptor.as_bytes(),
        digest.as_bytes(),
        state.as_bytes(),
        &state_revision.to_le_bytes(),
        &expires.to_le_bytes(),
        &created.to_le_bytes(),
    ]);
    let issue_receipt_row_sha256 = digest_query_rows(
        tx,
        "SELECT principal_id,idempotency_key,request_digest_sha256,snapshot_revision,event_id FROM context_idempotency_results WHERE snapshot_id=?1",
        snapshot_id,
    )?;
    Ok(Some(U04cContextRecord {
        snapshot_id: snapshot_id.to_owned(),
        snapshot_revision: positive(revision, "Context snapshot revision")?,
        state_revision: positive(state_revision, "Context state revision")?,
        state,
        compiled_context_sha256: digest,
        immutable_row_sha256,
        issue_receipt_row_sha256,
    }))
}

fn read_task_record(
    tx: &Transaction<'_>,
    task_id: &str,
) -> FaultConformanceResult<Option<U04cTaskRecord>> {
    let mut statement =
        tx.prepare("SELECT revision,status,snapshot FROM tasks WHERE task_id=?1")?;
    let mut rows = statement.query([task_id])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let revision: i64 = row.get(0)?;
    let status: i64 = row.get(1)?;
    let snapshot: Vec<u8> = row.get(2)?;
    if rows.next()?.is_some() {
        return Err(FaultConformanceError::invariant("duplicate U-04c Task"));
    }
    let idempotency_receipt_row_sha256 = digest_query_rows(
        tx,
        "SELECT authenticated_principal_id,operation,idempotency_scope,idempotency_key,request_digest_sha256,task_revision,event_id,result FROM task_idempotency_results WHERE task_id=?1",
        task_id,
    )?;
    let commit_receipt_row_sha256 = digest_query_rows(
        tx,
        "SELECT event_id,aggregate_revision,outbox_message_id,idempotency_key,request_digest_sha256,store_epoch,acknowledged_after_durability_barrier,committed_at_seconds FROM task_commit_receipts WHERE aggregate_id=?1",
        task_id,
    )?;
    Ok(Some(U04cTaskRecord {
        task_id: task_id.to_owned(),
        revision: positive(revision, "Task revision")?,
        status: i32::try_from(status)
            .map_err(|_| FaultConformanceError::invariant("invalid Task status"))?,
        snapshot_sha256: hex::encode(Sha256::digest(&snapshot)),
        snapshot,
        idempotency_receipt_row_sha256,
        commit_receipt_row_sha256,
    }))
}

fn digest_query_rows(
    tx: &Transaction<'_>,
    sql: &str,
    identity: &str,
) -> FaultConformanceResult<String> {
    let mut statement = tx.prepare(sql)?;
    let column_count = statement.column_count();
    let mut rows = statement.query([identity])?;
    let mut encoded_rows = Vec::new();
    while let Some(row) = rows.next()? {
        encoded_rows.push(encode_row(row, column_count)?);
    }
    encoded_rows.sort();
    let refs = encoded_rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(digest_fields(&refs))
}

fn table_digests(
    tx: &Transaction<'_>,
    expected: &[&str],
) -> FaultConformanceResult<Vec<U04cTableDigest>> {
    let mut actual = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut wanted = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    actual.sort();
    wanted.sort();
    if actual != wanted {
        return Err(FaultConformanceError::invariant(
            "U-04c store table set differs from the fixed allowlist",
        ));
    }
    let mut result = Vec::with_capacity(expected.len());
    for table in expected {
        let mut statement = tx.prepare(&format!("SELECT * FROM \"{table}\""))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = rows.next()? {
            encoded_rows.push(encode_row(row, columns)?);
        }
        encoded_rows.sort();
        let mut framed = Vec::new();
        append_framed(&mut framed, TABLE_DIGEST_DOMAIN);
        append_framed(&mut framed, table.as_bytes());
        framed.extend_from_slice(&(encoded_rows.len() as u64).to_le_bytes());
        for row in &encoded_rows {
            append_framed(&mut framed, row);
        }
        result.push(U04cTableDigest {
            table_name: (*table).to_owned(),
            row_count: encoded_rows.len() as u64,
            content_sha256: hex::encode(Sha256::digest(framed)),
        });
    }
    Ok(result)
}

fn encode_row(row: &rusqlite::Row<'_>, columns: usize) -> FaultConformanceResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(columns as u64).to_le_bytes());
    for index in 0..columns {
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
    Ok(encoded)
}

fn require_sequence(
    tx: &Transaction<'_>,
    event_table: &str,
    expected: u64,
) -> FaultConformanceResult<()> {
    let maximum: i64 = tx.query_row(
        &format!("SELECT COALESCE(MAX(sequence),0) FROM {event_table}"),
        [],
        |row| row.get(0),
    )?;
    if non_negative(maximum, "maximum event sequence")? != expected {
        return Err(FaultConformanceError::invariant(
            "U-04c metadata/event sequence mismatch",
        ));
    }
    Ok(())
}

fn digest_fields(fields: &[&[u8]]) -> String {
    let mut encoded = Vec::new();
    for field in fields {
        append_framed(&mut encoded, field);
    }
    hex::encode(Sha256::digest(encoded))
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}

fn positive(value: i64, label: &str) -> FaultConformanceResult<u64> {
    let value = u64::try_from(value)
        .map_err(|_| FaultConformanceError::invariant(format!("negative {label}")))?;
    if value == 0 {
        return Err(FaultConformanceError::invariant(format!("zero {label}")));
    }
    Ok(value)
}

fn non_negative(value: i64, label: &str) -> FaultConformanceResult<u64> {
    u64::try_from(value).map_err(|_| FaultConformanceError::invariant(format!("negative {label}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
