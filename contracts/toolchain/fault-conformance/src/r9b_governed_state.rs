//! Strict read-only Task and Policy Authority table-state oracle for R9B.
//!
//! The fixture identities are frozen here rather than supplied by callers so
//! an accidentally self-derived expectation cannot make a corrupt owner store
//! pass conformance. Each owner is captured in its own deferred read
//! transaction. The result authenticates the fixed table set and canonical row
//! digests under the frozen schema identity; it does not authenticate complete
//! DDL or database-file bytes. The combined value is intentionally not a
//! cross-database atomic snapshot.

use crate::{FaultConformanceError, FaultConformanceResult};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, types::ValueRef};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const TABLE_DIGEST_DOMAIN: &[u8] = b"egopulse/fault-conformance/table-snapshot/v1";

pub const R9B_TASK_STORE_EPOCH: &str = "c5-00-task-epoch";
pub const R9B_TASK_SCHEMA_PROFILE_ID: &str = "egopulse/task-authority-store/v1";
pub const R9B_TASK_SCHEMA_PROFILE_SHA256: &str =
    "468a3d02b5c0703eb1e7626fb70f1067905a603a98f959aabdf6c4b5961b0e32";
pub const R9B_POLICY_STORE_EPOCH: &str = "c5-00-policy-epoch";
pub const R9B_POLICY_SCHEMA_PROFILE_ID: &str = "egopulse/policy-decision-authority-store/v1";
pub const R9B_POLICY_SCHEMA_PROFILE_SHA256: &str =
    "b3179c4c1d7497b052059c7469aac3952262f6f70572f77b8813f74af86b6bca";

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

const POLICY_TABLES: &[&str] = &[
    "sqlite_sequence",
    "policy_store_metadata",
    "policy_decisions",
    "policy_decision_states",
    "policy_decision_events",
    "policy_idempotency_results",
    "policy_outbox",
    "policy_consumption_receipts",
    "policy_commit_receipts",
    "policy_projection_migrations",
];

const TASK_KEY: [u8; 32] = [0x11; 32];
const POLICY_KEY: [u8; 32] = [0x12; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9bAuthorityTableDigest {
    pub table_name: String,
    pub row_count: u64,
    pub canonical_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9bAuthorityStoreSnapshot {
    pub store_epoch: String,
    pub schema_profile_id: String,
    pub schema_profile_sha256: String,
    pub last_committed_revision: Option<u64>,
    pub last_event_sequence: u64,
    pub tables: Vec<R9bAuthorityTableDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9bGovernedStateAuthoritySnapshot {
    pub task: R9bAuthorityStoreSnapshot,
    pub policy: R9bAuthorityStoreSnapshot,
}

struct StoreDefinition {
    file_name: &'static str,
    key: [u8; 32],
    metadata_table: &'static str,
    event_table: &'static str,
    expected_epoch: &'static str,
    expected_profile_id: &'static str,
    expected_profile_sha256: &'static str,
    has_revision: bool,
    tables: &'static [&'static str],
}

const TASK_STORE: StoreDefinition = StoreDefinition {
    file_name: "task-authority.db",
    key: TASK_KEY,
    metadata_table: "task_store_metadata",
    event_table: "task_events",
    expected_epoch: R9B_TASK_STORE_EPOCH,
    expected_profile_id: R9B_TASK_SCHEMA_PROFILE_ID,
    expected_profile_sha256: R9B_TASK_SCHEMA_PROFILE_SHA256,
    has_revision: true,
    tables: TASK_TABLES,
};

const POLICY_STORE: StoreDefinition = StoreDefinition {
    file_name: "policy-authority.db",
    key: POLICY_KEY,
    metadata_table: "policy_store_metadata",
    event_table: "policy_decision_events",
    expected_epoch: R9B_POLICY_STORE_EPOCH,
    expected_profile_id: R9B_POLICY_SCHEMA_PROFILE_ID,
    expected_profile_sha256: R9B_POLICY_SCHEMA_PROFILE_SHA256,
    has_revision: false,
    tables: POLICY_TABLES,
};

/// Captures the fixed Task and Policy owner table sets and canonical row
/// digests without opening a product writer or exposing stored row bytes.
pub fn read_r9b_governed_state_authorities(
    root: &Path,
) -> FaultConformanceResult<R9bGovernedStateAuthoritySnapshot> {
    Ok(R9bGovernedStateAuthoritySnapshot {
        task: read_store(root, &TASK_STORE)?,
        policy: read_store(root, &POLICY_STORE)?,
    })
}

fn read_store(
    root: &Path,
    definition: &StoreDefinition,
) -> FaultConformanceResult<R9bAuthorityStoreSnapshot> {
    let mut connection = open_read_only(root.join(definition.file_name), definition.key)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;

    // This must remain the first owner-schema read in the transaction.
    let mut snapshot = read_and_validate_metadata(&tx, definition)?;
    verify_integrity(&tx)?;
    require_event_sequence(&tx, definition.event_table, snapshot.last_event_sequence)?;
    snapshot.tables = read_table_digests(&tx, definition.tables)?;
    tx.commit()?;
    Ok(snapshot)
}

fn open_read_only(path: PathBuf, key: [u8; 32]) -> FaultConformanceResult<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))?;

    let cipher_version: String =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if cipher_version.trim().is_empty() {
        return Err(FaultConformanceError::invariant(
            "R9B oracle requires SQLCipher",
        ));
    }

    connection.pragma_update(None, "query_only", true)?;
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 {
        return Err(FaultConformanceError::invariant(
            "R9B oracle failed to enter query-only mode",
        ));
    }

    Ok(connection)
}

fn verify_integrity(tx: &Transaction<'_>) -> FaultConformanceResult<()> {
    let mut cipher = tx.prepare("PRAGMA cipher_integrity_check")?;
    let cipher_findings = cipher
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(cipher);
    if !cipher_findings.is_empty() {
        return Err(FaultConformanceError::invariant(
            "R9B SQLCipher integrity check reported findings",
        ));
    }

    let integrity = tx
        .prepare("PRAGMA integrity_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if integrity != ["ok"] {
        return Err(FaultConformanceError::invariant(
            "R9B SQLite integrity check failed",
        ));
    }
    Ok(())
}

fn read_and_validate_metadata(
    tx: &Transaction<'_>,
    definition: &StoreDefinition,
) -> FaultConformanceResult<R9bAuthorityStoreSnapshot> {
    let sql = if definition.has_revision {
        format!(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256, last_committed_revision, last_event_sequence FROM {} WHERE singleton=1",
            definition.metadata_table
        )
    } else {
        format!(
            "SELECT store_epoch, schema_profile_id, schema_profile_sha256, NULL, last_event_sequence FROM {} WHERE singleton=1",
            definition.metadata_table
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

    let metadata_count: i64 = tx.query_row(
        &format!("SELECT count(*) FROM {}", definition.metadata_table),
        [],
        |row| row.get(0),
    )?;
    if metadata_count != 1 {
        return Err(FaultConformanceError::invariant(
            "R9B owner metadata is not a singleton",
        ));
    }

    if store_epoch != definition.expected_epoch
        || schema_profile_id != definition.expected_profile_id
        || schema_profile_sha256 != definition.expected_profile_sha256
        || !is_sha256(&schema_profile_sha256)
    {
        return Err(FaultConformanceError::invariant(
            "R9B owner metadata does not match the fixed fixture identity",
        ));
    }

    Ok(R9bAuthorityStoreSnapshot {
        store_epoch,
        schema_profile_id,
        schema_profile_sha256,
        last_committed_revision: revision
            .map(u64::try_from)
            .transpose()
            .map_err(|_| FaultConformanceError::invariant("negative R9B owner revision"))?,
        last_event_sequence: u64::try_from(sequence)
            .map_err(|_| FaultConformanceError::invariant("negative R9B event sequence"))?,
        tables: Vec::new(),
    })
}

fn require_event_sequence(
    tx: &Transaction<'_>,
    table: &str,
    expected_sequence: u64,
) -> FaultConformanceResult<()> {
    let maximum: i64 = tx.query_row(
        &format!("SELECT COALESCE(MAX(sequence), 0) FROM \"{table}\""),
        [],
        |row| row.get(0),
    )?;
    let maximum = u64::try_from(maximum)
        .map_err(|_| FaultConformanceError::invariant("negative R9B event sequence"))?;
    if maximum != expected_sequence {
        return Err(FaultConformanceError::invariant(
            "R9B metadata/event sequence mismatch",
        ));
    }
    Ok(())
}

fn read_table_digests(
    tx: &Transaction<'_>,
    expected_tables: &[&str],
) -> FaultConformanceResult<Vec<R9bAuthorityTableDigest>> {
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
            "R9B owner table set does not match the fixed allowlist",
        ));
    }

    expected_tables
        .iter()
        .map(|table| digest_table(tx, table))
        .collect()
}

fn digest_table(
    tx: &Transaction<'_>,
    table: &str,
) -> FaultConformanceResult<R9bAuthorityTableDigest> {
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

    Ok(R9bAuthorityTableDigest {
        table_name: table.to_owned(),
        row_count: encoded_rows.len() as u64,
        canonical_sha256: hex::encode(Sha256::digest(digest_input)),
    })
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_le_bytes());
    target.extend_from_slice(value);
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{Connection, params};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must follow epoch")
                .as_nanos();
            let ordinal = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "egopulse-r9b-oracle-{label}-{}-{nonce}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open_writer(path: &Path, key: [u8; 32]) -> Connection {
        let connection = Connection::open(path).expect("open fixture writer");
        connection
            .pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
            .expect("set SQLCipher key");
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .expect("enable WAL");
        connection
            .pragma_update(None, "synchronous", "FULL")
            .expect("enable full synchronization");
        connection
    }

    fn create_fixture(root: &Path) {
        let task = open_writer(&root.join(TASK_STORE.file_name), TASK_KEY);
        task.execute_batch(
            "
            CREATE TABLE task_store_metadata (
                singleton INTEGER PRIMARY KEY,
                store_epoch TEXT NOT NULL,
                schema_profile_id TEXT NOT NULL,
                schema_profile_sha256 TEXT NOT NULL,
                last_committed_revision INTEGER NOT NULL,
                last_event_sequence INTEGER NOT NULL
            );
            CREATE TABLE tasks (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE task_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                payload BLOB NOT NULL
            );
            CREATE TABLE task_idempotency_results (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE task_outbox (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE task_commit_receipts (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE task_cross_authority_outbox (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE task_commit_outbox_links (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
            ",
        )
        .expect("create Task fixture schema");
        task.execute(
            "INSERT INTO task_store_metadata VALUES (1, ?1, ?2, ?3, 7, 1)",
            params![
                R9B_TASK_STORE_EPOCH,
                R9B_TASK_SCHEMA_PROFILE_ID,
                R9B_TASK_SCHEMA_PROFILE_SHA256
            ],
        )
        .expect("insert Task metadata");
        task.execute(
            "INSERT INTO task_events(payload) VALUES (?1)",
            [b"task-event".as_slice()],
        )
        .expect("insert Task event");
        task.execute(
            "INSERT INTO tasks VALUES ('task-1', ?1)",
            [b"task-snapshot".as_slice()],
        )
        .expect("insert Task snapshot");
        drop(task);

        let policy = open_writer(&root.join(POLICY_STORE.file_name), POLICY_KEY);
        policy
            .execute_batch(
                "
                CREATE TABLE policy_store_metadata (
                    singleton INTEGER PRIMARY KEY,
                    store_epoch TEXT NOT NULL,
                    schema_profile_id TEXT NOT NULL,
                    schema_profile_sha256 TEXT NOT NULL,
                    last_event_sequence INTEGER NOT NULL
                );
                CREATE TABLE policy_decisions (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_decision_states (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_decision_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload BLOB NOT NULL
                );
                CREATE TABLE policy_idempotency_results (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_outbox (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_consumption_receipts (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_commit_receipts (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                CREATE TABLE policy_projection_migrations (id TEXT PRIMARY KEY, payload BLOB NOT NULL);
                ",
            )
            .expect("create Policy fixture schema");
        policy
            .execute(
                "INSERT INTO policy_store_metadata VALUES (1, ?1, ?2, ?3, 1)",
                params![
                    R9B_POLICY_STORE_EPOCH,
                    R9B_POLICY_SCHEMA_PROFILE_ID,
                    R9B_POLICY_SCHEMA_PROFILE_SHA256
                ],
            )
            .expect("insert Policy metadata");
        policy
            .execute(
                "INSERT INTO policy_decision_events(payload) VALUES (?1)",
                [b"policy-event".as_slice()],
            )
            .expect("insert Policy event");
        policy
            .execute(
                "INSERT INTO policy_decisions VALUES ('approval-1', ?1)",
                [b"policy-decision".as_slice()],
            )
            .expect("insert Policy decision");
    }

    fn update(root: &Path, definition: &StoreDefinition, sql: &str) {
        let connection = open_writer(&root.join(definition.file_name), definition.key);
        connection.execute_batch(sql).expect("tamper fixture");
    }

    fn table<'a>(
        snapshot: &'a R9bAuthorityStoreSnapshot,
        name: &str,
    ) -> &'a R9bAuthorityTableDigest {
        snapshot
            .tables
            .iter()
            .find(|table| table.table_name == name)
            .expect("table digest")
    }

    #[test]
    fn r9b_governed_state_oracle_reads_fixed_task_and_policy_stores() {
        let root = TestRoot::new("reads");
        create_fixture(root.path());

        let first = read_r9b_governed_state_authorities(root.path()).expect("read authorities");
        let second = read_r9b_governed_state_authorities(root.path()).expect("repeat read");

        assert_eq!(first, second);
        assert_eq!(first.task.store_epoch, R9B_TASK_STORE_EPOCH);
        assert_eq!(first.task.schema_profile_id, R9B_TASK_SCHEMA_PROFILE_ID);
        assert_eq!(
            first.task.schema_profile_sha256,
            R9B_TASK_SCHEMA_PROFILE_SHA256
        );
        assert_eq!(first.task.last_committed_revision, Some(7));
        assert_eq!(first.task.last_event_sequence, 1);
        assert_eq!(first.task.tables.len(), TASK_TABLES.len());
        assert_eq!(table(&first.task, "tasks").row_count, 1);

        assert_eq!(first.policy.store_epoch, R9B_POLICY_STORE_EPOCH);
        assert_eq!(first.policy.schema_profile_id, R9B_POLICY_SCHEMA_PROFILE_ID);
        assert_eq!(
            first.policy.schema_profile_sha256,
            R9B_POLICY_SCHEMA_PROFILE_SHA256
        );
        assert_eq!(first.policy.last_committed_revision, None);
        assert_eq!(first.policy.last_event_sequence, 1);
        assert_eq!(first.policy.tables.len(), POLICY_TABLES.len());
        assert_eq!(table(&first.policy, "policy_decisions").row_count, 1);

        for digest in first.task.tables.iter().chain(&first.policy.tables) {
            assert!(is_sha256(&digest.canonical_sha256));
        }
    }

    #[test]
    fn r9b_governed_state_oracle_rejects_identity_and_sequence_drift() {
        let identity = TestRoot::new("identity-drift");
        create_fixture(identity.path());
        update(
            identity.path(),
            &TASK_STORE,
            "UPDATE task_store_metadata SET store_epoch='forged-epoch' WHERE singleton=1",
        );
        let error = read_r9b_governed_state_authorities(identity.path())
            .expect_err("forged identity must fail closed");
        assert!(error.to_string().contains("fixed fixture identity"));

        let sequence = TestRoot::new("sequence-drift");
        create_fixture(sequence.path());
        update(
            sequence.path(),
            &POLICY_STORE,
            "UPDATE policy_store_metadata SET last_event_sequence=2 WHERE singleton=1",
        );
        let error = read_r9b_governed_state_authorities(sequence.path())
            .expect_err("sequence drift must fail closed");
        assert!(error.to_string().contains("sequence mismatch"));
    }

    #[test]
    fn r9b_governed_state_oracle_rejects_table_drift_and_never_creates_a_store() {
        let extra = TestRoot::new("extra-table");
        create_fixture(extra.path());
        update(
            extra.path(),
            &TASK_STORE,
            "CREATE TABLE unexpected_owner_data (value BLOB)",
        );
        let error = read_r9b_governed_state_authorities(extra.path())
            .expect_err("extra owner table must fail closed");
        assert!(error.to_string().contains("fixed allowlist"));

        let missing = TestRoot::new("missing-store");
        let task_path = missing.path().join(TASK_STORE.file_name);
        assert!(!task_path.exists());
        read_r9b_governed_state_authorities(missing.path())
            .expect_err("missing owner store must fail closed");
        assert!(
            !task_path.exists(),
            "read-only open must not create a store"
        );
    }

    #[test]
    fn r9b_governed_state_oracle_digest_detects_row_mutation_without_policy_drift() {
        let root = TestRoot::new("row-drift");
        create_fixture(root.path());
        let before = read_r9b_governed_state_authorities(root.path()).expect("read before");

        update(
            root.path(),
            &TASK_STORE,
            "UPDATE tasks SET payload=x'74616d7065726564' WHERE id='task-1'",
        );
        let after = read_r9b_governed_state_authorities(root.path()).expect("read after");

        assert_eq!(
            table(&before.task, "tasks").row_count,
            table(&after.task, "tasks").row_count
        );
        assert_ne!(
            table(&before.task, "tasks").canonical_sha256,
            table(&after.task, "tasks").canonical_sha256
        );
        assert_eq!(before.policy, after.policy);
    }

    #[test]
    fn r9b_governed_state_table_digest_is_independent_of_insertion_order() {
        fn digest(rows: &[(i64, &str, &[u8])]) -> R9bAuthorityTableDigest {
            let mut connection = Connection::open_in_memory().expect("open in-memory store");
            connection
                .execute_batch(
                    "CREATE TABLE stable_rows (
                        ordinal INTEGER NOT NULL,
                        label TEXT NOT NULL,
                        payload BLOB NOT NULL
                    )",
                )
                .expect("create stable row table");
            for (ordinal, label, payload) in rows {
                connection
                    .execute(
                        "INSERT INTO stable_rows VALUES (?1, ?2, ?3)",
                        params![ordinal, label, payload],
                    )
                    .expect("insert stable row");
            }
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .expect("begin read transaction");
            let result = digest_table(&tx, "stable_rows").expect("digest stable rows");
            tx.commit().expect("commit read transaction");
            result
        }

        let alpha = b"alpha-payload".as_slice();
        let beta = b"beta-payload".as_slice();
        let forward = digest(&[(1, "alpha", alpha), (2, "beta", beta)]);
        let reverse = digest(&[(2, "beta", beta), (1, "alpha", alpha)]);

        assert_eq!(forward.row_count, 2);
        assert_eq!(forward, reverse);
    }
}
