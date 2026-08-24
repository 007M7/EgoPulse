use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand, TaskCommand, TaskErrorCode,
    TaskSnapshot, TaskStatus, get_task_response, task_command, task_command_result,
};
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const STORE_EPOCH: &str = "task-store-g4-02-test";
const TEST_KEY: [u8; 32] = [0x42; 32];

struct FixtureCreationGuard;

impl TaskCreationGuard for FixtureCreationGuard {
    fn validate(
        &self,
        command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        if command.work_type != "governed_repository_change"
            || command.input_snapshot_id != "input-001"
            || command.target_scope_ref != "repo-scope-001"
        {
            return Err(CreationGuardRejection::UnverifiedReference);
        }
        let expected_acceptance =
            contract_ref("repository_change_acceptance", "1", &"a".repeat(64));
        let expected_budget = contract_ref("v01-quality-budget", "0.1", &"b".repeat(64));
        if command.acceptance_contract_ref.as_ref() != Some(&expected_acceptance)
            || command.budget_profile_ref.as_ref() != Some(&expected_budget)
        {
            return Err(CreationGuardRejection::ContractMismatch);
        }
        Ok(CreationAuthorization {
            evidence_refs: vec![
                "input-snapshot:input-001@verified".to_owned(),
                "target-scope:repo-scope-001@frozen".to_owned(),
            ],
        })
    }
}

struct IsolatedStore {
    root: PathBuf,
}

impl IsolatedStore {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create isolated Task Authority test directory");
        Self { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("task-authority.sqlcipher")
    }
}

impl Drop for IsolatedStore {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        assert!(self.root.starts_with(&temp_root));
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove isolated Task Authority test directory");
        }
    }
}

fn open_authority(path: &Path) -> TaskAuthority {
    TaskAuthority::open(
        TaskAuthorityConfig {
            database_path: path.to_owned(),
            store_epoch: STORE_EPOCH.to_owned(),
            key: SqlCipherKey::new(TEST_KEY),
        },
        FixtureCreationGuard,
    )
    .expect("open encrypted Task Authority")
}

fn founder() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "founder:test".to_owned(),
        authenticated: true,
    }
}

fn metadata(command_id: &str, idempotency_key: &str, correlation_id: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: command_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        idempotency_scope: "founder:test/v01".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_777_073_600,
            nanos: 0,
        }),
        correlation_id: correlation_id.to_owned(),
        causation_id: None,
    }
}

fn contract_ref(contract_id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: contract_id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn valid_create_command() -> TaskCommand {
    let mut command = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(metadata("cmd-create-001", "create-001", "corr-001")),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-001".to_owned(),
            target_scope_ref: "repo-scope-001".to_owned(),
            acceptance_contract_ref: Some(contract_ref(
                "repository_change_acceptance",
                "1",
                &"a".repeat(64),
            )),
            budget_profile_ref: Some(contract_ref("v01-quality-budget", "0.1", &"b".repeat(64))),
        })),
    };
    set_digest(&mut command);
    command
}

fn set_digest(command: &mut TaskCommand) {
    let digest = canonical_request_digest(command).expect("canonical Task request digest");
    match command.command.as_mut().expect("Task command variant") {
        task_command::Command::CreateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::ActivateTask(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        task_command::Command::ApplyFounderVerdict(value) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest;
        }
        _ => panic!("test helper does not support this command"),
    }
}

fn committed_task(
    result: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.clone().expect("Task result outcome") {
        task_command_result::Outcome::Task(snapshot) => snapshot,
        task_command_result::Outcome::Error(error) => {
            panic!(
                "expected committed Task, got error {}",
                error.safe_detail_code
            )
        }
    }
}

fn error_code(
    result: &egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskErrorCode {
    match result.outcome.as_ref().expect("Task result outcome") {
        task_command_result::Outcome::Error(error) => {
            TaskErrorCode::try_from(error.code).expect("known Task error code")
        }
        task_command_result::Outcome::Task(_) => panic!("expected Task error"),
    }
}

#[test]
fn valid_create_duplicate_and_conflict_preserve_one_atomic_commit() {
    let isolated = IsolatedStore::new("task-create");
    let mut authority = open_authority(&isolated.database_path());
    let command = valid_create_command();

    let committed = authority
        .execute(&command, &founder())
        .expect("create Task");
    assert!(!committed.replayed);
    let snapshot = committed_task(&committed);
    assert_eq!(snapshot.status, TaskStatus::Ready as i32);
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.work_revision, 1);

    let committed_counts = authority.inspect_store().expect("inspect committed store");
    assert_eq!(committed_counts.task_count, 1);
    assert_eq!(committed_counts.event_count, 1);
    assert_eq!(committed_counts.idempotency_count, 1);
    assert_eq!(committed_counts.outbox_count, 1);
    assert_eq!(committed_counts.commit_receipt_count, 1);
    assert_eq!(committed_counts.last_committed_revision, 1);
    assert_eq!(committed_counts.last_event_sequence, 1);

    let mut duplicate = command.clone();
    if let Some(task_command::Command::CreateTask(create)) = duplicate.command.as_mut() {
        let meta = create.meta.as_mut().expect("metadata");
        meta.command_id = "cmd-create-retry-001".to_owned();
        meta.correlation_id = "corr-retry-001".to_owned();
        meta.issued_at = Some(Timestamp {
            seconds: 1_777_073_601,
            nanos: 0,
        });
    }
    let replayed = authority
        .execute(&duplicate, &founder())
        .expect("replay committed Task");
    assert!(replayed.replayed);
    assert_eq!(committed_task(&replayed).task_id, snapshot.task_id);
    assert_eq!(
        authority.inspect_store().expect("inspect replay"),
        committed_counts
    );

    let mut conflict = command.clone();
    if let Some(task_command::Command::CreateTask(create)) = conflict.command.as_mut() {
        create.input_snapshot_id = "input-conflict".to_owned();
        create.meta.as_mut().expect("metadata").command_id = "cmd-create-conflict".to_owned();
    }
    set_digest(&mut conflict);
    let rejected = authority
        .execute(&conflict, &founder())
        .expect("reject idempotency conflict");
    assert_eq!(error_code(&rejected), TaskErrorCode::IdempotencyConflict);
    assert_eq!(
        authority.inspect_store().expect("inspect conflict"),
        committed_counts
    );

    let mut second = command;
    if let Some(task_command::Command::CreateTask(create)) = second.command.as_mut() {
        let meta = create.meta.as_mut().expect("metadata");
        meta.command_id = "cmd-create-002".to_owned();
        meta.idempotency_key = "create-002".to_owned();
        meta.correlation_id = "corr-002".to_owned();
    }
    set_digest(&mut second);
    let second_result = authority
        .execute(&second, &founder())
        .expect("create second Task");
    assert!(!second_result.replayed);
    let two_commits = authority.inspect_store().expect("inspect two commits");
    assert_eq!(two_commits.task_count, 2);
    assert_eq!(two_commits.event_count, 2);
    assert_eq!(two_commits.idempotency_count, 2);
    assert_eq!(two_commits.outbox_count, 2);
    assert_eq!(two_commits.commit_receipt_count, 2);
    assert_eq!(two_commits.last_committed_revision, 2);
    assert_eq!(two_commits.last_event_sequence, 2);
}

#[test]
fn stale_and_harness_terminal_write_are_zero_write_failures() {
    let isolated = IsolatedStore::new("task-negative");
    let mut authority = open_authority(&isolated.database_path());
    let created = authority
        .execute(&valid_create_command(), &founder())
        .expect("create Task");
    let snapshot = committed_task(&created);
    let baseline = authority.inspect_store().expect("inspect baseline");

    let mut stale = TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(metadata(
                "cmd-activate-stale",
                "activate-stale",
                "corr-stale",
            )),
            task_id: snapshot.task_id.clone(),
            expected_revision: 0,
            work_revision: 1,
            run_id: "run-001".to_owned(),
        })),
    };
    set_digest(&mut stale);
    let collaboration = AuthenticatedPrincipal {
        kind: PrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:test".to_owned(),
        authenticated: true,
    };
    let stale_result = authority
        .execute(&stale, &collaboration)
        .expect("reject stale command");
    assert_eq!(error_code(&stale_result), TaskErrorCode::RevisionConflict);
    assert_eq!(authority.inspect_store().expect("inspect stale"), baseline);

    let mut forged = TaskCommand {
        command: Some(task_command::Command::ApplyFounderVerdict(
            ApplyFounderVerdictCommand {
                meta: Some(metadata("cmd-forged", "forged", "corr-forged")),
                task_id: snapshot.task_id,
                expected_revision: 1,
                work_revision: 1,
                founder_verdict_id: "forged-by-harness".to_owned(),
            },
        )),
    };
    set_digest(&mut forged);
    let harness = AuthenticatedPrincipal {
        kind: PrincipalKind::Harness,
        principal_id: "codex-adapter:test".to_owned(),
        authenticated: true,
    };
    let unauthorized = authority
        .execute(&forged, &harness)
        .expect("reject Harness write");
    assert_eq!(error_code(&unauthorized), TaskErrorCode::PermissionDenied);
    assert_eq!(
        authority.inspect_store().expect("inspect unauthorized"),
        baseline
    );
}

#[test]
fn encrypted_store_reopens_with_the_same_authority_facts() {
    let isolated = IsolatedStore::new("task-reopen");
    let path = isolated.database_path();
    let command = valid_create_command();
    let mut authority = open_authority(&path);
    let created = authority
        .execute(&command, &founder())
        .expect("create Task");
    let snapshot = committed_task(&created);
    drop(authority);

    let bytes = fs::read(&path).expect("read encrypted Task store");
    assert!(bytes.len() >= 16);
    assert_ne!(&bytes[..16], b"SQLite format 3\0");

    let mut recovered = open_authority(&path);
    assert!(recovered.integrity_is_ok().expect("integrity check"));
    let get = recovered
        .get_task(&snapshot.task_id)
        .expect("get recovered Task");
    match get.outcome.expect("get outcome") {
        get_task_response::Outcome::Task(value) => assert_eq!(value, snapshot),
        get_task_response::Outcome::Error(error) => {
            panic!("recovered Task missing: {}", error.safe_detail_code)
        }
    }
    let replayed = recovered
        .execute(&command, &founder())
        .expect("recover replay");
    assert!(replayed.replayed);
    let counts = recovered.inspect_store().expect("inspect recovered store");
    assert_eq!(counts.task_count, 1);
    assert_eq!(counts.event_count, 1);
    assert_eq!(counts.idempotency_count, 1);
    assert_eq!(counts.outbox_count, 1);
}

#[test]
fn task_projection_feed_is_typed_digest_bound_and_acknowledged_explicitly() {
    let isolated = IsolatedStore::new("task-projection-feed");
    let mut authority = open_authority(&isolated.database_path());
    let created = authority
        .execute(&valid_create_command(), &founder())
        .expect("create projected Task");
    let task = committed_task(&created);

    let pending = authority
        .drain_projection_outbox()
        .expect("drain Task projection outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event.snapshot.as_ref(), Some(&task));
    assert!(
        !authority
            .acknowledge_projection(&pending[0].message_id, &"0".repeat(64))
            .expect("reject digest-mismatched ACK")
    );
    assert!(
        authority
            .acknowledge_projection(&pending[0].message_id, &pending[0].payload_digest_sha256)
            .expect("ack committed projection")
    );
    assert!(
        authority
            .drain_projection_outbox()
            .expect("projection outbox after ACK")
            .is_empty()
    );
    let baselines = authority
        .projection_baselines()
        .expect("Task projection baseline");
    assert_eq!(baselines.len(), 1);
    assert_eq!(baselines[0].event.snapshot.as_ref(), Some(&task));
}

#[test]
fn committed_create_survives_process_abort_before_response_delivery() {
    let isolated = IsolatedStore::new("task-abort");
    let path = isolated.database_path();
    let status =
        Command::new(std::env::current_exe().expect("current integration test executable"))
            .arg("--exact")
            .arg("crash_probe_child")
            .arg("--nocapture")
            .env("EGOPULSE_G4_02_CRASH_PROBE", "1")
            .env("EGOPULSE_G4_02_CRASH_DB", &path)
            .status()
            .expect("launch crash probe child");
    assert!(!status.success(), "crash probe must abort after commit");

    let mut recovered = open_authority(&path);
    let replayed = recovered
        .execute(&valid_create_command(), &founder())
        .expect("replay after child abort");
    assert!(replayed.replayed);
    let counts = recovered.inspect_store().expect("inspect abort recovery");
    assert_eq!(counts.task_count, 1);
    assert_eq!(counts.event_count, 1);
    assert_eq!(counts.idempotency_count, 1);
    assert_eq!(counts.outbox_count, 1);
    assert_eq!(counts.commit_receipt_count, 1);
}

#[test]
fn crash_probe_child() {
    if std::env::var("EGOPULSE_G4_02_CRASH_PROBE").as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(
        std::env::var_os("EGOPULSE_G4_02_CRASH_DB").expect("crash probe database path"),
    );
    let mut authority = open_authority(&path);
    let result = authority
        .execute(&valid_create_command(), &founder())
        .expect("commit before intentional abort");
    assert!(!result.replayed);
    std::process::abort();
}
