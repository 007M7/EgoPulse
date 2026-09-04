use std::{fs, path::PathBuf};

use egopulse_domain_contracts::{
    harness_content::{
        canonical_safe_harness_content_record_digest, canonical_safe_harness_content_record_id,
    },
    profiles::{
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
    },
    v01::egopulse::{
        collaboration::v1::{
            AttemptSnapshot, CollaborationCommandResult, CollaborationEvent, CollaborationSnapshot,
            Lease, RunSnapshot, collaboration_command_result,
        },
        common::v1::ContractReference,
        harness::v1::{
            ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation,
            ContentMutationOperation, HarnessContentHistoryCompactionRecord,
            HarnessContentLimitKind, HarnessContentMarkerKind, HarnessContentRetentionTombstone,
            HarnessContentSafetyFlag, HarnessObservation, SafeArtifactIdentity,
            SafeArtifactRelationContent, SafeAssistantTextContent, SafeContentMarker,
            SafeHarnessContentProjectionEvent, SafeHarnessContentRecord, SafeUsageContent,
            harness_observation, safe_harness_content_projection_event,
            safe_harness_content_record,
        },
        localapi::v1::{
            HarnessContentResetReason, ProjectionHealth, harness_artifact_relation_view,
            harness_content_record_view, harness_content_stream_frame,
        },
        task::v1::{TaskEvent, TaskSnapshot, TaskStatus},
    },
};
use egopulse_local_read_model::{
    AdapterApprovalProjectionInput, ApprovalViewAccess, CollaborationProjectionInput,
    HarnessContentApply, HarnessContentBaselineQuery, HarnessContentProjectionInput,
    HarnessContentReadAccess, HarnessContentWatchQuery, LocalReadModel, LocalReadModelConfig,
    LocalReadModelKey, ProjectionFailure, ProjectionMessageMetadata, ProjectionMessageMode,
    TaskListFilter, TaskProjectionInput, TaskViewAccess,
};
use prost::Message;
use prost_types::Timestamp;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const KEY: [u8; 32] = [0x39; 32];
const EPOCH: &str = "content-epoch-01";
const LEGACY_V3_SCHEMA_DIGEST: &str =
    "8b2734291a8ddfc3f345ff672dfbb8a99f7bb22c77905d03e705c0ef5d406c94";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-r9c-lrm-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated R9C root");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("read-model.db")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(root: &TempRoot) -> LocalReadModel {
    LocalReadModel::open(LocalReadModelConfig {
        database_path: root.database(),
        epoch: EPOCH.to_owned(),
        key: LocalReadModelKey::new(KEY),
    })
    .expect("open SQLCipher Local Read Model")
}

fn inspect(root: &TempRoot) -> Connection {
    let connection = Connection::open_with_flags(
        root.database(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open read-only read-model inspection handle");
    connection
        .pragma_update(None, "key", format!("x'{}'", hex::encode(KEY)))
        .expect("set SQLCipher inspection key");
    connection
        .pragma_update(None, "query_only", true)
        .expect("make inspection handle read-only");
    connection
}

fn mutable_fixture_connection(root: &TempRoot) -> Connection {
    let connection = Connection::open(root.database()).expect("open migration fixture handle");
    connection
        .pragma_update(None, "key", format!("x'{}'", hex::encode(KEY)))
        .expect("set SQLCipher fixture key");
    connection
}

fn timestamp(offset: i64) -> Timestamp {
    Timestamp {
        seconds: 1_800_000_000 + offset,
        nanos: 0,
    }
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

fn profile_ref() -> ContractReference {
    ContractReference {
        contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
        version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
        sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
    }
}

fn global_metadata(
    message_id: &str,
    source_event_id: &str,
    revision: u64,
    payload: &impl Message,
) -> ProjectionMessageMetadata {
    ProjectionMessageMetadata {
        message_id: message_id.to_owned(),
        source_event_id: source_event_id.to_owned(),
        source_revision: revision,
        mode: ProjectionMessageMode::Incremental,
        payload_digest_sha256: sha256(payload.encode_to_vec()),
        projected_at: timestamp(revision as i64),
    }
}

fn collaboration_input() -> CollaborationProjectionInput {
    let snapshot = CollaborationSnapshot {
        run: Some(RunSnapshot {
            run_id: "run-001".to_owned(),
            revision: 1,
            task_id: "task-global".to_owned(),
            ..Default::default()
        }),
        attempts: vec![AttemptSnapshot {
            attempt_id: "attempt-global".to_owned(),
            run_id: "run-001".to_owned(),
            step_id: "step-001".to_owned(),
            revision: 1,
            dispatch_id: Some("dispatch-global".to_owned()),
            lease: Some(Lease {
                fencing_token: 3,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let event = CollaborationEvent {
        event_id: "collaboration-event-001".to_owned(),
        run_id: "run-001".to_owned(),
        resulting_run_revision: 1,
        ..Default::default()
    };
    let result = CollaborationCommandResult {
        replayed: false,
        outcome: Some(collaboration_command_result::Outcome::Snapshot(snapshot)),
        committed_event: Some(event),
    };
    CollaborationProjectionInput {
        metadata: global_metadata(
            "collaboration-message-001",
            "collaboration-event-001",
            1,
            &result,
        ),
        result,
    }
}

fn approval_input() -> AdapterApprovalProjectionInput {
    let observation = HarnessObservation {
        observation_id: "approval-observation-001".to_owned(),
        adapter_id: "codex-adapter".to_owned(),
        attempt_id: "attempt-global".to_owned(),
        dispatch_id: "dispatch-global".to_owned(),
        fencing_token: 3,
        observation_sequence: 1,
        payload: Some(harness_observation::Payload::ApprovalRequest(
            ApprovalRequestObservation {
                approval_request_id: "approval-001".to_owned(),
                kind: ApprovalKind::Command as i32,
                action_digest_sha256: "a".repeat(64),
                requested_scope_ref: "safe://scope/001".to_owned(),
                display_summary_ref: "safe://summary/001".to_owned(),
                native_routing_ref: String::new(),
                lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                request_revision: 1,
            },
        )),
        ..Default::default()
    };
    AdapterApprovalProjectionInput {
        metadata: global_metadata(
            "approval-message-001",
            "approval-observation-001",
            1,
            &observation,
        ),
        run_id: "run-001".to_owned(),
        step_id: "step-001".to_owned(),
        attempt_id: "attempt-global".to_owned(),
        dispatch_id: "dispatch-global".to_owned(),
        fencing_token: 3,
        observation,
    }
}

fn task_input() -> TaskProjectionInput {
    let snapshot = TaskSnapshot {
        task_id: "task-global".to_owned(),
        revision: 1,
        work_revision: 1,
        status: TaskStatus::Ready as i32,
        created_at: Some(timestamp(1)),
        updated_at: Some(timestamp(1)),
        ..Default::default()
    };
    let event = TaskEvent {
        event_id: "task-event-001".to_owned(),
        task_id: snapshot.task_id.clone(),
        resulting_revision: 1,
        work_revision: 1,
        snapshot: Some(snapshot),
        ..Default::default()
    };
    TaskProjectionInput {
        metadata: global_metadata("task-message-001", "task-event-001", 1, &event),
        event,
    }
}

fn task_access() -> TaskViewAccess {
    TaskViewAccess {
        can_read: true,
        can_request_cancellation: true,
        can_resume: true,
        can_revise: true,
        can_issue_founder_verdict: true,
    }
}

fn task_view_bytes(model: &LocalReadModel) -> Vec<u8> {
    let views = model
        .list_task_views(&TaskListFilter::default(), task_access())
        .expect("read Task views");
    assert_eq!(views.len(), 1);
    views[0].encode_to_vec()
}

fn task_projection_counts(root: &TempRoot) -> (i64, i64) {
    let connection = inspect(root);
    let views = connection
        .query_row("SELECT count(*) FROM task_views", [], |row| row.get(0))
        .expect("count Task views");
    let frames = connection
        .query_row("SELECT count(*) FROM task_view_frames", [], |row| {
            row.get(0)
        })
        .expect("count Task frames");
    (views, frames)
}

fn record(
    id: usize,
    task_id: &str,
    attempt_id: &str,
    payload: safe_harness_content_record::Payload,
) -> SafeHarnessContentRecord {
    let mut record = SafeHarnessContentRecord {
        record_id: String::new(),
        record_digest_sha256: String::new(),
        content_event_id: sha256(format!("content-event-{id}")),
        task_id: task_id.to_owned(),
        run_id: format!("run-canary-{id}"),
        step_id: format!("step-canary-{id}"),
        attempt_id: attempt_id.to_owned(),
        dispatch_id: format!("dispatch-canary-{id}"),
        fencing_token: id as u64 + 1,
        route_binding_sha256: sha256(format!("route-canary-{id}")),
        disclosure_profile_ref: Some(profile_ref()),
        provider_family_alias: "openai".to_owned(),
        model_alias: "gpt-test".to_owned(),
        collaboration_role: "primary".to_owned(),
        safety_flags: vec![HarnessContentSafetyFlag::Provisional as i32],
        payload: Some(payload),
    };
    seal_record(&mut record);
    record
}

fn seal_record(record: &mut SafeHarnessContentRecord) {
    record.record_id.clear();
    record.record_digest_sha256.clear();
    record.record_id = canonical_safe_harness_content_record_id(record)
        .expect("fixture has canonical safe-record identity");
    record.record_digest_sha256 = canonical_safe_harness_content_record_digest(record)
        .expect("fixture has canonical safe-record digest");
}

fn usage_record(id: usize, task_id: &str, attempt_id: &str) -> SafeHarnessContentRecord {
    record(
        id,
        task_id,
        attempt_id,
        safe_harness_content_record::Payload::Usage(SafeUsageContent {
            input_tokens: id as u64,
            output_tokens: id as u64 + 1,
            cached_input_tokens: None,
        }),
    )
}

fn text_record(
    id: usize,
    task_id: &str,
    attempt_id: &str,
    text: String,
) -> SafeHarnessContentRecord {
    record(
        id,
        task_id,
        attempt_id,
        safe_harness_content_record::Payload::AssistantText(SafeAssistantTextContent {
            safe_message_id: format!("hcm_{}", sha256(format!("message-{id}"))),
            revision: 1,
            previous_revision: 0,
            operation: ContentMutationOperation::Append as i32,
            safe_cumulative_digest_sha256: sha256(text.as_bytes()),
            safe_text_utf8: text,
            part_index: 0,
            part_count: 1,
        }),
    )
}

fn limit_marker_record(
    id: usize,
    task_id: &str,
    attempt_id: &str,
    limit_kind: HarnessContentLimitKind,
) -> SafeHarnessContentRecord {
    let mut marker = record(
        id,
        task_id,
        attempt_id,
        safe_harness_content_record::Payload::Marker(SafeContentMarker {
            kind: HarnessContentMarkerKind::LimitReached as i32,
            limit_kind: limit_kind as i32,
        }),
    );
    marker.safety_flags.clear();
    seal_record(&mut marker);
    marker
}

fn limit_marker_after(
    prefix: &SafeHarnessContentRecord,
    limit_kind: HarnessContentLimitKind,
) -> SafeHarnessContentRecord {
    let mut marker = prefix.clone();
    marker.safety_flags.clear();
    marker.payload = Some(safe_harness_content_record::Payload::Marker(
        SafeContentMarker {
            kind: HarnessContentMarkerKind::LimitReached as i32,
            limit_kind: limit_kind as i32,
        },
    ));
    seal_record(&mut marker);
    marker
}

fn projection_input(
    delivery_id: impl Into<String>,
    record: SafeHarnessContentRecord,
    offset: i64,
) -> HarnessContentProjectionInput {
    let event = SafeHarnessContentProjectionEvent {
        payload: Some(safe_harness_content_projection_event::Payload::ContentRecord(record)),
    };
    HarnessContentProjectionInput {
        delivery_id: delivery_id.into(),
        payload_digest_sha256: sha256(event.encode_to_vec()),
        event,
        projected_at: timestamp(offset),
    }
}

fn read_access() -> HarnessContentReadAccess {
    HarnessContentReadAccess {
        can_read_content: true,
        can_read_artifact_identity: false,
    }
}

fn baseline_query(
    task_id: &str,
    attempt_ids: &[&str],
    page_size: u32,
) -> HarnessContentBaselineQuery {
    HarnessContentBaselineQuery {
        task_id: task_id.to_owned(),
        attempt_ids: attempt_ids
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        page_size,
        snapshot_position: None,
        cursor: None,
    }
}

fn content_counts(root: &TempRoot) -> (u64, u64) {
    let connection = inspect(root);
    let inbox: i64 = connection
        .query_row("SELECT count(*) FROM harness_content_inbox", [], |row| {
            row.get(0)
        })
        .expect("count content inbox");
    let records: i64 = connection
        .query_row("SELECT count(*) FROM harness_content_records", [], |row| {
            row.get(0)
        })
        .expect("count content records");
    (inbox as u64, records as u64)
}

#[derive(Debug, Eq, PartialEq)]
struct ContentRecordRow {
    content_sequence: i64,
    record_id: String,
    content_event_id: String,
    record_digest_sha256: String,
    delivery_payload_digest_sha256: String,
    task_id: String,
    attempt_id: String,
    disclosure_contract_id: String,
    disclosure_contract_version: String,
    disclosure_profile_sha256: String,
    safe_text_bytes: i64,
    projected_at_seconds: i64,
    projected_at_nanos: i32,
    safe_record: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct ContentInboxRow {
    delivery_id: String,
    event_kind: i32,
    owner_event_id: String,
    owner_event_digest_sha256: String,
    payload_digest_sha256: String,
    committed_sequence: i64,
    projected_at_seconds: i64,
    projected_at_nanos: i32,
}

#[derive(Debug, Eq, PartialEq)]
struct ContentDurableState {
    metadata: (String, i64, i64, i32, i32, i64, i32),
    inbox: Vec<ContentInboxRow>,
    records: Vec<ContentRecordRow>,
    owner_baselines: i64,
    compactions: i64,
    tombstones: i64,
}

fn content_durable_state(root: &TempRoot) -> ContentDurableState {
    let connection = inspect(root);
    let metadata = connection
        .query_row(
            "SELECT epoch,current_sequence,retention_floor_sequence,health,
                    reset_reason,current_projected_at_seconds,current_projected_at_nanos
             FROM harness_content_metadata WHERE singleton=1",
            [],
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
        .expect("read content metadata");
    let inbox = connection
        .prepare(
            "SELECT delivery_id,event_kind,owner_event_id,owner_event_digest_sha256,
                    payload_digest_sha256,committed_sequence,projected_at_seconds,
                    projected_at_nanos
             FROM harness_content_inbox ORDER BY delivery_id",
        )
        .expect("prepare content inbox inspection")
        .query_map([], |row| {
            Ok(ContentInboxRow {
                delivery_id: row.get(0)?,
                event_kind: row.get(1)?,
                owner_event_id: row.get(2)?,
                owner_event_digest_sha256: row.get(3)?,
                payload_digest_sha256: row.get(4)?,
                committed_sequence: row.get(5)?,
                projected_at_seconds: row.get(6)?,
                projected_at_nanos: row.get(7)?,
            })
        })
        .expect("read content inbox")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect content inbox");
    let records = connection
        .prepare(
            "SELECT content_sequence,record_id,content_event_id,record_digest_sha256,
                    delivery_payload_digest_sha256,task_id,attempt_id,
                    disclosure_contract_id,disclosure_contract_version,
                    disclosure_profile_sha256,safe_text_bytes,projected_at_seconds,
                    projected_at_nanos,safe_record
             FROM harness_content_records ORDER BY content_sequence",
        )
        .expect("prepare content record inspection")
        .query_map([], |row| {
            Ok(ContentRecordRow {
                content_sequence: row.get(0)?,
                record_id: row.get(1)?,
                content_event_id: row.get(2)?,
                record_digest_sha256: row.get(3)?,
                delivery_payload_digest_sha256: row.get(4)?,
                task_id: row.get(5)?,
                attempt_id: row.get(6)?,
                disclosure_contract_id: row.get(7)?,
                disclosure_contract_version: row.get(8)?,
                disclosure_profile_sha256: row.get(9)?,
                safe_text_bytes: row.get(10)?,
                projected_at_seconds: row.get(11)?,
                projected_at_nanos: row.get(12)?,
                safe_record: row.get(13)?,
            })
        })
        .expect("read content records")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect content records");
    let count = |table: &str| {
        connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count content recovery table")
    };
    ContentDurableState {
        metadata,
        inbox,
        records,
        owner_baselines: count("harness_content_owner_baselines"),
        compactions: count("harness_content_compactions"),
        tombstones: count("harness_content_tombstones"),
    }
}

#[test]
fn r9c_v4_migration_is_additive_and_creates_no_third_database() {
    let root = TempRoot::new("migration");
    let connection = mutable_fixture_connection(&root);
    connection
        .execute_batch(include_str!("fixtures/local_read_model_v3.sql"))
        .expect("create independent frozen V3 schema");
    connection
        .execute(
            "INSERT INTO projection_metadata(
               singleton,epoch,schema_profile_id,schema_profile_sha256,
               current_sequence,health,retention_floor_sequence
             ) VALUES(1,?1,?2,?3,2,?4,0)",
            params![
                EPOCH,
                "egopulse/local-read-model-store/v1",
                LEGACY_V3_SCHEMA_DIGEST,
                ProjectionHealth::Ready as i32
            ],
        )
        .expect("seed frozen V3 metadata");
    let legacy_task_view = b"independent-v3-task-view".to_vec();
    let legacy_task_frame = b"independent-v3-task-frame".to_vec();
    let legacy_approval_view = b"independent-v3-approval-view".to_vec();
    let legacy_approval_frame = b"independent-v3-approval-frame".to_vec();
    connection
        .execute(
            "INSERT INTO task_views(task_id,updated_sequence,view) VALUES(?1,1,?2)",
            params!["legacy-task", legacy_task_view],
        )
        .expect("seed frozen V3 Task view");
    connection
        .execute(
            "INSERT INTO task_view_frames(sequence,task_id,frame) VALUES(1,?1,?2)",
            params!["legacy-task", legacy_task_frame],
        )
        .expect("seed frozen V3 Task frame");
    connection
        .execute(
            "INSERT INTO harness_approval_views(
               approval_request_id,updated_sequence,view
             ) VALUES(?1,2,?2)",
            params!["legacy-approval", legacy_approval_view],
        )
        .expect("seed frozen V3 Approval view");
    connection
        .execute(
            "INSERT INTO harness_approval_frames(
               sequence,approval_request_id,frame
             ) VALUES(2,?1,?2)",
            params!["legacy-approval", legacy_approval_frame],
        )
        .expect("seed frozen V3 Approval frame");
    connection
        .pragma_update(None, "user_version", 3)
        .expect("freeze V3 migration level");
    drop(connection);

    let model = open(&root);
    assert_eq!(model.position().expect("global position").sequence, 2);
    assert_eq!(
        model
            .harness_content_position()
            .expect("content position")
            .sequence,
        0
    );
    drop(model);

    let connection = inspect(&root);
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read migrated schema version");
    assert_eq!(user_version, 4);
    let migrated_profile_digest: String = connection
        .query_row(
            "SELECT schema_profile_sha256 FROM projection_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("read migrated schema digest");
    assert_ne!(migrated_profile_digest, LEGACY_V3_SCHEMA_DIGEST);
    assert_eq!(migrated_profile_digest.len(), 64);
    for (table, identity_column, identity, payload_column, expected) in [
        (
            "task_views",
            "task_id",
            "legacy-task",
            "view",
            b"independent-v3-task-view".as_slice(),
        ),
        (
            "task_view_frames",
            "task_id",
            "legacy-task",
            "frame",
            b"independent-v3-task-frame".as_slice(),
        ),
        (
            "harness_approval_views",
            "approval_request_id",
            "legacy-approval",
            "view",
            b"independent-v3-approval-view".as_slice(),
        ),
        (
            "harness_approval_frames",
            "approval_request_id",
            "legacy-approval",
            "frame",
            b"independent-v3-approval-frame".as_slice(),
        ),
    ] {
        let bytes: Vec<u8> = connection
            .query_row(
                &format!("SELECT {payload_column} FROM {table} WHERE {identity_column}=?1"),
                [identity],
                |row| row.get(0),
            )
            .expect("read preserved V3 row");
        assert_eq!(bytes, expected);
    }
    let table_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type='table' AND name LIKE 'harness_content_%'",
            [],
            |row| row.get(0),
        )
        .expect("count V4 tables");
    assert_eq!(table_count, 7);
    let attached: Vec<String> = connection
        .prepare("PRAGMA database_list")
        .expect("prepare database list")
        .query_map([], |row| row.get::<_, String>(1))
        .expect("read database list")
        .collect::<Result<_, _>>()
        .expect("collect database list");
    assert_eq!(attached, vec!["main"]);
    let persistent_databases = fs::read_dir(&root.0)
        .expect("read migration root")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "db"))
        .count();
    assert_eq!(persistent_databases, 1);
}

#[test]
fn r9c_content_position_and_fail_closed_reset_are_independent_partial() {
    let root = TempRoot::new("domain-independence");
    let mut model = open(&root);
    model.apply_task(&task_input()).expect("project Task");
    model
        .apply_collaboration(&collaboration_input())
        .expect("project collaboration");
    model
        .apply_adapter_approval(&approval_input())
        .expect("project approval");
    let global_position = model.position().expect("global position");
    let global_floor = model.retention_floor().expect("global floor");
    let approval = model
        .get_harness_approval_view(
            "approval-001",
            ApprovalViewAccess {
                can_read: true,
                can_decide: false,
            },
        )
        .expect("read approval")
        .expect("approval exists")
        .encode_to_vec();
    let task = task_view_bytes(&model);
    let task_counts = task_projection_counts(&root);

    model
        .apply_harness_content(&projection_input(
            "content-delivery-001",
            usage_record(1, "task-content", "attempt-content"),
            1,
        ))
        .expect("project independent content");
    assert_eq!(
        model
            .harness_content_position()
            .expect("content position")
            .sequence,
        1
    );
    assert_eq!(
        model.position().expect("global position unchanged"),
        global_position
    );
    assert_eq!(
        model.retention_floor().expect("global floor unchanged"),
        global_floor
    );

    let before_unsafe_reset = content_durable_state(&root);
    assert!(matches!(
        model.reset_harness_content_for_rebuild(
            "content-epoch-02",
            HarnessContentResetReason::EpochChanged,
        ),
        Err(ProjectionFailure::ContentOwnerSnapshotRequired)
    ));
    assert_eq!(content_durable_state(&root), before_unsafe_reset);
    assert_eq!(
        model
            .harness_content_position()
            .expect("position after fail-closed reset")
            .sequence,
        1
    );
    assert_eq!(
        model.harness_content_health().expect("content health"),
        ProjectionHealth::Ready
    );
    assert_eq!(
        model.position().expect("global position after reset"),
        global_position
    );
    assert_eq!(
        model.retention_floor().expect("global floor after reset"),
        global_floor
    );
    assert_eq!(
        model
            .get_harness_approval_view(
                "approval-001",
                ApprovalViewAccess {
                    can_read: true,
                    can_decide: false,
                },
            )
            .expect("read approval after reset")
            .expect("approval remains")
            .encode_to_vec(),
        approval
    );
    assert_eq!(task_view_bytes(&model), task);
    assert_eq!(task_projection_counts(&root), task_counts);
}

#[test]
fn r9c_content_record_commit_replay_and_conflict_are_atomic() {
    let root = TempRoot::new("commit-replay-conflict");
    let mut model = open(&root);
    let input = projection_input(
        "content-delivery-001",
        usage_record(1, "task-001", "attempt-001"),
        1,
    );
    let first = model
        .apply_harness_content(&input)
        .expect("commit content record");
    assert!(matches!(first, HarnessContentApply::Committed { .. }));
    assert_eq!(content_counts(&root), (1, 1));

    let replay = model
        .apply_harness_content(&input)
        .expect("replay exact content record");
    let original_position = match first {
        HarnessContentApply::Committed { position, .. } => position,
        HarnessContentApply::Replay { .. } => unreachable!(),
    };
    assert_eq!(
        replay,
        HarnessContentApply::Replay {
            original_position: original_position.clone()
        }
    );
    assert_eq!(content_counts(&root), (1, 1));
    let committed_state = content_durable_state(&root);

    let mut owner_identity_replay = input.clone();
    owner_identity_replay.delivery_id = "content-delivery-owner-replay".to_owned();
    assert_eq!(
        model
            .apply_harness_content(&owner_identity_replay)
            .expect("replay by stable owner event identity"),
        HarnessContentApply::Replay {
            original_position: original_position.clone()
        }
    );
    assert_eq!(content_durable_state(&root), committed_state);

    let mut conflict = input.clone();
    let Some(safe_harness_content_projection_event::Payload::ContentRecord(record)) =
        conflict.event.payload.as_mut()
    else {
        unreachable!()
    };
    record.record_digest_sha256 = "f".repeat(64);
    conflict.payload_digest_sha256 = sha256(conflict.event.encode_to_vec());
    assert!(matches!(
        model.apply_harness_content(&conflict),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&root), (1, 1));
    let conflict_state = content_durable_state(&root);
    assert_eq!(conflict_state.inbox, committed_state.inbox);
    assert_eq!(conflict_state.records, committed_state.records);
    assert_eq!(
        (
            conflict_state.metadata.0,
            conflict_state.metadata.1,
            conflict_state.metadata.2,
            conflict_state.metadata.5,
            conflict_state.metadata.6,
        ),
        (
            committed_state.metadata.0,
            committed_state.metadata.1,
            committed_state.metadata.2,
            committed_state.metadata.5,
            committed_state.metadata.6,
        )
    );
    assert_eq!(
        model
            .harness_content_position()
            .expect("position after conflict")
            .sequence,
        1
    );
    assert_eq!(
        model
            .harness_content_health()
            .expect("health after conflict"),
        ProjectionHealth::IntegrityFailed
    );
}

#[test]
fn r9c_forged_record_id_fails_closed_without_cross_domain_write() {
    let root = TempRoot::new("forged-record-id");
    let mut model = open(&root);
    model.apply_task(&task_input()).expect("project Task");
    model
        .apply_collaboration(&collaboration_input())
        .expect("project collaboration");
    model
        .apply_adapter_approval(&approval_input())
        .expect("project approval");

    let task = task_view_bytes(&model);
    let task_counts = task_projection_counts(&root);
    let approval = model
        .get_harness_approval_view(
            "approval-001",
            ApprovalViewAccess {
                can_read: true,
                can_decide: false,
            },
        )
        .expect("read approval")
        .expect("approval exists")
        .encode_to_vec();

    let mut forged = projection_input(
        "forged-record-id-delivery",
        usage_record(77, "task-forged", "attempt-forged"),
        1,
    );
    let Some(safe_harness_content_projection_event::Payload::ContentRecord(record)) =
        forged.event.payload.as_mut()
    else {
        unreachable!()
    };
    record.record_id = format!("hcr_{}", "f".repeat(64));
    forged.payload_digest_sha256 = sha256(forged.event.encode_to_vec());

    assert!(matches!(
        model.apply_harness_content(&forged),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&root), (0, 0));
    assert_eq!(task_view_bytes(&model), task);
    assert_eq!(task_projection_counts(&root), task_counts);
    assert_eq!(
        model
            .get_harness_approval_view(
                "approval-001",
                ApprovalViewAccess {
                    can_read: true,
                    can_decide: false,
                },
            )
            .expect("read approval after forged record")
            .expect("approval remains")
            .encode_to_vec(),
        approval
    );
    assert_eq!(
        model
            .harness_content_health()
            .expect("content health after forged record"),
        ProjectionHealth::IntegrityFailed
    );
}

#[test]
fn r9c_content_event_accepts_all_canonical_safe_parts_exactly_once() {
    let root = TempRoot::new("multipart-owner-identity");
    let mut model = open(&root);
    let cumulative_digest = sha256("first-second");
    let mut first = text_record(
        501,
        "task-multipart",
        "attempt-multipart",
        "first-".to_owned(),
    );
    let Some(safe_harness_content_record::Payload::AssistantText(text)) = first.payload.as_mut()
    else {
        unreachable!()
    };
    text.safe_cumulative_digest_sha256 = cumulative_digest.clone();
    text.part_index = 0;
    text.part_count = 2;
    seal_record(&mut first);

    let mut second = first.clone();
    let Some(safe_harness_content_record::Payload::AssistantText(text)) = second.payload.as_mut()
    else {
        unreachable!()
    };
    text.safe_text_utf8 = "second".to_owned();
    text.safe_cumulative_digest_sha256 = cumulative_digest;
    text.part_index = 1;
    text.part_count = 2;
    seal_record(&mut second);

    assert_ne!(first.record_id, second.record_id);
    assert_eq!(first.content_event_id, second.content_event_id);
    let first_input = projection_input("multipart-delivery-0", first, 1);
    let second_input = projection_input("multipart-delivery-1", second, 2);
    assert!(matches!(
        model.apply_harness_content(&first_input),
        Ok(HarnessContentApply::Committed { .. })
    ));
    assert!(matches!(
        model.apply_harness_content(&second_input),
        Ok(HarnessContentApply::Committed { .. })
    ));
    assert_eq!(content_counts(&root), (2, 2));
    assert!(matches!(
        model.apply_harness_content(&second_input),
        Ok(HarnessContentApply::Replay { .. })
    ));
    assert_eq!(content_counts(&root), (2, 2));
}

#[test]
fn r9c_content_event_rejects_out_of_order_parts_and_identity_drift() {
    let out_of_order_root = TempRoot::new("multipart-out-of-order");
    let mut out_of_order_model = open(&out_of_order_root);
    let mut out_of_order = text_record(
        601,
        "task-multipart-order",
        "attempt-multipart-order",
        "second".to_owned(),
    );
    let Some(safe_harness_content_record::Payload::AssistantText(text)) =
        out_of_order.payload.as_mut()
    else {
        unreachable!()
    };
    text.part_index = 1;
    text.part_count = 2;
    seal_record(&mut out_of_order);
    assert!(matches!(
        out_of_order_model.apply_harness_content(&projection_input(
            "multipart-out-of-order-delivery",
            out_of_order,
            1,
        )),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&out_of_order_root), (0, 0));

    let drift_root = TempRoot::new("multipart-identity-drift");
    let mut drift_model = open(&drift_root);
    let mut first = text_record(
        602,
        "task-multipart-drift",
        "attempt-multipart-drift",
        "first".to_owned(),
    );
    let Some(safe_harness_content_record::Payload::AssistantText(text)) = first.payload.as_mut()
    else {
        unreachable!()
    };
    text.part_count = 2;
    seal_record(&mut first);
    let mut drifted_second = first.clone();
    drifted_second.model_alias = "different-model".to_owned();
    let Some(safe_harness_content_record::Payload::AssistantText(text)) =
        drifted_second.payload.as_mut()
    else {
        unreachable!()
    };
    text.part_index = 1;
    text.safe_text_utf8 = "second".to_owned();
    seal_record(&mut drifted_second);
    drift_model
        .apply_harness_content(&projection_input("multipart-drift-first", first, 1))
        .expect("commit first canonical part");
    assert!(matches!(
        drift_model.apply_harness_content(&projection_input(
            "multipart-drift-second",
            drifted_second,
            2,
        )),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&drift_root), (1, 1));
}

#[test]
fn r9c_limit_marker_follows_prefix_is_publicly_typed_and_terminates_task() {
    let root = TempRoot::new("typed-task-limit");
    let mut model = open(&root);
    let mut prefix = text_record(
        701,
        "task-typed-limit",
        "attempt-typed-limit",
        "final fitting prefix".to_owned(),
    );
    let Some(safe_harness_content_record::Payload::AssistantText(text)) = prefix.payload.as_mut()
    else {
        unreachable!()
    };
    text.part_count = 2;
    seal_record(&mut prefix);
    let marker = limit_marker_after(&prefix, HarnessContentLimitKind::TaskTextBytes);

    model
        .apply_harness_content(&projection_input("typed-limit-prefix", prefix, 1))
        .expect("commit final fitting prefix");
    model
        .apply_harness_content(&projection_input("typed-limit-marker", marker, 2))
        .expect("commit final typed marker");

    let page = model
        .list_harness_content(
            &baseline_query("task-typed-limit", &["attempt-typed-limit"], 10),
            read_access(),
        )
        .expect("read typed marker");
    assert_eq!(page.records.len(), 2);
    let Some(harness_content_record_view::Payload::Marker(public_marker)) =
        page.records[1].payload.as_ref()
    else {
        panic!("second record must be the public limit marker")
    };
    assert_eq!(
        HarnessContentMarkerKind::try_from(public_marker.kind),
        Ok(HarnessContentMarkerKind::LimitReached)
    );
    assert_eq!(
        HarnessContentLimitKind::try_from(public_marker.limit_kind),
        Ok(HarnessContentLimitKind::TaskTextBytes)
    );

    assert!(matches!(
        model.apply_harness_content(&projection_input(
            "typed-limit-after-task",
            usage_record(702, "task-typed-limit", "attempt-other"),
            3,
        )),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&root), (2, 2));
}

#[test]
fn r9c_attempt_limit_blocks_only_its_attempt() {
    let root = TempRoot::new("typed-attempt-limit");
    let mut model = open(&root);
    model
        .apply_harness_content(&projection_input(
            "attempt-limit-marker",
            limit_marker_record(
                711,
                "task-attempt-limit",
                "attempt-limited",
                HarnessContentLimitKind::AttemptRecords,
            ),
            1,
        ))
        .expect("commit attempt-scoped marker");
    model
        .apply_harness_content(&projection_input(
            "attempt-limit-other-attempt",
            usage_record(712, "task-attempt-limit", "attempt-open"),
            2,
        ))
        .expect("another Attempt remains open");
    assert!(matches!(
        model.apply_harness_content(&projection_input(
            "attempt-limit-after-attempt",
            usage_record(713, "task-attempt-limit", "attempt-limited"),
            3,
        )),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(content_counts(&root), (2, 2));
}

#[test]
fn r9c_content_baseline_pagination_is_fixed_and_cursor_bound() {
    let root = TempRoot::new("fixed-pagination");
    let mut model = open(&root);
    for id in 1..=3 {
        model
            .apply_harness_content(&projection_input(
                format!("content-delivery-{id}"),
                usage_record(id, "task-001", "attempt-001"),
                id as i64,
            ))
            .expect("project baseline record");
    }
    let first = model
        .list_harness_content(
            &baseline_query("task-001", &["attempt-001"], 2),
            read_access(),
        )
        .expect("read first fixed page");
    assert_eq!(first.records.len(), 2);
    assert!(first.has_more);
    assert_eq!(first.snapshot_position.sequence, 3);
    assert_eq!(
        first
            .next_cursor
            .as_ref()
            .expect("next cursor")
            .last_sequence(),
        2
    );

    model
        .apply_harness_content(&projection_input(
            "content-delivery-4",
            usage_record(4, "task-001", "attempt-001"),
            4,
        ))
        .expect("project record after first page");
    let second_query = HarnessContentBaselineQuery {
        task_id: "task-001".to_owned(),
        attempt_ids: vec!["attempt-001".to_owned()],
        page_size: 2,
        snapshot_position: Some(first.snapshot_position.clone()),
        cursor: first.next_cursor.clone(),
    };
    let second = model
        .list_harness_content(&second_query, read_access())
        .expect("read second fixed page");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].content_sequence, 3);
    assert!(!second.has_more);

    let mut changed_filter = second_query;
    changed_filter.attempt_ids = vec!["attempt-other".to_owned()];
    assert!(matches!(
        model.list_harness_content(&changed_filter, read_access()),
        Err(ProjectionFailure::ContentCursorMismatch)
    ));
}

#[test]
fn r9c_content_baseline_enforces_whole_record_and_byte_caps() {
    let root = TempRoot::new("page-caps");
    let mut model = open(&root);
    for id in 1..=256 {
        model
            .apply_harness_content(&projection_input(
                format!("metadata-delivery-{id}"),
                usage_record(id, "task-record-cap", "attempt-record-cap"),
                id as i64,
            ))
            .expect("project metadata record");
    }
    let exact_record_cap = model
        .list_harness_content(
            &baseline_query("task-record-cap", &["attempt-record-cap"], 257),
            read_access(),
        )
        .expect("read exact record-cap page");
    assert_eq!(exact_record_cap.records.len(), 256);
    assert!(!exact_record_cap.has_more);
    assert!(exact_record_cap.next_cursor.is_none());

    model
        .apply_harness_content(&projection_input(
            "metadata-delivery-257",
            usage_record(257, "task-record-cap", "attempt-record-cap"),
            257,
        ))
        .expect("project record-cap plus one");
    let record_cap = model
        .list_harness_content(
            &baseline_query("task-record-cap", &["attempt-record-cap"], 257),
            read_access(),
        )
        .expect("read record-cap page");
    assert_eq!(record_cap.records.len(), 256);
    assert!(record_cap.has_more);
    assert_eq!(
        record_cap
            .next_cursor
            .as_ref()
            .expect("record-cap cursor")
            .last_sequence(),
        256
    );
    let record_cap_tail = model
        .list_harness_content(
            &HarnessContentBaselineQuery {
                task_id: "task-record-cap".to_owned(),
                attempt_ids: vec!["attempt-record-cap".to_owned()],
                page_size: 256,
                snapshot_position: Some(record_cap.snapshot_position.clone()),
                cursor: record_cap.next_cursor.clone(),
            },
            read_access(),
        )
        .expect("read complete record-cap tail");
    assert_eq!(record_cap_tail.records.len(), 1);
    assert_eq!(record_cap_tail.records[0].content_sequence, 257);
    assert!(!record_cap_tail.has_more);
    assert!(record_cap_tail.next_cursor.is_none());

    for part in 0..16 {
        let id = 1_000 + part;
        model
            .apply_harness_content(&projection_input(
                format!("text-delivery-{id}"),
                text_record(id, "task-byte-cap", "attempt-byte-cap", "x".repeat(65_536)),
                id as i64,
            ))
            .expect("project exact byte-cap part");
    }
    let exact = model
        .list_harness_content(
            &baseline_query("task-byte-cap", &["attempt-byte-cap"], 256),
            read_access(),
        )
        .expect("read exact byte-cap page");
    assert_eq!(exact.records.len(), 16);
    assert!(!exact.has_more);
    let exact_bytes: usize = exact
        .records
        .iter()
        .map(
            |record| match record.payload.as_ref().expect("public payload") {
                harness_content_record_view::Payload::AssistantText(text) => {
                    text.safe_text_utf8.len()
                }
                _ => 0,
            },
        )
        .sum();
    assert_eq!(exact_bytes, 1_048_576);

    model
        .apply_harness_content(&projection_input(
            "text-delivery-plus-one",
            text_record(2_000, "task-byte-cap", "attempt-byte-cap", "y".to_owned()),
            2_000,
        ))
        .expect("project plus-one byte record");
    let plus_one = model
        .list_harness_content(
            &baseline_query("task-byte-cap", &["attempt-byte-cap"], 256),
            read_access(),
        )
        .expect("read plus-one byte page");
    assert_eq!(plus_one.records.len(), 16);
    assert!(plus_one.has_more);
    assert!(plus_one.next_cursor.is_some());
    let plus_one_tail = model
        .list_harness_content(
            &HarnessContentBaselineQuery {
                task_id: "task-byte-cap".to_owned(),
                attempt_ids: vec!["attempt-byte-cap".to_owned()],
                page_size: 256,
                snapshot_position: Some(plus_one.snapshot_position.clone()),
                cursor: plus_one.next_cursor.clone(),
            },
            read_access(),
        )
        .expect("read complete byte-cap tail");
    assert_eq!(plus_one_tail.records.len(), 1);
    let Some(harness_content_record_view::Payload::AssistantText(text)) =
        plus_one_tail.records[0].payload.as_ref()
    else {
        panic!("expected complete plus-one text record");
    };
    assert_eq!(text.safe_text_utf8, "y");
    assert!(!plus_one_tail.has_more);
    assert!(plus_one_tail.next_cursor.is_none());
}

#[test]
fn r9c_content_watch_replay_heartbeat_and_profile_reset_are_bounded_partial() {
    let root = TempRoot::new("watch-partial");
    let mut model = open(&root);
    let first_input = projection_input(
        "content-delivery-001",
        usage_record(1, "task-001", "attempt-001"),
        1,
    );
    model
        .apply_harness_content(&first_input)
        .expect("project first record");
    model
        .apply_harness_content(&projection_input(
            "content-delivery-002",
            usage_record(2, "task-001", "attempt-001"),
            2,
        ))
        .expect("project second record");
    let initial = egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessContentPosition {
        epoch: EPOCH.to_owned(),
        sequence: 0,
        projected_at: None,
    };
    let first = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: initial.clone(),
                max_frames: 0,
            },
            read_access(),
        )
        .expect("watch first bounded frame");
    assert_eq!(first.frames.len(), 1);
    assert_eq!(first.observed_position.sequence, 1);
    assert!(matches!(
        first.frames[0].payload,
        Some(harness_content_stream_frame::Payload::Records(_))
    ));

    for id in 3..=257 {
        model
            .apply_harness_content(&projection_input(
                format!("watch-delivery-{id}"),
                usage_record(id, "task-001", "attempt-001"),
                id as i64,
            ))
            .expect("project watch-cap record");
    }
    let capped = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: initial,
                max_frames: 257,
            },
            read_access(),
        )
        .expect("watch clamps plus-one request to 256 frames");
    assert_eq!(capped.frames.len(), 256);
    assert_eq!(capped.observed_position.sequence, 256);
    for (index, frame) in capped.frames.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        assert_eq!(
            frame.position.as_ref().expect("frame position").sequence,
            expected_sequence
        );
        let Some(harness_content_stream_frame::Payload::Records(records)) = frame.payload.as_ref()
        else {
            panic!("expected one records frame");
        };
        assert_eq!(records.records.len(), 1);
        assert_eq!(records.records[0].content_sequence, expected_sequence);
    }
    let tail = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: capped.observed_position,
                max_frames: 257,
            },
            read_access(),
        )
        .expect("watch returns unclipped tail");
    assert_eq!(tail.frames.len(), 1);
    assert_eq!(tail.observed_position.sequence, 257);

    model
        .apply_harness_content(&first_input)
        .expect("replay does not advance watch position");
    let before_max_text = model
        .harness_content_position()
        .expect("position before maximum text frame");
    assert_eq!(before_max_text.sequence, 257);
    model
        .apply_harness_content(&projection_input(
            "watch-max-text-delivery",
            text_record(
                5_000,
                "task-max-frame",
                "attempt-max-frame",
                "z".repeat(65_536),
            ),
            258,
        ))
        .expect("project maximum safe-text record");
    let max_text = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-max-frame".to_owned(),
                attempt_ids: vec!["attempt-max-frame".to_owned()],
                resume_after: before_max_text,
                max_frames: 1,
            },
            read_access(),
        )
        .expect("watch maximum safe-text frame");
    assert_eq!(max_text.frames.len(), 1);
    assert!(max_text.frames[0].encoded_len() < 81_920);
    let Some(harness_content_stream_frame::Payload::Records(records)) =
        max_text.frames[0].payload.as_ref()
    else {
        panic!("expected maximum text records frame");
    };
    let Some(harness_content_record_view::Payload::AssistantText(text)) =
        records.records[0].payload.as_ref()
    else {
        panic!("expected maximum text payload");
    };
    assert_eq!(text.safe_text_utf8.len(), 65_536);

    let current = model
        .harness_content_position()
        .expect("current content position");
    assert_eq!(current.sequence, 258);
    let heartbeat = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: current.clone(),
                max_frames: 1,
            },
            read_access(),
        )
        .expect("watch heartbeat");
    assert_eq!(heartbeat.observed_position, current);
    assert_eq!(heartbeat.frames.len(), 1);
    assert!(matches!(
        heartbeat.frames[0].payload,
        Some(harness_content_stream_frame::Payload::Heartbeat(_))
    ));

    drop(model);
    let connection = mutable_fixture_connection(&root);
    connection
        .execute(
            "UPDATE harness_content_metadata
             SET disclosure_profile_sha256=?1 WHERE singleton=1",
            ["8".repeat(64)],
        )
        .expect("inject profile mismatch");
    drop(connection);
    let model = open(&root);
    let reset = model
        .watch_harness_content(
            &HarnessContentWatchQuery {
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: current,
                max_frames: 1,
            },
            read_access(),
        )
        .expect("watch returns one reset");
    assert_eq!(reset.frames.len(), 1);
    let Some(harness_content_stream_frame::Payload::ResetRequired(frame)) =
        reset.frames[0].payload.as_ref()
    else {
        panic!("expected typed reset");
    };
    assert_eq!(
        frame.reason,
        HarnessContentResetReason::ProfileChanged as i32
    );
}

#[test]
fn r9c_artifact_identity_visibility_is_permission_gated_and_public_view_is_safe() {
    let root = TempRoot::new("artifact-visibility");
    let mut model = open(&root);
    let owner_record = record(
        77,
        "task-artifact",
        "attempt-artifact",
        safe_harness_content_record::Payload::ArtifactRelation(SafeArtifactRelationContent {
            safe_content_differs_from_artifact: true,
            artifact: Some(SafeArtifactIdentity {
                artifact_id: "artifact-secret-identity".to_owned(),
                artifact_digest_sha256: "b".repeat(64),
            }),
        }),
    );
    let owner_bytes = owner_record.encode_to_vec();
    model
        .apply_harness_content(&projection_input("artifact-delivery-001", owner_record, 1))
        .expect("project artifact relation");
    let query = baseline_query("task-artifact", &["attempt-artifact"], 1);

    assert!(matches!(
        model.list_harness_content(&query, HarnessContentReadAccess::default()),
        Err(ProjectionFailure::PermissionDenied)
    ));
    let redacted = model
        .list_harness_content(&query, read_access())
        .expect("read redacted artifact relation");
    let Some(harness_content_record_view::Payload::ArtifactRelation(relation)) =
        redacted.records[0].payload.as_ref()
    else {
        panic!("expected artifact relation");
    };
    assert!(matches!(
        relation.visibility,
        Some(harness_artifact_relation_view::Visibility::AvailableRedacted(_))
    ));

    let visible = model
        .list_harness_content(
            &query,
            HarnessContentReadAccess {
                can_read_content: true,
                can_read_artifact_identity: true,
            },
        )
        .expect("read visible artifact relation");
    let Some(harness_content_record_view::Payload::ArtifactRelation(relation)) =
        visible.records[0].payload.as_ref()
    else {
        panic!("expected visible artifact relation");
    };
    let Some(harness_artifact_relation_view::Visibility::Available(identity)) =
        relation.visibility.as_ref()
    else {
        panic!("expected authorized artifact identity");
    };
    assert_eq!(identity.artifact_id, "artifact-secret-identity");
    assert_eq!(content_counts(&root), (1, 1));

    let public_bytes = visible.records[0].encode_to_vec();
    let public_debug = format!("{:?}", visible.records[0]);
    for canary in [
        "run-canary-77".to_owned(),
        "step-canary-77".to_owned(),
        "dispatch-canary-77".to_owned(),
        sha256("route-canary-77"),
    ] {
        assert!(
            !public_bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
        assert!(!public_debug.contains(&canary));
        assert!(
            owner_bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
    }
}

#[test]
fn r9c_content_failure_is_domain_local_and_preserves_existing_projections() {
    let root = TempRoot::new("failure-isolation");
    let mut model = open(&root);
    model.apply_task(&task_input()).expect("project Task");
    model
        .apply_collaboration(&collaboration_input())
        .expect("project collaboration");
    model
        .apply_adapter_approval(&approval_input())
        .expect("project approval");
    let global_position = model.position().expect("global position");
    let global_floor = model.retention_floor().expect("global floor");
    let approval = model
        .get_harness_approval_view(
            "approval-001",
            ApprovalViewAccess {
                can_read: true,
                can_decide: false,
            },
        )
        .expect("read approval")
        .expect("approval exists")
        .encode_to_vec();
    let task = task_view_bytes(&model);
    let task_counts = task_projection_counts(&root);

    let missing = SafeHarnessContentProjectionEvent { payload: None };
    let missing_input = HarnessContentProjectionInput {
        delivery_id: "missing-payload".to_owned(),
        payload_digest_sha256: sha256(missing.encode_to_vec()),
        event: missing,
        projected_at: timestamp(1),
    };
    assert!(matches!(
        model.apply_harness_content(&missing_input),
        Err(ProjectionFailure::InvalidMessage)
    ));

    let mut wrong_digest = projection_input(
        "wrong-digest",
        usage_record(1, "task-content", "attempt-content"),
        2,
    );
    wrong_digest.payload_digest_sha256 = "0".repeat(64);
    assert!(matches!(
        model.apply_harness_content(&wrong_digest),
        Err(ProjectionFailure::InvalidMessage)
    ));

    let compaction = HarnessContentHistoryCompactionRecord {
        compaction_record_id: format!("hcc_{}", "1".repeat(64)),
        compaction_record_digest_sha256: "2".repeat(64),
        task_id: "task-content".to_owned(),
        attempt_id: "attempt-content".to_owned(),
        final_epoch: EPOCH.to_owned(),
        final_sequence: 1,
        final_safe_content_digest_sha256: "3".repeat(64),
        owner_snapshot_digest_sha256: "4".repeat(64),
        disclosure_profile_ref: Some(profile_ref()),
        compacted_at: Some(timestamp(3)),
        reason: 1,
    };
    let event = SafeHarnessContentProjectionEvent {
        payload: Some(
            safe_harness_content_projection_event::Payload::HistoryCompaction(compaction),
        ),
    };
    let compaction_input = HarnessContentProjectionInput {
        delivery_id: "compaction-without-owner-snapshot".to_owned(),
        payload_digest_sha256: sha256(event.encode_to_vec()),
        event,
        projected_at: timestamp(3),
    };
    let before_owner_snapshot_failures = content_durable_state(&root);
    assert!(matches!(
        model.apply_harness_content(&compaction_input),
        Err(ProjectionFailure::ContentOwnerSnapshotRequired)
    ));
    assert_eq!(content_durable_state(&root), before_owner_snapshot_failures);

    let tombstone = HarnessContentRetentionTombstone {
        tombstone_id: format!("hrt_{}", "5".repeat(64)),
        tombstone_digest_sha256: "6".repeat(64),
        task_id: "task-content".to_owned(),
        attempt_id: "attempt-content".to_owned(),
        final_epoch: EPOCH.to_owned(),
        final_sequence: 1,
        final_safe_content_digest_sha256: "7".repeat(64),
        disclosure_profile_ref: Some(profile_ref()),
        terminal_committed_at: Some(timestamp(3)),
        compacted_at: Some(timestamp(4)),
        reason: 1,
    };
    let event = SafeHarnessContentProjectionEvent {
        payload: Some(
            safe_harness_content_projection_event::Payload::RetentionTombstone(tombstone),
        ),
    };
    let tombstone_input = HarnessContentProjectionInput {
        delivery_id: "tombstone-without-owner-snapshot".to_owned(),
        payload_digest_sha256: sha256(event.encode_to_vec()),
        event,
        projected_at: timestamp(4),
    };
    assert!(matches!(
        model.apply_harness_content(&tombstone_input),
        Err(ProjectionFailure::ContentOwnerSnapshotRequired)
    ));
    assert_eq!(content_durable_state(&root), before_owner_snapshot_failures);
    assert_eq!(content_counts(&root), (0, 0));
    assert_eq!(
        model.position().expect("global position after failures"),
        global_position
    );
    assert_eq!(
        model
            .retention_floor()
            .expect("global floor after failures"),
        global_floor
    );
    assert_eq!(
        model
            .get_harness_approval_view(
                "approval-001",
                ApprovalViewAccess {
                    can_read: true,
                    can_decide: false,
                },
            )
            .expect("read approval after failures")
            .expect("approval remains")
            .encode_to_vec(),
        approval
    );
    assert_eq!(task_view_bytes(&model), task);
    assert_eq!(task_projection_counts(&root), task_counts);

    model
        .apply_harness_content(&projection_input(
            "retained-before-profile-hold",
            usage_record(1, "task-content", "attempt-content"),
            4,
        ))
        .expect("persist safe fact before profile hold");
    assert_eq!(content_counts(&root), (1, 1));
    drop(model);
    let connection = mutable_fixture_connection(&root);
    connection
        .execute(
            "UPDATE harness_content_metadata
             SET disclosure_profile_sha256=?1 WHERE singleton=1",
            ["9".repeat(64)],
        )
        .expect("inject persisted profile mismatch");
    drop(connection);

    let model = open(&root);
    assert_eq!(
        model.harness_content_health().expect("held content health"),
        ProjectionHealth::Held
    );
    assert_eq!(content_counts(&root), (1, 1));
    assert_eq!(
        model
            .position()
            .expect("global position in structured-only mode"),
        global_position
    );
    assert_eq!(
        model
            .get_harness_approval_view(
                "approval-001",
                ApprovalViewAccess {
                    can_read: true,
                    can_decide: false,
                },
            )
            .expect("read approval in structured-only mode")
            .expect("approval remains in structured-only mode")
            .encode_to_vec(),
        approval
    );
    assert_eq!(task_view_bytes(&model), task);
    assert_eq!(task_projection_counts(&root), task_counts);
    assert!(matches!(
        model.list_harness_content(
            &baseline_query("task-content", &["attempt-content"], 1),
            read_access()
        ),
        Err(ProjectionFailure::ContentBaselineUnavailable)
    ));
}
