use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AttemptSnapshot, CollaborationCommandResult, CollaborationEvent, CollaborationSnapshot, Lease,
    RunSnapshot, collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalKind, ApprovalRequestLifecycleKind, ApprovalRequestObservation,
    HarnessObservation, harness_observation,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    AvailableActionKind, ProjectionHealth, ProjectionPosition, StreamFrameKind,
};
use egopulse_domain_contracts::v01::egopulse::policy::v1::{
    HarnessApprovalDecisionRecord, HarnessApprovalDecisionState, HarnessApprovalDecisionStateKind,
    HarnessApprovalRequestBinding, PolicyDecisionCommandResult, PolicyDecisionEvent,
};
use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskEvent, TaskSnapshot, TaskStatus};
use egopulse_local_read_model::{
    AdapterApprovalProjectionInput, ApprovalListFilter, ApprovalViewAccess,
    CollaborationProjectionInput, LocalReadModel, LocalReadModelConfig, LocalReadModelKey,
    PolicyApprovalProjectionInput, ProjectionApply, ProjectionFailure, ProjectionMessageMetadata,
    ProjectionMessageMode, TaskProjectionInput,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const ACTION_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("egopulse-read-model-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create test root");
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

fn timestamp() -> Timestamp {
    Timestamp {
        seconds: NOW,
        nanos: 0,
    }
}

fn digest(message: &impl Message) -> String {
    hex::encode(Sha256::digest(message.encode_to_vec()))
}

fn metadata(id: &str, revision: u64, payload: &impl Message) -> ProjectionMessageMetadata {
    ProjectionMessageMetadata {
        message_id: format!("message-{id}"),
        source_event_id: id.to_owned(),
        source_revision: revision,
        mode: ProjectionMessageMode::Incremental,
        payload_digest_sha256: digest(payload),
        projected_at: timestamp(),
    }
}

fn open(root: &TempRoot, epoch: &str) -> LocalReadModel {
    LocalReadModel::open(LocalReadModelConfig {
        database_path: root.database(),
        epoch: epoch.to_owned(),
        key: LocalReadModelKey::new([41; 32]),
    })
    .expect("open SQLCipher read model")
}

fn collaboration_input() -> CollaborationProjectionInput {
    let snapshot = CollaborationSnapshot {
        run: Some(RunSnapshot {
            run_id: "run-01".to_owned(),
            revision: 1,
            task_id: "task-01".to_owned(),
            ..Default::default()
        }),
        attempts: vec![AttemptSnapshot {
            attempt_id: "attempt-01".to_owned(),
            run_id: "run-01".to_owned(),
            step_id: "step-01".to_owned(),
            revision: 4,
            dispatch_id: Some("dispatch-01".to_owned()),
            lease: Some(Lease {
                fencing_token: 9,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let event = CollaborationEvent {
        event_id: "collaboration-event-01".to_owned(),
        run_id: "run-01".to_owned(),
        resulting_run_revision: 1,
        ..Default::default()
    };
    let result = CollaborationCommandResult {
        replayed: false,
        outcome: Some(collaboration_command_result::Outcome::Snapshot(snapshot)),
        committed_event: Some(event),
    };
    CollaborationProjectionInput {
        metadata: metadata("collaboration-event-01", 1, &result),
        result,
    }
}

fn adapter_input(
    lifecycle: ApprovalRequestLifecycleKind,
    request_revision: u64,
    source_revision: u64,
) -> AdapterApprovalProjectionInput {
    let observation = HarnessObservation {
        observation_id: format!("adapter-observation-{source_revision}"),
        adapter_id: "codex-adapter".to_owned(),
        attempt_id: "attempt-01".to_owned(),
        dispatch_id: "dispatch-01".to_owned(),
        fencing_token: 9,
        observation_sequence: source_revision,
        payload: Some(harness_observation::Payload::ApprovalRequest(
            ApprovalRequestObservation {
                approval_request_id: "approval-01".to_owned(),
                kind: ApprovalKind::Command as i32,
                action_digest_sha256: ACTION_DIGEST.to_owned(),
                requested_scope_ref: "safe://scope/01".to_owned(),
                display_summary_ref: "safe://summary/01".to_owned(),
                native_routing_ref: String::new(),
                lifecycle: lifecycle as i32,
                request_revision,
            },
        )),
        ..Default::default()
    };
    AdapterApprovalProjectionInput {
        metadata: metadata(&observation.observation_id, source_revision, &observation),
        run_id: "run-01".to_owned(),
        step_id: "step-01".to_owned(),
        attempt_id: "attempt-01".to_owned(),
        dispatch_id: "dispatch-01".to_owned(),
        fencing_token: 9,
        observation,
    }
}

fn unrelated_task_input() -> TaskProjectionInput {
    let event = TaskEvent {
        event_id: "unrelated-task-event-01".to_owned(),
        task_id: "task-unrelated".to_owned(),
        resulting_revision: 1,
        work_revision: 1,
        snapshot: Some(TaskSnapshot {
            task_id: "task-unrelated".to_owned(),
            revision: 1,
            work_revision: 1,
            status: TaskStatus::Ready as i32,
            created_at: Some(timestamp()),
            updated_at: Some(timestamp()),
            ..Default::default()
        }),
        ..Default::default()
    };
    TaskProjectionInput {
        metadata: metadata("unrelated-task-event-01", 1, &event),
        event,
    }
}

fn policy_input() -> PolicyApprovalProjectionInput {
    let record = HarnessApprovalDecisionRecord {
        authority_decision_ref: "policy-decision-01".to_owned(),
        version: 1,
        request: Some(HarnessApprovalRequestBinding {
            adapter_id: "codex-adapter".to_owned(),
            attempt_id: "attempt-01".to_owned(),
            dispatch_id: "dispatch-01".to_owned(),
            fencing_token: 9,
            approval_request_id: "approval-01".to_owned(),
            kind: ApprovalKind::Command as i32,
            action_digest_sha256: ACTION_DIGEST.to_owned(),
            requested_scope_ref: "safe://scope/01".to_owned(),
            native_routing_ref: String::new(),
            request_observation_id: "adapter-observation-11".to_owned(),
            request_observation_sequence: 11,
            request_lifecycle: ApprovalRequestLifecycleKind::Open as i32,
            request_revision: 1,
        }),
        decision: ApprovalDecision::AllowOnce as i32,
        reason_code: "FOUNDER_CONFIRMED".to_owned(),
        issued_at: Some(timestamp()),
        expires_at: Some(Timestamp {
            seconds: NOW + 300,
            nanos: 0,
        }),
        ..Default::default()
    };
    let state = HarnessApprovalDecisionState {
        authority_decision_ref: "policy-decision-01".to_owned(),
        revision: 1,
        state: HarnessApprovalDecisionStateKind::Issued as i32,
        updated_at: Some(timestamp()),
        ..Default::default()
    };
    let event = PolicyDecisionEvent {
        event_id: "policy-event-01".to_owned(),
        authority_decision_ref: "policy-decision-01".to_owned(),
        resulting_state_revision: 1,
        ..Default::default()
    };
    let result = PolicyDecisionCommandResult {
        committed: true,
        decision_record: Some(record),
        state: Some(state),
        event: Some(event),
        ..Default::default()
    };
    PolicyApprovalProjectionInput {
        metadata: metadata("policy-event-01", 1, &result),
        result,
    }
}

fn collaboration_at_revision(
    revision: u64,
    mode: ProjectionMessageMode,
) -> CollaborationProjectionInput {
    let mut input = collaboration_input();
    let event_id = format!("collaboration-event-{revision:02}");
    if let Some(collaboration_command_result::Outcome::Snapshot(snapshot)) =
        input.result.outcome.as_mut()
    {
        snapshot.run.as_mut().expect("run").revision = revision;
    }
    let event = input.result.committed_event.as_mut().expect("event");
    event.event_id.clone_from(&event_id);
    event.resulting_run_revision = revision;
    input.metadata = metadata(&event_id, revision, &input.result);
    input.metadata.mode = mode;
    input
}

fn policy_at_revision(revision: u64, mode: ProjectionMessageMode) -> PolicyApprovalProjectionInput {
    let mut input = policy_input();
    let event_id = format!("policy-event-{revision:02}");
    input.result.state.as_mut().expect("state").revision = revision;
    let event = input.result.event.as_mut().expect("event");
    event.event_id.clone_from(&event_id);
    event.resulting_state_revision = revision;
    input.metadata = metadata(&event_id, revision, &input.result);
    input.metadata.mode = mode;
    input
}

fn founder_access() -> ApprovalViewAccess {
    ApprovalViewAccess {
        can_read: true,
        can_decide: true,
    }
}

#[test]
fn joins_three_owner_sources_without_exposing_native_routing() {
    let root = TempRoot::new("join");
    let mut model = open(&root, "epoch-01");
    model
        .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
        .expect("project Adapter request");
    let unbound = model
        .get_harness_approval_view("approval-01", founder_access())
        .expect("get unbound request")
        .expect("request exists");
    assert!(unbound.task_id.is_empty());
    assert!(unbound.available_actions.is_empty());

    model
        .apply_collaboration(&collaboration_input())
        .expect("project Collaboration binding");
    let actionable = model
        .list_harness_approval_views(
            &ApprovalListFilter {
                actionable_only: true,
                ..Default::default()
            },
            founder_access(),
        )
        .expect("list actionable requests");
    assert_eq!(actionable.len(), 1);
    assert_eq!(actionable[0].task_id, "task-01");
    assert_eq!(
        actionable[0].available_actions[0].kind,
        AvailableActionKind::DecideHarnessApproval as i32
    );
    let client_payload = format!("{actionable:?}");
    assert!(!client_payload.contains("codex-private://routing"));

    model
        .apply_policy_approval(&policy_input())
        .expect("project Policy decision");
    let decided = model
        .get_harness_approval_view("approval-01", founder_access())
        .expect("get decided request")
        .expect("decided request exists");
    assert!(decided.available_actions.is_empty());
    assert_eq!(
        decided.policy_decision.expect("sanitized decision").state,
        HarnessApprovalDecisionStateKind::Issued as i32
    );
    assert!(model.integrity_is_ok().expect("read model integrity"));
}

#[test]
fn rebuild_baseline_is_only_the_first_projection_of_a_rebuilding_epoch() {
    let root = TempRoot::new("bootstrap-boundary");
    let mut model = open(&root, "epoch-01");
    assert!(matches!(
        model.apply_collaboration(&collaboration_at_revision(
            4,
            ProjectionMessageMode::RebuildBaseline,
        )),
        Err(ProjectionFailure::RebuildBaselineNotAllowed)
    ));

    model
        .reset_for_rebuild("epoch-02")
        .expect("enter explicit rebuild");
    model
        .apply_collaboration(&collaboration_at_revision(
            4,
            ProjectionMessageMode::RebuildBaseline,
        ))
        .expect("accept Collaboration revision-N baseline");
    model
        .apply_policy_approval(&policy_at_revision(
            3,
            ProjectionMessageMode::RebuildBaseline,
        ))
        .expect("accept Policy revision-N baseline");
    model
        .apply_collaboration(&collaboration_at_revision(
            5,
            ProjectionMessageMode::Incremental,
        ))
        .expect("accept exact revision N+1");
    assert!(matches!(
        model.apply_collaboration(&collaboration_at_revision(
            6,
            ProjectionMessageMode::RebuildBaseline,
        )),
        Err(ProjectionFailure::RebuildBaselineNotAllowed)
    ));
    model.mark_rebuild_ready().expect("publish rebuilt epoch");
    assert_eq!(model.health().expect("health"), ProjectionHealth::Ready);
}

#[test]
fn duplicate_is_replayed_but_conflicting_message_id_holds_projection() {
    let root = TempRoot::new("dedupe");
    let mut model = open(&root, "epoch-01");
    let input = adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11);
    assert!(matches!(
        model
            .apply_adapter_approval(&input)
            .expect("first projection"),
        ProjectionApply::Committed { .. }
    ));
    assert!(matches!(
        model
            .apply_adapter_approval(&input)
            .expect("duplicate projection"),
        ProjectionApply::Replay { .. }
    ));
    let mut conflict = input;
    conflict.observation.adapter_id = "tampered-adapter".to_owned();
    conflict.metadata.payload_digest_sha256 = digest(&conflict.observation);
    assert!(matches!(
        model.apply_adapter_approval(&conflict),
        Err(ProjectionFailure::IntegrityFailure)
    ));
    assert_eq!(
        model.health().expect("held health"),
        ProjectionHealth::IntegrityFailed
    );
    let held = model
        .get_harness_approval_view("approval-01", founder_access())
        .expect("read-only held view")
        .expect("request remains visible for diagnosis");
    assert!(held.available_actions.is_empty());
    let held_metadata = held.metadata.expect("held metadata");
    assert!(held_metadata.stale);
    assert_eq!(
        held_metadata.health,
        ProjectionHealth::IntegrityFailed as i32
    );
    let frames = model
        .approval_frames_after(&ProjectionPosition::default(), founder_access())
        .expect("failed projection requires reset");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, StreamFrameKind::ResetRequired as i32);
}

#[test]
fn stale_lifecycle_and_old_epoch_resume_fail_closed() {
    let root = TempRoot::new("stale-reset");
    let mut model = open(&root, "epoch-01");
    model
        .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
        .expect("open request");
    let old_position = model.position().expect("old position");
    model
        .apply_adapter_approval(&adapter_input(
            ApprovalRequestLifecycleKind::Withdrawn,
            2,
            12,
        ))
        .expect("withdraw request");
    assert!(matches!(
        model.apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 13,)),
        Err(ProjectionFailure::StaleSourceRevision)
    ));

    model
        .reset_for_rebuild("epoch-02")
        .expect("start rebuild with new epoch");
    let frames = model
        .approval_frames_after(&old_position, founder_access())
        .expect("old epoch produces reset");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, StreamFrameKind::ResetRequired as i32);
    assert_eq!(
        model.health().expect("rebuild health"),
        ProjectionHealth::Rebuilding
    );
    model.mark_rebuild_ready().expect("finish rebuild");
}

#[test]
fn new_epoch_rebuild_reconstructs_view_from_retained_owner_messages() {
    let root = TempRoot::new("retained-rebuild");
    let mut model = open(&root, "epoch-01");
    let adapter = adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11);
    let collaboration = collaboration_input();
    let policy = policy_input();

    model
        .apply_policy_approval(&policy)
        .expect("policy may arrive before request");
    model
        .apply_adapter_approval(&adapter)
        .expect("adapter request");
    model
        .apply_collaboration(&collaboration)
        .expect("collaboration binding");
    assert_eq!(model.position().expect("first epoch position").sequence, 3);

    model
        .reset_for_rebuild("epoch-02")
        .expect("start new epoch rebuild");
    model
        .apply_collaboration(&collaboration)
        .expect("replay retained Collaboration feed");
    model
        .apply_adapter_approval(&adapter)
        .expect("replay retained Adapter feed");
    model
        .apply_policy_approval(&policy)
        .expect("replay retained Policy feed");
    model.mark_rebuild_ready().expect("publish rebuilt epoch");

    let rebuilt = model
        .get_harness_approval_view("approval-01", founder_access())
        .expect("read rebuilt view")
        .expect("rebuilt approval exists");
    assert_eq!(rebuilt.task_id, "task-01");
    assert!(rebuilt.policy_decision.is_some());
    assert!(rebuilt.available_actions.is_empty());
    let position = rebuilt
        .metadata
        .expect("projection metadata")
        .position
        .expect("projection position");
    assert_eq!(position.epoch, "epoch-02");
    assert_eq!(model.position().expect("rebuilt position").sequence, 3);
}

#[test]
fn first_owner_projection_must_start_at_revision_one() {
    let root = TempRoot::new("source-gap");
    let mut model = open(&root, "epoch-01");
    let mut collaboration = collaboration_input();
    if let Some(collaboration_command_result::Outcome::Snapshot(snapshot)) =
        collaboration.result.outcome.as_mut()
    {
        snapshot.run.as_mut().expect("run snapshot").revision = 2;
    }
    let event = collaboration
        .result
        .committed_event
        .as_mut()
        .expect("committed event");
    event.event_id = "collaboration-event-02".to_owned();
    event.resulting_run_revision = 2;
    collaboration.metadata = metadata("collaboration-event-02", 2, &collaboration.result);
    assert!(matches!(
        model.apply_collaboration(&collaboration),
        Err(ProjectionFailure::StaleSourceRevision)
    ));
}

#[test]
fn unauthorized_reader_cannot_observe_approval_projection() {
    let root = TempRoot::new("unauthorized");
    let mut model = open(&root, "epoch-01");
    model
        .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
        .expect("project request");
    assert!(matches!(
        model.get_harness_approval_view(
            "approval-01",
            ApprovalViewAccess {
                can_read: false,
                can_decide: false,
            }
        ),
        Err(ProjectionFailure::PermissionDenied)
    ));
}

#[test]
fn historical_approval_snapshot_and_watch_share_the_retention_floor() {
    let root = TempRoot::new("historical-approval-page");
    let mut model = open(&root, "epoch-01");
    let first = model
        .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
        .expect("project open approval request");
    let first_position = match first {
        ProjectionApply::Committed { position, .. } => position,
        ProjectionApply::Replay { .. } => panic!("first approval request must commit"),
    };
    model
        .apply_adapter_approval(&adapter_input(
            ApprovalRequestLifecycleKind::Resolved,
            2,
            12,
        ))
        .expect("project responded approval request");
    model
        .apply_task(&unrelated_task_input())
        .expect("advance projection without changing the approval");

    let historical = model
        .list_harness_approval_views_at(
            &first_position,
            &ApprovalListFilter::default(),
            founder_access(),
        )
        .expect("read stable historical approval snapshot");
    assert_eq!(historical.items.len(), 1);
    assert_eq!(
        historical.items[0].request_lifecycle,
        ApprovalRequestLifecycleKind::Open as i32
    );
    assert_eq!(
        model
            .get_harness_approval_view("approval-01", founder_access())
            .expect("read current approval")
            .expect("approval")
            .request_lifecycle,
        ApprovalRequestLifecycleKind::Resolved as i32
    );

    let current = model.position().expect("current position");
    model
        .compact_history(current.sequence)
        .expect("advance retention floor");
    let retained = model
        .list_harness_approval_views_at(&current, &ApprovalListFilter::default(), founder_access())
        .expect("approval baseline below the floor remains readable");
    assert_eq!(retained.items.len(), 1);
    assert_eq!(
        retained.items[0].request_lifecycle,
        ApprovalRequestLifecycleKind::Resolved as i32
    );
    assert!(matches!(
        model
            .list_harness_approval_views_at(
                &first_position,
                &ApprovalListFilter::default(),
                founder_access(),
            )
            .expect_err("approval snapshot below floor must reset"),
        ProjectionFailure::SnapshotBeforeRetention { .. }
    ));
    let frames = model
        .approval_frames_after(&first_position, founder_access())
        .expect("approval watch below floor receives reset");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, StreamFrameKind::ResetRequired as i32);
    assert_eq!(
        frames[0].reset_reason_code.as_deref(),
        Some("PROJECTION_RETENTION_GAP")
    );
}

#[test]
fn projector_rejects_native_routing_from_every_producer() {
    let root = TempRoot::new("native-routing-rejected");
    let mut model = open(&root, "epoch-01");

    let mut adapter = adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11);
    let request = match adapter.observation.payload.as_mut() {
        Some(harness_observation::Payload::ApprovalRequest(request)) => request,
        _ => panic!("approval request"),
    };
    request.native_routing_ref = "codex-private://routing/never-persist".to_owned();
    adapter.metadata.payload_digest_sha256 = digest(&adapter.observation);
    assert!(matches!(
        model.apply_adapter_approval(&adapter),
        Err(ProjectionFailure::InvalidMessage)
    ));

    let mut policy = policy_input();
    policy
        .result
        .decision_record
        .as_mut()
        .and_then(|record| record.request.as_mut())
        .expect("policy request binding")
        .native_routing_ref = "codex-private://routing/never-persist".to_owned();
    policy.metadata.payload_digest_sha256 = digest(&policy.result);
    assert!(matches!(
        model.apply_policy_approval(&policy),
        Err(ProjectionFailure::InvalidMessage)
    ));
}

#[test]
fn projector_commit_survives_abort_before_owner_ack_and_replay_is_exactly_once() {
    let root = TempRoot::new("abort-before-owner-ack");
    let database = root.database();
    let status =
        Command::new(std::env::current_exe().expect("current integration test executable"))
            .arg("--exact")
            .arg("projection_crash_probe_child")
            .arg("--nocapture")
            .env("EGOPULSE_G4_08A_CRASH_PROBE", "1")
            .env("EGOPULSE_G4_08A_CRASH_DB", &database)
            .status()
            .expect("launch projection crash probe child");
    assert!(
        !status.success(),
        "crash probe must abort after projection commit"
    );

    let bytes = fs::read(&database).expect("read encrypted local read model");
    assert!(bytes.len() >= 16);
    assert_ne!(&bytes[..16], b"SQLite format 3\0");

    let mut recovered = open(&root, "epoch-01");
    assert!(recovered.integrity_is_ok().expect("integrity after abort"));
    assert!(matches!(
        recovered
            .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
            .expect("owner redelivers because ACK did not happen"),
        ProjectionApply::Replay { .. }
    ));
    let views = recovered
        .list_harness_approval_views(&ApprovalListFilter::default(), founder_access())
        .expect("list recovered projection");
    assert_eq!(views.len(), 1);
    assert_eq!(recovered.position().expect("position").sequence, 1);
}

#[test]
fn projection_crash_probe_child() {
    if std::env::var("EGOPULSE_G4_08A_CRASH_PROBE").as_deref() != Ok("1") {
        return;
    }
    let database = PathBuf::from(
        std::env::var_os("EGOPULSE_G4_08A_CRASH_DB").expect("crash probe database path"),
    );
    let mut model = LocalReadModel::open(LocalReadModelConfig {
        database_path: database,
        epoch: "epoch-01".to_owned(),
        key: LocalReadModelKey::new([41; 32]),
    })
    .expect("open crash probe read model");
    model
        .apply_adapter_approval(&adapter_input(ApprovalRequestLifecycleKind::Open, 1, 11))
        .expect("commit projection before simulated owner ACK");
    std::process::abort();
}
