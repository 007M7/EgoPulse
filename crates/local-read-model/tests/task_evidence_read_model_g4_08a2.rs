use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactCommandResult, ArtifactDescriptor, ArtifactEvent, ArtifactSet, Claim, Evidence,
    LineageBinding, Provenance,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    CollaborationCommandResult, CollaborationEvent, CollaborationSnapshot, RunSnapshot,
    collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    AvailableActionKind, ProjectionHealth, SourceDomain, SourceRevision, StreamFrameKind,
};
use egopulse_domain_contracts::v01::egopulse::task::v1::{
    CreateTaskCommand, TaskCommand, TaskEvent, TaskSnapshot, TaskStatus, task_command,
};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    FounderVerdict, FounderVerdictState, VerdictCommandResult, VerdictEvent, VerdictScope,
};
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    VerificationArtifact, VerificationBinding, VerificationCommandResult, VerificationEvent,
};
use egopulse_local_read_model::{
    ArtifactProjectionInput, CollaborationProjectionInput, EvidenceGraphAccess, LocalReadModel,
    LocalReadModelConfig, LocalReadModelKey, ProjectionFailure, ProjectionMessageMetadata,
    ProjectionMessageMode, TaskListFilter, TaskProjectionApply, TaskProjectionInput,
    TaskViewAccess, VerdictProjectionInput, VerificationProjectionInput,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const TASK_STORE_KEY: [u8; 32] = [0x63; 32];

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "egopulse-task-read-model-{name}-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&path).expect("create test root");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("read-model.db")
    }

    fn task_database(&self) -> PathBuf {
        self.0.join("task-authority.db")
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
        key: LocalReadModelKey::new([57; 32]),
    })
    .expect("open SQLCipher read model")
}

struct AcceptCreation;

impl TaskCreationGuard for AcceptCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["fixture:verified".to_owned()],
        })
    }
}

fn open_task_authority(database_path: PathBuf) -> TaskAuthority {
    TaskAuthority::open(
        TaskAuthorityConfig {
            database_path,
            store_epoch: "task-store-g4-08a2".to_owned(),
            key: SqlCipherKey::new(TASK_STORE_KEY),
        },
        AcceptCreation,
    )
    .expect("open Task Authority")
}

fn founder() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: PrincipalKind::Founder,
        principal_id: "founder:g4-08a2".to_owned(),
        authenticated: true,
    }
}

fn contract_ref(id: &str, digest_byte: char) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "1".to_owned(),
        sha256: digest_byte.to_string().repeat(64),
    }
}

fn create_task_command() -> TaskCommand {
    let mut command = TaskCommand {
        command: Some(task_command::Command::CreateTask(CreateTaskCommand {
            meta: Some(CommandMetadata {
                command_id: "command-g4-08a2-crash".to_owned(),
                idempotency_key: "idempotency-g4-08a2-crash".to_owned(),
                idempotency_scope: "founder:g4-08a2/v01".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(timestamp()),
                correlation_id: "correlation-g4-08a2-crash".to_owned(),
                causation_id: None,
            }),
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-g4-08a2".to_owned(),
            target_scope_ref: "repo-scope-g4-08a2".to_owned(),
            acceptance_contract_ref: Some(contract_ref("acceptance-g4-08a2", 'a')),
            budget_profile_ref: Some(contract_ref("budget-g4-08a2", 'b')),
        })),
    };
    let request_digest = canonical_request_digest(&command).expect("canonical Task digest");
    let Some(task_command::Command::CreateTask(create)) = command.command.as_mut() else {
        unreachable!()
    };
    create
        .meta
        .as_mut()
        .expect("Task command metadata")
        .request_digest_sha256 = request_digest;
    command
}

fn owner_task_input(
    message: &egopulse_cognition_runtime::task_authority::TaskProjectionMessage,
) -> TaskProjectionInput {
    TaskProjectionInput {
        metadata: ProjectionMessageMetadata {
            message_id: message.message_id.clone(),
            source_event_id: message.source_event_id.clone(),
            source_revision: message.source_revision,
            mode: ProjectionMessageMode::Incremental,
            payload_digest_sha256: message.payload_digest_sha256.clone(),
            projected_at: timestamp(),
        },
        event: message.event.clone(),
    }
}

fn access() -> TaskViewAccess {
    TaskViewAccess {
        can_read: true,
        can_request_cancellation: true,
        can_resume: true,
        can_revise: true,
        can_issue_founder_verdict: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn task_input(
    revision: u64,
    status: TaskStatus,
    run_id: Option<&str>,
    artifact_set_id: Option<&str>,
    verification_artifact_id: Option<&str>,
    founder_verdict_id: Option<&str>,
) -> TaskProjectionInput {
    let event_id = format!("task-event-{revision:02}");
    let snapshot = TaskSnapshot {
        task_id: "task-01".to_owned(),
        revision,
        work_revision: 1,
        status: status as i32,
        current_run_id: run_id.map(str::to_owned),
        artifact_set_id: artifact_set_id.map(str::to_owned),
        verification_artifact_id: verification_artifact_id.map(str::to_owned),
        founder_verdict_id: founder_verdict_id.map(str::to_owned),
        ..Default::default()
    };
    let event = TaskEvent {
        event_id: event_id.clone(),
        task_id: snapshot.task_id.clone(),
        resulting_revision: revision,
        work_revision: 1,
        snapshot: Some(snapshot),
        ..Default::default()
    };
    TaskProjectionInput {
        metadata: metadata(&event_id, revision, &event),
        event,
    }
}

fn ordered_task_input(
    task_id: &str,
    revision: u64,
    status: TaskStatus,
    updated_at_seconds: i64,
) -> TaskProjectionInput {
    let event_id = format!("{task_id}-event-{revision:02}");
    let snapshot = TaskSnapshot {
        task_id: task_id.to_owned(),
        revision,
        work_revision: 1,
        status: status as i32,
        created_at: Some(Timestamp {
            seconds: NOW,
            nanos: 0,
        }),
        updated_at: Some(Timestamp {
            seconds: updated_at_seconds,
            nanos: 0,
        }),
        ..Default::default()
    };
    let event = TaskEvent {
        event_id: event_id.clone(),
        task_id: task_id.to_owned(),
        resulting_revision: revision,
        work_revision: 1,
        snapshot: Some(snapshot),
        ..Default::default()
    };
    TaskProjectionInput {
        metadata: metadata(&event_id, revision, &event),
        event,
    }
}

fn collaboration_input() -> CollaborationProjectionInput {
    let event_id = "collaboration-event-01";
    let snapshot = CollaborationSnapshot {
        run: Some(RunSnapshot {
            run_id: "run-01".to_owned(),
            revision: 1,
            task_id: "task-01".to_owned(),
            work_revision: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    let event = CollaborationEvent {
        event_id: event_id.to_owned(),
        run_id: "run-01".to_owned(),
        resulting_run_revision: 1,
        ..Default::default()
    };
    let result = CollaborationCommandResult {
        outcome: Some(collaboration_command_result::Outcome::Snapshot(snapshot)),
        committed_event: Some(event),
        ..Default::default()
    };
    CollaborationProjectionInput {
        metadata: metadata(event_id, 1, &result),
        result,
    }
}

fn lineage(task_id: &str) -> LineageBinding {
    LineageBinding {
        task_id: task_id.to_owned(),
        task_revision: 3,
        work_revision: 1,
        run_id: "run-01".to_owned(),
        run_revision: 1,
        ..Default::default()
    }
}

fn artifact_result(kind: &str, object_id: &str, task_id: &str) -> ArtifactProjectionInput {
    let event_id = format!("artifact-event-{object_id}");
    let mut result = ArtifactCommandResult {
        committed: true,
        event: Some(ArtifactEvent {
            event_id: event_id.clone(),
            aggregate_id: object_id.to_owned(),
            aggregate_revision: 1,
            lineage: Some(lineage(task_id)),
            ..Default::default()
        }),
        ..Default::default()
    };
    match kind {
        "artifact" => {
            result.artifact = Some(ArtifactDescriptor {
                artifact_id: object_id.to_owned(),
                revision: 1,
                provenance: Some(Provenance {
                    lineage: Some(lineage(task_id)),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        "claim" => {
            result.claim = Some(Claim {
                claim_id: object_id.to_owned(),
                revision: 1,
                lineage: Some(lineage(task_id)),
                ..Default::default()
            });
        }
        "evidence" => {
            result.evidence = Some(Evidence {
                evidence_id: object_id.to_owned(),
                revision: 1,
                lineage: Some(lineage(task_id)),
                ..Default::default()
            });
        }
        "artifact_set" => {
            result.artifact_set = Some(ArtifactSet {
                artifact_set_id: object_id.to_owned(),
                revision: 1,
                lineage: Some(lineage(task_id)),
                artifact_ids: vec!["artifact-01".to_owned()],
                claim_ids: vec!["claim-01".to_owned()],
                evidence_ids: vec!["evidence-01".to_owned()],
                ..Default::default()
            });
        }
        _ => panic!("unsupported fixture kind"),
    }
    ArtifactProjectionInput {
        metadata: metadata(&event_id, 1, &result),
        result,
    }
}

fn verification_input() -> VerificationProjectionInput {
    let event_id = "verification-event-01";
    let result = VerificationCommandResult {
        committed: true,
        artifact: Some(VerificationArtifact {
            verification_artifact_id: "verification-artifact-01".to_owned(),
            version: 1,
            binding: Some(VerificationBinding {
                lineage: Some(lineage("task-01")),
                artifact_set_id: "artifact-set-01".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        event: Some(VerificationEvent {
            event_id: event_id.to_owned(),
            aggregate_id: "verification-artifact-01".to_owned(),
            aggregate_revision: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    VerificationProjectionInput {
        metadata: metadata(event_id, 1, &result),
        result,
    }
}

fn verdict_input() -> VerdictProjectionInput {
    let event_id = "verdict-event-01";
    let result = VerdictCommandResult {
        committed: true,
        verdict: Some(FounderVerdict {
            founder_verdict_id: "verdict-01".to_owned(),
            version: 1,
            scope: Some(VerdictScope {
                task_id: "task-01".to_owned(),
                task_revision: 4,
                work_revision: 1,
                artifact_set_id: "artifact-set-01".to_owned(),
                verification_artifact_id: "verification-artifact-01".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        state: Some(FounderVerdictState {
            founder_verdict_id: "verdict-01".to_owned(),
            revision: 1,
            ..Default::default()
        }),
        event: Some(VerdictEvent {
            event_id: event_id.to_owned(),
            founder_verdict_id: "verdict-01".to_owned(),
            resulting_state_revision: 1,
            ..Default::default()
        }),
        ..Default::default()
    };
    VerdictProjectionInput {
        metadata: metadata(event_id, 1, &result),
        result,
    }
}

#[test]
fn projects_complete_task_and_evidence_chain_from_typed_owner_results() {
    let root = TempRoot::new("full-chain");
    let mut model = open(&root, "epoch-01");

    model
        .apply_task(&task_input(1, TaskStatus::Ready, None, None, None, None))
        .expect("task created");
    model
        .apply_task(&task_input(
            2,
            TaskStatus::Active,
            Some("run-01"),
            None,
            None,
            None,
        ))
        .expect("task active");
    let pending = model
        .get_task_view("task-01", access())
        .expect("get task")
        .expect("task view");
    assert!(pending.metadata.expect("metadata").stale);

    model
        .apply_collaboration(&collaboration_input())
        .expect("collaboration projected");
    model
        .apply_artifact(&artifact_result(
            "artifact_set",
            "artifact-set-01",
            "task-01",
        ))
        .expect("ArtifactSet projected before members");
    model
        .apply_task(&task_input(
            3,
            TaskStatus::VerificationPending,
            Some("run-01"),
            Some("artifact-set-01"),
            None,
            None,
        ))
        .expect("evidence linked before member projections");
    let pending_graph = model
        .get_evidence_graph(
            "task-01",
            "artifact-set-01",
            EvidenceGraphAccess { can_read: true },
        )
        .expect("get pending graph")
        .expect("stale graph remains visible");
    let pending_metadata = pending_graph.metadata.expect("pending graph metadata");
    assert!(pending_metadata.stale);
    assert_eq!(
        pending_metadata.safe_health_reason_code.as_deref(),
        Some("DEPENDENCY_PROJECTION_PENDING")
    );
    assert!(pending_graph.artifacts.is_empty());
    assert!(pending_graph.claims.is_empty());
    assert!(pending_graph.evidence.is_empty());
    assert!(
        model
            .get_task_view("task-01", access())
            .expect("get pending Task")
            .expect("pending Task")
            .metadata
            .expect("pending Task metadata")
            .stale
    );

    for input in [
        artifact_result("artifact", "artifact-01", "task-01"),
        artifact_result("claim", "claim-01", "task-01"),
        artifact_result("evidence", "evidence-01", "task-01"),
    ] {
        model.apply_artifact(&input).expect("artifact projected");
    }
    let graph = model
        .get_evidence_graph(
            "task-01",
            "artifact-set-01",
            EvidenceGraphAccess { can_read: true },
        )
        .expect("get graph")
        .expect("graph");
    assert_eq!(graph.artifacts.len(), 1);
    assert_eq!(graph.claims.len(), 1);
    assert_eq!(graph.evidence.len(), 1);
    assert_eq!(graph.metadata.expect("metadata").source_revisions.len(), 4);

    model
        .apply_verification(&verification_input())
        .expect("verification projected");
    model
        .apply_task(&task_input(
            4,
            TaskStatus::VerdictPending,
            Some("run-01"),
            Some("artifact-set-01"),
            Some("verification-artifact-01"),
            None,
        ))
        .expect("verification linked");
    let verdict_pending = model
        .get_task_view("task-01", access())
        .expect("get task")
        .expect("task view");
    assert!(
        verdict_pending
            .available_actions
            .iter()
            .any(|action| { action.kind == AvailableActionKind::SubmitFounderVerdict as i32 })
    );

    model
        .apply_verdict(&verdict_input())
        .expect("verdict projected");
    model
        .apply_task(&task_input(
            5,
            TaskStatus::Completed,
            Some("run-01"),
            Some("artifact-set-01"),
            Some("verification-artifact-01"),
            Some("verdict-01"),
        ))
        .expect("verdict linked");
    let complete = model
        .get_task_view("task-01", access())
        .expect("get task")
        .expect("task view");
    let metadata = complete.metadata.expect("metadata");
    assert!(!metadata.stale);
    assert_eq!(metadata.source_revisions.len(), 5);
    assert!(complete.collaboration.is_some());
    assert!(complete.artifact_set.is_some());
    assert!(complete.verification.is_some());
    assert!(complete.founder_verdict.is_some());
    assert!(complete.founder_verdict_state.is_some());
    assert!(complete.available_actions.is_empty());

    let listed = model
        .list_task_views(
            &TaskListFilter {
                statuses: vec![TaskStatus::Completed as i32],
            },
            access(),
        )
        .expect("list task views");
    assert_eq!(listed.len(), 1);
}

#[test]
fn duplicate_replays_and_revision_gap_fail_closed() {
    let root = TempRoot::new("revision");
    let mut model = open(&root, "epoch-01");
    let created = task_input(1, TaskStatus::Ready, None, None, None, None);
    model.apply_task(&created).expect("first projection");
    assert!(matches!(
        model.apply_task(&created).expect("idempotent replay"),
        TaskProjectionApply::Replay { .. }
    ));

    let failure = model
        .apply_task(&task_input(3, TaskStatus::Active, None, None, None, None))
        .expect_err("gap rejected");
    assert!(matches!(failure, ProjectionFailure::StaleSourceRevision));
    assert_eq!(
        model.health().expect("projection health"),
        ProjectionHealth::IntegrityFailed
    );
}

#[test]
fn mismatched_owner_lineage_is_never_joined() {
    let root = TempRoot::new("lineage");
    let mut model = open(&root, "epoch-01");
    model
        .apply_task(&task_input(1, TaskStatus::Ready, None, None, None, None))
        .expect("task created");
    model
        .apply_artifact(&artifact_result(
            "artifact_set",
            "artifact-set-01",
            "task-other",
        ))
        .expect("foreign set projected independently");
    let failure = model
        .apply_task(&task_input(
            2,
            TaskStatus::VerificationPending,
            None,
            Some("artifact-set-01"),
            None,
            None,
        ))
        .expect_err("cross-task join rejected");
    assert!(matches!(failure, ProjectionFailure::IntegrityFailure));
    assert_eq!(
        model.health().expect("projection health"),
        ProjectionHealth::IntegrityFailed
    );
}

#[test]
fn rebuild_baseline_accepts_non_initial_revision_only_while_rebuilding() {
    let root = TempRoot::new("baseline");
    let mut model = open(&root, "epoch-01");
    model.reset_for_rebuild("epoch-02").expect("reset");
    let mut baseline = task_input(8, TaskStatus::Held, None, None, None, None);
    baseline.metadata.mode = ProjectionMessageMode::RebuildBaseline;
    model.apply_task(&baseline).expect("baseline projected");

    let rebuilding = model
        .get_task_view("task-01", access())
        .expect("get rebuilding view")
        .expect("task view");
    let metadata = rebuilding.metadata.expect("metadata");
    assert_eq!(metadata.health, ProjectionHealth::Rebuilding as i32);
    assert!(metadata.stale);
    assert!(rebuilding.available_actions.is_empty());

    model.mark_rebuild_ready().expect("finish rebuild");
    let ready = model
        .get_task_view("task-01", access())
        .expect("get ready view")
        .expect("task view");
    assert!(
        ready
            .available_actions
            .iter()
            .any(|action| { action.kind == AvailableActionKind::ResumeTask as i32 })
    );

    let root = TempRoot::new("baseline-outside-rebuild");
    let mut normal = open(&root, "epoch-01");
    assert!(matches!(
        normal.apply_task(&baseline).expect_err("baseline rejected"),
        ProjectionFailure::RebuildBaselineNotAllowed
    ));
}

#[test]
fn permissions_source_wait_and_epoch_reset_are_enforced() {
    let root = TempRoot::new("surface-guards");
    let mut model = open(&root, "epoch-01");
    let created = task_input(1, TaskStatus::Ready, None, None, None, None);
    model.apply_task(&created).expect("task projected");
    assert!(matches!(
        model
            .get_task_view("task-01", TaskViewAccess::default())
            .expect_err("read denied"),
        ProjectionFailure::PermissionDenied
    ));
    let required = SourceRevision {
        domain: SourceDomain::Task as i32,
        aggregate_id: "task-01".to_owned(),
        revision: 1,
        last_event_id: "task-event-01".to_owned(),
    };
    assert!(
        model
            .has_projected_source(&required)
            .expect("source wait check")
    );
    let mut tampered = required.clone();
    tampered.aggregate_id = "task-other".to_owned();
    assert!(
        !model
            .has_projected_source(&tampered)
            .expect("tampered aggregate is not projected")
    );

    model
        .apply_task(&task_input(2, TaskStatus::Active, None, None, None, None))
        .expect("advance Task projection");
    assert!(
        model
            .has_projected_source(&required)
            .expect("older committed await token remains satisfied")
    );

    let old = model.position().expect("old position");
    model.reset_for_rebuild("epoch-02").expect("reset");
    let frames = model
        .task_frames_after(&old, &TaskListFilter::default(), &[], access())
        .expect("watch reset");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, StreamFrameKind::ResetRequired as i32);
}

#[test]
fn historical_task_snapshot_is_stable_until_retention_floor_advances() {
    let root = TempRoot::new("historical-task-page");
    let mut model = open(&root, "epoch-01");
    let first = model
        .apply_task(&ordered_task_input("task-01", 1, TaskStatus::Ready, NOW))
        .expect("project first Task revision");
    let first_position = match first {
        TaskProjectionApply::Committed { position, .. } => position,
        TaskProjectionApply::Replay { .. } => panic!("first Task revision must commit"),
    };
    model
        .apply_task(&ordered_task_input(
            "task-01",
            2,
            TaskStatus::Active,
            NOW + 20,
        ))
        .expect("project second Task revision");
    model
        .apply_task(&ordered_task_input(
            "task-02",
            1,
            TaskStatus::Ready,
            NOW + 10,
        ))
        .expect("project unrelated Task after the snapshot");

    let historical = model
        .list_task_views_at(&first_position, &TaskListFilter::default(), access())
        .expect("read stable historical Task snapshot");
    assert_eq!(historical.snapshot_position, first_position);
    assert_eq!(historical.retention_floor.sequence, 0);
    assert_eq!(historical.items.len(), 1);
    assert_eq!(historical.items[0].task.as_ref().expect("task").revision, 1);
    let current_items = model
        .list_task_views(&TaskListFilter::default(), access())
        .expect("read current Task snapshot");
    assert_eq!(current_items.len(), 2);
    assert_eq!(
        current_items[0].task.as_ref().expect("task").task_id,
        "task-01"
    );
    assert_eq!(current_items[0].task.as_ref().expect("task").revision, 2);

    let current = model.position().expect("current position");
    let floor = model
        .compact_history(current.sequence)
        .expect("compact with caller-selected floor");
    assert_eq!(floor.sequence, current.sequence);
    let retained = model
        .list_task_views_at(&current, &TaskListFilter::default(), access())
        .expect("baseline at retention floor remains readable");
    assert_eq!(retained.items.len(), 2);
    assert_eq!(
        retained.items[0].task.as_ref().expect("task").task_id,
        "task-01"
    );
    assert_eq!(retained.items[0].task.as_ref().expect("task").revision, 2);
    assert!(matches!(
        model
            .list_task_views_at(&first_position, &TaskListFilter::default(), access())
            .expect_err("snapshot below floor must reset"),
        ProjectionFailure::SnapshotBeforeRetention { .. }
    ));
    let frames = model
        .task_frames_after(&first_position, &TaskListFilter::default(), &[], access())
        .expect("watch below floor receives reset");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, StreamFrameKind::ResetRequired as i32);
    assert_eq!(
        frames[0].reset_reason_code.as_deref(),
        Some("PROJECTION_RETENTION_GAP")
    );
}

#[test]
fn task_owner_redelivery_after_projector_abort_is_exactly_once_then_acknowledged() {
    let root = TempRoot::new("owner-abort-before-ack");
    let status =
        Command::new(std::env::current_exe().expect("current integration test executable"))
            .arg("--exact")
            .arg("task_projection_crash_probe_child")
            .arg("--nocapture")
            .env("EGOPULSE_G4_08A2_CRASH_PROBE", "1")
            .env("EGOPULSE_G4_08A2_TASK_DB", root.task_database())
            .env("EGOPULSE_G4_08A2_READ_DB", root.database())
            .status()
            .expect("launch projection crash probe child");
    assert!(
        !status.success(),
        "child must abort after projector commit and before Owner ACK"
    );

    let mut owner = open_task_authority(root.task_database());
    let pending = owner
        .drain_projection_outbox()
        .expect("Owner redelivers unacknowledged projection");
    assert_eq!(pending.len(), 1);

    let mut recovered = open(&root, "epoch-01");
    assert!(recovered.integrity_is_ok().expect("read model integrity"));
    assert!(matches!(
        recovered
            .apply_task(&owner_task_input(&pending[0]))
            .expect("idempotent Owner redelivery"),
        TaskProjectionApply::Replay { .. }
    ));
    assert_eq!(
        recovered
            .list_task_views(&TaskListFilter::default(), access())
            .expect("list recovered Task views")
            .len(),
        1
    );
    assert_eq!(
        recovered.position().expect("projection position").sequence,
        1
    );

    assert!(
        owner
            .acknowledge_projection(&pending[0].message_id, &pending[0].payload_digest_sha256)
            .expect("digest-bound Owner ACK")
    );
    assert!(
        owner
            .drain_projection_outbox()
            .expect("projection feed after ACK")
            .is_empty()
    );
}

#[test]
fn task_projection_crash_probe_child() {
    if std::env::var("EGOPULSE_G4_08A2_CRASH_PROBE").as_deref() != Ok("1") {
        return;
    }
    let task_database =
        PathBuf::from(std::env::var_os("EGOPULSE_G4_08A2_TASK_DB").expect("Task database path"));
    let read_database = PathBuf::from(
        std::env::var_os("EGOPULSE_G4_08A2_READ_DB").expect("read model database path"),
    );
    let mut owner = open_task_authority(task_database);
    owner
        .execute(&create_task_command(), &founder())
        .expect("commit Task Authority fact");
    let pending = owner
        .drain_projection_outbox()
        .expect("drain committed Task projection");
    assert_eq!(pending.len(), 1);

    let mut projector = LocalReadModel::open(LocalReadModelConfig {
        database_path: read_database,
        epoch: "epoch-01".to_owned(),
        key: LocalReadModelKey::new([57; 32]),
    })
    .expect("open read model crash probe");
    projector
        .apply_task(&owner_task_input(&pending[0]))
        .expect("commit projector before Owner ACK");
    std::process::abort();
}
