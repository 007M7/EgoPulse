#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime},
};

use egopulse_client_kernel::{
    API_CONTRACT_DIGEST_SHA256, AUTHORIZATION_PROFILE_DIGEST_SHA256, ClientKernel, CommandAccess,
    ConfirmationClass, ContractProfiles, KernelError, SnapshotStreamTracker, StreamApply,
    api_contract_ref, authorization_contract_ref, client_kernel_contract_ref,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{
        ClientSurface, HarnessApprovalView, HarnessApprovalViewStreamFrame, LocalApiError,
        LocalApiErrorCode, OpenSessionResponse, ProjectionMetadata, ProjectionPosition,
        SourceDomain, SourceRevision, StreamFrameKind, TaskView, TaskViewStreamFrame,
    },
    task::v1::TaskSnapshot,
};
use prost_types::Timestamp;

fn position(epoch: &str, sequence: u64) -> ProjectionPosition {
    ProjectionPosition {
        epoch: epoch.to_owned(),
        sequence,
        projected_at: Some(Timestamp {
            seconds: 1,
            nanos: 0,
        }),
    }
}

fn response(permission_codes: Vec<&str>, now: SystemTime) -> OpenSessionResponse {
    let expires_at = now.duration_since(SystemTime::UNIX_EPOCH).unwrap() + Duration::from_secs(60);
    OpenSessionResponse {
        session_id: "session_01".to_owned(),
        authenticated_principal_id: "os-user:founder".to_owned(),
        negotiated_contract_ref: Some(api_contract_ref()),
        granted_permission_codes: permission_codes.into_iter().map(str::to_owned).collect(),
        expires_at: Some(Timestamp {
            seconds: expires_at.as_secs() as i64,
            nanos: expires_at.subsec_nanos() as i32,
        }),
        current_position: Some(position("epoch_01", 41)),
        error: None,
        client_kernel_contract_ref: Some(client_kernel_contract_ref()),
        authorization_policy_ref: Some(authorization_contract_ref()),
    }
}

fn task_view(frame_position: &ProjectionPosition, task_id: &str) -> TaskView {
    TaskView {
        metadata: Some(ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: "egopulse.localapi.v1/TaskView".to_owned(),
                version: "0.1.0".to_owned(),
                sha256: "a".repeat(64),
            }),
            position: Some(frame_position.clone()),
            source_revisions: vec![SourceRevision {
                domain: SourceDomain::Task as i32,
                aggregate_id: task_id.to_owned(),
                revision: 1,
                last_event_id: "event_01".to_owned(),
            }],
            health: 1,
            stale: false,
            safe_health_reason_code: None,
        }),
        task: Some(TaskSnapshot {
            task_id: task_id.to_owned(),
            revision: 1,
            ..TaskSnapshot::default()
        }),
        ..TaskView::default()
    }
}

fn task_frame(
    kind: i32,
    frame_position: ProjectionPosition,
    snapshot: Option<TaskView>,
) -> TaskViewStreamFrame {
    TaskViewStreamFrame {
        kind,
        position: Some(frame_position),
        snapshot,
        reset_reason_code: None,
    }
}

fn approval_frame(
    frame_position: &ProjectionPosition,
    approval_request_id: &str,
) -> HarnessApprovalViewStreamFrame {
    HarnessApprovalViewStreamFrame {
        kind: StreamFrameKind::Snapshot as i32,
        position: Some(frame_position.clone()),
        snapshot: Some(HarnessApprovalView {
            metadata: Some(ProjectionMetadata {
                schema_ref: Some(ContractReference {
                    contract_id: "egopulse.localapi.v1/HarnessApprovalView".to_owned(),
                    version: "0.1.0".to_owned(),
                    sha256: "b".repeat(64),
                }),
                position: Some(frame_position.clone()),
                source_revisions: vec![SourceRevision {
                    domain: SourceDomain::HarnessAdapter as i32,
                    aggregate_id: approval_request_id.to_owned(),
                    revision: 1,
                    last_event_id: "observation_01".to_owned(),
                }],
                health: 1,
                stale: false,
                safe_health_reason_code: None,
            }),
            approval_request_id: approval_request_id.to_owned(),
            task_id: "task_01".to_owned(),
            run_id: "run_01".to_owned(),
            step_id: "step_01".to_owned(),
            attempt_id: "attempt_01".to_owned(),
            dispatch_id: "dispatch_01".to_owned(),
            fencing_token: 1,
            action_digest_sha256: "c".repeat(64),
            request_observation_id: "observation_01".to_owned(),
            request_observation_sequence: 1,
            request_lifecycle: 1,
            request_revision: 1,
            ..HarnessApprovalView::default()
        }),
        reset_reason_code: None,
    }
}

#[test]
fn embedded_profiles_are_digest_bound_and_fail_closed_by_default() {
    let profiles = ContractProfiles::embedded().unwrap();
    assert_eq!(
        client_kernel_contract_ref().sha256,
        "0d9222fd5569ce5f7baa062d8353e9565be88da1fc55934e8cc21ba4067629e9"
    );
    assert_eq!(
        authorization_contract_ref().sha256,
        AUTHORIZATION_PROFILE_DIGEST_SHA256
    );
    assert_eq!(api_contract_ref().sha256, API_CONTRACT_DIGEST_SHA256);
    assert!(profiles.client_kernel.invariants.surface_neutral);
    assert!(
        !profiles
            .authorization
            .defaults
            .session_grant_is_final_authorization
    );
    assert!(
        profiles
            .authorization
            .defaults
            .owning_authority_revalidation_required
    );
    assert!(profiles.permission_codes().contains("local.task.read"));
    assert!(
        profiles
            .permission_codes()
            .contains("local.memory.retrieve")
    );
}

#[test]
fn all_three_surfaces_share_exactly_the_same_session_contracts() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut requests = Vec::new();
    for surface in [
        ClientSurface::Cli,
        ClientSurface::Tui,
        ClientSurface::Desktop,
    ] {
        let mut kernel = ClientKernel::new("client_01", surface).unwrap();
        let request = kernel.open_session_request("request_01").unwrap();
        let session = kernel
            .accept_open_session(
                response(vec!["local.task.read", "local.projection.await"], now),
                now,
            )
            .unwrap();
        assert_eq!(session.negotiated_contract_ref, api_contract_ref());
        assert_eq!(
            session.client_kernel_contract_ref,
            client_kernel_contract_ref()
        );
        assert_eq!(
            session.authorization_policy_ref,
            authorization_contract_ref()
        );
        requests.push(request);
    }
    assert_eq!(
        requests[0].supported_contracts,
        requests[1].supported_contracts
    );
    assert_eq!(
        requests[1].supported_contracts,
        requests[2].supported_contracts
    );
    assert_ne!(requests[0].surface, requests[1].surface);
}

#[test]
fn session_acceptance_rejects_contract_permission_and_error_ambiguity() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut kernel = ClientKernel::new("client_01", ClientSurface::Cli).unwrap();

    let mut wrong_contract = response(vec!["local.task.read"], now);
    wrong_contract
        .client_kernel_contract_ref
        .as_mut()
        .unwrap()
        .sha256 = "f".repeat(64);
    assert!(matches!(
        kernel.accept_open_session(wrong_contract, now),
        Err(KernelError::ContractMismatch("client_kernel"))
    ));

    assert!(matches!(
        kernel.accept_open_session(response(vec!["local.unknown"], now), now),
        Err(KernelError::UnknownPermission(_))
    ));
    assert!(matches!(
        kernel.accept_open_session(
            response(vec!["local.task.read", "local.task.read"], now),
            now,
        ),
        Err(KernelError::DuplicatePermission(_))
    ));

    let rejected = OpenSessionResponse {
        error: Some(LocalApiError {
            code: LocalApiErrorCode::PermissionDenied as i32,
            safe_fingerprint: "local-session/peer-not-allowed/v1".to_owned(),
            retryable: false,
            required_action_code: None,
            current_position: Some(position("epoch_01", 1)),
            correlation_id: "correlation_01".to_owned(),
        }),
        ..OpenSessionResponse::default()
    };
    assert!(matches!(
        kernel.accept_open_session(rejected, now),
        Err(KernelError::ServerRejected(error))
            if error.code == LocalApiErrorCode::PermissionDenied
    ));
}

#[test]
fn request_metadata_is_session_surface_and_contract_bound() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut kernel = ClientKernel::new("client_01", ClientSurface::Tui).unwrap();
    assert!(matches!(
        kernel.request_metadata("request_01", None, now),
        Err(KernelError::SessionUnavailable)
    ));
    kernel
        .accept_open_session(response(vec!["local.task.read"], now), now)
        .unwrap();
    let metadata = kernel
        .request_metadata("request_02", Some("correlation_02".to_owned()), now)
        .unwrap();
    assert_eq!(metadata.client_instance_id, "client_01");
    assert_eq!(metadata.surface, ClientSurface::Tui as i32);
    assert_eq!(metadata.session_id, "session_01");
    assert_eq!(metadata.api_contract_ref, Some(api_contract_ref()));
    assert!(matches!(
        kernel.request_metadata("request_03", None, now + Duration::from_secs(61)),
        Err(KernelError::SessionExpired)
    ));
}

#[test]
fn authorization_profile_allows_only_frozen_user_rpc_and_oneof_rules() {
    let profiles = ContractProfiles::embedded().unwrap();
    let read = BTreeSet::from(["local.task.read".to_owned()]);
    profiles
        .authorize_rpc("LocalReadModelService/GetTaskView", &read)
        .unwrap();
    assert!(matches!(
        profiles.authorize_rpc("LocalReadModelService/GetEvidenceGraph", &read),
        Err(KernelError::PermissionDenied(permission)) if permission == "local.evidence.read"
    ));

    let create = BTreeSet::from(["local.task.create".to_owned()]);
    let authorized = profiles
        .authorize_command(
            "LocalCommandGatewayService/ExecuteTaskCommand",
            "create_task",
            &create,
        )
        .unwrap();
    assert_eq!(authorized.write_owner, "TaskAuthority");
    assert_eq!(authorized.confirmation_class, ConfirmationClass::None);
    assert!(matches!(
        profiles.authorize_command(
            "LocalCommandGatewayService/ExecuteTaskCommand",
            "activate_task",
            &create,
        ),
        Err(KernelError::SystemOnlyCommand { .. })
    ));
    assert!(matches!(
        profiles.authorize_command(
            "LocalCommandGatewayService/ExecuteTaskCommand",
            "future_command",
            &create,
        ),
        Err(KernelError::UnknownCommandOneof { .. })
    ));

    let system_only_count = profiles
        .authorization
        .command_rules
        .iter()
        .filter(|rule| rule.access == CommandAccess::SystemOnly)
        .count();
    assert!(system_only_count > 0);
}

#[test]
fn stream_tracker_deduplicates_exact_replay_and_rejects_conflicts() {
    let mut tracker = SnapshotStreamTracker::default();
    let first_position = position("epoch_01", 10);
    let first = task_view(&first_position, "task_01");
    let first_frame = task_frame(
        StreamFrameKind::Snapshot as i32,
        first_position.clone(),
        Some(first.clone()),
    );
    assert_eq!(
        tracker.apply_task_frame(&first_frame).unwrap(),
        StreamApply::Applied
    );
    assert_eq!(
        tracker.apply_task_frame(&first_frame).unwrap(),
        StreamApply::Replay
    );
    let second = task_view(&first_position, "task_02");
    let second_frame = task_frame(
        StreamFrameKind::Snapshot as i32,
        first_position.clone(),
        Some(second),
    );
    assert_eq!(
        tracker.apply_task_frame(&second_frame).unwrap(),
        StreamApply::Applied
    );
    assert_eq!(
        tracker.apply_task_frame(&second_frame).unwrap(),
        StreamApply::Replay
    );

    let mut changed = first;
    changed.task.as_mut().unwrap().revision = 2;
    changed.metadata.as_mut().unwrap().source_revisions[0].revision = 2;
    let changed_frame = task_frame(
        StreamFrameKind::Snapshot as i32,
        first_position.clone(),
        Some(changed),
    );
    assert!(matches!(
        tracker.apply_task_frame(&changed_frame),
        Err(KernelError::ConflictingStreamReplay)
    ));

    let jumped_position = position("epoch_01", 15);
    let jumped_frame = task_frame(
        StreamFrameKind::Snapshot as i32,
        jumped_position.clone(),
        Some(task_view(&jumped_position, "task_03")),
    );
    assert_eq!(
        tracker.apply_task_frame(&jumped_frame).unwrap(),
        StreamApply::Applied
    );
    let same_position_heartbeat =
        task_frame(StreamFrameKind::Heartbeat as i32, jumped_position, None);
    assert_eq!(
        tracker.apply_task_frame(&same_position_heartbeat).unwrap(),
        StreamApply::Heartbeat
    );
    assert_eq!(
        tracker.apply_task_frame(&jumped_frame).unwrap(),
        StreamApply::Replay
    );
    let old_heartbeat = task_frame(
        StreamFrameKind::Heartbeat as i32,
        position("epoch_01", 14),
        None,
    );
    assert!(matches!(
        tracker.apply_task_frame(&old_heartbeat),
        Err(KernelError::StreamOutOfOrder)
    ));
    let new_epoch_heartbeat = task_frame(
        StreamFrameKind::Heartbeat as i32,
        position("epoch_02", 1),
        None,
    );
    assert!(matches!(
        tracker.apply_task_frame(&new_epoch_heartbeat),
        Err(KernelError::StreamResetMissing)
    ));
}

#[test]
fn reset_frame_blocks_stream_until_explicit_refetch() {
    let mut tracker = SnapshotStreamTracker::default();
    let reset = task_frame(
        StreamFrameKind::ResetRequired as i32,
        position("epoch_02", 0),
        None,
    );
    assert_eq!(
        tracker.apply_task_frame(&reset).unwrap(),
        StreamApply::ResetRequired
    );
    assert!(tracker.refetch_required());
    let blocked_position = position("epoch_02", 1);
    let blocked = task_frame(
        StreamFrameKind::Snapshot as i32,
        blocked_position.clone(),
        Some(task_view(&blocked_position, "task_01")),
    );
    assert!(matches!(
        tracker.apply_task_frame(&blocked),
        Err(KernelError::RefetchRequired)
    ));
    tracker.mark_refetched(position("epoch_02", 5)).unwrap();
    assert!(!tracker.refetch_required());
    let heartbeat = task_frame(
        StreamFrameKind::Heartbeat as i32,
        position("epoch_02", 6),
        None,
    );
    assert_eq!(
        tracker.apply_task_frame(&heartbeat).unwrap(),
        StreamApply::Heartbeat
    );
}

#[test]
fn unknown_or_incomplete_stream_frames_fail_closed() {
    let mut tracker = SnapshotStreamTracker::default();
    let unknown_position = position("epoch_01", 1);
    let unknown = task_frame(
        999,
        unknown_position.clone(),
        Some(task_view(&unknown_position, "task_01")),
    );
    assert!(matches!(
        tracker.apply_task_frame(&unknown),
        Err(KernelError::UnknownStreamFrame)
    ));
    let missing = task_frame(
        StreamFrameKind::Snapshot as i32,
        position("epoch_01", 1),
        None,
    );
    assert!(matches!(
        tracker.apply_task_frame(&missing),
        Err(KernelError::IncompleteStreamFrame)
    ));
    let heartbeat_position = position("epoch_01", 1);
    let contradictory_heartbeat = task_frame(
        StreamFrameKind::Heartbeat as i32,
        heartbeat_position.clone(),
        Some(task_view(&heartbeat_position, "task_01")),
    );
    assert!(matches!(
        tracker.apply_task_frame(&contradictory_heartbeat),
        Err(KernelError::IncompleteStreamFrame)
    ));
    let default_position = position("epoch_01", 2);
    let default_snapshot = task_frame(
        StreamFrameKind::Snapshot as i32,
        default_position,
        Some(TaskView::default()),
    );
    assert!(matches!(
        tracker.apply_task_frame(&default_snapshot),
        Err(KernelError::IncompleteStreamFrame)
    ));
}

#[test]
fn harness_approval_stream_uses_the_same_complete_snapshot_kernel() {
    let mut tracker = SnapshotStreamTracker::default();
    let frame_position = position("epoch_01", 3);
    let frame = approval_frame(&frame_position, "approval_01");
    assert_eq!(
        tracker.apply_harness_approval_frame(&frame).unwrap(),
        StreamApply::Applied
    );
    assert_eq!(
        tracker.apply_harness_approval_frame(&frame).unwrap(),
        StreamApply::Replay
    );

    let second = approval_frame(&frame_position, "approval_02");
    assert_eq!(
        tracker.apply_harness_approval_frame(&second).unwrap(),
        StreamApply::Applied
    );
    assert_eq!(
        tracker.apply_harness_approval_frame(&second).unwrap(),
        StreamApply::Replay
    );

    let mut conflicting = frame.clone();
    conflicting.snapshot.as_mut().unwrap().request_revision = 2;
    assert!(matches!(
        tracker.apply_harness_approval_frame(&conflicting),
        Err(KernelError::ConflictingStreamReplay)
    ));

    let incomplete = HarnessApprovalViewStreamFrame {
        kind: StreamFrameKind::Snapshot as i32,
        position: Some(position("epoch_01", 4)),
        snapshot: Some(HarnessApprovalView::default()),
        reset_reason_code: None,
    };
    assert!(matches!(
        tracker.apply_harness_approval_frame(&incomplete),
        Err(KernelError::IncompleteStreamFrame)
    ));
}

#[test]
fn contract_reference_helpers_are_exact_not_placeholder_values() {
    let refs = [
        api_contract_ref(),
        client_kernel_contract_ref(),
        authorization_contract_ref(),
    ];
    for reference in refs {
        assert!(!reference.contract_id.is_empty());
        assert!(!reference.version.is_empty());
        assert_eq!(reference.sha256.len(), 64);
        assert_ne!(reference, ContractReference::default());
    }
}
