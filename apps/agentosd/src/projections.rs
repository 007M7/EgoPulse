use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::ArtifactProjectionMessage;
use egopulse_cognition_runtime::task_authority::TaskProjectionMessage;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition;
use egopulse_founder_verdict_authority::VerdictProjectionMessage;
use egopulse_harness_adapter::{AdapterEdge, PendingAdapterApprovalProjection};
use egopulse_local_api::read_model_reader::ProjectionCommitNotifier;
use egopulse_local_ide_control::collaboration_control::PendingCollaborationProjection;
use egopulse_local_read_model::{
    AdapterApprovalProjectionInput, ArtifactProjectionInput, CollaborationProjectionInput,
    LocalReadModel, PolicyApprovalProjectionInput, ProjectionFailure, ProjectionMessageMetadata,
    ProjectionMessageMode, TaskProjectionInput, VerdictProjectionInput,
    VerificationProjectionInput,
};
use egopulse_policy_decision_authority::PendingPolicyProjection;
use egopulse_verification_authority::VerificationProjectionMessage;
use thiserror::Error;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub enum PendingOwnerProjection {
    Collaboration(Box<PendingCollaborationProjection>),
    AdapterApproval(Box<PendingAdapterApprovalProjection>),
    Task(Box<TaskProjectionMessage>),
    Policy(Box<PendingPolicyProjection>),
    Artifact(Box<ArtifactProjectionMessage>),
    Verification(Box<VerificationProjectionMessage>),
    Verdict(Box<VerdictProjectionMessage>),
}

#[derive(Debug, Error)]
pub enum ProjectionSourceFailure {
    #[error("collaboration projection source is unavailable")]
    Collaboration,
    #[error("harness adapter projection source is unavailable")]
    AdapterApproval,
    #[error("task projection source is unavailable")]
    Task,
    #[error("policy projection source is unavailable")]
    Policy,
    #[error("artifact projection source is unavailable")]
    Artifact,
    #[error("verification projection source is unavailable")]
    Verification,
    #[error("verdict projection source is unavailable")]
    Verdict,
    #[error("projection acknowledgement was not accepted by the owner")]
    Acknowledgement,
}

pub trait OwnerProjectionSource: Send + Sync + 'static {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure>;

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure>;
}

/// Joins independent owner feeds without giving the projector access to any
/// owner's private store. Each child source retains its own ACK authority.
pub struct CompositeOwnerProjectionSource {
    sources: Vec<Arc<dyn OwnerProjectionSource>>,
}

impl CompositeOwnerProjectionSource {
    #[must_use]
    pub fn new(sources: Vec<Arc<dyn OwnerProjectionSource>>) -> Self {
        Self { sources }
    }
}

impl OwnerProjectionSource for CompositeOwnerProjectionSource {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.sources.iter().try_fold(Vec::new(), |mut all, source| {
            all.extend(source.pending()?);
            Ok(all)
        })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        for source in &self.sources {
            if source.acknowledge(message)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub struct CollaborationProjectionSource<G, C> {
    owner: Mutex<egopulse_local_ide_control::collaboration_control::CollaborationControl<G, C>>,
}

impl<G, C> CollaborationProjectionSource<G, C> {
    #[must_use]
    pub fn new(
        owner: egopulse_local_ide_control::collaboration_control::CollaborationControl<G, C>,
    ) -> Self {
        Self {
            owner: Mutex::new(owner),
        }
    }
}

impl<G, C> OwnerProjectionSource for CollaborationProjectionSource<G, C>
where
    G: egopulse_local_ide_control::collaboration_control::CollaborationReferenceGuard
        + egopulse_local_ide_control::collaboration_control::HarnessEvidenceResolver
        + Send
        + 'static,
    C: egopulse_local_ide_control::collaboration_control::AuthorityClock + Send + 'static,
{
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Collaboration)?
            .pending_projection_messages()
            .map_err(|_| ProjectionSourceFailure::Collaboration)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| PendingOwnerProjection::Collaboration(Box::new(message)))
                    .collect()
            })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let PendingOwnerProjection::Collaboration(message) = message else {
            return Ok(false);
        };
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Collaboration)?
            .acknowledge_projection_message(
                &message.message_id,
                &message.canonical_payload_digest_sha256,
            )
            .map_err(|_| ProjectionSourceFailure::Collaboration)
    }
}

pub struct AdapterApprovalProjectionSource<R, D, C> {
    owner: Mutex<egopulse_harness_adapter::GovernedHarnessAdapter<R, D, C>>,
}

/// Projects approval observations through a read/ACK-only Adapter Edge handle
/// when the live governed adapter is owned by the dispatch runner. This keeps
/// projection access separate from native driver/session ownership.
pub struct AdapterEdgeApprovalProjectionSource {
    edge: Mutex<AdapterEdge>,
}

impl AdapterEdgeApprovalProjectionSource {
    #[must_use]
    pub fn new(edge: AdapterEdge) -> Self {
        Self {
            edge: Mutex::new(edge),
        }
    }
}

impl OwnerProjectionSource for AdapterEdgeApprovalProjectionSource {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.edge
            .lock()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)?
            .pending_approval_projection_messages()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| PendingOwnerProjection::AdapterApproval(Box::new(message)))
                    .collect()
            })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let PendingOwnerProjection::AdapterApproval(message) = message else {
            return Ok(false);
        };
        self.edge
            .lock()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)?
            .acknowledge_approval_projection_message(
                &message.message_id,
                &message.payload_digest_sha256,
            )
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)
    }
}

impl<R, D, C> AdapterApprovalProjectionSource<R, D, C> {
    #[must_use]
    pub fn new(owner: egopulse_harness_adapter::GovernedHarnessAdapter<R, D, C>) -> Self {
        Self {
            owner: Mutex::new(owner),
        }
    }
}

impl<R, D, C> OwnerProjectionSource for AdapterApprovalProjectionSource<R, D, C>
where
    R: egopulse_harness_adapter::DispatchMaterialResolver + Send + 'static,
    D: egopulse_harness_adapter::NativeHarnessDriver + Send + 'static,
    C: egopulse_harness_adapter::AdapterClock + Send + 'static,
{
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)?
            .pending_approval_projection_messages()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| PendingOwnerProjection::AdapterApproval(Box::new(message)))
                    .collect()
            })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let PendingOwnerProjection::AdapterApproval(message) = message else {
            return Ok(false);
        };
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)?
            .acknowledge_approval_projection_message(
                &message.message_id,
                &message.payload_digest_sha256,
            )
            .map_err(|_| ProjectionSourceFailure::AdapterApproval)
    }
}

pub struct ArtifactProjectionSource<G, C> {
    owner: Arc<Mutex<egopulse_artifact_authority::ArtifactAuthority<G, C>>>,
}

impl<G, C> ArtifactProjectionSource<G, C> {
    #[must_use]
    pub fn new(owner: egopulse_artifact_authority::ArtifactAuthority<G, C>) -> Self {
        Self::new_shared(Arc::new(Mutex::new(owner)))
    }

    #[must_use]
    pub fn new_shared(
        owner: Arc<Mutex<egopulse_artifact_authority::ArtifactAuthority<G, C>>>,
    ) -> Self {
        Self { owner }
    }
}

impl<G, C> OwnerProjectionSource for ArtifactProjectionSource<G, C>
where
    G: egopulse_artifact_authority::ArtifactAdmissionGuard + Send + 'static,
    C: egopulse_artifact_authority::ArtifactClock + Send + 'static,
{
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Artifact)?
            .drain_projection_outbox()
            .map_err(|_| ProjectionSourceFailure::Artifact)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| PendingOwnerProjection::Artifact(Box::new(message)))
                    .collect()
            })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let PendingOwnerProjection::Artifact(message) = message else {
            return Ok(false);
        };
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Artifact)?
            .acknowledge_projection(&message.message_id, &message.payload_digest_sha256)
            .map_err(|_| ProjectionSourceFailure::Artifact)
    }
}

pub struct VerificationProjectionSource<C> {
    owner: Arc<Mutex<egopulse_verification_authority::VerificationAuthority<C>>>,
}

impl<C> VerificationProjectionSource<C> {
    #[must_use]
    pub fn new(owner: egopulse_verification_authority::VerificationAuthority<C>) -> Self {
        Self::new_shared(Arc::new(Mutex::new(owner)))
    }

    #[must_use]
    pub fn new_shared(
        owner: Arc<Mutex<egopulse_verification_authority::VerificationAuthority<C>>>,
    ) -> Self {
        Self { owner }
    }
}

impl<C> OwnerProjectionSource for VerificationProjectionSource<C>
where
    C: egopulse_verification_authority::VerificationClock + Send,
{
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Verification)?
            .drain_projection_outbox()
            .map_err(|_| ProjectionSourceFailure::Verification)
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| PendingOwnerProjection::Verification(Box::new(message)))
                    .collect()
            })
    }

    fn acknowledge(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<bool, ProjectionSourceFailure> {
        let PendingOwnerProjection::Verification(message) = message else {
            return Ok(false);
        };
        self.owner
            .lock()
            .map_err(|_| ProjectionSourceFailure::Verification)?
            .acknowledge_projection(&message.message_id, &message.payload_digest_sha256)
            .map_err(|_| ProjectionSourceFailure::Verification)
    }
}

#[derive(Debug, Error)]
pub enum ProjectionPumpFailure {
    #[error(transparent)]
    Source(#[from] ProjectionSourceFailure),
    #[error("local read model rejected an owner projection")]
    ReadModel(#[source] ProjectionFailure),
}

pub struct ProjectionPump {
    model: Arc<Mutex<LocalReadModel>>,
    notifier: ProjectionCommitNotifier,
    source: Arc<dyn OwnerProjectionSource>,
}

impl ProjectionPump {
    #[must_use]
    pub fn new(
        model: Arc<Mutex<LocalReadModel>>,
        notifier: ProjectionCommitNotifier,
        source: Arc<dyn OwnerProjectionSource>,
    ) -> Self {
        Self {
            model,
            notifier,
            source,
        }
    }

    pub fn pump_once(&self) -> Result<usize, ProjectionPumpFailure> {
        let messages = self.source.pending()?;
        let mut applied = 0;
        for message in messages {
            let position = self.apply(&message)?;
            if !self.source.acknowledge(&message)? {
                return Err(ProjectionPumpFailure::Source(
                    ProjectionSourceFailure::Acknowledgement,
                ));
            }
            self.notifier.publish(position);
            applied += 1;
        }
        Ok(applied)
    }

    pub async fn run(self, mut stop: watch::Receiver<bool>) -> Result<(), ProjectionPumpFailure> {
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            let applied = self.pump_once()?;
            if applied == 0 {
                tokio::select! {
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            return Ok(());
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                }
            }
        }
    }

    fn apply(
        &self,
        message: &PendingOwnerProjection,
    ) -> Result<ProjectionPosition, ProjectionPumpFailure> {
        let projected_at = now_timestamp();
        let mut model = self
            .model
            .lock()
            .map_err(|_| ProjectionPumpFailure::ReadModel(ProjectionFailure::IntegrityFailure))?;
        match message {
            PendingOwnerProjection::Collaboration(message) => {
                model
                    .apply_collaboration(&CollaborationProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: if message.rebuild_baseline {
                                ProjectionMessageMode::RebuildBaseline
                            } else {
                                ProjectionMessageMode::Incremental
                            },
                            payload_digest_sha256: message
                                .canonical_payload_digest_sha256
                                .clone(),
                            projected_at,
                        },
                        result: egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationCommandResult {
                            replayed: false,
                            committed_event: Some(message.event.clone()),
                            outcome: Some(
                                egopulse_domain_contracts::v01::egopulse::collaboration::v1::collaboration_command_result::Outcome::Snapshot(
                                    message.snapshot.clone(),
                                ),
                            ),
                        },
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::AdapterApproval(message) => {
                model
                    .apply_adapter_approval(&AdapterApprovalProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_observation_id.clone(),
                            source_revision: message.source_revision,
                            mode: ProjectionMessageMode::Incremental,
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        run_id: message.run_id.clone(),
                        step_id: message.step_id.clone(),
                        attempt_id: message.attempt_id.clone(),
                        dispatch_id: message.dispatch_id.clone(),
                        fencing_token: message.fencing_token,
                        observation: message.observation.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::Task(message) => {
                model
                    .apply_task(&TaskProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: ProjectionMessageMode::Incremental,
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        event: message.event.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::Policy(message) => {
                model
                    .apply_policy_approval(&PolicyApprovalProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: if message.rebuild_baseline {
                                ProjectionMessageMode::RebuildBaseline
                            } else {
                                ProjectionMessageMode::Incremental
                            },
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        result: message.result.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::Artifact(message) => {
                model
                    .apply_artifact(&ArtifactProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: ProjectionMessageMode::Incremental,
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        result: message.result.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::Verification(message) => {
                model
                    .apply_verification(&VerificationProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: ProjectionMessageMode::Incremental,
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        result: message.result.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
            PendingOwnerProjection::Verdict(message) => {
                model
                    .apply_verdict(&VerdictProjectionInput {
                        metadata: ProjectionMessageMetadata {
                            message_id: message.message_id.clone(),
                            source_event_id: message.source_event_id.clone(),
                            source_revision: message.source_revision,
                            mode: ProjectionMessageMode::Incremental,
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            projected_at,
                        },
                        result: message.result.clone(),
                    })
                    .map_err(ProjectionPumpFailure::ReadModel)?;
            }
        }
        model.position().map_err(ProjectionPumpFailure::ReadModel)
    }
}

fn now_timestamp() -> prost_types::Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        collaboration::v1::{
            CollaborationEvent, CollaborationSnapshot, RunSnapshot, RunStatus, StepSnapshot,
            StepStatus, collaboration_command_result,
        },
        task::v1::{TaskEvent, TaskSnapshot, TaskStatus},
    };
    use prost::Message;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use uuid::Uuid;

    struct FixtureSource {
        messages: Vec<PendingOwnerProjection>,
        acknowledgements: AtomicUsize,
        accepted_prefix: Option<&'static str>,
    }

    fn projection_message_id(message: &PendingOwnerProjection) -> &str {
        match message {
            PendingOwnerProjection::Collaboration(message) => &message.message_id,
            PendingOwnerProjection::AdapterApproval(message) => &message.message_id,
            PendingOwnerProjection::Task(message) => &message.message_id,
            PendingOwnerProjection::Policy(message) => &message.message_id,
            PendingOwnerProjection::Artifact(message) => &message.message_id,
            PendingOwnerProjection::Verification(message) => &message.message_id,
            PendingOwnerProjection::Verdict(message) => &message.message_id,
        }
    }

    impl OwnerProjectionSource for FixtureSource {
        fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
            Ok(self.messages.clone())
        }

        fn acknowledge(
            &self,
            message: &PendingOwnerProjection,
        ) -> Result<bool, ProjectionSourceFailure> {
            let accepted = self
                .accepted_prefix
                .is_none_or(|prefix| projection_message_id(message).starts_with(prefix));
            if accepted {
                self.acknowledgements.fetch_add(1, Ordering::SeqCst);
            }
            Ok(accepted)
        }
    }

    fn open_model() -> (Arc<Mutex<LocalReadModel>>, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("egopulse-c4-pump-{}", Uuid::now_v7()));
        let model = LocalReadModel::open(egopulse_local_read_model::LocalReadModelConfig {
            database_path: root.join("read-model.db"),
            epoch: "c4-pump-epoch".to_owned(),
            key: egopulse_local_read_model::LocalReadModelKey::new([0x55; 32]),
        })
        .expect("open read model");
        (Arc::new(Mutex::new(model)), root)
    }

    fn valid_task_message() -> TaskProjectionMessage {
        let event = TaskEvent {
            event_id: "task-event-c4-pump".to_owned(),
            task_id: "task-c4-pump".to_owned(),
            resulting_revision: 1,
            work_revision: 1,
            snapshot: Some(TaskSnapshot {
                task_id: "task-c4-pump".to_owned(),
                revision: 1,
                work_revision: 1,
                status: TaskStatus::Ready as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        TaskProjectionMessage {
            message_id: "task-projection-c4-pump".to_owned(),
            source_event_id: event.event_id.clone(),
            source_revision: 1,
            payload_digest_sha256: hex::encode(Sha256::digest(event.encode_to_vec())),
            event,
        }
    }

    #[test]
    fn task_and_collaboration_projection_bind_into_one_task_view() {
        let (model, root) = open_model();
        let mut task_message = valid_task_message();
        let task = task_message.event.snapshot.as_mut().expect("task snapshot");
        task.task_id = "task-collaboration-bind".to_owned();
        task.current_run_id = Some("run-collaboration-bind".to_owned());
        task_message.event.task_id = task.task_id.clone();
        task_message.event.event_id = "task-event-collaboration-bind".to_owned();
        task_message.source_event_id = task_message.event.event_id.clone();
        task_message.message_id = "task-projection-collaboration-bind".to_owned();
        task_message.payload_digest_sha256 =
            hex::encode(Sha256::digest(task_message.event.encode_to_vec()));

        let snapshot = CollaborationSnapshot {
            run: Some(RunSnapshot {
                run_id: "run-collaboration-bind".to_owned(),
                revision: 1,
                task_id: "task-collaboration-bind".to_owned(),
                work_revision: 1,
                status: RunStatus::ReturnPending as i32,
                ..Default::default()
            }),
            steps: vec![StepSnapshot {
                step_id: "step-collaboration-bind".to_owned(),
                run_id: "run-collaboration-bind".to_owned(),
                revision: 1,
                status: StepStatus::ReturnPending as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        let event = CollaborationEvent {
            event_id: "collaboration-event-bind".to_owned(),
            run_id: "run-collaboration-bind".to_owned(),
            resulting_run_revision: 1,
            ..Default::default()
        };
        let result = egopulse_domain_contracts::v01::egopulse::collaboration::v1::CollaborationCommandResult {
            outcome: Some(collaboration_command_result::Outcome::Snapshot(snapshot.clone())),
            committed_event: Some(event.clone()),
            ..Default::default()
        };
        let collaboration = PendingCollaborationProjection {
            message_id: "collaboration-projection-bind".to_owned(),
            source_event_id: event.event_id.clone(),
            source_revision: 1,
            canonical_payload_digest_sha256: hex::encode(Sha256::digest(result.encode_to_vec())),
            rebuild_baseline: false,
            snapshot,
            event,
        };
        let source = Arc::new(FixtureSource {
            messages: vec![
                PendingOwnerProjection::Task(Box::new(task_message)),
                PendingOwnerProjection::Collaboration(Box::new(collaboration)),
            ],
            acknowledgements: AtomicUsize::new(0),
            accepted_prefix: None,
        });
        let initial = model
            .lock()
            .expect("model lock")
            .position()
            .expect("position");
        let notifier = ProjectionCommitNotifier::new(initial);
        let pump = ProjectionPump::new(model.clone(), notifier, source.clone());
        assert_eq!(
            pump.pump_once()
                .expect("task and collaboration projections"),
            2
        );
        let view = model
            .lock()
            .expect("model lock")
            .get_task_view(
                "task-collaboration-bind",
                egopulse_local_read_model::TaskViewAccess {
                    can_read: true,
                    ..Default::default()
                },
            )
            .expect("get task view")
            .expect("task view");
        assert_eq!(
            view.collaboration
                .expect("collaboration")
                .run
                .expect("run")
                .status,
            RunStatus::ReturnPending as i32
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_owner_projection_is_held_without_acknowledgement() {
        let (model, root) = open_model();
        let mut message = valid_task_message();
        message.payload_digest_sha256 = "0".repeat(64);
        let source = Arc::new(FixtureSource {
            messages: vec![PendingOwnerProjection::Task(Box::new(message))],
            acknowledgements: AtomicUsize::new(0),
            accepted_prefix: None,
        });
        let notifier = ProjectionCommitNotifier::new(
            model
                .lock()
                .expect("model lock")
                .position()
                .expect("position"),
        );
        let pump = ProjectionPump::new(model, notifier, source.clone());
        assert!(matches!(
            pump.pump_once(),
            Err(ProjectionPumpFailure::ReadModel(_))
        ));
        assert_eq!(source.acknowledgements.load(Ordering::SeqCst), 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn durable_projection_acknowledgement_and_duplicate_replay_are_safe() {
        let (model, root) = open_model();
        let source = Arc::new(FixtureSource {
            messages: vec![PendingOwnerProjection::Task(Box::new(valid_task_message()))],
            acknowledgements: AtomicUsize::new(0),
            accepted_prefix: None,
        });
        let initial = model
            .lock()
            .expect("model lock")
            .position()
            .expect("position");
        let notifier = ProjectionCommitNotifier::new(initial);
        let position = notifier.subscribe();
        let pump = ProjectionPump::new(model, notifier, source.clone());
        assert_eq!(pump.pump_once().expect("first projection"), 1);
        assert_eq!(pump.pump_once().expect("duplicate replay"), 1);
        assert_eq!(source.acknowledgements.load(Ordering::SeqCst), 2);
        assert_eq!(position.borrow().sequence, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn composite_source_routes_acknowledgement_to_the_owning_feed() {
        let first_message = valid_task_message();
        let mut second_message = valid_task_message();
        second_message.message_id = "second-projection-c4-pump".to_owned();
        let first = Arc::new(FixtureSource {
            messages: vec![PendingOwnerProjection::Task(Box::new(first_message))],
            acknowledgements: AtomicUsize::new(0),
            accepted_prefix: Some("task-projection"),
        });
        let second = Arc::new(FixtureSource {
            messages: vec![PendingOwnerProjection::Task(Box::new(second_message))],
            acknowledgements: AtomicUsize::new(0),
            accepted_prefix: Some("second-projection"),
        });
        let composite = CompositeOwnerProjectionSource::new(vec![
            Arc::clone(&first) as Arc<dyn OwnerProjectionSource>,
            Arc::clone(&second) as Arc<dyn OwnerProjectionSource>,
        ]);
        let pending = composite.pending().expect("pending projections");
        assert_eq!(pending.len(), 2);
        assert!(composite.acknowledge(&pending[0]).expect("first ack"));
        assert!(composite.acknowledge(&pending[1]).expect("second ack"));
        assert_eq!(first.acknowledgements.load(Ordering::SeqCst), 1);
        assert_eq!(second.acknowledgements.load(Ordering::SeqCst), 1);
    }
}
