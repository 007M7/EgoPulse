use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::task_authority::TaskProjectionMessage;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition;
use egopulse_founder_verdict_authority::VerdictProjectionMessage;
use egopulse_local_api::read_model_reader::ProjectionCommitNotifier;
use egopulse_local_read_model::{
    LocalReadModel, PolicyApprovalProjectionInput, ProjectionFailure, ProjectionMessageMetadata,
    ProjectionMessageMode, TaskProjectionInput, VerdictProjectionInput,
};
use egopulse_policy_decision_authority::PendingPolicyProjection;
use thiserror::Error;
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub enum PendingOwnerProjection {
    Task(Box<TaskProjectionMessage>),
    Policy(Box<PendingPolicyProjection>),
    Verdict(Box<VerdictProjectionMessage>),
}

#[derive(Debug, Error)]
pub enum ProjectionSourceFailure {
    #[error("task projection source is unavailable")]
    Task,
    #[error("policy projection source is unavailable")]
    Policy,
    #[error("verdict projection source is unavailable")]
    Verdict,
    #[error("projection acknowledgement was not accepted by the owner")]
    Acknowledgement,
}

pub trait OwnerProjectionSource: Send + Sync + 'static {
    fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure>;

    fn acknowledge(&self, message: &PendingOwnerProjection) -> Result<(), ProjectionSourceFailure>;
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
            self.source.acknowledge(&message)?;
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
    use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskEvent, TaskSnapshot, TaskStatus};
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
    }

    impl OwnerProjectionSource for FixtureSource {
        fn pending(&self) -> Result<Vec<PendingOwnerProjection>, ProjectionSourceFailure> {
            Ok(self.messages.clone())
        }

        fn acknowledge(
            &self,
            _message: &PendingOwnerProjection,
        ) -> Result<(), ProjectionSourceFailure> {
            self.acknowledgements.fetch_add(1, Ordering::SeqCst);
            Ok(())
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
    fn invalid_owner_projection_is_held_without_acknowledgement() {
        let (model, root) = open_model();
        let mut message = valid_task_message();
        message.payload_digest_sha256 = "0".repeat(64);
        let source = Arc::new(FixtureSource {
            messages: vec![PendingOwnerProjection::Task(Box::new(message))],
            acknowledgements: AtomicUsize::new(0),
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
}
