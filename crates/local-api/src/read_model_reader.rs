use std::sync::{Arc, Mutex};

use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    EvidenceGraphView, HarnessApprovalView, ProjectionHealth, ProjectionPosition, TaskView,
};
use egopulse_local_read_model::{
    ApprovalListFilter, ApprovalViewAccess, EvidenceGraphAccess, HistoricalPage, LocalReadModel,
    ProjectionFailure, StreamBatch, TaskListFilter, TaskViewAccess,
};
use thiserror::Error;
use tokio::sync::{Semaphore, watch};

#[derive(Clone, Debug)]
pub struct ReadModelStatus {
    pub position: ProjectionPosition,
    pub retention_floor: ProjectionPosition,
    pub health: ProjectionHealth,
}

#[derive(Debug, Error)]
pub enum ReadModelAccessError {
    #[error("local read model rejected the operation")]
    Projection(#[from] ProjectionFailure),
    #[error("local read model executor is unavailable")]
    Unavailable,
    #[error("local read model worker failed")]
    WorkerFailed,
}

#[tonic::async_trait]
pub trait ProjectionStatusReader: Send + Sync + 'static {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError>;
}

#[tonic::async_trait]
pub trait ReadModelReader: ProjectionStatusReader {
    async fn task_frames_after(
        &self,
        after: ProjectionPosition,
        filter: TaskListFilter,
        task_ids: Vec<String>,
        access: TaskViewAccess,
    ) -> Result<
        StreamBatch<egopulse_domain_contracts::v01::egopulse::localapi::v1::TaskViewStreamFrame>,
        ReadModelAccessError,
    > {
        let _ = (after, filter, task_ids, access);
        Err(ReadModelAccessError::Unavailable)
    }

    async fn approval_frames_after(
        &self,
        after: ProjectionPosition,
        filter: ApprovalListFilter,
        approval_request_ids: Vec<String>,
        access: ApprovalViewAccess,
    ) -> Result<
        StreamBatch<
            egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessApprovalViewStreamFrame,
        >,
        ReadModelAccessError,
    > {
        let _ = (after, filter, approval_request_ids, access);
        Err(ReadModelAccessError::Unavailable)
    }

    async fn has_projected_source(
        &self,
        required: egopulse_domain_contracts::v01::egopulse::localapi::v1::SourceRevision,
    ) -> Result<bool, ReadModelAccessError> {
        let _ = required;
        Err(ReadModelAccessError::Unavailable)
    }

    async fn get_task_view(
        &self,
        task_id: String,
        access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError>;

    async fn list_task_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: TaskListFilter,
        access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError>;

    async fn get_evidence_graph(
        &self,
        task_id: String,
        artifact_set_id: String,
        access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError>;

    async fn get_harness_approval_view(
        &self,
        approval_request_id: String,
        access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError>;

    async fn list_harness_approval_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: ApprovalListFilter,
        access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError>;
}

/// Serializes all access to the single synchronous SQLCipher owner and moves
/// every query off Tokio's async worker threads. The permit belongs only to a
/// single database operation; callers cannot retain it while awaiting a
/// projection commit notification.
pub struct BlockingLocalReadModelReader {
    model: Arc<Mutex<LocalReadModel>>,
    permits: Arc<Semaphore>,
}

impl BlockingLocalReadModelReader {
    #[must_use]
    pub fn new(model: Arc<Mutex<LocalReadModel>>) -> Self {
        Self {
            model,
            permits: Arc::new(Semaphore::new(1)),
        }
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, ReadModelAccessError>
    where
        T: Send + 'static,
        F: FnOnce(&LocalReadModel) -> Result<T, ProjectionFailure> + Send + 'static,
    {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| ReadModelAccessError::Unavailable)?;
        let model = Arc::clone(&self.model);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let model = model
                .lock()
                .map_err(|_| ReadModelAccessError::WorkerFailed)?;
            operation(&model).map_err(ReadModelAccessError::Projection)
        })
        .await
        .map_err(|_| ReadModelAccessError::WorkerFailed)?
    }
}

#[tonic::async_trait]
impl ProjectionStatusReader for BlockingLocalReadModelReader {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
        self.run(|model| {
            Ok(ReadModelStatus {
                position: model.position()?,
                retention_floor: model.retention_floor()?,
                health: model.health()?,
            })
        })
        .await
    }
}

#[tonic::async_trait]
impl ReadModelReader for BlockingLocalReadModelReader {
    async fn task_frames_after(
        &self,
        after: ProjectionPosition,
        filter: TaskListFilter,
        task_ids: Vec<String>,
        access: TaskViewAccess,
    ) -> Result<
        StreamBatch<egopulse_domain_contracts::v01::egopulse::localapi::v1::TaskViewStreamFrame>,
        ReadModelAccessError,
    > {
        self.run(move |model| model.task_frames_after_batch(&after, &filter, &task_ids, access))
            .await
    }

    async fn approval_frames_after(
        &self,
        after: ProjectionPosition,
        filter: ApprovalListFilter,
        approval_request_ids: Vec<String>,
        access: ApprovalViewAccess,
    ) -> Result<
        StreamBatch<
            egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessApprovalViewStreamFrame,
        >,
        ReadModelAccessError,
    > {
        self.run(move |model| {
            model.approval_frames_after_filtered(&after, &filter, &approval_request_ids, access)
        })
        .await
    }

    async fn has_projected_source(
        &self,
        required: egopulse_domain_contracts::v01::egopulse::localapi::v1::SourceRevision,
    ) -> Result<bool, ReadModelAccessError> {
        self.run(move |model| model.has_projected_source(&required))
            .await
    }

    async fn get_task_view(
        &self,
        task_id: String,
        access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError> {
        self.run(move |model| model.get_task_view(&task_id, access))
            .await
    }

    async fn list_task_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: TaskListFilter,
        access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError> {
        self.run(move |model| model.list_task_views_at(&snapshot, &filter, access))
            .await
    }

    async fn get_evidence_graph(
        &self,
        task_id: String,
        artifact_set_id: String,
        access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError> {
        self.run(move |model| model.get_evidence_graph(&task_id, &artifact_set_id, access))
            .await
    }

    async fn get_harness_approval_view(
        &self,
        approval_request_id: String,
        access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError> {
        self.run(move |model| model.get_harness_approval_view(&approval_request_id, access))
            .await
    }

    async fn list_harness_approval_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: ApprovalListFilter,
        access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError> {
        self.run(move |model| model.list_harness_approval_views_at(&snapshot, &filter, access))
            .await
    }
}

#[derive(Clone)]
pub struct ProjectionCommitNotifier {
    sender: watch::Sender<ProjectionPosition>,
}

impl ProjectionCommitNotifier {
    #[must_use]
    pub fn new(initial_position: ProjectionPosition) -> Self {
        let (sender, _) = watch::channel(initial_position);
        Self { sender }
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ProjectionPosition> {
        self.sender.subscribe()
    }

    pub fn publish(&self, committed_position: ProjectionPosition) {
        self.sender.send_replace(committed_position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(epoch: &str, sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: epoch.to_owned(),
            sequence,
            projected_at: None,
        }
    }

    #[tokio::test]
    async fn notifier_replays_latest_position_and_wakes_on_commit() {
        let notifier = ProjectionCommitNotifier::new(position("epoch-a", 3));
        let mut subscriber = notifier.subscribe();
        assert_eq!(subscriber.borrow().sequence, 3);

        notifier.publish(position("epoch-a", 4));
        subscriber.changed().await.expect("sender remains live");
        assert_eq!(subscriber.borrow().sequence, 4);

        let late_subscriber = notifier.subscribe();
        assert_eq!(late_subscriber.borrow().sequence, 4);
    }
}
