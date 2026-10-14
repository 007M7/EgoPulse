use std::pin::Pin;

use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    AwaitProjectionRequest, AwaitProjectionResponse, GetEvidenceGraphRequest,
    GetEvidenceGraphResponse, GetHarnessApprovalViewRequest, GetHarnessApprovalViewResponse,
    GetProjectionStatusRequest, GetProjectionStatusResponse, GetTaskViewRequest,
    GetTaskViewResponse, HarnessApprovalViewStreamFrame, HarnessContentStreamFrame,
    ListHarnessApprovalViewsRequest, ListHarnessApprovalViewsResponse, ListHarnessContentRequest,
    ListHarnessContentResponse, ListTaskViewsRequest, ListTaskViewsResponse, TaskViewStreamFrame,
    WatchHarnessApprovalViewsRequest, WatchHarnessContentRequest, WatchTaskViewsRequest,
    local_read_model_service_server::LocalReadModelService,
};
use egopulse_local_ipc_platform::PeerConnectionInfo;
use futures_util::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use crate::read_gateway::{
    ApprovalWatchSubscription, HarnessContentWatchSubscription, ReadGatewayApplication,
    TaskWatchSubscription,
};

pub struct LocalReadModelEndpoint {
    application: std::sync::Arc<ReadGatewayApplication>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
}

impl LocalReadModelEndpoint {
    #[must_use]
    pub fn new(application: std::sync::Arc<ReadGatewayApplication>) -> Self {
        Self {
            application,
            shutdown: None,
        }
    }

    /// Stops read-only streams when the daemon requests shutdown. No Authority
    /// state or client authorization is changed by closing an observation.
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: tokio::sync::watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    fn peer<T>(request: &Request<T>) -> Option<PeerConnectionInfo> {
        request.extensions().get::<PeerConnectionInfo>().cloned()
    }
}

type TaskWatchStream = Pin<Box<dyn Stream<Item = Result<TaskViewStreamFrame, Status>> + Send>>;
type ApprovalWatchStream =
    Pin<Box<dyn Stream<Item = Result<HarnessApprovalViewStreamFrame, Status>> + Send>>;
type HarnessContentWatchStream =
    Pin<Box<dyn Stream<Item = Result<HarnessContentStreamFrame, Status>> + Send>>;

fn shutdown_signal(
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async move {
        let Some(mut shutdown) = shutdown else {
            std::future::pending::<()>().await;
            return;
        };
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    })
}

#[tonic::async_trait]
impl LocalReadModelService for LocalReadModelEndpoint {
    async fn get_task_view(
        &self,
        request: Request<GetTaskViewRequest>,
    ) -> Result<Response<GetTaskViewResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .get_task_view(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn list_task_views(
        &self,
        request: Request<ListTaskViewsRequest>,
    ) -> Result<Response<ListTaskViewsResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .list_task_views(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn get_evidence_graph(
        &self,
        request: Request<GetEvidenceGraphRequest>,
    ) -> Result<Response<GetEvidenceGraphResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .get_evidence_graph(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn get_harness_approval_view(
        &self,
        request: Request<GetHarnessApprovalViewRequest>,
    ) -> Result<Response<GetHarnessApprovalViewResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .get_harness_approval_view(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn list_harness_approval_views(
        &self,
        request: Request<ListHarnessApprovalViewsRequest>,
    ) -> Result<Response<ListHarnessApprovalViewsResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .list_harness_approval_views(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn list_harness_content(
        &self,
        request: Request<ListHarnessContentRequest>,
    ) -> Result<Response<ListHarnessContentResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .list_harness_content(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    async fn get_projection_status(
        &self,
        request: Request<GetProjectionStatusRequest>,
    ) -> Result<Response<GetProjectionStatusResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .get_projection_status(peer.as_ref(), request.into_inner())
                .await,
        ))
    }

    type WatchTaskViewsStream = TaskWatchStream;

    async fn watch_task_views(
        &self,
        request: Request<WatchTaskViewsRequest>,
    ) -> Result<Response<Self::WatchTaskViewsStream>, Status> {
        let peer =
            Self::peer(&request).ok_or_else(|| Status::unauthenticated("peer_identity_missing"))?;
        let subscription = self
            .application
            .open_task_watch(peer, request.into_inner())
            .await
            .map_err(|error| local_error_status(*error))?;
        Ok(Response::new(Box::pin(
            futures_util::stream::unfold(
                Some(subscription),
                |state: Option<TaskWatchSubscription>| async move {
                    let mut subscription = state?;
                    match subscription.next_frame().await {
                        Ok(Some(frame)) => Some((Ok(frame), Some(subscription))),
                        Ok(None) => None,
                        Err(error) => Some((Err(local_error_status(*error)), None)),
                    }
                },
            )
            .take_until(shutdown_signal(self.shutdown.clone())),
        )))
    }

    type WatchHarnessApprovalViewsStream = ApprovalWatchStream;

    async fn watch_harness_approval_views(
        &self,
        request: Request<WatchHarnessApprovalViewsRequest>,
    ) -> Result<Response<Self::WatchHarnessApprovalViewsStream>, Status> {
        let peer =
            Self::peer(&request).ok_or_else(|| Status::unauthenticated("peer_identity_missing"))?;
        let subscription = self
            .application
            .open_approval_watch(peer, request.into_inner())
            .await
            .map_err(|error| local_error_status(*error))?;
        Ok(Response::new(Box::pin(
            futures_util::stream::unfold(
                Some(subscription),
                |state: Option<ApprovalWatchSubscription>| async move {
                    let mut subscription = state?;
                    match subscription.next_frame().await {
                        Ok(Some(frame)) => Some((Ok(frame), Some(subscription))),
                        Ok(None) => None,
                        Err(error) => Some((Err(local_error_status(*error)), None)),
                    }
                },
            )
            .take_until(shutdown_signal(self.shutdown.clone())),
        )))
    }

    type WatchHarnessContentStream = HarnessContentWatchStream;

    async fn watch_harness_content(
        &self,
        request: Request<WatchHarnessContentRequest>,
    ) -> Result<Response<Self::WatchHarnessContentStream>, Status> {
        let peer =
            Self::peer(&request).ok_or_else(|| Status::unauthenticated("peer_identity_missing"))?;
        let subscription = self
            .application
            .open_content_watch(peer, request.into_inner())
            .await
            .map_err(|error| local_error_status(*error))?;
        Ok(Response::new(Box::pin(
            futures_util::stream::unfold(
                Some(subscription),
                |state: Option<HarnessContentWatchSubscription>| async move {
                    let mut subscription = state?;
                    match subscription.next_frame().await {
                        Ok(Some(frame)) => Some((Ok(frame), Some(subscription))),
                        Ok(None) => None,
                        Err(error) => Some((Err(local_error_status(*error)), None)),
                    }
                },
            )
            .take_until(shutdown_signal(self.shutdown.clone())),
        )))
    }

    async fn await_projection(
        &self,
        request: Request<AwaitProjectionRequest>,
    ) -> Result<Response<AwaitProjectionResponse>, Status> {
        let peer = Self::peer(&request);
        Ok(Response::new(
            self.application
                .await_projection(peer.as_ref(), request.into_inner())
                .await,
        ))
    }
}

fn local_error_status(
    error: egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError,
) -> Status {
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode;

    let code = LocalApiErrorCode::try_from(error.code).unwrap_or(LocalApiErrorCode::Unspecified);
    let status = match code {
        LocalApiErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        LocalApiErrorCode::Unauthenticated | LocalApiErrorCode::SessionExpired => {
            tonic::Code::Unauthenticated
        }
        LocalApiErrorCode::PermissionDenied | LocalApiErrorCode::OwnerMismatch => {
            tonic::Code::PermissionDenied
        }
        LocalApiErrorCode::NotFound => tonic::Code::NotFound,
        LocalApiErrorCode::ContractIncompatible => tonic::Code::FailedPrecondition,
        LocalApiErrorCode::ProjectionBehind
        | LocalApiErrorCode::ProjectionResetRequired
        | LocalApiErrorCode::ProjectionHeld
        | LocalApiErrorCode::DeadlineExceeded => tonic::Code::DeadlineExceeded,
        LocalApiErrorCode::AuthorityUnavailable | LocalApiErrorCode::CognitionWorkerUnavailable => {
            tonic::Code::Unavailable
        }
        LocalApiErrorCode::ResourceExhausted => tonic::Code::ResourceExhausted,
        LocalApiErrorCode::ContextRevoked
        | LocalApiErrorCode::CapabilityNotAdmitted
        | LocalApiErrorCode::ConfigurationMigrationRequired => tonic::Code::FailedPrecondition,
        LocalApiErrorCode::StateRevisionConflict | LocalApiErrorCode::IdempotencyConflict => {
            tonic::Code::Aborted
        }
        LocalApiErrorCode::CursorInvalid
        | LocalApiErrorCode::CursorExpired
        | LocalApiErrorCode::IntegrityFailure
        | LocalApiErrorCode::UnknownCriticalSemantics
        | LocalApiErrorCode::Unspecified => tonic::Code::Internal,
    };
    Status::new(
        status,
        format!("{} ({})", error.safe_fingerprint, error.correlation_id),
    )
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_ends_idle_and_buffered_streams_without_another_frame() {
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let mut idle = Box::pin(
            futures_util::stream::pending::<u8>()
                .take_until(shutdown_signal(Some(receiver.clone()))),
        );
        stop.send(true).expect("shutdown signal");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), idle.next())
                .await
                .expect("idle stream closes"),
            None,
        );
        let mut buffered = Box::pin(
            futures_util::stream::iter([1_u8, 2]).take_until(shutdown_signal(Some(receiver))),
        );
        assert_eq!(buffered.next().await, None);
    }

    #[tokio::test]
    async fn lost_shutdown_sender_ends_idle_stream() {
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let mut idle = Box::pin(
            futures_util::stream::pending::<u8>().take_until(shutdown_signal(Some(receiver))),
        );
        drop(stop);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), idle.next())
                .await
                .expect("orphaned stream closes"),
            None,
        );
    }
}
