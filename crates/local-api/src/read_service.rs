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
use futures_util::Stream;
use tonic::{Request, Response, Status};

use crate::read_gateway::{
    ApprovalWatchSubscription, ReadGatewayApplication, TaskWatchSubscription,
};

pub struct LocalReadModelEndpoint {
    application: std::sync::Arc<ReadGatewayApplication>,
}

impl LocalReadModelEndpoint {
    #[must_use]
    pub fn new(application: std::sync::Arc<ReadGatewayApplication>) -> Self {
        Self { application }
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
        _request: Request<ListHarnessContentRequest>,
    ) -> Result<Response<ListHarnessContentResponse>, Status> {
        Err(Status::unimplemented("r9c_contract_only"))
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
        Ok(Response::new(Box::pin(futures_util::stream::unfold(
            Some(subscription),
            |state: Option<TaskWatchSubscription>| async move {
                let mut subscription = state?;
                match subscription.next_frame().await {
                    Ok(Some(frame)) => Some((Ok(frame), Some(subscription))),
                    Ok(None) => None,
                    Err(error) => Some((Err(local_error_status(*error)), None)),
                }
            },
        ))))
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
        Ok(Response::new(Box::pin(futures_util::stream::unfold(
            Some(subscription),
            |state: Option<ApprovalWatchSubscription>| async move {
                let mut subscription = state?;
                match subscription.next_frame().await {
                    Ok(Some(frame)) => Some((Ok(frame), Some(subscription))),
                    Ok(None) => None,
                    Err(error) => Some((Err(local_error_status(*error)), None)),
                }
            },
        ))))
    }

    type WatchHarnessContentStream = HarnessContentWatchStream;

    async fn watch_harness_content(
        &self,
        _request: Request<WatchHarnessContentRequest>,
    ) -> Result<Response<Self::WatchHarnessContentStream>, Status> {
        Err(Status::unimplemented("r9c_contract_only"))
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
        LocalApiErrorCode::ContextRevoked => tonic::Code::FailedPrecondition,
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
