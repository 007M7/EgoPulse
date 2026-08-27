use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use egopulse_domain_contracts::{
    profiles::{
        API_CONTRACT_DIGEST_SHA256, API_CONTRACT_VERSION, ContractProfileError, ContractProfiles,
    },
    v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::ApprovalRequestLifecycleKind,
        localapi::v1::{
            AwaitProjectionRequest, AwaitProjectionResponse, ClientRequestMetadata,
            GetEvidenceGraphRequest, GetEvidenceGraphResponse, GetHarnessApprovalViewRequest,
            GetHarnessApprovalViewResponse, GetProjectionStatusRequest,
            GetProjectionStatusResponse, GetTaskViewRequest, GetTaskViewResponse,
            HarnessApprovalView, HarnessApprovalViewStreamFrame, ListHarnessApprovalViewsRequest,
            ListHarnessApprovalViewsResponse, ListTaskViewsRequest, ListTaskViewsResponse,
            LocalApiError, LocalApiErrorCode, ProjectionHealth, ProjectionMetadata,
            ProjectionPosition, StreamFrameKind, TaskView, TaskViewStreamFrame,
            WatchHarnessApprovalViewsRequest, WatchTaskViewsRequest, await_projection_response,
            get_evidence_graph_response, get_harness_approval_view_response,
            get_task_view_response,
        },
        policy::v1::HarnessApprovalDecisionStateKind,
        task::v1::TaskStatus,
    },
};
use egopulse_local_ipc_platform::PeerConnectionInfo;
use egopulse_local_read_model::{
    ApprovalListFilter, ApprovalViewAccess, EvidenceGraphAccess, TaskListFilter, TaskViewAccess,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{sync::watch, time::Instant};
use uuid::Uuid;

use crate::{
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{
        ProjectionCommitNotifier, ProjectionStatusReader, ReadModelAccessError, ReadModelReader,
        ReadModelStatus,
    },
    read_tokens::{
        AwaitTarget, CursorAnchor, CursorCollection, CursorExpectation, CursorIssue, CursorSort,
        ReadTokenCodec, ReadTokenError, ReadTokenScope, VerifiedCursor,
    },
    session::{AuthenticatedSession, SessionAuthenticationFailure, SessionRegistry},
};

const MAX_EPOCH_BYTES: usize = 256;
const MAX_IDENTIFIER_BYTES: usize = 256;
const PROJECTION_STATUS_SCHEMA_ID: &str = "egopulse.localapi.v1/ProjectionMetadata";

const RPC_GET_TASK: &str = "LocalReadModelService/GetTaskView";
const RPC_GET_EVIDENCE: &str = "LocalReadModelService/GetEvidenceGraph";
const RPC_GET_APPROVAL: &str = "LocalReadModelService/GetHarnessApprovalView";
const RPC_GET_STATUS: &str = "LocalReadModelService/GetProjectionStatus";
const RPC_LIST_TASKS: &str = "LocalReadModelService/ListTaskViews";
const RPC_LIST_APPROVALS: &str = "LocalReadModelService/ListHarnessApprovalViews";
const RPC_WATCH_TASKS: &str = "LocalReadModelService/WatchTaskViews";
const RPC_WATCH_APPROVALS: &str = "LocalReadModelService/WatchHarnessApprovalViews";
const RPC_AWAIT: &str = "LocalReadModelService/AwaitProjection";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionGateFailureKind {
    InvalidMinimumPosition,
    Behind,
    ResetRequired,
    Held,
    IntegrityFailure,
    Unavailable,
}

#[derive(Debug)]
pub struct ProjectionGateFailure {
    pub kind: ProjectionGateFailureKind,
    pub current_position: Option<ProjectionPosition>,
}

pub struct MinimumPositionGate {
    notifier: ProjectionCommitNotifier,
    wait_timeout: Duration,
}

pub struct ReadGatewayApplication {
    registry: Arc<SessionRegistry>,
    profiles: Arc<ContractProfiles>,
    reader: Arc<dyn ReadModelReader>,
    minimum_gate: MinimumPositionGate,
    token_codec: Arc<ReadTokenCodec>,
    audit: Arc<dyn ReadGatewayAuditSink>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadGatewayAuditKind {
    SensitiveEvidenceRead,
    ProjectionResetRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadGatewayAuditEvent {
    pub kind: ReadGatewayAuditKind,
    pub rpc: &'static str,
    pub authenticated_principal_id: String,
    pub correlation_id: String,
    pub safe_outcome_code: &'static str,
}

pub trait ReadGatewayAuditSink: Send + Sync + 'static {
    fn record(&self, event: ReadGatewayAuditEvent);
}

#[derive(Default)]
pub struct NoopReadGatewayAuditSink;

impl ReadGatewayAuditSink for NoopReadGatewayAuditSink {
    fn record(&self, _event: ReadGatewayAuditEvent) {}
}

impl ReadGatewayApplication {
    #[must_use]
    pub fn new(
        registry: Arc<SessionRegistry>,
        profiles: Arc<ContractProfiles>,
        reader: Arc<dyn ReadModelReader>,
        notifier: ProjectionCommitNotifier,
        token_codec: Arc<ReadTokenCodec>,
        audit: Arc<dyn ReadGatewayAuditSink>,
    ) -> Self {
        let minimum_gate = MinimumPositionGate::new(notifier, token_codec.policy());
        Self {
            registry,
            profiles,
            reader,
            minimum_gate,
            token_codec,
            audit,
        }
    }

    pub async fn get_task_view(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: GetTaskViewRequest,
    ) -> GetTaskViewResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_GET_TASK) {
            Ok(value) => value,
            Err(failure) => {
                return task_error(failure.into_error(correlation_id));
            }
        };
        if validate_identifier(&request.task_id).is_err() {
            return task_error(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_task_id",
                false,
                None,
                None,
                correlation_id,
            ));
        }
        if let Err(failure) = self
            .minimum_gate
            .wait(self.reader.as_ref(), request.minimum_position.as_ref())
            .await
        {
            self.audit_gate_failure(RPC_GET_TASK, &context.session, &correlation_id, &failure);
            return task_error(gate_error(failure, correlation_id));
        }

        match self
            .reader
            .get_task_view(
                request.task_id,
                task_access(&context.session.permission_codes),
            )
            .await
        {
            Ok(Some(view)) => GetTaskViewResponse {
                outcome: Some(get_task_view_response::Outcome::View(view)),
            },
            Ok(None) => task_error(api_error(
                LocalApiErrorCode::NotFound,
                "task_view_not_found",
                false,
                None,
                None,
                correlation_id,
            )),
            Err(error) => task_error(read_error(error, correlation_id)),
        }
    }

    pub async fn get_evidence_graph(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: GetEvidenceGraphRequest,
    ) -> GetEvidenceGraphResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_GET_EVIDENCE) {
            Ok(value) => value,
            Err(failure) => return evidence_error(failure.into_error(correlation_id)),
        };
        if validate_identifier(&request.task_id).is_err()
            || validate_identifier(&request.artifact_set_id).is_err()
        {
            self.audit_evidence(&context.session, &correlation_id, "invalid_argument");
            return evidence_error(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_evidence_graph_id",
                false,
                None,
                None,
                correlation_id,
            ));
        }
        if let Err(failure) = self
            .minimum_gate
            .wait(self.reader.as_ref(), request.minimum_position.as_ref())
            .await
        {
            self.audit_gate_failure(
                RPC_GET_EVIDENCE,
                &context.session,
                &correlation_id,
                &failure,
            );
            self.audit_evidence(
                &context.session,
                &correlation_id,
                "projection_gate_rejected",
            );
            return evidence_error(gate_error(failure, correlation_id));
        }

        let access = EvidenceGraphAccess {
            can_read: context
                .session
                .permission_codes
                .contains("local.evidence.read"),
        };
        match self
            .reader
            .get_evidence_graph(request.task_id, request.artifact_set_id, access)
            .await
        {
            Ok(Some(graph)) => {
                self.audit_evidence(&context.session, &correlation_id, "succeeded");
                GetEvidenceGraphResponse {
                    outcome: Some(get_evidence_graph_response::Outcome::Graph(graph)),
                }
            }
            Ok(None) => {
                self.audit_evidence(&context.session, &correlation_id, "not_found");
                evidence_error(api_error(
                    LocalApiErrorCode::NotFound,
                    "evidence_graph_not_found",
                    false,
                    None,
                    None,
                    correlation_id,
                ))
            }
            Err(error) => {
                self.audit_evidence(&context.session, &correlation_id, "read_failed");
                evidence_error(read_error(error, correlation_id))
            }
        }
    }

    pub async fn get_harness_approval_view(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: GetHarnessApprovalViewRequest,
    ) -> GetHarnessApprovalViewResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_GET_APPROVAL) {
            Ok(value) => value,
            Err(failure) => return approval_error(failure.into_error(correlation_id)),
        };
        if validate_identifier(&request.approval_request_id).is_err() {
            return approval_error(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_approval_request_id",
                false,
                None,
                None,
                correlation_id,
            ));
        }
        if let Err(failure) = self
            .minimum_gate
            .wait(self.reader.as_ref(), request.minimum_position.as_ref())
            .await
        {
            self.audit_gate_failure(
                RPC_GET_APPROVAL,
                &context.session,
                &correlation_id,
                &failure,
            );
            return approval_error(gate_error(failure, correlation_id));
        }

        match self
            .reader
            .get_harness_approval_view(
                request.approval_request_id,
                approval_access(&context.session.permission_codes),
            )
            .await
        {
            Ok(Some(view)) => GetHarnessApprovalViewResponse {
                outcome: Some(get_harness_approval_view_response::Outcome::View(view)),
            },
            Ok(None) => approval_error(api_error(
                LocalApiErrorCode::NotFound,
                "approval_view_not_found",
                false,
                None,
                None,
                correlation_id,
            )),
            Err(error) => approval_error(read_error(error, correlation_id)),
        }
    }

    pub async fn list_task_views(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ListTaskViewsRequest,
    ) -> ListTaskViewsResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_LIST_TASKS) {
            Ok(value) => value,
            Err(failure) => return task_list_error(failure.into_error(correlation_id)),
        };
        let statuses = match normalize_enum_filter::<TaskStatus>(&request.status_filter) {
            Ok(value) => value,
            Err(()) => {
                return task_list_error(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_task_status_filter",
                    false,
                    None,
                    None,
                    correlation_id,
                ));
            }
        };
        let filter = TaskListFilter {
            statuses: statuses.clone(),
        };
        let filter_sha256 = match digest_filter(&TaskFilterMaterial {
            statuses: &statuses,
        }) {
            Ok(value) => value,
            Err(_) => {
                return task_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "task_filter_digest_failure",
                    false,
                    Some("RESTART_DAEMON"),
                    None,
                    correlation_id,
                ));
            }
        };
        let page_size = self
            .token_codec
            .policy()
            .effective_page_size(request.page_size);
        let status = match self
            .minimum_gate
            .wait(self.reader.as_ref(), request.minimum_position.as_ref())
            .await
        {
            Ok(value) => value,
            Err(failure) => {
                self.audit_gate_failure(
                    RPC_LIST_TASKS,
                    &context.session,
                    &correlation_id,
                    &failure,
                );
                return task_list_error(gate_error(failure, correlation_id));
            }
        };
        let scope = match ReadTokenScope::from_session(&context.session) {
            Ok(value) => value,
            Err(error) => return task_list_error(token_error(error, correlation_id)),
        };
        let (snapshot, anchor) = match self.resolve_task_cursor(
            request.page_cursor.as_deref(),
            request.minimum_position.as_ref(),
            &scope,
            &status,
            &filter_sha256,
            page_size,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.audit_deferred_failure(
                    RPC_LIST_TASKS,
                    &context.session,
                    &correlation_id,
                    &error,
                );
                return task_list_error(error.with_correlation(correlation_id));
            }
        };
        let historical = match self
            .reader
            .list_task_views_at(
                snapshot.clone(),
                filter,
                task_access(&context.session.permission_codes),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                if read_error_is_reset(&error) {
                    self.audit_reset(
                        RPC_LIST_TASKS,
                        &context.session,
                        &correlation_id,
                        "snapshot_reset_required",
                    );
                }
                return task_list_error(read_error(error, correlation_id));
            }
        };
        if historical.snapshot_position.epoch != snapshot.epoch
            || historical.snapshot_position.sequence != snapshot.sequence
        {
            return task_list_error(api_error(
                LocalApiErrorCode::IntegrityFailure,
                "task_page_snapshot_mismatch",
                false,
                Some("REBUILD_PROJECTION"),
                Some(historical.snapshot_position),
                correlation_id,
            ));
        }
        let start = match task_page_start(&historical.items, anchor.as_ref()) {
            Ok(value) => value,
            Err(()) => {
                return task_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "task_page_sort_or_anchor_integrity_failure",
                    false,
                    Some("REBUILD_PROJECTION"),
                    Some(snapshot),
                    correlation_id,
                ));
            }
        };
        let end = start
            .saturating_add(page_size as usize)
            .min(historical.items.len());
        let views = historical.items[start..end].to_vec();
        let next_page_cursor = if end < historical.items.len() {
            let Some(last) = views.last() else {
                return task_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "empty_task_page_with_more_results",
                    false,
                    Some("REBUILD_PROJECTION"),
                    Some(snapshot),
                    correlation_id,
                ));
            };
            let anchor = match task_anchor(last) {
                Ok(value) => value,
                Err(()) => {
                    return task_list_error(api_error(
                        LocalApiErrorCode::IntegrityFailure,
                        "invalid_task_sort_key",
                        false,
                        Some("REBUILD_PROJECTION"),
                        Some(snapshot),
                        correlation_id,
                    ));
                }
            };
            match self.token_codec.issue_cursor(
                &scope,
                CursorIssue {
                    collection: CursorCollection::TaskViews,
                    filter_sha256,
                    sort: CursorSort::TaskUpdatedAtDescTaskIdAsc,
                    effective_page_size: page_size,
                    snapshot_position: snapshot.clone(),
                    anchor,
                },
            ) {
                Ok(value) => Some(value),
                Err(error) => return task_list_error(token_error(error, correlation_id)),
            }
        } else {
            None
        };
        ListTaskViewsResponse {
            views,
            next_page_cursor,
            snapshot_position: Some(snapshot),
            error: None,
        }
    }

    pub async fn list_harness_approval_views(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: ListHarnessApprovalViewsRequest,
    ) -> ListHarnessApprovalViewsResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_LIST_APPROVALS) {
            Ok(value) => value,
            Err(failure) => return approval_list_error(failure.into_error(correlation_id)),
        };
        let request_lifecycles = match normalize_enum_filter::<ApprovalRequestLifecycleKind>(
            &request.request_lifecycle_filter,
        ) {
            Ok(value) => value,
            Err(()) => {
                return approval_list_error(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_approval_lifecycle_filter",
                    false,
                    None,
                    None,
                    correlation_id,
                ));
            }
        };
        let decision_states = match normalize_enum_filter::<HarnessApprovalDecisionStateKind>(
            &request.decision_state_filter,
        ) {
            Ok(value) => value,
            Err(()) => {
                return approval_list_error(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_approval_decision_filter",
                    false,
                    None,
                    None,
                    correlation_id,
                ));
            }
        };
        let task_ids = match normalize_identifiers(&request.task_ids) {
            Ok(value) => value,
            Err(()) => {
                return approval_list_error(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_approval_task_filter",
                    false,
                    None,
                    None,
                    correlation_id,
                ));
            }
        };
        let filter = ApprovalListFilter {
            request_lifecycles: request_lifecycles.clone(),
            decision_states: decision_states.clone(),
            task_ids: task_ids.clone(),
            actionable_only: request.actionable_only,
        };
        let filter_sha256 = match digest_filter(&ApprovalFilterMaterial {
            request_lifecycles: &request_lifecycles,
            decision_states: &decision_states,
            task_ids: &task_ids,
            actionable_only: request.actionable_only,
        }) {
            Ok(value) => value,
            Err(_) => {
                return approval_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "approval_filter_digest_failure",
                    false,
                    Some("RESTART_DAEMON"),
                    None,
                    correlation_id,
                ));
            }
        };
        let page_size = self
            .token_codec
            .policy()
            .effective_page_size(request.page_size);
        let status = match self
            .minimum_gate
            .wait(self.reader.as_ref(), request.minimum_position.as_ref())
            .await
        {
            Ok(value) => value,
            Err(failure) => {
                self.audit_gate_failure(
                    RPC_LIST_APPROVALS,
                    &context.session,
                    &correlation_id,
                    &failure,
                );
                return approval_list_error(gate_error(failure, correlation_id));
            }
        };
        let scope = match ReadTokenScope::from_session(&context.session) {
            Ok(value) => value,
            Err(error) => return approval_list_error(token_error(error, correlation_id)),
        };
        let (snapshot, anchor) = match self.resolve_approval_cursor(
            request.page_cursor.as_deref(),
            request.minimum_position.as_ref(),
            &scope,
            &status,
            &filter_sha256,
            page_size,
        ) {
            Ok(value) => value,
            Err(error) => {
                self.audit_deferred_failure(
                    RPC_LIST_APPROVALS,
                    &context.session,
                    &correlation_id,
                    &error,
                );
                return approval_list_error(error.with_correlation(correlation_id));
            }
        };
        let historical = match self
            .reader
            .list_harness_approval_views_at(
                snapshot.clone(),
                filter,
                approval_access(&context.session.permission_codes),
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                if read_error_is_reset(&error) {
                    self.audit_reset(
                        RPC_LIST_APPROVALS,
                        &context.session,
                        &correlation_id,
                        "snapshot_reset_required",
                    );
                }
                return approval_list_error(read_error(error, correlation_id));
            }
        };
        if historical.snapshot_position.epoch != snapshot.epoch
            || historical.snapshot_position.sequence != snapshot.sequence
        {
            return approval_list_error(api_error(
                LocalApiErrorCode::IntegrityFailure,
                "approval_page_snapshot_mismatch",
                false,
                Some("REBUILD_PROJECTION"),
                Some(historical.snapshot_position),
                correlation_id,
            ));
        }
        let start = match approval_page_start(&historical.items, anchor.as_ref()) {
            Ok(value) => value,
            Err(()) => {
                return approval_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "approval_page_sort_or_anchor_integrity_failure",
                    false,
                    Some("REBUILD_PROJECTION"),
                    Some(snapshot),
                    correlation_id,
                ));
            }
        };
        let end = start
            .saturating_add(page_size as usize)
            .min(historical.items.len());
        let views = historical.items[start..end].to_vec();
        let next_page_cursor = if end < historical.items.len() {
            let Some(last) = views.last() else {
                return approval_list_error(api_error(
                    LocalApiErrorCode::IntegrityFailure,
                    "empty_approval_page_with_more_results",
                    false,
                    Some("REBUILD_PROJECTION"),
                    Some(snapshot),
                    correlation_id,
                ));
            };
            let anchor = match approval_anchor(last) {
                Ok(value) => value,
                Err(()) => {
                    return approval_list_error(api_error(
                        LocalApiErrorCode::IntegrityFailure,
                        "invalid_approval_sort_key",
                        false,
                        Some("REBUILD_PROJECTION"),
                        Some(snapshot),
                        correlation_id,
                    ));
                }
            };
            match self.token_codec.issue_cursor(
                &scope,
                CursorIssue {
                    collection: CursorCollection::HarnessApprovalViews,
                    filter_sha256,
                    sort: CursorSort::ApprovalProjectionSequenceDescApprovalRequestIdAsc,
                    effective_page_size: page_size,
                    snapshot_position: snapshot.clone(),
                    anchor,
                },
            ) {
                Ok(value) => Some(value),
                Err(error) => return approval_list_error(token_error(error, correlation_id)),
            }
        } else {
            None
        };
        ListHarnessApprovalViewsResponse {
            views,
            next_page_cursor,
            snapshot_position: Some(snapshot),
            error: None,
        }
    }

    pub async fn get_projection_status(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: GetProjectionStatusRequest,
    ) -> GetProjectionStatusResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        if let Err(failure) = self.authorize(peer, request.client.as_ref(), RPC_GET_STATUS) {
            return GetProjectionStatusResponse {
                metadata: None,
                error: Some(failure.into_error(correlation_id)),
            };
        }
        match self.reader.status().await {
            Ok(status) => {
                let error = match status.health {
                    ProjectionHealth::IntegrityFailed | ProjectionHealth::Unspecified => {
                        Some(api_error(
                            LocalApiErrorCode::IntegrityFailure,
                            "projection_integrity_failure",
                            false,
                            Some("REBUILD_PROJECTION"),
                            Some(status.position.clone()),
                            correlation_id,
                        ))
                    }
                    _ => None,
                };
                GetProjectionStatusResponse {
                    metadata: Some(status_metadata(&status)),
                    error,
                }
            }
            Err(error) => GetProjectionStatusResponse {
                metadata: None,
                error: Some(read_error(error, correlation_id)),
            },
        }
    }

    pub async fn await_projection(
        &self,
        peer: Option<&PeerConnectionInfo>,
        request: AwaitProjectionRequest,
    ) -> AwaitProjectionResponse {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = match self.authorize(peer, request.client.as_ref(), RPC_AWAIT) {
            Ok(value) => value,
            Err(failure) => return await_error(failure.into_error(correlation_id)),
        };
        let scope = match ReadTokenScope::from_session(&context.session) {
            Ok(value) => value,
            Err(error) => return await_error(token_error(error, correlation_id)),
        };
        let token = match request.await_token.as_ref() {
            Some(value) => value,
            None => {
                return await_error(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "await_token_missing",
                    false,
                    Some("RETRY_COMMAND"),
                    None,
                    correlation_id,
                ));
            }
        };
        let verified = match self.token_codec.verify_await_token(token, &scope) {
            Ok(value) => value,
            Err(error) => return await_error(await_token_error(error, correlation_id)),
        };
        let mut commits = self.minimum_gate.subscribe();
        let deadline = Instant::now()
            + self
                .token_codec
                .policy()
                .effective_await_timeout(request.timeout_milliseconds);
        let mut final_check = false;
        loop {
            let status = match self.reader.status().await {
                Ok(value) => value,
                Err(error) => return await_error(read_error(error, correlation_id.clone())),
            };
            if let Err(failure) = evaluate_status(&status, None) {
                return await_error(gate_error(failure, correlation_id.clone()));
            }
            let projected = match self
                .reader
                .has_projected_source(verified.required_source_revision.clone())
                .await
            {
                Ok(value) => value,
                Err(error) => return await_error(read_error(error, correlation_id.clone())),
            };
            if projected {
                return match verified.target {
                    AwaitTarget::Task { task_id } => match self
                        .reader
                        .get_task_view(task_id, task_access(&context.session.permission_codes))
                        .await
                    {
                        Ok(Some(view)) => AwaitProjectionResponse {
                            outcome: Some(await_projection_response::Outcome::View(view)),
                        },
                        Ok(None) => await_error(api_error(
                            LocalApiErrorCode::NotFound,
                            "await_task_view_not_found",
                            false,
                            Some("RESET_AND_REFETCH"),
                            Some(status.position),
                            correlation_id,
                        )),
                        Err(error) => await_error(read_error(error, correlation_id)),
                    },
                    AwaitTarget::HarnessApproval {
                        approval_request_id,
                    } => match self
                        .reader
                        .get_harness_approval_view(
                            approval_request_id,
                            approval_access(&context.session.permission_codes),
                        )
                        .await
                    {
                        Ok(Some(view)) => AwaitProjectionResponse {
                            outcome: Some(await_projection_response::Outcome::ApprovalView(view)),
                        },
                        Ok(None) => await_error(api_error(
                            LocalApiErrorCode::NotFound,
                            "await_approval_view_not_found",
                            false,
                            Some("RESET_AND_REFETCH"),
                            Some(status.position),
                            correlation_id,
                        )),
                        Err(error) => await_error(read_error(error, correlation_id)),
                    },
                };
            }
            if final_check {
                return await_error(api_error(
                    LocalApiErrorCode::DeadlineExceeded,
                    "projection_await_deadline_exceeded",
                    true,
                    Some("RETRY_AWAIT"),
                    Some(status.position),
                    correlation_id,
                ));
            }
            match tokio::time::timeout_at(deadline, commits.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => final_check = true,
            }
        }
    }

    pub async fn open_task_watch(
        self: &Arc<Self>,
        peer: PeerConnectionInfo,
        request: WatchTaskViewsRequest,
    ) -> Result<TaskWatchSubscription, Box<LocalApiError>> {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = self
            .authorize(Some(&peer), request.client.as_ref(), RPC_WATCH_TASKS)
            .map_err(|failure| Box::new(failure.into_error(correlation_id.clone())))?;
        let statuses =
            normalize_enum_filter::<TaskStatus>(&request.status_filter).map_err(|()| {
                Box::new(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_task_status_filter",
                    false,
                    None,
                    None,
                    correlation_id.clone(),
                ))
            })?;
        let task_ids = normalize_identifiers(&request.task_ids).map_err(|()| {
            Box::new(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_task_watch_ids",
                false,
                None,
                None,
                correlation_id.clone(),
            ))
        })?;
        let position = match request.resume_after {
            Some(ref value) => {
                validate_minimum_position(value)
                    .map_err(|failure| Box::new(gate_error(failure, correlation_id.clone())))?;
                value.clone()
            }
            None => {
                self.reader
                    .status()
                    .await
                    .map_err(|error| Box::new(read_error(error, correlation_id.clone())))?
                    .position
            }
        };
        let mut pending = VecDeque::new();
        if request.resume_after.is_none() {
            let status = self
                .reader
                .status()
                .await
                .map_err(|error| Box::new(read_error(error, correlation_id.clone())))?;
            evaluate_status(&status, None)
                .map_err(|failure| Box::new(gate_error(failure, correlation_id.clone())))?;
            pending.push_back(TaskViewStreamFrame {
                kind: StreamFrameKind::Heartbeat as i32,
                position: Some(status.position),
                snapshot: None,
                reset_reason_code: None,
            });
        }
        Ok(TaskWatchSubscription {
            app: Arc::clone(self),
            peer,
            metadata: request.client.ok_or_else(|| {
                Box::new(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_client_metadata",
                    false,
                    None,
                    None,
                    correlation_id.clone(),
                ))
            })?,
            filter: TaskListFilter { statuses },
            task_ids,
            position,
            pending,
            pending_observed: None,
            notifier: self.minimum_gate.subscribe(),
            next_heartbeat: Instant::now() + self.token_codec.policy().watch_heartbeat_interval(),
            heartbeat_interval: self.token_codec.policy().watch_heartbeat_interval(),
            terminated: false,
            _authorized_principal_id: context.session.authenticated_principal_id,
        })
    }

    pub async fn open_approval_watch(
        self: &Arc<Self>,
        peer: PeerConnectionInfo,
        request: WatchHarnessApprovalViewsRequest,
    ) -> Result<ApprovalWatchSubscription, Box<LocalApiError>> {
        let correlation_id = correlation_id(request.client.as_ref());
        let context = self
            .authorize(Some(&peer), request.client.as_ref(), RPC_WATCH_APPROVALS)
            .map_err(|failure| Box::new(failure.into_error(correlation_id.clone())))?;
        let request_lifecycles = normalize_enum_filter::<ApprovalRequestLifecycleKind>(
            &request.request_lifecycle_filter,
        )
        .map_err(|()| {
            Box::new(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_approval_lifecycle_filter",
                false,
                None,
                None,
                correlation_id.clone(),
            ))
        })?;
        let decision_states = normalize_enum_filter::<HarnessApprovalDecisionStateKind>(
            &request.decision_state_filter,
        )
        .map_err(|()| {
            Box::new(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_approval_decision_filter",
                false,
                None,
                None,
                correlation_id.clone(),
            ))
        })?;
        let task_ids = normalize_identifiers(&request.task_ids).map_err(|()| {
            Box::new(api_error(
                LocalApiErrorCode::InvalidArgument,
                "invalid_approval_task_filter",
                false,
                None,
                None,
                correlation_id.clone(),
            ))
        })?;
        let approval_request_ids =
            normalize_identifiers(&request.approval_request_ids).map_err(|()| {
                Box::new(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_approval_watch_ids",
                    false,
                    None,
                    None,
                    correlation_id.clone(),
                ))
            })?;
        let position = match request.resume_after {
            Some(ref value) => {
                validate_minimum_position(value)
                    .map_err(|failure| Box::new(gate_error(failure, correlation_id.clone())))?;
                value.clone()
            }
            None => {
                self.reader
                    .status()
                    .await
                    .map_err(|error| Box::new(read_error(error, correlation_id.clone())))?
                    .position
            }
        };
        let mut pending = VecDeque::new();
        if request.resume_after.is_none() {
            let status = self
                .reader
                .status()
                .await
                .map_err(|error| Box::new(read_error(error, correlation_id.clone())))?;
            evaluate_status(&status, None)
                .map_err(|failure| Box::new(gate_error(failure, correlation_id.clone())))?;
            pending.push_back(HarnessApprovalViewStreamFrame {
                kind: StreamFrameKind::Heartbeat as i32,
                position: Some(status.position),
                snapshot: None,
                reset_reason_code: None,
            });
        }
        Ok(ApprovalWatchSubscription {
            app: Arc::clone(self),
            peer,
            metadata: request.client.ok_or_else(|| {
                Box::new(api_error(
                    LocalApiErrorCode::InvalidArgument,
                    "invalid_client_metadata",
                    false,
                    None,
                    None,
                    correlation_id.clone(),
                ))
            })?,
            filter: ApprovalListFilter {
                request_lifecycles,
                decision_states,
                task_ids,
                actionable_only: request.actionable_only,
            },
            approval_request_ids,
            position,
            pending,
            pending_observed: None,
            notifier: self.minimum_gate.subscribe(),
            next_heartbeat: Instant::now() + self.token_codec.policy().watch_heartbeat_interval(),
            heartbeat_interval: self.token_codec.policy().watch_heartbeat_interval(),
            terminated: false,
            _authorized_principal_id: context.session.authenticated_principal_id,
        })
    }

    fn authorize(
        &self,
        peer: Option<&PeerConnectionInfo>,
        metadata: Option<&ClientRequestMetadata>,
        rpc: &str,
    ) -> Result<ReadRequestContext, AuthorizationFailure> {
        let peer = peer.ok_or(AuthorizationFailure::Unauthenticated)?;
        if validate_client_metadata(metadata).is_err() {
            return Err(AuthorizationFailure::InvalidArgument);
        }
        let session = self
            .registry
            .authenticate(metadata, peer)
            .map_err(AuthorizationFailure::Session)?;
        self.profiles
            .authorize_rpc(rpc, &session.permission_codes)
            .map_err(AuthorizationFailure::Profile)?;
        Ok(ReadRequestContext { session })
    }

    fn audit_evidence(
        &self,
        session: &AuthenticatedSession,
        correlation_id: &str,
        safe_outcome_code: &'static str,
    ) {
        self.audit.record(ReadGatewayAuditEvent {
            kind: ReadGatewayAuditKind::SensitiveEvidenceRead,
            rpc: RPC_GET_EVIDENCE,
            authenticated_principal_id: session.authenticated_principal_id.clone(),
            correlation_id: correlation_id.to_owned(),
            safe_outcome_code,
        });
    }

    fn audit_reset(
        &self,
        rpc: &'static str,
        session: &AuthenticatedSession,
        correlation_id: &str,
        safe_outcome_code: &'static str,
    ) {
        self.audit.record(ReadGatewayAuditEvent {
            kind: ReadGatewayAuditKind::ProjectionResetRequired,
            rpc,
            authenticated_principal_id: session.authenticated_principal_id.clone(),
            correlation_id: correlation_id.to_owned(),
            safe_outcome_code,
        });
    }

    fn audit_gate_failure(
        &self,
        rpc: &'static str,
        session: &AuthenticatedSession,
        correlation_id: &str,
        failure: &ProjectionGateFailure,
    ) {
        if failure.kind == ProjectionGateFailureKind::ResetRequired {
            self.audit_reset(
                rpc,
                session,
                correlation_id,
                "minimum_position_reset_required",
            );
        }
    }

    fn audit_deferred_failure(
        &self,
        rpc: &'static str,
        session: &AuthenticatedSession,
        correlation_id: &str,
        failure: &DeferredApiError,
    ) {
        if failure.code == LocalApiErrorCode::ProjectionResetRequired {
            self.audit_reset(rpc, session, correlation_id, "cursor_reset_required");
        }
    }

    fn resolve_task_cursor(
        &self,
        token: Option<&str>,
        minimum: Option<&ProjectionPosition>,
        scope: &ReadTokenScope,
        status: &ReadModelStatus,
        filter_sha256: &str,
        page_size: u32,
    ) -> Result<(ProjectionPosition, Option<CursorAnchor>), DeferredApiError> {
        let Some(token) = token else {
            return Ok((status.position.clone(), None));
        };
        let verified = self
            .token_codec
            .verify_cursor(
                token,
                scope,
                &CursorExpectation {
                    collection: CursorCollection::TaskViews,
                    filter_sha256: filter_sha256.to_owned(),
                    sort: CursorSort::TaskUpdatedAtDescTaskIdAsc,
                    effective_page_size: page_size,
                    current_epoch: status.position.epoch.clone(),
                    retention_floor: status.retention_floor.sequence,
                },
            )
            .map_err(DeferredApiError::from_token)?;
        resolve_verified_cursor(verified, minimum)
    }

    fn resolve_approval_cursor(
        &self,
        token: Option<&str>,
        minimum: Option<&ProjectionPosition>,
        scope: &ReadTokenScope,
        status: &ReadModelStatus,
        filter_sha256: &str,
        page_size: u32,
    ) -> Result<(ProjectionPosition, Option<CursorAnchor>), DeferredApiError> {
        let Some(token) = token else {
            return Ok((status.position.clone(), None));
        };
        let verified = self
            .token_codec
            .verify_cursor(
                token,
                scope,
                &CursorExpectation {
                    collection: CursorCollection::HarnessApprovalViews,
                    filter_sha256: filter_sha256.to_owned(),
                    sort: CursorSort::ApprovalProjectionSequenceDescApprovalRequestIdAsc,
                    effective_page_size: page_size,
                    current_epoch: status.position.epoch.clone(),
                    retention_floor: status.retention_floor.sequence,
                },
            )
            .map_err(DeferredApiError::from_token)?;
        resolve_verified_cursor(verified, minimum)
    }
}

struct ReadRequestContext {
    session: AuthenticatedSession,
}

pub struct TaskWatchSubscription {
    app: Arc<ReadGatewayApplication>,
    peer: PeerConnectionInfo,
    metadata: ClientRequestMetadata,
    filter: TaskListFilter,
    task_ids: Vec<String>,
    position: ProjectionPosition,
    pending: VecDeque<TaskViewStreamFrame>,
    pending_observed: Option<ProjectionPosition>,
    notifier: watch::Receiver<ProjectionPosition>,
    next_heartbeat: Instant,
    heartbeat_interval: Duration,
    terminated: bool,
    _authorized_principal_id: String,
}

impl TaskWatchSubscription {
    pub async fn next_frame(&mut self) -> Result<Option<TaskViewStreamFrame>, Box<LocalApiError>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                if let Some(position) = frame.position.clone() {
                    self.position = position;
                }
                if self.pending.is_empty()
                    && let Some(observed) = self.pending_observed.take()
                {
                    self.position = observed;
                }
                self.next_heartbeat = Instant::now() + self.heartbeat_interval;
                if frame.kind == StreamFrameKind::ResetRequired as i32 {
                    self.terminated = true;
                }
                return Ok(Some(frame));
            }
            if self.terminated {
                return Ok(None);
            }
            let context = self
                .app
                .authorize(Some(&self.peer), Some(&self.metadata), RPC_WATCH_TASKS)
                .map_err(|failure| {
                    Box::new(failure.into_error(correlation_id(Some(&self.metadata))))
                })?;
            let batch = self
                .app
                .reader
                .task_frames_after(
                    self.position.clone(),
                    self.filter.clone(),
                    self.task_ids.clone(),
                    task_access(&context.session.permission_codes),
                )
                .await
                .map_err(|error| {
                    Box::new(read_error(error, correlation_id(Some(&self.metadata))))
                })?;
            if !batch.frames.is_empty() {
                self.pending = batch.frames.into();
                self.pending_observed = Some(batch.observed_position);
                continue;
            }
            self.position = batch.observed_position;
            if Instant::now() >= self.next_heartbeat {
                return Ok(Some(TaskViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(self.position.clone()),
                    snapshot: None,
                    reset_reason_code: None,
                }));
            }
            let mut sleep = Box::pin(tokio::time::sleep_until(self.next_heartbeat));
            tokio::select! {
                changed = self.notifier.changed() => {
                    if changed.is_err() {
                        return Ok(None);
                    }
                }
                _ = &mut sleep => {}
            }
        }
    }
}

pub struct ApprovalWatchSubscription {
    app: Arc<ReadGatewayApplication>,
    peer: PeerConnectionInfo,
    metadata: ClientRequestMetadata,
    filter: ApprovalListFilter,
    approval_request_ids: Vec<String>,
    position: ProjectionPosition,
    pending: VecDeque<HarnessApprovalViewStreamFrame>,
    pending_observed: Option<ProjectionPosition>,
    notifier: watch::Receiver<ProjectionPosition>,
    next_heartbeat: Instant,
    heartbeat_interval: Duration,
    terminated: bool,
    _authorized_principal_id: String,
}

impl ApprovalWatchSubscription {
    pub async fn next_frame(
        &mut self,
    ) -> Result<Option<HarnessApprovalViewStreamFrame>, Box<LocalApiError>> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                if let Some(position) = frame.position.clone() {
                    self.position = position;
                }
                if self.pending.is_empty()
                    && let Some(observed) = self.pending_observed.take()
                {
                    self.position = observed;
                }
                self.next_heartbeat = Instant::now() + self.heartbeat_interval;
                if frame.kind == StreamFrameKind::ResetRequired as i32 {
                    self.terminated = true;
                }
                return Ok(Some(frame));
            }
            if self.terminated {
                return Ok(None);
            }
            let context = self
                .app
                .authorize(Some(&self.peer), Some(&self.metadata), RPC_WATCH_APPROVALS)
                .map_err(|failure| {
                    Box::new(failure.into_error(correlation_id(Some(&self.metadata))))
                })?;
            let batch = self
                .app
                .reader
                .approval_frames_after(
                    self.position.clone(),
                    self.filter.clone(),
                    self.approval_request_ids.clone(),
                    approval_access(&context.session.permission_codes),
                )
                .await
                .map_err(|error| {
                    Box::new(read_error(error, correlation_id(Some(&self.metadata))))
                })?;
            if !batch.frames.is_empty() {
                self.pending = batch.frames.into();
                self.pending_observed = Some(batch.observed_position);
                continue;
            }
            self.position = batch.observed_position;
            if Instant::now() >= self.next_heartbeat {
                return Ok(Some(HarnessApprovalViewStreamFrame {
                    kind: StreamFrameKind::Heartbeat as i32,
                    position: Some(self.position.clone()),
                    snapshot: None,
                    reset_reason_code: None,
                }));
            }
            let mut sleep = Box::pin(tokio::time::sleep_until(self.next_heartbeat));
            tokio::select! {
                changed = self.notifier.changed() => {
                    if changed.is_err() {
                        return Ok(None);
                    }
                }
                _ = &mut sleep => {}
            }
        }
    }
}

struct DeferredApiError {
    code: LocalApiErrorCode,
    fingerprint: &'static str,
    retryable: bool,
    action: Option<&'static str>,
    current_position: Option<ProjectionPosition>,
}

impl DeferredApiError {
    fn from_token(error: ReadTokenError) -> Self {
        match error {
            ReadTokenError::Expired => Self {
                code: LocalApiErrorCode::CursorExpired,
                fingerprint: "cursor_expired",
                retryable: false,
                action: Some("RESET_AND_REFETCH"),
                current_position: None,
            },
            ReadTokenError::ResetRequired => Self {
                code: LocalApiErrorCode::ProjectionResetRequired,
                fingerprint: "cursor_snapshot_reset_required",
                retryable: true,
                action: Some("RESET_AND_REFETCH"),
                current_position: None,
            },
            ReadTokenError::InvalidToken
            | ReadTokenError::ScopeMismatch
            | ReadTokenError::BindingMismatch => Self {
                code: LocalApiErrorCode::CursorInvalid,
                fingerprint: "cursor_invalid",
                retryable: false,
                action: Some("RESET_AND_REFETCH"),
                current_position: None,
            },
            ReadTokenError::InvalidConfiguration | ReadTokenError::InvalidInput => Self {
                code: LocalApiErrorCode::IntegrityFailure,
                fingerprint: "read_token_configuration_failure",
                retryable: false,
                action: Some("RESTART_DAEMON"),
                current_position: None,
            },
        }
    }

    fn with_correlation(self, correlation_id: String) -> LocalApiError {
        api_error(
            self.code,
            self.fingerprint,
            self.retryable,
            self.action,
            self.current_position,
            correlation_id,
        )
    }
}

enum AuthorizationFailure {
    InvalidArgument,
    Unauthenticated,
    Session(SessionAuthenticationFailure),
    Profile(ContractProfileError),
}

impl AuthorizationFailure {
    fn into_error(self, correlation_id: String) -> LocalApiError {
        let (code, fingerprint, retryable, action) = match self {
            Self::InvalidArgument => (
                LocalApiErrorCode::InvalidArgument,
                "invalid_client_metadata",
                false,
                None,
            ),
            Self::Unauthenticated => (
                LocalApiErrorCode::Unauthenticated,
                "peer_identity_missing",
                false,
                Some("REOPEN_SESSION"),
            ),
            Self::Session(failure) => match failure {
                SessionAuthenticationFailure::ContractMismatch => (
                    LocalApiErrorCode::ContractIncompatible,
                    "session_contract_mismatch",
                    false,
                    Some("RENEGOTIATE_CONTRACT"),
                ),
                SessionAuthenticationFailure::Expired => (
                    LocalApiErrorCode::SessionExpired,
                    "session_expired",
                    true,
                    Some("REOPEN_SESSION"),
                ),
                SessionAuthenticationFailure::PolicyUnavailable => (
                    LocalApiErrorCode::AuthorityUnavailable,
                    "authorization_policy_unavailable",
                    true,
                    Some("RETRY"),
                ),
                SessionAuthenticationFailure::IntegrityFailure => (
                    LocalApiErrorCode::IntegrityFailure,
                    "session_registry_integrity_failure",
                    false,
                    Some("RESTART_DAEMON"),
                ),
                SessionAuthenticationFailure::Revoked
                | SessionAuthenticationFailure::PolicyDrift => (
                    LocalApiErrorCode::PermissionDenied,
                    "session_authorization_changed",
                    false,
                    Some("REOPEN_SESSION"),
                ),
                SessionAuthenticationFailure::MissingMetadata
                | SessionAuthenticationFailure::NotFound
                | SessionAuthenticationFailure::PeerMismatch
                | SessionAuthenticationFailure::ClientBindingMismatch => (
                    LocalApiErrorCode::Unauthenticated,
                    "session_authentication_failed",
                    false,
                    Some("REOPEN_SESSION"),
                ),
            },
            Self::Profile(ContractProfileError::PermissionDenied(_)) => (
                LocalApiErrorCode::PermissionDenied,
                "rpc_permission_denied",
                false,
                None,
            ),
            Self::Profile(_) => (
                LocalApiErrorCode::UnknownCriticalSemantics,
                "authorization_profile_semantics_unknown",
                false,
                Some("UPDATE_OR_REPAIR"),
            ),
        };
        api_error(code, fingerprint, retryable, action, None, correlation_id)
    }
}

impl MinimumPositionGate {
    #[must_use]
    pub fn new(notifier: ProjectionCommitNotifier, policy: &ReadGatewayPolicy) -> Self {
        Self {
            notifier,
            wait_timeout: policy.minimum_position_wait_timeout(),
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ProjectionPosition> {
        self.notifier.subscribe()
    }

    pub async fn wait<R>(
        &self,
        reader: &R,
        minimum: Option<&ProjectionPosition>,
    ) -> Result<ReadModelStatus, ProjectionGateFailure>
    where
        R: ProjectionStatusReader + ?Sized,
    {
        if let Some(minimum) = minimum {
            validate_minimum_position(minimum)?;
        }

        // Subscribe before the first truth read so a commit between those two
        // operations is either observed in the query or retained by watch.
        let mut commits = self.notifier.subscribe();
        let deadline = Instant::now() + self.wait_timeout;

        loop {
            let status = reader.status().await.map_err(map_reader_failure)?;
            evaluate_status(&status, minimum)?;
            if minimum.is_none_or(|value| status.position.sequence >= value.sequence) {
                return Ok(status);
            }

            if tokio::time::timeout_at(deadline, commits.changed())
                .await
                .is_err()
            {
                // The server cap is resolved by one final database truth read.
                // A notification is never accepted as proof of projection state.
                let final_status = reader.status().await.map_err(map_reader_failure)?;
                evaluate_status(&final_status, minimum)?;
                if minimum.is_none_or(|value| final_status.position.sequence >= value.sequence) {
                    return Ok(final_status);
                }
                return Err(ProjectionGateFailure {
                    kind: ProjectionGateFailureKind::Behind,
                    current_position: Some(final_status.position),
                });
            }
        }
    }
}

fn validate_minimum_position(minimum: &ProjectionPosition) -> Result<(), ProjectionGateFailure> {
    if minimum.epoch.trim().is_empty()
        || minimum.epoch.len() > MAX_EPOCH_BYTES
        || minimum.epoch.chars().any(char::is_control)
        || minimum
            .projected_at
            .is_some_and(|value| value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos))
    {
        Err(ProjectionGateFailure {
            kind: ProjectionGateFailureKind::InvalidMinimumPosition,
            current_position: None,
        })
    } else {
        Ok(())
    }
}

fn evaluate_status(
    status: &ReadModelStatus,
    minimum: Option<&ProjectionPosition>,
) -> Result<(), ProjectionGateFailure> {
    let failed = |kind| {
        Err(ProjectionGateFailure {
            kind,
            current_position: Some(status.position.clone()),
        })
    };

    match status.health {
        ProjectionHealth::Ready | ProjectionHealth::CatchingUp => {}
        ProjectionHealth::Rebuilding => {
            return failed(ProjectionGateFailureKind::ResetRequired);
        }
        ProjectionHealth::Held => return failed(ProjectionGateFailureKind::Held),
        ProjectionHealth::IntegrityFailed | ProjectionHealth::Unspecified => {
            return failed(ProjectionGateFailureKind::IntegrityFailure);
        }
    }

    if minimum.is_some_and(|value| value.epoch != status.position.epoch) {
        return failed(ProjectionGateFailureKind::ResetRequired);
    }
    Ok(())
}

fn map_reader_failure(error: ReadModelAccessError) -> ProjectionGateFailure {
    let kind = match error {
        ReadModelAccessError::Projection(_) | ReadModelAccessError::WorkerFailed => {
            ProjectionGateFailureKind::IntegrityFailure
        }
        ReadModelAccessError::Unavailable => ProjectionGateFailureKind::Unavailable,
    };
    ProjectionGateFailure {
        kind,
        current_position: None,
    }
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_client_metadata(metadata: Option<&ClientRequestMetadata>) -> Result<(), ()> {
    let metadata = metadata.ok_or(())?;
    validate_identifier(&metadata.request_id)?;
    if let Some(correlation_id) = metadata.correlation_id.as_deref() {
        validate_identifier(correlation_id)?;
    }
    Ok(())
}

fn correlation_id(metadata: Option<&ClientRequestMetadata>) -> String {
    metadata
        .and_then(|value| value.correlation_id.as_deref())
        .filter(|value| validate_identifier(value).is_ok())
        .map_or_else(|| Uuid::now_v7().to_string(), str::to_owned)
}

fn task_access(permissions: &BTreeSet<String>) -> TaskViewAccess {
    TaskViewAccess {
        can_read: permissions.contains("local.task.read"),
        can_request_cancellation: permissions.contains("local.task.cancellation.request"),
        // These branches are system-only in the frozen authorization profile.
        can_resume: false,
        can_revise: false,
        can_issue_founder_verdict: permissions.contains("local.founder-verdict.issue"),
    }
}

fn approval_access(permissions: &BTreeSet<String>) -> ApprovalViewAccess {
    ApprovalViewAccess {
        can_read: permissions.contains("local.approval.read"),
        can_decide: permissions.contains("local.approval.decide"),
    }
}

fn status_metadata(status: &ReadModelStatus) -> ProjectionMetadata {
    ProjectionMetadata {
        schema_ref: Some(ContractReference {
            contract_id: PROJECTION_STATUS_SCHEMA_ID.to_owned(),
            version: API_CONTRACT_VERSION.to_owned(),
            sha256: API_CONTRACT_DIGEST_SHA256.to_owned(),
        }),
        position: Some(status.position.clone()),
        source_revisions: Vec::new(),
        health: status.health as i32,
        stale: status.health != ProjectionHealth::Ready,
        safe_health_reason_code: match status.health {
            ProjectionHealth::Ready => None,
            ProjectionHealth::CatchingUp => Some("PROJECTION_CATCHING_UP".to_owned()),
            ProjectionHealth::Rebuilding => Some("PROJECTION_REBUILDING".to_owned()),
            ProjectionHealth::Held => Some("PROJECTION_HELD".to_owned()),
            ProjectionHealth::IntegrityFailed => Some("PROJECTION_INTEGRITY_FAILED".to_owned()),
            ProjectionHealth::Unspecified => Some("PROJECTION_HEALTH_UNKNOWN".to_owned()),
        },
    }
}

fn gate_error(failure: ProjectionGateFailure, correlation_id: String) -> LocalApiError {
    let (code, fingerprint, retryable, action) = match failure.kind {
        ProjectionGateFailureKind::InvalidMinimumPosition => (
            LocalApiErrorCode::InvalidArgument,
            "invalid_minimum_position",
            false,
            None,
        ),
        ProjectionGateFailureKind::Behind => (
            LocalApiErrorCode::ProjectionBehind,
            "projection_minimum_not_reached",
            true,
            Some("RETRY_OR_AWAIT"),
        ),
        ProjectionGateFailureKind::ResetRequired => (
            LocalApiErrorCode::ProjectionResetRequired,
            "projection_epoch_reset_required",
            true,
            Some("RESET_AND_REFETCH"),
        ),
        ProjectionGateFailureKind::Held => (
            LocalApiErrorCode::ProjectionHeld,
            "projection_held",
            true,
            Some("RESOLVE_PROJECTION_HOLD"),
        ),
        ProjectionGateFailureKind::IntegrityFailure => (
            LocalApiErrorCode::IntegrityFailure,
            "projection_integrity_failure",
            false,
            Some("REBUILD_PROJECTION"),
        ),
        ProjectionGateFailureKind::Unavailable => (
            LocalApiErrorCode::AuthorityUnavailable,
            "projection_reader_unavailable",
            true,
            Some("RETRY"),
        ),
    };
    api_error(
        code,
        fingerprint,
        retryable,
        action,
        failure.current_position,
        correlation_id,
    )
}

fn read_error(error: ReadModelAccessError, correlation_id: String) -> LocalApiError {
    use egopulse_local_read_model::ProjectionFailure;

    let (code, fingerprint, retryable, action) = match error {
        ReadModelAccessError::Projection(ProjectionFailure::PermissionDenied) => (
            LocalApiErrorCode::PermissionDenied,
            "read_model_permission_denied",
            false,
            None,
        ),
        ReadModelAccessError::Projection(
            ProjectionFailure::SnapshotEpochMismatch
            | ProjectionFailure::SnapshotAhead
            | ProjectionFailure::SnapshotBeforeRetention { .. },
        ) => (
            LocalApiErrorCode::ProjectionResetRequired,
            "projection_snapshot_reset_required",
            true,
            Some("RESET_AND_REFETCH"),
        ),
        ReadModelAccessError::Unavailable => (
            LocalApiErrorCode::AuthorityUnavailable,
            "projection_reader_unavailable",
            true,
            Some("RETRY"),
        ),
        ReadModelAccessError::Projection(_) | ReadModelAccessError::WorkerFailed => (
            LocalApiErrorCode::IntegrityFailure,
            "projection_read_integrity_failure",
            false,
            Some("REBUILD_PROJECTION"),
        ),
    };
    api_error(code, fingerprint, retryable, action, None, correlation_id)
}

fn read_error_is_reset(error: &ReadModelAccessError) -> bool {
    use egopulse_local_read_model::ProjectionFailure;

    matches!(
        error,
        ReadModelAccessError::Projection(
            ProjectionFailure::SnapshotEpochMismatch
                | ProjectionFailure::SnapshotAhead
                | ProjectionFailure::SnapshotBeforeRetention { .. }
        )
    )
}

fn token_error(error: ReadTokenError, correlation_id: String) -> LocalApiError {
    DeferredApiError::from_token(error).with_correlation(correlation_id)
}

fn await_token_error(error: ReadTokenError, correlation_id: String) -> LocalApiError {
    let (code, fingerprint, retryable, action) = match error {
        ReadTokenError::Expired => (
            LocalApiErrorCode::CursorExpired,
            "await_token_expired",
            false,
            Some("RETRY_COMMAND"),
        ),
        ReadTokenError::InvalidToken
        | ReadTokenError::ScopeMismatch
        | ReadTokenError::BindingMismatch => (
            LocalApiErrorCode::CursorInvalid,
            "await_token_invalid",
            false,
            Some("RETRY_COMMAND"),
        ),
        ReadTokenError::ResetRequired => (
            LocalApiErrorCode::ProjectionResetRequired,
            "await_token_projection_reset_required",
            true,
            Some("RESET_AND_REFETCH"),
        ),
        ReadTokenError::InvalidConfiguration | ReadTokenError::InvalidInput => (
            LocalApiErrorCode::IntegrityFailure,
            "await_token_configuration_failure",
            false,
            Some("RESTART_DAEMON"),
        ),
    };
    api_error(code, fingerprint, retryable, action, None, correlation_id)
}

fn resolve_verified_cursor(
    cursor: VerifiedCursor,
    minimum: Option<&ProjectionPosition>,
) -> Result<(ProjectionPosition, Option<CursorAnchor>), DeferredApiError> {
    let snapshot = ProjectionPosition {
        epoch: cursor.snapshot_epoch,
        sequence: cursor.snapshot_sequence,
        projected_at: None,
    };
    // A cursor freezes the snapshot. A later minimum cannot be satisfied by
    // silently advancing it because that would create duplicate/missing rows.
    if minimum
        .is_some_and(|value| value.epoch != snapshot.epoch || value.sequence > snapshot.sequence)
    {
        return Err(DeferredApiError {
            code: LocalApiErrorCode::InvalidArgument,
            fingerprint: "minimum_exceeds_cursor_snapshot",
            retryable: false,
            action: Some("RESET_AND_REFETCH"),
            current_position: Some(snapshot),
        });
    }
    Ok((snapshot, Some(cursor.anchor)))
}

fn normalize_enum_filter<T>(values: &[i32]) -> Result<Vec<i32>, ()>
where
    T: TryFrom<i32>,
{
    let mut normalized = BTreeSet::new();
    for value in values {
        if *value == 0 || T::try_from(*value).is_err() {
            return Err(());
        }
        normalized.insert(*value);
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_identifiers(values: &[String]) -> Result<Vec<String>, ()> {
    let mut normalized = BTreeSet::new();
    for value in values {
        validate_identifier(value)?;
        normalized.insert(value.clone());
    }
    Ok(normalized.into_iter().collect())
}

#[derive(Serialize)]
struct TaskFilterMaterial<'a> {
    statuses: &'a [i32],
}

#[derive(Serialize)]
struct ApprovalFilterMaterial<'a> {
    request_lifecycles: &'a [i32],
    decision_states: &'a [i32],
    task_ids: &'a [String],
    actionable_only: bool,
}

fn digest_filter(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn task_anchor(view: &TaskView) -> Result<CursorAnchor, ()> {
    let task = view.task.as_ref().ok_or(())?;
    let updated_at = task.updated_at.as_ref().ok_or(())?;
    if validate_identifier(&task.task_id).is_err()
        || updated_at.seconds < 0
        || !(0..1_000_000_000).contains(&updated_at.nanos)
    {
        return Err(());
    }
    Ok(CursorAnchor::Task {
        updated_at_seconds: updated_at.seconds,
        updated_at_nanos: updated_at.nanos,
        task_id: task.task_id.clone(),
    })
}

fn approval_anchor(view: &HarnessApprovalView) -> Result<CursorAnchor, ()> {
    let sequence = view
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.position.as_ref())
        .map(|position| position.sequence)
        .ok_or(())?;
    validate_identifier(&view.approval_request_id)?;
    Ok(CursorAnchor::HarnessApproval {
        projection_sequence: sequence,
        approval_request_id: view.approval_request_id.clone(),
    })
}

fn task_page_start(items: &[TaskView], anchor: Option<&CursorAnchor>) -> Result<usize, ()> {
    let anchors = items
        .iter()
        .map(task_anchor)
        .collect::<Result<Vec<_>, _>>()?;
    let Some(anchor) = anchor else {
        return Ok(0);
    };
    anchors
        .iter()
        .position(|value| value == anchor)
        .map(|index| index + 1)
        .ok_or(())
}

fn approval_page_start(
    items: &[HarnessApprovalView],
    anchor: Option<&CursorAnchor>,
) -> Result<usize, ()> {
    let anchors = items
        .iter()
        .map(approval_anchor)
        .collect::<Result<Vec<_>, _>>()?;
    let Some(anchor) = anchor else {
        return Ok(0);
    };
    anchors
        .iter()
        .position(|value| value == anchor)
        .map(|index| index + 1)
        .ok_or(())
}

fn api_error(
    code: LocalApiErrorCode,
    fingerprint: &str,
    retryable: bool,
    required_action: Option<&str>,
    current_position: Option<ProjectionPosition>,
    correlation_id: String,
) -> LocalApiError {
    LocalApiError {
        code: code as i32,
        safe_fingerprint: fingerprint.to_owned(),
        retryable,
        required_action_code: required_action.map(str::to_owned),
        current_position,
        correlation_id,
    }
}

fn task_error(error: LocalApiError) -> GetTaskViewResponse {
    GetTaskViewResponse {
        outcome: Some(get_task_view_response::Outcome::Error(error)),
    }
}

fn await_error(error: LocalApiError) -> AwaitProjectionResponse {
    AwaitProjectionResponse {
        outcome: Some(await_projection_response::Outcome::Error(error)),
    }
}

fn evidence_error(error: LocalApiError) -> GetEvidenceGraphResponse {
    GetEvidenceGraphResponse {
        outcome: Some(get_evidence_graph_response::Outcome::Error(error)),
    }
}

fn approval_error(error: LocalApiError) -> GetHarnessApprovalViewResponse {
    GetHarnessApprovalViewResponse {
        outcome: Some(get_harness_approval_view_response::Outcome::Error(error)),
    }
}

fn task_list_error(error: LocalApiError) -> ListTaskViewsResponse {
    ListTaskViewsResponse {
        views: Vec::new(),
        next_page_cursor: None,
        snapshot_position: None,
        error: Some(error),
    }
}

fn approval_list_error(error: LocalApiError) -> ListHarnessApprovalViewsResponse {
    ListHarnessApprovalViewsResponse {
        views: Vec::new(),
        next_page_cursor: None,
        snapshot_position: None,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::*;
    use crate::read_gateway_policy::ReadGatewayPolicy;

    struct FakeStatusReader {
        statuses: Mutex<VecDeque<ReadModelStatus>>,
    }

    impl FakeStatusReader {
        fn new(statuses: Vec<ReadModelStatus>) -> Self {
            Self {
                statuses: Mutex::new(statuses.into()),
            }
        }
    }

    #[tonic::async_trait]
    impl ProjectionStatusReader for FakeStatusReader {
        async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
            let mut statuses = self.statuses.lock().expect("fake status lock");
            if statuses.len() > 1 {
                Ok(statuses.pop_front().expect("status exists"))
            } else {
                Ok(statuses.front().expect("one status remains").clone())
            }
        }
    }

    fn position(epoch: &str, sequence: u64) -> ProjectionPosition {
        ProjectionPosition {
            epoch: epoch.to_owned(),
            sequence,
            projected_at: None,
        }
    }

    fn status(epoch: &str, sequence: u64, health: ProjectionHealth) -> ReadModelStatus {
        ReadModelStatus {
            position: position(epoch, sequence),
            retention_floor: position(epoch, 0),
            health,
        }
    }

    fn policy(wait: Duration) -> ReadGatewayPolicy {
        ReadGatewayPolicy::new(
            "test/v1",
            2,
            4,
            wait,
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(2),
            100,
            10,
        )
        .expect("test policy")
    }

    #[tokio::test]
    async fn already_satisfied_minimum_returns_without_waiting() {
        let notifier = ProjectionCommitNotifier::new(position("epoch-a", 7));
        let gate = MinimumPositionGate::new(notifier, &policy(Duration::from_secs(1)));
        let reader = FakeStatusReader::new(vec![status("epoch-a", 7, ProjectionHealth::Ready)]);

        let result = gate
            .wait(&reader, Some(&position("epoch-a", 7)))
            .await
            .expect("minimum is satisfied");
        assert_eq!(result.position.sequence, 7);
    }

    #[tokio::test]
    async fn commit_notification_wakes_then_database_truth_satisfies() {
        let notifier = ProjectionCommitNotifier::new(position("epoch-a", 4));
        let gate = Arc::new(MinimumPositionGate::new(
            notifier.clone(),
            &policy(Duration::from_secs(1)),
        ));
        let reader = Arc::new(FakeStatusReader::new(vec![
            status("epoch-a", 4, ProjectionHealth::CatchingUp),
            status("epoch-a", 5, ProjectionHealth::Ready),
        ]));
        let task = {
            let gate = Arc::clone(&gate);
            let reader = Arc::clone(&reader);
            tokio::spawn(async move {
                gate.wait(reader.as_ref(), Some(&position("epoch-a", 5)))
                    .await
            })
        };

        tokio::task::yield_now().await;
        notifier.publish(position("epoch-a", 5));
        let result = task.await.expect("waiter joins").expect("truth catches up");
        assert_eq!(result.position.sequence, 5);
    }

    #[tokio::test]
    async fn stale_notifications_never_claim_the_minimum_is_satisfied() {
        let notifier = ProjectionCommitNotifier::new(position("epoch-a", 4));
        let gate = Arc::new(MinimumPositionGate::new(
            notifier.clone(),
            &policy(Duration::from_millis(20)),
        ));
        let reader = Arc::new(FakeStatusReader::new(vec![status(
            "epoch-a",
            4,
            ProjectionHealth::CatchingUp,
        )]));
        let task = {
            let gate = Arc::clone(&gate);
            let reader = Arc::clone(&reader);
            tokio::spawn(async move {
                gate.wait(reader.as_ref(), Some(&position("epoch-a", 5)))
                    .await
            })
        };

        tokio::task::yield_now().await;
        notifier.publish(position("epoch-a", 4));
        let error = task.await.expect("waiter joins").expect_err("still behind");
        assert_eq!(error.kind, ProjectionGateFailureKind::Behind);
        assert_eq!(error.current_position.expect("position").sequence, 4);
    }

    #[tokio::test]
    async fn final_truth_recheck_can_succeed_without_a_notification() {
        let notifier = ProjectionCommitNotifier::new(position("epoch-a", 4));
        let gate = MinimumPositionGate::new(notifier, &policy(Duration::from_millis(10)));
        let reader = FakeStatusReader::new(vec![
            status("epoch-a", 4, ProjectionHealth::CatchingUp),
            status("epoch-a", 5, ProjectionHealth::Ready),
        ]);

        let result = gate
            .wait(&reader, Some(&position("epoch-a", 5)))
            .await
            .expect("final truth reaches minimum");
        assert_eq!(result.position.sequence, 5);
    }

    #[tokio::test]
    async fn epoch_and_health_fail_closed() {
        for (current, health, expected) in [
            (
                "epoch-b",
                ProjectionHealth::Ready,
                ProjectionGateFailureKind::ResetRequired,
            ),
            (
                "epoch-a",
                ProjectionHealth::Rebuilding,
                ProjectionGateFailureKind::ResetRequired,
            ),
            (
                "epoch-a",
                ProjectionHealth::Held,
                ProjectionGateFailureKind::Held,
            ),
            (
                "epoch-a",
                ProjectionHealth::IntegrityFailed,
                ProjectionGateFailureKind::IntegrityFailure,
            ),
            (
                "epoch-a",
                ProjectionHealth::Unspecified,
                ProjectionGateFailureKind::IntegrityFailure,
            ),
        ] {
            let notifier = ProjectionCommitNotifier::new(position(current, 4));
            let gate = MinimumPositionGate::new(notifier, &policy(Duration::from_millis(10)));
            let reader = FakeStatusReader::new(vec![status(current, 4, health)]);
            let error = gate
                .wait(&reader, Some(&position("epoch-a", 5)))
                .await
                .expect_err("state must fail closed");
            assert_eq!(error.kind, expected);
        }
    }

    #[test]
    fn enum_filters_are_validated_deduplicated_and_canonicalized() {
        assert_eq!(
            normalize_enum_filter::<TaskStatus>(&[
                TaskStatus::Completed as i32,
                TaskStatus::Active as i32,
                TaskStatus::Completed as i32,
            ]),
            Ok(vec![
                TaskStatus::Active as i32,
                TaskStatus::Completed as i32
            ])
        );
        assert!(normalize_enum_filter::<TaskStatus>(&[0]).is_err());
        assert!(normalize_enum_filter::<TaskStatus>(&[i32::MAX]).is_err());
    }

    #[test]
    fn task_pagination_requires_the_exact_frozen_anchor() {
        use egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot;
        use prost_types::Timestamp;

        let view = |id: &str, seconds: i64| TaskView {
            task: Some(TaskSnapshot {
                task_id: id.to_owned(),
                updated_at: Some(Timestamp { seconds, nanos: 0 }),
                ..TaskSnapshot::default()
            }),
            ..TaskView::default()
        };
        let items = vec![view("task-a", 3), view("task-b", 2), view("task-c", 1)];
        let anchor = task_anchor(&items[1]).expect("valid anchor");
        assert_eq!(task_page_start(&items, Some(&anchor)), Ok(2));
        assert!(
            task_page_start(
                &items,
                Some(&CursorAnchor::Task {
                    updated_at_seconds: 9,
                    updated_at_nanos: 0,
                    task_id: "missing".to_owned(),
                })
            )
            .is_err()
        );
    }

    #[test]
    fn a_later_minimum_cannot_mutate_a_cursor_snapshot() {
        let cursor = VerifiedCursor {
            collection: CursorCollection::TaskViews,
            filter_sha256: "a".repeat(64),
            sort: CursorSort::TaskUpdatedAtDescTaskIdAsc,
            effective_page_size: 2,
            snapshot_epoch: "epoch-a".to_owned(),
            snapshot_sequence: 10,
            anchor: CursorAnchor::Task {
                updated_at_seconds: 1,
                updated_at_nanos: 0,
                task_id: "task-a".to_owned(),
            },
        };
        let error = resolve_verified_cursor(cursor, Some(&position("epoch-a", 11)))
            .expect_err("snapshot cannot advance");
        assert_eq!(error.code, LocalApiErrorCode::InvalidArgument);
        assert_eq!(error.fingerprint, "minimum_exceeds_cursor_snapshot");
    }

    #[test]
    fn list_errors_never_return_partial_pages() {
        let response = task_list_error(api_error(
            LocalApiErrorCode::CursorInvalid,
            "cursor_invalid",
            false,
            Some("RESET_AND_REFETCH"),
            None,
            "correlation".to_owned(),
        ));
        assert!(response.views.is_empty());
        assert!(response.next_page_cursor.is_none());
        assert!(response.snapshot_position.is_none());
        assert!(response.error.is_some());
    }
}
