#![cfg(windows)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::{
    profiles::ContractProfiles,
    v01::egopulse::{
        common::v1::ContractReference,
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, EvidenceGraphView, GetEvidenceGraphRequest,
            GetHarnessApprovalViewRequest, GetProjectionStatusRequest, GetTaskViewRequest,
            HarnessApprovalView, ListHarnessApprovalViewsRequest, ListTaskViewsRequest,
            LocalApiErrorCode, OpenSessionRequest, ProjectionHealth, ProjectionMetadata,
            ProjectionPosition, TaskView, get_evidence_graph_response,
            get_harness_approval_view_response, get_task_view_response,
            local_session_service_server::LocalSessionService,
        },
        task::v1::TaskSnapshot,
    },
};
use egopulse_local_api::{
    read_gateway::{
        ReadGatewayApplication, ReadGatewayAuditEvent, ReadGatewayAuditKind, ReadGatewayAuditSink,
    },
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{
        ProjectionCommitNotifier, ProjectionStatusReader, ReadModelAccessError, ReadModelReader,
        ReadModelStatus,
    },
    read_tokens::{ReadTokenCodec, TokenMacKey},
    session::{
        FixedProjectionPosition, LocalSessionEndpoint, PrincipalGrant, PrincipalResolutionFailure,
        ProjectionPositionProvider, SessionAuditEvent, SessionAuditSink, SessionClock,
        SessionConfig, TrustedPrincipalResolver,
    },
};
use egopulse_local_ipc_platform::{
    LocalIpcAddress, LocalIpcClient, LocalIpcListener, OsPrincipal, PeerConnectionInfo,
};
use egopulse_local_read_model::{
    ApprovalListFilter, ApprovalViewAccess, EvidenceGraphAccess, HistoricalPage, TaskListFilter,
    TaskViewAccess,
};
use prost_types::Timestamp;
use tonic::Request;
use uuid::Uuid;

const CONTRACT_DIGEST: &str = "8eadb3686c8dfe76bf8b56fa48d8a76bd7fa57c177804b132eac793d33b7379e";
const KERNEL_DIGEST: &str = "367ad4210c499d7501acd060f5b544255521cefefca86b8d69a2cea022166c11";
const POLICY_DIGEST: &str = "5ae8cff8552910c780cdde9e29f1a5a3a95e40803ebcbb1de26544de5f6ac29f";

#[derive(Clone)]
struct FixedClock(SystemTime);

impl SessionClock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

#[derive(Clone)]
struct Resolver {
    peer: OsPrincipal,
    grant: PrincipalGrant,
}

impl TrustedPrincipalResolver for Resolver {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        if principal == &self.peer {
            Ok(self.grant.clone())
        } else {
            Err(PrincipalResolutionFailure::PermissionDenied)
        }
    }
}

#[derive(Default)]
struct NoopSessionAudit;

impl SessionAuditSink for NoopSessionAudit {
    fn record(&self, _event: SessionAuditEvent) {}
}

#[derive(Default)]
struct RecordingReadAudit(Mutex<Vec<ReadGatewayAuditEvent>>);

impl ReadGatewayAuditSink for RecordingReadAudit {
    fn record(&self, event: ReadGatewayAuditEvent) {
        self.0.lock().expect("audit lock").push(event);
    }
}

struct FakeReadModel {
    status: ReadModelStatus,
    tasks: Vec<TaskView>,
    approvals: Vec<HarnessApprovalView>,
    evidence: EvidenceGraphView,
}

#[tonic::async_trait]
impl ProjectionStatusReader for FakeReadModel {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
        Ok(self.status.clone())
    }
}

#[tonic::async_trait]
impl ReadModelReader for FakeReadModel {
    async fn get_task_view(
        &self,
        task_id: String,
        _access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError> {
        Ok(self
            .tasks
            .iter()
            .find(|view| {
                view.task
                    .as_ref()
                    .is_some_and(|task| task.task_id == task_id)
            })
            .cloned())
    }

    async fn list_task_views_at(
        &self,
        snapshot: ProjectionPosition,
        filter: TaskListFilter,
        _access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError> {
        let items = self
            .tasks
            .iter()
            .filter(|view| {
                filter.statuses.is_empty()
                    || view
                        .task
                        .as_ref()
                        .is_some_and(|task| filter.statuses.contains(&task.status))
            })
            .cloned()
            .collect();
        Ok(HistoricalPage {
            snapshot_position: snapshot,
            retention_floor: self.status.retention_floor.clone(),
            items,
        })
    }

    async fn get_evidence_graph(
        &self,
        task_id: String,
        artifact_set_id: String,
        _access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError> {
        Ok(
            (self.evidence.task_id == task_id && self.evidence.artifact_set_id == artifact_set_id)
                .then(|| self.evidence.clone()),
        )
    }

    async fn get_harness_approval_view(
        &self,
        approval_request_id: String,
        _access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError> {
        Ok(self
            .approvals
            .iter()
            .find(|view| view.approval_request_id == approval_request_id)
            .cloned())
    }

    async fn list_harness_approval_views_at(
        &self,
        snapshot: ProjectionPosition,
        _filter: ApprovalListFilter,
        _access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError> {
        Ok(HistoricalPage {
            snapshot_position: snapshot,
            retention_floor: self.status.retention_floor.clone(),
            items: self.approvals.clone(),
        })
    }
}

fn contract_ref(id: &str, version: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: digest.to_owned(),
    }
}

fn api_contract() -> ContractReference {
    contract_ref("egopulse.localapi.v1", "0.1.0-draft.14", CONTRACT_DIGEST)
}

fn kernel_contract() -> ContractReference {
    contract_ref("egopulse.client-kernel.v1", "0.1.0", KERNEL_DIGEST)
}

fn founder_grant() -> PrincipalGrant {
    PrincipalGrant {
        authenticated_principal_id: "os-user:founder".to_owned(),
        permission_codes: BTreeSet::from([
            "local.approval.decide".to_owned(),
            "local.approval.read".to_owned(),
            "local.evidence.read".to_owned(),
            "local.founder-verdict.issue".to_owned(),
            "local.founder-verdict.revoke".to_owned(),
            "local.projection.await".to_owned(),
            "local.projection.status.read".to_owned(),
            "local.task.cancellation.request".to_owned(),
            "local.task.create".to_owned(),
            "local.task.read".to_owned(),
        ]),
        authorization_policy_ref: contract_ref("egopulse.authorization.v1", "0.1.0", POLICY_DIGEST),
    }
}

fn position(sequence: u64) -> ProjectionPosition {
    ProjectionPosition {
        epoch: "epoch-read-gateway".to_owned(),
        sequence,
        projected_at: None,
    }
}

fn metadata(position: ProjectionPosition) -> ProjectionMetadata {
    ProjectionMetadata {
        position: Some(position),
        health: ProjectionHealth::Ready as i32,
        ..ProjectionMetadata::default()
    }
}

fn task(id: &str, seconds: i64) -> TaskView {
    TaskView {
        metadata: Some(metadata(position(10))),
        task: Some(TaskSnapshot {
            task_id: id.to_owned(),
            updated_at: Some(Timestamp { seconds, nanos: 0 }),
            ..TaskSnapshot::default()
        }),
        ..TaskView::default()
    }
}

fn approval(id: &str, sequence: u64) -> HarnessApprovalView {
    HarnessApprovalView {
        metadata: Some(metadata(position(sequence))),
        approval_request_id: id.to_owned(),
        task_id: "task-a".to_owned(),
        ..HarnessApprovalView::default()
    }
}

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address = LocalIpcAddress::for_instance(&format!("read-gateway-{}", Uuid::now_v7()))
        .expect("address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind");
    let client = LocalIpcClient::connect(&address).await.expect("connect");
    let connection = listener.accept().await.expect("accept");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

#[tokio::test]
async fn authenticated_gateway_get_list_status_and_evidence_form_one_fail_closed_path() {
    let peer = real_peer().await;
    let clock: Arc<dyn SessionClock> = Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs(100)));
    let endpoint = LocalSessionEndpoint::new(
        SessionConfig::new(
            vec![api_contract()],
            kernel_contract(),
            Duration::from_secs(60),
        )
        .expect("session config"),
        Arc::new(Resolver {
            peer: peer.principal().clone(),
            grant: founder_grant(),
        }),
        Arc::clone(&clock),
        Arc::new(FixedProjectionPosition(position(10))) as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopSessionAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "cli-client".to_owned(),
        surface: ClientSurface::Cli as i32,
        supported_contracts: vec![api_contract()],
    };
    let mut open_request = Request::new(open.clone());
    open_request.extensions_mut().insert(peer.clone());
    let opened = endpoint
        .open_session(open_request)
        .await
        .expect("transport response")
        .into_inner();
    assert!(opened.error.is_none());

    let client = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("correlation-read-gateway".to_owned()),
    };
    let reader: Arc<dyn ReadModelReader> = Arc::new(FakeReadModel {
        status: ReadModelStatus {
            position: position(10),
            retention_floor: position(0),
            health: ProjectionHealth::Ready,
        },
        tasks: vec![task("task-a", 3), task("task-b", 2), task("task-c", 1)],
        approvals: vec![approval("approval-a", 10), approval("approval-b", 9)],
        evidence: EvidenceGraphView {
            metadata: Some(metadata(position(10))),
            task_id: "task-a".to_owned(),
            artifact_set_id: "artifact-set-a".to_owned(),
            ..EvidenceGraphView::default()
        },
    });
    let audit = Arc::new(RecordingReadAudit::default());
    let app = ReadGatewayApplication::new(
        endpoint.registry(),
        Arc::new(ContractProfiles::embedded().expect("profiles")),
        reader,
        ProjectionCommitNotifier::new(position(10)),
        Arc::new(ReadTokenCodec::new(
            TokenMacKey::new([9; 32]).expect("key"),
            ReadGatewayPolicy::v01(),
            clock,
        )),
        audit.clone(),
    );

    let get = app
        .get_task_view(
            Some(&peer),
            GetTaskViewRequest {
                client: Some(client.clone()),
                task_id: "task-a".to_owned(),
                minimum_position: Some(position(10)),
            },
        )
        .await;
    assert!(matches!(
        get.outcome,
        Some(get_task_view_response::Outcome::View(_))
    ));

    let first = app
        .list_task_views(
            Some(&peer),
            ListTaskViewsRequest {
                client: Some(client.clone()),
                status_filter: Vec::new(),
                page_size: 2,
                page_cursor: None,
                minimum_position: Some(position(10)),
            },
        )
        .await;
    assert!(first.error.is_none());
    assert_eq!(first.views.len(), 2);
    let second = app
        .list_task_views(
            Some(&peer),
            ListTaskViewsRequest {
                client: Some(client.clone()),
                status_filter: Vec::new(),
                page_size: 2,
                page_cursor: first.next_page_cursor,
                minimum_position: Some(position(10)),
            },
        )
        .await;
    assert!(second.error.is_none());
    assert_eq!(second.views.len(), 1);
    assert_eq!(
        second.views[0].task.as_ref().expect("task").task_id,
        "task-c"
    );

    let evidence = app
        .get_evidence_graph(
            Some(&peer),
            GetEvidenceGraphRequest {
                client: Some(client.clone()),
                task_id: "task-a".to_owned(),
                artifact_set_id: "artifact-set-a".to_owned(),
                minimum_position: None,
            },
        )
        .await;
    assert!(matches!(
        evidence.outcome,
        Some(get_evidence_graph_response::Outcome::Graph(_))
    ));

    let approval = app
        .get_harness_approval_view(
            Some(&peer),
            GetHarnessApprovalViewRequest {
                client: Some(client.clone()),
                approval_request_id: "approval-a".to_owned(),
                minimum_position: None,
            },
        )
        .await;
    assert!(matches!(
        approval.outcome,
        Some(get_harness_approval_view_response::Outcome::View(_))
    ));
    let approvals = app
        .list_harness_approval_views(
            Some(&peer),
            ListHarnessApprovalViewsRequest {
                client: Some(client.clone()),
                request_lifecycle_filter: Vec::new(),
                decision_state_filter: Vec::new(),
                task_ids: Vec::new(),
                actionable_only: false,
                page_size: 2,
                page_cursor: None,
                minimum_position: None,
            },
        )
        .await;
    assert!(approvals.error.is_none());
    assert_eq!(approvals.views.len(), 2);

    let status = app
        .get_projection_status(
            Some(&peer),
            GetProjectionStatusRequest {
                client: Some(client.clone()),
            },
        )
        .await;
    assert!(status.error.is_none());
    assert_eq!(
        status
            .metadata
            .and_then(|value| value.position)
            .expect("position")
            .sequence,
        10
    );

    let denied = app
        .get_task_view(
            None,
            GetTaskViewRequest {
                client: Some(client),
                task_id: "task-a".to_owned(),
                minimum_position: None,
            },
        )
        .await;
    let Some(get_task_view_response::Outcome::Error(error)) = denied.outcome else {
        panic!("missing peer must return a typed error");
    };
    assert_eq!(
        LocalApiErrorCode::try_from(error.code),
        Ok(LocalApiErrorCode::Unauthenticated)
    );

    let events = audit.0.lock().expect("audit lock");
    assert!(events.iter().any(|event| {
        event.kind == ReadGatewayAuditKind::SensitiveEvidenceRead
            && event.safe_outcome_code == "succeeded"
    }));
}
