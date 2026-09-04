#![cfg(windows)]
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::{
    profiles::{
        API_CONTRACT_DIGEST_SHA256, API_CONTRACT_ID, API_CONTRACT_VERSION,
        AUTHORIZATION_CONTRACT_ID, AUTHORIZATION_CONTRACT_VERSION,
        AUTHORIZATION_PROFILE_DIGEST_SHA256, CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION, CLIENT_KERNEL_PROFILE_DIGEST_SHA256, ContractProfiles,
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
    },
    v01::egopulse::{
        common::v1::ContractReference,
        localapi::v1::{
            ClientRequestMetadata, ClientSurface, EvidenceGraphView, HarnessApprovalView,
            HarnessContentPosition, HarnessContentRecordView, HarnessContentRecordsFrame,
            HarnessContentStreamFrame, ListHarnessContentRequest, LocalApiErrorCode,
            OpenSessionRequest, ProjectionHealth, ProjectionPosition, TaskView,
            WatchHarnessContentRequest, harness_content_stream_frame,
            list_harness_content_response, local_session_service_server::LocalSessionService,
        },
    },
};
use egopulse_local_api::{
    read_gateway::{NoopReadGatewayAuditSink, ReadGatewayApplication},
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{
        HarnessContentCommitNotifier, HarnessContentScopeAccessError, HarnessContentScopeReader,
        HarnessContentStatus, ProjectionCommitNotifier, ProjectionStatusReader,
        ReadModelAccessError, ReadModelReader, ReadModelStatus,
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
    ApprovalListFilter, ApprovalViewAccess, EvidenceGraphAccess, HarnessContentBaselineQuery,
    HarnessContentBaselineResult, HarnessContentPageCursor, HarnessContentReadAccess,
    HarnessContentWatchQuery, HarnessContentWatchResult, HistoricalPage, TaskListFilter,
    TaskViewAccess,
};
use tonic::Request;
use uuid::Uuid;

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

struct FakeContentReader {
    baseline_results: Mutex<VecDeque<HarnessContentBaselineResult>>,
    watch_results: Mutex<VecDeque<HarnessContentWatchResult>>,
    baseline_calls: AtomicUsize,
    watch_calls: AtomicUsize,
}

#[tonic::async_trait]
impl ProjectionStatusReader for FakeContentReader {
    async fn status(&self) -> Result<ReadModelStatus, ReadModelAccessError> {
        Ok(ReadModelStatus {
            position: projection_position(10),
            retention_floor: projection_position(0),
            health: ProjectionHealth::Ready,
        })
    }
}

#[tonic::async_trait]
impl ReadModelReader for FakeContentReader {
    async fn harness_content_status(&self) -> Result<HarnessContentStatus, ReadModelAccessError> {
        Ok(HarnessContentStatus {
            position: content_position(13),
            retention_floor: content_position(0),
            health: ProjectionHealth::Ready,
        })
    }

    async fn list_harness_content(
        &self,
        _query: HarnessContentBaselineQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentBaselineResult, ReadModelAccessError> {
        assert!(access.can_read_content);
        self.baseline_calls.fetch_add(1, Ordering::SeqCst);
        self.baseline_results
            .lock()
            .expect("baseline result lock")
            .pop_front()
            .ok_or(ReadModelAccessError::Unavailable)
    }

    async fn watch_harness_content(
        &self,
        _query: HarnessContentWatchQuery,
        access: HarnessContentReadAccess,
    ) -> Result<HarnessContentWatchResult, ReadModelAccessError> {
        assert!(access.can_read_content);
        self.watch_calls.fetch_add(1, Ordering::SeqCst);
        self.watch_results
            .lock()
            .expect("watch result lock")
            .pop_front()
            .ok_or(ReadModelAccessError::Unavailable)
    }

    async fn get_task_view(
        &self,
        _task_id: String,
        _access: TaskViewAccess,
    ) -> Result<Option<TaskView>, ReadModelAccessError> {
        Err(ReadModelAccessError::Unavailable)
    }

    async fn list_task_views_at(
        &self,
        _snapshot: ProjectionPosition,
        _filter: TaskListFilter,
        _access: TaskViewAccess,
    ) -> Result<HistoricalPage<TaskView>, ReadModelAccessError> {
        Err(ReadModelAccessError::Unavailable)
    }

    async fn get_evidence_graph(
        &self,
        _task_id: String,
        _artifact_set_id: String,
        _access: EvidenceGraphAccess,
    ) -> Result<Option<EvidenceGraphView>, ReadModelAccessError> {
        Err(ReadModelAccessError::Unavailable)
    }

    async fn get_harness_approval_view(
        &self,
        _approval_request_id: String,
        _access: ApprovalViewAccess,
    ) -> Result<Option<HarnessApprovalView>, ReadModelAccessError> {
        Err(ReadModelAccessError::Unavailable)
    }

    async fn list_harness_approval_views_at(
        &self,
        _snapshot: ProjectionPosition,
        _filter: ApprovalListFilter,
        _access: ApprovalViewAccess,
    ) -> Result<HistoricalPage<HarnessApprovalView>, ReadModelAccessError> {
        Err(ReadModelAccessError::Unavailable)
    }
}

struct ScriptedScopeReader {
    owners: Mutex<VecDeque<String>>,
    fallback_owner: String,
    calls: AtomicUsize,
}

impl ScriptedScopeReader {
    fn stable(owner: &str) -> Self {
        Self {
            owners: Mutex::new(VecDeque::new()),
            fallback_owner: owner.to_owned(),
            calls: AtomicUsize::new(0),
        }
    }

    fn with_owners(owners: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            owners: Mutex::new(owners.into_iter().map(str::to_owned).collect()),
            fallback_owner: "os-user:other".to_owned(),
            calls: AtomicUsize::new(0),
        }
    }
}

#[tonic::async_trait]
impl HarnessContentScopeReader for ScriptedScopeReader {
    async fn task_owner_principal_id(
        &self,
        _task_id: String,
    ) -> Result<Option<String>, HarnessContentScopeAccessError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(
            self.owners
                .lock()
                .expect("owner script lock")
                .pop_front()
                .unwrap_or_else(|| self.fallback_owner.clone()),
        ))
    }

    async fn task_id_for_attempt(
        &self,
        _attempt_id: String,
    ) -> Result<Option<String>, HarnessContentScopeAccessError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some("task-001".to_owned()))
    }
}

fn contract_ref(id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn api_contract() -> ContractReference {
    contract_ref(
        API_CONTRACT_ID,
        API_CONTRACT_VERSION,
        API_CONTRACT_DIGEST_SHA256,
    )
}

fn kernel_contract() -> ContractReference {
    contract_ref(
        CLIENT_KERNEL_CONTRACT_ID,
        CLIENT_KERNEL_CONTRACT_VERSION,
        CLIENT_KERNEL_PROFILE_DIGEST_SHA256,
    )
}

fn projection_position(sequence: u64) -> ProjectionPosition {
    ProjectionPosition {
        epoch: "task-epoch".to_owned(),
        sequence,
        projected_at: None,
    }
}

fn content_position(sequence: u64) -> HarnessContentPosition {
    HarnessContentPosition {
        epoch: "content-epoch".to_owned(),
        sequence,
        projected_at: None,
    }
}

fn content_record(sequence: u64) -> HarnessContentRecordView {
    HarnessContentRecordView {
        record_id: format!("hcr-{sequence}"),
        record_digest_sha256: format!("{sequence:064x}"),
        content_sequence: sequence,
        task_id: "task-001".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        provider_family_alias: "gpt".to_owned(),
        model_alias: "gpt-codex".to_owned(),
        collaboration_role: "primary".to_owned(),
        disclosure_profile_ref: Some(contract_ref(
            HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
            HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
        )),
        ..HarnessContentRecordView::default()
    }
}

async fn real_peer() -> PeerConnectionInfo {
    use tonic::transport::server::Connected;

    let address = LocalIpcAddress::for_instance(&format!("content-gateway-{}", Uuid::now_v7()))
        .expect("address");
    let mut listener = LocalIpcListener::bind(address.clone()).expect("bind");
    let client = LocalIpcClient::connect(&address).await.expect("connect");
    let connection = listener.accept().await.expect("accept");
    let peer = connection.connect_info();
    drop(connection);
    drop(client);
    peer
}

async fn application(
    reader: Arc<FakeContentReader>,
    scope: Arc<ScriptedScopeReader>,
    grant_content: bool,
) -> (
    PeerConnectionInfo,
    ClientRequestMetadata,
    Arc<ReadGatewayApplication>,
) {
    let peer = real_peer().await;
    let mut permissions = BTreeSet::from(["local.task.read".to_owned()]);
    if grant_content {
        permissions.insert("local.harness.content.read".to_owned());
    }
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
            grant: PrincipalGrant {
                authenticated_principal_id: "os-user:founder".to_owned(),
                permission_codes: permissions,
                authorization_policy_ref: contract_ref(
                    AUTHORIZATION_CONTRACT_ID,
                    AUTHORIZATION_CONTRACT_VERSION,
                    AUTHORIZATION_PROFILE_DIGEST_SHA256,
                ),
            },
        }),
        Arc::clone(&clock),
        Arc::new(FixedProjectionPosition(projection_position(10)))
            as Arc<dyn ProjectionPositionProvider>,
        Arc::new(NoopSessionAudit),
    );
    let open = OpenSessionRequest {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: "r9c-client".to_owned(),
        surface: ClientSurface::Cli as i32,
        supported_contracts: vec![api_contract()],
    };
    let mut request = Request::new(open.clone());
    request.extensions_mut().insert(peer.clone());
    let opened = endpoint
        .open_session(request)
        .await
        .expect("open response")
        .into_inner();
    assert!(opened.error.is_none());
    let metadata = ClientRequestMetadata {
        request_id: Uuid::now_v7().to_string(),
        client_instance_id: open.client_instance_id,
        surface: open.surface,
        session_id: opened.session_id,
        api_contract_ref: Some(api_contract()),
        correlation_id: Some("r9c-correlation".to_owned()),
    };
    let app = Arc::new(ReadGatewayApplication::new_with_harness_content(
        endpoint.registry(),
        Arc::new(ContractProfiles::embedded().expect("profiles")),
        reader,
        ProjectionCommitNotifier::new(projection_position(10)),
        scope,
        HarnessContentCommitNotifier::new(content_position(13)),
        Arc::new(ReadTokenCodec::new(
            TokenMacKey::new([0x61; 32]).expect("token key"),
            ReadGatewayPolicy::v01(),
            clock,
        )),
        Arc::new(NoopReadGatewayAuditSink),
    ));
    (peer, metadata, app)
}

fn empty_reader() -> Arc<FakeContentReader> {
    Arc::new(FakeContentReader {
        baseline_results: Mutex::new(VecDeque::new()),
        watch_results: Mutex::new(VecDeque::new()),
        baseline_calls: AtomicUsize::new(0),
        watch_calls: AtomicUsize::new(0),
    })
}

#[tokio::test]
async fn content_permission_fails_before_scope_or_read_model_access() {
    let reader = empty_reader();
    let scope = Arc::new(ScriptedScopeReader::stable("os-user:founder"));
    let (peer, client, app) = application(Arc::clone(&reader), Arc::clone(&scope), false).await;
    let response = app
        .list_harness_content(
            Some(&peer),
            ListHarnessContentRequest {
                client: Some(client),
                task_id: "task-001".to_owned(),
                attempt_ids: Vec::new(),
                page_size: 32,
                page_cursor: None,
                snapshot_position: None,
            },
        )
        .await;
    let Some(list_harness_content_response::Outcome::Error(error)) = response.outcome else {
        panic!("permission failure")
    };
    assert_eq!(error.code, LocalApiErrorCode::PermissionDenied as i32);
    assert_eq!(scope.calls.load(Ordering::SeqCst), 0);
    assert_eq!(reader.baseline_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn baseline_cursor_binds_snapshot_task_and_attempt_filters_before_record_read() {
    let reader = Arc::new(FakeContentReader {
        baseline_results: Mutex::new(VecDeque::from([
            HarnessContentBaselineResult {
                records: vec![content_record(1)],
                next_cursor: Some(HarnessContentPageCursor::from_verified_parts(
                    "content-epoch".to_owned(),
                    2,
                    "task-001".to_owned(),
                    vec!["attempt-001".to_owned()],
                    1,
                )),
                has_more: true,
                snapshot_position: content_position(2),
                retained_from_sequence: 0,
                disclosure_profile_ref: contract_ref(
                    HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
                    HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
                    HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
                ),
            },
            HarnessContentBaselineResult {
                records: vec![content_record(2)],
                next_cursor: None,
                has_more: false,
                snapshot_position: content_position(2),
                retained_from_sequence: 0,
                disclosure_profile_ref: contract_ref(
                    HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
                    HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
                    HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
                ),
            },
        ])),
        watch_results: Mutex::new(VecDeque::new()),
        baseline_calls: AtomicUsize::new(0),
        watch_calls: AtomicUsize::new(0),
    });
    let scope = Arc::new(ScriptedScopeReader::stable("os-user:founder"));
    let (peer, client, app) = application(Arc::clone(&reader), scope, true).await;
    let first = app
        .list_harness_content(
            Some(&peer),
            ListHarnessContentRequest {
                client: Some(client.clone()),
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                page_size: 1,
                page_cursor: None,
                snapshot_position: None,
            },
        )
        .await;
    let Some(list_harness_content_response::Outcome::Page(first_page)) = first.outcome else {
        panic!("first content page")
    };
    let cursor = first_page.next_page_cursor.clone().expect("continuation");
    let snapshot = first_page.snapshot_position.clone().expect("snapshot");

    let tampered = app
        .list_harness_content(
            Some(&peer),
            ListHarnessContentRequest {
                client: Some(client.clone()),
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-002".to_owned()],
                page_size: 1,
                page_cursor: Some(cursor.clone()),
                snapshot_position: Some(snapshot.clone()),
            },
        )
        .await;
    let Some(list_harness_content_response::Outcome::Error(error)) = tampered.outcome else {
        panic!("tampered cursor rejection")
    };
    assert_eq!(error.code, LocalApiErrorCode::CursorInvalid as i32);
    assert_eq!(reader.baseline_calls.load(Ordering::SeqCst), 1);

    let second = app
        .list_harness_content(
            Some(&peer),
            ListHarnessContentRequest {
                client: Some(client),
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                page_size: 1,
                page_cursor: Some(cursor),
                snapshot_position: Some(snapshot),
            },
        )
        .await;
    let Some(list_harness_content_response::Outcome::Page(second_page)) = second.outcome else {
        panic!("second content page")
    };
    assert_eq!(second_page.records[0].content_sequence, 2);
    assert!(!second_page.has_more);
    assert_eq!(reader.baseline_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn watch_revalidates_owner_after_one_frame_is_reserved_and_before_yield() {
    let reader = Arc::new(FakeContentReader {
        baseline_results: Mutex::new(VecDeque::new()),
        watch_results: Mutex::new(VecDeque::from([HarnessContentWatchResult {
            observed_position: content_position(13),
            frames: vec![HarnessContentStreamFrame {
                position: Some(content_position(13)),
                payload: Some(harness_content_stream_frame::Payload::Records(
                    HarnessContentRecordsFrame {
                        records: vec![content_record(13)],
                    },
                )),
            }],
        }])),
        baseline_calls: AtomicUsize::new(0),
        watch_calls: AtomicUsize::new(0),
    });
    let scope = Arc::new(ScriptedScopeReader::with_owners([
        "os-user:founder",
        "os-user:founder",
        "os-user:other",
    ]));
    let (peer, client, app) = application(Arc::clone(&reader), scope, true).await;
    let mut watch = app
        .open_content_watch(
            peer,
            WatchHarnessContentRequest {
                client: Some(client),
                task_id: "task-001".to_owned(),
                attempt_ids: vec!["attempt-001".to_owned()],
                resume_after: Some(content_position(12)),
            },
        )
        .await
        .expect("open authorized content watch");
    let error = watch
        .next_frame()
        .await
        .expect_err("owner change must stop the reserved frame");
    assert_eq!(error.code, LocalApiErrorCode::OwnerMismatch as i32);
    assert_eq!(reader.watch_calls.load(Ordering::SeqCst), 1);
}
