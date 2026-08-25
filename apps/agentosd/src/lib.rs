#![forbid(unsafe_code)]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_domain_contracts::v01::egopulse::{
    policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
    task::v1::{TaskCommand, TaskCommandResult},
    verdict::v1::{VerdictCommand, VerdictCommandResult},
};
use egopulse_domain_contracts::{
    profiles::ContractProfiles,
    v01::egopulse::localapi::v1::{
        ProjectionPosition, local_command_gateway_service_server::LocalCommandGatewayServiceServer,
        local_read_model_service_server::LocalReadModelServiceServer,
        local_session_service_server::LocalSessionServiceServer,
    },
};
use egopulse_local_api::{
    command_gateway::{
        CommandGatewayApplication, CommandPortFailure, CommandPortResult, CommandPrincipal,
        LocalCommandGatewayEndpoint, PolicyCommandPort, TaskCommandPort, VerdictCommandPort,
    },
    read_gateway::{NoopReadGatewayAuditSink, ReadGatewayApplication},
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{BlockingLocalReadModelReader, ProjectionCommitNotifier},
    read_service::LocalReadModelEndpoint,
    read_tokens::{ReadTokenCodec, TokenMacKey},
    session::{
        DenyAllPrincipalResolver, LocalSessionEndpoint, NoopSessionAuditSink,
        ProjectionPositionProvider, SessionAuditSink, SessionClock, SessionConfig,
        SystemSessionClock, TrustedPrincipalResolver,
    },
};
use egopulse_local_ipc_platform::{LocalIpcAddress, LocalIpcListener};
use egopulse_local_read_model::{LocalReadModel, LocalReadModelConfig, LocalReadModelKey};
use tonic::transport::Server;

mod owners;
mod projections;

pub use owners::{
    AuthorityCommandPorts, AuthorityPrincipalResolver, DenyAllAuthorityPrincipalResolver,
};
pub use projections::{
    OwnerProjectionSource, PendingOwnerProjection, ProjectionPump, ProjectionPumpFailure,
};

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub instance: String,
    pub read_model_database_path: PathBuf,
    pub read_model_epoch: String,
    pub read_model_key: [u8; 32],
    pub token_mac_key: [u8; 32],
    pub session_ttl: Duration,
}

impl DaemonConfig {
    pub fn validate(&self) -> Result<(), DaemonCompositionError> {
        if self.instance.trim().is_empty() || self.instance.len() > 80 {
            return Err(DaemonCompositionError::InvalidConfiguration("ipc instance"));
        }
        if self.read_model_epoch.trim().is_empty() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "read model epoch",
            ));
        }
        if self.read_model_database_path.as_os_str().is_empty() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "read model path",
            ));
        }
        if self.read_model_key.iter().all(|byte| *byte == 0) {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "read model key",
            ));
        }
        if self.token_mac_key.iter().all(|byte| *byte == 0) {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "token MAC key",
            ));
        }
        if self.session_ttl.is_zero() || self.session_ttl > Duration::from_secs(24 * 60 * 60) {
            return Err(DaemonCompositionError::InvalidConfiguration("session TTL"));
        }
        Ok(())
    }
}

pub struct DaemonProviders {
    pub principal_resolver: Arc<dyn TrustedPrincipalResolver>,
    pub session_clock: Arc<dyn SessionClock>,
    pub session_audit: Arc<dyn SessionAuditSink>,
    pub task_port: Arc<dyn TaskCommandPort>,
    pub policy_port: Arc<dyn PolicyCommandPort>,
    pub verdict_port: Arc<dyn VerdictCommandPort>,
    pub projection_source: Option<Arc<dyn OwnerProjectionSource>>,
}

impl DaemonProviders {
    /// The default is deliberately non-serving from an authorization point of
    /// view. Production startup must inject a real trusted resolver and owner
    /// ports; this helper exists only to make the fail-closed boundary explicit
    /// and testable.
    #[must_use]
    pub fn fail_closed() -> Self {
        Self {
            principal_resolver: Arc::new(DenyAllPrincipalResolver),
            session_clock: Arc::new(SystemSessionClock),
            session_audit: Arc::new(NoopSessionAuditSink),
            task_port: Arc::new(FailClosedTaskPort),
            policy_port: Arc::new(FailClosedPolicyPort),
            verdict_port: Arc::new(FailClosedVerdictPort),
            projection_source: None,
        }
    }

    /// Builds the three command ports from the actual owning Authorities.
    /// Each Authority remains the sole writer of its own private store.
    #[must_use]
    pub fn from_authorities(
        task: egopulse_cognition_runtime::task_authority::TaskAuthority,
        policy: egopulse_policy_decision_authority::PolicyDecisionAuthority,
        verdict: egopulse_founder_verdict_authority::FounderVerdictAuthority,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
        session_principal_resolver: Arc<dyn TrustedPrincipalResolver>,
        session_clock: Arc<dyn SessionClock>,
        session_audit: Arc<dyn SessionAuditSink>,
    ) -> Self {
        let ports = Arc::new(AuthorityCommandPorts::new(
            task,
            policy,
            verdict,
            principal_resolver,
        ));
        Self {
            principal_resolver: session_principal_resolver,
            session_clock,
            session_audit,
            task_port: Arc::clone(&ports) as Arc<dyn TaskCommandPort>,
            policy_port: Arc::clone(&ports) as Arc<dyn PolicyCommandPort>,
            verdict_port: Arc::clone(&ports) as Arc<dyn VerdictCommandPort>,
            projection_source: Some(Arc::clone(&ports) as Arc<dyn OwnerProjectionSource>),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonCompositionError {
    #[error("daemon configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("local IPC address could not be created")]
    IpcAddress(#[source] std::io::Error),
    #[error("local IPC listener could not be bound")]
    IpcBind(#[source] std::io::Error),
    #[error("contract profiles are invalid")]
    Profiles,
    #[error("read model could not be opened")]
    ReadModel(#[source] egopulse_local_read_model::ProjectionFailure),
    #[error("read token key is invalid")]
    TokenKey,
    #[error("session configuration is invalid")]
    Session(#[source] egopulse_local_api::session::SessionConfigurationError),
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonServeError {
    #[error("daemon server failed")]
    Server(#[from] tonic::transport::Error),
    #[error("projection pump failed")]
    Projection(#[from] ProjectionPumpFailure),
}

pub struct DaemonComposition {
    address: LocalIpcAddress,
    listener: LocalIpcListener,
    session: LocalSessionEndpoint,
    read_model: LocalReadModelEndpoint,
    command: LocalCommandGatewayEndpoint,
    projection_pump: Option<ProjectionPump>,
}

impl DaemonComposition {
    pub fn build(
        config: DaemonConfig,
        providers: DaemonProviders,
    ) -> Result<Self, DaemonCompositionError> {
        config.validate()?;
        let profiles =
            Arc::new(ContractProfiles::embedded().map_err(|_| DaemonCompositionError::Profiles)?);
        let address = LocalIpcAddress::for_instance(&config.instance)
            .map_err(DaemonCompositionError::IpcAddress)?;
        let listener =
            LocalIpcListener::bind(address.clone()).map_err(DaemonCompositionError::IpcBind)?;

        let model = LocalReadModel::open(LocalReadModelConfig {
            database_path: config.read_model_database_path,
            epoch: config.read_model_epoch,
            key: LocalReadModelKey::new(config.read_model_key),
        })
        .map_err(DaemonCompositionError::ReadModel)?;
        let initial_position = model
            .position()
            .map_err(DaemonCompositionError::ReadModel)?;
        let model = Arc::new(Mutex::new(model));
        let reader = Arc::new(BlockingLocalReadModelReader::new(Arc::clone(&model)));
        let notifier = ProjectionCommitNotifier::new(initial_position.clone());
        let position_provider = Arc::new(SharedProjectionPosition::new(initial_position));

        let token_key =
            TokenMacKey::new(config.token_mac_key).map_err(|_| DaemonCompositionError::TokenKey)?;
        let token_codec = Arc::new(ReadTokenCodec::new(
            token_key,
            ReadGatewayPolicy::v01(),
            Arc::clone(&providers.session_clock),
        ));
        let session_config = SessionConfig::new(
            vec![egopulse_client_kernel::api_contract_ref()],
            egopulse_client_kernel::client_kernel_contract_ref(),
            config.session_ttl,
        )
        .map_err(DaemonCompositionError::Session)?;
        let session = LocalSessionEndpoint::new(
            session_config,
            providers.principal_resolver,
            Arc::clone(&providers.session_clock),
            position_provider,
            providers.session_audit,
        );
        let registry = session.registry();
        let read_application = Arc::new(ReadGatewayApplication::new(
            Arc::clone(&registry),
            profiles.clone(),
            reader,
            notifier.clone(),
            token_codec.clone(),
            Arc::new(NoopReadGatewayAuditSink),
        ));
        let read_model = LocalReadModelEndpoint::new(read_application);
        let command_application = Arc::new(CommandGatewayApplication::new(
            registry,
            profiles,
            token_codec,
            providers.task_port,
            providers.policy_port,
            providers.verdict_port,
        ));
        let command = LocalCommandGatewayEndpoint::new(command_application);
        let projection_pump = providers
            .projection_source
            .map(|source| ProjectionPump::new(Arc::clone(&model), notifier, source));

        Ok(Self {
            address,
            listener,
            session,
            read_model,
            command,
            projection_pump,
        })
    }

    #[must_use]
    pub fn address(&self) -> &LocalIpcAddress {
        &self.address
    }

    pub async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), DaemonServeError> {
        let Self {
            listener,
            session,
            read_model,
            command,
            projection_pump,
            ..
        } = self;
        let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
        let mut server_stop = stop_receiver.clone();
        let server_shutdown = async move {
            tokio::select! {
                _ = shutdown => {}
                _ = server_stop.changed() => {}
            }
        };
        let mut server = Box::pin(
            Server::builder()
                .add_service(LocalSessionServiceServer::new(session))
                .add_service(LocalReadModelServiceServer::new(read_model))
                .add_service(LocalCommandGatewayServiceServer::new(command))
                .serve_with_incoming_shutdown(listener.into_incoming(), server_shutdown),
        );
        let Some(projection_pump) = projection_pump else {
            return server.await.map_err(DaemonServeError::Server);
        };
        let mut pump = Box::pin(projection_pump.run(stop_receiver));
        tokio::select! {
            result = &mut server => {
                let _ = stop_sender.send(true);
                let _ = pump.await;
                result.map_err(DaemonServeError::Server)
            }
            result = &mut pump => {
                match result {
                    Ok(()) => server.await.map_err(DaemonServeError::Server),
                    Err(error) => {
                        let _ = stop_sender.send(true);
                        let _ = server.await;
                        Err(DaemonServeError::Projection(error))
                    }
                }
            }
        }
    }
}

struct SharedProjectionPosition(Mutex<ProjectionPosition>);

impl SharedProjectionPosition {
    fn new(position: ProjectionPosition) -> Self {
        Self(Mutex::new(position))
    }
}

impl ProjectionPositionProvider for SharedProjectionPosition {
    fn current_position(&self) -> ProjectionPosition {
        self.0
            .lock()
            .map(|position| position.clone())
            .unwrap_or_default()
    }
}

struct FailClosedTaskPort;

impl TaskCommandPort for FailClosedTaskPort {
    fn execute(
        &self,
        _command: &TaskCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

struct FailClosedPolicyPort;

impl PolicyCommandPort for FailClosedPolicyPort {
    fn execute(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<PolicyDecisionCommandResult>, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

struct FailClosedVerdictPort;

impl VerdictCommandPort for FailClosedVerdictPort {
    fn execute(
        &self,
        _command: &VerdictCommand,
        _principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<VerdictCommandResult>, CommandPortFailure> {
        Err(CommandPortFailure::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        ClientSurface, ExecuteFounderVerdictRequest, GetTaskViewRequest, LocalApiErrorCode,
        OpenSessionRequest, local_command_gateway_service_client::LocalCommandGatewayServiceClient,
        local_read_model_service_client::LocalReadModelServiceClient,
        local_session_service_client::LocalSessionServiceClient,
    };
    use hyper_util::rt::TokioIo;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tonic::transport::Endpoint;
    use tower::service_fn;
    use uuid::Uuid;

    fn config(instance: &str) -> (DaemonConfig, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "egopulse-agentosd-c4-{}-{}",
            std::process::id(),
            instance
        ));
        (
            DaemonConfig {
                instance: instance.to_owned(),
                read_model_database_path: root.join("read-model.db"),
                read_model_epoch: "c4-test-epoch".to_owned(),
                read_model_key: [0x11; 32],
                token_mac_key: [0x22; 32],
                session_ttl: Duration::from_secs(60),
            },
            root,
        )
    }

    #[test]
    fn composition_rejects_missing_secret_material_before_opening_storage() {
        let (mut config, root) = config("missing-key");
        config.read_model_key = [0; 32];
        assert!(matches!(
            DaemonComposition::build(config, DaemonProviders::fail_closed()),
            Err(DaemonCompositionError::InvalidConfiguration(
                "read model key"
            ))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn composition_builds_real_local_listener_with_fail_closed_providers() {
        let instance = format!("c4-build-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let daemon = DaemonComposition::build(config, DaemonProviders::fail_closed())
            .expect("composition should build");
        assert!(daemon.address().as_str().contains("EgoPulse-"));
        drop(daemon);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn composition_serves_session_over_real_named_pipe_and_fails_closed() {
        let instance = format!("c4-session-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let daemon = DaemonComposition::build(config, DaemonProviders::fail_closed())
            .expect("composition should build");
        let address = daemon.address().clone();
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            daemon
                .serve(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("daemon server");
        });

        let connector_address = address.clone();
        let channel = Endpoint::try_from("http://egopulse.local")
            .expect("endpoint")
            .connect_with_connector(service_fn(move |_| {
                let address = connector_address.clone();
                async move {
                    egopulse_local_ipc_platform::LocalIpcClient::connect(&address)
                        .await
                        .map(TokioIo::new)
                }
            }))
            .await
            .expect("named pipe channel");
        let mut client = LocalSessionServiceClient::new(channel.clone());
        let response = client
            .open_session(OpenSessionRequest {
                request_id: Uuid::now_v7().to_string(),
                client_instance_id: "c4-test-client".to_owned(),
                surface: ClientSurface::Cli as i32,
                supported_contracts: vec![egopulse_client_kernel::api_contract_ref()],
            })
            .await
            .expect("session RPC")
            .into_inner();
        assert_eq!(
            response
                .error
                .and_then(|error| LocalApiErrorCode::try_from(error.code).ok()),
            Some(LocalApiErrorCode::PermissionDenied)
        );
        let mut read_client = LocalReadModelServiceClient::new(channel.clone());
        read_client
            .get_task_view(GetTaskViewRequest::default())
            .await
            .expect("read gateway RPC should be registered");
        let mut command_client = LocalCommandGatewayServiceClient::new(channel);
        command_client
            .execute_founder_verdict(ExecuteFounderVerdictRequest::default())
            .await
            .expect("command gateway RPC should be registered");

        shutdown_sender.send(()).expect("shutdown");
        server.await.expect("server join");
        drop(client);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_rejects_expired_or_empty_session_ttl() {
        let (mut config, root) = config("ttl");
        config.session_ttl = Duration::ZERO;
        assert!(matches!(
            config.validate(),
            Err(DaemonCompositionError::InvalidConfiguration("session TTL"))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn duplicate_instance_fails_before_opening_a_second_daemon() {
        let instance = format!("c4-duplicate-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let daemon = DaemonComposition::build(config.clone(), DaemonProviders::fail_closed())
            .expect("first daemon");
        assert!(matches!(
            DaemonComposition::build(config, DaemonProviders::fail_closed()),
            Err(DaemonCompositionError::IpcBind(_))
        ));
        drop(daemon);
        let _ = fs::remove_dir_all(root);
    }

    #[allow(dead_code)]
    fn _system_time_is_available_for_future_lifecycle_tests() -> SystemTime {
        UNIX_EPOCH
    }
}
