#![forbid(unsafe_code)]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig, CodexAppServerDriver,
    FileDispatchMaterialResolver, codex_protocol_fingerprint,
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
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeKey, GovernedHarnessAdapter,
    SystemAdapterClock,
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
use egopulse_local_ide_control::collaboration_control::{
    AuthenticatedCollaborationPrincipal, CollaborationControl, CollaborationControlConfig,
    CollaborationControlError, CollaborationPrincipalKind, CollaborationSqlCipherKey,
    GovernedTaskActivationRunner, HarnessDispatchCycleError, HarnessDispatchRunner,
    SingleHarnessWorkConfig, SingleHarnessWorkflowResolver, SingleHarnessWorkflowResolverError,
    SystemAuthorityClock, TaskActivationGuardSet, TaskActivationSource,
};
use egopulse_local_ipc_platform::{LocalIpcAddress, LocalIpcListener};
use egopulse_local_read_model::{LocalReadModel, LocalReadModelConfig, LocalReadModelKey};
use tonic::transport::Server;

mod owners;
mod policy;
mod projections;
mod security;
mod task;

pub use owners::{
    AuthorityCommandPorts, AuthorityPrincipalResolver, DenyAllAuthorityPrincipalResolver,
};
pub use policy::{
    LocalUserPolicyConfigurationError, LocalUserPolicyResolver, LocalUserPolicyResolverConfig,
};
pub use projections::{
    AdapterApprovalProjectionSource, ArtifactProjectionSource, CollaborationProjectionSource,
    CompositeOwnerProjectionSource, OwnerProjectionSource, PendingOwnerProjection, ProjectionPump,
    ProjectionPumpFailure, ProjectionSourceFailure, VerificationProjectionSource,
};
pub use security::{
    AllowlistedPrincipal, AllowlistedPrincipalResolver, AuthorityPrincipalBinding,
    ConfiguredAuthorityPrincipalResolver, PrincipalPolicyError,
};
pub use task::{
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig,
    TaskCreationGuardConfigurationError,
};

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub instance: String,
    pub read_model_database_path: PathBuf,
    pub read_model_epoch: String,
    pub read_model_key: [u8; 32],
    pub token_mac_key: [u8; 32],
    pub session_ttl: Duration,
    pub harness_dispatch_interval: Duration,
}

impl DaemonConfig {
    pub fn from_environment() -> Result<Self, DaemonBootstrapError> {
        let read_model_key = parse_secret_key(
            "EGOPULSE_READ_MODEL_KEY_HEX",
            std::env::var("EGOPULSE_READ_MODEL_KEY_HEX")
                .map_err(|_| DaemonBootstrapError::MissingSecret("read model key"))?,
        )?;
        let token_mac_key = parse_secret_key(
            "EGOPULSE_TOKEN_MAC_KEY_HEX",
            std::env::var("EGOPULSE_TOKEN_MAC_KEY_HEX")
                .map_err(|_| DaemonBootstrapError::MissingSecret("token MAC key"))?,
        )?;
        let session_ttl = match std::env::var("EGOPULSE_SESSION_TTL_SECONDS") {
            Ok(value) => value
                .parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|_| DaemonBootstrapError::InvalidSetting("session TTL"))?,
            Err(std::env::VarError::NotPresent) => Duration::from_secs(60 * 60),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(DaemonBootstrapError::InvalidSetting("session TTL"));
            }
        };
        let harness_dispatch_interval = match std::env::var("EGOPULSE_HARNESS_DISPATCH_INTERVAL_MS")
        {
            Ok(value) => value
                .parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| DaemonBootstrapError::InvalidSetting("Harness dispatch interval"))?,
            Err(std::env::VarError::NotPresent) => Duration::from_millis(250),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(DaemonBootstrapError::InvalidSetting(
                    "Harness dispatch interval",
                ));
            }
        };

        Ok(Self {
            instance: std::env::var("EGOPULSE_IPC_INSTANCE")
                .unwrap_or_else(|_| "default".to_owned()),
            read_model_database_path: std::env::var_os("EGOPULSE_READ_MODEL_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("egopulse-data/read-model.db")),
            read_model_epoch: std::env::var("EGOPULSE_READ_MODEL_EPOCH")
                .unwrap_or_else(|_| "local-default".to_owned()),
            read_model_key,
            token_mac_key,
            session_ttl,
            harness_dispatch_interval,
        })
    }

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
        if self.harness_dispatch_interval < Duration::from_millis(10)
            || self.harness_dispatch_interval > Duration::from_secs(60)
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Harness dispatch interval",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonBootstrapError {
    #[error("required secret is missing: {0}")]
    MissingSecret(&'static str),
    #[error("secret is not a non-zero 32-byte hex value: {0}")]
    InvalidSecret(&'static str),
    #[error("bootstrap setting is invalid: {0}")]
    InvalidSetting(&'static str),
}

fn parse_secret_key(name: &'static str, value: String) -> Result<[u8; 32], DaemonBootstrapError> {
    let bytes = hex::decode(value).map_err(|_| DaemonBootstrapError::InvalidSecret(name))?;
    let key = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| DaemonBootstrapError::InvalidSecret(name))?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(DaemonBootstrapError::InvalidSecret(name));
    }
    Ok(key)
}

pub struct DaemonProviders {
    pub principal_resolver: Arc<dyn TrustedPrincipalResolver>,
    pub session_clock: Arc<dyn SessionClock>,
    pub session_audit: Arc<dyn SessionAuditSink>,
    pub task_port: Arc<dyn TaskCommandPort>,
    pub policy_port: Arc<dyn PolicyCommandPort>,
    pub verdict_port: Arc<dyn VerdictCommandPort>,
    pub projection_source: Option<Arc<dyn OwnerProjectionSource>>,
    pub harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    pub task_activation_source: Option<Arc<dyn TaskActivationSource>>,
}

/// Explicit workflow configuration boundary for the first vertical. It does
/// not derive a plan, model, workspace, or material from a Task payload; all
/// of those are injected as one reviewed configuration and only the activated
/// run id is checked against the handoff.
#[derive(Clone, Debug)]
pub struct ConfiguredSingleHarnessWorkflow {
    config: SingleHarnessWorkConfig,
}

impl ConfiguredSingleHarnessWorkflow {
    #[must_use]
    pub fn new(config: SingleHarnessWorkConfig) -> Self {
        Self { config }
    }
}

impl SingleHarnessWorkflowResolver for ConfiguredSingleHarnessWorkflow {
    fn resolve(
        &self,
        activation: &egopulse_local_ide_control::collaboration_control::TaskActivationHandoff,
    ) -> Result<SingleHarnessWorkConfig, SingleHarnessWorkflowResolverError> {
        if activation.task.current_run_id.as_deref() != Some(self.config.run_id.as_str()) {
            return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
        }
        Ok(self.config.clone())
    }
}

/// Explicit composition input for the first real Harness vertical. The
/// workflow configuration is reviewed data; no value is inferred from a Task
/// payload or from a provider response.
pub struct CodexHarnessCompositionConfig {
    pub collaboration_database_path: PathBuf,
    pub collaboration_store_epoch: String,
    pub collaboration_key: [u8; 32],
    pub adapter_database_path: PathBuf,
    pub adapter_store_epoch: String,
    pub adapter_key: [u8; 32],
    pub input_bundle_root: PathBuf,
    pub workspace_root: PathBuf,
    pub codex_executable: PathBuf,
    pub workflow: SingleHarnessWorkConfig,
    pub lease_ttl_seconds: u64,
}

impl CodexHarnessCompositionConfig {
    fn validate(&self) -> Result<(), DaemonCompositionError> {
        if self.collaboration_store_epoch.trim().is_empty()
            || self.adapter_store_epoch.trim().is_empty()
            || self.collaboration_key.iter().all(|byte| *byte == 0)
            || self.adapter_key.iter().all(|byte| *byte == 0)
            || self.codex_executable.as_os_str().is_empty()
            || self.lease_ttl_seconds == 0
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Codex Harness composition",
            ));
        }
        Ok(())
    }
}

pub struct AuthorityCompositionInputs {
    pub task: egopulse_cognition_runtime::task_authority::TaskAuthority,
    pub policy: egopulse_policy_decision_authority::PolicyDecisionAuthority,
    pub verdict: egopulse_founder_verdict_authority::FounderVerdictAuthority,
    pub principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    pub session_principal_resolver: Arc<dyn TrustedPrincipalResolver>,
    pub session_clock: Arc<dyn SessionClock>,
    pub session_audit: Arc<dyn SessionAuditSink>,
    pub additional_projection_sources: Vec<Arc<dyn OwnerProjectionSource>>,
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
            harness_dispatch_runner: None,
            task_activation_source: None,
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
        Self::from_authority_inputs(AuthorityCompositionInputs {
            task,
            policy,
            verdict,
            principal_resolver,
            session_principal_resolver,
            session_clock,
            session_audit,
            additional_projection_sources: Vec::new(),
        })
    }

    /// Builds the command ports and joins any additional typed owner feeds
    /// into the same projector. Additional feeds are still independently
    /// owned; this method only gives the daemon a polling/ack boundary.
    #[must_use]
    pub fn from_authority_inputs(inputs: AuthorityCompositionInputs) -> Self {
        let ports = Arc::new(AuthorityCommandPorts::new(
            inputs.task,
            inputs.policy,
            inputs.verdict,
            inputs.principal_resolver,
        ));
        let mut projection_sources =
            Vec::with_capacity(1 + inputs.additional_projection_sources.len());
        projection_sources.push(Arc::clone(&ports) as Arc<dyn OwnerProjectionSource>);
        projection_sources.extend(inputs.additional_projection_sources);
        Self {
            principal_resolver: inputs.session_principal_resolver,
            session_clock: inputs.session_clock,
            session_audit: inputs.session_audit,
            task_port: Arc::clone(&ports) as Arc<dyn TaskCommandPort>,
            policy_port: Arc::clone(&ports) as Arc<dyn PolicyCommandPort>,
            verdict_port: Arc::clone(&ports) as Arc<dyn VerdictCommandPort>,
            projection_source: Some(Arc::new(CompositeOwnerProjectionSource::new(
                projection_sources,
            ))),
            harness_dispatch_runner: None,
            task_activation_source: Some(Arc::clone(&ports) as Arc<dyn TaskActivationSource>),
        }
    }

    #[must_use]
    pub fn with_harness_dispatch_runner(mut self, runner: Arc<dyn HarnessDispatchRunner>) -> Self {
        self.harness_dispatch_runner = Some(runner);
        self
    }

    /// Installs the first production Harness composition. Task Authority,
    /// Collaboration Control, and the Harness Adapter remain separate owners;
    /// the returned runner is the only process-local writer that sequences
    /// activation consumption and dispatch for this vertical.
    pub fn with_codex_harness(
        mut self,
        config: CodexHarnessCompositionConfig,
    ) -> Result<Self, DaemonCompositionError> {
        config.validate()?;
        if self.harness_dispatch_runner.is_some() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Harness runner already configured",
            ));
        }
        let source = self.task_activation_source.take().ok_or(
            DaemonCompositionError::InvalidConfiguration("Task activation source"),
        )?;
        let adapter_id = CODEX_ADAPTER_ID.to_owned();
        let capability_profile_id = CODEX_CAPABILITY_PROFILE_ID.to_owned();
        let reader_edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: config.adapter_database_path.clone(),
            adapter_id: adapter_id.clone(),
            store_epoch: config.adapter_store_epoch.clone(),
            key: AdapterEdgeKey::new(config.adapter_key),
        })
        .map_err(DaemonCompositionError::AdapterEdge)?;
        let writer_edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: config.adapter_database_path,
            adapter_id: adapter_id.clone(),
            store_epoch: config.adapter_store_epoch,
            key: AdapterEdgeKey::new(config.adapter_key),
        })
        .map_err(DaemonCompositionError::AdapterEdge)?;
        let evidence =
            egopulse_local_ide_control::collaboration_control::AdapterBackedHarnessEvidenceResolver::new(
                reader_edge,
            );
        let (guard, reference) = TaskActivationGuardSet::new(evidence);
        let control = CollaborationControl::open(
            CollaborationControlConfig {
                database_path: config.collaboration_database_path,
                store_epoch: config.collaboration_store_epoch,
                key: CollaborationSqlCipherKey::new(config.collaboration_key),
            },
            guard,
            SystemAuthorityClock,
        )
        .map_err(DaemonCompositionError::Collaboration)?;
        let adapter = GovernedHarnessAdapter::new(
            adapter_id,
            capability_profile_id,
            codex_protocol_fingerprint(),
            writer_edge,
            FileDispatchMaterialResolver::new(config.input_bundle_root, config.workspace_root),
            CodexAppServerDriver::new(CodexAppServerConfig::new(config.codex_executable)),
            SystemAdapterClock,
        );
        let principal = AuthenticatedCollaborationPrincipal {
            kind: CollaborationPrincipalKind::HarnessAdapter,
            principal_id: config.workflow.harness_adapter_principal_id.clone(),
            authenticated: true,
        };
        let resolver = ConfiguredSingleHarnessWorkflow::new(config.workflow);
        let runner = GovernedTaskActivationRunner::new(
            control,
            adapter,
            source,
            resolver,
            principal,
            reference,
            config.lease_ttl_seconds,
        );
        self.harness_dispatch_runner = Some(Arc::new(runner));
        Ok(self)
    }
}

pub trait DaemonProviderFactory: Send + Sync {
    fn build(&self) -> DaemonProviders;
}

pub struct FailClosedProviderFactory;

impl DaemonProviderFactory for FailClosedProviderFactory {
    fn build(&self) -> DaemonProviders {
        DaemonProviders::fail_closed()
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
    #[error("Collaboration Control could not be opened")]
    Collaboration(#[source] CollaborationControlError),
    #[error("Harness Adapter edge could not be opened")]
    AdapterEdge(#[source] AdapterEdgeError),
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonServeError {
    #[error("daemon server failed")]
    Server(#[from] tonic::transport::Error),
    #[error("projection pump failed")]
    Projection(#[from] ProjectionPumpFailure),
    #[error("harness dispatch runner failed")]
    Dispatch(#[from] HarnessDispatchCycleError),
    #[error("daemon background worker stopped unexpectedly")]
    BackgroundStopped,
}

pub struct DaemonComposition {
    address: LocalIpcAddress,
    listener: LocalIpcListener,
    session: LocalSessionEndpoint,
    read_model: LocalReadModelEndpoint,
    command: LocalCommandGatewayEndpoint,
    projection_pump: Option<ProjectionPump>,
    harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    harness_dispatch_interval: Duration,
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
        let harness_dispatch_runner = providers.harness_dispatch_runner;

        Ok(Self {
            address,
            listener,
            session,
            read_model,
            command,
            projection_pump,
            harness_dispatch_runner,
            harness_dispatch_interval: config.harness_dispatch_interval,
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
            harness_dispatch_runner,
            harness_dispatch_interval,
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
        let mut background = Box::pin(run_background_workers(
            projection_pump,
            harness_dispatch_runner,
            harness_dispatch_interval,
            stop_receiver,
        ));
        tokio::select! {
            result = &mut server => {
                let _ = stop_sender.send(true);
                let _ = background.await;
                result.map_err(DaemonServeError::Server)
            }
            result = &mut background => {
                let _ = stop_sender.send(true);
                let _ = server.await;
                match result {
                    Ok(()) => Err(DaemonServeError::BackgroundStopped),
                    Err(error) => Err(error),
                }
            }
        }
    }
}

async fn run_background_workers(
    projection_pump: Option<ProjectionPump>,
    harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    harness_dispatch_interval: Duration,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), DaemonServeError> {
    match (projection_pump, harness_dispatch_runner) {
        (Some(projection_pump), Some(runner)) => {
            tokio::select! {
                result = projection_pump.run(stop.clone()) => {
                    result.map_err(DaemonServeError::Projection)
                }
                result = run_harness_dispatch_worker(runner, harness_dispatch_interval, stop) => {
                    result.map_err(DaemonServeError::Dispatch)
                }
            }
        }
        (Some(projection_pump), None) => projection_pump
            .run(stop)
            .await
            .map_err(DaemonServeError::Projection),
        (None, Some(runner)) => {
            run_harness_dispatch_worker(runner, harness_dispatch_interval, stop)
                .await
                .map_err(DaemonServeError::Dispatch)
        }
        (None, None) => {
            // A fail-closed daemon has no projection or Harness worker, but
            // it must still observe the server shutdown signal. Waiting
            // forever here would make a clean IPC shutdown hang after the
            // gRPC server has already stopped.
            let mut stop = stop;
            loop {
                if *stop.borrow() {
                    return Ok(());
                }
                if stop.changed().await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

async fn run_harness_dispatch_worker(
    runner: Arc<dyn HarnessDispatchRunner>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), HarnessDispatchCycleError> {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        runner.run_once().await?;
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = ticker.tick() => {
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
    use egopulse_local_ide_control::collaboration_control::HarnessDispatchCycleReport;
    use hyper_util::rt::TokioIo;
    use std::{
        fs,
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
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
                harness_dispatch_interval: Duration::from_millis(25),
            },
            root,
        )
    }

    struct CountingDispatchRunner {
        runs: Arc<AtomicUsize>,
    }

    impl HarnessDispatchRunner for CountingDispatchRunner {
        fn run_once(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                    + Send
                    + '_,
            >,
        > {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(HarnessDispatchCycleReport::default()) })
        }
    }

    #[tokio::test]
    async fn harness_dispatch_worker_polls_and_stops_with_daemon_signal() {
        let runs = Arc::new(AtomicUsize::new(0));
        let runner = Arc::new(CountingDispatchRunner {
            runs: Arc::clone(&runs),
        });
        let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(run_harness_dispatch_worker(
            runner,
            Duration::from_millis(1),
            stop_receiver,
        ));
        for _ in 0..100 {
            if runs.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        stop_sender.send(true).expect("worker stop signal");
        worker
            .await
            .expect("worker join")
            .expect("worker should stop cleanly");
        assert!(runs.load(Ordering::SeqCst) > 0);
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

    #[tokio::test]
    async fn composition_can_restart_after_the_first_instance_is_dropped() {
        let instance = format!("c4-restart-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let daemon = DaemonComposition::build(config.clone(), DaemonProviders::fail_closed())
            .expect("first daemon");
        drop(daemon);
        let daemon = DaemonComposition::build(config, DaemonProviders::fail_closed())
            .expect("daemon should restart after drop");
        drop(daemon);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn serve_can_be_cancelled_and_then_rebound() {
        let instance = format!("c4-cancel-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let daemon = DaemonComposition::build(config.clone(), DaemonProviders::fail_closed())
            .expect("daemon");
        let server = tokio::spawn(async move {
            daemon
                .serve(std::future::pending::<()>())
                .await
                .expect("daemon server");
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        server.abort();
        let _ = server.await;
        let daemon = DaemonComposition::build(config, DaemonProviders::fail_closed())
            .expect("daemon should rebind after cancellation");
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

        drop(command_client);
        drop(read_client);
        drop(client);
        let reconnect_address = address.clone();
        let reconnect_channel = Endpoint::try_from("http://egopulse.local")
            .expect("endpoint")
            .connect_with_connector(service_fn(move |_| {
                let address = reconnect_address.clone();
                async move {
                    egopulse_local_ipc_platform::LocalIpcClient::connect(&address)
                        .await
                        .map(TokioIo::new)
                }
            }))
            .await
            .expect("client should reconnect after disconnect");
        drop(reconnect_channel);

        shutdown_sender.send(()).expect("shutdown");
        server.await.expect("server join");
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

    #[test]
    fn bootstrap_parser_requires_non_zero_32_byte_hex_secrets() {
        assert!(matches!(
            parse_secret_key("test key", "00".repeat(32)),
            Err(DaemonBootstrapError::InvalidSecret("test key"))
        ));
        assert!(matches!(
            parse_secret_key("test key", "not-hex".to_owned()),
            Err(DaemonBootstrapError::InvalidSecret("test key"))
        ));
        assert_eq!(
            parse_secret_key("test key", "11".repeat(32)).expect("valid key"),
            [0x11; 32]
        );
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
