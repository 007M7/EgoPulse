#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig, CodexAppServerDriver,
    FileDispatchMaterialResolver, codex_protocol_fingerprint,
};
use egopulse_cognition_runtime::{
    context_authority::ContextAuthority, memory_authority::MemoryAuthority,
    task_authority::TaskAuthority,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    harness::v1::{CapabilityProfile, NativeProtocolFingerprint, SupportLevel},
    policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
    task::v1::{TaskCommand, TaskCommandResult, WorkCapabilityRouteBinding},
    verdict::v1::{VerdictCommand, VerdictCommandResult},
};
use egopulse_domain_contracts::{
    profiles::ContractProfiles,
    v01::egopulse::localapi::v1::{
        ProjectionPosition, local_cognition_service_server::LocalCognitionServiceServer,
        local_command_gateway_service_server::LocalCommandGatewayServiceServer,
        local_read_model_service_server::LocalReadModelServiceServer,
        local_session_service_server::LocalSessionServiceServer,
    },
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeKey, FinalArtifactRelationPolicy,
    GovernedHarnessAdapter, GovernedHarnessContentProjector, HarnessContentDrain,
    NativeHarnessDriver, SystemAdapterClock, validate_capability_binding,
};
use egopulse_local_api::{
    cognition_gateway::{
        CognitionGatewayApplication, LocalCognitionEndpoint, MemoryRetrievalAuditSink,
        MemoryRetrievalPort,
    },
    command_gateway::{
        CommandExtensionPorts, CommandGatewayApplication, CommandPortFailure, CommandPortResult,
        CommandPrincipal, ContextMutationPort, FailClosedContextMutationPort,
        FailClosedFounderSupportingMaterialPort, FailClosedMemoryMutationPort,
        FailClosedWorkCapabilityPort, FounderSupportingMaterialPort, LocalCommandGatewayEndpoint,
        MemoryMutationPort, PolicyCommandPort, TaskCommandPort, VerdictCommandPort,
        WorkCapabilityPort, WorkPreparationPort,
    },
    read_gateway::{NoopReadGatewayAuditSink, ReadGatewayApplication},
    read_gateway_policy::ReadGatewayPolicy,
    read_model_reader::{
        BlockingLocalReadModelReader, FailClosedHarnessContentScopeReader,
        HarnessContentCommitNotifier, HarnessContentScopeAccessError, HarnessContentScopeReader,
        ProjectionCommitNotifier,
    },
    read_service::LocalReadModelEndpoint,
    read_tokens::{ReadTokenCodec, TokenMacKey},
    session::{
        DenyAllPrincipalResolver, LocalSessionEndpoint, NoopSessionAuditSink,
        ProjectionPositionProvider, SessionAuditSink, SessionClock, SessionConfig,
        SystemSessionClock, TrustedPrincipalResolver,
    },
};
use egopulse_local_ide_control::collaboration_control::{
    ArtifactReturnSource, AuthenticatedCollaborationPrincipal, CollaborationControl,
    CollaborationControlConfig, CollaborationControlError, CollaborationLineageReader,
    CollaborationLineageReaderConfig, CollaborationPrincipalKind, CollaborationSqlCipherKey,
    CompositeHarnessDispatchRunner, GovernedTaskActivationRunner, HarnessApprovalDeliveryTarget,
    HarnessCancellationDeliveryTarget, HarnessDispatchCycleError, HarnessDispatchRunner,
    SingleHarnessWorkConfig, SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolver,
    SingleHarnessWorkflowResolverError, SystemAuthorityClock, TaskActivationGuardSet,
    TaskActivationSource, TaskCancellationSource, TrustedDispatchRouteProfile,
    build_dispatch_route_binding,
};
use egopulse_local_ipc_platform::{LocalIpcAddress, LocalIpcListener};
use egopulse_local_read_model::{LocalReadModel, LocalReadModelConfig, LocalReadModelKey};
use tonic::transport::Server;

mod approval_delivery;
#[cfg(test)]
mod approval_delivery_tests;
#[cfg(test)]
mod approval_recovery_tests;
mod artifact;
mod bootstrap;
mod cancellation_delivery;
mod context_material;
mod context_mutation;
mod founder_material;
#[cfg(test)]
mod founder_material_tests;
mod intent_interpretation;
mod memory_mutation;
mod memory_retrieval;
mod owners;
mod policy;
mod projections;
mod repository_command;
mod repository_dispatch;
mod repository_material;
mod repository_setup;
mod return_collector;
mod return_projection;
mod rework_preparation;
mod security;
mod task;
mod task_evidence;
mod task_recovery;
mod verdict;
mod verdict_consumer;
mod verdict_expiry;
mod verification;
mod verification_material;
#[cfg(test)]
mod verification_material_tests;
mod verification_output;
mod verification_profile;
#[cfg(test)]
mod verification_profile_tests;
mod verification_repository;
mod verification_repository_handoff;
mod work_capability;
mod work_preparation;

pub use artifact::{
    ArtifactAdmissionGuardConfigurationError, ArtifactAuthorityReferenceSource,
    ConfiguredArtifactAdmissionGuard, ConfiguredArtifactAdmissionGuardConfig,
};
pub use bootstrap::{
    DenyVerificationReferences, FounderSupportingMaterialConfig, LocalUserPolicyBootstrapConfig,
    ProductionBootstrapConfig, ProductionBootstrapError, ProviderAdmission,
    ProviderBootstrapProfile, ProviderCatalogModelView, ProviderCatalogProfileView,
    ProviderCatalogRefreshError, ProviderCatalogRefreshPreview, ProviderCatalogSnapshot,
    ProviderCredentialReference, ProviderHarnessKind, ProviderId, ProviderModelBinding,
    RepositoryCommandArtifactPolicyConfig, RepositoryVerificationConfig,
    WorkCapabilityConfigTransitionReport, apply_work_capability_config_migration,
    preview_work_capability_config_migration, preview_work_capability_config_rollback,
    rollback_work_capability_config_to_v2,
};
pub use context_mutation::ContextMutationPortAdapter;
pub use memory_mutation::{
    MemoryCandidateProducerBinding, MemoryCandidateProducerConfigurationError,
    MemoryCandidateProducerFailure, MemoryCandidateProducerHandle, MemoryCandidateProducerPort,
    MemoryCandidateProducerRegistry, MemoryCandidateProposal, MemoryMutationPortAdapter,
};
pub use memory_retrieval::{
    ConfiguredMemoryRetrievalPort, FailClosedMemoryRetrievalPort, GovernedWorkMemoryRetrieval,
    MemoryRetrievalCompositionConfig, MemoryRetrievalConfigurationError,
    TracingMemoryRetrievalAuditSink, WorkMemoryRetrievalPort,
};
pub use owners::{
    AuthorityCommandPorts, AuthorityPrincipalResolver, DenyAllAuthorityPrincipalResolver,
};
pub use policy::{
    LocalUserPolicyAdapterConfig, LocalUserPolicyConfigurationError, LocalUserPolicyResolver,
    LocalUserPolicyResolverConfig, LocalUserPolicyResolverMultiConfig,
};
pub use projections::{
    AdapterApprovalProjectionSource, AdapterEdgeApprovalProjectionSource, ArtifactProjectionSource,
    CollaborationProjectionSource, CompositeOwnerProjectionSource, OwnerProjectionSource,
    PendingOwnerProjection, ProjectionPump, ProjectionPumpFailure, ProjectionSourceFailure,
    VerificationProjectionSource,
};
pub use repository_material::RepositoryMaterialConfig;
pub use repository_setup::{
    RepositorySetupError, RepositorySetupReport, prepare_repository_configuration,
};
pub use return_collector::{GovernedReturnCollectorConfig, GovernedReturnCollectorRunner};
pub use return_projection::{ArtifactAuthorityReturnSource, GovernedReturnEvidenceResolver};
pub use security::{
    AllowlistedPrincipal, AllowlistedPrincipalResolver, AuthorityPrincipalBinding,
    ConfiguredAuthorityPrincipalResolver, PrincipalPolicyError,
};
pub use task::{
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, ConfiguredTaskTransitionGuard,
    SharedFounderVerdictAuthority, TaskCreationGuardConfigurationError,
};
pub use verdict::{
    ConfiguredFounderVerdictResolver, ConfiguredFounderVerdictResolverConfig,
    DenyFounderTaskCommitEvidence, FounderTaskCommitEvidenceSource,
    FounderVerdictConfigurationError, FounderVerificationEvidenceError,
    FounderVerificationEvidenceSource, TaskAuthorityCommitReceiptSource,
    VerificationAuthorityArtifactSource,
};
pub use verdict_consumer::{
    ConfiguredFounderVerdictConsumeWorker, FounderVerdictConsumeCycleError,
    FounderVerdictConsumeCycleResult, FounderVerdictConsumeWorker,
    FounderVerdictConsumeWorkerConfigurationError,
};
pub use verification::{
    CheckerProfileAttestationError, CheckerProfileAttestationResult, ConfiguredVerificationWorker,
    DynamicPrimaryClaimHandoffPlan, SystemCheckerProfileAttestation,
    SystemTaskVerificationWriteBack, TaskVerificationWriteBackError,
    TaskVerificationWriteBackResult, VerificationBindingTemplate, VerificationHandoffConsumeResult,
    VerificationHandoffIntake, VerificationHandoffIntakeError, VerificationHandoffPlan,
    VerificationHandoffPlanError, VerificationHandoffRequest, VerificationWorker,
    VerificationWorkerConfig, VerificationWorkerConfigurationError, VerificationWorkerCycleError,
    VerificationWorkerCycleResult,
};
pub use work_capability::{
    ResolvedWorkCapability, WorkCapabilityRegistry, WorkCapabilityRegistryError,
};
pub use work_preparation::ConfiguredWorkPreparationPort;

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub instance: String,
    pub read_model_database_path: PathBuf,
    pub read_model_epoch: String,
    pub read_model_key: [u8; 32],
    pub token_mac_key: [u8; 32],
    pub session_ttl: Duration,
    pub harness_dispatch_interval: Duration,
    pub verification_interval: Duration,
    pub verdict_consumption_interval: Duration,
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
        let verification_interval = match std::env::var("EGOPULSE_VERIFICATION_INTERVAL_MS") {
            Ok(value) => value
                .parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| DaemonBootstrapError::InvalidSetting("Verification interval"))?,
            Err(std::env::VarError::NotPresent) => Duration::from_millis(250),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(DaemonBootstrapError::InvalidSetting(
                    "Verification interval",
                ));
            }
        };
        let verdict_consumption_interval =
            match std::env::var("EGOPULSE_VERDICT_CONSUMPTION_INTERVAL_MS") {
                Ok(value) => value
                    .parse::<u64>()
                    .map(Duration::from_millis)
                    .map_err(|_| {
                        DaemonBootstrapError::InvalidSetting("Verdict consumption interval")
                    })?,
                Err(std::env::VarError::NotPresent) => Duration::from_millis(250),
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(DaemonBootstrapError::InvalidSetting(
                        "Verdict consumption interval",
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
            verification_interval,
            verdict_consumption_interval,
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
        if self.verification_interval < Duration::from_millis(10)
            || self.verification_interval > Duration::from_secs(60)
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Verification interval",
            ));
        }
        if self.verdict_consumption_interval < Duration::from_millis(10)
            || self.verdict_consumption_interval > Duration::from_secs(60)
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Verdict consumption interval",
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

pub(crate) fn parse_secret_key(
    name: &'static str,
    value: String,
) -> Result<[u8; 32], DaemonBootstrapError> {
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
    pub founder_supporting_material_port: Arc<dyn FounderSupportingMaterialPort>,
    pub projection_source: Option<Arc<dyn OwnerProjectionSource>>,
    pub harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    approval_delivery_source: Option<Arc<dyn approval_delivery::ApprovalDeliverySource>>,
    approval_delivery_worker: Option<Arc<approval_delivery::ApprovalDeliveryWorker>>,
    cancellation_delivery_source: Option<Arc<dyn TaskCancellationSource>>,
    task_cancellation_reconciler:
        Option<Arc<dyn cancellation_delivery::TaskCancellationReconciler>>,
    cancellation_delivery_worker: Option<Arc<cancellation_delivery::CancellationDeliveryWorker>>,
    pub verification_worker: Option<Arc<dyn VerificationWorker>>,
    pub founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    pub task_activation_source: Option<Arc<dyn TaskActivationSource>>,
    pub memory_retrieval_port: Arc<dyn MemoryRetrievalPort>,
    /// Same supervised retrieval owner used by Work Preparation. Keeping the
    /// second trait view here prevents accidental construction of another
    /// Worker, semaphore, allowlist or Memory Authority handle.
    work_memory_retrieval_port: Arc<dyn memory_retrieval::WorkMemoryRetrievalPort>,
    pub memory_retrieval_audit: Arc<dyn MemoryRetrievalAuditSink>,
    pub memory_mutation_port: Arc<dyn MemoryMutationPort>,
    pub context_mutation_port: Arc<dyn ContextMutationPort>,
    pub work_capability_port: Arc<dyn WorkCapabilityPort>,
    /// Internal candidate-only producer capabilities. This is deliberately
    /// separate from the public Local API mutation port.
    pub memory_candidate_producers: Arc<MemoryCandidateProducerRegistry>,
    pub work_preparation_port: Arc<dyn WorkPreparationPort>,
    context_authority: Option<Arc<Mutex<ContextAuthority>>>,
    repository_dispatch: Option<RepositoryDispatchComposition>,
    harness_content_workers: Vec<HarnessContentWorker>,
    harness_content_task_authority: Option<Arc<Mutex<TaskAuthority>>>,
    harness_content_lineage_readers: Vec<Arc<Mutex<CollaborationLineageReader>>>,
}

struct RepositoryDispatchComposition {
    coordinator: Option<Arc<repository_dispatch::RepositoryDispatchCoordinator>>,
    material: RepositoryMaterialConfig,
    admission: artifact::DerivedWorkspaceAdmissionHandle,
    command_artifacts: RepositoryCommandArtifactPolicyConfig,
}

struct HarnessContentWorker {
    projector: Arc<Mutex<GovernedHarnessContentProjector<SystemAdapterClock>>>,
    projection_edge: Arc<Mutex<AdapterEdge>>,
}

struct AuthorityHarnessContentScopeReader {
    task: Arc<Mutex<TaskAuthority>>,
    lineage_readers: Vec<Arc<Mutex<CollaborationLineageReader>>>,
}

#[tonic::async_trait]
impl HarnessContentScopeReader for AuthorityHarnessContentScopeReader {
    async fn task_owner_principal_id(
        &self,
        task_id: String,
    ) -> Result<Option<String>, HarnessContentScopeAccessError> {
        let task = Arc::clone(&self.task);
        tokio::task::spawn_blocking(move || {
            task.lock()
                .map_err(|_| HarnessContentScopeAccessError::Integrity)?
                .task_owner_principal_id(&task_id)
                .map_err(|_| HarnessContentScopeAccessError::Unavailable)
        })
        .await
        .map_err(|_| HarnessContentScopeAccessError::Unavailable)?
    }

    async fn task_id_for_attempt(
        &self,
        attempt_id: String,
    ) -> Result<Option<String>, HarnessContentScopeAccessError> {
        let readers = self.lineage_readers.clone();
        tokio::task::spawn_blocking(move || {
            let mut resolved = None;
            for reader in readers {
                let task_id = reader
                    .lock()
                    .map_err(|_| HarnessContentScopeAccessError::Integrity)?
                    .task_id_for_attempt(&attempt_id)
                    .map_err(|_| HarnessContentScopeAccessError::Unavailable)?;
                if let Some(task_id) = task_id {
                    if resolved.as_ref().is_some_and(|value| value != &task_id) {
                        return Err(HarnessContentScopeAccessError::Integrity);
                    }
                    resolved = Some(task_id);
                }
            }
            Ok(resolved)
        })
        .await
        .map_err(|_| HarnessContentScopeAccessError::Unavailable)?
    }
}

/// Explicit workflow configuration boundary for the first vertical. Reviewed
/// policy, workspace and provider facts remain injected configuration. For a
/// ContextSnapshot-backed Task, only the content-addressed input bundle
/// reference and matching material digest are rebound from the Authority-owned
/// `input_snapshot_id` carried by the activation handoff.
#[derive(Clone)]
pub struct ConfiguredSingleHarnessWorkflow {
    config: SingleHarnessWorkConfig,
    context_authority: Option<Arc<Mutex<ContextAuthority>>>,
    route_profile: Option<TrustedDispatchRouteProfile>,
    work_capability_route: Option<WorkCapabilityRouteBinding>,
}

impl ConfiguredSingleHarnessWorkflow {
    #[must_use]
    pub fn new(config: SingleHarnessWorkConfig) -> Self {
        Self {
            config,
            context_authority: None,
            route_profile: None,
            work_capability_route: None,
        }
    }

    #[must_use]
    pub fn with_context_authority(mut self, context: Arc<Mutex<ContextAuthority>>) -> Self {
        self.context_authority = Some(context);
        self
    }

    #[must_use]
    pub fn with_trusted_dispatch_route_profile(
        mut self,
        profile: TrustedDispatchRouteProfile,
    ) -> Self {
        self.route_profile = Some(profile);
        self
    }

    #[must_use]
    pub fn with_work_capability_route(mut self, route: WorkCapabilityRouteBinding) -> Self {
        self.work_capability_route = Some(route);
        self
    }
}

impl SingleHarnessWorkflowResolver for ConfiguredSingleHarnessWorkflow {
    fn resolve(
        &self,
        activation: &egopulse_local_ide_control::collaboration_control::TaskActivationHandoff,
    ) -> Result<SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolverError> {
        let mut config = self.config.clone();
        let task_route = activation.task.work_capability_route.as_ref();
        match (task_route, self.work_capability_route.as_ref()) {
            (Some(route), Some(expected)) => {
                egopulse_domain_contracts::work_capability::validate_work_capability_route_binding(
                    route,
                )
                .map_err(|_| SingleHarnessWorkflowResolverError::InvalidConfiguration)?;
                if route != expected {
                    return Ok(SingleHarnessWorkflowResolution::NotApplicable);
                }
                let work_revision = activation.task.work_revision;
                let run_id = work_preparation::work_capability_run_id(
                    &activation.task.task_id,
                    work_revision,
                    route,
                )
                .map_err(|_| SingleHarnessWorkflowResolverError::InvalidConfiguration)?;
                if activation.task.current_run_id.as_deref() != Some(run_id.as_str()) {
                    return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
                }
                config.run_id = run_id;
                config.attempt_id = work_capability_execution_id(
                    "attempt",
                    &activation.task.task_id,
                    work_revision,
                    &route.route_binding_sha256,
                )?;
                config.dispatch_id = work_capability_execution_id(
                    "dispatch",
                    &activation.task.task_id,
                    work_revision,
                    &route.route_binding_sha256,
                )?;
                // Step identities are global in Collaboration storage, just
                // like Attempt identities. Instantiate the single-step
                // template per task instead of reusing its storage key.
                if config.plan.steps.len() != 1
                    || config.plan.steps[0].step_id.trim().is_empty()
                    || !config.plan.steps[0].depends_on_step_ids.is_empty()
                {
                    return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
                }
                config.plan.steps[0].step_id = work_capability_execution_id(
                    "step",
                    &activation.task.task_id,
                    work_revision,
                    &route.route_binding_sha256,
                )?;
                if route.capability_profile_ref.as_ref() != Some(&config.capability_profile_ref)
                    || config.plan.steps.iter().any(|step| {
                        step.required_capability_profile_ref.as_ref()
                            != route.capability_profile_ref.as_ref()
                    })
                {
                    return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
                }
            }
            (Some(_), None) => return Ok(SingleHarnessWorkflowResolution::NotApplicable),
            (None, _) => {
                // Historical/static tasks have no additive route field and
                // retain their exact pre-draft.23 workflow identity.
                if activation.task.current_run_id.as_deref() != Some(self.config.run_id.as_str()) {
                    return Ok(SingleHarnessWorkflowResolution::NotApplicable);
                }
            }
        }
        if let Some(digest) = context_snapshot_digest(&activation.task.input_snapshot_id)? {
            let now_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| SingleHarnessWorkflowResolverError::Unavailable)?
                .as_secs()
                .try_into()
                .map_err(|_| SingleHarnessWorkflowResolverError::Unavailable)?;
            let context = self
                .context_authority
                .as_ref()
                .ok_or(SingleHarnessWorkflowResolverError::Unavailable)?;
            let resolved = context
                .lock()
                .map_err(|_| SingleHarnessWorkflowResolverError::Unavailable)?
                .resolve(
                    &activation.task.input_snapshot_id,
                    &activation.task.target_scope_ref,
                    now_seconds,
                )
                .map_err(|error| match error {
                    egopulse_cognition_runtime::context_authority::ContextAuthorityFailure::Storage => {
                        SingleHarnessWorkflowResolverError::Unavailable
                    }
                    _ => SingleHarnessWorkflowResolverError::InvalidConfiguration,
                })?;
            if resolved.snapshot.compiled_context_sha256 != digest {
                return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
            }
            let compiled_route = work_preparation::work_capability_route_from_compiled_context(
                &resolved.compiled_context,
            )
            .map_err(|_| SingleHarnessWorkflowResolverError::InvalidConfiguration)?;
            if compiled_route.as_ref() != task_route {
                return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
            }
            if config.plan.steps.is_empty() {
                return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
            }
            // The plan digest identifies the reviewed template artifact. The
            // current contract does not define a canonical digest over an
            // instantiated RunPlan, so the Authority-owned input binding is
            // carried by the step reference, material digest and sealed
            // CreateRun command rather than by inventing a new digest here.
            let input_bundle_ref = format!("ctx-{digest}.json");
            for step in &mut config.plan.steps {
                step.input_bundle_ref.clone_from(&input_bundle_ref);
            }
            config.material.input_bundle_sha256 = digest.to_owned();
        } else if task_route.is_some() {
            return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
        }
        match self.route_profile.as_ref() {
            Some(profile) => {
                let route_binding = build_dispatch_route_binding(profile)
                    .map_err(|_| SingleHarnessWorkflowResolverError::InvalidConfiguration)?;
                config.material.route_binding = Some(route_binding.clone());
                Ok(SingleHarnessWorkflowResolution::ResolvedWithRouteBinding {
                    config: Box::new(config),
                    route_binding: Box::new(route_binding),
                })
            }
            None => Ok(SingleHarnessWorkflowResolution::Resolved(Box::new(config))),
        }
    }
}

fn work_capability_execution_id(
    kind: &str,
    task_id: &str,
    work_revision: u64,
    route_binding_sha256: &str,
) -> Result<String, SingleHarnessWorkflowResolverError> {
    if work_revision == 0 {
        return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
    }
    if work_revision == 1 {
        Ok(format!("{kind}:work:{task_id}:{route_binding_sha256}"))
    } else {
        Ok(format!(
            "{kind}:work:{task_id}:revision:{work_revision}:{route_binding_sha256}"
        ))
    }
}

fn context_snapshot_digest(
    snapshot_id: &str,
) -> Result<Option<&str>, SingleHarnessWorkflowResolverError> {
    let Some(digest) = snapshot_id.strip_prefix("ctx:") else {
        return Ok(None);
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SingleHarnessWorkflowResolverError::InvalidConfiguration);
    }
    Ok(Some(digest))
}

/// Provider-neutral composition input for one admitted native Harness. The
/// workflow configuration is reviewed data; provider, workspace and policy
/// values are not inferred from a Task payload or provider response. A ctx
/// bundle binding may only be rebound from an Authority-resolved Task snapshot.
/// Provider process configuration stays outside this type.
pub struct NativeHarnessCompositionConfig {
    pub collaboration_database_path: PathBuf,
    pub collaboration_store_epoch: String,
    pub collaboration_key: [u8; 32],
    pub adapter_database_path: PathBuf,
    pub adapter_store_epoch: String,
    pub adapter_key: [u8; 32],
    pub input_bundle_root: PathBuf,
    pub workspace_root: PathBuf,
    /// Reviewed exact model route used when an input bundle does not name a
    /// model. Multi-provider production profiles must set this so dispatch
    /// cannot fall through to a Harness-owned default provider.
    pub default_model: Option<String>,
    pub workflow: SingleHarnessWorkConfig,
    pub lease_ttl_seconds: u64,
    pub return_collector: GovernedReturnCollectorConfig,
}

/// Codex-specific process input wrapped around the provider-neutral native
/// Harness composition. The user-owned JSON shape remains unchanged; only the
/// typed daemon boundary separates process choice from governed composition.
pub struct CodexHarnessCompositionConfig {
    pub native: NativeHarnessCompositionConfig,
    pub codex_executable: PathBuf,
    pub environment_overrides: Vec<(String, String)>,
    /// Exact admitted route compiled into new Context/Task facts. This is a
    /// typed bootstrap input, not a second user-facing process setting.
    pub work_capability_route: Option<WorkCapabilityRouteBinding>,
}

/// One provider-specific native Harness unit for the multi-model composition
/// boundary. Admission is still external: `profile` must come from the
/// attested capability path before this unit is passed to the daemon.
pub struct ProfiledNativeHarnessComposition {
    pub config: NativeHarnessCompositionConfig,
    pub profile: NativeHarnessCompositionProfile,
    pub driver: Box<dyn NativeHarnessDriver + Send>,
    route_profile: Option<TrustedDispatchRouteProfile>,
    work_capability_route: Option<WorkCapabilityRouteBinding>,
    disclosure_credentials: egopulse_harness_adapter::ManagedDisclosureCredentials,
}

impl ProfiledNativeHarnessComposition {
    /// Builds one already-attested provider composition. The safe default has
    /// no route and no disclosure input, so callers must opt into both facts
    /// explicitly before user-visible content can cross the Adapter boundary.
    pub fn new<D>(
        config: NativeHarnessCompositionConfig,
        profile: NativeHarnessCompositionProfile,
        driver: D,
    ) -> Self
    where
        D: NativeHarnessDriver + Send + 'static,
    {
        Self {
            config,
            profile,
            driver: Box::new(driver),
            route_profile: None,
            work_capability_route: None,
            disclosure_credentials:
                egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(),
        }
    }

    /// Binds the immutable, trusted provider/model route used by dispatch and
    /// safe-content identity. This does not perform Provider admission.
    #[must_use]
    pub fn with_trusted_dispatch_route_profile(
        mut self,
        route_profile: TrustedDispatchRouteProfile,
    ) -> Self {
        self.route_profile = Some(route_profile);
        self
    }

    #[must_use]
    pub fn with_work_capability_route(mut self, route: WorkCapabilityRouteBinding) -> Self {
        self.work_capability_route = Some(route);
        self
    }

    /// Supplies the already-resolved disclosure mode without exposing it to
    /// the driver or any Local API surface.
    #[must_use]
    pub fn with_disclosure_credentials(
        mut self,
        credentials: egopulse_harness_adapter::ManagedDisclosureCredentials,
    ) -> Self {
        self.disclosure_credentials = credentials;
        self
    }
}

/// Provider-neutral identity that binds a native driver to the capability
/// profile and protocol evidence it was admitted with. This is deliberately
/// separate from provider process configuration so the composition boundary
/// itself cannot hard-code an executable or provider identity.
#[derive(Clone, Debug)]
pub struct NativeHarnessCompositionProfile {
    adapter_id: String,
    capability_profile_id: String,
    capability_profile_ref: ContractReference,
    observed_protocol: NativeProtocolFingerprint,
    final_artifact_relation_policy: FinalArtifactRelationPolicy,
    /// Named gap for a Harness whose transport publishes no protocol schema.
    /// `Some` states that the digest is absent because there is nothing to
    /// digest, and keeps that absence part of the composition identity instead
    /// of padding the fingerprint with an unobserved value.
    schema_attestation_gap: Option<String>,
}

impl NativeHarnessCompositionProfile {
    /// Creates a composition identity only from a currently active,
    /// probe-attested and workflow-bound capability profile. Composition does
    /// not perform admission, but it cannot be called with an unbound or
    /// merely declared profile by accident.
    pub fn from_attested_capability(
        required_profile_ref: &ContractReference,
        model_family_selector: &str,
        capability_profile: &CapabilityProfile,
        observed_protocol: NativeProtocolFingerprint,
        now: &prost_types::Timestamp,
    ) -> Result<Self, DaemonCompositionError> {
        validate_capability_binding(
            required_profile_ref,
            model_family_selector,
            capability_profile,
            now,
        )
        .map_err(|_| {
            DaemonCompositionError::InvalidConfiguration(
                "native Harness capability profile admission",
            )
        })?;
        let declaration = capability_profile.declaration.as_ref().ok_or(
            DaemonCompositionError::InvalidConfiguration(
                "native Harness capability profile declaration",
            ),
        )?;
        let declared_protocol = declaration.native_protocol.as_ref().ok_or(
            DaemonCompositionError::InvalidConfiguration(
                "native Harness capability profile protocol",
            ),
        )?;
        if declared_protocol != &observed_protocol {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness capability profile protocol drift",
            ));
        }
        let final_artifact_relation_policy = match declaration.semantics.as_ref() {
            None => FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
            Some(semantics) => {
                let governed_content = SupportLevel::try_from(
                    semantics.governed_user_visible_content,
                )
                .map_err(|_| {
                    DaemonCompositionError::InvalidConfiguration(
                        "native Harness governed content capability",
                    )
                })?;
                match governed_content {
                    SupportLevel::NativeStructured | SupportLevel::AdapterEmulated => {
                        FinalArtifactRelationPolicy::RequiredGovernedContent
                    }
                    SupportLevel::Unspecified
                    | SupportLevel::Unknown
                    | SupportLevel::ProcessOnly
                    | SupportLevel::Unsupported => {
                        FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly
                    }
                }
            }
        };
        let profile = Self {
            adapter_id: declaration.adapter_id.clone(),
            capability_profile_id: capability_profile.profile_id.clone(),
            capability_profile_ref: required_profile_ref.clone(),
            observed_protocol,
            final_artifact_relation_policy,
            schema_attestation_gap: None,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), DaemonCompositionError> {
        let schema_digest_is_sound = match self.schema_attestation_gap.as_deref() {
            None => !self.observed_protocol.schema_sha256.trim().is_empty(),
            Some(gap_code) => {
                !gap_code.trim().is_empty()
                    && self.observed_protocol.schema_sha256.trim().is_empty()
            }
        };
        if self.adapter_id.trim().is_empty()
            || self.capability_profile_id.trim().is_empty()
            || self.capability_profile_ref.contract_id.trim().is_empty()
            || self.capability_profile_ref.version.trim().is_empty()
            || self.capability_profile_ref.sha256.trim().is_empty()
            || self.capability_profile_id != self.capability_profile_ref.contract_id
            || self.observed_protocol.protocol_name.trim().is_empty()
            || self.observed_protocol.protocol_version.trim().is_empty()
            || !schema_digest_is_sound
            || self.observed_protocol.adapter_version.trim().is_empty()
            || self
                .observed_protocol
                .native_executable_version
                .trim()
                .is_empty()
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile",
            ));
        }
        Ok(())
    }
}

/// Identity a production composition claims for one Harness kind: the adapter
/// that owns its dispatch evidence, and the capability profile it is admitted
/// under. The Adapter Edge store binds `adapter_id` in its metadata row and
/// refuses to open for a different one, so every composer that opens that store
/// — the composition and the policy resolver alike — must resolve this the same
/// way. `None` means this daemon has no composition for that Harness kind.
pub fn production_harness_identity(
    harness: bootstrap::ProviderHarnessKind,
) -> Option<ProviderHarnessIdentity> {
    match harness {
        bootstrap::ProviderHarnessKind::CodexAppServer => Some(ProviderHarnessIdentity {
            adapter_id: CODEX_ADAPTER_ID,
            capability_profile_id: CODEX_CAPABILITY_PROFILE_ID,
        }),
        bootstrap::ProviderHarnessKind::OpenCodeAcp => Some(ProviderHarnessIdentity {
            adapter_id: egopulse_opencode_adapter::OPENCODE_ADAPTER_ID,
            capability_profile_id: egopulse_opencode_adapter::OPENCODE_CAPABILITY_PROFILE_ID,
        }),
        bootstrap::ProviderHarnessKind::DshAcp | bootstrap::ProviderHarnessKind::KimiCliAcp => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderHarnessIdentity {
    pub adapter_id: &'static str,
    pub capability_profile_id: &'static str,
}

fn trusted_codex_route_profile(
    profile: &ProviderBootstrapProfile,
    native: &NativeHarnessCompositionConfig,
) -> Result<TrustedDispatchRouteProfile, DaemonCompositionError> {
    // Which provider/Harness pairings may be production is decided once by the
    // admission table in bootstrap; composition binds to whatever the profile
    // declares rather than to one provider's name.
    if profile.admission != bootstrap::ProviderAdmission::Production
        || native.default_model.as_deref() != Some(profile.exact_model.as_str())
    {
        return Err(DaemonCompositionError::InvalidConfiguration(
            "production Codex dispatch route profile",
        ));
    }
    let model = profile
        .models
        .iter()
        .find(|model| model.harness_model_id == profile.exact_model)
        .ok_or(DaemonCompositionError::InvalidConfiguration(
            "production Codex provider model binding",
        ))?;
    Ok(TrustedDispatchRouteProfile {
        provider_bootstrap_profile_id: profile.profile_id.clone(),
        selected_harness_id: profile.harness.as_str().to_owned(),
        provider_model_id: model.provider_model_id.clone(),
        catalog_snapshot_sha256: profile
            .catalog_snapshot
            .as_ref()
            .map(|snapshot| snapshot.evidence_digest_sha256.clone()),
        capability_profile_id: native.workflow.capability_profile_ref.contract_id.clone(),
    })
}

fn validate_codex_work_capability_route(
    route: &WorkCapabilityRouteBinding,
    profile: &ProviderBootstrapProfile,
    native: &NativeHarnessCompositionConfig,
) -> Result<(), DaemonCompositionError> {
    egopulse_domain_contracts::work_capability::validate_work_capability_route_binding(route)
        .map_err(|_| {
            DaemonCompositionError::InvalidConfiguration("production Codex work-capability route")
        })?;
    let model = profile
        .models
        .iter()
        .find(|model| model.harness_model_id == profile.exact_model)
        .ok_or(DaemonCompositionError::InvalidConfiguration(
            "production Codex provider model binding",
        ))?;
    if route.provider_profile_id != profile.profile_id
        || route.provider_id != profile.provider.as_str()
        || route.harness_id != profile.harness.as_str()
        || route.harness_model_id != model.harness_model_id
        || route.provider_model_id != model.provider_model_id
        || route.capability_profile_ref.as_ref() != Some(&native.workflow.capability_profile_ref)
        || route.catalog_snapshot_sha256
            != profile
                .catalog_snapshot
                .as_ref()
                .map(|snapshot| snapshot.evidence_digest_sha256.clone())
        || route.native_composition_generation != native.workflow.run_id
        || native.default_model.as_deref() != Some(route.harness_model_id.as_str())
    {
        return Err(DaemonCompositionError::InvalidConfiguration(
            "production Codex work-capability runtime binding",
        ));
    }
    Ok(())
}

fn codex_disclosure_credentials(
    profile: &ProviderBootstrapProfile,
    environment_overrides: &[(String, String)],
) -> egopulse_harness_adapter::ManagedDisclosureCredentials {
    use egopulse_harness_adapter::ManagedDisclosureCredentials;

    match &profile.credential {
        bootstrap::ProviderCredentialReference::HarnessAccount
            if environment_overrides.is_empty() =>
        {
            ManagedDisclosureCredentials::harness_account()
        }
        bootstrap::ProviderCredentialReference::ApiKeyEnvironment { target_env, .. } => {
            let mut matching = environment_overrides
                .iter()
                .filter(|(name, _)| name == target_env);
            match (
                matching.next(),
                matching.next(),
                environment_overrides.len(),
            ) {
                (Some((_, value)), None, 1) => {
                    ManagedDisclosureCredentials::managed_available(vec![value.clone()])
                }
                _ => ManagedDisclosureCredentials::managed_unavailable(),
            }
        }
        _ => ManagedDisclosureCredentials::managed_unavailable(),
    }
}

impl NativeHarnessCompositionConfig {
    fn validate(&self) -> Result<(), DaemonCompositionError> {
        if self.collaboration_store_epoch.trim().is_empty()
            || self.adapter_store_epoch.trim().is_empty()
            || self.collaboration_key.iter().all(|byte| *byte == 0)
            || self.adapter_key.iter().all(|byte| *byte == 0)
            || self.lease_ttl_seconds == 0
            || self
                .default_model
                .as_ref()
                .is_some_and(|model| model.trim().is_empty())
        {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition",
            ));
        }
        self.return_collector
            .validate()
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
        Ok(())
    }
}

impl CodexHarnessCompositionConfig {
    fn validate(&self) -> Result<(), DaemonCompositionError> {
        if self.codex_executable.as_os_str().is_empty() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Codex Harness executable",
            ));
        }
        self.native.validate()
    }

    fn app_server_config(&self) -> CodexAppServerConfig {
        let mut config = CodexAppServerConfig::new(self.codex_executable.clone());
        for (name, value) in &self.environment_overrides {
            config = config.with_environment_override(name.clone(), value.clone());
        }
        config
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

/// Composition input used when a cross-authority evidence source must share
/// the Task Authority's single-writer handle with the command ports.
pub struct SharedAuthorityCompositionInputs {
    pub task: Arc<Mutex<egopulse_cognition_runtime::task_authority::TaskAuthority>>,
    pub policy: egopulse_policy_decision_authority::PolicyDecisionAuthority,
    pub verdict: SharedFounderVerdictAuthority,
    pub principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    pub session_principal_resolver: Arc<dyn TrustedPrincipalResolver>,
    pub session_clock: Arc<dyn SessionClock>,
    pub session_audit: Arc<dyn SessionAuditSink>,
    pub additional_projection_sources: Vec<Arc<dyn OwnerProjectionSource>>,
}

/// Fully shared owner handles used by production workers that must coordinate
/// cross-Authority operations with command handling under one process-local
/// lock order.
pub struct SharedAuthorityHandlesCompositionInputs {
    pub task: Arc<Mutex<egopulse_cognition_runtime::task_authority::TaskAuthority>>,
    pub policy: Arc<Mutex<egopulse_policy_decision_authority::PolicyDecisionAuthority>>,
    pub verdict: SharedFounderVerdictAuthority,
    pub cross_authority_operation_gate: Arc<Mutex<()>>,
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
            approval_delivery_source: None,
            approval_delivery_worker: None,
            cancellation_delivery_source: None,
            task_cancellation_reconciler: None,
            cancellation_delivery_worker: None,
            verification_worker: None,
            founder_verdict_consume_worker: None,
            task_activation_source: None,
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            work_memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            context_mutation_port: Arc::new(FailClosedContextMutationPort),
            founder_supporting_material_port: Arc::new(FailClosedFounderSupportingMaterialPort),
            work_capability_port: Arc::new(FailClosedWorkCapabilityPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
            work_preparation_port: Arc::new(
                egopulse_local_api::command_gateway::FailClosedWorkPreparationPort,
            ),
            context_authority: None,
            repository_dispatch: None,
            harness_content_workers: Vec::new(),
            harness_content_task_authority: None,
            harness_content_lineage_readers: Vec::new(),
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
        let task = Arc::new(Mutex::new(inputs.task));
        let harness_content_task_authority = Arc::clone(&task);
        let verdict = Arc::new(Mutex::new(Some(inputs.verdict)));
        let cross_authority_operation_gate = Arc::new(Mutex::new(()));
        let ports = Arc::new(
            AuthorityCommandPorts::new_shared_handles_with_operation_gate(
                Arc::clone(&task),
                inputs.policy,
                Arc::clone(&verdict),
                inputs.principal_resolver,
                Arc::clone(&cross_authority_operation_gate),
            ),
        );
        let founder_verdict_consume_worker = Some(Arc::new(
            ConfiguredFounderVerdictConsumeWorker::new_with_operation_gate(
                task,
                verdict,
                "task-authority:founder-verdict-consumer",
                cross_authority_operation_gate,
            )
            .expect("static Founder Verdict consume worker principal"),
        )
            as Arc<dyn FounderVerdictConsumeWorker>);
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
            approval_delivery_source: Some(
                Arc::clone(&ports) as Arc<dyn approval_delivery::ApprovalDeliverySource>
            ),
            approval_delivery_worker: None,
            cancellation_delivery_source: Some(
                Arc::clone(&ports) as Arc<dyn TaskCancellationSource>
            ),
            task_cancellation_reconciler: Some(
                Arc::clone(&ports) as Arc<dyn cancellation_delivery::TaskCancellationReconciler>
            ),
            cancellation_delivery_worker: None,
            verification_worker: None,
            founder_verdict_consume_worker,
            task_activation_source: Some(Arc::clone(&ports) as Arc<dyn TaskActivationSource>),
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            work_memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            context_mutation_port: Arc::new(FailClosedContextMutationPort),
            founder_supporting_material_port: Arc::new(FailClosedFounderSupportingMaterialPort),
            work_capability_port: Arc::new(FailClosedWorkCapabilityPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
            work_preparation_port: Arc::new(
                egopulse_local_api::command_gateway::FailClosedWorkPreparationPort,
            ),
            context_authority: None,
            repository_dispatch: None,
            harness_content_workers: Vec::new(),
            harness_content_task_authority: Some(harness_content_task_authority),
            harness_content_lineage_readers: Vec::new(),
        }
    }

    /// Builds daemon providers from a shared Task Authority handle. This is
    /// the production path when Founder Verdict receipt validation and Task
    /// command handling must observe the same owner instance.
    #[must_use]
    pub fn from_shared_authority_inputs(inputs: SharedAuthorityCompositionInputs) -> Self {
        Self::from_shared_authority_handles(SharedAuthorityHandlesCompositionInputs {
            task: inputs.task,
            policy: Arc::new(Mutex::new(inputs.policy)),
            verdict: inputs.verdict,
            cross_authority_operation_gate: Arc::new(Mutex::new(())),
            principal_resolver: inputs.principal_resolver,
            session_principal_resolver: inputs.session_principal_resolver,
            session_clock: inputs.session_clock,
            session_audit: inputs.session_audit,
            additional_projection_sources: inputs.additional_projection_sources,
        })
    }

    /// Builds daemon providers around already shared Authority owners and the
    /// one gate used by every Task/Founder Verdict cross-owner operation.
    #[must_use]
    pub fn from_shared_authority_handles(inputs: SharedAuthorityHandlesCompositionInputs) -> Self {
        let harness_content_task_authority = Arc::clone(&inputs.task);
        let founder_verdict_consume_worker = Some(Arc::new(
            ConfiguredFounderVerdictConsumeWorker::new_with_operation_gate(
                Arc::clone(&inputs.task),
                Arc::clone(&inputs.verdict),
                "task-authority:founder-verdict-consumer",
                Arc::clone(&inputs.cross_authority_operation_gate),
            )
            .expect("static Founder Verdict consume worker principal"),
        )
            as Arc<dyn FounderVerdictConsumeWorker>);
        let ports = Arc::new(
            AuthorityCommandPorts::new_shared_authority_handles_with_operation_gate(
                inputs.task,
                inputs.policy,
                inputs.verdict,
                inputs.principal_resolver,
                inputs.cross_authority_operation_gate,
            ),
        );
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
            approval_delivery_source: Some(
                Arc::clone(&ports) as Arc<dyn approval_delivery::ApprovalDeliverySource>
            ),
            approval_delivery_worker: None,
            cancellation_delivery_source: Some(
                Arc::clone(&ports) as Arc<dyn TaskCancellationSource>
            ),
            task_cancellation_reconciler: Some(
                Arc::clone(&ports) as Arc<dyn cancellation_delivery::TaskCancellationReconciler>
            ),
            cancellation_delivery_worker: None,
            verification_worker: None,
            founder_verdict_consume_worker,
            task_activation_source: Some(Arc::clone(&ports) as Arc<dyn TaskActivationSource>),
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            work_memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            context_mutation_port: Arc::new(FailClosedContextMutationPort),
            founder_supporting_material_port: Arc::new(FailClosedFounderSupportingMaterialPort),
            work_capability_port: Arc::new(FailClosedWorkCapabilityPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
            work_preparation_port: Arc::new(
                egopulse_local_api::command_gateway::FailClosedWorkPreparationPort,
            ),
            context_authority: None,
            repository_dispatch: None,
            harness_content_workers: Vec::new(),
            harness_content_task_authority: Some(harness_content_task_authority),
            harness_content_lineage_readers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_context_authority(mut self, context: Arc<Mutex<ContextAuthority>>) -> Self {
        self.context_authority = Some(context);
        self
    }

    pub(crate) fn with_repository_dispatch(
        mut self,
        material: RepositoryMaterialConfig,
        admission: artifact::DerivedWorkspaceAdmissionHandle,
        command_artifacts: RepositoryCommandArtifactPolicyConfig,
    ) -> Self {
        self.repository_dispatch = Some(RepositoryDispatchComposition {
            coordinator: None,
            material,
            admission,
            command_artifacts,
        });
        self
    }

    #[must_use]
    pub fn with_context_mutation(mut self, port: Arc<dyn ContextMutationPort>) -> Self {
        self.context_mutation_port = port;
        self
    }

    #[must_use]
    pub fn with_work_capability_port(mut self, port: Arc<dyn WorkCapabilityPort>) -> Self {
        self.work_capability_port = port;
        self
    }

    #[must_use]
    pub fn with_harness_dispatch_runner(mut self, runner: Arc<dyn HarnessDispatchRunner>) -> Self {
        self.harness_dispatch_runner = Some(runner);
        self
    }

    #[must_use]
    pub fn with_work_preparation_port(mut self, port: Arc<dyn WorkPreparationPort>) -> Self {
        self.work_preparation_port = port;
        self
    }

    /// Installs a deterministic multi-Harness dispatch composition. Each
    /// runner is responsible for filtering to its own capability profile and
    /// owning its own Adapter Edge; the daemon only invokes the composite as
    /// one scheduling unit.
    pub fn with_harness_dispatch_runners(
        mut self,
        runners: Vec<Arc<dyn HarnessDispatchRunner>>,
    ) -> Result<Self, DaemonCompositionError> {
        if self.harness_dispatch_runner.is_some() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Harness runner already configured",
            ));
        }
        let composite = CompositeHarnessDispatchRunner::new(runners)
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
        self.harness_dispatch_runner = Some(Arc::new(composite));
        Ok(self)
    }

    /// Wraps the configured Harness dispatch cycle with the daemon-owned Task
    /// recovery settlement. The wrapper consumes the cycle's derived recovery
    /// findings and settles only those that still match the live Task
    /// snapshot through the existing Task Authority single-writer path. A
    /// runner must already be configured; settlement never installs a cycle of
    /// its own.
    pub fn with_task_recovery_settlement(
        mut self,
        task: Arc<Mutex<egopulse_cognition_runtime::task_authority::TaskAuthority>>,
    ) -> Result<Self, DaemonCompositionError> {
        let runner = self.harness_dispatch_runner.take().ok_or(
            DaemonCompositionError::InvalidConfiguration(
                "Harness runner required before Task recovery settlement",
            ),
        )?;
        let wrapped = crate::task_recovery::GovernedTaskRecoveryRunner::new(
            runner,
            task,
            "collaboration-control:task-recovery",
        )
        .map_err(DaemonCompositionError::InvalidConfiguration)?;
        self.harness_dispatch_runner = Some(Arc::new(wrapped));
        Ok(self)
    }

    #[must_use]
    pub fn with_verification_worker(mut self, worker: Arc<dyn VerificationWorker>) -> Self {
        self.verification_worker = Some(worker);
        self
    }

    #[must_use]
    pub fn with_founder_supporting_material_port(
        mut self,
        port: Arc<dyn FounderSupportingMaterialPort>,
    ) -> Self {
        self.founder_supporting_material_port = port;
        self
    }

    #[must_use]
    pub fn with_founder_verdict_consume_worker(
        mut self,
        worker: Arc<dyn FounderVerdictConsumeWorker>,
    ) -> Self {
        self.founder_verdict_consume_worker = Some(worker);
        self
    }

    pub fn with_memory_retrieval(
        mut self,
        authority: Arc<Mutex<MemoryAuthority>>,
        config: MemoryRetrievalCompositionConfig,
    ) -> Result<Self, DaemonCompositionError> {
        let port = Arc::new(
            ConfiguredMemoryRetrievalPort::new(authority, config)
                .map_err(DaemonCompositionError::MemoryRetrieval)?,
        );
        self.memory_retrieval_port = Arc::clone(&port) as Arc<dyn MemoryRetrievalPort>;
        self.work_memory_retrieval_port = port;
        Ok(self)
    }

    /// Returns the Work Preparation view of the already configured retrieval
    /// owner. The returned Arc points at the same concrete Worker instance as
    /// the public Local Cognition view.
    #[must_use]
    pub fn work_memory_retrieval_port(&self) -> Arc<dyn WorkMemoryRetrievalPort> {
        Arc::clone(&self.work_memory_retrieval_port)
    }

    #[must_use]
    pub fn with_memory_mutation(
        mut self,
        authority: Arc<Mutex<MemoryAuthority>>,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        self.memory_mutation_port = Arc::new(MemoryMutationPortAdapter::new(
            authority,
            principal_resolver,
        ));
        self
    }

    /// Installs the process-local, candidate-only producer registry used by
    /// explicitly admitted Agent/Model/Harness runtimes. The registry is not
    /// reachable through the public protobuf Local API.
    pub fn with_memory_candidate_producers<I>(
        mut self,
        authority: Arc<Mutex<MemoryAuthority>>,
        bindings: I,
    ) -> Result<Self, DaemonCompositionError>
    where
        I: IntoIterator<Item = MemoryCandidateProducerBinding>,
    {
        self.memory_candidate_producers = Arc::new(
            MemoryCandidateProducerRegistry::new(authority, bindings)
                .map_err(DaemonCompositionError::MemoryCandidateProducers)?,
        );
        Ok(self)
    }

    /// Installs the first production Harness composition. Task Authority,
    /// Collaboration Control, and the Harness Adapter remain separate owners;
    /// the returned runner is the only process-local writer that sequences
    /// activation consumption and dispatch for this vertical.
    ///
    /// The admitted profile chooses the driver, its executable and the
    /// composition identity, so one production route composes at a time and
    /// an unadmitted Harness kind is refused instead of silently falling back.
    pub fn with_codex_harness(
        self,
        config: CodexHarnessCompositionConfig,
        provider_profile: ProviderBootstrapProfile,
        artifact_authority: Arc<
            Mutex<egopulse_artifact_authority::ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>,
        >,
        verification: Arc<Mutex<egopulse_verification_authority::VerificationAuthority>>,
    ) -> Result<Self, DaemonCompositionError> {
        config.validate()?;
        let CodexHarnessCompositionConfig {
            native,
            codex_executable,
            environment_overrides,
            work_capability_route,
        } = config;
        let disclosure_credentials =
            codex_disclosure_credentials(&provider_profile, &environment_overrides);
        let route_profile = trusted_codex_route_profile(&provider_profile, &native)?;
        if let Some(route) = work_capability_route.as_ref() {
            validate_codex_work_capability_route(route, &provider_profile, &native)?;
        }
        let capability_profile_ref = native.workflow.capability_profile_ref.clone();
        let ProviderHarnessIdentity {
            adapter_id,
            capability_profile_id,
        } = production_harness_identity(provider_profile.harness).ok_or(
            DaemonCompositionError::InvalidConfiguration(
                "provider_profiles.production_harness_kind",
            ),
        )?;
        let (observed_protocol, schema_attestation_gap, driver) = match provider_profile.harness {
            bootstrap::ProviderHarnessKind::CodexAppServer => {
                let mut process = CodexAppServerConfig::new(codex_executable);
                for (name, value) in &environment_overrides {
                    process = process.with_environment_override(name.clone(), value.clone());
                }
                (
                    codex_protocol_fingerprint(),
                    None,
                    Box::new(CodexAppServerDriver::new(process))
                        as Box<dyn NativeHarnessDriver + Send>,
                )
            }
            bootstrap::ProviderHarnessKind::OpenCodeAcp => {
                let native_executable_version = provider_profile
                    .catalog_snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.harness_version.trim().to_owned())
                    .filter(|version| !version.is_empty())
                    .ok_or(DaemonCompositionError::InvalidConfiguration(
                        "provider_profiles.production_harness_version",
                    ))?;
                let mut process = egopulse_opencode_adapter::OpenCodeAcpConfig::new(
                    provider_profile.executable.clone(),
                    native.workspace_root.clone(),
                    provider_profile.exact_model.clone(),
                );
                for (name, value) in &environment_overrides {
                    process = process.with_environment_override(name.clone(), value.clone());
                }
                (
                    egopulse_opencode_adapter::opencode_acp_protocol_fingerprint(
                        native_executable_version,
                    ),
                    Some(
                        egopulse_opencode_adapter::OPENCODE_ACP_SCHEMA_ATTESTATION_REQUIRED
                            .to_owned(),
                    ),
                    Box::new(egopulse_opencode_adapter::OpenCodeAcpDriver::new(process))
                        as Box<dyn NativeHarnessDriver + Send>,
                )
            }
            _ => {
                return Err(DaemonCompositionError::InvalidConfiguration(
                    "provider_profiles.production_harness_kind",
                ));
            }
        };
        self.with_profiled_native_harness_drivers(
            vec![ProfiledNativeHarnessComposition {
                config: native,
                profile: NativeHarnessCompositionProfile {
                    adapter_id: adapter_id.to_owned(),
                    capability_profile_id: capability_profile_id.to_owned(),
                    capability_profile_ref,
                    observed_protocol,
                    final_artifact_relation_policy:
                        FinalArtifactRelationPolicy::RequiredGovernedContent,
                    schema_attestation_gap,
                },
                driver,
                route_profile: Some(route_profile),
                work_capability_route,
                disclosure_credentials,
            }],
            artifact_authority,
            verification,
        )
    }

    /// Installs the production Harness composition around an explicit native
    /// driver. Codex is the normal caller, while deterministic integration
    /// fixtures can provide the same `NativeHarnessDriver` contract without
    /// bypassing Collaboration Control, Adapter Edge, Artifact Authority, or
    /// Verification Authority.
    pub fn with_native_harness_driver<D>(
        self,
        config: NativeHarnessCompositionConfig,
        artifact_authority: Arc<
            Mutex<egopulse_artifact_authority::ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>,
        >,
        verification: Arc<Mutex<egopulse_verification_authority::VerificationAuthority>>,
        driver: D,
    ) -> Result<Self, DaemonCompositionError>
    where
        D: NativeHarnessDriver + Send + 'static,
    {
        let capability_profile_ref = config.workflow.capability_profile_ref.clone();
        self.with_profiled_native_harness_driver(
            config,
            artifact_authority,
            verification,
            NativeHarnessCompositionProfile {
                adapter_id: CODEX_ADAPTER_ID.to_owned(),
                capability_profile_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
                capability_profile_ref,
                observed_protocol: codex_protocol_fingerprint(),
                final_artifact_relation_policy:
                    FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
                schema_attestation_gap: None,
            },
            driver,
        )
    }

    /// Installs a native Harness composition using an explicitly admitted
    /// provider profile. The profile is an input to composition, not an
    /// admission mechanism: callers must obtain it from the relevant
    /// capability-attestation path before invoking this method. This keeps
    /// multi-model support provider-neutral without allowing an unverified
    /// driver to become production merely by being wired into the daemon.
    pub fn with_profiled_native_harness_driver<D>(
        self,
        config: NativeHarnessCompositionConfig,
        artifact_authority: Arc<
            Mutex<egopulse_artifact_authority::ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>,
        >,
        verification: Arc<Mutex<egopulse_verification_authority::VerificationAuthority>>,
        profile: NativeHarnessCompositionProfile,
        driver: D,
    ) -> Result<Self, DaemonCompositionError>
    where
        D: NativeHarnessDriver + Send + 'static,
    {
        self.with_profiled_native_harness_drivers(
            vec![ProfiledNativeHarnessComposition {
                config,
                profile,
                driver: Box::new(driver),
                route_profile: None,
                work_capability_route: None,
                disclosure_credentials:
                    egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(),
            }],
            artifact_authority,
            verification,
        )
    }

    /// Installs multiple independently profile-bound native Harness units.
    /// All units share the Task activation source, but each owns an isolated
    /// Collaboration store and Adapter Edge. The daemon invokes the resulting
    /// composite as one scheduled worker; it does not select, merge or
    /// downgrade providers.
    pub fn with_profiled_native_harness_drivers(
        mut self,
        compositions: Vec<ProfiledNativeHarnessComposition>,
        artifact_authority: Arc<
            Mutex<egopulse_artifact_authority::ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>,
        >,
        verification: Arc<Mutex<egopulse_verification_authority::VerificationAuthority>>,
    ) -> Result<Self, DaemonCompositionError> {
        if self.harness_dispatch_runner.is_some() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "Harness runner already configured",
            ));
        }
        if compositions.is_empty() {
            return Err(DaemonCompositionError::InvalidConfiguration(
                "at least one profiled native Harness is required",
            ));
        }
        let mut collaboration_paths = HashSet::new();
        let mut adapter_paths = HashSet::new();
        for composition in &compositions {
            composition.config.validate()?;
            composition.profile.validate()?;
            if composition.profile.capability_profile_ref
                != composition.config.workflow.capability_profile_ref
            {
                return Err(DaemonCompositionError::InvalidConfiguration(
                    "native Harness workflow/profile reference mismatch",
                ));
            }
            if !collaboration_paths.insert(composition.config.collaboration_database_path.clone())
                || !adapter_paths.insert(composition.config.adapter_database_path.clone())
            {
                return Err(DaemonCompositionError::InvalidConfiguration(
                    "multi-Harness stores must be isolated",
                ));
            }
        }
        let source = self.task_activation_source.take().ok_or(
            DaemonCompositionError::InvalidConfiguration("Task activation source"),
        )?;
        let approval_delivery_source = self.approval_delivery_source.clone();
        let cancellation_delivery_source = self.cancellation_delivery_source.clone();
        let artifact_return_source: Arc<dyn ArtifactReturnSource> = Arc::new(
            ArtifactAuthorityReturnSource::new(Arc::clone(&artifact_authority)),
        );
        let mut runners = Vec::with_capacity(compositions.len());
        let mut approval_routes = Vec::with_capacity(compositions.len());
        let mut cancellation_routes = Vec::with_capacity(compositions.len());
        for composition in compositions {
            let ProfiledNativeHarnessComposition {
                config,
                profile,
                driver,
                route_profile,
                work_capability_route,
                disclosure_credentials,
            } = composition;
            let NativeHarnessCompositionProfile {
                adapter_id,
                capability_profile_id,
                capability_profile_ref: _,
                observed_protocol,
                final_artifact_relation_policy,
                schema_attestation_gap: _,
            } = profile;
            let repository_dispatch = match self.repository_dispatch.as_ref() {
                Some(repository) if repository.coordinator.is_some() => {
                    repository.coordinator.clone()
                }
                Some(repository) => {
                    let context = self.context_authority.as_ref().ok_or(
                        DaemonCompositionError::InvalidConfiguration(
                            "repository dispatch Context Authority",
                        ),
                    )?;
                    Some(Arc::new(
                        repository_dispatch::RepositoryDispatchCoordinator::new(
                            Arc::clone(context),
                            Arc::clone(&artifact_authority),
                            repository.admission.clone(),
                            repository.material.clone(),
                            config.workspace_root.clone(),
                            repository_dispatch::RepositoryDispatchArtifactPolicy {
                                artifact_type_ref: config
                                    .return_collector
                                    .artifact_type_ref
                                    .clone(),
                                transformation_contract_ref: config
                                    .return_collector
                                    .transformation_contract_ref
                                    .clone(),
                                retention_profile_ref: config
                                    .return_collector
                                    .retention_profile_ref
                                    .clone(),
                                artifact_authority_principal_id: config
                                    .return_collector
                                    .artifact_authority_principal_id
                                    .clone(),
                                attempt_supervisor_principal_id: config
                                    .workflow
                                    .attempt_supervisor_principal_id
                                    .clone(),
                                evidence_profile_ref: config
                                    .return_collector
                                    .evidence_profile_ref
                                    .clone(),
                            },
                        )
                        .map_err(DaemonCompositionError::InvalidConfiguration)?,
                    ))
                }
                None => None,
            };
            let repository_commands = match (
                repository_dispatch.as_ref(),
                self.repository_dispatch.as_ref(),
            ) {
                (Some(_), Some(repository)) => Some(Arc::new(
                    repository_command::RepositoryCommandArtifactRunner::new(
                        Arc::clone(&artifact_authority),
                        repository_command::RepositoryCommandArtifactConfig {
                            intent_type_ref: repository.command_artifacts.intent_type_ref.clone(),
                            intent_transformation_ref: repository
                                .command_artifacts
                                .intent_transformation_ref
                                .clone(),
                            receipt_type_ref: repository.command_artifacts.receipt_type_ref.clone(),
                            receipt_transformation_ref: repository
                                .command_artifacts
                                .receipt_transformation_ref
                                .clone(),
                            retention_profile_ref: config
                                .return_collector
                                .retention_profile_ref
                                .clone(),
                            supervised_runner_principal_id: config
                                .workflow
                                .attempt_supervisor_principal_id
                                .clone(),
                            artifact_authority_principal_id: config
                                .return_collector
                                .artifact_authority_principal_id
                                .clone(),
                            component_name: "agentosd-repository-command-runner".to_owned(),
                            component_version: env!("CARGO_PKG_VERSION").to_owned(),
                            sensitivity_class: "local-user-data".to_owned(),
                        },
                    )
                    .map_err(|_| {
                        DaemonCompositionError::InvalidConfiguration(
                            "repository command Artifact policy",
                        )
                    })?,
                )),
                (None, None) => None,
                _ => {
                    return Err(DaemonCompositionError::InvalidConfiguration(
                        "repository return composition",
                    ));
                }
            };
            let reader_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let collector_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let content_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let content_projection_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let approval_projection_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let approval_route_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let writer_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let evidence = GovernedReturnEvidenceResolver::new(
                reader_edge,
                Arc::clone(&artifact_authority),
                Arc::clone(&verification),
            );
            let evidence = match approval_delivery_source.as_ref() {
                Some(source) => evidence.with_approval_delivery_source(Arc::clone(source)),
                None => evidence,
            };
            // The dispatch owner emits durable Collaboration projections;
            // attach its outbox to the same projector as the Task owner.
            // This separate owner handle exposes only projection read/ACK.
            let projection_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path.clone(),
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch.clone(),
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let (projection_guard, _) = TaskActivationGuardSet::new(
                egopulse_local_ide_control::collaboration_control::AdapterBackedHarnessEvidenceResolver::new(projection_edge),
            );
            let projection_owner = CollaborationControl::open(
                CollaborationControlConfig {
                    database_path: config.collaboration_database_path.clone(),
                    store_epoch: config.collaboration_store_epoch.clone(),
                    key: CollaborationSqlCipherKey::new(config.collaboration_key),
                },
                projection_guard,
                SystemAuthorityClock,
            )
            .map_err(DaemonCompositionError::Collaboration)?;
            let mut sources = self
                .projection_source
                .take()
                .into_iter()
                .collect::<Vec<_>>();
            sources.push(Arc::new(CollaborationProjectionSource::new(
                projection_owner,
            )));
            sources.push(Arc::new(AdapterEdgeApprovalProjectionSource::new(
                approval_projection_edge,
            )));
            self.projection_source = Some(Arc::new(CompositeOwnerProjectionSource::new(sources)));
            let lineage_reader_config = CollaborationLineageReaderConfig {
                database_path: config.collaboration_database_path.clone(),
                store_epoch: config.collaboration_store_epoch.clone(),
                key: CollaborationSqlCipherKey::new(config.collaboration_key),
            };
            self.harness_content_lineage_readers
                .push(Arc::new(Mutex::new(
                    CollaborationLineageReader::open(lineage_reader_config)
                        .map_err(DaemonCompositionError::Collaboration)?,
                )));
            let file_material = match config.default_model.as_ref() {
                Some(model) => FileDispatchMaterialResolver::new(
                    config.input_bundle_root,
                    config.workspace_root,
                )
                .with_default_model(model.clone()),
                None => FileDispatchMaterialResolver::new(
                    config.input_bundle_root,
                    config.workspace_root,
                ),
            };
            let approval_route_adapter_id = adapter_id.clone();
            let approval_route_profile_id = capability_profile_id.clone();
            let approval_route_principal_id = config.workflow.harness_adapter_principal_id.clone();
            let mut adapter = GovernedHarnessAdapter::new(
                adapter_id,
                capability_profile_id,
                observed_protocol,
                writer_edge,
                file_material,
                driver,
                SystemAdapterClock,
            )
            .with_final_artifact_relation_policy(final_artifact_relation_policy);
            self.harness_content_workers.push(HarnessContentWorker {
                projector: Arc::new(Mutex::new(GovernedHarnessContentProjector::new(
                    content_edge,
                    disclosure_credentials,
                    SystemAdapterClock,
                ))),
                projection_edge: Arc::new(Mutex::new(content_projection_edge)),
            });
            if let Some(route_profile) = route_profile.as_ref() {
                adapter = adapter.with_dispatch_route_binding(
                    build_dispatch_route_binding(route_profile).map_err(|_| {
                        DaemonCompositionError::InvalidConfiguration(
                            "native Harness dispatch route binding",
                        )
                    })?,
                    config.default_model.clone().ok_or(
                        DaemonCompositionError::InvalidConfiguration(
                            "native Harness dispatch route model",
                        ),
                    )?,
                );
            }
            let mut adapter = match self.context_authority.as_ref() {
                Some(context) => adapter
                    .with_dispatch_context_authorization_gate(
                        context_material::ContextDispatchAuthorizationGate::new(Arc::clone(
                            context,
                        )),
                    )
                    .with_dispatch_context_recovery_gate(
                        context_material::ContextDispatchRecoveryGate::new(Arc::clone(context)),
                    ),
                None => adapter,
            };
            if let Some(repository_dispatch) = repository_dispatch.as_ref() {
                adapter = adapter.with_ready_dispatch_material_guard(repository_dispatch.clone());
            }
            // The guard observes the exact adapter moved into this runner.
            // A separately reopened edge cannot prove process-local absence.
            let evidence = evidence.with_runtime_residency(adapter.runtime_residency_reader());
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
            let principal = AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::HarnessAdapter,
                principal_id: config.workflow.harness_adapter_principal_id.clone(),
                authenticated: true,
            };
            let capability_profile_ref = config.workflow.capability_profile_ref.clone();
            let resolver = ConfiguredSingleHarnessWorkflow::new(config.workflow);
            let resolver = match route_profile {
                Some(route_profile) => resolver.with_trusted_dispatch_route_profile(route_profile),
                None => resolver,
            };
            let resolver = match work_capability_route {
                Some(route) => resolver.with_work_capability_route(route),
                None => resolver,
            };
            let resolver = match self.context_authority.as_ref() {
                Some(context) => resolver.with_context_authority(Arc::clone(context)),
                None => resolver,
            };
            let artifact_return_principal = AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::ArtifactAuthority,
                principal_id: config
                    .return_collector
                    .artifact_authority_principal_id
                    .clone(),
                authenticated: true,
            };
            let mut runner = GovernedTaskActivationRunner::new(
                control,
                adapter,
                Arc::clone(&source),
                resolver,
                principal,
                reference,
                config.lease_ttl_seconds,
            )
            .with_capability_profile_ref(capability_profile_ref)
            .with_artifact_return_source(
                Arc::clone(&artifact_return_source),
                artifact_return_principal,
            )
            .with_step_return_principal(AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::CollaborationControl,
                principal_id: "collaboration-control:return-settlement".to_owned(),
                authenticated: true,
            });
            if let Some(repository_dispatch) = repository_dispatch.as_ref() {
                runner = runner.with_task_dispatch_material_preparer(repository_dispatch.clone());
            }
            let runner = Arc::new(runner);
            let approval_target: Arc<dyn HarnessApprovalDeliveryTarget> = runner.clone();
            let cancellation_target: Arc<dyn HarnessCancellationDeliveryTarget> = runner.clone();
            approval_routes.push(
                approval_delivery::ApprovalDeliveryRoute::new(
                    approval_route_adapter_id,
                    approval_route_profile_id,
                    approval_route_principal_id,
                    approval_route_edge,
                    approval_target,
                )
                .map_err(|_| {
                    DaemonCompositionError::InvalidConfiguration("approval delivery route")
                })?,
            );
            cancellation_routes.push(cancellation_delivery::CancellationDeliveryRoute::new(
                cancellation_target,
            ));
            let harness: Arc<dyn HarnessDispatchRunner> = runner;
            let mut collector = GovernedReturnCollectorRunner::new(
                harness,
                collector_edge,
                Arc::clone(&artifact_authority),
                config.return_collector,
            )
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
            if let (Some(repository_dispatch), Some(repository_commands)) =
                (repository_dispatch, repository_commands)
            {
                collector =
                    collector.with_repository_return(repository_dispatch, repository_commands);
            }
            runners.push(Arc::new(collector) as Arc<dyn HarnessDispatchRunner>);
        }
        let composite = CompositeHarnessDispatchRunner::new(runners)
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
        let evidence_intake = crate::task_evidence::GovernedTaskEvidenceIntakeRunner::new(
            Arc::new(composite),
            artifact_return_source,
            Arc::clone(&self.task_port),
        );
        self.harness_dispatch_runner = Some(Arc::new(evidence_intake));
        if let Some(approval_delivery_source) = approval_delivery_source {
            self.approval_delivery_worker = Some(Arc::new(
                approval_delivery::ApprovalDeliveryWorker::new(
                    approval_delivery_source,
                    approval_routes,
                )
                .map_err(|_| {
                    DaemonCompositionError::InvalidConfiguration("approval delivery worker")
                })?,
            ));
        }
        if let Some(cancellation_delivery_source) = cancellation_delivery_source {
            let reconciler = self.task_cancellation_reconciler.clone().ok_or(
                DaemonCompositionError::InvalidConfiguration("Task cancellation reconciler"),
            )?;
            self.cancellation_delivery_worker = Some(Arc::new(
                cancellation_delivery::CancellationDeliveryWorker::new(
                    cancellation_delivery_source,
                    cancellation_routes,
                )
                .map_err(|_| {
                    DaemonCompositionError::InvalidConfiguration("cancellation delivery worker")
                })?
                .with_task_reconciliation(reconciler)
                .with_lineage_readers(self.harness_content_lineage_readers.clone()),
            ));
        }
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
    #[error("Memory retrieval composition is invalid")]
    MemoryRetrieval(#[source] MemoryRetrievalConfigurationError),
    #[error("Memory candidate producer composition is invalid")]
    MemoryCandidateProducers(#[source] MemoryCandidateProducerConfigurationError),
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonServeError {
    #[error("daemon server failed")]
    Server(#[from] tonic::transport::Error),
    #[error("projection pump failed")]
    Projection(#[from] ProjectionPumpFailure),
    #[error("harness dispatch runner failed")]
    Dispatch(#[from] HarnessDispatchCycleError),
    #[error("approval delivery worker failed")]
    ApprovalDelivery,
    #[error("cancellation delivery worker failed")]
    CancellationDelivery,
    #[error("verification worker failed")]
    Verification(#[from] VerificationWorkerCycleError),
    #[error("Founder Verdict consume worker failed")]
    FounderVerdictConsume(#[from] FounderVerdictConsumeCycleError),
    #[error("daemon background worker stopped unexpectedly")]
    BackgroundStopped,
}

pub struct DaemonComposition {
    address: LocalIpcAddress,
    listener: LocalIpcListener,
    session: LocalSessionEndpoint,
    read_model: LocalReadModelEndpoint,
    command: LocalCommandGatewayEndpoint,
    cognition: LocalCognitionEndpoint,
    projection_pump: Option<ProjectionPump>,
    harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    approval_delivery_worker: Option<Arc<approval_delivery::ApprovalDeliveryWorker>>,
    cancellation_delivery_worker: Option<Arc<cancellation_delivery::CancellationDeliveryWorker>>,
    harness_dispatch_interval: Duration,
    verification_worker: Option<Arc<dyn VerificationWorker>>,
    verification_interval: Duration,
    founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    verdict_consumption_interval: Duration,
    harness_content_workers: Vec<HarnessContentWorker>,
    harness_content_read_model: Arc<Mutex<LocalReadModel>>,
    harness_content_notifier: HarnessContentCommitNotifier,
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
        let initial_content_position = model
            .harness_content_position()
            .map_err(DaemonCompositionError::ReadModel)?;
        let model = Arc::new(Mutex::new(model));
        let reader = Arc::new(BlockingLocalReadModelReader::new(Arc::clone(&model)));
        let notifier = ProjectionCommitNotifier::new(initial_position.clone());
        let content_notifier = HarnessContentCommitNotifier::new(initial_content_position);
        let position_provider = Arc::new(SharedProjectionPosition::new(initial_position));
        let content_scope_reader: Arc<dyn HarnessContentScopeReader> = match (
            providers.harness_content_task_authority.as_ref(),
            providers.harness_content_lineage_readers.is_empty(),
        ) {
            (Some(task), false) => Arc::new(AuthorityHarnessContentScopeReader {
                task: Arc::clone(task),
                lineage_readers: providers.harness_content_lineage_readers.clone(),
            }),
            _ => Arc::new(FailClosedHarnessContentScopeReader),
        };

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
        let read_application = Arc::new(ReadGatewayApplication::new_with_harness_content(
            Arc::clone(&registry),
            profiles.clone(),
            reader,
            notifier.clone(),
            content_scope_reader,
            content_notifier.clone(),
            token_codec.clone(),
            Arc::new(NoopReadGatewayAuditSink),
        ));
        let read_model = LocalReadModelEndpoint::new(read_application);
        let command_application = Arc::new(CommandGatewayApplication::new_with_memory_and_work(
            Arc::clone(&registry),
            Arc::clone(&profiles),
            token_codec,
            providers.task_port,
            providers.policy_port,
            providers.verdict_port,
            CommandExtensionPorts::new(
                providers.memory_mutation_port,
                providers.work_preparation_port,
            )
            .with_context(providers.context_mutation_port)
            .with_work_capability(providers.work_capability_port)
            .with_founder_supporting_material(providers.founder_supporting_material_port),
        ));
        let command = LocalCommandGatewayEndpoint::new(command_application);
        let cognition_application = Arc::new(CognitionGatewayApplication::new(
            registry,
            profiles,
            providers.memory_retrieval_port,
            providers.memory_retrieval_audit,
        ));
        let cognition = LocalCognitionEndpoint::new(cognition_application);
        let projection_pump = providers
            .projection_source
            .map(|source| ProjectionPump::new(Arc::clone(&model), notifier, source));
        let harness_dispatch_runner = providers.harness_dispatch_runner;
        let approval_delivery_worker = providers.approval_delivery_worker;
        let cancellation_delivery_worker = providers.cancellation_delivery_worker;
        let verification_worker = providers.verification_worker;
        let founder_verdict_consume_worker = providers.founder_verdict_consume_worker;
        let harness_content_workers = providers.harness_content_workers;

        Ok(Self {
            address,
            listener,
            session,
            read_model,
            command,
            cognition,
            projection_pump,
            harness_dispatch_runner,
            approval_delivery_worker,
            cancellation_delivery_worker,
            harness_dispatch_interval: config.harness_dispatch_interval,
            verification_worker,
            verification_interval: config.verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval: config.verdict_consumption_interval,
            harness_content_workers,
            harness_content_read_model: model,
            harness_content_notifier: content_notifier,
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
            cognition,
            projection_pump,
            harness_dispatch_runner,
            approval_delivery_worker,
            cancellation_delivery_worker,
            harness_dispatch_interval,
            verification_worker,
            verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval,
            harness_content_workers,
            harness_content_read_model,
            harness_content_notifier,
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
                .add_service(LocalCognitionServiceServer::new(cognition))
                .serve_with_incoming_shutdown(listener.into_incoming(), server_shutdown),
        );
        let mut background = Box::pin(run_background_workers(BackgroundWorkerInputs {
            projection_pump,
            harness_dispatch_runner,
            harness_dispatch_interval,
            approval_delivery_worker,
            cancellation_delivery_worker,
            verification_worker,
            verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval,
            harness_content_workers,
            read_model: harness_content_read_model,
            content_notifier: harness_content_notifier,
            stop: stop_receiver,
        }));
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

struct BackgroundWorkerInputs {
    projection_pump: Option<ProjectionPump>,
    harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    harness_dispatch_interval: Duration,
    approval_delivery_worker: Option<Arc<approval_delivery::ApprovalDeliveryWorker>>,
    cancellation_delivery_worker: Option<Arc<cancellation_delivery::CancellationDeliveryWorker>>,
    verification_worker: Option<Arc<dyn VerificationWorker>>,
    verification_interval: Duration,
    founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    verdict_consumption_interval: Duration,
    harness_content_workers: Vec<HarnessContentWorker>,
    read_model: Arc<Mutex<LocalReadModel>>,
    content_notifier: HarnessContentCommitNotifier,
    stop: tokio::sync::watch::Receiver<bool>,
}

async fn run_background_workers(inputs: BackgroundWorkerInputs) -> Result<(), DaemonServeError> {
    let BackgroundWorkerInputs {
        projection_pump,
        harness_dispatch_runner,
        harness_dispatch_interval,
        approval_delivery_worker,
        cancellation_delivery_worker,
        verification_worker,
        verification_interval,
        founder_verdict_consume_worker,
        verdict_consumption_interval,
        harness_content_workers,
        read_model,
        content_notifier,
        stop,
    } = inputs;
    let mut workers = tokio::task::JoinSet::new();
    if let Some(projection_pump) = projection_pump {
        let stop = stop.clone();
        workers.spawn(async move {
            projection_pump
                .run(stop)
                .await
                .map_err(DaemonServeError::Projection)
        });
    }
    if let Some(runner) = harness_dispatch_runner {
        let stop = stop.clone();
        workers.spawn(async move {
            run_harness_dispatch_worker(runner, harness_dispatch_interval, stop)
                .await
                .map_err(DaemonServeError::Dispatch)
        });
    }
    if let Some(worker) = approval_delivery_worker {
        let stop = stop.clone();
        workers.spawn(async move {
            run_approval_delivery_worker(worker, harness_dispatch_interval, stop)
                .await
                .map_err(|_| DaemonServeError::ApprovalDelivery)
        });
    }
    if let Some(worker) = cancellation_delivery_worker {
        let stop = stop.clone();
        workers.spawn(async move {
            run_cancellation_delivery_worker(worker, harness_dispatch_interval, stop)
                .await
                .map_err(|_| DaemonServeError::CancellationDelivery)
        });
    }
    if let Some(worker) = verification_worker {
        let stop_for_worker = stop.clone();
        workers.spawn(async move {
            run_verification_worker(worker, verification_interval, stop_for_worker)
                .await
                .map_err(DaemonServeError::Verification)
        });
    }
    if let Some(worker) = founder_verdict_consume_worker {
        let stop_for_worker = stop.clone();
        workers.spawn(async move {
            run_founder_verdict_consume_worker(
                worker,
                verdict_consumption_interval,
                stop_for_worker,
            )
            .await
            .map_err(DaemonServeError::FounderVerdictConsume)
        });
    }
    for worker in harness_content_workers {
        let stop_for_worker = stop.clone();
        let read_model = Arc::clone(&read_model);
        let content_notifier = content_notifier.clone();
        workers.spawn(async move {
            run_harness_content_worker(worker, read_model, content_notifier, stop_for_worker).await;
            Ok(())
        });
    }
    if workers.is_empty() {
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
    if let Some(result) = workers.join_next().await {
        workers.abort_all();
        match result {
            Ok(result) => result,
            Err(_) => Err(DaemonServeError::BackgroundStopped),
        }
    } else {
        Err(DaemonServeError::BackgroundStopped)
    }
}

const HARNESS_CONTENT_DRAIN_BATCH: usize = 32;
const HARNESS_CONTENT_DRAIN_INTERVAL: Duration = Duration::from_millis(100);

async fn run_harness_content_worker(
    worker: HarnessContentWorker,
    read_model: Arc<Mutex<LocalReadModel>>,
    content_notifier: HarnessContentCommitNotifier,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(HARNESS_CONTENT_DRAIN_INTERVAL);
    ticker.tick().await;
    loop {
        if *stop.borrow() {
            return;
        }
        let mut fatal = false;
        for _ in 0..HARNESS_CONTENT_DRAIN_BATCH {
            let projection_result = match worker.projector.lock() {
                Ok(mut projector) => projector.drain_once(),
                Err(_) => {
                    tracing::error!("Harness content projector lock failed closed");
                    fatal = true;
                    break;
                }
            };
            let projector_idle = match projection_result {
                Ok(
                    HarnessContentDrain::Idle | HarnessContentDrain::FinalArtifactRelationPending,
                ) => true,
                Ok(
                    HarnessContentDrain::Committed(_)
                    | HarnessContentDrain::FinalArtifactRelationCommitted
                    | HarnessContentDrain::FinalArtifactRelationSkipped
                    | HarnessContentDrain::Replayed
                    | HarnessContentDrain::Quarantined { .. },
                ) => false,
                Err(_) => {
                    tracing::error!("Harness content projector stopped in its isolated domain");
                    fatal = true;
                    break;
                }
            };
            let message = match worker.projection_edge.lock() {
                Ok(edge) => match edge.pending_safe_content_projection() {
                    Ok(messages) => messages.into_iter().next(),
                    Err(_) => {
                        tracing::error!(
                            "Harness content safe outbox read stopped in its isolated domain"
                        );
                        fatal = true;
                        break;
                    }
                },
                Err(_) => {
                    tracing::error!("Harness content projection Edge lock failed closed");
                    fatal = true;
                    break;
                }
            };
            let Some(message) = message else {
                if projector_idle {
                    break;
                }
                continue;
            };
            let projected_at = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(value) => prost_types::Timestamp {
                    seconds: match i64::try_from(value.as_secs()) {
                        Ok(seconds) => seconds,
                        Err(_) => {
                            tracing::error!("Harness content projection clock failed closed");
                            fatal = true;
                            break;
                        }
                    },
                    nanos: i32::try_from(value.subsec_nanos())
                        .expect("subsecond nanoseconds always fit i32"),
                },
                Err(_) => {
                    tracing::error!("Harness content projection clock failed closed");
                    fatal = true;
                    break;
                }
            };
            let apply_result = match read_model.lock() {
                Ok(mut model) => {
                    let applied = model.apply_harness_content(
                        &egopulse_local_read_model::HarnessContentProjectionInput {
                            delivery_id: message.message_id.clone(),
                            payload_digest_sha256: message.payload_digest_sha256.clone(),
                            event: message.event,
                            projected_at,
                        },
                    );
                    match applied {
                        Ok(_) => model.harness_content_position(),
                        Err(error) => Err(error),
                    }
                }
                Err(_) => {
                    tracing::error!("Harness content Local Read Model lock failed closed");
                    fatal = true;
                    break;
                }
            };
            let projected_position = match apply_result {
                Ok(position) => position,
                Err(_) => {
                    tracing::error!(
                        "Harness content Local Read Model projection stopped in its isolated domain"
                    );
                    fatal = true;
                    break;
                }
            };
            content_notifier.publish(projected_position);
            let acknowledge_result = match worker.projection_edge.lock() {
                Ok(mut edge) => edge.acknowledge_safe_content_projection(
                    &message.message_id,
                    &message.payload_digest_sha256,
                ),
                Err(_) => {
                    tracing::error!("Harness content projection Edge lock failed closed");
                    fatal = true;
                    break;
                }
            };
            if acknowledge_result.is_err() {
                tracing::error!("Harness content safe outbox ACK stopped in its isolated domain");
                fatal = true;
                break;
            }
        }
        if fatal {
            while !*stop.borrow() && stop.changed().await.is_ok() {}
            return;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {}
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
    let mut previous_blockages = std::collections::BTreeSet::new();
    let mut previous_held_returns = std::collections::BTreeSet::new();
    let mut append_deferred = false;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let report = match runner.run_once().await {
            Ok(report) => report,
            Err(HarnessDispatchCycleError::Adapter(error))
                if error.is_retryable_observation_append() =>
            {
                // Only an exact observation retained by this same Adapter may
                // retry here. Other storage/integrity failures remain fatal.
                if !append_deferred {
                    eprintln!(
                        "{}",
                        serde_json::json!({"event": "harness_observation_append_deferred"})
                    );
                }
                append_deferred = true;
                tokio::select! {
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            return Ok(());
                        }
                    }
                    _ = tokio::time::sleep(interval.max(Duration::from_millis(100))) => {}
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        if append_deferred {
            eprintln!(
                "{}",
                serde_json::json!({"event": "harness_observation_append_resumed"})
            );
            append_deferred = false;
        }
        // A return the Collaboration refuses on Attempt state is retried every
        // cycle and can never settle, so it is reported once per distinct
        // receipt and left in the outbox as the visible governance fact.
        let mut current_held_returns = std::collections::BTreeSet::new();
        for held in &report.held_return_receipts {
            let key = (held.receipt_id.clone(), held.safe_detail_code.clone());
            current_held_returns.insert(key.clone());
            if previous_held_returns.contains(&key) {
                continue;
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "artifact_return_held",
                    "receipt_id": held.receipt_id,
                    "run_id": held.run_id,
                    "attempt_id": held.attempt_id,
                    "safe_detail_code": held.safe_detail_code,
                })
            );
        }
        previous_held_returns = current_held_returns;
        let mut current_blockages = std::collections::BTreeSet::new();
        for blockage in report.activation_blockages {
            let key = (
                blockage.task_id.clone(),
                blockage.dispatch_id.clone(),
                blockage.safe_detail_code.clone(),
            );
            current_blockages.insert(key.clone());
            if previous_blockages.contains(&key) {
                continue;
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "task_activation_blocked",
                    "task_id": blockage.task_id,
                    "dispatch_id": blockage.dispatch_id,
                    "safe_detail_code": blockage.safe_detail_code,
                })
            );
        }
        previous_blockages = current_blockages;
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

async fn run_approval_delivery_worker(
    worker: Arc<approval_delivery::ApprovalDeliveryWorker>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), approval_delivery::ApprovalDeliveryCycleError> {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    let mut previous_holds = std::collections::BTreeSet::new();
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let report = worker.run_once().await?;
        let mut current_holds = std::collections::BTreeSet::new();
        for held in report.held {
            let key = (held.authority_decision_ref.clone(), held.safe_reason_code);
            current_holds.insert(key.clone());
            if previous_holds.contains(&key) {
                continue;
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "approval_delivery_held",
                    "authority_decision_ref": held.authority_decision_ref,
                    "approval_request_id": held.approval_request_id,
                    "safe_reason_code": held.safe_reason_code,
                })
            );
        }
        previous_holds = current_holds;
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = ticker.tick() => {}
        }
    }
}

async fn run_cancellation_delivery_worker(
    worker: Arc<cancellation_delivery::CancellationDeliveryWorker>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), cancellation_delivery::CancellationDeliveryCycleError> {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    let mut previous_holds = std::collections::BTreeSet::new();
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let report = worker.run_once().await?;
        let mut current_holds = std::collections::BTreeSet::new();
        for held in report.held {
            let key = (
                held.task_id.clone(),
                held.cancellation_request_id.clone(),
                held.safe_reason_code,
            );
            current_holds.insert(key.clone());
            if previous_holds.contains(&key) {
                continue;
            }
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "task_cancellation_delivery_held",
                    "task_id": held.task_id,
                    "cancellation_request_id": held.cancellation_request_id,
                    "safe_reason_code": held.safe_reason_code,
                })
            );
        }
        previous_holds = current_holds;
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = ticker.tick() => {}
        }
    }
}

async fn run_verification_worker(
    worker: Arc<dyn VerificationWorker>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), VerificationWorkerCycleError> {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        worker.run_once().await?;
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = ticker.tick() => {}
        }
    }
}

async fn run_founder_verdict_consume_worker(
    worker: Arc<dyn FounderVerdictConsumeWorker>,
    interval: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), FounderVerdictConsumeCycleError> {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    let mut last_failure = None;
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        let result = match worker.run_once().await {
            Ok(result) => {
                last_failure = None;
                result
            }
            Err(error) => {
                // Owner writes remain rejected and their durable outbox stays
                // pending. A held handoff must not stop unrelated workers.
                let reason = error.to_string();
                if last_failure.as_ref() != Some(&reason) {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "event": "founder_verdict_recovery_held", "reason": reason,
                        })
                    );
                    last_failure = Some(reason);
                }
                tokio::select! {
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() { return Ok(()); }
                    }
                    _ = ticker.tick() => {}
                }
                continue;
            }
        };
        match result {
            FounderVerdictConsumeCycleResult::Idle => {}
            FounderVerdictConsumeCycleResult::Expired {
                founder_verdict_id,
                task_id,
            } => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "unapplied_founder_verdict_expired",
                        "founder_verdict_id": founder_verdict_id, "task_id": task_id,
                    })
                );
            }
            FounderVerdictConsumeCycleResult::Consumed {
                message_id,
                founder_verdict_id,
                replayed,
            } => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "founder_verdict_consumed", "message_id": message_id,
                        "founder_verdict_id": founder_verdict_id, "replayed": replayed,
                    })
                );
            }
            FounderVerdictConsumeCycleResult::ApplicationAcknowledged {
                message_id,
                founder_verdict_id,
                task_id,
                replayed,
            } => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "founder_verdict_application_acknowledged", "message_id": message_id,
                        "founder_verdict_id": founder_verdict_id, "task_id": task_id, "replayed": replayed,
                    })
                );
            }
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            _ = ticker.tick() => {}
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
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        ApprovalDecisionEnvelope, CancelExecutionEnvelope, DispatchEnvelope, ProbeHarnessRequest,
        ProbeHarnessResult,
    };
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        ClientSurface, ConfirmWorkRequest, ExecuteFounderVerdictRequest, GetTaskViewRequest,
        LocalApiErrorCode, OpenSessionRequest, PrepareWorkRequest, UseDefaultWorkCapability,
        WorkMemoryMode, WorkSourceRequest,
        local_command_gateway_service_client::LocalCommandGatewayServiceClient,
        local_read_model_service_client::LocalReadModelServiceClient,
        local_session_service_client::LocalSessionServiceClient, prepare_work_request,
    };
    use egopulse_harness_adapter::{
        DriverDelivery, DriverError, NativeHarnessFuture, ReconciliationContext,
        ReconciliationFinding, ResolvedDispatchMaterial,
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
                verification_interval: Duration::from_millis(25),
                verdict_consumption_interval: Duration::from_millis(25),
            },
            root,
        )
    }

    struct CountingDispatchRunner {
        runs: Arc<AtomicUsize>,
    }

    struct OneFailureDispatchRunner {
        runs: Arc<AtomicUsize>,
        deferred: bool,
        invalid_deferred_source: bool,
    }

    impl HarnessDispatchRunner for OneFailureDispatchRunner {
        fn run_once(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                    + Send
                    + '_,
            >,
        > {
            let first = self.runs.fetch_add(1, Ordering::SeqCst) == 0;
            Box::pin(async move {
                if !first {
                    return Ok(HarnessDispatchCycleReport::default());
                }
                use egopulse_harness_adapter::{AdapterEdgeError, GovernedAdapterError};
                let error = if self.deferred {
                    if self.invalid_deferred_source {
                        GovernedAdapterError::ObservationAppendDeferred {
                            source: AdapterEdgeError::IntegrityFailure,
                        }
                    } else {
                        GovernedAdapterError::observation_append_busy_for_test()
                    }
                } else {
                    GovernedAdapterError::Edge(AdapterEdgeError::IntegrityFailure)
                };
                Err(HarnessDispatchCycleError::Adapter(error))
            })
        }
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

    #[derive(Clone, Copy)]
    struct WorkRoutePrincipalResolver;

    impl AuthorityPrincipalResolver for WorkRoutePrincipalResolver {
        fn resolve_task(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<egopulse_cognition_runtime::task_authority::PrincipalKind, CommandPortFailure>
        {
            Ok(egopulse_cognition_runtime::task_authority::PrincipalKind::Founder)
        }

        fn resolve_policy(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<egopulse_policy_decision_authority::PolicyPrincipalKind, CommandPortFailure>
        {
            Err(CommandPortFailure::Unavailable)
        }

        fn resolve_verdict(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<egopulse_founder_verdict_authority::VerdictPrincipalKind, CommandPortFailure>
        {
            Err(CommandPortFailure::Unavailable)
        }

        fn resolve_memory(
            &self,
            _principal: &CommandPrincipal,
        ) -> Result<
            egopulse_cognition_runtime::memory_authority::MemoryPrincipalKind,
            CommandPortFailure,
        > {
            Err(CommandPortFailure::Unavailable)
        }
    }

    #[derive(Clone, Copy)]
    struct UnusedPolicyReferences;

    impl egopulse_policy_decision_authority::PolicyReferenceResolver for UnusedPolicyReferences {
        fn resolve_issue(
            &self,
            _command: &egopulse_domain_contracts::v01::egopulse::policy::v1::IssueHarnessApprovalDecisionCommand,
            _principal: &egopulse_policy_decision_authority::AuthenticatedPolicyPrincipal,
        ) -> Result<
            egopulse_policy_decision_authority::ResolvedApprovalAuthorization,
            egopulse_policy_decision_authority::PolicyReferenceRejection,
        > {
            Err(egopulse_policy_decision_authority::PolicyReferenceRejection::PermissionDenied)
        }

        fn validate_adapter_receipt(
            &self,
            _command: &egopulse_domain_contracts::v01::egopulse::policy::v1::ConsumeHarnessApprovalDecisionCommand,
            _record: &egopulse_domain_contracts::v01::egopulse::policy::v1::HarnessApprovalDecisionRecord,
            _principal: &egopulse_policy_decision_authority::AuthenticatedPolicyPrincipal,
        ) -> Result<Vec<String>, egopulse_policy_decision_authority::PolicyReferenceRejection>
        {
            Err(egopulse_policy_decision_authority::PolicyReferenceRejection::PermissionDenied)
        }
    }

    #[derive(Clone, Copy)]
    struct UnusedVerdictReferences;

    impl egopulse_founder_verdict_authority::VerdictReferenceResolver for UnusedVerdictReferences {
        fn resolve_issue(
            &self,
            _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::IssueFounderVerdictCommand,
            _principal: &egopulse_founder_verdict_authority::AuthenticatedVerdictPrincipal,
        ) -> Result<
            (
                egopulse_founder_verdict_authority::ResolvedVerdictContext,
                egopulse_founder_verdict_authority::FounderAuthorization,
            ),
            egopulse_founder_verdict_authority::VerdictReferenceRejection,
        > {
            Err(egopulse_founder_verdict_authority::VerdictReferenceRejection::PermissionDenied)
        }

        fn validate_task_commit(
            &self,
            _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
            _scope: &egopulse_domain_contracts::v01::egopulse::verdict::v1::VerdictScope,
        ) -> Result<(), egopulse_founder_verdict_authority::VerdictReferenceRejection> {
            Err(egopulse_founder_verdict_authority::VerdictReferenceRejection::PermissionDenied)
        }
    }

    struct RouteProofDriver {
        sends: Arc<AtomicUsize>,
        envelope: Arc<Mutex<Option<DispatchEnvelope>>>,
    }

    impl NativeHarnessDriver for RouteProofDriver {
        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            Box::pin(async { panic!("runtime dispatch proof must not probe during execution") })
        }

        fn send_dispatch<'a>(
            &'a mut self,
            envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            *self.envelope.lock().expect("route proof envelope lock") = Some(envelope.clone());
            let dispatch_id = envelope.dispatch_id.clone();
            Box::pin(async move {
                Ok(DriverDelivery {
                    native_request_ref: format!("native-request:{dispatch_id}"),
                    native_session_ref: format!("native-session:{dispatch_id}"),
                    native_execution_ref: Some(format!("native-execution:{dispatch_id}")),
                    raw_evidence: b"route-proof-delivered".to_vec(),
                })
            })
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<
            'a,
            Result<Option<egopulse_harness_adapter::DriverEvent>, DriverError>,
        > {
            Box::pin(async { Ok(None) })
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            Box::pin(async {
                Ok(ReconciliationFinding::NoEffectProven {
                    evidence_ref: "route-proof:no-effect".to_owned(),
                })
            })
        }
    }

    struct CountingFounderVerdictConsumeWorker {
        runs: Arc<AtomicUsize>,
    }

    struct HeldFounderVerdictWorker(Arc<AtomicUsize>);

    impl FounderVerdictConsumeWorker for HeldFounderVerdictWorker {
        fn run_once<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            FounderVerdictConsumeCycleResult,
                            FounderVerdictConsumeCycleError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(FounderVerdictConsumeCycleError::ExpiryAuthorizationRejected) })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_founder_expiry_keeps_daemon_and_unrelated_dispatch_running() {
        let instance = format!("g4-verdict-held-worker-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let held_runs = Arc::new(AtomicUsize::new(0));
        let dispatch_runs = Arc::new(AtomicUsize::new(0));
        let providers = DaemonProviders::fail_closed()
            .with_founder_verdict_consume_worker(Arc::new(HeldFounderVerdictWorker(Arc::clone(
                &held_runs,
            ))))
            .with_harness_dispatch_runner(Arc::new(CountingDispatchRunner {
                runs: Arc::clone(&dispatch_runs),
            }));
        let daemon = DaemonComposition::build(config, providers).expect("daemon composition");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            daemon
                .serve(async {
                    let _ = shutdown_receiver.await;
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while held_runs.load(Ordering::SeqCst) < 2 || dispatch_runs.load(Ordering::SeqCst) < 2 {
                assert!(
                    !server.is_finished(),
                    "one held expiry must not stop the daemon"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("both workers keep polling");
        shutdown_sender
            .send(())
            .expect("daemon still accepts shutdown");
        server
            .await
            .expect("daemon joined")
            .expect("normal shutdown");
        let _ = fs::remove_dir_all(root);
    }

    impl FounderVerdictConsumeWorker for CountingFounderVerdictConsumeWorker {
        fn run_once<'a>(
            &'a self,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            FounderVerdictConsumeCycleResult,
                            FounderVerdictConsumeCycleError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(FounderVerdictConsumeCycleResult::Idle) })
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

    #[tokio::test]
    async fn harness_dispatch_worker_retries_only_deferred_append_errors() {
        for (deferred, invalid_deferred_source) in [(true, false), (false, false), (true, true)] {
            let runs = Arc::new(AtomicUsize::new(0));
            let runner = Arc::new(OneFailureDispatchRunner {
                runs: Arc::clone(&runs),
                deferred,
                invalid_deferred_source,
            });
            let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
            let worker = tokio::spawn(run_harness_dispatch_worker(
                runner,
                Duration::from_millis(1),
                stop_receiver,
            ));
            if deferred && !invalid_deferred_source {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while runs.load(Ordering::SeqCst) < 2 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("same runner must retry its retained append");
                stop_sender.send(true).expect("stop recovered worker");
                worker.await.expect("worker join").expect("clean stop");
            } else {
                let result = tokio::time::timeout(Duration::from_secs(2), worker)
                    .await
                    .expect("integrity error must stop the worker")
                    .expect("worker join");
                assert!(result.is_err(), "integrity errors must not be retried");
                assert_eq!(runs.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daemon_composition_polls_the_injected_harness_runner() {
        let instance = format!("g4-runner-worker-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let runs = Arc::new(AtomicUsize::new(0));
        let providers = DaemonProviders::fail_closed().with_harness_dispatch_runner(Arc::new(
            CountingDispatchRunner {
                runs: Arc::clone(&runs),
            },
        ));
        let daemon = DaemonComposition::build(config, providers).expect("daemon composition");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            daemon
                .serve(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("daemon should stop cleanly");
        });
        for _ in 0..100 {
            if runs.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        shutdown_sender
            .send(())
            .expect("daemon shutdown receiver should still be active");
        server.await.expect("daemon task should join");
        assert!(runs.load(Ordering::SeqCst) > 0);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn daemon_composition_polls_the_injected_founder_verdict_consumer() {
        let instance = format!("g4-verdict-consumer-worker-{}", Uuid::now_v7());
        let (config, root) = config(&instance);
        let runs = Arc::new(AtomicUsize::new(0));
        let providers = DaemonProviders::fail_closed().with_founder_verdict_consume_worker(
            Arc::new(CountingFounderVerdictConsumeWorker {
                runs: Arc::clone(&runs),
            }),
        );
        let daemon = DaemonComposition::build(config, providers).expect("daemon composition");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            daemon
                .serve(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("daemon should stop cleanly");
        });
        for _ in 0..100 {
            if runs.load(Ordering::SeqCst) > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        shutdown_sender
            .send(())
            .expect("daemon shutdown receiver should still be active");
        server.await.expect("daemon task should join");
        assert!(runs.load(Ordering::SeqCst) > 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn multi_harness_composition_is_fail_closed_before_daemon_build() {
        let empty = DaemonProviders::fail_closed().with_harness_dispatch_runners(Vec::new());
        assert!(matches!(
            empty,
            Err(DaemonCompositionError::InvalidConfiguration(
                "at least one Harness dispatch runner is required"
            ))
        ));

        let configured = DaemonProviders::fail_closed().with_harness_dispatch_runner(Arc::new(
            CountingDispatchRunner {
                runs: Arc::new(AtomicUsize::new(0)),
            },
        ));
        let replacement =
            configured.with_harness_dispatch_runners(vec![Arc::new(CountingDispatchRunner {
                runs: Arc::new(AtomicUsize::new(0)),
            })]);
        assert!(matches!(
            replacement,
            Err(DaemonCompositionError::InvalidConfiguration(
                "Harness runner already configured"
            ))
        ));
    }

    #[test]
    fn native_harness_profile_requires_explicit_identity_and_protocol_evidence() {
        fn composition_profile(
            capability: &CapabilityProfile,
        ) -> Result<NativeHarnessCompositionProfile, DaemonCompositionError> {
            NativeHarnessCompositionProfile::from_attested_capability(
                &ContractReference {
                    contract_id: "profile".to_owned(),
                    version: "v1".to_owned(),
                    sha256: "ab".repeat(32),
                },
                "family",
                capability,
                capability
                    .declaration
                    .as_ref()
                    .and_then(|declaration| declaration.native_protocol.clone())
                    .expect("test capability protocol"),
                &prost_types::Timestamp::default(),
            )
        }

        let capability = CapabilityProfile {
            profile_id: "profile".to_owned(),
            revision: 1,
            digest_sha256: "ab".repeat(32),
            status: egopulse_domain_contracts::v01::egopulse::harness::v1::CapabilityProfileStatus::Active
                as i32,
            declaration: Some(
                egopulse_domain_contracts::v01::egopulse::harness::v1::CapabilityDeclaration {
                    adapter_id: "adapter".to_owned(),
                    harness_id: "harness".to_owned(),
                    model_family_selectors: vec!["family".to_owned()],
                    native_protocol: Some(NativeProtocolFingerprint {
                        protocol_name: "acp".to_owned(),
                        protocol_version: "1".to_owned(),
                        schema_sha256: "schema".to_owned(),
                        adapter_version: "adapter-version".to_owned(),
                        native_executable_version: "native-version".to_owned(),
                        native_binary_sha256: None,
                    }),
                    semantics: Some(
                        egopulse_domain_contracts::v01::egopulse::harness::v1::CapabilitySemantics {
                            governed_user_visible_content: SupportLevel::AdapterEmulated as i32,
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                },
            ),
            attestation_level:
                egopulse_domain_contracts::v01::egopulse::harness::v1::AttestationLevel::ProbeVerified
                    as i32,
            attestation_evidence_refs: vec!["probe://harness/1".to_owned()],
            ..Default::default()
        };
        let bound = composition_profile(&capability)
            .expect("attested capability should produce a composition profile");
        assert_eq!(bound.adapter_id, "adapter");
        assert_eq!(bound.capability_profile_id, "profile");
        assert_eq!(
            bound.final_artifact_relation_policy,
            FinalArtifactRelationPolicy::RequiredGovernedContent
        );
        assert_eq!(
            bound.capability_profile_ref,
            ContractReference {
                contract_id: "profile".to_owned(),
                version: "v1".to_owned(),
                sha256: "ab".repeat(32),
            }
        );

        let mut missing_semantics = capability.clone();
        missing_semantics
            .declaration
            .as_mut()
            .expect("test capability declaration")
            .semantics = None;
        assert_eq!(
            composition_profile(&missing_semantics)
                .expect("legacy capability without semantics")
                .final_artifact_relation_policy,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly
        );

        let mut unspecified_content = capability.clone();
        unspecified_content
            .declaration
            .as_mut()
            .expect("test capability declaration")
            .semantics = Some(Default::default());
        assert_eq!(
            composition_profile(&unspecified_content)
                .expect("legacy capability with default content support")
                .final_artifact_relation_policy,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly
        );

        let mut unknown_content = capability.clone();
        unknown_content
            .declaration
            .as_mut()
            .and_then(|declaration| declaration.semantics.as_mut())
            .expect("test capability semantics")
            .governed_user_visible_content = SupportLevel::Unknown as i32;
        assert_eq!(
            composition_profile(&unknown_content)
                .expect("unknown support must remain conservative")
                .final_artifact_relation_policy,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly
        );

        let mut malformed_content = capability.clone();
        malformed_content
            .declaration
            .as_mut()
            .and_then(|declaration| declaration.semantics.as_mut())
            .expect("test capability semantics")
            .governed_user_visible_content = i32::MAX;
        assert!(matches!(
            composition_profile(&malformed_content),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness governed content capability"
            ))
        ));

        let mut drifted_protocol = bound.observed_protocol.clone();
        drifted_protocol.protocol_version.push_str("-drift");
        assert!(matches!(
            NativeHarnessCompositionProfile::from_attested_capability(
                &ContractReference {
                    contract_id: "profile".to_owned(),
                    version: "v1".to_owned(),
                    sha256: "ab".repeat(32),
                },
                "family",
                &capability,
                drifted_protocol,
                &prost_types::Timestamp::default(),
            ),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness capability profile protocol drift"
            ))
        ));

        let mut profile = NativeHarnessCompositionProfile {
            adapter_id: "adapter".to_owned(),
            capability_profile_id: "profile".to_owned(),
            schema_attestation_gap: None,
            capability_profile_ref: ContractReference {
                contract_id: "profile".to_owned(),
                version: "v1".to_owned(),
                sha256: "ab".repeat(32),
            },
            observed_protocol: NativeProtocolFingerprint {
                protocol_name: "acp".to_owned(),
                protocol_version: "1".to_owned(),
                schema_sha256: "schema".to_owned(),
                adapter_version: "adapter-version".to_owned(),
                native_executable_version: "native-version".to_owned(),
                native_binary_sha256: None,
            },
            final_artifact_relation_policy:
                FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
        };
        assert!(profile.validate().is_ok());

        profile.capability_profile_ref.contract_id = "different-profile".to_owned();
        assert!(matches!(
            profile.validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
        profile.capability_profile_ref.contract_id = "profile".to_owned();

        profile.adapter_id.clear();
        assert!(matches!(
            profile.validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
        profile.adapter_id = "adapter".to_owned();
        profile.observed_protocol.schema_sha256.clear();
        assert!(matches!(
            profile.validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
        profile.observed_protocol.schema_sha256 = "schema".to_owned();
        profile.capability_profile_ref.sha256.clear();
        assert!(matches!(
            profile.validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
    }

    #[test]
    fn composable_harnesses_resolve_one_adapter_identity() {
        // The Adapter Edge store binds this identity, and the policy resolver
        // must name the same one, so a route's adapter is resolved in exactly
        // one place for every composer.
        assert_eq!(
            production_harness_identity(bootstrap::ProviderHarnessKind::CodexAppServer),
            Some(ProviderHarnessIdentity {
                adapter_id: CODEX_ADAPTER_ID,
                capability_profile_id: CODEX_CAPABILITY_PROFILE_ID,
            })
        );
        assert_eq!(
            production_harness_identity(bootstrap::ProviderHarnessKind::OpenCodeAcp),
            Some(ProviderHarnessIdentity {
                adapter_id: egopulse_opencode_adapter::OPENCODE_ADAPTER_ID,
                capability_profile_id: egopulse_opencode_adapter::OPENCODE_CAPABILITY_PROFILE_ID,
            })
        );
        assert_eq!(
            production_harness_identity(bootstrap::ProviderHarnessKind::DshAcp),
            None
        );
        assert_eq!(
            production_harness_identity(bootstrap::ProviderHarnessKind::KimiCliAcp),
            None
        );
    }

    #[test]
    fn composition_profile_names_the_gap_when_the_transport_publishes_no_schema() {
        fn profile(schema_sha256: &str, gap: Option<&str>) -> NativeHarnessCompositionProfile {
            NativeHarnessCompositionProfile {
                adapter_id: "adapter".to_owned(),
                capability_profile_id: "profile".to_owned(),
                capability_profile_ref: ContractReference {
                    contract_id: "profile".to_owned(),
                    version: "v1".to_owned(),
                    sha256: "ab".repeat(32),
                },
                observed_protocol: NativeProtocolFingerprint {
                    protocol_name: "acp".to_owned(),
                    protocol_version: "1".to_owned(),
                    schema_sha256: schema_sha256.to_owned(),
                    adapter_version: "adapter-v1".to_owned(),
                    native_executable_version: "native-v1".to_owned(),
                    native_binary_sha256: None,
                },
                final_artifact_relation_policy:
                    FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
                schema_attestation_gap: gap.map(str::to_owned),
            }
        }

        assert!(
            profile("", Some("ACP_SCHEMA_ATTESTATION_REQUIRED"))
                .validate()
                .is_ok()
        );
        assert!(profile("digest", None).validate().is_ok());
        // An empty digest with no named gap is indistinguishable from a Harness
        // that merely failed to report one, so it stays refused.
        assert!(matches!(
            profile("", None).validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
        // A named gap next to a digest contradicts itself.
        assert!(matches!(
            profile("digest", Some("ACP_SCHEMA_ATTESTATION_REQUIRED")).validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
        assert!(matches!(
            profile("", Some("  ")).validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition profile"
            ))
        ));
    }

    #[test]
    fn native_harness_composition_is_independent_from_provider_executable_config() {
        fn reference(id: &str) -> ContractReference {
            ContractReference {
                contract_id: id.to_owned(),
                version: "v1".to_owned(),
                sha256: "ab".repeat(32),
            }
        }

        fn native_config() -> NativeHarnessCompositionConfig {
            NativeHarnessCompositionConfig {
                collaboration_database_path: PathBuf::from("collaboration.db"),
                collaboration_store_epoch: "collaboration-epoch".to_owned(),
                collaboration_key: [1; 32],
                adapter_database_path: PathBuf::from("adapter.db"),
                adapter_store_epoch: "adapter-epoch".to_owned(),
                adapter_key: [2; 32],
                input_bundle_root: PathBuf::from("input"),
                workspace_root: PathBuf::from("workspace"),
                default_model: Some("provider/model".to_owned()),
                workflow: SingleHarnessWorkConfig {
                    run_id: "run".to_owned(),
                    attempt_id: "attempt".to_owned(),
                    dispatch_id: "dispatch".to_owned(),
                    plan: Default::default(),
                    harness_id: "harness".to_owned(),
                    capability_profile_ref: reference("capability"),
                    workspace_ref: "workspace".to_owned(),
                    lease_policy_ref: reference("lease"),
                    owner_instance_id: "owner".to_owned(),
                    material:
                        egopulse_local_ide_control::collaboration_control::DispatchMaterial {
                            input_bundle_sha256: "cd".repeat(32),
                            sandbox_profile_ref: reference("sandbox"),
                            tool_policy_ref: reference("tool"),
                            data_egress_policy_ref: reference("egress"),
                            approval_policy_ref: reference("approval"),
                            session_strategy: egopulse_domain_contracts::v01::egopulse::harness::v1::NativeSessionStrategy::CreateNew,
                            native_session_ref: None,
                            checkpoint_ref: None,
                            route_binding: None,
                            evidence_refs: vec!["evidence".to_owned()],
                        },
                    task_authority_principal_id: "task".to_owned(),
                    collaboration_principal_id: "collaboration".to_owned(),
                    attempt_supervisor_principal_id: "supervisor".to_owned(),
                    harness_adapter_principal_id: "adapter".to_owned(),
                },
                lease_ttl_seconds: 30,
                return_collector: GovernedReturnCollectorConfig {
                    artifact_type_ref: reference("artifact-type"),
                    transformation_contract_ref: reference("transformation"),
                    retention_profile_ref: reference("retention"),
                    claim_semantic_profile_ref: reference("claim-semantic"),
                    claim_acceptance_contract_ref: reference("claim-acceptance"),
                    evidence_profile_ref: reference("evidence-profile"),
                    workspace_ref: "workspace".to_owned(),
                    collector_principal_id: "collector".to_owned(),
                    artifact_authority_principal_id: "artifact-authority".to_owned(),
                },
            }
        }

        assert!(native_config().validate().is_ok());
        assert!(matches!(
            CodexHarnessCompositionConfig {
                native: native_config(),
                codex_executable: PathBuf::new(),
                environment_overrides: Vec::new(),
                work_capability_route: None,
            }
            .validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "Codex Harness executable"
            ))
        ));

        let mut invalid_native = native_config();
        invalid_native.lease_ttl_seconds = 0;
        assert!(matches!(
            invalid_native.validate(),
            Err(DaemonCompositionError::InvalidConfiguration(
                "native Harness composition"
            ))
        ));
    }

    #[test]
    fn context_task_rebinds_only_bundle_reference_and_material_digest() {
        use egopulse_cognition_runtime::context_authority::{
            AuthenticatedContextPrincipal, ContextAuthorityConfig, ContextPrincipalKind,
            IssueContextSnapshot,
        };
        let root =
            std::env::temp_dir().join(format!("egopulse-workflow-context-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("context test root");
        let mut authority = ContextAuthority::open(ContextAuthorityConfig {
            database_path: root.join("context.db"),
            store_epoch: "workflow-context-test".to_owned(),
            key: egopulse_cognition_runtime::task_authority::SqlCipherKey::new([0x71; 32]),
        })
        .expect("context authority");
        let compiled = br#"{"prompt":"context task"}"#.to_vec();
        let (_, context_snapshot) = authority
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: "founder:test".to_owned(),
                    intent: "context task".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:repo".to_owned(),
                    compiled_context: compiled,
                    sources: Vec::new(),
                    memory_pack: None,
                    allowed_read_paths: vec!["workspace".to_owned()],
                    allowed_write_paths: vec!["workspace".to_owned()],
                    allowed_tools: Vec::new(),
                    external_resources: Vec::new(),
                    non_goals: Vec::new(),
                    acceptance_contract_ref: "acceptance:v1".to_owned(),
                    budget_profile_ref: "budget:v1".to_owned(),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: Vec::new(),
                    expires_at_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("clock")
                        .as_secs() as i64
                        + 600,
                    idempotency_key: "workflow-context-test".to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:test".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue context snapshot");
        let context = Arc::new(Mutex::new(authority));
        let mut config = multi_native_config(&root, "context").workflow;
        config.plan.steps = vec![
            egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepPlan {
                step_id: "step-1".to_owned(),
                input_bundle_ref: "static.json".to_owned(),
                ..Default::default()
            },
        ];
        let digest = context_snapshot.compiled_context_sha256.clone();
        let activation = egopulse_local_ide_control::collaboration_control::TaskActivationHandoff {
            message_id: "message-1".to_owned(),
            payload_digest_sha256: "payload".to_owned(),
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                current_run_id: Some(config.run_id.clone()),
                input_snapshot_id: context_snapshot.snapshot_id,
                target_scope_ref: "scope:repo".to_owned(),
                ..Default::default()
            },
        };
        let resolved = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .resolve(&activation)
            .expect("resolve context workflow");
        let SingleHarnessWorkflowResolution::Resolved(resolved) = resolved else {
            panic!("context workflow must apply");
        };
        assert_eq!(resolved.material.input_bundle_sha256, digest);
        assert_eq!(
            resolved.plan.steps[0].input_bundle_ref,
            format!("ctx-{digest}.json")
        );
        assert_eq!(resolved.workspace_ref, config.workspace_ref);
        assert_eq!(
            resolved.capability_profile_ref,
            config.capability_profile_ref
        );
        assert_eq!(resolved.plan.digest_sha256, config.plan.digest_sha256);

        let mut wrong_scope = activation.clone();
        wrong_scope.task.target_scope_ref = "scope:other".to_owned();
        assert_eq!(
            ConfiguredSingleHarnessWorkflow::new(config.clone())
                .with_context_authority(Arc::clone(&context))
                .resolve(&wrong_scope),
            Err(SingleHarnessWorkflowResolverError::InvalidConfiguration)
        );
        let mut empty_plan = config.clone();
        empty_plan.plan.steps.clear();
        assert_eq!(
            ConfiguredSingleHarnessWorkflow::new(empty_plan)
                .with_context_authority(Arc::clone(&context))
                .resolve(&activation),
            Err(SingleHarnessWorkflowResolverError::InvalidConfiguration)
        );

        let mut static_activation = activation;
        static_activation.task.input_snapshot_id = "static-snapshot".to_owned();
        let static_resolved = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .resolve(&static_activation)
            .expect("resolve static workflow");
        let SingleHarnessWorkflowResolution::Resolved(static_resolved) = static_resolved else {
            panic!("static workflow must apply");
        };
        assert_eq!(*static_resolved, config);
        drop(context);
        let _ = fs::remove_dir_all(root);
    }

    fn resolver_work_capability_route(
        config: &SingleHarnessWorkConfig,
    ) -> WorkCapabilityRouteBinding {
        egopulse_domain_contracts::work_capability::seal_work_capability_route_binding(
            WorkCapabilityRouteBinding {
                route_id: "route:resolver-test:v1".to_owned(),
                route_generation: 1,
                provider_profile_id: "provider-profile:resolver-test".to_owned(),
                provider_id: "gpt".to_owned(),
                harness_id: "codex_app_server".to_owned(),
                harness_model_id: "resolver/model".to_owned(),
                provider_model_id: "provider-resolver-model".to_owned(),
                capability_profile_ref: Some(config.capability_profile_ref.clone()),
                catalog_snapshot_sha256: Some("ef".repeat(32)),
                native_composition_generation: config.run_id.clone(),
                route_binding_sha256: String::new(),
            },
        )
        .expect("sealed resolver route")
    }

    fn compiled_context_for_route(route: &WorkCapabilityRouteBinding) -> Vec<u8> {
        let profile = route
            .capability_profile_ref
            .as_ref()
            .expect("route capability profile");
        serde_json::to_vec(&serde_json::json!({
            "prompt": "route-aware context",
            "model": route.harness_model_id,
            "work_capability": {
                "choice_id": "choice:resolver-test",
                "selection_source": egopulse_domain_contracts::v01::egopulse::localapi::v1::WorkCapabilitySelectionSource::ExplicitChoice as i32,
                "preference_revision_at_resolution": null,
                "route": {
                    "route_id": route.route_id,
                    "route_generation": route.route_generation,
                    "provider_profile_id": route.provider_profile_id,
                    "provider_id": route.provider_id,
                    "harness_id": route.harness_id,
                    "harness_model_id": route.harness_model_id,
                    "provider_model_id": route.provider_model_id,
                    "capability_profile_ref": {
                        "contract_id": profile.contract_id,
                        "version": profile.version,
                        "sha256": profile.sha256,
                    },
                    "catalog_snapshot_sha256": route.catalog_snapshot_sha256,
                    "native_composition_generation": route.native_composition_generation,
                    "route_binding_sha256": route.route_binding_sha256,
                }
            }
        }))
        .expect("compiled route context")
    }

    #[test]
    fn route_aware_workflow_binds_context_task_run_attempt_dispatch_and_rejects_drift() {
        use egopulse_cognition_runtime::context_authority::{
            AuthenticatedContextPrincipal, ContextAuthorityConfig, ContextPrincipalKind,
            IssueContextSnapshot,
        };
        let root =
            std::env::temp_dir().join(format!("egopulse-route-aware-workflow-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("route workflow root");
        let mut config = multi_native_config(&root, "resolver").workflow;
        config.plan.steps = vec![
            egopulse_domain_contracts::v01::egopulse::collaboration::v1::StepPlan {
                step_id: "step-route".to_owned(),
                input_bundle_ref: "static.json".to_owned(),
                required_capability_profile_ref: Some(config.capability_profile_ref.clone()),
                ..Default::default()
            },
        ];
        let route = resolver_work_capability_route(&config);
        let compiled = compiled_context_for_route(&route);
        let mut authority = ContextAuthority::open(ContextAuthorityConfig {
            database_path: root.join("context.db"),
            store_epoch: "route-aware-workflow-context".to_owned(),
            key: egopulse_cognition_runtime::task_authority::SqlCipherKey::new([0x72; 32]),
        })
        .expect("route context authority");
        let (_, context_snapshot) = authority
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: "founder:test".to_owned(),
                    intent: "route-aware work".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:repo".to_owned(),
                    compiled_context: compiled,
                    sources: Vec::new(),
                    memory_pack: None,
                    allowed_read_paths: vec!["workspace".to_owned()],
                    allowed_write_paths: vec!["workspace".to_owned()],
                    allowed_tools: Vec::new(),
                    external_resources: Vec::new(),
                    non_goals: Vec::new(),
                    acceptance_contract_ref: "acceptance:v1".to_owned(),
                    budget_profile_ref: "budget:v1".to_owned(),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: Vec::new(),
                    expires_at_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("clock")
                        .as_secs() as i64
                        + 600,
                    idempotency_key: "route-aware-workflow-context".to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:test".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue route context");
        let context = Arc::new(Mutex::new(authority));
        let task_id = "task:route-aware";
        let run_id = work_preparation::work_capability_run_id(task_id, 1, &route)
            .expect("route-bound run ID");
        let activation = egopulse_local_ide_control::collaboration_control::TaskActivationHandoff {
            message_id: "message-route-aware".to_owned(),
            payload_digest_sha256: "payload-route-aware".to_owned(),
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                task_id: task_id.to_owned(),
                work_revision: 1,
                current_run_id: Some(run_id.clone()),
                input_snapshot_id: context_snapshot.snapshot_id.clone(),
                target_scope_ref: "scope:repo".to_owned(),
                work_capability_route: Some(route.clone()),
                ..Default::default()
            },
        };
        let route_profile = TrustedDispatchRouteProfile {
            provider_bootstrap_profile_id: route.provider_profile_id.clone(),
            selected_harness_id: route.harness_id.clone(),
            provider_model_id: route.provider_model_id.clone(),
            catalog_snapshot_sha256: route.catalog_snapshot_sha256.clone(),
            capability_profile_id: config.capability_profile_ref.contract_id.clone(),
        };
        let resolved = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .with_work_capability_route(route.clone())
            .with_trusted_dispatch_route_profile(route_profile.clone())
            .resolve(&activation)
            .expect("resolve exact route-aware workflow");
        let SingleHarnessWorkflowResolution::ResolvedWithRouteBinding {
            config: resolved,
            route_binding,
        } = resolved
        else {
            panic!("route-aware workflow must carry dispatch route binding");
        };
        assert_eq!(resolved.run_id, run_id);
        let replayed = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .with_work_capability_route(route.clone())
            .with_trusted_dispatch_route_profile(route_profile.clone())
            .resolve(&activation)
            .expect("replay exact route-aware workflow");
        let SingleHarnessWorkflowResolution::ResolvedWithRouteBinding {
            config: replayed, ..
        } = replayed
        else {
            panic!("replayed route-aware workflow must carry dispatch route binding");
        };
        assert_eq!(replayed.run_id, resolved.run_id);
        assert_eq!(
            replayed.plan.steps[0].step_id,
            resolved.plan.steps[0].step_id
        );
        assert_eq!(replayed.attempt_id, resolved.attempt_id);
        assert_eq!(replayed.dispatch_id, resolved.dispatch_id);

        let mut revised_activation = activation.clone();
        revised_activation.task.work_revision = 2;
        revised_activation.task.current_run_id = Some(
            work_preparation::work_capability_run_id(task_id, 2, &route)
                .expect("revised route-bound run ID"),
        );
        let revised = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .with_work_capability_route(route.clone())
            .resolve(&revised_activation)
            .expect("resolve revised task work");
        let SingleHarnessWorkflowResolution::Resolved(revised) = revised else {
            panic!("revised workflow configuration");
        };
        assert_eq!(
            revised.run_id,
            format!(
                "run:work:{task_id}:revision:2:{}",
                route.route_binding_sha256
            )
        );
        assert_eq!(
            revised.plan.steps[0].step_id,
            format!(
                "step:work:{task_id}:revision:2:{}",
                route.route_binding_sha256
            )
        );
        assert_eq!(
            revised.attempt_id,
            format!(
                "attempt:work:{task_id}:revision:2:{}",
                route.route_binding_sha256
            )
        );
        assert_eq!(
            revised.dispatch_id,
            format!(
                "dispatch:work:{task_id}:revision:2:{}",
                route.route_binding_sha256
            )
        );
        assert_ne!(revised.run_id, resolved.run_id);
        assert_ne!(
            revised.plan.steps[0].step_id,
            resolved.plan.steps[0].step_id
        );
        assert_ne!(revised.attempt_id, resolved.attempt_id);
        assert_ne!(revised.dispatch_id, resolved.dispatch_id);

        let mut second_activation = activation.clone();
        second_activation.task.task_id = "task:route-aware-second".to_owned();
        second_activation.task.current_run_id = Some(
            work_preparation::work_capability_run_id(
                &second_activation.task.task_id,
                second_activation.task.work_revision,
                &route,
            )
            .expect("second route-bound run ID"),
        );
        let second = ConfiguredSingleHarnessWorkflow::new(config.clone())
            .with_context_authority(Arc::clone(&context))
            .with_work_capability_route(route.clone())
            .resolve(&second_activation)
            .expect("resolve second task");
        let SingleHarnessWorkflowResolution::Resolved(second) = second else {
            panic!("second workflow configuration");
        };
        assert_ne!(resolved.plan.steps[0].step_id, second.plan.steps[0].step_id);
        assert_eq!(
            resolved.attempt_id,
            format!("attempt:work:{task_id}:{}", route.route_binding_sha256)
        );
        assert_eq!(
            resolved.dispatch_id,
            format!("dispatch:work:{task_id}:{}", route.route_binding_sha256)
        );
        assert_eq!(
            resolved.material.input_bundle_sha256,
            context_snapshot.compiled_context_sha256
        );
        assert_eq!(
            *route_binding,
            build_dispatch_route_binding(&route_profile).expect("expected dispatch route")
        );

        let mut wrong_run = activation.clone();
        wrong_run.task.current_run_id = Some(config.run_id.clone());
        assert_eq!(
            ConfiguredSingleHarnessWorkflow::new(config.clone())
                .with_context_authority(Arc::clone(&context))
                .with_work_capability_route(route.clone())
                .resolve(&wrong_run),
            Err(SingleHarnessWorkflowResolverError::InvalidConfiguration)
        );

        let mut other_route = route.clone();
        other_route.route_id.push_str(":other");
        other_route.route_binding_sha256.clear();
        let other_route =
            egopulse_domain_contracts::work_capability::seal_work_capability_route_binding(
                other_route,
            )
            .expect("seal other route");
        assert_eq!(
            ConfiguredSingleHarnessWorkflow::new(config)
                .with_context_authority(Arc::clone(&context))
                .with_work_capability_route(other_route)
                .resolve(&activation),
            Ok(SingleHarnessWorkflowResolution::NotApplicable)
        );

        drop(context);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn governed_work_capability_crosses_real_authorities_and_only_the_exact_route_dispatches()
    {
        use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{RunPlan, StepPlan};
        use egopulse_domain_contracts::v01::egopulse::task::v1::{TaskStatus, task_command_result};

        let root = std::env::temp_dir().join(format!(
            "egopulse-work-capability-production-seams-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("route integration root");
        fs::write(root.join("intent.md"), "execute the exact admitted route")
            .expect("route integration source");

        let acceptance = composition_reference("route-acceptance");
        let budget = composition_reference("route-budget");
        let mut exact_config = multi_native_config(&root, "route-exact");
        exact_config.workflow.plan = RunPlan {
            plan_id: "route-plan".to_owned(),
            digest_sha256: "93".repeat(32),
            max_active_attempts: 1,
            steps: vec![StepPlan {
                step_id: "route-step".to_owned(),
                step_kind: "governed_repository_change".to_owned(),
                depends_on_step_ids: Vec::new(),
                input_bundle_ref: "static-route-input.json".to_owned(),
                expected_output_contract_ref: Some(composition_reference("route-output")),
                required_capability_profile_ref: Some(
                    exact_config.workflow.capability_profile_ref.clone(),
                ),
                max_attempts: 2,
            }],
            budget_profile_ref: Some(budget.clone()),
        };
        let exact_route = resolver_work_capability_route(&exact_config.workflow);
        exact_config.default_model = Some(exact_route.harness_model_id.clone());
        fs::create_dir_all(
            exact_config
                .workspace_root
                .join(&exact_config.workflow.workspace_ref),
        )
        .expect("exact governed workspace");

        let context = Arc::new(Mutex::new(
            egopulse_cognition_runtime::context_authority::ContextAuthority::open(
                egopulse_cognition_runtime::context_authority::ContextAuthorityConfig {
                    database_path: root.join("route-context.db"),
                    store_epoch: "route-context-epoch".to_owned(),
                    key: egopulse_cognition_runtime::task_authority::SqlCipherKey::new([0x81; 32]),
                },
            )
            .expect("route Context Authority"),
        ));
        let task_guard = ConfiguredTaskCreationGuard::new(ConfiguredTaskCreationGuardConfig {
            allowed_work_types: ["governed_repository_change".to_owned()]
                .into_iter()
                .collect(),
            allowed_input_snapshot_ids: ["static-reviewed".to_owned()].into_iter().collect(),
            allowed_target_scope_refs: ["scope:route-integration".to_owned()].into_iter().collect(),
            acceptance_contract_ref: acceptance.clone(),
            budget_profile_ref: budget.clone(),
        })
        .expect("route Task creation guard")
        .with_context_authority(Arc::clone(&context));
        let task =
            egopulse_cognition_runtime::task_authority::TaskAuthority::open_with_transition_guard(
                egopulse_cognition_runtime::task_authority::TaskAuthorityConfig {
                    database_path: root.join("route-task.db"),
                    store_epoch: "route-task-epoch".to_owned(),
                    key: egopulse_cognition_runtime::task_authority::SqlCipherKey::new([0x82; 32]),
                },
                task_guard,
                ConfiguredTaskTransitionGuard::new().with_context_authority(Arc::clone(&context)),
            )
            .expect("route Task Authority");
        let policy = egopulse_policy_decision_authority::PolicyDecisionAuthority::open(
            egopulse_policy_decision_authority::PolicyAuthorityConfig {
                database_path: root.join("route-policy.db"),
                store_epoch: "route-policy-epoch".to_owned(),
                key: egopulse_policy_decision_authority::PolicySqlCipherKey::new([0x83; 32]),
            },
            UnusedPolicyReferences,
        )
        .expect("route Policy Authority");
        let verdict = egopulse_founder_verdict_authority::FounderVerdictAuthority::open(
            egopulse_founder_verdict_authority::VerdictAuthorityConfig {
                database_path: root.join("route-verdict.db"),
                store_epoch: "route-verdict-epoch".to_owned(),
                key: egopulse_founder_verdict_authority::VerdictSqlCipherKey::new([0x84; 32]),
            },
            UnusedVerdictReferences,
        )
        .expect("route Founder Verdict Authority");
        let mut providers = DaemonProviders::from_authorities(
            task,
            policy,
            verdict,
            Arc::new(WorkRoutePrincipalResolver),
            Arc::new(DenyAllPrincipalResolver),
            Arc::new(SystemSessionClock),
            Arc::new(NoopSessionAuditSink),
        )
        .with_context_authority(Arc::clone(&context));

        let provider_profile = bootstrap::ProviderBootstrapProfile {
            profile_id: exact_route.provider_profile_id.clone(),
            provider: bootstrap::ProviderId::Gpt,
            harness: bootstrap::ProviderHarnessKind::CodexAppServer,
            admission: bootstrap::ProviderAdmission::Production,
            models: vec![bootstrap::ProviderModelBinding {
                harness_model_id: exact_route.harness_model_id.clone(),
                provider_model_id: exact_route.provider_model_id.clone(),
            }],
            catalog_snapshot: Some(bootstrap::ProviderCatalogSnapshot {
                source: "route-integration-fixture".to_owned(),
                fetched_at: "2026-09-05T00:00:00Z".to_owned(),
                harness_version: "fixture-v1".to_owned(),
                evidence_digest_sha256: exact_route
                    .catalog_snapshot_sha256
                    .clone()
                    .expect("route catalog digest"),
            }),
            exact_model: exact_route.harness_model_id.clone(),
            executable: PathBuf::from("unused-route-proof-driver"),
            credential: bootstrap::ProviderCredentialReference::HarnessAccount,
            hold_reason: None,
        };
        let registry = Arc::new(
            work_capability::WorkCapabilityRegistry::new(
                root.join("route-agentos.json"),
                &[provider_profile],
                exact_route.clone(),
                "choice:resolver-test".to_owned(),
                1,
                false,
            )
            .expect("route work-capability registry"),
        );
        let work_port = ConfiguredWorkPreparationPort::new(
            Arc::clone(&context),
            Arc::clone(&providers.task_port),
            providers.work_memory_retrieval_port(),
            root.clone(),
            ["governed_repository_change".to_owned()]
                .into_iter()
                .collect(),
            acceptance,
            budget,
        )
        .expect("route Work Preparation")
        .with_input_bundle_root(exact_config.input_bundle_root.clone())
        .and_then(|port| port.with_activation_run_id(exact_config.workflow.run_id.clone()))
        .expect("route Work Preparation dispatch binding")
        .with_work_capability_registry(registry);
        let principal = CommandPrincipal {
            principal_id: "founder:route-integration".to_owned(),
            required_authority_principal_kinds: vec!["TaskAuthority.Founder".to_owned()],
        };
        let preview = work_port
            .prepare(
                &PrepareWorkRequest {
                    intent: "run one admitted capability through production seams".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:route-integration".to_owned(),
                    sources: vec![WorkSourceRequest {
                        source_ref: "intent.md".to_owned(),
                        label: "reviewed intent".to_owned(),
                    }],
                    memory_mode: WorkMemoryMode::Disabled as i32,
                    work_capability_preference: Some(
                        prepare_work_request::WorkCapabilityPreference::UseDefaultWorkCapability(
                            UseDefaultWorkCapability {},
                        ),
                    ),
                    idempotency_key: "route-prepare".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .await
            .expect("prepare exact admitted route");
        assert_eq!(
            preview
                .work_capability
                .as_ref()
                .and_then(|capability| capability.admitted_route.as_ref()),
            Some(&exact_route)
        );
        let confirmed = work_port
            .confirm(
                &ConfirmWorkRequest {
                    snapshot_id: preview.snapshot_id.clone(),
                    confirmation_binding_sha256: preview.confirmation_binding_sha256.clone(),
                    idempotency_key: "route-confirm".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect("confirm exact admitted route");
        let task = match confirmed.result.outcome.as_ref() {
            Some(task_command_result::Outcome::Task(task)) => task.clone(),
            _ => panic!("route confirmation must return the activated Task"),
        };
        assert_eq!(task.status, TaskStatus::Active as i32);
        assert_eq!(task.work_capability_route.as_ref(), Some(&exact_route));
        let expected_run_id = work_preparation::work_capability_run_id(
            &task.task_id,
            task.work_revision,
            &exact_route,
        )
        .expect("route-bound run ID");
        let expected_attempt_id = format!(
            "attempt:work:{}:{}",
            task.task_id, exact_route.route_binding_sha256
        );
        let expected_dispatch_id = format!(
            "dispatch:work:{}:{}",
            task.task_id, exact_route.route_binding_sha256
        );
        assert_eq!(
            task.current_run_id.as_deref(),
            Some(expected_run_id.as_str())
        );
        providers = providers.with_work_preparation_port(Arc::new(work_port));

        let mut drift_route = exact_route.clone();
        drift_route.route_id.push_str(":drift");
        drift_route.route_binding_sha256.clear();
        let drift_route =
            egopulse_domain_contracts::work_capability::seal_work_capability_route_binding(
                drift_route,
            )
            .expect("seal drift route");
        let trusted_route = TrustedDispatchRouteProfile {
            provider_bootstrap_profile_id: exact_route.provider_profile_id.clone(),
            selected_harness_id: exact_route.harness_id.clone(),
            provider_model_id: exact_route.provider_model_id.clone(),
            catalog_snapshot_sha256: exact_route.catalog_snapshot_sha256.clone(),
            capability_profile_id: exact_config
                .workflow
                .capability_profile_ref
                .contract_id
                .clone(),
        };
        let expected_dispatch_route =
            build_dispatch_route_binding(&trusted_route).expect("trusted dispatch route");

        let mut drift_config = multi_native_config(&root, "route-drift");
        drift_config.input_bundle_root = exact_config.input_bundle_root.clone();
        drift_config.workspace_root = exact_config.workspace_root.clone();
        drift_config.default_model = exact_config.default_model.clone();
        drift_config.workflow = exact_config.workflow.clone();
        let drift_adapter_config = AdapterEdgeConfig {
            database_path: drift_config.adapter_database_path.clone(),
            adapter_id: drift_config.workflow.harness_adapter_principal_id.clone(),
            store_epoch: drift_config.adapter_store_epoch.clone(),
            key: AdapterEdgeKey::new(drift_config.adapter_key),
        };
        let exact_adapter_config = AdapterEdgeConfig {
            database_path: exact_config.adapter_database_path.clone(),
            adapter_id: exact_config.workflow.harness_adapter_principal_id.clone(),
            store_epoch: exact_config.adapter_store_epoch.clone(),
            key: AdapterEdgeKey::new(exact_config.adapter_key),
        };
        let drift_sends = Arc::new(AtomicUsize::new(0));
        let drift_envelope = Arc::new(Mutex::new(None));
        let exact_sends = Arc::new(AtomicUsize::new(0));
        let exact_envelope = Arc::new(Mutex::new(None));
        let drift_driver = RouteProofDriver {
            sends: Arc::clone(&drift_sends),
            envelope: Arc::clone(&drift_envelope),
        };
        let exact_driver = RouteProofDriver {
            sends: Arc::clone(&exact_sends),
            envelope: Arc::clone(&exact_envelope),
        };
        let drift_profile = multi_native_profile(&drift_config);
        let exact_profile = multi_native_profile(&exact_config);
        let (artifact, verification) = multi_native_authorities(&root);
        providers = providers
            .with_profiled_native_harness_drivers(
                vec![
                    ProfiledNativeHarnessComposition::new(
                        drift_config,
                        drift_profile,
                        drift_driver,
                    )
                    .with_trusted_dispatch_route_profile(trusted_route.clone())
                    .with_work_capability_route(drift_route),
                    ProfiledNativeHarnessComposition::new(
                        exact_config,
                        exact_profile,
                        exact_driver,
                    )
                    .with_trusted_dispatch_route_profile(trusted_route)
                    .with_work_capability_route(exact_route.clone()),
                ],
                artifact,
                verification,
            )
            .expect("production route runners");
        let report = providers
            .harness_dispatch_runner
            .as_ref()
            .expect("production Harness runner")
            .run_once()
            .await
            .expect("production route cycle");

        assert_eq!(report.activations_started, 1);
        assert_eq!(report.activations_acknowledged, 1);
        assert_eq!(report.dispatches_delivered, 1);
        assert_eq!(drift_sends.load(Ordering::SeqCst), 0);
        assert!(
            drift_envelope
                .lock()
                .expect("drift envelope lock")
                .is_none()
        );
        assert_eq!(exact_sends.load(Ordering::SeqCst), 1);
        let delivered = exact_envelope
            .lock()
            .expect("exact envelope lock")
            .clone()
            .expect("exact route reaches native driver");
        assert_eq!(delivered.run_id, expected_run_id);
        assert_eq!(delivered.attempt_id, expected_attempt_id);
        assert_eq!(delivered.dispatch_id, expected_dispatch_id);
        assert_eq!(
            delivered.route_binding.as_ref(),
            Some(&expected_dispatch_route)
        );

        assert_eq!(providers.harness_content_lineage_readers.len(), 2);
        let pending = providers
            .projection_source
            .as_ref()
            .expect("native projections")
            .pending()
            .expect("read native projections");
        assert!(
            pending
                .iter()
                .any(|message| matches!(message, PendingOwnerProjection::Collaboration(_)))
        );
        assert_eq!(
            providers.harness_content_lineage_readers[0]
                .lock()
                .expect("drift lineage lock")
                .task_id_for_attempt(&expected_attempt_id)
                .expect("read drift lineage"),
            None,
            "route drift must create no Collaboration run or attempt"
        );
        assert_eq!(
            providers.harness_content_lineage_readers[1]
                .lock()
                .expect("exact lineage lock")
                .task_id_for_attempt(&expected_attempt_id)
                .expect("read exact lineage")
                .as_deref(),
            Some(task.task_id.as_str())
        );
        let drift_adapter = AdapterEdge::open(drift_adapter_config).expect("drift Adapter Edge");
        let exact_adapter = AdapterEdge::open(exact_adapter_config).expect("exact Adapter Edge");
        assert_eq!(
            drift_adapter
                .inspect()
                .expect("inspect drift Adapter Edge")
                .dispatch_count,
            0
        );
        assert_eq!(
            exact_adapter
                .inspect()
                .expect("inspect exact Adapter Edge")
                .dispatch_count,
            1
        );

        drop(drift_adapter);
        drop(exact_adapter);
        drop(providers);
        drop(context);
        fs::remove_dir_all(root).expect("remove route integration root");
    }

    #[test]
    fn malformed_context_task_does_not_fall_back_to_static_material() {
        let config = multi_native_config(std::path::Path::new("."), "malformed").workflow;
        let activation = egopulse_local_ide_control::collaboration_control::TaskActivationHandoff {
            message_id: "message-1".to_owned(),
            payload_digest_sha256: "payload".to_owned(),
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                current_run_id: Some(config.run_id.clone()),
                input_snapshot_id: "ctx:not-a-digest".to_owned(),
                ..Default::default()
            },
        };
        assert_eq!(
            ConfiguredSingleHarnessWorkflow::new(config).resolve(&activation),
            Err(SingleHarnessWorkflowResolverError::InvalidConfiguration)
        );
    }

    #[test]
    fn configured_workflow_carries_one_route_binding_in_trusted_dispatch_material() {
        let config = multi_native_config(std::path::Path::new("."), "route-material").workflow;
        let activation = egopulse_local_ide_control::collaboration_control::TaskActivationHandoff {
            message_id: "message-route-material".to_owned(),
            payload_digest_sha256: "payload-route-material".to_owned(),
            task: egopulse_domain_contracts::v01::egopulse::task::v1::TaskSnapshot {
                current_run_id: Some(config.run_id.clone()),
                input_snapshot_id: "static-snapshot".to_owned(),
                ..Default::default()
            },
        };
        let profile = TrustedDispatchRouteProfile {
            provider_bootstrap_profile_id: "gpt-codex-route-material".to_owned(),
            selected_harness_id: "codex_app_server".to_owned(),
            provider_model_id: "provider/model".to_owned(),
            catalog_snapshot_sha256: Some("ef".repeat(32)),
            capability_profile_id: config.capability_profile_ref.contract_id.clone(),
        };
        let expected = build_dispatch_route_binding(&profile).expect("build trusted route binding");

        let resolved = ConfiguredSingleHarnessWorkflow::new(config)
            .with_trusted_dispatch_route_profile(profile)
            .resolve(&activation)
            .expect("resolve routed workflow");
        let SingleHarnessWorkflowResolution::ResolvedWithRouteBinding {
            config,
            route_binding,
        } = resolved
        else {
            panic!("routed workflow must carry a route binding");
        };

        assert_eq!(*route_binding, expected);
        assert_eq!(config.material.route_binding, Some(expected));
    }

    struct EmptyTaskActivationSource;

    impl TaskActivationSource for EmptyTaskActivationSource {
        fn pending_task_activations(
            &self,
        ) -> Result<
            Vec<egopulse_local_ide_control::collaboration_control::TaskActivationHandoff>,
            egopulse_local_ide_control::collaboration_control::TaskActivationSourceError,
        > {
            Ok(Vec::new())
        }

        fn acknowledge_task_activation(
            &self,
            _message_id: &str,
            _payload_digest_sha256: &str,
        ) -> Result<
            bool,
            egopulse_local_ide_control::collaboration_control::TaskActivationSourceError,
        > {
            Ok(false)
        }
    }

    fn composition_reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "ab".repeat(32),
        }
    }

    fn multi_native_config(root: &std::path::Path, suffix: &str) -> NativeHarnessCompositionConfig {
        NativeHarnessCompositionConfig {
            collaboration_database_path: root.join(format!("{suffix}-collaboration.db")),
            collaboration_store_epoch: format!("{suffix}-collaboration-epoch"),
            collaboration_key: [0x31; 32],
            adapter_database_path: root.join(format!("{suffix}-adapter.db")),
            adapter_store_epoch: format!("{suffix}-adapter-epoch"),
            adapter_key: [0x32; 32],
            input_bundle_root: root.join(format!("{suffix}-input")),
            workspace_root: root.join(format!("{suffix}-workspace")),
            default_model: Some(format!("{suffix}/model")),
            workflow: SingleHarnessWorkConfig {
                run_id: format!("{suffix}-run"),
                attempt_id: format!("{suffix}-attempt"),
                dispatch_id: format!("{suffix}-dispatch"),
                plan: Default::default(),
                harness_id: format!("{suffix}-harness"),
                capability_profile_ref: composition_reference(&format!("{suffix}-profile")),
                workspace_ref: "workspace".to_owned(),
                lease_policy_ref: composition_reference("lease"),
                owner_instance_id: format!("{suffix}-owner"),
                material:
                    egopulse_local_ide_control::collaboration_control::DispatchMaterial {
                        input_bundle_sha256: "cd".repeat(32),
                        sandbox_profile_ref: composition_reference("sandbox"),
                        tool_policy_ref: composition_reference("tool"),
                        data_egress_policy_ref: composition_reference("egress"),
                        approval_policy_ref: composition_reference("approval"),
                        session_strategy: egopulse_domain_contracts::v01::egopulse::harness::v1::NativeSessionStrategy::CreateNew,
                        native_session_ref: None,
                        checkpoint_ref: None,
                        route_binding: None,
                        evidence_refs: vec!["evidence".to_owned()],
                    },
                task_authority_principal_id: format!("{suffix}-task"),
                collaboration_principal_id: format!("{suffix}-collaboration"),
                attempt_supervisor_principal_id: format!("{suffix}-supervisor"),
                harness_adapter_principal_id: format!("{suffix}-adapter"),
            },
            lease_ttl_seconds: 30,
            return_collector: GovernedReturnCollectorConfig {
                artifact_type_ref: composition_reference("artifact-type"),
                transformation_contract_ref: composition_reference("transformation"),
                retention_profile_ref: composition_reference("retention"),
                claim_semantic_profile_ref: composition_reference("claim-semantic"),
                claim_acceptance_contract_ref: composition_reference("claim-acceptance"),
                evidence_profile_ref: composition_reference("evidence-profile"),
                workspace_ref: "workspace".to_owned(),
                collector_principal_id: format!("{suffix}-collector"),
                artifact_authority_principal_id: format!("{suffix}-artifact-authority"),
            },
        }
    }

    fn multi_native_profile_with_protocol(
        config: &NativeHarnessCompositionConfig,
        protocol_name: &str,
    ) -> NativeHarnessCompositionProfile {
        NativeHarnessCompositionProfile {
            adapter_id: config.workflow.harness_adapter_principal_id.clone(),
            capability_profile_id: config.workflow.capability_profile_ref.contract_id.clone(),
            capability_profile_ref: config.workflow.capability_profile_ref.clone(),
            observed_protocol: NativeProtocolFingerprint {
                protocol_name: protocol_name.to_owned(),
                protocol_version: "v1".to_owned(),
                schema_sha256: "schema".to_owned(),
                adapter_version: "adapter-v1".to_owned(),
                native_executable_version: "native-v1".to_owned(),
                native_binary_sha256: None,
            },
            final_artifact_relation_policy:
                FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
            schema_attestation_gap: None,
        }
    }

    fn multi_native_profile(
        config: &NativeHarnessCompositionConfig,
    ) -> NativeHarnessCompositionProfile {
        multi_native_profile_with_protocol(config, "test-native")
    }

    fn multi_native_authorities(
        root: &std::path::Path,
    ) -> (
        Arc<
            Mutex<egopulse_artifact_authority::ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>,
        >,
        Arc<Mutex<egopulse_verification_authority::VerificationAuthority>>,
    ) {
        let all_refs = [
            composition_reference("artifact-type"),
            composition_reference("transformation"),
            composition_reference("retention"),
            composition_reference("claim-semantic"),
            composition_reference("claim-acceptance"),
            composition_reference("evidence-profile"),
        ];
        let artifact_guard =
            ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
                allowed_workspace_refs: ["workspace".to_owned()].into_iter().collect(),
                allowed_artifact_type_refs: vec![all_refs[0].clone()],
                allowed_transformation_contract_refs: vec![all_refs[1].clone()],
                allowed_retention_profile_refs: vec![all_refs[2].clone()],
                allowed_claim_semantic_profile_refs: vec![all_refs[3].clone()],
                allowed_claim_acceptance_contract_refs: vec![all_refs[4].clone()],
                allowed_evidence_profile_refs: vec![all_refs[5].clone()],
            })
            .expect("test artifact guard");
        let artifact = egopulse_artifact_authority::ArtifactAuthority::open(
            egopulse_artifact_authority::ArtifactAuthorityConfig {
                database_path: root.join("artifact-authority.db"),
                blob_root: root.join("artifact-blobs"),
                store_epoch: "multi-harness-artifact-epoch".to_owned(),
                key: egopulse_artifact_authority::ArtifactSqlCipherKey::new([0x41; 32]),
            },
            artifact_guard,
        )
        .expect("test artifact authority");
        let verification = egopulse_verification_authority::VerificationAuthority::open(
            egopulse_verification_authority::VerificationAuthorityConfig {
                database_path: root.join("verification-authority.db"),
                store_epoch: "multi-harness-verification-epoch".to_owned(),
                key: egopulse_verification_authority::VerificationSqlCipherKey::new([0x42; 32]),
            },
            DenyVerificationReferences,
        )
        .expect("test verification authority");
        (
            Arc::new(Mutex::new(artifact)),
            Arc::new(Mutex::new(verification)),
        )
    }

    #[tokio::test]
    async fn gpt_model_composes_through_codex_and_dsh_harness_drivers_without_authentication() {
        let root = std::env::temp_dir().join(format!(
            "egopulse-agentosd-multi-harness-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("test root");
        let shared_gpt_model = "gpt-cross-harness-test";
        let mut config_a = multi_native_config(&root, "a");
        config_a.default_model = Some(shared_gpt_model.to_owned());
        config_a.workflow.harness_id = "codex_app_server".to_owned();
        let mut config_b = multi_native_config(&root, "b");
        config_b.default_model = Some(shared_gpt_model.to_owned());
        config_b.workflow.harness_id = "dsh_acp".to_owned();
        let (artifact, verification) = multi_native_authorities(&root);
        let mut providers = DaemonProviders::fail_closed();
        providers.task_activation_source = Some(Arc::new(EmptyTaskActivationSource));

        let mut providers = providers
            .with_profiled_native_harness_drivers(
                vec![
                    ProfiledNativeHarnessComposition {
                        profile: multi_native_profile(&config_a),
                        config: config_a,
                        driver: Box::new(CodexAppServerDriver::new(CodexAppServerConfig::new(
                            PathBuf::from("codex"),
                        ))),
                        route_profile: None,
                        work_capability_route: None,
                        disclosure_credentials: egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(),
                    },
                    ProfiledNativeHarnessComposition {
                        profile: multi_native_profile_with_protocol(
                            &config_b,
                            "agent-client-protocol",
                        ),
                        config: config_b,
                        driver: Box::new(egopulse_dsh_adapter::DshAcpDriver::new(
                            egopulse_dsh_adapter::DshAcpConfig::new(
                                PathBuf::from("dsh"),
                                PathBuf::from("workspace-dsh-candidate"),
                            )
                            .with_required_model(shared_gpt_model),
                        )),
                        route_profile: None,
                        work_capability_route: None,
                        disclosure_credentials: egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(),
                    },
                ],
                artifact,
                verification,
            )
            .expect("one GPT model should compose through two replaceable Harness drivers");
        let runner = providers
            .harness_dispatch_runner
            .take()
            .expect("composite dispatch runner");
        let report = runner.run_once().await.expect("empty source cycle");
        assert_eq!(report.activations_seen, 0);
        drop(runner);
        drop(providers);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn multi_profile_native_builder_rejects_shared_store_paths_before_opening_edges() {
        let root = std::env::temp_dir().join(format!(
            "egopulse-agentosd-multi-harness-duplicate-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("test root");
        let config_a = multi_native_config(&root, "a");
        let config_b = multi_native_config(&root, "a");
        let (artifact, verification) = multi_native_authorities(&root);
        let mut providers = DaemonProviders::fail_closed();
        providers.task_activation_source = Some(Arc::new(EmptyTaskActivationSource));

        let result = providers.with_profiled_native_harness_drivers(
            vec![
                ProfiledNativeHarnessComposition {
                    profile: multi_native_profile(&config_a),
                    config: config_a,
                    driver: Box::new(CodexAppServerDriver::new(CodexAppServerConfig::new(
                        PathBuf::from("codex"),
                    ))),
                    route_profile: None,
                    work_capability_route: None,
                    disclosure_credentials:
                        egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(
                        ),
                },
                ProfiledNativeHarnessComposition {
                    profile: multi_native_profile(&config_b),
                    config: config_b,
                    driver: Box::new(CodexAppServerDriver::new(CodexAppServerConfig::new(
                        PathBuf::from("codex"),
                    ))),
                    route_profile: None,
                    work_capability_route: None,
                    disclosure_credentials:
                        egopulse_harness_adapter::ManagedDisclosureCredentials::managed_unavailable(
                        ),
                },
            ],
            artifact,
            verification,
        );
        assert!(matches!(
            result,
            Err(DaemonCompositionError::InvalidConfiguration(
                "multi-Harness stores must be isolated"
            ))
        ));
        let _ = fs::remove_dir_all(root);
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

    #[tokio::test]
    async fn r9c_background_workers_start_the_independent_content_projector() {
        use egopulse_domain_contracts::v01::egopulse::harness::v1::{
            DeliveryDisposition, DispatchContextConsumptionProof, DispatchEnvelope,
            DispatchReceipt, DispatchRouteBinding, HarnessContentSignalObservation,
            HarnessObservation, NotContextBoundProof, ObservationCriticality,
            dispatch_context_consumption_proof, dispatch_route_binding, harness_observation,
        };
        use egopulse_harness_adapter::{
            ManagedDisclosureCredentials, assistant_text_content_candidate, bind_content_signal,
            canonical_dispatch_route_binding_digest,
        };

        let root = std::env::temp_dir().join(format!(
            "egopulse-agentosd-r9c-content-worker-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("create content worker test root");
        let database_path = root.join("adapter.sqlcipher");
        let open_edge = || {
            AdapterEdge::open(AdapterEdgeConfig {
                database_path: database_path.clone(),
                adapter_id: "codex-adapter".to_owned(),
                store_epoch: "r9c-content-worker-v4".to_owned(),
                key: AdapterEdgeKey::new([0x5c; 32]),
            })
        };
        let mut binding = DispatchRouteBinding {
            provider_bootstrap_profile_id: "gpt-codex-default".to_owned(),
            selected_harness_id: "codex_app_server".to_owned(),
            provider_model_id: "gpt-5.6-sol".to_owned(),
            catalog_snapshot: Some(
                dispatch_route_binding::CatalogSnapshot::CatalogSnapshotSha256("a".repeat(64)),
            ),
            capability_profile_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
            route_binding_sha256: String::new(),
        };
        binding.route_binding_sha256 = canonical_dispatch_route_binding_digest(&binding)
            .expect("canonical test route binding");
        let dispatch = DispatchEnvelope {
            run_id: "run-r9c-worker".to_owned(),
            run_revision: 1,
            step_id: "step-r9c-worker".to_owned(),
            step_revision: 1,
            attempt_id: "attempt-r9c-worker".to_owned(),
            attempt_revision: 1,
            dispatch_id: "dispatch-r9c-worker".to_owned(),
            dispatch_fingerprint: "d".repeat(64),
            fencing_token: 7,
            capability_profile_ref: Some(ContractReference {
                contract_id: CODEX_CAPABILITY_PROFILE_ID.to_owned(),
                version: "0.1.0".to_owned(),
                sha256: "c".repeat(64),
            }),
            input_bundle_ref: "input-r9c-worker.json".to_owned(),
            input_bundle_sha256: "e".repeat(64),
            route_binding: Some(binding.clone()),
            ..DispatchEnvelope::default()
        };
        let mut receipt = DispatchReceipt {
            receipt_id: "receipt-r9c-worker".to_owned(),
            disposition: DeliveryDisposition::Delivered as i32,
            attempt_id: dispatch.attempt_id.clone(),
            dispatch_id: dispatch.dispatch_id.clone(),
            fencing_token: dispatch.fencing_token,
            adapter_id: "codex-adapter".to_owned(),
            capability_profile_id: binding.capability_profile_id.clone(),
            evidence_ref: "adapter-edge:test".to_owned(),
            ..DispatchReceipt::default()
        };
        receipt.receipt_digest_sha256 = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            prost::Message::encode_to_vec(&receipt),
        ));
        let raw = b"independent-content-worker-event";
        let mut observation = HarnessObservation {
            attempt_id: dispatch.attempt_id.clone(),
            dispatch_id: dispatch.dispatch_id.clone(),
            fencing_token: dispatch.fencing_token,
            native_event_id: Some("native-r9c-worker-1".to_owned()),
            native_sequence: Some(1),
            native_event_digest_sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(raw)),
            capability_profile_id: binding.capability_profile_id.clone(),
            criticality: ObservationCriticality::Informational as i32,
            payload: Some(harness_observation::Payload::ContentSignal(
                HarnessContentSignalObservation {
                    candidate: assistant_text_content_candidate(
                        "message-r9c-worker",
                        b"safe worker text".to_vec(),
                    ),
                    ..HarnessContentSignalObservation::default()
                },
            )),
            ..HarnessObservation::default()
        };
        let source = observation.clone();
        let Some(harness_observation::Payload::ContentSignal(signal)) =
            observation.payload.as_mut()
        else {
            panic!("content signal fixture")
        };
        bind_content_signal(
            &source,
            signal,
            &receipt.receipt_id,
            &receipt.receipt_digest_sha256,
            &binding.route_binding_sha256,
            DispatchContextConsumptionProof {
                branch: Some(dispatch_context_consumption_proof::Branch::NotContextBound(
                    NotContextBoundProof {},
                )),
            },
        )
        .expect("bind exact worker content source tuple");

        {
            let mut edge = open_edge().expect("open writer Edge");
            edge.prepare_dispatch(&dispatch, 10).expect("prepare");
            edge.begin_delivery(&dispatch.dispatch_id, 11)
                .expect("begin delivery");
            edge.record_dispatch_receipt(&receipt, b"delivery-evidence", 12)
                .expect("record delivered receipt");
            edge.bind_dispatch_task_lineage(&dispatch.dispatch_id, "task-r9c-worker", 1, 1, 13)
                .expect("bind task lineage");
            edge.append_observation(
                &dispatch.dispatch_id,
                "content:worker:1",
                raw,
                observation,
                14,
            )
            .expect("persist pending content candidate");
            let before = edge.inspect().expect("inspect pending content");
            assert_eq!(before.pending_content_candidate_count, 1);
            assert_eq!(before.safe_content_ledger_count, 0);
        }

        let projector_edge = open_edge().expect("open projector Edge");
        let projector = Arc::new(Mutex::new(GovernedHarnessContentProjector::new(
            projector_edge,
            ManagedDisclosureCredentials::harness_account(),
            SystemAdapterClock,
        )));
        let projection_edge = Arc::new(Mutex::new(
            open_edge().expect("open safe content projection consumer Edge"),
        ));
        let read_model = Arc::new(Mutex::new(
            LocalReadModel::open(LocalReadModelConfig {
                database_path: root.join("local-read-model.sqlcipher"),
                epoch: "r9c-content-read-model-v1".to_owned(),
                key: LocalReadModelKey::new([0x5d; 32]),
            })
            .expect("open content Local Read Model"),
        ));
        let content_notifier = HarnessContentCommitNotifier::new(
            read_model
                .lock()
                .expect("read model lock")
                .harness_content_position()
                .expect("initial content position"),
        );
        let (stop_sender, stop_receiver) = tokio::sync::watch::channel(false);
        let background = tokio::spawn(run_background_workers(BackgroundWorkerInputs {
            projection_pump: None,
            harness_dispatch_runner: None,
            harness_dispatch_interval: Duration::from_millis(25),
            approval_delivery_worker: None,
            cancellation_delivery_worker: None,
            verification_worker: None,
            verification_interval: Duration::from_millis(25),
            founder_verdict_consume_worker: None,
            verdict_consumption_interval: Duration::from_millis(25),
            harness_content_workers: vec![HarnessContentWorker {
                projector,
                projection_edge,
            }],
            read_model: Arc::clone(&read_model),
            content_notifier,
            stop: stop_receiver,
        }));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let inspection = open_edge()
                    .expect("open observer Edge")
                    .inspect()
                    .expect("inspect content worker result");
                if inspection.safe_content_ledger_count == 1
                    && inspection.pending_content_projection_count == 0
                {
                    assert_eq!(inspection.pending_content_candidate_count, 0);
                    assert_eq!(
                        read_model
                            .lock()
                            .expect("read model lock")
                            .harness_content_position()
                            .expect("content position")
                            .sequence,
                        1
                    );
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("independent content worker bounded completion");
        stop_sender.send(true).expect("stop content worker");
        tokio::time::timeout(Duration::from_secs(2), background)
            .await
            .expect("background worker bounded stop")
            .expect("background worker task")
            .expect("background worker result");
        drop(read_model);
        fs::remove_dir_all(root).expect("remove content worker test root");
    }

    #[test]
    fn r9c_production_credential_composition_distinguishes_all_disclosure_states() {
        fn profile(credential: bootstrap::ProviderCredentialReference) -> ProviderBootstrapProfile {
            ProviderBootstrapProfile {
                profile_id: "gpt-codex-default".to_owned(),
                provider: bootstrap::ProviderId::Gpt,
                harness: bootstrap::ProviderHarnessKind::CodexAppServer,
                admission: bootstrap::ProviderAdmission::Production,
                models: vec![bootstrap::ProviderModelBinding {
                    harness_model_id: "gpt-5.6-sol".to_owned(),
                    provider_model_id: "gpt-5.6-sol".to_owned(),
                }],
                catalog_snapshot: None,
                exact_model: "gpt-5.6-sol".to_owned(),
                executable: PathBuf::from("codex"),
                credential,
                hold_reason: None,
            }
        }

        let harness_account = profile(bootstrap::ProviderCredentialReference::HarnessAccount);
        assert!(matches!(
            codex_disclosure_credentials(&harness_account, &[]),
            egopulse_harness_adapter::ManagedDisclosureCredentials::HarnessAccount
        ));
        assert!(matches!(
            codex_disclosure_credentials(
                &harness_account,
                &[("UNEXPECTED".to_owned(), "not-forwarded".to_owned())]
            ),
            egopulse_harness_adapter::ManagedDisclosureCredentials::ManagedUnavailable
        ));

        let managed = profile(bootstrap::ProviderCredentialReference::ApiKeyEnvironment {
            source_env: "EGOPULSE_TEST_SOURCE".to_owned(),
            target_env: "EGOPULSE_TEST_TARGET".to_owned(),
        });
        let available = codex_disclosure_credentials(
            &managed,
            &[(
                "EGOPULSE_TEST_TARGET".to_owned(),
                "ephemeral-test-secret".to_owned(),
            )],
        );
        assert!(matches!(
            available,
            egopulse_harness_adapter::ManagedDisclosureCredentials::ManagedAvailable(ref values)
                if values.as_slice() == ["ephemeral-test-secret"]
        ));
        assert!(matches!(
            codex_disclosure_credentials(&managed, &[]),
            egopulse_harness_adapter::ManagedDisclosureCredentials::ManagedUnavailable
        ));
        assert!(matches!(
            codex_disclosure_credentials(
                &managed,
                &[
                    (
                        "EGOPULSE_TEST_TARGET".to_owned(),
                        "ephemeral-test-secret".to_owned(),
                    ),
                    ("UNEXPECTED".to_owned(), "other".to_owned()),
                ]
            ),
            egopulse_harness_adapter::ManagedDisclosureCredentials::ManagedUnavailable
        ));
        assert!(matches!(
            codex_disclosure_credentials(
                &managed,
                &[("EGOPULSE_TEST_TARGET".to_owned(), "x".repeat(100_000))]
            ),
            egopulse_harness_adapter::ManagedDisclosureCredentials::ManagedOutOfBounds
        ));
    }

    #[allow(dead_code)]
    fn _system_time_is_available_for_future_lifecycle_tests() -> SystemTime {
        UNIX_EPOCH
    }
}
