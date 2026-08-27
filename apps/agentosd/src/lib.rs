#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_codex_adapter::{
    CODEX_ADAPTER_ID, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig, CodexAppServerDriver,
    FileDispatchMaterialResolver, codex_protocol_fingerprint,
};
use egopulse_cognition_runtime::memory_authority::MemoryAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    harness::v1::{CapabilityProfile, NativeProtocolFingerprint},
    policy::v1::{IssueHarnessApprovalDecisionCommand, PolicyDecisionCommandResult},
    task::v1::{TaskCommand, TaskCommandResult},
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
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeKey, GovernedHarnessAdapter,
    NativeHarnessDriver, SystemAdapterClock, validate_capability_binding,
};
use egopulse_local_api::{
    cognition_gateway::{
        CognitionGatewayApplication, LocalCognitionEndpoint, MemoryRetrievalAuditSink,
        MemoryRetrievalPort,
    },
    command_gateway::{
        CommandGatewayApplication, CommandPortFailure, CommandPortResult, CommandPrincipal,
        FailClosedMemoryMutationPort, LocalCommandGatewayEndpoint, MemoryMutationPort,
        PolicyCommandPort, TaskCommandPort, VerdictCommandPort,
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
    CompositeHarnessDispatchRunner, GovernedTaskActivationRunner, HarnessDispatchCycleError,
    HarnessDispatchRunner, SingleHarnessWorkConfig, SingleHarnessWorkflowResolution,
    SingleHarnessWorkflowResolver, SingleHarnessWorkflowResolverError, SystemAuthorityClock,
    TaskActivationGuardSet, TaskActivationSource,
};
use egopulse_local_ipc_platform::{LocalIpcAddress, LocalIpcListener};
use egopulse_local_read_model::{LocalReadModel, LocalReadModelConfig, LocalReadModelKey};
use tonic::transport::Server;

mod artifact;
mod bootstrap;
mod memory_mutation;
mod memory_retrieval;
mod owners;
mod policy;
mod projections;
mod return_collector;
mod return_projection;
mod security;
mod task;
mod verdict;
mod verdict_consumer;
mod verification;

pub use artifact::{
    ArtifactAdmissionGuardConfigurationError, ArtifactAuthorityReferenceSource,
    ConfiguredArtifactAdmissionGuard, ConfiguredArtifactAdmissionGuardConfig,
};
pub use bootstrap::{
    DenyVerificationReferences, LocalUserPolicyBootstrapConfig, ProductionBootstrapConfig,
    ProductionBootstrapError, ProviderCatalogModelView, ProviderCatalogProfileView,
};
pub use memory_mutation::{
    MemoryCandidateProducerBinding, MemoryCandidateProducerConfigurationError,
    MemoryCandidateProducerFailure, MemoryCandidateProducerHandle, MemoryCandidateProducerPort,
    MemoryCandidateProducerRegistry, MemoryCandidateProposal, MemoryMutationPortAdapter,
};
pub use memory_retrieval::{
    ConfiguredMemoryRetrievalPort, FailClosedMemoryRetrievalPort, MemoryRetrievalCompositionConfig,
    MemoryRetrievalConfigurationError, TracingMemoryRetrievalAuditSink,
};
pub use owners::{
    AuthorityCommandPorts, AuthorityPrincipalResolver, DenyAllAuthorityPrincipalResolver,
};
pub use policy::{
    LocalUserPolicyAdapterConfig, LocalUserPolicyConfigurationError, LocalUserPolicyResolver,
    LocalUserPolicyResolverConfig, LocalUserPolicyResolverMultiConfig,
};
pub use projections::{
    AdapterApprovalProjectionSource, ArtifactProjectionSource, CollaborationProjectionSource,
    CompositeOwnerProjectionSource, OwnerProjectionSource, PendingOwnerProjection, ProjectionPump,
    ProjectionPumpFailure, ProjectionSourceFailure, VerificationProjectionSource,
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
    SystemCheckerProfileAttestation, SystemTaskVerificationWriteBack,
    TaskVerificationWriteBackError, TaskVerificationWriteBackResult, VerificationBindingTemplate,
    VerificationHandoffConsumeResult, VerificationHandoffIntake, VerificationHandoffIntakeError,
    VerificationHandoffPlan, VerificationHandoffPlanError, VerificationHandoffRequest,
    VerificationWorker, VerificationWorkerConfig, VerificationWorkerConfigurationError,
    VerificationWorkerCycleError, VerificationWorkerCycleResult,
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
    pub projection_source: Option<Arc<dyn OwnerProjectionSource>>,
    pub harness_dispatch_runner: Option<Arc<dyn HarnessDispatchRunner>>,
    pub verification_worker: Option<Arc<dyn VerificationWorker>>,
    pub founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    pub task_activation_source: Option<Arc<dyn TaskActivationSource>>,
    pub memory_retrieval_port: Arc<dyn MemoryRetrievalPort>,
    pub memory_retrieval_audit: Arc<dyn MemoryRetrievalAuditSink>,
    pub memory_mutation_port: Arc<dyn MemoryMutationPort>,
    /// Internal candidate-only producer capabilities. This is deliberately
    /// separate from the public Local API mutation port.
    pub memory_candidate_producers: Arc<MemoryCandidateProducerRegistry>,
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
    ) -> Result<SingleHarnessWorkflowResolution, SingleHarnessWorkflowResolverError> {
        if activation.task.current_run_id.as_deref() != Some(self.config.run_id.as_str()) {
            return Ok(SingleHarnessWorkflowResolution::NotApplicable);
        }
        Ok(SingleHarnessWorkflowResolution::Resolved(Box::new(
            self.config.clone(),
        )))
    }
}

/// Provider-neutral composition input for one admitted native Harness. The
/// workflow configuration is reviewed data; no value is inferred from a Task
/// payload or from a provider response. Provider process configuration stays
/// outside this type.
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
}

/// One provider-specific native Harness unit for the multi-model composition
/// boundary. Admission is still external: `profile` must come from the
/// attested capability path before this unit is passed to the daemon.
pub struct ProfiledNativeHarnessComposition {
    pub config: NativeHarnessCompositionConfig,
    pub profile: NativeHarnessCompositionProfile,
    pub driver: Box<dyn NativeHarnessDriver + Send>,
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
        let profile = Self {
            adapter_id: declaration.adapter_id.clone(),
            capability_profile_id: capability_profile.profile_id.clone(),
            capability_profile_ref: required_profile_ref.clone(),
            observed_protocol,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), DaemonCompositionError> {
        if self.adapter_id.trim().is_empty()
            || self.capability_profile_id.trim().is_empty()
            || self.capability_profile_ref.contract_id.trim().is_empty()
            || self.capability_profile_ref.version.trim().is_empty()
            || self.capability_profile_ref.sha256.trim().is_empty()
            || self.capability_profile_id != self.capability_profile_ref.contract_id
            || self.observed_protocol.protocol_name.trim().is_empty()
            || self.observed_protocol.protocol_version.trim().is_empty()
            || self.observed_protocol.schema_sha256.trim().is_empty()
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
            verification_worker: None,
            founder_verdict_consume_worker: None,
            task_activation_source: None,
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
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
        let verdict = Arc::new(Mutex::new(Some(inputs.verdict)));
        let ports = Arc::new(AuthorityCommandPorts::new_shared_handles(
            Arc::clone(&task),
            inputs.policy,
            Arc::clone(&verdict),
            inputs.principal_resolver,
        ));
        let founder_verdict_consume_worker = Some(Arc::new(
            ConfiguredFounderVerdictConsumeWorker::new(
                task,
                verdict,
                "task-authority:founder-verdict-consumer",
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
            verification_worker: None,
            founder_verdict_consume_worker,
            task_activation_source: Some(Arc::clone(&ports) as Arc<dyn TaskActivationSource>),
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
        }
    }

    /// Builds daemon providers from a shared Task Authority handle. This is
    /// the production path when Founder Verdict receipt validation and Task
    /// command handling must observe the same owner instance.
    #[must_use]
    pub fn from_shared_authority_inputs(inputs: SharedAuthorityCompositionInputs) -> Self {
        let founder_verdict_consume_worker = Some(Arc::new(
            ConfiguredFounderVerdictConsumeWorker::new(
                Arc::clone(&inputs.task),
                Arc::clone(&inputs.verdict),
                "task-authority:founder-verdict-consumer",
            )
            .expect("static Founder Verdict consume worker principal"),
        )
            as Arc<dyn FounderVerdictConsumeWorker>);
        let ports = Arc::new(AuthorityCommandPorts::new_shared_handles(
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
            verification_worker: None,
            founder_verdict_consume_worker,
            task_activation_source: Some(Arc::clone(&ports) as Arc<dyn TaskActivationSource>),
            memory_retrieval_port: Arc::new(FailClosedMemoryRetrievalPort),
            memory_retrieval_audit: Arc::new(TracingMemoryRetrievalAuditSink),
            memory_mutation_port: Arc::new(FailClosedMemoryMutationPort),
            memory_candidate_producers: Arc::new(MemoryCandidateProducerRegistry::empty()),
        }
    }

    #[must_use]
    pub fn with_harness_dispatch_runner(mut self, runner: Arc<dyn HarnessDispatchRunner>) -> Self {
        self.harness_dispatch_runner = Some(runner);
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

    #[must_use]
    pub fn with_verification_worker(mut self, worker: Arc<dyn VerificationWorker>) -> Self {
        self.verification_worker = Some(worker);
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
        self.memory_retrieval_port = Arc::new(
            ConfiguredMemoryRetrievalPort::new(authority, config)
                .map_err(DaemonCompositionError::MemoryRetrieval)?,
        );
        Ok(self)
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
    pub fn with_codex_harness(
        self,
        config: CodexHarnessCompositionConfig,
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
        } = config;
        let mut process = CodexAppServerConfig::new(codex_executable);
        for (name, value) in environment_overrides {
            process = process.with_environment_override(name, value);
        }
        self.with_native_harness_driver(
            native,
            artifact_authority,
            verification,
            CodexAppServerDriver::new(process),
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
        let mut runners = Vec::with_capacity(compositions.len());
        for composition in compositions {
            let ProfiledNativeHarnessComposition {
                config,
                profile,
                driver,
            } = composition;
            let NativeHarnessCompositionProfile {
                adapter_id,
                capability_profile_id,
                capability_profile_ref: _,
                observed_protocol,
            } = profile;
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
            let writer_edge = AdapterEdge::open(AdapterEdgeConfig {
                database_path: config.adapter_database_path,
                adapter_id: adapter_id.clone(),
                store_epoch: config.adapter_store_epoch,
                key: AdapterEdgeKey::new(config.adapter_key),
            })
            .map_err(DaemonCompositionError::AdapterEdge)?;
            let evidence = GovernedReturnEvidenceResolver::new(
                reader_edge,
                Arc::clone(&artifact_authority),
                Arc::clone(&verification),
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
                observed_protocol,
                writer_edge,
                match config.default_model {
                    Some(model) => FileDispatchMaterialResolver::new(
                        config.input_bundle_root,
                        config.workspace_root,
                    )
                    .with_default_model(model),
                    None => FileDispatchMaterialResolver::new(
                        config.input_bundle_root,
                        config.workspace_root,
                    ),
                },
                driver,
                SystemAdapterClock,
            );
            let principal = AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::HarnessAdapter,
                principal_id: config.workflow.harness_adapter_principal_id.clone(),
                authenticated: true,
            };
            let capability_profile_ref = config.workflow.capability_profile_ref.clone();
            let resolver = ConfiguredSingleHarnessWorkflow::new(config.workflow);
            let artifact_return_principal = AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::ArtifactAuthority,
                principal_id: config
                    .return_collector
                    .artifact_authority_principal_id
                    .clone(),
                authenticated: true,
            };
            let artifact_return_source: Arc<
                dyn egopulse_local_ide_control::collaboration_control::ArtifactReturnSource,
            > = Arc::new(ArtifactAuthorityReturnSource::new(Arc::clone(
                &artifact_authority,
            )));
            let runner = GovernedTaskActivationRunner::new(
                control,
                adapter,
                Arc::clone(&source),
                resolver,
                principal,
                reference,
                config.lease_ttl_seconds,
            )
            .with_capability_profile_ref(capability_profile_ref)
            .with_artifact_return_source(artifact_return_source, artifact_return_principal)
            .with_step_return_principal(AuthenticatedCollaborationPrincipal {
                kind: CollaborationPrincipalKind::CollaborationControl,
                principal_id: "collaboration-control:return-settlement".to_owned(),
                authenticated: true,
            });
            let harness: Arc<dyn HarnessDispatchRunner> = Arc::new(runner);
            let collector = GovernedReturnCollectorRunner::new(
                harness,
                collector_edge,
                Arc::clone(&artifact_authority),
                config.return_collector,
            )
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
            runners.push(Arc::new(collector) as Arc<dyn HarnessDispatchRunner>);
        }
        let composite = CompositeHarnessDispatchRunner::new(runners)
            .map_err(DaemonCompositionError::InvalidConfiguration)?;
        self.harness_dispatch_runner = Some(Arc::new(composite));
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
    harness_dispatch_interval: Duration,
    verification_worker: Option<Arc<dyn VerificationWorker>>,
    verification_interval: Duration,
    founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    verdict_consumption_interval: Duration,
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
        let command_application = Arc::new(CommandGatewayApplication::new_with_memory(
            Arc::clone(&registry),
            Arc::clone(&profiles),
            token_codec,
            providers.task_port,
            providers.policy_port,
            providers.verdict_port,
            providers.memory_mutation_port,
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
        let verification_worker = providers.verification_worker;
        let founder_verdict_consume_worker = providers.founder_verdict_consume_worker;

        Ok(Self {
            address,
            listener,
            session,
            read_model,
            command,
            cognition,
            projection_pump,
            harness_dispatch_runner,
            harness_dispatch_interval: config.harness_dispatch_interval,
            verification_worker,
            verification_interval: config.verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval: config.verdict_consumption_interval,
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
            harness_dispatch_interval,
            verification_worker,
            verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval,
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
            verification_worker,
            verification_interval,
            founder_verdict_consume_worker,
            verdict_consumption_interval,
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
    verification_worker: Option<Arc<dyn VerificationWorker>>,
    verification_interval: Duration,
    founder_verdict_consume_worker: Option<Arc<dyn FounderVerdictConsumeWorker>>,
    verdict_consumption_interval: Duration,
    stop: tokio::sync::watch::Receiver<bool>,
}

async fn run_background_workers(inputs: BackgroundWorkerInputs) -> Result<(), DaemonServeError> {
    let BackgroundWorkerInputs {
        projection_pump,
        harness_dispatch_runner,
        harness_dispatch_interval,
        verification_worker,
        verification_interval,
        founder_verdict_consume_worker,
        verdict_consumption_interval,
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
                verification_interval: Duration::from_millis(25),
                verdict_consumption_interval: Duration::from_millis(25),
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

    struct CountingFounderVerdictConsumeWorker {
        runs: Arc<AtomicUsize>,
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
                    ..Default::default()
                },
            ),
            attestation_level:
                egopulse_domain_contracts::v01::egopulse::harness::v1::AttestationLevel::ProbeVerified
                    as i32,
            attestation_evidence_refs: vec!["probe://harness/1".to_owned()],
            ..Default::default()
        };
        let bound = NativeHarnessCompositionProfile::from_attested_capability(
            &ContractReference {
                contract_id: "profile".to_owned(),
                version: "v1".to_owned(),
                sha256: "ab".repeat(32),
            },
            "family",
            &capability,
            capability
                .declaration
                .as_ref()
                .and_then(|declaration| declaration.native_protocol.clone())
                .expect("test capability protocol"),
            &prost_types::Timestamp::default(),
        )
        .expect("attested capability should produce a composition profile");
        assert_eq!(bound.adapter_id, "adapter");
        assert_eq!(bound.capability_profile_id, "profile");
        assert_eq!(
            bound.capability_profile_ref,
            ContractReference {
                contract_id: "profile".to_owned(),
                version: "v1".to_owned(),
                sha256: "ab".repeat(32),
            }
        );

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
    async fn multi_profile_native_builder_assembles_isolated_runners_over_one_source() {
        let root = std::env::temp_dir().join(format!(
            "egopulse-agentosd-multi-harness-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("test root");
        let config_a = multi_native_config(&root, "a");
        let config_b = multi_native_config(&root, "b");
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
                            ),
                        )),
                    },
                ],
                artifact,
                verification,
            )
            .expect("two admitted profiles should compose");
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
                },
                ProfiledNativeHarnessComposition {
                    profile: multi_native_profile(&config_b),
                    config: config_b,
                    driver: Box::new(CodexAppServerDriver::new(CodexAppServerConfig::new(
                        PathBuf::from("codex"),
                    ))),
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

    #[allow(dead_code)]
    fn _system_time_is_available_for_future_lifecycle_tests() -> SystemTime {
        UNIX_EPOCH
    }
}
