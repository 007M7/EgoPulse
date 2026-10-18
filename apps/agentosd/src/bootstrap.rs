use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactAuthorityFailure, ArtifactSqlCipherKey,
};
use egopulse_cognition_runtime::context_authority::{
    ContextAuthority, ContextAuthorityConfig, ContextPrincipalKind,
};
use egopulse_cognition_runtime::memory_authority::{
    MemoryAuthority, MemoryAuthorityConfig, MemoryAuthorityFailure, MemoryPrincipalKind,
};
use egopulse_cognition_runtime::task_authority::{
    PrincipalKind as TaskPrincipalKind, SqlCipherKey, TaskAuthority, TaskAuthorityConfig,
    TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    collaboration::v1::{RunPlan, StepPlan},
    common::v1::ContractReference,
    harness::v1::NativeSessionStrategy,
    task::v1::WorkCapabilityRouteBinding,
    verification::v1::{CheckerProfile, VerificationBinding, VerificationRequest},
};
use egopulse_domain_contracts::work_capability::seal_work_capability_route_binding;
use egopulse_founder_verdict_authority::{FounderVerdictAuthority, VerdictAuthorityConfig};
use egopulse_founder_verdict_authority::{VerdictPrincipalKind, VerdictSqlCipherKey};
use egopulse_harness_adapter::{AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeKey};
use egopulse_local_api::session::{NoopSessionAuditSink, SystemSessionClock};
use egopulse_local_ide_control::collaboration_control::{
    DispatchMaterial, SingleHarnessWorkConfig,
};
use egopulse_policy_decision_authority::{
    PolicyAuthorityConfig, PolicyAuthorityFailure, PolicyDecisionAuthority, PolicyPrincipalKind,
    PolicySqlCipherKey,
};
use egopulse_process_supervision::is_supported_executable_file;
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, ReferenceRejection, ResolvedVerificationInput,
    SEGO_REVIEW_ARTIFACT_CONTRACT_ID, SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION,
    SegoFindingEvidenceBinding, SegoMapperPolicy, VerificationAuthority,
    VerificationAuthorityConfig, VerificationAuthorityFailure, VerificationReferenceResolver,
    VerificationSqlCipherKey,
};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::work_capability::{
    WorkCapabilityRegistry, WorkCapabilityRegistryError, persist_explicit_config_transition,
};
use crate::{AllowlistedPrincipal, AllowlistedPrincipalResolver, PrincipalPolicyError};
use crate::{
    ArtifactAuthorityReferenceSource, ArtifactProjectionSource, AuthorityPrincipalBinding,
    CodexHarnessCompositionConfig, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredAuthorityPrincipalResolver,
    ConfiguredFounderVerdictResolver, ConfiguredFounderVerdictResolverConfig,
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, ConfiguredTaskTransitionGuard,
    ConfiguredVerificationWorker, ContextMutationPortAdapter, DaemonCompositionError,
    DaemonProviders, FounderVerdictConfigurationError, GovernedReturnCollectorConfig,
    LocalUserPolicyResolver, LocalUserPolicyResolverConfig, MemoryCandidateProducerBinding,
    MemoryRetrievalCompositionConfig, NativeHarnessCompositionConfig,
    SharedAuthorityHandlesCompositionInputs, TaskAuthorityCommitReceiptSource,
    VerificationAuthorityArtifactSource, VerificationProjectionSource, VerificationWorkerConfig,
};
use crate::{ConfiguredWorkPreparationPort, RepositoryMaterialConfig};

#[path = "bootstrap_repository.rs"]
mod repository;
pub use repository::{FounderSupportingMaterialConfig, RepositoryVerificationConfig};

const PRODUCTION_BOOTSTRAP_V2: &str = "egopulse.production-bootstrap/v2";
const PRODUCTION_BOOTSTRAP_V3: &str = "egopulse.production-bootstrap/v3";
const V2_MIGRATION_BACKUP_SUFFIX: &str = ".v2.bak";
const V3_ROLLBACK_BACKUP_SUFFIX: &str = ".v3-rollback.bak";
const MAX_MIGRATION_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Explicit scalar configuration for the local-user Policy resolver. The
/// Adapter edge is opened by the composition root so the resolver reads the
/// same durable adapter store as the Codex Harness composition.
pub struct LocalUserPolicyBootstrapConfig {
    pub edge: AdapterEdgeConfig,
    pub authentication_context_ref: String,
    pub authorization_policy_ref: ContractReference,
    pub allowed_scope_refs: BTreeSet<String>,
    pub decision_ttl: Duration,
}

/// Stable provider identity shown by every client surface. This names the
/// model provider, not the executable used to reach it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderId {
    Gpt,
    DeepSeek,
    Kimi,
    Glm,
}

/// Replaceable open-source Harness selected for one provider profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHarnessKind {
    CodexAppServer,
    DshAcp,
    KimiCliAcp,
    OpenCodeAcp,
}

/// Admission is independent from configuration presence. Candidate and held
/// profiles are visible to operators but cannot enter production dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAdmission {
    Production,
    Candidate,
    Held,
}

/// A secret remains in its source environment variable. Only the variable
/// names cross this boundary; status and diagnostics never expose the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderCredentialReference {
    HarnessAccount,
    ApiKeyEnvironment {
        source_env: String,
        target_env: String,
    },
}

/// One model route carries both identities because Harness aliases and vendor
/// API model identifiers are not necessarily the same string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderModelBinding {
    /// Exact identifier accepted by the selected Harness. This is the value
    /// bound into dispatch and verified in the native receipt.
    pub harness_model_id: String,
    /// Vendor-native model identifier. For example, OpenCode may route
    /// `zai/glm-5.3` while Z.AI names the upstream model `glm-5.3`.
    pub provider_model_id: String,
}

/// Provenance for a local model-catalog snapshot. This describes where the
/// editable catalog came from; it is not evidence that the Harness is
/// reachable or that any model is production-admitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCatalogSnapshot {
    pub source: String,
    pub fetched_at: String,
    pub harness_version: String,
    pub evidence_digest_sha256: String,
}

/// Redaction-safe provider bootstrap profile shared by daemon startup and the
/// future CLI/TUI provider status projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderBootstrapProfile {
    pub profile_id: String,
    pub provider: ProviderId,
    pub harness: ProviderHarnessKind,
    pub admission: ProviderAdmission,
    /// User/provider supplied model catalog. It is configuration data, not a
    /// claim that every model is currently reachable.
    pub models: Vec<ProviderModelBinding>,
    pub catalog_snapshot: Option<ProviderCatalogSnapshot>,
    /// The exact Harness model identifier sent when a work input does not
    /// override the profile.
    pub exact_model: String,
    pub executable: PathBuf,
    pub credential: ProviderCredentialReference,
    pub hold_reason: Option<String>,
}

/// Redacted configuration projection for setup and diagnostics. It contains
/// provider/model identities and environment-variable names only; it never
/// resolves or serializes credential values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCatalogProfileView {
    pub profile_id: String,
    pub provider: String,
    pub harness: String,
    pub admission: String,
    pub models: Vec<ProviderCatalogModelView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_snapshot: Option<ProviderCatalogSnapshot>,
    pub selected_model: String,
    pub executable: String,
    /// Read-only local discovery result. This is not a protocol or
    /// authentication attestation and never executes the Harness.
    pub executable_available: bool,
    pub credential_mode: String,
    /// `present`/`missing` applies only to API-key environment references;
    /// `harness_account_delegated` means the Harness owns authentication.
    pub credential_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_source_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCatalogModelView {
    pub harness_model_id: String,
    pub provider_model_id: String,
}

/// Redaction-safe report for the explicit v2/v3 work-capability config
/// transition. It contains only public route identities and file locations;
/// authority keys and Provider credential values are never decoded here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkCapabilityConfigTransitionReport {
    pub transition: String,
    pub applied: bool,
    pub from_schema_version: String,
    pub to_schema_version: String,
    pub config_path: String,
    pub retained_backup_path: String,
    pub choice_id: String,
    pub provider_profile_id: String,
    pub provider_id: String,
    pub harness_id: String,
    pub harness_model_id: String,
    pub provider_model_id: String,
    pub route_binding_sha256: String,
    pub preference_revision: u64,
}

/// A provider-neutral preview of a refreshed Harness catalog.
///
/// This is intentionally a pure value and does not mutate user configuration.
/// A refresh can make the currently selected model unavailable, but it can
/// never select a replacement implicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCatalogRefreshPreview {
    pub profile_id: String,
    pub models: Vec<ProviderCatalogModelView>,
    pub selected_model: String,
    pub selected_model_available: bool,
    pub selection_changed: bool,
    pub requires_user_action: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProviderCatalogRefreshError {
    #[error("refreshed provider catalog must contain at least one model")]
    EmptyCatalog,
    #[error("refreshed provider catalog contains an invalid {0}")]
    InvalidModelIdentity(&'static str),
    #[error("refreshed provider catalog contains a duplicate Harness model id")]
    DuplicateHarnessModelId,
}

impl ProviderBootstrapProfile {
    #[must_use]
    pub fn redacted_catalog_view(&self) -> ProviderCatalogProfileView {
        let (credential_mode, credential_status, credential_source_env) = match &self.credential {
            ProviderCredentialReference::HarnessAccount => {
                ("harness_account", "harness_account_delegated", None)
            }
            ProviderCredentialReference::ApiKeyEnvironment { source_env, .. } => {
                let status = match std::env::var(source_env) {
                    Ok(value) if !value.trim().is_empty() => "present",
                    _ => "missing",
                };
                ("api_key_environment", status, Some(source_env.clone()))
            }
        };
        ProviderCatalogProfileView {
            profile_id: self.profile_id.clone(),
            provider: self.provider.as_str().to_owned(),
            harness: self.harness.as_str().to_owned(),
            admission: self.admission.as_str().to_owned(),
            models: self
                .models
                .iter()
                .map(|model| ProviderCatalogModelView {
                    harness_model_id: model.harness_model_id.clone(),
                    provider_model_id: model.provider_model_id.clone(),
                })
                .collect(),
            catalog_snapshot: self.catalog_snapshot.clone(),
            selected_model: self.exact_model.clone(),
            executable: self.executable.display().to_string(),
            executable_available: provider_executable_available(&self.executable),
            credential_mode: credential_mode.to_owned(),
            credential_status: credential_status.to_owned(),
            credential_source_env,
            hold_reason: self.hold_reason.clone(),
        }
    }

    /// Previews a Harness-native catalog refresh without changing selection.
    ///
    /// The returned preview is suitable for a future read/selection surface.
    /// It deliberately has no persistence side effect: selecting a model is a
    /// separate, Founder-visible operation that must later be bound to the
    /// frozen Local API contract and an exact dispatch receipt.
    pub fn preview_catalog_refresh(
        &self,
        refreshed_models: &[ProviderModelBinding],
    ) -> Result<ProviderCatalogRefreshPreview, ProviderCatalogRefreshError> {
        if refreshed_models.is_empty() {
            return Err(ProviderCatalogRefreshError::EmptyCatalog);
        }
        let mut models = refreshed_models.to_vec();
        for model in &models {
            validate_refreshed_model_identity(model)?;
        }
        models.sort_by(|left, right| {
            left.harness_model_id
                .cmp(&right.harness_model_id)
                .then_with(|| left.provider_model_id.cmp(&right.provider_model_id))
        });
        if models
            .windows(2)
            .any(|pair| pair[0].harness_model_id == pair[1].harness_model_id)
        {
            return Err(ProviderCatalogRefreshError::DuplicateHarnessModelId);
        }
        let selected_model_available = models
            .iter()
            .any(|model| model.harness_model_id == self.exact_model);
        Ok(ProviderCatalogRefreshPreview {
            profile_id: self.profile_id.clone(),
            models: models
                .into_iter()
                .map(|model| ProviderCatalogModelView {
                    harness_model_id: model.harness_model_id,
                    provider_model_id: model.provider_model_id,
                })
                .collect(),
            selected_model: self.exact_model.clone(),
            selected_model_available,
            selection_changed: false,
            requires_user_action: !selected_model_available,
            reason_code: (!selected_model_available)
                .then_some("selected_model_missing_from_refresh".to_owned()),
        })
    }
}

/// Performs non-invasive executable discovery for setup diagnostics.
///
/// A configured command can be a path or a bare command name. On Windows,
/// `PATHEXT` is honored so `.cmd` Harness launchers are reported correctly.
/// This function only inspects the filesystem/PATH; it never starts a child
/// process and therefore cannot be mistaken for a Provider capability probe.
fn provider_executable_available(executable: &Path) -> bool {
    resolve_provider_executable(executable).is_some()
}

fn provider_command_extensions(executable: &Path) -> Vec<String> {
    if !cfg!(windows) || executable.extension().is_some() {
        return Vec::new();
    }
    std::env::var_os("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(str::to_owned)
        .collect()
}

fn resolve_provider_executable(executable: &Path) -> Option<PathBuf> {
    // An extension does not make a command an explicit path: `codex.cmd` is
    // still a valid PATH lookup on Windows. Only a path-like value should be
    // checked relative to the current filesystem location.
    if executable.components().count() > 1 {
        let candidate = fs::canonicalize(executable).ok()?;
        return is_supported_executable_file(&candidate).then_some(candidate);
    }
    let path_value = std::env::var_os("PATH")?;
    let candidates =
        std::env::split_paths(&path_value).flat_map(|directory| {
            let direct = directory.join(executable);
            let extensions = provider_command_extensions(executable);
            std::iter::once(direct).chain(extensions.into_iter().map(move |extension| {
                directory.join(format!("{}{}", executable.display(), extension))
            }))
        });
    candidates.into_iter().find_map(|candidate| {
        let candidate = fs::canonicalize(candidate).ok()?;
        is_supported_executable_file(&candidate).then_some(candidate)
    })
}

fn validate_refreshed_model_identity(
    model: &ProviderModelBinding,
) -> Result<(), ProviderCatalogRefreshError> {
    for (value, field) in [
        (&model.harness_model_id, "harness model identity"),
        (&model.provider_model_id, "provider model identity"),
    ] {
        if value.is_empty() || value.trim() != value || value.len() > 4 * 1024 {
            return Err(ProviderCatalogRefreshError::InvalidModelIdentity(field));
        }
    }
    Ok(())
}

impl ProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpt => "gpt",
            Self::DeepSeek => "deepseek",
            Self::Kimi => "kimi",
            Self::Glm => "glm",
        }
    }
}

impl ProviderHarnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CodexAppServer => "codex_app_server",
            Self::DshAcp => "dsh_acp",
            Self::KimiCliAcp => "kimi_cli_acp",
            Self::OpenCodeAcp => "opencode_acp",
        }
    }
}

impl ProviderAdmission {
    fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Candidate => "candidate",
            Self::Held => "held",
        }
    }
}

/// Inputs owned by the local installation, not inferred from a client request.
pub struct ProductionBootstrapConfig {
    pub task: TaskAuthorityConfig,
    pub memory: MemoryAuthorityConfig,
    pub memory_retrieval: Option<MemoryRetrievalCompositionConfig>,
    pub memory_candidate_producers: Vec<MemoryCandidateProducerBinding>,
    pub task_guard: ConfiguredTaskCreationGuardConfig,
    /// Optional D-02 repository material source. Absence preserves the legacy
    /// work-preparation and snapshot behavior.
    pub repository_material: Option<RepositoryMaterialConfig>,
    /// Explicit Artifact contracts for governed repository command intents and
    /// receipts. This is present exactly when repository material is enabled.
    pub repository_command_artifacts: Option<RepositoryCommandArtifactPolicyConfig>,
    pub artifact: ArtifactAuthorityConfig,
    pub artifact_guard: ConfiguredArtifactAdmissionGuardConfig,
    pub verification: VerificationAuthorityConfig,
    /// Optional reviewed Artifact-backed Verification reference policy. When
    /// absent, production remains deny-by-default for external Verification
    /// requests and checker profile attestation.
    pub verification_references: Option<VerificationReferenceBootstrapConfig>,
    /// Optional explicit worker composition. When supplied by the user JSON
    /// file, every execution field is decoded from an explicit reviewed
    /// configuration object and validated before daemon construction.
    pub verification_worker: Option<VerificationWorkerConfig>,
    /// Per-task frozen repository checking, composed with the same authorities
    /// as dispatch and return collection. Mutually exclusive with the legacy worker.
    pub repository_verification: Option<RepositoryVerificationConfig>,
    pub founder_supporting_material: Option<FounderSupportingMaterialConfig>,
    pub policy: PolicyAuthorityConfig,
    pub policy_resolver: LocalUserPolicyBootstrapConfig,
    pub verdict: VerdictAuthorityConfig,
    pub allowed_founder_principal_ids: BTreeSet<String>,
    pub founder_authority_ref: String,
    pub founder_authority_policy_ref: ContractReference,
    pub allowed_confirmation_proof_refs: BTreeSet<String>,
    pub non_overridable_gate_ids: BTreeSet<String>,
    pub non_overridable_criterion_ids: BTreeSet<String>,
    pub founder_confirmation_ttl: Duration,
    pub os_principal: AllowlistedPrincipal,
    pub authority_binding: AuthorityPrincipalBinding,
    pub provider_profiles: Vec<ProviderBootstrapProfile>,
    pub work_capability_registry: Arc<WorkCapabilityRegistry>,
    pub codex: CodexHarnessCompositionConfig,
}

impl ProductionBootstrapConfig {
    /// Loads non-secret configuration from a user-owned JSON file. Secret
    /// material is referenced by environment-variable name and is never read
    /// from the file itself.
    pub fn from_environment() -> Result<Self, ProductionBootstrapError> {
        let path = std::env::var_os("EGOPULSE_USER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("egopulse-data/agentos-config.json"));
        Self::from_user_file(path)
    }

    pub fn from_user_file(path: impl AsRef<Path>) -> Result<Self, ProductionBootstrapError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| {
            ProductionBootstrapError::ConfigurationFile {
                path: path.display().to_string(),
                source,
            }
        })?;
        let file: UserOwnedBootstrapFile = serde_json::from_str(&raw).map_err(|source| {
            ProductionBootstrapError::ConfigurationFormat {
                path: path.display().to_string(),
                source,
            }
        })?;
        file.into_typed(path.to_path_buf())
    }

    /// Returns the redaction-safe Provider catalog. It intentionally does not
    /// return resolved secret values.
    #[must_use]
    pub fn provider_profiles(&self) -> &[ProviderBootstrapProfile] {
        &self.provider_profiles
    }

    /// Returns the provider/model catalog for setup and diagnostics without
    /// exposing credential values or authority state.
    #[must_use]
    pub fn provider_catalog_views(&self) -> Vec<ProviderCatalogProfileView> {
        self.provider_profiles
            .iter()
            .map(ProviderBootstrapProfile::redacted_catalog_view)
            .collect()
    }

    /// Opens every Authority exactly once and composes the first production
    /// vertical. Missing or invalid references fail before a serving daemon is
    /// built; no test resolver is used as a production fallback.
    pub fn build(mut self) -> Result<DaemonProviders, ProductionBootstrapError> {
        // User configuration may name an executable through PATH for setup
        // convenience, but the supervised process boundary accepts only an
        // exact absolute file. Resolve both copies before opening any Authority
        // store and reject drift between the Provider profile and runtime block.
        let codex_profile_index = self
            .provider_profiles
            .iter()
            .position(|profile| profile.admission == ProviderAdmission::Production)
            .ok_or(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_route_binding",
            ))?;
        let profile_executable =
            resolve_provider_executable(&self.provider_profiles[codex_profile_index].executable)
                .ok_or_else(|| {
                    ProductionBootstrapError::ProviderExecutableUnavailable(
                        self.provider_profiles[codex_profile_index]
                            .profile_id
                            .clone(),
                    )
                })?;
        let runtime_executable = resolve_provider_executable(&self.codex.codex_executable)
            .ok_or_else(|| {
                ProductionBootstrapError::ProviderExecutableUnavailable("codex.runtime".to_owned())
            })?;
        if profile_executable != runtime_executable {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_binding",
            ));
        }
        self.provider_profiles[codex_profile_index].executable = profile_executable;
        self.codex.codex_executable = runtime_executable;

        if let Some(material) = &self.repository_material {
            repository::validate_repository_claim_binding(
                &self.artifact_guard,
                &self.task_guard.acceptance_contract_ref,
                &self.codex.native.return_collector,
            )?;
            material
                .validate_acceptance_contract_ref(&self.task_guard.acceptance_contract_ref)
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration(
                        "repository frozen acceptance contract reference",
                    )
                })?;
        }

        if let Some(config) = &self.repository_verification {
            config.validate_model(&self.provider_profiles[codex_profile_index])?;
            if self.repository_material.is_none()
                || self.repository_command_artifacts.is_none()
                || self.verification_worker.is_some()
            {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "repository Verification composition",
                ));
            }
            config.validate(
                &self.artifact_guard,
                &self
                    .verification_references
                    .as_ref()
                    .ok_or(ProductionBootstrapError::InvalidConfiguration(
                        "verification.criteria",
                    ))?
                    .criteria,
            )?;
        }
        if let Some(config) = &self.founder_supporting_material {
            config.validate(&self.artifact_guard)?;
        }

        let context_database_path = self
            .memory
            .database_path
            .parent()
            .map(|parent| parent.join("context-authority.sqlite3"))
            .unwrap_or_else(|| PathBuf::from("context-authority.sqlite3"));
        let context = Arc::new(Mutex::new(
            ContextAuthority::open(ContextAuthorityConfig {
                database_path: context_database_path,
                store_epoch: format!("{}-context", self.memory.store_epoch),
                key: self.memory.key.duplicate_for_related_store(),
            })
            .map_err(|_| ProductionBootstrapError::ContextAuthority)?,
        ));
        let task_guard_config = self.task_guard;
        let task_guard = ConfiguredTaskCreationGuard::new(task_guard_config.clone())?
            .with_context_authority(Arc::clone(&context));
        let founder_verdict_handle = Arc::new(Mutex::new(None));
        let task = Arc::new(Mutex::new(TaskAuthority::open_with_transition_guard(
            self.task,
            task_guard,
            ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(
                &founder_verdict_handle,
            ))
            .with_context_authority(Arc::clone(&context)),
        )?));
        let memory = Arc::new(Mutex::new(MemoryAuthority::open(self.memory)?));

        let repository_material = self
            .repository_material
            .map(RepositoryMaterialConfig::validate)
            .transpose()
            .map_err(|_| ProductionBootstrapError::WorkPreparation)?;
        let artifact_guard = ConfiguredArtifactAdmissionGuard::new(self.artifact_guard)?;
        let derived_workspace_admission = artifact_guard.derived_workspace_admission_handle();
        let artifact = Arc::new(Mutex::new(ArtifactAuthority::open(
            self.artifact,
            artifact_guard,
        )?));

        let verification_resolver: Box<dyn VerificationReferenceResolver> = match self
            .verification_references
        {
            Some(config) => {
                let mut resolver = ArtifactBackedReferenceResolver::new(
                    ArtifactAuthorityReferenceSource::new_shared(Arc::clone(&artifact)),
                    config.criteria,
                )
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration("verification.criteria")
                })?;
                let output_collector = match &self.repository_verification {
                    Some(repository) => Some(repository.collector_principal_id().to_owned()),
                    None => self
                        .verification_worker
                        .as_ref()
                        .and_then(|worker| worker.checker_output_capture.as_ref())
                        .map(|capture| capture.collector_principal_id.clone()),
                };
                if let Some(collector) = output_collector {
                    resolver = resolver
                        .with_checker_output_collector(collector)
                        .map_err(|_| {
                            ProductionBootstrapError::InvalidConfiguration(
                                "Verification output collector",
                            )
                        })?;
                }
                Box::new(resolver)
            }
            None => Box::new(DenyVerificationReferences),
        };

        // Verification persists and projects only through its own Authority
        // boundary. The optional resolver above is still only an
        // Artifact-backed reference check; it does not attest a checker or
        // start Sego execution.
        let verification = Arc::new(Mutex::new(VerificationAuthority::open(
            self.verification,
            ComposedVerificationReferenceResolver {
                inner: verification_resolver,
            },
        )?));

        // The resolver declares which adapter's approvals it may resolve, and
        // the store it answers from binds that same identity, so both are read
        // from the admitted route instead of naming one provider's adapter.
        let policy_adapter_id = crate::production_harness_identity(
            self.provider_profiles
                .iter()
                .find(|profile| profile.admission == ProviderAdmission::Production)
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.production_harness_kind",
                ))?
                .harness,
        )
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.production_harness_kind",
        ))?
        .adapter_id
        .to_owned();
        let policy_edge = AdapterEdge::open(self.policy_resolver.edge)?;
        let policy_resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge: policy_edge,
            adapter_id: policy_adapter_id,
            authorization_policy_ref: self.policy_resolver.authorization_policy_ref,
            authentication_context_ref: self.policy_resolver.authentication_context_ref,
            allowed_scope_refs: self.policy_resolver.allowed_scope_refs,
            decision_ttl: self.policy_resolver.decision_ttl,
        })?;
        let policy = Arc::new(Mutex::new(PolicyDecisionAuthority::open(
            self.policy,
            crate::verdict_expiry::FounderExpiryPolicyResolver {
                approval: Box::new(policy_resolver),
                task: Arc::clone(&task),
                verdict: Arc::clone(&founder_verdict_handle),
                policy_ref: self.founder_authority_policy_ref.clone(),
            },
        )?));

        let founder_policy = self
            .founder_supporting_material
            .as_ref()
            .map(|config| {
                config.policy(
                    &self
                        .codex
                        .native
                        .return_collector
                        .artifact_authority_principal_id,
                )
            })
            .transpose()?;
        let founder_material_port = founder_policy
            .as_ref()
            .map(|policy| {
                let source =
                    crate::founder_material::OwnerBoundFounderSupportingMaterialSource::new(
                        Arc::clone(&task),
                        Arc::new(VerificationAuthorityArtifactSource::new_shared(Arc::clone(
                            &verification,
                        ))),
                        Arc::clone(&artifact),
                        self.allowed_founder_principal_ids.clone(),
                    )
                    .map_err(|_| {
                        ProductionBootstrapError::InvalidConfiguration(
                            "Founder material owner binding",
                        )
                    })?;
                crate::founder_material::GovernedFounderSupportingMaterialPort::new(
                    Arc::clone(&artifact),
                    Arc::new(source),
                    policy.clone(),
                    derived_workspace_admission.clone(),
                )
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration("Founder material intake")
                })
            })
            .transpose()?;
        let non_overridable_criterion_ids = self.non_overridable_criterion_ids;
        let mut founder_resolver =
            ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
                verification_source: Box::new(VerificationAuthorityArtifactSource::new_shared(
                    Arc::clone(&verification),
                )),
                task_commit_source: Box::new(TaskAuthorityCommitReceiptSource::new(Arc::clone(
                    &task,
                ))),
                allowed_founder_principal_ids: self.allowed_founder_principal_ids,
                authority_ref: self.founder_authority_ref,
                authority_policy_ref: self.founder_authority_policy_ref.clone(),
                allowed_confirmation_proof_refs: self.allowed_confirmation_proof_refs,
                non_overridable_gate_ids: self.non_overridable_gate_ids,
                confirmation_ttl: self.founder_confirmation_ttl,
            })?
            .with_non_overridable_criterion_ids(non_overridable_criterion_ids)?
            .with_expiry_source(
                crate::verdict_expiry::FounderVerdictExpiryProofSource {
                    policy: Arc::clone(&policy),
                    task: Arc::clone(&task),
                    policy_ref: self.founder_authority_policy_ref,
                },
            );
        if let Some(policy) = founder_policy {
            founder_resolver = founder_resolver.with_supporting_material_source(
                Box::new(
                    crate::founder_material::ArtifactAuthorityFounderSupportingMaterialSource::new(
                        Arc::clone(&artifact),
                    ),
                ),
                policy,
            )?;
        }
        let verdict = FounderVerdictAuthority::open(self.verdict, founder_resolver)?;
        *founder_verdict_handle
            .lock()
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verdict handle"))? =
            Some(verdict);

        let principal_resolver = Arc::new(ConfiguredAuthorityPrincipalResolver::new([
            self.authority_binding
        ])?);
        let memory_principal_resolver = Arc::clone(&principal_resolver);
        let context_principal_resolver = Arc::clone(&principal_resolver);
        let session_principal_resolver =
            Arc::new(AllowlistedPrincipalResolver::new([self.os_principal])?);
        let cross_authority_operation_gate = Arc::new(Mutex::new(()));
        let expiry_worker = crate::verdict_expiry::ExpiryRecoveringVerdictWorker {
            consumer: crate::ConfiguredFounderVerdictConsumeWorker::new_with_operation_gate(
                Arc::clone(&task),
                Arc::clone(&founder_verdict_handle),
                "task-authority:founder-verdict-consumer",
                Arc::clone(&cross_authority_operation_gate),
            )
            .map_err(|_| {
                ProductionBootstrapError::InvalidConfiguration("Founder Verdict recovery worker")
            })?,
            task: Arc::clone(&task),
            verdict: Arc::clone(&founder_verdict_handle),
            policy: Arc::clone(&policy),
            operation_gate: Arc::clone(&cross_authority_operation_gate),
        };
        let mut providers = DaemonProviders::from_shared_authority_handles(
            SharedAuthorityHandlesCompositionInputs {
                task: Arc::clone(&task),
                policy: Arc::clone(&policy),
                verdict: Arc::clone(&founder_verdict_handle),
                cross_authority_operation_gate: Arc::clone(&cross_authority_operation_gate),
                principal_resolver,
                session_principal_resolver,
                session_clock: Arc::new(SystemSessionClock),
                session_audit: Arc::new(NoopSessionAuditSink),
                additional_projection_sources: vec![
                    Arc::new(ArtifactProjectionSource::new_shared(Arc::clone(&artifact))),
                    Arc::new(VerificationProjectionSource::new_shared(Arc::clone(
                        &verification,
                    ))),
                ],
            },
        )
        .with_founder_verdict_consume_worker(Arc::new(expiry_worker))
        .with_context_authority(Arc::clone(&context))
        .with_context_mutation(Arc::new(ContextMutationPortAdapter::new(
            Arc::clone(&context),
            context_principal_resolver,
        )))
        .with_work_capability_port(self.work_capability_registry.clone());
        if let Some(port) = founder_material_port {
            providers = providers.with_founder_supporting_material_port(Arc::new(port));
        }
        if let Some(repository_material) = repository_material.as_ref() {
            let command_artifacts = self.repository_command_artifacts.clone().ok_or(
                ProductionBootstrapError::InvalidConfiguration(
                    "repository command Artifact policy",
                ),
            )?;
            providers = providers.with_repository_dispatch(
                repository_material.clone(),
                derived_workspace_admission.clone(),
                command_artifacts,
            );
        } else if self.repository_command_artifacts.is_some() {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "repository command Artifact policy without repository material",
            ));
        }
        if let Some(mut worker_config) = self.verification_worker {
            if let Some(capture) = worker_config.checker_output_capture.clone() {
                let sink = crate::ConfiguredCheckerOutputSink::new(
                    Arc::clone(&artifact),
                    Arc::clone(&verification),
                    derived_workspace_admission.clone(),
                    capture,
                )
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration(
                        "verification_worker.checker_output_capture",
                    )
                })?;
                worker_config.checker_output_sink =
                    Some(Arc::new(sink)
                        as Arc<
                            dyn egopulse_verification_authority::CheckerOutputSink,
                        >);
            }
            let deployment = worker_config
                .checker_profile_deployment
                .clone()
                .map(|config| {
                    crate::ConfiguredCheckerProfileDeployment::new(Arc::clone(&artifact), config)
                })
                .transpose()
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration(
                        "verification_worker.checker_profile_deployment",
                    )
                })?;
            let worker = ConfiguredVerificationWorker::new(
                Arc::clone(&task),
                Box::new(ArtifactAuthorityReferenceSource::new_shared(Arc::clone(
                    &artifact,
                ))),
                Arc::clone(&verification),
                worker_config,
                deployment,
            )
            .map_err(ProductionBootstrapError::VerificationWorker)?;
            providers = providers.with_verification_worker(Arc::new(worker));
        }
        if let Some(config) = self.repository_verification {
            let commands = self.repository_command_artifacts.as_ref().ok_or(
                ProductionBootstrapError::InvalidConfiguration(
                    "repository command Artifact policy",
                ),
            )?;
            let worker = config.compose(
                repository::RepositoryVerificationOwners {
                    context: Arc::clone(&context),
                    task: Arc::clone(&task),
                    artifact: Arc::clone(&artifact),
                    verification: Arc::clone(&verification),
                    admission: derived_workspace_admission.clone(),
                },
                &self.codex,
                commands,
            )?;
            providers = providers.with_verification_worker(Arc::new(worker));
        }
        if let Some(memory_retrieval) = self.memory_retrieval {
            providers = providers.with_memory_retrieval(Arc::clone(&memory), memory_retrieval)?;
        }
        providers = providers.with_memory_mutation(Arc::clone(&memory), memory_principal_resolver);
        let intent_defaults = only_configured_value(&task_guard_config.allowed_work_types).zip(
            only_configured_value(&task_guard_config.allowed_target_scope_refs),
        );
        let rework_coordinator = if let Some(material) = repository_material.as_ref() {
            let native = &self.codex.native;
            let collector = &native.return_collector;
            let repository = Arc::new(
                crate::repository_dispatch::RepositoryDispatchCoordinator::new(
                    Arc::clone(&context),
                    Arc::clone(&artifact),
                    derived_workspace_admission.clone(),
                    material.clone(),
                    native.workspace_root.clone(),
                    crate::repository_dispatch::RepositoryDispatchArtifactPolicy {
                        artifact_type_ref: collector.artifact_type_ref.clone(),
                        transformation_contract_ref: collector.transformation_contract_ref.clone(),
                        retention_profile_ref: collector.retention_profile_ref.clone(),
                        artifact_authority_principal_id: collector
                            .artifact_authority_principal_id
                            .clone(),
                        attempt_supervisor_principal_id: native
                            .workflow
                            .attempt_supervisor_principal_id
                            .clone(),
                        evidence_profile_ref: collector.evidence_profile_ref.clone(),
                    },
                )
                .map_err(ProductionBootstrapError::InvalidConfiguration)?,
            );
            if let Some(composition) = providers.repository_dispatch.as_mut() {
                composition.coordinator = Some(Arc::clone(&repository));
            }
            let resolver = crate::rework_preparation::ReworkPreparationResolver::new(
                Arc::clone(&task),
                Arc::clone(&founder_verdict_handle),
                Arc::new(
                    crate::founder_material::ArtifactAuthorityFounderSupportingMaterialSource::new(
                        Arc::clone(&artifact),
                    ),
                ),
                repository,
            );
            Some(Arc::new(
                crate::rework_preparation::ReworkPreparationCoordinator::new(
                    Arc::clone(&context),
                    Arc::clone(&providers.task_port),
                    resolver,
                    task_guard_config.budget_profile_ref.clone(),
                )
                .map_err(|_| ProductionBootstrapError::WorkPreparation)?
                .with_input_bundle_root(native.input_bundle_root.clone())
                .map_err(|_| ProductionBootstrapError::WorkPreparation)?
                .with_work_capability_registry(Arc::clone(&self.work_capability_registry)),
            ))
        } else {
            None
        };
        let mut work_port = ConfiguredWorkPreparationPort::new(
            Arc::clone(&context),
            Arc::clone(&providers.task_port),
            Arc::clone(&providers.work_memory_retrieval_port),
            self.codex.native.workspace_root.clone(),
            task_guard_config.allowed_work_types,
            task_guard_config.acceptance_contract_ref,
            task_guard_config.budget_profile_ref,
        )
        .and_then(|port| port.with_input_bundle_root(self.codex.native.input_bundle_root.clone()))
        .and_then(|port| port.with_activation_run_id(self.codex.native.workflow.run_id.clone()))
        .map(|port| port.with_work_capability_registry(Arc::clone(&self.work_capability_registry)))
        .map_err(|_| ProductionBootstrapError::WorkPreparation)?;
        if let Some(coordinator) = rework_coordinator {
            work_port = work_port.with_rework_preparation(coordinator);
        }
        if let Some((_work_type, target_scope_ref)) = intent_defaults {
            work_port = work_port
                .with_intent_interpreter(
                    {
                        use crate::intent_interpretation::IntentDriverConfig;
                        let production = self
                            .provider_profiles
                            .iter()
                            .find(|profile| profile.admission == ProviderAdmission::Production)
                            .ok_or(ProductionBootstrapError::WorkPreparation)?;
                        match production.harness {
                            ProviderHarnessKind::CodexAppServer => {
                                IntentDriverConfig::Codex(self.codex.app_server_config())
                            }
                            ProviderHarnessKind::OpenCodeAcp
                                if production.catalog_snapshot.as_ref().is_some_and(
                                    |snapshot| snapshot.harness_version == "1.18.31",
                                ) =>
                            {
                                let mut config = egopulse_opencode_adapter::OpenCodeAcpConfig::new(
                                    production.executable.clone(),
                                    self.codex.native.workspace_root.clone(),
                                    production.exact_model.clone(),
                                );
                                config.environment_overrides =
                                    self.codex.environment_overrides.clone();
                                IntentDriverConfig::OpenCode(config)
                            }
                            _ => IntentDriverConfig::Unsupported,
                        }
                    },
                    self.provider_profiles
                        .iter()
                        .find(|profile| profile.admission == ProviderAdmission::Production)
                        .ok_or(ProductionBootstrapError::WorkPreparation)?
                        .profile_id
                        .clone(),
                    self.provider_profiles
                        .iter()
                        .find(|profile| profile.admission == ProviderAdmission::Production)
                        .ok_or(ProductionBootstrapError::WorkPreparation)?
                        .harness,
                    target_scope_ref,
                )
                .map_err(|_| ProductionBootstrapError::WorkPreparation)?;
        }
        if let Some(repository_material) = repository_material {
            work_port = work_port
                .with_repository_material(repository_material)
                .map_err(|_| ProductionBootstrapError::WorkPreparation)?;
        }
        providers = providers.with_work_preparation_port(Arc::new(work_port));
        if !self.memory_candidate_producers.is_empty() {
            providers = providers.with_memory_candidate_producers(
                Arc::clone(&memory),
                self.memory_candidate_producers,
            )?;
        }
        let production_provider_profile = self
            .provider_profiles
            .iter()
            .find(|profile| profile.admission == ProviderAdmission::Production)
            .cloned()
            .ok_or(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_route_binding",
            ))?;
        providers = providers.with_codex_harness(
            self.codex,
            production_provider_profile,
            artifact,
            verification,
        )?;
        // The production dispatch cycle settles committed collaboration
        // recovery facts (run cancelled / harness outcome unknown) into the
        // Task Authority through the existing single-writer path.
        providers = providers.with_task_recovery_settlement(Arc::clone(&task))?;
        Ok(providers)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOwnedBootstrapFile {
    schema_version: String,
    stores: StoreFiles,
    identity: IdentityFile,
    task_guard: TaskGuardFile,
    #[serde(default)]
    repository_material: Option<RepositoryMaterialFile>,
    artifact: ArtifactPolicyFile,
    #[serde(default)]
    verification: Option<VerificationFile>,
    #[serde(default)]
    verification_worker: Option<VerificationWorkerFile>,
    #[serde(default)]
    repository_verification: Option<RepositoryVerificationConfig>,
    #[serde(default)]
    founder_supporting_material: Option<FounderSupportingMaterialConfig>,
    #[serde(default)]
    memory_retrieval: Option<MemoryRetrievalFile>,
    #[serde(default)]
    memory_candidate_producers: Vec<MemoryCandidateProducerFile>,
    policy: PolicyFile,
    founder: FounderFile,
    #[serde(default)]
    provider_profiles: Vec<ProviderProfileFile>,
    #[serde(default)]
    work_capabilities: Option<WorkCapabilitiesFile>,
    codex: CodexFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkCapabilitiesFile {
    preference_revision: u64,
    default_choice_id: String,
    routes: Vec<WorkCapabilityRouteFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkCapabilityRouteFile {
    choice_id: String,
    route_id: String,
    route_generation: u64,
    provider_profile_id: String,
    provider_id: String,
    harness_id: String,
    harness_model_id: String,
    provider_model_id: String,
    capability_profile_ref: ReferenceFile,
    #[serde(default)]
    catalog_snapshot_sha256: Option<String>,
    native_composition_generation: String,
    route_binding_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderProfileFile {
    profile_id: String,
    provider: String,
    harness: String,
    admission: String,
    #[serde(default)]
    exact_model: Option<String>,
    #[serde(default)]
    model_ids: Vec<String>,
    #[serde(default)]
    models: Vec<ProviderModelFile>,
    #[serde(default)]
    catalog_snapshot: Option<ProviderCatalogSnapshotFile>,
    #[serde(default)]
    selected_model: Option<String>,
    executable: String,
    credential: ProviderCredentialFile,
    #[serde(default)]
    hold_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderModelFile {
    harness_model_id: String,
    provider_model_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCatalogSnapshotFile {
    source: String,
    fetched_at: String,
    harness_version: String,
    evidence_digest_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum ProviderCredentialFile {
    HarnessAccount,
    ApiKeyEnvironment {
        source_env: String,
        target_env: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFiles {
    task: StoreFile,
    memory: StoreFile,
    artifact: ArtifactStoreFile,
    verification: StoreFile,
    policy: StoreFile,
    verdict: StoreFile,
    adapter: StoreFile,
    collaboration: StoreFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactStoreFile {
    database_path: String,
    blob_root: String,
    store_epoch: String,
    key_env: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    database_path: String,
    store_epoch: String,
    key_env: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    os_fingerprint_hex: String,
    principal_id: String,
    permission_codes: Vec<String>,
    authorization_policy_ref: ReferenceFile,
    task_kind: String,
    policy_kind: String,
    verdict_kind: String,
    #[serde(default)]
    memory_kind: Option<String>,
    #[serde(default)]
    context_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskGuardFile {
    allowed_work_types: Vec<String>,
    allowed_input_snapshot_ids: Vec<String>,
    allowed_target_scope_refs: Vec<String>,
    acceptance_contract_ref: ReferenceFile,
    budget_profile_ref: ReferenceFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryMaterialFile {
    acceptance_contract_path: String,
    repository_root: String,
    git_executable: String,
    artifact_type_ref: ReferenceFile,
    transformation_contract_ref: ReferenceFile,
    retention_profile_ref: ReferenceFile,
    evidence_profile_ref: ReferenceFile,
    claim_semantic_profile_ref: ReferenceFile,
    command_intent_type_ref: ReferenceFile,
    command_intent_transformation_ref: ReferenceFile,
    command_receipt_type_ref: ReferenceFile,
    command_receipt_transformation_ref: ReferenceFile,
}

struct RepositoryArtifactSelection {
    artifact_type_ref: ContractReference,
    transformation_contract_ref: ContractReference,
    retention_profile_ref: ContractReference,
    evidence_profile_ref: ContractReference,
    claim_semantic_profile_ref: ContractReference,
    command_intent_type_ref: ContractReference,
    command_intent_transformation_ref: ContractReference,
    command_receipt_type_ref: ContractReference,
    command_receipt_transformation_ref: ContractReference,
}

#[derive(Clone, Debug)]
pub struct RepositoryCommandArtifactPolicyConfig {
    pub intent_type_ref: ContractReference,
    pub intent_transformation_ref: ContractReference,
    pub receipt_type_ref: ContractReference,
    pub receipt_transformation_ref: ContractReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPolicyFile {
    allowed_workspace_refs: Vec<String>,
    allowed_artifact_type_refs: Vec<ReferenceFile>,
    allowed_transformation_contract_refs: Vec<ReferenceFile>,
    allowed_retention_profile_refs: Vec<ReferenceFile>,
    allowed_claim_semantic_profile_refs: Vec<ReferenceFile>,
    allowed_claim_acceptance_contract_refs: Vec<ReferenceFile>,
    allowed_evidence_profile_refs: Vec<ReferenceFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationFile {
    criteria: Vec<CriterionFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CriterionFile {
    criterion_id: String,
    requirement: i32,
    minimum_assurance: i32,
    not_applicable_allowed: bool,
    checker_profile_ids: Vec<String>,
}

/// Explicit user-owned configuration for the daemon's Verification worker.
/// Every field that affects execution is part of the reviewed file; no value
/// is inferred from a Task payload, checker output, or model response.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationWorkerFile {
    handoff: VerificationWorkerHandoffFile,
    checker_profile: CheckerProfileFile,
    /// Present when this environment must deploy the declared checker profile
    /// itself, because no repository workflow owns one here.
    #[serde(default)]
    checker_profile_deployment: Option<CheckerProfileDeploymentFile>,
    checker_executable: String,
    #[serde(default)]
    checker_arguments: Vec<String>,
    working_directory: String,
    checker_request_hex: String,
    mapper: SegoMapperFile,
    verification_run_id_prefix: String,
    verification_artifact_id_prefix: String,
    execution_id_prefix: String,
    #[serde(default)]
    tool_receipt_artifact_ids: Vec<String>,
    #[serde(default)]
    model_call_receipt_artifact_ids: Vec<String>,
    checker_timeout_ms: u64,
    checker_output_limit: u64,
    /// `stdout` (default) or `envelope_artifact_path` for a sidecar whose
    /// stdout answers with an envelope naming the review artifact file.
    #[serde(default)]
    checker_output_source: Option<String>,
    /// Present when this environment seals the checker's own output, so a
    /// Verification result cites the bytes the checker produced.
    #[serde(default)]
    checker_output_capture: Option<CheckerOutputCaptureFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerOutputCaptureFile {
    raw_output_type_ref: ReferenceFile,
    retention_profile_ref: ReferenceFile,
    collector_principal_id: String,
    artifact_authority_principal_id: String,
    max_output_bytes: u64,
}

impl CheckerOutputCaptureFile {
    fn into_typed(self) -> Result<crate::CheckerOutputCaptureConfig, ProductionBootstrapError> {
        let max_output_bytes = usize::try_from(self.max_output_bytes).map_err(|_| {
            ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_output_capture.max_output_bytes",
            )
        })?;
        Ok(crate::CheckerOutputCaptureConfig {
            raw_output_type_ref: self.raw_output_type_ref.into_typed(),
            retention_profile_ref: self.retention_profile_ref.into_typed(),
            collector_principal_id: required(
                self.collector_principal_id,
                "verification_worker.checker_output_capture.collector_principal_id",
            )?,
            artifact_authority_principal_id: required(
                self.artifact_authority_principal_id,
                "verification_worker.checker_output_capture.artifact_authority_principal_id",
            )?,
            max_output_bytes,
        })
    }
}

/// Explicit user-owned execution and principal-to-scope policy for the
/// read-only Memory retrieval Worker. Absence leaves the Local Cognition
/// service registered but fail-closed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryRetrievalFile {
    worker_executable: String,
    #[serde(default)]
    worker_arguments: Vec<String>,
    working_directory: String,
    #[serde(default)]
    inherited_environment: Vec<String>,
    #[serde(default)]
    environment_overrides: BTreeMap<String, String>,
    timeout_ms: u64,
    output_limit_bytes: u64,
    principal_scope_allowlist: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryCandidateProducerFile {
    producer_id: String,
    principal_id: String,
    principal_kind: String,
    scope_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationWorkerHandoffFile {
    claim_id: String,
    claim_semantic_profile_ref: ReferenceFile,
    criterion_ids: Vec<String>,
    checker_profile_refs: Vec<ReferenceFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerProfileFile {
    checker_profile_id: String,
    revision: u64,
    status: i32,
    checker_id: String,
    checker_version: String,
    input_contract_ref: Option<ReferenceFile>,
    output_contract_ref: Option<ReferenceFile>,
    supported_criterion_types: Vec<String>,
    assurance_class: i32,
    sandbox_profile_ref: Option<ReferenceFile>,
    tool_policy_ref: Option<ReferenceFile>,
    data_egress_policy_ref: Option<ReferenceFile>,
    timeout_ms: u64,
    network_allowed: bool,
    profile_digest_sha256: String,
    attestation_evidence_artifact_ids: Vec<String>,
    attested_at: Option<TimestampFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimestampFile {
    seconds: i64,
    nanos: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegoMapperFile {
    criterion_id: String,
    requirement: i32,
    checker_profile_ref: ReferenceFile,
    #[serde(default = "default_mapper_contract_id")]
    contract_id: String,
    #[serde(default = "default_mapper_contract_revision")]
    contract_revision: u64,
    expected_scope: String,
    expected_diff_hash: String,
    expected_reviewer: String,
    expected_engine_version: String,
    expected_review_mode: String,
    #[serde(default)]
    positive_acceptance: bool,
    failure_threshold: i32,
    raw_output_artifact_id: String,
    raw_output_address: ContentAddressFile,
    #[serde(default)]
    finding_evidence: std::collections::BTreeMap<String, FindingEvidenceFile>,
}

fn default_mapper_contract_id() -> String {
    SEGO_REVIEW_ARTIFACT_CONTRACT_ID.to_owned()
}

fn default_mapper_contract_revision() -> u64 {
    SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentAddressFile {
    algorithm: i32,
    digest: String,
    byte_length: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingEvidenceFile {
    evidence_id: String,
    description_artifact_id: String,
    suggested_fix_artifact_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    authentication_context_ref: String,
    authorization_policy_ref: ReferenceFile,
    allowed_scope_refs: Vec<String>,
    decision_ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FounderFile {
    allowed_founder_principal_ids: Vec<String>,
    authority_ref: String,
    authority_policy_ref: ReferenceFile,
    allowed_confirmation_proof_refs: Vec<String>,
    non_overridable_gate_ids: Vec<String>,
    #[serde(default)]
    non_overridable_criterion_ids: Vec<String>,
    confirmation_ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodexFile {
    input_bundle_root: String,
    workspace_root: String,
    codex_executable: String,
    #[serde(default)]
    default_model: Option<String>,
    lease_ttl_seconds: u64,
    workflow: WorkflowFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowFile {
    run_id: String,
    attempt_id: String,
    dispatch_id: String,
    harness_id: String,
    capability_profile_ref: ReferenceFile,
    workspace_ref: String,
    lease_policy_ref: ReferenceFile,
    owner_instance_id: String,
    task_authority_principal_id: String,
    collaboration_principal_id: String,
    attempt_supervisor_principal_id: String,
    harness_adapter_principal_id: String,
    plan: PlanFile,
    material: MaterialFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFile {
    plan_id: String,
    digest_sha256: String,
    max_active_attempts: u32,
    step: StepFile,
    budget_profile_ref: Option<ReferenceFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepFile {
    step_id: String,
    step_kind: String,
    depends_on_step_ids: Vec<String>,
    input_bundle_ref: String,
    expected_output_contract_ref: Option<ReferenceFile>,
    required_capability_profile_ref: Option<ReferenceFile>,
    max_attempts: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialFile {
    input_bundle_sha256: String,
    sandbox_profile_ref: ReferenceFile,
    tool_policy_ref: ReferenceFile,
    data_egress_policy_ref: ReferenceFile,
    approval_policy_ref: ReferenceFile,
    session_strategy: String,
    native_session_ref: Option<String>,
    checkpoint_ref: Option<String>,
    evidence_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFile {
    contract_id: String,
    version: String,
    sha256: String,
}

impl WorkCapabilitiesFile {
    fn into_typed(
        self,
        production_profile: &ProviderBootstrapProfile,
        codex: &CodexHarnessCompositionConfig,
    ) -> Result<(WorkCapabilityRouteBinding, String, u64), ProductionBootstrapError> {
        if self.preference_revision == 0 || self.routes.len() != 1 {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "work_capabilities initial single-route state",
            ));
        }
        let default_choice_id = required(
            self.default_choice_id,
            "work_capabilities.default_choice_id",
        )?;
        let route_file = self.routes.into_iter().next().ok_or(
            ProductionBootstrapError::InvalidConfiguration("work_capabilities.routes"),
        )?;
        let (choice_id, route) = route_file.into_typed()?;
        if choice_id != default_choice_id {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "work_capabilities.default_choice_id",
            ));
        }
        validate_codex_route_runtime_binding(&route, production_profile, codex)?;
        Ok((route, default_choice_id, self.preference_revision))
    }
}

impl WorkCapabilityRouteFile {
    fn into_typed(self) -> Result<(String, WorkCapabilityRouteBinding), ProductionBootstrapError> {
        let choice_id = required(self.choice_id, "work_capabilities.routes.choice_id")?;
        let route = WorkCapabilityRouteBinding {
            route_id: required(self.route_id, "work_capabilities.routes.route_id")?,
            route_generation: self.route_generation,
            provider_profile_id: required(
                self.provider_profile_id,
                "work_capabilities.routes.provider_profile_id",
            )?,
            provider_id: required(self.provider_id, "work_capabilities.routes.provider_id")?,
            harness_id: required(self.harness_id, "work_capabilities.routes.harness_id")?,
            harness_model_id: required(
                self.harness_model_id,
                "work_capabilities.routes.harness_model_id",
            )?,
            provider_model_id: required(
                self.provider_model_id,
                "work_capabilities.routes.provider_model_id",
            )?,
            capability_profile_ref: Some(self.capability_profile_ref.into_typed()),
            catalog_snapshot_sha256: self.catalog_snapshot_sha256,
            native_composition_generation: required(
                self.native_composition_generation,
                "work_capabilities.routes.native_composition_generation",
            )?,
            route_binding_sha256: required(
                self.route_binding_sha256,
                "work_capabilities.routes.route_binding_sha256",
            )?,
        };
        let route = seal_work_capability_route_binding(route).map_err(|_| {
            ProductionBootstrapError::InvalidConfiguration("work_capabilities.routes.route_binding")
        })?;
        Ok((choice_id, route))
    }
}

fn compatibility_codex_route(
    profile: &ProviderBootstrapProfile,
    codex: &CodexHarnessCompositionConfig,
) -> Result<WorkCapabilityRouteBinding, ProductionBootstrapError> {
    let route = compatibility_codex_route_from_parts(
        profile,
        codex.native.workflow.capability_profile_ref.clone(),
        codex.native.workflow.run_id.clone(),
    )?;
    validate_codex_route_runtime_binding(&route, profile, codex)?;
    Ok(route)
}

fn compatibility_codex_route_from_parts(
    profile: &ProviderBootstrapProfile,
    capability_profile_ref: ContractReference,
    native_composition_generation: String,
) -> Result<WorkCapabilityRouteBinding, ProductionBootstrapError> {
    let model = profile
        .models
        .iter()
        .find(|model| model.harness_model_id == profile.exact_model)
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.production_codex_model",
        ))?;
    let route = seal_work_capability_route_binding(WorkCapabilityRouteBinding {
        route_id: "route:compat-codex:v1".to_owned(),
        route_generation: 1,
        provider_profile_id: profile.profile_id.clone(),
        provider_id: profile.provider.as_str().to_owned(),
        harness_id: profile.harness.as_str().to_owned(),
        harness_model_id: model.harness_model_id.clone(),
        provider_model_id: model.provider_model_id.clone(),
        capability_profile_ref: Some(capability_profile_ref),
        catalog_snapshot_sha256: profile
            .catalog_snapshot
            .as_ref()
            .map(|snapshot| snapshot.evidence_digest_sha256.clone()),
        native_composition_generation,
        route_binding_sha256: String::new(),
    })
    .map_err(|_| {
        ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.production_codex_route_binding",
        )
    })?;
    Ok(route)
}

fn validate_codex_route_runtime_binding(
    route: &WorkCapabilityRouteBinding,
    profile: &ProviderBootstrapProfile,
    codex: &CodexHarnessCompositionConfig,
) -> Result<(), ProductionBootstrapError> {
    let model = profile
        .models
        .iter()
        .find(|model| model.harness_model_id == profile.exact_model)
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.production_codex_model",
        ))?;
    let catalog_snapshot_sha256 = profile
        .catalog_snapshot
        .as_ref()
        .map(|snapshot| snapshot.evidence_digest_sha256.as_str());
    if route.provider_profile_id != profile.profile_id
        || route.provider_id != profile.provider.as_str()
        || route.harness_id != profile.harness.as_str()
        || route.harness_model_id != model.harness_model_id
        || route.provider_model_id != model.provider_model_id
        || route.capability_profile_ref.as_ref()
            != Some(&codex.native.workflow.capability_profile_ref)
        || route.catalog_snapshot_sha256.as_deref() != catalog_snapshot_sha256
        || route.native_composition_generation != codex.native.workflow.run_id
    {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "work_capabilities.routes.runtime_binding",
        ));
    }
    Ok(())
}

/// Previews the additive v2 -> v3 work-capability configuration transition.
/// No file is opened for writing and no secret environment variable is read.
pub fn preview_work_capability_config_migration(
    path: impl AsRef<Path>,
) -> Result<WorkCapabilityConfigTransitionReport, ProductionBootstrapError> {
    let path = path.as_ref();
    let original = read_transition_config(path)?;
    render_v3_migration(path, &original).map(|(report, _)| report)
}

/// Applies exactly the previously previewable v2 -> v3 transition under the
/// daemon configuration lock. Startup never calls this function.
pub fn apply_work_capability_config_migration(
    path: impl AsRef<Path>,
) -> Result<WorkCapabilityConfigTransitionReport, ProductionBootstrapError> {
    let path = path.as_ref();
    let original = read_transition_config(path)?;
    let (mut report, replacement) = render_v3_migration(path, &original)?;
    persist_explicit_config_transition(path, &original, &replacement, V2_MIGRATION_BACKUP_SUFFIX)
        .map_err(transition_persistence_error)?;
    report.applied = true;
    Ok(report)
}

/// Previews a rollback only when the current v3 file is the exact semantic
/// result of migrating its retained v2 backup. Any later route/default/config
/// edit makes rollback fail closed.
pub fn preview_work_capability_config_rollback(
    path: impl AsRef<Path>,
) -> Result<WorkCapabilityConfigTransitionReport, ProductionBootstrapError> {
    let path = path.as_ref();
    let current = read_transition_config(path)?;
    render_v2_rollback(path, &current).map(|(report, _)| report)
}

/// Restores the retained complete v2 file and preserves the current v3 file
/// as a separate rollback backup. Authority stores are not touched.
pub fn rollback_work_capability_config_to_v2(
    path: impl AsRef<Path>,
) -> Result<WorkCapabilityConfigTransitionReport, ProductionBootstrapError> {
    let path = path.as_ref();
    let current = read_transition_config(path)?;
    let (mut report, replacement) = render_v2_rollback(path, &current)?;
    persist_explicit_config_transition(path, &current, &replacement, V3_ROLLBACK_BACKUP_SUFFIX)
        .map_err(transition_persistence_error)?;
    report.applied = true;
    Ok(report)
}

fn render_v3_migration(
    path: &Path,
    original: &[u8],
) -> Result<(WorkCapabilityConfigTransitionReport, Vec<u8>), ProductionBootstrapError> {
    let file: UserOwnedBootstrapFile = serde_json::from_slice(original).map_err(|source| {
        ProductionBootstrapError::ConfigurationFormat {
            path: path.display().to_string(),
            source,
        }
    })?;
    let UserOwnedBootstrapFile {
        schema_version,
        provider_profiles,
        work_capabilities,
        codex,
        ..
    } = file;
    if schema_version != PRODUCTION_BOOTSTRAP_V2 || work_capabilities.is_some() {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "configuration migration requires an unmigrated v2 file",
        ));
    }

    let provider_profiles = provider_profiles
        .into_iter()
        .map(ProviderProfileFile::into_typed)
        .collect::<Result<Vec<_>, _>>()?;
    validate_provider_profiles(&provider_profiles)?;
    let production_profiles = provider_profiles
        .iter()
        .filter(|profile| profile.admission == ProviderAdmission::Production)
        .collect::<Vec<_>>();
    let [production_profile] = production_profiles.as_slice() else {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "configuration migration requires exactly one production profile",
        ));
    };

    let CodexFile {
        codex_executable,
        default_model,
        workflow,
        ..
    } = codex;
    let default_model = required(default_model.unwrap_or_default(), "codex.default_model")?;
    let codex_executable = required(codex_executable, "codex.codex_executable")?;
    if default_model != production_profile.exact_model
        || Path::new(&codex_executable) != production_profile.executable.as_path()
    {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.production_codex_binding",
        ));
    }
    let WorkflowFile {
        run_id,
        capability_profile_ref,
        ..
    } = workflow;
    let route = compatibility_codex_route_from_parts(
        production_profile,
        capability_profile_ref.into_typed(),
        required(run_id, "codex.workflow.run_id")?,
    )?;
    let choice_id = format!("compat-codex:{}", &route.route_binding_sha256[..16]);

    let mut document: serde_json::Value = serde_json::from_slice(original).map_err(|source| {
        ProductionBootstrapError::ConfigurationFormat {
            path: path.display().to_string(),
            source,
        }
    })?;
    let root = document
        .as_object_mut()
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "configuration document root",
        ))?;
    root.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(PRODUCTION_BOOTSTRAP_V3.to_owned()),
    );
    let profile_ref = route.capability_profile_ref.as_ref().ok_or(
        ProductionBootstrapError::InvalidConfiguration("work-capability route capability profile"),
    )?;
    root.insert(
        "work_capabilities".to_owned(),
        serde_json::json!({
            "preference_revision": 1,
            "default_choice_id": choice_id,
            "routes": [{
                "choice_id": choice_id,
                "route_id": route.route_id,
                "route_generation": route.route_generation,
                "provider_profile_id": route.provider_profile_id,
                "provider_id": route.provider_id,
                "harness_id": route.harness_id,
                "harness_model_id": route.harness_model_id,
                "provider_model_id": route.provider_model_id,
                "capability_profile_ref": {
                    "contract_id": profile_ref.contract_id,
                    "version": profile_ref.version,
                    "sha256": profile_ref.sha256,
                },
                "catalog_snapshot_sha256": route.catalog_snapshot_sha256,
                "native_composition_generation": route.native_composition_generation,
                "route_binding_sha256": route.route_binding_sha256,
            }]
        }),
    );
    let mut replacement = serde_json::to_vec_pretty(&document).map_err(|_| {
        ProductionBootstrapError::InvalidConfiguration("configuration migration serialization")
    })?;
    replacement.push(b'\n');
    if replacement.len() > MAX_MIGRATION_CONFIG_BYTES {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "configuration file exceeds migration size limit",
        ));
    }

    let route = document["work_capabilities"]["routes"][0]
        .as_object()
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "work-capability migration route",
        ))?;
    let string_field = |name: &str| {
        route
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(ProductionBootstrapError::InvalidConfiguration(
                "work-capability migration route field",
            ))
    };
    Ok((
        WorkCapabilityConfigTransitionReport {
            transition: "migrate_v2_to_v3".to_owned(),
            applied: false,
            from_schema_version: PRODUCTION_BOOTSTRAP_V2.to_owned(),
            to_schema_version: PRODUCTION_BOOTSTRAP_V3.to_owned(),
            config_path: path.display().to_string(),
            retained_backup_path: transition_backup_path(path, V2_MIGRATION_BACKUP_SUFFIX)?
                .display()
                .to_string(),
            choice_id,
            provider_profile_id: string_field("provider_profile_id")?,
            provider_id: string_field("provider_id")?,
            harness_id: string_field("harness_id")?,
            harness_model_id: string_field("harness_model_id")?,
            provider_model_id: string_field("provider_model_id")?,
            route_binding_sha256: string_field("route_binding_sha256")?,
            preference_revision: 1,
        },
        replacement,
    ))
}

fn render_v2_rollback(
    path: &Path,
    current: &[u8],
) -> Result<(WorkCapabilityConfigTransitionReport, Vec<u8>), ProductionBootstrapError> {
    let v2_backup_path = transition_backup_path(path, V2_MIGRATION_BACKUP_SUFFIX)?;
    let v2_backup = read_transition_config(&v2_backup_path)?;
    let (migrated_report, expected_v3) = render_v3_migration(path, &v2_backup)?;
    let current_value: serde_json::Value = serde_json::from_slice(current).map_err(|source| {
        ProductionBootstrapError::ConfigurationFormat {
            path: path.display().to_string(),
            source,
        }
    })?;
    let expected_value: serde_json::Value =
        serde_json::from_slice(&expected_v3).map_err(|source| {
            ProductionBootstrapError::ConfigurationFormat {
                path: path.display().to_string(),
                source,
            }
        })?;
    if current_value != expected_value {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "rollback requires the unchanged initial v3 migration state",
        ));
    }

    Ok((
        WorkCapabilityConfigTransitionReport {
            transition: "rollback_v3_to_v2".to_owned(),
            applied: false,
            from_schema_version: PRODUCTION_BOOTSTRAP_V3.to_owned(),
            to_schema_version: PRODUCTION_BOOTSTRAP_V2.to_owned(),
            retained_backup_path: transition_backup_path(path, V3_ROLLBACK_BACKUP_SUFFIX)?
                .display()
                .to_string(),
            ..migrated_report
        },
        v2_backup,
    ))
}

fn read_transition_config(path: &Path) -> Result<Vec<u8>, ProductionBootstrapError> {
    let bytes = fs::read(path).map_err(|source| ProductionBootstrapError::ConfigurationFile {
        path: path.display().to_string(),
        source,
    })?;
    if bytes.len() > MAX_MIGRATION_CONFIG_BYTES {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "configuration file exceeds migration size limit",
        ));
    }
    Ok(bytes)
}

fn transition_backup_path(path: &Path, suffix: &str) -> Result<PathBuf, ProductionBootstrapError> {
    let mut file_name = path
        .file_name()
        .ok_or(ProductionBootstrapError::InvalidConfiguration(
            "configuration file path",
        ))?
        .to_os_string();
    file_name.push(suffix);
    Ok(path.with_file_name(file_name))
}

fn transition_persistence_error(
    failure: egopulse_local_api::command_gateway::WorkCapabilityPortFailure,
) -> ProductionBootstrapError {
    match failure {
        egopulse_local_api::command_gateway::WorkCapabilityPortFailure::StateRevisionConflict => {
            ProductionBootstrapError::ConfigurationTransitionConflict
        }
        _ => ProductionBootstrapError::ConfigurationTransition,
    }
}

impl ProviderProfileFile {
    fn into_typed(self) -> Result<ProviderBootstrapProfile, ProductionBootstrapError> {
        let profile_id = required(self.profile_id, "provider_profiles.profile_id")?;
        let provider = match self.provider.as_str() {
            "gpt" => ProviderId::Gpt,
            "deepseek" => ProviderId::DeepSeek,
            "kimi" => ProviderId::Kimi,
            "glm" => ProviderId::Glm,
            _ => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.provider",
                ));
            }
        };
        // Provider and Harness are independent route identities. Parsing a
        // known pair proves only that configuration can represent it;
        // production eligibility is enforced separately by admission.
        let harness = match self.harness.as_str() {
            "codex_app_server" => ProviderHarnessKind::CodexAppServer,
            "dsh_acp" => ProviderHarnessKind::DshAcp,
            "kimi_cli_acp" => ProviderHarnessKind::KimiCliAcp,
            "opencode_acp" => ProviderHarnessKind::OpenCodeAcp,
            _ => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.harness",
                ));
            }
        };
        let admission = match self.admission.as_str() {
            "production" => ProviderAdmission::Production,
            "candidate" => ProviderAdmission::Candidate,
            "held" => ProviderAdmission::Held,
            _ => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.admission",
                ));
            }
        };
        if !self.model_ids.is_empty() && !self.models.is_empty() {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.models_and_legacy_model_ids",
            ));
        }
        let mut models = if self.models.is_empty() {
            self.model_ids
                .into_iter()
                .map(|model| {
                    let model = required(model, "provider_profiles.model_ids")?;
                    Ok(ProviderModelBinding {
                        harness_model_id: model.clone(),
                        provider_model_id: model,
                    })
                })
                .collect::<Result<Vec<_>, ProductionBootstrapError>>()?
        } else {
            self.models
                .into_iter()
                .map(|model| {
                    Ok(ProviderModelBinding {
                        harness_model_id: required(
                            model.harness_model_id,
                            "provider_profiles.models.harness_model_id",
                        )?,
                        provider_model_id: required(
                            model.provider_model_id,
                            "provider_profiles.models.provider_model_id",
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, ProductionBootstrapError>>()?
        };
        if let Some(legacy_model) = self.exact_model.as_ref() {
            let legacy_model = required(legacy_model.clone(), "provider_profiles.exact_model")?;
            if models.is_empty() {
                models.push(ProviderModelBinding {
                    harness_model_id: legacy_model.clone(),
                    provider_model_id: legacy_model,
                });
            } else if !models
                .iter()
                .any(|model| model.harness_model_id == legacy_model)
            {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.exact_model_not_in_model_ids",
                ));
            }
        }
        models.sort_by(|left, right| left.harness_model_id.cmp(&right.harness_model_id));
        if models.is_empty() {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.models",
            ));
        }
        if models
            .windows(2)
            .any(|pair| pair[0].harness_model_id == pair[1].harness_model_id)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.models.duplicate_harness_model_id",
            ));
        }
        let exact_model = self
            .selected_model
            .or(self.exact_model)
            .unwrap_or_else(|| models[0].harness_model_id.clone());
        let exact_model = required(exact_model, "provider_profiles.selected_model")?;
        if !models
            .iter()
            .any(|model| model.harness_model_id == exact_model)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.selected_model_not_in_model_ids",
            ));
        }
        let executable = PathBuf::from(required(self.executable, "provider_profiles.executable")?);
        let catalog_snapshot = self
            .catalog_snapshot
            .map(ProviderCatalogSnapshotFile::into_typed)
            .transpose()?;
        let credential = match self.credential {
            ProviderCredentialFile::HarnessAccount => ProviderCredentialReference::HarnessAccount,
            ProviderCredentialFile::ApiKeyEnvironment {
                source_env,
                target_env,
            } => ProviderCredentialReference::ApiKeyEnvironment {
                source_env: environment_name(
                    source_env,
                    "provider_profiles.credential.source_env",
                )?,
                target_env: environment_name(
                    target_env,
                    "provider_profiles.credential.target_env",
                )?,
            },
        };
        if matches!(admission, ProviderAdmission::Held)
            && self
                .hold_reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.hold_reason",
            ));
        }
        Ok(ProviderBootstrapProfile {
            profile_id,
            provider,
            harness,
            admission,
            models,
            catalog_snapshot,
            exact_model,
            executable,
            credential,
            hold_reason: self.hold_reason,
        })
    }
}

impl ProviderCatalogSnapshotFile {
    fn into_typed(self) -> Result<ProviderCatalogSnapshot, ProductionBootstrapError> {
        let source = bounded_text(self.source, "provider_profiles.catalog_snapshot.source")?;
        let fetched_at = bounded_text(
            self.fetched_at,
            "provider_profiles.catalog_snapshot.fetched_at",
        )?;
        let harness_version = bounded_text(
            self.harness_version,
            "provider_profiles.catalog_snapshot.harness_version",
        )?;
        let evidence_digest_sha256 = required(
            self.evidence_digest_sha256,
            "provider_profiles.catalog_snapshot.evidence_digest_sha256",
        )?;
        if !is_lowercase_sha256(&evidence_digest_sha256) {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.catalog_snapshot.evidence_digest_sha256",
            ));
        }
        Ok(ProviderCatalogSnapshot {
            source,
            fetched_at,
            harness_version,
            evidence_digest_sha256,
        })
    }
}

fn environment_name(
    value: String,
    field: &'static str,
) -> Result<String, ProductionBootstrapError> {
    let value = required(value, field)?;
    if value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(value)
    } else {
        Err(ProductionBootstrapError::InvalidConfiguration(field))
    }
}

fn resolve_provider_credential(
    credential: &ProviderCredentialReference,
) -> Result<Vec<(String, String)>, ProductionBootstrapError> {
    match credential {
        ProviderCredentialReference::HarnessAccount => Ok(Vec::new()),
        ProviderCredentialReference::ApiKeyEnvironment {
            source_env,
            target_env,
        } => {
            let value = std::env::var(source_env)
                .map_err(|_| ProductionBootstrapError::MissingSecret(source_env.clone()))?;
            if value.trim().is_empty() {
                return Err(ProductionBootstrapError::MissingSecret(source_env.clone()));
            }
            Ok(vec![(target_env.clone(), value)])
        }
    }
}

/// Production-admissible Provider/Harness routes. ADR-0004 admitted only
/// GPT-through-Codex; the Founder promoted DeepSeek-over-DSH on 2026-09-19
/// (harness expansion ruling: claude code/zcode/dsh/kimi selectable; current
/// compute: DS + opencode). Routes outside this list keep failing Production
/// admission with `production_admission_pending` until promoted with evidence.
const PRODUCTION_ADMISSIBLE_ROUTES: &[(ProviderId, ProviderHarnessKind)] = &[
    (ProviderId::Gpt, ProviderHarnessKind::CodexAppServer),
    (ProviderId::DeepSeek, ProviderHarnessKind::DshAcp),
    (ProviderId::DeepSeek, ProviderHarnessKind::OpenCodeAcp),
    (ProviderId::DeepSeek, ProviderHarnessKind::CodexAppServer),
];

fn validate_provider_profiles(
    profiles: &[ProviderBootstrapProfile],
) -> Result<(), ProductionBootstrapError> {
    let mut profile_ids = BTreeSet::new();
    let mut production_count = 0;
    for profile in profiles {
        if !profile_ids.insert(profile.profile_id.clone()) {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.profile_id",
            ));
        }
        if profile.exact_model.trim().is_empty()
            || profile.models.is_empty()
            || !profile
                .models
                .iter()
                .any(|model| model.harness_model_id == profile.exact_model)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.exact_model",
            ));
        }
        if profile.admission == ProviderAdmission::Production {
            production_count += 1;
            if !PRODUCTION_ADMISSIBLE_ROUTES
                .iter()
                .any(|(provider, harness)| {
                    profile.provider == *provider && profile.harness == *harness
                })
            {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "provider_profiles.production_admission_pending",
                ));
            }
        }
    }
    if production_count > 1 {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.only_one_production_profile_supported",
        ));
    }
    Ok(())
}

impl UserOwnedBootstrapFile {
    fn into_typed(
        self,
        config_path: PathBuf,
    ) -> Result<ProductionBootstrapConfig, ProductionBootstrapError> {
        let migration_required = match self.schema_version.as_str() {
            "egopulse.production-bootstrap/v2" if self.work_capabilities.is_none() => true,
            "egopulse.production-bootstrap/v3" if self.work_capabilities.is_some() => false,
            "egopulse.production-bootstrap/v2" => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "work_capabilities are not valid in v2",
                ));
            }
            "egopulse.production-bootstrap/v3" => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "work_capabilities are required in v3",
                ));
            }
            _ => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "schema_version",
                ));
            }
        };
        let work_capabilities_file = self.work_capabilities;
        let provider_profiles = self
            .provider_profiles
            .into_iter()
            .map(ProviderProfileFile::into_typed)
            .collect::<Result<Vec<_>, _>>()?;
        validate_provider_profiles(&provider_profiles)?;
        let production_environment_overrides = provider_profiles
            .iter()
            .find(|profile| profile.admission == ProviderAdmission::Production)
            .map(|profile| resolve_provider_credential(&profile.credential))
            .transpose()?
            .unwrap_or_default();
        let task_store = typed_store(self.stores.task, "task authority")?;
        let memory_store = typed_store(self.stores.memory, "memory authority")?;
        let artifact_store = typed_artifact_store(self.stores.artifact)?;
        let verification_store = typed_store(self.stores.verification, "verification authority")?;
        let policy_store = typed_store(self.stores.policy, "policy authority")?;
        let verdict_store = typed_store(self.stores.verdict, "verdict authority")?;
        let adapter_store = typed_store(self.stores.adapter, "adapter edge")?;
        let collaboration_store = typed_store(self.stores.collaboration, "collaboration control")?;

        let policy_ref = self.policy.authorization_policy_ref.into_typed();
        let identity = self.identity;
        let identity_policy_ref = identity.authorization_policy_ref.into_typed();
        if identity_policy_ref != policy_ref {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "identity.authorization_policy_ref",
            ));
        }
        let principal_id = required(identity.principal_id, "identity.principal_id")?;
        let permission_codes =
            non_empty_set(identity.permission_codes, "identity.permission_codes")?;
        let context_kind = identity
            .context_kind
            .as_deref()
            .map(parse_context_principal)
            .transpose()?;
        validate_context_permission_binding(&permission_codes, context_kind)?;
        let grant = egopulse_local_api::session::PrincipalGrant {
            authenticated_principal_id: principal_id.clone(),
            permission_codes,
            authorization_policy_ref: identity_policy_ref,
        };
        let authority_binding = AuthorityPrincipalBinding {
            principal_id: principal_id.clone(),
            task: parse_task_principal(&identity.task_kind)?,
            policy: parse_policy_principal(&identity.policy_kind)?,
            verdict: parse_verdict_principal(&identity.verdict_kind)?,
            memory: identity
                .memory_kind
                .as_deref()
                .map(parse_memory_principal)
                .transpose()?,
            context: context_kind,
        };

        let task_guard = ConfiguredTaskCreationGuardConfig {
            allowed_work_types: non_empty_set(
                self.task_guard.allowed_work_types,
                "task_guard.allowed_work_types",
            )?,
            allowed_input_snapshot_ids: non_empty_set(
                self.task_guard.allowed_input_snapshot_ids,
                "task_guard.allowed_input_snapshot_ids",
            )?,
            allowed_target_scope_refs: non_empty_set(
                self.task_guard.allowed_target_scope_refs,
                "task_guard.allowed_target_scope_refs",
            )?,
            acceptance_contract_ref: self.task_guard.acceptance_contract_ref.into_typed(),
            budget_profile_ref: self.task_guard.budget_profile_ref.into_typed(),
        };

        let (repository_material, repository_artifact_selection) = match self.repository_material {
            Some(repository) => {
                let (material, selection) = repository.into_typed()?;
                (Some(material), Some(selection))
            }
            None => (None, None),
        };

        let artifact_guard = ConfiguredArtifactAdmissionGuardConfig {
            allowed_workspace_refs: non_empty_set(
                self.artifact.allowed_workspace_refs,
                "artifact.allowed_workspace_refs",
            )?,
            allowed_artifact_type_refs: self
                .artifact
                .allowed_artifact_type_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
            allowed_transformation_contract_refs: self
                .artifact
                .allowed_transformation_contract_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
            allowed_retention_profile_refs: self
                .artifact
                .allowed_retention_profile_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
            allowed_claim_semantic_profile_refs: self
                .artifact
                .allowed_claim_semantic_profile_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
            allowed_claim_acceptance_contract_refs: self
                .artifact
                .allowed_claim_acceptance_contract_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
            allowed_evidence_profile_refs: self
                .artifact
                .allowed_evidence_profile_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
        };

        let verification_references = self
            .verification
            .map(VerificationFile::into_typed)
            .transpose()?;
        let verification_worker = self
            .verification_worker
            .map(VerificationWorkerFile::into_typed)
            .transpose()?;
        let memory_retrieval = self
            .memory_retrieval
            .map(MemoryRetrievalFile::into_typed)
            .transpose()?;
        let memory_candidate_producers = self
            .memory_candidate_producers
            .into_iter()
            .map(MemoryCandidateProducerFile::into_typed)
            .collect::<Result<Vec<_>, ProductionBootstrapError>>()?;
        if verification_worker.is_some() && verification_references.is_none() {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker requires verification criteria",
            ));
        }
        if let Some(config) = &self.repository_verification {
            if repository_material.is_none() || verification_worker.is_some() {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "repository Verification composition",
                ));
            }
            config.validate(
                &artifact_guard,
                &verification_references
                    .as_ref()
                    .ok_or(ProductionBootstrapError::InvalidConfiguration(
                        "verification.criteria",
                    ))?
                    .criteria,
            )?;
        }
        if let Some(config) = &self.founder_supporting_material {
            config.validate(&artifact_guard)?;
        }

        let workflow = self.codex.workflow.into_typed()?;
        if !artifact_guard
            .allowed_workspace_refs
            .contains(&workflow.workspace_ref)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "artifact.allowed_workspace_refs must include codex.workflow.workspace_ref",
            ));
        }
        if let Some(selection) = repository_artifact_selection.as_ref()
            && (!artifact_guard
                .allowed_artifact_type_refs
                .contains(&selection.artifact_type_ref)
                || !artifact_guard
                    .allowed_transformation_contract_refs
                    .contains(&selection.transformation_contract_ref)
                || !artifact_guard
                    .allowed_retention_profile_refs
                    .contains(&selection.retention_profile_ref)
                || !artifact_guard
                    .allowed_evidence_profile_refs
                    .contains(&selection.evidence_profile_ref)
                || !artifact_guard
                    .allowed_artifact_type_refs
                    .contains(&selection.command_intent_type_ref)
                || !artifact_guard
                    .allowed_transformation_contract_refs
                    .contains(&selection.command_intent_transformation_ref)
                || !artifact_guard
                    .allowed_artifact_type_refs
                    .contains(&selection.command_receipt_type_ref)
                || !artifact_guard
                    .allowed_transformation_contract_refs
                    .contains(&selection.command_receipt_transformation_ref)
                || selection.command_intent_type_ref == selection.command_receipt_type_ref)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "repository_material Artifact references must be explicitly allowed",
            ));
        }
        let return_collector = GovernedReturnCollectorConfig {
            artifact_type_ref: repository_artifact_selection
                .as_ref()
                .map(|selection| selection.artifact_type_ref.clone())
                .or_else(|| artifact_guard.allowed_artifact_type_refs.first().cloned())
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_artifact_type_refs",
                ))?,
            transformation_contract_ref: repository_artifact_selection
                .as_ref()
                .map(|selection| selection.transformation_contract_ref.clone())
                .or_else(|| {
                    artifact_guard
                        .allowed_transformation_contract_refs
                        .first()
                        .cloned()
                })
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_transformation_contract_refs",
                ))?,
            retention_profile_ref: repository_artifact_selection
                .as_ref()
                .map(|selection| selection.retention_profile_ref.clone())
                .or_else(|| {
                    artifact_guard
                        .allowed_retention_profile_refs
                        .first()
                        .cloned()
                })
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_retention_profile_refs",
                ))?,
            claim_semantic_profile_ref: repository_artifact_selection
                .as_ref()
                .map(|selection| selection.claim_semantic_profile_ref.clone())
                .or_else(|| {
                    artifact_guard
                        .allowed_claim_semantic_profile_refs
                        .first()
                        .cloned()
                })
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_claim_semantic_profile_refs",
                ))?,
            claim_acceptance_contract_ref: repository_artifact_selection
                .as_ref()
                .map(|_| task_guard.acceptance_contract_ref.clone())
                .or_else(|| {
                    artifact_guard
                        .allowed_claim_acceptance_contract_refs
                        .first()
                        .cloned()
                })
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_claim_acceptance_contract_refs",
                ))?,
            evidence_profile_ref: repository_artifact_selection
                .as_ref()
                .map(|selection| selection.evidence_profile_ref.clone())
                .or_else(|| {
                    artifact_guard
                        .allowed_evidence_profile_refs
                        .first()
                        .cloned()
                })
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_evidence_profile_refs",
                ))?,
            workspace_ref: workflow.workspace_ref.clone(),
            collector_principal_id: "collector:terminal-output".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
        };
        if let Some(material) = &repository_material {
            repository::validate_repository_claim_binding(
                &artifact_guard,
                &task_guard.acceptance_contract_ref,
                &return_collector,
            )?;
            material
                .validate_acceptance_contract_ref(&task_guard.acceptance_contract_ref)
                .map_err(|_| {
                    ProductionBootstrapError::InvalidConfiguration(
                        "repository frozen acceptance contract reference",
                    )
                })?;
        }
        let mut codex = CodexHarnessCompositionConfig {
            native: NativeHarnessCompositionConfig {
                collaboration_database_path: collaboration_store.database_path,
                collaboration_store_epoch: collaboration_store.store_epoch,
                collaboration_key: collaboration_store.key,
                adapter_database_path: adapter_store.database_path.clone(),
                adapter_store_epoch: adapter_store.store_epoch.clone(),
                adapter_key: adapter_store.key,
                input_bundle_root: PathBuf::from(required(
                    self.codex.input_bundle_root,
                    "codex.input_bundle_root",
                )?),
                workspace_root: PathBuf::from(required(
                    self.codex.workspace_root,
                    "codex.workspace_root",
                )?),
                default_model: self
                    .codex
                    .default_model
                    .map(|model| required(model, "codex.default_model"))
                    .transpose()?,
                workflow,
                lease_ttl_seconds: self.codex.lease_ttl_seconds,
                return_collector,
            },
            codex_executable: PathBuf::from(required(
                self.codex.codex_executable,
                "codex.codex_executable",
            )?),
            environment_overrides: production_environment_overrides,
            work_capability_route: None,
        };
        // The configured native executable and default model are the admitted
        // route's, for whichever provider that route serves: composition reads
        // the profile's executable, so a config that declares a different one
        // would otherwise describe a route nobody runs.
        if let Some(profile) = provider_profiles
            .iter()
            .find(|profile| profile.admission == ProviderAdmission::Production)
            && (codex.native.default_model.as_deref() != Some(profile.exact_model.as_str())
                || codex.codex_executable != profile.executable)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_binding",
            ));
        }
        let production_profile = provider_profiles
            .iter()
            .find(|profile| profile.admission == ProviderAdmission::Production)
            .ok_or(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_route_binding",
            ))?;
        if let Some(config) = &self.repository_verification {
            config.validate_model(production_profile)?;
        }
        let (admitted_route, default_choice_id, preference_revision) = if migration_required {
            let route = compatibility_codex_route(production_profile, &codex)?;
            let choice_id = format!("compat-codex:{}", &route.route_binding_sha256[..16]);
            (route, choice_id, 1)
        } else {
            let file =
                work_capabilities_file.ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "work_capabilities are required in v3",
                ))?;
            file.into_typed(production_profile, &codex)?
        };
        codex.work_capability_route = Some(admitted_route.clone());
        let work_capability_registry = Arc::new(WorkCapabilityRegistry::new(
            config_path,
            &provider_profiles,
            admitted_route,
            default_choice_id,
            preference_revision,
            migration_required,
        )?);

        Ok(ProductionBootstrapConfig {
            task: TaskAuthorityConfig {
                database_path: task_store.database_path,
                store_epoch: task_store.store_epoch,
                key: SqlCipherKey::new(task_store.key),
            },
            memory: MemoryAuthorityConfig {
                database_path: memory_store.database_path,
                store_epoch: memory_store.store_epoch,
                key: SqlCipherKey::new(memory_store.key),
            },
            memory_retrieval,
            memory_candidate_producers,
            task_guard,
            repository_material,
            repository_command_artifacts: repository_artifact_selection.as_ref().map(|selection| {
                RepositoryCommandArtifactPolicyConfig {
                    intent_type_ref: selection.command_intent_type_ref.clone(),
                    intent_transformation_ref: selection.command_intent_transformation_ref.clone(),
                    receipt_type_ref: selection.command_receipt_type_ref.clone(),
                    receipt_transformation_ref: selection
                        .command_receipt_transformation_ref
                        .clone(),
                }
            }),
            artifact: ArtifactAuthorityConfig {
                database_path: artifact_store.database_path,
                blob_root: artifact_store.blob_root,
                store_epoch: artifact_store.store_epoch,
                key: ArtifactSqlCipherKey::new(artifact_store.key),
            },
            artifact_guard,
            verification: VerificationAuthorityConfig {
                database_path: verification_store.database_path,
                store_epoch: verification_store.store_epoch,
                key: VerificationSqlCipherKey::new(verification_store.key),
            },
            verification_references,
            verification_worker,
            repository_verification: self.repository_verification,
            founder_supporting_material: self.founder_supporting_material,
            policy: PolicyAuthorityConfig {
                database_path: policy_store.database_path,
                store_epoch: policy_store.store_epoch,
                key: PolicySqlCipherKey::new(policy_store.key),
            },
            policy_resolver: LocalUserPolicyBootstrapConfig {
                edge: AdapterEdgeConfig {
                    database_path: adapter_store.database_path,
                    // The Adapter Edge store binds one adapter identity, so the
                    // policy resolver must name the same adapter as the route
                    // this environment composes.
                    adapter_id: crate::production_harness_identity(production_profile.harness)
                        .ok_or(ProductionBootstrapError::InvalidConfiguration(
                            "provider_profiles.production_harness_kind",
                        ))?
                        .adapter_id
                        .to_owned(),
                    store_epoch: adapter_store.store_epoch,
                    key: AdapterEdgeKey::new(adapter_store.key),
                },
                authentication_context_ref: required(
                    self.policy.authentication_context_ref,
                    "policy.authentication_context_ref",
                )?,
                authorization_policy_ref: policy_ref,
                allowed_scope_refs: non_empty_set(
                    self.policy.allowed_scope_refs,
                    "policy.allowed_scope_refs",
                )?,
                decision_ttl: seconds(
                    self.policy.decision_ttl_seconds,
                    "policy.decision_ttl_seconds",
                )?,
            },
            verdict: VerdictAuthorityConfig {
                database_path: verdict_store.database_path,
                store_epoch: verdict_store.store_epoch,
                key: VerdictSqlCipherKey::new(verdict_store.key),
            },
            allowed_founder_principal_ids: non_empty_set(
                self.founder.allowed_founder_principal_ids,
                "founder.allowed_founder_principal_ids",
            )?,
            founder_authority_ref: required(self.founder.authority_ref, "founder.authority_ref")?,
            founder_authority_policy_ref: self.founder.authority_policy_ref.into_typed(),
            allowed_confirmation_proof_refs: non_empty_set(
                self.founder.allowed_confirmation_proof_refs,
                "founder.allowed_confirmation_proof_refs",
            )?,
            non_overridable_gate_ids: set(self.founder.non_overridable_gate_ids),
            non_overridable_criterion_ids: set(self.founder.non_overridable_criterion_ids),
            founder_confirmation_ttl: seconds(
                self.founder.confirmation_ttl_seconds,
                "founder.confirmation_ttl_seconds",
            )?,
            os_principal: AllowlistedPrincipal {
                fingerprint_hex: required(
                    identity.os_fingerprint_hex,
                    "identity.os_fingerprint_hex",
                )?,
                grant,
            },
            authority_binding,
            provider_profiles,
            work_capability_registry,
            codex,
        })
    }
}

struct TypedStore {
    database_path: PathBuf,
    store_epoch: String,
    key: [u8; 32],
}

struct TypedArtifactStore {
    database_path: PathBuf,
    blob_root: PathBuf,
    store_epoch: String,
    key: [u8; 32],
}

fn typed_artifact_store(
    value: ArtifactStoreFile,
) -> Result<TypedArtifactStore, ProductionBootstrapError> {
    Ok(TypedArtifactStore {
        database_path: PathBuf::from(required(
            value.database_path,
            "artifact authority database path",
        )?),
        blob_root: PathBuf::from(required(value.blob_root, "artifact authority blob root")?),
        store_epoch: required(value.store_epoch, "artifact authority store epoch")?,
        key: secret_from_environment(&value.key_env)?,
    })
}

fn typed_store(
    value: StoreFile,
    label: &'static str,
) -> Result<TypedStore, ProductionBootstrapError> {
    let database_path = PathBuf::from(required(value.database_path, label)?);
    let store_epoch = required(value.store_epoch, label)?;
    let key = secret_from_environment(&value.key_env)?;
    Ok(TypedStore {
        database_path,
        store_epoch,
        key,
    })
}

fn required(value: String, field: &'static str) -> Result<String, ProductionBootstrapError> {
    if value.trim().is_empty() {
        return Err(ProductionBootstrapError::InvalidConfiguration(field));
    }
    Ok(value)
}

fn bounded_text(value: String, field: &'static str) -> Result<String, ProductionBootstrapError> {
    let value = required(value, field)?;
    if value.len() > 4 * 1024 {
        return Err(ProductionBootstrapError::InvalidConfiguration(field));
    }
    Ok(value)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn set(values: Vec<String>) -> BTreeSet<String> {
    values.into_iter().collect()
}

fn non_empty_set(
    values: Vec<String>,
    field: &'static str,
) -> Result<BTreeSet<String>, ProductionBootstrapError> {
    let values = set(values);
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(ProductionBootstrapError::InvalidConfiguration(field));
    }
    Ok(values)
}

fn only_configured_value(values: &BTreeSet<String>) -> Option<String> {
    (values.len() == 1)
        .then(|| values.iter().next().cloned())
        .flatten()
}

fn seconds(value: u64, field: &'static str) -> Result<Duration, ProductionBootstrapError> {
    if value == 0 {
        return Err(ProductionBootstrapError::InvalidConfiguration(field));
    }
    Ok(Duration::from_secs(value))
}

fn secret_from_environment(name: &str) -> Result<[u8; 32], ProductionBootstrapError> {
    if name.trim().is_empty() {
        return Err(ProductionBootstrapError::InvalidConfiguration("key_env"));
    }
    if !name.starts_with("EGOPULSE_") || !name.ends_with("_KEY_HEX") {
        return Err(ProductionBootstrapError::InvalidConfiguration("key_env"));
    }
    let value = std::env::var(name)
        .map_err(|_| ProductionBootstrapError::MissingSecret(name.to_owned()))?;
    let bytes =
        hex::decode(value).map_err(|_| ProductionBootstrapError::InvalidSecret(name.to_owned()))?;
    let key = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ProductionBootstrapError::InvalidSecret(name.to_owned()))?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(ProductionBootstrapError::InvalidSecret(name.to_owned()));
    }
    Ok(key)
}

impl ReferenceFile {
    fn into_typed(self) -> ContractReference {
        ContractReference {
            contract_id: self.contract_id,
            version: self.version,
            sha256: self.sha256,
        }
    }
}

impl RepositoryMaterialFile {
    fn into_typed(
        self,
    ) -> Result<(RepositoryMaterialConfig, RepositoryArtifactSelection), ProductionBootstrapError>
    {
        Ok((
            RepositoryMaterialConfig {
                contract_path: PathBuf::from(required(
                    self.acceptance_contract_path,
                    "repository_material.acceptance_contract_path",
                )?),
                repository_root: PathBuf::from(required(
                    self.repository_root,
                    "repository_material.repository_root",
                )?),
                git_executable: PathBuf::from(required(
                    self.git_executable,
                    "repository_material.git_executable",
                )?),
            },
            RepositoryArtifactSelection {
                artifact_type_ref: self.artifact_type_ref.into_typed(),
                transformation_contract_ref: self.transformation_contract_ref.into_typed(),
                retention_profile_ref: self.retention_profile_ref.into_typed(),
                evidence_profile_ref: self.evidence_profile_ref.into_typed(),
                claim_semantic_profile_ref: self.claim_semantic_profile_ref.into_typed(),
                command_intent_type_ref: self.command_intent_type_ref.into_typed(),
                command_intent_transformation_ref: self
                    .command_intent_transformation_ref
                    .into_typed(),
                command_receipt_type_ref: self.command_receipt_type_ref.into_typed(),
                command_receipt_transformation_ref: self
                    .command_receipt_transformation_ref
                    .into_typed(),
            },
        ))
    }
}

impl VerificationWorkerFile {
    fn into_typed(self) -> Result<VerificationWorkerConfig, ProductionBootstrapError> {
        let checker_request = hex::decode(&self.checker_request_hex).map_err(|_| {
            ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_request_hex",
            )
        })?;
        Ok(VerificationWorkerConfig {
            handoff_plan: self.handoff.into_typed(),
            checker_profile: self.checker_profile.into_typed()?,
            checker_profile_deployment: self
                .checker_profile_deployment
                .map(CheckerProfileDeploymentFile::into_typed)
                .transpose()?,
            checker_executable: PathBuf::from(required(
                self.checker_executable,
                "verification_worker.checker_executable",
            )?),
            checker_arguments: self.checker_arguments,
            working_directory: PathBuf::from(required(
                self.working_directory,
                "verification_worker.working_directory",
            )?),
            checker_request,
            mapper_policy: self.mapper.into_typed()?,
            verification_run_id_prefix: required(
                self.verification_run_id_prefix,
                "verification_worker.verification_run_id_prefix",
            )?,
            verification_artifact_id_prefix: required(
                self.verification_artifact_id_prefix,
                "verification_worker.verification_artifact_id_prefix",
            )?,
            execution_id_prefix: required(
                self.execution_id_prefix,
                "verification_worker.execution_id_prefix",
            )?,
            tool_receipt_artifact_ids: self.tool_receipt_artifact_ids,
            model_call_receipt_artifact_ids: self.model_call_receipt_artifact_ids,
            checker_timeout: Duration::from_millis(self.checker_timeout_ms),
            checker_output_limit: self.checker_output_limit,
            output_source: match self.checker_output_source.as_deref() {
                None | Some("stdout") => {
                    egopulse_verification_authority::CheckerOutputSource::Stdout
                }
                Some("envelope_artifact_path") => {
                    egopulse_verification_authority::CheckerOutputSource::EnvelopeArtifactPath
                }
                Some(_) => {
                    return Err(ProductionBootstrapError::InvalidConfiguration(
                        "verification_worker.checker_output_source",
                    ));
                }
            },
            checker_output_capture: self
                .checker_output_capture
                .map(CheckerOutputCaptureFile::into_typed)
                .transpose()?,
            checker_output_sink: None,
        })
    }
}

impl MemoryRetrievalFile {
    fn into_typed(self) -> Result<MemoryRetrievalCompositionConfig, ProductionBootstrapError> {
        let principal_scope_allowlist = self
            .principal_scope_allowlist
            .into_iter()
            .map(|(principal, scopes)| {
                let principal = required(principal, "memory_retrieval.principal")?;
                let scopes = non_empty_set(scopes, "memory_retrieval.scope_refs")?;
                Ok((principal, scopes))
            })
            .collect::<Result<BTreeMap<_, _>, ProductionBootstrapError>>()?;
        let config = MemoryRetrievalCompositionConfig {
            worker_executable: PathBuf::from(required(
                self.worker_executable,
                "memory_retrieval.worker_executable",
            )?),
            worker_arguments: self.worker_arguments,
            working_directory: PathBuf::from(required(
                self.working_directory,
                "memory_retrieval.working_directory",
            )?),
            inherited_environment: set(self.inherited_environment),
            environment_overrides: self.environment_overrides,
            timeout: Duration::from_millis(self.timeout_ms),
            output_limit_bytes: self.output_limit_bytes,
            principal_scope_allowlist,
        };
        config
            .validate()
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("memory_retrieval"))?;
        Ok(config)
    }
}

impl MemoryCandidateProducerFile {
    fn into_typed(self) -> Result<MemoryCandidateProducerBinding, ProductionBootstrapError> {
        MemoryCandidateProducerBinding::new(
            self.producer_id,
            self.principal_id,
            parse_memory_producer_principal(&self.principal_kind)?,
            self.scope_ref,
        )
        .map_err(|_| ProductionBootstrapError::InvalidConfiguration("memory_candidate_producers"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerProfileDeploymentFile {
    workspace_ref: String,
    artifact_type_ref: ReferenceFile,
    transformation_contract_ref: ReferenceFile,
    retention_profile_ref: ReferenceFile,
    collector_principal_id: String,
    artifact_authority_principal_id: String,
    sensitivity_class: String,
}

impl CheckerProfileDeploymentFile {
    fn into_typed(self) -> Result<crate::CheckerProfileDeploymentConfig, ProductionBootstrapError> {
        let config = crate::CheckerProfileDeploymentConfig {
            workspace_ref: required(
                self.workspace_ref,
                "verification_worker.checker_profile_deployment.workspace_ref",
            )?,
            artifact_type_ref: self.artifact_type_ref.into_typed(),
            transformation_contract_ref: self.transformation_contract_ref.into_typed(),
            retention_profile_ref: self.retention_profile_ref.into_typed(),
            collector_principal_id: required(
                self.collector_principal_id,
                "verification_worker.checker_profile_deployment.collector_principal_id",
            )?,
            artifact_authority_principal_id: required(
                self.artifact_authority_principal_id,
                "verification_worker.checker_profile_deployment.artifact_authority_principal_id",
            )?,
            sensitivity_class: required(
                self.sensitivity_class,
                "verification_worker.checker_profile_deployment.sensitivity_class",
            )?,
        };
        config.validate().map_err(|_| {
            ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_profile_deployment",
            )
        })?;
        Ok(config)
    }
}

impl VerificationWorkerHandoffFile {
    fn into_typed(self) -> crate::VerificationHandoffPlan {
        crate::VerificationHandoffPlan {
            binding: crate::VerificationBindingTemplate {
                claim_id: self.claim_id,
                claim_semantic_profile_ref: self.claim_semantic_profile_ref.into_typed(),
            },
            criterion_ids: self.criterion_ids,
            checker_profile_refs: self
                .checker_profile_refs
                .into_iter()
                .map(ReferenceFile::into_typed)
                .collect(),
        }
    }
}

impl CheckerProfileFile {
    fn into_typed(self) -> Result<CheckerProfile, ProductionBootstrapError> {
        let status = egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfileStatus::try_from(self.status)
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verification_worker.checker_profile.status"))?;
        if status == egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfileStatus::Unspecified {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_profile.status",
            ));
        }
        let assurance_class = egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerAssuranceClass::try_from(self.assurance_class)
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verification_worker.checker_profile.assurance_class"))?;
        if assurance_class == egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerAssuranceClass::Unspecified {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_profile.assurance_class",
            ));
        }
        Ok(CheckerProfile {
            checker_profile_id: self.checker_profile_id,
            revision: self.revision,
            status: self.status,
            checker_id: self.checker_id,
            checker_version: self.checker_version,
            input_contract_ref: self.input_contract_ref.map(ReferenceFile::into_typed),
            output_contract_ref: self.output_contract_ref.map(ReferenceFile::into_typed),
            supported_criterion_types: self.supported_criterion_types,
            assurance_class: self.assurance_class,
            sandbox_profile_ref: self.sandbox_profile_ref.map(ReferenceFile::into_typed),
            tool_policy_ref: self.tool_policy_ref.map(ReferenceFile::into_typed),
            data_egress_policy_ref: self.data_egress_policy_ref.map(ReferenceFile::into_typed),
            timeout_ms: self.timeout_ms,
            network_allowed: self.network_allowed,
            profile_digest_sha256: self.profile_digest_sha256,
            attestation_evidence_artifact_ids: self.attestation_evidence_artifact_ids,
            attested_at: self.attested_at.map(TimestampFile::into_typed),
        })
    }
}

impl TimestampFile {
    fn into_typed(self) -> Timestamp {
        Timestamp {
            seconds: self.seconds,
            nanos: self.nanos,
        }
    }
}

impl SegoMapperFile {
    fn into_typed(self) -> Result<SegoMapperPolicy, ProductionBootstrapError> {
        let requirement = egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionRequirement::try_from(self.requirement)
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verification_worker.mapper.requirement"))?;
        if requirement == egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionRequirement::Unspecified {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.requirement",
            ));
        }
        let failure_threshold = egopulse_domain_contracts::v01::egopulse::verification::v1::DiscrepancySeverity::try_from(self.failure_threshold)
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verification_worker.mapper.failure_threshold"))?;
        if failure_threshold == egopulse_domain_contracts::v01::egopulse::verification::v1::DiscrepancySeverity::Unspecified {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.failure_threshold",
            ));
        }
        if self.contract_id != SEGO_REVIEW_ARTIFACT_CONTRACT_ID {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.contract_id",
            ));
        }
        if self.contract_revision != SEGO_REVIEW_ARTIFACT_CONTRACT_REVISION {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.contract_revision",
            ));
        }
        Ok(SegoMapperPolicy {
            criterion_id: self.criterion_id,
            requirement,
            checker_profile_ref: self.checker_profile_ref.into_typed(),
            contract_id: self.contract_id,
            contract_revision: self.contract_revision,
            expected_scope: self.expected_scope,
            expected_diff_hash: self.expected_diff_hash,
            expected_reviewer: self.expected_reviewer,
            expected_engine_version: self.expected_engine_version,
            expected_review_mode: self.expected_review_mode,
            positive_acceptance: self.positive_acceptance,
            failure_threshold,
            raw_output_artifact_id: self.raw_output_artifact_id,
            raw_output_address: self.raw_output_address.into_typed()?,
            finding_evidence: self
                .finding_evidence
                .into_iter()
                .map(|(key, value)| (key, value.into_typed()))
                .collect(),
        })
    }
}

impl ContentAddressFile {
    fn into_typed(self) -> Result<ContentAddress, ProductionBootstrapError> {
        let algorithm = HashAlgorithm::try_from(self.algorithm).map_err(|_| {
            ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.raw_output_address.algorithm",
            )
        })?;
        if algorithm != HashAlgorithm::Sha256 {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.raw_output_address.algorithm",
            ));
        }
        Ok(ContentAddress {
            algorithm: self.algorithm,
            digest: self.digest,
            byte_length: self.byte_length,
        })
    }
}

impl FindingEvidenceFile {
    fn into_typed(self) -> SegoFindingEvidenceBinding {
        SegoFindingEvidenceBinding {
            evidence_id: self.evidence_id,
            description_artifact_id: self.description_artifact_id,
            suggested_fix_artifact_id: self.suggested_fix_artifact_id,
        }
    }
}

/// Reviewed criterion policy snapshots used by the owner-backed Verification
/// resolver. This configuration names acceptance policy only; it does not
/// make a checker profile active or attest any evidence.
#[derive(Clone, Debug)]
pub struct VerificationReferenceBootstrapConfig {
    pub criteria: Vec<egopulse_verification_authority::CriterionPolicySnapshot>,
}

impl VerificationFile {
    fn into_typed(self) -> Result<VerificationReferenceBootstrapConfig, ProductionBootstrapError> {
        if self.criteria.is_empty() {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "verification.criteria",
            ));
        }
        let criteria = self
            .criteria
            .into_iter()
            .map(CriterionFile::into_typed)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerificationReferenceBootstrapConfig { criteria })
    }
}

impl CriterionFile {
    fn into_typed(
        self,
    ) -> Result<egopulse_verification_authority::CriterionPolicySnapshot, ProductionBootstrapError>
    {
        let criterion_id = required(self.criterion_id, "verification.criteria.criterion_id")?;
        let checker_profile_ids = non_empty_set(
            self.checker_profile_ids,
            "verification.criteria.checker_profile_ids",
        )?
        .into_iter()
        .collect();
        Ok(egopulse_verification_authority::CriterionPolicySnapshot {
            criterion_id,
            requirement: self.requirement,
            minimum_assurance: self.minimum_assurance,
            not_applicable_allowed: self.not_applicable_allowed,
            checker_profile_ids,
        })
    }
}

impl WorkflowFile {
    fn into_typed(self) -> Result<SingleHarnessWorkConfig, ProductionBootstrapError> {
        Ok(SingleHarnessWorkConfig {
            run_id: required(self.run_id, "codex.workflow.run_id")?,
            attempt_id: required(self.attempt_id, "codex.workflow.attempt_id")?,
            dispatch_id: required(self.dispatch_id, "codex.workflow.dispatch_id")?,
            plan: self.plan.into_typed()?,
            harness_id: required(self.harness_id, "codex.workflow.harness_id")?,
            capability_profile_ref: self.capability_profile_ref.into_typed(),
            workspace_ref: required(self.workspace_ref, "codex.workflow.workspace_ref")?,
            lease_policy_ref: self.lease_policy_ref.into_typed(),
            owner_instance_id: required(
                self.owner_instance_id,
                "codex.workflow.owner_instance_id",
            )?,
            material: self.material.into_typed()?,
            task_authority_principal_id: required(
                self.task_authority_principal_id,
                "codex.workflow.task_authority_principal_id",
            )?,
            collaboration_principal_id: required(
                self.collaboration_principal_id,
                "codex.workflow.collaboration_principal_id",
            )?,
            attempt_supervisor_principal_id: required(
                self.attempt_supervisor_principal_id,
                "codex.workflow.attempt_supervisor_principal_id",
            )?,
            harness_adapter_principal_id: required(
                self.harness_adapter_principal_id,
                "codex.workflow.harness_adapter_principal_id",
            )?,
        })
    }
}

impl PlanFile {
    fn into_typed(self) -> Result<RunPlan, ProductionBootstrapError> {
        Ok(RunPlan {
            plan_id: required(self.plan_id, "codex.workflow.plan.plan_id")?,
            digest_sha256: required(self.digest_sha256, "codex.workflow.plan.digest_sha256")?,
            max_active_attempts: self.max_active_attempts,
            steps: vec![self.step.into_typed()?],
            budget_profile_ref: self.budget_profile_ref.map(ReferenceFile::into_typed),
        })
    }
}

impl StepFile {
    fn into_typed(self) -> Result<StepPlan, ProductionBootstrapError> {
        Ok(StepPlan {
            step_id: required(self.step_id, "codex.workflow.plan.step.step_id")?,
            step_kind: required(self.step_kind, "codex.workflow.plan.step.step_kind")?,
            depends_on_step_ids: self.depends_on_step_ids,
            input_bundle_ref: required(
                self.input_bundle_ref,
                "codex.workflow.plan.step.input_bundle_ref",
            )?,
            expected_output_contract_ref: self
                .expected_output_contract_ref
                .map(ReferenceFile::into_typed),
            required_capability_profile_ref: self
                .required_capability_profile_ref
                .map(ReferenceFile::into_typed),
            max_attempts: self.max_attempts,
        })
    }
}

impl MaterialFile {
    fn into_typed(self) -> Result<DispatchMaterial, ProductionBootstrapError> {
        let session_strategy = match self.session_strategy.as_str() {
            "create_new" => NativeSessionStrategy::CreateNew,
            "continue_existing" => NativeSessionStrategy::ContinueExisting,
            _ => {
                return Err(ProductionBootstrapError::InvalidConfiguration(
                    "codex.workflow.material.session_strategy",
                ));
            }
        };
        Ok(DispatchMaterial {
            input_bundle_sha256: required(
                self.input_bundle_sha256,
                "codex.workflow.material.input_bundle_sha256",
            )?,
            sandbox_profile_ref: self.sandbox_profile_ref.into_typed(),
            tool_policy_ref: self.tool_policy_ref.into_typed(),
            data_egress_policy_ref: self.data_egress_policy_ref.into_typed(),
            approval_policy_ref: self.approval_policy_ref.into_typed(),
            session_strategy,
            native_session_ref: self.native_session_ref,
            checkpoint_ref: self.checkpoint_ref,
            route_binding: None,
            evidence_refs: self.evidence_refs,
        })
    }
}

fn parse_task_principal(
    value: &str,
) -> Result<Option<TaskPrincipalKind>, ProductionBootstrapError> {
    let kind = match value {
        "Founder" => TaskPrincipalKind::Founder,
        "FounderAuthority" => TaskPrincipalKind::FounderAuthority,
        "CollaborationControl" => TaskPrincipalKind::CollaborationControl,
        "SegoVerification" => TaskPrincipalKind::SegoVerification,
        "Harness" => TaskPrincipalKind::Harness,
        "Model" => TaskPrincipalKind::Model,
        "RecoveryCoordinator" => TaskPrincipalKind::RecoveryCoordinator,
        "none" => return Ok(None),
        _ => {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "identity.task_kind",
            ));
        }
    };
    Ok(Some(kind))
}

fn parse_policy_principal(
    value: &str,
) -> Result<Option<PolicyPrincipalKind>, ProductionBootstrapError> {
    let kind = match value {
        "LocalUser" => PolicyPrincipalKind::LocalUser,
        "FounderPolicy" => PolicyPrincipalKind::FounderPolicy,
        "HarnessAdapter" => PolicyPrincipalKind::HarnessAdapter,
        "PolicyAuthority" => PolicyPrincipalKind::PolicyAuthority,
        "RecoveryCoordinator" => PolicyPrincipalKind::RecoveryCoordinator,
        "Model" => PolicyPrincipalKind::Model,
        "UserInterface" => PolicyPrincipalKind::UserInterface,
        "none" => return Ok(None),
        _ => {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "identity.policy_kind",
            ));
        }
    };
    Ok(Some(kind))
}

fn parse_verdict_principal(
    value: &str,
) -> Result<Option<VerdictPrincipalKind>, ProductionBootstrapError> {
    let kind = match value {
        "FounderAuthority" => VerdictPrincipalKind::FounderAuthority,
        "TaskAuthority" => VerdictPrincipalKind::TaskAuthority,
        "Harness" => VerdictPrincipalKind::Harness,
        "Checker" => VerdictPrincipalKind::Checker,
        "Model" => VerdictPrincipalKind::Model,
        "RecoveryCoordinator" => VerdictPrincipalKind::RecoveryCoordinator,
        "PolicyAuthority" => VerdictPrincipalKind::PolicyAuthority,
        "none" => return Ok(None),
        _ => {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "identity.verdict_kind",
            ));
        }
    };
    Ok(Some(kind))
}

fn parse_memory_principal(value: &str) -> Result<MemoryPrincipalKind, ProductionBootstrapError> {
    match value {
        "Founder" => Ok(MemoryPrincipalKind::Founder),
        "FounderAuthority" => Ok(MemoryPrincipalKind::FounderAuthority),
        "Agent" => Ok(MemoryPrincipalKind::Agent),
        "Model" => Ok(MemoryPrincipalKind::Model),
        "Harness" => Ok(MemoryPrincipalKind::Harness),
        "GovernanceKernel" => Ok(MemoryPrincipalKind::GovernanceKernel),
        "RecoveryCoordinator" => Ok(MemoryPrincipalKind::RecoveryCoordinator),
        _ => Err(ProductionBootstrapError::InvalidConfiguration(
            "identity.memory_kind",
        )),
    }
}

fn parse_context_principal(value: &str) -> Result<ContextPrincipalKind, ProductionBootstrapError> {
    match value {
        "Founder" => Ok(ContextPrincipalKind::Founder),
        _ => Err(ProductionBootstrapError::InvalidConfiguration(
            "identity.context_kind",
        )),
    }
}

fn validate_context_permission_binding(
    permission_codes: &BTreeSet<String>,
    context_kind: Option<ContextPrincipalKind>,
) -> Result<(), ProductionBootstrapError> {
    if permission_codes.contains("local.context.revoke")
        && context_kind != Some(ContextPrincipalKind::Founder)
    {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "identity.context_kind",
        ));
    }
    Ok(())
}

fn parse_memory_producer_principal(
    value: &str,
) -> Result<MemoryPrincipalKind, ProductionBootstrapError> {
    match value {
        "Agent" => Ok(MemoryPrincipalKind::Agent),
        "Model" => Ok(MemoryPrincipalKind::Model),
        "Harness" => Ok(MemoryPrincipalKind::Harness),
        _ => Err(ProductionBootstrapError::InvalidConfiguration(
            "memory_candidate_producers.principal_kind",
        )),
    }
}

/// Production's temporary verification boundary. It prevents the daemon from
/// accepting client-supplied verification references before the reviewed
/// Sego/checker composition is installed in the next vertical. This resolver
/// remains useful for tests and for the explicit deny branch of the
/// production composition.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyVerificationReferences;

impl VerificationReferenceResolver for DenyVerificationReferences {
    fn validate_checker_profile(
        &self,
        _profile: &CheckerProfile,
    ) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn resolve_request(
        &self,
        _request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn revalidate_binding(&self, _binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn validate_result_references(
        &self,
        _evidence_ids: &[String],
        _artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }
}

/// Small composition-root adapter allowing the optional concrete resolver to
/// be selected without leaking its Artifact Authority generic parameters into
/// `ProductionBootstrapConfig` or `VerificationAuthority`.
struct ComposedVerificationReferenceResolver {
    inner: Box<dyn VerificationReferenceResolver>,
}

impl VerificationReferenceResolver for ComposedVerificationReferenceResolver {
    fn validate_checker_result_references(
        &self,
        context: &egopulse_verification_authority::CheckerResultReferenceContext<'_>,
        evidence_ids: &[String],
        references: &[egopulse_verification_authority::CheckerResultArtifactReference],
    ) -> Result<(), ReferenceRejection> {
        self.inner
            .validate_checker_result_references(context, evidence_ids, references)
    }

    fn validate_checker_profile(&self, profile: &CheckerProfile) -> Result<(), ReferenceRejection> {
        self.inner.validate_checker_profile(profile)
    }

    fn resolve_request(
        &self,
        request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        self.inner.resolve_request(request)
    }

    fn revalidate_binding(&self, binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        self.inner.revalidate_binding(binding)
    }

    fn validate_result_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        self.inner
            .validate_result_references(evidence_ids, artifact_ids)
    }

    fn validate_result_references_for_binding(
        &self,
        binding: &VerificationBinding,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        self.inner
            .validate_result_references_for_binding(binding, evidence_ids, artifact_ids)
    }
}

#[derive(Debug, Error)]
pub enum ProductionBootstrapError {
    #[error("user-owned configuration file could not be read: {path}")]
    ConfigurationFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("user-owned configuration file is not valid JSON: {path}")]
    ConfigurationFormat {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("user-owned production configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("user-owned configuration changed while the explicit transition was in progress")]
    ConfigurationTransitionConflict,
    #[error("user-owned configuration transition could not be persisted atomically")]
    ConfigurationTransition,
    #[error("required bootstrap secret is missing: {0}")]
    MissingSecret(String),
    #[error("production Provider executable is unavailable: {0}")]
    ProviderExecutableUnavailable(String),
    #[error("bootstrap secret is not a non-zero 32-byte hex value: {0}")]
    InvalidSecret(String),
    #[error("Task creation guard configuration is invalid")]
    TaskGuard(#[from] crate::TaskCreationGuardConfigurationError),
    #[error("Task Authority could not be opened")]
    TaskAuthority(#[from] TaskAuthorityFailure),
    #[error("Memory Authority could not be opened")]
    MemoryAuthority(#[from] MemoryAuthorityFailure),
    #[error("Context Authority could not be opened")]
    ContextAuthority,
    #[error("Work preparation composition is invalid")]
    WorkPreparation,
    #[error("work-capability registry configuration is invalid")]
    WorkCapability(#[from] WorkCapabilityRegistryError),
    #[error("Artifact admission guard configuration is invalid")]
    ArtifactGuard(#[from] crate::ArtifactAdmissionGuardConfigurationError),
    #[error("Artifact Authority could not be opened")]
    ArtifactAuthority(#[from] ArtifactAuthorityFailure),
    #[error("Verification Authority could not be opened")]
    VerificationAuthority(#[from] VerificationAuthorityFailure),
    #[error("Adapter edge for Policy could not be opened")]
    PolicyAdapterEdge(#[source] AdapterEdgeError),
    #[error("local-user Policy resolver configuration is invalid")]
    PolicyResolver(#[from] crate::LocalUserPolicyConfigurationError),
    #[error("Policy Authority could not be opened")]
    PolicyAuthority(#[from] PolicyAuthorityFailure),
    #[error("Founder Verdict resolver configuration is invalid")]
    FounderResolver(#[from] FounderVerdictConfigurationError),
    #[error("Founder Verdict Authority could not be opened")]
    VerdictAuthority(#[from] egopulse_founder_verdict_authority::VerdictAuthorityFailure),
    #[error("principal policy is invalid")]
    PrincipalPolicy(#[from] PrincipalPolicyError),
    #[error("Codex Harness composition is invalid: {0:#}")]
    Codex(#[from] DaemonCompositionError),
    #[error("Verification worker composition is invalid: {0}")]
    VerificationWorker(#[from] crate::VerificationWorkerConfigurationError),
}

impl From<AdapterEdgeError> for ProductionBootstrapError {
    fn from(error: AdapterEdgeError) -> Self {
        Self::PolicyAdapterEdge(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationBinding;
    use std::fs;
    use uuid::Uuid;

    fn packaged_v2_config_bytes() -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../config/agentos-config.example.json"
        ))
        .expect("packaged configuration JSON");
        value["schema_version"] = serde_json::json!(PRODUCTION_BOOTSTRAP_V2);
        value
            .as_object_mut()
            .expect("packaged configuration object")
            .remove("work_capabilities");
        let mut bytes = serde_json::to_vec_pretty(&value).expect("render packaged v2 fixture");
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn provider_executable_resolution_produces_an_absolute_file_boundary() {
        let current = std::env::current_exe().expect("current test executable");
        let resolved = resolve_provider_executable(&current).expect("resolve current executable");
        assert!(resolved.is_absolute());
        assert!(resolved.is_file());

        let missing = std::env::temp_dir().join(format!(
            "egopulse-missing-provider-executable-{}",
            Uuid::now_v7()
        ));
        assert_eq!(resolve_provider_executable(&missing), None);

        let ordinary_file = std::env::temp_dir().join(format!(
            "egopulse-non-executable-provider-{}.txt",
            Uuid::now_v7()
        ));
        fs::write(&ordinary_file, b"not an executable").expect("write ordinary file");
        assert_eq!(resolve_provider_executable(&ordinary_file), None);
        fs::remove_file(ordinary_file).expect("remove ordinary file");

        assert!(provider_command_extensions(Path::new("codex.exe")).is_empty());
        assert!(provider_command_extensions(Path::new("codex.cmd")).is_empty());
    }

    #[test]
    fn production_verification_boundary_denies_all_unreviewed_references() {
        let resolver = DenyVerificationReferences;
        assert_eq!(
            resolver.validate_checker_profile(&CheckerProfile::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.resolve_request(&VerificationRequest::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.revalidate_binding(&VerificationBinding::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.validate_result_references(&[], &[]),
            Err(ReferenceRejection::OutputUntrusted)
        );
    }

    #[test]
    fn user_owned_file_rejects_malformed_json_before_opening_any_store() {
        let path = std::env::temp_dir().join(format!("egopulse-bootstrap-{}.json", Uuid::now_v7()));
        fs::write(
            &path,
            br#"{"schema_version": "egopulse.production-bootstrap/v2", "unknown": true}"#,
        )
        .expect("write malformed bootstrap fixture");
        assert!(matches!(
            ProductionBootstrapConfig::from_user_file(&path),
            Err(ProductionBootstrapError::ConfigurationFormat { .. })
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn work_capability_config_migration_is_explicit_complete_and_reversible() {
        let directory = tempfile::tempdir().expect("migration tempdir");
        let path = directory.path().join("agentos-config.json");
        let original = packaged_v2_config_bytes();
        fs::write(&path, &original).expect("write v2 config");

        let preview =
            preview_work_capability_config_migration(&path).expect("preview v2 migration");
        assert!(!preview.applied);
        assert_eq!(preview.from_schema_version, PRODUCTION_BOOTSTRAP_V2);
        assert_eq!(preview.to_schema_version, PRODUCTION_BOOTSTRAP_V3);
        assert_eq!(preview.preference_revision, 1);
        assert_eq!(preview.harness_model_id, "gpt-5.6-sol");
        assert_eq!(fs::read(&path).expect("read after preview"), original);
        assert!(!Path::new(&preview.retained_backup_path).exists());

        let applied = apply_work_capability_config_migration(&path).expect("apply v2 migration");
        assert!(applied.applied);
        assert_eq!(applied.route_binding_sha256.len(), 64);
        assert_eq!(
            fs::read(&applied.retained_backup_path).expect("retained v2 backup"),
            original
        );
        let migrated = fs::read(&path).expect("read migrated v3");
        let migrated_value: serde_json::Value =
            serde_json::from_slice(&migrated).expect("parse migrated v3");
        assert_eq!(migrated_value["schema_version"], PRODUCTION_BOOTSTRAP_V3);
        assert_eq!(
            migrated_value["work_capabilities"]["default_choice_id"],
            applied.choice_id
        );
        assert_eq!(
            migrated_value["work_capabilities"]["routes"][0]["route_binding_sha256"],
            applied.route_binding_sha256
        );

        let rollback_preview =
            preview_work_capability_config_rollback(&path).expect("preview v2 rollback");
        assert!(!rollback_preview.applied);
        assert_eq!(
            rollback_preview.from_schema_version,
            PRODUCTION_BOOTSTRAP_V3
        );
        assert_eq!(rollback_preview.to_schema_version, PRODUCTION_BOOTSTRAP_V2);
        assert_eq!(
            fs::read(&path).expect("rollback preview is read-only"),
            migrated
        );

        let rolled_back = rollback_work_capability_config_to_v2(&path).expect("apply v2 rollback");
        assert!(rolled_back.applied);
        assert_eq!(fs::read(&path).expect("restored v2"), original);
        assert_eq!(
            fs::read(&rolled_back.retained_backup_path).expect("retained v3 rollback backup"),
            migrated
        );
    }

    #[test]
    fn work_capability_config_rollback_rejects_any_post_migration_drift() {
        let directory = tempfile::tempdir().expect("migration tempdir");
        let path = directory.path().join("agentos-config.json");
        let original = packaged_v2_config_bytes();
        fs::write(&path, original).expect("write v2 config");
        apply_work_capability_config_migration(&path).expect("apply v2 migration");

        let mut current: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read v3")).expect("parse v3");
        current["work_capabilities"]["preference_revision"] = serde_json::json!(2);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&current).expect("render drifted v3"),
        )
        .expect("write drifted v3");
        let before = fs::read(&path).expect("read drifted bytes");

        assert!(matches!(
            preview_work_capability_config_rollback(&path),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "rollback requires the unchanged initial v3 migration state"
            ))
        ));
        assert!(matches!(
            rollback_work_capability_config_to_v2(&path),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "rollback requires the unchanged initial v3 migration state"
            ))
        ));
        assert_eq!(fs::read(&path).expect("drift remains untouched"), before);
        assert!(
            !transition_backup_path(&path, V3_ROLLBACK_BACKUP_SUFFIX)
                .expect("rollback backup path")
                .exists()
        );
    }

    #[test]
    fn user_owned_memory_candidate_binding_freezes_runtime_identity_at_composition() {
        let binding = MemoryCandidateProducerFile {
            producer_id: "harness:codex".to_owned(),
            principal_id: "harness:codex".to_owned(),
            principal_kind: "Harness".to_owned(),
            scope_ref: "scope:founder".to_owned(),
        }
        .into_typed()
        .expect("valid candidate producer binding");

        assert_eq!(binding.producer_id, "harness:codex");
        assert_eq!(binding.principal_id, "harness:codex");
        assert_eq!(binding.principal_kind, MemoryPrincipalKind::Harness);
        assert_eq!(binding.scope_ref, "scope:founder");
    }

    #[test]
    fn user_owned_memory_candidate_binding_rejects_governance_identity_or_unknown_kind() {
        for principal_kind in ["Founder", "GovernanceKernel", "unknown"] {
            let result = MemoryCandidateProducerFile {
                producer_id: "harness:codex".to_owned(),
                principal_id: "harness:codex".to_owned(),
                principal_kind: principal_kind.to_owned(),
                scope_ref: "scope:founder".to_owned(),
            }
            .into_typed();

            assert!(matches!(
                result,
                Err(ProductionBootstrapError::InvalidConfiguration(
                    "memory_candidate_producers.principal_kind"
                ))
            ));
        }
    }

    #[test]
    fn user_owned_memory_candidate_binding_rejects_invalid_route_without_opening_authority() {
        let result = MemoryCandidateProducerFile {
            producer_id: " ".to_owned(),
            principal_id: "harness:codex".to_owned(),
            principal_kind: "Harness".to_owned(),
            scope_ref: "scope:founder".to_owned(),
        }
        .into_typed();

        assert!(matches!(
            result,
            Err(ProductionBootstrapError::InvalidConfiguration(
                "memory_candidate_producers"
            ))
        ));
    }

    #[test]
    fn provider_profile_keeps_catalog_and_exact_selected_model_separate() {
        let profile = ProviderProfileFile {
            profile_id: "glm".to_owned(),
            provider: "glm".to_owned(),
            harness: "opencode_acp".to_owned(),
            admission: "held".to_owned(),
            exact_model: None,
            model_ids: Vec::new(),
            models: vec![ProviderModelFile {
                harness_model_id: "zai/glm-5.3".to_owned(),
                provider_model_id: "glm-5.3".to_owned(),
            }],
            catalog_snapshot: Some(ProviderCatalogSnapshotFile {
                source: "offline-fallback:provider-docs".to_owned(),
                fetched_at: "2026-08-27T00:00:00Z".to_owned(),
                harness_version: "opencode-unverified".to_owned(),
                evidence_digest_sha256: "a".repeat(64),
            }),
            selected_model: Some("zai/glm-5.3".to_owned()),
            executable: "opencode".to_owned(),
            credential: ProviderCredentialFile::HarnessAccount,
            hold_reason: Some("pending authenticated lifecycle".to_owned()),
        }
        .into_typed()
        .expect("model catalog should decode");

        assert_eq!(profile.exact_model, "zai/glm-5.3");
        assert_eq!(
            profile.models,
            [ProviderModelBinding {
                harness_model_id: "zai/glm-5.3".to_owned(),
                provider_model_id: "glm-5.3".to_owned(),
            }]
        );
        assert!(matches!(
            profile.credential,
            ProviderCredentialReference::HarnessAccount
        ));
        assert_eq!(
            profile.catalog_snapshot,
            Some(ProviderCatalogSnapshot {
                source: "offline-fallback:provider-docs".to_owned(),
                fetched_at: "2026-08-27T00:00:00Z".to_owned(),
                harness_version: "opencode-unverified".to_owned(),
                evidence_digest_sha256: "a".repeat(64),
            })
        );
    }

    #[test]
    fn gpt_candidate_profiles_can_bind_each_known_harness_without_production_admission() {
        let harnesses = [
            ("codex_app_server", ProviderHarnessKind::CodexAppServer),
            ("dsh_acp", ProviderHarnessKind::DshAcp),
            ("kimi_cli_acp", ProviderHarnessKind::KimiCliAcp),
            ("opencode_acp", ProviderHarnessKind::OpenCodeAcp),
        ];
        let mut profiles = Vec::new();

        for (harness_name, expected_harness) in harnesses {
            let profile = ProviderProfileFile {
                profile_id: format!("gpt-{harness_name}"),
                provider: "gpt".to_owned(),
                harness: harness_name.to_owned(),
                admission: "held".to_owned(),
                exact_model: None,
                model_ids: Vec::new(),
                models: vec![ProviderModelFile {
                    harness_model_id: "gpt-cross-harness-test".to_owned(),
                    provider_model_id: "gpt-cross-harness-test".to_owned(),
                }],
                catalog_snapshot: None,
                selected_model: Some("gpt-cross-harness-test".to_owned()),
                executable: harness_name.to_owned(),
                credential: ProviderCredentialFile::HarnessAccount,
                hold_reason: Some("real authentication is outside this release gate".to_owned()),
            }
            .into_typed()
            .expect("known Provider and Harness identities should compose as held data");

            assert_eq!(profile.provider, ProviderId::Gpt);
            assert_eq!(profile.harness, expected_harness);
            assert_eq!(profile.admission, ProviderAdmission::Held);
            profiles.push(profile);
        }

        validate_provider_profiles(&profiles)
            .expect("held cross-Harness profiles must remain valid configuration");

        let mut unproven_production_profile = profiles[1].clone();
        unproven_production_profile.admission = ProviderAdmission::Production;
        assert!(matches!(
            validate_provider_profiles(&[unproven_production_profile]),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_admission_pending"
            ))
        ));
    }

    #[test]
    fn deepseek_dsh_production_route_is_founder_promoted() {
        let profile = ProviderProfileFile {
            profile_id: "deepseek-dsh-production".to_owned(),
            provider: "deepseek".to_owned(),
            harness: "dsh_acp".to_owned(),
            admission: "production".to_owned(),
            exact_model: None,
            model_ids: Vec::new(),
            models: vec![ProviderModelFile {
                harness_model_id: "deepseek-v4-pro".to_owned(),
                provider_model_id: "deepseek-v4-pro".to_owned(),
            }],
            catalog_snapshot: None,
            selected_model: Some("deepseek-v4-pro".to_owned()),
            executable: "dsh".to_owned(),
            credential: ProviderCredentialFile::ApiKeyEnvironment {
                source_env: "DEEPSEEK_API_KEY".to_owned(),
                target_env: "DEEPSEEK_API_KEY".to_owned(),
            },
            hold_reason: None,
        }
        .into_typed()
        .expect("deepseek/dsh profile composes");

        validate_provider_profiles(&[profile])
            .expect("Founder-promoted deepseek/dsh production route is admissible");

        // A pairing outside the table (deepseek over the kimi CLI) stays
        // rejected: promotion is per route, not per provider.
        let cross_harness = ProviderProfileFile {
            profile_id: "deepseek-kimi-production".to_owned(),
            provider: "deepseek".to_owned(),
            harness: "kimi_cli_acp".to_owned(),
            admission: "production".to_owned(),
            exact_model: None,
            model_ids: Vec::new(),
            models: vec![ProviderModelFile {
                harness_model_id: "deepseek-v4-pro".to_owned(),
                provider_model_id: "deepseek-v4-pro".to_owned(),
            }],
            catalog_snapshot: None,
            selected_model: Some("deepseek-v4-pro".to_owned()),
            executable: "codex".to_owned(),
            credential: ProviderCredentialFile::HarnessAccount,
            hold_reason: None,
        }
        .into_typed()
        .expect("deepseek/codex profile composes as configuration");

        assert!(matches!(
            validate_provider_profiles(&[cross_harness]),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_admission_pending"
            ))
        ));
    }

    #[test]
    fn provider_catalog_snapshot_rejects_noncanonical_evidence_digest() {
        let result = ProviderCatalogSnapshotFile {
            source: "harness".to_owned(),
            fetched_at: "2026-08-27T00:00:00Z".to_owned(),
            harness_version: "1.0.0".to_owned(),
            evidence_digest_sha256: "A".repeat(64),
        }
        .into_typed();

        assert!(matches!(
            result,
            Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.catalog_snapshot.evidence_digest_sha256"
            ))
        ));
    }

    #[test]
    fn provider_catalog_refresh_preserves_an_available_exact_selection() {
        let profile = ProviderBootstrapProfile {
            profile_id: "deepseek".to_owned(),
            provider: ProviderId::DeepSeek,
            harness: ProviderHarnessKind::DshAcp,
            admission: ProviderAdmission::Candidate,
            models: vec![ProviderModelBinding {
                harness_model_id: "deepseek-chat".to_owned(),
                provider_model_id: "deepseek-chat".to_owned(),
            }],
            catalog_snapshot: None,
            exact_model: "deepseek-chat".to_owned(),
            executable: "dsh".into(),
            credential: ProviderCredentialReference::ApiKeyEnvironment {
                source_env: "DEEPSEEK_API_KEY".to_owned(),
                target_env: "DEEPSEEK_API_KEY".to_owned(),
            },
            hold_reason: Some("candidate".to_owned()),
        };

        let preview = profile
            .preview_catalog_refresh(&[
                ProviderModelBinding {
                    harness_model_id: "deepseek-reasoner".to_owned(),
                    provider_model_id: "deepseek-reasoner".to_owned(),
                },
                ProviderModelBinding {
                    harness_model_id: "deepseek-chat".to_owned(),
                    provider_model_id: "deepseek-chat".to_owned(),
                },
            ])
            .expect("valid refreshed catalog");

        assert!(preview.selected_model_available);
        assert!(!preview.selection_changed);
        assert!(!preview.requires_user_action);
        assert_eq!(preview.selected_model, "deepseek-chat");
        assert_eq!(preview.models[0].harness_model_id, "deepseek-chat");
    }

    #[test]
    fn provider_catalog_refresh_never_falls_back_when_selection_disappears() {
        let profile = ProviderBootstrapProfile {
            profile_id: "kimi".to_owned(),
            provider: ProviderId::Kimi,
            harness: ProviderHarnessKind::KimiCliAcp,
            admission: ProviderAdmission::Held,
            models: vec![ProviderModelBinding {
                harness_model_id: "kimi-k2.5".to_owned(),
                provider_model_id: "kimi-k2.5".to_owned(),
            }],
            catalog_snapshot: None,
            exact_model: "kimi-k2.5".to_owned(),
            executable: "kimi".into(),
            credential: ProviderCredentialReference::HarnessAccount,
            hold_reason: Some("pending".to_owned()),
        };

        let preview = profile
            .preview_catalog_refresh(&[ProviderModelBinding {
                harness_model_id: "kimi-k2.6".to_owned(),
                provider_model_id: "kimi-k2.6".to_owned(),
            }])
            .expect("valid refreshed catalog");

        assert!(!preview.selected_model_available);
        assert!(!preview.selection_changed);
        assert!(preview.requires_user_action);
        assert_eq!(preview.selected_model, "kimi-k2.5");
        assert_eq!(
            preview.reason_code.as_deref(),
            Some("selected_model_missing_from_refresh")
        );
    }

    #[test]
    fn provider_catalog_refresh_rejects_empty_invalid_and_duplicate_models() {
        let profile = ProviderBootstrapProfile {
            profile_id: "glm".to_owned(),
            provider: ProviderId::Glm,
            harness: ProviderHarnessKind::OpenCodeAcp,
            admission: ProviderAdmission::Held,
            models: vec![ProviderModelBinding {
                harness_model_id: "zai/glm-5.3".to_owned(),
                provider_model_id: "glm-5.3".to_owned(),
            }],
            catalog_snapshot: None,
            exact_model: "zai/glm-5.3".to_owned(),
            executable: "opencode".into(),
            credential: ProviderCredentialReference::HarnessAccount,
            hold_reason: Some("pending".to_owned()),
        };

        assert_eq!(
            profile.preview_catalog_refresh(&[]),
            Err(ProviderCatalogRefreshError::EmptyCatalog)
        );
        assert_eq!(
            profile.preview_catalog_refresh(&[ProviderModelBinding {
                harness_model_id: " ".to_owned(),
                provider_model_id: "glm-5.3".to_owned(),
            }]),
            Err(ProviderCatalogRefreshError::InvalidModelIdentity(
                "harness model identity"
            ))
        );
        assert_eq!(
            profile.preview_catalog_refresh(&[
                ProviderModelBinding {
                    harness_model_id: "zai/glm-5.3".to_owned(),
                    provider_model_id: "glm-5.3".to_owned(),
                },
                ProviderModelBinding {
                    harness_model_id: "zai/glm-5.3".to_owned(),
                    provider_model_id: "glm-5.3-alias".to_owned(),
                },
            ]),
            Err(ProviderCatalogRefreshError::DuplicateHarnessModelId)
        );
    }

    #[test]
    fn provider_profile_rejects_selected_model_outside_catalog() {
        let result = ProviderProfileFile {
            profile_id: "deepseek".to_owned(),
            provider: "deepseek".to_owned(),
            harness: "dsh_acp".to_owned(),
            admission: "held".to_owned(),
            exact_model: None,
            model_ids: vec!["deepseek-chat".to_owned()],
            models: Vec::new(),
            catalog_snapshot: None,
            selected_model: Some("deepseek-reasoner".to_owned()),
            executable: "dsh".to_owned(),
            credential: ProviderCredentialFile::ApiKeyEnvironment {
                source_env: "DEEPSEEK_API_KEY".to_owned(),
                target_env: "DEEPSEEK_API_KEY".to_owned(),
            },
            hold_reason: Some("pending".to_owned()),
        }
        .into_typed();

        assert!(matches!(
            result,
            Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.selected_model_not_in_model_ids"
            ))
        ));
    }

    #[test]
    fn user_owned_worker_contract_decodes_all_execution_boundaries_explicitly() {
        let reference = serde_json::json!({
            "contract_id": "criterion:one",
            "version": "v1",
            "sha256": "a".repeat(64)
        });
        let value = serde_json::json!({
            "handoff": {
                "claim_id": "claim:one",
                "claim_semantic_profile_ref": reference,
                "criterion_ids": ["criterion:one"],
                "checker_profile_refs": [{
                    "contract_id": "checker-profile:one",
                    "version": "v1",
                    "sha256": "b".repeat(64)
                }]
            },
            "checker_profile": {
                "checker_profile_id": "checker-profile:one",
                "revision": 1,
                "status": 1,
                "checker_id": "sego",
                "checker_version": "v1",
                "input_contract_ref": null,
                "output_contract_ref": null,
                "supported_criterion_types": ["criterion:one"],
                "assurance_class": 2,
                "sandbox_profile_ref": null,
                "tool_policy_ref": null,
                "data_egress_policy_ref": null,
                "timeout_ms": 1000,
                "network_allowed": false,
                "profile_digest_sha256": "b".repeat(64),
                "attestation_evidence_artifact_ids": ["artifact:probe"],
                "attested_at": {"seconds": 1700000000, "nanos": 0}
            },
            "checker_executable": "C:/tools/sego.exe",
            "checker_arguments": ["--check"],
            "working_directory": "C:/workspace",
            "checker_request_hex": "7b7d",
            "mapper": {
                "criterion_id": "criterion:one",
                "requirement": 1,
                "checker_profile_ref": {
                    "contract_id": "checker-profile:one",
                    "version": "v1",
                    "sha256": "b".repeat(64)
                },
                "expected_scope": "scope:one",
                "expected_diff_hash": "c".repeat(64),
                "expected_reviewer": "reviewer:one",
                "expected_engine_version": "sego-v1",
                "expected_review_mode": "strict",
                "failure_threshold": 2,
                "raw_output_artifact_id": "artifact:raw",
                "raw_output_address": {
                    "algorithm": 1,
                    "digest": "d".repeat(64),
                    "byte_length": 2
                },
                "finding_evidence": {}
            },
            "verification_run_id_prefix": "run:",
            "verification_artifact_id_prefix": "artifact:verification:",
            "execution_id_prefix": "execution:",
            "tool_receipt_artifact_ids": [],
            "model_call_receipt_artifact_ids": [],
            "checker_timeout_ms": 1000,
            "checker_output_limit": 4096,
            "checker_output_source": "envelope_artifact_path",
            "checker_output_capture": {
                "raw_output_type_ref": {
                    "contract_id": "verification-raw-output",
                    "version": "v1",
                    "sha256": "e".repeat(64)
                },
                "retention_profile_ref": {
                    "contract_id": "verification-records",
                    "version": "v1",
                    "sha256": "f".repeat(64)
                },
                "collector_principal_id": "collector:checker-output",
                "artifact_authority_principal_id": "authority:artifact",
                "max_output_bytes": 1048576
            }
        });

        let mut unknown_output_source = value.clone();
        unknown_output_source["checker_output_source"] = serde_json::json!("stdout_files");
        let file: VerificationWorkerFile = serde_json::from_value(value).expect("worker JSON");
        let config = file.into_typed().expect("typed worker config");
        assert_eq!(config.checker_request, b"{}".to_vec());
        assert_eq!(config.handoff_plan.criterion_ids, ["criterion:one"]);
        assert_eq!(
            config.checker_profile.checker_profile_id,
            "checker-profile:one"
        );
        assert_eq!(
            config.mapper_policy.raw_output_address.algorithm,
            HashAlgorithm::Sha256 as i32
        );
        assert_eq!(config.checker_timeout, Duration::from_millis(1000));
        assert_eq!(
            config.output_source,
            egopulse_verification_authority::CheckerOutputSource::EnvelopeArtifactPath
        );
        let capture = config
            .checker_output_capture
            .as_ref()
            .expect("declared output capture");
        assert_eq!(capture.collector_principal_id, "collector:checker-output");
        assert_eq!(capture.max_output_bytes, 1_048_576);
        // The sink itself is composed at the application boundary, so a
        // parsed declaration alone stays inert.
        assert!(config.checker_output_sink.is_none());

        let rejected = serde_json::from_value::<VerificationWorkerFile>(unknown_output_source)
            .expect("worker JSON")
            .into_typed();
        assert!(matches!(
            rejected,
            Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_output_source"
            ))
        ));
    }

    #[test]
    fn user_owned_worker_contract_rejects_invalid_hex_and_hash_algorithm() {
        let mut value = serde_json::json!({
            "handoff": {
                "claim_id": "claim:one",
                "claim_semantic_profile_ref": {
                    "contract_id": "claim-profile:one",
                    "version": "v1",
                    "sha256": "a".repeat(64)
                },
                "criterion_ids": ["criterion:one"],
                "checker_profile_refs": []
            },
            "checker_profile": {
                "checker_profile_id": "checker-profile:one",
                "revision": 1,
                "status": 1,
                "checker_id": "sego",
                "checker_version": "v1",
                "input_contract_ref": null,
                "output_contract_ref": null,
                "supported_criterion_types": ["criterion:one"],
                "assurance_class": 2,
                "sandbox_profile_ref": null,
                "tool_policy_ref": null,
                "data_egress_policy_ref": null,
                "timeout_ms": 1000,
                "network_allowed": false,
                "profile_digest_sha256": "b".repeat(64),
                "attestation_evidence_artifact_ids": [],
                "attested_at": null
            },
            "checker_executable": "C:/tools/sego.exe",
            "working_directory": "C:/workspace",
            "checker_request_hex": "not-hex",
            "mapper": {
                "criterion_id": "criterion:one",
                "requirement": 1,
                "checker_profile_ref": {
                    "contract_id": "checker-profile:one",
                    "version": "v1",
                    "sha256": "b".repeat(64)
                },
                "expected_scope": "scope:one",
                "expected_diff_hash": "c".repeat(64),
                "expected_reviewer": "reviewer:one",
                "expected_engine_version": "sego-v1",
                "expected_review_mode": "strict",
                "failure_threshold": 2,
                "raw_output_artifact_id": "artifact:raw",
                "raw_output_address": {"algorithm": 99, "digest": "d", "byte_length": 1},
                "finding_evidence": {}
            },
            "verification_run_id_prefix": "run:",
            "verification_artifact_id_prefix": "artifact:verification:",
            "execution_id_prefix": "execution:",
            "checker_timeout_ms": 1000,
            "checker_output_limit": 4096
        });
        let file: VerificationWorkerFile =
            serde_json::from_value(value.clone()).expect("worker JSON");
        assert!(matches!(
            file.into_typed(),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.checker_request_hex"
            ))
        ));

        value["checker_request_hex"] = serde_json::Value::String("7b7d".to_owned());
        let file: VerificationWorkerFile = serde_json::from_value(value).expect("worker JSON");
        assert!(matches!(
            file.into_typed(),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "verification_worker.mapper.raw_output_address.algorithm"
            ))
        ));
    }

    #[test]
    fn context_revoke_permission_requires_explicit_founder_binding() {
        let revoke_permission = BTreeSet::from(["local.context.revoke".to_owned()]);
        assert!(matches!(
            validate_context_permission_binding(&revoke_permission, None),
            Err(ProductionBootstrapError::InvalidConfiguration(
                "identity.context_kind"
            ))
        ));
        assert!(
            validate_context_permission_binding(
                &revoke_permission,
                Some(ContextPrincipalKind::Founder)
            )
            .is_ok()
        );
        assert!(
            validate_context_permission_binding(
                &BTreeSet::from(["local.task.read".to_owned()]),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn context_identity_binding_accepts_only_founder() {
        assert_eq!(
            parse_context_principal("Founder").expect("Founder Context binding"),
            ContextPrincipalKind::Founder
        );
        for invalid in ["GovernanceKernel", "ContextCompiler", "none", "founder"] {
            assert!(matches!(
                parse_context_principal(invalid),
                Err(ProductionBootstrapError::InvalidConfiguration(
                    "identity.context_kind"
                ))
            ));
        }
    }
}
