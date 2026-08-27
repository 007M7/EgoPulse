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
    verification::v1::{CheckerProfile, VerificationBinding, VerificationRequest},
};
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
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, ReferenceRejection, ResolvedVerificationInput,
    SegoFindingEvidenceBinding, SegoMapperPolicy, VerificationAuthority,
    VerificationAuthorityConfig, VerificationAuthorityFailure, VerificationReferenceResolver,
    VerificationSqlCipherKey,
};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AllowlistedPrincipal, AllowlistedPrincipalResolver, PrincipalPolicyError};
use crate::{
    ArtifactAuthorityReferenceSource, ArtifactProjectionSource, AuthorityPrincipalBinding,
    CodexHarnessCompositionConfig, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredAuthorityPrincipalResolver,
    ConfiguredFounderVerdictResolver, ConfiguredFounderVerdictResolverConfig,
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, ConfiguredTaskTransitionGuard,
    ConfiguredVerificationWorker, DaemonCompositionError, DaemonProviders,
    FounderVerdictConfigurationError, GovernedReturnCollectorConfig, LocalUserPolicyResolver,
    LocalUserPolicyResolverConfig, MemoryCandidateProducerBinding,
    MemoryRetrievalCompositionConfig, NativeHarnessCompositionConfig,
    SharedAuthorityCompositionInputs, TaskAuthorityCommitReceiptSource,
    VerificationAuthorityArtifactSource, VerificationProjectionSource, VerificationWorkerConfig,
};

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
    // An extension does not make a command an explicit path: `codex.cmd` is
    // still a valid PATH lookup on Windows. Only a path-like value should be
    // checked relative to the current filesystem location.
    if executable.components().count() > 1 {
        return executable.is_file();
    }
    let Some(path_value) = std::env::var_os("PATH") else {
        return false;
    };
    let candidates =
        std::env::split_paths(&path_value).flat_map(|directory| {
            let direct = directory.join(executable);
            let extensions = if cfg!(windows) {
                std::env::var_os("PATHEXT")
                    .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into())
                    .to_string_lossy()
                    .split(';')
                    .filter(|extension| !extension.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            std::iter::once(direct).chain(extensions.into_iter().map(move |extension| {
                directory.join(format!("{}{}", executable.display(), extension))
            }))
        });
    candidates.into_iter().any(|candidate| candidate.is_file())
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
    fn as_str(self) -> &'static str {
        match self {
            Self::Gpt => "gpt",
            Self::DeepSeek => "deepseek",
            Self::Kimi => "kimi",
            Self::Glm => "glm",
        }
    }
}

impl ProviderHarnessKind {
    fn as_str(self) -> &'static str {
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
    pub policy: PolicyAuthorityConfig,
    pub policy_resolver: LocalUserPolicyBootstrapConfig,
    pub verdict: VerdictAuthorityConfig,
    pub allowed_founder_principal_ids: BTreeSet<String>,
    pub founder_authority_ref: String,
    pub founder_authority_policy_ref: ContractReference,
    pub allowed_confirmation_proof_refs: BTreeSet<String>,
    pub non_overridable_gate_ids: BTreeSet<String>,
    pub founder_confirmation_ttl: Duration,
    pub os_principal: AllowlistedPrincipal,
    pub authority_binding: AuthorityPrincipalBinding,
    pub provider_profiles: Vec<ProviderBootstrapProfile>,
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
        file.into_typed()
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
    pub fn build(self) -> Result<DaemonProviders, ProductionBootstrapError> {
        let task_guard = ConfiguredTaskCreationGuard::new(self.task_guard)?;
        let founder_verdict_handle = Arc::new(Mutex::new(None));
        let task = Arc::new(Mutex::new(TaskAuthority::open_with_transition_guard(
            self.task,
            task_guard,
            ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(
                &founder_verdict_handle,
            )),
        )?));
        let memory = Arc::new(Mutex::new(MemoryAuthority::open(self.memory)?));

        let artifact_guard = ConfiguredArtifactAdmissionGuard::new(self.artifact_guard)?;
        let artifact = Arc::new(Mutex::new(ArtifactAuthority::open(
            self.artifact,
            artifact_guard,
        )?));

        let verification_resolver: Box<dyn VerificationReferenceResolver> =
            match self.verification_references {
                Some(config) => Box::new(
                    ArtifactBackedReferenceResolver::new(
                        ArtifactAuthorityReferenceSource::new_shared(Arc::clone(&artifact)),
                        config.criteria,
                    )
                    .map_err(|_| {
                        ProductionBootstrapError::InvalidConfiguration("verification.criteria")
                    })?,
                ),
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

        let policy_edge = AdapterEdge::open(self.policy_resolver.edge)?;
        let policy_resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge: policy_edge,
            adapter_id: egopulse_codex_adapter::CODEX_ADAPTER_ID.to_owned(),
            authorization_policy_ref: self.policy_resolver.authorization_policy_ref,
            authentication_context_ref: self.policy_resolver.authentication_context_ref,
            allowed_scope_refs: self.policy_resolver.allowed_scope_refs,
            decision_ttl: self.policy_resolver.decision_ttl,
        })?;
        let policy = PolicyDecisionAuthority::open(self.policy, policy_resolver)?;

        let founder_resolver =
            ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
                verification_source: Box::new(VerificationAuthorityArtifactSource::new_shared(
                    Arc::clone(&verification),
                )),
                task_commit_source: Box::new(TaskAuthorityCommitReceiptSource::new(Arc::clone(
                    &task,
                ))),
                allowed_founder_principal_ids: self.allowed_founder_principal_ids,
                authority_ref: self.founder_authority_ref,
                authority_policy_ref: self.founder_authority_policy_ref,
                allowed_confirmation_proof_refs: self.allowed_confirmation_proof_refs,
                non_overridable_gate_ids: self.non_overridable_gate_ids,
                confirmation_ttl: self.founder_confirmation_ttl,
            })?;
        let verdict = FounderVerdictAuthority::open(self.verdict, founder_resolver)?;
        *founder_verdict_handle
            .lock()
            .map_err(|_| ProductionBootstrapError::InvalidConfiguration("verdict handle"))? =
            Some(verdict);

        let principal_resolver = Arc::new(ConfiguredAuthorityPrincipalResolver::new([
            self.authority_binding
        ])?);
        let memory_principal_resolver = Arc::clone(&principal_resolver);
        let session_principal_resolver =
            Arc::new(AllowlistedPrincipalResolver::new([self.os_principal])?);
        let mut providers =
            DaemonProviders::from_shared_authority_inputs(SharedAuthorityCompositionInputs {
                task: Arc::clone(&task),
                policy,
                verdict: founder_verdict_handle,
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
            });
        if let Some(worker_config) = self.verification_worker {
            let worker = ConfiguredVerificationWorker::new(
                task,
                Box::new(ArtifactAuthorityReferenceSource::new_shared(Arc::clone(
                    &artifact,
                ))),
                Arc::clone(&verification),
                worker_config,
            )
            .map_err(ProductionBootstrapError::VerificationWorker)?;
            providers = providers.with_verification_worker(Arc::new(worker));
        }
        if let Some(memory_retrieval) = self.memory_retrieval {
            providers = providers.with_memory_retrieval(Arc::clone(&memory), memory_retrieval)?;
        }
        providers = providers.with_memory_mutation(Arc::clone(&memory), memory_principal_resolver);
        if !self.memory_candidate_producers.is_empty() {
            providers = providers.with_memory_candidate_producers(
                Arc::clone(&memory),
                self.memory_candidate_producers,
            )?;
        }
        providers = providers.with_codex_harness(self.codex, artifact, verification)?;
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
    artifact: ArtifactPolicyFile,
    #[serde(default)]
    verification: Option<VerificationFile>,
    #[serde(default)]
    verification_worker: Option<VerificationWorkerFile>,
    #[serde(default)]
    memory_retrieval: Option<MemoryRetrievalFile>,
    #[serde(default)]
    memory_candidate_producers: Vec<MemoryCandidateProducerFile>,
    policy: PolicyFile,
    founder: FounderFile,
    #[serde(default)]
    provider_profiles: Vec<ProviderProfileFile>,
    codex: CodexFile,
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
        validate_provider_harness(provider, harness)?;
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

fn validate_provider_harness(
    provider: ProviderId,
    harness: ProviderHarnessKind,
) -> Result<(), ProductionBootstrapError> {
    let valid = matches!(
        (provider, harness),
        (ProviderId::Gpt, ProviderHarnessKind::CodexAppServer)
            | (ProviderId::DeepSeek, ProviderHarnessKind::DshAcp)
            | (ProviderId::Kimi, ProviderHarnessKind::KimiCliAcp)
            | (ProviderId::Glm, ProviderHarnessKind::OpenCodeAcp)
    );
    if valid {
        Ok(())
    } else {
        Err(ProductionBootstrapError::InvalidConfiguration(
            "provider_profiles.provider_harness_mapping",
        ))
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
            if profile.provider != ProviderId::Gpt
                || profile.harness != ProviderHarnessKind::CodexAppServer
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
    fn into_typed(self) -> Result<ProductionBootstrapConfig, ProductionBootstrapError> {
        if self.schema_version != "egopulse.production-bootstrap/v2" {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "schema_version",
            ));
        }
        let provider_profiles = self
            .provider_profiles
            .into_iter()
            .map(ProviderProfileFile::into_typed)
            .collect::<Result<Vec<_>, _>>()?;
        validate_provider_profiles(&provider_profiles)?;
        let gpt_environment_overrides = provider_profiles
            .iter()
            .find(|profile| {
                profile.provider == ProviderId::Gpt
                    && profile.admission == ProviderAdmission::Production
            })
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
        let grant = egopulse_local_api::session::PrincipalGrant {
            authenticated_principal_id: principal_id.clone(),
            permission_codes: non_empty_set(
                identity.permission_codes,
                "identity.permission_codes",
            )?,
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

        let workflow = self.codex.workflow.into_typed()?;
        if !artifact_guard
            .allowed_workspace_refs
            .contains(&workflow.workspace_ref)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "artifact.allowed_workspace_refs must include codex.workflow.workspace_ref",
            ));
        }
        let return_collector = GovernedReturnCollectorConfig {
            artifact_type_ref: artifact_guard
                .allowed_artifact_type_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_artifact_type_refs",
                ))?,
            transformation_contract_ref: artifact_guard
                .allowed_transformation_contract_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_transformation_contract_refs",
                ))?,
            retention_profile_ref: artifact_guard
                .allowed_retention_profile_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_retention_profile_refs",
                ))?,
            claim_semantic_profile_ref: artifact_guard
                .allowed_claim_semantic_profile_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_claim_semantic_profile_refs",
                ))?,
            claim_acceptance_contract_ref: artifact_guard
                .allowed_claim_acceptance_contract_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_claim_acceptance_contract_refs",
                ))?,
            evidence_profile_ref: artifact_guard
                .allowed_evidence_profile_refs
                .first()
                .cloned()
                .ok_or(ProductionBootstrapError::InvalidConfiguration(
                    "artifact.allowed_evidence_profile_refs",
                ))?,
            workspace_ref: workflow.workspace_ref.clone(),
            collector_principal_id: "collector:terminal-output".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
        };
        let codex = CodexHarnessCompositionConfig {
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
            environment_overrides: gpt_environment_overrides,
        };
        if let Some(profile) = provider_profiles.iter().find(|profile| {
            profile.provider == ProviderId::Gpt
                && profile.admission == ProviderAdmission::Production
        }) && (codex.native.default_model.as_deref() != Some(profile.exact_model.as_str())
            || codex.codex_executable != profile.executable)
        {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "provider_profiles.production_codex_binding",
            ));
        }

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
            policy: PolicyAuthorityConfig {
                database_path: policy_store.database_path,
                store_epoch: policy_store.store_epoch,
                key: PolicySqlCipherKey::new(policy_store.key),
            },
            policy_resolver: LocalUserPolicyBootstrapConfig {
                edge: AdapterEdgeConfig {
                    database_path: adapter_store.database_path,
                    adapter_id: egopulse_codex_adapter::CODEX_ADAPTER_ID.to_owned(),
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
        Ok(SegoMapperPolicy {
            criterion_id: self.criterion_id,
            requirement,
            checker_profile_ref: self.checker_profile_ref.into_typed(),
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
    #[error("required bootstrap secret is missing: {0}")]
    MissingSecret(String),
    #[error("bootstrap secret is not a non-zero 32-byte hex value: {0}")]
    InvalidSecret(String),
    #[error("Task creation guard configuration is invalid")]
    TaskGuard(#[from] crate::TaskCreationGuardConfigurationError),
    #[error("Task Authority could not be opened")]
    TaskAuthority(#[from] TaskAuthorityFailure),
    #[error("Memory Authority could not be opened")]
    MemoryAuthority(#[from] MemoryAuthorityFailure),
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
    #[error("Codex Harness composition is invalid")]
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
            "checker_output_limit": 4096
        });

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
}
