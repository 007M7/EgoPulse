use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactAuthorityFailure, ArtifactSqlCipherKey,
};
use egopulse_cognition_runtime::task_authority::{
    PrincipalKind as TaskPrincipalKind, SqlCipherKey, TaskAuthority, TaskAuthorityConfig,
    TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::{
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
    VerificationAuthority, VerificationAuthorityConfig, VerificationAuthorityFailure,
    VerificationReferenceResolver, VerificationSqlCipherKey,
};
use serde::Deserialize;
use thiserror::Error;

use crate::{AllowlistedPrincipal, AllowlistedPrincipalResolver, PrincipalPolicyError};
use crate::{
    ArtifactAuthorityReferenceSource, ArtifactProjectionSource, AuthorityPrincipalBinding,
    CodexHarnessCompositionConfig, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredAuthorityPrincipalResolver,
    ConfiguredFounderVerdictResolver, ConfiguredFounderVerdictResolverConfig,
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, DaemonCompositionError,
    DaemonProviders, FounderVerdictConfigurationError, LocalUserPolicyResolver,
    LocalUserPolicyResolverConfig, SharedAuthorityCompositionInputs,
    TaskAuthorityCommitReceiptSource, VerificationAuthorityArtifactSource,
    VerificationProjectionSource,
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

/// Inputs owned by the local installation, not inferred from a client request.
pub struct ProductionBootstrapConfig {
    pub task: TaskAuthorityConfig,
    pub task_guard: ConfiguredTaskCreationGuardConfig,
    pub artifact: ArtifactAuthorityConfig,
    pub artifact_guard: ConfiguredArtifactAdmissionGuardConfig,
    pub verification: VerificationAuthorityConfig,
    /// Optional reviewed Artifact-backed Verification reference policy. When
    /// absent, production remains deny-by-default for external Verification
    /// requests and checker profile attestation.
    pub verification_references: Option<VerificationReferenceBootstrapConfig>,
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

    /// Opens every Authority exactly once and composes the first production
    /// vertical. Missing or invalid references fail before a serving daemon is
    /// built; no test resolver is used as a production fallback.
    pub fn build(self) -> Result<DaemonProviders, ProductionBootstrapError> {
        let task_guard = ConfiguredTaskCreationGuard::new(self.task_guard)?;
        let task = Arc::new(Mutex::new(TaskAuthority::open(self.task, task_guard)?));

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

        let principal_resolver = Arc::new(ConfiguredAuthorityPrincipalResolver::new([
            self.authority_binding
        ])?);
        let session_principal_resolver =
            Arc::new(AllowlistedPrincipalResolver::new([self.os_principal])?);
        let mut providers =
            DaemonProviders::from_shared_authority_inputs(SharedAuthorityCompositionInputs {
                task,
                policy,
                verdict,
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
        providers = providers.with_codex_harness(self.codex)?;
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
    policy: PolicyFile,
    founder: FounderFile,
    codex: CodexFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFiles {
    task: StoreFile,
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

impl UserOwnedBootstrapFile {
    fn into_typed(self) -> Result<ProductionBootstrapConfig, ProductionBootstrapError> {
        if self.schema_version != "egopulse.production-bootstrap/v1" {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "schema_version",
            ));
        }
        let task_store = typed_store(self.stores.task, "task authority")?;
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

        let workflow = self.codex.workflow.into_typed()?;
        let codex = CodexHarnessCompositionConfig {
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
            codex_executable: PathBuf::from(required(
                self.codex.codex_executable,
                "codex.codex_executable",
            )?),
            workflow,
            lease_ttl_seconds: self.codex.lease_ttl_seconds,
        };

        Ok(ProductionBootstrapConfig {
            task: TaskAuthorityConfig {
                database_path: task_store.database_path,
                store_epoch: task_store.store_epoch,
                key: SqlCipherKey::new(task_store.key),
            },
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
            br#"{"schema_version": "egopulse.production-bootstrap/v1", "unknown": true}"#,
        )
        .expect("write malformed bootstrap fixture");
        assert!(matches!(
            ProductionBootstrapConfig::from_user_file(&path),
            Err(ProductionBootstrapError::ConfigurationFormat { .. })
        ));
        let _ = fs::remove_file(path);
    }
}
