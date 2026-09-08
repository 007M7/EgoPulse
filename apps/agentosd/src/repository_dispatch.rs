use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactPrincipalKind, AuthenticatedArtifactPrincipal,
    canonical_request_digest,
};
use egopulse_cognition_runtime::context_authority::ContextAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactStatus, ContentAddress,
        HashAlgorithm, IntegrityStatus, LineageBinding, ProducerIdentity, Provenance,
        SealArtifactCommand, StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::{DispatchEnvelope, HarnessError, HarnessErrorCode},
};
use egopulse_harness_adapter::{
    DispatchContextReference, ReadyDispatchMaterialGuard, ResolvedDispatchMaterial,
    classify_dispatch_context_reference,
};
use egopulse_local_ide_control::collaboration_control::{
    SingleHarnessWorkConfig, SingleHarnessWorkResult, TaskActivationHandoff,
    TaskDispatchMaterialPreparer, TaskDispatchMaterialRejection,
};
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcessSpec,
    run_governed_process_outcome,
};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ConfiguredArtifactAdmissionGuard,
    artifact::DerivedWorkspaceAdmissionLease,
    artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle},
    repository_material::{
        FrozenRepositoryMaterialV1, RepositoryMaterialConfig,
        frozen_repository_material_from_compiled_context,
    },
};

const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
const BASELINE_SCHEMA: &str = "egopulse.repository-baseline/v1";
const INITIAL_MANIFEST_SCHEMA: &str = "egopulse.workspace-initial-manifest/v1";
const BINDING_SCHEME: &str = "repository-dispatch-binding:sha256:";

#[derive(Clone)]
pub(crate) struct RepositoryDispatchArtifactPolicy {
    pub artifact_type_ref: ContractReference,
    pub transformation_contract_ref: ContractReference,
    pub retention_profile_ref: ContractReference,
    pub artifact_authority_principal_id: String,
    pub attempt_supervisor_principal_id: String,
    pub evidence_profile_ref: ContractReference,
}

pub(crate) struct RepositoryDispatchCoordinator {
    context: Arc<Mutex<ContextAuthority>>,
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    admission: DerivedWorkspaceAdmissionHandle,
    material_config: RepositoryMaterialConfig,
    workspace_root: PathBuf,
    artifact_policy: RepositoryDispatchArtifactPolicy,
    capture_guard: tokio::sync::Mutex<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SealedRepositoryDispatchMaterial {
    pub(crate) frozen_material: FrozenRepositoryMaterialV1,
    pub(crate) workspace_ref: String,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
    pub(crate) baseline_artifact_id: String,
    pub(crate) initial_manifest_artifact_id: String,
    pub(crate) lineage: LineageBinding,
    pub(crate) source_binding_ref: String,
}

// BUILD consumes this crate-local handoff in the collector integration slice;
// keeping it typed now prevents that caller from reconstructing identities.
#[allow(dead_code)]
pub(crate) struct CapturedRepositoryReturn {
    pub(crate) frozen_material: FrozenRepositoryMaterialV1,
    pub(crate) workspace_root: PathBuf,
    pub(crate) sealed_dispatch: SealedRepositoryDispatchMaterial,
    pub(crate) patch_artifact_id: String,
    pub(crate) patch_content: ContentAddress,
    pub(crate) final_manifest_artifact_id: String,
    pub(crate) final_manifest_content: ContentAddress,
    pub(crate) evidence_profile_ref: ContractReference,
    pub(crate) admission_lease: DerivedWorkspaceAdmissionLease,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryBaselinePayload {
    pub(crate) schema_version: String,
    pub(crate) task_id: String,
    pub(crate) task_revision: u64,
    pub(crate) work_revision: u64,
    pub(crate) input_snapshot_id: String,
    pub(crate) input_bundle_sha256: String,
    pub(crate) workspace_ref: String,
    pub(crate) contract_id: String,
    pub(crate) contract_version: String,
    pub(crate) contract_sha256: String,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct InitialWorkspaceManifestPayload {
    pub(crate) schema_version: String,
    pub(crate) task_id: String,
    pub(crate) task_revision: u64,
    pub(crate) work_revision: u64,
    pub(crate) run_id: String,
    pub(crate) run_revision: u64,
    pub(crate) step_id: String,
    pub(crate) step_revision: u64,
    pub(crate) attempt_id: String,
    pub(crate) attempt_revision: u64,
    pub(crate) dispatch_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) input_snapshot_id: String,
    pub(crate) input_bundle_sha256: String,
    pub(crate) workspace_ref: String,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
    pub(crate) status_porcelain_sha256: String,
    pub(crate) clean: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FinalWorkspaceManifestPayload {
    pub(crate) schema_version: String,
    pub(crate) workspace_ref: String,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
    pub(crate) observed_head_commit: String,
    pub(crate) observed_head_tree: String,
    pub(crate) status_porcelain_sha256: String,
    pub(crate) status_porcelain_bytes: u64,
    pub(crate) patch_sha256: String,
    pub(crate) patch_bytes: u64,
    pub(crate) entries: Vec<FinalWorkspaceManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FinalWorkspaceManifestEntry {
    pub(crate) status: String,
    pub(crate) path_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedWorkspaceState {
    patch: Vec<u8>,
    manifest: FinalWorkspaceManifestPayload,
}

impl RepositoryDispatchCoordinator {
    pub(crate) fn new(
        context: Arc<Mutex<ContextAuthority>>,
        artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
        admission: DerivedWorkspaceAdmissionHandle,
        material_config: RepositoryMaterialConfig,
        workspace_root: PathBuf,
        artifact_policy: RepositoryDispatchArtifactPolicy,
    ) -> Result<Self, &'static str> {
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|_| "repository dispatch workspace root")?;
        if !workspace_root.is_dir()
            || !contract_reference_valid(&artifact_policy.artifact_type_ref)
            || !contract_reference_valid(&artifact_policy.transformation_contract_ref)
            || !contract_reference_valid(&artifact_policy.retention_profile_ref)
            || artifact_policy
                .artifact_authority_principal_id
                .trim()
                .is_empty()
            || artifact_policy
                .attempt_supervisor_principal_id
                .trim()
                .is_empty()
            || !contract_reference_valid(&artifact_policy.evidence_profile_ref)
        {
            return Err("repository dispatch configuration");
        }
        Ok(Self {
            context,
            artifact,
            admission,
            material_config,
            workspace_root,
            artifact_policy,
            capture_guard: tokio::sync::Mutex::new(()),
        })
    }

    fn resolve_task_material(
        &self,
        activation: &TaskActivationHandoff,
    ) -> Result<Option<FrozenRepositoryMaterialV1>, TaskDispatchMaterialRejection> {
        let now = unix_seconds().ok_or_else(|| rejection("REPOSITORY_MATERIAL_CLOCK"))?;
        let resolved = self
            .context
            .lock()
            .map_err(|_| rejection("REPOSITORY_CONTEXT_UNAVAILABLE"))?
            .resolve(
                &activation.task.input_snapshot_id,
                &activation.task.target_scope_ref,
                now,
            )
            .map_err(|_| rejection("REPOSITORY_CONTEXT_UNAVAILABLE"))?;
        let Some(material) =
            frozen_repository_material_from_compiled_context(&resolved.compiled_context)
                .map_err(|_| rejection("REPOSITORY_MATERIAL_INVALID"))?
        else {
            return Ok(None);
        };
        let contract_ref = activation
            .task
            .acceptance_contract_ref
            .as_ref()
            .ok_or_else(|| rejection("REPOSITORY_ACCEPTANCE_REFERENCE_MISSING"))?;
        material
            .validate_stored(contract_ref)
            .map_err(|_| rejection("REPOSITORY_MATERIAL_INVALID"))?;
        if material.contract_path() != self.material_config.contract_path
            || material.repository_root() != self.material_config.repository_root
            || material.git_executable() != self.material_config.git_executable
        {
            return Err(rejection("REPOSITORY_MATERIAL_CONFIGURATION_DRIFT"));
        }
        Ok(Some(material))
    }

    fn resolve_envelope_material(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<(FrozenRepositoryMaterialV1, String)>, HarnessError> {
        let snapshot_id = match classify_dispatch_context_reference(&envelope.input_bundle_ref) {
            DispatchContextReference::NotContextBound => return Ok(None),
            DispatchContextReference::ContextSnapshot { snapshot_id } => snapshot_id,
            DispatchContextReference::InvalidContextBinding => {
                return Err(harness_rejection(
                    HarnessErrorCode::ConfigInvalid,
                    "REPOSITORY_CONTEXT_BINDING_INVALID",
                ));
            }
        };
        let now = unix_seconds().ok_or_else(|| {
            harness_rejection(
                HarnessErrorCode::DependencyUnavailable,
                "REPOSITORY_MATERIAL_CLOCK",
            )
        })?;
        let resolved = self
            .context
            .lock()
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::DependencyUnavailable,
                    "REPOSITORY_CONTEXT_UNAVAILABLE",
                )
            })?
            .resolve_for_consumption(&snapshot_id, now)
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::DependencyUnavailable,
                    "REPOSITORY_CONTEXT_UNAVAILABLE",
                )
            })?;
        let material = frozen_repository_material_from_compiled_context(&resolved.compiled_context)
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::IntegrityFailure,
                    "REPOSITORY_MATERIAL_INVALID",
                )
            })?;
        if let Some(material) = material.as_ref()
            && (material.contract_path() != self.material_config.contract_path
                || material.repository_root() != self.material_config.repository_root
                || material.git_executable() != self.material_config.git_executable)
        {
            return Err(harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_MATERIAL_CONFIGURATION_DRIFT",
            ));
        }
        Ok(material.map(|material| (material, snapshot_id)))
    }

    /// Reconstructs the exact derived-workspace admission from the two sealed
    /// pre-dispatch Artifacts and the trusted envelope. M3 can hold the lease
    /// only while staging return Artifacts; dropping it closes the admission
    /// on every success and failure path.
    pub(crate) fn admit_sealed_return_workspace(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<
        Option<(
            SealedRepositoryDispatchMaterial,
            DerivedWorkspaceAdmissionLease,
        )>,
        HarnessError,
    > {
        let Some((material, snapshot_id)) = self.resolve_envelope_material(envelope)? else {
            return Ok(None);
        };
        let baseline = self.ready_dispatch_baseline(envelope, &material, &snapshot_id)?;
        let lineage = artifact_lineage_from_baseline(&baseline, envelope);
        let source_binding_ref = source_binding_ref_from_baseline(&baseline, envelope);
        let lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: baseline.workspace_ref.clone(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.clone(),
            })
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::IntegrityFailure,
                    "REPOSITORY_WORKSPACE_ADMISSION_REJECTED",
                )
            })?;
        Ok(Some((
            SealedRepositoryDispatchMaterial {
                frozen_material: material,
                workspace_ref: baseline.workspace_ref,
                baseline_commit: baseline.baseline_commit,
                baseline_tree: baseline.baseline_tree,
                baseline_artifact_id: baseline_artifact_id(&envelope.dispatch_id),
                initial_manifest_artifact_id: initial_manifest_artifact_id(&envelope.dispatch_id),
                lineage,
                source_binding_ref,
            },
            lease,
        )))
    }

    pub(crate) async fn capture_return(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<CapturedRepositoryReturn>, HarnessError> {
        let _capture_guard = self.capture_guard.lock().await;
        let Some((sealed_dispatch, admission_lease)) =
            self.admit_sealed_return_workspace(envelope)?
        else {
            return Ok(None);
        };
        let workspace_root = self
            .workspace_root
            .join(&sealed_dispatch.workspace_ref)
            .canonicalize()
            .map_err(|_| return_rejection("REPOSITORY_RETURN_WORKSPACE_UNAVAILABLE"))?;
        if workspace_root != self.workspace_root.join(&sealed_dispatch.workspace_ref) {
            return Err(return_rejection("REPOSITORY_RETURN_WORKSPACE_MISMATCH"));
        }
        let patch_artifact_id = repository_patch_artifact_id(&envelope.dispatch_id);
        let final_manifest_artifact_id = final_manifest_artifact_id(&envelope.dispatch_id);
        let replay =
            self.return_artifact_presence(&patch_artifact_id, &final_manifest_artifact_id)?;
        let (patch_content, final_manifest_content) = match replay {
            ReturnArtifactPresence::Replay => self.verify_captured_return_replay(
                envelope,
                &sealed_dispatch,
                &patch_artifact_id,
                &final_manifest_artifact_id,
            )?,
            ReturnArtifactPresence::Fresh => {
                let first = capture_workspace_state(
                    &sealed_dispatch.frozen_material,
                    &workspace_root,
                    &sealed_dispatch.workspace_ref,
                )
                .await
                .map_err(map_return_capture_error)?;
                let second = capture_workspace_state(
                    &sealed_dispatch.frozen_material,
                    &workspace_root,
                    &sealed_dispatch.workspace_ref,
                )
                .await
                .map_err(map_return_capture_error)?;
                if first != second || first.patch.is_empty() {
                    return Err(return_rejection("REPOSITORY_RETURN_NOT_STABLE"));
                }
                let sealed = self.seal_captured_return(
                    envelope,
                    &sealed_dispatch,
                    &patch_artifact_id,
                    &final_manifest_artifact_id,
                    &first,
                )?;
                let after_seal = capture_workspace_state(
                    &sealed_dispatch.frozen_material,
                    &workspace_root,
                    &sealed_dispatch.workspace_ref,
                )
                .await
                .map_err(map_return_capture_error)?;
                if after_seal != first {
                    return Err(return_rejection(
                        "REPOSITORY_WORKSPACE_CHANGED_DURING_CAPTURE",
                    ));
                }
                sealed
            }
        };
        Ok(Some(CapturedRepositoryReturn {
            frozen_material: sealed_dispatch.frozen_material.clone(),
            workspace_root,
            sealed_dispatch,
            patch_artifact_id,
            patch_content,
            final_manifest_artifact_id,
            final_manifest_content,
            evidence_profile_ref: self.artifact_policy.evidence_profile_ref.clone(),
            admission_lease,
        }))
    }

    // This is the post-command half of the M3 handoff and is called by the
    // collector integration slice owned by BUILD.
    #[allow(dead_code)]
    pub(crate) async fn verify_return_unchanged(
        &self,
        captured: &CapturedRepositoryReturn,
    ) -> Result<(), HarnessError> {
        let _capture_guard = self.capture_guard.lock().await;
        let bytes = self.read_sealed_artifact_bytes(&captured.final_manifest_artifact_id)?;
        if content_address(&bytes) != captured.final_manifest_content {
            return Err(return_rejection("REPOSITORY_FINAL_MANIFEST_CHANGED"));
        }
        let sealed_manifest: FinalWorkspaceManifestPayload = serde_json::from_slice(&bytes)
            .map_err(|_| return_rejection("REPOSITORY_FINAL_MANIFEST_INVALID"))?;
        let current = capture_workspace_state(
            &captured.frozen_material,
            &captured.workspace_root,
            &captured.sealed_dispatch.workspace_ref,
        )
        .await
        .map_err(map_return_capture_error)?;
        let current_manifest = serde_json::to_vec(&current.manifest)
            .map_err(|_| return_rejection("REPOSITORY_FINAL_MANIFEST_INVALID"))?;
        if current.manifest != sealed_manifest
            || content_address(&current.patch) != captured.patch_content
            || content_address(&current_manifest) != captured.final_manifest_content
        {
            return Err(return_rejection(
                "REPOSITORY_WORKSPACE_CHANGED_AFTER_COMMANDS",
            ));
        }
        Ok(())
    }

    fn return_artifact_presence(
        &self,
        patch_artifact_id: &str,
        final_manifest_artifact_id: &str,
    ) -> Result<ReturnArtifactPresence, HarnessError> {
        let authority = self.artifact.lock().map_err(|_| {
            harness_rejection(
                HarnessErrorCode::DependencyUnavailable,
                "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
            )
        })?;
        let patch = authority.read_artifact(patch_artifact_id).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::DependencyUnavailable,
                "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
            )
        })?;
        let manifest = authority
            .read_artifact(final_manifest_artifact_id)
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::DependencyUnavailable,
                    "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
                )
            })?;
        match (patch, manifest) {
            (None, None) => Ok(ReturnArtifactPresence::Fresh),
            (Some(patch), Some(manifest))
                if patch.status == ArtifactStatus::Sealed as i32
                    && patch.integrity_status == IntegrityStatus::DigestVerified as i32
                    && manifest.status == ArtifactStatus::Sealed as i32
                    && manifest.integrity_status == IntegrityStatus::DigestVerified as i32 =>
            {
                Ok(ReturnArtifactPresence::Replay)
            }
            _ => Err(return_rejection("REPOSITORY_RETURN_ARTIFACTS_INCOMPLETE")),
        }
    }

    fn seal_captured_return(
        &self,
        envelope: &DispatchEnvelope,
        sealed: &SealedRepositoryDispatchMaterial,
        patch_artifact_id: &str,
        final_manifest_artifact_id: &str,
        captured: &CapturedWorkspaceState,
    ) -> Result<(ContentAddress, ContentAddress), HarnessError> {
        let patch_inputs = vec![
            sealed.baseline_artifact_id.clone(),
            sealed.initial_manifest_artifact_id.clone(),
        ];
        let patch = self.artifact_candidate(
            patch_artifact_id.to_owned(),
            ArtifactSemanticClass::RepositoryPatch,
            "application/vnd.git.patch",
            &captured.patch,
            sealed.lineage.clone(),
            patch_inputs.clone(),
            sealed.source_binding_ref.clone(),
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        );
        let patch_content = content_address(&captured.patch);
        self.stage_and_seal(
            patch,
            &captured.patch,
            &self.artifact_policy.attempt_supervisor_principal_id,
            &envelope.dispatch_id,
            "repository-patch",
        )
        .map_err(map_return_artifact_error)?;

        let manifest_bytes = serde_json::to_vec(&captured.manifest)
            .map_err(|_| return_rejection("REPOSITORY_FINAL_MANIFEST_INVALID"))?;
        let manifest = self.artifact_candidate(
            final_manifest_artifact_id.to_owned(),
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &manifest_bytes,
            sealed.lineage.clone(),
            vec![
                sealed.baseline_artifact_id.clone(),
                sealed.initial_manifest_artifact_id.clone(),
                patch_artifact_id.to_owned(),
            ],
            sealed.source_binding_ref.clone(),
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        );
        let final_manifest_content = content_address(&manifest_bytes);
        self.stage_and_seal(
            manifest,
            &manifest_bytes,
            &self.artifact_policy.attempt_supervisor_principal_id,
            &envelope.dispatch_id,
            "workspace-final",
        )
        .map_err(map_return_artifact_error)?;
        self.verify_one_artifact(
            patch_artifact_id,
            ArtifactSemanticClass::RepositoryPatch,
            "application/vnd.git.patch",
            &captured.patch,
            &sealed.lineage,
            &patch_inputs,
            &sealed.source_binding_ref,
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(map_return_artifact_error)?;
        self.verify_one_artifact(
            final_manifest_artifact_id,
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &manifest_bytes,
            &sealed.lineage,
            &[
                sealed.baseline_artifact_id.clone(),
                sealed.initial_manifest_artifact_id.clone(),
                patch_artifact_id.to_owned(),
            ],
            &sealed.source_binding_ref,
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(map_return_artifact_error)?;
        Ok((patch_content, final_manifest_content))
    }

    fn verify_captured_return_replay(
        &self,
        _envelope: &DispatchEnvelope,
        sealed: &SealedRepositoryDispatchMaterial,
        patch_artifact_id: &str,
        final_manifest_artifact_id: &str,
    ) -> Result<(ContentAddress, ContentAddress), HarnessError> {
        let patch_bytes = self.read_sealed_artifact_bytes(patch_artifact_id)?;
        if patch_bytes.is_empty() {
            return Err(return_rejection("REPOSITORY_PATCH_INVALID"));
        }
        let patch_inputs = vec![
            sealed.baseline_artifact_id.clone(),
            sealed.initial_manifest_artifact_id.clone(),
        ];
        self.verify_one_artifact(
            patch_artifact_id,
            ArtifactSemanticClass::RepositoryPatch,
            "application/vnd.git.patch",
            &patch_bytes,
            &sealed.lineage,
            &patch_inputs,
            &sealed.source_binding_ref,
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(map_return_artifact_error)?;
        let patch_content = content_address(&patch_bytes);
        let manifest_bytes = self.read_sealed_artifact_bytes(final_manifest_artifact_id)?;
        let manifest: FinalWorkspaceManifestPayload = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| return_rejection("REPOSITORY_FINAL_MANIFEST_INVALID"))?;
        if !final_manifest_valid(&manifest, sealed, &patch_content) {
            return Err(return_rejection("REPOSITORY_FINAL_MANIFEST_INVALID"));
        }
        self.verify_one_artifact(
            final_manifest_artifact_id,
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &manifest_bytes,
            &sealed.lineage,
            &[
                sealed.baseline_artifact_id.clone(),
                sealed.initial_manifest_artifact_id.clone(),
                patch_artifact_id.to_owned(),
            ],
            &sealed.source_binding_ref,
            &sealed.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(map_return_artifact_error)?;
        Ok((patch_content, content_address(&manifest_bytes)))
    }

    async fn prepare_task_workspace(
        &self,
        activation: &TaskActivationHandoff,
        config: &SingleHarnessWorkConfig,
        material: &FrozenRepositoryMaterialV1,
    ) -> Result<String, TaskDispatchMaterialRejection> {
        if config.material.input_bundle_sha256
            != activation
                .task
                .input_snapshot_id
                .strip_prefix("ctx:")
                .unwrap_or_default()
        {
            return Err(rejection("REPOSITORY_INPUT_BINDING_MISMATCH"));
        }
        let workspace_ref = derived_workspace_ref(
            &activation.task.task_id,
            &activation.task.input_snapshot_id,
            material.baseline_commit(),
        );
        let destination = self.workspace_root.join(&workspace_ref);
        if destination.exists() {
            let canonical = destination
                .canonicalize()
                .map_err(|_| rejection("REPOSITORY_WORKSPACE_CONFLICT"))?;
            if canonical != destination || !canonical.is_dir() {
                return Err(rejection("REPOSITORY_WORKSPACE_CONFLICT"));
            }
            if !self.pre_dispatch_artifacts_are_sealed(&config.dispatch_id)? {
                verify_clean_workspace(material, &canonical)
                    .await
                    .map_err(map_material_rejection)?;
            }
            return Ok(workspace_ref);
        }
        reject_unsafe_checkout_material(material, &self.workspace_root)
            .await
            .map_err(map_material_rejection)?;
        create_detached_worktree(material, &self.workspace_root, &destination)
            .await
            .map_err(map_material_rejection)?;
        verify_clean_workspace(material, &destination)
            .await
            .map_err(map_material_rejection)?;
        Ok(workspace_ref)
    }

    fn pre_dispatch_artifacts_are_sealed(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, TaskDispatchMaterialRejection> {
        let authority = self
            .artifact
            .lock()
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
        for artifact_id in pre_dispatch_artifact_ids(dispatch_id) {
            let Some(artifact) = authority
                .read_artifact(&artifact_id)
                .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?
            else {
                return Ok(false);
            };
            if artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn seal_pre_dispatch_artifacts(
        &self,
        activation: &TaskActivationHandoff,
        config: &SingleHarnessWorkConfig,
        result: &SingleHarnessWorkResult,
        material: &FrozenRepositoryMaterialV1,
    ) -> Result<(), TaskDispatchMaterialRejection> {
        validate_result_binding(activation, config, result, material)?;
        let lineage = artifact_lineage(activation, &result.envelope);
        let source_binding_ref = source_binding_ref(
            activation,
            &result.envelope,
            material,
            &config.workspace_ref,
        );
        let _lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: config.workspace_ref.clone(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.clone(),
            })
            .map_err(|_| rejection("REPOSITORY_WORKSPACE_ADMISSION_REJECTED"))?;
        let baseline = baseline_payload(activation, config, material);
        let baseline_bytes = serde_json::to_vec(&baseline)
            .map_err(|_| rejection("REPOSITORY_BASELINE_ENCODING_FAILED"))?;
        let baseline_id = baseline_artifact_id(&result.dispatch_id);
        let baseline_artifact = self.artifact_candidate(
            baseline_id.clone(),
            ArtifactSemanticClass::RepositoryBaseline,
            "application/json",
            &baseline_bytes,
            lineage.clone(),
            Vec::new(),
            source_binding_ref.clone(),
            &config.workspace_ref,
            &config.attempt_supervisor_principal_id,
        );
        self.stage_and_seal(
            baseline_artifact,
            &baseline_bytes,
            &config.attempt_supervisor_principal_id,
            &result.dispatch_id,
            "repository-baseline",
        )?;

        let manifest = initial_manifest_payload(activation, result, material);
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|_| rejection("REPOSITORY_MANIFEST_ENCODING_FAILED"))?;
        let manifest_artifact = self.artifact_candidate(
            initial_manifest_artifact_id(&result.dispatch_id),
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &manifest_bytes,
            lineage,
            vec![baseline_id],
            source_binding_ref,
            &config.workspace_ref,
            &config.attempt_supervisor_principal_id,
        );
        self.stage_and_seal(
            manifest_artifact,
            &manifest_bytes,
            &config.attempt_supervisor_principal_id,
            &result.dispatch_id,
            "workspace-initial",
        )?;
        self.verify_sealed_pre_dispatch_artifacts(activation, config, result, material)
    }

    // Keeping the candidate inputs explicit makes every Authority-bound field
    // reviewable at the sole Artifact construction boundary.
    #[allow(clippy::too_many_arguments)]
    fn artifact_candidate(
        &self,
        artifact_id: String,
        semantic_class: ArtifactSemanticClass,
        media_type: &str,
        bytes: &[u8],
        lineage: LineageBinding,
        input_artifact_ids: Vec<String>,
        source_binding_ref: String,
        workspace_ref: &str,
        producer_principal_id: &str,
    ) -> ArtifactDescriptor {
        ArtifactDescriptor {
            artifact_id,
            revision: 1,
            status: ArtifactStatus::Staged as i32,
            semantic_class: semantic_class as i32,
            type_contract_ref: Some(self.artifact_policy.artifact_type_ref.clone()),
            media_type: media_type.to_owned(),
            content: Some(content_address(bytes)),
            integrity_status: IntegrityStatus::Unverified as i32,
            provenance: Some(Provenance {
                lineage: Some(lineage),
                producer: Some(ProducerIdentity {
                    principal_kind: ArtifactPrincipalKind::AttemptSupervisor.as_str().to_owned(),
                    principal_id: producer_principal_id.to_owned(),
                    component_name: "agentosd-repository-dispatch".to_owned(),
                    component_version: env!("CARGO_PKG_VERSION").to_owned(),
                    capability_profile_id: None,
                    native_execution_ref: None,
                }),
                input_artifact_ids,
                transformation_contract_ref: Some(
                    self.artifact_policy.transformation_contract_ref.clone(),
                ),
                workspace_ref: workspace_ref.to_owned(),
                observed_at: None,
                captured_at: None,
                raw_source_ref: Some(source_binding_ref),
            }),
            sensitivity_class: "local-governance".to_owned(),
            retention_profile_ref: Some(self.artifact_policy.retention_profile_ref.clone()),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        }
    }

    fn stage_and_seal(
        &self,
        artifact: ArtifactDescriptor,
        bytes: &[u8],
        producer_principal_id: &str,
        dispatch_id: &str,
        role: &str,
    ) -> Result<(), TaskDispatchMaterialRejection> {
        let address = artifact
            .content
            .clone()
            .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_INVALID"))?;
        let mut authority = self
            .artifact
            .lock()
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
        authority
            .put_blob(bytes, &address)
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
        execute_artifact_command(
            &mut authority,
            artifact_command::Command::StageArtifact(StageArtifactCommand {
                metadata: Some(artifact_metadata(dispatch_id, role, "stage")),
                candidate: Some(artifact.clone()),
            }),
            &artifact_principal(
                ArtifactPrincipalKind::AttemptSupervisor,
                producer_principal_id,
            ),
        )?;
        execute_artifact_command(
            &mut authority,
            artifact_command::Command::SealArtifact(SealArtifactCommand {
                metadata: Some(artifact_metadata(dispatch_id, role, "seal")),
                artifact_id: artifact.artifact_id,
                expected_revision: 1,
                observed_content: Some(address),
            }),
            &artifact_principal(
                ArtifactPrincipalKind::ArtifactAuthority,
                &self.artifact_policy.artifact_authority_principal_id,
            ),
        )?;
        Ok(())
    }

    fn verify_sealed_pre_dispatch_artifacts(
        &self,
        activation: &TaskActivationHandoff,
        config: &SingleHarnessWorkConfig,
        result: &SingleHarnessWorkResult,
        material: &FrozenRepositoryMaterialV1,
    ) -> Result<(), TaskDispatchMaterialRejection> {
        let lineage = artifact_lineage(activation, &result.envelope);
        let source_ref = source_binding_ref(
            activation,
            &result.envelope,
            material,
            &config.workspace_ref,
        );
        let baseline_bytes = serde_json::to_vec(&baseline_payload(activation, config, material))
            .map_err(|_| rejection("REPOSITORY_BASELINE_ENCODING_FAILED"))?;
        let baseline_id = baseline_artifact_id(&result.dispatch_id);
        self.verify_one_artifact(
            &baseline_id,
            ArtifactSemanticClass::RepositoryBaseline,
            "application/json",
            &baseline_bytes,
            &lineage,
            &[],
            &source_ref,
            &config.workspace_ref,
            &config.attempt_supervisor_principal_id,
        )?;
        let manifest_bytes =
            serde_json::to_vec(&initial_manifest_payload(activation, result, material))
                .map_err(|_| rejection("REPOSITORY_MANIFEST_ENCODING_FAILED"))?;
        self.verify_one_artifact(
            &initial_manifest_artifact_id(&result.dispatch_id),
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &manifest_bytes,
            &lineage,
            &[baseline_id],
            &source_ref,
            &config.workspace_ref,
            &config.attempt_supervisor_principal_id,
        )
    }

    // This mirrors the full stored Artifact binding so replay cannot omit a
    // field merely to make an existing record compare equal.
    #[allow(clippy::too_many_arguments)]
    fn verify_one_artifact(
        &self,
        artifact_id: &str,
        semantic_class: ArtifactSemanticClass,
        media_type: &str,
        expected_bytes: &[u8],
        lineage: &LineageBinding,
        input_artifact_ids: &[String],
        source_binding_ref: &str,
        workspace_ref: &str,
        producer_principal_id: &str,
    ) -> Result<(), TaskDispatchMaterialRejection> {
        let authority = self
            .artifact
            .lock()
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
        let artifact = authority
            .read_artifact(artifact_id)
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?
            .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_MISSING"))?;
        let provenance = artifact
            .provenance
            .as_ref()
            .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_INVALID"))?;
        let producer = provenance
            .producer
            .as_ref()
            .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_INVALID"))?;
        let address = artifact
            .content
            .as_ref()
            .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_INVALID"))?;
        if artifact.status != ArtifactStatus::Sealed as i32
            || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
            || artifact.semantic_class != semantic_class as i32
            || artifact.type_contract_ref.as_ref() != Some(&self.artifact_policy.artifact_type_ref)
            || artifact.retention_profile_ref.as_ref()
                != Some(&self.artifact_policy.retention_profile_ref)
            || artifact.media_type != media_type
            || address != &content_address(expected_bytes)
            || provenance.lineage.as_ref() != Some(lineage)
            || provenance.input_artifact_ids != input_artifact_ids
            || provenance.transformation_contract_ref.as_ref()
                != Some(&self.artifact_policy.transformation_contract_ref)
            || provenance.workspace_ref != workspace_ref
            || provenance.raw_source_ref.as_deref() != Some(source_binding_ref)
            || producer.principal_kind != ArtifactPrincipalKind::AttemptSupervisor.as_str()
            || producer.principal_id != producer_principal_id
            || producer.component_name != "agentosd-repository-dispatch"
        {
            return Err(rejection("REPOSITORY_ARTIFACT_BINDING_MISMATCH"));
        }
        let bytes = authority
            .read_blob(address)
            .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
        if bytes != expected_bytes {
            return Err(rejection("REPOSITORY_ARTIFACT_DIGEST_MISMATCH"));
        }
        Ok(())
    }

    fn ready_dispatch_baseline(
        &self,
        envelope: &DispatchEnvelope,
        material: &FrozenRepositoryMaterialV1,
        snapshot_id: &str,
    ) -> Result<RepositoryBaselinePayload, HarnessError> {
        let baseline_id = baseline_artifact_id(&envelope.dispatch_id);
        let bytes = self.read_sealed_artifact_bytes(&baseline_id)?;
        let payload: RepositoryBaselinePayload = serde_json::from_slice(&bytes).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_BASELINE_ARTIFACT_INVALID",
            )
        })?;
        let contract_ref = ContractReference {
            contract_id: payload.contract_id.clone(),
            version: payload.contract_version.clone(),
            sha256: payload.contract_sha256.clone(),
        };
        material.validate_stored(&contract_ref).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_MATERIAL_INVALID",
            )
        })?;
        if payload.schema_version != BASELINE_SCHEMA
            || payload.input_snapshot_id != snapshot_id
            || payload.input_bundle_sha256 != envelope.input_bundle_sha256
            || payload.workspace_ref != envelope.workspace_ref
            || payload.baseline_commit != material.baseline_commit()
            || payload.baseline_tree != material.baseline_tree()
            || derived_workspace_ref(
                &payload.task_id,
                &payload.input_snapshot_id,
                &payload.baseline_commit,
            ) != payload.workspace_ref
        {
            return Err(harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_BASELINE_BINDING_MISMATCH",
            ));
        }
        let lineage = artifact_lineage_from_baseline(&payload, envelope);
        let source_ref = source_binding_ref_from_baseline(&payload, envelope);
        let expected_baseline = serde_json::to_vec(&payload).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_BASELINE_ARTIFACT_INVALID",
            )
        })?;
        self.verify_one_artifact(
            &baseline_id,
            ArtifactSemanticClass::RepositoryBaseline,
            "application/json",
            &expected_baseline,
            &lineage,
            &[],
            &source_ref,
            &payload.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_BASELINE_ARTIFACT_INVALID",
            )
        })?;
        let expected_manifest = initial_manifest_payload_from_baseline(&payload, envelope);
        let expected_manifest = serde_json::to_vec(&expected_manifest).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_MANIFEST_ARTIFACT_INVALID",
            )
        })?;
        self.verify_one_artifact(
            &initial_manifest_artifact_id(&envelope.dispatch_id),
            ArtifactSemanticClass::WorkspaceManifest,
            "application/json",
            &expected_manifest,
            &lineage,
            &[baseline_id],
            &source_ref,
            &payload.workspace_ref,
            &self.artifact_policy.attempt_supervisor_principal_id,
        )
        .map_err(|_| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_MANIFEST_ARTIFACT_INVALID",
            )
        })?;
        Ok(payload)
    }

    fn read_sealed_artifact_bytes(&self, artifact_id: &str) -> Result<Vec<u8>, HarnessError> {
        let authority = self.artifact.lock().map_err(|_| {
            harness_rejection(
                HarnessErrorCode::DependencyUnavailable,
                "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
            )
        })?;
        let artifact = authority
            .read_artifact(artifact_id)
            .map_err(|_| {
                harness_rejection(
                    HarnessErrorCode::DependencyUnavailable,
                    "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
                )
            })?
            .ok_or_else(|| {
                harness_rejection(
                    HarnessErrorCode::DependencyUnavailable,
                    "REPOSITORY_DISPATCH_ARTIFACT_MISSING",
                )
            })?;
        if artifact.status != ArtifactStatus::Sealed as i32
            || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
        {
            return Err(harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_DISPATCH_ARTIFACT_UNSEALED",
            ));
        }
        let address = artifact.content.as_ref().ok_or_else(|| {
            harness_rejection(
                HarnessErrorCode::IntegrityFailure,
                "REPOSITORY_DISPATCH_ARTIFACT_INVALID",
            )
        })?;
        authority.read_blob(address).map_err(|_| {
            harness_rejection(
                HarnessErrorCode::DependencyUnavailable,
                "REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE",
            )
        })
    }
}

impl TaskDispatchMaterialPreparer for RepositoryDispatchCoordinator {
    fn prepare<'a>(
        &'a self,
        activation: &'a TaskActivationHandoff,
        mut config: SingleHarnessWorkConfig,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SingleHarnessWorkConfig, TaskDispatchMaterialRejection>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(material) = self.resolve_task_material(activation)? else {
                return Ok(config);
            };
            config.workspace_ref = self
                .prepare_task_workspace(activation, &config, &material)
                .await?;
            Ok(config)
        })
    }

    fn seal_before_activation_ack<'a>(
        &'a self,
        activation: &'a TaskActivationHandoff,
        config: &'a SingleHarnessWorkConfig,
        result: &'a SingleHarnessWorkResult,
    ) -> Pin<Box<dyn Future<Output = Result<(), TaskDispatchMaterialRejection>> + Send + 'a>> {
        Box::pin(async move {
            let Some(material) = self.resolve_task_material(activation)? else {
                return Ok(());
            };
            self.seal_pre_dispatch_artifacts(activation, config, result, &material)
        })
    }
}

impl ReadyDispatchMaterialGuard for RepositoryDispatchCoordinator {
    fn validate_ready_dispatch<'a>(
        &'a self,
        envelope: &'a DispatchEnvelope,
        resolved_material: &'a ResolvedDispatchMaterial,
    ) -> Pin<Box<dyn Future<Output = Result<(), HarnessError>> + Send + 'a>> {
        Box::pin(async move {
            let Some((material, snapshot_id)) = self.resolve_envelope_material(envelope)? else {
                return Ok(());
            };
            let baseline = self.ready_dispatch_baseline(envelope, &material, &snapshot_id)?;
            let expected_workspace = self
                .workspace_root
                .join(&baseline.workspace_ref)
                .canonicalize()
                .map_err(|_| {
                    harness_rejection(
                        HarnessErrorCode::DependencyUnavailable,
                        "REPOSITORY_WORKSPACE_UNAVAILABLE",
                    )
                })?;
            let actual_workspace =
                resolved_material
                    .workspace_root
                    .canonicalize()
                    .map_err(|_| {
                        harness_rejection(
                            HarnessErrorCode::DependencyUnavailable,
                            "REPOSITORY_WORKSPACE_UNAVAILABLE",
                        )
                    })?;
            if actual_workspace != expected_workspace {
                return Err(harness_rejection(
                    HarnessErrorCode::IntegrityFailure,
                    "REPOSITORY_WORKSPACE_BINDING_MISMATCH",
                ));
            }
            verify_clean_workspace(&material, &actual_workspace)
                .await
                .map_err(|error| match error {
                    RepositoryDispatchError::Unavailable => harness_rejection(
                        HarnessErrorCode::DependencyUnavailable,
                        "REPOSITORY_WORKSPACE_UNAVAILABLE",
                    ),
                    RepositoryDispatchError::Rejected => harness_rejection(
                        HarnessErrorCode::IntegrityFailure,
                        "REPOSITORY_WORKSPACE_NOT_READY",
                    ),
                })?;
            Ok(())
        })
    }
}

fn validate_result_binding(
    activation: &TaskActivationHandoff,
    config: &SingleHarnessWorkConfig,
    result: &SingleHarnessWorkResult,
    material: &FrozenRepositoryMaterialV1,
) -> Result<(), TaskDispatchMaterialRejection> {
    if result.run_id != config.run_id
        || result.attempt_id != config.attempt_id
        || result.dispatch_id != config.dispatch_id
        || result.envelope.workspace_ref != config.workspace_ref
        || result.envelope.input_bundle_sha256 != config.material.input_bundle_sha256
        || config.workspace_ref
            != derived_workspace_ref(
                &activation.task.task_id,
                &activation.task.input_snapshot_id,
                material.baseline_commit(),
            )
    {
        return Err(rejection("REPOSITORY_DISPATCH_BINDING_MISMATCH"));
    }
    Ok(())
}

fn baseline_payload(
    activation: &TaskActivationHandoff,
    config: &SingleHarnessWorkConfig,
    material: &FrozenRepositoryMaterialV1,
) -> RepositoryBaselinePayload {
    let contract = material.acceptance_contract_ref();
    RepositoryBaselinePayload {
        schema_version: BASELINE_SCHEMA.to_owned(),
        task_id: activation.task.task_id.clone(),
        task_revision: activation.task.revision,
        work_revision: activation.task.work_revision,
        input_snapshot_id: activation.task.input_snapshot_id.clone(),
        input_bundle_sha256: config.material.input_bundle_sha256.clone(),
        workspace_ref: config.workspace_ref.clone(),
        contract_id: contract.contract_id,
        contract_version: contract.version,
        contract_sha256: contract.sha256,
        baseline_commit: material.baseline_commit().to_owned(),
        baseline_tree: material.baseline_tree().to_owned(),
    }
}

fn initial_manifest_payload(
    activation: &TaskActivationHandoff,
    result: &SingleHarnessWorkResult,
    material: &FrozenRepositoryMaterialV1,
) -> InitialWorkspaceManifestPayload {
    let envelope = &result.envelope;
    InitialWorkspaceManifestPayload {
        schema_version: INITIAL_MANIFEST_SCHEMA.to_owned(),
        task_id: activation.task.task_id.clone(),
        task_revision: activation.task.revision,
        work_revision: activation.task.work_revision,
        run_id: envelope.run_id.clone(),
        run_revision: envelope.run_revision,
        step_id: envelope.step_id.clone(),
        step_revision: envelope.step_revision,
        attempt_id: envelope.attempt_id.clone(),
        attempt_revision: envelope.attempt_revision,
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
        input_snapshot_id: activation.task.input_snapshot_id.clone(),
        input_bundle_sha256: envelope.input_bundle_sha256.clone(),
        workspace_ref: envelope.workspace_ref.clone(),
        baseline_commit: material.baseline_commit().to_owned(),
        baseline_tree: material.baseline_tree().to_owned(),
        status_porcelain_sha256: sha256(&[]),
        clean: true,
    }
}

fn initial_manifest_payload_from_baseline(
    baseline: &RepositoryBaselinePayload,
    envelope: &DispatchEnvelope,
) -> InitialWorkspaceManifestPayload {
    InitialWorkspaceManifestPayload {
        schema_version: INITIAL_MANIFEST_SCHEMA.to_owned(),
        task_id: baseline.task_id.clone(),
        task_revision: baseline.task_revision,
        work_revision: baseline.work_revision,
        run_id: envelope.run_id.clone(),
        run_revision: envelope.run_revision,
        step_id: envelope.step_id.clone(),
        step_revision: envelope.step_revision,
        attempt_id: envelope.attempt_id.clone(),
        attempt_revision: envelope.attempt_revision,
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
        input_snapshot_id: baseline.input_snapshot_id.clone(),
        input_bundle_sha256: envelope.input_bundle_sha256.clone(),
        workspace_ref: envelope.workspace_ref.clone(),
        baseline_commit: baseline.baseline_commit.clone(),
        baseline_tree: baseline.baseline_tree.clone(),
        status_porcelain_sha256: sha256(&[]),
        clean: true,
    }
}

fn artifact_lineage(
    activation: &TaskActivationHandoff,
    envelope: &DispatchEnvelope,
) -> LineageBinding {
    LineageBinding {
        task_id: activation.task.task_id.clone(),
        task_revision: activation.task.revision,
        work_revision: activation.task.work_revision,
        run_id: envelope.run_id.clone(),
        run_revision: envelope.run_revision,
        step_id: envelope.step_id.clone(),
        step_revision: envelope.step_revision,
        attempt_id: envelope.attempt_id.clone(),
        attempt_revision: envelope.attempt_revision,
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
    }
}

fn artifact_lineage_from_baseline(
    baseline: &RepositoryBaselinePayload,
    envelope: &DispatchEnvelope,
) -> LineageBinding {
    LineageBinding {
        task_id: baseline.task_id.clone(),
        task_revision: baseline.task_revision,
        work_revision: baseline.work_revision,
        run_id: envelope.run_id.clone(),
        run_revision: envelope.run_revision,
        step_id: envelope.step_id.clone(),
        step_revision: envelope.step_revision,
        attempt_id: envelope.attempt_id.clone(),
        attempt_revision: envelope.attempt_revision,
        dispatch_id: envelope.dispatch_id.clone(),
        fencing_token: envelope.fencing_token,
    }
}

fn source_binding_ref(
    activation: &TaskActivationHandoff,
    envelope: &DispatchEnvelope,
    material: &FrozenRepositoryMaterialV1,
    workspace_ref: &str,
) -> String {
    let lineage = artifact_lineage(activation, envelope);
    let contract = material.acceptance_contract_ref();
    let fields = vec![
        lineage.task_id,
        lineage.task_revision.to_string(),
        lineage.work_revision.to_string(),
        lineage.run_id,
        lineage.run_revision.to_string(),
        lineage.step_id,
        lineage.step_revision.to_string(),
        lineage.attempt_id,
        lineage.attempt_revision.to_string(),
        lineage.dispatch_id,
        lineage.fencing_token.to_string(),
        activation.task.input_snapshot_id.clone(),
        envelope.input_bundle_sha256.clone(),
        workspace_ref.to_owned(),
        contract.contract_id,
        contract.version,
        contract.sha256,
        material.baseline_commit().to_owned(),
        material.baseline_tree().to_owned(),
    ];
    format!("{BINDING_SCHEME}{}", framed_sha256_owned(&fields))
}

fn source_binding_ref_from_baseline(
    baseline: &RepositoryBaselinePayload,
    envelope: &DispatchEnvelope,
) -> String {
    repository_source_binding_ref(
        baseline,
        &artifact_lineage_from_baseline(baseline, envelope),
        &envelope.input_bundle_sha256,
    )
}

pub(crate) fn repository_source_binding_ref(
    baseline: &RepositoryBaselinePayload,
    lineage: &LineageBinding,
    input_bundle_sha256: &str,
) -> String {
    let fields = vec![
        baseline.task_id.clone(),
        baseline.task_revision.to_string(),
        baseline.work_revision.to_string(),
        lineage.run_id.clone(),
        lineage.run_revision.to_string(),
        lineage.step_id.clone(),
        lineage.step_revision.to_string(),
        lineage.attempt_id.clone(),
        lineage.attempt_revision.to_string(),
        lineage.dispatch_id.clone(),
        lineage.fencing_token.to_string(),
        baseline.input_snapshot_id.clone(),
        input_bundle_sha256.to_owned(),
        baseline.workspace_ref.clone(),
        baseline.contract_id.clone(),
        baseline.contract_version.clone(),
        baseline.contract_sha256.clone(),
        baseline.baseline_commit.clone(),
        baseline.baseline_tree.clone(),
    ];
    format!("{BINDING_SCHEME}{}", framed_sha256_owned(&fields))
}

pub(crate) fn derived_workspace_ref(
    task_id: &str,
    input_snapshot_id: &str,
    baseline_commit: &str,
) -> String {
    format!(
        "repository-task-{}",
        framed_sha256(&[task_id, input_snapshot_id, baseline_commit])
    )
}

fn pre_dispatch_artifact_ids(dispatch_id: &str) -> [String; 2] {
    [
        baseline_artifact_id(dispatch_id),
        initial_manifest_artifact_id(dispatch_id),
    ]
}

fn baseline_artifact_id(dispatch_id: &str) -> String {
    format!("artifact:repository-baseline:{dispatch_id}")
}

fn initial_manifest_artifact_id(dispatch_id: &str) -> String {
    format!("artifact:workspace-initial:{dispatch_id}")
}

fn repository_patch_artifact_id(dispatch_id: &str) -> String {
    format!("artifact:repository-patch:{dispatch_id}")
}

fn final_manifest_artifact_id(dispatch_id: &str) -> String {
    format!("artifact:workspace-final:{dispatch_id}")
}

fn framed_sha256(fields: &[&str]) -> String {
    let mut canonical = Vec::new();
    for field in fields {
        canonical.extend_from_slice(&(field.len() as u64).to_le_bytes());
        canonical.extend_from_slice(field.as_bytes());
    }
    sha256(&canonical)
}

fn framed_sha256_owned(fields: &[String]) -> String {
    framed_sha256(&fields.iter().map(String::as_str).collect::<Vec<_>>())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepositoryDispatchError {
    Rejected,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReturnArtifactPresence {
    Fresh,
    Replay,
}

async fn capture_workspace_state(
    material: &FrozenRepositoryMaterialV1,
    workspace: &Path,
    workspace_ref: &str,
) -> Result<CapturedWorkspaceState, RepositoryDispatchError> {
    let supervision_root = workspace
        .parent()
        .ok_or(RepositoryDispatchError::Rejected)?;
    let commit = git_text(
        material,
        workspace,
        &["rev-parse", "HEAD^{commit}"],
        supervision_root,
    )
    .await?;
    let tree = git_text(
        material,
        workspace,
        &["rev-parse", "HEAD^{tree}"],
        supervision_root,
    )
    .await?;
    let common_dir = git_text(
        material,
        workspace,
        &["rev-parse", "--git-common-dir"],
        supervision_root,
    )
    .await?;
    let common_dir = if Path::new(&common_dir).is_absolute() {
        PathBuf::from(common_dir)
    } else {
        workspace.join(common_dir)
    }
    .canonicalize()
    .map_err(|_| RepositoryDispatchError::Unavailable)?;
    if common_dir != material.git_common_dir() {
        return Err(RepositoryDispatchError::Rejected);
    }

    let paths = git_bytes(
        material,
        workspace,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        &[],
        None,
        supervision_root,
    )
    .await?;
    reject_external_attributes(material, workspace, &paths, supervision_root).await?;

    let temporary = tempfile::tempdir().map_err(|_| RepositoryDispatchError::Unavailable)?;
    let index = temporary.path().join("return.index");
    git_bytes(
        material,
        workspace,
        &["read-tree", material.baseline_commit()],
        &[],
        Some(&index),
        supervision_root,
    )
    .await?;
    git_bytes(
        material,
        workspace,
        &["add", "--all", "--", "."],
        &[],
        Some(&index),
        supervision_root,
    )
    .await?;
    let patch = git_bytes(
        material,
        workspace,
        &[
            "diff",
            "--cached",
            material.baseline_commit(),
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--",
        ],
        &[],
        Some(&index),
        supervision_root,
    )
    .await?;
    let names = git_bytes(
        material,
        workspace,
        &[
            "diff",
            "--cached",
            material.baseline_commit(),
            "--name-status",
            "-z",
            "--no-renames",
            "--",
        ],
        &[],
        Some(&index),
        supervision_root,
    )
    .await?;
    let status = git_bytes(
        material,
        workspace,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        &[],
        None,
        supervision_root,
    )
    .await?;
    let patch_content = content_address(&patch);
    Ok(CapturedWorkspaceState {
        patch,
        manifest: FinalWorkspaceManifestPayload {
            schema_version: "egopulse.workspace-final-manifest/v1".to_owned(),
            workspace_ref: workspace_ref.to_owned(),
            baseline_commit: material.baseline_commit().to_owned(),
            baseline_tree: material.baseline_tree().to_owned(),
            observed_head_commit: commit,
            observed_head_tree: tree,
            status_porcelain_sha256: sha256(&status),
            status_porcelain_bytes: status.len() as u64,
            patch_sha256: patch_content.digest,
            patch_bytes: patch_content.byte_length,
            entries: parse_name_status(&names)?,
        },
    })
}

async fn reject_external_attributes(
    material: &FrozenRepositoryMaterialV1,
    repository: &Path,
    nul_paths: &[u8],
    workspace_root: &Path,
) -> Result<(), RepositoryDispatchError> {
    let attributes = git_bytes(
        material,
        repository,
        &["check-attr", "-z", "--stdin", "--all"],
        nul_paths,
        None,
        workspace_root,
    )
    .await?;
    validate_attribute_output(&attributes)
}

fn validate_attribute_output(attributes: &[u8]) -> Result<(), RepositoryDispatchError> {
    let mut fields = attributes.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    let (triples, remainder) = fields.as_chunks::<3>();
    if !remainder.is_empty() {
        return Err(RepositoryDispatchError::Rejected);
    }
    for triple in triples {
        let attribute =
            std::str::from_utf8(triple[1]).map_err(|_| RepositoryDispatchError::Rejected)?;
        let value =
            std::str::from_utf8(triple[2]).map_err(|_| RepositoryDispatchError::Rejected)?;
        if matches!(attribute, "filter" | "working-tree-encoding") && value != "unspecified" {
            return Err(RepositoryDispatchError::Rejected);
        }
    }
    Ok(())
}

fn parse_name_status(
    bytes: &[u8],
) -> Result<Vec<FinalWorkspaceManifestEntry>, RepositoryDispatchError> {
    let mut fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    let (pairs, remainder) = fields.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(RepositoryDispatchError::Rejected);
    }
    pairs
        .iter()
        .map(|pair| {
            let status =
                std::str::from_utf8(pair[0]).map_err(|_| RepositoryDispatchError::Rejected)?;
            if !matches!(status, "A" | "M" | "D" | "T" | "U" | "X" | "B") {
                return Err(RepositoryDispatchError::Rejected);
            }
            Ok(FinalWorkspaceManifestEntry {
                status: status.to_owned(),
                path_hex: hex::encode(pair[1]),
            })
        })
        .collect()
}

fn final_manifest_valid(
    manifest: &FinalWorkspaceManifestPayload,
    sealed: &SealedRepositoryDispatchMaterial,
    patch: &ContentAddress,
) -> bool {
    manifest.schema_version == "egopulse.workspace-final-manifest/v1"
        && manifest.workspace_ref == sealed.workspace_ref
        && manifest.baseline_commit == sealed.baseline_commit
        && manifest.baseline_tree == sealed.baseline_tree
        && manifest.patch_sha256 == patch.digest
        && manifest.patch_bytes == patch.byte_length
        && git_object_id_valid(&manifest.observed_head_commit)
        && git_object_id_valid(&manifest.observed_head_tree)
        && lowercase_sha256_valid(&manifest.status_porcelain_sha256)
        && manifest.entries.iter().all(|entry| {
            matches!(
                entry.status.as_str(),
                "A" | "M" | "D" | "T" | "U" | "X" | "B"
            ) && !entry.path_hex.is_empty()
                && entry.path_hex.len() % 2 == 0
                && entry
                    .path_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn git_object_id_valid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lowercase_sha256_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn reject_unsafe_checkout_material(
    material: &FrozenRepositoryMaterialV1,
    workspace_root: &Path,
) -> Result<(), RepositoryDispatchError> {
    let tree = git_bytes(
        material,
        material.repository_root(),
        &[
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            material.baseline_commit(),
        ],
        &[],
        None,
        workspace_root,
    )
    .await?;
    let mut paths = Vec::new();
    for entry in tree
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(RepositoryDispatchError::Rejected)?;
        let header =
            std::str::from_utf8(&entry[..tab]).map_err(|_| RepositoryDispatchError::Rejected)?;
        if header.starts_with("160000 ") {
            return Err(RepositoryDispatchError::Rejected);
        }
        paths.extend_from_slice(&entry[tab + 1..]);
        paths.push(0);
    }
    let temp = tempfile::tempdir().map_err(|_| RepositoryDispatchError::Unavailable)?;
    let index = temp.path().join("baseline.index");
    git_bytes(
        material,
        material.repository_root(),
        &["read-tree", material.baseline_commit()],
        &[],
        Some(&index),
        workspace_root,
    )
    .await?;
    let attributes = git_bytes(
        material,
        material.repository_root(),
        &["check-attr", "--cached", "-z", "--stdin", "--all"],
        &paths,
        Some(&index),
        workspace_root,
    )
    .await?;
    validate_attribute_output(&attributes)
}

async fn create_detached_worktree(
    material: &FrozenRepositoryMaterialV1,
    workspace_root: &Path,
    destination: &Path,
) -> Result<(), RepositoryDispatchError> {
    let destination = git_path_argument(destination)?;
    git_bytes(
        material,
        material.repository_root(),
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            &destination,
            material.baseline_commit(),
        ],
        &[],
        None,
        workspace_root,
    )
    .await?;
    Ok(())
}

async fn verify_clean_workspace(
    material: &FrozenRepositoryMaterialV1,
    workspace: &Path,
) -> Result<(), RepositoryDispatchError> {
    let supervision_root = workspace
        .parent()
        .ok_or(RepositoryDispatchError::Rejected)?;
    let commit = git_text(
        material,
        workspace,
        &["rev-parse", "HEAD^{commit}"],
        supervision_root,
    )
    .await?;
    let tree = git_text(
        material,
        workspace,
        &["rev-parse", "HEAD^{tree}"],
        supervision_root,
    )
    .await?;
    let common_dir = git_text(
        material,
        workspace,
        &["rev-parse", "--git-common-dir"],
        supervision_root,
    )
    .await?;
    let common_dir = if Path::new(&common_dir).is_absolute() {
        PathBuf::from(common_dir)
    } else {
        workspace.join(common_dir)
    }
    .canonicalize()
    .map_err(|_| RepositoryDispatchError::Unavailable)?;
    let status = git_bytes(
        material,
        workspace,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        &[],
        None,
        supervision_root,
    )
    .await?;
    if commit != material.baseline_commit()
        || tree != material.baseline_tree()
        || common_dir != material.git_common_dir()
        || !status.is_empty()
    {
        return Err(RepositoryDispatchError::Rejected);
    }
    Ok(())
}

async fn git_text(
    material: &FrozenRepositoryMaterialV1,
    cwd: &Path,
    arguments: &[&str],
    workspace_root: &Path,
) -> Result<String, RepositoryDispatchError> {
    let bytes = git_bytes(material, cwd, arguments, &[], None, workspace_root).await?;
    Ok(std::str::from_utf8(&bytes)
        .map_err(|_| RepositoryDispatchError::Rejected)?
        .trim()
        .to_owned())
}

async fn git_bytes(
    material: &FrozenRepositoryMaterialV1,
    cwd: &Path,
    arguments: &[&str],
    input: &[u8],
    index: Option<&Path>,
    workspace_root: &Path,
) -> Result<Vec<u8>, RepositoryDispatchError> {
    let hooks = workspace_root.join(".egopulse-empty-hooks");
    fs::create_dir_all(&hooks).map_err(|_| RepositoryDispatchError::Unavailable)?;
    let hooks = hooks
        .canonicalize()
        .map_err(|_| RepositoryDispatchError::Unavailable)?;
    let mut spec = SupervisedProcessSpec::new(material.git_executable(), cwd);
    spec.arguments = arguments.iter().map(|value| (*value).to_owned()).collect();
    spec.clear_environment = true;
    spec.inherited_environment = [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    spec.environment_overrides = vec![
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("GIT_PAGER".to_owned(), "cat".to_owned()),
        ("GIT_OPTIONAL_LOCKS".to_owned(), "0".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        (
            "GIT_CONFIG_GLOBAL".to_owned(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.to_owned(),
        ),
        ("GIT_LFS_SKIP_SMUDGE".to_owned(), "1".to_owned()),
        ("GIT_CONFIG_COUNT".to_owned(), "5".to_owned()),
        ("GIT_CONFIG_KEY_0".to_owned(), "core.fsmonitor".to_owned()),
        ("GIT_CONFIG_VALUE_0".to_owned(), "false".to_owned()),
        ("GIT_CONFIG_KEY_1".to_owned(), "core.hooksPath".to_owned()),
        ("GIT_CONFIG_VALUE_1".to_owned(), git_path_argument(&hooks)?),
        ("GIT_CONFIG_KEY_2".to_owned(), "protocol.allow".to_owned()),
        ("GIT_CONFIG_VALUE_2".to_owned(), "never".to_owned()),
        ("GIT_CONFIG_KEY_3".to_owned(), "core.autocrlf".to_owned()),
        ("GIT_CONFIG_VALUE_3".to_owned(), "false".to_owned()),
        ("GIT_CONFIG_KEY_4".to_owned(), "safe.directory".to_owned()),
        (
            "GIT_CONFIG_VALUE_4".to_owned(),
            crate::repository_material::trusted_repository_git_path(cwd)
                .map_err(|_| RepositoryDispatchError::Rejected)?,
        ),
        ("LC_ALL".to_owned(), "C".to_owned()),
    ];
    if let Some(index) = index {
        spec.environment_overrides
            .push(("GIT_INDEX_FILE".to_owned(), git_path_argument(index)?));
    }
    let receipt = run_governed_process_outcome(
        &spec,
        input,
        GovernedProcessBudget {
            timeout: GIT_TIMEOUT,
            output_limit_bytes: GIT_OUTPUT_LIMIT,
        },
    )
    .await
    .map_err(map_process_error)?;
    if receipt.exit_code != 0 || !receipt.stderr.is_empty() {
        return Err(RepositoryDispatchError::Rejected);
    }
    Ok(receipt.stdout)
}

fn git_path_argument(path: &Path) -> Result<String, RepositoryDispatchError> {
    let value = path.to_str().ok_or(RepositoryDispatchError::Rejected)?;
    #[cfg(windows)]
    {
        if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
            return Ok(format!(r"\\{unc}"));
        }
        if let Some(local) = value.strip_prefix(r"\\?\") {
            return Ok(local.to_owned());
        }
    }
    Ok(value.to_owned())
}

fn execute_artifact_command(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    variant: artifact_command::Command,
    principal: &AuthenticatedArtifactPrincipal,
) -> Result<(), TaskDispatchMaterialRejection> {
    let mut command = ArtifactCommand {
        command: Some(variant),
    };
    let digest = canonical_request_digest(&command)
        .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_COMMAND_INVALID"))?;
    match command
        .command
        .as_mut()
        .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_COMMAND_INVALID"))?
    {
        artifact_command::Command::StageArtifact(command) => {
            command
                .metadata
                .as_mut()
                .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_COMMAND_INVALID"))?
                .request_digest_sha256 = digest
        }
        artifact_command::Command::SealArtifact(command) => {
            command
                .metadata
                .as_mut()
                .ok_or_else(|| rejection("REPOSITORY_ARTIFACT_COMMAND_INVALID"))?
                .request_digest_sha256 = digest
        }
        _ => return Err(rejection("REPOSITORY_ARTIFACT_COMMAND_INVALID")),
    }
    let result = authority
        .execute(&command, principal)
        .map_err(|_| rejection("REPOSITORY_ARTIFACT_AUTHORITY_UNAVAILABLE"))?;
    if !result.committed {
        return Err(rejection("REPOSITORY_ARTIFACT_REJECTED"));
    }
    Ok(())
}

fn artifact_metadata(dispatch_id: &str, role: &str, operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("repository-dispatch:{operation}:{role}:{dispatch_id}"),
        idempotency_key: format!("{dispatch_id}:{role}:{operation}"),
        idempotency_scope: dispatch_id.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: dispatch_id.to_owned(),
        causation_id: Some(format!("repository-dispatch:{dispatch_id}")),
    }
}

fn artifact_principal(
    kind: ArtifactPrincipalKind,
    principal_id: &str,
) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
    }
}

fn content_address(bytes: &[u8]) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: sha256(bytes),
        byte_length: bytes.len() as u64,
    }
}

fn rejection(code: &str) -> TaskDispatchMaterialRejection {
    TaskDispatchMaterialRejection {
        safe_detail_code: code.to_owned(),
    }
}

fn map_material_rejection(error: RepositoryDispatchError) -> TaskDispatchMaterialRejection {
    rejection(match error {
        RepositoryDispatchError::Rejected => "REPOSITORY_WORKSPACE_REJECTED",
        RepositoryDispatchError::Unavailable => "REPOSITORY_WORKSPACE_UNAVAILABLE",
    })
}

fn map_return_capture_error(error: RepositoryDispatchError) -> HarnessError {
    match error {
        RepositoryDispatchError::Rejected => return_rejection("REPOSITORY_RETURN_CAPTURE_REJECTED"),
        RepositoryDispatchError::Unavailable => harness_rejection(
            HarnessErrorCode::DependencyUnavailable,
            "REPOSITORY_RETURN_CAPTURE_UNAVAILABLE",
        ),
    }
}

fn map_return_artifact_error(_error: TaskDispatchMaterialRejection) -> HarnessError {
    return_rejection("REPOSITORY_RETURN_ARTIFACT_INVALID")
}

fn return_rejection(detail: &str) -> HarnessError {
    harness_rejection(HarnessErrorCode::IntegrityFailure, detail)
}

fn map_process_error(error: GovernedProcessError) -> RepositoryDispatchError {
    match error {
        GovernedProcessError::InvalidSpecification => RepositoryDispatchError::Rejected,
        GovernedProcessError::Spawn
        | GovernedProcessError::InputDelivery
        | GovernedProcessError::Timeout
        | GovernedProcessError::Crashed
        | GovernedProcessError::OutputLimit
        | GovernedProcessError::Io
        | GovernedProcessError::Protocol => RepositoryDispatchError::Unavailable,
    }
}

fn harness_rejection(code: HarnessErrorCode, detail: &str) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery: code == HarnessErrorCode::DependencyUnavailable,
        recovery_required: false,
        error_fingerprint: None,
        audit_ref: None,
    }
}

fn contract_reference_valid(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

fn unix_seconds() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .try_into()
        .ok()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, process::Command};

    use crate::repository_material::{FrozenContractReference, RepositoryAcceptanceContractV1};

    struct GitFixture {
        _root: tempfile::TempDir,
        repository: PathBuf,
        workspaces: PathBuf,
        git: PathBuf,
    }

    impl GitFixture {
        fn new(attributes: Option<&str>) -> Self {
            let root = tempfile::tempdir().expect("temporary Git fixture");
            let repository = root.path().join("source");
            let workspaces = root.path().join("workspaces");
            fs::create_dir_all(&repository).expect("source directory");
            fs::create_dir_all(&workspaces).expect("workspace directory");
            let git = test_git_executable();
            git_ok(&git, &repository, &["init", "--quiet"]);
            git_ok(
                &git,
                &repository,
                &["config", "user.email", "egopulse-test@example.invalid"],
            );
            git_ok(&git, &repository, &["config", "user.name", "EgoPulse Test"]);
            fs::write(repository.join("tracked.txt"), "baseline\n").expect("tracked file");
            fs::write(repository.join("deleted.txt"), "delete me\n").expect("deleted file");
            if let Some(attributes) = attributes {
                fs::write(repository.join(".gitattributes"), attributes).expect("attributes file");
            }
            git_ok(&git, &repository, &["add", "--all"]);
            git_ok(&git, &repository, &["commit", "--quiet", "-m", "baseline"]);
            Self {
                _root: root,
                repository: repository.canonicalize().expect("canonical source"),
                workspaces: workspaces.canonicalize().expect("canonical workspaces"),
                git,
            }
        }

        fn material(&self) -> FrozenRepositoryMaterialV1 {
            FrozenRepositoryMaterialV1 {
                schema_version: "egopulse.repository-material/v1".to_owned(),
                contract_path: self
                    .repository
                    .join("acceptance.json")
                    .display()
                    .to_string(),
                repository_root: self.repository.display().to_string(),
                git_executable: self.git.display().to_string(),
                acceptance_contract_ref: FrozenContractReference {
                    contract_id: "acceptance".to_owned(),
                    version: "v1".to_owned(),
                    sha256: "a".repeat(64),
                },
                acceptance_contract: RepositoryAcceptanceContractV1 {
                    schema_version: "repository_change_acceptance/v1".to_owned(),
                    contract_id: "acceptance".to_owned(),
                    version: "v1".to_owned(),
                    revision: 1,
                    allowed_paths: vec!["tracked.txt".to_owned()],
                    forbidden_paths: Vec::new(),
                    read_only_paths: Vec::new(),
                    required_commands: Vec::new(),
                    evidence_requirements: Vec::new(),
                },
                baseline_commit: git_text_direct(&self.git, &self.repository, "HEAD^{commit}"),
                baseline_tree: git_text_direct(&self.git, &self.repository, "HEAD^{tree}"),
                git_common_dir: self
                    .repository
                    .join(".git")
                    .canonicalize()
                    .expect("canonical common dir")
                    .display()
                    .to_string(),
                clean_worktree: true,
            }
        }
    }

    #[tokio::test]
    async fn detached_task_workspace_keeps_the_frozen_commit_when_source_advances() {
        let fixture = GitFixture::new(None);
        let material = fixture.material();
        reject_unsafe_checkout_material(&material, &fixture.workspaces)
            .await
            .expect("safe frozen tree");
        let workspace = fixture.workspaces.join("repository-task-one");
        create_detached_worktree(&material, &fixture.workspaces, &workspace)
            .await
            .expect("detached worktree");
        verify_clean_workspace(&material, &workspace)
            .await
            .expect("clean frozen worktree");

        fs::write(fixture.repository.join("tracked.txt"), "advanced\n").expect("advance source");
        git_ok(&fixture.git, &fixture.repository, &["add", "--all"]);
        git_ok(
            &fixture.git,
            &fixture.repository,
            &["commit", "--quiet", "-m", "advance"],
        );

        verify_clean_workspace(&material, &workspace)
            .await
            .expect("Task worktree remains fixed at frozen commit");
    }

    #[tokio::test]
    async fn checkout_rejects_a_frozen_tree_with_external_filter_attributes() {
        let fixture = GitFixture::new(Some("*.txt filter=untrusted\n"));
        assert_eq!(
            reject_unsafe_checkout_material(&fixture.material(), &fixture.workspaces).await,
            Err(RepositoryDispatchError::Rejected)
        );
    }

    #[tokio::test]
    async fn return_capture_contains_add_delete_and_binary_patch_and_detects_later_change() {
        let fixture = GitFixture::new(None);
        let material = fixture.material();
        let workspace = fixture.workspaces.join("repository-task-return");
        create_detached_worktree(&material, &fixture.workspaces, &workspace)
            .await
            .expect("detached worktree");
        fs::write(workspace.join("tracked.txt"), "changed\n").expect("modified file");
        fs::remove_file(workspace.join("deleted.txt")).expect("deleted file");
        fs::write(workspace.join("added.bin"), [0_u8, 159, 146, 150, 255]).expect("binary file");

        let captured = capture_workspace_state(&material, &workspace, "repository-task-return")
            .await
            .expect("capture repository return");
        let statuses = captured
            .manifest
            .entries
            .iter()
            .map(|entry| entry.status.as_str())
            .collect::<BTreeSet<_>>();
        assert!(statuses.contains("A"));
        assert!(statuses.contains("D"));
        assert!(statuses.contains("M"));
        assert!(
            String::from_utf8_lossy(&captured.patch).contains("GIT binary patch"),
            "binary content must use Git's binary patch encoding"
        );

        fs::write(workspace.join("tracked.txt"), "changed again\n").expect("later mutation");
        let changed = capture_workspace_state(&material, &workspace, "repository-task-return")
            .await
            .expect("capture changed repository return");
        assert_ne!(captured, changed);
    }

    #[test]
    fn repository_git_trust_accepts_only_the_exact_bound_directory() {
        let git = test_git_executable();
        let root = tempfile::tempdir().expect("private Git trust fixture");
        let bound = root.path().join("bound repository");
        let other = root.path().join("other repository");
        for path in [&bound, &other] {
            fs::create_dir(path).expect("fixture directory");
            git_ok(&git, path, &["init", "--quiet"]);
        }
        let bound = bound.canonicalize().expect("bound canonical repository");
        let trusted = crate::repository_material::trusted_repository_git_path(&bound)
            .expect("exact configured path");
        let status = |cwd: &Path, trust: Option<&str>| {
            let mut command = Command::new(&git);
            command
                .env_clear()
                .current_dir(cwd)
                .args(["status", "--porcelain"]);
            for name in ["SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env(
                    "GIT_CONFIG_GLOBAL",
                    if cfg!(windows) { "NUL" } else { "/dev/null" },
                )
                // Git's own t0033-safe-directory.sh uses this deterministic
                // ownership switch; no OS user or filesystem ACL is changed.
                .env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1");
            if let Some(trust) = trust {
                command
                    .env("GIT_CONFIG_COUNT", "1")
                    .env("GIT_CONFIG_KEY_0", "safe.directory")
                    .env("GIT_CONFIG_VALUE_0", trust);
            }
            command.output().expect("controlled Git ownership check")
        };
        let rejected = status(&bound, None);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("dubious ownership"));
        let accepted = status(&bound, Some(&trusted));
        assert!(
            accepted.status.success(),
            "exact bound repository must be accepted"
        );
        assert!(accepted.stderr.is_empty());
        let other = status(&other, Some(&trusted));
        assert!(
            !other.status.success(),
            "one repository cannot authorize its sibling"
        );
        assert!(String::from_utf8_lossy(&other.stderr).contains("dubious ownership"));
        assert!(
            crate::repository_material::trusted_repository_git_path(Path::new("relative")).is_err()
        );
        assert!(crate::repository_material::trusted_repository_git_path(&bound.join("*")).is_err());
    }

    fn test_git_executable() -> PathBuf {
        #[cfg(windows)]
        let output = Command::new("where.exe")
            .arg("git.exe")
            .output()
            .expect("locate Git");
        #[cfg(not(windows))]
        let output = Command::new("which")
            .arg("git")
            .output()
            .expect("locate Git");
        assert!(
            output.status.success(),
            "Git is required for this regression"
        );
        PathBuf::from(
            String::from_utf8(output.stdout)
                .expect("Git path UTF-8")
                .lines()
                .next()
                .expect("Git path")
                .trim(),
        )
        .canonicalize()
        .expect("canonical Git executable")
    }

    fn git_ok(git: &Path, cwd: &Path, arguments: &[&str]) {
        let output = Command::new(git)
            .current_dir(cwd)
            .args(arguments)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .output()
            .expect("run fixture Git");
        assert!(
            output.status.success(),
            "fixture Git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_text_direct(git: &Path, cwd: &Path, revision: &str) -> String {
        let output = Command::new(git)
            .current_dir(cwd)
            .args(["rev-parse", revision])
            .output()
            .expect("read Git revision");
        assert!(output.status.success(), "read Git revision");
        String::from_utf8(output.stdout)
            .expect("revision UTF-8")
            .trim()
            .to_owned()
    }
}
