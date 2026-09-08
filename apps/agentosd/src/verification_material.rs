use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use egopulse_artifact_authority::{canonical_artifact_set_manifest, content_address};
use egopulse_cognition_runtime::context_authority::ContextAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactDescriptor, ArtifactSemanticClass, ArtifactSetStatus, ArtifactStatus, Claim,
        ClaimSourceType, ClaimStatus, ContentAddress, Evidence, EvidenceProducerClass,
        EvidenceStatus, HashAlgorithm, IntegrityStatus, LineageBinding,
    },
    common::v1::ContractReference,
    verification::v1::VerificationBinding,
};
use egopulse_verification_authority::ArtifactContentSource;

use crate::{
    repository_command::{
        RepositoryCommandEvidenceDecodeRequest, RepositoryCommandSupervisionFailure,
        decode_repository_command_evidence,
    },
    repository_dispatch::{
        FinalWorkspaceManifestPayload, InitialWorkspaceManifestPayload, RepositoryBaselinePayload,
        derived_rework_workspace_ref, derived_workspace_ref, repository_source_binding_ref,
        rework_execution_revision_chain_valid, rework_repository_context,
    },
    repository_material::{
        FrozenRepositoryMaterialV1, RepositoryCommandRequirement, RepositoryPathAccess,
        frozen_repository_material_from_compiled_context,
    },
    rework_preparation::SealedReworkRepositoryCarryForward,
};

const BASELINE_SCHEMA: &str = "egopulse.repository-baseline/v1";
const INITIAL_MANIFEST_SCHEMA: &str = "egopulse.workspace-initial-manifest/v1";
const FINAL_MANIFEST_SCHEMA: &str = "egopulse.workspace-final-manifest/v1";

#[derive(Clone, Debug)]
pub(crate) struct RepositoryVerificationMaterialPolicy {
    pub(crate) repository_artifact_type_ref: ContractReference,
    pub(crate) repository_transformation_ref: ContractReference,
    pub(crate) command_intent_type_ref: ContractReference,
    pub(crate) command_intent_transformation_ref: ContractReference,
    pub(crate) command_receipt_type_ref: ContractReference,
    pub(crate) command_receipt_transformation_ref: ContractReference,
    pub(crate) retention_profile_ref: ContractReference,
    pub(crate) evidence_profile_ref: ContractReference,
    pub(crate) attempt_supervisor_principal_id: String,
    pub(crate) supervised_runner_principal_id: String,
    pub(crate) governed_collector_principal_id: String,
    pub(crate) repository_component_name: String,
    pub(crate) command_component_name: String,
}

pub(crate) struct RepositoryVerificationMaterialResolver {
    context: Arc<Mutex<ContextAuthority>>,
    artifacts: Arc<dyn ArtifactContentSource>,
    workspace_root: PathBuf,
    policy: RepositoryVerificationMaterialPolicy,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedRepositoryVerificationMaterial {
    pub(crate) binding: VerificationBinding,
    pub(crate) claim: Claim,
    pub(crate) claim_statement: Vec<u8>,
    pub(crate) frozen: FrozenRepositoryMaterialV1,
    pub(crate) workspace_root: PathBuf,
    pub(crate) scope: VerifiedRepositoryScope,
    pub(crate) baseline: VerifiedRepositoryBaseline,
    pub(crate) patch: VerifiedArtifactBytes,
    pub(crate) initial_manifest: VerifiedArtifactBytes,
    pub(crate) final_manifest: VerifiedArtifactBytes,
    pub(crate) command_observations: Vec<VerifiedRepositoryCommandObservation>,
    pub(crate) changed_paths: Vec<RepositoryChangedPath>,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) unverified_items: Vec<RepositoryMaterialUnverifiedItem>,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedArtifactBytes {
    pub(crate) descriptor: ArtifactDescriptor,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRepositoryScope {
    pub(crate) acceptance_contract_ref: ContractReference,
    pub(crate) allowed_paths: Vec<String>,
    pub(crate) forbidden_paths: Vec<String>,
    pub(crate) read_only_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedRepositoryBaseline {
    pub(crate) artifact: VerifiedArtifactBytes,
    pub(crate) input_snapshot_id: String,
    pub(crate) input_bundle_sha256: String,
    pub(crate) workspace_ref: String,
    pub(crate) source_binding_ref: String,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryChangedPath {
    Utf8 {
        status: String,
        relative_path: String,
    },
    UnverifiedNonUtf8 {
        status: String,
        path_hex: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedRepositoryCommandObservation {
    pub(crate) command_id: String,
    pub(crate) criterion_id: String,
    pub(crate) requirement: RepositoryCommandRequirement,
    pub(crate) expected_exit_code: i32,
    pub(crate) command_spec_sha256: String,
    pub(crate) intent: Option<VerifiedArtifactBytes>,
    pub(crate) receipt: Option<VerifiedArtifactBytes>,
    pub(crate) outcome: RepositoryCommandObservationOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryCommandObservationOutcome {
    Completed {
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration_ms: u64,
    },
    SupervisionFailed {
        failure: RepositoryCommandSupervisionFailure,
    },
    MissingReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryMaterialUnverifiedItem {
    pub(crate) item_id: String,
    pub(crate) reason_code: String,
    pub(crate) area: RepositoryMaterialVerificationArea,
    pub(crate) criterion_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryMaterialVerificationArea {
    Scope,
    Tests,
    Review,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum VerificationMaterialError {
    #[error("repository verification material is invalid")]
    Invalid,
    #[error("repository verification material is unavailable")]
    Unavailable,
}

struct VerifiedReworkCarryForward {
    carry: SealedReworkRepositoryCarryForward,
    final_payload: FinalWorkspaceManifestPayload,
    patch_is_empty: bool,
}

impl RepositoryVerificationMaterialResolver {
    pub(crate) fn new(
        context: Arc<Mutex<ContextAuthority>>,
        artifacts: Arc<dyn ArtifactContentSource>,
        workspace_root: PathBuf,
        policy: RepositoryVerificationMaterialPolicy,
    ) -> Result<Self, VerificationMaterialError> {
        let workspace_root = workspace_root
            .canonicalize()
            .map_err(|_| VerificationMaterialError::Invalid)?;
        if !workspace_root.is_dir() || !policy_valid(&policy) {
            return Err(VerificationMaterialError::Invalid);
        }
        Ok(Self {
            context,
            artifacts,
            workspace_root,
            policy,
        })
    }

    pub(crate) fn resolve(
        &self,
        binding: &VerificationBinding,
        now_seconds: i64,
    ) -> Result<VerifiedRepositoryVerificationMaterial, VerificationMaterialError> {
        let lineage = binding
            .lineage
            .as_ref()
            .filter(|lineage| lineage_complete(lineage))
            .ok_or(VerificationMaterialError::Invalid)?;
        let expected_manifest = binding
            .artifact_set_manifest
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?;
        let acceptance_ref = binding
            .acceptance_contract_ref
            .as_ref()
            .filter(|reference| contract_reference_valid(reference))
            .ok_or(VerificationMaterialError::Invalid)?;
        let semantic_profile_ref = binding
            .claim_semantic_profile_ref
            .as_ref()
            .filter(|reference| contract_reference_valid(reference))
            .ok_or(VerificationMaterialError::Invalid)?;

        let set = self
            .artifacts
            .read_artifact_set(&binding.artifact_set_id)
            .map_err(map_source_error)?
            .ok_or(VerificationMaterialError::Unavailable)?;
        if set.artifact_set_id != binding.artifact_set_id
            || set.status != ArtifactSetStatus::Sealed as i32
            || set.lineage.as_ref() != Some(lineage)
            || set.canonical_manifest.as_ref() != Some(expected_manifest)
            || content_address(&canonical_artifact_set_manifest(&set)) != *expected_manifest
            || unique_nonempty(&set.artifact_ids).is_none()
            || unique_nonempty(&set.claim_ids).is_none()
            || unique_nonempty(&set.evidence_ids).is_none()
            || !set.claim_ids.iter().any(|id| id == &binding.claim_id)
        {
            return Err(VerificationMaterialError::Invalid);
        }

        let claim = self.read_claim(&binding.claim_id)?;
        validate_claim(
            &claim,
            binding,
            lineage,
            semantic_profile_ref,
            acceptance_ref,
            &set.artifact_ids,
            &self.policy,
        )?;
        let claim_statement = claim
            .statement
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?;
        let statement_bytes = self
            .artifacts
            .read_content(claim_statement)
            .map_err(map_source_error)?;
        if content_address(&statement_bytes) != *claim_statement {
            return Err(VerificationMaterialError::Invalid);
        }
        let mut verified_evidence = Vec::with_capacity(set.evidence_ids.len());
        for evidence_id in &set.evidence_ids {
            let evidence = self.read_evidence(evidence_id)?;
            self.validate_evidence(&evidence, binding, lineage, &set.artifact_ids)?;
            verified_evidence.push(evidence);
        }

        let artifacts = set
            .artifact_ids
            .iter()
            .map(|id| {
                self.read_verified_artifact(id, lineage)
                    .map(|value| (id.clone(), value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let baseline_id = format!("artifact:repository-baseline:{}", lineage.dispatch_id);
        let initial_id = format!("artifact:workspace-initial:{}", lineage.dispatch_id);
        let patch_id = format!("artifact:repository-patch:{}", lineage.dispatch_id);
        let final_id = format!("artifact:workspace-final:{}", lineage.dispatch_id);
        let baseline = artifacts
            .get(&baseline_id)
            .cloned()
            .ok_or(VerificationMaterialError::Invalid)?;
        let initial_manifest = artifacts
            .get(&initial_id)
            .cloned()
            .ok_or(VerificationMaterialError::Invalid)?;
        let patch = artifacts
            .get(&patch_id)
            .cloned()
            .ok_or(VerificationMaterialError::Invalid)?;
        let final_manifest = artifacts
            .get(&final_id)
            .cloned()
            .ok_or(VerificationMaterialError::Invalid)?;

        let baseline_payload: RepositoryBaselinePayload =
            serde_json::from_slice(&baseline.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        validate_baseline_payload(&baseline_payload, lineage, acceptance_ref)?;
        let resolved = self
            .context
            .lock()
            .map_err(|_| VerificationMaterialError::Unavailable)?
            .resolve_for_consumption(&baseline_payload.input_snapshot_id, now_seconds)
            .map_err(|_| VerificationMaterialError::Unavailable)?;
        if resolved.snapshot.compiled_context_sha256 != baseline_payload.input_bundle_sha256 {
            return Err(VerificationMaterialError::Invalid);
        }
        let frozen = frozen_repository_material_from_compiled_context(&resolved.compiled_context)
            .map_err(|_| VerificationMaterialError::Invalid)?
            .ok_or(VerificationMaterialError::Invalid)?;
        frozen
            .validate_stored(acceptance_ref)
            .map_err(|_| VerificationMaterialError::Invalid)?;
        let rework = self.resolve_rework_carry_forward(
            &resolved.compiled_context,
            lineage,
            acceptance_ref,
            &frozen,
        )?;
        let expected_workspace_ref = match rework.as_ref() {
            Some(verified) => derived_rework_workspace_ref(
                &lineage.task_id,
                lineage.work_revision,
                &baseline_payload.input_snapshot_id,
                &baseline_payload.baseline_commit,
                &verified.carry.repository_patch_sha256,
            ),
            None => derived_workspace_ref(
                &lineage.task_id,
                &baseline_payload.input_snapshot_id,
                &baseline_payload.baseline_commit,
            ),
        };
        if frozen.baseline_commit != baseline_payload.baseline_commit
            || frozen.baseline_tree != baseline_payload.baseline_tree
            || expected_workspace_ref != baseline_payload.workspace_ref
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let source_binding_ref = repository_source_binding_ref(
            &baseline_payload,
            lineage,
            &baseline_payload.input_bundle_sha256,
        );
        let workspace_root =
            exact_workspace_root(&self.workspace_root, &baseline_payload.workspace_ref)?;

        validate_repository_artifact(
            &baseline,
            ArtifactSemanticClass::RepositoryBaseline,
            lineage,
            &baseline_payload.workspace_ref,
            &source_binding_ref,
            &[],
            &self.policy,
        )?;
        let initial_input_ids = match rework.as_ref() {
            Some(verified) => vec![
                baseline_id.clone(),
                verified.carry.repository_patch_artifact_id.clone(),
                verified.carry.final_manifest_artifact_id.clone(),
            ],
            None => vec![baseline_id.clone()],
        };
        validate_repository_artifact(
            &initial_manifest,
            ArtifactSemanticClass::WorkspaceManifest,
            lineage,
            &baseline_payload.workspace_ref,
            &source_binding_ref,
            &initial_input_ids,
            &self.policy,
        )?;
        validate_repository_artifact(
            &patch,
            ArtifactSemanticClass::RepositoryPatch,
            lineage,
            &baseline_payload.workspace_ref,
            &source_binding_ref,
            &[baseline_id.clone(), initial_id.clone()],
            &self.policy,
        )?;
        validate_repository_artifact(
            &final_manifest,
            ArtifactSemanticClass::WorkspaceManifest,
            lineage,
            &baseline_payload.workspace_ref,
            &source_binding_ref,
            &[baseline_id.clone(), initial_id.clone(), patch_id.clone()],
            &self.policy,
        )?;

        let initial_payload: InitialWorkspaceManifestPayload =
            serde_json::from_slice(&initial_manifest.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        if !initial_payload_matches_lineage(&initial_payload, &baseline_payload, lineage)
            || !initial_manifest_state_matches(&initial_payload, rework.as_ref())
        {
            return Err(VerificationMaterialError::Invalid);
        }

        let final_payload: FinalWorkspaceManifestPayload =
            serde_json::from_slice(&final_manifest.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        if !final_payload_matches(
            &final_payload,
            &baseline_payload,
            &patch,
            &baseline_payload.workspace_ref,
        ) {
            return Err(VerificationMaterialError::Invalid);
        }

        let mut changed_paths = Vec::with_capacity(final_payload.entries.len());
        let mut unverified_items = Vec::new();
        for entry in &final_payload.entries {
            let bytes =
                hex::decode(&entry.path_hex).map_err(|_| VerificationMaterialError::Invalid)?;
            if bytes.is_empty() || bytes.contains(&0) {
                return Err(VerificationMaterialError::Invalid);
            }
            match String::from_utf8(bytes) {
                Ok(relative_path) if safe_relative_git_path(&relative_path) => {
                    changed_paths.push(RepositoryChangedPath::Utf8 {
                        status: entry.status.clone(),
                        relative_path,
                    });
                }
                Ok(_) => return Err(VerificationMaterialError::Invalid),
                Err(_) => {
                    changed_paths.push(RepositoryChangedPath::UnverifiedNonUtf8 {
                        status: entry.status.clone(),
                        path_hex: entry.path_hex.clone(),
                    });
                    unverified_items.push(RepositoryMaterialUnverifiedItem {
                        item_id: format!("path:{}", entry.path_hex),
                        reason_code: "NON_UTF8_CHANGED_PATH".to_owned(),
                        area: RepositoryMaterialVerificationArea::Scope,
                        criterion_id: None,
                    });
                }
            }
        }

        let receipt_candidates = artifacts
            .values()
            .filter(|artifact| {
                artifact.descriptor.semantic_class == ArtifactSemanticClass::CommandReceipt as i32
            })
            .cloned()
            .collect::<Vec<_>>();
        for receipt in &receipt_candidates {
            validate_command_receipt_artifact(
                receipt,
                lineage,
                &baseline_payload.workspace_ref,
                &source_binding_ref,
                &self.policy,
            )?;
        }
        let expected_inputs = vec![baseline_id, initial_id, patch_id, final_id];
        let mut consumed_receipts = BTreeSet::new();
        let mut command_observations =
            Vec::with_capacity(frozen.acceptance_contract.required_commands.len());
        for command in &frozen.acceptance_contract.required_commands {
            let verification_area = command_verification_area(&command.criterion_id)?;
            let mut matched = None;
            for receipt in &receipt_candidates {
                let provenance = receipt
                    .descriptor
                    .provenance
                    .as_ref()
                    .ok_or(VerificationMaterialError::Invalid)?;
                let intent_id = provenance
                    .input_artifact_ids
                    .last()
                    .ok_or(VerificationMaterialError::Invalid)?;
                let intent = self.read_verified_artifact(intent_id, lineage)?;
                validate_command_intent_artifact(
                    &intent,
                    lineage,
                    &baseline_payload.workspace_ref,
                    &source_binding_ref,
                    &expected_inputs,
                    &self.policy,
                )?;
                let Some(decoded) =
                    decode_repository_command_evidence(RepositoryCommandEvidenceDecodeRequest {
                        material: &frozen,
                        command,
                        lineage,
                        workspace_ref: &baseline_payload.workspace_ref,
                        source_binding_ref: &source_binding_ref,
                        expected_input_artifact_ids: &expected_inputs,
                        observed_intent_input_artifact_ids: &intent
                            .descriptor
                            .provenance
                            .as_ref()
                            .ok_or(VerificationMaterialError::Invalid)?
                            .input_artifact_ids,
                        observed_receipt_input_artifact_ids: &provenance.input_artifact_ids,
                        intent_bytes: &intent.bytes,
                        receipt_bytes: &receipt.bytes,
                    })
                    .ok()
                else {
                    continue;
                };
                if matched.is_some() || consumed_receipts.contains(&receipt.descriptor.artifact_id)
                {
                    return Err(VerificationMaterialError::Invalid);
                }
                matched = Some((intent, receipt.clone(), decoded));
            }
            let observation = if let Some((intent, receipt, decoded)) = matched {
                consumed_receipts.insert(receipt.descriptor.artifact_id.clone());
                let outcome = match (
                    decoded.receipt.exit_code,
                    decoded.receipt.supervision_failure,
                ) {
                    (Some(exit_code), None) => RepositoryCommandObservationOutcome::Completed {
                        exit_code,
                        stdout: decoded.receipt.stdout,
                        stderr: decoded.receipt.stderr,
                        duration_ms: decoded.receipt.duration_ms,
                    },
                    (None, Some(failure)) => {
                        unverified_items.push(RepositoryMaterialUnverifiedItem {
                            item_id: format!("command:{}", command.command_id),
                            reason_code: "COMMAND_SUPERVISION_FAILURE".to_owned(),
                            area: verification_area,
                            criterion_id: Some(command.criterion_id.clone()),
                        });
                        RepositoryCommandObservationOutcome::SupervisionFailed { failure }
                    }
                    _ => return Err(VerificationMaterialError::Invalid),
                };
                VerifiedRepositoryCommandObservation {
                    command_id: command.command_id.clone(),
                    criterion_id: command.criterion_id.clone(),
                    requirement: command.requirement,
                    expected_exit_code: command.expected_exit_code,
                    command_spec_sha256: decoded.command_spec_sha256,
                    intent: Some(intent),
                    receipt: Some(receipt),
                    outcome,
                }
            } else {
                unverified_items.push(RepositoryMaterialUnverifiedItem {
                    item_id: format!("command:{}", command.command_id),
                    reason_code: "COMMAND_RECEIPT_MISSING".to_owned(),
                    area: verification_area,
                    criterion_id: Some(command.criterion_id.clone()),
                });
                VerifiedRepositoryCommandObservation {
                    command_id: command.command_id.clone(),
                    criterion_id: command.criterion_id.clone(),
                    requirement: command.requirement,
                    expected_exit_code: command.expected_exit_code,
                    command_spec_sha256: sha256_json(command)
                        .ok_or(VerificationMaterialError::Invalid)?,
                    intent: None,
                    receipt: None,
                    outcome: RepositoryCommandObservationOutcome::MissingReceipt,
                }
            };
            command_observations.push(observation);
        }
        if consumed_receipts.len() != receipt_candidates.len() {
            return Err(VerificationMaterialError::Invalid);
        }

        Ok(VerifiedRepositoryVerificationMaterial {
            binding: binding.clone(),
            claim,
            claim_statement: statement_bytes,
            scope: VerifiedRepositoryScope {
                acceptance_contract_ref: acceptance_ref.clone(),
                allowed_paths: frozen.acceptance_contract.allowed_paths.clone(),
                forbidden_paths: frozen.acceptance_contract.forbidden_paths.clone(),
                read_only_paths: frozen.acceptance_contract.read_only_paths.clone(),
            },
            baseline: VerifiedRepositoryBaseline {
                artifact: baseline,
                input_snapshot_id: baseline_payload.input_snapshot_id,
                input_bundle_sha256: baseline_payload.input_bundle_sha256,
                workspace_ref: baseline_payload.workspace_ref,
                source_binding_ref,
                baseline_commit: baseline_payload.baseline_commit,
                baseline_tree: baseline_payload.baseline_tree,
            },
            frozen,
            workspace_root,
            patch,
            initial_manifest,
            final_manifest,
            command_observations,
            changed_paths,
            evidence: verified_evidence,
            unverified_items,
        })
    }

    fn resolve_rework_carry_forward(
        &self,
        compiled_context: &[u8],
        current_lineage: &LineageBinding,
        acceptance_ref: &ContractReference,
        frozen: &FrozenRepositoryMaterialV1,
    ) -> Result<Option<VerifiedReworkCarryForward>, VerificationMaterialError> {
        let Some(context) = rework_repository_context(compiled_context)
            .map_err(|_| VerificationMaterialError::Invalid)?
        else {
            return Ok(None);
        };
        let carry = context.repository_carry_forward;
        let prior_lineage = carry.lineage.to_proto();
        let set_manifest = carry.artifact_set_manifest.to_proto();
        if context.rework_followup_version != 1
            || context.memory_mode != "frozen_original_context"
            || context.task_id != current_lineage.task_id
            || !rework_execution_revision_chain_valid(
                carry.prior_task_revision,
                context.task_revision,
                current_lineage.task_revision,
            )
            || context.prior_work_revision.checked_add(1) != Some(current_lineage.work_revision)
            || carry.prior_task_id != current_lineage.task_id
            || carry.prior_work_revision.checked_add(1) != Some(current_lineage.work_revision)
            || carry.frozen_material != *frozen
            || !lineage_complete(&prior_lineage)
            || prior_lineage.task_id != carry.prior_task_id
            || prior_lineage.task_revision != carry.prior_task_revision
            || prior_lineage.work_revision != carry.prior_work_revision
            || set_manifest.algorithm != HashAlgorithm::Sha256 as i32
            || !sha256_address_valid(&set_manifest)
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let baseline_id = format!("artifact:repository-baseline:{}", prior_lineage.dispatch_id);
        let initial_id = format!("artifact:workspace-initial:{}", prior_lineage.dispatch_id);
        let patch_id = format!("artifact:repository-patch:{}", prior_lineage.dispatch_id);
        let final_id = format!("artifact:workspace-final:{}", prior_lineage.dispatch_id);
        if carry.baseline_artifact_id != baseline_id
            || carry.initial_manifest_artifact_id != initial_id
            || carry.repository_patch_artifact_id != patch_id
            || carry.final_manifest_artifact_id != final_id
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let set = self
            .artifacts
            .read_artifact_set(&carry.artifact_set_id)
            .map_err(map_source_error)?
            .ok_or(VerificationMaterialError::Unavailable)?;
        if set.artifact_set_id != carry.artifact_set_id
            || set.status != ArtifactSetStatus::Sealed as i32
            || set.lineage.as_ref() != Some(&prior_lineage)
            || set.canonical_manifest.as_ref() != Some(&set_manifest)
            || content_address(&canonical_artifact_set_manifest(&set)) != set_manifest
            || [
                baseline_id.as_str(),
                initial_id.as_str(),
                patch_id.as_str(),
                final_id.as_str(),
            ]
            .iter()
            .any(|id| !set.artifact_ids.iter().any(|stored| stored == id))
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let baseline = self.read_verified_artifact(&baseline_id, &prior_lineage)?;
        let initial = self.read_verified_artifact(&initial_id, &prior_lineage)?;
        let patch = self.read_verified_artifact(&patch_id, &prior_lineage)?;
        let final_manifest = self.read_verified_artifact(&final_id, &prior_lineage)?;
        let baseline_payload: RepositoryBaselinePayload =
            serde_json::from_slice(&baseline.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        validate_baseline_payload(&baseline_payload, &prior_lineage, acceptance_ref)?;
        if baseline_payload.baseline_commit != frozen.baseline_commit
            || baseline_payload.baseline_tree != frozen.baseline_tree
            || baseline_payload.workspace_ref != carry.workspace_ref
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let source_binding_ref = repository_source_binding_ref(
            &baseline_payload,
            &prior_lineage,
            &baseline_payload.input_bundle_sha256,
        );
        if source_binding_ref != carry.source_binding_ref {
            return Err(VerificationMaterialError::Invalid);
        }
        let old_initial_inputs = initial
            .descriptor
            .provenance
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?
            .input_artifact_ids
            .clone();
        if !valid_prior_initial_inputs(&old_initial_inputs, &baseline_id) {
            return Err(VerificationMaterialError::Invalid);
        }
        validate_repository_artifact(
            &baseline,
            ArtifactSemanticClass::RepositoryBaseline,
            &prior_lineage,
            &carry.workspace_ref,
            &carry.source_binding_ref,
            &[],
            &self.policy,
        )?;
        validate_repository_artifact(
            &initial,
            ArtifactSemanticClass::WorkspaceManifest,
            &prior_lineage,
            &carry.workspace_ref,
            &carry.source_binding_ref,
            &old_initial_inputs,
            &self.policy,
        )?;
        validate_repository_artifact(
            &patch,
            ArtifactSemanticClass::RepositoryPatch,
            &prior_lineage,
            &carry.workspace_ref,
            &carry.source_binding_ref,
            &[baseline_id.clone(), initial_id.clone()],
            &self.policy,
        )?;
        validate_repository_artifact(
            &final_manifest,
            ArtifactSemanticClass::WorkspaceManifest,
            &prior_lineage,
            &carry.workspace_ref,
            &carry.source_binding_ref,
            &[baseline_id, initial_id, patch_id],
            &self.policy,
        )?;
        let initial_payload: InitialWorkspaceManifestPayload =
            serde_json::from_slice(&initial.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        if !initial_payload_matches_lineage(&initial_payload, &baseline_payload, &prior_lineage)
            || (old_initial_inputs.len() == 1
                && (!initial_payload.clean
                    || initial_payload.status_porcelain_sha256 != sha256_bytes(&[])))
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let final_payload: FinalWorkspaceManifestPayload =
            serde_json::from_slice(&final_manifest.bytes)
                .map_err(|_| VerificationMaterialError::Invalid)?;
        if !final_payload_matches(
            &final_payload,
            &baseline_payload,
            &patch,
            &carry.workspace_ref,
        ) || !rework_final_paths_valid(&final_payload, frozen)
            || patch
                .descriptor
                .content
                .as_ref()
                .map(|address| address.digest.as_str())
                != Some(carry.repository_patch_sha256.as_str())
            || final_manifest
                .descriptor
                .content
                .as_ref()
                .map(|address| address.digest.as_str())
                != Some(carry.final_manifest_sha256.as_str())
        {
            return Err(VerificationMaterialError::Invalid);
        }
        Ok(Some(VerifiedReworkCarryForward {
            carry,
            final_payload,
            patch_is_empty: patch.bytes.is_empty(),
        }))
    }

    #[cfg(test)]
    pub(super) fn verify_rework_carry_forward_for_test(
        &self,
        compiled_context: &[u8],
        current_lineage: &LineageBinding,
        acceptance_ref: &ContractReference,
        frozen: &FrozenRepositoryMaterialV1,
    ) -> Result<(), VerificationMaterialError> {
        self.resolve_rework_carry_forward(
            compiled_context,
            current_lineage,
            acceptance_ref,
            frozen,
        )?
        .ok_or(VerificationMaterialError::Invalid)
        .map(|_| ())
    }

    fn read_claim(&self, id: &str) -> Result<Claim, VerificationMaterialError> {
        self.artifacts
            .read_claim(id)
            .map_err(map_source_error)?
            .ok_or(VerificationMaterialError::Unavailable)
    }

    fn read_evidence(&self, id: &str) -> Result<Evidence, VerificationMaterialError> {
        self.artifacts
            .read_evidence(id)
            .map_err(map_source_error)?
            .ok_or(VerificationMaterialError::Unavailable)
    }

    fn read_verified_artifact(
        &self,
        id: &str,
        lineage: &LineageBinding,
    ) -> Result<VerifiedArtifactBytes, VerificationMaterialError> {
        let descriptor = self
            .artifacts
            .read_artifact(id)
            .map_err(map_source_error)?
            .ok_or(VerificationMaterialError::Unavailable)?;
        let address = descriptor
            .content
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?;
        if descriptor.artifact_id != id
            || descriptor.status != ArtifactStatus::Sealed as i32
            || descriptor.integrity_status != IntegrityStatus::DigestVerified as i32
            || descriptor
                .provenance
                .as_ref()
                .and_then(|value| value.lineage.as_ref())
                != Some(lineage)
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let bytes = self
            .artifacts
            .read_content(address)
            .map_err(map_source_error)?;
        if content_address(&bytes) != *address {
            return Err(VerificationMaterialError::Invalid);
        }
        Ok(VerifiedArtifactBytes { descriptor, bytes })
    }

    fn validate_evidence(
        &self,
        evidence: &Evidence,
        binding: &VerificationBinding,
        lineage: &LineageBinding,
        artifact_ids: &[String],
    ) -> Result<(), VerificationMaterialError> {
        let producer = evidence
            .producer
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?;
        let artifacts = artifact_ids.iter().collect::<BTreeSet<_>>();
        if evidence.status != EvidenceStatus::Recorded as i32
            || evidence.integrity_status != IntegrityStatus::DigestVerified as i32
            || evidence.claim_id != binding.claim_id
            || evidence.lineage.as_ref() != Some(lineage)
            || evidence.evidence_profile_ref.as_ref() != Some(&self.policy.evidence_profile_ref)
            || evidence.artifact_ids.is_empty()
            || evidence
                .artifact_ids
                .iter()
                .any(|id| !artifacts.contains(id))
            || !evidence_producer_matches(evidence, producer.principal_kind.as_str())
            || !evidence_principal_matches(evidence, &producer.principal_id, &self.policy)
        {
            return Err(VerificationMaterialError::Invalid);
        }
        let coverage = evidence
            .coverage_descriptor
            .as_ref()
            .ok_or(VerificationMaterialError::Invalid)?;
        let bytes = self
            .artifacts
            .read_content(coverage)
            .map_err(map_source_error)?;
        if content_address(&bytes) != *coverage {
            return Err(VerificationMaterialError::Invalid);
        }
        Ok(())
    }
}

fn validate_claim(
    claim: &Claim,
    binding: &VerificationBinding,
    lineage: &LineageBinding,
    semantic_profile_ref: &ContractReference,
    acceptance_ref: &ContractReference,
    artifact_ids: &[String],
    policy: &RepositoryVerificationMaterialPolicy,
) -> Result<(), VerificationMaterialError> {
    let proposer = claim
        .proposer
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    let artifacts = artifact_ids.iter().collect::<BTreeSet<_>>();
    if claim.claim_id != binding.claim_id
        || claim.status != ClaimStatus::Proposed as i32
        || claim.source_type != ClaimSourceType::CodeChange as i32
        || claim.semantic_profile_ref.as_ref() != Some(semantic_profile_ref)
        || claim.acceptance_contract_ref.as_ref() != Some(acceptance_ref)
        || claim.lineage.as_ref() != Some(lineage)
        || claim.statement.is_none()
        || claim.subject_artifact_ids.is_empty()
        || claim
            .subject_artifact_ids
            .iter()
            .any(|id| !artifacts.contains(id))
        || proposer.principal_kind != "governed_collector"
        || proposer.principal_id != policy.governed_collector_principal_id
        || proposer.component_name.trim().is_empty()
        || proposer.component_version.trim().is_empty()
    {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(())
}

fn validate_baseline_payload(
    baseline: &RepositoryBaselinePayload,
    lineage: &LineageBinding,
    acceptance_ref: &ContractReference,
) -> Result<(), VerificationMaterialError> {
    if baseline.schema_version != BASELINE_SCHEMA
        || baseline.task_id != lineage.task_id
        || baseline.task_revision != lineage.task_revision
        || baseline.work_revision != lineage.work_revision
        || baseline.contract_id != acceptance_ref.contract_id
        || baseline.contract_version != acceptance_ref.version
        || baseline.contract_sha256 != acceptance_ref.sha256
        || baseline.input_snapshot_id.trim().is_empty()
        || baseline.input_bundle_sha256.len() != 64
        || baseline.workspace_ref.trim().is_empty()
        || baseline.baseline_commit.len() != 40
        || baseline.baseline_tree.len() != 40
    {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(())
}

fn sha256_address_valid(address: &ContentAddress) -> bool {
    address.algorithm == HashAlgorithm::Sha256 as i32
        && address.digest.len() == 64
        && address
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prior_initial_inputs(input_ids: &[String], baseline_id: &str) -> bool {
    (input_ids.len() == 1 && input_ids[0] == baseline_id)
        || (input_ids.len() == 3
            && input_ids[0] == baseline_id
            && input_ids[1].starts_with("artifact:repository-patch:")
            && input_ids[2].starts_with("artifact:workspace-final:")
            && input_ids.iter().collect::<BTreeSet<_>>().len() == input_ids.len())
}

fn initial_payload_matches_lineage(
    initial: &InitialWorkspaceManifestPayload,
    baseline: &RepositoryBaselinePayload,
    lineage: &LineageBinding,
) -> bool {
    initial.schema_version == INITIAL_MANIFEST_SCHEMA
        && initial.task_id == lineage.task_id
        && initial.task_revision == lineage.task_revision
        && initial.work_revision == lineage.work_revision
        && initial.run_id == lineage.run_id
        && initial.run_revision == lineage.run_revision
        && initial.step_id == lineage.step_id
        && initial.step_revision == lineage.step_revision
        && initial.attempt_id == lineage.attempt_id
        && initial.attempt_revision == lineage.attempt_revision
        && initial.dispatch_id == lineage.dispatch_id
        && initial.fencing_token == lineage.fencing_token
        && initial.input_snapshot_id == baseline.input_snapshot_id
        && initial.input_bundle_sha256 == baseline.input_bundle_sha256
        && initial.workspace_ref == baseline.workspace_ref
        && initial.baseline_commit == baseline.baseline_commit
        && initial.baseline_tree == baseline.baseline_tree
        && initial.status_porcelain_sha256.len() == 64
        && initial
            .status_porcelain_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn initial_manifest_state_matches(
    initial: &InitialWorkspaceManifestPayload,
    rework: Option<&VerifiedReworkCarryForward>,
) -> bool {
    match rework {
        None => initial.clean && initial.status_porcelain_sha256 == sha256_bytes(&[]),
        Some(verified) => {
            initial.status_porcelain_sha256 == verified.final_payload.status_porcelain_sha256
                && initial.clean
                    == (verified.patch_is_empty && verified.final_payload.entries.is_empty())
        }
    }
}

fn final_payload_matches(
    final_payload: &FinalWorkspaceManifestPayload,
    baseline: &RepositoryBaselinePayload,
    patch: &VerifiedArtifactBytes,
    workspace_ref: &str,
) -> bool {
    final_payload.schema_version == FINAL_MANIFEST_SCHEMA
        && final_payload.workspace_ref == workspace_ref
        && final_payload.baseline_commit == baseline.baseline_commit
        && final_payload.baseline_tree == baseline.baseline_tree
        && final_payload.observed_head_commit == baseline.baseline_commit
        && final_payload.observed_head_tree == baseline.baseline_tree
        && final_payload.status_porcelain_sha256.len() == 64
        && final_payload
            .status_porcelain_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && final_payload.patch_sha256
            == patch
                .descriptor
                .content
                .as_ref()
                .map(|value| value.digest.as_str())
                .unwrap_or_default()
        && final_payload.patch_bytes == patch.bytes.len() as u64
        && final_payload.entries.iter().all(|entry| {
            matches!(
                entry.status.as_str(),
                "A" | "M" | "D" | "T" | "U" | "X" | "B"
            ) && !entry.path_hex.is_empty()
        })
}

fn rework_final_paths_valid(
    manifest: &FinalWorkspaceManifestPayload,
    frozen: &FrozenRepositoryMaterialV1,
) -> bool {
    let mut paths = BTreeSet::new();
    manifest.entries.iter().all(|entry| {
        let Ok(bytes) = hex::decode(&entry.path_hex) else {
            return false;
        };
        let Ok(path) = std::str::from_utf8(&bytes) else {
            return false;
        };
        !path.contains('\\')
            && paths.insert(path.to_owned())
            && frozen.path_access(path).ok() == Some(RepositoryPathAccess::Allowed)
    })
}

fn validate_repository_artifact(
    artifact: &VerifiedArtifactBytes,
    semantic_class: ArtifactSemanticClass,
    lineage: &LineageBinding,
    workspace_ref: &str,
    source_binding_ref: &str,
    input_artifact_ids: &[String],
    policy: &RepositoryVerificationMaterialPolicy,
) -> Result<(), VerificationMaterialError> {
    let provenance = artifact
        .descriptor
        .provenance
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    if artifact.descriptor.semantic_class != semantic_class as i32
        || artifact.descriptor.type_contract_ref.as_ref()
            != Some(&policy.repository_artifact_type_ref)
        || artifact.descriptor.retention_profile_ref.as_ref() != Some(&policy.retention_profile_ref)
        || provenance.lineage.as_ref() != Some(lineage)
        || provenance.input_artifact_ids != input_artifact_ids
        || provenance.transformation_contract_ref.as_ref()
            != Some(&policy.repository_transformation_ref)
        || provenance.workspace_ref != workspace_ref
        || provenance.raw_source_ref.as_deref() != Some(source_binding_ref)
        || producer.principal_kind != "attempt_supervisor"
        || producer.principal_id != policy.attempt_supervisor_principal_id
        || producer.component_name != policy.repository_component_name
    {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(())
}

fn validate_command_receipt_artifact(
    artifact: &VerifiedArtifactBytes,
    lineage: &LineageBinding,
    workspace_ref: &str,
    source_binding_ref: &str,
    policy: &RepositoryVerificationMaterialPolicy,
) -> Result<(), VerificationMaterialError> {
    let provenance = artifact
        .descriptor
        .provenance
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    if artifact.descriptor.type_contract_ref.as_ref() != Some(&policy.command_receipt_type_ref)
        || artifact.descriptor.retention_profile_ref.as_ref() != Some(&policy.retention_profile_ref)
        || provenance.lineage.as_ref() != Some(lineage)
        || provenance.transformation_contract_ref.as_ref()
            != Some(&policy.command_receipt_transformation_ref)
        || provenance.workspace_ref != workspace_ref
        || provenance.raw_source_ref.as_deref() != Some(source_binding_ref)
        || provenance.input_artifact_ids.len() != 5
        || producer.principal_kind != "supervised_runner"
        || producer.principal_id != policy.supervised_runner_principal_id
        || producer.component_name != policy.command_component_name
    {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(())
}

fn validate_command_intent_artifact(
    artifact: &VerifiedArtifactBytes,
    lineage: &LineageBinding,
    workspace_ref: &str,
    source_binding_ref: &str,
    input_artifact_ids: &[String],
    policy: &RepositoryVerificationMaterialPolicy,
) -> Result<(), VerificationMaterialError> {
    let provenance = artifact
        .descriptor
        .provenance
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(VerificationMaterialError::Invalid)?;
    if artifact.descriptor.semantic_class != ArtifactSemanticClass::TypedExtension as i32
        || artifact.descriptor.type_contract_ref.as_ref() != Some(&policy.command_intent_type_ref)
        || artifact.descriptor.retention_profile_ref.as_ref() != Some(&policy.retention_profile_ref)
        || provenance.lineage.as_ref() != Some(lineage)
        || provenance.input_artifact_ids != input_artifact_ids
        || provenance.transformation_contract_ref.as_ref()
            != Some(&policy.command_intent_transformation_ref)
        || provenance.workspace_ref != workspace_ref
        || provenance.raw_source_ref.as_deref() != Some(source_binding_ref)
        || producer.principal_kind != "supervised_runner"
        || producer.principal_id != policy.supervised_runner_principal_id
        || producer.component_name != policy.command_component_name
    {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(())
}

fn evidence_producer_matches(evidence: &Evidence, principal_kind: &str) -> bool {
    matches!(
        (evidence.producer_class, principal_kind),
        (x, "attempt_supervisor") if x == EvidenceProducerClass::AttemptSupervisor as i32
    ) || matches!(
        (evidence.producer_class, principal_kind),
        (x, "supervised_runner") if x == EvidenceProducerClass::SupervisedRunner as i32
    ) || matches!(
        (evidence.producer_class, principal_kind),
        (x, "governed_collector") if x == EvidenceProducerClass::GovernedCollector as i32
    )
}

fn evidence_principal_matches(
    evidence: &Evidence,
    principal_id: &str,
    policy: &RepositoryVerificationMaterialPolicy,
) -> bool {
    match EvidenceProducerClass::try_from(evidence.producer_class).ok() {
        Some(EvidenceProducerClass::AttemptSupervisor) => {
            principal_id == policy.attempt_supervisor_principal_id
                && evidence.independent_of_claim_proposer
        }
        Some(EvidenceProducerClass::SupervisedRunner) => {
            principal_id == policy.supervised_runner_principal_id
                && evidence.independent_of_claim_proposer
        }
        Some(EvidenceProducerClass::GovernedCollector) => {
            principal_id == policy.governed_collector_principal_id
                && !evidence.independent_of_claim_proposer
        }
        _ => false,
    }
}

fn exact_workspace_root(
    base: &Path,
    workspace_ref: &str,
) -> Result<PathBuf, VerificationMaterialError> {
    if workspace_ref.is_empty()
        || workspace_ref.contains('/')
        || workspace_ref.contains('\\')
        || workspace_ref == "."
        || workspace_ref == ".."
    {
        return Err(VerificationMaterialError::Invalid);
    }
    let root = base
        .join(workspace_ref)
        .canonicalize()
        .map_err(|_| VerificationMaterialError::Unavailable)?;
    if !root.is_dir() || !root.starts_with(base) || root.parent() != Some(base) {
        return Err(VerificationMaterialError::Invalid);
    }
    Ok(root)
}

fn safe_relative_git_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn command_verification_area(
    criterion_id: &str,
) -> Result<RepositoryMaterialVerificationArea, VerificationMaterialError> {
    match criterion_id {
        "scope" => Ok(RepositoryMaterialVerificationArea::Scope),
        "tests" => Ok(RepositoryMaterialVerificationArea::Tests),
        "review" => Ok(RepositoryMaterialVerificationArea::Review),
        _ => Err(VerificationMaterialError::Invalid),
    }
}

fn policy_valid(policy: &RepositoryVerificationMaterialPolicy) -> bool {
    [
        &policy.repository_artifact_type_ref,
        &policy.repository_transformation_ref,
        &policy.command_intent_type_ref,
        &policy.command_intent_transformation_ref,
        &policy.command_receipt_type_ref,
        &policy.command_receipt_transformation_ref,
        &policy.retention_profile_ref,
        &policy.evidence_profile_ref,
    ]
    .into_iter()
    .all(contract_reference_valid)
        && [
            &policy.attempt_supervisor_principal_id,
            &policy.supervised_runner_principal_id,
            &policy.governed_collector_principal_id,
            &policy.repository_component_name,
            &policy.command_component_name,
        ]
        .into_iter()
        .all(|value| !value.trim().is_empty())
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

fn lineage_complete(lineage: &LineageBinding) -> bool {
    !lineage.task_id.trim().is_empty()
        && lineage.task_revision > 0
        && lineage.work_revision > 0
        && !lineage.run_id.trim().is_empty()
        && lineage.run_revision > 0
        && !lineage.step_id.trim().is_empty()
        && lineage.step_revision > 0
        && !lineage.attempt_id.trim().is_empty()
        && lineage.attempt_revision > 0
        && !lineage.dispatch_id.trim().is_empty()
        && lineage.fencing_token > 0
}

fn unique_nonempty(values: &[String]) -> Option<BTreeSet<&String>> {
    let set = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>();
    (set.len() == values.len()).then_some(set)
}

fn sha256_json<T: serde::Serialize>(value: &T) -> Option<String> {
    use sha2::{Digest, Sha256};
    serde_json::to_vec(value)
        .ok()
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn map_source_error(
    error: egopulse_verification_authority::ArtifactReferenceSourceError,
) -> VerificationMaterialError {
    match error {
        egopulse_verification_authority::ArtifactReferenceSourceError::Unavailable => {
            VerificationMaterialError::Unavailable
        }
        egopulse_verification_authority::ArtifactReferenceSourceError::Corrupt => {
            VerificationMaterialError::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_unverified_area_follows_the_frozen_criterion() {
        assert_eq!(
            command_verification_area("scope"),
            Ok(RepositoryMaterialVerificationArea::Scope)
        );
        assert_eq!(
            command_verification_area("tests"),
            Ok(RepositoryMaterialVerificationArea::Tests)
        );
        assert_eq!(
            command_verification_area("review"),
            Ok(RepositoryMaterialVerificationArea::Review)
        );
        assert_eq!(
            command_verification_area("unknown"),
            Err(VerificationMaterialError::Invalid)
        );
    }
}
