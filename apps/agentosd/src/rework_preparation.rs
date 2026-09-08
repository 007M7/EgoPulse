//! Authority-owned preparation and confirmation for a follow-up after Rework.
//!
//! The Local API supplies only Task identity, expected revision and retry keys.
//! This module resolves the applied Founder directive from the existing owners,
//! freezes it into a new Context snapshot, then submits one `ReviseTask` through
//! the daemon-owned revision boundary. It never creates a second Task or a
//! Collaboration execution aggregate.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::{
    context_authority::{
        AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityFailure,
        ContextPrincipalKind, ContextSourceFact, IssueContextSnapshot,
    },
    task_authority::{TaskAuthority, canonical_request_digest},
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm, LineageBinding},
    common::v1::{CommandMetadata, ContractReference},
    localapi::v1::{
        ConfirmReworkRequest, PrepareReworkRequest, ReworkPreparationPreview,
        WorkPreparationPreview, WorkSourceFact,
    },
    task::v1::{
        ActivateTaskCommand, ReviseTaskCommand, TaskCommand, TaskCommandResult, TaskEvent,
        TaskSnapshot, TaskStatus, get_task_response, task_command, task_command_result,
    },
    verdict::v1::{
        FounderSupportingMaterial, FounderSupportingMaterialCoverage,
        FounderSupportingMaterialRole, FounderVerdict, FounderVerdictDecision, FounderVerdictState,
        ReworkDirective, VerdictScope,
    },
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPortResult, CommandPrincipal, TaskCommandPort,
};
use prost::Message;
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    SharedFounderVerdictAuthority,
    repository_material::FrozenRepositoryMaterialV1,
    verdict::{FounderSupportingMaterialEvidence, FounderSupportingMaterialSource},
    work_capability::WorkCapabilityRegistry,
    work_preparation::{
        persist_input_bundle, work_capability_run_id, work_capability_view_from_compiled_context,
    },
};

const REWORK_CONTEXT_COMPILER_PRINCIPAL: &str = "agentosd:rework-preparation:v1";
const REWORK_CONTEXT_VERSION: u64 = 1;
const REWORK_CONTEXT_TTL_SECONDS: i64 = 60 * 60;

/// Sealed repository inputs that DESIGN carries forward from the preceding
/// work revision. This is metadata only: the coordinator never receives a live
/// mutable workspace from this interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedReworkRepositoryCarryForward {
    pub prior_task_id: String,
    pub prior_task_revision: u64,
    pub prior_work_revision: u64,
    pub artifact_set_id: String,
    pub artifact_set_manifest: ReworkContentAddress,
    pub lineage: ReworkLineageBinding,
    pub baseline_artifact_id: String,
    pub initial_manifest_artifact_id: String,
    pub repository_patch_artifact_id: String,
    pub repository_patch_sha256: String,
    pub final_manifest_artifact_id: String,
    pub final_manifest_sha256: String,
    pub workspace_ref: String,
    pub source_binding_ref: String,
    pub frozen_material: FrozenRepositoryMaterialV1,
}

/// JSON-stable representation of an Artifact Authority content address. Generated
/// protobuf types deliberately do not derive serde, so the immutable compiled
/// Context retains every address field through this crate-private adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReworkContentAddress {
    algorithm: i32,
    digest: String,
    byte_length: u64,
}

impl From<&ContentAddress> for ReworkContentAddress {
    fn from(value: &ContentAddress) -> Self {
        Self {
            algorithm: value.algorithm,
            digest: value.digest.clone(),
            byte_length: value.byte_length,
        }
    }
}

impl ReworkContentAddress {
    pub(crate) fn to_proto(&self) -> ContentAddress {
        ContentAddress {
            algorithm: self.algorithm,
            digest: self.digest.clone(),
            byte_length: self.byte_length,
        }
    }
}

/// JSON-stable representation of the complete prior execution lineage. The
/// conversion is field-for-field so a restart can revalidate the same sealed
/// ArtifactSet proof without recovering identity from a mutable workspace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReworkLineageBinding {
    task_id: String,
    task_revision: u64,
    work_revision: u64,
    run_id: String,
    run_revision: u64,
    step_id: String,
    step_revision: u64,
    attempt_id: String,
    attempt_revision: u64,
    dispatch_id: String,
    fencing_token: u64,
}

impl From<&LineageBinding> for ReworkLineageBinding {
    fn from(value: &LineageBinding) -> Self {
        Self {
            task_id: value.task_id.clone(),
            task_revision: value.task_revision,
            work_revision: value.work_revision,
            run_id: value.run_id.clone(),
            run_revision: value.run_revision,
            step_id: value.step_id.clone(),
            step_revision: value.step_revision,
            attempt_id: value.attempt_id.clone(),
            attempt_revision: value.attempt_revision,
            dispatch_id: value.dispatch_id.clone(),
            fencing_token: value.fencing_token,
        }
    }
}

impl ReworkLineageBinding {
    pub(crate) fn to_proto(&self) -> LineageBinding {
        LineageBinding {
            task_id: self.task_id.clone(),
            task_revision: self.task_revision,
            work_revision: self.work_revision,
            run_id: self.run_id.clone(),
            run_revision: self.run_revision,
            step_id: self.step_id.clone(),
            step_revision: self.step_revision,
            attempt_id: self.attempt_id.clone(),
            attempt_revision: self.attempt_revision,
            dispatch_id: self.dispatch_id.clone(),
            fencing_token: self.fencing_token,
        }
    }
}

/// DESIGN-owned reader for the prior sealed repository result. Its
/// implementation must verify Artifact provenance before returning this value.
pub(crate) trait ReworkRepositoryCarryForward: Send + Sync + 'static {
    fn resolve(
        &self,
        task: &TaskSnapshot,
        scope: &VerdictScope,
    ) -> Result<SealedReworkRepositoryCarryForward, CommandPortFailure>;
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedRequiredChangesMaterial {
    pub artifact_id: String,
    pub evidence: FounderSupportingMaterialEvidence,
}

/// Complete, daemon-derived proof for one Rework continuation. No field is
/// populated from Local API payload other than the Task identity/revision that
/// this structure subsequently verifies.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedReworkFollowup {
    pub task: TaskSnapshot,
    pub owner_principal_id: String,
    pub applied_verdict_event: TaskEvent,
    pub verdict: FounderVerdict,
    pub verdict_state: FounderVerdictState,
    pub directive: ReworkDirective,
    pub required_changes: ResolvedRequiredChangesMaterial,
    pub repository_carry_forward: SealedReworkRepositoryCarryForward,
}

/// Reads each existing Authority only for the duration of its individual
/// query. The Task lock is released before Founder and Artifact reads, and no
/// guard calls back into `TaskAuthority` while it is held.
pub(crate) struct ReworkPreparationResolver {
    task: Arc<Mutex<TaskAuthority>>,
    founder_verdict: SharedFounderVerdictAuthority,
    required_changes_source: Arc<dyn FounderSupportingMaterialSource>,
    repository_carry_forward: Arc<dyn ReworkRepositoryCarryForward>,
}

impl ReworkPreparationResolver {
    pub(crate) fn new(
        task: Arc<Mutex<TaskAuthority>>,
        founder_verdict: SharedFounderVerdictAuthority,
        required_changes_source: Arc<dyn FounderSupportingMaterialSource>,
        repository_carry_forward: Arc<dyn ReworkRepositoryCarryForward>,
    ) -> Self {
        Self {
            task,
            founder_verdict,
            required_changes_source,
            repository_carry_forward,
        }
    }

    pub(crate) fn resolve(
        &self,
        principal: &CommandPrincipal,
        task_id: &str,
        expected_revision: u64,
    ) -> Result<ResolvedReworkFollowup, CommandPortFailure> {
        if !valid_routing(task_id)
            || expected_revision == 0
            || !valid_routing(&principal.principal_id)
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }

        let (task, owner_principal_id) = {
            let authority = self
                .task
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            let owner = authority
                .task_owner_principal_id(task_id)
                .map_err(task_read_failure)?
                .ok_or(CommandPortFailure::IntegrityFailure)?;
            let task = task_snapshot(&authority, task_id)?;
            (task, owner)
        };
        if owner_principal_id != principal.principal_id
            || task.revision != expected_revision
            || task.status != TaskStatus::Rework as i32
            || task.work_revision == 0
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let verdict_id = task
            .founder_verdict_id
            .as_deref()
            .filter(|value| valid_routing(value))
            .ok_or(CommandPortFailure::IntegrityFailure)?;

        let (verdict, verdict_state) = {
            let owner = self
                .founder_verdict
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            let authority = owner.as_ref().ok_or(CommandPortFailure::Unavailable)?;
            authority
                .get(verdict_id)
                .map_err(|_| CommandPortFailure::Unavailable)?
                .ok_or(CommandPortFailure::IntegrityFailure)?
        };
        let scope = verdict
            .scope
            .as_ref()
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let applied_verdict_event = {
            let authority = self
                .task
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            authority
                .applied_founder_verdict(scope, verdict_id)
                .map_err(task_read_failure)?
                .ok_or(CommandPortFailure::IntegrityFailure)?
        };
        let directive = verdict
            .rework_directive
            .clone()
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let required_changes = self
            .required_changes_source
            .material(&directive.required_changes_artifact_id, scope)
            .map_err(material_failure)?
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let repository_carry_forward = self.repository_carry_forward.resolve(&task, scope)?;
        let resolved = ResolvedReworkFollowup {
            task,
            owner_principal_id,
            applied_verdict_event,
            verdict,
            verdict_state,
            directive,
            required_changes: ResolvedRequiredChangesMaterial {
                artifact_id: required_changes.descriptor.artifact_id.clone(),
                evidence: required_changes,
            },
            repository_carry_forward,
        };
        validate_resolved_rework_followup(&resolved, principal)?;
        Ok(resolved)
    }
}

/// The production coordinator for one same-Task Rework
/// continuation. It owns Context issue and the fixed `ReviseTask`/activation
/// sequence; ordinary work preparation remains unchanged.
pub(crate) struct ReworkPreparationCoordinator {
    context: Arc<Mutex<ContextAuthority>>,
    task_port: Arc<dyn TaskCommandPort>,
    resolver: ReworkPreparationResolver,
    budget_profile_ref: ContractReference,
    input_bundle_root: Option<PathBuf>,
    work_capability_registry: Option<Arc<WorkCapabilityRegistry>>,
}

impl ReworkPreparationCoordinator {
    pub(crate) fn new(
        context: Arc<Mutex<ContextAuthority>>,
        task_port: Arc<dyn TaskCommandPort>,
        resolver: ReworkPreparationResolver,
        budget_profile_ref: ContractReference,
    ) -> Result<Self, CommandPortFailure> {
        if !complete_contract_reference(&budget_profile_ref) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        Ok(Self {
            context,
            task_port,
            resolver,
            budget_profile_ref,
            input_bundle_root: None,
            work_capability_registry: None,
        })
    }

    pub(crate) fn with_input_bundle_root(
        mut self,
        root: PathBuf,
    ) -> Result<Self, CommandPortFailure> {
        if root.as_os_str().is_empty() {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        self.input_bundle_root = Some(root);
        Ok(self)
    }

    #[must_use]
    pub(crate) fn with_work_capability_registry(
        mut self,
        registry: Arc<WorkCapabilityRegistry>,
    ) -> Self {
        self.work_capability_registry = Some(registry);
        self
    }

    pub(crate) async fn prepare(
        &self,
        request: &PrepareReworkRequest,
        principal: &CommandPrincipal,
    ) -> Result<ReworkPreparationPreview, CommandPortFailure> {
        validate_prepare_request(request)?;
        let context_key = rework_context_idempotency_key(principal, request);
        let compiler = context_compiler_principal();
        let existing = {
            let authority = self
                .context
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            authority
                .issued_snapshot_by_idempotency(&compiler, &context_key)
                .map_err(context_failure)?
        };
        if let Some(existing) = existing {
            let frozen = decode_compiled_rework_context(&existing.compiled_context)?;
            if existing.snapshot.owner_principal_id != principal.principal_id
                || frozen.task_id != request.task_id
                || frozen.task_revision != request.expected_revision
                || frozen.owner_principal_id != principal.principal_id
                || frozen.budget_profile_ref != contract_key(&self.budget_profile_ref)
            {
                return Err(CommandPortFailure::IntegrityFailure);
            }
            let context_state_revision = {
                let authority = self
                    .context
                    .lock()
                    .map_err(|_| CommandPortFailure::Unavailable)?;
                authority
                    .governance(&existing.snapshot.snapshot_id)
                    .map_err(context_failure)?
                    .ok_or(CommandPortFailure::IntegrityFailure)?
                    .state_revision
            };
            persist_input_bundle(
                self.input_bundle_root.as_deref(),
                &existing.snapshot.compiled_context_sha256,
                &existing.compiled_context,
            )?;
            return Ok(ReworkPreparationPreview {
                work: Some(work_preview(
                    &frozen,
                    &existing.snapshot,
                    context_state_revision,
                    &self.budget_profile_ref,
                    &existing.compiled_context,
                    self.work_capability_registry.as_deref(),
                )?),
                task_id: frozen.task_id,
                task_revision: frozen.task_revision,
                work_revision: frozen.prior_work_revision,
                directive_id: frozen.directive_id,
            });
        }
        let resolved =
            self.resolver
                .resolve(principal, &request.task_id, request.expected_revision)?;
        if resolved.task.budget_profile_ref.as_ref() != Some(&self.budget_profile_ref) {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let frozen = compile_rework_context(&resolved)?;
        let base_context = self.base_context(&resolved)?;
        let compiled = merge_rework_followup(&base_context.compiled_context, &frozen)?;
        let now = unix_seconds().ok_or(CommandPortFailure::Unavailable)?;
        let expires_at_seconds = now.saturating_add(REWORK_CONTEXT_TTL_SECONDS);
        let deadline_seconds = Some(expires_at_seconds);
        let input = issue_context_input(
            principal,
            &base_context.snapshot,
            compiled.clone(),
            frozen.clone(),
            context_key,
            deadline_seconds,
            expires_at_seconds,
        )?;
        let (snapshot, context_state_revision) = {
            let mut authority = self
                .context
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            let (_, snapshot) = authority
                .issue(&input, &compiler)
                .map_err(context_failure)?;
            let governance = authority
                .governance(&snapshot.snapshot_id)
                .map_err(context_failure)?
                .ok_or(CommandPortFailure::IntegrityFailure)?;
            (snapshot, governance.state_revision)
        };
        persist_input_bundle(
            self.input_bundle_root.as_deref(),
            &snapshot.compiled_context_sha256,
            &compiled,
        )?;
        Ok(ReworkPreparationPreview {
            work: Some(work_preview(
                &frozen,
                &snapshot,
                context_state_revision,
                &self.budget_profile_ref,
                &compiled,
                self.work_capability_registry.as_deref(),
            )?),
            task_id: resolved.task.task_id,
            task_revision: resolved.task.revision,
            work_revision: resolved.task.work_revision,
            directive_id: resolved.directive.directive_id,
        })
    }

    fn base_context(
        &self,
        resolved: &ResolvedReworkFollowup,
    ) -> Result<BaseReworkContext, CommandPortFailure> {
        let now = unix_seconds().ok_or(CommandPortFailure::Unavailable)?;
        let authority = self
            .context
            .lock()
            .map_err(|_| CommandPortFailure::Unavailable)?;
        let original = authority
            .resolve(
                &resolved.task.input_snapshot_id,
                &resolved.task.target_scope_ref,
                now,
            )
            .map_err(context_failure)?;
        if original.snapshot.snapshot_id != resolved.task.input_snapshot_id
            || original.snapshot.work_type != resolved.task.work_type
            || original.snapshot.target_scope_ref != resolved.task.target_scope_ref
            || original.snapshot.acceptance_contract_ref
                != contract_key(
                    resolved
                        .task
                        .acceptance_contract_ref
                        .as_ref()
                        .ok_or(CommandPortFailure::IntegrityFailure)?,
                )
            || original.snapshot.budget_profile_ref
                != contract_key(
                    resolved
                        .task
                        .budget_profile_ref
                        .as_ref()
                        .ok_or(CommandPortFailure::IntegrityFailure)?,
                )
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        Ok(BaseReworkContext {
            snapshot: original.snapshot,
            compiled_context: original.compiled_context,
        })
    }

    pub(crate) fn confirm(
        &self,
        request: &ConfirmReworkRequest,
        principal: &CommandPrincipal,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        validate_confirm_request(request)?;
        let now = unix_seconds().ok_or(CommandPortFailure::Unavailable)?;
        // This owner/binding/digest check reads only immutable prepared bytes.
        // It deliberately does not renew Context expiry or authorization; it
        // exists solely to reconstruct the exact already-committed command for
        // a response-loss replay.
        let prepared = {
            let authority = self
                .context
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            authority
                .read_prepared_confirmation(
                    &prepared_confirmation_principal(principal),
                    &request.snapshot_id,
                    &request.confirmation_binding_sha256,
                )
                .map_err(context_failure)?
        };
        let frozen = decode_compiled_rework_context(&prepared.compiled_context)?;
        validate_prepared_rework_confirmation(
            &prepared.snapshot,
            &frozen,
            request,
            principal,
            &self.budget_profile_ref,
        )?;
        let mut revise = revise_command(request, &frozen, now)?;
        set_revise_digest(&mut revise)?;
        if let Some(replayed) = self.task_port.replay_system_revision_if_recorded(&revise)? {
            if result_task_snapshot(&replayed.result).is_none() {
                // The Authority found a conflicting or rejected record. It is
                // already a complete no-write result, never a reason to issue
                // a new revision command.
                return Ok(replayed);
            }
            validate_replayed_rework_revision(&replayed.result, &prepared.snapshot, &frozen)?;
            return self.activate_revised_task(replayed, request, now);
        }

        // No durable system-revision receipt exists. Only this path consumes
        // the Context normally and therefore enforces its current state and
        // expiry before the resolver can authorize a fresh Task revision.
        let resolved = {
            let authority = self
                .context
                .lock()
                .map_err(|_| CommandPortFailure::Unavailable)?;
            authority
                .resolve(
                    &request.snapshot_id,
                    &prepared.snapshot.target_scope_ref,
                    now,
                )
                .map_err(context_failure)?
        };
        if resolved.snapshot != prepared.snapshot
            || resolved.compiled_context != prepared.compiled_context
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let current = self
            .resolver
            .resolve(principal, &request.task_id, frozen.task_revision)?;
        let current_frozen = compile_rework_context(&current)?;
        let current_base = self.base_context(&current)?;
        let current_compiled =
            merge_rework_followup(&current_base.compiled_context, &current_frozen)?;
        if current_frozen != frozen || current_compiled != prepared.compiled_context {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let revised = self.task_port.execute_system_revision(&revise)?;
        self.activate_revised_task(revised, request, now)
    }

    fn activate_revised_task(
        &self,
        revised: CommandPortResult<TaskCommandResult>,
        request: &ConfirmReworkRequest,
        now: i64,
    ) -> Result<CommandPortResult<TaskCommandResult>, CommandPortFailure> {
        let Some(task) = result_task_snapshot(&revised.result) else {
            return Ok(revised);
        };
        if task.status != TaskStatus::Ready as i32 {
            return Ok(revised);
        }
        let run_id = match task.work_capability_route.as_ref() {
            Some(route) => work_capability_run_id(&task.task_id, task.work_revision, route)?,
            None => return Err(CommandPortFailure::Unavailable),
        };
        let mut activation = activation_command(request, &task, &request.snapshot_id, run_id, now)?;
        set_activate_digest(&mut activation)?;
        match self.task_port.execute_system_activation(&activation) {
            Ok(activated)
                if matches!(
                    activated.result.outcome,
                    Some(task_command_result::Outcome::Task(_))
                ) =>
            {
                Ok(activated)
            }
            // The revision is already durable. Preserve the honest Ready result
            // if activation is currently unavailable; recovery owns its retry.
            Ok(_) | Err(_) => Ok(revised),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledReworkContext {
    rework_followup_version: u64,
    memory_mode: String,
    owner_principal_id: String,
    task_id: String,
    task_revision: u64,
    prior_work_revision: u64,
    work_type: String,
    target_scope_ref: String,
    acceptance_contract_ref: ReworkContractReference,
    budget_profile_ref: String,
    founder_verdict_id: String,
    verdict_state_revision: u64,
    verdict_application_event_id: String,
    directive_id: String,
    directive_reason_code: String,
    required_changes_artifact_id: String,
    required_changes_content_sha256: String,
    required_changes_material_id: String,
    required_changes_author_principal_id: String,
    required_changes_body: String,
    required_changes_coverage: ReworkCoverage,
    bound_workspace_ref: String,
    bound_source_binding_ref: String,
    repository_carry_forward: SealedReworkRepositoryCarryForward,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReworkContractReference {
    contract_id: String,
    version: String,
    sha256: String,
}

impl From<&ContractReference> for ReworkContractReference {
    fn from(value: &ContractReference) -> Self {
        Self {
            contract_id: value.contract_id.clone(),
            version: value.version.clone(),
            sha256: value.sha256.clone(),
        }
    }
}

impl ReworkContractReference {
    fn to_contract_reference(&self) -> ContractReference {
        ContractReference {
            contract_id: self.contract_id.clone(),
            version: self.version.clone(),
            sha256: self.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReworkCoverage {
    risk_category: i32,
    discrepancy_ids: Vec<String>,
    unverified_item_ids: Vec<String>,
}

impl From<&FounderSupportingMaterialCoverage> for ReworkCoverage {
    fn from(value: &FounderSupportingMaterialCoverage) -> Self {
        Self {
            risk_category: value.risk_category,
            discrepancy_ids: value.discrepancy_ids.clone(),
            unverified_item_ids: value.unverified_item_ids.clone(),
        }
    }
}

impl ReworkCoverage {
    fn to_proto(&self) -> FounderSupportingMaterialCoverage {
        FounderSupportingMaterialCoverage {
            risk_category: self.risk_category,
            discrepancy_ids: self.discrepancy_ids.clone(),
            unverified_item_ids: self.unverified_item_ids.clone(),
        }
    }
}

struct BaseReworkContext {
    snapshot: egopulse_cognition_runtime::context_authority::ContextSnapshot,
    compiled_context: Vec<u8>,
}

fn compile_rework_context(
    resolved: &ResolvedReworkFollowup,
) -> Result<CompiledReworkContext, CommandPortFailure> {
    let material =
        FounderSupportingMaterial::decode(resolved.required_changes.evidence.payload.as_slice())
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
    Ok(CompiledReworkContext {
        rework_followup_version: REWORK_CONTEXT_VERSION,
        memory_mode: "frozen_original_context".to_owned(),
        owner_principal_id: resolved.owner_principal_id.clone(),
        task_id: resolved.task.task_id.clone(),
        task_revision: resolved.task.revision,
        prior_work_revision: resolved.task.work_revision,
        work_type: resolved.task.work_type.clone(),
        target_scope_ref: resolved.task.target_scope_ref.clone(),
        acceptance_contract_ref: ReworkContractReference::from(
            resolved
                .task
                .acceptance_contract_ref
                .as_ref()
                .ok_or(CommandPortFailure::IntegrityFailure)?,
        ),
        budget_profile_ref: contract_key(
            resolved
                .task
                .budget_profile_ref
                .as_ref()
                .ok_or(CommandPortFailure::IntegrityFailure)?,
        ),
        founder_verdict_id: resolved.verdict.founder_verdict_id.clone(),
        verdict_state_revision: resolved.verdict_state.revision,
        verdict_application_event_id: resolved.applied_verdict_event.event_id.clone(),
        directive_id: resolved.directive.directive_id.clone(),
        directive_reason_code: resolved.directive.reason_code.clone(),
        required_changes_artifact_id: resolved.required_changes.artifact_id.clone(),
        required_changes_content_sha256: sha256(&resolved.required_changes.evidence.payload),
        required_changes_material_id: material.material_id,
        required_changes_author_principal_id: material.authenticated_founder_principal_id,
        required_changes_body: material.body,
        required_changes_coverage: ReworkCoverage::from(
            material
                .coverage
                .as_ref()
                .ok_or(CommandPortFailure::IntegrityFailure)?,
        ),
        bound_workspace_ref: resolved
            .required_changes
            .evidence
            .bound_workspace_ref
            .clone(),
        bound_source_binding_ref: resolved
            .required_changes
            .evidence
            .bound_source_binding_ref
            .clone(),
        repository_carry_forward: resolved.repository_carry_forward.clone(),
    })
}

fn decode_compiled_rework_context(
    bytes: &[u8],
) -> Result<CompiledReworkContext, CommandPortFailure> {
    let root: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CommandPortFailure::IntegrityFailure)?;
    let rework = root
        .as_object()
        .and_then(|root| root.get("rework_followup"))
        .ok_or(CommandPortFailure::IntegrityFailure)?
        .clone();
    let context: CompiledReworkContext =
        serde_json::from_value(rework).map_err(|_| CommandPortFailure::IntegrityFailure)?;
    if context.rework_followup_version != REWORK_CONTEXT_VERSION
        || context.memory_mode != "frozen_original_context"
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(context)
}

fn merge_rework_followup(
    base_compiled_context: &[u8],
    rework_followup: &CompiledReworkContext,
) -> Result<Vec<u8>, CommandPortFailure> {
    let mut root: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(base_compiled_context)
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
    let original_prompt = if root.contains_key("rework_followup") {
        let previous = decode_compiled_rework_context(base_compiled_context)?;
        if previous.task_id != rework_followup.task_id
            || previous.owner_principal_id != rework_followup.owner_principal_id
            || previous.prior_work_revision.checked_add(1)
                != Some(rework_followup.prior_work_revision)
            || previous.task_revision >= rework_followup.task_revision
            || previous.target_scope_ref != rework_followup.target_scope_ref
            || previous.acceptance_contract_ref != rework_followup.acceptance_contract_ref
            || previous.repository_carry_forward.frozen_material
                != rework_followup.repository_carry_forward.frozen_material
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        let original = root
            .get("rework_original_prompt")
            .and_then(serde_json::Value::as_str)
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        if root.get("prompt").and_then(serde_json::Value::as_str)
            != Some(rework_execution_prompt(original, &previous).as_str())
        {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        original.to_owned()
    } else {
        if root.contains_key("rework_original_prompt") || rework_followup.prior_work_revision != 1 {
            return Err(CommandPortFailure::IntegrityFailure);
        }
        root.get("prompt")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(CommandPortFailure::IntegrityFailure)?
            .to_owned()
    };
    // Native adapters consume `prompt`; a sibling proof object alone does not
    // deliver the new directive to the existing execution loop.
    root.insert(
        "prompt".to_owned(),
        serde_json::Value::String(rework_execution_prompt(&original_prompt, rework_followup)),
    );
    root.insert(
        "rework_original_prompt".to_owned(),
        serde_json::Value::String(original_prompt),
    );
    root.insert(
        "rework_followup".to_owned(),
        serde_json::to_value(rework_followup).map_err(|_| CommandPortFailure::IntegrityFailure)?,
    );
    serde_json::to_vec(&root).map_err(|_| CommandPortFailure::IntegrityFailure)
}

fn rework_execution_prompt(original: &str, followup: &CompiledReworkContext) -> String {
    format!(
        "{original}\n\nCurrent Founder Rework directive ({}):\n{}\n\nContinue this same task from the sealed changes already restored in the current workspace. Apply this current directive within the original allowed scope; do not revert inherited work or read an old live workspace. Return the cumulative result against the original baseline.",
        followup.directive_id, followup.required_changes_body
    )
}

fn issue_context_input(
    principal: &CommandPrincipal,
    base: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
    compiled_bytes: Vec<u8>,
    compiled: CompiledReworkContext,
    idempotency_key: String,
    deadline_seconds: Option<i64>,
    expires_at_seconds: i64,
) -> Result<IssueContextSnapshot, CommandPortFailure> {
    let source = ContextSourceFact {
        source_ref: format!("founder-directive:{}", compiled.directive_id),
        label: "founder-rework-required-changes".to_owned(),
        authority: "founder-verdict-authority".to_owned(),
        content_sha256: compiled.required_changes_content_sha256.clone(),
        included: true,
    };
    let acceptance_contract = compiled.acceptance_contract_ref.to_contract_reference();
    let acceptance_contract_ref = contract_key(&acceptance_contract);
    let budget_profile_ref = compiled.budget_profile_ref.clone();
    let mut sources = base.sources.clone();
    sources.push(source);
    if principal.principal_id != compiled.owner_principal_id
        || base.owner_principal_id != principal.principal_id
        || base.work_type != compiled.work_type
        || base.target_scope_ref != compiled.target_scope_ref
        || base.acceptance_contract_ref != acceptance_contract_ref
        || base.budget_profile_ref != budget_profile_ref
        || compiled.repository_carry_forward.prior_task_id != compiled.task_id
        || compiled.repository_carry_forward.prior_work_revision != compiled.prior_work_revision
        || compiled.repository_carry_forward.workspace_ref != compiled.bound_workspace_ref
        || compiled.repository_carry_forward.source_binding_ref != compiled.bound_source_binding_ref
        || !valid_digest(&compiled.required_changes_content_sha256)
        || !valid_body(&compiled.required_changes_body)
        || !complete_rework_contract_reference(&compiled.acceptance_contract_ref)
        || !valid_routing(&budget_profile_ref)
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(IssueContextSnapshot {
        owner_principal_id: principal.principal_id.clone(),
        intent: rework_intent(&base.intent, &compiled.required_changes_body)?,
        work_type: base.work_type.clone(),
        target_scope_ref: base.target_scope_ref.clone(),
        compiled_context: compiled_bytes,
        sources,
        // The original accepted pack remains an immutable input binding. A
        // Rework follow-up does not run a fresh memory retrieval.
        memory_pack: base.memory_pack.clone(),
        allowed_read_paths: base.allowed_read_paths.clone(),
        allowed_write_paths: base.allowed_write_paths.clone(),
        allowed_tools: base.allowed_tools.clone(),
        external_resources: base.external_resources.clone(),
        non_goals: base.non_goals.clone(),
        acceptance_contract_ref,
        budget_profile_ref,
        deadline_seconds,
        recovery_entry: base.recovery_entry.clone(),
        visibility: base.visibility.clone(),
        redactions: base.redactions.clone(),
        expires_at_seconds,
        idempotency_key,
    })
}

fn work_preview(
    frozen: &CompiledReworkContext,
    snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
    context_state_revision: u64,
    configured_budget_profile_ref: &ContractReference,
    compiled_context: &[u8],
    work_capability_registry: Option<&WorkCapabilityRegistry>,
) -> Result<WorkPreparationPreview, CommandPortFailure> {
    let (work_capability, selection_source, preference_revision) =
        work_capability_view_from_compiled_context(compiled_context, work_capability_registry)?;
    Ok(WorkPreparationPreview {
        snapshot_id: snapshot.snapshot_id.clone(),
        snapshot_revision: snapshot.revision,
        normalized_intent: snapshot.intent.clone(),
        work_type: snapshot.work_type.clone(),
        target_scope_ref: snapshot.target_scope_ref.clone(),
        compiled_context_sha256: snapshot.compiled_context_sha256.clone(),
        included_sources: snapshot
            .sources
            .iter()
            .cloned()
            .map(work_source_fact)
            .collect(),
        excluded_sources: Vec::new(),
        non_goals: snapshot.non_goals.clone(),
        allowed_read_paths: snapshot.allowed_read_paths.clone(),
        allowed_write_paths: snapshot.allowed_write_paths.clone(),
        allowed_tools: snapshot.allowed_tools.clone(),
        external_resources: snapshot.external_resources.clone(),
        acceptance_contract_ref: Some(frozen.acceptance_contract_ref.to_contract_reference()),
        budget_profile_ref: Some(configured_budget_profile_ref.clone()),
        memory_authority_revision: snapshot
            .memory_pack
            .as_ref()
            .map(|value| value.authority_revision),
        memory_pack_snapshot_sha256: snapshot
            .memory_pack
            .as_ref()
            .map(|value| value.snapshot_sha256.clone()),
        recovery_entry: snapshot.recovery_entry.clone(),
        visibility: snapshot.visibility.clone(),
        redactions: snapshot
            .redactions
            .iter()
            .map(|redaction| {
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RedactedField {
                    field_path: redaction.field_path.clone(),
                    reason_code: redaction.reason_code.clone(),
                }
            })
            .collect(),
        expires_at: Some(Timestamp {
            seconds: snapshot.expires_at_seconds,
            nanos: 0,
        }),
        confirmation_binding_sha256: snapshot.confirmation_binding_sha256.clone(),
        gate_ready: true,
        blockers: Vec::new(),
        warnings: Vec::new(),
        required_confirmations: vec!["founder.confirm_rework".to_owned()],
        evidence_required: vec![
            "sealed_required_changes".to_owned(),
            "sealed_repository_carry_forward".to_owned(),
            "artifact_and_evidence".to_owned(),
            "sego_verification".to_owned(),
            "founder_verdict".to_owned(),
        ],
        ready_for_founder_confirmation: true,
        deadline: snapshot
            .deadline_seconds
            .map(|seconds| Timestamp { seconds, nanos: 0 }),
        context_state_revision,
        work_capability,
        work_capability_selection_source: selection_source,
        preference_revision_at_resolution: preference_revision,
    })
}

fn work_source_fact(source: ContextSourceFact) -> WorkSourceFact {
    WorkSourceFact {
        source_ref: source.source_ref,
        label: source.label,
        authority: source.authority,
        content_sha256: source.content_sha256,
        included: source.included,
    }
}

fn rework_intent(
    base_intent: &str,
    required_changes_body: &str,
) -> Result<String, CommandPortFailure> {
    let reviewable_changes = required_changes_body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let intent = format!("{base_intent} | Required changes: {reviewable_changes}");
    if intent.trim().is_empty()
        || intent.len() > 16 * 1024 * 1024
        || intent.chars().any(char::is_control)
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(intent)
}

fn revise_command(
    request: &ConfirmReworkRequest,
    frozen: &CompiledReworkContext,
    now: i64,
) -> Result<TaskCommand, CommandPortFailure> {
    let mut command = TaskCommand {
        command: Some(task_command::Command::ReviseTask(ReviseTaskCommand {
            meta: Some(CommandMetadata {
                command_id: Uuid::now_v7().to_string(),
                idempotency_key: revision_idempotency_key(request, frozen),
                idempotency_scope: "local.work.rework.revise".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(Timestamp {
                    seconds: now,
                    nanos: 0,
                }),
                correlation_id: request
                    .client
                    .as_ref()
                    .and_then(|client| client.correlation_id.clone())
                    .unwrap_or_else(|| frozen.task_id.clone()),
                causation_id: Some(request.snapshot_id.clone()),
            }),
            task_id: frozen.task_id.clone(),
            expected_revision: frozen.task_revision,
            expected_work_revision: frozen.prior_work_revision,
            new_input_snapshot_id: request.snapshot_id.clone(),
            new_target_scope_ref: frozen.target_scope_ref.clone(),
            new_acceptance_contract_ref: Some(
                frozen.acceptance_contract_ref.to_contract_reference(),
            ),
        })),
    };
    if !valid_routing(&frozen.task_id)
        || frozen.task_revision == 0
        || frozen.prior_work_revision == 0
        || !valid_routing(&request.snapshot_id)
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    set_revise_digest(&mut command)?;
    Ok(command)
}

fn activation_command(
    request: &ConfirmReworkRequest,
    task: &TaskSnapshot,
    snapshot_id: &str,
    run_id: String,
    now: i64,
) -> Result<TaskCommand, CommandPortFailure> {
    if task.status != TaskStatus::Ready as i32
        || !valid_routing(snapshot_id)
        || !valid_routing(&run_id)
        || task.revision == 0
        || task.work_revision == 0
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    let mut command = TaskCommand {
        command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
            meta: Some(CommandMetadata {
                command_id: Uuid::now_v7().to_string(),
                idempotency_key: format!(
                    "{}:activate",
                    revision_idempotency_key_from_task(task, snapshot_id)
                ),
                idempotency_scope: "local.work.rework.activation".to_owned(),
                request_digest_sha256: String::new(),
                issued_at: Some(Timestamp {
                    seconds: now,
                    nanos: 0,
                }),
                correlation_id: request
                    .client
                    .as_ref()
                    .and_then(|client| client.correlation_id.clone())
                    .unwrap_or_else(|| task.task_id.clone()),
                causation_id: Some(snapshot_id.to_owned()),
            }),
            task_id: task.task_id.clone(),
            expected_revision: task.revision,
            work_revision: task.work_revision,
            run_id,
        })),
    };
    set_activate_digest(&mut command)?;
    Ok(command)
}

fn result_task_snapshot(result: &TaskCommandResult) -> Option<TaskSnapshot> {
    match result.outcome.as_ref()? {
        task_command_result::Outcome::Task(task) => Some(task.clone()),
        task_command_result::Outcome::Error(_) => None,
    }
}

fn set_revise_digest(command: &mut TaskCommand) -> Result<(), CommandPortFailure> {
    let digest = canonical_request_digest(command).map_err(task_read_failure)?;
    let Some(task_command::Command::ReviseTask(revise)) = command.command.as_mut() else {
        return Err(CommandPortFailure::IntegrityFailure);
    };
    revise
        .meta
        .as_mut()
        .ok_or(CommandPortFailure::IntegrityFailure)?
        .request_digest_sha256 = digest;
    Ok(())
}

fn set_activate_digest(command: &mut TaskCommand) -> Result<(), CommandPortFailure> {
    let digest = canonical_request_digest(command).map_err(task_read_failure)?;
    let Some(task_command::Command::ActivateTask(activate)) = command.command.as_mut() else {
        return Err(CommandPortFailure::IntegrityFailure);
    };
    activate
        .meta
        .as_mut()
        .ok_or(CommandPortFailure::IntegrityFailure)?
        .request_digest_sha256 = digest;
    Ok(())
}

/// Revalidates the immutable Rework proof at the Task transition boundary.
/// ROOT calls this from `ConfiguredTaskTransitionGuard` with the current
/// snapshot; this function opens no Task store and does not mutate any owner.
pub(crate) fn validate_rework_transition(
    current: &TaskSnapshot,
    command: &ReviseTaskCommand,
    context: &Arc<Mutex<ContextAuthority>>,
    founder_verdict: &SharedFounderVerdictAuthority,
) -> Result<Vec<String>, egopulse_cognition_runtime::task_authority::TransitionGuardRejection> {
    use egopulse_cognition_runtime::task_authority::TransitionGuardRejection;

    if current.status != TaskStatus::Rework as i32
        || command.task_id != current.task_id
        || command.expected_revision != current.revision
        || command.expected_work_revision != current.work_revision
        || !valid_routing(&command.new_input_snapshot_id)
        || command.new_target_scope_ref != current.target_scope_ref
        || command.new_acceptance_contract_ref.as_ref() != current.acceptance_contract_ref.as_ref()
    {
        return Err(TransitionGuardRejection::StateConflict);
    }
    let now = unix_seconds().ok_or(TransitionGuardRejection::IntegrityFailure)?;
    let compiled = {
        let authority = context
            .lock()
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
        let resolved = authority
            .resolve(
                &command.new_input_snapshot_id,
                &current.target_scope_ref,
                now,
            )
            .map_err(context_transition_rejection)?;
        if resolved.snapshot.snapshot_id != command.new_input_snapshot_id
            || resolved.snapshot.work_type != current.work_type
            || resolved.snapshot.target_scope_ref != current.target_scope_ref
            || resolved.snapshot.acceptance_contract_ref
                != contract_key(
                    current
                        .acceptance_contract_ref
                        .as_ref()
                        .ok_or(TransitionGuardRejection::IntegrityFailure)?,
                )
            || resolved.snapshot.budget_profile_ref
                != contract_key(
                    current
                        .budget_profile_ref
                        .as_ref()
                        .ok_or(TransitionGuardRejection::IntegrityFailure)?,
                )
        {
            return Err(TransitionGuardRejection::IntegrityFailure);
        }
        decode_compiled_rework_context(&resolved.compiled_context)
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?
    };
    if compiled.task_id != current.task_id
        || compiled.task_revision != current.revision
        || compiled.prior_work_revision != current.work_revision
        || compiled.work_type != current.work_type
        || compiled.target_scope_ref != current.target_scope_ref
        || compiled.memory_mode != "frozen_original_context"
        || compiled.acceptance_contract_ref.to_contract_reference()
            != *current
                .acceptance_contract_ref
                .as_ref()
                .ok_or(TransitionGuardRejection::IntegrityFailure)?
        || compiled.budget_profile_ref
            != contract_key(
                current
                    .budget_profile_ref
                    .as_ref()
                    .ok_or(TransitionGuardRejection::IntegrityFailure)?,
            )
        || compiled.repository_carry_forward.prior_task_id != current.task_id
        || compiled.repository_carry_forward.prior_work_revision != current.work_revision
        || !valid_carry_forward(&compiled.repository_carry_forward, current)
    {
        return Err(TransitionGuardRejection::StaleReference);
    }
    let verdict = {
        let owner = founder_verdict
            .lock()
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
        let authority = owner
            .as_ref()
            .ok_or(TransitionGuardRejection::UnverifiedReference)?;
        authority
            .get(&compiled.founder_verdict_id)
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?
            .ok_or(TransitionGuardRejection::StaleReference)?
    };
    let (verdict, state) = verdict;
    let scope = verdict
        .scope
        .as_ref()
        .ok_or(TransitionGuardRejection::IntegrityFailure)?;
    let directive = verdict
        .rework_directive
        .as_ref()
        .ok_or(TransitionGuardRejection::IntegrityFailure)?;
    if FounderVerdictDecision::try_from(verdict.decision).ok()
        != Some(FounderVerdictDecision::Rework)
        || verdict.founder_verdict_id != compiled.founder_verdict_id
        || state.founder_verdict_id != compiled.founder_verdict_id
        || state.revision != compiled.verdict_state_revision
        || state.revision == 0
        || scope.task_id != current.task_id
        || scope.task_revision != current.revision.saturating_sub(1)
        || scope.work_revision != current.work_revision
        || scope.acceptance_contract_ref.as_ref() != current.acceptance_contract_ref.as_ref()
        || directive.directive_id != compiled.directive_id
        || directive.reason_code != compiled.directive_reason_code
        || directive.required_changes_artifact_id != compiled.required_changes_artifact_id
        || directive.target_discrepancy_ids != compiled.required_changes_coverage.discrepancy_ids
        || directive.target_unverified_item_ids
            != compiled.required_changes_coverage.unverified_item_ids
        || compiled.required_changes_coverage.to_proto().risk_category != 0
    {
        return Err(TransitionGuardRejection::StaleReference);
    }
    Ok(vec![
        format!(
            "context-snapshot:{}@rework-v1",
            command.new_input_snapshot_id
        ),
        format!("founder-verdict:{}@applied", compiled.founder_verdict_id),
        format!(
            "founder-verdict-state:{}@{}",
            compiled.founder_verdict_id, state.revision
        ),
        format!("founder-directive:{}@sealed", compiled.directive_id),
        format!(
            "founder-required-changes-artifact:{}@sealed",
            compiled.required_changes_artifact_id
        ),
        format!(
            "repository-carry-forward-patch:{}@sealed",
            compiled
                .repository_carry_forward
                .repository_patch_artifact_id
        ),
        format!(
            "repository-carry-forward-final-manifest:{}@sealed",
            compiled.repository_carry_forward.final_manifest_artifact_id
        ),
        format!(
            "repository-carry-forward-artifact-set:{}@sealed",
            compiled.repository_carry_forward.artifact_set_id
        ),
        format!(
            "repository-carry-forward-baseline:{}@sealed",
            compiled.repository_carry_forward.baseline_artifact_id
        ),
        format!(
            "repository-carry-forward-initial-manifest:{}@sealed",
            compiled
                .repository_carry_forward
                .initial_manifest_artifact_id
        ),
    ])
}

fn validate_resolved_rework_followup(
    resolved: &ResolvedReworkFollowup,
    principal: &CommandPrincipal,
) -> Result<(), CommandPortFailure> {
    let task = &resolved.task;
    let verdict = &resolved.verdict;
    let scope = verdict
        .scope
        .as_ref()
        .ok_or(CommandPortFailure::IntegrityFailure)?;
    let material =
        FounderSupportingMaterial::decode(resolved.required_changes.evidence.payload.as_slice())
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
    let descriptor = &resolved.required_changes.evidence.descriptor;
    let content = descriptor
        .content
        .as_ref()
        .ok_or(CommandPortFailure::IntegrityFailure)?;
    let expected_coverage = FounderSupportingMaterialCoverage {
        risk_category: 0,
        discrepancy_ids: resolved.directive.target_discrepancy_ids.clone(),
        unverified_item_ids: resolved.directive.target_unverified_item_ids.clone(),
    };
    if principal.principal_id != resolved.owner_principal_id
        || task.status != TaskStatus::Rework as i32
        || task.revision == 0
        || task.work_revision == 0
        || task.founder_verdict_id.as_deref() != Some(verdict.founder_verdict_id.as_str())
        || FounderVerdictDecision::try_from(verdict.decision).ok()
            != Some(FounderVerdictDecision::Rework)
        || resolved.verdict_state.founder_verdict_id != verdict.founder_verdict_id
        || resolved.verdict_state.revision == 0
        || scope.task_id != task.task_id
        || scope.task_revision.checked_add(1) != Some(task.revision)
        || scope.work_revision != task.work_revision
        || scope.acceptance_contract_ref.as_ref() != task.acceptance_contract_ref.as_ref()
        || resolved.applied_verdict_event.task_id != task.task_id
        || resolved.applied_verdict_event.expected_revision != scope.task_revision
        || resolved.applied_verdict_event.resulting_revision != task.revision
        || resolved.applied_verdict_event.work_revision != task.work_revision
        || resolved.applied_verdict_event.snapshot.as_ref() != Some(task)
        || resolved.directive.directive_id.trim().is_empty()
        || resolved.directive.reason_code.trim().is_empty()
        || resolved.directive.required_changes_artifact_id != resolved.required_changes.artifact_id
        || descriptor.artifact_id != resolved.required_changes.artifact_id
        || content.digest != sha256(&resolved.required_changes.evidence.payload)
        || content.byte_length != resolved.required_changes.evidence.payload.len() as u64
        || material.role != FounderSupportingMaterialRole::ReworkRequiredChanges as i32
        || material.scope.as_ref() != Some(scope)
        || material.authenticated_founder_principal_id != resolved.owner_principal_id
        || material.body.trim().is_empty()
        || material.coverage.as_ref() != Some(&expected_coverage)
        || resolved
            .required_changes
            .evidence
            .bound_workspace_ref
            .trim()
            .is_empty()
        || resolved
            .required_changes
            .evidence
            .bound_source_binding_ref
            .trim()
            .is_empty()
        || !valid_carry_forward(&resolved.repository_carry_forward, task)
        || resolved
            .repository_carry_forward
            .frozen_material
            .acceptance_contract_ref()
            != *task
                .acceptance_contract_ref
                .as_ref()
                .ok_or(CommandPortFailure::IntegrityFailure)?
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(())
}

fn valid_carry_forward(value: &SealedReworkRepositoryCarryForward, task: &TaskSnapshot) -> bool {
    value.prior_task_id == task.task_id
        && value.prior_task_revision > 0
        && value.prior_work_revision == task.work_revision
        && valid_routing(&value.artifact_set_id)
        && valid_rework_content_address(&value.artifact_set_manifest)
        && valid_rework_lineage(&value.lineage)
        && value.lineage.task_id == value.prior_task_id
        && value.lineage.task_revision == value.prior_task_revision
        && value.lineage.work_revision == value.prior_work_revision
        && valid_routing(&value.baseline_artifact_id)
        && valid_routing(&value.initial_manifest_artifact_id)
        && valid_routing(&value.repository_patch_artifact_id)
        && valid_digest(&value.repository_patch_sha256)
        && valid_routing(&value.final_manifest_artifact_id)
        && valid_digest(&value.final_manifest_sha256)
        && valid_routing(&value.workspace_ref)
        && valid_routing(&value.source_binding_ref)
}

fn valid_rework_content_address(value: &ReworkContentAddress) -> bool {
    value.algorithm == HashAlgorithm::Sha256 as i32
        && valid_digest(&value.digest)
        && value.byte_length > 0
}

fn valid_rework_lineage(value: &ReworkLineageBinding) -> bool {
    valid_routing(&value.task_id)
        && value.task_revision > 0
        && value.work_revision > 0
        && valid_routing(&value.run_id)
        && value.run_revision > 0
        && valid_routing(&value.step_id)
        && value.step_revision > 0
        && valid_routing(&value.attempt_id)
        && value.attempt_revision > 0
        && valid_routing(&value.dispatch_id)
        && value.fencing_token > 0
}

fn validate_prepare_request(request: &PrepareReworkRequest) -> Result<(), CommandPortFailure> {
    if !valid_routing(&request.task_id)
        || request.expected_revision == 0
        || !valid_routing(&request.idempotency_key)
    {
        return Err(CommandPortFailure::InvalidArgument);
    }
    Ok(())
}

fn validate_confirm_request(request: &ConfirmReworkRequest) -> Result<(), CommandPortFailure> {
    if !valid_routing(&request.task_id)
        || !valid_routing(&request.snapshot_id)
        || !valid_digest(&request.confirmation_binding_sha256)
        || !valid_routing(&request.idempotency_key)
    {
        return Err(CommandPortFailure::InvalidArgument);
    }
    Ok(())
}

fn validate_prepared_rework_confirmation(
    snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
    frozen: &CompiledReworkContext,
    request: &ConfirmReworkRequest,
    principal: &CommandPrincipal,
    budget_profile_ref: &ContractReference,
) -> Result<(), CommandPortFailure> {
    if snapshot.snapshot_id != request.snapshot_id
        || snapshot.owner_principal_id != principal.principal_id
        || snapshot.confirmation_binding_sha256 != request.confirmation_binding_sha256
        || frozen.rework_followup_version != REWORK_CONTEXT_VERSION
        || frozen.memory_mode != "frozen_original_context"
        || frozen.task_id != request.task_id
        || frozen.owner_principal_id != principal.principal_id
        || frozen.target_scope_ref != snapshot.target_scope_ref
        || frozen.work_type != snapshot.work_type
        || snapshot.acceptance_contract_ref
            != contract_key(&frozen.acceptance_contract_ref.to_contract_reference())
        || frozen.budget_profile_ref != contract_key(budget_profile_ref)
        || snapshot.budget_profile_ref != frozen.budget_profile_ref
        || frozen.task_revision == 0
        || frozen.prior_work_revision == 0
        || !valid_carry_forward_for_prepared_confirmation(
            &frozen.repository_carry_forward,
            &frozen.task_id,
            frozen.prior_work_revision,
        )
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(())
}

fn validate_replayed_rework_revision(
    result: &TaskCommandResult,
    snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
    frozen: &CompiledReworkContext,
) -> Result<(), CommandPortFailure> {
    let task = result_task_snapshot(result).ok_or(CommandPortFailure::IntegrityFailure)?;
    if task.status != TaskStatus::Ready as i32
        || task.task_id != frozen.task_id
        || task.revision != frozen.task_revision.saturating_add(1)
        || task.work_revision != frozen.prior_work_revision.saturating_add(1)
        || task.input_snapshot_id != snapshot.snapshot_id
        || task.target_scope_ref != frozen.target_scope_ref
        || task.acceptance_contract_ref.as_ref()
            != Some(&frozen.acceptance_contract_ref.to_contract_reference())
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(())
}

fn valid_carry_forward_for_prepared_confirmation(
    value: &SealedReworkRepositoryCarryForward,
    task_id: &str,
    prior_work_revision: u64,
) -> bool {
    value.prior_task_id == task_id
        && value.prior_task_revision > 0
        && value.prior_work_revision == prior_work_revision
        && valid_routing(&value.artifact_set_id)
        && valid_rework_content_address(&value.artifact_set_manifest)
        && valid_rework_lineage(&value.lineage)
        && value.lineage.task_id == value.prior_task_id
        && value.lineage.task_revision == value.prior_task_revision
        && value.lineage.work_revision == value.prior_work_revision
        && valid_routing(&value.baseline_artifact_id)
        && valid_routing(&value.initial_manifest_artifact_id)
        && valid_routing(&value.repository_patch_artifact_id)
        && valid_digest(&value.repository_patch_sha256)
        && valid_routing(&value.final_manifest_artifact_id)
        && valid_digest(&value.final_manifest_sha256)
        && valid_routing(&value.workspace_ref)
        && valid_routing(&value.source_binding_ref)
}

fn context_compiler_principal() -> AuthenticatedContextPrincipal {
    AuthenticatedContextPrincipal {
        kind: ContextPrincipalKind::ContextCompiler,
        principal_id: REWORK_CONTEXT_COMPILER_PRINCIPAL.to_owned(),
        authenticated: true,
    }
}

fn prepared_confirmation_principal(principal: &CommandPrincipal) -> AuthenticatedContextPrincipal {
    AuthenticatedContextPrincipal {
        // This principal is only a typed projection of the already-authenticated
        // Local API owner for Context's read-only owner/binding check. It is
        // never used to issue, dispatch, or renew a Context snapshot.
        kind: ContextPrincipalKind::ContextCompiler,
        principal_id: principal.principal_id.clone(),
        authenticated: true,
    }
}

fn rework_context_idempotency_key(
    principal: &CommandPrincipal,
    request: &PrepareReworkRequest,
) -> String {
    let task_revision = request.expected_revision.to_string();
    framed_digest(
        "rework-prepare",
        [
            principal.principal_id.as_str(),
            request.idempotency_key.as_str(),
            request.task_id.as_str(),
            &task_revision,
        ],
    )
}

fn revision_idempotency_key(
    request: &ConfirmReworkRequest,
    frozen: &CompiledReworkContext,
) -> String {
    revision_idempotency_key_from_values(
        request.idempotency_key.as_str(),
        frozen.task_id.as_str(),
        frozen.prior_work_revision,
        frozen.directive_id.as_str(),
        request.snapshot_id.as_str(),
    )
}

fn revision_idempotency_key_from_task(task: &TaskSnapshot, snapshot_id: &str) -> String {
    // Activation uses the post-Revise Task identity but preserves the exact
    // frozen Context binding. It is stable across activation reconciliation.
    revision_idempotency_key_from_values(
        "activation",
        task.task_id.as_str(),
        task.work_revision.saturating_sub(1),
        "rework",
        snapshot_id,
    )
}

fn revision_idempotency_key_from_values(
    client_key: &str,
    task_id: &str,
    prior_work_revision: u64,
    directive_id: &str,
    snapshot_id: &str,
) -> String {
    let prior_work_revision = prior_work_revision.to_string();
    framed_digest(
        "rework-confirm",
        [
            client_key,
            task_id,
            &prior_work_revision,
            directive_id,
            snapshot_id,
        ],
    )
}

fn framed_digest<'a>(domain: &'a str, fields: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for field in std::iter::once(domain).chain(fields) {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{domain}:{}", hex::encode(hasher.finalize()))
}

fn task_snapshot(
    authority: &TaskAuthority,
    task_id: &str,
) -> Result<TaskSnapshot, CommandPortFailure> {
    match authority
        .get_task(task_id)
        .map_err(task_read_failure)?
        .outcome
    {
        Some(get_task_response::Outcome::Task(snapshot)) => Ok(snapshot),
        _ => Err(CommandPortFailure::IntegrityFailure),
    }
}

fn task_read_failure(
    _error: egopulse_cognition_runtime::task_authority::TaskAuthorityFailure,
) -> CommandPortFailure {
    CommandPortFailure::Unavailable
}

fn material_failure(
    error: crate::verdict::FounderSupportingMaterialEvidenceError,
) -> CommandPortFailure {
    match error {
        crate::verdict::FounderSupportingMaterialEvidenceError::Unavailable => {
            CommandPortFailure::Unavailable
        }
        crate::verdict::FounderSupportingMaterialEvidenceError::IntegrityFailure => {
            CommandPortFailure::IntegrityFailure
        }
    }
}

fn context_failure(error: ContextAuthorityFailure) -> CommandPortFailure {
    match error {
        ContextAuthorityFailure::Storage => CommandPortFailure::Unavailable,
        ContextAuthorityFailure::NotFound
        | ContextAuthorityFailure::Expired
        | ContextAuthorityFailure::Revoked
        | ContextAuthorityFailure::ScopeMismatch
        | ContextAuthorityFailure::InvalidArgument(_)
        | ContextAuthorityFailure::Unauthorized
        | ContextAuthorityFailure::OwnerMismatch
        | ContextAuthorityFailure::IdempotencyConflict
        | ContextAuthorityFailure::StateRevisionConflict
        | ContextAuthorityFailure::AuthorizationTupleConflict
        | ContextAuthorityFailure::Clock
        | ContextAuthorityFailure::IntegrityFailure => CommandPortFailure::IntegrityFailure,
    }
}

fn context_transition_rejection(
    error: ContextAuthorityFailure,
) -> egopulse_cognition_runtime::task_authority::TransitionGuardRejection {
    use egopulse_cognition_runtime::task_authority::TransitionGuardRejection;
    match error {
        ContextAuthorityFailure::NotFound
        | ContextAuthorityFailure::Expired
        | ContextAuthorityFailure::Revoked
        | ContextAuthorityFailure::ScopeMismatch => TransitionGuardRejection::StaleReference,
        ContextAuthorityFailure::Storage
        | ContextAuthorityFailure::IntegrityFailure
        | ContextAuthorityFailure::Clock => TransitionGuardRejection::IntegrityFailure,
        ContextAuthorityFailure::InvalidArgument(_)
        | ContextAuthorityFailure::Unauthorized
        | ContextAuthorityFailure::OwnerMismatch
        | ContextAuthorityFailure::IdempotencyConflict
        | ContextAuthorityFailure::StateRevisionConflict
        | ContextAuthorityFailure::AuthorizationTupleConflict => {
            TransitionGuardRejection::UnverifiedReference
        }
    }
}

fn valid_routing(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
}

fn valid_body(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 64 * 1024
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn complete_contract_reference(reference: &ContractReference) -> bool {
    valid_routing(&reference.contract_id)
        && valid_routing(&reference.version)
        && valid_digest(&reference.sha256)
}

fn complete_rework_contract_reference(reference: &ReworkContractReference) -> bool {
    valid_routing(&reference.contract_id)
        && valid_routing(&reference.version)
        && valid_digest(&reference.sha256)
}

fn contract_key(reference: &ContractReference) -> String {
    format!(
        "{}@{}#{}",
        reference.contract_id, reference.version, reference.sha256
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_seconds() -> Option<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository_material::{FrozenContractReference, RepositoryAcceptanceContractV1};

    fn digest() -> String {
        "a".repeat(64)
    }

    fn sample_compiled() -> CompiledReworkContext {
        let contract = ReworkContractReference {
            contract_id: "acceptance".to_owned(),
            version: "v1".to_owned(),
            sha256: digest(),
        };
        CompiledReworkContext {
            rework_followup_version: REWORK_CONTEXT_VERSION,
            memory_mode: "frozen_original_context".to_owned(),
            owner_principal_id: "founder:one".to_owned(),
            task_id: "task:one".to_owned(),
            task_revision: 3,
            prior_work_revision: 1,
            work_type: "governed_repository_change".to_owned(),
            target_scope_ref: "workspace:default".to_owned(),
            acceptance_contract_ref: contract.clone(),
            budget_profile_ref: format!("budget@v1#{}", digest()),
            founder_verdict_id: "verdict:one".to_owned(),
            verdict_state_revision: 2,
            verdict_application_event_id: "event:one".to_owned(),
            directive_id: "directive:one".to_owned(),
            directive_reason_code: "required_changes".to_owned(),
            required_changes_artifact_id: "artifact:changes".to_owned(),
            required_changes_content_sha256: digest(),
            required_changes_material_id: "material:one".to_owned(),
            required_changes_author_principal_id: "founder:one".to_owned(),
            required_changes_body: "Update the exact failing check".to_owned(),
            required_changes_coverage: ReworkCoverage {
                risk_category: 0,
                discrepancy_ids: vec!["scope".to_owned()],
                unverified_item_ids: Vec::new(),
            },
            bound_workspace_ref: "workspace:one".to_owned(),
            bound_source_binding_ref: "source:one".to_owned(),
            repository_carry_forward: SealedReworkRepositoryCarryForward {
                prior_task_id: "task:one".to_owned(),
                prior_task_revision: 2,
                prior_work_revision: 1,
                artifact_set_id: "artifact-set:one".to_owned(),
                artifact_set_manifest: ReworkContentAddress {
                    algorithm: HashAlgorithm::Sha256 as i32,
                    digest: digest(),
                    byte_length: 128,
                },
                lineage: ReworkLineageBinding {
                    task_id: "task:one".to_owned(),
                    task_revision: 2,
                    work_revision: 1,
                    run_id: "run:one".to_owned(),
                    run_revision: 1,
                    step_id: "step:one".to_owned(),
                    step_revision: 1,
                    attempt_id: "attempt:one".to_owned(),
                    attempt_revision: 1,
                    dispatch_id: "dispatch:one".to_owned(),
                    fencing_token: 1,
                },
                baseline_artifact_id: "artifact:baseline".to_owned(),
                initial_manifest_artifact_id: "artifact:initial-manifest".to_owned(),
                repository_patch_artifact_id: "artifact:patch".to_owned(),
                repository_patch_sha256: digest(),
                final_manifest_artifact_id: "artifact:manifest".to_owned(),
                final_manifest_sha256: digest(),
                workspace_ref: "workspace:one".to_owned(),
                source_binding_ref: "source:one".to_owned(),
                frozen_material: FrozenRepositoryMaterialV1 {
                    schema_version: "egopulse.repository-material/v1".to_owned(),
                    contract_path: "C:/contract.json".to_owned(),
                    repository_root: "C:/repo".to_owned(),
                    git_executable: "C:/git.exe".to_owned(),
                    acceptance_contract_ref: FrozenContractReference {
                        contract_id: contract.contract_id.clone(),
                        version: contract.version.clone(),
                        sha256: contract.sha256.clone(),
                    },
                    acceptance_contract: RepositoryAcceptanceContractV1 {
                        schema_version: "repository_change_acceptance/v1".to_owned(),
                        contract_id: contract.contract_id,
                        version: contract.version,
                        revision: 1,
                        allowed_paths: Vec::new(),
                        forbidden_paths: Vec::new(),
                        read_only_paths: Vec::new(),
                        required_commands: Vec::new(),
                        evidence_requirements: Vec::new(),
                    },
                    baseline_commit: digest(),
                    baseline_tree: digest(),
                    git_common_dir: "C:/repo/.git".to_owned(),
                    clean_worktree: true,
                },
            },
        }
    }

    #[test]
    fn merged_rework_keeps_existing_compiler_fields_at_the_root() {
        let base = br#"{
            "prompt":"Repair the repository",
            "model":"gpt-test",
            "work_capability":{"choice_id":"codex"},
            "repository_material":{"schema_version":"egopulse.repository-material/v1"}
        }"#;
        let merged = merge_rework_followup(base, &sample_compiled()).expect("merged Context");
        let root: serde_json::Value = serde_json::from_slice(&merged).expect("JSON root");

        assert_eq!(root["model"], "gpt-test");
        assert_eq!(root["work_capability"]["choice_id"], "codex");
        assert_eq!(
            root["repository_material"]["schema_version"],
            "egopulse.repository-material/v1"
        );
        assert_eq!(
            root["rework_followup"]["required_changes_body"],
            "Update the exact failing check"
        );
    }

    #[test]
    fn rework_intent_keeps_required_changes_reviewable_without_controls() {
        let intent = rework_intent("Repair the repository", "Fix the test\nthen update scope")
            .expect("reviewable rework intent");
        assert_eq!(
            intent,
            "Repair the repository | Required changes: Fix the test then update scope"
        );
    }

    #[test]
    fn successive_rework_replaces_only_the_current_directive_and_preserves_baseline() {
        let base = br#"{"prompt":"Repair clamp","model":"gpt-test","repository_material":{"baseline_commit":"original"}}"#;
        let first = sample_compiled();
        let first_bytes = merge_rework_followup(base, &first).expect("first follow-up");
        let mut second = first.clone();
        second.task_revision += 5;
        second.prior_work_revision += 1;
        second.directive_id = "directive:second".to_owned();
        second.required_changes_body = "Keep the fix and explain the bounds".to_owned();
        second.repository_carry_forward.prior_work_revision += 1;
        second.repository_carry_forward.repository_patch_artifact_id =
            "artifact:second-patch".to_owned();
        let second_bytes = merge_rework_followup(&first_bytes, &second).expect("second follow-up");
        let root: serde_json::Value = serde_json::from_slice(&second_bytes).expect("JSON");
        assert_eq!(root["model"], "gpt-test");
        assert_eq!(root["repository_material"]["baseline_commit"], "original");
        assert_eq!(root["rework_original_prompt"], "Repair clamp");
        let prompt = root["prompt"].as_str().expect("native prompt");
        assert!(prompt.contains(&second.required_changes_body));
        assert!(!prompt.contains(&first.required_changes_body));
        assert_eq!(
            root["rework_followup"]["repository_carry_forward"]["repository_patch_artifact_id"],
            "artifact:second-patch"
        );
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&first_bytes).expect("first JSON");
        tampered["prompt"] = serde_json::Value::String("replaced native instructions".to_owned());
        assert!(
            merge_rework_followup(&serde_json::to_vec(&tampered).expect("JSON bytes"), &second)
                .is_err()
        );
        let mut skipped = second.clone();
        skipped.prior_work_revision += 1;
        assert!(merge_rework_followup(&first_bytes, &skipped).is_err());
        second.task_id = "task:unrelated".to_owned();
        assert!(merge_rework_followup(&first_bytes, &second).is_err());
    }

    #[test]
    fn framed_rework_idempotency_keys_do_not_collide_on_field_boundaries() {
        assert_ne!(
            framed_digest("rework", ["one\ntwo", "three"]),
            framed_digest("rework", ["one", "two\nthree"])
        );
    }

    #[test]
    fn sealed_carry_forward_serializes_complete_artifact_set_identity() {
        let compiled = sample_compiled();
        let expected_manifest = ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: digest(),
            byte_length: 128,
        };
        let expected_lineage = LineageBinding {
            task_id: "task:one".to_owned(),
            task_revision: 2,
            work_revision: 1,
            run_id: "run:one".to_owned(),
            run_revision: 1,
            step_id: "step:one".to_owned(),
            step_revision: 1,
            attempt_id: "attempt:one".to_owned(),
            attempt_revision: 1,
            dispatch_id: "dispatch:one".to_owned(),
            fencing_token: 1,
        };

        let encoded = serde_json::to_vec(&compiled).expect("serialized compiled Context");
        let restored: CompiledReworkContext =
            serde_json::from_slice(&encoded).expect("restored compiled Context");
        let carry = &restored.repository_carry_forward;

        assert_eq!(carry.artifact_set_id, "artifact-set:one");
        assert_eq!(carry.artifact_set_manifest.to_proto(), expected_manifest);
        assert_eq!(carry.lineage.to_proto(), expected_lineage);
        assert_eq!(carry.baseline_artifact_id, "artifact:baseline");
        assert_eq!(
            carry.initial_manifest_artifact_id,
            "artifact:initial-manifest"
        );
        assert!(valid_carry_forward(
            carry,
            &TaskSnapshot {
                task_id: "task:one".to_owned(),
                work_revision: 1,
                ..TaskSnapshot::default()
            }
        ));

        let mut incomplete = carry.clone();
        incomplete.lineage.dispatch_id.clear();
        assert!(!valid_carry_forward(
            &incomplete,
            &TaskSnapshot {
                task_id: "task:one".to_owned(),
                work_revision: 1,
                ..TaskSnapshot::default()
            }
        ));
    }

    #[test]
    fn recorded_revise_receipt_remains_exact_after_later_activation() {
        let frozen = sample_compiled();
        let snapshot = egopulse_cognition_runtime::context_authority::ContextSnapshot {
            snapshot_id: "ctx:rework".to_owned(),
            revision: 1,
            owner_principal_id: "founder:one".to_owned(),
            intent: "Repair the repository".to_owned(),
            intent_sha256: digest(),
            work_type: "governed_repository_change".to_owned(),
            target_scope_ref: "workspace:default".to_owned(),
            compiled_context_sha256: digest(),
            sources: Vec::new(),
            memory_pack: None,
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_tools: Vec::new(),
            external_resources: Vec::new(),
            non_goals: Vec::new(),
            acceptance_contract_ref: contract_key(
                &frozen.acceptance_contract_ref.to_contract_reference(),
            ),
            budget_profile_ref: frozen.budget_profile_ref.clone(),
            deadline_seconds: None,
            recovery_entry: "hold-and-reconcile".to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: Vec::new(),
            expires_at_seconds: 1,
            confirmation_binding_sha256: digest(),
        };
        let revised = TaskCommandResult {
            outcome: Some(task_command_result::Outcome::Task(TaskSnapshot {
                task_id: frozen.task_id.clone(),
                revision: frozen.task_revision + 1,
                work_revision: frozen.prior_work_revision + 1,
                status: TaskStatus::Ready as i32,
                input_snapshot_id: snapshot.snapshot_id.clone(),
                target_scope_ref: frozen.target_scope_ref.clone(),
                acceptance_contract_ref: Some(
                    frozen.acceptance_contract_ref.to_contract_reference(),
                ),
                ..TaskSnapshot::default()
            })),
            replayed: true,
            ..TaskCommandResult::default()
        };
        // This is the live state after the original activation has committed.
        // The replay check deliberately consumes the stored Revise receipt,
        // not this later mutable Task state.
        let later_active = TaskSnapshot {
            task_id: frozen.task_id.clone(),
            revision: frozen.task_revision + 2,
            work_revision: frozen.prior_work_revision + 1,
            status: TaskStatus::Active as i32,
            input_snapshot_id: snapshot.snapshot_id.clone(),
            target_scope_ref: frozen.target_scope_ref.clone(),
            acceptance_contract_ref: Some(frozen.acceptance_contract_ref.to_contract_reference()),
            current_run_id: Some("run:rework".to_owned()),
            ..TaskSnapshot::default()
        };

        assert_eq!(later_active.status, TaskStatus::Active as i32);
        assert!(validate_replayed_rework_revision(&revised, &snapshot, &frozen).is_ok());
    }
}
