use std::collections::BTreeSet;

use egopulse_cognition_runtime::context_authority::ContextAuthority;
use egopulse_cognition_runtime::task_authority::{
    CreationAuthorization, CreationGuardRejection, TaskCreationGuard, TaskTransitionGuard,
    TransitionAuthorization, TransitionGuardRejection,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    task::v1::{CreateTaskCommand, TaskCommand, TaskSnapshot, TaskStatus, task_command},
};
use egopulse_founder_verdict_authority::FounderVerdictAuthority;
use std::sync::{Arc, Mutex};
use thiserror::Error;

use crate::work_preparation::work_capability_route_from_compiled_context;

/// Reviewed creation policy for the first local vertical.
///
/// This guard proves that a create request belongs to an explicitly reviewed
/// input/scope/work profile. It does not inspect client identity and it does
/// not become a second Task store; the Task Authority remains the sole writer.
pub struct ConfiguredTaskCreationGuard {
    allowed_work_types: BTreeSet<String>,
    allowed_input_snapshot_ids: BTreeSet<String>,
    allowed_target_scope_refs: BTreeSet<String>,
    acceptance_contract_ref: ContractReference,
    budget_profile_ref: ContractReference,
    context_authority: Option<Arc<Mutex<ContextAuthority>>>,
}

impl ConfiguredTaskCreationGuard {
    pub fn new(
        config: ConfiguredTaskCreationGuardConfig,
    ) -> Result<Self, TaskCreationGuardConfigurationError> {
        if config.allowed_work_types.is_empty()
            || config.allowed_input_snapshot_ids.is_empty()
            || config.allowed_target_scope_refs.is_empty()
            || config
                .allowed_work_types
                .iter()
                .any(|value| value.trim().is_empty())
            || config
                .allowed_input_snapshot_ids
                .iter()
                .any(|value| value.trim().is_empty())
            || config
                .allowed_target_scope_refs
                .iter()
                .any(|value| value.trim().is_empty())
            || !contract_reference_is_complete(&config.acceptance_contract_ref)
            || !contract_reference_is_complete(&config.budget_profile_ref)
        {
            return Err(TaskCreationGuardConfigurationError::InvalidConfiguration);
        }
        Ok(Self {
            allowed_work_types: config.allowed_work_types,
            allowed_input_snapshot_ids: config.allowed_input_snapshot_ids,
            allowed_target_scope_refs: config.allowed_target_scope_refs,
            acceptance_contract_ref: config.acceptance_contract_ref,
            budget_profile_ref: config.budget_profile_ref,
            context_authority: None,
        })
    }

    #[must_use]
    pub fn with_context_authority(mut self, authority: Arc<Mutex<ContextAuthority>>) -> Self {
        self.context_authority = Some(authority);
        self
    }

    fn context_snapshot_matches(
        &self,
        authority: &Arc<Mutex<ContextAuthority>>,
        command: &CreateTaskCommand,
    ) -> bool {
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(value) => value.as_secs() as i64,
            Err(_) => return false,
        };
        let Ok(authority) = authority.lock() else {
            return false;
        };
        let Ok(resolved) =
            authority.resolve(&command.input_snapshot_id, &command.target_scope_ref, now)
        else {
            return false;
        };
        let snapshot = resolved.snapshot;
        let route_matches = work_capability_route_from_compiled_context(&resolved.compiled_context)
            .is_ok_and(|route| route.as_ref() == command.work_capability_route.as_ref());
        snapshot.work_type == command.work_type
            && snapshot.acceptance_contract_ref
                == contract_reference_key(&self.acceptance_contract_ref)
            && snapshot.budget_profile_ref == contract_reference_key(&self.budget_profile_ref)
            && route_matches
    }
}

#[derive(Clone)]
pub struct ConfiguredTaskCreationGuardConfig {
    pub allowed_work_types: BTreeSet<String>,
    pub allowed_input_snapshot_ids: BTreeSet<String>,
    pub allowed_target_scope_refs: BTreeSet<String>,
    pub acceptance_contract_ref: ContractReference,
    pub budget_profile_ref: ContractReference,
}

impl TaskCreationGuard for ConfiguredTaskCreationGuard {
    fn validate(
        &self,
        command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        if command.work_type.trim().is_empty()
            || command.input_snapshot_id.trim().is_empty()
            || command.target_scope_ref.trim().is_empty()
        {
            return Err(CreationGuardRejection::InvalidArgument);
        }
        let snapshot_is_reviewed = (command.work_capability_route.is_none()
            && self
                .allowed_input_snapshot_ids
                .contains(&command.input_snapshot_id))
            || (command.input_snapshot_id.starts_with("ctx:")
                && self
                    .context_authority
                    .as_ref()
                    .is_some_and(|authority| self.context_snapshot_matches(authority, command)));
        if !self.allowed_work_types.contains(&command.work_type)
            || !snapshot_is_reviewed
            || !self
                .allowed_target_scope_refs
                .contains(&command.target_scope_ref)
        {
            return Err(CreationGuardRejection::UnverifiedReference);
        }
        if command.acceptance_contract_ref.as_ref() != Some(&self.acceptance_contract_ref)
            || command.budget_profile_ref.as_ref() != Some(&self.budget_profile_ref)
        {
            return Err(CreationGuardRejection::ContractMismatch);
        }
        Ok(CreationAuthorization {
            evidence_refs: vec![
                format!("input-snapshot:{}@reviewed", command.input_snapshot_id),
                format!("target-scope:{}@reviewed", command.target_scope_ref),
                format!(
                    "acceptance-contract:{}@frozen",
                    self.acceptance_contract_ref.contract_id
                ),
                format!(
                    "budget-profile:{}@frozen",
                    self.budget_profile_ref.contract_id
                ),
            ],
        })
    }
}

/// Shared late-bound Founder Verdict handle used only by the composition root
/// while the Task and Verdict Authorities are being assembled. Once bootstrap
/// completes, it contains exactly one Verdict Authority instance; an empty
/// handle remains fail-closed.
pub type SharedFounderVerdictAuthority = Arc<Mutex<Option<FounderVerdictAuthority>>>;

/// Production transition guard for the Task handoff path.
///
/// Collaboration submits Artifact/ReturnHandoff references, and the
/// Verification worker submits a Verification artifact reference after its
/// own cross-authority proof. Founder Verdict transitions remain denied until
/// Founder Verdict application is accepted only when the exact issued
/// verdict is read from the owning Verdict Authority and its scope is bound
/// to the current Task snapshot. The guard returns the decision and state
/// revision needed by Task Authority to create the durable cross-authority
/// consume outbox; it never writes Verdict state.
#[derive(Clone, Default)]
pub struct ConfiguredTaskTransitionGuard {
    founder_verdict: Option<SharedFounderVerdictAuthority>,
    context_authority: Option<Arc<Mutex<ContextAuthority>>>,
}

impl ConfiguredTaskTransitionGuard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            founder_verdict: None,
            context_authority: None,
        }
    }

    #[must_use]
    pub fn with_founder_verdict(founder_verdict: SharedFounderVerdictAuthority) -> Self {
        Self {
            founder_verdict: Some(founder_verdict),
            context_authority: None,
        }
    }

    #[must_use]
    pub fn with_context_authority(mut self, authority: Arc<Mutex<ContextAuthority>>) -> Self {
        self.context_authority = Some(authority);
        self
    }

    fn activation_context_evidence(
        &self,
        current: &TaskSnapshot,
    ) -> Result<Option<String>, TransitionGuardRejection> {
        if !current.input_snapshot_id.starts_with("ctx:") {
            return Ok(None);
        }
        let authority = self
            .context_authority
            .as_ref()
            .ok_or(TransitionGuardRejection::UnverifiedReference)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
        let authority = authority
            .lock()
            .map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
        let resolved = authority
            .resolve(&current.input_snapshot_id, &current.target_scope_ref, now)
            .map_err(context_transition_rejection)?;
        if resolved.snapshot.snapshot_id != current.input_snapshot_id
            || resolved.snapshot.target_scope_ref != current.target_scope_ref
        {
            return Err(TransitionGuardRejection::IntegrityFailure);
        }
        Ok(Some(format!(
            "context-snapshot:{}@revision:{}",
            resolved.snapshot.snapshot_id, resolved.snapshot.revision
        )))
    }
}

impl TaskTransitionGuard for ConfiguredTaskTransitionGuard {
    fn validate(
        &self,
        command: &TaskCommand,
        current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        match command.command.as_ref() {
            Some(task_command::Command::ActivateTask(value))
                if current.status == TaskStatus::Ready as i32
                    && value.work_revision == current.work_revision
                    && !value.run_id.trim().is_empty() =>
            {
                let mut evidence_refs = vec![format!(
                    "task-activation:{}@collaboration-control",
                    value.run_id
                )];
                if let Some(context_evidence) = self.activation_context_evidence(current)? {
                    evidence_refs.push(context_evidence);
                }
                Ok(TransitionAuthorization {
                    evidence_refs,
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::SubmitTaskEvidence(value))
                if current.status == TaskStatus::Active as i32
                    && value.work_revision == current.work_revision
                    && !value.return_handoff_id.trim().is_empty()
                    && !value.artifact_set_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![
                        format!(
                            "return-handoff:{}@artifact-authority-intake",
                            value.return_handoff_id
                        ),
                        format!(
                            "artifact-set:{}@artifact-authority-intake",
                            value.artifact_set_id
                        ),
                    ],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::RecordTaskVerification(value))
                if current.status == TaskStatus::VerificationPending as i32
                    && value.work_revision == current.work_revision
                    && !value.verification_artifact_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "verification-artifact:{}@verification-authority",
                        value.verification_artifact_id
                    )],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::RequestTaskCancellation(value))
                if (current.status == TaskStatus::Ready as i32
                    || current.status == TaskStatus::Active as i32)
                    && value.task_id == current.task_id
                    && value.expected_revision == current.revision
                    && !value.reason_code.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "task-cancellation-request:{}@founder",
                        value.reason_code
                    )],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::InterruptTask(value))
                if current.status == TaskStatus::Active as i32
                    && value.task_id == current.task_id
                    && value.expected_revision == current.revision
                    && !value.interruption_evidence_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "task-interruption:{}@collaboration-control",
                        value.interruption_evidence_id
                    )],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::HoldTask(value))
                if current.status == TaskStatus::Active as i32
                    && value.task_id == current.task_id
                    && value.expected_revision == current.revision
                    && !value.hold_reason_code.trim().is_empty()
                    && !value.recovery_evidence_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![
                        format!("task-hold:{}@collaboration-control", value.hold_reason_code),
                        format!(
                            "task-hold-recovery:{}@collaboration-control",
                            value.recovery_evidence_id
                        ),
                    ],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::ResumeTask(value))
                if (current.status == TaskStatus::Interrupted as i32
                    || current.status == TaskStatus::Held as i32)
                    && value.task_id == current.task_id
                    && value.expected_revision == current.revision
                    && value.expected_resume_status == TaskStatus::Active as i32
                    && !value.recovery_evidence_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "task-resume-recovery:{}@collaboration-control",
                        value.recovery_evidence_id
                    )],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::RecordTaskCancellationOutcome(value))
                if current.status == TaskStatus::CancellationPending as i32
                    && value.task_id == current.task_id
                    && value.expected_revision == current.revision
                    && matches!(
                        TaskStatus::try_from(value.outcome),
                        Ok(TaskStatus::Cancelled | TaskStatus::Interrupted)
                    )
                    && !value.cancellation_receipt_id.trim().is_empty() =>
            {
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "task-cancellation-outcome:{}@collaboration-control",
                        value.cancellation_receipt_id
                    )],
                    founder_decision: None,
                    founder_verdict_state_revision: None,
                })
            }
            Some(task_command::Command::ApplyFounderVerdict(value)) => {
                let Some(founder_verdict) = self.founder_verdict.as_ref() else {
                    return Err(TransitionGuardRejection::UnverifiedReference);
                };
                if current.status != TaskStatus::VerdictPending as i32
                    || value.task_id != current.task_id
                    || value.expected_revision != current.revision
                    || value.work_revision != current.work_revision
                    || value.founder_verdict_id.trim().is_empty()
                    || current.artifact_set_id.is_none()
                    || current.verification_artifact_id.is_none()
                {
                    return Err(TransitionGuardRejection::StateConflict);
                }
                let authority = founder_verdict
                    .lock()
                    .map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
                let Some(authority) = authority.as_ref() else {
                    return Err(TransitionGuardRejection::UnverifiedReference);
                };
                let Some((verdict, state)) = authority
                    .get_for_task_application(&value.founder_verdict_id)
                    .map_err(|_| TransitionGuardRejection::IntegrityFailure)?
                else {
                    return Err(TransitionGuardRejection::StaleReference);
                };
                if state.state
                    != egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictStateKind::Issued
                        as i32
                    || state.revision == 0
                    || state.founder_verdict_id != value.founder_verdict_id
                {
                    return Err(TransitionGuardRejection::StaleReference);
                }
                let Some(scope) = verdict.scope.as_ref() else {
                    return Err(TransitionGuardRejection::IntegrityFailure);
                };
                if scope.task_id != current.task_id
                    || scope.task_revision != current.revision
                    || scope.work_revision != current.work_revision
                    || scope.artifact_set_id
                        != current.artifact_set_id.as_deref().unwrap_or_default()
                    || scope.verification_artifact_id
                        != current
                            .verification_artifact_id
                            .as_deref()
                            .unwrap_or_default()
                    || scope.acceptance_contract_ref.as_ref()
                        != current.acceptance_contract_ref.as_ref()
                {
                    return Err(TransitionGuardRejection::StaleReference);
                }
                let decision = egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictDecision::try_from(verdict.decision)
                    .map_err(|_| TransitionGuardRejection::IntegrityFailure)?;
                let founder_decision = match decision {
                    egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictDecision::Accept => {
                        egopulse_domain_contracts::v01::egopulse::task::v1::FounderDecision::Accept
                    }
                    egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictDecision::Rework => {
                        egopulse_domain_contracts::v01::egopulse::task::v1::FounderDecision::Rework
                    }
                    egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictDecision::Reject => {
                        egopulse_domain_contracts::v01::egopulse::task::v1::FounderDecision::Reject
                    }
                    egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictDecision::Unspecified => {
                        return Err(TransitionGuardRejection::TerminalGateUnsatisfied);
                    }
                };
                Ok(TransitionAuthorization {
                    evidence_refs: vec![
                        format!("founder-verdict:{}@issued", value.founder_verdict_id),
                        format!(
                            "founder-verdict-state:{}@{}",
                            value.founder_verdict_id, state.revision
                        ),
                    ],
                    founder_decision: Some(founder_decision),
                    founder_verdict_state_revision: Some(state.revision),
                })
            }
            _ => Err(TransitionGuardRejection::UnverifiedReference),
        }
    }
}

fn context_transition_rejection(
    error: egopulse_cognition_runtime::context_authority::ContextAuthorityFailure,
) -> TransitionGuardRejection {
    use egopulse_cognition_runtime::context_authority::ContextAuthorityFailure;

    match error {
        ContextAuthorityFailure::NotFound
        | ContextAuthorityFailure::Expired
        | ContextAuthorityFailure::Revoked
        | ContextAuthorityFailure::ScopeMismatch => TransitionGuardRejection::StaleReference,
        ContextAuthorityFailure::Storage
        | ContextAuthorityFailure::IntegrityFailure
        | ContextAuthorityFailure::InvalidArgument(_)
        | ContextAuthorityFailure::Unauthorized
        | ContextAuthorityFailure::OwnerMismatch
        | ContextAuthorityFailure::IdempotencyConflict
        | ContextAuthorityFailure::StateRevisionConflict
        | ContextAuthorityFailure::AuthorizationTupleConflict
        | ContextAuthorityFailure::Clock => TransitionGuardRejection::IntegrityFailure,
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TaskCreationGuardConfigurationError {
    #[error("configured Task creation guard is invalid")]
    InvalidConfiguration,
}

fn contract_reference_is_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && hex::decode(&reference.sha256)
            .map(|bytes| bytes.len() == 32)
            .unwrap_or(false)
}

fn contract_reference_key(reference: &ContractReference) -> String {
    format!(
        "{}@{}#{}",
        reference.contract_id, reference.version, reference.sha256
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_cognition_runtime::context_authority::{
        AuthenticatedContextPrincipal, ContextAuthorityConfig, ContextPrincipalKind,
        ContextRedaction, ContextRevokeRequest, ContextSourceFact, IssueContextSnapshot,
    };
    use egopulse_cognition_runtime::task_authority::{
        AuthenticatedPrincipal, PrincipalKind, SqlCipherKey as TaskSqlCipherKey, TaskAuthority,
        TaskAuthorityConfig, canonical_request_digest,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        common::v1::{CommandMetadata, ContractReference},
        task::v1::{
            ActivateTaskCommand, RecordTaskVerificationCommand, SubmitTaskEvidenceCommand,
            TaskErrorCode, get_task_response, task_command_result,
        },
    };
    use egopulse_domain_contracts::work_capability::seal_work_capability_route_binding;
    use prost_types::Timestamp;
    use std::fs;
    use uuid::Uuid;

    fn contract(id: &str, version: &str, byte: u8) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: version.to_owned(),
            sha256: hex::encode([byte; 32]),
        }
    }

    fn config() -> ConfiguredTaskCreationGuardConfig {
        ConfiguredTaskCreationGuardConfig {
            allowed_work_types: BTreeSet::from(["governed_repository_change".to_owned()]),
            allowed_input_snapshot_ids: BTreeSet::from(["input-001".to_owned()]),
            allowed_target_scope_refs: BTreeSet::from(["repo-scope-001".to_owned()]),
            acceptance_contract_ref: contract("repository-change", "v1", 0x11),
            budget_profile_ref: contract("v01-quality-budget", "v1", 0x22),
        }
    }

    fn command() -> CreateTaskCommand {
        CreateTaskCommand {
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: "input-001".to_owned(),
            target_scope_ref: "repo-scope-001".to_owned(),
            acceptance_contract_ref: Some(contract("repository-change", "v1", 0x11)),
            budget_profile_ref: Some(contract("v01-quality-budget", "v1", 0x22)),
            ..Default::default()
        }
    }

    fn task_metadata(command_id: &str) -> CommandMetadata {
        CommandMetadata {
            command_id: command_id.to_owned(),
            idempotency_key: command_id.to_owned(),
            idempotency_scope: "r9a3a-task-test".to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(Timestamp {
                seconds: 1_777_073_600,
                nanos: 0,
            }),
            correlation_id: format!("correlation:{command_id}"),
            causation_id: None,
        }
    }

    fn seal_task_command(command: &mut TaskCommand) {
        let digest = canonical_request_digest(command).expect("canonical Task command digest");
        match command.command.as_mut().expect("Task command") {
            task_command::Command::CreateTask(value) => {
                value
                    .meta
                    .as_mut()
                    .expect("create metadata")
                    .request_digest_sha256 = digest;
            }
            task_command::Command::ActivateTask(value) => {
                value
                    .meta
                    .as_mut()
                    .expect("activate metadata")
                    .request_digest_sha256 = digest;
            }
            _ => panic!("test helper only seals create and activate"),
        }
    }

    fn guarded_work_capability_route()
    -> egopulse_domain_contracts::v01::egopulse::task::v1::WorkCapabilityRouteBinding {
        seal_work_capability_route_binding(
            egopulse_domain_contracts::v01::egopulse::task::v1::WorkCapabilityRouteBinding {
                route_id: "route:task-guard:v1".to_owned(),
                route_generation: 1,
                provider_profile_id: "provider-profile:task-guard".to_owned(),
                provider_id: "gpt".to_owned(),
                harness_id: "codex_app_server".to_owned(),
                harness_model_id: "guarded-model".to_owned(),
                provider_model_id: "provider-guarded-model".to_owned(),
                capability_profile_ref: Some(contract("capability", "v1", 0x33)),
                catalog_snapshot_sha256: Some(hex::encode([0x44; 32])),
                native_composition_generation: "native:task-guard:v1".to_owned(),
                route_binding_sha256: String::new(),
            },
        )
        .expect("sealed task-guard route")
    }

    fn compiled_route_context(
        route: &egopulse_domain_contracts::v01::egopulse::task::v1::WorkCapabilityRouteBinding,
    ) -> Vec<u8> {
        let profile = route
            .capability_profile_ref
            .as_ref()
            .expect("route capability profile");
        serde_json::to_vec(&serde_json::json!({
            "model": route.harness_model_id,
            "work_capability": {
                "choice_id": "choice:task-guard",
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
        .expect("compiled task-guard context")
    }

    #[test]
    fn reviewed_configuration_authorizes_exact_create_request() {
        let guard = ConfiguredTaskCreationGuard::new(config()).expect("valid guard");
        let authorization = guard.validate(&command()).expect("reviewed request");
        assert_eq!(authorization.evidence_refs.len(), 4);
    }

    #[test]
    fn unknown_snapshot_or_scope_is_not_verified() {
        let guard = ConfiguredTaskCreationGuard::new(config()).expect("valid guard");
        let mut request = command();
        request.input_snapshot_id = "input-unknown".to_owned();
        assert_eq!(
            guard.validate(&request),
            Err(CreationGuardRejection::UnverifiedReference)
        );
    }

    #[test]
    fn contract_drift_is_rejected() {
        let guard = ConfiguredTaskCreationGuard::new(config()).expect("valid guard");
        let mut request = command();
        request.budget_profile_ref = Some(contract("v02-quality-budget", "v2", 0x33));
        assert_eq!(
            guard.validate(&request),
            Err(CreationGuardRejection::ContractMismatch)
        );
    }

    #[test]
    fn malformed_reviewed_configuration_fails_at_construction() {
        let mut invalid = config();
        invalid.acceptance_contract_ref.sha256 = "not-a-digest".to_owned();
        assert!(matches!(
            ConfiguredTaskCreationGuard::new(invalid),
            Err(TaskCreationGuardConfigurationError::InvalidConfiguration)
        ));
    }

    #[test]
    fn production_transition_guard_accepts_only_reviewed_non_terminal_handoffs() {
        let guard = ConfiguredTaskTransitionGuard::new();
        let active = TaskSnapshot {
            task_id: "task-1".to_owned(),
            revision: 2,
            work_revision: 1,
            status: TaskStatus::Active as i32,
            ..TaskSnapshot::default()
        };
        let submit = TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    task_id: "task-1".to_owned(),
                    work_revision: 1,
                    return_handoff_id: "handoff-1".to_owned(),
                    artifact_set_id: "set-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        assert!(guard.validate(&submit, &active).is_ok());

        let verification_pending = TaskSnapshot {
            status: TaskStatus::VerificationPending as i32,
            ..active.clone()
        };
        let record = TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    task_id: "task-1".to_owned(),
                    work_revision: 1,
                    verification_artifact_id: "verification-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        assert!(guard.validate(&record, &verification_pending).is_ok());

        let denied = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                task_id: "task-1".to_owned(),
                work_revision: 1,
                run_id: "run-1".to_owned(),
                ..Default::default()
            })),
        };
        assert_eq!(
            guard.validate(&denied, &active),
            Err(TransitionGuardRejection::UnverifiedReference)
        );
    }

    #[test]
    fn task_creation_guard_requires_the_exact_context_bound_work_capability_route() {
        let root =
            std::env::temp_dir().join(format!("egopulse-task-route-guard-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("task route guard root");
        let acceptance = contract("repository-change", "v1", 0x11);
        let budget = contract("quality-budget", "v1", 0x22);
        let route = guarded_work_capability_route();
        let context = Arc::new(Mutex::new(
            ContextAuthority::open(ContextAuthorityConfig {
                database_path: root.join("context.db"),
                store_epoch: "task-route-guard-context".to_owned(),
                key: TaskSqlCipherKey::new([43; 32]),
            })
            .expect("Context Authority"),
        ));
        let expires_at_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            .saturating_add(600) as i64;
        let (_, snapshot) = context
            .lock()
            .expect("Context lock")
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: "founder:route-guard".to_owned(),
                    intent: "create an exact-route task".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:route-guard".to_owned(),
                    compiled_context: compiled_route_context(&route),
                    sources: vec![ContextSourceFact {
                        source_ref: "source:route-guard".to_owned(),
                        label: "route guard".to_owned(),
                        authority: "project".to_owned(),
                        content_sha256: "a".repeat(64),
                        included: true,
                    }],
                    memory_pack: None,
                    allowed_read_paths: vec!["src".to_owned()],
                    allowed_write_paths: vec!["src".to_owned()],
                    allowed_tools: Vec::new(),
                    external_resources: Vec::new(),
                    non_goals: Vec::new(),
                    acceptance_contract_ref: contract_reference_key(&acceptance),
                    budget_profile_ref: contract_reference_key(&budget),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: Vec::new(),
                    expires_at_seconds,
                    idempotency_key: "task-route-guard-context".to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:route-guard".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue route-bound Context");
        let guard = ConfiguredTaskCreationGuard::new(ConfiguredTaskCreationGuardConfig {
            allowed_work_types: BTreeSet::from(["governed_repository_change".to_owned()]),
            allowed_input_snapshot_ids: BTreeSet::from(["static-reviewed".to_owned()]),
            allowed_target_scope_refs: BTreeSet::from(["scope:route-guard".to_owned()]),
            acceptance_contract_ref: acceptance.clone(),
            budget_profile_ref: budget.clone(),
        })
        .expect("creation guard")
        .with_context_authority(Arc::clone(&context));
        let base = CreateTaskCommand {
            work_type: "governed_repository_change".to_owned(),
            input_snapshot_id: snapshot.snapshot_id,
            target_scope_ref: "scope:route-guard".to_owned(),
            acceptance_contract_ref: Some(acceptance),
            budget_profile_ref: Some(budget),
            work_capability_route: Some(route.clone()),
            ..Default::default()
        };
        assert!(guard.validate(&base).is_ok());

        let mut stripped = base.clone();
        stripped.work_capability_route = None;
        assert_eq!(
            guard.validate(&stripped),
            Err(CreationGuardRejection::UnverifiedReference)
        );

        let mut static_with_route = base.clone();
        static_with_route.input_snapshot_id = "static-reviewed".to_owned();
        assert_eq!(
            guard.validate(&static_with_route),
            Err(CreationGuardRejection::UnverifiedReference)
        );
        static_with_route.work_capability_route = None;
        assert!(guard.validate(&static_with_route).is_ok());

        type Route = egopulse_domain_contracts::v01::egopulse::task::v1::WorkCapabilityRouteBinding;
        type Mutator = fn(&mut Route);
        let mutations: [Mutator; 13] = [
            |value| value.route_id.push_str(":drift"),
            |value| value.route_generation += 1,
            |value| value.provider_profile_id.push_str(":drift"),
            |value| value.provider_id.push_str(":drift"),
            |value| value.harness_id.push_str(":drift"),
            |value| value.harness_model_id.push_str(":drift"),
            |value| value.provider_model_id.push_str(":drift"),
            |value| {
                value
                    .capability_profile_ref
                    .as_mut()
                    .expect("profile")
                    .contract_id
                    .push_str(":drift")
            },
            |value| {
                value
                    .capability_profile_ref
                    .as_mut()
                    .expect("profile")
                    .version
                    .push_str(":drift")
            },
            |value| {
                value
                    .capability_profile_ref
                    .as_mut()
                    .expect("profile")
                    .sha256 = hex::encode([0x55; 32])
            },
            |value| value.catalog_snapshot_sha256 = None,
            |value| value.native_composition_generation.push_str(":drift"),
            |value| value.catalog_snapshot_sha256 = Some(hex::encode([0x66; 32])),
        ];
        for mutate in mutations {
            let mut drifted_route = route.clone();
            drifted_route.route_binding_sha256.clear();
            mutate(&mut drifted_route);
            let drifted_route =
                seal_work_capability_route_binding(drifted_route).expect("seal drifted route");
            let mut command = base.clone();
            command.work_capability_route = Some(drifted_route);
            assert_eq!(
                guard.validate(&command),
                Err(CreationGuardRejection::UnverifiedReference)
            );
        }

        drop(guard);
        drop(context);
        fs::remove_dir_all(root).expect("remove task route guard root");
    }

    #[test]
    fn revoked_context_blocks_activation_without_task_writes_and_static_paths_remain_compatible() {
        let root = std::env::temp_dir().join(format!("egopulse-r9a3a-task-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("R9A.3a test root");
        let acceptance = contract("repository-change", "v1", 0x11);
        let budget = contract("quality-budget", "v1", 0x22);
        let context = Arc::new(Mutex::new(
            ContextAuthority::open(ContextAuthorityConfig {
                database_path: root.join("context.db"),
                store_epoch: "r9a3a-context".to_owned(),
                key: TaskSqlCipherKey::new([41; 32]),
            })
            .expect("Context Authority"),
        ));
        let expires_at_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            .saturating_add(600) as i64;
        let (_, snapshot) = context
            .lock()
            .expect("Context lock")
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: "founder:r9a3a".to_owned(),
                    intent: "activate governed work".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:r9a3a".to_owned(),
                    compiled_context: br#"{"prompt":"r9a3a"}"#.to_vec(),
                    sources: vec![ContextSourceFact {
                        source_ref: "source:r9a3a".to_owned(),
                        label: "R9A.3a".to_owned(),
                        authority: "project".to_owned(),
                        content_sha256: "a".repeat(64),
                        included: true,
                    }],
                    memory_pack: None,
                    allowed_read_paths: vec!["src".to_owned()],
                    allowed_write_paths: vec!["src".to_owned()],
                    allowed_tools: vec!["cargo".to_owned()],
                    external_resources: Vec::new(),
                    non_goals: vec!["no dispatch".to_owned()],
                    acceptance_contract_ref: contract_reference_key(&acceptance),
                    budget_profile_ref: contract_reference_key(&budget),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: vec![ContextRedaction {
                        field_path: "credentials".to_owned(),
                        reason_code: "secret".to_owned(),
                    }],
                    expires_at_seconds,
                    idempotency_key: "r9a3a-issue".to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:r9a3a".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue Context snapshot");

        let creation_guard = ConfiguredTaskCreationGuard::new(ConfiguredTaskCreationGuardConfig {
            allowed_work_types: BTreeSet::from(["governed_repository_change".to_owned()]),
            allowed_input_snapshot_ids: BTreeSet::from(["static-reviewed".to_owned()]),
            allowed_target_scope_refs: BTreeSet::from(["scope:r9a3a".to_owned()]),
            acceptance_contract_ref: acceptance.clone(),
            budget_profile_ref: budget.clone(),
        })
        .expect("creation guard")
        .with_context_authority(Arc::clone(&context));
        let transition_guard =
            ConfiguredTaskTransitionGuard::new().with_context_authority(Arc::clone(&context));
        let mut task = TaskAuthority::open_with_transition_guard(
            TaskAuthorityConfig {
                database_path: root.join("task.db"),
                store_epoch: "r9a3a-task".to_owned(),
                key: TaskSqlCipherKey::new([42; 32]),
            },
            creation_guard,
            transition_guard,
        )
        .expect("Task Authority");
        let founder = AuthenticatedPrincipal {
            kind: PrincipalKind::Founder,
            principal_id: "founder:r9a3a".to_owned(),
            authenticated: true,
        };
        let mut create = TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(task_metadata("r9a3a-create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: snapshot.snapshot_id.clone(),
                target_scope_ref: snapshot.target_scope_ref.clone(),
                acceptance_contract_ref: Some(acceptance),
                budget_profile_ref: Some(budget),
                work_capability_route: None,
            })),
        };
        seal_task_command(&mut create);
        let created = task.execute(&create, &founder).expect("create Task");
        let created = match created.outcome.expect("create outcome") {
            task_command_result::Outcome::Task(value) => value,
            other => panic!("unexpected create outcome: {other:?}"),
        };
        let before_rejected_activation = task.inspect_store().expect("Task inspection");

        context
            .lock()
            .expect("Context lock")
            .revoke(
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::Founder,
                    principal_id: "founder:r9a3a".to_owned(),
                    authenticated: true,
                },
                &ContextRevokeRequest {
                    command_id: "r9a3a-revoke-command".to_owned(),
                    snapshot_id: snapshot.snapshot_id.clone(),
                    expected_state_revision: 1,
                    reason_code: "withdrawn".to_owned(),
                    evidence_refs: vec!["evidence:r9a3a".to_owned()],
                    confirmation_proof_ref: "proof:r9a3a".to_owned(),
                    idempotency_key: "r9a3a-revoke".to_owned(),
                    correlation_id: "correlation:r9a3a-revoke".to_owned(),
                    causation_id: None,
                },
            )
            .expect("revoke Context snapshot");
        let mut activate = TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(task_metadata("r9a3a-activate")),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run:r9a3a".to_owned(),
            })),
        };
        seal_task_command(&mut activate);
        assert_eq!(
            ConfiguredTaskTransitionGuard::new().validate(&activate, &created),
            Err(TransitionGuardRejection::UnverifiedReference)
        );
        let result = task
            .execute(
                &activate,
                &AuthenticatedPrincipal {
                    kind: PrincipalKind::CollaborationControl,
                    principal_id: "collaboration:r9a3a".to_owned(),
                    authenticated: true,
                },
            )
            .expect("rejected activation result");
        match result.outcome.expect("activation outcome") {
            task_command_result::Outcome::Error(error) => {
                assert_eq!(error.code, TaskErrorCode::StaleReference as i32);
            }
            other => panic!("revoked Context activated Task: {other:?}"),
        }
        assert_eq!(
            task.inspect_store()
                .expect("Task inspection after rejected activation"),
            before_rejected_activation
        );
        let persisted = task
            .get_task(&created.task_id)
            .expect("read Task after rejected activation");
        let persisted = match persisted.outcome.expect("get Task outcome") {
            get_task_response::Outcome::Task(value) => value,
            other => panic!("Task missing after rejected activation: {other:?}"),
        };
        assert_eq!(persisted, created);

        let static_ready = TaskSnapshot {
            input_snapshot_id: "static-reviewed".to_owned(),
            target_scope_ref: "scope:r9a3a".to_owned(),
            status: TaskStatus::Ready as i32,
            work_revision: 1,
            ..TaskSnapshot::default()
        };
        assert!(
            ConfiguredTaskTransitionGuard::new()
                .validate(&activate, &static_ready)
                .is_ok()
        );

        drop(task);
        drop(context);
        fs::remove_dir_all(root).expect("remove R9A.3a test root");
    }
}
