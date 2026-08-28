use std::collections::BTreeSet;

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
        })
    }
}

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
        if !self.allowed_work_types.contains(&command.work_type)
            || !self
                .allowed_input_snapshot_ids
                .contains(&command.input_snapshot_id)
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
}

impl ConfiguredTaskTransitionGuard {
    #[must_use]
    pub fn new() -> Self {
        Self {
            founder_verdict: None,
        }
    }

    #[must_use]
    pub fn with_founder_verdict(founder_verdict: SharedFounderVerdictAuthority) -> Self {
        Self {
            founder_verdict: Some(founder_verdict),
        }
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
                Ok(TransitionAuthorization {
                    evidence_refs: vec![format!(
                        "task-activation:{}@collaboration-control",
                        value.run_id
                    )],
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
                    && value.outcome == TaskStatus::Cancelled as i32
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
                    .get(&value.founder_verdict_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        common::v1::ContractReference,
        task::v1::{ActivateTaskCommand, RecordTaskVerificationCommand, SubmitTaskEvidenceCommand},
    };

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
}
