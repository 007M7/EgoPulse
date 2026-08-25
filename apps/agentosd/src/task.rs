use std::collections::BTreeSet;

use egopulse_cognition_runtime::task_authority::{
    CreationAuthorization, CreationGuardRejection, TaskCreationGuard,
};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference, task::v1::CreateTaskCommand,
};
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
    use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;

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
}
