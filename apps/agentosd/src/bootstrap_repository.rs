//! Optional production composition of the existing repository verification and
//! Founder material ports. No Authority store is opened here.
#[cfg(test)]
#[path = "bootstrap_repository_tests.rs"]
mod repository_tests;

use super::*;
use crate::artifact::DerivedWorkspaceAdmissionHandle;
use crate::founder_material::FounderSupportingMaterialPolicy;
use crate::verification_material::{
    RepositoryVerificationMaterialPolicy, RepositoryVerificationMaterialResolver,
};
use crate::verification_output::{VerificationOutputPolicy, VerificationResultArtifactIntake};
use crate::verification_profile::{
    RepositoryCheckerDeploymentConfig, RepositoryCheckerDeploymentPreparer,
    RepositoryCheckerProfileDeployment, RepositoryCheckerRole,
};
use crate::verification_repository::{
    RepositoryVerificationChecker, RepositoryVerificationCheckerConfig,
};
use crate::verification_repository_handoff::RepositoryVerificationHandoffPreparation;
use egopulse_codex_adapter::CodexAppServerConfig;
use egopulse_verification_authority::CriterionPolicySnapshot;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryVerificationConfig {
    scope: CheckerDeploymentFile,
    tests: CheckerDeploymentFile,
    review: CheckerDeploymentFile,
    deployment_artifact_type_ref: ReferenceFile,
    deployment_transformation_ref: ReferenceFile,
    retention_profile_ref: ReferenceFile,
    output: CheckerOutputFile,
    collector_principal_id: String,
    max_prompt_bytes: usize,
    max_output_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerDeploymentFile {
    checker_profile_id: String,
    input_contract_ref: ReferenceFile,
    output_contract_ref: ReferenceFile,
    sandbox_profile_ref: ReferenceFile,
    tool_policy_ref: ReferenceFile,
    data_egress_policy_ref: ReferenceFile,
    budget_profile_ref: ReferenceFile,
    timeout_ms: u64,
    model: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckerOutputFile {
    raw_output_type_ref: ReferenceFile,
    detail_type_ref: ReferenceFile,
    tool_receipt_type_ref: ReferenceFile,
    model_receipt_type_ref: ReferenceFile,
    cost_receipt_type_ref: ReferenceFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FounderSupportingMaterialConfig {
    artifact_type_ref: ReferenceFile,
    transformation_contract_ref: ReferenceFile,
    retention_profile_ref: ReferenceFile,
    collector_principal_id: String,
}

fn reference(file: &ReferenceFile) -> ContractReference {
    ContractReference {
        contract_id: file.contract_id.clone(),
        version: file.version.clone(),
        sha256: file.sha256.clone(),
    }
}

fn complete(file: &ReferenceFile) -> bool {
    !file.contract_id.trim().is_empty()
        && !file.version.trim().is_empty()
        && file.sha256.len() == 64
        && file
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid() -> ProductionBootstrapError {
    ProductionBootstrapError::InvalidConfiguration(
        "repository Verification deployment or Founder material policy",
    )
}

/// Repository claims have one D-02 semantic identity. A list membership check
/// alone cannot select a profile or bind the collector to the Task contract.
pub(super) fn validate_repository_claim_binding(
    artifact: &ConfiguredArtifactAdmissionGuardConfig,
    task_acceptance: &ContractReference,
    collector: &GovernedReturnCollectorConfig,
) -> Result<(), ProductionBootstrapError> {
    let semantic = &collector.claim_semantic_profile_ref;
    if semantic.contract_id != "repository_change_acceptance"
        || semantic.version != "v1"
        || !artifact
            .allowed_claim_semantic_profile_refs
            .contains(semantic)
        || collector.claim_acceptance_contract_ref != *task_acceptance
        || !artifact
            .allowed_claim_acceptance_contract_refs
            .contains(task_acceptance)
    {
        return Err(ProductionBootstrapError::InvalidConfiguration(
            "repository D-02 claim and Task acceptance binding",
        ));
    }
    Ok(())
}

impl CheckerDeploymentFile {
    fn valid(&self, role: RepositoryCheckerRole) -> bool {
        !self.checker_profile_id.trim().is_empty()
            && self.timeout_ms > 0
            && self.timeout_ms <= 30 * 60 * 1000
            && [
                &self.input_contract_ref,
                &self.output_contract_ref,
                &self.sandbox_profile_ref,
                &self.tool_policy_ref,
                &self.data_egress_policy_ref,
                &self.budget_profile_ref,
            ]
            .into_iter()
            .all(complete)
            && if role == RepositoryCheckerRole::Review {
                self.model
                    .as_ref()
                    .is_some_and(|model| !model.trim().is_empty())
            } else {
                self.model.is_none()
            }
    }

    fn deployment(&self, role: RepositoryCheckerRole) -> RepositoryCheckerProfileDeployment {
        RepositoryCheckerProfileDeployment {
            role,
            checker_profile_id: self.checker_profile_id.clone(),
            input_contract_ref: reference(&self.input_contract_ref),
            output_contract_ref: reference(&self.output_contract_ref),
            sandbox_profile_ref: reference(&self.sandbox_profile_ref),
            tool_policy_ref: reference(&self.tool_policy_ref),
            data_egress_policy_ref: reference(&self.data_egress_policy_ref),
            budget_profile_ref: reference(&self.budget_profile_ref),
            timeout_ms: self.timeout_ms,
            model: self.model.clone(),
        }
    }
}

impl RepositoryVerificationConfig {
    pub(super) fn validate_model(
        &self,
        provider: &ProviderBootstrapProfile,
    ) -> Result<(), ProductionBootstrapError> {
        if !self.review.model.as_ref().is_some_and(|model| {
            provider
                .models
                .iter()
                .any(|entry| entry.harness_model_id == *model)
        }) {
            return Err(ProductionBootstrapError::InvalidConfiguration(
                "repository review model must belong to the production Codex catalog",
            ));
        }
        Ok(())
    }

    pub(super) fn collector_principal_id(&self) -> &str {
        &self.collector_principal_id
    }

    pub(super) fn validate(
        &self,
        artifact: &ConfiguredArtifactAdmissionGuardConfig,
        criteria: &[CriterionPolicySnapshot],
    ) -> Result<(), ProductionBootstrapError> {
        use egopulse_domain_contracts::v01::egopulse::verification::v1::{
            CheckerAssuranceClass, CriterionRequirement,
        };
        if self.collector_principal_id.trim().is_empty()
            || self.max_prompt_bytes == 0
            || self.max_prompt_bytes > 16 * 1024 * 1024
            || self.max_output_bytes == 0
            || self.max_output_bytes > 16 * 1024 * 1024
            || !self.scope.valid(RepositoryCheckerRole::Scope)
            || !self.tests.valid(RepositoryCheckerRole::Tests)
            || !self.review.valid(RepositoryCheckerRole::Review)
            || [
                &self.scope.checker_profile_id,
                &self.tests.checker_profile_id,
                &self.review.checker_profile_id,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
                != 3
            || !complete(&self.deployment_transformation_ref)
            || !complete(&self.retention_profile_ref)
            || !artifact
                .allowed_retention_profile_refs
                .contains(&reference(&self.retention_profile_ref))
            || !artifact
                .allowed_transformation_contract_refs
                .contains(&reference(&self.deployment_transformation_ref))
        {
            return Err(invalid());
        }
        for file in [
            &self.deployment_artifact_type_ref,
            &self.output.raw_output_type_ref,
            &self.output.detail_type_ref,
            &self.output.tool_receipt_type_ref,
            &self.output.model_receipt_type_ref,
            &self.output.cost_receipt_type_ref,
        ] {
            if !complete(file)
                || !artifact
                    .allowed_artifact_type_refs
                    .contains(&reference(file))
            {
                return Err(invalid());
            }
        }
        for (id, deployment, assurance) in [
            ("scope", &self.scope, CheckerAssuranceClass::Deterministic),
            ("tests", &self.tests, CheckerAssuranceClass::Deterministic),
            ("review", &self.review, CheckerAssuranceClass::ModelAssisted),
        ] {
            if !artifact
                .allowed_transformation_contract_refs
                .contains(&reference(&deployment.output_contract_ref))
                || !criteria.iter().any(|criterion| {
                    criterion.criterion_id == id
                        && criterion.requirement == CriterionRequirement::MustPass as i32
                        && criterion.minimum_assurance == assurance as i32
                        && !criterion.not_applicable_allowed
                        && criterion
                            .checker_profile_ids
                            .contains(&deployment.checker_profile_id)
                })
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(super) fn compose(
        &self,
        owners: RepositoryVerificationOwners,
        native: &CodexHarnessCompositionConfig,
        commands: &RepositoryCommandArtifactPolicyConfig,
    ) -> Result<ConfiguredVerificationWorker, ProductionBootstrapError> {
        let RepositoryVerificationOwners {
            context,
            task,
            artifact,
            verification,
            admission,
        } = owners;
        let collector = &native.native.return_collector;
        if self.collector_principal_id == collector.artifact_authority_principal_id {
            return Err(invalid());
        }
        let material = Arc::new(
            RepositoryVerificationMaterialResolver::new(
                context,
                Arc::new(ArtifactAuthorityReferenceSource::new_shared(Arc::clone(
                    &artifact,
                ))),
                native.native.workspace_root.clone(),
                RepositoryVerificationMaterialPolicy {
                    repository_artifact_type_ref: collector.artifact_type_ref.clone(),
                    repository_transformation_ref: collector.transformation_contract_ref.clone(),
                    command_intent_type_ref: commands.intent_type_ref.clone(),
                    command_intent_transformation_ref: commands.intent_transformation_ref.clone(),
                    command_receipt_type_ref: commands.receipt_type_ref.clone(),
                    command_receipt_transformation_ref: commands.receipt_transformation_ref.clone(),
                    retention_profile_ref: collector.retention_profile_ref.clone(),
                    evidence_profile_ref: collector.evidence_profile_ref.clone(),
                    attempt_supervisor_principal_id: native
                        .native
                        .workflow
                        .attempt_supervisor_principal_id
                        .clone(),
                    supervised_runner_principal_id: native
                        .native
                        .workflow
                        .attempt_supervisor_principal_id
                        .clone(),
                    governed_collector_principal_id: collector.collector_principal_id.clone(),
                    repository_component_name: "agentosd-repository-dispatch".into(),
                    command_component_name: "agentosd-repository-command-runner".into(),
                },
            )
            .map_err(|_| invalid())?,
        );
        let profiles = Arc::new(
            RepositoryCheckerDeploymentPreparer::new(
                Arc::clone(&artifact),
                admission.clone(),
                Arc::clone(&verification),
                RepositoryCheckerDeploymentConfig {
                    scope: self.scope.deployment(RepositoryCheckerRole::Scope),
                    tests: self.tests.deployment(RepositoryCheckerRole::Tests),
                    review: self.review.deployment(RepositoryCheckerRole::Review),
                    attestation_type_ref: reference(&self.deployment_artifact_type_ref),
                    attestation_transformation_ref: reference(&self.deployment_transformation_ref),
                    retention_profile_ref: reference(&self.retention_profile_ref),
                    governed_collector_principal_id: self.collector_principal_id.clone(),
                    artifact_authority_principal_id: collector
                        .artifact_authority_principal_id
                        .clone(),
                    sensitivity_class: "local-user-data".into(),
                },
            )
            .map_err(|_| invalid())?,
        );
        let output = Arc::new(
            VerificationResultArtifactIntake::new(
                Arc::clone(&artifact),
                Arc::clone(&verification),
                admission,
                VerificationOutputPolicy {
                    raw_output_type_ref: reference(&self.output.raw_output_type_ref),
                    detail_type_ref: reference(&self.output.detail_type_ref),
                    tool_receipt_type_ref: reference(&self.output.tool_receipt_type_ref),
                    model_receipt_type_ref: reference(&self.output.model_receipt_type_ref),
                    cost_receipt_type_ref: reference(&self.output.cost_receipt_type_ref),
                    retention_profile_ref: reference(&self.retention_profile_ref),
                    collector_principal_id: self.collector_principal_id.clone(),
                    artifact_authority_principal_id: collector
                        .artifact_authority_principal_id
                        .clone(),
                    max_output_bytes: self.max_output_bytes,
                },
            )
            .map_err(|_| invalid())?,
        );
        let mut process = CodexAppServerConfig::new(native.codex_executable.clone());
        for (name, value) in &native.environment_overrides {
            process = process.with_environment_override(name.clone(), value.clone());
        }
        let checker = Arc::new(
            RepositoryVerificationChecker::new(
                Arc::clone(&material),
                output,
                RepositoryVerificationCheckerConfig {
                    codex: process,
                    model: self.review.model.clone().ok_or_else(invalid)?,
                    scope_profile_id: self.scope.checker_profile_id.clone(),
                    tests_profile_id: self.tests.checker_profile_id.clone(),
                    review_profile_id: self.review.checker_profile_id.clone(),
                    max_prompt_bytes: self.max_prompt_bytes,
                    max_output_bytes: self.max_output_bytes,
                    probe_profile_ref: native.native.workflow.capability_profile_ref.clone(),
                },
            )
            .map_err(ProductionBootstrapError::InvalidConfiguration)?,
        );
        ConfiguredVerificationWorker::new_prepared(
            task,
            Box::new(ArtifactAuthorityReferenceSource::new_shared(artifact)),
            verification,
            Arc::new(RepositoryVerificationHandoffPreparation::new(
                material,
                profiles,
                collector.claim_semantic_profile_ref.clone(),
            )),
            vec!["scope".into(), "tests".into(), "review".into()],
            vec![
                self.scope.checker_profile_id.clone(),
                self.tests.checker_profile_id.clone(),
                self.review.checker_profile_id.clone(),
            ],
            checker,
        )
        .map_err(ProductionBootstrapError::VerificationWorker)
    }
}

pub(super) struct RepositoryVerificationOwners {
    pub context: Arc<Mutex<ContextAuthority>>,
    pub task: Arc<Mutex<TaskAuthority>>,
    pub artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    pub verification: Arc<Mutex<VerificationAuthority>>,
    pub admission: DerivedWorkspaceAdmissionHandle,
}

impl FounderSupportingMaterialConfig {
    pub(super) fn validate(
        &self,
        artifact: &ConfiguredArtifactAdmissionGuardConfig,
    ) -> Result<(), ProductionBootstrapError> {
        if self.collector_principal_id.trim().is_empty()
            || [
                &self.artifact_type_ref,
                &self.transformation_contract_ref,
                &self.retention_profile_ref,
            ]
            .into_iter()
            .any(|file| !complete(file))
            || !artifact
                .allowed_artifact_type_refs
                .contains(&reference(&self.artifact_type_ref))
            || !artifact
                .allowed_transformation_contract_refs
                .contains(&reference(&self.transformation_contract_ref))
            || !artifact
                .allowed_retention_profile_refs
                .contains(&reference(&self.retention_profile_ref))
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn policy(
        &self,
        authority_id: &str,
    ) -> Result<FounderSupportingMaterialPolicy, ProductionBootstrapError> {
        FounderSupportingMaterialPolicy {
            type_contract_ref: reference(&self.artifact_type_ref),
            transformation_contract_ref: reference(&self.transformation_contract_ref),
            retention_profile_ref: reference(&self.retention_profile_ref),
            collector_principal_id: self.collector_principal_id.clone(),
            artifact_authority_principal_id: authority_id.to_owned(),
            component_name: "agentosd-founder-supporting-material".into(),
            component_version: env!("CARGO_PKG_VERSION").into(),
            sensitivity_class: "local-user-data".into(),
        }
        .validate()
        .map_err(|_| invalid())
    }
}
