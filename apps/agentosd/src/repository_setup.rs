//! Prepare a separate, reviewable repository configuration using the same
//! acceptance parser as Task freeze. This path never opens Authority stores.
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::repository_material::RepositoryMaterialConfig;

const PROFILES: &str = include_str!("../../../config/repository-profiles.v1.json");

#[cfg(test)]
#[path = "repository_setup_tests.rs"]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositorySetupRequest {
    config_path: PathBuf,
    candidate_path: PathBuf,
    repository_root: PathBuf,
    acceptance_contract_path: PathBuf,
    git_executable: PathBuf,
    review_model: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RepositorySetupReport {
    pub candidate_config_path: PathBuf,
    pub review_model: String,
    pub stores_opened: bool,
    pub commands_executed: bool,
}

#[derive(Debug, Error)]
pub enum RepositorySetupError {
    #[error(
        "repository setup input, configured production model or acceptance contract is invalid"
    )]
    Invalid,
    #[error(
        "repository_root, acceptance_contract_path and git_executable must resolve to absolute existing paths of the required type"
    )]
    InvalidPaths,
    #[error(
        "acceptance contract is invalid; check its schema, path rules, direct executable, uppercase environment names, command budgets and required evidence"
    )]
    InvalidAcceptanceContract,
    #[error("repository setup file is unavailable or the candidate path already exists")]
    Unavailable,
}

/// Writes only a new candidate. The installed configuration and its stores are
/// untouched; the installer can promote it before first startup and then run
/// the ordinary full configuration preflight.
pub fn prepare_repository_configuration(
    request_path: impl AsRef<std::path::Path>,
) -> Result<RepositorySetupReport, RepositorySetupError> {
    let bytes = fs::read(request_path).map_err(|_| RepositorySetupError::Unavailable)?;
    let request: RepositorySetupRequest =
        serde_json::from_slice(&bytes).map_err(|_| RepositorySetupError::Invalid)?;
    if !request.config_path.is_absolute() || !request.candidate_path.is_absolute() {
        return Err(RepositorySetupError::Invalid);
    }
    let material = RepositoryMaterialConfig {
        contract_path: request.acceptance_contract_path,
        repository_root: request.repository_root,
        git_executable: request.git_executable,
    }
    .validate()
    .map_err(|_| RepositorySetupError::InvalidPaths)?;
    let acceptance = material
        .acceptance_contract_reference()
        .map_err(|_| RepositorySetupError::InvalidAcceptanceContract)?;
    let bytes = fs::read(&request.config_path).map_err(|_| RepositorySetupError::Unavailable)?;
    let mut config: Value =
        serde_json::from_slice(&bytes).map_err(|_| RepositorySetupError::Invalid)?;
    let review_model = configure(&mut config, &material, &acceptance, request.review_model)?;
    let parent = request
        .candidate_path
        .parent()
        .ok_or(RepositorySetupError::Invalid)?;
    let mut file =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| RepositorySetupError::Unavailable)?;
    let bytes = serde_json::to_vec_pretty(&config).map_err(|_| RepositorySetupError::Invalid)?;
    file.write_all(&bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|_| RepositorySetupError::Unavailable)?;
    file.persist_noclobber(&request.candidate_path)
        .map_err(|_| RepositorySetupError::Unavailable)?;
    Ok(RepositorySetupReport {
        candidate_config_path: request.candidate_path,
        review_model,
        stores_opened: false,
        commands_executed: false,
    })
}

fn configure(
    config: &mut Value,
    material: &RepositoryMaterialConfig,
    acceptance: &egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference,
    requested_model: Option<String>,
) -> Result<String, RepositorySetupError> {
    if !matches!(
        config["schema_version"].as_str(),
        Some("egopulse.production-bootstrap/v2" | "egopulse.production-bootstrap/v3")
    ) || !config["task_guard"].is_object()
        || !config["artifact"].is_object()
        || !config["verification"].is_object()
        || !config["codex"].is_object()
        || !config["verification_worker"].is_null()
    {
        return Err(RepositorySetupError::Invalid);
    }
    let profiles = config["provider_profiles"]
        .as_array()
        .ok_or(RepositorySetupError::Invalid)?;
    let production: Vec<_> = profiles
        .iter()
        .filter(|profile| profile["admission"] == "production")
        .collect();
    if production.len() != 1 || production[0]["harness"] != "codex_app_server" {
        return Err(RepositorySetupError::Invalid);
    }
    let provider = production[0];
    let review_model = requested_model
        .or_else(|| provider["selected_model"].as_str().map(str::to_owned))
        .filter(|model| !model.trim().is_empty())
        .ok_or(RepositorySetupError::Invalid)?;
    if !provider["models"].as_array().is_some_and(|models| {
        models
            .iter()
            .any(|model| model["harness_model_id"] == review_model)
    }) {
        return Err(RepositorySetupError::Invalid);
    }

    let profiles: BTreeMap<String, Value> =
        serde_json::from_str(PROFILES).map_err(|_| RepositorySetupError::Invalid)?;
    let refs: BTreeMap<_, _> = profiles
        .iter()
        .map(|(id, profile)| {
            let body = json!({"contract_id": id, "profile": profile});
            let canonical = serde_json::to_vec(&body).map_err(|_| RepositorySetupError::Invalid)?;
            Ok((
                id.clone(),
                json!({
                    "contract_id": id, "version": profile["version"],
                    "sha256": hex::encode(Sha256::digest(canonical))
                }),
            ))
        })
        .collect::<Result<_, RepositorySetupError>>()?;
    let reference = |id: &str| -> Result<Value, RepositorySetupError> {
        refs.get(id).cloned().ok_or(RepositorySetupError::Invalid)
    };
    let acceptance = json!({
        "contract_id": acceptance.contract_id,
        "version": acceptance.version,
        "sha256": acceptance.sha256
    });
    config["task_guard"]["acceptance_contract_ref"] = acceptance.clone();
    config["task_guard"]["allowed_work_types"] = json!(["governed_repository_change"]);

    for (key, ids) in [
        (
            "allowed_artifact_type_refs",
            &[
                "repository_material",
                "repository_command_intent",
                "repository_command_receipt",
                "repository_checker_deployment",
                "repository_checker_raw_output",
                "repository_checker_detail",
                "repository_checker_tool_receipt",
                "repository_checker_model_receipt",
                "repository_checker_cost_receipt",
                "founder_supporting_material",
            ][..],
        ),
        (
            "allowed_transformation_contract_refs",
            &[
                "repository_capture",
                "repository_command_capture",
                "repository_checker_output",
                "repository_checker_capture",
                "founder_supporting_material_capture",
            ][..],
        ),
        ("allowed_retention_profile_refs", &["local_retention"][..]),
        (
            "allowed_evidence_profile_refs",
            &["repository_evidence"][..],
        ),
        (
            "allowed_claim_semantic_profile_refs",
            &["repository_change_acceptance"][..],
        ),
    ] {
        for id in ids {
            append_reference(&mut config["artifact"][key], reference(id)?)?;
        }
    }
    append_reference(
        &mut config["artifact"]["allowed_claim_acceptance_contract_refs"],
        acceptance,
    )?;
    config["repository_material"] = json!({
        "repository_root": material.repository_root,
        "acceptance_contract_path": material.contract_path,
        "git_executable": material.git_executable,
        "artifact_type_ref": reference("repository_material")?,
        "transformation_contract_ref": reference("repository_capture")?,
        "retention_profile_ref": reference("local_retention")?,
        "evidence_profile_ref": reference("repository_evidence")?,
        "claim_semantic_profile_ref": reference("repository_change_acceptance")?,
        "command_intent_type_ref": reference("repository_command_intent")?,
        "command_intent_transformation_ref": reference("repository_command_capture")?,
        "command_receipt_type_ref": reference("repository_command_receipt")?,
        "command_receipt_transformation_ref": reference("repository_command_capture")?
    });

    let mut verification = json!({
        "deployment_artifact_type_ref": reference("repository_checker_deployment")?,
        "deployment_transformation_ref": reference("repository_checker_capture")?,
        "retention_profile_ref": reference("local_retention")?,
        "collector_principal_id": "collector:repository-verification:v1",
        "max_prompt_bytes": 1048576, "max_output_bytes": 1048576,
        "output": {
            "raw_output_type_ref": reference("repository_checker_raw_output")?,
            "detail_type_ref": reference("repository_checker_detail")?,
            "tool_receipt_type_ref": reference("repository_checker_tool_receipt")?,
            "model_receipt_type_ref": reference("repository_checker_model_receipt")?,
            "cost_receipt_type_ref": reference("repository_checker_cost_receipt")?
        }
    });
    let mut criteria = Vec::new();
    for role in ["scope", "tests", "review"] {
        let mut deployment = json!({
            "input_contract_ref": reference("repository_checker_input")?,
            "output_contract_ref": reference("repository_checker_output")?,
            "sandbox_profile_ref": reference("repository_checker_readonly")?,
            "tool_policy_ref": reference("repository_checker_tools")?,
            "data_egress_policy_ref": reference("repository_checker_egress")?,
            "budget_profile_ref": reference("repository_checker_budget")?,
            "timeout_ms": 120000,
            "model": if role == "review" { Some(&review_model) } else { None }
        });
        // A changed model/configuration/implementation gets a new immutable
        // deployment identity; subsequent Tasks reuse the same identity.
        let basis = serde_json::to_vec(&json!({
            "role": role, "deployment": deployment,
            "agentosd_version": env!("CARGO_PKG_VERSION")
        }))
        .map_err(|_| RepositorySetupError::Invalid)?;
        let profile_id = format!("repository:{role}:{}", hex::encode(Sha256::digest(basis)));
        deployment["checker_profile_id"] = json!(profile_id);
        verification[role] = deployment;
        criteria.push(json!({
            "criterion_id": role, "requirement": 1,
            "minimum_assurance": if role == "review" { 2 } else { 1 },
            "not_applicable_allowed": false, "checker_profile_ids": [profile_id]
        }));
    }
    config["verification"]["criteria"] = json!(criteria);
    config["repository_verification"] = verification;
    config["founder_supporting_material"] = json!({
        "artifact_type_ref": reference("founder_supporting_material")?,
        "transformation_contract_ref": reference("founder_supporting_material_capture")?,
        "retention_profile_ref": reference("local_retention")?,
        "collector_principal_id": "collector:founder-supporting-material:v1"
    });
    Ok(review_model)
}

fn append_reference(target: &mut Value, reference: Value) -> Result<(), RepositorySetupError> {
    let values = target.as_array_mut().ok_or(RepositorySetupError::Invalid)?;
    if !values.contains(&reference) {
        values.push(reference);
    }
    Ok(())
}
