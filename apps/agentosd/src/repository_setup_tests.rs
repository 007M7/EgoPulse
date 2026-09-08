use super::*;

fn setup_files(root: &std::path::Path) -> (PathBuf, PathBuf) {
    let config_path = root.join("installed.json");
    fs::write(
        &config_path,
        include_str!("../../../config/agentos-config.example.json"),
    )
    .expect("write base configuration");
    let contract_path = root.join("acceptance.json");
    let contract = json!({
        "schema_version": "repository_change_acceptance/v1",
        "contract_id": "setup-test-acceptance", "version": "v1", "revision": 1,
        "allowed_paths": ["src/**"], "forbidden_paths": ["tests/**"],
        "read_only_paths": ["README.md"],
        "required_commands": [{
            "command_id": "regression", "criterion_id": "tests", "requirement": "must_pass",
            "executable": std::env::current_exe().expect("current executable"),
            "argv": ["--help"], "cwd": ".", "inherited_environment": [],
            "environment_overrides": {}, "timeout_seconds": 30,
            "output_limit_bytes": 1024, "expected_exit_code": 0
        }],
        "evidence_requirements": ["repository_baseline", "repository_patch", "workspace_manifest", "command_receipt", "independent_checker"]
    });
    fs::write(
        &contract_path,
        serde_json::to_vec(&contract).expect("contract JSON"),
    )
    .expect("write contract");
    (config_path, contract_path)
}

fn request(
    root: &std::path::Path,
    config: &std::path::Path,
    contract: &std::path::Path,
    candidate: &std::path::Path,
    model: &str,
) -> PathBuf {
    let path = root.join("request.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "config_path": config, "candidate_path": candidate,
            "repository_root": root, "acceptance_contract_path": contract,
            // A real file is sufficient: setup must not launch Git or a checker.
            "git_executable": std::env::current_exe().expect("current executable"),
            "review_model": model
        }))
        .expect("setup request JSON"),
    )
    .expect("write request");
    path
}

#[test]
fn setup_binds_real_contract_preserves_source_and_never_overwrites_candidate() {
    let root = tempfile::tempdir().expect("isolated setup root");
    let (source, contract) = setup_files(root.path());
    let original = fs::read(&source).expect("source bytes");
    let candidate = root.path().join("candidate.json");
    let request = request(root.path(), &source, &contract, &candidate, "gpt-5.6-sol");
    let report = prepare_repository_configuration(&request).expect("prepare candidate");
    assert!(!report.stores_opened && !report.commands_executed);
    assert_eq!(fs::read(&source).expect("source retained"), original);
    let bytes = fs::read(&candidate).expect("candidate bytes");
    let config: Value = serde_json::from_slice(&bytes).expect("candidate JSON");
    let material = RepositoryMaterialConfig {
        contract_path: contract,
        repository_root: root.path().to_path_buf(),
        git_executable: std::env::current_exe().expect("current executable"),
    };
    let expected = material
        .acceptance_contract_reference()
        .expect("same Task parser");
    assert_eq!(
        config["task_guard"]["acceptance_contract_ref"]["sha256"],
        expected.sha256
    );
    assert!(
        config["artifact"]["allowed_claim_acceptance_contract_refs"]
            .as_array()
            .expect("acceptance allowlist")
            .contains(&config["task_guard"]["acceptance_contract_ref"])
    );
    assert_eq!(
        config["repository_material"]["claim_semantic_profile_ref"]["contract_id"],
        "repository_change_acceptance"
    );
    let _: crate::RepositoryVerificationConfig =
        serde_json::from_value(config["repository_verification"].clone())
            .expect("real deployment schema");
    assert_eq!(
        config["repository_verification"]["collector_principal_id"],
        "collector:repository-verification:v1"
    );
    assert!(matches!(
        prepare_repository_configuration(&request),
        Err(RepositorySetupError::Unavailable)
    ));
    assert_eq!(fs::read(&candidate).expect("candidate retained"), bytes);
    assert!(!root.path().join("egopulse-data").exists());
}

#[test]
fn setup_model_selection_is_catalog_bound_and_changes_only_review_deployment_identity() {
    let root = tempfile::tempdir().expect("isolated setup root");
    let (source, contract) = setup_files(root.path());
    let first_path = root.path().join("first.json");
    prepare_repository_configuration(request(
        root.path(),
        &source,
        &contract,
        &first_path,
        "gpt-5.6-sol",
    ))
    .expect("first candidate");
    let second_path = root.path().join("second.json");
    prepare_repository_configuration(request(
        root.path(),
        &source,
        &contract,
        &second_path,
        "gpt-5.6-terra",
    ))
    .expect("second candidate");
    let first: Value =
        serde_json::from_slice(&fs::read(first_path).expect("first bytes")).expect("first JSON");
    let second: Value =
        serde_json::from_slice(&fs::read(second_path).expect("second bytes")).expect("second JSON");
    for role in ["scope", "tests"] {
        assert_eq!(
            first["repository_verification"][role],
            second["repository_verification"][role]
        );
    }
    assert_ne!(
        first["repository_verification"]["review"]["checker_profile_id"],
        second["repository_verification"]["review"]["checker_profile_id"]
    );
    assert_eq!(first["provider_profiles"], second["provider_profiles"]);
    assert_eq!(first["codex"], second["codex"]);
    let refused = root.path().join("refused.json");
    assert!(matches!(
        prepare_repository_configuration(request(
            root.path(),
            &source,
            &contract,
            &refused,
            "not-in-catalog"
        )),
        Err(RepositorySetupError::Invalid)
    ));
    assert!(!refused.exists());
}
