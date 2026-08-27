use std::process::Command;

#[test]
fn check_config_rejects_missing_user_config_before_opening_any_store() {
    let config_path = std::env::temp_dir().join(format!(
        "egopulse-config-check-missing-{}.json",
        uuid::Uuid::now_v7()
    ));
    assert!(!config_path.exists());
    let read_model_key = "11".repeat(32);
    let token_mac_key = "22".repeat(32);

    let output = Command::new(env!("CARGO_BIN_EXE_agentosd"))
        .arg("--check-config")
        .env("EGOPULSE_USER_CONFIG", &config_path)
        .env("EGOPULSE_READ_MODEL_KEY_HEX", read_model_key)
        .env("EGOPULSE_TOKEN_MAC_KEY_HEX", token_mac_key)
        .output()
        .expect("run agentosd config check");

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration check refused"));
    assert!(!config_path.exists());
}

#[test]
fn check_config_rejects_out_of_range_daemon_setting_before_opening_any_store() {
    let config_path = std::env::temp_dir().join(format!(
        "egopulse-config-check-invalid-setting-{}.json",
        uuid::Uuid::now_v7()
    ));
    assert!(!config_path.exists());
    let read_model_key = "33".repeat(32);
    let token_mac_key = "44".repeat(32);

    let output = Command::new(env!("CARGO_BIN_EXE_agentosd"))
        .arg("--check-config")
        .env("EGOPULSE_USER_CONFIG", &config_path)
        .env("EGOPULSE_READ_MODEL_KEY_HEX", read_model_key)
        .env("EGOPULSE_TOKEN_MAC_KEY_HEX", token_mac_key)
        .env("EGOPULSE_HARNESS_DISPATCH_INTERVAL_MS", "1")
        .output()
        .expect("run agentosd config check");

    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration check refused"));
    assert!(stderr.contains("Harness dispatch interval"));
    assert!(!config_path.exists());
}

#[test]
fn check_config_accepts_the_packaged_example_without_opening_any_store() {
    let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config/agentos-config.example.json")
        .canonicalize()
        .expect("packaged example config exists");
    let key = "55".repeat(32);

    let output = Command::new(env!("CARGO_BIN_EXE_agentosd"))
        .arg("--check-config")
        .env("EGOPULSE_USER_CONFIG", config_path)
        .env("EGOPULSE_READ_MODEL_KEY_HEX", &key)
        .env("EGOPULSE_TOKEN_MAC_KEY_HEX", &key)
        .env("EGOPULSE_TASK_KEY_HEX", &key)
        .env("EGOPULSE_MEMORY_KEY_HEX", &key)
        .env("EGOPULSE_ARTIFACT_KEY_HEX", &key)
        .env("EGOPULSE_VERIFICATION_KEY_HEX", &key)
        .env("EGOPULSE_POLICY_KEY_HEX", &key)
        .env("EGOPULSE_VERDICT_KEY_HEX", &key)
        .env("EGOPULSE_ADAPTER_KEY_HEX", &key)
        .env("EGOPULSE_COLLABORATION_KEY_HEX", &key)
        .output()
        .expect("run agentosd config check");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "agentosd configuration=passed stores_opened=false"
    );
    assert!(output.stderr.is_empty());
}
