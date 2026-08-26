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
