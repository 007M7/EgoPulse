#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use egopulse_local_api::LocalApiClient;

#[tauri::command]
fn foundation_status() -> String {
    LocalApiClient::platform_default()
        .foundation_health()
        .state
        .as_str()
        .to_owned()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![foundation_status])
        .run(tauri::generate_context!())
        .expect("failed to run EgoPulse desktop foundation shell");
}
