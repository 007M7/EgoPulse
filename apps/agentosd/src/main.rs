#![forbid(unsafe_code)]

use std::{path::PathBuf, time::Duration};

use egopulse_agentosd::{DaemonComposition, DaemonConfig, DaemonProviders};

#[tokio::main]
async fn main() {
    let config = DaemonConfig {
        instance: std::env::var("EGOPULSE_IPC_INSTANCE").unwrap_or_else(|_| "default".to_owned()),
        read_model_database_path: std::env::var_os("EGOPULSE_READ_MODEL_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("egopulse-data/read-model.db")),
        read_model_epoch: std::env::var("EGOPULSE_READ_MODEL_EPOCH")
            .unwrap_or_else(|_| "local-default".to_owned()),
        read_model_key: [0; 32],
        token_mac_key: [0; 32],
        session_ttl: Duration::from_secs(60 * 60),
    };

    let daemon = match DaemonComposition::build(config, DaemonProviders::fail_closed()) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("agentosd startup refused: {error}");
            std::process::exit(78);
        }
    };
    let address = daemon.address().as_str().to_owned();
    eprintln!("agentosd listening on {address}");
    if let Err(error) = daemon
        .serve(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    {
        eprintln!("agentosd stopped with error: {error}");
        std::process::exit(1);
    }
}
