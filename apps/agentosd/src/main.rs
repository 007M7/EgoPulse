#![forbid(unsafe_code)]

use egopulse_agentosd::{
    DaemonComposition, DaemonConfig, DaemonProviderFactory, FailClosedProviderFactory,
};

#[tokio::main]
async fn main() {
    let config = match DaemonConfig::from_environment() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("agentosd startup refused: {error}");
            std::process::exit(78);
        }
    };

    let providers = FailClosedProviderFactory.build();
    let daemon = match DaemonComposition::build(config, providers) {
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
