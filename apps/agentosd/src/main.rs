#![forbid(unsafe_code)]

#[tokio::main]
async fn main() {
    let cognition = egopulse_cognition_runtime::foundation_health();
    let control = egopulse_local_ide_control::foundation_health();
    let supervision = egopulse_process_supervision::foundation_probe().await;

    tracing::info!("EgoPulse foundation probe complete");
    println!(
        "agentosd: {} / {} / {} (no listener; foundation scaffold only)",
        cognition.state.as_str(),
        control.state.as_str(),
        supervision.state.as_str()
    );
}
