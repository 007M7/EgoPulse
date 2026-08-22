#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use egopulse_local_api::LocalApiClient;

#[derive(Debug, Parser)]
#[command(name = "egopulse", version, about = "EgoPulse local client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the honest foundation state.
    Status {
        /// Emit stable JSON for scripts.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Status { json } => {
            let health = LocalApiClient::platform_default().foundation_health();
            if json {
                println!(
                    "{{\"architectureVersion\":\"{}\",\"service\":\"{}\",\"state\":\"{}\"}}",
                    health.architecture_version,
                    health.service,
                    health.state.as_str()
                );
            } else {
                println!("EgoPulse status: {}", health.state.as_str());
            }
        }
    }
}
