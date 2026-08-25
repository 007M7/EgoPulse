#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use egopulse_client_kernel::ClientKernel;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    ClientSurface, GetProjectionStatusRequest, ProjectionHealth,
};
use egopulse_local_api::{LocalApiClient, LocalIpcAddress};
use uuid::Uuid;

const DEFAULT_INSTANCE: &str = "default";

#[derive(Debug, Parser)]
#[command(name = "egopulse", version, about = "EgoPulse local client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Attach to the local daemon and print typed projection status.
    Status {
        /// Emit stable JSON for scripts.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug)]
struct CliFailure {
    exit_code: u8,
    reason_code: &'static str,
    message: String,
}

impl CliFailure {
    fn daemon_unavailable(message: impl Into<String>) -> Self {
        Self {
            exit_code: 3,
            reason_code: "DAEMON_UNAVAILABLE",
            message: message.into(),
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            exit_code: 70,
            reason_code: "LOCAL_API_PROTOCOL_ERROR",
            message: message.into(),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Status { json } => status(json).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}: {}", error.reason_code, error.message);
            ExitCode::from(error.exit_code)
        }
    }
}

async fn status(json: bool) -> Result<(), CliFailure> {
    let address = LocalIpcAddress::for_instance(DEFAULT_INSTANCE)
        .map_err(|error| CliFailure::protocol(format!("invalid IPC instance: {error}")))?;
    let connection = LocalApiClient::platform_default()
        .connect(address)
        .await
        .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?;
    let mut kernel = ClientKernel::new("egopulse-cli", ClientSurface::Cli)
        .map_err(|error| CliFailure::protocol(error.to_string()))?;
    let open_request = kernel
        .open_session_request(Uuid::now_v7().to_string())
        .map_err(|error| CliFailure::protocol(error.to_string()))?;
    let open_response = connection
        .session_service()
        .open_session(open_request)
        .await
        .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?
        .into_inner();
    kernel
        .accept_open_session(open_response, std::time::SystemTime::now())
        .map_err(|error| CliFailure::protocol(error.to_string()))?;
    let metadata = kernel
        .request_metadata(
            Uuid::now_v7().to_string(),
            None,
            std::time::SystemTime::now(),
        )
        .map_err(|error| CliFailure::protocol(error.to_string()))?;
    let response = connection
        .read_model_service()
        .get_projection_status(GetProjectionStatusRequest {
            client: Some(metadata),
        })
        .await
        .map_err(|error| CliFailure::daemon_unavailable(error.to_string()))?
        .into_inner();
    if let Some(error) = response.error {
        return Err(CliFailure::protocol(format!(
            "local_api_error_code={} required_action={}",
            error.code,
            error.required_action_code.as_deref().unwrap_or("none")
        )));
    }
    let metadata = response
        .metadata
        .ok_or_else(|| CliFailure::protocol("projection metadata missing"))?;
    let position = metadata
        .position
        .ok_or_else(|| CliFailure::protocol("projection position missing"))?;
    let health = ProjectionHealth::try_from(metadata.health)
        .map_err(|_| CliFailure::protocol("projection health is unknown"))?;

    if json {
        println!(
            "{{\"state\":\"connected\",\"projectionHealth\":\"{}\",\"stale\":{},\"epoch\":\"{}\",\"sequence\":{}}}",
            health.as_str_name(),
            metadata.stale,
            position.epoch,
            position.sequence
        );
    } else {
        println!("EgoPulse status: connected");
        println!("Projection: {}", health.as_str_name());
        println!("Position: {}:{}", position.epoch, position.sequence);
        println!("Stale: {}", metadata.stale);
    }
    Ok(())
}
