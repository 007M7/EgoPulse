#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use egopulse_client_kernel::ClientKernel;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    ClientSurface, GetProjectionStatusRequest, LocalApiError, LocalApiErrorCode, ProjectionHealth,
};
use egopulse_local_api::{LocalApiClient, LocalIpcAddress};
use serde_json::json;
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
    category: &'static str,
    retryable: bool,
    required_action_code: Option<String>,
    safe_fingerprint: Option<String>,
}

struct ProjectionStatusView {
    health: String,
    stale: bool,
    epoch: String,
    sequence: u64,
}

impl ProjectionStatusView {
    fn json(&self) -> serde_json::Value {
        json!({
            "schemaVersion": "egopulse.cli-result/v0.1",
            "ok": true,
            "operation": "status",
            "data": { "state": "connected" },
            "projection": {
                "position": { "epoch": self.epoch, "sequence": self.sequence },
                "health": self.health,
                "stale": self.stale,
            },
            "correlationId": Uuid::now_v7().to_string(),
        })
    }

    fn text(&self) -> String {
        format!(
            "EgoPulse status: connected\nProjection: {}\nPosition: {}:{}\nStale: {}\n",
            self.health, self.epoch, self.sequence, self.stale
        )
    }
}

impl CliFailure {
    fn daemon_unavailable(message: impl Into<String>) -> Self {
        Self {
            exit_code: 3,
            reason_code: "DAEMON_UNAVAILABLE",
            message: message.into(),
            category: "unavailable",
            retryable: true,
            required_action_code: Some("attach_to_daemon".to_owned()),
            safe_fingerprint: None,
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            exit_code: 70,
            reason_code: "LOCAL_API_PROTOCOL_ERROR",
            message: message.into(),
            category: "internal",
            retryable: false,
            required_action_code: None,
            safe_fingerprint: None,
        }
    }

    fn from_local_api_error(error: LocalApiError) -> Self {
        let code = LocalApiErrorCode::try_from(error.code)
            .map(|code| code.as_str_name())
            .unwrap_or("LOCAL_API_ERROR_UNKNOWN");
        let (exit_code, category) = match LocalApiErrorCode::try_from(error.code).ok() {
            Some(LocalApiErrorCode::Unauthenticated | LocalApiErrorCode::PermissionDenied) => {
                (4, "authentication")
            }
            Some(LocalApiErrorCode::ContractIncompatible | LocalApiErrorCode::SessionExpired) => {
                (5, "contract")
            }
            Some(
                LocalApiErrorCode::ProjectionBehind
                | LocalApiErrorCode::ProjectionResetRequired
                | LocalApiErrorCode::CursorExpired
                | LocalApiErrorCode::CursorInvalid,
            ) => (7, "projection"),
            _ => (70, "internal"),
        };
        Self {
            exit_code,
            reason_code: "LOCAL_API_ERROR",
            message: code.to_owned(),
            category,
            retryable: error.retryable,
            required_action_code: error.required_action_code,
            safe_fingerprint: (!error.safe_fingerprint.is_empty())
                .then_some(error.safe_fingerprint),
        }
    }

    fn json_envelope(&self) -> serde_json::Value {
        json!({
            "schemaVersion": "egopulse.cli-result/v0.1",
            "ok": false,
            "operation": "status",
            "error": {
                "category": self.category,
                "code": self.reason_code,
                "retryable": self.retryable,
                "requiredActionCode": self.required_action_code,
                "safeFingerprint": self.safe_fingerprint,
            },
            "projection": serde_json::Value::Null,
            "correlationId": Uuid::now_v7().to_string(),
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_output = matches!(&cli.command, Command::Status { json: true });
    let result = match cli.command {
        Command::Status { json } => status(json).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json_output {
                println!("{}", serde_json::to_string(&error.json_envelope()).unwrap());
            } else {
                eprintln!("{}: {}", error.reason_code, error.message);
            }
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
        return Err(CliFailure::from_local_api_error(error));
    }
    let metadata = response
        .metadata
        .ok_or_else(|| CliFailure::protocol("projection metadata missing"))?;
    let position = metadata
        .position
        .ok_or_else(|| CliFailure::protocol("projection position missing"))?;
    let health = ProjectionHealth::try_from(metadata.health)
        .map_err(|_| CliFailure::protocol("projection health is unknown"))?;

    let view = ProjectionStatusView {
        health: health.as_str_name().to_owned(),
        stale: metadata.stale,
        epoch: position.epoch,
        sequence: position.sequence,
    };
    if json {
        println!("{}", serde_json::to_string(&view.json()).unwrap());
    } else {
        print!("{}", view.text());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text_and_json_share_the_same_projection_facts() {
        let view = ProjectionStatusView {
            health: "PROJECTION_HEALTH_READY".to_owned(),
            stale: false,
            epoch: "epoch-test".to_owned(),
            sequence: 7,
        };
        let json = view.json();
        assert_eq!(json["schemaVersion"], "egopulse.cli-result/v0.1");
        assert_eq!(json["ok"], true);
        assert_eq!(json["operation"], "status");
        assert_eq!(json["projection"]["health"], "PROJECTION_HEALTH_READY");
        assert_eq!(json["projection"]["position"]["epoch"], "epoch-test");
        assert_eq!(json["projection"]["position"]["sequence"], 7);
        let text = view.text();
        assert!(text.contains("Projection: PROJECTION_HEALTH_READY"));
        assert!(text.contains("Position: epoch-test:7"));
        assert!(text.contains("Stale: false"));
    }

    #[test]
    fn json_error_envelope_does_not_include_transport_diagnostics() {
        let error = CliFailure::daemon_unavailable("private pipe path");
        let json = error.json_envelope();
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["code"], "DAEMON_UNAVAILABLE");
        assert_eq!(json["error"]["requiredActionCode"], "attach_to_daemon");
        assert!(
            serde_json::to_string(&json)
                .unwrap()
                .contains("attach_to_daemon")
        );
        assert!(
            !serde_json::to_string(&json)
                .unwrap()
                .contains("private pipe path")
        );
    }
}
