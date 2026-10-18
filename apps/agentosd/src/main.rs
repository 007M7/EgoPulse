#![forbid(unsafe_code)]

use std::path::PathBuf;

use egopulse_agentosd::{
    DaemonComposition, DaemonConfig, ProductionBootstrapConfig,
    WorkCapabilityConfigTransitionReport, apply_work_capability_config_migration,
    prepare_repository_configuration, preview_work_capability_config_migration,
    preview_work_capability_config_rollback, rollback_work_capability_config_to_v2,
};
use serde_json::json;

fn print_help() {
    println!(
        r#"EgoPulse AgentOS daemon

Usage: agentosd [OPTIONS]

Options:
  -h, --help       Print this help message
  -V, --version    Print the daemon version
  --check-config  Validate local configuration without opening stores
  --check-config --json
                  Emit the redacted Provider/Model catalog for diagnostics
  --prepare-repository-config REQUEST.json [--json]
                  Write a separate repository configuration candidate; no stores or commands
  --preview-v3-migration [--json]
                  Preview the explicit work-capability v2 -> v3 transition
  --migrate-to-v3 [--json]
                  Apply the previewable transition and retain a complete v2 backup
  --preview-v2-rollback [--json]
                  Verify that the initial migrated v3 can be rolled back safely
  --rollback-to-v2 [--json]
                  Restore v2 and retain the current complete v3 file

The daemon accepts no positional arguments. Without an option it starts only
when the local configuration and all required authority keys are valid.

Configuration:
  EGOPULSE_USER_CONFIG    Path to the user config JSON
                          (default: egopulse-data/agentos-config.json)
  EGOPULSE_*_KEY_HEX      Required authority and runtime secrets

See config/README.md and config/agentos-config.example.json for the
first-run configuration template."#
    );
}

#[tokio::main]
async fn main() {
    if egopulse_local_ipc_platform::load_protected_process_keys().is_err() {
        eprintln!("LOCAL_KEYS_INVALID: protected installation keys could not be loaded");
        std::process::exit(78);
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let json_output = args
        .last()
        .is_some_and(|argument| argument.to_string_lossy() == "--json");
    let command_args = if json_output {
        &args[..args.len().saturating_sub(1)]
    } else {
        args.as_slice()
    };
    if command_args.len() == 2 && command_args[0] == "--prepare-repository-config" {
        match prepare_repository_configuration(PathBuf::from(&command_args[1])) {
            Ok(report) => match serde_json::to_string_pretty(&report) {
                Ok(output) => println!("{output}"),
                Err(_) => std::process::exit(78),
            },
            Err(error) => {
                eprintln!("agentosd repository configuration refused: {error}");
                std::process::exit(78);
            }
        }
        return;
    }
    if command_args.len() == 1 {
        match command_args[0].to_string_lossy().as_ref() {
            "-h" | "--help" => {
                if json_output {
                    refuse_unknown_arguments(&args);
                }
                print_help();
                return;
            }
            "-V" | "--version" => {
                if json_output {
                    refuse_unknown_arguments(&args);
                }
                println!("{}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--check-config" => {
                match check_configuration() {
                    Ok(config) if json_output => {
                        let report = json!({
                            "configuration": "passed",
                            "stores_opened": false,
                            "provider_profiles": config.provider_catalog_views(),
                            "verification_worker_configured": config.verification_worker.is_some() || config.repository_verification.is_some(),
                            "repository_verification_configured": config.repository_verification.is_some(),
                            "founder_supporting_material_configured": config.founder_supporting_material.is_some(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&report)
                                .expect("provider config report serializes")
                        );
                    }
                    Ok(_) => println!("agentosd configuration=passed stores_opened=false"),
                    Err(error) => {
                        eprintln!("agentosd configuration check refused: {error}");
                        std::process::exit(78);
                    }
                }
                return;
            }
            "--preview-v3-migration" => {
                run_config_transition(
                    preview_work_capability_config_migration(user_config_path()),
                    json_output,
                );
                return;
            }
            "--migrate-to-v3" => {
                run_config_transition(
                    apply_work_capability_config_migration(user_config_path()),
                    json_output,
                );
                return;
            }
            "--preview-v2-rollback" => {
                run_config_transition(
                    preview_work_capability_config_rollback(user_config_path()),
                    json_output,
                );
                return;
            }
            "--rollback-to-v2" => {
                run_config_transition(
                    rollback_work_capability_config_to_v2(user_config_path()),
                    json_output,
                );
                return;
            }
            _ => {}
        }
    }
    if !args.is_empty() {
        refuse_unknown_arguments(&args);
    }

    let config = match DaemonConfig::from_environment() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("agentosd startup refused: {error}");
            std::process::exit(78);
        }
    };

    let providers = match ProductionBootstrapConfig::from_environment()
        .and_then(ProductionBootstrapConfig::build)
    {
        Ok(value) => value,
        Err(error) => {
            eprintln!("agentosd startup refused: {error}");
            std::process::exit(78);
        }
    };
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
        let mut cause = std::error::Error::source(&error);
        while let Some(source) = cause {
            eprintln!("  caused by: {source}");
            cause = source.source();
        }
        std::process::exit(1);
    }
}

fn user_config_path() -> PathBuf {
    std::env::var_os("EGOPULSE_USER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("egopulse-data/agentos-config.json"))
}

fn run_config_transition(
    result: Result<WorkCapabilityConfigTransitionReport, impl std::fmt::Display>,
    json_output: bool,
) {
    match result {
        Ok(report) if json_output => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("transition report serializes")
        ),
        Ok(report) => println!(
            "agentosd transition={} applied={} from={} to={} choice={} model={} route_sha256={} backup={}",
            report.transition,
            report.applied,
            report.from_schema_version,
            report.to_schema_version,
            report.choice_id,
            report.harness_model_id,
            report.route_binding_sha256,
            report.retained_backup_path,
        ),
        Err(error) => {
            eprintln!("agentosd configuration transition refused: {error}");
            std::process::exit(78);
        }
    }
}

fn refuse_unknown_arguments(args: &[std::ffi::OsString]) -> ! {
    eprintln!(
        "agentosd: unknown argument(s): {}",
        args.iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    eprintln!("agentosd: use --help for usage");
    std::process::exit(64);
}

fn check_configuration() -> Result<ProductionBootstrapConfig, String> {
    let daemon = DaemonConfig::from_environment().map_err(|error| error.to_string())?;
    daemon.validate().map_err(|error| error.to_string())?;
    ProductionBootstrapConfig::from_environment().map_err(|error| error.to_string())
}
