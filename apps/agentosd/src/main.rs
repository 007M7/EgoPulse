#![forbid(unsafe_code)]

use egopulse_agentosd::{DaemonComposition, DaemonConfig, ProductionBootstrapConfig};

fn print_help() {
    println!(
        r#"EgoPulse AgentOS daemon

Usage: agentosd [OPTIONS]

Options:
  -h, --help       Print this help message
  -V, --version    Print the daemon version

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
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 {
        match args[0].to_string_lossy().as_ref() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "-V" | "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => {}
        }
    }
    if !args.is_empty() {
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
        std::process::exit(1);
    }
}
