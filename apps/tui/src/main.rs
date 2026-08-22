#![forbid(unsafe_code)]

use clap::Parser;
use egopulse_local_api::LocalApiClient;
use ratatui::text::Line;

#[derive(Debug, Parser)]
#[command(name = "egopulse-tui", version, about = "EgoPulse terminal surface")]
struct Args {
    /// Print the foundation probe without entering raw terminal mode.
    #[arg(long, default_value_t = true)]
    foundation_check: bool,
}

fn main() {
    let args = Args::parse();
    if args.foundation_check {
        let health = LocalApiClient::platform_default().foundation_health();
        let line = Line::from(format!("EgoPulse TUI: {}", health.state.as_str()));
        let terminal = crossterm::terminal::size()
            .map(|(width, height)| format!("{width}x{height}"))
            .unwrap_or_else(|_| "unknown".to_owned());
        println!("{line} (terminal: {terminal})");
    }
}
