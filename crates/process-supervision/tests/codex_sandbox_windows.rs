#![cfg(windows)]

use egopulse_process_supervision::{
    GovernedProcessBudget, SupervisedProcessSpec, run_governed_process_outcome,
};
use std::{path::PathBuf, time::Duration};

/// A local sandbox smoke check, without a model/API request. It verifies that
/// our process tree and credential-free environment still permit native Codex
/// to launch one sandboxed command. No global sandbox settings are changed.
#[tokio::test]
#[ignore = "requires EGOPULSE_SANDBOX_TEST_CODEX and EGOPULSE_SANDBOX_TEST_CWD"]
async fn real_codex_sandbox_starts_inside_governed_process_tree() {
    let binary =
        PathBuf::from(std::env::var_os("EGOPULSE_SANDBOX_TEST_CODEX").expect("Codex path"));
    let cwd =
        PathBuf::from(std::env::var_os("EGOPULSE_SANDBOX_TEST_CWD").expect("fixture directory"));
    let desktop_shell = PathBuf::from(std::env::var_os("ProgramFiles").expect("ProgramFiles"))
        .join("PowerShell/7/pwsh.exe");
    assert!(
        desktop_shell.is_file(),
        "ordinary PowerShell 7 must be installed"
    );
    let mut failures = Vec::new();
    for minimal in [false, true] {
        let mut spec = SupervisedProcessSpec::new(&binary, &cwd);
        if minimal {
            spec = spec
                .with_minimal_user_environment()
                .with_inherited_environment("CODEX_HOME");
        }
        spec = spec.with_desktop_shell_path();
        spec.arguments = vec![
            "sandbox".to_owned(),
            "--".to_owned(),
            "pwsh.exe".to_owned(),
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Write-Output ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)"
                .to_owned(),
        ];
        let result = run_governed_process_outcome(
            &spec,
            &[],
            GovernedProcessBudget {
                timeout: Duration::from_secs(25),
                output_limit_bytes: 65536,
            },
        )
        .await;
        match result {
            Ok(receipt) => {
                let marker = std::path::Path::new(String::from_utf8_lossy(&receipt.stdout).trim())
                    == desktop_shell;
                let access_denied = String::from_utf8_lossy(&receipt.stderr)
                    .contains("CreateProcessAsUserW failed: 5");
                println!(
                    "sandbox_smoke minimal={minimal} exit={} marker={marker} spawn_access_denied={access_denied}",
                    receipt.exit_code
                );
                if receipt.exit_code != 0 || !marker {
                    failures.push(minimal);
                }
            }
            Err(error) => {
                println!("sandbox_smoke minimal={minimal} error={error:?}");
                failures.push(minimal);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "native sandbox failed in modes: {failures:?}"
    );
}
