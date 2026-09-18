use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, GovernedProcessReceipt, SupervisedProcessSpec,
    run_governed_process,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerExecutionReceipt {
    pub stdout: Vec<u8>,
    pub stderr_sha256: String,
    pub stderr_byte_length: u64,
    pub exit_code: i32,
    pub duration_ms: u64,
}

pub type CheckerExecutionError = GovernedProcessError;

pub struct GovernedCheckerSupervisor {
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
    output_limit: u64,
    /// Explicit child-process environment entries.
    ///
    /// The checker environment stays cleared; only the inherited names plus
    /// these explicitly declared overrides are visible. Values are supplied by
    /// the composing owner from its credential reference resolution and are
    /// never read from configuration text by this type.
    environment_overrides: Vec<(String, String)>,
}

impl GovernedCheckerSupervisor {
    pub fn new(
        executable: PathBuf,
        arguments: Vec<String>,
        timeout: Duration,
        output_limit: u64,
    ) -> Result<Self, CheckerExecutionError> {
        if !executable.is_absolute()
            || !executable.is_file()
            || timeout.is_zero()
            || output_limit == 0
        {
            return Err(CheckerExecutionError::InvalidSpecification);
        }
        Ok(Self {
            executable,
            arguments,
            timeout,
            output_limit,
            environment_overrides: Vec::new(),
        })
    }

    /// Declares the only extra environment entries the checker process may see.
    ///
    /// `clear_environment` is deliberately left enabled: this adds entries on
    /// top of the cleared environment, it does not widen inheritance. An entry
    /// with an empty name or a NUL byte in either part is rejected so a caller
    /// cannot smuggle the ambient environment back in.
    pub fn with_environment_overrides(
        mut self,
        overrides: Vec<(String, String)>,
    ) -> Result<Self, CheckerExecutionError> {
        if overrides
            .iter()
            .any(|(name, value)| !is_declarable_environment_entry(name, value))
        {
            return Err(CheckerExecutionError::InvalidSpecification);
        }
        self.environment_overrides = overrides;
        Ok(self)
    }

    pub async fn run(
        &self,
        working_directory: &Path,
        request: &[u8],
    ) -> Result<CheckerExecutionReceipt, CheckerExecutionError> {
        let mut spec = SupervisedProcessSpec::new(&self.executable, working_directory);
        spec.arguments.clone_from(&self.arguments);
        spec.clear_environment = true;
        spec.inherited_environment = vec!["PATH".to_owned(), "SYSTEMROOT".to_owned()];
        spec.environment_overrides
            .clone_from(&self.environment_overrides);
        let receipt = run_governed_process(
            &spec,
            request,
            GovernedProcessBudget {
                timeout: self.timeout,
                output_limit_bytes: self.output_limit,
            },
        )
        .await?;
        Ok(map_receipt(receipt))
    }
}

/// An override entry is declarable only when the name is a non-empty identifier
/// and neither part can terminate a native environment block entry.
fn is_declarable_environment_entry(name: &str, value: &str) -> bool {
    !name.trim().is_empty() && !name.contains('\0') && !name.contains('=') && !value.contains('\0')
}

fn map_receipt(receipt: GovernedProcessReceipt) -> CheckerExecutionReceipt {
    CheckerExecutionReceipt {
        stdout: receipt.stdout,
        stderr_sha256: hex::encode(Sha256::digest(&receipt.stderr)),
        stderr_byte_length: receipt.stderr.len() as u64,
        exit_code: receipt.exit_code,
        duration_ms: receipt.duration_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Declarable entries are non-empty names without NUL or `=`, and values
    /// without NUL. Everything else is refused before it can reach a spec.
    #[test]
    fn environment_entries_are_declarable_only_when_well_formed() {
        assert!(is_declarable_environment_entry(
            "PROVIDER_API_KEY",
            "s3cret"
        ));
        assert!(is_declarable_environment_entry("A", ""));
        // An empty or blank name would re-open the ambient environment.
        assert!(!is_declarable_environment_entry("", "v"));
        assert!(!is_declarable_environment_entry("   ", "v"));
        // `=` would let a caller inject a second `NAME=value` pair.
        assert!(!is_declarable_environment_entry("A=B", "v"));
        // A NUL would terminate the native environment block entry.
        assert!(!is_declarable_environment_entry("A", "v\0w"));
        assert!(!is_declarable_environment_entry("A\0B", "v"));
    }

    /// The builder refuses a malformed declaration instead of quietly dropping
    /// it, so a composing owner cannot believe a credential was wired when it
    /// was not.
    #[test]
    fn malformed_overrides_are_rejected_at_construction() {
        let executable = std::env::current_exe().expect("current test executable");
        let build = |overrides: Vec<(String, String)>| {
            GovernedCheckerSupervisor::new(
                executable.clone(),
                Vec::new(),
                Duration::from_secs(5),
                4096,
            )
            .expect("valid supervisor")
            .with_environment_overrides(overrides)
        };

        assert!(build(Vec::new()).is_ok());
        assert!(build(vec![("A".to_owned(), "b".to_owned())]).is_ok());
        assert!(matches!(
            build(vec![(String::new(), "b".to_owned())]),
            Err(CheckerExecutionError::InvalidSpecification)
        ));
        assert!(matches!(
            build(vec![("A".to_owned(), "b\0c".to_owned())]),
            Err(CheckerExecutionError::InvalidSpecification)
        ));
    }

    /// The override must actually reach the child process while the environment
    /// stays cleared: the declared variable is visible, and an undeclared one
    /// that exists in this process's own environment is not inherited.
    #[tokio::test]
    async fn declared_override_reaches_child_and_undeclared_names_do_not() {
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_default())
            .join("System32")
            .join("cmd.exe");
        if !shell.is_file() {
            // No shell available in this environment; the declarable-entry rules
            // are still covered by the unit tests above.
            return;
        }
        // `USERPROFILE` is present in the parent but is not in the supervisor's
        // inherited set (only PATH and SYSTEMROOT), so it must not be visible.
        let undeclared = "USERPROFILE";
        assert!(
            std::env::var_os(undeclared).is_some(),
            "precondition: the parent must actually define {undeclared}"
        );
        let variable = "EGOPULSE_CHECKER_TEST_DECLARED";
        let supervisor = GovernedCheckerSupervisor::new(
            shell,
            vec!["/c".to_owned(), format!("echo %{variable}%,%{undeclared}%")],
            Duration::from_secs(10),
            4096,
        )
        .expect("valid supervisor")
        .with_environment_overrides(vec![(variable.to_owned(), "visible".to_owned())])
        .expect("declarable override");

        let receipt = supervisor
            .run(&std::env::temp_dir(), b"")
            .await
            .expect("supervised checker run");
        let stdout = String::from_utf8_lossy(&receipt.stdout);
        assert!(
            stdout.contains("visible"),
            "declared override must be visible to the child, got {stdout:?}"
        );
        // cmd expands an undefined variable to the literal `%NAME%`, so seeing
        // the literal proves the name was absent from the child environment.
        assert!(
            stdout.contains(&format!("%{undeclared}%")),
            "expected {undeclared} to be absent (literal), got {stdout:?}"
        );
    }
}
