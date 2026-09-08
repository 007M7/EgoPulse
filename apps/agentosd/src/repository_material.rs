use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, SupervisedProcessSpec, run_governed_process,
};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTRACT_SCHEMA: &str = "repository_change_acceptance/v1";
const MATERIAL_SCHEMA: &str = "egopulse.repository-material/v1";
const GIT_TIMEOUT: Duration = Duration::from_secs(10);
const GIT_OUTPUT_LIMIT: u64 = 1024 * 1024;
const MAX_CONTRACT_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
static REPOSITORY_PREPARATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

// `ContractReference.sha256` binds the compact UTF-8 JSON serialization of the
// fully typed and normalized contract below. Object field order follows the
// Rust structs; set-like path/environment/evidence fields are sorted, while
// command order and each command's argv order remain authored order.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryMaterialConfig {
    pub contract_path: PathBuf,
    pub repository_root: PathBuf,
    pub git_executable: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenRepositoryMaterialV1 {
    pub(crate) schema_version: String,
    pub(crate) contract_path: String,
    pub(crate) repository_root: String,
    pub(crate) git_executable: String,
    pub(crate) acceptance_contract_ref: FrozenContractReference,
    pub(crate) acceptance_contract: RepositoryAcceptanceContractV1,
    pub(crate) baseline_commit: String,
    pub(crate) baseline_tree: String,
    pub(crate) git_common_dir: String,
    pub(crate) clean_worktree: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenContractReference {
    pub(crate) contract_id: String,
    pub(crate) version: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryAcceptanceContractV1 {
    pub(crate) schema_version: String,
    pub(crate) contract_id: String,
    pub(crate) version: String,
    pub(crate) revision: u64,
    pub(crate) allowed_paths: Vec<String>,
    pub(crate) forbidden_paths: Vec<String>,
    pub(crate) read_only_paths: Vec<String>,
    pub(crate) required_commands: Vec<RepositoryAcceptanceCommandV1>,
    pub(crate) evidence_requirements: Vec<RepositoryEvidenceRequirement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepositoryAcceptanceCommandV1 {
    pub(crate) command_id: String,
    pub(crate) criterion_id: String,
    pub(crate) requirement: RepositoryCommandRequirement,
    pub(crate) executable: String,
    pub(crate) argv: Vec<String>,
    pub(crate) cwd: String,
    pub(crate) inherited_environment: Vec<String>,
    pub(crate) environment_overrides: BTreeMap<String, String>,
    pub(crate) timeout_seconds: u64,
    pub(crate) output_limit_bytes: u64,
    pub(crate) expected_exit_code: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepositoryCommandRequirement {
    MustPass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepositoryEvidenceRequirement {
    RepositoryBaseline,
    RepositoryPatch,
    WorkspaceManifest,
    CommandReceipt,
    IndependentChecker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryPathAccess {
    Allowed,
    ReadOnly,
    Forbidden,
    Unspecified,
}

#[derive(Debug, Error)]
pub enum RepositoryMaterialError {
    #[error("repository material configuration or contract is invalid")]
    Invalid,
    #[error("repository material could not be read")]
    Unavailable,
    #[error("repository material no longer matches its frozen snapshot")]
    Drift,
}

impl RepositoryMaterialConfig {
    /// Returns the reference derived by the same parser used at Task freeze.
    /// Configuration tools must not maintain a second canonicalization routine.
    pub fn acceptance_contract_reference(
        &self,
    ) -> Result<ContractReference, RepositoryMaterialError> {
        let (contract, digest) = read_contract(&self.contract_path)?;
        Ok(ContractReference {
            contract_id: contract.contract_id,
            version: contract.version,
            sha256: digest,
        })
    }

    /// Uses the same normalization and reference contract as per-Task freeze.
    /// This preflight performs no Git or acceptance-command execution.
    pub(crate) fn validate_acceptance_contract_ref(
        &self,
        expected: &ContractReference,
    ) -> Result<(), RepositoryMaterialError> {
        let (contract, digest) = read_contract(&self.contract_path)?;
        validate_contract_reference(&contract, &digest, expected)
    }

    pub(crate) fn validate(self) -> Result<Self, RepositoryMaterialError> {
        if !self.contract_path.is_absolute()
            || !self.repository_root.is_absolute()
            || !self.git_executable.is_absolute()
        {
            return Err(RepositoryMaterialError::Invalid);
        }
        let contract_path = self
            .contract_path
            .canonicalize()
            .map_err(|_| RepositoryMaterialError::Unavailable)?;
        let repository_root = self
            .repository_root
            .canonicalize()
            .map_err(|_| RepositoryMaterialError::Unavailable)?;
        let git_executable = self
            .git_executable
            .canonicalize()
            .map_err(|_| RepositoryMaterialError::Unavailable)?;
        if !contract_path.is_file() || !repository_root.is_dir() || !git_executable.is_file() {
            return Err(RepositoryMaterialError::Invalid);
        }
        Ok(Self {
            contract_path,
            repository_root,
            git_executable,
        })
    }
}

impl FrozenRepositoryMaterialV1 {
    pub(crate) fn acceptance_contract_ref(&self) -> ContractReference {
        ContractReference {
            contract_id: self.acceptance_contract_ref.contract_id.clone(),
            version: self.acceptance_contract_ref.version.clone(),
            sha256: self.acceptance_contract_ref.sha256.clone(),
        }
    }

    pub(crate) fn contract_path(&self) -> &Path {
        Path::new(&self.contract_path)
    }

    pub(crate) fn repository_root(&self) -> &Path {
        Path::new(&self.repository_root)
    }

    pub(crate) fn git_executable(&self) -> &Path {
        Path::new(&self.git_executable)
    }

    pub(crate) fn git_common_dir(&self) -> &Path {
        Path::new(&self.git_common_dir)
    }

    pub(crate) fn baseline_commit(&self) -> &str {
        &self.baseline_commit
    }

    pub(crate) fn baseline_tree(&self) -> &str {
        &self.baseline_tree
    }

    pub(crate) fn validate_stored(
        &self,
        configured_ref: &ContractReference,
    ) -> Result<(), RepositoryMaterialError> {
        if self.schema_version != MATERIAL_SCHEMA
            || !self.clean_worktree
            || !Path::new(&self.contract_path).is_absolute()
            || !Path::new(&self.repository_root).is_absolute()
            || !Path::new(&self.git_executable).is_absolute()
            || !Path::new(&self.git_common_dir).is_absolute()
            || !is_lowercase_hex_digest(&self.baseline_commit)
            || !is_lowercase_hex_digest(&self.baseline_tree)
        {
            return Err(RepositoryMaterialError::Invalid);
        }
        let mut normalized = self.acceptance_contract.clone();
        normalize_and_validate_contract(&mut normalized)?;
        if normalized != self.acceptance_contract {
            return Err(RepositoryMaterialError::Invalid);
        }
        let canonical =
            serde_json::to_vec(&normalized).map_err(|_| RepositoryMaterialError::Invalid)?;
        let stored_ref = self.acceptance_contract_ref();
        validate_contract_reference(&normalized, &sha256(&canonical), &stored_ref)?;
        if &stored_ref != configured_ref {
            return Err(RepositoryMaterialError::Drift);
        }
        Ok(())
    }

    // M1 freezes the path policy; M2 consumes this crate-local precedence
    // helper when it provisions and inspects the isolated Task worktree.
    #[allow(dead_code)]
    pub(crate) fn path_access(
        &self,
        repository_relative_path: &str,
    ) -> Result<RepositoryPathAccess, RepositoryMaterialError> {
        let path = normalize_relative_path(repository_relative_path, false)?;
        if self
            .acceptance_contract
            .forbidden_paths
            .iter()
            .any(|prefix| repository_prefix_matches(prefix, &path))
        {
            return Ok(RepositoryPathAccess::Forbidden);
        }
        if self
            .acceptance_contract
            .read_only_paths
            .iter()
            .any(|prefix| repository_prefix_matches(prefix, &path))
        {
            return Ok(RepositoryPathAccess::ReadOnly);
        }
        if self
            .acceptance_contract
            .allowed_paths
            .iter()
            .any(|prefix| repository_prefix_matches(prefix, &path))
        {
            return Ok(RepositoryPathAccess::Allowed);
        }
        Ok(RepositoryPathAccess::Unspecified)
    }
}

pub(crate) fn frozen_repository_material_from_compiled_context(
    compiled_context: &[u8],
) -> Result<Option<FrozenRepositoryMaterialV1>, RepositoryMaterialError> {
    let root: serde_json::Value =
        serde_json::from_slice(compiled_context).map_err(|_| RepositoryMaterialError::Invalid)?;
    let root = root.as_object().ok_or(RepositoryMaterialError::Invalid)?;
    let version = root.get("repository_material_version");
    let Some(value) = root.get("repository_material") else {
        return if version.is_none() {
            Ok(None)
        } else {
            Err(RepositoryMaterialError::Invalid)
        };
    };
    if version.and_then(serde_json::Value::as_u64) != Some(1) || value.is_null() {
        return Err(RepositoryMaterialError::Invalid);
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|_| RepositoryMaterialError::Invalid)
}

pub(crate) async fn freeze_repository_material(
    config: &RepositoryMaterialConfig,
    expected_ref: &ContractReference,
) -> Result<FrozenRepositoryMaterialV1, RepositoryMaterialError> {
    let _guard = repository_preparation_lock().lock().await;
    let config = config.clone().validate()?;
    let (contract, contract_sha256) = read_contract(&config.contract_path)?;
    validate_contract_reference(&contract, &contract_sha256, expected_ref)?;
    let baseline = read_clean_baseline(&config).await?;
    Ok(FrozenRepositoryMaterialV1 {
        schema_version: MATERIAL_SCHEMA.to_owned(),
        contract_path: path_text(&config.contract_path)?,
        repository_root: path_text(&config.repository_root)?,
        git_executable: path_text(&config.git_executable)?,
        acceptance_contract_ref: FrozenContractReference {
            contract_id: expected_ref.contract_id.clone(),
            version: expected_ref.version.clone(),
            sha256: expected_ref.sha256.clone(),
        },
        acceptance_contract: contract,
        baseline_commit: baseline.commit,
        baseline_tree: baseline.tree,
        git_common_dir: baseline.git_common_dir,
        clean_worktree: true,
    })
}

struct RepositoryBaseline {
    commit: String,
    tree: String,
    git_common_dir: String,
}

async fn read_clean_baseline(
    config: &RepositoryMaterialConfig,
) -> Result<RepositoryBaseline, RepositoryMaterialError> {
    let top_level = git_text(config, &["rev-parse", "--show-toplevel"]).await?;
    let actual_root = PathBuf::from(top_level)
        .canonicalize()
        .map_err(|_| RepositoryMaterialError::Unavailable)?;
    if actual_root != config.repository_root {
        return Err(RepositoryMaterialError::Invalid);
    }
    let commit = git_text(config, &["rev-parse", "HEAD^{commit}"]).await?;
    let first_status = git_bytes(
        config,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    .await?;
    let second_commit = git_text(config, &["rev-parse", "HEAD^{commit}"]).await?;
    let second_status = git_bytes(
        config,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    .await?;
    if commit != second_commit || !first_status.is_empty() || !second_status.is_empty() {
        return Err(RepositoryMaterialError::Drift);
    }
    if git_text(config, &["cat-file", "-t", &commit]).await? != "commit" {
        return Err(RepositoryMaterialError::Invalid);
    }
    let tree = git_text(config, &["rev-parse", &format!("{commit}^{{tree}}")]).await?;
    if git_text(config, &["cat-file", "-t", &tree]).await? != "tree" {
        return Err(RepositoryMaterialError::Invalid);
    }
    let common_dir = git_text(config, &["rev-parse", "--git-common-dir"]).await?;
    let common_dir = if Path::new(&common_dir).is_absolute() {
        PathBuf::from(common_dir)
    } else {
        config.repository_root.join(common_dir)
    }
    .canonicalize()
    .map_err(|_| RepositoryMaterialError::Unavailable)?;
    if !is_lowercase_hex_digest(&commit) || !is_lowercase_hex_digest(&tree) {
        return Err(RepositoryMaterialError::Invalid);
    }
    Ok(RepositoryBaseline {
        commit,
        tree,
        git_common_dir: path_text(&common_dir)?,
    })
}

async fn git_text(
    config: &RepositoryMaterialConfig,
    arguments: &[&str],
) -> Result<String, RepositoryMaterialError> {
    let output = git_bytes(config, arguments).await?;
    let output = std::str::from_utf8(&output).map_err(|_| RepositoryMaterialError::Invalid)?;
    Ok(output.trim().to_owned())
}

async fn git_bytes(
    config: &RepositoryMaterialConfig,
    arguments: &[&str],
) -> Result<Vec<u8>, RepositoryMaterialError> {
    let mut spec = SupervisedProcessSpec::new(&config.git_executable, &config.repository_root);
    spec.arguments = arguments.iter().map(|value| (*value).to_owned()).collect();
    spec.clear_environment = true;
    spec.inherited_environment = [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "HOME",
        "USERPROFILE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    spec.environment_overrides = vec![
        ("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()),
        ("GIT_PAGER".to_owned(), "cat".to_owned()),
        ("GIT_OPTIONAL_LOCKS".to_owned(), "0".to_owned()),
        ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".to_owned()),
        (
            "GIT_CONFIG_GLOBAL".to_owned(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.to_owned(),
        ),
        ("GIT_CONFIG_COUNT".to_owned(), "2".to_owned()),
        ("GIT_CONFIG_KEY_0".to_owned(), "core.fsmonitor".to_owned()),
        ("GIT_CONFIG_VALUE_0".to_owned(), "false".to_owned()),
        ("GIT_CONFIG_KEY_1".to_owned(), "safe.directory".to_owned()),
        (
            "GIT_CONFIG_VALUE_1".to_owned(),
            trusted_repository_git_path(&config.repository_root)?,
        ),
        ("LC_ALL".to_owned(), "C".to_owned()),
    ];
    let receipt = run_governed_process(
        &spec,
        &[],
        GovernedProcessBudget {
            timeout: GIT_TIMEOUT,
            output_limit_bytes: GIT_OUTPUT_LIMIT,
        },
    )
    .await
    .map_err(process_error)?;
    if !receipt.stderr.is_empty() {
        return Err(RepositoryMaterialError::Invalid);
    }
    Ok(receipt.stdout)
}

fn process_error(error: GovernedProcessError) -> RepositoryMaterialError {
    match error {
        GovernedProcessError::InvalidSpecification => RepositoryMaterialError::Invalid,
        GovernedProcessError::Spawn
        | GovernedProcessError::InputDelivery
        | GovernedProcessError::Timeout
        | GovernedProcessError::Crashed
        | GovernedProcessError::OutputLimit
        | GovernedProcessError::Io
        | GovernedProcessError::Protocol => RepositoryMaterialError::Unavailable,
    }
}

/// The caller has already bound this exact repository through local daemon
/// configuration or the sealed per-Task workspace. Trust only that directory
/// for this child process, independently of its filesystem owner. Never
/// inherit or write a user-wide trust list, and never accept Git wildcards.
pub(crate) fn trusted_repository_git_path(path: &Path) -> Result<String, RepositoryMaterialError> {
    if !path.is_absolute() {
        return Err(RepositoryMaterialError::Invalid);
    }
    let value = path.to_str().ok_or(RepositoryMaterialError::Invalid)?;
    if value.contains('*') || value.chars().any(char::is_control) {
        return Err(RepositoryMaterialError::Invalid);
    }
    #[cfg(windows)]
    {
        // Git's safe.directory matching expects a native, non-verbatim path.
        // Canonical paths are still retained for all containment comparisons.
        let value = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else {
            value.strip_prefix(r"\\?\").unwrap_or(value).to_owned()
        };
        Ok(value.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        Ok(value.to_owned())
    }
}

fn read_contract(
    path: &Path,
) -> Result<(RepositoryAcceptanceContractV1, String), RepositoryMaterialError> {
    let metadata = fs::metadata(path).map_err(|_| RepositoryMaterialError::Unavailable)?;
    if metadata.len() == 0 || metadata.len() > MAX_CONTRACT_BYTES {
        return Err(RepositoryMaterialError::Invalid);
    }
    let bytes = fs::read(path).map_err(|_| RepositoryMaterialError::Unavailable)?;
    serde_json::from_slice::<NoDuplicateJson>(&bytes)
        .map_err(|_| RepositoryMaterialError::Invalid)?;
    let mut contract: RepositoryAcceptanceContractV1 =
        serde_json::from_slice(&bytes).map_err(|_| RepositoryMaterialError::Invalid)?;
    normalize_and_validate_contract(&mut contract)?;
    let canonical = serde_json::to_vec(&contract).map_err(|_| RepositoryMaterialError::Invalid)?;
    Ok((contract, sha256(&canonical)))
}

fn normalize_and_validate_contract(
    contract: &mut RepositoryAcceptanceContractV1,
) -> Result<(), RepositoryMaterialError> {
    if contract.schema_version != CONTRACT_SCHEMA
        || contract.contract_id.trim().is_empty()
        || contract.version.trim().is_empty()
        || contract.revision == 0
        || contract.allowed_paths.is_empty()
        || contract.required_commands.is_empty()
        || contract.contract_id.len() > 256
        || contract.version.len() > 128
        || contract.allowed_paths.len() > 1024
        || contract.forbidden_paths.len() > 1024
        || contract.read_only_paths.len() > 1024
        || contract.required_commands.len() > 128
        || contract.evidence_requirements.len() > 16
    {
        return Err(RepositoryMaterialError::Invalid);
    }
    normalize_paths(&mut contract.allowed_paths, false)?;
    normalize_paths(&mut contract.forbidden_paths, false)?;
    normalize_paths(&mut contract.read_only_paths, false)?;

    let mut command_ids = BTreeSet::new();
    for command in &mut contract.required_commands {
        if command.command_id.trim().is_empty()
            || !command_ids.insert(command.command_id.clone())
            || !matches!(command.criterion_id.as_str(), "scope" | "tests" | "review")
            || command.command_id.len() > 256
            || command.argv.len() > 256
            || command.inherited_environment.len() > 64
            || command.environment_overrides.len() > 64
            || command.requirement != RepositoryCommandRequirement::MustPass
            || command.expected_exit_code != 0
            || command.timeout_seconds == 0
            || command.timeout_seconds > MAX_COMMAND_TIMEOUT_SECONDS
            || command.output_limit_bytes == 0
            || command.output_limit_bytes > MAX_COMMAND_OUTPUT_BYTES
            || command.executable.trim().is_empty()
            || !Path::new(&command.executable).is_absolute()
            || contains_nul_or_control(&command.executable)
            || is_shell_executable(&command.executable)
            || command.argv.iter().any(|value| {
                value.len() > 4096
                    || value.contains('\0')
                    || value.contains('\r')
                    || value.contains('\n')
            })
        {
            return Err(RepositoryMaterialError::Invalid);
        }
        command.cwd = normalize_relative_path(&command.cwd, true)?;
        command.inherited_environment.sort();
        if command
            .inherited_environment
            .windows(2)
            .any(|pair| pair[0] == pair[1])
            || command
                .inherited_environment
                .iter()
                .any(|name| !valid_environment_name(name))
            || command.environment_overrides.iter().any(|(name, value)| {
                !valid_environment_name(name) || value.len() > 16 * 1024 || value.contains('\0')
            })
        {
            return Err(RepositoryMaterialError::Invalid);
        }
    }

    contract.evidence_requirements.sort();
    contract.evidence_requirements.dedup();
    let required = vec![
        RepositoryEvidenceRequirement::RepositoryBaseline,
        RepositoryEvidenceRequirement::RepositoryPatch,
        RepositoryEvidenceRequirement::WorkspaceManifest,
        RepositoryEvidenceRequirement::CommandReceipt,
        RepositoryEvidenceRequirement::IndependentChecker,
    ];
    if contract.evidence_requirements != required {
        return Err(RepositoryMaterialError::Invalid);
    }
    Ok(())
}

fn validate_contract_reference(
    contract: &RepositoryAcceptanceContractV1,
    digest: &str,
    expected_ref: &ContractReference,
) -> Result<(), RepositoryMaterialError> {
    if contract.contract_id != expected_ref.contract_id
        || contract.version != expected_ref.version
        || digest != expected_ref.sha256
        || !is_lowercase_sha256(&expected_ref.sha256)
    {
        return Err(RepositoryMaterialError::Invalid);
    }
    Ok(())
}

fn normalize_paths(
    paths: &mut Vec<String>,
    allow_root: bool,
) -> Result<(), RepositoryMaterialError> {
    for path in paths.iter_mut() {
        *path = normalize_repository_path_pattern(path, allow_root)?;
    }
    paths.sort();
    paths.dedup();
    Ok(())
}

fn normalize_relative_path(
    value: &str,
    allow_root: bool,
) -> Result<String, RepositoryMaterialError> {
    let normalized = value.replace('\\', "/");
    if allow_root && normalized == "." {
        return Ok(normalized);
    }
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.ends_with('/')
        || normalized.contains("//")
        || normalized.contains(':')
        || normalized.chars().any(char::is_control)
        || normalized
            .chars()
            .any(|character| matches!(character, '*' | '?' | '[' | ']'))
    {
        return Err(RepositoryMaterialError::Invalid);
    }
    let path = Path::new(&normalized);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::ParentDir
                    | Component::CurDir
            )
        })
    {
        return Err(RepositoryMaterialError::Invalid);
    }
    for segment in normalized.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.eq_ignore_ascii_case(".git")
            || segment.ends_with(['.', ' '])
            || is_windows_device_name(segment)
        {
            return Err(RepositoryMaterialError::Invalid);
        }
    }
    Ok(normalized)
}

fn normalize_repository_path_pattern(
    value: &str,
    allow_root: bool,
) -> Result<String, RepositoryMaterialError> {
    let normalized = value.replace('\\', "/");
    let (base, recursive) = match normalized.strip_suffix("/**") {
        Some(base) if !base.contains('*') => (base, true),
        _ => (normalized.as_str(), false),
    };
    let base = normalize_relative_path(base, allow_root)?;
    Ok(if recursive {
        format!("{base}/**")
    } else {
        base
    })
}

fn is_windows_device_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

fn repository_prefix_matches(prefix: &str, path: &str) -> bool {
    let prefix = prefix.strip_suffix("/**").unwrap_or(prefix);
    path.eq_ignore_ascii_case(prefix)
        || path
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
            && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

fn is_shell_executable(value: &str) -> bool {
    let path = Path::new(value);
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if matches!(
        extension.to_ascii_lowercase().as_str(),
        "bat" | "cmd" | "ps1"
    ) {
        return true;
    }
    matches!(
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "cmd.exe" | "powershell.exe" | "pwsh.exe" | "sh" | "bash"
    )
}

fn valid_environment_name(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    if upper.starts_with("EGOPULSE_")
        || upper.starts_with("AUTHORITY_")
        || upper.contains("_AUTHORITY_")
        || upper.ends_with("_KEY")
        || upper.ends_with("_KEY_HEX")
    {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn contains_nul_or_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn path_text(path: &Path) -> Result<String, RepositoryMaterialError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(RepositoryMaterialError::Invalid)
}

fn is_lowercase_hex_digest(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn repository_preparation_lock() -> &'static tokio::sync::Mutex<()> {
    REPOSITORY_PREPARATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

struct NoDuplicateJson;

impl<'de> Deserialize<'de> for NoDuplicateJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateJsonVisitor)
    }
}

struct NoDuplicateJsonVisitor;

impl<'de> Visitor<'de> for NoDuplicateJsonVisitor {
    type Value = NoDuplicateJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<NoDuplicateJson>()?.is_some() {}
        Ok(NoDuplicateJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            map.next_value::<NoDuplicateJson>()?;
        }
        Ok(NoDuplicateJson)
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) fn acceptance_contract_digest_for_test(
    path: &Path,
) -> Result<String, RepositoryMaterialError> {
    read_contract(path).map(|(_, digest)| digest)
}
