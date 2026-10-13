#![forbid(unsafe_code)]

//! Provider-bound OpenCode ACP adapter.
//!
//! OpenCode uses the same ACP transport already exercised by the DSH
//! candidate. This crate deliberately wraps that implementation instead of
//! maintaining a second JSON-RPC parser. It adds OpenCode identity, an exact
//! provider/model route and provider-specific evidence names. Native
//! load/resume remains a separate admission gate.

use std::{path::PathBuf, time::Duration};

use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, CancelExecutionEnvelope, DispatchEnvelope, NativeProtocolFingerprint,
    ProbeHarnessRequest, ProbeHarnessResult, harness_observation,
};
use egopulse_dsh_adapter::{DshAcpConfig, DshAcpDriver};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverEvent, NativeHarnessDriver, NativeHarnessFuture,
    ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
    TerminalOutputCandidate,
};

pub const OPENCODE_ADAPTER_ID: &str = "opencode-adapter";
/// Composition identity for routes served by one OpenCode executable. The
/// admitted provider/model route travels separately in the sealed
/// work-capability binding, so this names the Harness capability profile
/// rather than any single model.
pub const OPENCODE_CAPABILITY_PROFILE_ID: &str = "opencode-acp-v1";
pub const OPENCODE_ACP_PROTOCOL: &str = "agent-client-protocol";
pub const OPENCODE_ACP_PROTOCOL_VERSION: &str = "v1";
/// OpenCode publishes no protocol schema, so a composition cannot pin a schema
/// digest the way Codex pins its App Server schema. Naming the gap keeps that
/// absence observable instead of filling the digest with a value nobody
/// observed.
pub const OPENCODE_ACP_SCHEMA_ATTESTATION_REQUIRED: &str =
    "OPENCODE_ACP_SCHEMA_ATTESTATION_REQUIRED";
pub const OPENCODE_NATIVE_RECOVERY_UNATTESTED_EVIDENCE_REF: &str =
    "opencode-reconcile:native-session-load-resume-not-attested";

/// Protocol identity declared for an OpenCode ACP composition. The schema
/// digest stays empty by design; `native_executable_version` is the version
/// the admitting configuration observed for the executable it pinned.
#[must_use]
pub fn opencode_acp_protocol_fingerprint(
    native_executable_version: String,
) -> NativeProtocolFingerprint {
    NativeProtocolFingerprint {
        protocol_name: OPENCODE_ACP_PROTOCOL.to_owned(),
        protocol_version: OPENCODE_ACP_PROTOCOL_VERSION.to_owned(),
        schema_sha256: String::new(),
        adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
        native_executable_version,
        native_binary_sha256: None,
    }
}

#[derive(Clone, Debug)]
pub struct OpenCodeAcpConfig {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment_overrides: Vec<(String, String)>,
    pub required_model: String,
    pub request_timeout: Duration,
}

impl OpenCodeAcpConfig {
    #[must_use]
    pub fn new(
        executable: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        required_model: impl Into<String>,
    ) -> Self {
        Self {
            executable: executable.into(),
            arguments: vec!["acp".to_owned()],
            working_directory: working_directory.into(),
            environment_overrides: Vec::new(),
            required_model: required_model.into(),
            request_timeout: Duration::from_secs(30),
        }
    }

    #[must_use]
    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    #[must_use]
    pub fn with_environment_override(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.environment_overrides.push((name.into(), value.into()));
        self
    }

    fn into_inner(self) -> DshAcpConfig {
        let mut config = DshAcpConfig::new(self.executable, self.working_directory)
            .with_required_model(self.required_model)
            // OpenCode offers a model option whose default is one of its own
            // models, so the exact provider/model route is established by
            // setting that option before the first prompt.
            .with_session_model_selection();
        config.arguments = self.arguments;
        config.environment_overrides = self.environment_overrides;
        config.request_timeout = self.request_timeout;
        config
    }
}

pub struct OpenCodeAcpDriver {
    inner: DshAcpDriver,
    config: OpenCodeAcpConfig,
}

impl OpenCodeAcpDriver {
    #[must_use]
    pub fn new(config: OpenCodeAcpConfig) -> Self {
        Self {
            inner: DshAcpDriver::new(config.clone().into_inner()),
            config,
        }
    }
}

impl egopulse_harness_adapter::ReadOnlyTurnDriver for OpenCodeAcpDriver {
    fn run_bounded_read_only_turn<'a>(
        &'a mut self,
        mut request: egopulse_harness_adapter::ReadOnlyTurnRequest,
    ) -> NativeHarnessFuture<'a, Result<egopulse_harness_adapter::ReadOnlyTurnOutcome, DriverError>>
    {
        Box::pin(async move {
            if request.model != self.config.required_model || request.model.is_empty() {
                return Err(read_only_error("READ_ONLY_MODEL_MISMATCH"));
            }
            // No preexisting native configuration may widen this capability.
            if self.config.environment_overrides.iter().any(|(name, _)| {
                name.starts_with("OPENCODE_")
                    || name.starts_with("XDG_")
                    || matches!(name.as_str(), "HOME" | "USERPROFILE" | "ProgramData")
            }) {
                return Err(read_only_error("READ_ONLY_CONFIGURATION_OVERRIDE_REFUSED"));
            }
            let data_home = read_only_data_home()?;
            refuse_remote_configuration(&data_home.join("opencode/auth.json"))?;
            let managed = if cfg!(windows) {
                PathBuf::from(
                    std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()),
                )
                .join("opencode")
            } else {
                PathBuf::from("/etc/opencode")
            };
            if managed.try_exists().unwrap_or(true) || cfg!(target_os = "macos") {
                return Err(read_only_error(
                    "READ_ONLY_MANAGED_CONFIGURATION_UNATTESTED",
                ));
            }
            let root = tempfile::tempdir()
                .map_err(|_| read_only_error("READ_ONLY_ISOLATION_UNAVAILABLE"))?;
            let mut config = self.config.clone();
            config.working_directory = root.path().to_owned();
            // A fresh empty workspace/config directory prevents inheriting project
            // instructions, MCP servers, plugins or user agents. Credentials still
            // cross only the already-admitted process environment boundary.
            config.environment_overrides.extend([
                ("XDG_DATA_HOME".to_owned(), data_home.display().to_string()),
                (
                    "XDG_STATE_HOME".to_owned(),
                    root.path().join("state").display().to_string(),
                ),
                (
                    "XDG_CACHE_HOME".to_owned(),
                    root.path().join("cache").display().to_string(),
                ),
                (
                    "OPENCODE_DB".to_owned(),
                    root.path().join("native.db").display().to_string(),
                ),
                (
                    "OPENCODE_TEST_HOME".to_owned(),
                    root.path().display().to_string(),
                ),
                ("OPENCODE_PURE".to_owned(), "true".to_owned()),
                ("OPENCODE_DISABLE_AUTOUPDATE".to_owned(), "true".to_owned()),
                (
                    "XDG_CONFIG_HOME".to_owned(),
                    root.path().display().to_string(),
                ),
                (
                    "OPENCODE_CONFIG_DIR".to_owned(),
                    root.path().display().to_string(),
                ),
                (
                    "OPENCODE_DISABLE_PROJECT_CONFIG".to_owned(),
                    "true".to_owned(),
                ),
                ("OPENCODE_DISABLE_CLAUDE_CODE".to_owned(), "true".to_owned()),
                (
                    "OPENCODE_CONFIG_CONTENT".to_owned(),
                    serde_json::json!({
                        "permission":{"*":"deny"}, "tools":{"*":false}, "plugin":[],
                        "instructions":[], "autoupdate":false, "share":"disabled",
                        "agent":{"build":{"permission":{"*":"deny"},"tools":{"*":false}}}
                    })
                    .to_string(),
                ),
            ]);
            request.working_directory = root.path().to_owned();
            let mut fresh = DshAcpDriver::new(config.into_inner());
            fresh
                .run_tools_disabled_turn(request)
                .await
                .map_err(map_error)
        })
    }
}
fn read_only_data_home() -> Result<PathBuf, DriverError> {
    let path = if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path)
    } else {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .ok_or_else(|| read_only_error("READ_ONLY_HOME_UNAVAILABLE"))?;
        PathBuf::from(home).join(".local/share")
    };
    if !path.is_absolute() {
        return Err(read_only_error("READ_ONLY_HOME_UNAVAILABLE"));
    }
    Ok(path)
}
fn refuse_remote_configuration(path: &std::path::Path) -> Result<(), DriverError> {
    use std::{collections::BTreeMap, io::Read};
    #[derive(serde::Deserialize)]
    struct Metadata {
        r#type: String,
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(read_only_error("READ_ONLY_AUTH_METADATA_UNAVAILABLE")),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| read_only_error("READ_ONLY_AUTH_METADATA_UNAVAILABLE"))?;
    if bytes.len() > 65_536 {
        return Err(read_only_error("READ_ONLY_AUTH_METADATA_UNAVAILABLE"));
    }
    // Deserialize only types, ignoring credential fields; never log or persist the body.
    let metadata: BTreeMap<String, Metadata> = serde_json::from_slice(&bytes)
        .map_err(|_| read_only_error("READ_ONLY_AUTH_METADATA_UNAVAILABLE"))?;
    if metadata
        .values()
        .any(|entry| !matches!(entry.r#type.as_str(), "api" | "oauth"))
    {
        return Err(read_only_error("READ_ONLY_REMOTE_CONFIGURATION_UNATTESTED"));
    }
    Ok(())
}
fn read_only_error(code: &str) -> DriverError {
    DriverError {
        certainty: egopulse_harness_adapter::DriverErrorCertainty::ProvenNotSent,
        code:
            egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessErrorCode::InvalidArgument,
        safe_detail_code: code.to_owned(),
        error_fingerprint: None,
        raw_evidence: Vec::new(),
    }
}

impl NativeHarnessDriver for OpenCodeAcpDriver {
    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async move {
            let mut result = self.inner.probe(request).await.map_err(map_error)?;
            if let Some(protocol) = result.observed_protocol.as_mut() {
                protocol.protocol_name = OPENCODE_ACP_PROTOCOL.to_owned();
                protocol.protocol_version = OPENCODE_ACP_PROTOCOL_VERSION.to_owned();
                protocol.adapter_version = env!("CARGO_PKG_VERSION").to_owned();
            }
            result.safe_diagnostic_codes = result
                .safe_diagnostic_codes
                .into_iter()
                .map(|code| provider_code(&code))
                .collect();
            result.evidence_refs = result
                .evidence_refs
                .into_iter()
                .map(|evidence| evidence.replace("dsh-acp", "opencode-acp"))
                .collect();
            Ok(result)
        })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            let mut delivery = self
                .inner
                .send_dispatch(envelope, material)
                .await
                .map_err(map_error)?;
            delivery.native_request_ref = delivery
                .native_request_ref
                .replace("dsh-acp", "opencode-acp");
            delivery.native_execution_ref = delivery
                .native_execution_ref
                .map(|value| value.replace("dsh-acp", "opencode-acp"));
            Ok(delivery)
        })
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            let mut event = self.inner.next_event(envelope).await.map_err(map_error)?;
            if let Some(event) = event.as_mut() {
                event.native_key = event.native_key.replace("dsh-acp", "opencode-acp");
                if let harness_observation::Payload::ApprovalRequest(request) = &mut event.payload {
                    request.requested_scope_ref =
                        "adapter-edge://opencode-acp/approval/scope".to_owned();
                    request.display_summary_ref =
                        "adapter-edge://opencode-acp/approval/summary".to_owned();
                }
            }
            Ok(event)
        })
    }

    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        Box::pin(async move {
            let mut candidate = self
                .inner
                .take_terminal_output_candidate(envelope)
                .await
                .map_err(map_error)?;
            if let Some(candidate) = candidate.as_mut() {
                candidate.native_completion_ref = candidate
                    .native_completion_ref
                    .replace("dsh-acp", "opencode-acp");
            }
            Ok(candidate)
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            self.inner
                .decide_approval(envelope)
                .await
                .map_err(map_error)
        })
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move { self.inner.cancel(envelope).await.map_err(map_error) })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async {
            Ok(ReconciliationFinding::OutcomeUnknown {
                evidence_ref: OPENCODE_NATIVE_RECOVERY_UNATTESTED_EVIDENCE_REF.to_owned(),
            })
        })
    }
}

fn map_error(mut error: DriverError) -> DriverError {
    error.safe_detail_code = provider_code(&error.safe_detail_code);
    error
}

fn provider_code(code: &str) -> String {
    code.strip_prefix("DSH_ACP_")
        .map(|suffix| format!("OPENCODE_ACP_{suffix}"))
        .unwrap_or_else(|| code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_has_an_exact_model_and_provider_owned_evidence_namespace() {
        let config = OpenCodeAcpConfig::new(
            "opencode",
            std::env::current_dir().expect("cwd"),
            "zai/glm-4.7",
        );
        assert_eq!(config.arguments, ["acp"]);
        assert_eq!(config.required_model, "zai/glm-4.7");
        assert_eq!(
            provider_code("DSH_ACP_SESSION_MODEL_MISMATCH"),
            "OPENCODE_ACP_SESSION_MODEL_MISMATCH"
        );
    }

    #[test]
    fn wrapper_establishes_the_model_option_before_prompting() {
        let config = OpenCodeAcpConfig::new(
            "opencode",
            std::env::current_dir().expect("cwd"),
            "zen/deepseek-v4-flash",
        )
        .into_inner();
        assert_eq!(
            config.required_model.as_deref(),
            Some("zen/deepseek-v4-flash")
        );
        assert!(
            config.select_session_model,
            "an OpenCode session defaults to another model, so the exact route must be selected"
        );
    }

    #[test]
    fn protocol_fingerprint_names_the_transport_without_a_fabricated_schema_digest() {
        let fingerprint = opencode_acp_protocol_fingerprint("1.18.31".to_owned());
        assert_eq!(fingerprint.protocol_name, OPENCODE_ACP_PROTOCOL);
        assert_eq!(fingerprint.protocol_version, OPENCODE_ACP_PROTOCOL_VERSION);
        assert!(fingerprint.schema_sha256.is_empty());
        assert_eq!(fingerprint.native_executable_version, "1.18.31");
        assert_eq!(fingerprint.adapter_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            OPENCODE_ACP_SCHEMA_ATTESTATION_REQUIRED,
            "OPENCODE_ACP_SCHEMA_ATTESTATION_REQUIRED"
        );
    }
}

#[cfg(test)]
mod read_only_metadata_tests {
    use super::*;
    #[test]
    fn remote_account_configuration_is_refused_without_exposing_credentials() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("auth.json");
        std::fs::write(&path, br#"{"provider":{"type":"wellknown","token":"fixture-secret-token","key":"fixture-key"}}"#).unwrap();
        let error = refuse_remote_configuration(&path).unwrap_err();
        assert_eq!(
            error.safe_detail_code,
            "READ_ONLY_REMOTE_CONFIGURATION_UNATTESTED"
        );
        assert!(error.raw_evidence.is_empty());
        assert_eq!(
            error.certainty,
            egopulse_harness_adapter::DriverErrorCertainty::ProvenNotSent
        );
        std::fs::write(
            &path,
            br#"{"provider":{"type":"api","key":"fixture-secret-token"}}"#,
        )
        .unwrap();
        assert!(refuse_remote_configuration(&path).is_ok());
        std::fs::write(&path, br#"{"provider":{"type":"unknown-future-account"}}"#).unwrap();
        assert!(refuse_remote_configuration(&path).is_err());
        std::fs::write(&path, vec![b' '; 65_537]).unwrap();
        assert!(refuse_remote_configuration(&path).is_err());
    }
}
