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
}

impl OpenCodeAcpDriver {
    #[must_use]
    pub fn new(config: OpenCodeAcpConfig) -> Self {
        Self {
            inner: DshAcpDriver::new(config.into_inner()),
        }
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
