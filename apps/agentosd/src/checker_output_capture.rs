//! Sealing of the exact bytes a configured checker produced.
//!
//! A non-repository verification worker runs a checker whose output is not a
//! member of the task's artifact set, so the Verification Authority admits a
//! citation of that output only when a governed collector sealed it for the
//! same execution. This module is that collector side: it wraps the existing
//! checker-output intake, so the sealed identity, provenance and binding checks
//! are the ones the repository path already uses. Environments that declare no
//! capture keep the published behaviour and cite the artifact their
//! configuration named.

use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::ArtifactAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    verification::v1::{CheckerProfile, VerificationRequest},
};
use egopulse_verification_authority::{
    CheckerOutputRole, CheckerOutputSink, SealedCheckerOutput, VerificationAuthority,
};

use crate::{
    ConfiguredArtifactAdmissionGuard,
    artifact::DerivedWorkspaceAdmissionHandle,
    verification_output::{
        VerificationOutputError, VerificationOutputPolicy, VerificationOutputRequest,
        VerificationResultArtifactIntake,
    },
};

/// Declared deployment of one configured checker's raw output. The type and
/// retention contracts must be admitted for this installation; the two
/// principals must be the collector that stages and the Authority that seals.
#[derive(Clone, Debug)]
pub struct CheckerOutputCaptureConfig {
    pub(crate) raw_output_type_ref: ContractReference,
    pub(crate) retention_profile_ref: ContractReference,
    pub(crate) collector_principal_id: String,
    pub(crate) artifact_authority_principal_id: String,
    pub(crate) max_output_bytes: usize,
}

impl CheckerOutputCaptureConfig {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        for reference in [&self.raw_output_type_ref, &self.retention_profile_ref] {
            if reference.contract_id.trim().is_empty()
                || reference.version.trim().is_empty()
                || reference.sha256.len() != 64
                || !reference
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("checker_output_capture.contract_ref");
            }
        }
        if self.collector_principal_id.trim().is_empty()
            || self.artifact_authority_principal_id.trim().is_empty()
            || self.collector_principal_id == self.artifact_authority_principal_id
        {
            return Err("checker_output_capture.principal");
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > 64 * 1024 * 1024 {
            return Err("checker_output_capture.max_output_bytes");
        }
        Ok(())
    }
}

pub(crate) struct ConfiguredCheckerOutputSink {
    intake: VerificationResultArtifactIntake,
    max_output_bytes: usize,
}

impl ConfiguredCheckerOutputSink {
    pub(crate) fn new(
        artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
        verification: Arc<Mutex<VerificationAuthority>>,
        admission: DerivedWorkspaceAdmissionHandle,
        config: CheckerOutputCaptureConfig,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        let max_output_bytes = config.max_output_bytes;
        let intake = VerificationResultArtifactIntake::new(
            artifact,
            verification,
            admission,
            VerificationOutputPolicy::raw_output_only(
                config.raw_output_type_ref,
                config.retention_profile_ref,
                config.collector_principal_id,
                config.artifact_authority_principal_id,
                max_output_bytes,
            ),
        )
        .map_err(|_| "checker_output_capture.policy")?;
        Ok(Self {
            intake,
            max_output_bytes,
        })
    }
}

impl CheckerOutputSink for ConfiguredCheckerOutputSink {
    fn capture(
        &self,
        request: &VerificationRequest,
        run_id: &str,
        profile: &CheckerProfile,
        output_key: &str,
        bytes: &[u8],
    ) -> Result<SealedCheckerOutput, String> {
        if bytes.is_empty() {
            return Err("CHECKER_OUTPUT_CAPTURE_EMPTY".to_owned());
        }
        if bytes.len() > self.max_output_bytes {
            return Err("CHECKER_OUTPUT_CAPTURE_TOO_LARGE".to_owned());
        }
        self.intake
            .capture(VerificationOutputRequest {
                verification_request_id: &request.verification_request_id,
                verification_run_id: run_id,
                checker_profile_id: &profile.checker_profile_id,
                role: CheckerOutputRole::RawOutput,
                output_key,
                media_type: "application/json",
                bytes,
            })
            .map(|sealed| SealedCheckerOutput {
                artifact_id: sealed.artifact_id,
                address: sealed.content,
            })
            .map_err(capture_failure_code)
    }
}

fn capture_failure_code(error: VerificationOutputError) -> String {
    match error {
        VerificationOutputError::Invalid => "CHECKER_OUTPUT_CAPTURE_INVALID",
        VerificationOutputError::Binding => "CHECKER_OUTPUT_CAPTURE_BINDING",
        VerificationOutputError::Unavailable => "CHECKER_OUTPUT_CAPTURE_UNAVAILABLE",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn config() -> CheckerOutputCaptureConfig {
        CheckerOutputCaptureConfig {
            raw_output_type_ref: reference("verification-raw-output"),
            retention_profile_ref: reference("verification-records"),
            collector_principal_id: "collector:checker-output".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
            max_output_bytes: 4096,
        }
    }

    #[test]
    fn a_declared_capture_names_its_contracts_and_principals() {
        assert_eq!(config().validate(), Ok(()));
    }

    #[test]
    fn a_capture_that_cannot_be_deployed_is_refused_before_any_execution() {
        let mut missing_contract = config();
        missing_contract.raw_output_type_ref.sha256 = "ab".to_owned();
        assert_eq!(
            missing_contract.validate(),
            Err("checker_output_capture.contract_ref")
        );

        let mut shared_principal = config();
        shared_principal.artifact_authority_principal_id =
            shared_principal.collector_principal_id.clone();
        assert_eq!(
            shared_principal.validate(),
            Err("checker_output_capture.principal")
        );

        let mut unbounded = config();
        unbounded.max_output_bytes = 0;
        assert_eq!(
            unbounded.validate(),
            Err("checker_output_capture.max_output_bytes")
        );
    }
}
