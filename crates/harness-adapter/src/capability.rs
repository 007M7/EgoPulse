use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::StepPlan,
    common::v1::ContractReference,
    harness::v1::{AttestationLevel, CapabilityProfile, CapabilityProfileStatus},
};
use prost_types::Timestamp;
use thiserror::Error;

/// Validates the immutable workflow-to-Harness capability binding before a
/// native driver is started. It does not select a provider and it does not
/// inspect provider-private protocol data.
pub fn validate_step_capability_binding(
    step: &StepPlan,
    model_family_selector: &str,
    profile: &CapabilityProfile,
    now: &Timestamp,
) -> Result<(), CapabilityBindingError> {
    let required_profile_ref = step
        .required_capability_profile_ref
        .as_ref()
        .ok_or(CapabilityBindingError::RequiredProfileMissing)?;
    validate_capability_binding(required_profile_ref, model_family_selector, profile, now)
}

/// Validates the immutable workflow-to-Harness capability binding before a
/// native driver is started. It does not select a provider and it does not
/// inspect provider-private protocol data.
pub fn validate_capability_binding(
    required_profile_ref: &ContractReference,
    model_family_selector: &str,
    profile: &CapabilityProfile,
    now: &Timestamp,
) -> Result<(), CapabilityBindingError> {
    if required_profile_ref.contract_id.trim().is_empty()
        || required_profile_ref.version.trim().is_empty()
        || required_profile_ref.sha256.len() != 64
        || !required_profile_ref
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || model_family_selector.trim().is_empty()
    {
        return Err(CapabilityBindingError::InvalidRequirement);
    }
    if profile.profile_id != required_profile_ref.contract_id
        || !profile
            .digest_sha256
            .eq_ignore_ascii_case(&required_profile_ref.sha256)
    {
        return Err(CapabilityBindingError::ProfileDigestMismatch);
    }
    if CapabilityProfileStatus::try_from(profile.status) != Ok(CapabilityProfileStatus::Active) {
        return Err(CapabilityBindingError::ProfileInactive);
    }
    if AttestationLevel::try_from(profile.attestation_level) != Ok(AttestationLevel::ProbeVerified)
        || profile.attestation_evidence_refs.is_empty()
    {
        return Err(CapabilityBindingError::AttestationInsufficient);
    }
    let declaration = profile
        .declaration
        .as_ref()
        .ok_or(CapabilityBindingError::DeclarationMissing)?;
    if declaration.adapter_id.trim().is_empty()
        || declaration.harness_id.trim().is_empty()
        || !declaration
            .model_family_selectors
            .iter()
            .any(|selector| selector == model_family_selector)
    {
        return Err(CapabilityBindingError::SelectorMismatch);
    }
    if let Some(activated_at) = profile.activated_at.as_ref()
        && timestamp_cmp(activated_at, now).is_gt()
    {
        return Err(CapabilityBindingError::ValidityWindowInvalid);
    }
    if let Some(valid_until) = profile.valid_until.as_ref()
        && timestamp_cmp(valid_until, now).is_le()
    {
        return Err(CapabilityBindingError::ValidityWindowInvalid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum CapabilityBindingError {
    #[error("workflow step does not declare a required capability profile")]
    RequiredProfileMissing,
    #[error("capability binding requirement is incomplete or malformed")]
    InvalidRequirement,
    #[error("capability profile ID or digest does not match the workflow binding")]
    ProfileDigestMismatch,
    #[error("capability profile is not active")]
    ProfileInactive,
    #[error("capability profile is not probe-attested")]
    AttestationInsufficient,
    #[error("capability profile declaration is missing")]
    DeclarationMissing,
    #[error("capability profile does not match the requested model family")]
    SelectorMismatch,
    #[error("capability profile validity window is not current")]
    ValidityWindowInvalid,
}

fn timestamp_cmp(left: &Timestamp, right: &Timestamp) -> std::cmp::Ordering {
    left.seconds
        .cmp(&right.seconds)
        .then(left.nanos.cmp(&right.nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        CapabilityDeclaration, NativeProtocolFingerprint,
    };

    fn profile() -> CapabilityProfile {
        CapabilityProfile {
            profile_id: "profile:codex".to_owned(),
            revision: 1,
            digest_sha256: "ab".repeat(32),
            status: CapabilityProfileStatus::Active as i32,
            declaration: Some(CapabilityDeclaration {
                adapter_id: "codex-adapter".to_owned(),
                harness_id: "codex".to_owned(),
                model_family_selectors: vec!["codex".to_owned()],
                native_protocol: Some(NativeProtocolFingerprint {
                    protocol_name: "native-harness-protocol".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            attestation_level: AttestationLevel::ProbeVerified as i32,
            attestation_evidence_refs: vec!["probe://codex/1".to_owned()],
            activated_at: Some(Timestamp {
                seconds: 10,
                nanos: 0,
            }),
            valid_until: Some(Timestamp {
                seconds: 100,
                nanos: 0,
            }),
        }
    }

    fn profile_ref() -> ContractReference {
        ContractReference {
            contract_id: "profile:codex".to_owned(),
            version: "v1".to_owned(),
            sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn accepts_current_probe_attested_profile() {
        assert_eq!(
            validate_capability_binding(
                &profile_ref(),
                "codex",
                &profile(),
                &Timestamp {
                    seconds: 50,
                    nanos: 0
                },
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_digest_or_profile_id_drift() {
        let mut reference = profile_ref();
        reference.sha256 = "cd".repeat(32);
        assert_eq!(
            validate_capability_binding(
                &reference,
                "codex",
                &profile(),
                &Timestamp {
                    seconds: 50,
                    nanos: 0
                },
            ),
            Err(CapabilityBindingError::ProfileDigestMismatch)
        );
    }

    #[test]
    fn rejects_declared_only_profile() {
        let mut value = profile();
        value.attestation_level = AttestationLevel::Declared as i32;
        assert_eq!(
            validate_capability_binding(
                &profile_ref(),
                "codex",
                &value,
                &Timestamp {
                    seconds: 50,
                    nanos: 0
                },
            ),
            Err(CapabilityBindingError::AttestationInsufficient)
        );
    }

    #[test]
    fn rejects_model_selector_drift() {
        assert_eq!(
            validate_capability_binding(
                &profile_ref(),
                "kimi",
                &profile(),
                &Timestamp {
                    seconds: 50,
                    nanos: 0
                },
            ),
            Err(CapabilityBindingError::SelectorMismatch)
        );
    }

    #[test]
    fn rejects_expired_profile() {
        assert_eq!(
            validate_capability_binding(
                &profile_ref(),
                "codex",
                &profile(),
                &Timestamp {
                    seconds: 100,
                    nanos: 0
                },
            ),
            Err(CapabilityBindingError::ValidityWindowInvalid)
        );
    }
}
