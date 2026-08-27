use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::StepPlan,
    common::v1::ContractReference,
    harness::v1::{
        AttestationLevel, CapabilityDeclaration, CapabilityProfile, CapabilityProfileStatus,
        NativeProtocolFingerprint,
    },
};
use egopulse_harness_adapter::{CapabilityBindingError, validate_step_capability_binding};
use prost_types::Timestamp;

const PROFILE_ID: &str = "profile:codex";
const PROFILE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn step_plan_binding_matrix_requires_active_probe_attested_profile() {
    let plan = [step(Some(profile_ref())), step(None)];
    let profile = profile();
    let now = Timestamp {
        seconds: 50,
        nanos: 0,
    };

    assert_eq!(
        validate_step_capability_binding(&plan[0], "codex", &profile, &now),
        Ok(())
    );
    assert_eq!(
        validate_step_capability_binding(&plan[1], "codex", &profile, &now),
        Err(CapabilityBindingError::RequiredProfileMissing)
    );

    let cases = [
        (
            "digest drift",
            {
                let mut value = profile_ref();
                value.sha256 = "cd".repeat(32);
                value
            },
            profile.clone(),
            "codex",
            CapabilityBindingError::ProfileDigestMismatch,
        ),
        (
            "inactive",
            profile_ref(),
            CapabilityProfile {
                status: CapabilityProfileStatus::Candidate as i32,
                ..profile.clone()
            },
            "codex",
            CapabilityBindingError::ProfileInactive,
        ),
        (
            "declared only",
            profile_ref(),
            CapabilityProfile {
                attestation_level: AttestationLevel::Declared as i32,
                ..profile.clone()
            },
            "codex",
            CapabilityBindingError::AttestationInsufficient,
        ),
        (
            "model family drift",
            profile_ref(),
            profile.clone(),
            "kimi",
            CapabilityBindingError::SelectorMismatch,
        ),
        (
            "expired",
            profile_ref(),
            profile.clone(),
            "codex",
            CapabilityBindingError::ValidityWindowInvalid,
        ),
    ];

    for (name, reference, candidate, selector, expected) in cases {
        let case_step = step(Some(reference));
        let case_now = if name == "expired" {
            Timestamp {
                seconds: 100,
                nanos: 0,
            }
        } else {
            now
        };
        assert_eq!(
            validate_step_capability_binding(&case_step, selector, &candidate, &case_now),
            Err(expected),
            "fixture case: {name}"
        );
    }
}

fn step(required: Option<ContractReference>) -> StepPlan {
    StepPlan {
        step_id: "step-g4-09".to_owned(),
        step_kind: "governed-work".to_owned(),
        input_bundle_ref: "bundle-g4-09".to_owned(),
        required_capability_profile_ref: required,
        ..StepPlan::default()
    }
}

fn profile_ref() -> ContractReference {
    ContractReference {
        contract_id: PROFILE_ID.to_owned(),
        version: "v1".to_owned(),
        sha256: PROFILE_DIGEST.to_owned(),
    }
}

fn profile() -> CapabilityProfile {
    CapabilityProfile {
        profile_id: PROFILE_ID.to_owned(),
        revision: 1,
        digest_sha256: PROFILE_DIGEST.to_owned(),
        status: CapabilityProfileStatus::Active as i32,
        declaration: Some(CapabilityDeclaration {
            declaration_id: "declaration:codex".to_owned(),
            adapter_id: "codex-adapter".to_owned(),
            harness_id: "codex".to_owned(),
            model_family_selectors: vec!["codex".to_owned()],
            native_protocol: Some(NativeProtocolFingerprint {
                protocol_name: "provider-native-protocol".to_owned(),
                protocol_version: "v2".to_owned(),
                ..NativeProtocolFingerprint::default()
            }),
            ..CapabilityDeclaration::default()
        }),
        attestation_level: AttestationLevel::ProbeVerified as i32,
        attestation_evidence_refs: vec!["probe://codex/g4-09".to_owned()],
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
