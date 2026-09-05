//! Canonical binding for an immutable, admitted work-capability route.
//!
//! Every canonical field is framed as `u64_le(byte_length) || bytes`. The
//! route binding digest is the output and is therefore not part of its own
//! preimage. Strings are used exactly as supplied; this module never trims or
//! normalizes an accepted identity.

use crate::v01::egopulse::task::v1::WorkCapabilityRouteBinding;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const WORK_CAPABILITY_ROUTE_DOMAIN_SEPARATOR: &str = "egopulse/work-capability-route/v1";
pub const WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES: usize = 256;

const OPTIONAL_NONE: &str = "NONE";
const OPTIONAL_SOME: &str = "SOME";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkCapabilityRouteBindingError {
    #[error("work-capability route identity is missing: {0}")]
    MissingIdentity(&'static str),
    #[error("work-capability route identity exceeds its byte limit: {0}")]
    IdentityTooLong(&'static str),
    #[error("work-capability route identity has non-canonical whitespace or control bytes: {0}")]
    InvalidIdentityFormat(&'static str),
    #[error("work-capability route generation must be positive")]
    InvalidRouteGeneration,
    #[error("work-capability route capability profile reference is missing")]
    MissingCapabilityProfileReference,
    #[error("work-capability route SHA-256 is not canonical lowercase hex: {0}")]
    InvalidSha256(&'static str),
    #[error("work-capability route binding digest does not match its canonical fields")]
    DigestMismatch,
}

/// Returns the canonical digest preimage for all immutable route fields.
///
/// Field order is domain separator, route ID, route generation as eight-byte
/// little-endian, provider profile ID, provider ID, harness ID, harness model
/// ID, provider model ID, the capability contract ID/version/SHA-256 triple,
/// catalog presence (`NONE` or `SOME`), catalog value (empty for `NONE`), and
/// native composition generation. Every item, including the presence and empty
/// value frames, has an eight-byte little-endian length prefix.
pub fn canonical_work_capability_route_bytes(
    binding: &WorkCapabilityRouteBinding,
) -> Result<Vec<u8>, WorkCapabilityRouteBindingError> {
    validate_bound_fields(binding)?;
    let profile = binding
        .capability_profile_ref
        .as_ref()
        .ok_or(WorkCapabilityRouteBindingError::MissingCapabilityProfileReference)?;

    let mut out = Vec::new();
    append_field(&mut out, WORK_CAPABILITY_ROUTE_DOMAIN_SEPARATOR.as_bytes());
    append_field(&mut out, binding.route_id.as_bytes());
    append_field(&mut out, &binding.route_generation.to_le_bytes());
    append_field(&mut out, binding.provider_profile_id.as_bytes());
    append_field(&mut out, binding.provider_id.as_bytes());
    append_field(&mut out, binding.harness_id.as_bytes());
    append_field(&mut out, binding.harness_model_id.as_bytes());
    append_field(&mut out, binding.provider_model_id.as_bytes());
    append_field(&mut out, profile.contract_id.as_bytes());
    append_field(&mut out, profile.version.as_bytes());
    append_field(&mut out, profile.sha256.as_bytes());
    match binding.catalog_snapshot_sha256.as_deref() {
        Some(digest) => {
            append_field(&mut out, OPTIONAL_SOME.as_bytes());
            append_field(&mut out, digest.as_bytes());
        }
        None => {
            append_field(&mut out, OPTIONAL_NONE.as_bytes());
            append_field(&mut out, b"");
        }
    }
    append_field(&mut out, binding.native_composition_generation.as_bytes());
    Ok(out)
}

/// Computes the lowercase SHA-256 binding without trusting a stored digest.
pub fn compute_work_capability_route_binding_sha256(
    binding: &WorkCapabilityRouteBinding,
) -> Result<String, WorkCapabilityRouteBindingError> {
    Ok(hex::encode(Sha256::digest(
        canonical_work_capability_route_bytes(binding)?,
    )))
}

/// Seals an unsealed route, or verifies an already-sealed route before
/// returning it. A conflicting supplied digest is never silently replaced.
pub fn seal_work_capability_route_binding(
    mut binding: WorkCapabilityRouteBinding,
) -> Result<WorkCapabilityRouteBinding, WorkCapabilityRouteBindingError> {
    let expected = compute_work_capability_route_binding_sha256(&binding)?;
    if !binding.route_binding_sha256.is_empty() {
        validate_sha256("route_binding_sha256", &binding.route_binding_sha256)?;
        if binding.route_binding_sha256 != expected {
            return Err(WorkCapabilityRouteBindingError::DigestMismatch);
        }
    }
    binding.route_binding_sha256 = expected;
    Ok(binding)
}

/// Validates structure and proves that the stored digest binds every canonical
/// route field.
pub fn validate_work_capability_route_binding(
    binding: &WorkCapabilityRouteBinding,
) -> Result<(), WorkCapabilityRouteBindingError> {
    validate_sha256("route_binding_sha256", &binding.route_binding_sha256)?;
    let expected = compute_work_capability_route_binding_sha256(binding)?;
    if binding.route_binding_sha256 != expected {
        return Err(WorkCapabilityRouteBindingError::DigestMismatch);
    }
    Ok(())
}

fn validate_bound_fields(
    binding: &WorkCapabilityRouteBinding,
) -> Result<(), WorkCapabilityRouteBindingError> {
    for (field, value) in [
        ("route_id", binding.route_id.as_str()),
        ("provider_profile_id", binding.provider_profile_id.as_str()),
        ("provider_id", binding.provider_id.as_str()),
        ("harness_id", binding.harness_id.as_str()),
        ("harness_model_id", binding.harness_model_id.as_str()),
        ("provider_model_id", binding.provider_model_id.as_str()),
        (
            "native_composition_generation",
            binding.native_composition_generation.as_str(),
        ),
    ] {
        validate_identity(field, value)?;
    }
    if binding.route_generation == 0 {
        return Err(WorkCapabilityRouteBindingError::InvalidRouteGeneration);
    }

    let profile = binding
        .capability_profile_ref
        .as_ref()
        .ok_or(WorkCapabilityRouteBindingError::MissingCapabilityProfileReference)?;
    validate_identity("capability_profile_ref.contract_id", &profile.contract_id)?;
    validate_identity("capability_profile_ref.version", &profile.version)?;
    validate_sha256("capability_profile_ref.sha256", &profile.sha256)?;

    if let Some(digest) = binding.catalog_snapshot_sha256.as_deref() {
        validate_sha256("catalog_snapshot_sha256", digest)?;
    }
    Ok(())
}

fn validate_identity(
    field: &'static str,
    value: &str,
) -> Result<(), WorkCapabilityRouteBindingError> {
    if value.trim().is_empty() {
        return Err(WorkCapabilityRouteBindingError::MissingIdentity(field));
    }
    if value.len() > WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES {
        return Err(WorkCapabilityRouteBindingError::IdentityTooLong(field));
    }
    if value != value.trim() || value.chars().any(char::is_control) {
        return Err(WorkCapabilityRouteBindingError::InvalidIdentityFormat(
            field,
        ));
    }
    Ok(())
}

fn validate_sha256(
    field: &'static str,
    value: &str,
) -> Result<(), WorkCapabilityRouteBindingError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WorkCapabilityRouteBindingError::InvalidSha256(field));
    }
    Ok(())
}

fn append_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v01::egopulse::common::v1::ContractReference;

    fn unsealed_binding() -> WorkCapabilityRouteBinding {
        WorkCapabilityRouteBinding {
            route_id: "route:codex:gpt-5".to_owned(),
            route_generation: 7,
            provider_profile_id: "provider-profile:openai".to_owned(),
            provider_id: "provider:openai".to_owned(),
            harness_id: "harness:codex".to_owned(),
            harness_model_id: "gpt-5".to_owned(),
            provider_model_id: "openai:gpt-5".to_owned(),
            capability_profile_ref: Some(ContractReference {
                contract_id: "egopulse.harness.codex".to_owned(),
                version: "1.0.0".to_owned(),
                sha256: "a".repeat(64),
            }),
            catalog_snapshot_sha256: Some("b".repeat(64)),
            native_composition_generation: "codex-native:v3".to_owned(),
            route_binding_sha256: String::new(),
        }
    }

    #[test]
    fn work_capability_seal_and_validate_bind_a_stable_canonical_vector() {
        let binding = unsealed_binding();
        let canonical = canonical_work_capability_route_bytes(&binding).expect("canonical route");
        let sealed = seal_work_capability_route_binding(binding).expect("sealed route");

        assert_eq!(
            hex::encode(canonical),
            "210000000000000065676f70756c73652f776f726b2d6361706162696c6974792d726f7574652f76311100000000000000726f7574653a636f6465783a6770742d3508000000000000000700000000000000170000000000000070726f76696465722d70726f66696c653a6f70656e61690f0000000000000070726f76696465723a6f70656e61690d000000000000006861726e6573733a636f64657805000000000000006770742d350c000000000000006f70656e61693a6770742d35160000000000000065676f70756c73652e6861726e6573732e636f6465780500000000000000312e302e304000000000000000616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610400000000000000534f4d454000000000000000626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620f00000000000000636f6465782d6e61746976653a7633"
        );
        assert_eq!(
            sealed.route_binding_sha256,
            "f6a1c576bd3de059194ca98250cf193e405d87809253be5dd5b96f31fcc578d8"
        );
        assert_eq!(validate_work_capability_route_binding(&sealed), Ok(()));
        assert_eq!(
            seal_work_capability_route_binding(sealed.clone()),
            Ok(sealed)
        );
    }

    #[test]
    fn work_capability_every_bound_field_changes_the_digest() {
        let baseline = unsealed_binding();
        let digest = compute_work_capability_route_binding_sha256(&baseline).expect("baseline");
        let mut variants = Vec::new();

        macro_rules! variant {
            ($change:expr) => {{
                let mut value = baseline.clone();
                $change(&mut value);
                variants.push(value);
            }};
        }

        variant!(|value: &mut WorkCapabilityRouteBinding| value.route_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.route_generation += 1);
        variant!(|value: &mut WorkCapabilityRouteBinding| value.provider_profile_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.provider_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.harness_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.harness_model_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.provider_model_id.push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value
            .capability_profile_ref
            .as_mut()
            .unwrap()
            .contract_id
            .push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value
            .capability_profile_ref
            .as_mut()
            .unwrap()
            .version
            .push('2'));
        variant!(|value: &mut WorkCapabilityRouteBinding| value
            .capability_profile_ref
            .as_mut()
            .unwrap()
            .sha256 = "c".repeat(64));
        variant!(|value: &mut WorkCapabilityRouteBinding| value.catalog_snapshot_sha256 = None);
        variant!(
            |value: &mut WorkCapabilityRouteBinding| value.catalog_snapshot_sha256 =
                Some("c".repeat(64))
        );
        variant!(|value: &mut WorkCapabilityRouteBinding| value
            .native_composition_generation
            .push('2'));

        assert_eq!(variants.len(), 13);
        for variant in variants {
            assert_ne!(
                compute_work_capability_route_binding_sha256(&variant).expect("valid variant"),
                digest
            );
        }
    }

    #[test]
    fn work_capability_missing_or_oversized_identity_fails_closed() {
        type Mutator = fn(&mut WorkCapabilityRouteBinding);
        let missing: [Mutator; 9] = [
            |value| value.route_id.clear(),
            |value| value.provider_profile_id = "  ".to_owned(),
            |value| value.provider_id.clear(),
            |value| value.harness_id.clear(),
            |value| value.harness_model_id.clear(),
            |value| value.provider_model_id.clear(),
            |value| value.native_composition_generation.clear(),
            |value| {
                value
                    .capability_profile_ref
                    .as_mut()
                    .unwrap()
                    .contract_id
                    .clear()
            },
            |value| {
                value
                    .capability_profile_ref
                    .as_mut()
                    .unwrap()
                    .version
                    .clear()
            },
        ];
        for mutate in missing {
            let mut value = unsealed_binding();
            mutate(&mut value);
            assert!(matches!(
                compute_work_capability_route_binding_sha256(&value),
                Err(WorkCapabilityRouteBindingError::MissingIdentity(_))
            ));
        }

        let oversized: [Mutator; 9] = [
            |value| value.route_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1),
            |value| {
                value.provider_profile_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
            |value| value.provider_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1),
            |value| value.harness_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1),
            |value| {
                value.harness_model_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
            |value| {
                value.provider_model_id = "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
            |value| {
                value.native_composition_generation =
                    "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
            |value| {
                value.capability_profile_ref.as_mut().unwrap().contract_id =
                    "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
            |value| {
                value.capability_profile_ref.as_mut().unwrap().version =
                    "x".repeat(WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES + 1)
            },
        ];
        for mutate in oversized {
            let mut value = unsealed_binding();
            mutate(&mut value);
            assert!(matches!(
                compute_work_capability_route_binding_sha256(&value),
                Err(WorkCapabilityRouteBindingError::IdentityTooLong(_))
            ));
        }

        let mut missing_profile = unsealed_binding();
        missing_profile.capability_profile_ref = None;
        assert_eq!(
            compute_work_capability_route_binding_sha256(&missing_profile),
            Err(WorkCapabilityRouteBindingError::MissingCapabilityProfileReference)
        );

        let mut zero_generation = unsealed_binding();
        zero_generation.route_generation = 0;
        assert_eq!(
            compute_work_capability_route_binding_sha256(&zero_generation),
            Err(WorkCapabilityRouteBindingError::InvalidRouteGeneration)
        );
    }

    #[test]
    fn work_capability_non_canonical_identity_fails_closed() {
        type Mutator = fn(&mut WorkCapabilityRouteBinding);
        let invalid: [Mutator; 4] = [
            |value| value.route_id = " route:codex:gpt-5".to_owned(),
            |value| value.provider_profile_id = "provider-profile:openai ".to_owned(),
            |value| value.harness_model_id = "gpt-5\n".to_owned(),
            |value| value.capability_profile_ref.as_mut().unwrap().version = "1.0.0\t".to_owned(),
        ];
        for mutate in invalid {
            let mut value = unsealed_binding();
            mutate(&mut value);
            assert!(matches!(
                compute_work_capability_route_binding_sha256(&value),
                Err(WorkCapabilityRouteBindingError::InvalidIdentityFormat(_))
            ));
        }
    }

    #[test]
    fn work_capability_hashes_and_stored_digest_fail_closed() {
        for invalid in ["", &"A".repeat(64), &"g".repeat(64), &"a".repeat(63)] {
            let mut profile_hash = unsealed_binding();
            profile_hash.capability_profile_ref.as_mut().unwrap().sha256 = invalid.to_owned();
            assert!(matches!(
                compute_work_capability_route_binding_sha256(&profile_hash),
                Err(WorkCapabilityRouteBindingError::InvalidSha256(
                    "capability_profile_ref.sha256"
                ))
            ));

            let mut catalog_hash = unsealed_binding();
            catalog_hash.catalog_snapshot_sha256 = Some(invalid.to_owned());
            assert!(matches!(
                compute_work_capability_route_binding_sha256(&catalog_hash),
                Err(WorkCapabilityRouteBindingError::InvalidSha256(
                    "catalog_snapshot_sha256"
                ))
            ));
        }

        let sealed = seal_work_capability_route_binding(unsealed_binding()).expect("sealed");
        let mut malformed = sealed.clone();
        malformed.route_binding_sha256 = "A".repeat(64);
        assert!(matches!(
            validate_work_capability_route_binding(&malformed),
            Err(WorkCapabilityRouteBindingError::InvalidSha256(
                "route_binding_sha256"
            ))
        ));

        let mut mismatch = sealed.clone();
        mismatch.route_binding_sha256 = "f".repeat(64);
        assert_eq!(
            validate_work_capability_route_binding(&mismatch),
            Err(WorkCapabilityRouteBindingError::DigestMismatch)
        );
        assert_eq!(
            seal_work_capability_route_binding(mismatch),
            Err(WorkCapabilityRouteBindingError::DigestMismatch)
        );
    }

    #[test]
    fn work_capability_optional_presence_is_canonical_and_unambiguous() {
        let mut absent = unsealed_binding();
        absent.catalog_snapshot_sha256 = None;
        let absent = canonical_work_capability_route_bytes(&absent).expect("absent catalog");
        let present =
            canonical_work_capability_route_bytes(&unsealed_binding()).expect("present catalog");

        assert_ne!(absent, present);
        assert!(absent.windows(4).any(|window| window == b"NONE"));
        assert!(present.windows(4).any(|window| window == b"SOME"));
    }
}
