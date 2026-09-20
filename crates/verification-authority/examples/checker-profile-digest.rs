//! Prints the canonical `profile_digest_sha256` of a checker profile file.
//!
//! A checker profile has to carry the canonical digest of its own fields, and
//! only this crate can compute it. Configuration authors read the profile JSON
//! from stdin and paste the printed digest back into
//! `verification_worker.checker_profile.profile_digest_sha256` instead of
//! guessing a value the Verification Authority will reject.
//!
//! ```text
//! cargo run -p egopulse-verification-authority --example checker-profile-digest < profile.json
//! ```
//!
//! Input is the checker-profile object exactly as the daemon configuration
//! spells it (snake_case fields, references as `{contract_id, version,
//! sha256}`). `revision`, `status`, `profile_digest_sha256` and `attested_at`
//! are ignored by canonicalization and may be omitted.

use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
};
use egopulse_verification_authority::canonical_checker_profile_digest;
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct ReferenceJson {
    contract_id: String,
    version: String,
    sha256: String,
}

impl ReferenceJson {
    fn into_typed(self) -> ContractReference {
        ContractReference {
            contract_id: self.contract_id,
            version: self.version,
            sha256: self.sha256,
        }
    }
}

#[derive(Deserialize)]
struct ProfileJson {
    checker_profile_id: String,
    checker_id: String,
    checker_version: String,
    supported_criterion_types: Vec<String>,
    assurance_class: i32,
    timeout_ms: u64,
    network_allowed: bool,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    status: i32,
    #[serde(default)]
    input_contract_ref: Option<ReferenceJson>,
    #[serde(default)]
    output_contract_ref: Option<ReferenceJson>,
    #[serde(default)]
    sandbox_profile_ref: Option<ReferenceJson>,
    #[serde(default)]
    tool_policy_ref: Option<ReferenceJson>,
    #[serde(default)]
    data_egress_policy_ref: Option<ReferenceJson>,
    #[serde(default)]
    attestation_evidence_artifact_ids: Vec<String>,
}

fn main() {
    let mut input = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("checker-profile-digest: cannot read stdin: {error}");
        std::process::exit(2);
    }
    let profile: ProfileJson = match serde_json::from_str(&input) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("checker-profile-digest: profile JSON is invalid: {error}");
            std::process::exit(2);
        }
    };
    if !(1..=4).contains(&profile.status) {
        eprintln!("checker-profile-digest: status must be a declared CheckerProfileStatus");
        std::process::exit(2);
    }
    if !(1..=3).contains(&profile.assurance_class) {
        eprintln!(
            "checker-profile-digest: assurance_class must be a declared CheckerAssuranceClass"
        );
        std::process::exit(2);
    }
    let candidate = CheckerProfile {
        checker_profile_id: profile.checker_profile_id,
        revision: profile.revision,
        status: profile.status,
        checker_id: profile.checker_id,
        checker_version: profile.checker_version,
        input_contract_ref: profile.input_contract_ref.map(ReferenceJson::into_typed),
        output_contract_ref: profile.output_contract_ref.map(ReferenceJson::into_typed),
        supported_criterion_types: profile.supported_criterion_types,
        assurance_class: profile.assurance_class,
        sandbox_profile_ref: profile.sandbox_profile_ref.map(ReferenceJson::into_typed),
        tool_policy_ref: profile.tool_policy_ref.map(ReferenceJson::into_typed),
        data_egress_policy_ref: profile
            .data_egress_policy_ref
            .map(ReferenceJson::into_typed),
        timeout_ms: profile.timeout_ms,
        network_allowed: profile.network_allowed,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: profile.attestation_evidence_artifact_ids,
        attested_at: None,
    };
    let _ = CheckerProfileStatus::try_from(candidate.status);
    let _ = CheckerAssuranceClass::try_from(candidate.assurance_class);
    println!("{}", canonical_checker_profile_digest(&candidate));
}
