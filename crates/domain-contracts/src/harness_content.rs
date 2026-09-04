//! Canonical R9C safe Harness-content identities.
//!
//! These helpers encode the frozen disclosure profile. Producers and derived
//! consumers use the same contract oracle, while every trust boundary still
//! recomputes and compares the supplied identity instead of trusting it.

use sha2::{Digest, Sha256};

use crate::{
    profiles::{
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
    },
    v01::egopulse::harness::v1::{
        ContentMutationOperation, HarnessContentLimitKind, HarnessContentMarkerKind,
        HarnessContentSafetyFlag, LifecycleKind, SafeArtifactRelationContent,
        SafeAssistantTextContent, SafeContentMarker, SafeHarnessContentRecord,
        SafeLifecycleContent, SafeUsageContent, SideEffectCertainty, safe_harness_content_record,
    },
};

const SAFE_RECORD_ID_DOMAIN: &str = "egopulse/harness-content/safe-record-id/v1";
const SAFE_RECORD_DOMAIN: &str = "egopulse/harness-content/safe-record/v1";
const SAFE_ASSISTANT_DOMAIN: &str = "egopulse/harness-content/safe-assistant-text/v1";
const SAFE_LIFECYCLE_DOMAIN: &str = "egopulse/harness-content/safe-lifecycle/v1";
const SAFE_USAGE_DOMAIN: &str = "egopulse/harness-content/safe-usage/v1";
const SAFE_APPROVAL_DOMAIN: &str = "egopulse/harness-content/safe-approval-required/v1";
const SAFE_ARTIFACT_DOMAIN: &str = "egopulse/harness-content/safe-artifact-relation/v1";
const SAFE_MARKER_DOMAIN: &str = "egopulse/harness-content/safe-marker/v1";

/// Recompute the stable safe-record identifier from the frozen source/profile
/// tuple and payload discriminator. Assistant parts add their zero-based part
/// index; structured records use zero.
#[must_use]
pub fn canonical_safe_harness_content_record_id(
    record: &SafeHarnessContentRecord,
) -> Option<String> {
    let profile = valid_profile(record)?;
    let payload = record.payload.as_ref()?;
    let (kind, limit_kind, _) = safe_payload_digest(payload)?;
    if !canonical_sha256(&record.content_event_id) {
        return None;
    }
    let part_index = match payload {
        safe_harness_content_record::Payload::AssistantText(value) => value.part_index,
        _ => 0,
    };
    let mut bytes = Vec::new();
    for value in [
        SAFE_RECORD_ID_DOMAIN,
        record.content_event_id.as_str(),
        profile.contract_id.as_str(),
        profile.version.as_str(),
        profile.sha256.as_str(),
        kind,
        limit_kind,
    ] {
        frame(&mut bytes, value.as_bytes());
    }
    frame(&mut bytes, &part_index.to_le_bytes());
    Some(format!("hcr_{}", sha256(&bytes)))
}

/// Recompute the canonical digest of a safe record. The stored digest field is
/// deliberately excluded from its own preimage.
#[must_use]
pub fn canonical_safe_harness_content_record_digest(
    record: &SafeHarnessContentRecord,
) -> Option<String> {
    let profile = valid_profile(record)?;
    let payload = record.payload.as_ref()?;
    let (kind, _, payload_digest) = safe_payload_digest(payload)?;
    if record.record_id != canonical_safe_harness_content_record_id(record)?
        || record.task_id.trim().is_empty()
        || record.run_id.trim().is_empty()
        || record.step_id.trim().is_empty()
        || record.attempt_id.trim().is_empty()
        || record.dispatch_id.trim().is_empty()
        || record.fencing_token == 0
        || !canonical_sha256(&record.route_binding_sha256)
        || record.provider_family_alias.trim().is_empty()
        || record.model_alias.trim().is_empty()
        || record.collaboration_role.trim().is_empty()
        || !valid_safety_flags(&record.safety_flags)
    {
        return None;
    }

    let mut bytes = Vec::new();
    for value in [
        SAFE_RECORD_DOMAIN,
        record.record_id.as_str(),
        record.content_event_id.as_str(),
        record.task_id.as_str(),
        record.run_id.as_str(),
        record.step_id.as_str(),
        record.attempt_id.as_str(),
        record.dispatch_id.as_str(),
    ] {
        frame(&mut bytes, value.as_bytes());
    }
    frame(&mut bytes, &record.fencing_token.to_le_bytes());
    for value in [
        record.route_binding_sha256.as_str(),
        profile.contract_id.as_str(),
        profile.version.as_str(),
        profile.sha256.as_str(),
        record.provider_family_alias.as_str(),
        record.model_alias.as_str(),
        record.collaboration_role.as_str(),
    ] {
        frame(&mut bytes, value.as_bytes());
    }
    frame(
        &mut bytes,
        &(record.safety_flags.len() as u64).to_le_bytes(),
    );
    for flag in &record.safety_flags {
        frame(&mut bytes, &(*flag as u64).to_le_bytes());
    }
    frame(&mut bytes, kind.as_bytes());
    frame(&mut bytes, payload_digest.as_bytes());
    Some(sha256(&bytes))
}

fn valid_profile(
    record: &SafeHarnessContentRecord,
) -> Option<&crate::v01::egopulse::common::v1::ContractReference> {
    let profile = record.disclosure_profile_ref.as_ref()?;
    (profile.contract_id == HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        && profile.version == HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
        && profile.sha256 == HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256)
        .then_some(profile)
}

fn valid_safety_flags(flags: &[i32]) -> bool {
    let mut previous = None;
    for value in flags {
        let Ok(flag) = HarnessContentSafetyFlag::try_from(*value) else {
            return false;
        };
        if flag == HarnessContentSafetyFlag::Unspecified
            || previous.is_some_and(|prior| prior >= *value)
        {
            return false;
        }
        previous = Some(*value);
    }
    true
}

fn safe_payload_digest(
    payload: &safe_harness_content_record::Payload,
) -> Option<(&'static str, &'static str, String)> {
    match payload {
        safe_harness_content_record::Payload::AssistantText(value) => {
            safe_assistant_digest(value).map(|digest| ("ASSISTANT_TEXT", "UNSPECIFIED", digest))
        }
        safe_harness_content_record::Payload::Lifecycle(value) => {
            safe_lifecycle_digest(value).map(|digest| ("LIFECYCLE", "UNSPECIFIED", digest))
        }
        safe_harness_content_record::Payload::Usage(value) => {
            Some(("USAGE", "UNSPECIFIED", safe_usage_digest(value)))
        }
        safe_harness_content_record::Payload::ApprovalRequired(_) => Some((
            "APPROVAL_REQUIRED",
            "UNSPECIFIED",
            framed_digest(SAFE_APPROVAL_DOMAIN, &[]),
        )),
        safe_harness_content_record::Payload::ArtifactRelation(value) => {
            safe_artifact_relation_digest(value)
                .map(|digest| ("ARTIFACT_RELATION", "UNSPECIFIED", digest))
        }
        safe_harness_content_record::Payload::Marker(value) => {
            safe_marker_digest(value).map(|(limit_kind, digest)| ("MARKER", limit_kind, digest))
        }
    }
}

fn safe_assistant_digest(value: &SafeAssistantTextContent) -> Option<String> {
    let operation = ContentMutationOperation::try_from(value.operation).ok()?;
    if value.safe_message_id.trim().is_empty()
        || operation == ContentMutationOperation::Unspecified
        || value.revision == 0
        || value.previous_revision >= value.revision
        || !canonical_sha256(&value.safe_cumulative_digest_sha256)
        || value.part_count == 0
        || value.part_index >= value.part_count
    {
        return None;
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_ASSISTANT_DOMAIN.as_bytes());
    frame(&mut bytes, value.safe_message_id.as_bytes());
    frame(&mut bytes, &value.revision.to_le_bytes());
    frame(&mut bytes, &value.previous_revision.to_le_bytes());
    frame(
        &mut bytes,
        short_name(operation.as_str_name(), "CONTENT_MUTATION_OPERATION_")?.as_bytes(),
    );
    frame(&mut bytes, value.safe_text_utf8.as_bytes());
    frame(&mut bytes, value.safe_cumulative_digest_sha256.as_bytes());
    frame(&mut bytes, &value.part_index.to_le_bytes());
    frame(&mut bytes, &value.part_count.to_le_bytes());
    Some(sha256(&bytes))
}

fn safe_lifecycle_digest(value: &SafeLifecycleContent) -> Option<String> {
    let kind = LifecycleKind::try_from(value.kind).ok()?;
    let certainty = SideEffectCertainty::try_from(value.side_effect_certainty).ok()?;
    if kind == LifecycleKind::Unspecified || certainty == SideEffectCertainty::Unspecified {
        return None;
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_LIFECYCLE_DOMAIN.as_bytes());
    frame(
        &mut bytes,
        short_name(kind.as_str_name(), "LIFECYCLE_KIND_")?.as_bytes(),
    );
    frame(
        &mut bytes,
        short_name(certainty.as_str_name(), "SIDE_EFFECT_CERTAINTY_")?.as_bytes(),
    );
    match value.native_will_retry {
        Some(retry) => {
            frame(&mut bytes, b"SOME");
            frame(&mut bytes, &u64::from(retry).to_le_bytes());
        }
        None => {
            frame(&mut bytes, b"NONE");
            frame(&mut bytes, &[]);
        }
    }
    Some(sha256(&bytes))
}

fn safe_usage_digest(value: &SafeUsageContent) -> String {
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_USAGE_DOMAIN.as_bytes());
    frame(&mut bytes, &value.input_tokens.to_le_bytes());
    frame(&mut bytes, &value.output_tokens.to_le_bytes());
    match value.cached_input_tokens {
        Some(cached) => {
            frame(&mut bytes, b"SOME");
            frame(&mut bytes, &cached.to_le_bytes());
        }
        None => {
            frame(&mut bytes, b"NONE");
            frame(&mut bytes, &[]);
        }
    }
    sha256(&bytes)
}

fn safe_artifact_relation_digest(value: &SafeArtifactRelationContent) -> Option<String> {
    let artifact = value.artifact.as_ref()?;
    if artifact.artifact_id.trim().is_empty() || !canonical_sha256(&artifact.artifact_digest_sha256)
    {
        return None;
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_ARTIFACT_DOMAIN.as_bytes());
    frame(
        &mut bytes,
        &u64::from(value.safe_content_differs_from_artifact).to_le_bytes(),
    );
    frame(&mut bytes, artifact.artifact_id.as_bytes());
    frame(&mut bytes, artifact.artifact_digest_sha256.as_bytes());
    Some(sha256(&bytes))
}

fn safe_marker_digest(value: &SafeContentMarker) -> Option<(&'static str, String)> {
    let kind = HarnessContentMarkerKind::try_from(value.kind).ok()?;
    let limit_kind = HarnessContentLimitKind::try_from(value.limit_kind).ok()?;
    if kind == HarnessContentMarkerKind::Unspecified {
        return None;
    }
    let canonical_limit_kind = match (kind, limit_kind) {
        (HarnessContentMarkerKind::LimitReached, HarnessContentLimitKind::Unspecified) => {
            return None;
        }
        (HarnessContentMarkerKind::LimitReached, value) => {
            short_name(value.as_str_name(), "HARNESS_CONTENT_LIMIT_KIND_")?
        }
        (_, HarnessContentLimitKind::Unspecified) => "UNSPECIFIED",
        _ => return None,
    };
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_MARKER_DOMAIN.as_bytes());
    frame(
        &mut bytes,
        short_name(kind.as_str_name(), "HARNESS_CONTENT_MARKER_KIND_")?.as_bytes(),
    );
    frame(&mut bytes, canonical_limit_kind.as_bytes());
    Some((canonical_limit_kind, sha256(&bytes)))
}

fn short_name<'a>(full: &'a str, prefix: &str) -> Option<&'a str> {
    full.strip_prefix(prefix)
}

fn framed_digest(domain: &str, value: &[u8]) -> String {
    let mut bytes = Vec::new();
    frame(&mut bytes, domain.as_bytes());
    frame(&mut bytes, value);
    sha256(&bytes)
}

fn frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::{SafeAssistantTextContent, safe_harness_content_record},
    };

    #[test]
    fn frozen_safe_record_vector_matches_shared_oracle() {
        // Independent literal values from
        // valid-content-append-not-context-bound.json. Expected values are not
        // manufactured by this canonicalizer.
        let record = SafeHarnessContentRecord {
            record_id: "hcr_2d4a8740678287b4b680b1370cf550b45d579c18f54f2d7f1508386ec4486d6d"
                .to_owned(),
            record_digest_sha256:
                "f79bac6dba76c3045be2dca16cddcda1cf9f1414e2037d7c0b66b3b5b8b73c83".to_owned(),
            content_event_id: "8bf9b6392731854455807e7a35791f39e99e1c119bc0d43c0bcdf813fdc768c3"
                .to_owned(),
            task_id: "task-001".to_owned(),
            run_id: "run-001".to_owned(),
            step_id: "step-001".to_owned(),
            attempt_id: "attempt-001".to_owned(),
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 3,
            route_binding_sha256:
                "5fc3d40c5d3ecdc61ccac5826e0e2d0b10131133adcd8a5ca8438188c01c39a8".to_owned(),
            disclosure_profile_ref: Some(ContractReference {
                contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
                version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
                sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
            }),
            provider_family_alias: "openai".to_owned(),
            model_alias: "gpt-5.6-sol".to_owned(),
            collaboration_role: "primary".to_owned(),
            safety_flags: vec![
                HarnessContentSafetyFlag::ControlRedacted as i32,
                HarnessContentSafetyFlag::CredentialRedacted as i32,
                HarnessContentSafetyFlag::Provisional as i32,
            ],
            payload: Some(safe_harness_content_record::Payload::AssistantText(
                SafeAssistantTextContent {
                    safe_message_id:
                        "hcm_b060407711409ba70a1affd38e053f313e27c549d9bfb6c2312415adf28f229a"
                            .to_owned(),
                    revision: 1,
                    previous_revision: 0,
                    operation: ContentMutationOperation::Append as i32,
                    safe_text_utf8: "Hello,\nworld!    ".to_owned(),
                    safe_cumulative_digest_sha256:
                        "51b7cf9b02c27b407880e537b5bfa722bcd3e82e284c8d9152ab613894568e77"
                            .to_owned(),
                    part_index: 0,
                    part_count: 1,
                },
            )),
        };
        assert_eq!(
            canonical_safe_harness_content_record_id(&record).as_deref(),
            Some(record.record_id.as_str())
        );
        assert_eq!(
            canonical_safe_harness_content_record_digest(&record).as_deref(),
            Some(record.record_digest_sha256.as_str())
        );
    }
}
