use std::collections::BTreeSet;

use egopulse_domain_contracts::{
    profiles::{ContractProfileError, ContractProfiles},
    v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::{
            AssistantTextContentCandidate, ContentMutationOperation,
            DispatchContextConsumptionProof, DispatchRouteBinding, HarnessContentCompactionReason,
            HarnessContentHistoryCompactionRecord, HarnessContentLimitKind,
            HarnessContentMarkerKind, HarnessContentRetentionReason,
            HarnessContentRetentionTombstone, HarnessContentSafetyFlag, LifecycleContentCandidate,
            LifecycleKind, SafeAssistantTextContent, SafeContentMarker,
            SafeHarnessContentProjectionEvent, SafeHarnessContentRecord, SideEffectCertainty,
            UserVisibleContentCandidate, safe_harness_content_projection_event,
            safe_harness_content_record,
        },
        localapi::v1::{
            HarnessArtifactRelationView, HarnessContentRecordView, HarnessContentResetReason,
            HarnessContentResetRequiredFrame, HarnessContentStreamFrame,
            ListHarnessContentResponse,
        },
    },
};
use prost::Message;
use serde_json::Value;
use sha2::{Digest, Sha256};

const HARNESS_PROTO: &str =
    include_str!("../../../contracts/proto/egopulse/harness/v1/harness.proto");
const LOCAL_API_PROTO: &str =
    include_str!("../../../contracts/proto/egopulse/localapi/v1/local_api.proto");
const PERSISTENCE_PROTO: &str =
    include_str!("../../../contracts/proto/egopulse/persistence/v1/persistence.proto");
const DISCLOSURE_PROFILE: &str =
    include_str!("../../../contracts/profiles/harness-content-disclosure/v1/v01-default.json");
const VALID_HARNESS_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/harness/v1/valid-content-append-not-context-bound.json"
);
const VALID_DISPATCH_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/harness/v1/valid-dispatch-delivery.json");
const AUTHORIZED_CONTEXT_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/harness/v1/valid-content-authorized-context.json");
const NO_CATALOG_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/harness/v1/valid-route-binding-no-catalog.json");
const FORBIDDEN_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/harness/v1/invalid-content-forbidden-category.json");
const SOURCE_DRIFT_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/harness/v1/invalid-content-source-binding-drift.json"
);
const REVISION_DRIFT_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/harness/v1/invalid-content-revision-digest-drift.json"
);
const DUPLICATE_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/harness/v1/duplicate-content-exact-replay.json");
const BASELINE_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/localapi/v1/valid-harness-content-baseline.json");
const WATCH_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/localapi/v1/valid-harness-content-watch.json");
const INVALID_FRAME_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/localapi/v1/invalid-harness-content-frame-combination.json"
);
const UNAUTHORIZED_FIXTURE: &str =
    include_str!("../../../contracts/fixtures/localapi/v1/unauthorized-harness-content-read.json");
const RESET_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/localapi/v1/recovery-harness-content-retention-reset.json"
);
const PERSISTENCE_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/persistence/v1/recovery-safe-content-outbox-after-consumer-commit.json"
);
const PREWRITE_MIGRATION_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/persistence/v1/recovery-r9c-prewrite-migration-backup-restore.json"
);
const POSTWRITE_MIGRATION_FIXTURE: &str = include_str!(
    "../../../contracts/fixtures/persistence/v1/recovery-r9c-postwrite-forward-disable.json"
);
const MANIFEST: &str = include_str!("../../../contracts/manifest.json");

const R9C_AUTHORITY: &str =
    "conversation:2026-09-04:founder-froze-r9c-d01-d12-and-phase-2-82-section-7";

fn json(source: &str) -> Value {
    serde_json::from_str(source).expect("frozen JSON parses")
}

fn framed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

fn framed_text(out: &mut Vec<u8>, value: &str) {
    framed(out, value.as_bytes());
}

fn framed_u64(out: &mut Vec<u8>, value: u64) {
    framed(out, &value.to_le_bytes());
}

fn framed_u32(out: &mut Vec<u8>, value: u32) {
    framed(out, &value.to_le_bytes());
}

fn framed_i64(out: &mut Vec<u8>, value: i64) {
    framed(out, &value.to_le_bytes());
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn safe_record_canonical_bytes(
    record: &SafeHarnessContentRecord,
    payload_discriminator: &str,
    payload_digest_sha256: &str,
) -> Vec<u8> {
    let profile = record
        .disclosure_profile_ref
        .as_ref()
        .expect("safe record profile");
    let mut bytes = Vec::new();
    for value in [
        "egopulse/harness-content/safe-record/v1",
        record.record_id.as_str(),
        record.content_event_id.as_str(),
        record.task_id.as_str(),
        record.run_id.as_str(),
        record.step_id.as_str(),
        record.attempt_id.as_str(),
        record.dispatch_id.as_str(),
    ] {
        framed_text(&mut bytes, value);
    }
    framed_u64(&mut bytes, record.fencing_token);
    for value in [
        record.route_binding_sha256.as_str(),
        profile.contract_id.as_str(),
        profile.version.as_str(),
        profile.sha256.as_str(),
        record.provider_family_alias.as_str(),
        record.model_alias.as_str(),
        record.collaboration_role.as_str(),
    ] {
        framed_text(&mut bytes, value);
    }
    framed_u64(&mut bytes, record.safety_flags.len() as u64);
    for flag in &record.safety_flags {
        framed_u64(
            &mut bytes,
            u64::try_from(*flag).expect("non-negative safety flag"),
        );
    }
    framed_text(&mut bytes, payload_discriminator);
    framed_text(&mut bytes, payload_digest_sha256);
    bytes
}

fn committed_records_canonical_bytes(records: &[SafeHarnessContentRecord]) -> Vec<u8> {
    let mut bytes = Vec::new();
    framed_text(&mut bytes, "egopulse/harness-content/committed-records/v1");
    framed_u64(&mut bytes, records.len() as u64);
    for record in records {
        framed(&mut bytes, &record.encode_to_vec());
    }
    bytes
}

fn canonical_json_content_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn canonical_percent_uppercase(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(*byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn base64_encode(value: &[u8], url_safe: bool, padded: bool) -> String {
    let alphabet = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut encoded = String::new();
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(alphabet[(first >> 2) as usize]));
        encoded.push(char::from(
            alphabet[(((first & 0x03) << 4) | (second >> 4)) as usize],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                alphabet[(((second & 0x0f) << 2) | (third >> 6)) as usize],
            ));
        } else if padded {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(char::from(alphabet[(third & 0x3f) as usize]));
        } else if padded {
            encoded.push('=');
        }
    }
    encoded
}

fn scan_exact_pattern(chunks: &[&[u8]], pattern: &[u8]) -> (bool, Vec<u8>) {
    let mut pending = Vec::new();
    let mut disclosed = Vec::new();
    let mut matched = false;
    for byte in chunks.iter().flat_map(|chunk| chunk.iter().copied()) {
        pending.push(byte);
        loop {
            if pattern.starts_with(&pending) {
                if pending.len() == pattern.len() {
                    matched = true;
                    pending.clear();
                }
                break;
            }
            disclosed.push(pending.remove(0));
            if pending.is_empty() {
                break;
            }
        }
    }
    disclosed.extend_from_slice(&pending);
    (matched, disclosed)
}

fn route_binding_bytes(
    provider_bootstrap_profile_id: &str,
    harness_id: &str,
    model_id: &str,
    catalog_snapshot_kind: &str,
    catalog_snapshot_value: &str,
    capability_profile_id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    for value in [
        "egopulse/harness-content/route-binding/v1",
        provider_bootstrap_profile_id,
        harness_id,
        model_id,
        catalog_snapshot_kind,
        catalog_snapshot_value,
        capability_profile_id,
    ] {
        framed_text(&mut out, value);
    }
    out
}

fn message_block<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("message {name} {{");
    let start = source.find(&marker).expect("message exists");
    let bytes = source.as_bytes();
    let mut depth = 0_u32;
    for index in start..bytes.len() {
        match bytes[index] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=index];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated message {name}");
}

fn message_field_inventory(source: &str, name: &str) -> Vec<String> {
    let mut oneof = None;
    let mut inventory = Vec::new();
    for line in message_block(source, name).lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(value) = line
            .strip_prefix("oneof ")
            .and_then(|value| value.strip_suffix(" {"))
        {
            oneof = Some(value.to_owned());
            continue;
        }
        if line == "}" {
            if oneof.take().is_some() {
                continue;
            }
            break;
        }
        let Some(declaration) = line.strip_suffix(';') else {
            continue;
        };
        let (left, right) = declaration.split_once(" = ").expect("field assignment");
        let number = right.split_whitespace().next().expect("field number");
        let mut parts = left.split_whitespace();
        let first = parts.next().expect("field type");
        let (scope, field_type) = if matches!(first, "optional" | "repeated") {
            (
                first.to_owned(),
                parts.next().expect("qualified field type"),
            )
        } else if let Some(oneof_name) = oneof.as_deref() {
            (format!("oneof:{oneof_name}"), first)
        } else {
            ("field".to_owned(), first)
        };
        let field_name = parts.next().expect("field name");
        assert!(
            parts.next().is_none(),
            "unexpected field declaration: {line}"
        );
        inventory.push(format!("{scope}|{field_name}|{number}|{field_type}"));
    }
    inventory
}

fn assert_exact_message_inventory(source: &str, name: &str, expected: &[&str]) {
    assert_eq!(message_field_inventory(source, name), expected);
}

#[test]
fn r9c_d01_provider_neutral_safe_model_excludes_raw_terminal_shape() {
    let typed = HarnessContentRecordView::default();
    assert!(typed.payload.is_none());
    assert!(typed.safety_flags.is_empty());
    let public = message_block(LOCAL_API_PROTO, "HarnessContentRecordView");
    for required in [
        "string record_id",
        "string task_id",
        "string attempt_id",
        "string provider_family_alias",
        "string model_alias",
        "oneof payload",
    ] {
        assert!(
            public.contains(required),
            "missing public safe field {required}"
        );
    }
    for forbidden in [
        "raw_evidence",
        "native_event",
        "native_routing",
        "native_session",
        "native_execution",
        "route_binding",
        "raw_cumulative",
        "credential",
    ] {
        assert!(!public.contains(forbidden), "public DTO leaked {forbidden}");
    }
    assert!(LOCAL_API_PROTO.contains("rpc ListHarnessContent"));
    assert!(LOCAL_API_PROTO.contains("rpc WatchHarnessContent"));
    assert_exact_message_inventory(
        LOCAL_API_PROTO,
        "HarnessContentRecordView",
        &[
            "field|record_id|1|string",
            "field|record_digest_sha256|2|string",
            "field|content_sequence|3|uint64",
            "field|task_id|4|string",
            "field|attempt_id|5|string",
            "field|provider_family_alias|6|string",
            "field|model_alias|7|string",
            "field|collaboration_role|8|string",
            "field|disclosure_profile_ref|9|egopulse.common.v1.ContractReference",
            "field|projected_at|10|google.protobuf.Timestamp",
            "repeated|safety_flags|11|egopulse.harness.v1.HarnessContentSafetyFlag",
            "oneof:payload|assistant_text|20|HarnessAssistantTextView",
            "oneof:payload|lifecycle|21|HarnessLifecycleContentView",
            "oneof:payload|usage|22|HarnessUsageContentView",
            "oneof:payload|approval_required|23|HarnessApprovalRequiredContentView",
            "oneof:payload|artifact_relation|24|HarnessArtifactRelationView",
            "oneof:payload|marker|25|HarnessContentMarkerView",
        ],
    );
    assert_exact_message_inventory(
        LOCAL_API_PROTO,
        "HarnessArtifactIdentityView",
        &[
            "field|artifact_id|1|string",
            "field|artifact_digest_sha256|2|string",
        ],
    );
    assert_exact_message_inventory(
        LOCAL_API_PROTO,
        "HarnessContentMarkerView",
        &[
            "field|kind|1|egopulse.harness.v1.HarnessContentMarkerKind",
            "field|limit_kind|2|egopulse.harness.v1.HarnessContentLimitKind",
        ],
    );
    assert_exact_message_inventory(
        HARNESS_PROTO,
        "SafeContentMarker",
        &[
            "field|kind|1|HarnessContentMarkerKind",
            "field|limit_kind|2|HarnessContentLimitKind",
        ],
    );
}

#[test]
fn r9c_d02_candidate_safe_projection_and_authority_boundaries_are_closed() {
    let harness = json(VALID_HARNESS_FIXTURE);
    assert!(
        harness["command"]["ingestObservation"]["contentSignal"]["candidate"]
            ["assistantText"]["textUtf8Hex"]
            .is_string()
    );
    assert_eq!(harness["expected"]["taskAuthorityWriteCount"], 0);
    let persistence = json(PERSISTENCE_FIXTURE);
    assert_eq!(persistence["expected"]["authorityBusinessWriteCount"], 0);
    assert_eq!(persistence["expected"]["rawCandidateReadByConsumer"], false);
    assert_eq!(persistence["expected"]["sameSafeRecordReplayed"], true);
    assert!(HARNESS_PROTO.contains("message SafeHarnessContentRecord"));
    assert!(!LOCAL_API_PROTO.contains("message UserVisibleContentCandidate"));
}

#[test]
fn r9c_d03_source_binding_context_branches_and_operations_are_fixed() {
    let fixture = json(VALID_HARNESS_FIXTURE);
    let dispatch = json(VALID_DISPATCH_FIXTURE);
    let binding = &dispatch["command"]["dispatch"]["routeBinding"];
    let vectors = &fixture["canonicalVectors"];
    let route = route_binding_bytes(
        binding["providerBootstrapProfileId"].as_str().unwrap(),
        binding["selectedHarnessId"].as_str().unwrap(),
        binding["providerModelId"].as_str().unwrap(),
        "DIGEST",
        binding["catalogSnapshotSha256"].as_str().unwrap(),
        binding["capabilityProfileId"].as_str().unwrap(),
    );
    assert_eq!(hex::encode(&route), vectors["routeBindingHex"]);
    assert_eq!(digest(&route), vectors["routeBindingSha256"]);

    let text =
        hex::decode(
            fixture["command"]["ingestObservation"]["contentSignal"]["candidate"]["assistantText"]
                ["textUtf8Hex"]
                .as_str()
                .expect("text hex"),
        )
        .expect("valid text hex");
    let mut candidate = Vec::new();
    framed_text(&mut candidate, "egopulse/harness-content/text-candidate/v1");
    framed_text(&mut candidate, "msg-safe-001");
    framed_u64(&mut candidate, 1);
    framed_u64(&mut candidate, 0);
    framed_text(&mut candidate, "APPEND");
    framed(&mut candidate, &text);
    for value in [
        "7fc849816061c35cc7d05023a41064e6df98009688072686b66916e7ea6f36af",
        "87daed9be3cf1353adde646397681802b85f5dff8321d313e339229c92bdba28",
        "3f5278a253c9e81ad98f135a3d0262abbfa5f551a222d5060b83dc5d1f5330df",
    ] {
        framed_text(&mut candidate, value);
    }
    assert_eq!(digest(&candidate), vectors["candidateSha256"]);

    let mut event = Vec::new();
    for value in [
        "egopulse/harness-content/event/v1",
        "receipt-001",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "NOT_CONTEXT_BOUND",
        "",
        "",
        "5fc3d40c5d3ecdc61ccac5826e0e2d0b10131133adcd8a5ca8438188c01c39a8",
        "attempt-001",
        "dispatch-001",
    ] {
        framed_text(&mut event, value);
    }
    framed_u64(&mut event, 3);
    for value in [
        fixture["command"]["ingestObservation"]["capabilityProfileId"]
            .as_str()
            .unwrap(),
        "native-event-001",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    ] {
        framed_text(&mut event, value);
    }
    framed_u64(&mut event, 7);
    framed_text(
        &mut event,
        "97de32300fc9f29a2482e2e46917a1caa2ffd14218ca795847ebb682ea81843f",
    );
    assert_eq!(digest(&event), vectors["contentEventSha256"]);

    let no_catalog = json(NO_CATALOG_FIXTURE);
    let no_catalog_route = &no_catalog["command"]["dispatch"]["routeBinding"];
    let no_catalog_bytes = route_binding_bytes(
        no_catalog_route["providerBootstrapProfileId"]
            .as_str()
            .unwrap(),
        no_catalog_route["selectedHarnessId"].as_str().unwrap(),
        no_catalog_route["providerModelId"].as_str().unwrap(),
        "NO_CATALOG",
        "",
        no_catalog_route["capabilityProfileId"].as_str().unwrap(),
    );
    assert_eq!(
        hex::encode(&no_catalog_bytes),
        no_catalog["canonicalVector"]["routeBindingHex"]
    );
    assert_eq!(
        digest(&no_catalog_bytes),
        no_catalog["canonicalVector"]["routeBindingSha256"]
    );

    let authorized = json(AUTHORIZED_CONTEXT_FIXTURE);
    let authorized_command = &authorized["command"]["ingestObservation"];
    let authorized_signal = &authorized_command["contentSignal"];
    let mut lifecycle = Vec::new();
    for value in [
        "egopulse/harness-content/lifecycle-candidate/v1",
        "EXECUTION_STARTED",
        "NONE_PROVEN",
        "SOME",
    ] {
        framed_text(&mut lifecycle, value);
    }
    framed_u64(&mut lifecycle, 1);
    assert_eq!(
        hex::encode(&lifecycle),
        authorized["canonicalVectors"]["lifecycleCandidateHex"]
    );
    assert_eq!(
        digest(&lifecycle),
        authorized["canonicalVectors"]["lifecycleCandidateSha256"]
    );

    let proof = &authorized_signal["contextConsumptionProof"]["authorizedContext"];
    let mut authorized_event = Vec::new();
    for value in [
        "egopulse/harness-content/event/v1",
        authorized_signal["deliveredReceiptId"].as_str().unwrap(),
        authorized_signal["deliveredReceiptDigestSha256"]
            .as_str()
            .unwrap(),
        "AUTHORIZED_CONTEXT",
        proof["authorizationId"].as_str().unwrap(),
        proof["committedRequestDigestSha256"].as_str().unwrap(),
        authorized_signal["dispatchRouteBindingSha256"]
            .as_str()
            .unwrap(),
        authorized_command["attemptId"].as_str().unwrap(),
        authorized_command["dispatchId"].as_str().unwrap(),
    ] {
        framed_text(&mut authorized_event, value);
    }
    framed_u64(
        &mut authorized_event,
        authorized_command["fencingToken"].as_u64().unwrap(),
    );
    for value in [
        authorized_command["capabilityProfileId"].as_str().unwrap(),
        authorized_command["nativeEventId"].as_str().unwrap(),
        authorized_command["nativeEventDigestSha256"]
            .as_str()
            .unwrap(),
    ] {
        framed_text(&mut authorized_event, value);
    }
    framed_u64(
        &mut authorized_event,
        authorized_command["nativeSequence"].as_u64().unwrap(),
    );
    framed_text(
        &mut authorized_event,
        authorized_signal["candidate"]["candidateDigestSha256"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        hex::encode(&authorized_event),
        authorized["canonicalVectors"]["contentEventHex"]
    );
    assert_eq!(
        digest(&authorized_event),
        authorized["canonicalVectors"]["contentEventSha256"]
    );
    assert!(HARNESS_PROTO.contains("NotContextBoundProof not_context_bound = 1"));
    assert!(HARNESS_PROTO.contains("AuthorizedContextConsumptionProof authorized_context = 2"));
}

#[test]
fn r9c_d04_allowlist_denylist_and_unknown_enums_fail_closed() {
    let profile = json(DISCLOSURE_PROFILE);
    assert_eq!(
        profile["contentCategories"]["allowed"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert_eq!(
        profile["contentCategories"]["forbidden"]
            .as_array()
            .unwrap()
            .len(),
        28
    );
    assert_eq!(
        profile["contentCategories"]["unknownCategory"],
        "blocked_marker_no_source_bytes"
    );
    let blocked = json(FORBIDDEN_FIXTURE);
    assert_eq!(
        blocked["expected"]["safeMarker"],
        "HARNESS_CONTENT_MARKER_KIND_FORBIDDEN_CATEGORY"
    );

    // Independent wire bytes: field 4 (operation), varint value 127.
    let decoded = AssistantTextContentCandidate::decode([0x20, 0x7f].as_slice())
        .expect("prost preserves unknown enum number");
    assert_eq!(decoded.operation, 127);
    assert!(ContentMutationOperation::try_from(decoded.operation).is_err());

    let safe_text = SafeAssistantTextContent::decode([0x20, 0x7f].as_slice()).unwrap();
    assert!(ContentMutationOperation::try_from(safe_text.operation).is_err());
    let marker = SafeContentMarker::decode([0x08, 0x7f].as_slice()).unwrap();
    assert!(HarnessContentMarkerKind::try_from(marker.kind).is_err());
    let limit = SafeContentMarker::decode([0x10, 0x7f].as_slice()).unwrap();
    assert!(HarnessContentLimitKind::try_from(limit.limit_kind).is_err());
    let marker_contract_is_valid = |value: &SafeContentMarker| {
        let Ok(marker_kind) = HarnessContentMarkerKind::try_from(value.kind) else {
            return false;
        };
        let Ok(limit_kind) = HarnessContentLimitKind::try_from(value.limit_kind) else {
            return false;
        };
        if marker_kind == HarnessContentMarkerKind::Unspecified {
            return false;
        }
        if marker_kind == HarnessContentMarkerKind::LimitReached {
            limit_kind != HarnessContentLimitKind::Unspecified
        } else {
            limit_kind == HarnessContentLimitKind::Unspecified
        }
    };
    assert!(marker_contract_is_valid(&SafeContentMarker {
        kind: HarnessContentMarkerKind::LimitReached as i32,
        limit_kind: HarnessContentLimitKind::TaskRecords as i32,
    }));
    assert!(marker_contract_is_valid(&SafeContentMarker {
        kind: HarnessContentMarkerKind::InvalidText as i32,
        limit_kind: HarnessContentLimitKind::Unspecified as i32,
    }));
    assert!(!marker_contract_is_valid(&SafeContentMarker {
        kind: HarnessContentMarkerKind::LimitReached as i32,
        limit_kind: HarnessContentLimitKind::Unspecified as i32,
    }));
    assert!(!marker_contract_is_valid(&SafeContentMarker {
        kind: HarnessContentMarkerKind::InvalidText as i32,
        limit_kind: HarnessContentLimitKind::TaskRecords as i32,
    }));
    let compaction =
        HarnessContentHistoryCompactionRecord::decode([0x58, 0x7f].as_slice()).unwrap();
    assert!(HarnessContentCompactionReason::try_from(compaction.reason).is_err());
    let tombstone = HarnessContentRetentionTombstone::decode([0x58, 0x7f].as_slice()).unwrap();
    assert!(HarnessContentRetentionReason::try_from(tombstone.reason).is_err());
    let lifecycle = LifecycleContentCandidate::decode([0x08, 0x7f, 0x10, 0x7f].as_slice()).unwrap();
    assert!(LifecycleKind::try_from(lifecycle.kind).is_err());
    assert!(SideEffectCertainty::try_from(lifecycle.side_effect_certainty).is_err());
    let safety = SafeHarnessContentRecord::decode([0x7a, 0x01, 0x7f].as_slice()).unwrap();
    assert_eq!(safety.safety_flags, [127]);
    assert!(HarnessContentSafetyFlag::try_from(safety.safety_flags[0]).is_err());
    // HarnessContentResetRequiredFrame.reason is enum field 1 (wire key 0x08).
    let reset = HarnessContentResetRequiredFrame::decode([0x08, 0x7f].as_slice())
        .expect("prost preserves unknown reset reason");
    assert_eq!(reset.reason, 127);
    assert!(HarnessContentResetReason::try_from(reset.reason).is_err());
}

#[test]
fn r9c_d05_disclosure_profile_and_literal_transform_vectors_are_frozen() {
    fn normalize(input: &str) -> String {
        let mut normalized_newlines = input.replace("\r\n", "\n").replace('\r', "\n");
        normalized_newlines = normalized_newlines
            .replace(['\u{2028}', '\u{2029}'], "\n")
            .replace('\t', "    ");
        normalized_newlines
            .chars()
            .map(|scalar| {
                let code = scalar as u32;
                let denied = (code < 0x20 && scalar != '\n')
                    || code == 0x7f
                    || (0x80..=0x9f).contains(&code)
                    || matches!(code, 0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069);
                if denied { '\u{fffd}' } else { scalar }
            })
            .collect()
    }

    assert_eq!(normalize("Hello,\r\nworld!\t"), "Hello,\nworld!    ");
    assert_eq!(normalize("a\rb\u{2028}c\u{2029}d"), "a\nb\nc\nd");
    assert_eq!(normalize("\u{1b}[31m\u{7f}\u{0085}\u{202e}"), "�[31m���");
    let invalid_utf8 = vec![0xff];
    assert!(std::str::from_utf8(&invalid_utf8).is_err());
    let profile = json(DISCLOSURE_PROFILE);
    assert_eq!(
        profile["managedCredentialRedaction"]["maxEncodedPatternBytes"],
        3072
    );
    assert_eq!(
        profile["managedCredentialRedaction"]["maxWithheldSuffixBytes"],
        3071
    );
    assert_eq!(
        profile["managedCredentialRedaction"]["variants"]
            .as_array()
            .unwrap()
            .len(),
        7
    );

    let fixture = json(VALID_HARNESS_FIXTURE);
    for vector in fixture["credentialVariantVectors"].as_array().unwrap() {
        let credential = vector["credentialUtf8"].as_str().unwrap();
        let bytes = credential.as_bytes();
        let expected = &vector["variants"];
        let variants = [
            ("rawAscii", credential.to_owned()),
            (
                "canonicalJsonContentEscape",
                canonical_json_content_escape(credential),
            ),
            (
                "canonicalPercentUppercase",
                canonical_percent_uppercase(bytes),
            ),
            ("base64StandardPadded", base64_encode(bytes, false, true)),
            ("base64StandardUnpadded", base64_encode(bytes, false, false)),
            ("base64urlPadded", base64_encode(bytes, true, true)),
            ("base64urlUnpadded", base64_encode(bytes, true, false)),
        ];
        for (name, actual) in variants {
            assert_eq!(actual, expected[name].as_str().unwrap(), "{name}");
            let pattern = actual.as_bytes();
            for split in 1..pattern.len() {
                let (matched, disclosed) =
                    scan_exact_pattern(&[&pattern[..split], &pattern[split..]], pattern);
                assert!(matched, "{name} failed at split {split}");
                assert!(disclosed.is_empty(), "{name} leaked at split {split}");
            }
            if pattern.len() > 1 {
                let (matched, disclosed) =
                    scan_exact_pattern(&[&pattern[..pattern.len() - 1]], pattern);
                assert!(!matched);
                assert_eq!(disclosed, pattern[..pattern.len() - 1]);
            }
        }
    }
    let boundaries = &fixture["streamingCredentialBoundaryContract"];
    assert_eq!(boundaries["maxCredentialBytes"], 1_024);
    assert_eq!(boundaries["maxPercentEncodedPatternBytes"], 3_072);
    assert_eq!(boundaries["maxProperPrefixWithheldBytes"], 3_071);
    let maximum_percent = canonical_percent_uppercase(&vec![b'!'; 1_024]);
    assert_eq!(maximum_percent.len(), 3_072);

    let vectors = &fixture["canonicalVectors"];
    let safe = &fixture["safeProjection"];
    let safe_text = safe["assistantText"]["safeTextUtf8"]
        .as_str()
        .unwrap()
        .as_bytes();
    let mut safe_cumulative = Vec::new();
    framed_text(
        &mut safe_cumulative,
        "egopulse/harness-content/safe-cumulative/v1",
    );
    framed(&mut safe_cumulative, safe_text);
    assert_eq!(hex::encode(&safe_cumulative), vectors["safeCumulativeHex"]);
    assert_eq!(digest(&safe_cumulative), vectors["safeCumulativeSha256"]);

    let signal = &fixture["command"]["ingestObservation"]["contentSignal"];
    let mut safe_message_id = Vec::new();
    for value in [
        "egopulse/harness-content/safe-message-id/v1",
        safe["attemptId"].as_str().unwrap(),
        safe["dispatchId"].as_str().unwrap(),
        safe["routeBindingSha256"].as_str().unwrap(),
        signal["candidate"]["assistantText"]["messageId"]
            .as_str()
            .unwrap(),
    ] {
        framed_text(&mut safe_message_id, value);
    }
    assert_eq!(hex::encode(&safe_message_id), vectors["safeMessageIdHex"]);
    assert_eq!(digest(&safe_message_id), vectors["safeMessageIdSha256"]);
    assert_eq!(
        safe["assistantText"]["safeMessageId"].as_str().unwrap(),
        format!("hcm_{}", digest(&safe_message_id))
    );

    let mut safe_payload = Vec::new();
    framed_text(
        &mut safe_payload,
        "egopulse/harness-content/safe-assistant-text/v1",
    );
    framed_text(
        &mut safe_payload,
        safe["assistantText"]["safeMessageId"].as_str().unwrap(),
    );
    framed_u64(
        &mut safe_payload,
        safe["assistantText"]["revision"].as_u64().unwrap(),
    );
    framed_u64(
        &mut safe_payload,
        safe["assistantText"]["previousRevision"].as_u64().unwrap(),
    );
    framed_text(&mut safe_payload, "APPEND");
    framed(&mut safe_payload, safe_text);
    framed_text(
        &mut safe_payload,
        safe["assistantText"]["safeCumulativeDigestSha256"]
            .as_str()
            .unwrap(),
    );
    framed_u32(
        &mut safe_payload,
        u32::try_from(safe["assistantText"]["partIndex"].as_u64().unwrap()).unwrap(),
    );
    framed_u32(
        &mut safe_payload,
        u32::try_from(safe["assistantText"]["partCount"].as_u64().unwrap()).unwrap(),
    );
    assert_eq!(
        hex::encode(&safe_payload),
        vectors["safeAssistantPayloadHex"]
    );
    assert_eq!(digest(&safe_payload), vectors["safeAssistantPayloadSha256"]);

    let profile_ref = &safe["disclosureProfileRef"];
    let mut record_id = Vec::new();
    for value in [
        "egopulse/harness-content/safe-record-id/v1",
        safe["contentEventId"].as_str().unwrap(),
        profile_ref["contractId"].as_str().unwrap(),
        profile_ref["version"].as_str().unwrap(),
        profile_ref["sha256"].as_str().unwrap(),
        "ASSISTANT_TEXT",
        "UNSPECIFIED",
    ] {
        framed_text(&mut record_id, value);
    }
    framed_u32(&mut record_id, 0);
    assert_eq!(hex::encode(&record_id), vectors["safeRecordIdHex"]);
    assert_eq!(digest(&record_id), vectors["safeRecordIdSha256"]);
    assert_eq!(
        safe["recordId"].as_str().unwrap(),
        format!("hcr_{}", digest(&record_id))
    );

    let mut record = Vec::new();
    for value in [
        "egopulse/harness-content/safe-record/v1",
        safe["recordId"].as_str().unwrap(),
        safe["contentEventId"].as_str().unwrap(),
        safe["taskId"].as_str().unwrap(),
        safe["runId"].as_str().unwrap(),
        safe["stepId"].as_str().unwrap(),
        safe["attemptId"].as_str().unwrap(),
        safe["dispatchId"].as_str().unwrap(),
    ] {
        framed_text(&mut record, value);
    }
    framed_u64(&mut record, safe["fencingToken"].as_u64().unwrap());
    for value in [
        safe["routeBindingSha256"].as_str().unwrap(),
        profile_ref["contractId"].as_str().unwrap(),
        profile_ref["version"].as_str().unwrap(),
        profile_ref["sha256"].as_str().unwrap(),
        safe["providerFamilyAlias"].as_str().unwrap(),
        safe["modelAlias"].as_str().unwrap(),
        safe["collaborationRole"].as_str().unwrap(),
    ] {
        framed_text(&mut record, value);
    }
    framed_u64(&mut record, 3);
    for flag in [1, 2, 4] {
        framed_u64(&mut record, flag);
    }
    framed_text(&mut record, "ASSISTANT_TEXT");
    framed_text(
        &mut record,
        vectors["safeAssistantPayloadSha256"].as_str().unwrap(),
    );
    assert_eq!(hex::encode(&record), vectors["safeRecordHex"]);
    assert_eq!(digest(&record), vectors["safeRecordSha256"]);
    assert_eq!(digest(&record), safe["recordDigestSha256"]);

    let limit_vectors = fixture["limitMarkerCanonicalVectors"]
        .as_array()
        .expect("typed limit vectors");
    let expected_limit_order = [
        "TASK_RECORDS",
        "TASK_TEXT_BYTES",
        "ATTEMPT_RECORDS",
        "ATTEMPT_TEXT_BYTES",
    ];
    assert_eq!(limit_vectors.len(), expected_limit_order.len());
    let typed_profile_ref = ContractReference {
        contract_id: profile_ref["contractId"].as_str().unwrap().to_owned(),
        version: profile_ref["version"].as_str().unwrap().to_owned(),
        sha256: profile_ref["sha256"].as_str().unwrap().to_owned(),
    };
    let typed_assistant_record = SafeHarnessContentRecord {
        record_id: safe["recordId"].as_str().unwrap().to_owned(),
        record_digest_sha256: safe["recordDigestSha256"].as_str().unwrap().to_owned(),
        content_event_id: safe["contentEventId"].as_str().unwrap().to_owned(),
        task_id: safe["taskId"].as_str().unwrap().to_owned(),
        run_id: safe["runId"].as_str().unwrap().to_owned(),
        step_id: safe["stepId"].as_str().unwrap().to_owned(),
        attempt_id: safe["attemptId"].as_str().unwrap().to_owned(),
        dispatch_id: safe["dispatchId"].as_str().unwrap().to_owned(),
        fencing_token: safe["fencingToken"].as_u64().unwrap(),
        route_binding_sha256: safe["routeBindingSha256"].as_str().unwrap().to_owned(),
        disclosure_profile_ref: Some(typed_profile_ref.clone()),
        provider_family_alias: safe["providerFamilyAlias"].as_str().unwrap().to_owned(),
        model_alias: safe["modelAlias"].as_str().unwrap().to_owned(),
        collaboration_role: safe["collaborationRole"].as_str().unwrap().to_owned(),
        safety_flags: vec![
            HarnessContentSafetyFlag::ControlRedacted as i32,
            HarnessContentSafetyFlag::CredentialRedacted as i32,
            HarnessContentSafetyFlag::Provisional as i32,
        ],
        payload: Some(safe_harness_content_record::Payload::AssistantText(
            SafeAssistantTextContent {
                safe_message_id: safe["assistantText"]["safeMessageId"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                revision: safe["assistantText"]["revision"].as_u64().unwrap(),
                previous_revision: safe["assistantText"]["previousRevision"].as_u64().unwrap(),
                operation: ContentMutationOperation::Append as i32,
                safe_text_utf8: safe["assistantText"]["safeTextUtf8"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                safe_cumulative_digest_sha256: safe["assistantText"]["safeCumulativeDigestSha256"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                part_index: 0,
                part_count: 1,
            },
        )),
    };
    let mut limit_record_ids = BTreeSet::new();
    for (vector, expected_limit_kind) in limit_vectors.iter().zip(expected_limit_order) {
        assert_eq!(vector["markerKind"], "LIMIT_REACHED");
        assert_eq!(vector["limitKind"], expected_limit_kind);

        let mut marker = Vec::new();
        for value in [
            "egopulse/harness-content/safe-marker/v1",
            "LIMIT_REACHED",
            expected_limit_kind,
        ] {
            framed_text(&mut marker, value);
        }
        assert_eq!(hex::encode(&marker), vector["markerHex"]);
        assert_eq!(digest(&marker), vector["markerSha256"]);

        let mut limit_record_id = Vec::new();
        for value in [
            "egopulse/harness-content/safe-record-id/v1",
            safe["contentEventId"].as_str().unwrap(),
            profile_ref["contractId"].as_str().unwrap(),
            profile_ref["version"].as_str().unwrap(),
            profile_ref["sha256"].as_str().unwrap(),
            "MARKER",
            expected_limit_kind,
        ] {
            framed_text(&mut limit_record_id, value);
        }
        framed_u32(&mut limit_record_id, 0);
        assert_eq!(hex::encode(&limit_record_id), vector["recordIdHex"]);
        assert_eq!(digest(&limit_record_id), vector["recordIdSha256"]);
        assert!(limit_record_ids.insert(digest(&limit_record_id)));

        let typed_limit_kind = match expected_limit_kind {
            "TASK_RECORDS" => HarnessContentLimitKind::TaskRecords,
            "TASK_TEXT_BYTES" => HarnessContentLimitKind::TaskTextBytes,
            "ATTEMPT_RECORDS" => HarnessContentLimitKind::AttemptRecords,
            "ATTEMPT_TEXT_BYTES" => HarnessContentLimitKind::AttemptTextBytes,
            other => panic!("unexpected limit kind {other}"),
        };
        let marker_payload_digest = digest(&marker);
        let mut typed_marker_record = SafeHarnessContentRecord {
            record_id: format!("hcr_{}", vector["recordIdSha256"].as_str().unwrap()),
            content_event_id: safe["contentEventId"].as_str().unwrap().to_owned(),
            task_id: safe["taskId"].as_str().unwrap().to_owned(),
            run_id: safe["runId"].as_str().unwrap().to_owned(),
            step_id: safe["stepId"].as_str().unwrap().to_owned(),
            attempt_id: safe["attemptId"].as_str().unwrap().to_owned(),
            dispatch_id: safe["dispatchId"].as_str().unwrap().to_owned(),
            fencing_token: safe["fencingToken"].as_u64().unwrap(),
            route_binding_sha256: safe["routeBindingSha256"].as_str().unwrap().to_owned(),
            disclosure_profile_ref: Some(typed_profile_ref.clone()),
            provider_family_alias: safe["providerFamilyAlias"].as_str().unwrap().to_owned(),
            model_alias: safe["modelAlias"].as_str().unwrap().to_owned(),
            collaboration_role: safe["collaborationRole"].as_str().unwrap().to_owned(),
            payload: Some(safe_harness_content_record::Payload::Marker(
                SafeContentMarker {
                    kind: HarnessContentMarkerKind::LimitReached as i32,
                    limit_kind: typed_limit_kind as i32,
                },
            )),
            ..SafeHarnessContentRecord::default()
        };
        let typed_record_bytes =
            safe_record_canonical_bytes(&typed_marker_record, "MARKER", &marker_payload_digest);
        assert_eq!(digest(&typed_record_bytes), vector["recordSha256"]);
        typed_marker_record.record_digest_sha256 = digest(&typed_record_bytes);

        let projection_event = SafeHarnessContentProjectionEvent {
            payload: Some(
                safe_harness_content_projection_event::Payload::ContentRecord(
                    typed_marker_record.clone(),
                ),
            ),
        };
        assert_eq!(
            digest(&projection_event.encode_to_vec()),
            vector["projectionEventSha256"]
        );
        assert_eq!(
            digest(&committed_records_canonical_bytes(&[
                typed_marker_record.clone()
            ])),
            vector["markerOnlyCommittedRecordsSha256"]
        );
        assert_eq!(
            digest(&committed_records_canonical_bytes(&[
                typed_assistant_record.clone(),
                typed_marker_record,
            ])),
            vector["prefixThenMarkerCommittedRecordsSha256"]
        );
    }

    let additional = &fixture["additionalCandidateVectors"];
    let usage = &additional["usage"];
    let mut usage_bytes = Vec::new();
    framed_text(
        &mut usage_bytes,
        "egopulse/harness-content/usage-candidate/v1",
    );
    framed_u64(&mut usage_bytes, usage["inputTokens"].as_u64().unwrap());
    framed_u64(&mut usage_bytes, usage["outputTokens"].as_u64().unwrap());
    framed_text(&mut usage_bytes, "SOME");
    framed_u64(
        &mut usage_bytes,
        usage["cachedInputTokens"].as_u64().unwrap(),
    );
    assert_eq!(hex::encode(&usage_bytes), usage["canonicalHex"]);
    assert_eq!(digest(&usage_bytes), usage["candidateDigestSha256"]);

    let mut approval = Vec::new();
    framed_text(
        &mut approval,
        "egopulse/harness-content/approval-required-candidate/v1",
    );
    assert_eq!(
        hex::encode(&approval),
        additional["approvalRequired"]["canonicalHex"]
    );
    assert_eq!(
        digest(&approval),
        additional["approvalRequired"]["candidateDigestSha256"]
    );

    let mut blocked = Vec::new();
    framed_text(
        &mut blocked,
        "egopulse/harness-content/blocked-source-candidate/v1",
    );
    framed_text(&mut blocked, "FORBIDDEN_CATEGORY");
    assert_eq!(
        hex::encode(&blocked),
        additional["blockedSource"]["canonicalHex"]
    );
    assert_eq!(
        digest(&blocked),
        additional["blockedSource"]["candidateDigestSha256"]
    );
}

#[test]
fn r9c_d06_content_permission_rpc_and_profile_digests_are_exact() {
    let profiles = ContractProfiles::embedded().expect("frozen profiles load");
    let content = BTreeSet::from(["local.harness.content.read".to_owned()]);
    profiles
        .authorize_rpc("LocalReadModelService/ListHarnessContent", &content)
        .expect("content baseline permission");
    profiles
        .authorize_rpc("LocalReadModelService/WatchHarnessContent", &content)
        .expect("content watch permission");
    let unrelated = BTreeSet::from([
        "local.task.read".to_owned(),
        "local.approval.read".to_owned(),
        "local.evidence.read".to_owned(),
    ]);
    assert!(matches!(
        profiles.authorize_rpc("LocalReadModelService/ListHarnessContent", &unrelated),
        Err(ContractProfileError::PermissionDenied(permission))
            if permission == "local.harness.content.read"
    ));
    let unauthorized = json(UNAUTHORIZED_FIXTURE);
    assert_eq!(unauthorized["expected"]["readModelCallCount"], 0);
}

#[test]
fn r9c_d07_operation_record_stream_replay_and_reset_shapes_are_closed() {
    let baseline = json(BASELINE_FIXTURE);
    assert_eq!(baseline["expected"]["operationRecordStream"], true);
    assert_eq!(baseline["expected"]["completeSnapshotFrame"], false);
    let watch = json(WATCH_FIXTURE);
    assert_eq!(watch["expected"]["operationRecords"], true);
    assert_eq!(watch["expected"]["taskPositionCompared"], false);
    let reset = json(RESET_FIXTURE);
    assert_eq!(reset["expected"]["clientDiscardsIncompleteAssembly"], true);
    assert_eq!(reset["expected"]["taskStreamTerminated"], false);
    let duplicate = json(DUPLICATE_FIXTURE);
    assert_eq!(duplicate["expected"]["outcome"], "replayed");
    assert_exact_message_inventory(
        LOCAL_API_PROTO,
        "HarnessContentStreamFrame",
        &[
            "field|position|1|HarnessContentPosition",
            "oneof:payload|records|2|HarnessContentRecordsFrame",
            "oneof:payload|heartbeat|3|HarnessContentHeartbeatFrame",
            "oneof:payload|reset_required|4|HarnessContentResetRequiredFrame",
        ],
    );
    let invalid = json(INVALID_FRAME_FIXTURE);
    assert_eq!(
        invalid["fixtureId"],
        "localapi-invalid-harness-content-frame-combination"
    );
    let vectors = invalid["operation"]["watchHarnessContent"]["typedFrameVectors"]
        .as_array()
        .expect("typed frame vectors");
    assert_eq!(vectors.len(), 2);
    for (index, expected_case) in ["missing-payload", "unknown-payload"]
        .into_iter()
        .enumerate()
    {
        assert_eq!(vectors[index]["case"], expected_case);
        let bytes = hex::decode(
            vectors[index]["wireHex"]
                .as_str()
                .expect("typed frame wire hex"),
        )
        .expect("typed frame wire vector is hexadecimal");
        assert!(
            HarnessContentStreamFrame::decode(bytes.as_slice())
                .expect("typed content frame vector")
                .payload
                .is_none()
        );
    }
    assert_eq!(invalid["expected"]["recordsDelivered"], 0);
    assert_eq!(invalid["expected"]["assemblyMutated"], false);
    assert_eq!(
        invalid["expected"]["duplicateWireBranchRejectionClaimed"],
        false
    );
    assert_eq!(invalid["expected"]["missingPayloadBranchFailsClosed"], true);
    assert_eq!(invalid["expected"]["unknownPayloadBranchFailsClosed"], true);
    assert!(HARNESS_PROTO.contains("message SafeHarnessContentProjectionEvent"));
    assert!(HARNESS_PROTO.contains("HarnessContentHistoryCompactionRecord history_compaction = 2"));
    assert!(
        UserVisibleContentCandidate::decode([0x32, 0x00].as_slice())
            .unwrap()
            .payload
            .is_none()
    );
    assert!(
        DispatchContextConsumptionProof::decode([0x1a, 0x00].as_slice())
            .unwrap()
            .branch
            .is_none()
    );
    assert!(
        DispatchRouteBinding::decode([0x42, 0x00].as_slice())
            .unwrap()
            .catalog_snapshot
            .is_none()
    );
    assert!(
        SafeHarnessContentRecord::decode([0xa2, 0x02, 0x00].as_slice())
            .unwrap()
            .payload
            .is_none()
    );
    assert!(
        SafeHarnessContentProjectionEvent::decode([0x22, 0x00].as_slice())
            .unwrap()
            .payload
            .is_none()
    );
    assert!(
        HarnessContentStreamFrame::decode([0x2a, 0x00].as_slice())
            .unwrap()
            .payload
            .is_none()
    );
    for bytes in [&[][..], &[0xfa, 0x07, 0x00][..]] {
        assert!(
            HarnessArtifactRelationView::decode(bytes)
                .expect("typed artifact relation vector")
                .visibility
                .is_none()
        );
        assert!(
            HarnessContentRecordView::decode(bytes)
                .expect("typed content record vector")
                .payload
                .is_none()
        );
        assert!(
            ListHarnessContentResponse::decode(bytes)
                .expect("typed list response vector")
                .outcome
                .is_none()
        );
    }
}

#[test]
fn r9c_d08_limits_retention_and_pagination_vectors_are_exact() {
    let profile = json(DISCLOSURE_PROFILE);
    let limits = &profile["resourceLimits"];
    assert_eq!(limits["candidateTextBytes"], 65_536);
    assert_eq!(limits["safePartBytes"], 65_536);
    assert_eq!(limits["serializedFrameBytes"], 81_920);
    assert_eq!(limits["attemptSafeTextBytes"], 16_777_216);
    assert_eq!(limits["attemptSafeRecords"], 16_384);
    assert_eq!(limits["taskSafeTextBytes"], 67_108_864);
    assert_eq!(limits["taskSafeRecords"], 65_536);
    assert_eq!(limits["baselinePageRecords"], 256);
    assert_eq!(limits["baselinePageTextBytes"], 1_048_576);
    assert_eq!(limits["reservedFinalRecordSlot"], "LIMIT_REACHED");

    let exact = "a".repeat(65_536);
    assert_eq!(exact.floor_char_boundary(65_536), 65_536);
    let plus_one_scalar = format!("{}é", "a".repeat(65_535));
    assert_eq!(plus_one_scalar.len(), 65_537);
    assert_eq!(plus_one_scalar.floor_char_boundary(65_536), 65_535);
    assert_eq!(
        16_383_u64 + 1,
        limits["attemptSafeRecords"].as_u64().unwrap()
    );
    assert_eq!(65_535_u64 + 1, limits["taskSafeRecords"].as_u64().unwrap());
    let baseline = json(BASELINE_FIXTURE);
    let page = &baseline["boundaryCases"];
    assert_eq!(page["pageRecordLimit"]["exact"], 256);
    assert_eq!(page["pageRecordLimit"]["plusOne"], 257);
    assert_eq!(page["pageRecordLimit"]["recordsReturnedAtPlusOne"], 256);
    assert_eq!(page["pageRecordLimit"]["hasMoreAtPlusOne"], true);
    assert_eq!(page["pageTextByteLimit"]["partialRecordReturned"], false);
    assert_eq!(page["tamperedCursor"]["recordsReturned"], 0);
    assert_eq!(page["tamperedCursor"]["readModelRowsConsumed"], 0);
    assert_eq!(page["tamperedCursor"]["failsClosedBeforeRecordRead"], true);
    assert_eq!(
        profile["recoveryAndRetention"]["minimumSecondsAfterTaskTerminal"],
        2_592_000
    );
    let reset = json(RESET_FIXTURE);
    let tombstone = &reset["ownerRetentionTombstone"];
    assert_eq!(reset["expected"]["ownerTombstoneTyped"], true);
    assert_eq!(reset["expected"]["expiredContentResurrected"], false);
    let retention = &reset["retentionBoundary"];
    let terminal = retention["terminalCommittedAtSeconds"].as_i64().unwrap();
    let minimum = retention["minimumRetentionSeconds"].as_i64().unwrap();
    assert_eq!(
        terminal + minimum - 1,
        retention["oneSecondBeforeEligibleAtSeconds"]
    );
    assert_eq!(terminal + minimum, retention["firstEligibleAtSeconds"]);
    assert_eq!(retention["eligibleOneSecondBefore"], false);
    assert_eq!(retention["eligibleAtBoundary"], true);
    assert_eq!(
        tombstone["reason"],
        "HARNESS_CONTENT_RETENTION_REASON_TERMINAL_MINIMUM_EXPIRED"
    );
    assert_eq!(tombstone.get("text"), None);
    for (hex_field, digest_field) in [
        ("retentionTombstoneIdHex", "retentionTombstoneIdSha256"),
        ("retentionTombstoneHex", "retentionTombstoneSha256"),
    ] {
        let bytes = hex::decode(
            reset["canonicalVectors"][hex_field]
                .as_str()
                .expect("literal tombstone bytes"),
        )
        .expect("valid tombstone hex");
        assert_eq!(
            digest(&bytes),
            reset["canonicalVectors"][digest_field].as_str().unwrap()
        );
    }
    let tombstone_profile = &tombstone["disclosureProfileRef"];
    let mut tombstone_id = Vec::new();
    for value in [
        "egopulse/harness-content/retention-tombstone-id/v1",
        tombstone["taskId"].as_str().unwrap(),
        tombstone["attemptId"].as_str().unwrap(),
        tombstone["finalEpoch"].as_str().unwrap(),
    ] {
        framed_text(&mut tombstone_id, value);
    }
    framed_u64(
        &mut tombstone_id,
        tombstone["finalSequence"].as_u64().unwrap(),
    );
    for value in [
        tombstone_profile["sha256"].as_str().unwrap(),
        "TERMINAL_MINIMUM_EXPIRED",
    ] {
        framed_text(&mut tombstone_id, value);
    }
    assert_eq!(
        hex::encode(&tombstone_id),
        reset["canonicalVectors"]["retentionTombstoneIdHex"]
    );
    assert_eq!(
        tombstone["tombstoneId"].as_str().unwrap(),
        format!("hrt_{}", digest(&tombstone_id))
    );

    let mut tombstone_bytes = Vec::new();
    for value in [
        "egopulse/harness-content/retention-tombstone/v1",
        tombstone["tombstoneId"].as_str().unwrap(),
        tombstone["taskId"].as_str().unwrap(),
        tombstone["attemptId"].as_str().unwrap(),
        tombstone["finalEpoch"].as_str().unwrap(),
    ] {
        framed_text(&mut tombstone_bytes, value);
    }
    framed_u64(
        &mut tombstone_bytes,
        tombstone["finalSequence"].as_u64().unwrap(),
    );
    for value in [
        tombstone["finalSafeContentDigestSha256"].as_str().unwrap(),
        tombstone_profile["contractId"].as_str().unwrap(),
        tombstone_profile["version"].as_str().unwrap(),
        tombstone_profile["sha256"].as_str().unwrap(),
    ] {
        framed_text(&mut tombstone_bytes, value);
    }
    framed_i64(
        &mut tombstone_bytes,
        tombstone["terminalCommittedAt"]["seconds"]
            .as_i64()
            .unwrap(),
    );
    framed_u32(
        &mut tombstone_bytes,
        u32::try_from(tombstone["terminalCommittedAt"]["nanos"].as_u64().unwrap()).unwrap(),
    );
    framed_i64(
        &mut tombstone_bytes,
        tombstone["compactedAt"]["seconds"].as_i64().unwrap(),
    );
    framed_u32(
        &mut tombstone_bytes,
        u32::try_from(tombstone["compactedAt"]["nanos"].as_u64().unwrap()).unwrap(),
    );
    framed_text(&mut tombstone_bytes, "TERMINAL_MINIMUM_EXPIRED");
    assert_eq!(
        hex::encode(&tombstone_bytes),
        reset["canonicalVectors"]["retentionTombstoneHex"]
    );
    assert_eq!(digest(&tombstone_bytes), tombstone["tombstoneDigestSha256"]);

    let persistence = json(PERSISTENCE_FIXTURE);
    assert_eq!(
        persistence["expected"]["typedHistoryCompactionRecord"],
        true
    );
    let compaction = &persistence["typedHistoryCompaction"];
    let compaction_profile = &compaction["disclosureProfileRef"];
    let mut compaction_id = Vec::new();
    for value in [
        "egopulse/harness-content/history-compaction-id/v1",
        compaction["taskId"].as_str().unwrap(),
        compaction["attemptId"].as_str().unwrap(),
        compaction["finalEpoch"].as_str().unwrap(),
    ] {
        framed_text(&mut compaction_id, value);
    }
    framed_u64(
        &mut compaction_id,
        compaction["finalSequence"].as_u64().unwrap(),
    );
    for value in [
        compaction_profile["sha256"].as_str().unwrap(),
        "OWNER_HISTORY_FLOOR_ADVANCED",
    ] {
        framed_text(&mut compaction_id, value);
    }
    assert_eq!(
        hex::encode(&compaction_id),
        persistence["canonicalVectors"]["historyCompactionRecordIdHex"]
    );
    assert_eq!(
        compaction["compactionRecordId"].as_str().unwrap(),
        format!("hcc_{}", digest(&compaction_id))
    );

    let mut compaction_bytes = Vec::new();
    for value in [
        "egopulse/harness-content/history-compaction/v1",
        compaction["compactionRecordId"].as_str().unwrap(),
        compaction["taskId"].as_str().unwrap(),
        compaction["attemptId"].as_str().unwrap(),
        compaction["finalEpoch"].as_str().unwrap(),
    ] {
        framed_text(&mut compaction_bytes, value);
    }
    framed_u64(
        &mut compaction_bytes,
        compaction["finalSequence"].as_u64().unwrap(),
    );
    for value in [
        compaction["finalSafeContentDigestSha256"].as_str().unwrap(),
        compaction["ownerSnapshotDigestSha256"].as_str().unwrap(),
        compaction_profile["contractId"].as_str().unwrap(),
        compaction_profile["version"].as_str().unwrap(),
        compaction_profile["sha256"].as_str().unwrap(),
    ] {
        framed_text(&mut compaction_bytes, value);
    }
    framed_i64(
        &mut compaction_bytes,
        compaction["compactedAt"]["seconds"].as_i64().unwrap(),
    );
    framed_u32(
        &mut compaction_bytes,
        u32::try_from(compaction["compactedAt"]["nanos"].as_u64().unwrap()).unwrap(),
    );
    framed_text(&mut compaction_bytes, "OWNER_HISTORY_FLOOR_ADVANCED");
    assert_eq!(
        hex::encode(&compaction_bytes),
        persistence["canonicalVectors"]["historyCompactionRecordHex"]
    );
    assert_eq!(
        digest(&compaction_bytes),
        compaction["compactionRecordDigestSha256"]
    );
    assert!(HARNESS_PROTO.contains("message HarnessContentRetentionTombstone"));
}

#[test]
fn r9c_d09_final_artifact_relation_never_implies_task_completion() {
    let owner_relation =
        egopulse_domain_contracts::v01::egopulse::harness::v1::SafeArtifactRelationContent::default(
        );
    assert!(owner_relation.artifact.is_none());
    let principal_relation = HarnessArtifactRelationView::default();
    assert!(principal_relation.visibility.is_none());
    let relation = message_block(LOCAL_API_PROTO, "HarnessArtifactRelationView");
    let identity = message_block(LOCAL_API_PROTO, "HarnessArtifactIdentityView");
    assert!(identity.contains("string artifact_id"));
    assert!(identity.contains("string artifact_digest_sha256"));
    assert!(relation.contains("oneof visibility"));
    assert!(relation.contains("HarnessArtifactAvailableRedactedView available_redacted"));
    for forbidden in ["task_status", "completed", "verdict", "verification"] {
        assert!(!relation.contains(forbidden));
    }
    let safe_relation = message_block(HARNESS_PROTO, "SafeArtifactRelationContent");
    assert!(!safe_relation.contains("task_completion"));
    assert!(safe_relation.contains("SafeArtifactIdentity artifact = 2"));
    assert!(!safe_relation.contains("oneof visibility"));
    assert!(!safe_relation.contains("available_redacted"));
    assert_exact_message_inventory(
        HARNESS_PROTO,
        "SafeArtifactIdentity",
        &[
            "field|artifact_id|1|string",
            "field|artifact_digest_sha256|2|string",
        ],
    );
    assert_exact_message_inventory(
        HARNESS_PROTO,
        "SafeArtifactRelationContent",
        &[
            "field|safe_content_differs_from_artifact|1|bool",
            "field|artifact|2|SafeArtifactIdentity",
        ],
    );
    assert!(
        json(DISCLOSURE_PROFILE)["contentCategories"]["allowed"]
            .as_array()
            .unwrap()
            .contains(&Value::String("final_artifact_relation".to_owned()))
    );
}

#[test]
fn r9c_d10_route_identity_is_distinct_and_alias_independent() {
    let dispatch = json(VALID_DISPATCH_FIXTURE);
    let binding = &dispatch["command"]["dispatch"]["routeBinding"];
    let bootstrap = binding["providerBootstrapProfileId"].as_str().unwrap();
    let harness = binding["selectedHarnessId"].as_str().unwrap();
    let model = binding["providerModelId"].as_str().unwrap();
    let snapshot = binding["catalogSnapshotSha256"].as_str().unwrap();
    let capability = binding["capabilityProfileId"].as_str().unwrap();
    let first = digest(&route_binding_bytes(
        bootstrap, harness, model, "DIGEST", snapshot, capability,
    ));
    let other_harness = digest(&route_binding_bytes(
        bootstrap,
        "other_harness",
        model,
        "DIGEST",
        snapshot,
        capability,
    ));
    let other_model = digest(&route_binding_bytes(
        bootstrap,
        harness,
        "other-model",
        "DIGEST",
        snapshot,
        capability,
    ));
    assert_ne!(first, other_harness);
    assert_ne!(first, other_model);
    assert_eq!(
        first,
        "5fc3d40c5d3ecdc61ccac5826e0e2d0b10131133adcd8a5ca8438188c01c39a8"
    );
    let profile = json(DISCLOSURE_PROFILE);
    let fields = profile["canonicalEncoding"]["routeBindingFieldOrder"]
        .as_array()
        .unwrap();
    assert!(!fields.contains(&Value::String("provider_family_alias".to_owned())));
    assert!(!fields.contains(&Value::String("model_alias".to_owned())));
}

#[test]
fn r9c_d11_descriptor_footprint_adds_no_authority_or_store() {
    assert_eq!(HARNESS_PROTO.matches("service ").count(), 2);
    assert_eq!(LOCAL_API_PROTO.matches("service ").count(), 4);
    for forbidden in [
        "service HarnessContentAuthorityService",
        "service ContentAuthorityService",
        "service MemoryAuthorityService",
    ] {
        assert!(!HARNESS_PROTO.contains(forbidden));
        assert!(!LOCAL_API_PROTO.contains(forbidden));
    }
    assert!(!PERSISTENCE_PROTO.contains("PERSISTENCE_DOMAIN_HARNESS_CONTENT"));
    assert!(!PERSISTENCE_PROTO.contains("third_database"));

    let prewrite = json(PREWRITE_MIGRATION_FIXTURE);
    assert_eq!(
        prewrite["startingState"]["postMigrationProductWriteCount"],
        0
    );
    assert_eq!(
        prewrite["expected"]["verifiedBackupAndOldBinaryRestoredAsOneOperation"],
        true
    );
    assert_eq!(prewrite["expected"]["automaticDownMigration"], false);
    assert_eq!(prewrite["expected"]["factLoss"], false);

    let postwrite = json(POSTWRITE_MIGRATION_FIXTURE);
    assert!(
        postwrite["startingState"]["postMigrationProductWriteCount"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(postwrite["expected"]["verifiedBackupRestored"], false);
    assert_eq!(postwrite["expected"]["oldBinaryActivated"], false);
    assert_eq!(postwrite["expected"]["structuredOnlyModeEnabled"], true);
    assert_eq!(postwrite["expected"]["nativeEvidenceRetained"], true);
    assert_eq!(postwrite["expected"]["safeRecordsRetained"], true);
    assert_eq!(postwrite["expected"]["retentionTombstonesRetained"], true);
    assert_eq!(postwrite["expected"]["factLoss"], false);
}

#[test]
fn r9c_d12_manifest_fixture_and_cross_language_bindings_are_pinned() {
    let manifest = json(MANIFEST);
    assert_eq!(manifest["candidateVersion"], "0.1.0-draft.22");
    assert_eq!(manifest["r9cHarnessContentAuthorityRef"], R9C_AUTHORITY);
    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts");
    for path in [
        "harness-content-disclosure-profile.schema.json",
        "profiles/harness-content-disclosure/v1/v01-default.json",
        "fixtures/harness/v1/valid-content-append-not-context-bound.json",
        "fixtures/harness/v1/valid-content-authorized-context.json",
        "fixtures/harness/v1/valid-route-binding-no-catalog.json",
        "fixtures/localapi/v1/valid-harness-content-watch.json",
        "fixtures/localapi/v1/invalid-harness-content-frame-combination.json",
        "fixtures/persistence/v1/recovery-safe-content-outbox-after-consumer-commit.json",
        "fixtures/persistence/v1/recovery-r9c-prewrite-migration-backup-restore.json",
        "fixtures/persistence/v1/recovery-r9c-postwrite-forward-disable.json",
    ] {
        assert!(
            artifacts.iter().any(|entry| entry["path"] == path),
            "missing {path}"
        );
    }
    let rust = include_str!("../src/generated/egopulse.harness.v1.rs");
    let rust_local = include_str!("../src/generated/egopulse.localapi.v1.rs");
    let typescript = include_str!(
        "../../../packages/generated-client/src/generated/egopulse/harness/v1/harness_pb.ts"
    );
    let typescript_local = include_str!(
        "../../../packages/generated-client/src/generated/egopulse/localapi/v1/local_api_pb.ts"
    );
    let python =
        include_str!("../../../workers/contract-bindings/src/egopulse/harness/v1/harness_pb2.pyi");
    let python_local = include_str!(
        "../../../workers/contract-bindings/src/egopulse/localapi/v1/local_api_pb2.pyi"
    );
    for source in [rust, typescript, python] {
        assert!(source.contains("DispatchRouteBinding"));
        assert!(source.contains("SafeHarnessContentRecord"));
        assert!(source.contains("HarnessContentRetentionTombstone"));
        assert!(source.contains("SafeHarnessContentProjectionEvent"));
    }
    for source in [rust_local, typescript_local, python_local] {
        assert!(source.contains("HarnessContentRecordView"));
        assert!(source.contains("HarnessContentRecordsFrame"));
        assert!(source.contains("WatchHarnessContent"));
    }
    assert_eq!(
        json(REVISION_DRIFT_FIXTURE)["expected"]["quarantined"],
        true
    );
    assert_eq!(
        json(SOURCE_DRIFT_FIXTURE)["expected"]["historicBindingRecomputed"],
        false
    );
}
