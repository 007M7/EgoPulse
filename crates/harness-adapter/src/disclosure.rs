use base64::{Engine as _, engine::general_purpose};
use egopulse_domain_contracts::profiles::{
    HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
    HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalRequiredContentCandidate, AssistantTextContentCandidate, BlockedSourceContentCandidate,
    ContentMutationOperation, DispatchContextConsumptionProof, DispatchRouteBinding,
    HarnessContentLimitKind, HarnessContentMarkerKind, HarnessContentSafetyFlag,
    HarnessContentSignalObservation, HarnessObservation, LifecycleContentCandidate, LifecycleKind,
    SafeApprovalRequiredContent, SafeArtifactRelationContent, SafeAssistantTextContent,
    SafeContentMarker, SafeHarnessContentRecord, SafeLifecycleContent, SafeUsageContent,
    SideEffectCertainty, UsageContentCandidate, UserVisibleContentCandidate,
    dispatch_context_consumption_proof, dispatch_route_binding, safe_harness_content_record,
    user_visible_content_candidate,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ROUTE_DOMAIN: &str = "egopulse/harness-content/route-binding/v1";
const TEXT_PAYLOAD_DOMAIN: &str = "egopulse/harness-content/text-payload/v1";
const RAW_CUMULATIVE_DOMAIN: &str = "egopulse/harness-content/raw-cumulative/v1";
const TEXT_CANDIDATE_DOMAIN: &str = "egopulse/harness-content/text-candidate/v1";
const CONTENT_EVENT_DOMAIN: &str = "egopulse/harness-content/event/v1";
const SAFE_CUMULATIVE_DOMAIN: &str = "egopulse/harness-content/safe-cumulative/v1";
const SAFE_MESSAGE_ID_DOMAIN: &str = "egopulse/harness-content/safe-message-id/v1";
const SAFE_RECORD_ID_DOMAIN: &str = "egopulse/harness-content/safe-record-id/v1";
const SAFE_RECORD_DOMAIN: &str = "egopulse/harness-content/safe-record/v1";
const SAFE_ASSISTANT_DOMAIN: &str = "egopulse/harness-content/safe-assistant-text/v1";
const SAFE_LIFECYCLE_DOMAIN: &str = "egopulse/harness-content/safe-lifecycle/v1";
const SAFE_USAGE_DOMAIN: &str = "egopulse/harness-content/safe-usage/v1";
const SAFE_APPROVAL_DOMAIN: &str = "egopulse/harness-content/safe-approval-required/v1";
const SAFE_MARKER_DOMAIN: &str = "egopulse/harness-content/safe-marker/v1";
const SAFE_ARTIFACT_DOMAIN: &str = "egopulse/harness-content/safe-artifact-relation/v1";
const REDACTION_MARKER: &str = "[REDACTED]";
const SAFE_TEXT_PART_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedContentLineage {
    pub task_id: String,
    pub run_id: String,
    pub step_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentAssemblyCheckpoint {
    pub(crate) message_id: String,
    pub(crate) current_revision: u64,
    pub(crate) candidate_digest_sha256: String,
    pub(crate) finalized: bool,
    pub(crate) raw_cumulative: Vec<u8>,
    pub(crate) raw_cumulative_digest_sha256: String,
    pub(crate) safe_cumulative: String,
    pub(crate) safe_cumulative_digest_sha256: String,
    pub(crate) withheld_suffix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeContentProjection {
    records: Vec<SafeHarnessContentRecord>,
    pub(crate) checkpoint: Option<ContentAssemblyCheckpoint>,
}

impl SafeContentProjection {
    #[must_use]
    pub fn record(&self) -> &SafeHarnessContentRecord {
        &self.records[0]
    }

    #[must_use]
    pub fn records(&self) -> &[SafeHarnessContentRecord] {
        &self.records
    }

    #[must_use]
    pub const fn checkpoint(&self) -> Option<&ContentAssemblyCheckpoint> {
        self.checkpoint.as_ref()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContentDisclosureError {
    #[error("Harness content source binding failed closed")]
    SourceBinding,
    #[error("Harness content candidate is malformed or conflicts with its digest")]
    CandidateIntegrity,
    #[error("managed credential input exceeds the frozen disclosure bounds")]
    CredentialInput,
}

#[must_use]
pub fn canonical_dispatch_route_binding_digest(binding: &DispatchRouteBinding) -> Option<String> {
    let (kind, value) = match binding.catalog_snapshot.as_ref()? {
        dispatch_route_binding::CatalogSnapshot::CatalogSnapshotSha256(value)
            if canonical_sha256(value) =>
        {
            ("DIGEST", value.as_str())
        }
        dispatch_route_binding::CatalogSnapshot::NoCatalogSnapshot(_) => ("NO_CATALOG", ""),
        _ => return None,
    };
    if binding.provider_bootstrap_profile_id.trim().is_empty()
        || binding.selected_harness_id.trim().is_empty()
        || binding.provider_model_id.trim().is_empty()
        || binding.capability_profile_id.trim().is_empty()
    {
        return None;
    }
    let mut bytes = Vec::new();
    for field in [
        ROUTE_DOMAIN,
        binding.provider_bootstrap_profile_id.as_str(),
        binding.selected_harness_id.as_str(),
        binding.provider_model_id.as_str(),
        kind,
        value,
        binding.capability_profile_id.as_str(),
    ] {
        frame(&mut bytes, field.as_bytes());
    }
    Some(sha256(&bytes))
}

/// Constructs the provider candidate for one complete Codex `agentMessage`.
/// Provider/model/Task identity is deliberately absent and is added only from
/// trusted Adapter stores after durable delivery has been proven.
pub fn assistant_text_content_candidate(
    message_id: &str,
    text: Vec<u8>,
) -> Option<UserVisibleContentCandidate> {
    assistant_text_mutation_candidate(
        message_id,
        1,
        0,
        ContentMutationOperation::Append,
        text,
        &[],
    )
}

/// Constructs a bounded structural lifecycle candidate. No native payload or
/// diagnostic text crosses this typed boundary.
pub fn lifecycle_content_candidate(
    kind: LifecycleKind,
    side_effect_certainty: SideEffectCertainty,
    native_will_retry: Option<bool>,
) -> Option<UserVisibleContentCandidate> {
    if matches!(kind, LifecycleKind::Unspecified)
        || matches!(side_effect_certainty, SideEffectCertainty::Unspecified)
    {
        return None;
    }
    let value = LifecycleContentCandidate {
        kind: kind as i32,
        side_effect_certainty: side_effect_certainty as i32,
        native_will_retry,
    };
    let mut canonical = Vec::new();
    frame(
        &mut canonical,
        b"egopulse/harness-content/lifecycle-candidate/v1",
    );
    frame(&mut canonical, lifecycle_name(value.kind)?.as_bytes());
    frame(
        &mut canonical,
        certainty_name(value.side_effect_certainty)?.as_bytes(),
    );
    match value.native_will_retry {
        Some(retry) => {
            frame(&mut canonical, b"SOME");
            frame(&mut canonical, &u64::from(retry).to_le_bytes());
        }
        None => {
            frame(&mut canonical, b"NONE");
            frame(&mut canonical, &[]);
        }
    }
    Some(UserVisibleContentCandidate {
        payload: Some(user_visible_content_candidate::Payload::Lifecycle(value)),
        candidate_digest_sha256: sha256(&canonical),
    })
}

/// Constructs the structural token-usage candidate without a cost/provider
/// payload or any native receipt reference.
#[must_use]
pub fn usage_content_candidate(
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: Option<u64>,
) -> UserVisibleContentCandidate {
    let value = UsageContentCandidate {
        input_tokens,
        output_tokens,
        cached_input_tokens,
    };
    let mut canonical = Vec::new();
    frame(
        &mut canonical,
        b"egopulse/harness-content/usage-candidate/v1",
    );
    frame(&mut canonical, &value.input_tokens.to_le_bytes());
    frame(&mut canonical, &value.output_tokens.to_le_bytes());
    match value.cached_input_tokens {
        Some(cached) => {
            frame(&mut canonical, b"SOME");
            frame(&mut canonical, &cached.to_le_bytes());
        }
        None => {
            frame(&mut canonical, b"NONE");
            frame(&mut canonical, &[]);
        }
    }
    UserVisibleContentCandidate {
        payload: Some(user_visible_content_candidate::Payload::Usage(value)),
        candidate_digest_sha256: sha256(&canonical),
    }
}

/// Constructs the closed approval-required marker. Approval identity and
/// routing remain exclusively in the Approval projection.
#[must_use]
pub fn approval_required_content_candidate() -> UserVisibleContentCandidate {
    let mut canonical = Vec::new();
    frame(
        &mut canonical,
        b"egopulse/harness-content/approval-required-candidate/v1",
    );
    UserVisibleContentCandidate {
        payload: Some(user_visible_content_candidate::Payload::ApprovalRequired(
            ApprovalRequiredContentCandidate {},
        )),
        candidate_digest_sha256: sha256(&canonical),
    }
}

/// Constructs only the two closed source-classification markers. Native bytes
/// are intentionally not accepted by this API.
pub fn blocked_source_content_candidate(
    reason: HarnessContentMarkerKind,
) -> Option<UserVisibleContentCandidate> {
    if !matches!(
        reason,
        HarnessContentMarkerKind::ForbiddenCategory | HarnessContentMarkerKind::UnknownCategory
    ) {
        return None;
    }
    let value = BlockedSourceContentCandidate {
        reason: reason as i32,
    };
    let mut canonical = Vec::new();
    frame(
        &mut canonical,
        b"egopulse/harness-content/blocked-source-candidate/v1",
    );
    frame(&mut canonical, marker_name(value.reason)?.as_bytes());
    Some(UserVisibleContentCandidate {
        payload: Some(user_visible_content_candidate::Payload::BlockedSource(
            value,
        )),
        candidate_digest_sha256: sha256(&canonical),
    })
}

pub(crate) fn validate_candidate_semantics(
    candidate: &UserVisibleContentCandidate,
) -> Result<(), ContentDisclosureError> {
    match candidate.payload.as_ref() {
        Some(user_visible_content_candidate::Payload::AssistantText(value)) => {
            let operation = ContentMutationOperation::try_from(value.operation)
                .map_err(|_| ContentDisclosureError::CandidateIntegrity)?;
            if value.message_id.trim().is_empty()
                || value.text_utf8.len() > SAFE_TEXT_PART_BYTES
                || value.revision == 0
                || value.previous_revision >= value.revision
                || (value.revision == 1 && value.previous_revision != 0)
                || (operation == ContentMutationOperation::Finalize && !value.text_utf8.is_empty())
                || operation == ContentMutationOperation::Unspecified
                || value.delta_or_snapshot_digest_sha256
                    != framed_digest(TEXT_PAYLOAD_DOMAIN, &value.text_utf8)
                || !canonical_sha256(&value.previous_raw_cumulative_digest_sha256)
                || !canonical_sha256(&value.raw_cumulative_digest_sha256)
            {
                return Err(ContentDisclosureError::CandidateIntegrity);
            }
            let mut canonical = Vec::new();
            frame(&mut canonical, TEXT_CANDIDATE_DOMAIN.as_bytes());
            frame(&mut canonical, value.message_id.as_bytes());
            frame(&mut canonical, &value.revision.to_le_bytes());
            frame(&mut canonical, &value.previous_revision.to_le_bytes());
            frame(
                &mut canonical,
                operation_name(value.operation)
                    .ok_or(ContentDisclosureError::CandidateIntegrity)?
                    .as_bytes(),
            );
            frame(&mut canonical, &value.text_utf8);
            frame(
                &mut canonical,
                value.delta_or_snapshot_digest_sha256.as_bytes(),
            );
            frame(
                &mut canonical,
                value.previous_raw_cumulative_digest_sha256.as_bytes(),
            );
            frame(
                &mut canonical,
                value.raw_cumulative_digest_sha256.as_bytes(),
            );
            require_candidate_digest(candidate, &canonical)
        }
        Some(user_visible_content_candidate::Payload::Lifecycle(value)) => {
            validate_lifecycle_candidate(candidate, value)
        }
        Some(user_visible_content_candidate::Payload::Usage(value)) => {
            validate_usage_candidate(candidate, value)
        }
        Some(user_visible_content_candidate::Payload::ApprovalRequired(value)) => {
            validate_approval_candidate(candidate, value)
        }
        Some(user_visible_content_candidate::Payload::BlockedSource(value)) => {
            validate_blocked_candidate(candidate, value)
        }
        None => Err(ContentDisclosureError::CandidateIntegrity),
    }
}

pub fn assistant_text_mutation_candidate(
    message_id: &str,
    revision: u64,
    previous_revision: u64,
    operation: ContentMutationOperation,
    text: Vec<u8>,
    previous_raw_cumulative: &[u8],
) -> Option<UserVisibleContentCandidate> {
    if message_id.trim().is_empty()
        || text.len() > 65_536
        || revision == 0
        || previous_revision >= revision
        || (revision == 1 && previous_revision != 0)
        || (operation == ContentMutationOperation::Finalize && !text.is_empty())
        || operation == ContentMutationOperation::Unspecified
    {
        return None;
    }
    let delta_digest = framed_digest(TEXT_PAYLOAD_DOMAIN, &text);
    let previous_raw_digest = framed_digest(RAW_CUMULATIVE_DOMAIN, previous_raw_cumulative);
    let raw_cumulative = match operation {
        ContentMutationOperation::Append => {
            let mut cumulative = previous_raw_cumulative.to_vec();
            cumulative.extend_from_slice(&text);
            cumulative
        }
        ContentMutationOperation::Replace => text.clone(),
        ContentMutationOperation::Finalize => previous_raw_cumulative.to_vec(),
        ContentMutationOperation::Unspecified => return None,
    };
    let raw_digest = framed_digest(RAW_CUMULATIVE_DOMAIN, &raw_cumulative);
    let assistant = AssistantTextContentCandidate {
        message_id: message_id.to_owned(),
        revision,
        previous_revision,
        operation: operation as i32,
        text_utf8: text,
        delta_or_snapshot_digest_sha256: delta_digest,
        previous_raw_cumulative_digest_sha256: previous_raw_digest,
        raw_cumulative_digest_sha256: raw_digest,
    };
    let mut canonical = Vec::new();
    frame(&mut canonical, TEXT_CANDIDATE_DOMAIN.as_bytes());
    frame(&mut canonical, assistant.message_id.as_bytes());
    frame(&mut canonical, &assistant.revision.to_le_bytes());
    frame(&mut canonical, &assistant.previous_revision.to_le_bytes());
    frame(
        &mut canonical,
        operation_name(assistant.operation)?.as_bytes(),
    );
    frame(&mut canonical, &assistant.text_utf8);
    frame(
        &mut canonical,
        assistant.delta_or_snapshot_digest_sha256.as_bytes(),
    );
    frame(
        &mut canonical,
        assistant.previous_raw_cumulative_digest_sha256.as_bytes(),
    );
    frame(
        &mut canonical,
        assistant.raw_cumulative_digest_sha256.as_bytes(),
    );
    Some(UserVisibleContentCandidate {
        candidate_digest_sha256: sha256(&canonical),
        payload: Some(user_visible_content_candidate::Payload::AssistantText(
            assistant,
        )),
    })
}

pub fn bind_content_signal(
    observation: &HarnessObservation,
    signal: &mut HarnessContentSignalObservation,
    delivered_receipt_id: &str,
    delivered_receipt_digest_sha256: &str,
    route_binding_sha256: &str,
    context_proof: DispatchContextConsumptionProof,
) -> Result<(), ContentDisclosureError> {
    let content_event_id = canonical_content_event_id(
        observation,
        signal
            .candidate
            .as_ref()
            .ok_or(ContentDisclosureError::CandidateIntegrity)?,
        delivered_receipt_id,
        delivered_receipt_digest_sha256,
        route_binding_sha256,
        &context_proof,
    )?;
    signal.content_event_id = content_event_id;
    signal.delivered_receipt_id = delivered_receipt_id.to_owned();
    signal.delivered_receipt_digest_sha256 = delivered_receipt_digest_sha256.to_owned();
    signal.dispatch_route_binding_sha256 = route_binding_sha256.to_owned();
    signal.context_consumption_proof = Some(context_proof);
    Ok(())
}

pub(crate) fn canonical_content_event_id(
    observation: &HarnessObservation,
    candidate: &UserVisibleContentCandidate,
    delivered_receipt_id: &str,
    delivered_receipt_digest_sha256: &str,
    route_binding_sha256: &str,
    context_proof: &DispatchContextConsumptionProof,
) -> Result<String, ContentDisclosureError> {
    let native_event_id = observation
        .native_event_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(ContentDisclosureError::SourceBinding)?;
    let native_sequence = observation
        .native_sequence
        .ok_or(ContentDisclosureError::SourceBinding)?;
    if delivered_receipt_id.trim().is_empty()
        || !canonical_sha256(delivered_receipt_digest_sha256)
        || !canonical_sha256(route_binding_sha256)
        || !canonical_sha256(&observation.native_event_digest_sha256)
        || !canonical_sha256(&candidate.candidate_digest_sha256)
        || observation.attempt_id.trim().is_empty()
        || observation.dispatch_id.trim().is_empty()
        || observation.fencing_token == 0
        || observation.capability_profile_id.trim().is_empty()
    {
        return Err(ContentDisclosureError::SourceBinding);
    }
    let (proof_branch, authorization_id, request_digest) = proof_fields(context_proof)?;
    let mut canonical = Vec::new();
    for field in [
        CONTENT_EVENT_DOMAIN,
        delivered_receipt_id,
        delivered_receipt_digest_sha256,
        proof_branch,
        authorization_id,
        request_digest,
        route_binding_sha256,
        observation.attempt_id.as_str(),
        observation.dispatch_id.as_str(),
    ] {
        frame(&mut canonical, field.as_bytes());
    }
    frame(&mut canonical, &observation.fencing_token.to_le_bytes());
    for field in [
        observation.capability_profile_id.as_str(),
        native_event_id,
        observation.native_event_digest_sha256.as_str(),
    ] {
        frame(&mut canonical, field.as_bytes());
    }
    frame(&mut canonical, &native_sequence.to_le_bytes());
    frame(&mut canonical, candidate.candidate_digest_sha256.as_bytes());
    Ok(sha256(&canonical))
}

pub fn project_safe_content(
    observation: &HarnessObservation,
    signal: &HarnessContentSignalObservation,
    route_binding: &DispatchRouteBinding,
    lineage: &TrustedContentLineage,
    managed_credentials: &[String],
    previous: Option<&ContentAssemblyCheckpoint>,
) -> Result<SafeContentProjection, ContentDisclosureError> {
    validate_projection_binding(observation, signal, route_binding, lineage)?;
    let candidate = signal
        .candidate
        .as_ref()
        .ok_or(ContentDisclosureError::CandidateIntegrity)?;
    let (payload, payload_kind, mut flags, checkpoint) = project_candidate(
        candidate,
        observation,
        route_binding,
        managed_credentials,
        previous,
    )?;
    flags.sort_unstable();
    flags.dedup();
    let payloads = split_safe_payload(payload)?;
    let records = payloads
        .into_iter()
        .map(|payload| {
            build_safe_record(
                observation,
                signal,
                route_binding,
                lineage,
                payload,
                payload_kind,
                flags.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SafeContentProjection {
        records,
        checkpoint,
    })
}

pub fn project_structured_only_content(
    observation: &HarnessObservation,
    signal: &HarnessContentSignalObservation,
    route_binding: &DispatchRouteBinding,
    lineage: &TrustedContentLineage,
    previous: Option<&ContentAssemblyCheckpoint>,
) -> Result<SafeContentProjection, ContentDisclosureError> {
    validate_projection_binding(observation, signal, route_binding, lineage)?;
    let candidate = signal
        .candidate
        .as_ref()
        .ok_or(ContentDisclosureError::CandidateIntegrity)?;
    let checkpoint = match candidate.payload.as_ref() {
        Some(user_visible_content_candidate::Payload::AssistantText(text)) => Some(
            advance_assistant_checkpoint(
                text,
                candidate,
                observation,
                route_binding,
                previous,
                None,
            )?
            .checkpoint,
        ),
        Some(user_visible_content_candidate::Payload::Lifecycle(value)) => {
            validate_lifecycle_candidate(candidate, value)?;
            None
        }
        Some(user_visible_content_candidate::Payload::Usage(value)) => {
            validate_usage_candidate(candidate, value)?;
            None
        }
        Some(user_visible_content_candidate::Payload::ApprovalRequired(value)) => {
            validate_approval_candidate(candidate, value)?;
            None
        }
        Some(user_visible_content_candidate::Payload::BlockedSource(value)) => {
            validate_blocked_candidate(candidate, value)?;
            None
        }
        None => return Err(ContentDisclosureError::CandidateIntegrity),
    };
    let marker = SafeContentMarker {
        kind: HarnessContentMarkerKind::RedactionInputUnavailable as i32,
        limit_kind: HarnessContentLimitKind::Unspecified as i32,
    };
    let record = build_safe_record(
        observation,
        signal,
        route_binding,
        lineage,
        safe_harness_content_record::Payload::Marker(marker),
        "MARKER",
        Vec::new(),
    )?;
    Ok(SafeContentProjection {
        records: vec![record],
        checkpoint,
    })
}

fn split_safe_payload(
    payload: safe_harness_content_record::Payload,
) -> Result<Vec<safe_harness_content_record::Payload>, ContentDisclosureError> {
    let safe_harness_content_record::Payload::AssistantText(mut text) = payload else {
        return Ok(vec![payload]);
    };
    let chunks = utf8_chunks(&text.safe_text_utf8, SAFE_TEXT_PART_BYTES)
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let part_count =
        u32::try_from(chunks.len()).map_err(|_| ContentDisclosureError::CandidateIntegrity)?;
    let mut payloads = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        text.safe_text_utf8 = chunk;
        text.part_index =
            u32::try_from(index).map_err(|_| ContentDisclosureError::CandidateIntegrity)?;
        text.part_count = part_count;
        payloads.push(safe_harness_content_record::Payload::AssistantText(
            text.clone(),
        ));
    }
    Ok(payloads)
}

fn utf8_chunks(value: &str, max_bytes: usize) -> Vec<&str> {
    if value.is_empty() {
        return vec![value];
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = value.len().min(start + max_bytes);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(&value[start..end]);
        start = end;
    }
    chunks
}

#[allow(clippy::too_many_arguments)]
fn build_safe_record(
    observation: &HarnessObservation,
    signal: &HarnessContentSignalObservation,
    route_binding: &DispatchRouteBinding,
    lineage: &TrustedContentLineage,
    payload: safe_harness_content_record::Payload,
    payload_kind: &str,
    flags: Vec<i32>,
) -> Result<SafeHarnessContentRecord, ContentDisclosureError> {
    let profile = ContractReference {
        contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
        version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
        sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
    };
    let part_index = match &payload {
        safe_harness_content_record::Payload::AssistantText(text) => text.part_index,
        _ => 0,
    };
    let limit_kind =
        safe_payload_limit_kind(&payload).ok_or(ContentDisclosureError::CandidateIntegrity)?;
    let record_id = canonical_safe_record_id(
        &signal.content_event_id,
        payload_kind,
        limit_kind,
        part_index,
    );
    let provider_family_alias = if route_binding.selected_harness_id == "codex_app_server" {
        "openai".to_owned()
    } else {
        route_binding.provider_bootstrap_profile_id.clone()
    };
    let mut record = SafeHarnessContentRecord {
        record_id,
        record_digest_sha256: String::new(),
        content_event_id: signal.content_event_id.clone(),
        task_id: lineage.task_id.clone(),
        run_id: lineage.run_id.clone(),
        step_id: lineage.step_id.clone(),
        attempt_id: observation.attempt_id.clone(),
        dispatch_id: observation.dispatch_id.clone(),
        fencing_token: observation.fencing_token,
        route_binding_sha256: route_binding.route_binding_sha256.clone(),
        disclosure_profile_ref: Some(profile),
        provider_family_alias,
        model_alias: route_binding.provider_model_id.clone(),
        collaboration_role: "primary".to_owned(),
        safety_flags: flags,
        payload: Some(payload),
    };
    record.record_digest_sha256 =
        canonical_safe_record_digest(&record).ok_or(ContentDisclosureError::CandidateIntegrity)?;
    Ok(record)
}

fn validate_projection_binding(
    observation: &HarnessObservation,
    signal: &HarnessContentSignalObservation,
    route_binding: &DispatchRouteBinding,
    lineage: &TrustedContentLineage,
) -> Result<(), ContentDisclosureError> {
    let candidate = signal
        .candidate
        .as_ref()
        .ok_or(ContentDisclosureError::CandidateIntegrity)?;
    let context_proof = signal
        .context_consumption_proof
        .as_ref()
        .ok_or(ContentDisclosureError::SourceBinding)?;
    let expected_content_event_id = canonical_content_event_id(
        observation,
        candidate,
        &signal.delivered_receipt_id,
        &signal.delivered_receipt_digest_sha256,
        &signal.dispatch_route_binding_sha256,
        context_proof,
    )?;
    if signal.content_event_id != expected_content_event_id
        || signal.dispatch_route_binding_sha256 != route_binding.route_binding_sha256
        || observation.attempt_id.trim().is_empty()
        || observation.dispatch_id.trim().is_empty()
        || observation.fencing_token == 0
        || lineage.task_id.trim().is_empty()
        || lineage.run_id.trim().is_empty()
        || lineage.step_id.trim().is_empty()
        || canonical_dispatch_route_binding_digest(route_binding).as_deref()
            != Some(route_binding.route_binding_sha256.as_str())
    {
        Err(ContentDisclosureError::SourceBinding)
    } else {
        Ok(())
    }
}

#[must_use]
pub fn canonical_safe_record_digest(record: &SafeHarnessContentRecord) -> Option<String> {
    let profile = record.disclosure_profile_ref.as_ref()?;
    let payload = record.payload.as_ref()?;
    let (kind, digest) = safe_payload_digest(payload)?;
    let part_index = match payload {
        safe_harness_content_record::Payload::AssistantText(text) => text.part_index,
        _ => 0,
    };
    let limit_kind = safe_payload_limit_kind(payload)?;
    if record.record_id
        != canonical_safe_record_id(&record.content_event_id, kind, limit_kind, part_index)
        || record.content_event_id.trim().is_empty()
        || record.task_id.trim().is_empty()
        || record.run_id.trim().is_empty()
        || record.step_id.trim().is_empty()
        || record.attempt_id.trim().is_empty()
        || record.dispatch_id.trim().is_empty()
        || record.fencing_token == 0
        || !canonical_sha256(&record.route_binding_sha256)
        || profile.contract_id != HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        || profile.version != HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
        || profile.sha256 != HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
        || record
            .safety_flags
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
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
    frame(&mut bytes, digest.as_bytes());
    Some(sha256(&bytes))
}

pub(crate) fn canonical_safe_record_id(
    content_event_id: &str,
    payload_kind: &str,
    limit_kind: HarnessContentLimitKind,
    part_index: u32,
) -> String {
    let mut bytes = Vec::new();
    for value in [
        SAFE_RECORD_ID_DOMAIN,
        content_event_id,
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID,
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
        payload_kind,
        limit_kind_name(limit_kind as i32).expect("generated limit kind has a canonical name"),
    ] {
        frame(&mut bytes, value.as_bytes());
    }
    frame(&mut bytes, &part_index.to_le_bytes());
    format!("hcr_{}", sha256(&bytes))
}

struct AssistantProjection {
    checkpoint: ContentAssemblyCheckpoint,
    payload: AssistantProjectionPayload,
}

enum AssistantProjectionPayload {
    Text {
        safe: SafeAssistantTextContent,
        flags: Vec<i32>,
    },
    Marker(HarnessContentMarkerKind),
}

fn advance_assistant_checkpoint(
    text: &AssistantTextContentCandidate,
    candidate: &UserVisibleContentCandidate,
    observation: &HarnessObservation,
    route_binding: &DispatchRouteBinding,
    previous: Option<&ContentAssemblyCheckpoint>,
    patterns: Option<&[String]>,
) -> Result<AssistantProjection, ContentDisclosureError> {
    let operation = ContentMutationOperation::try_from(text.operation)
        .map_err(|_| ContentDisclosureError::CandidateIntegrity)?;
    let previous_raw = match previous {
        Some(previous)
            if previous.message_id == text.message_id
                && !previous.finalized
                && text.revision == previous.current_revision.saturating_add(1)
                && text.previous_revision == previous.current_revision
                && text.previous_raw_cumulative_digest_sha256
                    == previous.raw_cumulative_digest_sha256 =>
        {
            previous.raw_cumulative.as_slice()
        }
        None if text.revision == 1 && text.previous_revision == 0 => &[],
        _ => return Err(ContentDisclosureError::CandidateIntegrity),
    };
    let rebuilt = assistant_text_mutation_candidate(
        &text.message_id,
        text.revision,
        text.previous_revision,
        operation,
        text.text_utf8.clone(),
        previous_raw,
    )
    .filter(|rebuilt| rebuilt == candidate)
    .ok_or(ContentDisclosureError::CandidateIntegrity)?;
    drop(rebuilt);
    let raw_cumulative = match operation {
        ContentMutationOperation::Append => {
            let mut value = previous_raw.to_vec();
            value.extend_from_slice(&text.text_utf8);
            value
        }
        ContentMutationOperation::Replace => text.text_utf8.clone(),
        ContentMutationOperation::Finalize => previous_raw.to_vec(),
        ContentMutationOperation::Unspecified => {
            return Err(ContentDisclosureError::CandidateIntegrity);
        }
    };
    let previous_safe = previous.map_or("", |value| value.safe_cumulative.as_str());
    let mut checkpoint = ContentAssemblyCheckpoint {
        message_id: text.message_id.clone(),
        current_revision: text.revision,
        candidate_digest_sha256: candidate.candidate_digest_sha256.clone(),
        finalized: operation == ContentMutationOperation::Finalize,
        raw_cumulative_digest_sha256: text.raw_cumulative_digest_sha256.clone(),
        raw_cumulative,
        safe_cumulative: previous_safe.to_owned(),
        safe_cumulative_digest_sha256: framed_digest(
            SAFE_CUMULATIVE_DOMAIN,
            previous_safe.as_bytes(),
        ),
        withheld_suffix: String::new(),
    };
    let Some(patterns) = patterns else {
        return Ok(AssistantProjection {
            checkpoint,
            payload: AssistantProjectionPayload::Marker(
                HarnessContentMarkerKind::RedactionInputUnavailable,
            ),
        });
    };
    let (normalized, control_redacted) = match normalize_text(&checkpoint.raw_cumulative) {
        Ok(value) => value,
        Err(ContentDisclosureError::CandidateIntegrity) => {
            return Ok(AssistantProjection {
                checkpoint,
                payload: AssistantProjectionPayload::Marker(HarnessContentMarkerKind::InvalidText),
            });
        }
        Err(error) => return Err(error),
    };
    let (safe_cumulative, withheld_suffix, credential_redacted) = redact_streaming_text(
        &normalized,
        patterns,
        operation == ContentMutationOperation::Finalize,
    );
    let safe_text = match operation {
        ContentMutationOperation::Replace => safe_cumulative.clone(),
        ContentMutationOperation::Append | ContentMutationOperation::Finalize => safe_cumulative
            .strip_prefix(previous_safe)
            .ok_or(ContentDisclosureError::CandidateIntegrity)?
            .to_owned(),
        ContentMutationOperation::Unspecified => {
            return Err(ContentDisclosureError::CandidateIntegrity);
        }
    };
    checkpoint.safe_cumulative_digest_sha256 =
        framed_digest(SAFE_CUMULATIVE_DOMAIN, safe_cumulative.as_bytes());
    checkpoint.safe_cumulative = safe_cumulative;
    checkpoint.withheld_suffix = withheld_suffix;
    let mut flags = vec![HarnessContentSafetyFlag::Provisional as i32];
    if control_redacted {
        flags.push(HarnessContentSafetyFlag::ControlRedacted as i32);
    }
    if credential_redacted {
        flags.push(HarnessContentSafetyFlag::CredentialRedacted as i32);
    }
    let mut id_bytes = Vec::new();
    for value in [
        SAFE_MESSAGE_ID_DOMAIN,
        observation.attempt_id.as_str(),
        observation.dispatch_id.as_str(),
        route_binding.route_binding_sha256.as_str(),
        text.message_id.as_str(),
    ] {
        frame(&mut id_bytes, value.as_bytes());
    }
    let safe = SafeAssistantTextContent {
        safe_message_id: format!("hcm_{}", sha256(&id_bytes)),
        revision: text.revision,
        previous_revision: text.previous_revision,
        operation: text.operation,
        safe_cumulative_digest_sha256: checkpoint.safe_cumulative_digest_sha256.clone(),
        safe_text_utf8: safe_text,
        part_index: 0,
        part_count: 1,
    };
    safe_assistant_digest(&safe).ok_or(ContentDisclosureError::CandidateIntegrity)?;
    Ok(AssistantProjection {
        checkpoint,
        payload: AssistantProjectionPayload::Text { safe, flags },
    })
}

type ProjectedCandidate = (
    safe_harness_content_record::Payload,
    &'static str,
    Vec<i32>,
    Option<ContentAssemblyCheckpoint>,
);

fn project_candidate(
    candidate: &UserVisibleContentCandidate,
    observation: &HarnessObservation,
    route_binding: &DispatchRouteBinding,
    managed_credentials: &[String],
    previous: Option<&ContentAssemblyCheckpoint>,
) -> Result<ProjectedCandidate, ContentDisclosureError> {
    match candidate.payload.as_ref() {
        Some(user_visible_content_candidate::Payload::AssistantText(text)) => {
            let patterns = credential_matcher_variants(managed_credentials)?;
            let projected = advance_assistant_checkpoint(
                text,
                candidate,
                observation,
                route_binding,
                previous,
                Some(&patterns),
            )?;
            match projected.payload {
                AssistantProjectionPayload::Text { safe, flags } => Ok((
                    safe_harness_content_record::Payload::AssistantText(safe),
                    "ASSISTANT_TEXT",
                    flags,
                    Some(projected.checkpoint),
                )),
                AssistantProjectionPayload::Marker(marker) => Ok((
                    safe_harness_content_record::Payload::Marker(SafeContentMarker {
                        kind: marker as i32,
                        limit_kind: HarnessContentLimitKind::Unspecified as i32,
                    }),
                    "MARKER",
                    Vec::new(),
                    Some(projected.checkpoint),
                )),
            }
        }
        Some(user_visible_content_candidate::Payload::Lifecycle(value)) => {
            validate_lifecycle_candidate(candidate, value)?;
            let safe = SafeLifecycleContent {
                kind: value.kind,
                side_effect_certainty: value.side_effect_certainty,
                native_will_retry: value.native_will_retry,
            };
            safe_lifecycle_digest(&safe).ok_or(ContentDisclosureError::CandidateIntegrity)?;
            Ok((
                safe_harness_content_record::Payload::Lifecycle(safe),
                "LIFECYCLE",
                vec![HarnessContentSafetyFlag::Provisional as i32],
                None,
            ))
        }
        Some(user_visible_content_candidate::Payload::Usage(value)) => {
            validate_usage_candidate(candidate, value)?;
            let safe = SafeUsageContent {
                input_tokens: value.input_tokens,
                output_tokens: value.output_tokens,
                cached_input_tokens: value.cached_input_tokens,
            };
            let _ = safe_usage_digest(&safe);
            Ok((
                safe_harness_content_record::Payload::Usage(safe),
                "USAGE",
                vec![HarnessContentSafetyFlag::Provisional as i32],
                None,
            ))
        }
        Some(user_visible_content_candidate::Payload::ApprovalRequired(value)) => {
            validate_approval_candidate(candidate, value)?;
            let safe = SafeApprovalRequiredContent {};
            Ok((
                safe_harness_content_record::Payload::ApprovalRequired(safe),
                "APPROVAL_REQUIRED",
                vec![HarnessContentSafetyFlag::Provisional as i32],
                None,
            ))
        }
        Some(user_visible_content_candidate::Payload::BlockedSource(value)) => {
            validate_blocked_candidate(candidate, value)?;
            let safe = SafeContentMarker {
                kind: value.reason,
                limit_kind: HarnessContentLimitKind::Unspecified as i32,
            };
            safe_marker_digest(&safe).ok_or(ContentDisclosureError::CandidateIntegrity)?;
            Ok((
                safe_harness_content_record::Payload::Marker(safe),
                "MARKER",
                Vec::new(),
                None,
            ))
        }
        None => Err(ContentDisclosureError::CandidateIntegrity),
    }
}

fn proof_fields(
    proof: &DispatchContextConsumptionProof,
) -> Result<(&str, &str, &str), ContentDisclosureError> {
    match proof.branch.as_ref() {
        Some(dispatch_context_consumption_proof::Branch::NotContextBound(_)) => {
            Ok(("NOT_CONTEXT_BOUND", "", ""))
        }
        Some(dispatch_context_consumption_proof::Branch::AuthorizedContext(value))
            if !value.authorization_id.trim().is_empty()
                && canonical_sha256(&value.committed_request_digest_sha256) =>
        {
            Ok((
                "AUTHORIZED_CONTEXT",
                value.authorization_id.as_str(),
                value.committed_request_digest_sha256.as_str(),
            ))
        }
        _ => Err(ContentDisclosureError::SourceBinding),
    }
}

fn normalize_text(bytes: &[u8]) -> Result<(String, bool), ContentDisclosureError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| ContentDisclosureError::CandidateIntegrity)?;
    let mut output = String::with_capacity(text.len());
    let mut redacted = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            output.push('\n');
        } else if ch == '\t' {
            output.push_str("    ");
        } else if matches!(ch, '\u{2028}' | '\u{2029}') {
            output.push('\n');
        } else if forbidden_control(ch) {
            output.push('\u{fffd}');
            redacted = true;
        } else {
            output.push(ch);
        }
    }
    Ok((output, redacted))
}

fn forbidden_control(ch: char) -> bool {
    (ch <= '\u{1f}' && ch != '\n')
        || ('\u{7f}'..='\u{9f}').contains(&ch)
        || matches!(
            ch,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

pub(crate) fn canonical_credential_variants(
    values: &[String],
) -> Result<Vec<String>, ContentDisclosureError> {
    if values.len() > 32 {
        return Err(ContentDisclosureError::CredentialInput);
    }
    let mut variants = Vec::new();
    for value in values {
        if value.is_empty()
            || value.len() > 1_024
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(ContentDisclosureError::CredentialInput);
        }
        let bytes = value.as_bytes();
        variants.extend([
            value.clone(),
            json_escape(value),
            percent_encode(bytes),
            base64_encode(bytes, false, true),
            base64_encode(bytes, false, false),
            base64_encode(bytes, true, true),
            base64_encode(bytes, true, false),
        ]);
    }
    // The commitment profile freezes unsigned byte-lexicographic order. Keep
    // this canonical order independent from the longest-match order used by
    // the streaming redactor.
    variants.sort_unstable();
    variants.dedup();
    Ok(variants)
}

fn credential_matcher_variants(values: &[String]) -> Result<Vec<String>, ContentDisclosureError> {
    let mut variants = canonical_credential_variants(values)?;
    variants.sort_by(|left, right| right.len().cmp(&left.len()).then(left.cmp(right)));
    Ok(variants)
}

fn redact_streaming_text(
    text: &str,
    patterns: &[String],
    finalize: bool,
) -> (String, String, bool) {
    let mut output = String::with_capacity(text.len());
    let mut offset = 0;
    let mut redacted = false;
    let mut withheld_suffix = String::new();
    while offset < text.len() {
        let suffix = &text[offset..];
        if let Some(pattern) = patterns
            .iter()
            .find(|pattern| suffix.starts_with(pattern.as_str()))
        {
            output.push_str(REDACTION_MARKER);
            offset += pattern.len();
            redacted = true;
        } else if !finalize
            && patterns
                .iter()
                .any(|pattern| suffix.len() < pattern.len() && pattern.starts_with(suffix))
        {
            withheld_suffix.push_str(suffix);
            break;
        } else {
            let ch = suffix.chars().next().expect("non-empty suffix");
            output.push(ch);
            offset += ch.len_utf8();
        }
    }
    (output, withheld_suffix, redacted)
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn percent_encode(value: &[u8]) -> String {
    let mut output = String::new();
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

fn base64_encode(value: &[u8], url_safe: bool, padded: bool) -> String {
    let engine = if url_safe && padded {
        &general_purpose::URL_SAFE
    } else if url_safe {
        &general_purpose::URL_SAFE_NO_PAD
    } else if padded {
        &general_purpose::STANDARD
    } else {
        &general_purpose::STANDARD_NO_PAD
    };
    engine.encode(value)
}

fn safe_payload_digest(
    payload: &safe_harness_content_record::Payload,
) -> Option<(&'static str, String)> {
    match payload {
        safe_harness_content_record::Payload::AssistantText(value) => {
            safe_assistant_digest(value).map(|digest| ("ASSISTANT_TEXT", digest))
        }
        safe_harness_content_record::Payload::Lifecycle(value) => {
            safe_lifecycle_digest(value).map(|digest| ("LIFECYCLE", digest))
        }
        safe_harness_content_record::Payload::Usage(value) => {
            Some(("USAGE", safe_usage_digest(value)))
        }
        safe_harness_content_record::Payload::ApprovalRequired(_) => Some((
            "APPROVAL_REQUIRED",
            framed_digest(SAFE_APPROVAL_DOMAIN, &[]),
        )),
        safe_harness_content_record::Payload::Marker(value) => {
            safe_marker_digest(value).map(|digest| ("MARKER", digest))
        }
        safe_harness_content_record::Payload::ArtifactRelation(value) => {
            safe_artifact_relation_digest(value).map(|digest| ("ARTIFACT_RELATION", digest))
        }
    }
}

fn safe_assistant_digest(value: &SafeAssistantTextContent) -> Option<String> {
    let mut bytes = Vec::new();
    for field in [SAFE_ASSISTANT_DOMAIN, value.safe_message_id.as_str()] {
        frame(&mut bytes, field.as_bytes());
    }
    frame(&mut bytes, &value.revision.to_le_bytes());
    frame(&mut bytes, &value.previous_revision.to_le_bytes());
    frame(&mut bytes, operation_name(value.operation)?.as_bytes());
    frame(&mut bytes, value.safe_text_utf8.as_bytes());
    frame(&mut bytes, value.safe_cumulative_digest_sha256.as_bytes());
    frame(&mut bytes, &value.part_index.to_le_bytes());
    frame(&mut bytes, &value.part_count.to_le_bytes());
    Some(sha256(&bytes))
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

fn safe_lifecycle_digest(value: &SafeLifecycleContent) -> Option<String> {
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_LIFECYCLE_DOMAIN.as_bytes());
    frame(&mut bytes, lifecycle_name(value.kind)?.as_bytes());
    frame(
        &mut bytes,
        certainty_name(value.side_effect_certainty)?.as_bytes(),
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

fn safe_marker_digest(value: &SafeContentMarker) -> Option<String> {
    let marker_kind = HarnessContentMarkerKind::try_from(value.kind).ok()?;
    let limit_kind = HarnessContentLimitKind::try_from(value.limit_kind).ok()?;
    if marker_kind == HarnessContentMarkerKind::Unspecified
        || (marker_kind == HarnessContentMarkerKind::LimitReached)
            != (limit_kind != HarnessContentLimitKind::Unspecified)
    {
        return None;
    }
    let mut bytes = Vec::new();
    frame(&mut bytes, SAFE_MARKER_DOMAIN.as_bytes());
    frame(&mut bytes, marker_name(value.kind)?.as_bytes());
    frame(&mut bytes, limit_kind_name(value.limit_kind)?.as_bytes());
    Some(sha256(&bytes))
}

fn safe_payload_limit_kind(
    payload: &safe_harness_content_record::Payload,
) -> Option<HarnessContentLimitKind> {
    match payload {
        safe_harness_content_record::Payload::Marker(value) => {
            safe_marker_digest(value)?;
            HarnessContentLimitKind::try_from(value.limit_kind).ok()
        }
        _ => Some(HarnessContentLimitKind::Unspecified),
    }
}

fn validate_lifecycle_candidate(
    candidate: &UserVisibleContentCandidate,
    value: &LifecycleContentCandidate,
) -> Result<(), ContentDisclosureError> {
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        b"egopulse/harness-content/lifecycle-candidate/v1",
    );
    frame(
        &mut bytes,
        lifecycle_name(value.kind)
            .ok_or(ContentDisclosureError::CandidateIntegrity)?
            .as_bytes(),
    );
    frame(
        &mut bytes,
        certainty_name(value.side_effect_certainty)
            .ok_or(ContentDisclosureError::CandidateIntegrity)?
            .as_bytes(),
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
    require_candidate_digest(candidate, &bytes)
}

fn validate_usage_candidate(
    candidate: &UserVisibleContentCandidate,
    value: &UsageContentCandidate,
) -> Result<(), ContentDisclosureError> {
    let mut bytes = Vec::new();
    frame(&mut bytes, b"egopulse/harness-content/usage-candidate/v1");
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
    require_candidate_digest(candidate, &bytes)
}

fn validate_approval_candidate(
    candidate: &UserVisibleContentCandidate,
    _: &ApprovalRequiredContentCandidate,
) -> Result<(), ContentDisclosureError> {
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        b"egopulse/harness-content/approval-required-candidate/v1",
    );
    require_candidate_digest(candidate, &bytes)
}

fn validate_blocked_candidate(
    candidate: &UserVisibleContentCandidate,
    value: &BlockedSourceContentCandidate,
) -> Result<(), ContentDisclosureError> {
    let mut bytes = Vec::new();
    frame(
        &mut bytes,
        b"egopulse/harness-content/blocked-source-candidate/v1",
    );
    frame(
        &mut bytes,
        marker_name(value.reason)
            .ok_or(ContentDisclosureError::CandidateIntegrity)?
            .as_bytes(),
    );
    require_candidate_digest(candidate, &bytes)
}

fn require_candidate_digest(
    candidate: &UserVisibleContentCandidate,
    bytes: &[u8],
) -> Result<(), ContentDisclosureError> {
    if candidate.candidate_digest_sha256 == sha256(bytes) {
        Ok(())
    } else {
        Err(ContentDisclosureError::CandidateIntegrity)
    }
}

fn operation_name(value: i32) -> Option<&'static str> {
    match ContentMutationOperation::try_from(value).ok()? {
        ContentMutationOperation::Append => Some("APPEND"),
        ContentMutationOperation::Replace => Some("REPLACE"),
        ContentMutationOperation::Finalize => Some("FINALIZE"),
        ContentMutationOperation::Unspecified => None,
    }
}

fn lifecycle_name(value: i32) -> Option<&'static str> {
    use egopulse_domain_contracts::v01::egopulse::harness::v1::LifecycleKind;
    let value = LifecycleKind::try_from(value).ok()?;
    let full = value.as_str_name();
    full.strip_prefix("LIFECYCLE_KIND_")
}

fn certainty_name(value: i32) -> Option<&'static str> {
    use egopulse_domain_contracts::v01::egopulse::harness::v1::SideEffectCertainty;
    let value = SideEffectCertainty::try_from(value).ok()?;
    let full = value.as_str_name();
    full.strip_prefix("SIDE_EFFECT_CERTAINTY_")
}

fn marker_name(value: i32) -> Option<&'static str> {
    let value = HarnessContentMarkerKind::try_from(value).ok()?;
    let full = value.as_str_name();
    full.strip_prefix("HARNESS_CONTENT_MARKER_KIND_")
}

fn limit_kind_name(value: i32) -> Option<&'static str> {
    let value = HarnessContentLimitKind::try_from(value).ok()?;
    let full = value.as_str_name();
    full.strip_prefix("HARNESS_CONTENT_LIMIT_KIND_")
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
    use egopulse_domain_contracts::v01::egopulse::harness::v1::NoCatalogSnapshot;

    #[test]
    fn frozen_no_catalog_route_vector_matches_contract() {
        let binding = DispatchRouteBinding {
            provider_bootstrap_profile_id: "glm-default".to_owned(),
            selected_harness_id: "glm_cli".to_owned(),
            provider_model_id: "glm-5".to_owned(),
            catalog_snapshot: Some(dispatch_route_binding::CatalogSnapshot::NoCatalogSnapshot(
                NoCatalogSnapshot {},
            )),
            capability_profile_id: "glm-cli-v1".to_owned(),
            route_binding_sha256: String::new(),
        };
        assert_eq!(
            canonical_dispatch_route_binding_digest(&binding).as_deref(),
            Some("587d3a6f20042c32eec5f2e0a6152f1aef494dd2d3ea0c7bf5d452c5aaf5d442")
        );
    }
}
