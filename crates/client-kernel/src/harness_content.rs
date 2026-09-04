use std::collections::BTreeMap;

use egopulse_domain_contracts::{
    harness_content::canonical_safe_cumulative_digest,
    profiles::{
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
    },
    v01::egopulse::{
        harness::v1::{
            ContentMutationOperation, HarnessContentLimitKind, HarnessContentMarkerKind,
            HarnessContentSafetyFlag, LifecycleKind, SideEffectCertainty,
        },
        localapi::v1::{
            HarnessAssistantTextView, HarnessContentBaselinePage, HarnessContentPosition,
            HarnessContentRecordView, HarnessContentResetReason, HarnessContentStreamFrame,
            harness_artifact_relation_view, harness_content_record_view,
            harness_content_stream_frame,
        },
    },
};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{KernelError, StreamApply};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_SAFE_TEXT_BYTES: usize = 64 * 1024;
const MAX_SERIALIZED_FRAME_BYTES: usize = 80 * 1024;
const MAX_BASELINE_PAGE_RECORDS: usize = 256;
const MAX_BASELINE_PAGE_TEXT_BYTES: usize = 1024 * 1024;
const MAX_TASK_RECORDS: usize = 65_536;
const MAX_TASK_TEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 16 * 1024;

/// One fully assembled, post-disclosure assistant message. `finalized` means
/// only that this message stopped changing; it never implies Task completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessAssistantMessage {
    pub safe_message_id: String,
    pub task_id: String,
    pub attempt_id: String,
    pub provider_family_alias: String,
    pub model_alias: String,
    pub collaboration_role: String,
    pub revision: u64,
    pub safe_text: String,
    pub safe_cumulative_digest_sha256: String,
    pub provisional: bool,
    pub finalized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessContentFrameApply {
    pub disposition: StreamApply,
    pub changed_message_ids: Vec<String>,
}

#[derive(Clone, Debug)]
struct PendingAssistantMutation {
    task_id: String,
    attempt_id: String,
    provider_family_alias: String,
    model_alias: String,
    collaboration_role: String,
    revision: u64,
    previous_revision: u64,
    operation: ContentMutationOperation,
    safe_cumulative_digest_sha256: String,
    part_count: u32,
    next_part_index: u32,
    safe_text: String,
    provisional: bool,
}

/// Independent operation-record tracker for governed Harness content.
///
/// It deliberately shares no position or reducer state with the complete
/// Task/Approval snapshot tracker.
#[derive(Clone, Debug, Default)]
pub struct HarnessContentStreamTracker {
    baseline_snapshot: Option<HarnessContentPosition>,
    baseline_retained_from_sequence: Option<u64>,
    baseline_last_record_sequence: Option<u64>,
    baseline_complete: bool,
    last_position: Option<HarnessContentPosition>,
    last_records_frame_digest: Option<String>,
    refetch_required: bool,
    seen_record_digests: BTreeMap<String, String>,
    record_count: usize,
    text_bytes: usize,
    pending: BTreeMap<String, PendingAssistantMutation>,
    messages: BTreeMap<String, HarnessAssistantMessage>,
}

impl HarnessContentStreamTracker {
    #[must_use]
    pub fn last_position(&self) -> Option<&HarnessContentPosition> {
        self.last_position.as_ref()
    }

    #[must_use]
    pub const fn baseline_complete(&self) -> bool {
        self.baseline_complete
    }

    #[must_use]
    pub const fn refetch_required(&self) -> bool {
        self.refetch_required
    }

    #[must_use]
    pub fn assistant_message(&self, safe_message_id: &str) -> Option<&HarnessAssistantMessage> {
        self.messages.get(safe_message_id)
    }

    #[must_use]
    pub fn assistant_messages(&self) -> Vec<&HarnessAssistantMessage> {
        self.messages.values().collect()
    }

    /// Apply one page from a fixed-position baseline. A final page seals the
    /// baseline and makes the tracker eligible to consume the paired watch.
    pub fn apply_baseline_page(
        &mut self,
        page: &HarnessContentBaselinePage,
    ) -> Result<Vec<String>, KernelError> {
        if self.baseline_complete || self.refetch_required {
            return Err(KernelError::HarnessContentProtocol(
                "baseline generation is already sealed",
            ));
        }
        validate_profile_ref(page.disclosure_profile_ref.as_ref())?;
        let snapshot = page
            .snapshot_position
            .as_ref()
            .filter(|value| valid_content_position(value))
            .ok_or(KernelError::HarnessContentProtocol(
                "baseline snapshot position is invalid",
            ))?;
        if page.retained_from_sequence > snapshot.sequence.saturating_add(1) {
            return Err(KernelError::HarnessContentProtocol(
                "baseline retention floor is ahead of the snapshot",
            ));
        }
        validate_page_shape(page)?;
        let mut staged = self.clone();
        match staged.baseline_snapshot.as_ref() {
            Some(expected) if expected != snapshot => {
                return Err(KernelError::HarnessContentProtocol(
                    "baseline pages changed snapshot position",
                ));
            }
            None => staged.baseline_snapshot = Some(snapshot.clone()),
            Some(_) => {}
        }
        match staged.baseline_retained_from_sequence {
            Some(expected) if expected != page.retained_from_sequence => {
                return Err(KernelError::HarnessContentProtocol(
                    "baseline pages changed retention floor",
                ));
            }
            None => staged.baseline_retained_from_sequence = Some(page.retained_from_sequence),
            Some(_) => {}
        }
        let mut changed = Vec::new();
        for record in &page.records {
            if record.content_sequence > snapshot.sequence
                || staged
                    .baseline_last_record_sequence
                    .is_some_and(|last| record.content_sequence <= last)
            {
                return Err(KernelError::StreamOutOfOrder);
            }
            if let Some(message_id) = staged.apply_record(record)? {
                changed.push(message_id);
            }
            staged.baseline_last_record_sequence = Some(record.content_sequence);
        }
        if !page.has_more {
            if !staged.pending.is_empty() {
                return Err(KernelError::HarnessContentProtocol(
                    "baseline ended inside a multipart assistant mutation",
                ));
            }
            staged.baseline_complete = true;
            staged.last_position = Some(snapshot.clone());
            staged.last_records_frame_digest = None;
        }
        *self = staged;
        Ok(changed)
    }

    pub fn apply_stream_frame(
        &mut self,
        frame: &HarnessContentStreamFrame,
    ) -> Result<HarnessContentFrameApply, KernelError> {
        if self.refetch_required {
            return Err(KernelError::RefetchRequired);
        }
        if !self.baseline_complete {
            return Err(KernelError::HarnessContentProtocol(
                "a complete content baseline is required before watch",
            ));
        }
        if frame.encoded_len() > MAX_SERIALIZED_FRAME_BYTES {
            return Err(KernelError::HarnessContentProtocol(
                "content frame exceeds the serialized limit",
            ));
        }
        let position = frame
            .position
            .as_ref()
            .filter(|value| valid_content_position(value))
            .ok_or(KernelError::StreamPositionInvalid)?;
        let payload = frame
            .payload
            .as_ref()
            .ok_or(KernelError::IncompleteStreamFrame)?;

        if matches!(
            payload,
            harness_content_stream_frame::Payload::ResetRequired(_)
        ) {
            let harness_content_stream_frame::Payload::ResetRequired(reset) = payload else {
                unreachable!("matched reset payload")
            };
            let reason = HarnessContentResetReason::try_from(reset.reason)
                .map_err(|_| KernelError::UnknownStreamFrame)?;
            if reason == HarnessContentResetReason::Unspecified {
                return Err(KernelError::UnknownStreamFrame);
            }
            self.baseline_snapshot = None;
            self.baseline_retained_from_sequence = None;
            self.baseline_last_record_sequence = None;
            self.baseline_complete = false;
            self.last_position = Some(position.clone());
            self.last_records_frame_digest = None;
            self.refetch_required = true;
            self.seen_record_digests.clear();
            self.record_count = 0;
            self.text_bytes = 0;
            self.pending.clear();
            self.messages.clear();
            return Ok(HarnessContentFrameApply {
                disposition: StreamApply::ResetRequired,
                changed_message_ids: Vec::new(),
            });
        }

        let last = self
            .last_position
            .as_ref()
            .ok_or(KernelError::HarnessContentProtocol(
                "sealed baseline position is missing",
            ))?;
        if last.epoch != position.epoch {
            return Err(KernelError::StreamResetMissing);
        }
        if position.sequence < last.sequence {
            return Err(KernelError::StreamOutOfOrder);
        }

        match payload {
            harness_content_stream_frame::Payload::Heartbeat(_) => {
                if position.sequence > last.sequence {
                    self.last_position = Some(position.clone());
                    self.last_records_frame_digest = None;
                }
                Ok(HarnessContentFrameApply {
                    disposition: StreamApply::Heartbeat,
                    changed_message_ids: Vec::new(),
                })
            }
            harness_content_stream_frame::Payload::Records(records) => {
                if records.records.is_empty() {
                    return Err(KernelError::IncompleteStreamFrame);
                }
                let frame_digest = sha256_hex(&frame.encode_to_vec());
                if position.sequence == last.sequence {
                    if self.last_records_frame_digest.as_deref() == Some(frame_digest.as_str()) {
                        return Ok(HarnessContentFrameApply {
                            disposition: StreamApply::Replay,
                            changed_message_ids: Vec::new(),
                        });
                    }
                    return Err(KernelError::ConflictingStreamReplay);
                }
                let mut staged = self.clone();
                let mut changed = Vec::new();
                let mut previous_sequence = last.sequence;
                for record in &records.records {
                    if record.content_sequence <= previous_sequence
                        || record.content_sequence > position.sequence
                    {
                        return Err(KernelError::StreamOutOfOrder);
                    }
                    if let Some(message_id) = staged.apply_record(record)? {
                        changed.push(message_id);
                    }
                    previous_sequence = record.content_sequence;
                }
                if previous_sequence != position.sequence {
                    return Err(KernelError::HarnessContentProtocol(
                        "record frame position does not match its final record",
                    ));
                }
                staged.last_position = Some(position.clone());
                staged.last_records_frame_digest = Some(frame_digest);
                *self = staged;
                Ok(HarnessContentFrameApply {
                    disposition: StreamApply::Applied,
                    changed_message_ids: changed,
                })
            }
            harness_content_stream_frame::Payload::ResetRequired(_) => {
                unreachable!("reset handled above")
            }
        }
    }

    fn apply_record(
        &mut self,
        record: &HarnessContentRecordView,
    ) -> Result<Option<String>, KernelError> {
        let text_bytes = validate_record(record)?;
        if let Some(existing) = self.seen_record_digests.get(&record.record_id) {
            return if existing == &record.record_digest_sha256 {
                Err(KernelError::HarnessContentProtocol(
                    "baseline or frame repeats a committed content record",
                ))
            } else {
                Err(KernelError::ConflictingStreamReplay)
            };
        }
        if self.record_count >= MAX_TASK_RECORDS
            || self.text_bytes.saturating_add(text_bytes) > MAX_TASK_TEXT_BYTES
        {
            return Err(KernelError::HarnessContentProtocol(
                "content stream exceeded its bounded client state",
            ));
        }
        self.seen_record_digests.insert(
            record.record_id.clone(),
            record.record_digest_sha256.clone(),
        );
        self.record_count += 1;
        self.text_bytes += text_bytes;

        let Some(harness_content_record_view::Payload::AssistantText(text)) =
            record.payload.as_ref()
        else {
            return Ok(None);
        };
        self.apply_assistant_part(record, text)
    }

    fn apply_assistant_part(
        &mut self,
        record: &HarnessContentRecordView,
        text: &HarnessAssistantTextView,
    ) -> Result<Option<String>, KernelError> {
        let operation = ContentMutationOperation::try_from(text.operation)
            .map_err(|_| KernelError::HarnessContentProtocol("assistant operation is unknown"))?;
        if let Some(pending) = self.pending.get_mut(&text.safe_message_id) {
            if text.part_index != pending.next_part_index
                || text.part_count != pending.part_count
                || text.revision != pending.revision
                || text.previous_revision != pending.previous_revision
                || operation != pending.operation
                || text.safe_cumulative_digest_sha256 != pending.safe_cumulative_digest_sha256
                || text.provisional != pending.provisional
                || record.task_id != pending.task_id
                || record.attempt_id != pending.attempt_id
                || record.provider_family_alias != pending.provider_family_alias
                || record.model_alias != pending.model_alias
                || record.collaboration_role != pending.collaboration_role
            {
                return Err(KernelError::HarnessContentProtocol(
                    "multipart assistant mutation changed identity",
                ));
            }
            pending.safe_text.push_str(&text.safe_text_utf8);
            pending.next_part_index += 1;
        } else {
            if text.part_index != 0 {
                return Err(KernelError::HarnessContentProtocol(
                    "multipart assistant mutation did not start at part zero",
                ));
            }
            validate_assistant_predecessor(self.messages.get(&text.safe_message_id), text)?;
            self.pending.insert(
                text.safe_message_id.clone(),
                PendingAssistantMutation {
                    task_id: record.task_id.clone(),
                    attempt_id: record.attempt_id.clone(),
                    provider_family_alias: record.provider_family_alias.clone(),
                    model_alias: record.model_alias.clone(),
                    collaboration_role: record.collaboration_role.clone(),
                    revision: text.revision,
                    previous_revision: text.previous_revision,
                    operation,
                    safe_cumulative_digest_sha256: text.safe_cumulative_digest_sha256.clone(),
                    part_count: text.part_count,
                    next_part_index: 1,
                    safe_text: text.safe_text_utf8.clone(),
                    provisional: text.provisional,
                },
            );
        }

        let complete = self
            .pending
            .get(&text.safe_message_id)
            .is_some_and(|pending| pending.next_part_index == pending.part_count);
        if !complete {
            return Ok(None);
        }
        let pending = self.pending.remove(&text.safe_message_id).ok_or(
            KernelError::HarnessContentProtocol("completed assistant mutation disappeared"),
        )?;
        let previous_text = self
            .messages
            .get(&text.safe_message_id)
            .map_or("", |message| message.safe_text.as_str());
        let safe_text = match pending.operation {
            ContentMutationOperation::Append | ContentMutationOperation::Finalize => {
                let mut value =
                    String::with_capacity(previous_text.len() + pending.safe_text.len());
                value.push_str(previous_text);
                value.push_str(&pending.safe_text);
                value
            }
            ContentMutationOperation::Replace => pending.safe_text,
            ContentMutationOperation::Unspecified => {
                return Err(KernelError::HarnessContentProtocol(
                    "assistant operation is unspecified",
                ));
            }
        };
        if canonical_safe_cumulative_digest(&safe_text) != pending.safe_cumulative_digest_sha256 {
            return Err(KernelError::HarnessContentProtocol(
                "assistant cumulative digest does not match assembled text",
            ));
        }
        let message_id = text.safe_message_id.clone();
        self.messages.insert(
            message_id.clone(),
            HarnessAssistantMessage {
                safe_message_id: message_id.clone(),
                task_id: pending.task_id,
                attempt_id: pending.attempt_id,
                provider_family_alias: pending.provider_family_alias,
                model_alias: pending.model_alias,
                collaboration_role: pending.collaboration_role,
                revision: pending.revision,
                safe_text,
                safe_cumulative_digest_sha256: pending.safe_cumulative_digest_sha256,
                provisional: pending.provisional,
                finalized: pending.operation == ContentMutationOperation::Finalize,
            },
        );
        Ok(Some(message_id))
    }
}

fn validate_page_shape(page: &HarnessContentBaselinePage) -> Result<(), KernelError> {
    if page.records.len() > MAX_BASELINE_PAGE_RECORDS
        || page
            .records
            .iter()
            .map(record_text_bytes)
            .try_fold(0usize, |total, value| {
                value.map(|value| total.saturating_add(value))
            })?
            > MAX_BASELINE_PAGE_TEXT_BYTES
    {
        return Err(KernelError::HarnessContentProtocol(
            "content baseline page exceeds its bound",
        ));
    }
    match (page.has_more, page.next_page_cursor.as_deref()) {
        (true, Some(cursor))
            if !page.records.is_empty()
                && !cursor.is_empty()
                && cursor.len() <= MAX_CURSOR_BYTES
                && !cursor.chars().any(char::is_control) =>
        {
            Ok(())
        }
        (false, None) => Ok(()),
        _ => Err(KernelError::HarnessContentProtocol(
            "content baseline continuation is contradictory",
        )),
    }
}

fn validate_record(record: &HarnessContentRecordView) -> Result<usize, KernelError> {
    if !prefixed_sha256(&record.record_id, "hcr_")
        || !canonical_sha256(&record.record_digest_sha256)
        || record.content_sequence == 0
        || !valid_identifier(&record.task_id)
        || !valid_identifier(&record.attempt_id)
        || !valid_label(&record.provider_family_alias)
        || !valid_label(&record.model_alias)
        || !valid_label(&record.collaboration_role)
        || record
            .projected_at
            .as_ref()
            .is_none_or(|value| !valid_timestamp(value))
    {
        return Err(KernelError::HarnessContentProtocol(
            "content record identity is invalid",
        ));
    }
    validate_profile_ref(record.disclosure_profile_ref.as_ref())?;
    let mut previous = None;
    for raw in &record.safety_flags {
        let flag = HarnessContentSafetyFlag::try_from(*raw)
            .map_err(|_| KernelError::HarnessContentProtocol("content safety flag is unknown"))?;
        if flag == HarnessContentSafetyFlag::Unspecified
            || previous.is_some_and(|value| value >= *raw)
        {
            return Err(KernelError::HarnessContentProtocol(
                "content safety flags are not canonical",
            ));
        }
        previous = Some(*raw);
    }
    let payload = record
        .payload
        .as_ref()
        .ok_or(KernelError::IncompleteStreamFrame)?;
    match payload {
        harness_content_record_view::Payload::AssistantText(value) => {
            validate_assistant_text(value, &record.safety_flags)?;
            Ok(value.safe_text_utf8.len())
        }
        harness_content_record_view::Payload::Lifecycle(value) => {
            let lifecycle = LifecycleKind::try_from(value.kind).map_err(|_| {
                KernelError::HarnessContentProtocol("content lifecycle kind is unknown")
            })?;
            let certainty =
                SideEffectCertainty::try_from(value.side_effect_certainty).map_err(|_| {
                    KernelError::HarnessContentProtocol("side-effect certainty is unknown")
                })?;
            if lifecycle == LifecycleKind::Unspecified
                || certainty == SideEffectCertainty::Unspecified
            {
                return Err(KernelError::HarnessContentProtocol(
                    "content lifecycle is unspecified",
                ));
            }
            Ok(0)
        }
        harness_content_record_view::Payload::Usage(_) => Ok(0),
        harness_content_record_view::Payload::ApprovalRequired(_) => Ok(0),
        harness_content_record_view::Payload::ArtifactRelation(value) => {
            match value.visibility.as_ref() {
                Some(harness_artifact_relation_view::Visibility::Available(artifact))
                    if valid_identifier(&artifact.artifact_id)
                        && canonical_sha256(&artifact.artifact_digest_sha256) =>
                {
                    Ok(0)
                }
                Some(harness_artifact_relation_view::Visibility::AvailableRedacted(_)) => Ok(0),
                _ => Err(KernelError::HarnessContentProtocol(
                    "artifact relation visibility is invalid",
                )),
            }
        }
        harness_content_record_view::Payload::Marker(value) => {
            let kind = HarnessContentMarkerKind::try_from(value.kind).map_err(|_| {
                KernelError::HarnessContentProtocol("content marker kind is unknown")
            })?;
            let limit = HarnessContentLimitKind::try_from(value.limit_kind).map_err(|_| {
                KernelError::HarnessContentProtocol("content limit kind is unknown")
            })?;
            if kind == HarnessContentMarkerKind::Unspecified
                || (kind == HarnessContentMarkerKind::LimitReached
                    && limit == HarnessContentLimitKind::Unspecified)
                || (kind != HarnessContentMarkerKind::LimitReached
                    && limit != HarnessContentLimitKind::Unspecified)
            {
                return Err(KernelError::HarnessContentProtocol(
                    "content marker and limit kind conflict",
                ));
            }
            Ok(0)
        }
    }
}

fn record_text_bytes(record: &HarnessContentRecordView) -> Result<usize, KernelError> {
    match record.payload.as_ref() {
        Some(harness_content_record_view::Payload::AssistantText(value)) => {
            Ok(value.safe_text_utf8.len())
        }
        Some(_) => Ok(0),
        None => Err(KernelError::IncompleteStreamFrame),
    }
}

fn validate_assistant_text(
    value: &HarnessAssistantTextView,
    safety_flags: &[i32],
) -> Result<(), KernelError> {
    let operation = ContentMutationOperation::try_from(value.operation)
        .map_err(|_| KernelError::HarnessContentProtocol("assistant operation is unknown"))?;
    let flag_provisional = safety_flags.contains(&(HarnessContentSafetyFlag::Provisional as i32));
    if !prefixed_sha256(&value.safe_message_id, "hcm_")
        || value.revision == 0
        || value.previous_revision >= value.revision
        || (value.revision == 1 && value.previous_revision != 0)
        || (value.revision > 1 && value.previous_revision + 1 != value.revision)
        || operation == ContentMutationOperation::Unspecified
        || value.safe_text_utf8.len() > MAX_SAFE_TEXT_BYTES
        || !canonical_sha256(&value.safe_cumulative_digest_sha256)
        || value.part_count == 0
        || value.part_index >= value.part_count
        || value.provisional != flag_provisional
    {
        return Err(KernelError::HarnessContentProtocol(
            "assistant text record is invalid",
        ));
    }
    Ok(())
}

fn validate_assistant_predecessor(
    previous: Option<&HarnessAssistantMessage>,
    incoming: &HarnessAssistantTextView,
) -> Result<(), KernelError> {
    match previous {
        None if incoming.revision == 1 && incoming.previous_revision == 0 => Ok(()),
        Some(previous)
            if !previous.finalized
                && incoming.previous_revision == previous.revision
                && incoming.revision == previous.revision.saturating_add(1) =>
        {
            Ok(())
        }
        _ => Err(KernelError::HarnessContentProtocol(
            "assistant revision predecessor is invalid",
        )),
    }
}

fn validate_profile_ref(
    profile: Option<&egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference>,
) -> Result<(), KernelError> {
    if profile.is_some_and(|value| {
        value.contract_id == HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
            && value.version == HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
            && value.sha256 == HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
    }) {
        Ok(())
    } else {
        Err(KernelError::ContractMismatch("harness_content_disclosure"))
    }
}

fn valid_content_position(position: &HarnessContentPosition) -> bool {
    valid_identifier(&position.epoch) && position.projected_at.as_ref().is_none_or(valid_timestamp)
}

fn valid_timestamp(value: &prost_types::Timestamp) -> bool {
    value.seconds >= 0 && (0..1_000_000_000).contains(&value.nanos)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(canonical_sha256)
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
