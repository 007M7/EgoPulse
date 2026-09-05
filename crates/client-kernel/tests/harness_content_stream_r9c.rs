#![forbid(unsafe_code)]

use egopulse_client_kernel::{HarnessContentStreamTracker, KernelError, StreamApply};
use egopulse_domain_contracts::{
    harness_content::canonical_safe_cumulative_digest,
    profiles::{
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
    },
    v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::{ContentMutationOperation, HarnessContentSafetyFlag},
        localapi::v1::{
            HarnessAssistantTextView, HarnessContentBaselinePage, HarnessContentPosition,
            HarnessContentRecordView, HarnessContentRecordsFrame, HarnessContentResetReason,
            HarnessContentResetRequiredFrame, HarnessContentStreamFrame,
            harness_content_record_view, harness_content_stream_frame,
        },
    },
};
use prost_types::Timestamp;

fn position(epoch: &str, sequence: u64) -> HarnessContentPosition {
    HarnessContentPosition {
        epoch: epoch.to_owned(),
        sequence,
        projected_at: (sequence > 0).then_some(Timestamp {
            seconds: sequence as i64,
            nanos: 0,
        }),
    }
}

fn profile() -> ContractReference {
    ContractReference {
        contract_id: HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID.to_owned(),
        version: HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION.to_owned(),
        sha256: HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn assistant_record(
    sequence: u64,
    revision: u64,
    previous_revision: u64,
    operation: ContentMutationOperation,
    text: &str,
    cumulative: &str,
    part_index: u32,
    part_count: u32,
) -> HarnessContentRecordView {
    HarnessContentRecordView {
        record_id: format!("hcr_{sequence:064x}"),
        record_digest_sha256: format!("{:064x}", sequence + 1_000),
        content_sequence: sequence,
        task_id: "task-001".to_owned(),
        attempt_id: "attempt-001".to_owned(),
        provider_family_alias: "openai".to_owned(),
        model_alias: "gpt-governed".to_owned(),
        collaboration_role: "primary".to_owned(),
        disclosure_profile_ref: Some(profile()),
        projected_at: Some(Timestamp {
            seconds: sequence as i64,
            nanos: 0,
        }),
        safety_flags: vec![HarnessContentSafetyFlag::Provisional as i32],
        payload: Some(harness_content_record_view::Payload::AssistantText(
            HarnessAssistantTextView {
                safe_message_id: format!("hcm_{:064x}", 77),
                revision,
                previous_revision,
                operation: operation as i32,
                safe_text_utf8: text.to_owned(),
                safe_cumulative_digest_sha256: canonical_safe_cumulative_digest(cumulative),
                part_index,
                part_count,
                provisional: true,
            },
        )),
    }
}

fn baseline_page(
    records: Vec<HarnessContentRecordView>,
    snapshot_sequence: u64,
    has_more: bool,
) -> HarnessContentBaselinePage {
    HarnessContentBaselinePage {
        records,
        next_page_cursor: has_more.then(|| "opaque-next-page".to_owned()),
        has_more,
        snapshot_position: Some(position("content-epoch-01", snapshot_sequence)),
        retained_from_sequence: 0,
        disclosure_profile_ref: Some(profile()),
    }
}

fn records_frame(record: HarnessContentRecordView) -> HarnessContentStreamFrame {
    HarnessContentStreamFrame {
        position: Some(position("content-epoch-01", record.content_sequence)),
        payload: Some(harness_content_stream_frame::Payload::Records(
            HarnessContentRecordsFrame {
                records: vec![record],
            },
        )),
    }
}

#[test]
fn baseline_and_watch_assemble_append_replace_and_finalize_without_task_semantics() {
    let mut tracker = HarnessContentStreamTracker::default();
    tracker
        .apply_baseline_page(&baseline_page(
            vec![assistant_record(
                1,
                1,
                0,
                ContentMutationOperation::Append,
                "hel",
                "hello",
                0,
                2,
            )],
            2,
            true,
        ))
        .unwrap();
    assert!(!tracker.baseline_complete());
    tracker
        .apply_baseline_page(&baseline_page(
            vec![assistant_record(
                2,
                1,
                0,
                ContentMutationOperation::Append,
                "lo",
                "hello",
                1,
                2,
            )],
            2,
            false,
        ))
        .unwrap();
    assert!(tracker.baseline_complete());
    assert_eq!(tracker.assistant_messages()[0].safe_text, "hello");

    let append = records_frame(assistant_record(
        3,
        2,
        1,
        ContentMutationOperation::Append,
        "!",
        "hello!",
        0,
        1,
    ));
    let applied = tracker.apply_stream_frame(&append).unwrap();
    assert_eq!(applied.disposition, StreamApply::Applied);
    assert_eq!(applied.changed_message_ids.len(), 1);
    assert_eq!(tracker.assistant_messages()[0].safe_text, "hello!");
    assert_eq!(
        tracker.apply_stream_frame(&append).unwrap().disposition,
        StreamApply::Replay
    );

    tracker
        .apply_stream_frame(&records_frame(assistant_record(
            4,
            3,
            2,
            ContentMutationOperation::Replace,
            "world",
            "world",
            0,
            1,
        )))
        .unwrap();
    tracker
        .apply_stream_frame(&records_frame(assistant_record(
            5,
            4,
            3,
            ContentMutationOperation::Finalize,
            "",
            "world",
            0,
            1,
        )))
        .unwrap();
    let message = tracker.assistant_messages()[0];
    assert_eq!(message.safe_text, "world");
    assert!(message.finalized);
    assert!(message.provisional);
}

#[test]
fn reset_discards_incomplete_assembly_and_requires_a_new_baseline() {
    let mut tracker = HarnessContentStreamTracker::default();
    tracker
        .apply_baseline_page(&baseline_page(Vec::new(), 0, false))
        .unwrap();
    tracker
        .apply_stream_frame(&records_frame(assistant_record(
            1,
            1,
            0,
            ContentMutationOperation::Append,
            "half",
            "half-done",
            0,
            2,
        )))
        .unwrap();
    assert!(tracker.assistant_messages().is_empty());

    let reset = HarnessContentStreamFrame {
        position: Some(position("content-epoch-02", 0)),
        payload: Some(harness_content_stream_frame::Payload::ResetRequired(
            HarnessContentResetRequiredFrame {
                reason: HarnessContentResetReason::RetentionCompacted as i32,
            },
        )),
    };
    assert_eq!(
        tracker.apply_stream_frame(&reset).unwrap().disposition,
        StreamApply::ResetRequired
    );
    assert!(tracker.refetch_required());
    assert!(tracker.assistant_messages().is_empty());
    assert!(matches!(
        tracker.apply_stream_frame(&reset),
        Err(KernelError::RefetchRequired)
    ));
}

#[test]
fn invalid_multi_record_frame_is_rejected_atomically() {
    let mut tracker = HarnessContentStreamTracker::default();
    tracker
        .apply_baseline_page(&baseline_page(Vec::new(), 0, false))
        .unwrap();
    let first = assistant_record(
        1,
        1,
        0,
        ContentMutationOperation::Append,
        "safe",
        "safe",
        0,
        1,
    );
    let mut invalid = assistant_record(
        2,
        2,
        1,
        ContentMutationOperation::Append,
        "!",
        "safe!",
        0,
        1,
    );
    let Some(harness_content_record_view::Payload::AssistantText(text)) = invalid.payload.as_mut()
    else {
        panic!("assistant payload")
    };
    text.safe_cumulative_digest_sha256 = "f".repeat(64);
    let frame = HarnessContentStreamFrame {
        position: Some(position("content-epoch-01", 2)),
        payload: Some(harness_content_stream_frame::Payload::Records(
            HarnessContentRecordsFrame {
                records: vec![first, invalid],
            },
        )),
    };
    assert!(matches!(
        tracker.apply_stream_frame(&frame),
        Err(KernelError::HarnessContentProtocol(_))
    ));
    assert!(tracker.assistant_messages().is_empty());
    assert_eq!(tracker.last_position().unwrap().sequence, 0);
}
