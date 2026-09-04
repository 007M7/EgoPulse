#![forbid(unsafe_code)]

use egopulse_client_kernel::StreamApply;
use egopulse_client_operations::{
    ClientHarnessContentError, HarnessContentDriver, HarnessContentFilter, HarnessContentUpdateKind,
};
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

fn record(
    sequence: u64,
    revision: u64,
    previous: u64,
    text: &str,
    cumulative: &str,
) -> HarnessContentRecordView {
    HarnessContentRecordView {
        record_id: format!("hcr_{sequence:064x}"),
        record_digest_sha256: format!("{:064x}", sequence + 900),
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
                safe_message_id: format!("hcm_{:064x}", 22),
                revision,
                previous_revision: previous,
                operation: ContentMutationOperation::Append as i32,
                safe_text_utf8: text.to_owned(),
                safe_cumulative_digest_sha256: canonical_safe_cumulative_digest(cumulative),
                part_index: 0,
                part_count: 1,
                provisional: true,
            },
        )),
    }
}

fn baseline(records: Vec<HarnessContentRecordView>, sequence: u64) -> HarnessContentBaselinePage {
    HarnessContentBaselinePage {
        records,
        next_page_cursor: None,
        has_more: false,
        snapshot_position: Some(position("content-epoch-01", sequence)),
        retained_from_sequence: 0,
        disclosure_profile_ref: Some(profile()),
    }
}

fn frame(record: HarnessContentRecordView) -> HarnessContentStreamFrame {
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
fn shared_driver_pairs_baseline_with_source_labelled_operation_updates() {
    let filter = HarnessContentFilter::new("task-001", vec!["attempt-001".to_owned()]).unwrap();
    let mut driver = HarnessContentDriver::new(filter);
    driver
        .apply_baseline_page(&baseline(vec![record(1, 1, 0, "hello", "hello")], 1))
        .unwrap();
    assert!(driver.baseline_complete());
    assert_eq!(driver.records().len(), 1);
    assert_eq!(driver.assistant_messages()[0].safe_text, "hello");

    let next = frame(record(2, 2, 1, " world", "hello world"));
    let update = driver.apply_stream_frame(&next).unwrap();
    assert_eq!(update.disposition, StreamApply::Applied);
    assert_eq!(update.kind, HarnessContentUpdateKind::Records);
    assert_eq!(update.records[0].provider_family_alias, "openai");
    assert_eq!(update.records[0].model_alias, "gpt-governed");
    assert_eq!(update.changed_messages[0].safe_text, "hello world");
    assert_eq!(driver.records().len(), 2);

    let replay = driver.apply_stream_frame(&next).unwrap();
    assert_eq!(replay.disposition, StreamApply::Replay);
    assert!(replay.records.is_empty());
    assert_eq!(driver.records().len(), 2);
}

#[test]
fn reset_clears_only_the_content_generation_and_closes_the_session_state() {
    let mut driver =
        HarnessContentDriver::new(HarnessContentFilter::new("task-001", Vec::new()).unwrap());
    driver
        .apply_baseline_page(&baseline(vec![record(1, 1, 0, "safe", "safe")], 1))
        .unwrap();
    let reset = HarnessContentStreamFrame {
        position: Some(position("content-epoch-02", 0)),
        payload: Some(harness_content_stream_frame::Payload::ResetRequired(
            HarnessContentResetRequiredFrame {
                reason: HarnessContentResetReason::EpochChanged as i32,
            },
        )),
    };
    let update = driver.apply_stream_frame(&reset).unwrap();
    assert_eq!(update.kind, HarnessContentUpdateKind::ResetRequired);
    assert_eq!(
        update.reset_reason,
        Some(HarnessContentResetReason::EpochChanged)
    );
    assert!(driver.records().is_empty());
    assert!(driver.assistant_messages().is_empty());
    assert!(driver.refetch_required());
    assert!(matches!(
        driver.apply_stream_frame(&reset),
        Err(ClientHarnessContentError::ResetBarrier)
    ));
}

#[test]
fn filter_is_canonical_and_rejects_scope_escape_before_kernel_apply() {
    let filter = HarnessContentFilter::new(
        "task-001",
        vec!["attempt-002".to_owned(), "attempt-001".to_owned()],
    )
    .unwrap();
    assert_eq!(
        filter.attempt_ids(),
        &["attempt-001".to_owned(), "attempt-002".to_owned()]
    );
    assert!(matches!(
        HarnessContentFilter::new(
            "task-001",
            vec!["attempt-001".to_owned(), "attempt-001".to_owned()]
        ),
        Err(ClientHarnessContentError::InvalidInput(_))
    ));

    let mut driver = HarnessContentDriver::new(filter);
    let mut escaped = record(1, 1, 0, "safe", "safe");
    escaped.task_id = "task-foreign".to_owned();
    assert!(matches!(
        driver.apply_baseline_page(&baseline(vec![escaped], 1)),
        Err(ClientHarnessContentError::Protocol(_))
    ));
    assert!(!driver.baseline_complete());
    assert!(driver.records().is_empty());
}
