use egopulse_domain_contracts::v01::egopulse::{
    localapi::v1::PrepareWorkRequest, task::v1::TaskSnapshot,
};
use prost::Message;

// Fixed bytes emitted by the pre-draft.23 shape. These fixtures are written
// literally so the test cannot accidentally regenerate history with the new
// types it is intended to verify.
const PRE_DRAFT23_PREPARE_WORK: &[u8] = &[
    0x12, 0x05, b'h', b'e', b'l', b'l', b'o', 0x1a, 0x04, b'c', b'o', b'd', b'e', 0x22, 0x05, b's',
    b'c', b'o', b'p', b'e', 0x32, 0x03, b'k', b'e', b'y',
];

const PRE_DRAFT23_TASK_SNAPSHOT: &[u8] = &[
    0x0a, 0x06, b't', b'a', b's', b'k', b'-', b'1', 0x10, 0x01, 0x18, 0x01, 0x20, 0x01, 0x32, 0x04,
    b'c', b'o', b'd', b'e', 0x3a, 0x05, b'c', b't', b'x', b'-', b'1', 0x42, 0x05, b's', b'c', b'o',
    b'p', b'e',
];

#[test]
fn pre_draft23_prepare_work_bytes_decode_with_omitted_capability_preference() {
    let request = PrepareWorkRequest::decode(PRE_DRAFT23_PREPARE_WORK)
        .expect("decode fixed pre-draft.23 PrepareWorkRequest bytes");
    assert_eq!(request.intent, "hello");
    assert_eq!(request.work_type, "code");
    assert_eq!(request.target_scope_ref, "scope");
    assert_eq!(request.idempotency_key, "key");
    assert!(request.work_capability_preference.is_none());
}

#[test]
fn pre_draft23_task_snapshot_bytes_decode_with_no_route_binding() {
    let snapshot = TaskSnapshot::decode(PRE_DRAFT23_TASK_SNAPSHOT)
        .expect("decode fixed pre-draft.23 TaskSnapshot bytes");
    assert_eq!(snapshot.task_id, "task-1");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.work_revision, 1);
    assert_eq!(snapshot.work_type, "code");
    assert_eq!(snapshot.input_snapshot_id, "ctx-1");
    assert_eq!(snapshot.target_scope_ref, "scope");
    assert!(snapshot.work_capability_route.is_none());
}
