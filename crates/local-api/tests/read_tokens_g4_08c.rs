#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{ClientSurface, ProjectionPosition, SourceDomain, SourceRevision},
};
use egopulse_local_api::{
    read_gateway_policy::ReadGatewayPolicy,
    read_tokens::{
        AwaitTarget, CursorAnchor, CursorCollection, CursorExpectation, CursorIssue, CursorSort,
        ReadTokenCodec, ReadTokenError, ReadTokenScope, TokenMacKey,
    },
    session::{AuthenticatedSession, SessionClock},
};

const API_DIGEST: &str = "28d05e2533ea7650d8fedbc44abfa21d33c2845f8d105650e3287676e789e7bb";
const KERNEL_DIGEST: &str = "0d9222fd5569ce5f7baa062d8353e9565be88da1fc55934e8cc21ba4067629e9";
const POLICY_DIGEST: &str = "5d17887f8e6555d0e4c973583dd07590a68a4be99c8b80a9e31877b9b2ed99b1";

#[derive(Clone)]
struct MutableClock(Arc<Mutex<SystemTime>>);

impl MutableClock {
    fn new(now: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.0.lock().unwrap();
        *now = now.checked_add(duration).unwrap();
    }
}

impl SessionClock for MutableClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

fn contract_ref(id: &str, version: &str, sha256: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn session(surface: ClientSurface) -> AuthenticatedSession {
    AuthenticatedSession {
        session_id: format!("session-{}", surface.as_str_name()),
        authenticated_principal_id: "os-user:founder".to_owned(),
        permission_codes: BTreeSet::from([
            "local.projection.await".to_owned(),
            "local.task.read".to_owned(),
        ]),
        authorization_policy_ref: contract_ref("egopulse.authorization.v1", "0.1.0", POLICY_DIGEST),
        negotiated_contract_ref: contract_ref("egopulse.localapi.v1", "0.1.0-draft.16", API_DIGEST),
        client_kernel_contract_ref: contract_ref(
            "egopulse.client-kernel.v1",
            "0.1.0",
            KERNEL_DIGEST,
        ),
        client_instance_id: format!("client-{}", surface.as_str_name()),
        surface,
        expires_at: UNIX_EPOCH + Duration::from_secs(10_000),
        generation: 1,
    }
}

fn build_codec(clock: &MutableClock, key_byte: u8) -> ReadTokenCodec {
    ReadTokenCodec::new(
        TokenMacKey::new([key_byte; 32]).unwrap(),
        ReadGatewayPolicy::v01(),
        Arc::new(clock.clone()),
    )
}

fn task_cursor_issue() -> CursorIssue {
    CursorIssue {
        collection: CursorCollection::TaskViews,
        filter_sha256: "a".repeat(64),
        sort: CursorSort::TaskUpdatedAtDescTaskIdAsc,
        effective_page_size: 50,
        snapshot_position: ProjectionPosition {
            epoch: "epoch-v01".to_owned(),
            sequence: 12_345,
            projected_at: None,
        },
        anchor: CursorAnchor::Task {
            updated_at_seconds: 1_700_000_000,
            updated_at_nanos: 123,
            task_id: "task-050".to_owned(),
        },
    }
}

fn task_cursor_expectation() -> CursorExpectation {
    CursorExpectation {
        collection: CursorCollection::TaskViews,
        filter_sha256: "a".repeat(64),
        sort: CursorSort::TaskUpdatedAtDescTaskIdAsc,
        effective_page_size: 50,
        current_epoch: "epoch-v01".to_owned(),
        retention_floor: 10_000,
    }
}

fn tamper_one_payload_byte(token: &str) -> String {
    let mut bytes = token.as_bytes().to_vec();
    let index = token.find('.').unwrap() + 1;
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

#[test]
fn scope_is_surface_and_session_neutral_but_capability_sensitive() {
    let cli = ReadTokenScope::from_session(&session(ClientSurface::Cli)).unwrap();
    let tui = ReadTokenScope::from_session(&session(ClientSurface::Tui)).unwrap();
    let desktop = ReadTokenScope::from_session(&session(ClientSurface::Desktop)).unwrap();
    assert_eq!(cli, tui);
    assert_eq!(tui, desktop);

    let mut changed_permission = session(ClientSurface::Cli);
    changed_permission
        .permission_codes
        .insert("local.approval.read".to_owned());
    assert_ne!(
        cli,
        ReadTokenScope::from_session(&changed_permission).unwrap()
    );

    let mut changed_contract = session(ClientSurface::Cli);
    changed_contract.negotiated_contract_ref.sha256 = "f".repeat(64);
    assert_ne!(
        cli,
        ReadTokenScope::from_session(&changed_contract).unwrap()
    );
}

#[test]
fn cursor_round_trips_across_surfaces_and_binds_snapshot_policy_and_scope() {
    let clock = MutableClock::new(UNIX_EPOCH + Duration::from_secs(1_000));
    let codec = build_codec(&clock, 7);
    let cli_scope = ReadTokenScope::from_session(&session(ClientSurface::Cli)).unwrap();
    let desktop_scope = ReadTokenScope::from_session(&session(ClientSurface::Desktop)).unwrap();
    let token = codec.issue_cursor(&cli_scope, task_cursor_issue()).unwrap();
    let verified = codec
        .verify_cursor(&token, &desktop_scope, &task_cursor_expectation())
        .unwrap();
    assert_eq!(verified.snapshot_epoch, "epoch-v01");
    assert_eq!(verified.snapshot_sequence, 12_345);
    assert_eq!(verified.effective_page_size, 50);
    assert!(matches!(verified.anchor, CursorAnchor::Task { .. }));

    let mut wrong_filter = task_cursor_expectation();
    wrong_filter.filter_sha256 = "b".repeat(64);
    assert_eq!(
        codec.verify_cursor(&token, &desktop_scope, &wrong_filter),
        Err(ReadTokenError::BindingMismatch)
    );

    let mut wrong_page_size = task_cursor_expectation();
    wrong_page_size.effective_page_size = 51;
    assert_eq!(
        codec.verify_cursor(&token, &desktop_scope, &wrong_page_size),
        Err(ReadTokenError::BindingMismatch)
    );

    let mut wrong_epoch = task_cursor_expectation();
    wrong_epoch.current_epoch = "epoch-rebuilt".to_owned();
    assert_eq!(
        codec.verify_cursor(&token, &desktop_scope, &wrong_epoch),
        Err(ReadTokenError::ResetRequired)
    );

    let mut outside_retention = task_cursor_expectation();
    outside_retention.retention_floor = 12_346;
    assert_eq!(
        codec.verify_cursor(&token, &desktop_scope, &outside_retention),
        Err(ReadTokenError::ResetRequired)
    );

    let mut changed_principal = session(ClientSurface::Desktop);
    changed_principal.authenticated_principal_id = "os-user:other".to_owned();
    let changed_scope = ReadTokenScope::from_session(&changed_principal).unwrap();
    assert_eq!(
        codec.verify_cursor(&token, &changed_scope, &task_cursor_expectation()),
        Err(ReadTokenError::ScopeMismatch)
    );
}

#[test]
fn cursor_rejects_tampering_rotation_expiry_and_invalid_shape() {
    let clock = MutableClock::new(UNIX_EPOCH + Duration::from_secs(2_000));
    let codec = build_codec(&clock, 9);
    let scope = ReadTokenScope::from_session(&session(ClientSurface::Cli)).unwrap();
    let token = codec.issue_cursor(&scope, task_cursor_issue()).unwrap();

    assert_eq!(
        codec.verify_cursor(
            &tamper_one_payload_byte(&token),
            &scope,
            &task_cursor_expectation()
        ),
        Err(ReadTokenError::InvalidToken)
    );
    assert_eq!(
        build_codec(&clock, 10).verify_cursor(&token, &scope, &task_cursor_expectation()),
        Err(ReadTokenError::InvalidToken)
    );
    for malformed in ["", "c1", "c1.payload", "c1.payload.tag.extra", "a1.x.y"] {
        assert_eq!(
            codec.verify_cursor(malformed, &scope, &task_cursor_expectation()),
            Err(ReadTokenError::InvalidToken)
        );
    }

    clock.advance(Duration::from_secs(1_800));
    assert_eq!(
        codec.verify_cursor(&token, &scope, &task_cursor_expectation()),
        Err(ReadTokenError::Expired)
    );

    let invalid_binding = CursorIssue {
        anchor: CursorAnchor::HarnessApproval {
            projection_sequence: 42,
            approval_request_id: "approval-42".to_owned(),
        },
        ..task_cursor_issue()
    };
    assert_eq!(
        codec.issue_cursor(&scope, invalid_binding),
        Err(ReadTokenError::InvalidInput)
    );
}

#[test]
fn await_token_binds_visible_claims_target_scope_and_expiry() {
    let clock = MutableClock::new(UNIX_EPOCH + Duration::from_secs(3_000));
    let codec = build_codec(&clock, 11);
    let cli_scope = ReadTokenScope::from_session(&session(ClientSurface::Cli)).unwrap();
    let tui_scope = ReadTokenScope::from_session(&session(ClientSurface::Tui)).unwrap();
    let source = SourceRevision {
        domain: SourceDomain::Task as i32,
        aggregate_id: "task-001".to_owned(),
        revision: 8,
        last_event_id: "event-008".to_owned(),
    };
    let token = codec
        .issue_await_token(
            &cli_scope,
            source.clone(),
            AwaitTarget::Task {
                task_id: "task-001".to_owned(),
            },
        )
        .unwrap();
    let verified = codec.verify_await_token(&token, &tui_scope).unwrap();
    assert_eq!(verified.required_source_revision, source);
    assert_eq!(
        verified.target,
        AwaitTarget::Task {
            task_id: "task-001".to_owned()
        }
    );
    assert_eq!(verified.expires_at.seconds, 3_300);

    let mut forged_source = token.clone();
    forged_source
        .required_source_revision
        .as_mut()
        .unwrap()
        .revision += 1;
    assert_eq!(
        codec.verify_await_token(&forged_source, &tui_scope),
        Err(ReadTokenError::BindingMismatch)
    );

    let mut forged_expiry = token.clone();
    forged_expiry.expires_at.as_mut().unwrap().seconds += 1;
    assert_eq!(
        codec.verify_await_token(&forged_expiry, &tui_scope),
        Err(ReadTokenError::BindingMismatch)
    );

    let mut forged_opaque = token.clone();
    forged_opaque.token = tamper_one_payload_byte(&forged_opaque.token);
    assert_eq!(
        codec.verify_await_token(&forged_opaque, &tui_scope),
        Err(ReadTokenError::InvalidToken)
    );

    let mut changed_permission = session(ClientSurface::Tui);
    changed_permission
        .permission_codes
        .insert("local.approval.read".to_owned());
    let changed_scope = ReadTokenScope::from_session(&changed_permission).unwrap();
    assert_eq!(
        codec.verify_await_token(&token, &changed_scope),
        Err(ReadTokenError::ScopeMismatch)
    );

    let invalid_source = SourceRevision {
        domain: i32::MAX,
        ..source
    };
    assert_eq!(
        codec.issue_await_token(
            &cli_scope,
            invalid_source,
            AwaitTarget::Task {
                task_id: "task-001".to_owned()
            }
        ),
        Err(ReadTokenError::InvalidInput)
    );

    clock.advance(Duration::from_secs(300));
    assert_eq!(
        codec.verify_await_token(&token, &tui_scope),
        Err(ReadTokenError::Expired)
    );
}

#[test]
fn approval_cursor_and_await_variants_remain_typed() {
    let clock = MutableClock::new(UNIX_EPOCH + Duration::from_secs(4_000));
    let codec = build_codec(&clock, 12);
    let scope = ReadTokenScope::from_session(&session(ClientSurface::Desktop)).unwrap();
    let cursor = codec
        .issue_cursor(
            &scope,
            CursorIssue {
                collection: CursorCollection::HarnessApprovalViews,
                filter_sha256: "c".repeat(64),
                sort: CursorSort::ApprovalProjectionSequenceDescApprovalRequestIdAsc,
                effective_page_size: 200,
                snapshot_position: ProjectionPosition {
                    epoch: "epoch-v01".to_owned(),
                    sequence: 15_000,
                    projected_at: None,
                },
                anchor: CursorAnchor::HarnessApproval {
                    projection_sequence: 14_950,
                    approval_request_id: "approval-050".to_owned(),
                },
            },
        )
        .unwrap();
    let verified_cursor = codec
        .verify_cursor(
            &cursor,
            &scope,
            &CursorExpectation {
                collection: CursorCollection::HarnessApprovalViews,
                filter_sha256: "c".repeat(64),
                sort: CursorSort::ApprovalProjectionSequenceDescApprovalRequestIdAsc,
                effective_page_size: 200,
                current_epoch: "epoch-v01".to_owned(),
                retention_floor: 10_000,
            },
        )
        .unwrap();
    assert!(matches!(
        verified_cursor.anchor,
        CursorAnchor::HarnessApproval { .. }
    ));

    let approval_await = codec
        .issue_await_token(
            &scope,
            SourceRevision {
                domain: SourceDomain::PolicyDecision as i32,
                aggregate_id: "policy-decision-001".to_owned(),
                revision: 1,
                last_event_id: "event-policy-001".to_owned(),
            },
            AwaitTarget::HarnessApproval {
                approval_request_id: "approval-050".to_owned(),
            },
        )
        .unwrap();
    assert_eq!(
        codec
            .verify_await_token(&approval_await, &scope)
            .unwrap()
            .target,
        AwaitTarget::HarnessApproval {
            approval_request_id: "approval-050".to_owned()
        }
    );
}

#[test]
fn product_composition_cannot_accept_an_all_zero_mac_key() {
    assert!(matches!(
        TokenMacKey::new([0; 32]),
        Err(ReadTokenError::InvalidConfiguration)
    ));
}
