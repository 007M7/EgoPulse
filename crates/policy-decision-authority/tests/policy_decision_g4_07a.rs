use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalDecisionEnvelope, ApprovalDecisionReceipt, ApprovalKind,
    ApprovalRequestLifecycleKind, DeliveryDisposition,
};
use egopulse_domain_contracts::v01::egopulse::policy::v1::{
    ConsumeHarnessApprovalDecisionCommand, ExpireHarnessApprovalDecisionCommand,
    HarnessApprovalDecisionRecord, HarnessApprovalDecisionStateKind, HarnessApprovalRequestBinding,
    IssueHarnessApprovalDecisionCommand, PolicyAuthorityProof, PolicyDecisionCommand,
    PolicyDecisionErrorCode, RevokeHarnessApprovalDecisionCommand, policy_decision_command,
};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyAuthorityConfig, PolicyAuthorityFailure, PolicyClock,
    PolicyDecisionAuthority, PolicyPrincipalKind, PolicyReferenceRejection,
    PolicyReferenceResolver, PolicySqlCipherKey, ResolvedApprovalAuthorization,
    canonical_receipt_digest, canonical_request_digest,
};
use prost::Message;
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const NOW: i64 = 1_782_100_000;
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CRASH_PROBE: &str = "EGOPULSE_G4_07A_CRASH_PROBE";
const CRASH_DB: &str = "EGOPULSE_G4_07A_CRASH_DB";

#[derive(Clone, Copy)]
struct FixedClock(i64);

impl PolicyClock for FixedClock {
    fn now(&self) -> Result<Timestamp, PolicyAuthorityFailure> {
        Ok(timestamp(self.0))
    }
}

#[derive(Clone)]
struct StaticResolver {
    expires_at: i64,
    receipt_valid: bool,
    issue_rejection: Option<PolicyReferenceRejection>,
    request_override: Option<HarnessApprovalRequestBinding>,
}

impl PolicyReferenceResolver for StaticResolver {
    fn resolve_issue(
        &self,
        _command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        if let Some(rejection) = self.issue_rejection {
            return Err(rejection);
        }
        Ok(ResolvedApprovalAuthorization {
            request: self
                .request_override
                .clone()
                .unwrap_or_else(request_binding),
            authority_proof: PolicyAuthorityProof {
                authenticated_principal_id: principal.principal_id.clone(),
                authentication_context_ref: "ipc-session:trusted-local-user".to_owned(),
                authorization_policy_ref: Some(contract_ref()),
                authorization_decision_id: "policy-evaluation:allow-01".to_owned(),
                verified_at: Some(timestamp(NOW - 1)),
            },
            evidence_refs: vec![
                "harness-observation:approval-01".to_owned(),
                "policy-evaluation:allow-01".to_owned(),
            ],
            expires_at: timestamp(self.expires_at),
        })
    }

    fn validate_adapter_receipt(
        &self,
        _command: &ConsumeHarnessApprovalDecisionCommand,
        _record: &HarnessApprovalDecisionRecord,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        if self.receipt_valid && principal.kind == PolicyPrincipalKind::HarnessAdapter {
            Ok(vec!["adapter-edge:durable-receipt-01".to_owned()])
        } else {
            Err(PolicyReferenceRejection::DeliveryReceiptInvalid)
        }
    }

    fn validate_revoke(
        &self,
        _command: &RevokeHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Ok(vec!["founder-confirmation:revoke-01".to_owned()])
    }

    fn validate_expiry(
        &self,
        _command: &ExpireHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Ok(vec!["policy-evaluation:expired-01".to_owned()])
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-07a-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated test root");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("policy-decision.db")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("egopulse-g4-07a-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn issue_is_authoritative_immutable_idempotent_and_exactly_routed() {
    let root = TempRoot::new("issue");
    let mut authority = open_authority(&root.database(), NOW, NOW + 300);
    let mut command = issue_command();

    let denied = authority
        .execute(&command, &principal(PolicyPrincipalKind::Model, "model:01"))
        .expect("model denial");
    assert_eq!(
        denied.error_code,
        PolicyDecisionErrorCode::PermissionDenied as i32
    );
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        0
    );

    let unauthenticated = AuthenticatedPolicyPrincipal {
        kind: PolicyPrincipalKind::LocalUser,
        principal_id: "local-user:forged".to_owned(),
        authenticated: false,
    };
    let denied = authority
        .execute(&command, &unauthenticated)
        .expect("unauthenticated denial");
    assert_eq!(
        denied.error_code,
        PolicyDecisionErrorCode::Unauthenticated as i32
    );

    sign(&mut command);
    let issued = authority
        .execute(&command, &local_user())
        .expect("issue approval decision");
    assert!(issued.committed);
    let record = issued.decision_record.as_ref().expect("decision record");
    assert!(
        record
            .authority_decision_ref
            .starts_with("policy-decision-")
    );
    assert_eq!(record.request.as_ref(), Some(&request_binding()));
    assert_eq!(record.canonical_payload_digest_sha256.len(), 64);
    assert_eq!(
        issued.state.as_ref().expect("state").state,
        HarnessApprovalDecisionStateKind::Issued as i32
    );

    let outbox = authority.pending_outbox().expect("pending outbox");
    assert_eq!(outbox.len(), 2);
    let adapter = outbox
        .iter()
        .find(|item| item.destination_domain == "harness-adapter")
        .expect("adapter outbox");
    let envelope = ApprovalDecisionEnvelope::decode(adapter.payload.as_slice()).expect("envelope");
    assert_eq!(
        envelope.authority_decision_ref,
        record.authority_decision_ref
    );
    assert_eq!(envelope.native_routing_ref, "native-route:approval-01");
    assert_eq!(envelope.fencing_token, 9);
    assert_eq!(envelope.action_digest_sha256, SHA_A);

    let replay = authority.execute(&command, &local_user()).expect("replay");
    assert!(replay.replayed);
    assert_eq!(
        replay
            .decision_record
            .as_ref()
            .map(|value| &value.authority_decision_ref),
        Some(&record.authority_decision_ref)
    );
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        1
    );

    let mut conflict = command.clone();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        conflict.command.as_mut()
    {
        issue.decision = ApprovalDecision::Deny as i32;
    }
    sign(&mut conflict);
    let conflict = authority
        .execute(&conflict, &local_user())
        .expect("conflict");
    assert_eq!(
        conflict.error_code,
        PolicyDecisionErrorCode::IdempotencyConflict as i32
    );
}

#[test]
fn request_mismatch_and_identity_forgery_fail_with_zero_writes() {
    let root = TempRoot::new("mismatch");
    let mut authority = open_authority(&root.database(), NOW, NOW + 300);
    let mut mismatch = issue_command();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
        mismatch.command.as_mut()
    {
        issue.expected_action_digest_sha256 = SHA_B.to_owned();
    }
    sign(&mut mismatch);
    let rejected = authority
        .execute(&mismatch, &local_user())
        .expect("mismatch");
    assert_eq!(
        rejected.error_code,
        PolicyDecisionErrorCode::RequestMismatch as i32
    );
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        0
    );

    let mut valid = issue_command();
    sign(&mut valid);

    let fenced_root = TempRoot::new("fenced");
    let mut fenced = open_authority_with_resolver(
        &fenced_root.database(),
        NOW,
        StaticResolver {
            expires_at: NOW + 300,
            receipt_valid: true,
            issue_rejection: Some(PolicyReferenceRejection::FencingRejected),
            request_override: None,
        },
    );
    let rejected = fenced.execute(&valid, &local_user()).expect("fence denial");
    assert_eq!(
        rejected.error_code,
        PolicyDecisionErrorCode::FencingRejected as i32
    );
    assert_eq!(fenced.inspect_store().expect("inspect").decision_count, 0);

    for kind in [
        PolicyPrincipalKind::UserInterface,
        PolicyPrincipalKind::HarnessAdapter,
    ] {
        let rejected = authority
            .execute(&valid, &principal(kind, "forged:principal"))
            .expect("forgery denial");
        assert_eq!(
            rejected.error_code,
            PolicyDecisionErrorCode::PermissionDenied as i32
        );
    }
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        0
    );
}

#[test]
fn withdrawn_or_stale_request_revision_cannot_be_decided() {
    let root = TempRoot::new("withdrawn-request");
    let mut withdrawn = request_binding();
    withdrawn.request_lifecycle = ApprovalRequestLifecycleKind::Withdrawn as i32;
    withdrawn.request_revision = 2;
    let mut authority = open_authority_with_resolver(
        &root.database(),
        NOW,
        StaticResolver {
            expires_at: NOW + 300,
            receipt_valid: true,
            issue_rejection: None,
            request_override: Some(withdrawn),
        },
    );
    let mut command = issue_command();
    sign(&mut command);
    let rejected = authority
        .execute(&command, &local_user())
        .expect("withdrawn request denial");
    assert_eq!(
        rejected.error_code,
        PolicyDecisionErrorCode::RevisionConflict as i32
    );
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        0
    );
    assert!(authority.pending_outbox().expect("outbox").is_empty());
}

#[test]
fn adapter_receipt_is_bound_final_and_consumed_once() {
    let root = TempRoot::new("consume");
    let mut authority = open_authority(&root.database(), NOW, NOW + 300);
    let mut issue = issue_command();
    sign(&mut issue);
    let issued = authority.execute(&issue, &local_user()).expect("issue");
    let decision_ref = issued
        .decision_record
        .as_ref()
        .expect("record")
        .authority_decision_ref
        .clone();

    let mut unknown = consume_command(&decision_ref, DeliveryDisposition::Unknown);
    sign(&mut unknown);
    let rejected = authority
        .execute(&unknown, &adapter())
        .expect("unknown denial");
    assert_eq!(
        rejected.error_code,
        PolicyDecisionErrorCode::DeliveryReceiptInvalid as i32
    );
    assert_eq!(authority.inspect_store().expect("inspect").event_count, 1);
    assert_eq!(
        authority.pending_outbox().expect("outbox retained").len(),
        2
    );

    let mut mismatched = consume_command(&decision_ref, DeliveryDisposition::Delivered);
    if let Some(policy_decision_command::Command::ConsumeHarnessApprovalDecision(command)) =
        mismatched.command.as_mut()
    {
        let receipt = command.adapter_receipt.as_mut().expect("receipt");
        receipt.decision = ApprovalDecision::Deny as i32;
        receipt.receipt_digest_sha256 = canonical_receipt_digest(receipt);
        command.metadata.as_mut().expect("meta").idempotency_key = "consume-mismatched".to_owned();
    }
    sign(&mut mismatched);
    let rejected = authority
        .execute(&mismatched, &adapter())
        .expect("mismatched receipt denial");
    assert_eq!(
        rejected.error_code,
        PolicyDecisionErrorCode::DeliveryReceiptInvalid as i32
    );
    assert_eq!(authority.inspect_store().expect("inspect").event_count, 1);

    let mut valid = consume_command(&decision_ref, DeliveryDisposition::Delivered);
    sign(&mut valid);
    let consumed = authority.execute(&valid, &adapter()).expect("consume");
    assert!(consumed.committed);
    assert_eq!(
        consumed.state.as_ref().expect("state").state,
        HarnessApprovalDecisionStateKind::Consumed as i32
    );
    assert_eq!(
        authority
            .inspect_store()
            .expect("inspect")
            .consumption_receipt_count,
        1
    );

    let replay = authority
        .execute(&valid, &adapter())
        .expect("consume replay");
    assert!(replay.replayed);

    let mut stale = consume_command(&decision_ref, DeliveryDisposition::Delivered);
    if let Some(policy_decision_command::Command::ConsumeHarnessApprovalDecision(command)) =
        stale.command.as_mut()
    {
        command.metadata.as_mut().expect("meta").idempotency_key = "consume-stale".to_owned();
    }
    sign(&mut stale);
    let stale = authority.execute(&stale, &adapter()).expect("stale denial");
    assert_eq!(
        stale.error_code,
        PolicyDecisionErrorCode::RevisionConflict as i32
    );

    let mut second = consume_command(&decision_ref, DeliveryDisposition::Delivered);
    if let Some(policy_decision_command::Command::ConsumeHarnessApprovalDecision(command)) =
        second.command.as_mut()
    {
        command.metadata.as_mut().expect("meta").idempotency_key = "consume-second".to_owned();
        command.expected_state_revision = 2;
    }
    sign(&mut second);
    let second = authority
        .execute(&second, &adapter())
        .expect("second denial");
    assert_eq!(
        second.error_code,
        PolicyDecisionErrorCode::AlreadyConsumed as i32
    );

    let mut reissue = issue_command();
    if let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(command)) =
        reissue.command.as_mut()
    {
        command.metadata.as_mut().expect("meta").idempotency_key = "issue-after-consume".to_owned();
    }
    sign(&mut reissue);
    let reissue = authority
        .execute(&reissue, &local_user())
        .expect("reissue denial");
    assert_eq!(
        reissue.error_code,
        PolicyDecisionErrorCode::PolicyDenied as i32
    );
    assert_eq!(
        authority.inspect_store().expect("inspect").decision_count,
        1
    );
}

#[test]
fn revoke_and_authority_clock_expiry_use_revision_cas() {
    let revoke_root = TempRoot::new("revoke");
    let mut authority = open_authority(&revoke_root.database(), NOW, NOW + 300);
    let mut issue = issue_command();
    sign(&mut issue);
    let issued = authority.execute(&issue, &local_user()).expect("issue");
    let decision_ref = issued
        .decision_record
        .as_ref()
        .expect("record")
        .authority_decision_ref
        .clone();
    let mut revoke = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::RevokeHarnessApprovalDecision(
                RevokeHarnessApprovalDecisionCommand {
                    metadata: Some(meta("revoke", "revoke-01")),
                    authority_decision_ref: decision_ref,
                    expected_state_revision: 1,
                    reason_code: "FOUNDER_REVOKED".to_owned(),
                    confirmation_proof_ref: "founder-confirmation:revoke-01".to_owned(),
                },
            ),
        ),
    };
    sign(&mut revoke);
    let revoked = authority
        .execute(
            &revoke,
            &principal(PolicyPrincipalKind::FounderPolicy, "founder-policy:local"),
        )
        .expect("revoke");
    assert_eq!(
        revoked.state.expect("state").state,
        HarnessApprovalDecisionStateKind::Revoked as i32
    );

    let expiry_root = TempRoot::new("expiry");
    let path = expiry_root.database();
    let mut before = open_authority(&path, NOW, NOW + 10);
    let mut issue = issue_command();
    sign(&mut issue);
    let issued = before
        .execute(&issue, &local_user())
        .expect("issue expiring");
    let decision_ref = issued
        .decision_record
        .expect("record")
        .authority_decision_ref;
    drop(before);
    let mut after = open_authority(&path, NOW + 11, NOW + 10);
    let mut expire = PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::ExpireHarnessApprovalDecision(
                ExpireHarnessApprovalDecisionCommand {
                    metadata: Some(meta("expire", "expire-01")),
                    authority_decision_ref: decision_ref,
                    expected_state_revision: 1,
                    policy_evaluation_ref: "policy-evaluation:expired-01".to_owned(),
                },
            ),
        ),
    };
    sign(&mut expire);
    let expired = after
        .execute(
            &expire,
            &principal(
                PolicyPrincipalKind::PolicyAuthority,
                "policy-authority:local",
            ),
        )
        .expect("expire");
    assert_eq!(
        expired.state.expect("state").state,
        HarnessApprovalDecisionStateKind::Expired as i32
    );
}

#[test]
fn committed_decision_survives_real_process_abort_and_replays_same_outbox() {
    let root = TempRoot::new("abort");
    let database = root.database();
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("crash_probe_child")
        .arg("--nocapture")
        .env(CRASH_PROBE, "1")
        .env(CRASH_DB, &database)
        .status()
        .expect("launch crash probe");
    assert!(!status.success(), "child must abort after Authority commit");

    let bytes = fs::read(&database).expect("read encrypted policy store");
    assert!(bytes.len() >= 16);
    assert_ne!(&bytes[..16], b"SQLite format 3\0");

    let mut recovered = open_authority(&database, NOW, NOW + 300);
    let mut command = issue_command();
    sign(&mut command);
    let replay = recovered
        .execute(&command, &local_user())
        .expect("replay after abort");
    assert!(replay.replayed);
    let outbox = recovered.pending_outbox().expect("recover outbox");
    assert_eq!(outbox.len(), 2);
    let envelope = ApprovalDecisionEnvelope::decode(
        outbox
            .iter()
            .find(|item| item.destination_domain == "harness-adapter")
            .expect("adapter outbox")
            .payload
            .as_slice(),
    )
    .expect("recovered envelope");
    assert_eq!(
        Some(&envelope.authority_decision_ref),
        replay
            .decision_record
            .as_ref()
            .map(|record| &record.authority_decision_ref)
    );
    assert_eq!(
        recovered.inspect_store().expect("inspect").decision_count,
        1
    );
}

#[test]
fn crash_probe_child() {
    if std::env::var(CRASH_PROBE).as_deref() != Ok("1") {
        return;
    }
    let database = PathBuf::from(std::env::var_os(CRASH_DB).expect("crash database"));
    let mut authority = open_authority(&database, NOW, NOW + 300);
    let mut command = issue_command();
    sign(&mut command);
    assert!(
        authority
            .execute(&command, &local_user())
            .expect("commit before abort")
            .committed
    );
    std::process::abort();
}

fn open_authority(
    database: &Path,
    now: i64,
    expires_at: i64,
) -> PolicyDecisionAuthority<FixedClock> {
    open_authority_with_resolver(
        database,
        now,
        StaticResolver {
            expires_at,
            receipt_valid: true,
            issue_rejection: None,
            request_override: None,
        },
    )
}

fn open_authority_with_resolver(
    database: &Path,
    now: i64,
    resolver: StaticResolver,
) -> PolicyDecisionAuthority<FixedClock> {
    PolicyDecisionAuthority::open_with_clock(
        PolicyAuthorityConfig {
            database_path: database.to_path_buf(),
            store_epoch: "epoch-g4-07a".to_owned(),
            key: PolicySqlCipherKey::new([107; 32]),
        },
        resolver,
        FixedClock(now),
    )
    .expect("open Policy Decision Authority")
}

fn issue_command() -> PolicyDecisionCommand {
    PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::IssueHarnessApprovalDecision(
                IssueHarnessApprovalDecisionCommand {
                    metadata: Some(meta("issue", "issue-01")),
                    approval_request_id: "approval-request-01".to_owned(),
                    expected_action_digest_sha256: SHA_A.to_owned(),
                    expected_request_observation_id: "observation-approval-01".to_owned(),
                    expected_request_observation_sequence: 17,
                    expected_request_revision: 1,
                    decision: ApprovalDecision::AllowOnce as i32,
                    reason_code: "FOUNDER_ALLOW_ONCE".to_owned(),
                    confirmation_proof_ref: Some("founder-confirmation:approval-01".to_owned()),
                },
            ),
        ),
    }
}

fn consume_command(decision_ref: &str, disposition: DeliveryDisposition) -> PolicyDecisionCommand {
    let mut receipt = ApprovalDecisionReceipt {
        receipt_id: "adapter-receipt-01".to_owned(),
        approval_request_id: "approval-request-01".to_owned(),
        decision: ApprovalDecision::AllowOnce as i32,
        disposition: disposition as i32,
        receipt_digest_sha256: String::new(),
        delivered_at: Some(timestamp(NOW + 1)),
    };
    receipt.receipt_digest_sha256 = canonical_receipt_digest(&receipt);
    PolicyDecisionCommand {
        command: Some(
            policy_decision_command::Command::ConsumeHarnessApprovalDecision(
                ConsumeHarnessApprovalDecisionCommand {
                    metadata: Some(meta("consume", "consume-01")),
                    authority_decision_ref: decision_ref.to_owned(),
                    expected_state_revision: 1,
                    adapter_receipt: Some(receipt),
                },
            ),
        ),
    }
}

fn request_binding() -> HarnessApprovalRequestBinding {
    HarnessApprovalRequestBinding {
        adapter_id: "codex-adapter:local".to_owned(),
        attempt_id: "attempt-01".to_owned(),
        dispatch_id: "dispatch-01".to_owned(),
        fencing_token: 9,
        approval_request_id: "approval-request-01".to_owned(),
        kind: ApprovalKind::Command as i32,
        action_digest_sha256: SHA_A.to_owned(),
        requested_scope_ref: "scope:workspace-write".to_owned(),
        native_routing_ref: "native-route:approval-01".to_owned(),
        request_observation_id: "observation-approval-01".to_owned(),
        request_observation_sequence: 17,
        request_lifecycle: ApprovalRequestLifecycleKind::Open as i32,
        request_revision: 1,
    }
}

fn contract_ref() -> ContractReference {
    ContractReference {
        contract_id: "policy/harness-approval".to_owned(),
        version: "1.0.0".to_owned(),
        sha256: SHA_B.to_owned(),
    }
}

fn meta(operation: &str, key: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("policy-command-{operation}"),
        idempotency_key: key.to_owned(),
        idempotency_scope: "policy-decision-authority:test".to_owned(),
        request_digest_sha256: "0".repeat(64),
        issued_at: Some(timestamp(NOW - 1)),
        correlation_id: "correlation-g4-07a".to_owned(),
        causation_id: None,
    }
}

fn sign(command: &mut PolicyDecisionCommand) {
    let digest = canonical_request_digest(command);
    match command.command.as_mut().expect("command") {
        policy_decision_command::Command::IssueHarnessApprovalDecision(value) => {
            value.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        policy_decision_command::Command::ConsumeHarnessApprovalDecision(value) => {
            value.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        policy_decision_command::Command::RevokeHarnessApprovalDecision(value) => {
            value.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        policy_decision_command::Command::ExpireHarnessApprovalDecision(value) => {
            value.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
    }
}

fn local_user() -> AuthenticatedPolicyPrincipal {
    principal(PolicyPrincipalKind::LocalUser, "local-user:founder")
}

fn adapter() -> AuthenticatedPolicyPrincipal {
    principal(
        PolicyPrincipalKind::HarnessAdapter,
        "harness-adapter:codex-local",
    )
}

fn principal(kind: PolicyPrincipalKind, id: &str) -> AuthenticatedPolicyPrincipal {
    AuthenticatedPolicyPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp { seconds, nanos: 0 }
}
