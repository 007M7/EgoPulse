use egopulse_domain_contracts::v01::egopulse::artifact::v1::{ContentAddress, HashAlgorithm};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    ConfirmationClass, ConsumeFounderVerdictCommand, ExpireFounderVerdictCommand, FounderVerdict,
    FounderVerdictDecision, FounderVerdictStateKind, IssueFounderVerdictCommand,
    RevokeFounderVerdictCommand, RiskAcceptance, RiskCategory, VerdictCommand, VerdictErrorCode,
    VerdictScope, verdict_command,
};
use egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationConclusion;
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictAuthorityFailure, VerdictClock,
    VerdictPrincipalKind, VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
    canonical_request_digest,
};
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy)]
struct FixedClock;

impl VerdictClock for FixedClock {
    fn now(&self) -> Result<Timestamp, VerdictAuthorityFailure> {
        Ok(Timestamp {
            seconds: 1_782_000_000,
            nanos: 0,
        })
    }
}

#[derive(Clone)]
struct StaticResolver {
    context: ResolvedVerdictContext,
    task_commit_valid: bool,
}

impl VerdictReferenceResolver for StaticResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        if principal.kind != VerdictPrincipalKind::FounderAuthority {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        Ok((
            self.context.clone(),
            FounderAuthorization {
                authenticated_founder_principal_id: "founder:local".to_owned(),
                authority_ref: "founder-authority:local".to_owned(),
                confirmation_class: ConfirmationClass::try_from(
                    command.required_confirmation_class,
                )
                .unwrap_or(ConfirmationClass::Unspecified),
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: Timestamp {
                    seconds: 1_781_999_990,
                    nanos: 0,
                },
                valid_until: Timestamp {
                    seconds: 1_782_000_300,
                    nanos: 0,
                },
                authority_policy_ref: contract_ref("founder-policy", SHA_B),
                evidence_refs: vec!["confirmation-artifact-01".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        _command: &ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        self.task_commit_valid
            .then_some(())
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    }

    fn validate_revoke(
        &self,
        _command: &RevokeFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Ok(vec!["founder-revoke-proof:01".to_owned()])
    }

    fn validate_expiry(
        &self,
        _command: &ExpireFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Ok(vec!["policy-expiry-proof:01".to_owned()])
    }

    fn validate_supersede(
        &self,
        _command: &IssueFounderVerdictCommand,
        _superseded_verdict: &FounderVerdict,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Ok(vec!["founder-supersede-proof:01".to_owned()])
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-07-{name}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated test directory");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("egopulse-g4-07-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn passed_accept_is_immutable_duplicate_safe_and_harness_cannot_issue() {
    let (root, mut authority, founder, _) = authority_fixture(
        "passed",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let mut command = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );

    let denied = authority
        .execute(
            &command,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::Harness,
                principal_id: "harness:01".to_owned(),
                authenticated: true,
            },
        )
        .expect("denial result");
    assert_eq!(denied.error_code, VerdictErrorCode::PermissionDenied as i32);
    assert_eq!(authority.inspect_store().expect("inspect").verdict_count, 0);

    sign(&mut command);
    let first = authority
        .execute(&command, &founder)
        .expect("issue verdict");
    assert!(first.committed);
    assert_eq!(
        first.state.as_ref().expect("state").state,
        FounderVerdictStateKind::Issued as i32
    );
    let payload = first
        .verdict
        .as_ref()
        .expect("verdict")
        .canonical_payload
        .as_ref()
        .expect("payload");
    assert_eq!(payload.algorithm, HashAlgorithm::Sha256 as i32);
    assert_eq!(payload.digest.len(), 64);

    let replay = authority
        .execute(&command, &founder)
        .expect("replay verdict");
    assert!(replay.replayed);
    assert_eq!(
        replay.verdict.as_ref().map(|v| &v.founder_verdict_id),
        first.verdict.as_ref().map(|v| &v.founder_verdict_id)
    );
    let inspection = authority.inspect_store().expect("inspect");
    assert_eq!(inspection.verdict_count, 1);
    assert_eq!(inspection.event_count, 1);
    assert_eq!(inspection.outbox_count, 2);
    drop(root);
}

#[test]
fn nonpassed_accept_requires_elevated_exact_risk_coverage_and_redlines_fail_closed() {
    let (_root, mut authority, founder, _) = authority_fixture(
        "risk",
        VerificationConclusion::Partial,
        vec!["disc-01"],
        vec!["unverified-01"],
        vec![],
        true,
    );
    let mut missing = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Partial,
        vec![],
    );
    set_confirmation(&mut missing, ConfirmationClass::ElevatedRiskAcceptance);
    sign(&mut missing);
    let rejected = authority
        .execute(&missing, &founder)
        .expect("missing risk rejected");
    assert_eq!(
        rejected.error_code,
        VerdictErrorCode::RiskAcceptanceRequired as i32
    );

    let risk = RiskAcceptance {
        risk_acceptance_id: "risk-01".to_owned(),
        category: RiskCategory::QualityResidual as i32,
        discrepancy_ids: vec!["disc-01".to_owned()],
        unverified_item_ids: vec!["unverified-01".to_owned()],
        rationale_artifact_id: "artifact-rationale-01".to_owned(),
        compensating_control_artifact_ids: vec!["artifact-control-01".to_owned()],
        review_trigger_code: None,
    };
    let mut valid = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Partial,
        vec![risk],
    );
    set_confirmation(&mut valid, ConfirmationClass::ElevatedRiskAcceptance);
    sign(&mut valid);
    assert!(
        authority
            .execute(&valid, &founder)
            .expect("risk accept")
            .committed
    );

    let (_red_root, mut redline, red_founder, _) = authority_fixture(
        "redline",
        VerificationConclusion::Failed,
        vec!["disc-01"],
        vec![],
        vec!["secret-leak"],
        true,
    );
    let risk = RiskAcceptance {
        risk_acceptance_id: "risk-02".to_owned(),
        category: RiskCategory::OperationalResidual as i32,
        discrepancy_ids: vec!["disc-01".to_owned()],
        unverified_item_ids: vec![],
        rationale_artifact_id: "artifact-rationale-02".to_owned(),
        compensating_control_artifact_ids: vec!["artifact-control-02".to_owned()],
        review_trigger_code: None,
    };
    let mut command = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Failed,
        vec![risk],
    );
    set_confirmation(&mut command, ConfirmationClass::ElevatedRiskAcceptance);
    sign(&mut command);
    let rejected = redline
        .execute(&command, &red_founder)
        .expect("redline rejected");
    assert_eq!(
        rejected.error_code,
        VerdictErrorCode::NonOverridableGate as i32
    );
}

#[test]
fn verdict_projection_feed_carries_verdict_and_state_and_acks_by_digest() {
    let (_root, mut authority, founder, _) = authority_fixture(
        "projection-feed",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let mut command = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );
    sign(&mut command);
    let committed = authority
        .execute(&command, &founder)
        .expect("issue verdict");
    let pending = authority
        .drain_projection_outbox()
        .expect("drain Verdict projection outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].result, committed);
    assert!(pending[0].result.verdict.is_some());
    assert!(pending[0].result.state.is_some());
    assert!(
        !authority
            .acknowledge_projection(&pending[0].message_id, &"0".repeat(64))
            .expect("reject mismatched Verdict ACK")
    );
    assert!(
        authority
            .acknowledge_projection(&pending[0].message_id, &pending[0].payload_digest_sha256)
            .expect("ack Verdict projection")
    );
    assert!(
        authority
            .drain_projection_outbox()
            .expect("Verdict projection after ACK")
            .is_empty()
    );
    let baselines = authority
        .projection_baselines()
        .expect("Verdict projection baseline");
    assert_eq!(baselines.len(), 1);
    assert_eq!(baselines[0].result.verdict, committed.verdict);
    assert_eq!(baselines[0].result.state, committed.state);
}

#[test]
fn task_commit_consumes_once_and_invalid_receipt_cannot_mutate_state() {
    let (_root, mut authority, founder, task) = authority_fixture(
        "consume",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let mut issue = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );
    sign(&mut issue);
    let issued = authority.execute(&issue, &founder).expect("issue");
    let verdict_id = issued
        .verdict
        .as_ref()
        .expect("verdict")
        .founder_verdict_id
        .clone();

    let mut consume = consume_command(&verdict_id);
    sign(&mut consume);
    let consumed = authority.execute(&consume, &task).expect("consume");
    assert!(consumed.committed);
    assert_eq!(
        consumed.state.as_ref().expect("state").state,
        FounderVerdictStateKind::Consumed as i32
    );
    let replay = authority.execute(&consume, &task).expect("consume replay");
    assert!(replay.replayed);
    let inspection = authority.inspect_store().expect("inspect");
    assert_eq!(inspection.consumption_receipt_count, 1);
    assert_eq!(inspection.event_count, 2);
    let mut revoke_consumed = revoke_command(&verdict_id, 2);
    sign(&mut revoke_consumed);
    assert_eq!(
        authority
            .execute(&revoke_consumed, &founder)
            .expect("consumed verdict cannot be revoked")
            .error_code,
        VerdictErrorCode::AlreadyConsumed as i32
    );
    assert_eq!(authority.inspect_store().expect("inspect"), inspection);

    let (_bad_root, mut invalid, bad_founder, bad_task) = authority_fixture(
        "bad-receipt",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        false,
    );
    let mut issue = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );
    sign(&mut issue);
    let id = invalid
        .execute(&issue, &bad_founder)
        .expect("issue")
        .verdict
        .expect("verdict")
        .founder_verdict_id;
    let mut consume = consume_command(&id);
    sign(&mut consume);
    let rejected = invalid
        .execute(&consume, &bad_task)
        .expect("invalid receipt");
    assert_eq!(
        rejected.error_code,
        VerdictErrorCode::TaskCommitReceiptInvalid as i32
    );
    assert_eq!(
        invalid.get(&id).expect("get").expect("stored").1.state,
        FounderVerdictStateKind::Issued as i32
    );
}

#[test]
fn revoke_expire_and_supersede_are_cas_guarded_before_consumption() {
    let (_root, mut revoked_authority, founder, task) = authority_fixture(
        "revoke",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let revoked_id = issue_accept(&mut revoked_authority, &founder);
    let mut revoke = revoke_command(&revoked_id, 1);
    sign(&mut revoke);
    let revoked = revoked_authority
        .execute(&revoke, &founder)
        .expect("revoke issued verdict");
    assert!(revoked.committed);
    assert_eq!(
        revoked.state.as_ref().expect("state").state,
        FounderVerdictStateKind::Revoked as i32
    );
    assert!(
        revoked_authority
            .execute(&revoke, &founder)
            .expect("revoke replay")
            .replayed
    );
    let mut consume = consume_command(&revoked_id);
    if let Some(verdict_command::Command::ConsumeFounderVerdict(command)) = consume.command.as_mut()
    {
        command.expected_state_revision = 2;
    }
    sign(&mut consume);
    assert_eq!(
        revoked_authority
            .execute(&consume, &task)
            .expect("revoked verdict denied")
            .error_code,
        VerdictErrorCode::Revoked as i32
    );

    let (_root, mut expired_authority, founder, _) = authority_fixture(
        "expire",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let expired_id = issue_accept(&mut expired_authority, &founder);
    let policy = AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::PolicyAuthority,
        principal_id: "policy-authority:local".to_owned(),
        authenticated: true,
    };
    let mut expire = expire_command(&expired_id, 1);
    sign(&mut expire);
    let expired = expired_authority
        .execute(&expire, &policy)
        .expect("expire verdict");
    assert_eq!(
        expired.state.as_ref().expect("state").state,
        FounderVerdictStateKind::Expired as i32
    );

    let (_root, mut supersede_authority, founder, _) = authority_fixture(
        "supersede",
        VerificationConclusion::Passed,
        vec![],
        vec![],
        vec![],
        true,
    );
    let old_id = issue_accept(&mut supersede_authority, &founder);
    let mut duplicate = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );
    sign(&mut duplicate);
    let active = supersede_authority
        .execute(&duplicate, &founder)
        .expect("duplicate active denied");
    assert_eq!(active.error_code, VerdictErrorCode::AlreadyActive as i32);

    let mut replacement = issue_command(
        FounderVerdictDecision::Reject,
        VerificationConclusion::Passed,
        vec![],
    );
    if let Some(verdict_command::Command::IssueFounderVerdict(issue)) = replacement.command.as_mut()
    {
        issue.supersedes_founder_verdict_id = Some(old_id.clone());
    }
    sign(&mut replacement);
    let replaced = supersede_authority
        .execute(&replacement, &founder)
        .expect("supersede verdict");
    assert!(replaced.committed);
    let new_id = replaced
        .verdict
        .as_ref()
        .expect("replacement verdict")
        .founder_verdict_id
        .clone();
    let old_state = supersede_authority
        .get(&old_id)
        .expect("get old")
        .expect("old verdict")
        .1;
    assert_eq!(old_state.state, FounderVerdictStateKind::Superseded as i32);
    assert_eq!(
        old_state.superseded_by_verdict_id.as_deref(),
        Some(new_id.as_str())
    );
    assert_eq!(
        supersede_authority
            .get(&new_id)
            .expect("get new")
            .expect("new verdict")
            .1
            .state,
        FounderVerdictStateKind::Issued as i32
    );
    let inspection = supersede_authority.inspect_store().expect("inspect");
    assert_eq!(inspection.verdict_count, 2);
    assert_eq!(inspection.event_count, 3);
    assert_eq!(inspection.outbox_count, 5);
}

fn authority_fixture(
    name: &str,
    conclusion: VerificationConclusion,
    discrepancies: Vec<&str>,
    unverified: Vec<&str>,
    redlines: Vec<&str>,
    task_commit_valid: bool,
) -> (
    TempRoot,
    FounderVerdictAuthority<FixedClock>,
    AuthenticatedVerdictPrincipal,
    AuthenticatedVerdictPrincipal,
) {
    let root = TempRoot::new(name);
    let context = ResolvedVerdictContext {
        scope: scope(),
        verification_conclusion: conclusion,
        open_discrepancy_ids: discrepancies.into_iter().map(str::to_owned).collect(),
        open_unverified_item_ids: unverified.into_iter().map(str::to_owned).collect(),
        non_overridable_gate_ids: redlines.into_iter().map(str::to_owned).collect(),
    };
    let authority = FounderVerdictAuthority::open_with_clock(
        VerdictAuthorityConfig {
            database_path: root.path().join("verdict.db"),
            store_epoch: format!("epoch-{name}"),
            key: VerdictSqlCipherKey::new([71; 32]),
        },
        StaticResolver {
            context,
            task_commit_valid,
        },
        FixedClock,
    )
    .expect("open authority");
    let founder = AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::FounderAuthority,
        principal_id: "founder-authority:local".to_owned(),
        authenticated: true,
    };
    let task = AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::TaskAuthority,
        principal_id: "task-authority:local".to_owned(),
        authenticated: true,
    };
    (root, authority, founder, task)
}

fn issue_command(
    decision: FounderVerdictDecision,
    conclusion: VerificationConclusion,
    risks: Vec<RiskAcceptance>,
) -> VerdictCommand {
    VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(meta("issue")),
                scope: Some(scope()),
                decision: decision as i32,
                observed_verification_conclusion: conclusion as i32,
                risk_acceptances: risks,
                rework_directive: None,
                reason_code: if decision == FounderVerdictDecision::Reject {
                    "REJECTED".to_owned()
                } else {
                    String::new()
                },
                rationale_artifact_id: None,
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "founder-confirmation:01".to_owned(),
                expires_at: Some(Timestamp {
                    seconds: 1_782_003_600,
                    nanos: 0,
                }),
                supersedes_founder_verdict_id: None,
            },
        )),
    }
}

fn consume_command(id: &str) -> VerdictCommand {
    VerdictCommand {
        command: Some(verdict_command::Command::ConsumeFounderVerdict(
            ConsumeFounderVerdictCommand {
                metadata: Some(meta("consume")),
                founder_verdict_id: id.to_owned(),
                expected_state_revision: 1,
                task_event_id: "task-event-completed-01".to_owned(),
                consumed_task_revision: 5,
                resulting_task_revision: 6,
                resulting_task_status: "TASK_STATUS_COMPLETED".to_owned(),
                task_commit_receipt_ref: "task-commit:task-event-completed-01".to_owned(),
            },
        )),
    }
}

fn revoke_command(id: &str, revision: u64) -> VerdictCommand {
    VerdictCommand {
        command: Some(verdict_command::Command::RevokeFounderVerdict(
            RevokeFounderVerdictCommand {
                metadata: Some(meta("revoke")),
                founder_verdict_id: id.to_owned(),
                expected_state_revision: revision,
                reason_code: "FOUNDER_WITHDREW_DECISION".to_owned(),
                confirmation_proof_ref: "founder-revoke-proof:01".to_owned(),
            },
        )),
    }
}

fn expire_command(id: &str, revision: u64) -> VerdictCommand {
    VerdictCommand {
        command: Some(verdict_command::Command::ExpireFounderVerdict(
            ExpireFounderVerdictCommand {
                metadata: Some(meta("expire")),
                founder_verdict_id: id.to_owned(),
                expected_state_revision: revision,
                policy_decision_ref: "policy-expiry-proof:01".to_owned(),
            },
        )),
    }
}

fn issue_accept(
    authority: &mut FounderVerdictAuthority<FixedClock>,
    founder: &AuthenticatedVerdictPrincipal,
) -> String {
    let mut issue = issue_command(
        FounderVerdictDecision::Accept,
        VerificationConclusion::Passed,
        vec![],
    );
    sign(&mut issue);
    authority
        .execute(&issue, founder)
        .expect("issue")
        .verdict
        .expect("verdict")
        .founder_verdict_id
}

fn sign(command: &mut VerdictCommand) {
    let digest = canonical_request_digest(command);
    match command.command.as_mut().expect("command") {
        verdict_command::Command::IssueFounderVerdict(v) => {
            v.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        verdict_command::Command::ConsumeFounderVerdict(v) => {
            v.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        verdict_command::Command::RevokeFounderVerdict(v) => {
            v.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
        verdict_command::Command::ExpireFounderVerdict(v) => {
            v.metadata.as_mut().expect("meta").request_digest_sha256 = digest
        }
    }
}

fn set_confirmation(command: &mut VerdictCommand, class: ConfirmationClass) {
    let Some(verdict_command::Command::IssueFounderVerdict(issue)) = command.command.as_mut()
    else {
        panic!("issue command required");
    };
    issue.required_confirmation_class = class as i32;
}

fn scope() -> VerdictScope {
    VerdictScope {
        task_id: "task-01".to_owned(),
        task_revision: 5,
        work_revision: 2,
        artifact_set_id: "artifact-set-01".to_owned(),
        artifact_set_manifest: Some(address(SHA_A)),
        verification_artifact_id: "verification-artifact-01".to_owned(),
        verification_payload: Some(address(SHA_B)),
        acceptance_contract_ref: Some(contract_ref("acceptance", SHA_A)),
    }
}

fn address(digest: &str) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: digest.to_owned(),
        byte_length: 128,
    }
}
fn contract_ref(id: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: digest.to_owned(),
    }
}
fn meta(prefix: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command-{prefix}-{}", Uuid::now_v7()),
        idempotency_key: format!("idem-{prefix}-{}", Uuid::now_v7()),
        idempotency_scope: "g4-07".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: 1_781_999_999,
            nanos: 0,
        }),
        correlation_id: format!("correlation-{prefix}"),
        causation_id: None,
    }
}
