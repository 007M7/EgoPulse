//! C-06 FounderVerdict single-writer boundary.
//!
//! Founder confirmation and cross-Authority references are resolved by trusted
//! composition guards. Request-body actor claims never grant authority.

mod store;

use egopulse_domain_contracts::v01::egopulse::artifact::v1::{ContentAddress, HashAlgorithm};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    ConfirmationClass, ConsumeFounderVerdictCommand, ExpireFounderVerdictCommand,
    FounderAuthorityProof, FounderVerdict, FounderVerdictDecision, FounderVerdictState,
    FounderVerdictStateKind, IssueFounderVerdictCommand, RevokeFounderVerdictCommand,
    RiskAcceptance, RiskCategory, VerdictCommand, VerdictCommandResult, VerdictConsumptionReceipt,
    VerdictErrorCode, VerdictEvent, VerdictEventKind, VerdictScope, verdict_command,
};
use egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationConclusion;
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use store::VerdictStoreInspection;
use store::{ConsumeCommit, IssueCommit, StateCommit, StoreError, SupersedeCommit, VerdictStore};

const ISSUE_OPERATION: &str = "issue_founder_verdict";
const CONSUME_OPERATION: &str = "consume_founder_verdict";
const REVOKE_OPERATION: &str = "revoke_founder_verdict";
const EXPIRE_OPERATION: &str = "expire_founder_verdict";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictPrincipalKind {
    FounderAuthority,
    TaskAuthority,
    Harness,
    Checker,
    Model,
    RecoveryCoordinator,
    PolicyAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedVerdictPrincipal {
    pub kind: VerdictPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

#[derive(Clone, Debug)]
pub struct ResolvedVerdictContext {
    pub scope: VerdictScope,
    pub verification_conclusion: VerificationConclusion,
    pub open_discrepancy_ids: Vec<String>,
    pub open_unverified_item_ids: Vec<String>,
    pub non_overridable_gate_ids: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct FounderAuthorization {
    pub authenticated_founder_principal_id: String,
    pub authority_ref: String,
    pub confirmation_class: ConfirmationClass,
    pub confirmation_proof_ref: String,
    pub verified_at: Timestamp,
    pub valid_until: Timestamp,
    pub authority_policy_ref: ContractReference,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictReferenceRejection {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    ScopeStale,
    VerificationMismatch,
    ConfirmationRequired,
    TaskCommitReceiptInvalid,
    IntegrityFailure,
}

pub trait VerdictReferenceResolver: Send + Sync + 'static {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection>;

    fn validate_task_commit(
        &self,
        command: &ConsumeFounderVerdictCommand,
    ) -> Result<(), VerdictReferenceRejection>;

    fn validate_revoke(
        &self,
        _command: &RevokeFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_expiry(
        &self,
        _command: &ExpireFounderVerdictCommand,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }

    fn validate_supersede(
        &self,
        _command: &IssueFounderVerdictCommand,
        _superseded_verdict: &FounderVerdict,
        _principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::PermissionDenied)
    }
}

pub trait VerdictClock: Send + Sync + 'static {
    fn now(&self) -> Result<Timestamp, VerdictAuthorityFailure>;
}

pub struct SystemVerdictClock;

impl VerdictClock for SystemVerdictClock {
    fn now(&self) -> Result<Timestamp, VerdictAuthorityFailure> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerdictAuthorityFailure::Clock)?;
        Ok(Timestamp {
            seconds: duration.as_secs() as i64,
            nanos: duration.subsec_nanos() as i32,
        })
    }
}

pub struct VerdictSqlCipherKey(Zeroizing<[u8; 32]>);

impl VerdictSqlCipherKey {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct VerdictAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: VerdictSqlCipherKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerdictProjectionMessage {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub result: VerdictCommandResult,
}

#[derive(Debug, Error)]
pub enum VerdictAuthorityFailure {
    #[error("founder verdict storage is unavailable")]
    Storage,
    #[error("stored founder verdict protobuf could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("founder verdict clock is before Unix epoch")]
    Clock,
}

impl From<StoreError> for VerdictAuthorityFailure {
    fn from(_: StoreError) -> Self {
        Self::Storage
    }
}

pub struct FounderVerdictAuthority<C = SystemVerdictClock> {
    store: VerdictStore,
    resolver: Box<dyn VerdictReferenceResolver>,
    clock: C,
}

struct PreparedSupersedeCommit {
    verdict_id: String,
    expected_revision: u64,
    state: Vec<u8>,
    event_id: String,
    command_id: String,
    event: Vec<u8>,
    outbox_id: String,
    outbox_digest: String,
    projection_outbox_id: String,
    projection_payload_digest: String,
    projection_payload: Vec<u8>,
}

impl PreparedSupersedeCommit {
    fn as_store_commit(&self) -> SupersedeCommit<'_> {
        SupersedeCommit {
            verdict_id: &self.verdict_id,
            expected_revision: self.expected_revision,
            state: &self.state,
            state_kind: FounderVerdictStateKind::Superseded as i32,
            event_id: &self.event_id,
            command_id: &self.command_id,
            event: &self.event,
            outbox_id: &self.outbox_id,
            outbox_digest: &self.outbox_digest,
            projection_outbox_id: &self.projection_outbox_id,
            projection_payload_digest: &self.projection_payload_digest,
            projection_payload: &self.projection_payload,
        }
    }
}

impl FounderVerdictAuthority<SystemVerdictClock> {
    pub fn open(
        config: VerdictAuthorityConfig,
        resolver: impl VerdictReferenceResolver,
    ) -> Result<Self, VerdictAuthorityFailure> {
        Self::open_with_clock(config, resolver, SystemVerdictClock)
    }
}

impl<C: VerdictClock> FounderVerdictAuthority<C> {
    pub fn open_with_clock(
        config: VerdictAuthorityConfig,
        resolver: impl VerdictReferenceResolver,
        clock: C,
    ) -> Result<Self, VerdictAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(VerdictAuthorityFailure::Storage);
        }
        Ok(Self {
            store: VerdictStore::open(
                &config.database_path,
                config.key.expose(),
                &config.store_epoch,
            )?,
            resolver: Box::new(resolver),
            clock,
        })
    }

    pub fn execute(
        &mut self,
        command: &VerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "VERDICT_COMMAND_MISSING",
            ));
        };
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                VerdictErrorCode::Unauthenticated,
                "PRINCIPAL_NOT_AUTHENTICATED",
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                VerdictErrorCode::PermissionDenied,
                "PRINCIPAL_OPERATION_NOT_ALLOWED",
            ));
        }
        let Some(meta) = command_metadata(command) else {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "COMMAND_METADATA_MISSING",
            ));
        };
        if !metadata_complete(meta) {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "COMMAND_METADATA_INCOMPLETE",
            ));
        }
        let digest = canonical_request_digest(command);
        if digest != meta.request_digest_sha256 {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "REQUEST_DIGEST_MISMATCH",
            ));
        }
        if let Some(record) = self.store.idempotency_record(
            &principal.principal_id,
            operation,
            &meta.idempotency_scope,
            &meta.idempotency_key,
        )? {
            if record.request_digest_sha256 != digest {
                return Ok(error_result(
                    VerdictErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED",
                ));
            }
            let mut result = VerdictCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }
        match command.command.as_ref() {
            Some(verdict_command::Command::IssueFounderVerdict(issue)) => {
                self.issue(issue, principal, &digest)
            }
            Some(verdict_command::Command::ConsumeFounderVerdict(consume)) => {
                self.consume(consume, principal, &digest)
            }
            Some(verdict_command::Command::RevokeFounderVerdict(revoke)) => {
                self.revoke(revoke, principal, &digest)
            }
            Some(verdict_command::Command::ExpireFounderVerdict(expire)) => {
                self.expire(expire, principal, &digest)
            }
            None => Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "VERDICT_COMMAND_MISSING",
            )),
        }
    }

    pub fn get(
        &self,
        id: &str,
    ) -> Result<Option<(FounderVerdict, FounderVerdictState)>, VerdictAuthorityFailure> {
        self.store
            .stored_verdict(id)?
            .map(|stored| {
                Ok((
                    FounderVerdict::decode(stored.verdict.as_slice())?,
                    FounderVerdictState::decode(stored.state.as_slice())?,
                ))
            })
            .transpose()
    }

    pub fn inspect_store(&self) -> Result<VerdictStoreInspection, VerdictAuthorityFailure> {
        self.store.inspect().map_err(VerdictAuthorityFailure::from)
    }

    pub fn drain_projection_outbox(
        &self,
    ) -> Result<Vec<VerdictProjectionMessage>, VerdictAuthorityFailure> {
        self.store
            .pending_projection_outbox()?
            .into_iter()
            .map(|pending| {
                let actual_digest = hex::encode(Sha256::digest(&pending.payload));
                let result = VerdictCommandResult::decode(pending.payload.as_slice())?;
                let event = result
                    .event
                    .as_ref()
                    .ok_or(VerdictAuthorityFailure::Storage)?;
                let state = result
                    .state
                    .as_ref()
                    .ok_or(VerdictAuthorityFailure::Storage)?;
                if actual_digest != pending.payload_digest_sha256
                    || !result.committed
                    || result.verdict.is_none()
                    || event.event_id != pending.source_event_id
                    || event.resulting_state_revision != pending.source_revision
                    || state.revision != pending.source_revision
                    || state.founder_verdict_id != event.founder_verdict_id
                {
                    return Err(VerdictAuthorityFailure::Storage);
                }
                Ok(VerdictProjectionMessage {
                    message_id: pending.message_id,
                    source_event_id: pending.source_event_id,
                    source_revision: pending.source_revision,
                    payload_digest_sha256: pending.payload_digest_sha256,
                    result,
                })
            })
            .collect()
    }

    pub fn projection_baselines(
        &self,
    ) -> Result<Vec<VerdictProjectionMessage>, VerdictAuthorityFailure> {
        self.store
            .projection_baselines()?
            .into_iter()
            .map(|baseline| {
                let verdict = FounderVerdict::decode(baseline.verdict.as_slice())?;
                let state = FounderVerdictState::decode(baseline.state.as_slice())?;
                let event = VerdictEvent::decode(baseline.event.as_slice())?;
                if verdict.founder_verdict_id != state.founder_verdict_id
                    || state.founder_verdict_id != event.founder_verdict_id
                    || state.revision != baseline.source_revision
                    || event.resulting_state_revision != baseline.source_revision
                    || event.event_id != baseline.source_event_id
                {
                    return Err(VerdictAuthorityFailure::Storage);
                }
                let result = VerdictCommandResult {
                    committed: true,
                    replayed: false,
                    verdict: Some(verdict),
                    state: Some(state),
                    consumption_receipt: None,
                    event: Some(event),
                    error_code: VerdictErrorCode::Unspecified as i32,
                    safe_error_fingerprint: None,
                };
                let payload = result.encode_to_vec();
                Ok(VerdictProjectionMessage {
                    message_id: format!("bootstrap:{}", baseline.source_event_id),
                    source_event_id: baseline.source_event_id,
                    source_revision: baseline.source_revision,
                    payload_digest_sha256: hex::encode(Sha256::digest(payload)),
                    result,
                })
            })
            .collect()
    }

    pub fn acknowledge_projection(
        &mut self,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, VerdictAuthorityFailure> {
        self.store
            .acknowledge_projection_outbox(message_id, expected_payload_digest_sha256)
            .map_err(VerdictAuthorityFailure::from)
    }

    fn issue(
        &mut self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        request_digest: &str,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        let now = self.clock.now()?;
        let (resolved, authorization) = match self.resolver.resolve_issue(command, principal) {
            Ok(value) => value,
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        if !scope_complete(command.scope.as_ref()) || command.scope != Some(resolved.scope.clone())
        {
            return Ok(error_result(
                VerdictErrorCode::ScopeStale,
                "VERDICT_SCOPE_STALE",
            ));
        }
        let observed = VerificationConclusion::try_from(command.observed_verification_conclusion)
            .unwrap_or(VerificationConclusion::Unspecified);
        if observed == VerificationConclusion::Unspecified
            || observed != resolved.verification_conclusion
        {
            return Ok(error_result(
                VerdictErrorCode::VerificationMismatch,
                "VERIFICATION_CONCLUSION_MISMATCH",
            ));
        }
        if authorization
            .authenticated_founder_principal_id
            .trim()
            .is_empty()
            || authorization.authority_ref.trim().is_empty()
            || authorization.confirmation_proof_ref != command.confirmation_proof_ref
            || !contract_complete(&authorization.authority_policy_ref)
            || authorization.evidence_refs.is_empty()
            || timestamp_after(&now, &authorization.valid_until)
        {
            return Ok(error_result(
                VerdictErrorCode::ConfirmationRequired,
                "TRUSTED_CONFIRMATION_INVALID",
            ));
        }
        let decision = FounderVerdictDecision::try_from(command.decision)
            .unwrap_or(FounderVerdictDecision::Unspecified);
        let required_confirmation = if decision == FounderVerdictDecision::Accept
            && observed != VerificationConclusion::Passed
        {
            ConfirmationClass::ElevatedRiskAcceptance
        } else {
            ConfirmationClass::Explicit
        };
        if decision == FounderVerdictDecision::Unspecified
            || ConfirmationClass::try_from(command.required_confirmation_class)
                .unwrap_or(ConfirmationClass::Unspecified)
                != required_confirmation
            || authorization.confirmation_class != required_confirmation
        {
            return Ok(error_result(
                VerdictErrorCode::ConfirmationRequired,
                "CONFIRMATION_CLASS_INSUFFICIENT",
            ));
        }
        if timestamp_after_or_equal(&now, command.expires_at.as_ref()) {
            return Ok(error_result(
                VerdictErrorCode::Expired,
                "VERDICT_EXPIRY_NOT_FUTURE",
            ));
        }
        if let Some(error) = validate_decision(command, &resolved, decision, observed) {
            return Ok(error);
        }

        let superseded = if let Some(superseded_id) = command.supersedes_founder_verdict_id.as_ref()
        {
            if superseded_id.trim().is_empty() {
                return Ok(error_result(
                    VerdictErrorCode::InvalidArgument,
                    "SUPERSEDED_VERDICT_ID_EMPTY",
                ));
            }
            let Some((old_verdict, old_state)) = self.get(superseded_id)? else {
                return Ok(error_result(
                    VerdictErrorCode::NotFound,
                    "SUPERSEDED_VERDICT_NOT_FOUND",
                ));
            };
            if let Some(error) = validate_issued_revision(&old_state, old_state.revision) {
                return Ok(error);
            }
            if old_verdict.scope != command.scope {
                return Ok(error_result(
                    VerdictErrorCode::ScopeStale,
                    "SUPERSEDED_VERDICT_SCOPE_MISMATCH",
                ));
            }
            if timestamp_after_or_equal(&now, old_verdict.expires_at.as_ref()) {
                return Ok(error_result(
                    VerdictErrorCode::Expired,
                    "SUPERSEDED_VERDICT_EXPIRED",
                ));
            }
            let mut evidence =
                match self
                    .resolver
                    .validate_supersede(command, &old_verdict, principal)
                {
                    Ok(evidence) => evidence,
                    Err(rejection) => return Ok(reference_error(rejection)),
                };
            if evidence.is_empty() {
                return Ok(error_result(
                    VerdictErrorCode::ConfirmationRequired,
                    "TRUSTED_SUPERSEDE_EVIDENCE_MISSING",
                ));
            }
            evidence.extend(authorization.evidence_refs.iter().cloned());
            normalize_evidence(&mut evidence);
            Some((old_verdict, old_state, evidence))
        } else {
            None
        };

        let meta = command.metadata.as_ref().expect("metadata checked");
        let verdict_id = format!("founder-verdict-{}", Uuid::now_v7());
        let event_id = format!("verdict-event-{}", Uuid::now_v7());
        let scope = command.scope.clone().expect("scope checked");
        let mut verdict = FounderVerdict {
            founder_verdict_id: verdict_id.clone(),
            version: 1,
            decision: command.decision,
            scope: Some(scope.clone()),
            observed_verification_conclusion: command.observed_verification_conclusion,
            authority_proof: Some(FounderAuthorityProof {
                authenticated_founder_principal_id: authorization
                    .authenticated_founder_principal_id,
                authority_ref: authorization.authority_ref,
                confirmation_class: authorization.confirmation_class as i32,
                confirmation_proof_ref: authorization.confirmation_proof_ref,
                verified_at: Some(authorization.verified_at),
                valid_until: Some(authorization.valid_until),
                authority_policy_ref: Some(authorization.authority_policy_ref),
            }),
            risk_acceptances: command.risk_acceptances.clone(),
            rework_directive: command.rework_directive.clone(),
            reason_code: command.reason_code.clone(),
            rationale_artifact_id: command.rationale_artifact_id.clone(),
            valid_from: Some(now),
            expires_at: command.expires_at,
            issued_at: Some(now),
            canonical_payload: None,
            supersedes_founder_verdict_id: command.supersedes_founder_verdict_id.clone(),
        };
        let payload_bytes = verdict.encode_to_vec();
        let payload_digest = hex::encode(Sha256::digest(&payload_bytes));
        verdict.canonical_payload = Some(ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: payload_digest.clone(),
            byte_length: payload_bytes.len() as u64,
        });
        let state = FounderVerdictState {
            founder_verdict_id: verdict_id.clone(),
            revision: 1,
            state: FounderVerdictStateKind::Issued as i32,
            consumption_receipt_id: None,
            superseded_by_verdict_id: None,
            terminal_reason_code: None,
            updated_at: Some(now),
        };
        let event = VerdictEvent {
            event_id: event_id.clone(),
            kind: VerdictEventKind::Issued as i32,
            founder_verdict_id: verdict_id.clone(),
            resulting_state_revision: 1,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            evidence_artifact_ids: authorization.evidence_refs,
            committed_at: Some(now),
        };
        let result = VerdictCommandResult {
            committed: true,
            replayed: false,
            verdict: Some(verdict.clone()),
            state: Some(state.clone()),
            consumption_receipt: None,
            event: Some(event.clone()),
            error_code: VerdictErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let event_bytes = event.encode_to_vec();
        let scope_digest = hex::encode(Sha256::digest(scope.encode_to_vec()));
        let outbox_digest = hex::encode(Sha256::digest(&event_bytes));
        let prepared_supersede = superseded.map(|(old_verdict, old_state, evidence)| {
            let event_id = format!("verdict-event-{}", Uuid::now_v7());
            let command_id = format!("{}:supersede", meta.command_id);
            let state = FounderVerdictState {
                founder_verdict_id: old_state.founder_verdict_id.clone(),
                revision: old_state.revision + 1,
                state: FounderVerdictStateKind::Superseded as i32,
                consumption_receipt_id: None,
                superseded_by_verdict_id: Some(verdict_id.clone()),
                terminal_reason_code: Some("SUPERSEDED_BY_NEW_VERDICT".to_owned()),
                updated_at: Some(now),
            };
            let supersede_event = VerdictEvent {
                event_id: event_id.clone(),
                kind: VerdictEventKind::Superseded as i32,
                founder_verdict_id: old_state.founder_verdict_id,
                resulting_state_revision: state.revision,
                authenticated_principal_id: principal.principal_id.clone(),
                command_id: command_id.clone(),
                evidence_artifact_ids: evidence,
                committed_at: Some(now),
            };
            let event = supersede_event.encode_to_vec();
            let projection_result = VerdictCommandResult {
                committed: true,
                replayed: false,
                verdict: Some(old_verdict),
                state: Some(state.clone()),
                consumption_receipt: None,
                event: Some(supersede_event),
                error_code: VerdictErrorCode::Unspecified as i32,
                safe_error_fingerprint: None,
            }
            .encode_to_vec();
            PreparedSupersedeCommit {
                verdict_id: state.founder_verdict_id.clone(),
                expected_revision: old_state.revision,
                state: state.encode_to_vec(),
                event_id,
                command_id,
                outbox_id: format!("verdict-outbox-read-{}", Uuid::now_v7()),
                outbox_digest: hex::encode(Sha256::digest(&event)),
                event,
                projection_outbox_id: format!("verdict-projection-outbox-{}", Uuid::now_v7()),
                projection_payload_digest: hex::encode(Sha256::digest(&projection_result)),
                projection_payload: projection_result,
            }
        });
        let supersede_commit = prepared_supersede
            .as_ref()
            .map(PreparedSupersedeCommit::as_store_commit);
        let result_bytes = result.encode_to_vec();
        let projection_digest = hex::encode(Sha256::digest(&result_bytes));
        let changed = self.store.issue(&IssueCommit {
            verdict_id: &verdict_id,
            scope_digest: &scope_digest,
            payload_digest: &payload_digest,
            verdict: &verdict.encode_to_vec(),
            state: &state.encode_to_vec(),
            state_kind: state.state,
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest,
            event: &event_bytes,
            principal_id: &principal.principal_id,
            operation: ISSUE_OPERATION,
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result_bytes,
            read_outbox_id: &format!("verdict-outbox-read-{}", Uuid::now_v7()),
            task_outbox_id: &format!("verdict-outbox-task-{}", Uuid::now_v7()),
            outbox_digest: &outbox_digest,
            projection_outbox_id: &format!("verdict-projection-outbox-{}", Uuid::now_v7()),
            projection_payload_digest: &projection_digest,
            projection_payload: &result_bytes,
            committed_at: now.seconds,
            supersede: supersede_commit,
        })?;
        if !changed {
            return Ok(error_result(
                VerdictErrorCode::AlreadyActive,
                "VERDICT_ALREADY_ACTIVE_FOR_SCOPE",
            ));
        }
        Ok(result)
    }

    fn consume(
        &mut self,
        command: &ConsumeFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        request_digest: &str,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        if command.founder_verdict_id.trim().is_empty()
            || command.expected_state_revision == 0
            || command.task_event_id.trim().is_empty()
            || command.task_commit_receipt_ref.trim().is_empty()
        {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "CONSUME_INPUT_INCOMPLETE",
            ));
        }
        let Some((verdict, current)) = self.get(&command.founder_verdict_id)? else {
            return Ok(error_result(
                VerdictErrorCode::NotFound,
                "VERDICT_NOT_FOUND",
            ));
        };
        if let Some(error) = validate_issued_revision(&current, command.expected_state_revision) {
            return Ok(error);
        }
        let now = self.clock.now()?;
        if timestamp_after_or_equal(&now, verdict.expires_at.as_ref()) {
            return Ok(error_result(VerdictErrorCode::Expired, "VERDICT_EXPIRED"));
        }
        if let Err(rejection) = self.resolver.validate_task_commit(command) {
            return Ok(reference_error(rejection));
        }
        let expected_status = match FounderVerdictDecision::try_from(verdict.decision)
            .unwrap_or(FounderVerdictDecision::Unspecified)
        {
            FounderVerdictDecision::Accept => "TASK_STATUS_COMPLETED",
            FounderVerdictDecision::Rework => "TASK_STATUS_REWORK",
            FounderVerdictDecision::Reject => "TASK_STATUS_REJECTED",
            _ => {
                return Ok(error_result(
                    VerdictErrorCode::IntegrityFailure,
                    "STORED_VERDICT_DECISION_INVALID",
                ));
            }
        };
        if command.resulting_task_status != expected_status
            || command.resulting_task_revision != command.consumed_task_revision + 1
        {
            return Ok(error_result(
                VerdictErrorCode::TaskCommitReceiptInvalid,
                "TASK_RESULT_DOES_NOT_MATCH_VERDICT",
            ));
        }
        let meta = command.metadata.as_ref().expect("metadata checked");
        let receipt_id = format!("verdict-consumption-{}", Uuid::now_v7());
        let event_id = format!("verdict-event-{}", Uuid::now_v7());
        let receipt = VerdictConsumptionReceipt {
            consumption_receipt_id: receipt_id.clone(),
            founder_verdict_id: command.founder_verdict_id.clone(),
            task_id: verdict
                .scope
                .as_ref()
                .map(|s| s.task_id.clone())
                .unwrap_or_default(),
            consumed_task_revision: command.consumed_task_revision,
            resulting_task_revision: command.resulting_task_revision,
            task_event_id: command.task_event_id.clone(),
            resulting_task_status: command.resulting_task_status.clone(),
            consumed_at: Some(now),
        };
        let state = FounderVerdictState {
            founder_verdict_id: command.founder_verdict_id.clone(),
            revision: current.revision + 1,
            state: FounderVerdictStateKind::Consumed as i32,
            consumption_receipt_id: Some(receipt_id.clone()),
            superseded_by_verdict_id: None,
            terminal_reason_code: None,
            updated_at: Some(now),
        };
        let event = VerdictEvent {
            event_id: event_id.clone(),
            kind: VerdictEventKind::Consumed as i32,
            founder_verdict_id: command.founder_verdict_id.clone(),
            resulting_state_revision: state.revision,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            evidence_artifact_ids: vec![command.task_commit_receipt_ref.clone()],
            committed_at: Some(now),
        };
        let result = VerdictCommandResult {
            committed: true,
            replayed: false,
            verdict: Some(verdict),
            state: Some(state.clone()),
            consumption_receipt: Some(receipt.clone()),
            event: Some(event.clone()),
            error_code: VerdictErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let event_bytes = event.encode_to_vec();
        let outbox_digest = hex::encode(Sha256::digest(&event_bytes));
        let result_bytes = result.encode_to_vec();
        let projection_digest = hex::encode(Sha256::digest(&result_bytes));
        let changed = self.store.consume(&ConsumeCommit {
            verdict_id: &command.founder_verdict_id,
            expected_revision: command.expected_state_revision,
            state: &state.encode_to_vec(),
            state_kind: state.state,
            receipt_id: &receipt_id,
            task_event_id: &command.task_event_id,
            receipt: &receipt.encode_to_vec(),
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest,
            event: &event_bytes,
            principal_id: &principal.principal_id,
            operation: CONSUME_OPERATION,
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result_bytes,
            outbox_id: &format!("verdict-outbox-read-{}", Uuid::now_v7()),
            outbox_digest: &outbox_digest,
            projection_outbox_id: &format!("verdict-projection-outbox-{}", Uuid::now_v7()),
            projection_payload_digest: &projection_digest,
            projection_payload: &result_bytes,
            committed_at: now.seconds,
        })?;
        if !changed {
            return Ok(error_result(
                VerdictErrorCode::RevisionConflict,
                "VERDICT_STATE_REVISION_STALE",
            ));
        }
        Ok(result)
    }

    fn revoke(
        &mut self,
        command: &RevokeFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        request_digest: &str,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        if command.founder_verdict_id.trim().is_empty()
            || command.expected_state_revision == 0
            || command.reason_code.trim().is_empty()
            || command.confirmation_proof_ref.trim().is_empty()
        {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "REVOKE_INPUT_INCOMPLETE",
            ));
        }
        let Some((verdict, current)) = self.get(&command.founder_verdict_id)? else {
            return Ok(error_result(
                VerdictErrorCode::NotFound,
                "VERDICT_NOT_FOUND",
            ));
        };
        if let Some(error) = validate_issued_revision(&current, command.expected_state_revision) {
            return Ok(error);
        }
        let now = self.clock.now()?;
        if timestamp_after_or_equal(&now, verdict.expires_at.as_ref()) {
            return Ok(error_result(VerdictErrorCode::Expired, "VERDICT_EXPIRED"));
        }
        let mut evidence = match self.resolver.validate_revoke(command, principal) {
            Ok(evidence) => evidence,
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        if evidence.is_empty() {
            return Ok(error_result(
                VerdictErrorCode::ConfirmationRequired,
                "TRUSTED_REVOKE_EVIDENCE_MISSING",
            ));
        }
        evidence.push(command.confirmation_proof_ref.clone());
        normalize_evidence(&mut evidence);
        self.commit_state_transition(
            verdict,
            current,
            FounderVerdictStateKind::Revoked,
            VerdictEventKind::Revoked,
            Some(command.reason_code.clone()),
            None,
            evidence,
            command.metadata.as_ref().expect("metadata checked"),
            principal,
            REVOKE_OPERATION,
            request_digest,
            now,
        )
    }

    fn expire(
        &mut self,
        command: &ExpireFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        request_digest: &str,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        if command.founder_verdict_id.trim().is_empty()
            || command.expected_state_revision == 0
            || command.policy_decision_ref.trim().is_empty()
        {
            return Ok(error_result(
                VerdictErrorCode::InvalidArgument,
                "EXPIRE_INPUT_INCOMPLETE",
            ));
        }
        let Some((verdict, current)) = self.get(&command.founder_verdict_id)? else {
            return Ok(error_result(
                VerdictErrorCode::NotFound,
                "VERDICT_NOT_FOUND",
            ));
        };
        if let Some(error) = validate_issued_revision(&current, command.expected_state_revision) {
            return Ok(error);
        }
        let mut evidence = match self.resolver.validate_expiry(command, principal) {
            Ok(evidence) => evidence,
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        if evidence.is_empty() {
            return Ok(error_result(
                VerdictErrorCode::IntegrityFailure,
                "TRUSTED_EXPIRY_EVIDENCE_MISSING",
            ));
        }
        evidence.push(command.policy_decision_ref.clone());
        normalize_evidence(&mut evidence);
        self.commit_state_transition(
            verdict,
            current,
            FounderVerdictStateKind::Expired,
            VerdictEventKind::Expired,
            Some("POLICY_EXPIRED".to_owned()),
            None,
            evidence,
            command.metadata.as_ref().expect("metadata checked"),
            principal,
            EXPIRE_OPERATION,
            request_digest,
            self.clock.now()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_state_transition(
        &mut self,
        verdict: FounderVerdict,
        current: FounderVerdictState,
        target_state: FounderVerdictStateKind,
        event_kind: VerdictEventKind,
        terminal_reason_code: Option<String>,
        superseded_by_verdict_id: Option<String>,
        evidence_artifact_ids: Vec<String>,
        metadata: &CommandMetadata,
        principal: &AuthenticatedVerdictPrincipal,
        operation: &str,
        request_digest: &str,
        now: Timestamp,
    ) -> Result<VerdictCommandResult, VerdictAuthorityFailure> {
        let event_id = format!("verdict-event-{}", Uuid::now_v7());
        let state = FounderVerdictState {
            founder_verdict_id: verdict.founder_verdict_id.clone(),
            revision: current.revision + 1,
            state: target_state as i32,
            consumption_receipt_id: None,
            superseded_by_verdict_id,
            terminal_reason_code,
            updated_at: Some(now),
        };
        let event = VerdictEvent {
            event_id: event_id.clone(),
            kind: event_kind as i32,
            founder_verdict_id: verdict.founder_verdict_id.clone(),
            resulting_state_revision: state.revision,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: metadata.command_id.clone(),
            evidence_artifact_ids,
            committed_at: Some(now),
        };
        let result = VerdictCommandResult {
            committed: true,
            replayed: false,
            verdict: Some(verdict),
            state: Some(state.clone()),
            consumption_receipt: None,
            event: Some(event.clone()),
            error_code: VerdictErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let event_bytes = event.encode_to_vec();
        let outbox_digest = hex::encode(Sha256::digest(&event_bytes));
        let result_bytes = result.encode_to_vec();
        let projection_digest = hex::encode(Sha256::digest(&result_bytes));
        let changed = self.store.transition(&StateCommit {
            verdict_id: &state.founder_verdict_id,
            expected_revision: current.revision,
            state: &state.encode_to_vec(),
            state_kind: state.state,
            event_id: &event_id,
            command_id: &metadata.command_id,
            request_digest,
            event: &event_bytes,
            principal_id: &principal.principal_id,
            operation,
            idempotency_scope: &metadata.idempotency_scope,
            idempotency_key: &metadata.idempotency_key,
            result: &result_bytes,
            outbox_id: &format!("verdict-outbox-read-{}", Uuid::now_v7()),
            outbox_digest: &outbox_digest,
            projection_outbox_id: &format!("verdict-projection-outbox-{}", Uuid::now_v7()),
            projection_payload_digest: &projection_digest,
            projection_payload: &result_bytes,
            committed_at: now.seconds,
        })?;
        if !changed {
            return Ok(error_result(
                VerdictErrorCode::RevisionConflict,
                "VERDICT_STATE_REVISION_STALE",
            ));
        }
        Ok(result)
    }
}

#[must_use]
pub fn canonical_request_digest(command: &VerdictCommand) -> String {
    let mut canonical = command.clone();
    if let Some(meta) = command_metadata_mut(&mut canonical) {
        meta.command_id.clear();
        meta.request_digest_sha256.clear();
        meta.issued_at = None;
        meta.correlation_id.clear();
        meta.causation_id = None;
    }
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

fn validate_issued_revision(
    state: &FounderVerdictState,
    expected_revision: u64,
) -> Option<VerdictCommandResult> {
    if state.revision != expected_revision {
        return Some(error_result(
            VerdictErrorCode::RevisionConflict,
            "VERDICT_STATE_REVISION_STALE",
        ));
    }
    match FounderVerdictStateKind::try_from(state.state)
        .unwrap_or(FounderVerdictStateKind::Unspecified)
    {
        FounderVerdictStateKind::Issued => {}
        FounderVerdictStateKind::Consumed => {
            return Some(error_result(
                VerdictErrorCode::AlreadyConsumed,
                "VERDICT_ALREADY_CONSUMED",
            ));
        }
        FounderVerdictStateKind::Expired => {
            return Some(error_result(VerdictErrorCode::Expired, "VERDICT_EXPIRED"));
        }
        FounderVerdictStateKind::Revoked | FounderVerdictStateKind::Superseded => {
            return Some(error_result(
                VerdictErrorCode::Revoked,
                "VERDICT_NOT_ISSUED",
            ));
        }
        FounderVerdictStateKind::Unspecified => {
            return Some(error_result(
                VerdictErrorCode::IntegrityFailure,
                "VERDICT_STATE_INVALID",
            ));
        }
    }
    None
}

fn normalize_evidence(evidence: &mut Vec<String>) {
    evidence.retain(|item| !item.trim().is_empty());
    evidence.sort();
    evidence.dedup();
}

fn validate_decision(
    command: &IssueFounderVerdictCommand,
    resolved: &ResolvedVerdictContext,
    decision: FounderVerdictDecision,
    observed: VerificationConclusion,
) -> Option<VerdictCommandResult> {
    match decision {
        FounderVerdictDecision::Accept if !resolved.non_overridable_gate_ids.is_empty() => {
            Some(error_result(
                VerdictErrorCode::NonOverridableGate,
                "NON_OVERRIDABLE_GATE_OPEN",
            ))
        }
        FounderVerdictDecision::Accept if observed != VerificationConclusion::Passed => {
            validate_risk_coverage(&command.risk_acceptances, resolved)
        }
        FounderVerdictDecision::Rework
            if command.rework_directive.as_ref().is_none_or(|d| {
                d.directive_id.trim().is_empty()
                    || d.reason_code.trim().is_empty()
                    || d.required_changes_artifact_id.trim().is_empty()
            }) =>
        {
            Some(error_result(
                VerdictErrorCode::ReworkDirectiveRequired,
                "REWORK_DIRECTIVE_REQUIRED",
            ))
        }
        FounderVerdictDecision::Reject if command.reason_code.trim().is_empty() => Some(
            error_result(VerdictErrorCode::InvalidArgument, "REJECT_REASON_REQUIRED"),
        ),
        _ => None,
    }
}

fn validate_risk_coverage(
    risks: &[RiskAcceptance],
    resolved: &ResolvedVerdictContext,
) -> Option<VerdictCommandResult> {
    if risks.is_empty() {
        return Some(error_result(
            VerdictErrorCode::RiskAcceptanceRequired,
            "RISK_ACCEPTANCE_REQUIRED",
        ));
    }
    let expected_discrepancies: BTreeSet<_> =
        resolved.open_discrepancy_ids.iter().cloned().collect();
    let expected_unverified: BTreeSet<_> =
        resolved.open_unverified_item_ids.iter().cloned().collect();
    let mut discrepancies = BTreeSet::new();
    let mut unverified = BTreeSet::new();
    for risk in risks {
        let category = RiskCategory::try_from(risk.category).unwrap_or(RiskCategory::Unspecified);
        if risk.risk_acceptance_id.trim().is_empty()
            || category == RiskCategory::Unspecified
            || risk.rationale_artifact_id.trim().is_empty()
            || risk.compensating_control_artifact_ids.is_empty()
        {
            return Some(error_result(
                VerdictErrorCode::RiskAcceptanceRequired,
                "RISK_ACCEPTANCE_INCOMPLETE",
            ));
        }
        if risk
            .discrepancy_ids
            .iter()
            .any(|id| !discrepancies.insert(id.clone()))
            || risk
                .unverified_item_ids
                .iter()
                .any(|id| !unverified.insert(id.clone()))
        {
            return Some(error_result(
                VerdictErrorCode::RiskCoverageIncomplete,
                "RISK_COVERAGE_DUPLICATE",
            ));
        }
    }
    if discrepancies != expected_discrepancies || unverified != expected_unverified {
        return Some(error_result(
            VerdictErrorCode::RiskCoverageIncomplete,
            "RISK_COVERAGE_INCOMPLETE",
        ));
    }
    None
}

fn operation_name(command: &VerdictCommand) -> Option<&'static str> {
    match command.command.as_ref()? {
        verdict_command::Command::IssueFounderVerdict(_) => Some(ISSUE_OPERATION),
        verdict_command::Command::ConsumeFounderVerdict(_) => Some(CONSUME_OPERATION),
        verdict_command::Command::RevokeFounderVerdict(_) => Some(REVOKE_OPERATION),
        verdict_command::Command::ExpireFounderVerdict(_) => Some(EXPIRE_OPERATION),
    }
}

fn operation_allowed(operation: &str, kind: VerdictPrincipalKind) -> bool {
    match operation {
        ISSUE_OPERATION | REVOKE_OPERATION => kind == VerdictPrincipalKind::FounderAuthority,
        CONSUME_OPERATION => kind == VerdictPrincipalKind::TaskAuthority,
        EXPIRE_OPERATION => kind == VerdictPrincipalKind::PolicyAuthority,
        _ => false,
    }
}

fn command_metadata(command: &VerdictCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        verdict_command::Command::IssueFounderVerdict(v) => v.metadata.as_ref(),
        verdict_command::Command::ConsumeFounderVerdict(v) => v.metadata.as_ref(),
        verdict_command::Command::RevokeFounderVerdict(v) => v.metadata.as_ref(),
        verdict_command::Command::ExpireFounderVerdict(v) => v.metadata.as_ref(),
    }
}

fn command_metadata_mut(command: &mut VerdictCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        verdict_command::Command::IssueFounderVerdict(v) => v.metadata.as_mut(),
        verdict_command::Command::ConsumeFounderVerdict(v) => v.metadata.as_mut(),
        verdict_command::Command::RevokeFounderVerdict(v) => v.metadata.as_mut(),
        verdict_command::Command::ExpireFounderVerdict(v) => v.metadata.as_mut(),
    }
}

fn metadata_complete(meta: &CommandMetadata) -> bool {
    !meta.command_id.trim().is_empty()
        && !meta.idempotency_scope.trim().is_empty()
        && !meta.idempotency_key.trim().is_empty()
        && meta.request_digest_sha256.len() == 64
        && meta.issued_at.is_some()
        && !meta.correlation_id.trim().is_empty()
}

fn scope_complete(scope: Option<&VerdictScope>) -> bool {
    scope.is_some_and(|s| {
        !s.task_id.trim().is_empty()
            && s.task_revision > 0
            && s.work_revision > 0
            && !s.artifact_set_id.trim().is_empty()
            && content_address_complete(s.artifact_set_manifest.as_ref())
            && !s.verification_artifact_id.trim().is_empty()
            && content_address_complete(s.verification_payload.as_ref())
            && s.acceptance_contract_ref
                .as_ref()
                .is_some_and(contract_complete)
    })
}

fn content_address_complete(address: Option<&ContentAddress>) -> bool {
    address.is_some_and(|a| {
        a.algorithm == HashAlgorithm::Sha256 as i32
            && a.digest.len() == 64
            && a.digest.bytes().all(|b| b.is_ascii_hexdigit())
            && a.byte_length > 0
    })
}

fn contract_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && reference.sha256.len() == 64
        && reference.sha256.bytes().all(|b| b.is_ascii_hexdigit())
}

fn timestamp_after(left: &Timestamp, right: &Timestamp) -> bool {
    (left.seconds, left.nanos) > (right.seconds, right.nanos)
}
fn timestamp_after_or_equal(left: &Timestamp, right: Option<&Timestamp>) -> bool {
    right.is_none_or(|r| (left.seconds, left.nanos) >= (r.seconds, r.nanos))
}

fn reference_error(rejection: VerdictReferenceRejection) -> VerdictCommandResult {
    let (code, detail) = match rejection {
        VerdictReferenceRejection::Unauthenticated => (
            VerdictErrorCode::Unauthenticated,
            "TRUSTED_PRINCIPAL_UNAVAILABLE",
        ),
        VerdictReferenceRejection::PermissionDenied => (
            VerdictErrorCode::PermissionDenied,
            "AUTHORITY_POLICY_DENIED",
        ),
        VerdictReferenceRejection::NotFound => (VerdictErrorCode::NotFound, "REFERENCE_NOT_FOUND"),
        VerdictReferenceRejection::ScopeStale => {
            (VerdictErrorCode::ScopeStale, "VERDICT_SCOPE_STALE")
        }
        VerdictReferenceRejection::VerificationMismatch => (
            VerdictErrorCode::VerificationMismatch,
            "VERIFICATION_MISMATCH",
        ),
        VerdictReferenceRejection::ConfirmationRequired => (
            VerdictErrorCode::ConfirmationRequired,
            "TRUSTED_CONFIRMATION_REQUIRED",
        ),
        VerdictReferenceRejection::TaskCommitReceiptInvalid => (
            VerdictErrorCode::TaskCommitReceiptInvalid,
            "TASK_COMMIT_RECEIPT_INVALID",
        ),
        VerdictReferenceRejection::IntegrityFailure => (
            VerdictErrorCode::IntegrityFailure,
            "REFERENCE_INTEGRITY_FAILURE",
        ),
    };
    error_result(code, detail)
}

fn error_result(code: VerdictErrorCode, detail: &str) -> VerdictCommandResult {
    VerdictCommandResult {
        committed: false,
        replayed: false,
        verdict: None,
        state: None,
        consumption_receipt: None,
        event: None,
        error_code: code as i32,
        safe_error_fingerprint: Some(detail.to_owned()),
    }
}
