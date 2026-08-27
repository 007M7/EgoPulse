#![forbid(unsafe_code)]
//! C-03/C-08 Policy Decision Authority single-writer boundary.
//!
//! Client commands carry approval intent only. Durable Harness request facts,
//! native routing, fencing and authorization proof are supplied by trusted
//! composition guards and are never accepted as request-body assertions.

mod store;

use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecision, ApprovalDecisionEnvelope, ApprovalDecisionReceipt, ApprovalKind,
    ApprovalRequestLifecycleKind, DeliveryDisposition,
};
use egopulse_domain_contracts::v01::egopulse::policy::v1::{
    ConsumeHarnessApprovalDecisionCommand, ExpireHarnessApprovalDecisionCommand,
    HarnessApprovalConsumptionReceipt, HarnessApprovalDecisionRecord, HarnessApprovalDecisionState,
    HarnessApprovalDecisionStateKind, HarnessApprovalRequestBinding,
    IssueHarnessApprovalDecisionCommand, PolicyAuthorityProof, PolicyDecisionCommand,
    PolicyDecisionCommandResult, PolicyDecisionErrorCode, PolicyDecisionEvent,
    PolicyDecisionEventKind, RevokeHarnessApprovalDecisionCommand, policy_decision_command,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use store::{
    ConsumeCommit, IssueCommit, PolicyStore, ProjectionBootstrapCandidate,
    ProjectionBootstrapWrite, StateCommit, StoreError,
};
pub use store::{PendingPolicyOutbox, PolicyStoreInspection};

const ISSUE_OPERATION: &str = "issue_harness_approval_decision";
const CONSUME_OPERATION: &str = "consume_harness_approval_decision";
const REVOKE_OPERATION: &str = "revoke_harness_approval_decision";
const EXPIRE_OPERATION: &str = "expire_harness_approval_decision";

#[derive(Clone, Debug, PartialEq)]
pub struct PendingPolicyProjection {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub rebuild_baseline: bool,
    pub result: PolicyDecisionCommandResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPrincipalKind {
    LocalUser,
    FounderPolicy,
    HarnessAdapter,
    PolicyAuthority,
    RecoveryCoordinator,
    Model,
    UserInterface,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPolicyPrincipal {
    pub kind: PolicyPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

#[derive(Clone, Debug)]
pub struct ResolvedApprovalAuthorization {
    pub request: HarnessApprovalRequestBinding,
    pub authority_proof: PolicyAuthorityProof,
    pub evidence_refs: Vec<String>,
    pub expires_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyReferenceRejection {
    Unauthenticated,
    PermissionDenied,
    NotFound,
    RequestMismatch,
    FencingRejected,
    PolicyDenied,
    DeliveryReceiptInvalid,
    IntegrityFailure,
}

pub trait PolicyReferenceResolver: Send + Sync + 'static {
    fn resolve_issue(
        &self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection>;

    fn validate_adapter_receipt(
        &self,
        command: &ConsumeHarnessApprovalDecisionCommand,
        record: &HarnessApprovalDecisionRecord,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection>;

    fn validate_revoke(
        &self,
        _command: &RevokeHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }

    fn validate_expiry(
        &self,
        _command: &ExpireHarnessApprovalDecisionCommand,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        Err(PolicyReferenceRejection::PermissionDenied)
    }
}

pub trait PolicyClock: Send + Sync + 'static {
    fn now(&self) -> Result<Timestamp, PolicyAuthorityFailure>;
}

pub struct SystemPolicyClock;

impl PolicyClock for SystemPolicyClock {
    fn now(&self) -> Result<Timestamp, PolicyAuthorityFailure> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PolicyAuthorityFailure::Clock)?;
        Ok(Timestamp {
            seconds: duration.as_secs() as i64,
            nanos: duration.subsec_nanos() as i32,
        })
    }
}

pub struct PolicySqlCipherKey(Zeroizing<[u8; 32]>);

impl PolicySqlCipherKey {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct PolicyAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: PolicySqlCipherKey,
}

#[derive(Debug, Error)]
pub enum PolicyAuthorityFailure {
    #[error("policy decision storage is unavailable")]
    Storage,
    #[error("stored policy decision protobuf could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("policy decision clock is before Unix epoch")]
    Clock,
}

impl From<StoreError> for PolicyAuthorityFailure {
    fn from(_: StoreError) -> Self {
        Self::Storage
    }
}

pub struct PolicyDecisionAuthority<C = SystemPolicyClock> {
    store: PolicyStore,
    resolver: Box<dyn PolicyReferenceResolver>,
    clock: C,
}

impl PolicyDecisionAuthority<SystemPolicyClock> {
    pub fn open(
        config: PolicyAuthorityConfig,
        resolver: impl PolicyReferenceResolver,
    ) -> Result<Self, PolicyAuthorityFailure> {
        Self::open_with_clock(config, resolver, SystemPolicyClock)
    }
}

impl<C: PolicyClock> PolicyDecisionAuthority<C> {
    pub fn open_with_clock(
        config: PolicyAuthorityConfig,
        resolver: impl PolicyReferenceResolver,
        clock: C,
    ) -> Result<Self, PolicyAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(PolicyAuthorityFailure::Storage);
        }
        let mut store = PolicyStore::open(
            &config.database_path,
            config.key.expose(),
            &config.store_epoch,
        )?;
        let bootstrap_writes = store
            .projection_bootstrap_candidates()?
            .into_iter()
            .map(encode_projection_bootstrap)
            .collect::<Result<Vec<_>, _>>()?;
        store.complete_projection_bootstrap(&bootstrap_writes)?;
        Ok(Self {
            store,
            resolver: Box::new(resolver),
            clock,
        })
    }

    pub fn execute(
        &mut self,
        command: &PolicyDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "POLICY_COMMAND_MISSING",
            ));
        };
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                PolicyDecisionErrorCode::Unauthenticated,
                "PRINCIPAL_NOT_AUTHENTICATED",
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                PolicyDecisionErrorCode::PermissionDenied,
                "PRINCIPAL_OPERATION_NOT_ALLOWED",
            ));
        }
        let Some(meta) = command_metadata(command) else {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "COMMAND_METADATA_MISSING",
            ));
        };
        if !metadata_complete(meta) {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "COMMAND_METADATA_INCOMPLETE",
            ));
        }
        let digest = canonical_request_digest(command);
        if digest != meta.request_digest_sha256 {
            return Ok(error_result(
                PolicyDecisionErrorCode::RequestMismatch,
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
                    PolicyDecisionErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED",
                ));
            }
            let mut result = PolicyDecisionCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }
        match command.command.as_ref() {
            Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) => {
                self.issue(issue, principal, &digest)
            }
            Some(policy_decision_command::Command::ConsumeHarnessApprovalDecision(consume)) => {
                self.consume(consume, principal, &digest)
            }
            Some(policy_decision_command::Command::RevokeHarnessApprovalDecision(revoke)) => {
                self.revoke(revoke, principal, &digest)
            }
            Some(policy_decision_command::Command::ExpireHarnessApprovalDecision(expire)) => {
                self.expire(expire, principal, &digest)
            }
            None => Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "POLICY_COMMAND_MISSING",
            )),
        }
    }

    pub fn get(
        &self,
        decision_ref: &str,
    ) -> Result<
        Option<(HarnessApprovalDecisionRecord, HarnessApprovalDecisionState)>,
        PolicyAuthorityFailure,
    > {
        self.store
            .stored_decision(decision_ref)?
            .map(|stored| {
                Ok((
                    HarnessApprovalDecisionRecord::decode(stored.decision_record.as_slice())?,
                    HarnessApprovalDecisionState::decode(stored.state.as_slice())?,
                ))
            })
            .transpose()
    }

    pub fn inspect_store(&self) -> Result<PolicyStoreInspection, PolicyAuthorityFailure> {
        self.store.inspect().map_err(PolicyAuthorityFailure::from)
    }

    pub fn pending_outbox(&self) -> Result<Vec<PendingPolicyOutbox>, PolicyAuthorityFailure> {
        self.store
            .pending_outbox()
            .map_err(PolicyAuthorityFailure::from)
    }

    pub fn pending_projection_messages(
        &self,
    ) -> Result<Vec<PendingPolicyProjection>, PolicyAuthorityFailure> {
        self.store
            .pending_projection_outbox()?
            .into_iter()
            .map(decode_projection_outbox)
            .collect()
    }

    pub fn retained_projection_messages_for_rebuild(
        &self,
    ) -> Result<Vec<PendingPolicyProjection>, PolicyAuthorityFailure> {
        self.store
            .retained_projection_outbox()?
            .into_iter()
            .map(decode_projection_outbox)
            .collect()
    }

    pub fn acknowledge_projection_message(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, PolicyAuthorityFailure> {
        self.store
            .acknowledge_projection_outbox(message_id, payload_digest_sha256)
            .map_err(PolicyAuthorityFailure::from)
    }

    fn issue(
        &mut self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
        request_digest: &str,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        if command.approval_request_id.trim().is_empty()
            || !sha256_is_valid(&command.expected_action_digest_sha256)
            || command.expected_request_observation_id.trim().is_empty()
            || command.expected_request_observation_sequence == 0
            || command.expected_request_revision == 0
            || command.reason_code.trim().is_empty()
            || ApprovalDecision::try_from(command.decision).unwrap_or(ApprovalDecision::Unspecified)
                == ApprovalDecision::Unspecified
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "ISSUE_INPUT_INCOMPLETE",
            ));
        }
        let resolved = match self.resolver.resolve_issue(command, principal) {
            Ok(value) => value,
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        if !binding_complete(&resolved.request) {
            return Ok(error_result(
                PolicyDecisionErrorCode::RequestMismatch,
                "TRUSTED_APPROVAL_REQUEST_INVALID",
            ));
        }
        if resolved.request.request_revision != command.expected_request_revision
            || ApprovalRequestLifecycleKind::try_from(resolved.request.request_lifecycle)
                .unwrap_or(ApprovalRequestLifecycleKind::Unspecified)
                != ApprovalRequestLifecycleKind::Open
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::RevisionConflict,
                "TRUSTED_APPROVAL_REQUEST_NOT_CURRENT_OPEN_REVISION",
            ));
        }
        if resolved.request.approval_request_id != command.approval_request_id
            || resolved.request.action_digest_sha256 != command.expected_action_digest_sha256
            || resolved.request.request_observation_id != command.expected_request_observation_id
            || resolved.request.request_observation_sequence
                != command.expected_request_observation_sequence
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::RequestMismatch,
                "TRUSTED_APPROVAL_REQUEST_MISMATCH",
            ));
        }
        let now = self.clock.now()?;
        if !proof_complete(&resolved.authority_proof)
            || resolved.authority_proof.authenticated_principal_id != principal.principal_id
            || resolved.evidence_refs.is_empty()
            || timestamp_after(&resolved.authority_proof.verified_at, &now)
            || timestamp_after_or_equal(&now, Some(resolved.expires_at))
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::PolicyDenied,
                "TRUSTED_POLICY_AUTHORIZATION_INVALID",
            ));
        }
        let meta = command.metadata.as_ref().expect("metadata checked");
        let decision_ref = format!("policy-decision-{}", Uuid::now_v7());
        let event_id = format!("policy-event-{}", Uuid::now_v7());
        let mut record = HarnessApprovalDecisionRecord {
            authority_decision_ref: decision_ref.clone(),
            version: 1,
            request: Some(resolved.request.clone()),
            decision: command.decision,
            reason_code: command.reason_code.clone(),
            authority_proof: Some(resolved.authority_proof),
            issued_at: Some(now),
            expires_at: Some(resolved.expires_at),
            canonical_payload_digest_sha256: String::new(),
            supersedes_authority_decision_ref: None,
        };
        record.canonical_payload_digest_sha256 =
            hex::encode(Sha256::digest(record.encode_to_vec()));
        let state = HarnessApprovalDecisionState {
            authority_decision_ref: decision_ref.clone(),
            revision: 1,
            state: HarnessApprovalDecisionStateKind::Issued as i32,
            consumption_receipt_id: None,
            superseded_by_authority_decision_ref: None,
            terminal_reason_code: None,
            updated_at: Some(now),
        };
        let event = PolicyDecisionEvent {
            event_id: event_id.clone(),
            kind: PolicyDecisionEventKind::Issued as i32,
            authority_decision_ref: decision_ref.clone(),
            resulting_state_revision: 1,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            evidence_refs: normalize_evidence(resolved.evidence_refs),
            committed_at: Some(now),
        };
        let result = PolicyDecisionCommandResult {
            committed: true,
            replayed: false,
            decision_record: Some(record.clone()),
            state: Some(state.clone()),
            consumption_receipt: None,
            event: Some(event.clone()),
            error_code: PolicyDecisionErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let envelope = approval_envelope(&record, meta, now);
        let event_bytes = event.encode_to_vec();
        let envelope_bytes = envelope.encode_to_vec();
        let result_bytes = result.encode_to_vec();
        let projection_bytes = sanitized_read_model_projection(&result).encode_to_vec();
        let changed = self.store.issue(&IssueCommit {
            decision_ref: &decision_ref,
            approval_request_id: &command.approval_request_id,
            payload_digest: &record.canonical_payload_digest_sha256,
            decision_record: &record.encode_to_vec(),
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
            adapter_outbox_id: &format!("policy-outbox-adapter-{}", Uuid::now_v7()),
            adapter_payload_digest: &sha256(&envelope_bytes),
            adapter_payload: &envelope_bytes,
            read_outbox_id: &format!("policy-outbox-read-{}", Uuid::now_v7()),
            read_payload_digest: &sha256(&projection_bytes),
            read_payload: &projection_bytes,
            committed_at: now.seconds,
        })?;
        if !changed {
            return Ok(error_result(
                PolicyDecisionErrorCode::PolicyDenied,
                "ACTIVE_DECISION_ALREADY_EXISTS",
            ));
        }
        Ok(result)
    }

    fn consume(
        &mut self,
        command: &ConsumeHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
        request_digest: &str,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        let Some(receipt) = command.adapter_receipt.as_ref() else {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "ADAPTER_RECEIPT_MISSING",
            ));
        };
        if command.authority_decision_ref.trim().is_empty()
            || command.expected_state_revision == 0
            || !receipt_complete(receipt)
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "CONSUME_INPUT_INCOMPLETE",
            ));
        }
        let Some((record, current)) = self.get(&command.authority_decision_ref)? else {
            return Ok(error_result(
                PolicyDecisionErrorCode::NotFound,
                "POLICY_DECISION_NOT_FOUND",
            ));
        };
        if let Some(error) = validate_issued_revision(&current, command.expected_state_revision) {
            return Ok(error);
        }
        let now = self.clock.now()?;
        if timestamp_after_or_equal(&now, record.expires_at) {
            return Ok(error_result(
                PolicyDecisionErrorCode::Expired,
                "POLICY_DECISION_EXPIRED",
            ));
        }
        let disposition = DeliveryDisposition::try_from(receipt.disposition)
            .unwrap_or(DeliveryDisposition::Unspecified);
        if disposition != DeliveryDisposition::Delivered
            && disposition != DeliveryDisposition::Rejected
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::DeliveryReceiptInvalid,
                "DELIVERY_OUTCOME_NOT_FINAL",
            ));
        }
        let request = record.request.as_ref().expect("stored record validated");
        if receipt.approval_request_id != request.approval_request_id
            || receipt.decision != record.decision
            || canonical_receipt_digest(receipt) != receipt.receipt_digest_sha256
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::DeliveryReceiptInvalid,
                "ADAPTER_RECEIPT_BINDING_INVALID",
            ));
        }
        let mut evidence = match self
            .resolver
            .validate_adapter_receipt(command, &record, principal)
        {
            Ok(value) => value,
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        evidence.push(receipt.receipt_id.clone());
        let meta = command.metadata.as_ref().expect("metadata checked");
        let consumption_receipt_id = format!("policy-consumption-{}", Uuid::now_v7());
        let event_id = format!("policy-event-{}", Uuid::now_v7());
        let consumption = HarnessApprovalConsumptionReceipt {
            consumption_receipt_id: consumption_receipt_id.clone(),
            authority_decision_ref: command.authority_decision_ref.clone(),
            adapter_receipt: Some(receipt.clone()),
            consumed_at: Some(now),
        };
        let state = HarnessApprovalDecisionState {
            authority_decision_ref: command.authority_decision_ref.clone(),
            revision: current.revision + 1,
            state: HarnessApprovalDecisionStateKind::Consumed as i32,
            consumption_receipt_id: Some(consumption_receipt_id.clone()),
            superseded_by_authority_decision_ref: None,
            terminal_reason_code: None,
            updated_at: Some(now),
        };
        let event = PolicyDecisionEvent {
            event_id: event_id.clone(),
            kind: PolicyDecisionEventKind::Consumed as i32,
            authority_decision_ref: command.authority_decision_ref.clone(),
            resulting_state_revision: state.revision,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            evidence_refs: normalize_evidence(evidence),
            committed_at: Some(now),
        };
        let result = PolicyDecisionCommandResult {
            committed: true,
            replayed: false,
            decision_record: Some(record),
            state: Some(state.clone()),
            consumption_receipt: Some(consumption.clone()),
            event: Some(event.clone()),
            error_code: PolicyDecisionErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let event_bytes = event.encode_to_vec();
        let result_bytes = result.encode_to_vec();
        let projection_bytes = sanitized_read_model_projection(&result).encode_to_vec();
        let changed = self.store.consume(&ConsumeCommit {
            decision_ref: &command.authority_decision_ref,
            expected_revision: current.revision,
            state: &state.encode_to_vec(),
            state_kind: state.state,
            receipt_id: &consumption_receipt_id,
            adapter_receipt_id: &receipt.receipt_id,
            receipt: &consumption.encode_to_vec(),
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest,
            event: &event_bytes,
            principal_id: &principal.principal_id,
            operation: CONSUME_OPERATION,
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result_bytes,
            outbox_id: &format!("policy-outbox-read-{}", Uuid::now_v7()),
            outbox_digest: &sha256(&projection_bytes),
            outbox_payload: &projection_bytes,
            committed_at: now.seconds,
        })?;
        if !changed {
            return Ok(error_result(
                PolicyDecisionErrorCode::RevisionConflict,
                "POLICY_DECISION_REVISION_STALE",
            ));
        }
        Ok(result)
    }

    fn revoke(
        &mut self,
        command: &RevokeHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
        request_digest: &str,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        if command.reason_code.trim().is_empty() || command.confirmation_proof_ref.trim().is_empty()
        {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "REVOKE_PROOF_INCOMPLETE",
            ));
        }
        let evidence = match self.resolver.validate_revoke(command, principal) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                return Ok(error_result(
                    PolicyDecisionErrorCode::PolicyDenied,
                    "REVOKE_EVIDENCE_MISSING",
                ));
            }
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        self.transition(
            &command.authority_decision_ref,
            command.expected_state_revision,
            HarnessApprovalDecisionStateKind::Revoked,
            PolicyDecisionEventKind::Revoked,
            &command.reason_code,
            evidence,
            command.metadata.as_ref().expect("metadata checked"),
            principal,
            request_digest,
            REVOKE_OPERATION,
        )
    }

    fn expire(
        &mut self,
        command: &ExpireHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
        request_digest: &str,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        if command.policy_evaluation_ref.trim().is_empty() {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "EXPIRY_EVALUATION_MISSING",
            ));
        }
        let Some((record, _)) = self.get(&command.authority_decision_ref)? else {
            return Ok(error_result(
                PolicyDecisionErrorCode::NotFound,
                "POLICY_DECISION_NOT_FOUND",
            ));
        };
        let now = self.clock.now()?;
        if !timestamp_after_or_equal(&now, record.expires_at) {
            return Ok(error_result(
                PolicyDecisionErrorCode::PolicyDenied,
                "POLICY_DECISION_NOT_EXPIRED",
            ));
        }
        let evidence = match self.resolver.validate_expiry(command, principal) {
            Ok(value) if !value.is_empty() => value,
            Ok(_) => {
                return Ok(error_result(
                    PolicyDecisionErrorCode::PolicyDenied,
                    "EXPIRY_EVIDENCE_MISSING",
                ));
            }
            Err(rejection) => return Ok(reference_error(rejection)),
        };
        self.transition(
            &command.authority_decision_ref,
            command.expected_state_revision,
            HarnessApprovalDecisionStateKind::Expired,
            PolicyDecisionEventKind::Expired,
            "POLICY_DECISION_EXPIRED",
            evidence,
            command.metadata.as_ref().expect("metadata checked"),
            principal,
            request_digest,
            EXPIRE_OPERATION,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn transition(
        &mut self,
        decision_ref: &str,
        expected_revision: u64,
        state_kind: HarnessApprovalDecisionStateKind,
        event_kind: PolicyDecisionEventKind,
        reason: &str,
        evidence: Vec<String>,
        meta: &CommandMetadata,
        principal: &AuthenticatedPolicyPrincipal,
        request_digest: &str,
        operation: &str,
    ) -> Result<PolicyDecisionCommandResult, PolicyAuthorityFailure> {
        if decision_ref.trim().is_empty() || expected_revision == 0 {
            return Ok(error_result(
                PolicyDecisionErrorCode::InvalidArgument,
                "TRANSITION_INPUT_INCOMPLETE",
            ));
        }
        let Some((record, current)) = self.get(decision_ref)? else {
            return Ok(error_result(
                PolicyDecisionErrorCode::NotFound,
                "POLICY_DECISION_NOT_FOUND",
            ));
        };
        if let Some(error) = validate_issued_revision(&current, expected_revision) {
            return Ok(error);
        }
        let now = self.clock.now()?;
        let state = HarnessApprovalDecisionState {
            authority_decision_ref: decision_ref.to_owned(),
            revision: current.revision + 1,
            state: state_kind as i32,
            consumption_receipt_id: None,
            superseded_by_authority_decision_ref: None,
            terminal_reason_code: Some(reason.to_owned()),
            updated_at: Some(now),
        };
        let event_id = format!("policy-event-{}", Uuid::now_v7());
        let event = PolicyDecisionEvent {
            event_id: event_id.clone(),
            kind: event_kind as i32,
            authority_decision_ref: decision_ref.to_owned(),
            resulting_state_revision: state.revision,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            evidence_refs: normalize_evidence(evidence),
            committed_at: Some(now),
        };
        let result = PolicyDecisionCommandResult {
            committed: true,
            replayed: false,
            decision_record: Some(record),
            state: Some(state.clone()),
            consumption_receipt: None,
            event: Some(event.clone()),
            error_code: PolicyDecisionErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        let event_bytes = event.encode_to_vec();
        let result_bytes = result.encode_to_vec();
        let projection_bytes = sanitized_read_model_projection(&result).encode_to_vec();
        let changed = self.store.transition(&StateCommit {
            decision_ref,
            expected_revision: current.revision,
            state: &state.encode_to_vec(),
            state_kind: state.state,
            event_id: &event_id,
            command_id: &meta.command_id,
            request_digest,
            event: &event_bytes,
            principal_id: &principal.principal_id,
            operation,
            idempotency_scope: &meta.idempotency_scope,
            idempotency_key: &meta.idempotency_key,
            result: &result_bytes,
            outbox_id: &format!("policy-outbox-read-{}", Uuid::now_v7()),
            outbox_digest: &sha256(&projection_bytes),
            outbox_payload: &projection_bytes,
            committed_at: now.seconds,
        })?;
        if !changed {
            return Ok(error_result(
                PolicyDecisionErrorCode::RevisionConflict,
                "POLICY_DECISION_REVISION_STALE",
            ));
        }
        Ok(result)
    }
}

#[must_use]
pub fn canonical_request_digest(command: &PolicyDecisionCommand) -> String {
    let mut canonical = command.clone();
    if let Some(meta) = command_metadata_mut(&mut canonical) {
        meta.command_id.clear();
        meta.request_digest_sha256.clear();
        meta.issued_at = None;
        meta.correlation_id.clear();
        meta.causation_id = None;
    }
    sha256(&canonical.encode_to_vec())
}

#[must_use]
pub fn canonical_receipt_digest(receipt: &ApprovalDecisionReceipt) -> String {
    let mut canonical = receipt.clone();
    canonical.receipt_digest_sha256.clear();
    sha256(&canonical.encode_to_vec())
}

fn approval_envelope(
    record: &HarnessApprovalDecisionRecord,
    source: &CommandMetadata,
    now: Timestamp,
) -> ApprovalDecisionEnvelope {
    let request = record.request.as_ref().expect("record request checked");
    ApprovalDecisionEnvelope {
        meta: Some(CommandMetadata {
            command_id: format!("policy-delivery-{}", Uuid::now_v7()),
            idempotency_key: record.authority_decision_ref.clone(),
            idempotency_scope: "policy-decision-to-harness-adapter".to_owned(),
            request_digest_sha256: record.canonical_payload_digest_sha256.clone(),
            issued_at: Some(now),
            correlation_id: source.correlation_id.clone(),
            causation_id: Some(source.command_id.clone()),
        }),
        attempt_id: request.attempt_id.clone(),
        dispatch_id: request.dispatch_id.clone(),
        fencing_token: request.fencing_token,
        approval_request_id: request.approval_request_id.clone(),
        action_digest_sha256: request.action_digest_sha256.clone(),
        decision: record.decision,
        authority_decision_ref: record.authority_decision_ref.clone(),
        native_routing_ref: request.native_routing_ref.clone(),
    }
}

fn validate_issued_revision(
    state: &HarnessApprovalDecisionState,
    expected: u64,
) -> Option<PolicyDecisionCommandResult> {
    if state.revision != expected {
        return Some(error_result(
            PolicyDecisionErrorCode::RevisionConflict,
            "POLICY_DECISION_REVISION_STALE",
        ));
    }
    match HarnessApprovalDecisionStateKind::try_from(state.state)
        .unwrap_or(HarnessApprovalDecisionStateKind::Unspecified)
    {
        HarnessApprovalDecisionStateKind::Issued => None,
        HarnessApprovalDecisionStateKind::Consumed => Some(error_result(
            PolicyDecisionErrorCode::AlreadyConsumed,
            "POLICY_DECISION_ALREADY_CONSUMED",
        )),
        HarnessApprovalDecisionStateKind::Expired => Some(error_result(
            PolicyDecisionErrorCode::Expired,
            "POLICY_DECISION_EXPIRED",
        )),
        HarnessApprovalDecisionStateKind::Revoked
        | HarnessApprovalDecisionStateKind::Superseded => Some(error_result(
            PolicyDecisionErrorCode::Revoked,
            "POLICY_DECISION_NOT_ISSUED",
        )),
        HarnessApprovalDecisionStateKind::Unspecified => Some(error_result(
            PolicyDecisionErrorCode::IntegrityFailure,
            "POLICY_DECISION_STATE_INVALID",
        )),
    }
}

fn operation_name(command: &PolicyDecisionCommand) -> Option<&'static str> {
    match command.command.as_ref()? {
        policy_decision_command::Command::IssueHarnessApprovalDecision(_) => Some(ISSUE_OPERATION),
        policy_decision_command::Command::ConsumeHarnessApprovalDecision(_) => {
            Some(CONSUME_OPERATION)
        }
        policy_decision_command::Command::RevokeHarnessApprovalDecision(_) => {
            Some(REVOKE_OPERATION)
        }
        policy_decision_command::Command::ExpireHarnessApprovalDecision(_) => {
            Some(EXPIRE_OPERATION)
        }
    }
}

fn operation_allowed(operation: &str, kind: PolicyPrincipalKind) -> bool {
    match operation {
        ISSUE_OPERATION => matches!(
            kind,
            PolicyPrincipalKind::LocalUser | PolicyPrincipalKind::FounderPolicy
        ),
        CONSUME_OPERATION => kind == PolicyPrincipalKind::HarnessAdapter,
        REVOKE_OPERATION => matches!(
            kind,
            PolicyPrincipalKind::FounderPolicy | PolicyPrincipalKind::PolicyAuthority
        ),
        EXPIRE_OPERATION => matches!(
            kind,
            PolicyPrincipalKind::PolicyAuthority | PolicyPrincipalKind::RecoveryCoordinator
        ),
        _ => false,
    }
}

fn command_metadata(command: &PolicyDecisionCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        policy_decision_command::Command::IssueHarnessApprovalDecision(v) => v.metadata.as_ref(),
        policy_decision_command::Command::ConsumeHarnessApprovalDecision(v) => v.metadata.as_ref(),
        policy_decision_command::Command::RevokeHarnessApprovalDecision(v) => v.metadata.as_ref(),
        policy_decision_command::Command::ExpireHarnessApprovalDecision(v) => v.metadata.as_ref(),
    }
}

fn command_metadata_mut(command: &mut PolicyDecisionCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        policy_decision_command::Command::IssueHarnessApprovalDecision(v) => v.metadata.as_mut(),
        policy_decision_command::Command::ConsumeHarnessApprovalDecision(v) => v.metadata.as_mut(),
        policy_decision_command::Command::RevokeHarnessApprovalDecision(v) => v.metadata.as_mut(),
        policy_decision_command::Command::ExpireHarnessApprovalDecision(v) => v.metadata.as_mut(),
    }
}

fn metadata_complete(meta: &CommandMetadata) -> bool {
    !meta.command_id.trim().is_empty()
        && !meta.idempotency_scope.trim().is_empty()
        && !meta.idempotency_key.trim().is_empty()
        && sha256_is_valid(&meta.request_digest_sha256)
        && meta.issued_at.is_some()
        && !meta.correlation_id.trim().is_empty()
}

fn binding_complete(binding: &HarnessApprovalRequestBinding) -> bool {
    !binding.adapter_id.trim().is_empty()
        && !binding.attempt_id.trim().is_empty()
        && !binding.dispatch_id.trim().is_empty()
        && binding.fencing_token > 0
        && !binding.approval_request_id.trim().is_empty()
        && ApprovalKind::try_from(binding.kind).unwrap_or(ApprovalKind::Unspecified)
            != ApprovalKind::Unspecified
        && sha256_is_valid(&binding.action_digest_sha256)
        && !binding.requested_scope_ref.trim().is_empty()
        && !binding.native_routing_ref.trim().is_empty()
        && !binding.request_observation_id.trim().is_empty()
        && binding.request_observation_sequence > 0
        && ApprovalRequestLifecycleKind::try_from(binding.request_lifecycle)
            .unwrap_or(ApprovalRequestLifecycleKind::Unspecified)
            != ApprovalRequestLifecycleKind::Unspecified
        && binding.request_revision > 0
}

fn proof_complete(proof: &PolicyAuthorityProof) -> bool {
    !proof.authenticated_principal_id.trim().is_empty()
        && !proof.authentication_context_ref.trim().is_empty()
        && !proof.authorization_decision_id.trim().is_empty()
        && proof.verified_at.is_some()
        && proof
            .authorization_policy_ref
            .as_ref()
            .is_some_and(contract_complete)
}

fn contract_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && sha256_is_valid(&reference.sha256)
}

fn receipt_complete(receipt: &ApprovalDecisionReceipt) -> bool {
    !receipt.receipt_id.trim().is_empty()
        && !receipt.approval_request_id.trim().is_empty()
        && ApprovalDecision::try_from(receipt.decision).unwrap_or(ApprovalDecision::Unspecified)
            != ApprovalDecision::Unspecified
        && DeliveryDisposition::try_from(receipt.disposition)
            .unwrap_or(DeliveryDisposition::Unspecified)
            != DeliveryDisposition::Unspecified
        && sha256_is_valid(&receipt.receipt_digest_sha256)
        && receipt.delivered_at.is_some()
}

fn reference_error(rejection: PolicyReferenceRejection) -> PolicyDecisionCommandResult {
    let (code, fingerprint) = match rejection {
        PolicyReferenceRejection::Unauthenticated => (
            PolicyDecisionErrorCode::Unauthenticated,
            "TRUSTED_REFERENCE_UNAUTHENTICATED",
        ),
        PolicyReferenceRejection::PermissionDenied => (
            PolicyDecisionErrorCode::PermissionDenied,
            "TRUSTED_REFERENCE_PERMISSION_DENIED",
        ),
        PolicyReferenceRejection::NotFound => (
            PolicyDecisionErrorCode::NotFound,
            "TRUSTED_REFERENCE_NOT_FOUND",
        ),
        PolicyReferenceRejection::RequestMismatch => (
            PolicyDecisionErrorCode::RequestMismatch,
            "TRUSTED_REQUEST_MISMATCH",
        ),
        PolicyReferenceRejection::FencingRejected => (
            PolicyDecisionErrorCode::FencingRejected,
            "TRUSTED_FENCE_REJECTED",
        ),
        PolicyReferenceRejection::PolicyDenied => (
            PolicyDecisionErrorCode::PolicyDenied,
            "TRUSTED_POLICY_DENIED",
        ),
        PolicyReferenceRejection::DeliveryReceiptInvalid => (
            PolicyDecisionErrorCode::DeliveryReceiptInvalid,
            "TRUSTED_DELIVERY_RECEIPT_INVALID",
        ),
        PolicyReferenceRejection::IntegrityFailure => (
            PolicyDecisionErrorCode::IntegrityFailure,
            "TRUSTED_REFERENCE_INTEGRITY_FAILURE",
        ),
    };
    error_result(code, fingerprint)
}

fn error_result(code: PolicyDecisionErrorCode, fingerprint: &str) -> PolicyDecisionCommandResult {
    PolicyDecisionCommandResult {
        committed: false,
        replayed: false,
        decision_record: None,
        state: None,
        consumption_receipt: None,
        event: None,
        error_code: code as i32,
        safe_error_fingerprint: Some(fingerprint.to_owned()),
    }
}

fn normalize_evidence(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.trim().is_empty());
    values.sort();
    values.dedup();
    values
}

fn sanitized_read_model_projection(
    result: &PolicyDecisionCommandResult,
) -> PolicyDecisionCommandResult {
    let mut projection = result.clone();
    if let Some(request) = projection
        .decision_record
        .as_mut()
        .and_then(|record| record.request.as_mut())
    {
        request.native_routing_ref.clear();
    }
    projection
}

fn decode_projection_outbox(
    outbox: PendingPolicyOutbox,
) -> Result<PendingPolicyProjection, PolicyAuthorityFailure> {
    if outbox.payload_digest_sha256 != sha256(&outbox.payload) {
        return Err(PolicyAuthorityFailure::Storage);
    }
    let result = PolicyDecisionCommandResult::decode(outbox.payload.as_slice())?;
    let record = result
        .decision_record
        .as_ref()
        .ok_or(PolicyAuthorityFailure::Storage)?;
    let state = result
        .state
        .as_ref()
        .ok_or(PolicyAuthorityFailure::Storage)?;
    let event = result
        .event
        .as_ref()
        .ok_or(PolicyAuthorityFailure::Storage)?;
    let request = record
        .request
        .as_ref()
        .ok_or(PolicyAuthorityFailure::Storage)?;
    if !result.committed
        || event.event_id != outbox.source_event_id
        || event.resulting_state_revision != outbox.source_revision
        || state.revision != outbox.source_revision
        || state.authority_decision_ref != record.authority_decision_ref
        || event.authority_decision_ref != record.authority_decision_ref
        || !request.native_routing_ref.is_empty()
    {
        return Err(PolicyAuthorityFailure::Storage);
    }
    Ok(PendingPolicyProjection {
        message_id: outbox.message_id,
        source_event_id: outbox.source_event_id,
        source_revision: outbox.source_revision,
        payload_digest_sha256: outbox.payload_digest_sha256,
        rebuild_baseline: outbox.rebuild_baseline,
        result,
    })
}

fn encode_projection_bootstrap(
    candidate: ProjectionBootstrapCandidate,
) -> Result<ProjectionBootstrapWrite, PolicyAuthorityFailure> {
    let record = HarnessApprovalDecisionRecord::decode(candidate.decision_record.as_slice())?;
    let state = HarnessApprovalDecisionState::decode(candidate.state.as_slice())?;
    let event = PolicyDecisionEvent::decode(candidate.event.as_slice())?;
    let consumption_receipt = candidate
        .consumption_receipt
        .as_deref()
        .map(HarnessApprovalConsumptionReceipt::decode)
        .transpose()?;
    if record.authority_decision_ref != candidate.decision_ref
        || state.authority_decision_ref != candidate.decision_ref
        || state.revision != candidate.source_revision
        || event.authority_decision_ref != candidate.decision_ref
        || event.event_id != candidate.source_event_id
        || event.resulting_state_revision != candidate.source_revision
        || consumption_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.authority_decision_ref != candidate.decision_ref)
    {
        return Err(PolicyAuthorityFailure::Storage);
    }
    let result = sanitized_read_model_projection(&PolicyDecisionCommandResult {
        committed: true,
        replayed: false,
        decision_record: Some(record),
        state: Some(state),
        consumption_receipt,
        event: Some(event),
        error_code: PolicyDecisionErrorCode::Unspecified as i32,
        safe_error_fingerprint: None,
    });
    let payload = result.encode_to_vec();
    let identity = sha256(
        format!(
            "g4-08a|policy|{}|{}|{}",
            candidate.decision_ref, candidate.source_revision, candidate.source_event_id
        )
        .as_bytes(),
    );
    Ok(ProjectionBootstrapWrite {
        decision_ref: candidate.decision_ref,
        source_event_id: candidate.source_event_id,
        source_revision: candidate.source_revision,
        message_id: format!("policy-bootstrap-v1-{identity}"),
        payload_digest_sha256: sha256(&payload),
        payload,
        created_at_seconds: candidate.created_at_seconds,
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn sha256_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

fn timestamp_after(left: &Option<Timestamp>, right: &Timestamp) -> bool {
    left.as_ref()
        .is_some_and(|value| (value.seconds, value.nanos) > (right.seconds, right.nanos))
}

fn timestamp_after_or_equal(left: &Timestamp, right: Option<Timestamp>) -> bool {
    right
        .as_ref()
        .is_none_or(|value| (left.seconds, left.nanos) >= (value.seconds, value.nanos))
}
