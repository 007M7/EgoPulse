//! Internal ContextSnapshot owner.
//!
//! This module is deliberately not a Local API surface. It establishes the
//! durable owner and resolver needed by the frozen interaction before a public
//! prepare/confirm contract is admitted. A snapshot is immutable, content
//! addressed and checked again at consumption; no client, Worker, Provider or
//! Harness receives a store handle.

mod store;

use crate::task_authority::SqlCipherKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

pub const CONTEXT_AUTHORITY_REF: &str = "egopulse/context-authority/v1";
const MAX_ROUTING_BYTES: usize = 4 * 1024;
const MAX_CONTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LIST_ITEMS: usize = 256;
const MAX_REVOKE_REASON_BYTES: usize = 128;
const MAX_REVOKE_EVIDENCE_ITEMS: usize = 16;
const MAX_REVOKE_EVIDENCE_BYTES: usize = 512;
const MAX_REVOKE_EVIDENCE_TOTAL_BYTES: usize = 4 * 1024;
const MAX_CONFIRMATION_PROOF_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextPrincipalKind {
    ContextCompiler,
    GovernanceKernel,
    Founder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedContextPrincipal {
    pub kind: ContextPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

pub struct ContextAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: SqlCipherKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextSourceFact {
    pub source_ref: String,
    pub label: String,
    pub authority: String,
    pub content_sha256: String,
    pub included: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryPackBinding {
    pub scope_ref: String,
    pub authority_revision: u64,
    pub snapshot_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextRedaction {
    pub field_path: String,
    pub reason_code: String,
}

/// Input accepted only from the internal Context Compiler boundary.
/// `compiled_context` is the exact immutable byte sequence whose digest becomes
/// the snapshot identity; it is never reconstructed from the user intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueContextSnapshot {
    /// Authenticated session principal that is allowed to confirm this
    /// snapshot. The internal compiler principal remains the authority that
    /// persists it, but it must not erase the founder/session binding.
    pub owner_principal_id: String,
    pub intent: String,
    pub work_type: String,
    pub target_scope_ref: String,
    pub compiled_context: Vec<u8>,
    pub sources: Vec<ContextSourceFact>,
    pub memory_pack: Option<MemoryPackBinding>,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub external_resources: Vec<String>,
    pub non_goals: Vec<String>,
    pub acceptance_contract_ref: String,
    pub budget_profile_ref: String,
    pub deadline_seconds: Option<i64>,
    pub recovery_entry: String,
    pub visibility: String,
    pub redactions: Vec<ContextRedaction>,
    pub expires_at_seconds: i64,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextSnapshot {
    pub snapshot_id: String,
    pub revision: u64,
    pub owner_principal_id: String,
    pub intent: String,
    pub intent_sha256: String,
    pub work_type: String,
    pub target_scope_ref: String,
    pub compiled_context_sha256: String,
    pub sources: Vec<ContextSourceFact>,
    pub memory_pack: Option<MemoryPackBinding>,
    pub allowed_read_paths: Vec<String>,
    pub allowed_write_paths: Vec<String>,
    pub allowed_tools: Vec<String>,
    pub external_resources: Vec<String>,
    pub non_goals: Vec<String>,
    pub acceptance_contract_ref: String,
    pub budget_profile_ref: String,
    pub deadline_seconds: Option<i64>,
    pub recovery_entry: String,
    pub visibility: String,
    pub redactions: Vec<ContextRedaction>,
    pub expires_at_seconds: i64,
    pub confirmation_binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedContextSnapshot {
    pub snapshot: ContextSnapshot,
    pub compiled_context: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSnapshotReceipt {
    pub snapshot_id: String,
    pub revision: u64,
    pub event_id: String,
    pub request_digest_sha256: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRevokeRequest {
    pub command_id: String,
    pub snapshot_id: String,
    pub expected_state_revision: u64,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub confirmation_proof_ref: String,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextGovernanceState {
    Issued,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSnapshotGovernance {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub owner_principal_id: String,
    pub state: ContextGovernanceState,
    pub state_revision: u64,
    pub expires_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRevokeReceipt {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub previous_state_revision: u64,
    pub result_state_revision: u64,
    pub previous_state: ContextGovernanceState,
    pub result_state: ContextGovernanceState,
    pub request_digest_sha256: String,
    pub event_id: String,
    pub committed_at_seconds: i64,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContextConsumptionAuthorizationRequest {
    pub command_id: String,
    pub snapshot_id: String,
    pub expected_state_revision: u64,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub input_digest_sha256: String,
    pub expected_scope_ref: String,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContextConsumptionAuthorizationReceipt {
    pub authorization_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub observed_state_revision: u64,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub input_digest_sha256: String,
    pub expected_scope_ref: String,
    pub request_digest_sha256: String,
    pub event_id: String,
    pub committed_at_seconds: i64,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryContextPurpose {
    RecoveryOrReconciliation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryContextMaterialRequest {
    pub snapshot_id: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub input_digest_sha256: String,
    pub expected_scope_ref: String,
    pub evidence_ref: String,
    pub purpose: RecoveryContextPurpose,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryContextMaterial {
    pub snapshot: ContextSnapshot,
    pub compiled_context: Vec<u8>,
    pub observed_governance_state: ContextGovernanceState,
    pub observed_state_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryUseReceiptRequest {
    pub snapshot_id: String,
    pub expected_scope_ref: String,
    pub consumer_principal_id: String,
    pub model_ref: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub memory_authority_revision: u64,
    pub memory_pack_snapshot_sha256: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryUseReceipt {
    pub receipt_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub consumer_principal_id: String,
    pub model_ref: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub memory_authority_revision: u64,
    pub memory_pack_snapshot_sha256: String,
    pub request_digest_sha256: String,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextStoreInspection {
    pub snapshot_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub revoke_receipt_count: u64,
    pub revoke_idempotency_count: u64,
    pub dispatch_authorization_count: u64,
    pub dispatch_authorization_idempotency_count: u64,
    pub last_event_sequence: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ContextAuthorityFailure {
    #[error("context authority storage is unavailable")]
    Storage,
    #[error("context authority input is invalid: {0}")]
    InvalidArgument(&'static str),
    #[error("context authority principal is not authorized")]
    Unauthorized,
    #[error("context snapshot owner does not match the authenticated Founder")]
    OwnerMismatch,
    #[error("context snapshot was not found")]
    NotFound,
    #[error("context snapshot has expired")]
    Expired,
    #[error("context snapshot is revoked")]
    Revoked,
    #[error("context snapshot scope does not match the consumer")]
    ScopeMismatch,
    #[error("context snapshot content digest is invalid")]
    IntegrityFailure,
    #[error("context authority idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("context governance state revision does not match")]
    StateRevisionConflict,
    #[error("context dispatch authorization tuple conflicts with an existing grant")]
    AuthorizationTupleConflict,
    #[error("context authority clock is before the Unix epoch")]
    Clock,
}

impl From<store::StoreError> for ContextAuthorityFailure {
    fn from(value: store::StoreError) -> Self {
        match value {
            store::StoreError::NotFound => Self::NotFound,
            store::StoreError::OwnerMismatch => Self::OwnerMismatch,
            store::StoreError::Revoked => Self::Revoked,
            store::StoreError::Expired => Self::Expired,
            store::StoreError::ScopeMismatch => Self::ScopeMismatch,
            store::StoreError::StateRevisionConflict => Self::StateRevisionConflict,
            store::StoreError::IdempotencyConflict => Self::IdempotencyConflict,
            store::StoreError::AuthorizationTupleConflict => Self::AuthorizationTupleConflict,
            store::StoreError::IntegrityFailure | store::StoreError::DescriptorDecode => {
                Self::IntegrityFailure
            }
            store::StoreError::Sql(_)
            | store::StoreError::Migration(_)
            | store::StoreError::Directory(_)
            | store::StoreError::CipherUnavailable
            | store::StoreError::StoreGenerationMismatch => Self::Storage,
        }
    }
}

pub struct ContextAuthority {
    store: store::ContextStore,
}

impl ContextAuthority {
    pub fn open(config: ContextAuthorityConfig) -> Result<Self, ContextAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(ContextAuthorityFailure::InvalidArgument("store_epoch"));
        }
        Ok(Self {
            store: store::ContextStore::open(
                &config.database_path,
                config.key.expose(),
                &config.store_epoch,
            )?,
        })
    }

    pub fn revoke(
        &mut self,
        principal: &AuthenticatedContextPrincipal,
        request: &ContextRevokeRequest,
    ) -> Result<ContextRevokeReceipt, ContextAuthorityFailure> {
        validate_principal(principal)?;
        if principal.kind != ContextPrincipalKind::Founder {
            return Err(ContextAuthorityFailure::Unauthorized);
        }
        validate_revoke_request(request)?;
        let request_digest_sha256 = context_revoke_request_digest(&principal.principal_id, request);
        self.store
            .revoke(store::ContextRevokeCommit {
                snapshot_id: &request.snapshot_id,
                expected_state_revision: request.expected_state_revision,
                principal_id: &principal.principal_id,
                command_id: &request.command_id,
                idempotency_key: &request.idempotency_key,
                reason_code: &request.reason_code,
                evidence_refs: &request.evidence_refs,
                confirmation_proof_ref: &request.confirmation_proof_ref,
                correlation_id: &request.correlation_id,
                causation_id: request.causation_id.as_deref(),
                request_digest_sha256: &request_digest_sha256,
                event_id: &Uuid::now_v7().to_string(),
                committed_at_seconds: current_timestamp()?,
            })
            .map_err(Into::into)
    }

    /// Commits the Context decision for exactly one dispatch. This is the
    /// linearization point shared with revoke; it does not call Adapter or a
    /// native Harness.
    pub fn authorize_dispatch_consumption(
        &mut self,
        principal: &AuthenticatedContextPrincipal,
        request: &DispatchContextConsumptionAuthorizationRequest,
    ) -> Result<DispatchContextConsumptionAuthorizationReceipt, ContextAuthorityFailure> {
        validate_principal(principal)?;
        if principal.kind != ContextPrincipalKind::GovernanceKernel {
            return Err(ContextAuthorityFailure::Unauthorized);
        }
        validate_dispatch_authorization_request(request)?;
        let committed_at_seconds = current_timestamp()?;
        let request_digest_sha256 = dispatch_authorization_request_digest(request);
        self.store
            .authorize_dispatch_consumption(store::DispatchAuthorizationCommit {
                snapshot_id: &request.snapshot_id,
                expected_state_revision: request.expected_state_revision,
                principal_id: &principal.principal_id,
                command_id: &request.command_id,
                idempotency_key: &request.idempotency_key,
                attempt_id: &request.attempt_id,
                dispatch_id: &request.dispatch_id,
                input_digest_sha256: &request.input_digest_sha256,
                expected_scope_ref: &request.expected_scope_ref,
                correlation_id: &request.correlation_id,
                causation_id: &request.causation_id,
                request_digest_sha256: &request_digest_sha256,
                authorization_id: &format!("ctxauth:{}", Uuid::now_v7()),
                event_id: &Uuid::now_v7().to_string(),
                committed_at_seconds,
            })
            .map_err(Into::into)
    }

    /// Returns immutable material only for an already-authorized historical
    /// dispatch. The result type carries no dispatch authorization and has no
    /// conversion into the normal dispatch-material seam.
    pub fn resolve_for_recovery(
        &self,
        principal: &AuthenticatedContextPrincipal,
        request: &RecoveryContextMaterialRequest,
    ) -> Result<RecoveryContextMaterial, ContextAuthorityFailure> {
        validate_principal(principal)?;
        if principal.kind != ContextPrincipalKind::GovernanceKernel {
            return Err(ContextAuthorityFailure::Unauthorized);
        }
        validate_recovery_request(request)?;
        let stored = self
            .store
            .recovery_material(store::RecoveryLineageRequest {
                snapshot_id: &request.snapshot_id,
                attempt_id: &request.attempt_id,
                dispatch_id: &request.dispatch_id,
                input_digest_sha256: &request.input_digest_sha256,
                expected_scope_ref: &request.expected_scope_ref,
            })?;
        Ok(RecoveryContextMaterial {
            snapshot: stored.snapshot,
            compiled_context: stored.compiled_context,
            observed_governance_state: parse_governance_state(&stored.state)?,
            observed_state_revision: stored.state_revision,
        })
    }

    /// Revalidates a complete durable authorization without consulting the
    /// snapshot's current revoke/expiry state. That preserves the frozen
    /// authorization-first ordering while still rejecting receipt tampering.
    pub fn verify_dispatch_authorization(
        &self,
        principal: &AuthenticatedContextPrincipal,
        receipt: &DispatchContextConsumptionAuthorizationReceipt,
    ) -> Result<(), ContextAuthorityFailure> {
        validate_principal(principal)?;
        if principal.kind != ContextPrincipalKind::GovernanceKernel {
            return Err(ContextAuthorityFailure::Unauthorized);
        }
        self.store
            .verify_dispatch_authorization(receipt)
            .map_err(Into::into)
    }

    pub fn governance(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<ContextSnapshotGovernance>, ContextAuthorityFailure> {
        validate_snapshot_id(snapshot_id)?;
        self.store
            .snapshot_with_bytes(snapshot_id)?
            .map(|stored| {
                Ok(ContextSnapshotGovernance {
                    snapshot_id: stored.snapshot.snapshot_id,
                    snapshot_revision: stored.snapshot.revision,
                    content_digest_sha256: stored.snapshot.compiled_context_sha256,
                    owner_principal_id: stored.snapshot.owner_principal_id,
                    state: parse_governance_state(&stored.state)?,
                    state_revision: stored.state_revision,
                    expires_at_seconds: stored.snapshot.expires_at_seconds,
                })
            })
            .transpose()
    }

    /// Issues an immutable snapshot and returns a digest-bound receipt.
    pub fn issue(
        &mut self,
        input: &IssueContextSnapshot,
        principal: &AuthenticatedContextPrincipal,
    ) -> Result<(ContextSnapshotReceipt, ContextSnapshot), ContextAuthorityFailure> {
        validate_principal(principal)?;
        validate_input(input)?;
        if !matches!(
            principal.kind,
            ContextPrincipalKind::ContextCompiler | ContextPrincipalKind::GovernanceKernel
        ) {
            return Err(ContextAuthorityFailure::Unauthorized);
        }

        let compiled_context_sha256 = sha256(&input.compiled_context);
        let snapshot_id = format!("ctx:{compiled_context_sha256}");
        let snapshot = build_snapshot(input, &snapshot_id, &compiled_context_sha256)?;
        let request_digest = snapshot_digest(&snapshot);
        if let Some(existing) = self
            .store
            .idempotency_record(&principal.principal_id, &input.idempotency_key)?
        {
            if existing.request_digest_sha256 != request_digest {
                return Err(ContextAuthorityFailure::IdempotencyConflict);
            }
            let snapshot = self
                .store
                .snapshot(&existing.snapshot_id)?
                .ok_or(ContextAuthorityFailure::IntegrityFailure)?;
            return Ok((
                ContextSnapshotReceipt {
                    snapshot_id: existing.snapshot_id,
                    revision: existing.revision,
                    event_id: existing.event_id,
                    request_digest_sha256: request_digest,
                    replayed: true,
                },
                snapshot,
            ));
        }

        if let Some(existing) = self.store.snapshot_with_bytes(&snapshot_id)? {
            if existing.state == "revoked" {
                return Err(ContextAuthorityFailure::Revoked);
            }
            if snapshot_digest(&existing.snapshot) != request_digest
                || existing.snapshot.compiled_context_sha256 != compiled_context_sha256
            {
                return Err(ContextAuthorityFailure::IdempotencyConflict);
            }
            let (revision, event_id) = self
                .store
                .issue_record(&snapshot_id)?
                .ok_or(ContextAuthorityFailure::IntegrityFailure)?;
            self.store.bind_idempotency(
                &principal.principal_id,
                &input.idempotency_key,
                &request_digest,
                &snapshot_id,
                revision,
                &event_id,
            )?;
            return Ok((
                ContextSnapshotReceipt {
                    snapshot_id,
                    revision,
                    event_id,
                    request_digest_sha256: request_digest,
                    replayed: true,
                },
                existing.snapshot,
            ));
        }

        let event_id = Uuid::now_v7().to_string();
        let committed_at_seconds = current_timestamp()?;
        self.store.insert(store::ContextInsert {
            snapshot: &snapshot,
            compiled_context: &input.compiled_context,
            event_id: &event_id,
            principal_id: &principal.principal_id,
            idempotency_key: &input.idempotency_key,
            request_digest_sha256: &request_digest,
            committed_at_seconds,
        })?;
        Ok((
            ContextSnapshotReceipt {
                snapshot_id,
                revision: 1,
                event_id,
                request_digest_sha256: request_digest,
                replayed: false,
            },
            snapshot,
        ))
    }

    /// Resolves only an unrevoked, unexpired snapshot with a matching scope.
    /// The stored bytes are rehashed at the consumption boundary.
    pub fn resolve(
        &self,
        snapshot_id: &str,
        expected_scope_ref: &str,
        now_seconds: i64,
    ) -> Result<ResolvedContextSnapshot, ContextAuthorityFailure> {
        validate_routing(snapshot_id, "snapshot_id")?;
        validate_routing(expected_scope_ref, "scope_ref")?;
        if now_seconds < 0 {
            return Err(ContextAuthorityFailure::Clock);
        }
        let stored = self
            .store
            .snapshot_with_bytes(snapshot_id)?
            .ok_or(ContextAuthorityFailure::NotFound)?;
        if stored.snapshot.target_scope_ref != expected_scope_ref {
            return Err(ContextAuthorityFailure::ScopeMismatch);
        }
        if stored.state == "revoked" {
            return Err(ContextAuthorityFailure::Revoked);
        }
        if stored.snapshot.expires_at_seconds <= now_seconds {
            return Err(ContextAuthorityFailure::Expired);
        }
        if sha256(&stored.compiled_context) != stored.snapshot.compiled_context_sha256
            || !stored.snapshot.snapshot_id.starts_with("ctx:")
            || stored.snapshot.snapshot_id
                != format!("ctx:{}", stored.snapshot.compiled_context_sha256)
        {
            return Err(ContextAuthorityFailure::IntegrityFailure);
        }
        Ok(ResolvedContextSnapshot {
            snapshot: stored.snapshot,
            compiled_context: stored.compiled_context,
        })
    }

    /// Revalidates an immutable snapshot at a dispatch-consumption boundary.
    /// Scope was already bound to the Task activation and cannot be changed
    /// for this content-addressed snapshot; this method repeats the state,
    /// expiry and byte-integrity checks without a new client contract.
    pub fn resolve_for_consumption(
        &self,
        snapshot_id: &str,
        now_seconds: i64,
    ) -> Result<ResolvedContextSnapshot, ContextAuthorityFailure> {
        validate_routing(snapshot_id, "snapshot_id")?;
        if now_seconds < 0 {
            return Err(ContextAuthorityFailure::Clock);
        }
        let stored = self
            .store
            .snapshot_with_bytes(snapshot_id)?
            .ok_or(ContextAuthorityFailure::NotFound)?;
        if stored.state == "revoked" {
            return Err(ContextAuthorityFailure::Revoked);
        }
        if stored.snapshot.expires_at_seconds <= now_seconds {
            return Err(ContextAuthorityFailure::Expired);
        }
        if sha256(&stored.compiled_context) != stored.snapshot.compiled_context_sha256
            || stored.snapshot.snapshot_id
                != format!("ctx:{}", stored.snapshot.compiled_context_sha256)
        {
            return Err(ContextAuthorityFailure::IntegrityFailure);
        }
        Ok(ResolvedContextSnapshot {
            snapshot: stored.snapshot,
            compiled_context: stored.compiled_context,
        })
    }

    /// Records the immutable Memory revision consumed by one model dispatch.
    /// The daemon must obtain the revision and pack digest from Memory
    /// Authority before calling this method; this owner only records and
    /// revalidates the ContextSnapshot binding.
    pub fn record_memory_use(
        &mut self,
        input: &MemoryUseReceiptRequest,
        principal: &AuthenticatedContextPrincipal,
        now_seconds: i64,
    ) -> Result<MemoryUseReceipt, ContextAuthorityFailure> {
        validate_principal(principal)?;
        if principal.kind != ContextPrincipalKind::GovernanceKernel {
            return Err(ContextAuthorityFailure::Unauthorized);
        }
        validate_routing(&input.consumer_principal_id, "consumer_principal_id")?;
        validate_routing(&input.model_ref, "model_ref")?;
        validate_routing(&input.attempt_id, "attempt_id")?;
        validate_routing(&input.dispatch_id, "dispatch_id")?;
        validate_routing(&input.idempotency_key, "idempotency_key")?;
        validate_digest(
            &input.memory_pack_snapshot_sha256,
            "memory_pack_snapshot_sha256",
        )?;
        if input.memory_authority_revision == 0 {
            return Err(ContextAuthorityFailure::InvalidArgument(
                "memory_authority_revision",
            ));
        }
        let resolved = self.resolve(&input.snapshot_id, &input.expected_scope_ref, now_seconds)?;
        let memory_pack = resolved
            .snapshot
            .memory_pack
            .as_ref()
            .ok_or(ContextAuthorityFailure::InvalidArgument("memory_pack"))?;
        if memory_pack.scope_ref != input.expected_scope_ref
            || memory_pack.authority_revision != input.memory_authority_revision
            || memory_pack.snapshot_sha256 != input.memory_pack_snapshot_sha256
        {
            return Err(ContextAuthorityFailure::IntegrityFailure);
        }

        let request_digest = memory_use_digest(input, &resolved.snapshot);
        if let Some(existing) = self
            .store
            .memory_use_idempotency_record(&principal.principal_id, &input.idempotency_key)?
        {
            if existing.0 != request_digest {
                return Err(ContextAuthorityFailure::IdempotencyConflict);
            }
            let receipt = self
                .store
                .memory_use_receipt(&existing.1)?
                .ok_or(ContextAuthorityFailure::IntegrityFailure)?;
            return Ok(MemoryUseReceipt {
                request_digest_sha256: request_digest,
                replayed: true,
                ..receipt
            });
        }

        let receipt_id = format!(
            "memory-use:{}",
            sha256(
                format!(
                    "{}\n{}\n{}\n{}",
                    input.snapshot_id, input.model_ref, input.attempt_id, input.dispatch_id
                )
                .as_bytes()
            )
        );
        if let Some(existing) = self.store.memory_use_receipt_by_tuple(
            &input.snapshot_id,
            &input.model_ref,
            &input.attempt_id,
            &input.dispatch_id,
        )? {
            self.store.bind_memory_use_idempotency(
                &principal.principal_id,
                &input.idempotency_key,
                &request_digest,
                &existing.receipt_id,
            )?;
            return Ok(MemoryUseReceipt {
                request_digest_sha256: request_digest,
                replayed: true,
                ..existing
            });
        }

        let receipt = MemoryUseReceipt {
            receipt_id,
            snapshot_id: resolved.snapshot.snapshot_id.clone(),
            snapshot_revision: resolved.snapshot.revision,
            consumer_principal_id: input.consumer_principal_id.clone(),
            model_ref: input.model_ref.clone(),
            attempt_id: input.attempt_id.clone(),
            dispatch_id: input.dispatch_id.clone(),
            memory_authority_revision: input.memory_authority_revision,
            memory_pack_snapshot_sha256: input.memory_pack_snapshot_sha256.clone(),
            request_digest_sha256: request_digest.clone(),
            replayed: false,
        };
        self.store.insert_memory_use_receipt(
            &receipt,
            &principal.principal_id,
            &input.idempotency_key,
            now_seconds,
        )?;
        Ok(receipt)
    }

    pub fn get(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<ContextSnapshot>, ContextAuthorityFailure> {
        validate_routing(snapshot_id, "snapshot_id")?;
        self.store.snapshot(snapshot_id).map_err(Into::into)
    }

    pub fn inspect_store(&self) -> Result<ContextStoreInspection, ContextAuthorityFailure> {
        self.store.inspect().map_err(Into::into)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, ContextAuthorityFailure> {
        self.store.integrity_is_ok().map_err(Into::into)
    }
}

fn build_snapshot(
    input: &IssueContextSnapshot,
    snapshot_id: &str,
    compiled_context_sha256: &str,
) -> Result<ContextSnapshot, ContextAuthorityFailure> {
    let intent_sha256 = sha256(input.intent.as_bytes());
    let source_and_gate_digest = source_ledger_digest(&input.sources, &input.recovery_entry);
    let confirmation_binding_sha256 = confirmation_digest(&ConfirmationDigestInput {
        snapshot_id,
        intent_sha256: &intent_sha256,
        work_type: &input.work_type,
        target_scope_ref: &input.target_scope_ref,
        acceptance_contract_ref: &input.acceptance_contract_ref,
        budget_profile_ref: &input.budget_profile_ref,
        compiled_context_sha256,
        source_and_gate_digest: &source_and_gate_digest,
        owner_principal_id: &input.owner_principal_id,
        expires_at_seconds: input.expires_at_seconds,
    });
    Ok(ContextSnapshot {
        snapshot_id: snapshot_id.to_owned(),
        revision: 1,
        owner_principal_id: input.owner_principal_id.clone(),
        intent: input.intent.clone(),
        intent_sha256,
        work_type: input.work_type.clone(),
        target_scope_ref: input.target_scope_ref.clone(),
        compiled_context_sha256: compiled_context_sha256.to_owned(),
        sources: input.sources.clone(),
        memory_pack: input.memory_pack.clone(),
        allowed_read_paths: input.allowed_read_paths.clone(),
        allowed_write_paths: input.allowed_write_paths.clone(),
        allowed_tools: input.allowed_tools.clone(),
        external_resources: input.external_resources.clone(),
        non_goals: input.non_goals.clone(),
        acceptance_contract_ref: input.acceptance_contract_ref.clone(),
        budget_profile_ref: input.budget_profile_ref.clone(),
        deadline_seconds: input.deadline_seconds,
        recovery_entry: input.recovery_entry.clone(),
        visibility: input.visibility.clone(),
        redactions: input.redactions.clone(),
        expires_at_seconds: input.expires_at_seconds,
        confirmation_binding_sha256,
    })
}

fn validate_principal(
    principal: &AuthenticatedContextPrincipal,
) -> Result<(), ContextAuthorityFailure> {
    if !principal.authenticated {
        return Err(ContextAuthorityFailure::Unauthorized);
    }
    validate_routing(&principal.principal_id, "principal_id")?;
    Ok(())
}

fn validate_revoke_request(request: &ContextRevokeRequest) -> Result<(), ContextAuthorityFailure> {
    validate_snapshot_id(&request.snapshot_id)?;
    if request.expected_state_revision == 0 {
        return Err(ContextAuthorityFailure::InvalidArgument(
            "expected_state_revision",
        ));
    }
    validate_routing(&request.command_id, "command_id")?;
    validate_routing(&request.idempotency_key, "idempotency_key")?;
    validate_routing(&request.correlation_id, "correlation_id")?;
    if let Some(value) = &request.causation_id {
        validate_routing(value, "causation_id")?;
    }
    validate_opaque_reference(&request.reason_code, "reason_code", MAX_REVOKE_REASON_BYTES)?;
    if request.evidence_refs.is_empty() || request.evidence_refs.len() > MAX_REVOKE_EVIDENCE_ITEMS {
        return Err(ContextAuthorityFailure::InvalidArgument("evidence_refs"));
    }
    let mut total_bytes = 0usize;
    for value in &request.evidence_refs {
        validate_opaque_reference(value, "evidence_ref", MAX_REVOKE_EVIDENCE_BYTES)?;
        total_bytes = total_bytes
            .checked_add(value.len())
            .ok_or(ContextAuthorityFailure::InvalidArgument("evidence_refs"))?;
    }
    if total_bytes > MAX_REVOKE_EVIDENCE_TOTAL_BYTES {
        return Err(ContextAuthorityFailure::InvalidArgument("evidence_refs"));
    }
    validate_opaque_reference(
        &request.confirmation_proof_ref,
        "confirmation_proof_ref",
        MAX_CONFIRMATION_PROOF_BYTES,
    )
}

fn validate_dispatch_authorization_request(
    request: &DispatchContextConsumptionAuthorizationRequest,
) -> Result<(), ContextAuthorityFailure> {
    validate_snapshot_id(&request.snapshot_id)?;
    if request.expected_state_revision == 0 {
        return Err(ContextAuthorityFailure::InvalidArgument(
            "expected_state_revision",
        ));
    }
    for (field, value) in [
        ("command_id", &request.command_id),
        ("attempt_id", &request.attempt_id),
        ("dispatch_id", &request.dispatch_id),
        ("expected_scope_ref", &request.expected_scope_ref),
        ("idempotency_key", &request.idempotency_key),
        ("correlation_id", &request.correlation_id),
        ("causation_id", &request.causation_id),
    ] {
        validate_routing(value, field)?;
    }
    validate_canonical_digest(&request.input_digest_sha256, "input_digest_sha256")
}

fn validate_recovery_request(
    request: &RecoveryContextMaterialRequest,
) -> Result<(), ContextAuthorityFailure> {
    validate_snapshot_id(&request.snapshot_id)?;
    for (field, value) in [
        ("attempt_id", &request.attempt_id),
        ("dispatch_id", &request.dispatch_id),
        ("expected_scope_ref", &request.expected_scope_ref),
    ] {
        validate_routing(value, field)?;
    }
    validate_canonical_digest(&request.input_digest_sha256, "input_digest_sha256")?;
    validate_opaque_reference(
        &request.evidence_ref,
        "recovery_evidence_ref",
        MAX_REVOKE_EVIDENCE_BYTES,
    )
}

fn validate_snapshot_id(value: &str) -> Result<(), ContextAuthorityFailure> {
    let Some(digest) = value.strip_prefix("ctx:") else {
        return Err(ContextAuthorityFailure::InvalidArgument("snapshot_id"));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContextAuthorityFailure::InvalidArgument("snapshot_id"));
    }
    Ok(())
}

fn validate_opaque_reference(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ContextAuthorityFailure> {
    if value.is_empty()
        || value.len() > max_bytes
        || value != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(ContextAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn parse_governance_state(value: &str) -> Result<ContextGovernanceState, ContextAuthorityFailure> {
    match value {
        "issued" => Ok(ContextGovernanceState::Issued),
        "revoked" => Ok(ContextGovernanceState::Revoked),
        _ => Err(ContextAuthorityFailure::IntegrityFailure),
    }
}

pub fn context_revoke_request_digest(
    founder_principal_id: &str,
    request: &ContextRevokeRequest,
) -> String {
    egopulse_domain_contracts::context_revoke::ContextRevokeSemanticRequest {
        founder_principal_id,
        snapshot_id: &request.snapshot_id,
        expected_state_revision: request.expected_state_revision,
        reason_code: &request.reason_code,
        evidence_refs: &request.evidence_refs,
        confirmation_proof_ref: &request.confirmation_proof_ref,
    }
    .digest_sha256()
}

pub fn dispatch_authorization_request_digest(
    request: &DispatchContextConsumptionAuthorizationRequest,
) -> String {
    dispatch_authorization_semantic_digest(
        &request.snapshot_id,
        request.expected_state_revision,
        &request.attempt_id,
        &request.dispatch_id,
        &request.input_digest_sha256,
        &request.expected_scope_ref,
    )
}

fn dispatch_authorization_semantic_digest(
    snapshot_id: &str,
    expected_state_revision: u64,
    attempt_id: &str,
    dispatch_id: &str,
    input_digest_sha256: &str,
    expected_scope_ref: &str,
) -> String {
    let mut hasher = Sha256::new();
    update_digest_field(
        &mut hasher,
        b"egopulse/context-dispatch-consumption-authorization/v1",
    );
    update_digest_field(&mut hasher, snapshot_id.as_bytes());
    update_digest_field(&mut hasher, &expected_state_revision.to_le_bytes());
    update_digest_field(&mut hasher, attempt_id.as_bytes());
    update_digest_field(&mut hasher, dispatch_id.as_bytes());
    update_digest_field(&mut hasher, input_digest_sha256.as_bytes());
    update_digest_field(&mut hasher, expected_scope_ref.as_bytes());
    hex::encode(hasher.finalize())
}

fn update_digest_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn validate_input(input: &IssueContextSnapshot) -> Result<(), ContextAuthorityFailure> {
    let now = current_timestamp()?;
    validate_routing(&input.owner_principal_id, "owner_principal_id")?;
    validate_text(&input.intent, "intent", MAX_CONTEXT_BYTES)?;
    validate_routing(&input.work_type, "work_type")?;
    validate_routing(&input.target_scope_ref, "target_scope_ref")?;
    validate_routing(&input.acceptance_contract_ref, "acceptance_contract_ref")?;
    validate_routing(&input.budget_profile_ref, "budget_profile_ref")?;
    validate_routing(&input.recovery_entry, "recovery_entry")?;
    validate_routing(&input.visibility, "visibility")?;
    validate_routing(&input.idempotency_key, "idempotency_key")?;
    for source in &input.sources {
        validate_routing(&source.source_ref, "source_ref")?;
        validate_routing(&source.label, "source_label")?;
        validate_routing(&source.authority, "source_authority")?;
        validate_digest(&source.content_sha256, "source_content_sha256")?;
    }
    if let Some(memory_pack) = &input.memory_pack {
        validate_routing(&memory_pack.scope_ref, "memory_pack_scope_ref")?;
        if memory_pack.authority_revision == 0 {
            return Err(ContextAuthorityFailure::InvalidArgument(
                "memory_pack_authority_revision",
            ));
        }
        validate_digest(&memory_pack.snapshot_sha256, "memory_pack_snapshot_sha256")?;
    }
    if input.compiled_context.is_empty() || input.compiled_context.len() > MAX_CONTEXT_BYTES {
        return Err(ContextAuthorityFailure::InvalidArgument("compiled_context"));
    }
    if input.expires_at_seconds <= now {
        return Err(ContextAuthorityFailure::InvalidArgument(
            "expires_at_seconds",
        ));
    }
    if input
        .deadline_seconds
        .is_some_and(|deadline| deadline <= now)
    {
        return Err(ContextAuthorityFailure::InvalidArgument("deadline_seconds"));
    }
    for (name, values) in [
        ("sources", input.sources.len()),
        ("allowed_read_paths", input.allowed_read_paths.len()),
        ("allowed_write_paths", input.allowed_write_paths.len()),
        ("allowed_tools", input.allowed_tools.len()),
        ("external_resources", input.external_resources.len()),
        ("non_goals", input.non_goals.len()),
        ("redactions", input.redactions.len()),
    ] {
        if values > MAX_LIST_ITEMS {
            return Err(ContextAuthorityFailure::InvalidArgument(name));
        }
    }
    for (name, values) in [
        ("allowed_read_paths", &input.allowed_read_paths),
        ("allowed_write_paths", &input.allowed_write_paths),
        ("allowed_tools", &input.allowed_tools),
        ("external_resources", &input.external_resources),
        ("non_goals", &input.non_goals),
    ] {
        for value in values {
            validate_routing(value, name)?;
        }
    }
    for redaction in &input.redactions {
        validate_routing(&redaction.field_path, "redaction_field_path")?;
        validate_routing(&redaction.reason_code, "redaction_reason_code")?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ContextAuthorityFailure> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ContextAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn validate_routing(value: &str, field: &'static str) -> Result<(), ContextAuthorityFailure> {
    validate_text(value, field, MAX_ROUTING_BYTES)
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ContextAuthorityFailure> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ContextAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn validate_canonical_digest(
    value: &str,
    field: &'static str,
) -> Result<(), ContextAuthorityFailure> {
    validate_digest(value, field)?;
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ContextAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn snapshot_digest(snapshot: &ContextSnapshot) -> String {
    let descriptor = serde_json::to_vec(snapshot).expect("ContextSnapshot must be serializable");
    sha256(&descriptor)
}

fn memory_use_digest(input: &MemoryUseReceiptRequest, snapshot: &ContextSnapshot) -> String {
    let descriptor = serde_json::json!({
        "snapshot": snapshot,
        "consumer_principal_id": input.consumer_principal_id,
        "model_ref": input.model_ref,
        "attempt_id": input.attempt_id,
        "dispatch_id": input.dispatch_id,
        "memory_authority_revision": input.memory_authority_revision,
        "memory_pack_snapshot_sha256": input.memory_pack_snapshot_sha256,
    });
    sha256(&serde_json::to_vec(&descriptor).expect("Memory use descriptor is serializable"))
}

struct ConfirmationDigestInput<'a> {
    snapshot_id: &'a str,
    intent_sha256: &'a str,
    work_type: &'a str,
    target_scope_ref: &'a str,
    acceptance_contract_ref: &'a str,
    budget_profile_ref: &'a str,
    compiled_context_sha256: &'a str,
    source_and_gate_digest: &'a str,
    owner_principal_id: &'a str,
    expires_at_seconds: i64,
}

fn confirmation_digest(input: &ConfirmationDigestInput<'_>) -> String {
    let expires_at_seconds = input.expires_at_seconds.to_string();
    let values = [
        input.snapshot_id,
        input.intent_sha256,
        input.work_type,
        input.target_scope_ref,
        input.acceptance_contract_ref,
        input.budget_profile_ref,
        input.compiled_context_sha256,
        input.source_and_gate_digest,
        input.owner_principal_id,
        &expires_at_seconds,
    ];
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn source_ledger_digest(sources: &[ContextSourceFact], recovery_entry: &str) -> String {
    let descriptor = serde_json::json!({
        "sources": sources,
        "gateRecoveryEntry": recovery_entry,
    });
    sha256(&serde_json::to_vec(&descriptor).expect("source ledger is serializable"))
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn current_timestamp() -> Result<i64, ContextAuthorityFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| ContextAuthorityFailure::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::Duration;

    fn authority() -> ContextAuthority {
        let root = std::env::temp_dir().join(format!("egopulse-context-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("context test root");
        ContextAuthority::open(ContextAuthorityConfig {
            database_path: root.join("context.sqlcipher"),
            store_epoch: "context-test-epoch".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        })
        .expect("context authority")
    }

    fn input(idempotency_key: &str) -> IssueContextSnapshot {
        IssueContextSnapshot {
            owner_principal_id: "founder:test".to_owned(),
            intent: "inspect the local repository".to_owned(),
            work_type: "governed_repository_change".to_owned(),
            target_scope_ref: "scope:repo".to_owned(),
            compiled_context: br#"{"prompt":"inspect","scope":"scope:repo"}"#.to_vec(),
            sources: vec![ContextSourceFact {
                source_ref: "docs/ARCHITECTURE.md".to_owned(),
                label: "architecture".to_owned(),
                authority: "project".to_owned(),
                content_sha256: "a".repeat(64),
                included: true,
            }],
            memory_pack: Some(MemoryPackBinding {
                scope_ref: "scope:repo".to_owned(),
                authority_revision: 3,
                snapshot_sha256: "b".repeat(64),
            }),
            allowed_read_paths: vec!["docs".to_owned()],
            allowed_write_paths: vec!["src".to_owned()],
            allowed_tools: vec!["git".to_owned()],
            external_resources: Vec::new(),
            non_goals: vec!["no release".to_owned()],
            acceptance_contract_ref: "acceptance:v1".to_owned(),
            budget_profile_ref: "budget:v1".to_owned(),
            deadline_seconds: None,
            recovery_entry: "hold-and-reconcile".to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: vec![ContextRedaction {
                field_path: "credentials".to_owned(),
                reason_code: "secret".to_owned(),
            }],
            expires_at_seconds: current_timestamp().expect("clock") + 600,
            idempotency_key: idempotency_key.to_owned(),
        }
    }

    fn compiler() -> AuthenticatedContextPrincipal {
        AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::ContextCompiler,
            principal_id: "context-compiler".to_owned(),
            authenticated: true,
        }
    }

    fn governance_kernel() -> AuthenticatedContextPrincipal {
        AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::GovernanceKernel,
            principal_id: "governance-kernel".to_owned(),
            authenticated: true,
        }
    }

    fn founder(principal_id: &str) -> AuthenticatedContextPrincipal {
        AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::Founder,
            principal_id: principal_id.to_owned(),
            authenticated: true,
        }
    }

    fn test_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("egopulse-context-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("context test root");
        root
    }

    fn authority_at(root: &Path, store_epoch: &str) -> ContextAuthority {
        ContextAuthority::open(ContextAuthorityConfig {
            database_path: root.join("context.sqlcipher"),
            store_epoch: store_epoch.to_owned(),
            key: SqlCipherKey::new([41; 32]),
        })
        .expect("context authority")
    }

    fn revoke_request(
        snapshot_id: &str,
        expected_state_revision: u64,
        idempotency_key: &str,
    ) -> ContextRevokeRequest {
        ContextRevokeRequest {
            command_id: format!("command:{idempotency_key}"),
            snapshot_id: snapshot_id.to_owned(),
            expected_state_revision,
            reason_code: "founder-requested-revoke".to_owned(),
            evidence_refs: vec!["evidence:r9a-test".to_owned()],
            confirmation_proof_ref: "confirmation:r9a-test".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: format!("correlation:{idempotency_key}"),
            causation_id: Some(format!("causation:{idempotency_key}")),
        }
    }

    fn authorization_request(
        snapshot_id: &str,
        attempt_id: &str,
        dispatch_id: &str,
        idempotency_key: &str,
    ) -> DispatchContextConsumptionAuthorizationRequest {
        DispatchContextConsumptionAuthorizationRequest {
            command_id: format!("command:{idempotency_key}"),
            snapshot_id: snapshot_id.to_owned(),
            expected_state_revision: 1,
            attempt_id: attempt_id.to_owned(),
            dispatch_id: dispatch_id.to_owned(),
            input_digest_sha256: "d".repeat(64),
            expected_scope_ref: "scope:repo".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: format!("correlation:{idempotency_key}"),
            causation_id: format!("causation:{idempotency_key}"),
        }
    }

    fn recovery_request(
        request: &DispatchContextConsumptionAuthorizationRequest,
    ) -> RecoveryContextMaterialRequest {
        RecoveryContextMaterialRequest {
            snapshot_id: request.snapshot_id.clone(),
            attempt_id: request.attempt_id.clone(),
            dispatch_id: request.dispatch_id.clone(),
            input_digest_sha256: request.input_digest_sha256.clone(),
            expected_scope_ref: request.expected_scope_ref.clone(),
            evidence_ref: "recovery:r9a-test".to_owned(),
            purpose: RecoveryContextPurpose::RecoveryOrReconciliation,
        }
    }

    fn assert_revoke_replay_matches_original(
        original: &ContextRevokeReceipt,
        replay: &ContextRevokeReceipt,
    ) {
        let mut expected = original.clone();
        expected.replayed = true;
        assert_eq!(replay, &expected);
    }

    fn assert_authorization_replay_matches_original(
        original: &DispatchContextConsumptionAuthorizationReceipt,
        replay: &DispatchContextConsumptionAuthorizationReceipt,
    ) {
        let mut expected = original.clone();
        expected.replayed = true;
        assert_eq!(replay, &expected);
    }

    fn force_writer_order(
        first: &mut ContextAuthority,
        first_operation: store::TestWriteOperation,
        second: &mut ContextAuthority,
        second_operation: store::TestWriteOperation,
    ) {
        let competition_open = Arc::new(Barrier::new(2));
        let busy_observed = Arc::new(Barrier::new(2));
        let first_competition_open = Arc::clone(&competition_open);
        let first_busy_observed = Arc::clone(&busy_observed);
        first
            .store
            .set_test_write_hook(Arc::new(move |operation, phase| {
                if operation == first_operation
                    && phase == store::TestWritePhase::AfterBeginImmediate
                {
                    first_competition_open.wait();
                    first_busy_observed.wait();
                }
            }))
            .expect("install first-writer test hook");
        let second_busy_seen = Arc::new(AtomicBool::new(false));
        second
            .store
            .set_test_write_hook(Arc::new(move |operation, phase| {
                if operation != second_operation {
                    return;
                }
                if phase == store::TestWritePhase::BeforeBeginImmediate {
                    competition_open.wait();
                } else if phase == store::TestWritePhase::Busy
                    && !second_busy_seen.swap(true, Ordering::SeqCst)
                {
                    busy_observed.wait();
                }
            }))
            .expect("install second-writer test hook");
    }

    fn assert_invalid_revoke_without_writes(
        authority: &mut ContextAuthority,
        request: &ContextRevokeRequest,
        expected_failure: ContextAuthorityFailure,
        expected_governance: &ContextSnapshotGovernance,
        expected_inspection: ContextStoreInspection,
    ) {
        assert_eq!(
            authority.revoke(&founder("founder:test"), request),
            Err(expected_failure)
        );
        assert_eq!(
            authority
                .governance(&request.snapshot_id)
                .expect("governance after rejected revoke")
                .expect("snapshot governance"),
            *expected_governance
        );
        assert_eq!(
            authority.inspect_store().expect("inspection after failure"),
            expected_inspection
        );
    }

    #[test]
    fn r9a_revoke_exact_replay_survives_restart_and_changed_semantics_conflicts() {
        let root = test_root("r9a-revoke-replay");
        let store_epoch = "r9a-revoke-replay-epoch";
        let mut authority = authority_at(&root, store_epoch);
        let (_, snapshot) = authority
            .issue(&input("r9a-revoke-replay-issue"), &compiler())
            .expect("issue snapshot");
        let immutable_snapshot = authority
            .get(&snapshot.snapshot_id)
            .expect("read immutable snapshot")
            .expect("snapshot exists");
        let issued = authority
            .governance(&snapshot.snapshot_id)
            .expect("read issued governance")
            .expect("issued governance");
        assert_eq!(issued.state, ContextGovernanceState::Issued);
        assert_eq!(issued.state_revision, 1);
        let issued_inspection = authority.inspect_store().expect("issued inspection");

        let unauthenticated_request =
            revoke_request(&snapshot.snapshot_id, 1, "r9a-revoke-unauthenticated");
        let mut unauthenticated_founder = founder("founder:test");
        unauthenticated_founder.authenticated = false;
        assert_eq!(
            authority.revoke(&unauthenticated_founder, &unauthenticated_request),
            Err(ContextAuthorityFailure::Unauthorized)
        );
        assert_eq!(
            authority.revoke(&compiler(), &unauthenticated_request),
            Err(ContextAuthorityFailure::Unauthorized)
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after unauthorized revoke"),
            issued_inspection
        );

        let owner_mismatch = revoke_request(&snapshot.snapshot_id, 1, "r9a-revoke-owner");
        assert_eq!(
            authority.revoke(&founder("founder:other"), &owner_mismatch),
            Err(ContextAuthorityFailure::OwnerMismatch)
        );
        assert_eq!(
            authority
                .governance(&snapshot.snapshot_id)
                .expect("governance after owner mismatch")
                .expect("snapshot governance"),
            issued
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after owner mismatch"),
            issued_inspection
        );

        let stale = revoke_request(&snapshot.snapshot_id, 2, "r9a-revoke-stale");
        assert_eq!(
            authority.revoke(&founder("founder:test"), &stale),
            Err(ContextAuthorityFailure::StateRevisionConflict)
        );
        assert_eq!(
            authority
                .governance(&snapshot.snapshot_id)
                .expect("governance after stale CAS")
                .expect("snapshot governance"),
            issued
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after stale CAS"),
            issued_inspection
        );

        let request = revoke_request(&snapshot.snapshot_id, 1, "r9a-revoke-replay");
        let original = authority
            .revoke(&founder("founder:test"), &request)
            .expect("commit revoke");
        assert!(!original.replayed);
        assert_eq!(original.snapshot_revision, snapshot.revision);
        assert_eq!(
            original.content_digest_sha256,
            snapshot.compiled_context_sha256
        );
        assert_eq!(original.previous_state_revision, 1);
        assert_eq!(original.result_state_revision, 2);
        assert_eq!(original.previous_state, ContextGovernanceState::Issued);
        assert_eq!(original.result_state, ContextGovernanceState::Revoked);
        let revoked = authority
            .governance(&snapshot.snapshot_id)
            .expect("read revoked governance")
            .expect("revoked governance");
        assert_eq!(revoked.state, ContextGovernanceState::Revoked);
        assert_eq!(revoked.state_revision, 2);
        assert_eq!(
            authority
                .get(&snapshot.snapshot_id)
                .expect("read after revoke")
                .expect("snapshot after revoke"),
            immutable_snapshot
        );
        let committed_inspection = authority.inspect_store().expect("committed inspection");
        assert_eq!(
            committed_inspection.event_count,
            issued_inspection.event_count + 1
        );
        assert_eq!(committed_inspection.revoke_receipt_count, 1);
        assert_eq!(committed_inspection.revoke_idempotency_count, 1);
        assert_eq!(committed_inspection.dispatch_authorization_count, 0);
        assert_eq!(
            committed_inspection.dispatch_authorization_idempotency_count,
            0
        );

        drop(authority);
        let mut reopened = authority_at(&root, store_epoch);
        let replay = reopened
            .revoke(&founder("founder:test"), &request)
            .expect("replay revoke after restart");
        assert_revoke_replay_matches_original(&original, &replay);
        assert_eq!(
            reopened
                .inspect_store()
                .expect("inspection after exact replay"),
            committed_inspection
        );
        assert_eq!(
            reopened
                .governance(&snapshot.snapshot_id)
                .expect("governance after replay")
                .expect("snapshot governance"),
            revoked
        );

        let mut changed_semantics = request.clone();
        changed_semantics.reason_code = "different-governance-reason".to_owned();
        assert_eq!(
            reopened.revoke(&founder("founder:test"), &changed_semantics),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );
        assert_eq!(
            reopened
                .inspect_store()
                .expect("inspection after idempotency conflict"),
            committed_inspection
        );
        assert_eq!(
            reopened
                .get(&snapshot.snapshot_id)
                .expect("read immutable snapshot after restart")
                .expect("snapshot after restart"),
            immutable_snapshot
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove revoke replay root");
    }

    #[test]
    fn r9a_expired_issued_snapshot_can_be_revoked() {
        let root = test_root("r9a-expired-revoke");
        let mut authority = authority_at(&root, "r9a-expired-revoke-epoch");
        let mut expiring = input("r9a-expired-revoke-issue");
        expiring.expires_at_seconds = current_timestamp().expect("clock") + 2;
        let (_, snapshot) = authority
            .issue(&expiring, &compiler())
            .expect("issue expiring snapshot");
        while current_timestamp().expect("clock") < snapshot.expires_at_seconds {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            authority.resolve_for_consumption(&snapshot.snapshot_id, snapshot.expires_at_seconds),
            Err(ContextAuthorityFailure::Expired)
        );
        let expired_inspection = authority.inspect_store().expect("expired inspection");
        let expired_authorization = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-expired",
            "dispatch:r9a-expired",
            "r9a-expired-authorization",
        );
        assert_eq!(
            authority.authorize_dispatch_consumption(&governance_kernel(), &expired_authorization),
            Err(ContextAuthorityFailure::Expired)
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after expired authorization"),
            expired_inspection
        );
        let immutable_snapshot = authority
            .get(&snapshot.snapshot_id)
            .expect("read expired snapshot")
            .expect("expired snapshot exists");
        let receipt = authority
            .revoke(
                &founder("founder:test"),
                &revoke_request(&snapshot.snapshot_id, 1, "r9a-expired-revoke"),
            )
            .expect("revoke expired issued snapshot");
        assert_eq!(receipt.previous_state, ContextGovernanceState::Issued);
        assert_eq!(receipt.result_state, ContextGovernanceState::Revoked);
        let governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read expired revoked governance")
            .expect("snapshot governance");
        assert_eq!(governance.state, ContextGovernanceState::Revoked);
        assert_eq!(governance.state_revision, 2);
        assert_eq!(governance.expires_at_seconds, snapshot.expires_at_seconds);
        assert_eq!(
            authority
                .get(&snapshot.snapshot_id)
                .expect("read immutable revoked snapshot")
                .expect("revoked snapshot exists"),
            immutable_snapshot
        );
        drop(authority);
        fs::remove_dir_all(root).expect("remove expired revoke root");
    }

    #[test]
    fn r9a_authorization_first_survives_revoke_and_recovery_is_read_only() {
        let root = test_root("r9a-authorization-first");
        let store_epoch = "r9a-authorization-first-epoch";
        let mut authority = authority_at(&root, store_epoch);
        let (_, snapshot) = authority
            .issue(&input("r9a-authorization-first-issue"), &compiler())
            .expect("issue snapshot");
        let request = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-authorization-first",
            "dispatch:r9a-authorization-first",
            "r9a-authorization-first",
        );
        let authorization = authority
            .authorize_dispatch_consumption(&governance_kernel(), &request)
            .expect("authorize dispatch consumption");
        assert!(!authorization.replayed);
        assert_eq!(authorization.observed_state_revision, 1);
        let revoke = authority
            .revoke(
                &founder("founder:test"),
                &revoke_request(&snapshot.snapshot_id, 1, "r9a-authorization-first-revoke"),
            )
            .expect("revoke after authorization");
        assert_eq!(revoke.result_state_revision, 2);
        let revoked_governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read revoked governance")
            .expect("snapshot governance");
        let stable_inspection = authority.inspect_store().expect("stable inspection");
        assert_eq!(stable_inspection.dispatch_authorization_count, 1);
        assert_eq!(
            stable_inspection.dispatch_authorization_idempotency_count,
            1
        );
        assert_eq!(stable_inspection.revoke_receipt_count, 1);

        drop(authority);
        let mut reopened = authority_at(&root, store_epoch);
        let replay = reopened
            .authorize_dispatch_consumption(&governance_kernel(), &request)
            .expect("replay authorization after revoke and restart");
        assert_authorization_replay_matches_original(&authorization, &replay);
        reopened
            .verify_dispatch_authorization(&governance_kernel(), &authorization)
            .expect("verify original authorization after revoke");
        reopened
            .verify_dispatch_authorization(&governance_kernel(), &replay)
            .expect("verify replayed authorization after revoke");
        let recovery = recovery_request(&request);
        let first_material = reopened
            .resolve_for_recovery(&governance_kernel(), &recovery)
            .expect("recover authorized material after revoke");
        assert_eq!(first_material.snapshot, snapshot);
        assert_eq!(
            first_material.compiled_context,
            input("unused").compiled_context
        );
        assert_eq!(
            first_material.observed_governance_state,
            ContextGovernanceState::Revoked
        );
        assert_eq!(first_material.observed_state_revision, 2);
        let second_material = reopened
            .resolve_for_recovery(&governance_kernel(), &recovery)
            .expect("replay recovery read");
        assert_eq!(second_material, first_material);
        assert_eq!(
            reopened
                .inspect_store()
                .expect("inspection after replay and recovery reads"),
            stable_inspection
        );
        assert_eq!(
            reopened
                .governance(&snapshot.snapshot_id)
                .expect("governance after recovery reads")
                .expect("snapshot governance"),
            revoked_governance
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove authorization-first root");
    }

    #[test]
    fn r9a_revoke_first_blocks_authorization_with_zero_writes() {
        let root = test_root("r9a-revoke-first");
        let mut authority = authority_at(&root, "r9a-revoke-first-epoch");
        let (_, snapshot) = authority
            .issue(&input("r9a-revoke-first-issue"), &compiler())
            .expect("issue snapshot");
        authority
            .revoke(
                &founder("founder:test"),
                &revoke_request(&snapshot.snapshot_id, 1, "r9a-revoke-first"),
            )
            .expect("revoke before authorization");
        let revoked_governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read revoked governance")
            .expect("snapshot governance");
        let stable_inspection = authority.inspect_store().expect("inspection after revoke");
        let request = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-revoke-first",
            "dispatch:r9a-revoke-first",
            "r9a-revoke-first-authorization",
        );
        assert_eq!(
            authority.authorize_dispatch_consumption(&governance_kernel(), &request),
            Err(ContextAuthorityFailure::Revoked)
        );
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &recovery_request(&request)),
            Err(ContextAuthorityFailure::NotFound)
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after rejection"),
            stable_inspection
        );
        assert_eq!(stable_inspection.dispatch_authorization_count, 0);
        assert_eq!(
            stable_inspection.dispatch_authorization_idempotency_count,
            0
        );
        assert_eq!(
            authority
                .governance(&snapshot.snapshot_id)
                .expect("governance after rejection")
                .expect("snapshot governance"),
            revoked_governance
        );
        drop(authority);
        fs::remove_dir_all(root).expect("remove revoke-first root");
    }

    #[test]
    fn r9a_two_connections_deterministically_linearize_authorization_first() {
        let root = test_root("r9a-concurrent-authorization-first");
        let store_epoch = "r9a-concurrent-authorization-first-epoch";
        let mut issuer = authority_at(&root, store_epoch);
        let (_, snapshot) = issuer
            .issue(
                &input("r9a-concurrent-authorization-first-issue"),
                &compiler(),
            )
            .expect("issue snapshot");
        drop(issuer);

        let request = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-concurrent-authorization-first",
            "dispatch:r9a-concurrent-authorization-first",
            "r9a-concurrent-authorization-first",
        );
        let revoke = revoke_request(
            &snapshot.snapshot_id,
            1,
            "r9a-concurrent-authorization-first-revoke",
        );
        let mut authorization_authority = authority_at(&root, store_epoch);
        let mut revoke_authority = authority_at(&root, store_epoch);
        force_writer_order(
            &mut authorization_authority,
            store::TestWriteOperation::AuthorizeDispatchConsumption,
            &mut revoke_authority,
            store::TestWriteOperation::Revoke,
        );

        let concurrent_request = request.clone();
        let authorization = thread::spawn(move || {
            authorization_authority
                .authorize_dispatch_consumption(&governance_kernel(), &concurrent_request)
        });
        let concurrent_revoke = revoke.clone();
        let revocation = thread::spawn(move || {
            revoke_authority.revoke(&founder("founder:test"), &concurrent_revoke)
        });

        let authorization = authorization
            .join()
            .expect("authorization thread")
            .expect("authorization wins write lock");
        let revocation = revocation
            .join()
            .expect("revoke thread")
            .expect("revoke follows committed authorization");
        assert_eq!(authorization.observed_state_revision, 1);
        assert_eq!(revocation.previous_state_revision, 1);
        assert_eq!(revocation.result_state_revision, 2);

        let mut reopened = authority_at(&root, store_epoch);
        let stable_inspection = reopened.inspect_store().expect("concurrent inspection");
        assert_eq!(
            stable_inspection,
            ContextStoreInspection {
                snapshot_count: 1,
                event_count: 3,
                idempotency_count: 1,
                revoke_receipt_count: 1,
                revoke_idempotency_count: 1,
                dispatch_authorization_count: 1,
                dispatch_authorization_idempotency_count: 1,
                last_event_sequence: 3,
            }
        );
        let replay = reopened
            .authorize_dispatch_consumption(&governance_kernel(), &request)
            .expect("authorization replay after revoke and restart");
        assert_authorization_replay_matches_original(&authorization, &replay);
        let revoke_replay = reopened
            .revoke(&founder("founder:test"), &revoke)
            .expect("revoke replay after authorization and restart");
        assert_revoke_replay_matches_original(&revocation, &revoke_replay);
        reopened
            .verify_dispatch_authorization(&governance_kernel(), &authorization)
            .expect("original authorization remains verifiable");
        let recovery = reopened
            .resolve_for_recovery(&governance_kernel(), &recovery_request(&request))
            .expect("authorized recovery after revoke and restart");
        assert_eq!(recovery.snapshot, snapshot);
        assert_eq!(recovery.compiled_context, input("unused").compiled_context);
        assert_eq!(
            recovery.observed_governance_state,
            ContextGovernanceState::Revoked
        );
        assert_eq!(recovery.observed_state_revision, 2);
        assert_eq!(
            reopened
                .inspect_store()
                .expect("inspection after replay and recovery"),
            stable_inspection
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove concurrent authorization-first root");
    }

    #[test]
    fn r9a_two_connections_deterministically_linearize_revoke_first() {
        let root = test_root("r9a-concurrent-revoke-first");
        let store_epoch = "r9a-concurrent-revoke-first-epoch";
        let mut issuer = authority_at(&root, store_epoch);
        let (_, snapshot) = issuer
            .issue(&input("r9a-concurrent-revoke-first-issue"), &compiler())
            .expect("issue snapshot");
        drop(issuer);

        let request = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-concurrent-revoke-first",
            "dispatch:r9a-concurrent-revoke-first",
            "r9a-concurrent-revoke-first",
        );
        let revoke = revoke_request(
            &snapshot.snapshot_id,
            1,
            "r9a-concurrent-revoke-first-revoke",
        );
        let mut revoke_authority = authority_at(&root, store_epoch);
        let mut authorization_authority = authority_at(&root, store_epoch);
        force_writer_order(
            &mut revoke_authority,
            store::TestWriteOperation::Revoke,
            &mut authorization_authority,
            store::TestWriteOperation::AuthorizeDispatchConsumption,
        );

        let concurrent_revoke = revoke.clone();
        let revocation = thread::spawn(move || {
            revoke_authority.revoke(&founder("founder:test"), &concurrent_revoke)
        });
        let concurrent_request = request.clone();
        let authorization = thread::spawn(move || {
            authorization_authority
                .authorize_dispatch_consumption(&governance_kernel(), &concurrent_request)
        });

        let revocation = revocation
            .join()
            .expect("revoke thread")
            .expect("revoke wins write lock");
        assert_eq!(
            authorization.join().expect("authorization thread"),
            Err(ContextAuthorityFailure::Revoked)
        );

        let mut reopened = authority_at(&root, store_epoch);
        let stable_inspection = reopened.inspect_store().expect("concurrent inspection");
        assert_eq!(
            stable_inspection,
            ContextStoreInspection {
                snapshot_count: 1,
                event_count: 2,
                idempotency_count: 1,
                revoke_receipt_count: 1,
                revoke_idempotency_count: 1,
                dispatch_authorization_count: 0,
                dispatch_authorization_idempotency_count: 0,
                last_event_sequence: 2,
            }
        );
        let replay = reopened
            .revoke(&founder("founder:test"), &revoke)
            .expect("revoke replay after restart");
        assert_revoke_replay_matches_original(&revocation, &replay);
        assert_eq!(
            reopened.authorize_dispatch_consumption(&governance_kernel(), &request),
            Err(ContextAuthorityFailure::Revoked)
        );
        assert_eq!(
            reopened.resolve_for_recovery(&governance_kernel(), &recovery_request(&request)),
            Err(ContextAuthorityFailure::NotFound)
        );
        assert_eq!(
            reopened
                .inspect_store()
                .expect("inspection after rejected authorization and recovery"),
            stable_inspection
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("remove concurrent revoke-first root");
    }

    #[test]
    fn r9a_authorization_and_recovery_tuple_tamper_fail_closed() {
        let root = test_root("r9a-tuple-tamper");
        let mut authority = authority_at(&root, "r9a-tuple-tamper-epoch");
        let (_, snapshot) = authority
            .issue(&input("r9a-tuple-tamper-issue"), &compiler())
            .expect("issue snapshot");
        let request = authorization_request(
            &snapshot.snapshot_id,
            "attempt:r9a-tuple",
            "dispatch:r9a-tuple",
            "r9a-tuple-authorization",
        );
        let authorization = authority
            .authorize_dispatch_consumption(&governance_kernel(), &request)
            .expect("authorize dispatch consumption");
        authority
            .verify_dispatch_authorization(&governance_kernel(), &authorization)
            .expect("verify exact authorization");
        let stable_inspection = authority.inspect_store().expect("stable inspection");
        let stable_governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read governance")
            .expect("snapshot governance");

        assert_eq!(
            authority.verify_dispatch_authorization(&founder("founder:test"), &authorization),
            Err(ContextAuthorityFailure::Unauthorized)
        );
        assert_eq!(
            authority.resolve_for_recovery(&founder("founder:test"), &recovery_request(&request)),
            Err(ContextAuthorityFailure::Unauthorized)
        );

        let mut same_key_changed_input = request.clone();
        same_key_changed_input.input_digest_sha256 = "e".repeat(64);
        assert_eq!(
            authority.authorize_dispatch_consumption(&governance_kernel(), &same_key_changed_input),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );
        let mut same_dispatch_changed_tuple = request.clone();
        same_dispatch_changed_tuple.idempotency_key = "r9a-tuple-new-key".to_owned();
        same_dispatch_changed_tuple.attempt_id = "attempt:r9a-tuple-other".to_owned();
        assert_eq!(
            authority
                .authorize_dispatch_consumption(&governance_kernel(), &same_dispatch_changed_tuple),
            Err(ContextAuthorityFailure::AuthorizationTupleConflict)
        );

        let mut missing_authorization = authorization.clone();
        missing_authorization.authorization_id = format!("ctxauth:{}", Uuid::now_v7());
        assert_eq!(
            authority.verify_dispatch_authorization(&governance_kernel(), &missing_authorization),
            Err(ContextAuthorityFailure::NotFound)
        );
        let mut tampered_receipts = Vec::new();
        let mut tampered = authorization.clone();
        tampered.snapshot_id = format!("ctx:{}", "0".repeat(64));
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.snapshot_revision += 1;
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.observed_state_revision += 1;
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.attempt_id.push_str(":tampered");
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.dispatch_id.push_str(":tampered");
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.input_digest_sha256 = "f".repeat(64);
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.expected_scope_ref.push_str(":tampered");
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.request_digest_sha256 = "0".repeat(64);
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.event_id = Uuid::now_v7().to_string();
        tampered_receipts.push(tampered);
        let mut tampered = authorization.clone();
        tampered.committed_at_seconds += 1;
        tampered_receipts.push(tampered);
        for tampered in tampered_receipts {
            assert_eq!(
                authority.verify_dispatch_authorization(&governance_kernel(), &tampered),
                Err(ContextAuthorityFailure::AuthorizationTupleConflict)
            );
        }

        let recovery = recovery_request(&request);
        authority
            .resolve_for_recovery(&governance_kernel(), &recovery)
            .expect("resolve exact recovery tuple");
        let mut tampered = recovery.clone();
        tampered.snapshot_id = format!("ctx:{}", "0".repeat(64));
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &tampered),
            Err(ContextAuthorityFailure::AuthorizationTupleConflict)
        );
        let mut tampered = recovery.clone();
        tampered.attempt_id.push_str(":tampered");
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &tampered),
            Err(ContextAuthorityFailure::AuthorizationTupleConflict)
        );
        let mut tampered = recovery.clone();
        tampered.dispatch_id.push_str(":tampered");
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &tampered),
            Err(ContextAuthorityFailure::NotFound)
        );
        let mut tampered = recovery.clone();
        tampered.input_digest_sha256 = "f".repeat(64);
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &tampered),
            Err(ContextAuthorityFailure::AuthorizationTupleConflict)
        );
        let mut tampered = recovery.clone();
        tampered.expected_scope_ref.push_str(":tampered");
        assert_eq!(
            authority.resolve_for_recovery(&governance_kernel(), &tampered),
            Err(ContextAuthorityFailure::AuthorizationTupleConflict)
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection after tuple tamper"),
            stable_inspection
        );
        assert_eq!(
            authority
                .governance(&snapshot.snapshot_id)
                .expect("governance after tuple tamper")
                .expect("snapshot governance"),
            stable_governance
        );
        drop(authority);
        fs::remove_dir_all(root).expect("remove tuple tamper root");
    }

    #[test]
    fn r9a_revoke_reference_bounds_and_empty_padded_or_control_values_fail_closed() {
        let root = test_root("r9a-revoke-validation");
        let mut authority = authority_at(&root, "r9a-revoke-validation-epoch");
        let (_, snapshot) = authority
            .issue(&input("r9a-revoke-validation-issue"), &compiler())
            .expect("issue snapshot");
        let governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read governance")
            .expect("snapshot governance");
        let inspection = authority.inspect_store().expect("baseline inspection");
        let base = revoke_request(&snapshot.snapshot_id, 1, "r9a-revoke-validation");
        let mut cases = Vec::new();

        let mut request = base.clone();
        request.reason_code.clear();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("reason_code"),
        ));
        let mut request = base.clone();
        request.reason_code = " padded".to_owned();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("reason_code"),
        ));
        let mut request = base.clone();
        request.reason_code = "control\u{0007}".to_owned();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("reason_code"),
        ));
        let mut request = base.clone();
        request.reason_code = "r".repeat(MAX_REVOKE_REASON_BYTES + 1);
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("reason_code"),
        ));

        let mut request = base.clone();
        request.evidence_refs.clear();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_refs"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec![String::new()];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_ref"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec!["padded ".to_owned()];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_ref"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec!["control\nvalue".to_owned()];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_ref"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec!["e".repeat(MAX_REVOKE_EVIDENCE_BYTES + 1)];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_ref"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec!["evidence".to_owned(); MAX_REVOKE_EVIDENCE_ITEMS + 1];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_refs"),
        ));
        let mut request = base.clone();
        request.evidence_refs = vec!["e".repeat(MAX_REVOKE_EVIDENCE_BYTES); 9];
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("evidence_refs"),
        ));

        let mut request = base.clone();
        request.confirmation_proof_ref.clear();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("confirmation_proof_ref"),
        ));
        let mut request = base.clone();
        request.confirmation_proof_ref = " padded".to_owned();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("confirmation_proof_ref"),
        ));
        let mut request = base.clone();
        request.confirmation_proof_ref = "control\rvalue".to_owned();
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("confirmation_proof_ref"),
        ));
        let mut request = base.clone();
        request.confirmation_proof_ref = "p".repeat(MAX_CONFIRMATION_PROOF_BYTES + 1);
        cases.push((
            request,
            ContextAuthorityFailure::InvalidArgument("confirmation_proof_ref"),
        ));

        for (request, expected_failure) in cases {
            assert_invalid_revoke_without_writes(
                &mut authority,
                &request,
                expected_failure,
                &governance,
                inspection,
            );
        }

        let mut boundary = base;
        boundary.reason_code = "r".repeat(MAX_REVOKE_REASON_BYTES);
        boundary.evidence_refs = vec![
            "e".repeat(MAX_REVOKE_EVIDENCE_BYTES);
            MAX_REVOKE_EVIDENCE_TOTAL_BYTES / MAX_REVOKE_EVIDENCE_BYTES
        ];
        boundary.confirmation_proof_ref = "p".repeat(MAX_CONFIRMATION_PROOF_BYTES);
        authority
            .revoke(&founder("founder:test"), &boundary)
            .expect("accept exact opaque-reference bounds");
        let final_inspection = authority.inspect_store().expect("final inspection");
        assert_eq!(final_inspection.event_count, inspection.event_count + 1);
        assert_eq!(final_inspection.revoke_receipt_count, 1);
        assert_eq!(final_inspection.revoke_idempotency_count, 1);
        drop(authority);
        fs::remove_dir_all(root).expect("remove revoke validation root");
    }

    #[test]
    fn issue_is_content_addressed_and_replays_by_idempotency() {
        let mut authority = authority();
        let (first_receipt, first) = authority
            .issue(&input("idem-1"), &compiler())
            .expect("issue");
        let (replay_receipt, replay) = authority
            .issue(&input("idem-1"), &compiler())
            .expect("replay");
        let (dedupe_receipt, dedupe) = authority
            .issue(&input("idem-1b"), &compiler())
            .expect("dedupe");
        assert!(!first_receipt.replayed);
        assert!(replay_receipt.replayed);
        assert!(dedupe_receipt.replayed);
        assert_eq!(
            first.snapshot_id,
            format!("ctx:{}", first.compiled_context_sha256)
        );
        assert_eq!(first, replay);
        assert_eq!(first, dedupe);
        assert_eq!(first_receipt.snapshot_id, replay_receipt.snapshot_id);
        assert_eq!(first_receipt.event_id, dedupe_receipt.event_id);
    }

    #[test]
    fn resolve_rechecks_digest_scope_and_expiry() {
        let mut authority = authority();
        let (_, snapshot) = authority
            .issue(&input("idem-2"), &compiler())
            .expect("issue");
        let resolved = authority
            .resolve(
                &snapshot.snapshot_id,
                "scope:repo",
                current_timestamp().expect("clock"),
            )
            .expect("resolve");
        assert_eq!(
            resolved.compiled_context,
            br#"{"prompt":"inspect","scope":"scope:repo"}"#
        );
        assert_eq!(
            authority
                .resolve_for_consumption(&snapshot.snapshot_id, current_timestamp().expect("clock"))
                .expect("dispatch consumption resolve")
                .compiled_context,
            resolved.compiled_context
        );
        assert_eq!(
            authority.resolve(
                &snapshot.snapshot_id,
                "scope:other",
                current_timestamp().expect("clock")
            ),
            Err(ContextAuthorityFailure::ScopeMismatch)
        );
        assert_eq!(
            authority.resolve(
                &snapshot.snapshot_id,
                "scope:repo",
                snapshot.expires_at_seconds
            ),
            Err(ContextAuthorityFailure::Expired)
        );
        assert_eq!(
            authority.resolve_for_consumption(&snapshot.snapshot_id, snapshot.expires_at_seconds),
            Err(ContextAuthorityFailure::Expired)
        );
    }

    #[test]
    fn dispatch_consumption_fails_closed_when_stored_snapshot_is_revoked() {
        let root =
            std::env::temp_dir().join(format!("egopulse-context-revoked-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("context test root");
        let database_path = root.join("context.sqlcipher");
        let key = [41; 32];
        let mut authority = ContextAuthority::open(ContextAuthorityConfig {
            database_path: database_path.clone(),
            store_epoch: "context-revoked-test".to_owned(),
            key: SqlCipherKey::new(key),
        })
        .expect("context authority");
        let (_, snapshot) = authority
            .issue(&input("revoked-dispatch"), &compiler())
            .expect("issue");
        drop(authority);

        let connection = rusqlite::Connection::open(&database_path).expect("open context store");
        connection
            .pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
            .expect("apply context store key");
        connection
            .execute(
                "UPDATE context_snapshots SET state = 'revoked' WHERE snapshot_id = ?1",
                [&snapshot.snapshot_id],
            )
            .expect("simulate an already-governed revoked snapshot");
        drop(connection);

        let authority = ContextAuthority::open(ContextAuthorityConfig {
            database_path: database_path.clone(),
            store_epoch: "context-revoked-test".to_owned(),
            key: SqlCipherKey::new(key),
        })
        .expect("reopen context authority");
        assert_eq!(
            authority.resolve_for_consumption(
                &snapshot.snapshot_id,
                current_timestamp().expect("clock")
            ),
            Err(ContextAuthorityFailure::Revoked)
        );
        drop(authority);

        let connection = rusqlite::Connection::open(&database_path).expect("reopen context store");
        connection
            .pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
            .expect("apply context store key");
        connection
            .execute(
                "UPDATE context_snapshots SET state = 'issued', compiled_context = ?1 WHERE snapshot_id = ?2",
                rusqlite::params![b"tampered".as_slice(), &snapshot.snapshot_id],
            )
            .expect("simulate corrupted stored bytes");
        drop(connection);
        let authority = ContextAuthority::open(ContextAuthorityConfig {
            database_path,
            store_epoch: "context-revoked-test".to_owned(),
            key: SqlCipherKey::new(key),
        })
        .expect("reopen corrupted context authority");
        assert_eq!(
            authority.resolve_for_consumption(
                &snapshot.snapshot_id,
                current_timestamp().expect("clock")
            ),
            Err(ContextAuthorityFailure::IntegrityFailure)
        );
        drop(authority);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn altered_request_and_unauthenticated_principal_fail_closed() {
        let mut authority = authority();
        let mut altered = input("idem-3");
        altered.intent.push_str(" altered");
        authority
            .issue(&input("idem-3"), &compiler())
            .expect("issue");
        assert_eq!(
            authority.issue(&altered, &compiler()),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );
        let mut principal = compiler();
        principal.authenticated = false;
        assert_eq!(
            authority.issue(&input("idem-4"), &principal),
            Err(ContextAuthorityFailure::Unauthorized)
        );
    }

    #[test]
    fn invalid_source_and_memory_digests_fail_before_persistence() {
        let mut authority = authority();
        let mut invalid_source = input("invalid-source");
        invalid_source.sources[0].content_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            authority.issue(&invalid_source, &compiler()),
            Err(ContextAuthorityFailure::InvalidArgument(
                "source_content_sha256"
            ))
        );

        let mut invalid_memory = input("invalid-memory");
        invalid_memory
            .memory_pack
            .as_mut()
            .expect("memory pack")
            .authority_revision = 0;
        assert_eq!(
            authority.issue(&invalid_memory, &compiler()),
            Err(ContextAuthorityFailure::InvalidArgument(
                "memory_pack_authority_revision"
            ))
        );
        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection")
                .snapshot_count,
            0
        );
    }

    #[test]
    fn authority_reopens_across_restart_with_persistence_and_replay() {
        let root = std::env::temp_dir().join(format!("egopulse-context-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("context restart test root");
        let database_path = root.join("context.sqlcipher");
        let config = || ContextAuthorityConfig {
            database_path: database_path.clone(),
            store_epoch: "context-restart-epoch".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        };

        let snapshot_id;
        let first_event_id;
        {
            let mut authority = ContextAuthority::open(config()).expect("open before restart");
            let (receipt, snapshot) = authority
                .issue(&input("restart-1"), &compiler())
                .expect("issue");
            assert!(!receipt.replayed);
            snapshot_id = snapshot.snapshot_id.clone();
            first_event_id = receipt.event_id;
        }

        // Simulate a daemon restart: the same database is reopened and every
        // durability property must hold — snapshot persistence, resolvable
        // material, idempotent replay and content dedupe.
        let mut reopened = ContextAuthority::open(config()).expect("reopen after restart");
        let persisted = reopened
            .get(&snapshot_id)
            .expect("read persisted snapshot")
            .expect("snapshot survived restart");
        assert_eq!(persisted.snapshot_id, snapshot_id);
        assert!(reopened.integrity_is_ok().expect("integrity after reopen"));
        let resolved = reopened
            .resolve(
                &snapshot_id,
                "scope:repo",
                current_timestamp().expect("clock"),
            )
            .expect("resolve after restart");
        assert_eq!(resolved.snapshot.snapshot_id, snapshot_id);

        let (replay_receipt, replayed) = reopened
            .issue(&input("restart-1"), &compiler())
            .expect("idempotent replay after restart");
        assert!(replay_receipt.replayed);
        assert_eq!(replay_receipt.event_id, first_event_id);
        assert_eq!(replayed.snapshot_id, snapshot_id);

        let (dedupe_receipt, deduped) = reopened
            .issue(&input("restart-1b"), &compiler())
            .expect("content dedupe after restart");
        assert!(dedupe_receipt.replayed);
        assert_eq!(deduped.snapshot_id, snapshot_id);
        assert_eq!(
            reopened.inspect_store().expect("inspection").snapshot_count,
            1,
            "restart replay must not create a second snapshot"
        );
        drop(reopened);

        if root.exists() {
            fs::remove_dir_all(&root).expect("remove context restart test root");
        }
    }

    #[test]
    fn same_content_with_changed_descriptor_fails_closed_without_second_snapshot() {
        let mut authority = authority();
        let (_, first) = authority
            .issue(&input("descriptor-1"), &compiler())
            .expect("issue baseline");

        // Identical compiled bytes, different governance descriptor: the
        // content-addressed identity collides and the owner must fail closed
        // instead of mutating or aliasing the existing snapshot.
        let mut changed_visibility = input("descriptor-2");
        changed_visibility.visibility = "execution-only".to_owned();
        assert_eq!(
            authority.issue(&changed_visibility, &compiler()),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );

        let mut changed_expiry = input("descriptor-3");
        changed_expiry.expires_at_seconds += 3_600;
        assert_eq!(
            authority.issue(&changed_expiry, &compiler()),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );

        let mut changed_permissions = input("descriptor-4");
        changed_permissions.allowed_write_paths.clear();
        assert_eq!(
            authority.issue(&changed_permissions, &compiler()),
            Err(ContextAuthorityFailure::IdempotencyConflict)
        );

        assert_eq!(
            authority
                .inspect_store()
                .expect("inspection")
                .snapshot_count,
            1,
            "a changed descriptor must never create or mutate a snapshot"
        );
        let unchanged = authority
            .get(&first.snapshot_id)
            .expect("read baseline")
            .expect("baseline snapshot");
        assert_eq!(unchanged.visibility, first.visibility);
        assert_eq!(unchanged.expires_at_seconds, first.expires_at_seconds);
        assert_eq!(
            unchanged.allowed_write_paths, first.allowed_write_paths,
            "the original governance fields remain immutable"
        );
    }

    #[test]
    fn memory_use_receipt_is_bound_per_model_and_replays_idempotently() {
        let mut authority = authority();
        let (_, snapshot) = authority
            .issue(&input("memory-use-context"), &compiler())
            .expect("issue");
        let memory_pack = snapshot.memory_pack.as_ref().expect("memory pack");
        let request = MemoryUseReceiptRequest {
            snapshot_id: snapshot.snapshot_id.clone(),
            expected_scope_ref: "scope:repo".to_owned(),
            consumer_principal_id: "model:gpt".to_owned(),
            model_ref: "gpt:model-1".to_owned(),
            attempt_id: "attempt-1".to_owned(),
            dispatch_id: "dispatch-1".to_owned(),
            memory_authority_revision: memory_pack.authority_revision,
            memory_pack_snapshot_sha256: memory_pack.snapshot_sha256.clone(),
            idempotency_key: "memory-use-1".to_owned(),
        };
        let first = authority
            .record_memory_use(
                &request,
                &governance_kernel(),
                current_timestamp().expect("clock"),
            )
            .expect("record memory use");
        assert!(!first.replayed);
        assert_eq!(first.snapshot_id, snapshot.snapshot_id);
        assert_eq!(first.model_ref, "gpt:model-1");

        let replay = authority
            .record_memory_use(
                &request,
                &governance_kernel(),
                current_timestamp().expect("clock"),
            )
            .expect("replay memory use");
        assert!(replay.replayed);
        assert_eq!(replay.receipt_id, first.receipt_id);
        assert_eq!(replay.request_digest_sha256, first.request_digest_sha256);

        let mut another_model = request.clone();
        another_model.model_ref = "deepseek:model-1".to_owned();
        another_model.idempotency_key = "memory-use-2".to_owned();
        let second = authority
            .record_memory_use(
                &another_model,
                &governance_kernel(),
                current_timestamp().expect("clock"),
            )
            .expect("record second model use");
        assert!(!second.replayed);
        assert_ne!(second.receipt_id, first.receipt_id);
    }

    #[test]
    fn memory_use_revision_or_principal_mismatch_fails_closed() {
        let mut authority = authority();
        let (_, snapshot) = authority
            .issue(&input("memory-use-invalid"), &compiler())
            .expect("issue");
        let memory_pack = snapshot.memory_pack.as_ref().expect("memory pack");
        let mut request = MemoryUseReceiptRequest {
            snapshot_id: snapshot.snapshot_id.clone(),
            expected_scope_ref: "scope:repo".to_owned(),
            consumer_principal_id: "model:gpt".to_owned(),
            model_ref: "gpt:model-1".to_owned(),
            attempt_id: "attempt-2".to_owned(),
            dispatch_id: "dispatch-2".to_owned(),
            memory_authority_revision: memory_pack.authority_revision + 1,
            memory_pack_snapshot_sha256: memory_pack.snapshot_sha256.clone(),
            idempotency_key: "memory-use-invalid-1".to_owned(),
        };
        assert_eq!(
            authority.record_memory_use(
                &request,
                &governance_kernel(),
                current_timestamp().expect("clock")
            ),
            Err(ContextAuthorityFailure::IntegrityFailure)
        );
        request.memory_authority_revision = memory_pack.authority_revision;
        assert_eq!(
            authority.record_memory_use(&request, &compiler(), current_timestamp().expect("clock")),
            Err(ContextAuthorityFailure::Unauthorized)
        );
    }
}
