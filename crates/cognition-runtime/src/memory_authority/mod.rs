//! C-09 Memory single-writer and governance boundary.
//!
//! Agents, models and harnesses may submit candidate memories, but they can
//! never choose an authoritative state. Founder-controlled decisions promote
//! candidates, while revocation is an explicit terminal governance action.
//! Retrieval receives accepted snapshots only; the Python worker has no
//! database handle and no mutation capability.

mod store;

use crate::task_authority::SqlCipherKey;
use egopulse_domain_contracts::memory::{
    MEMORY_MAX_ROUTING_FIELD_BYTES, MEMORY_MAX_TOTAL_CONTENT_BYTES,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use store::{MemoryStore, StoreError, StoredMemory, StoredState, TransitionCommit};

pub const MEMORY_AUTHORITY_REF: &str = "egopulse/memory-authority/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryState {
    Candidate,
    Accepted,
    Revoked,
}

impl MemoryState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: StoredState) -> Result<Self, MemoryAuthorityFailure> {
        match value.as_str() {
            "candidate" => Ok(Self::Candidate),
            "accepted" => Ok(Self::Accepted),
            "revoked" => Ok(Self::Revoked),
            _ => Err(MemoryAuthorityFailure::Storage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryPrincipalKind {
    Founder,
    FounderAuthority,
    Agent,
    Model,
    Harness,
    GovernanceKernel,
    RecoveryCoordinator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedMemoryPrincipal {
    pub kind: MemoryPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

pub struct MemoryAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: SqlCipherKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitMemoryCandidate {
    pub memory_id: String,
    pub content: String,
    pub source_ref: String,
    pub scope_ref: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernMemory {
    pub memory_id: String,
    pub expected_revision: u64,
    pub evidence_ref: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRecord {
    pub memory_id: String,
    pub revision: u64,
    pub content: String,
    pub content_sha256: String,
    pub source_ref: String,
    pub scope_ref: String,
    pub state: MemoryState,
    pub created_at_seconds: i64,
    pub updated_at_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryMutationReceipt {
    pub memory_id: String,
    pub revision: u64,
    pub state: MemoryState,
    pub event_id: String,
    pub request_digest_sha256: String,
    pub acknowledged_after_durability_barrier: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedMemorySnapshot {
    pub scope_ref: String,
    pub records: Vec<MemoryRecord>,
    pub snapshot_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryStoreInspection {
    pub memory_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
    pub last_event_sequence: u64,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MemoryAuthorityFailure {
    #[error("memory authority storage is unavailable")]
    Storage,
    #[error("memory authority input is invalid: {0}")]
    InvalidArgument(&'static str),
    #[error("memory authority principal is not authorized")]
    Unauthorized,
    #[error("memory authority memory was not found")]
    NotFound,
    #[error("memory authority state transition conflicts with the current state")]
    StateConflict,
    #[error("memory authority idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("memory authority clock is before the Unix epoch")]
    Clock,
}

impl From<StoreError> for MemoryAuthorityFailure {
    fn from(_: StoreError) -> Self {
        Self::Storage
    }
}

pub struct MemoryAuthority {
    store: MemoryStore,
}

impl MemoryAuthority {
    pub fn open(config: MemoryAuthorityConfig) -> Result<Self, MemoryAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(MemoryAuthorityFailure::InvalidArgument("store_epoch"));
        }
        Ok(Self {
            store: MemoryStore::open(
                &config.database_path,
                config.key.expose(),
                &config.store_epoch,
            )?,
        })
    }

    /// Accepts an agent/model/harness proposal as a candidate only.
    pub fn submit_candidate(
        &mut self,
        command: &SubmitMemoryCandidate,
        principal: &AuthenticatedMemoryPrincipal,
    ) -> Result<MemoryMutationReceipt, MemoryAuthorityFailure> {
        validate_principal(principal)?;
        if !matches!(
            principal.kind,
            MemoryPrincipalKind::Founder
                | MemoryPrincipalKind::FounderAuthority
                | MemoryPrincipalKind::Agent
                | MemoryPrincipalKind::Model
                | MemoryPrincipalKind::Harness
        ) {
            return Err(MemoryAuthorityFailure::Unauthorized);
        }
        validate_routing_text(&command.memory_id, "memory_id")?;
        validate_content(&command.content)?;
        validate_routing_text(&command.source_ref, "source_ref")?;
        validate_routing_text(&command.scope_ref, "scope_ref")?;
        validate_text(&command.idempotency_key, "idempotency_key")?;

        let request_digest = digest_parts(&[
            "submit-candidate",
            &command.memory_id,
            &command.content,
            &command.source_ref,
            &command.scope_ref,
        ]);
        if let Some(existing) = self.store.idempotency_record(
            &principal.principal_id,
            "submit-candidate",
            &command.idempotency_key,
        )? {
            return replay_or_conflict(existing, &request_digest);
        }
        if self.store.memory(&command.memory_id)?.is_some() {
            return Err(MemoryAuthorityFailure::StateConflict);
        }

        let now = current_timestamp()?;
        let event_id = Uuid::now_v7().to_string();
        let content_sha256 = digest_text(&command.content);
        self.store.insert_candidate(
            &StoredMemory {
                memory_id: command.memory_id.clone(),
                revision: 1,
                content: command.content.clone(),
                content_sha256: content_sha256.clone(),
                source_ref: command.source_ref.clone(),
                scope_ref: command.scope_ref.clone(),
                state: StoredState::from(MemoryState::Candidate.as_str()),
                created_at_seconds: now,
                updated_at_seconds: now,
            },
            &event_id,
            &principal.principal_id,
            &command.idempotency_key,
            &request_digest,
        )?;
        Ok(receipt(
            &command.memory_id,
            1,
            MemoryState::Candidate,
            event_id,
            request_digest,
        ))
    }

    /// Promotes a candidate only with Founder-controlled authorization.
    pub fn accept(
        &mut self,
        command: &GovernMemory,
        principal: &AuthenticatedMemoryPrincipal,
    ) -> Result<MemoryMutationReceipt, MemoryAuthorityFailure> {
        validate_principal(principal)?;
        if !matches!(
            principal.kind,
            MemoryPrincipalKind::Founder | MemoryPrincipalKind::FounderAuthority
        ) {
            return Err(MemoryAuthorityFailure::Unauthorized);
        }
        validate_governance_command(command)?;
        let request_digest = governance_digest("accept", command);
        if let Some(existing) = self.store.idempotency_record(
            &principal.principal_id,
            "accept",
            &command.idempotency_key,
        )? {
            return replay_or_conflict(existing, &request_digest);
        }
        let current = self
            .store
            .memory(&command.memory_id)?
            .ok_or(MemoryAuthorityFailure::NotFound)?;
        if current.revision != command.expected_revision
            || current.state.as_str() != MemoryState::Candidate.as_str()
        {
            return Err(MemoryAuthorityFailure::StateConflict);
        }
        self.transition(
            &current,
            MemoryState::Accepted,
            command,
            principal,
            "accept",
            request_digest,
        )
    }

    /// Revokes a memory. Revocation is terminal and always needs evidence.
    pub fn revoke(
        &mut self,
        command: &GovernMemory,
        principal: &AuthenticatedMemoryPrincipal,
    ) -> Result<MemoryMutationReceipt, MemoryAuthorityFailure> {
        validate_principal(principal)?;
        if !matches!(
            principal.kind,
            MemoryPrincipalKind::Founder
                | MemoryPrincipalKind::FounderAuthority
                | MemoryPrincipalKind::GovernanceKernel
                | MemoryPrincipalKind::RecoveryCoordinator
        ) {
            return Err(MemoryAuthorityFailure::Unauthorized);
        }
        validate_governance_command(command)?;
        let request_digest = governance_digest("revoke", command);
        if let Some(existing) = self.store.idempotency_record(
            &principal.principal_id,
            "revoke",
            &command.idempotency_key,
        )? {
            return replay_or_conflict(existing, &request_digest);
        }
        let current = self
            .store
            .memory(&command.memory_id)?
            .ok_or(MemoryAuthorityFailure::NotFound)?;
        if current.revision != command.expected_revision
            || current.state.as_str() == MemoryState::Revoked.as_str()
        {
            return Err(MemoryAuthorityFailure::StateConflict);
        }
        self.transition(
            &current,
            MemoryState::Revoked,
            command,
            principal,
            "revoke",
            request_digest,
        )
    }

    pub fn get(&self, memory_id: &str) -> Result<Option<MemoryRecord>, MemoryAuthorityFailure> {
        validate_text(memory_id, "memory_id")?;
        self.store.memory(memory_id)?.map(to_record).transpose()
    }

    /// Produces the only input shape that the retrieval worker may consume.
    pub fn accepted_snapshot(
        &self,
        scope_ref: &str,
    ) -> Result<AcceptedMemorySnapshot, MemoryAuthorityFailure> {
        validate_text(scope_ref, "scope_ref")?;
        let records = self
            .store
            .accepted_memories(scope_ref)?
            .into_iter()
            .map(to_record)
            .collect::<Result<Vec<_>, _>>()?;
        let snapshot_sha256 = digest_records(scope_ref, &records);
        Ok(AcceptedMemorySnapshot {
            scope_ref: scope_ref.to_owned(),
            records,
            snapshot_sha256,
        })
    }

    /// Returns bounded candidate records available for Founder review.
    ///
    /// This is a read-only Authority projection. It does not grant a
    /// producer any acceptance or revocation capability.
    pub fn candidate_records(
        &self,
        scope_ref: &str,
    ) -> Result<Vec<MemoryRecord>, MemoryAuthorityFailure> {
        validate_text(scope_ref, "scope_ref")?;
        self.store
            .candidate_memories(scope_ref)?
            .into_iter()
            .map(to_record)
            .collect()
    }

    pub fn inspect_store(&self) -> Result<MemoryStoreInspection, MemoryAuthorityFailure> {
        self.store.inspect().map_err(MemoryAuthorityFailure::from)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, MemoryAuthorityFailure> {
        self.store
            .integrity_is_ok()
            .map_err(MemoryAuthorityFailure::from)
    }

    fn transition(
        &mut self,
        current: &StoredMemory,
        next_state: MemoryState,
        command: &GovernMemory,
        principal: &AuthenticatedMemoryPrincipal,
        operation: &str,
        request_digest: String,
    ) -> Result<MemoryMutationReceipt, MemoryAuthorityFailure> {
        let now = current_timestamp()?;
        let event_id = Uuid::now_v7().to_string();
        let resulting_revision = current.revision + 1;
        let changed = self.store.transition(&TransitionCommit {
            current,
            next_state: next_state.as_str(),
            resulting_revision,
            committed_at_seconds: now,
            event_id: &event_id,
            principal_id: &principal.principal_id,
            operation,
            evidence_ref: &command.evidence_ref,
            idempotency_key: &command.idempotency_key,
            request_digest_sha256: &request_digest,
        })?;
        if !changed {
            return Err(MemoryAuthorityFailure::StateConflict);
        }
        Ok(receipt(
            &command.memory_id,
            resulting_revision,
            next_state,
            event_id,
            request_digest,
        ))
    }
}

fn validate_principal(
    principal: &AuthenticatedMemoryPrincipal,
) -> Result<(), MemoryAuthorityFailure> {
    if !principal.authenticated || principal.principal_id.trim().is_empty() {
        return Err(MemoryAuthorityFailure::Unauthorized);
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), MemoryAuthorityFailure> {
    if value.trim().is_empty() {
        return Err(MemoryAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn validate_routing_text(value: &str, field: &'static str) -> Result<(), MemoryAuthorityFailure> {
    validate_text(value, field)?;
    if value.len() > MEMORY_MAX_ROUTING_FIELD_BYTES {
        return Err(MemoryAuthorityFailure::InvalidArgument(field));
    }
    Ok(())
}

fn validate_content(value: &str) -> Result<(), MemoryAuthorityFailure> {
    validate_text(value, "content")?;
    if value.len() > MEMORY_MAX_TOTAL_CONTENT_BYTES {
        return Err(MemoryAuthorityFailure::InvalidArgument("content"));
    }
    Ok(())
}

fn validate_governance_command(command: &GovernMemory) -> Result<(), MemoryAuthorityFailure> {
    validate_text(&command.memory_id, "memory_id")?;
    validate_text(&command.evidence_ref, "evidence_ref")?;
    validate_text(&command.idempotency_key, "idempotency_key")?;
    if command.expected_revision == 0 {
        return Err(MemoryAuthorityFailure::InvalidArgument("expected_revision"));
    }
    Ok(())
}

fn governance_digest(operation: &str, command: &GovernMemory) -> String {
    digest_parts(&[
        operation,
        &command.memory_id,
        &command.expected_revision.to_string(),
        &command.evidence_ref,
    ])
}

fn digest_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn digest_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn digest_records(scope_ref: &str, records: &[MemoryRecord]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope_ref.as_bytes());
    for record in records {
        for value in [
            record.memory_id.as_str(),
            &record.revision.to_string(),
            record.content_sha256.as_str(),
            record.source_ref.as_str(),
            record.scope_ref.as_str(),
            record.state.as_str(),
        ] {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn current_timestamp() -> Result<i64, MemoryAuthorityFailure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|_| MemoryAuthorityFailure::Clock)
}

fn to_record(stored: StoredMemory) -> Result<MemoryRecord, MemoryAuthorityFailure> {
    // SQLCipher's structural integrity check does not prove that denormalized
    // semantic fields still agree. Recompute the content digest at the
    // authority read boundary so `get` and accepted snapshots cannot attest to
    // a record whose content and digest have drifted apart.
    if digest_text(&stored.content) != stored.content_sha256 {
        return Err(MemoryAuthorityFailure::Storage);
    }

    Ok(MemoryRecord {
        memory_id: stored.memory_id,
        revision: stored.revision,
        content: stored.content,
        content_sha256: stored.content_sha256,
        source_ref: stored.source_ref,
        scope_ref: stored.scope_ref,
        state: MemoryState::parse(stored.state)?,
        created_at_seconds: stored.created_at_seconds,
        updated_at_seconds: stored.updated_at_seconds,
    })
}

fn receipt(
    memory_id: &str,
    revision: u64,
    state: MemoryState,
    event_id: String,
    request_digest_sha256: String,
) -> MemoryMutationReceipt {
    MemoryMutationReceipt {
        memory_id: memory_id.to_owned(),
        revision,
        state,
        event_id,
        request_digest_sha256,
        acknowledged_after_durability_barrier: true,
    }
}

fn replay_or_conflict(
    existing: store::IdempotencyRecord,
    request_digest: &str,
) -> Result<MemoryMutationReceipt, MemoryAuthorityFailure> {
    if existing.request_digest_sha256 != request_digest {
        return Err(MemoryAuthorityFailure::IdempotencyConflict);
    }
    Ok(receipt(
        &existing.memory_id,
        existing.revision,
        MemoryState::parse(existing.state)?,
        existing.event_id,
        existing.request_digest_sha256,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(content: &str, content_sha256: &str) -> StoredMemory {
        StoredMemory {
            memory_id: "memory-test".to_owned(),
            revision: 1,
            content: content.to_owned(),
            content_sha256: content_sha256.to_owned(),
            source_ref: "source:test".to_owned(),
            scope_ref: "scope:test".to_owned(),
            state: StoredState::from("accepted"),
            created_at_seconds: 1,
            updated_at_seconds: 1,
        }
    }

    #[test]
    fn authority_rejects_semantic_content_digest_drift() {
        let content = "accepted content";
        let drifted = stored(content, &digest_text("different content"));

        assert_eq!(to_record(drifted), Err(MemoryAuthorityFailure::Storage));
    }

    #[test]
    fn authority_accepts_matching_content_digest() {
        let content = "accepted content";
        let record = to_record(stored(content, &digest_text(content)))
            .expect("matching content digest should be readable");

        assert_eq!(record.content, content);
        assert_eq!(record.state, MemoryState::Accepted);
    }
}
