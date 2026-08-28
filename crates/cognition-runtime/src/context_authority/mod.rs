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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextPrincipalKind {
    ContextCompiler,
    GovernanceKernel,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextStoreInspection {
    pub snapshot_count: u64,
    pub event_count: u64,
    pub idempotency_count: u64,
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
    #[error("context authority clock is before the Unix epoch")]
    Clock,
}

impl From<store::StoreError> for ContextAuthorityFailure {
    fn from(_: store::StoreError) -> Self {
        Self::Storage
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
    let confirmation_binding_sha256 = confirmation_digest(
        snapshot_id,
        &intent_sha256,
        &input.work_type,
        &input.target_scope_ref,
        &input.acceptance_contract_ref,
        &input.budget_profile_ref,
        input.expires_at_seconds,
    );
    Ok(ContextSnapshot {
        snapshot_id: snapshot_id.to_owned(),
        revision: 1,
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

fn validate_input(input: &IssueContextSnapshot) -> Result<(), ContextAuthorityFailure> {
    let now = current_timestamp()?;
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

fn snapshot_digest(snapshot: &ContextSnapshot) -> String {
    let descriptor = serde_json::to_vec(snapshot).expect("ContextSnapshot must be serializable");
    sha256(&descriptor)
}

fn confirmation_digest(
    snapshot_id: &str,
    intent_sha256: &str,
    work_type: &str,
    target_scope_ref: &str,
    acceptance_contract_ref: &str,
    budget_profile_ref: &str,
    expires_at_seconds: i64,
) -> String {
    let values = [
        snapshot_id,
        intent_sha256,
        work_type,
        target_scope_ref,
        acceptance_contract_ref,
        budget_profile_ref,
        &expires_at_seconds.to_string(),
    ];
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
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
}
