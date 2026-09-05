use egopulse_cognition_runtime::memory_authority::{
    AcceptedMemorySnapshot, AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority,
    MemoryAuthorityConfig, MemoryAuthorityFailure, MemoryPrincipalKind, MemoryState,
    SubmitMemoryCandidate,
};
use egopulse_cognition_runtime::task_authority::SqlCipherKey;
use egopulse_domain_contracts::memory::{
    MEMORY_MAX_ROUTING_FIELD_BYTES, MEMORY_MAX_TOTAL_CONTENT_BYTES,
};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-memory-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create isolated memory authority directory");
        Self { path }
    }

    fn database_path(&self) -> PathBuf {
        self.path.join("memory-authority.sqlcipher")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn authority(root: &TempRoot) -> MemoryAuthority {
    MemoryAuthority::open(MemoryAuthorityConfig {
        database_path: root.database_path(),
        store_epoch: "memory-test-epoch".to_owned(),
        key: SqlCipherKey::new([71_u8; 32]),
    })
    .expect("open memory authority")
}

fn principal(kind: MemoryPrincipalKind, id: &str) -> AuthenticatedMemoryPrincipal {
    AuthenticatedMemoryPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn candidate(idempotency_key: &str) -> SubmitMemoryCandidate {
    SubmitMemoryCandidate {
        memory_id: "memory-1".to_owned(),
        content: "Founder prefers deterministic local execution.".to_owned(),
        source_ref: "run:demo:event:1".to_owned(),
        scope_ref: "scope:founder".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
    }
}

fn governance(revision: u64, idempotency_key: &str) -> GovernMemory {
    GovernMemory {
        memory_id: "memory-1".to_owned(),
        expected_revision: revision,
        evidence_ref: "evidence:founder-review:1".to_owned(),
        idempotency_key: idempotency_key.to_owned(),
    }
}

#[test]
fn agent_write_is_candidate_only_and_founder_acceptance_exposes_snapshot() {
    let root = TempRoot::new("governance");
    let mut authority = authority(&root);
    let agent = principal(MemoryPrincipalKind::Agent, "agent:local");
    let founder = principal(MemoryPrincipalKind::Founder, "founder:local");

    let submitted = authority
        .submit_candidate(&candidate("submit-1"), &agent)
        .expect("submit candidate");
    assert_eq!(submitted.state, MemoryState::Candidate);
    assert_eq!(submitted.revision, 1);

    let candidates = authority
        .candidate_records("scope:founder")
        .expect("read candidate records");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].memory_id, "memory-1");
    assert_eq!(candidates[0].state, MemoryState::Candidate);
    assert_eq!(
        candidates[0].content,
        "Founder prefers deterministic local execution."
    );

    let snapshot = authority
        .accepted_snapshot("scope:founder")
        .expect("read empty accepted snapshot");
    assert!(snapshot.records.is_empty());

    let accepted = authority
        .accept(&governance(1, "accept-1"), &founder)
        .expect("founder accepts candidate");
    assert_eq!(accepted.state, MemoryState::Accepted);
    assert_eq!(accepted.revision, 2);

    let AcceptedMemorySnapshot { records, .. } = authority
        .accepted_snapshot("scope:founder")
        .expect("read accepted snapshot");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].memory_id, "memory-1");
    assert_eq!(records[0].state, MemoryState::Accepted);
    assert_eq!(
        records[0].content,
        "Founder prefers deterministic local execution."
    );
    assert!(
        authority
            .candidate_records("scope:founder")
            .expect("read empty candidate projection")
            .is_empty()
    );
    assert!(authority.integrity_is_ok().expect("check memory integrity"));
}

#[test]
fn unauthorized_acceptance_and_missing_evidence_fail_closed() {
    let root = TempRoot::new("authorization");
    let mut authority = authority(&root);
    let agent = principal(MemoryPrincipalKind::Agent, "agent:local");
    authority
        .submit_candidate(&candidate("submit-1"), &agent)
        .expect("submit candidate");

    let unauthorized = authority.accept(
        &governance(1, "accept-1"),
        &principal(MemoryPrincipalKind::Agent, "agent:local"),
    );
    assert_eq!(unauthorized, Err(MemoryAuthorityFailure::Unauthorized));

    let missing_evidence = GovernMemory {
        evidence_ref: String::new(),
        ..governance(1, "accept-2")
    };
    assert_eq!(
        authority.accept(
            &missing_evidence,
            &principal(MemoryPrincipalKind::Founder, "founder:local"),
        ),
        Err(MemoryAuthorityFailure::InvalidArgument("evidence_ref"))
    );
}

#[test]
fn idempotency_replay_and_conflict_are_explicit() {
    let root = TempRoot::new("idempotency");
    let mut authority = authority(&root);
    let agent = principal(MemoryPrincipalKind::Agent, "agent:local");

    let command = candidate("same-key");
    let first = authority
        .submit_candidate(&command, &agent)
        .expect("first candidate submission");
    let replay = authority
        .submit_candidate(&command, &agent)
        .expect("idempotent candidate replay");
    assert_eq!(first, replay);

    let changed = SubmitMemoryCandidate {
        content: "different content".to_owned(),
        ..command
    };
    assert_eq!(
        authority.submit_candidate(&changed, &agent),
        Err(MemoryAuthorityFailure::IdempotencyConflict)
    );
    assert_eq!(
        authority.inspect_store().expect("inspect memory store"),
        egopulse_cognition_runtime::memory_authority::MemoryStoreInspection {
            memory_count: 1,
            event_count: 1,
            idempotency_count: 1,
            last_event_sequence: 1,
        }
    );
}

#[test]
fn revoke_is_terminal_and_stale_revision_cannot_mutate() {
    let root = TempRoot::new("revoke");
    let mut authority = authority(&root);
    let agent = principal(MemoryPrincipalKind::Agent, "agent:local");
    let founder = principal(MemoryPrincipalKind::Founder, "founder:local");
    authority
        .submit_candidate(&candidate("submit-1"), &agent)
        .expect("submit candidate");
    authority
        .accept(&governance(1, "accept-1"), &founder)
        .expect("accept candidate");
    let revoked = authority
        .revoke(&governance(2, "revoke-1"), &founder)
        .expect("revoke accepted memory");
    assert_eq!(revoked.state, MemoryState::Revoked);

    assert!(
        authority
            .accepted_snapshot("scope:founder")
            .expect("read revoked snapshot")
            .records
            .is_empty()
    );
    assert_eq!(
        authority.revoke(&governance(2, "revoke-stale"), &founder),
        Err(MemoryAuthorityFailure::StateConflict)
    );
}

#[test]
fn accepted_memory_reopens_from_encrypted_store() {
    let root = TempRoot::new("reopen");
    {
        let mut authority = authority(&root);
        let agent = principal(MemoryPrincipalKind::Agent, "agent:local");
        let founder = principal(MemoryPrincipalKind::Founder, "founder:local");
        authority
            .submit_candidate(&candidate("submit-1"), &agent)
            .expect("submit candidate");
        authority
            .accept(&governance(1, "accept-1"), &founder)
            .expect("accept candidate");
    }
    let reopened = authority(&root);
    let snapshot = reopened
        .accepted_snapshot("scope:founder")
        .expect("read reopened accepted memory");
    assert_eq!(snapshot.records.len(), 1);
    assert!(
        reopened
            .integrity_is_ok()
            .expect("check reopened integrity")
    );
}

#[test]
fn unauthenticated_principal_cannot_write() {
    let root = TempRoot::new("identity");
    let mut authority = authority(&root);
    let mut unauthenticated = principal(MemoryPrincipalKind::Agent, "agent:local");
    unauthenticated.authenticated = false;
    assert_eq!(
        authority.submit_candidate(&candidate("submit-1"), &unauthenticated),
        Err(MemoryAuthorityFailure::Unauthorized)
    );
}

#[test]
fn candidate_rejects_content_and_routing_fields_above_worker_limits() {
    let root = TempRoot::new("bounds");
    let mut authority = authority(&root);
    let agent = principal(MemoryPrincipalKind::Agent, "agent:local");

    let oversized_content = SubmitMemoryCandidate {
        content: "x".repeat(MEMORY_MAX_TOTAL_CONTENT_BYTES + 1),
        idempotency_key: "oversized-content".to_owned(),
        ..candidate("oversized-content")
    };
    assert_eq!(
        authority.submit_candidate(&oversized_content, &agent),
        Err(MemoryAuthorityFailure::InvalidArgument("content"))
    );

    let oversized_scope = SubmitMemoryCandidate {
        scope_ref: "s".repeat(MEMORY_MAX_ROUTING_FIELD_BYTES + 1),
        idempotency_key: "oversized-scope".to_owned(),
        ..candidate("oversized-scope")
    };
    assert_eq!(
        authority.submit_candidate(&oversized_scope, &agent),
        Err(MemoryAuthorityFailure::InvalidArgument("scope_ref"))
    );
}
