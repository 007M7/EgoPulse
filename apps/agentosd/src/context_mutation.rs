use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::context_authority::{
    AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityFailure,
    ContextGovernanceState as AuthorityContextGovernanceState, ContextPrincipalKind,
    ContextRevokeReceipt as AuthorityContextRevokeReceipt, ContextRevokeRequest,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    ContextGovernanceState, ContextRevokeReceipt,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, ContextMutationPort, ContextMutationPortFailure,
    VerifiedContextRevokeCommand,
};
use prost_types::Timestamp;

use crate::AuthorityPrincipalResolver;

const CONTEXT_FOUNDER_CONSTRAINT: &str = "ContextAuthority.Founder";

/// The daemon-owned bridge from the authenticated Local API command boundary
/// to the sole Context Authority writer. It shares the same Authority handle
/// used by preparation and internal Context consumers.
pub struct ContextMutationPortAdapter {
    authority: Arc<Mutex<ContextAuthority>>,
    principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
}

impl ContextMutationPortAdapter {
    #[must_use]
    pub fn new(
        authority: Arc<Mutex<ContextAuthority>>,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        Self {
            authority,
            principal_resolver,
        }
    }

    fn revoke_request(
        &self,
        request: &ContextRevokeRequest,
        expected_request_digest_sha256: &str,
        principal: &CommandPrincipal,
    ) -> Result<ContextRevokeReceipt, ContextMutationPortFailure> {
        let authority_principal = self.context_founder_principal(principal)?;
        let receipt = self
            .authority
            .lock()
            .map_err(|_| ContextMutationPortFailure::IntegrityFailure)?
            .revoke(&authority_principal, request)
            .map_err(map_authority_failure)?;
        map_receipt(
            receipt,
            &request.snapshot_id,
            expected_request_digest_sha256,
        )
    }

    fn context_founder_principal(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<AuthenticatedContextPrincipal, ContextMutationPortFailure> {
        if principal.required_authority_principal_kinds.as_slice() != [CONTEXT_FOUNDER_CONSTRAINT] {
            return Err(ContextMutationPortFailure::UnknownCriticalSemantics);
        }
        let kind = self
            .principal_resolver
            .resolve_context(principal)
            .map_err(map_principal_resolution_failure)?;
        if kind != ContextPrincipalKind::Founder {
            return Err(ContextMutationPortFailure::UnknownCriticalSemantics);
        }
        Ok(AuthenticatedContextPrincipal {
            kind,
            principal_id: principal.principal_id.clone(),
            authenticated: true,
        })
    }
}

impl ContextMutationPort for ContextMutationPortAdapter {
    fn revoke(
        &self,
        command: &VerifiedContextRevokeCommand,
        principal: &CommandPrincipal,
    ) -> Result<ContextRevokeReceipt, ContextMutationPortFailure> {
        self.revoke_request(
            &ContextRevokeRequest {
                command_id: command.command_id().to_owned(),
                snapshot_id: command.snapshot_id().to_owned(),
                expected_state_revision: command.expected_state_revision(),
                reason_code: command.reason_code().to_owned(),
                evidence_refs: command.evidence_refs().to_vec(),
                confirmation_proof_ref: command.confirmation_proof_ref().to_owned(),
                idempotency_key: command.idempotency_key().to_owned(),
                correlation_id: command.correlation_id().to_owned(),
                causation_id: command.causation_id().map(str::to_owned),
            },
            command.request_digest_sha256(),
            principal,
        )
    }
}

fn map_principal_resolution_failure(failure: CommandPortFailure) -> ContextMutationPortFailure {
    match failure {
        CommandPortFailure::Unavailable => ContextMutationPortFailure::PermissionDenied,
        CommandPortFailure::IntegrityFailure => ContextMutationPortFailure::IntegrityFailure,
        CommandPortFailure::DeliveryUnknown => ContextMutationPortFailure::UnknownCriticalSemantics,
    }
}

fn map_authority_failure(failure: ContextAuthorityFailure) -> ContextMutationPortFailure {
    match failure {
        ContextAuthorityFailure::InvalidArgument(_) => ContextMutationPortFailure::InvalidArgument,
        ContextAuthorityFailure::Unauthorized => ContextMutationPortFailure::PermissionDenied,
        ContextAuthorityFailure::OwnerMismatch => ContextMutationPortFailure::OwnerMismatch,
        ContextAuthorityFailure::NotFound => ContextMutationPortFailure::NotFound,
        ContextAuthorityFailure::Revoked => ContextMutationPortFailure::ContextRevoked,
        ContextAuthorityFailure::StateRevisionConflict => {
            ContextMutationPortFailure::StateRevisionConflict
        }
        ContextAuthorityFailure::IdempotencyConflict => {
            ContextMutationPortFailure::IdempotencyConflict
        }
        ContextAuthorityFailure::IntegrityFailure => ContextMutationPortFailure::IntegrityFailure,
        ContextAuthorityFailure::Storage => ContextMutationPortFailure::AuthorityUnavailable,
        ContextAuthorityFailure::Clock
        | ContextAuthorityFailure::Expired
        | ContextAuthorityFailure::ScopeMismatch
        | ContextAuthorityFailure::AuthorizationTupleConflict => {
            ContextMutationPortFailure::IntegrityFailure
        }
    }
}

fn map_receipt(
    receipt: AuthorityContextRevokeReceipt,
    expected_snapshot_id: &str,
    expected_request_digest_sha256: &str,
) -> Result<ContextRevokeReceipt, ContextMutationPortFailure> {
    if receipt.snapshot_id != expected_snapshot_id
        || receipt.request_digest_sha256 != expected_request_digest_sha256
    {
        return Err(ContextMutationPortFailure::IntegrityFailure);
    }
    Ok(ContextRevokeReceipt {
        snapshot_id: receipt.snapshot_id,
        snapshot_revision: receipt.snapshot_revision,
        content_digest_sha256: receipt.content_digest_sha256,
        previous_state_revision: receipt.previous_state_revision,
        result_state_revision: receipt.result_state_revision,
        previous_state: proto_governance_state(receipt.previous_state) as i32,
        result_state: proto_governance_state(receipt.result_state) as i32,
        request_digest_sha256: receipt.request_digest_sha256,
        event_id: receipt.event_id,
        committed_at: Some(Timestamp {
            seconds: receipt.committed_at_seconds,
            nanos: 0,
        }),
        replayed: receipt.replayed,
        acknowledged_after_durability_barrier: true,
    })
}

fn proto_governance_state(state: AuthorityContextGovernanceState) -> ContextGovernanceState {
    match state {
        AuthorityContextGovernanceState::Issued => ContextGovernanceState::Issued,
        AuthorityContextGovernanceState::Revoked => ContextGovernanceState::Revoked,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use egopulse_cognition_runtime::{
        context_authority::{
            ContextAuthorityConfig, IssueContextSnapshot, context_revoke_request_digest,
        },
        task_authority::{PrincipalKind as TaskPrincipalKind, SqlCipherKey},
    };
    use uuid::Uuid;

    use super::*;
    use crate::{AuthorityPrincipalBinding, ConfiguredAuthorityPrincipalResolver};

    const FOUNDER_ID: &str = "founder:context-test";

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()))
    }

    fn open_authority(root: &Path, epoch: &str) -> ContextAuthority {
        fs::create_dir_all(root).expect("create Context test root");
        ContextAuthority::open(ContextAuthorityConfig {
            database_path: root.join("context-authority.db"),
            store_epoch: epoch.to_owned(),
            key: SqlCipherKey::new([0x6d; 32]),
        })
        .expect("open Context Authority")
    }

    fn issue_snapshot(authority: &mut ContextAuthority, idempotency_key: &str) -> String {
        let (_, snapshot) = authority
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: FOUNDER_ID.to_owned(),
                    intent: "revoke adapter test".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "scope:repository".to_owned(),
                    compiled_context: br#"{"prompt":"revoke adapter"}"#.to_vec(),
                    sources: Vec::new(),
                    memory_pack: None,
                    allowed_read_paths: vec!["workspace".to_owned()],
                    allowed_write_paths: vec!["workspace".to_owned()],
                    allowed_tools: Vec::new(),
                    external_resources: Vec::new(),
                    non_goals: Vec::new(),
                    acceptance_contract_ref: "acceptance:v1".to_owned(),
                    budget_profile_ref: "budget:v1".to_owned(),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: Vec::new(),
                    expires_at_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("clock")
                        .as_secs() as i64
                        + 600,
                    idempotency_key: idempotency_key.to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:test".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue Context snapshot");
        snapshot.snapshot_id
    }

    fn resolver(
        entries: impl IntoIterator<Item = (&'static str, ContextPrincipalKind)>,
    ) -> Arc<dyn AuthorityPrincipalResolver> {
        Arc::new(
            ConfiguredAuthorityPrincipalResolver::new(entries.into_iter().map(|(id, context)| {
                AuthorityPrincipalBinding {
                    principal_id: id.to_owned(),
                    task: None,
                    policy: None,
                    verdict: None,
                    memory: None,
                    context: Some(context),
                }
            }))
            .expect("Context principal resolver"),
        )
    }

    fn principal(id: &str) -> CommandPrincipal {
        CommandPrincipal {
            principal_id: id.to_owned(),
            required_authority_principal_kinds: vec![CONTEXT_FOUNDER_CONSTRAINT.to_owned()],
        }
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
            reason_code: "founder-withdrawn".to_owned(),
            evidence_refs: vec!["evidence:review:42".to_owned()],
            confirmation_proof_ref: "confirmation:local:1".to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            correlation_id: format!("correlation:{idempotency_key}"),
            causation_id: None,
        }
    }

    fn execute(
        adapter: &ContextMutationPortAdapter,
        request: &ContextRevokeRequest,
        principal: &CommandPrincipal,
    ) -> Result<ContextRevokeReceipt, ContextMutationPortFailure> {
        let digest = context_revoke_request_digest(&principal.principal_id, request);
        adapter.revoke_request(request, &digest, principal)
    }

    #[test]
    fn real_authority_revoke_success_and_durable_replay_are_sanitized() {
        let root = test_root("context-mutation-success");
        let authority = Arc::new(Mutex::new(open_authority(
            &root,
            "context-mutation-success",
        )));
        let snapshot_id = issue_snapshot(
            &mut authority.lock().expect("Context Authority lock"),
            "issue:success",
        );
        let adapter = ContextMutationPortAdapter::new(
            Arc::clone(&authority),
            resolver([(FOUNDER_ID, ContextPrincipalKind::Founder)]),
        );
        let request = revoke_request(&snapshot_id, 1, "revoke:success");
        let first = execute(&adapter, &request, &principal(FOUNDER_ID)).expect("commit revoke");
        assert_eq!(first.snapshot_id, snapshot_id);
        assert_eq!(first.snapshot_revision, 1);
        assert_eq!(first.previous_state_revision, 1);
        assert_eq!(first.result_state_revision, 2);
        assert_eq!(first.previous_state, ContextGovernanceState::Issued as i32);
        assert_eq!(first.result_state, ContextGovernanceState::Revoked as i32);
        assert!(first.acknowledged_after_durability_barrier);
        assert!(!first.replayed);
        assert_eq!(
            first.request_digest_sha256,
            context_revoke_request_digest(FOUNDER_ID, &request)
        );
        assert_eq!(
            first.committed_at.as_ref().map(|value| value.nanos),
            Some(0)
        );
        let after_commit = authority
            .lock()
            .expect("Context Authority lock")
            .inspect_store()
            .expect("inspect Context store after commit");
        assert_eq!(after_commit.revoke_receipt_count, 1);
        assert_eq!(after_commit.revoke_idempotency_count, 1);

        let replay = execute(&adapter, &request, &principal(FOUNDER_ID)).expect("replay revoke");
        let mut expected_replay = first.clone();
        expected_replay.replayed = true;
        assert_eq!(replay, expected_replay);
        let after_replay = authority
            .lock()
            .expect("Context Authority lock")
            .inspect_store()
            .expect("inspect Context store after replay");
        assert_eq!(after_replay.event_count, after_commit.event_count);
        assert_eq!(
            after_replay.revoke_receipt_count,
            after_commit.revoke_receipt_count
        );
        assert_eq!(
            after_replay.revoke_idempotency_count,
            after_commit.revoke_idempotency_count
        );

        drop(adapter);
        drop(authority);
        fs::remove_dir_all(root).expect("remove Context test root");
    }

    #[test]
    fn real_authority_failures_preserve_owner_cas_revoked_and_idempotency_types() {
        let root = test_root("context-mutation-failures");
        let authority = Arc::new(Mutex::new(open_authority(
            &root,
            "context-mutation-failures",
        )));
        let snapshot_id = issue_snapshot(
            &mut authority.lock().expect("Context Authority lock"),
            "issue:failures",
        );
        let adapter = ContextMutationPortAdapter::new(
            Arc::clone(&authority),
            resolver([
                (FOUNDER_ID, ContextPrincipalKind::Founder),
                ("founder:other", ContextPrincipalKind::Founder),
            ]),
        );

        let owner_request = revoke_request(&snapshot_id, 1, "revoke:other-owner");
        assert_eq!(
            execute(&adapter, &owner_request, &principal("founder:other")),
            Err(ContextMutationPortFailure::OwnerMismatch)
        );
        let stale = revoke_request(&snapshot_id, 2, "revoke:stale");
        assert_eq!(
            execute(&adapter, &stale, &principal(FOUNDER_ID)),
            Err(ContextMutationPortFailure::StateRevisionConflict)
        );

        let committed = revoke_request(&snapshot_id, 1, "revoke:commit");
        execute(&adapter, &committed, &principal(FOUNDER_ID)).expect("commit revoke");
        let revoked = revoke_request(&snapshot_id, 2, "revoke:after-revoked");
        assert_eq!(
            execute(&adapter, &revoked, &principal(FOUNDER_ID)),
            Err(ContextMutationPortFailure::ContextRevoked)
        );
        let mut conflicting = committed;
        conflicting.reason_code = "different-reason".to_owned();
        assert_eq!(
            execute(&adapter, &conflicting, &principal(FOUNDER_ID)),
            Err(ContextMutationPortFailure::IdempotencyConflict)
        );

        drop(adapter);
        drop(authority);
        fs::remove_dir_all(root).expect("remove Context test root");
    }

    #[test]
    fn adapter_requires_exact_profile_constraint_and_trusted_founder_binding() {
        let root = test_root("context-mutation-principal");
        let authority = Arc::new(Mutex::new(open_authority(
            &root,
            "context-mutation-principal",
        )));
        let snapshot_id = issue_snapshot(
            &mut authority.lock().expect("Context Authority lock"),
            "issue:principal",
        );
        let request = revoke_request(&snapshot_id, 1, "revoke:principal");
        let missing_binding = ContextMutationPortAdapter::new(
            Arc::clone(&authority),
            Arc::new(
                ConfiguredAuthorityPrincipalResolver::new([AuthorityPrincipalBinding {
                    principal_id: FOUNDER_ID.to_owned(),
                    task: Some(TaskPrincipalKind::Founder),
                    policy: None,
                    verdict: None,
                    memory: None,
                    context: None,
                }])
                .expect("task-only principal resolver"),
            ),
        );
        assert_eq!(
            execute(&missing_binding, &request, &principal(FOUNDER_ID)),
            Err(ContextMutationPortFailure::PermissionDenied)
        );
        let non_founder = ContextMutationPortAdapter::new(
            Arc::clone(&authority),
            resolver([(FOUNDER_ID, ContextPrincipalKind::GovernanceKernel)]),
        );
        assert_eq!(
            execute(&non_founder, &request, &principal(FOUNDER_ID)),
            Err(ContextMutationPortFailure::UnknownCriticalSemantics)
        );

        let founder = ContextMutationPortAdapter::new(
            Arc::clone(&authority),
            resolver([(FOUNDER_ID, ContextPrincipalKind::Founder)]),
        );
        let wrong_profile = CommandPrincipal {
            principal_id: FOUNDER_ID.to_owned(),
            required_authority_principal_kinds: vec![
                CONTEXT_FOUNDER_CONSTRAINT.to_owned(),
                "ContextAuthority.GovernanceKernel".to_owned(),
            ],
        };
        assert_eq!(
            execute(&founder, &request, &wrong_profile),
            Err(ContextMutationPortFailure::UnknownCriticalSemantics)
        );
        let inspection = authority
            .lock()
            .expect("Context Authority lock")
            .inspect_store()
            .expect("inspect Context store");
        assert_eq!(inspection.revoke_receipt_count, 0);
        assert_eq!(inspection.revoke_idempotency_count, 0);

        drop(founder);
        drop(non_founder);
        drop(missing_binding);
        drop(authority);
        fs::remove_dir_all(root).expect("remove Context test root");
    }

    #[test]
    fn receipt_digest_mismatch_fails_closed_without_public_receipt() {
        let authority_receipt = AuthorityContextRevokeReceipt {
            snapshot_id: "ctx:expected".to_owned(),
            snapshot_revision: 1,
            content_digest_sha256: "11".repeat(32),
            previous_state_revision: 1,
            result_state_revision: 2,
            previous_state: AuthorityContextGovernanceState::Issued,
            result_state: AuthorityContextGovernanceState::Revoked,
            request_digest_sha256: "22".repeat(32),
            event_id: "event:revoke".to_owned(),
            committed_at_seconds: 100,
            replayed: false,
        };
        assert_eq!(
            map_receipt(authority_receipt, "ctx:expected", &"33".repeat(32)),
            Err(ContextMutationPortFailure::IntegrityFailure)
        );
    }

    #[test]
    fn failure_mapping_is_exhaustive_and_keeps_only_storage_retryable() {
        for (failure, expected) in [
            (
                ContextAuthorityFailure::InvalidArgument("invalid"),
                ContextMutationPortFailure::InvalidArgument,
            ),
            (
                ContextAuthorityFailure::Unauthorized,
                ContextMutationPortFailure::PermissionDenied,
            ),
            (
                ContextAuthorityFailure::OwnerMismatch,
                ContextMutationPortFailure::OwnerMismatch,
            ),
            (
                ContextAuthorityFailure::NotFound,
                ContextMutationPortFailure::NotFound,
            ),
            (
                ContextAuthorityFailure::Revoked,
                ContextMutationPortFailure::ContextRevoked,
            ),
            (
                ContextAuthorityFailure::StateRevisionConflict,
                ContextMutationPortFailure::StateRevisionConflict,
            ),
            (
                ContextAuthorityFailure::IdempotencyConflict,
                ContextMutationPortFailure::IdempotencyConflict,
            ),
            (
                ContextAuthorityFailure::IntegrityFailure,
                ContextMutationPortFailure::IntegrityFailure,
            ),
            (
                ContextAuthorityFailure::Storage,
                ContextMutationPortFailure::AuthorityUnavailable,
            ),
            (
                ContextAuthorityFailure::Clock,
                ContextMutationPortFailure::IntegrityFailure,
            ),
            (
                ContextAuthorityFailure::Expired,
                ContextMutationPortFailure::IntegrityFailure,
            ),
            (
                ContextAuthorityFailure::ScopeMismatch,
                ContextMutationPortFailure::IntegrityFailure,
            ),
            (
                ContextAuthorityFailure::AuthorizationTupleConflict,
                ContextMutationPortFailure::IntegrityFailure,
            ),
        ] {
            assert_eq!(map_authority_failure(failure), expected);
        }
        for (failure, expected) in [
            (
                CommandPortFailure::Unavailable,
                ContextMutationPortFailure::PermissionDenied,
            ),
            (
                CommandPortFailure::IntegrityFailure,
                ContextMutationPortFailure::IntegrityFailure,
            ),
            (
                CommandPortFailure::DeliveryUnknown,
                ContextMutationPortFailure::UnknownCriticalSemantics,
            ),
        ] {
            assert_eq!(map_principal_resolution_failure(failure), expected);
        }
    }
}
