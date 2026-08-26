use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::memory_authority::{
    AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority, MemoryAuthorityFailure,
    MemoryPrincipalKind, SubmitMemoryCandidate,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    MemoryMutationCommand, MemoryMutationReceipt, memory_mutation_command,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, MemoryMutationPort,
};

use crate::AuthorityPrincipalResolver;

/// The only Local API adapter that can call Memory Authority mutations. The
/// gateway supplies authorization constraints; this adapter requires one
/// unambiguous Memory principal kind before invoking the owner.
pub struct MemoryMutationPortAdapter {
    authority: Arc<Mutex<MemoryAuthority>>,
    principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
}

impl MemoryMutationPortAdapter {
    #[must_use]
    pub fn new(
        authority: Arc<Mutex<MemoryAuthority>>,
        principal_resolver: Arc<dyn AuthorityPrincipalResolver>,
    ) -> Self {
        Self {
            authority,
            principal_resolver,
        }
    }
}

impl MemoryMutationPort for MemoryMutationPortAdapter {
    fn execute(
        &self,
        command: &MemoryMutationCommand,
        principal: &CommandPrincipal,
    ) -> Result<MemoryMutationReceipt, CommandPortFailure> {
        let command = command
            .command
            .as_ref()
            .ok_or(CommandPortFailure::IntegrityFailure)?;
        let authority_principal = principal_for(
            resolve_kind(
                self.principal_resolver.resolve_memory(principal)?,
                principal,
                match command {
                    memory_mutation_command::Command::SubmitMemoryCandidate(_) => {
                        &["MemoryAuthority.Founder"][..]
                    }
                    memory_mutation_command::Command::AcceptMemory(_)
                    | memory_mutation_command::Command::RevokeMemory(_) => &[
                        "MemoryAuthority.Founder",
                        "MemoryAuthority.FounderAuthority",
                    ][..],
                },
            )?,
            principal,
        );
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| CommandPortFailure::IntegrityFailure)?;
        let receipt = match command {
            memory_mutation_command::Command::SubmitMemoryCandidate(value) => authority
                .submit_candidate(
                    &SubmitMemoryCandidate {
                        memory_id: value.memory_id.clone(),
                        content: value.content.clone(),
                        source_ref: value.source_ref.clone(),
                        scope_ref: value.scope_ref.clone(),
                        idempotency_key: value.idempotency_key.clone(),
                    },
                    &authority_principal,
                )
                .map_err(map_failure)?,
            memory_mutation_command::Command::AcceptMemory(value) => authority
                .accept(
                    &GovernMemory {
                        memory_id: value.memory_id.clone(),
                        expected_revision: value.expected_revision,
                        evidence_ref: value.evidence_ref.clone(),
                        idempotency_key: value.idempotency_key.clone(),
                    },
                    &authority_principal,
                )
                .map_err(map_failure)?,
            memory_mutation_command::Command::RevokeMemory(value) => authority
                .revoke(
                    &GovernMemory {
                        memory_id: value.memory_id.clone(),
                        expected_revision: value.expected_revision,
                        evidence_ref: value.evidence_ref.clone(),
                        idempotency_key: value.idempotency_key.clone(),
                    },
                    &authority_principal,
                )
                .map_err(map_failure)?,
        };
        Ok(MemoryMutationReceipt {
            memory_id: receipt.memory_id,
            revision: receipt.revision,
            state: format_memory_state(receipt.state),
            event_id: receipt.event_id,
            request_digest_sha256: receipt.request_digest_sha256,
            acknowledged_after_durability_barrier: receipt.acknowledged_after_durability_barrier,
        })
    }
}

fn resolve_kind(
    resolved: MemoryPrincipalKind,
    principal: &CommandPrincipal,
    allowed: &[&str],
) -> Result<MemoryPrincipalKind, CommandPortFailure> {
    let resolved_kind = match resolved {
        MemoryPrincipalKind::Founder => "MemoryAuthority.Founder",
        MemoryPrincipalKind::FounderAuthority => "MemoryAuthority.FounderAuthority",
        MemoryPrincipalKind::Agent => "MemoryAuthority.Agent",
        MemoryPrincipalKind::Model => "MemoryAuthority.Model",
        MemoryPrincipalKind::Harness => "MemoryAuthority.Harness",
        MemoryPrincipalKind::GovernanceKernel => "MemoryAuthority.GovernanceKernel",
        MemoryPrincipalKind::RecoveryCoordinator => "MemoryAuthority.RecoveryCoordinator",
    };
    if !allowed.contains(&resolved_kind)
        || !principal
            .required_authority_principal_kinds
            .iter()
            .any(|value| value == resolved_kind)
    {
        return Err(CommandPortFailure::IntegrityFailure);
    }
    Ok(resolved)
}

fn principal_for(
    kind: MemoryPrincipalKind,
    principal: &CommandPrincipal,
) -> AuthenticatedMemoryPrincipal {
    AuthenticatedMemoryPrincipal {
        kind,
        principal_id: principal.principal_id.clone(),
        authenticated: true,
    }
}

fn map_failure(failure: MemoryAuthorityFailure) -> CommandPortFailure {
    match failure {
        MemoryAuthorityFailure::Storage | MemoryAuthorityFailure::Clock => {
            CommandPortFailure::Unavailable
        }
        MemoryAuthorityFailure::InvalidArgument(_)
        | MemoryAuthorityFailure::Unauthorized
        | MemoryAuthorityFailure::NotFound
        | MemoryAuthorityFailure::StateConflict
        | MemoryAuthorityFailure::IdempotencyConflict => CommandPortFailure::IntegrityFailure,
    }
}

fn format_memory_state(state: egopulse_cognition_runtime::memory_authority::MemoryState) -> String {
    match state {
        egopulse_cognition_runtime::memory_authority::MemoryState::Candidate => "candidate",
        egopulse_cognition_runtime::memory_authority::MemoryState::Accepted => "accepted",
        egopulse_cognition_runtime::memory_authority::MemoryState::Revoked => "revoked",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_cognition_runtime::{
        memory_authority::MemoryAuthorityConfig, task_authority::SqlCipherKey,
    };
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        AcceptMemoryCommand, SubmitMemoryCandidateCommand,
    };
    use std::path::PathBuf;
    use uuid::Uuid;

    fn principal(kind: &str) -> CommandPrincipal {
        principal_with_id("founder-local", kind)
    }

    fn principal_with_id(principal_id: &str, kind: &str) -> CommandPrincipal {
        CommandPrincipal {
            principal_id: principal_id.to_owned(),
            required_authority_principal_kinds: vec![kind.to_owned()],
        }
    }

    fn database_path() -> PathBuf {
        std::env::temp_dir().join(format!("egopulse-memory-gateway-{}.db", Uuid::now_v7()))
    }

    #[test]
    fn adapter_preserves_candidate_governance_cas_and_idempotency() {
        let database_path = database_path();
        let authority = Arc::new(Mutex::new(
            MemoryAuthority::open(MemoryAuthorityConfig {
                database_path: database_path.clone(),
                store_epoch: "memory-gateway-test".to_owned(),
                key: SqlCipherKey::new([0x71; 32]),
            })
            .expect("memory authority"),
        ));
        let resolver = Arc::new(
            crate::ConfiguredAuthorityPrincipalResolver::new([
                crate::AuthorityPrincipalBinding {
                    principal_id: "founder-local".to_owned(),
                    task: None,
                    policy: None,
                    verdict: None,
                    memory: Some(MemoryPrincipalKind::Founder),
                },
                crate::AuthorityPrincipalBinding {
                    principal_id: "governance-local".to_owned(),
                    task: None,
                    policy: None,
                    verdict: None,
                    memory: Some(MemoryPrincipalKind::FounderAuthority),
                },
            ])
            .expect("memory principal resolver"),
        );
        let adapter = MemoryMutationPortAdapter::new(Arc::clone(&authority), resolver);
        let candidate = MemoryMutationCommand {
            command: Some(memory_mutation_command::Command::SubmitMemoryCandidate(
                SubmitMemoryCandidateCommand {
                    memory_id: "memory-1".to_owned(),
                    content: "durable fact".to_owned(),
                    source_ref: "source:session-1".to_owned(),
                    scope_ref: "scope:founder".to_owned(),
                    idempotency_key: "candidate-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        let candidate_receipt = adapter
            .execute(&candidate, &principal("MemoryAuthority.Founder"))
            .expect("candidate receipt");
        assert_eq!(candidate_receipt.state, "candidate");
        assert_eq!(candidate_receipt.revision, 1);

        let accept = MemoryMutationCommand {
            command: Some(memory_mutation_command::Command::AcceptMemory(
                AcceptMemoryCommand {
                    memory_id: "memory-1".to_owned(),
                    expected_revision: 1,
                    evidence_ref: "evidence:founder-review-1".to_owned(),
                    idempotency_key: "accept-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        let accepted = adapter
            .execute(&accept, &principal("MemoryAuthority.Founder"))
            .expect("accept receipt");
        assert_eq!(accepted.state, "accepted");
        assert_eq!(accepted.revision, 2);
        let replay = adapter
            .execute(&accept, &principal("MemoryAuthority.Founder"))
            .expect("idempotent replay");
        assert_eq!(replay, accepted);

        let stale_revoke = MemoryMutationCommand {
            command: Some(memory_mutation_command::Command::RevokeMemory(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeMemoryCommand {
                    memory_id: "memory-1".to_owned(),
                    expected_revision: 1,
                    evidence_ref: "evidence:founder-revoke-stale".to_owned(),
                    idempotency_key: "revoke-stale-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        assert_eq!(
            adapter
                .execute(
                    &stale_revoke,
                    &principal_with_id("governance-local", "MemoryAuthority.FounderAuthority"),
                )
                .expect_err("stale revision must fail"),
            CommandPortFailure::IntegrityFailure
        );

        let revoke = MemoryMutationCommand {
            command: Some(memory_mutation_command::Command::RevokeMemory(
                egopulse_domain_contracts::v01::egopulse::localapi::v1::RevokeMemoryCommand {
                    memory_id: "memory-1".to_owned(),
                    expected_revision: 2,
                    evidence_ref: "evidence:founder-revoke-1".to_owned(),
                    idempotency_key: "revoke-1".to_owned(),
                    ..Default::default()
                },
            )),
        };
        let revoked = adapter
            .execute(
                &revoke,
                &principal_with_id("governance-local", "MemoryAuthority.FounderAuthority"),
            )
            .expect("revoke receipt");
        assert_eq!(revoked.state, "revoked");
        assert_eq!(revoked.revision, 3);
        drop(authority);
        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn candidate_adapter_rejects_a_governance_only_principal_constraint() {
        let database_path = database_path();
        let authority = Arc::new(Mutex::new(
            MemoryAuthority::open(MemoryAuthorityConfig {
                database_path: database_path.clone(),
                store_epoch: "memory-gateway-test-reject".to_owned(),
                key: SqlCipherKey::new([0x72; 32]),
            })
            .expect("memory authority"),
        ));
        let resolver = Arc::new(
            crate::ConfiguredAuthorityPrincipalResolver::new([crate::AuthorityPrincipalBinding {
                principal_id: "founder-local".to_owned(),
                task: None,
                policy: None,
                verdict: None,
                memory: Some(MemoryPrincipalKind::FounderAuthority),
            }])
            .expect("memory principal resolver"),
        );
        let adapter = MemoryMutationPortAdapter::new(authority, resolver);
        let command = MemoryMutationCommand {
            command: Some(memory_mutation_command::Command::SubmitMemoryCandidate(
                SubmitMemoryCandidateCommand::default(),
            )),
        };
        assert_eq!(
            adapter
                .execute(&command, &principal("MemoryAuthority.FounderAuthority"),)
                .expect_err("candidate must require Founder"),
            CommandPortFailure::IntegrityFailure
        );
        let _ = std::fs::remove_file(database_path);
    }
}
