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

/// The only Local API adapter that can call Memory Authority mutations. The
/// gateway supplies authorization constraints; this adapter requires one
/// unambiguous Memory principal kind before invoking the owner.
pub struct MemoryMutationPortAdapter {
    authority: Arc<Mutex<MemoryAuthority>>,
}

impl MemoryMutationPortAdapter {
    #[must_use]
    pub fn new(authority: Arc<Mutex<MemoryAuthority>>) -> Self {
        Self { authority }
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
    principal: &CommandPrincipal,
    allowed: &[&str],
) -> Result<MemoryPrincipalKind, CommandPortFailure> {
    let matches = allowed
        .iter()
        .filter(|allowed_kind| {
            principal
                .required_authority_principal_kinds
                .iter()
                .any(|value| value == **allowed_kind)
        })
        .copied()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        ["MemoryAuthority.Founder"] => Ok(MemoryPrincipalKind::Founder),
        ["MemoryAuthority.FounderAuthority"] => Ok(MemoryPrincipalKind::FounderAuthority),
        _ => Err(CommandPortFailure::IntegrityFailure),
    }
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
