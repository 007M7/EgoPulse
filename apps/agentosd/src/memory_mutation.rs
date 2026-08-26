use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use egopulse_cognition_runtime::memory_authority::{
    AuthenticatedMemoryPrincipal, GovernMemory, MemoryAuthority, MemoryAuthorityFailure,
    MemoryMutationReceipt as AuthorityMemoryMutationReceipt, MemoryPrincipalKind,
    SubmitMemoryCandidate,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    MemoryMutationCommand, MemoryMutationReceipt, memory_mutation_command,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, MemoryMutationPort,
};

use crate::AuthorityPrincipalResolver;

/// Fixed identity binding for an internal candidate producer.
///
/// `producer_id` is an application-owned route, not a field supplied by a
/// model or a Local API client. The binding is resolved during composition and
/// the resulting port never accepts a caller-selected principal. This keeps
/// Agent/Model/Harness proposals inside the Memory Authority boundary while
/// leaving acceptance and revocation to the governance path below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCandidateProducerBinding {
    pub producer_id: String,
    pub principal_id: String,
    pub principal_kind: MemoryPrincipalKind,
    pub scope_ref: String,
}

impl MemoryCandidateProducerBinding {
    pub fn new(
        producer_id: impl Into<String>,
        principal_id: impl Into<String>,
        principal_kind: MemoryPrincipalKind,
        scope_ref: impl Into<String>,
    ) -> Result<Self, MemoryCandidateProducerConfigurationError> {
        let binding = Self {
            producer_id: producer_id.into(),
            principal_id: principal_id.into(),
            principal_kind,
            scope_ref: scope_ref.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), MemoryCandidateProducerConfigurationError> {
        validate_identifier(&self.producer_id, "producer_id")?;
        validate_identifier(&self.principal_id, "principal_id")?;
        validate_identifier(&self.scope_ref, "scope_ref")?;
        if !matches!(
            self.principal_kind,
            MemoryPrincipalKind::Agent | MemoryPrincipalKind::Model | MemoryPrincipalKind::Harness
        ) {
            return Err(MemoryCandidateProducerConfigurationError::UnsupportedPrincipalKind);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MemoryCandidateProducerConfigurationError {
    #[error("memory candidate producer {0} is empty or exceeds 128 bytes")]
    InvalidIdentifier(&'static str),
    #[error("memory candidate producer must use Agent, Model, or Harness identity")]
    UnsupportedPrincipalKind,
    #[error("memory candidate producer id is registered more than once: {0}")]
    DuplicateProducer(String),
    #[error("at least one memory candidate producer binding is required")]
    EmptyRegistration,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MemoryCandidateProducerFailure {
    #[error("memory candidate producer is not configured: {0}")]
    UnknownProducer(String),
    #[error(transparent)]
    Authority(#[from] MemoryAuthorityFailure),
    #[error("memory candidate producer is not authorized for the requested scope")]
    ScopeViolation,
}

/// Narrow internal write capability granted to a candidate producer. There is
/// intentionally no accept/revoke method and no principal argument.
pub trait MemoryCandidateProducerPort: Send + Sync {
    fn submit_candidate(
        &self,
        command: &SubmitMemoryCandidate,
    ) -> Result<AuthorityMemoryMutationReceipt, MemoryCandidateProducerFailure>;
}

/// An explicit application-level proposal from an admitted Agent/Model/Harness
/// runtime. Scope is intentionally absent: it is supplied by the fixed
/// producer handle created during composition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryCandidateProposal {
    pub memory_id: String,
    pub content: String,
    pub source_ref: String,
    pub idempotency_key: String,
}

/// A capability narrowed to one already-admitted producer route. Provider
/// runtimes should receive this handle during composition instead of keeping
/// the whole registry, so a runtime cannot switch to another producer's
/// identity by changing a request field.
#[derive(Clone)]
pub struct MemoryCandidateProducerHandle {
    producer: Arc<dyn MemoryCandidateProducerPort>,
    scope_ref: String,
}

impl MemoryCandidateProducerHandle {
    /// Submits an explicit proposal using the scope fixed at composition time.
    /// The returned state is always candidate; this handle has no governance
    /// capability.
    pub fn submit_proposal(
        &self,
        proposal: &MemoryCandidateProposal,
    ) -> Result<AuthorityMemoryMutationReceipt, MemoryCandidateProducerFailure> {
        self.submit_candidate(&SubmitMemoryCandidate {
            memory_id: proposal.memory_id.clone(),
            content: proposal.content.clone(),
            source_ref: proposal.source_ref.clone(),
            scope_ref: self.scope_ref.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
        })
    }

    pub(crate) fn submit_candidate(
        &self,
        command: &SubmitMemoryCandidate,
    ) -> Result<AuthorityMemoryMutationReceipt, MemoryCandidateProducerFailure> {
        self.producer.submit_candidate(command)
    }
}

struct ConfiguredMemoryCandidateProducer {
    authority: Arc<Mutex<MemoryAuthority>>,
    principal: AuthenticatedMemoryPrincipal,
    scope_ref: String,
}

impl ConfiguredMemoryCandidateProducer {
    fn new(
        authority: Arc<Mutex<MemoryAuthority>>,
        binding: &MemoryCandidateProducerBinding,
    ) -> Self {
        Self {
            authority,
            principal: AuthenticatedMemoryPrincipal {
                kind: binding.principal_kind,
                principal_id: binding.principal_id.clone(),
                authenticated: true,
            },
            scope_ref: binding.scope_ref.clone(),
        }
    }
}

impl MemoryCandidateProducerPort for ConfiguredMemoryCandidateProducer {
    fn submit_candidate(
        &self,
        command: &SubmitMemoryCandidate,
    ) -> Result<AuthorityMemoryMutationReceipt, MemoryCandidateProducerFailure> {
        if command.scope_ref != self.scope_ref {
            return Err(MemoryCandidateProducerFailure::ScopeViolation);
        }
        let mut authority = self.authority.lock().map_err(|_| {
            MemoryCandidateProducerFailure::Authority(MemoryAuthorityFailure::Storage)
        })?;
        authority
            .submit_candidate(command, &self.principal)
            .map_err(MemoryCandidateProducerFailure::Authority)
    }
}

/// Composition-time registry for future Agent/Model/Harness runtimes.
///
/// This is deliberately not exposed through the protobuf Local API. A runtime
/// receives a registry handle only after its producer identity has been
/// explicitly admitted and bound to one fixed Memory principal.
#[derive(Clone, Default)]
pub struct MemoryCandidateProducerRegistry {
    producers: Arc<BTreeMap<String, Arc<dyn MemoryCandidateProducerPort>>>,
    scope_refs: Arc<BTreeMap<String, String>>,
}

impl MemoryCandidateProducerRegistry {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new<I>(
        authority: Arc<Mutex<MemoryAuthority>>,
        bindings: I,
    ) -> Result<Self, MemoryCandidateProducerConfigurationError>
    where
        I: IntoIterator<Item = MemoryCandidateProducerBinding>,
    {
        let mut producers = BTreeMap::new();
        let mut scope_refs = BTreeMap::new();
        for binding in bindings {
            binding.validate()?;
            if producers.contains_key(&binding.producer_id) {
                return Err(
                    MemoryCandidateProducerConfigurationError::DuplicateProducer(
                        binding.producer_id,
                    ),
                );
            }
            let producer_id = binding.producer_id.clone();
            let producer = ConfiguredMemoryCandidateProducer::new(Arc::clone(&authority), &binding);
            producers.insert(
                producer_id.clone(),
                Arc::new(producer) as Arc<dyn MemoryCandidateProducerPort>,
            );
            scope_refs.insert(producer_id, binding.scope_ref);
        }
        if producers.is_empty() {
            return Err(MemoryCandidateProducerConfigurationError::EmptyRegistration);
        }
        Ok(Self {
            producers: Arc::new(producers),
            scope_refs: Arc::new(scope_refs),
        })
    }

    pub fn bind_producer(
        &self,
        producer_id: &str,
    ) -> Result<MemoryCandidateProducerHandle, MemoryCandidateProducerFailure> {
        Ok(MemoryCandidateProducerHandle {
            producer: Arc::clone(self.producers.get(producer_id).ok_or_else(|| {
                MemoryCandidateProducerFailure::UnknownProducer(producer_id.to_owned())
            })?),
            scope_ref: self.scope_refs.get(producer_id).cloned().ok_or_else(|| {
                MemoryCandidateProducerFailure::UnknownProducer(producer_id.to_owned())
            })?,
        })
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), MemoryCandidateProducerConfigurationError> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(MemoryCandidateProducerConfigurationError::InvalidIdentifier(field));
    }
    Ok(())
}

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
        memory_authority::{MemoryAuthorityConfig, MemoryState},
        task_authority::SqlCipherKey,
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

    #[test]
    fn producer_registry_routes_candidates_with_fixed_agent_model_and_harness_identities() {
        let database_path = database_path();
        let authority = Arc::new(Mutex::new(
            MemoryAuthority::open(MemoryAuthorityConfig {
                database_path: database_path.clone(),
                store_epoch: "memory-producer-registry-test".to_owned(),
                key: SqlCipherKey::new([0x73; 32]),
            })
            .expect("memory authority"),
        ));
        let registry = MemoryCandidateProducerRegistry::new(
            Arc::clone(&authority),
            [
                MemoryCandidateProducerBinding::new(
                    "agent:planner",
                    "agent-planner-v1",
                    MemoryPrincipalKind::Agent,
                    "scope:founder",
                )
                .expect("agent binding"),
                MemoryCandidateProducerBinding::new(
                    "model:reasoner",
                    "model-reasoner-v1",
                    MemoryPrincipalKind::Model,
                    "scope:founder",
                )
                .expect("model binding"),
                MemoryCandidateProducerBinding::new(
                    "harness:codex",
                    "harness-codex-v1",
                    MemoryPrincipalKind::Harness,
                    "scope:founder",
                )
                .expect("harness binding"),
            ],
        )
        .expect("producer registry");

        for (producer_id, memory_id) in [
            ("agent:planner", "memory-agent"),
            ("model:reasoner", "memory-model"),
            ("harness:codex", "memory-harness"),
        ] {
            let producer = registry
                .bind_producer(producer_id)
                .expect("producer handle");
            let command = SubmitMemoryCandidate {
                memory_id: memory_id.to_owned(),
                content: format!("candidate from {producer_id}"),
                source_ref: format!("source:{producer_id}"),
                scope_ref: "scope:founder".to_owned(),
                idempotency_key: format!("idempotency:{producer_id}"),
            };
            let receipt = producer
                .submit_candidate(&command)
                .expect("candidate receipt");
            assert_eq!(
                receipt.state,
                egopulse_cognition_runtime::memory_authority::MemoryState::Candidate
            );
            assert_eq!(
                producer
                    .submit_candidate(&command)
                    .expect("idempotent producer replay"),
                receipt
            );
        }

        let proposal = MemoryCandidateProposal {
            memory_id: "memory-fixed-scope".to_owned(),
            content: "explicit proposal uses the bound scope".to_owned(),
            source_ref: "source:harness-codex".to_owned(),
            idempotency_key: "idempotency:fixed-scope".to_owned(),
        };
        let codex = registry
            .bind_producer("harness:codex")
            .expect("Codex producer handle");
        let proposal_receipt = codex.submit_proposal(&proposal).expect("proposal receipt");
        assert_eq!(proposal_receipt.state, MemoryState::Candidate);

        let wrong_scope = SubmitMemoryCandidate {
            memory_id: "memory-wrong-scope".to_owned(),
            content: "candidate".to_owned(),
            source_ref: "source:agent".to_owned(),
            scope_ref: "scope:other".to_owned(),
            idempotency_key: "idempotency:wrong-scope".to_owned(),
        };
        assert_eq!(
            registry
                .bind_producer("agent:planner")
                .expect("planner producer handle")
                .submit_candidate(&wrong_scope)
                .expect_err("producer scope must be fixed"),
            MemoryCandidateProducerFailure::ScopeViolation
        );

        match registry.bind_producer("unknown:producer") {
            Err(error) => assert_eq!(
                error,
                MemoryCandidateProducerFailure::UnknownProducer("unknown:producer".to_owned())
            ),
            Ok(_) => panic!("unknown producer must fail closed"),
        }

        drop(authority);
        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn producer_binding_rejects_governance_identities_and_duplicate_routes() {
        assert_eq!(
            MemoryCandidateProducerBinding::new(
                "founder:local",
                "founder-local",
                MemoryPrincipalKind::Founder,
                "scope:founder",
            )
            .expect_err("Founder cannot be registered as a producer"),
            MemoryCandidateProducerConfigurationError::UnsupportedPrincipalKind
        );
        assert_eq!(
            MemoryCandidateProducerBinding::new(
                " ",
                "agent-1",
                MemoryPrincipalKind::Agent,
                "scope:founder",
            )
            .expect_err("empty producer route must fail"),
            MemoryCandidateProducerConfigurationError::InvalidIdentifier("producer_id")
        );

        let database_path = database_path();
        let authority = Arc::new(Mutex::new(
            MemoryAuthority::open(MemoryAuthorityConfig {
                database_path: database_path.clone(),
                store_epoch: "memory-producer-duplicate-test".to_owned(),
                key: SqlCipherKey::new([0x74; 32]),
            })
            .expect("memory authority"),
        ));
        let first = MemoryCandidateProducerBinding::new(
            "agent:planner",
            "agent-planner-v1",
            MemoryPrincipalKind::Agent,
            "scope:founder",
        )
        .expect("first binding");
        let second = MemoryCandidateProducerBinding::new(
            "agent:planner",
            "agent-planner-v2",
            MemoryPrincipalKind::Agent,
            "scope:founder",
        )
        .expect("second binding");
        match MemoryCandidateProducerRegistry::new(authority, [first, second]) {
            Err(error) => assert_eq!(
                error,
                MemoryCandidateProducerConfigurationError::DuplicateProducer(
                    "agent:planner".to_owned(),
                )
            ),
            Ok(_) => panic!("duplicate route must fail"),
        }
        let _ = std::fs::remove_file(database_path);
    }
}
