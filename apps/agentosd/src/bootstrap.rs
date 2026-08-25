use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use egopulse_cognition_runtime::task_authority::{
    TaskAuthority, TaskAuthorityConfig, TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CheckerProfile, VerificationBinding, VerificationRequest,
};
use egopulse_founder_verdict_authority::{FounderVerdictAuthority, VerdictAuthorityConfig};
use egopulse_harness_adapter::{AdapterEdge, AdapterEdgeConfig, AdapterEdgeError};
use egopulse_local_api::session::{NoopSessionAuditSink, SystemSessionClock};
use egopulse_policy_decision_authority::{
    PolicyAuthorityConfig, PolicyAuthorityFailure, PolicyDecisionAuthority,
};
use egopulse_verification_authority::{
    ReferenceRejection, ResolvedVerificationInput, VerificationAuthority,
    VerificationAuthorityConfig, VerificationAuthorityFailure, VerificationReferenceResolver,
};
use thiserror::Error;

use crate::{AllowlistedPrincipal, AllowlistedPrincipalResolver, PrincipalPolicyError};
use crate::{
    AuthorityPrincipalBinding, CodexHarnessCompositionConfig, ConfiguredAuthorityPrincipalResolver,
    ConfiguredFounderVerdictResolver, ConfiguredFounderVerdictResolverConfig,
    ConfiguredTaskCreationGuard, ConfiguredTaskCreationGuardConfig, DaemonCompositionError,
    DaemonProviders, FounderVerdictConfigurationError, LocalUserPolicyResolver,
    LocalUserPolicyResolverConfig, SharedAuthorityCompositionInputs,
    TaskAuthorityCommitReceiptSource, VerificationAuthorityArtifactSource,
    VerificationProjectionSource,
};

/// Explicit scalar configuration for the local-user Policy resolver. The
/// Adapter edge is opened by the composition root so the resolver reads the
/// same durable adapter store as the Codex Harness composition.
pub struct LocalUserPolicyBootstrapConfig {
    pub edge: AdapterEdgeConfig,
    pub authentication_context_ref: String,
    pub authorization_policy_ref: ContractReference,
    pub allowed_scope_refs: BTreeSet<String>,
    pub decision_ttl: Duration,
}

/// Inputs owned by the local installation, not inferred from a client request.
pub struct ProductionBootstrapConfig {
    pub task: TaskAuthorityConfig,
    pub task_guard: ConfiguredTaskCreationGuardConfig,
    pub verification: VerificationAuthorityConfig,
    pub policy: PolicyAuthorityConfig,
    pub policy_resolver: LocalUserPolicyBootstrapConfig,
    pub verdict: VerdictAuthorityConfig,
    pub allowed_founder_principal_ids: BTreeSet<String>,
    pub founder_authority_ref: String,
    pub founder_authority_policy_ref: ContractReference,
    pub allowed_confirmation_proof_refs: BTreeSet<String>,
    pub non_overridable_gate_ids: BTreeSet<String>,
    pub founder_confirmation_ttl: Duration,
    pub os_principal: AllowlistedPrincipal,
    pub authority_binding: AuthorityPrincipalBinding,
    pub codex: CodexHarnessCompositionConfig,
}

impl ProductionBootstrapConfig {
    /// Opens every Authority exactly once and composes the first production
    /// vertical. Missing or invalid references fail before a serving daemon is
    /// built; no test resolver is used as a production fallback.
    pub fn build(self) -> Result<DaemonProviders, ProductionBootstrapError> {
        let task_guard = ConfiguredTaskCreationGuard::new(self.task_guard)?;
        let task = Arc::new(Mutex::new(TaskAuthority::open(self.task, task_guard)?));

        // Verification is intentionally opened with a deny-by-default
        // reference resolver until the reviewed Sego checker composition is
        // supplied by the verification vertical. It can still persist and
        // project only through its own Authority boundary.
        let verification = Arc::new(Mutex::new(VerificationAuthority::open(
            self.verification,
            DenyVerificationReferences,
        )?));

        let policy_edge = AdapterEdge::open(self.policy_resolver.edge)?;
        let policy_resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge: policy_edge,
            adapter_id: egopulse_codex_adapter::CODEX_ADAPTER_ID.to_owned(),
            authorization_policy_ref: self.policy_resolver.authorization_policy_ref,
            authentication_context_ref: self.policy_resolver.authentication_context_ref,
            allowed_scope_refs: self.policy_resolver.allowed_scope_refs,
            decision_ttl: self.policy_resolver.decision_ttl,
        })?;
        let policy = PolicyDecisionAuthority::open(self.policy, policy_resolver)?;

        let founder_resolver =
            ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
                verification_source: Box::new(VerificationAuthorityArtifactSource::new_shared(
                    Arc::clone(&verification),
                )),
                task_commit_source: Box::new(TaskAuthorityCommitReceiptSource::new(Arc::clone(
                    &task,
                ))),
                allowed_founder_principal_ids: self.allowed_founder_principal_ids,
                authority_ref: self.founder_authority_ref,
                authority_policy_ref: self.founder_authority_policy_ref,
                allowed_confirmation_proof_refs: self.allowed_confirmation_proof_refs,
                non_overridable_gate_ids: self.non_overridable_gate_ids,
                confirmation_ttl: self.founder_confirmation_ttl,
            })?;
        let verdict = FounderVerdictAuthority::open(self.verdict, founder_resolver)?;

        let principal_resolver = Arc::new(ConfiguredAuthorityPrincipalResolver::new([
            self.authority_binding
        ])?);
        let session_principal_resolver =
            Arc::new(AllowlistedPrincipalResolver::new([self.os_principal])?);
        let mut providers =
            DaemonProviders::from_shared_authority_inputs(SharedAuthorityCompositionInputs {
                task,
                policy,
                verdict,
                principal_resolver,
                session_principal_resolver,
                session_clock: Arc::new(SystemSessionClock),
                session_audit: Arc::new(NoopSessionAuditSink),
                additional_projection_sources: vec![Arc::new(
                    VerificationProjectionSource::new_shared(Arc::clone(&verification)),
                )],
            });
        providers = providers.with_codex_harness(self.codex)?;
        Ok(providers)
    }
}

/// Production's temporary verification boundary. It prevents the daemon from
/// accepting client-supplied verification references before the reviewed
/// Sego/checker composition is installed in the next vertical.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyVerificationReferences;

impl VerificationReferenceResolver for DenyVerificationReferences {
    fn validate_checker_profile(
        &self,
        _profile: &CheckerProfile,
    ) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn resolve_request(
        &self,
        _request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn revalidate_binding(&self, _binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }

    fn validate_result_references(
        &self,
        _evidence_ids: &[String],
        _artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        Err(ReferenceRejection::OutputUntrusted)
    }
}

#[derive(Debug, Error)]
pub enum ProductionBootstrapError {
    #[error("Task creation guard configuration is invalid")]
    TaskGuard(#[from] crate::TaskCreationGuardConfigurationError),
    #[error("Task Authority could not be opened")]
    TaskAuthority(#[from] TaskAuthorityFailure),
    #[error("Verification Authority could not be opened")]
    VerificationAuthority(#[from] VerificationAuthorityFailure),
    #[error("Adapter edge for Policy could not be opened")]
    PolicyAdapterEdge(#[source] AdapterEdgeError),
    #[error("local-user Policy resolver configuration is invalid")]
    PolicyResolver(#[from] crate::LocalUserPolicyConfigurationError),
    #[error("Policy Authority could not be opened")]
    PolicyAuthority(#[from] PolicyAuthorityFailure),
    #[error("Founder Verdict resolver configuration is invalid")]
    FounderResolver(#[from] FounderVerdictConfigurationError),
    #[error("Founder Verdict Authority could not be opened")]
    VerdictAuthority(#[from] egopulse_founder_verdict_authority::VerdictAuthorityFailure),
    #[error("principal policy is invalid")]
    PrincipalPolicy(#[from] PrincipalPolicyError),
    #[error("Codex Harness composition is invalid")]
    Codex(#[from] DaemonCompositionError),
}

impl From<AdapterEdgeError> for ProductionBootstrapError {
    fn from(error: AdapterEdgeError) -> Self {
        Self::PolicyAdapterEdge(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationBinding;

    #[test]
    fn production_verification_boundary_denies_all_unreviewed_references() {
        let resolver = DenyVerificationReferences;
        assert_eq!(
            resolver.validate_checker_profile(&CheckerProfile::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.resolve_request(&VerificationRequest::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.revalidate_binding(&VerificationBinding::default()),
            Err(ReferenceRejection::OutputUntrusted)
        );
        assert_eq!(
            resolver.validate_result_references(&[], &[]),
            Err(ReferenceRejection::OutputUntrusted)
        );
    }
}
