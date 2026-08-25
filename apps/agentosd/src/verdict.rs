use egopulse_cognition_runtime::task_authority::{TaskAuthority, TaskAuthorityFailure};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm, LineageBinding},
    common::v1::ContractReference,
    verdict::v1::{
        ConfirmationClass, FounderVerdictDecision, IssueFounderVerdictCommand, VerdictScope,
    },
    verification::v1::{VerificationArtifact, VerificationConclusion},
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, ResolvedVerdictContext,
    VerdictPrincipalKind, VerdictReferenceRejection, VerdictReferenceResolver,
};
use egopulse_verification_authority::{
    VerificationAuthority, VerificationAuthorityFailure, VerificationClock,
};
use thiserror::Error;

/// Cross-authority reads are expressed as evidence-source traits. A resolver
/// never receives another Authority's database connection and cannot repair
/// the evidence it reads.
pub trait FounderVerificationEvidenceSource: Send + Sync + 'static {
    fn verification_artifact(
        &self,
        verification_artifact_id: &str,
    ) -> Result<Option<VerificationArtifact>, FounderVerificationEvidenceError>;
}

/// The Task Authority owns commit receipts. Founder Verdict only asks that
/// owner to validate the exact receipt; it does not infer success from task
/// fields or from the local client.
pub trait FounderTaskCommitEvidenceSource: Send + Sync + 'static {
    fn validate_task_commit(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection>;
}

/// Provider-neutral Task commit receipt reader backed by the owning Task
/// Authority. The caller shares the Authority's single-writer handle; no
/// second database connection or repair path is introduced.
pub struct TaskAuthorityCommitReceiptSource {
    authority: Arc<Mutex<TaskAuthority>>,
}

impl TaskAuthorityCommitReceiptSource {
    #[must_use]
    pub fn new(authority: Arc<Mutex<TaskAuthority>>) -> Self {
        Self { authority }
    }
}

impl FounderTaskCommitEvidenceSource for TaskAuthorityCommitReceiptSource {
    fn validate_task_commit(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        if scope.task_id.trim().is_empty()
            || scope.task_revision == 0
            || command.task_event_id.trim().is_empty()
            || command.task_commit_receipt_ref.trim().is_empty()
            || command.consumed_task_revision != scope.task_revision
            || command.resulting_task_revision != command.consumed_task_revision + 1
        {
            return Err(VerdictReferenceRejection::TaskCommitReceiptInvalid);
        }
        let event_id = command
            .task_commit_receipt_ref
            .strip_prefix("task-commit:")
            .filter(|value| !value.trim().is_empty())
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)?;
        if event_id != command.task_event_id {
            return Err(VerdictReferenceRejection::TaskCommitReceiptInvalid);
        }
        let committed = self
            .authority
            .lock()
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .commit_receipt_exists(event_id, &scope.task_id, command.resulting_task_revision)
            .map_err(|error| match error {
                TaskAuthorityFailure::Storage
                | TaskAuthorityFailure::Decode(_)
                | TaskAuthorityFailure::InvalidCrossAuthorityHandoff
                | TaskAuthorityFailure::Clock => VerdictReferenceRejection::IntegrityFailure,
            })?;
        committed
            .then_some(())
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FounderVerificationEvidenceError {
    #[error("verification artifact evidence is unavailable or corrupt")]
    IntegrityFailure,
}

/// Adapter from the owning Verification Authority to the provider-neutral
/// evidence boundary used by the Verdict Authority.
pub struct VerificationAuthorityArtifactSource<
    C = egopulse_verification_authority::SystemVerificationClock,
> where
    C: VerificationClock,
{
    authority: Arc<Mutex<VerificationAuthority<C>>>,
}

impl<C> VerificationAuthorityArtifactSource<C>
where
    C: VerificationClock,
{
    #[must_use]
    pub fn new(authority: VerificationAuthority<C>) -> Self {
        Self::new_shared(Arc::new(Mutex::new(authority)))
    }

    #[must_use]
    pub fn new_shared(authority: Arc<Mutex<VerificationAuthority<C>>>) -> Self {
        Self { authority }
    }
}

impl<C> FounderVerificationEvidenceSource for VerificationAuthorityArtifactSource<C>
where
    C: VerificationClock,
{
    fn verification_artifact(
        &self,
        verification_artifact_id: &str,
    ) -> Result<Option<VerificationArtifact>, FounderVerificationEvidenceError> {
        self.authority
            .lock()
            .map_err(|_| FounderVerificationEvidenceError::IntegrityFailure)?
            .verification_artifact(verification_artifact_id)
            .map_err(|error| match error {
                VerificationAuthorityFailure::Storage
                | VerificationAuthorityFailure::Decode(_)
                | VerificationAuthorityFailure::PolicyDecode => {
                    FounderVerificationEvidenceError::IntegrityFailure
                }
            })
    }
}

/// Explicitly denies verdict consumption until the Task Authority commit
/// receipt source is composed. This is safer than treating a receipt-shaped
/// client string as evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyFounderTaskCommitEvidence;

impl FounderTaskCommitEvidenceSource for DenyFounderTaskCommitEvidence {
    fn validate_task_commit(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    }
}

/// Founder reference resolver for the first vertical. It binds a verdict to
/// a durable Verification artifact, an explicitly allowlisted Founder
/// confirmation proof, and a bounded validity interval.
pub struct ConfiguredFounderVerdictResolver {
    verification_source: Box<dyn FounderVerificationEvidenceSource>,
    task_commit_source: Box<dyn FounderTaskCommitEvidenceSource>,
    allowed_founder_principal_ids: BTreeSet<String>,
    authority_ref: String,
    authority_policy_ref: ContractReference,
    allowed_confirmation_proof_refs: BTreeSet<String>,
    non_overridable_gate_ids: BTreeSet<String>,
    confirmation_ttl: Duration,
}

impl ConfiguredFounderVerdictResolver {
    pub fn new(
        config: ConfiguredFounderVerdictResolverConfig,
    ) -> Result<Self, FounderVerdictConfigurationError> {
        if config.allowed_founder_principal_ids.is_empty()
            || config
                .allowed_founder_principal_ids
                .iter()
                .any(|value| value.trim().is_empty())
            || config.authority_ref.trim().is_empty()
            || !contract_reference_is_complete(&config.authority_policy_ref)
            || config.allowed_confirmation_proof_refs.is_empty()
            || config
                .allowed_confirmation_proof_refs
                .iter()
                .any(|value| value.trim().is_empty())
            || config.confirmation_ttl.is_zero()
            || config.confirmation_ttl > Duration::from_secs(24 * 60 * 60)
            || config
                .non_overridable_gate_ids
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(FounderVerdictConfigurationError::InvalidConfiguration);
        }
        Ok(Self {
            verification_source: config.verification_source,
            task_commit_source: config.task_commit_source,
            allowed_founder_principal_ids: config.allowed_founder_principal_ids,
            authority_ref: config.authority_ref,
            authority_policy_ref: config.authority_policy_ref,
            allowed_confirmation_proof_refs: config.allowed_confirmation_proof_refs,
            non_overridable_gate_ids: config.non_overridable_gate_ids,
            confirmation_ttl: config.confirmation_ttl,
        })
    }
}

pub struct ConfiguredFounderVerdictResolverConfig {
    pub verification_source: Box<dyn FounderVerificationEvidenceSource>,
    pub task_commit_source: Box<dyn FounderTaskCommitEvidenceSource>,
    pub allowed_founder_principal_ids: BTreeSet<String>,
    pub authority_ref: String,
    pub authority_policy_ref: ContractReference,
    pub allowed_confirmation_proof_refs: BTreeSet<String>,
    pub non_overridable_gate_ids: BTreeSet<String>,
    pub confirmation_ttl: Duration,
}

impl VerdictReferenceResolver for ConfiguredFounderVerdictResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Err(VerdictReferenceRejection::Unauthenticated);
        }
        if principal.kind != VerdictPrincipalKind::FounderAuthority
            || !self
                .allowed_founder_principal_ids
                .contains(&principal.principal_id)
        {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        let scope = command
            .scope
            .as_ref()
            .ok_or(VerdictReferenceRejection::ScopeStale)?;
        let artifact = self
            .verification_source
            .verification_artifact(&scope.verification_artifact_id)
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .ok_or(VerdictReferenceRejection::NotFound)?;
        let provenance = artifact
            .provenance
            .as_ref()
            .filter(|value| !value.verifier_principal_id.trim().is_empty())
            .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
        if !artifact_matches_scope(&artifact, scope) {
            return Err(VerdictReferenceRejection::ScopeStale);
        }
        let conclusion = VerificationConclusion::try_from(artifact.conclusion)
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?;
        if conclusion == VerificationConclusion::Unspecified
            || conclusion as i32 != command.observed_verification_conclusion
        {
            return Err(VerdictReferenceRejection::VerificationMismatch);
        }
        if !self
            .allowed_confirmation_proof_refs
            .contains(&command.confirmation_proof_ref)
        {
            return Err(VerdictReferenceRejection::ConfirmationRequired);
        }
        let decision = FounderVerdictDecision::try_from(command.decision)
            .map_err(|_| VerdictReferenceRejection::ConfirmationRequired)?;
        if decision == FounderVerdictDecision::Unspecified {
            return Err(VerdictReferenceRejection::ConfirmationRequired);
        }
        let confirmation_class = if decision == FounderVerdictDecision::Accept
            && conclusion != VerificationConclusion::Passed
        {
            ConfirmationClass::ElevatedRiskAcceptance
        } else {
            ConfirmationClass::Explicit
        };
        let now = current_timestamp()?;
        let valid_until = command
            .expires_at
            .ok_or(VerdictReferenceRejection::ConfirmationRequired)?;
        let maximum_valid_until = timestamp_after(&now, self.confirmation_ttl)?;
        if !timestamp_is_after(&valid_until, &now)
            || timestamp_is_after(&valid_until, &maximum_valid_until)
        {
            return Err(VerdictReferenceRejection::ConfirmationRequired);
        }
        let open_discrepancy_ids = unique_ids(
            artifact
                .discrepancies
                .iter()
                .map(|value| value.discrepancy_id.as_str()),
        )?;
        let open_unverified_item_ids = unique_ids(
            artifact
                .unverified_items
                .iter()
                .map(|value| value.unverified_item_id.as_str()),
        )?;
        Ok((
            ResolvedVerdictContext {
                scope: scope.clone(),
                verification_conclusion: conclusion,
                open_discrepancy_ids,
                open_unverified_item_ids,
                non_overridable_gate_ids: self.non_overridable_gate_ids.iter().cloned().collect(),
            },
            FounderAuthorization {
                authenticated_founder_principal_id: principal.principal_id.clone(),
                authority_ref: self.authority_ref.clone(),
                confirmation_class,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: now,
                valid_until,
                authority_policy_ref: self.authority_policy_ref.clone(),
                evidence_refs: vec![
                    format!(
                        "verification-artifact:{}@durable",
                        artifact.verification_artifact_id
                    ),
                    format!(
                        "verification-provenance:{}@durable",
                        provenance.verifier_principal_id
                    ),
                    format!(
                        "founder-confirmation:{}@configured",
                        command.confirmation_proof_ref
                    ),
                ],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        self.task_commit_source.validate_task_commit(command, scope)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FounderVerdictConfigurationError {
    #[error("configured Founder Verdict resolver is invalid")]
    InvalidConfiguration,
}

fn artifact_matches_scope(artifact: &VerificationArtifact, scope: &VerdictScope) -> bool {
    if artifact.verification_artifact_id != scope.verification_artifact_id
        || artifact.version != 1
        || !content_address_is_complete(artifact.canonical_payload.as_ref())
    {
        return false;
    }
    let Some(binding) = artifact.binding.as_ref() else {
        return false;
    };
    let Some(lineage) = binding.lineage.as_ref() else {
        return false;
    };
    lineage_matches_scope(lineage, scope)
        && binding.artifact_set_id == scope.artifact_set_id
        && binding.artifact_set_manifest == scope.artifact_set_manifest
        && binding.acceptance_contract_ref == scope.acceptance_contract_ref
}

fn lineage_matches_scope(lineage: &LineageBinding, scope: &VerdictScope) -> bool {
    lineage.task_id == scope.task_id
        && lineage.task_revision == scope.task_revision
        && lineage.work_revision == scope.work_revision
}

fn content_address_is_complete(address: Option<&ContentAddress>) -> bool {
    address.is_some_and(|value| {
        value.algorithm == HashAlgorithm::Sha256 as i32
            && value.digest.len() == 64
            && value.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            && value.byte_length > 0
    })
}

fn contract_reference_is_complete(reference: &ContractReference) -> bool {
    !reference.contract_id.trim().is_empty()
        && !reference.version.trim().is_empty()
        && reference.sha256.len() == 64
        && reference
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn unique_ids<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Vec<String>, VerdictReferenceRejection> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for value in values {
        if value.trim().is_empty() || !seen.insert(value) {
            return Err(VerdictReferenceRejection::IntegrityFailure);
        }
        output.push(value.to_owned());
    }
    Ok(output)
}

fn current_timestamp() -> Result<prost_types::Timestamp, VerdictReferenceRejection> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?;
    Ok(prost_types::Timestamp {
        seconds: i64::try_from(duration.as_secs())
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?,
        nanos: i32::try_from(duration.subsec_nanos())
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?,
    })
}

fn timestamp_after(
    now: &prost_types::Timestamp,
    ttl: Duration,
) -> Result<prost_types::Timestamp, VerdictReferenceRejection> {
    Ok(prost_types::Timestamp {
        seconds: now
            .seconds
            .checked_add(
                i64::try_from(ttl.as_secs())
                    .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?,
            )
            .ok_or(VerdictReferenceRejection::IntegrityFailure)?,
        nanos: now.nanos,
    })
}

fn timestamp_is_after(left: &prost_types::Timestamp, right: &prost_types::Timestamp) -> bool {
    (left.seconds, left.nanos) > (right.seconds, right.nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{ContentAddress, LineageBinding},
        common::v1::ContractReference,
        verdict::v1::{ConsumeFounderVerdictCommand, FounderVerdictDecision},
        verification::v1::{VerificationBinding, VerificationProvenance},
    };

    struct StaticEvidence(VerificationArtifact);

    impl FounderVerificationEvidenceSource for StaticEvidence {
        fn verification_artifact(
            &self,
            verification_artifact_id: &str,
        ) -> Result<Option<VerificationArtifact>, FounderVerificationEvidenceError> {
            Ok(
                (self.0.verification_artifact_id == verification_artifact_id)
                    .then(|| self.0.clone()),
            )
        }
    }

    fn contract(id: &str, byte: u8) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: hex::encode([byte; 32]),
        }
    }

    fn address(byte: u8) -> ContentAddress {
        ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: hex::encode([byte; 32]),
            byte_length: 1,
        }
    }

    fn scope() -> VerdictScope {
        VerdictScope {
            task_id: "task-1".to_owned(),
            task_revision: 3,
            work_revision: 2,
            artifact_set_id: "artifact-set-1".to_owned(),
            artifact_set_manifest: Some(address(0x11)),
            verification_artifact_id: "verification-artifact-1".to_owned(),
            verification_payload: Some(address(0x22)),
            acceptance_contract_ref: Some(contract("acceptance", 0x33)),
        }
    }

    fn artifact() -> VerificationArtifact {
        let scope = scope();
        VerificationArtifact {
            verification_artifact_id: scope.verification_artifact_id.clone(),
            version: 1,
            verification_request_id: "verification-request-1".to_owned(),
            verification_run_id: "verification-run-1".to_owned(),
            verification_type: "repository-change".to_owned(),
            binding: Some(VerificationBinding {
                lineage: Some(LineageBinding {
                    task_id: scope.task_id,
                    task_revision: scope.task_revision,
                    work_revision: scope.work_revision,
                    ..Default::default()
                }),
                artifact_set_id: scope.artifact_set_id,
                artifact_set_manifest: scope.artifact_set_manifest,
                acceptance_contract_ref: scope.acceptance_contract_ref,
                ..Default::default()
            }),
            conclusion: VerificationConclusion::Passed as i32,
            provenance: Some(VerificationProvenance {
                verifier_principal_id: "sego:checker-1".to_owned(),
                ..Default::default()
            }),
            canonical_payload: Some(address(0x44)),
            ..Default::default()
        }
    }

    fn resolver() -> ConfiguredFounderVerdictResolver {
        ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
            verification_source: Box::new(StaticEvidence(artifact())),
            task_commit_source: Box::new(DenyFounderTaskCommitEvidence),
            allowed_founder_principal_ids: BTreeSet::from(["founder:local".to_owned()]),
            authority_ref: "founder-authority:v01".to_owned(),
            authority_policy_ref: contract("founder-policy", 0x55),
            allowed_confirmation_proof_refs: BTreeSet::from(["confirm:local:1".to_owned()]),
            non_overridable_gate_ids: BTreeSet::new(),
            confirmation_ttl: Duration::from_secs(600),
        })
        .expect("valid verdict resolver")
    }

    fn issue() -> IssueFounderVerdictCommand {
        let expiry = current_timestamp().expect("clock");
        let expiry = timestamp_after(&expiry, Duration::from_secs(300)).expect("expiry");
        IssueFounderVerdictCommand {
            scope: Some(scope()),
            decision: FounderVerdictDecision::Accept as i32,
            observed_verification_conclusion: VerificationConclusion::Passed as i32,
            required_confirmation_class: ConfirmationClass::Explicit as i32,
            confirmation_proof_ref: "confirm:local:1".to_owned(),
            expires_at: Some(expiry),
            ..Default::default()
        }
    }

    fn founder() -> AuthenticatedVerdictPrincipal {
        AuthenticatedVerdictPrincipal {
            kind: VerdictPrincipalKind::FounderAuthority,
            principal_id: "founder:local".to_owned(),
            authenticated: true,
        }
    }

    #[test]
    fn resolver_binds_founder_verdict_to_durable_verification_artifact() {
        let (context, authorization) = resolver()
            .resolve_issue(&issue(), &founder())
            .expect("artifact-backed verdict authorization");
        assert_eq!(context.scope.task_id, "task-1");
        assert_eq!(
            context.verification_conclusion,
            VerificationConclusion::Passed
        );
        assert_eq!(
            authorization.confirmation_class,
            ConfirmationClass::Explicit
        );
        assert_eq!(authorization.evidence_refs.len(), 3);
    }

    #[test]
    fn resolver_rejects_verification_conclusion_drift() {
        let mut command = issue();
        command.observed_verification_conclusion = VerificationConclusion::Partial as i32;
        let error = resolver()
            .resolve_issue(&command, &founder())
            .expect_err("conclusion drift must be rejected");
        assert_eq!(error, VerdictReferenceRejection::VerificationMismatch);
    }

    #[test]
    fn resolver_rejects_unallowlisted_confirmation() {
        let mut command = issue();
        command.confirmation_proof_ref = "confirm:unknown".to_owned();
        let error = resolver()
            .resolve_issue(&command, &founder())
            .expect_err("unallowlisted confirmation must be rejected");
        assert_eq!(error, VerdictReferenceRejection::ConfirmationRequired);
    }

    #[test]
    fn task_consumption_remains_fail_closed_without_task_receipt_source() {
        let error = resolver()
            .validate_task_commit(&ConsumeFounderVerdictCommand::default(), &scope())
            .expect_err("task receipt source is not configured");
        assert_eq!(error, VerdictReferenceRejection::TaskCommitReceiptInvalid);
    }
}
