use egopulse_cognition_runtime::task_authority::{TaskAuthority, TaskAuthorityFailure};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactDescriptor, ArtifactSemanticClass, ArtifactStatus, ContentAddress, HashAlgorithm,
        IntegrityStatus, LineageBinding,
    },
    common::v1::ContractReference,
    verdict::v1::{
        ConfirmationClass, FounderSupportingMaterial, FounderSupportingMaterialCoverage,
        FounderSupportingMaterialRole, FounderVerdictDecision, IssueFounderVerdictCommand,
        RiskCategory, VerdictScope,
    },
    verification::v1::{
        CriterionOutcome, EvidenceCoverage, VerificationArtifact, VerificationConclusion,
    },
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, ResolvedVerdictContext,
    VerdictPrincipalKind, VerdictReferenceRejection, VerdictReferenceResolver,
};
use egopulse_verification_authority::{
    VerificationAuthority, VerificationAuthorityFailure, VerificationClock,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::founder_material::{
    FounderSupportingMaterialPolicy, MATERIAL_MEDIA_TYPE, MATERIAL_SCHEMA_VERSION,
    founder_supporting_material_artifact_id,
};

/// Cross-authority reads are expressed as evidence-source traits. A resolver
/// never receives another Authority's database connection and cannot repair
/// the evidence it reads.
pub trait FounderVerificationEvidenceSource: Send + Sync + 'static {
    fn verification_artifact(
        &self,
        verification_artifact_id: &str,
    ) -> Result<Option<VerificationArtifact>, FounderVerificationEvidenceError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct FounderSupportingMaterialEvidence {
    pub descriptor: ArtifactDescriptor,
    pub payload: Vec<u8>,
    pub bound_workspace_ref: String,
    pub bound_source_binding_ref: String,
    pub bound_input_artifact_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FounderSupportingMaterialEvidenceError {
    IntegrityFailure,
    Unavailable,
}

pub trait FounderSupportingMaterialSource: Send + Sync + 'static {
    fn material(
        &self,
        artifact_id: &str,
        scope: &VerdictScope,
    ) -> Result<Option<FounderSupportingMaterialEvidence>, FounderSupportingMaterialEvidenceError>;
}

struct SupportingMaterialValidation {
    source: Box<dyn FounderSupportingMaterialSource>,
    policy: FounderSupportingMaterialPolicy,
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

    fn validate_task_commit_before_expiry(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
        _expires_at: &prost_types::Timestamp,
    ) -> Result<(), VerdictReferenceRejection> {
        Err(VerdictReferenceRejection::TaskCommitReceiptInvalid)
    }
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

    fn committed_application(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<
        egopulse_domain_contracts::v01::egopulse::task::v1::TaskEvent,
        VerdictReferenceRejection,
    > {
        if scope.task_id.trim().is_empty()
            || scope.task_revision == 0
            || command.task_event_id.trim().is_empty()
            || command.task_commit_receipt_ref.trim().is_empty()
            || command.consumed_task_revision != scope.task_revision
            || command.consumed_task_revision.checked_add(1)
                != Some(command.resulting_task_revision)
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
        let event = self
            .authority
            .lock()
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .applied_founder_verdict(scope, &command.founder_verdict_id)
            .map_err(|error| match error {
                TaskAuthorityFailure::Storage
                | TaskAuthorityFailure::Decode(_)
                | TaskAuthorityFailure::InvalidCrossAuthorityHandoff
                | TaskAuthorityFailure::Clock => VerdictReferenceRejection::IntegrityFailure,
            })?
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)?;
        let snapshot = event
            .snapshot
            .as_ref()
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)?;
        let status = egopulse_domain_contracts::v01::egopulse::task::v1::TaskStatus::try_from(
            snapshot.status,
        )
        .map_err(|_| VerdictReferenceRejection::TaskCommitReceiptInvalid)?;
        if event.event_id != event_id
            || event.resulting_revision != command.resulting_task_revision
            || status.as_str_name() != command.resulting_task_status
        {
            return Err(VerdictReferenceRejection::TaskCommitReceiptInvalid);
        }
        Ok(event)
    }
}

impl FounderTaskCommitEvidenceSource for TaskAuthorityCommitReceiptSource {
    fn validate_task_commit(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        self.committed_application(command, scope).map(|_| ())
    }

    fn validate_task_commit_before_expiry(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
        expires_at: &prost_types::Timestamp,
    ) -> Result<(), VerdictReferenceRejection> {
        let event = self.committed_application(command, scope)?;
        let at = event
            .occurred_at
            .as_ref()
            .ok_or(VerdictReferenceRejection::TaskCommitReceiptInvalid)?;
        if !(0..1_000_000_000).contains(&expires_at.nanos)
            || (at.seconds, at.nanos) >= (expires_at.seconds, expires_at.nanos)
        {
            return Err(VerdictReferenceRejection::TaskCommitReceiptInvalid);
        }
        Ok(())
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
    non_overridable_criterion_ids: BTreeSet<String>,
    expiry_source: Option<crate::verdict_expiry::FounderVerdictExpiryProofSource>,
    confirmation_ttl: Duration,
    supporting_materials: Option<SupportingMaterialValidation>,
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
            non_overridable_criterion_ids: BTreeSet::new(),
            expiry_source: None,
            confirmation_ttl: config.confirmation_ttl,
            supporting_materials: None,
        })
    }

    pub fn with_supporting_material_source(
        mut self,
        source: Box<dyn FounderSupportingMaterialSource>,
        policy: FounderSupportingMaterialPolicy,
    ) -> Result<Self, FounderVerdictConfigurationError> {
        self.supporting_materials = Some(SupportingMaterialValidation {
            source,
            policy: policy
                .validate()
                .map_err(|_| FounderVerdictConfigurationError::InvalidConfiguration)?,
        });
        Ok(self)
    }

    /// Adds Verification criteria which must be closed in the current bound
    /// artifact before an Accept can proceed. This remains separate from the
    /// legacy static gate list so existing user configuration keeps its
    /// explicit, unconditional blocking meaning.
    pub fn with_non_overridable_criterion_ids(
        mut self,
        criterion_ids: BTreeSet<String>,
    ) -> Result<Self, FounderVerdictConfigurationError> {
        if criterion_ids.iter().any(|value| value.trim().is_empty()) {
            return Err(FounderVerdictConfigurationError::InvalidConfiguration);
        }
        self.non_overridable_criterion_ids = criterion_ids;
        Ok(self)
    }

    pub(crate) fn with_expiry_source(
        mut self,
        source: crate::verdict_expiry::FounderVerdictExpiryProofSource,
    ) -> Self {
        self.expiry_source = Some(source);
        self
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
        let mut non_overridable_gate_ids = self.non_overridable_gate_ids.clone();
        non_overridable_gate_ids.extend(
            self.non_overridable_criterion_ids
                .iter()
                .filter(|criterion_id| !criterion_is_closed(&artifact, criterion_id))
                .cloned(),
        );
        let material_evidence = validate_supporting_materials(
            self.supporting_materials.as_ref(),
            command,
            scope,
            &principal.principal_id,
            conclusion,
        )?;
        let mut evidence_refs = vec![
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
        ];
        evidence_refs.extend(
            material_evidence
                .into_iter()
                .map(|artifact_id| format!("founder-supporting-material:{artifact_id}@sealed")),
        );
        Ok((
            ResolvedVerdictContext {
                scope: scope.clone(),
                verification_conclusion: conclusion,
                open_discrepancy_ids,
                open_unverified_item_ids,
                non_overridable_gate_ids: non_overridable_gate_ids.into_iter().collect(),
            },
            FounderAuthorization {
                authenticated_founder_principal_id: principal.principal_id.clone(),
                authority_ref: self.authority_ref.clone(),
                confirmation_class,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: now,
                valid_until,
                authority_policy_ref: self.authority_policy_ref.clone(),
                evidence_refs,
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

    fn validate_task_commit_before_expiry(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ConsumeFounderVerdictCommand,
        scope: &VerdictScope,
        expires_at: &prost_types::Timestamp,
    ) -> Result<(), VerdictReferenceRejection> {
        self.task_commit_source
            .validate_task_commit_before_expiry(command, scope, expires_at)
    }

    fn validate_expiry_for_verdict(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::ExpireFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
        verdict: &egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdict,
        state: &egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictState,
    ) -> Result<Vec<String>, VerdictReferenceRejection> {
        self.expiry_source
            .as_ref()
            .ok_or(VerdictReferenceRejection::PermissionDenied)?
            .validate(command, principal, verdict, state)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FounderVerdictConfigurationError {
    #[error("configured Founder Verdict resolver is invalid")]
    InvalidConfiguration,
}

fn validate_supporting_materials(
    validation: Option<&SupportingMaterialValidation>,
    command: &IssueFounderVerdictCommand,
    scope: &VerdictScope,
    authenticated_founder_principal_id: &str,
    conclusion: VerificationConclusion,
) -> Result<Vec<String>, VerdictReferenceRejection> {
    let decision = FounderVerdictDecision::try_from(command.decision)
        .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?;
    let mut expected = Vec::new();
    if decision == FounderVerdictDecision::Rework {
        if let Some(directive) = command.rework_directive.as_ref()
            && !directive.required_changes_artifact_id.trim().is_empty()
        {
            expected.push((
                directive.required_changes_artifact_id.as_str(),
                FounderSupportingMaterialRole::ReworkRequiredChanges,
                FounderSupportingMaterialCoverage {
                    risk_category: RiskCategory::Unspecified as i32,
                    discrepancy_ids: directive.target_discrepancy_ids.clone(),
                    unverified_item_ids: directive.target_unverified_item_ids.clone(),
                },
            ));
        }
    } else if decision == FounderVerdictDecision::Accept
        && conclusion != VerificationConclusion::Passed
    {
        for risk in &command.risk_acceptances {
            let coverage = FounderSupportingMaterialCoverage {
                risk_category: risk.category,
                discrepancy_ids: risk.discrepancy_ids.clone(),
                unverified_item_ids: risk.unverified_item_ids.clone(),
            };
            if !risk.rationale_artifact_id.trim().is_empty() {
                expected.push((
                    risk.rationale_artifact_id.as_str(),
                    FounderSupportingMaterialRole::RiskRationale,
                    coverage.clone(),
                ));
            }
            for artifact_id in &risk.compensating_control_artifact_ids {
                if !artifact_id.trim().is_empty() {
                    expected.push((
                        artifact_id.as_str(),
                        FounderSupportingMaterialRole::CompensatingControl,
                        coverage.clone(),
                    ));
                }
            }
        }
    }
    if expected.is_empty() {
        return Ok(Vec::new());
    }
    let validation = validation.ok_or(VerdictReferenceRejection::IntegrityFailure)?;
    let mut seen = BTreeSet::new();
    let mut verified = Vec::with_capacity(expected.len());
    for (artifact_id, role, coverage) in expected {
        if !seen.insert(artifact_id) {
            return Err(VerdictReferenceRejection::IntegrityFailure);
        }
        let evidence = validation
            .source
            .material(artifact_id, scope)
            .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?
            .ok_or(VerdictReferenceRejection::NotFound)?;
        validate_supporting_material(
            &evidence,
            artifact_id,
            role,
            &coverage,
            scope,
            authenticated_founder_principal_id,
            &validation.policy,
        )?;
        verified.push(artifact_id.to_owned());
    }
    Ok(verified)
}

fn validate_supporting_material(
    evidence: &FounderSupportingMaterialEvidence,
    artifact_id: &str,
    expected_role: FounderSupportingMaterialRole,
    expected_coverage: &FounderSupportingMaterialCoverage,
    scope: &VerdictScope,
    authenticated_founder_principal_id: &str,
    policy: &FounderSupportingMaterialPolicy,
) -> Result<(), VerdictReferenceRejection> {
    let descriptor = &evidence.descriptor;
    let provenance = descriptor
        .provenance
        .as_ref()
        .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
    let lineage = provenance
        .lineage
        .as_ref()
        .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
    let content = descriptor
        .content
        .as_ref()
        .ok_or(VerdictReferenceRejection::IntegrityFailure)?;
    let payload = FounderSupportingMaterial::decode(evidence.payload.as_slice())
        .map_err(|_| VerdictReferenceRejection::IntegrityFailure)?;
    let digest = hex::encode(Sha256::digest(&evidence.payload));
    let unique_inputs: BTreeSet<_> = provenance.input_artifact_ids.iter().collect();
    if descriptor.artifact_id != artifact_id
        || descriptor.artifact_id != founder_supporting_material_artifact_id(&payload.material_id)
        || descriptor.revision != 2
        || descriptor.status != ArtifactStatus::Sealed as i32
        || descriptor.integrity_status != IntegrityStatus::DigestVerified as i32
        || descriptor.semantic_class != ArtifactSemanticClass::TypedExtension as i32
        || descriptor.type_contract_ref.as_ref() != Some(&policy.type_contract_ref)
        || descriptor.media_type != MATERIAL_MEDIA_TYPE
        || descriptor.retention_profile_ref.as_ref() != Some(&policy.retention_profile_ref)
        || descriptor.sensitivity_class != policy.sensitivity_class
        || content.algorithm != HashAlgorithm::Sha256 as i32
        || content.digest != digest
        || content.byte_length != evidence.payload.len() as u64
        || provenance.transformation_contract_ref.as_ref()
            != Some(&policy.transformation_contract_ref)
        || provenance.workspace_ref.trim().is_empty()
        || provenance.workspace_ref != evidence.bound_workspace_ref
        || provenance.raw_source_ref.as_deref() != Some(evidence.bound_source_binding_ref.as_str())
        || provenance.input_artifact_ids != evidence.bound_input_artifact_ids
        || unique_inputs.len() != provenance.input_artifact_ids.len()
        || producer.principal_kind != "governed_collector"
        || producer.principal_id != policy.collector_principal_id
        || producer.component_name != policy.component_name
        || producer.component_version != policy.component_version
        || descriptor.sealed_at.is_none()
        || descriptor.quarantine_reason_code.is_some()
        || payload.schema_version != MATERIAL_SCHEMA_VERSION
        || payload.role != expected_role as i32
        || payload.scope.as_ref() != Some(scope)
        || payload.lineage.as_ref() != Some(lineage)
        || !lineage_belongs_to_scope_work(lineage, scope)
        || payload.authenticated_founder_principal_id != authenticated_founder_principal_id
        || payload.body.trim().is_empty()
        || payload.coverage.as_ref() != Some(expected_coverage)
    {
        return Err(VerdictReferenceRejection::IntegrityFailure);
    }
    Ok(())
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
    lineage_belongs_to_scope_work(lineage, scope)
        && binding.artifact_set_id == scope.artifact_set_id
        && binding.artifact_set_manifest == scope.artifact_set_manifest
        && binding.acceptance_contract_ref == scope.acceptance_contract_ref
}

/// A configured non-overridable criterion is closed only when the bound
/// artifact contains one complete, evidenced passing result and neither its
/// result nor the artifact records an associated discrepancy or unverified
/// item. Missing and ambiguous results deliberately remain open.
fn criterion_is_closed(artifact: &VerificationArtifact, criterion_id: &str) -> bool {
    let mut matching_results = artifact
        .criterion_results
        .iter()
        .filter(|result| result.criterion_id == criterion_id);
    let Some(result) = matching_results.next() else {
        return false;
    };
    // A closed criterion has to carry a durable proof of what the checker
    // observed. Routine checkers record Evidence aggregates, and then the
    // evidence ids are that proof. A deterministic acceptance checker that
    // treats a zero-finding review as positive proof cannot do that: its raw
    // output is an Artifact, and the Verification Authority rejects an
    // artifact id in `evidence_ids` as a type confusion. Its durable proof is
    // the detail artifact instead, which the Authority verified when the
    // result was recorded. Requiring evidence ids of that shape would make
    // such a criterion impossible to close, so protection and this checker
    // shape would exclude each other.
    let carries_evidence = !result.evidence_ids.is_empty()
        && result
            .evidence_ids
            .iter()
            .all(|evidence_id| !evidence_id.trim().is_empty());
    let carries_detail_artifact = result
        .safe_detail_artifact_id
        .as_deref()
        .is_some_and(|artifact_id| !artifact_id.trim().is_empty());
    if matching_results.next().is_some()
        || result.criterion_result_id.trim().is_empty()
        || result.outcome != CriterionOutcome::Passed as i32
        || result.evidence_coverage != EvidenceCoverage::Complete as i32
        || !(carries_evidence || carries_detail_artifact)
        || !result.discrepancy_ids.is_empty()
        || !result.unverified_item_ids.is_empty()
    {
        return false;
    }
    !artifact
        .discrepancies
        .iter()
        .any(|discrepancy| discrepancy.criterion_id == criterion_id)
        && !artifact
            .unverified_items
            .iter()
            .any(|item| item.criterion_id == criterion_id)
}

// Artifact lineage freezes the Task revision that created the run. Verdict
// scope freezes the later, current VerdictPending Task revision after evidence
// and Verification write-back. Equal revisions remain valid for legacy data;
// a future lineage revision must never bind to an earlier Task scope.
fn lineage_belongs_to_scope_work(lineage: &LineageBinding, scope: &VerdictScope) -> bool {
    lineage.task_id == scope.task_id
        && lineage.task_revision <= scope.task_revision
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
        verification::v1::{
            CriterionResult, Discrepancy, UnverifiedItem, VerificationBinding,
            VerificationProvenance,
        },
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
        resolver_for(artifact(), BTreeSet::new(), BTreeSet::new())
    }

    fn resolver_for(
        artifact: VerificationArtifact,
        legacy_gate_ids: BTreeSet<String>,
        criterion_ids: BTreeSet<String>,
    ) -> ConfiguredFounderVerdictResolver {
        ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
            verification_source: Box::new(StaticEvidence(artifact)),
            task_commit_source: Box::new(DenyFounderTaskCommitEvidence),
            allowed_founder_principal_ids: BTreeSet::from(["founder:local".to_owned()]),
            authority_ref: "founder-authority:v01".to_owned(),
            authority_policy_ref: contract("founder-policy", 0x55),
            allowed_confirmation_proof_refs: BTreeSet::from(["confirm:local:1".to_owned()]),
            non_overridable_gate_ids: legacy_gate_ids,
            confirmation_ttl: Duration::from_secs(600),
        })
        .expect("valid verdict resolver")
        .with_non_overridable_criterion_ids(criterion_ids)
        .expect("valid criterion configuration")
    }

    fn closed_scope_result() -> CriterionResult {
        CriterionResult {
            criterion_result_id: "criterion-result:scope:1".to_owned(),
            criterion_id: "scope".to_owned(),
            outcome: CriterionOutcome::Passed as i32,
            evidence_coverage: EvidenceCoverage::Complete as i32,
            evidence_ids: vec!["evidence:scope:1".to_owned()],
            ..Default::default()
        }
    }

    fn artifact_with_closed_scope() -> VerificationArtifact {
        let mut value = artifact();
        value.criterion_results = vec![closed_scope_result()];
        value
    }

    fn resolved_blockers(
        artifact: VerificationArtifact,
        legacy_gate_ids: BTreeSet<String>,
    ) -> BTreeSet<String> {
        resolver_for(
            artifact,
            legacy_gate_ids,
            BTreeSet::from(["scope".to_owned()]),
        )
        .resolve_issue(&issue(), &founder())
        .expect("artifact-backed verdict authorization")
        .0
        .non_overridable_gate_ids
        .into_iter()
        .collect()
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
    fn configured_scope_criterion_does_not_block_a_complete_unique_passing_result() {
        assert!(resolved_blockers(artifact_with_closed_scope(), BTreeSet::new()).is_empty());
    }

    #[test]
    fn configured_scope_criterion_blocks_incomplete_or_ambiguous_artifact_results() {
        let mut duplicate = artifact_with_closed_scope();
        let mut duplicate_result = closed_scope_result();
        duplicate_result.criterion_result_id = "criterion-result:scope:2".to_owned();
        duplicate.criterion_results.push(duplicate_result);

        let mut failed = artifact_with_closed_scope();
        failed.criterion_results[0].outcome = CriterionOutcome::Failed as i32;

        let mut unverified = artifact_with_closed_scope();
        unverified.criterion_results[0].outcome = CriterionOutcome::Unverified as i32;

        let mut incomplete_coverage = artifact_with_closed_scope();
        incomplete_coverage.criterion_results[0].evidence_coverage =
            EvidenceCoverage::Missing as i32;

        let mut missing_evidence = artifact_with_closed_scope();
        missing_evidence.criterion_results[0].evidence_ids.clear();

        let mut orphan_discrepancy = artifact_with_closed_scope();
        orphan_discrepancy.discrepancies.push(Discrepancy {
            discrepancy_id: "discrepancy:scope:orphan".to_owned(),
            criterion_id: "scope".to_owned(),
            ..Default::default()
        });

        let mut orphan_unverified = artifact_with_closed_scope();
        orphan_unverified.unverified_items.push(UnverifiedItem {
            unverified_item_id: "unverified:scope:orphan".to_owned(),
            criterion_id: "scope".to_owned(),
            ..Default::default()
        });

        for (name, artifact) in [
            ("missing", artifact()),
            ("duplicate", duplicate),
            ("failed", failed),
            ("unverified", unverified),
            ("incomplete coverage", incomplete_coverage),
            ("missing evidence", missing_evidence),
            ("orphan discrepancy", orphan_discrepancy),
            ("orphan unverified item", orphan_unverified),
        ] {
            assert_eq!(
                resolved_blockers(artifact, BTreeSet::new()),
                BTreeSet::from(["scope".to_owned()]),
                "{name} must keep scope open"
            );
        }
    }

    #[test]
    fn positive_acceptance_result_closes_its_criterion_without_evidence_aggregates() {
        // A deterministic acceptance checker reports its raw output as an
        // Artifact, so this result carries no evidence aggregate. The artifact
        // reference is what the Authority verified at intake, and it closes
        // the criterion.
        let mut result = closed_scope_result();
        result.evidence_ids.clear();
        result.safe_detail_artifact_id = Some("artifact:harness-output:1".to_owned());
        let mut artifact = artifact();
        artifact.criterion_results = vec![result];
        assert_eq!(
            resolved_blockers(artifact, BTreeSet::new()),
            BTreeSet::new()
        );
    }

    #[test]
    fn a_result_without_a_durable_proof_keeps_its_criterion_open() {
        for (name, detail) in [
            ("no proof at all", None),
            ("blank detail artifact", Some("   ".to_owned())),
        ] {
            let mut result = closed_scope_result();
            result.evidence_ids.clear();
            result.safe_detail_artifact_id = detail;
            let mut artifact = artifact();
            artifact.criterion_results = vec![result];
            assert_eq!(
                resolved_blockers(artifact, BTreeSet::new()),
                BTreeSet::from(["scope".to_owned()]),
                "{name} must keep scope open"
            );
        }
    }

    #[test]
    fn legacy_explicit_gate_remains_open_when_configured_criterion_is_closed() {
        assert_eq!(
            resolved_blockers(
                artifact_with_closed_scope(),
                BTreeSet::from(["legacy-gate".to_owned()]),
            ),
            BTreeSet::from(["legacy-gate".to_owned()])
        );
    }

    #[test]
    fn task_consumption_remains_fail_closed_without_task_receipt_source() {
        let error = resolver()
            .validate_task_commit(&ConsumeFounderVerdictCommand::default(), &scope())
            .expect_err("task receipt source is not configured");
        assert_eq!(error, VerdictReferenceRejection::TaskCommitReceiptInvalid);
    }
}
