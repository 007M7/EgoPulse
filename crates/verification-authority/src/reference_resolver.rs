use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus, ArtifactStatus,
        Claim, ClaimStatus, ContentAddress, Evidence, EvidenceStatus, IntegrityStatus,
    },
    verification::v1::{CheckerProfile, VerificationBinding, VerificationRequest},
};
use std::collections::BTreeSet;
use thiserror::Error;

use super::{
    CriterionPolicySnapshot, ReferenceRejection, ResolvedVerificationInput,
    VerificationReferenceResolver,
};

/// Read-only owner boundary consumed by Verification. Implementations may
/// use a shared Authority handle, but must expose decoded snapshots only.
pub trait ArtifactReferenceSource: Send + Sync + 'static {
    fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError>;

    fn read_claim(&self, claim_id: &str) -> Result<Option<Claim>, ArtifactReferenceSourceError>;

    fn read_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ArtifactReferenceSourceError>;

    fn read_artifact_set(
        &self,
        artifact_set_id: &str,
    ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError>;
}

/// Optional content-plane companion to the immutable metadata boundary. The
/// implementation may return bytes, but must re-verify the supplied content
/// address and must not expose a filesystem path, blob store, or writer.
pub trait ArtifactContentSource: ArtifactReferenceSource {
    fn read_content(
        &self,
        address: &ContentAddress,
    ) -> Result<Vec<u8>, ArtifactReferenceSourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ArtifactReferenceSourceError {
    #[error("Artifact Authority is unavailable")]
    Unavailable,
    #[error("Artifact Authority returned a corrupt snapshot")]
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ReferenceResolverConfigurationError {
    #[error("verification criterion policy set is empty or contains duplicate IDs")]
    InvalidCriteria,
    #[error("checker output collector identity is empty")]
    InvalidCheckerOutputCollector,
}

/// Roles are supplied by the Authority field being validated, not by the
/// artifact producer. Evidence remains restricted to the frozen input set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerOutputRole {
    Detail,
    RawOutput,
    ToolReceipt,
    ModelCallReceipt,
    CostReceipt,
}

#[derive(Clone, Debug)]
pub struct CheckerResultArtifactReference {
    pub artifact_id: String,
    pub role: CheckerOutputRole,
    pub checker_profile_id: Option<String>,
}

pub struct CheckerResultReferenceContext<'a> {
    pub binding: &'a VerificationBinding,
    pub verification_request_id: &'a str,
    pub verification_run_id: &'a str,
    /// Authority-owned, attested profiles read for the stored criterion results.
    pub checker_profiles: &'a [CheckerProfile],
}

/// The framed execution identity binds post-execution artifacts to exactly
/// one request, run and attested profile without path/ID delimiter ambiguity.
#[must_use]
pub fn checker_output_execution_ref(request_id: &str, run_id: &str, profile_id: &str) -> String {
    format!(
        "verification-output:{}",
        serde_json::json!([request_id, run_id, profile_id])
    )
}

/// Resolves Verification references from immutable Artifact Authority facts.
/// The resolver never treats a request, checker output or user configuration
/// as evidence; every referenced member must be present in the sealed set and
/// must retain the same lineage as the request binding.
pub struct ArtifactBackedReferenceResolver<S> {
    source: S,
    criteria: Vec<CriterionPolicySnapshot>,
    checker_output_collector: Option<String>,
}

impl<S> ArtifactBackedReferenceResolver<S>
where
    S: ArtifactReferenceSource,
{
    pub fn new(
        source: S,
        criteria: Vec<CriterionPolicySnapshot>,
    ) -> Result<Self, ReferenceResolverConfigurationError> {
        let mut ids = BTreeSet::new();
        if criteria.is_empty()
            || criteria
                .iter()
                .any(|value| value.criterion_id.trim().is_empty())
            || !criteria
                .iter()
                .all(|value| ids.insert(value.criterion_id.clone()))
        {
            return Err(ReferenceResolverConfigurationError::InvalidCriteria);
        }
        Ok(Self {
            source,
            criteria,
            checker_output_collector: None,
        })
    }

    /// Enable only alongside the application's governed checker-output intake.
    /// The legacy constructor retains the original sealed-input-set boundary.
    pub fn with_checker_output_collector(
        mut self,
        principal_id: String,
    ) -> Result<Self, ReferenceResolverConfigurationError> {
        if principal_id.trim().is_empty() {
            return Err(ReferenceResolverConfigurationError::InvalidCheckerOutputCollector);
        }
        self.checker_output_collector = Some(principal_id);
        Ok(self)
    }

    fn resolve_binding(
        &self,
        binding: &VerificationBinding,
    ) -> Result<BindingResolution, ReferenceRejection> {
        let expected_manifest = binding
            .artifact_set_manifest
            .as_ref()
            .ok_or(ReferenceRejection::BindingStale)?;
        let expected_lineage = binding
            .lineage
            .as_ref()
            .ok_or(ReferenceRejection::BindingStale)?;
        let expected_semantic_profile = binding
            .claim_semantic_profile_ref
            .as_ref()
            .ok_or(ReferenceRejection::BindingStale)?;
        let expected_acceptance_contract = binding
            .acceptance_contract_ref
            .as_ref()
            .ok_or(ReferenceRejection::BindingStale)?;
        let artifact_set = self
            .source
            .read_artifact_set(&binding.artifact_set_id)
            .map_err(source_error)?
            .ok_or(ReferenceRejection::NotFound)?;
        if artifact_set.status != ArtifactSetStatus::Sealed as i32 {
            return Err(ReferenceRejection::ArtifactSetNotSealed);
        }
        if artifact_set.canonical_manifest.as_ref() != Some(expected_manifest) {
            return Err(ReferenceRejection::ManifestMismatch);
        }
        if artifact_set.lineage.as_ref() != Some(expected_lineage) {
            return Err(ReferenceRejection::BindingStale);
        }

        let artifact_ids = unique_nonempty(&artifact_set.artifact_ids)
            .ok_or(ReferenceRejection::IntegrityFailure)?;
        let evidence_ids = unique_nonempty(&artifact_set.evidence_ids)
            .ok_or(ReferenceRejection::IntegrityFailure)?;
        if !artifact_set
            .claim_ids
            .iter()
            .any(|id| id == &binding.claim_id)
        {
            return Err(ReferenceRejection::ClaimMismatch);
        }
        let claim = self
            .source
            .read_claim(&binding.claim_id)
            .map_err(source_error)?
            .ok_or(ReferenceRejection::NotFound)?;
        if claim.status != ClaimStatus::Proposed as i32
            || claim.semantic_profile_ref.as_ref() != Some(expected_semantic_profile)
            || claim.acceptance_contract_ref.as_ref() != Some(expected_acceptance_contract)
        {
            return Err(ReferenceRejection::ClaimMismatch);
        }
        if claim.lineage.as_ref() != Some(expected_lineage) {
            return Err(ReferenceRejection::ClaimMismatch);
        }

        for evidence_id in &evidence_ids {
            let evidence = self
                .source
                .read_evidence(evidence_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            if evidence.status != EvidenceStatus::Recorded as i32
                || evidence.claim_id != binding.claim_id
                || evidence.lineage.as_ref() != Some(expected_lineage)
                || evidence
                    .artifact_ids
                    .iter()
                    .any(|id| !artifact_ids.contains(id))
            {
                return Err(ReferenceRejection::EvidenceIncomplete);
            }
        }

        for artifact_id in &artifact_ids {
            let artifact = self
                .source
                .read_artifact(artifact_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            if artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
                || artifact
                    .provenance
                    .as_ref()
                    .and_then(|value| value.lineage.as_ref())
                    != Some(expected_lineage)
            {
                return Err(ReferenceRejection::IntegrityFailure);
            }
        }

        Ok(BindingResolution {
            artifact_set,
            artifact_ids,
            evidence_ids,
        })
    }

    fn validate_artifact_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        for evidence_id in evidence_ids {
            let evidence = self
                .source
                .read_evidence(evidence_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            if evidence.status != EvidenceStatus::Recorded as i32 {
                return Err(ReferenceRejection::EvidenceIncomplete);
            }
        }
        for artifact_id in artifact_ids {
            let artifact = self
                .source
                .read_artifact(artifact_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            if artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
            {
                return Err(ReferenceRejection::IntegrityFailure);
            }
        }
        Ok(())
    }
}

impl<S> VerificationReferenceResolver for ArtifactBackedReferenceResolver<S>
where
    S: ArtifactReferenceSource,
{
    fn validate_checker_profile(&self, profile: &CheckerProfile) -> Result<(), ReferenceRejection> {
        if profile.attestation_evidence_artifact_ids.is_empty() {
            return Err(ReferenceRejection::EvidenceIncomplete);
        }
        for artifact_id in &profile.attestation_evidence_artifact_ids {
            let artifact = self
                .source
                .read_artifact(artifact_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            if artifact.status != ArtifactStatus::Sealed as i32 {
                return Err(ReferenceRejection::EvidenceIncomplete);
            }
            if artifact.integrity_status != IntegrityStatus::DigestVerified as i32 {
                return Err(ReferenceRejection::IntegrityFailure);
            }
        }
        Ok(())
    }

    fn resolve_request(
        &self,
        request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        let binding = request
            .binding
            .as_ref()
            .ok_or(ReferenceRejection::BindingStale)?;
        let resolved = self.resolve_binding(binding)?;
        let criteria = request
            .criterion_ids
            .iter()
            .map(|criterion_id| {
                self.criteria
                    .iter()
                    .find(|value| value.criterion_id == *criterion_id)
                    .cloned()
                    .ok_or(ReferenceRejection::AcceptanceContractMismatch)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ResolvedVerificationInput {
            artifact_set_status: resolved.artifact_set.status.try_into().unwrap_or_default(),
            binding: binding.clone(),
            criteria,
            evidence_ids: resolved.evidence_ids,
        })
    }

    fn revalidate_binding(&self, binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        self.resolve_binding(binding).map(|_| ())
    }

    fn validate_result_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        self.validate_artifact_references(evidence_ids, artifact_ids)
    }

    fn validate_result_references_for_binding(
        &self,
        binding: &VerificationBinding,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        let resolved = self.resolve_binding(binding)?;
        if evidence_ids
            .iter()
            .any(|id| !resolved.evidence_ids.contains(id))
            || artifact_ids
                .iter()
                .any(|id| !resolved.artifact_ids.contains(id))
        {
            return Err(ReferenceRejection::EvidenceIncomplete);
        }
        self.validate_artifact_references(evidence_ids, artifact_ids)
    }

    fn validate_checker_result_references(
        &self,
        context: &CheckerResultReferenceContext<'_>,
        evidence_ids: &[String],
        references: &[CheckerResultArtifactReference],
    ) -> Result<(), ReferenceRejection> {
        let resolved = self.resolve_binding(context.binding)?;
        if evidence_ids
            .iter()
            .any(|id| !resolved.evidence_ids.contains(id))
        {
            return Err(ReferenceRejection::EvidenceIncomplete);
        }
        for reference in references {
            // Published single-checker fixtures used only input-set members.
            // Keep that compatibility; external outputs use the narrower path.
            if resolved.artifact_ids.contains(&reference.artifact_id) {
                continue;
            }
            let collector = self
                .checker_output_collector
                .as_deref()
                .ok_or(ReferenceRejection::EvidenceIncomplete)?;
            let artifact = self
                .source
                .read_artifact(&reference.artifact_id)
                .map_err(source_error)?
                .ok_or(ReferenceRejection::NotFound)?;
            let provenance = artifact
                .provenance
                .as_ref()
                .ok_or(ReferenceRejection::IntegrityFailure)?;
            let producer = provenance
                .producer
                .as_ref()
                .ok_or(ReferenceRejection::IntegrityFailure)?;
            let inputs = unique_nonempty(&provenance.input_artifact_ids)
                .ok_or(ReferenceRejection::EvidenceIncomplete)?;
            let profile = context
                .checker_profiles
                .iter()
                .find(|profile| {
                    producer.capability_profile_id.as_deref()
                        == Some(profile.checker_profile_id.as_str())
                        && reference
                            .checker_profile_id
                            .as_ref()
                            .is_none_or(|id| id == &profile.checker_profile_id)
                })
                .ok_or(ReferenceRejection::IntegrityFailure)?;
            if artifact.artifact_id != reference.artifact_id
                || artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
                || artifact.content.is_none()
                || provenance.lineage.as_ref() != context.binding.lineage.as_ref()
                || provenance.workspace_ref.trim().is_empty()
                || !inputs.is_subset(&resolved.artifact_ids)
                || producer.principal_kind != "governed_collector"
                || producer.principal_id != collector
                || producer.component_version != profile.checker_version
                || producer.native_execution_ref.as_deref()
                    != Some(
                        checker_output_execution_ref(
                            context.verification_request_id,
                            context.verification_run_id,
                            &profile.checker_profile_id,
                        )
                        .as_str(),
                    )
                || profile.output_contract_ref.is_none()
                || provenance.transformation_contract_ref != profile.output_contract_ref
                || !output_role_matches(
                    reference.role,
                    artifact.semantic_class,
                    &producer.component_name,
                )
            {
                return Err(ReferenceRejection::IntegrityFailure);
            }
            // A matching Task lineage alone must not authorize a different
            // workspace or arbitrary artifacts from another execution.
            for input_id in inputs {
                let input = self
                    .source
                    .read_artifact(&input_id)
                    .map_err(source_error)?
                    .ok_or(ReferenceRejection::NotFound)?;
                if input
                    .provenance
                    .as_ref()
                    .map(|value| value.workspace_ref.as_str())
                    != Some(provenance.workspace_ref.as_str())
                {
                    return Err(ReferenceRejection::IntegrityFailure);
                }
            }
        }
        self.validate_artifact_references(
            evidence_ids,
            &references
                .iter()
                .map(|value| value.artifact_id.clone())
                .collect::<Vec<_>>(),
        )
    }
}

fn output_role_matches(role: CheckerOutputRole, semantic_class: i32, component: &str) -> bool {
    match role {
        CheckerOutputRole::Detail => {
            (semantic_class == ArtifactSemanticClass::LogBundle as i32
                && component == "verification-raw-output")
                || (semantic_class == ArtifactSemanticClass::TypedExtension as i32
                    && component == "verification-finding-detail")
        }
        CheckerOutputRole::RawOutput => {
            semantic_class == ArtifactSemanticClass::LogBundle as i32
                && component == "verification-raw-output"
        }
        CheckerOutputRole::ToolReceipt => {
            semantic_class == ArtifactSemanticClass::ToolReceipt as i32
                && component == "verification-tool-receipt"
        }
        CheckerOutputRole::ModelCallReceipt => {
            semantic_class == ArtifactSemanticClass::ToolReceipt as i32
                && component == "verification-model-call-receipt"
        }
        CheckerOutputRole::CostReceipt => {
            semantic_class == ArtifactSemanticClass::UsageReceipt as i32
                && component == "verification-cost-receipt"
        }
    }
}

struct BindingResolution {
    artifact_set: ArtifactSet,
    artifact_ids: BTreeSet<String>,
    evidence_ids: BTreeSet<String>,
}

fn unique_nonempty(values: &[String]) -> Option<BTreeSet<String>> {
    let result = values.iter().cloned().collect::<BTreeSet<_>>();
    (result.len() == values.len()
        && !result.is_empty()
        && result.iter().all(|value| !value.trim().is_empty()))
    .then_some(result)
}

fn source_error(error: ArtifactReferenceSourceError) -> ReferenceRejection {
    match error {
        ArtifactReferenceSourceError::Unavailable => ReferenceRejection::NotFound,
        ArtifactReferenceSourceError::Corrupt => ReferenceRejection::IntegrityFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{ContentAddress, LineageBinding, ProducerIdentity, Provenance},
        common::v1::ContractReference,
        verification::v1::CheckerProfile,
    };
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FixtureSource {
        artifacts: BTreeMap<String, ArtifactDescriptor>,
        claims: BTreeMap<String, Claim>,
        evidence: BTreeMap<String, Evidence>,
        sets: BTreeMap<String, ArtifactSet>,
    }

    impl ArtifactReferenceSource for FixtureSource {
        fn read_artifact(
            &self,
            artifact_id: &str,
        ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
            Ok(self.artifacts.get(artifact_id).cloned())
        }

        fn read_claim(
            &self,
            claim_id: &str,
        ) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
            Ok(self.claims.get(claim_id).cloned())
        }

        fn read_evidence(
            &self,
            evidence_id: &str,
        ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
            Ok(self.evidence.get(evidence_id).cloned())
        }

        fn read_artifact_set(
            &self,
            artifact_set_id: &str,
        ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
            Ok(self.sets.get(artifact_set_id).cloned())
        }
    }

    fn reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn lineage() -> LineageBinding {
        LineageBinding {
            task_id: "task-1".to_owned(),
            task_revision: 1,
            work_revision: 1,
            run_id: "run-1".to_owned(),
            run_revision: 1,
            step_id: "step-1".to_owned(),
            step_revision: 1,
            attempt_id: "attempt-1".to_owned(),
            attempt_revision: 1,
            dispatch_id: "dispatch-1".to_owned(),
            fencing_token: 1,
        }
    }

    fn binding() -> VerificationBinding {
        VerificationBinding {
            lineage: Some(lineage()),
            artifact_set_id: "set-1".to_owned(),
            artifact_set_manifest: Some(ContentAddress {
                digest: "b".repeat(64),
                byte_length: 1,
                ..Default::default()
            }),
            claim_id: "claim-1".to_owned(),
            claim_semantic_profile_ref: Some(reference("claim-profile")),
            acceptance_contract_ref: Some(reference("acceptance")),
        }
    }

    fn source() -> FixtureSource {
        let line = lineage();
        let mut source = FixtureSource::default();
        source.artifacts.insert(
            "artifact-1".to_owned(),
            ArtifactDescriptor {
                artifact_id: "artifact-1".to_owned(),
                status: ArtifactStatus::Sealed as i32,
                integrity_status: IntegrityStatus::DigestVerified as i32,
                provenance: Some(Provenance {
                    lineage: Some(line.clone()),
                    producer: Some(ProducerIdentity {
                        principal_id: "runner-1".to_owned(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        source.claims.insert(
            "claim-1".to_owned(),
            Claim {
                claim_id: "claim-1".to_owned(),
                status: ClaimStatus::Proposed as i32,
                semantic_profile_ref: Some(reference("claim-profile")),
                acceptance_contract_ref: Some(reference("acceptance")),
                lineage: Some(line.clone()),
                ..Default::default()
            },
        );
        source.evidence.insert(
            "evidence-1".to_owned(),
            Evidence {
                evidence_id: "evidence-1".to_owned(),
                status: EvidenceStatus::Recorded as i32,
                claim_id: "claim-1".to_owned(),
                artifact_ids: vec!["artifact-1".to_owned()],
                lineage: Some(line.clone()),
                ..Default::default()
            },
        );
        source.sets.insert(
            "set-1".to_owned(),
            ArtifactSet {
                artifact_set_id: "set-1".to_owned(),
                status: ArtifactSetStatus::Sealed as i32,
                lineage: Some(line),
                artifact_ids: vec!["artifact-1".to_owned()],
                claim_ids: vec!["claim-1".to_owned()],
                evidence_ids: vec!["evidence-1".to_owned()],
                canonical_manifest: binding().artifact_set_manifest,
                ..Default::default()
            },
        );
        source
    }

    fn resolver() -> ArtifactBackedReferenceResolver<FixtureSource> {
        ArtifactBackedReferenceResolver::new(
            source(),
            vec![CriterionPolicySnapshot {
                criterion_id: "criterion-1".to_owned(),
                requirement: 1,
                minimum_assurance: 1,
                not_applicable_allowed: false,
                checker_profile_ids: vec!["checker-1".to_owned()],
            }],
        )
        .expect("valid criteria")
    }

    #[test]
    fn resolves_only_the_sealed_lineage_bound_set() {
        let resolver = resolver();
        let request = VerificationRequest {
            verification_type: "task_acceptance".to_owned(),
            binding: Some(binding()),
            criterion_ids: vec!["criterion-1".to_owned()],
            ..Default::default()
        };
        let resolved = resolver.resolve_request(&request).expect("resolve request");
        assert_eq!(
            resolved.evidence_ids,
            BTreeSet::from(["evidence-1".to_owned()])
        );

        assert_eq!(
            resolver.validate_result_references_for_binding(
                request.binding.as_ref().expect("binding"),
                &["evidence-1".to_owned()],
                &["artifact-1".to_owned()],
            ),
            Ok(())
        );
        assert_eq!(
            resolver.validate_result_references_for_binding(
                request.binding.as_ref().expect("binding"),
                &["evidence-1".to_owned()],
                &["artifact-from-another-set".to_owned()],
            ),
            Err(ReferenceRejection::EvidenceIncomplete)
        );
    }

    #[test]
    fn rejects_manifest_and_lineage_drift() {
        let resolver = resolver();
        let mut changed = binding();
        changed
            .artifact_set_manifest
            .as_mut()
            .expect("manifest")
            .digest = "c".repeat(64);
        assert_eq!(
            resolver.revalidate_binding(&changed),
            Err(ReferenceRejection::ManifestMismatch)
        );

        let mut changed = binding();
        changed.lineage.as_mut().expect("lineage").fencing_token = 2;
        assert_eq!(
            resolver.revalidate_binding(&changed),
            Err(ReferenceRejection::BindingStale)
        );
    }

    #[test]
    fn checker_profile_attestation_requires_sealed_digest_verified_artifacts() {
        let resolver = resolver();
        let profile = CheckerProfile {
            attestation_evidence_artifact_ids: vec!["artifact-1".to_owned()],
            ..Default::default()
        };
        assert_eq!(resolver.validate_checker_profile(&profile), Ok(()));
    }

    fn output_profile() -> CheckerProfile {
        CheckerProfile {
            checker_profile_id: "checker-1".to_owned(),
            checker_version: "1.0".to_owned(),
            output_contract_ref: Some(reference("checker-output")),
            ..Default::default()
        }
    }

    fn output_resolver() -> ArtifactBackedReferenceResolver<FixtureSource> {
        let mut resolver = resolver()
            .with_checker_output_collector("output-collector".to_owned())
            .expect("collector");
        resolver
            .source
            .artifacts
            .get_mut("artifact-1")
            .expect("input")
            .provenance
            .as_mut()
            .expect("provenance")
            .workspace_ref = "workspace-1".to_owned();
        resolver.source.artifacts.insert(
            "output-1".to_owned(),
            ArtifactDescriptor {
                artifact_id: "output-1".to_owned(),
                status: ArtifactStatus::Sealed as i32,
                semantic_class: ArtifactSemanticClass::LogBundle as i32,
                integrity_status: IntegrityStatus::DigestVerified as i32,
                content: Some(ContentAddress {
                    digest: "c".repeat(64),
                    byte_length: 8,
                    ..Default::default()
                }),
                provenance: Some(Provenance {
                    lineage: Some(lineage()),
                    input_artifact_ids: vec!["artifact-1".to_owned()],
                    workspace_ref: "workspace-1".to_owned(),
                    transformation_contract_ref: output_profile().output_contract_ref,
                    producer: Some(ProducerIdentity {
                        principal_kind: "governed_collector".to_owned(),
                        principal_id: "output-collector".to_owned(),
                        component_name: "verification-raw-output".to_owned(),
                        component_version: "1.0".to_owned(),
                        capability_profile_id: Some("checker-1".to_owned()),
                        native_execution_ref: Some(checker_output_execution_ref(
                            "request-1",
                            "run-1",
                            "checker-1",
                        )),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        resolver
    }

    fn check_output(
        resolver: &ArtifactBackedReferenceResolver<FixtureSource>,
        role: CheckerOutputRole,
        evidence: &[String],
    ) -> Result<(), ReferenceRejection> {
        resolver.validate_checker_result_references(
            &CheckerResultReferenceContext {
                binding: &binding(),
                verification_request_id: "request-1",
                verification_run_id: "run-1",
                checker_profiles: &[output_profile()],
            },
            evidence,
            &[CheckerResultArtifactReference {
                artifact_id: "output-1".to_owned(),
                role,
                checker_profile_id: Some("checker-1".to_owned()),
            }],
        )
    }

    #[test]
    fn checker_outputs_require_explicit_intake_and_cannot_become_input_evidence() {
        let mut resolver = output_resolver();
        assert_eq!(
            check_output(
                &resolver,
                CheckerOutputRole::RawOutput,
                &["evidence-1".to_owned()]
            ),
            Ok(())
        );
        assert_eq!(
            check_output(&resolver, CheckerOutputRole::Detail, &[]),
            Ok(())
        );
        assert_eq!(
            check_output(&resolver, CheckerOutputRole::ToolReceipt, &[]),
            Err(ReferenceRejection::IntegrityFailure)
        );
        assert_eq!(
            check_output(
                &resolver,
                CheckerOutputRole::RawOutput,
                &["output-1".to_owned()]
            ),
            Err(ReferenceRejection::EvidenceIncomplete)
        );
        // The old API and a bootstrap without output intake both stay strict.
        assert_eq!(
            resolver.validate_result_references_for_binding(
                &binding(),
                &[],
                &["output-1".to_owned()]
            ),
            Err(ReferenceRejection::EvidenceIncomplete)
        );
        resolver.checker_output_collector = None;
        assert_eq!(
            check_output(&resolver, CheckerOutputRole::RawOutput, &[]),
            Err(ReferenceRejection::EvidenceIncomplete)
        );
    }

    #[test]
    fn checker_outputs_reject_profile_execution_role_workspace_and_input_substitution() {
        let mutations: &[fn(&mut ArtifactDescriptor)] = &[
            |a| a.status = ArtifactStatus::Staged as i32,
            |a| a.integrity_status = IntegrityStatus::Unverified as i32,
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .lineage
                    .as_mut()
                    .unwrap()
                    .fencing_token += 1
            },
            |a| a.provenance.as_mut().unwrap().workspace_ref = "workspace-2".to_owned(),
            |a| {
                a.provenance.as_mut().unwrap().input_artifact_ids = vec!["foreign-input".to_owned()]
            },
            |a| a.provenance.as_mut().unwrap().input_artifact_ids.clear(),
            |a| {
                a.provenance.as_mut().unwrap().transformation_contract_ref =
                    Some(reference("wrong-output"))
            },
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .producer
                    .as_mut()
                    .unwrap()
                    .principal_id = "harness".to_owned()
            },
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .producer
                    .as_mut()
                    .unwrap()
                    .capability_profile_id = Some("checker-2".to_owned())
            },
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .producer
                    .as_mut()
                    .unwrap()
                    .component_version = "2.0".to_owned()
            },
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .producer
                    .as_mut()
                    .unwrap()
                    .component_name = "verification-model-call-receipt".to_owned()
            },
            |a| {
                a.provenance
                    .as_mut()
                    .unwrap()
                    .producer
                    .as_mut()
                    .unwrap()
                    .native_execution_ref = Some(checker_output_execution_ref(
                    "request-2",
                    "run-1",
                    "checker-1",
                ))
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut resolver = output_resolver();
            mutate(
                resolver
                    .source
                    .artifacts
                    .get_mut("output-1")
                    .expect("output"),
            );
            assert!(
                check_output(&resolver, CheckerOutputRole::RawOutput, &[]).is_err(),
                "substitution {index}"
            );
        }
    }
}
