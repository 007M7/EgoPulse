use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use egopulse_artifact_authority::{
    ArtifactAdmissionGuard, ArtifactAuthority, ArtifactAuthorityFailure, ArtifactClock,
};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactDescriptor, ArtifactSet, Claim, ContentAddress, Evidence, LineageBinding, ReturnHandoff,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_verification_authority::{
    ArtifactContentSource, ArtifactReferenceSource, ArtifactReferenceSourceError,
};

/// Read-only adapter from the Artifact Authority's shared owner handle to the
/// Verification Authority reference boundary.
///
/// The adapter deliberately exposes decoded snapshots only. Verification
/// cannot obtain the Artifact Authority store, blob store, guard, or writer
/// handle through this type. All reads use the one owner handle opened by the
/// composition root, so a second database connection cannot observe or repair
/// a different state.
pub struct ArtifactAuthorityReferenceSource<G, C> {
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
}

/// User-owned admission policy for Artifact Authority objects. The policy is
/// deliberately narrower than identity authentication: an authenticated
/// principal may still submit only artifacts and evidence whose semantic
/// contracts and workspace are explicitly reviewed for this installation.
#[derive(Clone, Debug)]
pub struct ConfiguredArtifactAdmissionGuardConfig {
    pub allowed_workspace_refs: BTreeSet<String>,
    pub allowed_artifact_type_refs: Vec<ContractReference>,
    pub allowed_transformation_contract_refs: Vec<ContractReference>,
    pub allowed_retention_profile_refs: Vec<ContractReference>,
    pub allowed_claim_semantic_profile_refs: Vec<ContractReference>,
    pub allowed_claim_acceptance_contract_refs: Vec<ContractReference>,
    pub allowed_evidence_profile_refs: Vec<ContractReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactAdmissionGuardConfigurationError {
    #[error("Artifact admission allowlists are empty, malformed, or contain duplicates")]
    InvalidConfiguration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DerivedWorkspaceAdmissionBinding {
    pub workspace_ref: String,
    pub lineage: LineageBinding,
    pub source_binding_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum DerivedWorkspaceAdmissionError {
    #[error("derived workspace binding is invalid or conflicts with an active exact binding")]
    Rejected,
}

#[derive(Clone, Default)]
pub(crate) struct DerivedWorkspaceAdmissionHandle {
    bindings: Arc<Mutex<BTreeMap<String, ActiveDerivedWorkspaceBinding>>>,
}

#[derive(Clone, Debug)]
struct ActiveDerivedWorkspaceBinding {
    binding: DerivedWorkspaceAdmissionBinding,
    leases: u64,
}

pub(crate) struct DerivedWorkspaceAdmissionLease {
    handle: DerivedWorkspaceAdmissionHandle,
    binding: DerivedWorkspaceAdmissionBinding,
}

impl DerivedWorkspaceAdmissionHandle {
    pub(crate) fn register(
        &self,
        binding: DerivedWorkspaceAdmissionBinding,
    ) -> Result<DerivedWorkspaceAdmissionLease, DerivedWorkspaceAdmissionError> {
        if binding.workspace_ref.trim().is_empty()
            || binding.source_binding_ref.trim().is_empty()
            || !lineage_complete(&binding.lineage)
        {
            return Err(DerivedWorkspaceAdmissionError::Rejected);
        }
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|_| DerivedWorkspaceAdmissionError::Rejected)?;
        match bindings.get_mut(&binding.workspace_ref) {
            Some(active) if active.binding == binding => {
                active.leases = active
                    .leases
                    .checked_add(1)
                    .ok_or(DerivedWorkspaceAdmissionError::Rejected)?;
            }
            Some(_) => return Err(DerivedWorkspaceAdmissionError::Rejected),
            None => {
                bindings.insert(
                    binding.workspace_ref.clone(),
                    ActiveDerivedWorkspaceBinding {
                        binding: binding.clone(),
                        leases: 1,
                    },
                );
            }
        }
        drop(bindings);
        Ok(DerivedWorkspaceAdmissionLease {
            handle: self.clone(),
            binding,
        })
    }

    fn admits(&self, artifact: &ArtifactDescriptor) -> bool {
        let Some(provenance) = artifact.provenance.as_ref() else {
            return false;
        };
        let Some(lineage) = provenance.lineage.as_ref() else {
            return false;
        };
        let Some(source_binding_ref) = provenance.raw_source_ref.as_ref() else {
            return false;
        };
        self.bindings.lock().is_ok_and(|bindings| {
            bindings
                .get(&provenance.workspace_ref)
                .is_some_and(|active| {
                    active.binding.lineage == *lineage
                        && active.binding.source_binding_ref == *source_binding_ref
                })
        })
    }
}

impl Drop for DerivedWorkspaceAdmissionLease {
    fn drop(&mut self) {
        let Ok(mut bindings) = self.handle.bindings.lock() else {
            return;
        };
        let should_remove = match bindings.get_mut(&self.binding.workspace_ref) {
            Some(active) if active.binding == self.binding && active.leases > 1 => {
                active.leases -= 1;
                false
            }
            Some(active) if active.binding == self.binding => true,
            _ => false,
        };
        if should_remove {
            bindings.remove(&self.binding.workspace_ref);
        }
    }
}

/// Admission guard used by the production Artifact Authority composition.
/// Artifact Authority still performs structural, producer and content-address
/// checks; this guard adds the installation-specific policy checks without
/// opening a second store or granting Verification write access.
pub struct ConfiguredArtifactAdmissionGuard {
    config: ConfiguredArtifactAdmissionGuardConfig,
    derived_workspace_admission: DerivedWorkspaceAdmissionHandle,
}

impl ConfiguredArtifactAdmissionGuard {
    pub fn new(
        config: ConfiguredArtifactAdmissionGuardConfig,
    ) -> Result<Self, ArtifactAdmissionGuardConfigurationError> {
        if config.allowed_workspace_refs.is_empty()
            || config
                .allowed_workspace_refs
                .iter()
                .any(|value| value.trim().is_empty())
            || !contract_refs_valid(&config.allowed_artifact_type_refs)
            || !contract_refs_valid(&config.allowed_transformation_contract_refs)
            || !contract_refs_valid(&config.allowed_retention_profile_refs)
            || !contract_refs_valid(&config.allowed_claim_semantic_profile_refs)
            || !contract_refs_valid(&config.allowed_claim_acceptance_contract_refs)
            || !contract_refs_valid(&config.allowed_evidence_profile_refs)
        {
            return Err(ArtifactAdmissionGuardConfigurationError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            derived_workspace_admission: DerivedWorkspaceAdmissionHandle::default(),
        })
    }

    fn allows(refs: &[ContractReference], candidate: Option<&ContractReference>) -> bool {
        candidate.is_some_and(|candidate| refs.iter().any(|allowed| allowed == candidate))
    }

    pub(crate) fn derived_workspace_admission_handle(&self) -> DerivedWorkspaceAdmissionHandle {
        self.derived_workspace_admission.clone()
    }
}

impl egopulse_artifact_authority::ArtifactAdmissionGuard for ConfiguredArtifactAdmissionGuard {
    fn validate_artifact(
        &self,
        artifact: &ArtifactDescriptor,
        bytes: &[u8],
        principal: &egopulse_artifact_authority::AuthenticatedArtifactPrincipal,
    ) -> Result<(), egopulse_artifact_authority::AdmissionRejection> {
        let provenance = artifact
            .provenance
            .as_ref()
            .ok_or(egopulse_artifact_authority::AdmissionRejection::InvalidArgument)?;
        if bytes.is_empty()
            || !principal.authenticated
            || principal.principal_id.trim().is_empty()
            || (!self
                .config
                .allowed_workspace_refs
                .contains(&provenance.workspace_ref)
                && !self.derived_workspace_admission.admits(artifact))
            || !Self::allows(
                &self.config.allowed_artifact_type_refs,
                artifact.type_contract_ref.as_ref(),
            )
            || !Self::allows(
                &self.config.allowed_transformation_contract_refs,
                provenance.transformation_contract_ref.as_ref(),
            )
            || !Self::allows(
                &self.config.allowed_retention_profile_refs,
                artifact.retention_profile_ref.as_ref(),
            )
        {
            return Err(egopulse_artifact_authority::AdmissionRejection::ScopeViolation);
        }
        Ok(())
    }

    fn validate_claim(
        &self,
        claim: &Claim,
        _principal: &egopulse_artifact_authority::AuthenticatedArtifactPrincipal,
    ) -> Result<(), egopulse_artifact_authority::AdmissionRejection> {
        if !Self::allows(
            &self.config.allowed_claim_semantic_profile_refs,
            claim.semantic_profile_ref.as_ref(),
        ) || !Self::allows(
            &self.config.allowed_claim_acceptance_contract_refs,
            claim.acceptance_contract_ref.as_ref(),
        ) {
            return Err(egopulse_artifact_authority::AdmissionRejection::ContractMismatch);
        }
        Ok(())
    }

    fn validate_evidence(
        &self,
        evidence: &Evidence,
        _principal: &egopulse_artifact_authority::AuthenticatedArtifactPrincipal,
    ) -> Result<(), egopulse_artifact_authority::AdmissionRejection> {
        if !Self::allows(
            &self.config.allowed_evidence_profile_refs,
            evidence.evidence_profile_ref.as_ref(),
        ) {
            return Err(egopulse_artifact_authority::AdmissionRejection::ContractMismatch);
        }
        Ok(())
    }

    fn validate_artifact_set(
        &self,
        artifact_set: &ArtifactSet,
        _principal: &egopulse_artifact_authority::AuthenticatedArtifactPrincipal,
    ) -> Result<(), egopulse_artifact_authority::AdmissionRejection> {
        if artifact_set.lineage.is_none()
            || !unique_nonempty(&artifact_set.artifact_ids)
            || !unique_nonempty(&artifact_set.claim_ids)
            || !unique_nonempty(&artifact_set.evidence_ids)
        {
            return Err(egopulse_artifact_authority::AdmissionRejection::LineageMismatch);
        }
        Ok(())
    }

    fn validate_return_handoff(
        &self,
        handoff: &ReturnHandoff,
        _principal: &egopulse_artifact_authority::AuthenticatedArtifactPrincipal,
    ) -> Result<(), egopulse_artifact_authority::AdmissionRejection> {
        if handoff.lineage.is_none()
            || !unique_nonempty(&handoff.primary_claim_ids)
            || !unique_nonempty(&handoff.evidence_ids)
        {
            return Err(egopulse_artifact_authority::AdmissionRejection::LineageMismatch);
        }
        Ok(())
    }
}

impl<G, C> ArtifactAuthorityReferenceSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    #[must_use]
    pub fn new(authority: ArtifactAuthority<G, C>) -> Self {
        Self::new_shared(Arc::new(Mutex::new(authority)))
    }

    #[must_use]
    pub fn new_shared(authority: Arc<Mutex<ArtifactAuthority<G, C>>>) -> Self {
        Self { authority }
    }
}

impl<G, C> ArtifactReferenceSource for ArtifactAuthorityReferenceSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_artifact(artifact_id)
            .map_err(map_authority_failure)
    }

    fn read_claim(&self, claim_id: &str) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_claim(claim_id)
            .map_err(map_authority_failure)
    }

    fn read_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_evidence(evidence_id)
            .map_err(map_authority_failure)
    }

    fn read_artifact_set(
        &self,
        artifact_set_id: &str,
    ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_artifact_set(artifact_set_id)
            .map_err(map_authority_failure)
    }
}

impl<G, C> ArtifactContentSource for ArtifactAuthorityReferenceSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn read_content(
        &self,
        address: &ContentAddress,
    ) -> Result<Vec<u8>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_blob(address)
            .map_err(map_authority_failure)
    }
}

fn map_authority_failure(error: ArtifactAuthorityFailure) -> ArtifactReferenceSourceError {
    match error {
        ArtifactAuthorityFailure::Storage => ArtifactReferenceSourceError::Unavailable,
        ArtifactAuthorityFailure::Blob(_) | ArtifactAuthorityFailure::Decode(_) => {
            ArtifactReferenceSourceError::Corrupt
        }
    }
}

fn contract_refs_valid(values: &[ContractReference]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| {
            !value.contract_id.trim().is_empty()
                && !value.version.trim().is_empty()
                && value.sha256.len() == 64
                && value
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && values
            .iter()
            .enumerate()
            .all(|(index, value)| !values[..index].contains(value))
}

fn unique_nonempty(values: &[String]) -> bool {
    let mut unique = BTreeSet::new();
    !values.is_empty()
        && values
            .iter()
            .all(|value| !value.trim().is_empty() && unique.insert(value))
}

fn lineage_complete(lineage: &LineageBinding) -> bool {
    !lineage.task_id.trim().is_empty()
        && lineage.task_revision > 0
        && lineage.work_revision > 0
        && !lineage.run_id.trim().is_empty()
        && lineage.run_revision > 0
        && !lineage.step_id.trim().is_empty()
        && lineage.step_revision > 0
        && !lineage.attempt_id.trim().is_empty()
        && lineage.attempt_revision > 0
        && !lineage.dispatch_id.trim().is_empty()
        && lineage.fencing_token > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_artifact_authority::{
        AdmissionRejection, ArtifactAdmissionGuard, ArtifactPrincipalKind,
        AuthenticatedArtifactPrincipal,
    };
    use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
        ArtifactSemanticClass, ContentAddress, HashAlgorithm, LineageBinding, ProducerIdentity,
        Provenance,
    };

    fn reference(id: &str) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn config() -> ConfiguredArtifactAdmissionGuardConfig {
        ConfiguredArtifactAdmissionGuardConfig {
            allowed_workspace_refs: BTreeSet::from(["workspace-1".to_owned()]),
            allowed_artifact_type_refs: vec![reference("artifact-type")],
            allowed_transformation_contract_refs: vec![reference("capture")],
            allowed_retention_profile_refs: vec![reference("retention")],
            allowed_claim_semantic_profile_refs: vec![reference("claim")],
            allowed_claim_acceptance_contract_refs: vec![reference("acceptance")],
            allowed_evidence_profile_refs: vec![reference("evidence")],
        }
    }

    fn principal() -> AuthenticatedArtifactPrincipal {
        AuthenticatedArtifactPrincipal {
            kind: ArtifactPrincipalKind::GovernedCollector,
            principal_id: "collector:local".to_owned(),
            authenticated: true,
        }
    }

    fn artifact() -> ArtifactDescriptor {
        ArtifactDescriptor {
            artifact_id: "artifact-1".to_owned(),
            semantic_class: ArtifactSemanticClass::CommandReceipt as i32,
            type_contract_ref: Some(reference("artifact-type")),
            media_type: "application/json".to_owned(),
            content: Some(ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "b".repeat(64),
                byte_length: 2,
            }),
            provenance: Some(Provenance {
                lineage: Some(LineageBinding {
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
                }),
                producer: Some(ProducerIdentity {
                    principal_id: "collector:local".to_owned(),
                    principal_kind: "governed_collector".to_owned(),
                    component_name: "collector".to_owned(),
                    component_version: "0.1.0".to_owned(),
                    ..Default::default()
                }),
                transformation_contract_ref: Some(reference("capture")),
                workspace_ref: "workspace-1".to_owned(),
                ..Default::default()
            }),
            sensitivity_class: "local".to_owned(),
            retention_profile_ref: Some(reference("retention")),
            ..Default::default()
        }
    }

    #[test]
    fn configured_guard_accepts_reviewed_artifact_scope() {
        let guard = ConfiguredArtifactAdmissionGuard::new(config()).expect("valid guard");
        guard
            .validate_artifact(&artifact(), b"{}", &principal())
            .expect("reviewed artifact should be admitted");
    }

    #[test]
    fn configured_guard_rejects_workspace_and_contract_drift() {
        let guard = ConfiguredArtifactAdmissionGuard::new(config()).expect("valid guard");
        let mut candidate = artifact();
        candidate
            .provenance
            .as_mut()
            .expect("provenance")
            .workspace_ref = "workspace-forged".to_owned();
        assert_eq!(
            guard.validate_artifact(&candidate, b"{}", &principal()),
            Err(AdmissionRejection::ScopeViolation)
        );
        let mut candidate = artifact();
        candidate.type_contract_ref = Some(reference("forged-type"));
        assert_eq!(
            guard.validate_artifact(&candidate, b"{}", &principal()),
            Err(AdmissionRejection::ScopeViolation)
        );
    }

    #[test]
    fn derived_workspace_admission_is_exact_and_lease_scoped() {
        let guard = ConfiguredArtifactAdmissionGuard::new(config()).expect("valid guard");
        let admission = guard.derived_workspace_admission_handle();
        let mut candidate = artifact();
        let provenance = candidate.provenance.as_mut().expect("provenance");
        provenance.workspace_ref = "repository-task-derived".to_owned();
        provenance.raw_source_ref = Some("repository-binding:1".to_owned());
        let binding = DerivedWorkspaceAdmissionBinding {
            workspace_ref: provenance.workspace_ref.clone(),
            lineage: provenance.lineage.clone().expect("lineage"),
            source_binding_ref: provenance.raw_source_ref.clone().expect("source binding"),
        };

        assert_eq!(
            guard.validate_artifact(&candidate, b"{}", &principal()),
            Err(AdmissionRejection::ScopeViolation)
        );
        let lease = admission.register(binding).expect("exact binding lease");
        guard
            .validate_artifact(&candidate, b"{}", &principal())
            .expect("exact derived workspace should be admitted");

        let mut forged = candidate.clone();
        forged
            .provenance
            .as_mut()
            .expect("provenance")
            .raw_source_ref = Some("repository-binding:forged".to_owned());
        assert_eq!(
            guard.validate_artifact(&forged, b"{}", &principal()),
            Err(AdmissionRejection::ScopeViolation)
        );

        drop(lease);
        assert_eq!(
            guard.validate_artifact(&candidate, b"{}", &principal()),
            Err(AdmissionRejection::ScopeViolation)
        );
    }

    #[test]
    fn configured_guard_rejects_empty_policy_at_construction() {
        let mut invalid = config();
        invalid.allowed_workspace_refs.clear();
        assert!(matches!(
            ConfiguredArtifactAdmissionGuard::new(invalid),
            Err(ArtifactAdmissionGuardConfigurationError::InvalidConfiguration)
        ));
    }
}
