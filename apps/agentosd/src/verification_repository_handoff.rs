use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_cognition_runtime::task_authority::PendingTaskVerification;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::ArtifactSet,
    common::v1::ContractReference,
    verification::v1::{CheckerProfile, VerificationBinding},
};
use egopulse_verification_authority::ArtifactReferenceSource;

use crate::{
    verification::{
        DynamicPrimaryClaimHandoffPlan, VerificationHandoffIntakeError, VerificationHandoffPlan,
        VerificationHandoffPlanError, VerificationHandoffPreparation,
    },
    verification_material::{RepositoryVerificationMaterialResolver, VerificationMaterialError},
    verification_profile::{RepositoryCheckerDeploymentPreparer, RepositoryCheckerProfileError},
};

pub(crate) struct RepositoryVerificationHandoffPreparation {
    material: Arc<RepositoryVerificationMaterialResolver>,
    profiles: Arc<RepositoryCheckerDeploymentPreparer>,
    claim_semantic_profile_ref: ContractReference,
}

impl RepositoryVerificationHandoffPreparation {
    pub(crate) fn new(
        material: Arc<RepositoryVerificationMaterialResolver>,
        profiles: Arc<RepositoryCheckerDeploymentPreparer>,
        claim_semantic_profile_ref: ContractReference,
    ) -> Self {
        Self {
            material,
            profiles,
            claim_semantic_profile_ref,
        }
    }
}

impl VerificationHandoffPreparation for RepositoryVerificationHandoffPreparation {
    fn prepare(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        artifact: &dyn ArtifactReferenceSource,
    ) -> Result<VerificationHandoffPlan, VerificationHandoffIntakeError> {
        let invalid = || {
            VerificationHandoffIntakeError::Plan(VerificationHandoffPlanError::ArtifactSetInvalid)
        };
        let snapshot = handoff.event.snapshot.as_ref().ok_or_else(invalid)?;
        let lineage = artifact_set.lineage.as_ref().ok_or_else(invalid)?;
        let [claim_id] = artifact_set.claim_ids.as_slice() else {
            return Err(invalid());
        };
        let claim = artifact.read_claim(claim_id)?.ok_or_else(invalid)?;
        if claim.semantic_profile_ref.as_ref() != Some(&self.claim_semantic_profile_ref) {
            return Err(VerificationHandoffIntakeError::PreparationBlocked(
                "VERIFICATION_HANDOFF_NOT_OWNED",
            ));
        }
        if snapshot.task_id != lineage.task_id
            || snapshot.work_revision != lineage.work_revision
            || Some(snapshot.revision) != lineage.task_revision.checked_add(1)
            || snapshot.artifact_set_id.as_deref() != Some(artifact_set.artifact_set_id.as_str())
        {
            return Err(invalid());
        }
        // Construct only a binding from current owner facts. No placeholder
        // request, profile reference or DispatchEnvelope is introduced to obtain
        // the first real deployment declaration.
        let binding = VerificationBinding {
            lineage: Some(lineage.clone()),
            artifact_set_id: artifact_set.artifact_set_id.clone(),
            artifact_set_manifest: artifact_set.canonical_manifest.clone(),
            claim_id: claim_id.clone(),
            claim_semantic_profile_ref: Some(self.claim_semantic_profile_ref.clone()),
            acceptance_contract_ref: snapshot.acceptance_contract_ref.clone(),
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?;
        let material = self
            .material
            .resolve(
                &binding,
                i64::try_from(now.as_secs()).map_err(|_| invalid())?,
            )
            .map_err(|error| {
                VerificationHandoffIntakeError::PreparationBlocked(match error {
                    VerificationMaterialError::Invalid => "VERIFICATION_MATERIAL_INVALID",
                    VerificationMaterialError::Unavailable => "VERIFICATION_MATERIAL_UNAVAILABLE",
                })
            })?;
        let profiles = self
            .profiles
            .prepare_for(
                &material,
                prost_types::Timestamp {
                    seconds: i64::try_from(now.as_secs()).map_err(|_| invalid())?,
                    nanos: now.subsec_nanos() as i32,
                },
            )
            .map_err(|error| {
                VerificationHandoffIntakeError::PreparationBlocked(match error {
                    RepositoryCheckerProfileError::InvalidConfiguration => {
                        "CHECKER_PROFILE_DEPLOYMENT_INVALID_CONFIGURATION"
                    }
                    RepositoryCheckerProfileError::InvalidMaterial => {
                        "CHECKER_PROFILE_DEPLOYMENT_INVALID_MATERIAL"
                    }
                    RepositoryCheckerProfileError::Unavailable => {
                        "CHECKER_PROFILE_DEPLOYMENT_UNAVAILABLE"
                    }
                    RepositoryCheckerProfileError::Conflict => {
                        "CHECKER_PROFILE_DEPLOYMENT_CONFLICT"
                    }
                })
            })?;
        DynamicPrimaryClaimHandoffPlan {
            claim_semantic_profile_ref: self.claim_semantic_profile_ref.clone(),
            criterion_ids: vec!["scope".into(), "tests".into(), "review".into()],
            checker_profile_refs: vec![
                profile_ref(&profiles.scope),
                profile_ref(&profiles.tests),
                profile_ref(&profiles.review),
            ],
        }
        .resolve(handoff, artifact_set, artifact)
    }
}

fn profile_ref(profile: &CheckerProfile) -> ContractReference {
    ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    }
}
