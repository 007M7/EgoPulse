use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{ArtifactAdmissionGuard, ArtifactAuthority, ArtifactClock};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding, ReturnHandoffStatus,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    CollaborationSnapshot, RecordAttemptCancellationOutcomeCommand,
    RecordAttemptReconciliationCommand, RecordAttemptReturnCommand, RecordDeliveryReceiptCommand,
    RecordHarnessAckCommand, RecordRunningObservationCommand,
};
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CriterionOutcome, CriterionRequirement, EvidenceCoverage, VerificationArtifact,
    VerificationConclusion,
};
use egopulse_harness_adapter::AdapterEdge;
use egopulse_local_ide_control::collaboration_control::{
    AdapterBackedHarnessEvidenceResolver, ArtifactReturnSource, HarnessEvidenceResolver,
    PendingArtifactReturn, ReferenceAuthorization, ReferenceGuardRejection, ResolvedArtifactReturn,
    ResolvedHarnessEvidence, ResolvedStepReturn,
};
use egopulse_verification_authority::VerificationAuthority;
use prost::Message;
use sha2::{Digest, Sha256};

pub struct ArtifactAuthorityReturnSource<G, C> {
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
}

fn complete_sha256(value: Option<&ContentAddress>) -> bool {
    value.is_some_and(|value| {
        value.algorithm == HashAlgorithm::Sha256 as i32
            && value.byte_length > 0
            && value.digest.len() == 64
            && value
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn select_accepted_verification_artifact(
    artifacts: Vec<VerificationArtifact>,
    artifact_set: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactSet,
    lineage: &LineageBinding,
) -> Option<VerificationArtifact> {
    let mut candidates = artifacts
        .into_iter()
        .filter(|artifact| {
            let Some(binding) = artifact.binding.as_ref() else {
                return false;
            };
            let Some(artifact_lineage) = binding.lineage.as_ref() else {
                return false;
            };
            binding.artifact_set_id == artifact_set.artifact_set_id
                && binding.artifact_set_manifest == artifact_set.canonical_manifest
                && artifact_lineage == lineage
                && artifact.version == 1
                && artifact.conclusion == VerificationConclusion::Passed as i32
                && artifact.overall_evidence_coverage == EvidenceCoverage::Complete as i32
                && complete_sha256(artifact.canonical_payload.as_ref())
                && artifact.completed_at.is_some()
                && artifact.criterion_results.iter().all(|result| {
                    result.requirement != CriterionRequirement::MustPass as i32
                        || result.outcome == CriterionOutcome::Passed as i32
                })
        })
        .collect::<Vec<_>>();
    (candidates.len() == 1).then(|| candidates.pop().expect("one candidate"))
}

impl<G, C> ArtifactAuthorityReturnSource<G, C> {
    #[must_use]
    pub fn new(authority: Arc<Mutex<ArtifactAuthority<G, C>>>) -> Self {
        Self { authority }
    }
}

impl<G, C> ArtifactReturnSource for ArtifactAuthorityReturnSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn pending_returns(&self) -> Result<Vec<PendingArtifactReturn>, String> {
        self.authority
            .lock()
            .map_err(|_| "Artifact Authority lock poisoned".to_owned())?
            .drain_collaboration_outbox()
            .map_err(|_| "Artifact Authority collaboration outbox unavailable".to_owned())?
            .into_iter()
            .map(|message| {
                let receipt = message.result.return_receipt.ok_or_else(|| {
                    "Artifact collaboration outbox contained no return receipt".to_owned()
                })?;
                if !receipt.accepted_for_evidence_intake
                    || receipt.verification_performed
                    || receipt.task_completion_decided
                    || receipt.lineage.is_none()
                {
                    return Err("Artifact return receipt flags or lineage invalid".to_owned());
                }
                Ok(PendingArtifactReturn {
                    message_id: message.message_id,
                    payload_digest_sha256: message.payload_digest_sha256,
                    receipt,
                })
            })
            .collect()
    }

    fn acknowledge_return(
        &self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, String> {
        self.authority
            .lock()
            .map_err(|_| "Artifact Authority lock poisoned".to_owned())?
            .acknowledge_collaboration_projection(message_id, payload_digest_sha256)
            .map_err(|_| "Artifact collaboration outbox acknowledgement failed".to_owned())
    }
}

/// Evidence join used only by Collaboration Control. Native protocol values
/// remain behind Adapter Edge and Artifact storage remains behind Artifact
/// Authority; this adapter compares their typed read ports without writing
/// either owner.
pub struct GovernedReturnEvidenceResolver<G, C> {
    harness: AdapterBackedHarnessEvidenceResolver,
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
    verification: Arc<Mutex<VerificationAuthority>>,
}

impl<G, C> GovernedReturnEvidenceResolver<G, C> {
    #[must_use]
    pub fn new(
        edge: AdapterEdge,
        authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        verification: Arc<Mutex<VerificationAuthority>>,
    ) -> Self {
        Self {
            harness: AdapterBackedHarnessEvidenceResolver::new(edge),
            authority,
            verification,
        }
    }
}

impl<G, C> HarnessEvidenceResolver for GovernedReturnEvidenceResolver<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.harness.resolve_delivery_receipt(command, snapshot)
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.harness.resolve_harness_ack(command, snapshot)
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.harness.validate_running_observation(command, snapshot)
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.harness
            .validate_cancellation_outcome(command, snapshot)
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.harness.validate_reconciliation(command, snapshot)
    }

    fn resolve_attempt_return(
        &self,
        command: &RecordAttemptReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedArtifactReturn, ReferenceGuardRejection> {
        let receipt = self
            .authority
            .lock()
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .read_return_receipt(&command.artifact_return_receipt_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let receipt_digest = hex::encode(Sha256::digest(receipt.encode_to_vec()));
        let lineage = receipt
            .lineage
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let run = snapshot
            .run
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let step = snapshot
            .steps
            .iter()
            .find(|step| step.step_id == lineage.step_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == lineage.attempt_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let candidate = self
            .harness
            .edge()
            .terminal_output_candidate_for_dispatch(&lineage.dispatch_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;

        if receipt.receipt_id != command.artifact_return_receipt_id
            || receipt_digest != command.receipt_digest_sha256
            || !receipt.accepted_for_evidence_intake
            || receipt.verification_performed
            || receipt.task_completion_decided
            || receipt.return_handoff_id.trim().is_empty()
            || receipt.artifact_set_id.trim().is_empty()
            || lineage.task_id != run.task_id
            || lineage.task_revision != run.task_revision_at_creation
            || lineage.work_revision != run.work_revision
            || lineage.run_id != run.run_id
            || lineage.run_revision == 0
            || lineage.run_revision > run.revision
            || lineage.step_id != step.step_id
            || lineage.step_revision == 0
            || lineage.step_revision > step.revision
            || lineage.attempt_id != attempt.attempt_id
            || lineage.attempt_revision == 0
            || lineage.attempt_revision > attempt.revision
            || attempt.dispatch_id.as_deref() != Some(lineage.dispatch_id.as_str())
            || lineage.fencing_token != command.fencing_token
            || candidate.fencing_token != command.fencing_token
            || candidate.source_revision != command.harness_sequence
            || candidate.run_id != lineage.run_id
            || candidate.task_id != lineage.task_id
            || candidate.task_revision != lineage.task_revision
            || candidate.work_revision != lineage.work_revision
            || candidate.step_id != lineage.step_id
            || candidate.attempt_id != lineage.attempt_id
            || !candidate.content_complete
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }

        Ok(ResolvedArtifactReturn {
            artifact_set_id: receipt.artifact_set_id.clone(),
            return_handoff_id: receipt.return_handoff_id.clone(),
            dispatch_id: lineage.dispatch_id.clone(),
            evidence_refs: vec![
                format!("artifact-return-receipt:{}@durable", receipt.receipt_id),
                format!(
                    "adapter-terminal-observation:{}@durable",
                    candidate.source_observation_id
                ),
            ],
        })
    }

    fn resolve_step_return(
        &self,
        command: &egopulse_domain_contracts::v01::egopulse::collaboration::v1::CommitStepReturnCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedStepReturn, ReferenceGuardRejection> {
        let (handoff, artifact_set) = {
            let authority = self
                .authority
                .lock()
                .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
            let handoff = authority
                .read_return_handoff(&command.return_handoff_id)
                .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            let artifact_set = authority
                .read_artifact_set(&command.artifact_set_id)
                .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            (handoff, artifact_set)
        };
        let run = snapshot
            .run
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let step = snapshot
            .steps
            .iter()
            .find(|step| step.step_id == command.step_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == command.attempt_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let Some(set_lineage) = artifact_set.lineage.as_ref() else {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        };
        let Some(handoff_lineage) = handoff.lineage.as_ref() else {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        };
        if artifact_set.status != ArtifactSetStatus::Sealed as i32
            || handoff.status != ReturnHandoffStatus::Receipted as i32
            || artifact_set.artifact_set_id != command.artifact_set_id
            || handoff.return_handoff_id != command.return_handoff_id
            || handoff.artifact_set_id != command.artifact_set_id
            || handoff.artifact_set_manifest != artifact_set.canonical_manifest
            || handoff_lineage != set_lineage
            || set_lineage.task_id != run.task_id
            || set_lineage.task_revision != run.task_revision_at_creation
            || set_lineage.work_revision != run.work_revision
            || set_lineage.run_id != run.run_id
            || set_lineage.run_revision == 0
            || set_lineage.run_revision > run.revision
            || set_lineage.step_id != step.step_id
            || set_lineage.step_revision == 0
            || set_lineage.step_revision > step.revision
            || set_lineage.attempt_id != attempt.attempt_id
            || set_lineage.attempt_revision == 0
            || set_lineage.attempt_revision > attempt.revision
            || attempt.dispatch_id.as_deref() != Some(set_lineage.dispatch_id.as_str())
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }

        let artifacts = self
            .verification
            .lock()
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .verification_artifacts()
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        let Some(verification_artifact) =
            select_accepted_verification_artifact(artifacts, &artifact_set, set_lineage)
        else {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        };
        Ok(ResolvedStepReturn {
            artifact_set_id: command.artifact_set_id.clone(),
            return_handoff_id: command.return_handoff_id.clone(),
            verification_artifact_id: verification_artifact.verification_artifact_id,
            evidence_refs: vec![format!(
                "return-handoff:{}@durable",
                handoff.return_handoff_id
            )],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::ArtifactSet,
        verification::v1::{CriterionResult, VerificationBinding},
    };
    use prost_types::Timestamp;

    fn fixture() -> (ArtifactSet, LineageBinding, VerificationArtifact) {
        let manifest = ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: "a".repeat(64),
            byte_length: 1,
        };
        let lineage = LineageBinding {
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
        };
        let artifact_set = ArtifactSet {
            artifact_set_id: "set-1".to_owned(),
            canonical_manifest: Some(manifest.clone()),
            ..ArtifactSet::default()
        };
        let artifact = VerificationArtifact {
            verification_artifact_id: "verification-1".to_owned(),
            version: 1,
            binding: Some(VerificationBinding {
                lineage: Some(lineage.clone()),
                artifact_set_id: artifact_set.artifact_set_id.clone(),
                artifact_set_manifest: Some(manifest),
                ..VerificationBinding::default()
            }),
            conclusion: VerificationConclusion::Passed as i32,
            overall_evidence_coverage: EvidenceCoverage::Complete as i32,
            criterion_results: vec![CriterionResult {
                requirement: CriterionRequirement::MustPass as i32,
                outcome: CriterionOutcome::Passed as i32,
                ..CriterionResult::default()
            }],
            canonical_payload: Some(ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "b".repeat(64),
                byte_length: 1,
            }),
            completed_at: Some(Timestamp {
                seconds: 1,
                nanos: 0,
            }),
            ..VerificationArtifact::default()
        };
        (artifact_set, lineage, artifact)
    }

    #[test]
    fn accepted_verification_selection_is_binding_and_ambiguity_safe() {
        let (artifact_set, lineage, accepted) = fixture();
        assert_eq!(
            select_accepted_verification_artifact(vec![accepted.clone()], &artifact_set, &lineage,)
                .expect("accepted artifact")
                .verification_artifact_id,
            "verification-1"
        );

        let mut failed = accepted.clone();
        failed.verification_artifact_id = "verification-failed".to_owned();
        failed.conclusion = VerificationConclusion::Failed as i32;
        assert!(
            select_accepted_verification_artifact(vec![failed], &artifact_set, &lineage,).is_none()
        );

        let mut duplicate = accepted.clone();
        duplicate.verification_artifact_id = "verification-duplicate".to_owned();
        assert!(
            select_accepted_verification_artifact(
                vec![accepted, duplicate],
                &artifact_set,
                &lineage,
            )
            .is_none()
        );
    }
}
