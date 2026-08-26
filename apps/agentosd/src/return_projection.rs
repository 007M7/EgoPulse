use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{ArtifactAdmissionGuard, ArtifactAuthority, ArtifactClock};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    CollaborationSnapshot, RecordAttemptCancellationOutcomeCommand,
    RecordAttemptReconciliationCommand, RecordAttemptReturnCommand, RecordDeliveryReceiptCommand,
    RecordHarnessAckCommand, RecordRunningObservationCommand,
};
use egopulse_harness_adapter::AdapterEdge;
use egopulse_local_ide_control::collaboration_control::{
    AdapterBackedHarnessEvidenceResolver, ArtifactReturnSource, HarnessEvidenceResolver,
    PendingArtifactReturn, ReferenceAuthorization, ReferenceGuardRejection, ResolvedArtifactReturn,
    ResolvedHarnessEvidence,
};
use prost::Message;
use sha2::{Digest, Sha256};

pub struct ArtifactAuthorityReturnSource<G, C> {
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
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
}

impl<G, C> GovernedReturnEvidenceResolver<G, C> {
    #[must_use]
    pub fn new(edge: AdapterEdge, authority: Arc<Mutex<ArtifactAuthority<G, C>>>) -> Self {
        Self {
            harness: AdapterBackedHarnessEvidenceResolver::new(edge),
            authority,
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
}
