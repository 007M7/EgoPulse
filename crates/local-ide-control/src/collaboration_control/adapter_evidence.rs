#[path = "approval_evidence.rs"]
mod approval_evidence;

use super::{
    DELIVERY_OUTCOME_UNKNOWN_REASON_CODE, HarnessEvidenceResolver, ReferenceAuthorization,
    ReferenceGuardRejection, ResolvedHarnessEvidence,
};
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    CollaborationSnapshot, MarkAttemptOutcomeUnknownCommand, ReconciliationDisposition,
    RecordAttemptCancellationOutcomeCommand, RecordAttemptReconciliationCommand,
    RecordDeliveryReceiptCommand, RecordHarnessAckCommand, RecordRunningObservationCommand,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, DeliveryDisposition, DispatchReceipt, LifecycleKind,
    harness_observation,
};
use egopulse_domain_contracts::v01::egopulse::policy::v1::{
    HarnessApprovalDecisionRecord, HarnessApprovalDecisionState,
};
use egopulse_harness_adapter::{AdapterEdge, AdapterRuntimeResidencyReader};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const NATIVE_DISPATCH_SESSION_NOT_RESIDENT_REASON_CODE: &str =
    "NATIVE_DISPATCH_SESSION_NOT_RESIDENT";

type ApprovalPolicyEvidenceReader = Arc<
    dyn Fn(
            &str,
        ) -> Result<
            Option<(
                HarnessApprovalDecisionRecord,
                HarnessApprovalDecisionState,
                ApprovalDecisionEnvelope,
            )>,
            (),
        > + Send
        + Sync,
>;

/// Provider-neutral read port backed by the Adapter's durable edge.
///
/// Collaboration Control never receives native Codex/Kimi/DeepSeek values from
/// this type. It only verifies that a command-selected evidence reference is a
/// durable Adapter record with the expected digest, fence and payload shape.
pub struct AdapterBackedHarnessEvidenceResolver {
    edge: AdapterEdge,
    runtime_residency: Option<AdapterRuntimeResidencyReader>,
    approval_policy_evidence: Option<ApprovalPolicyEvidenceReader>,
}

impl AdapterBackedHarnessEvidenceResolver {
    #[must_use]
    pub fn new(edge: AdapterEdge) -> Self {
        Self {
            edge,
            runtime_residency: None,
            approval_policy_evidence: None,
        }
    }

    /// Installs the read-only residency capability exported by the same
    /// `GovernedHarnessAdapter` instance owned by the dispatch runner.
    #[must_use]
    pub fn with_runtime_residency(mut self, reader: AdapterRuntimeResidencyReader) -> Self {
        self.runtime_residency = Some(reader);
        self
    }

    #[must_use]
    pub fn with_approval_policy_evidence<F>(mut self, reader: F) -> Self
    where
        F: Fn(
                &str,
            ) -> Result<
                Option<(
                    HarnessApprovalDecisionRecord,
                    HarnessApprovalDecisionState,
                    ApprovalDecisionEnvelope,
                )>,
                (),
            > + Send
            + Sync
            + 'static,
    {
        self.approval_policy_evidence = Some(Arc::new(reader));
        self
    }

    #[must_use]
    pub fn edge(&self) -> &AdapterEdge {
        &self.edge
    }
}

impl HarnessEvidenceResolver for AdapterBackedHarnessEvidenceResolver {
    fn validate_delivery_unknown(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let expected_disposition = match command.reason_code.as_str() {
            DELIVERY_OUTCOME_UNKNOWN_REASON_CODE => DeliveryDisposition::Unknown,
            NATIVE_DISPATCH_SESSION_NOT_RESIDENT_REASON_CODE => DeliveryDisposition::Delivered,
            _ => return Err(ReferenceGuardRejection::UnverifiedReference),
        };
        let is_nonresident_recovery =
            command.reason_code == NATIVE_DISPATCH_SESSION_NOT_RESIDENT_REASON_CODE;
        if command.uncertainty_evidence_id.trim().is_empty() {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        let base = command
            .base
            .as_ref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let run = snapshot
            .run
            .as_ref()
            .filter(|run| run.run_id == base.run_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == base.attempt_id)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let dispatch_id = attempt
            .dispatch_id
            .as_deref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let receipt = self
            .edge
            .dispatch_receipt(dispatch_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        if let Some(receipt) = receipt.filter(|receipt| {
            receipt.receipt_id == command.uncertainty_evidence_id
                && DeliveryDisposition::try_from(receipt.disposition) == Ok(expected_disposition)
        }) {
            let envelope = self
                .edge
                .dispatch_envelope(dispatch_id)
                .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            let lineage = self
                .edge
                .dispatch_task_lineage(dispatch_id)
                .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            let capability = attempt
                .capability_profile_ref
                .as_ref()
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            let fencing_token = attempt
                .lease
                .as_ref()
                .map(|lease| lease.fencing_token)
                .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
            if receipt.adapter_id != self.edge.adapter_id()
                || receipt.dispatch_id != dispatch_id
                || receipt.attempt_id != attempt.attempt_id
                || receipt.fencing_token != fencing_token
                || receipt.fencing_token != envelope.fencing_token
                || receipt.capability_profile_id != capability.contract_id
                || (is_nonresident_recovery
                    && (receipt.evidence_ref.trim().is_empty()
                        || receipt.delivered_at.is_none()
                        || canonical_receipt_digest(&receipt) != receipt.receipt_digest_sha256))
                || envelope.dispatch_id != dispatch_id
                || envelope.run_id != run.run_id
                || envelope.step_id != attempt.step_id
                || envelope.attempt_id != attempt.attempt_id
                || envelope.capability_profile_ref.as_ref() != Some(capability)
                || lineage.task_id != run.task_id
                || lineage.task_revision != run.task_revision_at_creation
                || lineage.work_revision != run.work_revision
            {
                return Err(ReferenceGuardRejection::UnverifiedReference);
            }
            if is_nonresident_recovery {
                let residency = self
                    .runtime_residency
                    .as_ref()
                    .filter(|reader| reader.adapter_id() == self.edge.adapter_id())
                    .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
                if !residency
                    .observes_nonresident_dispatch(dispatch_id)
                    .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
                {
                    return Err(ReferenceGuardRejection::UnverifiedReference);
                }
            }
            return Ok(ReferenceAuthorization {
                evidence_refs: vec![if is_nonresident_recovery {
                    format!(
                        "adapter-delivered-nonresident:{}:{}@durable",
                        receipt.receipt_id, receipt.receipt_digest_sha256
                    )
                } else {
                    format!(
                        "adapter-delivery-unknown:{}:{}@durable",
                        receipt.receipt_id, receipt.receipt_digest_sha256
                    )
                }],
            });
        }
        if is_nonresident_recovery {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        approval_evidence::validate_approval_delivery_unknown(
            &self.edge,
            self.approval_policy_evidence.as_ref(),
            command,
            snapshot,
        )
    }

    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        let receipt = self
            .edge
            .dispatch_receipt(&command.dispatch_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt_id = command
            .base
            .as_ref()
            .map(|value| value.attempt_id.as_str())
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if receipt.receipt_id != command.delivery_receipt_id
            || receipt.receipt_digest_sha256 != command.receipt_digest_sha256
            || receipt.attempt_id != attempt_id
            || receipt.fencing_token != command.fencing_token
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: receipt.native_session_ref,
            evidence_refs: vec![format!(
                "adapter-receipt:{}@durable",
                command.delivery_receipt_id
            )],
        })
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence_by_sequence(&command.dispatch_id, command.harness_sequence)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let ack = match evidence.observation.payload.as_ref() {
            Some(harness_observation::Payload::Ack(value)) => value,
            _ => return Err(ReferenceGuardRejection::UnverifiedReference),
        };
        if evidence.observation.native_event_digest_sha256 != command.receipt_digest_sha256
            || evidence.observation.fencing_token != command.fencing_token
            || ack.ack_receipt_id != command.ack_receipt_id
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ResolvedHarnessEvidence {
            harness_session_ref: ack.native_session_ref.clone(),
            evidence_refs: vec![format!(
                "adapter-observation:{}@durable",
                evidence.observation.observation_id
            )],
        })
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.lifecycle_event_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|value| {
                Some(value.attempt_id.as_str())
                    == command.base.as_ref().map(|base| base.attempt_id.as_str())
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if evidence.observation.dispatch_id != attempt.dispatch_id.clone().unwrap_or_default()
            || evidence.observation.observation_sequence != command.harness_sequence
            || evidence.observation.fencing_token != command.fencing_token
            || evidence.observation.native_event_digest_sha256 != command.event_digest_sha256
            || !matches!(
                evidence.observation.payload,
                Some(harness_observation::Payload::Lifecycle(ref value))
                    if value.kind == LifecycleKind::ExecutionStarted as i32
            )
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-observation:{}@durable",
                command.lifecycle_event_id
            )],
        })
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        _snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.cancellation_receipt_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if !matches!(
            evidence.observation.payload,
            Some(harness_observation::Payload::Lifecycle(ref value))
                if value.kind == LifecycleKind::ExecutionInterrupted as i32
        ) {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-cancellation-observation:{}@durable",
                command.cancellation_receipt_id
            )],
        })
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        let evidence = self
            .edge
            .observation_evidence(&command.evidence_id)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let diagnostic = match evidence.observation.payload {
            Some(harness_observation::Payload::Diagnostic(value)) => value,
            _ => return Err(ReferenceGuardRejection::UnverifiedReference),
        };
        let disposition = ReconciliationDisposition::try_from(command.disposition)
            .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|attempt| {
                command
                    .base
                    .as_ref()
                    .is_some_and(|base| base.attempt_id == attempt.attempt_id)
            })
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let dispatch_id = attempt
            .dispatch_id
            .as_deref()
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        let fencing_token = attempt
            .lease
            .as_ref()
            .map(|lease| lease.fencing_token)
            .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
        if evidence.observation.native_event_id.as_deref()
            != Some(command.reconciliation_id.as_str())
            || evidence.observation.dispatch_id != dispatch_id
            || evidence.observation.attempt_id != attempt.attempt_id
            || evidence.observation.fencing_token != fencing_token
            || !matches!(
                (diagnostic.safe_diagnostic_code.as_str(), disposition),
                (
                    "ADAPTER_RECONCILIATION_NO_EFFECT_PROVEN",
                    ReconciliationDisposition::NoEffectProven
                ) | (
                    "ADAPTER_RECONCILIATION_NATIVE_EXECUTION_ACTIVE",
                    ReconciliationDisposition::ManualOnly
                ) | (
                    "ADAPTER_RECONCILIATION_TERMINAL_OBSERVATION_RECOVERED",
                    ReconciliationDisposition::ManualOnly
                ) | (
                    "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN",
                    ReconciliationDisposition::ManualOnly
                )
            )
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        Ok(ReferenceAuthorization {
            evidence_refs: vec![format!(
                "adapter-reconciliation:{}@durable",
                command.evidence_id
            )],
        })
    }
}

fn canonical_receipt_digest(receipt: &DispatchReceipt) -> String {
    let mut canonical = receipt.clone();
    canonical.receipt_digest_sha256.clear();
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}
