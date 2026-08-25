use super::*;

/// Composes the business reference guard with the independent Adapter
/// evidence read port. The two owners remain separate; this type only joins
/// their typed interfaces at the Collaboration Control composition boundary.
pub struct CompositeCollaborationGuard<G, E> {
    reference: G,
    evidence: E,
}

impl<G, E> CompositeCollaborationGuard<G, E> {
    #[must_use]
    pub fn new(reference: G, evidence: E) -> Self {
        Self {
            reference,
            evidence,
        }
    }

    #[must_use]
    pub fn reference(&self) -> &G {
        &self.reference
    }

    #[must_use]
    pub fn evidence(&self) -> &E {
        &self.evidence
    }
}

impl<G, E> CollaborationReferenceGuard for CompositeCollaborationGuard<G, E>
where
    G: CollaborationReferenceGuard,
{
    fn validate_create_run(
        &self,
        command: &CreateRunCommand,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference.validate_create_run(command)
    }

    fn validate_activate_run(
        &self,
        command: &ActivateRunCommand,
        run: &RunSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference.validate_activate_run(command, run)
    }

    fn validate_create_attempt(
        &self,
        command: &CreateAttemptCommand,
        run: &RunSnapshot,
        step: &StepSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference.validate_create_attempt(command, run, step)
    }

    fn authorize_lease(
        &self,
        command: &AcquireAttemptLeaseCommand,
        attempt: &AttemptSnapshot,
    ) -> Result<LeaseAuthorization, ReferenceGuardRejection> {
        self.reference.authorize_lease(command, attempt)
    }

    fn resolve_dispatch_material(
        &self,
        command: &RecordDispatchIntentCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<DispatchMaterial, ReferenceGuardRejection> {
        self.reference.resolve_dispatch_material(command, snapshot)
    }

    fn validate_unknown_outcome(
        &self,
        command: &MarkAttemptOutcomeUnknownCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference.validate_unknown_outcome(command, snapshot)
    }

    fn validate_cancellation_request(
        &self,
        command: &RequestAttemptCancellationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.reference
            .validate_cancellation_request(command, snapshot)
    }
}

impl<G, E> HarnessEvidenceResolver for CompositeCollaborationGuard<G, E>
where
    E: HarnessEvidenceResolver,
{
    fn resolve_delivery_receipt(
        &self,
        command: &RecordDeliveryReceiptCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.evidence.resolve_delivery_receipt(command, snapshot)
    }

    fn resolve_harness_ack(
        &self,
        command: &RecordHarnessAckCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ResolvedHarnessEvidence, ReferenceGuardRejection> {
        self.evidence.resolve_harness_ack(command, snapshot)
    }

    fn validate_running_observation(
        &self,
        command: &RecordRunningObservationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence
            .validate_running_observation(command, snapshot)
    }

    fn validate_cancellation_outcome(
        &self,
        command: &RecordAttemptCancellationOutcomeCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence
            .validate_cancellation_outcome(command, snapshot)
    }

    fn validate_reconciliation(
        &self,
        command: &RecordAttemptReconciliationCommand,
        snapshot: &CollaborationSnapshot,
    ) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
        self.evidence.validate_reconciliation(command, snapshot)
    }
}
