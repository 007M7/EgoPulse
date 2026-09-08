use super::{
    AdapterEdge, AdapterEdgeError, AdapterObservationEvidence, DispatchEnvelope,
    DispatchTaskLineage, PendingAdapterApprovalProjection,
};

/// A consistent owner read, including the private material that public
/// projections intentionally omit. Consumers must validate the exact join.
#[derive(Clone)]
pub struct RetainedApprovalAuthorization {
    pub projection: PendingAdapterApprovalProjection,
    pub evidence: AdapterObservationEvidence,
    pub envelope: DispatchEnvelope,
    pub lineage: Option<DispatchTaskLineage>,
}

#[derive(Clone)]
pub struct ApprovalAuthorizationSnapshot {
    pub entries: Vec<RetainedApprovalAuthorization>,
}

impl AdapterEdge {
    pub fn approval_authorization_snapshot(
        &self,
    ) -> Result<ApprovalAuthorizationSnapshot, AdapterEdgeError> {
        // Keep latest lifecycle selection and its private evidence in the same
        // SQLite read snapshot even when the live adapter has another handle.
        let transaction = self.connection.unchecked_transaction()?;
        let entries = self
            .retained_approval_projection_messages_for_rebuild()?
            .into_iter()
            .map(|projection| {
                let evidence = self
                    .observation_evidence(&projection.source_observation_id)?
                    .ok_or(AdapterEdgeError::IntegrityFailure)?;
                let envelope = self
                    .dispatch_envelope(&projection.dispatch_id)?
                    .ok_or(AdapterEdgeError::IntegrityFailure)?;
                let lineage = self.dispatch_task_lineage(&projection.dispatch_id)?;
                Ok(RetainedApprovalAuthorization {
                    projection,
                    evidence,
                    envelope,
                    lineage,
                })
            })
            .collect::<Result<Vec<_>, AdapterEdgeError>>()?;
        transaction.commit()?;
        Ok(ApprovalAuthorizationSnapshot { entries })
    }
}
