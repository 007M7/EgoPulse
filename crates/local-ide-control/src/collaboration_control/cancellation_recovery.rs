//! Read-only reconstruction of Task cancellation recovery facts from the
//! current, durably committed Collaboration head.

use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{
        AttemptSnapshot, AttemptStatus, CollaborationEvent, CollaborationEventKind,
        CollaborationSnapshot, RunStatus, StepSnapshot, StepStatus,
    },
    common::v1::ContractReference,
};
use prost::Message;

use super::{
    AUTHORITY_REF, CollaborationControl, CollaborationControlError, contract_reference_is_complete,
    harness_dispatch::{TaskRecoveryFinding, TaskRecoveryKind},
    store::SettledCancellationHead,
};

impl<G, C> CollaborationControl<G, C> {
    /// Reconstructs cancellation findings only from a current-revision
    /// `CancellationRecorded` event with a durable commit receipt. The caller
    /// remains responsible for exact profile routing and Task-side settlement.
    pub(super) fn settled_cancellation_findings(
        &self,
    ) -> Result<Vec<(TaskRecoveryFinding, ContractReference)>, CollaborationControlError> {
        let mut findings = Vec::new();
        for head in self.store.settled_cancellation_heads(
            RunStatus::Cancelled as i32,
            RunStatus::ReturnPending as i32,
        )? {
            if let Some(finding) = settled_cancellation_finding(head)? {
                findings.push(finding);
            }
        }
        Ok(findings)
    }
}

fn settled_cancellation_finding(
    head: SettledCancellationHead,
) -> Result<Option<(TaskRecoveryFinding, ContractReference)>, CollaborationControlError> {
    let event = CollaborationEvent::decode(head.event.as_slice())?;
    // ReturnPending is also the normal pre-verification state after an
    // AttemptReturnRecorded event. It is not a cancellation recovery fact and
    // must not make the daemon fail. Once the current head says
    // CancellationRecorded, every remaining mismatch is an integrity error.
    if event.kind != CollaborationEventKind::CancellationRecorded as i32 {
        return Ok(None);
    }
    let snapshot = decode_snapshot(&head)?;
    let run = snapshot
        .run
        .as_ref()
        .ok_or(CollaborationControlError::Persistence)?;
    if event.event_id != head.event_id
        || event.run_id != head.run_id
        || event.resulting_run_revision != head.run_revision
        || event.expected_run_revision.checked_add(1) != Some(event.resulting_run_revision)
        || event.authority_ref != AUTHORITY_REF
        || event.authenticated_principal_id.trim().is_empty()
        || event.command_id.trim().is_empty()
        || event.idempotency_key.trim().is_empty()
        || event.correlation_id.trim().is_empty()
        || event.occurred_at.is_none()
        || !sha256_is_complete(&event.request_digest_sha256)
        || event.request_digest_sha256 != head.event_request_digest_sha256
        || event.request_digest_sha256 != head.receipt_request_digest_sha256
        || event.idempotency_key != head.receipt_idempotency_key
        || head.receipt_aggregate_id != head.run_id
        || head.receipt_aggregate_revision != head.run_revision
        || run.run_id != head.run_id
        || run.revision != head.run_revision
        || run.task_id.trim().is_empty()
        || run.work_revision == 0
        || event.evidence_refs.is_empty()
        || event
            .evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CollaborationControlError::Persistence);
    }

    let step_id = event
        .step_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CollaborationControlError::Persistence)?;
    let attempt_id = event
        .attempt_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CollaborationControlError::Persistence)?;
    let step = current_step(&snapshot, step_id)?;
    let attempt = current_attempt(&snapshot, step_id, attempt_id)?;
    if event.resulting_step_revision != Some(step.revision)
        || event.resulting_attempt_revision != Some(attempt.revision)
        || !run.step_ids.iter().any(|value| value == step_id)
        || !step.attempt_ids.iter().any(|value| value == attempt_id)
        || step.current_attempt_id.as_deref() != Some(attempt_id)
        || attempt.run_id != run.run_id
        || attempt.step_id != step.step_id
    {
        return Err(CollaborationControlError::Persistence);
    }
    let profile = attempt
        .capability_profile_ref
        .clone()
        .filter(contract_reference_is_complete)
        .ok_or(CollaborationControlError::Persistence)?;
    let (cancellation_evidence, receipt_id) =
        unique_prefixed_evidence(&event.evidence_refs, "cancellation-receipt:")?;

    let kind = match RunStatus::try_from(run.status) {
        Ok(RunStatus::Cancelled)
            if step.status == StepStatus::Cancelled as i32
                && attempt.status == AttemptStatus::Cancelled as i32
                && event.evidence_refs.iter().any(|item| {
                    item == &format!("adapter-cancellation-observation:{receipt_id}@durable")
                }) =>
        {
            TaskRecoveryKind::CancellationConfirmed
        }
        Ok(RunStatus::ReturnPending)
            if step.status == StepStatus::ReturnPending as i32
                && attempt.status == AttemptStatus::Returned as i32
                && step
                    .artifact_set_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                && step
                    .return_handoff_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                && event.evidence_refs.iter().any(|item| {
                    item == &format!("artifact-return-receipt:{receipt_id}@durable")
                })
                && has_unique_durable_evidence(
                    &event.evidence_refs,
                    "adapter-terminal-observation:",
                ) =>
        {
            TaskRecoveryKind::CancellationReturnFound
        }
        _ => return Err(CollaborationControlError::Persistence),
    };
    Ok(Some((
        TaskRecoveryFinding {
            kind,
            task_id: run.task_id.clone(),
            run_id: run.run_id.clone(),
            evidence_ref: if kind == TaskRecoveryKind::CancellationConfirmed {
                cancellation_evidence.to_owned()
            } else {
                receipt_id.to_owned()
            },
        },
        profile,
    )))
}

fn decode_snapshot(
    head: &SettledCancellationHead,
) -> Result<CollaborationSnapshot, CollaborationControlError> {
    Ok(CollaborationSnapshot {
        run: Some(
            egopulse_domain_contracts::v01::egopulse::collaboration::v1::RunSnapshot::decode(
                head.snapshots.run.as_slice(),
            )?,
        ),
        steps: head
            .snapshots
            .steps
            .iter()
            .map(|bytes| StepSnapshot::decode(bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?,
        attempts: head
            .snapshots
            .attempts
            .iter()
            .map(|bytes| AttemptSnapshot::decode(bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn current_step<'a>(
    snapshot: &'a CollaborationSnapshot,
    step_id: &str,
) -> Result<&'a StepSnapshot, CollaborationControlError> {
    let mut matches = snapshot.steps.iter().filter(|step| step.step_id == step_id);
    let step = matches
        .next()
        .ok_or(CollaborationControlError::Persistence)?;
    if matches.next().is_some() || step.run_id != snapshot.run.as_ref().expect("run checked").run_id
    {
        return Err(CollaborationControlError::Persistence);
    }
    Ok(step)
}

fn current_attempt<'a>(
    snapshot: &'a CollaborationSnapshot,
    step_id: &str,
    attempt_id: &str,
) -> Result<&'a AttemptSnapshot, CollaborationControlError> {
    let mut matches = snapshot
        .attempts
        .iter()
        .filter(|attempt| attempt.attempt_id == attempt_id && attempt.step_id == step_id);
    let attempt = matches
        .next()
        .ok_or(CollaborationControlError::Persistence)?;
    if matches.next().is_some() {
        return Err(CollaborationControlError::Persistence);
    }
    Ok(attempt)
}

fn unique_prefixed_evidence<'a>(
    evidence_refs: &'a [String],
    prefix: &str,
) -> Result<(&'a str, &'a str), CollaborationControlError> {
    let mut matches = evidence_refs.iter().filter_map(|item| {
        item.strip_prefix(prefix)
            .map(|suffix| (item.as_str(), suffix))
    });
    let (evidence, suffix) = matches
        .next()
        .filter(|(_, suffix)| !suffix.trim().is_empty())
        .ok_or(CollaborationControlError::Persistence)?;
    if matches.next().is_some() {
        return Err(CollaborationControlError::Persistence);
    }
    Ok((evidence, suffix))
}

fn has_unique_durable_evidence(evidence_refs: &[String], prefix: &str) -> bool {
    let mut matches = evidence_refs.iter().filter_map(|item| {
        item.strip_prefix(prefix)
            .and_then(|value| value.strip_suffix("@durable"))
            .filter(|value| !value.trim().is_empty())
    });
    matches.next().is_some() && matches.next().is_none()
}

fn sha256_is_complete(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collaboration_control::store::SnapshotBlobs;
    use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
        AttemptSnapshot, CollaborationEvent, RunSnapshot, StepSnapshot,
    };

    #[test]
    fn ordinary_return_pending_head_is_not_a_cancellation_finding_or_error() {
        let event = CollaborationEvent {
            event_id: "event-return-1".to_owned(),
            kind: CollaborationEventKind::ReturnRecorded as i32,
            run_id: "run-1".to_owned(),
            resulting_run_revision: 7,
            ..Default::default()
        };
        let head = SettledCancellationHead {
            run_id: "run-1".to_owned(),
            run_revision: 7,
            event_id: event.event_id.clone(),
            event_request_digest_sha256: "a".repeat(64),
            event: event.encode_to_vec(),
            receipt_aggregate_id: "run-1".to_owned(),
            receipt_aggregate_revision: 7,
            receipt_idempotency_key: "return-1".to_owned(),
            receipt_request_digest_sha256: "a".repeat(64),
            snapshots: SnapshotBlobs {
                run: RunSnapshot {
                    run_id: "run-1".to_owned(),
                    revision: 7,
                    status: RunStatus::ReturnPending as i32,
                    ..Default::default()
                }
                .encode_to_vec(),
                steps: vec![
                    StepSnapshot {
                        step_id: "step-1".to_owned(),
                        run_id: "run-1".to_owned(),
                        status: StepStatus::ReturnPending as i32,
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ],
                attempts: vec![
                    AttemptSnapshot {
                        attempt_id: "attempt-1".to_owned(),
                        run_id: "run-1".to_owned(),
                        step_id: "step-1".to_owned(),
                        status: AttemptStatus::Returned as i32,
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ],
            },
        };

        assert_eq!(
            settled_cancellation_finding(head).expect("ordinary return is readable"),
            None
        );
    }
}
