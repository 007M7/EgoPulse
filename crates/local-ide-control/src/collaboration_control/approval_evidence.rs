use super::ApprovalPolicyEvidenceReader;
use crate::collaboration_control::{ReferenceAuthorization, ReferenceGuardRejection};
use egopulse_domain_contracts::v01::egopulse::{
    collaboration::v1::{CollaborationSnapshot, MarkAttemptOutcomeUnknownCommand},
    harness::v1::{ApprovalRequestLifecycleKind, DeliveryDisposition, harness_observation},
    policy::v1::HarnessApprovalDecisionStateKind,
};
use egopulse_harness_adapter::{AdapterEdge, ApprovalDeliveryState};
use prost::Message;
use sha2::{Digest, Sha256};

pub(super) fn validate_approval_delivery_unknown(
    edge: &AdapterEdge,
    policy_reader: Option<&ApprovalPolicyEvidenceReader>,
    command: &MarkAttemptOutcomeUnknownCommand,
    snapshot: &CollaborationSnapshot,
) -> Result<ReferenceAuthorization, ReferenceGuardRejection> {
    let reader = policy_reader.ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let (record, state, approval_envelope) = reader(&command.uncertainty_evidence_id)
        .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
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
    let capability = attempt
        .capability_profile_ref
        .as_ref()
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let fencing_token = attempt
        .lease
        .as_ref()
        .map(|lease| lease.fencing_token)
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let binding = record
        .request
        .as_ref()
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let approval = edge
        .approval_record(&binding.approval_request_id)
        .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let receipt = approval
        .receipt
        .as_ref()
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let authorization = edge
        .approval_authorization_snapshot()
        .map_err(|_| ReferenceGuardRejection::UnverifiedReference)?;
    let mut latest = None;
    for entry in &authorization.entries {
        let Some(harness_observation::Payload::ApprovalRequest(request)) =
            entry.evidence.observation.payload.as_ref()
        else {
            continue;
        };
        if request.approval_request_id != binding.approval_request_id {
            continue;
        }
        if entry.evidence.observation.adapter_id != binding.adapter_id
            || entry.evidence.observation.dispatch_id != binding.dispatch_id
            || entry.evidence.observation.attempt_id != binding.attempt_id
            || entry.evidence.observation.capability_profile_id != capability.contract_id
        {
            return Err(ReferenceGuardRejection::UnverifiedReference);
        }
        let candidate_key = (
            request.request_revision,
            entry.evidence.observation.observation_sequence,
        );
        match latest {
            Some((latest_key, _)) if candidate_key == latest_key => {
                return Err(ReferenceGuardRejection::UnverifiedReference);
            }
            Some((latest_key, _)) if candidate_key < latest_key => {}
            _ => latest = Some((candidate_key, entry)),
        }
    }
    let Some((_, authorization)) = latest else {
        return Err(ReferenceGuardRejection::UnverifiedReference);
    };
    if authorization.projection.source_observation_id != binding.request_observation_id
        || authorization.projection.source_revision != binding.request_observation_sequence
    {
        return Err(ReferenceGuardRejection::UnverifiedReference);
    }
    let projection = &authorization.projection;
    let private_evidence = &authorization.evidence;
    let dispatch = &authorization.envelope;
    let lineage = authorization
        .lineage
        .as_ref()
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;
    let private_request = match private_evidence.observation.payload.as_ref() {
        Some(harness_observation::Payload::ApprovalRequest(request)) => request,
        _ => return Err(ReferenceGuardRejection::UnverifiedReference),
    };
    let mut expected_projection = private_evidence.observation.clone();
    let Some(harness_observation::Payload::ApprovalRequest(projected_request)) =
        expected_projection.payload.as_mut()
    else {
        return Err(ReferenceGuardRejection::UnverifiedReference);
    };
    projected_request.native_routing_ref.clear();
    let route_profile = dispatch
        .route_binding
        .as_ref()
        .map(|route| route.capability_profile_id.as_str());
    let envelope_metadata = approval_envelope
        .meta
        .as_ref()
        .ok_or(ReferenceGuardRejection::UnverifiedReference)?;

    if command.uncertainty_evidence_id != record.authority_decision_ref
        || record.version != 1
        || record.canonical_payload_digest_sha256 != canonical_policy_record_digest(&record)
        || state.authority_decision_ref != record.authority_decision_ref
        || state.revision == 0
        || HarnessApprovalDecisionStateKind::try_from(state.state)
            != Ok(HarnessApprovalDecisionStateKind::Issued)
        || state.consumption_receipt_id.is_some()
        || state.superseded_by_authority_decision_ref.is_some()
        || state.terminal_reason_code.is_some()
        || envelope_metadata.request_digest_sha256 != record.canonical_payload_digest_sha256
        || envelope_metadata.idempotency_key != record.authority_decision_ref
        || envelope_metadata.idempotency_scope != "policy-decision-to-harness-adapter"
        || approval.request_digest_sha256 != digest(&approval_envelope)
        || approval.approval_request_id != binding.approval_request_id
        || approval.dispatch_id != binding.dispatch_id
        || approval.delivery_state != ApprovalDeliveryState::DeliveryUnknown
        || DeliveryDisposition::try_from(receipt.disposition) != Ok(DeliveryDisposition::Unknown)
        || receipt.receipt_digest_sha256 != canonical_receipt_digest(receipt)
        || receipt.approval_request_id != binding.approval_request_id
        || receipt.decision != record.decision
        || approval_envelope.attempt_id != binding.attempt_id
        || approval_envelope.dispatch_id != binding.dispatch_id
        || approval_envelope.fencing_token != binding.fencing_token
        || approval_envelope.approval_request_id != binding.approval_request_id
        || approval_envelope.action_digest_sha256 != binding.action_digest_sha256
        || approval_envelope.decision != record.decision
        || approval_envelope.authority_decision_ref != record.authority_decision_ref
        || approval_envelope.native_routing_ref != binding.native_routing_ref
        || binding.attempt_id != attempt.attempt_id
        || binding.dispatch_id != attempt.dispatch_id.as_deref().unwrap_or_default()
        || binding.fencing_token != fencing_token
        || binding.adapter_id != edge.adapter_id()
        || binding.request_observation_sequence == 0
        || binding.request_lifecycle != ApprovalRequestLifecycleKind::Open as i32
        || private_evidence.observation.observation_id != binding.request_observation_id
        || private_evidence.observation.adapter_id != binding.adapter_id
        || private_evidence.observation.attempt_id != binding.attempt_id
        || private_evidence.observation.dispatch_id != binding.dispatch_id
        || private_evidence.observation.fencing_token != binding.fencing_token
        || private_evidence.observation.observation_sequence != binding.request_observation_sequence
        || private_request.approval_request_id != binding.approval_request_id
        || private_request.kind != binding.kind
        || private_request.action_digest_sha256 != binding.action_digest_sha256
        || private_request.requested_scope_ref != binding.requested_scope_ref
        || private_request.native_routing_ref != binding.native_routing_ref
        || private_request.lifecycle != binding.request_lifecycle
        || private_request.request_revision != binding.request_revision
        || private_request.native_routing_ref.trim().is_empty()
        || digest_bytes(&private_evidence.raw_event)
            != private_evidence.observation.native_event_digest_sha256
        || expected_projection != projection.observation
        || projection.payload_digest_sha256 != digest(&projection.observation)
        || projection.run_id != run.run_id
        || projection.step_id != attempt.step_id
        || projection.attempt_id != attempt.attempt_id
        || projection.dispatch_id != binding.dispatch_id
        || projection.fencing_token != fencing_token
        || dispatch.run_id != run.run_id
        || dispatch.step_id != attempt.step_id
        || dispatch.attempt_id != attempt.attempt_id
        || dispatch.dispatch_id != binding.dispatch_id
        || dispatch.fencing_token != fencing_token
        || dispatch.capability_profile_ref.as_ref() != Some(capability)
        || private_evidence.observation.capability_profile_id != capability.contract_id
        || route_profile != Some(capability.contract_id.as_str())
        || lineage.task_id != run.task_id
        || lineage.task_revision != run.task_revision_at_creation
        || lineage.work_revision != run.work_revision
    {
        return Err(ReferenceGuardRejection::UnverifiedReference);
    }

    Ok(ReferenceAuthorization {
        evidence_refs: vec![format!(
            "policy-approval-delivery-unknown:{}:{}:{}@durable",
            record.authority_decision_ref, receipt.receipt_id, receipt.receipt_digest_sha256
        )],
    })
}

fn canonical_policy_record_digest(
    record: &egopulse_domain_contracts::v01::egopulse::policy::v1::HarnessApprovalDecisionRecord,
) -> String {
    let mut canonical = record.clone();
    canonical.canonical_payload_digest_sha256.clear();
    digest(&canonical)
}

fn canonical_receipt_digest(
    receipt: &egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecisionReceipt,
) -> String {
    let mut canonical = receipt.clone();
    canonical.receipt_digest_sha256.clear();
    digest(&canonical)
}

fn digest<M: Message>(message: &M) -> String {
    digest_bytes(&message.encode_to_vec())
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collaboration_control::{
        AdapterBackedHarnessEvidenceResolver, DELIVERY_OUTCOME_UNKNOWN_REASON_CODE,
        HarnessEvidenceResolver,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        collaboration::v1::{AttemptCommandBase, AttemptSnapshot, Lease, RunSnapshot},
        common::v1::{CommandMetadata, ContractReference},
        harness::v1::{
            ApprovalDecision, ApprovalDecisionEnvelope, ApprovalKind, ApprovalRequestLifecycleKind,
            ApprovalRequestObservation, DispatchEnvelope, DispatchReceipt, DispatchRouteBinding,
            HarnessObservation, ObservationCriticality, harness_observation,
        },
        policy::v1::{
            HarnessApprovalDecisionRecord, HarnessApprovalDecisionState,
            HarnessApprovalRequestBinding,
        },
    };
    use egopulse_harness_adapter::{AdapterEdgeConfig, AdapterEdgeKey, DurableWritePreparation};
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    const ADAPTER_ID: &str = "adapter:codex";
    const PROFILE_ID: &str = "profile:codex:approval";
    const RUN_ID: &str = "run-approval-001";
    const STEP_ID: &str = "step-approval-001";
    const ATTEMPT_ID: &str = "attempt-approval-001";
    const DISPATCH_ID: &str = "dispatch-approval-001";
    const TASK_ID: &str = "task-approval-001";
    const DECISION_REF: &str = "policy-decision-approval-001";
    const REQUEST_ID: &str = "approval-request-001";
    const FENCE: u64 = 7;

    struct Fixture {
        root: PathBuf,
        edge: Option<AdapterEdge>,
        snapshot: CollaborationSnapshot,
        command: MarkAttemptOutcomeUnknownCommand,
        record: HarnessApprovalDecisionRecord,
        state: HarnessApprovalDecisionState,
        envelope: ApprovalDecisionEnvelope,
    }

    impl Fixture {
        fn resolver(&mut self) -> AdapterBackedHarnessEvidenceResolver {
            let record = self.record.clone();
            let state = self.state.clone();
            let envelope = self.envelope.clone();
            AdapterBackedHarnessEvidenceResolver::new(
                self.edge.take().expect("fixture edge is available"),
            )
            .with_approval_policy_evidence(move |reference| {
                Ok((reference == DECISION_REF)
                    .then(|| (record.clone(), state.clone(), envelope.clone())))
            })
        }

        fn plain_resolver(&mut self) -> AdapterBackedHarnessEvidenceResolver {
            AdapterBackedHarnessEvidenceResolver::new(
                self.edge.take().expect("fixture edge is available"),
            )
        }

        fn withdraw_request(&mut self) {
            let edge = self.edge.as_mut().expect("fixture edge is available");
            edge.append_observation(
                DISPATCH_ID,
                "native-approval-request-withdrawn-002",
                b"private native approval withdrawal",
                HarnessObservation {
                    attempt_id: ATTEMPT_ID.to_owned(),
                    dispatch_id: DISPATCH_ID.to_owned(),
                    fencing_token: FENCE,
                    capability_profile_id: PROFILE_ID.to_owned(),
                    criticality: ObservationCriticality::Security as i32,
                    payload: Some(harness_observation::Payload::ApprovalRequest(
                        ApprovalRequestObservation {
                            approval_request_id: REQUEST_ID.to_owned(),
                            kind: ApprovalKind::Command as i32,
                            action_digest_sha256: "7".repeat(64),
                            requested_scope_ref: "scope:task:command-001".to_owned(),
                            display_summary_ref: "summary:command-001".to_owned(),
                            display_summary: None,
                            native_routing_ref: "native-private-route-001".to_owned(),
                            lifecycle: ApprovalRequestLifecycleKind::Withdrawn as i32,
                            request_revision: 2,
                        },
                    )),
                    ..HarnessObservation::default()
                },
                14,
            )
            .expect("append approval withdrawal");
            let projection = edge
                .pending_approval_projection_messages()
                .expect("read approval withdrawal projection")
                .into_iter()
                .find(|projection| projection.source_revision == 2)
                .expect("approval withdrawal projection");
            assert!(
                edge.acknowledge_approval_projection_message(
                    &projection.message_id,
                    &projection.payload_digest_sha256,
                )
                .expect("ack approval withdrawal projection")
            );
        }

        fn cleanup(mut self) {
            drop(self.edge.take());
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove approval evidence fixture");
            }
        }
    }

    fn approval_fixture(disposition: DeliveryDisposition) -> Fixture {
        let root =
            std::env::temp_dir().join(format!("egopulse-approval-evidence-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create approval evidence fixture");
        let mut edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("adapter-edge.db"),
            adapter_id: ADAPTER_ID.to_owned(),
            store_epoch: "approval-evidence-test-v1".to_owned(),
            key: AdapterEdgeKey::new([0x71; 32]),
        })
        .expect("open approval evidence edge");
        let profile = ContractReference {
            contract_id: PROFILE_ID.to_owned(),
            version: "1".to_owned(),
            sha256: "3".repeat(64),
        };
        let dispatch = DispatchEnvelope {
            run_id: RUN_ID.to_owned(),
            run_revision: 3,
            step_id: STEP_ID.to_owned(),
            step_revision: 4,
            attempt_id: ATTEMPT_ID.to_owned(),
            attempt_revision: 5,
            dispatch_id: DISPATCH_ID.to_owned(),
            dispatch_fingerprint: "4".repeat(64),
            fencing_token: FENCE,
            capability_profile_ref: Some(profile.clone()),
            input_bundle_sha256: "5".repeat(64),
            route_binding: Some(DispatchRouteBinding {
                capability_profile_id: PROFILE_ID.to_owned(),
                route_binding_sha256: "6".repeat(64),
                ..DispatchRouteBinding::default()
            }),
            ..DispatchEnvelope::default()
        };
        edge.prepare_dispatch(&dispatch, 10)
            .expect("prepare approval dispatch");
        edge.begin_delivery(DISPATCH_ID, 10)
            .expect("begin approval dispatch delivery");
        let mut dispatch_receipt = DispatchReceipt {
            receipt_id: "dispatch-receipt-001".to_owned(),
            disposition: DeliveryDisposition::Delivered as i32,
            dispatch_id: DISPATCH_ID.to_owned(),
            attempt_id: ATTEMPT_ID.to_owned(),
            fencing_token: FENCE,
            adapter_id: ADAPTER_ID.to_owned(),
            capability_profile_id: PROFILE_ID.to_owned(),
            receipt_digest_sha256: String::new(),
            ..DispatchReceipt::default()
        };
        dispatch_receipt.receipt_digest_sha256 = digest(&dispatch_receipt);
        edge.record_dispatch_receipt(&dispatch_receipt, b"native dispatch delivery", 10)
            .expect("record approval dispatch delivery");
        edge.bind_dispatch_task_lineage(DISPATCH_ID, TASK_ID, 8, 9, 10)
            .expect("bind approval dispatch lineage");
        edge.append_observation(
            DISPATCH_ID,
            "native-approval-request-001",
            b"private native approval request",
            HarnessObservation {
                attempt_id: ATTEMPT_ID.to_owned(),
                dispatch_id: DISPATCH_ID.to_owned(),
                fencing_token: FENCE,
                capability_profile_id: PROFILE_ID.to_owned(),
                criticality: ObservationCriticality::Security as i32,
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: REQUEST_ID.to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "7".repeat(64),
                        requested_scope_ref: "scope:task:command-001".to_owned(),
                        display_summary_ref: "summary:command-001".to_owned(),
                        display_summary: None,
                        native_routing_ref: "native-private-route-001".to_owned(),
                        lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                        request_revision: 1,
                    },
                )),
                ..HarnessObservation::default()
            },
            11,
        )
        .expect("append approval request");
        let projection = edge
            .pending_approval_projection_messages()
            .expect("read approval projection")
            .remove(0);
        assert!(
            edge.acknowledge_approval_projection_message(
                &projection.message_id,
                &projection.payload_digest_sha256,
            )
            .expect("ack approval projection")
        );
        let request = HarnessApprovalRequestBinding {
            adapter_id: ADAPTER_ID.to_owned(),
            attempt_id: ATTEMPT_ID.to_owned(),
            dispatch_id: DISPATCH_ID.to_owned(),
            fencing_token: FENCE,
            approval_request_id: REQUEST_ID.to_owned(),
            kind: ApprovalKind::Command as i32,
            action_digest_sha256: "7".repeat(64),
            requested_scope_ref: "scope:task:command-001".to_owned(),
            native_routing_ref: "native-private-route-001".to_owned(),
            request_observation_id: projection.source_observation_id,
            request_observation_sequence: projection.source_revision,
            request_lifecycle: ApprovalRequestLifecycleKind::Open as i32,
            request_revision: 1,
        };
        let mut record = HarnessApprovalDecisionRecord {
            authority_decision_ref: DECISION_REF.to_owned(),
            version: 1,
            request: Some(request),
            decision: ApprovalDecision::AllowOnce as i32,
            reason_code: "FOUNDER_APPROVED_SCOPED_COMMAND".to_owned(),
            canonical_payload_digest_sha256: String::new(),
            ..HarnessApprovalDecisionRecord::default()
        };
        record.canonical_payload_digest_sha256 = canonical_policy_record_digest(&record);
        let state = HarnessApprovalDecisionState {
            authority_decision_ref: DECISION_REF.to_owned(),
            revision: 1,
            state: HarnessApprovalDecisionStateKind::Issued as i32,
            ..HarnessApprovalDecisionState::default()
        };
        let envelope = ApprovalDecisionEnvelope {
            meta: Some(CommandMetadata {
                command_id: "policy-delivery-approval-001".to_owned(),
                idempotency_key: DECISION_REF.to_owned(),
                idempotency_scope: "policy-decision-to-harness-adapter".to_owned(),
                request_digest_sha256: record.canonical_payload_digest_sha256.clone(),
                ..CommandMetadata::default()
            }),
            attempt_id: ATTEMPT_ID.to_owned(),
            dispatch_id: DISPATCH_ID.to_owned(),
            fencing_token: FENCE,
            approval_request_id: REQUEST_ID.to_owned(),
            action_digest_sha256: "7".repeat(64),
            decision: ApprovalDecision::AllowOnce as i32,
            authority_decision_ref: DECISION_REF.to_owned(),
            native_routing_ref: "native-private-route-001".to_owned(),
        };
        assert_eq!(
            edge.prepare_approval(REQUEST_ID, DISPATCH_ID, &digest(&envelope), 12)
                .expect("prepare approval decision"),
            DurableWritePreparation::Ready
        );
        edge.begin_approval(REQUEST_ID, 12)
            .expect("begin approval decision");
        let mut receipt =
            egopulse_domain_contracts::v01::egopulse::harness::v1::ApprovalDecisionReceipt {
                receipt_id: "approval-receipt-001".to_owned(),
                approval_request_id: REQUEST_ID.to_owned(),
                decision: ApprovalDecision::AllowOnce as i32,
                disposition: disposition as i32,
                receipt_digest_sha256: String::new(),
                delivered_at: None,
            };
        receipt.receipt_digest_sha256 = canonical_receipt_digest(&receipt);
        edge.record_approval_receipt(
            REQUEST_ID,
            match disposition {
                DeliveryDisposition::Delivered => "delivered",
                DeliveryDisposition::Rejected => "rejected",
                _ => "delivery_unknown",
            },
            &receipt.encode_to_vec(),
            b"opaque native approval delivery evidence",
            13,
        )
        .expect("record approval decision receipt");
        let snapshot = CollaborationSnapshot {
            run: Some(RunSnapshot {
                run_id: RUN_ID.to_owned(),
                task_id: TASK_ID.to_owned(),
                task_revision_at_creation: 8,
                work_revision: 9,
                ..RunSnapshot::default()
            }),
            attempts: vec![AttemptSnapshot {
                attempt_id: ATTEMPT_ID.to_owned(),
                run_id: RUN_ID.to_owned(),
                step_id: STEP_ID.to_owned(),
                capability_profile_ref: Some(profile),
                dispatch_id: Some(DISPATCH_ID.to_owned()),
                lease: Some(Lease {
                    fencing_token: FENCE,
                    ..Lease::default()
                }),
                ..AttemptSnapshot::default()
            }],
            ..CollaborationSnapshot::default()
        };
        let command = MarkAttemptOutcomeUnknownCommand {
            base: Some(AttemptCommandBase {
                run_id: RUN_ID.to_owned(),
                step_id: STEP_ID.to_owned(),
                attempt_id: ATTEMPT_ID.to_owned(),
                ..AttemptCommandBase::default()
            }),
            reason_code: DELIVERY_OUTCOME_UNKNOWN_REASON_CODE.to_owned(),
            uncertainty_evidence_id: DECISION_REF.to_owned(),
        };
        Fixture {
            root,
            edge: Some(edge),
            snapshot,
            command,
            record,
            state,
            envelope,
        }
    }

    #[test]
    fn approval_unknown_requires_durable_policy_and_adapter_evidence() {
        let mut fixture = approval_fixture(DeliveryDisposition::Unknown);
        let command = fixture.command.clone();
        let snapshot = fixture.snapshot.clone();
        let resolver = fixture.resolver();
        let authorization = resolver
            .validate_delivery_unknown(&command, &snapshot)
            .expect("validate approval delivery uncertainty");
        assert_eq!(authorization.evidence_refs.len(), 1);
        assert!(
            authorization.evidence_refs[0]
                .starts_with("policy-approval-delivery-unknown:policy-decision-approval-001:")
        );
        drop(resolver);
        fixture.cleanup();

        let mut fixture = approval_fixture(DeliveryDisposition::Unknown);
        let command = fixture.command.clone();
        let snapshot = fixture.snapshot.clone();
        let resolver = fixture.plain_resolver();
        assert_eq!(
            resolver.validate_delivery_unknown(&command, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
        drop(resolver);
        fixture.cleanup();
    }

    #[test]
    fn approval_unknown_rejects_stale_reference_wrong_fence_and_non_unknown_receipt() {
        let mut fixture = approval_fixture(DeliveryDisposition::Unknown);
        let mut stale = fixture.command.clone();
        stale.uncertainty_evidence_id = "policy-decision-stale".to_owned();
        let snapshot = fixture.snapshot.clone();
        let resolver = fixture.resolver();
        assert_eq!(
            resolver.validate_delivery_unknown(&stale, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
        drop(resolver);
        fixture.cleanup();

        let mut fixture = approval_fixture(DeliveryDisposition::Unknown);
        let command = fixture.command.clone();
        let mut wrong_fence = fixture.snapshot.clone();
        wrong_fence.attempts[0]
            .lease
            .as_mut()
            .expect("fixture lease")
            .fencing_token += 1;
        let resolver = fixture.resolver();
        assert_eq!(
            resolver.validate_delivery_unknown(&command, &wrong_fence),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
        drop(resolver);
        fixture.cleanup();

        let mut fixture = approval_fixture(DeliveryDisposition::Unknown);
        fixture.withdraw_request();
        let command = fixture.command.clone();
        let snapshot = fixture.snapshot.clone();
        let resolver = fixture.resolver();
        assert_eq!(
            resolver.validate_delivery_unknown(&command, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
        drop(resolver);
        fixture.cleanup();

        let mut fixture = approval_fixture(DeliveryDisposition::Delivered);
        let command = fixture.command.clone();
        let snapshot = fixture.snapshot.clone();
        let resolver = fixture.resolver();
        assert_eq!(
            resolver.validate_delivery_unknown(&command, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
        drop(resolver);
        fixture.cleanup();
    }
}
