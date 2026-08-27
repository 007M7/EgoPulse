use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, ApprovalDecisionEnvelope, CancelExecutionEnvelope, DispatchEnvelope,
    HarnessAckObservation, HarnessReadiness, LifecycleKind, LifecycleObservation,
    ObservationCriticality, ProbeHarnessRequest, ProbeHarnessResult, SideEffectCertainty,
    harness_observation,
};
use egopulse_harness_adapter::{
    DriverDelivery, DriverError, DriverEvent, NativeHarnessDriver, NativeHarnessFuture,
    ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial,
    TerminalOutputCandidate,
};
use prost_types::Timestamp;
use std::collections::VecDeque;
use uuid::Uuid;

use crate::protocol::codex_protocol_fingerprint;

#[derive(Default)]
pub struct FakeCodexDriver {
    events: VecDeque<DriverEvent>,
    dispatch_count: u64,
    cancel_count: u64,
    reconcile_count: u64,
    defer_terminal_once: bool,
    terminal_deferred: bool,
    terminal_output_candidate: Option<TerminalOutputCandidate>,
    reconciliation_finding: Option<ReconciliationFinding>,
}

impl FakeCodexDriver {
    #[must_use]
    pub const fn dispatch_count(&self) -> u64 {
        self.dispatch_count
    }

    #[must_use]
    pub const fn cancel_count(&self) -> u64 {
        self.cancel_count
    }

    #[must_use]
    pub const fn reconcile_count(&self) -> u64 {
        self.reconcile_count
    }

    #[must_use]
    pub fn with_reconciliation_finding(mut self, finding: ReconciliationFinding) -> Self {
        self.reconciliation_finding = Some(finding);
        self
    }

    #[must_use]
    pub fn with_deferred_terminal(mut self) -> Self {
        self.defer_terminal_once = true;
        self
    }
}

impl NativeHarnessDriver for FakeCodexDriver {
    fn probe<'a>(
        &'a mut self,
        _request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        Box::pin(async move {
            Ok(ProbeHarnessResult {
                probe_id: Uuid::now_v7().to_string(),
                readiness: HarnessReadiness::Ready as i32,
                observed_protocol: Some(codex_protocol_fingerprint()),
                safe_diagnostic_codes: vec!["FAKE_CODEX_READY".to_owned()],
                evidence_refs: vec!["fixture://codex/fake/probe".to_owned()],
                observed_at: Some(timestamp(1_787_488_000)),
            })
        })
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        _material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        Box::pin(async move {
            self.dispatch_count += 1;
            let thread_id = format!("fake-thread-{}", envelope.dispatch_id);
            let turn_id = format!("fake-turn-{}", envelope.dispatch_id);
            self.events.push_back(event(
                "fake-ack",
                ObservationCriticality::Control,
                harness_observation::Payload::Ack(HarnessAckObservation {
                    disposition: AckDisposition::Accepted as i32,
                    ack_receipt_id: format!("fake-ack-{}", envelope.dispatch_id),
                    native_session_ref: Some(thread_id.clone()),
                    native_execution_ref: Some(turn_id.clone()),
                }),
            ));
            self.events.push_back(event(
                "fake-running",
                ObservationCriticality::Control,
                harness_observation::Payload::Lifecycle(LifecycleObservation {
                    kind: LifecycleKind::ExecutionStarted as i32,
                    native_item_ref: None,
                    safe_status_code: Some("inProgress".to_owned()),
                    side_effect_certainty: SideEffectCertainty::Unknown as i32,
                    native_will_retry: None,
                }),
            ));
            self.events.push_back(event(
                "fake-completed",
                ObservationCriticality::Terminal,
                harness_observation::Payload::Lifecycle(LifecycleObservation {
                    kind: LifecycleKind::ExecutionCompleted as i32,
                    native_item_ref: None,
                    safe_status_code: Some("completed".to_owned()),
                    side_effect_certainty: SideEffectCertainty::Unknown as i32,
                    native_will_retry: None,
                }),
            ));
            self.terminal_output_candidate = Some(TerminalOutputCandidate {
                dispatch_id: envelope.dispatch_id.clone(),
                native_completion_ref: turn_id.clone(),
                media_type: "text/plain; charset=utf-8".to_owned(),
                content: b"fake governed terminal output".to_vec(),
            });
            Ok(DriverDelivery {
                native_request_ref: format!("fake-request-{}", envelope.dispatch_id),
                native_session_ref: thread_id,
                native_execution_ref: Some(turn_id),
                raw_evidence: b"fake-dispatch-delivered".to_vec(),
            })
        })
    }

    fn next_event<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        Box::pin(async move {
            if self.defer_terminal_once && !self.terminal_deferred && self.events.len() == 1 {
                self.terminal_deferred = true;
                return Ok(None);
            }
            Ok(self.events.pop_front())
        })
    }

    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        Box::pin(async move {
            Ok(self
                .terminal_output_candidate
                .take()
                .filter(|candidate| candidate.dispatch_id == envelope.dispatch_id))
        })
    }

    fn decide_approval<'a>(
        &'a mut self,
        _envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move { Ok(b"fake-approval-delivered".to_vec()) })
    }

    fn cancel<'a>(
        &'a mut self,
        _envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        Box::pin(async move {
            self.cancel_count += 1;
            self.events.push_back(event(
                "fake-interrupted",
                ObservationCriticality::Terminal,
                harness_observation::Payload::Lifecycle(LifecycleObservation {
                    kind: LifecycleKind::ExecutionInterrupted as i32,
                    native_item_ref: None,
                    safe_status_code: Some("interrupted".to_owned()),
                    side_effect_certainty: SideEffectCertainty::Unknown as i32,
                    native_will_retry: None,
                }),
            ));
            Ok(b"fake-cancel-delivered".to_vec())
        })
    }

    fn reconcile<'a>(
        &'a mut self,
        _context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        Box::pin(async move {
            self.reconcile_count += 1;
            Ok(self.reconciliation_finding.clone().unwrap_or_else(|| {
                ReconciliationFinding::TerminalObservationRecovered {
                    evidence_ref: "fixture://codex/fake/reconciled".to_owned(),
                }
            }))
        })
    }
}

fn event(
    key: &str,
    criticality: ObservationCriticality,
    payload: harness_observation::Payload,
) -> DriverEvent {
    DriverEvent {
        native_key: key.to_owned(),
        native_event_id: Some(key.to_owned()),
        native_sequence: None,
        native_observed_at: timestamp(1_787_488_001),
        criticality,
        payload,
        raw_event: key.as_bytes().to_vec(),
    }
}

fn timestamp(seconds: i64) -> Timestamp {
    Timestamp { seconds, nanos: 0 }
}
