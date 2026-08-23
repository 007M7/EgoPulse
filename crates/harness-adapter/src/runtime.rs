use crate::{AdapterEdge, AdapterEdgeError, DispatchPreparation, DurableWritePreparation};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, ApprovalDecisionReceipt, ApprovalDecisionResult,
    CancelExecutionEnvelope, CancelExecutionReceipt, CancelExecutionResult,
    CancellationDeliveryDisposition, DeliveryDisposition, DispatchEnvelope, DispatchReceipt,
    DispatchResult, HarnessError, HarnessErrorCode, HarnessObservation, NativeProtocolFingerprint,
    ObservationCriticality, ProbeHarnessRequest, ProbeHarnessResult, ResumeExecutionEnvelope,
    ResumeExecutionResult, approval_decision_result, cancel_execution_result, dispatch_result,
    harness_observation, resume_execution_result,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

pub trait AdapterClock {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAdapterClock;

impl AdapterClock for SystemAdapterClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDispatchMaterial {
    pub canonical_input_bundle: Vec<u8>,
    pub prompt: String,
    pub workspace_root: PathBuf,
    pub model: Option<String>,
}

pub trait DispatchMaterialResolver {
    fn resolve(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverErrorCertainty {
    ProvenNotSent,
    DeliveryUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverError {
    pub certainty: DriverErrorCertainty,
    pub code: HarnessErrorCode,
    pub safe_detail_code: String,
    pub error_fingerprint: Option<String>,
    pub raw_evidence: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverDelivery {
    pub native_request_ref: String,
    pub native_session_ref: String,
    pub native_execution_ref: Option<String>,
    pub raw_evidence: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DriverEvent {
    pub native_key: String,
    pub native_event_id: Option<String>,
    pub native_sequence: Option<u64>,
    pub native_observed_at: Timestamp,
    pub criticality: ObservationCriticality,
    pub payload: harness_observation::Payload,
    pub raw_event: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationFinding {
    NoEffectProven { evidence_ref: String },
    NativeExecutionActive { evidence_ref: String },
    TerminalObservationRecovered { evidence_ref: String },
    OutcomeUnknown { evidence_ref: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationContext {
    pub envelope: DispatchEnvelope,
    pub delivery_receipt: Option<DispatchReceipt>,
    pub material: ResolvedDispatchMaterial,
}

pub trait NativeHarnessDriver {
    async fn probe(
        &mut self,
        request: &ProbeHarnessRequest,
    ) -> Result<ProbeHarnessResult, DriverError>;

    async fn send_dispatch(
        &mut self,
        envelope: &DispatchEnvelope,
        material: &ResolvedDispatchMaterial,
    ) -> Result<DriverDelivery, DriverError>;

    async fn next_event(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<DriverEvent>, DriverError>;

    async fn decide_approval(
        &mut self,
        envelope: &ApprovalDecisionEnvelope,
    ) -> Result<Vec<u8>, DriverError>;

    async fn cancel(&mut self, envelope: &CancelExecutionEnvelope) -> Result<Vec<u8>, DriverError>;

    async fn reconcile(
        &mut self,
        context: &ReconciliationContext,
    ) -> Result<ReconciliationFinding, DriverError>;
}

#[derive(Debug, Error)]
pub enum GovernedAdapterError {
    #[error("persisted adapter data could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("adapter durable edge failed")]
    Edge(#[from] AdapterEdgeError),
}

pub struct GovernedHarnessAdapter<R, D, C> {
    adapter_id: String,
    capability_profile_id: String,
    observed_protocol: NativeProtocolFingerprint,
    edge: AdapterEdge,
    resolver: R,
    driver: D,
    clock: C,
}

impl<R, D, C> GovernedHarnessAdapter<R, D, C>
where
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    C: AdapterClock,
{
    #[must_use]
    pub fn new(
        adapter_id: impl Into<String>,
        capability_profile_id: impl Into<String>,
        observed_protocol: NativeProtocolFingerprint,
        edge: AdapterEdge,
        resolver: R,
        driver: D,
        clock: C,
    ) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            capability_profile_id: capability_profile_id.into(),
            observed_protocol,
            edge,
            resolver,
            driver,
            clock,
        }
    }

    pub async fn probe(&mut self, request: &ProbeHarnessRequest) -> ProbeHarnessResult {
        match self.driver.probe(request).await {
            Ok(result) => result,
            Err(error) => ProbeHarnessResult {
                probe_id: Uuid::now_v7().to_string(),
                readiness: readiness_for_error(&error) as i32,
                observed_protocol: Some(self.observed_protocol.clone()),
                safe_diagnostic_codes: vec![error.safe_detail_code],
                evidence_refs: error
                    .error_fingerprint
                    .into_iter()
                    .map(|value| format!("error-fingerprint:{value}"))
                    .collect(),
                observed_at: Some(self.clock.now()),
            },
        }
    }

    pub async fn dispatch(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchResult, GovernedAdapterError> {
        if let Some(error) = self.validate_dispatch(envelope) {
            return Ok(dispatch_error(error));
        }
        let now = self.clock.now();
        match self.edge.prepare_dispatch(envelope, now.seconds)? {
            DispatchPreparation::Replay(receipt) => return Ok(dispatch_receipt(*receipt)),
            DispatchPreparation::DeliveryUnknown => {
                let receipt =
                    self.delivery_unknown_receipt(envelope, "RECOVERED_UNCERTAIN_DELIVERY", &now);
                self.edge.record_dispatch_receipt(
                    &receipt,
                    b"RECOVERED_UNCERTAIN_DELIVERY",
                    now.seconds,
                )?;
                return Ok(dispatch_receipt(receipt));
            }
            DispatchPreparation::Ready => {}
        }
        let material = match self.resolver.resolve(envelope) {
            Ok(value) => value,
            Err(error) => return Ok(dispatch_error(error)),
        };
        if sha256(&material.canonical_input_bundle) != envelope.input_bundle_sha256 {
            return Ok(dispatch_error(harness_error(
                HarnessErrorCode::IntegrityFailure,
                "INPUT_BUNDLE_DIGEST_MISMATCH",
                false,
                false,
                None,
            )));
        }

        self.edge
            .begin_delivery(&envelope.dispatch_id, now.seconds)?;
        let (receipt, raw_evidence) = match self.driver.send_dispatch(envelope, &material).await {
            Ok(delivery) => {
                let evidence = delivery.raw_evidence.clone();
                (
                    self.delivery_receipt(envelope, delivery, DeliveryDisposition::Delivered, &now),
                    evidence,
                )
            }
            Err(error) => {
                let disposition = match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => DeliveryDisposition::Rejected,
                    DriverErrorCertainty::DeliveryUnknown => DeliveryDisposition::Unknown,
                };
                let evidence = error.raw_evidence.clone();
                (
                    self.failed_delivery_receipt(envelope, disposition, &error, &now),
                    evidence,
                )
            }
        };
        let raw_evidence = if raw_evidence.is_empty() {
            receipt.evidence_ref.as_bytes()
        } else {
            raw_evidence.as_slice()
        };
        self.edge
            .record_dispatch_receipt(&receipt, raw_evidence, now.seconds)?;
        Ok(dispatch_receipt(receipt))
    }

    pub async fn pump_one(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<HarnessObservation>, GovernedAdapterError> {
        let event = match self.driver.next_event(envelope).await {
            Ok(value) => value,
            Err(error) => Some(driver_error_event(error, self.clock.now())),
        };
        let Some(event) = event else {
            return Ok(None);
        };
        let received_at = self.clock.now();
        let observation = HarnessObservation {
            observation_id: String::new(),
            adapter_id: self.adapter_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            observation_sequence: 0,
            native_event_id: event.native_event_id,
            native_sequence: event.native_sequence,
            native_event_digest_sha256: String::new(),
            capability_profile_id: self.capability_profile_id.clone(),
            criticality: event.criticality as i32,
            raw_evidence_ref: String::new(),
            native_observed_at: Some(event.native_observed_at),
            adapter_received_at: Some(received_at),
            payload: Some(event.payload),
        };
        let appended = self.edge.append_observation(
            &envelope.dispatch_id,
            &event.native_key,
            &event.raw_event,
            observation,
            received_at.seconds,
        )?;
        Ok(Some(match appended {
            crate::ObservationAppend::Committed(value)
            | crate::ObservationAppend::Replay(value) => value,
        }))
    }

    pub async fn decide_approval(
        &mut self,
        envelope: &ApprovalDecisionEnvelope,
    ) -> Result<ApprovalDecisionResult, GovernedAdapterError> {
        let now = self.clock.now();
        if envelope.approval_request_id.trim().is_empty()
            || envelope.dispatch_id.trim().is_empty()
            || envelope.fencing_token == 0
            || !sha256_is_valid(&envelope.action_digest_sha256)
            || envelope.authority_decision_ref.trim().is_empty()
            || envelope.native_routing_ref.trim().is_empty()
        {
            return Ok(ApprovalDecisionResult {
                outcome: Some(approval_decision_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "APPROVAL_DECISION_ENVELOPE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let request_digest = canonical_digest(envelope);
        match self.edge.prepare_approval(
            &envelope.approval_request_id,
            &envelope.dispatch_id,
            &request_digest,
            now.seconds,
        )? {
            DurableWritePreparation::Replay(bytes) => {
                return Ok(approval_receipt(ApprovalDecisionReceipt::decode(
                    bytes.as_slice(),
                )?));
            }
            DurableWritePreparation::DeliveryUnknown => {
                let receipt =
                    approval_delivery_receipt(envelope, DeliveryDisposition::Unknown, &now);
                self.edge.record_approval_receipt(
                    &envelope.approval_request_id,
                    "delivery_unknown",
                    &receipt.encode_to_vec(),
                    b"RECOVERED_UNCERTAIN_APPROVAL_DELIVERY",
                    now.seconds,
                )?;
                return Ok(approval_receipt(receipt));
            }
            DurableWritePreparation::Ready => {}
        }
        self.edge
            .begin_approval(&envelope.approval_request_id, now.seconds)?;
        let (disposition, raw) = match self.driver.decide_approval(envelope).await {
            Ok(raw) => (DeliveryDisposition::Delivered, raw),
            Err(error) => (
                match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => DeliveryDisposition::Rejected,
                    DriverErrorCertainty::DeliveryUnknown => DeliveryDisposition::Unknown,
                },
                error.raw_evidence,
            ),
        };
        let receipt = approval_delivery_receipt(envelope, disposition, &now);
        let state = match disposition {
            DeliveryDisposition::Delivered => "delivered",
            DeliveryDisposition::Rejected => "rejected",
            _ => "delivery_unknown",
        };
        self.edge.record_approval_receipt(
            &envelope.approval_request_id,
            state,
            &receipt.encode_to_vec(),
            &raw,
            now.seconds,
        )?;
        Ok(approval_receipt(receipt))
    }

    pub async fn cancel(
        &mut self,
        envelope: &CancelExecutionEnvelope,
    ) -> Result<CancelExecutionResult, GovernedAdapterError> {
        let now = self.clock.now();
        if envelope.cancellation_request_id.trim().is_empty()
            || envelope.dispatch_id.trim().is_empty()
            || envelope.attempt_id.trim().is_empty()
            || envelope.fencing_token == 0
            || envelope.native_session_ref.trim().is_empty()
            || envelope.native_execution_ref.trim().is_empty()
            || envelope.confirmation_deadline.is_none()
        {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "CANCELLATION_ENVELOPE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let request_digest = canonical_digest(envelope);
        match self.edge.prepare_cancellation(
            &envelope.cancellation_request_id,
            &envelope.dispatch_id,
            &request_digest,
            now.seconds,
        )? {
            DurableWritePreparation::Replay(replay) => {
                return Ok(cancel_receipt(CancelExecutionReceipt::decode(
                    replay.as_slice(),
                )?));
            }
            DurableWritePreparation::DeliveryUnknown => {
                let receipt = cancellation_delivery_receipt(
                    envelope,
                    CancellationDeliveryDisposition::Unknown,
                    "adapter-edge://cancel/recovered-uncertain-delivery".to_owned(),
                    &now,
                );
                self.edge.record_cancellation_receipt(
                    &envelope.cancellation_request_id,
                    "delivery_unknown",
                    &receipt.encode_to_vec(),
                    b"RECOVERED_UNCERTAIN_CANCELLATION_DELIVERY",
                    now.seconds,
                )?;
                return Ok(cancel_receipt(receipt));
            }
            DurableWritePreparation::Ready => {}
        }
        self.edge
            .begin_cancellation(&envelope.cancellation_request_id, now.seconds)?;
        let (disposition, raw, evidence_ref) = match self.driver.cancel(envelope).await {
            Ok(raw) => (
                CancellationDeliveryDisposition::Delivered,
                raw,
                format!(
                    "adapter-edge://{}/cancel/{}",
                    self.adapter_id, envelope.cancellation_request_id
                ),
            ),
            Err(error) => {
                let disposition = match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => {
                        CancellationDeliveryDisposition::Rejected
                    }
                    DriverErrorCertainty::DeliveryUnknown => {
                        CancellationDeliveryDisposition::Unknown
                    }
                };
                let evidence_ref = error
                    .error_fingerprint
                    .as_ref()
                    .map(|value| format!("error-fingerprint:{value}"))
                    .unwrap_or_else(|| "adapter-edge://cancel/unknown".to_owned());
                (disposition, error.raw_evidence, evidence_ref)
            }
        };
        let receipt = cancellation_delivery_receipt(envelope, disposition, evidence_ref, &now);
        let state = match disposition {
            CancellationDeliveryDisposition::Delivered => "delivered",
            CancellationDeliveryDisposition::Rejected => "rejected",
            CancellationDeliveryDisposition::Unsupported => "unsupported",
            _ => "delivery_unknown",
        };
        self.edge.record_cancellation_receipt(
            &envelope.cancellation_request_id,
            state,
            &receipt.encode_to_vec(),
            &raw,
            now.seconds,
        )?;
        Ok(cancel_receipt(receipt))
    }

    pub async fn cancel_dispatch(
        &mut self,
        cancellation_request_id: &str,
        dispatch_id: &str,
        confirmation_deadline: Timestamp,
    ) -> Result<CancelExecutionResult, GovernedAdapterError> {
        if cancellation_request_id.trim().is_empty() || dispatch_id.trim().is_empty() {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "CANCELLATION_REFERENCE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let Some(binding) = self.edge.resolve_native_execution_binding(dispatch_id)? else {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::NotFound,
                    "NATIVE_EXECUTION_BINDING_NOT_FOUND",
                    false,
                    false,
                    None,
                ))),
            });
        };
        self.cancel(&CancelExecutionEnvelope {
            attempt_id: binding.attempt_id,
            dispatch_id: binding.dispatch_id,
            fencing_token: binding.fencing_token,
            cancellation_request_id: cancellation_request_id.to_owned(),
            native_session_ref: binding.native_session_ref,
            native_execution_ref: binding.native_execution_ref,
            confirmation_deadline: Some(confirmation_deadline),
            ..CancelExecutionEnvelope::default()
        })
        .await
    }

    pub async fn reconcile(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<ReconciliationFinding, DriverError> {
        let material = self
            .resolver
            .resolve(envelope)
            .map_err(resolver_driver_error)?;
        let delivery_receipt =
            self.edge
                .dispatch_receipt(&envelope.dispatch_id)
                .map_err(|error| {
                    driver_error_from_edge("ADAPTER_EDGE_RECONCILE_READ_FAILED", &error)
                })?;
        self.driver
            .reconcile(&ReconciliationContext {
                envelope: envelope.clone(),
                delivery_receipt,
                material,
            })
            .await
    }

    pub fn observations_after(
        &self,
        sequence: u64,
    ) -> Result<Vec<HarnessObservation>, GovernedAdapterError> {
        self.edge.observations_after(sequence).map_err(Into::into)
    }

    pub fn pending_observations(&self) -> Result<Vec<HarnessObservation>, GovernedAdapterError> {
        self.edge.pending_observations().map_err(Into::into)
    }

    pub fn mark_observation_consumed(
        &mut self,
        observation_id: &str,
    ) -> Result<(), GovernedAdapterError> {
        self.edge
            .mark_observation_consumed(observation_id)
            .map_err(Into::into)
    }

    pub fn quarantine_observation(
        &mut self,
        observation_id: &str,
        reason_code: &str,
    ) -> Result<(), GovernedAdapterError> {
        self.edge
            .quarantine_observation(observation_id, reason_code, self.clock.now().seconds)
            .map_err(Into::into)
    }

    #[must_use]
    pub fn edge(&self) -> &AdapterEdge {
        &self.edge
    }

    #[must_use]
    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    fn validate_dispatch(&self, envelope: &DispatchEnvelope) -> Option<HarnessError> {
        let profile = envelope.capability_profile_ref.as_ref();
        if envelope.dispatch_id.trim().is_empty()
            || envelope.attempt_id.trim().is_empty()
            || envelope.fencing_token == 0
            || !sha256_is_valid(&envelope.dispatch_fingerprint)
            || !sha256_is_valid(&envelope.input_bundle_sha256)
            || profile.is_none_or(|value| {
                value.contract_id != self.capability_profile_id || !sha256_is_valid(&value.sha256)
            })
        {
            return Some(harness_error(
                HarnessErrorCode::InvalidArgument,
                "DISPATCH_ENVELOPE_INVALID",
                false,
                false,
                None,
            ));
        }
        None
    }

    fn delivery_receipt(
        &self,
        envelope: &DispatchEnvelope,
        delivery: DriverDelivery,
        disposition: DeliveryDisposition,
        now: &Timestamp,
    ) -> DispatchReceipt {
        let receipt_id = Uuid::now_v7().to_string();
        let mut receipt = DispatchReceipt {
            receipt_id: receipt_id.clone(),
            disposition: disposition as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: self.adapter_id.clone(),
            capability_profile_id: self.capability_profile_id.clone(),
            observed_protocol: Some(self.observed_protocol.clone()),
            native_request_ref: Some(delivery.native_request_ref),
            native_session_ref: Some(delivery.native_session_ref),
            native_execution_ref: delivery.native_execution_ref,
            receipt_digest_sha256: String::new(),
            evidence_ref: format!("adapter-edge://{}/delivery/{receipt_id}", self.adapter_id),
            delivered_at: Some(*now),
        };
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        receipt
    }

    fn failed_delivery_receipt(
        &self,
        envelope: &DispatchEnvelope,
        disposition: DeliveryDisposition,
        error: &DriverError,
        now: &Timestamp,
    ) -> DispatchReceipt {
        let receipt_id = Uuid::now_v7().to_string();
        let mut receipt = DispatchReceipt {
            receipt_id: receipt_id.clone(),
            disposition: disposition as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: self.adapter_id.clone(),
            capability_profile_id: self.capability_profile_id.clone(),
            observed_protocol: Some(self.observed_protocol.clone()),
            native_request_ref: None,
            native_session_ref: None,
            native_execution_ref: None,
            receipt_digest_sha256: String::new(),
            evidence_ref: error
                .error_fingerprint
                .as_ref()
                .map(|value| format!("error-fingerprint:{value}"))
                .unwrap_or_else(|| {
                    format!("adapter-edge://{}/delivery/{receipt_id}", self.adapter_id)
                }),
            delivered_at: Some(*now),
        };
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        receipt
    }

    fn delivery_unknown_receipt(
        &self,
        envelope: &DispatchEnvelope,
        reason: &str,
        now: &Timestamp,
    ) -> DispatchReceipt {
        self.failed_delivery_receipt(
            envelope,
            DeliveryDisposition::Unknown,
            &DriverError {
                certainty: DriverErrorCertainty::DeliveryUnknown,
                code: HarnessErrorCode::DeliveryUnknown,
                safe_detail_code: reason.to_owned(),
                error_fingerprint: None,
                raw_evidence: Vec::new(),
            },
            now,
        )
    }
}

fn dispatch_receipt(receipt: DispatchReceipt) -> DispatchResult {
    DispatchResult {
        outcome: Some(dispatch_result::Outcome::Receipt(receipt)),
    }
}

fn dispatch_error(error: HarnessError) -> DispatchResult {
    DispatchResult {
        outcome: Some(dispatch_result::Outcome::Error(error)),
    }
}

fn approval_receipt(receipt: ApprovalDecisionReceipt) -> ApprovalDecisionResult {
    ApprovalDecisionResult {
        outcome: Some(approval_decision_result::Outcome::Receipt(receipt)),
    }
}

fn approval_delivery_receipt(
    envelope: &ApprovalDecisionEnvelope,
    disposition: DeliveryDisposition,
    now: &Timestamp,
) -> ApprovalDecisionReceipt {
    let mut receipt = ApprovalDecisionReceipt {
        receipt_id: Uuid::now_v7().to_string(),
        approval_request_id: envelope.approval_request_id.clone(),
        decision: envelope.decision,
        disposition: disposition as i32,
        receipt_digest_sha256: String::new(),
        delivered_at: Some(*now),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    receipt
}

fn cancel_receipt(receipt: CancelExecutionReceipt) -> CancelExecutionResult {
    CancelExecutionResult {
        outcome: Some(cancel_execution_result::Outcome::Receipt(receipt)),
    }
}

fn cancellation_delivery_receipt(
    envelope: &CancelExecutionEnvelope,
    disposition: CancellationDeliveryDisposition,
    evidence_ref: String,
    now: &Timestamp,
) -> CancelExecutionReceipt {
    let mut receipt = CancelExecutionReceipt {
        receipt_id: Uuid::now_v7().to_string(),
        cancellation_request_id: envelope.cancellation_request_id.clone(),
        disposition: disposition as i32,
        receipt_digest_sha256: String::new(),
        evidence_ref,
        delivered_at: Some(*now),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    receipt
}

fn driver_error_event(error: DriverError, now: Timestamp) -> DriverEvent {
    let fingerprint = error.error_fingerprint.clone();
    let criticality = if error.code == HarnessErrorCode::UnknownCriticalEvent {
        ObservationCriticality::Terminal
    } else if matches!(
        error.code,
        HarnessErrorCode::Unauthenticated | HarnessErrorCode::PermissionDenied
    ) {
        ObservationCriticality::Security
    } else {
        ObservationCriticality::Control
    };
    DriverEvent {
        native_key: format!(
            "driver-error:{}:{}",
            error.safe_detail_code,
            sha256(&error.raw_evidence)
        ),
        native_event_id: None,
        native_sequence: None,
        native_observed_at: now,
        criticality,
        payload: harness_observation::Payload::Diagnostic(
            egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                safe_diagnostic_code: error.safe_detail_code,
                error_fingerprint: fingerprint,
                recovery_required: error.certainty == DriverErrorCertainty::DeliveryUnknown,
            },
        ),
        raw_event: error.raw_evidence,
    }
}

fn resolver_driver_error(error: HarnessError) -> DriverError {
    DriverError {
        certainty: DriverErrorCertainty::ProvenNotSent,
        code: HarnessErrorCode::try_from(error.code).unwrap_or(HarnessErrorCode::Internal),
        safe_detail_code: error.safe_detail_code,
        error_fingerprint: error.error_fingerprint,
        raw_evidence: Vec::new(),
    }
}

fn driver_error_from_edge(detail: &str, error: &AdapterEdgeError) -> DriverError {
    DriverError {
        certainty: DriverErrorCertainty::DeliveryUnknown,
        code: HarnessErrorCode::DependencyUnavailable,
        safe_detail_code: detail.to_owned(),
        error_fingerprint: Some(sha256(format!("{error:?}").as_bytes())),
        raw_evidence: Vec::new(),
    }
}

fn harness_error(
    code: HarnessErrorCode,
    detail: &str,
    retryable_delivery: bool,
    recovery_required: bool,
    fingerprint: Option<String>,
) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery,
        recovery_required,
        error_fingerprint: fingerprint,
        audit_ref: None,
    }
}

fn readiness_for_error(
    error: &DriverError,
) -> egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessReadiness {
    use egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessReadiness;
    if error.code == HarnessErrorCode::ProtocolMismatch {
        HarnessReadiness::ProtocolMismatch
    } else {
        HarnessReadiness::Unavailable
    }
}

fn canonical_digest<M>(message: &M) -> String
where
    M: Message + Clone,
{
    sha256(&message.encode_to_vec())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

#[allow(dead_code)]
fn _unimplemented_resume_boundary(_: &ResumeExecutionEnvelope) -> ResumeExecutionResult {
    ResumeExecutionResult {
        outcome: Some(resume_execution_result::Outcome::Error(harness_error(
            HarnessErrorCode::ResumeUnsupported,
            "PARTIAL_EXECUTION_RESUME_UNSUPPORTED",
            false,
            true,
            None,
        ))),
    }
}
