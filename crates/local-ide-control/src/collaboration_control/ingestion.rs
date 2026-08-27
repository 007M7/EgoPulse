use super::*;
use egopulse_domain_contracts::v01::egopulse::collaboration::v1::{
    AttemptCancellationDisposition, AttemptCommandBase, MarkAttemptOutcomeUnknownCommand,
    RecordAttemptCancellationOutcomeCommand, RecordDeliveryReceiptCommand, RecordHarnessAckCommand,
    RecordRunningObservationCommand, collaboration_command, collaboration_command_result,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AckDisposition, DeliveryDisposition, DispatchReceipt, HarnessObservation, LifecycleKind,
    ObservationCriticality, SideEffectCertainty, harness_observation,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessFactIngestionDisposition {
    Consumed,
    IgnoredInformational,
    DeferredToArtifactAuthority,
    RetainedForDependency,
    QuarantineRequired { reason_code: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct HarnessFactIngestionResult {
    pub disposition: HarnessFactIngestionDisposition,
    pub authority_result: Option<CollaborationCommandResult>,
}

impl<G, C> CollaborationControl<G, C>
where
    G: CollaborationReferenceGuard + HarnessEvidenceResolver,
    C: AuthorityClock,
{
    pub fn ingest_dispatch_receipt(
        &mut self,
        receipt: &DispatchReceipt,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        if !is_authenticated_adapter(principal) {
            return Ok(ingestion_authority_result(error_result(
                CollaborationErrorCode::PermissionDenied,
                "HARNESS_INGESTION_NOT_AUTHORIZED",
                None,
                None,
            )));
        }
        if DeliveryDisposition::try_from(receipt.disposition) != Ok(DeliveryDisposition::Delivered)
        {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::RetainedForDependency,
                authority_result: None,
            });
        }
        let source_evidence = format!("delivery-receipt-digest:{}", receipt.receipt_digest_sha256);
        if let Some(result) = self.replay_harness_source(
            principal,
            "record_delivery_receipt",
            &receipt.attempt_id,
            &receipt.receipt_id,
            &source_evidence,
        )? {
            return Ok(ingestion_authority_result(result));
        }
        let snapshot = self.snapshot_for_attempt(&receipt.attempt_id)?;
        let mut command = CollaborationCommand {
            command: Some(collaboration_command::Command::RecordDeliveryReceipt(
                RecordDeliveryReceiptCommand {
                    base: Some(ingestion_base(
                        &snapshot,
                        &receipt.attempt_id,
                        &receipt.receipt_id,
                        "delivery",
                        self.clock.now(),
                    )?),
                    dispatch_id: receipt.dispatch_id.clone(),
                    fencing_token: receipt.fencing_token,
                    delivery_receipt_id: receipt.receipt_id.clone(),
                    receipt_digest_sha256: receipt.receipt_digest_sha256.clone(),
                },
            )),
        };
        seal_ingestion_command(&mut command);
        let result = self.execute(&command, principal)?;
        Ok(classify_ingestion_result(result))
    }

    pub fn ingest_harness_observation(
        &mut self,
        observation: &HarnessObservation,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        if !is_authenticated_adapter(principal) {
            return Ok(ingestion_authority_result(error_result(
                CollaborationErrorCode::PermissionDenied,
                "HARNESS_INGESTION_NOT_AUTHORIZED",
                None,
                None,
            )));
        }
        if observation.observation_id.trim().is_empty()
            || observation.attempt_id.trim().is_empty()
            || observation.dispatch_id.trim().is_empty()
            || observation.fencing_token == 0
            || observation.observation_sequence == 0
            || !sha256_is_complete(&observation.native_event_digest_sha256)
        {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                    reason_code: "HARNESS_OBSERVATION_INVALID".to_owned(),
                },
                authority_result: None,
            });
        }
        let snapshot = self.snapshot_for_attempt(&observation.attempt_id)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|value| value.attempt_id == observation.attempt_id)
            .ok_or(CollaborationControlError::Persistence)?;
        if attempt.dispatch_id.as_deref() != Some(observation.dispatch_id.as_str()) {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                    reason_code: "DISPATCH_ID_MISMATCH".to_owned(),
                },
                authority_result: None,
            });
        }
        if !current_fence_matches(attempt, observation.fencing_token) {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                    reason_code: "FENCING_TOKEN_STALE".to_owned(),
                },
                authority_result: None,
            });
        }
        match observation.payload.as_ref() {
            Some(harness_observation::Payload::Ack(ack))
                if AckDisposition::try_from(ack.disposition) == Ok(AckDisposition::Accepted) =>
            {
                self.ingest_ack_observation(observation, ack, principal)
            }
            Some(harness_observation::Payload::Lifecycle(lifecycle)) => {
                match LifecycleKind::try_from(lifecycle.kind) {
                    Ok(LifecycleKind::ExecutionStarted) => {
                        self.ingest_running_observation(observation, principal)
                    }
                    Ok(LifecycleKind::ExecutionInterrupted) => {
                        self.ingest_interrupted_observation(observation)
                    }
                    Ok(LifecycleKind::ExecutionCompleted) => Ok(HarnessFactIngestionResult {
                        disposition: HarnessFactIngestionDisposition::DeferredToArtifactAuthority,
                        authority_result: None,
                    }),
                    Ok(LifecycleKind::ExecutionFailed | LifecycleKind::ProcessExited)
                        if SideEffectCertainty::try_from(lifecycle.side_effect_certainty)
                            != Ok(SideEffectCertainty::NoneProven) =>
                    {
                        self.hold_unknown_observation(
                            observation,
                            "HARNESS_TERMINAL_OUTCOME_UNKNOWN",
                        )
                    }
                    Ok(_) => Ok(HarnessFactIngestionResult {
                        disposition: HarnessFactIngestionDisposition::IgnoredInformational,
                        authority_result: None,
                    }),
                    Err(_) => self
                        .hold_unknown_observation(observation, "UNKNOWN_NATIVE_TERMINAL_VARIANT"),
                }
            }
            Some(harness_observation::Payload::ArtifactReturn(_)) => {
                Ok(HarnessFactIngestionResult {
                    disposition: HarnessFactIngestionDisposition::DeferredToArtifactAuthority,
                    authority_result: None,
                })
            }
            Some(harness_observation::Payload::Diagnostic(diagnostic))
                if diagnostic.recovery_required
                    && ObservationCriticality::try_from(observation.criticality)
                        != Ok(ObservationCriticality::Informational) =>
            {
                self.hold_unknown_observation(observation, &diagnostic.safe_diagnostic_code)
            }
            Some(_) => Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::IgnoredInformational,
                authority_result: None,
            }),
            None if matches!(
                ObservationCriticality::try_from(observation.criticality),
                Ok(ObservationCriticality::Control
                    | ObservationCriticality::Security
                    | ObservationCriticality::Terminal
                    | ObservationCriticality::Artifact)
            ) =>
            {
                self.hold_unknown_observation(observation, "UNKNOWN_CRITICAL_EVENT")
            }
            None => Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::IgnoredInformational,
                authority_result: None,
            }),
        }
    }

    fn ingest_ack_observation(
        &mut self,
        observation: &HarnessObservation,
        ack: &egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessAckObservation,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        let evidence = format!(
            "harness-observation-digest:{}",
            observation.native_event_digest_sha256
        );
        if let Some(result) = self.replay_harness_source(
            principal,
            "record_harness_ack",
            &observation.attempt_id,
            &observation.observation_id,
            &evidence,
        )? {
            return Ok(ingestion_authority_result(result));
        }
        let snapshot = self.snapshot_for_attempt(&observation.attempt_id)?;
        let mut command = CollaborationCommand {
            command: Some(collaboration_command::Command::RecordHarnessAck(
                RecordHarnessAckCommand {
                    base: Some(ingestion_base(
                        &snapshot,
                        &observation.attempt_id,
                        &observation.observation_id,
                        "ack",
                        self.clock.now(),
                    )?),
                    dispatch_id: observation.dispatch_id.clone(),
                    fencing_token: observation.fencing_token,
                    harness_sequence: observation.observation_sequence,
                    ack_receipt_id: ack.ack_receipt_id.clone(),
                    receipt_digest_sha256: observation.native_event_digest_sha256.clone(),
                },
            )),
        };
        seal_ingestion_command(&mut command);
        Ok(classify_ingestion_result(
            self.execute(&command, principal)?,
        ))
    }

    fn ingest_running_observation(
        &mut self,
        observation: &HarnessObservation,
        principal: &AuthenticatedCollaborationPrincipal,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        let evidence = format!(
            "harness-observation-digest:{}",
            observation.native_event_digest_sha256
        );
        if let Some(result) = self.replay_harness_source(
            principal,
            "record_running_observation",
            &observation.attempt_id,
            &observation.observation_id,
            &evidence,
        )? {
            return Ok(ingestion_authority_result(result));
        }
        let snapshot = self.snapshot_for_attempt(&observation.attempt_id)?;
        let mut command = CollaborationCommand {
            command: Some(collaboration_command::Command::RecordRunningObservation(
                RecordRunningObservationCommand {
                    base: Some(ingestion_base(
                        &snapshot,
                        &observation.attempt_id,
                        &observation.observation_id,
                        "running",
                        self.clock.now(),
                    )?),
                    fencing_token: observation.fencing_token,
                    harness_sequence: observation.observation_sequence,
                    lifecycle_event_id: observation.observation_id.clone(),
                    event_digest_sha256: observation.native_event_digest_sha256.clone(),
                },
            )),
        };
        seal_ingestion_command(&mut command);
        Ok(classify_ingestion_result(
            self.execute(&command, principal)?,
        ))
    }

    fn ingest_interrupted_observation(
        &mut self,
        observation: &HarnessObservation,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        let snapshot = self.snapshot_for_attempt(&observation.attempt_id)?;
        let attempt = snapshot
            .attempts
            .iter()
            .find(|value| value.attempt_id == observation.attempt_id)
            .ok_or(CollaborationControlError::Persistence)?;
        if attempt.status != AttemptStatus::CancellationPending as i32 {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::RetainedForDependency,
                authority_result: None,
            });
        }
        let recovery_principal = harness_recovery_principal();
        let evidence = format!("cancellation-receipt:{}", observation.observation_id);
        if let Some(result) = self.replay_harness_source(
            &recovery_principal,
            "record_attempt_cancellation_outcome",
            &observation.attempt_id,
            &observation.observation_id,
            &evidence,
        )? {
            return Ok(ingestion_authority_result(result));
        }
        let mut command = CollaborationCommand {
            command: Some(
                collaboration_command::Command::RecordAttemptCancellationOutcome(
                    RecordAttemptCancellationOutcomeCommand {
                        base: Some(ingestion_base(
                            &snapshot,
                            &observation.attempt_id,
                            &observation.observation_id,
                            "cancellation-confirmation",
                            self.clock.now(),
                        )?),
                        disposition: AttemptCancellationDisposition::CancelledConfirmed as i32,
                        cancellation_receipt_id: observation.observation_id.clone(),
                    },
                ),
            ),
        };
        seal_ingestion_command(&mut command);
        Ok(classify_ingestion_result(
            self.execute(&command, &recovery_principal)?,
        ))
    }

    fn hold_unknown_observation(
        &mut self,
        observation: &HarnessObservation,
        reason_code: &str,
    ) -> Result<HarnessFactIngestionResult, CollaborationControlError> {
        let recovery_principal = harness_recovery_principal();
        let evidence = format!("uncertainty-evidence:{}", observation.observation_id);
        if let Some(result) = self.replay_harness_source(
            &recovery_principal,
            "mark_attempt_outcome_unknown",
            &observation.attempt_id,
            &observation.observation_id,
            &evidence,
        )? {
            return Ok(HarnessFactIngestionResult {
                disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                    reason_code: reason_code.to_owned(),
                },
                authority_result: Some(result),
            });
        }
        let snapshot = self.snapshot_for_attempt(&observation.attempt_id)?;
        let mut command = CollaborationCommand {
            command: Some(collaboration_command::Command::MarkAttemptOutcomeUnknown(
                MarkAttemptOutcomeUnknownCommand {
                    base: Some(ingestion_base(
                        &snapshot,
                        &observation.attempt_id,
                        &observation.observation_id,
                        "outcome-unknown",
                        self.clock.now(),
                    )?),
                    reason_code: reason_code.to_owned(),
                    uncertainty_evidence_id: observation.observation_id.clone(),
                },
            )),
        };
        seal_ingestion_command(&mut command);
        Ok(HarnessFactIngestionResult {
            disposition: HarnessFactIngestionDisposition::QuarantineRequired {
                reason_code: reason_code.to_owned(),
            },
            authority_result: Some(self.execute(&command, &recovery_principal)?),
        })
    }

    fn snapshot_for_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<CollaborationSnapshot, CollaborationControlError> {
        let run_id = self
            .store
            .run_id_for_attempt(attempt_id)?
            .ok_or(CollaborationControlError::Persistence)?;
        self.load_snapshot(&run_id)?
            .ok_or(CollaborationControlError::Persistence)
    }

    fn replay_harness_source(
        &self,
        principal: &AuthenticatedCollaborationPrincipal,
        operation: &str,
        scope: &str,
        key: &str,
        source_evidence: &str,
    ) -> Result<Option<CollaborationCommandResult>, CollaborationControlError> {
        let Some(record) =
            self.store
                .idempotency_record(&principal.principal_id, operation, scope, key)?
        else {
            return Ok(None);
        };
        let event = self
            .store
            .event_blob(&record.event_id)?
            .ok_or(CollaborationControlError::Persistence)?;
        let event = CollaborationEvent::decode(event.as_slice())?;
        if !event
            .evidence_refs
            .iter()
            .any(|value| value == source_evidence)
        {
            return Ok(Some(error_result(
                CollaborationErrorCode::IdempotencyConflict,
                "HARNESS_SOURCE_ID_REUSED_WITH_DIFFERENT_DIGEST",
                Some(record.run_revision),
                None,
            )));
        }
        let mut result = CollaborationCommandResult::decode(record.result.as_slice())?;
        result.replayed = true;
        Ok(Some(result))
    }
}

fn ingestion_base(
    snapshot: &CollaborationSnapshot,
    attempt_id: &str,
    source_id: &str,
    operation: &str,
    now: Timestamp,
) -> Result<AttemptCommandBase, CollaborationControlError> {
    let run = snapshot
        .run
        .as_ref()
        .ok_or(CollaborationControlError::Persistence)?;
    let attempt = snapshot
        .attempts
        .iter()
        .find(|value| value.attempt_id == attempt_id)
        .ok_or(CollaborationControlError::Persistence)?;
    let step = snapshot
        .steps
        .iter()
        .find(|value| value.step_id == attempt.step_id)
        .ok_or(CollaborationControlError::Persistence)?;
    Ok(AttemptCommandBase {
        meta: Some(CommandMetadata {
            command_id: format!("harness-ingest:{operation}:{source_id}"),
            idempotency_key: source_id.to_owned(),
            idempotency_scope: attempt_id.to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(now),
            correlation_id: format!("harness-ingest:{source_id}"),
            causation_id: Some(source_id.to_owned()),
        }),
        run_id: run.run_id.clone(),
        expected_run_revision: run.revision,
        step_id: step.step_id.clone(),
        expected_step_revision: step.revision,
        attempt_id: attempt.attempt_id.clone(),
        expected_attempt_revision: attempt.revision,
    })
}

fn seal_ingestion_command(command: &mut CollaborationCommand) {
    let digest = canonical_request_digest(command).expect("ingestion command has metadata");
    command_metadata_mut(command)
        .expect("ingestion command has metadata")
        .request_digest_sha256 = digest;
}

fn is_authenticated_adapter(principal: &AuthenticatedCollaborationPrincipal) -> bool {
    principal.authenticated
        && principal.kind == CollaborationPrincipalKind::HarnessAdapter
        && !principal.principal_id.trim().is_empty()
}

fn harness_recovery_principal() -> AuthenticatedCollaborationPrincipal {
    AuthenticatedCollaborationPrincipal {
        kind: CollaborationPrincipalKind::RecoveryWorker,
        principal_id: "collaboration-control:harness-ingestion".to_owned(),
        authenticated: true,
    }
}

fn ingestion_authority_result(result: CollaborationCommandResult) -> HarnessFactIngestionResult {
    classify_ingestion_result(result)
}

fn classify_ingestion_result(result: CollaborationCommandResult) -> HarnessFactIngestionResult {
    let disposition = match result.outcome.as_ref() {
        Some(collaboration_command_result::Outcome::Snapshot(_)) => {
            HarnessFactIngestionDisposition::Consumed
        }
        Some(collaboration_command_result::Outcome::Error(error))
            if matches!(
                CollaborationErrorCode::try_from(error.code),
                Ok(CollaborationErrorCode::FencingRejected
                    | CollaborationErrorCode::SequenceConflict
                    | CollaborationErrorCode::ContractMismatch
                    | CollaborationErrorCode::IdempotencyConflict)
            ) =>
        {
            HarnessFactIngestionDisposition::QuarantineRequired {
                reason_code: error.safe_detail_code.clone(),
            }
        }
        Some(collaboration_command_result::Outcome::Error(_)) | None => {
            HarnessFactIngestionDisposition::RetainedForDependency
        }
    };
    HarnessFactIngestionResult {
        disposition,
        authority_result: Some(result),
    }
}
