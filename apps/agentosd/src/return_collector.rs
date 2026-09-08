use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAdmissionGuard, ArtifactAuthority, ArtifactClock, ArtifactPrincipalKind,
    AuthenticatedArtifactPrincipal, canonical_artifact_set_manifest, canonical_request_digest,
    content_address,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus,
        ArtifactStatus, Claim, ClaimSourceType, ClaimStatus, Evidence, EvidenceProducerClass,
        EvidenceRelation, EvidenceStatus, IntegrityStatus, LineageBinding, ProducerIdentity,
        Provenance, ReturnHandoff, ReturnHandoffStatus, SealArtifactCommand,
        SealArtifactSetCommand, StageArtifactCommand, SubmitReturnHandoffCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    harness::v1::HarnessErrorCode,
};
#[cfg(test)]
use egopulse_harness_adapter::FinalArtifactRelationPolicy;
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeError, FinalArtifactRelationRegistration, FinalArtifactRelationRequest,
    PendingTerminalOutputCandidate,
};
use egopulse_local_ide_control::collaboration_control::{
    HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
};
use prost_types::Timestamp;

use crate::{
    repository_command::{
        GovernedRepositoryCommandProcessExecutor, RepositoryCommandArtifactRunner,
        RepositoryCommandBlockedReason, RepositoryCommandExecutionOutcome,
        RepositoryCommandExecutionRequest, RepositoryCommandHelperError, RepositoryCommandReceipt,
    },
    repository_dispatch::{CapturedRepositoryReturn, RepositoryDispatchCoordinator},
    repository_material::RepositoryAcceptanceCommandV1,
};

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[derive(Clone, Debug)]
pub struct GovernedReturnCollectorConfig {
    pub artifact_type_ref: ContractReference,
    pub transformation_contract_ref: ContractReference,
    pub retention_profile_ref: ContractReference,
    pub claim_semantic_profile_ref: ContractReference,
    pub claim_acceptance_contract_ref: ContractReference,
    pub evidence_profile_ref: ContractReference,
    pub workspace_ref: String,
    pub collector_principal_id: String,
    pub artifact_authority_principal_id: String,
}

impl GovernedReturnCollectorConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.workspace_ref.trim().is_empty()
            || self.collector_principal_id.trim().is_empty()
            || self.artifact_authority_principal_id.trim().is_empty()
            || [
                &self.artifact_type_ref,
                &self.transformation_contract_ref,
                &self.retention_profile_ref,
                &self.claim_semantic_profile_ref,
                &self.claim_acceptance_contract_ref,
                &self.evidence_profile_ref,
            ]
            .iter()
            .any(|reference| {
                reference.contract_id.trim().is_empty()
                    || reference.version.trim().is_empty()
                    || !is_sha256(&reference.sha256)
            })
        {
            return Err("return collector configuration");
        }
        Ok(())
    }
}

pub struct GovernedReturnCollectorRunner<G, C> {
    harness: Arc<dyn HarnessDispatchRunner>,
    edge: Mutex<AdapterEdge>,
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
    config: GovernedReturnCollectorConfig,
    collection_guard: tokio::sync::Mutex<()>,
    repository_dispatch: Option<Arc<RepositoryDispatchCoordinator>>,
    repository_commands: Option<
        Arc<RepositoryCommandArtifactRunner<G, C, GovernedRepositoryCommandProcessExecutor>>,
    >,
}

impl<G, C> GovernedReturnCollectorRunner<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    pub fn new(
        harness: Arc<dyn HarnessDispatchRunner>,
        edge: AdapterEdge,
        authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
        config: GovernedReturnCollectorConfig,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            harness,
            edge: Mutex::new(edge),
            authority,
            config,
            collection_guard: tokio::sync::Mutex::new(()),
            repository_dispatch: None,
            repository_commands: None,
        })
    }

    pub(crate) fn with_repository_return(
        mut self,
        repository_dispatch: Arc<RepositoryDispatchCoordinator>,
        repository_commands: Arc<
            RepositoryCommandArtifactRunner<G, C, GovernedRepositoryCommandProcessExecutor>,
        >,
    ) -> Self {
        self.repository_dispatch = Some(repository_dispatch);
        self.repository_commands = Some(repository_commands);
        self
    }

    async fn collect_pending(
        &self,
        report: &mut HarnessDispatchCycleReport,
    ) -> Result<(), HarnessDispatchCycleError> {
        let _collection_guard = self.collection_guard.lock().await;
        let pending = {
            let edge = self.edge.lock().map_err(|_| {
                HarnessDispatchCycleError::ReturnCollector("adapter edge lock poisoned".to_owned())
            })?;
            edge.pending_terminal_output_candidates().map_err(|_| {
                HarnessDispatchCycleError::ReturnCollector(
                    "terminal output outbox unavailable or corrupt".to_owned(),
                )
            })?
        };
        report.terminal_output_candidates_seen += pending.len() as u64;
        for candidate in pending {
            if !candidate.content_complete || candidate.content.is_empty() {
                self.hold_candidate(&candidate)?;
                report.terminal_output_candidates_held += 1;
                continue;
            }
            let collected = if self.repository_dispatch.is_some() {
                self.collect_repository_candidate(&candidate).await
            } else {
                let mut authority = self.authority.lock().map_err(|_| {
                    HarnessDispatchCycleError::ReturnCollector(
                        "Artifact Authority lock poisoned".to_owned(),
                    )
                })?;
                collect_legacy_candidate(&mut authority, &self.config, &candidate)
            };
            match collected {
                Ok(collected) => {
                    let relation = self
                        .edge
                        .lock()
                        .map_err(|_| {
                            HarnessDispatchCycleError::ReturnCollector(
                                "adapter edge lock poisoned".to_owned(),
                            )
                        })?
                        .register_final_artifact_relation_intent_and_ack(
                            &FinalArtifactRelationRequest {
                                terminal_message_id: candidate.message_id.clone(),
                                terminal_payload_digest_sha256: candidate
                                    .payload_digest_sha256
                                    .clone(),
                                artifact_id: collected.artifact_id,
                                artifact_digest_sha256: collected.artifact_digest_sha256,
                            },
                            now().seconds,
                        );
                    match relation {
                        Ok(FinalArtifactRelationRegistration::Registered)
                        | Ok(FinalArtifactRelationRegistration::Replay) => {}
                        Ok(FinalArtifactRelationRegistration::SkippedLegacy) => tracing::info!(
                            safe_reason_code = "FINAL_ARTIFACT_RELATION_LEGACY_NOT_REQUIRED",
                            "technical return settled without a relation intent"
                        ),
                        Err(_) => {
                            tracing::warn!(
                                safe_reason_code = "FINAL_ARTIFACT_RELATION_STORE_UNAVAILABLE",
                                "technical return will retry from the durable candidate"
                            );
                            continue;
                        }
                    }
                    report.terminal_output_candidates_receipted += 1;
                }
                Err(CollectorFailure::Rejected) => {
                    self.hold_candidate(&candidate)?;
                    report.terminal_output_candidates_held += 1;
                }
                Err(CollectorFailure::Unavailable) => {
                    tracing::warn!(
                        safe_reason_code = "RETURN_COLLECTION_DEPENDENCY_UNAVAILABLE",
                        "technical return will retry from the durable candidate"
                    );
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn collect_repository_candidate(
        &self,
        candidate: &PendingTerminalOutputCandidate,
    ) -> Result<CollectedReturn, CollectorFailure> {
        let repository_dispatch = self
            .repository_dispatch
            .as_ref()
            .ok_or(CollectorFailure::Rejected)?;
        let envelope = {
            let edge = self
                .edge
                .lock()
                .map_err(|_| CollectorFailure::Unavailable)?;
            match edge.dispatch_envelope(&candidate.dispatch_id) {
                Ok(Some(envelope)) => envelope,
                Ok(None) => return Err(CollectorFailure::Rejected),
                Err(error) => return Err(classify_edge_read_failure(&error)),
            }
        };
        let captured = repository_dispatch
            .capture_return(&envelope)
            .await
            .map_err(|error| classify_harness_failure(&error))?;
        let Some(captured) = captured else {
            let mut authority = self
                .authority
                .lock()
                .map_err(|_| CollectorFailure::Unavailable)?;
            return collect_legacy_candidate(&mut authority, &self.config, candidate);
        };
        let repository_commands = self
            .repository_commands
            .as_ref()
            .ok_or(CollectorFailure::Rejected)?;
        if captured.sealed_dispatch.lineage != lineage(candidate) {
            return Err(CollectorFailure::Rejected);
        }
        let input_artifact_ids = vec![
            captured.sealed_dispatch.baseline_artifact_id.clone(),
            captured
                .sealed_dispatch
                .initial_manifest_artifact_id
                .clone(),
            captured.patch_artifact_id.clone(),
            captured.final_manifest_artifact_id.clone(),
        ];
        let mut completed = Vec::with_capacity(
            captured
                .frozen_material
                .acceptance_contract
                .required_commands
                .len(),
        );
        for command in &captured
            .frozen_material
            .acceptance_contract
            .required_commands
        {
            let outcome = repository_commands
                .execute(RepositoryCommandExecutionRequest {
                    material: &captured.frozen_material,
                    command,
                    lineage: captured.sealed_dispatch.lineage.clone(),
                    workspace_root: &captured.workspace_root,
                    workspace_ref: &captured.sealed_dispatch.workspace_ref,
                    source_binding_ref: &captured.sealed_dispatch.source_binding_ref,
                    input_artifact_ids: &input_artifact_ids,
                })
                .await
                .map_err(classify_command_helper_failure)?;
            match outcome {
                RepositoryCommandExecutionOutcome::Completed(receipt)
                | RepositoryCommandExecutionOutcome::Replayed(receipt) => {
                    completed.push(CompletedRepositoryCommand {
                        command: command.clone(),
                        receipt,
                    });
                }
                RepositoryCommandExecutionOutcome::Blocked(blocked) => {
                    return Err(classify_command_blocked(blocked.reason));
                }
            }
        }
        repository_dispatch
            .verify_return_unchanged(&captured)
            .await
            .map_err(|error| classify_harness_failure(&error))?;
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| CollectorFailure::Unavailable)?;
        collect_repository_one(
            &mut authority,
            &self.config,
            candidate,
            &captured,
            &completed,
        )
    }

    fn hold_candidate(
        &self,
        candidate: &PendingTerminalOutputCandidate,
    ) -> Result<(), HarnessDispatchCycleError> {
        let held = self
            .edge
            .lock()
            .map_err(|_| {
                HarnessDispatchCycleError::ReturnCollector("adapter edge lock poisoned".to_owned())
            })?
            .hold_terminal_output_candidate(&candidate.message_id, &candidate.payload_digest_sha256)
            .map_err(|_| {
                HarnessDispatchCycleError::ReturnCollector("terminal output hold failed".to_owned())
            })?;
        if !held {
            return Err(HarnessDispatchCycleError::ReturnCollector(
                "terminal output hold was not persisted".to_owned(),
            ));
        }
        Ok(())
    }
}

impl<G, C> HarnessDispatchRunner for GovernedReturnCollectorRunner<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn run_once(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let mut report = self.harness.run_once().await?;
            self.collect_pending(&mut report).await?;
            Ok(report)
        })
    }
}

fn collect_legacy_candidate<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    ensure_legacy_fallback_allowed(authority, candidate)?;
    collect_one(authority, config, candidate)
}

fn ensure_legacy_fallback_allowed<G, C>(
    authority: &ArtifactAuthority<G, C>,
    candidate: &PendingTerminalOutputCandidate,
) -> Result<(), CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let baseline_id = format!("artifact:repository-baseline:{}", candidate.dispatch_id);
    let initial_manifest_id = format!("artifact:workspace-initial:{}", candidate.dispatch_id);
    let baseline = authority
        .read_artifact(&baseline_id)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if baseline.is_some() {
        return Err(CollectorFailure::Rejected);
    }
    let initial_manifest = authority
        .read_artifact(&initial_manifest_id)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if initial_manifest.is_some() {
        return Err(CollectorFailure::Rejected);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectorFailure {
    Rejected,
    Unavailable,
}

fn classify_edge_read_failure(error: &AdapterEdgeError) -> CollectorFailure {
    match error {
        AdapterEdgeError::Sql(_)
        | AdapterEdgeError::Directory(_)
        | AdapterEdgeError::CipherUnavailable => CollectorFailure::Unavailable,
        AdapterEdgeError::Migration(_)
        | AdapterEdgeError::StoreGenerationMismatch
        | AdapterEdgeError::IntegrityFailure
        | AdapterEdgeError::DispatchConflict
        | AdapterEdgeError::DispatchStateConflict
        | AdapterEdgeError::DispatchNotFound(_)
        | AdapterEdgeError::SequenceConflict
        | AdapterEdgeError::Decode(_) => CollectorFailure::Rejected,
    }
}

fn classify_harness_failure(
    error: &egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessError,
) -> CollectorFailure {
    if error.code == HarnessErrorCode::DependencyUnavailable as i32 {
        CollectorFailure::Unavailable
    } else {
        CollectorFailure::Rejected
    }
}

fn classify_command_helper_failure(_error: RepositoryCommandHelperError) -> CollectorFailure {
    CollectorFailure::Rejected
}

fn classify_command_blocked(reason: RepositoryCommandBlockedReason) -> CollectorFailure {
    match reason {
        RepositoryCommandBlockedReason::ArtifactAuthorityUnavailable => {
            CollectorFailure::Unavailable
        }
        RepositoryCommandBlockedReason::ExistingIntentWithoutReceipt
        | RepositoryCommandBlockedReason::ArtifactIntegrityConflict
        | RepositoryCommandBlockedReason::ReceiptPersistenceIncomplete => {
            CollectorFailure::Rejected
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CollectedReturn {
    artifact_id: String,
    artifact_digest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CollectedArtifact {
    artifact_id: String,
    address: egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
    producer: ProducerIdentity,
}

struct CompletedRepositoryCommand {
    command: RepositoryAcceptanceCommandV1,
    receipt: RepositoryCommandReceipt,
}

#[derive(Clone)]
struct PlannedEvidence {
    evidence_id: String,
    relation: EvidenceRelation,
    artifact_ids: Vec<String>,
    producer: ProducerIdentity,
    producer_class: EvidenceProducerClass,
    independent_of_claim_proposer: bool,
    coverage: Vec<u8>,
    limitation_codes: Vec<String>,
    evidence_profile_ref: ContractReference,
}

#[derive(Clone)]
struct ExpectedEvidence {
    evidence_id: String,
    relation: EvidenceRelation,
    artifact_ids: Vec<String>,
    producer: ProducerIdentity,
    producer_class: EvidenceProducerClass,
    independent_of_claim_proposer: bool,
    coverage: egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
    limitation_codes: Vec<String>,
    evidence_profile_ref: ContractReference,
}

fn collect_one<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let lineage = LineageBinding {
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision,
        work_revision: candidate.work_revision,
        run_id: candidate.run_id.clone(),
        run_revision: candidate.run_revision,
        step_id: candidate.step_id.clone(),
        step_revision: candidate.step_revision,
        attempt_id: candidate.attempt_id.clone(),
        attempt_revision: candidate.attempt_revision,
        dispatch_id: candidate.dispatch_id.clone(),
        fencing_token: candidate.fencing_token,
    };
    let object_suffix = candidate.dispatch_id.clone();
    let artifact_id = format!("artifact:harness-output:{object_suffix}");
    let claim_id = format!("claim:harness-output-captured:{object_suffix}");
    let evidence_id = format!("evidence:collector-capture:{object_suffix}");
    let set_id = format!("artifact-set:harness-return:{object_suffix}");
    let handoff_id = format!("return-handoff:harness:{object_suffix}");
    let collector = principal(
        ArtifactPrincipalKind::GovernedCollector,
        &config.collector_principal_id,
    );
    let authority_principal = principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        &config.artifact_authority_principal_id,
    );
    let producer = producer(config, candidate);

    let final_message = stage_final_message(
        authority,
        config,
        candidate,
        &lineage,
        &artifact_id,
        &collector,
        &authority_principal,
        &producer,
        &config.workspace_ref,
        format!(
            "adapter-terminal-output://{}",
            candidate.source_observation_id
        ),
        Vec::new(),
    )?;
    let artifact_digest_sha256 = final_message.address.digest;

    let statement_bytes = format!(
        "governed collector captured terminal Harness output; dispatch={}; digest={}; completion={}",
        candidate.dispatch_id, candidate.content_digest_sha256, candidate.native_completion_ref
    )
    .into_bytes();
    let statement = content_address(&statement_bytes);
    authority
        .put_blob(&statement_bytes, &statement)
        .map_err(|_| CollectorFailure::Unavailable)?;
    execute_committed(
        authority,
        command(artifact_command::Command::ProposeClaim(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::ProposeClaimCommand {
                metadata: Some(metadata(candidate, "propose-claim")),
                claim: Some(Claim {
                    claim_id: claim_id.clone(),
                    revision: 1,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::GovernedCollector as i32,
                    semantic_profile_ref: Some(config.claim_semantic_profile_ref.clone()),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec![artifact_id.clone()],
                    acceptance_contract_ref: Some(config.claim_acceptance_contract_ref.clone()),
                    statement: Some(statement.clone()),
                    proposer: Some(producer.clone()),
                    proposed_at: None,
                    supersedes_claim_id: None,
                }),
            },
        )),
        &collector,
    )?;

    let coverage_bytes = format!(
        "source_observation={}; payload_digest={}; content_digest={}; bytes={}",
        candidate.source_observation_id,
        candidate.payload_digest_sha256,
        candidate.content_digest_sha256,
        candidate.original_content_bytes
    )
    .into_bytes();
    let coverage = content_address(&coverage_bytes);
    authority
        .put_blob(&coverage_bytes, &coverage)
        .map_err(|_| CollectorFailure::Unavailable)?;
    execute_committed(
        authority,
        command(artifact_command::Command::RecordEvidence(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::RecordEvidenceCommand {
                metadata: Some(metadata(candidate, "record-evidence")),
                evidence: Some(Evidence {
                    evidence_id: evidence_id.clone(),
                    revision: 1,
                    status: EvidenceStatus::Recorded as i32,
                    relation: EvidenceRelation::Supports as i32,
                    claim_id: claim_id.clone(),
                    artifact_ids: vec![artifact_id.clone()],
                    evidence_profile_ref: Some(config.evidence_profile_ref.clone()),
                    lineage: Some(lineage.clone()),
                    producer: Some(producer.clone()),
                    producer_class: EvidenceProducerClass::GovernedCollector as i32,
                    independent_of_claim_proposer: false,
                    integrity_status: IntegrityStatus::DigestVerified as i32,
                    coverage_descriptor: Some(coverage),
                    limitation_codes: Vec::new(),
                    recorded_at: None,
                    supersedes_evidence_id: None,
                }),
            },
        )),
        &collector,
    )?;

    let mut artifact_set = ArtifactSet {
        artifact_set_id: set_id.clone(),
        revision: 1,
        status: ArtifactSetStatus::Draft as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec![artifact_id.clone()],
        claim_ids: vec![claim_id.clone()],
        evidence_ids: vec![evidence_id.clone()],
        canonical_manifest: None,
        created_at: None,
        sealed_at: None,
        supersedes_artifact_set_id: None,
    };
    let manifest_bytes = canonical_artifact_set_manifest(&artifact_set);
    let manifest = content_address(&manifest_bytes);
    artifact_set.canonical_manifest = Some(manifest.clone());
    authority
        .put_blob(&manifest_bytes, &manifest)
        .map_err(|_| CollectorFailure::Unavailable)?;
    execute_committed(
        authority,
        command(artifact_command::Command::CreateArtifactSet(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::CreateArtifactSetCommand {
                metadata: Some(metadata(candidate, "create-set")),
                artifact_set: Some(artifact_set),
            },
        )),
        &collector,
    )?;
    execute_committed(
        authority,
        command(artifact_command::Command::SealArtifactSet(
            SealArtifactSetCommand {
                metadata: Some(metadata(candidate, "seal-set")),
                artifact_set_id: set_id.clone(),
                expected_revision: 1,
                observed_manifest: Some(manifest.clone()),
            },
        )),
        &authority_principal,
    )?;

    let result = execute_committed(
        authority,
        command(artifact_command::Command::SubmitReturnHandoff(
            SubmitReturnHandoffCommand {
                metadata: Some(metadata(candidate, "submit-handoff")),
                return_handoff: Some(ReturnHandoff {
                    return_handoff_id: handoff_id,
                    revision: 1,
                    status: ReturnHandoffStatus::Submitted as i32,
                    lineage: Some(lineage.clone()),
                    artifact_set_id: set_id,
                    artifact_set_manifest: Some(manifest),
                    primary_claim_ids: vec![claim_id],
                    evidence_ids: vec![evidence_id],
                    limitation_artifact_ids: Vec::new(),
                    unknown_artifact_ids: Vec::new(),
                    final_message_artifact_id: Some(artifact_id.clone()),
                    submitted_by: Some(producer),
                    submitted_at: None,
                    supersedes_return_handoff_id: None,
                }),
                expected_artifact_set_revision: 2,
            },
        )),
        &collector,
    )?;
    read_back_collected_return(
        authority,
        &result,
        &lineage,
        candidate,
        &artifact_id,
        &artifact_digest_sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_final_message<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
    lineage: &LineageBinding,
    artifact_id: &str,
    collector: &AuthenticatedArtifactPrincipal,
    authority_principal: &AuthenticatedArtifactPrincipal,
    producer: &ProducerIdentity,
    workspace_ref: &str,
    raw_source_ref: String,
    input_artifact_ids: Vec<String>,
) -> Result<CollectedArtifact, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let output_address = content_address(&candidate.content);
    authority
        .put_blob(&candidate.content, &output_address)
        .map_err(|_| CollectorFailure::Unavailable)?;
    let artifact = ArtifactDescriptor {
        artifact_id: artifact_id.to_owned(),
        revision: 1,
        status: ArtifactStatus::Staged as i32,
        semantic_class: ArtifactSemanticClass::FinalMessage as i32,
        type_contract_ref: Some(config.artifact_type_ref.clone()),
        media_type: candidate.media_type.clone(),
        content: Some(output_address.clone()),
        integrity_status: IntegrityStatus::Unverified as i32,
        provenance: Some(Provenance {
            lineage: Some(lineage.clone()),
            producer: Some(producer.clone()),
            input_artifact_ids,
            transformation_contract_ref: Some(config.transformation_contract_ref.clone()),
            workspace_ref: workspace_ref.to_owned(),
            observed_at: None,
            captured_at: None,
            raw_source_ref: Some(raw_source_ref),
        }),
        sensitivity_class: "local-user-data".to_owned(),
        retention_profile_ref: Some(config.retention_profile_ref.clone()),
        created_at: None,
        sealed_at: None,
        supersedes_artifact_id: None,
        quarantine_reason_code: None,
    };
    execute_committed(
        authority,
        command(artifact_command::Command::StageArtifact(
            StageArtifactCommand {
                metadata: Some(metadata(candidate, "stage-artifact")),
                candidate: Some(artifact),
            },
        )),
        collector,
    )?;
    execute_committed(
        authority,
        command(artifact_command::Command::SealArtifact(
            SealArtifactCommand {
                metadata: Some(metadata(candidate, "seal-artifact")),
                artifact_id: artifact_id.to_owned(),
                expected_revision: 1,
                observed_content: Some(output_address.clone()),
            },
        )),
        authority_principal,
    )?;
    Ok(CollectedArtifact {
        artifact_id: artifact_id.to_owned(),
        address: output_address,
        producer: producer.clone(),
    })
}

fn collect_repository_one<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
    captured: &CapturedRepositoryReturn,
    commands: &[CompletedRepositoryCommand],
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let lineage = lineage(candidate);
    if captured.sealed_dispatch.lineage != lineage
        || captured.sealed_dispatch.workspace_ref.trim().is_empty()
        || captured.workspace_root.as_os_str().is_empty()
        || captured.frozen_material != captured.sealed_dispatch.frozen_material
        || commands.len()
            != captured
                .frozen_material
                .acceptance_contract
                .required_commands
                .len()
    {
        return Err(CollectorFailure::Rejected);
    }
    let repository_artifacts = [
        read_sealed_artifact(
            authority,
            &captured.sealed_dispatch.baseline_artifact_id,
            ArtifactSemanticClass::RepositoryBaseline,
            &lineage,
            None,
        )?,
        read_sealed_artifact(
            authority,
            &captured.sealed_dispatch.initial_manifest_artifact_id,
            ArtifactSemanticClass::WorkspaceManifest,
            &lineage,
            None,
        )?,
        read_sealed_artifact(
            authority,
            &captured.patch_artifact_id,
            ArtifactSemanticClass::RepositoryPatch,
            &lineage,
            Some(&captured.patch_content),
        )?,
        read_sealed_artifact(
            authority,
            &captured.final_manifest_artifact_id,
            ArtifactSemanticClass::WorkspaceManifest,
            &lineage,
            Some(&captured.final_manifest_content),
        )?,
    ];
    let capture_producer = repository_artifacts[2].producer.clone();
    if repository_artifacts
        .iter()
        .any(|artifact| artifact.producer != capture_producer)
    {
        return Err(CollectorFailure::Rejected);
    }

    let collector = principal(
        ArtifactPrincipalKind::GovernedCollector,
        &config.collector_principal_id,
    );
    let authority_principal = principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        &config.artifact_authority_principal_id,
    );
    let final_message_producer = producer(config, candidate);
    let final_message_id = format!("artifact:harness-output:{}", candidate.dispatch_id);
    let final_message = stage_final_message(
        authority,
        config,
        candidate,
        &lineage,
        &final_message_id,
        &collector,
        &authority_principal,
        &final_message_producer,
        &captured.sealed_dispatch.workspace_ref,
        captured.sealed_dispatch.source_binding_ref.clone(),
        vec![
            captured.patch_artifact_id.clone(),
            captured.final_manifest_artifact_id.clone(),
        ],
    )?;

    let mut artifact_ids = repository_artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.clone())
        .collect::<Vec<_>>();
    let mut evidence = vec![PlannedEvidence {
        evidence_id: format!("evidence:repository-capture:{}", candidate.dispatch_id),
        relation: EvidenceRelation::Context,
        artifact_ids: repository_artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect(),
        producer: capture_producer,
        producer_class: EvidenceProducerClass::AttemptSupervisor,
        independent_of_claim_proposer: true,
        coverage: repository_coverage(captured),
        limitation_codes: Vec::new(),
        evidence_profile_ref: captured.evidence_profile_ref.clone(),
    }];

    for (index, (expected, completed)) in captured
        .frozen_material
        .acceptance_contract
        .required_commands
        .iter()
        .zip(commands)
        .enumerate()
    {
        if expected != &completed.command {
            return Err(CollectorFailure::Rejected);
        }
        let receipt_artifact = read_sealed_artifact(
            authority,
            &completed.receipt.artifact_id,
            ArtifactSemanticClass::CommandReceipt,
            &lineage,
            None,
        )?;
        if receipt_artifact.producer.principal_kind
            != ArtifactPrincipalKind::SupervisedRunner.as_str()
        {
            return Err(CollectorFailure::Rejected);
        }
        let (relation, limitation_codes) =
            command_evidence_disposition(expected, &completed.receipt);
        artifact_ids.push(receipt_artifact.artifact_id.clone());
        evidence.push(PlannedEvidence {
            evidence_id: format!(
                "evidence:repository-command:{}:{index}",
                candidate.dispatch_id
            ),
            relation,
            artifact_ids: vec![receipt_artifact.artifact_id],
            producer: receipt_artifact.producer,
            producer_class: EvidenceProducerClass::SupervisedRunner,
            independent_of_claim_proposer: true,
            coverage: command_coverage(expected, &completed.receipt),
            limitation_codes,
            evidence_profile_ref: captured.evidence_profile_ref.clone(),
        });
    }
    artifact_ids.push(final_message.artifact_id.clone());
    evidence.push(PlannedEvidence {
        evidence_id: format!("evidence:collector-capture:{}", candidate.dispatch_id),
        relation: EvidenceRelation::Context,
        artifact_ids: vec![final_message.artifact_id.clone()],
        producer: final_message.producer.clone(),
        producer_class: EvidenceProducerClass::GovernedCollector,
        independent_of_claim_proposer: false,
        coverage: final_message_coverage(candidate),
        limitation_codes: Vec::new(),
        evidence_profile_ref: captured.evidence_profile_ref.clone(),
    });

    let subject_artifact_ids = vec![
        captured.patch_artifact_id.clone(),
        captured.final_manifest_artifact_id.clone(),
        final_message.artifact_id.clone(),
    ];
    finish_repository_graph(
        authority,
        config,
        candidate,
        captured,
        &lineage,
        artifact_ids,
        subject_artifact_ids,
        evidence,
        &final_message,
        captured.frozen_material.acceptance_contract_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_repository_graph<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
    captured: &CapturedRepositoryReturn,
    lineage: &LineageBinding,
    artifact_ids: Vec<String>,
    subject_artifact_ids: Vec<String>,
    evidence: Vec<PlannedEvidence>,
    final_message: &CollectedArtifact,
    acceptance_contract_ref: ContractReference,
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let collector = principal(
        ArtifactPrincipalKind::GovernedCollector,
        &config.collector_principal_id,
    );
    let authority_principal = principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        &config.artifact_authority_principal_id,
    );
    let claim_id = format!("claim:repository-return:{}", candidate.dispatch_id);
    let statement_bytes =
        repository_claim_statement(candidate, &acceptance_contract_ref, &subject_artifact_ids)?;
    let statement = content_address(&statement_bytes);
    authority
        .put_blob(&statement_bytes, &statement)
        .map_err(|_| CollectorFailure::Unavailable)?;
    execute_committed(
        authority,
        command(artifact_command::Command::ProposeClaim(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::ProposeClaimCommand {
                metadata: Some(metadata(candidate, "propose-repository-claim")),
                claim: Some(Claim {
                    claim_id: claim_id.clone(),
                    revision: 1,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(config.claim_semantic_profile_ref.clone()),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: subject_artifact_ids.clone(),
                    acceptance_contract_ref: Some(acceptance_contract_ref.clone()),
                    statement: Some(statement.clone()),
                    proposer: Some(final_message.producer.clone()),
                    proposed_at: None,
                    supersedes_claim_id: None,
                }),
            },
        )),
        &collector,
    )?;

    let mut expected_evidence = Vec::with_capacity(evidence.len());
    for (index, planned) in evidence.into_iter().enumerate() {
        let evidence_principal = evidence_principal(&planned, &final_message.producer)?;
        let coverage = content_address(&planned.coverage);
        authority
            .put_blob(&planned.coverage, &coverage)
            .map_err(|_| CollectorFailure::Unavailable)?;
        let operation = format!("record-repository-evidence-{index}");
        execute_committed(
            authority,
            command(artifact_command::Command::RecordEvidence(
                egopulse_domain_contracts::v01::egopulse::artifact::v1::RecordEvidenceCommand {
                    metadata: Some(metadata(candidate, &operation)),
                    evidence: Some(Evidence {
                        evidence_id: planned.evidence_id.clone(),
                        revision: 1,
                        status: EvidenceStatus::Recorded as i32,
                        relation: planned.relation as i32,
                        claim_id: claim_id.clone(),
                        artifact_ids: planned.artifact_ids.clone(),
                        evidence_profile_ref: Some(planned.evidence_profile_ref.clone()),
                        lineage: Some(lineage.clone()),
                        producer: Some(planned.producer.clone()),
                        producer_class: planned.producer_class as i32,
                        independent_of_claim_proposer: planned.independent_of_claim_proposer,
                        integrity_status: IntegrityStatus::DigestVerified as i32,
                        coverage_descriptor: Some(coverage.clone()),
                        limitation_codes: planned.limitation_codes.clone(),
                        recorded_at: None,
                        supersedes_evidence_id: None,
                    }),
                },
            )),
            &evidence_principal,
        )?;
        expected_evidence.push(ExpectedEvidence {
            evidence_id: planned.evidence_id,
            relation: planned.relation,
            artifact_ids: planned.artifact_ids,
            producer: planned.producer,
            producer_class: planned.producer_class,
            independent_of_claim_proposer: planned.independent_of_claim_proposer,
            coverage,
            limitation_codes: planned.limitation_codes,
            evidence_profile_ref: planned.evidence_profile_ref,
        });
    }
    let evidence_ids = expected_evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<Vec<_>>();

    let set_id = format!("artifact-set:harness-return:{}", candidate.dispatch_id);
    let mut artifact_set = ArtifactSet {
        artifact_set_id: set_id.clone(),
        revision: 1,
        status: ArtifactSetStatus::Draft as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: artifact_ids.clone(),
        claim_ids: vec![claim_id.clone()],
        evidence_ids: evidence_ids.clone(),
        canonical_manifest: None,
        created_at: None,
        sealed_at: None,
        supersedes_artifact_set_id: None,
    };
    let manifest_bytes = canonical_artifact_set_manifest(&artifact_set);
    let manifest = content_address(&manifest_bytes);
    artifact_set.canonical_manifest = Some(manifest.clone());
    authority
        .put_blob(&manifest_bytes, &manifest)
        .map_err(|_| CollectorFailure::Unavailable)?;
    execute_committed(
        authority,
        command(artifact_command::Command::CreateArtifactSet(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::CreateArtifactSetCommand {
                metadata: Some(metadata(candidate, "create-repository-set")),
                artifact_set: Some(artifact_set),
            },
        )),
        &collector,
    )?;
    execute_committed(
        authority,
        command(artifact_command::Command::SealArtifactSet(
            SealArtifactSetCommand {
                metadata: Some(metadata(candidate, "seal-repository-set")),
                artifact_set_id: set_id.clone(),
                expected_revision: 1,
                observed_manifest: Some(manifest.clone()),
            },
        )),
        &authority_principal,
    )?;
    let result = execute_committed(
        authority,
        command(artifact_command::Command::SubmitReturnHandoff(
            SubmitReturnHandoffCommand {
                metadata: Some(metadata(candidate, "submit-repository-handoff")),
                return_handoff: Some(ReturnHandoff {
                    return_handoff_id: format!("return-handoff:harness:{}", candidate.dispatch_id),
                    revision: 1,
                    status: ReturnHandoffStatus::Submitted as i32,
                    lineage: Some(lineage.clone()),
                    artifact_set_id: set_id,
                    artifact_set_manifest: Some(manifest),
                    primary_claim_ids: vec![claim_id.clone()],
                    evidence_ids: evidence_ids.clone(),
                    limitation_artifact_ids: Vec::new(),
                    unknown_artifact_ids: Vec::new(),
                    final_message_artifact_id: Some(final_message.artifact_id.clone()),
                    submitted_by: Some(final_message.producer.clone()),
                    submitted_at: None,
                    supersedes_return_handoff_id: None,
                }),
                expected_artifact_set_revision: 2,
            },
        )),
        &collector,
    )?;
    read_back_repository_return(
        authority,
        config,
        &result,
        lineage,
        candidate,
        &artifact_ids,
        &claim_id,
        &subject_artifact_ids,
        &expected_evidence,
        &final_message.artifact_id,
        &final_message.address,
        &acceptance_contract_ref,
        &statement,
        &captured.sealed_dispatch.workspace_ref,
        &captured.sealed_dispatch.source_binding_ref,
        &[
            captured.patch_artifact_id.clone(),
            captured.final_manifest_artifact_id.clone(),
        ],
    )
}

fn evidence_principal(
    planned: &PlannedEvidence,
    claim_proposer: &ProducerIdentity,
) -> Result<AuthenticatedArtifactPrincipal, CollectorFailure> {
    let kind = match planned.producer.principal_kind.as_str() {
        "attempt_supervisor" => ArtifactPrincipalKind::AttemptSupervisor,
        "governed_collector" => ArtifactPrincipalKind::GovernedCollector,
        "supervised_runner" => ArtifactPrincipalKind::SupervisedRunner,
        "harness" => ArtifactPrincipalKind::Harness,
        "deterministic_checker" => ArtifactPrincipalKind::DeterministicChecker,
        "external_verifier" => ArtifactPrincipalKind::ExternalVerifier,
        _ => return Err(CollectorFailure::Rejected),
    };
    let class_matches = matches!(
        (kind, planned.producer_class),
        (
            ArtifactPrincipalKind::AttemptSupervisor,
            EvidenceProducerClass::AttemptSupervisor
        ) | (
            ArtifactPrincipalKind::GovernedCollector,
            EvidenceProducerClass::GovernedCollector
        ) | (
            ArtifactPrincipalKind::SupervisedRunner,
            EvidenceProducerClass::SupervisedRunner
        ) | (
            ArtifactPrincipalKind::Harness,
            EvidenceProducerClass::Harness
        ) | (
            ArtifactPrincipalKind::DeterministicChecker,
            EvidenceProducerClass::DeterministicChecker
        ) | (
            ArtifactPrincipalKind::ExternalVerifier,
            EvidenceProducerClass::ExternalVerifier
        )
    );
    if !class_matches
        || (planned.independent_of_claim_proposer
            && planned.producer.principal_id == claim_proposer.principal_id)
    {
        return Err(CollectorFailure::Rejected);
    }
    Ok(principal(kind, &planned.producer.principal_id))
}

fn lineage(candidate: &PendingTerminalOutputCandidate) -> LineageBinding {
    LineageBinding {
        task_id: candidate.task_id.clone(),
        task_revision: candidate.task_revision,
        work_revision: candidate.work_revision,
        run_id: candidate.run_id.clone(),
        run_revision: candidate.run_revision,
        step_id: candidate.step_id.clone(),
        step_revision: candidate.step_revision,
        attempt_id: candidate.attempt_id.clone(),
        attempt_revision: candidate.attempt_revision,
        dispatch_id: candidate.dispatch_id.clone(),
        fencing_token: candidate.fencing_token,
    }
}

fn read_sealed_artifact<G, C>(
    authority: &ArtifactAuthority<G, C>,
    artifact_id: &str,
    semantic_class: ArtifactSemanticClass,
    expected_lineage: &LineageBinding,
    expected_content: Option<
        &egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
    >,
) -> Result<CollectedArtifact, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let artifact = authority
        .read_artifact(artifact_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let address = artifact
        .content
        .as_ref()
        .ok_or(CollectorFailure::Rejected)?;
    let provenance = artifact
        .provenance
        .as_ref()
        .ok_or(CollectorFailure::Rejected)?;
    let producer = provenance
        .producer
        .as_ref()
        .ok_or(CollectorFailure::Rejected)?;
    if artifact.artifact_id != artifact_id
        || artifact.status != ArtifactStatus::Sealed as i32
        || artifact.semantic_class != semantic_class as i32
        || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
        || provenance.lineage.as_ref() != Some(expected_lineage)
        || expected_content.is_some_and(|expected| expected != address)
    {
        return Err(CollectorFailure::Rejected);
    }
    let bytes = authority
        .read_blob(address)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if content_address(&bytes) != *address {
        return Err(CollectorFailure::Rejected);
    }
    Ok(CollectedArtifact {
        artifact_id: artifact.artifact_id,
        address: address.clone(),
        producer: producer.clone(),
    })
}

fn repository_coverage(captured: &CapturedRepositoryReturn) -> Vec<u8> {
    format!(
        "baseline_artifact={}; initial_manifest_artifact={}; patch_artifact={}; patch_digest={}; final_manifest_artifact={}; final_manifest_digest={}",
        captured.sealed_dispatch.baseline_artifact_id,
        captured.sealed_dispatch.initial_manifest_artifact_id,
        captured.patch_artifact_id,
        captured.patch_content.digest,
        captured.final_manifest_artifact_id,
        captured.final_manifest_content.digest,
    )
    .into_bytes()
}

fn command_evidence_disposition(
    expected: &RepositoryAcceptanceCommandV1,
    receipt: &RepositoryCommandReceipt,
) -> (EvidenceRelation, Vec<String>) {
    if receipt.supervision_failure.is_some() {
        return (
            EvidenceRelation::Refutes,
            vec!["COMMAND_SUPERVISION_FAILURE".to_owned()],
        );
    }
    if receipt.exit_code == Some(expected.expected_exit_code) {
        (EvidenceRelation::Supports, Vec::new())
    } else {
        (
            EvidenceRelation::Refutes,
            vec!["COMMAND_EXIT_CODE_MISMATCH".to_owned()],
        )
    }
}

fn command_coverage(
    expected: &RepositoryAcceptanceCommandV1,
    receipt: &RepositoryCommandReceipt,
) -> Vec<u8> {
    format!(
        "command_id={}; criterion_id={}; receipt_artifact={}; expected_exit={}; observed_exit={:?}; supervision_failure={:?}; duration_ms={}",
        expected.command_id,
        expected.criterion_id,
        receipt.artifact_id,
        expected.expected_exit_code,
        receipt.exit_code,
        receipt.supervision_failure,
        receipt.duration_ms,
    )
    .into_bytes()
}

fn final_message_coverage(candidate: &PendingTerminalOutputCandidate) -> Vec<u8> {
    format!(
        "source_observation={}; payload_digest={}; content_digest={}; bytes={}",
        candidate.source_observation_id,
        candidate.payload_digest_sha256,
        candidate.content_digest_sha256,
        candidate.original_content_bytes
    )
    .into_bytes()
}

fn repository_claim_statement(
    candidate: &PendingTerminalOutputCandidate,
    acceptance_contract_ref: &ContractReference,
    subject_artifact_ids: &[String],
) -> Result<Vec<u8>, CollectorFailure> {
    serde_json::to_vec(&serde_json::json!({
        "schema": "egopulse.repository-return-claim/v1",
        "dispatch_id": candidate.dispatch_id,
        "acceptance_contract": {
            "contract_id": acceptance_contract_ref.contract_id,
            "version": acceptance_contract_ref.version,
            "sha256": acceptance_contract_ref.sha256,
        },
        "subject_artifact_ids": subject_artifact_ids,
    }))
    .map_err(|_| CollectorFailure::Rejected)
}

#[allow(clippy::too_many_arguments)]
fn read_back_repository_return<G, C>(
    authority: &ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    result: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactCommandResult,
    expected_lineage: &LineageBinding,
    candidate: &PendingTerminalOutputCandidate,
    expected_artifact_ids: &[String],
    expected_claim_id: &str,
    expected_subject_ids: &[String],
    expected_evidence: &[ExpectedEvidence],
    expected_final_message_id: &str,
    expected_final_message_content: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
    expected_acceptance_ref: &ContractReference,
    expected_claim_statement: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
    expected_workspace_ref: &str,
    expected_source_binding_ref: &str,
    expected_final_message_inputs: &[String],
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let receipt = result
        .return_receipt
        .as_ref()
        .filter(|receipt| {
            receipt.accepted_for_evidence_intake
                && !receipt.verification_performed
                && !receipt.task_completion_decided
                && receipt.lineage.as_ref() == Some(expected_lineage)
        })
        .ok_or(CollectorFailure::Rejected)?;
    let stored_receipt = authority
        .read_return_receipt(&receipt.receipt_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .filter(|stored| stored == receipt)
        .ok_or(CollectorFailure::Rejected)?;
    let handoff = authority
        .read_return_handoff(&stored_receipt.return_handoff_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let artifact_set = authority
        .read_artifact_set(&stored_receipt.artifact_set_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let claim = authority
        .read_claim(expected_claim_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let expected_evidence_ids = expected_evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<Vec<_>>();
    if handoff.status != ReturnHandoffStatus::Receipted as i32
        || handoff.lineage.as_ref() != Some(expected_lineage)
        || handoff.artifact_set_id != artifact_set.artifact_set_id
        || handoff.artifact_set_id != stored_receipt.artifact_set_id
        || handoff.artifact_set_manifest != stored_receipt.artifact_set_manifest
        || handoff.artifact_set_manifest != artifact_set.canonical_manifest
        || handoff.primary_claim_ids.len() != 1
        || handoff.primary_claim_ids[0] != expected_claim_id
        || handoff.evidence_ids != expected_evidence_ids
        || handoff.final_message_artifact_id.as_deref() != Some(expected_final_message_id)
        || handoff.submitted_by.as_ref() != Some(&final_message_producer(config, candidate))
        || !handoff.limitation_artifact_ids.is_empty()
        || !handoff.unknown_artifact_ids.is_empty()
        || artifact_set.status != ArtifactSetStatus::Sealed as i32
        || artifact_set.lineage.as_ref() != Some(expected_lineage)
        || artifact_set.artifact_ids != expected_artifact_ids
        || artifact_set.claim_ids.len() != 1
        || artifact_set.claim_ids[0] != expected_claim_id
        || artifact_set.evidence_ids != expected_evidence_ids
        || claim.status != ClaimStatus::Proposed as i32
        || claim.source_type != ClaimSourceType::CodeChange as i32
        || claim.semantic_profile_ref.as_ref() != Some(&config.claim_semantic_profile_ref)
        || claim.lineage.as_ref() != Some(expected_lineage)
        || claim.subject_artifact_ids != expected_subject_ids
        || claim.acceptance_contract_ref.as_ref() != Some(expected_acceptance_ref)
        || claim.statement.as_ref() != Some(expected_claim_statement)
        || claim.proposer.as_ref() != Some(&final_message_producer(config, candidate))
    {
        return Err(CollectorFailure::Rejected);
    }
    let claim_statement = authority
        .read_blob(expected_claim_statement)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if content_address(&claim_statement) != *expected_claim_statement {
        return Err(CollectorFailure::Rejected);
    }
    let canonical_manifest = canonical_artifact_set_manifest(&artifact_set);
    if artifact_set.canonical_manifest.as_ref() != Some(&content_address(&canonical_manifest)) {
        return Err(CollectorFailure::Rejected);
    }
    for expected in expected_evidence {
        let evidence = authority
            .read_evidence(&expected.evidence_id)
            .map_err(|_| CollectorFailure::Unavailable)?
            .ok_or(CollectorFailure::Rejected)?;
        if evidence.status != EvidenceStatus::Recorded as i32
            || evidence.claim_id != expected_claim_id
            || evidence.lineage.as_ref() != Some(expected_lineage)
            || evidence.integrity_status != IntegrityStatus::DigestVerified as i32
            || evidence.relation != expected.relation as i32
            || evidence.artifact_ids != expected.artifact_ids
            || evidence.producer.as_ref() != Some(&expected.producer)
            || evidence.producer_class != expected.producer_class as i32
            || evidence.independent_of_claim_proposer != expected.independent_of_claim_proposer
            || evidence.coverage_descriptor.as_ref() != Some(&expected.coverage)
            || evidence.limitation_codes != expected.limitation_codes
            || evidence.evidence_profile_ref.as_ref() != Some(&expected.evidence_profile_ref)
        {
            return Err(CollectorFailure::Rejected);
        }
        let coverage = authority
            .read_blob(&expected.coverage)
            .map_err(|_| CollectorFailure::Unavailable)?;
        if content_address(&coverage) != expected.coverage {
            return Err(CollectorFailure::Rejected);
        }
    }
    for artifact_id in expected_artifact_ids {
        let artifact = authority
            .read_artifact(artifact_id)
            .map_err(|_| CollectorFailure::Unavailable)?
            .ok_or(CollectorFailure::Rejected)?;
        if artifact.status != ArtifactStatus::Sealed as i32
            || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
            || artifact
                .provenance
                .as_ref()
                .and_then(|provenance| provenance.lineage.as_ref())
                != Some(expected_lineage)
        {
            return Err(CollectorFailure::Rejected);
        }
    }
    let final_message = read_sealed_artifact(
        authority,
        expected_final_message_id,
        ArtifactSemanticClass::FinalMessage,
        expected_lineage,
        Some(expected_final_message_content),
    )?;
    let final_message_descriptor = authority
        .read_artifact(expected_final_message_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let final_message_provenance = final_message_descriptor
        .provenance
        .as_ref()
        .ok_or(CollectorFailure::Rejected)?;
    if final_message_descriptor.type_contract_ref.as_ref() != Some(&config.artifact_type_ref)
        || final_message_descriptor.retention_profile_ref.as_ref()
            != Some(&config.retention_profile_ref)
        || final_message_descriptor.media_type != candidate.media_type
        || final_message_provenance.producer.as_ref()
            != Some(&final_message_producer(config, candidate))
        || final_message_provenance.input_artifact_ids != expected_final_message_inputs
        || final_message_provenance
            .transformation_contract_ref
            .as_ref()
            != Some(&config.transformation_contract_ref)
        || final_message_provenance.workspace_ref != expected_workspace_ref
        || final_message_provenance.raw_source_ref.as_deref() != Some(expected_source_binding_ref)
    {
        return Err(CollectorFailure::Rejected);
    }
    let bytes = authority
        .read_blob(&final_message.address)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if bytes != candidate.content {
        return Err(CollectorFailure::Rejected);
    }
    Ok(CollectedReturn {
        artifact_id: final_message.artifact_id,
        artifact_digest_sha256: final_message.address.digest,
    })
}

fn final_message_producer(
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
) -> ProducerIdentity {
    producer(config, candidate)
}

fn read_back_collected_return<G, C>(
    authority: &ArtifactAuthority<G, C>,
    result: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactCommandResult,
    expected_lineage: &LineageBinding,
    candidate: &PendingTerminalOutputCandidate,
    expected_artifact_id: &str,
    expected_artifact_digest_sha256: &str,
) -> Result<CollectedReturn, CollectorFailure>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let receipt = result
        .return_receipt
        .as_ref()
        .filter(|receipt| {
            receipt.accepted_for_evidence_intake
                && !receipt.verification_performed
                && !receipt.task_completion_decided
                && receipt.lineage.as_ref() == Some(expected_lineage)
        })
        .ok_or(CollectorFailure::Rejected)?;
    let stored_receipt = authority
        .read_return_receipt(&receipt.receipt_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .filter(|stored| stored == receipt)
        .ok_or(CollectorFailure::Rejected)?;
    let handoff = authority
        .read_return_handoff(&stored_receipt.return_handoff_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let artifact_set = authority
        .read_artifact_set(&stored_receipt.artifact_set_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let final_artifact_id = handoff
        .final_message_artifact_id
        .as_deref()
        .filter(|id| *id == expected_artifact_id)
        .ok_or(CollectorFailure::Rejected)?;
    if handoff.status != ReturnHandoffStatus::Receipted as i32
        || handoff.lineage.as_ref() != Some(expected_lineage)
        || handoff.artifact_set_id != artifact_set.artifact_set_id
        || handoff.artifact_set_id != stored_receipt.artifact_set_id
        || handoff.artifact_set_manifest != stored_receipt.artifact_set_manifest
        || handoff.artifact_set_manifest != artifact_set.canonical_manifest
        || artifact_set.status != ArtifactSetStatus::Sealed as i32
        || artifact_set.lineage.as_ref() != Some(expected_lineage)
        || !artifact_set
            .artifact_ids
            .iter()
            .any(|id| id == final_artifact_id)
    {
        return Err(CollectorFailure::Rejected);
    }
    let artifact = authority
        .read_artifact(final_artifact_id)
        .map_err(|_| CollectorFailure::Unavailable)?
        .ok_or(CollectorFailure::Rejected)?;
    let address = artifact
        .content
        .as_ref()
        .ok_or(CollectorFailure::Rejected)?;
    if artifact.status != ArtifactStatus::Sealed as i32
        || artifact.semantic_class != ArtifactSemanticClass::FinalMessage as i32
        || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
        || artifact
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.lineage.as_ref())
            != Some(expected_lineage)
        || address.digest != expected_artifact_digest_sha256
        || address.digest != candidate.content_digest_sha256
        || address.byte_length != candidate.original_content_bytes
        || address != &content_address(&candidate.content)
    {
        return Err(CollectorFailure::Rejected);
    }
    let bytes = authority
        .read_blob(address)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if bytes != candidate.content || bytes.len() as u64 != candidate.original_content_bytes {
        return Err(CollectorFailure::Rejected);
    }
    Ok(CollectedReturn {
        artifact_id: artifact.artifact_id,
        artifact_digest_sha256: address.digest.clone(),
    })
}

fn execute_committed<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    command: ArtifactCommand,
    principal: &AuthenticatedArtifactPrincipal,
) -> Result<
    egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactCommandResult,
    CollectorFailure,
>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    let result = authority
        .execute(&command, principal)
        .map_err(|_| CollectorFailure::Unavailable)?;
    if result.committed {
        Ok(result)
    } else {
        Err(CollectorFailure::Rejected)
    }
}

fn command(variant: artifact_command::Command) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(variant),
    };
    let digest = canonical_request_digest(&command).expect("Artifact command variant is set");
    let metadata = match command.command.as_mut().expect("Artifact command variant") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_mut(),
        artifact_command::Command::QuarantineObject(_)
        | artifact_command::Command::WithdrawClaim(_)
        | artifact_command::Command::TombstoneObject(_) => None,
    };
    metadata
        .expect("collector command metadata")
        .request_digest_sha256 = digest;
    command
}

fn metadata(candidate: &PendingTerminalOutputCandidate, operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("collector:{operation}:{}", candidate.dispatch_id),
        idempotency_key: format!("{}:{operation}", candidate.message_id),
        idempotency_scope: format!(
            "{}/{}/{}",
            candidate.task_id, candidate.attempt_id, candidate.dispatch_id
        ),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: candidate.dispatch_id.clone(),
        causation_id: Some(candidate.source_observation_id.clone()),
    }
}

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn producer(
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
        principal_id: config.collector_principal_id.clone(),
        component_name: "agentosd-governed-return-collector".to_owned(),
        component_version: env!("CARGO_PKG_VERSION").to_owned(),
        capability_profile_id: None,
        native_execution_ref: Some(candidate.native_completion_ref.clone()),
    }
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::{
        artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle},
        bootstrap::DenyVerificationReferences,
        repository_dispatch::SealedRepositoryDispatchMaterial,
        repository_material::{
            FrozenContractReference, FrozenRepositoryMaterialV1, RepositoryAcceptanceContractV1,
            RepositoryCommandRequirement, RepositoryEvidenceRequirement,
        },
        return_projection::GovernedReturnEvidenceResolver,
    };
    use egopulse_artifact_authority::{
        AdmissionRejection, ArtifactAuthorityConfig, ArtifactSqlCipherKey,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        collaboration::v1::{
            AttemptCancellationDisposition, AttemptCommandBase, AttemptSnapshot,
            CollaborationSnapshot, Lease, RecordAttemptCancellationOutcomeCommand, RunSnapshot,
            StepSnapshot,
        },
        harness::v1::{
            DispatchEnvelope, HarnessObservation, LifecycleKind, LifecycleObservation,
            ObservationCriticality, harness_observation,
        },
    };
    use egopulse_harness_adapter::{AdapterEdgeConfig, AdapterEdgeKey, TerminalOutputCandidate};
    use egopulse_local_ide_control::collaboration_control::{
        HarnessEvidenceResolver, ReferenceGuardRejection,
    };
    use egopulse_verification_authority::{
        VerificationAuthority, VerificationAuthorityConfig, VerificationSqlCipherKey,
    };
    use std::{fs, path::PathBuf};
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl ArtifactClock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp {
                seconds: 1_787_500_000,
                nanos: 0,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct AllowGuard;

    impl ArtifactAdmissionGuard for AllowGuard {
        fn validate_artifact(
            &self,
            _artifact: &ArtifactDescriptor,
            bytes: &[u8],
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            (!bytes.is_empty())
                .then_some(())
                .ok_or(AdmissionRejection::InvalidArgument)
        }

        fn validate_claim(
            &self,
            _claim: &Claim,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_evidence(
            &self,
            _evidence: &Evidence,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_artifact_set(
            &self,
            _artifact_set: &ArtifactSet,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }

        fn validate_return_handoff(
            &self,
            _handoff: &ReturnHandoff,
            _principal: &AuthenticatedArtifactPrincipal,
        ) -> Result<(), AdmissionRejection> {
            Ok(())
        }
    }

    struct NoopHarness;

    impl HarnessDispatchRunner for NoopHarness {
        fn run_once(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<HarnessDispatchCycleReport, HarnessDispatchCycleError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(HarnessDispatchCycleReport::default()) })
        }
    }

    struct Isolated {
        root: PathBuf,
    }

    impl Isolated {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("egopulse-return-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).expect("create return collector test root");
            Self { root }
        }

        fn edge_path(&self) -> PathBuf {
            self.root.join("adapter.sqlcipher")
        }

        fn artifact_path(&self) -> PathBuf {
            self.root.join("artifact.sqlcipher")
        }

        fn blob_root(&self) -> PathBuf {
            self.root.join("blobs")
        }

        fn verification_path(&self) -> PathBuf {
            self.root.join("verification.sqlcipher")
        }
    }

    impl Drop for Isolated {
        fn drop(&mut self) {
            assert!(self.root.starts_with(std::env::temp_dir()));
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove return collector test root");
            }
        }
    }

    fn reference(id: &str, marker: char) -> ContractReference {
        ContractReference {
            contract_id: id.to_owned(),
            version: "v1".to_owned(),
            sha256: marker.to_string().repeat(64),
        }
    }

    fn config() -> GovernedReturnCollectorConfig {
        GovernedReturnCollectorConfig {
            artifact_type_ref: reference("harness-output-type", 'a'),
            transformation_contract_ref: reference("governed-capture", 'b'),
            retention_profile_ref: reference("local-retention", 'c'),
            claim_semantic_profile_ref: reference("capture-claim", 'd'),
            claim_acceptance_contract_ref: reference("capture-acceptance", 'e'),
            evidence_profile_ref: reference("capture-evidence", 'f'),
            workspace_ref: "workspace-001".to_owned(),
            collector_principal_id: "collector:terminal-output".to_owned(),
            artifact_authority_principal_id: "authority:artifact".to_owned(),
        }
    }

    fn envelope() -> DispatchEnvelope {
        DispatchEnvelope {
            run_id: "run-001".to_owned(),
            run_revision: 4,
            step_id: "step-001".to_owned(),
            step_revision: 3,
            attempt_id: "attempt-001".to_owned(),
            attempt_revision: 5,
            dispatch_id: "dispatch-001".to_owned(),
            dispatch_fingerprint: "1".repeat(64),
            input_bundle_sha256: "2".repeat(64),
            workspace_ref: "workspace-001".to_owned(),
            fencing_token: 7,
            ..Default::default()
        }
    }

    fn open_edge(path: PathBuf) -> AdapterEdge {
        AdapterEdge::open(AdapterEdgeConfig {
            database_path: path,
            adapter_id: "codex-adapter".to_owned(),
            store_epoch: "return-collector-test".to_owned(),
            key: AdapterEdgeKey::new([0x44; 32]),
        })
        .expect("open Adapter Edge")
    }

    fn open_authority(isolated: &Isolated) -> ArtifactAuthority<AllowGuard, FixedClock> {
        ArtifactAuthority::open_with_clock(
            ArtifactAuthorityConfig {
                database_path: isolated.artifact_path(),
                blob_root: isolated.blob_root(),
                store_epoch: "return-collector-test".to_owned(),
                key: ArtifactSqlCipherKey::new([0x55; 32]),
            },
            AllowGuard,
            FixedClock,
        )
        .expect("open Artifact Authority")
    }

    fn open_verification(isolated: &Isolated) -> VerificationAuthority {
        VerificationAuthority::open(
            VerificationAuthorityConfig {
                database_path: isolated.verification_path(),
                store_epoch: "return-collector-test".to_owned(),
                key: VerificationSqlCipherKey::new([0x66; 32]),
            },
            DenyVerificationReferences,
        )
        .expect("open empty Verification Authority")
    }

    fn cancellation_snapshot() -> CollaborationSnapshot {
        CollaborationSnapshot {
            run: Some(RunSnapshot {
                run_id: "run-001".to_owned(),
                revision: 4,
                task_id: "task-001".to_owned(),
                task_revision_at_creation: 2,
                work_revision: 1,
                ..Default::default()
            }),
            steps: vec![StepSnapshot {
                step_id: "step-001".to_owned(),
                run_id: "run-001".to_owned(),
                revision: 3,
                ..Default::default()
            }],
            attempts: vec![AttemptSnapshot {
                attempt_id: "attempt-001".to_owned(),
                run_id: "run-001".to_owned(),
                step_id: "step-001".to_owned(),
                revision: 5,
                dispatch_id: Some("dispatch-001".to_owned()),
                lease: Some(Lease {
                    fencing_token: 7,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        }
    }

    fn cancellation_command(receipt_id: &str) -> RecordAttemptCancellationOutcomeCommand {
        RecordAttemptCancellationOutcomeCommand {
            base: Some(AttemptCommandBase {
                run_id: "run-001".to_owned(),
                expected_run_revision: 4,
                step_id: "step-001".to_owned(),
                expected_step_revision: 3,
                attempt_id: "attempt-001".to_owned(),
                expected_attempt_revision: 5,
                ..Default::default()
            }),
            disposition: AttemptCancellationDisposition::ReturnFound as i32,
            cancellation_receipt_id: receipt_id.to_owned(),
        }
    }

    fn collected_return_owners(
        isolated: &Isolated,
    ) -> (
        AdapterEdge,
        ArtifactAuthority<AllowGuard, FixedClock>,
        String,
    ) {
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"governed final answer".to_vec());
        let candidate = edge
            .pending_terminal_output_candidates()
            .expect("pending terminal candidate")
            .into_iter()
            .next()
            .expect("terminal candidate");
        let mut authority = open_authority(isolated);
        collect_one(&mut authority, &config(), &candidate).expect("collect sealed return");
        let messages = authority
            .drain_collaboration_outbox()
            .expect("read technical return receipt");
        assert_eq!(messages.len(), 1);
        let receipt_id = messages[0]
            .result
            .return_receipt
            .as_ref()
            .expect("technical return receipt")
            .receipt_id
            .clone();
        (edge, authority, receipt_id)
    }

    fn persist_candidate(edge: &mut AdapterEdge, content: Vec<u8>) {
        persist_candidate_with_policy(
            edge,
            content,
            FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
        );
    }

    fn persist_candidate_with_policy(
        edge: &mut AdapterEdge,
        content: Vec<u8>,
        policy: FinalArtifactRelationPolicy,
    ) {
        let envelope = envelope();
        edge.prepare_dispatch_with_relation_policy(&envelope, policy, 10)
            .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage(&envelope.dispatch_id, "task-001", 2, 1, 10)
            .expect("bind task lineage");
        edge.append_observation_with_terminal_output(
            &envelope.dispatch_id,
            "native:terminal:001",
            b"terminal-event",
            HarnessObservation {
                attempt_id: envelope.attempt_id.clone(),
                dispatch_id: envelope.dispatch_id.clone(),
                fencing_token: envelope.fencing_token,
                criticality: ObservationCriticality::Terminal as i32,
                payload: Some(harness_observation::Payload::Lifecycle(
                    LifecycleObservation {
                        kind: LifecycleKind::ExecutionCompleted as i32,
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
            Some(&TerminalOutputCandidate {
                dispatch_id: envelope.dispatch_id.clone(),
                native_completion_ref: "codex-turn-001".to_owned(),
                media_type: "text/plain; charset=utf-8".to_owned(),
                content,
            }),
            11,
        )
        .expect("persist terminal candidate");
    }

    fn stage_test_artifact(
        authority: &mut ArtifactAuthority<AllowGuard, FixedClock>,
        candidate: &PendingTerminalOutputCandidate,
        artifact_id: &str,
        semantic_class: ArtifactSemanticClass,
        bytes: &[u8],
        producer_kind: ArtifactPrincipalKind,
        producer_id: &str,
    ) -> egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress {
        let address = content_address(bytes);
        authority.put_blob(bytes, &address).expect("test blob");
        let descriptor = ArtifactDescriptor {
            artifact_id: artifact_id.to_owned(),
            revision: 1,
            status: ArtifactStatus::Staged as i32,
            semantic_class: semantic_class as i32,
            type_contract_ref: Some(reference("repository-artifact", '7')),
            media_type: "application/octet-stream".to_owned(),
            content: Some(address.clone()),
            integrity_status: IntegrityStatus::Unverified as i32,
            provenance: Some(Provenance {
                lineage: Some(lineage(candidate)),
                producer: Some(ProducerIdentity {
                    principal_kind: producer_kind.as_str().to_owned(),
                    principal_id: producer_id.to_owned(),
                    component_name: "repository-return-test".to_owned(),
                    component_version: "v1".to_owned(),
                    capability_profile_id: None,
                    native_execution_ref: None,
                }),
                input_artifact_ids: Vec::new(),
                transformation_contract_ref: Some(reference("repository-capture", '8')),
                workspace_ref: "workspace-001".to_owned(),
                observed_at: None,
                captured_at: None,
                raw_source_ref: Some("repository-test://dispatch-001".to_owned()),
            }),
            sensitivity_class: "local-user-data".to_owned(),
            retention_profile_ref: Some(reference("repository-retention", '9')),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        };
        execute_committed(
            authority,
            command(artifact_command::Command::StageArtifact(
                StageArtifactCommand {
                    metadata: Some(metadata(candidate, &format!("stage-{artifact_id}"))),
                    candidate: Some(descriptor),
                },
            )),
            &principal(producer_kind, producer_id),
        )
        .expect("stage test artifact");
        execute_committed(
            authority,
            command(artifact_command::Command::SealArtifact(
                SealArtifactCommand {
                    metadata: Some(metadata(candidate, &format!("seal-{artifact_id}"))),
                    artifact_id: artifact_id.to_owned(),
                    expected_revision: 1,
                    observed_content: Some(address.clone()),
                },
            )),
            &principal(
                ArtifactPrincipalKind::ArtifactAuthority,
                "authority:artifact",
            ),
        )
        .expect("seal test artifact");
        address
    }

    fn test_repository_command() -> RepositoryAcceptanceCommandV1 {
        RepositoryAcceptanceCommandV1 {
            command_id: "tests".to_owned(),
            criterion_id: "tests-pass".to_owned(),
            requirement: RepositoryCommandRequirement::MustPass,
            executable: "fixture-command".to_owned(),
            argv: vec!["--safe".to_owned()],
            cwd: ".".to_owned(),
            inherited_environment: Vec::new(),
            environment_overrides: BTreeMap::new(),
            timeout_seconds: 5,
            output_limit_bytes: 1024,
            expected_exit_code: 0,
        }
    }

    fn captured_repository_return(
        isolated: &Isolated,
        authority: &mut ArtifactAuthority<AllowGuard, FixedClock>,
        candidate: &PendingTerminalOutputCandidate,
    ) -> (CapturedRepositoryReturn, Vec<CompletedRepositoryCommand>) {
        let command = test_repository_command();
        let acceptance = reference("repository-acceptance", '6');
        let frozen = FrozenRepositoryMaterialV1 {
            schema_version: "egopulse.repository-material/v1".to_owned(),
            contract_path: isolated.root.join("acceptance.json").display().to_string(),
            repository_root: isolated.root.display().to_string(),
            git_executable: isolated.root.join("git.exe").display().to_string(),
            acceptance_contract_ref: FrozenContractReference {
                contract_id: acceptance.contract_id,
                version: acceptance.version,
                sha256: acceptance.sha256,
            },
            acceptance_contract: RepositoryAcceptanceContractV1 {
                schema_version: "repository_change_acceptance/v1".to_owned(),
                contract_id: "repository-acceptance".to_owned(),
                version: "v1".to_owned(),
                revision: 1,
                allowed_paths: vec!["src".to_owned()],
                forbidden_paths: Vec::new(),
                read_only_paths: Vec::new(),
                required_commands: vec![command.clone()],
                evidence_requirements: vec![
                    RepositoryEvidenceRequirement::RepositoryBaseline,
                    RepositoryEvidenceRequirement::RepositoryPatch,
                    RepositoryEvidenceRequirement::WorkspaceManifest,
                    RepositoryEvidenceRequirement::CommandReceipt,
                    RepositoryEvidenceRequirement::IndependentChecker,
                ],
            },
            baseline_commit: "a".repeat(40),
            baseline_tree: "b".repeat(40),
            git_common_dir: isolated.root.join("git-common").display().to_string(),
            clean_worktree: true,
        };
        let lineage = lineage(candidate);
        let baseline_id = "artifact:repository-baseline:dispatch-001".to_owned();
        let initial_id = "artifact:workspace-initial:dispatch-001".to_owned();
        let patch_id = "artifact:repository-patch:dispatch-001".to_owned();
        let final_manifest_id = "artifact:workspace-final:dispatch-001".to_owned();
        stage_test_artifact(
            authority,
            candidate,
            &baseline_id,
            ArtifactSemanticClass::RepositoryBaseline,
            b"baseline",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        stage_test_artifact(
            authority,
            candidate,
            &initial_id,
            ArtifactSemanticClass::WorkspaceManifest,
            b"initial",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        let patch_content = stage_test_artifact(
            authority,
            candidate,
            &patch_id,
            ArtifactSemanticClass::RepositoryPatch,
            b"diff --git a/src/lib.rs b/src/lib.rs",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        let final_manifest_content = stage_test_artifact(
            authority,
            candidate,
            &final_manifest_id,
            ArtifactSemanticClass::WorkspaceManifest,
            b"final manifest",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        let receipt_id = "artifact:repository-command-receipt:dispatch-001:tests".to_owned();
        stage_test_artifact(
            authority,
            candidate,
            &receipt_id,
            ArtifactSemanticClass::CommandReceipt,
            b"receipt",
            ArtifactPrincipalKind::SupervisedRunner,
            "runner:repository-command",
        );
        let admission = DerivedWorkspaceAdmissionHandle::default();
        let admission_lease = admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: "workspace-001".to_owned(),
                lineage: lineage.clone(),
                source_binding_ref: "repository-test://dispatch-001".to_owned(),
            })
            .expect("admission lease");
        let sealed_dispatch = SealedRepositoryDispatchMaterial {
            frozen_material: frozen.clone(),
            workspace_ref: "workspace-001".to_owned(),
            baseline_commit: frozen.baseline_commit.clone(),
            baseline_tree: frozen.baseline_tree.clone(),
            baseline_artifact_id: baseline_id,
            initial_manifest_artifact_id: initial_id,
            lineage,
            source_binding_ref: "repository-test://dispatch-001".to_owned(),
        };
        (
            CapturedRepositoryReturn {
                frozen_material: frozen,
                workspace_root: isolated.root.clone(),
                sealed_dispatch,
                patch_artifact_id: patch_id,
                patch_content,
                final_manifest_artifact_id: final_manifest_id,
                final_manifest_content,
                evidence_profile_ref: reference("repository-evidence", '5'),
                admission_lease,
            },
            vec![CompletedRepositoryCommand {
                command,
                receipt: RepositoryCommandReceipt {
                    artifact_id: receipt_id,
                    intent_artifact_id: "artifact:command-intent:tests".to_owned(),
                    exit_code: Some(0),
                    supervision_failure: None,
                    stdout: b"passed".to_vec(),
                    stderr: Vec::new(),
                    duration_ms: 5,
                },
            }],
        )
    }

    #[test]
    fn cancellation_return_found_resolves_sealed_receipt_before_and_after_reopen() {
        let isolated = Isolated::new();
        let (edge, authority, receipt_id) = collected_return_owners(&isolated);
        let command = cancellation_command(&receipt_id);
        let snapshot = cancellation_snapshot();
        let resolver = GovernedReturnEvidenceResolver::new(
            edge,
            Arc::new(Mutex::new(authority)),
            Arc::new(Mutex::new(open_verification(&isolated))),
        );

        let resolved = resolver
            .resolve_cancellation_return(&command, &snapshot)
            .expect("sealed technical return resolves cancellation");
        assert_eq!(
            resolved.artifact_set_id,
            "artifact-set:harness-return:dispatch-001"
        );
        assert_eq!(
            resolved.return_handoff_id,
            "return-handoff:harness:dispatch-001"
        );
        assert_eq!(resolved.dispatch_id, "dispatch-001");
        assert!(
            resolved
                .evidence_refs
                .iter()
                .any(|value| { value == &format!("artifact-return-receipt:{receipt_id}@durable") })
        );
        drop(resolver);

        let reopened = GovernedReturnEvidenceResolver::new(
            open_edge(isolated.edge_path()),
            Arc::new(Mutex::new(open_authority(&isolated))),
            Arc::new(Mutex::new(open_verification(&isolated))),
        );
        assert_eq!(
            reopened
                .resolve_cancellation_return(&command, &snapshot)
                .expect("same durable proof resolves after SQLCipher reopen"),
            resolved
        );
    }

    #[test]
    fn cancellation_return_rejects_cross_owner_binding_and_wrong_receipt() {
        let isolated = Isolated::new();
        let (edge, authority, receipt_id) = collected_return_owners(&isolated);
        let resolver = GovernedReturnEvidenceResolver::new(
            edge,
            Arc::new(Mutex::new(authority)),
            Arc::new(Mutex::new(open_verification(&isolated))),
        );
        let command = cancellation_command(&receipt_id);
        let snapshot = cancellation_snapshot();

        let mut wrong_task = snapshot.clone();
        wrong_task.run.as_mut().expect("run").task_id = "task-other".to_owned();
        assert_eq!(
            resolver.resolve_cancellation_return(&command, &wrong_task),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );

        let mut wrong_run = command.clone();
        wrong_run.base.as_mut().expect("base").run_id = "run-other".to_owned();
        assert_eq!(
            resolver.resolve_cancellation_return(&wrong_run, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );

        let mut wrong_attempt = command.clone();
        wrong_attempt.base.as_mut().expect("base").attempt_id = "attempt-other".to_owned();
        assert_eq!(
            resolver.resolve_cancellation_return(&wrong_attempt, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );

        let mut wrong_fence = snapshot.clone();
        wrong_fence.attempts[0]
            .lease
            .as_mut()
            .expect("lease")
            .fencing_token = 8;
        assert_eq!(
            resolver.resolve_cancellation_return(&command, &wrong_fence),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );

        let wrong_receipt = cancellation_command("return-handoff:harness:dispatch-001");
        assert_eq!(
            resolver.resolve_cancellation_return(&wrong_receipt, &snapshot),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
    }

    #[test]
    fn execution_completed_without_artifact_receipt_cannot_be_return_found() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"terminal output without receipt".to_vec());
        let resolver = GovernedReturnEvidenceResolver::new(
            edge,
            Arc::new(Mutex::new(open_authority(&isolated))),
            Arc::new(Mutex::new(open_verification(&isolated))),
        );

        assert_eq!(
            resolver.resolve_cancellation_return(
                &cancellation_command("missing-artifact-return-receipt"),
                &cancellation_snapshot(),
            ),
            Err(ReferenceGuardRejection::UnverifiedReference)
        );
    }

    #[tokio::test]
    async fn collector_issues_only_technical_return_receipt_and_settles_edge() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"governed final answer".to_vec());
        let authority = Arc::new(Mutex::new(open_authority(&isolated)));
        let runner = GovernedReturnCollectorRunner::new(
            Arc::new(NoopHarness),
            edge,
            Arc::clone(&authority),
            config(),
        )
        .expect("compose collector");

        let report = runner.run_once().await.expect("collect output");
        assert_eq!(report.terminal_output_candidates_seen, 1);
        assert_eq!(report.terminal_output_candidates_receipted, 1);
        assert_eq!(report.terminal_output_candidates_held, 0);
        let inspection = authority
            .lock()
            .expect("authority lock")
            .inspect_store()
            .expect("inspect authority");
        assert_eq!(inspection.artifact_count, 1);
        assert_eq!(inspection.claim_count, 1);
        assert_eq!(inspection.evidence_count, 1);
        assert_eq!(inspection.artifact_set_count, 1);
        assert_eq!(inspection.return_handoff_count, 1);
        assert_eq!(inspection.return_receipt_count, 1);
        let reader = open_edge(isolated.edge_path());
        assert!(
            reader
                .pending_terminal_output_candidates()
                .expect("read settled outbox")
                .is_empty()
        );

        let replay = runner.run_once().await.expect("collector replay");
        assert_eq!(replay.terminal_output_candidates_seen, 0);
        assert_eq!(
            authority
                .lock()
                .expect("authority lock")
                .inspect_store()
                .expect("inspect replay")
                .return_receipt_count,
            1
        );
    }

    #[tokio::test]
    async fn missing_repository_provider_holds_when_dispatch_has_sealed_repository_artifacts() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"repository work completed".to_vec());
        let candidate = edge
            .pending_terminal_output_candidates()
            .expect("pending candidate")
            .into_iter()
            .next()
            .expect("candidate");
        let mut authority = open_authority(&isolated);
        stage_test_artifact(
            &mut authority,
            &candidate,
            "artifact:repository-baseline:dispatch-001",
            ArtifactSemanticClass::RepositoryBaseline,
            b"baseline",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        stage_test_artifact(
            &mut authority,
            &candidate,
            "artifact:workspace-initial:dispatch-001",
            ArtifactSemanticClass::WorkspaceManifest,
            b"initial",
            ArtifactPrincipalKind::AttemptSupervisor,
            "supervisor:attempt",
        );
        let authority = Arc::new(Mutex::new(authority));
        let runner = GovernedReturnCollectorRunner::new(
            Arc::new(NoopHarness),
            edge,
            Arc::clone(&authority),
            config(),
        )
        .expect("compose collector without repository provider");

        let report = runner
            .run_once()
            .await
            .expect("hold stale repository return");
        assert_eq!(report.terminal_output_candidates_seen, 1);
        assert_eq!(report.terminal_output_candidates_receipted, 0);
        assert_eq!(report.terminal_output_candidates_held, 1);
        assert_eq!(
            authority
                .lock()
                .expect("authority lock")
                .inspect_store()
                .expect("inspect authority")
                .artifact_count,
            2
        );
        let reader = open_edge(isolated.edge_path());
        assert!(
            reader
                .pending_terminal_output_candidates()
                .expect("held candidate")
                .is_empty()
        );
        assert!(
            reader
                .pending_final_artifact_relation_intent()
                .expect("relation intent")
                .is_none()
        );
    }

    #[tokio::test]
    async fn required_relation_intent_is_durable_without_blocking_technical_ack() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate_with_policy(
            &mut edge,
            b"governed final answer".to_vec(),
            FinalArtifactRelationPolicy::RequiredGovernedContent,
        );
        let authority = Arc::new(Mutex::new(open_authority(&isolated)));
        let runner = GovernedReturnCollectorRunner::new(
            Arc::new(NoopHarness),
            edge,
            Arc::clone(&authority),
            config(),
        )
        .expect("compose collector");

        let report = runner.run_once().await.expect("collect technical return");
        assert_eq!(report.terminal_output_candidates_seen, 1);
        assert_eq!(report.terminal_output_candidates_receipted, 1);
        assert_eq!(report.terminal_output_candidates_held, 0);
        let reader = open_edge(isolated.edge_path());
        assert!(
            reader
                .pending_terminal_output_candidates()
                .expect("technical return ACK")
                .is_empty()
        );
        assert!(
            reader
                .pending_final_artifact_relation_intent()
                .expect("durable relation intent")
                .is_some()
        );
        assert_eq!(
            authority
                .lock()
                .expect("authority lock")
                .inspect_store()
                .expect("inspect authority")
                .return_receipt_count,
            1
        );
    }

    #[test]
    fn command_unknown_maps_to_durable_terminal_candidate_hold_without_native_unknown() {
        assert_eq!(
            classify_command_blocked(RepositoryCommandBlockedReason::ExistingIntentWithoutReceipt),
            CollectorFailure::Rejected
        );
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"repository work completed".to_vec());
        let candidate = edge
            .pending_terminal_output_candidates()
            .expect("pending candidate")
            .into_iter()
            .next()
            .expect("candidate");
        assert!(
            edge.hold_terminal_output_candidate(
                &candidate.message_id,
                &candidate.payload_digest_sha256
            )
            .expect("persist held state")
        );
        drop(edge);

        let reopened = open_edge(isolated.edge_path());
        let inspection = reopened.inspect().expect("inspect reopened Edge");
        assert_eq!(inspection.terminal_output_outbox_count, 1);
        assert_eq!(inspection.pending_terminal_output_count, 0);
        assert!(
            reopened
                .pending_terminal_output_candidates()
                .expect("held candidates are not retryable")
                .is_empty()
        );
    }

    #[test]
    fn command_evidence_preserves_nonzero_and_supervision_failure_as_refuting_results() {
        let mut expected = test_repository_command();
        expected.expected_exit_code = 0;
        let nonzero = RepositoryCommandReceipt {
            artifact_id: "artifact:receipt:nonzero".to_owned(),
            intent_artifact_id: "artifact:intent:nonzero".to_owned(),
            exit_code: Some(7),
            supervision_failure: None,
            stdout: b"bounded stdout".to_vec(),
            stderr: b"bounded stderr".to_vec(),
            duration_ms: 4,
        };
        assert_eq!(
            command_evidence_disposition(&expected, &nonzero),
            (
                EvidenceRelation::Refutes,
                vec!["COMMAND_EXIT_CODE_MISMATCH".to_owned()]
            )
        );

        let failed = RepositoryCommandReceipt {
            artifact_id: "artifact:receipt:supervision".to_owned(),
            intent_artifact_id: "artifact:intent:supervision".to_owned(),
            exit_code: None,
            supervision_failure: Some(
                crate::repository_command::RepositoryCommandSupervisionFailure::Timeout,
            ),
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration_ms: 5,
        };
        assert_eq!(
            command_evidence_disposition(&expected, &failed),
            (
                EvidenceRelation::Refutes,
                vec!["COMMAND_SUPERVISION_FAILURE".to_owned()]
            )
        );
    }

    #[test]
    fn evidence_principal_rejects_kind_class_mismatch_and_independent_proposer_reuse() {
        let proposer = ProducerIdentity {
            principal_kind: "governed_collector".to_owned(),
            principal_id: "collector:terminal-output".to_owned(),
            component_name: "collector".to_owned(),
            component_version: "v1".to_owned(),
            capability_profile_id: None,
            native_execution_ref: None,
        };
        let mut planned = PlannedEvidence {
            evidence_id: "evidence:test".to_owned(),
            relation: EvidenceRelation::Context,
            artifact_ids: vec!["artifact:test".to_owned()],
            producer: ProducerIdentity {
                principal_kind: "supervised_runner".to_owned(),
                principal_id: "runner:test".to_owned(),
                component_name: "runner".to_owned(),
                component_version: "v1".to_owned(),
                capability_profile_id: None,
                native_execution_ref: None,
            },
            producer_class: EvidenceProducerClass::AttemptSupervisor,
            independent_of_claim_proposer: true,
            coverage: b"coverage".to_vec(),
            limitation_codes: Vec::new(),
            evidence_profile_ref: reference("evidence", '1'),
        };
        assert!(evidence_principal(&planned, &proposer).is_err());

        planned.producer_class = EvidenceProducerClass::SupervisedRunner;
        planned.producer.principal_id = proposer.principal_id.clone();
        assert!(evidence_principal(&planned, &proposer).is_err());
    }

    #[test]
    fn repository_return_uses_one_claim_set_handoff_and_typed_evidence() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, b"repository work completed".to_vec());
        let candidate = edge
            .pending_terminal_output_candidates()
            .expect("pending candidate")
            .into_iter()
            .next()
            .expect("candidate");
        let mut authority = open_authority(&isolated);
        let (captured, commands) =
            captured_repository_return(&isolated, &mut authority, &candidate);

        let collected =
            collect_repository_one(&mut authority, &config(), &candidate, &captured, &commands)
                .expect("collect repository graph");
        assert_eq!(
            collected.artifact_id,
            "artifact:harness-output:dispatch-001"
        );
        let inspection = authority.inspect_store().expect("inspect graph");
        assert_eq!(inspection.artifact_count, 6);
        assert_eq!(inspection.claim_count, 1);
        assert_eq!(inspection.evidence_count, 3);
        assert_eq!(inspection.artifact_set_count, 1);
        assert_eq!(inspection.return_handoff_count, 1);
        assert_eq!(inspection.return_receipt_count, 1);

        let set = authority
            .read_artifact_set("artifact-set:harness-return:dispatch-001")
            .expect("read set")
            .expect("set");
        assert_eq!(
            set.artifact_ids,
            vec![
                "artifact:repository-baseline:dispatch-001",
                "artifact:workspace-initial:dispatch-001",
                "artifact:repository-patch:dispatch-001",
                "artifact:workspace-final:dispatch-001",
                "artifact:repository-command-receipt:dispatch-001:tests",
                "artifact:harness-output:dispatch-001",
            ]
        );
        let claim = authority
            .read_claim("claim:repository-return:dispatch-001")
            .expect("read claim")
            .expect("claim");
        assert_eq!(claim.source_type, ClaimSourceType::CodeChange as i32);
        assert_eq!(
            claim.subject_artifact_ids,
            vec![
                "artifact:repository-patch:dispatch-001",
                "artifact:workspace-final:dispatch-001",
                "artifact:harness-output:dispatch-001",
            ]
        );
        assert_eq!(
            claim.acceptance_contract_ref,
            Some(reference("repository-acceptance", '6'))
        );
        let capture = authority
            .read_evidence("evidence:repository-capture:dispatch-001")
            .expect("read capture evidence")
            .expect("capture evidence");
        assert_eq!(
            capture
                .producer
                .as_ref()
                .map(|producer| producer.principal_kind.as_str()),
            Some("attempt_supervisor")
        );
        assert_eq!(
            capture
                .producer
                .as_ref()
                .map(|producer| producer.principal_id.as_str()),
            Some("supervisor:attempt")
        );
        assert_eq!(
            capture.producer_class,
            EvidenceProducerClass::AttemptSupervisor as i32
        );
        assert!(capture.independent_of_claim_proposer);

        let command_evidence = authority
            .read_evidence("evidence:repository-command:dispatch-001:0")
            .expect("read command evidence")
            .expect("command evidence");
        assert_eq!(
            command_evidence
                .producer
                .as_ref()
                .map(|producer| producer.principal_kind.as_str()),
            Some("supervised_runner")
        );
        assert_eq!(
            command_evidence
                .producer
                .as_ref()
                .map(|producer| producer.principal_id.as_str()),
            Some("runner:repository-command")
        );
        assert_eq!(
            command_evidence.producer_class,
            EvidenceProducerClass::SupervisedRunner as i32
        );
        assert!(command_evidence.independent_of_claim_proposer);

        let final_message_evidence = authority
            .read_evidence("evidence:collector-capture:dispatch-001")
            .expect("read final message evidence")
            .expect("final message evidence");
        assert_eq!(
            final_message_evidence
                .producer
                .as_ref()
                .map(|producer| producer.principal_kind.as_str()),
            Some("governed_collector")
        );
        assert_eq!(
            final_message_evidence.producer_class,
            EvidenceProducerClass::GovernedCollector as i32
        );
        assert!(!final_message_evidence.independent_of_claim_proposer);
    }

    #[tokio::test]
    async fn incomplete_or_empty_output_is_held_without_fabricating_artifacts() {
        let isolated = Isolated::new();
        let mut edge = open_edge(isolated.edge_path());
        persist_candidate(&mut edge, Vec::new());
        let authority = Arc::new(Mutex::new(open_authority(&isolated)));
        let runner = GovernedReturnCollectorRunner::new(
            Arc::new(NoopHarness),
            edge,
            Arc::clone(&authority),
            config(),
        )
        .expect("compose collector");
        let report = runner.run_once().await.expect("hold empty output");
        assert_eq!(report.terminal_output_candidates_seen, 1);
        assert_eq!(report.terminal_output_candidates_receipted, 0);
        assert_eq!(report.terminal_output_candidates_held, 1);
        let inspection = authority
            .lock()
            .expect("authority lock")
            .inspect_store()
            .expect("inspect empty authority");
        assert_eq!(inspection.artifact_count, 0);
        assert_eq!(inspection.return_receipt_count, 0);
    }

    #[test]
    fn governed_collector_claim_source_replays_without_duplicate_authority_objects() {
        let isolated = Isolated::new();
        let mut authority = open_authority(&isolated);
        let candidate = PendingTerminalOutputCandidate {
            message_id: "message-001".to_owned(),
            source_observation_id: "observation-001".to_owned(),
            source_revision: 1,
            payload_digest_sha256: "1".repeat(64),
            run_id: "run-001".to_owned(),
            task_id: "task-001".to_owned(),
            task_revision: 2,
            work_revision: 1,
            run_revision: 4,
            step_id: "step-001".to_owned(),
            step_revision: 3,
            attempt_id: "attempt-001".to_owned(),
            attempt_revision: 5,
            dispatch_id: "dispatch-001".to_owned(),
            fencing_token: 7,
            native_completion_ref: "codex-turn-001".to_owned(),
            media_type: "text/plain".to_owned(),
            content_digest_sha256: content_address(b"answer").digest,
            original_content_bytes: 6,
            content: b"answer".to_vec(),
            content_complete: true,
        };
        collect_one(&mut authority, &config(), &candidate).expect("first collection");
        collect_one(&mut authority, &config(), &candidate).expect("idempotent replay");
        let inspection = authority.inspect_store().expect("inspect replay");
        assert_eq!(inspection.return_receipt_count, 1);
        assert_eq!(inspection.idempotency_count, 7);
    }
}
