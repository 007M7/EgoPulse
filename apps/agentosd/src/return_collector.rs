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
};
use egopulse_harness_adapter::{AdapterEdge, PendingTerminalOutputCandidate};
use egopulse_local_ide_control::collaboration_control::{
    HarnessDispatchCycleError, HarnessDispatchCycleReport, HarnessDispatchRunner,
};
use prost_types::Timestamp;

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
}

impl<G, C> GovernedReturnCollectorRunner<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
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
        })
    }

    fn collect_pending(
        &self,
        report: &mut HarnessDispatchCycleReport,
    ) -> Result<(), HarnessDispatchCycleError> {
        let mut edge = self.edge.lock().map_err(|_| {
            HarnessDispatchCycleError::ReturnCollector("adapter edge lock poisoned".to_owned())
        })?;
        let pending = edge.pending_terminal_output_candidates().map_err(|_| {
            HarnessDispatchCycleError::ReturnCollector(
                "terminal output outbox unavailable or corrupt".to_owned(),
            )
        })?;
        report.terminal_output_candidates_seen += pending.len() as u64;
        for candidate in pending {
            if !candidate.content_complete || candidate.content.is_empty() {
                let held = edge
                    .hold_terminal_output_candidate(
                        &candidate.message_id,
                        &candidate.payload_digest_sha256,
                    )
                    .map_err(|_| {
                        HarnessDispatchCycleError::ReturnCollector(
                            "terminal output hold failed".to_owned(),
                        )
                    })?;
                if !held {
                    return Err(HarnessDispatchCycleError::ReturnCollector(
                        "terminal output hold was not persisted".to_owned(),
                    ));
                }
                report.terminal_output_candidates_held += 1;
                continue;
            }
            let mut authority = self.authority.lock().map_err(|_| {
                HarnessDispatchCycleError::ReturnCollector(
                    "Artifact Authority lock poisoned".to_owned(),
                )
            })?;
            match collect_one(&mut authority, &self.config, &candidate) {
                Ok(()) => {
                    let acknowledged = edge
                        .acknowledge_terminal_output_candidate(
                            &candidate.message_id,
                            &candidate.payload_digest_sha256,
                        )
                        .map_err(|_| {
                            HarnessDispatchCycleError::ReturnCollector(
                                "terminal output acknowledgement failed".to_owned(),
                            )
                        })?;
                    if !acknowledged {
                        return Err(HarnessDispatchCycleError::ReturnCollector(
                            "terminal output acknowledgement was not persisted".to_owned(),
                        ));
                    }
                    report.terminal_output_candidates_receipted += 1;
                }
                Err(CollectorFailure::Rejected) => {
                    let held = edge
                        .hold_terminal_output_candidate(
                            &candidate.message_id,
                            &candidate.payload_digest_sha256,
                        )
                        .map_err(|_| {
                            HarnessDispatchCycleError::ReturnCollector(
                                "rejected terminal output hold failed".to_owned(),
                            )
                        })?;
                    if !held {
                        return Err(HarnessDispatchCycleError::ReturnCollector(
                            "rejected terminal output hold was not persisted".to_owned(),
                        ));
                    }
                    report.terminal_output_candidates_held += 1;
                }
                Err(CollectorFailure::Unavailable) => {
                    return Err(HarnessDispatchCycleError::ReturnCollector(
                        "Artifact Authority unavailable".to_owned(),
                    ));
                }
            }
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
            self.collect_pending(&mut report)?;
            Ok(report)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CollectorFailure {
    Rejected,
    Unavailable,
}

fn collect_one<G, C>(
    authority: &mut ArtifactAuthority<G, C>,
    config: &GovernedReturnCollectorConfig,
    candidate: &PendingTerminalOutputCandidate,
) -> Result<(), CollectorFailure>
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

    let output_address = content_address(&candidate.content);
    authority
        .put_blob(&candidate.content, &output_address)
        .map_err(|_| CollectorFailure::Unavailable)?;
    let artifact = ArtifactDescriptor {
        artifact_id: artifact_id.clone(),
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
            input_artifact_ids: Vec::new(),
            transformation_contract_ref: Some(config.transformation_contract_ref.clone()),
            workspace_ref: config.workspace_ref.clone(),
            observed_at: None,
            captured_at: None,
            raw_source_ref: Some(format!(
                "adapter-terminal-output://{}",
                candidate.source_observation_id
            )),
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
        &collector,
    )?;
    execute_committed(
        authority,
        command(artifact_command::Command::SealArtifact(
            SealArtifactCommand {
                metadata: Some(metadata(candidate, "seal-artifact")),
                artifact_id: artifact_id.clone(),
                expected_revision: 1,
                observed_content: Some(output_address),
            },
        )),
        &authority_principal,
    )?;

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
                    statement: Some(statement),
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
                    lineage: Some(lineage),
                    artifact_set_id: set_id,
                    artifact_set_manifest: Some(manifest),
                    primary_claim_ids: vec![claim_id],
                    evidence_ids: vec![evidence_id],
                    limitation_artifact_ids: Vec::new(),
                    unknown_artifact_ids: Vec::new(),
                    final_message_artifact_id: Some(artifact_id),
                    submitted_by: Some(producer),
                    submitted_at: None,
                    supersedes_return_handoff_id: None,
                }),
                expected_artifact_set_revision: 2,
            },
        )),
        &collector,
    )?;
    if result.return_receipt.as_ref().is_none_or(|receipt| {
        !receipt.accepted_for_evidence_intake
            || receipt.verification_performed
            || receipt.task_completion_decided
    }) {
        return Err(CollectorFailure::Rejected);
    }
    Ok(())
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
    use egopulse_artifact_authority::{
        AdmissionRejection, ArtifactAuthorityConfig, ArtifactSqlCipherKey,
    };
    use egopulse_domain_contracts::v01::egopulse::harness::v1::{
        DispatchEnvelope, HarnessObservation, LifecycleKind, LifecycleObservation,
        ObservationCriticality, harness_observation,
    };
    use egopulse_harness_adapter::{AdapterEdgeConfig, AdapterEdgeKey, TerminalOutputCandidate};
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

    fn persist_candidate(edge: &mut AdapterEdge, content: Vec<u8>) {
        let envelope = envelope();
        edge.prepare_dispatch(&envelope, 10)
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
