use egopulse_agentosd::GovernedReturnEvidenceResolver;
use egopulse_artifact_authority::{
    AdmissionRejection, ArtifactAdmissionGuard, ArtifactAuthority, ArtifactAuthorityConfig,
    ArtifactClock, ArtifactPrincipalKind, ArtifactSqlCipherKey, AuthenticatedArtifactPrincipal,
    canonical_artifact_set_manifest, canonical_request_digest, content_address,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus,
        ArtifactStatus, Claim, ClaimSourceType, ClaimStatus, ContentAddress, Evidence,
        EvidenceProducerClass, EvidenceRelation, EvidenceStatus, IntegrityStatus, LineageBinding,
        ProducerIdentity, Provenance, ReturnHandoff, ReturnHandoffStatus, SealArtifactCommand,
        SealArtifactSetCommand, StageArtifactCommand, SubmitReturnHandoffCommand, artifact_command,
    },
    collaboration::v1::{
        AttemptSnapshot, CollaborationSnapshot, CommitStepReturnCommand, RunCommandBase,
        RunSnapshot, StepSnapshot,
    },
    common::v1::CommandMetadata,
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
        CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
        CriterionRequirement, CriterionResult, EvidenceCoverage, RecordCriterionResultCommand,
        StartVerificationRunCommand, VerificationArtifact, VerificationBinding,
        VerificationCommand, VerificationConclusion, VerificationProvenance, VerificationRequest,
        VerificationStatus, verification_command,
    },
};
use egopulse_harness_adapter::{AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey};
use egopulse_local_ide_control::collaboration_control::HarnessEvidenceResolver;
use egopulse_verification_authority::{
    AuthenticatedVerificationPrincipal, CriterionPolicySnapshot, ReferenceRejection,
    ResolvedVerificationInput, VerificationAuthority, VerificationAuthorityConfig,
    VerificationPrincipalKind, VerificationReferenceResolver, VerificationSqlCipherKey,
    canonical_checker_profile_digest,
    canonical_request_digest as canonical_verification_request_digest,
};
use prost_types::Timestamp;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const FIXED_TIME: i64 = 1_777_073_600;
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Clone, Copy)]
struct FixedArtifactClock;

impl ArtifactClock for FixedArtifactClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct AllowArtifactAdmission;

impl ArtifactAdmissionGuard for AllowArtifactAdmission {
    fn validate_artifact(
        &self,
        _artifact: &ArtifactDescriptor,
        _bytes: &[u8],
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        Ok(())
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

#[derive(Clone)]
struct VerificationFixtureResolver {
    binding: VerificationBinding,
    criteria: Vec<CriterionPolicySnapshot>,
    evidence_ids: BTreeSet<String>,
    artifact_ids: BTreeSet<String>,
}

impl VerificationReferenceResolver for VerificationFixtureResolver {
    fn validate_checker_profile(&self, profile: &CheckerProfile) -> Result<(), ReferenceRejection> {
        profile
            .attestation_evidence_artifact_ids
            .iter()
            .all(|id| self.evidence_ids.contains(id))
            .then_some(())
            .ok_or(ReferenceRejection::EvidenceIncomplete)
    }

    fn resolve_request(
        &self,
        request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection> {
        if request.binding.as_ref() != Some(&self.binding) {
            return Err(ReferenceRejection::BindingStale);
        }
        Ok(ResolvedVerificationInput {
            artifact_set_status:
                egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactSetStatus::Sealed,
            binding: self.binding.clone(),
            criteria: self.criteria.clone(),
            evidence_ids: self.evidence_ids.clone(),
        })
    }

    fn revalidate_binding(&self, binding: &VerificationBinding) -> Result<(), ReferenceRejection> {
        (binding == &self.binding)
            .then_some(())
            .ok_or(ReferenceRejection::BindingStale)
    }

    fn validate_result_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection> {
        if evidence_ids.iter().all(|id| self.evidence_ids.contains(id))
            && artifact_ids.iter().all(|id| self.artifact_ids.contains(id))
        {
            Ok(())
        } else {
            Err(ReferenceRejection::EvidenceIncomplete)
        }
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("egopulse-g4-11-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create G4-11 fixture root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if self
            .0
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("egopulse-g4-11-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

fn timestamp() -> Timestamp {
    Timestamp {
        seconds: FIXED_TIME,
        nanos: 0,
    }
}

fn lineage() -> LineageBinding {
    LineageBinding {
        task_id: "task-g4-11".to_owned(),
        task_revision: 2,
        work_revision: 1,
        run_id: "run-g4-11".to_owned(),
        run_revision: 5,
        step_id: "step-g4-11".to_owned(),
        step_revision: 4,
        attempt_id: "attempt-g4-11".to_owned(),
        attempt_revision: 3,
        dispatch_id: "dispatch-g4-11".to_owned(),
        fencing_token: 1,
    }
}

fn contract_ref(
    id: &str,
    sha256: &str,
) -> egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
    egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference {
        contract_id: id.to_owned(),
        version: "1".to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn producer(kind: ArtifactPrincipalKind, id: &str) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: kind.as_str().to_owned(),
        principal_id: id.to_owned(),
        component_name: "g4-11-fixture".to_owned(),
        component_version: "0.1.0".to_owned(),
        capability_profile_id: Some("v01-single-harness".to_owned()),
        native_execution_ref: None,
    }
}

fn artifact_principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn artifact_metadata(operation: &str, key: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("g4-11-{operation}-{key}"),
        idempotency_key: key.to_owned(),
        idempotency_scope: "g4-11".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(timestamp()),
        correlation_id: "g4-11-correlation".to_owned(),
        causation_id: None,
    }
}

fn set_artifact_digest(command: &mut ArtifactCommand) {
    let digest = canonical_request_digest(command).expect("Artifact command canonical digest");
    let metadata = match command.command.as_mut().expect("Artifact command") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_mut(),
        _ => None,
    }
    .expect("Artifact metadata");
    metadata.request_digest_sha256 = digest;
}

fn artifact_candidate(
    id: &str,
    semantic_class: ArtifactSemanticClass,
    address: ContentAddress,
    principal: &AuthenticatedArtifactPrincipal,
) -> ArtifactDescriptor {
    ArtifactDescriptor {
        artifact_id: id.to_owned(),
        revision: 1,
        status: ArtifactStatus::Staged as i32,
        semantic_class: semantic_class as i32,
        type_contract_ref: Some(contract_ref("artifact-type", SHA_A)),
        media_type: "application/octet-stream".to_owned(),
        content: Some(address),
        integrity_status: IntegrityStatus::Unverified as i32,
        provenance: Some(Provenance {
            lineage: Some(lineage()),
            producer: Some(producer(principal.kind, &principal.principal_id)),
            input_artifact_ids: Vec::new(),
            transformation_contract_ref: Some(contract_ref("artifact-transform", SHA_B)),
            workspace_ref: "workspace-g4-11".to_owned(),
            observed_at: Some(timestamp()),
            captured_at: Some(timestamp()),
            raw_source_ref: Some(format!("g4-11:{id}")),
        }),
        sensitivity_class: "internal".to_owned(),
        retention_profile_ref: Some(contract_ref("artifact-retention", SHA_A)),
        created_at: None,
        sealed_at: None,
        supersedes_artifact_id: None,
        quarantine_reason_code: None,
    }
}

fn stage_and_seal(
    authority: &mut ArtifactAuthority<AllowArtifactAdmission, FixedArtifactClock>,
    id: &str,
    semantic_class: ArtifactSemanticClass,
    bytes: &[u8],
    principal: &AuthenticatedArtifactPrincipal,
) {
    let address = content_address(bytes);
    authority
        .put_blob(bytes, &address)
        .expect("put artifact blob");
    let mut stage = ArtifactCommand {
        command: Some(artifact_command::Command::StageArtifact(
            StageArtifactCommand {
                metadata: Some(artifact_metadata("stage", id)),
                candidate: Some(artifact_candidate(
                    id,
                    semantic_class,
                    address.clone(),
                    principal,
                )),
            },
        )),
    };
    set_artifact_digest(&mut stage);
    assert!(
        authority
            .execute(&stage, principal)
            .expect("stage artifact")
            .committed
    );

    let mut seal = ArtifactCommand {
        command: Some(artifact_command::Command::SealArtifact(
            SealArtifactCommand {
                metadata: Some(artifact_metadata("seal", id)),
                artifact_id: id.to_owned(),
                expected_revision: 1,
                observed_content: Some(address),
            },
        )),
    };
    set_artifact_digest(&mut seal);
    assert!(
        authority
            .execute(
                &seal,
                &artifact_principal(
                    ArtifactPrincipalKind::ArtifactAuthority,
                    "artifact-authority:g4-11"
                )
            )
            .expect("seal artifact")
            .committed
    );
}

fn artifact_authority_metadata(operation: &str) -> CommandMetadata {
    artifact_metadata(operation, operation)
}

fn propose_claim_command(statement: ContentAddress) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::ProposeClaim(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::ProposeClaimCommand {
                metadata: Some(artifact_authority_metadata("claim")),
                claim: Some(Claim {
                    claim_id: "claim-g4-11".to_owned(),
                    revision: 1,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(contract_ref("task-acceptance", SHA_A)),
                    lineage: Some(lineage()),
                    subject_artifact_ids: vec!["artifact-output-g4-11".to_owned()],
                    acceptance_contract_ref: Some(contract_ref("task-acceptance", SHA_A)),
                    statement: Some(statement),
                    proposer: Some(producer(ArtifactPrincipalKind::Harness, "harness:g4-11")),
                    proposed_at: None,
                    supersedes_claim_id: None,
                }),
            },
        )),
    };
    set_artifact_digest(&mut command);
    command
}

fn record_evidence_command(coverage: ContentAddress) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::RecordEvidence(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::RecordEvidenceCommand {
                metadata: Some(artifact_authority_metadata("evidence")),
                evidence: Some(Evidence {
                    evidence_id: "evidence-g4-11".to_owned(),
                    revision: 1,
                    status: EvidenceStatus::Recorded as i32,
                    relation: EvidenceRelation::Supports as i32,
                    claim_id: "claim-g4-11".to_owned(),
                    artifact_ids: vec!["artifact-output-g4-11".to_owned()],
                    evidence_profile_ref: Some(contract_ref("task-acceptance-evidence", SHA_B)),
                    lineage: Some(lineage()),
                    producer: Some(producer(
                        ArtifactPrincipalKind::SupervisedRunner,
                        "runner:g4-11",
                    )),
                    producer_class: EvidenceProducerClass::SupervisedRunner as i32,
                    independent_of_claim_proposer: true,
                    integrity_status: IntegrityStatus::Unverified as i32,
                    coverage_descriptor: Some(coverage),
                    limitation_codes: Vec::new(),
                    recorded_at: None,
                    supersedes_evidence_id: None,
                }),
            },
        )),
    };
    set_artifact_digest(&mut command);
    command
}

fn create_and_seal_artifact_set(
    authority: &mut ArtifactAuthority<AllowArtifactAdmission, FixedArtifactClock>,
) -> ContentAddress {
    let mut artifact_set = ArtifactSet {
        artifact_set_id: "artifact-set-g4-11".to_owned(),
        revision: 1,
        status: ArtifactSetStatus::Draft as i32,
        lineage: Some(lineage()),
        artifact_ids: vec!["artifact-output-g4-11".to_owned()],
        claim_ids: vec!["claim-g4-11".to_owned()],
        evidence_ids: vec!["evidence-g4-11".to_owned()],
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
        .expect("put artifact-set manifest");

    let mut create = ArtifactCommand {
        command: Some(artifact_command::Command::CreateArtifactSet(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::CreateArtifactSetCommand {
                metadata: Some(artifact_authority_metadata("create-set")),
                artifact_set: Some(artifact_set),
            },
        )),
    };
    set_artifact_digest(&mut create);
    assert!(
        authority
            .execute(
                &create,
                &artifact_principal(ArtifactPrincipalKind::Harness, "harness:g4-11"),
            )
            .expect("create artifact set")
            .committed
    );

    let mut seal = ArtifactCommand {
        command: Some(artifact_command::Command::SealArtifactSet(
            SealArtifactSetCommand {
                metadata: Some(artifact_authority_metadata("seal-set")),
                artifact_set_id: "artifact-set-g4-11".to_owned(),
                expected_revision: 1,
                observed_manifest: Some(manifest.clone()),
            },
        )),
    };
    set_artifact_digest(&mut seal);
    assert!(
        authority
            .execute(
                &seal,
                &artifact_principal(
                    ArtifactPrincipalKind::ArtifactAuthority,
                    "artifact-authority:g4-11",
                ),
            )
            .expect("seal artifact set")
            .committed
    );
    manifest
}

fn submit_return_handoff(
    authority: &mut ArtifactAuthority<AllowArtifactAdmission, FixedArtifactClock>,
    manifest: ContentAddress,
) -> String {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::SubmitReturnHandoff(
            SubmitReturnHandoffCommand {
                metadata: Some(artifact_authority_metadata("handoff")),
                return_handoff: Some(ReturnHandoff {
                    return_handoff_id: "return-handoff-g4-11".to_owned(),
                    revision: 1,
                    status: ReturnHandoffStatus::Submitted as i32,
                    lineage: Some(lineage()),
                    artifact_set_id: "artifact-set-g4-11".to_owned(),
                    artifact_set_manifest: Some(manifest),
                    primary_claim_ids: vec!["claim-g4-11".to_owned()],
                    evidence_ids: vec!["evidence-g4-11".to_owned()],
                    limitation_artifact_ids: Vec::new(),
                    unknown_artifact_ids: Vec::new(),
                    final_message_artifact_id: None,
                    submitted_by: Some(producer(ArtifactPrincipalKind::Harness, "harness:g4-11")),
                    submitted_at: None,
                    supersedes_return_handoff_id: None,
                }),
                expected_artifact_set_revision: 2,
            },
        )),
    };
    set_artifact_digest(&mut command);
    let result = authority
        .execute(
            &command,
            &artifact_principal(ArtifactPrincipalKind::Harness, "harness:g4-11"),
        )
        .expect("submit return handoff");
    assert!(result.committed);
    "return-handoff-g4-11".to_owned()
}

fn verification_metadata(operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("g4-11-verification-{operation}"),
        idempotency_key: format!("g4-11-verification-{operation}"),
        idempotency_scope: "g4-11-verification".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(timestamp()),
        correlation_id: "g4-11-verification-correlation".to_owned(),
        causation_id: None,
    }
}

fn seal_verification_command(mut command: VerificationCommand) -> VerificationCommand {
    let digest = canonical_verification_request_digest(&command).expect("verification digest");
    match command.command.as_mut().expect("verification command") {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        verification_command::Command::CreateVerificationRequest(value) => value.metadata.as_mut(),
        verification_command::Command::StartVerificationRun(value) => value.metadata.as_mut(),
        verification_command::Command::RecordCriterionResult(value) => value.metadata.as_mut(),
        verification_command::Command::CompleteVerification(value) => value.metadata.as_mut(),
        verification_command::Command::RequestVerificationCancellation(value) => {
            value.metadata.as_mut()
        }
        verification_command::Command::RecordVerificationCancellation(value) => {
            value.metadata.as_mut()
        }
        verification_command::Command::HoldVerification(value) => value.metadata.as_mut(),
    }
    .expect("verification metadata")
    .request_digest_sha256 = digest;
    command
}

fn checker_profile() -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: "checker-g4-11".to_owned(),
        revision: 0,
        status: CheckerProfileStatus::Unspecified as i32,
        checker_id: "deterministic:g4-11".to_owned(),
        checker_version: "1".to_owned(),
        input_contract_ref: Some(contract_ref("verification-input", SHA_A)),
        output_contract_ref: Some(contract_ref("verification-output", SHA_B)),
        supported_criterion_types: vec!["acceptance".to_owned()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(contract_ref("verification-sandbox", SHA_A)),
        tool_policy_ref: Some(contract_ref("verification-tools", SHA_B)),
        data_egress_policy_ref: Some(contract_ref("local-only", SHA_A)),
        timeout_ms: 1_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec!["artifact-output-g4-11".to_owned()],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

fn verification_principal(
    kind: VerificationPrincipalKind,
    id: &str,
    profile_id: Option<String>,
) -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
        checker_profile_id: profile_id,
    }
}

fn snapshot() -> CollaborationSnapshot {
    CollaborationSnapshot {
        run: Some(RunSnapshot {
            run_id: "run-g4-11".to_owned(),
            revision: 5,
            task_id: "task-g4-11".to_owned(),
            task_revision_at_creation: 2,
            work_revision: 1,
            status: 0,
            ..Default::default()
        }),
        steps: vec![StepSnapshot {
            step_id: "step-g4-11".to_owned(),
            revision: 4,
            run_id: "run-g4-11".to_owned(),
            status: 0,
            ..Default::default()
        }],
        attempts: vec![AttemptSnapshot {
            attempt_id: "attempt-g4-11".to_owned(),
            revision: 3,
            step_id: "step-g4-11".to_owned(),
            dispatch_id: Some("dispatch-g4-11".to_owned()),
            status: 0,
            ..Default::default()
        }],
    }
}

#[test]
fn production_resolver_joins_actual_artifact_and_verification_authorities() {
    let root = TempRoot::new();
    let artifact_authority = ArtifactAuthority::open_with_clock(
        ArtifactAuthorityConfig {
            database_path: root.path().join("artifact.db"),
            blob_root: root.path().join("blobs"),
            store_epoch: "g4-11-artifact".to_owned(),
            key: ArtifactSqlCipherKey::new([0x11; 32]),
        },
        AllowArtifactAdmission,
        FixedArtifactClock,
    )
    .expect("open artifact authority");
    let output_bytes = b"harness output accepted by the local return fixture";
    let harness_principal = artifact_principal(ArtifactPrincipalKind::Harness, "harness:g4-11");
    let mut artifact_authority = artifact_authority;
    stage_and_seal(
        &mut artifact_authority,
        "artifact-output-g4-11",
        ArtifactSemanticClass::CommandReceipt,
        output_bytes,
        &harness_principal,
    );
    let statement_bytes = b"the governed harness return satisfies acceptance";
    let statement_address = content_address(statement_bytes);
    artifact_authority
        .put_blob(statement_bytes, &statement_address)
        .expect("put claim statement");
    assert!(
        artifact_authority
            .execute(
                &propose_claim_command(statement_address),
                &harness_principal,
            )
            .expect("propose claim")
            .committed
    );
    let coverage_bytes = b"acceptance=passed;artifact=artifact-output-g4-11";
    let coverage_address = content_address(coverage_bytes);
    artifact_authority
        .put_blob(coverage_bytes, &coverage_address)
        .expect("put evidence coverage");
    let runner_principal =
        artifact_principal(ArtifactPrincipalKind::SupervisedRunner, "runner:g4-11");
    let evidence_result = artifact_authority
        .execute(
            &record_evidence_command(coverage_address),
            &runner_principal,
        )
        .expect("record evidence");
    assert!(
        evidence_result.committed,
        "evidence result: {evidence_result:?}"
    );
    let manifest = create_and_seal_artifact_set(&mut artifact_authority);
    let handoff_id = submit_return_handoff(&mut artifact_authority, manifest.clone());

    let binding = VerificationBinding {
        lineage: Some(lineage()),
        artifact_set_id: "artifact-set-g4-11".to_owned(),
        artifact_set_manifest: Some(manifest),
        claim_id: "claim-g4-11".to_owned(),
        claim_semantic_profile_ref: Some(contract_ref("task-acceptance", SHA_A)),
        acceptance_contract_ref: Some(contract_ref("task-acceptance", SHA_A)),
    };
    let profile = checker_profile();
    let profile_ref = contract_ref(&profile.checker_profile_id, &profile.profile_digest_sha256);
    let resolver = VerificationFixtureResolver {
        binding: binding.clone(),
        criteria: vec![CriterionPolicySnapshot {
            criterion_id: "acceptance".to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::Deterministic as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![profile.checker_profile_id.clone()],
        }],
        evidence_ids: [
            "artifact-output-g4-11".to_owned(),
            "evidence-g4-11".to_owned(),
        ]
        .into_iter()
        .collect(),
        artifact_ids: ["artifact-output-g4-11".to_owned()].into_iter().collect(),
    };
    let verification = VerificationAuthority::open_with_clock(
        VerificationAuthorityConfig {
            database_path: root.path().join("verification.db"),
            store_epoch: "g4-11-verification".to_owned(),
            key: VerificationSqlCipherKey::new([0x22; 32]),
        },
        resolver,
        egopulse_verification_authority::SystemVerificationClock,
    )
    .expect("open verification authority");
    let mut verification = verification;
    let authority_principal = verification_principal(
        VerificationPrincipalKind::VerificationAuthority,
        "verification-authority:g4-11",
        None,
    );
    let attest = seal_verification_command(VerificationCommand {
        command: Some(verification_command::Command::AttestCheckerProfile(
            AttestCheckerProfileCommand {
                metadata: Some(verification_metadata("attest")),
                profile: Some(profile.clone()),
            },
        )),
    });
    assert!(
        verification
            .execute(&attest, &authority_principal)
            .expect("attest checker")
            .committed
    );
    let request = VerificationRequest {
        verification_request_id: "verification-request-g4-11".to_owned(),
        revision: 1,
        status: VerificationStatus::Queued as i32,
        verification_type: "task_acceptance".to_owned(),
        binding: Some(binding),
        criterion_ids: vec!["acceptance".to_owned()],
        checker_profile_refs: vec![profile_ref.clone()],
        created_at: None,
        hold_reason_code: None,
    };
    let create = seal_verification_command(VerificationCommand {
        command: Some(verification_command::Command::CreateVerificationRequest(
            CreateVerificationRequestCommand {
                metadata: Some(verification_metadata("create")),
                request: Some(request.clone()),
            },
        )),
    });
    assert!(
        verification
            .execute(
                &create,
                &verification_principal(
                    VerificationPrincipalKind::TaskAuthority,
                    "task-authority:g4-11",
                    None
                ),
            )
            .expect("create verification request")
            .committed
    );
    let start = seal_verification_command(VerificationCommand {
        command: Some(verification_command::Command::StartVerificationRun(
            StartVerificationRunCommand {
                metadata: Some(verification_metadata("start")),
                verification_request_id: request.verification_request_id.clone(),
                expected_request_revision: 1,
                verification_run_id: "verification-run-g4-11".to_owned(),
            },
        )),
    });
    assert!(
        verification
            .execute(&start, &authority_principal)
            .expect("start verification")
            .committed
    );
    let criterion = CriterionResult {
        criterion_result_id: "criterion-result-g4-11".to_owned(),
        criterion_id: "acceptance".to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        outcome: CriterionOutcome::Passed as i32,
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        checker_profile_ref: Some(profile_ref.clone()),
        evidence_coverage: EvidenceCoverage::Complete as i32,
        evidence_ids: vec!["evidence-g4-11".to_owned()],
        discrepancy_ids: Vec::new(),
        unverified_item_ids: Vec::new(),
        duration_ms: 1,
        safe_detail_artifact_id: Some("artifact-output-g4-11".to_owned()),
    };
    let record = seal_verification_command(VerificationCommand {
        command: Some(verification_command::Command::RecordCriterionResult(
            RecordCriterionResultCommand {
                metadata: Some(verification_metadata("record")),
                verification_run_id: "verification-run-g4-11".to_owned(),
                expected_run_revision: 1,
                result: Some(criterion.clone()),
            },
        )),
    });
    assert!(
        verification
            .execute(
                &record,
                &verification_principal(
                    VerificationPrincipalKind::DeterministicChecker,
                    "checker:g4-11",
                    Some(profile.checker_profile_id.clone()),
                ),
            )
            .expect("record criterion")
            .committed
    );
    let verification_artifact = VerificationArtifact {
        verification_artifact_id: "verification-artifact-g4-11".to_owned(),
        version: 1,
        verification_request_id: request.verification_request_id,
        verification_run_id: "verification-run-g4-11".to_owned(),
        verification_type: "task_acceptance".to_owned(),
        binding: request.binding,
        conclusion: VerificationConclusion::Passed as i32,
        overall_evidence_coverage: EvidenceCoverage::Complete as i32,
        criterion_results: vec![criterion],
        discrepancies: Vec::new(),
        unverified_items: Vec::new(),
        provenance: Some(VerificationProvenance {
            verifier_principal_id: authority_principal.principal_id.clone(),
            checker_profile_refs: vec![profile_ref],
            tool_receipt_artifact_ids: Vec::new(),
            model_call_receipt_artifact_ids: Vec::new(),
            raw_output_artifact_ids: vec!["artifact-output-g4-11".to_owned()],
            duration_ms: 1,
            cost_receipt_artifact_id: None,
        }),
        canonical_payload: None,
        completed_at: None,
        supersedes_verification_artifact_id: None,
    };
    let complete = seal_verification_command(VerificationCommand {
        command: Some(verification_command::Command::CompleteVerification(
            CompleteVerificationCommand {
                metadata: Some(verification_metadata("complete")),
                verification_run_id: "verification-run-g4-11".to_owned(),
                expected_run_revision: 2,
                artifact: Some(verification_artifact),
            },
        )),
    });
    assert!(
        verification
            .execute(&complete, &authority_principal)
            .expect("complete verification")
            .committed
    );

    let _ = handoff_id;
    let edge = AdapterEdge::open(AdapterEdgeConfig {
        database_path: root.path().join("adapter.db"),
        adapter_id: "codex-g4-11".to_owned(),
        store_epoch: "g4-11-adapter".to_owned(),
        key: AdapterEdgeKey::new([0x33; 32]),
    })
    .expect("open adapter edge");
    let resolver = GovernedReturnEvidenceResolver::new(
        edge,
        Arc::new(Mutex::new(artifact_authority)),
        Arc::new(Mutex::new(verification)),
    );
    let command = CommitStepReturnCommand {
        base: Some(RunCommandBase {
            meta: None,
            run_id: "run-g4-11".to_owned(),
            expected_run_revision: 5,
        }),
        step_id: "step-g4-11".to_owned(),
        attempt_id: "attempt-g4-11".to_owned(),
        expected_step_revision: 4,
        artifact_set_id: "artifact-set-g4-11".to_owned(),
        return_handoff_id: "return-handoff-g4-11".to_owned(),
    };
    let resolved = resolver
        .resolve_step_return(&command, &snapshot())
        .expect("production resolver joins authorities");
    assert_eq!(resolved.artifact_set_id, "artifact-set-g4-11");
    assert_eq!(resolved.return_handoff_id, "return-handoff-g4-11");
    assert_eq!(
        resolved.verification_artifact_id,
        "verification-artifact-g4-11"
    );
}
