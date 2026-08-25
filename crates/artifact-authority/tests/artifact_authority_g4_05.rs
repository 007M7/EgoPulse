use egopulse_artifact_authority::{
    AdmissionRejection, ArtifactAdmissionGuard, ArtifactAuthority, ArtifactAuthorityConfig,
    ArtifactClock, ArtifactPrincipalKind, ArtifactSqlCipherKey, AuthenticatedArtifactPrincipal,
    canonical_artifact_set_manifest, canonical_request_digest, content_address,
};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactCommand, ArtifactDescriptor, ArtifactErrorCode, ArtifactSemanticClass, ArtifactSet,
    ArtifactSetStatus, ArtifactStatus, Claim, ClaimSourceType, ClaimStatus, ContentAddress,
    Evidence, EvidenceProducerClass, EvidenceRelation, EvidenceStatus, IntegrityStatus,
    LineageBinding, ProducerIdentity, Provenance, ReturnHandoff, ReturnHandoffStatus,
    SealArtifactCommand, SealArtifactSetCommand, StageArtifactCommand, SubmitReturnHandoffCommand,
    artifact_command,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use prost_types::Timestamp;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const STORE_EPOCH: &str = "artifact-store-g4-05-test";
const TEST_KEY: [u8; 32] = [0x75; 32];
const FIXED_TIME: i64 = 1_777_073_600;

#[derive(Clone, Copy)]
struct FixedClock;

impl ArtifactClock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureGuard;

impl ArtifactAdmissionGuard for FixtureGuard {
    fn validate_artifact(
        &self,
        artifact: &ArtifactDescriptor,
        bytes: &[u8],
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        if artifact
            .provenance
            .as_ref()
            .is_none_or(|value| value.workspace_ref != "workspace-001")
        {
            return Err(AdmissionRejection::ScopeViolation);
        }
        if bytes.windows(6).any(|window| window == b"SECRET") {
            return Err(AdmissionRejection::SecretDetected);
        }
        if bytes.windows(3).any(|window| window == b"../") {
            return Err(AdmissionRejection::ScopeViolation);
        }
        Ok(())
    }

    fn validate_claim(
        &self,
        claim: &Claim,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        if claim
            .semantic_profile_ref
            .as_ref()
            .is_none_or(|value| value.contract_id != "repository_change_acceptance")
        {
            return Err(AdmissionRejection::ContractMismatch);
        }
        Ok(())
    }

    fn validate_evidence(
        &self,
        evidence: &Evidence,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        if evidence
            .evidence_profile_ref
            .as_ref()
            .is_none_or(|value| value.contract_id != "command_receipt_evidence")
        {
            return Err(AdmissionRejection::ContractMismatch);
        }
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
        handoff: &ReturnHandoff,
        _principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection> {
        if handoff.primary_claim_ids != ["claim-code-change-001"] {
            return Err(AdmissionRejection::InvalidArgument);
        }
        Ok(())
    }
}

struct IsolatedStore {
    root: PathBuf,
}

impl IsolatedStore {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create isolated Artifact Authority directory");
        Self { root }
    }

    fn database_path(&self) -> PathBuf {
        self.root.join("artifact-authority.sqlcipher")
    }

    fn blob_root(&self) -> PathBuf {
        self.root.join("blobs")
    }
}

impl Drop for IsolatedStore {
    fn drop(&mut self) {
        let temp_root = std::env::temp_dir();
        assert!(self.root.starts_with(&temp_root));
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove isolated Artifact Authority directory");
        }
    }
}

fn open_authority(
    database_path: &Path,
    blob_root: &Path,
) -> ArtifactAuthority<FixtureGuard, FixedClock> {
    ArtifactAuthority::open_with_clock(
        ArtifactAuthorityConfig {
            database_path: database_path.to_owned(),
            blob_root: blob_root.to_owned(),
            store_epoch: STORE_EPOCH.to_owned(),
            key: ArtifactSqlCipherKey::new(TEST_KEY),
        },
        FixtureGuard,
        FixedClock,
    )
    .expect("open encrypted Artifact Authority")
}

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.to_owned(),
        authenticated: true,
    }
}

fn harness() -> AuthenticatedArtifactPrincipal {
    principal(ArtifactPrincipalKind::Harness, "harness:codex")
}

fn collector() -> AuthenticatedArtifactPrincipal {
    principal(ArtifactPrincipalKind::GovernedCollector, "collector:repo")
}

fn runner() -> AuthenticatedArtifactPrincipal {
    principal(ArtifactPrincipalKind::SupervisedRunner, "runner:command")
}

fn authority_principal() -> AuthenticatedArtifactPrincipal {
    principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        "authority:artifact",
    )
}

fn metadata(operation: &str, key: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("cmd-{operation}-{key}"),
        idempotency_key: key.to_owned(),
        idempotency_scope: "task-001/work-1/attempt-001".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: FIXED_TIME,
            nanos: 0,
        }),
        correlation_id: "corr-g4-05".to_owned(),
        causation_id: None,
    }
}

fn set_digest(command: &mut ArtifactCommand) {
    let digest = canonical_request_digest(command).expect("canonical Artifact request digest");
    let meta = match command.command.as_mut().expect("command variant") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::QuarantineObject(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::WithdrawClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_mut(),
        artifact_command::Command::TombstoneObject(value) => value.metadata.as_mut(),
    };
    meta.expect("command metadata").request_digest_sha256 = digest;
}

fn contract_ref(id: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "1".to_owned(),
        sha256: match id {
            "repository_change_acceptance" => "a".repeat(64),
            "command_receipt_evidence" => "b".repeat(64),
            "artifact-type" => "c".repeat(64),
            "artifact-transform" => "d".repeat(64),
            "artifact-retention" => "e".repeat(64),
            _ => "f".repeat(64),
        },
    }
}

fn lineage() -> LineageBinding {
    LineageBinding {
        task_id: "task-001".to_owned(),
        task_revision: 2,
        work_revision: 1,
        run_id: "run-001".to_owned(),
        run_revision: 8,
        step_id: "step-001".to_owned(),
        step_revision: 7,
        attempt_id: "attempt-001".to_owned(),
        attempt_revision: 6,
        dispatch_id: "dispatch-001".to_owned(),
        fencing_token: 1,
    }
}

fn producer(kind: ArtifactPrincipalKind, id: &str, component: &str) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: kind.as_str().to_owned(),
        principal_id: id.to_owned(),
        component_name: component.to_owned(),
        component_version: "0.1.0".to_owned(),
        capability_profile_id: Some("v01-single-harness".to_owned()),
        native_execution_ref: None,
    }
}

fn artifact_candidate(
    id: &str,
    semantic_class: ArtifactSemanticClass,
    address: ContentAddress,
    principal_kind: ArtifactPrincipalKind,
    principal_id: &str,
) -> ArtifactDescriptor {
    ArtifactDescriptor {
        artifact_id: id.to_owned(),
        revision: 1,
        status: ArtifactStatus::Staged as i32,
        semantic_class: semantic_class as i32,
        type_contract_ref: Some(contract_ref("artifact-type")),
        media_type: "application/octet-stream".to_owned(),
        content: Some(address),
        integrity_status: IntegrityStatus::Unverified as i32,
        provenance: Some(Provenance {
            lineage: Some(lineage()),
            producer: Some(producer(principal_kind, principal_id, "fixture-producer")),
            input_artifact_ids: Vec::new(),
            transformation_contract_ref: Some(contract_ref("artifact-transform")),
            workspace_ref: "workspace-001".to_owned(),
            observed_at: Some(Timestamp {
                seconds: FIXED_TIME,
                nanos: 0,
            }),
            captured_at: Some(Timestamp {
                seconds: FIXED_TIME,
                nanos: 0,
            }),
            raw_source_ref: Some(format!("source:{id}")),
        }),
        sensitivity_class: "internal".to_owned(),
        retention_profile_ref: Some(contract_ref("artifact-retention")),
        created_at: None,
        sealed_at: None,
        supersedes_artifact_id: None,
        quarantine_reason_code: None,
    }
}

fn stage_command(candidate: ArtifactDescriptor, key: &str) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::StageArtifact(
            StageArtifactCommand {
                metadata: Some(metadata("stage", key)),
                candidate: Some(candidate),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn seal_command(id: &str, content: ContentAddress, key: &str) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::SealArtifact(
            SealArtifactCommand {
                metadata: Some(metadata("seal", key)),
                artifact_id: id.to_owned(),
                expected_revision: 1,
                observed_content: Some(content),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn stage_and_seal(
    authority: &mut ArtifactAuthority<FixtureGuard, FixedClock>,
    id: &str,
    class: ArtifactSemanticClass,
    bytes: &[u8],
    artifact_principal: &AuthenticatedArtifactPrincipal,
) {
    let address = content_address(bytes);
    authority
        .put_blob(bytes, &address)
        .expect("put Artifact blob");
    let staged = authority
        .execute(
            &stage_command(
                artifact_candidate(
                    id,
                    class,
                    address.clone(),
                    artifact_principal.kind,
                    &artifact_principal.principal_id,
                ),
                &format!("stage-{id}"),
            ),
            artifact_principal,
        )
        .expect("stage Artifact");
    assert!(staged.committed);
    let sealed = authority
        .execute(
            &seal_command(id, address, &format!("seal-{id}")),
            &authority_principal(),
        )
        .expect("seal Artifact");
    assert_eq!(
        sealed.artifact.expect("sealed Artifact").status,
        ArtifactStatus::Sealed as i32
    );
}

fn claim_command(statement: ContentAddress) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::ProposeClaim(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::ProposeClaimCommand {
                metadata: Some(metadata("claim", "claim-001")),
                claim: Some(Claim {
                    claim_id: "claim-code-change-001".to_owned(),
                    revision: 1,
                    status: ClaimStatus::Proposed as i32,
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(contract_ref("repository_change_acceptance")),
                    lineage: Some(lineage()),
                    subject_artifact_ids: vec![
                        "artifact-baseline-001".to_owned(),
                        "artifact-patch-001".to_owned(),
                    ],
                    acceptance_contract_ref: Some(contract_ref("repository_change_acceptance")),
                    statement: Some(statement),
                    proposer: Some(producer(
                        ArtifactPrincipalKind::Harness,
                        "harness:codex",
                        "codex-adapter",
                    )),
                    proposed_at: None,
                    supersedes_claim_id: None,
                }),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn evidence_command(
    coverage: ContentAddress,
    producer_identity: ProducerIdentity,
) -> ArtifactCommand {
    let producer_class =
        if producer_identity.principal_kind == ArtifactPrincipalKind::Harness.as_str() {
            EvidenceProducerClass::Harness
        } else {
            EvidenceProducerClass::SupervisedRunner
        };
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::RecordEvidence(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::RecordEvidenceCommand {
                metadata: Some(metadata("evidence", "evidence-001")),
                evidence: Some(Evidence {
                    evidence_id: "evidence-command-001".to_owned(),
                    revision: 1,
                    status: EvidenceStatus::Recorded as i32,
                    relation: EvidenceRelation::Supports as i32,
                    claim_id: "claim-code-change-001".to_owned(),
                    artifact_ids: vec!["artifact-command-001".to_owned()],
                    evidence_profile_ref: Some(contract_ref("command_receipt_evidence")),
                    lineage: Some(lineage()),
                    producer: Some(producer_identity),
                    producer_class: producer_class as i32,
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
    set_digest(&mut command);
    command
}

fn artifact_set_candidate() -> (ArtifactSet, Vec<u8>) {
    let mut artifact_set = ArtifactSet {
        artifact_set_id: "artifact-set-001".to_owned(),
        revision: 1,
        status: ArtifactSetStatus::Draft as i32,
        lineage: Some(lineage()),
        artifact_ids: vec![
            "artifact-patch-001".to_owned(),
            "artifact-baseline-001".to_owned(),
            "artifact-command-001".to_owned(),
        ],
        claim_ids: vec!["claim-code-change-001".to_owned()],
        evidence_ids: vec!["evidence-command-001".to_owned()],
        canonical_manifest: None,
        created_at: None,
        sealed_at: None,
        supersedes_artifact_set_id: None,
    };
    let manifest = canonical_artifact_set_manifest(&artifact_set);
    artifact_set.canonical_manifest = Some(content_address(&manifest));
    (artifact_set, manifest)
}

fn create_set_command(set: ArtifactSet) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::CreateArtifactSet(
            egopulse_domain_contracts::v01::egopulse::artifact::v1::CreateArtifactSetCommand {
                metadata: Some(metadata("create-set", "set-001")),
                artifact_set: Some(set),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn seal_set_command(manifest: ContentAddress, key: &str) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::SealArtifactSet(
            SealArtifactSetCommand {
                metadata: Some(metadata("seal-set", key)),
                artifact_set_id: "artifact-set-001".to_owned(),
                expected_revision: 1,
                observed_manifest: Some(manifest),
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn handoff_command(manifest: ContentAddress) -> ArtifactCommand {
    let mut command = ArtifactCommand {
        command: Some(artifact_command::Command::SubmitReturnHandoff(
            SubmitReturnHandoffCommand {
                metadata: Some(metadata("handoff", "handoff-001")),
                return_handoff: Some(ReturnHandoff {
                    return_handoff_id: "return-handoff-001".to_owned(),
                    revision: 1,
                    status: ReturnHandoffStatus::Submitted as i32,
                    lineage: Some(lineage()),
                    artifact_set_id: "artifact-set-001".to_owned(),
                    artifact_set_manifest: Some(manifest),
                    primary_claim_ids: vec!["claim-code-change-001".to_owned()],
                    evidence_ids: vec!["evidence-command-001".to_owned()],
                    limitation_artifact_ids: Vec::new(),
                    unknown_artifact_ids: Vec::new(),
                    final_message_artifact_id: None,
                    submitted_by: Some(producer(
                        ArtifactPrincipalKind::Harness,
                        "harness:codex",
                        "codex-adapter",
                    )),
                    submitted_at: None,
                    supersedes_return_handoff_id: None,
                }),
                expected_artifact_set_revision: 2,
            },
        )),
    };
    set_digest(&mut command);
    command
}

fn advance_to_sealed_set(
    authority: &mut ArtifactAuthority<FixtureGuard, FixedClock>,
) -> ContentAddress {
    stage_and_seal(
        authority,
        "artifact-baseline-001",
        ArtifactSemanticClass::RepositoryBaseline,
        b"baseline-tree",
        &collector(),
    );
    stage_and_seal(
        authority,
        "artifact-patch-001",
        ArtifactSemanticClass::RepositoryPatch,
        b"canonical-patch",
        &collector(),
    );
    stage_and_seal(
        authority,
        "artifact-command-001",
        ArtifactSemanticClass::CommandReceipt,
        b"cargo test: exit=0",
        &runner(),
    );

    let statement_bytes = b"repository change satisfies frozen acceptance criteria";
    let statement = content_address(statement_bytes);
    authority
        .put_blob(statement_bytes, &statement)
        .expect("put Claim statement");
    assert!(
        authority
            .execute(&claim_command(statement), &harness())
            .expect("propose Claim")
            .committed
    );

    let coverage_bytes = b"criterion=test;receipt=artifact-command-001";
    let coverage = content_address(coverage_bytes);
    authority
        .put_blob(coverage_bytes, &coverage)
        .expect("put Evidence coverage");
    assert!(
        authority
            .execute(
                &evidence_command(
                    coverage,
                    producer(
                        ArtifactPrincipalKind::SupervisedRunner,
                        "runner:command",
                        "supervised-runner",
                    ),
                ),
                &runner(),
            )
            .expect("record Evidence")
            .committed
    );

    let (set, manifest_bytes) = artifact_set_candidate();
    let manifest = set.canonical_manifest.clone().expect("manifest address");
    authority
        .put_blob(&manifest_bytes, &manifest)
        .expect("put canonical manifest");
    assert!(
        authority
            .execute(&create_set_command(set), &harness())
            .expect("create ArtifactSet")
            .committed
    );
    let sealed = authority
        .execute(
            &seal_set_command(manifest.clone(), "seal-set-001"),
            &authority_principal(),
        )
        .expect("seal ArtifactSet");
    assert_eq!(
        sealed.artifact_set.expect("sealed set").status,
        ArtifactSetStatus::Sealed as i32
    );
    manifest
}

#[test]
fn immutable_return_intake_is_atomic_and_duplicate_safe() {
    let isolated = IsolatedStore::new("artifact-intake");
    let mut authority = open_authority(&isolated.database_path(), &isolated.blob_root());
    let manifest = advance_to_sealed_set(&mut authority);
    let sealed_counts = authority.inspect_store().expect("sealed-set counts");
    let stale = authority
        .execute(
            &seal_set_command(manifest.clone(), "seal-set-stale"),
            &authority_principal(),
        )
        .expect("reject stale ArtifactSet seal");
    assert_eq!(stale.error_code, ArtifactErrorCode::RevisionConflict as i32);
    assert_eq!(
        authority.inspect_store().expect("stale set zero write"),
        sealed_counts
    );
    let command = handoff_command(manifest);
    let committed = authority
        .execute(&command, &harness())
        .expect("submit ReturnHandoff");
    assert!(committed.committed);
    let receipt = committed.return_receipt.expect("technical ReturnReceipt");
    assert!(receipt.accepted_for_evidence_intake);
    assert!(!receipt.verification_performed);
    assert!(!receipt.task_completion_decided);

    let counts = authority.inspect_store().expect("inspect Artifact store");
    assert_eq!(counts.artifact_count, 3);
    assert_eq!(counts.claim_count, 1);
    assert_eq!(counts.evidence_count, 1);
    assert_eq!(counts.artifact_set_count, 1);
    assert_eq!(counts.return_handoff_count, 1);
    assert_eq!(counts.return_receipt_count, 1);
    assert_eq!(counts.event_count, 11);
    assert_eq!(counts.idempotency_count, 11);
    assert_eq!(counts.outbox_count, 12);
    assert_eq!(counts.commit_receipt_count, 11);

    let mut duplicate = command.clone();
    if let Some(artifact_command::Command::SubmitReturnHandoff(value)) = duplicate.command.as_mut()
    {
        let meta = value.metadata.as_mut().expect("metadata");
        meta.command_id = "cmd-handoff-retry".to_owned();
        meta.correlation_id = "corr-retry".to_owned();
        meta.issued_at = Some(Timestamp {
            seconds: FIXED_TIME + 1,
            nanos: 0,
        });
    }
    let replayed = authority
        .execute(&duplicate, &harness())
        .expect("replay ReturnHandoff");
    assert!(replayed.replayed);
    assert_eq!(authority.inspect_store().expect("replay counts"), counts);

    let mut conflict = command;
    if let Some(artifact_command::Command::SubmitReturnHandoff(value)) = conflict.command.as_mut() {
        value
            .return_handoff
            .as_mut()
            .expect("handoff")
            .unknown_artifact_ids
            .push("artifact-unknown".to_owned());
    }
    set_digest(&mut conflict);
    let rejected = authority
        .execute(&conflict, &harness())
        .expect("reject idempotency conflict");
    assert_eq!(
        rejected.error_code,
        ArtifactErrorCode::IdempotencyConflict as i32
    );
    assert_eq!(authority.inspect_store().expect("conflict counts"), counts);
}

#[test]
fn cross_authority_reads_expose_only_decoded_immutable_snapshots() {
    let isolated = IsolatedStore::new("artifact-read-boundary");
    let mut authority = open_authority(&isolated.database_path(), &isolated.blob_root());
    let manifest = advance_to_sealed_set(&mut authority);

    let artifact_set = authority
        .read_artifact_set("artifact-set-001")
        .expect("read sealed ArtifactSet")
        .expect("ArtifactSet exists");
    assert_eq!(artifact_set.status, ArtifactSetStatus::Sealed as i32);
    assert_eq!(artifact_set.canonical_manifest, Some(manifest));

    let claim = authority
        .read_claim("claim-code-change-001")
        .expect("read Claim")
        .expect("Claim exists");
    assert_eq!(claim.status, ClaimStatus::Proposed as i32);
    assert_eq!(
        claim.acceptance_contract_ref,
        Some(contract_ref("repository_change_acceptance"))
    );

    let evidence = authority
        .read_evidence("evidence-command-001")
        .expect("read Evidence")
        .expect("Evidence exists");
    assert_eq!(evidence.status, EvidenceStatus::Recorded as i32);
    assert_eq!(evidence.claim_id, "claim-code-change-001");
}

#[test]
fn blob_must_be_durable_and_verified_before_metadata() {
    let isolated = IsolatedStore::new("artifact-blob-order");
    let database = isolated.database_path();
    let blob_root = isolated.blob_root();
    let authority = open_authority(&database, &blob_root);
    let bytes = b"orphan-before-metadata";
    let address = content_address(bytes);

    let wrong = authority.put_blob(b"different", &address);
    assert!(wrong.is_err());
    assert_eq!(
        authority
            .inspect_store()
            .expect("zero metadata")
            .artifact_count,
        0
    );
    authority
        .put_blob(bytes, &address)
        .expect("durably write orphan blob");
    drop(authority);

    let mut recovered = open_authority(&database, &blob_root);
    let result = recovered
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-orphan-001",
                    ArtifactSemanticClass::TypedExtension,
                    address,
                    ArtifactPrincipalKind::GovernedCollector,
                    "collector:repo",
                ),
                "orphan-stage",
            ),
            &collector(),
        )
        .expect("reuse verified orphan blob");
    assert!(result.committed);
    assert_eq!(
        recovered
            .inspect_store()
            .expect("recovered metadata")
            .artifact_count,
        1
    );

    let missing_bytes = b"never-published";
    let missing = content_address(missing_bytes);
    let rejected = recovered
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-missing-001",
                    ArtifactSemanticClass::TypedExtension,
                    missing,
                    ArtifactPrincipalKind::GovernedCollector,
                    "collector:repo",
                ),
                "missing-stage",
            ),
            &collector(),
        )
        .expect("reject missing blob");
    assert_eq!(
        rejected.error_code,
        ArtifactErrorCode::IntegrityFailure as i32
    );
    assert_eq!(
        recovered
            .inspect_store()
            .expect("missing zero write")
            .artifact_count,
        1
    );
}

#[test]
fn admission_identity_and_owner_boundaries_fail_closed() {
    let isolated = IsolatedStore::new("artifact-owner-boundaries");
    let mut authority = open_authority(&isolated.database_path(), &isolated.blob_root());

    let secret_bytes = b"SECRET=must-not-enter-artifact-metadata";
    let secret_address = content_address(secret_bytes);
    authority
        .put_blob(secret_bytes, &secret_address)
        .expect("stage candidate bytes before admission");
    let secret = authority
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-secret-001",
                    ArtifactSemanticClass::TypedExtension,
                    secret_address,
                    ArtifactPrincipalKind::GovernedCollector,
                    "collector:repo",
                ),
                "secret-stage",
            ),
            &collector(),
        )
        .expect("reject secret-bearing candidate");
    assert_eq!(secret.error_code, ArtifactErrorCode::SecretDetected as i32);
    assert_eq!(
        authority
            .inspect_store()
            .expect("secret zero write")
            .artifact_count,
        0
    );

    let valid_bytes = b"provider-neutral artifact";
    let valid_address = content_address(valid_bytes);
    authority
        .put_blob(valid_bytes, &valid_address)
        .expect("put valid candidate bytes");
    let forged = authority
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-forged-001",
                    ArtifactSemanticClass::TypedExtension,
                    valid_address.clone(),
                    ArtifactPrincipalKind::Harness,
                    "harness:codex",
                ),
                "forged-stage",
            ),
            &collector(),
        )
        .expect("reject forged producer identity");
    assert_eq!(forged.error_code, ArtifactErrorCode::InvalidArgument as i32);
    assert_eq!(
        authority
            .inspect_store()
            .expect("forgery zero write")
            .artifact_count,
        0
    );

    let staged = authority
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-valid-001",
                    ArtifactSemanticClass::TypedExtension,
                    valid_address.clone(),
                    ArtifactPrincipalKind::GovernedCollector,
                    "collector:repo",
                ),
                "valid-stage",
            ),
            &collector(),
        )
        .expect("stage valid Artifact");
    assert!(staged.committed);
    let counts = authority.inspect_store().expect("staged counts");
    let unauthorized = authority
        .execute(
            &seal_command("artifact-valid-001", valid_address, "unauthorized-seal"),
            &harness(),
        )
        .expect("reject Harness seal");
    assert_eq!(
        unauthorized.error_code,
        ArtifactErrorCode::PermissionDenied as i32
    );
    assert_eq!(authority.inspect_store().expect("seal zero write"), counts);
}

#[test]
fn private_artifact_store_does_not_escape_the_owner_crate() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace");
    let mut stack = vec![workspace_root.join("crates"), workspace_root.join("apps")];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).expect("scan workspace source boundary") {
            let entry = entry.expect("source entry");
            let entry_path = entry.path();
            if entry_path.is_dir() {
                if entry_path != crate_root {
                    stack.push(entry_path);
                }
                continue;
            }
            if entry_path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&entry_path).expect("read Rust source");
            assert!(
                !source.contains("artifact_authority::store")
                    && !source.contains("artifact_authority::blob"),
                "private Artifact storage boundary leaked into {}",
                entry_path.display()
            );
        }
    }
}

#[test]
fn self_attested_independence_is_a_zero_write_failure() {
    let isolated = IsolatedStore::new("artifact-guards");
    let mut authority = open_authority(&isolated.database_path(), &isolated.blob_root());

    stage_and_seal(
        &mut authority,
        "artifact-baseline-001",
        ArtifactSemanticClass::RepositoryBaseline,
        b"baseline-tree",
        &collector(),
    );
    stage_and_seal(
        &mut authority,
        "artifact-patch-001",
        ArtifactSemanticClass::RepositoryPatch,
        b"canonical-patch",
        &collector(),
    );
    stage_and_seal(
        &mut authority,
        "artifact-command-001",
        ArtifactSemanticClass::CommandReceipt,
        b"cargo test: exit=0",
        &harness(),
    );
    let statement_bytes = b"statement";
    let statement = content_address(statement_bytes);
    authority
        .put_blob(statement_bytes, &statement)
        .expect("statement");
    authority
        .execute(&claim_command(statement), &harness())
        .expect("claim");

    let coverage_bytes = b"coverage";
    let coverage = content_address(coverage_bytes);
    authority
        .put_blob(coverage_bytes, &coverage)
        .expect("coverage");
    let counts_before = authority.inspect_store().expect("pre-rejection counts");
    let rejected = authority
        .execute(
            &evidence_command(
                coverage,
                producer(
                    ArtifactPrincipalKind::Harness,
                    "harness:codex",
                    "codex-adapter",
                ),
            ),
            &harness(),
        )
        .expect("reject Harness self-attested independence");
    assert_eq!(
        rejected.error_code,
        ArtifactErrorCode::IndependenceViolation as i32
    );
    assert_eq!(
        authority.inspect_store().expect("self-attest zero write"),
        counts_before
    );
}

#[test]
fn committed_return_survives_process_abort_before_response_delivery() {
    let isolated = IsolatedStore::new("artifact-abort");
    let database = isolated.database_path();
    let blob_root = isolated.blob_root();
    let status =
        Command::new(std::env::current_exe().expect("current integration test executable"))
            .arg("--exact")
            .arg("crash_probe_child")
            .arg("--nocapture")
            .env("EGOPULSE_G4_05_CRASH_PROBE", "1")
            .env("EGOPULSE_G4_05_CRASH_DB", &database)
            .env("EGOPULSE_G4_05_CRASH_BLOBS", &blob_root)
            .status()
            .expect("launch Artifact crash probe child");
    assert!(!status.success(), "crash probe must abort after commit");

    let bytes = fs::read(&database).expect("read encrypted Artifact store");
    assert!(bytes.len() >= 16);
    assert_ne!(&bytes[..16], b"SQLite format 3\0");

    let mut recovered = open_authority(&database, &blob_root);
    assert!(recovered.integrity_is_ok().expect("integrity after abort"));
    let (_, manifest_bytes) = artifact_set_candidate();
    let replayed = recovered
        .execute(
            &handoff_command(content_address(&manifest_bytes)),
            &harness(),
        )
        .expect("replay committed handoff after abort");
    assert!(replayed.replayed);
    let counts = recovered.inspect_store().expect("recovered counts");
    assert_eq!(counts.return_handoff_count, 1);
    assert_eq!(counts.return_receipt_count, 1);
    assert_eq!(counts.outbox_count, 12);
}

#[test]
fn artifact_projection_feed_exposes_committed_result_and_requires_digest_bound_ack() {
    let isolated = IsolatedStore::new("artifact-projection-feed");
    let mut authority = open_authority(&isolated.database_path(), &isolated.blob_root());
    let bytes = b"projection artifact";
    let address = content_address(bytes);
    authority
        .put_blob(bytes, &address)
        .expect("put projection blob");
    let result = authority
        .execute(
            &stage_command(
                artifact_candidate(
                    "artifact-projection-001",
                    ArtifactSemanticClass::CommandReceipt,
                    address,
                    ArtifactPrincipalKind::Harness,
                    "harness:codex",
                ),
                "projection-stage",
            ),
            &harness(),
        )
        .expect("stage projection artifact");
    let pending = authority
        .drain_projection_outbox()
        .expect("drain Artifact projection outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].result, result);
    assert!(
        !authority
            .acknowledge_projection(&pending[0].message_id, &"0".repeat(64))
            .expect("reject mismatched Artifact ACK")
    );
    assert!(
        authority
            .acknowledge_projection(&pending[0].message_id, &pending[0].payload_digest_sha256)
            .expect("ack Artifact projection")
    );
    assert!(
        authority
            .drain_projection_outbox()
            .expect("Artifact projection after ACK")
            .is_empty()
    );
    let baselines = authority
        .projection_baselines()
        .expect("Artifact projection baseline");
    assert_eq!(baselines.len(), 1);
    assert_eq!(baselines[0].result.artifact, result.artifact);
}

#[test]
fn crash_probe_child() {
    if std::env::var("EGOPULSE_G4_05_CRASH_PROBE").as_deref() != Ok("1") {
        return;
    }
    let database =
        PathBuf::from(std::env::var_os("EGOPULSE_G4_05_CRASH_DB").expect("crash database path"));
    let blob_root =
        PathBuf::from(std::env::var_os("EGOPULSE_G4_05_CRASH_BLOBS").expect("crash blob path"));
    let mut authority = open_authority(&database, &blob_root);
    let manifest = advance_to_sealed_set(&mut authority);
    let result = authority
        .execute(&handoff_command(manifest), &harness())
        .expect("commit handoff before intentional abort");
    assert!(result.committed);
    std::process::abort();
}
