use super::*;
use std::path::Path;

use egopulse_artifact_authority::{ArtifactAuthorityConfig, ArtifactSqlCipherKey};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactSet, Claim, ClaimSourceType, CreateArtifactSetCommand, Evidence,
        EvidenceProducerClass, EvidenceRelation, LineageBinding, ProposeClaimCommand,
        RecordEvidenceCommand, SealArtifactSetCommand,
    },
    verification::v1::{
        CheckerAssuranceClass, CheckerProfile, CreateVerificationRequestCommand,
        CriterionRequirement, HoldVerificationCommand, StartVerificationRunCommand,
        VerificationBinding, VerificationCommand, VerificationRequest, verification_command,
    },
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, CheckerResultArtifactReference, CheckerResultReferenceContext,
    CriterionPolicySnapshot, VerificationAuthorityConfig, VerificationPrincipalKind,
    VerificationReferenceResolver, VerificationSqlCipherKey, canonical_checker_profile_digest,
};

use crate::{
    ArtifactAuthorityReferenceSource, ConfiguredArtifactAdmissionGuardConfig,
    SystemCheckerProfileAttestation,
};

fn reference(id: &str) -> ContractReference {
    ContractReference {
        contract_id: id.into(),
        version: "v1".into(),
        sha256: "a".repeat(64),
    }
}

fn guard() -> ConfiguredArtifactAdmissionGuard {
    ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
        // The actual Task workspace must be admitted through its exact lease.
        allowed_workspace_refs: BTreeSet::from(["unrelated-installed-workspace".into()]),
        allowed_artifact_type_refs: vec![reference("input"), reference("output")],
        allowed_transformation_contract_refs: vec![
            reference("capture"),
            reference("checker-result"),
        ],
        allowed_retention_profile_refs: vec![reference("retention")],
        allowed_claim_semantic_profile_refs: vec![reference("claim")],
        allowed_claim_acceptance_contract_refs: vec![reference("acceptance")],
        allowed_evidence_profile_refs: vec![reference("evidence")],
    })
    .expect("configured admission")
}

fn policy() -> VerificationOutputPolicy {
    VerificationOutputPolicy {
        raw_output_type_ref: reference("output"),
        detail_type_ref: reference("output"),
        tool_receipt_type_ref: reference("output"),
        model_receipt_type_ref: reference("output"),
        cost_receipt_type_ref: reference("output"),
        retention_profile_ref: reference("retention"),
        collector_principal_id: "collector:verification".into(),
        artifact_authority_principal_id: "authority:artifact".into(),
        max_output_bytes: 4096,
    }
}

fn principal(kind: ArtifactPrincipalKind, id: &str) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: id.into(),
        authenticated: true,
    }
}

fn producer(kind: ArtifactPrincipalKind, id: &str) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: kind.as_str().into(),
        principal_id: id.into(),
        component_name: "output-intake-test".into(),
        component_version: "1".into(),
        ..Default::default()
    }
}

fn artifact_command(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    variant: artifact_command::Command,
    principal: &AuthenticatedArtifactPrincipal,
) {
    let mut command = ArtifactCommand {
        command: Some(variant),
    };
    let digest = canonical_request_digest(&command).expect("canonical Artifact command");
    let metadata = match command.command.as_mut().expect("command") {
        artifact_command::Command::StageArtifact(v) => v.metadata.as_mut(),
        artifact_command::Command::SealArtifact(v) => v.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(v) => v.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(v) => v.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(v) => v.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(v) => v.metadata.as_mut(),
        _ => panic!("unexpected test operation"),
    }
    .expect("metadata");
    metadata.request_digest_sha256 = digest;
    let result = authority
        .execute(&command, principal)
        .expect("Artifact command");
    assert!(
        result.committed || result.replayed,
        "Artifact rejected: {result:?}"
    );
}

fn verification_command(
    authority: &mut VerificationAuthority,
    variant: verification_command::Command,
    kind: VerificationPrincipalKind,
) {
    let mut command = VerificationCommand {
        command: Some(variant),
    };
    let digest =
        egopulse_verification_authority::canonical_request_digest(&command).expect("digest");
    match command.command.as_mut().expect("command") {
        verification_command::Command::CreateVerificationRequest(v) => v.metadata.as_mut(),
        verification_command::Command::StartVerificationRun(v) => v.metadata.as_mut(),
        verification_command::Command::HoldVerification(v) => v.metadata.as_mut(),
        _ => panic!("unexpected Verification test operation"),
    }
    .expect("metadata")
    .request_digest_sha256 = digest;
    let result = authority
        .execute(
            &command,
            &egopulse_verification_authority::AuthenticatedVerificationPrincipal {
                kind,
                principal_id: "output-test:authority".into(),
                authenticated: true,
                checker_profile_id: None,
            },
        )
        .expect("Verification command");
    assert!(
        result.committed || result.replayed,
        "Verification rejected: {result:?}"
    );
}

struct Fixture {
    authority: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    verification: Arc<Mutex<VerificationAuthority>>,
    admission: DerivedWorkspaceAdmissionHandle,
    binding: VerificationBinding,
    profile: CheckerProfile,
}

impl Fixture {
    /// Reopening replays only stable setup commands through the real owners.
    /// No test writes owner tables or manufactures owner read responses.
    fn open(root: &Path) -> Self {
        let configured_guard = guard();
        let admission = configured_guard.derived_workspace_admission_handle();
        let mut artifact = ArtifactAuthority::open(
            ArtifactAuthorityConfig {
                database_path: root.join("artifact.db"),
                blob_root: root.join("blobs"),
                store_epoch: "verification-output-test".into(),
                key: ArtifactSqlCipherKey::new([0x39; 32]),
            },
            configured_guard,
        )
        .expect("Artifact SQLCipher owner");
        let lineage = LineageBinding {
            task_id: "task-output-1".into(),
            task_revision: 3,
            work_revision: 1,
            run_id: "run-1".into(),
            run_revision: 1,
            step_id: "step-1".into(),
            step_revision: 1,
            attempt_id: "attempt-1".into(),
            attempt_revision: 2,
            dispatch_id: "dispatch-1".into(),
            fencing_token: 1,
        };
        let lease = admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: "derived-task-workspace".into(),
                lineage: lineage.clone(),
                source_binding_ref: "original-dispatch-binding".into(),
            })
            .expect("setup exact lease");
        let collector = principal(ArtifactPrincipalKind::GovernedCollector, "collector:input");
        let supervisor = principal(ArtifactPrincipalKind::AttemptSupervisor, "supervisor:input");
        let owner = principal(
            ArtifactPrincipalKind::ArtifactAuthority,
            "authority:artifact",
        );
        for (id, semantic, bytes) in [
            (
                "baseline",
                ArtifactSemanticClass::RepositoryBaseline,
                b"sealed baseline".as_slice(),
            ),
            (
                "attestation",
                ArtifactSemanticClass::TypedExtension,
                b"test checker deployment declaration".as_slice(),
            ),
        ] {
            let content = content_address(bytes);
            artifact.put_blob(bytes, &content).expect("input blob");
            artifact_command(
                &mut artifact,
                artifact_command::Command::StageArtifact(StageArtifactCommand {
                    metadata: Some(metadata(id, "stage").expect("metadata")),
                    candidate: Some(ArtifactDescriptor {
                        artifact_id: id.into(),
                        semantic_class: semantic as i32,
                        type_contract_ref: Some(reference("input")),
                        media_type: "text/plain".into(),
                        content: Some(content.clone()),
                        provenance: Some(Provenance {
                            lineage: Some(lineage.clone()),
                            producer: Some(producer(supervisor.kind, &supervisor.principal_id)),
                            transformation_contract_ref: Some(reference("capture")),
                            workspace_ref: "derived-task-workspace".into(),
                            raw_source_ref: Some("original-dispatch-binding".into()),
                            ..Default::default()
                        }),
                        sensitivity_class: "local".into(),
                        retention_profile_ref: Some(reference("retention")),
                        ..Default::default()
                    }),
                }),
                &supervisor,
            );
            artifact_command(
                &mut artifact,
                artifact_command::Command::SealArtifact(SealArtifactCommand {
                    metadata: Some(metadata(id, "seal").expect("metadata")),
                    artifact_id: id.into(),
                    expected_revision: 1,
                    observed_content: Some(content),
                }),
                &owner,
            );
        }
        drop(lease);
        let statement = content_address(b"test subject assertion");
        artifact
            .put_blob(b"test subject assertion", &statement)
            .expect("statement");
        artifact_command(
            &mut artifact,
            artifact_command::Command::ProposeClaim(ProposeClaimCommand {
                metadata: Some(metadata("claim", "propose").expect("metadata")),
                claim: Some(Claim {
                    claim_id: "claim".into(),
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(reference("claim")),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec!["baseline".into()],
                    acceptance_contract_ref: Some(reference("acceptance")),
                    statement: Some(statement.clone()),
                    proposer: Some(producer(collector.kind, &collector.principal_id)),
                    ..Default::default()
                }),
            }),
            &collector,
        );
        artifact_command(
            &mut artifact,
            artifact_command::Command::RecordEvidence(RecordEvidenceCommand {
                metadata: Some(metadata("evidence", "record").expect("metadata")),
                evidence: Some(Evidence {
                    evidence_id: "evidence".into(),
                    relation: EvidenceRelation::Supports as i32,
                    claim_id: "claim".into(),
                    artifact_ids: vec!["baseline".into()],
                    evidence_profile_ref: Some(reference("evidence")),
                    lineage: Some(lineage.clone()),
                    producer: Some(producer(supervisor.kind, &supervisor.principal_id)),
                    producer_class: EvidenceProducerClass::AttemptSupervisor as i32,
                    independent_of_claim_proposer: true,
                    coverage_descriptor: Some(statement),
                    ..Default::default()
                }),
            }),
            &supervisor,
        );
        let mut set = ArtifactSet {
            artifact_set_id: "input-set".into(),
            lineage: Some(lineage.clone()),
            artifact_ids: vec!["baseline".into()],
            claim_ids: vec!["claim".into()],
            evidence_ids: vec!["evidence".into()],
            ..Default::default()
        };
        let bytes = canonical_artifact_set_manifest(&set);
        let manifest = content_address(&bytes);
        artifact.put_blob(&bytes, &manifest).expect("set manifest");
        set.canonical_manifest = Some(manifest.clone());
        artifact_command(
            &mut artifact,
            artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
                metadata: Some(metadata("set", "create").expect("metadata")),
                artifact_set: Some(set),
            }),
            &collector,
        );
        artifact_command(
            &mut artifact,
            artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
                metadata: Some(metadata("set", "seal").expect("metadata")),
                artifact_set_id: "input-set".into(),
                expected_revision: 1,
                observed_manifest: Some(manifest.clone()),
            }),
            &owner,
        );
        let binding = VerificationBinding {
            lineage: Some(lineage),
            artifact_set_id: "input-set".into(),
            artifact_set_manifest: Some(manifest),
            claim_id: "claim".into(),
            claim_semantic_profile_ref: Some(reference("claim")),
            acceptance_contract_ref: Some(reference("acceptance")),
        };
        let authority = Arc::new(Mutex::new(artifact));
        let mut profile = CheckerProfile {
            checker_profile_id: "test-review-profile".into(),
            checker_id: "test:review".into(),
            checker_version: "1".into(),
            input_contract_ref: Some(reference("acceptance")),
            output_contract_ref: Some(reference("checker-result")),
            supported_criterion_types: vec!["review".into()],
            assurance_class: CheckerAssuranceClass::ModelAssisted as i32,
            sandbox_profile_ref: Some(reference("read-only")),
            tool_policy_ref: Some(reference("no-tools")),
            data_egress_policy_ref: Some(reference("local")),
            timeout_ms: 10_000,
            attestation_evidence_artifact_ids: vec!["attestation".into()],
            ..Default::default()
        };
        profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
        let resolver = ArtifactBackedReferenceResolver::new(
            ArtifactAuthorityReferenceSource::new_shared(Arc::clone(&authority)),
            vec![criterion()],
        )
        .expect("input resolver")
        .with_checker_output_collector(policy().collector_principal_id)
        .expect("output policy");
        let verification = Arc::new(Mutex::new(
            VerificationAuthority::open(
                VerificationAuthorityConfig {
                    database_path: root.join("verification.db"),
                    store_epoch: "verification-output-test".into(),
                    key: VerificationSqlCipherKey::new([0x49; 32]),
                },
                resolver,
            )
            .expect("Verification SQLCipher owner"),
        ));
        SystemCheckerProfileAttestation::new(Arc::clone(&verification))
            .attest_one(
                profile.clone(),
                metadata("clock", "now")
                    .expect("metadata")
                    .issued_at
                    .expect("time"),
            )
            .expect("attest fixture checker");
        let mut verification_owner = verification.lock().expect("Verification lock");
        let request = VerificationRequest {
            verification_request_id: "request-1".into(),
            revision: 1,
            status: VerificationStatus::Queued as i32,
            verification_type: "task_acceptance".into(),
            binding: Some(binding.clone()),
            criterion_ids: vec!["review".into()],
            checker_profile_refs: vec![ContractReference {
                contract_id: profile.checker_profile_id.clone(),
                version: profile.checker_version.clone(),
                sha256: profile.profile_digest_sha256.clone(),
            }],
            ..Default::default()
        };
        verification_command(
            &mut verification_owner,
            verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata("request", "create").expect("metadata")),
                    request: Some(request),
                },
            ),
            VerificationPrincipalKind::TaskAuthority,
        );
        verification_command(
            &mut verification_owner,
            verification_command::Command::StartVerificationRun(StartVerificationRunCommand {
                metadata: Some(metadata("run", "start").expect("metadata")),
                verification_request_id: "request-1".into(),
                expected_request_revision: 1,
                verification_run_id: "verification-run-1".into(),
            }),
            VerificationPrincipalKind::VerificationAuthority,
        );
        profile = verification_owner
            .checker_profile(&profile.checker_profile_id)
            .expect("profile")
            .expect("profile exists");
        drop(verification_owner);
        Self {
            authority,
            verification,
            admission,
            binding,
            profile,
        }
    }

    fn intake(&self) -> VerificationResultArtifactIntake {
        VerificationResultArtifactIntake::new(
            Arc::clone(&self.authority),
            Arc::clone(&self.verification),
            self.admission.clone(),
            policy(),
        )
        .expect("output intake")
    }
}

fn criterion() -> CriterionPolicySnapshot {
    CriterionPolicySnapshot {
        criterion_id: "review".into(),
        requirement: CriterionRequirement::MustPass as i32,
        minimum_assurance: CheckerAssuranceClass::ModelAssisted as i32,
        not_applicable_allowed: false,
        checker_profile_ids: vec!["test-review-profile".into()],
    }
}

fn output(role: CheckerOutputRole, bytes: &[u8]) -> VerificationOutputRequest<'_> {
    VerificationOutputRequest {
        verification_request_id: "request-1",
        verification_run_id: "verification-run-1",
        checker_profile_id: "test-review-profile",
        role,
        output_key: "result",
        media_type: "application/json",
        bytes,
    }
}

#[test]
fn verification_output_seals_roles_without_mutating_frozen_input_set() {
    let root = tempfile::tempdir().expect("test root");
    let fixture = Fixture::open(root.path());
    let intake = fixture.intake();
    let before = fixture
        .authority
        .lock()
        .expect("lock")
        .read_artifact_set("input-set")
        .expect("set");
    let resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(Arc::clone(&fixture.authority)),
        vec![criterion()],
    )
    .expect("resolver")
    .with_checker_output_collector(policy().collector_principal_id)
    .expect("collector");
    let mut ids = BTreeSet::new();
    for role in [
        CheckerOutputRole::RawOutput,
        CheckerOutputRole::Detail,
        CheckerOutputRole::ToolReceipt,
        CheckerOutputRole::ModelCallReceipt,
        CheckerOutputRole::CostReceipt,
    ] {
        let sealed = intake
            .capture(output(role, b"{\"actual\":true}"))
            .expect("seal output");
        assert!(ids.insert(sealed.artifact_id.clone()));
        assert_eq!(
            sealed,
            intake
                .capture(output(role, b"{\"actual\":true}"))
                .expect("exact replay")
        );
        let context = CheckerResultReferenceContext {
            binding: &fixture.binding,
            verification_request_id: "request-1",
            verification_run_id: "verification-run-1",
            checker_profiles: std::slice::from_ref(&fixture.profile),
        };
        resolver
            .validate_checker_result_references(
                &context,
                &[],
                &[CheckerResultArtifactReference {
                    artifact_id: sealed.artifact_id.clone(),
                    role,
                    checker_profile_id: Some(fixture.profile.checker_profile_id.clone()),
                }],
            )
            .expect("production resolver accepts exact captured role");
        let authority = fixture.authority.lock().expect("lock");
        assert_eq!(
            authority.read_blob(&sealed.content).expect("output bytes"),
            b"{\"actual\":true}"
        );
        // A conflicting exact tuple can be registered only after the original
        // short capture lease was released from this very admission handle.
        let mut other_lineage = fixture.binding.lineage.clone().expect("lineage");
        other_lineage.work_revision += 1;
        drop(
            fixture
                .admission
                .register(DerivedWorkspaceAdmissionBinding {
                    workspace_ref: "derived-task-workspace".into(),
                    lineage: other_lineage,
                    source_binding_ref: "different-source".into(),
                })
                .expect("capture lease was released"),
        );
    }
    assert_eq!(
        before,
        fixture
            .authority
            .lock()
            .expect("lock")
            .read_artifact_set("input-set")
            .expect("set")
    );
}

#[test]
fn verification_output_rejects_changed_bytes_and_foreign_owner_bindings() {
    let root = tempfile::tempdir().expect("test root");
    let fixture = Fixture::open(root.path());
    let intake = fixture.intake();
    let mut unrelated_profile = fixture.profile.clone();
    unrelated_profile.checker_profile_id = "profile-other".into();
    unrelated_profile.revision = 0;
    unrelated_profile.status = CheckerProfileStatus::Unspecified as i32;
    unrelated_profile.attested_at = None;
    unrelated_profile.profile_digest_sha256 = canonical_checker_profile_digest(&unrelated_profile);
    SystemCheckerProfileAttestation::new(Arc::clone(&fixture.verification))
        .attest_one(
            unrelated_profile,
            metadata("clock", "now")
                .expect("metadata")
                .issued_at
                .expect("time"),
        )
        .expect("unrelated but real Active profile");
    let original = intake
        .capture(output(CheckerOutputRole::RawOutput, b"original"))
        .expect("original");
    assert!(matches!(
        intake.capture(output(CheckerOutputRole::RawOutput, b"replacement")),
        Err(VerificationOutputError::Binding)
    ));
    for field in 0..3 {
        let mut request = output(CheckerOutputRole::Detail, b"details");
        match field {
            0 => request.verification_request_id = "request-other",
            1 => request.verification_run_id = "run-other",
            _ => request.checker_profile_id = "profile-other",
        }
        assert!(matches!(
            intake.capture(request),
            Err(VerificationOutputError::Binding)
        ));
    }
    assert!(matches!(
        intake.capture(output(CheckerOutputRole::RawOutput, &vec![b'x'; 4097])),
        Err(VerificationOutputError::Invalid)
    ));
    assert_eq!(
        fixture
            .authority
            .lock()
            .expect("lock")
            .read_blob(&original.content)
            .expect("original preserved"),
        b"original"
    );
}

#[test]
fn verification_output_does_not_capture_after_owner_holds_the_run() {
    let root = tempfile::tempdir().expect("test root");
    let fixture = Fixture::open(root.path());
    let intake = fixture.intake();
    intake
        .capture(output(
            CheckerOutputRole::RawOutput,
            b"observed before interruption",
        ))
        .expect("raw observation");
    verification_command(
        &mut fixture.verification.lock().expect("owner"),
        verification_command::Command::HoldVerification(HoldVerificationCommand {
            metadata: Some(metadata("run", "hold").expect("metadata")),
            verification_run_id: "verification-run-1".into(),
            expected_run_revision: 1,
            reason_code: "CHECKER_RESULT_COMMIT_INCOMPLETE".into(),
            evidence_artifact_ids: vec![],
        }),
        VerificationPrincipalKind::VerificationAuthority,
    );
    assert!(matches!(
        intake.capture(output(CheckerOutputRole::Detail, b"late result")),
        Err(VerificationOutputError::Binding)
    ));
}

#[test]
fn verification_output_replays_same_artifact_after_both_sqlcipher_owners_reopen() {
    let root = tempfile::tempdir().expect("test root");
    let (sealed, before) = {
        let fixture = Fixture::open(root.path());
        let sealed = fixture
            .intake()
            .capture(output(CheckerOutputRole::RawOutput, b"persisted output"))
            .expect("capture");
        let before = fixture
            .authority
            .lock()
            .expect("lock")
            .read_artifact(&sealed.artifact_id)
            .expect("read");
        (sealed, before)
    };
    let fixture = Fixture::open(root.path());
    assert_eq!(
        sealed,
        fixture
            .intake()
            .capture(output(CheckerOutputRole::RawOutput, b"persisted output"))
            .expect("replay after restart")
    );
    assert_eq!(
        before,
        fixture
            .authority
            .lock()
            .expect("lock")
            .read_artifact(&sealed.artifact_id)
            .expect("read")
    );
}
