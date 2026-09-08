use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactPrincipalKind, ArtifactSqlCipherKey,
    AuthenticatedArtifactPrincipal, SystemArtifactClock, canonical_artifact_set_manifest,
    canonical_request_digest as artifact_request_digest, content_address,
};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
    canonical_request_digest as task_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, Claim,
        ClaimSourceType, CreateArtifactSetCommand, Evidence, EvidenceProducerClass,
        EvidenceRelation, LineageBinding, ProducerIdentity, ProposeClaimCommand, Provenance,
        RecordEvidenceCommand, SealArtifactCommand, SealArtifactSetCommand, StageArtifactCommand,
        artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, RecordTaskVerificationCommand,
        SubmitTaskEvidenceCommand, TaskCommand, TaskSnapshot, TaskStatus, task_command,
        task_command_result,
    },
    verdict::v1::{
        ConfirmationClass, CreateFounderSupportingMaterialCommand, FounderSupportingMaterial,
        FounderSupportingMaterialCoverage, FounderSupportingMaterialRole, FounderVerdictDecision,
        IssueFounderVerdictCommand, ReworkDirective, RiskAcceptance, RiskCategory, VerdictScope,
    },
    verification::v1::{
        AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile,
        CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
        CriterionRequirement, CriterionResult, Discrepancy, DiscrepancySeverity, EvidenceCoverage,
        RecordCriterionResultCommand, StartVerificationRunCommand, UnverifiedItem,
        UnverifiedReason, VerificationArtifact, VerificationBinding, VerificationCommand,
        VerificationConclusion, VerificationProvenance, VerificationRequest, VerificationStatus,
        verification_command,
    },
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, VerdictPrincipalKind, VerdictReferenceRejection,
    VerdictReferenceResolver,
};
use egopulse_local_api::command_gateway::{
    CommandPortFailure, CommandPrincipal, FounderSupportingMaterialPort,
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, AuthenticatedVerificationPrincipal, CriterionPolicySnapshot,
    VerificationAuthority, VerificationAuthorityConfig, VerificationPrincipalKind,
    VerificationSqlCipherKey, canonical_checker_profile_digest,
    canonical_request_digest as verification_request_digest,
};
use prost::Message;
use prost_types::Timestamp;

use crate::artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle};
use crate::founder_material::{
    ArtifactAuthorityFounderSupportingMaterialSource, FounderSupportingMaterialBindingSource,
    FounderSupportingMaterialPolicy, GovernedFounderSupportingMaterialPort, MATERIAL_MEDIA_TYPE,
    MATERIAL_SCHEMA_VERSION, OwnerBoundFounderSupportingMaterialSource,
    canonical_material_request_digest, founder_supporting_material_artifact_id,
};
use crate::{
    ArtifactAuthorityReferenceSource, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig, ConfiguredFounderVerdictResolver,
    ConfiguredFounderVerdictResolverConfig, ConfiguredTaskTransitionGuard,
    DenyFounderTaskCommitEvidence, FounderVerificationEvidenceSource,
    VerificationAuthorityArtifactSource,
};

const FOUNDER_ID: &str = "founder:c04-material";
const OTHER_FOUNDER_ID: &str = "founder:c04-other";
const WORKSPACE_REF: &str = "workspace:c04-derived";
const SOURCE_REF: &str = "repository-baseline:c04-raw-source";
const SET_ID: &str = "artifact-set:c04";
const BASELINE_ID: &str = "repository-baseline:c04";
const ATTESTATION_ID: &str = "checker-attestation:c04";
const CLAIM_ID: &str = "claim:c04";
const EVIDENCE_ID: &str = "evidence:c04";
const VERIFICATION_ID: &str = "verification-artifact:c04";
const REQUEST_ID: &str = "verification-request:c04";
const RUN_ID: &str = "verification-run:c04";
const DISCREPANCY_ID: &str = "discrepancy:c04";
const UNVERIFIED_ID: &str = "unverified:c04";
const CONFIRMATION_REF: &str = "confirmation:c04";
const FOUNDER_AUTHORITY_KIND: &str = "FounderVerdictAuthority.FounderAuthority";

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["test:reviewed-task-input".to_owned()],
        })
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    task: Arc<Mutex<TaskAuthority>>,
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    verification: Arc<Mutex<VerificationAuthority>>,
    admission: DerivedWorkspaceAdmissionHandle,
    scope: VerdictScope,
    policy: FounderSupportingMaterialPolicy,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("isolated C04 test root");
        let mut task = open_task(root.path());
        let created = execute_task(
            &mut task,
            task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(metadata("task-create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "snapshot:c04".to_owned(),
                target_scope_ref: "scope:c04".to_owned(),
                acceptance_contract_ref: Some(reference("acceptance")),
                budget_profile_ref: Some(reference("budget")),
                work_capability_route: None,
            }),
            PrincipalKind::Founder,
            FOUNDER_ID,
        );
        let active = execute_task(
            &mut task,
            task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(metadata("task-activate")),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "task-run:c04".to_owned(),
            }),
            PrincipalKind::CollaborationControl,
            "collaboration-control:c04",
        );
        assert_eq!(active.revision, 2);

        let policy = material_policy();
        let (artifact, admission) = open_artifact(root.path(), &policy);
        let lineage = LineageBinding {
            task_id: active.task_id.clone(),
            // The run and its ArtifactSet bind the Active Task revision. The
            // later evidence and Verification write-backs advance Task twice.
            task_revision: active.revision,
            work_revision: active.work_revision,
            run_id: "run:c04".to_owned(),
            run_revision: 1,
            step_id: "step:c04".to_owned(),
            step_revision: 1,
            attempt_id: "attempt:c04".to_owned(),
            attempt_revision: 1,
            dispatch_id: "dispatch:c04".to_owned(),
            fencing_token: 1,
        };
        let manifest = seed_artifact_graph(&artifact, &admission, &lineage);

        let evidence_pending = execute_task(
            &mut task,
            task_command::Command::SubmitTaskEvidence(SubmitTaskEvidenceCommand {
                meta: Some(metadata("task-evidence")),
                task_id: active.task_id.clone(),
                expected_revision: active.revision,
                work_revision: active.work_revision,
                return_handoff_id: "return-handoff:c04".to_owned(),
                artifact_set_id: SET_ID.to_owned(),
            }),
            PrincipalKind::CollaborationControl,
            "collaboration-control:c04",
        );
        assert_eq!(
            evidence_pending.status,
            TaskStatus::VerificationPending as i32
        );
        assert_eq!(evidence_pending.revision, 3);

        let verification = open_verification(root.path(), Arc::clone(&artifact));
        let verification_artifact = seed_verification(&verification, &lineage, &manifest);
        let verdict_pending = execute_task(
            &mut task,
            task_command::Command::RecordTaskVerification(RecordTaskVerificationCommand {
                meta: Some(metadata("task-verification")),
                task_id: evidence_pending.task_id.clone(),
                expected_revision: evidence_pending.revision,
                work_revision: evidence_pending.work_revision,
                verification_artifact_id: VERIFICATION_ID.to_owned(),
            }),
            PrincipalKind::SegoVerification,
            "verification-authority:c04",
        );
        assert_eq!(verdict_pending.status, TaskStatus::VerdictPending as i32);
        assert_eq!(verdict_pending.revision, lineage.task_revision + 2);

        let scope = VerdictScope {
            task_id: verdict_pending.task_id.clone(),
            task_revision: verdict_pending.revision,
            work_revision: verdict_pending.work_revision,
            artifact_set_id: SET_ID.to_owned(),
            artifact_set_manifest: Some(manifest),
            verification_artifact_id: VERIFICATION_ID.to_owned(),
            verification_payload: verification_artifact.canonical_payload,
            acceptance_contract_ref: verdict_pending.acceptance_contract_ref,
        };
        Self {
            _root: root,
            task: Arc::new(Mutex::new(task)),
            artifact,
            verification,
            admission,
            scope,
            policy,
        }
    }

    fn owner_source(
        &self,
    ) -> Arc<
        OwnerBoundFounderSupportingMaterialSource<
            ConfiguredArtifactAdmissionGuard,
            SystemArtifactClock,
        >,
    > {
        let verification_source: Arc<dyn FounderVerificationEvidenceSource> = Arc::new(
            VerificationAuthorityArtifactSource::new_shared(Arc::clone(&self.verification)),
        );
        Arc::new(
            OwnerBoundFounderSupportingMaterialSource::new(
                Arc::clone(&self.task),
                verification_source,
                Arc::clone(&self.artifact),
                BTreeSet::from([FOUNDER_ID.to_owned()]),
            )
            .expect("production owner-bound material source"),
        )
    }

    fn port(
        &self,
    ) -> GovernedFounderSupportingMaterialPort<ConfiguredArtifactAdmissionGuard, SystemArtifactClock>
    {
        GovernedFounderSupportingMaterialPort::new(
            Arc::clone(&self.artifact),
            self.owner_source(),
            self.policy.clone(),
            self.admission.clone(),
        )
        .expect("production material port")
    }

    fn verdict_resolver(&self) -> ConfiguredFounderVerdictResolver {
        ConfiguredFounderVerdictResolver::new(ConfiguredFounderVerdictResolverConfig {
            verification_source: Box::new(VerificationAuthorityArtifactSource::new_shared(
                Arc::clone(&self.verification),
            )),
            task_commit_source: Box::new(DenyFounderTaskCommitEvidence),
            allowed_founder_principal_ids: BTreeSet::from([FOUNDER_ID.to_owned()]),
            authority_ref: "founder-verdict-authority:c04".to_owned(),
            authority_policy_ref: reference("founder-policy"),
            allowed_confirmation_proof_refs: BTreeSet::from([CONFIRMATION_REF.to_owned()]),
            non_overridable_gate_ids: BTreeSet::new(),
            confirmation_ttl: std::time::Duration::from_secs(600),
        })
        .expect("production verdict resolver")
        .with_supporting_material_source(
            Box::new(ArtifactAuthorityFounderSupportingMaterialSource::new(
                Arc::clone(&self.artifact),
            )),
            self.policy.clone(),
        )
        .expect("production supporting-material resolver")
    }
}

#[test]
fn real_authorities_reopen_and_exact_material_command_replays() {
    let fixture = Fixture::new();
    let command = material_command(
        "material:reopen",
        &fixture.scope,
        FounderSupportingMaterialRole::ReworkRequiredChanges,
        "Change the failing repository behavior and rerun the acceptance check.",
        rework_coverage(),
    );
    let first = fixture
        .port()
        .create(&command, &founder_command_principal())
        .expect("first real stage and seal");
    assert!(first.result.committed);
    assert!(!first.result.replayed);
    let artifact_count = fixture
        .artifact
        .lock()
        .expect("artifact lock")
        .inspect_store()
        .expect("artifact inspection")
        .artifact_count;

    // Close and reopen every durable owner used by the production binding.
    // The replay is resolved from their persisted state, not a retained mock.
    let Fixture {
        _root,
        task,
        artifact,
        verification,
        admission: _,
        scope: _,
        policy,
    } = fixture;
    drop(task);
    drop(verification);
    drop(artifact);
    let (artifact, admission) = open_artifact(_root.path(), &policy);
    let verification = open_verification(_root.path(), Arc::clone(&artifact));
    let task = Arc::new(Mutex::new(open_task(_root.path())));
    let verification_source: Arc<dyn FounderVerificationEvidenceSource> = Arc::new(
        VerificationAuthorityArtifactSource::new_shared(Arc::clone(&verification)),
    );
    let binding_source = Arc::new(
        OwnerBoundFounderSupportingMaterialSource::new(
            task,
            verification_source,
            Arc::clone(&artifact),
            BTreeSet::from([FOUNDER_ID.to_owned()]),
        )
        .expect("reopened production owner source"),
    );
    let port = GovernedFounderSupportingMaterialPort::new(
        Arc::clone(&artifact),
        binding_source,
        policy,
        admission,
    )
    .expect("reopened production material port");

    let replay = port
        .create(&command, &founder_command_principal())
        .expect("exact command replay after owner reopen");
    assert!(replay.result.committed);
    assert!(replay.result.replayed);
    assert_eq!(replay.result.artifact_id, first.result.artifact_id);
    assert_eq!(
        replay.result.canonical_payload,
        first.result.canonical_payload
    );
    assert_eq!(
        artifact
            .lock()
            .expect("artifact lock")
            .inspect_store()
            .expect("artifact inspection")
            .artifact_count,
        artifact_count
    );

    let mut changed = command.clone();
    changed.body.push_str(" Changed under the same identity.");
    seal_material_command(&mut changed);
    assert_eq!(
        port.create(&changed, &founder_command_principal()),
        Err(CommandPortFailure::IntegrityFailure)
    );
}

#[test]
fn owner_binding_and_stable_material_identity_reject_cross_scope_author_and_role() {
    let fixture = Fixture::new();
    let port = fixture.port();
    let base = material_command(
        "material:binding",
        &fixture.scope,
        FounderSupportingMaterialRole::ReworkRequiredChanges,
        "Apply the bounded required changes.",
        rework_coverage(),
    );

    for scope in [
        VerdictScope {
            task_id: "task:foreign".to_owned(),
            ..fixture.scope.clone()
        },
        VerdictScope {
            work_revision: fixture.scope.work_revision + 1,
            ..fixture.scope.clone()
        },
        VerdictScope {
            artifact_set_id: "artifact-set:foreign".to_owned(),
            ..fixture.scope.clone()
        },
    ] {
        let mut command = base.clone();
        command.scope = Some(scope);
        seal_material_command(&mut command);
        assert_eq!(
            port.create(&command, &founder_command_principal()),
            Err(CommandPortFailure::IntegrityFailure)
        );
    }

    let foreign_principal = CommandPrincipal {
        principal_id: OTHER_FOUNDER_ID.to_owned(),
        required_authority_principal_kinds: vec![FOUNDER_AUTHORITY_KIND.to_owned()],
    };
    assert_eq!(
        port.create(&base, &foreign_principal),
        Err(CommandPortFailure::IntegrityFailure)
    );

    let mut invalid_role = base.clone();
    invalid_role.role = FounderSupportingMaterialRole::Unspecified as i32;
    seal_material_command(&mut invalid_role);
    assert_eq!(
        port.create(&invalid_role, &founder_command_principal()),
        Err(CommandPortFailure::InvalidArgument)
    );
    let mut invalid_coverage = base.clone();
    invalid_coverage.coverage = Some(FounderSupportingMaterialCoverage {
        risk_category: RiskCategory::QualityResidual as i32,
        ..FounderSupportingMaterialCoverage::default()
    });
    seal_material_command(&mut invalid_coverage);
    assert_eq!(
        port.create(&invalid_coverage, &founder_command_principal()),
        Err(CommandPortFailure::InvalidArgument)
    );

    port.create(&base, &founder_command_principal())
        .expect("freeze stable material identity");
    for (role, coverage) in [
        (
            FounderSupportingMaterialRole::RiskRationale,
            risk_coverage(),
        ),
        (
            FounderSupportingMaterialRole::ReworkRequiredChanges,
            FounderSupportingMaterialCoverage {
                discrepancy_ids: vec!["discrepancy:other".to_owned()],
                ..rework_coverage()
            },
        ),
    ] {
        let mut replacement = base.clone();
        replacement.role = role as i32;
        replacement.coverage = Some(coverage);
        seal_material_command(&mut replacement);
        assert_eq!(
            port.create(&replacement, &founder_command_principal()),
            Err(CommandPortFailure::IntegrityFailure)
        );
    }
}

#[test]
fn production_resolver_accepts_real_rework_and_risk_materials() {
    let fixture = Fixture::new();
    let port = fixture.port();
    let rework = port
        .create(
            &material_command(
                "material:rework",
                &fixture.scope,
                FounderSupportingMaterialRole::ReworkRequiredChanges,
                "Correct the discrepancy and supply evidence for the unverified item.",
                rework_coverage(),
            ),
            &founder_command_principal(),
        )
        .expect("sealed rework material")
        .result;
    let rationale = port
        .create(
            &material_command(
                "material:rationale",
                &fixture.scope,
                FounderSupportingMaterialRole::RiskRationale,
                "The bounded residual risk is acceptable for this explicit decision.",
                risk_coverage(),
            ),
            &founder_command_principal(),
        )
        .expect("sealed risk rationale")
        .result;
    let control = port
        .create(
            &material_command(
                "material:control",
                &fixture.scope,
                FounderSupportingMaterialRole::CompensatingControl,
                "Keep the affected path disabled and monitor the stated discrepancy.",
                risk_coverage(),
            ),
            &founder_command_principal(),
        )
        .expect("sealed compensating control")
        .result;

    let resolver = fixture.verdict_resolver();
    let (rework_context, rework_auth) = resolver
        .resolve_issue(
            &rework_issue(&fixture.scope, &rework.artifact_id),
            &founder_verdict_principal(),
        )
        .expect("production resolver accepts sealed Rework material");
    assert_eq!(rework_context.scope, fixture.scope);
    assert!(rework_auth.evidence_refs.contains(&format!(
        "founder-supporting-material:{}@sealed",
        rework.artifact_id
    )));

    let (risk_context, risk_auth) = resolver
        .resolve_issue(
            &risk_accept_issue(&fixture.scope, &rationale.artifact_id, &control.artifact_id),
            &founder_verdict_principal(),
        )
        .expect("production resolver accepts rationale and compensating control");
    assert_eq!(
        risk_context.verification_conclusion,
        VerificationConclusion::Failed
    );
    assert_eq!(
        risk_auth.confirmation_class,
        ConfirmationClass::ElevatedRiskAcceptance
    );
    for artifact_id in [&rationale.artifact_id, &control.artifact_id] {
        assert!(
            risk_auth
                .evidence_refs
                .contains(&format!("founder-supporting-material:{artifact_id}@sealed"))
        );
    }
}

#[test]
fn production_resolver_rejects_unsealed_and_tampered_material_bytes() {
    let fixture = Fixture::new();
    let binding = fixture
        .owner_source()
        .bind(&fixture.scope, FOUNDER_ID)
        .expect("real owner binding");

    let unsealed_id = "material:unsealed";
    stage_manual_material(
        &fixture,
        unsealed_id,
        FounderSupportingMaterial {
            material_id: unsealed_id.to_owned(),
            schema_version: MATERIAL_SCHEMA_VERSION,
            role: FounderSupportingMaterialRole::ReworkRequiredChanges as i32,
            scope: Some(fixture.scope.clone()),
            lineage: Some(binding.lineage.clone()),
            authenticated_founder_principal_id: FOUNDER_ID.to_owned(),
            body: "This valid payload is intentionally left staged.".to_owned(),
            coverage: Some(rework_coverage()),
        }
        .encode_to_vec(),
        &binding,
        false,
    );
    let unsealed_error = fixture
        .verdict_resolver()
        .resolve_issue(
            &rework_issue(
                &fixture.scope,
                &founder_supporting_material_artifact_id(unsealed_id),
            ),
            &founder_verdict_principal(),
        )
        .expect_err("unsealed material must be rejected");
    assert_eq!(unsealed_error, VerdictReferenceRejection::IntegrityFailure);

    let tampered_id = "material:tampered";
    stage_manual_material(
        &fixture,
        tampered_id,
        // The descriptor digest truthfully covers these bytes, but the bytes
        // are not a canonical FounderSupportingMaterial message.
        b"\xff\x00tampered-founder-material".to_vec(),
        &binding,
        true,
    );
    let tampered_error = fixture
        .verdict_resolver()
        .resolve_issue(
            &rework_issue(
                &fixture.scope,
                &founder_supporting_material_artifact_id(tampered_id),
            ),
            &founder_verdict_principal(),
        )
        .expect_err("tampered material bytes must be rejected");
    assert_eq!(tampered_error, VerdictReferenceRejection::IntegrityFailure);
}

fn open_task(root: &std::path::Path) -> TaskAuthority {
    TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.join("task.db"),
            store_epoch: "c04-task".to_owned(),
            key: SqlCipherKey::new([0x41; 32]),
        },
        AllowCreation,
        ConfiguredTaskTransitionGuard::new(),
    )
    .expect("Task Authority")
}

fn open_artifact(
    root: &std::path::Path,
    policy: &FounderSupportingMaterialPolicy,
) -> (
    Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    DerivedWorkspaceAdmissionHandle,
) {
    let guard = ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
        allowed_workspace_refs: BTreeSet::from(["workspace:unrelated-static".to_owned()]),
        allowed_artifact_type_refs: vec![reference("input"), policy.type_contract_ref.clone()],
        allowed_transformation_contract_refs: vec![
            reference("capture"),
            policy.transformation_contract_ref.clone(),
        ],
        allowed_retention_profile_refs: vec![reference("retention")],
        allowed_claim_semantic_profile_refs: vec![reference("claim")],
        allowed_claim_acceptance_contract_refs: vec![reference("acceptance")],
        allowed_evidence_profile_refs: vec![reference("evidence")],
    })
    .expect("artifact admission guard");
    let admission = guard.derived_workspace_admission_handle();
    let authority = ArtifactAuthority::open(
        ArtifactAuthorityConfig {
            database_path: root.join("artifact.db"),
            blob_root: root.join("blobs"),
            store_epoch: "c04-artifact".to_owned(),
            key: ArtifactSqlCipherKey::new([0x42; 32]),
        },
        guard,
    )
    .expect("Artifact Authority");
    (Arc::new(Mutex::new(authority)), admission)
}

fn open_verification(
    root: &std::path::Path,
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
) -> Arc<Mutex<VerificationAuthority>> {
    let resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(artifact),
        vec![CriterionPolicySnapshot {
            criterion_id: "review".to_owned(),
            requirement: CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::ModelAssisted as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec!["checker:c04".to_owned()],
        }],
    )
    .expect("production artifact-backed Verification resolver");
    Arc::new(Mutex::new(
        VerificationAuthority::open(
            VerificationAuthorityConfig {
                database_path: root.join("verification.db"),
                store_epoch: "c04-verification".to_owned(),
                key: VerificationSqlCipherKey::new([0x43; 32]),
            },
            resolver,
        )
        .expect("Verification Authority"),
    ))
}

fn seed_artifact_graph(
    authority: &Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    admission: &DerivedWorkspaceAdmissionHandle,
    lineage: &LineageBinding,
) -> egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress {
    let _lease = admission
        .register(DerivedWorkspaceAdmissionBinding {
            workspace_ref: WORKSPACE_REF.to_owned(),
            lineage: lineage.clone(),
            source_binding_ref: SOURCE_REF.to_owned(),
        })
        .expect("exact derived workspace lease");
    let supervisor = artifact_principal(ArtifactPrincipalKind::AttemptSupervisor, "supervisor:c04");
    let owner = artifact_principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        "authority:artifact",
    );
    let collector = artifact_principal(ArtifactPrincipalKind::GovernedCollector, "collector:input");
    let mut authority = authority.lock().expect("artifact lock");
    for (id, semantic, bytes) in [
        (
            BASELINE_ID,
            ArtifactSemanticClass::RepositoryBaseline,
            b"sealed repository baseline".as_slice(),
        ),
        (
            ATTESTATION_ID,
            ArtifactSemanticClass::TypedExtension,
            b"sealed checker attestation".as_slice(),
        ),
    ] {
        let address = content_address(bytes);
        authority.put_blob(bytes, &address).expect("input blob");
        execute_artifact(
            &mut authority,
            artifact_command::Command::StageArtifact(StageArtifactCommand {
                metadata: Some(metadata(&format!("{id}:stage"))),
                candidate: Some(ArtifactDescriptor {
                    artifact_id: id.to_owned(),
                    semantic_class: semantic as i32,
                    type_contract_ref: Some(reference("input")),
                    media_type: "text/plain".to_owned(),
                    content: Some(address.clone()),
                    provenance: Some(Provenance {
                        lineage: Some(lineage.clone()),
                        producer: Some(producer(&supervisor)),
                        transformation_contract_ref: Some(reference("capture")),
                        workspace_ref: WORKSPACE_REF.to_owned(),
                        raw_source_ref: Some(SOURCE_REF.to_owned()),
                        ..Provenance::default()
                    }),
                    sensitivity_class: "local".to_owned(),
                    retention_profile_ref: Some(reference("retention")),
                    ..ArtifactDescriptor::default()
                }),
            }),
            &supervisor,
        );
        execute_artifact(
            &mut authority,
            artifact_command::Command::SealArtifact(SealArtifactCommand {
                metadata: Some(metadata(&format!("{id}:seal"))),
                artifact_id: id.to_owned(),
                expected_revision: 1,
                observed_content: Some(address),
            }),
            &owner,
        );
    }
    let statement = content_address(b"repository acceptance claim");
    authority
        .put_blob(b"repository acceptance claim", &statement)
        .expect("claim statement");
    execute_artifact(
        &mut authority,
        artifact_command::Command::ProposeClaim(ProposeClaimCommand {
            metadata: Some(metadata("claim:propose")),
            claim: Some(Claim {
                claim_id: CLAIM_ID.to_owned(),
                source_type: ClaimSourceType::CodeChange as i32,
                semantic_profile_ref: Some(reference("claim")),
                lineage: Some(lineage.clone()),
                subject_artifact_ids: vec![BASELINE_ID.to_owned()],
                acceptance_contract_ref: Some(reference("acceptance")),
                statement: Some(statement.clone()),
                proposer: Some(producer(&collector)),
                ..Claim::default()
            }),
        }),
        &collector,
    );
    execute_artifact(
        &mut authority,
        artifact_command::Command::RecordEvidence(RecordEvidenceCommand {
            metadata: Some(metadata("evidence:record")),
            evidence: Some(Evidence {
                evidence_id: EVIDENCE_ID.to_owned(),
                relation: EvidenceRelation::Supports as i32,
                claim_id: CLAIM_ID.to_owned(),
                artifact_ids: vec![BASELINE_ID.to_owned()],
                evidence_profile_ref: Some(reference("evidence")),
                lineage: Some(lineage.clone()),
                producer: Some(producer(&supervisor)),
                producer_class: EvidenceProducerClass::AttemptSupervisor as i32,
                independent_of_claim_proposer: true,
                coverage_descriptor: Some(statement),
                ..Evidence::default()
            }),
        }),
        &supervisor,
    );
    let mut set = ArtifactSet {
        artifact_set_id: SET_ID.to_owned(),
        lineage: Some(lineage.clone()),
        artifact_ids: vec![BASELINE_ID.to_owned(), ATTESTATION_ID.to_owned()],
        claim_ids: vec![CLAIM_ID.to_owned()],
        evidence_ids: vec![EVIDENCE_ID.to_owned()],
        ..ArtifactSet::default()
    };
    let manifest = content_address(&canonical_artifact_set_manifest(&set));
    authority
        .put_blob(&canonical_artifact_set_manifest(&set), &manifest)
        .expect("artifact set manifest");
    set.canonical_manifest = Some(manifest.clone());
    execute_artifact(
        &mut authority,
        artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
            metadata: Some(metadata("set:create")),
            artifact_set: Some(set),
        }),
        &collector,
    );
    execute_artifact(
        &mut authority,
        artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
            metadata: Some(metadata("set:seal")),
            artifact_set_id: SET_ID.to_owned(),
            expected_revision: 1,
            observed_manifest: Some(manifest.clone()),
        }),
        &owner,
    );
    manifest
}

fn seed_verification(
    authority: &Arc<Mutex<VerificationAuthority>>,
    lineage: &LineageBinding,
    manifest: &egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
) -> VerificationArtifact {
    let mut profile = CheckerProfile {
        checker_profile_id: "checker:c04".to_owned(),
        checker_id: "checker:c04".to_owned(),
        checker_version: "v1".to_owned(),
        input_contract_ref: Some(reference("acceptance")),
        output_contract_ref: Some(reference("checker-output")),
        supported_criterion_types: vec!["review".to_owned()],
        assurance_class: CheckerAssuranceClass::ModelAssisted as i32,
        sandbox_profile_ref: Some(reference("sandbox")),
        tool_policy_ref: Some(reference("tool-policy")),
        data_egress_policy_ref: Some(reference("local-only")),
        timeout_ms: 1_000,
        attestation_evidence_artifact_ids: vec![ATTESTATION_ID.to_owned()],
        ..CheckerProfile::default()
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    let profile_ref = ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    };
    let binding = VerificationBinding {
        lineage: Some(lineage.clone()),
        artifact_set_id: SET_ID.to_owned(),
        artifact_set_manifest: Some(manifest.clone()),
        claim_id: CLAIM_ID.to_owned(),
        claim_semantic_profile_ref: Some(reference("claim")),
        acceptance_contract_ref: Some(reference("acceptance")),
    };
    let authority_principal = verification_principal(
        VerificationPrincipalKind::VerificationAuthority,
        "verification-authority:c04",
        None,
    );
    let checker_principal = verification_principal(
        VerificationPrincipalKind::SegoChecker,
        "checker:c04",
        Some(profile.checker_profile_id.clone()),
    );
    let mut authority = authority.lock().expect("verification lock");
    execute_verification(
        &mut authority,
        verification_command::Command::AttestCheckerProfile(AttestCheckerProfileCommand {
            metadata: Some(metadata("verification:attest")),
            profile: Some(profile),
        }),
        &authority_principal,
    );
    execute_verification(
        &mut authority,
        verification_command::Command::CreateVerificationRequest(
            CreateVerificationRequestCommand {
                metadata: Some(metadata("verification:create")),
                request: Some(VerificationRequest {
                    verification_request_id: REQUEST_ID.to_owned(),
                    revision: 1,
                    status: VerificationStatus::Queued as i32,
                    verification_type: "task_acceptance".to_owned(),
                    binding: Some(binding.clone()),
                    criterion_ids: vec!["review".to_owned()],
                    checker_profile_refs: vec![profile_ref.clone()],
                    ..VerificationRequest::default()
                }),
            },
        ),
        &verification_principal(
            VerificationPrincipalKind::TaskAuthority,
            "task-authority:c04",
            None,
        ),
    );
    execute_verification(
        &mut authority,
        verification_command::Command::StartVerificationRun(StartVerificationRunCommand {
            metadata: Some(metadata("verification:start")),
            verification_request_id: REQUEST_ID.to_owned(),
            expected_request_revision: 1,
            verification_run_id: RUN_ID.to_owned(),
        }),
        &authority_principal,
    );
    let result = CriterionResult {
        criterion_result_id: "criterion-result:c04".to_owned(),
        criterion_id: "review".to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        outcome: CriterionOutcome::Failed as i32,
        assurance_class: CheckerAssuranceClass::ModelAssisted as i32,
        checker_profile_ref: Some(profile_ref.clone()),
        evidence_coverage: EvidenceCoverage::Complete as i32,
        evidence_ids: vec![EVIDENCE_ID.to_owned()],
        discrepancy_ids: vec![DISCREPANCY_ID.to_owned()],
        unverified_item_ids: vec![UNVERIFIED_ID.to_owned()],
        ..CriterionResult::default()
    };
    execute_verification(
        &mut authority,
        verification_command::Command::RecordCriterionResult(RecordCriterionResultCommand {
            metadata: Some(metadata("verification:record")),
            verification_run_id: RUN_ID.to_owned(),
            expected_run_revision: 1,
            result: Some(result.clone()),
        }),
        &checker_principal,
    );
    execute_verification(
        &mut authority,
        verification_command::Command::CompleteVerification(CompleteVerificationCommand {
            metadata: Some(metadata("verification:complete")),
            verification_run_id: RUN_ID.to_owned(),
            expected_run_revision: 2,
            artifact: Some(VerificationArtifact {
                verification_artifact_id: VERIFICATION_ID.to_owned(),
                version: 1,
                verification_request_id: REQUEST_ID.to_owned(),
                verification_run_id: RUN_ID.to_owned(),
                verification_type: "task_acceptance".to_owned(),
                binding: Some(binding),
                conclusion: VerificationConclusion::Failed as i32,
                overall_evidence_coverage: EvidenceCoverage::Complete as i32,
                criterion_results: vec![result],
                discrepancies: vec![Discrepancy {
                    discrepancy_id: DISCREPANCY_ID.to_owned(),
                    criterion_id: "review".to_owned(),
                    severity: DiscrepancySeverity::Major as i32,
                    evidence_ids: vec![EVIDENCE_ID.to_owned()],
                    description_artifact_id: BASELINE_ID.to_owned(),
                    suggested_fix_artifact_id: None,
                }],
                unverified_items: vec![UnverifiedItem {
                    unverified_item_id: UNVERIFIED_ID.to_owned(),
                    criterion_id: "review".to_owned(),
                    reason: UnverifiedReason::RequiresJudgement as i32,
                    evidence_ids: vec![EVIDENCE_ID.to_owned()],
                    context_artifact_id: Some(BASELINE_ID.to_owned()),
                }],
                provenance: Some(VerificationProvenance {
                    verifier_principal_id: authority_principal.principal_id.clone(),
                    checker_profile_refs: vec![profile_ref],
                    duration_ms: 10,
                    ..VerificationProvenance::default()
                }),
                ..VerificationArtifact::default()
            }),
        }),
        &authority_principal,
    );
    authority
        .verification_artifact(VERIFICATION_ID)
        .expect("read Verification artifact")
        .expect("durable Verification artifact")
}

fn stage_manual_material(
    fixture: &Fixture,
    material_id: &str,
    bytes: Vec<u8>,
    binding: &crate::founder_material::FounderSupportingMaterialBinding,
    seal: bool,
) {
    let address = content_address(&bytes);
    let artifact_id = founder_supporting_material_artifact_id(material_id);
    let _lease = fixture
        .admission
        .register(DerivedWorkspaceAdmissionBinding {
            workspace_ref: binding.workspace_ref.clone(),
            lineage: binding.lineage.clone(),
            source_binding_ref: binding.source_binding_ref.clone(),
        })
        .expect("manual material exact lease");
    let collector = artifact_principal(
        ArtifactPrincipalKind::GovernedCollector,
        &fixture.policy.collector_principal_id,
    );
    let owner = artifact_principal(
        ArtifactPrincipalKind::ArtifactAuthority,
        &fixture.policy.artifact_authority_principal_id,
    );
    let mut authority = fixture.artifact.lock().expect("artifact lock");
    authority.put_blob(&bytes, &address).expect("manual blob");
    execute_artifact(
        &mut authority,
        artifact_command::Command::StageArtifact(StageArtifactCommand {
            metadata: Some(metadata(&format!("manual:{material_id}:stage"))),
            candidate: Some(ArtifactDescriptor {
                artifact_id: artifact_id.clone(),
                semantic_class: ArtifactSemanticClass::TypedExtension as i32,
                type_contract_ref: Some(fixture.policy.type_contract_ref.clone()),
                media_type: MATERIAL_MEDIA_TYPE.to_owned(),
                content: Some(address.clone()),
                provenance: Some(Provenance {
                    lineage: Some(binding.lineage.clone()),
                    producer: Some(ProducerIdentity {
                        principal_kind: ArtifactPrincipalKind::GovernedCollector
                            .as_str()
                            .to_owned(),
                        principal_id: fixture.policy.collector_principal_id.clone(),
                        component_name: fixture.policy.component_name.clone(),
                        component_version: fixture.policy.component_version.clone(),
                        ..ProducerIdentity::default()
                    }),
                    input_artifact_ids: binding.input_artifact_ids.clone(),
                    transformation_contract_ref: Some(
                        fixture.policy.transformation_contract_ref.clone(),
                    ),
                    workspace_ref: binding.workspace_ref.clone(),
                    raw_source_ref: Some(binding.source_binding_ref.clone()),
                    ..Provenance::default()
                }),
                sensitivity_class: fixture.policy.sensitivity_class.clone(),
                retention_profile_ref: Some(fixture.policy.retention_profile_ref.clone()),
                ..ArtifactDescriptor::default()
            }),
        }),
        &collector,
    );
    if seal {
        execute_artifact(
            &mut authority,
            artifact_command::Command::SealArtifact(SealArtifactCommand {
                metadata: Some(metadata(&format!("manual:{material_id}:seal"))),
                artifact_id,
                expected_revision: 1,
                observed_content: Some(address),
            }),
            &owner,
        );
    }
}

fn execute_task(
    authority: &mut TaskAuthority,
    operation: task_command::Command,
    kind: PrincipalKind,
    principal_id: &str,
) -> TaskSnapshot {
    let mut command = TaskCommand {
        command: Some(operation),
    };
    let digest = task_request_digest(&command).expect("Task request digest");
    match command.command.as_mut().expect("Task operation") {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        task_command::Command::RecordTaskVerification(value) => value.meta.as_mut(),
        _ => unreachable!("C04 fixture uses four Task transitions"),
    }
    .expect("Task metadata")
    .request_digest_sha256 = digest;
    let result = authority
        .execute(
            &command,
            &AuthenticatedPrincipal {
                kind,
                principal_id: principal_id.to_owned(),
                authenticated: true,
            },
        )
        .expect("Task command");
    match result.outcome.expect("Task outcome") {
        task_command_result::Outcome::Task(snapshot) => snapshot,
        task_command_result::Outcome::Error(error) => panic!("Task rejected: {error:?}"),
    }
}

fn execute_artifact(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    operation: artifact_command::Command,
    principal: &AuthenticatedArtifactPrincipal,
) {
    let mut command = ArtifactCommand {
        command: Some(operation),
    };
    let digest = artifact_request_digest(&command).expect("Artifact request digest");
    match command.command.as_mut().expect("Artifact operation") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        _ => unreachable!("C04 fixture Artifact operation"),
    }
    .expect("Artifact metadata")
    .request_digest_sha256 = digest;
    let result = authority
        .execute(&command, principal)
        .expect("Artifact command");
    assert!(
        result.committed || result.replayed,
        "Artifact command rejected: {result:?}"
    );
}

fn execute_verification(
    authority: &mut VerificationAuthority,
    operation: verification_command::Command,
    principal: &AuthenticatedVerificationPrincipal,
) {
    let mut command = VerificationCommand {
        command: Some(operation),
    };
    let digest = verification_request_digest(&command).expect("Verification request digest");
    match command.command.as_mut().expect("Verification operation") {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        verification_command::Command::CreateVerificationRequest(value) => value.metadata.as_mut(),
        verification_command::Command::StartVerificationRun(value) => value.metadata.as_mut(),
        verification_command::Command::RecordCriterionResult(value) => value.metadata.as_mut(),
        verification_command::Command::CompleteVerification(value) => value.metadata.as_mut(),
        _ => unreachable!("C04 fixture Verification operation"),
    }
    .expect("Verification metadata")
    .request_digest_sha256 = digest;
    let result = authority
        .execute(&command, principal)
        .expect("Verification command");
    assert!(
        result.committed || result.replayed,
        "Verification command rejected: {result:?}"
    );
}

fn material_command(
    material_id: &str,
    scope: &VerdictScope,
    role: FounderSupportingMaterialRole,
    body: &str,
    coverage: FounderSupportingMaterialCoverage,
) -> CreateFounderSupportingMaterialCommand {
    let mut command = CreateFounderSupportingMaterialCommand {
        metadata: Some(metadata(&format!("material:{material_id}"))),
        material_id: material_id.to_owned(),
        scope: Some(scope.clone()),
        role: role as i32,
        body: body.to_owned(),
        coverage: Some(coverage),
    };
    seal_material_command(&mut command);
    command
}

fn seal_material_command(command: &mut CreateFounderSupportingMaterialCommand) {
    let digest = canonical_material_request_digest(command).expect("material request digest");
    command
        .metadata
        .as_mut()
        .expect("material metadata")
        .request_digest_sha256 = digest;
}

fn rework_issue(scope: &VerdictScope, artifact_id: &str) -> IssueFounderVerdictCommand {
    IssueFounderVerdictCommand {
        metadata: Some(metadata("verdict:rework")),
        scope: Some(scope.clone()),
        decision: FounderVerdictDecision::Rework as i32,
        observed_verification_conclusion: VerificationConclusion::Failed as i32,
        required_confirmation_class: ConfirmationClass::Explicit as i32,
        confirmation_proof_ref: CONFIRMATION_REF.to_owned(),
        rework_directive: Some(ReworkDirective {
            directive_id: "directive:c04".to_owned(),
            reason_code: "VERIFICATION_FAILED".to_owned(),
            required_changes_artifact_id: artifact_id.to_owned(),
            target_discrepancy_ids: vec![DISCREPANCY_ID.to_owned()],
            target_unverified_item_ids: vec![UNVERIFIED_ID.to_owned()],
        }),
        expires_at: Some(expiry()),
        ..IssueFounderVerdictCommand::default()
    }
}

fn risk_accept_issue(
    scope: &VerdictScope,
    rationale_artifact_id: &str,
    control_artifact_id: &str,
) -> IssueFounderVerdictCommand {
    IssueFounderVerdictCommand {
        metadata: Some(metadata("verdict:risk-accept")),
        scope: Some(scope.clone()),
        decision: FounderVerdictDecision::Accept as i32,
        observed_verification_conclusion: VerificationConclusion::Failed as i32,
        required_confirmation_class: ConfirmationClass::ElevatedRiskAcceptance as i32,
        confirmation_proof_ref: CONFIRMATION_REF.to_owned(),
        risk_acceptances: vec![RiskAcceptance {
            risk_acceptance_id: "risk:c04".to_owned(),
            category: RiskCategory::QualityResidual as i32,
            discrepancy_ids: vec![DISCREPANCY_ID.to_owned()],
            unverified_item_ids: vec![UNVERIFIED_ID.to_owned()],
            rationale_artifact_id: rationale_artifact_id.to_owned(),
            compensating_control_artifact_ids: vec![control_artifact_id.to_owned()],
            review_trigger_code: Some("REVIEW_AFTER_REPAIR".to_owned()),
        }],
        expires_at: Some(expiry()),
        ..IssueFounderVerdictCommand::default()
    }
}

fn rework_coverage() -> FounderSupportingMaterialCoverage {
    FounderSupportingMaterialCoverage {
        risk_category: RiskCategory::Unspecified as i32,
        discrepancy_ids: vec![DISCREPANCY_ID.to_owned()],
        unverified_item_ids: vec![UNVERIFIED_ID.to_owned()],
    }
}

fn risk_coverage() -> FounderSupportingMaterialCoverage {
    FounderSupportingMaterialCoverage {
        risk_category: RiskCategory::QualityResidual as i32,
        discrepancy_ids: vec![DISCREPANCY_ID.to_owned()],
        unverified_item_ids: vec![UNVERIFIED_ID.to_owned()],
    }
}

fn material_policy() -> FounderSupportingMaterialPolicy {
    FounderSupportingMaterialPolicy {
        type_contract_ref: reference("founder-supporting-material"),
        transformation_contract_ref: reference("founder-material-collection"),
        retention_profile_ref: reference("retention"),
        collector_principal_id: "collector:founder-material".to_owned(),
        artifact_authority_principal_id: "authority:artifact".to_owned(),
        component_name: "agentosd-founder-material".to_owned(),
        component_version: "v1".to_owned(),
        sensitivity_class: "local".to_owned(),
    }
}

fn reference(id: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: "a".repeat(64),
    }
}

fn metadata(label: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command:{label}"),
        idempotency_key: format!("key:{label}"),
        idempotency_scope: "c04-founder-material-tests".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: format!("correlation:{label}"),
        causation_id: None,
    }
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch");
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).expect("timestamp fits i64"),
        nanos: i32::try_from(duration.subsec_nanos()).expect("nanoseconds fit i32"),
    }
}

fn expiry() -> Timestamp {
    let mut value = now();
    value.seconds += 300;
    value
}

fn founder_command_principal() -> CommandPrincipal {
    CommandPrincipal {
        principal_id: FOUNDER_ID.to_owned(),
        required_authority_principal_kinds: vec![FOUNDER_AUTHORITY_KIND.to_owned()],
    }
}

fn founder_verdict_principal() -> AuthenticatedVerdictPrincipal {
    AuthenticatedVerdictPrincipal {
        kind: VerdictPrincipalKind::FounderAuthority,
        principal_id: FOUNDER_ID.to_owned(),
        authenticated: true,
    }
}

fn artifact_principal(
    kind: ArtifactPrincipalKind,
    principal_id: &str,
) -> AuthenticatedArtifactPrincipal {
    AuthenticatedArtifactPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
    }
}

fn producer(principal: &AuthenticatedArtifactPrincipal) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: principal.kind.as_str().to_owned(),
        principal_id: principal.principal_id.clone(),
        component_name: "c04-owner-fixture".to_owned(),
        component_version: "v1".to_owned(),
        ..ProducerIdentity::default()
    }
}

fn verification_principal(
    kind: VerificationPrincipalKind,
    principal_id: &str,
    checker_profile_id: Option<String>,
) -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind,
        principal_id: principal_id.to_owned(),
        authenticated: true,
        checker_profile_id,
    }
}
