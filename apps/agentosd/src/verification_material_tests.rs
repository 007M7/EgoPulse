use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactAuthorityConfig, ArtifactPrincipalKind, ArtifactSqlCipherKey,
    AuthenticatedArtifactPrincipal, canonical_artifact_set_manifest, canonical_request_digest,
    content_address,
};
use egopulse_cognition_runtime::{
    context_authority::{
        AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityConfig,
        ContextPrincipalKind, IssueContextSnapshot,
    },
    task_authority::SqlCipherKey,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSet, Claim,
        ClaimSourceType, CreateArtifactSetCommand, Evidence, EvidenceProducerClass,
        EvidenceRelation, IntegrityStatus, LineageBinding, ProducerIdentity, ProposeClaimCommand,
        Provenance, RecordEvidenceCommand, SealArtifactCommand, SealArtifactSetCommand,
        StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    verification::v1::VerificationBinding,
};
use egopulse_process_supervision::{
    GovernedProcessBudget, GovernedProcessError, GovernedProcessReceipt, SupervisedProcessSpec,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactAuthorityReferenceSource, ConfiguredArtifactAdmissionGuard,
    ConfiguredArtifactAdmissionGuardConfig,
    artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle},
    repository_command::{
        RepositoryCommandArtifactConfig, RepositoryCommandArtifactRunner,
        RepositoryCommandExecutionOutcome, RepositoryCommandExecutionRequest,
        RepositoryCommandProcessExecutor,
    },
    repository_dispatch::{
        FinalWorkspaceManifestEntry, FinalWorkspaceManifestPayload,
        InitialWorkspaceManifestPayload, RepositoryBaselinePayload, derived_workspace_ref,
        repository_source_binding_ref,
    },
    repository_material::{
        FrozenContractReference, FrozenRepositoryMaterialV1, RepositoryAcceptanceCommandV1,
        RepositoryAcceptanceContractV1, RepositoryCommandRequirement,
        RepositoryEvidenceRequirement,
    },
    verification_material::{
        RepositoryCommandObservationOutcome, RepositoryVerificationMaterialPolicy,
        RepositoryVerificationMaterialResolver, VerificationMaterialError,
    },
};

const BASELINE_COMMIT: &str = "1111111111111111111111111111111111111111";
const BASELINE_TREE: &str = "2222222222222222222222222222222222222222";
const TASK_ID: &str = "task:verification-material";
const DISPATCH_ID: &str = "dispatch:verification-material";
const SET_ID: &str = "artifact-set:verification-material";
const CLAIM_ID: &str = "claim:verification-material";

#[derive(Clone, Copy)]
struct PassingExecutor;

impl RepositoryCommandProcessExecutor for PassingExecutor {
    fn execute<'a>(
        &'a self,
        _spec: &'a SupervisedProcessSpec,
        _budget: GovernedProcessBudget,
    ) -> Pin<
        Box<dyn Future<Output = Result<GovernedProcessReceipt, GovernedProcessError>> + Send + 'a>,
    > {
        Box::pin(async {
            Ok(GovernedProcessReceipt {
                stdout: b"one test passed\n".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
                duration_ms: 7,
            })
        })
    }
}

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    pub(super) context: Arc<Mutex<ContextAuthority>>,
    pub(super) artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    pub(super) admission: DerivedWorkspaceAdmissionHandle,
    pub(super) workspace_base: PathBuf,
    pub(super) contract_path: PathBuf,
    pub(super) policy: RepositoryVerificationMaterialPolicy,
    pub(super) binding: VerificationBinding,
    pub(super) frozen: FrozenRepositoryMaterialV1,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let root = tempfile::tempdir().expect("verification material fixture root");
        let repository_root = root.path().join("source");
        let workspace_base = root.path().join("workspaces");
        let git_common_dir = root.path().join("git-common");
        std::fs::create_dir_all(&repository_root).expect("source root");
        std::fs::create_dir_all(&workspace_base).expect("workspace base");
        std::fs::create_dir_all(&git_common_dir).expect("git common dir");
        let repository_root = repository_root.canonicalize().expect("canonical source");
        let workspace_base = workspace_base.canonicalize().expect("canonical workspaces");
        let git_common_dir = git_common_dir
            .canonicalize()
            .expect("canonical git common dir");
        let contract_path = root.path().join("acceptance-contract.json");
        let executable = std::env::current_exe()
            .expect("test executable")
            .canonicalize()
            .expect("canonical test executable");

        let command = RepositoryAcceptanceCommandV1 {
            command_id: "tests-primary".to_owned(),
            criterion_id: "tests".to_owned(),
            requirement: RepositoryCommandRequirement::MustPass,
            executable: path_text(&executable),
            argv: vec!["--fixture-does-not-run".to_owned()],
            cwd: ".".to_owned(),
            inherited_environment: Vec::new(),
            environment_overrides: BTreeMap::new(),
            timeout_seconds: 30,
            output_limit_bytes: 4096,
            expected_exit_code: 0,
        };
        let contract = RepositoryAcceptanceContractV1 {
            schema_version: "repository_change_acceptance/v1".to_owned(),
            contract_id: "repository-acceptance".to_owned(),
            version: "v1".to_owned(),
            revision: 1,
            allowed_paths: vec!["src".to_owned()],
            forbidden_paths: vec![".github".to_owned()],
            read_only_paths: vec!["contracts".to_owned()],
            required_commands: vec![command.clone()],
            evidence_requirements: vec![
                RepositoryEvidenceRequirement::RepositoryBaseline,
                RepositoryEvidenceRequirement::RepositoryPatch,
                RepositoryEvidenceRequirement::WorkspaceManifest,
                RepositoryEvidenceRequirement::CommandReceipt,
                RepositoryEvidenceRequirement::IndependentChecker,
            ],
        };
        let contract_bytes = serde_json::to_vec(&contract).expect("canonical contract");
        std::fs::write(&contract_path, &contract_bytes).expect("live contract fixture");
        let contract_path = contract_path
            .canonicalize()
            .expect("canonical contract path");
        let acceptance_ref = ContractReference {
            contract_id: contract.contract_id.clone(),
            version: contract.version.clone(),
            sha256: sha256(&contract_bytes),
        };
        let frozen = FrozenRepositoryMaterialV1 {
            schema_version: "egopulse.repository-material/v1".to_owned(),
            contract_path: path_text(&contract_path),
            repository_root: path_text(&repository_root),
            git_executable: path_text(&executable),
            acceptance_contract_ref: FrozenContractReference {
                contract_id: acceptance_ref.contract_id.clone(),
                version: acceptance_ref.version.clone(),
                sha256: acceptance_ref.sha256.clone(),
            },
            acceptance_contract: contract,
            baseline_commit: BASELINE_COMMIT.to_owned(),
            baseline_tree: BASELINE_TREE.to_owned(),
            git_common_dir: path_text(&git_common_dir),
            clean_worktree: true,
        };
        let compiled_context = serde_json::to_vec(&serde_json::json!({
            "prompt": "fix the bounded repository defect",
            "repository_material_version": 1,
            "repository_material": frozen,
        }))
        .expect("compiled Context");
        let context = Arc::new(Mutex::new(
            ContextAuthority::open(ContextAuthorityConfig {
                database_path: root.path().join("context.db"),
                store_epoch: "verification-material-context".to_owned(),
                key: SqlCipherKey::new([0x61; 32]),
            })
            .expect("Context Authority"),
        ));
        let now = unix_seconds();
        let (_, snapshot) = context
            .lock()
            .expect("Context lock")
            .issue(
                &IssueContextSnapshot {
                    owner_principal_id: "founder:verification-material".to_owned(),
                    intent: "fix the bounded repository defect".to_owned(),
                    work_type: "governed_repository_change".to_owned(),
                    target_scope_ref: "project:fixture".to_owned(),
                    compiled_context,
                    sources: Vec::new(),
                    memory_pack: None,
                    allowed_read_paths: vec!["src".to_owned()],
                    allowed_write_paths: vec!["src".to_owned()],
                    allowed_tools: vec!["git".to_owned()],
                    external_resources: Vec::new(),
                    non_goals: vec!["no release".to_owned()],
                    acceptance_contract_ref: "repository-acceptance:v1".to_owned(),
                    budget_profile_ref: "budget:fixture".to_owned(),
                    deadline_seconds: None,
                    recovery_entry: "hold-and-reconcile".to_owned(),
                    visibility: "founder-only".to_owned(),
                    redactions: Vec::new(),
                    expires_at_seconds: now + 3600,
                    idempotency_key: "verification-material-context".to_owned(),
                },
                &AuthenticatedContextPrincipal {
                    kind: ContextPrincipalKind::ContextCompiler,
                    principal_id: "context-compiler:verification-material".to_owned(),
                    authenticated: true,
                },
            )
            .expect("issue frozen Context");

        let lineage = fixture_lineage();
        let workspace_ref = derived_workspace_ref(TASK_ID, &snapshot.snapshot_id, BASELINE_COMMIT);
        let workspace_root = workspace_base.join(&workspace_ref);
        std::fs::create_dir(&workspace_root).expect("derived workspace");
        let baseline_payload = RepositoryBaselinePayload {
            schema_version: "egopulse.repository-baseline/v1".to_owned(),
            task_id: lineage.task_id.clone(),
            task_revision: lineage.task_revision,
            work_revision: lineage.work_revision,
            input_snapshot_id: snapshot.snapshot_id.clone(),
            input_bundle_sha256: snapshot.compiled_context_sha256.clone(),
            workspace_ref: workspace_ref.clone(),
            contract_id: acceptance_ref.contract_id.clone(),
            contract_version: acceptance_ref.version.clone(),
            contract_sha256: acceptance_ref.sha256.clone(),
            baseline_commit: BASELINE_COMMIT.to_owned(),
            baseline_tree: BASELINE_TREE.to_owned(),
        };
        let source_binding_ref = repository_source_binding_ref(
            &baseline_payload,
            &lineage,
            &snapshot.compiled_context_sha256,
        );

        let policy = material_policy();
        let (artifact, admission) = open_artifact(root.path(), &policy, &acceptance_ref);
        let _lease = admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: workspace_ref.clone(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.clone(),
            })
            .expect("exact workspace admission");
        let baseline_id = format!("artifact:repository-baseline:{DISPATCH_ID}");
        let initial_id = format!("artifact:workspace-initial:{DISPATCH_ID}");
        let patch_id = format!("artifact:repository-patch:{DISPATCH_ID}");
        let final_id = format!("artifact:workspace-final:{DISPATCH_ID}");
        let baseline_bytes = serde_json::to_vec(&baseline_payload).expect("baseline bytes");
        stage_repository_artifact(
            &artifact,
            &policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &baseline_id,
            ArtifactSemanticClass::RepositoryBaseline,
            Vec::new(),
            baseline_bytes,
        );
        let initial_bytes = serde_json::to_vec(&InitialWorkspaceManifestPayload {
            schema_version: "egopulse.workspace-initial-manifest/v1".to_owned(),
            task_id: lineage.task_id.clone(),
            task_revision: lineage.task_revision,
            work_revision: lineage.work_revision,
            run_id: lineage.run_id.clone(),
            run_revision: lineage.run_revision,
            step_id: lineage.step_id.clone(),
            step_revision: lineage.step_revision,
            attempt_id: lineage.attempt_id.clone(),
            attempt_revision: lineage.attempt_revision,
            dispatch_id: lineage.dispatch_id.clone(),
            fencing_token: lineage.fencing_token,
            input_snapshot_id: snapshot.snapshot_id,
            input_bundle_sha256: snapshot.compiled_context_sha256,
            workspace_ref: workspace_ref.clone(),
            baseline_commit: BASELINE_COMMIT.to_owned(),
            baseline_tree: BASELINE_TREE.to_owned(),
            status_porcelain_sha256: sha256(&[]),
            clean: true,
        })
        .expect("initial manifest bytes");
        stage_repository_artifact(
            &artifact,
            &policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &initial_id,
            ArtifactSemanticClass::WorkspaceManifest,
            vec![baseline_id.clone()],
            initial_bytes,
        );
        let patch_bytes = b"diff --git a/src/lib.rs b/src/lib.rs\n".to_vec();
        let patch_address = content_address(&patch_bytes);
        stage_repository_artifact(
            &artifact,
            &policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &patch_id,
            ArtifactSemanticClass::RepositoryPatch,
            vec![baseline_id.clone(), initial_id.clone()],
            patch_bytes,
        );
        let final_bytes = serde_json::to_vec(&FinalWorkspaceManifestPayload {
            schema_version: "egopulse.workspace-final-manifest/v1".to_owned(),
            workspace_ref: workspace_ref.clone(),
            baseline_commit: BASELINE_COMMIT.to_owned(),
            baseline_tree: BASELINE_TREE.to_owned(),
            observed_head_commit: BASELINE_COMMIT.to_owned(),
            observed_head_tree: BASELINE_TREE.to_owned(),
            status_porcelain_sha256: "3".repeat(64),
            status_porcelain_bytes: 12,
            patch_sha256: patch_address.digest.clone(),
            patch_bytes: patch_address.byte_length,
            entries: vec![FinalWorkspaceManifestEntry {
                status: "M".to_owned(),
                path_hex: hex::encode("src/lib.rs"),
            }],
        })
        .expect("final manifest bytes");
        stage_repository_artifact(
            &artifact,
            &policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &final_id,
            ArtifactSemanticClass::WorkspaceManifest,
            vec![baseline_id.clone(), initial_id.clone(), patch_id.clone()],
            final_bytes,
        );

        let command_inputs = vec![
            baseline_id.clone(),
            initial_id.clone(),
            patch_id.clone(),
            final_id.clone(),
        ];
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&artifact),
            command_config(&policy),
            PassingExecutor,
        )
        .expect("repository command runner");
        let receipt = match runner
            .execute(RepositoryCommandExecutionRequest {
                material: &frozen,
                command: &command,
                lineage: lineage.clone(),
                workspace_root: &workspace_root,
                workspace_ref: &workspace_ref,
                source_binding_ref: &source_binding_ref,
                input_artifact_ids: &command_inputs,
            })
            .await
            .expect("command helper")
        {
            RepositoryCommandExecutionOutcome::Completed(receipt) => receipt,
            other => panic!("expected completed command receipt, got {other:?}"),
        };

        let statement_bytes = b"repository return is ready for independent verification";
        let statement = content_address(statement_bytes);
        let coverage_repository = content_address(b"baseline patch and manifests captured");
        let coverage_command = content_address(b"supervised tests command completed");
        {
            let mut authority = artifact.lock().expect("Artifact lock");
            authority
                .put_blob(statement_bytes, &statement)
                .expect("claim statement");
            authority
                .put_blob(
                    b"baseline patch and manifests captured",
                    &coverage_repository,
                )
                .expect("repository coverage");
            authority
                .put_blob(b"supervised tests command completed", &coverage_command)
                .expect("command coverage");
            execute_artifact(
                &mut authority,
                artifact_command::Command::ProposeClaim(ProposeClaimCommand {
                    metadata: Some(metadata("claim", "propose")),
                    claim: Some(Claim {
                        claim_id: CLAIM_ID.to_owned(),
                        source_type: ClaimSourceType::CodeChange as i32,
                        semantic_profile_ref: Some(claim_profile_ref()),
                        lineage: Some(lineage.clone()),
                        subject_artifact_ids: vec![
                            baseline_id.clone(),
                            patch_id.clone(),
                            final_id.clone(),
                            receipt.artifact_id.clone(),
                        ],
                        acceptance_contract_ref: Some(acceptance_ref.clone()),
                        statement: Some(statement),
                        proposer: Some(producer(
                            ArtifactPrincipalKind::GovernedCollector,
                            &policy.governed_collector_principal_id,
                            "agentosd-return-collector",
                        )),
                        ..Default::default()
                    }),
                }),
                ArtifactPrincipalKind::GovernedCollector,
                &policy.governed_collector_principal_id,
            );
            record_evidence(
                &mut authority,
                &policy,
                &lineage,
                CLAIM_ID,
                "evidence:repository-material",
                vec![
                    baseline_id.clone(),
                    initial_id.clone(),
                    patch_id.clone(),
                    final_id.clone(),
                ],
                EvidenceProducerClass::AttemptSupervisor,
                &policy.attempt_supervisor_principal_id,
                coverage_repository,
            );
            record_evidence(
                &mut authority,
                &policy,
                &lineage,
                CLAIM_ID,
                "evidence:command-receipt",
                vec![receipt.artifact_id.clone()],
                EvidenceProducerClass::SupervisedRunner,
                &policy.supervised_runner_principal_id,
                coverage_command,
            );
            let mut set = ArtifactSet {
                artifact_set_id: SET_ID.to_owned(),
                lineage: Some(lineage.clone()),
                artifact_ids: vec![
                    baseline_id,
                    initial_id,
                    patch_id,
                    final_id,
                    receipt.artifact_id,
                ],
                claim_ids: vec![CLAIM_ID.to_owned()],
                evidence_ids: vec![
                    "evidence:repository-material".to_owned(),
                    "evidence:command-receipt".to_owned(),
                ],
                ..Default::default()
            };
            let manifest_bytes = canonical_artifact_set_manifest(&set);
            let manifest = content_address(&manifest_bytes);
            authority
                .put_blob(&manifest_bytes, &manifest)
                .expect("set manifest blob");
            set.canonical_manifest = Some(manifest.clone());
            execute_artifact(
                &mut authority,
                artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
                    metadata: Some(metadata("set", "create")),
                    artifact_set: Some(set),
                }),
                ArtifactPrincipalKind::GovernedCollector,
                &policy.governed_collector_principal_id,
            );
            execute_artifact(
                &mut authority,
                artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
                    metadata: Some(metadata("set", "seal")),
                    artifact_set_id: SET_ID.to_owned(),
                    expected_revision: 1,
                    observed_manifest: Some(manifest.clone()),
                }),
                ArtifactPrincipalKind::ArtifactAuthority,
                "authority:artifact",
            );
            let binding = VerificationBinding {
                lineage: Some(lineage),
                artifact_set_id: SET_ID.to_owned(),
                artifact_set_manifest: Some(manifest),
                claim_id: CLAIM_ID.to_owned(),
                claim_semantic_profile_ref: Some(claim_profile_ref()),
                acceptance_contract_ref: Some(acceptance_ref),
            };
            drop(authority);
            Self {
                root,
                context,
                artifact,
                admission,
                workspace_base,
                contract_path,
                policy,
                binding,
                frozen,
            }
        }
    }

    pub(super) fn resolver(&self) -> RepositoryVerificationMaterialResolver {
        RepositoryVerificationMaterialResolver::new(
            Arc::clone(&self.context),
            Arc::new(ArtifactAuthorityReferenceSource::new_shared(Arc::clone(
                &self.artifact,
            ))),
            self.workspace_base.clone(),
            self.policy.clone(),
        )
        .expect("verification material resolver")
    }

    pub(super) async fn seed_second_task(&self) -> VerificationBinding {
        let first = self
            .resolver()
            .resolve(&self.binding, unix_seconds())
            .expect("first sealed material");
        let task_id = "task:verification-material:second";
        let dispatch_id = "dispatch:verification-material:second";
        let set_id = "artifact-set:verification-material:second";
        let claim_id = "claim:verification-material:second";
        let lineage = fixture_lineage_for(task_id, dispatch_id, 5);
        let workspace_ref = derived_workspace_ref(
            task_id,
            &first.baseline.input_snapshot_id,
            &first.baseline.baseline_commit,
        );
        let workspace_root = self.workspace_base.join(&workspace_ref);
        std::fs::create_dir(&workspace_root).expect("second derived workspace");
        let acceptance_ref = self.frozen.acceptance_contract_ref();
        let baseline_payload = RepositoryBaselinePayload {
            schema_version: "egopulse.repository-baseline/v1".to_owned(),
            task_id: task_id.to_owned(),
            task_revision: lineage.task_revision,
            work_revision: lineage.work_revision,
            input_snapshot_id: first.baseline.input_snapshot_id.clone(),
            input_bundle_sha256: first.baseline.input_bundle_sha256.clone(),
            workspace_ref: workspace_ref.clone(),
            contract_id: acceptance_ref.contract_id.clone(),
            contract_version: acceptance_ref.version.clone(),
            contract_sha256: acceptance_ref.sha256.clone(),
            baseline_commit: first.baseline.baseline_commit.clone(),
            baseline_tree: first.baseline.baseline_tree.clone(),
        };
        let source_binding_ref = repository_source_binding_ref(
            &baseline_payload,
            &lineage,
            &first.baseline.input_bundle_sha256,
        );
        let _lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: workspace_ref.clone(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.clone(),
            })
            .expect("second exact workspace admission");
        let baseline_id = format!("artifact:repository-baseline:{dispatch_id}");
        let initial_id = format!("artifact:workspace-initial:{dispatch_id}");
        let patch_id = format!("artifact:repository-patch:{dispatch_id}");
        let final_id = format!("artifact:workspace-final:{dispatch_id}");
        stage_repository_artifact(
            &self.artifact,
            &self.policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &baseline_id,
            ArtifactSemanticClass::RepositoryBaseline,
            Vec::new(),
            serde_json::to_vec(&baseline_payload).expect("second baseline bytes"),
        );
        stage_repository_artifact(
            &self.artifact,
            &self.policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &initial_id,
            ArtifactSemanticClass::WorkspaceManifest,
            vec![baseline_id.clone()],
            serde_json::to_vec(&InitialWorkspaceManifestPayload {
                schema_version: "egopulse.workspace-initial-manifest/v1".to_owned(),
                task_id: task_id.to_owned(),
                task_revision: lineage.task_revision,
                work_revision: lineage.work_revision,
                run_id: lineage.run_id.clone(),
                run_revision: lineage.run_revision,
                step_id: lineage.step_id.clone(),
                step_revision: lineage.step_revision,
                attempt_id: lineage.attempt_id.clone(),
                attempt_revision: lineage.attempt_revision,
                dispatch_id: dispatch_id.to_owned(),
                fencing_token: lineage.fencing_token,
                input_snapshot_id: first.baseline.input_snapshot_id,
                input_bundle_sha256: first.baseline.input_bundle_sha256,
                workspace_ref: workspace_ref.clone(),
                baseline_commit: first.baseline.baseline_commit.clone(),
                baseline_tree: first.baseline.baseline_tree.clone(),
                status_porcelain_sha256: sha256(&[]),
                clean: true,
            })
            .expect("second initial manifest"),
        );
        let patch_bytes = b"diff --git a/src/lib.rs b/src/lib.rs\nsecond task\n".to_vec();
        let patch_address = content_address(&patch_bytes);
        stage_repository_artifact(
            &self.artifact,
            &self.policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &patch_id,
            ArtifactSemanticClass::RepositoryPatch,
            vec![baseline_id.clone(), initial_id.clone()],
            patch_bytes,
        );
        stage_repository_artifact(
            &self.artifact,
            &self.policy,
            &lineage,
            &workspace_ref,
            &source_binding_ref,
            &final_id,
            ArtifactSemanticClass::WorkspaceManifest,
            vec![baseline_id.clone(), initial_id.clone(), patch_id.clone()],
            serde_json::to_vec(&FinalWorkspaceManifestPayload {
                schema_version: "egopulse.workspace-final-manifest/v1".to_owned(),
                workspace_ref: workspace_ref.clone(),
                baseline_commit: first.baseline.baseline_commit.clone(),
                baseline_tree: first.baseline.baseline_tree.clone(),
                observed_head_commit: first.baseline.baseline_commit,
                observed_head_tree: first.baseline.baseline_tree,
                status_porcelain_sha256: "4".repeat(64),
                status_porcelain_bytes: 13,
                patch_sha256: patch_address.digest,
                patch_bytes: patch_address.byte_length,
                entries: vec![FinalWorkspaceManifestEntry {
                    status: "M".to_owned(),
                    path_hex: hex::encode("src/lib.rs"),
                }],
            })
            .expect("second final manifest"),
        );
        let command = self
            .frozen
            .acceptance_contract
            .required_commands
            .first()
            .expect("frozen tests command");
        let command_inputs = vec![
            baseline_id.clone(),
            initial_id.clone(),
            patch_id.clone(),
            final_id.clone(),
        ];
        let runner = RepositoryCommandArtifactRunner::with_executor(
            Arc::clone(&self.artifact),
            command_config(&self.policy),
            PassingExecutor,
        )
        .expect("second repository command runner");
        let receipt = match runner
            .execute(RepositoryCommandExecutionRequest {
                material: &self.frozen,
                command,
                lineage: lineage.clone(),
                workspace_root: &workspace_root,
                workspace_ref: &workspace_ref,
                source_binding_ref: &source_binding_ref,
                input_artifact_ids: &command_inputs,
            })
            .await
            .expect("second command helper")
        {
            RepositoryCommandExecutionOutcome::Completed(receipt) => receipt,
            other => panic!("expected second completed command receipt, got {other:?}"),
        };

        let statement = content_address(b"second repository return");
        let repository_coverage = content_address(b"second repository capture");
        let command_coverage = content_address(b"second command receipt");
        let repository_evidence_id = "evidence:repository-material:second";
        let command_evidence_id = "evidence:command-receipt:second";
        let mut authority = self.artifact.lock().expect("Artifact lock");
        authority
            .put_blob(b"second repository return", &statement)
            .expect("second claim statement");
        authority
            .put_blob(b"second repository capture", &repository_coverage)
            .expect("second repository coverage");
        authority
            .put_blob(b"second command receipt", &command_coverage)
            .expect("second command coverage");
        execute_artifact(
            &mut authority,
            artifact_command::Command::ProposeClaim(ProposeClaimCommand {
                metadata: Some(metadata(claim_id, "propose")),
                claim: Some(Claim {
                    claim_id: claim_id.to_owned(),
                    source_type: ClaimSourceType::CodeChange as i32,
                    semantic_profile_ref: Some(claim_profile_ref()),
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec![
                        baseline_id.clone(),
                        patch_id.clone(),
                        final_id.clone(),
                        receipt.artifact_id.clone(),
                    ],
                    acceptance_contract_ref: Some(acceptance_ref.clone()),
                    statement: Some(statement),
                    proposer: Some(producer(
                        ArtifactPrincipalKind::GovernedCollector,
                        &self.policy.governed_collector_principal_id,
                        "agentosd-return-collector",
                    )),
                    ..Default::default()
                }),
            }),
            ArtifactPrincipalKind::GovernedCollector,
            &self.policy.governed_collector_principal_id,
        );
        record_evidence(
            &mut authority,
            &self.policy,
            &lineage,
            claim_id,
            repository_evidence_id,
            vec![
                baseline_id.clone(),
                initial_id.clone(),
                patch_id.clone(),
                final_id.clone(),
            ],
            EvidenceProducerClass::AttemptSupervisor,
            &self.policy.attempt_supervisor_principal_id,
            repository_coverage,
        );
        record_evidence(
            &mut authority,
            &self.policy,
            &lineage,
            claim_id,
            command_evidence_id,
            vec![receipt.artifact_id.clone()],
            EvidenceProducerClass::SupervisedRunner,
            &self.policy.supervised_runner_principal_id,
            command_coverage,
        );
        let mut set = ArtifactSet {
            artifact_set_id: set_id.to_owned(),
            lineage: Some(lineage.clone()),
            artifact_ids: vec![
                baseline_id,
                initial_id,
                patch_id,
                final_id,
                receipt.artifact_id,
            ],
            claim_ids: vec![claim_id.to_owned()],
            evidence_ids: vec![
                repository_evidence_id.to_owned(),
                command_evidence_id.to_owned(),
            ],
            ..Default::default()
        };
        let manifest_bytes = canonical_artifact_set_manifest(&set);
        let manifest = content_address(&manifest_bytes);
        authority
            .put_blob(&manifest_bytes, &manifest)
            .expect("second set manifest");
        set.canonical_manifest = Some(manifest.clone());
        execute_artifact(
            &mut authority,
            artifact_command::Command::CreateArtifactSet(CreateArtifactSetCommand {
                metadata: Some(metadata(set_id, "create")),
                artifact_set: Some(set),
            }),
            ArtifactPrincipalKind::GovernedCollector,
            &self.policy.governed_collector_principal_id,
        );
        execute_artifact(
            &mut authority,
            artifact_command::Command::SealArtifactSet(SealArtifactSetCommand {
                metadata: Some(metadata(set_id, "seal")),
                artifact_set_id: set_id.to_owned(),
                expected_revision: 1,
                observed_manifest: Some(manifest.clone()),
            }),
            ArtifactPrincipalKind::ArtifactAuthority,
            "authority:artifact",
        );
        VerificationBinding {
            lineage: Some(lineage),
            artifact_set_id: set_id.to_owned(),
            artifact_set_manifest: Some(manifest),
            claim_id: claim_id.to_owned(),
            claim_semantic_profile_ref: Some(claim_profile_ref()),
            acceptance_contract_ref: Some(acceptance_ref),
        }
    }
}

#[tokio::test]
async fn loader_resolves_frozen_context_sealed_set_and_real_command_receipt() {
    let fixture = Fixture::new().await;
    let material = fixture
        .resolver()
        .resolve(&fixture.binding, unix_seconds())
        .expect("verified repository material");

    assert_eq!(material.frozen, fixture.frozen);
    assert_eq!(material.scope.allowed_paths, vec!["src".to_owned()]);
    assert_eq!(material.evidence.len(), 2);
    assert_eq!(material.command_observations.len(), 1);
    assert!(matches!(
        &material.command_observations[0].outcome,
        RepositoryCommandObservationOutcome::Completed {
            exit_code: 0,
            stdout,
            stderr,
            duration_ms: 7,
        } if stdout == b"one test passed\n" && stderr.is_empty()
    ));
}

#[tokio::test]
async fn loader_rejects_binding_with_wrong_lineage() {
    let fixture = Fixture::new().await;
    let mut binding = fixture.binding.clone();
    binding
        .lineage
        .as_mut()
        .expect("binding lineage")
        .fencing_token += 1;

    assert_eq!(
        fixture
            .resolver()
            .resolve(&binding, unix_seconds())
            .map(|_| ()),
        Err(VerificationMaterialError::Invalid)
    );
}

#[tokio::test]
async fn loader_ignores_overwritten_live_contract_and_uses_frozen_context_body() {
    let fixture = Fixture::new().await;
    std::fs::write(
        &fixture.contract_path,
        br#"{"schema_version":"attacker-controlled"}"#,
    )
    .expect("overwrite live contract after freeze");

    let material = fixture
        .resolver()
        .resolve(&fixture.binding, unix_seconds())
        .expect("live file is outside the verification truth path");
    assert_eq!(material.scope.allowed_paths, vec!["src".to_owned()]);
    assert_eq!(
        material.scope.acceptance_contract_ref,
        fixture.frozen.acceptance_contract_ref()
    );
}

fn fixture_lineage() -> LineageBinding {
    fixture_lineage_for(TASK_ID, DISPATCH_ID, 3)
}

fn fixture_lineage_for(task_id: &str, dispatch_id: &str, fencing_token: u64) -> LineageBinding {
    LineageBinding {
        task_id: task_id.to_owned(),
        task_revision: 2,
        work_revision: 1,
        run_id: "run:verification-material".to_owned(),
        run_revision: 1,
        step_id: "step:verification-material".to_owned(),
        step_revision: 1,
        attempt_id: "attempt:verification-material".to_owned(),
        attempt_revision: 1,
        dispatch_id: dispatch_id.to_owned(),
        fencing_token,
    }
}

fn material_policy() -> RepositoryVerificationMaterialPolicy {
    RepositoryVerificationMaterialPolicy {
        repository_artifact_type_ref: reference("repository-artifact", 0x11),
        repository_transformation_ref: reference("repository-capture", 0x12),
        command_intent_type_ref: reference("command-intent", 0x21),
        command_intent_transformation_ref: reference("command-intent-capture", 0x22),
        command_receipt_type_ref: reference("command-receipt", 0x31),
        command_receipt_transformation_ref: reference("command-receipt-capture", 0x32),
        retention_profile_ref: reference("repository-retention", 0x41),
        evidence_profile_ref: evidence_profile_ref(),
        attempt_supervisor_principal_id: "attempt-supervisor:repository".to_owned(),
        supervised_runner_principal_id: "supervised-runner:repository".to_owned(),
        governed_collector_principal_id: "collector:repository".to_owned(),
        repository_component_name: "agentosd-repository-dispatch".to_owned(),
        command_component_name: "agentosd-repository-command".to_owned(),
    }
}

fn command_config(
    policy: &RepositoryVerificationMaterialPolicy,
) -> RepositoryCommandArtifactConfig {
    RepositoryCommandArtifactConfig {
        intent_type_ref: policy.command_intent_type_ref.clone(),
        intent_transformation_ref: policy.command_intent_transformation_ref.clone(),
        receipt_type_ref: policy.command_receipt_type_ref.clone(),
        receipt_transformation_ref: policy.command_receipt_transformation_ref.clone(),
        retention_profile_ref: policy.retention_profile_ref.clone(),
        supervised_runner_principal_id: policy.supervised_runner_principal_id.clone(),
        artifact_authority_principal_id: "authority:artifact".to_owned(),
        component_name: policy.command_component_name.clone(),
        component_version: env!("CARGO_PKG_VERSION").to_owned(),
        sensitivity_class: "local-user-data".to_owned(),
    }
}

pub(super) fn open_artifact(
    root: &Path,
    policy: &RepositoryVerificationMaterialPolicy,
    acceptance_ref: &ContractReference,
) -> (
    Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    DerivedWorkspaceAdmissionHandle,
) {
    let guard = ConfiguredArtifactAdmissionGuard::new(ConfiguredArtifactAdmissionGuardConfig {
        allowed_workspace_refs: BTreeSet::from(["unrelated-static-workspace".to_owned()]),
        allowed_artifact_type_refs: vec![
            policy.repository_artifact_type_ref.clone(),
            policy.command_intent_type_ref.clone(),
            policy.command_receipt_type_ref.clone(),
            profile_attestation_type_ref(),
        ],
        allowed_transformation_contract_refs: vec![
            policy.repository_transformation_ref.clone(),
            policy.command_intent_transformation_ref.clone(),
            policy.command_receipt_transformation_ref.clone(),
            profile_attestation_transformation_ref(),
        ],
        allowed_retention_profile_refs: vec![policy.retention_profile_ref.clone()],
        allowed_claim_semantic_profile_refs: vec![claim_profile_ref()],
        allowed_claim_acceptance_contract_refs: vec![acceptance_ref.clone()],
        allowed_evidence_profile_refs: vec![policy.evidence_profile_ref.clone()],
    })
    .expect("Artifact admission guard");
    let admission = guard.derived_workspace_admission_handle();
    let authority = ArtifactAuthority::open(
        ArtifactAuthorityConfig {
            database_path: root.join("artifact.db"),
            blob_root: root.join("artifact-blobs"),
            store_epoch: "verification-material-artifact".to_owned(),
            key: ArtifactSqlCipherKey::new([0x62; 32]),
        },
        guard,
    )
    .expect("Artifact Authority");
    (Arc::new(Mutex::new(authority)), admission)
}

// The helper mirrors the complete Artifact provenance boundary so each test
// call must name every identity and contract input explicitly.
#[allow(clippy::too_many_arguments)]
fn stage_repository_artifact(
    authority: &Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    policy: &RepositoryVerificationMaterialPolicy,
    lineage: &LineageBinding,
    workspace_ref: &str,
    source_binding_ref: &str,
    artifact_id: &str,
    semantic_class: ArtifactSemanticClass,
    input_artifact_ids: Vec<String>,
    bytes: Vec<u8>,
) {
    let address = content_address(&bytes);
    let descriptor = ArtifactDescriptor {
        artifact_id: artifact_id.to_owned(),
        revision: 1,
        status: egopulse_domain_contracts::v01::egopulse::artifact::v1::ArtifactStatus::Staged
            as i32,
        semantic_class: semantic_class as i32,
        type_contract_ref: Some(policy.repository_artifact_type_ref.clone()),
        media_type: "application/json".to_owned(),
        content: Some(address.clone()),
        integrity_status: IntegrityStatus::Unverified as i32,
        provenance: Some(Provenance {
            lineage: Some(lineage.clone()),
            producer: Some(producer(
                ArtifactPrincipalKind::AttemptSupervisor,
                &policy.attempt_supervisor_principal_id,
                &policy.repository_component_name,
            )),
            input_artifact_ids,
            transformation_contract_ref: Some(policy.repository_transformation_ref.clone()),
            workspace_ref: workspace_ref.to_owned(),
            raw_source_ref: Some(source_binding_ref.to_owned()),
            ..Default::default()
        }),
        sensitivity_class: "local-user-data".to_owned(),
        retention_profile_ref: Some(policy.retention_profile_ref.clone()),
        ..Default::default()
    };
    let mut authority = authority.lock().expect("Artifact lock");
    authority.put_blob(&bytes, &address).expect("Artifact blob");
    execute_artifact(
        &mut authority,
        artifact_command::Command::StageArtifact(StageArtifactCommand {
            metadata: Some(metadata(artifact_id, "stage")),
            candidate: Some(descriptor),
        }),
        ArtifactPrincipalKind::AttemptSupervisor,
        &policy.attempt_supervisor_principal_id,
    );
    execute_artifact(
        &mut authority,
        artifact_command::Command::SealArtifact(SealArtifactCommand {
            metadata: Some(metadata(artifact_id, "seal")),
            artifact_id: artifact_id.to_owned(),
            expected_revision: 1,
            observed_content: Some(address),
        }),
        ArtifactPrincipalKind::ArtifactAuthority,
        "authority:artifact",
    );
}

// Evidence identity, lineage, coverage and producer class remain explicit to
// prevent the fixture from hiding a production validation input.
#[allow(clippy::too_many_arguments)]
fn record_evidence(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    policy: &RepositoryVerificationMaterialPolicy,
    lineage: &LineageBinding,
    claim_id: &str,
    evidence_id: &str,
    artifact_ids: Vec<String>,
    producer_class: EvidenceProducerClass,
    principal_id: &str,
    coverage_descriptor: egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress,
) {
    let kind = match producer_class {
        EvidenceProducerClass::AttemptSupervisor => ArtifactPrincipalKind::AttemptSupervisor,
        EvidenceProducerClass::SupervisedRunner => ArtifactPrincipalKind::SupervisedRunner,
        _ => panic!("fixture uses independent producer classes"),
    };
    execute_artifact(
        authority,
        artifact_command::Command::RecordEvidence(RecordEvidenceCommand {
            metadata: Some(metadata(evidence_id, "record")),
            evidence: Some(Evidence {
                evidence_id: evidence_id.to_owned(),
                relation: EvidenceRelation::Supports as i32,
                claim_id: claim_id.to_owned(),
                artifact_ids,
                evidence_profile_ref: Some(policy.evidence_profile_ref.clone()),
                lineage: Some(lineage.clone()),
                producer: Some(producer(
                    kind,
                    principal_id,
                    "verification-material-fixture",
                )),
                producer_class: producer_class as i32,
                independent_of_claim_proposer: true,
                coverage_descriptor: Some(coverage_descriptor),
                ..Default::default()
            }),
        }),
        kind,
        principal_id,
    );
}

fn execute_artifact(
    authority: &mut ArtifactAuthority<ConfiguredArtifactAdmissionGuard>,
    variant: artifact_command::Command,
    kind: ArtifactPrincipalKind,
    principal_id: &str,
) {
    let mut command = ArtifactCommand {
        command: Some(variant),
    };
    let digest = canonical_request_digest(&command).expect("canonical Artifact command");
    command_metadata_mut(&mut command).request_digest_sha256 = digest;
    let result = authority
        .execute(
            &command,
            &AuthenticatedArtifactPrincipal {
                kind,
                principal_id: principal_id.to_owned(),
                authenticated: true,
            },
        )
        .expect("Artifact command");
    assert!(
        result.committed || result.replayed,
        "Artifact command rejected: {result:?}"
    );
}

fn command_metadata_mut(command: &mut ArtifactCommand) -> &mut CommandMetadata {
    match command.command.as_mut().expect("Artifact command") {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        _ => panic!("unexpected fixture Artifact command"),
    }
    .expect("Artifact command metadata")
}

fn metadata(subject: &str, operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("verification-material:{operation}:{subject}"),
        idempotency_key: format!("{operation}:{subject}"),
        idempotency_scope: "verification-material-fixture".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: subject.to_owned(),
        causation_id: Some(format!("verification-material:{subject}")),
    }
}

fn producer(kind: ArtifactPrincipalKind, id: &str, component: &str) -> ProducerIdentity {
    ProducerIdentity {
        principal_kind: kind.as_str().to_owned(),
        principal_id: id.to_owned(),
        component_name: component.to_owned(),
        component_version: env!("CARGO_PKG_VERSION").to_owned(),
        ..Default::default()
    }
}

pub(super) fn reference(id: &str, byte: u8) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: format!("{byte:02x}").repeat(32),
    }
}

fn claim_profile_ref() -> ContractReference {
    reference("repository-change-claim", 0x51)
}

fn evidence_profile_ref() -> ContractReference {
    reference("repository-change-evidence", 0x52)
}

pub(super) fn profile_attestation_type_ref() -> ContractReference {
    reference("checker-profile-deployment", 0x71)
}

pub(super) fn profile_attestation_transformation_ref() -> ContractReference {
    reference("checker-profile-deployment-capture", 0x72)
}

fn path_text(path: &Path) -> String {
    path.to_str().expect("fixture path UTF-8").to_owned()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
        .try_into()
        .expect("timestamp range")
}

fn now() -> Timestamp {
    Timestamp {
        seconds: unix_seconds(),
        nanos: 0,
    }
}
