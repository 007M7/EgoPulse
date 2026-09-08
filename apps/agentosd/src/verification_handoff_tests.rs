use super::*;
use egopulse_cognition_runtime::task_authority::{
    CreationAuthorization, CreationGuardRejection, SqlCipherKey, TaskCreationGuard,
    TaskTransitionGuard, TransitionAuthorization, TransitionGuardRejection,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactDescriptor, ArtifactStatus, Claim, ClaimSourceType, Evidence,
        EvidenceProducerClass, EvidenceRelation, EvidenceStatus, IntegrityStatus, LineageBinding,
        Provenance,
    },
    task::v1::{
        ActivateTaskCommand, CreateTaskCommand, SubmitTaskEvidenceCommand, TaskSnapshot,
        task_command_result,
    },
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, CriterionPolicySnapshot, VerificationAuthorityConfig,
    VerificationSqlCipherKey, canonical_checker_profile_digest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct AllowCreation;

impl TaskCreationGuard for AllowCreation {
    fn validate(
        &self,
        _command: &CreateTaskCommand,
    ) -> Result<CreationAuthorization, CreationGuardRejection> {
        Ok(CreationAuthorization {
            evidence_refs: vec!["creation-proof".to_owned()],
        })
    }
}

struct AllowTransitions;

impl TaskTransitionGuard for AllowTransitions {
    fn validate(
        &self,
        _command: &TaskCommand,
        _current: &TaskSnapshot,
    ) -> Result<TransitionAuthorization, TransitionGuardRejection> {
        Ok(TransitionAuthorization {
            evidence_refs: vec!["transition-proof".to_owned()],
            founder_decision: None,
            founder_verdict_state_revision: None,
        })
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "egopulse-verification-handoff-fairness-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&path).expect("create isolated handoff test root");
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
            .is_some_and(|value| value.starts_with("egopulse-verification-handoff-fairness-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[derive(Clone, Default)]
struct SharedArtifactSource {
    sets: Arc<Mutex<BTreeMap<String, ArtifactSet>>>,
    artifacts: Arc<Mutex<BTreeMap<String, ArtifactDescriptor>>>,
    claims: Arc<Mutex<BTreeMap<String, Claim>>>,
    evidence: Arc<Mutex<BTreeMap<String, Evidence>>>,
}

impl SharedArtifactSource {
    fn insert(&self, material: TaskMaterial) {
        self.sets
            .lock()
            .expect("set source lock")
            .insert(material.set.artifact_set_id.clone(), material.set);
        self.artifacts
            .lock()
            .expect("artifact source lock")
            .insert(material.artifact.artifact_id.clone(), material.artifact);
        self.claims
            .lock()
            .expect("claim source lock")
            .insert(material.claim.claim_id.clone(), material.claim);
        self.evidence
            .lock()
            .expect("evidence source lock")
            .insert(material.evidence.evidence_id.clone(), material.evidence);
    }
}

impl ArtifactReferenceSource for SharedArtifactSource {
    fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
        Ok(self
            .artifacts
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .get(artifact_id)
            .cloned())
    }

    fn read_claim(&self, claim_id: &str) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
        Ok(self
            .claims
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .get(claim_id)
            .cloned())
    }

    fn read_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
        Ok(self
            .evidence
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .get(evidence_id)
            .cloned())
    }

    fn read_artifact_set(
        &self,
        artifact_set_id: &str,
    ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
        Ok(self
            .sets
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .get(artifact_set_id)
            .cloned())
    }
}

#[derive(Clone, Copy)]
enum PreparedDisposition {
    LegacyNotOwned,
    InitiallyUnavailable,
    Valid,
}

struct ControlledPreparation {
    dispositions: BTreeMap<String, PreparedDisposition>,
    legacy_ready: AtomicBool,
    unavailable_ready: AtomicBool,
    semantic: ContractReference,
    criterion_id: String,
    profile_ref: ContractReference,
}

impl ControlledPreparation {
    fn make_legacy_available(&self) {
        self.legacy_ready.store(true, Ordering::SeqCst);
    }

    fn make_available(&self) {
        self.unavailable_ready.store(true, Ordering::SeqCst);
    }

    fn valid_plan(&self, artifact_set: &ArtifactSet) -> VerificationHandoffPlan {
        VerificationHandoffPlan {
            binding: VerificationBindingTemplate {
                claim_id: artifact_set
                    .claim_ids
                    .first()
                    .expect("test set has one claim")
                    .clone(),
                claim_semantic_profile_ref: self.semantic.clone(),
            },
            criterion_ids: vec![self.criterion_id.clone()],
            checker_profile_refs: vec![self.profile_ref.clone()],
        }
    }
}

impl VerificationHandoffPreparation for ControlledPreparation {
    fn prepare(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        _artifact: &dyn ArtifactReferenceSource,
    ) -> Result<VerificationHandoffPlan, VerificationHandoffIntakeError> {
        let task_id = &handoff
            .event
            .snapshot
            .as_ref()
            .expect("real Task handoff snapshot")
            .task_id;
        match self
            .dispositions
            .get(task_id)
            .copied()
            .expect("every pending test Task is classified")
        {
            PreparedDisposition::LegacyNotOwned if !self.legacy_ready.load(Ordering::SeqCst) => {
                Err(VerificationHandoffIntakeError::PreparationBlocked(
                    "VERIFICATION_HANDOFF_NOT_OWNED",
                ))
            }
            PreparedDisposition::InitiallyUnavailable
                if !self.unavailable_ready.load(Ordering::SeqCst) =>
            {
                Err(VerificationHandoffIntakeError::PreparationBlocked(
                    "VERIFICATION_MATERIAL_UNAVAILABLE",
                ))
            }
            PreparedDisposition::LegacyNotOwned
            | PreparedDisposition::InitiallyUnavailable
            | PreparedDisposition::Valid => Ok(self.valid_plan(artifact_set)),
        }
    }
}

struct TaskMaterial {
    set: ArtifactSet,
    artifact: ArtifactDescriptor,
    claim: Claim,
    evidence: Evidence,
}

#[test]
fn prepared_intake_skips_blocked_tasks_recovers_material_and_never_duplicates_requests() {
    let root = TempRoot::new();
    let acceptance = contract("repository-acceptance", SHA_A);
    let semantic = contract("repository_change_acceptance", SHA_B);
    let source = SharedArtifactSource::default();
    let mut task = TaskAuthority::open_with_transition_guard(
        egopulse_cognition_runtime::task_authority::TaskAuthorityConfig {
            database_path: root.path().join("task.db"),
            store_epoch: "handoff-fairness-task".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        },
        AllowCreation,
        AllowTransitions,
    )
    .expect("open Task Authority");

    for label in ["one", "two", "three"] {
        let (pending, material) = create_pending_task(&mut task, label, &acceptance, &semantic);
        assert_eq!(pending.status, TaskStatus::VerificationPending as i32);
        source.insert(material);
    }
    let ordered = task
        .pending_task_verifications()
        .expect("read ordered handoffs");
    assert_eq!(ordered.len(), 3);
    let task_a = ordered[0]
        .event
        .snapshot
        .as_ref()
        .expect("A snapshot")
        .task_id
        .clone();
    let task_b = ordered[1]
        .event
        .snapshot
        .as_ref()
        .expect("B snapshot")
        .task_id
        .clone();
    let task_c = ordered[2]
        .event
        .snapshot
        .as_ref()
        .expect("C snapshot")
        .task_id
        .clone();

    let profile = checker_profile(
        ordered[0]
            .event
            .snapshot
            .as_ref()
            .expect("profile source Task")
            .artifact_set_id
            .as_deref()
            .and_then(|set_id| source.sets.lock().ok()?.get(set_id).cloned())
            .and_then(|set| set.artifact_ids.first().cloned())
            .expect("profile attestation Artifact"),
    );
    let profile_ref = ContractReference {
        contract_id: profile.checker_profile_id.clone(),
        version: profile.checker_version.clone(),
        sha256: profile.profile_digest_sha256.clone(),
    };
    let resolver = ArtifactBackedReferenceResolver::new(
        source.clone(),
        vec![CriterionPolicySnapshot {
            criterion_id: "scope".to_owned(),
            requirement: egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionRequirement::MustPass as i32,
            minimum_assurance: CheckerAssuranceClass::Deterministic as i32,
            not_applicable_allowed: false,
            checker_profile_ids: vec![profile.checker_profile_id.clone()],
        }],
    )
    .expect("valid reference resolver");
    let mut verification = VerificationAuthority::open(
        VerificationAuthorityConfig {
            database_path: root.path().join("verification.db"),
            store_epoch: "handoff-fairness-verification".to_owned(),
            key: VerificationSqlCipherKey::new([42; 32]),
        },
        resolver,
    )
    .expect("open Verification Authority");
    attest_profile(&mut verification, profile);

    let preparation = Arc::new(ControlledPreparation {
        dispositions: BTreeMap::from([
            (task_a.clone(), PreparedDisposition::LegacyNotOwned),
            (task_b.clone(), PreparedDisposition::InitiallyUnavailable),
            (task_c.clone(), PreparedDisposition::Valid),
        ]),
        legacy_ready: AtomicBool::new(false),
        unavailable_ready: AtomicBool::new(false),
        semantic,
        criterion_id: "scope".to_owned(),
        profile_ref,
    });
    let task = Arc::new(Mutex::new(task));
    let verification = Arc::new(Mutex::new(verification));
    let intake = VerificationHandoffIntake {
        task: Arc::clone(&task),
        artifact: Box::new(source),
        verification: Arc::clone(&verification),
        plan: VerificationHandoffPlanSource::Prepared(preparation.clone()),
        principal: AuthenticatedVerificationPrincipal {
            kind: VerificationPrincipalKind::TaskAuthority,
            principal_id: "task-authority:handoff-fairness".to_owned(),
            authenticated: true,
            checker_profile_id: None,
        },
    };

    let first = intake
        .consume_one_with_report(timestamp())
        .expect("blocked A/B must not fail intake or prevent C");
    assert_eq!(
        first.blockages,
        vec![
            VerificationHandoffBlockage {
                task_id: task_a.clone(),
                message_id: ordered[0].message_id.clone(),
                reason_code: "VERIFICATION_HANDOFF_NOT_OWNED",
            },
            VerificationHandoffBlockage {
                task_id: task_b.clone(),
                message_id: ordered[1].message_id.clone(),
                reason_code: "VERIFICATION_MATERIAL_UNAVAILABLE",
            },
        ]
    );
    let first_consumed = first.consumed.expect("C is consumed in the same scan");
    assert!(first_consumed.committed);
    assert!(first_consumed.task_outbox_acknowledged);
    assert_request_belongs_to(
        &verification,
        &first_consumed.verification_request_id,
        &task_c,
    );
    assert_counts(&verification, 1, 0);
    assert_pending_tasks(&task, [&task_a, &task_b]);

    let before_unavailable_replay = verification
        .lock()
        .expect("verification lock")
        .inspect_store()
        .expect("inspection before unavailable replay");
    let unavailable_replay = intake
        .consume_one_with_report(timestamp())
        .expect("repeated blocked scan remains nonfatal");
    assert!(unavailable_replay.consumed.is_none());
    assert_eq!(
        unavailable_replay.blockages,
        vec![
            VerificationHandoffBlockage {
                task_id: task_a.clone(),
                message_id: ordered[0].message_id.clone(),
                reason_code: "VERIFICATION_HANDOFF_NOT_OWNED",
            },
            VerificationHandoffBlockage {
                task_id: task_b.clone(),
                message_id: ordered[1].message_id.clone(),
                reason_code: "VERIFICATION_MATERIAL_UNAVAILABLE",
            },
        ]
    );
    let after_unavailable_replay = verification
        .lock()
        .expect("verification lock")
        .inspect_store()
        .expect("inspection after unavailable replay");
    assert_eq!(before_unavailable_replay, after_unavailable_replay);
    assert_pending_tasks(&task, [&task_a, &task_b]);

    preparation.make_available();
    let second = intake
        .consume_one_with_report(timestamp())
        .expect("A remains blocked while repaired B proceeds");
    assert_eq!(
        second.blockages,
        vec![VerificationHandoffBlockage {
            task_id: task_a.clone(),
            message_id: ordered[0].message_id.clone(),
            reason_code: "VERIFICATION_HANDOFF_NOT_OWNED",
        }]
    );
    let second_consumed = second
        .consumed
        .expect("B is consumed after material recovery");
    assert!(second_consumed.committed);
    assert_request_belongs_to(
        &verification,
        &second_consumed.verification_request_id,
        &task_b,
    );
    assert_counts(&verification, 2, 0);
    assert_pending_tasks(&task, [&task_a]);

    let before = verification
        .lock()
        .expect("verification lock")
        .inspect_store()
        .expect("inspection before blocked replay");
    let third = intake
        .consume_one_with_report(timestamp())
        .expect("bad queue head is a report, not a worker failure");
    assert!(third.consumed.is_none());
    assert_eq!(third.blockages.len(), 1);
    assert_eq!(third.blockages[0].task_id, task_a);
    assert!(
        intake
            .consume_one(timestamp())
            .expect("the worker-facing API also treats the bad head as nonfatal")
            .is_none()
    );
    let after = verification
        .lock()
        .expect("verification lock")
        .inspect_store()
        .expect("inspection after blocked replay");
    assert_eq!(before.request_count, after.request_count);
    assert_eq!(before.run_count, after.run_count);
    assert_eq!(before.event_count, after.event_count);
    assert_eq!(before.idempotency_count, after.idempotency_count);
    assert_pending_tasks(&task, [&third.blockages[0].task_id]);

    poison_mutex(&task, "Task Authority");
    assert!(matches!(
        intake.consume_one_with_report(timestamp()),
        Err(VerificationHandoffIntakeError::TaskLock)
    ));
    task.clear_poison();

    preparation.make_legacy_available();
    poison_mutex(&verification, "Verification Authority");
    assert!(matches!(
        intake.consume_one_with_report(timestamp()),
        Err(VerificationHandoffIntakeError::VerificationLock)
    ));
}

fn poison_mutex<T: Send + 'static>(owner: &Arc<Mutex<T>>, label: &'static str) {
    let owner = Arc::clone(owner);
    assert!(
        std::thread::spawn(move || {
            let _guard = owner.lock().expect("owner lock before deliberate poison");
            panic!("deliberately poison {label} mutex");
        })
        .join()
        .is_err()
    );
}

fn create_pending_task(
    authority: &mut TaskAuthority,
    label: &str,
    acceptance: &ContractReference,
    semantic: &ContractReference,
) -> (TaskSnapshot, TaskMaterial) {
    let created = task_snapshot(
        authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                        meta: Some(metadata(&format!("create-{label}"), "handoff-task")),
                        work_type: "governed_repository_change".to_owned(),
                        input_snapshot_id: format!("input-{label}"),
                        target_scope_ref: "scope:repository".to_owned(),
                        acceptance_contract_ref: Some(acceptance.clone()),
                        budget_profile_ref: Some(contract("budget", SHA_B)),
                        work_capability_route: None,
                    })),
                }),
                &founder(),
            )
            .expect("create Task"),
    );
    let run_id = format!("run-{label}");
    let active = task_snapshot(
        authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                        meta: Some(metadata(&format!("activate-{label}"), "handoff-task")),
                        task_id: created.task_id.clone(),
                        expected_revision: created.revision,
                        work_revision: created.work_revision,
                        run_id: run_id.clone(),
                    })),
                }),
                &collaboration_control(),
            )
            .expect("activate Task"),
    );
    let activation = authority
        .pending_cross_authority_outbox()
        .expect("activation outbox")
        .into_iter()
        .find(|message| message.destination_domain == "collaboration-control")
        .expect("activation handoff");
    assert!(
        authority
            .acknowledge_cross_authority_outbox(
                &activation.message_id,
                &activation.payload_digest_sha256,
            )
            .expect("ack activation")
    );

    let set_id = format!("artifact-set-{label}");
    let artifact_id = format!("artifact-{label}");
    let claim_id = format!("claim-{label}");
    let evidence_id = format!("evidence-{label}");
    let lineage = LineageBinding {
        task_id: created.task_id.clone(),
        task_revision: active.revision,
        work_revision: active.work_revision,
        run_id,
        run_revision: 1,
        step_id: format!("step-{label}"),
        step_revision: 1,
        attempt_id: format!("attempt-{label}"),
        attempt_revision: 1,
        dispatch_id: format!("dispatch-{label}"),
        fencing_token: 1,
    };
    let manifest_digest_byte = match label {
        "one" => '1',
        "two" => '2',
        "three" => '3',
        _ => unreachable!("fixture labels are fixed"),
    };
    let manifest = ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: manifest_digest_byte.to_string().repeat(64),
        byte_length: 128,
    };
    let set = ArtifactSet {
        artifact_set_id: set_id.clone(),
        revision: 1,
        status: ArtifactSetStatus::Sealed as i32,
        lineage: Some(lineage.clone()),
        artifact_ids: vec![artifact_id.clone()],
        claim_ids: vec![claim_id.clone()],
        evidence_ids: vec![evidence_id.clone()],
        canonical_manifest: Some(manifest),
        ..ArtifactSet::default()
    };
    let artifact = ArtifactDescriptor {
        artifact_id,
        revision: 1,
        status: ArtifactStatus::Sealed as i32,
        integrity_status: IntegrityStatus::DigestVerified as i32,
        content: Some(ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: SHA_A.to_owned(),
            byte_length: 32,
        }),
        provenance: Some(Provenance {
            lineage: Some(lineage.clone()),
            ..Provenance::default()
        }),
        ..ArtifactDescriptor::default()
    };
    let claim = Claim {
        claim_id,
        revision: 1,
        status: ClaimStatus::Proposed as i32,
        source_type: ClaimSourceType::CodeChange as i32,
        semantic_profile_ref: Some(semantic.clone()),
        lineage: Some(lineage.clone()),
        acceptance_contract_ref: Some(acceptance.clone()),
        ..Claim::default()
    };
    let evidence = Evidence {
        evidence_id,
        revision: 1,
        status: EvidenceStatus::Recorded as i32,
        relation: EvidenceRelation::Supports as i32,
        claim_id: claim.claim_id.clone(),
        artifact_ids: set.artifact_ids.clone(),
        lineage: Some(lineage),
        producer_class: EvidenceProducerClass::DeterministicChecker as i32,
        integrity_status: IntegrityStatus::DigestVerified as i32,
        ..Evidence::default()
    };
    let pending = task_snapshot(
        authority
            .execute(
                &signed_task_command(TaskCommand {
                    command: Some(task_command::Command::SubmitTaskEvidence(
                        SubmitTaskEvidenceCommand {
                            meta: Some(metadata(
                                &format!("submit-evidence-{label}"),
                                "handoff-task",
                            )),
                            task_id: active.task_id.clone(),
                            expected_revision: active.revision,
                            work_revision: active.work_revision,
                            return_handoff_id: format!("return-{label}"),
                            artifact_set_id: set_id,
                        },
                    )),
                }),
                &collaboration_control(),
            )
            .expect("submit Task evidence"),
    );
    (
        pending,
        TaskMaterial {
            set,
            artifact,
            claim,
            evidence,
        },
    )
}

fn checker_profile(attestation_artifact_id: String) -> CheckerProfile {
    let mut profile = CheckerProfile {
        checker_profile_id: "checker:handoff-fairness".to_owned(),
        revision: 0,
        status: CheckerProfileStatus::Unspecified as i32,
        checker_id: "deterministic:scope".to_owned(),
        checker_version: "v1".to_owned(),
        input_contract_ref: Some(contract("verification-input", SHA_A)),
        output_contract_ref: Some(contract("verification-output", SHA_B)),
        supported_criterion_types: vec!["scope".to_owned()],
        assurance_class: CheckerAssuranceClass::Deterministic as i32,
        sandbox_profile_ref: Some(contract("verification-sandbox", SHA_A)),
        tool_policy_ref: Some(contract("verification-tools", SHA_B)),
        data_egress_policy_ref: Some(contract("local-only", SHA_A)),
        timeout_ms: 1_000,
        network_allowed: false,
        profile_digest_sha256: String::new(),
        attestation_evidence_artifact_ids: vec![attestation_artifact_id],
        attested_at: None,
    };
    profile.profile_digest_sha256 = canonical_checker_profile_digest(&profile);
    profile
}

fn attest_profile(authority: &mut VerificationAuthority, profile: CheckerProfile) {
    let command = signed_verification_command(VerificationCommand {
        command: Some(verification_command::Command::AttestCheckerProfile(
            AttestCheckerProfileCommand {
                metadata: Some(metadata("attest-profile", "handoff-verification")),
                profile: Some(profile),
            },
        )),
    });
    let result = authority
        .execute(
            &command,
            &AuthenticatedVerificationPrincipal {
                kind: VerificationPrincipalKind::VerificationAuthority,
                principal_id: "verification-authority:handoff-fairness".to_owned(),
                authenticated: true,
                checker_profile_id: None,
            },
        )
        .expect("attest profile");
    assert!(result.committed);
}

fn assert_request_belongs_to(
    authority: &Arc<Mutex<VerificationAuthority>>,
    request_id: &str,
    task_id: &str,
) {
    let request = authority
        .lock()
        .expect("verification lock")
        .verification_request(request_id)
        .expect("read request")
        .expect("request exists");
    assert_eq!(
        request
            .binding
            .as_ref()
            .and_then(|binding| binding.lineage.as_ref())
            .map(|lineage| lineage.task_id.as_str()),
        Some(task_id)
    );
}

fn assert_counts(authority: &Arc<Mutex<VerificationAuthority>>, requests: u64, runs: u64) {
    let inspection = authority
        .lock()
        .expect("verification lock")
        .inspect_store()
        .expect("inspect Verification store");
    assert_eq!(inspection.request_count, requests);
    assert_eq!(inspection.run_count, runs);
}

fn assert_pending_tasks<const N: usize>(
    authority: &Arc<Mutex<TaskAuthority>>,
    expected: [&String; N],
) {
    let actual = authority
        .lock()
        .expect("task lock")
        .pending_task_verifications()
        .expect("pending handoffs")
        .into_iter()
        .map(|handoff| handoff.event.snapshot.expect("pending snapshot").task_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected.into_iter().cloned().collect());
}

fn contract(id: &str, digest: &str) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: digest.to_owned(),
    }
}

fn metadata(label: &str, scope: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("command-{label}"),
        idempotency_key: format!("key-{label}"),
        idempotency_scope: scope.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(timestamp()),
        correlation_id: format!("correlation-{label}"),
        causation_id: None,
    }
}

fn timestamp() -> Timestamp {
    Timestamp {
        seconds: 1_788_000_000,
        nanos: 0,
    }
}

fn signed_task_command(mut command: TaskCommand) -> TaskCommand {
    let digest = task_canonical_request_digest(&command).expect("Task command digest");
    match command.command.as_mut().expect("Task operation") {
        task_command::Command::CreateTask(value) => value.meta.as_mut(),
        task_command::Command::ActivateTask(value) => value.meta.as_mut(),
        task_command::Command::SubmitTaskEvidence(value) => value.meta.as_mut(),
        _ => unreachable!("handoff fixture uses only Task setup operations"),
    }
    .expect("Task metadata")
    .request_digest_sha256 = digest;
    command
}

fn signed_verification_command(mut command: VerificationCommand) -> VerificationCommand {
    let digest = canonical_request_digest(&command).expect("Verification command digest");
    match command.command.as_mut().expect("Verification operation") {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        _ => unreachable!("handoff fixture signs only profile attestation"),
    }
    .expect("Verification metadata")
    .request_digest_sha256 = digest;
    command
}

fn task_snapshot(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("Task command outcome") {
        task_command_result::Outcome::Task(task) => task,
        task_command_result::Outcome::Error(error) => panic!("unexpected Task error: {error:?}"),
    }
}

fn founder() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: TaskPrincipalKind::Founder,
        principal_id: "founder:handoff-fairness".to_owned(),
        authenticated: true,
    }
}

fn collaboration_control() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        kind: TaskPrincipalKind::CollaborationControl,
        principal_id: "collaboration-control:handoff-fairness".to_owned(),
        authenticated: true,
    }
}
