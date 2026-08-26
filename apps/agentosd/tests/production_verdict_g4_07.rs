#![forbid(unsafe_code)]

//! Production Task/Founder Verdict composition evidence for G4-07.
//!
//! This test uses the same Authority boundaries as production, but replaces
//! only the external Verification artifact resolver with a deterministic
//! reviewed fixture. It proves that the production transition guard reads an
//! issued Verdict, applies the exact decision to Task, and creates the
//! durable consume outbox without giving Task a Verdict write path.

use egopulse_agentosd::{
    ConfiguredFounderVerdictConsumeWorker, ConfiguredTaskTransitionGuard,
    FounderVerdictConsumeCycleResult, FounderVerdictConsumeWorker, SharedFounderVerdictAuthority,
};
use egopulse_cognition_runtime::task_authority::{
    AuthenticatedPrincipal, CreationAuthorization, CreationGuardRejection, PrincipalKind,
    SqlCipherKey, TaskAuthority, TaskAuthorityConfig, TaskCreationGuard,
    canonical_request_digest as task_digest,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{
        ActivateTaskCommand, ApplyFounderVerdictCommand, CreateTaskCommand,
        RecordTaskVerificationCommand, SubmitTaskEvidenceCommand, TaskCommand, TaskSnapshot,
        TaskStatus, task_command, task_command_result,
    },
    verdict::v1::{
        ConfirmationClass, FounderVerdictDecision, IssueFounderVerdictCommand, VerdictCommand,
        VerdictScope, verdict_command,
    },
    verification::v1::VerificationConclusion,
};
use egopulse_founder_verdict_authority::{
    AuthenticatedVerdictPrincipal, FounderAuthorization, FounderVerdictAuthority,
    ResolvedVerdictContext, VerdictAuthorityConfig, VerdictPrincipalKind,
    VerdictReferenceRejection, VerdictReferenceResolver, VerdictSqlCipherKey,
    canonical_request_digest as verdict_digest,
};
use prost_types::Timestamp;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
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
            evidence_refs: vec!["g4-07-test:creation-reviewed".to_owned()],
        })
    }
}

#[derive(Clone)]
struct StaticVerdictResolver {
    context: ResolvedVerdictContext,
}

impl VerdictReferenceResolver for StaticVerdictResolver {
    fn resolve_issue(
        &self,
        command: &IssueFounderVerdictCommand,
        principal: &AuthenticatedVerdictPrincipal,
    ) -> Result<(ResolvedVerdictContext, FounderAuthorization), VerdictReferenceRejection> {
        if principal.kind != VerdictPrincipalKind::FounderAuthority {
            return Err(VerdictReferenceRejection::PermissionDenied);
        }
        Ok((
            self.context.clone(),
            FounderAuthorization {
                authenticated_founder_principal_id: "founder:local".to_owned(),
                authority_ref: "founder-authority:g4-07".to_owned(),
                confirmation_class: ConfirmationClass::Explicit,
                confirmation_proof_ref: command.confirmation_proof_ref.clone(),
                verified_at: now(),
                valid_until: command.expires_at.expect("expiry"),
                authority_policy_ref: contract("founder-policy", 0x33),
                evidence_refs: vec!["g4-07-test:founder-confirmation".to_owned()],
            },
        ))
    }

    fn validate_task_commit(
        &self,
        _command: &egopulse_domain_contracts::v01::egopulse::verdict::v1::
            ConsumeFounderVerdictCommand,
        _scope: &VerdictScope,
    ) -> Result<(), VerdictReferenceRejection> {
        Ok(())
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("egopulse-g4-07-production-{}", Uuid::now_v7()));
        fs::create_dir_all(&path).expect("create G4-07 test root");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn issued_founder_verdict_applies_to_task_and_daemon_consumes_outbox() {
    let root = TempRoot::new();
    let verdict_handle: SharedFounderVerdictAuthority = Arc::new(Mutex::new(None));
    let mut task = TaskAuthority::open_with_transition_guard(
        TaskAuthorityConfig {
            database_path: root.path().join("task.db"),
            store_epoch: "g4-07-task".to_owned(),
            key: SqlCipherKey::new([41; 32]),
        },
        AllowCreation,
        ConfiguredTaskTransitionGuard::with_founder_verdict(Arc::clone(&verdict_handle)),
    )
    .expect("open Task Authority");

    let pending = advance_to_verdict_pending(&mut task);
    let scope = VerdictScope {
        task_id: pending.task_id.clone(),
        task_revision: pending.revision,
        work_revision: pending.work_revision,
        artifact_set_id: pending.artifact_set_id.clone().expect("artifact set"),
        artifact_set_manifest: Some(address(SHA_A)),
        verification_artifact_id: pending
            .verification_artifact_id
            .clone()
            .expect("verification artifact"),
        verification_payload: Some(address(SHA_B)),
        acceptance_contract_ref: pending.acceptance_contract_ref.clone(),
    };
    let verdict_authority = FounderVerdictAuthority::open(
        VerdictAuthorityConfig {
            database_path: root.path().join("verdict.db"),
            store_epoch: "g4-07-verdict".to_owned(),
            key: VerdictSqlCipherKey::new([42; 32]),
        },
        StaticVerdictResolver {
            context: ResolvedVerdictContext {
                scope: scope.clone(),
                verification_conclusion: VerificationConclusion::Passed,
                open_discrepancy_ids: Vec::new(),
                open_unverified_item_ids: Vec::new(),
                non_overridable_gate_ids: Vec::new(),
            },
        },
    )
    .expect("open Founder Verdict Authority");
    *verdict_handle.lock().expect("verdict handle") = Some(verdict_authority);

    let mut issue = VerdictCommand {
        command: Some(verdict_command::Command::IssueFounderVerdict(
            IssueFounderVerdictCommand {
                metadata: Some(metadata("issue")),
                scope: Some(scope),
                decision: FounderVerdictDecision::Accept as i32,
                observed_verification_conclusion: VerificationConclusion::Passed as i32,
                required_confirmation_class: ConfirmationClass::Explicit as i32,
                confirmation_proof_ref: "confirm:g4-07".to_owned(),
                expires_at: Some(Timestamp {
                    seconds: now().seconds + 300,
                    nanos: 0,
                }),
                ..Default::default()
            },
        )),
    };
    seal_verdict(&mut issue);
    let issued = verdict_handle
        .lock()
        .expect("verdict handle")
        .as_mut()
        .expect("verdict authority")
        .execute(
            &issue,
            &AuthenticatedVerdictPrincipal {
                kind: VerdictPrincipalKind::FounderAuthority,
                principal_id: "founder:local".to_owned(),
                authenticated: true,
            },
        )
        .expect("issue Founder Verdict");
    assert!(issued.committed);
    let verdict_id = issued.verdict.expect("issued verdict").founder_verdict_id;

    let applied = execute_task(
        &mut task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::ApplyFounderVerdict(
                ApplyFounderVerdictCommand {
                    meta: Some(metadata("apply")),
                    task_id: pending.task_id.clone(),
                    expected_revision: pending.revision,
                    work_revision: pending.work_revision,
                    founder_verdict_id: verdict_id.clone(),
                },
            )),
        }),
        PrincipalKind::FounderAuthority,
    );
    let completed = task_from(applied);
    assert_eq!(completed.status, TaskStatus::Completed as i32);
    assert_eq!(completed.revision, pending.revision + 1);
    let outbox = task
        .pending_cross_authority_outbox()
        .expect("Task cross-authority outbox");
    assert_eq!(
        outbox
            .iter()
            .filter(|message| message.destination_domain == "founder-verdict-authority")
            .count(),
        1
    );

    let task = Arc::new(Mutex::new(task));
    let worker = ConfiguredFounderVerdictConsumeWorker::new(
        Arc::clone(&task),
        Arc::clone(&verdict_handle),
        "task-authority:founder-verdict-consumer",
    )
    .expect("configure consume worker");
    let consumed = worker.run_once().await.expect("consume Founder Verdict");
    assert!(matches!(
        consumed,
        FounderVerdictConsumeCycleResult::Consumed {
            replayed: false,
            ..
        }
    ));
    assert!(
        task.lock()
            .expect("Task Authority lock")
            .pending_cross_authority_outbox()
            .expect("pending Task outbox")
            .into_iter()
            .all(|message| message.destination_domain != "founder-verdict-authority")
    );
    let (_, state) = verdict_handle
        .lock()
        .expect("Verdict Authority lock")
        .as_ref()
        .expect("Founder Verdict Authority")
        .get(&verdict_id)
        .expect("read consumed Founder Verdict")
        .expect("stored Founder Verdict");
    assert_eq!(
        state.state,
        egopulse_domain_contracts::v01::egopulse::verdict::v1::FounderVerdictStateKind::Consumed
            as i32
    );
}

fn advance_to_verdict_pending(task: &mut TaskAuthority) -> TaskSnapshot {
    let created = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::CreateTask(CreateTaskCommand {
                meta: Some(metadata("create")),
                work_type: "governed_repository_change".to_owned(),
                input_snapshot_id: "input-01".to_owned(),
                target_scope_ref: "scope-01".to_owned(),
                acceptance_contract_ref: Some(contract("acceptance", 0x11)),
                budget_profile_ref: Some(contract("budget", 0x22)),
            })),
        }),
        PrincipalKind::Founder,
    ));
    let active = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::ActivateTask(ActivateTaskCommand {
                meta: Some(metadata("activate")),
                task_id: created.task_id.clone(),
                expected_revision: created.revision,
                work_revision: created.work_revision,
                run_id: "run-01".to_owned(),
            })),
        }),
        PrincipalKind::CollaborationControl,
    ));
    let evidence = task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::SubmitTaskEvidence(
                SubmitTaskEvidenceCommand {
                    meta: Some(metadata("evidence")),
                    task_id: active.task_id.clone(),
                    expected_revision: active.revision,
                    work_revision: active.work_revision,
                    return_handoff_id: "handoff-01".to_owned(),
                    artifact_set_id: "artifact-set-01".to_owned(),
                },
            )),
        }),
        PrincipalKind::CollaborationControl,
    ));
    task_from(execute_task(
        task,
        seal_task(TaskCommand {
            command: Some(task_command::Command::RecordTaskVerification(
                RecordTaskVerificationCommand {
                    meta: Some(metadata("verification")),
                    task_id: evidence.task_id.clone(),
                    expected_revision: evidence.revision,
                    work_revision: evidence.work_revision,
                    verification_artifact_id: "verification-artifact-01".to_owned(),
                },
            )),
        }),
        PrincipalKind::SegoVerification,
    ))
}

fn execute_task(
    task: &mut TaskAuthority,
    command: TaskCommand,
    kind: PrincipalKind,
) -> egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult {
    task.execute(
        &command,
        &AuthenticatedPrincipal {
            kind,
            principal_id: format!("g4-07:{kind:?}"),
            authenticated: true,
        },
    )
    .expect("Task command result")
}

fn task_from(
    result: egopulse_domain_contracts::v01::egopulse::task::v1::TaskCommandResult,
) -> TaskSnapshot {
    match result.outcome.expect("Task outcome") {
        task_command_result::Outcome::Task(task) => task,
        other => panic!("Task outcome expected, got {other:?}"),
    }
}

fn metadata(operation: &str) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("g4-07:{operation}:{}", Uuid::now_v7()),
        idempotency_key: format!("g4-07:{operation}:{}", Uuid::now_v7()),
        idempotency_scope: "g4-07-production".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(now()),
        correlation_id: format!("g4-07:{operation}"),
        causation_id: None,
    }
}

fn seal_task(mut command: TaskCommand) -> TaskCommand {
    let digest = task_digest(&command).expect("Task digest");
    match command.command.as_mut() {
        Some(task_command::Command::CreateTask(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::ActivateTask(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::SubmitTaskEvidence(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::RecordTaskVerification(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        Some(task_command::Command::ApplyFounderVerdict(value)) => {
            value.meta.as_mut().expect("metadata").request_digest_sha256 = digest
        }
        _ => panic!("unexpected Task command"),
    }
    command
}

fn seal_verdict(command: &mut VerdictCommand) {
    let digest = verdict_digest(command);
    if let Some(verdict_command::Command::IssueFounderVerdict(value)) = command.command.as_mut() {
        value
            .metadata
            .as_mut()
            .expect("verdict metadata")
            .request_digest_sha256 = digest;
    }
}

fn contract(id: &str, byte: u8) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: "v1".to_owned(),
        sha256: hex::encode([byte; 32]),
    }
}

fn address(digest: &str) -> ContentAddress {
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: digest.to_owned(),
        byte_length: 128,
    }
}

fn now() -> Timestamp {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock");
    Timestamp {
        seconds: duration.as_secs() as i64,
        nanos: duration.subsec_nanos() as i32,
    }
}
