use std::sync::{Arc, Mutex};

use egopulse_cognition_runtime::task_authority::{
    PendingTaskVerification, TaskAuthority, TaskAuthorityFailure,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{ArtifactSet, ArtifactSetStatus, ContentAddress, HashAlgorithm},
    common::v1::{CommandMetadata, ContractReference},
    task::v1::{TaskEventKind, TaskStatus},
    verification::v1::{
        CreateVerificationRequestCommand, VerificationBinding, VerificationCommand,
        VerificationRequest, verification_command,
    },
};
use egopulse_verification_authority::{
    ArtifactReferenceSource, ArtifactReferenceSourceError, AuthenticatedVerificationPrincipal,
    VerificationAuthority, VerificationAuthorityFailure, canonical_request_digest,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use thiserror::Error;

const TASK_ACCEPTANCE: &str = "task_acceptance";
const HANDOFF_IDEMPOTENCY_SCOPE: &str = "task-verification-handoff-v1";

/// The parts of Artifact/Verification binding that cannot be inferred from a
/// Task handoff. They are reviewed configuration, not Agent output.
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationBindingTemplate {
    pub claim_id: String,
    pub claim_semantic_profile_ref: ContractReference,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffPlan {
    pub binding: VerificationBindingTemplate,
    pub criterion_ids: Vec<String>,
    pub checker_profile_refs: Vec<ContractReference>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffRequest {
    pub verification_request_id: String,
    pub request: VerificationRequest,
    pub message_id: String,
    pub payload_digest_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationHandoffPlanError {
    #[error("verification handoff plan is invalid")]
    Invalid,
    #[error("Task handoff is not VerificationPending")]
    TaskNotVerificationPending,
    #[error("Task handoff acceptance contract is missing")]
    AcceptanceContractMissing,
    #[error("Artifact set is missing, unsealed, or does not belong to the handoff")]
    ArtifactSetInvalid,
    #[error("Task handoff and configured lineage do not match")]
    LineageMismatch,
}

impl VerificationHandoffPlan {
    pub fn validate(&self) -> Result<(), VerificationHandoffPlanError> {
        let binding = &self.binding;
        if binding.claim_id.trim().is_empty()
            || !contract_reference_valid(&binding.claim_semantic_profile_ref)
            || self.criterion_ids.is_empty()
            || !unique_nonempty(&self.criterion_ids)
            || self.checker_profile_refs.is_empty()
            || !self
                .checker_profile_refs
                .iter()
                .all(contract_reference_valid)
            || !unique_contract_references(&self.checker_profile_refs)
        {
            return Err(VerificationHandoffPlanError::Invalid);
        }
        Ok(())
    }

    pub fn request_for(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
    ) -> Result<VerificationHandoffRequest, VerificationHandoffPlanError> {
        self.validate()?;
        let snapshot = handoff
            .event
            .snapshot
            .as_ref()
            .ok_or(VerificationHandoffPlanError::LineageMismatch)?;
        if snapshot.status != TaskStatus::VerificationPending as i32
            || handoff.event.kind != TaskEventKind::EvidenceSubmitted as i32
            || snapshot.task_id != handoff.event.task_id
            || snapshot.revision != handoff.event.resulting_revision
            || snapshot.work_revision != handoff.event.work_revision
        {
            return Err(VerificationHandoffPlanError::TaskNotVerificationPending);
        }
        let acceptance_contract_ref = snapshot
            .acceptance_contract_ref
            .clone()
            .ok_or(VerificationHandoffPlanError::AcceptanceContractMissing)?;
        if !contract_reference_valid(&acceptance_contract_ref) {
            return Err(VerificationHandoffPlanError::AcceptanceContractMissing);
        }
        let artifact_set_id = snapshot
            .artifact_set_id
            .as_deref()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if artifact_set.status != ArtifactSetStatus::Sealed as i32
            || artifact_set.artifact_set_id != artifact_set_id
            || !artifact_set
                .claim_ids
                .iter()
                .any(|id| id == &self.binding.claim_id)
        {
            return Err(VerificationHandoffPlanError::ArtifactSetInvalid);
        }
        let lineage = artifact_set
            .lineage
            .clone()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if !lineage_valid(&lineage)
            || lineage.task_id != snapshot.task_id
            || lineage.task_revision != snapshot.revision
            || lineage.work_revision != snapshot.work_revision
        {
            return Err(VerificationHandoffPlanError::LineageMismatch);
        }
        let artifact_set_manifest = artifact_set
            .canonical_manifest
            .clone()
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        if !content_address_valid(&artifact_set_manifest) {
            return Err(VerificationHandoffPlanError::ArtifactSetInvalid);
        }
        let binding = VerificationBinding {
            lineage: Some(lineage),
            artifact_set_id: artifact_set_id.to_owned(),
            artifact_set_manifest: Some(artifact_set_manifest),
            claim_id: self.binding.claim_id.clone(),
            claim_semantic_profile_ref: Some(self.binding.claim_semantic_profile_ref.clone()),
            acceptance_contract_ref: Some(acceptance_contract_ref),
        };
        let verification_request_id =
            deterministic_request_id(&snapshot.task_id, snapshot.revision, snapshot.work_revision);
        let request = VerificationRequest {
            verification_request_id: verification_request_id.clone(),
            revision: 0,
            status: 0,
            verification_type: TASK_ACCEPTANCE.to_owned(),
            binding: Some(binding),
            criterion_ids: self.criterion_ids.clone(),
            checker_profile_refs: self.checker_profile_refs.clone(),
            created_at: None,
            hold_reason_code: None,
        };
        Ok(VerificationHandoffRequest {
            verification_request_id,
            request,
            message_id: handoff.message_id.clone(),
            payload_digest_sha256: handoff.payload_digest_sha256.clone(),
        })
    }

    pub fn create_command(
        &self,
        handoff: &PendingTaskVerification,
        artifact_set: &ArtifactSet,
        issued_at: Timestamp,
    ) -> Result<VerificationCommand, VerificationHandoffPlanError> {
        let prepared = self.request_for(handoff, artifact_set)?;
        let mut metadata = CommandMetadata {
            command_id: format!("verification-handoff-{}", prepared.message_id),
            idempotency_key: prepared.message_id.clone(),
            idempotency_scope: HANDOFF_IDEMPOTENCY_SCOPE.to_owned(),
            request_digest_sha256: String::new(),
            issued_at: Some(issued_at),
            correlation_id: prepared.message_id.clone(),
            causation_id: None,
        };
        let mut command = VerificationCommand {
            command: Some(verification_command::Command::CreateVerificationRequest(
                CreateVerificationRequestCommand {
                    metadata: Some(metadata.clone()),
                    request: Some(prepared.request),
                },
            )),
        };
        metadata.request_digest_sha256 =
            canonical_request_digest(&command).ok_or(VerificationHandoffPlanError::Invalid)?;
        if let Some(verification_command::Command::CreateVerificationRequest(value)) =
            command.command.as_mut()
        {
            value.metadata = Some(metadata);
        }
        Ok(command)
    }
}

#[derive(Debug, Error)]
pub enum VerificationHandoffIntakeError {
    #[error("Task Authority handoff read failed: {0}")]
    Task(#[from] TaskAuthorityFailure),
    #[error("Verification Authority command failed: {0}")]
    Verification(#[from] VerificationAuthorityFailure),
    #[error("Verification handoff plan failed: {0}")]
    Plan(#[from] VerificationHandoffPlanError),
    #[error("Artifact Authority read failed: {0}")]
    Artifact(#[from] ArtifactReferenceSourceError),
    #[error("Task Authority lock is poisoned")]
    TaskLock,
    #[error("Verification Authority lock is poisoned")]
    VerificationLock,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationHandoffConsumeResult {
    pub message_id: String,
    pub payload_digest_sha256: String,
    pub verification_request_id: String,
    pub committed: bool,
    pub replayed: bool,
    pub task_outbox_acknowledged: bool,
}

/// Consumes one durable Task handoff. ACK is deliberately after the
/// Verification Authority commit/replay, so a crash between the two is safe:
/// the deterministic idempotency key replays the same Verification request.
pub struct VerificationHandoffIntake {
    task: Arc<Mutex<TaskAuthority>>,
    artifact: Box<dyn ArtifactReferenceSource>,
    verification: Arc<Mutex<VerificationAuthority>>,
    plan: VerificationHandoffPlan,
    principal: AuthenticatedVerificationPrincipal,
}

impl VerificationHandoffIntake {
    pub fn new(
        task: Arc<Mutex<TaskAuthority>>,
        artifact: Box<dyn ArtifactReferenceSource>,
        verification: Arc<Mutex<VerificationAuthority>>,
        plan: VerificationHandoffPlan,
        principal: AuthenticatedVerificationPrincipal,
    ) -> Result<Self, VerificationHandoffPlanError> {
        plan.validate()?;
        Ok(Self {
            task,
            artifact,
            verification,
            plan,
            principal,
        })
    }

    pub fn consume_one(
        &self,
        issued_at: Timestamp,
    ) -> Result<Option<VerificationHandoffConsumeResult>, VerificationHandoffIntakeError> {
        let handoff = {
            let task = self
                .task
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::TaskLock)?;
            task.pending_task_verifications()?.into_iter().next()
        };
        let Some(handoff) = handoff else {
            return Ok(None);
        };
        let artifact_set_id = handoff
            .event
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.artifact_set_id.as_deref())
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        let artifact_set = self
            .artifact
            .read_artifact_set(artifact_set_id)?
            .ok_or(VerificationHandoffPlanError::ArtifactSetInvalid)?;
        let command = self
            .plan
            .create_command(&handoff, &artifact_set, issued_at)?;
        let expected_request_id = self
            .plan
            .request_for(&handoff, &artifact_set)?
            .verification_request_id;
        let result = {
            let mut verification = self
                .verification
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::VerificationLock)?;
            verification.execute(&command, &self.principal)?
        };
        if !result.committed && !result.replayed {
            return Ok(Some(VerificationHandoffConsumeResult {
                message_id: handoff.message_id,
                payload_digest_sha256: handoff.payload_digest_sha256,
                verification_request_id: expected_request_id,
                committed: false,
                replayed: false,
                task_outbox_acknowledged: false,
            }));
        }
        let acknowledged = {
            let mut task = self
                .task
                .lock()
                .map_err(|_| VerificationHandoffIntakeError::TaskLock)?;
            task.acknowledge_cross_authority_outbox(
                &handoff.message_id,
                &handoff.payload_digest_sha256,
            )?
        };
        Ok(Some(VerificationHandoffConsumeResult {
            message_id: handoff.message_id,
            payload_digest_sha256: handoff.payload_digest_sha256,
            verification_request_id: expected_request_id,
            committed: result.committed,
            replayed: result.replayed,
            task_outbox_acknowledged: acknowledged,
        }))
    }
}

fn deterministic_request_id(task_id: &str, revision: u64, work_revision: u64) -> String {
    let seed = format!("{task_id}:{revision}:{work_revision}");
    format!(
        "verification-request-{}",
        hex::encode(Sha256::digest(seed.as_bytes()))
    )
}

fn unique_nonempty(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| !value.trim().is_empty())
        && values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == values.len()
}

fn unique_contract_references(values: &[ContractReference]) -> bool {
    values
        .iter()
        .map(|value| (&value.contract_id, &value.version, &value.sha256))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == values.len()
}

fn contract_reference_valid(value: &ContractReference) -> bool {
    !value.contract_id.trim().is_empty()
        && !value.version.trim().is_empty()
        && value.sha256.len() == 64
        && value
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lineage_valid(
    value: &egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding,
) -> bool {
    !value.task_id.trim().is_empty()
        && value.task_revision > 0
        && value.work_revision > 0
        && !value.run_id.trim().is_empty()
        && value.run_revision > 0
        && !value.step_id.trim().is_empty()
        && value.step_revision > 0
        && !value.attempt_id.trim().is_empty()
        && value.attempt_revision > 0
        && !value.dispatch_id.trim().is_empty()
        && value.fencing_token > 0
}

fn content_address_valid(value: &ContentAddress) -> bool {
    value.algorithm == HashAlgorithm::Sha256 as i32
        && value.byte_length > 0
        && value.digest.len() == 64
        && value
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactSet, ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding,
        },
        task::v1::{TaskEvent, TaskEventKind, TaskSnapshot},
    };

    fn contract(seed: &str) -> ContractReference {
        ContractReference {
            contract_id: format!("contract-{seed}"),
            version: "0.1.0".to_owned(),
            sha256: "a".repeat(64),
        }
    }

    fn plan() -> VerificationHandoffPlan {
        VerificationHandoffPlan {
            binding: VerificationBindingTemplate {
                claim_id: "claim-1".to_owned(),
                claim_semantic_profile_ref: contract("semantic"),
            },
            criterion_ids: vec!["criterion-1".to_owned()],
            checker_profile_refs: vec![contract("checker")],
        }
    }

    fn handoff() -> PendingTaskVerification {
        let snapshot = TaskSnapshot {
            task_id: "task-1".to_owned(),
            revision: 4,
            work_revision: 2,
            status: TaskStatus::VerificationPending as i32,
            acceptance_contract_ref: Some(contract("acceptance")),
            artifact_set_id: Some("artifact-set-1".to_owned()),
            ..TaskSnapshot::default()
        };
        PendingTaskVerification {
            message_id: "task-outbox-verification-1".to_owned(),
            payload_digest_sha256: "c".repeat(64),
            event: TaskEvent {
                event_id: "task-event-1".to_owned(),
                kind: TaskEventKind::EvidenceSubmitted as i32,
                task_id: "task-1".to_owned(),
                resulting_revision: 4,
                work_revision: 2,
                snapshot: Some(snapshot),
                ..TaskEvent::default()
            },
        }
    }

    fn artifact_set() -> ArtifactSet {
        ArtifactSet {
            artifact_set_id: "artifact-set-1".to_owned(),
            status: ArtifactSetStatus::Sealed as i32,
            lineage: Some(LineageBinding {
                task_id: "task-1".to_owned(),
                task_revision: 4,
                work_revision: 2,
                run_id: "run-1".to_owned(),
                run_revision: 1,
                step_id: "step-1".to_owned(),
                step_revision: 1,
                attempt_id: "attempt-1".to_owned(),
                attempt_revision: 1,
                dispatch_id: "dispatch-1".to_owned(),
                fencing_token: 1,
            }),
            claim_ids: vec!["claim-1".to_owned()],
            canonical_manifest: Some(ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: "b".repeat(64),
                byte_length: 128,
            }),
            ..ArtifactSet::default()
        }
    }

    #[test]
    fn explicit_plan_binds_task_facts_without_deriving_verification_policy() {
        let request = plan()
            .request_for(&handoff(), &artifact_set())
            .expect("valid handoff");
        assert_eq!(request.request.verification_type, TASK_ACCEPTANCE);
        assert_eq!(
            request
                .request
                .binding
                .as_ref()
                .unwrap()
                .lineage
                .as_ref()
                .unwrap()
                .task_id,
            "task-1"
        );
        assert_eq!(
            request.request.binding.as_ref().unwrap().artifact_set_id,
            "artifact-set-1"
        );
        assert_eq!(request.request.criterion_ids, vec!["criterion-1"]);
        assert_eq!(request.request.checker_profile_refs.len(), 1);
    }

    #[test]
    fn handoff_command_uses_deterministic_digest_bound_idempotency() {
        let command = plan()
            .create_command(
                &handoff(),
                &artifact_set(),
                Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                },
            )
            .expect("valid command");
        let verification_command::Command::CreateVerificationRequest(create) =
            command.command.as_ref().expect("command")
        else {
            panic!("wrong command");
        };
        let metadata = create.metadata.as_ref().expect("metadata");
        assert_eq!(metadata.idempotency_key, "task-outbox-verification-1");
        assert_eq!(metadata.idempotency_scope, HANDOFF_IDEMPOTENCY_SCOPE);
        assert_eq!(
            canonical_request_digest(&command).as_deref(),
            Some(metadata.request_digest_sha256.as_str())
        );
    }

    #[test]
    fn invalid_plan_is_rejected_before_any_authority_is_opened() {
        let mut invalid = plan();
        invalid.criterion_ids.clear();
        assert_eq!(
            invalid.validate(),
            Err(VerificationHandoffPlanError::Invalid)
        );
    }
}
