use crate::{
    AuthenticatedVerificationPrincipal, GovernedSegoRunError, GovernedSegoRunner, SegoMapperPolicy,
    VerificationAuthority, VerificationAuthorityFailure, VerificationClock,
    VerificationPrincipalKind, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::CommandMetadata;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CompleteVerificationCommand, CriterionOutcome, CriterionRequirement, EvidenceCoverage,
    RecordCriterionResultCommand, StartVerificationRunCommand, VerificationArtifact,
    VerificationCommand, VerificationConclusion, VerificationProvenance, VerificationStatus,
    verification_command,
};
use prost_types::Timestamp;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;

const EXECUTION_IDEMPOTENCY_SCOPE: &str = "verification-execution-v1";
const VERIFICATION_PRINCIPAL_ID: &str = "verification-runtime:local";

/// Reviewed inputs for one single-criterion Sego execution. The coordinator
/// accepts no policy derived from a Task payload; the mapper policy and
/// provenance references are explicit composition data.
#[derive(Clone, Debug)]
pub struct GovernedVerificationExecutionPlan {
    pub verification_request_id: String,
    pub verification_run_id: String,
    pub execution_id: String,
    pub working_directory: PathBuf,
    pub checker_request: Vec<u8>,
    pub mapper_policy: SegoMapperPolicy,
    pub verification_artifact_id: String,
    pub tool_receipt_artifact_ids: Vec<String>,
    pub model_call_receipt_artifact_ids: Vec<String>,
    pub issued_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GovernedVerificationExecutionOutcome {
    pub verification_artifact: VerificationArtifact,
    pub replayed: bool,
    pub recovered_existing_result: bool,
}

#[derive(Debug, Error)]
pub enum GovernedVerificationExecutionError {
    #[error("single-criterion execution plan is invalid")]
    InvalidPlan,
    #[error("Verification Authority lock is poisoned")]
    AuthorityLock,
    #[error("Verification Authority failed: {0}")]
    Authority(#[from] VerificationAuthorityFailure),
    #[error("Sego runner failed to start: {0}")]
    Runner(#[from] GovernedSegoRunError),
    #[error("verification request was not found")]
    RequestNotFound,
    #[error("verification run was not found after start")]
    RunNotFound,
    #[error("verification run is not executable: {0}")]
    RunNotExecutable(&'static str),
    #[error("Verification Authority rejected execution command: {0}")]
    Rejected(String),
    #[error("recovered checker result does not match the durable result")]
    RecoveryResultMismatch,
    #[error("completed verification artifact is missing")]
    ArtifactNotFound,
}

/// Application-level coordinator for the first real Verification vertical.
/// It is deliberately single-criterion and reuses the existing governed
/// supervisor/mapper. Authority remains the only writer of request, run and
/// artifact state.
pub struct GovernedVerificationExecutionCoordinator<C> {
    authority: Arc<Mutex<VerificationAuthority<C>>>,
    runner: GovernedSegoRunner,
}

impl<C> GovernedVerificationExecutionCoordinator<C>
where
    C: VerificationClock,
{
    #[must_use]
    pub fn new(
        authority: Arc<Mutex<VerificationAuthority<C>>>,
        runner: GovernedSegoRunner,
    ) -> Self {
        Self { authority, runner }
    }

    pub async fn execute_one(
        &self,
        plan: GovernedVerificationExecutionPlan,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        validate_plan(&plan)?;
        let request = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_request(&plan.verification_request_id)?
            .ok_or(GovernedVerificationExecutionError::RequestNotFound)?;
        validate_request(&request, &plan)?;

        let mut run = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_run(&plan.verification_run_id)?;

        if run.is_none() {
            if request.status != VerificationStatus::Queued as i32 {
                return Err(GovernedVerificationExecutionError::RunNotExecutable(
                    "request is not queued",
                ));
            }
            let command = start_command(&plan, request.revision);
            let result = self.execute_authority(&command, &verification_principal())?;
            require_committed(
                result.committed,
                result.replayed,
                result.safe_error_fingerprint,
            )?;
            run = self
                .authority
                .lock()
                .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
                .verification_run(&plan.verification_run_id)?;
        }

        let mut run = run.ok_or(GovernedVerificationExecutionError::RunNotFound)?;
        if run.verification_request_id != request.verification_request_id {
            return Err(GovernedVerificationExecutionError::RunNotExecutable(
                "run/request identity mismatch",
            ));
        }
        if run.status == VerificationStatus::Completed as i32 {
            let artifact = self
                .authority
                .lock()
                .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
                .verification_artifact(&plan.verification_artifact_id)?
                .ok_or(GovernedVerificationExecutionError::ArtifactNotFound)?;
            return Ok(GovernedVerificationExecutionOutcome {
                verification_artifact: artifact,
                replayed: true,
                recovered_existing_result: true,
            });
        }
        if run.status != VerificationStatus::Running as i32 {
            return Err(GovernedVerificationExecutionError::RunNotExecutable(
                "run is not running",
            ));
        }

        let started = Instant::now();
        let mut mapped = self
            .runner
            .run(
                &plan.working_directory,
                &plan.checker_request,
                &plan.execution_id,
                &plan.mapper_policy,
            )
            .await?;
        let elapsed_ms = elapsed_millis(started);
        mapped.mapped.criterion_result.duration_ms = elapsed_ms;

        let recovered_existing_result = if let Some(stored) = run
            .criterion_results
            .iter()
            .find(|value| value.criterion_id == plan.mapper_policy.criterion_id)
        {
            let mut reconstructed = mapped.mapped.criterion_result.clone();
            reconstructed.duration_ms = stored.duration_ms;
            if reconstructed != *stored {
                return Err(GovernedVerificationExecutionError::RecoveryResultMismatch);
            }
            true
        } else {
            let command =
                record_command(&plan, run.revision, mapped.mapped.criterion_result.clone());
            let result = self.execute_authority(&command, &checker_principal(&plan))?;
            require_committed(
                result.committed,
                result.replayed,
                result.safe_error_fingerprint,
            )?;
            run = self
                .authority
                .lock()
                .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
                .verification_run(&plan.verification_run_id)?
                .ok_or(GovernedVerificationExecutionError::RunNotFound)?;
            false
        };

        let result = run
            .criterion_results
            .iter()
            .find(|value| value.criterion_id == plan.mapper_policy.criterion_id)
            .cloned()
            .ok_or(GovernedVerificationExecutionError::RunNotFound)?;
        let artifact = VerificationArtifact {
            verification_artifact_id: plan.verification_artifact_id.clone(),
            version: 1,
            verification_request_id: request.verification_request_id.clone(),
            verification_run_id: run.verification_run_id.clone(),
            verification_type: request.verification_type.clone(),
            binding: request.binding.clone(),
            conclusion: single_criterion_conclusion(&result),
            overall_evidence_coverage: result.evidence_coverage,
            criterion_results: run.criterion_results.clone(),
            discrepancies: mapped.mapped.discrepancies,
            unverified_items: mapped.mapped.unverified_items,
            provenance: Some(VerificationProvenance {
                verifier_principal_id: VERIFICATION_PRINCIPAL_ID.to_owned(),
                checker_profile_refs: vec![plan.mapper_policy.checker_profile_ref.clone()],
                tool_receipt_artifact_ids: plan.tool_receipt_artifact_ids.clone(),
                model_call_receipt_artifact_ids: plan.model_call_receipt_artifact_ids.clone(),
                raw_output_artifact_ids: vec![plan.mapper_policy.raw_output_artifact_id.clone()],
                duration_ms: elapsed_ms,
                cost_receipt_artifact_id: None,
            }),
            canonical_payload: None,
            completed_at: None,
            supersedes_verification_artifact_id: None,
        };
        let command = complete_command(&plan, run.revision, artifact);
        let authority_result = self.execute_authority(&command, &verification_principal())?;
        require_committed(
            authority_result.committed,
            authority_result.replayed,
            authority_result.safe_error_fingerprint,
        )?;
        let artifact = authority_result
            .artifact
            .or_else(|| {
                self.authority.lock().ok().and_then(|authority| {
                    authority
                        .verification_artifact(&plan.verification_artifact_id)
                        .ok()
                        .flatten()
                })
            })
            .ok_or(GovernedVerificationExecutionError::ArtifactNotFound)?;
        Ok(GovernedVerificationExecutionOutcome {
            verification_artifact: artifact,
            replayed: authority_result.replayed,
            recovered_existing_result,
        })
    }

    fn execute_authority(
        &self,
        command: &VerificationCommand,
        principal: &AuthenticatedVerificationPrincipal,
    ) -> Result<
        egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationCommandResult,
        GovernedVerificationExecutionError,
    > {
        self.authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .execute(command, principal)
            .map_err(Into::into)
    }
}

fn validate_plan(
    plan: &GovernedVerificationExecutionPlan,
) -> Result<(), GovernedVerificationExecutionError> {
    if plan.verification_request_id.trim().is_empty()
        || plan.verification_run_id.trim().is_empty()
        || plan.execution_id.trim().is_empty()
        || plan.working_directory.as_os_str().is_empty()
        || plan.verification_artifact_id.trim().is_empty()
        || plan.mapper_policy.criterion_id.trim().is_empty()
        || plan.mapper_policy.raw_output_artifact_id.trim().is_empty()
        || plan
            .mapper_policy
            .checker_profile_ref
            .contract_id
            .trim()
            .is_empty()
        || plan
            .tool_receipt_artifact_ids
            .iter()
            .any(|value| value.trim().is_empty())
        || plan
            .model_call_receipt_artifact_ids
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err(GovernedVerificationExecutionError::InvalidPlan);
    }
    Ok(())
}

fn validate_request(
    request: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
    plan: &GovernedVerificationExecutionPlan,
) -> Result<(), GovernedVerificationExecutionError> {
    if request.criterion_ids.len() != 1
        || request.criterion_ids.first() != Some(&plan.mapper_policy.criterion_id)
        || !request
            .checker_profile_refs
            .iter()
            .any(|value| value == &plan.mapper_policy.checker_profile_ref)
    {
        return Err(GovernedVerificationExecutionError::InvalidPlan);
    }
    Ok(())
}

fn verification_principal() -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind: VerificationPrincipalKind::VerificationAuthority,
        principal_id: VERIFICATION_PRINCIPAL_ID.to_owned(),
        authenticated: true,
        checker_profile_id: None,
    }
}

fn checker_principal(
    plan: &GovernedVerificationExecutionPlan,
) -> AuthenticatedVerificationPrincipal {
    AuthenticatedVerificationPrincipal {
        kind: VerificationPrincipalKind::SegoChecker,
        principal_id: format!(
            "sego-checker:{}",
            plan.mapper_policy.checker_profile_ref.contract_id
        ),
        authenticated: true,
        checker_profile_id: Some(plan.mapper_policy.checker_profile_ref.contract_id.clone()),
    }
}

fn start_command(
    plan: &GovernedVerificationExecutionPlan,
    expected_revision: u64,
) -> VerificationCommand {
    let key = format!("{}:start", plan.verification_run_id);
    seal_command(VerificationCommand {
        command: Some(verification_command::Command::StartVerificationRun(
            StartVerificationRunCommand {
                metadata: Some(metadata(&key, &plan.issued_at)),
                verification_request_id: plan.verification_request_id.clone(),
                expected_request_revision: expected_revision,
                verification_run_id: plan.verification_run_id.clone(),
            },
        )),
    })
}

fn record_command(
    plan: &GovernedVerificationExecutionPlan,
    expected_revision: u64,
    result: egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionResult,
) -> VerificationCommand {
    let key = format!(
        "{}:record:{}",
        plan.verification_run_id, plan.mapper_policy.criterion_id
    );
    seal_command(VerificationCommand {
        command: Some(verification_command::Command::RecordCriterionResult(
            RecordCriterionResultCommand {
                metadata: Some(metadata(&key, &plan.issued_at)),
                verification_run_id: plan.verification_run_id.clone(),
                expected_run_revision: expected_revision,
                result: Some(result),
            },
        )),
    })
}

fn complete_command(
    plan: &GovernedVerificationExecutionPlan,
    expected_revision: u64,
    artifact: VerificationArtifact,
) -> VerificationCommand {
    let key = format!("{}:complete", plan.verification_run_id);
    seal_command(VerificationCommand {
        command: Some(verification_command::Command::CompleteVerification(
            CompleteVerificationCommand {
                metadata: Some(metadata(&key, &plan.issued_at)),
                verification_run_id: plan.verification_run_id.clone(),
                expected_run_revision: expected_revision,
                artifact: Some(artifact),
            },
        )),
    })
}

fn metadata(key: &str, issued_at: &Timestamp) -> CommandMetadata {
    CommandMetadata {
        command_id: format!("verification-execution-{key}"),
        idempotency_key: key.to_owned(),
        idempotency_scope: EXECUTION_IDEMPOTENCY_SCOPE.to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(*issued_at),
        correlation_id: key.to_owned(),
        causation_id: None,
    }
}

fn seal_command(mut command: VerificationCommand) -> VerificationCommand {
    let digest = canonical_request_digest(&command).expect("execution command canonicalization");
    match command.command.as_mut().expect("execution command") {
        verification_command::Command::StartVerificationRun(value) => {
            value
                .metadata
                .as_mut()
                .expect("start metadata")
                .request_digest_sha256 = digest;
        }
        verification_command::Command::RecordCriterionResult(value) => {
            value
                .metadata
                .as_mut()
                .expect("record metadata")
                .request_digest_sha256 = digest;
        }
        verification_command::Command::CompleteVerification(value) => {
            value
                .metadata
                .as_mut()
                .expect("complete metadata")
                .request_digest_sha256 = digest;
        }
        _ => unreachable!("only execution commands are sealed here"),
    }
    command
}

fn require_committed(
    committed: bool,
    replayed: bool,
    fingerprint: Option<String>,
) -> Result<(), GovernedVerificationExecutionError> {
    if committed || replayed {
        Ok(())
    } else {
        Err(GovernedVerificationExecutionError::Rejected(
            fingerprint.unwrap_or_else(|| "VERIFICATION_EXECUTION_REJECTED".to_owned()),
        ))
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().max(1) as u64
}

fn single_criterion_conclusion(
    result: &egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionResult,
) -> i32 {
    let requirement = CriterionRequirement::try_from(result.requirement).ok();
    let outcome = CriterionOutcome::try_from(result.outcome).ok();
    let coverage = EvidenceCoverage::try_from(result.evidence_coverage).ok();
    if coverage == Some(EvidenceCoverage::IntegrityFailed) {
        return VerificationConclusion::Indeterminate as i32;
    }
    match (requirement, outcome, coverage) {
        (
            Some(CriterionRequirement::MustPass),
            Some(CriterionOutcome::Failed),
            Some(EvidenceCoverage::Complete),
        ) => VerificationConclusion::Failed as i32,
        (
            Some(CriterionRequirement::MustPass),
            Some(CriterionOutcome::Passed),
            Some(EvidenceCoverage::Complete),
        ) => VerificationConclusion::Passed as i32,
        (Some(CriterionRequirement::MustPass), _, _) => {
            VerificationConclusion::Indeterminate as i32
        }
        (_, Some(CriterionOutcome::Passed), Some(EvidenceCoverage::Complete)) => {
            VerificationConclusion::Passed as i32
        }
        _ => VerificationConclusion::Partial as i32,
    }
}
