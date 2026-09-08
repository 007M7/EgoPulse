use crate::{
    AuthenticatedVerificationPrincipal, GovernedSegoRunError, GovernedSegoRunner, SegoMapperPolicy,
    VerificationAuthority, VerificationAuthorityFailure, VerificationClock,
    VerificationPrincipalKind, canonical_request_digest,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::CommandMetadata;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CompleteVerificationCommand, HoldVerificationCommand, RecordCriterionResultCommand,
    StartVerificationRunCommand, VerificationArtifact, VerificationCommand, VerificationProvenance,
    VerificationStatus, verification_command,
};
use prost_types::Timestamp;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;

const EXECUTION_IDEMPOTENCY_SCOPE: &str = "verification-execution-v1";
const VERIFICATION_PRINCIPAL_ID: &str = "verification-runtime:local";
const RECOVERY_OUTCOME_UNKNOWN: &str = "CHECKER_EXECUTION_OUTCOME_UNKNOWN_AFTER_RESTART";

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
    #[error("attested checker profile was not found")]
    CheckerProfileNotFound,
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
    #[error("verification execution is held for recovery: {reason_code}")]
    HeldForRecovery {
        verification_run_id: String,
        reason_code: String,
    },
}

/// One execution identity, shared by legacy single-checker and task-bound
/// multi-criterion execution. Authority state and recovery use the same path.
#[derive(Clone, Debug)]
pub struct GovernedVerificationBatchPlan {
    pub verification_request_id: String,
    pub verification_run_id: String,
    pub verification_artifact_id: String,
    pub issued_at: Timestamp,
}

#[derive(Clone, Debug)]
pub struct GovernedVerificationCheckOutput {
    pub results: Vec<crate::SegoMappedResult>,
    pub tool_receipt_artifact_ids: Vec<String>,
    pub model_call_receipt_artifact_ids: Vec<String>,
    pub raw_output_artifact_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Error)]
#[error("checker output could not be durably captured")]
pub struct GovernedVerificationCheckerError;

/// The application reads the current sealed inputs, executes its configured
/// checkers, and seals their outputs before returning. It cannot write
/// Verification facts: this coordinator remains their existing writer boundary.
pub trait GovernedVerificationChecker: Send + Sync {
    fn check<'a>(
        &'a self,
        request: &'a egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
        run_id: &'a str,
        profiles: &'a [egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfile],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        GovernedVerificationCheckOutput,
                        GovernedVerificationCheckerError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}

pub struct GovernedVerificationExecutionCoordinator<C> {
    authority: Arc<Mutex<VerificationAuthority<C>>>,
    runner: Option<GovernedSegoRunner>,
    execution_lock: tokio::sync::Mutex<()>,
}

enum StartedExecution {
    Fresh(egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRun),
    Completed(Box<VerificationArtifact>),
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
        Self {
            authority,
            runner: Some(runner),
            execution_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[must_use]
    pub fn from_authority(authority: Arc<Mutex<VerificationAuthority<C>>>) -> Self {
        Self {
            authority,
            runner: None,
            execution_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn execute_one(
        &self,
        plan: GovernedVerificationExecutionPlan,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        let _execution_guard = self.execution_lock.lock().await;
        validate_plan(&plan)?;
        let runner = self
            .runner
            .as_ref()
            .ok_or(GovernedVerificationExecutionError::InvalidPlan)?;
        let request = self.read_request(&plan.verification_request_id)?;
        validate_request(&request, &plan)?;
        let profiles = self.read_profiles(&request)?;
        let profile = profiles
            .iter()
            .find(|profile| {
                profile.checker_profile_id == plan.mapper_policy.checker_profile_ref.contract_id
            })
            .ok_or(GovernedVerificationExecutionError::CheckerProfileNotFound)?;
        let identity = GovernedVerificationBatchPlan {
            verification_request_id: plan.verification_request_id.clone(),
            verification_run_id: plan.verification_run_id.clone(),
            verification_artifact_id: plan.verification_artifact_id.clone(),
            issued_at: plan.issued_at,
        };
        let run = match self.begin_execution(&identity, &request)? {
            StartedExecution::Fresh(run) => run,
            StartedExecution::Completed(artifact) => return Ok(replayed(*artifact)),
        };
        let started = Instant::now();
        let mut output = runner
            .run(
                &plan.working_directory,
                &plan.checker_request,
                &plan.execution_id,
                &plan.mapper_policy,
            )
            .await?;
        output.mapped.criterion_result.assurance_class = profile.assurance_class;
        output.mapped.criterion_result.duration_ms = elapsed_millis(started);
        self.finish_execution(
            &identity,
            &request,
            run,
            GovernedVerificationCheckOutput {
                results: vec![output.mapped],
                tool_receipt_artifact_ids: plan.tool_receipt_artifact_ids,
                model_call_receipt_artifact_ids: plan.model_call_receipt_artifact_ids,
                raw_output_artifact_ids: vec![plan.mapper_policy.raw_output_artifact_id],
            },
            elapsed_millis(started),
            true,
        )
    }

    pub async fn execute_prepared(
        &self,
        plan: GovernedVerificationBatchPlan,
        checker: &dyn GovernedVerificationChecker,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        let _execution_guard = self.execution_lock.lock().await;
        if [
            &plan.verification_request_id,
            &plan.verification_run_id,
            &plan.verification_artifact_id,
        ]
        .iter()
        .any(|id| id.trim().is_empty())
        {
            return Err(GovernedVerificationExecutionError::InvalidPlan);
        }
        let request = self.read_request(&plan.verification_request_id)?;
        let profiles = self.read_profiles(&request)?;
        let run = match self.begin_execution(&plan, &request)? {
            StartedExecution::Fresh(run) => run,
            StartedExecution::Completed(artifact) => return Ok(replayed(*artifact)),
        };
        let started = Instant::now();
        let output = match checker
            .check(&request, &plan.verification_run_id, &profiles)
            .await
        {
            Ok(output) => output,
            Err(_) => {
                self.hold_execution(&plan, &run, "CHECKER_OUTPUT_CAPTURE_INCOMPLETE")?;
                return Err(GovernedVerificationExecutionError::HeldForRecovery {
                    verification_run_id: run.verification_run_id,
                    reason_code: "CHECKER_OUTPUT_CAPTURE_INCOMPLETE".to_owned(),
                });
            }
        };
        match self.finish_execution(&plan, &request, run, output, elapsed_millis(started), false) {
            Ok(outcome) => Ok(outcome),
            Err(error) => self.recover_failed_completion(&plan, &request, error),
        }
    }

    fn recover_failed_completion(
        &self,
        plan: &GovernedVerificationBatchPlan,
        request: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
        original_error: GovernedVerificationExecutionError,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        // The checker has already run. Use the latest revision after partial
        // criterion commits, and report Held only after its Authority commit.
        let run = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_run(&plan.verification_run_id)?
            .ok_or(GovernedVerificationExecutionError::RunNotFound)?;
        if run.verification_request_id != request.verification_request_id {
            return Err(original_error);
        }
        if run.status == VerificationStatus::Completed as i32 {
            return match self.begin_execution(plan, request)? {
                StartedExecution::Completed(artifact) => Ok(replayed(*artifact)),
                StartedExecution::Fresh(_) => Err(original_error),
            };
        }
        if run.status == VerificationStatus::Held as i32 {
            return Err(GovernedVerificationExecutionError::HeldForRecovery {
                verification_run_id: run.verification_run_id,
                reason_code: run
                    .hold_reason_code
                    .unwrap_or_else(|| "VERIFICATION_HELD".to_owned()),
            });
        }
        if run.status != VerificationStatus::Running as i32 {
            return Err(original_error);
        }
        const REASON: &str = "CHECKER_RESULT_COMMIT_INCOMPLETE";
        self.hold_execution(plan, &run, REASON)?;
        Err(GovernedVerificationExecutionError::HeldForRecovery {
            verification_run_id: run.verification_run_id,
            reason_code: REASON.to_owned(),
        })
    }

    fn read_request(
        &self,
        request_id: &str,
    ) -> Result<
        egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
        GovernedVerificationExecutionError,
    > {
        self.authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_request(request_id)?
            .ok_or(GovernedVerificationExecutionError::RequestNotFound)
    }

    fn read_profiles(
        &self,
        request: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
    ) -> Result<
        Vec<egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfile>,
        GovernedVerificationExecutionError,
    > {
        let authority = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?;
        request.checker_profile_refs.iter().map(|reference| {
            let profile = authority.checker_profile(&reference.contract_id)?
                .ok_or(GovernedVerificationExecutionError::CheckerProfileNotFound)?;
            if !crate::profile_ref_matches(reference, &profile)
                || profile.status != egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerProfileStatus::Active as i32 {
                return Err(GovernedVerificationExecutionError::InvalidPlan);
            }
            Ok(profile)
        }).collect()
    }

    fn begin_execution(
        &self,
        plan: &GovernedVerificationBatchPlan,
        request: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
    ) -> Result<StartedExecution, GovernedVerificationExecutionError> {
        let mut run = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_run(&plan.verification_run_id)?;
        let mut started_here = false;
        if run.is_none() {
            if request.status != VerificationStatus::Queued as i32 {
                return Err(GovernedVerificationExecutionError::RunNotExecutable(
                    "request is not queued",
                ));
            }
            let result = self.execute_authority(
                &start_command(plan, request.revision),
                &verification_principal(),
            )?;
            require_committed(
                result.committed,
                result.replayed,
                result.safe_error_fingerprint,
            )?;
            started_here = result.committed && !result.replayed;
            run = self
                .authority
                .lock()
                .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
                .verification_run(&plan.verification_run_id)?;
        }
        let run = run.ok_or(GovernedVerificationExecutionError::RunNotFound)?;
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
            if artifact.verification_request_id != request.verification_request_id
                || artifact.verification_run_id != run.verification_run_id
                || artifact.binding != request.binding
            {
                return Err(GovernedVerificationExecutionError::RecoveryResultMismatch);
            }
            return Ok(StartedExecution::Completed(Box::new(artifact)));
        }
        if run.status == VerificationStatus::Held as i32 {
            return Err(GovernedVerificationExecutionError::HeldForRecovery {
                verification_run_id: run.verification_run_id,
                reason_code: run
                    .hold_reason_code
                    .unwrap_or_else(|| "VERIFICATION_HELD".to_owned()),
            });
        }
        if run.status != VerificationStatus::Running as i32 {
            return Err(GovernedVerificationExecutionError::RunNotExecutable(
                "run is not running",
            ));
        }
        if !started_here {
            self.hold_execution(plan, &run, RECOVERY_OUTCOME_UNKNOWN)?;
            return Err(GovernedVerificationExecutionError::HeldForRecovery {
                verification_run_id: run.verification_run_id,
                reason_code: RECOVERY_OUTCOME_UNKNOWN.to_owned(),
            });
        }
        Ok(StartedExecution::Fresh(run))
    }

    fn hold_execution(
        &self,
        plan: &GovernedVerificationBatchPlan,
        run: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRun,
        reason_code: &str,
    ) -> Result<(), GovernedVerificationExecutionError> {
        let key = format!("{}:hold-unknown-execution", plan.verification_run_id);
        let command = seal_command(VerificationCommand {
            command: Some(verification_command::Command::HoldVerification(
                HoldVerificationCommand {
                    metadata: Some(metadata(&key, &plan.issued_at)),
                    verification_run_id: run.verification_run_id.clone(),
                    expected_run_revision: run.revision,
                    reason_code: reason_code.to_owned(),
                    evidence_artifact_ids: Vec::new(),
                },
            )),
        });
        let result = self.execute_authority(&command, &verification_principal())?;
        require_committed(
            result.committed,
            result.replayed,
            result.safe_error_fingerprint,
        )
    }

    fn finish_execution(
        &self,
        plan: &GovernedVerificationBatchPlan,
        request: &egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRequest,
        mut run: egopulse_domain_contracts::v01::egopulse::verification::v1::VerificationRun,
        output: GovernedVerificationCheckOutput,
        duration_ms: u64,
        legacy: bool,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        let ids = output
            .results
            .iter()
            .map(|mapped| mapped.criterion_result.criterion_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if output.results.is_empty()
            || ids.len() != output.results.len()
            || ids != request.criterion_ids.iter().map(String::as_str).collect()
            || output.raw_output_artifact_ids.is_empty()
        {
            return Err(GovernedVerificationExecutionError::InvalidPlan);
        }
        let mut discrepancies = Vec::new();
        let mut unverified_items = Vec::new();
        let mut profile_refs = Vec::new();
        for mapped in output.results {
            let reference = mapped
                .criterion_result
                .checker_profile_ref
                .as_ref()
                .ok_or(GovernedVerificationExecutionError::InvalidPlan)?;
            if !request.checker_profile_refs.contains(reference) {
                return Err(GovernedVerificationExecutionError::InvalidPlan);
            }
            if !profile_refs.contains(reference) {
                profile_refs.push(reference.clone());
            }
            let principal = AuthenticatedVerificationPrincipal {
                kind: if !legacy && mapped.criterion_result.assurance_class
                    == egopulse_domain_contracts::v01::egopulse::verification::v1::CheckerAssuranceClass::Deterministic as i32
                    { VerificationPrincipalKind::DeterministicChecker } else { VerificationPrincipalKind::SegoChecker },
                principal_id: format!("sego-checker:{}", reference.contract_id),
                authenticated: true,
                checker_profile_id: Some(reference.contract_id.clone()),
            };
            let result = self.execute_authority(
                &record_command(plan, run.revision, mapped.criterion_result),
                &principal,
            )?;
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
            discrepancies.extend(mapped.discrepancies);
            unverified_items.extend(mapped.unverified_items);
        }
        // Use the owner's existing aggregation rules for both execution paths.
        let computed = {
            let authority = self
                .authority
                .lock()
                .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?;
            let policies = authority.policy(&request.verification_request_id)?;
            crate::compute_conclusion(&policies, &run.criterion_results, &discrepancies)
                .map_err(|_| GovernedVerificationExecutionError::InvalidPlan)?
        };
        let artifact = VerificationArtifact {
            verification_artifact_id: plan.verification_artifact_id.clone(),
            version: 1,
            verification_request_id: request.verification_request_id.clone(),
            verification_run_id: run.verification_run_id.clone(),
            verification_type: request.verification_type.clone(),
            binding: request.binding.clone(),
            conclusion: computed.conclusion as i32,
            overall_evidence_coverage: computed.coverage as i32,
            criterion_results: run.criterion_results.clone(),
            discrepancies,
            unverified_items,
            provenance: Some(VerificationProvenance {
                verifier_principal_id: VERIFICATION_PRINCIPAL_ID.to_owned(),
                checker_profile_refs: profile_refs,
                tool_receipt_artifact_ids: output.tool_receipt_artifact_ids,
                model_call_receipt_artifact_ids: output.model_call_receipt_artifact_ids,
                raw_output_artifact_ids: output.raw_output_artifact_ids,
                duration_ms,
                cost_receipt_artifact_id: None,
            }),
            canonical_payload: None,
            completed_at: None,
            supersedes_verification_artifact_id: None,
        };
        let result = self.execute_authority(
            &complete_command(plan, run.revision, artifact),
            &verification_principal(),
        )?;
        require_committed(
            result.committed,
            result.replayed,
            result.safe_error_fingerprint,
        )?;
        let artifact = self
            .authority
            .lock()
            .map_err(|_| GovernedVerificationExecutionError::AuthorityLock)?
            .verification_artifact(&plan.verification_artifact_id)?
            .ok_or(GovernedVerificationExecutionError::ArtifactNotFound)?;
        Ok(GovernedVerificationExecutionOutcome {
            verification_artifact: artifact,
            replayed: result.replayed,
            recovered_existing_result: false,
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

fn replayed(artifact: VerificationArtifact) -> GovernedVerificationExecutionOutcome {
    GovernedVerificationExecutionOutcome {
        verification_artifact: artifact,
        replayed: true,
        recovered_existing_result: true,
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

fn start_command(
    plan: &GovernedVerificationBatchPlan,
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
    plan: &GovernedVerificationBatchPlan,
    expected_revision: u64,
    result: egopulse_domain_contracts::v01::egopulse::verification::v1::CriterionResult,
) -> VerificationCommand {
    let key = format!(
        "{}:record:{}",
        plan.verification_run_id, result.criterion_id
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
    plan: &GovernedVerificationBatchPlan,
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
        verification_command::Command::HoldVerification(value) => {
            value
                .metadata
                .as_mut()
                .expect("hold metadata")
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
