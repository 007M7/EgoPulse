use crate::{
    AuthenticatedVerificationPrincipal, CheckerOutputSink, CheckerOutputSource,
    CheckerProcessFailure, GovernedCheckerProcessOutcome, GovernedSegoRunError, GovernedSegoRunner,
    SealedCheckerOutput, SegoMapError, SegoMapperPolicy, VerificationAuthority,
    VerificationAuthorityFailure, VerificationClock, VerificationPrincipalKind,
    canonical_request_digest, checker_failure_result_with_detail, checker_uncited_failure_result,
    map_sego_review,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::CommandMetadata;
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    CheckerProfile, CompleteVerificationCommand, HoldVerificationCommand,
    RecordCriterionResultCommand, StartVerificationRunCommand, UnverifiedReason,
    VerificationArtifact, VerificationCommand, VerificationProvenance, VerificationRequest,
    VerificationStatus, verification_command,
};
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
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
#[derive(Clone)]
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
    /// Where this environment reads the checker's review artifact from.
    pub output_source: CheckerOutputSource,
    /// Optional application boundary that seals the exact checker bytes, so a
    /// Verification result cites the checker's own output instead of only the
    /// artifact its configuration declared.
    pub checker_output_sink: Option<Arc<dyn CheckerOutputSink>>,
}

/// Why one execution did not produce a citable checker result. Reading,
/// mapping and sealing failures are execution failures too, so the report
/// covers all four instead of only the process state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedCheckerFailureKind {
    /// The checker process failed or could not be started.
    Process(CheckerProcessFailure),
    /// A normally exited checker produced output this environment will not map.
    OutputUntrusted,
    /// The declared capture of this execution's output could not be sealed, so
    /// nothing this execution produced may be cited.
    CaptureRefused,
}

impl GovernedCheckerFailureKind {
    #[must_use]
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Process(failure) => failure.safe_code(),
            Self::OutputUntrusted => "CHECKER_OUTPUT_UNTRUSTED",
            Self::CaptureRefused => "CHECKER_OUTPUT_CAPTURE_REFUSED",
        }
    }
}

/// What one execution left behind for attribution. A report never changes a
/// criterion outcome; the failure itself already failed the criterion. The
/// checker's own declared code is reported as a declaration, not as a kernel
/// fact, and every citation is named for what it actually is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedCheckerFailureReport {
    pub kind: GovernedCheckerFailureKind,
    pub exit_code: Option<i32>,
    /// Digest and length of the bytes this execution could not turn into a
    /// result: its captured output, or the output that failed to map.
    pub output_sha256: Option<String>,
    pub output_byte_length: u64,
    /// A code the checker declared about its own stop or error.
    pub checker_declared_code: Option<String>,
    /// This execution's output, sealed. Present only when sealing succeeded.
    pub captured_artifact_id: Option<String>,
    /// The artifact the configuration declared, cited because this execution's
    /// output was not sealed. It belongs to the Task's input set, not to this
    /// execution.
    pub cited_configured_input_artifact_id: Option<String>,
    /// Why sealing this execution's output was refused, when it was.
    pub capture_failure_code: Option<String>,
}

/// What one completed execution contributes beyond its criterion results: how
/// long it took, which reader produced it, and what failed while producing it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GovernedVerificationCompletion {
    pub duration_ms: u64,
    pub legacy: bool,
    pub checker_failure: Option<GovernedCheckerFailureReport>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GovernedVerificationExecutionOutcome {
    pub verification_artifact: VerificationArtifact,
    pub replayed: bool,
    pub recovered_existing_result: bool,
    pub checker_failure: Option<GovernedCheckerFailureReport>,
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
        let process = runner
            .run_checker(
                &plan.working_directory,
                &plan.checker_request,
                &plan.execution_id,
                plan.output_source,
            )
            .await?;
        // One execution cites one raw output: the checker's own bytes when
        // this environment can seal them, otherwise — and only when no capture
        // is declared — the artifact its configuration named. A declared
        // capture that cannot be sealed is a failure of this execution: it
        // fails the criterion and cites nothing.
        let capture = capture_checker_output(&plan, &request, profile, &process);
        let capture_failure_code = capture.failure_code();
        let capture_refused = capture.is_refused();
        let sealed_citation = capture.sealed();
        let mut policy = plan.mapper_policy.clone();
        if let Some(sealed) = sealed_citation.as_ref() {
            policy.raw_output_artifact_id = sealed.artifact_id.clone();
            policy.raw_output_address = sealed.address.clone();
        }
        let detail = sealed_citation
            .as_ref()
            .map(|sealed| sealed.artifact_id.as_str());
        let (mapped, effective_failure) = match process.failure {
            Some(failure) => (
                checker_failure_result_with_detail(&policy, &plan.execution_id, failure, detail),
                Some(GovernedCheckerFailureKind::Process(failure)),
            ),
            None => match map_sego_review(&process.output, &policy) {
                Ok(mapped) => (mapped, None),
                Err(SegoMapError::InvalidJson)
                | Err(SegoMapError::ProfileMismatch)
                | Err(SegoMapError::BindingMismatch)
                | Err(SegoMapError::InconsistentArtifact) => (
                    checker_failure_result_with_detail(
                        &policy,
                        &plan.execution_id,
                        CheckerProcessFailure::OutputUntrusted,
                        detail,
                    ),
                    Some(GovernedCheckerFailureKind::OutputUntrusted),
                ),
            },
        };
        // A declared capture this execution could not seal — refused, or with
        // no output at all — is a failure of this execution: neither its
        // outcome nor the configured input artifact may stand in for output
        // that never became evidence. The process failure, when there was one,
        // stays the reported kind; the refusal is reported beside it.
        let (mapped, effective_failure, raw_output_artifact_ids) = if capture_refused {
            let reason = match process.failure {
                Some(CheckerProcessFailure::Unavailable | CheckerProcessFailure::Timeout) => {
                    UnverifiedReason::CheckerUnavailable
                }
                _ => UnverifiedReason::InsufficientEvidence,
            };
            (
                checker_uncited_failure_result(&policy, &plan.execution_id, reason),
                effective_failure.or(Some(GovernedCheckerFailureKind::CaptureRefused)),
                Vec::new(),
            )
        } else {
            let raw_output_artifact_ids = vec![
                sealed_citation
                    .as_ref()
                    .map(|sealed| sealed.artifact_id.clone())
                    .unwrap_or_else(|| policy.raw_output_artifact_id.clone()),
            ];
            (mapped, effective_failure, raw_output_artifact_ids)
        };
        let unsealed = process
            .captured
            .as_ref()
            .map(|captured| captured.bytes.as_slice())
            .unwrap_or(process.output.as_slice());
        let checker_failure = effective_failure.map(|kind| GovernedCheckerFailureReport {
            kind,
            exit_code: process.receipt.as_ref().map(|receipt| receipt.exit_code),
            output_sha256: (!unsealed.is_empty()).then(|| hex::encode(Sha256::digest(unsealed))),
            output_byte_length: unsealed.len() as u64,
            checker_declared_code: process
                .captured
                .as_ref()
                .and_then(|captured| captured.safe_reason_code.clone()),
            captured_artifact_id: sealed_citation
                .as_ref()
                .map(|sealed| sealed.artifact_id.clone()),
            cited_configured_input_artifact_id: (sealed_citation.is_none()
                && !raw_output_artifact_ids.is_empty())
            .then(|| policy.raw_output_artifact_id.clone()),
            capture_failure_code,
        });
        let mut result = mapped;
        result.criterion_result.assurance_class = profile.assurance_class;
        result.criterion_result.duration_ms = elapsed_millis(started);
        self.finish_execution(
            &identity,
            &request,
            run,
            GovernedVerificationCheckOutput {
                results: vec![result],
                tool_receipt_artifact_ids: plan.tool_receipt_artifact_ids,
                model_call_receipt_artifact_ids: plan.model_call_receipt_artifact_ids,
                raw_output_artifact_ids,
            },
            GovernedVerificationCompletion {
                duration_ms: elapsed_millis(started),
                legacy: true,
                checker_failure,
            },
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
        match self.finish_execution(
            &plan,
            &request,
            run,
            output,
            GovernedVerificationCompletion {
                duration_ms: elapsed_millis(started),
                legacy: false,
                checker_failure: None,
            },
        ) {
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
        completion: GovernedVerificationCompletion,
    ) -> Result<GovernedVerificationExecutionOutcome, GovernedVerificationExecutionError> {
        let GovernedVerificationCompletion {
            duration_ms,
            legacy,
            checker_failure,
        } = completion;
        let ids = output
            .results
            .iter()
            .map(|mapped| mapped.criterion_result.criterion_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        // A result that cites a detail artifact must also name the raw output
        // it came from. A result that cites nothing (an execution whose
        // declared output capture was refused) carries no raw output either:
        // an empty list is then honest, while a fabricated citation is not.
        let cites_a_detail = output
            .results
            .iter()
            .any(|mapped| mapped.criterion_result.safe_detail_artifact_id.is_some());
        if output.results.is_empty()
            || ids.len() != output.results.len()
            || ids != request.criterion_ids.iter().map(String::as_str).collect()
            || (cites_a_detail && output.raw_output_artifact_ids.is_empty())
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
            checker_failure,
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
        checker_failure: None,
    }
}

/// The outcome of the declared output capture for one execution.
enum CheckerOutputCapture {
    /// This environment declares no capture; the configured artifact stays the
    /// citation, as it did before capture was configurable.
    NotDeclared,
    Sealed(SealedCheckerOutput),
    /// Declared, but no output of this execution could be sealed.
    Refused {
        code: String,
    },
}

impl CheckerOutputCapture {
    fn sealed(self) -> Option<SealedCheckerOutput> {
        match self {
            Self::Sealed(sealed) => Some(sealed),
            _ => None,
        }
    }

    fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }

    fn failure_code(&self) -> Option<String> {
        match self {
            Self::Refused { code } => Some(code.clone()),
            _ => None,
        }
    }
}

/// Seals the bytes this execution cites as the checker's raw output. A
/// successful exchange cites the mapped review artifact; a failed one cites
/// what the failed process left behind. When the capture is declared and there
/// is nothing to seal — a zero-byte answer, an empty output file, a failure
/// that produced no receipt — the outcome is a typed refusal with no artifact,
/// so no citation of this execution can be invented from an earlier input.
fn capture_checker_output(
    plan: &GovernedVerificationExecutionPlan,
    request: &VerificationRequest,
    profile: &CheckerProfile,
    process: &GovernedCheckerProcessOutcome,
) -> CheckerOutputCapture {
    let Some(sink) = plan.checker_output_sink.as_deref() else {
        return CheckerOutputCapture::NotDeclared;
    };
    let (key, bytes) = match process.failure {
        None if !process.output.is_empty() => ("review", process.output.as_slice()),
        _ => match process.captured.as_ref() {
            Some(captured) if !captured.bytes.is_empty() => {
                ("checker-failure-output", captured.bytes.as_slice())
            }
            _ => {
                return CheckerOutputCapture::Refused {
                    code: "CHECKER_OUTPUT_CAPTURE_EMPTY".to_owned(),
                };
            }
        },
    };
    match sink.capture(request, &plan.verification_run_id, profile, key, bytes) {
        Ok(sealed) => CheckerOutputCapture::Sealed(sealed),
        Err(code) => CheckerOutputCapture::Refused { code },
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
