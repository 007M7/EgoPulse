#![forbid(unsafe_code)]

mod sego;
mod store;
mod supervisor;

pub use sego::{
    CheckerProcessFailure, SegoFindingEvidenceBinding, SegoMapError, SegoMappedResult,
    SegoMapperPolicy, checker_failure_result, map_sego_review,
};
pub use store::VerificationStoreInspection;
pub use supervisor::{CheckerExecutionError, CheckerExecutionReceipt, GovernedCheckerSupervisor};

use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactSetStatus, ContentAddress, HashAlgorithm, LineageBinding,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use egopulse_domain_contracts::v01::egopulse::verification::v1::{
    AttestCheckerProfileCommand, CheckerAssuranceClass, CheckerProfile, CheckerProfileStatus,
    CompleteVerificationCommand, CreateVerificationRequestCommand, CriterionOutcome,
    CriterionRequirement, CriterionResult, Discrepancy, DiscrepancySeverity, EvidenceCoverage,
    HoldVerificationCommand, RecordCriterionResultCommand, StartVerificationRunCommand,
    VerificationArtifact, VerificationBinding, VerificationCommand, VerificationCommandResult,
    VerificationConclusion, VerificationErrorCode, VerificationEvent, VerificationEventKind,
    VerificationRequest, VerificationRun, VerificationStatus, verification_command,
};
use prost::Message;
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{AuthorityCommit, Mutation, OutboxWrite, StoreError, VerificationStore};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const LOCAL_READ_MODEL: &str = "local-read-model";
const TASK_AUTHORITY: &str = "task-authority";
const FOUNDER_VERDICT: &str = "founder-verdict";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationPrincipalKind {
    TaskAuthority,
    VerificationAuthority,
    SegoChecker,
    DeterministicChecker,
    RecoveryCoordinator,
    Harness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedVerificationPrincipal {
    pub kind: VerificationPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
    pub checker_profile_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CriterionPolicySnapshot {
    pub criterion_id: String,
    pub requirement: i32,
    pub minimum_assurance: i32,
    pub not_applicable_allowed: bool,
    pub checker_profile_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedVerificationInput {
    pub artifact_set_status: ArtifactSetStatus,
    pub binding: VerificationBinding,
    pub criteria: Vec<CriterionPolicySnapshot>,
    pub evidence_ids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRejection {
    NotFound,
    BindingStale,
    ArtifactSetNotSealed,
    ManifestMismatch,
    ClaimMismatch,
    AcceptanceContractMismatch,
    CheckerProfileMismatch,
    EvidenceIncomplete,
    IntegrityFailure,
    OutputUntrusted,
}

/// Cross-authority reads return only verified immutable projections. An
/// implementation must not expose another Authority's database connection or
/// allow Verification Authority to repair the source facts.
pub trait VerificationReferenceResolver: Send + Sync + 'static {
    fn validate_checker_profile(&self, profile: &CheckerProfile) -> Result<(), ReferenceRejection>;

    fn resolve_request(
        &self,
        request: &VerificationRequest,
    ) -> Result<ResolvedVerificationInput, ReferenceRejection>;

    fn revalidate_binding(&self, binding: &VerificationBinding) -> Result<(), ReferenceRejection>;

    fn validate_result_references(
        &self,
        evidence_ids: &[String],
        artifact_ids: &[String],
    ) -> Result<(), ReferenceRejection>;
}

pub trait VerificationClock: Send + Sync + 'static {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemVerificationClock;

impl VerificationClock for SystemVerificationClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch");
        Timestamp {
            seconds: duration.as_secs() as i64,
            nanos: duration.subsec_nanos() as i32,
        }
    }
}

pub struct VerificationSqlCipherKey(Zeroizing<[u8; 32]>);

impl VerificationSqlCipherKey {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct VerificationAuthorityConfig {
    pub database_path: PathBuf,
    pub store_epoch: String,
    pub key: VerificationSqlCipherKey,
}

#[derive(Debug, Error)]
pub enum VerificationAuthorityFailure {
    #[error("verification authority storage failed")]
    Storage,
    #[error("verification authority persisted an undecodable contract value")]
    Decode(#[from] prost::DecodeError),
    #[error("verification authority policy snapshot is invalid")]
    PolicyDecode,
}

impl From<StoreError> for VerificationAuthorityFailure {
    fn from(_: StoreError) -> Self {
        Self::Storage
    }
}

pub struct VerificationAuthority<C = SystemVerificationClock> {
    store: VerificationStore,
    resolver: Box<dyn VerificationReferenceResolver>,
    clock: C,
}

impl VerificationAuthority<SystemVerificationClock> {
    pub fn open(
        config: VerificationAuthorityConfig,
        resolver: impl VerificationReferenceResolver,
    ) -> Result<Self, VerificationAuthorityFailure> {
        Self::open_with_clock(config, resolver, SystemVerificationClock)
    }
}

impl<C> VerificationAuthority<C>
where
    C: VerificationClock,
{
    pub fn open_with_clock(
        config: VerificationAuthorityConfig,
        resolver: impl VerificationReferenceResolver,
        clock: C,
    ) -> Result<Self, VerificationAuthorityFailure> {
        if config.store_epoch.trim().is_empty() {
            return Err(VerificationAuthorityFailure::Storage);
        }
        Ok(Self {
            store: VerificationStore::open(
                &config.database_path,
                config.key.expose(),
                &config.store_epoch,
            )?,
            resolver: Box::new(resolver),
            clock,
        })
    }

    pub fn execute(
        &mut self,
        command: &VerificationCommand,
        principal: &AuthenticatedVerificationPrincipal,
    ) -> Result<VerificationCommandResult, VerificationAuthorityFailure> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                VerificationErrorCode::InvalidArgument,
                "VERIFICATION_COMMAND_MISSING",
            ));
        };
        let Some(metadata) = command_metadata(command) else {
            return Ok(error_result(
                VerificationErrorCode::InvalidArgument,
                "COMMAND_METADATA_MISSING",
            ));
        };
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                VerificationErrorCode::Unauthenticated,
                "AUTHENTICATED_PRINCIPAL_REQUIRED",
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                VerificationErrorCode::PermissionDenied,
                "PRINCIPAL_OPERATION_NOT_ALLOWED",
            ));
        }
        if !metadata_complete(metadata) {
            return Ok(error_result(
                VerificationErrorCode::InvalidArgument,
                "COMMAND_METADATA_INVALID",
            ));
        }
        let Some(digest) = canonical_request_digest(command) else {
            return Ok(error_result(
                VerificationErrorCode::InvalidArgument,
                "COMMAND_CANONICALIZATION_FAILED",
            ));
        };
        if digest != metadata.request_digest_sha256 {
            return Ok(error_result(
                VerificationErrorCode::InvalidArgument,
                "REQUEST_DIGEST_MISMATCH",
            ));
        }
        if let Some(record) = self.store.idempotency_record(
            &principal.principal_id,
            operation,
            &metadata.idempotency_scope,
            &metadata.idempotency_key,
        )? {
            if record.request_digest_sha256 != digest {
                return Ok(error_result(
                    VerificationErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
                ));
            }
            let mut result = VerificationCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }

        let prepared = match command.command.as_ref().expect("checked above") {
            verification_command::Command::AttestCheckerProfile(value) => {
                self.prepare_attest(value, principal)?
            }
            verification_command::Command::CreateVerificationRequest(value) => {
                self.prepare_create_request(value)?
            }
            verification_command::Command::StartVerificationRun(value) => {
                self.prepare_start(value)?
            }
            verification_command::Command::RecordCriterionResult(value) => {
                self.prepare_record(value, principal)?
            }
            verification_command::Command::CompleteVerification(value) => {
                self.prepare_complete(value, principal)?
            }
            verification_command::Command::HoldVerification(value) => self.prepare_hold(value)?,
            verification_command::Command::RequestVerificationCancellation(_)
            | verification_command::Command::RecordVerificationCancellation(_) => {
                return Ok(error_result(
                    VerificationErrorCode::CancellationOutcomeUnknown,
                    "CANCELLATION_PROOF_NOT_IMPLEMENTED_G4_06",
                ));
            }
        };
        let Prepared::Commit(prepared) = prepared else {
            return Ok(prepared.into_error());
        };
        self.commit(*prepared, command, principal, operation, metadata, &digest)
    }

    pub fn inspect_store(
        &self,
    ) -> Result<VerificationStoreInspection, VerificationAuthorityFailure> {
        Ok(self.store.inspect()?)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, VerificationAuthorityFailure> {
        Ok(self.store.integrity_is_ok()?)
    }

    fn prepare_attest(
        &self,
        command: &AttestCheckerProfileCommand,
        principal: &AuthenticatedVerificationPrincipal,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        let Some(candidate) = command.profile.as_ref() else {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "CHECKER_PROFILE_MISSING",
            ));
        };
        if principal.kind != VerificationPrincipalKind::VerificationAuthority
            || !profile_structure_valid(candidate)
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_PROFILE_INVALID",
            ));
        }
        if self.store.profile(&candidate.checker_profile_id)?.is_some() {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "CHECKER_PROFILE_ALREADY_EXISTS",
            ));
        }
        if let Err(rejection) = self.resolver.validate_checker_profile(candidate) {
            return Ok(Prepared::reference_rejection(rejection));
        }
        let expected_digest = canonical_checker_profile_digest(candidate);
        if candidate.profile_digest_sha256 != expected_digest {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_PROFILE_DIGEST_MISMATCH",
            ));
        }
        let mut profile = candidate.clone();
        profile.revision = 1;
        profile.status = CheckerProfileStatus::Active as i32;
        profile.attested_at = Some(self.clock.now());
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::InsertProfile {
                id: profile.checker_profile_id.clone(),
                revision: 1,
                status: profile.status,
                digest: profile.profile_digest_sha256.clone(),
                snapshot: profile.encode_to_vec(),
            },
            kind: VerificationEventKind::CheckerProfileAttested,
            aggregate_id: profile.checker_profile_id.clone(),
            aggregate_revision: 1,
            object: ResultObject::Profile(Box::new(profile)),
            destinations: vec![LOCAL_READ_MODEL],
            evidence_artifact_ids: candidate.attestation_evidence_artifact_ids.clone(),
        })))
    }

    fn prepare_create_request(
        &self,
        command: &CreateVerificationRequestCommand,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        let Some(candidate) = command.request.as_ref() else {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "VERIFICATION_REQUEST_MISSING",
            ));
        };
        if !request_structure_valid(candidate)
            || self
                .store
                .request(&candidate.verification_request_id)?
                .is_some()
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "VERIFICATION_REQUEST_INVALID_OR_EXISTS",
            ));
        }
        let resolved = match self.resolver.resolve_request(candidate) {
            Ok(value) => value,
            Err(rejection) => return Ok(Prepared::reference_rejection(rejection)),
        };
        if resolved.artifact_set_status != ArtifactSetStatus::Sealed {
            return Ok(Prepared::reject(
                VerificationErrorCode::ArtifactSetNotSealed,
                "ARTIFACT_SET_NOT_SEALED",
            ));
        }
        if candidate.binding.as_ref() != Some(&resolved.binding) {
            return Ok(Prepared::reject(
                VerificationErrorCode::BindingStale,
                "RESOLVED_BINDING_MISMATCH",
            ));
        }
        let policies = match validate_request_policy(candidate, &resolved.criteria, &self.store)? {
            Ok(value) => value,
            Err(error) => return Ok(error),
        };
        let mut request = candidate.clone();
        request.revision = 1;
        request.status = VerificationStatus::Queued as i32;
        request.created_at = Some(self.clock.now());
        request.hold_reason_code = None;
        let policy_snapshot = serde_json::to_vec(&policies)
            .map_err(|_| VerificationAuthorityFailure::PolicyDecode)?;
        let binding_digest = hex::encode(Sha256::digest(
            request
                .binding
                .as_ref()
                .expect("validated binding")
                .encode_to_vec(),
        ));
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::InsertRequest {
                id: request.verification_request_id.clone(),
                revision: 1,
                status: request.status,
                binding_digest,
                policy_snapshot,
                snapshot: request.encode_to_vec(),
            },
            kind: VerificationEventKind::RequestCreated,
            aggregate_id: request.verification_request_id.clone(),
            aggregate_revision: 1,
            object: ResultObject::Request(Box::new(request)),
            destinations: vec![LOCAL_READ_MODEL],
            evidence_artifact_ids: resolved.evidence_ids.into_iter().collect(),
        })))
    }

    fn prepare_start(
        &self,
        command: &StartVerificationRunCommand,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        if command.verification_run_id.trim().is_empty() {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "VERIFICATION_RUN_ID_MISSING",
            ));
        }
        let Some(bytes) = self.store.request(&command.verification_request_id)? else {
            return Ok(Prepared::reject(
                VerificationErrorCode::NotFound,
                "VERIFICATION_REQUEST_NOT_FOUND",
            ));
        };
        let mut request = VerificationRequest::decode(bytes.as_slice())?;
        if request.revision != command.expected_request_revision
            || request.status != VerificationStatus::Queued as i32
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "VERIFICATION_REQUEST_STALE_OR_NOT_QUEUED",
            ));
        }
        if self.store.run(&command.verification_run_id)?.is_some() {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "VERIFICATION_RUN_ALREADY_EXISTS",
            ));
        }
        if let Err(rejection) = self
            .resolver
            .revalidate_binding(request.binding.as_ref().expect("validated request"))
        {
            return Ok(Prepared::reference_rejection(rejection));
        }
        request.revision += 1;
        request.status = VerificationStatus::Running as i32;
        let run = VerificationRun {
            verification_run_id: command.verification_run_id.clone(),
            verification_request_id: request.verification_request_id.clone(),
            revision: 1,
            status: VerificationStatus::Running as i32,
            criterion_results: Vec::new(),
            started_at: Some(self.clock.now()),
            ended_at: None,
            hold_reason_code: None,
        };
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::StartRun {
                request_id: request.verification_request_id.clone(),
                expected_request_revision: command.expected_request_revision,
                request_revision: request.revision,
                request_status: request.status,
                request_snapshot: request.encode_to_vec(),
                run_id: run.verification_run_id.clone(),
                run_revision: 1,
                run_status: run.status,
                run_snapshot: run.encode_to_vec(),
            },
            kind: VerificationEventKind::RunStarted,
            aggregate_id: run.verification_run_id.clone(),
            aggregate_revision: 1,
            object: ResultObject::Run(Box::new(run)),
            destinations: vec![LOCAL_READ_MODEL],
            evidence_artifact_ids: Vec::new(),
        })))
    }

    fn prepare_record(
        &self,
        command: &RecordCriterionResultCommand,
        principal: &AuthenticatedVerificationPrincipal,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        let Some(candidate) = command.result.as_ref() else {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "CRITERION_RESULT_MISSING",
            ));
        };
        let Some(bytes) = self.store.run(&command.verification_run_id)? else {
            return Ok(Prepared::reject(
                VerificationErrorCode::NotFound,
                "VERIFICATION_RUN_NOT_FOUND",
            ));
        };
        let mut run = VerificationRun::decode(bytes.as_slice())?;
        if run.revision != command.expected_run_revision
            || run.status != VerificationStatus::Running as i32
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "VERIFICATION_RUN_STALE_OR_NOT_RUNNING",
            ));
        }
        if run
            .criterion_results
            .iter()
            .any(|value| value.criterion_id == candidate.criterion_id)
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "CRITERION_RESULT_ALREADY_RECORDED",
            ));
        }
        let policies = self.policy(&run.verification_request_id)?;
        let Some(policy) = policies
            .iter()
            .find(|value| value.criterion_id == candidate.criterion_id)
        else {
            return Ok(Prepared::reject(
                VerificationErrorCode::AcceptanceContractMismatch,
                "CRITERION_NOT_IN_FROZEN_ACCEPTANCE_CONTRACT",
            ));
        };
        let Some(profile_ref) = candidate.checker_profile_ref.as_ref() else {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CRITERION_CHECKER_PROFILE_MISSING",
            ));
        };
        if principal.checker_profile_id.as_deref() != Some(profile_ref.contract_id.as_str())
            || !policy
                .checker_profile_ids
                .contains(&profile_ref.contract_id)
            || candidate.requirement != policy.requirement
            || !assurance_satisfies(candidate.assurance_class, policy.minimum_assurance)
            || !criterion_result_structure_valid(candidate, policy.not_applicable_allowed)
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_CANNOT_REWRITE_CRITERION_POLICY",
            ));
        }
        let Some(profile_bytes) = self.store.profile(&profile_ref.contract_id)? else {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_PROFILE_NOT_ATTESTED",
            ));
        };
        let profile = CheckerProfile::decode(profile_bytes.as_slice())?;
        if profile.status != CheckerProfileStatus::Active as i32
            || !profile_ref_matches(profile_ref, &profile)
            || candidate.assurance_class != profile.assurance_class
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_PROFILE_BINDING_MISMATCH",
            ));
        }
        let artifact_ids = candidate
            .safe_detail_artifact_id
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if let Err(rejection) = self
            .resolver
            .validate_result_references(&candidate.evidence_ids, &artifact_ids)
        {
            return Ok(Prepared::reference_rejection(rejection));
        }
        let result = candidate.clone();
        run.revision += 1;
        run.criterion_results.push(result.clone());
        run.criterion_results
            .sort_by(|left, right| left.criterion_id.cmp(&right.criterion_id));
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::RecordCriterion {
                run_id: run.verification_run_id.clone(),
                expected_run_revision: command.expected_run_revision,
                run_revision: run.revision,
                run_status: run.status,
                run_snapshot: run.encode_to_vec(),
                criterion_result_id: result.criterion_result_id.clone(),
                criterion_id: result.criterion_id.clone(),
                criterion_snapshot: result.encode_to_vec(),
            },
            kind: VerificationEventKind::CriterionRecorded,
            aggregate_id: run.verification_run_id.clone(),
            aggregate_revision: run.revision,
            object: ResultObject::Run(Box::new(run)),
            destinations: vec![LOCAL_READ_MODEL],
            evidence_artifact_ids: result.evidence_ids,
        })))
    }

    fn prepare_complete(
        &self,
        command: &CompleteVerificationCommand,
        principal: &AuthenticatedVerificationPrincipal,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        let Some(candidate) = command.artifact.as_ref() else {
            return Ok(Prepared::reject(
                VerificationErrorCode::InvalidArgument,
                "VERIFICATION_ARTIFACT_MISSING",
            ));
        };
        let Some(bytes) = self.store.run(&command.verification_run_id)? else {
            return Ok(Prepared::reject(
                VerificationErrorCode::NotFound,
                "VERIFICATION_RUN_NOT_FOUND",
            ));
        };
        let mut run = VerificationRun::decode(bytes.as_slice())?;
        if run.revision != command.expected_run_revision
            || run.status != VerificationStatus::Running as i32
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "VERIFICATION_RUN_STALE_OR_NOT_RUNNING",
            ));
        }
        let request_bytes = self
            .store
            .request(&run.verification_request_id)?
            .ok_or(VerificationAuthorityFailure::Storage)?;
        let mut request = VerificationRequest::decode(request_bytes.as_slice())?;
        if let Err(rejection) = self
            .resolver
            .revalidate_binding(request.binding.as_ref().expect("validated request"))
        {
            return Ok(Prepared::reference_rejection(rejection));
        }
        let policies = self.policy(&run.verification_request_id)?;
        let stored_results = self
            .store
            .criterion_results(&run.verification_run_id)?
            .into_iter()
            .map(|bytes| CriterionResult::decode(bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()?;
        let computed =
            match compute_conclusion(&policies, &stored_results, &candidate.discrepancies) {
                Ok(value) => value,
                Err(result) => return Ok(result),
            };
        if !artifact_candidate_matches(
            candidate,
            &request,
            &run,
            &stored_results,
            principal,
            computed,
        ) {
            return Ok(Prepared::reject(
                VerificationErrorCode::SchemaInvalid,
                "VERIFICATION_ARTIFACT_NOT_CANONICAL",
            ));
        }
        let referenced_evidence = candidate
            .criterion_results
            .iter()
            .flat_map(|value| value.evidence_ids.iter().cloned())
            .chain(
                candidate
                    .discrepancies
                    .iter()
                    .flat_map(|value| value.evidence_ids.iter().cloned()),
            )
            .chain(
                candidate
                    .unverified_items
                    .iter()
                    .flat_map(|value| value.evidence_ids.iter().cloned()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let referenced_artifacts = artifact_reference_ids(candidate);
        if let Err(rejection) = self
            .resolver
            .validate_result_references(&referenced_evidence, &referenced_artifacts)
        {
            return Ok(Prepared::reference_rejection(rejection));
        }
        let mut artifact = candidate.clone();
        artifact.version = 1;
        artifact.completed_at = Some(self.clock.now());
        artifact.canonical_payload = Some(canonical_verification_payload(&artifact));
        run.revision += 1;
        run.status = VerificationStatus::Completed as i32;
        run.ended_at = artifact.completed_at;
        let expected_request_revision = request.revision;
        request.revision += 1;
        request.status = VerificationStatus::Completed as i32;
        let payload_digest = artifact
            .canonical_payload
            .as_ref()
            .expect("just assigned")
            .digest
            .clone();
        let evidence = referenced_evidence;
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::Complete {
                request_id: request.verification_request_id.clone(),
                expected_request_revision,
                request_revision: request.revision,
                request_status: request.status,
                request_snapshot: request.encode_to_vec(),
                run_id: run.verification_run_id.clone(),
                expected_run_revision: command.expected_run_revision,
                run_revision: run.revision,
                run_status: run.status,
                run_snapshot: run.encode_to_vec(),
                artifact_id: artifact.verification_artifact_id.clone(),
                artifact_version: artifact.version,
                conclusion: artifact.conclusion,
                payload_digest,
                artifact_snapshot: artifact.encode_to_vec(),
            },
            kind: VerificationEventKind::ArtifactCommitted,
            aggregate_id: artifact.verification_artifact_id.clone(),
            aggregate_revision: artifact.version,
            object: ResultObject::Artifact(Box::new(artifact)),
            destinations: vec![TASK_AUTHORITY, FOUNDER_VERDICT, LOCAL_READ_MODEL],
            evidence_artifact_ids: evidence,
        })))
    }

    fn prepare_hold(
        &self,
        command: &HoldVerificationCommand,
    ) -> Result<Prepared, VerificationAuthorityFailure> {
        let Some(bytes) = self.store.run(&command.verification_run_id)? else {
            return Ok(Prepared::reject(
                VerificationErrorCode::NotFound,
                "VERIFICATION_RUN_NOT_FOUND",
            ));
        };
        let mut run = VerificationRun::decode(bytes.as_slice())?;
        if run.revision != command.expected_run_revision
            || run.status != VerificationStatus::Running as i32
            || command.reason_code.trim().is_empty()
        {
            return Ok(Prepared::reject(
                VerificationErrorCode::RevisionConflict,
                "VERIFICATION_RUN_STALE_OR_NOT_HOLDABLE",
            ));
        }
        if let Err(rejection) = self
            .resolver
            .validate_result_references(&command.evidence_artifact_ids, &[])
        {
            return Ok(Prepared::reference_rejection(rejection));
        }
        run.revision += 1;
        run.status = VerificationStatus::Held as i32;
        run.hold_reason_code = Some(command.reason_code.clone());
        run.ended_at = Some(self.clock.now());
        let request_bytes = self
            .store
            .request(&run.verification_request_id)?
            .ok_or(VerificationAuthorityFailure::Storage)?;
        let mut request = VerificationRequest::decode(request_bytes.as_slice())?;
        let expected_request_revision = request.revision;
        request.revision += 1;
        request.status = VerificationStatus::Held as i32;
        request.hold_reason_code = Some(command.reason_code.clone());
        Ok(Prepared::Commit(Box::new(PreparedCommit {
            mutation: Mutation::Hold {
                request_id: request.verification_request_id.clone(),
                expected_request_revision,
                request_revision: request.revision,
                request_status: request.status,
                request_snapshot: request.encode_to_vec(),
                run_id: run.verification_run_id.clone(),
                expected_run_revision: command.expected_run_revision,
                run_revision: run.revision,
                run_status: run.status,
                run_snapshot: run.encode_to_vec(),
            },
            kind: VerificationEventKind::Held,
            aggregate_id: run.verification_run_id.clone(),
            aggregate_revision: run.revision,
            object: ResultObject::Run(Box::new(run)),
            destinations: vec![TASK_AUTHORITY, LOCAL_READ_MODEL],
            evidence_artifact_ids: command.evidence_artifact_ids.clone(),
        })))
    }

    fn policy(
        &self,
        request_id: &str,
    ) -> Result<Vec<CriterionPolicySnapshot>, VerificationAuthorityFailure> {
        let bytes = self
            .store
            .request_policy(request_id)?
            .ok_or(VerificationAuthorityFailure::Storage)?;
        serde_json::from_slice(&bytes).map_err(|_| VerificationAuthorityFailure::PolicyDecode)
    }

    fn commit(
        &mut self,
        prepared: PreparedCommit,
        _command: &VerificationCommand,
        principal: &AuthenticatedVerificationPrincipal,
        operation: &str,
        metadata: &CommandMetadata,
        digest: &str,
    ) -> Result<VerificationCommandResult, VerificationAuthorityFailure> {
        let now = self.clock.now();
        let event = VerificationEvent {
            event_id: format!("verification-event-{}", Uuid::now_v7()),
            kind: prepared.kind as i32,
            aggregate_id: prepared.aggregate_id.clone(),
            aggregate_revision: prepared.aggregate_revision,
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: metadata.command_id.clone(),
            evidence_artifact_ids: prepared.evidence_artifact_ids,
            committed_at: Some(now),
        };
        let result = prepared.object.into_result(event.clone());
        let payload = result.encode_to_vec();
        let outbox = prepared
            .destinations
            .into_iter()
            .map(|destination| OutboxWrite {
                message_id: format!("verification-outbox-{}", Uuid::now_v7()),
                destination_domain: destination.to_owned(),
                payload_digest_sha256: hex::encode(Sha256::digest(&payload)),
                payload: payload.clone(),
            })
            .collect();
        let event_bytes = event.encode_to_vec();
        self.store.commit(AuthorityCommit {
            mutation: prepared.mutation,
            event_id: event.event_id,
            command_id: metadata.command_id.clone(),
            aggregate_id: prepared.aggregate_id,
            aggregate_revision: prepared.aggregate_revision,
            request_digest_sha256: digest.to_owned(),
            event: event_bytes,
            authenticated_principal_id: principal.principal_id.clone(),
            operation: operation.to_owned(),
            idempotency_scope: metadata.idempotency_scope.clone(),
            idempotency_key: metadata.idempotency_key.clone(),
            result: payload,
            outbox,
            committed_at_seconds: now.seconds,
        })?;
        Ok(result)
    }
}

enum Prepared {
    Commit(Box<PreparedCommit>),
    Reject(Box<VerificationCommandResult>),
}

impl Prepared {
    fn reject(code: VerificationErrorCode, fingerprint: &str) -> Self {
        Self::Reject(Box::new(error_result(code, fingerprint)))
    }

    fn reference_rejection(value: ReferenceRejection) -> Self {
        let (code, fingerprint) = match value {
            ReferenceRejection::NotFound => {
                (VerificationErrorCode::NotFound, "REFERENCE_NOT_FOUND")
            }
            ReferenceRejection::BindingStale => (
                VerificationErrorCode::BindingStale,
                "REFERENCE_BINDING_STALE",
            ),
            ReferenceRejection::ArtifactSetNotSealed => (
                VerificationErrorCode::ArtifactSetNotSealed,
                "ARTIFACT_SET_NOT_SEALED",
            ),
            ReferenceRejection::ManifestMismatch => (
                VerificationErrorCode::ManifestMismatch,
                "ARTIFACT_SET_MANIFEST_MISMATCH",
            ),
            ReferenceRejection::ClaimMismatch => (
                VerificationErrorCode::ClaimMismatch,
                "CLAIM_BINDING_MISMATCH",
            ),
            ReferenceRejection::AcceptanceContractMismatch => (
                VerificationErrorCode::AcceptanceContractMismatch,
                "ACCEPTANCE_CONTRACT_MISMATCH",
            ),
            ReferenceRejection::CheckerProfileMismatch => (
                VerificationErrorCode::CheckerProfileMismatch,
                "CHECKER_PROFILE_MISMATCH",
            ),
            ReferenceRejection::EvidenceIncomplete => (
                VerificationErrorCode::EvidenceIncomplete,
                "EVIDENCE_INCOMPLETE",
            ),
            ReferenceRejection::IntegrityFailure => (
                VerificationErrorCode::IntegrityFailure,
                "REFERENCE_INTEGRITY_FAILURE",
            ),
            ReferenceRejection::OutputUntrusted => (
                VerificationErrorCode::OutputUntrusted,
                "CHECKER_OUTPUT_UNTRUSTED",
            ),
        };
        Self::reject(code, fingerprint)
    }

    fn into_error(self) -> VerificationCommandResult {
        match self {
            Self::Reject(result) => *result,
            Self::Commit(_) => unreachable!(),
        }
    }
}

struct PreparedCommit {
    mutation: Mutation,
    kind: VerificationEventKind,
    aggregate_id: String,
    aggregate_revision: u64,
    object: ResultObject,
    destinations: Vec<&'static str>,
    evidence_artifact_ids: Vec<String>,
}

enum ResultObject {
    Profile(Box<CheckerProfile>),
    Request(Box<VerificationRequest>),
    Run(Box<VerificationRun>),
    Artifact(Box<VerificationArtifact>),
}

impl ResultObject {
    fn into_result(self, event: VerificationEvent) -> VerificationCommandResult {
        let mut result = VerificationCommandResult {
            committed: true,
            replayed: false,
            checker_profile: None,
            request: None,
            run: None,
            artifact: None,
            event: Some(event),
            error_code: VerificationErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        match self {
            Self::Profile(value) => result.checker_profile = Some(*value),
            Self::Request(value) => result.request = Some(*value),
            Self::Run(value) => result.run = Some(*value),
            Self::Artifact(value) => result.artifact = Some(*value),
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ComputedConclusion {
    conclusion: VerificationConclusion,
    coverage: EvidenceCoverage,
}

fn validate_request_policy(
    request: &VerificationRequest,
    criteria: &[CriterionPolicySnapshot],
    store: &VerificationStore,
) -> Result<Result<Vec<CriterionPolicySnapshot>, Prepared>, VerificationAuthorityFailure> {
    let mut policies = criteria.to_vec();
    policies.sort_by(|left, right| left.criterion_id.cmp(&right.criterion_id));
    if policies.is_empty()
        || policies
            .windows(2)
            .any(|window| window[0].criterion_id == window[1].criterion_id)
    {
        return Ok(Err(Prepared::reject(
            VerificationErrorCode::AcceptanceContractMismatch,
            "ACCEPTANCE_CRITERIA_INVALID",
        )));
    }
    let requested = request
        .criterion_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let resolved = policies
        .iter()
        .map(|value| value.criterion_id.clone())
        .collect::<BTreeSet<_>>();
    if requested != resolved {
        return Ok(Err(Prepared::reject(
            VerificationErrorCode::AcceptanceContractMismatch,
            "CRITERION_SET_MISMATCH",
        )));
    }
    for policy in &policies {
        if CriterionRequirement::try_from(policy.requirement).is_err()
            || CheckerAssuranceClass::try_from(policy.minimum_assurance).is_err()
            || policy.checker_profile_ids.is_empty()
        {
            return Ok(Err(Prepared::reject(
                VerificationErrorCode::AcceptanceContractMismatch,
                "CRITERION_POLICY_INVALID",
            )));
        }
        for profile_id in &policy.checker_profile_ids {
            let Some(bytes) = store.profile(profile_id)? else {
                return Ok(Err(Prepared::reject(
                    VerificationErrorCode::CheckerProfileMismatch,
                    "REQUIRED_CHECKER_PROFILE_NOT_ATTESTED",
                )));
            };
            let profile = CheckerProfile::decode(bytes.as_slice())?;
            if profile.status != CheckerProfileStatus::Active as i32
                || !profile
                    .supported_criterion_types
                    .contains(&policy.criterion_id)
                || !assurance_satisfies(profile.assurance_class, policy.minimum_assurance)
                || !request
                    .checker_profile_refs
                    .iter()
                    .any(|reference| profile_ref_matches(reference, &profile))
            {
                return Ok(Err(Prepared::reject(
                    VerificationErrorCode::CheckerProfileMismatch,
                    "REQUIRED_CHECKER_PROFILE_BINDING_INVALID",
                )));
            }
        }
    }
    Ok(Ok(policies))
}

fn compute_conclusion(
    policies: &[CriterionPolicySnapshot],
    results: &[CriterionResult],
    discrepancies: &[Discrepancy],
) -> Result<ComputedConclusion, Prepared> {
    if results.len() != policies.len() {
        return Err(Prepared::reject(
            VerificationErrorCode::EvidenceIncomplete,
            "NOT_ALL_CRITERIA_RECORDED",
        ));
    }
    let result_by_id = results
        .iter()
        .map(|value| (value.criterion_id.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let discrepancy_by_id = discrepancies
        .iter()
        .map(|value| (value.discrepancy_id.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    if discrepancy_by_id.len() != discrepancies.len() {
        return Err(Prepared::reject(
            VerificationErrorCode::SchemaInvalid,
            "DUPLICATE_DISCREPANCY_ID",
        ));
    }
    let mut credible_must_failure = false;
    let mut must_unknown = false;
    let mut non_must_not_passed = false;
    let mut coverage = EvidenceCoverage::Complete;
    for policy in policies {
        let Some(result) = result_by_id.get(policy.criterion_id.as_str()) else {
            return Err(Prepared::reject(
                VerificationErrorCode::EvidenceIncomplete,
                "CRITERION_RESULT_MISSING",
            ));
        };
        if result.requirement != policy.requirement
            || !assurance_satisfies(result.assurance_class, policy.minimum_assurance)
            || !criterion_result_structure_valid(result, policy.not_applicable_allowed)
        {
            return Err(Prepared::reject(
                VerificationErrorCode::CheckerProfileMismatch,
                "RECORDED_CRITERION_POLICY_MISMATCH",
            ));
        }
        for discrepancy_id in &result.discrepancy_ids {
            let Some(discrepancy) = discrepancy_by_id.get(discrepancy_id.as_str()) else {
                return Err(Prepared::reject(
                    VerificationErrorCode::SchemaInvalid,
                    "DISCREPANCY_REFERENCE_MISSING",
                ));
            };
            if discrepancy.criterion_id != policy.criterion_id
                || (result.outcome == CriterionOutcome::Passed as i32
                    && discrepancy.severity == DiscrepancySeverity::Blocker as i32)
            {
                return Err(Prepared::reject(
                    VerificationErrorCode::UnknownCriticalResult,
                    "DISCREPANCY_OUTCOME_CONTRADICTION",
                ));
            }
        }
        let result_coverage =
            EvidenceCoverage::try_from(result.evidence_coverage).map_err(|_| {
                Prepared::reject(
                    VerificationErrorCode::SchemaInvalid,
                    "EVIDENCE_COVERAGE_INVALID",
                )
            })?;
        coverage = worse_coverage(coverage, result_coverage);
        let outcome = CriterionOutcome::try_from(result.outcome).map_err(|_| {
            Prepared::reject(
                VerificationErrorCode::UnknownCriticalResult,
                "CRITERION_OUTCOME_INVALID",
            )
        })?;
        let requirement = CriterionRequirement::try_from(policy.requirement).map_err(|_| {
            Prepared::reject(
                VerificationErrorCode::AcceptanceContractMismatch,
                "CRITERION_REQUIREMENT_INVALID",
            )
        })?;
        if requirement == CriterionRequirement::MustPass {
            match outcome {
                CriterionOutcome::Failed if result_coverage == EvidenceCoverage::Complete => {
                    credible_must_failure = true;
                }
                CriterionOutcome::Passed if result_coverage == EvidenceCoverage::Complete => {}
                CriterionOutcome::NotApplicable if policy.not_applicable_allowed => {}
                _ => must_unknown = true,
            }
        } else if outcome != CriterionOutcome::Passed
            || result_coverage != EvidenceCoverage::Complete
        {
            non_must_not_passed = true;
        }
    }
    let conclusion = if credible_must_failure {
        VerificationConclusion::Failed
    } else if must_unknown || coverage == EvidenceCoverage::IntegrityFailed {
        VerificationConclusion::Indeterminate
    } else if non_must_not_passed {
        VerificationConclusion::Partial
    } else {
        VerificationConclusion::Passed
    };
    Ok(ComputedConclusion {
        conclusion,
        coverage,
    })
}

fn artifact_candidate_matches(
    candidate: &VerificationArtifact,
    request: &VerificationRequest,
    run: &VerificationRun,
    results: &[CriterionResult],
    principal: &AuthenticatedVerificationPrincipal,
    computed: ComputedConclusion,
) -> bool {
    if candidate.verification_artifact_id.trim().is_empty()
        || candidate.version != 1
        || candidate.verification_request_id != request.verification_request_id
        || candidate.verification_run_id != run.verification_run_id
        || candidate.verification_type != request.verification_type
        || candidate.binding != request.binding
        || candidate.conclusion != computed.conclusion as i32
        || candidate.overall_evidence_coverage != computed.coverage as i32
        || candidate.canonical_payload.is_some()
        || candidate.completed_at.is_some()
    {
        return false;
    }
    let mut candidate_results = candidate.criterion_results.clone();
    candidate_results.sort_by(|left, right| left.criterion_id.cmp(&right.criterion_id));
    let mut stored_results = results.to_vec();
    stored_results.sort_by(|left, right| left.criterion_id.cmp(&right.criterion_id));
    if candidate_results != stored_results {
        return false;
    }
    let Some(provenance) = candidate.provenance.as_ref() else {
        return false;
    };
    let result_profiles = candidate
        .criterion_results
        .iter()
        .filter_map(|value| value.checker_profile_ref.as_ref().map(contract_ref_key))
        .collect::<BTreeSet<_>>();
    let provenance_profiles = provenance
        .checker_profile_refs
        .iter()
        .map(contract_ref_key)
        .collect::<BTreeSet<_>>();
    provenance.verifier_principal_id == principal.principal_id
        && provenance.duration_ms > 0
        && result_profiles == provenance_profiles
        && unique_nonempty(&candidate.discrepancies, |value| &value.discrepancy_id)
        && unique_nonempty(&candidate.unverified_items, |value| {
            &value.unverified_item_id
        })
        && all_result_detail_ids_resolved(candidate)
}

fn all_result_detail_ids_resolved(candidate: &VerificationArtifact) -> bool {
    let discrepancy_ids = candidate
        .discrepancies
        .iter()
        .map(|value| value.discrepancy_id.as_str())
        .collect::<BTreeSet<_>>();
    let unverified_ids = candidate
        .unverified_items
        .iter()
        .map(|value| value.unverified_item_id.as_str())
        .collect::<BTreeSet<_>>();
    let referenced_discrepancies = candidate
        .criterion_results
        .iter()
        .flat_map(|result| result.discrepancy_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let referenced_unverified = candidate
        .criterion_results
        .iter()
        .flat_map(|result| result.unverified_item_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    referenced_discrepancies == discrepancy_ids && referenced_unverified == unverified_ids
}

fn artifact_reference_ids(candidate: &VerificationArtifact) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for result in &candidate.criterion_results {
        ids.extend(result.safe_detail_artifact_id.iter().cloned());
    }
    for discrepancy in &candidate.discrepancies {
        ids.insert(discrepancy.description_artifact_id.clone());
        ids.extend(discrepancy.suggested_fix_artifact_id.iter().cloned());
    }
    for item in &candidate.unverified_items {
        ids.extend(item.context_artifact_id.iter().cloned());
    }
    if let Some(provenance) = candidate.provenance.as_ref() {
        ids.extend(provenance.tool_receipt_artifact_ids.iter().cloned());
        ids.extend(provenance.model_call_receipt_artifact_ids.iter().cloned());
        ids.extend(provenance.raw_output_artifact_ids.iter().cloned());
        ids.extend(provenance.cost_receipt_artifact_id.iter().cloned());
    }
    ids.into_iter().collect()
}

#[must_use]
pub fn canonical_verification_payload(artifact: &VerificationArtifact) -> ContentAddress {
    let mut canonical = artifact.clone();
    canonical.canonical_payload = None;
    let bytes = canonical.encode_to_vec();
    ContentAddress {
        algorithm: HashAlgorithm::Sha256 as i32,
        digest: hex::encode(Sha256::digest(&bytes)),
        byte_length: bytes.len() as u64,
    }
}

#[must_use]
pub fn canonical_checker_profile_digest(profile: &CheckerProfile) -> String {
    let mut canonical = profile.clone();
    canonical.revision = 0;
    canonical.status = CheckerProfileStatus::Unspecified as i32;
    canonical.profile_digest_sha256.clear();
    canonical.attested_at = None;
    hex::encode(Sha256::digest(canonical.encode_to_vec()))
}

#[must_use]
pub fn canonical_request_digest(command: &VerificationCommand) -> Option<String> {
    command.command.as_ref()?;
    let mut canonical = command.clone();
    let metadata = command_metadata_mut(&mut canonical)?;
    metadata.command_id.clear();
    metadata.request_digest_sha256.clear();
    metadata.issued_at = None;
    metadata.correlation_id.clear();
    metadata.causation_id = None;
    Some(hex::encode(Sha256::digest(canonical.encode_to_vec())))
}

fn request_structure_valid(value: &VerificationRequest) -> bool {
    !value.verification_request_id.trim().is_empty()
        && value.verification_type == "task_acceptance"
        && value.binding.as_ref().is_some_and(binding_valid)
        && !value.criterion_ids.is_empty()
        && unique_strings(&value.criterion_ids)
        && !value.checker_profile_refs.is_empty()
        && value.checker_profile_refs.iter().all(contract_ref_valid)
}

fn binding_valid(value: &VerificationBinding) -> bool {
    value.lineage.as_ref().is_some_and(lineage_valid)
        && !value.artifact_set_id.trim().is_empty()
        && value
            .artifact_set_manifest
            .as_ref()
            .is_some_and(content_address_valid)
        && !value.claim_id.trim().is_empty()
        && value
            .claim_semantic_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value
            .acceptance_contract_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
}

fn profile_structure_valid(value: &CheckerProfile) -> bool {
    !value.checker_profile_id.trim().is_empty()
        && !value.checker_id.trim().is_empty()
        && !value.checker_version.trim().is_empty()
        && value
            .input_contract_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value
            .output_contract_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && !value.supported_criterion_types.is_empty()
        && unique_strings(&value.supported_criterion_types)
        && CheckerAssuranceClass::try_from(value.assurance_class)
            .is_ok_and(|v| v != CheckerAssuranceClass::Unspecified)
        && value
            .sandbox_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value
            .tool_policy_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value
            .data_egress_policy_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value.timeout_ms > 0
        && is_sha256(&value.profile_digest_sha256)
        && !value.attestation_evidence_artifact_ids.is_empty()
}

fn criterion_result_structure_valid(value: &CriterionResult, na_allowed: bool) -> bool {
    !value.criterion_result_id.trim().is_empty()
        && !value.criterion_id.trim().is_empty()
        && CriterionRequirement::try_from(value.requirement)
            .is_ok_and(|v| v != CriterionRequirement::Unspecified)
        && CriterionOutcome::try_from(value.outcome).is_ok_and(|v| {
            v != CriterionOutcome::Unspecified
                && (v != CriterionOutcome::NotApplicable || na_allowed)
        })
        && CheckerAssuranceClass::try_from(value.assurance_class)
            .is_ok_and(|v| v != CheckerAssuranceClass::Unspecified)
        && value
            .checker_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && EvidenceCoverage::try_from(value.evidence_coverage)
            .is_ok_and(|v| v != EvidenceCoverage::Unspecified)
        && unique_strings(&value.evidence_ids)
        && unique_strings(&value.discrepancy_ids)
        && unique_strings(&value.unverified_item_ids)
}

fn assurance_satisfies(actual: i32, required: i32) -> bool {
    let Ok(actual) = CheckerAssuranceClass::try_from(actual) else {
        return false;
    };
    let Ok(required) = CheckerAssuranceClass::try_from(required) else {
        return false;
    };
    match required {
        CheckerAssuranceClass::Deterministic => actual == CheckerAssuranceClass::Deterministic,
        CheckerAssuranceClass::ModelAssisted => matches!(
            actual,
            CheckerAssuranceClass::Deterministic | CheckerAssuranceClass::ModelAssisted
        ),
        CheckerAssuranceClass::HumanRequired => actual == CheckerAssuranceClass::HumanRequired,
        CheckerAssuranceClass::Unspecified => false,
    }
}

fn profile_ref_matches(reference: &ContractReference, profile: &CheckerProfile) -> bool {
    reference.contract_id == profile.checker_profile_id
        && reference.version == profile.checker_version
        && reference.sha256 == profile.profile_digest_sha256
}

fn contract_ref_key(reference: &ContractReference) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        reference.contract_id, reference.version, reference.sha256
    )
}

fn worse_coverage(left: EvidenceCoverage, right: EvidenceCoverage) -> EvidenceCoverage {
    fn rank(value: EvidenceCoverage) -> u8 {
        match value {
            EvidenceCoverage::Complete => 0,
            EvidenceCoverage::Partial => 1,
            EvidenceCoverage::Missing => 2,
            EvidenceCoverage::IntegrityFailed => 3,
            EvidenceCoverage::Unspecified => 4,
        }
    }
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

fn unique_nonempty<T>(values: &[T], id: impl Fn(&T) -> &String) -> bool {
    let ids = values.iter().map(id).collect::<BTreeSet<_>>();
    ids.len() == values.len() && ids.iter().all(|value| !value.trim().is_empty())
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
        && values.iter().all(|value| !value.trim().is_empty())
}

fn lineage_valid(value: &LineageBinding) -> bool {
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

fn contract_ref_valid(value: &ContractReference) -> bool {
    !value.contract_id.trim().is_empty()
        && !value.version.trim().is_empty()
        && is_sha256(&value.sha256)
}

fn content_address_valid(value: &ContentAddress) -> bool {
    value.algorithm == HashAlgorithm::Sha256 as i32
        && is_sha256(&value.digest)
        && value.byte_length > 0
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn metadata_complete(value: &CommandMetadata) -> bool {
    !value.command_id.trim().is_empty()
        && !value.idempotency_key.trim().is_empty()
        && !value.idempotency_scope.trim().is_empty()
        && is_sha256(&value.request_digest_sha256)
        && value.issued_at.is_some()
        && !value.correlation_id.trim().is_empty()
}

fn operation_name(command: &VerificationCommand) -> Option<&'static str> {
    match command.command.as_ref()? {
        verification_command::Command::AttestCheckerProfile(_) => Some("attest_checker_profile"),
        verification_command::Command::CreateVerificationRequest(_) => {
            Some("create_verification_request")
        }
        verification_command::Command::StartVerificationRun(_) => Some("start_verification_run"),
        verification_command::Command::RecordCriterionResult(_) => Some("record_criterion_result"),
        verification_command::Command::CompleteVerification(_) => Some("complete_verification"),
        verification_command::Command::RequestVerificationCancellation(_) => {
            Some("request_verification_cancellation")
        }
        verification_command::Command::RecordVerificationCancellation(_) => {
            Some("record_verification_cancellation")
        }
        verification_command::Command::HoldVerification(_) => Some("hold_verification"),
    }
}

fn operation_allowed(operation: &str, kind: VerificationPrincipalKind) -> bool {
    match operation {
        "attest_checker_profile" | "start_verification_run" | "complete_verification" => {
            kind == VerificationPrincipalKind::VerificationAuthority
        }
        "create_verification_request" => kind == VerificationPrincipalKind::TaskAuthority,
        "record_criterion_result" => matches!(
            kind,
            VerificationPrincipalKind::SegoChecker
                | VerificationPrincipalKind::DeterministicChecker
        ),
        "hold_verification" => matches!(
            kind,
            VerificationPrincipalKind::VerificationAuthority
                | VerificationPrincipalKind::RecoveryCoordinator
        ),
        "request_verification_cancellation" | "record_verification_cancellation" => matches!(
            kind,
            VerificationPrincipalKind::VerificationAuthority
                | VerificationPrincipalKind::RecoveryCoordinator
        ),
        _ => false,
    }
}

fn command_metadata(command: &VerificationCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_ref(),
        verification_command::Command::CreateVerificationRequest(value) => value.metadata.as_ref(),
        verification_command::Command::StartVerificationRun(value) => value.metadata.as_ref(),
        verification_command::Command::RecordCriterionResult(value) => value.metadata.as_ref(),
        verification_command::Command::CompleteVerification(value) => value.metadata.as_ref(),
        verification_command::Command::RequestVerificationCancellation(value) => {
            value.metadata.as_ref()
        }
        verification_command::Command::RecordVerificationCancellation(value) => {
            value.metadata.as_ref()
        }
        verification_command::Command::HoldVerification(value) => value.metadata.as_ref(),
    }
}

fn command_metadata_mut(command: &mut VerificationCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        verification_command::Command::AttestCheckerProfile(value) => value.metadata.as_mut(),
        verification_command::Command::CreateVerificationRequest(value) => value.metadata.as_mut(),
        verification_command::Command::StartVerificationRun(value) => value.metadata.as_mut(),
        verification_command::Command::RecordCriterionResult(value) => value.metadata.as_mut(),
        verification_command::Command::CompleteVerification(value) => value.metadata.as_mut(),
        verification_command::Command::RequestVerificationCancellation(value) => {
            value.metadata.as_mut()
        }
        verification_command::Command::RecordVerificationCancellation(value) => {
            value.metadata.as_mut()
        }
        verification_command::Command::HoldVerification(value) => value.metadata.as_mut(),
    }
}

fn error_result(code: VerificationErrorCode, fingerprint: &str) -> VerificationCommandResult {
    VerificationCommandResult {
        committed: false,
        replayed: false,
        checker_profile: None,
        request: None,
        run: None,
        artifact: None,
        event: None,
        error_code: code as i32,
        safe_error_fingerprint: Some(fingerprint.to_owned()),
    }
}
