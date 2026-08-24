#![forbid(unsafe_code)]

mod blob;
mod store;

pub use blob::BlobStoreError;
pub use store::ArtifactStoreInspection;

use blob::ContentAddressedBlobStore;

use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactCommand, ArtifactCommandResult, ArtifactDescriptor, ArtifactErrorCode, ArtifactEvent,
    ArtifactEventKind, ArtifactSemanticClass, ArtifactSet, ArtifactSetStatus, ArtifactStatus,
    Claim, ClaimSourceType, ClaimStatus, ContentAddress, Evidence, EvidenceProducerClass,
    EvidenceRelation, EvidenceStatus, IntegrityStatus, LineageBinding, ProducerIdentity,
    ReturnHandoff, ReturnHandoffStatus, ReturnReceipt, artifact_command,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::{CommandMetadata, ContractReference};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{ArtifactStore, AuthorityCommit, Mutation, OutboxWrite, StoreError};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const LOCAL_READ_MODEL: &str = "local-read-model";
const COLLABORATION_CONTROL: &str = "collaboration-control";

#[must_use]
pub fn content_address(bytes: &[u8]) -> ContentAddress {
    ContentAddressedBlobStore::address(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactPrincipalKind {
    Harness,
    AttemptSupervisor,
    GovernedCollector,
    DeterministicChecker,
    SupervisedRunner,
    ExternalVerifier,
    ArtifactAuthority,
    RetentionAuthority,
}

impl ArtifactPrincipalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Harness => "harness",
            Self::AttemptSupervisor => "attempt_supervisor",
            Self::GovernedCollector => "governed_collector",
            Self::DeterministicChecker => "deterministic_checker",
            Self::SupervisedRunner => "supervised_runner",
            Self::ExternalVerifier => "external_verifier",
            Self::ArtifactAuthority => "artifact_authority",
            Self::RetentionAuthority => "retention_authority",
        }
    }

    const fn evidence_class(self) -> Option<EvidenceProducerClass> {
        match self {
            Self::Harness => Some(EvidenceProducerClass::Harness),
            Self::AttemptSupervisor => Some(EvidenceProducerClass::AttemptSupervisor),
            Self::GovernedCollector => Some(EvidenceProducerClass::GovernedCollector),
            Self::DeterministicChecker => Some(EvidenceProducerClass::DeterministicChecker),
            Self::SupervisedRunner => Some(EvidenceProducerClass::SupervisedRunner),
            Self::ExternalVerifier => Some(EvidenceProducerClass::ExternalVerifier),
            Self::ArtifactAuthority | Self::RetentionAuthority => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedArtifactPrincipal {
    pub kind: ArtifactPrincipalKind,
    pub principal_id: String,
    pub authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    InvalidArgument,
    ContractMismatch,
    LineageMismatch,
    ScopeViolation,
    SecretDetected,
    IndependenceViolation,
    Quarantined,
}

pub trait ArtifactAdmissionGuard {
    fn validate_artifact(
        &self,
        artifact: &ArtifactDescriptor,
        bytes: &[u8],
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection>;

    fn validate_claim(
        &self,
        claim: &Claim,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection>;

    fn validate_evidence(
        &self,
        evidence: &Evidence,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection>;

    fn validate_artifact_set(
        &self,
        artifact_set: &ArtifactSet,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection>;

    fn validate_return_handoff(
        &self,
        handoff: &ReturnHandoff,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<(), AdmissionRejection>;
}

pub trait ArtifactClock {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemArtifactClock;

impl ArtifactClock for SystemArtifactClock {
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

pub struct ArtifactSqlCipherKey(Zeroizing<[u8; 32]>);

impl ArtifactSqlCipherKey {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct ArtifactAuthorityConfig {
    pub database_path: PathBuf,
    pub blob_root: PathBuf,
    pub store_epoch: String,
    pub key: ArtifactSqlCipherKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ArtifactProjectionMessage {
    pub message_id: String,
    pub source_event_id: String,
    pub source_revision: u64,
    pub payload_digest_sha256: String,
    pub result: ArtifactCommandResult,
}

#[derive(Debug, Error)]
pub enum ArtifactAuthorityFailure {
    #[error("artifact authority storage failed")]
    Storage,
    #[error("artifact content data plane failed")]
    Blob(#[from] BlobStoreError),
    #[error("artifact authority persisted an undecodable contract value")]
    Decode(#[from] prost::DecodeError),
}

impl From<StoreError> for ArtifactAuthorityFailure {
    fn from(_value: StoreError) -> Self {
        Self::Storage
    }
}

pub struct ArtifactAuthority<G, C = SystemArtifactClock> {
    store: ArtifactStore,
    blobs: ContentAddressedBlobStore,
    guard: G,
    clock: C,
}

impl<G> ArtifactAuthority<G, SystemArtifactClock>
where
    G: ArtifactAdmissionGuard,
{
    pub fn open(
        config: ArtifactAuthorityConfig,
        guard: G,
    ) -> Result<Self, ArtifactAuthorityFailure> {
        Self::open_with_clock(config, guard, SystemArtifactClock)
    }
}

impl<G, C> ArtifactAuthority<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    pub fn open_with_clock(
        config: ArtifactAuthorityConfig,
        guard: G,
        clock: C,
    ) -> Result<Self, ArtifactAuthorityFailure> {
        let store = ArtifactStore::open(
            &config.database_path,
            config.key.expose(),
            &config.store_epoch,
        )?;
        let blobs = ContentAddressedBlobStore::open(config.blob_root)?;
        Ok(Self {
            store,
            blobs,
            guard,
            clock,
        })
    }

    pub fn put_blob(&self, bytes: &[u8], expected: &ContentAddress) -> Result<(), BlobStoreError> {
        self.blobs.put_verified(bytes, expected).map(|_| ())
    }

    pub fn execute(
        &mut self,
        command: &ArtifactCommand,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(operation) = operation_name(command) else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_COMMAND_MISSING",
            ));
        };
        let Some(meta) = command_metadata(command) else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "COMMAND_METADATA_MISSING",
            ));
        };
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Ok(error_result(
                ArtifactErrorCode::Unauthenticated,
                "AUTHENTICATED_PRINCIPAL_REQUIRED",
            ));
        }
        if !metadata_is_complete(meta) {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "COMMAND_METADATA_INVALID",
            ));
        }
        if !operation_allowed(operation, principal.kind) {
            return Ok(error_result(
                ArtifactErrorCode::PermissionDenied,
                "ARTIFACT_OPERATION_NOT_AUTHORIZED",
            ));
        }
        let Some(canonical_digest) = canonical_request_digest(command) else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_COMMAND_MISSING",
            ));
        };
        if canonical_digest != meta.request_digest_sha256 {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "REQUEST_DIGEST_INVALID",
            ));
        }
        if let Some(record) = self.store.idempotency_record(
            &principal.principal_id,
            operation,
            &meta.idempotency_scope,
            &meta.idempotency_key,
        )? {
            if record.request_digest_sha256 != canonical_digest {
                return Ok(error_result(
                    ArtifactErrorCode::IdempotencyConflict,
                    "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST",
                ));
            }
            let mut result = ArtifactCommandResult::decode(record.result.as_slice())?;
            result.replayed = true;
            return Ok(result);
        }

        match command
            .command
            .as_ref()
            .expect("operation resolved command")
        {
            artifact_command::Command::StageArtifact(value) => {
                self.stage_artifact(value.candidate.as_ref(), meta, principal)
            }
            artifact_command::Command::SealArtifact(value) => self.seal_artifact(
                &value.artifact_id,
                value.expected_revision,
                value.observed_content.as_ref(),
                meta,
                principal,
            ),
            artifact_command::Command::ProposeClaim(value) => {
                self.propose_claim(value.claim.as_ref(), meta, principal)
            }
            artifact_command::Command::RecordEvidence(value) => {
                self.record_evidence(value.evidence.as_ref(), meta, principal)
            }
            artifact_command::Command::CreateArtifactSet(value) => {
                self.create_artifact_set(value.artifact_set.as_ref(), meta, principal)
            }
            artifact_command::Command::SealArtifactSet(value) => self.seal_artifact_set(
                &value.artifact_set_id,
                value.expected_revision,
                value.observed_manifest.as_ref(),
                meta,
                principal,
            ),
            artifact_command::Command::SubmitReturnHandoff(value) => self.submit_return_handoff(
                value.return_handoff.as_ref(),
                value.expected_artifact_set_revision,
                meta,
                principal,
            ),
            artifact_command::Command::QuarantineObject(_)
            | artifact_command::Command::WithdrawClaim(_)
            | artifact_command::Command::TombstoneObject(_) => Ok(error_result(
                ArtifactErrorCode::PermissionDenied,
                "DEPENDENCY_PROOF_NOT_AVAILABLE_G4_05",
            )),
        }
    }

    fn stage_artifact(
        &mut self,
        candidate: Option<&ArtifactDescriptor>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(candidate) = candidate else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_CANDIDATE_MISSING",
            ));
        };
        if self.store.artifact(&candidate.artifact_id)?.is_some() {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_ALREADY_EXISTS",
            ));
        }
        if !artifact_structure_is_valid(candidate)
            || !producer_matches(
                candidate
                    .provenance
                    .as_ref()
                    .and_then(|value| value.producer.as_ref()),
                principal,
            )
        {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_CANDIDATE_INVALID",
            ));
        }
        let content = candidate.content.as_ref().expect("validated content");
        let bytes = match self.blobs.read_verified(content) {
            Ok(bytes) => bytes,
            Err(error) => return Ok(blob_error_result(error)),
        };
        if let Err(rejection) = self.guard.validate_artifact(candidate, &bytes, principal) {
            return Ok(admission_error_result(rejection));
        }

        let now = self.clock.now();
        let mut artifact = candidate.clone();
        artifact.revision = 1;
        artifact.status = ArtifactStatus::Staged as i32;
        artifact.integrity_status = IntegrityStatus::DigestVerified as i32;
        artifact.created_at = Some(now);
        artifact.sealed_at = None;
        let aggregate_id = artifact.artifact_id.clone();
        self.commit_object(
            meta,
            principal,
            "stage_artifact",
            "artifact",
            &aggregate_id,
            artifact.revision,
            ArtifactEventKind::ArtifactStaged,
            &artifact.encode_to_vec(),
            Mutation::InsertArtifact {
                id: artifact.artifact_id.clone(),
                revision: artifact.revision,
                status: artifact.status,
                content_digest: content.digest.clone(),
                snapshot: artifact.encode_to_vec(),
            },
            ResultObject::Artifact(artifact),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn seal_artifact(
        &mut self,
        artifact_id: &str,
        expected_revision: u64,
        observed_content: Option<&ContentAddress>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(bytes) = self.store.artifact(artifact_id)? else {
            return Ok(error_result(
                ArtifactErrorCode::NotFound,
                "ARTIFACT_NOT_FOUND",
            ));
        };
        let mut artifact = ArtifactDescriptor::decode(bytes.as_slice())?;
        if artifact.revision != expected_revision {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_REVISION_STALE",
            ));
        }
        if artifact.status != ArtifactStatus::Staged as i32 {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_NOT_STAGED",
            ));
        }
        if observed_content != artifact.content.as_ref() {
            return Ok(error_result(
                ArtifactErrorCode::DigestMismatch,
                "ARTIFACT_OBSERVED_CONTENT_MISMATCH",
            ));
        }
        if let Err(error) = self
            .blobs
            .verify(artifact.content.as_ref().expect("stored content"))
        {
            return Ok(blob_error_result(error));
        }
        let now = self.clock.now();
        artifact.revision += 1;
        artifact.status = ArtifactStatus::Sealed as i32;
        artifact.integrity_status = IntegrityStatus::DigestVerified as i32;
        artifact.sealed_at = Some(now);
        let aggregate_id = artifact.artifact_id.clone();
        self.commit_object(
            meta,
            principal,
            "seal_artifact",
            "artifact",
            &aggregate_id,
            artifact.revision,
            ArtifactEventKind::ArtifactSealed,
            &artifact.encode_to_vec(),
            Mutation::UpdateArtifact {
                id: artifact.artifact_id.clone(),
                expected_revision,
                revision: artifact.revision,
                status: artifact.status,
                snapshot: artifact.encode_to_vec(),
            },
            ResultObject::Artifact(artifact),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn propose_claim(
        &mut self,
        candidate: Option<&Claim>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(candidate) = candidate else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "CLAIM_CANDIDATE_MISSING",
            ));
        };
        if self.store.claim(&candidate.claim_id)?.is_some() {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "CLAIM_ALREADY_EXISTS",
            ));
        }
        if !claim_structure_is_valid(candidate)
            || !producer_matches(candidate.proposer.as_ref(), principal)
        {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "CLAIM_CANDIDATE_INVALID",
            ));
        }
        if let Err(result) = self.verify_claim_subjects(candidate) {
            return Ok(result.into_result());
        }
        if let Err(error) = self
            .blobs
            .verify(candidate.statement.as_ref().expect("validated statement"))
        {
            return Ok(blob_error_result(error));
        }
        if let Err(rejection) = self.guard.validate_claim(candidate, principal) {
            return Ok(admission_error_result(rejection));
        }
        let now = self.clock.now();
        let mut claim = candidate.clone();
        claim.revision = 1;
        claim.status = ClaimStatus::Proposed as i32;
        claim.proposed_at = Some(now);
        let aggregate_id = claim.claim_id.clone();
        self.commit_object(
            meta,
            principal,
            "propose_claim",
            "claim",
            &aggregate_id,
            claim.revision,
            ArtifactEventKind::ClaimProposed,
            &claim.encode_to_vec(),
            Mutation::InsertClaim {
                id: claim.claim_id.clone(),
                revision: claim.revision,
                status: claim.status,
                proposer_principal_id: claim
                    .proposer
                    .as_ref()
                    .expect("validated proposer")
                    .principal_id
                    .clone(),
                snapshot: claim.encode_to_vec(),
            },
            ResultObject::Claim(claim),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn record_evidence(
        &mut self,
        candidate: Option<&Evidence>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(candidate) = candidate else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "EVIDENCE_CANDIDATE_MISSING",
            ));
        };
        if self.store.evidence(&candidate.evidence_id)?.is_some() {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "EVIDENCE_ALREADY_EXISTS",
            ));
        }
        if !evidence_structure_is_valid(candidate)
            || !producer_matches(candidate.producer.as_ref(), principal)
            || principal.kind.evidence_class().map(|value| value as i32)
                != Some(candidate.producer_class)
        {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "EVIDENCE_CANDIDATE_INVALID",
            ));
        }
        let Some(claim_bytes) = self.store.claim(&candidate.claim_id)? else {
            return Ok(error_result(ArtifactErrorCode::NotFound, "CLAIM_NOT_FOUND"));
        };
        let claim = Claim::decode(claim_bytes.as_slice())?;
        if candidate.lineage != claim.lineage {
            return Ok(error_result(
                ArtifactErrorCode::LineageMismatch,
                "EVIDENCE_CLAIM_LINEAGE_MISMATCH",
            ));
        }
        if candidate.independent_of_claim_proposer
            && candidate.producer.as_ref().is_some_and(|producer| {
                claim
                    .proposer
                    .as_ref()
                    .is_some_and(|proposer| proposer.principal_id == producer.principal_id)
            })
        {
            return Ok(error_result(
                ArtifactErrorCode::IndependenceViolation,
                "CLAIM_PROPOSER_CANNOT_SELF_ATTEST_INDEPENDENCE",
            ));
        }
        for artifact_id in &candidate.artifact_ids {
            let Some(artifact_bytes) = self.store.artifact(artifact_id)? else {
                return Ok(error_result(
                    ArtifactErrorCode::NotFound,
                    "ARTIFACT_NOT_FOUND",
                ));
            };
            let artifact = ArtifactDescriptor::decode(artifact_bytes.as_slice())?;
            if artifact.status != ArtifactStatus::Sealed as i32 {
                return Ok(error_result(
                    ArtifactErrorCode::MemberNotSealed,
                    "EVIDENCE_ARTIFACT_NOT_SEALED",
                ));
            }
            if artifact
                .provenance
                .as_ref()
                .and_then(|value| value.lineage.as_ref())
                != candidate.lineage.as_ref()
            {
                return Ok(error_result(
                    ArtifactErrorCode::LineageMismatch,
                    "EVIDENCE_ARTIFACT_LINEAGE_MISMATCH",
                ));
            }
        }
        if let Err(error) = self.blobs.verify(
            candidate
                .coverage_descriptor
                .as_ref()
                .expect("validated coverage descriptor"),
        ) {
            return Ok(blob_error_result(error));
        }
        if let Err(rejection) = self.guard.validate_evidence(candidate, principal) {
            return Ok(admission_error_result(rejection));
        }
        let now = self.clock.now();
        let mut evidence = candidate.clone();
        evidence.revision = 1;
        evidence.status = EvidenceStatus::Recorded as i32;
        evidence.integrity_status = IntegrityStatus::DigestVerified as i32;
        evidence.recorded_at = Some(now);
        let aggregate_id = evidence.evidence_id.clone();
        self.commit_object(
            meta,
            principal,
            "record_evidence",
            "evidence",
            &aggregate_id,
            evidence.revision,
            ArtifactEventKind::EvidenceRecorded,
            &evidence.encode_to_vec(),
            Mutation::InsertEvidence {
                id: evidence.evidence_id.clone(),
                revision: evidence.revision,
                status: evidence.status,
                claim_id: evidence.claim_id.clone(),
                producer_principal_id: evidence
                    .producer
                    .as_ref()
                    .expect("validated producer")
                    .principal_id
                    .clone(),
                snapshot: evidence.encode_to_vec(),
            },
            ResultObject::Evidence(evidence),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn create_artifact_set(
        &mut self,
        candidate: Option<&ArtifactSet>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(candidate) = candidate else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_SET_CANDIDATE_MISSING",
            ));
        };
        if self
            .store
            .artifact_set(&candidate.artifact_set_id)?
            .is_some()
        {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_SET_ALREADY_EXISTS",
            ));
        }
        if !artifact_set_structure_is_valid(candidate) {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "ARTIFACT_SET_CANDIDATE_INVALID",
            ));
        }
        if let Err(result) = self.verify_set_members(candidate) {
            return Ok(result.into_result());
        }
        let canonical = canonical_artifact_set_manifest(candidate);
        let expected = ContentAddressedBlobStore::address(&canonical);
        if candidate.canonical_manifest.as_ref() != Some(&expected) {
            return Ok(error_result(
                ArtifactErrorCode::DigestMismatch,
                "ARTIFACT_SET_MANIFEST_NOT_CANONICAL",
            ));
        }
        if let Err(error) = self.blobs.verify(&expected) {
            return Ok(blob_error_result(error));
        }
        if let Err(rejection) = self.guard.validate_artifact_set(candidate, principal) {
            return Ok(admission_error_result(rejection));
        }
        let now = self.clock.now();
        let mut artifact_set = candidate.clone();
        artifact_set.revision = 1;
        artifact_set.status = ArtifactSetStatus::Draft as i32;
        artifact_set.created_at = Some(now);
        artifact_set.sealed_at = None;
        let aggregate_id = artifact_set.artifact_set_id.clone();
        self.commit_object(
            meta,
            principal,
            "create_artifact_set",
            "artifact_set",
            &aggregate_id,
            artifact_set.revision,
            ArtifactEventKind::SetCreated,
            &artifact_set.encode_to_vec(),
            Mutation::InsertArtifactSet {
                id: artifact_set.artifact_set_id.clone(),
                revision: artifact_set.revision,
                status: artifact_set.status,
                manifest_digest: expected.digest,
                snapshot: artifact_set.encode_to_vec(),
            },
            ResultObject::ArtifactSet(artifact_set),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn seal_artifact_set(
        &mut self,
        artifact_set_id: &str,
        expected_revision: u64,
        observed_manifest: Option<&ContentAddress>,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(bytes) = self.store.artifact_set(artifact_set_id)? else {
            return Ok(error_result(
                ArtifactErrorCode::NotFound,
                "ARTIFACT_SET_NOT_FOUND",
            ));
        };
        let mut artifact_set = ArtifactSet::decode(bytes.as_slice())?;
        if artifact_set.revision != expected_revision {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_SET_REVISION_STALE",
            ));
        }
        if artifact_set.status != ArtifactSetStatus::Draft as i32 {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_SET_NOT_DRAFT",
            ));
        }
        if observed_manifest != artifact_set.canonical_manifest.as_ref() {
            return Ok(error_result(
                ArtifactErrorCode::DigestMismatch,
                "ARTIFACT_SET_OBSERVED_MANIFEST_MISMATCH",
            ));
        }
        if let Err(result) = self.verify_set_members(&artifact_set) {
            return Ok(result.into_result());
        }
        let canonical = canonical_artifact_set_manifest(&artifact_set);
        let expected = ContentAddressedBlobStore::address(&canonical);
        if artifact_set.canonical_manifest.as_ref() != Some(&expected) {
            return Ok(error_result(
                ArtifactErrorCode::DigestMismatch,
                "ARTIFACT_SET_MANIFEST_NOT_CANONICAL",
            ));
        }
        if let Err(error) = self.blobs.verify(&expected) {
            return Ok(blob_error_result(error));
        }
        let now = self.clock.now();
        artifact_set.revision += 1;
        artifact_set.status = ArtifactSetStatus::Sealed as i32;
        artifact_set.sealed_at = Some(now);
        let aggregate_id = artifact_set.artifact_set_id.clone();
        self.commit_object(
            meta,
            principal,
            "seal_artifact_set",
            "artifact_set",
            &aggregate_id,
            artifact_set.revision,
            ArtifactEventKind::SetSealed,
            &artifact_set.encode_to_vec(),
            Mutation::UpdateArtifactSet {
                id: artifact_set.artifact_set_id.clone(),
                expected_revision,
                revision: artifact_set.revision,
                status: artifact_set.status,
                snapshot: artifact_set.encode_to_vec(),
            },
            ResultObject::ArtifactSet(artifact_set),
            &[LOCAL_READ_MODEL],
            now,
        )
    }

    fn submit_return_handoff(
        &mut self,
        candidate: Option<&ReturnHandoff>,
        expected_set_revision: u64,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let Some(candidate) = candidate else {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "RETURN_HANDOFF_CANDIDATE_MISSING",
            ));
        };
        if self
            .store
            .return_handoff(&candidate.return_handoff_id)?
            .is_some()
        {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "RETURN_HANDOFF_ALREADY_EXISTS",
            ));
        }
        if !return_handoff_structure_is_valid(candidate)
            || !producer_matches(candidate.submitted_by.as_ref(), principal)
        {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "RETURN_HANDOFF_CANDIDATE_INVALID",
            ));
        }
        let Some(set_bytes) = self.store.artifact_set(&candidate.artifact_set_id)? else {
            return Ok(error_result(
                ArtifactErrorCode::NotFound,
                "ARTIFACT_SET_NOT_FOUND",
            ));
        };
        let artifact_set = ArtifactSet::decode(set_bytes.as_slice())?;
        if artifact_set.revision != expected_set_revision {
            return Ok(error_result(
                ArtifactErrorCode::RevisionConflict,
                "ARTIFACT_SET_REVISION_STALE",
            ));
        }
        if artifact_set.status != ArtifactSetStatus::Sealed as i32 {
            return Ok(error_result(
                ArtifactErrorCode::MemberNotSealed,
                "ARTIFACT_SET_NOT_SEALED",
            ));
        }
        if candidate.lineage != artifact_set.lineage
            || candidate.artifact_set_manifest != artifact_set.canonical_manifest
        {
            return Ok(error_result(
                ArtifactErrorCode::LineageMismatch,
                "RETURN_HANDOFF_SET_BINDING_MISMATCH",
            ));
        }
        if !handoff_members_are_subsets(candidate, &artifact_set) {
            return Ok(error_result(
                ArtifactErrorCode::InvalidArgument,
                "RETURN_HANDOFF_MEMBER_NOT_IN_SET",
            ));
        }
        if let Err(rejection) = self.guard.validate_return_handoff(candidate, principal) {
            return Ok(admission_error_result(rejection));
        }

        let now = self.clock.now();
        let mut handoff = candidate.clone();
        handoff.revision = 1;
        handoff.status = ReturnHandoffStatus::Receipted as i32;
        handoff.submitted_at = Some(now);
        let handoff_bytes = handoff.encode_to_vec();
        let handoff_digest = ContentAddressedBlobStore::address(&handoff_bytes);
        self.blobs.put_verified(&handoff_bytes, &handoff_digest)?;
        let receipt = ReturnReceipt {
            receipt_id: format!("return-receipt-{}", Uuid::now_v7()),
            return_handoff_id: handoff.return_handoff_id.clone(),
            return_handoff_digest: Some(handoff_digest),
            artifact_set_id: artifact_set.artifact_set_id.clone(),
            artifact_set_manifest: artifact_set.canonical_manifest.clone(),
            lineage: artifact_set.lineage.clone(),
            accepted_for_evidence_intake: true,
            verification_performed: false,
            task_completion_decided: false,
            committed_at: Some(now),
        };
        let receipt_bytes = receipt.encode_to_vec();
        let aggregate_id = handoff.return_handoff_id.clone();
        self.commit_object(
            meta,
            principal,
            "submit_return_handoff",
            "return_handoff",
            &aggregate_id,
            handoff.revision,
            ArtifactEventKind::ReturnReceipted,
            &receipt_bytes,
            Mutation::InsertReturn {
                handoff_id: handoff.return_handoff_id.clone(),
                handoff_revision: handoff.revision,
                handoff_status: handoff.status,
                artifact_set_id: handoff.artifact_set_id.clone(),
                handoff_snapshot: handoff.encode_to_vec(),
                receipt_id: receipt.receipt_id.clone(),
                receipt_snapshot: receipt_bytes.clone(),
            },
            ResultObject::Return(handoff, receipt),
            &[LOCAL_READ_MODEL, COLLABORATION_CONTROL],
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_object(
        &mut self,
        meta: &CommandMetadata,
        principal: &AuthenticatedArtifactPrincipal,
        operation: &str,
        aggregate_type: &str,
        aggregate_id: &str,
        aggregate_revision: u64,
        event_kind: ArtifactEventKind,
        payload: &[u8],
        mutation: Mutation,
        result_object: ResultObject,
        destinations: &[&str],
        now: Timestamp,
    ) -> Result<ArtifactCommandResult, ArtifactAuthorityFailure> {
        let payload_address = ContentAddressedBlobStore::address(payload);
        self.blobs.put_verified(payload, &payload_address)?;
        let event = ArtifactEvent {
            event_id: format!("artifact-event-{}", Uuid::now_v7()),
            kind: event_kind as i32,
            aggregate_type: aggregate_type.to_owned(),
            aggregate_id: aggregate_id.to_owned(),
            aggregate_revision,
            lineage: result_object.lineage(),
            committed_at: Some(now),
            authenticated_principal_id: principal.principal_id.clone(),
            command_id: meta.command_id.clone(),
            payload: Some(payload_address),
        };
        let mut result = result_object.into_result(event.clone());
        result.committed = true;
        let result_bytes = result.encode_to_vec();
        let event_bytes = event.encode_to_vec();
        let outbox = destinations
            .iter()
            .map(|destination| OutboxWrite {
                message_id: format!("artifact-outbox-{}", Uuid::now_v7()),
                destination_domain: (*destination).to_owned(),
                payload_digest_sha256: hex::encode(Sha256::digest(&result_bytes)),
                payload: result_bytes.clone(),
            })
            .collect();
        self.store.commit(AuthorityCommit {
            mutation,
            event_id: event.event_id.clone(),
            command_id: meta.command_id.clone(),
            aggregate_type: aggregate_type.to_owned(),
            aggregate_id: aggregate_id.to_owned(),
            aggregate_revision,
            request_digest_sha256: meta.request_digest_sha256.clone(),
            event: event_bytes,
            authenticated_principal_id: principal.principal_id.clone(),
            operation: operation.to_owned(),
            idempotency_scope: meta.idempotency_scope.clone(),
            idempotency_key: meta.idempotency_key.clone(),
            result: result_bytes,
            outbox,
            committed_at_seconds: now.seconds,
        })?;
        Ok(result)
    }

    fn verify_claim_subjects(&self, claim: &Claim) -> Result<(), DomainRejection> {
        for artifact_id in &claim.subject_artifact_ids {
            let artifact_bytes = self
                .store
                .artifact(artifact_id)
                .map_err(|_| {
                    DomainRejection::new(ArtifactErrorCode::IntegrityFailure, "STORE_READ_FAILED")
                })?
                .ok_or_else(|| {
                    DomainRejection::new(ArtifactErrorCode::NotFound, "ARTIFACT_NOT_FOUND")
                })?;
            let artifact = ArtifactDescriptor::decode(artifact_bytes.as_slice()).map_err(|_| {
                DomainRejection::new(
                    ArtifactErrorCode::IntegrityFailure,
                    "ARTIFACT_DECODE_FAILED",
                )
            })?;
            if artifact.status != ArtifactStatus::Sealed as i32 {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::MemberNotSealed,
                    "CLAIM_SUBJECT_NOT_SEALED",
                ));
            }
            if artifact
                .provenance
                .as_ref()
                .and_then(|value| value.lineage.as_ref())
                != claim.lineage.as_ref()
            {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::LineageMismatch,
                    "CLAIM_SUBJECT_LINEAGE_MISMATCH",
                ));
            }
        }
        Ok(())
    }

    fn verify_set_members(&self, artifact_set: &ArtifactSet) -> Result<(), DomainRejection> {
        let lineage = artifact_set.lineage.as_ref();
        for id in &artifact_set.artifact_ids {
            let bytes = required_snapshot(self.store.artifact(id), "ARTIFACT_NOT_FOUND")?;
            let value = ArtifactDescriptor::decode(bytes.as_slice()).map_err(|_| {
                DomainRejection::new(
                    ArtifactErrorCode::IntegrityFailure,
                    "ARTIFACT_DECODE_FAILED",
                )
            })?;
            if value.status != ArtifactStatus::Sealed as i32 {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::MemberNotSealed,
                    "ARTIFACT_SET_MEMBER_NOT_SEALED",
                ));
            }
            if value
                .provenance
                .as_ref()
                .and_then(|item| item.lineage.as_ref())
                != lineage
            {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::LineageMismatch,
                    "ARTIFACT_SET_LINEAGE_MISMATCH",
                ));
            }
        }
        for id in &artifact_set.claim_ids {
            let bytes = required_snapshot(self.store.claim(id), "CLAIM_NOT_FOUND")?;
            let value = Claim::decode(bytes.as_slice()).map_err(|_| {
                DomainRejection::new(ArtifactErrorCode::IntegrityFailure, "CLAIM_DECODE_FAILED")
            })?;
            if value.status != ClaimStatus::Proposed as i32 || value.lineage.as_ref() != lineage {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::LineageMismatch,
                    "ARTIFACT_SET_CLAIM_INVALID",
                ));
            }
        }
        for id in &artifact_set.evidence_ids {
            let bytes = required_snapshot(self.store.evidence(id), "EVIDENCE_NOT_FOUND")?;
            let value = Evidence::decode(bytes.as_slice()).map_err(|_| {
                DomainRejection::new(
                    ArtifactErrorCode::IntegrityFailure,
                    "EVIDENCE_DECODE_FAILED",
                )
            })?;
            if value.status != EvidenceStatus::Recorded as i32 || value.lineage.as_ref() != lineage
            {
                return Err(DomainRejection::new(
                    ArtifactErrorCode::LineageMismatch,
                    "ARTIFACT_SET_EVIDENCE_INVALID",
                ));
            }
        }
        Ok(())
    }

    pub fn inspect_store(&self) -> Result<ArtifactStoreInspection, ArtifactAuthorityFailure> {
        Ok(self.store.inspect()?)
    }

    pub fn integrity_is_ok(&self) -> Result<bool, ArtifactAuthorityFailure> {
        Ok(self.store.integrity_is_ok()?)
    }

    pub fn drain_projection_outbox(
        &self,
    ) -> Result<Vec<ArtifactProjectionMessage>, ArtifactAuthorityFailure> {
        self.decode_projection_messages(self.store.pending_projection_outbox()?)
    }

    pub fn projection_baselines(
        &self,
    ) -> Result<Vec<ArtifactProjectionMessage>, ArtifactAuthorityFailure> {
        self.decode_projection_messages(self.store.projection_baselines()?)
    }

    fn decode_projection_messages(
        &self,
        pending_messages: Vec<store::PendingProjectionOutbox>,
    ) -> Result<Vec<ArtifactProjectionMessage>, ArtifactAuthorityFailure> {
        pending_messages
            .into_iter()
            .map(|pending| {
                let actual_digest = hex::encode(Sha256::digest(&pending.payload));
                let result = ArtifactCommandResult::decode(pending.payload.as_slice())?;
                let event = result
                    .event
                    .as_ref()
                    .ok_or(ArtifactAuthorityFailure::Storage)?;
                if actual_digest != pending.payload_digest_sha256
                    || !result.committed
                    || event.event_id != pending.source_event_id
                    || event.aggregate_revision != pending.source_revision
                {
                    return Err(ArtifactAuthorityFailure::Storage);
                }
                Ok(ArtifactProjectionMessage {
                    message_id: pending.message_id,
                    source_event_id: pending.source_event_id,
                    source_revision: pending.source_revision,
                    payload_digest_sha256: pending.payload_digest_sha256,
                    result,
                })
            })
            .collect()
    }

    pub fn acknowledge_projection(
        &mut self,
        message_id: &str,
        expected_payload_digest_sha256: &str,
    ) -> Result<bool, ArtifactAuthorityFailure> {
        self.store
            .acknowledge_projection_outbox(message_id, expected_payload_digest_sha256)
            .map_err(ArtifactAuthorityFailure::from)
    }
}

enum ResultObject {
    Artifact(ArtifactDescriptor),
    Claim(Claim),
    Evidence(Evidence),
    ArtifactSet(ArtifactSet),
    Return(ReturnHandoff, ReturnReceipt),
}

#[derive(Clone, Copy)]
struct DomainRejection {
    code: ArtifactErrorCode,
    fingerprint: &'static str,
}

impl DomainRejection {
    const fn new(code: ArtifactErrorCode, fingerprint: &'static str) -> Self {
        Self { code, fingerprint }
    }

    fn into_result(self) -> ArtifactCommandResult {
        error_result(self.code, self.fingerprint)
    }
}

impl ResultObject {
    fn lineage(&self) -> Option<LineageBinding> {
        match self {
            Self::Artifact(value) => value
                .provenance
                .as_ref()
                .and_then(|item| item.lineage.clone()),
            Self::Claim(value) => value.lineage.clone(),
            Self::Evidence(value) => value.lineage.clone(),
            Self::ArtifactSet(value) => value.lineage.clone(),
            Self::Return(value, _) => value.lineage.clone(),
        }
    }

    fn into_result(self, event: ArtifactEvent) -> ArtifactCommandResult {
        let mut result = ArtifactCommandResult {
            committed: false,
            replayed: false,
            artifact: None,
            claim: None,
            evidence: None,
            artifact_set: None,
            return_handoff: None,
            return_receipt: None,
            event: Some(event),
            error_code: ArtifactErrorCode::Unspecified as i32,
            safe_error_fingerprint: None,
        };
        match self {
            Self::Artifact(value) => result.artifact = Some(value),
            Self::Claim(value) => result.claim = Some(value),
            Self::Evidence(value) => result.evidence = Some(value),
            Self::ArtifactSet(value) => result.artifact_set = Some(value),
            Self::Return(handoff, receipt) => {
                result.return_handoff = Some(handoff);
                result.return_receipt = Some(receipt);
            }
        }
        result
    }
}

fn required_snapshot(
    result: Result<Option<Vec<u8>>, StoreError>,
    missing_code: &'static str,
) -> Result<Vec<u8>, DomainRejection> {
    result
        .map_err(|_| {
            DomainRejection::new(ArtifactErrorCode::IntegrityFailure, "STORE_READ_FAILED")
        })?
        .ok_or_else(|| DomainRejection::new(ArtifactErrorCode::NotFound, missing_code))
}

#[must_use]
pub fn canonical_request_digest(command: &ArtifactCommand) -> Option<String> {
    command.command.as_ref()?;
    let mut canonical = command.clone();
    let meta = command_metadata_mut(&mut canonical)?;
    meta.command_id.clear();
    meta.request_digest_sha256.clear();
    meta.issued_at = None;
    meta.correlation_id.clear();
    meta.causation_id = None;
    Some(hex::encode(Sha256::digest(canonical.encode_to_vec())))
}

#[must_use]
pub fn canonical_artifact_set_manifest(artifact_set: &ArtifactSet) -> Vec<u8> {
    let mut artifacts = artifact_set.artifact_ids.clone();
    let mut claims = artifact_set.claim_ids.clone();
    let mut evidence = artifact_set.evidence_ids.clone();
    artifacts.sort();
    claims.sort();
    evidence.sort();
    let mut bytes = b"EGOPULSE_ARTIFACT_SET_MANIFEST_V1\n".to_vec();
    append_field(&mut bytes, "artifact_set_id", &artifact_set.artifact_set_id);
    if let Some(lineage) = artifact_set.lineage.as_ref() {
        append_field(&mut bytes, "lineage", &hex::encode(lineage.encode_to_vec()));
    }
    for value in artifacts {
        append_field(&mut bytes, "artifact", &value);
    }
    for value in claims {
        append_field(&mut bytes, "claim", &value);
    }
    for value in evidence {
        append_field(&mut bytes, "evidence", &value);
    }
    if let Some(value) = artifact_set.supersedes_artifact_set_id.as_ref() {
        append_field(&mut bytes, "supersedes", value);
    }
    bytes
}

fn append_field(bytes: &mut Vec<u8>, name: &str, value: &str) {
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(b'=');
    bytes.extend_from_slice(value.len().to_string().as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'\n');
}

fn operation_name(command: &ArtifactCommand) -> Option<&'static str> {
    match command.command.as_ref()? {
        artifact_command::Command::StageArtifact(_) => Some("stage_artifact"),
        artifact_command::Command::SealArtifact(_) => Some("seal_artifact"),
        artifact_command::Command::QuarantineObject(_) => Some("quarantine_object"),
        artifact_command::Command::ProposeClaim(_) => Some("propose_claim"),
        artifact_command::Command::WithdrawClaim(_) => Some("withdraw_claim"),
        artifact_command::Command::RecordEvidence(_) => Some("record_evidence"),
        artifact_command::Command::CreateArtifactSet(_) => Some("create_artifact_set"),
        artifact_command::Command::SealArtifactSet(_) => Some("seal_artifact_set"),
        artifact_command::Command::SubmitReturnHandoff(_) => Some("submit_return_handoff"),
        artifact_command::Command::TombstoneObject(_) => Some("tombstone_object"),
    }
}

fn operation_allowed(operation: &str, kind: ArtifactPrincipalKind) -> bool {
    match operation {
        "stage_artifact" => matches!(
            kind,
            ArtifactPrincipalKind::Harness
                | ArtifactPrincipalKind::AttemptSupervisor
                | ArtifactPrincipalKind::GovernedCollector
                | ArtifactPrincipalKind::SupervisedRunner
        ),
        "propose_claim" => matches!(
            kind,
            ArtifactPrincipalKind::Harness | ArtifactPrincipalKind::GovernedCollector
        ),
        "record_evidence" => kind.evidence_class().is_some(),
        "create_artifact_set" | "submit_return_handoff" => matches!(
            kind,
            ArtifactPrincipalKind::Harness
                | ArtifactPrincipalKind::GovernedCollector
                | ArtifactPrincipalKind::ArtifactAuthority
        ),
        "seal_artifact" | "seal_artifact_set" | "quarantine_object" => {
            kind == ArtifactPrincipalKind::ArtifactAuthority
        }
        "withdraw_claim" => matches!(
            kind,
            ArtifactPrincipalKind::Harness | ArtifactPrincipalKind::GovernedCollector
        ),
        "tombstone_object" => kind == ArtifactPrincipalKind::RetentionAuthority,
        _ => false,
    }
}

fn command_metadata(command: &ArtifactCommand) -> Option<&CommandMetadata> {
    match command.command.as_ref()? {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_ref(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_ref(),
        artifact_command::Command::QuarantineObject(value) => value.metadata.as_ref(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_ref(),
        artifact_command::Command::WithdrawClaim(value) => value.metadata.as_ref(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_ref(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_ref(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_ref(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_ref(),
        artifact_command::Command::TombstoneObject(value) => value.metadata.as_ref(),
    }
}

fn command_metadata_mut(command: &mut ArtifactCommand) -> Option<&mut CommandMetadata> {
    match command.command.as_mut()? {
        artifact_command::Command::StageArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifact(value) => value.metadata.as_mut(),
        artifact_command::Command::QuarantineObject(value) => value.metadata.as_mut(),
        artifact_command::Command::ProposeClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::WithdrawClaim(value) => value.metadata.as_mut(),
        artifact_command::Command::RecordEvidence(value) => value.metadata.as_mut(),
        artifact_command::Command::CreateArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SealArtifactSet(value) => value.metadata.as_mut(),
        artifact_command::Command::SubmitReturnHandoff(value) => value.metadata.as_mut(),
        artifact_command::Command::TombstoneObject(value) => value.metadata.as_mut(),
    }
}

fn metadata_is_complete(meta: &CommandMetadata) -> bool {
    !meta.command_id.trim().is_empty()
        && !meta.idempotency_key.trim().is_empty()
        && !meta.idempotency_scope.trim().is_empty()
        && is_sha256(&meta.request_digest_sha256)
        && meta.issued_at.is_some()
        && !meta.correlation_id.trim().is_empty()
}

fn artifact_structure_is_valid(value: &ArtifactDescriptor) -> bool {
    !value.artifact_id.trim().is_empty()
        && value.semantic_class != ArtifactSemanticClass::Unspecified as i32
        && value
            .type_contract_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && !value.media_type.trim().is_empty()
        && value.content.as_ref().is_some_and(content_address_valid)
        && value.provenance.as_ref().is_some_and(|item| {
            item.lineage.as_ref().is_some_and(lineage_valid)
                && item.producer.is_some()
                && item
                    .transformation_contract_ref
                    .as_ref()
                    .is_some_and(contract_ref_valid)
                && !item.workspace_ref.trim().is_empty()
        })
        && !value.sensitivity_class.trim().is_empty()
        && value
            .retention_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
}

fn claim_structure_is_valid(value: &Claim) -> bool {
    !value.claim_id.trim().is_empty()
        && value.source_type == ClaimSourceType::CodeChange as i32
        && value
            .semantic_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value.lineage.as_ref().is_some_and(lineage_valid)
        && !value.subject_artifact_ids.is_empty()
        && value
            .acceptance_contract_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value.statement.as_ref().is_some_and(content_address_valid)
        && value.proposer.is_some()
}

fn evidence_structure_is_valid(value: &Evidence) -> bool {
    !value.evidence_id.trim().is_empty()
        && value.relation != EvidenceRelation::Unspecified as i32
        && !value.claim_id.trim().is_empty()
        && !value.artifact_ids.is_empty()
        && value
            .evidence_profile_ref
            .as_ref()
            .is_some_and(contract_ref_valid)
        && value.lineage.as_ref().is_some_and(lineage_valid)
        && value.producer.is_some()
        && value.producer_class != EvidenceProducerClass::Unspecified as i32
        && value
            .coverage_descriptor
            .as_ref()
            .is_some_and(content_address_valid)
}

fn artifact_set_structure_is_valid(value: &ArtifactSet) -> bool {
    !value.artifact_set_id.trim().is_empty()
        && value.lineage.as_ref().is_some_and(lineage_valid)
        && !value.artifact_ids.is_empty()
        && !value.claim_ids.is_empty()
        && !value.evidence_ids.is_empty()
        && value
            .canonical_manifest
            .as_ref()
            .is_some_and(content_address_valid)
        && unique(&value.artifact_ids)
        && unique(&value.claim_ids)
        && unique(&value.evidence_ids)
}

fn return_handoff_structure_is_valid(value: &ReturnHandoff) -> bool {
    !value.return_handoff_id.trim().is_empty()
        && value.lineage.as_ref().is_some_and(lineage_valid)
        && !value.artifact_set_id.trim().is_empty()
        && value
            .artifact_set_manifest
            .as_ref()
            .is_some_and(content_address_valid)
        && !value.primary_claim_ids.is_empty()
        && !value.evidence_ids.is_empty()
        && value.submitted_by.is_some()
}

fn producer_matches(
    producer: Option<&ProducerIdentity>,
    principal: &AuthenticatedArtifactPrincipal,
) -> bool {
    producer.is_some_and(|producer| {
        producer.principal_id == principal.principal_id
            && producer.principal_kind == principal.kind.as_str()
            && !producer.component_name.trim().is_empty()
            && !producer.component_version.trim().is_empty()
    })
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
    value.algorithm
        == egopulse_domain_contracts::v01::egopulse::artifact::v1::HashAlgorithm::Sha256 as i32
        && is_sha256(&value.digest)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unique(values: &[String]) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.windows(2).all(|window| window[0] != window[1])
}

fn handoff_members_are_subsets(handoff: &ReturnHandoff, set: &ArtifactSet) -> bool {
    handoff
        .primary_claim_ids
        .iter()
        .all(|value| set.claim_ids.contains(value))
        && handoff
            .evidence_ids
            .iter()
            .all(|value| set.evidence_ids.contains(value))
        && handoff
            .limitation_artifact_ids
            .iter()
            .chain(handoff.unknown_artifact_ids.iter())
            .all(|value| set.artifact_ids.contains(value))
        && handoff
            .final_message_artifact_id
            .as_ref()
            .is_none_or(|value| set.artifact_ids.contains(value))
}

fn error_result(code: ArtifactErrorCode, fingerprint: &str) -> ArtifactCommandResult {
    ArtifactCommandResult {
        committed: false,
        replayed: false,
        artifact: None,
        claim: None,
        evidence: None,
        artifact_set: None,
        return_handoff: None,
        return_receipt: None,
        event: None,
        error_code: code as i32,
        safe_error_fingerprint: Some(fingerprint.to_owned()),
    }
}

fn admission_error_result(rejection: AdmissionRejection) -> ArtifactCommandResult {
    match rejection {
        AdmissionRejection::InvalidArgument => error_result(
            ArtifactErrorCode::InvalidArgument,
            "ADMISSION_INPUT_INVALID",
        ),
        AdmissionRejection::ContractMismatch => error_result(
            ArtifactErrorCode::SchemaInvalid,
            "ADMISSION_CONTRACT_MISMATCH",
        ),
        AdmissionRejection::LineageMismatch => error_result(
            ArtifactErrorCode::LineageMismatch,
            "ADMISSION_LINEAGE_MISMATCH",
        ),
        AdmissionRejection::ScopeViolation => error_result(
            ArtifactErrorCode::ScopeViolation,
            "ADMISSION_SCOPE_VIOLATION",
        ),
        AdmissionRejection::SecretDetected => error_result(
            ArtifactErrorCode::SecretDetected,
            "ADMISSION_SECRET_DETECTED",
        ),
        AdmissionRejection::IndependenceViolation => error_result(
            ArtifactErrorCode::IndependenceViolation,
            "ADMISSION_INDEPENDENCE_VIOLATION",
        ),
        AdmissionRejection::Quarantined => {
            error_result(ArtifactErrorCode::Quarantined, "ADMISSION_QUARANTINED")
        }
    }
}

fn blob_error_result(error: BlobStoreError) -> ArtifactCommandResult {
    match error {
        BlobStoreError::UnsupportedAlgorithm | BlobStoreError::InvalidDigest => error_result(
            ArtifactErrorCode::InvalidArgument,
            "CONTENT_ADDRESS_INVALID",
        ),
        BlobStoreError::DigestMismatch => {
            error_result(ArtifactErrorCode::DigestMismatch, "BLOB_DIGEST_MISMATCH")
        }
        BlobStoreError::LengthMismatch => {
            error_result(ArtifactErrorCode::LengthMismatch, "BLOB_LENGTH_MISMATCH")
        }
        BlobStoreError::Missing => {
            error_result(ArtifactErrorCode::IntegrityFailure, "BLOB_MISSING")
        }
        BlobStoreError::Io(_) => {
            error_result(ArtifactErrorCode::IntegrityFailure, "BLOB_IO_FAILURE")
        }
    }
}
