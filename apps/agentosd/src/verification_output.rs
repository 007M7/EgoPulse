use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use egopulse_artifact_authority::{
    ArtifactAuthority, ArtifactPrincipalKind, AuthenticatedArtifactPrincipal,
    canonical_artifact_set_manifest, canonical_request_digest, content_address,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactCommand, ArtifactDescriptor, ArtifactSemanticClass, ArtifactSetStatus,
        ArtifactStatus, ClaimStatus, ContentAddress, IntegrityStatus, ProducerIdentity, Provenance,
        SealArtifactCommand, StageArtifactCommand, artifact_command,
    },
    common::v1::{CommandMetadata, ContractReference},
    verification::v1::{CheckerProfileStatus, VerificationStatus},
};
use egopulse_verification_authority::{
    CheckerOutputRole, VerificationAuthority, checker_output_execution_ref,
};
use prost_types::Timestamp;

use crate::{
    ConfiguredArtifactAdmissionGuard,
    artifact::{DerivedWorkspaceAdmissionBinding, DerivedWorkspaceAdmissionHandle},
};

/// Explicit deployment contracts for checker output, separate from the
/// contracts describing the repository artifacts under review.
#[derive(Clone, Debug)]
pub(crate) struct VerificationOutputPolicy {
    pub(crate) raw_output_type_ref: ContractReference,
    pub(crate) detail_type_ref: ContractReference,
    pub(crate) tool_receipt_type_ref: ContractReference,
    pub(crate) model_receipt_type_ref: ContractReference,
    pub(crate) cost_receipt_type_ref: ContractReference,
    pub(crate) retention_profile_ref: ContractReference,
    pub(crate) collector_principal_id: String,
    pub(crate) artifact_authority_principal_id: String,
    pub(crate) max_output_bytes: usize,
}

pub(crate) struct VerificationOutputRequest<'a> {
    pub(crate) verification_request_id: &'a str,
    pub(crate) verification_run_id: &'a str,
    pub(crate) checker_profile_id: &'a str,
    pub(crate) role: CheckerOutputRole,
    /// Stable within the checker execution, e.g. raw, receipt or finding ID.
    pub(crate) output_key: &'a str,
    pub(crate) media_type: &'a str,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SealedVerificationOutput {
    pub(crate) artifact_id: String,
    pub(crate) content: ContentAddress,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum VerificationOutputError {
    #[error("verification output configuration or input is invalid")]
    Invalid,
    #[error("verification output does not match the sealed input binding")]
    Binding,
    #[error("verification output could not be persisted")]
    Unavailable,
}

pub(crate) struct VerificationResultArtifactIntake {
    authority: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    verification: Arc<Mutex<VerificationAuthority>>,
    admission: DerivedWorkspaceAdmissionHandle,
    policy: VerificationOutputPolicy,
}

impl VerificationResultArtifactIntake {
    pub(crate) fn new(
        authority: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
        verification: Arc<Mutex<VerificationAuthority>>,
        admission: DerivedWorkspaceAdmissionHandle,
        policy: VerificationOutputPolicy,
    ) -> Result<Self, VerificationOutputError> {
        if policy.collector_principal_id.trim().is_empty()
            || policy.artifact_authority_principal_id.trim().is_empty()
            || policy.max_output_bytes == 0
            || policy.max_output_bytes > 64 * 1024 * 1024
            || [
                &policy.raw_output_type_ref,
                &policy.detail_type_ref,
                &policy.tool_receipt_type_ref,
                &policy.model_receipt_type_ref,
                &policy.cost_receipt_type_ref,
                &policy.retention_profile_ref,
            ]
            .iter()
            .any(|reference| {
                reference.contract_id.trim().is_empty()
                    || reference.version.trim().is_empty()
                    || reference.sha256.len() != 64
                    || !reference
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(VerificationOutputError::Invalid);
        }
        Ok(Self {
            authority,
            verification,
            admission,
            policy,
        })
    }

    /// Called only after the governed execution has produced these bytes.
    /// A lost response or partial stage/seal can replay the same bytes; an
    /// existing identity with different content is rejected by Artifact Authority.
    pub(crate) fn capture(
        &self,
        request: VerificationOutputRequest<'_>,
    ) -> Result<SealedVerificationOutput, VerificationOutputError> {
        // Never take the verification scope or profile body from an output
        // producer. Read both from their owner before locking Artifact Authority.
        let (verification_request, profile) = {
            let verification = self
                .verification
                .lock()
                .map_err(|_| VerificationOutputError::Unavailable)?;
            let stored = verification
                .verification_request(request.verification_request_id)
                .map_err(|_| VerificationOutputError::Unavailable)?
                .ok_or(VerificationOutputError::Binding)?;
            let run = verification
                .verification_run(request.verification_run_id)
                .map_err(|_| VerificationOutputError::Unavailable)?
                .ok_or(VerificationOutputError::Binding)?;
            let profile = verification
                .checker_profile(request.checker_profile_id)
                .map_err(|_| VerificationOutputError::Unavailable)?
                .ok_or(VerificationOutputError::Binding)?;
            if stored.status != VerificationStatus::Running as i32
                || run.status != VerificationStatus::Running as i32
                || run.verification_request_id != stored.verification_request_id
                || profile.status != CheckerProfileStatus::Active as i32
                || !stored.checker_profile_refs.iter().any(|reference| {
                    reference.contract_id == profile.checker_profile_id
                        && reference.version == profile.checker_version
                        && reference.sha256 == profile.profile_digest_sha256
                })
            {
                return Err(VerificationOutputError::Binding);
            }
            (stored, profile)
        };
        let binding = verification_request
            .binding
            .as_ref()
            .ok_or(VerificationOutputError::Binding)?;
        if [
            request.verification_request_id,
            request.verification_run_id,
            request.output_key,
            request.media_type,
            &profile.checker_profile_id,
            &profile.checker_version,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || profile.output_contract_ref.is_none()
            || request.bytes.len() > self.policy.max_output_bytes
        {
            return Err(VerificationOutputError::Invalid);
        }
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| VerificationOutputError::Unavailable)?;
        let set = authority
            .read_artifact_set(&binding.artifact_set_id)
            .map_err(|_| VerificationOutputError::Unavailable)?
            .ok_or(VerificationOutputError::Binding)?;
        if set.status != ArtifactSetStatus::Sealed as i32
            || set.lineage != binding.lineage
            || set.canonical_manifest != binding.artifact_set_manifest
            || !set.claim_ids.contains(&binding.claim_id)
        {
            return Err(VerificationOutputError::Binding);
        }
        let claim = authority
            .read_claim(&binding.claim_id)
            .map_err(|_| VerificationOutputError::Unavailable)?
            .ok_or(VerificationOutputError::Binding)?;
        if claim.status != ClaimStatus::Proposed as i32
            || claim.lineage != binding.lineage
            || claim.semantic_profile_ref != binding.claim_semantic_profile_ref
            || claim.acceptance_contract_ref != binding.acceptance_contract_ref
            || claim
                .subject_artifact_ids
                .iter()
                .any(|id| !set.artifact_ids.contains(id))
        {
            return Err(VerificationOutputError::Binding);
        }
        let manifest = set
            .canonical_manifest
            .as_ref()
            .ok_or(VerificationOutputError::Binding)?;
        if authority
            .read_blob(manifest)
            .map_err(|_| VerificationOutputError::Unavailable)?
            != canonical_artifact_set_manifest(&set)
        {
            return Err(VerificationOutputError::Binding);
        }
        let lineage = set
            .lineage
            .clone()
            .ok_or(VerificationOutputError::Binding)?;
        let ids = set.artifact_ids.iter().collect::<BTreeSet<_>>();
        if ids.is_empty() || ids.len() != set.artifact_ids.len() {
            return Err(VerificationOutputError::Binding);
        }
        let mut baseline = None;
        let mut workspaces = BTreeSet::new();
        for id in &set.artifact_ids {
            let artifact = authority
                .read_artifact(id)
                .map_err(|_| VerificationOutputError::Unavailable)?
                .ok_or(VerificationOutputError::Binding)?;
            let provenance = artifact
                .provenance
                .as_ref()
                .ok_or(VerificationOutputError::Binding)?;
            if artifact.status != ArtifactStatus::Sealed as i32
                || artifact.integrity_status != IntegrityStatus::DigestVerified as i32
                || provenance.lineage.as_ref() != Some(&lineage)
            {
                return Err(VerificationOutputError::Binding);
            }
            workspaces.insert(provenance.workspace_ref.clone());
            if artifact.semantic_class == ArtifactSemanticClass::RepositoryBaseline as i32 {
                if baseline.is_some() {
                    return Err(VerificationOutputError::Binding);
                }
                baseline = Some(provenance.clone());
            }
        }
        let baseline = baseline.ok_or(VerificationOutputError::Binding)?;
        let source_binding_ref = baseline
            .raw_source_ref
            .ok_or(VerificationOutputError::Binding)?;
        if workspaces.len() != 1
            || baseline.workspace_ref.trim().is_empty()
            || source_binding_ref.trim().is_empty()
        {
            return Err(VerificationOutputError::Binding);
        }
        let _lease = self
            .admission
            .register(DerivedWorkspaceAdmissionBinding {
                workspace_ref: baseline.workspace_ref.clone(),
                lineage: lineage.clone(),
                source_binding_ref: source_binding_ref.clone(),
            })
            .map_err(|_| VerificationOutputError::Binding)?;
        let (component, semantic_class, type_contract_ref) = self.role_policy(request.role);
        let identity = serde_json::to_vec(&serde_json::json!([
            request.verification_request_id,
            request.verification_run_id,
            profile.checker_profile_id,
            component,
            request.output_key,
        ]))
        .map_err(|_| VerificationOutputError::Invalid)?;
        let artifact_id = format!(
            "artifact:verification-output:{}",
            content_address(&identity).digest
        );
        let content = content_address(request.bytes);
        let candidate = ArtifactDescriptor {
            artifact_id: artifact_id.clone(),
            revision: 1,
            status: ArtifactStatus::Staged as i32,
            semantic_class: semantic_class as i32,
            type_contract_ref: Some(type_contract_ref.clone()),
            media_type: request.media_type.to_owned(),
            content: Some(content.clone()),
            integrity_status: IntegrityStatus::Unverified as i32,
            provenance: Some(Provenance {
                lineage: Some(lineage),
                producer: Some(ProducerIdentity {
                    principal_kind: ArtifactPrincipalKind::GovernedCollector.as_str().to_owned(),
                    principal_id: self.policy.collector_principal_id.clone(),
                    component_name: component.to_owned(),
                    component_version: profile.checker_version.clone(),
                    capability_profile_id: Some(profile.checker_profile_id.clone()),
                    native_execution_ref: Some(checker_output_execution_ref(
                        request.verification_request_id,
                        request.verification_run_id,
                        &profile.checker_profile_id,
                    )),
                }),
                input_artifact_ids: set.artifact_ids,
                transformation_contract_ref: profile.output_contract_ref.clone(),
                workspace_ref: baseline.workspace_ref,
                raw_source_ref: Some(source_binding_ref),
                observed_at: None,
                captured_at: None,
            }),
            sensitivity_class: "local-user-data".to_owned(),
            retention_profile_ref: Some(self.policy.retention_profile_ref.clone()),
            created_at: None,
            sealed_at: None,
            supersedes_artifact_id: None,
            quarantine_reason_code: None,
        };
        authority
            .put_blob(request.bytes, &content)
            .map_err(|_| VerificationOutputError::Unavailable)?;
        let stage = make_command(artifact_command::Command::StageArtifact(
            StageArtifactCommand {
                metadata: Some(metadata(&artifact_id, "stage")?),
                candidate: Some(candidate.clone()),
            },
        ))?;
        let seal = make_command(artifact_command::Command::SealArtifact(
            SealArtifactCommand {
                metadata: Some(metadata(&artifact_id, "seal")?),
                artifact_id: artifact_id.clone(),
                expected_revision: 1,
                observed_content: Some(content.clone()),
            },
        ))?;
        for (command, kind, principal_id) in [
            (
                stage,
                ArtifactPrincipalKind::GovernedCollector,
                self.policy.collector_principal_id.clone(),
            ),
            (
                seal,
                ArtifactPrincipalKind::ArtifactAuthority,
                self.policy.artifact_authority_principal_id.clone(),
            ),
        ] {
            let result = authority
                .execute(
                    &command,
                    &AuthenticatedArtifactPrincipal {
                        kind,
                        principal_id,
                        authenticated: true,
                    },
                )
                .map_err(|_| VerificationOutputError::Unavailable)?;
            if !result.committed && !result.replayed {
                return Err(VerificationOutputError::Binding);
            }
        }
        let sealed = authority
            .read_artifact(&artifact_id)
            .map_err(|_| VerificationOutputError::Unavailable)?
            .ok_or(VerificationOutputError::Unavailable)?;
        let mut expected = candidate;
        expected.revision = sealed.revision;
        expected.status = ArtifactStatus::Sealed as i32;
        expected.integrity_status = IntegrityStatus::DigestVerified as i32;
        expected.created_at = sealed.created_at;
        expected.sealed_at = sealed.sealed_at;
        if sealed != expected
            || sealed.revision != 2
            || authority
                .read_blob(&content)
                .map_err(|_| VerificationOutputError::Unavailable)?
                != request.bytes
        {
            return Err(VerificationOutputError::Binding);
        }
        Ok(SealedVerificationOutput {
            artifact_id,
            content,
        })
    }

    fn role_policy(
        &self,
        role: CheckerOutputRole,
    ) -> (&'static str, ArtifactSemanticClass, &ContractReference) {
        match role {
            CheckerOutputRole::RawOutput => (
                "verification-raw-output",
                ArtifactSemanticClass::LogBundle,
                &self.policy.raw_output_type_ref,
            ),
            CheckerOutputRole::Detail => (
                "verification-finding-detail",
                ArtifactSemanticClass::TypedExtension,
                &self.policy.detail_type_ref,
            ),
            CheckerOutputRole::ToolReceipt => (
                "verification-tool-receipt",
                ArtifactSemanticClass::ToolReceipt,
                &self.policy.tool_receipt_type_ref,
            ),
            CheckerOutputRole::ModelCallReceipt => (
                "verification-model-call-receipt",
                ArtifactSemanticClass::ToolReceipt,
                &self.policy.model_receipt_type_ref,
            ),
            CheckerOutputRole::CostReceipt => (
                "verification-cost-receipt",
                ArtifactSemanticClass::UsageReceipt,
                &self.policy.cost_receipt_type_ref,
            ),
        }
    }
}

fn metadata(id: &str, operation: &str) -> Result<CommandMetadata, VerificationOutputError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VerificationOutputError::Unavailable)?;
    let key = format!("{id}:{operation}");
    Ok(CommandMetadata {
        command_id: key.clone(),
        idempotency_key: key,
        idempotency_scope: "verification-output-v1".to_owned(),
        request_digest_sha256: String::new(),
        issued_at: Some(Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }),
        correlation_id: id.to_owned(),
        causation_id: None,
    })
}

fn make_command(
    value: artifact_command::Command,
) -> Result<ArtifactCommand, VerificationOutputError> {
    let mut command = ArtifactCommand {
        command: Some(value),
    };
    let digest = canonical_request_digest(&command).ok_or(VerificationOutputError::Invalid)?;
    let metadata = match command.command.as_mut() {
        Some(artifact_command::Command::StageArtifact(value)) => value.metadata.as_mut(),
        Some(artifact_command::Command::SealArtifact(value)) => value.metadata.as_mut(),
        _ => None,
    }
    .ok_or(VerificationOutputError::Invalid)?;
    metadata.request_digest_sha256 = digest;
    Ok(command)
}

#[cfg(test)]
#[path = "verification_output_tests.rs"]
mod tests;
