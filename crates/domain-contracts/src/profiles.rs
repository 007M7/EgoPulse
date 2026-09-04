//! Shared parsing and fail-closed interpretation of frozen client/API profiles.
//!
//! This module is deliberately owned by the common contract boundary so local
//! clients and services cannot drift into separate authorization rule sets.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const API_CONTRACT_ID: &str = "egopulse.localapi.v1";
pub const API_CONTRACT_VERSION: &str = "0.1.0-draft.22";
pub const API_CONTRACT_DIGEST_SHA256: &str =
    "c5996f33fa260c2599a4c3c28ced43959d648e34978c3175940e1dd22c58babd";
pub const CLIENT_KERNEL_CONTRACT_ID: &str = "egopulse.client-kernel.v1";
pub const CLIENT_KERNEL_CONTRACT_VERSION: &str = "0.1.0";
pub const CLIENT_KERNEL_PROFILE_DIGEST_SHA256: &str =
    "d1eee23877a6b55cbfe12a7b90041a86a1eaebbdb4a6a863e924ba101ad694bc";
pub const AUTHORIZATION_CONTRACT_ID: &str = "egopulse.authorization.v1";
pub const AUTHORIZATION_CONTRACT_VERSION: &str = "0.1.0";
pub const AUTHORIZATION_PROFILE_DIGEST_SHA256: &str =
    "8426ece110ca30ca64bc384daee0bd1b6b2ab1966eed2b3b8c1a17cea5f0cc06";
pub const HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID: &str = "egopulse.harness-content-disclosure.v1";
pub const HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION: &str = "0.1.1";
pub const HARNESS_CONTENT_DISCLOSURE_PROFILE_ID: &str = "harness-content-disclosure-v01-default";
pub const HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256: &str =
    "c969c9eda5394617aa8bcbca4ed0086eb0dd61ced2519818db830cc73ed1e58f";
const R9C_PROFILE_AUTHORITY_REF: &str =
    "conversation:2026-09-04:founder-froze-r9c-d01-d12-and-phase-2-82-section-7";
const M13_PROFILE_AUTHORITY_REF: &str =
    "conversation:2026-09-05:founder-resume-after-m13-decision-package";

const CLIENT_KERNEL_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/client-kernel/v1/v01-default.json");
const AUTHORIZATION_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/authorization/v1/v01-default.json");
const HARNESS_CONTENT_DISCLOSURE_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/harness-content-disclosure/v1/v01-default.json");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientKernelProfile {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub authority_ref: String,
    pub local_api_compatibility: LocalApiCompatibility,
    pub implementation_boundary: ImplementationBoundary,
    pub capabilities: BTreeSet<String>,
    pub stream_semantics: ClientKernelStreamSemantics,
    pub invariants: ClientKernelInvariants,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientKernelStreamSemantics {
    pub complete_snapshot_domains: Vec<String>,
    pub operation_record_domains: Vec<String>,
    pub independent_domain_positions: bool,
    pub reset_discards_incomplete_assembly: bool,
    pub cross_domain_ordering: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalApiCompatibility {
    pub contract_id: String,
    pub minimum_version: String,
    pub maximum_version_exclusive: String,
    pub runtime_reference_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImplementationBoundary {
    pub shared_kernel_language: String,
    pub surfaces: BTreeSet<String>,
    pub typescript_business_kernel_allowed: bool,
    pub transport: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientKernelInvariants {
    pub surface_neutral: bool,
    pub complete_snapshot_streams: bool,
    pub ordered_within_epoch: bool,
    pub at_least_once_delivery: bool,
    pub unknown_frame_fail_closed: bool,
    pub gap_requires_reset: bool,
    pub authority_result_preserved: bool,
    pub client_never_becomes_authority: bool,
    pub operation_record_assembly_in_shared_kernel: bool,
    pub cross_domain_position_comparison_forbidden: bool,
    pub content_cannot_advance_authority_state: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentDisclosureProfile {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub profile_id: String,
    pub authority_ref: String,
    pub contract_bindings: HarnessContentContractBindings,
    pub source_admission: HarnessContentSourceAdmission,
    pub content_categories: HarnessContentCategories,
    pub message_protocol: HarnessContentMessageProtocol,
    pub canonical_encoding: HarnessContentCanonicalEncoding,
    pub text_safety: HarnessContentTextSafety,
    pub managed_credential_redaction: HarnessContentManagedCredentialRedaction,
    pub resource_limits: HarnessContentResourceLimits,
    pub recovery_and_retention: HarnessContentRecoveryAndRetention,
    pub authorization: HarnessContentAuthorization,
    pub fixture_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentContractBindings {
    pub harness_contract_id: String,
    pub local_api_contract_id: String,
    pub capability_field: String,
    pub permission_code: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentSourceAdmission {
    pub required_delivery_disposition: String,
    pub candidate_identity_source: String,
    pub context_proof_branches: Vec<String>,
    pub missing_route_binding: String,
    pub legacy_dispatch: String,
    pub provider_capability_required: bool,
    pub unknown_oneof: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentCategories {
    pub allowed: Vec<String>,
    pub forbidden: Vec<String>,
    pub unknown_category: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentMessageProtocol {
    pub operations: Vec<String>,
    pub revision_starts_at: u64,
    pub same_revision_same_digest: String,
    pub same_revision_different_digest: String,
    pub revision_gap: String,
    pub invalid_predecessor: String,
    pub second_finalize: String,
    pub update_after_finalize: String,
    pub replace_matcher_state: String,
    pub finalize_matcher_state: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentCanonicalEncoding {
    pub digest_algorithm: String,
    pub digest_output: String,
    pub length_prefix: String,
    pub integer_encoding: String,
    pub signed_integer_encoding: String,
    pub uint32_encoding: String,
    pub boolean_encoding: String,
    pub string_encoding: String,
    pub enum_encoding: String,
    pub optional_encoding: String,
    pub collection_encoding: String,
    pub timestamp_encoding: String,
    pub catalog_snapshot_kinds: HarnessContentCatalogSnapshotKinds,
    pub context_proof_canonicalization: HarnessContentContextProofCanonicalization,
    pub candidate_payload_discriminators: HarnessContentCandidatePayloadDiscriminators,
    pub safe_payload_discriminators: HarnessContentSafePayloadDiscriminators,
    pub projection_event_discriminators: HarnessContentProjectionEventDiscriminators,
    pub identifier_formats: HarnessContentIdentifierFormats,
    pub digest_rules: HarnessContentDigestRules,
    pub domain_separators: HarnessContentDomainSeparators,
    pub route_binding_field_order: Vec<String>,
    pub text_payload_field_order: Vec<String>,
    pub raw_cumulative_field_order: Vec<String>,
    pub safe_cumulative_field_order: Vec<String>,
    pub safe_message_id_field_order: Vec<String>,
    pub text_candidate_field_order: Vec<String>,
    pub lifecycle_candidate_field_order: Vec<String>,
    pub usage_candidate_field_order: Vec<String>,
    pub approval_required_candidate_field_order: Vec<String>,
    pub blocked_source_candidate_field_order: Vec<String>,
    pub content_event_id_field_order: Vec<String>,
    pub safe_record_id_field_order: Vec<String>,
    pub safe_record_field_order: Vec<String>,
    pub safe_assistant_text_field_order: Vec<String>,
    pub safe_lifecycle_field_order: Vec<String>,
    pub safe_usage_field_order: Vec<String>,
    pub safe_approval_required_field_order: Vec<String>,
    pub safe_artifact_relation_field_order: Vec<String>,
    pub safe_marker_field_order: Vec<String>,
    pub history_compaction_record_id_field_order: Vec<String>,
    pub history_compaction_record_field_order: Vec<String>,
    pub retention_tombstone_id_field_order: Vec<String>,
    pub retention_tombstone_field_order: Vec<String>,
    pub credential_commitment_field_order: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentCatalogSnapshotKinds {
    pub digest: String,
    pub no_catalog: String,
    pub no_catalog_value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentContextProofCanonicalization {
    pub not_context_bound_branch: String,
    pub not_context_bound_authorization_id: String,
    pub not_context_bound_request_digest_sha256: String,
    pub authorized_context_branch: String,
    pub authorized_context_requires_authorization_id: bool,
    pub authorized_context_requires_request_digest_sha256: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentCandidatePayloadDiscriminators {
    pub assistant_text: String,
    pub lifecycle: String,
    pub usage: String,
    pub approval_required: String,
    pub blocked_source: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentSafePayloadDiscriminators {
    pub assistant_text: String,
    pub lifecycle: String,
    pub usage: String,
    pub approval_required: String,
    pub artifact_relation: String,
    pub marker: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentProjectionEventDiscriminators {
    pub content_record: String,
    pub history_compaction: String,
    pub retention_tombstone: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentIdentifierFormats {
    pub safe_message_id: String,
    pub safe_record_id: String,
    pub history_compaction_record_id: String,
    pub retention_tombstone_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentDigestRules {
    pub candidate_digest: String,
    pub safe_payload_digest: String,
    pub safe_record_digest: String,
    pub history_compaction_digest: String,
    pub retention_tombstone_digest: String,
    pub safety_flags: String,
    pub non_text_part_index_for_record_id: u64,
    pub non_limit_record_id_limit_kind: String,
    pub limit_marker_invariant: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentDomainSeparators {
    pub route_binding: String,
    pub text_payload: String,
    pub raw_cumulative: String,
    pub safe_cumulative: String,
    pub safe_message_id: String,
    pub text_candidate: String,
    pub lifecycle_candidate: String,
    pub usage_candidate: String,
    pub approval_required_candidate: String,
    pub blocked_source_candidate: String,
    pub content_event: String,
    pub safe_record_id: String,
    pub safe_record: String,
    pub safe_assistant_text: String,
    pub safe_lifecycle: String,
    pub safe_usage: String,
    pub safe_approval_required: String,
    pub safe_artifact_relation: String,
    pub safe_marker: String,
    pub history_compaction_record_id: String,
    pub history_compaction_record: String,
    pub retention_tombstone_id: String,
    pub retention_tombstone: String,
    pub credential_commitment: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentTextSafety {
    pub invalid_utf8: String,
    pub newline_normalization: String,
    pub tab_replacement_spaces: u64,
    pub unicode_line_separators_to_lf: Vec<String>,
    pub replacement_scalar: String,
    pub c0_allowed: Vec<String>,
    pub replace_del: bool,
    pub replace_c1: bool,
    pub bidi_control_scalars: Vec<String>,
    pub ansi_interpretation: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentManagedCredentialRedaction {
    pub credential_mode: String,
    pub max_non_empty_values: u64,
    pub max_value_bytes: u64,
    pub value_encoding: String,
    pub variants: Vec<String>,
    pub max_encoded_pattern_bytes: u64,
    pub max_withheld_suffix_bytes: u64,
    pub matcher: String,
    pub commitment: String,
    pub persisted_secret_material: String,
    pub oversize_behavior: String,
    pub restart_mismatch_behavior: String,
    pub harness_account_guarantee: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentResourceLimits {
    pub candidate_text_bytes: u64,
    pub safe_part_bytes: u64,
    pub serialized_frame_bytes: u64,
    pub attempt_safe_text_bytes: u64,
    pub attempt_safe_records: u64,
    pub task_safe_text_bytes: u64,
    pub task_safe_records: u64,
    pub baseline_page_records: u64,
    pub baseline_page_text_bytes: u64,
    pub reserved_final_record_slot: String,
    pub simultaneous_limit_precedence: Vec<String>,
    pub terminal_scopes: String,
    pub byte_accounting: String,
    pub pagination_whole_records_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentRecoveryAndRetention {
    pub projection_domain: String,
    pub delivery: String,
    pub stable_identity: String,
    pub rebuild_source: String,
    pub rerun_redaction_on_replay: bool,
    pub profile_change: String,
    pub minimum_seconds_after_task_terminal: u64,
    pub compaction: String,
    pub tombstone_prevents_resurrection: bool,
    pub unknown_gap: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessContentAuthorization {
    pub permission_code: String,
    pub scope_source: String,
    pub revalidate_after_send_reservation: bool,
    pub max_frames_in_flight: u64,
    pub post_change_exposure_frames: u64,
    pub artifact_identity_permission_code: String,
    pub failure_isolation: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationProfile {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_version: String,
    pub authority_ref: String,
    pub local_api_contract_id: String,
    pub defaults: AuthorizationDefaults,
    pub permissions: Vec<PermissionDefinition>,
    pub rpc_rules: Vec<RpcRule>,
    pub command_rules: Vec<CommandRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationDefaults {
    pub unknown_permission: String,
    pub unknown_rpc: String,
    pub unknown_command_oneof: String,
    pub surface_neutral: bool,
    pub session_grant_is_final_authorization: bool,
    pub owning_authority_revalidation_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionDefinition {
    pub code: String,
    pub kind: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RpcAccess {
    AuthenticatedPeerBootstrap,
    GrantedPermission,
    PerCommandOneof,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RpcRule {
    pub rpc: String,
    pub access: RpcAccess,
    pub required_permission_codes: Vec<String>,
    #[serde(default)]
    pub token_scope_enforced: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CommandAccess {
    User,
    SystemOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationClass {
    None,
    AuthorityContract,
    FullSemanticDigest,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandRule {
    pub rpc: String,
    pub oneof: String,
    pub access: CommandAccess,
    pub required_permission_codes: Vec<String>,
    pub confirmation_class: ConfirmationClass,
    pub write_owner: String,
    pub required_authority_principal_kinds: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ContractProfiles {
    pub client_kernel: ClientKernelProfile,
    pub authorization: AuthorizationProfile,
    pub harness_content_disclosure: HarnessContentDisclosureProfile,
    permission_codes: BTreeSet<String>,
    rpc_rules: BTreeMap<String, RpcRule>,
    command_rules: BTreeMap<(String, String), CommandRule>,
}

impl ContractProfiles {
    pub fn embedded() -> Result<Self, ContractProfileError> {
        verify_digest(
            CLIENT_KERNEL_PROFILE_BYTES,
            CLIENT_KERNEL_PROFILE_DIGEST_SHA256,
        )?;
        verify_digest(
            AUTHORIZATION_PROFILE_BYTES,
            AUTHORIZATION_PROFILE_DIGEST_SHA256,
        )?;
        verify_digest(
            HARNESS_CONTENT_DISCLOSURE_PROFILE_BYTES,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
        )?;
        let client_kernel: ClientKernelProfile =
            serde_json::from_slice(CLIENT_KERNEL_PROFILE_BYTES)
                .map_err(|_| ContractProfileError::Invalid("client_kernel"))?;
        let authorization: AuthorizationProfile =
            serde_json::from_slice(AUTHORIZATION_PROFILE_BYTES)
                .map_err(|_| ContractProfileError::Invalid("authorization"))?;
        let harness_content_disclosure: HarnessContentDisclosureProfile =
            serde_json::from_slice(HARNESS_CONTENT_DISCLOSURE_PROFILE_BYTES)
                .map_err(|_| ContractProfileError::Invalid("harness_content_disclosure"))?;
        validate_client_kernel_profile(&client_kernel)?;
        validate_authorization_profile(client_kernel.contract_id.as_str(), &authorization)?;
        validate_harness_content_disclosure_profile(&harness_content_disclosure)?;

        let mut permission_codes = BTreeSet::new();
        for permission in &authorization.permissions {
            if permission.code.is_empty()
                || !permission_codes.insert(permission.code.clone())
                || !matches!(permission.kind.as_str(), "read" | "write")
                || permission.description.is_empty()
            {
                return Err(ContractProfileError::Invalid("authorization_permissions"));
            }
        }

        let mut rpc_rules = BTreeMap::new();
        for rule in &authorization.rpc_rules {
            validate_permission_references(&permission_codes, &rule.required_permission_codes)?;
            if rule.rpc.is_empty() || rpc_rules.insert(rule.rpc.clone(), rule.clone()).is_some() {
                return Err(ContractProfileError::Invalid("authorization_rpc_rules"));
            }
        }
        validate_harness_content_authorization(
            &authorization,
            &harness_content_disclosure,
            &rpc_rules,
        )?;

        let mut command_rules = BTreeMap::new();
        for rule in &authorization.command_rules {
            validate_permission_references(&permission_codes, &rule.required_permission_codes)?;
            if rule.rpc.is_empty()
                || rule.oneof.is_empty()
                || rule.write_owner.is_empty()
                || rule.required_authority_principal_kinds.is_empty()
                || command_rules
                    .insert((rule.rpc.clone(), rule.oneof.clone()), rule.clone())
                    .is_some()
            {
                return Err(ContractProfileError::Invalid("authorization_command_rules"));
            }
        }

        Ok(Self {
            client_kernel,
            authorization,
            harness_content_disclosure,
            permission_codes,
            rpc_rules,
            command_rules,
        })
    }

    #[must_use]
    pub fn permission_codes(&self) -> &BTreeSet<String> {
        &self.permission_codes
    }

    pub fn authorize_rpc(
        &self,
        rpc: &str,
        granted: &BTreeSet<String>,
    ) -> Result<(), ContractProfileError> {
        self.validate_grants(granted)?;
        let rule = self
            .rpc_rules
            .get(rpc)
            .ok_or_else(|| ContractProfileError::UnknownRpc(rpc.to_owned()))?;
        if rule.access != RpcAccess::GrantedPermission {
            return Err(ContractProfileError::WrongAuthorizationPath(rpc.to_owned()));
        }
        require_permissions(granted, &rule.required_permission_codes)
    }

    pub fn authorize_command(
        &self,
        rpc: &str,
        oneof: &str,
        granted: &BTreeSet<String>,
    ) -> Result<AuthorizedCommand, ContractProfileError> {
        self.validate_grants(granted)?;
        let rpc_rule = self
            .rpc_rules
            .get(rpc)
            .ok_or_else(|| ContractProfileError::UnknownRpc(rpc.to_owned()))?;
        if rpc_rule.access != RpcAccess::PerCommandOneof {
            return Err(ContractProfileError::WrongAuthorizationPath(rpc.to_owned()));
        }
        let rule = self
            .command_rules
            .get(&(rpc.to_owned(), oneof.to_owned()))
            .ok_or_else(|| ContractProfileError::UnknownCommandOneof {
                rpc: rpc.to_owned(),
                oneof: oneof.to_owned(),
            })?;
        if rule.access == CommandAccess::SystemOnly {
            return Err(ContractProfileError::SystemOnlyCommand {
                rpc: rpc.to_owned(),
                oneof: oneof.to_owned(),
            });
        }
        require_permissions(granted, &rule.required_permission_codes)?;
        Ok(AuthorizedCommand {
            write_owner: rule.write_owner.clone(),
            confirmation_class: rule.confirmation_class,
            required_authority_principal_kinds: rule.required_authority_principal_kinds.clone(),
        })
    }

    fn validate_grants(&self, granted: &BTreeSet<String>) -> Result<(), ContractProfileError> {
        for permission in granted {
            if !self.permission_codes.contains(permission) {
                return Err(ContractProfileError::UnknownPermission(permission.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCommand {
    pub write_owner: String,
    pub confirmation_class: ConfirmationClass,
    pub required_authority_principal_kinds: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ContractProfileError {
    #[error("embedded contract profile is invalid: {0}")]
    Invalid(&'static str),
    #[error("embedded contract profile digest does not match the frozen manifest")]
    DigestMismatch,
    #[error("permission is unknown: {0}")]
    UnknownPermission(String),
    #[error("required permission is missing: {0}")]
    PermissionDenied(String),
    #[error("RPC is unknown: {0}")]
    UnknownRpc(String),
    #[error("RPC requires a different authorization path: {0}")]
    WrongAuthorizationPath(String),
    #[error("command oneof is unknown: {rpc}/{oneof}")]
    UnknownCommandOneof { rpc: String, oneof: String },
    #[error("command is system-only: {rpc}/{oneof}")]
    SystemOnlyCommand { rpc: String, oneof: String },
}

fn verify_digest(payload: &[u8], expected: &str) -> Result<(), ContractProfileError> {
    if hex::encode(Sha256::digest(payload)) == expected {
        Ok(())
    } else {
        Err(ContractProfileError::DigestMismatch)
    }
}

fn validate_client_kernel_profile(
    profile: &ClientKernelProfile,
) -> Result<(), ContractProfileError> {
    let required_capabilities = [
        "session_negotiation",
        "query",
        "list",
        "watch_complete_snapshots",
        "await_projection",
        "typed_command",
        "stable_cursor",
        "reset_and_refetch",
        "read_your_write",
        "typed_error",
        "frame_deduplication",
        "memory_retrieval",
        "governed_memory_work_preparation",
        "context_revoke_full_digest_confirmation",
        "content_baseline_pagination",
        "watch_operation_records",
        "content_generation_fencing",
    ];
    if profile.schema_version != "egopulse.client-kernel-profile/v0.1"
        || profile.contract_id != CLIENT_KERNEL_CONTRACT_ID
        || profile.contract_version != CLIENT_KERNEL_CONTRACT_VERSION
        || profile.authority_ref != M13_PROFILE_AUTHORITY_REF
        || profile.local_api_compatibility.contract_id != API_CONTRACT_ID
        || !profile.local_api_compatibility.runtime_reference_required
        || profile.local_api_compatibility.minimum_version != API_CONTRACT_VERSION
        || profile.local_api_compatibility.maximum_version_exclusive != "0.2.0"
        || profile.implementation_boundary.shared_kernel_language != "rust"
        || profile
            .implementation_boundary
            .typescript_business_kernel_allowed
        || profile.implementation_boundary.transport
            != "tonic_grpc_http2_semantics_over_named_pipe_or_uds_no_tcp"
        || profile.implementation_boundary.surfaces.len() != 3
        || !profile.implementation_boundary.surfaces.contains("cli")
        || !profile.implementation_boundary.surfaces.contains("tui")
        || !profile
            .implementation_boundary
            .surfaces
            .iter()
            .any(|surface| surface.starts_with("desktop_"))
        || profile.capabilities.len() != required_capabilities.len()
        || required_capabilities
            .iter()
            .any(|value| !profile.capabilities.contains(*value))
        || !exact_strings(
            &profile.stream_semantics.complete_snapshot_domains,
            &["task_views", "harness_approval_views"],
        )
        || !exact_strings(
            &profile.stream_semantics.operation_record_domains,
            &["harness_content"],
        )
        || !profile.stream_semantics.independent_domain_positions
        || !profile.stream_semantics.reset_discards_incomplete_assembly
        || profile.stream_semantics.cross_domain_ordering != "forbidden"
        || !profile.invariants.surface_neutral
        || !profile.invariants.complete_snapshot_streams
        || !profile.invariants.ordered_within_epoch
        || !profile.invariants.at_least_once_delivery
        || !profile.invariants.unknown_frame_fail_closed
        || !profile.invariants.gap_requires_reset
        || !profile.invariants.authority_result_preserved
        || !profile.invariants.client_never_becomes_authority
        || !profile
            .invariants
            .operation_record_assembly_in_shared_kernel
        || !profile
            .invariants
            .cross_domain_position_comparison_forbidden
        || !profile.invariants.content_cannot_advance_authority_state
    {
        return Err(ContractProfileError::Invalid("client_kernel_invariants"));
    }
    Ok(())
}

fn validate_authorization_profile(
    client_kernel_contract_id: &str,
    profile: &AuthorizationProfile,
) -> Result<(), ContractProfileError> {
    let defaults = &profile.defaults;
    if client_kernel_contract_id != CLIENT_KERNEL_CONTRACT_ID
        || profile.schema_version != "egopulse.authorization-capability-profile/v0.1"
        || profile.contract_id != AUTHORIZATION_CONTRACT_ID
        || profile.contract_version != AUTHORIZATION_CONTRACT_VERSION
        || profile.authority_ref != M13_PROFILE_AUTHORITY_REF
        || profile.local_api_contract_id != API_CONTRACT_ID
        || defaults.unknown_permission != "fail_closed"
        || defaults.unknown_rpc != "fail_closed"
        || defaults.unknown_command_oneof != "fail_closed"
        || !defaults.surface_neutral
        || defaults.session_grant_is_final_authorization
        || !defaults.owning_authority_revalidation_required
    {
        return Err(ContractProfileError::Invalid("authorization_defaults"));
    }
    Ok(())
}

fn harness_content_canonical_encoding_is_exact(encoding: &HarnessContentCanonicalEncoding) -> bool {
    let catalog = &encoding.catalog_snapshot_kinds;
    let context = &encoding.context_proof_canonicalization;
    let candidate = &encoding.candidate_payload_discriminators;
    let safe = &encoding.safe_payload_discriminators;
    let projection = &encoding.projection_event_discriminators;
    let identifiers = &encoding.identifier_formats;
    let rules = &encoding.digest_rules;
    let separators = &encoding.domain_separators;

    encoding.signed_integer_encoding == "i64_little_endian"
        && encoding.uint32_encoding == "u32_little_endian"
        && encoding.boolean_encoding == "u64_little_endian_zero_or_one"
        && encoding.enum_encoding == "canonical_short_name_utf8"
        && encoding.optional_encoding == "presence_NONE_or_SOME_utf8_then_empty_or_encoded_value"
        && encoding.collection_encoding == "count_u64_then_each_value_in_declared_order"
        && encoding.timestamp_encoding
            == "seconds_i64_little_endian_then_nanos_u32_little_endian_each_framed"
        && catalog.digest == "DIGEST"
        && catalog.no_catalog == "NO_CATALOG"
        && catalog.no_catalog_value.is_empty()
        && context.not_context_bound_branch == "NOT_CONTEXT_BOUND"
        && context.not_context_bound_authorization_id.is_empty()
        && context.not_context_bound_request_digest_sha256.is_empty()
        && context.authorized_context_branch == "AUTHORIZED_CONTEXT"
        && context.authorized_context_requires_authorization_id
        && context.authorized_context_requires_request_digest_sha256
        && candidate.assistant_text == "ASSISTANT_TEXT"
        && candidate.lifecycle == "LIFECYCLE"
        && candidate.usage == "USAGE"
        && candidate.approval_required == "APPROVAL_REQUIRED"
        && candidate.blocked_source == "BLOCKED_SOURCE"
        && safe.assistant_text == "ASSISTANT_TEXT"
        && safe.lifecycle == "LIFECYCLE"
        && safe.usage == "USAGE"
        && safe.approval_required == "APPROVAL_REQUIRED"
        && safe.artifact_relation == "ARTIFACT_RELATION"
        && safe.marker == "MARKER"
        && projection.content_record == "CONTENT_RECORD"
        && projection.history_compaction == "HISTORY_COMPACTION"
        && projection.retention_tombstone == "RETENTION_TOMBSTONE"
        && identifiers.safe_message_id == "hcm_<lowercase_hex_64>"
        && identifiers.safe_record_id == "hcr_<lowercase_hex_64>"
        && identifiers.history_compaction_record_id == "hcc_<lowercase_hex_64>"
        && identifiers.retention_tombstone_id == "hrt_<lowercase_hex_64>"
        && rules.candidate_digest == "sha256_of_selected_candidate_payload_canonical_bytes"
        && rules.safe_payload_digest == "sha256_of_selected_safe_payload_canonical_bytes"
        && rules.safe_record_digest
            == "sha256_of_safe_record_canonical_bytes_excluding_record_digest_sha256"
        && rules.history_compaction_digest
            == "sha256_of_history_compaction_canonical_bytes_excluding_compaction_record_digest_sha256"
        && rules.retention_tombstone_digest
            == "sha256_of_retention_tombstone_canonical_bytes_excluding_tombstone_digest_sha256"
        && rules.safety_flags == "ascending_numeric_unique"
        && rules.non_text_part_index_for_record_id == 0
        && rules.non_limit_record_id_limit_kind == "UNSPECIFIED"
        && rules.limit_marker_invariant
            == "LIMIT_REACHED_requires_typed_limit_kind_non_limit_markers_require_UNSPECIFIED"
        && separators.safe_cumulative == "egopulse/harness-content/safe-cumulative/v1"
        && separators.safe_message_id == "egopulse/harness-content/safe-message-id/v1"
        && separators.lifecycle_candidate == "egopulse/harness-content/lifecycle-candidate/v1"
        && separators.usage_candidate == "egopulse/harness-content/usage-candidate/v1"
        && separators.approval_required_candidate
            == "egopulse/harness-content/approval-required-candidate/v1"
        && separators.blocked_source_candidate
            == "egopulse/harness-content/blocked-source-candidate/v1"
        && separators.safe_record_id == "egopulse/harness-content/safe-record-id/v1"
        && separators.safe_assistant_text == "egopulse/harness-content/safe-assistant-text/v1"
        && separators.safe_lifecycle == "egopulse/harness-content/safe-lifecycle/v1"
        && separators.safe_usage == "egopulse/harness-content/safe-usage/v1"
        && separators.safe_approval_required == "egopulse/harness-content/safe-approval-required/v1"
        && separators.safe_artifact_relation == "egopulse/harness-content/safe-artifact-relation/v1"
        && separators.safe_marker == "egopulse/harness-content/safe-marker/v1"
        && separators.history_compaction_record_id
            == "egopulse/harness-content/history-compaction-id/v1"
        && separators.history_compaction_record == "egopulse/harness-content/history-compaction/v1"
        && separators.retention_tombstone_id == "egopulse/harness-content/retention-tombstone-id/v1"
        && separators.retention_tombstone == "egopulse/harness-content/retention-tombstone/v1"
        && exact_strings(
            &encoding.safe_cumulative_field_order,
            &["domain_separator", "safe_cumulative_text_utf8"],
        )
        && exact_strings(
            &encoding.safe_message_id_field_order,
            &[
                "domain_separator",
                "attempt_id",
                "dispatch_id",
                "route_binding_sha256",
                "candidate_message_id",
            ],
        )
        && exact_strings(
            &encoding.lifecycle_candidate_field_order,
            &[
                "domain_separator",
                "lifecycle_kind",
                "side_effect_certainty",
                "native_will_retry_presence",
                "native_will_retry_value",
            ],
        )
        && exact_strings(
            &encoding.usage_candidate_field_order,
            &[
                "domain_separator",
                "input_tokens",
                "output_tokens",
                "cached_input_tokens_presence",
                "cached_input_tokens_value",
            ],
        )
        && exact_strings(
            &encoding.approval_required_candidate_field_order,
            &["domain_separator"],
        )
        && exact_strings(
            &encoding.blocked_source_candidate_field_order,
            &["domain_separator", "marker_kind"],
        )
        && exact_strings(
            &encoding.safe_record_id_field_order,
            &[
                "domain_separator",
                "content_event_id",
                "disclosure_profile_contract_id",
                "disclosure_profile_version",
                "disclosure_profile_sha256",
                "payload_discriminator",
                "limit_kind",
                "part_index",
            ],
        )
        && exact_strings(
            &encoding.safe_record_field_order,
            &[
                "domain_separator",
                "record_id",
                "content_event_id",
                "task_id",
                "run_id",
                "step_id",
                "attempt_id",
                "dispatch_id",
                "fencing_token",
                "route_binding_sha256",
                "disclosure_profile_contract_id",
                "disclosure_profile_version",
                "disclosure_profile_sha256",
                "provider_family_alias",
                "model_alias",
                "collaboration_role",
                "safety_flags_count",
                "safety_flags_ascending_numeric",
                "payload_discriminator",
                "payload_digest_sha256",
            ],
        )
        && exact_strings(
            &encoding.safe_assistant_text_field_order,
            &[
                "domain_separator",
                "safe_message_id",
                "revision",
                "previous_revision",
                "operation",
                "safe_text_utf8",
                "safe_cumulative_digest_sha256",
                "part_index",
                "part_count",
            ],
        )
        && exact_strings(
            &encoding.safe_lifecycle_field_order,
            &[
                "domain_separator",
                "lifecycle_kind",
                "side_effect_certainty",
                "native_will_retry_presence",
                "native_will_retry_value",
            ],
        )
        && exact_strings(
            &encoding.safe_usage_field_order,
            &[
                "domain_separator",
                "input_tokens",
                "output_tokens",
                "cached_input_tokens_presence",
                "cached_input_tokens_value",
            ],
        )
        && exact_strings(
            &encoding.safe_approval_required_field_order,
            &["domain_separator"],
        )
        && exact_strings(
            &encoding.safe_artifact_relation_field_order,
            &[
                "domain_separator",
                "safe_content_differs_from_artifact",
                "artifact_id",
                "artifact_digest_sha256",
            ],
        )
        && exact_strings(
            &encoding.safe_marker_field_order,
            &["domain_separator", "marker_kind", "limit_kind"],
        )
        && exact_strings(
            &encoding.history_compaction_record_id_field_order,
            &[
                "domain_separator",
                "task_id",
                "attempt_id",
                "final_epoch",
                "final_sequence",
                "disclosure_profile_sha256",
                "reason",
            ],
        )
        && exact_strings(
            &encoding.history_compaction_record_field_order,
            &[
                "domain_separator",
                "compaction_record_id",
                "task_id",
                "attempt_id",
                "final_epoch",
                "final_sequence",
                "final_safe_content_digest_sha256",
                "owner_snapshot_digest_sha256",
                "disclosure_profile_contract_id",
                "disclosure_profile_version",
                "disclosure_profile_sha256",
                "compacted_at_seconds",
                "compacted_at_nanos",
                "reason",
            ],
        )
        && exact_strings(
            &encoding.retention_tombstone_id_field_order,
            &[
                "domain_separator",
                "task_id",
                "attempt_id",
                "final_epoch",
                "final_sequence",
                "disclosure_profile_sha256",
                "reason",
            ],
        )
        && exact_strings(
            &encoding.retention_tombstone_field_order,
            &[
                "domain_separator",
                "tombstone_id",
                "task_id",
                "attempt_id",
                "final_epoch",
                "final_sequence",
                "final_safe_content_digest_sha256",
                "disclosure_profile_contract_id",
                "disclosure_profile_version",
                "disclosure_profile_sha256",
                "terminal_committed_at_seconds",
                "terminal_committed_at_nanos",
                "compacted_at_seconds",
                "compacted_at_nanos",
                "reason",
            ],
        )
        && exact_strings(
            &encoding.credential_commitment_field_order,
            &[
                "domain_separator",
                "variant_value_count",
                "variant_values_sorted_unsigned_byte_lexicographic",
            ],
        )
}

fn validate_harness_content_disclosure_profile(
    profile: &HarnessContentDisclosureProfile,
) -> Result<(), ContractProfileError> {
    let bindings = &profile.contract_bindings;
    let admission = &profile.source_admission;
    let categories = &profile.content_categories;
    let protocol = &profile.message_protocol;
    let encoding = &profile.canonical_encoding;
    let separators = &encoding.domain_separators;
    let text = &profile.text_safety;
    let credentials = &profile.managed_credential_redaction;
    let limits = &profile.resource_limits;
    let recovery = &profile.recovery_and_retention;
    let authorization = &profile.authorization;

    if profile.schema_version != "egopulse.harness-content-disclosure-profile/v0.1"
        || profile.contract_id != HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        || profile.contract_version != HARNESS_CONTENT_DISCLOSURE_CONTRACT_VERSION
        || profile.profile_id != HARNESS_CONTENT_DISCLOSURE_PROFILE_ID
        || profile.authority_ref != R9C_PROFILE_AUTHORITY_REF
        || bindings.harness_contract_id != "egopulse.harness.v1"
        || bindings.local_api_contract_id != API_CONTRACT_ID
        || bindings.capability_field != "governed_user_visible_content"
        || bindings.permission_code != "local.harness.content.read"
        || admission.required_delivery_disposition != "DELIVERY_DISPOSITION_DELIVERED"
        || admission.candidate_identity_source != "trusted_stores_only"
        || !exact_strings(
            &admission.context_proof_branches,
            &["NOT_CONTEXT_BOUND", "AUTHORIZED_CONTEXT"],
        )
        || admission.missing_route_binding != "fail_closed_no_text_disclosure"
        || admission.legacy_dispatch != "never_backfill_from_current_configuration"
        || !admission.provider_capability_required
        || admission.unknown_oneof != "fail_closed"
        || !exact_strings(
            &categories.allowed,
            &[
                "assistant_text",
                "lifecycle_activity_code",
                "usage_counters",
                "approval_required_code",
                "final_artifact_relation",
                "redacted_marker",
                "blocked_marker",
                "truncated_marker",
                "content_domain_status_marker",
            ],
        )
        || !exact_strings(
            &categories.forbidden,
            &[
                "hidden_reasoning",
                "chain_of_thought",
                "system_prompt",
                "developer_prompt",
                "provider_request_payload",
                "context_source_field",
                "memory_source_field",
                "rag_query",
                "embedding",
                "proof",
                "source_reference",
                "tool_arguments",
                "tool_results",
                "command_stdout",
                "command_stderr",
                "ansi_or_terminal_control",
                "file_content",
                "workspace_path",
                "raw_native_event",
                "raw_evidence_reference",
                "native_routing_identifier",
                "native_session_identifier",
                "native_execution_identifier",
                "credential_or_token",
                "private_key",
                "environment_value",
                "secret_store_material",
                "unknown_category",
            ],
        )
        || categories.unknown_category != "blocked_marker_no_source_bytes"
        || !exact_strings(&protocol.operations, &["APPEND", "REPLACE", "FINALIZE"])
        || protocol.revision_starts_at != 1
        || protocol.same_revision_same_digest != "idempotent_no_op"
        || protocol.same_revision_different_digest != "quarantine_integrity_conflict"
        || protocol.revision_gap != "fail_closed"
        || protocol.invalid_predecessor != "fail_closed"
        || protocol.second_finalize != "fail_closed"
        || protocol.update_after_finalize != "fail_closed"
        || protocol.replace_matcher_state != "reset_from_complete_replacement"
        || protocol.finalize_matcher_state != "flush_non_secret_suffix"
        || !harness_content_canonical_encoding_is_exact(encoding)
        || encoding.digest_algorithm != "SHA-256"
        || encoding.digest_output != "lowercase_hex_64"
        || encoding.length_prefix != "u64_little_endian_byte_length"
        || encoding.integer_encoding != "u64_little_endian"
        || encoding.string_encoding != "utf8_no_normalization"
        || separators.route_binding != "egopulse/harness-content/route-binding/v1"
        || separators.text_payload != "egopulse/harness-content/text-payload/v1"
        || separators.raw_cumulative != "egopulse/harness-content/raw-cumulative/v1"
        || separators.text_candidate != "egopulse/harness-content/text-candidate/v1"
        || separators.content_event != "egopulse/harness-content/event/v1"
        || separators.safe_record != "egopulse/harness-content/safe-record/v1"
        || separators.credential_commitment != "egopulse/harness-content/credential-set/v1"
        || !exact_strings(
            &encoding.route_binding_field_order,
            &[
                "domain_separator",
                "provider_bootstrap_profile_id",
                "selected_harness_id",
                "provider_model_id",
                "catalog_snapshot_kind",
                "catalog_snapshot_value",
                "capability_profile_id",
            ],
        )
        || !exact_strings(
            &encoding.text_payload_field_order,
            &["domain_separator", "text_utf8"],
        )
        || !exact_strings(
            &encoding.raw_cumulative_field_order,
            &["domain_separator", "raw_cumulative_text_utf8"],
        )
        || !exact_strings(
            &encoding.text_candidate_field_order,
            &[
                "domain_separator",
                "message_id",
                "revision",
                "previous_revision",
                "operation",
                "text_utf8",
                "delta_or_snapshot_digest_sha256",
                "previous_raw_cumulative_digest_sha256",
                "raw_cumulative_digest_sha256",
            ],
        )
        || !exact_strings(
            &encoding.content_event_id_field_order,
            &[
                "domain_separator",
                "delivered_receipt_id",
                "delivered_receipt_digest_sha256",
                "context_proof_branch",
                "context_authorization_id",
                "context_authorization_request_digest_sha256",
                "dispatch_route_binding_sha256",
                "attempt_id",
                "dispatch_id",
                "fencing_token",
                "capability_profile_id",
                "native_event_id",
                "native_event_digest_sha256",
                "native_sequence",
                "candidate_digest_sha256",
            ],
        )
        || text.invalid_utf8 != "INVALID_TEXT_marker_no_text"
        || text.newline_normalization != "crlf_and_cr_to_lf"
        || text.tab_replacement_spaces != 4
        || !exact_strings(&text.unicode_line_separators_to_lf, &["U+2028", "U+2029"])
        || text.replacement_scalar != "U+FFFD"
        || !exact_strings(&text.c0_allowed, &["LF"])
        || !text.replace_del
        || !text.replace_c1
        || !exact_strings(
            &text.bidi_control_scalars,
            &[
                "U+061C",
                "U+200E",
                "U+200F",
                "U+202A-U+202E",
                "U+2066-U+2069",
            ],
        )
        || text.ansi_interpretation != "forbidden"
        || credentials.credential_mode != "api_key_environment"
        || credentials.max_non_empty_values != 32
        || credentials.max_value_bytes != 1_024
        || credentials.value_encoding != "printable_ascii"
        || !exact_strings(
            &credentials.variants,
            &[
                "raw_ascii",
                "canonical_json_content_escape",
                "canonical_percent_uppercase",
                "base64_standard_padded",
                "base64_standard_unpadded",
                "base64url_padded",
                "base64url_unpadded",
            ],
        )
        || credentials.max_encoded_pattern_bytes != 3_072
        || credentials.max_withheld_suffix_bytes != 3_071
        || credentials.matcher != "deterministic_streaming_multi_pattern_longest_match"
        || credentials.commitment != "domain_separated_hmac_sha256_from_adapter_store_key"
        || credentials.persisted_secret_material != "commitment_only"
        || credentials.oversize_behavior != "structured_only_attempt_execution_continues"
        || credentials.restart_mismatch_behavior
            != "REDACTION_INPUT_UNAVAILABLE_then_structured_only"
        || credentials.harness_account_guarantee
            != "forbidden_source_and_daemon_managed_secret_bytes_only"
        || limits.candidate_text_bytes != 65_536
        || limits.safe_part_bytes != 65_536
        || limits.serialized_frame_bytes != 81_920
        || limits.attempt_safe_text_bytes != 16_777_216
        || limits.attempt_safe_records != 16_384
        || limits.task_safe_text_bytes != 67_108_864
        || limits.task_safe_records != 65_536
        || limits.baseline_page_records != 256
        || limits.baseline_page_text_bytes != 1_048_576
        || limits.reserved_final_record_slot != "LIMIT_REACHED"
        || !exact_strings(
            &limits.simultaneous_limit_precedence,
            &[
                "TASK_RECORDS",
                "TASK_TEXT_BYTES",
                "ATTEMPT_RECORDS",
                "ATTEMPT_TEXT_BYTES",
            ],
        )
        || limits.terminal_scopes != "all_scopes_exhausted_by_admitted_prefix_and_marker"
        || limits.byte_accounting != "safe_normalized_redacted_utf8_before_proto"
        || !limits.pagination_whole_records_only
        || recovery.projection_domain != "independent_harness_content"
        || recovery.delivery != "at_least_once_idempotent"
        || recovery.stable_identity != "content_event_id_and_record_digest"
        || recovery.rebuild_source != "adapter_safe_ledger_or_owner_snapshot_only"
        || recovery.rerun_redaction_on_replay
        || recovery.profile_change
            != "new_epoch_reset_old_text_excluded_history_unavailable_tombstone"
        || recovery.minimum_seconds_after_task_terminal != 2_592_000
        || recovery.compaction != "owner_snapshot_floor_delete_and_typed_record_atomic"
        || !recovery.tombstone_prevents_resurrection
        || recovery.unknown_gap != "ResetRequired"
        || authorization.permission_code != "local.harness.content.read"
        || authorization.scope_source != "trusted_task_and_attempt_lineage"
        || !authorization.revalidate_after_send_reservation
        || authorization.max_frames_in_flight != 1
        || authorization.post_change_exposure_frames != 1
        || authorization.artifact_identity_permission_code != "local.evidence.read"
        || authorization.failure_isolation != "content_domain_only"
        || !exact_strings(
            &profile.fixture_refs,
            &[
                "fixtures/harness/v1/valid-content-append-not-context-bound.json",
                "fixtures/harness/v1/valid-content-authorized-context.json",
                "fixtures/harness/v1/valid-route-binding-no-catalog.json",
                "fixtures/harness/v1/invalid-content-forbidden-category.json",
                "fixtures/harness/v1/invalid-content-source-binding-drift.json",
                "fixtures/harness/v1/invalid-content-revision-digest-drift.json",
                "fixtures/harness/v1/duplicate-content-exact-replay.json",
                "fixtures/localapi/v1/valid-harness-content-baseline.json",
                "fixtures/localapi/v1/valid-harness-content-watch.json",
                "fixtures/localapi/v1/invalid-harness-content-frame-combination.json",
                "fixtures/localapi/v1/unauthorized-harness-content-read.json",
                "fixtures/localapi/v1/recovery-harness-content-retention-reset.json",
                "fixtures/persistence/v1/recovery-safe-content-outbox-after-consumer-commit.json",
            ],
        )
    {
        return Err(ContractProfileError::Invalid(
            "harness_content_disclosure_semantics",
        ));
    }
    Ok(())
}

fn validate_harness_content_authorization(
    authorization: &AuthorizationProfile,
    disclosure: &HarnessContentDisclosureProfile,
    rpc_rules: &BTreeMap<String, RpcRule>,
) -> Result<(), ContractProfileError> {
    const PERMISSION: &str = "local.harness.content.read";
    const RPCS: [&str; 2] = [
        "LocalReadModelService/ListHarnessContent",
        "LocalReadModelService/WatchHarnessContent",
    ];

    let permission = authorization
        .permissions
        .iter()
        .find(|permission| permission.code == PERMISSION);
    let permission_is_exact = permission.is_some_and(|permission| permission.kind == "read");
    let rpc_rules_are_exact = RPCS.iter().all(|rpc| {
        rpc_rules.get(*rpc).is_some_and(|rule| {
            rule.access == RpcAccess::GrantedPermission
                && exact_strings(&rule.required_permission_codes, &[PERMISSION])
                && !rule.token_scope_enforced
        })
    });
    let permission_rule_count = authorization
        .rpc_rules
        .iter()
        .filter(|rule| {
            rule.required_permission_codes
                .iter()
                .any(|code| code == PERMISSION)
        })
        .count();

    if authorization.authority_ref != M13_PROFILE_AUTHORITY_REF
        || disclosure.authority_ref != R9C_PROFILE_AUTHORITY_REF
        || disclosure.contract_bindings.permission_code != PERMISSION
        || disclosure.authorization.permission_code != PERMISSION
        || !permission_is_exact
        || !rpc_rules_are_exact
        || permission_rule_count != RPCS.len()
    {
        return Err(ContractProfileError::Invalid(
            "harness_content_authorization",
        ));
    }
    Ok(())
}

fn exact_strings(actual: &[String], expected: &[&str]) -> bool {
    actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn validate_permission_references(
    known: &BTreeSet<String>,
    required: &[String],
) -> Result<(), ContractProfileError> {
    let mut unique = BTreeSet::new();
    if required
        .iter()
        .any(|value| !known.contains(value) || !unique.insert(value))
    {
        return Err(ContractProfileError::Invalid("permission_reference"));
    }
    Ok(())
}

fn require_permissions(
    granted: &BTreeSet<String>,
    required: &[String],
) -> Result<(), ContractProfileError> {
    for permission in required {
        if !granted.contains(permission) {
            return Err(ContractProfileError::PermissionDenied(permission.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_profiles_are_the_single_fail_closed_interpreter() {
        let profiles = ContractProfiles::embedded().expect("frozen profiles load");
        let read = BTreeSet::from(["local.task.read".to_owned()]);
        profiles
            .authorize_rpc("LocalReadModelService/GetTaskView", &read)
            .expect("known read is authorized");
        assert!(matches!(
            profiles.authorize_rpc("LocalReadModelService/GetEvidenceGraph", &read),
            Err(ContractProfileError::PermissionDenied(permission))
                if permission == "local.evidence.read"
        ));
        assert!(matches!(
            profiles.authorize_rpc("LocalReadModelService/FutureRpc", &read),
            Err(ContractProfileError::UnknownRpc(_))
        ));
    }

    #[test]
    fn r9c_harness_content_profile_and_permission_are_exact_and_independent() {
        let profiles = ContractProfiles::embedded().expect("draft.22 profiles load");
        assert_eq!(API_CONTRACT_VERSION, "0.1.0-draft.22");
        assert_eq!(
            profiles.harness_content_disclosure.contract_id,
            HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
        );
        assert_eq!(
            profiles.harness_content_disclosure.profile_id,
            HARNESS_CONTENT_DISCLOSURE_PROFILE_ID
        );
        assert_eq!(
            profiles
                .client_kernel
                .stream_semantics
                .complete_snapshot_domains,
            ["task_views", "harness_approval_views"]
        );
        assert_eq!(
            profiles
                .client_kernel
                .stream_semantics
                .operation_record_domains,
            ["harness_content"]
        );
        assert!(profiles.client_kernel.invariants.complete_snapshot_streams);
        assert!(
            profiles
                .client_kernel
                .invariants
                .operation_record_assembly_in_shared_kernel
        );

        let content = BTreeSet::from(["local.harness.content.read".to_owned()]);
        for rpc in [
            "LocalReadModelService/ListHarnessContent",
            "LocalReadModelService/WatchHarnessContent",
        ] {
            profiles
                .authorize_rpc(rpc, &content)
                .expect("content permission authorizes its exact RPC");
        }
        assert!(matches!(
            profiles.authorize_rpc(
                "LocalReadModelService/ListHarnessContent",
                &BTreeSet::from(["local.task.read".to_owned()]),
            ),
            Err(ContractProfileError::PermissionDenied(permission))
                if permission == "local.harness.content.read"
        ));
        assert!(matches!(
            profiles.authorize_rpc("LocalReadModelService/GetTaskView", &content),
            Err(ContractProfileError::PermissionDenied(permission))
                if permission == "local.task.read"
        ));

        let content_rules = profiles
            .authorization
            .rpc_rules
            .iter()
            .filter(|rule| {
                rule.required_permission_codes == ["local.harness.content.read".to_owned()]
            })
            .map(|rule| rule.rpc.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            content_rules,
            BTreeSet::from([
                "LocalReadModelService/ListHarnessContent",
                "LocalReadModelService/WatchHarnessContent",
            ])
        );
    }

    #[test]
    fn context_revoke_is_surface_neutral_founder_owned_and_fail_closed() {
        let profiles = ContractProfiles::embedded().expect("frozen profiles load");
        assert!(profiles.client_kernel.invariants.surface_neutral);
        assert!(
            profiles
                .client_kernel
                .implementation_boundary
                .surfaces
                .contains("cli")
        );
        assert!(
            profiles
                .client_kernel
                .implementation_boundary
                .surfaces
                .contains("tui")
        );

        let granted = BTreeSet::from(["local.context.revoke".to_owned()]);
        let authorized = profiles
            .authorize_command(
                "LocalCommandGatewayService/ExecuteContextMutation",
                "revoke_context_snapshot",
                &granted,
            )
            .expect("Founder Context revoke is authorized");
        assert_eq!(authorized.write_owner, "ContextAuthority");
        assert_eq!(
            authorized.confirmation_class,
            ConfirmationClass::FullSemanticDigest
        );
        assert_eq!(
            authorized.required_authority_principal_kinds,
            ["ContextAuthority.Founder"]
        );

        assert!(matches!(
            profiles.authorize_command(
                "LocalCommandGatewayService/ExecuteContextMutation",
                "revoke_context_snapshot",
                &BTreeSet::new(),
            ),
            Err(ContractProfileError::PermissionDenied(permission))
                if permission == "local.context.revoke"
        ));
        assert!(matches!(
            profiles.authorize_command(
                "LocalCommandGatewayService/ExecuteContextMutation",
                "future_context_mutation",
                &granted,
            ),
            Err(ContractProfileError::UnknownCommandOneof { .. })
        ));
    }
}
