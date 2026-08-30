//! Shared parsing and fail-closed interpretation of frozen client/API profiles.
//!
//! This module is deliberately owned by the common contract boundary so local
//! clients and services cannot drift into separate authorization rule sets.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const API_CONTRACT_ID: &str = "egopulse.localapi.v1";
pub const API_CONTRACT_VERSION: &str = "0.1.0-draft.18";
pub const API_CONTRACT_DIGEST_SHA256: &str =
    "63cb39b13ca4fdce5b0cca524c8cc6496edf18758bbe5066cd920bdca9848460";
pub const CLIENT_KERNEL_CONTRACT_ID: &str = "egopulse.client-kernel.v1";
pub const CLIENT_KERNEL_CONTRACT_VERSION: &str = "0.1.0";
pub const CLIENT_KERNEL_PROFILE_DIGEST_SHA256: &str =
    "c729726c718a6f49c45e74a0f7435aa0974748661461f4be0e1315b838b17fa4";
pub const AUTHORIZATION_CONTRACT_ID: &str = "egopulse.authorization.v1";
pub const AUTHORIZATION_CONTRACT_VERSION: &str = "0.1.0";
pub const AUTHORIZATION_PROFILE_DIGEST_SHA256: &str =
    "e44e1cee143b35173372b75fa7ce4efb5732be58bb787d59e961450599d612ab";

const CLIENT_KERNEL_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/client-kernel/v1/v01-default.json");
const AUTHORIZATION_PROFILE_BYTES: &[u8] =
    include_bytes!("../../../contracts/profiles/authorization/v1/v01-default.json");

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
    pub invariants: ClientKernelInvariants,
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
        let client_kernel: ClientKernelProfile =
            serde_json::from_slice(CLIENT_KERNEL_PROFILE_BYTES)
                .map_err(|_| ContractProfileError::Invalid("client_kernel"))?;
        let authorization: AuthorizationProfile =
            serde_json::from_slice(AUTHORIZATION_PROFILE_BYTES)
                .map_err(|_| ContractProfileError::Invalid("authorization"))?;
        validate_client_kernel_profile(&client_kernel)?;
        validate_authorization_profile(client_kernel.contract_id.as_str(), &authorization)?;

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
        "context_revoke_full_digest_confirmation",
    ];
    if profile.schema_version != "egopulse.client-kernel-profile/v0.1"
        || profile.contract_id != CLIENT_KERNEL_CONTRACT_ID
        || profile.contract_version != CLIENT_KERNEL_CONTRACT_VERSION
        || profile.authority_ref.is_empty()
        || profile.local_api_compatibility.contract_id != API_CONTRACT_ID
        || !profile.local_api_compatibility.runtime_reference_required
        || profile.local_api_compatibility.minimum_version.is_empty()
        || profile
            .local_api_compatibility
            .maximum_version_exclusive
            .is_empty()
        || profile.implementation_boundary.shared_kernel_language != "rust"
        || profile
            .implementation_boundary
            .typescript_business_kernel_allowed
        || profile.implementation_boundary.transport
            != "tonic_grpc_http2_semantics_over_named_pipe_or_uds_no_tcp"
        || profile.implementation_boundary.surfaces.len() != 3
        || profile
            .implementation_boundary
            .surfaces
            .iter()
            .any(|value| value.is_empty())
        || required_capabilities
            .iter()
            .any(|value| !profile.capabilities.contains(*value))
        || !profile.invariants.surface_neutral
        || !profile.invariants.complete_snapshot_streams
        || !profile.invariants.ordered_within_epoch
        || !profile.invariants.at_least_once_delivery
        || !profile.invariants.unknown_frame_fail_closed
        || !profile.invariants.gap_requires_reset
        || !profile.invariants.authority_result_preserved
        || !profile.invariants.client_never_becomes_authority
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
        || profile.authority_ref.is_empty()
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
