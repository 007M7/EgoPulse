use std::{collections::BTreeMap, sync::Arc};

use egopulse_cognition_runtime::task_authority::PrincipalKind as TaskPrincipalKind;
use egopulse_founder_verdict_authority::VerdictPrincipalKind;
use egopulse_local_api::{
    command_gateway::{CommandPortFailure, CommandPrincipal},
    session::{PrincipalGrant, PrincipalResolutionFailure, TrustedPrincipalResolver},
};
use egopulse_local_ipc_platform::OsPrincipal;
use egopulse_policy_decision_authority::PolicyPrincipalKind;
use thiserror::Error;

/// One explicit OS-peer to Local Session grant. The fingerprint is the
/// platform-derived identity exposed by the local IPC transport; it is not an
/// Authority identity and never grants Founder rights by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowlistedPrincipal {
    pub fingerprint_hex: String,
    pub grant: PrincipalGrant,
}

/// A reviewed mapping from one authenticated session principal to the three
/// owner-specific Authority principal kinds. Each field is optional on
/// purpose: a local user may be allowed to use one owner without being
/// silently promoted in the other two Authorities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPrincipalBinding {
    pub principal_id: String,
    pub task: Option<TaskPrincipalKind>,
    pub policy: Option<PolicyPrincipalKind>,
    pub verdict: Option<VerdictPrincipalKind>,
}

/// Validated, immutable local identity policy used by the production
/// composition root. There is no fallback entry and no environment-derived
/// Founder principal.
#[derive(Clone, Debug)]
pub struct AllowlistedPrincipalResolver {
    grants: Arc<BTreeMap<String, PrincipalGrant>>,
}

impl AllowlistedPrincipalResolver {
    pub fn new(
        entries: impl IntoIterator<Item = AllowlistedPrincipal>,
    ) -> Result<Self, PrincipalPolicyError> {
        let mut grants = BTreeMap::new();
        for entry in entries {
            let fingerprint = normalize_fingerprint(&entry.fingerprint_hex)?;
            entry
                .grant
                .validate()
                .map_err(|_| PrincipalPolicyError::InvalidGrant)?;
            if grants.insert(fingerprint, entry.grant).is_some() {
                return Err(PrincipalPolicyError::DuplicateFingerprint);
            }
        }
        if grants.is_empty() {
            return Err(PrincipalPolicyError::EmptyPolicy);
        }
        Ok(Self {
            grants: Arc::new(grants),
        })
    }
}

impl TrustedPrincipalResolver for AllowlistedPrincipalResolver {
    fn resolve(
        &self,
        principal: &OsPrincipal,
    ) -> Result<PrincipalGrant, PrincipalResolutionFailure> {
        self.grants
            .get(&principal.fingerprint_hex())
            .cloned()
            .ok_or(PrincipalResolutionFailure::PermissionDenied)
    }
}

/// Validated owner mapping used after Local Session authentication. Mapping
/// is keyed by the authenticated session principal ID, not by a request field
/// supplied by a CLI/TUI/desktop client.
#[derive(Clone, Debug)]
pub struct ConfiguredAuthorityPrincipalResolver {
    bindings: Arc<BTreeMap<String, AuthorityPrincipalBinding>>,
}

impl ConfiguredAuthorityPrincipalResolver {
    pub fn new(
        entries: impl IntoIterator<Item = AuthorityPrincipalBinding>,
    ) -> Result<Self, PrincipalPolicyError> {
        let mut bindings = BTreeMap::new();
        for entry in entries {
            validate_principal_id(&entry.principal_id)?;
            if entry.task.is_none() && entry.policy.is_none() && entry.verdict.is_none() {
                return Err(PrincipalPolicyError::EmptyAuthorityMapping);
            }
            let key = entry.principal_id.clone();
            if bindings.insert(key, entry).is_some() {
                return Err(PrincipalPolicyError::DuplicatePrincipalId);
            }
        }
        if bindings.is_empty() {
            return Err(PrincipalPolicyError::EmptyPolicy);
        }
        Ok(Self {
            bindings: Arc::new(bindings),
        })
    }

    fn binding(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<&AuthorityPrincipalBinding, CommandPortFailure> {
        self.bindings
            .get(&principal.principal_id)
            .ok_or(CommandPortFailure::Unavailable)
    }
}

impl crate::AuthorityPrincipalResolver for ConfiguredAuthorityPrincipalResolver {
    fn resolve_task(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<TaskPrincipalKind, CommandPortFailure> {
        self.binding(principal)?
            .task
            .ok_or(CommandPortFailure::Unavailable)
    }

    fn resolve_policy(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<PolicyPrincipalKind, CommandPortFailure> {
        self.binding(principal)?
            .policy
            .ok_or(CommandPortFailure::Unavailable)
    }

    fn resolve_verdict(
        &self,
        principal: &CommandPrincipal,
    ) -> Result<VerdictPrincipalKind, CommandPortFailure> {
        self.binding(principal)?
            .verdict
            .ok_or(CommandPortFailure::Unavailable)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PrincipalPolicyError {
    #[error("principal policy must contain at least one entry")]
    EmptyPolicy,
    #[error("principal fingerprint must be exactly 32 bytes of hexadecimal")]
    InvalidFingerprint,
    #[error("principal grant is invalid")]
    InvalidGrant,
    #[error("principal fingerprint is duplicated")]
    DuplicateFingerprint,
    #[error("authenticated principal ID is invalid")]
    InvalidPrincipalId,
    #[error("authenticated principal ID is duplicated")]
    DuplicatePrincipalId,
    #[error("authority mapping must grant at least one explicit owner kind")]
    EmptyAuthorityMapping,
}

fn normalize_fingerprint(value: &str) -> Result<String, PrincipalPolicyError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PrincipalPolicyError::InvalidFingerprint);
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_principal_id(value: &str) -> Result<(), PrincipalPolicyError> {
    if value.trim().is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.'))
    {
        return Err(PrincipalPolicyError::InvalidPrincipalId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorityPrincipalResolver;
    use egopulse_client_kernel::authorization_contract_ref;
    use std::collections::BTreeSet;

    fn grant(principal_id: &str) -> PrincipalGrant {
        PrincipalGrant {
            authenticated_principal_id: principal_id.to_owned(),
            permission_codes: BTreeSet::from(["task.write".to_owned()]),
            authorization_policy_ref: authorization_contract_ref(),
        }
    }

    #[test]
    fn allowlist_rejects_empty_or_malformed_entries() {
        assert!(matches!(
            AllowlistedPrincipalResolver::new([]),
            Err(PrincipalPolicyError::EmptyPolicy)
        ));
        assert!(matches!(
            AllowlistedPrincipalResolver::new([AllowlistedPrincipal {
                fingerprint_hex: "00".repeat(31),
                grant: grant("os-user:test"),
            }]),
            Err(PrincipalPolicyError::InvalidFingerprint)
        ));
    }

    #[test]
    fn authority_mapping_has_no_implicit_cross_authority_grant() {
        let resolver = ConfiguredAuthorityPrincipalResolver::new([AuthorityPrincipalBinding {
            principal_id: "os-user:test".to_owned(),
            task: Some(TaskPrincipalKind::Founder),
            policy: None,
            verdict: None,
        }])
        .expect("valid explicit task-only mapping");
        let principal = CommandPrincipal {
            principal_id: "os-user:test".to_owned(),
            required_authority_principal_kinds: Vec::new(),
        };
        assert_eq!(
            resolver.resolve_task(&principal),
            Ok(TaskPrincipalKind::Founder)
        );
        assert_eq!(
            resolver.resolve_policy(&principal),
            Err(CommandPortFailure::Unavailable)
        );
        assert_eq!(
            resolver.resolve_verdict(&principal),
            Err(CommandPortFailure::Unavailable)
        );
    }

    #[test]
    fn authority_mapping_rejects_empty_owner_mapping() {
        assert!(matches!(
            ConfiguredAuthorityPrincipalResolver::new([AuthorityPrincipalBinding {
                principal_id: "os-user:test".to_owned(),
                task: None,
                policy: None,
                verdict: None,
            }]),
            Err(PrincipalPolicyError::EmptyAuthorityMapping)
        ));
    }
}
