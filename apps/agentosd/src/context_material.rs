use egopulse_cognition_runtime::context_authority::{
    AuthenticatedContextPrincipal, ContextAuthority, ContextAuthorityFailure,
    ContextGovernanceState, ContextPrincipalKind, ContextSnapshot,
    DispatchContextConsumptionAuthorizationLookup,
    DispatchContextConsumptionAuthorizationReceipt as AuthorityAuthorizationReceipt,
    DispatchContextConsumptionAuthorizationRequest, RecoveryContextMaterialRequest,
    RecoveryContextPurpose,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, HarnessError, HarnessErrorCode,
};
use egopulse_harness_adapter::{
    AuthorizedDispatchContext, DispatchContextAuthorization, DispatchContextAuthorizationGate,
    DispatchContextAuthorizationReceipt, DispatchContextBinding, DispatchContextRecovery,
    DispatchContextRecoveryGate, DispatchContextReference, HistoricalDispatchContext,
    HistoricalDispatchContextBinding, HistoricalDispatchContextState,
    classify_dispatch_context_reference,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const GOVERNANCE_KERNEL_PRINCIPAL_ID: &str = "agentosd:context-dispatch-gate";

/// Production bridge between the provider-neutral Adapter and Context
/// Authority. It shares the same Authority instance used by work preparation
/// and Context mutation, preserving the authorize/revoke linearization point.
pub(crate) struct ContextDispatchAuthorizationGate {
    context: Arc<Mutex<ContextAuthority>>,
    principal: AuthenticatedContextPrincipal,
}

impl ContextDispatchAuthorizationGate {
    pub(crate) fn new(context: Arc<Mutex<ContextAuthority>>) -> Self {
        Self {
            context,
            principal: AuthenticatedContextPrincipal {
                kind: ContextPrincipalKind::GovernanceKernel,
                principal_id: GOVERNANCE_KERNEL_PRINCIPAL_ID.to_owned(),
                authenticated: true,
            },
        }
    }

    fn authorize_or_lookup(
        &self,
        envelope: &DispatchEnvelope,
        allow_authorize: bool,
    ) -> Result<DispatchContextAuthorization, HarnessError> {
        let snapshot_id = match classify_dispatch_context_reference(&envelope.input_bundle_ref) {
            DispatchContextReference::NotContextBound => {
                return Ok(DispatchContextAuthorization::NotContextBound);
            }
            DispatchContextReference::ContextSnapshot { snapshot_id } => snapshot_id,
            DispatchContextReference::InvalidContextBinding => {
                return Err(context_error(
                    HarnessErrorCode::ConfigInvalid,
                    "CONTEXT_BINDING_INVALID",
                    false,
                ));
            }
        };
        let mut authority = self.context.lock().map_err(|_| {
            context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_AUTHORITY_LOCK_FAILED",
                false,
            )
        })?;
        let snapshot = authority
            .get(&snapshot_id)
            .map_err(map_authority_failure)?
            .ok_or_else(|| {
                context_error(
                    HarnessErrorCode::DependencyUnavailable,
                    "CONTEXT_SNAPSHOT_NOT_FOUND",
                    false,
                )
            })?;
        if snapshot.snapshot_id != snapshot_id
            || snapshot.revision == 0
            || snapshot.compiled_context_sha256 != envelope.input_bundle_sha256
            || !canonical_sha256_is_valid(&snapshot.compiled_context_sha256)
            || snapshot.target_scope_ref.is_empty()
        {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_SNAPSHOT_BINDING_INVALID",
                false,
            ));
        }

        let lookup = DispatchContextConsumptionAuthorizationLookup {
            snapshot_id: snapshot.snapshot_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            input_digest_sha256: envelope.input_bundle_sha256.clone(),
            expected_scope_ref: snapshot.target_scope_ref.clone(),
        };
        if let Some(receipt) = authority
            .dispatch_authorization_by_dispatch_id(&self.principal, &lookup)
            .map_err(map_authority_failure)?
        {
            authority
                .verify_dispatch_authorization(&self.principal, &receipt)
                .map_err(map_authority_failure)?;
            return Ok(authorized_context(&snapshot, receipt));
        }
        if !allow_authorize {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_AUTHORIZATION_MISSING",
                false,
            ));
        }

        let governance = authority
            .governance(&snapshot_id)
            .map_err(map_authority_failure)?
            .ok_or_else(|| {
                context_error(
                    HarnessErrorCode::DependencyUnavailable,
                    "CONTEXT_SNAPSHOT_NOT_FOUND",
                    false,
                )
            })?;
        if governance.snapshot_id != snapshot.snapshot_id
            || governance.snapshot_revision != snapshot.revision
            || governance.content_digest_sha256 != snapshot.compiled_context_sha256
        {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_GOVERNANCE_BINDING_INVALID",
                false,
            ));
        }
        let request = DispatchContextConsumptionAuthorizationRequest {
            command_id: format!("context-dispatch-authorize:{}", envelope.dispatch_id),
            snapshot_id: snapshot.snapshot_id.clone(),
            expected_state_revision: governance.state_revision,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            input_digest_sha256: envelope.input_bundle_sha256.clone(),
            expected_scope_ref: snapshot.target_scope_ref.clone(),
            idempotency_key: format!("context-dispatch:{}", envelope.dispatch_id),
            correlation_id: stable_correlation_id(envelope),
            causation_id: stable_causation_id(envelope),
        };
        let receipt = authority
            .authorize_dispatch_consumption(&self.principal, &request)
            .map_err(map_authority_failure)?;
        authority
            .verify_dispatch_authorization(&self.principal, &receipt)
            .map_err(map_authority_failure)?;
        Ok(authorized_context(&snapshot, receipt))
    }
}

impl DispatchContextAuthorizationGate for ContextDispatchAuthorizationGate {
    fn authorize_ready_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError> {
        self.authorize_or_lookup(envelope, true)
    }

    fn verify_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError> {
        self.authorize_or_lookup(envelope, false)
    }
}

/// Independent, read-only production bridge for reconciliation of a dispatch
/// whose exact Context authorization lineage is already durable. It shares the
/// same Authority instance as normal authorization but cannot mint a receipt.
pub(crate) struct ContextDispatchRecoveryGate {
    context: Arc<Mutex<ContextAuthority>>,
    principal: AuthenticatedContextPrincipal,
}

impl ContextDispatchRecoveryGate {
    pub(crate) fn new(context: Arc<Mutex<ContextAuthority>>) -> Self {
        Self {
            context,
            principal: AuthenticatedContextPrincipal {
                kind: ContextPrincipalKind::GovernanceKernel,
                principal_id: GOVERNANCE_KERNEL_PRINCIPAL_ID.to_owned(),
                authenticated: true,
            },
        }
    }
}

impl DispatchContextRecoveryGate for ContextDispatchRecoveryGate {
    fn recover_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextRecovery, HarnessError> {
        let snapshot_id = match classify_dispatch_context_reference(&envelope.input_bundle_ref) {
            DispatchContextReference::NotContextBound => {
                return Ok(DispatchContextRecovery::NotContextBound);
            }
            DispatchContextReference::ContextSnapshot { snapshot_id } => snapshot_id,
            DispatchContextReference::InvalidContextBinding => {
                return Err(context_error(
                    HarnessErrorCode::ConfigInvalid,
                    "CONTEXT_BINDING_INVALID",
                    false,
                ));
            }
        };
        let authority = self.context.lock().map_err(|_| {
            context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_AUTHORITY_LOCK_FAILED",
                false,
            )
        })?;
        let snapshot = authority
            .get(&snapshot_id)
            .map_err(map_authority_failure)?
            .ok_or_else(|| {
                context_error(
                    HarnessErrorCode::DependencyUnavailable,
                    "CONTEXT_SNAPSHOT_NOT_FOUND",
                    false,
                )
            })?;
        if snapshot.snapshot_id != snapshot_id
            || snapshot.revision == 0
            || snapshot.compiled_context_sha256 != envelope.input_bundle_sha256
            || !canonical_sha256_is_valid(&snapshot.compiled_context_sha256)
            || snapshot.target_scope_ref.is_empty()
        {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_SNAPSHOT_BINDING_INVALID",
                false,
            ));
        }
        let lookup = DispatchContextConsumptionAuthorizationLookup {
            snapshot_id: snapshot.snapshot_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            input_digest_sha256: envelope.input_bundle_sha256.clone(),
            expected_scope_ref: snapshot.target_scope_ref.clone(),
        };
        let receipt = authority
            .dispatch_authorization_by_dispatch_id(&self.principal, &lookup)
            .map_err(map_authority_failure)?
            .ok_or_else(|| {
                context_error(
                    HarnessErrorCode::IntegrityFailure,
                    "CONTEXT_AUTHORIZATION_MISSING",
                    false,
                )
            })?;
        if !recovery_authorization_matches(&snapshot, envelope, &receipt) {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_AUTHORIZATION_INVALID",
                false,
            ));
        }
        authority
            .verify_dispatch_authorization(&self.principal, &receipt)
            .map_err(map_authority_failure)?;
        let evidence_ref = stable_recovery_evidence_ref(&snapshot, envelope, &receipt);
        let recovered = authority
            .resolve_for_recovery(
                &self.principal,
                &RecoveryContextMaterialRequest {
                    snapshot_id: snapshot.snapshot_id.clone(),
                    attempt_id: envelope.attempt_id.clone(),
                    dispatch_id: envelope.dispatch_id.clone(),
                    input_digest_sha256: envelope.input_bundle_sha256.clone(),
                    expected_scope_ref: snapshot.target_scope_ref.clone(),
                    evidence_ref,
                    purpose: RecoveryContextPurpose::RecoveryOrReconciliation,
                },
            )
            .map_err(map_authority_failure)?;
        if recovered.snapshot != snapshot
            || recovered.observed_state_revision == 0
            || sha256(&recovered.compiled_context) != snapshot.compiled_context_sha256
        {
            return Err(context_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_RECOVERY_EVIDENCE_INVALID",
                false,
            ));
        }
        let observed_state = match recovered.observed_governance_state {
            ContextGovernanceState::Issued => HistoricalDispatchContextState::Issued,
            ContextGovernanceState::Revoked => HistoricalDispatchContextState::Revoked,
        };
        Ok(DispatchContextRecovery::Historical(Box::new(
            HistoricalDispatchContext {
                binding: HistoricalDispatchContextBinding {
                    snapshot_id: snapshot.snapshot_id,
                    snapshot_revision: snapshot.revision,
                    content_digest_sha256: snapshot.compiled_context_sha256,
                    expected_scope_ref: snapshot.target_scope_ref,
                },
                authority_immutable_bytes: recovered.compiled_context,
                observed_state_revision: recovered.observed_state_revision,
                observed_state,
            },
        )))
    }
}

fn recovery_authorization_matches(
    snapshot: &ContextSnapshot,
    envelope: &DispatchEnvelope,
    receipt: &AuthorityAuthorizationReceipt,
) -> bool {
    !receipt.authorization_id.is_empty()
        && receipt.snapshot_id == snapshot.snapshot_id
        && receipt.snapshot_revision == snapshot.revision
        && receipt.observed_state_revision > 0
        && receipt.attempt_id == envelope.attempt_id
        && receipt.dispatch_id == envelope.dispatch_id
        && receipt.input_digest_sha256 == envelope.input_bundle_sha256
        && receipt.input_digest_sha256 == snapshot.compiled_context_sha256
        && receipt.expected_scope_ref == snapshot.target_scope_ref
        && canonical_sha256_is_valid(&receipt.request_digest_sha256)
        && !receipt.event_id.is_empty()
        && receipt.committed_at_seconds > 0
}

fn stable_recovery_evidence_ref(
    snapshot: &ContextSnapshot,
    envelope: &DispatchEnvelope,
    receipt: &AuthorityAuthorizationReceipt,
) -> String {
    fn field(hasher: &mut Sha256, value: &[u8]) {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    field(&mut hasher, b"egopulse/context-recovery-evidence/v1");
    field(&mut hasher, snapshot.snapshot_id.as_bytes());
    field(&mut hasher, &snapshot.revision.to_le_bytes());
    field(&mut hasher, snapshot.compiled_context_sha256.as_bytes());
    field(&mut hasher, snapshot.target_scope_ref.as_bytes());
    field(&mut hasher, envelope.attempt_id.as_bytes());
    field(&mut hasher, envelope.dispatch_id.as_bytes());
    field(&mut hasher, envelope.input_bundle_sha256.as_bytes());
    field(&mut hasher, receipt.authorization_id.as_bytes());
    field(&mut hasher, &receipt.observed_state_revision.to_le_bytes());
    field(&mut hasher, receipt.request_digest_sha256.as_bytes());
    field(&mut hasher, receipt.event_id.as_bytes());
    format!("context-recovery-sha256:{:x}", hasher.finalize())
}

fn authorized_context(
    snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
    receipt: AuthorityAuthorizationReceipt,
) -> DispatchContextAuthorization {
    DispatchContextAuthorization::Authorized(Box::new(AuthorizedDispatchContext {
        binding: DispatchContextBinding {
            snapshot_id: snapshot.snapshot_id.clone(),
            snapshot_revision: snapshot.revision,
            content_digest_sha256: snapshot.compiled_context_sha256.clone(),
            expected_scope_ref: snapshot.target_scope_ref.clone(),
        },
        receipt: DispatchContextAuthorizationReceipt {
            authorization_id: receipt.authorization_id,
            snapshot_id: receipt.snapshot_id,
            snapshot_revision: receipt.snapshot_revision,
            observed_state_revision: receipt.observed_state_revision,
            attempt_id: receipt.attempt_id,
            dispatch_id: receipt.dispatch_id,
            input_digest_sha256: receipt.input_digest_sha256,
            expected_scope_ref: receipt.expected_scope_ref,
            request_digest_sha256: receipt.request_digest_sha256,
            event_id: receipt.event_id,
            committed_at_seconds: receipt.committed_at_seconds,
            replayed: receipt.replayed,
        },
    }))
}

fn stable_correlation_id(envelope: &DispatchEnvelope) -> String {
    if envelope.run_id.is_empty() {
        format!("context-dispatch:{}", envelope.dispatch_id)
    } else {
        envelope.run_id.clone()
    }
}

fn stable_causation_id(envelope: &DispatchEnvelope) -> String {
    envelope
        .meta
        .as_ref()
        .map(|meta| meta.command_id.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("context-dispatch:{}", envelope.dispatch_id))
}

fn map_authority_failure(failure: ContextAuthorityFailure) -> HarnessError {
    let (code, detail, retryable) = match failure {
        ContextAuthorityFailure::Storage => (
            HarnessErrorCode::DependencyUnavailable,
            "CONTEXT_AUTHORITY_STORAGE_UNAVAILABLE",
            true,
        ),
        ContextAuthorityFailure::Expired => (
            HarnessErrorCode::InvalidArgument,
            "CONTEXT_SNAPSHOT_EXPIRED",
            false,
        ),
        ContextAuthorityFailure::Revoked => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_SNAPSHOT_REVOKED",
            false,
        ),
        ContextAuthorityFailure::AuthorizationTupleConflict => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORIZATION_TUPLE_CONFLICT",
            false,
        ),
        ContextAuthorityFailure::IdempotencyConflict => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORIZATION_IDEMPOTENCY_CONFLICT",
            false,
        ),
        ContextAuthorityFailure::StateRevisionConflict => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_STATE_REVISION_CONFLICT",
            false,
        ),
        ContextAuthorityFailure::ScopeMismatch => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_SCOPE_MISMATCH",
            false,
        ),
        ContextAuthorityFailure::NotFound => (
            HarnessErrorCode::DependencyUnavailable,
            "CONTEXT_SNAPSHOT_NOT_FOUND",
            false,
        ),
        ContextAuthorityFailure::InvalidArgument(_) => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORIZATION_REQUEST_INVALID",
            false,
        ),
        ContextAuthorityFailure::Unauthorized => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORITY_PRINCIPAL_INVALID",
            false,
        ),
        ContextAuthorityFailure::OwnerMismatch => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORITY_OWNER_INVALID",
            false,
        ),
        ContextAuthorityFailure::IntegrityFailure | ContextAuthorityFailure::Clock => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORITY_INTEGRITY_FAILURE",
            false,
        ),
    };
    context_error(code, detail, retryable)
}

fn context_error(code: HarnessErrorCode, detail: &str, retryable_delivery: bool) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery,
        recovery_required: true,
        error_fingerprint: Some(sha256(detail.as_bytes())),
        audit_ref: Some("agentosd:context-dispatch-authorization".to_owned()),
    }
}

fn canonical_sha256_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_cognition_runtime::context_authority::{
        ContextAuthorityConfig, ContextRevokeRequest, ContextStoreInspection, IssueContextSnapshot,
    };
    use egopulse_cognition_runtime::task_authority::SqlCipherKey;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    struct FixtureRoot(PathBuf);

    impl FixtureRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "egopulse-agentosd-context-gate-{label}-{}",
                Uuid::now_v7()
            ));
            fs::create_dir_all(&path).expect("create context gate fixture");
            Self(path)
        }
    }

    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            let temp = std::env::temp_dir();
            assert!(self.0.starts_with(temp));
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove context gate fixture");
            }
        }
    }

    fn compiler() -> AuthenticatedContextPrincipal {
        AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::ContextCompiler,
            principal_id: "agentosd:test-context-compiler".to_owned(),
            authenticated: true,
        }
    }

    fn founder() -> AuthenticatedContextPrincipal {
        AuthenticatedContextPrincipal {
            kind: ContextPrincipalKind::Founder,
            principal_id: "founder:context-gate-test".to_owned(),
            authenticated: true,
        }
    }

    fn now_seconds() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_secs() as i64
    }

    fn open_authority(root: &FixtureRoot) -> Arc<Mutex<ContextAuthority>> {
        Arc::new(Mutex::new(
            ContextAuthority::open(ContextAuthorityConfig {
                database_path: root.0.join("context.sqlcipher"),
                store_epoch: "agentosd-context-gate-test-v1".to_owned(),
                key: SqlCipherKey::new([0x5e; 32]),
            })
            .expect("open context authority"),
        ))
    }

    fn issue_snapshot(
        authority: &Arc<Mutex<ContextAuthority>>,
        idempotency_key: &str,
    ) -> egopulse_cognition_runtime::context_authority::ContextSnapshot {
        let input = IssueContextSnapshot {
            owner_principal_id: founder().principal_id,
            intent: "authorize one governed dispatch".to_owned(),
            work_type: "governed-test".to_owned(),
            target_scope_ref: "scope:repo".to_owned(),
            compiled_context: br#"{"prompt":"authorized context"}"#.to_vec(),
            sources: Vec::new(),
            memory_pack: None,
            allowed_read_paths: vec!["workspace".to_owned()],
            allowed_write_paths: Vec::new(),
            allowed_tools: Vec::new(),
            external_resources: Vec::new(),
            non_goals: Vec::new(),
            acceptance_contract_ref: "acceptance:test".to_owned(),
            budget_profile_ref: "budget:test".to_owned(),
            deadline_seconds: None,
            recovery_entry: "hold-and-reconcile".to_owned(),
            visibility: "founder-only".to_owned(),
            redactions: Vec::new(),
            expires_at_seconds: now_seconds() + 600,
            idempotency_key: idempotency_key.to_owned(),
        };
        authority
            .lock()
            .expect("context lock")
            .issue(&input, &compiler())
            .expect("issue context snapshot")
            .1
    }

    fn envelope(
        snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
        dispatch_id: &str,
    ) -> DispatchEnvelope {
        DispatchEnvelope {
            run_id: "run:context-gate-test".to_owned(),
            attempt_id: format!("attempt:{dispatch_id}"),
            dispatch_id: dispatch_id.to_owned(),
            input_bundle_ref: format!(
                "ctx-{}.json",
                snapshot
                    .snapshot_id
                    .strip_prefix("ctx:")
                    .expect("snapshot digest")
            ),
            input_bundle_sha256: snapshot.compiled_context_sha256.clone(),
            ..DispatchEnvelope::default()
        }
    }

    fn revoke(
        authority: &Arc<Mutex<ContextAuthority>>,
        snapshot: &egopulse_cognition_runtime::context_authority::ContextSnapshot,
        idempotency_key: &str,
    ) {
        let mut authority = authority.lock().expect("context lock");
        let governance = authority
            .governance(&snapshot.snapshot_id)
            .expect("read governance")
            .expect("governance snapshot");
        authority
            .revoke(
                &founder(),
                &ContextRevokeRequest {
                    command_id: format!("command:{idempotency_key}"),
                    snapshot_id: snapshot.snapshot_id.clone(),
                    expected_state_revision: governance.state_revision,
                    reason_code: "test-revoke".to_owned(),
                    evidence_refs: vec!["evidence:context-gate-test".to_owned()],
                    confirmation_proof_ref: "proof:context-gate-test".to_owned(),
                    idempotency_key: idempotency_key.to_owned(),
                    correlation_id: format!("correlation:{idempotency_key}"),
                    causation_id: Some(format!("causation:{idempotency_key}")),
                },
            )
            .expect("revoke snapshot");
    }

    fn inspect(authority: &Arc<Mutex<ContextAuthority>>) -> ContextStoreInspection {
        authority
            .lock()
            .expect("context lock")
            .inspect_store()
            .expect("inspect context store")
    }

    #[test]
    fn authority_failures_are_sanitized_with_explicit_retryability() {
        for (failure, detail, retryable) in [
            (
                ContextAuthorityFailure::Storage,
                "CONTEXT_AUTHORITY_STORAGE_UNAVAILABLE",
                true,
            ),
            (
                ContextAuthorityFailure::Revoked,
                "CONTEXT_SNAPSHOT_REVOKED",
                false,
            ),
            (
                ContextAuthorityFailure::Expired,
                "CONTEXT_SNAPSHOT_EXPIRED",
                false,
            ),
            (
                ContextAuthorityFailure::NotFound,
                "CONTEXT_SNAPSHOT_NOT_FOUND",
                false,
            ),
            (
                ContextAuthorityFailure::AuthorizationTupleConflict,
                "CONTEXT_AUTHORIZATION_TUPLE_CONFLICT",
                false,
            ),
            (
                ContextAuthorityFailure::IntegrityFailure,
                "CONTEXT_AUTHORITY_INTEGRITY_FAILURE",
                false,
            ),
        ] {
            let error = map_authority_failure(failure);
            assert_eq!(error.safe_detail_code, detail);
            assert_eq!(error.retryable_delivery, retryable);
            assert!(error.recovery_required);
            assert!(!error.safe_detail_code.contains('{'));
        }
    }

    #[test]
    fn revoke_first_rejects_ready_dispatch_without_creating_authorization_or_event() {
        let root = FixtureRoot::new("revoke-first");
        let authority = open_authority(&root);
        let snapshot = issue_snapshot(&authority, "issue-revoke-first");
        let dispatch = envelope(&snapshot, "dispatch:revoke-first");
        revoke(&authority, &snapshot, "revoke-first");
        let before = inspect(&authority);
        assert_eq!(before.dispatch_authorization_count, 0);
        let gate = ContextDispatchAuthorizationGate::new(Arc::clone(&authority));

        let error = gate
            .authorize_ready_dispatch(&dispatch)
            .expect_err("revoked snapshot must fail closed");
        assert_eq!(error.safe_detail_code, "CONTEXT_SNAPSHOT_REVOKED");
        assert!(!error.retryable_delivery);
        assert_eq!(inspect(&authority), before);
    }

    #[test]
    fn authorization_first_survives_revoke_only_through_exact_existing_lookup() {
        let root = FixtureRoot::new("authorization-first");
        let authority = open_authority(&root);
        let snapshot = issue_snapshot(&authority, "issue-authorization-first");
        let dispatch = envelope(&snapshot, "dispatch:authorization-first");
        let gate = ContextDispatchAuthorizationGate::new(Arc::clone(&authority));

        let first = gate
            .authorize_ready_dispatch(&dispatch)
            .expect("authorize ready dispatch");
        let after_authorize = inspect(&authority);
        assert_eq!(after_authorize.dispatch_authorization_count, 1);
        assert_eq!(after_authorize.dispatch_authorization_idempotency_count, 1);
        revoke(&authority, &snapshot, "revoke-after-authorization");
        let after_revoke = inspect(&authority);

        let existing = gate
            .verify_existing_dispatch(&dispatch)
            .expect("exact existing authorization remains verifiable");
        assert_eq!(existing, first);
        assert_eq!(inspect(&authority), after_revoke);

        let mut changed = dispatch.clone();
        changed.attempt_id = "attempt:changed".to_owned();
        let error = gate
            .verify_existing_dispatch(&changed)
            .expect_err("changed tuple must not inherit authorization");
        assert_eq!(
            error.safe_detail_code,
            "CONTEXT_AUTHORIZATION_TUPLE_CONFLICT"
        );
        assert_eq!(inspect(&authority), after_revoke);
    }

    #[test]
    fn authorization_first_then_revoke_recovers_exact_immutable_material_without_writes() {
        let root = FixtureRoot::new("recovery-authorization-first");
        let authority = open_authority(&root);
        let snapshot = issue_snapshot(&authority, "issue-recovery-authorization-first");
        let dispatch = envelope(&snapshot, "dispatch:recovery-authorization-first");
        ContextDispatchAuthorizationGate::new(Arc::clone(&authority))
            .authorize_ready_dispatch(&dispatch)
            .expect("authorize ready dispatch");
        revoke(&authority, &snapshot, "revoke-before-recovery");
        let before_recovery = inspect(&authority);

        let recovered = ContextDispatchRecoveryGate::new(Arc::clone(&authority))
            .recover_existing_dispatch(&dispatch)
            .expect("recover exact authorized dispatch after revoke");
        let DispatchContextRecovery::Historical(recovered) = recovered else {
            panic!("context dispatch must recover historical material");
        };
        assert_eq!(recovered.binding.snapshot_id, snapshot.snapshot_id);
        assert_eq!(recovered.binding.snapshot_revision, snapshot.revision);
        assert_eq!(
            recovered.binding.content_digest_sha256,
            snapshot.compiled_context_sha256
        );
        assert_eq!(
            recovered.binding.expected_scope_ref,
            snapshot.target_scope_ref
        );
        assert_eq!(
            recovered.authority_immutable_bytes,
            br#"{"prompt":"authorized context"}"#
        );
        assert_eq!(
            recovered.observed_state,
            HistoricalDispatchContextState::Revoked
        );
        assert!(recovered.observed_state_revision > 1);
        assert_eq!(inspect(&authority), before_recovery);
    }

    #[test]
    fn recovery_requires_existing_exact_authorization_tuple_and_never_writes() {
        let root = FixtureRoot::new("recovery-exact-tuple");
        let authority = open_authority(&root);
        let snapshot = issue_snapshot(&authority, "issue-recovery-exact-tuple");
        let dispatch = envelope(&snapshot, "dispatch:recovery-exact-tuple");
        let recovery_gate = ContextDispatchRecoveryGate::new(Arc::clone(&authority));

        let before_missing = inspect(&authority);
        let missing = recovery_gate
            .recover_existing_dispatch(&dispatch)
            .expect_err("missing authorization must fail closed");
        assert_eq!(missing.safe_detail_code, "CONTEXT_AUTHORIZATION_MISSING");
        assert_eq!(inspect(&authority), before_missing);

        ContextDispatchAuthorizationGate::new(Arc::clone(&authority))
            .authorize_ready_dispatch(&dispatch)
            .expect("authorize exact tuple");
        let before_drift = inspect(&authority);
        let mut changed = dispatch.clone();
        changed.attempt_id = "attempt:wrong-recovery-lineage".to_owned();
        let drift = recovery_gate
            .recover_existing_dispatch(&changed)
            .expect_err("wrong tuple must fail closed");
        assert_eq!(
            drift.safe_detail_code,
            "CONTEXT_AUTHORIZATION_TUPLE_CONFLICT"
        );
        assert_eq!(inspect(&authority), before_drift);
    }

    #[test]
    fn recovery_receipt_match_and_evidence_digest_bind_the_complete_lineage() {
        let root = FixtureRoot::new("recovery-lineage-digest");
        let authority = open_authority(&root);
        let snapshot = issue_snapshot(&authority, "issue-recovery-lineage-digest");
        let dispatch = envelope(&snapshot, "dispatch:recovery-lineage-digest");
        let gate = ContextDispatchAuthorizationGate::new(Arc::clone(&authority));
        gate.authorize_ready_dispatch(&dispatch)
            .expect("authorize exact tuple");
        let lookup = DispatchContextConsumptionAuthorizationLookup {
            snapshot_id: snapshot.snapshot_id.clone(),
            attempt_id: dispatch.attempt_id.clone(),
            dispatch_id: dispatch.dispatch_id.clone(),
            input_digest_sha256: dispatch.input_bundle_sha256.clone(),
            expected_scope_ref: snapshot.target_scope_ref.clone(),
        };
        let receipt = authority
            .lock()
            .expect("context lock")
            .dispatch_authorization_by_dispatch_id(&gate.principal, &lookup)
            .expect("lookup authorization")
            .expect("authorization receipt");
        let before = inspect(&authority);
        assert!(recovery_authorization_matches(
            &snapshot, &dispatch, &receipt
        ));

        for field in [
            "snapshot-id",
            "snapshot-revision",
            "state-revision",
            "attempt",
            "dispatch",
            "input-digest",
            "scope",
            "request-digest",
        ] {
            let mut changed = receipt.clone();
            match field {
                "snapshot-id" => changed.snapshot_id.push_str(":drift"),
                "snapshot-revision" => changed.snapshot_revision += 1,
                "state-revision" => changed.observed_state_revision = 0,
                "attempt" => changed.attempt_id.push_str(":drift"),
                "dispatch" => changed.dispatch_id.push_str(":drift"),
                "input-digest" => changed.input_digest_sha256 = "f".repeat(64),
                "scope" => changed.expected_scope_ref.push_str(":drift"),
                "request-digest" => changed.request_digest_sha256 = "F".repeat(64),
                _ => unreachable!(),
            }
            assert!(
                !recovery_authorization_matches(&snapshot, &dispatch, &changed),
                "receipt drift must fail: {field}"
            );
        }

        let evidence = stable_recovery_evidence_ref(&snapshot, &dispatch, &receipt);
        assert!(evidence.starts_with("context-recovery-sha256:"));
        assert_eq!(evidence.len(), "context-recovery-sha256:".len() + 64);
        assert!(!evidence.contains(&dispatch.dispatch_id));
        assert_eq!(
            evidence,
            stable_recovery_evidence_ref(&snapshot, &dispatch, &receipt)
        );
        let mut drifted_dispatch = dispatch.clone();
        drifted_dispatch.attempt_id.push_str(":drift");
        assert_ne!(
            evidence,
            stable_recovery_evidence_ref(&snapshot, &drifted_dispatch, &receipt)
        );
        assert_eq!(inspect(&authority), before);
    }
}
