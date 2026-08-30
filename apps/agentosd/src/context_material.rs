use egopulse_codex_adapter::FileDispatchMaterialResolver;
use egopulse_cognition_runtime::context_authority::{ContextAuthority, ContextAuthorityFailure};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, HarnessError, HarnessErrorCode,
};
use egopulse_harness_adapter::{DispatchMaterialResolver, ResolvedDispatchMaterial};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Dispatch-time proof decorator for ContextSnapshot-backed bundles. The
/// file resolver remains responsible for path, JSON and byte-digest checks;
/// this decorator repeats Context Authority state validation immediately
/// before the native Harness can receive the material.
pub(crate) struct ContextBoundDispatchMaterialResolver {
    inner: FileDispatchMaterialResolver,
    context: Option<Arc<Mutex<ContextAuthority>>>,
}

impl ContextBoundDispatchMaterialResolver {
    pub(crate) fn new(
        inner: FileDispatchMaterialResolver,
        context: Option<Arc<Mutex<ContextAuthority>>>,
    ) -> Self {
        Self { inner, context }
    }
}

impl DispatchMaterialResolver for ContextBoundDispatchMaterialResolver {
    fn resolve(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError> {
        let snapshot_id = match classify_context_bundle_reference(&envelope.input_bundle_ref) {
            ContextBundleReference::Static => return self.inner.resolve(envelope),
            ContextBundleReference::ValidContext(snapshot_id) => snapshot_id,
            ContextBundleReference::InvalidContext => {
                return Err(material_error(
                    HarnessErrorCode::ConfigInvalid,
                    "CONTEXT_BUNDLE_REFERENCE_INVALID",
                    false,
                    true,
                ));
            }
        };
        let Some(context) = self.context.as_ref() else {
            return Err(material_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_AUTHORITY_UNAVAILABLE",
                false,
                true,
            ));
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            material_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_CLOCK_INVALID",
                false,
                true,
            )
        })?;
        let resolved = context
            .lock()
            .map_err(|_| {
                material_error(
                    HarnessErrorCode::IntegrityFailure,
                    "CONTEXT_AUTHORITY_LOCKED",
                    false,
                    true,
                )
            })?
            .resolve_for_consumption(
                &snapshot_id,
                i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            )
            .map_err(context_error)?;
        if resolved.snapshot.compiled_context_sha256 != envelope.input_bundle_sha256
            || sha256(&resolved.compiled_context) != envelope.input_bundle_sha256
        {
            return Err(material_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_BUNDLE_DIGEST_MISMATCH",
                false,
                true,
            ));
        }
        self.inner.resolve(envelope)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContextBundleReference {
    Static,
    ValidContext(String),
    InvalidContext,
}

fn classify_context_bundle_reference(reference: &str) -> ContextBundleReference {
    let Some(context_reference) = reference.strip_prefix("ctx-") else {
        return ContextBundleReference::Static;
    };
    let Some(digest) = context_reference.strip_suffix(".json") else {
        return ContextBundleReference::InvalidContext;
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return ContextBundleReference::InvalidContext;
    }
    ContextBundleReference::ValidContext(format!("ctx:{digest}"))
}

fn context_error(error: ContextAuthorityFailure) -> HarnessError {
    let (code, detail, retryable, recovery) = match error {
        ContextAuthorityFailure::Expired => (
            HarnessErrorCode::InvalidArgument,
            "CONTEXT_SNAPSHOT_EXPIRED",
            false,
            true,
        ),
        ContextAuthorityFailure::Revoked => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_SNAPSHOT_REVOKED",
            false,
            true,
        ),
        ContextAuthorityFailure::NotFound => (
            HarnessErrorCode::DependencyUnavailable,
            "CONTEXT_SNAPSHOT_UNAVAILABLE",
            true,
            true,
        ),
        _ => (
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_SNAPSHOT_INVALID",
            false,
            true,
        ),
    };
    material_error(code, detail, retryable, recovery)
}

fn material_error(
    code: HarnessErrorCode,
    detail: &str,
    retryable_delivery: bool,
    recovery_required: bool,
) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery,
        recovery_required,
        error_fingerprint: Some(sha256(detail.as_bytes())),
        audit_ref: Some("agentosd:context-dispatch-material".to_owned()),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_canonical_context_bundle_names() {
        let digest = "ab".repeat(32);
        assert_eq!(
            classify_context_bundle_reference(&format!("ctx-{digest}.json")),
            ContextBundleReference::ValidContext(format!("ctx:{digest}"))
        );
        assert_eq!(
            classify_context_bundle_reference("static-bundle.json"),
            ContextBundleReference::Static
        );
        assert_eq!(
            classify_context_bundle_reference("ctx-not-a-digest.json"),
            ContextBundleReference::InvalidContext
        );
        assert_eq!(
            classify_context_bundle_reference(&format!("ctx-{}.json", "AB".repeat(32))),
            ContextBundleReference::InvalidContext
        );
    }

    #[test]
    fn malformed_context_reference_fails_before_static_file_resolution() {
        let resolver = ContextBoundDispatchMaterialResolver::new(
            FileDispatchMaterialResolver::new("missing-bundles", "missing-workspaces"),
            None,
        );
        for reference in [
            "ctx-not-a-digest.json".to_owned(),
            format!("ctx-{}.json", "AB".repeat(32)),
            format!("ctx-{}", "ab".repeat(32)),
        ] {
            let error = resolver
                .resolve(&DispatchEnvelope {
                    input_bundle_ref: reference,
                    ..Default::default()
                })
                .expect_err("malformed ctx reference must fail closed");
            assert_eq!(error.code, HarnessErrorCode::ConfigInvalid as i32);
            assert_eq!(error.safe_detail_code, "CONTEXT_BUNDLE_REFERENCE_INVALID");
        }
    }

    #[test]
    fn revoked_expired_and_integrity_failures_are_non_retryable_recovery_errors() {
        for (failure, detail) in [
            (ContextAuthorityFailure::Revoked, "CONTEXT_SNAPSHOT_REVOKED"),
            (ContextAuthorityFailure::Expired, "CONTEXT_SNAPSHOT_EXPIRED"),
            (
                ContextAuthorityFailure::IntegrityFailure,
                "CONTEXT_SNAPSHOT_INVALID",
            ),
        ] {
            let error = context_error(failure);
            assert_eq!(error.safe_detail_code, detail);
            assert!(!error.retryable_delivery);
            assert!(error.recovery_required);
        }
    }
}
