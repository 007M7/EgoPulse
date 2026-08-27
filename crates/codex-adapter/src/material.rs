use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    DispatchEnvelope, HarnessError, HarnessErrorCode,
};
use egopulse_harness_adapter::{DispatchMaterialResolver, ResolvedDispatchMaterial};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

const DEFAULT_MAX_INPUT_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

/// Resolves the immutable, provider-neutral input bundle used by a Codex
/// dispatch. References are logical relative paths under configured roots;
/// they never become arbitrary filesystem paths supplied to the harness.
#[derive(Clone, Debug)]
pub struct FileDispatchMaterialResolver {
    input_bundle_root: PathBuf,
    workspace_root: PathBuf,
    default_model: Option<String>,
    max_input_bundle_bytes: usize,
}

impl FileDispatchMaterialResolver {
    #[must_use]
    pub fn new(input_bundle_root: impl Into<PathBuf>, workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            input_bundle_root: input_bundle_root.into(),
            workspace_root: workspace_root.into(),
            default_model: None,
            max_input_bundle_bytes: DEFAULT_MAX_INPUT_BUNDLE_BYTES,
        }
    }

    #[must_use]
    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = Some(model.into());
        self
    }

    #[must_use]
    pub fn with_max_input_bundle_bytes(mut self, limit: usize) -> Self {
        self.max_input_bundle_bytes = limit;
        self
    }
}

impl DispatchMaterialResolver for FileDispatchMaterialResolver {
    fn resolve(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError> {
        let bundle_path = resolve_existing_reference(
            &self.input_bundle_root,
            &envelope.input_bundle_ref,
            "INPUT_BUNDLE_REFERENCE_INVALID",
            "INPUT_BUNDLE_UNAVAILABLE",
        )?;
        let canonical_input_bundle = std::fs::read(&bundle_path).map_err(|_| {
            material_error(
                HarnessErrorCode::DependencyUnavailable,
                "INPUT_BUNDLE_UNAVAILABLE",
                true,
                false,
            )
        })?;
        if canonical_input_bundle.len() > self.max_input_bundle_bytes {
            return Err(material_error(
                HarnessErrorCode::InvalidArgument,
                "INPUT_BUNDLE_TOO_LARGE",
                false,
                false,
            ));
        }
        if sha256(&canonical_input_bundle) != envelope.input_bundle_sha256 {
            return Err(material_error(
                HarnessErrorCode::IntegrityFailure,
                "INPUT_BUNDLE_DIGEST_MISMATCH",
                false,
                true,
            ));
        }
        let bundle = serde_json::from_slice::<Value>(&canonical_input_bundle).map_err(|_| {
            material_error(
                HarnessErrorCode::InvalidArgument,
                "INPUT_BUNDLE_JSON_INVALID",
                false,
                false,
            )
        })?;
        let prompt = bundle
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                material_error(
                    HarnessErrorCode::InvalidArgument,
                    "INPUT_BUNDLE_PROMPT_REQUIRED",
                    false,
                    false,
                )
            })?
            .to_owned();
        let model = bundle
            .get("model")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| self.default_model.clone());
        let workspace_root = resolve_existing_reference(
            &self.workspace_root,
            &envelope.workspace_ref,
            "WORKSPACE_REFERENCE_INVALID",
            "WORKSPACE_UNAVAILABLE",
        )?;
        if !workspace_root.is_dir() {
            return Err(material_error(
                HarnessErrorCode::DependencyUnavailable,
                "WORKSPACE_UNAVAILABLE",
                false,
                true,
            ));
        }
        Ok(ResolvedDispatchMaterial {
            canonical_input_bundle,
            prompt,
            workspace_root,
            model,
        })
    }
}

fn resolve_existing_reference(
    root: &Path,
    reference: &str,
    invalid_detail: &str,
    unavailable_detail: &str,
) -> Result<PathBuf, HarnessError> {
    if reference.trim().is_empty()
        || Path::new(reference)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(material_error(
            HarnessErrorCode::ConfigInvalid,
            invalid_detail,
            false,
            false,
        ));
    }
    let canonical_root = std::fs::canonicalize(root).map_err(|_| {
        material_error(
            HarnessErrorCode::DependencyUnavailable,
            unavailable_detail,
            true,
            false,
        )
    })?;
    let candidate = std::fs::canonicalize(canonical_root.join(reference)).map_err(|_| {
        material_error(
            HarnessErrorCode::DependencyUnavailable,
            unavailable_detail,
            true,
            false,
        )
    })?;
    if !candidate.starts_with(&canonical_root) {
        return Err(material_error(
            HarnessErrorCode::ConfigInvalid,
            invalid_detail,
            false,
            false,
        ));
    }
    Ok(candidate)
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
        audit_ref: Some("codex-adapter:dispatch-material".to_owned()),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_harness_adapter::DispatchMaterialResolver;
    use std::fs;
    use uuid::Uuid;

    fn envelope(bundle: &[u8]) -> DispatchEnvelope {
        DispatchEnvelope {
            input_bundle_ref: "bundle-001.json".to_owned(),
            input_bundle_sha256: sha256(bundle),
            workspace_ref: "workspace-001".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn resolves_digest_bound_bundle_and_workspace_without_leaking_paths() {
        let root = std::env::temp_dir().join(format!("egopulse-codex-material-{}", Uuid::now_v7()));
        let bundles = root.join("bundles");
        let workspaces = root.join("workspaces");
        let workspace = workspaces.join("workspace-001");
        fs::create_dir_all(&workspace).expect("workspace directory");
        let bundle = br#"{"prompt":"inspect the repository","model":"codex-mini"}"#;
        fs::create_dir_all(&bundles).expect("bundle directory");
        fs::write(bundles.join("bundle-001.json"), bundle).expect("bundle file");

        let material = FileDispatchMaterialResolver::new(&bundles, &workspaces)
            .resolve(&envelope(bundle))
            .expect("resolve bundle");
        assert_eq!(material.canonical_input_bundle, bundle);
        assert_eq!(material.prompt, "inspect the repository");
        assert_eq!(material.model.as_deref(), Some("codex-mini"));
        assert_eq!(
            material.workspace_root,
            fs::canonicalize(workspace).expect("canonical workspace")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_digest_mismatch_and_path_escape_before_reading() {
        let resolver = FileDispatchMaterialResolver::new("bundles", "workspaces");
        let mut digest_mismatch = envelope(b"{}");
        digest_mismatch.input_bundle_sha256 = "00".repeat(32);
        let error = resolver
            .resolve(&digest_mismatch)
            .expect_err("missing bundle first");
        assert_eq!(error.safe_detail_code, "INPUT_BUNDLE_UNAVAILABLE");

        let mut escaped = envelope(b"{}");
        escaped.input_bundle_ref = "..\\secret.json".to_owned();
        let error = resolver.resolve(&escaped).expect_err("path escape");
        assert_eq!(error.safe_detail_code, "INPUT_BUNDLE_REFERENCE_INVALID");
    }
}
