//! Daemon-owned work-capability discovery and future-work preference.
//!
//! This module deliberately does not own Provider admission or Task routing.
//! It projects already-admitted immutable routes and, for v3 configuration,
//! atomically changes only the default used by later work preparation.

use crate::bootstrap::{
    ProviderAdmission, ProviderBootstrapProfile, ProviderHarnessKind, ProviderId,
};
use egopulse_domain_contracts::{
    v01::egopulse::{
        localapi::v1::{
            ListWorkCapabilitiesResult, SetDefaultWorkCapabilityRequest,
            WorkCapabilityAvailability, WorkCapabilityPreferenceReceipt,
            WorkCapabilityPreferenceView, WorkCapabilitySelectionSource, WorkCapabilityView,
        },
        task::v1::WorkCapabilityRouteBinding,
    },
    work_capability::{
        WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES, validate_work_capability_route_binding,
    },
};
use egopulse_local_api::command_gateway::{
    CommandPrincipal, WorkCapabilityPort, WorkCapabilityPortFailure,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    fs::{self, File, OpenOptions, Permissions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tempfile::NamedTempFile;
use thiserror::Error;

const V3_SCHEMA_VERSION: &str = "egopulse.production-bootstrap/v3";
const WORK_CAPABILITIES_FIELD: &str = "work_capabilities";
const DEFAULT_CHOICE_FIELD: &str = "default_choice_id";
const PREFERENCE_REVISION_FIELD: &str = "preference_revision";
const MAX_BOOTSTRAP_FILE_BYTES: u64 = 4 * 1024 * 1024;

const CANDIDATE_REASON: &str = "provider_profile_candidate";
const HELD_REASON: &str = "provider_profile_held";
const ROUTE_NOT_ADMITTED_REASON: &str = "work_capability_route_not_admitted";

/// Immutable route resolution returned to work preparation.
///
/// The route is cloned from the sealed registry input. No executable,
/// credential, mutable catalog object, or native driver is carried here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedWorkCapability {
    pub(crate) choice_id: String,
    pub(crate) route: WorkCapabilityRouteBinding,
    pub(crate) selection_source: WorkCapabilitySelectionSource,
    pub(crate) preference_revision_at_resolution: Option<u64>,
}

impl ResolvedWorkCapability {
    pub fn choice_id(&self) -> &str {
        &self.choice_id
    }

    pub fn route(&self) -> &WorkCapabilityRouteBinding {
        &self.route
    }

    pub fn selection_source(&self) -> WorkCapabilitySelectionSource {
        self.selection_source
    }

    pub fn preference_revision_at_resolution(&self) -> Option<u64> {
        self.preference_revision_at_resolution
    }

    /// Restores an immutable resolution from a validated compiled Context.
    ///
    /// This is intentionally narrower than a general constructor: callers may
    /// only rebuild the facts that were sealed by work preparation, and the
    /// same source/revision invariants used by live resolution are enforced.
    pub(crate) fn restore_from_compiled_context(
        choice_id: String,
        route: WorkCapabilityRouteBinding,
        selection_source: WorkCapabilitySelectionSource,
        preference_revision_at_resolution: Option<u64>,
    ) -> Result<Self, WorkCapabilityPortFailure> {
        validate_choice_id(&choice_id)?;
        validate_work_capability_route_binding(&route)
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        match selection_source {
            WorkCapabilitySelectionSource::FutureWorkDefault
            | WorkCapabilitySelectionSource::LegacyOmittedDefault
                if preference_revision_at_resolution.is_some_and(|revision| revision > 0) => {}
            WorkCapabilitySelectionSource::ExplicitChoice
                if preference_revision_at_resolution.is_none() => {}
            _ => return Err(WorkCapabilityPortFailure::IntegrityFailure),
        }
        Ok(Self {
            choice_id,
            route,
            selection_source,
            preference_revision_at_resolution,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkCapabilityRegistryError {
    #[error("work-capability choice identifier is invalid")]
    InvalidChoiceId,
    #[error("work-capability route is not a valid sealed route")]
    InvalidAdmittedRoute,
    #[error("work-capability route does not match exactly one production profile/model")]
    AdmittedRouteProfileMismatch,
    #[error("work-capability choices are not unique")]
    DuplicateChoice,
    #[error("work-capability routes are ambiguous")]
    AmbiguousAdmittedRoute,
    #[error("future-work default is not an admitted choice")]
    InvalidDefaultChoice,
    #[error("future-work preference revision must be positive")]
    InvalidPreferenceRevision,
}

#[derive(Clone)]
struct AdmittedCapability {
    choice_id: String,
    route: WorkCapabilityRouteBinding,
}

#[derive(Clone)]
struct PreferenceState {
    default_choice_id: String,
    revision: u64,
}

/// Safe registry for immutable work routes and the mutable future-work
/// preference. The Local API gateway authenticates and authorizes callers
/// before invoking the [`WorkCapabilityPort`] methods.
pub struct WorkCapabilityRegistry {
    config_path: PathBuf,
    capabilities: Vec<WorkCapabilityView>,
    admitted_by_choice: BTreeMap<String, AdmittedCapability>,
    migration_required: bool,
    preference: Mutex<PreferenceState>,
}

impl WorkCapabilityRegistry {
    /// Builds a narrow registry around one already-sealed admitted route.
    ///
    /// Every configured profile/model remains visible, but only the unique
    /// production model that exactly matches `admitted_route` is selectable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_path: PathBuf,
        profiles: &[ProviderBootstrapProfile],
        admitted_route: WorkCapabilityRouteBinding,
        choice_id: String,
        preference_revision: u64,
        migration_required: bool,
    ) -> Result<Self, WorkCapabilityRegistryError> {
        Self::from_admitted_capabilities(
            config_path,
            profiles,
            vec![AdmittedCapability {
                choice_id: choice_id.clone(),
                route: admitted_route,
            }],
            choice_id,
            preference_revision,
            migration_required,
        )
    }

    /// Resolves the current future-work default without mutating configuration.
    pub fn resolve_default(&self) -> Result<ResolvedWorkCapability, WorkCapabilityPortFailure> {
        let preference = self
            .preference
            .lock()
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        self.resolve_locked(
            &preference.default_choice_id,
            WorkCapabilitySelectionSource::FutureWorkDefault,
            Some(preference.revision),
        )
    }

    /// Resolves an omitted legacy preference through the same governed
    /// default while preserving the compatibility source in the binding.
    pub(crate) fn resolve_legacy_default(
        &self,
    ) -> Result<ResolvedWorkCapability, WorkCapabilityPortFailure> {
        let preference = self
            .preference
            .lock()
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        self.resolve_locked(
            &preference.default_choice_id,
            WorkCapabilitySelectionSource::LegacyOmittedDefault,
            Some(preference.revision),
        )
    }

    /// Resolves an explicit public choice into its immutable admitted route.
    pub fn resolve_choice(
        &self,
        choice_id: &str,
    ) -> Result<ResolvedWorkCapability, WorkCapabilityPortFailure> {
        validate_choice_id(choice_id)?;
        self.resolve_locked(
            choice_id,
            WorkCapabilitySelectionSource::ExplicitChoice,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn replace_preference_for_test(&self, default_choice_id: &str, revision: u64) {
        let mut preference = self.preference.lock().expect("test preference lock");
        preference.default_choice_id = default_choice_id.to_owned();
        preference.revision = revision;
    }

    /// Returns the safe list projection corresponding exactly to a resolved
    /// immutable route. The route remains historical; the display-only
    /// default flag reflects the current future-work preference.
    pub(crate) fn projection_for_resolution(
        &self,
        resolved: &ResolvedWorkCapability,
    ) -> Result<WorkCapabilityView, WorkCapabilityPortFailure> {
        validate_choice_id(&resolved.choice_id)?;
        validate_work_capability_route_binding(&resolved.route)
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        let admitted = self
            .admitted_by_choice
            .get(&resolved.choice_id)
            .ok_or(WorkCapabilityPortFailure::CapabilityNotAdmitted)?;
        if admitted.route != resolved.route {
            return Err(WorkCapabilityPortFailure::IntegrityFailure);
        }

        let preference = self
            .preference
            .lock()
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        match resolved.selection_source {
            WorkCapabilitySelectionSource::FutureWorkDefault
            | WorkCapabilitySelectionSource::LegacyOmittedDefault
                if resolved
                    .preference_revision_at_resolution
                    .is_some_and(|revision| revision > 0 && revision <= preference.revision) => {}
            WorkCapabilitySelectionSource::ExplicitChoice
                if resolved.preference_revision_at_resolution.is_none() => {}
            _ => return Err(WorkCapabilityPortFailure::IntegrityFailure),
        }

        let mut view = self
            .capabilities
            .iter()
            .find(|view| {
                view.selectable
                    && view.choice_id.as_deref() == Some(resolved.choice_id.as_str())
                    && view.admitted_route.as_ref() == Some(&resolved.route)
            })
            .cloned()
            .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;
        view.current_future_work_default =
            view.choice_id.as_deref() == Some(preference.default_choice_id.as_str());
        Ok(view)
    }

    fn resolve_locked(
        &self,
        choice_id: &str,
        selection_source: WorkCapabilitySelectionSource,
        preference_revision_at_resolution: Option<u64>,
    ) -> Result<ResolvedWorkCapability, WorkCapabilityPortFailure> {
        let admitted = self
            .admitted_by_choice
            .get(choice_id)
            .ok_or(WorkCapabilityPortFailure::CapabilityNotAdmitted)?;
        Ok(ResolvedWorkCapability {
            choice_id: admitted.choice_id.clone(),
            route: admitted.route.clone(),
            selection_source,
            preference_revision_at_resolution,
        })
    }

    fn from_admitted_capabilities(
        config_path: PathBuf,
        profiles: &[ProviderBootstrapProfile],
        admitted_capabilities: Vec<AdmittedCapability>,
        default_choice_id: String,
        preference_revision: u64,
        migration_required: bool,
    ) -> Result<Self, WorkCapabilityRegistryError> {
        if admitted_capabilities.is_empty() || validate_choice_id(&default_choice_id).is_err() {
            return Err(WorkCapabilityRegistryError::InvalidDefaultChoice);
        }
        if preference_revision == 0 {
            return Err(WorkCapabilityRegistryError::InvalidPreferenceRevision);
        }

        let mut admitted_by_choice = BTreeMap::new();
        let mut admitted_model_keys = HashSet::new();
        for admitted in admitted_capabilities {
            if validate_choice_id(&admitted.choice_id).is_err() {
                return Err(WorkCapabilityRegistryError::InvalidChoiceId);
            }
            validate_work_capability_route_binding(&admitted.route)
                .map_err(|_| WorkCapabilityRegistryError::InvalidAdmittedRoute)?;

            let matches = profile_model_matches(profiles, &admitted.route);
            if matches.len() != 1 {
                return Err(WorkCapabilityRegistryError::AdmittedRouteProfileMismatch);
            }
            if !admitted_model_keys.insert(matches[0]) {
                return Err(WorkCapabilityRegistryError::AmbiguousAdmittedRoute);
            }
            if admitted_by_choice
                .insert(admitted.choice_id.clone(), admitted)
                .is_some()
            {
                return Err(WorkCapabilityRegistryError::DuplicateChoice);
            }
        }
        if !admitted_by_choice.contains_key(&default_choice_id) {
            return Err(WorkCapabilityRegistryError::InvalidDefaultChoice);
        }

        let mut capabilities = Vec::new();
        for (profile_index, profile) in profiles.iter().enumerate() {
            for (model_index, model) in profile.models.iter().enumerate() {
                let admitted = admitted_by_choice.values().find(|admitted| {
                    route_matches_profile_model(&admitted.route, profile, model_index)
                });
                let (availability, selectable, safe_reason_code, choice_id, admitted_route) =
                    if let Some(admitted) = admitted {
                        (
                            WorkCapabilityAvailability::Admitted,
                            true,
                            None,
                            Some(admitted.choice_id.clone()),
                            Some(admitted.route.clone()),
                        )
                    } else {
                        let (availability, reason) = match profile.admission {
                            ProviderAdmission::Candidate => {
                                (WorkCapabilityAvailability::Candidate, CANDIDATE_REASON)
                            }
                            ProviderAdmission::Held => {
                                (WorkCapabilityAvailability::Held, HELD_REASON)
                            }
                            ProviderAdmission::Production => {
                                (WorkCapabilityAvailability::Held, ROUTE_NOT_ADMITTED_REASON)
                            }
                        };
                        (availability, false, Some(reason.to_owned()), None, None)
                    };

                capabilities.push(WorkCapabilityView {
                    provider_profile_id: profile.profile_id.clone(),
                    provider_alias: provider_id(profile.provider).to_owned(),
                    harness_alias: harness_id(profile.harness).to_owned(),
                    harness_model_alias: model.harness_model_id.clone(),
                    provider_model_alias: model.provider_model_id.clone(),
                    availability: availability as i32,
                    selectable,
                    safe_reason_code,
                    choice_id: choice_id.clone(),
                    admitted_route,
                    current_future_work_default: choice_id.as_deref()
                        == Some(default_choice_id.as_str()),
                });

                debug_assert_eq!(
                    admitted_model_keys.contains(&(profile_index, model_index)),
                    selectable
                );
            }
        }
        capabilities.sort_by(|left, right| {
            (
                &left.provider_profile_id,
                &left.harness_model_alias,
                &left.provider_model_alias,
            )
                .cmp(&(
                    &right.provider_profile_id,
                    &right.harness_model_alias,
                    &right.provider_model_alias,
                ))
        });

        Ok(Self {
            config_path,
            capabilities,
            admitted_by_choice,
            migration_required,
            preference: Mutex::new(PreferenceState {
                default_choice_id,
                revision: preference_revision,
            }),
        })
    }

    fn list_result(&self) -> Result<ListWorkCapabilitiesResult, WorkCapabilityPortFailure> {
        let preference = self
            .preference
            .lock()
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        if !self
            .admitted_by_choice
            .contains_key(&preference.default_choice_id)
        {
            return Err(WorkCapabilityPortFailure::IntegrityFailure);
        }

        let mut capabilities = self.capabilities.clone();
        for capability in &mut capabilities {
            capability.current_future_work_default =
                capability.choice_id.as_deref() == Some(preference.default_choice_id.as_str());
        }
        Ok(ListWorkCapabilitiesResult {
            capabilities,
            preference: Some(WorkCapabilityPreferenceView {
                default_choice_id: preference.default_choice_id.clone(),
                preference_revision: preference.revision,
                configuration_migration_required: self.migration_required,
            }),
        })
    }

    fn set_default_inner(
        &self,
        request: &SetDefaultWorkCapabilityRequest,
    ) -> Result<WorkCapabilityPreferenceReceipt, WorkCapabilityPortFailure> {
        validate_choice_id(&request.choice_id)?;
        if self.migration_required {
            return Err(WorkCapabilityPortFailure::ConfigurationMigrationRequired);
        }
        if !self.admitted_by_choice.contains_key(&request.choice_id) {
            return Err(WorkCapabilityPortFailure::CapabilityNotAdmitted);
        }

        let mut preference = self
            .preference
            .lock()
            .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
        if request.expected_preference_revision != preference.revision {
            return Err(WorkCapabilityPortFailure::StateRevisionConflict);
        }

        let _process_lock = ConfigurationLock::acquire(&self.config_path)?;
        let original = read_bounded_config(&self.config_path)?;
        let updated = validate_and_render_v3_update(&original, &preference, &request.choice_id)?;

        let receipt = WorkCapabilityPreferenceReceipt {
            previous_default_choice_id: preference.default_choice_id.clone(),
            default_choice_id: request.choice_id.clone(),
            previous_preference_revision: preference.revision,
            preference_revision: preference.revision,
            changed: false,
        };
        let Some((updated_bytes, next_revision)) = updated else {
            return Ok(receipt);
        };

        persist_complete_config(&self.config_path, &original, &updated_bytes)?;
        let receipt = WorkCapabilityPreferenceReceipt {
            preference_revision: next_revision,
            changed: true,
            ..receipt
        };
        preference.default_choice_id = request.choice_id.clone();
        preference.revision = next_revision;
        Ok(receipt)
    }
}

impl WorkCapabilityPort for WorkCapabilityRegistry {
    fn list(
        &self,
        _principal: &CommandPrincipal,
    ) -> Result<ListWorkCapabilitiesResult, WorkCapabilityPortFailure> {
        self.list_result()
    }

    fn set_default(
        &self,
        request: &SetDefaultWorkCapabilityRequest,
        _principal: &CommandPrincipal,
    ) -> Result<WorkCapabilityPreferenceReceipt, WorkCapabilityPortFailure> {
        self.set_default_inner(request)
    }
}

fn profile_model_matches(
    profiles: &[ProviderBootstrapProfile],
    route: &WorkCapabilityRouteBinding,
) -> Vec<(usize, usize)> {
    profiles
        .iter()
        .enumerate()
        .flat_map(|(profile_index, profile)| {
            profile
                .models
                .iter()
                .enumerate()
                .filter_map(move |(model_index, _)| {
                    route_matches_profile_model(route, profile, model_index)
                        .then_some((profile_index, model_index))
                })
        })
        .collect()
}

fn route_matches_profile_model(
    route: &WorkCapabilityRouteBinding,
    profile: &ProviderBootstrapProfile,
    model_index: usize,
) -> bool {
    let Some(model) = profile.models.get(model_index) else {
        return false;
    };
    profile.admission == ProviderAdmission::Production
        && route.provider_profile_id == profile.profile_id
        && route.provider_id == provider_id(profile.provider)
        && route.harness_id == harness_id(profile.harness)
        && route.harness_model_id == model.harness_model_id
        && route.provider_model_id == model.provider_model_id
        && profile.exact_model == model.harness_model_id
        && route.catalog_snapshot_sha256
            == profile
                .catalog_snapshot
                .as_ref()
                .map(|snapshot| snapshot.evidence_digest_sha256.clone())
}

fn provider_id(provider: ProviderId) -> &'static str {
    match provider {
        ProviderId::Gpt => "gpt",
        ProviderId::DeepSeek => "deepseek",
        ProviderId::Kimi => "kimi",
        ProviderId::Glm => "glm",
    }
}

fn harness_id(harness: ProviderHarnessKind) -> &'static str {
    match harness {
        ProviderHarnessKind::CodexAppServer => "codex_app_server",
        ProviderHarnessKind::DshAcp => "dsh_acp",
        ProviderHarnessKind::KimiCliAcp => "kimi_cli_acp",
        ProviderHarnessKind::OpenCodeAcp => "opencode_acp",
    }
}

fn validate_choice_id(choice_id: &str) -> Result<(), WorkCapabilityPortFailure> {
    if choice_id.is_empty()
        || choice_id.len() > WORK_CAPABILITY_ROUTE_IDENTITY_MAX_BYTES
        || choice_id.trim() != choice_id
        || choice_id.chars().any(char::is_control)
    {
        return Err(WorkCapabilityPortFailure::InvalidArgument);
    }
    Ok(())
}

struct ConfigurationLock {
    _file: File,
}

impl ConfigurationLock {
    fn acquire(config_path: &Path) -> Result<Self, WorkCapabilityPortFailure> {
        let path = sibling_path(config_path, ".work-capability.lock")?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
        file.try_lock()
            .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
        Ok(Self { _file: file })
    }
}

fn read_bounded_config(path: &Path) -> Result<Vec<u8>, WorkCapabilityPortFailure> {
    let mut file = File::open(path).map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_BOOTSTRAP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    if bytes.len() as u64 > MAX_BOOTSTRAP_FILE_BYTES {
        return Err(WorkCapabilityPortFailure::IntegrityFailure);
    }
    Ok(bytes)
}

fn validate_and_render_v3_update(
    original: &[u8],
    preference: &PreferenceState,
    requested_choice_id: &str,
) -> Result<Option<(Vec<u8>, u64)>, WorkCapabilityPortFailure> {
    let mut document: Value = serde_json::from_slice(original)
        .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
    let root = document
        .as_object_mut()
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;
    if root.get("schema_version").and_then(Value::as_str) != Some(V3_SCHEMA_VERSION) {
        return Err(WorkCapabilityPortFailure::IntegrityFailure);
    }
    let work_capabilities = root
        .get_mut(WORK_CAPABILITIES_FIELD)
        .and_then(Value::as_object_mut)
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;
    let file_default = work_capabilities
        .get(DEFAULT_CHOICE_FIELD)
        .and_then(Value::as_str)
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?
        .to_owned();
    let file_revision = work_capabilities
        .get(PREFERENCE_REVISION_FIELD)
        .and_then(Value::as_u64)
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;

    if file_revision != preference.revision {
        return Err(WorkCapabilityPortFailure::StateRevisionConflict);
    }
    if file_default != preference.default_choice_id {
        return Err(WorkCapabilityPortFailure::IntegrityFailure);
    }
    if requested_choice_id == preference.default_choice_id {
        return Ok(None);
    }

    let next_revision = preference
        .revision
        .checked_add(1)
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;
    work_capabilities.insert(
        DEFAULT_CHOICE_FIELD.to_owned(),
        Value::String(requested_choice_id.to_owned()),
    );
    work_capabilities.insert(
        PREFERENCE_REVISION_FIELD.to_owned(),
        Value::Number(next_revision.into()),
    );
    let mut updated = serde_json::to_vec_pretty(&document)
        .map_err(|_| WorkCapabilityPortFailure::IntegrityFailure)?;
    updated.push(b'\n');
    if updated.len() as u64 > MAX_BOOTSTRAP_FILE_BYTES {
        return Err(WorkCapabilityPortFailure::IntegrityFailure);
    }
    Ok(Some((updated, next_revision)))
}

fn persist_complete_config(
    config_path: &Path,
    original: &[u8],
    updated: &[u8],
) -> Result<(), WorkCapabilityPortFailure> {
    persist_complete_config_with_backup(config_path, original, updated, ".bak")
}

/// Persists an explicit schema transition under the same process lock used
/// by future-work preference CAS updates. The exact bytes previewed by the
/// caller must still be current after the lock is acquired.
pub(crate) fn persist_explicit_config_transition(
    config_path: &Path,
    expected_original: &[u8],
    replacement: &[u8],
    backup_suffix: &str,
) -> Result<PathBuf, WorkCapabilityPortFailure> {
    let _process_lock = ConfigurationLock::acquire(config_path)?;
    let current = read_bounded_config(config_path)?;
    if current != expected_original {
        return Err(WorkCapabilityPortFailure::StateRevisionConflict);
    }
    persist_complete_config_with_backup(
        config_path,
        expected_original,
        replacement,
        backup_suffix,
    )?;
    sibling_path(config_path, backup_suffix)
}

fn persist_complete_config_with_backup(
    config_path: &Path,
    original: &[u8],
    updated: &[u8],
    backup_suffix: &str,
) -> Result<(), WorkCapabilityPortFailure> {
    let parent = nonempty_parent(config_path);
    let permissions = fs::metadata(config_path)
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?
        .permissions();
    let backup_path = sibling_path(config_path, backup_suffix)?;

    // Prepare both complete files before replacing either destination.
    let replacement = prepare_synced_temp(parent, updated, &permissions)?;
    let backup = prepare_synced_temp(parent, original, &permissions)?;
    persist_and_sync(backup, &backup_path)?;
    persist_and_sync(replacement, config_path)?;
    Ok(())
}

fn prepare_synced_temp(
    parent: &Path,
    bytes: &[u8],
    permissions: &Permissions,
) -> Result<NamedTempFile, WorkCapabilityPortFailure> {
    let mut temp =
        NamedTempFile::new_in(parent).map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    temp.write_all(bytes)
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    temp.flush()
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    temp.as_file()
        .sync_all()
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    fs::set_permissions(temp.path(), permissions.clone())
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    Ok(temp)
}

fn persist_and_sync(
    temp: NamedTempFile,
    destination: &Path,
) -> Result<(), WorkCapabilityPortFailure> {
    let file = temp
        .persist(destination)
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)?;
    file.sync_all()
        .map_err(|_| WorkCapabilityPortFailure::Unavailable)
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf, WorkCapabilityPortFailure> {
    let file_name = path
        .file_name()
        .ok_or(WorkCapabilityPortFailure::IntegrityFailure)?;
    let mut sibling_name = OsString::from(file_name);
    sibling_name.push(suffix);
    Ok(path.with_file_name(sibling_name))
}

fn nonempty_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        ProviderCatalogSnapshot, ProviderCredentialReference, ProviderModelBinding,
    };
    use egopulse_domain_contracts::{
        v01::egopulse::common::v1::ContractReference,
        work_capability::seal_work_capability_route_binding,
    };
    use serde_json::json;
    use std::{
        process::Command,
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };
    use tempfile::tempdir;

    const SECRET: &str = "provider-secret-must-not-leak";

    fn principal() -> CommandPrincipal {
        CommandPrincipal {
            principal_id: "local-user:test".to_owned(),
            required_authority_principal_kinds: Vec::new(),
        }
    }

    fn profile(
        profile_id: &str,
        admission: ProviderAdmission,
        harness_model: &str,
        provider_model: &str,
    ) -> ProviderBootstrapProfile {
        ProviderBootstrapProfile {
            profile_id: profile_id.to_owned(),
            provider: ProviderId::Gpt,
            harness: ProviderHarnessKind::CodexAppServer,
            admission,
            models: vec![ProviderModelBinding {
                harness_model_id: harness_model.to_owned(),
                provider_model_id: provider_model.to_owned(),
            }],
            catalog_snapshot: Some(ProviderCatalogSnapshot {
                source: "fixture".to_owned(),
                fetched_at: "2026-09-05T00:00:00Z".to_owned(),
                harness_version: "fixture-v1".to_owned(),
                evidence_digest_sha256: "b".repeat(64),
            }),
            exact_model: harness_model.to_owned(),
            executable: PathBuf::from("must-not-be-projected.exe"),
            credential: ProviderCredentialReference::ApiKeyEnvironment {
                source_env: "DO_NOT_PROJECT_SOURCE".to_owned(),
                target_env: "DO_NOT_PROJECT_TARGET".to_owned(),
            },
            hold_reason: Some("must-not-be-projected-hold-detail".to_owned()),
        }
    }

    fn route(profile_id: &str, model: &str, generation: u64) -> WorkCapabilityRouteBinding {
        seal_work_capability_route_binding(WorkCapabilityRouteBinding {
            route_id: format!("route:{profile_id}:{model}:{generation}"),
            route_generation: generation,
            provider_profile_id: profile_id.to_owned(),
            provider_id: "gpt".to_owned(),
            harness_id: "codex_app_server".to_owned(),
            harness_model_id: model.to_owned(),
            provider_model_id: format!("provider-{model}"),
            capability_profile_ref: Some(ContractReference {
                contract_id: "egopulse.harness.codex".to_owned(),
                version: "1.0.0".to_owned(),
                sha256: "a".repeat(64),
            }),
            catalog_snapshot_sha256: Some("b".repeat(64)),
            native_composition_generation: "codex-native:v1".to_owned(),
            route_binding_sha256: String::new(),
        })
        .expect("seal route")
    }

    fn write_v3(path: &Path, default: &str, revision: u64) {
        let bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": V3_SCHEMA_VERSION,
            "identity": { "credential_material": SECRET },
            "provider_profiles": [{
                "executable": "must-not-be-projected.exe",
                "credential": SECRET
            }],
            "work_capabilities": {
                "default_choice_id": default,
                "preference_revision": revision,
                "routes": [{ "preserved": true }]
            }
        }))
        .expect("serialize v3 fixture");
        fs::write(path, bytes).expect("write v3 fixture");
    }

    fn request(choice_id: &str, revision: u64) -> SetDefaultWorkCapabilityRequest {
        SetDefaultWorkCapabilityRequest {
            client: None,
            choice_id: choice_id.to_owned(),
            expected_preference_revision: revision,
        }
    }

    fn two_route_registry(path: &Path) -> WorkCapabilityRegistry {
        let profiles = vec![
            profile(
                "provider-profile:a",
                ProviderAdmission::Production,
                "model-a",
                "provider-model-a",
            ),
            profile(
                "provider-profile:b",
                ProviderAdmission::Production,
                "model-b",
                "provider-model-b",
            ),
        ];
        WorkCapabilityRegistry::from_admitted_capabilities(
            path.to_path_buf(),
            &profiles,
            vec![
                AdmittedCapability {
                    choice_id: "choice-a".to_owned(),
                    route: route("provider-profile:a", "model-a", 1),
                },
                AdmittedCapability {
                    choice_id: "choice-b".to_owned(),
                    route: route("provider-profile:b", "model-b", 2),
                },
            ],
            "choice-a".to_owned(),
            1,
            false,
        )
        .expect("two-route test registry")
    }

    #[test]
    fn work_capability_held_and_candidate_are_visible_but_never_selectable_or_writable() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-production", 7);
        let before = fs::read(&config_path).expect("read before");
        let profiles = vec![
            profile(
                "provider-profile:production",
                ProviderAdmission::Production,
                "model-production",
                "provider-model-production",
            ),
            profile(
                "provider-profile:candidate",
                ProviderAdmission::Candidate,
                "model-candidate",
                "provider-model-candidate",
            ),
            profile(
                "provider-profile:held",
                ProviderAdmission::Held,
                "model-held",
                "provider-model-held",
            ),
        ];
        let registry = WorkCapabilityRegistry::new(
            config_path.clone(),
            &profiles,
            route("provider-profile:production", "model-production", 1),
            "choice-production".to_owned(),
            7,
            false,
        )
        .expect("registry");

        let listed = registry.list(&principal()).expect("list");
        assert_eq!(listed.capabilities.len(), 3);
        let selectable = listed
            .capabilities
            .iter()
            .filter(|view| view.selectable)
            .collect::<Vec<_>>();
        assert_eq!(selectable.len(), 1);
        assert!(selectable[0].admitted_route.is_some());
        for blocked in listed.capabilities.iter().filter(|view| !view.selectable) {
            assert!(blocked.choice_id.is_none());
            assert!(blocked.admitted_route.is_none());
            assert!(blocked.safe_reason_code.is_some());
        }

        assert_eq!(
            registry.set_default(&request("choice-held", 7), &principal()),
            Err(WorkCapabilityPortFailure::CapabilityNotAdmitted)
        );
        assert_eq!(fs::read(&config_path).expect("read after"), before);
        assert!(
            !sibling_path(&config_path, ".bak")
                .expect("backup path")
                .exists()
        );
    }

    #[test]
    fn work_capability_cas_and_same_value_replay_are_zero_write() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-a", 3);
        let profiles = vec![profile(
            "provider-profile:a",
            ProviderAdmission::Production,
            "model-a",
            "provider-model-a",
        )];
        let registry = WorkCapabilityRegistry::new(
            config_path.clone(),
            &profiles,
            route("provider-profile:a", "model-a", 1),
            "choice-a".to_owned(),
            3,
            false,
        )
        .expect("registry");
        let before = fs::read(&config_path).expect("read before");

        assert_eq!(
            registry.set_default(&request("choice-a", 2), &principal()),
            Err(WorkCapabilityPortFailure::StateRevisionConflict)
        );
        let receipt = registry
            .set_default(&request("choice-a", 3), &principal())
            .expect("same-value replay");
        assert!(!receipt.changed);
        assert_eq!(receipt.preference_revision, 3);
        assert_eq!(fs::read(&config_path).expect("read after"), before);
        assert!(
            !sibling_path(&config_path, ".bak")
                .expect("backup path")
                .exists()
        );
    }

    #[test]
    fn work_capability_default_change_only_changes_future_resolution() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-a", 1);
        let registry = two_route_registry(&config_path);

        let resolved_before = registry.resolve_default().expect("resolve default before");
        let legacy_before = registry
            .resolve_legacy_default()
            .expect("resolve legacy default before");
        let explicit_before = registry
            .resolve_choice("choice-b")
            .expect("resolve explicit before");
        let receipt = registry
            .set_default(&request("choice-b", 1), &principal())
            .expect("set default");
        let resolved_after = registry.resolve_default().expect("resolve default after");
        let explicit_after = registry
            .resolve_choice("choice-b")
            .expect("resolve explicit after");

        assert!(receipt.changed);
        assert_eq!(receipt.preference_revision, 2);
        assert_eq!(resolved_before.choice_id, "choice-a");
        assert_eq!(resolved_before.route.route_generation, 1);
        assert_eq!(
            resolved_before.selection_source,
            WorkCapabilitySelectionSource::FutureWorkDefault
        );
        assert_eq!(legacy_before.choice_id, "choice-a");
        assert_eq!(
            legacy_before.selection_source,
            WorkCapabilitySelectionSource::LegacyOmittedDefault
        );
        assert_eq!(legacy_before.preference_revision_at_resolution, Some(1));
        assert_eq!(explicit_before.choice_id, "choice-b");
        assert_eq!(
            explicit_before.selection_source,
            WorkCapabilitySelectionSource::ExplicitChoice
        );
        assert_eq!(explicit_before.preference_revision_at_resolution, None);
        assert_eq!(resolved_after.choice_id, "choice-b");
        assert_eq!(resolved_after.route, explicit_before.route);
        assert_eq!(resolved_after.preference_revision_at_resolution, Some(2));
        assert!(
            !registry
                .projection_for_resolution(&resolved_before)
                .expect("old resolution remains projectable")
                .current_future_work_default
        );
        assert!(
            !registry
                .projection_for_resolution(&legacy_before)
                .expect("legacy resolution remains projectable")
                .current_future_work_default
        );
        assert!(
            registry
                .projection_for_resolution(&explicit_before)
                .expect("old explicit resolution remains projectable")
                .current_future_work_default
        );
        assert!(
            registry
                .projection_for_resolution(&resolved_after)
                .expect("new resolution projection")
                .current_future_work_default
        );
        assert!(
            registry
                .projection_for_resolution(&explicit_after)
                .expect("new explicit resolution projection")
                .current_future_work_default
        );
        assert_eq!(resolved_before.choice_id, "choice-a");
    }

    #[test]
    fn work_capability_v2_mutation_requires_explicit_migration_and_writes_nothing() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        let v2 = br#"{"schema_version":"egopulse.production-bootstrap/v2","secret":"untouched"}"#;
        fs::write(&config_path, v2).expect("write v2");
        let profiles = vec![profile(
            "provider-profile:a",
            ProviderAdmission::Production,
            "model-a",
            "provider-model-a",
        )];
        let registry = WorkCapabilityRegistry::new(
            config_path.clone(),
            &profiles,
            route("provider-profile:a", "model-a", 1),
            "choice-a".to_owned(),
            1,
            true,
        )
        .expect("v2 read-compatible registry");

        assert_eq!(
            registry.set_default(&request("choice-a", 1), &principal()),
            Err(WorkCapabilityPortFailure::ConfigurationMigrationRequired)
        );
        assert_eq!(fs::read(&config_path).expect("read after"), v2);
        assert!(
            registry
                .list(&principal())
                .expect("list")
                .preference
                .expect("preference")
                .configuration_migration_required
        );
    }

    #[test]
    fn work_capability_cross_registry_race_commits_at_most_once() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-a", 1);
        let first = two_route_registry(&config_path);
        let second = two_route_registry(&config_path);
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let spawn = |registry: WorkCapabilityRegistry, barrier: Arc<std::sync::Barrier>| {
            thread::spawn(move || {
                barrier.wait();
                registry.set_default(&request("choice-b", 1), &principal())
            })
        };
        let first = spawn(first, Arc::clone(&barrier));
        let second = spawn(second, Arc::clone(&barrier));
        barrier.wait();
        let outcomes = [first.join().expect("first"), second.join().expect("second")];

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(receipt) if receipt.changed))
                .count(),
            1
        );
        assert!(outcomes.iter().any(|outcome| {
            matches!(
                outcome,
                Err(WorkCapabilityPortFailure::Unavailable)
                    | Err(WorkCapabilityPortFailure::StateRevisionConflict)
            )
        }));
        let document: Value = serde_json::from_slice(&fs::read(&config_path).expect("read final"))
            .expect("parse final");
        assert_eq!(
            document[WORK_CAPABILITIES_FIELD][DEFAULT_CHOICE_FIELD],
            "choice-b"
        );
        assert_eq!(
            document[WORK_CAPABILITIES_FIELD][PREFERENCE_REVISION_FIELD],
            2
        );
    }

    #[test]
    fn work_capability_lock_recovers_from_a_stale_file_and_remains_exclusive() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        let lock_path = sibling_path(&config_path, ".work-capability.lock").expect("lock path");
        fs::write(&lock_path, b"legacy-stale-lock-file").expect("legacy stale lock file");

        let first = ConfigurationLock::acquire(&config_path).expect("acquire stale lock file");
        assert!(matches!(
            ConfigurationLock::acquire(&config_path),
            Err(WorkCapabilityPortFailure::Unavailable)
        ));
        drop(first);
        ConfigurationLock::acquire(&config_path).expect("reacquire after owner exit");
    }

    #[test]
    fn work_capability_lock_child_process() {
        let Ok(config_path) = std::env::var("EGOPULSE_LOCK_TEST_CONFIG") else {
            return;
        };
        let marker_path =
            std::env::var("EGOPULSE_LOCK_TEST_MARKER").expect("lock child marker environment");
        let _lock = ConfigurationLock::acquire(Path::new(&config_path))
            .expect("child process acquires configuration lock");
        fs::write(marker_path, b"locked").expect("publish child lock marker");
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn work_capability_lock_is_released_after_process_termination() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        let marker_path = temp.path().join("child.locked");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("work_capability::tests::work_capability_lock_child_process")
            .arg("--nocapture")
            .env("EGOPULSE_LOCK_TEST_CONFIG", &config_path)
            .env("EGOPULSE_LOCK_TEST_MARKER", &marker_path)
            .spawn()
            .expect("spawn lock owner process");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker_path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            marker_path.exists(),
            "child did not acquire lock before deadline"
        );
        assert!(matches!(
            ConfigurationLock::acquire(&config_path),
            Err(WorkCapabilityPortFailure::Unavailable)
        ));

        child.kill().expect("terminate lock owner process");
        let reap_deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .expect("poll terminated lock owner process")
            {
                break status;
            }
            assert!(
                Instant::now() < reap_deadline,
                "terminated lock owner process was not reaped before deadline"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            !status.success(),
            "hard-terminated lock owner must not report successful exit: {status}"
        );
        ConfigurationLock::acquire(&config_path)
            .expect("OS releases configuration lock after hard termination");
    }

    #[test]
    fn work_capability_outputs_never_spread_executable_or_credentials() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-a", 1);
        let registry = two_route_registry(&config_path);
        let listed = registry.list(&principal()).expect("list");
        let receipt = registry
            .set_default(&request("choice-b", 1), &principal())
            .expect("set default");
        let resolution = registry.resolve_default().expect("resolve default");
        let public_debug = format!("{listed:?}{receipt:?}{resolution:?}");
        assert!(!public_debug.contains(SECRET));
        assert!(!public_debug.contains("must-not-be-projected.exe"));
        assert!(!public_debug.contains("DO_NOT_PROJECT_SOURCE"));
        assert!(!public_debug.contains("must-not-be-projected-hold-detail"));

        let mut file_names = fs::read_dir(temp.path())
            .expect("read fixture directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        file_names.sort();
        assert_eq!(
            file_names,
            vec![
                "agentos.json",
                "agentos.json.bak",
                "agentos.json.work-capability.lock"
            ]
        );
        let files_with_secret = file_names
            .iter()
            .filter(|name| {
                fs::read_to_string(temp.path().join(name))
                    .expect("read durable file")
                    .contains(SECRET)
            })
            .count();
        // The complete current file and the one explicitly required backup
        // retain the existing value; no lock/temp/public projection copies it.
        assert_eq!(files_with_secret, 2);

        let current: Value = serde_json::from_slice(&fs::read(&config_path).expect("read current"))
            .expect("parse current");
        let backup: Value = serde_json::from_slice(
            &fs::read(sibling_path(&config_path, ".bak").expect("backup path"))
                .expect("read backup"),
        )
        .expect("parse backup");
        assert_eq!(current["identity"], backup["identity"]);
        assert_eq!(current["provider_profiles"], backup["provider_profiles"]);
    }

    #[test]
    fn work_capability_v3_validation_fails_closed_on_state_drift() {
        let temp = tempdir().expect("tempdir");
        let config_path = temp.path().join("agentos.json");
        write_v3(&config_path, "choice-a", 9);
        let before = fs::read(&config_path).expect("read before");
        let registry = two_route_registry(&config_path);

        assert_eq!(
            registry.set_default(&request("choice-b", 1), &principal()),
            Err(WorkCapabilityPortFailure::StateRevisionConflict)
        );
        assert_eq!(fs::read(&config_path).expect("read after"), before);
    }
}
