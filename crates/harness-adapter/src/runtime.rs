use crate::{
    AdapterEdge, AdapterEdgeError, AdapterObservationEvidence, ContentDisclosureError,
    ContentDisclosureMode, DispatchPreparation, DurableWritePreparation,
    FinalArtifactRelationPolicy, LegacyExecutionStartEvidence,
    LegacyExecutionStartEvidenceRejection, LegacyExecutionStartEvidenceResolution,
    NormalObservationRecoveryView, PendingAdapterApprovalProjection, SafeContentCommit,
    TrustedContentLineage, bind_content_signal, canonical_safe_record_digest, project_safe_content,
    project_structured_only_content,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ApprovalDecisionEnvelope, ApprovalDecisionReceipt, ApprovalDecisionResult,
    AuthorizedContextConsumptionProof, CancelExecutionEnvelope, CancelExecutionReceipt,
    CancelExecutionResult, CancellationDeliveryDisposition, DeliveryDisposition,
    DiagnosticObservation, DispatchContextConsumptionProof, DispatchEnvelope, DispatchReceipt,
    DispatchResult, DispatchRouteBinding, HarnessError, HarnessErrorCode, HarnessObservation,
    HarnessReadiness, LifecycleKind, NativeProtocolFingerprint, NotContextBoundProof,
    ObservationCriticality, ProbeHarnessRequest, ProbeHarnessResult, ResumeExecutionEnvelope,
    ResumeExecutionResult, approval_decision_result, cancel_execution_result,
    dispatch_context_consumption_proof, dispatch_result, harness_observation,
    resume_execution_result,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub trait AdapterClock {
    fn now(&self) -> Timestamp;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAdapterClock;

impl AdapterClock for SystemAdapterClock {
    fn now(&self) -> Timestamp {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp {
            seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(duration.subsec_nanos()).unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDispatchMaterial {
    pub canonical_input_bundle: Vec<u8>,
    pub prompt: String,
    pub workspace_root: PathBuf,
    pub model: Option<String>,
}

pub trait DispatchMaterialResolver {
    fn resolve(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<ResolvedDispatchMaterial, HarnessError>;
}

/// Optional, read-only material check for a dispatch that Adapter Edge has
/// proven has never crossed the native delivery boundary. Replay and
/// DeliveryUnknown bypass this hook by construction.
pub trait ReadyDispatchMaterialGuard: Send + Sync {
    fn validate_ready_dispatch<'a>(
        &'a self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> Pin<Box<dyn Future<Output = Result<(), HarnessError>> + Send + 'a>>;
}

/// Canonical classification of the dispatch input reference at the Adapter
/// boundary. Context-backed references are intentionally recognized here so a
/// malformed `ctx-`/`ctx:` value can never fall through to a static resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchContextReference {
    NotContextBound,
    ContextSnapshot { snapshot_id: String },
    InvalidContextBinding,
}

#[must_use]
pub fn classify_dispatch_context_reference(reference: &str) -> DispatchContextReference {
    if let Some(context_reference) = reference.strip_prefix("ctx-") {
        let Some(digest) = context_reference.strip_suffix(".json") else {
            return DispatchContextReference::InvalidContextBinding;
        };
        if canonical_sha256_is_valid(digest) {
            return DispatchContextReference::ContextSnapshot {
                snapshot_id: format!("ctx:{digest}"),
            };
        }
        return DispatchContextReference::InvalidContextBinding;
    }
    if reference.starts_with("ctx:") {
        return DispatchContextReference::InvalidContextBinding;
    }
    DispatchContextReference::NotContextBound
}

/// Immutable Context Authority binding independently compared with the
/// dispatch envelope, resolved bytes and authorization receipt by the Adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContextBinding {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub expected_scope_ref: String,
    pub memory_pack: Option<DispatchMemoryPackBinding>,
}

/// Memory facts embedded in the immutable ContextSnapshot and independently
/// compared with the Context Authority use receipt before delivery begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchMemoryPackBinding {
    pub memory_authority_revision: u64,
    pub memory_pack_snapshot_sha256: String,
}

/// Complete durable per-route Memory-use receipt. This is evidence that the
/// exact pack was made available to this governed dispatch, not evidence of
/// Provider delivery or model influence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchMemoryUseReceipt {
    pub receipt_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub consumer_principal_id: String,
    pub model_ref: String,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub memory_authority_revision: u64,
    pub memory_pack_snapshot_sha256: String,
    pub request_digest_sha256: String,
    pub replayed: bool,
}

/// Complete durable Context dispatch-consumption receipt. Keeping every field
/// at this boundary prevents a gate implementation from reducing Authority
/// evidence to a boolean decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchContextAuthorizationReceipt {
    pub authorization_id: String,
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub observed_state_revision: u64,
    pub attempt_id: String,
    pub dispatch_id: String,
    pub input_digest_sha256: String,
    pub expected_scope_ref: String,
    pub request_digest_sha256: String,
    pub event_id: String,
    pub committed_at_seconds: i64,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedDispatchContext {
    pub binding: DispatchContextBinding,
    pub receipt: DispatchContextAuthorizationReceipt,
    pub memory_use: Option<DispatchMemoryUseReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchContextAuthorization {
    NotContextBound,
    Authorized(Box<AuthorizedDispatchContext>),
}

/// Authority-owned Context authorization seam used by normal dispatch. The
/// existing-dispatch entry is contractually read-only: Replay and
/// DeliveryUnknown must never mint authorization after the native boundary may
/// already have been crossed.
pub trait DispatchContextAuthorizationGate: Send {
    fn authorize_ready_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError>;

    fn verify_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError>;
}

/// Immutable Context identity carried into reconciliation. This binding is
/// intentionally separate from normal-dispatch authorization and contains no
/// permission or authorization identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalDispatchContextBinding {
    pub snapshot_id: String,
    pub snapshot_revision: u64,
    pub content_digest_sha256: String,
    pub expected_scope_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoricalDispatchContextState {
    Issued,
    Revoked,
}

/// Authority-owned immutable Context material available solely for recovering
/// a dispatch whose authorization lineage already exists. This type does not
/// represent permission to begin or send a dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalDispatchContext {
    pub binding: HistoricalDispatchContextBinding,
    pub authority_immutable_bytes: Vec<u8>,
    pub observed_state_revision: u64,
    pub observed_state: HistoricalDispatchContextState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchContextRecovery {
    NotContextBound,
    Historical(Box<HistoricalDispatchContext>),
}

/// Read-only Context recovery seam. Implementations may only recover immutable
/// material for an existing exact dispatch authorization lineage; they must
/// never mint authorization or confer send permission.
pub trait DispatchContextRecoveryGate: Send {
    fn recover_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextRecovery, HarnessError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct RejectContextAuthorizationGate;

impl DispatchContextAuthorizationGate for RejectContextAuthorizationGate {
    fn authorize_ready_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError> {
        reject_context_authorization(&envelope.input_bundle_ref)
    }

    fn verify_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextAuthorization, HarnessError> {
        reject_context_authorization(&envelope.input_bundle_ref)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RejectContextRecoveryGate;

impl DispatchContextRecoveryGate for RejectContextRecoveryGate {
    fn recover_existing_dispatch(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextRecovery, HarnessError> {
        reject_context_recovery(&envelope.input_bundle_ref)
    }
}

struct AuthorizedDispatchMaterial {
    material: ResolvedDispatchMaterial,
    _context: Option<AuthorizedDispatchContext>,
}

impl AuthorizedDispatchMaterial {
    fn material(&self) -> &ResolvedDispatchMaterial {
        &self.material
    }
}

struct HistoricalDispatchMaterial {
    material: ResolvedDispatchMaterial,
    _context: Option<HistoricalDispatchContext>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverErrorCertainty {
    ProvenNotSent,
    DeliveryUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverError {
    pub certainty: DriverErrorCertainty,
    pub code: HarnessErrorCode,
    pub safe_detail_code: String,
    pub error_fingerprint: Option<String>,
    pub raw_evidence: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverDelivery {
    pub native_request_ref: String,
    pub native_session_ref: String,
    pub native_execution_ref: Option<String>,
    pub raw_evidence: Vec<u8>,
}

/// Provider-neutral output bytes that are still only a collector candidate.
///
/// This boundary deliberately stops before Artifact Authority. The bytes and
/// native completion reference can be handed to a governed collector, but
/// they are not an ArtifactReturnObservation, a Claim, or a completion fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalOutputCandidate {
    pub dispatch_id: String,
    pub native_completion_ref: String,
    pub media_type: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DriverEvent {
    pub native_key: String,
    pub native_event_id: Option<String>,
    pub native_sequence: Option<u64>,
    pub native_observed_at: Timestamp,
    pub criticality: ObservationCriticality,
    pub payload: harness_observation::Payload,
    pub raw_event: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationFinding {
    NoEffectProven { evidence_ref: String },
    NativeExecutionActive { evidence_ref: String },
    TerminalObservationRecovered { evidence_ref: String },
    OutcomeUnknown { evidence_ref: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterReconciliationEvidence {
    pub reconciliation_id: String,
    pub dispatch_id: String,
    pub evidence_id: String,
    pub raw_evidence_ref: String,
    pub finding: ReconciliationFinding,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationContext {
    pub envelope: DispatchEnvelope,
    pub delivery_receipt: Option<DispatchReceipt>,
    pub material: ResolvedDispatchMaterial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyExecutionStartRawContext {
    pub prior_raw_event: Vec<u8>,
    pub pending_raw_event: Vec<u8>,
    pub native_session_ref: String,
    pub native_execution_ref: String,
    pub terminal_raw_event: Option<Vec<u8>>,
    pub terminal_native_completion_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyExecutionStartRawClassification {
    ExactDuplicate { durable_terminal_handoff: bool },
    Conflict,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyExecutionStartRecovery {
    ExactDuplicate(Box<LegacyExecutionStartEvidence>),
    OwnerMismatch,
    Unverified { reason_code: &'static str },
    Unsupported,
}

pub type NativeHarnessFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait NativeHarnessDriver {
    /// Reports whether this driver can accept a new dispatch without replacing
    /// an already-active native execution. Drivers that support concurrent
    /// dispatches keep the permissive default.
    #[must_use]
    fn is_dispatch_ready(&self) -> bool {
        true
    }

    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>>;

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>>;

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>>;

    /// Returns committed native output only as a candidate for a separate
    /// governed collector. Drivers that cannot expose committed output keep
    /// the default `None` and remain lifecycle-only at this boundary.
    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        _envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        Box::pin(async { Ok(None) })
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>>;

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>>;

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>>;

    fn classify_legacy_execution_start(
        &self,
        _context: &LegacyExecutionStartRawContext,
    ) -> LegacyExecutionStartRawClassification {
        LegacyExecutionStartRawClassification::Unsupported
    }
}

// A daemon that composes more than one provider needs to hold heterogeneous
// native drivers behind one runner collection. Keep the type-erasure utility
// at the provider-neutral adapter boundary; no provider-specific code needs to
// know how another provider is stored.
impl NativeHarnessDriver for Box<dyn NativeHarnessDriver + Send> {
    fn is_dispatch_ready(&self) -> bool {
        (**self).is_dispatch_ready()
    }

    fn probe<'a>(
        &'a mut self,
        request: &'a ProbeHarnessRequest,
    ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
        (**self).probe(request)
    }

    fn send_dispatch<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
        material: &'a ResolvedDispatchMaterial,
    ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
        (**self).send_dispatch(envelope, material)
    }

    fn next_event<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
        (**self).next_event(envelope)
    }

    fn take_terminal_output_candidate<'a>(
        &'a mut self,
        envelope: &'a DispatchEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
        (**self).take_terminal_output_candidate(envelope)
    }

    fn decide_approval<'a>(
        &'a mut self,
        envelope: &'a ApprovalDecisionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        (**self).decide_approval(envelope)
    }

    fn cancel<'a>(
        &'a mut self,
        envelope: &'a CancelExecutionEnvelope,
    ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
        (**self).cancel(envelope)
    }

    fn reconcile<'a>(
        &'a mut self,
        context: &'a ReconciliationContext,
    ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
        (**self).reconcile(context)
    }

    fn classify_legacy_execution_start(
        &self,
        context: &LegacyExecutionStartRawContext,
    ) -> LegacyExecutionStartRawClassification {
        (**self).classify_legacy_execution_start(context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProbeValidationError {
    #[error("probe result has no stable probe ID")]
    ProbeIdMissing,
    #[error("probe result has no observation timestamp")]
    ObservationTimeMissing,
    #[error("probe result marked ready without an observed protocol fingerprint")]
    ObservedProtocolMissing,
    #[error("probe result marked ready without evidence")]
    EvidenceMissing,
    #[error("probe result marked ready with an incomplete protocol fingerprint")]
    ProtocolFingerprintIncomplete,
    #[error(
        "probe result marked ready with a protocol fingerprint that does not match the request"
    )]
    ProtocolFingerprintMismatch,
    #[error("probe result contains an unknown readiness value")]
    ReadinessInvalid,
}

#[derive(Debug, Error)]
pub enum GovernedAdapterError {
    #[error("persisted adapter data could not be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error("adapter durable edge failed")]
    Edge(#[from] AdapterEdgeError),
    #[error("reconciliation reference is invalid")]
    InvalidReconciliationReference,
    #[error("the durable dispatch could not be found")]
    DispatchNotFound,
    #[error("durable reconciliation evidence is invalid")]
    InvalidReconciliationEvidence,
    #[error("durable delivered dispatch recovery evidence is invalid")]
    InvalidDeliveredRecoveryEvidence,
    #[error("process-local Adapter residency evidence is unavailable")]
    ResidencyEvidenceUnavailable,
    #[error("native terminal output candidate extraction failed")]
    TerminalOutputCandidate,
    #[error("terminal observation append is deferred while the Adapter Edge is busy")]
    ObservationAppendDeferred {
        #[source]
        source: AdapterEdgeError,
    },
    #[error("Harness content disclosure failed closed")]
    ContentDisclosure(#[from] ContentDisclosureError),
}

impl GovernedAdapterError {
    /// Constructs the storage-owner failure used by downstream worker tests.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn observation_append_busy_for_test() -> Self {
        Self::ObservationAppendDeferred {
            source: AdapterEdgeError::Sql(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                None,
            )),
        }
    }

    /// Returns true only for the retained-observation retry boundary that is
    /// safe to retry within this Adapter process.
    #[must_use]
    pub fn is_retryable_observation_append(&self) -> bool {
        matches!(
            self,
            Self::ObservationAppendDeferred { source }
                if is_retryable_observation_append_failure(source)
        )
    }
}

#[derive(Default)]
struct AdapterRuntimeResidencyState {
    resident_dispatches: HashSet<String>,
    active_nonresident_observations: HashMap<String, usize>,
}

/// Read-only capability for the process-local residency state of one concrete
/// `GovernedHarnessAdapter` instance.
///
/// A reopened `AdapterEdge` cannot construct this capability. Composition must
/// obtain it from the same Adapter instance owned by the dispatch runner and
/// give it to the Authority evidence resolver.
#[derive(Clone)]
pub struct AdapterRuntimeResidencyReader {
    adapter_id: String,
    state: Arc<Mutex<AdapterRuntimeResidencyState>>,
}

impl AdapterRuntimeResidencyReader {
    #[must_use]
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    /// Returns true only while the owning Adapter has an active, scoped
    /// observation proving that this dispatch is absent from its resident set.
    /// Lock failure is an error so Authority callers can fail closed.
    pub fn observes_nonresident_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, GovernedAdapterError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GovernedAdapterError::ResidencyEvidenceUnavailable)?;
        Ok(!state.resident_dispatches.contains(dispatch_id)
            && state
                .active_nonresident_observations
                .get(dispatch_id)
                .is_some_and(|count| *count > 0))
    }
}

/// Scoped proof that the owning Adapter observed a dispatch as nonresident.
/// Dropping the value removes the proof, so a durable receipt cannot reuse it
/// outside the exact Authority call which requested the observation.
pub struct NonresidentDispatchObservation {
    dispatch_id: String,
    state: Arc<Mutex<AdapterRuntimeResidencyState>>,
}

impl Drop for NonresidentDispatchObservation {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(count) = state
            .active_nonresident_observations
            .get_mut(&self.dispatch_id)
        else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            state
                .active_nonresident_observations
                .remove(&self.dispatch_id);
        }
    }
}

pub struct GovernedHarnessAdapter<R, D, C> {
    adapter_id: String,
    capability_profile_id: String,
    observed_protocol: NativeProtocolFingerprint,
    edge: AdapterEdge,
    resolver: R,
    driver: D,
    clock: C,
    context_authorization_gate: Box<dyn DispatchContextAuthorizationGate>,
    context_authorization_gate_installed: bool,
    context_recovery_gate: Box<dyn DispatchContextRecoveryGate>,
    expected_route_binding: Option<ExpectedDispatchRouteBinding>,
    disclosure_credentials: ManagedDisclosureCredentials,
    final_artifact_relation_policy: FinalArtifactRelationPolicy,
    ready_dispatch_material_guard: Option<std::sync::Arc<dyn ReadyDispatchMaterialGuard>>,
    // This is intentionally process-local. A persisted Delivered receipt only
    // proves a prior native side effect; it cannot prove a restarted adapter
    // still owns a live native session that may be polled for terminal events.
    runtime_residency: Arc<Mutex<AdapterRuntimeResidencyState>>,
    // Driver events are destructive reads. Keep the exact event-derived
    // observation and any terminal candidate here until the Edge atomically
    // records both, so a transient Edge failure cannot release native capacity.
    pending_observation_append: Option<PendingObservationAppend>,
    #[cfg(test)]
    next_observation_append_failure_for_test: Option<TestObservationAppendFailure>,
}

#[cfg(test)]
enum TestObservationAppendFailure {
    DatabaseBusy,
    IntegrityFailure,
}

struct PendingObservationAppend {
    dispatch_id: String,
    attempt_id: String,
    fencing_token: u64,
    native_key: String,
    raw_event: Vec<u8>,
    observation: HarnessObservation,
    terminal_output: Option<TerminalOutputCandidate>,
    terminal: bool,
    received_at_seconds: i64,
}

impl PendingObservationAppend {
    fn matches(&self, envelope: &DispatchEnvelope) -> bool {
        self.dispatch_id == envelope.dispatch_id
            && self.attempt_id == envelope.attempt_id
            && self.fencing_token == envelope.fencing_token
    }
}

fn is_retryable_observation_append_failure(error: &AdapterEdgeError) -> bool {
    matches!(
        error,
        AdapterEdgeError::Sql(error)
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            )
    )
}

/// Credentials a managed disclosure path may use for one native send.
///
/// `Clone` exists because a profile-bound multi-route composition installs one
/// independent runner per admitted route from a single resolved credential
/// set: each runner owns its own copy rather than sharing one value across
/// futures. The resolved secret is held in [`Zeroizing`], so a clone is
/// zeroized on drop like its origin.
#[derive(Clone)]
pub enum ManagedDisclosureCredentials {
    HarnessAccount,
    ManagedAvailable(Zeroizing<Vec<String>>),
    ManagedUnavailable,
    ManagedOutOfBounds,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessContentDrain {
    Idle,
    Committed(crate::SafeContentCommit),
    FinalArtifactRelationCommitted,
    FinalArtifactRelationPending,
    FinalArtifactRelationSkipped,
    Replayed,
    Quarantined { reason_code: &'static str },
}

/// Content-only projector. It owns a separate Adapter Edge connection and has
/// no Driver or material resolver, so content failures cannot escape through
/// the execution/Task/Approval pump.
pub struct GovernedHarnessContentProjector<C> {
    edge: AdapterEdge,
    disclosure_credentials: ManagedDisclosureCredentials,
    clock: C,
}

impl<C> GovernedHarnessContentProjector<C>
where
    C: AdapterClock,
{
    #[must_use]
    pub fn new(
        edge: AdapterEdge,
        disclosure_credentials: ManagedDisclosureCredentials,
        clock: C,
    ) -> Self {
        Self {
            edge,
            disclosure_credentials,
            clock,
        }
    }

    #[must_use]
    pub const fn edge(&self) -> &AdapterEdge {
        &self.edge
    }

    pub fn drain_once(&mut self) -> Result<HarnessContentDrain, GovernedAdapterError> {
        let Some(pending) = self.edge.pending_content_candidates()?.into_iter().next() else {
            let Some(intent) = self.edge.pending_final_artifact_relation_intent()? else {
                return Ok(HarnessContentDrain::Idle);
            };
            return match self
                .edge
                .commit_final_artifact_relation(&intent, self.clock.now().seconds)?
            {
                crate::FinalArtifactRelationCommit::Committed(_)
                | crate::FinalArtifactRelationCommit::Replay(_) => {
                    Ok(HarnessContentDrain::FinalArtifactRelationCommitted)
                }
                crate::FinalArtifactRelationCommit::PendingContent => {
                    Ok(HarnessContentDrain::FinalArtifactRelationPending)
                }
                crate::FinalArtifactRelationCommit::Ambiguous => {
                    Ok(HarnessContentDrain::Quarantined {
                        reason_code: "FINAL_ARTIFACT_RELATION_AMBIGUOUS",
                    })
                }
                crate::FinalArtifactRelationCommit::RawMismatch => {
                    Ok(HarnessContentDrain::Quarantined {
                        reason_code: "FINAL_ARTIFACT_RELATION_RAW_MISMATCH",
                    })
                }
                crate::FinalArtifactRelationCommit::Skipped(_) => {
                    Ok(HarnessContentDrain::FinalArtifactRelationSkipped)
                }
            };
        };
        let now_seconds = self.clock.now().seconds;
        let dispatch_id = pending.observation.dispatch_id.as_str();
        let envelope = self
            .edge
            .dispatch_envelope(dispatch_id)?
            .ok_or(ContentDisclosureError::SourceBinding)?;
        let route_binding = self
            .edge
            .dispatch_route_binding(dispatch_id)?
            .filter(|binding| envelope.route_binding.as_ref() == Some(binding))
            .ok_or(ContentDisclosureError::SourceBinding)?;
        let receipt = self
            .edge
            .delivered_dispatch_receipt(dispatch_id)?
            .filter(|receipt| {
                let recorded_digest = receipt.receipt_digest_sha256.as_str();
                let mut canonical = receipt.clone();
                canonical.receipt_digest_sha256.clear();
                receipt.receipt_id == pending.signal.delivered_receipt_id
                    && recorded_digest == pending.signal.delivered_receipt_digest_sha256
                    && canonical_sha256_is_valid(recorded_digest)
                    && canonical_digest(&canonical) == recorded_digest
                    && receipt.disposition == DeliveryDisposition::Delivered as i32
                    && receipt.dispatch_id == envelope.dispatch_id
                    && receipt.attempt_id == envelope.attempt_id
                    && receipt.fencing_token == envelope.fencing_token
                    && receipt.adapter_id == self.edge.adapter_id()
                    && envelope
                        .capability_profile_ref
                        .as_ref()
                        .is_some_and(|profile| profile.contract_id == receipt.capability_profile_id)
            })
            .ok_or(ContentDisclosureError::SourceBinding)?;
        let lineage = self
            .edge
            .dispatch_task_lineage(dispatch_id)?
            .ok_or(ContentDisclosureError::SourceBinding)?;
        if pending.observation.attempt_id != envelope.attempt_id
            || pending.observation.fencing_token != envelope.fencing_token
            || pending.observation.capability_profile_id != receipt.capability_profile_id
            || pending.signal.dispatch_route_binding_sha256 != route_binding.route_binding_sha256
            || crate::canonical_dispatch_route_binding_digest(&route_binding).as_deref()
                != Some(route_binding.route_binding_sha256.as_str())
        {
            return Err(ContentDisclosureError::SourceBinding.into());
        }
        let trusted_lineage = TrustedContentLineage {
            task_id: lineage.task_id,
            run_id: envelope.run_id.clone(),
            step_id: envelope.step_id.clone(),
        };
        if let Some(limit_kind) = self
            .edge
            .content_scope_limit_kind(&trusted_lineage.task_id, &pending.observation.attempt_id)?
        {
            let candidate = pending
                .signal
                .candidate
                .as_ref()
                .ok_or(ContentDisclosureError::CandidateIntegrity)?;
            crate::disclosure::validate_candidate_semantics(candidate)?;
            self.edge.settle_limited_content_candidate(
                &pending.signal.content_event_id,
                &candidate.candidate_digest_sha256,
                limit_kind,
                now_seconds,
            )?;
            return Ok(HarnessContentDrain::Committed(
                SafeContentCommit::Suppressed {
                    content_event_id: pending.signal.content_event_id,
                },
            ));
        }
        let previous = self
            .edge
            .content_projection_checkpoint(dispatch_id, &pending.signal)?;
        if let (
            Some(previous),
            Some(egopulse_domain_contracts::v01::egopulse::harness::v1::user_visible_content_candidate::Payload::AssistantText(text)),
            Some(candidate),
        ) = (
            previous.as_ref(),
            pending.signal.candidate.as_ref().and_then(|candidate| candidate.payload.as_ref()),
            pending.signal.candidate.as_ref(),
        ) && text.revision == previous.current_revision
        {
            if candidate.candidate_digest_sha256 == previous.candidate_digest_sha256 {
                self.edge.settle_replayed_content_candidate(
                    &pending.signal.content_event_id,
                    now_seconds,
                )?;
                return Ok(HarnessContentDrain::Replayed);
            }
            self.edge.quarantine_content_candidate(
                &pending.signal.content_event_id,
                "CONTENT_REVISION_DIGEST_CONFLICT",
                now_seconds,
            )?;
            return Ok(HarnessContentDrain::Quarantined {
                reason_code: "CONTENT_REVISION_DIGEST_CONFLICT",
            });
        }
        let disclosure_mode = self.edge.verify_or_bind_content_disclosure(
            dispatch_id,
            self.disclosure_credentials.values(),
            now_seconds,
        )?;
        let projection = match disclosure_mode {
            ContentDisclosureMode::Full => project_safe_content(
                &pending.observation,
                &pending.signal,
                &route_binding,
                &trusted_lineage,
                self.disclosure_credentials
                    .values()
                    .ok_or(ContentDisclosureError::CredentialInput)?,
                previous.as_ref(),
            ),
            ContentDisclosureMode::StructuredOnly => project_structured_only_content(
                &pending.observation,
                &pending.signal,
                &route_binding,
                &trusted_lineage,
                previous.as_ref(),
            ),
        };
        let projection = match projection {
            Ok(projection) => projection,
            Err(ContentDisclosureError::CandidateIntegrity) => {
                self.edge.quarantine_content_candidate(
                    &pending.signal.content_event_id,
                    "CONTENT_CANDIDATE_INTEGRITY",
                    now_seconds,
                )?;
                return Ok(HarnessContentDrain::Quarantined {
                    reason_code: "CONTENT_CANDIDATE_INTEGRITY",
                });
            }
            Err(error) => return Err(error.into()),
        };
        if projection.records().iter().any(|record| {
            canonical_safe_record_digest(record).as_deref()
                != Some(record.record_digest_sha256.as_str())
        }) {
            return Err(ContentDisclosureError::CandidateIntegrity.into());
        }
        self.edge
            .commit_safe_content_projection(&projection, now_seconds)
            .map(HarnessContentDrain::Committed)
            .map_err(Into::into)
    }
}

impl ManagedDisclosureCredentials {
    #[must_use]
    pub const fn harness_account() -> Self {
        Self::HarnessAccount
    }

    #[must_use]
    pub fn managed_available(values: Vec<String>) -> Self {
        let values = Zeroizing::new(values);
        if crate::disclosure::canonical_credential_variants(values.as_slice()).is_ok() {
            Self::ManagedAvailable(values)
        } else {
            Self::ManagedOutOfBounds
        }
    }

    #[must_use]
    pub const fn managed_unavailable() -> Self {
        Self::ManagedUnavailable
    }

    fn values(&self) -> Option<&[String]> {
        match self {
            Self::HarnessAccount => Some(&[]),
            Self::ManagedAvailable(values) => Some(values.as_slice()),
            Self::ManagedUnavailable | Self::ManagedOutOfBounds => None,
        }
    }
}

#[derive(Clone)]
struct ExpectedDispatchRouteBinding {
    binding: DispatchRouteBinding,
    harness_model_id: String,
}

impl<R, D, C> GovernedHarnessAdapter<R, D, C>
where
    R: DispatchMaterialResolver,
    D: NativeHarnessDriver,
    C: AdapterClock,
{
    #[must_use]
    pub fn new(
        adapter_id: impl Into<String>,
        capability_profile_id: impl Into<String>,
        observed_protocol: NativeProtocolFingerprint,
        edge: AdapterEdge,
        resolver: R,
        driver: D,
        clock: C,
    ) -> Self {
        Self {
            adapter_id: adapter_id.into(),
            capability_profile_id: capability_profile_id.into(),
            observed_protocol,
            edge,
            resolver,
            driver,
            clock,
            context_authorization_gate: Box::new(RejectContextAuthorizationGate),
            context_authorization_gate_installed: false,
            context_recovery_gate: Box::new(RejectContextRecoveryGate),
            expected_route_binding: None,
            disclosure_credentials: ManagedDisclosureCredentials::ManagedUnavailable,
            final_artifact_relation_policy:
                FinalArtifactRelationPolicy::NotRequiredLegacyOrLifecycleOnly,
            ready_dispatch_material_guard: None,
            runtime_residency: Arc::new(Mutex::new(AdapterRuntimeResidencyState::default())),
            pending_observation_append: None,
            #[cfg(test)]
            next_observation_append_failure_for_test: None,
        }
    }

    /// Installs the immutable route selected by trusted daemon composition.
    /// The Adapter only verifies it; it never enriches a persisted envelope.
    #[must_use]
    pub fn with_dispatch_route_binding(
        mut self,
        binding: DispatchRouteBinding,
        harness_model_id: impl Into<String>,
    ) -> Self {
        self.expected_route_binding = Some(ExpectedDispatchRouteBinding {
            binding,
            harness_model_id: harness_model_id.into(),
        });
        self
    }

    #[must_use]
    pub fn with_managed_disclosure_credentials(mut self, values: Vec<String>) -> Self {
        self.disclosure_credentials = ManagedDisclosureCredentials::managed_available(values);
        self
    }

    /// Declares that authentication is owned by the Harness account and that
    /// no daemon-managed secret is expected for disclosure redaction.
    #[must_use]
    pub fn with_harness_account_disclosure(mut self) -> Self {
        self.disclosure_credentials = ManagedDisclosureCredentials::HarnessAccount;
        self
    }

    #[must_use]
    pub fn with_disclosure_credentials(
        mut self,
        credentials: ManagedDisclosureCredentials,
    ) -> Self {
        self.disclosure_credentials = credentials;
        self
    }

    /// Persists the capability-attested return/content relation contract with
    /// every new dispatch. Existing dispatches must replay their stored policy.
    #[must_use]
    pub fn with_final_artifact_relation_policy(
        mut self,
        policy: FinalArtifactRelationPolicy,
    ) -> Self {
        self.final_artifact_relation_policy = policy;
        self
    }

    #[must_use]
    pub fn with_ready_dispatch_material_guard(
        mut self,
        guard: std::sync::Arc<dyn ReadyDispatchMaterialGuard>,
    ) -> Self {
        self.ready_dispatch_material_guard = Some(guard);
        self
    }

    /// Installs the production Context Authority bridge. Static dispatches are
    /// still admitted only when the gate explicitly returns NotContextBound.
    #[must_use]
    pub fn with_dispatch_context_authorization_gate(
        mut self,
        gate: impl DispatchContextAuthorizationGate + 'static,
    ) -> Self {
        self.context_authorization_gate = Box::new(gate);
        self.context_authorization_gate_installed = true;
        self
    }

    /// Installs the independent, read-only Context recovery bridge. It is not
    /// used by normal dispatch and cannot authorize, begin, or send work.
    #[must_use]
    pub fn with_dispatch_context_recovery_gate(
        mut self,
        gate: impl DispatchContextRecoveryGate + 'static,
    ) -> Self {
        self.context_recovery_gate = Box::new(gate);
        self
    }

    pub async fn probe(&mut self, request: &ProbeHarnessRequest) -> ProbeHarnessResult {
        if request.adapter_id != self.adapter_id {
            return invalid_probe_result(
                None,
                &self.observed_protocol,
                "PROBE_ADAPTER_ID_MISMATCH",
                self.clock.now(),
            );
        }
        match self.driver.probe(request).await {
            Ok(result) => match validate_probe_result(request, &result, &self.observed_protocol) {
                Ok(()) => result,
                Err(error) => invalid_probe_result(
                    Some(result),
                    &self.observed_protocol,
                    probe_validation_code(error),
                    self.clock.now(),
                ),
            },
            Err(error) => ProbeHarnessResult {
                probe_id: Uuid::now_v7().to_string(),
                readiness: readiness_for_error(&error) as i32,
                observed_protocol: Some(self.observed_protocol.clone()),
                safe_diagnostic_codes: vec![error.safe_detail_code],
                evidence_refs: error
                    .error_fingerprint
                    .into_iter()
                    .map(|value| format!("error-fingerprint:{value}"))
                    .collect(),
                observed_at: Some(self.clock.now()),
            },
        }
    }

    pub async fn dispatch(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchResult, GovernedAdapterError> {
        if let Some(error) = self.validate_dispatch(envelope) {
            return Ok(dispatch_error(error));
        }
        let now = self.clock.now();
        match self.edge.prepare_dispatch_with_relation_policy(
            envelope,
            self.final_artifact_relation_policy,
            now.seconds,
        )? {
            DispatchPreparation::Replay(receipt) => {
                if let Err(error) = self.verify_existing_context_authorization(envelope) {
                    return Ok(dispatch_error(error));
                }
                return Ok(dispatch_receipt(*receipt));
            }
            DispatchPreparation::DeliveryUnknown => {
                if let Err(error) = self.verify_existing_context_authorization(envelope) {
                    return Ok(dispatch_error(error));
                }
                let receipt =
                    self.delivery_unknown_receipt(envelope, "RECOVERED_UNCERTAIN_DELIVERY", &now);
                self.edge.record_dispatch_receipt(
                    &receipt,
                    b"RECOVERED_UNCERTAIN_DELIVERY",
                    now.seconds,
                )?;
                return Ok(dispatch_receipt(receipt));
            }
            DispatchPreparation::Ready => {}
        }
        let context_reference = classify_dispatch_context_reference(&envelope.input_bundle_ref);
        if context_reference == DispatchContextReference::InvalidContextBinding {
            return Ok(dispatch_error(context_binding_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_BINDING_INVALID",
                false,
            )));
        }
        if matches!(
            context_reference,
            DispatchContextReference::ContextSnapshot { .. }
        ) && !self.context_authorization_gate_installed
        {
            return Ok(dispatch_error(context_binding_error(
                HarnessErrorCode::DependencyUnavailable,
                "CONTEXT_GATE_UNAVAILABLE",
                true,
            )));
        }
        let material = match self.resolver.resolve(envelope) {
            Ok(value) => value,
            Err(error) => return Ok(dispatch_error(error)),
        };
        if sha256(&material.canonical_input_bundle) != envelope.input_bundle_sha256 {
            return Ok(dispatch_error(harness_error(
                HarnessErrorCode::IntegrityFailure,
                "INPUT_BUNDLE_DIGEST_MISMATCH",
                false,
                false,
                None,
            )));
        }
        if let Err(error) = self.validate_resolved_route(envelope, &material) {
            return Ok(dispatch_error(error));
        }

        let context_authorization = match self
            .context_authorization_gate
            .authorize_ready_dispatch(envelope)
        {
            Ok(value) => value,
            Err(error) => return Ok(dispatch_error(error)),
        };
        let material = match authorize_dispatch_material(
            envelope,
            context_reference,
            material,
            context_authorization,
        ) {
            Ok(value) => value,
            Err(error) => return Ok(dispatch_error(error)),
        };

        if let Some(guard) = self.ready_dispatch_material_guard.as_ref()
            && let Err(error) = guard
                .validate_ready_dispatch(envelope, material.material())
                .await
        {
            return Ok(dispatch_error(error));
        }

        self.edge
            .begin_delivery(&envelope.dispatch_id, now.seconds)?;
        let (receipt, raw_evidence) = match self
            .driver
            .send_dispatch(envelope, material.material())
            .await
        {
            Ok(delivery) => {
                let evidence = delivery.raw_evidence.clone();
                (
                    self.delivery_receipt(envelope, delivery, DeliveryDisposition::Delivered, &now),
                    evidence,
                )
            }
            Err(error) => {
                let disposition = match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => DeliveryDisposition::Rejected,
                    DriverErrorCertainty::DeliveryUnknown => DeliveryDisposition::Unknown,
                };
                let evidence = error.raw_evidence.clone();
                (
                    self.failed_delivery_receipt(envelope, disposition, &error, &now),
                    evidence,
                )
            }
        };
        let raw_evidence = if raw_evidence.is_empty() {
            receipt.evidence_ref.as_bytes()
        } else {
            raw_evidence.as_slice()
        };
        self.edge
            .record_dispatch_receipt(&receipt, raw_evidence, now.seconds)?;
        if receipt.disposition == DeliveryDisposition::Delivered as i32 {
            self.runtime_residency
                .lock()
                .map_err(|_| GovernedAdapterError::ResidencyEvidenceUnavailable)?
                .resident_dispatches
                .insert(envelope.dispatch_id.clone());
        }
        Ok(dispatch_receipt(receipt))
    }

    /// Returns whether this Adapter instance itself sent and durably recorded
    /// the current dispatch. Persisted receipt replay and restart recovery are
    /// deliberately excluded because they cannot establish a live native
    /// session for polling.
    #[must_use]
    pub fn has_resident_dispatch(&self, dispatch_id: &str) -> bool {
        self.runtime_residency
            .lock()
            .map(|state| state.resident_dispatches.contains(dispatch_id))
            .unwrap_or(true)
    }

    /// Returns the current driver admission state for a new native dispatch.
    /// Durable receipt replay and observation recovery use their existing
    /// paths and do not depend on this signal.
    #[must_use]
    pub fn is_dispatch_ready(&self) -> bool {
        self.pending_observation_append.is_none() && self.driver.is_dispatch_ready()
    }

    /// Exposes a read-only view of this exact Adapter instance's residency.
    /// The handle must be installed on the Authority evidence resolver paired
    /// with this Adapter by daemon composition.
    #[must_use]
    pub fn runtime_residency_reader(&self) -> AdapterRuntimeResidencyReader {
        AdapterRuntimeResidencyReader {
            adapter_id: self.adapter_id.clone(),
            state: Arc::clone(&self.runtime_residency),
        }
    }

    /// Creates a short-lived proof for one Authority call after observing that
    /// this exact Adapter instance does not own the native dispatch stream.
    pub fn observe_nonresident_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<NonresidentDispatchObservation, GovernedAdapterError> {
        let mut state = self
            .runtime_residency
            .lock()
            .map_err(|_| GovernedAdapterError::ResidencyEvidenceUnavailable)?;
        if state.resident_dispatches.contains(dispatch_id) {
            return Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence);
        }
        *state
            .active_nonresident_observations
            .entry(dispatch_id.to_owned())
            .or_default() += 1;
        drop(state);
        Ok(NonresidentDispatchObservation {
            dispatch_id: dispatch_id.to_owned(),
            state: Arc::clone(&self.runtime_residency),
        })
    }

    pub async fn pump_one(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<HarnessObservation>, GovernedAdapterError> {
        let pending = match self.pending_observation_append.take() {
            Some(pending) if pending.matches(envelope) => pending,
            Some(pending) => {
                self.pending_observation_append = Some(pending);
                return Ok(None);
            }
            None => {
                let event = match self.driver.next_event(envelope).await {
                    Ok(value) => value,
                    Err(error) => Some(driver_error_event(error, self.clock.now())),
                };
                let Some(event) = event else {
                    return Ok(None);
                };
                let received_at = self.clock.now();
                let terminal = event.criticality == ObservationCriticality::Terminal;
                let completed = terminal
                    && matches!(
                        &event.payload,
                        harness_observation::Payload::Lifecycle(lifecycle)
                            if lifecycle.kind == LifecycleKind::ExecutionCompleted as i32
                    );
                let terminal_output = if completed {
                    self.driver
                        .take_terminal_output_candidate(envelope)
                        .await
                        .map_err(|_| GovernedAdapterError::TerminalOutputCandidate)?
                } else {
                    None
                };
                let mut observation = HarnessObservation {
                    observation_id: String::new(),
                    adapter_id: self.adapter_id.clone(),
                    attempt_id: envelope.attempt_id.clone(),
                    dispatch_id: envelope.dispatch_id.clone(),
                    fencing_token: envelope.fencing_token,
                    observation_sequence: 0,
                    native_event_id: event.native_event_id,
                    native_sequence: event.native_sequence,
                    native_event_digest_sha256: String::new(),
                    capability_profile_id: self.capability_profile_id.clone(),
                    criticality: event.criticality as i32,
                    raw_evidence_ref: String::new(),
                    native_observed_at: Some(event.native_observed_at),
                    adapter_received_at: Some(received_at),
                    payload: Some(event.payload),
                };
                observation.native_event_digest_sha256 = sha256(&event.raw_event);
                if matches!(
                    observation.payload.as_ref(),
                    Some(harness_observation::Payload::ContentSignal(_))
                ) {
                    self.bind_content_observation(envelope, &mut observation)?;
                }
                PendingObservationAppend {
                    dispatch_id: envelope.dispatch_id.clone(),
                    attempt_id: envelope.attempt_id.clone(),
                    fencing_token: envelope.fencing_token,
                    native_key: event.native_key,
                    raw_event: event.raw_event,
                    observation,
                    terminal_output,
                    terminal,
                    received_at_seconds: received_at.seconds,
                }
            }
        };
        let appended = match self.append_pending_observation(&pending) {
            Ok(appended) => appended,
            Err(source) => {
                self.pending_observation_append = Some(pending);
                if is_retryable_observation_append_failure(&source) {
                    return Err(GovernedAdapterError::ObservationAppendDeferred { source });
                }
                return Err(source.into());
            }
        };
        if pending.terminal {
            self.runtime_residency
                .lock()
                .map_err(|_| GovernedAdapterError::ResidencyEvidenceUnavailable)?
                .resident_dispatches
                .remove(&envelope.dispatch_id);
        }
        Ok(Some(match appended {
            crate::ObservationAppend::Committed(value)
            | crate::ObservationAppend::Replay(value) => value,
        }))
    }

    fn append_pending_observation(
        &mut self,
        pending: &PendingObservationAppend,
    ) -> Result<crate::ObservationAppend, AdapterEdgeError> {
        #[cfg(test)]
        if let Some(failure) = self.next_observation_append_failure_for_test.take() {
            return Err(match failure {
                TestObservationAppendFailure::DatabaseBusy => {
                    AdapterEdgeError::Sql(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                        None,
                    ))
                }
                TestObservationAppendFailure::IntegrityFailure => {
                    AdapterEdgeError::IntegrityFailure
                }
            });
        }
        self.edge.append_observation_with_terminal_output(
            &pending.dispatch_id,
            &pending.native_key,
            &pending.raw_event,
            pending.observation.clone(),
            pending.terminal_output.as_ref(),
            pending.received_at_seconds,
        )
    }

    #[cfg(test)]
    fn fail_next_observation_append_with_busy_for_test(&mut self) {
        self.next_observation_append_failure_for_test =
            Some(TestObservationAppendFailure::DatabaseBusy);
    }

    #[cfg(test)]
    fn fail_next_observation_append_with_integrity_failure_for_test(&mut self) {
        self.next_observation_append_failure_for_test =
            Some(TestObservationAppendFailure::IntegrityFailure);
    }

    /// Reads a driver-owned terminal output candidate without persisting it.
    /// A caller must pass the candidate to a governed collector; this method
    /// cannot create an Artifact Authority fact by itself.
    pub async fn take_terminal_output_candidate(
        &mut self,
        envelope: &DispatchEnvelope,
    ) -> Result<Option<TerminalOutputCandidate>, DriverError> {
        self.driver.take_terminal_output_candidate(envelope).await
    }

    pub async fn decide_approval(
        &mut self,
        envelope: &ApprovalDecisionEnvelope,
    ) -> Result<ApprovalDecisionResult, GovernedAdapterError> {
        let now = self.clock.now();
        if envelope.approval_request_id.trim().is_empty()
            || envelope.dispatch_id.trim().is_empty()
            || envelope.fencing_token == 0
            || !sha256_is_valid(&envelope.action_digest_sha256)
            || envelope.authority_decision_ref.trim().is_empty()
            || envelope.native_routing_ref.trim().is_empty()
        {
            return Ok(ApprovalDecisionResult {
                outcome: Some(approval_decision_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "APPROVAL_DECISION_ENVELOPE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let request_digest = canonical_digest(envelope);
        match self.edge.prepare_approval(
            &envelope.approval_request_id,
            &envelope.dispatch_id,
            &request_digest,
            now.seconds,
        )? {
            DurableWritePreparation::Replay(bytes) => {
                return Ok(approval_receipt(ApprovalDecisionReceipt::decode(
                    bytes.as_slice(),
                )?));
            }
            DurableWritePreparation::DeliveryUnknown => {
                let receipt =
                    approval_delivery_receipt(envelope, DeliveryDisposition::Unknown, &now);
                self.edge.record_approval_receipt(
                    &envelope.approval_request_id,
                    "delivery_unknown",
                    &receipt.encode_to_vec(),
                    b"RECOVERED_UNCERTAIN_APPROVAL_DELIVERY",
                    now.seconds,
                )?;
                return Ok(approval_receipt(receipt));
            }
            DurableWritePreparation::Ready => {}
        }
        self.edge
            .begin_approval(&envelope.approval_request_id, now.seconds)?;
        let (disposition, raw) = match self.driver.decide_approval(envelope).await {
            Ok(raw) => (DeliveryDisposition::Delivered, raw),
            Err(error) => (
                match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => DeliveryDisposition::Rejected,
                    DriverErrorCertainty::DeliveryUnknown => DeliveryDisposition::Unknown,
                },
                error.raw_evidence,
            ),
        };
        let receipt = approval_delivery_receipt(envelope, disposition, &now);
        let state = match disposition {
            DeliveryDisposition::Delivered => "delivered",
            DeliveryDisposition::Rejected => "rejected",
            _ => "delivery_unknown",
        };
        self.edge.record_approval_receipt(
            &envelope.approval_request_id,
            state,
            &receipt.encode_to_vec(),
            &raw,
            now.seconds,
        )?;
        Ok(approval_receipt(receipt))
    }

    pub async fn cancel(
        &mut self,
        envelope: &CancelExecutionEnvelope,
    ) -> Result<CancelExecutionResult, GovernedAdapterError> {
        let now = self.clock.now();
        if envelope.cancellation_request_id.trim().is_empty()
            || envelope.dispatch_id.trim().is_empty()
            || envelope.attempt_id.trim().is_empty()
            || envelope.fencing_token == 0
            || envelope.native_session_ref.trim().is_empty()
            || envelope.native_execution_ref.trim().is_empty()
            || envelope.confirmation_deadline.is_none()
        {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "CANCELLATION_ENVELOPE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let request_digest = canonical_digest(envelope);
        match self.edge.prepare_cancellation(
            &envelope.cancellation_request_id,
            &envelope.dispatch_id,
            &request_digest,
            now.seconds,
        )? {
            DurableWritePreparation::Replay(replay) => {
                return Ok(cancel_receipt(CancelExecutionReceipt::decode(
                    replay.as_slice(),
                )?));
            }
            DurableWritePreparation::DeliveryUnknown => {
                let receipt = cancellation_delivery_receipt(
                    envelope,
                    CancellationDeliveryDisposition::Unknown,
                    "adapter-edge://cancel/recovered-uncertain-delivery".to_owned(),
                    &now,
                );
                self.edge.record_cancellation_receipt(
                    &envelope.cancellation_request_id,
                    "delivery_unknown",
                    &receipt.encode_to_vec(),
                    b"RECOVERED_UNCERTAIN_CANCELLATION_DELIVERY",
                    now.seconds,
                )?;
                return Ok(cancel_receipt(receipt));
            }
            DurableWritePreparation::Ready => {}
        }
        self.edge
            .begin_cancellation(&envelope.cancellation_request_id, now.seconds)?;
        let (disposition, raw, evidence_ref) = match self.driver.cancel(envelope).await {
            Ok(raw) => (
                CancellationDeliveryDisposition::Delivered,
                raw,
                format!(
                    "adapter-edge://{}/cancel/{}",
                    self.adapter_id, envelope.cancellation_request_id
                ),
            ),
            Err(error) => {
                let disposition = match error.certainty {
                    DriverErrorCertainty::ProvenNotSent => {
                        CancellationDeliveryDisposition::Rejected
                    }
                    DriverErrorCertainty::DeliveryUnknown => {
                        CancellationDeliveryDisposition::Unknown
                    }
                };
                let evidence_ref = error
                    .error_fingerprint
                    .as_ref()
                    .map(|value| format!("error-fingerprint:{value}"))
                    .unwrap_or_else(|| "adapter-edge://cancel/unknown".to_owned());
                (disposition, error.raw_evidence, evidence_ref)
            }
        };
        let receipt = cancellation_delivery_receipt(envelope, disposition, evidence_ref, &now);
        let state = match disposition {
            CancellationDeliveryDisposition::Delivered => "delivered",
            CancellationDeliveryDisposition::Rejected => "rejected",
            CancellationDeliveryDisposition::Unsupported => "unsupported",
            _ => "delivery_unknown",
        };
        self.edge.record_cancellation_receipt(
            &envelope.cancellation_request_id,
            state,
            &receipt.encode_to_vec(),
            &raw,
            now.seconds,
        )?;
        Ok(cancel_receipt(receipt))
    }

    pub async fn cancel_dispatch(
        &mut self,
        cancellation_request_id: &str,
        dispatch_id: &str,
        confirmation_deadline: Timestamp,
    ) -> Result<CancelExecutionResult, GovernedAdapterError> {
        if cancellation_request_id.trim().is_empty() || dispatch_id.trim().is_empty() {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::InvalidArgument,
                    "CANCELLATION_REFERENCE_INVALID",
                    false,
                    false,
                    None,
                ))),
            });
        }
        let Some(binding) = self.edge.resolve_native_execution_binding(dispatch_id)? else {
            return Ok(CancelExecutionResult {
                outcome: Some(cancel_execution_result::Outcome::Error(harness_error(
                    HarnessErrorCode::NotFound,
                    "NATIVE_EXECUTION_BINDING_NOT_FOUND",
                    false,
                    false,
                    None,
                ))),
            });
        };
        self.cancel(&CancelExecutionEnvelope {
            attempt_id: binding.attempt_id,
            dispatch_id: binding.dispatch_id,
            fencing_token: binding.fencing_token,
            cancellation_request_id: cancellation_request_id.to_owned(),
            native_session_ref: binding.native_session_ref,
            native_execution_ref: binding.native_execution_ref,
            confirmation_deadline: Some(confirmation_deadline),
            ..CancelExecutionEnvelope::default()
        })
        .await
    }

    pub async fn reconcile_dispatch(
        &mut self,
        reconciliation_id: &str,
        dispatch_id: &str,
    ) -> Result<AdapterReconciliationEvidence, GovernedAdapterError> {
        if reconciliation_id.trim().is_empty() || dispatch_id.trim().is_empty() {
            return Err(GovernedAdapterError::InvalidReconciliationReference);
        }
        let native_key = reconciliation_native_key(reconciliation_id);
        if let Some(evidence) = self
            .edge
            .observation_evidence_by_native_key(dispatch_id, &native_key)?
        {
            return decode_reconciliation_evidence(reconciliation_id, dispatch_id, evidence, true);
        }
        let envelope = self
            .edge
            .dispatch_envelope(dispatch_id)?
            .ok_or(GovernedAdapterError::DispatchNotFound)?;
        let native_binding = self.edge.resolve_native_execution_binding(dispatch_id)?;
        let mut delivery_receipt = self.edge.dispatch_receipt(dispatch_id)?;
        if let (Some(binding), Some(receipt)) = (native_binding.as_ref(), delivery_receipt.as_mut())
        {
            receipt.native_session_ref = Some(binding.native_session_ref.clone());
            receipt.native_execution_ref = Some(binding.native_execution_ref.clone());
        }
        let now = self.clock.now();
        let reference = classify_dispatch_context_reference(&envelope.input_bundle_ref);
        let recovered_material = match reference {
            DispatchContextReference::InvalidContextBinding => Err(context_binding_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_BINDING_INVALID",
                false,
            )),
            reference => self
                .context_recovery_gate
                .recover_existing_dispatch(&envelope)
                .and_then(|recovery| validate_context_recovery(&envelope, &reference, recovery))
                .and_then(|context| {
                    self.resolver
                        .resolve(&envelope)
                        .and_then(|material| recover_dispatch_material(material, context))
                }),
        };
        let (finding, supplemental_raw_evidence) = match recovered_material {
            Ok(historical_material) => match self
                .driver
                .reconcile(&ReconciliationContext {
                    envelope: envelope.clone(),
                    delivery_receipt,
                    material: historical_material.material,
                })
                .await
            {
                Ok(finding) => (finding, Vec::new()),
                Err(error) => {
                    let evidence_ref = error
                        .error_fingerprint
                        .as_ref()
                        .map(|value| format!("error-fingerprint:{value}"))
                        .unwrap_or_else(|| {
                            format!("adapter-reconciliation-error:{}", error.safe_detail_code)
                        });
                    (
                        ReconciliationFinding::OutcomeUnknown { evidence_ref },
                        error.raw_evidence,
                    )
                }
            },
            Err(error) => {
                let evidence_ref = error
                    .error_fingerprint
                    .as_ref()
                    .map(|value| format!("error-fingerprint:{value}"))
                    .unwrap_or_else(|| {
                        format!("adapter-reconciliation-error:{}", error.safe_detail_code)
                    });
                (
                    ReconciliationFinding::OutcomeUnknown { evidence_ref },
                    error.encode_to_vec(),
                )
            }
        };
        let raw_event = encode_reconciliation_evidence(&finding, &supplemental_raw_evidence);
        let observation = HarnessObservation {
            observation_id: String::new(),
            adapter_id: self.adapter_id.clone(),
            attempt_id: envelope.attempt_id,
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            observation_sequence: 0,
            native_event_id: Some(reconciliation_id.to_owned()),
            native_sequence: None,
            native_event_digest_sha256: String::new(),
            capability_profile_id: self.capability_profile_id.clone(),
            criticality: ObservationCriticality::Informational as i32,
            raw_evidence_ref: String::new(),
            native_observed_at: Some(now),
            adapter_received_at: Some(now),
            payload: Some(harness_observation::Payload::Diagnostic(
                DiagnosticObservation {
                    safe_diagnostic_code: reconciliation_diagnostic_code(&finding).to_owned(),
                    error_fingerprint: None,
                    recovery_required: false,
                },
            )),
        };
        let appended = self.edge.append_observation(
            dispatch_id,
            &native_key,
            &raw_event,
            observation,
            now.seconds,
        )?;
        let (observation, replayed) = match appended {
            crate::ObservationAppend::Committed(value) => (value, false),
            crate::ObservationAppend::Replay(value) => (value, true),
        };
        decode_reconciliation_evidence(
            reconciliation_id,
            dispatch_id,
            AdapterObservationEvidence {
                observation,
                raw_event,
            },
            replayed,
        )
    }

    pub fn reconciliation_evidence(
        &self,
        reconciliation_id: &str,
        dispatch_id: &str,
    ) -> Result<Option<AdapterReconciliationEvidence>, GovernedAdapterError> {
        let native_key = reconciliation_native_key(reconciliation_id);
        self.edge
            .observation_evidence_by_native_key(dispatch_id, &native_key)?
            .map(|evidence| {
                decode_reconciliation_evidence(reconciliation_id, dispatch_id, evidence, true)
            })
            .transpose()
    }

    pub fn stored_dispatch_receipt(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchReceipt>, GovernedAdapterError> {
        Ok(self.edge.dispatch_receipt(dispatch_id)?)
    }

    pub fn observations_after(
        &self,
        sequence: u64,
    ) -> Result<Vec<HarnessObservation>, GovernedAdapterError> {
        self.edge.observations_after(sequence).map_err(Into::into)
    }

    pub fn pending_observations(&self) -> Result<Vec<HarnessObservation>, GovernedAdapterError> {
        self.edge.pending_observations().map_err(Into::into)
    }

    pub fn normal_observation_recovery_view(
        &self,
        dispatch_id: &str,
    ) -> Result<NormalObservationRecoveryView, GovernedAdapterError> {
        self.edge
            .normal_observation_recovery_view(dispatch_id, &self.capability_profile_id)
            .map_err(Into::into)
    }

    pub fn classify_legacy_execution_start(
        &self,
        envelope: &DispatchEnvelope,
        pending_observation_id: &str,
        prior_start_sequence: u64,
    ) -> Result<LegacyExecutionStartRecovery, GovernedAdapterError> {
        let evidence = self.edge.legacy_execution_start_recovery_evidence(
            &envelope.dispatch_id,
            &envelope.attempt_id,
            envelope.fencing_token,
            &self.capability_profile_id,
            pending_observation_id,
            prior_start_sequence,
        )?;
        let evidence = match evidence {
            LegacyExecutionStartEvidenceResolution::Verified(evidence) => evidence,
            LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::OwnerMismatch,
            ) => return Ok(LegacyExecutionStartRecovery::OwnerMismatch),
            LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::PriorStartMissing,
            ) => {
                return Ok(LegacyExecutionStartRecovery::Unverified {
                    reason_code: "LEGACY_EXECUTION_START_PRIOR_EVIDENCE_MISSING",
                });
            }
            LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::NativeBindingMissing,
            ) => {
                return Ok(LegacyExecutionStartRecovery::Unverified {
                    reason_code: "LEGACY_EXECUTION_START_NATIVE_BINDING_MISSING",
                });
            }
            LegacyExecutionStartEvidenceResolution::Rejected(
                LegacyExecutionStartEvidenceRejection::NativeBindingConflict,
            ) => {
                return Ok(LegacyExecutionStartRecovery::Unverified {
                    reason_code: "LEGACY_EXECUTION_START_NATIVE_BINDING_CONFLICT",
                });
            }
        };
        let context = LegacyExecutionStartRawContext {
            prior_raw_event: evidence.prior_start.raw_event.clone(),
            pending_raw_event: evidence.pending_start.raw_event.clone(),
            native_session_ref: evidence.native_binding.native_session_ref.clone(),
            native_execution_ref: evidence.native_binding.native_execution_ref.clone(),
            terminal_raw_event: evidence.terminal_raw_event.clone(),
            terminal_native_completion_ref: evidence.terminal_native_completion_ref.clone(),
        };
        Ok(
            match self.driver.classify_legacy_execution_start(&context) {
                LegacyExecutionStartRawClassification::ExactDuplicate {
                    durable_terminal_handoff,
                } => {
                    let mut evidence = evidence;
                    evidence.durable_terminal_handoff &= durable_terminal_handoff;
                    LegacyExecutionStartRecovery::ExactDuplicate(evidence)
                }
                LegacyExecutionStartRawClassification::Conflict => {
                    LegacyExecutionStartRecovery::Unverified {
                        reason_code: "LEGACY_EXECUTION_START_RAW_IDENTITY_CONFLICT",
                    }
                }
                LegacyExecutionStartRawClassification::Unsupported => {
                    LegacyExecutionStartRecovery::Unsupported
                }
            },
        )
    }

    /// Verifies the Adapter-owned transport evidence for a delivered dispatch.
    ///
    /// This deliberately proves only the receipt's capability profile ID. The
    /// full profile reference version and digest remain part of the caller's
    /// independently verified Collaboration candidate.
    pub fn verify_delivered_recovery_candidate(
        &self,
        candidate: &DispatchEnvelope,
    ) -> Result<(), GovernedAdapterError> {
        let invalid = GovernedAdapterError::InvalidDeliveredRecoveryEvidence;
        let Some(candidate_profile) = candidate.capability_profile_ref.as_ref() else {
            return Err(invalid);
        };
        if candidate.dispatch_id.trim().is_empty()
            || candidate.attempt_id.trim().is_empty()
            || candidate.fencing_token == 0
            || !sha256_is_valid(&candidate.dispatch_fingerprint)
            || candidate_profile.contract_id.trim().is_empty()
        {
            return Err(invalid);
        }

        let stored = self
            .edge
            .stored_delivered_dispatch_evidence(&candidate.dispatch_id)?
            .ok_or(GovernedAdapterError::InvalidDeliveredRecoveryEvidence)?;
        if stored.delivery_state != "delivered"
            || stored.dispatch_id != candidate.dispatch_id
            || stored.attempt_id != candidate.attempt_id
            || stored.fencing_token != candidate.fencing_token
            || stored.dispatch_fingerprint != candidate.dispatch_fingerprint
            || sha256(&stored.envelope) != stored.envelope_digest_sha256
        {
            return Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence);
        }

        let stored_envelope = DispatchEnvelope::decode(stored.envelope.as_slice())
            .map_err(|_| GovernedAdapterError::InvalidDeliveredRecoveryEvidence)?;
        if stored_envelope != *candidate {
            return Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence);
        }

        let receipt = stored
            .receipt
            .ok_or(GovernedAdapterError::InvalidDeliveredRecoveryEvidence)
            .and_then(|receipt| {
                DispatchReceipt::decode(receipt.as_slice())
                    .map_err(|_| GovernedAdapterError::InvalidDeliveredRecoveryEvidence)
            })?;
        if !matches!(
            DeliveryDisposition::try_from(receipt.disposition),
            Ok(DeliveryDisposition::Delivered)
        ) || receipt.receipt_id.trim().is_empty()
            || receipt.evidence_ref.trim().is_empty()
            || self.adapter_id != self.edge.adapter_id()
            || receipt.adapter_id != self.adapter_id
            || receipt.attempt_id != candidate.attempt_id
            || receipt.dispatch_id != candidate.dispatch_id
            || receipt.fencing_token != candidate.fencing_token
            || receipt.capability_profile_id != self.capability_profile_id
            || candidate_profile.contract_id != self.capability_profile_id
        {
            return Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence);
        }

        let recorded_receipt_digest = receipt.receipt_digest_sha256.clone();
        let mut canonical_receipt = receipt;
        canonical_receipt.receipt_digest_sha256.clear();
        if !sha256_is_valid(&recorded_receipt_digest)
            || canonical_digest(&canonical_receipt) != recorded_receipt_digest
        {
            return Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence);
        }
        Ok(())
    }

    pub fn bind_dispatch_task_lineage(
        &mut self,
        dispatch_id: &str,
        task_id: &str,
        task_revision: u64,
        work_revision: u64,
    ) -> Result<(), GovernedAdapterError> {
        self.edge
            .bind_dispatch_task_lineage(
                dispatch_id,
                task_id,
                task_revision,
                work_revision,
                self.clock.now().seconds,
            )
            .map_err(Into::into)
    }

    pub fn pending_approval_projection_messages(
        &self,
    ) -> Result<Vec<PendingAdapterApprovalProjection>, GovernedAdapterError> {
        self.edge
            .pending_approval_projection_messages()
            .map_err(Into::into)
    }

    pub fn pending_terminal_output_candidates(
        &self,
    ) -> Result<Vec<crate::PendingTerminalOutputCandidate>, GovernedAdapterError> {
        self.edge
            .pending_terminal_output_candidates()
            .map_err(Into::into)
    }

    pub fn terminal_output_candidate_is_durable(
        &self,
        dispatch_id: &str,
    ) -> Result<bool, GovernedAdapterError> {
        self.edge
            .terminal_output_candidate_is_durable(dispatch_id)
            .map_err(Into::into)
    }

    pub fn terminal_output_candidate_for_dispatch(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<crate::PendingTerminalOutputCandidate>, GovernedAdapterError> {
        self.edge
            .terminal_output_candidate_for_dispatch(dispatch_id)
            .map_err(Into::into)
    }

    pub fn acknowledge_terminal_output_candidate(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, GovernedAdapterError> {
        self.edge
            .acknowledge_terminal_output_candidate(message_id, payload_digest_sha256)
            .map_err(Into::into)
    }

    pub fn hold_terminal_output_candidate(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, GovernedAdapterError> {
        self.edge
            .hold_terminal_output_candidate(message_id, payload_digest_sha256)
            .map_err(Into::into)
    }

    pub fn retained_approval_projection_messages_for_rebuild(
        &self,
    ) -> Result<Vec<PendingAdapterApprovalProjection>, GovernedAdapterError> {
        self.edge
            .retained_approval_projection_messages_for_rebuild()
            .map_err(Into::into)
    }

    pub fn acknowledge_approval_projection_message(
        &mut self,
        message_id: &str,
        payload_digest_sha256: &str,
    ) -> Result<bool, GovernedAdapterError> {
        self.edge
            .acknowledge_approval_projection_message(message_id, payload_digest_sha256)
            .map_err(Into::into)
    }

    pub fn mark_observation_consumed(
        &mut self,
        observation_id: &str,
    ) -> Result<(), GovernedAdapterError> {
        self.edge
            .mark_observation_consumed(observation_id)
            .map_err(Into::into)
    }

    pub fn consume_legacy_execution_start_duplicate(
        &mut self,
        evidence: &LegacyExecutionStartEvidence,
    ) -> Result<bool, GovernedAdapterError> {
        self.edge
            .consume_legacy_execution_start_duplicate(evidence)
            .map_err(Into::into)
    }

    pub fn quarantine_observation(
        &mut self,
        observation_id: &str,
        reason_code: &str,
    ) -> Result<(), GovernedAdapterError> {
        self.edge
            .quarantine_observation(observation_id, reason_code, self.clock.now().seconds)
            .map_err(Into::into)
    }

    #[must_use]
    pub fn edge(&self) -> &AdapterEdge {
        &self.edge
    }

    #[must_use]
    pub fn driver(&self) -> &D {
        &self.driver
    }

    fn verify_existing_context_authorization(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<(), HarnessError> {
        let reference = classify_dispatch_context_reference(&envelope.input_bundle_ref);
        if reference == DispatchContextReference::InvalidContextBinding {
            return Err(context_binding_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_BINDING_INVALID",
                false,
            ));
        }
        let authorization = self
            .context_authorization_gate
            .verify_existing_dispatch(envelope)?;
        validate_context_authorization(envelope, &reference, authorization).map(|_| ())
    }

    fn content_context_proof(
        &self,
        envelope: &DispatchEnvelope,
    ) -> Result<DispatchContextConsumptionProof, HarnessError> {
        let reference = classify_dispatch_context_reference(&envelope.input_bundle_ref);
        if reference == DispatchContextReference::InvalidContextBinding {
            return Err(context_binding_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_BINDING_INVALID",
                false,
            ));
        }
        let authorization = self
            .context_authorization_gate
            .verify_existing_dispatch(envelope)?;
        let authorized = validate_context_authorization(envelope, &reference, authorization)?;
        Ok(DispatchContextConsumptionProof {
            branch: Some(match authorized {
                Some(value) => dispatch_context_consumption_proof::Branch::AuthorizedContext(
                    AuthorizedContextConsumptionProof {
                        authorization_id: value.receipt.authorization_id,
                        committed_request_digest_sha256: value.receipt.request_digest_sha256,
                    },
                ),
                None => dispatch_context_consumption_proof::Branch::NotContextBound(
                    NotContextBoundProof {},
                ),
            }),
        })
    }

    fn bind_content_observation(
        &self,
        envelope: &DispatchEnvelope,
        observation: &mut HarnessObservation,
    ) -> Result<(), GovernedAdapterError> {
        let route_binding = self
            .edge
            .dispatch_route_binding(&envelope.dispatch_id)?
            .filter(|binding| envelope.route_binding.as_ref() == Some(binding))
            .ok_or(ContentDisclosureError::SourceBinding)?;
        if crate::canonical_dispatch_route_binding_digest(&route_binding).as_deref()
            != Some(route_binding.route_binding_sha256.as_str())
        {
            return Err(ContentDisclosureError::SourceBinding.into());
        }
        let receipt = self
            .edge
            .delivered_dispatch_receipt(&envelope.dispatch_id)?
            .filter(|receipt| {
                receipt.dispatch_id == envelope.dispatch_id
                    && receipt.attempt_id == envelope.attempt_id
                    && receipt.fencing_token == envelope.fencing_token
                    && receipt.adapter_id == self.adapter_id
                    && receipt.capability_profile_id == self.capability_profile_id
                    && receipt.disposition == DeliveryDisposition::Delivered as i32
                    && canonical_sha256_is_valid(&receipt.receipt_digest_sha256)
            })
            .ok_or(ContentDisclosureError::SourceBinding)?;
        let proof = self.content_context_proof(envelope).map_err(|_| {
            GovernedAdapterError::ContentDisclosure(ContentDisclosureError::SourceBinding)
        })?;
        let source_observation = observation.clone();
        let Some(harness_observation::Payload::ContentSignal(signal)) =
            observation.payload.as_mut()
        else {
            return Err(ContentDisclosureError::CandidateIntegrity.into());
        };
        bind_content_signal(
            &source_observation,
            signal,
            &receipt.receipt_id,
            &receipt.receipt_digest_sha256,
            &route_binding.route_binding_sha256,
            proof,
        )?;
        Ok(())
    }

    fn validate_dispatch(&self, envelope: &DispatchEnvelope) -> Option<HarnessError> {
        let profile = envelope.capability_profile_ref.as_ref();
        if envelope.dispatch_id.trim().is_empty()
            || envelope.attempt_id.trim().is_empty()
            || envelope.fencing_token == 0
            || !sha256_is_valid(&envelope.dispatch_fingerprint)
            || !sha256_is_valid(&envelope.input_bundle_sha256)
            || profile.is_none_or(|value| {
                value.contract_id != self.capability_profile_id || !sha256_is_valid(&value.sha256)
            })
        {
            return Some(harness_error(
                HarnessErrorCode::InvalidArgument,
                "DISPATCH_ENVELOPE_INVALID",
                false,
                false,
                None,
            ));
        }
        None
    }

    fn validate_resolved_route(
        &self,
        envelope: &DispatchEnvelope,
        material: &ResolvedDispatchMaterial,
    ) -> Result<(), HarnessError> {
        let Some(expected) = self.expected_route_binding.as_ref() else {
            if envelope.route_binding.is_none() {
                return Ok(());
            }
            return Err(harness_error(
                HarnessErrorCode::ConfigInvalid,
                "DISPATCH_ROUTE_UNAVAILABLE",
                false,
                false,
                None,
            ));
        };
        let Some(actual) = envelope.route_binding.as_ref() else {
            return Err(harness_error(
                HarnessErrorCode::IntegrityFailure,
                "DISPATCH_ROUTE_BINDING_MISSING",
                false,
                false,
                None,
            ));
        };
        if actual != &expected.binding
            || crate::canonical_dispatch_route_binding_digest(actual).as_deref()
                != Some(actual.route_binding_sha256.as_str())
            || material.model.as_deref() != Some(expected.harness_model_id.as_str())
            || actual.capability_profile_id != self.capability_profile_id
        {
            return Err(harness_error(
                HarnessErrorCode::IntegrityFailure,
                "DISPATCH_ROUTE_BINDING_MISMATCH",
                false,
                false,
                None,
            ));
        }
        Ok(())
    }

    fn delivery_receipt(
        &self,
        envelope: &DispatchEnvelope,
        delivery: DriverDelivery,
        disposition: DeliveryDisposition,
        now: &Timestamp,
    ) -> DispatchReceipt {
        let receipt_id = Uuid::now_v7().to_string();
        let mut receipt = DispatchReceipt {
            receipt_id: receipt_id.clone(),
            disposition: disposition as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: self.adapter_id.clone(),
            capability_profile_id: self.capability_profile_id.clone(),
            observed_protocol: Some(self.observed_protocol.clone()),
            native_request_ref: Some(delivery.native_request_ref),
            native_session_ref: Some(delivery.native_session_ref),
            native_execution_ref: delivery.native_execution_ref,
            receipt_digest_sha256: String::new(),
            evidence_ref: format!("adapter-edge://{}/delivery/{receipt_id}", self.adapter_id),
            delivered_at: Some(*now),
        };
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        receipt
    }

    fn failed_delivery_receipt(
        &self,
        envelope: &DispatchEnvelope,
        disposition: DeliveryDisposition,
        error: &DriverError,
        now: &Timestamp,
    ) -> DispatchReceipt {
        let receipt_id = Uuid::now_v7().to_string();
        let mut receipt = DispatchReceipt {
            receipt_id: receipt_id.clone(),
            disposition: disposition as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: self.adapter_id.clone(),
            capability_profile_id: self.capability_profile_id.clone(),
            observed_protocol: Some(self.observed_protocol.clone()),
            native_request_ref: None,
            native_session_ref: None,
            native_execution_ref: None,
            receipt_digest_sha256: String::new(),
            evidence_ref: error
                .error_fingerprint
                .as_ref()
                .map(|value| format!("error-fingerprint:{value}"))
                .unwrap_or_else(|| {
                    format!("adapter-edge://{}/delivery/{receipt_id}", self.adapter_id)
                }),
            delivered_at: Some(*now),
        };
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        receipt
    }

    fn delivery_unknown_receipt(
        &self,
        envelope: &DispatchEnvelope,
        reason: &str,
        now: &Timestamp,
    ) -> DispatchReceipt {
        self.failed_delivery_receipt(
            envelope,
            DeliveryDisposition::Unknown,
            &DriverError {
                certainty: DriverErrorCertainty::DeliveryUnknown,
                code: HarnessErrorCode::DeliveryUnknown,
                safe_detail_code: reason.to_owned(),
                error_fingerprint: None,
                raw_evidence: Vec::new(),
            },
            now,
        )
    }
}

/// Validates the provider-neutral part of a native Harness probe. Provider
/// adapters may discover their own native details, but a Ready result must
/// match the adapter's expected fingerprint before the result can become a
/// capability attestation input.
pub fn validate_probe_result(
    request: &ProbeHarnessRequest,
    result: &ProbeHarnessResult,
    expected: &NativeProtocolFingerprint,
) -> Result<(), ProbeValidationError> {
    if result.probe_id.trim().is_empty() {
        return Err(ProbeValidationError::ProbeIdMissing);
    }
    if result.observed_at.is_none() {
        return Err(ProbeValidationError::ObservationTimeMissing);
    }
    let readiness = HarnessReadiness::try_from(result.readiness)
        .map_err(|_| ProbeValidationError::ReadinessInvalid)?;
    if readiness != HarnessReadiness::Ready {
        return Ok(());
    }
    let observed = result
        .observed_protocol
        .as_ref()
        .ok_or(ProbeValidationError::ObservedProtocolMissing)?;
    if result.evidence_refs.is_empty() {
        return Err(ProbeValidationError::EvidenceMissing);
    }
    if observed.protocol_name.trim().is_empty()
        || observed.protocol_version.trim().is_empty()
        || observed.schema_sha256.trim().is_empty()
        || observed.adapter_version.trim().is_empty()
        || observed.native_executable_version.trim().is_empty()
    {
        return Err(ProbeValidationError::ProtocolFingerprintIncomplete);
    }
    if observed.protocol_name != expected.protocol_name
        || observed.protocol_version != expected.protocol_version
        || !observed
            .schema_sha256
            .eq_ignore_ascii_case(&request.expected_protocol_schema_sha256)
        || !observed
            .schema_sha256
            .eq_ignore_ascii_case(&expected.schema_sha256)
        || observed.adapter_version != expected.adapter_version
        || observed.native_executable_version != expected.native_executable_version
    {
        return Err(ProbeValidationError::ProtocolFingerprintMismatch);
    }
    Ok(())
}

fn probe_validation_code(error: ProbeValidationError) -> &'static str {
    match error {
        ProbeValidationError::ProbeIdMissing => "PROBE_ID_MISSING",
        ProbeValidationError::ObservationTimeMissing => "PROBE_OBSERVED_AT_MISSING",
        ProbeValidationError::ObservedProtocolMissing => "PROBE_PROTOCOL_MISSING",
        ProbeValidationError::EvidenceMissing => "PROBE_EVIDENCE_MISSING",
        ProbeValidationError::ProtocolFingerprintIncomplete => "PROBE_PROTOCOL_INCOMPLETE",
        ProbeValidationError::ProtocolFingerprintMismatch => "PROBE_PROTOCOL_FINGERPRINT_MISMATCH",
        ProbeValidationError::ReadinessInvalid => "PROBE_READINESS_INVALID",
    }
}

fn invalid_probe_result(
    result: Option<ProbeHarnessResult>,
    expected: &NativeProtocolFingerprint,
    diagnostic_code: &str,
    observed_at: Timestamp,
) -> ProbeHarnessResult {
    let result = result.unwrap_or_default();
    ProbeHarnessResult {
        probe_id: if result.probe_id.trim().is_empty() {
            Uuid::now_v7().to_string()
        } else {
            result.probe_id
        },
        readiness: HarnessReadiness::ProtocolMismatch as i32,
        observed_protocol: result.observed_protocol.or_else(|| Some(expected.clone())),
        safe_diagnostic_codes: result
            .safe_diagnostic_codes
            .into_iter()
            .chain(std::iter::once(diagnostic_code.to_owned()))
            .collect(),
        evidence_refs: result.evidence_refs,
        observed_at: Some(result.observed_at.unwrap_or(observed_at)),
    }
}

fn dispatch_receipt(receipt: DispatchReceipt) -> DispatchResult {
    DispatchResult {
        outcome: Some(dispatch_result::Outcome::Receipt(receipt)),
    }
}

fn dispatch_error(error: HarnessError) -> DispatchResult {
    DispatchResult {
        outcome: Some(dispatch_result::Outcome::Error(error)),
    }
}

fn reject_context_authorization(
    input_bundle_ref: &str,
) -> Result<DispatchContextAuthorization, HarnessError> {
    match classify_dispatch_context_reference(input_bundle_ref) {
        DispatchContextReference::NotContextBound => {
            Ok(DispatchContextAuthorization::NotContextBound)
        }
        DispatchContextReference::ContextSnapshot { .. } => Err(context_binding_error(
            HarnessErrorCode::DependencyUnavailable,
            "CONTEXT_GATE_UNAVAILABLE",
            true,
        )),
        DispatchContextReference::InvalidContextBinding => Err(context_binding_error(
            HarnessErrorCode::ConfigInvalid,
            "CONTEXT_BINDING_INVALID",
            false,
        )),
    }
}

fn reject_context_recovery(
    input_bundle_ref: &str,
) -> Result<DispatchContextRecovery, HarnessError> {
    match classify_dispatch_context_reference(input_bundle_ref) {
        DispatchContextReference::NotContextBound => Ok(DispatchContextRecovery::NotContextBound),
        DispatchContextReference::ContextSnapshot { .. } => Err(context_binding_error(
            HarnessErrorCode::DependencyUnavailable,
            "CONTEXT_RECOVERY_GATE_UNAVAILABLE",
            true,
        )),
        DispatchContextReference::InvalidContextBinding => Err(context_binding_error(
            HarnessErrorCode::ConfigInvalid,
            "CONTEXT_BINDING_INVALID",
            false,
        )),
    }
}

fn validate_context_recovery(
    envelope: &DispatchEnvelope,
    reference: &DispatchContextReference,
    recovery: DispatchContextRecovery,
) -> Result<Option<HistoricalDispatchContext>, HarnessError> {
    let context = match (reference, recovery) {
        (DispatchContextReference::NotContextBound, DispatchContextRecovery::NotContextBound) => {
            None
        }
        (
            DispatchContextReference::ContextSnapshot { snapshot_id },
            DispatchContextRecovery::Historical(context),
        ) => {
            let binding = &context.binding;
            let valid = binding.snapshot_id == *snapshot_id
                && binding.snapshot_revision > 0
                && canonical_sha256_is_valid(&binding.content_digest_sha256)
                && binding.content_digest_sha256 == envelope.input_bundle_sha256
                && snapshot_id
                    .strip_prefix("ctx:")
                    .is_some_and(|digest| digest == binding.content_digest_sha256)
                && opaque_reference_is_valid(&binding.expected_scope_ref)
                && context.observed_state_revision > 0
                && sha256(&context.authority_immutable_bytes) == binding.content_digest_sha256;
            if !valid {
                return Err(context_binding_error(
                    HarnessErrorCode::IntegrityFailure,
                    "CONTEXT_RECOVERY_EVIDENCE_INVALID",
                    false,
                ));
            }
            Some(*context)
        }
        (DispatchContextReference::InvalidContextBinding, _) => {
            return Err(context_binding_error(
                HarnessErrorCode::ConfigInvalid,
                "CONTEXT_BINDING_INVALID",
                false,
            ));
        }
        _ => {
            return Err(context_binding_error(
                HarnessErrorCode::IntegrityFailure,
                "CONTEXT_RECOVERY_EVIDENCE_INVALID",
                false,
            ));
        }
    };
    Ok(context)
}

fn recover_dispatch_material(
    material: ResolvedDispatchMaterial,
    context: Option<HistoricalDispatchContext>,
) -> Result<HistoricalDispatchMaterial, HarnessError> {
    if let Some(context) = context.as_ref()
        && (sha256(&material.canonical_input_bundle) != context.binding.content_digest_sha256
            || material.canonical_input_bundle != context.authority_immutable_bytes)
    {
        return Err(context_binding_error(
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_RECOVERY_EVIDENCE_INVALID",
            false,
        ));
    }
    Ok(HistoricalDispatchMaterial {
        material,
        _context: context,
    })
}

fn authorize_dispatch_material(
    envelope: &DispatchEnvelope,
    reference: DispatchContextReference,
    material: ResolvedDispatchMaterial,
    authorization: DispatchContextAuthorization,
) -> Result<AuthorizedDispatchMaterial, HarnessError> {
    let context = validate_context_authorization(envelope, &reference, authorization)?;
    if let Some(context) = context.as_ref()
        && sha256(&material.canonical_input_bundle) != context.binding.content_digest_sha256
    {
        return Err(context_binding_error(
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORIZATION_INVALID",
            false,
        ));
    }
    Ok(AuthorizedDispatchMaterial {
        material,
        _context: context,
    })
}

fn validate_context_authorization(
    envelope: &DispatchEnvelope,
    reference: &DispatchContextReference,
    authorization: DispatchContextAuthorization,
) -> Result<Option<AuthorizedDispatchContext>, HarnessError> {
    match (reference, authorization) {
        (
            DispatchContextReference::NotContextBound,
            DispatchContextAuthorization::NotContextBound,
        ) => Ok(None),
        (
            DispatchContextReference::ContextSnapshot { snapshot_id },
            DispatchContextAuthorization::Authorized(context),
        ) => {
            let binding = &context.binding;
            let receipt = &context.receipt;
            let valid = binding.snapshot_id == *snapshot_id
                && binding.snapshot_revision > 0
                && canonical_sha256_is_valid(&binding.content_digest_sha256)
                && binding.content_digest_sha256 == envelope.input_bundle_sha256
                && snapshot_id
                    .strip_prefix("ctx:")
                    .is_some_and(|digest| digest == binding.content_digest_sha256)
                && opaque_reference_is_valid(&binding.expected_scope_ref)
                && opaque_reference_is_valid(&receipt.authorization_id)
                && receipt.snapshot_id == binding.snapshot_id
                && receipt.snapshot_revision == binding.snapshot_revision
                && receipt.observed_state_revision > 0
                && receipt.attempt_id == envelope.attempt_id
                && receipt.dispatch_id == envelope.dispatch_id
                && receipt.input_digest_sha256 == binding.content_digest_sha256
                && receipt.expected_scope_ref == binding.expected_scope_ref
                && canonical_sha256_is_valid(&receipt.input_digest_sha256)
                && canonical_sha256_is_valid(&receipt.request_digest_sha256)
                && opaque_reference_is_valid(&receipt.event_id)
                && receipt.committed_at_seconds > 0
                && memory_authorization_is_valid(envelope, binding, context.memory_use.as_ref());
            if !valid {
                return Err(context_binding_error(
                    HarnessErrorCode::IntegrityFailure,
                    "CONTEXT_AUTHORIZATION_INVALID",
                    false,
                ));
            }
            Ok(Some(*context))
        }
        (DispatchContextReference::InvalidContextBinding, _) => Err(context_binding_error(
            HarnessErrorCode::ConfigInvalid,
            "CONTEXT_BINDING_INVALID",
            false,
        )),
        _ => Err(context_binding_error(
            HarnessErrorCode::IntegrityFailure,
            "CONTEXT_AUTHORIZATION_INVALID",
            false,
        )),
    }
}

fn memory_authorization_is_valid(
    envelope: &DispatchEnvelope,
    context: &DispatchContextBinding,
    receipt: Option<&DispatchMemoryUseReceipt>,
) -> bool {
    match (context.memory_pack.as_ref(), receipt) {
        (None, None) => true,
        (Some(memory_pack), Some(receipt)) => {
            envelope.route_binding.as_ref().is_some_and(|route| {
                opaque_reference_is_valid(&receipt.receipt_id)
                    && receipt.snapshot_id == context.snapshot_id
                    && receipt.snapshot_revision == context.snapshot_revision
                    && opaque_reference_is_valid(&receipt.consumer_principal_id)
                    && receipt.consumer_principal_id == route.selected_harness_id
                    && opaque_reference_is_valid(&receipt.model_ref)
                    && receipt.model_ref == route.provider_model_id
                    && receipt.attempt_id == envelope.attempt_id
                    && receipt.dispatch_id == envelope.dispatch_id
                    && memory_pack.memory_authority_revision > 0
                    && receipt.memory_authority_revision == memory_pack.memory_authority_revision
                    && canonical_sha256_is_valid(&memory_pack.memory_pack_snapshot_sha256)
                    && receipt.memory_pack_snapshot_sha256
                        == memory_pack.memory_pack_snapshot_sha256
                    && canonical_sha256_is_valid(&receipt.request_digest_sha256)
            })
        }
        _ => false,
    }
}

fn context_binding_error(
    code: HarnessErrorCode,
    detail: &str,
    retryable_delivery: bool,
) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery,
        recovery_required: true,
        error_fingerprint: Some(sha256(detail.as_bytes())),
        audit_ref: Some("harness-adapter:context-authorization".to_owned()),
    }
}

fn opaque_reference_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= 4 * 1024
        && !value.chars().any(char::is_control)
}

fn approval_receipt(receipt: ApprovalDecisionReceipt) -> ApprovalDecisionResult {
    ApprovalDecisionResult {
        outcome: Some(approval_decision_result::Outcome::Receipt(receipt)),
    }
}

fn approval_delivery_receipt(
    envelope: &ApprovalDecisionEnvelope,
    disposition: DeliveryDisposition,
    now: &Timestamp,
) -> ApprovalDecisionReceipt {
    let mut receipt = ApprovalDecisionReceipt {
        receipt_id: Uuid::now_v7().to_string(),
        approval_request_id: envelope.approval_request_id.clone(),
        decision: envelope.decision,
        disposition: disposition as i32,
        receipt_digest_sha256: String::new(),
        delivered_at: Some(*now),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    receipt
}

fn cancel_receipt(receipt: CancelExecutionReceipt) -> CancelExecutionResult {
    CancelExecutionResult {
        outcome: Some(cancel_execution_result::Outcome::Receipt(receipt)),
    }
}

fn cancellation_delivery_receipt(
    envelope: &CancelExecutionEnvelope,
    disposition: CancellationDeliveryDisposition,
    evidence_ref: String,
    now: &Timestamp,
) -> CancelExecutionReceipt {
    let mut receipt = CancelExecutionReceipt {
        receipt_id: Uuid::now_v7().to_string(),
        cancellation_request_id: envelope.cancellation_request_id.clone(),
        disposition: disposition as i32,
        receipt_digest_sha256: String::new(),
        evidence_ref,
        delivered_at: Some(*now),
    };
    receipt.receipt_digest_sha256 = canonical_digest(&receipt);
    receipt
}

const RECONCILIATION_EVIDENCE_MAGIC: &[u8] = b"EGOPULSE_RECONCILIATION_EVIDENCE_V1\0";

fn reconciliation_native_key(reconciliation_id: &str) -> String {
    format!("reconciliation:{reconciliation_id}")
}

fn reconciliation_diagnostic_code(finding: &ReconciliationFinding) -> &'static str {
    match finding {
        ReconciliationFinding::NoEffectProven { .. } => "ADAPTER_RECONCILIATION_NO_EFFECT_PROVEN",
        ReconciliationFinding::NativeExecutionActive { .. } => {
            "ADAPTER_RECONCILIATION_NATIVE_EXECUTION_ACTIVE"
        }
        ReconciliationFinding::TerminalObservationRecovered { .. } => {
            "ADAPTER_RECONCILIATION_TERMINAL_OBSERVATION_RECOVERED"
        }
        ReconciliationFinding::OutcomeUnknown { .. } => "ADAPTER_RECONCILIATION_OUTCOME_UNKNOWN",
    }
}

fn reconciliation_kind(finding: &ReconciliationFinding) -> u8 {
    match finding {
        ReconciliationFinding::NoEffectProven { .. } => 1,
        ReconciliationFinding::NativeExecutionActive { .. } => 2,
        ReconciliationFinding::TerminalObservationRecovered { .. } => 3,
        ReconciliationFinding::OutcomeUnknown { .. } => 4,
    }
}

fn reconciliation_evidence_ref(finding: &ReconciliationFinding) -> &str {
    match finding {
        ReconciliationFinding::NoEffectProven { evidence_ref }
        | ReconciliationFinding::NativeExecutionActive { evidence_ref }
        | ReconciliationFinding::TerminalObservationRecovered { evidence_ref }
        | ReconciliationFinding::OutcomeUnknown { evidence_ref } => evidence_ref,
    }
}

fn encode_reconciliation_evidence(
    finding: &ReconciliationFinding,
    supplemental_raw_evidence: &[u8],
) -> Vec<u8> {
    let evidence_ref = reconciliation_evidence_ref(finding).as_bytes();
    let length = u32::try_from(evidence_ref.len()).unwrap_or(u32::MAX);
    let mut encoded = Vec::with_capacity(
        RECONCILIATION_EVIDENCE_MAGIC.len()
            + 1
            + size_of::<u32>()
            + evidence_ref.len()
            + supplemental_raw_evidence.len(),
    );
    encoded.extend_from_slice(RECONCILIATION_EVIDENCE_MAGIC);
    encoded.push(reconciliation_kind(finding));
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(evidence_ref);
    encoded.extend_from_slice(supplemental_raw_evidence);
    encoded
}

fn decode_reconciliation_finding(
    raw_evidence: &[u8],
) -> Result<ReconciliationFinding, GovernedAdapterError> {
    let header_length = RECONCILIATION_EVIDENCE_MAGIC.len() + 1 + size_of::<u32>();
    if raw_evidence.len() < header_length
        || !raw_evidence.starts_with(RECONCILIATION_EVIDENCE_MAGIC)
    {
        return Err(GovernedAdapterError::InvalidReconciliationEvidence);
    }
    let kind = raw_evidence[RECONCILIATION_EVIDENCE_MAGIC.len()];
    let length_start = RECONCILIATION_EVIDENCE_MAGIC.len() + 1;
    let length = u32::from_be_bytes(
        raw_evidence[length_start..length_start + size_of::<u32>()]
            .try_into()
            .map_err(|_| GovernedAdapterError::InvalidReconciliationEvidence)?,
    ) as usize;
    let evidence_start = header_length;
    let evidence_end = evidence_start
        .checked_add(length)
        .filter(|value| *value <= raw_evidence.len())
        .ok_or(GovernedAdapterError::InvalidReconciliationEvidence)?;
    let evidence_ref = std::str::from_utf8(&raw_evidence[evidence_start..evidence_end])
        .map_err(|_| GovernedAdapterError::InvalidReconciliationEvidence)?
        .to_owned();
    if evidence_ref.trim().is_empty() {
        return Err(GovernedAdapterError::InvalidReconciliationEvidence);
    }
    match kind {
        1 => Ok(ReconciliationFinding::NoEffectProven { evidence_ref }),
        2 => Ok(ReconciliationFinding::NativeExecutionActive { evidence_ref }),
        3 => Ok(ReconciliationFinding::TerminalObservationRecovered { evidence_ref }),
        4 => Ok(ReconciliationFinding::OutcomeUnknown { evidence_ref }),
        _ => Err(GovernedAdapterError::InvalidReconciliationEvidence),
    }
}

fn decode_reconciliation_evidence(
    reconciliation_id: &str,
    dispatch_id: &str,
    evidence: AdapterObservationEvidence,
    replayed: bool,
) -> Result<AdapterReconciliationEvidence, GovernedAdapterError> {
    if evidence.observation.dispatch_id != dispatch_id
        || evidence.observation.native_event_id.as_deref() != Some(reconciliation_id)
        || !matches!(
            evidence.observation.payload,
            Some(harness_observation::Payload::Diagnostic(_))
        )
    {
        return Err(GovernedAdapterError::InvalidReconciliationEvidence);
    }
    let finding = decode_reconciliation_finding(&evidence.raw_event)?;
    Ok(AdapterReconciliationEvidence {
        reconciliation_id: reconciliation_id.to_owned(),
        dispatch_id: dispatch_id.to_owned(),
        evidence_id: evidence.observation.observation_id,
        raw_evidence_ref: evidence.observation.raw_evidence_ref,
        finding,
        replayed,
    })
}

fn driver_error_event(error: DriverError, now: Timestamp) -> DriverEvent {
    let fingerprint = error.error_fingerprint.clone();
    let criticality = if error.code == HarnessErrorCode::UnknownCriticalEvent {
        ObservationCriticality::Terminal
    } else if matches!(
        error.code,
        HarnessErrorCode::Unauthenticated | HarnessErrorCode::PermissionDenied
    ) {
        ObservationCriticality::Security
    } else {
        ObservationCriticality::Control
    };
    DriverEvent {
        native_key: format!(
            "driver-error:{}:{}",
            error.safe_detail_code,
            sha256(&error.raw_evidence)
        ),
        native_event_id: None,
        native_sequence: None,
        native_observed_at: now,
        criticality,
        payload: harness_observation::Payload::Diagnostic(
            egopulse_domain_contracts::v01::egopulse::harness::v1::DiagnosticObservation {
                safe_diagnostic_code: error.safe_detail_code,
                error_fingerprint: fingerprint,
                recovery_required: error.certainty == DriverErrorCertainty::DeliveryUnknown,
            },
        ),
        raw_event: error.raw_evidence,
    }
}

fn harness_error(
    code: HarnessErrorCode,
    detail: &str,
    retryable_delivery: bool,
    recovery_required: bool,
    fingerprint: Option<String>,
) -> HarnessError {
    HarnessError {
        code: code as i32,
        safe_detail_code: detail.to_owned(),
        retryable_delivery,
        recovery_required,
        error_fingerprint: fingerprint,
        audit_ref: None,
    }
}

fn readiness_for_error(
    error: &DriverError,
) -> egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessReadiness {
    use egopulse_domain_contracts::v01::egopulse::harness::v1::HarnessReadiness;
    if error.code == HarnessErrorCode::ProtocolMismatch {
        HarnessReadiness::ProtocolMismatch
    } else {
        HarnessReadiness::Unavailable
    }
}

fn canonical_digest<M>(message: &M) -> String
where
    M: Message + Clone,
{
    sha256(&message.encode_to_vec())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

fn canonical_sha256_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

#[allow(dead_code)]
fn _unimplemented_resume_boundary(_: &ResumeExecutionEnvelope) -> ResumeExecutionResult {
    ResumeExecutionResult {
        outcome: Some(resume_execution_result::Outcome::Error(harness_error(
            HarnessErrorCode::ResumeUnsupported,
            "PARTIAL_EXECUTION_RESUME_UNSUPPORTED",
            false,
            true,
            None,
        ))),
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    fn fingerprint() -> NativeProtocolFingerprint {
        NativeProtocolFingerprint {
            protocol_name: "fixture-native-protocol".to_owned(),
            protocol_version: "v1".to_owned(),
            schema_sha256: "ab".repeat(32),
            adapter_version: "0.1.0".to_owned(),
            native_executable_version: "fixture-1".to_owned(),
            native_binary_sha256: None,
        }
    }

    fn request() -> ProbeHarnessRequest {
        ProbeHarnessRequest {
            adapter_id: "fixture-adapter".to_owned(),
            expected_protocol_schema_sha256: "ab".repeat(32),
            ..ProbeHarnessRequest::default()
        }
    }

    fn ready_result(protocol: NativeProtocolFingerprint) -> ProbeHarnessResult {
        ProbeHarnessResult {
            probe_id: "probe-001".to_owned(),
            readiness: HarnessReadiness::Ready as i32,
            observed_protocol: Some(protocol),
            safe_diagnostic_codes: vec!["FIXTURE_READY".to_owned()],
            evidence_refs: vec!["fixture://probe/001".to_owned()],
            observed_at: Some(Timestamp {
                seconds: 1,
                nanos: 0,
            }),
        }
    }

    #[test]
    fn accepts_ready_probe_when_fingerprint_and_evidence_match() {
        let expected = fingerprint();
        assert_eq!(
            validate_probe_result(&request(), &ready_result(expected.clone()), &expected),
            Ok(())
        );
    }

    #[test]
    fn rejects_ready_probe_with_protocol_drift() {
        let expected = fingerprint();
        let mut observed = expected.clone();
        observed.schema_sha256 = "cd".repeat(32);
        assert_eq!(
            validate_probe_result(&request(), &ready_result(observed), &expected),
            Err(ProbeValidationError::ProtocolFingerprintMismatch)
        );
    }

    #[test]
    fn rejects_ready_probe_without_independent_evidence() {
        let expected = fingerprint();
        let mut result = ready_result(expected.clone());
        result.evidence_refs.clear();
        assert_eq!(
            validate_probe_result(&request(), &result, &expected),
            Err(ProbeValidationError::EvidenceMissing)
        );
    }

    #[test]
    fn permits_non_ready_probe_to_report_unavailable_without_fingerprint() {
        let expected = fingerprint();
        let result = ProbeHarnessResult {
            probe_id: "probe-002".to_owned(),
            readiness: HarnessReadiness::Unavailable as i32,
            observed_protocol: None,
            observed_at: Some(Timestamp {
                seconds: 1,
                nanos: 0,
            }),
            ..ProbeHarnessResult::default()
        };
        assert_eq!(
            validate_probe_result(&request(), &result, &expected),
            Ok(())
        );
    }

    #[test]
    fn rejects_unknown_readiness_even_when_probe_is_otherwise_well_formed() {
        let expected = fingerprint();
        let mut result = ready_result(expected.clone());
        result.readiness = 99;
        assert_eq!(
            validate_probe_result(&request(), &result, &expected),
            Err(ProbeValidationError::ReadinessInvalid)
        );
    }
}

#[cfg(test)]
mod dispatch_context_gate_tests {
    use super::*;
    use crate::{AdapterEdgeConfig, AdapterEdgeKey};
    use egopulse_domain_contracts::v01::egopulse::{
        common::v1::ContractReference,
        harness::v1::{DispatchRouteBinding, NoCatalogSnapshot, dispatch_route_binding},
    };
    use std::fs;
    use std::path::Path;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const ADAPTER_ID: &str = "adapter:context-gate-test";
    const PROFILE_ID: &str = "profile:context-gate-test";

    struct FixtureRoot(PathBuf);

    impl FixtureRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "egopulse-harness-context-{label}-{}",
                Uuid::now_v7()
            ));
            fs::create_dir_all(&path).expect("create context gate fixture");
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("adapter.sqlcipher")
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

    fn open_edge(path: &Path) -> AdapterEdge {
        AdapterEdge::open(AdapterEdgeConfig {
            database_path: path.to_owned(),
            adapter_id: ADAPTER_ID.to_owned(),
            store_epoch: "context-gate-test-v1".to_owned(),
            key: AdapterEdgeKey::new([0x6d; 32]),
        })
        .expect("open context gate edge")
    }

    #[derive(Clone)]
    struct FixtureResolver {
        material: ResolvedDispatchMaterial,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl DispatchMaterialResolver for FixtureResolver {
        fn resolve(
            &self,
            _envelope: &DispatchEnvelope,
        ) -> Result<ResolvedDispatchMaterial, HarnessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(harness_error(
                    HarnessErrorCode::DependencyUnavailable,
                    "FIXTURE_RESOLVER_FAILURE",
                    true,
                    false,
                    None,
                ));
            }
            Ok(self.material.clone())
        }
    }

    struct CountingDriver {
        sends: Arc<AtomicUsize>,
    }

    impl NativeHarnessDriver for CountingDriver {
        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            Box::pin(async { panic!("probe is not used") })
        }

        fn send_dispatch<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(DriverDelivery {
                    native_request_ref: "native-request:context-test".to_owned(),
                    native_session_ref: "native-session:context-test".to_owned(),
                    native_execution_ref: Some("native-execution:context-test".to_owned()),
                    raw_evidence: b"context-gate-delivered".to_vec(),
                })
            })
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
            Box::pin(async { panic!("next_event is not used") })
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("approval is not used") })
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("cancel is not used") })
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            Box::pin(async { panic!("reconcile is not used") })
        }
    }

    struct ResidentDriver {
        sends: Arc<AtomicUsize>,
        terminal: Option<DriverEvent>,
    }

    impl NativeHarnessDriver for ResidentDriver {
        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            Box::pin(async { panic!("probe is not used") })
        }

        fn send_dispatch<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(DriverDelivery {
                    native_request_ref: "native-request:resident-test".to_owned(),
                    native_session_ref: "native-session:resident-test".to_owned(),
                    native_execution_ref: Some("native-execution:resident-test".to_owned()),
                    raw_evidence: b"resident-dispatch-delivered".to_vec(),
                })
            })
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
            let event = self.terminal.take();
            Box::pin(async move { Ok(event) })
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("approval is not used") })
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("cancel is not used") })
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            Box::pin(async { panic!("reconcile is not used") })
        }
    }

    struct TerminalCandidateDriver {
        sends: Arc<AtomicUsize>,
        candidate_reads: Arc<AtomicUsize>,
        terminal: Option<DriverEvent>,
        terminal_output: Option<TerminalOutputCandidate>,
    }

    impl NativeHarnessDriver for TerminalCandidateDriver {
        fn is_dispatch_ready(&self) -> bool {
            true
        }

        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            Box::pin(async { panic!("probe is not used") })
        }

        fn send_dispatch<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(DriverDelivery {
                    native_request_ref: "native-request:terminal-candidate-test".to_owned(),
                    native_session_ref: "native-session:terminal-candidate-test".to_owned(),
                    native_execution_ref: Some(
                        "native-execution:terminal-candidate-test".to_owned(),
                    ),
                    raw_evidence: b"terminal-candidate-delivered".to_vec(),
                })
            })
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
            let event = self.terminal.take();
            Box::pin(async move { Ok(event) })
        }

        fn take_terminal_output_candidate<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<TerminalOutputCandidate>, DriverError>> {
            self.candidate_reads.fetch_add(1, Ordering::SeqCst);
            let candidate = self.terminal_output.take();
            Box::pin(async move { Ok(candidate) })
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("approval is not used") })
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("cancel is not used") })
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            Box::pin(async { panic!("reconcile is not used") })
        }
    }

    #[derive(Clone)]
    struct CountingGate {
        authorization: DispatchContextAuthorization,
        ready_calls: Arc<AtomicUsize>,
        existing_calls: Arc<AtomicUsize>,
    }

    impl DispatchContextAuthorizationGate for CountingGate {
        fn authorize_ready_dispatch(
            &self,
            _envelope: &DispatchEnvelope,
        ) -> Result<DispatchContextAuthorization, HarnessError> {
            self.ready_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.authorization.clone())
        }

        fn verify_existing_dispatch(
            &self,
            _envelope: &DispatchEnvelope,
        ) -> Result<DispatchContextAuthorization, HarnessError> {
            self.existing_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.authorization.clone())
        }
    }

    struct CountingMaterialGuard {
        calls: Arc<AtomicUsize>,
    }

    impl ReadyDispatchMaterialGuard for CountingMaterialGuard {
        fn validate_ready_dispatch<'a>(
            &'a self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> Pin<Box<dyn Future<Output = Result<(), HarnessError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone)]
    struct CountingRecoveryGate {
        recovery: DispatchContextRecovery,
        calls: Arc<AtomicUsize>,
    }

    impl DispatchContextRecoveryGate for CountingRecoveryGate {
        fn recover_existing_dispatch(
            &self,
            _envelope: &DispatchEnvelope,
        ) -> Result<DispatchContextRecovery, HarnessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.recovery.clone())
        }
    }

    struct RecoveryDriver {
        reconciles: Arc<AtomicUsize>,
        finding: ReconciliationFinding,
    }

    impl NativeHarnessDriver for RecoveryDriver {
        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            Box::pin(async { panic!("probe is not used") })
        }

        fn send_dispatch<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            Box::pin(async { panic!("send is forbidden during recovery") })
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
            Box::pin(async { panic!("next_event is not used") })
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("approval is not used") })
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            Box::pin(async { panic!("cancel is not used") })
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            self.reconciles.fetch_add(1, Ordering::SeqCst);
            let finding = self.finding.clone();
            Box::pin(async move { Ok(finding) })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl AdapterClock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp {
                seconds: 1_787_488_000,
                nanos: 0,
            }
        }
    }

    fn protocol() -> NativeProtocolFingerprint {
        NativeProtocolFingerprint {
            protocol_name: "fixture".to_owned(),
            protocol_version: "v1".to_owned(),
            schema_sha256: "a".repeat(64),
            adapter_version: "test".to_owned(),
            native_executable_version: "test".to_owned(),
            native_binary_sha256: None,
        }
    }

    fn material() -> ResolvedDispatchMaterial {
        ResolvedDispatchMaterial {
            canonical_input_bundle: br#"{"prompt":"context gate"}"#.to_vec(),
            prompt: "context gate".to_owned(),
            workspace_root: std::env::temp_dir(),
            model: None,
        }
    }

    fn envelope(material: &ResolvedDispatchMaterial, dispatch_id: &str) -> DispatchEnvelope {
        let digest = sha256(&material.canonical_input_bundle);
        DispatchEnvelope {
            run_id: "run-context-001".to_owned(),
            run_revision: 1,
            step_id: "step-context-001".to_owned(),
            step_revision: 1,
            attempt_id: format!("attempt-{dispatch_id}"),
            attempt_revision: 1,
            dispatch_id: dispatch_id.to_owned(),
            dispatch_fingerprint: "b".repeat(64),
            fencing_token: 1,
            capability_profile_ref: Some(ContractReference {
                contract_id: PROFILE_ID.to_owned(),
                version: "1".to_owned(),
                sha256: "c".repeat(64),
            }),
            input_bundle_ref: format!("ctx-{digest}.json"),
            input_bundle_sha256: digest,
            workspace_ref: "workspace".to_owned(),
            ..DispatchEnvelope::default()
        }
    }

    fn authorization(envelope: &DispatchEnvelope) -> DispatchContextAuthorization {
        let snapshot_id = match classify_dispatch_context_reference(&envelope.input_bundle_ref) {
            DispatchContextReference::ContextSnapshot { snapshot_id } => snapshot_id,
            other => panic!("expected context reference, got {other:?}"),
        };
        DispatchContextAuthorization::Authorized(Box::new(AuthorizedDispatchContext {
            binding: DispatchContextBinding {
                snapshot_id: snapshot_id.clone(),
                snapshot_revision: 1,
                content_digest_sha256: envelope.input_bundle_sha256.clone(),
                expected_scope_ref: "scope:repo".to_owned(),
                memory_pack: None,
            },
            receipt: DispatchContextAuthorizationReceipt {
                authorization_id: "ctxauth:test".to_owned(),
                snapshot_id,
                snapshot_revision: 1,
                observed_state_revision: 1,
                attempt_id: envelope.attempt_id.clone(),
                dispatch_id: envelope.dispatch_id.clone(),
                input_digest_sha256: envelope.input_bundle_sha256.clone(),
                expected_scope_ref: "scope:repo".to_owned(),
                request_digest_sha256: "d".repeat(64),
                event_id: "event:context-auth".to_owned(),
                committed_at_seconds: 1_787_488_000,
                replayed: false,
            },
            memory_use: None,
        }))
    }

    fn route_binding() -> DispatchRouteBinding {
        let mut binding = DispatchRouteBinding {
            provider_bootstrap_profile_id: "provider:openai".to_owned(),
            selected_harness_id: "codex".to_owned(),
            provider_model_id: "gpt-5.3-codex".to_owned(),
            catalog_snapshot: Some(dispatch_route_binding::CatalogSnapshot::NoCatalogSnapshot(
                NoCatalogSnapshot {},
            )),
            capability_profile_id: PROFILE_ID.to_owned(),
            route_binding_sha256: String::new(),
        };
        binding.route_binding_sha256 = crate::canonical_dispatch_route_binding_digest(&binding)
            .expect("canonical route binding");
        binding
    }

    fn memory_authorization(envelope: &DispatchEnvelope) -> DispatchContextAuthorization {
        let DispatchContextAuthorization::Authorized(mut context) = authorization(envelope) else {
            panic!("fixture authorization")
        };
        let memory_pack_snapshot_sha256 = "e".repeat(64);
        context.binding.memory_pack = Some(DispatchMemoryPackBinding {
            memory_authority_revision: 7,
            memory_pack_snapshot_sha256: memory_pack_snapshot_sha256.clone(),
        });
        let route = envelope.route_binding.as_ref().expect("dispatch route");
        context.memory_use = Some(DispatchMemoryUseReceipt {
            receipt_id: "memory-use:test".to_owned(),
            snapshot_id: context.binding.snapshot_id.clone(),
            snapshot_revision: context.binding.snapshot_revision,
            consumer_principal_id: route.selected_harness_id.clone(),
            model_ref: route.provider_model_id.clone(),
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            memory_authority_revision: 7,
            memory_pack_snapshot_sha256,
            request_digest_sha256: "f".repeat(64),
            replayed: false,
        });
        DispatchContextAuthorization::Authorized(context)
    }

    fn result_error(result: DispatchResult) -> HarnessError {
        match result.outcome.expect("dispatch outcome") {
            dispatch_result::Outcome::Error(error) => error,
            dispatch_result::Outcome::Receipt(receipt) => {
                panic!("expected error, got receipt {receipt:?}")
            }
        }
    }

    fn assert_prepared(path: &Path, envelope: &DispatchEnvelope) {
        let mut edge = open_edge(path);
        assert_eq!(
            edge.prepare_dispatch(envelope, 1_787_488_001)
                .expect("inspect prepared dispatch"),
            DispatchPreparation::Ready
        );
        let inspection = edge.inspect().expect("inspect edge");
        assert_eq!(inspection.dispatch_count, 1);
        assert_eq!(inspection.delivery_unknown_count, 0);
    }

    fn adapter(
        path: &Path,
        material: ResolvedDispatchMaterial,
        sends: Arc<AtomicUsize>,
    ) -> GovernedHarnessAdapter<FixtureResolver, CountingDriver, FixedClock> {
        adapter_with_resolver(path, material, sends, Arc::new(AtomicUsize::new(0)), false)
    }

    fn adapter_with_resolver(
        path: &Path,
        material: ResolvedDispatchMaterial,
        sends: Arc<AtomicUsize>,
        resolver_calls: Arc<AtomicUsize>,
        resolver_fails: bool,
    ) -> GovernedHarnessAdapter<FixtureResolver, CountingDriver, FixedClock> {
        GovernedHarnessAdapter::new(
            ADAPTER_ID,
            PROFILE_ID,
            protocol(),
            open_edge(path),
            FixtureResolver {
                material,
                calls: resolver_calls,
                fail: resolver_fails,
            },
            CountingDriver { sends },
            FixedClock,
        )
    }

    fn historical_recovery(
        envelope: &DispatchEnvelope,
        authority_immutable_bytes: Vec<u8>,
    ) -> DispatchContextRecovery {
        let snapshot_id = match classify_dispatch_context_reference(&envelope.input_bundle_ref) {
            DispatchContextReference::ContextSnapshot { snapshot_id } => snapshot_id,
            other => panic!("expected context reference, got {other:?}"),
        };
        DispatchContextRecovery::Historical(Box::new(HistoricalDispatchContext {
            binding: HistoricalDispatchContextBinding {
                snapshot_id,
                snapshot_revision: 1,
                content_digest_sha256: envelope.input_bundle_sha256.clone(),
                expected_scope_ref: "scope:repo".to_owned(),
            },
            authority_immutable_bytes,
            observed_state_revision: 2,
            observed_state: HistoricalDispatchContextState::Revoked,
        }))
    }

    fn seed_reconciliation_dispatch(path: &Path, envelope: &DispatchEnvelope) {
        let mut edge = open_edge(path);
        assert_eq!(
            edge.prepare_dispatch(envelope, 1_787_488_001)
                .expect("seed reconciliation dispatch"),
            DispatchPreparation::Ready
        );
    }

    fn seed_non_delivered_reconciliation_receipt(
        path: &Path,
        envelope: &DispatchEnvelope,
        disposition: DeliveryDisposition,
        mutate: impl FnOnce(&mut DispatchReceipt),
        corrupt_digest: bool,
    ) {
        let mut edge = open_edge(path);
        edge.begin_delivery(&envelope.dispatch_id, 1_787_488_002)
            .expect("begin non-delivered reconciliation receipt");
        let mut receipt = DispatchReceipt {
            receipt_id: format!("receipt:reconciliation:{}", envelope.dispatch_id),
            disposition: disposition as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: ADAPTER_ID.to_owned(),
            capability_profile_id: PROFILE_ID.to_owned(),
            evidence_ref: format!("fixture:reconciliation:{}", envelope.dispatch_id),
            ..DispatchReceipt::default()
        };
        mutate(&mut receipt);
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        if corrupt_digest {
            receipt.receipt_digest_sha256 = "0".repeat(64);
        }
        edge.record_dispatch_receipt(&receipt, b"non-delivered-reconciliation", 1_787_488_003)
            .expect("record non-delivered reconciliation receipt");
    }

    fn recovery_adapter(
        path: &Path,
        material: ResolvedDispatchMaterial,
        resolver_calls: Arc<AtomicUsize>,
        reconciles: Arc<AtomicUsize>,
    ) -> GovernedHarnessAdapter<FixtureResolver, RecoveryDriver, FixedClock> {
        recovery_adapter_with_finding(
            path,
            material,
            resolver_calls,
            reconciles,
            ReconciliationFinding::NoEffectProven {
                evidence_ref: "recovery:no-effect".to_owned(),
            },
        )
    }

    fn recovery_adapter_with_finding(
        path: &Path,
        material: ResolvedDispatchMaterial,
        resolver_calls: Arc<AtomicUsize>,
        reconciles: Arc<AtomicUsize>,
        finding: ReconciliationFinding,
    ) -> GovernedHarnessAdapter<FixtureResolver, RecoveryDriver, FixedClock> {
        GovernedHarnessAdapter::new(
            ADAPTER_ID,
            PROFILE_ID,
            protocol(),
            open_edge(path),
            FixtureResolver {
                material,
                calls: resolver_calls,
                fail: false,
            },
            RecoveryDriver {
                reconciles,
                finding,
            },
            FixedClock,
        )
    }

    #[tokio::test]
    async fn default_gate_rejects_context_and_malformed_bindings_before_begin_or_send() {
        for (label, reference, expected_detail) in [
            ("valid", None, "CONTEXT_GATE_UNAVAILABLE"),
            (
                "malformed-prefix",
                Some("ctx:not-a-bundle".to_owned()),
                "CONTEXT_BINDING_INVALID",
            ),
            (
                "malformed-case",
                Some(format!("ctx-{}.json", "AB".repeat(32))),
                "CONTEXT_BINDING_INVALID",
            ),
        ] {
            let root = FixtureRoot::new(label);
            let resolved = material();
            let mut dispatch = envelope(&resolved, &format!("dispatch-{label}"));
            if let Some(reference) = reference {
                dispatch.input_bundle_ref = reference;
            }
            let sends = Arc::new(AtomicUsize::new(0));
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let mut governed = adapter_with_resolver(
                &root.database(),
                resolved,
                Arc::clone(&sends),
                Arc::clone(&resolver_calls),
                true,
            );

            let error = result_error(
                governed
                    .dispatch(&dispatch)
                    .await
                    .expect("dispatch is represented as a typed result"),
            );
            assert_eq!(error.safe_detail_code, expected_detail);
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(sends.load(Ordering::SeqCst), 0);
            drop(governed);
            assert_prepared(&root.database(), &dispatch);
        }
    }

    #[tokio::test]
    async fn matching_context_authorization_is_the_only_ready_path_that_can_send() {
        let root = FixtureRoot::new("matching");
        let resolved = material();
        let dispatch = envelope(&resolved, "dispatch-matching");
        let sends = Arc::new(AtomicUsize::new(0));
        let ready_calls = Arc::new(AtomicUsize::new(0));
        let existing_calls = Arc::new(AtomicUsize::new(0));
        let mut governed = adapter(&root.database(), resolved, Arc::clone(&sends))
            .with_dispatch_context_authorization_gate(CountingGate {
                authorization: authorization(&dispatch),
                ready_calls: Arc::clone(&ready_calls),
                existing_calls: Arc::clone(&existing_calls),
            });

        let result = governed
            .dispatch(&dispatch)
            .await
            .expect("authorized dispatch");
        assert!(matches!(
            result.outcome,
            Some(dispatch_result::Outcome::Receipt(receipt))
                if receipt.disposition == DeliveryDisposition::Delivered as i32
        ));
        assert_eq!(ready_calls.load(Ordering::SeqCst), 1);
        assert_eq!(existing_calls.load(Ordering::SeqCst), 0);
        assert_eq!(sends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn memory_bound_authorization_requires_complete_receipt_and_exact_route_before_send() {
        let root = FixtureRoot::new("memory-matching");
        let route = route_binding();
        let mut resolved = material();
        resolved.model = Some(route.provider_model_id.clone());
        let mut dispatch = envelope(&resolved, "dispatch-memory-matching");
        dispatch.route_binding = Some(route.clone());
        let sends = Arc::new(AtomicUsize::new(0));
        let mut governed = adapter(&root.database(), resolved, Arc::clone(&sends))
            .with_dispatch_route_binding(route.clone(), route.provider_model_id.clone())
            .with_dispatch_context_authorization_gate(CountingGate {
                authorization: memory_authorization(&dispatch),
                ready_calls: Arc::new(AtomicUsize::new(0)),
                existing_calls: Arc::new(AtomicUsize::new(0)),
            });

        let result = governed
            .dispatch(&dispatch)
            .await
            .expect("memory-authorized dispatch");
        assert!(matches!(
            result.outcome,
            Some(dispatch_result::Outcome::Receipt(receipt))
                if receipt.disposition == DeliveryDisposition::Delivered as i32
        ));
        assert_eq!(sends.load(Ordering::SeqCst), 1);

        for label in [
            "missing-receipt",
            "missing-binding",
            "consumer-route",
            "model-route",
            "memory-revision",
            "memory-pack",
            "memory-request-digest",
            "memory-snapshot",
        ] {
            let root = FixtureRoot::new(label);
            let route = route_binding();
            let mut resolved = material();
            resolved.model = Some(route.provider_model_id.clone());
            let mut dispatch = envelope(&resolved, &format!("dispatch-{label}"));
            dispatch.route_binding = Some(route.clone());
            let DispatchContextAuthorization::Authorized(mut context) =
                memory_authorization(&dispatch)
            else {
                panic!("memory fixture authorization")
            };
            match label {
                "missing-receipt" => context.memory_use = None,
                "missing-binding" => context.binding.memory_pack = None,
                "consumer-route" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .consumer_principal_id = "other-harness".to_owned();
                }
                "model-route" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .model_ref = "other-model".to_owned();
                }
                "memory-revision" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .memory_authority_revision += 1;
                }
                "memory-pack" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .memory_pack_snapshot_sha256 = "0".repeat(64);
                }
                "memory-request-digest" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .request_digest_sha256 = "F".repeat(64);
                }
                "memory-snapshot" => {
                    context
                        .memory_use
                        .as_mut()
                        .expect("memory receipt")
                        .snapshot_id = format!("ctx:{}", "0".repeat(64));
                }
                _ => unreachable!(),
            }
            let sends = Arc::new(AtomicUsize::new(0));
            let mut governed = adapter(&root.database(), resolved, Arc::clone(&sends))
                .with_dispatch_route_binding(route.clone(), route.provider_model_id.clone())
                .with_dispatch_context_authorization_gate(CountingGate {
                    authorization: DispatchContextAuthorization::Authorized(context),
                    ready_calls: Arc::new(AtomicUsize::new(0)),
                    existing_calls: Arc::new(AtomicUsize::new(0)),
                });

            let error = result_error(
                governed
                    .dispatch(&dispatch)
                    .await
                    .expect("tamper is represented as typed result"),
            );
            assert_eq!(error.safe_detail_code, "CONTEXT_AUTHORIZATION_INVALID");
            assert_eq!(sends.load(Ordering::SeqCst), 0);
            drop(governed);
            assert_prepared(&root.database(), &dispatch);
        }
    }

    #[tokio::test]
    async fn every_context_binding_and_receipt_tuple_tamper_stops_before_begin_or_send() {
        let base_material = material();
        let base_envelope = envelope(&base_material, "dispatch-tamper-base");
        let DispatchContextAuthorization::Authorized(base) = authorization(&base_envelope) else {
            panic!("fixture authorization")
        };
        let mut cases = Vec::new();

        let mut binding = base.clone();
        binding.binding.snapshot_revision += 1;
        cases.push((
            "binding",
            binding,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut receipt = base.clone();
        receipt.receipt.authorization_id.clear();
        cases.push((
            "receipt",
            receipt,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut attempt = base.clone();
        attempt.receipt.attempt_id = "attempt-tampered".to_owned();
        cases.push((
            "attempt",
            attempt,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut dispatch = base.clone();
        dispatch.receipt.dispatch_id = "dispatch-tampered".to_owned();
        cases.push((
            "dispatch",
            dispatch,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut scope = base.clone();
        scope.receipt.expected_scope_ref = "scope:other".to_owned();
        cases.push((
            "scope",
            scope,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut digest = base.clone();
        digest.binding.content_digest_sha256 = "e".repeat(64);
        cases.push((
            "digest",
            digest,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut receipt_snapshot_id = base.clone();
        receipt_snapshot_id.receipt.snapshot_id = format!("ctx:{}", "e".repeat(64));
        cases.push((
            "receipt-snapshot-id",
            receipt_snapshot_id,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut receipt_snapshot_revision = base.clone();
        receipt_snapshot_revision.receipt.snapshot_revision += 1;
        cases.push((
            "receipt-snapshot-revision",
            receipt_snapshot_revision,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut observed_state_revision = base.clone();
        observed_state_revision.receipt.observed_state_revision = 0;
        cases.push((
            "receipt-observed-state-revision",
            observed_state_revision,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut receipt_input_digest = base.clone();
        receipt_input_digest.receipt.input_digest_sha256 = "e".repeat(64);
        cases.push((
            "receipt-input-digest",
            receipt_input_digest,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut request_digest = base.clone();
        request_digest.receipt.request_digest_sha256 = "D".repeat(64);
        cases.push((
            "receipt-request-digest",
            request_digest,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut event_id = base.clone();
        event_id.receipt.event_id.clear();
        cases.push((
            "receipt-event-id",
            event_id,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut committed_at = base.clone();
        committed_at.receipt.committed_at_seconds = 0;
        cases.push((
            "receipt-committed-at",
            committed_at,
            base_material.clone(),
            "CONTEXT_AUTHORIZATION_INVALID",
        ));
        let mut bytes_mismatch = base_material.clone();
        bytes_mismatch.canonical_input_bundle = b"different owned bytes".to_vec();
        cases.push((
            "bytes-envelope-digest",
            base,
            bytes_mismatch,
            "INPUT_BUNDLE_DIGEST_MISMATCH",
        ));

        for (label, mut context, resolved_material, expected_detail) in cases {
            let root = FixtureRoot::new(label);
            let mut dispatch = base_envelope.clone();
            dispatch.dispatch_id = format!("dispatch-tamper-{label}");
            dispatch.attempt_id = format!("attempt-tamper-{label}");
            context.receipt.attempt_id = match label {
                "attempt" => context.receipt.attempt_id,
                _ => dispatch.attempt_id.clone(),
            };
            context.receipt.dispatch_id = match label {
                "dispatch" => context.receipt.dispatch_id,
                _ => dispatch.dispatch_id.clone(),
            };
            let sends = Arc::new(AtomicUsize::new(0));
            let mut governed = adapter(&root.database(), resolved_material, Arc::clone(&sends))
                .with_dispatch_context_authorization_gate(CountingGate {
                    authorization: DispatchContextAuthorization::Authorized(context),
                    ready_calls: Arc::new(AtomicUsize::new(0)),
                    existing_calls: Arc::new(AtomicUsize::new(0)),
                });

            let error = result_error(
                governed
                    .dispatch(&dispatch)
                    .await
                    .expect("tamper is a typed dispatch error"),
            );
            assert_eq!(error.safe_detail_code, expected_detail);
            assert_eq!(sends.load(Ordering::SeqCst), 0);
            drop(governed);
            assert_prepared(&root.database(), &dispatch);
        }
    }

    #[tokio::test]
    async fn replay_and_delivery_unknown_use_existing_lookup_only_and_never_send() {
        for replay in [false, true] {
            let label = if replay { "replay" } else { "delivery-unknown" };
            let root = FixtureRoot::new(label);
            let resolved = material();
            let dispatch = envelope(&resolved, &format!("dispatch-{label}"));
            let mut seeded = open_edge(&root.database());
            assert_eq!(
                seeded
                    .prepare_dispatch(&dispatch, 1_787_487_999)
                    .expect("seed prepare"),
                DispatchPreparation::Ready
            );
            seeded
                .begin_delivery(&dispatch.dispatch_id, 1_787_487_999)
                .expect("seed native boundary");
            if replay {
                let mut receipt = DispatchReceipt {
                    receipt_id: "receipt:seeded".to_owned(),
                    disposition: DeliveryDisposition::Delivered as i32,
                    attempt_id: dispatch.attempt_id.clone(),
                    dispatch_id: dispatch.dispatch_id.clone(),
                    fencing_token: dispatch.fencing_token,
                    adapter_id: ADAPTER_ID.to_owned(),
                    capability_profile_id: PROFILE_ID.to_owned(),
                    evidence_ref: "evidence:seeded".to_owned(),
                    delivered_at: Some(Timestamp {
                        seconds: 1_787_487_999,
                        nanos: 0,
                    }),
                    ..DispatchReceipt::default()
                };
                receipt.receipt_digest_sha256 = canonical_digest(&receipt);
                seeded
                    .record_dispatch_receipt(&receipt, b"seeded", 1_787_487_999)
                    .expect("seed receipt");
            }
            drop(seeded);

            let ready_calls = Arc::new(AtomicUsize::new(0));
            let existing_calls = Arc::new(AtomicUsize::new(0));
            let material_calls = Arc::new(AtomicUsize::new(0));
            let sends = Arc::new(AtomicUsize::new(0));
            let mut governed = adapter(&root.database(), resolved, Arc::clone(&sends))
                .with_dispatch_context_authorization_gate(CountingGate {
                    authorization: authorization(&dispatch),
                    ready_calls: Arc::clone(&ready_calls),
                    existing_calls: Arc::clone(&existing_calls),
                })
                .with_ready_dispatch_material_guard(Arc::new(CountingMaterialGuard {
                    calls: Arc::clone(&material_calls),
                }));
            let result = governed
                .dispatch(&dispatch)
                .await
                .expect("recover existing dispatch");
            assert!(matches!(
                result.outcome,
                Some(dispatch_result::Outcome::Receipt(_))
            ));
            assert_eq!(ready_calls.load(Ordering::SeqCst), 0);
            assert_eq!(existing_calls.load(Ordering::SeqCst), 1);
            assert_eq!(material_calls.load(Ordering::SeqCst), 0);
            assert_eq!(sends.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn static_dispatches_remain_compatible_with_the_default_gate() {
        let root = FixtureRoot::new("static");
        let resolved = material();
        let mut dispatch = envelope(&resolved, "dispatch-static");
        dispatch.input_bundle_ref = "static-bundle.json".to_owned();
        let material_calls = Arc::new(AtomicUsize::new(0));
        let sends = Arc::new(AtomicUsize::new(0));
        let mut governed = adapter(&root.database(), resolved, Arc::clone(&sends))
            .with_ready_dispatch_material_guard(Arc::new(CountingMaterialGuard {
                calls: Arc::clone(&material_calls),
            }));

        let result = governed.dispatch(&dispatch).await.expect("static dispatch");
        assert!(matches!(
            result.outcome,
            Some(dispatch_result::Outcome::Receipt(receipt))
                if receipt.disposition == DeliveryDisposition::Delivered as i32
        ));
        assert_eq!(material_calls.load(Ordering::SeqCst), 1);
        assert_eq!(sends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resident_dispatch_is_current_process_only_and_clears_after_terminal_pump() {
        let root = FixtureRoot::new("resident-dispatch");
        let resolved = material();
        let mut dispatch = envelope(&resolved, "dispatch-resident");
        dispatch.input_bundle_ref = "static-resident-bundle.json".to_owned();
        let sends = Arc::new(AtomicUsize::new(0));
        let terminal = DriverEvent {
            native_key: "native:resident:interrupted".to_owned(),
            native_event_id: Some("native-event:resident:interrupted".to_owned()),
            native_sequence: Some(2),
            native_observed_at: Timestamp {
                seconds: 10,
                nanos: 0,
            },
            criticality: ObservationCriticality::Terminal,
            payload: harness_observation::Payload::Lifecycle(
                egopulse_domain_contracts::v01::egopulse::harness::v1::LifecycleObservation {
                    kind: LifecycleKind::ExecutionInterrupted as i32,
                    ..Default::default()
                },
            ),
            raw_event: b"resident-interrupted".to_vec(),
        };
        let mut governed = GovernedHarnessAdapter::new(
            ADAPTER_ID,
            PROFILE_ID,
            protocol(),
            open_edge(&root.database()),
            FixtureResolver {
                material: resolved.clone(),
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            ResidentDriver {
                sends: Arc::clone(&sends),
                terminal: Some(terminal),
            },
            FixedClock,
        );

        let delivered = governed
            .dispatch(&dispatch)
            .await
            .expect("real native send");
        assert!(matches!(
            delivered.outcome,
            Some(dispatch_result::Outcome::Receipt(receipt))
                if receipt.disposition == DeliveryDisposition::Delivered as i32
        ));
        assert!(governed.has_resident_dispatch(&dispatch.dispatch_id));
        assert!(matches!(
            governed.observe_nonresident_dispatch(&dispatch.dispatch_id),
            Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence)
        ));
        assert_eq!(sends.load(Ordering::SeqCst), 1);

        governed.dispatch(&dispatch).await.expect("durable replay");
        assert!(governed.has_resident_dispatch(&dispatch.dispatch_id));
        assert_eq!(sends.load(Ordering::SeqCst), 1);

        let terminal = governed
            .pump_one(&dispatch)
            .await
            .expect("terminal pump")
            .expect("interrupted terminal observation");
        assert_eq!(
            terminal.criticality,
            ObservationCriticality::Terminal as i32
        );
        assert!(!governed.has_resident_dispatch(&dispatch.dispatch_id));
        let reader = governed.runtime_residency_reader();
        assert!(
            !reader
                .observes_nonresident_dispatch(&dispatch.dispatch_id)
                .expect("read unobserved nonresident state")
        );
        let observation = governed
            .observe_nonresident_dispatch(&dispatch.dispatch_id)
            .expect("observe terminal dispatch as nonresident");
        assert!(
            reader
                .observes_nonresident_dispatch(&dispatch.dispatch_id)
                .expect("read scoped nonresident observation")
        );
        drop(observation);
        assert!(
            !reader
                .observes_nonresident_dispatch(&dispatch.dispatch_id)
                .expect("scoped observation is removed on drop")
        );
        drop(governed);

        let mut reopened = adapter(&root.database(), resolved, Arc::clone(&sends));
        reopened
            .dispatch(&dispatch)
            .await
            .expect("persisted delivered replay after reopen");
        assert!(!reopened.has_resident_dispatch(&dispatch.dispatch_id));
        assert_eq!(sends.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn busy_terminal_append_keeps_native_capacity_busy_until_same_candidate_commits() {
        let root = FixtureRoot::new("terminal-append-retry");
        let resolved = material();
        let mut dispatch = envelope(&resolved, "dispatch-terminal-append-retry");
        dispatch.input_bundle_ref = "static-terminal-append-retry.json".to_owned();
        let sends = Arc::new(AtomicUsize::new(0));
        let candidate_reads = Arc::new(AtomicUsize::new(0));
        let terminal = DriverEvent {
            native_key: "native:terminal-append-retry".to_owned(),
            native_event_id: Some("native-event:terminal-append-retry".to_owned()),
            native_sequence: Some(2),
            native_observed_at: Timestamp {
                seconds: 10,
                nanos: 0,
            },
            criticality: ObservationCriticality::Terminal,
            payload: harness_observation::Payload::Lifecycle(
                egopulse_domain_contracts::v01::egopulse::harness::v1::LifecycleObservation {
                    kind: LifecycleKind::ExecutionCompleted as i32,
                    ..Default::default()
                },
            ),
            raw_event: b"terminal-append-retry-event".to_vec(),
        };
        let expected_content = b"same terminal output bytes".to_vec();
        let mut governed = GovernedHarnessAdapter::new(
            ADAPTER_ID,
            PROFILE_ID,
            protocol(),
            open_edge(&root.database()),
            FixtureResolver {
                material: resolved.clone(),
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            TerminalCandidateDriver {
                sends: Arc::clone(&sends),
                candidate_reads: Arc::clone(&candidate_reads),
                terminal: Some(terminal),
                terminal_output: Some(TerminalOutputCandidate {
                    dispatch_id: dispatch.dispatch_id.clone(),
                    native_completion_ref: "item:terminal-append-retry".to_owned(),
                    media_type: "text/plain".to_owned(),
                    content: expected_content.clone(),
                }),
            },
            FixedClock,
        );

        governed.dispatch(&dispatch).await.expect("native send");
        governed
            .bind_dispatch_task_lineage(&dispatch.dispatch_id, "task-terminal-append-retry", 1, 1)
            .expect("bind dispatch lineage");
        governed.fail_next_observation_append_with_busy_for_test();

        assert!(matches!(
            governed.pump_one(&dispatch).await,
            Err(GovernedAdapterError::ObservationAppendDeferred {
                source: AdapterEdgeError::Sql(error),
            }) if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)
        ));
        assert!(governed.has_resident_dispatch(&dispatch.dispatch_id));
        assert!(
            !governed.is_dispatch_ready(),
            "the Adapter-local pending append must block a second native dispatch"
        );
        assert_eq!(candidate_reads.load(Ordering::SeqCst), 1);

        let terminal = governed
            .pump_one(&dispatch)
            .await
            .expect("retry pending terminal append")
            .expect("terminal observation");
        assert_eq!(
            terminal.criticality,
            ObservationCriticality::Terminal as i32
        );
        assert_eq!(candidate_reads.load(Ordering::SeqCst), 1);
        assert!(!governed.has_resident_dispatch(&dispatch.dispatch_id));
        assert!(governed.is_dispatch_ready());

        let stored = governed
            .edge
            .terminal_output_candidate_for_dispatch(&dispatch.dispatch_id)
            .expect("read committed candidate")
            .expect("candidate persisted");
        assert_eq!(stored.native_completion_ref, "item:terminal-append-retry");
        assert_eq!(stored.content, expected_content);
    }

    #[tokio::test]
    async fn terminal_append_integrity_failure_remains_fatal() {
        let root = FixtureRoot::new("terminal-append-integrity");
        let resolved = material();
        let mut dispatch = envelope(&resolved, "dispatch-terminal-append-integrity");
        dispatch.input_bundle_ref = "static-terminal-append-integrity.json".to_owned();
        let sends = Arc::new(AtomicUsize::new(0));
        let terminal = DriverEvent {
            native_key: "native:terminal-append-integrity".to_owned(),
            native_event_id: Some("native-event:terminal-append-integrity".to_owned()),
            native_sequence: Some(2),
            native_observed_at: Timestamp {
                seconds: 10,
                nanos: 0,
            },
            criticality: ObservationCriticality::Terminal,
            payload: harness_observation::Payload::Lifecycle(
                egopulse_domain_contracts::v01::egopulse::harness::v1::LifecycleObservation {
                    kind: LifecycleKind::ExecutionInterrupted as i32,
                    ..Default::default()
                },
            ),
            raw_event: b"terminal-append-integrity-event".to_vec(),
        };
        let mut governed = GovernedHarnessAdapter::new(
            ADAPTER_ID,
            PROFILE_ID,
            protocol(),
            open_edge(&root.database()),
            FixtureResolver {
                material: resolved,
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            },
            ResidentDriver {
                sends,
                terminal: Some(terminal),
            },
            FixedClock,
        );

        governed.dispatch(&dispatch).await.expect("native send");
        governed.fail_next_observation_append_with_integrity_failure_for_test();
        assert!(matches!(
            governed.pump_one(&dispatch).await,
            Err(GovernedAdapterError::Edge(
                AdapterEdgeError::IntegrityFailure
            ))
        ));
        assert!(governed.has_resident_dispatch(&dispatch.dispatch_id));
        assert!(!governed.is_dispatch_ready());
    }

    #[test]
    fn only_busy_or_locked_edge_failures_are_deferred() {
        let sqlite_failure = |code| {
            AdapterEdgeError::Sql(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ))
        };
        assert!(is_retryable_observation_append_failure(&sqlite_failure(
            rusqlite::ffi::SQLITE_BUSY
        )));
        assert!(is_retryable_observation_append_failure(&sqlite_failure(
            rusqlite::ffi::SQLITE_LOCKED
        )));
        assert!(!is_retryable_observation_append_failure(
            &AdapterEdgeError::IntegrityFailure
        ));
    }

    #[tokio::test]
    async fn context_reconciliation_defaults_and_malformed_references_fail_before_resolution() {
        for (label, malformed) in [("default", false), ("malformed", true)] {
            let root = FixtureRoot::new(&format!("recovery-{label}"));
            let resolved = material();
            let mut dispatch = envelope(&resolved, &format!("dispatch-recovery-{label}"));
            if malformed {
                dispatch.input_bundle_ref = "ctx-not-canonical.json".to_owned();
            }
            seed_reconciliation_dispatch(&root.database(), &dispatch);
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let reconciles = Arc::new(AtomicUsize::new(0));
            let mut governed = recovery_adapter(
                &root.database(),
                resolved,
                Arc::clone(&resolver_calls),
                Arc::clone(&reconciles),
            );

            let evidence = governed
                .reconcile_dispatch(&format!("reconciliation-{label}"), &dispatch.dispatch_id)
                .await
                .expect("fail-closed recovery produces durable unknown evidence");
            assert!(matches!(
                evidence.finding,
                ReconciliationFinding::OutcomeUnknown { .. }
            ));
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(reconciles.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn static_reconciliation_remains_compatible_with_the_default_recovery_gate() {
        let root = FixtureRoot::new("recovery-static");
        let resolved = material();
        let mut dispatch = envelope(&resolved, "dispatch-recovery-static");
        dispatch.input_bundle_ref = "static-bundle.json".to_owned();
        seed_reconciliation_dispatch(&root.database(), &dispatch);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let reconciles = Arc::new(AtomicUsize::new(0));
        let mut governed = recovery_adapter(
            &root.database(),
            resolved,
            Arc::clone(&resolver_calls),
            Arc::clone(&reconciles),
        );

        let evidence = governed
            .reconcile_dispatch("reconciliation-static", &dispatch.dispatch_id)
            .await
            .expect("static reconciliation");
        assert!(matches!(
            evidence.finding,
            ReconciliationFinding::NoEffectProven { .. }
        ));
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
        assert_eq!(reconciles.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reconciliation_without_delivery_binding_defers_to_driver_after_owner_validation() {
        for (label, disposition, driver_finding) in [
            (
                "intent-no-receipt",
                None,
                ReconciliationFinding::NoEffectProven {
                    evidence_ref: "recovery:no-effect:no-receipt".to_owned(),
                },
            ),
            (
                "rejected-receipt",
                Some(DeliveryDisposition::Rejected),
                ReconciliationFinding::NoEffectProven {
                    evidence_ref: "recovery:no-effect:rejected".to_owned(),
                },
            ),
            (
                "unknown-receipt",
                Some(DeliveryDisposition::Unknown),
                ReconciliationFinding::OutcomeUnknown {
                    evidence_ref: "recovery:outcome-unknown".to_owned(),
                },
            ),
        ] {
            let root = FixtureRoot::new(&format!("recovery-{label}"));
            let resolved = material();
            let mut dispatch = envelope(&resolved, &format!("dispatch-recovery-{label}"));
            dispatch.input_bundle_ref = "static-bundle.json".to_owned();
            seed_reconciliation_dispatch(&root.database(), &dispatch);
            if let Some(disposition) = disposition {
                seed_non_delivered_reconciliation_receipt(
                    &root.database(),
                    &dispatch,
                    disposition,
                    |_| {},
                    false,
                );
            }
            let expected_finding = driver_finding.clone();
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let reconciles = Arc::new(AtomicUsize::new(0));
            let mut governed = recovery_adapter_with_finding(
                &root.database(),
                resolved,
                Arc::clone(&resolver_calls),
                Arc::clone(&reconciles),
                driver_finding,
            );

            let evidence = governed
                .reconcile_dispatch(&format!("reconciliation-{label}"), &dispatch.dispatch_id)
                .await
                .expect("reconcile without a confirmed delivery binding");
            assert_eq!(evidence.finding, expected_finding);
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 1);
            assert_eq!(reconciles.load(Ordering::SeqCst), 1);
        }

        for tamper in ["owner", "digest"] {
            let root = FixtureRoot::new(&format!("recovery-non-delivered-{tamper}"));
            let resolved = material();
            let mut dispatch = envelope(
                &resolved,
                &format!("dispatch-recovery-non-delivered-{tamper}"),
            );
            dispatch.input_bundle_ref = "static-bundle.json".to_owned();
            seed_reconciliation_dispatch(&root.database(), &dispatch);
            seed_non_delivered_reconciliation_receipt(
                &root.database(),
                &dispatch,
                DeliveryDisposition::Rejected,
                |receipt| {
                    if tamper == "owner" {
                        receipt.attempt_id = "attempt:other".to_owned();
                    }
                },
                tamper == "digest",
            );
            let reconciles = Arc::new(AtomicUsize::new(0));
            let mut governed = recovery_adapter(
                &root.database(),
                resolved,
                Arc::new(AtomicUsize::new(0)),
                Arc::clone(&reconciles),
            );
            assert!(matches!(
                governed
                    .reconcile_dispatch(
                        &format!("reconciliation-non-delivered-{tamper}"),
                        &dispatch.dispatch_id,
                    )
                    .await,
                Err(GovernedAdapterError::Edge(
                    AdapterEdgeError::IntegrityFailure
                ))
            ));
            assert_eq!(reconciles.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn recovered_context_bytes_mismatch_never_reaches_native_reconciliation() {
        let root = FixtureRoot::new("recovery-bytes-mismatch");
        let resolved = material();
        let dispatch = envelope(&resolved, "dispatch-recovery-bytes-mismatch");
        seed_reconciliation_dispatch(&root.database(), &dispatch);
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let reconciles = Arc::new(AtomicUsize::new(0));
        let gate_calls = Arc::new(AtomicUsize::new(0));
        let mut governed = recovery_adapter(
            &root.database(),
            resolved,
            Arc::clone(&resolver_calls),
            Arc::clone(&reconciles),
        )
        .with_dispatch_context_recovery_gate(CountingRecoveryGate {
            recovery: historical_recovery(&dispatch, b"tampered authority bytes".to_vec()),
            calls: Arc::clone(&gate_calls),
        });

        let evidence = governed
            .reconcile_dispatch("reconciliation-bytes-mismatch", &dispatch.dispatch_id)
            .await
            .expect("mismatch produces durable unknown evidence");
        assert!(matches!(
            evidence.finding,
            ReconciliationFinding::OutcomeUnknown { .. }
        ));
        assert_eq!(gate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reconciles.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn recovery_variant_and_reference_mismatch_fails_before_file_resolution() {
        for static_reference in [false, true] {
            let label = if static_reference {
                "static-with-context"
            } else {
                "context-with-not-context"
            };
            let root = FixtureRoot::new(label);
            let resolved = material();
            let mut dispatch = envelope(&resolved, &format!("dispatch-{label}"));
            let recovery = if static_reference {
                let historical =
                    historical_recovery(&dispatch, resolved.canonical_input_bundle.clone());
                dispatch.input_bundle_ref = "static-bundle.json".to_owned();
                historical
            } else {
                DispatchContextRecovery::NotContextBound
            };
            seed_reconciliation_dispatch(&root.database(), &dispatch);
            let resolver_calls = Arc::new(AtomicUsize::new(0));
            let reconciles = Arc::new(AtomicUsize::new(0));
            let gate_calls = Arc::new(AtomicUsize::new(0));
            let mut governed = recovery_adapter(
                &root.database(),
                resolved,
                Arc::clone(&resolver_calls),
                Arc::clone(&reconciles),
            )
            .with_dispatch_context_recovery_gate(CountingRecoveryGate {
                recovery,
                calls: Arc::clone(&gate_calls),
            });

            let evidence = governed
                .reconcile_dispatch(&format!("reconciliation-{label}"), &dispatch.dispatch_id)
                .await
                .expect("mismatched recovery variant is retained as unknown");
            assert!(matches!(
                evidence.finding,
                ReconciliationFinding::OutcomeUnknown { .. }
            ));
            assert_eq!(gate_calls.load(Ordering::SeqCst), 1);
            assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
            assert_eq!(reconciles.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn durable_reconciliation_evidence_replays_before_recovery_gate_or_native_calls() {
        let root = FixtureRoot::new("recovery-evidence-replay");
        let resolved = material();
        let dispatch = envelope(&resolved, "dispatch-recovery-evidence-replay");
        seed_reconciliation_dispatch(&root.database(), &dispatch);
        let first_gate_calls = Arc::new(AtomicUsize::new(0));
        let mut first = recovery_adapter(
            &root.database(),
            resolved.clone(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        )
        .with_dispatch_context_recovery_gate(CountingRecoveryGate {
            recovery: historical_recovery(&dispatch, resolved.canonical_input_bundle.clone()),
            calls: Arc::clone(&first_gate_calls),
        });
        let first_evidence = first
            .reconcile_dispatch("reconciliation-replay", &dispatch.dispatch_id)
            .await
            .expect("first reconciliation");
        assert!(!first_evidence.replayed);
        assert_eq!(first_gate_calls.load(Ordering::SeqCst), 1);
        drop(first);

        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let reconciles = Arc::new(AtomicUsize::new(0));
        let gate_calls = Arc::new(AtomicUsize::new(0));
        let mut reopened = recovery_adapter(
            &root.database(),
            resolved,
            Arc::clone(&resolver_calls),
            Arc::clone(&reconciles),
        )
        .with_dispatch_context_recovery_gate(CountingRecoveryGate {
            recovery: DispatchContextRecovery::NotContextBound,
            calls: Arc::clone(&gate_calls),
        });
        let replay = reopened
            .reconcile_dispatch("reconciliation-replay", &dispatch.dispatch_id)
            .await
            .expect("durable evidence replay");
        assert!(replay.replayed);
        assert_eq!(replay.evidence_id, first_evidence.evidence_id);
        assert_eq!(gate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
        assert_eq!(reconciles.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod delivered_recovery_tests {
    use super::*;
    use crate::{AdapterEdgeConfig, AdapterEdgeKey};
    use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
    use rusqlite::{Connection, params};
    use std::fs;
    use std::path::{Path, PathBuf};

    const ADAPTER_ID: &str = "adapter:test";
    const PROFILE_ID: &str = "profile:test";
    const EDGE_KEY: [u8; 32] = [0x5a; 32];

    struct IsolatedStore {
        root: PathBuf,
    }

    impl IsolatedStore {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).expect("create runtime recovery test directory");
            Self { root }
        }

        fn path(&self) -> PathBuf {
            self.root.join("adapter-edge.sqlcipher")
        }
    }

    impl Drop for IsolatedStore {
        fn drop(&mut self) {
            let temp = std::env::temp_dir();
            assert!(self.root.starts_with(&temp));
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove runtime recovery test directory");
            }
        }
    }

    struct UnusedResolver;

    impl DispatchMaterialResolver for UnusedResolver {
        fn resolve(
            &self,
            _envelope: &DispatchEnvelope,
        ) -> Result<ResolvedDispatchMaterial, HarnessError> {
            panic!("delivered recovery verification must not resolve dispatch material")
        }
    }

    struct PanicDriver;

    impl NativeHarnessDriver for PanicDriver {
        fn probe<'a>(
            &'a mut self,
            _request: &'a ProbeHarnessRequest,
        ) -> NativeHarnessFuture<'a, Result<ProbeHarnessResult, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }

        fn send_dispatch<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
            _material: &'a ResolvedDispatchMaterial,
        ) -> NativeHarnessFuture<'a, Result<DriverDelivery, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }

        fn next_event<'a>(
            &'a mut self,
            _envelope: &'a DispatchEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Option<DriverEvent>, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }

        fn decide_approval<'a>(
            &'a mut self,
            _envelope: &'a ApprovalDecisionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }

        fn cancel<'a>(
            &'a mut self,
            _envelope: &'a CancelExecutionEnvelope,
        ) -> NativeHarnessFuture<'a, Result<Vec<u8>, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }

        fn reconcile<'a>(
            &'a mut self,
            _context: &'a ReconciliationContext,
        ) -> NativeHarnessFuture<'a, Result<ReconciliationFinding, DriverError>> {
            panic!("delivered recovery verification must not call the native driver")
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl AdapterClock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp {
                seconds: 10,
                nanos: 0,
            }
        }
    }

    fn edge(path: &Path) -> AdapterEdge {
        AdapterEdge::open(AdapterEdgeConfig {
            database_path: path.to_owned(),
            adapter_id: ADAPTER_ID.to_owned(),
            store_epoch: "delivered-recovery-test-v1".to_owned(),
            key: AdapterEdgeKey::new(EDGE_KEY),
        })
        .expect("open Adapter Edge")
    }

    fn adapter(path: &Path) -> GovernedHarnessAdapter<UnusedResolver, PanicDriver, FixedClock> {
        adapter_with_runtime_identity(path, ADAPTER_ID, PROFILE_ID)
    }

    fn adapter_with_runtime_identity(
        path: &Path,
        runtime_adapter_id: &str,
        runtime_profile_id: &str,
    ) -> GovernedHarnessAdapter<UnusedResolver, PanicDriver, FixedClock> {
        GovernedHarnessAdapter::new(
            runtime_adapter_id,
            runtime_profile_id,
            NativeProtocolFingerprint::default(),
            edge(path),
            UnusedResolver,
            PanicDriver,
            FixedClock,
        )
    }

    fn candidate() -> DispatchEnvelope {
        DispatchEnvelope {
            dispatch_id: "dispatch-001".to_owned(),
            run_id: "run-001".to_owned(),
            run_revision: 1,
            step_id: "step-001".to_owned(),
            step_revision: 1,
            attempt_id: "attempt-001".to_owned(),
            attempt_revision: 1,
            fencing_token: 7,
            dispatch_fingerprint: "a".repeat(64),
            input_bundle_sha256: "b".repeat(64),
            capability_profile_ref: Some(ContractReference {
                contract_id: PROFILE_ID.to_owned(),
                version: "v1".to_owned(),
                sha256: "c".repeat(64),
            }),
            ..DispatchEnvelope::default()
        }
    }

    fn delivered_receipt(envelope: &DispatchEnvelope) -> DispatchReceipt {
        let mut receipt = DispatchReceipt {
            receipt_id: "receipt-001".to_owned(),
            disposition: DeliveryDisposition::Delivered as i32,
            attempt_id: envelope.attempt_id.clone(),
            dispatch_id: envelope.dispatch_id.clone(),
            fencing_token: envelope.fencing_token,
            adapter_id: ADAPTER_ID.to_owned(),
            capability_profile_id: PROFILE_ID.to_owned(),
            receipt_digest_sha256: String::new(),
            evidence_ref: "adapter-edge://adapter:test/delivery/receipt-001".to_owned(),
            delivered_at: Some(Timestamp {
                seconds: 10,
                nanos: 0,
            }),
            ..DispatchReceipt::default()
        };
        receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        receipt
    }

    fn seed_delivered(path: &Path) -> DispatchEnvelope {
        let envelope = candidate();
        let mut edge = edge(path);
        assert_eq!(
            edge.prepare_dispatch(&envelope, 8)
                .expect("prepare dispatch"),
            DispatchPreparation::Ready
        );
        edge.begin_delivery(&envelope.dispatch_id, 9)
            .expect("begin delivery");
        edge.record_dispatch_receipt(&delivered_receipt(&envelope), b"native-delivery", 10)
            .expect("record delivered receipt");
        envelope
    }

    fn raw_connection(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("open raw Adapter Edge");
        connection
            .pragma_update(None, "key", format!("x'{}'", hex::encode(EDGE_KEY)))
            .expect("unlock raw Adapter Edge");
        connection
    }

    #[derive(Clone, Copy, Debug)]
    enum EvidenceTamper {
        DeliveryState,
        RowAttempt,
        RowFence,
        RowFingerprint,
        EnvelopeDigest,
        EnvelopeBlob,
        EnvelopeMalformed,
        ReceiptMissing,
        ReceiptMalformed,
        ReceiptDisposition,
        ReceiptIdEmpty,
        ReceiptEvidenceRefEmpty,
        ReceiptAdapter,
        ReceiptAttempt,
        ReceiptDispatch,
        ReceiptFence,
        ReceiptProfile,
        ReceiptDigest,
    }

    fn rewrite_receipt(
        connection: &Connection,
        recompute_digest: bool,
        mutate: impl FnOnce(&mut DispatchReceipt),
    ) {
        let bytes: Vec<u8> = connection
            .query_row(
                "SELECT receipt FROM adapter_dispatches WHERE dispatch_id = 'dispatch-001'",
                [],
                |row| row.get(0),
            )
            .expect("read stored receipt");
        let mut receipt = DispatchReceipt::decode(bytes.as_slice()).expect("decode stored receipt");
        mutate(&mut receipt);
        if recompute_digest {
            receipt.receipt_digest_sha256.clear();
            receipt.receipt_digest_sha256 = canonical_digest(&receipt);
        }
        assert_eq!(
            connection
                .execute(
                    "UPDATE adapter_dispatches SET receipt = ?1 WHERE dispatch_id = 'dispatch-001'",
                    [receipt.encode_to_vec()],
                )
                .expect("rewrite stored receipt"),
            1
        );
    }

    fn inject_tamper(path: &Path, tamper: EvidenceTamper) {
        let connection = raw_connection(path);
        let changed = match tamper {
            EvidenceTamper::DeliveryState => connection.execute(
                "UPDATE adapter_dispatches SET delivery_state = 'rejected'
                 WHERE dispatch_id = 'dispatch-001'",
                [],
            ),
            EvidenceTamper::RowAttempt => connection.execute(
                "UPDATE adapter_dispatches SET attempt_id = 'attempt-row-drift'
                 WHERE dispatch_id = 'dispatch-001'",
                [],
            ),
            EvidenceTamper::RowFence => connection.execute(
                "UPDATE adapter_dispatches SET fencing_token = 8
                 WHERE dispatch_id = 'dispatch-001'",
                [],
            ),
            EvidenceTamper::RowFingerprint => connection.execute(
                "UPDATE adapter_dispatches SET dispatch_fingerprint = ?1
                 WHERE dispatch_id = 'dispatch-001'",
                ["d".repeat(64)],
            ),
            EvidenceTamper::EnvelopeDigest => connection.execute(
                "UPDATE adapter_dispatches SET envelope_digest_sha256 = ?1
                 WHERE dispatch_id = 'dispatch-001'",
                ["0".repeat(64)],
            ),
            EvidenceTamper::EnvelopeBlob => {
                let bytes: Vec<u8> = connection
                    .query_row(
                        "SELECT envelope FROM adapter_dispatches
                         WHERE dispatch_id = 'dispatch-001'",
                        [],
                        |row| row.get(0),
                    )
                    .expect("read stored envelope");
                let mut envelope =
                    DispatchEnvelope::decode(bytes.as_slice()).expect("decode stored envelope");
                envelope.run_id = "run-envelope-drift".to_owned();
                let bytes = envelope.encode_to_vec();
                connection.execute(
                    "UPDATE adapter_dispatches
                     SET envelope = ?1, envelope_digest_sha256 = ?2
                     WHERE dispatch_id = 'dispatch-001'",
                    params![bytes, sha256(&bytes)],
                )
            }
            EvidenceTamper::EnvelopeMalformed => {
                let bytes = vec![0xff];
                connection.execute(
                    "UPDATE adapter_dispatches
                     SET envelope = ?1, envelope_digest_sha256 = ?2
                     WHERE dispatch_id = 'dispatch-001'",
                    params![bytes, sha256(&bytes)],
                )
            }
            EvidenceTamper::ReceiptMissing => connection.execute(
                "UPDATE adapter_dispatches SET receipt = NULL
                 WHERE dispatch_id = 'dispatch-001'",
                [],
            ),
            EvidenceTamper::ReceiptMalformed => connection.execute(
                "UPDATE adapter_dispatches SET receipt = ?1
                 WHERE dispatch_id = 'dispatch-001'",
                [vec![0xff]],
            ),
            EvidenceTamper::ReceiptDisposition => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.disposition = DeliveryDisposition::Rejected as i32;
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptIdEmpty => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.receipt_id.clear();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptEvidenceRefEmpty => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.evidence_ref.clear();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptAdapter => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.adapter_id = "adapter:other".to_owned();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptAttempt => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.attempt_id = "attempt-receipt-drift".to_owned();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptDispatch => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.dispatch_id = "dispatch-receipt-drift".to_owned();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptFence => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.fencing_token = 8;
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptProfile => {
                rewrite_receipt(&connection, true, |receipt| {
                    receipt.capability_profile_id = "profile:other".to_owned();
                });
                Ok(1)
            }
            EvidenceTamper::ReceiptDigest => {
                rewrite_receipt(&connection, false, |receipt| {
                    receipt.receipt_digest_sha256 = "0".repeat(64);
                });
                Ok(1)
            }
        }
        .expect("inject delivered evidence tamper");
        assert_eq!(changed, 1, "tamper must change exactly one dispatch row");
    }

    #[test]
    fn delivered_recovery_candidate_requires_complete_adapter_transport_evidence() {
        let isolated = IsolatedStore::new("delivered-recovery-valid");
        let candidate = seed_delivered(&isolated.path());
        let adapter = adapter(&isolated.path());

        adapter
            .verify_delivered_recovery_candidate(&candidate)
            .expect("verify delivered recovery candidate");
        let normal_view = adapter
            .normal_observation_recovery_view(&candidate.dispatch_id)
            .expect("delegate normal recovery view");
        assert!(normal_view.pending.is_empty());
        assert_eq!(normal_view.durable_terminal_sequence, None);
    }

    #[test]
    fn delivered_recovery_candidate_fails_closed_for_each_durable_binding_drift() {
        let cases = [
            EvidenceTamper::DeliveryState,
            EvidenceTamper::RowAttempt,
            EvidenceTamper::RowFence,
            EvidenceTamper::RowFingerprint,
            EvidenceTamper::EnvelopeDigest,
            EvidenceTamper::EnvelopeBlob,
            EvidenceTamper::EnvelopeMalformed,
            EvidenceTamper::ReceiptMissing,
            EvidenceTamper::ReceiptMalformed,
            EvidenceTamper::ReceiptDisposition,
            EvidenceTamper::ReceiptIdEmpty,
            EvidenceTamper::ReceiptEvidenceRefEmpty,
            EvidenceTamper::ReceiptAdapter,
            EvidenceTamper::ReceiptAttempt,
            EvidenceTamper::ReceiptDispatch,
            EvidenceTamper::ReceiptFence,
            EvidenceTamper::ReceiptProfile,
            EvidenceTamper::ReceiptDigest,
        ];

        for tamper in cases {
            let isolated = IsolatedStore::new(&format!("delivered-recovery-{tamper:?}"));
            let candidate = seed_delivered(&isolated.path());
            inject_tamper(&isolated.path(), tamper);
            let adapter = adapter(&isolated.path());
            assert!(
                matches!(
                    adapter.verify_delivered_recovery_candidate(&candidate),
                    Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence)
                ),
                "tamper case must fail closed: {tamper:?}"
            );
        }
    }

    #[test]
    fn delivered_recovery_candidate_rejects_runtime_adapter_or_profile_identity_drift() {
        for (runtime_adapter_id, runtime_profile_id) in [
            ("adapter:runtime-drift", PROFILE_ID),
            (ADAPTER_ID, "profile:runtime-drift"),
        ] {
            let isolated = IsolatedStore::new("delivered-recovery-runtime-identity-drift");
            let candidate = seed_delivered(&isolated.path());
            let adapter = adapter_with_runtime_identity(
                &isolated.path(),
                runtime_adapter_id,
                runtime_profile_id,
            );
            assert!(matches!(
                adapter.verify_delivered_recovery_candidate(&candidate),
                Err(GovernedAdapterError::InvalidDeliveredRecoveryEvidence)
            ));
        }
    }

    #[test]
    fn r9c_managed_credential_states_are_explicit_and_fail_closed() {
        let harness_account = ManagedDisclosureCredentials::harness_account();
        assert_eq!(harness_account.values(), Some(&[][..]));

        let available = ManagedDisclosureCredentials::managed_available(vec![
            "credential-for-ephemeral-matching".to_owned(),
        ]);
        assert_eq!(
            available.values(),
            Some(["credential-for-ephemeral-matching".to_owned()].as_slice())
        );

        let unavailable = ManagedDisclosureCredentials::managed_unavailable();
        assert_eq!(unavailable.values(), None);

        let out_of_bounds =
            ManagedDisclosureCredentials::managed_available(vec!["x".repeat(100_000)]);
        assert!(matches!(
            out_of_bounds,
            ManagedDisclosureCredentials::ManagedOutOfBounds
        ));
        assert_eq!(out_of_bounds.values(), None);
    }
}
