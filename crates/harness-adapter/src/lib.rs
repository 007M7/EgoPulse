#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod capability;
mod disclosure;
mod edge;
mod runtime;

pub use capability::{
    CapabilityBindingError, validate_capability_binding, validate_step_capability_binding,
};
pub use disclosure::{
    ContentAssemblyCheckpoint, ContentDisclosureError, SafeContentProjection,
    TrustedContentLineage, approval_required_content_candidate, assistant_text_content_candidate,
    assistant_text_mutation_candidate, bind_content_signal, blocked_source_content_candidate,
    canonical_dispatch_route_binding_digest, canonical_safe_record_digest,
    lifecycle_content_candidate, project_safe_content, project_structured_only_content,
    usage_content_candidate,
};
pub use edge::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeInspection, AdapterEdgeKey,
    AdapterObservationEvidence, ApprovalAuthorizationSnapshot, ApprovalDeliveryState,
    ContentDisclosureMode, ContentRetentionCompactionReceipt, ContentRetentionCompactionRequest,
    DispatchPreparation, DispatchTaskLineage, DurableApprovalRecord, DurableWritePreparation,
    FinalArtifactRelationCommit, FinalArtifactRelationPolicy, FinalArtifactRelationRegistration,
    FinalArtifactRelationRequest, FinalArtifactRelationSkipReason, FinalArtifactRelationState,
    FinalArtifactRelationStatus, LegacyExecutionStartEvidence,
    LegacyExecutionStartEvidenceRejection, LegacyExecutionStartEvidenceResolution,
    NativeExecutionBinding, NormalObservationRecoveryView, ObservationAppend,
    PendingAdapterApprovalProjection, PendingContentCandidate, PendingTerminalOutputCandidate,
    RetainedApprovalAuthorization, RetainedSafeContent, SafeContentAssemblyCheckpoint,
    SafeContentBudgetSnapshot, SafeContentBudgetUsage, SafeContentCommit, SafeContentOwnerRecord,
    SafeContentOwnerSnapshot, SafeContentProjectionMessage,
};
pub use runtime::{
    AdapterClock, AdapterReconciliationEvidence, AuthorizedDispatchContext,
    DispatchContextAuthorization, DispatchContextAuthorizationGate,
    DispatchContextAuthorizationReceipt, DispatchContextBinding, DispatchContextRecovery,
    DispatchContextRecoveryGate, DispatchContextReference, DispatchMaterialResolver,
    DispatchMemoryPackBinding, DispatchMemoryUseReceipt, DriverDelivery, DriverError,
    DriverErrorCertainty, DriverEvent, GovernedAdapterError, GovernedHarnessAdapter,
    GovernedHarnessContentProjector, HarnessContentDrain, HistoricalDispatchContext,
    HistoricalDispatchContextBinding, HistoricalDispatchContextState,
    LegacyExecutionStartRawClassification, LegacyExecutionStartRawContext,
    LegacyExecutionStartRecovery, ManagedDisclosureCredentials, NativeHarnessDriver,
    NativeHarnessFuture, ProbeValidationError, ReadyDispatchMaterialGuard, ReconciliationContext,
    ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock, TerminalOutputCandidate,
    classify_dispatch_context_reference, validate_probe_result,
};
