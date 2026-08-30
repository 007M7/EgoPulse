#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod capability;
mod edge;
mod runtime;

pub use capability::{
    CapabilityBindingError, validate_capability_binding, validate_step_capability_binding,
};
pub use edge::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeInspection, AdapterEdgeKey,
    AdapterObservationEvidence, DispatchPreparation, DispatchTaskLineage, DurableWritePreparation,
    NativeExecutionBinding, NormalObservationRecoveryView, ObservationAppend,
    PendingAdapterApprovalProjection, PendingTerminalOutputCandidate,
};
pub use runtime::{
    AdapterClock, AdapterReconciliationEvidence, AuthorizedDispatchContext,
    DispatchContextAuthorization, DispatchContextAuthorizationGate,
    DispatchContextAuthorizationReceipt, DispatchContextBinding, DispatchContextRecovery,
    DispatchContextRecoveryGate, DispatchContextReference, DispatchMaterialResolver,
    DriverDelivery, DriverError, DriverErrorCertainty, DriverEvent, GovernedAdapterError,
    GovernedHarnessAdapter, HistoricalDispatchContext, HistoricalDispatchContextBinding,
    HistoricalDispatchContextState, NativeHarnessDriver, NativeHarnessFuture, ProbeValidationError,
    ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock,
    TerminalOutputCandidate, classify_dispatch_context_reference, validate_probe_result,
};
