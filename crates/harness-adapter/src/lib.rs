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
    AdapterObservationEvidence, DispatchPreparation, DurableWritePreparation,
    NativeExecutionBinding, ObservationAppend, PendingAdapterApprovalProjection,
    PendingTerminalOutputCandidate,
};
pub use runtime::{
    AdapterClock, AdapterReconciliationEvidence, DispatchMaterialResolver, DriverDelivery,
    DriverError, DriverErrorCertainty, DriverEvent, GovernedAdapterError, GovernedHarnessAdapter,
    NativeHarnessDriver, NativeHarnessFuture, ProbeValidationError, ReconciliationContext,
    ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock, TerminalOutputCandidate,
    validate_probe_result,
};
