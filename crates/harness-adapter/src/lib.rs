#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod edge;
mod runtime;

pub use edge::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeInspection, AdapterEdgeKey,
    AdapterObservationEvidence, DispatchPreparation, DurableWritePreparation,
    NativeExecutionBinding, ObservationAppend,
};
pub use runtime::{
    AdapterClock, AdapterReconciliationEvidence, DispatchMaterialResolver, DriverDelivery,
    DriverError, DriverErrorCertainty, DriverEvent, GovernedHarnessAdapter, NativeHarnessDriver,
    ReconciliationContext, ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock,
};
