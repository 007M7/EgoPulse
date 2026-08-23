#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

mod edge;
mod runtime;

pub use edge::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeError, AdapterEdgeInspection, AdapterEdgeKey,
    DispatchPreparation, DurableWritePreparation, ObservationAppend,
};
pub use runtime::{
    AdapterClock, DispatchMaterialResolver, DriverDelivery, DriverError, DriverErrorCertainty,
    DriverEvent, GovernedHarnessAdapter, NativeHarnessDriver, ReconciliationContext,
    ReconciliationFinding, ResolvedDispatchMaterial, SystemAdapterClock,
};
