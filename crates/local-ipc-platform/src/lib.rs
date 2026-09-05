#![deny(unsafe_op_in_unsafe_fn)]

mod identity;

#[cfg(windows)]
mod process_tree;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use identity::{LocalTransport, OsPrincipal, PeerConnectionInfo};

#[cfg(windows)]
pub use process_tree::WindowsProcessTree;
#[cfg(unix)]
pub use unix::{
    LocalIpcAddress, LocalIpcClient, LocalIpcConnection, LocalIpcIncoming, LocalIpcListener,
};
#[cfg(windows)]
pub use windows::{
    LocalIpcAddress, LocalIpcClient, LocalIpcConnection, LocalIpcIncoming, LocalIpcListener,
};

#[cfg(not(any(unix, windows)))]
compile_error!("EgoPulse local IPC supports only Windows Named Pipe or Unix Domain Socket");
