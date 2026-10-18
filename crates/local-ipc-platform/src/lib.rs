#![deny(unsafe_op_in_unsafe_fn)]

mod identity;
#[cfg(windows)]
mod secret_keys;
#[cfg(windows)]
pub use secret_keys::load_protected_process_keys;
#[cfg(not(windows))]
pub fn load_protected_process_keys() -> std::io::Result<()> {
    if std::env::var_os("EGOPULSE_KEY_FILE").is_some() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "LOCAL_KEYS_WINDOWS_REQUIRED",
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
mod client_record;
#[cfg(windows)]
mod process_tree;
#[cfg(windows)]
mod shell_environment;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use identity::{LocalTransport, OsPrincipal, PeerConnectionInfo};

#[cfg(windows)]
pub use client_record::{
    protect_client_record, publish_client_record_noclobber, unprotect_client_record,
};
#[cfg(windows)]
pub use process_tree::WindowsProcessTree;
#[cfg(windows)]
pub use shell_environment::desktop_powershell_path;
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
