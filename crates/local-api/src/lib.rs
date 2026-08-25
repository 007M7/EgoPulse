#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;
pub use egopulse_local_ipc_platform::LocalTransport;

pub mod read_gateway;
pub mod read_gateway_policy;
pub mod read_model_reader;
pub mod read_service;
pub mod read_tokens;
pub mod session;

#[derive(Clone, Copy, Debug)]
pub struct LocalApiClient {
    transport: LocalTransport,
}

impl LocalApiClient {
    #[must_use]
    pub const fn platform_default() -> Self {
        #[cfg(windows)]
        let transport = LocalTransport::WindowsNamedPipe;
        #[cfg(not(windows))]
        let transport = LocalTransport::UnixDomainSocket;

        Self { transport }
    }

    #[must_use]
    pub const fn transport(self) -> LocalTransport {
        self.transport
    }

    #[must_use]
    pub const fn foundation_health(self) -> FoundationHealth {
        let _ = self;
        FoundationHealth::foundation_only("local-api-client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_does_not_pretend_transport_is_connected() {
        let client = LocalApiClient::platform_default();
        assert_eq!(client.foundation_health().state.as_str(), "foundation-only");
    }
}
