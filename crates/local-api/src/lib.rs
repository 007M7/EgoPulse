#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
    local_command_gateway_service_client::LocalCommandGatewayServiceClient,
    local_read_model_service_client::LocalReadModelServiceClient,
    local_session_service_client::LocalSessionServiceClient,
};
pub use egopulse_local_ipc_platform::{LocalIpcAddress, LocalTransport};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

pub mod command_gateway;
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

#[derive(Debug, Error)]
pub enum LocalApiConnectError {
    #[error("local IPC transport connection failed")]
    Transport(#[from] tonic::transport::Error),
}

#[derive(Clone)]
pub struct LocalApiConnection {
    channel: Channel,
    transport: LocalTransport,
}

impl LocalApiConnection {
    #[must_use]
    pub const fn transport(&self) -> LocalTransport {
        self.transport
    }

    #[must_use]
    pub fn session_service(&self) -> LocalSessionServiceClient<Channel> {
        LocalSessionServiceClient::new(self.channel.clone())
    }

    #[must_use]
    pub fn read_model_service(&self) -> LocalReadModelServiceClient<Channel> {
        LocalReadModelServiceClient::new(self.channel.clone())
    }

    #[must_use]
    pub fn command_gateway_service(&self) -> LocalCommandGatewayServiceClient<Channel> {
        LocalCommandGatewayServiceClient::new(self.channel.clone())
    }
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

    /// Connects to an already-running local daemon. The caller owns the
    /// lifecycle decision; this method never starts or supervises a process.
    pub async fn connect(
        self,
        address: LocalIpcAddress,
    ) -> Result<LocalApiConnection, LocalApiConnectError> {
        let connector_address = address.clone();
        let channel = Endpoint::from_static("http://egopulse.local")
            .connect_with_connector(service_fn(move |_| {
                let address = connector_address.clone();
                async move {
                    egopulse_local_ipc_platform::LocalIpcClient::connect(&address)
                        .await
                        .map(TokioIo::new)
                }
            }))
            .await?;
        Ok(LocalApiConnection {
            channel,
            transport: self.transport,
        })
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
