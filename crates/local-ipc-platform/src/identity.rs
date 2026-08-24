use std::{fmt, sync::Arc};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LocalTransport {
    WindowsNamedPipe,
    UnixDomainSocket,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OsPrincipal {
    transport: LocalTransport,
    account_key: Arc<[u8]>,
    fingerprint: [u8; 32],
}

impl OsPrincipal {
    pub(crate) fn from_account_key(
        transport: LocalTransport,
        namespace: &[u8],
        account_key: impl Into<Arc<[u8]>>,
    ) -> Self {
        let account_key = account_key.into();
        let mut hasher = Sha256::new();
        hasher.update(namespace);
        hasher.update([0]);
        hasher.update(account_key.as_ref());
        let fingerprint = hasher.finalize().into();
        Self {
            transport,
            account_key,
            fingerprint,
        }
    }

    #[must_use]
    pub const fn transport(&self) -> LocalTransport {
        self.transport
    }

    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

impl fmt::Debug for OsPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OsPrincipal")
            .field("transport", &self.transport)
            .field("fingerprint", &self.fingerprint_hex())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConnectionInfo {
    principal: OsPrincipal,
    connection_id: Arc<str>,
}

impl PeerConnectionInfo {
    pub(crate) fn new(principal: OsPrincipal, connection_id: impl Into<Arc<str>>) -> Self {
        Self {
            principal,
            connection_id: connection_id.into(),
        }
    }

    #[must_use]
    pub const fn principal(&self) -> &OsPrincipal {
        &self.principal
    }

    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
}
