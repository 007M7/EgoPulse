use std::{
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{UnixListener, UnixStream},
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use uuid::Uuid;

use crate::{LocalTransport, OsPrincipal, PeerConnectionInfo};

const INCOMING_CAPACITY: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalIpcAddress(Arc<PathBuf>);

impl LocalIpcAddress {
    pub fn in_private_runtime_dir(runtime_dir: &Path, instance: &str) -> io::Result<Self> {
        if instance.is_empty()
            || instance.len() > 80
            || !instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local IPC instance name is invalid",
            ));
        }
        validate_private_runtime_dir(runtime_dir)?;
        Ok(Self(Arc::new(
            runtime_dir.join(format!("egopulse-{instance}.sock")),
        )))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        self.0.as_path()
    }
}

pub struct LocalIpcListener {
    address: LocalIpcAddress,
    listener: UnixListener,
    owner_uid: u32,
    socket_identity: (u64, u64),
}

impl LocalIpcListener {
    pub fn bind(address: LocalIpcAddress) -> io::Result<Self> {
        if std::fs::symlink_metadata(address.as_path()).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "local IPC socket path already exists",
            ));
        }
        let parent = address.as_path().parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "local IPC path has no parent")
        })?;
        let parent_metadata = validate_private_runtime_dir(parent)?;
        let listener = UnixListener::bind(address.as_path())?;
        std::fs::set_permissions(address.as_path(), std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(address.as_path())?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != parent_metadata.uid()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local IPC socket ownership or mode is unsafe",
            ));
        }
        Ok(Self {
            address,
            listener,
            owner_uid: parent_metadata.uid(),
            socket_identity: (metadata.dev(), metadata.ino()),
        })
    }

    #[must_use]
    pub const fn address(&self) -> &LocalIpcAddress {
        &self.address
    }

    pub async fn accept(&self) -> io::Result<LocalIpcConnection> {
        let (stream, _) = self.listener.accept().await?;
        let credential = stream.peer_cred()?;
        if credential.uid() != self.owner_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local IPC peer account is not allowed",
            ));
        }
        let principal = principal_from_uid(credential.uid());
        Ok(LocalIpcConnection {
            io: stream,
            info: PeerConnectionInfo::new(principal, Uuid::now_v7().to_string()),
        })
    }

    #[must_use]
    pub fn into_incoming(self) -> LocalIpcIncoming {
        let (sender, receiver) = mpsc::channel(INCOMING_CAPACITY);
        tokio::spawn(async move {
            loop {
                let accepted = self.accept().await;
                let failed = accepted.is_err();
                if sender.send(accepted).await.is_err() || failed {
                    break;
                }
            }
        });
        ReceiverStream::new(receiver)
    }
}

impl Drop for LocalIpcListener {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(self.address.as_path()) else {
            return;
        };
        if metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.socket_identity
        {
            let _ = std::fs::remove_file(self.address.as_path());
        }
    }
}

pub type LocalIpcIncoming = ReceiverStream<io::Result<LocalIpcConnection>>;

pub struct LocalIpcConnection {
    io: UnixStream,
    info: PeerConnectionInfo,
}

impl Connected for LocalIpcConnection {
    type ConnectInfo = PeerConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for LocalIpcConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(context, buffer)
    }
}

impl AsyncWrite for LocalIpcConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().io).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().io).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(context)
    }
}

pub struct LocalIpcClient;

impl LocalIpcClient {
    pub async fn connect(address: &LocalIpcAddress) -> io::Result<UnixStream> {
        UnixStream::connect(address.as_path()).await
    }
}

fn validate_private_runtime_dir(path: &Path) -> io::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "local IPC runtime directory must be owner-only and not a symlink",
        ));
    }
    Ok(metadata)
}

fn principal_from_uid(uid: u32) -> OsPrincipal {
    OsPrincipal::from_account_key(
        LocalTransport::UnixDomainSocket,
        b"egopulse/unix-uid/v1",
        Arc::<[u8]>::from(uid.to_be_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn uds_requires_private_directory_and_uses_kernel_peer_uid() {
        let root = std::env::temp_dir().join(format!("egopulse-ipc-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
        let address = LocalIpcAddress::in_private_runtime_dir(&root, "test").unwrap();
        let listener = LocalIpcListener::bind(address.clone()).unwrap();
        let client_task = tokio::spawn(async move {
            let mut client = LocalIpcClient::connect(&address).await.unwrap();
            client.write_all(b"peer").await.unwrap();
        });
        let mut connection = listener.accept().await.unwrap();
        let mut payload = [0_u8; 4];
        connection.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"peer");
        assert_eq!(
            connection.connect_info().principal().transport(),
            LocalTransport::UnixDomainSocket
        );
        client_task.await.unwrap();
        drop(listener);
        std::fs::remove_dir(&root).unwrap();
    }
}
