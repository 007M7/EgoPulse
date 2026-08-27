use std::{
    ffi::{OsStr, c_void},
    io,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
    sync::mpsc,
};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use uuid::Uuid;
use windows_sys::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES,
            TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenRestrictedSids, TokenUser,
        },
        System::{
            Pipes::ImpersonateNamedPipeClient,
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        },
    },
    core::PWSTR,
};

use crate::{LocalTransport, OsPrincipal, PeerConnectionInfo};

const PIPE_PREFIX: &str = r"\\.\pipe\EgoPulse-";
const INCOMING_CAPACITY: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalIpcAddress(Arc<str>);

impl LocalIpcAddress {
    pub fn for_instance(instance: &str) -> io::Result<Self> {
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
        Ok(Self(Arc::from(format!("{PIPE_PREFIX}{instance}"))))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct LocalIpcListener {
    address: LocalIpcAddress,
    owner_principal: OsPrincipal,
    security_identities: SecurityIdentitySet,
    next_server: NamedPipeServer,
}

impl LocalIpcListener {
    pub fn bind(address: LocalIpcAddress) -> io::Result<Self> {
        let security_identities = current_process_security_identities()?;
        let owner_principal = principal_from_sid(&security_identities.owner_sid);
        let next_server = create_server(&address, &security_identities, true)?;
        Ok(Self {
            address,
            owner_principal,
            security_identities,
            next_server,
        })
    }

    #[must_use]
    pub const fn owner_principal(&self) -> &OsPrincipal {
        &self.owner_principal
    }

    #[must_use]
    pub const fn address(&self) -> &LocalIpcAddress {
        &self.address
    }

    pub async fn accept(&mut self) -> io::Result<LocalIpcConnection> {
        self.next_server.connect().await?;
        let replacement = create_server(&self.address, &self.security_identities, false)?;
        let connected = std::mem::replace(&mut self.next_server, replacement);
        let peer = connected_peer_principal(&connected)?;
        if peer != self.owner_principal {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local IPC peer account is not allowed",
            ));
        }
        Ok(LocalIpcConnection {
            io: connected,
            info: PeerConnectionInfo::new(peer, Uuid::now_v7().to_string()),
        })
    }

    #[must_use]
    pub fn into_incoming(mut self) -> LocalIpcIncoming {
        let (sender, receiver) = mpsc::channel(INCOMING_CAPACITY);
        let task = tokio::spawn(async move {
            loop {
                let accepted = self.accept().await;
                let failed = accepted.is_err();
                if sender.send(accepted).await.is_err() || failed {
                    break;
                }
            }
        });
        LocalIpcIncoming {
            receiver: ReceiverStream::new(receiver),
            abort_handle: task.abort_handle(),
        }
    }
}

pub struct LocalIpcIncoming {
    receiver: ReceiverStream<io::Result<LocalIpcConnection>>,
    abort_handle: tokio::task::AbortHandle,
}

impl Stream for LocalIpcIncoming {
    type Item = io::Result<LocalIpcConnection>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Unpin for LocalIpcIncoming {}

impl Drop for LocalIpcIncoming {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

pub struct LocalIpcConnection {
    io: NamedPipeServer,
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
    pub async fn connect(address: &LocalIpcAddress) -> io::Result<NamedPipeClient> {
        ClientOptions::new().open(address.as_str())
    }
}

fn create_server(
    address: &LocalIpcAddress,
    security_identities: &SecurityIdentitySet,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let mut descriptor = OwnedSecurityDescriptor::for_identities(security_identities)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "security attributes size overflow",
            )
        })?,
        lpSecurityDescriptor: descriptor.as_mut_ptr(),
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    // SAFETY: `attributes` and its owned security descriptor remain valid for the complete call.
    unsafe {
        options.create_with_security_attributes_raw(
            address.as_str(),
            std::ptr::from_mut(&mut attributes).cast::<c_void>(),
        )
    }
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn for_identities(identities: &SecurityIdentitySet) -> io::Result<Self> {
        let sddl = owner_dacl_sddl(identities);
        let wide = wide_null(OsStr::new(&sddl));
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `wide` is null terminated and `descriptor` is a valid out pointer.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0
    }
}

fn owner_dacl_sddl(identities: &SecurityIdentitySet) -> String {
    let mut sddl = format!(
        "O:{owner}D:P(A;;GA;;;{owner})",
        owner = identities.owner_sid
    );
    // Restricted Windows tokens are checked once against their ordinary SIDs
    // and again against their restricting SID set. Grant only the exact
    // restricting SIDs present on the owner process; never grant Everyone or
    // Authenticated Users merely to make a sandbox work.
    for sid in &identities.restricted_sids {
        sddl.push_str(&format!("(A;;GA;;;{sid})"));
    }
    sddl
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this descriptor was allocated by the SDDL conversion API and is owned here.
            unsafe {
                LocalFree(self.0.cast::<c_void>() as HLOCAL);
            }
        }
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is uniquely owned by this guard.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Clone)]
struct SecurityIdentitySet {
    owner_sid: String,
    restricted_sids: Vec<String>,
}

fn current_process_security_identities() -> io::Result<SecurityIdentitySet> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the pseudo process handle is valid and `token` is a valid out pointer.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle::new(token)?;
    Ok(SecurityIdentitySet {
        owner_sid: token_sid_string(&token)?,
        restricted_sids: token_restricted_sid_strings(&token)?,
    })
}

fn connected_peer_principal(server: &NamedPipeServer) -> io::Result<OsPrincipal> {
    let pipe = server.as_raw_handle() as HANDLE;
    // SAFETY: the pipe is a connected server handle and no await occurs while impersonating.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let sid_result = (|| {
        let mut token = std::ptr::null_mut();
        // SAFETY: the current thread is impersonating the pipe client and `token` is a valid out pointer.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        token_sid_string(&OwnedHandle::new(token)?)
    })();

    // SAFETY: the current thread must always leave impersonation before returning.
    let reverted = unsafe { RevertToSelf() };
    if reverted == 0 {
        return Err(io::Error::last_os_error());
    }
    sid_result.map(|sid| principal_from_sid(&sid))
}

fn token_sid_string(token: &OwnedHandle) -> io::Result<String> {
    let buffer = token_information_buffer(token, TokenUser)?;
    // SAFETY: a successful TokenUser query begins with a valid TOKEN_USER value.
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_to_string(token_user.User.Sid)
}

fn token_restricted_sid_strings(token: &OwnedHandle) -> io::Result<Vec<String>> {
    let buffer = token_information_buffer(token, TokenRestrictedSids)?;
    // SAFETY: a successful TokenRestrictedSids query begins with TOKEN_GROUPS.
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = usize::try_from(groups.GroupCount)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "restricted SID count overflow"))?;
    let first = groups.Groups.as_ptr();
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: GetTokenInformation returned storage for GroupCount entries.
        let group = unsafe { &*first.add(index) };
        result.push(sid_to_string(group.Sid)?);
    }
    Ok(result)
}

fn token_information_buffer(token: &OwnedHandle, information_class: i32) -> io::Result<Vec<usize>> {
    let mut required = 0_u32;
    // SAFETY: the first call intentionally requests the required buffer length.
    unsafe {
        GetTokenInformation(
            token.0,
            information_class,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 {
        return Err(io::Error::last_os_error());
    }

    let word = std::mem::size_of::<usize>();
    let words = usize::try_from(required)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "token size overflow"))?
        .div_ceil(word);
    let mut buffer = vec![0_usize; words];
    // SAFETY: the aligned buffer has at least `required` writable bytes.
    let read = unsafe {
        GetTokenInformation(
            token.0,
            information_class,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

fn sid_to_string(sid: *mut c_void) -> io::Result<String> {
    let mut sid_text: PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` comes from a successful token query and `sid_text` is a valid out pointer.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_text) };
    if converted == 0 || sid_text.is_null() {
        return Err(io::Error::last_os_error());
    }
    let sid = wide_pointer_to_string(sid_text);
    // SAFETY: the SID string was allocated by `ConvertSidToStringSidW`.
    unsafe {
        LocalFree(sid_text.cast::<c_void>() as HLOCAL);
    }
    sid
}

fn wide_pointer_to_string(pointer: PWSTR) -> io::Result<String> {
    let mut length = 0_usize;
    // SAFETY: the Windows API guarantees a valid null-terminated UTF-16 string on success.
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(
            pointer
                .as_ref()
                .map_or(&[], |_| std::slice::from_raw_parts(pointer, length)),
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows SID is not valid UTF-16",
            )
        })
    }
}

fn principal_from_sid(sid: &str) -> OsPrincipal {
    OsPrincipal::from_account_key(
        LocalTransport::WindowsNamedPipe,
        b"egopulse/windows-sid/v1",
        Arc::<[u8]>::from(sid.as_bytes()),
    )
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn address_rejects_remote_or_ambiguous_names() {
        assert!(LocalIpcAddress::for_instance("").is_err());
        assert!(LocalIpcAddress::for_instance("../other").is_err());
        assert!(LocalIpcAddress::for_instance("server\\share").is_err());
        assert!(LocalIpcAddress::for_instance("v01_test-1").is_ok());
    }

    #[test]
    fn dacl_names_only_owner_and_exact_restricting_sids() {
        let identities = current_process_security_identities().unwrap();
        let sddl = owner_dacl_sddl(&identities);
        assert!(sddl.contains(&identities.owner_sid));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;AU)"));
        for sid in identities.restricted_sids {
            assert!(sddl.contains(&sid));
        }
    }

    #[tokio::test]
    async fn named_pipe_uses_kernel_peer_account_and_first_instance() {
        let address = LocalIpcAddress::for_instance(&format!("test-{}", Uuid::now_v7())).unwrap();
        let mut listener = LocalIpcListener::bind(address.clone()).unwrap();
        let owner = listener.owner_principal().clone();
        assert!(LocalIpcListener::bind(address.clone()).is_err());

        let mut client = LocalIpcClient::connect(&address).await.unwrap();
        let mut connection =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                .await
                .expect("named pipe accept timed out")
                .unwrap();
        client.write_all(b"peer").await.unwrap();
        let mut payload = [0_u8; 4];
        connection.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"peer");
        assert_eq!(connection.connect_info().principal(), &owner);
    }
}
