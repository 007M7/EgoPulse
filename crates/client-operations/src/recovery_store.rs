//! OS-user-owned recovery storage. This protects saved records against edits
//! and other OS users; it does not isolate malicious code running as this user.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

const ENVELOPE_LIMIT: u64 = 20 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    protected_payload_hex: String,
}

pub(super) fn write_new(bytes: &[u8], path: &Path) -> io::Result<()> {
    let protected = protect(bytes)?;
    let envelope = Envelope {
        schema: "egopulse.client-recovery-envelope/v1".into(),
        protected_payload_hex: hex::encode(protected),
    };
    let encoded = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
    if encoded.len() as u64 > ENVELOPE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery record exceeds limit",
        ));
    }
    publish_new(&encoded, path)
}

fn publish_new(bytes: &[u8], path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery path requires a directory",
            )
        })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(windows)]
    {
        egopulse_local_ipc_platform::publish_client_record_noclobber(temporary.path(), path)?;
    }
    #[cfg(unix)]
    {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(ENVELOPE_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > ENVELOPE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery envelope exceeds limit",
        ));
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid recovery envelope"))?;
    if envelope.schema != "egopulse.client-recovery-envelope/v1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported recovery envelope",
        ));
    }
    let protected = hex::decode(&envelope.protected_payload_hex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid protected record"))?;
    unprotect(&protected)
}

#[cfg(windows)]
fn protect(bytes: &[u8]) -> io::Result<Vec<u8>> {
    egopulse_local_ipc_platform::protect_client_record(bytes)
}

#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> io::Result<Vec<u8>> {
    egopulse_local_ipc_platform::unprotect_client_record(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "recovery authentication failed"))
}

#[cfg(unix)]
mod unix_protection {
    use super::*;
    use hmac::{Hmac, Mac};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    type RecordMac = Hmac<sha2::Sha256>;
    const DOMAIN: &[u8] = b"egopulse.client-recovery-auth/v1\0";

    // One OS-user-owned key, independent of arbitrary caller-supplied record
    // paths. A record copied from another user does not bring its own trust key.
    fn key(create: bool) -> io::Result<Vec<u8>> {
        let root = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local/state"))
            })
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "private client state unavailable")
            })?;
        let directory = root.join("egopulse/client/recovery-auth");
        if create {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&directory)?;
        }
        let directory_meta = fs::symlink_metadata(&directory)?;
        if !directory_meta.is_dir() || directory_meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client key directory is not private",
            ));
        }
        let path = directory.join("record-auth.key");
        if create && !path.try_exists()? {
            let mut bytes = [0_u8; 32];
            fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            if let Err(error) = publish_new(&bytes, &path) {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != directory_meta.uid()
            || metadata.len() != 32
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client key is not private",
            ));
        }
        fs::read(path)
    }

    pub(super) fn protect(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut mac = RecordMac::new_from_slice(&key(true)?).map_err(io::Error::other)?;
        mac.update(DOMAIN);
        mac.update(bytes);
        let mut result = mac.finalize().into_bytes().to_vec();
        result.extend_from_slice(bytes);
        Ok(result)
    }

    pub(super) fn unprotect(bytes: &[u8]) -> io::Result<Vec<u8>> {
        if bytes.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protected record",
            ));
        }
        let (tag, payload) = bytes.split_at(32);
        let mut mac = RecordMac::new_from_slice(&key(false)?).map_err(io::Error::other)?;
        mac.update(DOMAIN);
        mac.update(payload);
        mac.verify_slice(tag).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "recovery authentication failed")
        })?;
        Ok(payload.to_vec())
    }
}

#[cfg(unix)]
use unix_protection::{protect, unprotect};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_envelope_rejects_identity_edits_and_corruption() {
        let root = tempfile::tempdir().expect("isolated record");
        let path = root.path().join("record.json");
        let original = br#"{"principal":"founder:a","epoch":"store:a","command":"unchanged"}"#;
        write_new(original, &path).expect("published");
        assert_eq!(read(&path).expect("authenticated read"), original);
        let saved = fs::read(&path).expect("saved envelope");
        for field in ["authenticated_principal_id", "projection_epoch"] {
            let mut edited: serde_json::Value = serde_json::from_slice(&saved).expect("json");
            edited[field] = serde_json::json!("attacker-controlled");
            fs::write(&path, serde_json::to_vec(&edited).expect("edited")).expect("tamper");
            assert_eq!(
                read(&path)
                    .expect_err("identity is not an editable outer field")
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut edited: Envelope = serde_json::from_slice(&saved).expect("json");
        let mut protected = hex::decode(&edited.protected_payload_hex).expect("hex");
        let last = protected.len() - 1;
        protected[last] ^= 1;
        edited.protected_payload_hex = hex::encode(protected);
        fs::write(&path, serde_json::to_vec(&edited).expect("edited")).expect("tamper");
        assert_eq!(
            read(&path)
                .expect_err("protected payload authentication")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn atomic_record_publish_never_replaces_an_existing_recovery() {
        let root = tempfile::tempdir().expect("isolated record");
        let path = root.path().join("record.json");
        write_new(b"original", &path).expect("first publish");
        assert!(write_new(b"replacement", &path).is_err());
        assert_eq!(read(&path).expect("retained"), b"original");
        assert_eq!(
            fs::read_dir(root.path()).expect("directory").count(),
            1,
            "no partially published record or temporary file remains"
        );
    }
}
