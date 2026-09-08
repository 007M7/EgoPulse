#![cfg(windows)]

use std::{io, os::windows::ffi::OsStrExt, path::Path, ptr};

use windows_sys::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GetLastError, HLOCAL, LocalFree},
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
    Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
};

const MAX_CLIENT_RECORD_BYTES: usize = 16 * 1024 * 1024;
const CLIENT_RECORD_ENTROPY: &[u8] = b"egopulse/local-ipc/client-record/v1\0";

fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "client record is invalid")
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

pub fn protect_client_record(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_CLIENT_RECORD_BYTES {
        return Err(invalid_data());
    }
    let input = blob(payload);
    let entropy = blob(CLIENT_RECORD_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: bounded input slices remain live, reserved/prompt pointers are
    // null, and output is initialized for the OS-owned allocation.
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    // Capture the operation error before LocalFree can change the thread error.
    let error = (ok == 0).then(io::Error::last_os_error);
    copy_and_free_output(output, error)
}

pub fn unprotect_client_record(protected: &[u8]) -> io::Result<Vec<u8>> {
    if protected.is_empty() || protected.len() > MAX_CLIENT_RECORD_BYTES {
        return Err(invalid_data());
    }
    let input = blob(protected);
    let entropy = blob(CLIENT_RECORD_ENTROPY);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: as for protect_client_record; the description output is omitted.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let error = (ok == 0).then(io::Error::last_os_error);
    copy_and_free_output(output, error)
}

fn copy_and_free_output(
    output: CRYPT_INTEGER_BLOB,
    error: Option<io::Error>,
) -> io::Result<Vec<u8>> {
    let result = if let Some(error) = error {
        Err(error)
    } else if output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > MAX_CLIENT_RECORD_BYTES
    {
        Err(invalid_data())
    } else {
        // SAFETY: only called with DPAPI output; the OS supplied the allocation
        // and its checked length. Copy it before releasing the OS allocation.
        Ok(unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() })
    };
    if !output.pbData.is_null() {
        // SAFETY: DPAPI requires LocalFree for this output allocation.
        unsafe {
            LocalFree(output.pbData as HLOCAL);
        }
    }
    result
}

pub fn publish_client_record_noclobber(temp_path: &Path, final_path: &Path) -> io::Result<()> {
    if temp_path.parent() != final_path.parent() || !temp_path.is_file() {
        return Err(invalid_data());
    }
    if final_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "client record already exists",
        ));
    }
    let source = wide_path(temp_path)?;
    let destination = wide_path(final_path)?;
    // SAFETY: both owned UTF-16 paths are NUL-terminated and live for this call.
    // No replace or copy-across-volume flag is set.
    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError has no preconditions and follows the failed call.
        let code = unsafe { GetLastError() };
        if code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "client record already exists",
            ));
        }
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    if path.as_os_str().encode_wide().any(|unit| unit == 0) {
        return Err(invalid_data());
    }
    Ok(path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn roundtrip_and_tamper_rejection() {
        let plain = b"client-record";
        let protected = protect_client_record(plain).expect("protect");
        assert_eq!(
            unprotect_client_record(&protected).expect("unprotect"),
            plain
        );
        let mut tampered = protected;
        tampered[0] ^= 1;
        assert!(unprotect_client_record(&tampered).is_err());
    }

    #[test]
    fn publish_does_not_replace_existing_final() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("egopulse-client-record-{suffix}"));
        fs::create_dir_all(&dir).expect("dir");
        let temp = dir.join("temp");
        let final_path = dir.join("final");
        fs::write(&temp, b"new").expect("temp");
        fs::write(&final_path, b"old").expect("final");
        assert!(publish_client_record_noclobber(&temp, &final_path).is_err());
        assert_eq!(fs::read(&final_path).expect("final bytes"), b"old");
        let _ = fs::remove_dir_all(dir);
    }
}
