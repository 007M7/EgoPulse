//! Current-user protected installation keys. No User environment plaintext is written.
use std::{collections::BTreeMap, io};
use zeroize::{Zeroize, Zeroizing};

pub const LOCAL_KEY_NAMES: [&str; 10] = [
    "EGOPULSE_TASK_KEY_HEX",
    "EGOPULSE_MEMORY_KEY_HEX",
    "EGOPULSE_ARTIFACT_KEY_HEX",
    "EGOPULSE_VERIFICATION_KEY_HEX",
    "EGOPULSE_POLICY_KEY_HEX",
    "EGOPULSE_VERDICT_KEY_HEX",
    "EGOPULSE_ADAPTER_KEY_HEX",
    "EGOPULSE_COLLABORATION_KEY_HEX",
    "EGOPULSE_READ_MODEL_KEY_HEX",
    "EGOPULSE_TOKEN_MAC_KEY_HEX",
];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalKeys {
    schema_version: String,
    keys: BTreeMap<String, String>,
}
impl Drop for LocalKeys {
    fn drop(&mut self) {
        for value in self.keys.values_mut() {
            value.zeroize();
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "LOCAL_KEYS_INVALID")
}
fn decode(bytes: &[u8]) -> io::Result<LocalKeys> {
    let keys: LocalKeys = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if keys.schema_version != "egopulse.local-keys/v1"
        || keys.keys.len() != LOCAL_KEY_NAMES.len()
        || !LOCAL_KEY_NAMES.iter().all(|name| {
            keys.keys.get(*name).is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
            })
        })
    {
        return Err(invalid());
    }
    Ok(keys)
}

/// Called at process startup. Windows environment mutation is thread-safe;
/// nothing is injected until the entire DPAPI payload has been authenticated and validated.
pub fn load_protected_process_keys() -> io::Result<()> {
    let Some(path) = std::env::var_os("EGOPULSE_KEY_FILE") else {
        return Ok(());
    };
    #[cfg(windows)]
    {
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|_| invalid())?;
        let mut protected = Vec::new();
        file.take(65_537)
            .read_to_end(&mut protected)
            .map_err(|_| invalid())?;
        if protected.is_empty() || protected.len() > 65_536 {
            return Err(invalid());
        }
        let plain =
            Zeroizing::new(crate::unprotect_client_record(&protected).map_err(|_| invalid())?);
        let keys = decode(&plain)?;
        for (name, value) in &keys.keys {
            // SAFETY: this module is Windows-only here. SetEnvironmentVariableW
            // is thread-safe on Windows (the Unix libc environment caveat does not apply).
            unsafe {
                std::env::set_var(name, value);
            }
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_or_incomplete_keys_are_rejected_before_injection() {
        assert!(decode(br#"{"schema_version":"egopulse.local-keys/v1","keys":{}}"#).is_err());
        let mut keys: BTreeMap<_, _> = LOCAL_KEY_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), "12".repeat(32)))
            .collect();
        let encode = |keys: &BTreeMap<String, String>| {
            serde_json::to_vec(
                &serde_json::json!({"schema_version":"egopulse.local-keys/v1", "keys":keys}),
            )
            .unwrap()
        };
        assert!(decode(&encode(&keys)).is_ok());
        keys.insert(LOCAL_KEY_NAMES[0].to_owned(), "invalid".to_owned());
        assert!(decode(&encode(&keys)).is_err());
        keys.insert(LOCAL_KEY_NAMES[0].to_owned(), "12".repeat(32));
        keys.insert("UNRELATED_KEY".to_owned(), "12".repeat(32));
        assert!(decode(&encode(&keys)).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_preserves_keys_and_rejects_tampering() {
        let values: BTreeMap<_, _> = LOCAL_KEY_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), "42".repeat(32)))
            .collect();
        let bytes = Zeroizing::new(
            serde_json::to_vec(
                &serde_json::json!({"schema_version":"egopulse.local-keys/v1", "keys":values}),
            )
            .unwrap(),
        );
        let mut protected = crate::protect_client_record(&bytes).unwrap();
        assert!(
            !protected
                .windows(64)
                .any(|window| window == "42".repeat(32).as_bytes())
        );
        let plain = Zeroizing::new(crate::unprotect_client_record(&protected).unwrap());
        assert!(decode(&plain).is_ok());
        let last = protected.len() - 1;
        protected[last] ^= 1;
        assert!(crate::unprotect_client_record(&protected).is_err());
    }
}
