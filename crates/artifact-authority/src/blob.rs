use egopulse_domain_contracts::v01::egopulse::artifact::v1::{ContentAddress, HashAlgorithm};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum BlobStoreError {
    #[error("only SHA-256 content addresses are supported")]
    UnsupportedAlgorithm,
    #[error("content digest is not a canonical lowercase SHA-256 value")]
    InvalidDigest,
    #[error("content digest does not match the supplied bytes")]
    DigestMismatch,
    #[error("content length does not match the supplied bytes")]
    LengthMismatch,
    #[error("content-addressed blob is missing")]
    Missing,
    #[error("content-addressed blob I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct ContentAddressedBlobStore {
    root: PathBuf,
}

impl ContentAddressedBlobStore {
    pub fn open(root: PathBuf) -> Result<Self, BlobStoreError> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn address(bytes: &[u8]) -> ContentAddress {
        ContentAddress {
            algorithm: HashAlgorithm::Sha256 as i32,
            digest: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
        }
    }

    pub fn put_verified(
        &self,
        bytes: &[u8],
        expected: &ContentAddress,
    ) -> Result<PathBuf, BlobStoreError> {
        validate_address(expected)?;
        if bytes.len() as u64 != expected.byte_length {
            return Err(BlobStoreError::LengthMismatch);
        }
        if Self::address(bytes).digest != expected.digest {
            return Err(BlobStoreError::DigestMismatch);
        }

        let final_path = self.path_for(expected)?;
        if final_path.exists() {
            self.verify(expected)?;
            return Ok(final_path);
        }

        let parent = final_path.parent().expect("blob path always has a shard");
        fs::create_dir_all(parent)?;
        let temporary_path = parent.join(format!(".{}.tmp", Uuid::now_v7()));
        let publish_result = (|| -> Result<(), BlobStoreError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            match fs::rename(&temporary_path, &final_path) {
                Ok(()) => Ok(()),
                Err(_error) if final_path.exists() => {
                    let _ = fs::remove_file(&temporary_path);
                    self.verify(expected).map(|_| ())
                }
                Err(error) => Err(BlobStoreError::Io(error)),
            }
        })();
        if publish_result.is_err() && temporary_path.exists() {
            let _ = fs::remove_file(&temporary_path);
        }
        publish_result?;

        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&final_path)?
            .sync_all()?;
        self.verify(expected)?;
        Ok(final_path)
    }

    pub fn verify(&self, address: &ContentAddress) -> Result<PathBuf, BlobStoreError> {
        let path = self.path_for(address)?;
        if !path.is_file() {
            return Err(BlobStoreError::Missing);
        }
        let mut file = File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            length += read as u64;
            hasher.update(&buffer[..read]);
        }
        if length != address.byte_length {
            return Err(BlobStoreError::LengthMismatch);
        }
        if hex::encode(hasher.finalize()) != address.digest {
            return Err(BlobStoreError::DigestMismatch);
        }
        Ok(path)
    }

    pub fn read_verified(&self, address: &ContentAddress) -> Result<Vec<u8>, BlobStoreError> {
        let path = self.verify(address)?;
        Ok(fs::read(path)?)
    }

    fn path_for(&self, address: &ContentAddress) -> Result<PathBuf, BlobStoreError> {
        validate_address(address)?;
        Ok(self
            .root
            .join(&address.digest[0..2])
            .join(&address.digest[2..4])
            .join(&address.digest))
    }
}

fn validate_address(address: &ContentAddress) -> Result<(), BlobStoreError> {
    if address.algorithm != HashAlgorithm::Sha256 as i32 {
        return Err(BlobStoreError::UnsupportedAlgorithm);
    }
    if address.digest.len() != 64
        || !address
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BlobStoreError::InvalidDigest);
    }
    Ok(())
}
