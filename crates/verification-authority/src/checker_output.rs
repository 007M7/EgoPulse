//! Where a checker's review artifact is read from, and how the exact bytes are
//! sealed so a Verification result can cite the checker's own output.
//!
//! Two producer shapes are supported. A checker that prints its review artifact
//! on stdout needs no configuration. A sidecar that answers on stdout with an
//! envelope and writes the artifact next to its own working directory is read
//! through its declared `artifact_path`; the path is confined to that working
//! directory and the bytes are capped, so a checker cannot turn this reader
//! into a general file read. In both cases the bytes that are mapped are the
//! bytes that get sealed.

use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::ContentAddress,
    verification::v1::{CheckerProfile, VerificationRequest},
};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Upper bound for one checker artifact read through an envelope. The governed
/// process output limit does not bound a file the checker wrote itself.
pub const MAX_CHECKER_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

/// Explicit choice of the checker output location. Absence of configuration
/// keeps the published stdout contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerOutputSource {
    /// The review artifact is the process' stdout, as in the published
    /// single-checker contract.
    Stdout,
    /// The process' stdout is an envelope and the review artifact is the file
    /// its `artifact_path` names, read inside the checker's working directory.
    EnvelopeArtifactPath,
}

/// The exact bytes a checker produced, sealed at the application boundary. A
/// returned value means the artifact exists, is digest verified and carries the
/// execution it was captured for; it says nothing about the criterion outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedCheckerOutput {
    pub artifact_id: String,
    pub address: ContentAddress,
}

/// Seals one checker output for one Verification execution. The Verification
/// Authority crate owns no Artifact store, so this is implemented by the
/// application composition; the returned value is what a criterion result is
/// allowed to cite as the checker's raw output.
pub trait CheckerOutputSink: Send + Sync {
    fn capture(
        &self,
        request: &VerificationRequest,
        run_id: &str,
        profile: &CheckerProfile,
        output_key: &str,
        bytes: &[u8],
    ) -> Result<SealedCheckerOutput, String>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum EnvelopeReadError {
    /// stdout is not a JSON object carrying a usable `artifact_path`.
    NotAnEnvelope,
    /// The captured output declares more than one different artifact path.
    /// Choosing one of several answers would be an unattributed guess.
    AmbiguousArtifactPath,
    /// The named path is itself a symbolic link.
    SymbolicLink,
    /// The named path leaves the checker's working directory.
    OutsideWorkingDirectory,
    /// The named path is not a readable regular file.
    Unavailable,
    /// The artifact exceeds the reader's byte cap.
    TooLarge,
}

#[derive(Debug, Deserialize)]
struct CheckerEnvelope {
    #[serde(default)]
    artifact_path: Option<String>,
}

/// Reads the review artifact a sidecar envelope points at.
///
/// The declared path is confined to the checker's working directory, the
/// artifact is read through one file handle with a `max_bytes + 1` bound, and
/// a declared path that is itself a symbolic link is refused rather than
/// followed. A link in a parent directory is resolved by the containment check
/// below, so its target still has to be inside the working directory. A
/// checker that writes a preamble before its envelope is still read, because
/// the envelope is the one object written on its own line.
pub fn read_envelope_artifact(
    working_directory: &Path,
    envelope: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, EnvelopeReadError> {
    let declared = envelope_path(envelope)?;
    let directory =
        std::fs::canonicalize(working_directory).map_err(|_| EnvelopeReadError::Unavailable)?;
    let declared = PathBuf::from(declared);
    let candidate = if declared.is_absolute() {
        declared
    } else {
        directory.join(declared)
    };
    let link_metadata =
        std::fs::symlink_metadata(&candidate).map_err(|_| EnvelopeReadError::Unavailable)?;
    if link_metadata.file_type().is_symlink() {
        return Err(EnvelopeReadError::SymbolicLink);
    }
    let resolved = std::fs::canonicalize(&candidate).map_err(|_| EnvelopeReadError::Unavailable)?;
    if resolved == directory || !resolved.starts_with(&directory) {
        return Err(EnvelopeReadError::OutsideWorkingDirectory);
    }
    let file = std::fs::File::open(&resolved).map_err(|_| EnvelopeReadError::Unavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| EnvelopeReadError::Unavailable)?;
    if !metadata.is_file() {
        return Err(EnvelopeReadError::Unavailable);
    }
    let cap = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if metadata.len() > cap {
        return Err(EnvelopeReadError::TooLarge);
    }
    // The cap is enforced on the read itself: a file that grows between the
    // metadata check and the read cannot deliver more than `max_bytes + 1`
    // bytes, and that extra byte is refused.
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| EnvelopeReadError::Unavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > cap {
        return Err(EnvelopeReadError::TooLarge);
    }
    Ok(bytes)
}

/// The one artifact path this captured output declares. Several different
/// declared paths are an ambiguity, not a choice: a reader that picked one
/// could not attribute what it read.
fn envelope_path(envelope: &[u8]) -> Result<String, EnvelopeReadError> {
    let mut declared: Option<String> = None;
    for candidate in json_objects(envelope) {
        let Some(path) = envelope_path_in_json(candidate) else {
            continue;
        };
        match declared.as_deref() {
            None => declared = Some(path),
            Some(existing) if existing == path => {}
            Some(_) => return Err(EnvelopeReadError::AmbiguousArtifactPath),
        }
    }
    declared.ok_or(EnvelopeReadError::NotAnEnvelope)
}

fn envelope_path_in_json(bytes: &[u8]) -> Option<String> {
    let parsed: CheckerEnvelope = serde_json::from_slice(bytes).ok()?;
    parsed
        .artifact_path
        .filter(|value| !value.trim().is_empty())
}

/// Every complete top-level JSON object in captured process output, in the
/// order each one ends. A governed checker may share stdout with a wrapper
/// process and may write several answers, so all of them are enumerated: a
/// reader that used only the first would silently choose between conflicting
/// answers. Braces inside strings do not count, and scanning stops at the
/// first object that never closes, so a truncated answer is refused instead of
/// being read as a shorter one.
pub(crate) fn json_objects(bytes: &[u8]) -> Vec<&[u8]> {
    let mut objects = Vec::new();
    let mut index = 0usize;
    while let Some(offset) = bytes[index..].iter().position(|byte| *byte == b'{') {
        let start = index + offset;
        let Some(end) = json_object_end(bytes, start) else {
            break;
        };
        objects.push(&bytes[start..=end]);
        index = end + 1;
    }
    objects
}

/// Index of the brace closing the object that opens at `start`, or `None` when
/// it never closes.
fn json_object_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TempDirectory {
        path: PathBuf,
    }

    impl TempDirectory {
        fn new() -> Self {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let unique = format!(
                "{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            );
            let path = std::env::temp_dir().join(format!("egopulse-checker-output-{unique}"));
            fs::create_dir_all(&path).expect("create temp directory");
            Self { path }
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn envelope_artifact_is_read_inside_the_working_directory() {
        let directory = TempDirectory::new();
        let reviews = directory.path.join(".sego").join("reviews");
        fs::create_dir_all(&reviews).expect("create reviews directory");
        fs::write(reviews.join("r1.json"), b"{\"id\":\"r1\"}").expect("write artifact");
        let envelope = serde_json::json!({"artifact_path": ".sego/reviews/r1.json"});
        let bytes = read_envelope_artifact(
            &directory.path,
            &serde_json::to_vec(&envelope).expect("serialize envelope"),
            MAX_CHECKER_ARTIFACT_BYTES,
        )
        .expect("artifact is readable");
        assert_eq!(bytes, b"{\"id\":\"r1\"}");
    }

    #[test]
    fn absolute_artifact_path_inside_the_working_directory_is_accepted() {
        let directory = TempDirectory::new();
        let artifact = directory.path.join("review.json");
        fs::write(&artifact, b"{}").expect("write artifact");
        let envelope = serde_json::json!({"artifact_path": artifact.display().to_string()});
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                &serde_json::to_vec(&envelope).expect("serialize envelope"),
                MAX_CHECKER_ARTIFACT_BYTES,
            ),
            Ok(b"{}".to_vec())
        );
    }

    #[test]
    fn envelope_pointing_outside_the_working_directory_is_refused() {
        let directory = TempDirectory::new();
        let outside = TempDirectory::new();
        let sibling_name = format!(
            "{}-escape.json",
            directory
                .path
                .file_name()
                .expect("temporary name")
                .to_string_lossy()
        );
        let sibling = directory
            .path
            .parent()
            .expect("temporary parent")
            .join(&sibling_name);
        fs::write(outside.path.join("review.json"), b"{}").expect("write outside artifact");
        fs::write(&sibling, b"{}").expect("write sibling artifact");
        // Both an absolute path outside the directory and a relative path that
        // climbs out of it name a real file, so only the containment check can
        // refuse them.
        for declared in [
            outside.path.join("review.json").display().to_string(),
            format!("..{}{sibling_name}", std::path::MAIN_SEPARATOR),
        ] {
            let envelope = serde_json::json!({ "artifact_path": declared });
            assert_eq!(
                read_envelope_artifact(
                    &directory.path,
                    &serde_json::to_vec(&envelope).expect("serialize envelope"),
                    MAX_CHECKER_ARTIFACT_BYTES,
                ),
                Err(EnvelopeReadError::OutsideWorkingDirectory),
                "declared {declared}"
            );
        }
        let _ = fs::remove_file(sibling);
    }

    #[test]
    fn envelope_without_a_usable_path_is_refused() {
        assert_eq!(
            read_envelope_artifact(Path::new("."), b"not json", MAX_CHECKER_ARTIFACT_BYTES),
            Err(EnvelopeReadError::NotAnEnvelope)
        );
        assert_eq!(
            read_envelope_artifact(
                Path::new("."),
                b"{\"status\":\"ok\"}",
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::NotAnEnvelope)
        );
    }

    #[test]
    fn the_byte_cap_is_exact_and_enforced_on_the_read() {
        let directory = TempDirectory::new();
        fs::write(directory.path.join("review.json"), vec![b'x'; 32]).expect("write artifact");
        let envelope = serde_json::json!({"artifact_path": "review.json"});
        let envelope = serde_json::to_vec(&envelope).expect("serialize envelope");
        // Exactly at the cap is readable; one byte over is refused.
        assert_eq!(
            read_envelope_artifact(&directory.path, &envelope, 32)
                .expect("artifact at the cap")
                .len(),
            32
        );
        assert_eq!(
            read_envelope_artifact(&directory.path, &envelope, 31),
            Err(EnvelopeReadError::TooLarge)
        );
    }

    #[test]
    fn a_directory_a_missing_file_and_a_relative_escape_are_refused() {
        let directory = TempDirectory::new();
        fs::create_dir_all(directory.path.join("reviews")).expect("create directory");
        for (declared, expected) in [
            ("reviews", EnvelopeReadError::Unavailable),
            ("missing.json", EnvelopeReadError::Unavailable),
            (r"..\elsewhere.json", EnvelopeReadError::Unavailable),
        ] {
            let envelope = serde_json::json!({ "artifact_path": declared });
            assert_eq!(
                read_envelope_artifact(
                    &directory.path,
                    &serde_json::to_vec(&envelope).expect("serialize envelope"),
                    MAX_CHECKER_ARTIFACT_BYTES,
                ),
                Err(expected),
                "declared {declared}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_declared_path_that_is_a_symbolic_link_is_refused() {
        let directory = TempDirectory::new();
        let target = directory.path.join("review.json");
        fs::write(&target, b"{}").expect("write artifact");
        let link = directory.path.join("link.json");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            // Creating a link needs a privilege this process may not hold; the
            // refusal itself is still exercised on platforms that allow it.
            eprintln!("symbolic link creation unavailable; refusal not exercised here");
            return;
        }
        let envelope = serde_json::json!({"artifact_path": "link.json"});
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                &serde_json::to_vec(&envelope).expect("serialize envelope"),
                MAX_CHECKER_ARTIFACT_BYTES,
            ),
            Err(EnvelopeReadError::SymbolicLink)
        );
    }

    #[test]
    fn conflicting_declared_paths_on_one_line_are_refused() {
        let directory = TempDirectory::new();
        for name in ["one.json", "two.json"] {
            fs::write(directory.path.join(name), b"{}").expect("write artifact");
        }
        // A wrapper may share the line with the answer, and the line itself
        // may carry two answers: the second one must count.
        let envelope =
            "prefix {\"artifact_path\":\"one.json\"} {\"artifact_path\":\"two.json\"} suffix";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                envelope.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::AmbiguousArtifactPath)
        );
        // Nested braces and escaped quotes inside strings do not confuse the
        // scan, and the conflict is still seen.
        let nested = "{\"note\":\"a { \\\"quoted\\\" } brace\",\"artifact_path\":\"one.json\"} {\"artifact_path\":\"two.json\"}";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                nested.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::AmbiguousArtifactPath)
        );
    }

    #[test]
    fn a_pretty_printed_envelope_and_a_truncated_one_are_read_as_such() {
        let directory = TempDirectory::new();
        fs::write(directory.path.join("one.json"), b"{}").expect("write artifact");
        let pretty = "{\n  \"action\": \"review\",\n  \"artifact_path\": \"one.json\"\n}";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                pretty.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Ok(b"{}".to_vec()),
            "a legitimate multi-line envelope is read"
        );
        let truncated = "{\"artifact_path\":\"one.json\"";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                truncated.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::NotAnEnvelope),
            "an object that never closes declares nothing"
        );
        let noise = "review started\nstill working\n";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                noise.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::NotAnEnvelope)
        );
    }

    #[test]
    fn conflicting_declared_paths_are_refused_instead_of_chosen() {
        let directory = TempDirectory::new();
        for name in ["one.json", "two.json"] {
            fs::write(directory.path.join(name), b"{}").expect("write artifact");
        }
        let envelope = "{\"artifact_path\":\"one.json\"}
{\"artifact_path\":\"two.json\"}";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                envelope.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Err(EnvelopeReadError::AmbiguousArtifactPath)
        );
        // Repeating the same path is not a conflict.
        let repeated = "{\"artifact_path\":\"one.json\"}
{\"artifact_path\":\"one.json\"}";
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                repeated.as_bytes(),
                MAX_CHECKER_ARTIFACT_BYTES
            ),
            Ok(b"{}".to_vec())
        );
    }

    #[test]
    fn oversized_artifact_is_refused_before_it_is_read() {
        let directory = TempDirectory::new();
        fs::write(directory.path.join("review.json"), vec![b'x'; 64]).expect("write artifact");
        let envelope = serde_json::json!({"artifact_path": "review.json"});
        assert_eq!(
            read_envelope_artifact(
                &directory.path,
                &serde_json::to_vec(&envelope).expect("serialize envelope"),
                16,
            ),
            Err(EnvelopeReadError::TooLarge)
        );
    }
}
