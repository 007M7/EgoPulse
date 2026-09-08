//! Safe approval-display contract helpers.
//!
//! `egopulse.approval-display/v1` is an additive presentation profile. Older
//! observations may omit the summary, but absence never authorizes a positive
//! decision. The summary remains separate from Policy Authority and R9C content:
//! it contains only bounded terminal-safe labels, never native routing identity,
//! raw request JSON, diffs, credentials, or authority-bearing state.

use crate::v01::egopulse::harness::v1::{
    ApprovalDisplaySummary, ApprovalDisplaySummaryState, ApprovalKind,
};
use prost::Message;
use sha2::{Digest, Sha256};

pub const APPROVAL_DISPLAY_POLICY_CODE: &str = "egopulse.approval-display/v1";

const MAX_SUMMARY_REF_CHARS: usize = 512;
const MAX_COMMAND_PREVIEW_CHARS: usize = 2_048;
const MAX_WORKING_DIRECTORY_CHARS: usize = 512;
const MAX_FILE_CHANGES: usize = 512;
const MAX_FILE_PATH_CHARS: usize = 1_024;
const MAX_CHANGE_KIND_CHARS: usize = 64;
const MAX_REASON_CODES: usize = 32;
const MAX_REASON_CODE_CHARS: usize = 128;

/// Seals the protobuf bytes after clearing the digest field itself.
#[must_use]
pub fn seal_approval_display_summary(
    mut summary: ApprovalDisplaySummary,
) -> ApprovalDisplaySummary {
    summary.summary_digest_sha256.clear();
    summary.summary_digest_sha256 = sha256(&summary.encode_to_vec());
    summary
}

/// Validates a sealed summary's common bindings and safe field envelope.
///
/// This accepts non-reviewable states so a projection can preserve an explicit
/// unavailable/redacted/conflict result. Call `valid_reviewable_approval_summary`
/// before enabling a positive user decision.
#[must_use]
pub fn valid_approval_display_summary(
    summary: Option<&ApprovalDisplaySummary>,
    summary_ref: &str,
    action_digest: &str,
    kind: i32,
) -> bool {
    let Some(summary) = summary else {
        return false;
    };
    let Ok(state) = ApprovalDisplaySummaryState::try_from(summary.state) else {
        return false;
    };
    let Ok(approval_kind) = ApprovalKind::try_from(kind) else {
        return false;
    };
    state != ApprovalDisplaySummaryState::Unspecified
        && approval_kind != ApprovalKind::Unspecified
        && summary.policy_code == APPROVAL_DISPLAY_POLICY_CODE
        && summary.summary_ref == summary_ref
        && summary.action_digest_sha256 == action_digest
        && canonical_sha256(&summary.summary_digest_sha256)
        && canonical_sha256(&summary.action_digest_sha256)
        && canonical_sha256(&summary.source_binding_sha256)
        && summary.summary_digest_sha256
            == seal_approval_display_summary(summary.clone()).summary_digest_sha256
        && valid_safe_fields(summary)
        && (state != ApprovalDisplaySummaryState::Reviewable
            || valid_reviewable_shape(summary, kind))
}

/// Returns true only for a fully sealed, exactly bound, reviewable v1 summary.
#[must_use]
pub fn valid_reviewable_approval_summary(
    summary: Option<&ApprovalDisplaySummary>,
    summary_ref: &str,
    action_digest: &str,
    kind: i32,
) -> bool {
    summary.is_some_and(|value| {
        value.state == ApprovalDisplaySummaryState::Reviewable as i32
            && valid_approval_display_summary(Some(value), summary_ref, action_digest, kind)
    })
}

/// Renders only a valid reviewable summary. Every invalid, missing, redacted,
/// unavailable, or conflicting summary produces an explicit non-reviewable
/// message and never falls back to native request content.
#[must_use]
pub fn approval_display_text(
    summary: Option<&ApprovalDisplaySummary>,
    summary_ref: &str,
    action_digest: &str,
    kind: i32,
) -> String {
    if !valid_reviewable_approval_summary(summary, summary_ref, action_digest, kind) {
        return "Approval summary unavailable; this request cannot be reviewed safely.".to_owned();
    }
    let Some(summary) = summary else {
        return "Approval summary unavailable; this request cannot be reviewed safely.".to_owned();
    };
    let mut lines = Vec::new();
    if !summary.command_preview.is_empty() {
        lines.push(format!("Command: {}", summary.command_preview));
    }
    if !summary.working_directory_label.is_empty() {
        lines.push(format!(
            "Working directory: {}",
            summary.working_directory_label
        ));
    }
    for file in &summary.files {
        lines.push(format!("File {}: {}", file.change_kind, file.relative_path));
    }
    lines.join("\n")
}

/// Accepts a bounded, single-line display label only when it contains no known
/// managed credential, credential-shaped token, environment assignment, or
/// terminal control character.
///
/// `Some` means only that these deterministic checks passed. It is not a
/// general secret scanner, and callers must supply every credential managed for
/// the dispatch before treating the result as displayable.
#[must_use]
pub fn sanitize_approval_display_text(
    text: &str,
    managed_credentials: &[String],
    max_chars: usize,
) -> Option<String> {
    let value = text.trim();
    let credential_variants = canonical_managed_credential_variants(managed_credentials)?;
    if value.is_empty()
        || max_chars == 0
        || value.chars().count() > max_chars
        || value.chars().any(unsafe_display_char)
        || credential_variants
            .iter()
            .any(|credential| value.contains(credential))
    {
        return None;
    }

    let lower = value.to_ascii_lowercase();
    const CREDENTIAL_PATTERNS: [&str; 14] = [
        "authorization:",
        "bearer ",
        "cookie:",
        "api_key",
        "api-key",
        "apikey",
        "access_token",
        "access-token",
        "secret_key",
        "client_secret",
        "password=",
        "token=",
        "$env:",
        "-----begin private key-----",
    ];
    if CREDENTIAL_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
        || contains_flexible_credential_assignment(&lower)
        || contains_url_userinfo(value)
        || contains_common_token_shape(value)
        || value
            .split_ascii_whitespace()
            .any(looks_like_env_assignment)
    {
        return None;
    }
    Some(value.to_owned())
}

fn valid_safe_fields(summary: &ApprovalDisplaySummary) -> bool {
    safe_text(&summary.summary_ref, MAX_SUMMARY_REF_CHARS)
        && optional_sanitized_text(&summary.command_preview, MAX_COMMAND_PREVIEW_CHARS)
        && optional_sanitized_text(
            &summary.working_directory_label,
            MAX_WORKING_DIRECTORY_CHARS,
        )
        && summary.files.len() <= MAX_FILE_CHANGES
        && summary.files.iter().all(|file| {
            valid_relative_path(&file.relative_path)
                && safe_token(&file.change_kind, MAX_CHANGE_KIND_CHARS)
        })
        && summary.redaction_reason_codes.len() <= MAX_REASON_CODES
        && summary
            .redaction_reason_codes
            .iter()
            .all(|code| safe_token(code, MAX_REASON_CODE_CHARS))
}

fn valid_reviewable_shape(summary: &ApprovalDisplaySummary, kind: i32) -> bool {
    if summary.truncated || !summary.redaction_reason_codes.is_empty() {
        return false;
    }
    match ApprovalKind::try_from(kind) {
        Ok(ApprovalKind::Command) => {
            !summary.command_preview.is_empty() && summary.files.is_empty()
        }
        Ok(ApprovalKind::FileChange) => {
            summary.command_preview.is_empty() && !summary.files.is_empty()
        }
        _ => false,
    }
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_text(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.chars().count() <= max_chars
        && !value.chars().any(unsafe_display_char)
}

fn unsafe_display_char(value: char) -> bool {
    value.is_control()
        || matches!(
            value,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn optional_sanitized_text(value: &str, max_chars: usize) -> bool {
    value.is_empty()
        || sanitize_approval_display_text(value, &[], max_chars).as_deref() == Some(value)
}

fn safe_token(value: &str, max_chars: usize) -> bool {
    safe_text(value, max_chars)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

fn valid_relative_path(value: &str) -> bool {
    sanitize_approval_display_text(value, &[], MAX_FILE_PATH_CHARS).as_deref() == Some(value)
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn looks_like_env_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    !value.is_empty()
        && !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
}

fn canonical_managed_credential_variants(values: &[String]) -> Option<Vec<String>> {
    if values.len() > 32 {
        return None;
    }
    let mut variants = Vec::new();
    for value in values {
        if value.is_empty()
            || value.len() > 1_024
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return None;
        }
        let bytes = value.as_bytes();
        let percent_encoded = percent_encode(bytes);
        variants.extend([
            value.clone(),
            json_escape(value),
            percent_hex_lowercase(&percent_encoded),
            percent_encoded,
            base64_encode(bytes, false, true),
            base64_encode(bytes, false, false),
            base64_encode(bytes, true, true),
            base64_encode(bytes, true, false),
        ]);
    }
    variants.sort_unstable();
    variants.dedup();
    Some(variants)
}

fn contains_flexible_credential_assignment(lower: &str) -> bool {
    const NAMES: [&str; 9] = [
        "authorization",
        "api_key",
        "api-key",
        "access_token",
        "access-token",
        "client_secret",
        "password",
        "passwd",
        "token",
    ];
    NAMES.iter().any(|name| {
        lower.match_indices(name).any(|(offset, _)| {
            let before = &lower[..offset];
            let after = &lower[offset + name.len()..];
            let boundary_before = before
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric());
            let field_tail =
                after.trim_start_matches(|ch: char| ch.is_whitespace() || matches!(ch, '\'' | '"'));
            field_tail.starts_with('=')
                || field_tail.starts_with(':')
                || field_tail.starts_with('/')
                || boundary_before && after.chars().next().is_some_and(char::is_whitespace)
        })
    })
}

fn contains_url_userinfo(value: &str) -> bool {
    let mut remainder = value;
    while let Some(scheme_offset) = remainder.find("://") {
        let authority = &remainder[scheme_offset + 3..];
        let authority_end = authority
            .find(|ch: char| ch == '/' || ch == '?' || ch == '#' || ch.is_whitespace())
            .unwrap_or(authority.len());
        if authority[..authority_end].contains('@') {
            return true;
        }
        remainder = &authority[authority_end..];
    }
    value.split_ascii_whitespace().any(|token| {
        let trimmed = token
            .trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';' | '(' | ')' | '[' | ']'));
        let Some(at) = trimmed.find('@') else {
            return false;
        };
        let userinfo = trimmed[..at]
            .rsplit(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let host = &trimmed[at + 1..];
        if host.is_empty() {
            return false;
        }
        if userinfo
            .split_once(':')
            .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty())
        {
            return true;
        }
        let lower_userinfo = userinfo.to_ascii_lowercase();
        lower_userinfo
            .find("%3a")
            .is_some_and(|separator| separator > 0 && separator + 3 < userinfo.len())
    })
}

fn contains_common_token_shape(value: &str) -> bool {
    value.split_ascii_whitespace().any(|token| {
        let trimmed = token
            .trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';' | '(' | ')' | '[' | ']'));
        let lower = trimmed.to_ascii_lowercase();
        (lower.starts_with("ghp_") && trimmed.len() >= 20)
            || (lower.starts_with("github_pat_") && trimmed.len() >= 24)
            || (lower.starts_with("sk-") && trimmed.len() >= 20)
            || (lower.starts_with("sk_live_") && trimmed.len() >= 20)
            || (lower.starts_with("glpat-") && trimmed.len() >= 20)
            || (lower.starts_with("npm_") && trimmed.len() >= 20)
            || (lower.starts_with("xox") && trimmed.len() >= 20)
            || (trimmed.starts_with("AKIA")
                && trimmed.len() == 20
                && trimmed.bytes().all(|byte| byte.is_ascii_alphanumeric()))
            || looks_like_jwt(trimmed)
    })
}

fn looks_like_jwt(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(header) = segments.next() else {
        return false;
    };
    let Some(payload) = segments.next() else {
        return false;
    };
    let Some(signature) = segments.next() else {
        return false;
    };
    segments.next().is_none()
        && header.starts_with("eyJ")
        && [header, payload, signature]
            .iter()
            .all(|segment| segment.len() >= 8 && segment.bytes().all(is_base64_url_byte))
}

fn is_base64_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=')
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn percent_encode(value: &[u8]) -> String {
    let mut output = String::new();
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

fn percent_hex_lowercase(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut percent_digits_remaining = 0_u8;
    for ch in value.chars() {
        if ch == '%' {
            percent_digits_remaining = 2;
            output.push(ch);
        } else if percent_digits_remaining > 0 {
            percent_digits_remaining -= 1;
            output.push(ch.to_ascii_lowercase());
        } else {
            output.push(ch);
        }
    }
    output
}

fn base64_encode(value: &[u8], url_safe: bool, padded: bool) -> String {
    let alphabet = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(alphabet[usize::from(first >> 2)]));
        output.push(char::from(
            alphabet[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                alphabet[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else if padded {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(char::from(alphabet[usize::from(third & 0x3f)]));
        } else if padded {
            output.push('=');
        }
    }
    output
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v01::egopulse::harness::v1::ApprovalDisplayFileChange;

    const ACTION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SOURCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SUMMARY_REF: &str = "adapter-edge://codex/approval/summary";

    fn command_summary() -> ApprovalDisplaySummary {
        seal_approval_display_summary(ApprovalDisplaySummary {
            state: ApprovalDisplaySummaryState::Reviewable as i32,
            summary_ref: SUMMARY_REF.to_owned(),
            summary_digest_sha256: String::new(),
            action_digest_sha256: ACTION.to_owned(),
            source_binding_sha256: SOURCE.to_owned(),
            command_preview: "git status --short".to_owned(),
            working_directory_label: "repository root".to_owned(),
            files: Vec::new(),
            redaction_reason_codes: Vec::new(),
            truncated: false,
            policy_code: APPROVAL_DISPLAY_POLICY_CODE.to_owned(),
        })
    }

    #[test]
    fn sealed_reviewable_summary_requires_exact_ref_action_kind_and_digest() {
        let summary = command_summary();
        assert!(valid_reviewable_approval_summary(
            Some(&summary),
            SUMMARY_REF,
            ACTION,
            ApprovalKind::Command as i32
        ));

        for invalid in [
            valid_reviewable_approval_summary(
                Some(&summary),
                "adapter-edge://other",
                ACTION,
                ApprovalKind::Command as i32,
            ),
            valid_reviewable_approval_summary(
                Some(&summary),
                SUMMARY_REF,
                SOURCE,
                ApprovalKind::Command as i32,
            ),
            valid_reviewable_approval_summary(
                Some(&summary),
                SUMMARY_REF,
                ACTION,
                ApprovalKind::FileChange as i32,
            ),
        ] {
            assert!(!invalid);
        }

        let mut tampered = summary;
        tampered.command_preview.push_str(" --ignored");
        assert!(!valid_reviewable_approval_summary(
            Some(&tampered),
            SUMMARY_REF,
            ACTION,
            ApprovalKind::Command as i32
        ));
    }

    #[test]
    fn absent_legacy_summary_is_compatible_but_explicitly_not_reviewable() {
        assert!(!valid_reviewable_approval_summary(
            None,
            SUMMARY_REF,
            ACTION,
            ApprovalKind::Command as i32
        ));
        assert!(
            approval_display_text(None, SUMMARY_REF, ACTION, ApprovalKind::Command as i32)
                .contains("cannot be reviewed safely")
        );
    }

    #[test]
    fn sanitizer_rejects_limits_controls_credentials_and_environment_assignments() {
        let managed = vec!["managed secret/value".to_owned()];
        assert_eq!(
            sanitize_approval_display_text("git status", &managed, 32),
            Some("git status".to_owned())
        );
        assert_eq!(sanitize_approval_display_text("abcd", &managed, 3), None);
        assert_eq!(
            sanitize_approval_display_text("git\nstatus", &managed, 32),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("safe\u{202e}txt", &managed, 32),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("echo managed secret/value", &managed, 64),
            None
        );
        for encoded in [
            "managed%20secret%2Fvalue",
            "managed%20secret%2fvalue",
            "bWFuYWdlZCBzZWNyZXQvdmFsdWU=",
            "bWFuYWdlZCBzZWNyZXQvdmFsdWU",
        ] {
            assert_eq!(sanitize_approval_display_text(encoded, &managed, 64), None);
        }
        assert_eq!(sanitize_approval_display_text("TOKEN=value", &[], 64), None);
        assert_eq!(
            sanitize_approval_display_text(
                "curl --token hunter2 https://example.invalid",
                &[],
                128,
            ),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("tool --password hunter2", &[], 64),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("config.credentials.password/hunter2", &[], 64),
            None
        );
        assert_eq!(
            sanitize_approval_display_text(r#"{"credentials":{"password":"hunter2"}}"#, &[], 128,),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("Authorization: Bearer x", &[], 64),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("https://user:secret@example.test/path", &[], 128),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("alice:hunter2@example.invalid", &[], 64),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("alice%3Ahunter2@example.invalid", &[], 64),
            None
        );
        assert_eq!(
            sanitize_approval_display_text(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature123",
                &[],
                128,
            ),
            None
        );
        assert_eq!(
            sanitize_approval_display_text("--token opaque-value", &[], 64),
            None
        );
        assert!(!valid_relative_path("secrets/password/hunter2.txt"));
    }

    #[test]
    fn file_summary_requires_relative_safe_changes_and_renders_without_native_data() {
        let summary = seal_approval_display_summary(ApprovalDisplaySummary {
            state: ApprovalDisplaySummaryState::Reviewable as i32,
            summary_ref: SUMMARY_REF.to_owned(),
            summary_digest_sha256: String::new(),
            action_digest_sha256: ACTION.to_owned(),
            source_binding_sha256: SOURCE.to_owned(),
            command_preview: String::new(),
            working_directory_label: "repository root".to_owned(),
            files: vec![ApprovalDisplayFileChange {
                relative_path: "src/main.rs".to_owned(),
                change_kind: "update".to_owned(),
            }],
            redaction_reason_codes: Vec::new(),
            truncated: false,
            policy_code: APPROVAL_DISPLAY_POLICY_CODE.to_owned(),
        });
        assert!(valid_reviewable_approval_summary(
            Some(&summary),
            SUMMARY_REF,
            ACTION,
            ApprovalKind::FileChange as i32
        ));
        let rendered = approval_display_text(
            Some(&summary),
            SUMMARY_REF,
            ACTION,
            ApprovalKind::FileChange as i32,
        );
        assert_eq!(
            rendered,
            "Working directory: repository root\nFile update: src/main.rs"
        );
    }
}
