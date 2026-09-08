//! Private native-item joining for the separate, bounded approval display.
//! This never produces a Harness-content candidate or exposes native routing.
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
};

use egopulse_domain_contracts::{
    approval_display::{sanitize_approval_display_text, seal_approval_display_summary},
    v01::egopulse::harness::v1::{ApprovalDisplayFileChange, ApprovalDisplaySummary, ApprovalKind},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_ITEMS: usize = 64;
const MAX_ITEM_BYTES: usize = 131_072;
const REVIEWABLE: i32 = 1;
const UNAVAILABLE: i32 = 2;
const REDACTED: i32 = 3;
const CONFLICT: i32 = 4;

pub(crate) struct ApprovalContext<'a> {
    pub dispatch_id: &'a str,
    pub thread_id: &'a str,
    pub turn_id: Option<&'a str>,
    pub workspace_root: &'a Path,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NativeItemKey {
    dispatch: String,
    thread: String,
    turn: String,
    item: String,
}

#[derive(Default)]
pub(crate) struct ApprovalItemCache {
    // None means a duplicate/conflicting item. Do not repair it by proximity.
    items: HashMap<NativeItemKey, Option<Value>>,
    overflowed: bool,
}

impl ApprovalItemCache {
    pub fn record_started(&mut self, context: &ApprovalContext<'_>, params: &Value) {
        let Some(item) = params.get("item") else {
            return;
        };
        if !matches!(
            item.get("type").and_then(Value::as_str),
            Some("commandExecution" | "fileChange")
        ) {
            return;
        }
        let Some(key) = item_key(context, params, item.get("id")) else {
            return;
        };
        if let Some(existing) = self.items.get_mut(&key) {
            *existing = None;
            return;
        }
        if self.items.len() >= MAX_ITEMS {
            self.overflowed = true;
            return;
        }
        // Raw file diffs remain private and bounded. They are only used to bind
        // the displayed paths to this exact started item, never displayed.
        let bounded = serde_json::to_vec(item).is_ok_and(|bytes| bytes.len() <= MAX_ITEM_BYTES);
        self.items.insert(key, bounded.then(|| item.clone()));
    }

    pub fn summarize(
        &self,
        context: Option<&ApprovalContext<'_>>,
        params: &Value,
        request_id: &str,
        action_digest: &str,
        kind: ApprovalKind,
        credentials: &[String],
    ) -> ApprovalDisplaySummary {
        let mut summary = ApprovalDisplaySummary {
            state: UNAVAILABLE,
            summary_ref: format!("adapter-edge://codex/approval/summary/{request_id}"),
            action_digest_sha256: action_digest.to_owned(),
            source_binding_sha256: action_digest.to_owned(),
            policy_code: "egopulse.approval-display/v1".to_owned(),
            ..Default::default()
        };
        let Some(context) = context else {
            return seal_approval_display_summary(summary);
        };
        let Some(key) = item_key(context, params, params.get("itemId")) else {
            return seal_approval_display_summary(summary);
        };
        if self.overflowed {
            summary.truncated = true;
            return seal_approval_display_summary(summary);
        }
        let item = match self.items.get(&key) {
            Some(Some(item)) => item,
            Some(None) => {
                summary.state = CONFLICT;
                return seal_approval_display_summary(summary);
            }
            None => return seal_approval_display_summary(summary),
        };
        let binding = serde_json::json!([key.dispatch, key.thread, key.turn, key.item, item]);
        summary.source_binding_sha256 = hex::encode(Sha256::digest(binding.to_string().as_bytes()));
        // Broader permission/network grants cannot be represented by a command
        // or a finite file list. Keep them explicitly unavailable for AllowOnce.
        if [
            "additionalPermissions",
            "networkApprovalContext",
            "grantRoot",
        ]
        .into_iter()
        .any(|field| params.get(field).is_some_and(|value| !value.is_null()))
        {
            return seal_approval_display_summary(summary);
        }
        match kind {
            ApprovalKind::Command
                if item.get("type").and_then(Value::as_str) == Some("commandExecution") =>
            {
                for field in ["command", "cwd", "commandActions"] {
                    if let (Some(requested), Some(started)) = (params.get(field), item.get(field))
                        && !requested.is_null()
                        && !started.is_null()
                        && requested != started
                    {
                        summary.state = CONFLICT;
                        return seal_approval_display_summary(summary);
                    }
                }
                let Some(command) = item.get("command").and_then(Value::as_str) else {
                    return seal_approval_display_summary(summary);
                };
                let Some(cwd) = item.get("cwd").and_then(Value::as_str) else {
                    return seal_approval_display_summary(summary);
                };
                let Some(label) = workspace_path(context.workspace_root, cwd, true) else {
                    return seal_approval_display_summary(summary);
                };
                let Some(command) = sanitize_approval_display_text(command, credentials, 2048)
                else {
                    summary.state = REDACTED;
                    summary
                        .redaction_reason_codes
                        .push("COMMAND_DISPLAY_WITHHELD".to_owned());
                    return seal_approval_display_summary(summary);
                };
                let Some(label) = sanitize_approval_display_text(&label, credentials, 256) else {
                    summary.state = REDACTED;
                    summary
                        .redaction_reason_codes
                        .push("WORKSPACE_LABEL_WITHHELD".to_owned());
                    return seal_approval_display_summary(summary);
                };
                summary.command_preview = command;
                summary.working_directory_label = label;
                summary.state = REVIEWABLE;
            }
            ApprovalKind::FileChange
                if item.get("type").and_then(Value::as_str) == Some("fileChange") =>
            {
                let Some(changes) = item.get("changes").and_then(Value::as_array) else {
                    return seal_approval_display_summary(summary);
                };
                if changes.is_empty() || changes.len() > 64 {
                    summary.truncated = changes.len() > 64;
                    return seal_approval_display_summary(summary);
                }
                let mut files = Vec::with_capacity(changes.len());
                for change in changes {
                    let Some(path) = change
                        .get("path")
                        .and_then(Value::as_str)
                        .and_then(|path| workspace_path(context.workspace_root, path, false))
                    else {
                        return seal_approval_display_summary(summary);
                    };
                    let Some(path) = sanitize_approval_display_text(&path, credentials, 256) else {
                        summary.state = REDACTED;
                        summary
                            .redaction_reason_codes
                            .push("FILE_PATH_WITHHELD".to_owned());
                        return seal_approval_display_summary(summary);
                    };
                    let kind = change
                        .pointer("/kind/type")
                        .and_then(Value::as_str)
                        .or_else(|| change.get("kind").and_then(Value::as_str));
                    let Some(kind @ ("add" | "delete" | "update")) = kind else {
                        return seal_approval_display_summary(summary);
                    };
                    // Renames affect a second path. Until both are represented,
                    // do not present a one-path summary as complete.
                    if change
                        .pointer("/kind/movePath")
                        .is_some_and(|value| !value.is_null())
                    {
                        return seal_approval_display_summary(summary);
                    }
                    files.push(ApprovalDisplayFileChange {
                        relative_path: path,
                        change_kind: kind.to_owned(),
                    });
                }
                files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
                if files
                    .windows(2)
                    .any(|pair| pair[0].relative_path == pair[1].relative_path)
                {
                    summary.state = CONFLICT;
                    return seal_approval_display_summary(summary);
                }
                summary.files = files;
                summary.working_directory_label = ".".to_owned();
                summary.state = REVIEWABLE;
            }
            _ => {}
        }
        seal_approval_display_summary(summary)
    }
}

fn item_key(
    context: &ApprovalContext<'_>,
    params: &Value,
    item: Option<&Value>,
) -> Option<NativeItemKey> {
    let thread = params.get("threadId")?.as_str()?;
    let turn = params.get("turnId")?.as_str()?;
    let item = item?.as_str()?;
    if context.dispatch_id.is_empty()
        || thread != context.thread_id
        || Some(turn) != context.turn_id
        || item.is_empty()
        || item.len() > 256
        || thread.len() > 256
        || turn.len() > 256
    {
        return None;
    }
    Some(NativeItemKey {
        dispatch: context.dispatch_id.to_owned(),
        thread: thread.to_owned(),
        turn: turn.to_owned(),
        item: item.to_owned(),
    })
}

fn workspace_path(root: &Path, path: &str, allow_root: bool) -> Option<String> {
    let root = root.canonicalize().ok()?;
    let input = Path::new(path);
    if input
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return None;
    }
    let joined = if input.is_absolute() {
        input.to_owned()
    } else {
        root.join(input)
    };
    // Resolve the nearest existing ancestor, so a symlink cannot make an
    // apparently relative new file authorize a write outside the workspace.
    let mut existing = joined.as_path();
    let mut tail = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tail.push(existing.file_name()?.to_owned());
                existing = existing.parent()?;
                if tail.len() > 64 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    let mut resolved: PathBuf = existing.canonicalize().ok()?;
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    let relative = resolved.strip_prefix(&root).ok()?;
    if relative.as_os_str().is_empty() {
        return allow_root.then(|| ".".to_owned());
    }
    Some(relative.to_str()?.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_domain_contracts::approval_display::valid_reviewable_approval_summary;
    use serde_json::json;

    #[test]
    fn approval_display_joins_only_the_exact_item_and_withholds_conflicts() {
        let root = std::env::current_dir().expect("crate directory");
        let context = ApprovalContext {
            dispatch_id: "dispatch-one",
            thread_id: "thread-one",
            turn_id: Some("turn-one"),
            workspace_root: &root,
        };
        let started = json!({"threadId":"thread-one", "turnId":"turn-one", "item":{"id":"item-one", "type":"commandExecution", "command":"cargo test", "cwd":root}});
        let request = json!({"threadId":"thread-one", "turnId":"turn-one", "itemId":"item-one", "command":"cargo test", "cwd":root});
        let mut cache = ApprovalItemCache::default();
        cache.record_started(&context, &started);
        let digest = "a".repeat(64);
        let summary = cache.summarize(
            Some(&context),
            &request,
            "request-one",
            &digest,
            ApprovalKind::Command,
            &[],
        );
        assert!(valid_reviewable_approval_summary(
            Some(&summary),
            &summary.summary_ref,
            &digest,
            ApprovalKind::Command as i32
        ));
        assert_eq!(summary.working_directory_label, ".");
        let other = ApprovalContext {
            dispatch_id: "dispatch-two",
            ..context
        };
        assert_eq!(
            cache
                .summarize(
                    Some(&other),
                    &request,
                    "request-two",
                    &digest,
                    ApprovalKind::Command,
                    &[]
                )
                .state,
            UNAVAILABLE
        );
        let mut conflict = request.clone();
        conflict["command"] = json!("cargo clean");
        assert_eq!(
            cache
                .summarize(
                    Some(&context),
                    &conflict,
                    "request-three",
                    &digest,
                    ApprovalKind::Command,
                    &[]
                )
                .state,
            CONFLICT
        );
        cache.record_started(&context, &started);
        assert_eq!(
            cache
                .summarize(
                    Some(&context),
                    &request,
                    "request-four",
                    &digest,
                    ApprovalKind::Command,
                    &[]
                )
                .state,
            CONFLICT
        );
    }

    #[test]
    fn file_approval_displays_only_workspace_paths_never_diff_or_credentials() {
        let root = std::env::current_dir().expect("crate directory");
        let context = ApprovalContext {
            dispatch_id: "dispatch",
            thread_id: "thread",
            turn_id: Some("turn"),
            workspace_root: &root,
        };
        let started = json!({"threadId":"thread", "turnId":"turn", "item":{"id":"file-item", "type":"fileChange", "changes":[{"path":"src/lib.rs", "kind":{"type":"update"}, "diff":"private diff content NEVER DISPLAY"}]}});
        let request = json!({"threadId":"thread", "turnId":"turn", "itemId":"file-item"});
        let mut cache = ApprovalItemCache::default();
        cache.record_started(&context, &started);
        let summary = cache.summarize(
            Some(&context),
            &request,
            "request",
            &"b".repeat(64),
            ApprovalKind::FileChange,
            &[],
        );
        assert_eq!(summary.state, REVIEWABLE);
        assert_eq!(summary.files[0].relative_path, "src/lib.rs");
        assert!(!format!("{summary:?}").contains("private diff"));
        let withheld = cache.summarize(
            Some(&context),
            &request,
            "request",
            &"b".repeat(64),
            ApprovalKind::FileChange,
            &["lib.rs".to_owned()],
        );
        assert_eq!(withheld.state, REDACTED);
        assert!(withheld.files.is_empty());
        assert!(workspace_path(&root, "../outside", false).is_none());
        assert!(workspace_path(&root, "src/new-approval-file.cjs", false).is_some());
    }
}
