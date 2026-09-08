use std::{path::PathBuf, time::Duration};

use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexReadOnlyReviewRequest {
    pub execution_id: String,
    pub working_directory: PathBuf,
    pub model: String,
    pub prompt: String,
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}

/// One fresh, bounded read-only model turn whose caller does not inherit the
/// user's MCP, app, hook, web-search, shell, or collaboration tool surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexReadOnlyTurnRequest {
    pub execution_id: String,
    pub working_directory: PathBuf,
    pub model: String,
    pub prompt: String,
    pub output_schema: Value,
    pub timeout: Duration,
    pub output_limit_bytes: usize,
}

impl From<CodexReadOnlyTurnRequest> for CodexReadOnlyReviewRequest {
    fn from(value: CodexReadOnlyTurnRequest) -> Self {
        Self {
            execution_id: value.execution_id,
            working_directory: value.working_directory,
            model: value.model,
            prompt: value.prompt,
            timeout: value.timeout,
            output_limit_bytes: value.output_limit_bytes,
        }
    }
}

pub type CodexReadOnlyTurnOutcome = CodexReadOnlyReviewOutcome;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexReadOnlyReviewTerminalStatus {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexReadOnlyReviewUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexReadOnlyModelCallReceipt {
    pub execution_id: String,
    pub model: String,
    pub thread_id: String,
    pub turn_id: String,
    pub terminal_status: CodexReadOnlyReviewTerminalStatus,
    pub duration: Duration,
    pub output_bytes: usize,
    pub output_sha256: String,
    pub usage: Option<CodexReadOnlyReviewUsage>,
    pub delivery_started: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexReadOnlyReviewOutcome {
    pub thread_id: String,
    pub turn_id: String,
    pub terminal_status: CodexReadOnlyReviewTerminalStatus,
    pub assistant_output: Vec<u8>,
    pub receipt: CodexReadOnlyModelCallReceipt,
    pub delivery_started: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewMessageAction {
    Continue,
    Terminal(CodexReadOnlyReviewTerminalStatus),
}

#[derive(Debug)]
pub(crate) struct ReviewExchange {
    thread_id: String,
    turn_id: String,
    assistant_items: Vec<AssistantItem>,
    observed_output_bytes: usize,
    usage: Option<CodexReadOnlyReviewUsage>,
}

#[derive(Debug)]
struct AssistantItem {
    id: String,
    phase: Option<String>,
    text: Vec<u8>,
    completed: bool,
}

impl ReviewExchange {
    pub(crate) fn new(thread_id: String, turn_id: String) -> Self {
        Self {
            thread_id,
            turn_id,
            assistant_items: Vec::new(),
            observed_output_bytes: 0,
            usage: None,
        }
    }

    pub(crate) fn accept_notification(
        &mut self,
        value: &Value,
        output_limit_bytes: usize,
    ) -> Result<ReviewMessageAction, &'static str> {
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .ok_or("CODEX_REVIEW_NOTIFICATION_INVALID")?;
        let params = value.get("params").unwrap_or(&Value::Null);
        self.validate_thread_id(params)?;
        self.validate_turn_id(params)?;
        match method {
            "turn/started" => {
                self.validate_thread_id(params)?;
                let turn_id = params
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .ok_or("CODEX_REVIEW_TURN_START_INVALID")?;
                if turn_id != self.turn_id {
                    return Err("CODEX_REVIEW_TURN_ID_DRIFT");
                }
                Ok(ReviewMessageAction::Continue)
            }
            "item/agentMessage/delta" => {
                self.validate_thread_id(params)?;
                self.validate_turn_id(params)?;
                let item_id = params
                    .get("itemId")
                    .or_else(|| params.pointer("/item/id"))
                    .and_then(Value::as_str)
                    .ok_or("CODEX_REVIEW_ASSISTANT_ITEM_ID_MISSING")?;
                let delta = params
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or("CODEX_REVIEW_ASSISTANT_DELTA_INVALID")?;
                self.observe_output(delta.as_bytes(), output_limit_bytes)?;
                self.item_mut(item_id)?
                    .text
                    .extend_from_slice(delta.as_bytes());
                Ok(ReviewMessageAction::Continue)
            }
            "item/completed" => {
                self.validate_thread_id(params)?;
                self.validate_turn_id(params)?;
                if params.pointer("/item/type").and_then(Value::as_str) != Some("agentMessage") {
                    return Ok(ReviewMessageAction::Continue);
                }
                let item = params
                    .get("item")
                    .ok_or("CODEX_REVIEW_ASSISTANT_ITEM_INVALID")?;
                let item_id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or("CODEX_REVIEW_ASSISTANT_ITEM_ID_MISSING")?;
                let phase = item
                    .get("phase")
                    .or_else(|| params.get("phase"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    self.observe_output(text.as_bytes(), output_limit_bytes)?;
                    self.item_mut(item_id)?.text = text.as_bytes().to_vec();
                }
                let item_state = self.item_mut(item_id)?;
                item_state.phase = phase;
                item_state.completed = true;
                Ok(ReviewMessageAction::Continue)
            }
            "turn/completed" => {
                self.validate_thread_id(params)?;
                let turn_id = params
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .ok_or("CODEX_REVIEW_TERMINAL_TURN_ID_MISSING")?;
                if turn_id != self.turn_id {
                    return Err("CODEX_REVIEW_TURN_ID_DRIFT");
                }
                let status = match params.pointer("/turn/status").and_then(Value::as_str) {
                    Some("completed") => CodexReadOnlyReviewTerminalStatus::Completed,
                    Some("interrupted") => CodexReadOnlyReviewTerminalStatus::Interrupted,
                    Some("failed") => CodexReadOnlyReviewTerminalStatus::Failed,
                    _ => return Err("CODEX_REVIEW_TERMINAL_STATUS_UNKNOWN"),
                };
                Ok(ReviewMessageAction::Terminal(status))
            }
            "thread/tokenUsage/updated" | "turn/tokenUsage/updated" => {
                self.usage = parse_usage(params)?;
                Ok(ReviewMessageAction::Continue)
            }
            "account/rateLimits/updated" => {
                if crate::protocol::native_rate_limit_reached(params) {
                    Err("CODEX_REVIEW_CAPACITY_EXHAUSTED")
                } else {
                    Ok(ReviewMessageAction::Continue)
                }
            }
            "mcpServer/startupStatus/updated" => {
                match params.get("status").and_then(Value::as_str) {
                    Some("starting" | "ready" | "cancelled") => Ok(ReviewMessageAction::Continue),
                    _ => Err("CODEX_REVIEW_MCP_STARTUP_UNSUCCESSFUL"),
                }
            }
            "hook/started"
                if params.pointer("/run/status").and_then(Value::as_str) == Some("running") =>
            {
                Ok(ReviewMessageAction::Continue)
            }
            "hook/completed"
                if params.pointer("/run/status").and_then(Value::as_str) == Some("completed") =>
            {
                Ok(ReviewMessageAction::Continue)
            }
            "hook/started" | "hook/completed" => Err("CODEX_REVIEW_HOOK_UNSUCCESSFUL"),
            // These are informational Codex notifications already classified
            // as non-critical by the native protocol driver. They must not
            // turn ordinary reasoning/plan progress into delivery-unknown,
            // but their content is deliberately never exposed by this review
            // mapper.
            "turn/diff/updated"
            | "turn/plan/updated"
            | "item/plan/delta"
            | "item/commandExecution/outputDelta"
            | "item/commandExecution/terminalInteraction"
            | "item/fileChange/outputDelta"
            | "item/fileChange/patchUpdated"
            | "item/mcpToolCall/progress"
            | "item/reasoning/summaryTextDelta"
            | "item/reasoning/summaryPartAdded"
            | "item/reasoning/textDelta"
            | "turn/moderationMetadata"
            | "remoteControl/status/changed" => Ok(ReviewMessageAction::Continue),
            "thread/started"
            | "thread/status/changed"
            | "item/started"
            | "context/compacted"
            | "warning" => Ok(ReviewMessageAction::Continue),
            _ => Err("CODEX_REVIEW_PROTOCOL_MESSAGE_UNKNOWN"),
        }
    }

    pub(crate) fn finish(
        self,
        execution_id: String,
        model: String,
        status: CodexReadOnlyReviewTerminalStatus,
        duration: Duration,
    ) -> Result<CodexReadOnlyReviewOutcome, &'static str> {
        let phase_known = self.assistant_items.iter().any(|item| item.phase.is_some());
        let final_item = self
            .assistant_items
            .iter()
            .rev()
            .find(|item| {
                item.completed && !item.text.is_empty() && item.phase.as_deref() == Some("final")
            })
            .or_else(|| {
                self.assistant_items.iter().rev().find(|item| {
                    item.completed
                        && !item.text.is_empty()
                        && (!phase_known || item.phase.as_deref() != Some("commentary"))
                })
            })
            .ok_or("CODEX_REVIEW_FINAL_ASSISTANT_ITEM_MISSING")?;
        let assistant_output = final_item.text.clone();
        let receipt = CodexReadOnlyModelCallReceipt {
            execution_id,
            model,
            thread_id: self.thread_id.clone(),
            turn_id: self.turn_id.clone(),
            terminal_status: status,
            duration,
            output_bytes: assistant_output.len(),
            output_sha256: hex::encode(Sha256::digest(&assistant_output)),
            usage: self.usage,
            delivery_started: true,
        };
        Ok(CodexReadOnlyReviewOutcome {
            thread_id: self.thread_id,
            turn_id: self.turn_id,
            terminal_status: status,
            assistant_output,
            receipt,
            delivery_started: true,
        })
    }

    fn item_mut(&mut self, item_id: &str) -> Result<&mut AssistantItem, &'static str> {
        if item_id.trim().is_empty() {
            return Err("CODEX_REVIEW_ASSISTANT_ITEM_ID_MISSING");
        }
        if let Some(index) = self
            .assistant_items
            .iter()
            .position(|item| item.id == item_id)
        {
            return Ok(&mut self.assistant_items[index]);
        }
        self.assistant_items.push(AssistantItem {
            id: item_id.to_owned(),
            phase: None,
            text: Vec::new(),
            completed: false,
        });
        self.assistant_items
            .last_mut()
            .ok_or("CODEX_REVIEW_ASSISTANT_ITEM_INVALID")
    }

    fn validate_thread_id(&self, params: &Value) -> Result<(), &'static str> {
        let observed = params
            .get("threadId")
            .or_else(|| params.pointer("/item/threadId"))
            .or_else(|| params.pointer("/turn/threadId"))
            .and_then(Value::as_str);
        if observed.is_some_and(|value| value != self.thread_id) {
            return Err("CODEX_REVIEW_THREAD_ID_DRIFT");
        }
        Ok(())
    }

    fn validate_turn_id(&self, params: &Value) -> Result<(), &'static str> {
        let observed = params
            .get("turnId")
            .or_else(|| params.pointer("/item/turnId"))
            .or_else(|| params.pointer("/turn/id"))
            .and_then(Value::as_str);
        if observed.is_some_and(|value| value != self.turn_id) {
            return Err("CODEX_REVIEW_TURN_ID_DRIFT");
        }
        Ok(())
    }

    fn observe_output(
        &mut self,
        bytes: &[u8],
        output_limit_bytes: usize,
    ) -> Result<(), &'static str> {
        let total = self
            .observed_output_bytes
            .checked_add(bytes.len())
            .ok_or("CODEX_REVIEW_OUTPUT_LIMIT")?;
        if total > output_limit_bytes {
            return Err("CODEX_REVIEW_OUTPUT_LIMIT");
        }
        self.observed_output_bytes = total;
        Ok(())
    }
}

fn parse_usage(params: &Value) -> Result<Option<CodexReadOnlyReviewUsage>, &'static str> {
    let usage = params
        .pointer("/tokenUsage/total")
        .or_else(|| params.get("tokenUsage"))
        .or_else(|| params.get("usage"))
        .unwrap_or(&Value::Null);
    if usage.is_null() {
        return Ok(None);
    }
    let input_tokens = usage
        .get("inputTokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(Value::as_u64);
    let output_tokens = usage
        .get("outputTokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(Value::as_u64);
    let (Some(input_tokens), Some(output_tokens)) = (input_tokens, output_tokens) else {
        return Ok(None);
    };
    Ok(Some(CodexReadOnlyReviewUsage {
        input_tokens,
        output_tokens,
        cached_input_tokens: usage
            .get("cachedInputTokens")
            .or_else(|| usage.get("cached_input_tokens"))
            .and_then(Value::as_u64),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn review_distinguishes_routine_capacity_and_startup_from_failures() {
        let mut exchange = ReviewExchange::new("thread-1".into(), "turn-1".into());
        for (params, accepted) in [
            (json!({"status":"starting"}), true),
            (json!({"status":"ready"}), true),
            (json!({"status":"failed"}), false),
            (json!({"status":"future-status"}), false),
        ] {
            assert_eq!(
                exchange
                    .accept_notification(
                        &json!({"method":"mcpServer/startupStatus/updated","params":params}),
                        1024
                    )
                    .is_ok(),
                accepted
            );
        }
        for (params, accepted) in [
            (json!({"rateLimits":{"primary":{"usedPercent":5}}}), true),
            (json!({"rateLimits":{"primary":{"usedPercent":100}}}), false),
            (json!({"rateLimits":{"spendControlReached":true}}), false),
        ] {
            assert_eq!(
                exchange
                    .accept_notification(
                        &json!({"method":"account/rateLimits/updated","params":params}),
                        1024
                    )
                    .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn review_accepts_successful_hook_lifecycle_without_hiding_failure() {
        let mut exchange = ReviewExchange::new("thread-1".into(), "turn-1".into());
        for (method, status, accepted) in [
            ("hook/started", "running", true),
            ("hook/completed", "completed", true),
            ("hook/completed", "failed", false),
            ("hook/completed", "blocked", false),
            ("hook/completed", "future-status", false),
        ] {
            let message = json!({"method": method, "params": {"threadId": "thread-1", "turnId": null,
                "run": {"status": status, "entries": [{"kind": "context", "text": "private hook context"}]}}});
            assert_eq!(
                exchange.accept_notification(&message, 1024).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn review_requires_matching_turn_and_keeps_item_id_separate() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        assert_eq!(
            exchange
                .accept_notification(
                    &json!({
                        "method": "item/agentMessage/delta",
                        "params": {"itemId": "item-1", "delta": "answer"}
                    }),
                    100,
                )
                .expect("delta"),
            ReviewMessageAction::Continue
        );
        assert_eq!(
            exchange
                .accept_notification(
                    &json!({
                        "method": "item/completed",
                        "params": {"item": {"type": "agentMessage", "id": "item-1", "text": "answer"}}
                    }),
                    100,
                )
                .expect("item complete"),
            ReviewMessageAction::Continue
        );
        assert!(exchange
            .accept_notification(
                &json!({"method": "turn/completed", "params": {"turn": {"id": "item-1", "status": "completed"}}}),
                100,
            )
            .is_err());
        assert!(exchange
            .accept_notification(
                &json!({"method": "turn/started", "params": {"threadId": "thread-other", "turn": {"id": "turn-1"}}}),
                100,
            )
            .is_err());
        assert_eq!(
            exchange
                .accept_notification(
                    &json!({"method": "turn/completed", "params": {"turn": {"id": "turn-1", "status": "completed"}}}),
                    100,
                )
                .expect("turn complete"),
            ReviewMessageAction::Terminal(CodexReadOnlyReviewTerminalStatus::Completed)
        );
        let outcome = exchange
            .finish(
                "execution-1".to_owned(),
                "model-1".to_owned(),
                CodexReadOnlyReviewTerminalStatus::Completed,
                Duration::from_millis(3),
            )
            .expect("final assistant item");
        assert_eq!(outcome.assistant_output, b"answer");
    }

    #[test]
    fn review_selects_final_item_after_commentary_and_rejects_commentary_only() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        for (item_id, phase, text) in [
            ("item-commentary", "commentary", "thinking aloud"),
            ("item-final", "final", "{\"findings\":[]}"),
        ] {
            exchange
                .accept_notification(
                    &json!({
                        "method": "item/completed",
                        "params": {"item": {"type": "agentMessage", "id": item_id, "phase": phase, "text": text}}
                    }),
                    1024,
                )
                .expect("agent item");
        }
        let outcome = exchange
            .finish(
                "execution-1".to_owned(),
                "model-1".to_owned(),
                CodexReadOnlyReviewTerminalStatus::Completed,
                Duration::from_millis(3),
            )
            .expect("final phase item");
        assert_eq!(outcome.assistant_output, br#"{"findings":[]}"#);

        let mut commentary_only = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        commentary_only
            .accept_notification(
                &json!({
                    "method": "item/completed",
                    "params": {"item": {"type": "agentMessage", "id": "item-commentary", "phase": "commentary", "text": "only commentary"}}
                }),
                1024,
            )
            .expect("commentary item");
        assert!(
            commentary_only
                .finish(
                    "execution-1".to_owned(),
                    "model-1".to_owned(),
                    CodexReadOnlyReviewTerminalStatus::Completed,
                    Duration::from_millis(3),
                )
                .is_err()
        );
    }

    #[test]
    fn review_rejects_approval_unknown_protocol_and_output_overflow() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        assert!(
            exchange
                .accept_notification(
                    &json!({"method": "item/commandExecution/requestApproval", "id": 9}),
                    100,
                )
                .is_err()
        );
        assert!(
            exchange
                .accept_notification(&json!({"method": "future/event", "params": {}}), 100)
                .is_err()
        );
        assert!(exchange
            .accept_notification(
                &json!({"method": "item/agentMessage/delta", "params": {"itemId": "item-1", "delta": "12345"}}),
                4,
            )
            .is_err());
    }

    #[test]
    fn review_ignores_known_informational_sequence_without_exposing_reasoning() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        for method in [
            "item/reasoning/summaryTextDelta",
            "item/reasoning/summaryPartAdded",
            "item/reasoning/textDelta",
            "turn/plan/updated",
            "item/commandExecution/outputDelta",
        ] {
            assert_eq!(
                exchange
                    .accept_notification(
                        &json!({"method": method, "params": {"threadId": "thread-1", "turnId": "turn-1", "delta": "secret reasoning"}}),
                        64,
                    )
                    .expect("known informational notification"),
                ReviewMessageAction::Continue
            );
        }
        exchange
            .accept_notification(
                &json!({"method": "item/completed", "params": {"threadId": "thread-1", "turnId": "turn-1", "item": {"type": "agentMessage", "id": "final", "phase": "final", "text": "answer"}}}),
                64,
            )
            .expect("final item");
        let outcome = exchange
            .finish(
                "execution-1".to_owned(),
                "model-1".to_owned(),
                CodexReadOnlyReviewTerminalStatus::Completed,
                Duration::from_millis(1),
            )
            .expect("final output");
        assert_eq!(outcome.assistant_output, b"answer");
    }

    #[test]
    fn review_binds_item_thread_and_turn_and_reads_total_usage() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        assert!(exchange
            .accept_notification(
                &json!({"method": "item/agentMessage/delta", "params": {"threadId": "thread-other", "turnId": "turn-1", "itemId": "item-1", "delta": "x"}}),
                64,
            )
            .is_err());
        exchange
            .accept_notification(
                &json!({"method": "thread/tokenUsage/updated", "params": {"tokenUsage": {"total": {"inputTokens": 3, "outputTokens": 4, "cachedInputTokens": 2}}}}),
                64,
            )
            .expect("nested usage");
        assert_eq!(
            exchange.usage,
            Some(CodexReadOnlyReviewUsage {
                input_tokens: 3,
                output_tokens: 4,
                cached_input_tokens: Some(2)
            })
        );
    }

    #[test]
    fn unknown_usage_is_kept_as_none() {
        let mut exchange = ReviewExchange::new("thread-1".to_owned(), "turn-1".to_owned());
        exchange
            .accept_notification(
                &json!({"method": "thread/tokenUsage/updated", "params": {}}),
                10,
            )
            .expect("usage without fields is currently protocol-invalid");
    }
}
