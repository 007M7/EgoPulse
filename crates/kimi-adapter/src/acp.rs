#![allow(dead_code)]

use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KimiAcpMessage {
    Response(KimiAcpResponse),
    Notification(KimiAcpNotification),
    ServerRequest(KimiAcpServerRequest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KimiAcpResponse {
    Result {
        id: Value,
        result: Value,
    },
    Error {
        id: Option<Value>,
        code: Option<i64>,
        message: String,
        data: Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KimiAcpNotification {
    SessionUpdate {
        session_id: String,
        update: KimiAcpUpdate,
    },
    Unknown {
        method: String,
        params: Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum KimiAcpUpdate {
    UserMessageChunk {
        text: String,
    },
    AgentThoughtChunk {
        text: String,
    },
    AgentMessageChunk {
        text: String,
    },
    ToolCall {
        tool_call_id: String,
        title: Option<String>,
        status: String,
        content: Value,
    },
    Plan {
        entries: Value,
    },
    AvailableCommands {
        commands: Value,
    },
    Unknown {
        kind: String,
        raw: Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KimiAcpServerRequest {
    pub id: Value,
    pub method: String,
    pub params: Value,
}

pub(crate) fn parse_message(raw: &[u8]) -> Result<KimiAcpMessage, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "invalid-json".to_owned())?;
    if let Some(error) = value.get("error") {
        return Ok(KimiAcpMessage::Response(KimiAcpResponse::Error {
            id: value.get("id").cloned(),
            code: error.get("code").and_then(Value::as_i64),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown-error")
                .to_owned(),
            data: error.get("data").cloned().unwrap_or(Value::Null),
        }));
    }
    if value.get("result").is_some() {
        return Ok(KimiAcpMessage::Response(KimiAcpResponse::Result {
            id: value
                .get("id")
                .cloned()
                .ok_or_else(|| "response-id-missing".to_owned())?,
            result: value.get("result").cloned().unwrap_or(Value::Null),
        }));
    }
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "message-shape-unknown".to_owned())?
        .to_owned();
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    if value.get("id").is_some() {
        return Ok(KimiAcpMessage::ServerRequest(KimiAcpServerRequest {
            id: value.get("id").cloned().unwrap_or(Value::Null),
            method,
            params,
        }));
    }
    if method == "session/update" {
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "session-update-session-id-missing".to_owned())?
            .to_owned();
        let update = params
            .get("update")
            .cloned()
            .ok_or_else(|| "session-update-payload-missing".to_owned())?;
        return Ok(KimiAcpMessage::Notification(
            KimiAcpNotification::SessionUpdate {
                session_id,
                update: parse_update(update)?,
            },
        ));
    }
    Ok(KimiAcpMessage::Notification(KimiAcpNotification::Unknown {
        method,
        params,
    }))
}

pub(crate) fn session_prompt_request(id: u64, session_id: &str, prompt: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "session/prompt",
        "params": {
            "sessionId": session_id,
            "prompt": [{ "type": "text", "text": prompt }]
        }
    })
}

pub(crate) fn session_cancel_request(id: u64, session_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "session/cancel",
        "params": { "sessionId": session_id }
    })
}

fn parse_update(value: Value) -> Result<KimiAcpUpdate, String> {
    let kind = value
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .ok_or_else(|| "session-update-kind-missing".to_owned())?
        .to_owned();
    match kind.as_str() {
        "user_message_chunk" => Ok(KimiAcpUpdate::UserMessageChunk {
            text: text_content(&value)?,
        }),
        "agent_thought_chunk" => Ok(KimiAcpUpdate::AgentThoughtChunk {
            text: text_content(&value)?,
        }),
        "agent_message_chunk" => Ok(KimiAcpUpdate::AgentMessageChunk {
            text: text_content(&value)?,
        }),
        "tool_call" | "tool_call_update" => Ok(KimiAcpUpdate::ToolCall {
            tool_call_id: value
                .get("toolCallId")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "tool-call-id-missing".to_owned())?
                .to_owned(),
            title: value
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_owned),
            status: value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
            content: value.get("content").cloned().unwrap_or(Value::Null),
        }),
        "plan" => Ok(KimiAcpUpdate::Plan {
            entries: value.get("entries").cloned().unwrap_or(Value::Null),
        }),
        "available_commands_update" => Ok(KimiAcpUpdate::AvailableCommands {
            commands: value
                .get("availableCommands")
                .cloned()
                .unwrap_or(Value::Null),
        }),
        _ => Ok(KimiAcpUpdate::Unknown { kind, raw: value }),
    }
}

fn text_content(value: &Value) -> Result<String, String> {
    value
        .pointer("/content/text")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "text-content-missing".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agent_message_update_without_losing_session_identity() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"kimi-session-1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}}}"#,
        )
        .expect("parse update");
        assert_eq!(
            message,
            KimiAcpMessage::Notification(KimiAcpNotification::SessionUpdate {
                session_id: "kimi-session-1".to_owned(),
                update: KimiAcpUpdate::AgentMessageChunk {
                    text: "hello".to_owned()
                }
            })
        );
    }

    #[test]
    fn parses_permission_request_as_server_request() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","id":7,"method":"session/request_permission","params":{"sessionId":"s","options":[{"optionId":"allow_once"}]}}"#,
        )
        .expect("parse permission request");
        assert!(matches!(
            message,
            KimiAcpMessage::ServerRequest(KimiAcpServerRequest { method, .. })
                if method == "session/request_permission"
        ));
    }

    #[test]
    fn unknown_session_update_is_preserved_for_fail_closed_policy() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"future_update","value":1}}}"#,
        )
        .expect("parse future update");
        assert!(matches!(
            message,
            KimiAcpMessage::Notification(KimiAcpNotification::SessionUpdate {
                update: KimiAcpUpdate::Unknown { kind, .. },
                ..
            }) if kind == "future_update"
        ));
    }

    #[test]
    fn prompt_and_cancel_requests_use_provider_native_method_names() {
        let prompt = session_prompt_request(3, "s", "hello");
        assert_eq!(prompt["method"], "session/prompt");
        assert_eq!(prompt["params"]["sessionId"], "s");
        assert_eq!(prompt["params"]["prompt"][0]["type"], "text");

        let cancel = session_cancel_request(4, "s");
        assert_eq!(cancel["method"], "session/cancel");
        assert_eq!(cancel["params"]["sessionId"], "s");
    }
}
