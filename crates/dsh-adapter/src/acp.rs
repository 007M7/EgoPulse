#![allow(dead_code)]

use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DshAcpMessage {
    Response(DshAcpResponse),
    SessionUpdate {
        session_id: String,
        update: DshAcpUpdate,
    },
    ServerRequest {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DshAcpResponse {
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
pub(crate) enum DshAcpUpdate {
    AgentMessageChunk {
        text: String,
    },
    AgentThoughtChunk {
        text: String,
    },
    ToolCall {
        tool_call_id: String,
        status: String,
    },
    Unknown {
        kind: String,
        raw: Value,
    },
}

pub(crate) fn parse_message(raw: &[u8]) -> Result<DshAcpMessage, String> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "invalid-json".to_owned())?;
    if let Some(error) = value.get("error") {
        return Ok(DshAcpMessage::Response(DshAcpResponse::Error {
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
        return Ok(DshAcpMessage::Response(DshAcpResponse::Result {
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
        return Ok(DshAcpMessage::ServerRequest {
            id: value.get("id").cloned().unwrap_or(Value::Null),
            method,
            params,
        });
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
        return Ok(DshAcpMessage::SessionUpdate {
            session_id,
            update: parse_update(update)?,
        });
    }
    Ok(DshAcpMessage::Notification { method, params })
}

pub(crate) fn initialize_request(client_version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": { "name": "egopulse-dsh-adapter", "version": client_version }
        }
    })
}

pub(crate) fn session_new_request(working_directory: &str, id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "session/new",
        "params": {
            "cwd": working_directory,
            "mcpServers": [],
            "additionalDirectories": []
        }
    })
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

pub(crate) fn session_cancel_request(session_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "session/cancel",
        "params": { "sessionId": session_id }
    })
}

fn parse_update(value: Value) -> Result<DshAcpUpdate, String> {
    let kind = value
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .ok_or_else(|| "session-update-kind-missing".to_owned())?
        .to_owned();
    match kind.as_str() {
        "agent_message_chunk" => Ok(DshAcpUpdate::AgentMessageChunk {
            text: text_content(&value)?,
        }),
        "agent_thought_chunk" => Ok(DshAcpUpdate::AgentThoughtChunk {
            text: text_content(&value)?,
        }),
        "tool_call" | "tool_call_update" => Ok(DshAcpUpdate::ToolCall {
            tool_call_id: value
                .get("toolCallId")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "tool-call-id-missing".to_owned())?
                .to_owned(),
            status: value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        }),
        _ => Ok(DshAcpUpdate::Unknown { kind, raw: value }),
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
    fn parses_dsh_agent_message_update() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"dsh-session-1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}}}"#,
        )
        .expect("parse update");
        assert_eq!(
            message,
            DshAcpMessage::SessionUpdate {
                session_id: "dsh-session-1".to_owned(),
                update: DshAcpUpdate::AgentMessageChunk {
                    text: "hello".to_owned()
                }
            }
        );
    }

    #[test]
    fn preserves_unknown_updates_for_fail_closed_policy() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"future_update","value":1}}}"#,
        )
        .expect("parse update");
        assert!(matches!(
            message,
            DshAcpMessage::SessionUpdate {
                update: DshAcpUpdate::Unknown { kind, .. },
                ..
            } if kind == "future_update"
        ));
    }

    #[test]
    fn parses_native_permission_request_with_opaque_jsonrpc_identity() {
        let message = parse_message(
            br#"{"jsonrpc":"2.0","id":41,"method":"session/request_permission","params":{"sessionId":"s","toolCall":{"toolCallId":"call-1","title":"mock side effect"},"options":[{"optionId":"yes","kind":"allow_once"},{"optionId":"no","kind":"reject_once"}]}}"#,
        )
        .expect("parse permission request");
        assert_eq!(
            message,
            DshAcpMessage::ServerRequest {
                id: serde_json::json!(41),
                method: "session/request_permission".to_owned(),
                params: serde_json::json!({
                    "sessionId": "s",
                    "toolCall": { "toolCallId": "call-1", "title": "mock side effect" },
                    "options": [
                        { "optionId": "yes", "kind": "allow_once" },
                        { "optionId": "no", "kind": "reject_once" }
                    ]
                }),
            }
        );
    }

    #[test]
    fn uses_native_prompt_and_cancel_methods() {
        assert_eq!(
            session_prompt_request(3, "s", "hello")["method"],
            "session/prompt"
        );
        assert_eq!(session_cancel_request("s")["method"], "session/cancel");
        assert!(session_cancel_request("s").get("id").is_none());
    }
}
