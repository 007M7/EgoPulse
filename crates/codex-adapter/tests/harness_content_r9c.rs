use egopulse_codex_adapter::{
    codex_user_visible_content_candidate, codex_user_visible_content_mutations,
};
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    ContentMutationOperation, user_visible_content_candidate,
};

#[test]
fn r9c_codex_agent_message_is_the_only_text_candidate_source() {
    let candidate =
        codex_user_visible_content_candidate("agentMessage", "msg-safe-001", b"Hello,\r\nworld!\t")
            .expect("explicit agentMessage maps to one candidate");
    assert_eq!(
        candidate.candidate_digest_sha256,
        "97de32300fc9f29a2482e2e46917a1caa2ffd14218ca795847ebb682ea81843f"
    );
    let Some(user_visible_content_candidate::Payload::AssistantText(text)) = candidate.payload
    else {
        panic!("agentMessage must remain typed assistant text")
    };
    assert_eq!(text.message_id, "msg-safe-001");
    assert_eq!(text.operation, ContentMutationOperation::Append as i32);
    assert_eq!(text.text_utf8, b"Hello,\r\nworld!\t");

    for forbidden in [
        "reasoning",
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "toolResult",
        "rawResponse",
    ] {
        assert!(
            codex_user_visible_content_candidate(
                forbidden,
                "sensitive-native-id",
                b"sensitive-native-payload"
            )
            .is_none(),
            "{forbidden} must never become a content candidate"
        );
    }
}

#[test]
fn r9c_codex_large_utf8_message_is_a_lossless_mutation_sequence() {
    let text = format!("{}界{}", "a".repeat(65_535), "b".repeat(65_535));
    let candidates = codex_user_visible_content_mutations(
        "agentMessage",
        "message-large",
        0,
        &[],
        ContentMutationOperation::Append,
        &text,
    )
    .expect("large user-visible text must split instead of disappearing");
    assert_eq!(candidates.len(), 3);
    let mut rebuilt = Vec::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let Some(user_visible_content_candidate::Payload::AssistantText(value)) = candidate.payload
        else {
            panic!("split candidate must remain assistant text")
        };
        assert_eq!(value.revision, index as u64 + 1);
        assert_eq!(value.previous_revision, index as u64);
        assert_eq!(value.operation, ContentMutationOperation::Append as i32);
        assert!(value.text_utf8.len() <= 65_536);
        std::str::from_utf8(&value.text_utf8).expect("each split is valid UTF-8");
        rebuilt.extend_from_slice(&value.text_utf8);
    }
    assert_eq!(rebuilt, text.as_bytes());
}

#[test]
fn r9c_codex_candidate_is_bounded_and_carries_no_route_or_authority_identity() {
    assert!(codex_user_visible_content_candidate("agentMessage", "", b"text").is_none());
    assert!(
        codex_user_visible_content_candidate("agentMessage", "msg", &vec![b'x'; 65_537]).is_none()
    );
    let candidate = codex_user_visible_content_candidate(
        "agentMessage",
        "msg",
        b"provider-canary task-canary proof-canary",
    )
    .expect("bounded assistant message");
    let debug = format!("{candidate:?}");
    assert!(!debug.contains("route_binding"));
    assert!(!debug.contains("authorization_id"));
    assert!(!debug.contains("task_id"));
}
