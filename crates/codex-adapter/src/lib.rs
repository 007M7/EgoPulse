#![forbid(unsafe_code)]

mod approval_display;
mod fake;
mod material;
mod protocol;
mod review;

pub use fake::FakeCodexDriver;
pub use material::FileDispatchMaterialResolver;
pub use protocol::{
    CODEX_ADAPTER_ID, CODEX_APP_SERVER_PROTOCOL, CODEX_APP_SERVER_SCHEMA_SHA256,
    CODEX_APP_SERVER_VERSION, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig,
    CodexAppServerDriver, codex_protocol_fingerprint, codex_user_visible_content_candidate,
    codex_user_visible_content_mutations,
};
pub use review::{
    CodexReadOnlyModelCallReceipt, CodexReadOnlyReviewOutcome, CodexReadOnlyReviewRequest,
    CodexReadOnlyReviewTerminalStatus, CodexReadOnlyReviewUsage, CodexReadOnlyTurnOutcome,
    CodexReadOnlyTurnRequest,
};
