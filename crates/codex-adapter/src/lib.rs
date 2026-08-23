#![forbid(unsafe_code)]

mod fake;
mod protocol;

pub use fake::FakeCodexDriver;
pub use protocol::{
    CODEX_ADAPTER_ID, CODEX_APP_SERVER_PROTOCOL, CODEX_APP_SERVER_SCHEMA_SHA256,
    CODEX_APP_SERVER_VERSION, CODEX_CAPABILITY_PROFILE_ID, CodexAppServerConfig,
    CodexAppServerDriver, codex_protocol_fingerprint,
};
