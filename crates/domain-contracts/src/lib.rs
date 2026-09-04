#![forbid(unsafe_code)]

pub mod context_revoke;
pub mod harness_content;
pub mod memory;
pub mod profiles;

pub const ARCHITECTURE_VERSION: &str = "1.0";

/// Machine-generated V-01 wire contracts. Authority behavior remains in its
/// owning modules; these types do not grant write authority by themselves.
///
/// Prost oneofs mirror the frozen wire shapes and can contain differently sized
/// variants. Keep this lint exception at the generated boundary: changing the
/// generated representation here would create a Rust-only contract profile.
#[allow(clippy::large_enum_variant)]
pub mod v01 {
    pub mod egopulse {
        pub mod common {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.common.v1.rs"
                ));
            }
        }
        pub mod task {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.task.v1.rs"
                ));
            }
        }
        pub mod collaboration {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.collaboration.v1.rs"
                ));
            }
        }
        pub mod harness {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.harness.v1.rs"
                ));
            }
        }
        pub mod artifact {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.artifact.v1.rs"
                ));
            }
        }
        pub mod verification {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.verification.v1.rs"
                ));
            }
        }
        pub mod verdict {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.verdict.v1.rs"
                ));
            }
        }
        pub mod policy {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.policy.v1.rs"
                ));
            }
        }
        pub mod localapi {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.localapi.v1.rs"
                ));
            }
        }
        pub mod persistence {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.persistence.v1.rs"
                ));
            }
        }
        pub mod memory {
            pub mod v1 {
                include!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/generated/egopulse.memory.v1.rs"
                ));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoundationState {
    FoundationOnly,
    Serving,
    Degraded,
}

impl FoundationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FoundationOnly => "foundation-only",
            Self::Serving => "serving",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoundationHealth {
    pub architecture_version: &'static str,
    pub service: &'static str,
    pub state: FoundationState,
}

impl FoundationHealth {
    #[must_use]
    pub const fn foundation_only(service: &'static str) -> Self {
        Self {
            architecture_version: ARCHITECTURE_VERSION,
            service,
            state: FoundationState::FoundationOnly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundation_health_is_explicitly_not_serving() {
        let health = FoundationHealth::foundation_only("agentosd");
        assert_eq!(health.architecture_version, "1.0");
        assert_eq!(health.state, FoundationState::FoundationOnly);
        assert_eq!(health.state.as_str(), "foundation-only");
    }

    #[test]
    fn generated_task_command_round_trips() {
        use crate::v01::egopulse::task::v1::TaskCommand;
        use prost::Message;

        let command = TaskCommand::default();
        let encoded = command.encode_to_vec();
        let decoded = TaskCommand::decode(encoded.as_slice()).expect("generated protobuf decodes");
        assert_eq!(decoded.command, None);
    }
}
