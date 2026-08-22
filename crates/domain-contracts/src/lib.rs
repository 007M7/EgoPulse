#![forbid(unsafe_code)]

pub const ARCHITECTURE_VERSION: &str = "1.0";

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
}
