#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptBudget {
    pub timeout_seconds: u64,
    pub max_restarts: u8,
}

impl Default for AttemptBudget {
    fn default() -> Self {
        Self {
            timeout_seconds: 30,
            max_restarts: 0,
        }
    }
}

pub async fn foundation_probe() -> FoundationHealth {
    tracing::trace!("running process supervision foundation probe");
    tokio::task::yield_now().await;
    FoundationHealth::foundation_only("process-supervision")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn foundation_probe_is_non_serving() {
        assert_eq!(foundation_probe().await.state.as_str(), "foundation-only");
    }
}
