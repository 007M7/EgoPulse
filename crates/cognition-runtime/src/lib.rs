#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;

pub const AUTHORITY_BOUNDARIES: &[&str] = &[
    "task-authority",
    "policy-approval-authority",
    "memory-authority",
    "context-compiler",
    "founder-authority-boundary",
    "verdict-promotion-gate",
    "release-authority",
];

#[must_use]
pub const fn foundation_health() -> FoundationHealth {
    FoundationHealth::foundation_only("cognition-runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_boundaries_are_declared_without_implementation_claims() {
        assert!(AUTHORITY_BOUNDARIES.contains(&"memory-authority"));
        assert_eq!(foundation_health().state.as_str(), "foundation-only");
    }
}
