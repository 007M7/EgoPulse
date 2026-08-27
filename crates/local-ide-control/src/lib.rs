#![forbid(unsafe_code)]

use egopulse_domain_contracts::FoundationHealth;

pub mod collaboration_control;

pub const CONTROL_BOUNDARIES: &[&str] = &[
    "collaboration-run-planner",
    "capability-harness-registry",
    "policy-router",
    "dispatch-attempt-supervisor",
    "workspace-lease-manager",
    "checkpoint-recovery",
    "handoff-decision-queue",
    "read-model-projector",
];

#[must_use]
pub const fn foundation_health() -> FoundationHealth {
    FoundationHealth::foundation_only("local-ide-control")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collaboration_control_does_not_claim_task_authority() {
        assert!(!CONTROL_BOUNDARIES.contains(&"task-authority"));
        assert_eq!(foundation_health().state.as_str(), "foundation-only");
    }
}
