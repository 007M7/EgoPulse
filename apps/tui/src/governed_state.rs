//! Pure safe page model for the governed state session view.
//!
//! The model is built exclusively from the public getters of the shared
//! `client-operations` governed state composite. It holds no projection
//! cursor, no recovery logic and no async; `mark_stopped` is the only
//! mutation and it never touches the extracted facts.

use egopulse_client_operations::{
    GovernedStateComposite, GovernedStateDomain, GovernedStateDomainPhase, GovernedStateReason,
};

/// Which record the page model represents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Initial,
    Update,
}

impl RecordKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Update => "update",
        }
    }
}

/// One domain's phase, recovery budget and its own optional position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainView {
    pub phase: String,
    pub reason: Option<String>,
    pub generation: u64,
    pub recovery_limit: u32,
    pub recovery_remaining: u32,
    pub epoch: Option<String>,
    pub sequence: Option<u64>,
}

/// One safe Task fact in the composite's BTree order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskFactView {
    pub task_id: String,
    pub revision: u64,
    pub status: String,
}

/// One safe Approval fact in the composite's BTree order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalFactView {
    pub approval_request_id: String,
    pub task_id: String,
}

/// The Task domain view: `DomainView` plus its ordered safe facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDomainPage {
    pub view: DomainView,
    pub facts: Vec<TaskFactView>,
}

/// The Approval domain view: `DomainView` plus its ordered safe facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDomainPage {
    pub view: DomainView,
    pub facts: Vec<ApprovalFactView>,
}

/// The complete safe governed state page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedStatePageModel {
    pub kind: RecordKind,
    pub update_index: u64,
    pub changed_domain: Option<GovernedStateDomain>,
    pub task: TaskDomainPage,
    pub approval: ApprovalDomainPage,
    pub stopped: bool,
}

impl GovernedStatePageModel {
    #[must_use]
    pub fn initial(composite: &GovernedStateComposite) -> Self {
        Self {
            kind: RecordKind::Initial,
            update_index: 0,
            changed_domain: None,
            task: task_domain_page(composite.task()),
            approval: approval_domain_page(composite.approval()),
            stopped: false,
        }
    }

    #[must_use]
    pub fn updated(
        update_index: u64,
        domain: GovernedStateDomain,
        composite: &GovernedStateComposite,
    ) -> Self {
        Self {
            kind: RecordKind::Update,
            update_index,
            changed_domain: Some(domain),
            task: task_domain_page(composite.task()),
            approval: approval_domain_page(composite.approval()),
            stopped: false,
        }
    }

    pub fn mark_stopped(&mut self) {
        self.stopped = true;
    }
}

#[must_use]
pub fn phase_label(phase: GovernedStateDomainPhase) -> &'static str {
    match phase {
        GovernedStateDomainPhase::Connecting => "connecting",
        GovernedStateDomainPhase::Live => "live",
        GovernedStateDomainPhase::Stale => "stale",
        GovernedStateDomainPhase::ResetRequired => "reset_required",
        GovernedStateDomainPhase::Fatal => "fatal",
    }
}

#[must_use]
pub fn reason_label(reason: GovernedStateReason) -> &'static str {
    match reason {
        GovernedStateReason::SessionUnavailable => "session_unavailable",
        GovernedStateReason::PermissionDenied => "permission_denied",
        GovernedStateReason::ApiRejected => "api_rejected",
        GovernedStateReason::TransportUnavailable => "transport_unavailable",
        GovernedStateReason::UnexpectedEof => "unexpected_eof",
        GovernedStateReason::ProjectionResetRequired => "projection_reset_required",
        GovernedStateReason::ProjectionIntegrityFailure => "projection_integrity_failure",
        GovernedStateReason::BaselineLimitExceeded => "baseline_limit_exceeded",
        GovernedStateReason::RecoveryExhausted => "recovery_exhausted",
    }
}

#[must_use]
pub const fn domain_label(domain: GovernedStateDomain) -> &'static str {
    match domain {
        GovernedStateDomain::Task => "task",
        GovernedStateDomain::Approval => "approval",
    }
}

fn task_domain_page(state: &egopulse_client_operations::GovernedTaskDomainState) -> TaskDomainPage {
    let position = state.position();
    TaskDomainPage {
        view: DomainView {
            phase: phase_label(state.phase()).to_owned(),
            reason: state.reason().map(|reason| reason_label(reason).to_owned()),
            generation: state.generation(),
            recovery_limit: state.recovery_limit(),
            recovery_remaining: state.recovery_remaining(),
            epoch: position.map(|position| position.epoch().to_owned()),
            sequence: position.map(|position| position.sequence()),
        },
        facts: state
            .tasks()
            .into_iter()
            .map(|task| TaskFactView {
                task_id: task.task_id.clone(),
                revision: task.revision,
                status: task.status.as_str_name().to_ascii_lowercase(),
            })
            .collect(),
    }
}

fn approval_domain_page(
    state: &egopulse_client_operations::GovernedApprovalDomainState,
) -> ApprovalDomainPage {
    let position = state.position();
    ApprovalDomainPage {
        view: DomainView {
            phase: phase_label(state.phase()).to_owned(),
            reason: state.reason().map(|reason| reason_label(reason).to_owned()),
            generation: state.generation(),
            recovery_limit: state.recovery_limit(),
            recovery_remaining: state.recovery_remaining(),
            epoch: position.map(|position| position.epoch().to_owned()),
            sequence: position.map(|position| position.sequence()),
        },
        facts: state
            .approvals()
            .into_iter()
            .map(|approval| ApprovalFactView {
                approval_request_id: approval.approval_request_id().to_owned(),
                task_id: approval.task_id().to_owned(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_labels_are_stable_and_lowercase() {
        assert_eq!(
            phase_label(GovernedStateDomainPhase::Connecting),
            "connecting"
        );
        assert_eq!(phase_label(GovernedStateDomainPhase::Live), "live");
        assert_eq!(phase_label(GovernedStateDomainPhase::Stale), "stale");
        assert_eq!(
            phase_label(GovernedStateDomainPhase::ResetRequired),
            "reset_required"
        );
        assert_eq!(phase_label(GovernedStateDomainPhase::Fatal), "fatal");
    }

    #[test]
    fn reason_labels_are_stable_and_lowercase() {
        assert_eq!(
            reason_label(GovernedStateReason::SessionUnavailable),
            "session_unavailable"
        );
        assert_eq!(
            reason_label(GovernedStateReason::PermissionDenied),
            "permission_denied"
        );
        assert_eq!(
            reason_label(GovernedStateReason::ApiRejected),
            "api_rejected"
        );
        assert_eq!(
            reason_label(GovernedStateReason::TransportUnavailable),
            "transport_unavailable"
        );
        assert_eq!(
            reason_label(GovernedStateReason::UnexpectedEof),
            "unexpected_eof"
        );
        assert_eq!(
            reason_label(GovernedStateReason::ProjectionResetRequired),
            "projection_reset_required"
        );
        assert_eq!(
            reason_label(GovernedStateReason::ProjectionIntegrityFailure),
            "projection_integrity_failure"
        );
        assert_eq!(
            reason_label(GovernedStateReason::BaselineLimitExceeded),
            "baseline_limit_exceeded"
        );
        assert_eq!(
            reason_label(GovernedStateReason::RecoveryExhausted),
            "recovery_exhausted"
        );
    }

    #[test]
    fn domain_and_record_labels_are_stable_and_lowercase() {
        assert_eq!(domain_label(GovernedStateDomain::Task), "task");
        assert_eq!(domain_label(GovernedStateDomain::Approval), "approval");
        assert_eq!(RecordKind::Initial.label(), "initial");
        assert_eq!(RecordKind::Update.label(), "update");
    }

    #[test]
    fn mark_stopped_never_touches_the_extracted_facts() {
        let mut model = GovernedStatePageModel {
            kind: RecordKind::Update,
            update_index: 7,
            changed_domain: Some(GovernedStateDomain::Approval),
            task: TaskDomainPage {
                view: DomainView {
                    phase: "live".to_owned(),
                    reason: None,
                    generation: 3,
                    recovery_limit: 3,
                    recovery_remaining: 1,
                    epoch: Some("task-epoch".to_owned()),
                    sequence: Some(9),
                },
                facts: vec![TaskFactView {
                    task_id: "task:1".to_owned(),
                    revision: 4,
                    status: "task_status_ready".to_owned(),
                }],
            },
            approval: ApprovalDomainPage {
                view: DomainView {
                    phase: "stale".to_owned(),
                    reason: Some("transport_unavailable".to_owned()),
                    generation: 2,
                    recovery_limit: 3,
                    recovery_remaining: 2,
                    epoch: None,
                    sequence: None,
                },
                facts: vec![ApprovalFactView {
                    approval_request_id: "approval:1".to_owned(),
                    task_id: "task:1".to_owned(),
                }],
            },
            stopped: false,
        };
        let before = model.clone();

        model.mark_stopped();

        assert!(model.stopped);
        assert_eq!(model.task, before.task);
        assert_eq!(model.approval, before.approval);
        assert_eq!(model.kind, before.kind);
        assert_eq!(model.update_index, before.update_index);
        assert_eq!(model.changed_domain, before.changed_domain);
    }
}
