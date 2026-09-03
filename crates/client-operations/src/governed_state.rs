use std::{collections::BTreeMap, num::NonZeroU32};

use crate::GovernedTaskState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedStateDomain {
    Task,
    Approval,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedStateDomainPhase {
    Connecting,
    Live,
    Stale,
    ResetRequired,
    Fatal,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedStateReason {
    SessionUnavailable,
    PermissionDenied,
    ApiRejected,
    TransportUnavailable,
    UnexpectedEof,
    ProjectionResetRequired,
    ProjectionIntegrityFailure,
    BaselineLimitExceeded,
    RecoveryExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedRecoverableCause {
    RetryableApiRejected,
    TransportUnavailable,
    UnexpectedEof,
}

impl GovernedRecoverableCause {
    const fn reason(self) -> GovernedStateReason {
        match self {
            Self::RetryableApiRejected => GovernedStateReason::ApiRejected,
            Self::TransportUnavailable => GovernedStateReason::TransportUnavailable,
            Self::UnexpectedEof => GovernedStateReason::UnexpectedEof,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedFatalCause {
    InitialSessionUnavailable,
    PermissionDenied,
    ApiRejected,
    ProjectionIntegrityFailure,
    BaselineLimitExceeded,
}

impl GovernedFatalCause {
    const fn reason(self) -> GovernedStateReason {
        match self {
            Self::InitialSessionUnavailable => GovernedStateReason::SessionUnavailable,
            Self::PermissionDenied => GovernedStateReason::PermissionDenied,
            Self::ApiRejected => GovernedStateReason::ApiRejected,
            Self::ProjectionIntegrityFailure => GovernedStateReason::ProjectionIntegrityFailure,
            Self::BaselineLimitExceeded => GovernedStateReason::BaselineLimitExceeded,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedTaskDomainPosition {
    epoch: String,
    sequence: u64,
}

impl GovernedTaskDomainPosition {
    pub(crate) fn new(epoch: impl Into<String>, sequence: u64) -> Self {
        Self {
            epoch: epoch.into(),
            sequence,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedApprovalDomainPosition {
    epoch: String,
    sequence: u64,
}

impl GovernedApprovalDomainPosition {
    pub(crate) fn new(epoch: impl Into<String>, sequence: u64) -> Self {
        Self {
            epoch: epoch.into(),
            sequence,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedApprovalState {
    approval_request_id: String,
    task_id: String,
}

impl GovernedApprovalState {
    pub(crate) fn new(approval_request_id: impl Into<String>, task_id: impl Into<String>) -> Self {
        Self {
            approval_request_id: approval_request_id.into(),
            task_id: task_id.into(),
        }
    }

    #[must_use]
    pub fn approval_request_id(&self) -> &str {
        &self.approval_request_id
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedTaskDomainState {
    phase: GovernedStateDomainPhase,
    reason: Option<GovernedStateReason>,
    position: Option<GovernedTaskDomainPosition>,
    tasks: BTreeMap<String, GovernedTaskState>,
    generation: u64,
    recovery_limit: u32,
    recovery_remaining: u32,
}

impl GovernedTaskDomainState {
    pub(crate) fn connecting(recovery_limit: NonZeroU32) -> Self {
        let recovery_limit = recovery_limit.get();
        Self {
            phase: GovernedStateDomainPhase::Connecting,
            reason: None,
            position: None,
            tasks: BTreeMap::new(),
            generation: 1,
            recovery_limit,
            recovery_remaining: recovery_limit,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> GovernedStateDomainPhase {
        self.phase
    }
    #[must_use]
    pub const fn reason(&self) -> Option<GovernedStateReason> {
        self.reason
    }
    #[must_use]
    pub const fn position(&self) -> Option<&GovernedTaskDomainPosition> {
        self.position.as_ref()
    }
    #[must_use]
    pub fn tasks(&self) -> Vec<&GovernedTaskState> {
        self.tasks.values().collect()
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn recovery_remaining(&self) -> u32 {
        self.recovery_remaining
    }

    #[must_use]
    pub const fn recovery_limit(&self) -> u32 {
        self.recovery_limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedApprovalDomainState {
    phase: GovernedStateDomainPhase,
    reason: Option<GovernedStateReason>,
    position: Option<GovernedApprovalDomainPosition>,
    approvals: BTreeMap<String, GovernedApprovalState>,
    generation: u64,
    recovery_limit: u32,
    recovery_remaining: u32,
}

impl GovernedApprovalDomainState {
    pub(crate) fn connecting(recovery_limit: NonZeroU32) -> Self {
        let recovery_limit = recovery_limit.get();
        Self {
            phase: GovernedStateDomainPhase::Connecting,
            reason: None,
            position: None,
            approvals: BTreeMap::new(),
            generation: 1,
            recovery_limit,
            recovery_remaining: recovery_limit,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> GovernedStateDomainPhase {
        self.phase
    }
    #[must_use]
    pub const fn reason(&self) -> Option<GovernedStateReason> {
        self.reason
    }
    #[must_use]
    pub const fn position(&self) -> Option<&GovernedApprovalDomainPosition> {
        self.position.as_ref()
    }
    #[must_use]
    pub fn approvals(&self) -> Vec<&GovernedApprovalState> {
        self.approvals.values().collect()
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn recovery_remaining(&self) -> u32 {
        self.recovery_remaining
    }

    #[must_use]
    pub const fn recovery_limit(&self) -> u32 {
        self.recovery_limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedStateComposite {
    task: GovernedTaskDomainState,
    approval: GovernedApprovalDomainState,
}

impl GovernedStateComposite {
    pub(crate) const fn new(
        task: GovernedTaskDomainState,
        approval: GovernedApprovalDomainState,
    ) -> Self {
        Self { task, approval }
    }

    #[must_use]
    pub const fn task(&self) -> &GovernedTaskDomainState {
        &self.task
    }
    #[must_use]
    pub const fn approval(&self) -> &GovernedApprovalDomainState {
        &self.approval
    }

    pub(crate) fn apply_task(&mut self, input: GovernedTaskReducerInput) {
        reduce_task_domain(&mut self.task, input);
    }

    pub(crate) fn apply_approval(&mut self, input: GovernedApprovalReducerInput) {
        reduce_approval_domain(&mut self.approval, input);
    }
}

pub(crate) enum GovernedTaskReducerInput {
    Applied {
        generation: u64,
        position: GovernedTaskDomainPosition,
        task: GovernedTaskState,
    },
    Replay {
        generation: u64,
    },
    Heartbeat {
        generation: u64,
    },
    RecoverableFailure {
        generation: u64,
        cause: GovernedRecoverableCause,
    },
    Reset {
        generation: u64,
    },
    Fatal {
        generation: u64,
        cause: GovernedFatalCause,
    },
    CompleteRebaseline {
        generation: u64,
        position: GovernedTaskDomainPosition,
        tasks: BTreeMap<String, GovernedTaskState>,
    },
    RebaselineFailed {
        generation: u64,
        cause: GovernedFatalCause,
    },
    RebaselineRecoverableFailure {
        generation: u64,
        cause: GovernedRecoverableCause,
    },
    RebaselinePartial {
        generation: u64,
    },
}

pub(crate) enum GovernedApprovalReducerInput {
    Applied {
        generation: u64,
        position: GovernedApprovalDomainPosition,
        approval: GovernedApprovalState,
    },
    Remove {
        generation: u64,
        position: GovernedApprovalDomainPosition,
        approval_request_id: String,
    },
    Replay {
        generation: u64,
    },
    Heartbeat {
        generation: u64,
    },
    RecoverableFailure {
        generation: u64,
        cause: GovernedRecoverableCause,
    },
    Reset {
        generation: u64,
    },
    Fatal {
        generation: u64,
        cause: GovernedFatalCause,
    },
    CompleteRebaseline {
        generation: u64,
        position: GovernedApprovalDomainPosition,
        approvals: BTreeMap<String, GovernedApprovalState>,
    },
    RebaselineFailed {
        generation: u64,
        cause: GovernedFatalCause,
    },
    RebaselineRecoverableFailure {
        generation: u64,
        cause: GovernedRecoverableCause,
    },
    RebaselinePartial {
        generation: u64,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PositionProgress {
    Same,
    Forward,
    Invalid,
}

fn position_progress(
    current_epoch: &str,
    current: u64,
    next_epoch: &str,
    next: u64,
) -> PositionProgress {
    if current_epoch != next_epoch || next < current {
        PositionProgress::Invalid
    } else if next == current {
        PositionProgress::Same
    } else {
        PositionProgress::Forward
    }
}

fn fail_task_integrity(state: &mut GovernedTaskDomainState) {
    state.phase = GovernedStateDomainPhase::Fatal;
    state.reason = Some(GovernedStateReason::ProjectionIntegrityFailure);
}

fn fail_approval_integrity(state: &mut GovernedApprovalDomainState) {
    state.phase = GovernedStateDomainPhase::Fatal;
    state.reason = Some(GovernedStateReason::ProjectionIntegrityFailure);
}

fn reduce_task_domain(state: &mut GovernedTaskDomainState, input: GovernedTaskReducerInput) {
    if state.phase == GovernedStateDomainPhase::Fatal {
        return;
    }
    let generation = match &input {
        GovernedTaskReducerInput::Applied { generation, .. }
        | GovernedTaskReducerInput::Replay { generation }
        | GovernedTaskReducerInput::Heartbeat { generation }
        | GovernedTaskReducerInput::RecoverableFailure { generation, .. }
        | GovernedTaskReducerInput::Reset { generation }
        | GovernedTaskReducerInput::Fatal { generation, .. }
        | GovernedTaskReducerInput::CompleteRebaseline { generation, .. }
        | GovernedTaskReducerInput::RebaselineFailed { generation, .. }
        | GovernedTaskReducerInput::RebaselineRecoverableFailure { generation, .. }
        | GovernedTaskReducerInput::RebaselinePartial { generation } => *generation,
    };
    if generation != state.generation {
        return;
    }
    if state.phase == GovernedStateDomainPhase::ResetRequired
        && !matches!(
            &input,
            GovernedTaskReducerInput::CompleteRebaseline { .. }
                | GovernedTaskReducerInput::RebaselineFailed { .. }
                | GovernedTaskReducerInput::RebaselineRecoverableFailure { .. }
                | GovernedTaskReducerInput::RebaselinePartial { .. }
                | GovernedTaskReducerInput::Fatal { .. }
        )
    {
        return;
    }
    match input {
        GovernedTaskReducerInput::Applied { position, task, .. } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Live | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(current) = state.position.as_ref() else {
                fail_task_integrity(state);
                return;
            };
            match position_progress(
                &current.epoch,
                current.sequence,
                &position.epoch,
                position.sequence,
            ) {
                PositionProgress::Same => return,
                PositionProgress::Invalid => {
                    fail_task_integrity(state);
                    return;
                }
                PositionProgress::Forward => {}
            }
            state.tasks.insert(task.task_id.clone(), task);
            state.position = Some(position);
            state.phase = GovernedStateDomainPhase::Live;
            state.reason = None;
            state.recovery_remaining = state.recovery_limit;
        }
        GovernedTaskReducerInput::Replay { .. } | GovernedTaskReducerInput::Heartbeat { .. } => {}
        GovernedTaskReducerInput::RecoverableFailure { cause, .. } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Live
                    | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(generation) = state.generation.checked_add(1) else {
                fail_task_integrity(state);
                return;
            };
            state.generation = generation;
            state.recovery_remaining = state.recovery_remaining.saturating_sub(1);
            if state.recovery_remaining == 0 {
                state.phase = GovernedStateDomainPhase::Fatal;
                state.reason = Some(GovernedStateReason::RecoveryExhausted);
            } else {
                state.phase = GovernedStateDomainPhase::Stale;
                state.reason = Some(cause.reason());
            }
        }
        GovernedTaskReducerInput::Reset { .. } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Live
                    | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(generation) = state.generation.checked_add(1) else {
                fail_task_integrity(state);
                return;
            };
            state.generation = generation;
            state.phase = GovernedStateDomainPhase::ResetRequired;
            state.reason = Some(GovernedStateReason::ProjectionResetRequired);
        }
        GovernedTaskReducerInput::Fatal { cause, .. } => {
            state.phase = GovernedStateDomainPhase::Fatal;
            state.reason = Some(cause.reason());
        }
        GovernedTaskReducerInput::CompleteRebaseline {
            position, tasks, ..
        } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                return;
            }
            state.tasks = tasks;
            state.position = Some(position);
            state.phase = GovernedStateDomainPhase::Live;
            state.reason = None;
        }
        GovernedTaskReducerInput::RebaselineFailed { cause, .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                state.phase = GovernedStateDomainPhase::Fatal;
                state.reason = Some(cause.reason());
            }
        }
        GovernedTaskReducerInput::RebaselineRecoverableFailure { cause, .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Stale | GovernedStateDomainPhase::ResetRequired
            ) {
                let Some(generation) = state.generation.checked_add(1) else {
                    fail_task_integrity(state);
                    return;
                };
                state.generation = generation;
                state.recovery_remaining = state.recovery_remaining.saturating_sub(1);
                if state.recovery_remaining == 0 {
                    state.phase = GovernedStateDomainPhase::Fatal;
                    state.reason = Some(GovernedStateReason::RecoveryExhausted);
                } else {
                    state.reason = Some(cause.reason());
                }
            }
        }
        GovernedTaskReducerInput::RebaselinePartial { .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                fail_task_integrity(state);
            }
        }
    }
}

fn reduce_approval_domain(
    state: &mut GovernedApprovalDomainState,
    input: GovernedApprovalReducerInput,
) {
    if state.phase == GovernedStateDomainPhase::Fatal {
        return;
    }
    let generation = match &input {
        GovernedApprovalReducerInput::Applied { generation, .. }
        | GovernedApprovalReducerInput::Remove { generation, .. }
        | GovernedApprovalReducerInput::Replay { generation }
        | GovernedApprovalReducerInput::Heartbeat { generation }
        | GovernedApprovalReducerInput::RecoverableFailure { generation, .. }
        | GovernedApprovalReducerInput::Reset { generation }
        | GovernedApprovalReducerInput::Fatal { generation, .. }
        | GovernedApprovalReducerInput::CompleteRebaseline { generation, .. }
        | GovernedApprovalReducerInput::RebaselineFailed { generation, .. }
        | GovernedApprovalReducerInput::RebaselineRecoverableFailure { generation, .. }
        | GovernedApprovalReducerInput::RebaselinePartial { generation } => *generation,
    };
    if generation != state.generation {
        return;
    }
    if state.phase == GovernedStateDomainPhase::ResetRequired
        && !matches!(
            &input,
            GovernedApprovalReducerInput::CompleteRebaseline { .. }
                | GovernedApprovalReducerInput::RebaselineFailed { .. }
                | GovernedApprovalReducerInput::RebaselineRecoverableFailure { .. }
                | GovernedApprovalReducerInput::RebaselinePartial { .. }
                | GovernedApprovalReducerInput::Fatal { .. }
        )
    {
        return;
    }
    match input {
        GovernedApprovalReducerInput::Applied {
            position, approval, ..
        } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Live | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(current) = state.position.as_ref() else {
                fail_approval_integrity(state);
                return;
            };
            match position_progress(
                &current.epoch,
                current.sequence,
                &position.epoch,
                position.sequence,
            ) {
                PositionProgress::Same => return,
                PositionProgress::Invalid => {
                    fail_approval_integrity(state);
                    return;
                }
                PositionProgress::Forward => {}
            }
            state
                .approvals
                .insert(approval.approval_request_id.clone(), approval);
            state.position = Some(position);
            state.phase = GovernedStateDomainPhase::Live;
            state.reason = None;
            state.recovery_remaining = state.recovery_limit;
        }
        GovernedApprovalReducerInput::Remove {
            position,
            approval_request_id,
            ..
        } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Live | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(current) = state.position.as_ref() else {
                fail_approval_integrity(state);
                return;
            };
            match position_progress(
                &current.epoch,
                current.sequence,
                &position.epoch,
                position.sequence,
            ) {
                PositionProgress::Same => return,
                PositionProgress::Invalid => {
                    fail_approval_integrity(state);
                    return;
                }
                PositionProgress::Forward => {}
            }
            state.approvals.remove(&approval_request_id);
            state.position = Some(position);
            state.phase = GovernedStateDomainPhase::Live;
            state.reason = None;
            state.recovery_remaining = state.recovery_limit;
        }
        GovernedApprovalReducerInput::Replay { .. }
        | GovernedApprovalReducerInput::Heartbeat { .. } => {}
        GovernedApprovalReducerInput::RecoverableFailure { cause, .. } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Live
                    | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(generation) = state.generation.checked_add(1) else {
                fail_approval_integrity(state);
                return;
            };
            state.generation = generation;
            state.recovery_remaining = state.recovery_remaining.saturating_sub(1);
            if state.recovery_remaining == 0 {
                state.phase = GovernedStateDomainPhase::Fatal;
                state.reason = Some(GovernedStateReason::RecoveryExhausted);
            } else {
                state.phase = GovernedStateDomainPhase::Stale;
                state.reason = Some(cause.reason());
            }
        }
        GovernedApprovalReducerInput::Reset { .. } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Live
                    | GovernedStateDomainPhase::Stale
            ) {
                return;
            }
            let Some(generation) = state.generation.checked_add(1) else {
                fail_approval_integrity(state);
                return;
            };
            state.generation = generation;
            state.phase = GovernedStateDomainPhase::ResetRequired;
            state.reason = Some(GovernedStateReason::ProjectionResetRequired);
        }
        GovernedApprovalReducerInput::Fatal { cause, .. } => {
            state.phase = GovernedStateDomainPhase::Fatal;
            state.reason = Some(cause.reason());
        }
        GovernedApprovalReducerInput::CompleteRebaseline {
            position,
            approvals,
            ..
        } => {
            if !matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                return;
            }
            state.approvals = approvals;
            state.position = Some(position);
            state.phase = GovernedStateDomainPhase::Live;
            state.reason = None;
        }
        GovernedApprovalReducerInput::RebaselineFailed { cause, .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                state.phase = GovernedStateDomainPhase::Fatal;
                state.reason = Some(cause.reason());
            }
        }
        GovernedApprovalReducerInput::RebaselineRecoverableFailure { cause, .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Stale | GovernedStateDomainPhase::ResetRequired
            ) {
                let Some(generation) = state.generation.checked_add(1) else {
                    fail_approval_integrity(state);
                    return;
                };
                state.generation = generation;
                state.recovery_remaining = state.recovery_remaining.saturating_sub(1);
                if state.recovery_remaining == 0 {
                    state.phase = GovernedStateDomainPhase::Fatal;
                    state.reason = Some(GovernedStateReason::RecoveryExhausted);
                } else {
                    state.reason = Some(cause.reason());
                }
            }
        }
        GovernedApprovalReducerInput::RebaselinePartial { .. } => {
            if matches!(
                state.phase,
                GovernedStateDomainPhase::Connecting
                    | GovernedStateDomainPhase::Stale
                    | GovernedStateDomainPhase::ResetRequired
            ) {
                fail_approval_integrity(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_composite(task_budget: u32, approval_budget: u32) -> GovernedStateComposite {
        let mut composite = GovernedStateComposite::new(
            GovernedTaskDomainState::connecting(NonZeroU32::new(task_budget).unwrap()),
            GovernedApprovalDomainState::connecting(NonZeroU32::new(approval_budget).unwrap()),
        );
        composite.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 1),
            tasks: BTreeMap::new(),
        });
        let mut approvals = BTreeMap::new();
        approvals.insert(
            "approval:1".to_owned(),
            GovernedApprovalState::new("approval:1", "task:1"),
        );
        composite.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approvals,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        composite
    }

    #[test]
    fn initial_single_domain_fatal_allows_other_live_symmetrically() {
        let mut approvals = BTreeMap::new();
        approvals.insert(
            "approval:1".to_owned(),
            GovernedApprovalState::new("approval:1", "task:1"),
        );

        // Task domain hits an initial fatal while the approval domain reaches Live.
        let mut composite = GovernedStateComposite::new(
            GovernedTaskDomainState::connecting(NonZeroU32::new(2).unwrap()),
            GovernedApprovalDomainState::connecting(NonZeroU32::new(2).unwrap()),
        );
        composite.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approvals: approvals.clone(),
        });
        composite.apply_task(GovernedTaskReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::InitialSessionUnavailable,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::SessionUnavailable)
        );
        assert_eq!(composite.task().position(), None);
        assert!(composite.task().tasks().is_empty());
        // The fatal domain is terminal: even a valid rebaseline is ignored.
        composite.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 1),
            tasks: BTreeMap::new(),
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        // The other domain stays fully live and keeps advancing independently.
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().reason(), None);
        assert_eq!(composite.approval().generation(), 1);
        assert_eq!(
            composite.approval().position(),
            Some(&GovernedApprovalDomainPosition::new("approval-epoch", 1))
        );
        assert_eq!(composite.approval().approvals().len(), 1);
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approval: GovernedApprovalState::new("approval:2", "task:2"),
        });
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().approvals().len(), 2);
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);

        // Symmetric: approval domain hits the initial fatal, task domain reaches Live.
        let mut mirrored = GovernedStateComposite::new(
            GovernedTaskDomainState::connecting(NonZeroU32::new(2).unwrap()),
            GovernedApprovalDomainState::connecting(NonZeroU32::new(2).unwrap()),
        );
        mirrored.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 1),
            tasks: BTreeMap::new(),
        });
        mirrored.apply_approval(GovernedApprovalReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::PermissionDenied,
        });
        assert_eq!(mirrored.approval().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            mirrored.approval().reason(),
            Some(GovernedStateReason::PermissionDenied)
        );
        assert_eq!(mirrored.approval().position(), None);
        assert_eq!(mirrored.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(mirrored.task().reason(), None);
        assert_eq!(
            mirrored.task().position(),
            Some(&GovernedTaskDomainPosition::new("task-epoch", 1))
        );
        // The live task domain keeps consuming its own lifecycle events.
        mirrored.apply_task(GovernedTaskReducerInput::Heartbeat { generation: 1 });
        assert_eq!(mirrored.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(mirrored.task().generation(), 1);
        assert_eq!(mirrored.approval().phase(), GovernedStateDomainPhase::Fatal);
    }

    fn sample_task() -> GovernedTaskState {
        GovernedTaskState {
            task_id: "task:1".to_owned(),
            revision: 1,
            status: crate::DomainTaskStatus::Ready,
            resume_status: None,
            hold_reason: None,
            projection: crate::GovernedProjectionState {
                position: crate::GovernedProjectionPosition {
                    epoch: "task-epoch".to_owned(),
                    sequence: 2,
                },
                health: crate::ProjectionHealth::Ready,
                stale: false,
                reason: None,
            },
            run: None,
        }
    }

    #[test]
    fn every_task_input_preserves_entire_approval() {
        // Applied (forward progress).
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Applied {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 2),
            task: sample_task(),
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.task().tasks().len(), 1);
        assert_eq!(composite.approval(), &approval_before);

        // Applied at the same position is a no-op.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Applied {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 1),
            task: sample_task(),
        });
        assert_eq!(composite.task().tasks().len(), 0);
        assert_eq!(composite.approval(), &approval_before);

        // Replay never changes facts.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Replay { generation: 1 });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.task().tasks().len(), 0);
        assert_eq!(composite.approval(), &approval_before);

        // Heartbeat never changes facts.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Heartbeat { generation: 1 });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.task().tasks().len(), 0);
        assert_eq!(composite.approval(), &approval_before);

        // Recoverable failure transitions the task domain only.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Stale);
        assert_eq!(composite.task().generation(), 2);
        assert_eq!(composite.task().recovery_remaining(), 1);
        assert_eq!(composite.approval(), &approval_before);

        // Reset requires a rebaseline in the task domain only.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        assert_eq!(
            composite.task().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(composite.approval(), &approval_before);

        // A complete rebaseline restores the task domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let approval_before = composite.approval().clone();
        let mut tasks = BTreeMap::new();
        tasks.insert("task:1".to_owned(), sample_task());
        composite.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 2,
            position: GovernedTaskDomainPosition::new("task-epoch:2", 1),
            tasks,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.task().tasks().len(), 1);
        assert_eq!(composite.approval(), &approval_before);

        // A failed rebaseline is fatal in the task domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::RebaselineFailed {
            generation: 2,
            cause: GovernedFatalCause::ApiRejected,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::ApiRejected)
        );
        assert_eq!(composite.approval(), &approval_before);

        // A recoverable rebaseline failure keeps the task barrier without recovery refill.
        let mut composite = live_composite(2, 2);
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        assert_eq!(
            composite.task().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::UnexpectedEof)
        );
        assert_eq!(composite.task().generation(), 3);
        assert_eq!(composite.task().recovery_remaining(), 1);
        assert_eq!(composite.approval(), &approval_before);

        // A partial rebaseline is an integrity failure in the task domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::RebaselinePartial { generation: 2 });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(composite.approval(), &approval_before);

        // A direct fatal is terminal in the task domain only.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::BaselineLimitExceeded,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::BaselineLimitExceeded)
        );
        assert_eq!(composite.approval(), &approval_before);

        // A stale generation is fenced off in the task domain only.
        let mut composite = live_composite(2, 2);
        let approval_before = composite.approval().clone();
        composite.apply_task(GovernedTaskReducerInput::Applied {
            generation: 99,
            position: GovernedTaskDomainPosition::new("task-epoch", 9),
            task: sample_task(),
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.task().tasks().len(), 0);
        assert_eq!(composite.approval(), &approval_before);
    }

    #[test]
    fn every_approval_input_preserves_entire_task() {
        // Applied adds an approval fact.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approval: GovernedApprovalState::new("approval:2", "task:2"),
        });
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().approvals().len(), 2);
        assert_eq!(composite.task(), &task_before);

        // Remove drops an approval fact without touching the task domain.
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approval: GovernedApprovalState::new("approval:2", "task:2"),
        });
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Remove {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 3),
            approval_request_id: "approval:2".to_owned(),
        });
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.approval().position().unwrap().sequence(), 3);
        assert_eq!(composite.task(), &task_before);

        // Applied at the same position is a no-op.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approval: GovernedApprovalState::new("approval:dup", "task:dup"),
        });
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.task(), &task_before);

        // Remove at the same position is a no-op.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Remove {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approval_request_id: "approval:1".to_owned(),
        });
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.task(), &task_before);

        // Replay never changes facts.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Replay { generation: 1 });
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.task(), &task_before);

        // Heartbeat never changes facts.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Heartbeat { generation: 1 });
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.task(), &task_before);

        // Recoverable failure transitions the approval domain only.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(composite.approval().generation(), 2);
        assert_eq!(composite.approval().recovery_remaining(), 1);
        assert_eq!(composite.task(), &task_before);

        // Reset requires a rebaseline in the approval domain only.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(composite.task(), &task_before);

        // A complete rebaseline restores the approval domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let task_before = composite.task().clone();
        let mut approvals = BTreeMap::new();
        approvals.insert(
            "approval:next".to_owned(),
            GovernedApprovalState::new("approval:next", "task:next"),
        );
        composite.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 2,
            position: GovernedApprovalDomainPosition::new("approval-epoch:2", 1),
            approvals,
        });
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(
            composite.approval().approvals()[0].approval_request_id(),
            "approval:next"
        );
        assert_eq!(composite.task(), &task_before);

        // A failed rebaseline is fatal in the approval domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::RebaselineFailed {
            generation: 2,
            cause: GovernedFatalCause::ProjectionIntegrityFailure,
        });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(composite.task(), &task_before);

        // A recoverable rebaseline failure keeps the approval barrier without refill.
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::TransportUnavailable)
        );
        assert_eq!(composite.approval().generation(), 3);
        assert_eq!(composite.approval().recovery_remaining(), 1);
        assert_eq!(composite.task(), &task_before);

        // A partial rebaseline is an integrity failure in the approval domain only.
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::RebaselinePartial { generation: 2 });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(composite.task(), &task_before);

        // A direct fatal is terminal in the approval domain only.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::InitialSessionUnavailable,
        });
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::SessionUnavailable)
        );
        assert_eq!(composite.task(), &task_before);

        // A stale generation is fenced off in the approval domain only.
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 99,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 9),
            approval: GovernedApprovalState::new("approval:stale", "task:stale"),
        });
        assert_eq!(composite.approval().approvals().len(), 1);
        assert_eq!(composite.task(), &task_before);
    }

    #[test]
    fn governed_state_approval_update_advances_only_approval_domain() {
        let mut composite = live_composite(2, 2);
        let task_before = composite.task().clone();

        composite.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(composite.approval().generation(), 2);
        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(composite.approval().recovery_remaining(), 1);

        let stale_before_same_position = composite.approval().clone();
        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 2,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approval: GovernedApprovalState::new("approval:same", "task:same"),
        });
        assert_eq!(composite.approval(), &stale_before_same_position);

        composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 2,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approval: GovernedApprovalState::new("approval:2", "task:2"),
        });

        assert_eq!(composite.task(), &task_before);
        assert_eq!(composite.approval().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(composite.approval().position().unwrap().sequence(), 2);
        assert_eq!(composite.approval().approvals().len(), 2);
        assert_eq!(
            composite.approval().recovery_remaining(),
            composite.approval().recovery_limit()
        );
    }

    #[test]
    fn governed_state_task_failure_and_generation_fence_leave_approval_unchanged() {
        let mut composite = live_composite(1, 2);
        let approval_before = composite.approval().clone();

        composite.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            composite.task().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(composite.approval(), &approval_before);

        let task_before_stale_event = composite.task().clone();
        composite.apply_task(GovernedTaskReducerInput::Reset { generation: 0 });
        assert_eq!(composite.task(), &task_before_stale_event);
        assert_eq!(composite.approval(), &approval_before);

        let mut reset = live_composite(2, 2);
        let reset_approval_before = reset.approval().clone();
        reset.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        assert_eq!(reset.task().generation(), 2);
        assert_eq!(
            reset.task().phase(),
            GovernedStateDomainPhase::ResetRequired
        );

        let reset_before_old_generation = reset.task().clone();
        reset.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch:2", 1),
            tasks: BTreeMap::new(),
        });
        assert_eq!(reset.task(), &reset_before_old_generation);

        reset.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 2,
            position: GovernedTaskDomainPosition::new("task-epoch:2", 1),
            tasks: BTreeMap::new(),
        });
        assert_eq!(reset.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(reset.task().generation(), 2);
        assert_eq!(reset.task().recovery_remaining(), 2);
        assert_eq!(reset.approval(), &reset_approval_before);
    }

    #[test]
    fn governed_state_partial_rebaseline_preserves_last_good_and_other_domain() {
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        let target_before = composite.approval().clone();
        let task_before = composite.task().clone();

        composite.apply_approval(GovernedApprovalReducerInput::RebaselinePartial { generation: 2 });

        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(composite.approval().position(), target_before.position());
        assert_eq!(composite.approval().approvals(), target_before.approvals());
        assert_eq!(
            composite.approval().generation(),
            target_before.generation()
        );
        assert_eq!(
            composite.approval().recovery_remaining(),
            target_before.recovery_remaining()
        );
        assert_eq!(
            composite.approval().recovery_limit(),
            target_before.recovery_limit()
        );
        assert_eq!(composite.task(), &task_before);
    }

    #[test]
    fn governed_state_reset_rebaseline_retry_fences_and_preserves_last_good() {
        let mut composite = live_composite(2, 2);
        composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let reset_facts = composite
            .approval()
            .approvals()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let reset_position = composite.approval().position().cloned();
        let task_before = composite.task().clone();

        composite.apply_approval(GovernedApprovalReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });

        assert_eq!(
            composite.approval().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            composite.approval().reason(),
            Some(GovernedStateReason::UnexpectedEof)
        );
        assert_eq!(composite.approval().generation(), 3);
        assert_eq!(composite.approval().recovery_remaining(), 1);
        assert_eq!(composite.approval().recovery_limit(), 2);
        assert_eq!(composite.approval().position(), reset_position.as_ref());
        assert_eq!(
            composite
                .approval()
                .approvals()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>(),
            reset_facts
        );
        assert_eq!(composite.task(), &task_before);
    }

    #[test]
    fn r9b1_symmetric_failure_matrix_and_budget_isolated() {
        fn fatal_case(index: usize) -> (GovernedFatalCause, GovernedStateReason) {
            match index {
                0 => (
                    GovernedFatalCause::InitialSessionUnavailable,
                    GovernedStateReason::SessionUnavailable,
                ),
                1 => (
                    GovernedFatalCause::PermissionDenied,
                    GovernedStateReason::PermissionDenied,
                ),
                2 => (
                    GovernedFatalCause::ApiRejected,
                    GovernedStateReason::ApiRejected,
                ),
                3 => (
                    GovernedFatalCause::ProjectionIntegrityFailure,
                    GovernedStateReason::ProjectionIntegrityFailure,
                ),
                4 => (
                    GovernedFatalCause::BaselineLimitExceeded,
                    GovernedStateReason::BaselineLimitExceeded,
                ),
                _ => unreachable!("fatal case index is bounded by the test matrix"),
            }
        }

        for index in 0..5 {
            let (cause, expected_reason) = fatal_case(index);
            let mut composite = live_composite(2, 2);
            let approval_before = composite.approval().clone();
            composite.apply_task(GovernedTaskReducerInput::Fatal {
                generation: 1,
                cause,
            });
            assert_eq!(composite.task().phase(), GovernedStateDomainPhase::Fatal);
            assert_eq!(composite.task().reason(), Some(expected_reason));
            assert_eq!(composite.approval(), &approval_before);

            let (cause, expected_reason) = fatal_case(index);
            let mut composite = live_composite(2, 2);
            let task_before = composite.task().clone();
            composite.apply_approval(GovernedApprovalReducerInput::Fatal {
                generation: 1,
                cause,
            });
            assert_eq!(
                composite.approval().phase(),
                GovernedStateDomainPhase::Fatal
            );
            assert_eq!(composite.approval().reason(), Some(expected_reason));
            assert_eq!(composite.task(), &task_before);
        }

        let mut task_retryable_api = live_composite(2, 2);
        let approval_before = task_retryable_api.approval().clone();
        task_retryable_api.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::RetryableApiRejected,
        });
        assert_eq!(
            task_retryable_api.task().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(
            task_retryable_api.task().reason(),
            Some(GovernedStateReason::ApiRejected)
        );
        assert_eq!(task_retryable_api.task().generation(), 2);
        assert_eq!(task_retryable_api.task().recovery_remaining(), 1);
        assert_eq!(task_retryable_api.approval(), &approval_before);

        let mut approval_retryable_api = live_composite(2, 2);
        let task_before = approval_retryable_api.task().clone();
        approval_retryable_api.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::RetryableApiRejected,
        });
        assert_eq!(
            approval_retryable_api.approval().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(
            approval_retryable_api.approval().reason(),
            Some(GovernedStateReason::ApiRejected)
        );
        assert_eq!(approval_retryable_api.approval().generation(), 2);
        assert_eq!(approval_retryable_api.approval().recovery_remaining(), 1);
        assert_eq!(approval_retryable_api.task(), &task_before);

        let mut task_exhausted = live_composite(1, 2);
        let approval_before = task_exhausted.approval().clone();
        task_exhausted.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            task_exhausted.task().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            task_exhausted.task().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(task_exhausted.task().generation(), 2);
        assert_eq!(task_exhausted.task().recovery_remaining(), 0);
        assert_eq!(task_exhausted.approval(), &approval_before);

        let mut approval_exhausted = live_composite(2, 1);
        let task_before = approval_exhausted.task().clone();
        approval_exhausted.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        assert_eq!(
            approval_exhausted.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            approval_exhausted.approval().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(approval_exhausted.approval().generation(), 2);
        assert_eq!(approval_exhausted.approval().recovery_remaining(), 0);
        assert_eq!(approval_exhausted.task(), &task_before);

        let mut task_reset = live_composite(2, 2);
        let approval_before = task_reset.approval().clone();
        task_reset.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        assert_eq!(
            task_reset.task().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            task_reset.task().reason(),
            Some(GovernedStateReason::ProjectionResetRequired)
        );
        assert_eq!(task_reset.task().generation(), 2);
        assert_eq!(task_reset.task().recovery_remaining(), 2);
        assert_eq!(task_reset.approval(), &approval_before);

        let mut approval_reset = live_composite(2, 2);
        let task_before = approval_reset.task().clone();
        approval_reset.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        assert_eq!(
            approval_reset.approval().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            approval_reset.approval().reason(),
            Some(GovernedStateReason::ProjectionResetRequired)
        );
        assert_eq!(approval_reset.approval().generation(), 2);
        assert_eq!(approval_reset.approval().recovery_remaining(), 2);
        assert_eq!(approval_reset.task(), &task_before);

        let mut task_retry = live_composite(2, 2);
        task_retry.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let task_facts_before = task_retry.task().clone();
        let approval_before = task_retry.approval().clone();
        task_retry.apply_task(GovernedTaskReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        assert_eq!(
            task_retry.task().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            task_retry.task().reason(),
            Some(GovernedStateReason::UnexpectedEof)
        );
        assert_eq!(task_retry.task().generation(), 3);
        assert_eq!(task_retry.task().recovery_remaining(), 1);
        assert_eq!(task_retry.task().position(), task_facts_before.position());
        assert_eq!(task_retry.task().tasks(), task_facts_before.tasks());
        assert_eq!(task_retry.task().recovery_limit(), 2);
        assert_eq!(task_retry.approval(), &approval_before);

        let mut approval_retry = live_composite(2, 2);
        approval_retry.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let approval_facts_before = approval_retry.approval().clone();
        let task_before = approval_retry.task().clone();
        approval_retry.apply_approval(GovernedApprovalReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            approval_retry.approval().phase(),
            GovernedStateDomainPhase::ResetRequired
        );
        assert_eq!(
            approval_retry.approval().reason(),
            Some(GovernedStateReason::TransportUnavailable)
        );
        assert_eq!(approval_retry.approval().generation(), 3);
        assert_eq!(approval_retry.approval().recovery_remaining(), 1);
        assert_eq!(
            approval_retry.approval().position(),
            approval_facts_before.position()
        );
        assert_eq!(
            approval_retry.approval().approvals(),
            approval_facts_before.approvals()
        );
        assert_eq!(approval_retry.approval().recovery_limit(), 2);
        assert_eq!(approval_retry.task(), &task_before);

        let mut task_retry_exhausted = live_composite(1, 2);
        task_retry_exhausted.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        let approval_before = task_retry_exhausted.approval().clone();
        task_retry_exhausted.apply_task(GovernedTaskReducerInput::RebaselineRecoverableFailure {
            generation: 2,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            task_retry_exhausted.task().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            task_retry_exhausted.task().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(task_retry_exhausted.task().generation(), 3);
        assert_eq!(task_retry_exhausted.task().recovery_remaining(), 0);
        assert_eq!(task_retry_exhausted.approval(), &approval_before);

        let mut approval_retry_exhausted = live_composite(2, 1);
        approval_retry_exhausted
            .apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        let task_before = approval_retry_exhausted.task().clone();
        approval_retry_exhausted.apply_approval(
            GovernedApprovalReducerInput::RebaselineRecoverableFailure {
                generation: 2,
                cause: GovernedRecoverableCause::UnexpectedEof,
            },
        );
        assert_eq!(
            approval_retry_exhausted.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            approval_retry_exhausted.approval().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(approval_retry_exhausted.approval().generation(), 3);
        assert_eq!(approval_retry_exhausted.approval().recovery_remaining(), 0);
        assert_eq!(approval_retry_exhausted.task(), &task_before);
    }

    #[test]
    fn r9b1_replay_heartbeat_same_position_and_stale_generation_never_publish_or_refill() {
        let mut task_composite = live_composite(2, 2);
        let task_live = task_composite.task().clone();
        let approval_live = task_composite.approval().clone();

        task_composite.apply_task(GovernedTaskReducerInput::Replay { generation: 1 });
        assert_eq!(task_composite.task(), &task_live);
        assert_eq!(task_composite.approval(), &approval_live);
        task_composite.apply_task(GovernedTaskReducerInput::Heartbeat { generation: 1 });
        assert_eq!(task_composite.task(), &task_live);
        assert_eq!(task_composite.approval(), &approval_live);
        task_composite.apply_task(GovernedTaskReducerInput::Applied {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 1),
            task: sample_task(),
        });
        assert_eq!(task_composite.task(), &task_live);
        assert_eq!(task_composite.approval(), &approval_live);

        task_composite.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        assert_eq!(
            task_composite.task().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(task_composite.task().generation(), 2);
        assert_eq!(task_composite.task().recovery_remaining(), 1);
        let task_stale = task_composite.task().clone();
        let approval_before_stale_inputs = task_composite.approval().clone();

        task_composite.apply_task(GovernedTaskReducerInput::Applied {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 2),
            task: sample_task(),
        });
        assert_eq!(task_composite.task(), &task_stale);
        assert_eq!(task_composite.approval(), &approval_before_stale_inputs);
        task_composite.apply_task(GovernedTaskReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::PermissionDenied,
        });
        assert_eq!(task_composite.task(), &task_stale);
        assert_eq!(task_composite.approval(), &approval_before_stale_inputs);
        task_composite.apply_task(GovernedTaskReducerInput::Reset { generation: 1 });
        assert_eq!(task_composite.task(), &task_stale);
        assert_eq!(task_composite.approval(), &approval_before_stale_inputs);
        task_composite.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch:stale", 1),
            tasks: BTreeMap::new(),
        });
        assert_eq!(task_composite.task(), &task_stale);
        assert_eq!(task_composite.approval(), &approval_before_stale_inputs);

        let mut approval_composite = live_composite(2, 2);
        let approval_live = approval_composite.approval().clone();
        let task_live = approval_composite.task().clone();

        approval_composite.apply_approval(GovernedApprovalReducerInput::Replay { generation: 1 });
        assert_eq!(approval_composite.approval(), &approval_live);
        assert_eq!(approval_composite.task(), &task_live);
        approval_composite
            .apply_approval(GovernedApprovalReducerInput::Heartbeat { generation: 1 });
        assert_eq!(approval_composite.approval(), &approval_live);
        assert_eq!(approval_composite.task(), &task_live);
        approval_composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approval: GovernedApprovalState::new("approval:same", "task:same"),
        });
        assert_eq!(approval_composite.approval(), &approval_live);
        assert_eq!(approval_composite.task(), &task_live);
        approval_composite.apply_approval(GovernedApprovalReducerInput::Remove {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 1),
            approval_request_id: "approval:1".to_owned(),
        });
        assert_eq!(approval_composite.approval(), &approval_live);
        assert_eq!(approval_composite.task(), &task_live);

        approval_composite.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        assert_eq!(
            approval_composite.approval().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(approval_composite.approval().generation(), 2);
        assert_eq!(approval_composite.approval().recovery_remaining(), 1);
        let approval_stale = approval_composite.approval().clone();
        let task_before_stale_inputs = approval_composite.task().clone();

        approval_composite.apply_approval(GovernedApprovalReducerInput::Applied {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approval: GovernedApprovalState::new("approval:stale", "task:stale"),
        });
        assert_eq!(approval_composite.approval(), &approval_stale);
        assert_eq!(approval_composite.task(), &task_before_stale_inputs);
        approval_composite.apply_approval(GovernedApprovalReducerInput::Fatal {
            generation: 1,
            cause: GovernedFatalCause::ApiRejected,
        });
        assert_eq!(approval_composite.approval(), &approval_stale);
        assert_eq!(approval_composite.task(), &task_before_stale_inputs);
        approval_composite.apply_approval(GovernedApprovalReducerInput::Reset { generation: 1 });
        assert_eq!(approval_composite.approval(), &approval_stale);
        assert_eq!(approval_composite.task(), &task_before_stale_inputs);
        approval_composite.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch:stale", 1),
            approvals: BTreeMap::new(),
        });
        assert_eq!(approval_composite.approval(), &approval_stale);
        assert_eq!(approval_composite.task(), &task_before_stale_inputs);
    }

    #[test]
    fn r9b1_rebaseline_is_atomic_preserves_last_good_and_does_not_refill_budget() {
        fn task_fact(task_id: &str, revision: u64) -> GovernedTaskState {
            GovernedTaskState {
                task_id: task_id.to_owned(),
                revision,
                ..sample_task()
            }
        }

        fn task_composite_with_old_fact() -> GovernedStateComposite {
            let mut composite = live_composite(3, 3);
            composite.apply_task(GovernedTaskReducerInput::Applied {
                generation: 1,
                position: GovernedTaskDomainPosition::new("task-epoch", 2),
                task: task_fact("task:old", 2),
            });
            assert_eq!(composite.task().tasks().len(), 1);
            composite
        }

        let mut task_complete = task_composite_with_old_fact();
        task_complete.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        let approval_before = task_complete.approval().clone();
        let mut replacement_tasks = BTreeMap::new();
        replacement_tasks.insert("task:new".to_owned(), task_fact("task:new", 7));
        task_complete.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 2,
            position: GovernedTaskDomainPosition::new("task-epoch:new", 7),
            tasks: replacement_tasks,
        });
        assert_eq!(task_complete.task().phase(), GovernedStateDomainPhase::Live);
        assert_eq!(task_complete.task().reason(), None);
        assert_eq!(task_complete.task().generation(), 2);
        assert_eq!(task_complete.task().recovery_remaining(), 2);
        assert_eq!(task_complete.task().recovery_limit(), 3);
        assert_eq!(
            task_complete.task().position(),
            Some(&GovernedTaskDomainPosition::new("task-epoch:new", 7))
        );
        assert_eq!(task_complete.task().tasks().len(), 1);
        assert_eq!(task_complete.task().tasks()[0].task_id, "task:new");
        assert_eq!(task_complete.task().tasks()[0].revision, 7);
        assert!(
            task_complete
                .task()
                .tasks()
                .iter()
                .all(|task| task.task_id != "task:old")
        );
        assert_eq!(task_complete.approval(), &approval_before);

        let mut approval_complete = live_composite(3, 3);
        approval_complete.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        let task_before = approval_complete.task().clone();
        let mut replacement_approvals = BTreeMap::new();
        replacement_approvals.insert(
            "approval:new".to_owned(),
            GovernedApprovalState::new("approval:new", "task:new"),
        );
        approval_complete.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 2,
            position: GovernedApprovalDomainPosition::new("approval-epoch:new", 7),
            approvals: replacement_approvals,
        });
        assert_eq!(
            approval_complete.approval().phase(),
            GovernedStateDomainPhase::Live
        );
        assert_eq!(approval_complete.approval().reason(), None);
        assert_eq!(approval_complete.approval().generation(), 2);
        assert_eq!(approval_complete.approval().recovery_remaining(), 2);
        assert_eq!(approval_complete.approval().recovery_limit(), 3);
        assert_eq!(
            approval_complete.approval().position(),
            Some(&GovernedApprovalDomainPosition::new(
                "approval-epoch:new",
                7
            ))
        );
        assert_eq!(approval_complete.approval().approvals().len(), 1);
        assert_eq!(
            approval_complete.approval().approvals()[0].approval_request_id(),
            "approval:new"
        );
        assert_eq!(
            approval_complete.approval().approvals()[0].task_id(),
            "task:new"
        );
        assert!(
            approval_complete
                .approval()
                .approvals()
                .iter()
                .all(|approval| approval.approval_request_id() != "approval:1")
        );
        assert_eq!(approval_complete.task(), &task_before);

        let mut task_failed = task_composite_with_old_fact();
        task_failed.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        let task_before = task_failed.task().clone();
        let approval_before = task_failed.approval().clone();
        task_failed.apply_task(GovernedTaskReducerInput::RebaselineFailed {
            generation: 2,
            cause: GovernedFatalCause::ApiRejected,
        });
        assert_eq!(task_failed.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            task_failed.task().reason(),
            Some(GovernedStateReason::ApiRejected)
        );
        assert_eq!(task_failed.task().position(), task_before.position());
        assert_eq!(task_failed.task().tasks(), task_before.tasks());
        assert_eq!(task_failed.task().generation(), task_before.generation());
        assert_eq!(
            task_failed.task().recovery_remaining(),
            task_before.recovery_remaining()
        );
        assert_eq!(
            task_failed.task().recovery_limit(),
            task_before.recovery_limit()
        );
        assert_eq!(task_failed.approval(), &approval_before);

        let mut approval_failed = live_composite(3, 3);
        approval_failed.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        let approval_before = approval_failed.approval().clone();
        let task_before = approval_failed.task().clone();
        approval_failed.apply_approval(GovernedApprovalReducerInput::RebaselineFailed {
            generation: 2,
            cause: GovernedFatalCause::BaselineLimitExceeded,
        });
        assert_eq!(
            approval_failed.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            approval_failed.approval().reason(),
            Some(GovernedStateReason::BaselineLimitExceeded)
        );
        assert_eq!(
            approval_failed.approval().position(),
            approval_before.position()
        );
        assert_eq!(
            approval_failed.approval().approvals(),
            approval_before.approvals()
        );
        assert_eq!(
            approval_failed.approval().generation(),
            approval_before.generation()
        );
        assert_eq!(
            approval_failed.approval().recovery_remaining(),
            approval_before.recovery_remaining()
        );
        assert_eq!(
            approval_failed.approval().recovery_limit(),
            approval_before.recovery_limit()
        );
        assert_eq!(approval_failed.task(), &task_before);

        let mut task_partial = task_composite_with_old_fact();
        task_partial.apply_task(GovernedTaskReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::UnexpectedEof,
        });
        let task_before = task_partial.task().clone();
        let approval_before = task_partial.approval().clone();
        task_partial.apply_task(GovernedTaskReducerInput::RebaselinePartial { generation: 2 });
        assert_eq!(task_partial.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(
            task_partial.task().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(task_partial.task().position(), task_before.position());
        assert_eq!(task_partial.task().tasks(), task_before.tasks());
        assert_eq!(task_partial.task().generation(), task_before.generation());
        assert_eq!(
            task_partial.task().recovery_remaining(),
            task_before.recovery_remaining()
        );
        assert_eq!(
            task_partial.task().recovery_limit(),
            task_before.recovery_limit()
        );
        assert_eq!(task_partial.approval(), &approval_before);

        let mut approval_partial = live_composite(3, 3);
        approval_partial.apply_approval(GovernedApprovalReducerInput::RecoverableFailure {
            generation: 1,
            cause: GovernedRecoverableCause::TransportUnavailable,
        });
        let approval_before = approval_partial.approval().clone();
        let task_before = approval_partial.task().clone();
        approval_partial
            .apply_approval(GovernedApprovalReducerInput::RebaselinePartial { generation: 2 });
        assert_eq!(
            approval_partial.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            approval_partial.approval().reason(),
            Some(GovernedStateReason::ProjectionIntegrityFailure)
        );
        assert_eq!(
            approval_partial.approval().position(),
            approval_before.position()
        );
        assert_eq!(
            approval_partial.approval().approvals(),
            approval_before.approvals()
        );
        assert_eq!(
            approval_partial.approval().generation(),
            approval_before.generation()
        );
        assert_eq!(
            approval_partial.approval().recovery_remaining(),
            approval_before.recovery_remaining()
        );
        assert_eq!(
            approval_partial.approval().recovery_limit(),
            approval_before.recovery_limit()
        );
        assert_eq!(approval_partial.task(), &task_before);
    }

    #[test]
    fn r9b1_cross_domain_positions_have_no_global_order() {
        fn task_facts() -> BTreeMap<String, GovernedTaskState> {
            let mut tasks = BTreeMap::new();
            tasks.insert("task:1".to_owned(), sample_task());
            tasks
        }

        fn approval_facts() -> BTreeMap<String, GovernedApprovalState> {
            let mut approvals = BTreeMap::new();
            approvals.insert(
                "approval:1".to_owned(),
                GovernedApprovalState::new("approval:1", "task:1"),
            );
            approvals
        }

        let connecting = || {
            GovernedStateComposite::new(
                GovernedTaskDomainState::connecting(NonZeroU32::new(3).unwrap()),
                GovernedApprovalDomainState::connecting(NonZeroU32::new(4).unwrap()),
            )
        };

        let mut task_then_approval = connecting();
        task_then_approval.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 100),
            tasks: task_facts(),
        });
        task_then_approval.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approvals: approval_facts(),
        });

        let mut approval_then_task = connecting();
        approval_then_task.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch", 2),
            approvals: approval_facts(),
        });
        approval_then_task.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch", 100),
            tasks: task_facts(),
        });

        assert_eq!(task_then_approval, approval_then_task);
        assert_eq!(
            task_then_approval.task().phase(),
            GovernedStateDomainPhase::Live
        );
        assert_eq!(
            task_then_approval.task().position().unwrap().epoch(),
            "task-epoch"
        );
        assert_eq!(
            task_then_approval.task().position().unwrap().sequence(),
            100
        );
        assert_eq!(task_then_approval.task().generation(), 1);
        assert_eq!(task_then_approval.task().recovery_limit(), 3);
        assert_eq!(task_then_approval.task().recovery_remaining(), 3);
        assert_eq!(
            task_then_approval.approval().phase(),
            GovernedStateDomainPhase::Live
        );
        assert_eq!(
            task_then_approval.approval().position().unwrap().epoch(),
            "approval-epoch"
        );
        assert_eq!(
            task_then_approval.approval().position().unwrap().sequence(),
            2
        );
        assert_eq!(task_then_approval.approval().generation(), 1);
        assert_eq!(task_then_approval.approval().recovery_limit(), 4);
        assert_eq!(task_then_approval.approval().recovery_remaining(), 4);

        let mut reverse_magnitude = connecting();
        reverse_magnitude.apply_task(GovernedTaskReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedTaskDomainPosition::new("task-epoch:reverse", 2),
            tasks: task_facts(),
        });
        reverse_magnitude.apply_approval(GovernedApprovalReducerInput::CompleteRebaseline {
            generation: 1,
            position: GovernedApprovalDomainPosition::new("approval-epoch:reverse", 100),
            approvals: approval_facts(),
        });
        assert_eq!(
            reverse_magnitude.task().phase(),
            GovernedStateDomainPhase::Live
        );
        assert_eq!(
            reverse_magnitude.task().position().unwrap().epoch(),
            "task-epoch:reverse"
        );
        assert_eq!(reverse_magnitude.task().position().unwrap().sequence(), 2);
        assert_eq!(reverse_magnitude.task().recovery_limit(), 3);
        assert_eq!(reverse_magnitude.task().recovery_remaining(), 3);
        assert_eq!(
            reverse_magnitude.approval().phase(),
            GovernedStateDomainPhase::Live
        );
        assert_eq!(
            reverse_magnitude.approval().position().unwrap().epoch(),
            "approval-epoch:reverse"
        );
        assert_eq!(
            reverse_magnitude.approval().position().unwrap().sequence(),
            100
        );
        assert_eq!(reverse_magnitude.approval().recovery_limit(), 4);
        assert_eq!(reverse_magnitude.approval().recovery_remaining(), 4);
    }
}
