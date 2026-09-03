use egopulse_client_kernel::KernelError;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode;

use crate::governed_state::{
    GovernedApprovalReducerInput, GovernedFatalCause, GovernedRecoverableCause,
    GovernedTaskReducerInput,
};
use crate::{ClientApprovalWatchError, ClientGovernedTaskError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverStage {
    Initial,
    Recovery,
    Live,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverFailure {
    Recoverable(GovernedRecoverableCause),
    Fatal(GovernedFatalCause),
    Reset,
}

pub(crate) fn task_failure_input(
    stage: DriverStage,
    generation: u64,
    failure: DriverFailure,
) -> GovernedTaskReducerInput {
    match (stage, failure) {
        (DriverStage::Recovery, DriverFailure::Recoverable(cause)) => {
            GovernedTaskReducerInput::RebaselineRecoverableFailure { generation, cause }
        }
        (DriverStage::Initial | DriverStage::Live, DriverFailure::Recoverable(cause)) => {
            GovernedTaskReducerInput::RecoverableFailure { generation, cause }
        }
        (DriverStage::Recovery, DriverFailure::Fatal(cause)) => {
            GovernedTaskReducerInput::RebaselineFailed { generation, cause }
        }
        (DriverStage::Initial | DriverStage::Live, DriverFailure::Fatal(cause)) => {
            GovernedTaskReducerInput::Fatal { generation, cause }
        }
        (DriverStage::Live, DriverFailure::Reset) => GovernedTaskReducerInput::Reset { generation },
        (DriverStage::Initial, DriverFailure::Reset) => {
            GovernedTaskReducerInput::RecoverableFailure {
                generation,
                cause: GovernedRecoverableCause::ProjectionResetRequired,
            }
        }
        (DriverStage::Recovery, DriverFailure::Reset) => {
            GovernedTaskReducerInput::RebaselineRecoverableFailure {
                generation,
                cause: GovernedRecoverableCause::ProjectionResetRequired,
            }
        }
    }
}

pub(crate) fn approval_failure_input(
    stage: DriverStage,
    generation: u64,
    failure: DriverFailure,
) -> GovernedApprovalReducerInput {
    match (stage, failure) {
        (DriverStage::Recovery, DriverFailure::Recoverable(cause)) => {
            GovernedApprovalReducerInput::RebaselineRecoverableFailure { generation, cause }
        }
        (DriverStage::Initial | DriverStage::Live, DriverFailure::Recoverable(cause)) => {
            GovernedApprovalReducerInput::RecoverableFailure { generation, cause }
        }
        (DriverStage::Recovery, DriverFailure::Fatal(cause)) => {
            GovernedApprovalReducerInput::RebaselineFailed { generation, cause }
        }
        (DriverStage::Initial | DriverStage::Live, DriverFailure::Fatal(cause)) => {
            GovernedApprovalReducerInput::Fatal { generation, cause }
        }
        (DriverStage::Live, DriverFailure::Reset) => {
            GovernedApprovalReducerInput::Reset { generation }
        }
        (DriverStage::Initial, DriverFailure::Reset) => {
            GovernedApprovalReducerInput::RecoverableFailure {
                generation,
                cause: GovernedRecoverableCause::ProjectionResetRequired,
            }
        }
        (DriverStage::Recovery, DriverFailure::Reset) => {
            GovernedApprovalReducerInput::RebaselineRecoverableFailure {
                generation,
                cause: GovernedRecoverableCause::ProjectionResetRequired,
            }
        }
    }
}

pub(crate) fn classify_task_error(
    stage: DriverStage,
    error: &ClientGovernedTaskError,
) -> DriverFailure {
    match error {
        ClientGovernedTaskError::Transport(_) => {
            DriverFailure::Recoverable(GovernedRecoverableCause::TransportUnavailable)
        }
        ClientGovernedTaskError::UnexpectedEof => {
            DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof)
        }
        ClientGovernedTaskError::Api(error) => classify_api_error(error.code, error.retryable),
        ClientGovernedTaskError::BaselineLimitExceeded => {
            DriverFailure::Fatal(GovernedFatalCause::BaselineLimitExceeded)
        }
        ClientGovernedTaskError::ResetBarrier => DriverFailure::Reset,
        ClientGovernedTaskError::Protocol(_) => {
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
        }
        ClientGovernedTaskError::Kernel(error) => classify_kernel_error(stage, error),
    }
}

pub(crate) fn classify_approval_error(
    stage: DriverStage,
    error: &ClientApprovalWatchError,
) -> DriverFailure {
    match error {
        ClientApprovalWatchError::Transport(_) => {
            DriverFailure::Recoverable(GovernedRecoverableCause::TransportUnavailable)
        }
        ClientApprovalWatchError::UnexpectedEof => {
            DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof)
        }
        ClientApprovalWatchError::Api(error) => classify_api_error(error.code, error.retryable),
        ClientApprovalWatchError::BaselineLimitExceeded => {
            DriverFailure::Fatal(GovernedFatalCause::BaselineLimitExceeded)
        }
        ClientApprovalWatchError::ResetBarrier => DriverFailure::Reset,
        ClientApprovalWatchError::Protocol(_) => {
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
        }
        ClientApprovalWatchError::Kernel(error) => classify_kernel_error(stage, error),
    }
}

fn classify_kernel_error(_stage: DriverStage, error: &KernelError) -> DriverFailure {
    match error {
        KernelError::PermissionDenied(_) => {
            DriverFailure::Fatal(GovernedFatalCause::PermissionDenied)
        }
        KernelError::SessionUnavailable | KernelError::SessionExpired => {
            DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable)
        }
        KernelError::SessionMalformed(_) => {
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
        }
        KernelError::ServerRejected(error) => {
            classify_api_error(error.code as i32, error.retryable)
        }
        _ => DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
    }
}

fn classify_api_error(code: i32, retryable: bool) -> DriverFailure {
    let Ok(code) = LocalApiErrorCode::try_from(code) else {
        return DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure);
    };
    match code {
        LocalApiErrorCode::PermissionDenied
        | LocalApiErrorCode::OwnerMismatch
        | LocalApiErrorCode::ContextRevoked => {
            DriverFailure::Fatal(GovernedFatalCause::PermissionDenied)
        }
        LocalApiErrorCode::Unauthenticated | LocalApiErrorCode::SessionExpired => {
            DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable)
        }
        LocalApiErrorCode::ProjectionResetRequired | LocalApiErrorCode::CursorExpired => {
            DriverFailure::Reset
        }
        LocalApiErrorCode::Unspecified
        | LocalApiErrorCode::InvalidArgument
        | LocalApiErrorCode::ContractIncompatible
        | LocalApiErrorCode::CursorInvalid
        | LocalApiErrorCode::IntegrityFailure
        | LocalApiErrorCode::UnknownCriticalSemantics => {
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
        }
        _ if retryable => {
            DriverFailure::Recoverable(GovernedRecoverableCause::RetryableApiRejected)
        }
        _ => DriverFailure::Fatal(GovernedFatalCause::ApiRejected),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use egopulse_client_kernel::{KernelError, KernelServerError};
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        LocalApiError, LocalApiErrorCode,
    };

    use super::{
        DriverFailure, DriverStage, approval_failure_input, classify_approval_error,
        classify_task_error, task_failure_input,
    };
    use crate::governed_state::{
        GovernedApprovalDomainState, GovernedApprovalReducerInput, GovernedFatalCause,
        GovernedRecoverableCause, GovernedStateComposite, GovernedStateDomainPhase,
        GovernedStateReason, GovernedTaskDomainState, GovernedTaskReducerInput,
    };
    use crate::{ClientApprovalWatchError, ClientGovernedTaskError};

    const STAGES: [DriverStage; 3] = [
        DriverStage::Initial,
        DriverStage::Recovery,
        DriverStage::Live,
    ];

    fn local_api_error(code: i32, retryable: bool) -> LocalApiError {
        LocalApiError {
            code,
            safe_fingerprint: "governed-state-driver/test/v1".to_owned(),
            retryable,
            required_action_code: None,
            current_position: None,
            correlation_id: "correlation:governed-state-driver".to_owned(),
        }
    }

    fn kernel_server_error(code: LocalApiErrorCode, retryable: bool) -> KernelError {
        KernelError::ServerRejected(Box::new(KernelServerError {
            code,
            safe_fingerprint: "governed-state-driver/test/v1".to_owned(),
            retryable,
            required_action_code: None,
            current_position: None,
            correlation_id: "correlation:governed-state-driver".to_owned(),
        }))
    }

    fn assert_local_api_classification(code: i32, retryable: bool, expected: DriverFailure) {
        for stage in STAGES {
            assert_eq!(
                classify_task_error(
                    stage,
                    &ClientGovernedTaskError::Api(Box::new(local_api_error(code, retryable))),
                ),
                expected
            );
            assert_eq!(
                classify_approval_error(
                    stage,
                    &ClientApprovalWatchError::Api(Box::new(local_api_error(code, retryable))),
                ),
                expected
            );
        }
    }

    fn assert_kernel_server_classification(
        code: LocalApiErrorCode,
        retryable: bool,
        expected: DriverFailure,
    ) {
        for stage in STAGES {
            assert_eq!(
                classify_task_error(
                    stage,
                    &ClientGovernedTaskError::Kernel(kernel_server_error(code, retryable)),
                ),
                expected
            );
            assert_eq!(
                classify_approval_error(
                    stage,
                    &ClientApprovalWatchError::Kernel(kernel_server_error(code, retryable)),
                ),
                expected
            );
        }
    }

    fn assert_kernel_classification(error: impl Fn() -> KernelError, expected: DriverFailure) {
        for stage in STAGES {
            assert_eq!(
                classify_task_error(stage, &ClientGovernedTaskError::Kernel(error())),
                expected
            );
            assert_eq!(
                classify_approval_error(stage, &ClientApprovalWatchError::Kernel(error())),
                expected
            );
        }
    }

    #[test]
    fn r9b2_local_api_error_matrix_is_symmetric_and_stage_invariant() {
        for code in [
            LocalApiErrorCode::PermissionDenied,
            LocalApiErrorCode::OwnerMismatch,
            LocalApiErrorCode::ContextRevoked,
        ] {
            for retryable in [false, true] {
                assert_local_api_classification(
                    code as i32,
                    retryable,
                    DriverFailure::Fatal(GovernedFatalCause::PermissionDenied),
                );
            }
        }
        for code in [
            LocalApiErrorCode::Unauthenticated,
            LocalApiErrorCode::SessionExpired,
        ] {
            for retryable in [false, true] {
                assert_local_api_classification(
                    code as i32,
                    retryable,
                    DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable),
                );
            }
        }
        for code in [
            LocalApiErrorCode::ProjectionResetRequired,
            LocalApiErrorCode::CursorExpired,
        ] {
            for retryable in [false, true] {
                assert_local_api_classification(code as i32, retryable, DriverFailure::Reset);
            }
        }
        for code in [
            LocalApiErrorCode::Unspecified,
            LocalApiErrorCode::InvalidArgument,
            LocalApiErrorCode::ContractIncompatible,
            LocalApiErrorCode::CursorInvalid,
            LocalApiErrorCode::IntegrityFailure,
            LocalApiErrorCode::UnknownCriticalSemantics,
        ] {
            for retryable in [false, true] {
                assert_local_api_classification(
                    code as i32,
                    retryable,
                    DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
                );
            }
        }
        for code in [
            LocalApiErrorCode::NotFound,
            LocalApiErrorCode::ProjectionBehind,
            LocalApiErrorCode::ProjectionHeld,
            LocalApiErrorCode::DeadlineExceeded,
            LocalApiErrorCode::AuthorityUnavailable,
            LocalApiErrorCode::ResourceExhausted,
            LocalApiErrorCode::StateRevisionConflict,
            LocalApiErrorCode::IdempotencyConflict,
        ] {
            assert_local_api_classification(
                code as i32,
                true,
                DriverFailure::Recoverable(GovernedRecoverableCause::RetryableApiRejected),
            );
            assert_local_api_classification(
                code as i32,
                false,
                DriverFailure::Fatal(GovernedFatalCause::ApiRejected),
            );
        }
        for retryable in [false, true] {
            assert_local_api_classification(
                i32::MAX,
                retryable,
                DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
            );
        }
    }

    #[test]
    fn r9b2_kernel_error_matrix_is_symmetric_and_stage_invariant() {
        for code in [
            LocalApiErrorCode::PermissionDenied,
            LocalApiErrorCode::OwnerMismatch,
            LocalApiErrorCode::ContextRevoked,
        ] {
            assert_kernel_server_classification(
                code,
                true,
                DriverFailure::Fatal(GovernedFatalCause::PermissionDenied),
            );
        }
        for code in [
            LocalApiErrorCode::Unauthenticated,
            LocalApiErrorCode::SessionExpired,
        ] {
            assert_kernel_server_classification(
                code,
                true,
                DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable),
            );
        }
        for code in [
            LocalApiErrorCode::ProjectionResetRequired,
            LocalApiErrorCode::CursorExpired,
        ] {
            assert_kernel_server_classification(code, true, DriverFailure::Reset);
        }
        for code in [
            LocalApiErrorCode::Unspecified,
            LocalApiErrorCode::InvalidArgument,
            LocalApiErrorCode::ContractIncompatible,
            LocalApiErrorCode::CursorInvalid,
            LocalApiErrorCode::IntegrityFailure,
            LocalApiErrorCode::UnknownCriticalSemantics,
        ] {
            assert_kernel_server_classification(
                code,
                true,
                DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
            );
        }
        assert_kernel_server_classification(
            LocalApiErrorCode::AuthorityUnavailable,
            true,
            DriverFailure::Recoverable(GovernedRecoverableCause::RetryableApiRejected),
        );
        assert_kernel_server_classification(
            LocalApiErrorCode::AuthorityUnavailable,
            false,
            DriverFailure::Fatal(GovernedFatalCause::ApiRejected),
        );

        assert_kernel_classification(
            || KernelError::PermissionDenied("governed-state/test".to_owned()),
            DriverFailure::Fatal(GovernedFatalCause::PermissionDenied),
        );
        assert_kernel_classification(
            || KernelError::SessionUnavailable,
            DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable),
        );
        assert_kernel_classification(
            || KernelError::SessionExpired,
            DriverFailure::Fatal(GovernedFatalCause::InitialSessionUnavailable),
        );
        assert_kernel_classification(
            || KernelError::SessionMalformed("malformed"),
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::ContractMismatch("contract"),
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::ProfileInvalid("profile"),
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::ProfileDigestMismatch,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::IncompleteStreamFrame,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
    }

    #[test]
    fn r9b2a_top_level_failure_matrix_is_symmetric_and_stage_invariant() {
        for stage in STAGES {
            assert_eq!(
                classify_task_error(
                    stage,
                    &ClientGovernedTaskError::Transport("transport down".to_owned())
                ),
                DriverFailure::Recoverable(GovernedRecoverableCause::TransportUnavailable)
            );
            assert_eq!(
                classify_approval_error(
                    stage,
                    &ClientApprovalWatchError::Transport("transport down".to_owned())
                ),
                DriverFailure::Recoverable(GovernedRecoverableCause::TransportUnavailable)
            );
            assert_eq!(
                classify_task_error(stage, &ClientGovernedTaskError::UnexpectedEof),
                DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof)
            );
            assert_eq!(
                classify_approval_error(stage, &ClientApprovalWatchError::UnexpectedEof),
                DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof)
            );
            assert_eq!(
                classify_task_error(stage, &ClientGovernedTaskError::ResetBarrier),
                DriverFailure::Reset
            );
            assert_eq!(
                classify_approval_error(stage, &ClientApprovalWatchError::ResetBarrier),
                DriverFailure::Reset
            );
            assert_eq!(
                classify_task_error(stage, &ClientGovernedTaskError::Protocol("integrity")),
                DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
            );
            assert_eq!(
                classify_approval_error(stage, &ClientApprovalWatchError::Protocol("integrity")),
                DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure)
            );
            assert_eq!(
                classify_task_error(stage, &ClientGovernedTaskError::BaselineLimitExceeded),
                DriverFailure::Fatal(GovernedFatalCause::BaselineLimitExceeded)
            );
            assert_eq!(
                classify_approval_error(stage, &ClientApprovalWatchError::BaselineLimitExceeded),
                DriverFailure::Fatal(GovernedFatalCause::BaselineLimitExceeded)
            );
        }
    }

    #[test]
    fn r9b2a_kernel_unknown_fallback_and_worker_unavailable_maps_by_retryable() {
        assert_kernel_classification(
            || KernelError::UnknownServerError,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::InvalidSurface,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::InvalidIdentifier,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::UnknownPermission("perm".to_owned()),
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::UnknownRpc("rpc".to_owned()),
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::UnknownStreamFrame,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );
        assert_kernel_classification(
            || KernelError::StreamPositionInvalid,
            DriverFailure::Fatal(GovernedFatalCause::ProjectionIntegrityFailure),
        );

        assert_local_api_classification(
            LocalApiErrorCode::CognitionWorkerUnavailable as i32,
            true,
            DriverFailure::Recoverable(GovernedRecoverableCause::RetryableApiRejected),
        );
        assert_local_api_classification(
            LocalApiErrorCode::CognitionWorkerUnavailable as i32,
            false,
            DriverFailure::Fatal(GovernedFatalCause::ApiRejected),
        );
        assert_kernel_server_classification(
            LocalApiErrorCode::CognitionWorkerUnavailable,
            true,
            DriverFailure::Recoverable(GovernedRecoverableCause::RetryableApiRejected),
        );
        assert_kernel_server_classification(
            LocalApiErrorCode::CognitionWorkerUnavailable,
            false,
            DriverFailure::Fatal(GovernedFatalCause::ApiRejected),
        );
    }

    #[test]
    fn r9b2a_task_failure_input_respects_driver_stage_and_reset_recovery() {
        let recoverable = DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof);
        let fatal = DriverFailure::Fatal(GovernedFatalCause::PermissionDenied);

        assert!(matches!(
            task_failure_input(DriverStage::Initial, 7, recoverable),
            GovernedTaskReducerInput::RecoverableFailure {
                generation: 7,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            task_failure_input(DriverStage::Recovery, 7, recoverable),
            GovernedTaskReducerInput::RebaselineRecoverableFailure {
                generation: 7,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            task_failure_input(DriverStage::Live, 7, recoverable),
            GovernedTaskReducerInput::RecoverableFailure {
                generation: 7,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            task_failure_input(DriverStage::Recovery, 7, fatal),
            GovernedTaskReducerInput::RebaselineFailed {
                generation: 7,
                cause: GovernedFatalCause::PermissionDenied
            }
        ));
        for stage in [DriverStage::Initial, DriverStage::Live] {
            assert!(matches!(
                task_failure_input(stage, 7, fatal),
                GovernedTaskReducerInput::Fatal {
                    generation: 7,
                    cause: GovernedFatalCause::PermissionDenied
                }
            ));
        }
        assert!(matches!(
            task_failure_input(DriverStage::Initial, 7, DriverFailure::Reset),
            GovernedTaskReducerInput::RecoverableFailure {
                generation: 7,
                cause: GovernedRecoverableCause::ProjectionResetRequired
            }
        ));
        assert!(matches!(
            task_failure_input(DriverStage::Recovery, 7, DriverFailure::Reset),
            GovernedTaskReducerInput::RebaselineRecoverableFailure {
                generation: 7,
                cause: GovernedRecoverableCause::ProjectionResetRequired
            }
        ));
        assert!(matches!(
            task_failure_input(DriverStage::Live, 7, DriverFailure::Reset),
            GovernedTaskReducerInput::Reset { generation: 7 }
        ));
    }

    #[test]
    fn r9b2a_approval_failure_input_respects_driver_stage_and_reset_recovery() {
        let recoverable = DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof);
        let fatal = DriverFailure::Fatal(GovernedFatalCause::PermissionDenied);

        assert!(matches!(
            approval_failure_input(DriverStage::Initial, 9, recoverable),
            GovernedApprovalReducerInput::RecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            approval_failure_input(DriverStage::Recovery, 9, recoverable),
            GovernedApprovalReducerInput::RebaselineRecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            approval_failure_input(DriverStage::Live, 9, recoverable),
            GovernedApprovalReducerInput::RecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::UnexpectedEof
            }
        ));
        assert!(matches!(
            approval_failure_input(DriverStage::Recovery, 9, fatal),
            GovernedApprovalReducerInput::RebaselineFailed {
                generation: 9,
                cause: GovernedFatalCause::PermissionDenied
            }
        ));
        for stage in [DriverStage::Initial, DriverStage::Live] {
            assert!(matches!(
                approval_failure_input(stage, 9, fatal),
                GovernedApprovalReducerInput::Fatal {
                    generation: 9,
                    cause: GovernedFatalCause::PermissionDenied
                }
            ));
        }
        assert!(matches!(
            approval_failure_input(DriverStage::Initial, 9, DriverFailure::Reset),
            GovernedApprovalReducerInput::RecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::ProjectionResetRequired
            }
        ));
        assert!(matches!(
            approval_failure_input(DriverStage::Recovery, 9, DriverFailure::Reset),
            GovernedApprovalReducerInput::RebaselineRecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::ProjectionResetRequired
            }
        ));
        assert!(matches!(
            approval_failure_input(DriverStage::Live, 9, DriverFailure::Reset),
            GovernedApprovalReducerInput::Reset { generation: 9 }
        ));
    }

    #[test]
    fn r9b2a_reset_recovery_is_bounded_and_generation_fenced_symmetrically() {
        let recovery_limit = NonZeroU32::new(2).expect("non-zero recovery limit");
        let mut task_path = GovernedStateComposite::new(
            GovernedTaskDomainState::connecting(recovery_limit),
            GovernedApprovalDomainState::connecting(recovery_limit),
        );
        let approval_before = task_path.approval().clone();

        task_path.apply_task(task_failure_input(
            DriverStage::Initial,
            1,
            DriverFailure::Reset,
        ));
        assert_eq!(task_path.task().phase(), GovernedStateDomainPhase::Stale);
        assert_eq!(task_path.task().generation(), 2);
        assert_eq!(task_path.task().recovery_remaining(), 1);
        assert_eq!(
            task_path.task().reason(),
            Some(GovernedStateReason::ProjectionResetRequired)
        );
        assert_eq!(task_path.approval(), &approval_before);

        let task_before_stale_replay = task_path.task().clone();
        task_path.apply_task(task_failure_input(
            DriverStage::Recovery,
            1,
            DriverFailure::Reset,
        ));
        assert_eq!(task_path.task(), &task_before_stale_replay);
        assert_eq!(task_path.approval(), &approval_before);

        task_path.apply_task(task_failure_input(
            DriverStage::Recovery,
            2,
            DriverFailure::Reset,
        ));
        assert_eq!(task_path.task().phase(), GovernedStateDomainPhase::Fatal);
        assert_eq!(task_path.task().generation(), 3);
        assert_eq!(task_path.task().recovery_remaining(), 0);
        assert_eq!(
            task_path.task().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(task_path.approval(), &approval_before);

        let mut approval_path = GovernedStateComposite::new(
            GovernedTaskDomainState::connecting(recovery_limit),
            GovernedApprovalDomainState::connecting(recovery_limit),
        );
        let task_before = approval_path.task().clone();

        approval_path.apply_approval(approval_failure_input(
            DriverStage::Initial,
            1,
            DriverFailure::Reset,
        ));
        assert_eq!(
            approval_path.approval().phase(),
            GovernedStateDomainPhase::Stale
        );
        assert_eq!(approval_path.approval().generation(), 2);
        assert_eq!(approval_path.approval().recovery_remaining(), 1);
        assert_eq!(
            approval_path.approval().reason(),
            Some(GovernedStateReason::ProjectionResetRequired)
        );
        assert_eq!(approval_path.task(), &task_before);

        let approval_before_stale_replay = approval_path.approval().clone();
        approval_path.apply_approval(approval_failure_input(
            DriverStage::Recovery,
            1,
            DriverFailure::Reset,
        ));
        assert_eq!(approval_path.approval(), &approval_before_stale_replay);
        assert_eq!(approval_path.task(), &task_before);

        approval_path.apply_approval(approval_failure_input(
            DriverStage::Recovery,
            2,
            DriverFailure::Reset,
        ));
        assert_eq!(
            approval_path.approval().phase(),
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(approval_path.approval().generation(), 3);
        assert_eq!(approval_path.approval().recovery_remaining(), 0);
        assert_eq!(
            approval_path.approval().reason(),
            Some(GovernedStateReason::RecoveryExhausted)
        );
        assert_eq!(approval_path.task(), &task_before);
    }
}
