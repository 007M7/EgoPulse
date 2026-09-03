use egopulse_client_kernel::KernelError;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode;

use crate::governed_state::{GovernedFatalCause, GovernedRecoverableCause};
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
    use egopulse_client_kernel::{KernelError, KernelServerError};
    use egopulse_domain_contracts::v01::egopulse::localapi::v1::{
        LocalApiError, LocalApiErrorCode,
    };

    use super::{DriverFailure, DriverStage, classify_approval_error, classify_task_error};
    use crate::governed_state::{GovernedFatalCause, GovernedRecoverableCause};
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
}
