use std::{collections::BTreeMap, future::Future, num::NonZeroU32, sync::Arc};

use egopulse_client_kernel::KernelError;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode;
use egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionPosition;
use tokio::sync::{mpsc, mpsc::error::TryRecvError, oneshot};

use crate::governed_state::{
    GovernedApprovalDomainPosition, GovernedApprovalDomainState, GovernedApprovalReducerInput,
    GovernedApprovalState, GovernedFatalCause, GovernedRecoverableCause, GovernedStateComposite,
    GovernedStateDomain, GovernedStateDomainPhase, GovernedTaskDomainPosition,
    GovernedTaskDomainState, GovernedTaskReducerInput,
};
use crate::{
    ApprovalQueueSession, ApprovalWatchClassification, ApprovalWatchUpdate,
    ClientApprovalWatchError, ClientAttachment, ClientGovernedTaskError,
    GovernedProjectionPosition, GovernedTaskSession, GovernedTaskState, GovernedTaskUpdate,
    TaskWatchClassification,
};

const GOVERNED_STATE_REQUEST_CAPACITY: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainAck {
    phase: GovernedStateDomainPhase,
    generation: u64,
    recovery_remaining: u32,
}

struct TaskRequest {
    input: GovernedTaskReducerInput,
    ack: oneshot::Sender<DomainAck>,
}

struct ApprovalRequest {
    input: GovernedApprovalReducerInput,
    ack: oneshot::Sender<DomainAck>,
}

type TaskRequestSender = mpsc::Sender<TaskRequest>;
type TaskRequestReceiver = mpsc::Receiver<TaskRequest>;
type ApprovalRequestSender = mpsc::Sender<ApprovalRequest>;
type ApprovalRequestReceiver = mpsc::Receiver<ApprovalRequest>;

fn governed_state_request_channels() -> (
    TaskRequestSender,
    TaskRequestReceiver,
    ApprovalRequestSender,
    ApprovalRequestReceiver,
) {
    let (task_sender, task_receiver) = mpsc::channel(GOVERNED_STATE_REQUEST_CAPACITY);
    let (approval_sender, approval_receiver) = mpsc::channel(GOVERNED_STATE_REQUEST_CAPACITY);
    (
        task_sender,
        task_receiver,
        approval_sender,
        approval_receiver,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernedStateUpdate {
    domain: GovernedStateDomain,
}

impl GovernedStateUpdate {
    #[must_use]
    pub const fn domain(&self) -> GovernedStateDomain {
        self.domain
    }
}

enum ReadyRequest {
    Task(TaskRequest),
    Approval(ApprovalRequest),
}

enum ReceivedRequest {
    Task(Option<TaskRequest>),
    Approval(Option<ApprovalRequest>),
}

struct GovernedStateSessionCore {
    state: GovernedStateComposite,
    task_receiver: TaskRequestReceiver,
    approval_receiver: ApprovalRequestReceiver,
    task_closed: bool,
    approval_closed: bool,
    preferred: GovernedStateDomain,
}

impl GovernedStateSessionCore {
    fn new() -> (Self, TaskRequestSender, ApprovalRequestSender) {
        Self::with_recovery_limit(
            NonZeroU32::new(3).expect("production recovery limit is non-zero"),
        )
    }

    fn with_recovery_limit(
        recovery_limit: NonZeroU32,
    ) -> (Self, TaskRequestSender, ApprovalRequestSender) {
        let (task_sender, task_receiver, approval_sender, approval_receiver) =
            governed_state_request_channels();
        (
            Self {
                state: GovernedStateComposite::new(
                    GovernedTaskDomainState::connecting(recovery_limit),
                    GovernedApprovalDomainState::connecting(recovery_limit),
                ),
                task_receiver,
                approval_receiver,
                task_closed: false,
                approval_closed: false,
                preferred: GovernedStateDomain::Task,
            },
            task_sender,
            approval_sender,
        )
    }

    fn state(&self) -> &GovernedStateComposite {
        &self.state
    }

    async fn next_update(&mut self) -> Option<GovernedStateUpdate> {
        loop {
            if let Some(request) = self.try_ready_request() {
                return Some(self.apply_request(request));
            }

            if self.task_closed && self.approval_closed {
                return None;
            }

            let received = match self.preferred {
                GovernedStateDomain::Task => {
                    tokio::select! {
                        biased;
                        request = self.task_receiver.recv(), if !self.task_closed => {
                            ReceivedRequest::Task(request)
                        }
                        request = self.approval_receiver.recv(), if !self.approval_closed => {
                            ReceivedRequest::Approval(request)
                        }
                    }
                }
                GovernedStateDomain::Approval => {
                    tokio::select! {
                        biased;
                        request = self.approval_receiver.recv(), if !self.approval_closed => {
                            ReceivedRequest::Approval(request)
                        }
                        request = self.task_receiver.recv(), if !self.task_closed => {
                            ReceivedRequest::Task(request)
                        }
                    }
                }
            };
            match received {
                ReceivedRequest::Task(Some(request)) => {
                    return Some(self.apply_request(ReadyRequest::Task(request)));
                }
                ReceivedRequest::Approval(Some(request)) => {
                    return Some(self.apply_request(ReadyRequest::Approval(request)));
                }
                ReceivedRequest::Task(None) => self.task_closed = true,
                ReceivedRequest::Approval(None) => self.approval_closed = true,
            }
        }
    }

    fn try_ready_request(&mut self) -> Option<ReadyRequest> {
        match self.preferred {
            GovernedStateDomain::Task => self
                .try_task_request()
                .or_else(|| self.try_approval_request()),
            GovernedStateDomain::Approval => self
                .try_approval_request()
                .or_else(|| self.try_task_request()),
        }
    }

    fn try_task_request(&mut self) -> Option<ReadyRequest> {
        if self.task_closed {
            return None;
        }
        match self.task_receiver.try_recv() {
            Ok(request) => Some(ReadyRequest::Task(request)),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.task_closed = true;
                None
            }
        }
    }

    fn try_approval_request(&mut self) -> Option<ReadyRequest> {
        if self.approval_closed {
            return None;
        }
        match self.approval_receiver.try_recv() {
            Ok(request) => Some(ReadyRequest::Approval(request)),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.approval_closed = true;
                None
            }
        }
    }

    fn apply_request(&mut self, request: ReadyRequest) -> GovernedStateUpdate {
        match request {
            ReadyRequest::Task(request) => {
                self.state.apply_task(request.input);
                let task = self.state.task();
                let _ = request.ack.send(DomainAck {
                    phase: task.phase(),
                    generation: task.generation(),
                    recovery_remaining: task.recovery_remaining(),
                });
                self.preferred = GovernedStateDomain::Approval;
                GovernedStateUpdate {
                    domain: GovernedStateDomain::Task,
                }
            }
            ReadyRequest::Approval(request) => {
                self.state.apply_approval(request.input);
                let approval = self.state.approval();
                let _ = request.ack.send(DomainAck {
                    phase: approval.phase(),
                    generation: approval.generation(),
                    recovery_remaining: approval.recovery_remaining(),
                });
                self.preferred = GovernedStateDomain::Task;
                GovernedStateUpdate {
                    domain: GovernedStateDomain::Approval,
                }
            }
        }
    }
}

struct GovernedStateSources {
    task: TaskSource,
    approval: ApprovalSource,
}

impl GovernedStateSources {
    fn new(attachment: Arc<ClientAttachment>) -> Self {
        let (task, approval) = clone_shared_pair(attachment);
        Self {
            task: TaskSource { attachment: task },
            approval: ApprovalSource {
                attachment: approval,
            },
        }
    }
}

struct TaskSource {
    attachment: Arc<ClientAttachment>,
}

struct ApprovalSource {
    attachment: Arc<ClientAttachment>,
}

struct Opened<Session, Input> {
    session: Session,
    complete_input: Input,
}

type OpenedTaskSource = Opened<GovernedTaskSession, GovernedTaskReducerInput>;
type OpenedApprovalSource = Opened<ApprovalQueueSession, GovernedApprovalReducerInput>;

fn clone_shared_pair<T>(shared: Arc<T>) -> (Arc<T>, Arc<T>) {
    (Arc::clone(&shared), shared)
}

async fn open_source_via<
    Baseline,
    Session,
    Input,
    Error,
    ReadBaseline,
    ReadFuture,
    OpenSession,
    OpenFuture,
    CompleteFromSession,
    MapError,
>(
    read_baseline: ReadBaseline,
    open_session: OpenSession,
    complete_from_session: CompleteFromSession,
    mut map_error: MapError,
) -> Result<Opened<Session, Input>, Box<Input>>
where
    ReadBaseline: FnOnce() -> ReadFuture,
    ReadFuture: Future<Output = Result<Baseline, Error>>,
    OpenSession: FnOnce(Baseline) -> OpenFuture,
    OpenFuture: Future<Output = Result<Session, Error>>,
    CompleteFromSession: FnOnce(&Session) -> Input,
    MapError: FnMut(Error) -> Input,
{
    let baseline = match read_baseline().await {
        Ok(baseline) => baseline,
        Err(error) => return Err(Box::new(map_error(error))),
    };
    let session = match open_session(baseline).await {
        Ok(session) => session,
        Err(error) => return Err(Box::new(map_error(error))),
    };
    let complete_input = complete_from_session(&session);
    Ok(Opened {
        session,
        complete_input,
    })
}

impl TaskSource {
    async fn open(
        &self,
        stage: DriverStage,
        generation: u64,
    ) -> Result<OpenedTaskSource, Box<GovernedTaskReducerInput>> {
        open_source_via(
            || self.attachment.read_governed_task_baseline(),
            |baseline| self.attachment.open_governed_task_session(baseline),
            |session| task_complete_input_from_session(generation, session),
            |error| task_failure_input(stage, generation, classify_task_error(stage, &error)),
        )
        .await
    }
}

impl ApprovalSource {
    async fn open(
        &self,
        stage: DriverStage,
        generation: u64,
    ) -> Result<OpenedApprovalSource, Box<GovernedApprovalReducerInput>> {
        open_source_via(
            || self.attachment.read_actionable_approval_queue(),
            |baseline| self.attachment.open_approval_queue_from(baseline),
            |session| approval_complete_input_from_session(generation, session),
            |error| {
                approval_failure_input(stage, generation, classify_approval_error(stage, &error))
            },
        )
        .await
    }
}

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

pub(crate) fn task_complete_input_from_session(
    generation: u64,
    session: &GovernedTaskSession,
) -> GovernedTaskReducerInput {
    task_complete_input_from_parts(generation, session.position(), session.tasks())
}

async fn next_task_live_input(
    generation: u64,
    session: &mut GovernedTaskSession,
) -> GovernedTaskReducerInput {
    task_live_input_from_result(generation, session.next_update().await)
}

fn task_live_input_from_result(
    generation: u64,
    result: Result<GovernedTaskUpdate, ClientGovernedTaskError>,
) -> GovernedTaskReducerInput {
    match result {
        Ok(update) => task_live_input_from_update(generation, update),
        Err(error) => task_failure_input(
            DriverStage::Live,
            generation,
            classify_task_error(DriverStage::Live, &error),
        ),
    }
}

fn task_live_input_from_update(
    generation: u64,
    update: GovernedTaskUpdate,
) -> GovernedTaskReducerInput {
    match update.classification {
        TaskWatchClassification::Applied => match update.task {
            Some(task) => GovernedTaskReducerInput::Applied {
                generation,
                position: GovernedTaskDomainPosition::new(
                    update.position.epoch,
                    update.position.sequence,
                ),
                task,
            },
            None => GovernedTaskReducerInput::Fatal {
                generation,
                cause: GovernedFatalCause::ProjectionIntegrityFailure,
            },
        },
        TaskWatchClassification::Replay => GovernedTaskReducerInput::Replay { generation },
        TaskWatchClassification::Heartbeat => GovernedTaskReducerInput::Heartbeat { generation },
        TaskWatchClassification::ResetRequired => GovernedTaskReducerInput::Reset { generation },
    }
}

fn task_complete_input_from_parts<'a>(
    generation: u64,
    position: &GovernedProjectionPosition,
    tasks: impl IntoIterator<Item = &'a GovernedTaskState>,
) -> GovernedTaskReducerInput {
    let tasks = tasks
        .into_iter()
        .map(|task| (task.task_id.clone(), task.clone()))
        .collect::<BTreeMap<_, _>>();
    GovernedTaskReducerInput::CompleteRebaseline {
        generation,
        position: GovernedTaskDomainPosition::new(position.epoch.clone(), position.sequence),
        tasks,
    }
}

pub(crate) fn approval_complete_input_from_session(
    generation: u64,
    session: &ApprovalQueueSession,
) -> GovernedApprovalReducerInput {
    approval_complete_input_from_parts(
        generation,
        session.position(),
        session.actionable_approvals().into_iter().map(|approval| {
            let view = approval.view();
            (view.approval_request_id.as_str(), view.task_id.as_str())
        }),
    )
}

fn approval_complete_input_from_parts<'a>(
    generation: u64,
    position: &ProjectionPosition,
    approvals: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> GovernedApprovalReducerInput {
    let approvals = approvals
        .into_iter()
        .map(|(approval_request_id, task_id)| {
            (
                approval_request_id.to_owned(),
                GovernedApprovalState::new(approval_request_id, task_id),
            )
        })
        .collect::<BTreeMap<_, _>>();
    GovernedApprovalReducerInput::CompleteRebaseline {
        generation,
        position: GovernedApprovalDomainPosition::new(position.epoch.clone(), position.sequence),
        approvals,
    }
}

async fn next_approval_live_input(
    generation: u64,
    session: &mut ApprovalQueueSession,
) -> GovernedApprovalReducerInput {
    let result = session.next_update().await;
    approval_live_input_from_result(generation, result, |approval_request_id| {
        session
            .actionable_approvals()
            .into_iter()
            .find_map(|approval| {
                let view = approval.view();
                (view.approval_request_id == approval_request_id).then(|| {
                    GovernedApprovalState::new(
                        view.approval_request_id.as_str(),
                        view.task_id.as_str(),
                    )
                })
            })
    })
}

fn approval_live_input_from_result<F>(
    generation: u64,
    result: Result<Option<ApprovalWatchUpdate>, ClientApprovalWatchError>,
    lookup_safe: F,
) -> GovernedApprovalReducerInput
where
    F: FnOnce(&str) -> Option<GovernedApprovalState>,
{
    match result {
        Ok(Some(update)) => match update.classification {
            ApprovalWatchClassification::Applied => {
                let Some(view) = update.view.as_ref() else {
                    return GovernedApprovalReducerInput::Fatal {
                        generation,
                        cause: GovernedFatalCause::ProjectionIntegrityFailure,
                    };
                };
                let approval_request_id = view.approval_request_id.as_str();
                approval_live_input_from_parts(
                    generation,
                    ApprovalWatchClassification::Applied,
                    &update.position,
                    Some(approval_request_id),
                    lookup_safe(approval_request_id),
                )
            }
            classification => approval_live_input_from_parts(
                generation,
                classification,
                &update.position,
                None,
                None,
            ),
        },
        Ok(None) => {
            let error = ClientApprovalWatchError::UnexpectedEof;
            approval_failure_input(
                DriverStage::Live,
                generation,
                classify_approval_error(DriverStage::Live, &error),
            )
        }
        Err(error) => approval_failure_input(
            DriverStage::Live,
            generation,
            classify_approval_error(DriverStage::Live, &error),
        ),
    }
}

fn approval_live_input_from_parts(
    generation: u64,
    classification: ApprovalWatchClassification,
    position: &ProjectionPosition,
    applied_approval_request_id: Option<&str>,
    actionable: Option<GovernedApprovalState>,
) -> GovernedApprovalReducerInput {
    match classification {
        ApprovalWatchClassification::Applied => {
            let Some(approval_request_id) = applied_approval_request_id else {
                return GovernedApprovalReducerInput::Fatal {
                    generation,
                    cause: GovernedFatalCause::ProjectionIntegrityFailure,
                };
            };
            match actionable {
                Some(approval) if approval.approval_request_id() == approval_request_id => {
                    GovernedApprovalReducerInput::Applied {
                        generation,
                        position: GovernedApprovalDomainPosition::new(
                            position.epoch.clone(),
                            position.sequence,
                        ),
                        approval,
                    }
                }
                Some(_) => GovernedApprovalReducerInput::Fatal {
                    generation,
                    cause: GovernedFatalCause::ProjectionIntegrityFailure,
                },
                None => GovernedApprovalReducerInput::Remove {
                    generation,
                    position: GovernedApprovalDomainPosition::new(
                        position.epoch.clone(),
                        position.sequence,
                    ),
                    approval_request_id: approval_request_id.to_owned(),
                },
            }
        }
        ApprovalWatchClassification::Replay => GovernedApprovalReducerInput::Replay { generation },
        ApprovalWatchClassification::Heartbeat => {
            GovernedApprovalReducerInput::Heartbeat { generation }
        }
        ApprovalWatchClassification::ResetRequired => {
            GovernedApprovalReducerInput::Reset { generation }
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
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        num::NonZeroU32,
        pin::pin,
        sync::Arc,
        task::{Context, Poll, Waker},
    };

    use egopulse_client_kernel::{KernelError, KernelServerError};
    use egopulse_domain_contracts::v01::egopulse::{
        localapi::v1::{LocalApiError, LocalApiErrorCode, ProjectionHealth, ProjectionPosition},
        task::v1::TaskStatus,
    };

    use super::{
        ApprovalRequest, DomainAck, DriverFailure, DriverStage, GovernedStateSessionCore, Opened,
        TaskRequest, approval_complete_input_from_parts, approval_failure_input,
        approval_live_input_from_parts, approval_live_input_from_result, classify_approval_error,
        classify_task_error, clone_shared_pair, open_source_via, task_complete_input_from_parts,
        task_failure_input, task_live_input_from_result, task_live_input_from_update,
    };
    use crate::governed_state::{
        GovernedApprovalDomainState, GovernedApprovalReducerInput, GovernedApprovalState,
        GovernedFatalCause, GovernedRecoverableCause, GovernedStateComposite, GovernedStateDomain,
        GovernedStateDomainPhase, GovernedStateReason, GovernedTaskDomainState,
        GovernedTaskReducerInput,
    };
    use crate::{
        ApprovalWatchClassification, ClientApprovalWatchError, ClientGovernedTaskError,
        GovernedProjectionPosition, GovernedProjectionState, GovernedTaskState, GovernedTaskUpdate,
        TaskWatchClassification,
    };

    const STAGES: [DriverStage; 3] = [
        DriverStage::Initial,
        DriverStage::Recovery,
        DriverStage::Live,
    ];

    fn poll_ready_once<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("ready test future unexpectedly returned Pending"),
        }
    }

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

    fn governed_task(task_id: &str, position: &GovernedProjectionPosition) -> GovernedTaskState {
        GovernedTaskState {
            task_id: task_id.to_owned(),
            revision: 3,
            status: TaskStatus::Ready,
            resume_status: None,
            hold_reason: None,
            projection: GovernedProjectionState {
                position: position.clone(),
                health: ProjectionHealth::Ready,
                stale: false,
                reason: None,
            },
            run: None,
        }
    }

    #[test]
    fn r9b2b_task_live_update_maps_all_classifications_and_rejects_missing_applied_task() {
        let position = GovernedProjectionPosition {
            epoch: "epoch:task-live".to_owned(),
            sequence: 17,
        };
        let task = governed_task("task:live", &position);

        let applied = task_live_input_from_update(
            5,
            GovernedTaskUpdate {
                classification: TaskWatchClassification::Applied,
                position: position.clone(),
                task: Some(task.clone()),
            },
        );
        assert!(matches!(
            applied,
            GovernedTaskReducerInput::Applied {
                generation: 5,
                position: ref mapped_position,
                task: ref mapped_task,
            } if mapped_position.epoch() == "epoch:task-live"
                && mapped_position.sequence() == 17
                && mapped_task == &task
        ));

        assert!(matches!(
            task_live_input_from_update(
                5,
                GovernedTaskUpdate {
                    classification: TaskWatchClassification::Replay,
                    position: position.clone(),
                    task: None,
                },
            ),
            GovernedTaskReducerInput::Replay { generation: 5 }
        ));
        assert!(matches!(
            task_live_input_from_update(
                5,
                GovernedTaskUpdate {
                    classification: TaskWatchClassification::Heartbeat,
                    position: position.clone(),
                    task: None,
                },
            ),
            GovernedTaskReducerInput::Heartbeat { generation: 5 }
        ));
        assert!(matches!(
            task_live_input_from_update(
                5,
                GovernedTaskUpdate {
                    classification: TaskWatchClassification::ResetRequired,
                    position: position.clone(),
                    task: None,
                },
            ),
            GovernedTaskReducerInput::Reset { generation: 5 }
        ));

        assert!(matches!(
            task_live_input_from_update(
                5,
                GovernedTaskUpdate {
                    classification: TaskWatchClassification::Applied,
                    position,
                    task: None,
                },
            ),
            GovernedTaskReducerInput::Fatal {
                generation: 5,
                cause: GovernedFatalCause::ProjectionIntegrityFailure,
            }
        ));
    }

    #[test]
    fn r9b2b_approval_live_update_maps_applied_remove_replay_heartbeat_reset_and_eof() {
        let position = ProjectionPosition {
            epoch: "epoch:approval-live".to_owned(),
            sequence: 23,
            projected_at: None,
        };

        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::Applied,
                &position,
                Some("approval:1"),
                Some(GovernedApprovalState::new("approval:1", "task:1")),
            ),
            GovernedApprovalReducerInput::Applied {
                generation: 9,
                position: ref mapped_position,
                approval: ref mapped_approval,
            } if mapped_position.epoch() == "epoch:approval-live"
                && mapped_position.sequence() == 23
                && mapped_approval.approval_request_id() == "approval:1"
                && mapped_approval.task_id() == "task:1"
        ));
        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::Applied,
                &position,
                Some("approval:1"),
                None,
            ),
            GovernedApprovalReducerInput::Remove {
                generation: 9,
                position: ref mapped_position,
                ref approval_request_id,
            } if mapped_position.epoch() == "epoch:approval-live"
                && mapped_position.sequence() == 23
                && approval_request_id == "approval:1"
        ));
        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::Replay,
                &position,
                None,
                None,
            ),
            GovernedApprovalReducerInput::Replay { generation: 9 }
        ));
        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::Heartbeat,
                &position,
                None,
                None,
            ),
            GovernedApprovalReducerInput::Heartbeat { generation: 9 }
        ));
        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::ResetRequired,
                &position,
                None,
                None,
            ),
            GovernedApprovalReducerInput::Reset { generation: 9 }
        ));
        assert!(matches!(
            approval_live_input_from_parts(
                9,
                ApprovalWatchClassification::Applied,
                &position,
                None,
                None,
            ),
            GovernedApprovalReducerInput::Fatal {
                generation: 9,
                cause: GovernedFatalCause::ProjectionIntegrityFailure,
            }
        ));
        assert!(matches!(
            approval_failure_input(
                DriverStage::Live,
                9,
                DriverFailure::Recoverable(GovernedRecoverableCause::UnexpectedEof),
            ),
            GovernedApprovalReducerInput::RecoverableFailure {
                generation: 9,
                cause: GovernedRecoverableCause::UnexpectedEof,
            }
        ));
    }

    #[test]
    fn r9b2b_live_result_seams_fix_error_and_eof_mapping_to_live_stage() {
        assert!(matches!(
            task_live_input_from_result(12, Err(ClientGovernedTaskError::UnexpectedEof)),
            GovernedTaskReducerInput::RecoverableFailure {
                generation: 12,
                cause: GovernedRecoverableCause::UnexpectedEof,
            }
        ));

        let lookup_calls = Cell::new(0_u32);
        let eof = approval_live_input_from_result(13, Ok(None), |_| {
            lookup_calls.set(lookup_calls.get() + 1);
            None
        });
        assert!(matches!(
            eof,
            GovernedApprovalReducerInput::RecoverableFailure {
                generation: 13,
                cause: GovernedRecoverableCause::UnexpectedEof,
            }
        ));
        assert_eq!(lookup_calls.get(), 0);

        let reset = approval_live_input_from_result(
            14,
            Err(ClientApprovalWatchError::ResetBarrier),
            |_| {
                lookup_calls.set(lookup_calls.get() + 1);
                None
            },
        );
        assert!(matches!(
            reset,
            GovernedApprovalReducerInput::Reset { generation: 14 }
        ));
        assert_eq!(lookup_calls.get(), 0);
    }

    #[test]
    fn r9b2a_sources_clone_one_shared_attachment_identity() {
        let shared = Arc::new(());
        let (task, approval) = clone_shared_pair(Arc::clone(&shared));

        assert!(Arc::ptr_eq(&shared, &task));
        assert!(Arc::ptr_eq(&shared, &approval));
        assert!(Arc::ptr_eq(&task, &approval));
    }

    #[test]
    fn r9b2a_open_source_via_orders_read_open_and_complete() {
        let calls = RefCell::new(Vec::new());
        let opened = poll_ready_once(open_source_via(
            || {
                calls.borrow_mut().push("read");
                std::future::ready(Ok::<_, ()>("baseline"))
            },
            |baseline| {
                assert_eq!(baseline, "baseline");
                calls.borrow_mut().push("open");
                std::future::ready(Ok::<_, ()>("session"))
            },
            |session| {
                assert_eq!(*session, "session");
                calls.borrow_mut().push("complete");
                "complete-input"
            },
            |()| "mapped-error",
        ))
        .expect("ready source opens");
        let Opened {
            session,
            complete_input,
        } = opened;

        assert_eq!(session, "session");
        assert_eq!(complete_input, "complete-input");
        assert_eq!(*calls.borrow(), ["read", "open", "complete"]);
    }

    #[test]
    fn r9b2a_task_permission_denial_does_not_open_or_block_approval_source() {
        let task_open_calls = Cell::new(0_u64);
        let task_complete_calls = Cell::new(0_u64);
        let task_result = poll_ready_once(open_source_via(
            || {
                std::future::ready(Err::<&str, _>(ClientGovernedTaskError::Kernel(
                    KernelError::PermissionDenied("task.read".to_owned()),
                )))
            },
            |_baseline| {
                task_open_calls.set(task_open_calls.get() + 1);
                std::future::ready(Ok::<_, ClientGovernedTaskError>("task-session"))
            },
            |_session| {
                task_complete_calls.set(task_complete_calls.get() + 1);
                panic!("permission failure must not complete a Task source")
            },
            |error| {
                task_failure_input(
                    DriverStage::Initial,
                    3,
                    classify_task_error(DriverStage::Initial, &error),
                )
            },
        ));
        let Err(task_failure) = task_result else {
            panic!("permission failure must fail the Task source");
        };
        assert!(matches!(
            *task_failure,
            GovernedTaskReducerInput::Fatal {
                generation: 3,
                cause: GovernedFatalCause::PermissionDenied
            }
        ));
        assert_eq!(task_open_calls.get(), 0);
        assert_eq!(task_complete_calls.get(), 0);

        let approval_calls = RefCell::new(Vec::new());
        let approval = poll_ready_once(open_source_via(
            || {
                approval_calls.borrow_mut().push("read");
                std::future::ready(Ok::<_, ClientApprovalWatchError>("approval-baseline"))
            },
            |baseline| {
                assert_eq!(baseline, "approval-baseline");
                approval_calls.borrow_mut().push("open");
                std::future::ready(Ok::<_, ClientApprovalWatchError>("approval-session"))
            },
            |session| {
                assert_eq!(*session, "approval-session");
                approval_calls.borrow_mut().push("complete");
                "approval-input"
            },
            |_error| "approval-error",
        ))
        .expect("Approval source remains independent");

        assert_eq!(approval.session, "approval-session");
        assert_eq!(approval.complete_input, "approval-input");
        assert_eq!(*approval_calls.borrow(), ["read", "open", "complete"]);
    }

    #[test]
    fn r9b2b_session_core_starts_both_domains_connecting() {
        let (core, _task_sender, _approval_sender) = GovernedStateSessionCore::new();

        assert_eq!(
            core.state().task().phase(),
            GovernedStateDomainPhase::Connecting
        );
        assert_eq!(core.state().task().generation(), 1);
        assert_eq!(core.state().task().recovery_remaining(), 3);
        assert_eq!(
            core.state().approval().phase(),
            GovernedStateDomainPhase::Connecting
        );
        assert_eq!(core.state().approval().generation(), 1);
        assert_eq!(core.state().approval().recovery_remaining(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r9b2b_single_domain_apply_and_ack_leave_other_domain_unchanged() {
        let recovery_limit = NonZeroU32::new(2).expect("non-zero recovery limit");
        let (mut core, task_sender, _approval_sender) =
            GovernedStateSessionCore::with_recovery_limit(recovery_limit);
        let approval_before = core.state().approval().clone();
        let (ack_sender, ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            task_sender
                .try_send(TaskRequest {
                    input: GovernedTaskReducerInput::Fatal {
                        generation: 1,
                        cause: GovernedFatalCause::PermissionDenied,
                    },
                    ack: ack_sender,
                })
                .is_ok()
        );

        let update = core.next_update().await.expect("Task update");
        let ack = ack_receiver.await.expect("Task acknowledgement");
        assert_eq!(update.domain(), GovernedStateDomain::Task);
        assert_eq!(ack.phase, GovernedStateDomainPhase::Fatal);
        assert_eq!(ack.generation, 1);
        assert_eq!(ack.recovery_remaining, 2);
        assert_eq!(core.state().approval(), &approval_before);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r9b2b_simultaneously_ready_domains_are_strictly_alternated() {
        let (mut core, task_sender, approval_sender) = GovernedStateSessionCore::new();
        let (task_ack_sender, task_ack_receiver) = tokio::sync::oneshot::channel();
        let (approval_ack_sender, approval_ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            task_sender
                .try_send(TaskRequest {
                    input: GovernedTaskReducerInput::Fatal {
                        generation: 1,
                        cause: GovernedFatalCause::PermissionDenied,
                    },
                    ack: task_ack_sender,
                })
                .is_ok()
        );
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Fatal {
                        generation: 1,
                        cause: GovernedFatalCause::ApiRejected,
                    },
                    ack: approval_ack_sender,
                })
                .is_ok()
        );

        assert_eq!(
            core.next_update().await.expect("first update").domain(),
            GovernedStateDomain::Task
        );
        assert_eq!(
            core.next_update().await.expect("second update").domain(),
            GovernedStateDomain::Approval
        );
        assert_eq!(
            task_ack_receiver.await.expect("Task acknowledgement").phase,
            GovernedStateDomainPhase::Fatal
        );
        assert_eq!(
            approval_ack_receiver
                .await
                .expect("Approval acknowledgement")
                .phase,
            GovernedStateDomainPhase::Fatal
        );

        let (second_task_ack_sender, second_task_ack_receiver) = tokio::sync::oneshot::channel();
        let (second_approval_ack_sender, second_approval_ack_receiver) =
            tokio::sync::oneshot::channel();
        assert!(
            task_sender
                .try_send(TaskRequest {
                    input: GovernedTaskReducerInput::Replay { generation: 1 },
                    ack: second_task_ack_sender,
                })
                .is_ok()
        );
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Replay { generation: 1 },
                    ack: second_approval_ack_sender,
                })
                .is_ok()
        );
        assert_eq!(
            core.next_update().await.expect("third update").domain(),
            GovernedStateDomain::Task
        );
        assert_eq!(
            core.next_update().await.expect("fourth update").domain(),
            GovernedStateDomain::Approval
        );
        assert!(second_task_ack_receiver.await.is_ok());
        assert!(second_approval_ack_receiver.await.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r9b2b_pending_or_closed_domain_does_not_block_other_domain() {
        let (mut core, task_sender, approval_sender) = GovernedStateSessionCore::new();
        let (first_ack_sender, first_ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Replay { generation: 1 },
                    ack: first_ack_sender,
                })
                .is_ok()
        );
        assert_eq!(
            core.next_update()
                .await
                .expect("Approval bypasses pending Task domain")
                .domain(),
            GovernedStateDomain::Approval
        );
        assert_eq!(
            first_ack_receiver
                .await
                .expect("first Approval acknowledgement")
                .phase,
            GovernedStateDomainPhase::Connecting
        );

        drop(task_sender);
        let (second_ack_sender, second_ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Heartbeat { generation: 1 },
                    ack: second_ack_sender,
                })
                .is_ok()
        );
        assert_eq!(
            core.next_update()
                .await
                .expect("Approval bypasses closed Task domain")
                .domain(),
            GovernedStateDomain::Approval
        );
        assert_eq!(
            second_ack_receiver
                .await
                .expect("second Approval acknowledgement")
                .generation,
            1
        );

        drop(approval_sender);
        assert_eq!(core.next_update().await, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r9b2b_buffered_requests_survive_immediate_sender_drop_symmetrically() {
        let (mut core, task_sender, approval_sender) = GovernedStateSessionCore::new();
        let (task_ack_sender, task_ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            task_sender
                .try_send(TaskRequest {
                    input: GovernedTaskReducerInput::Replay { generation: 1 },
                    ack: task_ack_sender,
                })
                .is_ok()
        );
        drop(task_sender);
        assert_eq!(
            core.next_update()
                .await
                .expect("buffered Task request")
                .domain(),
            GovernedStateDomain::Task
        );
        assert!(task_ack_receiver.await.is_ok());

        let (approval_ack_sender, approval_ack_receiver) = tokio::sync::oneshot::channel();
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Replay { generation: 1 },
                    ack: approval_ack_sender,
                })
                .is_ok()
        );
        drop(approval_sender);
        assert_eq!(
            core.next_update()
                .await
                .expect("buffered Approval request")
                .domain(),
            GovernedStateDomain::Approval
        );
        assert!(approval_ack_receiver.await.is_ok());
        assert_eq!(core.next_update().await, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r9b2b_each_domain_channel_has_exact_capacity_one() {
        let (mut core, task_sender, approval_sender) = GovernedStateSessionCore::new();
        let (first_task_ack, first_task_receiver) = tokio::sync::oneshot::channel();
        assert!(
            task_sender
                .try_send(TaskRequest {
                    input: GovernedTaskReducerInput::Replay { generation: 1 },
                    ack: first_task_ack,
                })
                .is_ok()
        );
        let (second_task_ack, _second_task_receiver) = tokio::sync::oneshot::channel();
        assert!(matches!(
            task_sender.try_send(TaskRequest {
                input: GovernedTaskReducerInput::Replay { generation: 1 },
                ack: second_task_ack,
            }),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
        ));

        let (first_approval_ack, first_approval_receiver) = tokio::sync::oneshot::channel();
        assert!(
            approval_sender
                .try_send(ApprovalRequest {
                    input: GovernedApprovalReducerInput::Replay { generation: 1 },
                    ack: first_approval_ack,
                })
                .is_ok()
        );
        let (second_approval_ack, _second_approval_receiver) = tokio::sync::oneshot::channel();
        assert!(matches!(
            approval_sender.try_send(ApprovalRequest {
                input: GovernedApprovalReducerInput::Replay { generation: 1 },
                ack: second_approval_ack,
            }),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_))
        ));

        assert_eq!(
            core.next_update().await.expect("Task request").domain(),
            GovernedStateDomain::Task
        );
        assert_eq!(
            core.next_update().await.expect("Approval request").domain(),
            GovernedStateDomain::Approval
        );
        assert!(first_task_receiver.await.is_ok());
        assert!(first_approval_receiver.await.is_ok());
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

    #[test]
    fn r9b2a_task_complete_input_clones_only_safe_session_facts_and_position() {
        let position = GovernedProjectionPosition {
            epoch: "task-epoch:7".to_owned(),
            sequence: 41,
        };
        let first = governed_task("task:1", &position);
        let second = governed_task("task:2", &position);

        let input = task_complete_input_from_parts(8, &position, [&first, &second]);
        let GovernedTaskReducerInput::CompleteRebaseline {
            generation,
            position,
            tasks,
        } = input
        else {
            panic!("expected complete Task rebaseline input");
        };
        assert_eq!(generation, 8);
        assert_eq!(position.epoch(), "task-epoch:7");
        assert_eq!(position.sequence(), 41);
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks["task:1"], first);
        assert_eq!(tasks["task:2"], second);
    }

    #[test]
    fn r9b2a_approval_complete_input_contains_only_safe_ids_and_position() {
        let position = ProjectionPosition {
            epoch: "approval-epoch:9".to_owned(),
            sequence: 53,
            projected_at: None,
        };
        let input = approval_complete_input_from_parts(
            10,
            &position,
            [("approval:1", "task:1"), ("approval:2", "task:2")],
        );
        let GovernedApprovalReducerInput::CompleteRebaseline {
            generation,
            position,
            approvals,
        } = input
        else {
            panic!("expected complete Approval rebaseline input");
        };
        assert_eq!(generation, 10);
        assert_eq!(position.epoch(), "approval-epoch:9");
        assert_eq!(position.sequence(), 53);
        assert_eq!(approvals.len(), 2);
        assert_eq!(approvals["approval:1"].approval_request_id(), "approval:1");
        assert_eq!(approvals["approval:1"].task_id(), "task:1");
        assert_eq!(approvals["approval:2"].approval_request_id(), "approval:2");
        assert_eq!(approvals["approval:2"].task_id(), "task:2");
    }

    #[test]
    fn r9b2b_next_update_parks_on_empty_queues_and_wakes_on_approval_send() {
        let (mut core, _task_sender, approval_sender) =
            GovernedStateSessionCore::with_recovery_limit(
                NonZeroU32::new(3).expect("test recovery limit is non-zero"),
            );
        let mut next_update = pin!(core.next_update());
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            next_update.as_mut().poll(&mut context).is_pending(),
            "next_update must park while both capacity-one queues are empty"
        );

        let (ack, _ack_receiver) = tokio::sync::oneshot::channel();
        approval_sender
            .try_send(ApprovalRequest {
                input: GovernedApprovalReducerInput::Heartbeat { generation: 1 },
                ack,
            })
            .expect("capacity-one approval queue must accept one request");
        let update = match next_update.as_mut().poll(&mut context) {
            Poll::Ready(update) => update.expect("parked coordinator must not be finished"),
            Poll::Pending => panic!("queued approval request must make next_update ready"),
        };
        assert_eq!(update.domain(), GovernedStateDomain::Approval);
    }

    #[test]
    fn r9b2b_approval_ack_is_own_domain_only_and_leaves_task_state_untouched() {
        let (mut core, task_sender, approval_sender) =
            GovernedStateSessionCore::with_recovery_limit(
                NonZeroU32::new(3).expect("test recovery limit is non-zero"),
            );
        let task_before = core.state().task().clone();

        // A task recoverable failure first moves only the task domain.
        let (task_ack, mut task_ack_receiver) = tokio::sync::oneshot::channel();
        task_sender
            .try_send(TaskRequest {
                input: GovernedTaskReducerInput::RecoverableFailure {
                    generation: 1,
                    cause: GovernedRecoverableCause::TransportUnavailable,
                },
                ack: task_ack,
            })
            .expect("capacity-one task queue must accept one request");
        let task_update =
            poll_ready_once(core.next_update()).expect("task request must produce a task update");
        assert_eq!(task_update.domain(), GovernedStateDomain::Task);
        assert_eq!(
            task_ack_receiver
                .try_recv()
                .expect("ack must be ready after the coordinated apply"),
            DomainAck {
                phase: GovernedStateDomainPhase::Stale,
                generation: 2,
                recovery_remaining: 2,
            }
        );
        let task_after_failure = core.state().task().clone();
        assert_ne!(task_after_failure, task_before);

        // An approval heartbeat then acks exactly the approval domain facts.
        let (approval_ack, mut approval_ack_receiver) = tokio::sync::oneshot::channel();
        approval_sender
            .try_send(ApprovalRequest {
                input: GovernedApprovalReducerInput::Heartbeat { generation: 1 },
                ack: approval_ack,
            })
            .expect("capacity-one approval queue must accept one request");
        let approval_update = poll_ready_once(core.next_update())
            .expect("approval request must produce an approval update");
        assert_eq!(approval_update.domain(), GovernedStateDomain::Approval);
        let approval = core.state().approval();
        assert_eq!(
            approval_ack_receiver
                .try_recv()
                .expect("ack must be ready after the coordinated apply"),
            DomainAck {
                phase: approval.phase(),
                generation: approval.generation(),
                recovery_remaining: approval.recovery_remaining(),
            }
        );

        // The approval apply must not have touched the changed task state.
        assert_eq!(core.state().task(), &task_after_failure);
        assert_ne!(core.state().task(), &task_before);
    }

    #[test]
    fn r9b2b_dropped_ack_receiver_does_not_block_coordinator_or_other_domain() {
        let (mut core, task_sender, approval_sender) =
            GovernedStateSessionCore::with_recovery_limit(
                NonZeroU32::new(3).expect("test recovery limit is non-zero"),
            );

        // The ack consumer disappears before the coordinator applies the request.
        let (task_ack, task_ack_receiver) = tokio::sync::oneshot::channel();
        drop(task_ack_receiver);
        task_sender
            .try_send(TaskRequest {
                input: GovernedTaskReducerInput::Heartbeat { generation: 1 },
                ack: task_ack,
            })
            .expect("capacity-one task queue must accept one request");
        let task_update = poll_ready_once(core.next_update())
            .expect("coordinator must apply a request whose ack consumer vanished");
        assert_eq!(task_update.domain(), GovernedStateDomain::Task);
        assert_eq!(core.state().task().generation(), 1);

        // The coordinator keeps serving the other domain afterwards.
        let (approval_ack, mut approval_ack_receiver) = tokio::sync::oneshot::channel();
        approval_sender
            .try_send(ApprovalRequest {
                input: GovernedApprovalReducerInput::Heartbeat { generation: 1 },
                ack: approval_ack,
            })
            .expect("capacity-one approval queue must accept one request");
        let approval_update = poll_ready_once(core.next_update())
            .expect("other domain must continue after a dropped ack receiver");
        assert_eq!(approval_update.domain(), GovernedStateDomain::Approval);
        let approval = core.state().approval();
        assert_eq!(
            approval_ack_receiver
                .try_recv()
                .expect("ack must be ready after the coordinated apply"),
            DomainAck {
                phase: approval.phase(),
                generation: approval.generation(),
                recovery_remaining: approval.recovery_remaining(),
            }
        );
    }
}
