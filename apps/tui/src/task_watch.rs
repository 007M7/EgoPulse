use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_kernel::KernelError;
use egopulse_client_operations::{
    ClientAttachment, ClientGovernedTaskError, GovernedProjectionPosition, GovernedTaskBaseline,
    GovernedTaskSession, GovernedTaskState, GovernedTaskUpdate, TaskWatchClassification,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

pub const TASK_WATCH_CHANNEL_CAPACITY: usize = 32;
pub const TASK_WATCH_STOP_TIMEOUT: Duration = Duration::from_secs(1);
pub const TASK_WATCH_RECONNECT_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
    Duration::from_millis(2_000),
    Duration::from_millis(2_000),
];
pub const TASK_WATCH_MAX_AUTOMATIC_REBASES: u8 = 3;

pub type TaskWatchNextFuture<'a> =
    Pin<Box<dyn Future<Output = Result<GovernedTaskUpdate, ClientGovernedTaskError>> + Send + 'a>>;
pub type TaskWatchOpenFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Box<dyn TaskWatchStream>, ClientGovernedTaskError>> + Send + 'a>,
>;
pub type TaskWatchBaselineFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TaskWatchBaseline, ClientGovernedTaskError>> + Send + 'a>>;
type TaskWatchSleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait TaskWatchStream: Send {
    fn next_update(&mut self) -> TaskWatchNextFuture<'_>;
}

impl TaskWatchStream for GovernedTaskSession {
    fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
        Box::pin(GovernedTaskSession::next_update(self))
    }
}

/// The complete safe baseline and its private, consume-bound session token.
pub struct TaskWatchBaseline {
    model: TaskWatchPageModel,
    governed: Option<GovernedTaskBaseline>,
}

impl TaskWatchBaseline {
    fn from_governed(baseline: GovernedTaskBaseline) -> Self {
        let model = TaskWatchPageModel::new(
            baseline.position().clone(),
            baseline.tasks().into_iter().cloned().collect(),
        );
        Self {
            model,
            governed: Some(baseline),
        }
    }

    /// Adapts an already-safe projection for a custom `TaskWatchClient` component seam.
    ///
    /// This does not prove daemon or Authority participation; production clients use the
    /// consume-bound governed baseline above.
    #[doc(hidden)]
    pub fn from_safe_projection_adapter(
        position: GovernedProjectionPosition,
        tasks: Vec<GovernedTaskState>,
    ) -> Self {
        Self {
            model: TaskWatchPageModel::new(position, tasks),
            governed: None,
        }
    }
}

pub trait TaskWatchClient: Send + Sync {
    fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_>;
    fn open_task_watch_session(&self, baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_>;
}

impl TaskWatchClient for ClientAttachment {
    fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
        Box::pin(async move {
            self.read_governed_task_baseline()
                .await
                .map(TaskWatchBaseline::from_governed)
        })
    }

    fn open_task_watch_session(&self, mut baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
        Box::pin(async move {
            let governed = baseline
                .governed
                .take()
                .ok_or(ClientGovernedTaskError::Protocol(
                    "governed Task baseline token is unavailable",
                ))?;
            self.open_governed_task_session(governed)
                .await
                .map(|session| Box::new(session) as Box<dyn TaskWatchStream>)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskWatchPhase {
    Connecting,
    Live,
    Stale,
    FatalStopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskWatchPageModel {
    pub position: GovernedProjectionPosition,
    pub phase: TaskWatchPhase,
    pub tasks: Vec<GovernedTaskState>,
    pub selected_task_id: Option<String>,
    pub detail_scroll: u16,
    pub message: String,
}

impl TaskWatchPageModel {
    fn new(position: GovernedProjectionPosition, mut tasks: Vec<GovernedTaskState>) -> Self {
        tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
        let selected_task_id = tasks.first().map(|task| task.task_id.clone());
        Self {
            position,
            phase: TaskWatchPhase::Connecting,
            tasks,
            selected_task_id,
            detail_scroll: 0,
            message: "Task Watch baseline loaded; opening its consume-bound stream".to_owned(),
        }
    }

    /// Adapts an already-safe projection for custom component and rendering evidence.
    ///
    /// This does not prove daemon or Authority participation.
    #[doc(hidden)]
    #[must_use]
    pub fn from_safe_projection_adapter(
        position: GovernedProjectionPosition,
        tasks: Vec<GovernedTaskState>,
    ) -> Self {
        Self::new(position, tasks)
    }
}

#[derive(Clone, Copy)]
enum TaskWatchRecoveryReason {
    Transport,
    UnexpectedEof,
    ProjectionReset,
}

impl TaskWatchRecoveryReason {
    const fn message(self) -> &'static str {
        match self {
            Self::Transport => "Task Watch transport interrupted; refetching the complete baseline",
            Self::UnexpectedEof => "Task Watch ended; refetching the complete baseline",
            Self::ProjectionReset => "Task Watch reset; refetching the complete baseline",
        }
    }
}

#[derive(Clone, Copy)]
enum TaskWatchFatalReason {
    PermissionDenied,
    SessionInvalid,
    ApiRejected,
    BaselineLimit,
    ProjectionIntegrity,
    RebaseBudgetExhausted,
    ReconnectBudgetExhausted,
}

impl TaskWatchFatalReason {
    const fn message(self) -> &'static str {
        match self {
            Self::PermissionDenied => {
                "Task Watch permission was denied; press r after access is restored"
            }
            Self::SessionInvalid => "Task Watch session is unavailable; press r after reconnecting",
            Self::ApiRejected => "Task Watch request was rejected; no facts were applied",
            Self::BaselineLimit => "Task Watch baseline exceeded its safe item limit",
            Self::ProjectionIntegrity => {
                "Task Watch projection integrity failed; no facts were applied"
            }
            Self::RebaseBudgetExhausted => "Task Watch stopped after repeated projection resets",
            Self::ReconnectBudgetExhausted => "Task Watch stopped after bounded reconnect attempts",
        }
    }
}

enum TaskWatchWorkerEvent {
    Connected {
        generation: u64,
    },
    Replace {
        generation: u64,
        model: TaskWatchPageModel,
    },
    Update {
        generation: u64,
        update: GovernedTaskUpdate,
    },
    Stale {
        generation: u64,
        reason: TaskWatchRecoveryReason,
    },
    Failed {
        generation: u64,
        reason: TaskWatchFatalReason,
    },
}

impl TaskWatchWorkerEvent {
    const fn generation(&self) -> u64 {
        match self {
            Self::Connected { generation }
            | Self::Replace { generation, .. }
            | Self::Update { generation, .. }
            | Self::Stale { generation, .. }
            | Self::Failed { generation, .. } => *generation,
        }
    }
}

struct TaskWatchRuntime {
    events: mpsc::Receiver<TaskWatchWorkerEvent>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl TaskWatchRuntime {
    async fn stop(mut self) {
        let _ = self.cancel.send(true);
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if tokio::time::timeout(TASK_WATCH_STOP_TIMEOUT, &mut worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = tokio::time::timeout(TASK_WATCH_STOP_TIMEOUT, worker).await;
        }
    }
}

impl Drop for TaskWatchRuntime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

trait TaskWatchSleeper: Send + Sync {
    fn sleep(&self, duration: Duration) -> TaskWatchSleepFuture;
}

struct TokioTaskWatchSleeper;

impl TaskWatchSleeper for TokioTaskWatchSleeper {
    fn sleep(&self, duration: Duration) -> TaskWatchSleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

pub struct TaskWatchController<C: TaskWatchClient + ?Sized + 'static> {
    client: Arc<C>,
    model: Option<TaskWatchPageModel>,
    generation: u64,
    runtime: Option<TaskWatchRuntime>,
    sleeper: Arc<dyn TaskWatchSleeper>,
}

impl<C: TaskWatchClient + ?Sized + 'static> TaskWatchController<C> {
    #[must_use]
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            model: None,
            generation: 0,
            runtime: None,
            sleeper: Arc::new(TokioTaskWatchSleeper),
        }
    }

    #[cfg(test)]
    fn with_sleeper(client: Arc<C>, sleeper: Arc<dyn TaskWatchSleeper>) -> Self {
        Self {
            client,
            model: None,
            generation: 0,
            runtime: None,
            sleeper,
        }
    }

    #[must_use]
    pub fn model(&self) -> Option<&TaskWatchPageModel> {
        self.model.as_ref()
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let prior_selection = self
            .model
            .as_ref()
            .and_then(|model| model.selected_task_id.clone());
        let prior_index = self.model.as_ref().and_then(selected_task_index);
        self.stop().await;

        let baseline = self
            .client
            .read_task_watch_baseline()
            .await
            .map_err(|error| fatal_reason(&error).message().to_owned())?;
        let mut model = baseline.model.clone();
        reconcile_selection(&mut model, prior_selection.as_deref(), prior_index);
        self.model = Some(model);

        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        let (event_tx, event_rx) = mpsc::channel(TASK_WATCH_CHANNEL_CAPACITY);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let worker = tokio::spawn(run_task_watch_worker(
            self.client.clone(),
            generation,
            baseline,
            event_tx,
            cancel_rx,
            self.sleeper.clone(),
        ));
        self.runtime = Some(TaskWatchRuntime {
            events: event_rx,
            cancel: cancel_tx,
            worker: Some(worker),
        });
        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop().await;
        }
    }

    pub fn pump(&mut self) -> Result<(), String> {
        let Some(runtime) = self.runtime.as_mut() else {
            return Ok(());
        };
        let mut events = Vec::new();
        while let Ok(event) = runtime.events.try_recv() {
            events.push(event);
        }
        for event in events {
            if event.generation() != self.generation {
                continue;
            }
            match event {
                TaskWatchWorkerEvent::Connected { .. } => {
                    if let Some(model) = self.model.as_mut() {
                        model.phase = TaskWatchPhase::Live;
                        model.message =
                            "Task Watch live; governance facts are observation-only".to_owned();
                    }
                }
                TaskWatchWorkerEvent::Replace { mut model, .. } => {
                    let prior_selection = self
                        .model
                        .as_ref()
                        .and_then(|current| current.selected_task_id.clone());
                    let prior_index = self.model.as_ref().and_then(selected_task_index);
                    reconcile_selection(&mut model, prior_selection.as_deref(), prior_index);
                    model.detail_scroll = 0;
                    self.model = Some(model);
                }
                TaskWatchWorkerEvent::Update { update, .. } => self.apply_update(update)?,
                TaskWatchWorkerEvent::Stale { reason, .. } => {
                    if let Some(model) = self.model.as_mut() {
                        model.phase = TaskWatchPhase::Stale;
                        model.message = reason.message().to_owned();
                    }
                }
                TaskWatchWorkerEvent::Failed { reason, .. } => {
                    if let Some(model) = self.model.as_mut() {
                        model.phase = TaskWatchPhase::FatalStopped;
                        model.message = reason.message().to_owned();
                    }
                    self.runtime = None;
                    break;
                }
            }
        }
        Ok(())
    }

    fn apply_update(&mut self, update: GovernedTaskUpdate) -> Result<(), String> {
        let model = self
            .model
            .as_mut()
            .ok_or_else(|| "Task Watch safe baseline is unavailable".to_owned())?;
        match update.classification {
            TaskWatchClassification::Applied => {
                let task = update.task.ok_or_else(|| {
                    "Task Watch applied update omitted safe Task facts".to_owned()
                })?;
                let selected_changed =
                    model.selected_task_id.as_deref() == Some(task.task_id.as_str());
                match model
                    .tasks
                    .binary_search_by(|current| current.task_id.cmp(&task.task_id))
                {
                    Ok(index) => model.tasks[index] = task,
                    Err(index) => model.tasks.insert(index, task),
                }
                if model.selected_task_id.is_none() {
                    model.selected_task_id = model.tasks.first().map(|item| item.task_id.clone());
                }
                if selected_changed {
                    model.detail_scroll = 0;
                }
            }
            TaskWatchClassification::Replay => {
                // Replayed safe snapshots are evidence that the cursor was already consumed;
                // the U-05 session reducer deliberately leaves the current map untouched.
            }
            TaskWatchClassification::Heartbeat => {
                if update.task.is_some() {
                    return Err("Task Watch non-applied update carried Task facts".to_owned());
                }
            }
            TaskWatchClassification::ResetRequired => {
                return Err("Task Watch reset crossed the worker barrier".to_owned());
            }
        }
        model.position = update.position;
        model.phase = TaskWatchPhase::Live;
        model.message = "Task Watch live; governance facts are observation-only".to_owned();
        Ok(())
    }

    pub fn select_next(&mut self) {
        self.move_selection(1);
    }

    pub fn select_previous(&mut self) {
        self.move_selection(-1);
    }

    fn move_selection(&mut self, delta: isize) {
        let Some(model) = self.model.as_mut() else {
            return;
        };
        if model.tasks.is_empty() {
            model.selected_task_id = None;
            model.detail_scroll = 0;
            return;
        }
        let current = selected_task_index(model).unwrap_or(0) as isize;
        let maximum = model.tasks.len().saturating_sub(1) as isize;
        let next = (current + delta).clamp(0, maximum) as usize;
        if model.selected_task_id.as_deref() != Some(model.tasks[next].task_id.as_str()) {
            model.selected_task_id = Some(model.tasks[next].task_id.clone());
            model.detail_scroll = 0;
        }
    }

    pub fn select_task(&mut self, task_id: &str) -> bool {
        let Some(model) = self.model.as_mut() else {
            return false;
        };
        if model.tasks.iter().any(|task| task.task_id == task_id) {
            if model.selected_task_id.as_deref() != Some(task_id) {
                model.detail_scroll = 0;
            }
            model.selected_task_id = Some(task_id.to_owned());
            true
        } else {
            false
        }
    }

    pub fn clear_selection(&mut self) {
        if let Some(model) = self.model.as_mut() {
            model.selected_task_id = None;
            model.detail_scroll = 0;
        }
    }

    pub fn scroll_detail_down(&mut self) {
        if let Some(model) = self.model.as_mut() {
            let maximum = selected_detail_line_count(model)
                .saturating_sub(1)
                .min(usize::from(u16::MAX)) as u16;
            model.detail_scroll = model.detail_scroll.saturating_add(1).min(maximum);
        }
    }

    pub fn scroll_detail_up(&mut self) {
        if let Some(model) = self.model.as_mut() {
            model.detail_scroll = model.detail_scroll.saturating_sub(1);
        }
    }
}

fn selected_detail_line_count(model: &TaskWatchPageModel) -> usize {
    let Some(task) = model
        .selected_task_id
        .as_deref()
        .and_then(|selected| model.tasks.iter().find(|task| task.task_id == selected))
    else {
        return 1;
    };
    let run_lines = task.run.as_ref().map_or(1, |run| {
        1 + run
            .steps
            .iter()
            .map(|step| 1 + step.attempts.len().saturating_mul(2))
            .sum::<usize>()
    });
    3 + run_lines + 1
}

fn selected_task_index(model: &TaskWatchPageModel) -> Option<usize> {
    let selected = model.selected_task_id.as_deref()?;
    model.tasks.iter().position(|task| task.task_id == selected)
}

fn reconcile_selection(
    model: &mut TaskWatchPageModel,
    prior_selection: Option<&str>,
    prior_index: Option<usize>,
) {
    if let Some(selected) = prior_selection
        && model.tasks.iter().any(|task| task.task_id == selected)
    {
        model.selected_task_id = Some(selected.to_owned());
        return;
    }
    model.selected_task_id = prior_index
        .and_then(|index| {
            model
                .tasks
                .get(index.min(model.tasks.len().saturating_sub(1)))
        })
        .or_else(|| model.tasks.first())
        .map(|task| task.task_id.clone());
    if prior_selection.is_some() {
        model.message = "The selected Task left the projection; selection moved safely".to_owned();
    }
}

fn fatal_reason(error: &ClientGovernedTaskError) -> TaskWatchFatalReason {
    match error {
        ClientGovernedTaskError::Kernel(KernelError::PermissionDenied(_)) => {
            TaskWatchFatalReason::PermissionDenied
        }
        ClientGovernedTaskError::Kernel(KernelError::SessionUnavailable)
        | ClientGovernedTaskError::Kernel(_) => TaskWatchFatalReason::SessionInvalid,
        ClientGovernedTaskError::Api(error)
            if error.code == LocalApiErrorCode::PermissionDenied as i32 =>
        {
            TaskWatchFatalReason::PermissionDenied
        }
        ClientGovernedTaskError::Api(_) => TaskWatchFatalReason::ApiRejected,
        ClientGovernedTaskError::BaselineLimitExceeded => TaskWatchFatalReason::BaselineLimit,
        ClientGovernedTaskError::Protocol(_) | ClientGovernedTaskError::ResetBarrier => {
            TaskWatchFatalReason::ProjectionIntegrity
        }
        ClientGovernedTaskError::Transport(_) | ClientGovernedTaskError::UnexpectedEof => {
            TaskWatchFatalReason::ReconnectBudgetExhausted
        }
    }
}

fn transient_reason(error: &ClientGovernedTaskError) -> Option<TaskWatchRecoveryReason> {
    match error {
        ClientGovernedTaskError::Transport(_) => Some(TaskWatchRecoveryReason::Transport),
        ClientGovernedTaskError::UnexpectedEof => Some(TaskWatchRecoveryReason::UnexpectedEof),
        ClientGovernedTaskError::ResetBarrier => Some(TaskWatchRecoveryReason::ProjectionReset),
        _ => None,
    }
}

async fn send_event(
    event_tx: &mpsc::Sender<TaskWatchWorkerEvent>,
    cancel_rx: &mut watch::Receiver<bool>,
    event: TaskWatchWorkerEvent,
) -> bool {
    tokio::select! {
        biased;
        changed = cancel_rx.changed() => changed.is_err() || *cancel_rx.borrow(),
        result = event_tx.send(event) => result.is_err(),
    }
}

async fn sleep_or_cancel(
    sleeper: &dyn TaskWatchSleeper,
    delay: Duration,
    cancel_rx: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        changed = cancel_rx.changed() => changed.is_err() || *cancel_rx.borrow(),
        () = sleeper.sleep(delay) => false,
    }
}

async fn run_task_watch_worker<C: TaskWatchClient + ?Sized + 'static>(
    client: Arc<C>,
    generation: u64,
    initial_baseline: TaskWatchBaseline,
    event_tx: mpsc::Sender<TaskWatchWorkerEvent>,
    mut cancel_rx: watch::Receiver<bool>,
    sleeper: Arc<dyn TaskWatchSleeper>,
) {
    let mut baseline = Some(initial_baseline);
    let mut session: Option<Box<dyn TaskWatchStream>> = None;
    let mut reconnect_index = 0_usize;
    let mut automatic_rebases = 0_u8;
    let mut reset_floor: Option<GovernedProjectionPosition> = None;
    let mut session_floor: Option<GovernedProjectionPosition> = None;

    loop {
        if *cancel_rx.borrow() {
            return;
        }

        if session.is_none() {
            let next_baseline = match baseline.take() {
                Some(value) => value,
                None => match client.read_task_watch_baseline().await {
                    Ok(value) => {
                        let floor = value.model.position.clone();
                        if automatic_rebases > 0 {
                            reset_floor = Some(floor);
                        }
                        if send_event(
                            &event_tx,
                            &mut cancel_rx,
                            TaskWatchWorkerEvent::Replace {
                                generation,
                                model: value.model.clone(),
                            },
                        )
                        .await
                        {
                            return;
                        }
                        value
                    }
                    Err(error) => {
                        if transient_reason(&error).is_some()
                            && reconnect_index < TASK_WATCH_RECONNECT_DELAYS.len()
                        {
                            let delay = TASK_WATCH_RECONNECT_DELAYS[reconnect_index];
                            reconnect_index += 1;
                            if sleep_or_cancel(sleeper.as_ref(), delay, &mut cancel_rx).await {
                                return;
                            }
                            continue;
                        }
                        let reason = if transient_reason(&error).is_some() {
                            TaskWatchFatalReason::ReconnectBudgetExhausted
                        } else {
                            fatal_reason(&error)
                        };
                        let _ = send_event(
                            &event_tx,
                            &mut cancel_rx,
                            TaskWatchWorkerEvent::Failed { generation, reason },
                        )
                        .await;
                        return;
                    }
                },
            };
            let next_session_floor = next_baseline.model.position.clone();
            match client.open_task_watch_session(next_baseline).await {
                Ok(opened) => {
                    session = Some(opened);
                    session_floor = Some(next_session_floor);
                    if send_event(
                        &event_tx,
                        &mut cancel_rx,
                        TaskWatchWorkerEvent::Connected { generation },
                    )
                    .await
                    {
                        return;
                    }
                }
                Err(error) => {
                    if transient_reason(&error).is_some()
                        && reconnect_index < TASK_WATCH_RECONNECT_DELAYS.len()
                    {
                        let reason = transient_reason(&error).expect("checked transient reason");
                        if send_event(
                            &event_tx,
                            &mut cancel_rx,
                            TaskWatchWorkerEvent::Stale { generation, reason },
                        )
                        .await
                        {
                            return;
                        }
                        let delay = TASK_WATCH_RECONNECT_DELAYS[reconnect_index];
                        reconnect_index += 1;
                        if sleep_or_cancel(sleeper.as_ref(), delay, &mut cancel_rx).await {
                            return;
                        }
                        continue;
                    }
                    let reason = if transient_reason(&error).is_some() {
                        TaskWatchFatalReason::ReconnectBudgetExhausted
                    } else {
                        fatal_reason(&error)
                    };
                    let _ = send_event(
                        &event_tx,
                        &mut cancel_rx,
                        TaskWatchWorkerEvent::Failed { generation, reason },
                    )
                    .await;
                    return;
                }
            }
        }

        let update = tokio::select! {
            biased;
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() { return; }
                continue;
            }
            result = session.as_mut().expect("session established").next_update() => result,
        };

        match update {
            Ok(update) if update.classification == TaskWatchClassification::ResetRequired => {
                session = None;
                automatic_rebases = automatic_rebases.saturating_add(1);
                if automatic_rebases > TASK_WATCH_MAX_AUTOMATIC_REBASES {
                    let _ = send_event(
                        &event_tx,
                        &mut cancel_rx,
                        TaskWatchWorkerEvent::Failed {
                            generation,
                            reason: TaskWatchFatalReason::RebaseBudgetExhausted,
                        },
                    )
                    .await;
                    return;
                }
                if send_event(
                    &event_tx,
                    &mut cancel_rx,
                    TaskWatchWorkerEvent::Stale {
                        generation,
                        reason: TaskWatchRecoveryReason::ProjectionReset,
                    },
                )
                .await
                {
                    return;
                }
            }
            Ok(update) => {
                if let Some(floor) = reset_floor.as_ref()
                    && matches!(
                        update.classification,
                        TaskWatchClassification::Applied | TaskWatchClassification::Heartbeat
                    )
                    && update.position.epoch == floor.epoch
                    && update.position.sequence > floor.sequence
                {
                    automatic_rebases = 0;
                    reset_floor = None;
                }
                if let Some(floor) = session_floor.as_ref()
                    && matches!(
                        update.classification,
                        TaskWatchClassification::Applied | TaskWatchClassification::Heartbeat
                    )
                    && update.position.epoch == floor.epoch
                    && update.position.sequence > floor.sequence
                {
                    reconnect_index = 0;
                }
                if send_event(
                    &event_tx,
                    &mut cancel_rx,
                    TaskWatchWorkerEvent::Update { generation, update },
                )
                .await
                {
                    return;
                }
            }
            Err(error) => {
                let Some(reason) = transient_reason(&error) else {
                    let _ = send_event(
                        &event_tx,
                        &mut cancel_rx,
                        TaskWatchWorkerEvent::Failed {
                            generation,
                            reason: fatal_reason(&error),
                        },
                    )
                    .await;
                    return;
                };
                session = None;
                if send_event(
                    &event_tx,
                    &mut cancel_rx,
                    TaskWatchWorkerEvent::Stale { generation, reason },
                )
                .await
                {
                    return;
                }
                if reconnect_index >= TASK_WATCH_RECONNECT_DELAYS.len() {
                    let _ = send_event(
                        &event_tx,
                        &mut cancel_rx,
                        TaskWatchWorkerEvent::Failed {
                            generation,
                            reason: TaskWatchFatalReason::ReconnectBudgetExhausted,
                        },
                    )
                    .await;
                    return;
                }
                let delay = TASK_WATCH_RECONNECT_DELAYS[reconnect_index];
                reconnect_index += 1;
                if sleep_or_cancel(sleeper.as_ref(), delay, &mut cancel_rx).await {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use egopulse_client_operations::{
        GovernedAttemptState, GovernedHoldReason, GovernedProjectionState, GovernedRunState,
        GovernedStepState,
    };
    use egopulse_domain_contracts::v01::egopulse::{
        collaboration::v1::{AttemptStatus, RecoveryClass, RunStatus, StepStatus},
        localapi::v1::ProjectionHealth,
        task::v1::TaskStatus,
    };

    enum StreamStep {
        Update(GovernedTaskUpdate),
        Error(ClientGovernedTaskError),
        Pending,
    }

    struct ScriptedStream {
        steps: VecDeque<StreamStep>,
        next_calls: Arc<AtomicUsize>,
    }

    impl TaskWatchStream for ScriptedStream {
        fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
            self.next_calls.fetch_add(1, Ordering::SeqCst);
            let step = self.steps.pop_front().unwrap_or(StreamStep::Pending);
            Box::pin(async move {
                match step {
                    StreamStep::Update(update) => Ok(update),
                    StreamStep::Error(error) => Err(error),
                    StreamStep::Pending => std::future::pending().await,
                }
            })
        }
    }

    struct ScriptedClient {
        baselines: Mutex<VecDeque<Result<TaskWatchBaseline, ClientGovernedTaskError>>>,
        streams: Mutex<VecDeque<VecDeque<StreamStep>>>,
        calls: Mutex<Vec<&'static str>>,
        next_calls: Arc<AtomicUsize>,
    }

    impl ScriptedClient {
        fn new(
            baselines: VecDeque<Result<TaskWatchBaseline, ClientGovernedTaskError>>,
            streams: VecDeque<VecDeque<StreamStep>>,
        ) -> Self {
            Self {
                baselines: Mutex::new(baselines),
                streams: Mutex::new(streams),
                calls: Mutex::new(Vec::new()),
                next_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl TaskWatchClient for ScriptedClient {
        fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            self.calls.lock().unwrap().push("baseline");
            let result = self.baselines.lock().unwrap().pop_front().unwrap_or(Err(
                ClientGovernedTaskError::Protocol("scripted baseline exhausted"),
            ));
            Box::pin(std::future::ready(result))
        }

        fn open_task_watch_session(&self, _baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
            self.calls.lock().unwrap().push("open");
            let steps = self
                .streams
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| VecDeque::from([StreamStep::Pending]));
            let next_calls = Arc::clone(&self.next_calls);
            Box::pin(async move {
                Ok(Box::new(ScriptedStream { steps, next_calls }) as Box<dyn TaskWatchStream>)
            })
        }
    }

    struct FailingOpenClient {
        open_calls: AtomicUsize,
    }

    impl TaskWatchClient for FailingOpenClient {
        fn read_task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            Box::pin(std::future::ready(Ok(baseline(
                10,
                vec![task("task:connecting", 10, 1)],
            ))))
        }

        fn open_task_watch_session(&self, _baseline: TaskWatchBaseline) -> TaskWatchOpenFuture<'_> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Err(ClientGovernedTaskError::Protocol(
                "scripted open failure",
            ))))
        }
    }

    struct ImmediateSleeper;

    impl TaskWatchSleeper for ImmediateSleeper {
        fn sleep(&self, _duration: Duration) -> TaskWatchSleepFuture {
            Box::pin(std::future::ready(()))
        }
    }

    fn position(sequence: u64) -> GovernedProjectionPosition {
        GovernedProjectionPosition {
            epoch: "epoch:u05-tui".to_owned(),
            sequence,
        }
    }

    fn task(task_id: &str, sequence: u64, attempt_count: usize) -> GovernedTaskState {
        let projection_position = position(sequence);
        let attempts = (0..attempt_count)
            .map(|index| GovernedAttemptState {
                attempt_id: format!("attempt:{task_id}:{index}"),
                revision: (index + 1) as u64,
                attempt_number: (index + 1) as u32,
                status: AttemptStatus::Held,
                recovery_class: RecoveryClass::ManualOnly,
                hold_reason: Some(GovernedHoldReason::ManualRecoveryRequired),
                last_harness_sequence: index as u64,
                checkpoint_reference_recorded: index % 2 == 0,
            })
            .collect::<Vec<_>>();
        GovernedTaskState {
            task_id: task_id.to_owned(),
            revision: 7,
            status: TaskStatus::Active,
            resume_status: None,
            hold_reason: None,
            projection: GovernedProjectionState {
                position: projection_position,
                health: ProjectionHealth::Ready,
                stale: false,
                reason: None,
            },
            run: Some(GovernedRunState {
                run_id: format!("run:{task_id}"),
                revision: 6,
                status: RunStatus::Returned,
                work_revision: 1,
                hold_reason: None,
                steps: vec![GovernedStepState {
                    step_id: format!("step:{task_id}"),
                    revision: 5,
                    status: StepStatus::Held,
                    hold_reason: Some(GovernedHoldReason::ManualRecoveryRequired),
                    current_attempt_id: attempts.last().map(|attempt| attempt.attempt_id.clone()),
                    attempts,
                }],
            }),
        }
    }

    fn baseline(sequence: u64, tasks: Vec<GovernedTaskState>) -> TaskWatchBaseline {
        TaskWatchBaseline::from_safe_projection_adapter(position(sequence), tasks)
    }

    fn update(
        classification: TaskWatchClassification,
        sequence: u64,
        task: Option<GovernedTaskState>,
    ) -> GovernedTaskUpdate {
        GovernedTaskUpdate {
            classification,
            position: position(sequence),
            task,
        }
    }

    async fn pump_until<C: TaskWatchClient + ?Sized + 'static>(
        controller: &mut TaskWatchController<C>,
        predicate: impl Fn(&TaskWatchController<C>) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                controller.pump().unwrap();
                if predicate(controller) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("controller condition");
    }

    #[tokio::test]
    async fn complete_baseline_is_published_before_its_consume_bound_session_opens() {
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([Ok(baseline(
                10,
                vec![task("task:b", 10, 1), task("task:a", 10, 1)],
            ))]),
            VecDeque::from([VecDeque::from([StreamStep::Pending])]),
        ));
        let mut controller = TaskWatchController::new(Arc::clone(&client));
        controller.start().await.unwrap();
        assert_eq!(
            controller
                .model()
                .unwrap()
                .tasks
                .iter()
                .map(|task| task.task_id.as_str())
                .collect::<Vec<_>>(),
            ["task:a", "task:b"]
        );
        assert_eq!(client.calls.lock().unwrap().as_slice(), ["baseline"]);
        assert_eq!(
            controller.model().unwrap().phase,
            TaskWatchPhase::Connecting
        );
        pump_until(&mut controller, |controller| {
            controller.model().unwrap().phase == TaskWatchPhase::Live
        })
        .await;
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["baseline", "open"]
        );
        controller.stop().await;
    }

    #[tokio::test]
    async fn failed_session_open_never_claims_the_published_baseline_is_live() {
        let client = Arc::new(FailingOpenClient {
            open_calls: AtomicUsize::new(0),
        });
        let mut controller = TaskWatchController::new(Arc::clone(&client));
        controller.start().await.unwrap();
        assert_eq!(
            controller.model().unwrap().phase,
            TaskWatchPhase::Connecting
        );
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        assert_eq!(client.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.model().unwrap().phase,
            TaskWatchPhase::FatalStopped
        );
    }

    #[tokio::test]
    async fn applied_updates_safe_tree_while_replay_snapshot_and_heartbeat_leave_facts_unchanged() {
        let original = task("task:active", 10, 2);
        assert_eq!(original.status, TaskStatus::Active);
        assert_eq!(original.run.as_ref().unwrap().status, RunStatus::Returned);
        let replay_canary = task("sensitive-replay-canary", 10, 1);
        let mut changed = original.clone();
        changed.revision = 8;
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([Ok(baseline(10, vec![original.clone()]))]),
            VecDeque::from([VecDeque::from([
                StreamStep::Update(update(
                    TaskWatchClassification::Replay,
                    10,
                    Some(replay_canary),
                )),
                StreamStep::Update(update(TaskWatchClassification::Heartbeat, 11, None)),
                StreamStep::Update(update(
                    TaskWatchClassification::Applied,
                    12,
                    Some(changed.clone()),
                )),
                StreamStep::Pending,
            ])]),
        ));
        let mut controller = TaskWatchController::new(client);
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| {
            controller.model().unwrap().position.sequence == 12
        })
        .await;
        let model = controller.model().unwrap();
        assert_eq!(model.tasks, [changed]);
        assert_eq!(model.tasks[0].status, TaskStatus::Active);
        assert_eq!(
            model.tasks[0].run.as_ref().unwrap().status,
            RunStatus::Returned
        );
        assert!(!format!("{model:?}").contains("sensitive-replay-canary"));
        controller.stop().await;
    }

    #[tokio::test]
    async fn same_position_replay_applied_and_heartbeat_do_not_clear_reset_budget() {
        let mut streams = VecDeque::new();
        streams.push_back(VecDeque::from([StreamStep::Update(update(
            TaskWatchClassification::ResetRequired,
            10,
            None,
        ))]));
        streams.push_back(VecDeque::from([
            StreamStep::Update(update(
                TaskWatchClassification::Replay,
                10,
                Some(task("task:replay", 10, 1)),
            )),
            StreamStep::Update(update(TaskWatchClassification::ResetRequired, 10, None)),
        ]));
        streams.push_back(VecDeque::from([
            StreamStep::Update(update(
                TaskWatchClassification::Applied,
                10,
                Some(task("task:same", 10, 1)),
            )),
            StreamStep::Update(update(TaskWatchClassification::ResetRequired, 10, None)),
        ]));
        streams.push_back(VecDeque::from([
            StreamStep::Update(update(TaskWatchClassification::Heartbeat, 10, None)),
            StreamStep::Update(update(TaskWatchClassification::ResetRequired, 10, None)),
        ]));
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([
                Ok(baseline(10, vec![task("task:a", 10, 1)])),
                Ok(baseline(10, vec![task("task:a", 10, 1)])),
                Ok(baseline(10, vec![task("task:a", 10, 1)])),
                Ok(baseline(10, vec![task("task:a", 10, 1)])),
            ]),
            streams,
        ));
        let mut controller = TaskWatchController::with_sleeper(client, Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        assert_eq!(
            controller.model().unwrap().phase,
            TaskWatchPhase::FatalStopped
        );
        assert_eq!(
            controller.model().unwrap().message,
            TaskWatchFatalReason::RebaseBudgetExhausted.message()
        );
    }

    async fn later_update_clears_reset_budget(classification: TaskWatchClassification) {
        let mut baselines = VecDeque::new();
        let mut streams = VecDeque::new();
        baselines.push_back(Ok(baseline(10, vec![task("task:a", 10, 1)])));
        streams.push_back(VecDeque::from([StreamStep::Update(update(
            TaskWatchClassification::ResetRequired,
            10,
            None,
        ))]));
        for cycle in 0..4 {
            baselines.push_back(Ok(baseline(10, vec![task("task:a", 10, 1)])));
            let fact = (classification == TaskWatchClassification::Applied)
                .then(|| task(&format!("task:later:{cycle}"), 11, 1));
            streams.push_back(VecDeque::from([
                StreamStep::Update(update(classification, 11, fact)),
                StreamStep::Update(update(TaskWatchClassification::ResetRequired, 11, None)),
            ]));
        }
        baselines.push_back(Ok(baseline(11, vec![task("task:done", 11, 1)])));
        streams.push_back(VecDeque::from([StreamStep::Pending]));
        let client = Arc::new(ScriptedClient::new(baselines, streams));
        let mut controller =
            TaskWatchController::with_sleeper(Arc::clone(&client), Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| {
            client
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| **call == "open")
                .count()
                == 6
                && controller.is_running()
        })
        .await;
        assert_ne!(
            controller.model().unwrap().phase,
            TaskWatchPhase::FatalStopped
        );
        controller.stop().await;
    }

    #[tokio::test]
    async fn strictly_later_applied_clears_automatic_reset_budget() {
        later_update_clears_reset_budget(TaskWatchClassification::Applied).await;
    }

    #[tokio::test]
    async fn strictly_later_heartbeat_clears_automatic_reset_budget() {
        later_update_clears_reset_budget(TaskWatchClassification::Heartbeat).await;
    }

    #[tokio::test]
    async fn eof_and_transport_use_bounded_full_rebaseline_without_leaking_details() {
        for error in [
            ClientGovernedTaskError::UnexpectedEof,
            ClientGovernedTaskError::Transport("sensitive-transport-canary".to_owned()),
        ] {
            let client = Arc::new(ScriptedClient::new(
                VecDeque::from([
                    Ok(baseline(10, vec![task("task:old", 10, 1)])),
                    Ok(baseline(11, vec![task("task:new", 11, 1)])),
                ]),
                VecDeque::from([
                    VecDeque::from([StreamStep::Error(error)]),
                    VecDeque::from([StreamStep::Pending]),
                ]),
            ));
            let mut controller =
                TaskWatchController::with_sleeper(client, Arc::new(ImmediateSleeper));
            controller.start().await.unwrap();
            pump_until(&mut controller, |controller| {
                controller.model().unwrap().position.sequence == 11
            })
            .await;
            let model = controller.model().unwrap();
            assert_eq!(model.tasks[0].task_id, "task:new");
            assert!(!model.message.contains("sensitive-transport-canary"));
            controller.stop().await;
        }
    }

    #[tokio::test]
    async fn repeated_transport_failure_exhausts_five_delays_without_hot_loop() {
        let baselines = VecDeque::from_iter(
            (0..=TASK_WATCH_RECONNECT_DELAYS.len())
                .map(|_| Ok(baseline(10, vec![task("task:stable", 10, 1)]))),
        );
        let streams = VecDeque::from_iter((0..=TASK_WATCH_RECONNECT_DELAYS.len()).map(|_| {
            VecDeque::from([StreamStep::Error(ClientGovernedTaskError::Transport(
                "sensitive-reconnect-canary".to_owned(),
            ))])
        }));
        let client = Arc::new(ScriptedClient::new(baselines, streams));
        let mut controller =
            TaskWatchController::with_sleeper(Arc::clone(&client), Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        assert_eq!(
            controller.model().unwrap().message,
            TaskWatchFatalReason::ReconnectBudgetExhausted.message()
        );
        assert!(!controller.model().unwrap().message.contains("canary"));
        let calls = client.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|call| **call == "baseline").count(), 6);
        assert_eq!(calls.iter().filter(|call| **call == "open").count(), 6);
        assert_eq!(client.next_calls.load(Ordering::SeqCst), 6);
    }

    #[derive(Clone, Copy)]
    enum ScriptedTransientFailure {
        Transport,
        Eof,
    }

    fn transient_stream_step(failure: ScriptedTransientFailure) -> StreamStep {
        match failure {
            ScriptedTransientFailure::Transport => StreamStep::Error(
                ClientGovernedTaskError::Transport("sensitive-reconnect-canary".to_owned()),
            ),
            ScriptedTransientFailure::Eof => {
                StreamStep::Error(ClientGovernedTaskError::UnexpectedEof)
            }
        }
    }

    async fn non_progress_update_does_not_reset_reconnect_budget(
        classification: TaskWatchClassification,
        failure: ScriptedTransientFailure,
    ) {
        let baselines = VecDeque::from_iter(
            (0..=TASK_WATCH_RECONNECT_DELAYS.len())
                .map(|_| Ok(baseline(10, vec![task("task:stable", 10, 1)]))),
        );
        let streams = VecDeque::from_iter((0..=TASK_WATCH_RECONNECT_DELAYS.len()).map(|cycle| {
            let fact = matches!(
                classification,
                TaskWatchClassification::Applied | TaskWatchClassification::Replay
            )
            .then(|| task(&format!("task:non-progress:{cycle}"), 10, 1));
            VecDeque::from([
                StreamStep::Update(update(classification, 10, fact)),
                transient_stream_step(failure),
            ])
        }));
        let client = Arc::new(ScriptedClient::new(baselines, streams));
        let mut controller =
            TaskWatchController::with_sleeper(Arc::clone(&client), Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        assert_eq!(
            controller.model().unwrap().message,
            TaskWatchFatalReason::ReconnectBudgetExhausted.message()
        );
        assert_eq!(
            client
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| **call == "open")
                .count(),
            6
        );
        assert_eq!(client.next_calls.load(Ordering::SeqCst), 12);
    }

    #[tokio::test]
    async fn replay_and_same_position_updates_cannot_make_reconnect_unbounded() {
        non_progress_update_does_not_reset_reconnect_budget(
            TaskWatchClassification::Replay,
            ScriptedTransientFailure::Transport,
        )
        .await;
        non_progress_update_does_not_reset_reconnect_budget(
            TaskWatchClassification::Replay,
            ScriptedTransientFailure::Eof,
        )
        .await;
        non_progress_update_does_not_reset_reconnect_budget(
            TaskWatchClassification::Applied,
            ScriptedTransientFailure::Transport,
        )
        .await;
        non_progress_update_does_not_reset_reconnect_budget(
            TaskWatchClassification::Heartbeat,
            ScriptedTransientFailure::Transport,
        )
        .await;
    }

    async fn strict_live_progress_resets_reconnect_budget(classification: TaskWatchClassification) {
        let baselines = VecDeque::from_iter((0..7).map(|index| {
            let sequence = if index == 6 { 11 } else { 10 };
            Ok(baseline(sequence, vec![task("task:stable", sequence, 1)]))
        }));
        let mut streams =
            VecDeque::from_iter((0..5).map(|_| {
                VecDeque::from([transient_stream_step(ScriptedTransientFailure::Transport)])
            }));
        let fact = (classification == TaskWatchClassification::Applied)
            .then(|| task("task:progress", 11, 1));
        streams.push_back(VecDeque::from([
            StreamStep::Update(update(classification, 11, fact)),
            transient_stream_step(ScriptedTransientFailure::Transport),
        ]));
        streams.push_back(VecDeque::from([StreamStep::Pending]));

        let client = Arc::new(ScriptedClient::new(baselines, streams));
        let mut controller =
            TaskWatchController::with_sleeper(Arc::clone(&client), Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| {
            client
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| **call == "open")
                .count()
                == 7
                && controller.model().unwrap().phase == TaskWatchPhase::Live
                && controller.is_running()
        })
        .await;
        assert_ne!(
            controller.model().unwrap().phase,
            TaskWatchPhase::FatalStopped
        );
        controller.stop().await;
    }

    #[tokio::test]
    async fn strictly_later_applied_and_heartbeat_reset_reconnect_budget() {
        strict_live_progress_resets_reconnect_budget(TaskWatchClassification::Applied).await;
        strict_live_progress_resets_reconnect_budget(TaskWatchClassification::Heartbeat).await;
    }

    #[tokio::test]
    async fn integrity_failure_stops_without_retry_or_sensitive_detail() {
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([Ok(baseline(10, vec![task("task:a", 10, 1)]))]),
            VecDeque::from([VecDeque::from([StreamStep::Error(
                ClientGovernedTaskError::Protocol("sensitive-integrity-canary"),
            )])]),
        ));
        let mut controller =
            TaskWatchController::with_sleeper(Arc::clone(&client), Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        let model = controller.model().unwrap();
        assert_eq!(model.phase, TaskWatchPhase::FatalStopped);
        assert_eq!(
            model.message,
            TaskWatchFatalReason::ProjectionIntegrity.message()
        );
        assert!(!model.message.contains("sensitive-integrity-canary"));
        assert_eq!(
            client.calls.lock().unwrap().as_slice(),
            ["baseline", "open"]
        );
    }

    #[tokio::test]
    async fn permission_and_baseline_limit_fail_closed_with_fixed_messages() {
        let permission_client = Arc::new(ScriptedClient::new(
            VecDeque::from([Ok(baseline(10, vec![task("task:a", 10, 1)]))]),
            VecDeque::from([VecDeque::from([StreamStep::Error(
                ClientGovernedTaskError::Kernel(KernelError::PermissionDenied(
                    "sensitive-permission-canary".to_owned(),
                )),
            )])]),
        ));
        let mut controller =
            TaskWatchController::with_sleeper(permission_client, Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        assert_eq!(
            controller.model().unwrap().message,
            TaskWatchFatalReason::PermissionDenied.message()
        );
        assert!(!controller.model().unwrap().message.contains("canary"));

        let limit_client = Arc::new(ScriptedClient::new(
            VecDeque::from([Err(ClientGovernedTaskError::BaselineLimitExceeded)]),
            VecDeque::new(),
        ));
        let mut limited = TaskWatchController::new(limit_client);
        assert_eq!(
            limited.start().await.unwrap_err(),
            TaskWatchFatalReason::BaselineLimit.message()
        );
        assert!(limited.model().is_none());
        assert!(!limited.is_running());
    }

    #[tokio::test]
    async fn failed_rebaseline_never_partially_replaces_last_complete_safe_tree() {
        let original = task("task:last-complete", 10, 1);
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([
                Ok(baseline(10, vec![original.clone()])),
                Err(ClientGovernedTaskError::Protocol(
                    "sensitive-partial-baseline-canary",
                )),
            ]),
            VecDeque::from([VecDeque::from([StreamStep::Update(update(
                TaskWatchClassification::ResetRequired,
                10,
                None,
            ))])]),
        ));
        let mut controller = TaskWatchController::with_sleeper(client, Arc::new(ImmediateSleeper));
        controller.start().await.unwrap();
        pump_until(&mut controller, |controller| !controller.is_running()).await;
        let model = controller.model().unwrap();
        assert_eq!(model.tasks, [original]);
        assert_eq!(model.phase, TaskWatchPhase::FatalStopped);
        assert!(!model.message.contains("canary"));
    }

    #[tokio::test]
    async fn selection_and_detail_scroll_are_stable_clamped_and_reset_on_fact_changes() {
        let long = task("task:long", 10, 8);
        let short = task("task:short", 10, 0);
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([
                Ok(baseline(10, vec![long.clone(), short.clone()])),
                Ok(baseline(12, vec![short.clone()])),
            ]),
            VecDeque::from([
                VecDeque::from([
                    StreamStep::Update(update(
                        TaskWatchClassification::Applied,
                        11,
                        Some(task("task:long", 11, 0)),
                    )),
                    StreamStep::Pending,
                ]),
                VecDeque::from([StreamStep::Pending]),
            ]),
        ));
        let mut controller = TaskWatchController::new(client);
        controller.start().await.unwrap();
        assert!(controller.select_task("task:long"));
        for _ in 0..100 {
            controller.scroll_detail_down();
        }
        assert!(controller.model().unwrap().detail_scroll < 100);
        pump_until(&mut controller, |controller| {
            controller.model().unwrap().position.sequence == 11
        })
        .await;
        assert_eq!(controller.model().unwrap().detail_scroll, 0);
        controller.scroll_detail_down();
        controller.select_next();
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:short")
        );
        assert_eq!(controller.model().unwrap().detail_scroll, 0);
        controller.scroll_detail_down();
        let short_max = selected_detail_line_count(controller.model().unwrap()) - 1;
        for _ in 0..100 {
            controller.scroll_detail_down();
        }
        assert_eq!(
            usize::from(controller.model().unwrap().detail_scroll),
            short_max
        );
        controller.start().await.unwrap();
        assert_eq!(controller.model().unwrap().detail_scroll, 0);
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:short")
        );
        controller.stop().await;
    }

    #[tokio::test]
    async fn stale_generation_event_is_discarded_and_runtime_is_retired_on_failure() {
        let client = Arc::new(ScriptedClient::new(VecDeque::new(), VecDeque::new()));
        let mut controller = TaskWatchController::new(client);
        controller.generation = 2;
        controller.model = Some(TaskWatchPageModel::new(
            position(10),
            vec![task("task:current", 10, 1)],
        ));
        let (event_tx, event_rx) = mpsc::channel(2);
        let (cancel, _cancel_rx) = watch::channel(false);
        event_tx
            .send(TaskWatchWorkerEvent::Replace {
                generation: 1,
                model: TaskWatchPageModel::new(
                    position(99),
                    vec![task("task:stale-generation", 99, 1)],
                ),
            })
            .await
            .unwrap();
        event_tx
            .send(TaskWatchWorkerEvent::Failed {
                generation: 2,
                reason: TaskWatchFatalReason::ProjectionIntegrity,
            })
            .await
            .unwrap();
        controller.runtime = Some(TaskWatchRuntime {
            events: event_rx,
            cancel,
            worker: None,
        });
        controller.pump().unwrap();
        assert_eq!(controller.model().unwrap().tasks[0].task_id, "task:current");
        assert_eq!(
            controller.model().unwrap().phase,
            TaskWatchPhase::FatalStopped
        );
        assert!(!controller.is_running());
    }

    #[tokio::test]
    async fn full_channel_send_is_cancelable_and_stop_retires_worker() {
        let client = Arc::new(ScriptedClient::new(
            VecDeque::from([Ok(baseline(1, vec![task("task:a", 1, 1)]))]),
            VecDeque::from([VecDeque::from_iter((0..100).map(|sequence| {
                StreamStep::Update(update(
                    TaskWatchClassification::Heartbeat,
                    sequence + 2,
                    None,
                ))
            }))]),
        ));
        let mut controller = TaskWatchController::new(client);
        controller.start().await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::timeout(TASK_WATCH_STOP_TIMEOUT, controller.stop())
            .await
            .expect("full channel stop is bounded");
        assert!(!controller.is_running());
    }
}
