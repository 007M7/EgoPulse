use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_operations::{
    ClientAttachment, ClientTaskWatchError, TaskWatch, TaskWatchClassification, TaskWatchRequest,
    TaskWatchUpdate,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::{HarnessApprovalView, TaskView};
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

pub type TaskWatchOpenFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Box<dyn TaskWatchStream>, ClientTaskWatchError>> + Send + 'a>,
>;
pub type TaskWatchNextFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Option<TaskWatchUpdate>, ClientTaskWatchError>> + Send + 'a>,
>;
pub type TaskWatchBaselineFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TaskWatchPageModel, String>> + Send + 'a>>;
type TaskWatchSleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait TaskWatchStream: Send {
    fn next_update(&mut self) -> TaskWatchNextFuture<'_>;
}

impl TaskWatchStream for TaskWatch {
    fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
        Box::pin(TaskWatch::next_update(self))
    }
}

pub trait TaskWatchClient: Send + Sync {
    fn task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_>;
    fn open_task_watch(&self, request: TaskWatchRequest) -> TaskWatchOpenFuture<'_>;
}

impl TaskWatchClient for ClientAttachment {
    fn task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
        Box::pin(async move {
            let projection = self
                .read_projection_snapshot()
                .await
                .map_err(|error| error.to_string())?;
            TaskWatchPageModel::from_projection(projection)
        })
    }

    fn open_task_watch(&self, request: TaskWatchRequest) -> TaskWatchOpenFuture<'_> {
        Box::pin(async move {
            ClientAttachment::open_task_watch(self, request)
                .await
                .map(|watch| Box::new(watch) as Box<dyn TaskWatchStream>)
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskWatchPageModel {
    pub health: String,
    pub stale: bool,
    pub position: String,
    pub resume_epoch: Option<String>,
    pub resume_sequence: Option<u64>,
    pub tasks: Vec<TaskView>,
    pub approvals: Vec<HarnessApprovalView>,
    pub selected_task_id: Option<String>,
    pub message: String,
}

impl TaskWatchPageModel {
    fn from_projection(
        projection: egopulse_client_operations::ProjectionSnapshot,
    ) -> Result<Self, String> {
        use egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionHealth;

        let position = projection.metadata.position;
        let resume_epoch = position.as_ref().map(|value| value.epoch.clone());
        let resume_sequence = position.as_ref().map(|value| value.sequence);
        if resume_epoch.is_none() || resume_sequence.is_none() {
            return Err("Task watch baseline has no resumable projection position".to_owned());
        }
        let mut tasks = projection.tasks;
        tasks.sort_by(|left, right| {
            task_id_of(left)
                .unwrap_or_default()
                .cmp(task_id_of(right).unwrap_or_default())
        });
        validate_task_identities(&tasks)?;
        let selected_task_id = tasks.first().and_then(task_id_of).map(str::to_owned);
        Ok(Self {
            health: ProjectionHealth::try_from(projection.metadata.health)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned()),
            stale: projection.metadata.stale,
            position: position
                .as_ref()
                .map(|value| format!("{}:{}", value.epoch, value.sequence))
                .unwrap_or_else(|| "unknown".to_owned()),
            resume_epoch,
            resume_sequence,
            tasks,
            approvals: projection.approvals,
            selected_task_id,
            message: "Task Watch live; Esc returns, r refetches, q quits".to_owned(),
        })
    }
}

#[derive(Debug)]
enum TaskWatchWorkerEvent {
    Update {
        generation: u64,
        update: Box<TaskWatchUpdate>,
    },
    Stale {
        generation: u64,
        detail: String,
    },
    Failed {
        generation: u64,
        detail: String,
    },
}

impl TaskWatchWorkerEvent {
    fn generation(&self) -> u64 {
        match self {
            Self::Update { generation, .. }
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
        let previous_selection = self
            .model
            .as_ref()
            .and_then(|model| model.selected_task_id.clone());
        let previous_index = self.model.as_ref().and_then(selected_task_index);
        self.stop().await;
        let mut baseline = self.client.task_watch_baseline().await?;
        normalize_task_order(&mut baseline.tasks);
        validate_task_identities(&baseline.tasks)?;
        let desired_selection = previous_selection
            .clone()
            .or_else(|| baseline.selected_task_id.clone());
        let desired_index = previous_index.or_else(|| {
            desired_selection.as_deref().and_then(|selected| {
                baseline
                    .tasks
                    .iter()
                    .position(|view| task_id_of(view) == Some(selected))
            })
        });
        let selection_disappeared = previous_selection.as_ref().is_some_and(|selected| {
            !baseline
                .tasks
                .iter()
                .any(|view| task_id_of(view) == Some(selected.as_str()))
        });
        reconcile_task_selection(&mut baseline, desired_selection.as_deref(), desired_index);
        if selection_disappeared {
            baseline.message =
                "Selected Task left the projection; selection moved safely".to_owned();
        }
        let resume_epoch = baseline.resume_epoch.clone();
        let resume_sequence = baseline.resume_sequence;
        if resume_epoch.is_none() || resume_sequence.is_none() {
            return Err("Task watch baseline has no resumable projection position".to_owned());
        }
        self.model = Some(baseline);
        self.generation = self.generation.wrapping_add(1).max(1);
        self.spawn_worker(resume_epoch, resume_sequence);
        Ok(())
    }

    fn spawn_worker(&mut self, resume_epoch: Option<String>, resume_sequence: Option<u64>) {
        let generation = self.generation;
        let (sender, events) = mpsc::channel(TASK_WATCH_CHANNEL_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);
        let worker = tokio::spawn(run_task_watch_worker(
            Arc::clone(&self.client),
            generation,
            resume_epoch,
            resume_sequence,
            sender,
            cancel_receiver,
            Arc::clone(&self.sleeper),
        ));
        self.runtime = Some(TaskWatchRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    pub async fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop().await;
        }
    }

    pub async fn pump(&mut self) -> Result<(), String> {
        let events = self.take_events();
        for event in events {
            if event.generation() != self.generation {
                continue;
            }
            match event {
                TaskWatchWorkerEvent::Update { update, .. } => {
                    let update = *update;
                    if update.classification == TaskWatchClassification::ResetRequired {
                        self.start().await?;
                        break;
                    }
                    if let Err(error) = self.apply_update(update) {
                        self.stop().await;
                        if let Some(model) = &mut self.model {
                            model.stale = true;
                            model.message = format!("Task Watch stopped fail-closed: {error}");
                        }
                        return Err(error);
                    }
                }
                TaskWatchWorkerEvent::Stale { detail, .. } => {
                    if let Some(model) = &mut self.model {
                        model.stale = true;
                        model.message = format!("Task Watch stale; bounded reconnect: {detail}");
                    }
                }
                TaskWatchWorkerEvent::Failed { detail, .. } => {
                    if let Some(model) = &mut self.model {
                        model.stale = true;
                        model.message = format!("Task Watch stopped fail-closed: {detail}");
                    }
                    self.stop().await;
                    return Err(detail);
                }
            }
        }
        Ok(())
    }

    pub fn select_previous(&mut self) {
        self.select_relative(false);
    }

    pub fn select_next(&mut self) {
        self.select_relative(true);
    }

    pub fn select_task(&mut self, task_id: &str) -> bool {
        let Some(model) = &mut self.model else {
            return false;
        };
        if model
            .tasks
            .iter()
            .any(|view| task_id_of(view) == Some(task_id))
        {
            model.selected_task_id = Some(task_id.to_owned());
            true
        } else {
            false
        }
    }

    /// Clears only the local page selection; projected Task facts remain unchanged.
    pub fn clear_selection(&mut self) {
        if let Some(model) = &mut self.model {
            model.selected_task_id = None;
        }
    }

    fn select_relative(&mut self, forward: bool) {
        let Some(model) = &mut self.model else {
            return;
        };
        if model.tasks.is_empty() {
            model.selected_task_id = None;
            return;
        }
        let current = selected_task_index(model).unwrap_or(0);
        let next = if forward {
            (current + 1).min(model.tasks.len() - 1)
        } else {
            current.saturating_sub(1)
        };
        model.selected_task_id = task_id_of(&model.tasks[next]).map(str::to_owned);
    }

    fn take_events(&mut self) -> Vec<TaskWatchWorkerEvent> {
        let Some(runtime) = &mut self.runtime else {
            return Vec::new();
        };
        let mut events = Vec::new();
        while let Ok(event) = runtime.events.try_recv() {
            events.push(event);
        }
        events
    }

    fn apply_update(&mut self, update: TaskWatchUpdate) -> Result<(), String> {
        let model = self
            .model
            .as_mut()
            .ok_or_else(|| "Task Watch has no baseline snapshot".to_owned())?;
        let mut selection_disappeared = false;
        if update.classification == TaskWatchClassification::Applied {
            let previous_selection = model.selected_task_id.clone();
            let previous_index = selected_task_index(model);
            let view = update
                .view
                .ok_or_else(|| "applied Task watch update omitted its view".to_owned())?;
            let task_id = view
                .task
                .as_ref()
                .map(|task| task.task_id.as_str())
                .filter(|task_id| !task_id.is_empty())
                .ok_or_else(|| "applied Task watch update has an empty Task identity".to_owned())?
                .to_owned();
            let matches = model
                .tasks
                .iter()
                .enumerate()
                .filter_map(|(index, current)| {
                    current
                        .task
                        .as_ref()
                        .is_some_and(|task| task.task_id == task_id)
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => model.tasks.push(view),
                [index] => model.tasks[*index] = view,
                _ => {
                    return Err("Task Watch baseline contains duplicate Task identities".to_owned());
                }
            }
            normalize_task_order(&mut model.tasks);
            selection_disappeared = previous_selection.as_ref().is_some_and(|selected| {
                !model
                    .tasks
                    .iter()
                    .any(|view| task_id_of(view) == Some(selected.as_str()))
            });
            reconcile_task_selection(model, previous_selection.as_deref(), previous_index);
            if selection_disappeared {
                model.message =
                    "Selected Task left the projection; selection moved safely".to_owned();
            }
        }
        model.position = format!("{}:{}", update.position.epoch, update.position.sequence);
        model.resume_epoch = Some(update.position.epoch);
        model.resume_sequence = Some(update.position.sequence);
        model.stale = false;
        let normal_message = match update.classification {
            TaskWatchClassification::Applied => {
                "Task Watch applied a durable projection".to_owned()
            }
            TaskWatchClassification::Replay => {
                "Task Watch verified a replay; facts unchanged".to_owned()
            }
            TaskWatchClassification::Heartbeat => {
                "Task Watch heartbeat; facts unchanged".to_owned()
            }
            TaskWatchClassification::ResetRequired => {
                return Err("reset update crossed the Task Watch refetch barrier".to_owned());
            }
        };
        if !selection_disappeared {
            model.message = normal_message;
        }
        Ok(())
    }
}

impl<C: TaskWatchClient + ?Sized + 'static> Drop for TaskWatchController<C> {
    fn drop(&mut self) {
        self.runtime.take();
    }
}

fn task_id_of(view: &TaskView) -> Option<&str> {
    view.task.as_ref().map(|task| task.task_id.as_str())
}

fn normalize_task_order(tasks: &mut [TaskView]) {
    tasks.sort_by(|left, right| {
        task_id_of(left)
            .unwrap_or_default()
            .cmp(task_id_of(right).unwrap_or_default())
    });
}

fn validate_task_identities(tasks: &[TaskView]) -> Result<(), String> {
    let mut previous = None;
    for view in tasks {
        let task_id = task_id_of(view)
            .filter(|task_id| !task_id.is_empty())
            .ok_or_else(|| "Task Watch baseline contains an empty Task identity".to_owned())?;
        if previous == Some(task_id) {
            return Err("Task Watch baseline contains duplicate Task identities".to_owned());
        }
        previous = Some(task_id);
    }
    Ok(())
}

fn selected_task_index(model: &TaskWatchPageModel) -> Option<usize> {
    let selected = model.selected_task_id.as_deref()?;
    model
        .tasks
        .iter()
        .position(|view| task_id_of(view) == Some(selected))
}

fn reconcile_task_selection(
    model: &mut TaskWatchPageModel,
    previous_selection: Option<&str>,
    previous_index: Option<usize>,
) {
    if let Some(previous) = previous_selection
        && model
            .tasks
            .iter()
            .any(|view| task_id_of(view) == Some(previous))
    {
        model.selected_task_id = Some(previous.to_owned());
        return;
    }
    model.selected_task_id = if model.tasks.is_empty() {
        None
    } else {
        let index = previous_index.unwrap_or(0).min(model.tasks.len() - 1);
        task_id_of(&model.tasks[index]).map(str::to_owned)
    };
}

async fn send_task_watch_event(
    sender: &mpsc::Sender<TaskWatchWorkerEvent>,
    cancel: &mut watch::Receiver<bool>,
    event: TaskWatchWorkerEvent,
) -> bool {
    send_task_watch_event_via(sender, cancel, event, None).await
}

async fn send_task_watch_event_via(
    sender: &mpsc::Sender<TaskWatchWorkerEvent>,
    cancel: &mut watch::Receiver<bool>,
    event: TaskWatchWorkerEvent,
    entered: Option<&tokio::sync::Notify>,
) -> bool {
    if let Some(entered) = entered {
        entered.notify_one();
    }
    tokio::select! {
        permit = sender.reserve() => match permit {
            Ok(permit) => { permit.send(event); true }
            Err(_) => false,
        },
        changed = cancel.changed() => changed.is_ok() && !*cancel.borrow(),
    }
}

fn task_watch_failure_is_retryable(error: &ClientTaskWatchError) -> bool {
    matches!(error, ClientTaskWatchError::Transport(_))
}

async fn run_task_watch_worker<C: TaskWatchClient + ?Sized + 'static>(
    client: Arc<C>,
    generation: u64,
    mut resume_epoch: Option<String>,
    mut resume_sequence: Option<u64>,
    sender: mpsc::Sender<TaskWatchWorkerEvent>,
    mut cancel: watch::Receiver<bool>,
    sleeper: Arc<dyn TaskWatchSleeper>,
) {
    let mut retry_index = 0_usize;
    loop {
        if *cancel.borrow() {
            return;
        }
        let request = TaskWatchRequest {
            resume_epoch: resume_epoch.clone(),
            resume_sequence,
        };
        let mut stream = match client.open_task_watch(request).await {
            Ok(stream) => stream,
            Err(error) => {
                if !task_watch_failure_is_retryable(&error) {
                    let _ = send_task_watch_event(
                        &sender,
                        &mut cancel,
                        TaskWatchWorkerEvent::Failed {
                            generation,
                            detail: error.to_string(),
                        },
                    )
                    .await;
                    return;
                }
                if !schedule_task_watch_reconnect(
                    &sender,
                    &mut cancel,
                    generation,
                    &mut retry_index,
                    error.to_string(),
                    sleeper.as_ref(),
                )
                .await
                {
                    return;
                }
                continue;
            }
        };
        loop {
            let next = tokio::select! {
                _ = cancel.changed() => return,
                next = stream.next_update() => next,
            };
            match next {
                Ok(Some(update)) => {
                    resume_epoch = Some(update.position.epoch.clone());
                    resume_sequence = Some(update.position.sequence);
                    retry_index = 0;
                    let reset = update.classification == TaskWatchClassification::ResetRequired;
                    if !send_task_watch_event(
                        &sender,
                        &mut cancel,
                        TaskWatchWorkerEvent::Update {
                            generation,
                            update: Box::new(update),
                        },
                    )
                    .await
                    {
                        return;
                    }
                    if reset {
                        return;
                    }
                }
                Ok(None) => {
                    if !schedule_task_watch_reconnect(
                        &sender,
                        &mut cancel,
                        generation,
                        &mut retry_index,
                        "Task watch stream ended".to_owned(),
                        sleeper.as_ref(),
                    )
                    .await
                    {
                        return;
                    }
                    break;
                }
                Err(error) if task_watch_failure_is_retryable(&error) => {
                    if !schedule_task_watch_reconnect(
                        &sender,
                        &mut cancel,
                        generation,
                        &mut retry_index,
                        error.to_string(),
                        sleeper.as_ref(),
                    )
                    .await
                    {
                        return;
                    }
                    break;
                }
                Err(error) => {
                    let _ = send_task_watch_event(
                        &sender,
                        &mut cancel,
                        TaskWatchWorkerEvent::Failed {
                            generation,
                            detail: error.to_string(),
                        },
                    )
                    .await;
                    return;
                }
            }
        }
    }
}

async fn schedule_task_watch_reconnect(
    sender: &mpsc::Sender<TaskWatchWorkerEvent>,
    cancel: &mut watch::Receiver<bool>,
    generation: u64,
    retry_index: &mut usize,
    detail: String,
    sleeper: &dyn TaskWatchSleeper,
) -> bool {
    if !send_task_watch_event(
        sender,
        cancel,
        TaskWatchWorkerEvent::Stale { generation, detail },
    )
    .await
    {
        return false;
    }
    let Some(delay) = TASK_WATCH_RECONNECT_DELAYS.get(*retry_index).copied() else {
        let _ = send_task_watch_event(
            sender,
            cancel,
            TaskWatchWorkerEvent::Failed {
                generation,
                detail: "Task watch reconnect budget exhausted".to_owned(),
            },
        )
        .await;
        return false;
    };
    *retry_index += 1;
    tokio::select! {
        _ = sleeper.sleep(delay) => true,
        _ = cancel.changed() => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use egopulse_client_kernel::KernelError;
    use egopulse_client_operations::{TaskWatchFrameKind, TaskWatchRequest};
    use egopulse_domain_contracts::v01::egopulse::{
        localapi::v1::{ProjectionPosition, TaskView},
        task::v1::{TaskSnapshot, TaskStatus},
    };

    use super::*;

    #[derive(Clone)]
    enum Step {
        Update(Box<TaskWatchUpdate>),
        Eof,
        Transport,
        Integrity,
        Pending,
    }

    struct ScriptedStream {
        steps: Arc<Mutex<VecDeque<Step>>>,
        next_calls: Arc<AtomicUsize>,
    }

    impl TaskWatchStream for ScriptedStream {
        fn next_update(&mut self) -> TaskWatchNextFuture<'_> {
            self.next_calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Step::Pending);
            Box::pin(async move {
                match step {
                    Step::Update(update) => Ok(Some(*update)),
                    Step::Eof => Ok(None),
                    Step::Transport => Err(ClientTaskWatchError::Transport("offline".to_owned())),
                    Step::Integrity => Err(ClientTaskWatchError::Kernel(
                        KernelError::ConflictingStreamReplay,
                    )),
                    Step::Pending => std::future::pending().await,
                }
            })
        }
    }

    struct ScriptedClient {
        baselines: Mutex<VecDeque<TaskWatchPageModel>>,
        sessions: Mutex<VecDeque<VecDeque<Step>>>,
        open_errors: Mutex<VecDeque<ClientTaskWatchError>>,
        requests: Mutex<Vec<TaskWatchRequest>>,
        open_calls: AtomicUsize,
        next_calls: Arc<AtomicUsize>,
    }

    impl TaskWatchClient for ScriptedClient {
        fn task_watch_baseline(&self) -> TaskWatchBaselineFuture<'_> {
            let baseline = self.baselines.lock().unwrap().pop_front();
            Box::pin(async move { baseline.ok_or_else(|| "missing baseline".to_owned()) })
        }

        fn open_task_watch(&self, request: TaskWatchRequest) -> TaskWatchOpenFuture<'_> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request);
            if let Some(error) = self.open_errors.lock().unwrap().pop_front() {
                return Box::pin(async move { Err(error) });
            }
            let steps = self
                .sessions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| VecDeque::from([Step::Pending]));
            let next_calls = Arc::clone(&self.next_calls);
            Box::pin(async move {
                Ok(Box::new(ScriptedStream {
                    steps: Arc::new(Mutex::new(steps)),
                    next_calls,
                }) as Box<dyn TaskWatchStream>)
            })
        }
    }

    #[derive(Default)]
    struct ImmediateSleeper {
        delays: Mutex<Vec<Duration>>,
    }

    impl TaskWatchSleeper for ImmediateSleeper {
        fn sleep(&self, duration: Duration) -> TaskWatchSleepFuture {
            self.delays.lock().unwrap().push(duration);
            Box::pin(std::future::ready(()))
        }
    }

    struct Termination(Arc<AtomicBool>);

    impl Drop for Termination {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn witnessed_runtime(honor_cancellation: bool) -> (TaskWatchRuntime, Arc<AtomicBool>) {
        let (event_sender, events) = mpsc::channel(1);
        let (cancel, mut cancellation) = watch::channel(false);
        let terminated = Arc::new(AtomicBool::new(false));
        let witness = Arc::clone(&terminated);
        let (started_sender, started) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let _termination = Termination(witness);
            let _ = started_sender.send(());
            if honor_cancellation {
                let _ = cancellation.changed().await;
            } else {
                std::future::pending::<()>().await;
            }
        });
        started.await.unwrap();
        drop(event_sender);
        (
            TaskWatchRuntime {
                events,
                cancel,
                worker: Some(worker),
            },
            terminated,
        )
    }

    async fn await_termination(terminated: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !terminated.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    fn task(task_id: &str, revision: u64, status: TaskStatus) -> TaskView {
        TaskView {
            task: Some(TaskSnapshot {
                task_id: task_id.to_owned(),
                revision,
                status: status as i32,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn baseline(sequence: u64) -> TaskWatchPageModel {
        TaskWatchPageModel {
            health: "PROJECTION_HEALTH_READY".to_owned(),
            stale: false,
            position: format!("epoch:test:{sequence}"),
            resume_epoch: Some("epoch:test".to_owned()),
            resume_sequence: Some(sequence),
            tasks: vec![task("task:active", 1, TaskStatus::Active)],
            approvals: Vec::new(),
            selected_task_id: Some("task:active".to_owned()),
            message: "baseline".to_owned(),
        }
    }

    fn update(
        classification: TaskWatchClassification,
        sequence: u64,
        view: Option<TaskView>,
    ) -> TaskWatchUpdate {
        TaskWatchUpdate {
            classification,
            kind: match classification {
                TaskWatchClassification::Applied | TaskWatchClassification::Replay => {
                    TaskWatchFrameKind::Snapshot
                }
                TaskWatchClassification::Heartbeat => TaskWatchFrameKind::Heartbeat,
                TaskWatchClassification::ResetRequired => TaskWatchFrameKind::ResetRequired,
            },
            position: ProjectionPosition {
                epoch: "epoch:test".to_owned(),
                sequence,
                projected_at: None,
            },
            view,
            reset_reason_code: (classification == TaskWatchClassification::ResetRequired)
                .then(|| "reset:test".to_owned()),
        }
    }

    fn client(
        baselines: VecDeque<TaskWatchPageModel>,
        sessions: VecDeque<VecDeque<Step>>,
    ) -> Arc<ScriptedClient> {
        Arc::new(ScriptedClient {
            baselines: Mutex::new(baselines),
            sessions: Mutex::new(sessions),
            open_errors: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
            open_calls: AtomicUsize::new(0),
            next_calls: Arc::new(AtomicUsize::new(0)),
        })
    }

    async fn pump_until(
        controller: &mut TaskWatchController<ScriptedClient>,
        predicate: impl Fn(&TaskWatchController<ScriptedClient>) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                controller.pump().await.unwrap();
                if predicate(controller) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("controller condition reached");
    }

    #[tokio::test]
    async fn controller_reset_generation_fence_integrity_and_no_false_completion() {
        let reset_client = client(
            VecDeque::from([baseline(10), baseline(30)]),
            VecDeque::from([
                VecDeque::from([Step::Update(Box::new(update(
                    TaskWatchClassification::ResetRequired,
                    11,
                    None,
                )))]),
                VecDeque::from([
                    Step::Update(Box::new(update(
                        TaskWatchClassification::Heartbeat,
                        31,
                        Some(task("task:active", 99, TaskStatus::Completed)),
                    ))),
                    Step::Update(Box::new(update(
                        TaskWatchClassification::Replay,
                        32,
                        Some(task("task:active", 99, TaskStatus::Completed)),
                    ))),
                    Step::Update(Box::new(update(
                        TaskWatchClassification::Applied,
                        33,
                        Some(task("task:active", 2, TaskStatus::Active)),
                    ))),
                    Step::Pending,
                ]),
            ]),
        );
        let mut controller = TaskWatchController::new(Arc::clone(&reset_client));
        controller.start().await.unwrap();
        let first_generation = controller.generation();
        pump_until(&mut controller, |controller| {
            controller.generation() > first_generation
                && controller.model().unwrap().resume_sequence == Some(33)
        })
        .await;
        let observed_task = controller.model().unwrap().tasks[0].task.as_ref().unwrap();
        assert_eq!(observed_task.status, TaskStatus::Active as i32);
        assert_eq!(observed_task.revision, 2);
        assert_eq!(reset_client.open_calls.load(Ordering::SeqCst), 2);
        controller.stop().await;

        let current_generation = controller.generation();
        let (sender, events) = mpsc::channel(TASK_WATCH_CHANNEL_CAPACITY);
        sender
            .send(TaskWatchWorkerEvent::Update {
                generation: first_generation,
                update: Box::new(update(
                    TaskWatchClassification::Applied,
                    34,
                    Some(task("task:active", 99, TaskStatus::Completed)),
                )),
            })
            .await
            .unwrap();
        for task_id in ["task:z", "task:a"] {
            sender
                .send(TaskWatchWorkerEvent::Update {
                    generation: current_generation,
                    update: Box::new(update(
                        TaskWatchClassification::Applied,
                        35,
                        Some(task(task_id, 1, TaskStatus::Active)),
                    )),
                })
                .await
                .unwrap();
        }
        drop(sender);
        let (cancel, _) = watch::channel(false);
        controller.runtime = Some(TaskWatchRuntime {
            events,
            cancel,
            worker: None,
        });
        controller.pump().await.unwrap();
        let task_ids = controller
            .model()
            .unwrap()
            .tasks
            .iter()
            .map(|view| task_id_of(view).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(task_ids, ["task:a", "task:active", "task:z"]);
        let active = controller.model().unwrap().tasks[1].task.as_ref().unwrap();
        assert_eq!(active.status, TaskStatus::Active as i32);
        assert_eq!(active.revision, 2);
        controller.stop().await;

        let integrity_client = client(
            VecDeque::from([baseline(40)]),
            VecDeque::from([VecDeque::from([Step::Integrity])]),
        );
        let mut failed = TaskWatchController::new(integrity_client);
        failed.start().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if failed.pump().await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!failed.is_running());
        assert!(failed.model().unwrap().stale);
    }

    #[tokio::test]
    async fn full_channel_cancellation_and_runtime_stop_drop_are_deterministic() {
        let (sender, mut receiver) = mpsc::channel(TASK_WATCH_CHANNEL_CAPACITY);
        for index in 0..TASK_WATCH_CHANNEL_CAPACITY {
            sender
                .try_send(TaskWatchWorkerEvent::Stale {
                    generation: 1,
                    detail: index.to_string(),
                })
                .unwrap();
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let worker_entered = Arc::clone(&entered);
        let (cancel, cancellation) = watch::channel(false);
        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move {
            let mut cancellation = cancellation;
            send_task_watch_event_via(
                &blocked_sender,
                &mut cancellation,
                TaskWatchWorkerEvent::Failed {
                    generation: 1,
                    detail: "blocked".to_owned(),
                },
                Some(worker_entered.as_ref()),
            )
            .await
        });
        entered.notified().await;
        assert!(!blocked.is_finished());
        cancel.send(true).unwrap();
        assert!(!blocked.await.unwrap());
        assert_eq!(receiver.len(), TASK_WATCH_CHANNEL_CAPACITY);
        drop(receiver.recv().await);

        let (cooperative, cooperative_terminated) = witnessed_runtime(true).await;
        cooperative.stop().await;
        await_termination(cooperative_terminated.as_ref()).await;

        let (stubborn, stubborn_terminated) = witnessed_runtime(false).await;
        tokio::time::timeout(
            TASK_WATCH_STOP_TIMEOUT + Duration::from_secs(1),
            stubborn.stop(),
        )
        .await
        .unwrap();
        await_termination(stubborn_terminated.as_ref()).await;

        let (dropped, dropped_terminated) = witnessed_runtime(false).await;
        drop(dropped);
        await_termination(dropped_terminated.as_ref()).await;
    }

    #[tokio::test]
    async fn eof_exact_cursor_permission_no_retry_and_finite_budget_use_worker_seam() {
        let sleeper = Arc::new(ImmediateSleeper::default());
        let eof_client = client(
            VecDeque::from([baseline(50)]),
            VecDeque::from([
                VecDeque::from([
                    Step::Update(Box::new(update(
                        TaskWatchClassification::Applied,
                        51,
                        Some(task("task:active", 2, TaskStatus::Active)),
                    ))),
                    Step::Eof,
                ]),
                VecDeque::from([Step::Pending]),
            ]),
        );
        let mut eof = TaskWatchController::with_sleeper(
            Arc::clone(&eof_client),
            sleeper.clone() as Arc<dyn TaskWatchSleeper>,
        );
        eof.start().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while eof_client.open_calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            eof_client.requests.lock().unwrap().as_slice(),
            [
                TaskWatchRequest {
                    resume_epoch: Some("epoch:test".to_owned()),
                    resume_sequence: Some(50),
                },
                TaskWatchRequest {
                    resume_epoch: Some("epoch:test".to_owned()),
                    resume_sequence: Some(51),
                },
            ]
        );
        eof.stop().await;

        for error in [
            ClientTaskWatchError::Kernel(KernelError::PermissionDenied(
                "WatchTaskViews".to_owned(),
            )),
            ClientTaskWatchError::Kernel(KernelError::UnknownRpc("WatchTaskViews".to_owned())),
        ] {
            let denied = Arc::new(ScriptedClient {
                baselines: Mutex::new(VecDeque::from([baseline(60)])),
                sessions: Mutex::new(VecDeque::new()),
                open_errors: Mutex::new(VecDeque::from([error])),
                requests: Mutex::new(Vec::new()),
                open_calls: AtomicUsize::new(0),
                next_calls: Arc::new(AtomicUsize::new(0)),
            });
            let mut controller = TaskWatchController::with_sleeper(
                Arc::clone(&denied),
                sleeper.clone() as Arc<dyn TaskWatchSleeper>,
            );
            controller.start().await.unwrap();
            let error = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if let Err(error) = controller.pump().await {
                        break error;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(error.contains("WatchTaskViews"));
            assert_eq!(denied.open_calls.load(Ordering::SeqCst), 1);
            assert_eq!(denied.next_calls.load(Ordering::SeqCst), 0);
            assert!(!controller.is_running());
        }

        let exhausted = client(
            VecDeque::from([baseline(70)]),
            VecDeque::from_iter((0..6).map(|_| VecDeque::from([Step::Transport]))),
        );
        let budget_sleeper = Arc::new(ImmediateSleeper::default());
        let mut budget = TaskWatchController::with_sleeper(
            Arc::clone(&exhausted),
            budget_sleeper.clone() as Arc<dyn TaskWatchSleeper>,
        );
        budget.start().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Err(error) = budget.pump().await {
                    break error;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(error.contains("budget exhausted"));
        assert_eq!(exhausted.open_calls.load(Ordering::SeqCst), 6);
        assert_eq!(exhausted.next_calls.load(Ordering::SeqCst), 6);
        assert_eq!(
            budget_sleeper.delays.lock().unwrap().as_slice(),
            TASK_WATCH_RECONNECT_DELAYS
        );
        assert!(!budget.is_running());
    }

    #[tokio::test]
    async fn selection_is_stable_by_task_identity_and_refetch_falls_back_adjacent() {
        let mut first = baseline(80);
        first.tasks = vec![
            task("task:c", 1, TaskStatus::Active),
            task("task:a", 1, TaskStatus::Active),
            task("task:b", 1, TaskStatus::Active),
        ];
        first.selected_task_id = Some("task:c".to_owned());
        let mut second = baseline(90);
        second.tasks = vec![
            task("task:d", 1, TaskStatus::Active),
            task("task:a", 1, TaskStatus::Active),
        ];
        let client = client(
            VecDeque::from([first, second]),
            VecDeque::from([
                VecDeque::from([Step::Pending]),
                VecDeque::from([Step::Pending]),
            ]),
        );
        let mut controller = TaskWatchController::new(client);
        controller.start().await.unwrap();
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:c")
        );
        controller.select_previous();
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:b")
        );
        controller
            .apply_update(update(
                TaskWatchClassification::Applied,
                81,
                Some(task("task:aa", 1, TaskStatus::Active)),
            ))
            .unwrap();
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:b")
        );
        controller.start().await.unwrap();
        assert_eq!(
            controller.model().unwrap().selected_task_id.as_deref(),
            Some("task:d")
        );
        assert!(
            controller
                .model()
                .unwrap()
                .message
                .contains("left the projection")
        );
        controller.stop().await;
    }
}
