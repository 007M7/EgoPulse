use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_operations::{
    ApprovalQueueSession, ApprovalWatchClassification, ClientApprovalWatchError, ClientAttachment,
    ClientGuidedApprovalDecisionError, GuidedApprovalDecision, GuidedApprovalDecisionInput,
    GuidedApprovalDecisionResult,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

pub const APPROVAL_QUEUE_CHANNEL_CAPACITY: usize = 32;
pub const APPROVAL_QUEUE_STOP_TIMEOUT: Duration = Duration::from_secs(1);
pub const APPROVAL_QUEUE_RECONNECT_DELAYS: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
    Duration::from_millis(2_000),
    Duration::from_millis(2_000),
];

pub type ApprovalQueueOpenFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ApprovalQueueOpened, ClientApprovalWatchError>> + Send + 'a>,
>;
pub type ApprovalQueueNextFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Option<ApprovalQueueStreamUpdate>, ClientApprovalWatchError>>
            + Send
            + 'a,
    >,
>;
pub type GuidedApprovalFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ApprovalDecisionReceipt, ClientGuidedApprovalDecisionError>>
            + Send
            + 'a,
    >,
>;
type ApprovalQueueSleepFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalQueueItem {
    pub approval_request_id: String,
    pub task_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalQueuePageModel {
    pub items: Vec<ApprovalQueueItem>,
    pub position: String,
    pub stale: bool,
    pub message: String,
    pub selected_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalProjectionWarning {
    pub code: i32,
    pub retryable: bool,
    pub required_action_code: Option<String>,
    pub safe_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionReceipt {
    pub committed: bool,
    pub replayed: bool,
    pub authority_decision_ref: String,
    pub decision: GuidedApprovalDecision,
    pub state_revision: u64,
    pub projection_warning: Option<ApprovalProjectionWarning>,
}

impl From<GuidedApprovalDecisionResult> for ApprovalDecisionReceipt {
    fn from(value: GuidedApprovalDecisionResult) -> Self {
        let warning = value
            .projection_warning()
            .map(|warning| ApprovalProjectionWarning {
                code: warning.code,
                retryable: warning.retryable,
                required_action_code: warning.required_action_code.clone(),
                safe_fingerprint: warning.safe_fingerprint.clone(),
            });
        Self {
            committed: value.committed(),
            replayed: value.replayed(),
            authority_decision_ref: value.authority_decision_ref().to_owned(),
            decision: value.decision(),
            state_revision: value.state_revision(),
            projection_warning: warning,
        }
    }
}

pub struct ApprovalQueueStreamUpdate {
    classification: ApprovalWatchClassification,
    position: String,
    items: Vec<ApprovalQueueItem>,
}

impl ApprovalQueueStreamUpdate {
    #[doc(hidden)]
    #[must_use]
    pub fn from_safe_projection(
        classification: ApprovalWatchClassification,
        position: impl Into<String>,
        items: Vec<ApprovalQueueItem>,
    ) -> Self {
        Self {
            classification,
            position: position.into(),
            items,
        }
    }
}

pub trait ApprovalQueueStream: Send {
    fn next_update(&mut self) -> ApprovalQueueNextFuture<'_>;
}

impl ApprovalQueueStream for ApprovalQueueSession {
    fn next_update(&mut self) -> ApprovalQueueNextFuture<'_> {
        Box::pin(async move {
            let update = ApprovalQueueSession::next_update(self).await?;
            Ok(update.map(|update| ApprovalQueueStreamUpdate {
                classification: update.classification,
                position: format!("{}:{}", update.position.epoch, update.position.sequence),
                items: safe_items(self.actionable_approvals()),
            }))
        })
    }
}

pub struct ApprovalQueueOpened {
    position: String,
    items: Vec<ApprovalQueueItem>,
    stream: Box<dyn ApprovalQueueStream>,
}

impl ApprovalQueueOpened {
    #[doc(hidden)]
    #[must_use]
    pub fn from_safe_projection(
        position: impl Into<String>,
        items: Vec<ApprovalQueueItem>,
        stream: Box<dyn ApprovalQueueStream>,
    ) -> Self {
        Self {
            position: position.into(),
            items,
            stream,
        }
    }
}

pub trait ApprovalQueueClient: Send + Sync {
    fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_>;
    fn decide_guided_approval(
        &self,
        input: GuidedApprovalDecisionInput,
    ) -> GuidedApprovalFuture<'_>;
}

impl ApprovalQueueClient for ClientAttachment {
    fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
        Box::pin(async move {
            let baseline = self.read_actionable_approval_queue().await?;
            let position = format!(
                "{}:{}",
                baseline.position().epoch,
                baseline.position().sequence
            );
            let items = safe_items(baseline.actionable_approvals());
            let session = self.open_approval_queue_from(baseline).await?;
            Ok(ApprovalQueueOpened {
                position,
                items,
                stream: Box::new(session),
            })
        })
    }

    fn decide_guided_approval(
        &self,
        input: GuidedApprovalDecisionInput,
    ) -> GuidedApprovalFuture<'_> {
        Box::pin(async move {
            ClientAttachment::decide_guided_approval(self, input)
                .await
                .map(ApprovalDecisionReceipt::from)
        })
    }
}

fn safe_items(
    values: Vec<&egopulse_client_operations::ActionableApproval>,
) -> Vec<ApprovalQueueItem> {
    let mut items = values
        .into_iter()
        .map(|value| ApprovalQueueItem {
            approval_request_id: value.approval_request_id().to_owned(),
            task_id: value.task_id().to_owned(),
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.approval_request_id.cmp(&right.approval_request_id));
    items
}

enum ApprovalQueueWorkerEvent {
    Update {
        generation: u64,
        update: ApprovalQueueStreamUpdate,
    },
    Replace {
        generation: u64,
        position: String,
        items: Vec<ApprovalQueueItem>,
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

impl ApprovalQueueWorkerEvent {
    fn generation(&self) -> u64 {
        match self {
            Self::Update { generation, .. }
            | Self::Replace { generation, .. }
            | Self::Stale { generation, .. }
            | Self::Failed { generation, .. } => *generation,
        }
    }
}

struct ApprovalQueueRuntime {
    events: mpsc::Receiver<ApprovalQueueWorkerEvent>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl ApprovalQueueRuntime {
    async fn stop(mut self) {
        let _ = self.cancel.send(true);
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if tokio::time::timeout(APPROVAL_QUEUE_STOP_TIMEOUT, &mut worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = tokio::time::timeout(APPROVAL_QUEUE_STOP_TIMEOUT, worker).await;
        }
    }
}

impl Drop for ApprovalQueueRuntime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

trait ApprovalQueueSleeper: Send + Sync {
    fn sleep(&self, duration: Duration) -> ApprovalQueueSleepFuture;
}

struct TokioApprovalQueueSleeper;

impl ApprovalQueueSleeper for TokioApprovalQueueSleeper {
    fn sleep(&self, duration: Duration) -> ApprovalQueueSleepFuture {
        Box::pin(tokio::time::sleep(duration))
    }
}

pub struct ApprovalQueueController<C: ApprovalQueueClient + ?Sized + 'static> {
    client: Arc<C>,
    model: Option<ApprovalQueuePageModel>,
    generation: u64,
    runtime: Option<ApprovalQueueRuntime>,
    sleeper: Arc<dyn ApprovalQueueSleeper>,
}

impl<C: ApprovalQueueClient + ?Sized + 'static> ApprovalQueueController<C> {
    #[must_use]
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            model: None,
            generation: 0,
            runtime: None,
            sleeper: Arc::new(TokioApprovalQueueSleeper),
        }
    }

    #[must_use]
    pub fn model(&self) -> Option<&ApprovalQueuePageModel> {
        self.model.as_ref()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    pub async fn start(&mut self) -> Result<(), String> {
        self.stop().await;
        let opened = self
            .client
            .open_approval_queue()
            .await
            .map_err(|error| error.to_string())?;
        self.generation = self.generation.wrapping_add(1).max(1);
        let mut items = opened.items;
        items.sort_by(|left, right| left.approval_request_id.cmp(&right.approval_request_id));
        let selected_id = items.first().map(|item| item.approval_request_id.clone());
        self.model = Some(ApprovalQueuePageModel {
            selected_id,
            items,
            position: opened.position,
            stale: false,
            message: "Approval Queue live; Enter decides, Esc returns, r refetches".to_owned(),
        });
        self.spawn_worker(opened.stream);
        Ok(())
    }

    fn spawn_worker(&mut self, stream: Box<dyn ApprovalQueueStream>) {
        let generation = self.generation;
        let (sender, events) = mpsc::channel(APPROVAL_QUEUE_CHANNEL_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);
        let worker = tokio::spawn(run_approval_queue_worker(
            Arc::clone(&self.client),
            generation,
            stream,
            sender,
            cancel_receiver,
            Arc::clone(&self.sleeper),
        ));
        self.runtime = Some(ApprovalQueueRuntime {
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

    pub fn select_previous(&mut self) {
        self.move_selection(-1);
    }

    pub fn select_next(&mut self) {
        self.move_selection(1);
    }

    fn move_selection(&mut self, delta: isize) {
        let Some(model) = &mut self.model else { return };
        if model.items.is_empty() {
            model.selected_id = None;
            return;
        }
        let current = model
            .selected_id
            .as_ref()
            .and_then(|id| {
                model
                    .items
                    .iter()
                    .position(|item| &item.approval_request_id == id)
            })
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, model.items.len().saturating_sub(1) as isize)
            as usize;
        model.selected_id = Some(model.items[next].approval_request_id.clone());
    }

    pub async fn pump(&mut self) -> Result<(), String> {
        let events = self.take_events();
        for event in events {
            if event.generation() != self.generation {
                continue;
            }
            match event {
                ApprovalQueueWorkerEvent::Update { update, .. } => {
                    self.replace_items(update.items, update.position);
                    if let Some(model) = &mut self.model {
                        model.stale = false;
                        model.message = match update.classification {
                            ApprovalWatchClassification::Applied => {
                                "Approval Queue applied a durable projection".to_owned()
                            }
                            ApprovalWatchClassification::Replay => {
                                "Approval Queue verified a replay; facts unchanged".to_owned()
                            }
                            ApprovalWatchClassification::Heartbeat => {
                                "Approval Queue heartbeat; facts unchanged".to_owned()
                            }
                            ApprovalWatchClassification::ResetRequired => {
                                "Approval Queue reset and refetched".to_owned()
                            }
                        };
                    }
                }
                ApprovalQueueWorkerEvent::Replace {
                    position, items, ..
                } => {
                    self.replace_items(items, position);
                    if let Some(model) = &mut self.model {
                        model.stale = false;
                        model.message = "Approval Queue refetched after stream reset".to_owned();
                    }
                }
                ApprovalQueueWorkerEvent::Stale { detail, .. } => {
                    if let Some(model) = &mut self.model {
                        model.stale = true;
                        model.message =
                            format!("Approval Queue stale; bounded reconnect: {detail}");
                    }
                }
                ApprovalQueueWorkerEvent::Failed { detail, .. } => {
                    if let Some(model) = &mut self.model {
                        model.stale = true;
                        model.message = format!("Approval Queue stopped fail-closed: {detail}");
                    }
                    self.stop().await;
                    return Err(detail);
                }
            }
        }
        Ok(())
    }

    fn take_events(&mut self) -> Vec<ApprovalQueueWorkerEvent> {
        let Some(runtime) = &mut self.runtime else {
            return Vec::new();
        };
        let mut events = Vec::new();
        while let Ok(event) = runtime.events.try_recv() {
            events.push(event);
        }
        events
    }

    fn replace_items(&mut self, mut items: Vec<ApprovalQueueItem>, position: String) {
        items.sort_by(|left, right| left.approval_request_id.cmp(&right.approval_request_id));
        let model = self.model.get_or_insert_with(|| ApprovalQueuePageModel {
            items: Vec::new(),
            position: position.clone(),
            stale: false,
            message: String::new(),
            selected_id: None,
        });
        let selected = model.selected_id.clone();
        model.items = items;
        model.position = position;
        model.selected_id = selected
            .filter(|id| {
                model
                    .items
                    .iter()
                    .any(|item| &item.approval_request_id == id)
            })
            .or_else(|| {
                model
                    .items
                    .first()
                    .map(|item| item.approval_request_id.clone())
            });
    }

    pub async fn decide_selected(
        &mut self,
        decision: GuidedApprovalDecision,
        reason_code: String,
        confirmation_proof_ref: Option<String>,
    ) -> Result<ApprovalDecisionReceipt, ClientGuidedApprovalDecisionError> {
        let selected = self
            .model
            .as_ref()
            .and_then(|model| model.selected_id.clone())
            .ok_or(ClientGuidedApprovalDecisionError::NonActionable)?;
        if !self.model.as_ref().is_some_and(|model| {
            model
                .items
                .iter()
                .any(|item| item.approval_request_id == selected)
        }) {
            return Err(ClientGuidedApprovalDecisionError::NonActionable);
        }
        self.client
            .decide_guided_approval(GuidedApprovalDecisionInput {
                approval_request_id: selected,
                decision,
                reason_code,
                confirmation_proof_ref,
            })
            .await
    }
}

impl<C: ApprovalQueueClient + ?Sized + 'static> Drop for ApprovalQueueController<C> {
    fn drop(&mut self) {
        self.runtime.take();
    }
}

fn approval_queue_failure_is_retryable(error: &ClientApprovalWatchError) -> bool {
    matches!(
        error,
        ClientApprovalWatchError::Transport(_) | ClientApprovalWatchError::UnexpectedEof
    )
}

async fn send_event(
    sender: &mpsc::Sender<ApprovalQueueWorkerEvent>,
    cancel: &mut watch::Receiver<bool>,
    event: ApprovalQueueWorkerEvent,
) -> bool {
    tokio::select! {
        permit = sender.reserve() => match permit {
            Ok(permit) => { permit.send(event); true }
            Err(_) => false,
        },
        changed = cancel.changed() => changed.is_ok() && !*cancel.borrow(),
    }
}

async fn run_approval_queue_worker<C: ApprovalQueueClient + ?Sized + 'static>(
    client: Arc<C>,
    generation: u64,
    mut stream: Box<dyn ApprovalQueueStream>,
    sender: mpsc::Sender<ApprovalQueueWorkerEvent>,
    mut cancel: watch::Receiver<bool>,
    sleeper: Arc<dyn ApprovalQueueSleeper>,
) {
    let mut retry_index = 0_usize;
    let recovery = ApprovalQueueRecoveryContext {
        client: &client,
        generation,
        sender: &sender,
        sleeper: sleeper.as_ref(),
    };
    loop {
        let next = tokio::select! {
            _ = cancel.changed() => return,
            next = stream.next_update() => next,
        };
        match next {
            Ok(Some(update))
                if update.classification == ApprovalWatchClassification::ResetRequired =>
            {
                match client.open_approval_queue().await {
                    Ok(opened) => {
                        retry_index = 0;
                        stream = opened.stream;
                        if !send_event(
                            &sender,
                            &mut cancel,
                            ApprovalQueueWorkerEvent::Replace {
                                generation,
                                position: opened.position,
                                items: opened.items,
                            },
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(error) => {
                        if !recover_queue(
                            &recovery,
                            &mut cancel,
                            &mut stream,
                            &mut retry_index,
                            error,
                        )
                        .await
                        {
                            return;
                        }
                    }
                }
            }
            Ok(Some(update)) => {
                retry_index = 0;
                if !send_event(
                    &sender,
                    &mut cancel,
                    ApprovalQueueWorkerEvent::Update { generation, update },
                )
                .await
                {
                    return;
                }
            }
            Ok(None) => {
                if !recover_queue(
                    &recovery,
                    &mut cancel,
                    &mut stream,
                    &mut retry_index,
                    ClientApprovalWatchError::UnexpectedEof,
                )
                .await
                {
                    return;
                }
            }
            Err(error) => {
                if !recover_queue(&recovery, &mut cancel, &mut stream, &mut retry_index, error)
                    .await
                {
                    return;
                }
            }
        }
    }
}

struct ApprovalQueueRecoveryContext<'a, C: ApprovalQueueClient + ?Sized> {
    client: &'a Arc<C>,
    generation: u64,
    sender: &'a mpsc::Sender<ApprovalQueueWorkerEvent>,
    sleeper: &'a dyn ApprovalQueueSleeper,
}

async fn recover_queue<C: ApprovalQueueClient + ?Sized + 'static>(
    context: &ApprovalQueueRecoveryContext<'_, C>,
    cancel: &mut watch::Receiver<bool>,
    stream: &mut Box<dyn ApprovalQueueStream>,
    retry_index: &mut usize,
    error: ClientApprovalWatchError,
) -> bool {
    if !approval_queue_failure_is_retryable(&error) {
        let _ = send_event(
            context.sender,
            cancel,
            ApprovalQueueWorkerEvent::Failed {
                generation: context.generation,
                detail: error.to_string(),
            },
        )
        .await;
        return false;
    }
    if !send_event(
        context.sender,
        cancel,
        ApprovalQueueWorkerEvent::Stale {
            generation: context.generation,
            detail: error.to_string(),
        },
    )
    .await
    {
        return false;
    }
    let Some(delay) = APPROVAL_QUEUE_RECONNECT_DELAYS.get(*retry_index).copied() else {
        let _ = send_event(
            context.sender,
            cancel,
            ApprovalQueueWorkerEvent::Failed {
                generation: context.generation,
                detail: "Approval Queue reconnect budget exhausted".to_owned(),
            },
        )
        .await;
        return false;
    };
    *retry_index += 1;
    tokio::select! {
        _ = context.sleeper.sleep(delay) => {}
        _ = cancel.changed() => return false,
    }
    match context.client.open_approval_queue().await {
        Ok(opened) => {
            *stream = opened.stream;
            if !send_event(
                context.sender,
                cancel,
                ApprovalQueueWorkerEvent::Replace {
                    generation: context.generation,
                    position: opened.position,
                    items: opened.items,
                },
            )
            .await
            {
                return false;
            }
            true
        }
        Err(next) => Box::pin(recover_queue(context, cancel, stream, retry_index, next)).await,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use egopulse_domain_contracts::v01::egopulse::{
        localapi::v1::LocalApiError, policy::v1::PolicyDecisionErrorCode,
    };

    use super::*;

    enum StreamStep {
        Update(
            ApprovalWatchClassification,
            &'static str,
            Vec<ApprovalQueueItem>,
        ),
        Eof,
        Transport,
        Integrity,
        Pending,
    }

    struct ScriptedStream {
        steps: VecDeque<StreamStep>,
        next_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for ScriptedStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ApprovalQueueStream for ScriptedStream {
        fn next_update(&mut self) -> ApprovalQueueNextFuture<'_> {
            self.next_calls.fetch_add(1, Ordering::SeqCst);
            let step = self.steps.pop_front().unwrap_or(StreamStep::Pending);
            Box::pin(async move {
                match step {
                    StreamStep::Update(classification, position, items) => {
                        Ok(Some(ApprovalQueueStreamUpdate {
                            classification,
                            position: position.to_owned(),
                            items,
                        }))
                    }
                    StreamStep::Eof => Ok(None),
                    StreamStep::Transport => {
                        Err(ClientApprovalWatchError::Transport("offline".to_owned()))
                    }
                    StreamStep::Integrity => Err(ClientApprovalWatchError::Protocol("drift")),
                    StreamStep::Pending => std::future::pending().await,
                }
            })
        }
    }

    enum OpenStep {
        Open {
            position: &'static str,
            items: Vec<ApprovalQueueItem>,
            stream: VecDeque<StreamStep>,
        },
        Transport,
        Permission,
    }

    enum DecideStep {
        Success(Option<ApprovalProjectionWarning>),
        Conflict,
    }

    struct ScriptedClient {
        opens: Mutex<VecDeque<OpenStep>>,
        decisions: Mutex<VecDeque<DecideStep>>,
        open_calls: AtomicUsize,
        decide_calls: AtomicUsize,
        next_calls: Arc<AtomicUsize>,
        stream_drops: Arc<AtomicUsize>,
        captured: Mutex<Vec<GuidedApprovalDecisionInput>>,
    }

    impl ScriptedClient {
        fn new(opens: VecDeque<OpenStep>) -> Self {
            Self {
                opens: Mutex::new(opens),
                decisions: Mutex::new(VecDeque::new()),
                open_calls: AtomicUsize::new(0),
                decide_calls: AtomicUsize::new(0),
                next_calls: Arc::new(AtomicUsize::new(0)),
                stream_drops: Arc::new(AtomicUsize::new(0)),
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl ApprovalQueueClient for ScriptedClient {
        fn open_approval_queue(&self) -> ApprovalQueueOpenFuture<'_> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .opens
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(OpenStep::Permission);
            let next_calls = Arc::clone(&self.next_calls);
            let drops = Arc::clone(&self.stream_drops);
            Box::pin(async move {
                match step {
                    OpenStep::Open {
                        position,
                        items,
                        stream,
                    } => Ok(ApprovalQueueOpened {
                        position: position.to_owned(),
                        items,
                        stream: Box::new(ScriptedStream {
                            steps: stream,
                            next_calls,
                            drops,
                        }),
                    }),
                    OpenStep::Transport => {
                        Err(ClientApprovalWatchError::Transport("offline".to_owned()))
                    }
                    OpenStep::Permission => Err(ClientApprovalWatchError::Protocol("permission")),
                }
            })
        }

        fn decide_guided_approval(
            &self,
            input: GuidedApprovalDecisionInput,
        ) -> GuidedApprovalFuture<'_> {
            self.decide_calls.fetch_add(1, Ordering::SeqCst);
            self.captured.lock().unwrap().push(input.clone());
            let step = self
                .decisions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DecideStep::Conflict);
            Box::pin(async move {
                match step {
                    DecideStep::Success(projection_warning) => Ok(ApprovalDecisionReceipt {
                        committed: true,
                        replayed: false,
                        authority_decision_ref: "decision:1".to_owned(),
                        decision: input.decision,
                        state_revision: 1,
                        projection_warning,
                    }),
                    DecideStep::Conflict => Err(ClientGuidedApprovalDecisionError::Authority {
                        error_code: PolicyDecisionErrorCode::IdempotencyConflict as i32,
                        safe_error_fingerprint: Some("approval/conflict/v1".to_owned()),
                    }),
                }
            })
        }
    }

    struct ImmediateSleeper {
        delays: Mutex<Vec<Duration>>,
    }

    impl ApprovalQueueSleeper for ImmediateSleeper {
        fn sleep(&self, duration: Duration) -> ApprovalQueueSleepFuture {
            self.delays.lock().unwrap().push(duration);
            Box::pin(std::future::ready(()))
        }
    }

    fn item(id: &str) -> ApprovalQueueItem {
        ApprovalQueueItem {
            approval_request_id: id.to_owned(),
            task_id: format!("task:{id}"),
        }
    }

    fn opened(
        position: &'static str,
        items: Vec<ApprovalQueueItem>,
        stream: VecDeque<StreamStep>,
    ) -> OpenStep {
        OpenStep::Open {
            position,
            items,
            stream,
        }
    }

    async fn pump_until(
        controller: &mut ApprovalQueueController<ScriptedClient>,
        predicate: impl Fn(&ApprovalQueuePageModel) -> bool,
    ) {
        for _ in 0..100 {
            tokio::task::yield_now().await;
            let _ = controller.pump().await;
            if controller.model().is_some_and(&predicate) {
                return;
            }
        }
        panic!("Approval Queue condition not reached");
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "counter did not reach {expected}; actual={}",
            counter.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn baseline_open_updates_same_position_removal_and_selection_are_deterministic() {
        let client = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:100",
            vec![item("approval:b"), item("approval:a")],
            VecDeque::from([
                StreamStep::Update(
                    ApprovalWatchClassification::Applied,
                    "epoch:1:101",
                    vec![item("approval:a"), item("approval:c")],
                ),
                StreamStep::Update(
                    ApprovalWatchClassification::Applied,
                    "epoch:1:101",
                    vec![item("approval:c"), item("approval:d")],
                ),
                StreamStep::Pending,
            ]),
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&client));
        controller.start().await.unwrap();
        assert_eq!(client.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller
                .model()
                .unwrap()
                .items
                .iter()
                .map(|item| item.approval_request_id.as_str())
                .collect::<Vec<_>>(),
            ["approval:a", "approval:b"]
        );
        controller.select_next();
        assert_eq!(
            controller.model().unwrap().selected_id.as_deref(),
            Some("approval:b")
        );
        pump_until(&mut controller, |model| {
            model
                .items
                .iter()
                .any(|item| item.approval_request_id == "approval:d")
        })
        .await;
        assert_eq!(
            controller.model().unwrap().selected_id.as_deref(),
            Some("approval:c")
        );
        assert_eq!(controller.model().unwrap().position, "epoch:1:101");
        controller.stop().await;
    }

    #[tokio::test]
    async fn reset_refetches_and_eof_transport_use_bounded_full_reopen() {
        let client = Arc::new(ScriptedClient::new(VecDeque::from([
            opened(
                "epoch:1:1",
                vec![item("approval:a")],
                VecDeque::from([StreamStep::Update(
                    ApprovalWatchClassification::ResetRequired,
                    "epoch:1:2",
                    vec![item("approval:a")],
                )]),
            ),
            opened(
                "epoch:2:20",
                vec![item("approval:b")],
                VecDeque::from([StreamStep::Eof]),
            ),
            OpenStep::Transport,
            opened(
                "epoch:2:21",
                vec![item("approval:c")],
                VecDeque::from([StreamStep::Transport]),
            ),
            opened(
                "epoch:2:22",
                vec![item("approval:d")],
                VecDeque::from([StreamStep::Pending]),
            ),
        ])));
        let sleeper = Arc::new(ImmediateSleeper {
            delays: Mutex::new(Vec::new()),
        });
        let mut controller = ApprovalQueueController {
            client: Arc::clone(&client),
            model: None,
            generation: 0,
            runtime: None,
            sleeper: Arc::clone(&sleeper) as Arc<dyn ApprovalQueueSleeper>,
        };
        controller.start().await.unwrap();
        pump_until(&mut controller, |model| {
            model
                .items
                .iter()
                .any(|item| item.approval_request_id == "approval:d")
        })
        .await;
        assert_eq!(client.open_calls.load(Ordering::SeqCst), 5);
        assert_eq!(
            sleeper.delays.lock().unwrap().as_slice(),
            &APPROVAL_QUEUE_RECONNECT_DELAYS[..3]
        );
        controller.stop().await;
    }

    #[tokio::test]
    async fn integrity_and_permission_fail_closed_without_retry_and_stop_cancels() {
        let integrity = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            VecDeque::from([StreamStep::Integrity]),
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&integrity));
        controller.start().await.unwrap();
        wait_for_count(&integrity.next_calls, 1).await;
        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match controller.pump().await {
                    Ok(()) => tokio::task::yield_now().await,
                    Err(error) => break error,
                }
            }
        })
        .await
        .expect("integrity failure must reach the controller deterministically");
        assert_eq!(error, "approval watch protocol integrity failed: drift");
        assert!(!controller.is_running());
        assert!(controller.model().unwrap().stale);
        assert_eq!(integrity.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(integrity.next_calls.load(Ordering::SeqCst), 1);

        let pending = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            VecDeque::from([StreamStep::Pending]),
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&pending));
        controller.start().await.unwrap();
        wait_for_count(&pending.next_calls, 1).await;
        controller.stop().await;
        assert!(!controller.is_running());
        assert_eq!(pending.open_calls.load(Ordering::SeqCst), 1);
        assert_eq!(pending.stream_drops.load(Ordering::SeqCst), 1);

        let denied = Arc::new(ScriptedClient::new(VecDeque::from([OpenStep::Permission])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&denied));
        assert!(controller.start().await.is_err());
        assert!(controller.model().is_none());
        assert_eq!(denied.open_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn full_channel_stop_and_drop_cancel_workers_without_leaks() {
        let updates = (0..=APPROVAL_QUEUE_CHANNEL_CAPACITY)
            .map(|sequence| {
                StreamStep::Update(
                    ApprovalWatchClassification::Applied,
                    "epoch:1:2",
                    vec![item(&format!("approval:{sequence}"))],
                )
            })
            .collect::<VecDeque<_>>();
        let blocked = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            updates,
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&blocked));
        controller.start().await.unwrap();
        wait_for_count(&blocked.next_calls, APPROVAL_QUEUE_CHANNEL_CAPACITY + 1).await;
        tokio::time::timeout(
            APPROVAL_QUEUE_STOP_TIMEOUT + Duration::from_secs(1),
            controller.stop(),
        )
        .await
        .expect("full-channel stop must remain bounded");
        assert!(!controller.is_running());
        assert_eq!(blocked.stream_drops.load(Ordering::SeqCst), 1);

        let dropped = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            VecDeque::from([StreamStep::Pending]),
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&dropped));
        controller.start().await.unwrap();
        wait_for_count(&dropped.next_calls, 1).await;
        drop(controller);
        wait_for_count(&dropped.stream_drops, 1).await;
        assert_eq!(dropped.next_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_generation_events_are_discarded_without_mutating_the_page() {
        let client = Arc::new(ScriptedClient::new(VecDeque::new()));
        let (sender, events) = mpsc::channel(1);
        sender
            .send(ApprovalQueueWorkerEvent::Update {
                generation: 1,
                update: ApprovalQueueStreamUpdate {
                    classification: ApprovalWatchClassification::Applied,
                    position: "epoch:1:2".to_owned(),
                    items: vec![item("approval:stale")],
                },
            })
            .await
            .unwrap();
        drop(sender);
        let (cancel, _cancel_receiver) = watch::channel(false);
        let expected = ApprovalQueuePageModel {
            items: vec![item("approval:current")],
            position: "epoch:2:8".to_owned(),
            stale: false,
            message: "current".to_owned(),
            selected_id: Some("approval:current".to_owned()),
        };
        let mut controller = ApprovalQueueController {
            client,
            model: Some(expected.clone()),
            generation: 2,
            runtime: Some(ApprovalQueueRuntime {
                events,
                cancel,
                worker: None,
            }),
            sleeper: Arc::new(TokioApprovalQueueSleeper),
        };
        controller.pump().await.unwrap();
        assert_eq!(controller.model(), Some(&expected));
        controller.stop().await;
    }

    #[tokio::test]
    async fn candidate_removed_after_modal_open_is_non_actionable_without_decide_rpc() {
        let client = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            VecDeque::from([
                StreamStep::Update(
                    ApprovalWatchClassification::Applied,
                    "epoch:1:2",
                    Vec::new(),
                ),
                StreamStep::Pending,
            ]),
        )])));
        let mut controller = ApprovalQueueController::new(Arc::clone(&client));
        controller.start().await.unwrap();
        pump_until(&mut controller, |model| model.items.is_empty()).await;
        assert!(matches!(
            controller
                .decide_selected(
                    GuidedApprovalDecision::Deny,
                    "founder-reviewed".to_owned(),
                    None,
                )
                .await,
            Err(ClientGuidedApprovalDecisionError::NonActionable)
        ));
        assert_eq!(client.decide_calls.load(Ordering::SeqCst), 0);
        controller.stop().await;
    }

    #[tokio::test]
    async fn guided_decision_returns_safe_warning_and_conflict_without_queue_mutation_or_retry() {
        let client = Arc::new(ScriptedClient::new(VecDeque::from([opened(
            "epoch:1:1",
            vec![item("approval:a")],
            VecDeque::from([StreamStep::Pending]),
        )])));
        client.decisions.lock().unwrap().extend([
            DecideStep::Success(Some(ApprovalProjectionWarning {
                code: 8,
                retryable: true,
                required_action_code: Some("AWAIT_PROJECTION".to_owned()),
                safe_fingerprint: "projection/behind/v1".to_owned(),
            })),
            DecideStep::Conflict,
        ]);
        let mut controller = ApprovalQueueController::new(Arc::clone(&client));
        controller.start().await.unwrap();
        let receipt = controller
            .decide_selected(
                GuidedApprovalDecision::Deny,
                "founder-denied".to_owned(),
                Some("proof:1".to_owned()),
            )
            .await
            .unwrap();
        assert!(receipt.projection_warning.is_some());
        assert_eq!(controller.model().unwrap().items, [item("approval:a")]);
        assert!(matches!(
            controller
                .decide_selected(GuidedApprovalDecision::AllowOnce, "again".to_owned(), None)
                .await,
            Err(ClientGuidedApprovalDecisionError::Authority { .. })
        ));
        assert_eq!(client.decide_calls.load(Ordering::SeqCst), 2);
        assert_eq!(controller.model().unwrap().items, [item("approval:a")]);
        {
            let captured = client.captured.lock().unwrap();
            assert_eq!(captured[0].approval_request_id, "approval:a");
            assert_eq!(captured[0].reason_code, "founder-denied");
        }
        controller.stop().await;
    }

    #[test]
    fn public_page_model_contains_only_safe_projection_fields() {
        let model = ApprovalQueuePageModel {
            items: vec![item("approval:a")],
            position: "epoch:1:1".to_owned(),
            stale: false,
            message: "live".to_owned(),
            selected_id: Some("approval:a".to_owned()),
        };
        assert_eq!(model.items[0].task_id, "task:approval:a");
        let _safe_warning = ApprovalProjectionWarning {
            code: LocalApiError::default().code,
            retryable: false,
            required_action_code: None,
            safe_fingerprint: String::new(),
        };
    }
}
