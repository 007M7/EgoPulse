//! Pure safe page model for the governed state session view.
//!
//! The model is built exclusively from the public getters of the shared
//! `client-operations` governed state composite. It holds no projection
//! cursor and owns no recovery logic.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_operations::{
    ClientAttachment, GovernedStateComposite, GovernedStateDomain, GovernedStateDomainPhase,
    GovernedStateReason, GovernedStateSession,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

const GOVERNED_STATE_CHANNEL_CAPACITY: usize = 1;
const GOVERNED_STATE_STOP_TIMEOUT: Duration = Duration::from_secs(3);

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

/// An owned safe snapshot of the two independently governed domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedStateSnapshot {
    pub task: TaskDomainPage,
    pub approval: ApprovalDomainPage,
}

impl GovernedStateSnapshot {
    #[must_use]
    pub fn from_composite(composite: &GovernedStateComposite) -> Self {
        Self {
            task: task_domain_page(composite.task()),
            approval: approval_domain_page(composite.approval()),
        }
    }
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
        Self::initial_from_snapshot(GovernedStateSnapshot::from_composite(composite))
    }

    #[must_use]
    pub fn initial_from_snapshot(snapshot: GovernedStateSnapshot) -> Self {
        Self {
            kind: RecordKind::Initial,
            update_index: 0,
            changed_domain: None,
            task: snapshot.task,
            approval: snapshot.approval,
            stopped: false,
        }
    }

    #[must_use]
    pub fn updated(
        update_index: u64,
        domain: GovernedStateDomain,
        composite: &GovernedStateComposite,
    ) -> Self {
        Self::updated_from_snapshot(
            update_index,
            domain,
            GovernedStateSnapshot::from_composite(composite),
        )
    }

    #[must_use]
    pub fn updated_from_snapshot(
        update_index: u64,
        domain: GovernedStateDomain,
        snapshot: GovernedStateSnapshot,
    ) -> Self {
        Self {
            kind: RecordKind::Update,
            update_index,
            changed_domain: Some(domain),
            task: snapshot.task,
            approval: snapshot.approval,
            stopped: false,
        }
    }

    pub fn mark_stopped(&mut self) {
        self.stopped = true;
    }
}

/// Safe start failure for the presentation-only controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernedStateControllerStartError {
    RuntimeUnavailable,
}

/// Narrow safe stream owned by the TUI controller.
pub trait GovernedStateStream: Send {
    fn safe_snapshot(&self) -> GovernedStateSnapshot;

    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + Send + '_>>;

    fn shutdown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Narrow attachment seam. Implementations may only start the shared stream.
pub trait GovernedStateClient: Send + Sync {
    fn start_governed_state_stream(
        self: &Arc<Self>,
    ) -> Result<Box<dyn GovernedStateStream>, GovernedStateControllerStartError>;
}

struct AttachedGovernedStateStream {
    session: GovernedStateSession,
}

impl GovernedStateStream for AttachedGovernedStateStream {
    fn safe_snapshot(&self) -> GovernedStateSnapshot {
        GovernedStateSnapshot::from_composite(self.session.state())
    }

    fn next_update(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + Send + '_>> {
        Box::pin(async move {
            self.session
                .next_update()
                .await
                .map(|update| update.domain())
        })
    }

    fn shutdown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let _ = self.session.shutdown().await;
        })
    }
}

impl GovernedStateClient for ClientAttachment {
    fn start_governed_state_stream(
        self: &Arc<Self>,
    ) -> Result<Box<dyn GovernedStateStream>, GovernedStateControllerStartError> {
        ClientAttachment::start_governed_state_session(self)
            .map(|session| {
                Box::new(AttachedGovernedStateStream { session }) as Box<dyn GovernedStateStream>
            })
            .map_err(|_| GovernedStateControllerStartError::RuntimeUnavailable)
    }
}

enum GovernedStateWorkerEvent {
    Updated {
        domain: GovernedStateDomain,
        snapshot: Box<GovernedStateSnapshot>,
    },
    Stopped,
}

struct GovernedStateRuntime {
    events: mpsc::Receiver<GovernedStateWorkerEvent>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl GovernedStateRuntime {
    async fn stop(mut self) {
        let _ = self.cancel.send(true);
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if tokio::time::timeout(GOVERNED_STATE_STOP_TIMEOUT, &mut worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = worker.await;
        }
    }
}

impl Drop for GovernedStateRuntime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

/// Presentation controller for one shared governed-state session.
pub struct GovernedStateController {
    model: GovernedStatePageModel,
    runtime: Option<GovernedStateRuntime>,
}

impl GovernedStateController {
    pub fn start<Client>(client: Arc<Client>) -> Result<Self, GovernedStateControllerStartError>
    where
        Client: GovernedStateClient + ?Sized + 'static,
    {
        tokio::runtime::Handle::try_current()
            .map_err(|_| GovernedStateControllerStartError::RuntimeUnavailable)?;
        let stream = client.start_governed_state_stream()?;
        let model = GovernedStatePageModel::initial_from_snapshot(stream.safe_snapshot());
        let (event_sender, events) = mpsc::channel(GOVERNED_STATE_CHANNEL_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);
        let worker = tokio::spawn(run_governed_state_worker(
            stream,
            event_sender,
            cancel_receiver,
        ));
        Ok(Self {
            model,
            runtime: Some(GovernedStateRuntime {
                events,
                cancel,
                worker: Some(worker),
            }),
        })
    }

    #[must_use]
    pub const fn model(&self) -> &GovernedStatePageModel {
        &self.model
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime
            .as_ref()
            .and_then(|runtime| runtime.worker.as_ref())
            .is_some_and(|worker| !worker.is_finished())
    }

    pub fn pump(&mut self) {
        let Some(runtime) = self.runtime.as_mut() else {
            return;
        };
        loop {
            match runtime.events.try_recv() {
                Ok(GovernedStateWorkerEvent::Updated { domain, snapshot }) => {
                    self.model = GovernedStatePageModel::updated_from_snapshot(
                        self.model.update_index.saturating_add(1),
                        domain,
                        *snapshot,
                    );
                }
                Ok(GovernedStateWorkerEvent::Stopped) => self.model.mark_stopped(),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.model.mark_stopped();
                    break;
                }
            }
        }
    }

    pub async fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop().await;
        }
        self.model.mark_stopped();
    }
}

async fn send_governed_state_event(
    sender: &mpsc::Sender<GovernedStateWorkerEvent>,
    cancellation: &mut watch::Receiver<bool>,
    event: GovernedStateWorkerEvent,
) -> bool {
    if *cancellation.borrow() {
        return false;
    }
    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            false
        }
        permit = sender.reserve() => match permit {
            Ok(permit) => {
                permit.send(event);
                true
            }
            Err(_) => false,
        }
    }
}

async fn run_governed_state_worker(
    mut stream: Box<dyn GovernedStateStream>,
    sender: mpsc::Sender<GovernedStateWorkerEvent>,
    mut cancellation: watch::Receiver<bool>,
) {
    loop {
        if *cancellation.borrow() {
            break;
        }
        let update = tokio::select! {
            biased;
            changed = cancellation.changed() => {
                let _ = changed;
                break;
            }
            update = stream.next_update() => update,
        };
        let Some(domain) = update else {
            let _ = send_governed_state_event(
                &sender,
                &mut cancellation,
                GovernedStateWorkerEvent::Stopped,
            )
            .await;
            break;
        };
        let snapshot = Box::new(stream.safe_snapshot());
        if !send_governed_state_event(
            &sender,
            &mut cancellation,
            GovernedStateWorkerEvent::Updated { domain, snapshot },
        )
        .await
        {
            break;
        }
    }
    stream.shutdown().await;
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
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    enum ScriptedNext {
        Update(GovernedStateDomain, GovernedStateSnapshot),
        Eof,
        Pending,
    }

    struct ScriptedGovernedStateStream {
        snapshot: GovernedStateSnapshot,
        outcomes: VecDeque<ScriptedNext>,
        next_calls: Arc<AtomicUsize>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl GovernedStateStream for ScriptedGovernedStateStream {
        fn safe_snapshot(&self) -> GovernedStateSnapshot {
            self.snapshot.clone()
        }

        fn next_update(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Option<GovernedStateDomain>> + Send + '_>> {
            Box::pin(async move {
                self.next_calls.fetch_add(1, Ordering::SeqCst);
                match self.outcomes.pop_front().unwrap_or(ScriptedNext::Pending) {
                    ScriptedNext::Update(domain, snapshot) => {
                        self.snapshot = snapshot;
                        Some(domain)
                    }
                    ScriptedNext::Eof => None,
                    ScriptedNext::Pending => std::future::pending().await,
                }
            })
        }

        fn shutdown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    struct ScriptedGovernedStateClient {
        stream: Mutex<Option<ScriptedGovernedStateStream>>,
        starts: AtomicUsize,
    }

    impl GovernedStateClient for ScriptedGovernedStateClient {
        fn start_governed_state_stream(
            self: &Arc<Self>,
        ) -> Result<Box<dyn GovernedStateStream>, GovernedStateControllerStartError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            self.stream
                .lock()
                .expect("scripted stream lock")
                .take()
                .map(|stream| Box::new(stream) as Box<dyn GovernedStateStream>)
                .ok_or(GovernedStateControllerStartError::RuntimeUnavailable)
        }
    }

    fn scripted_client(
        snapshot: GovernedStateSnapshot,
        outcomes: Vec<ScriptedNext>,
    ) -> (
        Arc<ScriptedGovernedStateClient>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        let next_calls = Arc::new(AtomicUsize::new(0));
        let shutdowns = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(ScriptedGovernedStateClient {
                stream: Mutex::new(Some(ScriptedGovernedStateStream {
                    snapshot,
                    outcomes: outcomes.into(),
                    next_calls: Arc::clone(&next_calls),
                    shutdowns: Arc::clone(&shutdowns),
                })),
                starts: AtomicUsize::new(0),
            }),
            next_calls,
            shutdowns,
        )
    }

    fn domain_view(
        phase: GovernedStateDomainPhase,
        reason: Option<GovernedStateReason>,
        domain: &str,
        sequence: Option<u64>,
    ) -> DomainView {
        DomainView {
            phase: phase_label(phase).to_owned(),
            reason: reason.map(|reason| reason_label(reason).to_owned()),
            generation: sequence.unwrap_or(1),
            recovery_limit: 3,
            recovery_remaining: 3,
            epoch: sequence.map(|_| format!("{domain}-epoch:test")),
            sequence,
        }
    }

    fn connecting_snapshot() -> GovernedStateSnapshot {
        GovernedStateSnapshot {
            task: TaskDomainPage {
                view: domain_view(GovernedStateDomainPhase::Connecting, None, "task", None),
                facts: Vec::new(),
            },
            approval: ApprovalDomainPage {
                view: domain_view(GovernedStateDomainPhase::Connecting, None, "approval", None),
                facts: Vec::new(),
            },
        }
    }

    fn live_snapshot(task_sequence: u64, approval_sequence: u64) -> GovernedStateSnapshot {
        GovernedStateSnapshot {
            task: TaskDomainPage {
                view: domain_view(
                    GovernedStateDomainPhase::Live,
                    None,
                    "task",
                    Some(task_sequence),
                ),
                facts: vec![TaskFactView {
                    task_id: "task:governed".to_owned(),
                    revision: task_sequence,
                    status: "task_status_active".to_owned(),
                }],
            },
            approval: ApprovalDomainPage {
                view: domain_view(
                    GovernedStateDomainPhase::Live,
                    None,
                    "approval",
                    Some(approval_sequence),
                ),
                facts: vec![ApprovalFactView {
                    approval_request_id: format!("approval:{approval_sequence}"),
                    task_id: "task:governed".to_owned(),
                }],
            },
        }
    }

    async fn pump_until(
        controller: &mut GovernedStateController,
        predicate: impl Fn(&GovernedStatePageModel) -> bool,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                controller.pump();
                if predicate(controller.model()) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("governed state controller condition");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_publishes_the_double_connecting_snapshot_before_updates() {
        let (client, next_calls, shutdowns) =
            scripted_client(connecting_snapshot(), vec![ScriptedNext::Pending]);
        let mut controller =
            GovernedStateController::start(Arc::clone(&client)).expect("controller should start");

        assert_eq!(client.starts.load(Ordering::SeqCst), 1);
        assert_eq!(controller.model().kind, RecordKind::Initial);
        assert_eq!(controller.model().update_index, 0);
        assert_eq!(controller.model().changed_domain, None);
        assert_eq!(controller.model().task.view.phase, "connecting");
        assert_eq!(controller.model().approval.view.phase, "connecting");
        assert!(controller.model().task.view.reason.is_none());
        assert!(controller.model().approval.view.reason.is_none());
        assert!(controller.model().task.view.epoch.is_none());
        assert!(controller.model().approval.view.epoch.is_none());
        assert!(controller.model().task.facts.is_empty());
        assert!(controller.model().approval.facts.is_empty());

        tokio::task::yield_now().await;
        assert_eq!(next_calls.load(Ordering::SeqCst), 1);
        controller.stop().await;
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert!(controller.model().stopped);
        assert!(!controller.is_running());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_applies_domains_independently_and_approval_survives_task_fatal() {
        let mut task_live = connecting_snapshot();
        task_live.task = live_snapshot(2, 1).task;
        let mut approval_live = task_live.clone();
        approval_live.approval = live_snapshot(2, 2).approval;
        let mut task_fatal = approval_live.clone();
        task_fatal.task.view.phase = "fatal".to_owned();
        task_fatal.task.view.reason = Some("projection_integrity_failure".to_owned());
        let mut approval_after_fatal = task_fatal.clone();
        approval_after_fatal.approval = live_snapshot(2, 3).approval;
        let (client, _, shutdowns) = scripted_client(
            connecting_snapshot(),
            vec![
                ScriptedNext::Update(GovernedStateDomain::Task, task_live.clone()),
                ScriptedNext::Update(GovernedStateDomain::Approval, approval_live.clone()),
                ScriptedNext::Update(GovernedStateDomain::Task, task_fatal.clone()),
                ScriptedNext::Update(GovernedStateDomain::Approval, approval_after_fatal.clone()),
                ScriptedNext::Eof,
            ],
        );
        let mut controller = GovernedStateController::start(client).expect("controller start");

        pump_until(&mut controller, |model| model.update_index == 1).await;
        assert_eq!(controller.model().task, task_live.task);
        assert_eq!(controller.model().approval, connecting_snapshot().approval);
        pump_until(&mut controller, |model| model.update_index == 2).await;
        assert_eq!(controller.model().task, approval_live.task);
        assert_eq!(controller.model().approval, approval_live.approval);
        pump_until(&mut controller, |model| model.update_index == 3).await;
        assert_eq!(controller.model().task, task_fatal.task);
        let fatal_task = controller.model().task.clone();
        pump_until(&mut controller, |model| model.update_index == 4).await;
        assert_eq!(controller.model().task, fatal_task);
        assert_eq!(controller.model().approval, approval_after_fatal.approval);
        assert_eq!(
            controller.model().changed_domain,
            Some(GovernedStateDomain::Approval)
        );
        pump_until(&mut controller, |model| model.stopped).await;

        controller.stop().await;
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert!(!controller.is_running());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_cancel_interrupts_pending_next_and_shuts_down_once() {
        let (client, next_calls, shutdowns) =
            scripted_client(connecting_snapshot(), vec![ScriptedNext::Pending]);
        let mut controller = GovernedStateController::start(client).expect("controller start");
        while next_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        controller.stop().await;
        controller.stop().await;

        assert_eq!(next_calls.load(Ordering::SeqCst), 1);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert!(controller.model().stopped);
        assert!(!controller.is_running());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_event_channel_cancellation_leaves_no_worker_or_second_event() {
        let (client, next_calls, shutdowns) = scripted_client(
            connecting_snapshot(),
            vec![
                ScriptedNext::Update(GovernedStateDomain::Task, live_snapshot(2, 1)),
                ScriptedNext::Update(GovernedStateDomain::Approval, live_snapshot(2, 2)),
                ScriptedNext::Pending,
            ],
        );
        let mut controller = GovernedStateController::start(client).expect("controller start");
        tokio::time::timeout(Duration::from_secs(2), async {
            while next_calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker should block on the full capacity-one channel");

        controller.stop().await;

        assert_eq!(next_calls.load(Ordering::SeqCst), 2);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(controller.model().update_index, 0);
        assert!(controller.model().stopped);
        assert!(!controller.is_running());
    }

    #[test]
    fn client_attachment_is_the_production_governed_state_client() {
        fn assert_client<Client: GovernedStateClient>() {}
        assert_client::<ClientAttachment>();
    }

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
