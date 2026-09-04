//! Governed Harness-content presentation for the TUI.
//!
//! This module owns no disclosure, stream-reduction, or Authority semantics.
//! It consumes only the safe, assembled output of `client-operations` and
//! keeps presentation recovery separate from every other projection domain.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use egopulse_client_kernel::HarnessAssistantMessage;
use egopulse_client_operations::{
    ClientAttachment, ClientHarnessContentError, HarnessContentFilter, HarnessContentUpdate,
    HarnessContentUpdateKind,
};
use egopulse_domain_contracts::v01::egopulse::localapi::v1::HarnessContentPosition;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

const CONTENT_CHANNEL_CAPACITY: usize = 16;
const CONTENT_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const CONTENT_RECONNECT_LIMIT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessContentPhase {
    Connecting,
    Live,
    Reconnecting,
    Failed,
    Stopped,
}

impl HarnessContentPhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HarnessContentLaneKey {
    pub provider_family_alias: String,
    pub model_alias: String,
    pub collaboration_role: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessContentLane {
    pub key: HarnessContentLaneKey,
    pub messages: Vec<HarnessAssistantMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HarnessContentSnapshot {
    position: HarnessContentPosition,
    messages: Vec<HarnessAssistantMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarnessContentPageModel {
    pub task_id: String,
    pub phase: HarnessContentPhase,
    pub position: Option<HarnessContentPosition>,
    pub lanes: Vec<HarnessContentLane>,
    pub selected_lane: usize,
    pub detail_scroll: u16,
    pub message: String,
    messages: BTreeMap<String, HarnessAssistantMessage>,
}

impl HarnessContentPageModel {
    #[must_use]
    pub fn connecting(task_id: String) -> Self {
        Self {
            task_id,
            phase: HarnessContentPhase::Connecting,
            position: None,
            lanes: Vec::new(),
            selected_lane: 0,
            detail_scroll: 0,
            message: "Opening the governed content baseline".to_owned(),
            messages: BTreeMap::new(),
        }
    }

    fn replace_baseline(&mut self, snapshot: HarnessContentSnapshot) {
        self.position = Some(snapshot.position);
        self.messages = snapshot
            .messages
            .into_iter()
            .map(|message| (message.safe_message_id.clone(), message))
            .collect();
        self.phase = HarnessContentPhase::Live;
        self.message = if self.messages.is_empty() {
            "Live; waiting for governed assistant content".to_owned()
        } else {
            format!("Live; {} safe assistant message(s)", self.messages.len())
        };
        self.rebuild_lanes();
    }

    fn apply_update(&mut self, update: HarnessContentUpdate) {
        self.position = Some(update.position);
        for message in update.changed_messages {
            self.messages
                .insert(message.safe_message_id.clone(), message);
        }
        self.phase = HarnessContentPhase::Live;
        self.message = match update.kind {
            HarnessContentUpdateKind::Records => {
                format!("Live; {} safe assistant message(s)", self.messages.len())
            }
            HarnessContentUpdateKind::Heartbeat => "Live; content position confirmed".to_owned(),
            HarnessContentUpdateKind::ResetRequired => {
                "Content generation changed; rebuilding its baseline".to_owned()
            }
        };
        self.rebuild_lanes();
    }

    fn mark_reconnecting(&mut self, attempt: usize, clear_generation: bool) {
        if clear_generation {
            self.position = None;
            self.messages.clear();
            self.lanes.clear();
            self.selected_lane = 0;
            self.detail_scroll = 0;
        }
        self.phase = HarnessContentPhase::Reconnecting;
        self.message =
            format!("Reopening governed content baseline ({attempt}/{CONTENT_RECONNECT_LIMIT})");
    }

    fn mark_failed(&mut self, reason: &'static str) {
        self.phase = HarnessContentPhase::Failed;
        self.message = format!("Content stream stopped fail-closed: {reason}");
    }

    fn mark_stopped(&mut self) {
        self.phase = HarnessContentPhase::Stopped;
        self.message = "Content stream closed".to_owned();
    }

    fn rebuild_lanes(&mut self) {
        let selected = self
            .lanes
            .get(self.selected_lane)
            .map(|lane| lane.key.clone());
        let mut grouped = BTreeMap::<HarnessContentLaneKey, Vec<HarnessAssistantMessage>>::new();
        for message in self.messages.values() {
            grouped
                .entry(HarnessContentLaneKey {
                    provider_family_alias: message.provider_family_alias.clone(),
                    model_alias: message.model_alias.clone(),
                    collaboration_role: message.collaboration_role.clone(),
                    attempt_id: message.attempt_id.clone(),
                })
                .or_default()
                .push(message.clone());
        }
        self.lanes = grouped
            .into_iter()
            .map(|(key, mut messages)| {
                messages.sort_by(|left, right| left.safe_message_id.cmp(&right.safe_message_id));
                HarnessContentLane { key, messages }
            })
            .collect();
        self.selected_lane = selected
            .as_ref()
            .and_then(|key| self.lanes.iter().position(|lane| &lane.key == key))
            .unwrap_or_else(|| self.selected_lane.min(self.lanes.len().saturating_sub(1)));
        self.detail_scroll = 0;
    }

    pub fn select_next(&mut self) {
        if !self.lanes.is_empty() {
            self.selected_lane = (self.selected_lane + 1).min(self.lanes.len() - 1);
            self.detail_scroll = 0;
        }
    }

    pub fn select_previous(&mut self) {
        self.selected_lane = self.selected_lane.saturating_sub(1);
        self.detail_scroll = 0;
    }

    pub fn scroll_down(&mut self, lines: u16) {
        self.detail_scroll = self.detail_scroll.saturating_add(lines);
    }

    pub fn scroll_up(&mut self, lines: u16) {
        self.detail_scroll = self.detail_scroll.saturating_sub(lines);
    }
}

enum HarnessContentWorkerEvent {
    Baseline(HarnessContentSnapshot),
    Update(HarnessContentUpdate),
    Reconnecting {
        attempt: usize,
        clear_generation: bool,
    },
    Failed(&'static str),
}

struct HarnessContentRuntime {
    events: mpsc::Receiver<HarnessContentWorkerEvent>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl HarnessContentRuntime {
    async fn stop(mut self) {
        let _ = self.cancel.send(true);
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if tokio::time::timeout(CONTENT_STOP_TIMEOUT, &mut worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = worker.await;
        }
    }
}

impl Drop for HarnessContentRuntime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

pub struct HarnessContentController {
    filter: HarnessContentFilter,
    model: HarnessContentPageModel,
    runtime: Option<HarnessContentRuntime>,
}

impl HarnessContentController {
    pub fn start(
        client: Arc<ClientAttachment>,
        filter: HarnessContentFilter,
    ) -> Result<Self, &'static str> {
        tokio::runtime::Handle::try_current().map_err(|_| "content runtime is unavailable")?;
        let model = HarnessContentPageModel::connecting(filter.task_id().to_owned());
        let (sender, events) = mpsc::channel(CONTENT_CHANNEL_CAPACITY);
        let (cancel, cancel_receiver) = watch::channel(false);
        let worker = tokio::spawn(run_harness_content_worker(
            client,
            filter.clone(),
            sender,
            cancel_receiver,
        ));
        Ok(Self {
            filter,
            model,
            runtime: Some(HarnessContentRuntime {
                events,
                cancel,
                worker: Some(worker),
            }),
        })
    }

    #[must_use]
    pub fn task_id(&self) -> &str {
        self.filter.task_id()
    }

    #[must_use]
    pub const fn model(&self) -> &HarnessContentPageModel {
        &self.model
    }

    pub const fn model_mut(&mut self) -> &mut HarnessContentPageModel {
        &mut self.model
    }

    pub fn pump(&mut self) {
        let Some(runtime) = self.runtime.as_mut() else {
            return;
        };
        loop {
            match runtime.events.try_recv() {
                Ok(HarnessContentWorkerEvent::Baseline(snapshot)) => {
                    self.model.replace_baseline(snapshot);
                }
                Ok(HarnessContentWorkerEvent::Update(update)) => {
                    self.model.apply_update(update);
                }
                Ok(HarnessContentWorkerEvent::Reconnecting {
                    attempt,
                    clear_generation,
                }) => self.model.mark_reconnecting(attempt, clear_generation),
                Ok(HarnessContentWorkerEvent::Failed(reason)) => {
                    self.model.mark_failed(reason);
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if !matches!(self.model.phase, HarnessContentPhase::Failed) {
                        self.model.mark_stopped();
                    }
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

async fn run_harness_content_worker(
    client: Arc<ClientAttachment>,
    filter: HarnessContentFilter,
    sender: mpsc::Sender<HarnessContentWorkerEvent>,
    mut cancellation: watch::Receiver<bool>,
) {
    let mut recovery_attempts = 0usize;
    loop {
        if *cancellation.borrow() {
            return;
        }
        let opened = tokio::select! {
            biased;
            changed = cancellation.changed() => {
                let _ = changed;
                return;
            }
            opened = client.open_harness_content_session(filter.clone()) => opened,
        };
        let mut session = match opened {
            Ok(session) => session,
            Err(error) if recoverable(&error) && recovery_attempts < CONTENT_RECONNECT_LIMIT => {
                recovery_attempts += 1;
                if !send_event(
                    &sender,
                    &mut cancellation,
                    HarnessContentWorkerEvent::Reconnecting {
                        attempt: recovery_attempts,
                        clear_generation: false,
                    },
                )
                .await
                {
                    return;
                }
                if !reconnect_delay(recovery_attempts, &mut cancellation).await {
                    return;
                }
                continue;
            }
            Err(error) => {
                let _ = send_event(
                    &sender,
                    &mut cancellation,
                    HarnessContentWorkerEvent::Failed(safe_failure_reason(&error)),
                )
                .await;
                return;
            }
        };
        let snapshot = HarnessContentSnapshot {
            position: session.position().clone(),
            messages: session.assistant_messages().into_iter().cloned().collect(),
        };
        if !send_event(
            &sender,
            &mut cancellation,
            HarnessContentWorkerEvent::Baseline(snapshot),
        )
        .await
        {
            return;
        }

        loop {
            let next = tokio::select! {
                biased;
                changed = cancellation.changed() => {
                    let _ = changed;
                    return;
                }
                next = session.next_update() => next,
            };
            match next {
                Ok(update) if update.kind == HarnessContentUpdateKind::ResetRequired => {
                    if recovery_attempts >= CONTENT_RECONNECT_LIMIT {
                        let _ = send_event(
                            &sender,
                            &mut cancellation,
                            HarnessContentWorkerEvent::Failed("content recovery was exhausted"),
                        )
                        .await;
                        return;
                    }
                    recovery_attempts += 1;
                    if !send_event(
                        &sender,
                        &mut cancellation,
                        HarnessContentWorkerEvent::Reconnecting {
                            attempt: recovery_attempts,
                            clear_generation: true,
                        },
                    )
                    .await
                        || !reconnect_delay(recovery_attempts, &mut cancellation).await
                    {
                        return;
                    }
                    break;
                }
                Ok(update) => {
                    if !send_event(
                        &sender,
                        &mut cancellation,
                        HarnessContentWorkerEvent::Update(update),
                    )
                    .await
                    {
                        return;
                    }
                }
                Err(error)
                    if recoverable(&error) && recovery_attempts < CONTENT_RECONNECT_LIMIT =>
                {
                    recovery_attempts += 1;
                    if !send_event(
                        &sender,
                        &mut cancellation,
                        HarnessContentWorkerEvent::Reconnecting {
                            attempt: recovery_attempts,
                            clear_generation: false,
                        },
                    )
                    .await
                        || !reconnect_delay(recovery_attempts, &mut cancellation).await
                    {
                        return;
                    }
                    break;
                }
                Err(error) => {
                    let _ = send_event(
                        &sender,
                        &mut cancellation,
                        HarnessContentWorkerEvent::Failed(safe_failure_reason(&error)),
                    )
                    .await;
                    return;
                }
            }
        }
    }
}

fn recoverable(error: &ClientHarnessContentError) -> bool {
    matches!(
        error,
        ClientHarnessContentError::Transport(_)
            | ClientHarnessContentError::UnexpectedEof
            | ClientHarnessContentError::ResetBarrier
    )
}

fn safe_failure_reason(error: &ClientHarnessContentError) -> &'static str {
    match error {
        ClientHarnessContentError::Kernel(_) | ClientHarnessContentError::Protocol(_) => {
            "content integrity validation failed"
        }
        ClientHarnessContentError::InvalidInput(_) => "content filter is invalid",
        ClientHarnessContentError::Transport(_) | ClientHarnessContentError::UnexpectedEof => {
            "local content transport is unavailable"
        }
        ClientHarnessContentError::Api(_) => "local API rejected the content read",
        ClientHarnessContentError::BaselineLimitExceeded => "content baseline exceeded its bound",
        ClientHarnessContentError::ResetBarrier => "a new content baseline is required",
    }
}

async fn send_event(
    sender: &mpsc::Sender<HarnessContentWorkerEvent>,
    cancellation: &mut watch::Receiver<bool>,
    event: HarnessContentWorkerEvent,
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

async fn reconnect_delay(attempt: usize, cancellation: &mut watch::Receiver<bool>) -> bool {
    let delay = Duration::from_millis(match attempt {
        1 => 250,
        2 => 500,
        _ => 1_000,
    });
    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            false
        }
        () = tokio::time::sleep(delay) => true,
    }
}

pub fn render_harness_content_page(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &HarnessContentPageModel,
) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(area);
    let lane_items = model
        .lanes
        .iter()
        .map(|lane| {
            ListItem::new(vec![
                Line::from(format!(
                    "{} / {}",
                    lane.key.provider_family_alias, lane.key.model_alias
                )),
                Line::from(format!(
                    "{} / {}",
                    lane.key.collaboration_role, lane.key.attempt_id
                )),
            ])
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    if !model.lanes.is_empty() {
        state.select(Some(model.selected_lane));
    }
    frame.render_stateful_widget(
        List::new(lane_items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Harness content - {} - {}",
                model.phase.label(),
                position_label(model.position.as_ref())
            )))
            .highlight_symbol("> ")
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        columns[0],
        &mut state,
    );

    let detail = model.lanes.get(model.selected_lane).map_or_else(
        || "Waiting for safe assistant output...".to_owned(),
        |lane| {
            lane.messages
                .iter()
                .map(|message| {
                    format!(
                        "[{} | revision {} | {}]\n{}",
                        if message.finalized {
                            "finalized"
                        } else if message.provisional {
                            "streaming/provisional"
                        } else {
                            "committed"
                        },
                        message.revision,
                        message.safe_message_id,
                        message.safe_text
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        },
    );
    frame.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Task {} - safe output only", model.task_id)),
            )
            .wrap(Wrap { trim: false })
            .scroll((model.detail_scroll, 0)),
        columns[1],
    );
}

fn position_label(position: Option<&HarnessContentPosition>) -> String {
    position.map_or_else(
        || "baseline pending".to_owned(),
        |position| format!("{}:{}", position.epoch, position.sequence),
    )
}

#[cfg(test)]
mod tests {
    use egopulse_client_kernel::StreamApply;

    use super::*;

    fn message(
        id: &str,
        provider: &str,
        model: &str,
        role: &str,
        attempt: &str,
        revision: u64,
        text: &str,
    ) -> HarnessAssistantMessage {
        HarnessAssistantMessage {
            safe_message_id: id.to_owned(),
            task_id: "task:one".to_owned(),
            attempt_id: attempt.to_owned(),
            provider_family_alias: provider.to_owned(),
            model_alias: model.to_owned(),
            collaboration_role: role.to_owned(),
            revision,
            safe_text: text.to_owned(),
            safe_cumulative_digest_sha256: "a".repeat(64),
            provisional: true,
            finalized: false,
        }
    }

    fn position(sequence: u64) -> HarnessContentPosition {
        HarnessContentPosition {
            epoch: "content:test".to_owned(),
            sequence,
            projected_at: None,
        }
    }

    #[test]
    fn model_groups_safe_messages_by_provider_model_role_and_attempt() {
        let mut model = HarnessContentPageModel::connecting("task:one".to_owned());
        model.replace_baseline(HarnessContentSnapshot {
            position: position(2),
            messages: vec![
                message(
                    "message:one",
                    "gpt",
                    "gpt-latest",
                    "worker",
                    "attempt:1",
                    1,
                    "a",
                ),
                message(
                    "message:two",
                    "kimi",
                    "kimi-latest",
                    "reviewer",
                    "attempt:2",
                    1,
                    "b",
                ),
            ],
        });
        assert_eq!(model.phase, HarnessContentPhase::Live);
        assert_eq!(model.lanes.len(), 2);
        assert_eq!(model.lanes[0].key.provider_family_alias, "gpt");
        assert_eq!(model.lanes[1].key.provider_family_alias, "kimi");
    }

    #[test]
    fn replacement_updates_one_message_without_duplicating_it() {
        let mut model = HarnessContentPageModel::connecting("task:one".to_owned());
        model.replace_baseline(HarnessContentSnapshot {
            position: position(1),
            messages: vec![message(
                "message:one",
                "glm",
                "glm-latest",
                "worker",
                "attempt:1",
                1,
                "draft",
            )],
        });
        let mut replacement = message(
            "message:one",
            "glm",
            "glm-latest",
            "worker",
            "attempt:1",
            2,
            "final",
        );
        replacement.provisional = false;
        replacement.finalized = true;
        model.apply_update(HarnessContentUpdate {
            disposition: StreamApply::Applied,
            kind: HarnessContentUpdateKind::Records,
            position: position(2),
            records: Vec::new(),
            changed_messages: vec![replacement],
            reset_reason: None,
        });
        assert_eq!(model.lanes.len(), 1);
        assert_eq!(model.lanes[0].messages.len(), 1);
        assert_eq!(model.lanes[0].messages[0].safe_text, "final");
        assert!(model.lanes[0].messages[0].finalized);
    }

    #[test]
    fn reset_clears_only_the_content_generation() {
        let mut model = HarnessContentPageModel::connecting("task:one".to_owned());
        model.replace_baseline(HarnessContentSnapshot {
            position: position(1),
            messages: vec![message(
                "message:one",
                "deepseek",
                "deepseek-latest",
                "worker",
                "attempt:1",
                1,
                "draft",
            )],
        });
        model.mark_reconnecting(1, true);
        assert_eq!(model.phase, HarnessContentPhase::Reconnecting);
        assert_eq!(model.task_id, "task:one");
        assert!(model.position.is_none());
        assert!(model.lanes.is_empty());
    }
}
