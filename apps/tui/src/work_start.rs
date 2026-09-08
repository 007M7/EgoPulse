use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_operations::{
    ClientAttachment, ClientGuidedWorkError, ConfirmedWork, GovernedWorkCapabilitySelectionSource,
    GovernedWorkNotice, GuidedWorkCapabilityChoice, GuidedWorkConfirmationAttempt, GuidedWorkInput,
    GuidedWorkMemoryMode, GuidedWorkNonGoal, GuidedWorkPreparationAttempt, GuidedWorkPreview,
    GuidedWorkSource, PreparedWork, RecoverableWorkConfirmation, RecoverableWorkPreparation,
};
use egopulse_domain_contracts::v01::egopulse::task::v1::task_command_result;
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use tokio::{sync::mpsc, task::JoinHandle};

const WORK_START_CHANNEL_CAPACITY: usize = 1;

type WorkStartPrepareFuture =
    Pin<Box<dyn Future<Output = Result<WorkStartPreparationOutcome, String>> + Send + 'static>>;
type WorkStartReplayPreparationFuture =
    Pin<Box<dyn Future<Output = Result<WorkStartPrepared, String>> + Send + 'static>>;
type WorkStartConfirmFuture =
    Pin<Box<dyn Future<Output = Result<WorkStartConfirmationOutcome, String>> + Send + 'static>>;
type WorkStartReplayConfirmationFuture =
    Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'static>>;

trait WorkStartClient: Send + Sync {
    fn prepare(self: Arc<Self>, input: GuidedWorkInput) -> WorkStartPrepareFuture;
}

trait WorkStartPreparationRecovery: Send + Sync {
    fn replay(self: Arc<Self>) -> WorkStartReplayPreparationFuture;
}

trait WorkStartConfirmation: Send {
    fn confirm(self: Box<Self>) -> WorkStartConfirmFuture;
}

trait WorkStartConfirmationRecovery: Send + Sync {
    fn replay(self: Arc<Self>) -> WorkStartReplayConfirmationFuture;
}

struct WorkStartPrepared {
    preview: WorkStartPreview,
    confirmation: Box<dyn WorkStartConfirmation>,
}

impl WorkStartPrepared {
    #[cfg(test)]
    #[must_use]
    fn from_safe_projection(
        preview: WorkStartPreview,
        confirmation: Box<dyn WorkStartConfirmation>,
    ) -> Self {
        Self {
            preview,
            confirmation,
        }
    }
}

enum WorkStartPreparationOutcome {
    Prepared(Box<WorkStartPrepared>),
    OutcomeUnknown(Arc<dyn WorkStartPreparationRecovery>),
}

enum WorkStartConfirmationOutcome {
    Confirmed(String),
    OutcomeUnknown(Arc<dyn WorkStartConfirmationRecovery>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkStartPreview {
    normalized_intent: String,
    work_type: String,
    target_scope_ref: String,
    non_goals: Vec<GuidedWorkNonGoal>,
    included_source_count: usize,
    excluded_source_count: usize,
    blockers: Vec<GovernedWorkNotice>,
    warnings: Vec<GovernedWorkNotice>,
    memory_mode: GuidedWorkMemoryMode,
    memory_authority_revision: Option<u64>,
    memory_pack_snapshot_sha256: Option<String>,
    capability_choice_id: String,
    provider_alias: String,
    harness_alias: String,
    harness_model_alias: String,
    provider_model_alias: String,
    route_binding_sha256: String,
    capability_selection_source: GovernedWorkCapabilitySelectionSource,
    preference_revision_at_resolution: Option<u64>,
    gate_ready: bool,
    ready_for_founder_confirmation: bool,
}

impl WorkStartPreview {
    fn from_shared(preview: &GuidedWorkPreview) -> Self {
        Self {
            normalized_intent: preview.normalized_intent().to_owned(),
            work_type: preview.work_type().to_owned(),
            target_scope_ref: preview.target_scope_ref().to_owned(),
            non_goals: preview.non_goals().to_vec(),
            included_source_count: preview.included_source_count(),
            excluded_source_count: preview.excluded_source_count(),
            blockers: preview.blockers().to_vec(),
            warnings: preview.warnings().to_vec(),
            memory_mode: preview.memory_mode(),
            memory_authority_revision: preview.memory_authority_revision(),
            memory_pack_snapshot_sha256: preview
                .memory_pack_snapshot_sha256()
                .map(ToOwned::to_owned),
            capability_choice_id: preview.capability_choice_id().to_owned(),
            provider_alias: preview.provider_alias().to_owned(),
            harness_alias: preview.harness_alias().to_owned(),
            harness_model_alias: preview.harness_model_alias().to_owned(),
            provider_model_alias: preview.provider_model_alias().to_owned(),
            route_binding_sha256: preview.route_binding_sha256().to_owned(),
            capability_selection_source: preview.capability_selection_source(),
            preference_revision_at_resolution: preview.preference_revision_at_resolution(),
            gate_ready: preview.gate_ready(),
            ready_for_founder_confirmation: preview.ready_for_founder_confirmation(),
        }
    }

    fn can_confirm(&self) -> bool {
        self.gate_ready && self.ready_for_founder_confirmation && self.blockers.is_empty()
    }

    #[must_use]
    pub fn normalized_intent(&self) -> &str {
        &self.normalized_intent
    }

    #[must_use]
    pub fn work_type(&self) -> &str {
        &self.work_type
    }

    #[must_use]
    pub fn target_scope_ref(&self) -> &str {
        &self.target_scope_ref
    }

    #[must_use]
    pub fn non_goals(&self) -> &[GuidedWorkNonGoal] {
        &self.non_goals
    }

    #[must_use]
    pub const fn included_source_count(&self) -> usize {
        self.included_source_count
    }

    #[must_use]
    pub const fn excluded_source_count(&self) -> usize {
        self.excluded_source_count
    }

    #[must_use]
    pub fn blockers(&self) -> &[GovernedWorkNotice] {
        &self.blockers
    }

    #[must_use]
    pub fn warnings(&self) -> &[GovernedWorkNotice] {
        &self.warnings
    }

    #[must_use]
    pub const fn memory_mode(&self) -> GuidedWorkMemoryMode {
        self.memory_mode
    }

    #[must_use]
    pub const fn memory_authority_revision(&self) -> Option<u64> {
        self.memory_authority_revision
    }

    #[must_use]
    pub fn memory_pack_snapshot_sha256(&self) -> Option<&str> {
        self.memory_pack_snapshot_sha256.as_deref()
    }

    #[must_use]
    pub fn capability_choice_id(&self) -> &str {
        &self.capability_choice_id
    }

    #[must_use]
    pub fn provider_alias(&self) -> &str {
        &self.provider_alias
    }

    #[must_use]
    pub fn harness_alias(&self) -> &str {
        &self.harness_alias
    }

    #[must_use]
    pub fn harness_model_alias(&self) -> &str {
        &self.harness_model_alias
    }

    #[must_use]
    pub fn provider_model_alias(&self) -> &str {
        &self.provider_model_alias
    }

    #[must_use]
    pub fn route_binding_sha256(&self) -> &str {
        &self.route_binding_sha256
    }

    #[must_use]
    pub const fn capability_selection_source(&self) -> GovernedWorkCapabilitySelectionSource {
        self.capability_selection_source
    }

    #[must_use]
    pub const fn preference_revision_at_resolution(&self) -> Option<u64> {
        self.preference_revision_at_resolution
    }

    #[must_use]
    pub const fn gate_ready(&self) -> bool {
        self.gate_ready
    }

    #[must_use]
    pub const fn ready_for_founder_confirmation(&self) -> bool {
        self.ready_for_founder_confirmation
    }
}

struct ProductionWorkStartClient {
    attachment: Arc<ClientAttachment>,
}

impl WorkStartClient for ProductionWorkStartClient {
    fn prepare(self: Arc<Self>, input: GuidedWorkInput) -> WorkStartPrepareFuture {
        Box::pin(async move {
            match self.attachment.prepare_guided_work(input).await {
                Ok(GuidedWorkPreparationAttempt::Prepared(prepared)) => {
                    Ok(WorkStartPreparationOutcome::Prepared(Box::new(
                        production_prepared(Arc::clone(&self.attachment), *prepared),
                    )))
                }
                Ok(GuidedWorkPreparationAttempt::OutcomeUnknown(recovery)) => {
                    Ok(WorkStartPreparationOutcome::OutcomeUnknown(Arc::new(
                        ProductionPreparationRecovery {
                            attachment: Arc::clone(&self.attachment),
                            recovery: *recovery,
                        },
                    )))
                }
                Err(error) => Err(safe_guided_work_error(&error)),
            }
        })
    }
}

struct ProductionPreparationRecovery {
    attachment: Arc<ClientAttachment>,
    recovery: RecoverableWorkPreparation,
}

impl WorkStartPreparationRecovery for ProductionPreparationRecovery {
    fn replay(self: Arc<Self>) -> WorkStartReplayPreparationFuture {
        Box::pin(async move {
            self.attachment
                .replay_guided_work_preparation(&self.recovery)
                .await
                .map(|prepared| production_prepared(Arc::clone(&self.attachment), prepared))
                .map_err(|error| safe_guided_work_error(&error))
        })
    }
}

fn production_prepared(
    attachment: Arc<ClientAttachment>,
    prepared: PreparedWork,
) -> WorkStartPrepared {
    let preview = WorkStartPreview::from_shared(prepared.preview());
    WorkStartPrepared {
        preview,
        confirmation: Box::new(ProductionConfirmation {
            attachment,
            prepared,
        }),
    }
}

struct ProductionConfirmation {
    attachment: Arc<ClientAttachment>,
    prepared: PreparedWork,
}

impl WorkStartConfirmation for ProductionConfirmation {
    fn confirm(self: Box<Self>) -> WorkStartConfirmFuture {
        Box::pin(async move {
            match self.attachment.confirm_guided_work(self.prepared).await {
                Ok(GuidedWorkConfirmationAttempt::Confirmed(confirmed)) => {
                    confirmed_task_id(*confirmed)
                        .map(WorkStartConfirmationOutcome::Confirmed)
                        .map_err(|error| safe_guided_work_error(&error))
                }
                Ok(GuidedWorkConfirmationAttempt::OutcomeUnknown(recovery)) => {
                    Ok(WorkStartConfirmationOutcome::OutcomeUnknown(Arc::new(
                        ProductionConfirmationRecovery {
                            attachment: Arc::clone(&self.attachment),
                            recovery: *recovery,
                        },
                    )))
                }
                Err(error) => Err(safe_guided_work_error(&error)),
            }
        })
    }
}

struct ProductionConfirmationRecovery {
    attachment: Arc<ClientAttachment>,
    recovery: RecoverableWorkConfirmation,
}

impl WorkStartConfirmationRecovery for ProductionConfirmationRecovery {
    fn replay(self: Arc<Self>) -> WorkStartReplayConfirmationFuture {
        Box::pin(async move {
            self.attachment
                .replay_guided_work_confirmation(&self.recovery)
                .await
                .and_then(confirmed_task_id)
                .map_err(|error| safe_guided_work_error(&error))
        })
    }
}

fn confirmed_task_id(confirmed: ConfirmedWork) -> Result<String, ClientGuidedWorkError> {
    match confirmed.result.outcome {
        Some(task_command_result::Outcome::Task(task)) if !task.task_id.trim().is_empty() => {
            Ok(task.task_id)
        }
        _ => Err(ClientGuidedWorkError::Protocol(
            "confirmed Task identity missing",
        )),
    }
}

fn safe_guided_work_error(error: &ClientGuidedWorkError) -> String {
    match error {
        ClientGuidedWorkError::Kernel(_) => {
            "Work Start permission or attached session was rejected".to_owned()
        }
        ClientGuidedWorkError::InvalidInput(detail) => {
            format!("Work Start input is invalid: {detail}")
        }
        ClientGuidedWorkError::Blocked => {
            "The governed preview is blocked; Task confirmation was not sent".to_owned()
        }
        ClientGuidedWorkError::SessionChanged => {
            "The attached session changed; do not submit the sealed operation".to_owned()
        }
        ClientGuidedWorkError::BindingChanged => {
            "The governed Work binding changed; confirmation was rejected".to_owned()
        }
        ClientGuidedWorkError::PreparationOutcomeUnknown(_) => {
            "Preparation outcome is unknown; press Enter to replay the exact request".to_owned()
        }
        ClientGuidedWorkError::ConfirmationOutcomeUnknown(_) => {
            "Task confirmation outcome is unknown; replay exactly or open Task Watch to reconcile"
                .to_owned()
        }
        ClientGuidedWorkError::ApiOutcomeUnknown(error) => {
            let code = egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiErrorCode::try_from(error.code)
                .map(|code| code.as_str_name())
                .unwrap_or("LOCAL_API_ERROR_UNKNOWN");
            format!(
                "{code}: the API responded but the commit outcome is unknown; replay the exact request"
            )
        }
        ClientGuidedWorkError::Api(_) => "The Work API rejected the operation".to_owned(),
        ClientGuidedWorkError::Authority { .. } => {
            "Task Authority rejected the confirmation".to_owned()
        }
        ClientGuidedWorkError::Protocol(_) => {
            "The Work API response failed integrity validation".to_owned()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkStartStage {
    Editing,
    Preparing,
    PreviewReady,
    PreparationOutcomeUnknown,
    Confirming,
    ConfirmationOutcomeUnknown,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkStartField {
    Intent,
    WorkType,
    Scope,
    Capability,
    ContextReferences,
}

impl WorkStartField {
    const ALL: [Self; 5] = [
        Self::Intent,
        Self::WorkType,
        Self::Scope,
        Self::Capability,
        Self::ContextReferences,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intent => "Intent",
            Self::WorkType => "Work type",
            Self::Scope => "Scope",
            Self::Capability => "Capability choice (blank = future-work default)",
            Self::ContextReferences => "Context refs (comma separated)",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkStartDraft {
    pub intent: String,
    pub work_type: String,
    pub target_scope_ref: String,
    pub capability_choice_id: String,
    pub context_references: String,
    pub memory_enabled: bool,
}

impl Default for WorkStartDraft {
    fn default() -> Self {
        Self {
            intent: String::new(),
            work_type: String::new(),
            target_scope_ref: String::new(),
            capability_choice_id: String::new(),
            context_references: String::new(),
            memory_enabled: true,
        }
    }
}

impl WorkStartDraft {
    fn to_input(&self) -> GuidedWorkInput {
        GuidedWorkInput {
            intent: self.intent.clone(),
            work_type: self.work_type.clone(),
            target_scope_ref: self.target_scope_ref.clone(),
            sources: self
                .context_references
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| GuidedWorkSource {
                    source_ref: value.to_owned(),
                    label: value.to_owned(),
                })
                .collect(),
            memory_mode: if self.memory_enabled {
                GuidedWorkMemoryMode::GovernedRetrieval
            } else {
                GuidedWorkMemoryMode::Disabled
            },
            capability: if self.capability_choice_id.trim().is_empty() {
                GuidedWorkCapabilityChoice::FutureWorkDefault
            } else {
                GuidedWorkCapabilityChoice::Explicit(self.capability_choice_id.clone())
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkStartPageModel {
    stage: WorkStartStage,
    active_field: WorkStartField,
    draft: WorkStartDraft,
    preview: Option<WorkStartPreview>,
    message: String,
}

impl Default for WorkStartPageModel {
    fn default() -> Self {
        Self {
            stage: WorkStartStage::Editing,
            active_field: WorkStartField::Intent,
            draft: WorkStartDraft::default(),
            preview: None,
            message: "Enter high-level Work intent and governed Context references".to_owned(),
        }
    }
}

impl WorkStartPageModel {
    #[must_use]
    pub const fn stage(&self) -> WorkStartStage {
        self.stage
    }

    #[must_use]
    pub const fn active_field(&self) -> WorkStartField {
        self.active_field
    }

    #[must_use]
    pub fn draft(&self) -> &WorkStartDraft {
        &self.draft
    }

    pub fn draft_mut(&mut self) -> &mut WorkStartDraft {
        &mut self.draft
    }

    #[must_use]
    pub fn preview(&self) -> Option<&WorkStartPreview> {
        self.preview.as_ref()
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn next_field(&mut self) {
        let index = WorkStartField::ALL
            .iter()
            .position(|field| *field == self.active_field)
            .expect("Work Start field is enumerated");
        self.active_field = WorkStartField::ALL[(index + 1) % WorkStartField::ALL.len()];
    }

    pub fn previous_field(&mut self) {
        let index = WorkStartField::ALL
            .iter()
            .position(|field| *field == self.active_field)
            .expect("Work Start field is enumerated");
        let previous = index
            .checked_sub(1)
            .unwrap_or(WorkStartField::ALL.len() - 1);
        self.active_field = WorkStartField::ALL[previous];
    }

    pub fn push(&mut self, character: char) {
        self.active_value_mut().push(character);
    }

    pub fn backspace(&mut self) {
        self.active_value_mut().pop();
    }

    pub fn toggle_memory(&mut self) {
        self.draft.memory_enabled = !self.draft.memory_enabled;
        self.message = if self.draft.memory_enabled {
            "Governed Memory retrieval enabled for this work".to_owned()
        } else {
            "Memory disabled for this work".to_owned()
        };
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.active_field {
            WorkStartField::Intent => &mut self.draft.intent,
            WorkStartField::WorkType => &mut self.draft.work_type,
            WorkStartField::Scope => &mut self.draft.target_scope_ref,
            WorkStartField::Capability => &mut self.draft.capability_choice_id,
            WorkStartField::ContextReferences => &mut self.draft.context_references,
        }
    }
}

/// Renders only the validated Work Start page projection. Governance bindings and
/// raw source, evidence, proof, and digest values are not represented by this model.
pub fn render_work_start_page(frame: &mut Frame<'_>, area: Rect, model: &WorkStartPageModel) {
    let draft = model.draft();
    let marker = |field| {
        if model.active_field() == field {
            ">"
        } else {
            " "
        }
    };
    let mut lines = vec![
        Line::from(format!("Stage: {:?}", model.stage())),
        Line::from(format!(
            "{} Intent: {}",
            marker(WorkStartField::Intent),
            draft.intent
        )),
        Line::from(format!(
            "{} Work type: {}",
            marker(WorkStartField::WorkType),
            draft.work_type
        )),
        Line::from(format!(
            "{} Scope: {}",
            marker(WorkStartField::Scope),
            draft.target_scope_ref
        )),
        Line::from(format!(
            "{} Capability: {}",
            marker(WorkStartField::Capability),
            if draft.capability_choice_id.is_empty() {
                "<future-work default>"
            } else {
                draft.capability_choice_id.as_str()
            }
        )),
        Line::from(format!(
            "{} Context refs: {}",
            marker(WorkStartField::ContextReferences),
            draft.context_references
        )),
        Line::from(format!(
            "  Memory: {} (F2 toggles before preparation)",
            if draft.memory_enabled {
                "governed retrieval"
            } else {
                "disabled"
            }
        )),
        Line::from(format!("Status: {}", model.message())),
    ];
    if let Some(preview) = model.preview() {
        lines.extend([
            Line::from(""),
            Line::from(format!(
                "Normalized intent: {}",
                preview.normalized_intent()
            )),
            Line::from(format!("Governed work type: {}", preview.work_type())),
            Line::from(format!("Governed scope: {}", preview.target_scope_ref())),
            Line::from(format!(
                "Capability: {} / provider: {} / harness: {} / model: {} -> {}",
                preview.capability_choice_id(),
                preview.provider_alias(),
                preview.harness_alias(),
                preview.harness_model_alias(),
                preview.provider_model_alias(),
            )),
            Line::from(format!(
                "Route: {} / selection: {:?} / preference revision: {}",
                preview.route_binding_sha256(),
                preview.capability_selection_source(),
                preview
                    .preference_revision_at_resolution()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "not used".to_owned()),
            )),
            Line::from(format!(
                "Sources: {} included, {} excluded",
                preview.included_source_count(),
                preview.excluded_source_count()
            )),
            Line::from(format!(
                "Gate: {} / founder confirmation: {}",
                preview.gate_ready(),
                preview.ready_for_founder_confirmation()
            )),
            Line::from(format!(
                "Memory: {:?} / authority revision: {} / pack: {}",
                preview.memory_mode(),
                preview
                    .memory_authority_revision()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "disabled".to_owned()),
                preview.memory_pack_snapshot_sha256().unwrap_or("-")
            )),
        ]);
        for non_goal in preview.non_goals() {
            lines.push(Line::from(format!("Non-goal: {}", non_goal.as_str())));
        }
        for blocker in preview.blockers() {
            lines.push(Line::from(format!("Blocker: {}", blocker.as_str())));
        }
        for warning in preview.warnings() {
            lines.push(Line::from(format!("Warning: {}", warning.as_str())));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Work Start"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

enum WorkStartWorkerEvent {
    Prepared {
        generation: u64,
        prepared: Box<WorkStartPrepared>,
    },
    PreparationUnknown {
        generation: u64,
        recovery: Arc<dyn WorkStartPreparationRecovery>,
    },
    Confirmed {
        generation: u64,
        task_id: String,
    },
    ConfirmationUnknown {
        generation: u64,
        recovery: Arc<dyn WorkStartConfirmationRecovery>,
    },
    Failed {
        generation: u64,
        detail: String,
    },
}

impl WorkStartWorkerEvent {
    fn generation(&self) -> u64 {
        match self {
            Self::Prepared { generation, .. }
            | Self::PreparationUnknown { generation, .. }
            | Self::Confirmed { generation, .. }
            | Self::ConfirmationUnknown { generation, .. }
            | Self::Failed { generation, .. } => *generation,
        }
    }
}

struct WorkStartRuntime {
    events: mpsc::Receiver<WorkStartWorkerEvent>,
    worker: Option<JoinHandle<()>>,
}

impl WorkStartRuntime {
    async fn retire(mut self) -> Result<(), String> {
        let Some(mut worker) = self.worker.take() else {
            return Ok(());
        };
        (&mut worker)
            .await
            .map_err(|_| "Work Start worker failed after settlement".to_owned())
    }
}

struct WorkStartControllerCore<C: WorkStartClient + ?Sized + 'static> {
    client: Arc<C>,
    generation: u64,
    model: WorkStartPageModel,
    prepared: Option<WorkStartPrepared>,
    preparation_recovery: Option<Arc<dyn WorkStartPreparationRecovery>>,
    confirmation_recovery: Option<Arc<dyn WorkStartConfirmationRecovery>>,
    runtime: Option<WorkStartRuntime>,
    return_after_preparation: bool,
    navigate_dashboard: bool,
    confirmed_task_id: Option<String>,
}

impl<C: WorkStartClient + ?Sized + 'static> WorkStartControllerCore<C> {
    #[must_use]
    pub fn new(client: Arc<C>) -> Self {
        Self {
            client,
            generation: 0,
            model: WorkStartPageModel::default(),
            prepared: None,
            preparation_recovery: None,
            confirmation_recovery: None,
            runtime: None,
            return_after_preparation: false,
            navigate_dashboard: false,
            confirmed_task_id: None,
        }
    }

    #[must_use]
    pub fn model(&self) -> &WorkStartPageModel {
        &self.model
    }

    pub fn model_mut(&mut self) -> &mut WorkStartPageModel {
        &mut self.model
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    pub async fn prepare(&mut self) -> Result<(), String> {
        if self.model.stage != WorkStartStage::Editing && self.model.stage != WorkStartStage::Failed
        {
            return Err("Work preparation is not available in the current stage".to_owned());
        }
        if self.runtime.is_some() {
            return Err("Work preparation is already in flight".to_owned());
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let input = self.model.draft.to_input();
        let client = Arc::clone(&self.client);
        self.model.stage = WorkStartStage::Preparing;
        self.model.preview = None;
        self.model.message =
            "Preparing governed Context; Escape waits for the result before returning".to_owned();
        self.return_after_preparation = false;
        self.spawn(
            async move { client.prepare(input).await },
            move |result| match result {
                Ok(WorkStartPreparationOutcome::Prepared(prepared)) => {
                    WorkStartWorkerEvent::Prepared {
                        generation,
                        prepared,
                    }
                }
                Ok(WorkStartPreparationOutcome::OutcomeUnknown(recovery)) => {
                    WorkStartWorkerEvent::PreparationUnknown {
                        generation,
                        recovery,
                    }
                }
                Err(detail) => WorkStartWorkerEvent::Failed { generation, detail },
            },
        );
        Ok(())
    }

    pub fn request_return_after_preparation(&mut self) {
        if self.model.stage == WorkStartStage::Preparing {
            self.return_after_preparation = true;
            self.model.message =
                "Return requested; waiting for preparation outcome without claiming zero writes"
                    .to_owned();
        }
    }

    pub async fn replay_preparation(&mut self) -> Result<(), String> {
        if self.model.stage != WorkStartStage::PreparationOutcomeUnknown {
            return Err("No uncertain preparation is available for exact replay".to_owned());
        }
        let recovery = Arc::clone(
            self.preparation_recovery
                .as_ref()
                .ok_or_else(|| "Preparation recovery capsule is unavailable".to_owned())?,
        );
        if self.runtime.is_some() {
            return Err("Work preparation is already in flight".to_owned());
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        self.model.stage = WorkStartStage::Preparing;
        self.model.message = "Replaying the exact sealed preparation request".to_owned();
        self.spawn(
            async move { recovery.replay().await },
            move |result| match result {
                Ok(prepared) => WorkStartWorkerEvent::Prepared {
                    generation,
                    prepared: Box::new(prepared),
                },
                Err(detail) => WorkStartWorkerEvent::Failed { generation, detail },
            },
        );
        Ok(())
    }

    pub async fn cancel_preview(&mut self) -> Result<(), String> {
        if self.model.stage != WorkStartStage::PreviewReady {
            return Err("Only a settled preview can be cancelled".to_owned());
        }
        self.prepared.take();
        self.generation = self.generation.wrapping_add(1).max(1);
        self.navigate_dashboard = true;
        self.model.message =
            "Preview cancelled; Task confirmation was not sent (preparation may have written Context)"
                .to_owned();
        Ok(())
    }

    pub async fn confirm(&mut self) -> Result<(), String> {
        if self.model.stage != WorkStartStage::PreviewReady {
            return Err("Work confirmation requires a settled preview".to_owned());
        }
        let preview = self
            .model
            .preview
            .as_ref()
            .ok_or_else(|| "Governed preview is unavailable".to_owned())?;
        if !preview.can_confirm() {
            return Err("Governed preview is blocked; Task confirmation was not sent".to_owned());
        }
        let prepared = self
            .prepared
            .take()
            .ok_or_else(|| "Prepared Work was already consumed".to_owned())?;
        if self.runtime.is_some() {
            self.prepared = Some(prepared);
            return Err("Task confirmation is already in flight".to_owned());
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        self.model.stage = WorkStartStage::Confirming;
        self.model.message =
            "Confirming Task; Escape cannot cancel an Authority command already in flight"
                .to_owned();
        self.spawn(
            async move { prepared.confirmation.confirm().await },
            move |result| match result {
                Ok(WorkStartConfirmationOutcome::Confirmed(task_id)) => {
                    WorkStartWorkerEvent::Confirmed {
                        generation,
                        task_id,
                    }
                }
                Ok(WorkStartConfirmationOutcome::OutcomeUnknown(recovery)) => {
                    WorkStartWorkerEvent::ConfirmationUnknown {
                        generation,
                        recovery,
                    }
                }
                Err(detail) => WorkStartWorkerEvent::Failed { generation, detail },
            },
        );
        Ok(())
    }

    pub fn note_confirmation_cannot_cancel(&mut self) {
        if self.model.stage == WorkStartStage::Confirming {
            self.model.message =
                "Task confirmation is in flight; wait for settlement before navigating".to_owned();
        }
    }

    pub async fn replay_confirmation(&mut self) -> Result<(), String> {
        if self.model.stage != WorkStartStage::ConfirmationOutcomeUnknown {
            return Err("No uncertain Task confirmation is available for exact replay".to_owned());
        }
        let recovery = Arc::clone(
            self.confirmation_recovery
                .as_ref()
                .ok_or_else(|| "Task confirmation recovery capsule is unavailable".to_owned())?,
        );
        if self.runtime.is_some() {
            return Err("Task confirmation is already in flight".to_owned());
        }
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        self.model.stage = WorkStartStage::Confirming;
        self.model.message = "Replaying the exact sealed Task confirmation".to_owned();
        self.spawn(
            async move { recovery.replay().await },
            move |result| match result {
                Ok(task_id) => WorkStartWorkerEvent::Confirmed {
                    generation,
                    task_id,
                },
                Err(detail) => WorkStartWorkerEvent::Failed { generation, detail },
            },
        );
        Ok(())
    }

    pub async fn pump(&mut self) -> Result<(), String> {
        let event = self
            .runtime
            .as_mut()
            .and_then(|runtime| runtime.events.try_recv().ok());
        if let Some(event) = event {
            self.apply_terminal_event(event).await?;
        }
        Ok(())
    }

    pub async fn wait_for_settlement(&mut self, timeout: Duration) -> Result<(), String> {
        let Some(runtime) = self.runtime.as_mut() else {
            return Ok(());
        };
        let event = match tokio::time::timeout(timeout, runtime.events.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => {
                return Err("Work Start worker ended without a settlement event".to_owned());
            }
            Err(_) => {
                return Err(
                    "Work Start mutation remains unresolved; keep this controller alive".to_owned(),
                );
            }
        };
        self.apply_terminal_event(event).await
    }

    async fn apply_terminal_event(&mut self, event: WorkStartWorkerEvent) -> Result<(), String> {
        let runtime = self
            .runtime
            .take()
            .ok_or_else(|| "Work Start runtime is unavailable".to_owned())?;
        runtime.retire().await?;
        if event.generation() != self.generation {
            return Ok(());
        }
        match event {
            WorkStartWorkerEvent::Prepared { prepared, .. } => {
                let prepared = *prepared;
                self.preparation_recovery.take();
                if self.return_after_preparation {
                    self.prepared.take();
                    self.model.preview = None;
                    self.navigate_dashboard = true;
                    self.model.message =
                        "Preparation settled; returning without Task confirmation".to_owned();
                } else {
                    self.model.preview = Some(prepared.preview.clone());
                    self.prepared = Some(prepared);
                    self.model.stage = WorkStartStage::PreviewReady;
                    self.model.message = if self
                        .model
                        .preview
                        .as_ref()
                        .is_some_and(WorkStartPreview::can_confirm)
                    {
                        "Review the governed preview; Enter confirms once, Escape sends no Task confirmation"
                                .to_owned()
                    } else {
                        "Preview is blocked; Enter cannot send Task confirmation".to_owned()
                    };
                }
            }
            WorkStartWorkerEvent::PreparationUnknown { recovery, .. } => {
                self.preparation_recovery = Some(recovery);
                self.model.stage = WorkStartStage::PreparationOutcomeUnknown;
                self.model.message = "Preparation outcome is unknown; Enter replays only the exact request. Do not start over"
                        .to_owned();
            }
            WorkStartWorkerEvent::Confirmed { task_id, .. } => {
                self.confirmation_recovery.take();
                self.confirmed_task_id = Some(task_id);
                self.model.message =
                    "Task confirmed; opening Task Watch without inferring completion".to_owned();
            }
            WorkStartWorkerEvent::ConfirmationUnknown { recovery, .. } => {
                self.confirmation_recovery = Some(recovery);
                self.model.stage = WorkStartStage::ConfirmationOutcomeUnknown;
                self.model.message = "Task confirmation outcome is unknown; Enter exact-replays or w opens Task Watch for reconciliation"
                        .to_owned();
            }
            WorkStartWorkerEvent::Failed { detail, .. } => {
                let preparation_unknown = self.preparation_recovery.is_some();
                let confirmation_unknown = self.confirmation_recovery.is_some();
                self.model.stage = if preparation_unknown {
                    WorkStartStage::PreparationOutcomeUnknown
                } else if confirmation_unknown {
                    WorkStartStage::ConfirmationOutcomeUnknown
                } else {
                    WorkStartStage::Failed
                };
                self.model.message = detail.clone();
                if self.return_after_preparation && !preparation_unknown {
                    self.navigate_dashboard = true;
                }
                return Err(detail);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn take_dashboard_navigation(&mut self) -> bool {
        std::mem::take(&mut self.navigate_dashboard)
    }

    pub fn take_confirmed_task_id(&mut self) -> Option<String> {
        self.confirmed_task_id.take()
    }

    fn spawn<F, M>(&mut self, future: F, map: M)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
        M: FnOnce(F::Output) -> WorkStartWorkerEvent + Send + 'static,
    {
        let (sender, events) = mpsc::channel(WORK_START_CHANNEL_CAPACITY);
        let worker = tokio::spawn(async move {
            let output = future.await;
            let event = map(output);
            let _ = sender.send(event).await;
        });
        self.runtime = Some(WorkStartRuntime {
            events,
            worker: Some(worker),
        });
    }
}

/// Production Work Start controller. Mutation workers are intentionally retained until their
/// terminal settlement event is observed; callers must not discard a running controller.
pub struct WorkStartController {
    inner: WorkStartControllerCore<ProductionWorkStartClient>,
}

impl WorkStartController {
    #[must_use]
    pub fn new(attachment: Arc<ClientAttachment>) -> Self {
        Self {
            inner: WorkStartControllerCore::new(Arc::new(ProductionWorkStartClient { attachment })),
        }
    }

    #[must_use]
    pub fn model(&self) -> &WorkStartPageModel {
        self.inner.model()
    }

    pub fn model_mut(&mut self) -> &mut WorkStartPageModel {
        self.inner.model_mut()
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.is_running()
    }

    pub async fn prepare(&mut self) -> Result<(), String> {
        self.inner.prepare().await
    }

    pub fn request_return_after_preparation(&mut self) {
        self.inner.request_return_after_preparation();
    }

    pub async fn replay_preparation(&mut self) -> Result<(), String> {
        self.inner.replay_preparation().await
    }

    pub async fn cancel_preview(&mut self) -> Result<(), String> {
        self.inner.cancel_preview().await
    }

    pub async fn confirm(&mut self) -> Result<(), String> {
        self.inner.confirm().await
    }

    pub fn note_confirmation_cannot_cancel(&mut self) {
        self.inner.note_confirmation_cannot_cancel();
    }

    pub async fn replay_confirmation(&mut self) -> Result<(), String> {
        self.inner.replay_confirmation().await
    }

    pub async fn pump(&mut self) -> Result<(), String> {
        self.inner.pump().await
    }

    /// Waits for one in-flight mutation to settle. A timeout preserves the worker and capsule.
    pub async fn wait_for_settlement(&mut self, timeout: Duration) -> Result<(), String> {
        self.inner.wait_for_settlement(timeout).await
    }

    #[must_use]
    pub fn take_dashboard_navigation(&mut self) -> bool {
        self.inner.take_dashboard_navigation()
    }

    pub fn take_confirmed_task_id(&mut self) -> Option<String> {
        self.inner.take_confirmed_task_id()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use tokio::sync::Notify;

    struct ScriptedClient {
        prepares: AtomicU64,
        result: Mutex<Option<Result<WorkStartPreparationOutcome, String>>>,
    }

    impl WorkStartClient for ScriptedClient {
        fn prepare(self: Arc<Self>, _input: GuidedWorkInput) -> WorkStartPrepareFuture {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            let result = self.result.lock().expect("script lock").take().unwrap();
            Box::pin(async move { result })
        }
    }

    struct ConfirmOnce {
        calls: Arc<AtomicU64>,
        outcome: WorkStartConfirmationOutcome,
    }

    struct PendingClient {
        calls: Arc<AtomicU64>,
        release: Arc<Notify>,
        result: Mutex<Option<Result<WorkStartPreparationOutcome, String>>>,
    }

    impl WorkStartClient for PendingClient {
        fn prepare(self: Arc<Self>, _input: GuidedWorkInput) -> WorkStartPrepareFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let release = Arc::clone(&self.release);
            let result = self
                .result
                .lock()
                .expect("pending result lock")
                .take()
                .unwrap();
            Box::pin(async move {
                release.notified().await;
                result
            })
        }
    }

    struct PendingConfirmation {
        calls: Arc<AtomicU64>,
        release: Arc<Notify>,
        outcome: WorkStartConfirmationOutcome,
    }

    impl WorkStartConfirmation for PendingConfirmation {
        fn confirm(self: Box<Self>) -> WorkStartConfirmFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let release = Arc::clone(&self.release);
            let outcome = self.outcome;
            Box::pin(async move {
                release.notified().await;
                Ok(outcome)
            })
        }
    }

    impl WorkStartConfirmation for ConfirmOnce {
        fn confirm(self: Box<Self>) -> WorkStartConfirmFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(self.outcome) })
        }
    }

    struct PreparationReplay {
        calls: AtomicU64,
        prepared: Mutex<Option<WorkStartPrepared>>,
    }

    impl WorkStartPreparationRecovery for PreparationReplay {
        fn replay(self: Arc<Self>) -> WorkStartReplayPreparationFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let prepared = self.prepared.lock().expect("prepared lock").take().unwrap();
            Box::pin(async move { Ok(prepared) })
        }
    }

    struct ConfirmationReplay {
        calls: Arc<AtomicU64>,
        task_id: String,
    }

    impl WorkStartConfirmationRecovery for ConfirmationReplay {
        fn replay(self: Arc<Self>) -> WorkStartReplayConfirmationFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let task_id = self.task_id.clone();
            Box::pin(async move { Ok(task_id) })
        }
    }

    fn preview(ready: bool) -> WorkStartPreview {
        WorkStartPreview {
            normalized_intent: "implement".to_owned(),
            work_type: "implementation".to_owned(),
            target_scope_ref: "project:test".to_owned(),
            non_goals: vec![
                GuidedWorkNonGoal::ProviderRouteCannotBeModelSelected,
                GuidedWorkNonGoal::MemoryMutationExcluded,
            ],
            included_source_count: usize::from(ready),
            excluded_source_count: usize::from(!ready),
            blockers: (!ready)
                .then_some(GovernedWorkNotice::ContextSourceUnreadable)
                .into_iter()
                .collect(),
            warnings: Vec::new(),
            memory_mode: GuidedWorkMemoryMode::Disabled,
            memory_authority_revision: None,
            memory_pack_snapshot_sha256: None,
            capability_choice_id: "capability:codex:test".to_owned(),
            provider_alias: "gpt".to_owned(),
            harness_alias: "codex_app_server".to_owned(),
            harness_model_alias: "gpt-5.4".to_owned(),
            provider_model_alias: "gpt-5.4".to_owned(),
            route_binding_sha256: "d".repeat(64),
            capability_selection_source: GovernedWorkCapabilitySelectionSource::FutureWorkDefault,
            preference_revision_at_resolution: Some(1),
            gate_ready: ready,
            ready_for_founder_confirmation: ready,
        }
    }

    fn prepared(calls: Arc<AtomicU64>, outcome: WorkStartConfirmationOutcome) -> WorkStartPrepared {
        WorkStartPrepared::from_safe_projection(
            preview(true),
            Box::new(ConfirmOnce { calls, outcome }),
        )
    }

    fn controller_for(
        result: Result<WorkStartPreparationOutcome, String>,
    ) -> WorkStartControllerCore<ScriptedClient> {
        let client = Arc::new(ScriptedClient {
            prepares: AtomicU64::new(0),
            result: Mutex::new(Some(result)),
        });
        let mut controller = WorkStartControllerCore::new(client);
        controller.model.draft = WorkStartDraft {
            intent: "implement".to_owned(),
            work_type: "implementation".to_owned(),
            target_scope_ref: "project:test".to_owned(),
            capability_choice_id: String::new(),
            context_references: "docs/one.md, docs/two.md".to_owned(),
            memory_enabled: true,
        };
        controller
    }

    async fn pump_until_settled<C: WorkStartClient + ?Sized + 'static>(
        controller: &mut WorkStartControllerCore<C>,
    ) {
        for _ in 0..100 {
            let _ = controller.pump().await;
            if !controller.is_running() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("controller did not settle")
    }

    async fn install_event<C: WorkStartClient + ?Sized + 'static>(
        controller: &mut WorkStartControllerCore<C>,
        event: WorkStartWorkerEvent,
    ) {
        let (sender, events) = mpsc::channel(1);
        sender.send(event).await.unwrap();
        controller.runtime = Some(WorkStartRuntime {
            events,
            worker: None,
        });
    }

    #[tokio::test]
    async fn prepared_work_is_confirmed_once_and_navigates_with_real_task_identity() {
        let confirms = Arc::new(AtomicU64::new(0));
        let mut controller = controller_for(Ok(WorkStartPreparationOutcome::Prepared(Box::new(
            prepared(
                Arc::clone(&confirms),
                WorkStartConfirmationOutcome::Confirmed("task:real".to_owned()),
            ),
        ))));
        controller.prepare().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert_eq!(controller.model.stage, WorkStartStage::PreviewReady);
        controller.confirm().await.unwrap();
        assert!(controller.confirm().await.is_err());
        pump_until_settled(&mut controller).await;
        assert_eq!(confirms.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.take_confirmed_task_id().as_deref(),
            Some("task:real")
        );
    }

    #[tokio::test]
    async fn blocked_preview_and_preview_escape_send_zero_confirmations() {
        let confirms = Arc::new(AtomicU64::new(0));
        let mut blocked = prepared(
            Arc::clone(&confirms),
            WorkStartConfirmationOutcome::Confirmed("task:blocked".to_owned()),
        );
        blocked.preview = preview(false);
        let mut controller =
            controller_for(Ok(WorkStartPreparationOutcome::Prepared(Box::new(blocked))));
        controller.prepare().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert!(controller.confirm().await.is_err());
        assert_eq!(confirms.load(Ordering::SeqCst), 0);
        controller.cancel_preview().await.unwrap();
        assert!(controller.take_dashboard_navigation());
        assert!(
            controller
                .model
                .message
                .contains("preparation may have written Context")
        );
    }

    #[tokio::test]
    async fn unknown_outcomes_retain_exact_recovery_and_never_start_over() {
        let confirms = Arc::new(AtomicU64::new(0));
        let confirmation_replays = Arc::new(AtomicU64::new(0));
        let preparation_recovery = Arc::new(PreparationReplay {
            calls: AtomicU64::new(0),
            prepared: Mutex::new(Some(prepared(
                Arc::clone(&confirms),
                WorkStartConfirmationOutcome::OutcomeUnknown(Arc::new(ConfirmationReplay {
                    calls: Arc::clone(&confirmation_replays),
                    task_id: "task:replayed".to_owned(),
                })),
            ))),
        });
        let mut controller = controller_for(Ok(WorkStartPreparationOutcome::OutcomeUnknown(
            preparation_recovery.clone(),
        )));
        controller.prepare().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert_eq!(
            controller.model.stage,
            WorkStartStage::PreparationOutcomeUnknown
        );
        controller.replay_preparation().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert_eq!(preparation_recovery.calls.load(Ordering::SeqCst), 1);
        controller.confirm().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert_eq!(
            controller.model.stage,
            WorkStartStage::ConfirmationOutcomeUnknown
        );
        controller.replay_confirmation().await.unwrap();
        pump_until_settled(&mut controller).await;
        assert_eq!(
            controller.take_confirmed_task_id().as_deref(),
            Some("task:replayed")
        );
        assert_eq!(confirms.load(Ordering::SeqCst), 1);
        assert_eq!(confirmation_replays.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn in_flight_escape_waits_without_cancelling_or_repeating_mutations() {
        let prepare_calls = Arc::new(AtomicU64::new(0));
        let prepare_release = Arc::new(Notify::new());
        let confirms = Arc::new(AtomicU64::new(0));
        let confirm_release = Arc::new(Notify::new());
        let pending_confirmation = WorkStartPrepared::from_safe_projection(
            preview(true),
            Box::new(PendingConfirmation {
                calls: Arc::clone(&confirms),
                release: Arc::clone(&confirm_release),
                outcome: WorkStartConfirmationOutcome::Confirmed("task:settled".to_owned()),
            }),
        );
        let client = Arc::new(PendingClient {
            calls: Arc::clone(&prepare_calls),
            release: Arc::clone(&prepare_release),
            result: Mutex::new(Some(Ok(WorkStartPreparationOutcome::Prepared(Box::new(
                pending_confirmation,
            ))))),
        });
        let mut controller = WorkStartControllerCore::new(client);
        controller.prepare().await.unwrap();
        controller.request_return_after_preparation();
        assert!(controller.is_running());
        assert!(
            controller
                .wait_for_settlement(Duration::from_millis(1))
                .await
                .is_err()
        );
        assert!(controller.is_running());
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
        prepare_release.notify_one();
        controller
            .wait_for_settlement(Duration::from_secs(1))
            .await
            .unwrap();
        assert!(controller.take_dashboard_navigation());
        assert!(
            controller
                .model
                .message
                .contains("without Task confirmation")
        );

        let pending_confirmation = WorkStartPrepared::from_safe_projection(
            preview(true),
            Box::new(PendingConfirmation {
                calls: Arc::clone(&confirms),
                release: Arc::clone(&confirm_release),
                outcome: WorkStartConfirmationOutcome::Confirmed("task:settled".to_owned()),
            }),
        );
        controller.prepared = Some(pending_confirmation);
        controller.model.preview = Some(preview(true));
        controller.model.stage = WorkStartStage::PreviewReady;
        controller.confirm().await.unwrap();
        controller.note_confirmation_cannot_cancel();
        assert!(
            controller
                .wait_for_settlement(Duration::from_millis(1))
                .await
                .is_err()
        );
        controller.note_confirmation_cannot_cancel();
        assert!(controller.is_running());
        assert_eq!(confirms.load(Ordering::SeqCst), 1);
        confirm_release.notify_one();
        controller
            .wait_for_settlement(Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(confirms.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.take_confirmed_task_id().as_deref(),
            Some("task:settled")
        );
    }

    #[tokio::test]
    async fn stale_terminal_successes_retire_runtime_without_opening_preview_or_task_watch() {
        let confirms = Arc::new(AtomicU64::new(0));
        let mut controller = controller_for(Err("unused".to_owned()));
        controller.generation = 9;
        let original = controller.model.clone();
        install_event(
            &mut controller,
            WorkStartWorkerEvent::Prepared {
                generation: 8,
                prepared: Box::new(prepared(
                    Arc::clone(&confirms),
                    WorkStartConfirmationOutcome::Confirmed("task:stale-prepared".to_owned()),
                )),
            },
        )
        .await;
        controller.pump().await.unwrap();
        assert!(!controller.is_running());
        assert_eq!(controller.model, original);
        assert!(controller.model.preview.is_none());

        install_event(
            &mut controller,
            WorkStartWorkerEvent::Confirmed {
                generation: 8,
                task_id: "task:stale-confirmed".to_owned(),
            },
        )
        .await;
        controller.pump().await.unwrap();
        assert!(!controller.is_running());
        assert_eq!(controller.model, original);
        assert!(controller.take_confirmed_task_id().is_none());
        assert_eq!(confirms.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn production_renderer_never_exposes_raw_governance_or_source_canaries() {
        const RAW_CANARIES: [&str; 5] = [
            "RAW_REASON_CANARY",
            "RAW_EVIDENCE_CANARY",
            "RAW_PROOF_CANARY",
            "RAW_SOURCE_CANARY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        let mut model = WorkStartPageModel {
            stage: WorkStartStage::PreviewReady,
            preview: Some(preview(false)),
            ..WorkStartPageModel::default()
        };
        model.message = safe_guided_work_error(&ClientGuidedWorkError::Protocol(
            "RAW_REASON_CANARY RAW_EVIDENCE_CANARY RAW_PROOF_CANARY RAW_SOURCE_CANARY 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ));

        let backend = ratatui::backend::TestBackend::new(120, 24);
        let mut terminal = ratatui::Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render_work_start_page(frame, frame.area(), &model))
            .expect("render Work Start safe projection");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(rendered.contains("Work Start"));
        assert!(rendered.contains("The Work API response failed integrity validation"));
        assert!(rendered.contains("CONTEXT_SOURCE_UNREADABLE"));
        for canary in RAW_CANARIES {
            assert!(!rendered.contains(canary), "leaked raw canary {canary}");
        }
    }

    #[test]
    fn missing_context_without_memory_shows_the_recovery_action() {
        let message = safe_guided_work_error(&ClientGuidedWorkError::InvalidInput(
            "add a context reference or enable memory",
        ));

        assert_eq!(
            message,
            "Work Start input is invalid: add a context reference or enable memory"
        );
    }
}
