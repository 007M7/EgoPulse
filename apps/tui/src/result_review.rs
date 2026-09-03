use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use egopulse_client_operations::{
    ClientAttachment, ClientTaskResultReviewError, TaskResultReview, TaskResultReviewStage,
};
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::{
        ArtifactSemanticClass, ArtifactSetStatus, ArtifactStatus, ClaimSourceType, ClaimStatus,
        EvidenceProducerClass, EvidenceRelation, EvidenceStatus, HashAlgorithm, IntegrityStatus,
    },
    localapi::v1::{ProjectionHealth, SourceDomain},
    task::v1::TaskStatus,
    verdict::v1::{FounderVerdictDecision, FounderVerdictStateKind, RiskCategory},
    verification::v1::{
        CheckerAssuranceClass, CriterionOutcome, CriterionRequirement, DiscrepancySeverity,
        EvidenceCoverage, UnverifiedReason, VerificationConclusion,
    },
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

pub const RESULT_REVIEW_CHANNEL_CAPACITY: usize = 1;
pub const RESULT_REVIEW_STOP_TIMEOUT: Duration = Duration::from_secs(1);
pub const RESULT_REVIEW_NOTICE: &str = "Governance evidence does not complete the Task.";

pub type TaskResultReviewFuture<'a> = Pin<
    Box<dyn Future<Output = Result<TaskResultReview, ClientTaskResultReviewError>> + Send + 'a>,
>;

pub trait TaskResultReviewClient: Send + Sync {
    fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a>;
}

impl TaskResultReviewClient for ClientAttachment {
    fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a> {
        Box::pin(ClientAttachment::read_task_result_review(self, task_id))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultReviewSection {
    Summary,
    ArtifactsClaimsEvidence,
    Verification,
    FounderVerdictState,
    ProjectionRedactions,
}

impl ResultReviewSection {
    pub const ALL: [Self; 5] = [
        Self::Summary,
        Self::ArtifactsClaimsEvidence,
        Self::Verification,
        Self::FounderVerdictState,
        Self::ProjectionRedactions,
    ];

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::ArtifactsClaimsEvidence => "Artifacts / Claims / Evidence",
            Self::Verification => "Verification",
            Self::FounderVerdictState => "Founder Verdict / State",
            Self::ProjectionRedactions => "Projection / Redactions",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultReviewPageModel {
    pub task_id: String,
    pub task_status: String,
    pub section: ResultReviewSection,
    pub scroll: u16,
    pub stale: bool,
    pub message: String,
    sections: [Vec<String>; 5],
}

impl ResultReviewPageModel {
    fn from_review(review: TaskResultReview) -> Result<Self, String> {
        let task = review
            .task_view
            .task
            .as_ref()
            .ok_or_else(|| "Result review omitted its Task snapshot".to_owned())?;
        if task.task_id.is_empty() {
            return Err("Result review returned an empty Task identity".to_owned());
        }
        let task_status = enum_name::<TaskStatus>(task.status);
        let mut summary = vec![
            format!("Task: {}", task.task_id),
            format!("Task revision: {}", task.revision),
            format!("Task status: {task_status}"),
            RESULT_REVIEW_NOTICE.to_owned(),
        ];
        match review.task_view.artifact_set.as_ref() {
            Some(set) => {
                summary.push(format!("ArtifactSet: {}", set.artifact_set_id));
                summary.push(format!("ArtifactSet revision: {}", set.revision));
                summary.push(format!(
                    "ArtifactSet status: {}",
                    enum_name::<ArtifactSetStatus>(set.status)
                ));
                push_lineage(&mut summary, "ArtifactSet lineage", set.lineage.as_ref());
                summary.push(format!("Artifact IDs: {}", set.artifact_ids.join(",")));
                summary.push(format!("Claim IDs: {}", set.claim_ids.join(",")));
                summary.push(format!("Evidence IDs: {}", set.evidence_ids.join(",")));
                push_content(
                    &mut summary,
                    "ArtifactSet canonical manifest",
                    set.canonical_manifest.as_ref(),
                );
                push_timestamp(&mut summary, "ArtifactSet created", set.created_at.as_ref());
                push_timestamp(&mut summary, "ArtifactSet sealed", set.sealed_at.as_ref());
                summary.push(format!(
                    "ArtifactSet supersedes: {}",
                    display_option(&set.supersedes_artifact_set_id)
                ));
            }
            None => summary.push("ArtifactSet: Not projected".to_owned()),
        }

        let mut ace = Vec::new();
        let mut verification_lines = Vec::new();
        let mut verdict_lines = Vec::new();
        let mut projection_lines = Vec::new();
        match review.evidence_graph.as_ref() {
            Some(graph) => {
                ace.push(format!("Graph task: {}", graph.task_id));
                ace.push(format!("Graph ArtifactSet: {}", graph.artifact_set_id));
                for artifact in &graph.artifacts {
                    ace.push(format!(
                        "Artifact {} rev={} status={} class={} media={}",
                        artifact.artifact_id,
                        artifact.revision,
                        enum_name::<ArtifactStatus>(artifact.status),
                        enum_name::<ArtifactSemanticClass>(artifact.semantic_class),
                        artifact.media_type
                    ));
                    push_contract(&mut ace, "  type", artifact.type_contract_ref.as_ref());
                    push_content(&mut ace, "  content", artifact.content.as_ref());
                    ace.push(format!(
                        "  integrity={} sensitivity={} quarantine={}",
                        enum_name::<IntegrityStatus>(artifact.integrity_status),
                        artifact.sensitivity_class,
                        display_option(&artifact.quarantine_reason_code)
                    ));
                    push_contract(
                        &mut ace,
                        "  retention",
                        artifact.retention_profile_ref.as_ref(),
                    );
                    if let Some(provenance) = &artifact.provenance {
                        push_lineage(&mut ace, "  lineage", provenance.lineage.as_ref());
                        if let Some(producer) = &provenance.producer {
                            ace.push(format!(
                                "  producer kind={} component={} version={} profile={}",
                                producer.principal_kind,
                                producer.component_name,
                                producer.component_version,
                                display_option(&producer.capability_profile_id)
                            ));
                        }
                        ace.push(format!(
                            "  inputs={}",
                            provenance.input_artifact_ids.join(",")
                        ));
                        push_contract(
                            &mut ace,
                            "  transformation",
                            provenance.transformation_contract_ref.as_ref(),
                        );
                        push_timestamp(&mut ace, "  observed", provenance.observed_at.as_ref());
                        push_timestamp(&mut ace, "  captured", provenance.captured_at.as_ref());
                    }
                    push_timestamp(&mut ace, "  created", artifact.created_at.as_ref());
                    push_timestamp(&mut ace, "  sealed", artifact.sealed_at.as_ref());
                    ace.push(format!(
                        "  supersedes={}",
                        display_option(&artifact.supersedes_artifact_id)
                    ));
                }
                for claim in &graph.claims {
                    ace.push(format!(
                        "Claim {} rev={} status={} source={}",
                        claim.claim_id,
                        claim.revision,
                        enum_name::<ClaimStatus>(claim.status),
                        enum_name::<ClaimSourceType>(claim.source_type)
                    ));
                    push_contract(
                        &mut ace,
                        "  semantic profile",
                        claim.semantic_profile_ref.as_ref(),
                    );
                    push_lineage(&mut ace, "  lineage", claim.lineage.as_ref());
                    ace.push(format!(
                        "  subjects={}",
                        claim.subject_artifact_ids.join(",")
                    ));
                    push_contract(
                        &mut ace,
                        "  acceptance",
                        claim.acceptance_contract_ref.as_ref(),
                    );
                    push_content(&mut ace, "  statement", claim.statement.as_ref());
                    push_timestamp(&mut ace, "  proposed", claim.proposed_at.as_ref());
                    ace.push(format!(
                        "  supersedes={}",
                        display_option(&claim.supersedes_claim_id)
                    ));
                }
                for evidence in &graph.evidence {
                    ace.push(format!(
                        "Evidence {} rev={} status={} relation={} claim={}",
                        evidence.evidence_id,
                        evidence.revision,
                        enum_name::<EvidenceStatus>(evidence.status),
                        enum_name::<EvidenceRelation>(evidence.relation),
                        evidence.claim_id
                    ));
                    ace.push(format!("  artifacts={}", evidence.artifact_ids.join(",")));
                    push_contract(
                        &mut ace,
                        "  profile",
                        evidence.evidence_profile_ref.as_ref(),
                    );
                    push_lineage(&mut ace, "  lineage", evidence.lineage.as_ref());
                    ace.push(format!(
                        "  producer={} independent={} integrity={}",
                        enum_name::<EvidenceProducerClass>(evidence.producer_class),
                        evidence.independent_of_claim_proposer,
                        enum_name::<IntegrityStatus>(evidence.integrity_status)
                    ));
                    push_content(
                        &mut ace,
                        "  coverage",
                        evidence.coverage_descriptor.as_ref(),
                    );
                    ace.push(format!(
                        "  limitations={}",
                        evidence.limitation_codes.join(",")
                    ));
                    push_timestamp(&mut ace, "  recorded", evidence.recorded_at.as_ref());
                    ace.push(format!(
                        "  supersedes={}",
                        display_option(&evidence.supersedes_evidence_id)
                    ));
                }
                push_projection(
                    &mut projection_lines,
                    "Evidence projection",
                    graph.metadata.as_ref(),
                );
                push_redactions(
                    &mut projection_lines,
                    "Evidence redaction",
                    &graph.redactions,
                );
            }
            None => ace.push("Artifacts / Claims / Evidence: Not projected".to_owned()),
        }

        match review.task_view.verification.as_ref() {
            Some(verification) => {
                verification_lines.push(format!(
                    "Verification: {} version={}",
                    verification.verification_artifact_id, verification.version
                ));
                verification_lines.push(format!(
                    "Request={} run={} type={} conclusion={} coverage={}",
                    verification.verification_request_id,
                    verification.verification_run_id,
                    verification.verification_type,
                    enum_name::<VerificationConclusion>(verification.conclusion),
                    enum_name::<EvidenceCoverage>(verification.overall_evidence_coverage)
                ));
                if let Some(binding) = &verification.binding {
                    push_lineage(
                        &mut verification_lines,
                        "Binding lineage",
                        binding.lineage.as_ref(),
                    );
                    verification_lines.push(format!(
                        "Binding ArtifactSet={} claim={}",
                        binding.artifact_set_id, binding.claim_id
                    ));
                    push_content(
                        &mut verification_lines,
                        "Binding manifest",
                        binding.artifact_set_manifest.as_ref(),
                    );
                    push_contract(
                        &mut verification_lines,
                        "Binding claim profile",
                        binding.claim_semantic_profile_ref.as_ref(),
                    );
                    push_contract(
                        &mut verification_lines,
                        "Binding acceptance",
                        binding.acceptance_contract_ref.as_ref(),
                    );
                }
                for criterion in &verification.criterion_results {
                    verification_lines.push(format!("Criterion {} requirement={} outcome={} assurance={} coverage={} evidence={} discrepancies={} unverified={} duration_ms={} detail={}", criterion.criterion_id, enum_name::<CriterionRequirement>(criterion.requirement), enum_name::<CriterionOutcome>(criterion.outcome), enum_name::<CheckerAssuranceClass>(criterion.assurance_class), enum_name::<EvidenceCoverage>(criterion.evidence_coverage), criterion.evidence_ids.join(","), criterion.discrepancy_ids.join(","), criterion.unverified_item_ids.join(","), criterion.duration_ms, display_option(&criterion.safe_detail_artifact_id)));
                    push_contract(
                        &mut verification_lines,
                        "  checker",
                        criterion.checker_profile_ref.as_ref(),
                    );
                }
                for discrepancy in &verification.discrepancies {
                    verification_lines.push(format!("Discrepancy {} criterion={} severity={} evidence={} description={} suggested_fix={}", discrepancy.discrepancy_id, discrepancy.criterion_id, enum_name::<DiscrepancySeverity>(discrepancy.severity), discrepancy.evidence_ids.join(","), discrepancy.description_artifact_id, display_option(&discrepancy.suggested_fix_artifact_id)));
                }
                for item in &verification.unverified_items {
                    verification_lines.push(format!(
                        "Unverified {} criterion={} reason={} evidence={} context={}",
                        item.unverified_item_id,
                        item.criterion_id,
                        enum_name::<UnverifiedReason>(item.reason),
                        item.evidence_ids.join(","),
                        display_option(&item.context_artifact_id)
                    ));
                }
                if let Some(provenance) = &verification.provenance {
                    verification_lines.push(format!("Provenance tools={} model_calls={} raw_output_artifacts={} duration_ms={} cost_receipt={}", provenance.tool_receipt_artifact_ids.join(","), provenance.model_call_receipt_artifact_ids.join(","), provenance.raw_output_artifact_ids.join(","), provenance.duration_ms, display_option(&provenance.cost_receipt_artifact_id)));
                    for profile in &provenance.checker_profile_refs {
                        push_contract(&mut verification_lines, "  checker profile", Some(profile));
                    }
                }
                push_content(
                    &mut verification_lines,
                    "Canonical payload",
                    verification.canonical_payload.as_ref(),
                );
                push_timestamp(
                    &mut verification_lines,
                    "Completed",
                    verification.completed_at.as_ref(),
                );
                verification_lines.push(format!(
                    "Supersedes={}",
                    display_option(&verification.supersedes_verification_artifact_id)
                ));
            }
            None => verification_lines.push("Verification: Not projected".to_owned()),
        }

        match review.task_view.founder_verdict.as_ref() {
            Some(verdict) => {
                verdict_lines.push(format!(
                    "Founder Verdict: {} version={} decision={} observed={}",
                    verdict.founder_verdict_id,
                    verdict.version,
                    enum_name::<FounderVerdictDecision>(verdict.decision),
                    enum_name::<VerificationConclusion>(verdict.observed_verification_conclusion)
                ));
                if let Some(scope) = &verdict.scope {
                    verdict_lines.push(format!(
                        "Scope task={} task_rev={} work_rev={} ArtifactSet={} verification={}",
                        scope.task_id,
                        scope.task_revision,
                        scope.work_revision,
                        scope.artifact_set_id,
                        scope.verification_artifact_id
                    ));
                    push_content(
                        &mut verdict_lines,
                        "Scope manifest",
                        scope.artifact_set_manifest.as_ref(),
                    );
                    push_content(
                        &mut verdict_lines,
                        "Scope verification payload",
                        scope.verification_payload.as_ref(),
                    );
                    push_contract(
                        &mut verdict_lines,
                        "Scope acceptance",
                        scope.acceptance_contract_ref.as_ref(),
                    );
                }
                for risk in &verdict.risk_acceptances {
                    verdict_lines.push(format!("Risk {} category={} discrepancies={} unverified={} rationale={} controls={} trigger={}", risk.risk_acceptance_id, enum_name::<RiskCategory>(risk.category), risk.discrepancy_ids.join(","), risk.unverified_item_ids.join(","), risk.rationale_artifact_id, risk.compensating_control_artifact_ids.join(","), display_option(&risk.review_trigger_code)));
                }
                if let Some(rework) = &verdict.rework_directive {
                    verdict_lines.push(format!(
                        "Rework {} reason={} required={} discrepancies={} unverified={}",
                        rework.directive_id,
                        rework.reason_code,
                        rework.required_changes_artifact_id,
                        rework.target_discrepancy_ids.join(","),
                        rework.target_unverified_item_ids.join(",")
                    ));
                }
                verdict_lines.push(format!(
                    "Reason={} rationale={}",
                    verdict.reason_code,
                    display_option(&verdict.rationale_artifact_id)
                ));
                push_timestamp(
                    &mut verdict_lines,
                    "Valid from",
                    verdict.valid_from.as_ref(),
                );
                push_timestamp(&mut verdict_lines, "Expires", verdict.expires_at.as_ref());
                push_timestamp(&mut verdict_lines, "Issued", verdict.issued_at.as_ref());
                push_content(
                    &mut verdict_lines,
                    "Canonical payload",
                    verdict.canonical_payload.as_ref(),
                );
                verdict_lines.push(format!(
                    "Supersedes={}",
                    display_option(&verdict.supersedes_founder_verdict_id)
                ));
            }
            None => verdict_lines.push("Founder Verdict: Not projected".to_owned()),
        }
        match review.task_view.founder_verdict_state.as_ref() {
            Some(state) => {
                verdict_lines.push(format!("Founder Verdict State: {} rev={} state={} receipt={} superseded_by={} terminal_reason={}", state.founder_verdict_id, state.revision, enum_name::<FounderVerdictStateKind>(state.state), display_option(&state.consumption_receipt_id), display_option(&state.superseded_by_verdict_id), display_option(&state.terminal_reason_code)));
                push_timestamp(
                    &mut verdict_lines,
                    "State updated",
                    state.updated_at.as_ref(),
                );
            }
            None => verdict_lines.push("Founder Verdict State: Not projected".to_owned()),
        }
        push_projection(
            &mut projection_lines,
            "Task projection",
            review.task_view.metadata.as_ref(),
        );
        push_redactions(
            &mut projection_lines,
            "Task redaction",
            &review.task_view.redactions,
        );

        Ok(Self {
            task_id: task.task_id.clone(),
            task_status,
            section: ResultReviewSection::Summary,
            scroll: 0,
            stale: false,
            message: "Result review loaded; r refreshes, Esc returns to Task Watch".to_owned(),
            sections: [
                summary,
                ace,
                verification_lines,
                verdict_lines,
                projection_lines,
            ],
        })
    }

    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.sections[self.section_index()]
    }

    pub fn next_section(&mut self) {
        self.section =
            ResultReviewSection::ALL[(self.section_index() + 1) % ResultReviewSection::ALL.len()];
        self.scroll = 0;
    }

    pub fn previous_section(&mut self) {
        let index = self.section_index();
        self.section = ResultReviewSection::ALL[index
            .checked_sub(1)
            .unwrap_or(ResultReviewSection::ALL.len() - 1)];
        self.scroll = 0;
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_add(amount);
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    fn section_index(&self) -> usize {
        ResultReviewSection::ALL
            .iter()
            .position(|section| *section == self.section)
            .expect("section is enumerated")
    }
}

#[derive(Debug)]
enum ResultReviewWorkerEvent {
    Loaded {
        generation: u64,
        model: Box<ResultReviewPageModel>,
    },
    Failed {
        generation: u64,
        detail: String,
    },
}

impl ResultReviewWorkerEvent {
    fn generation(&self) -> u64 {
        match self {
            Self::Loaded { generation, .. } | Self::Failed { generation, .. } => *generation,
        }
    }
}

struct ResultReviewRuntime {
    events: mpsc::Receiver<ResultReviewWorkerEvent>,
    cancel: watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl ResultReviewRuntime {
    async fn stop(mut self) {
        let _ = self.cancel.send(true);
        let Some(mut worker) = self.worker.take() else {
            return;
        };
        if tokio::time::timeout(RESULT_REVIEW_STOP_TIMEOUT, &mut worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = tokio::time::timeout(RESULT_REVIEW_STOP_TIMEOUT, worker).await;
        }
    }
}

impl Drop for ResultReviewRuntime {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

pub struct ResultReviewController<C: TaskResultReviewClient + ?Sized + 'static> {
    client: Arc<C>,
    task_id: String,
    generation: u64,
    model: Option<ResultReviewPageModel>,
    runtime: Option<ResultReviewRuntime>,
}

impl<C: TaskResultReviewClient + ?Sized + 'static> ResultReviewController<C> {
    #[must_use]
    pub fn new(client: Arc<C>, task_id: String) -> Self {
        Self {
            client,
            task_id,
            generation: 0,
            model: None,
            runtime: None,
        }
    }

    #[must_use]
    pub fn model(&self) -> Option<&ResultReviewPageModel> {
        self.model.as_ref()
    }
    pub fn model_mut(&mut self) -> Option<&mut ResultReviewPageModel> {
        self.model.as_mut()
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.task_id.trim().is_empty() {
            return Err("Result review requires a selected Task".to_owned());
        }
        self.refresh().await
    }

    pub async fn refresh(&mut self) -> Result<(), String> {
        self.stop().await;
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let task_id = self.task_id.clone();
        let client = Arc::clone(&self.client);
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.read_task_result_review(&task_id) => result,
            };
            let event = match result {
                Ok(review) => match ResultReviewPageModel::from_review(review) {
                    Ok(model) => ResultReviewWorkerEvent::Loaded {
                        generation,
                        model: Box::new(model),
                    },
                    Err(detail) => ResultReviewWorkerEvent::Failed { generation, detail },
                },
                Err(error) => ResultReviewWorkerEvent::Failed {
                    generation,
                    detail: safe_review_error(&error),
                },
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
        Ok(())
    }

    pub async fn pump(&mut self) -> Result<(), String> {
        let events = self.runtime.as_mut().map_or_else(Vec::new, |runtime| {
            let mut events = Vec::new();
            while let Ok(event) = runtime.events.try_recv() {
                events.push(event);
            }
            events
        });
        for event in events {
            if event.generation() != self.generation {
                continue;
            }
            match event {
                ResultReviewWorkerEvent::Loaded { model, .. } => {
                    self.model = Some(*model);
                }
                ResultReviewWorkerEvent::Failed { detail, .. } => {
                    self.stop().await;
                    if let Some(model) = &mut self.model {
                        model.stale = true;
                        model.message = format!("Result review stopped fail-closed: {detail}");
                    }
                    return Err(detail);
                }
            }
        }
        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop().await;
        }
    }
}

async fn send_result_review_event(
    sender: &mpsc::Sender<ResultReviewWorkerEvent>,
    cancellation: &mut watch::Receiver<bool>,
    event: ResultReviewWorkerEvent,
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
        changed = cancellation.changed() => changed.is_ok() && !*cancellation.borrow(),
    }
}

impl<C: TaskResultReviewClient + ?Sized + 'static> Drop for ResultReviewController<C> {
    fn drop(&mut self) {
        self.runtime.take();
    }
}

fn safe_review_error(error: &ClientTaskResultReviewError) -> String {
    match error {
        ClientTaskResultReviewError::InvalidInput(_) => "invalid result review request".to_owned(),
        ClientTaskResultReviewError::Kernel { stage, .. } => format!(
            "{} review permission or session rejected",
            stage_name(*stage)
        ),
        ClientTaskResultReviewError::Transport { stage, .. } => {
            format!("{} review transport unavailable", stage_name(*stage))
        }
        ClientTaskResultReviewError::Api { stage, error } => format!(
            "{} review API rejected code={} retryable={}",
            stage_name(*stage),
            error.code,
            error.retryable
        ),
        ClientTaskResultReviewError::Integrity { stage, .. } => {
            format!("{} review integrity failed", stage_name(*stage))
        }
    }
}

fn stage_name(stage: TaskResultReviewStage) -> &'static str {
    stage.as_str()
}

fn enum_name<E>(value: i32) -> String
where
    E: TryFrom<i32> + std::fmt::Debug,
{
    E::try_from(value).map_or_else(|_| "UNSPECIFIED".to_owned(), |value| format!("{value:?}"))
}

fn display_option(value: &Option<String>) -> &str {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("Not projected")
}

fn push_timestamp(lines: &mut Vec<String>, label: &str, value: Option<&prost_types::Timestamp>) {
    lines.push(value.map_or_else(
        || format!("{label}: Not projected"),
        |value| format!("{label}: {}.{:09}", value.seconds, value.nanos),
    ));
}

fn push_content(
    lines: &mut Vec<String>,
    label: &str,
    value: Option<&egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress>,
) {
    lines.push(value.map_or_else(
        || format!("{label}: Not projected"),
        |value| {
            format!(
                "{label}: algorithm={} digest={} bytes={}",
                enum_name::<HashAlgorithm>(value.algorithm),
                value.digest,
                value.byte_length
            )
        },
    ));
}

fn push_contract(
    lines: &mut Vec<String>,
    label: &str,
    value: Option<&egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference>,
) {
    lines.push(value.map_or_else(
        || format!("{label}: Not projected"),
        |value| {
            format!(
                "{label}: {}@{} sha256={}",
                value.contract_id, value.version, value.sha256
            )
        },
    ));
}

fn push_lineage(
    lines: &mut Vec<String>,
    label: &str,
    value: Option<&egopulse_domain_contracts::v01::egopulse::artifact::v1::LineageBinding>,
) {
    lines.push(value.map_or_else(|| format!("{label}: Not projected"), |value| format!("{label}: task={} task_rev={} work_rev={} run={} run_rev={} step={} step_rev={} attempt={} attempt_rev={} dispatch={} fence={}", value.task_id, value.task_revision, value.work_revision, value.run_id, value.run_revision, value.step_id, value.step_revision, value.attempt_id, value.attempt_revision, value.dispatch_id, value.fencing_token)));
}

fn push_projection(
    lines: &mut Vec<String>,
    label: &str,
    value: Option<&egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionMetadata>,
) {
    let Some(value) = value else {
        lines.push(format!("{label}: Not projected"));
        return;
    };
    lines.push(format!(
        "{label}: health={} stale={} reason={}",
        enum_name::<ProjectionHealth>(value.health),
        value.stale,
        display_option(&value.safe_health_reason_code)
    ));
    push_contract(lines, "  schema", value.schema_ref.as_ref());
    if let Some(position) = &value.position {
        lines.push(format!(
            "  position={}:{}",
            position.epoch, position.sequence
        ));
    }
    for source in &value.source_revisions {
        lines.push(format!(
            "  source={} aggregate={} revision={} event={}",
            enum_name::<SourceDomain>(source.domain),
            source.aggregate_id,
            source.revision,
            source.last_event_id
        ));
    }
}

fn push_redactions(
    lines: &mut Vec<String>,
    label: &str,
    values: &[egopulse_domain_contracts::v01::egopulse::localapi::v1::RedactedField],
) {
    if values.is_empty() {
        lines.push(format!("{label}: none"));
    }
    for value in values {
        lines.push(format!(
            "{label}: field={} reason={}",
            value.field_path, value.reason_code
        ));
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

    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactDescriptor, ArtifactSet, Claim, Evidence, ProducerIdentity, Provenance,
        },
        localapi::v1::{EvidenceGraphView, RedactedField, TaskView},
        task::v1::TaskSnapshot,
        verdict::v1::{FounderAuthorityProof, FounderVerdict},
        verification::v1::{VerificationArtifact, VerificationProvenance},
    };

    use super::*;

    #[derive(Clone)]
    enum ReadStep {
        Ready(Box<TaskResultReview>),
        Integrity,
        Pending(Arc<AtomicBool>),
    }

    struct DropWitness(Arc<AtomicBool>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct ScriptedClient {
        steps: Mutex<VecDeque<ReadStep>>,
        calls: AtomicUsize,
    }

    impl TaskResultReviewClient for ScriptedClient {
        fn read_task_result_review<'a>(&'a self, _task_id: &'a str) -> TaskResultReviewFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted read");
            Box::pin(async move {
                match step {
                    ReadStep::Ready(review) => Ok(*review),
                    ReadStep::Integrity => Err(ClientTaskResultReviewError::Integrity {
                        stage: TaskResultReviewStage::Evidence,
                        detail: "tampered",
                    }),
                    ReadStep::Pending(witness) => {
                        let _guard = DropWitness(witness);
                        std::future::pending().await
                    }
                }
            })
        }
    }

    fn review(task_id: &str) -> TaskResultReview {
        let sensitive = ProducerIdentity {
            principal_id: "SECRET-PRINCIPAL".to_owned(),
            native_execution_ref: Some("SECRET-NATIVE".to_owned()),
            component_name: "safe-component".to_owned(),
            ..Default::default()
        };
        TaskResultReview {
            task_view: TaskView {
                task: Some(TaskSnapshot {
                    task_id: task_id.to_owned(),
                    revision: 7,
                    status: TaskStatus::Active as i32,
                    ..Default::default()
                }),
                artifact_set: Some(ArtifactSet {
                    artifact_set_id: "artifact-set:safe".to_owned(),
                    revision: 2,
                    ..Default::default()
                }),
                verification: Some(VerificationArtifact {
                    verification_artifact_id: "verification:safe".to_owned(),
                    conclusion: VerificationConclusion::Partial as i32,
                    provenance: Some(VerificationProvenance {
                        verifier_principal_id: "SECRET-VERIFIER".to_owned(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                founder_verdict: Some(FounderVerdict {
                    founder_verdict_id: "verdict:safe".to_owned(),
                    decision: FounderVerdictDecision::Rework as i32,
                    authority_proof: Some(FounderAuthorityProof {
                        authenticated_founder_principal_id: "SECRET-FOUNDER".to_owned(),
                        confirmation_proof_ref: "SECRET-PROOF".to_owned(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                redactions: vec![RedactedField {
                    field_path: "founder_verdict.authority_proof".to_owned(),
                    reason_code: "PRIVATE".to_owned(),
                }],
                ..Default::default()
            },
            evidence_graph: Some(EvidenceGraphView {
                task_id: task_id.to_owned(),
                artifact_set_id: "artifact-set:safe".to_owned(),
                artifacts: vec![ArtifactDescriptor {
                    artifact_id: "artifact:safe".to_owned(),
                    provenance: Some(Provenance {
                        producer: Some(sensitive),
                        workspace_ref: "SECRET-WORKSPACE".to_owned(),
                        raw_source_ref: Some("SECRET-RAW".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                claims: vec![Claim {
                    claim_id: "claim:safe".to_owned(),
                    statement: Some(
                        egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress {
                            algorithm: HashAlgorithm::Sha256 as i32,
                            digest: "a".repeat(64),
                            byte_length: 12,
                        },
                    ),
                    ..Default::default()
                }],
                evidence: vec![Evidence {
                    evidence_id: "evidence:safe".to_owned(),
                    claim_id: "claim:safe".to_owned(),
                    limitation_codes: vec!["limited:safe".to_owned()],
                    ..Default::default()
                }],
                ..Default::default()
            }),
        }
    }

    async fn pump_until_settled(
        controller: &mut ResultReviewController<ScriptedClient>,
    ) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                controller.pump().await?;
                if controller.model().is_some() {
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("review settled")
    }

    #[tokio::test]
    async fn controller_reads_once_maps_safe_dto_and_discards_old_generation_events() {
        let client = Arc::new(ScriptedClient {
            steps: Mutex::new(VecDeque::from([ReadStep::Ready(Box::new(review(
                "task:safe",
            )))])),
            calls: AtomicUsize::new(0),
        });
        let mut controller =
            ResultReviewController::new(Arc::clone(&client), "task:safe".to_owned());
        controller.start().await.unwrap();
        pump_until_settled(&mut controller).await.unwrap();
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        let model = controller.model().unwrap();
        assert_eq!(model.task_status, "Active");
        let all = model.sections.concat().join("\n");
        assert!(all.contains("artifact:safe"));
        assert!(all.contains("claim:safe"));
        assert!(all.contains("evidence:safe"));
        assert!(all.contains("verification:safe"));
        assert!(all.contains("verdict:safe"));
        assert!(all.contains("Not projected"));
        assert!(all.contains(RESULT_REVIEW_NOTICE));
        for secret in [
            "SECRET-PRINCIPAL",
            "SECRET-NATIVE",
            "SECRET-VERIFIER",
            "SECRET-FOUNDER",
            "SECRET-PROOF",
            "SECRET-WORKSPACE",
            "SECRET-RAW",
        ] {
            assert!(!all.contains(secret));
        }
        assert!(!all.contains("Task status: Completed"));

        let generation = controller.generation;
        let (sender, events) = mpsc::channel(2);
        sender
            .send(ResultReviewWorkerEvent::Loaded {
                generation: generation - 1,
                model: Box::new(ResultReviewPageModel::from_review(review("task:old")).unwrap()),
            })
            .await
            .unwrap();
        sender
            .send(ResultReviewWorkerEvent::Failed {
                generation: generation - 1,
                detail: "old failure".to_owned(),
            })
            .await
            .unwrap();
        drop(sender);
        let (cancel, _) = watch::channel(false);
        controller.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: None,
        });
        controller.pump().await.unwrap();
        assert!(!controller.model().unwrap().stale);
        assert_eq!(controller.model().unwrap().task_id, "task:safe");
        controller.stop().await;
    }

    #[tokio::test]
    async fn typed_failure_refresh_cancellation_and_runtime_drop_are_bounded() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let client = Arc::new(ScriptedClient {
            steps: Mutex::new(VecDeque::from([
                ReadStep::Pending(Arc::clone(&cancelled)),
                ReadStep::Ready(Box::new(review("task:refresh"))),
                ReadStep::Integrity,
            ])),
            calls: AtomicUsize::new(0),
        });
        let mut controller =
            ResultReviewController::new(Arc::clone(&client), "task:refresh".to_owned());
        controller.start().await.unwrap();
        tokio::task::yield_now().await;
        controller.refresh().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancelled.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        pump_until_settled(&mut controller).await.unwrap();
        controller.refresh().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Err(error) = controller.pump().await {
                    return error;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(error, "evidence review integrity failed");
        assert!(!controller.is_running());
        assert!(controller.model().unwrap().stale);
        assert!(
            controller
                .model()
                .unwrap()
                .message
                .contains("stopped fail-closed")
        );

        let terminated = Arc::new(AtomicBool::new(false));
        let witness = Arc::clone(&terminated);
        let (sender, events) = mpsc::channel(1);
        let (cancel, mut cancellation) = watch::channel(false);
        let (started_sender, started) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let _guard = DropWitness(witness);
            let _ = started_sender.send(());
            let _ = cancellation.changed().await;
        });
        started.await.unwrap();
        drop(sender);
        let runtime = ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        };
        drop(runtime);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !terminated.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let terminated = Arc::new(AtomicBool::new(false));
        let witness = Arc::clone(&terminated);
        let (sender, events) = mpsc::channel(1);
        let (cancel, _) = watch::channel(false);
        let (started_sender, started) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let _guard = DropWitness(witness);
            let _ = started_sender.send(());
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        drop(sender);
        ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        }
        .stop()
        .await;
        assert!(terminated.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn full_channel_send_is_released_by_cancellation() {
        let (sender, _events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        sender
            .try_send(ResultReviewWorkerEvent::Failed {
                generation: 1,
                detail: "full".to_owned(),
            })
            .unwrap();
        let (cancel, mut cancellation) = watch::channel(false);
        let entered = Arc::new(tokio::sync::Notify::new());
        let notified = Arc::clone(&entered);
        let blocked_sender = sender.clone();
        let blocked = tokio::spawn(async move {
            send_result_review_event(
                &blocked_sender,
                &mut cancellation,
                ResultReviewWorkerEvent::Failed {
                    generation: 1,
                    detail: "blocked".to_owned(),
                },
                Some(notified.as_ref()),
            )
            .await
        });
        entered.notified().await;
        cancel.send(true).unwrap();
        assert!(!blocked.await.unwrap());
    }
}
