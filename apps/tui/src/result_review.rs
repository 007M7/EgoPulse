use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use egopulse_client_operations::{
    ClientAttachment, ClientFounderSupportingMaterialError, ClientGuidedFounderVerdictError,
    ClientTaskResultReviewError, ConfirmedFounderSupportingMaterialReceipt,
    DurableFounderDecisionAttempt, DurableFounderMaterialAttempt, DurableFounderMaterialRecovery,
    DurableFounderRecoveryError, DurableFounderVerdictRecovery, FounderSupportingMaterialBuilder,
    FounderSupportingMaterialCollection, GuidedFounderVerdictAttempt, GuidedFounderVerdictInput,
    GuidedFounderVerdictSelection, PreparedFounderSupportingMaterial,
    RecoverableGuidedFounderVerdict, TaskResultReview, TaskResultReviewStage,
    build_guided_founder_verdict, build_guided_founder_verdict_with_materials, command_metadata,
    timestamp_after,
};
use egopulse_domain_contracts::v01::egopulse::verdict::v1::{
    FounderSupportingMaterialCoverage, FounderSupportingMaterialRole, VerdictCommand,
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
const RESULT_REVIEW_VERDICT_EXPIRY: Duration = Duration::from_secs(240);

pub type TaskResultReviewFuture<'a> = Pin<
    Box<dyn Future<Output = Result<TaskResultReview, ClientTaskResultReviewError>> + Send + 'a>,
>;
pub type GuidedFounderVerdictFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<ResultReviewVerdictAttempt, ClientGuidedFounderVerdictError>>
            + Send
            + 'a,
    >,
>;
pub type ResultReviewMaterialFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResultReviewMaterialAttempt, String>> + Send + 'a>>;
pub type DurableFounderVerdictFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResultReviewDurableVerdictAttempt, String>> + Send + 'a>>;
pub type DurableFounderVerdictPathFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResultReviewDurablePathAttempt, String>> + Send + 'a>>;

#[derive(Clone)]
pub struct ResultReviewMaterialPlan {
    task_id: String,
    allowed_roles: Vec<FounderSupportingMaterialRole>,
    recovery_paths: Vec<PathBuf>,
    prepared: Vec<(PreparedFounderSupportingMaterial, PathBuf)>,
    confirmed: Vec<ConfirmedFounderSupportingMaterialReceipt>,
}

pub struct ResultReviewMaterialInput {
    drafts: Vec<ResultReviewMaterialDraft>,
    recovery_paths: Vec<PathBuf>,
    allowed_roles: Vec<FounderSupportingMaterialRole>,
}

struct ResultReviewMaterialDraft {
    role: FounderSupportingMaterialRole,
    body: String,
    coverage: FounderSupportingMaterialCoverage,
}

pub enum ResultReviewMaterialAttempt {
    Confirmed(FounderSupportingMaterialCollection),
    Unknown {
        retry_plan: ResultReviewMaterialPlan,
        recovery_path: PathBuf,
        safe_reason_code: &'static str,
    },
}

pub enum ResultReviewDurableVerdictAttempt {
    Committed(ResultReviewCommittedVerdict),
    Unknown {
        recovery: Box<DurableFounderVerdictRecovery>,
        recovery_path: PathBuf,
        safe_reason_code: &'static str,
    },
}

pub enum ResultReviewDurablePathAttempt {
    Committed(ResultReviewCommittedVerdict),
    Unknown { safe_reason_code: &'static str },
}

#[derive(Clone)]
struct DurableVerdictRecoveryState {
    recovery: DurableFounderVerdictRecovery,
    recovery_path: PathBuf,
    selection: GuidedFounderVerdictSelection,
    safe_reason_code: &'static str,
}

#[derive(Clone)]
pub struct ResultReviewVerdictRecovery {
    selection: GuidedFounderVerdictSelection,
    sealed_command: VerdictCommand,
    shared: Option<Box<RecoverableGuidedFounderVerdict>>,
    durable: Option<DurableFounderVerdictRecovery>,
    recovery_path: Option<PathBuf>,
}

impl ResultReviewVerdictRecovery {
    /// Creates the opaque recovery held by a custom client adapter. Production
    /// `ClientAttachment` adapters retain the shared recovery internally.
    #[must_use]
    pub fn from_sealed_command_for_client_adapter(
        selection: GuidedFounderVerdictSelection,
        sealed_command: VerdictCommand,
    ) -> Self {
        Self {
            selection,
            sealed_command,
            shared: None,
            durable: None,
            recovery_path: None,
        }
    }

    #[must_use]
    pub const fn selection(&self) -> GuidedFounderVerdictSelection {
        self.selection
    }

    #[must_use]
    pub fn sealed_command(&self) -> &VerdictCommand {
        &self.sealed_command
    }

    #[must_use]
    pub fn recovery_path(&self) -> Option<&Path> {
        self.recovery_path.as_deref()
    }
}

pub struct ResultReviewCommittedVerdict {
    pub founder_verdict_id: String,
    pub decision: FounderVerdictDecision,
    pub replayed: bool,
    pub projection_pending: bool,
}

pub enum ResultReviewVerdictAttempt {
    Committed(ResultReviewCommittedVerdict),
    OutcomeUnknown(Box<ResultReviewVerdictRecovery>),
}

fn map_shared_verdict_attempt(attempt: GuidedFounderVerdictAttempt) -> ResultReviewVerdictAttempt {
    match attempt {
        GuidedFounderVerdictAttempt::Committed(result) => {
            ResultReviewVerdictAttempt::Committed(map_committed_verdict(&result))
        }
        GuidedFounderVerdictAttempt::OutcomeUnknown(recovery) => {
            ResultReviewVerdictAttempt::OutcomeUnknown(Box::new(ResultReviewVerdictRecovery {
                selection: recovery.selection(),
                sealed_command: recovery.sealed_command().clone(),
                shared: Some(recovery),
                durable: None,
                recovery_path: None,
            }))
        }
    }
}

fn map_committed_verdict(
    result: &egopulse_client_operations::GuidedFounderVerdictResult,
) -> ResultReviewCommittedVerdict {
    ResultReviewCommittedVerdict {
        founder_verdict_id: result.founder_verdict_id().to_owned(),
        decision: result.decision(),
        replayed: result.replayed(),
        projection_pending: result.await_token().is_none() || result.projection_warning().is_some(),
    }
}

fn map_applied_decision(
    result: &egopulse_client_operations::GuidedFounderDecisionResult,
) -> ResultReviewCommittedVerdict {
    ResultReviewCommittedVerdict {
        founder_verdict_id: result.verdict().founder_verdict_id().to_owned(),
        decision: result.verdict().decision(),
        replayed: result.verdict().replayed() && result.task_replayed(),
        projection_pending: result.await_token().is_none() || result.projection_warning().is_some(),
    }
}

pub trait TaskResultReviewClient: Send + Sync {
    fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a>;

    fn submit_guided_founder_verdict<'a>(
        &'a self,
        _command: VerdictCommand,
        _selection: GuidedFounderVerdictSelection,
    ) -> GuidedFounderVerdictFuture<'a> {
        Box::pin(async {
            Err(ClientGuidedFounderVerdictError::InvalidInput(
                "guided Founder Verdict is unavailable for this client",
            ))
        })
    }

    fn retry_guided_founder_verdict<'a>(
        &'a self,
        _recovery: &'a ResultReviewVerdictRecovery,
    ) -> GuidedFounderVerdictFuture<'a> {
        Box::pin(async {
            Err(ClientGuidedFounderVerdictError::InvalidInput(
                "guided Founder Verdict retry is unavailable for this client",
            ))
        })
    }

    fn collect_founder_supporting_materials<'a>(
        &'a self,
        _plan: ResultReviewMaterialPlan,
    ) -> ResultReviewMaterialFuture<'a> {
        Box::pin(async {
            Err("Founder supporting material is unavailable for this client".to_owned())
        })
    }

    fn prepare_founder_supporting_materials(
        &self,
        _review: &TaskResultReview,
        _input: ResultReviewMaterialInput,
    ) -> Result<ResultReviewMaterialPlan, String> {
        Err("Founder supporting material is unavailable for this client".to_owned())
    }

    fn build_guided_founder_verdict_with_materials(
        &self,
        _review: &TaskResultReview,
        _input: GuidedFounderVerdictInput,
        _materials: &FounderSupportingMaterialCollection,
    ) -> Result<VerdictCommand, String> {
        Err("Founder supporting material is unavailable for this client".to_owned())
    }

    fn submit_guided_founder_verdict_durable<'a>(
        &'a self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        _materials: Option<FounderSupportingMaterialCollection>,
        _recovery_path: PathBuf,
    ) -> GuidedFounderVerdictFuture<'a> {
        self.submit_guided_founder_verdict(command, selection)
    }

    fn retry_durable_founder_verdict<'a>(
        &'a self,
        _recovery: &'a DurableFounderVerdictRecovery,
        _recovery_path: PathBuf,
    ) -> DurableFounderVerdictFuture<'a> {
        Box::pin(async { Err("durable Founder Verdict recovery is unavailable".to_owned()) })
    }

    fn retry_durable_founder_verdict_from_path<'a>(
        &'a self,
        _recovery_path: PathBuf,
        _expected_task_id: String,
    ) -> DurableFounderVerdictPathFuture<'a> {
        Box::pin(async { Err("durable Founder Verdict recovery is unavailable".to_owned()) })
    }
}

impl TaskResultReviewClient for ClientAttachment {
    fn read_task_result_review<'a>(&'a self, task_id: &'a str) -> TaskResultReviewFuture<'a> {
        Box::pin(ClientAttachment::read_task_result_review(self, task_id))
    }

    fn submit_guided_founder_verdict<'a>(
        &'a self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
    ) -> GuidedFounderVerdictFuture<'a> {
        Box::pin(async move {
            ClientAttachment::submit_guided_founder_verdict(self, command, selection)
                .await
                .map(map_shared_verdict_attempt)
        })
    }

    fn retry_guided_founder_verdict<'a>(
        &'a self,
        recovery: &'a ResultReviewVerdictRecovery,
    ) -> GuidedFounderVerdictFuture<'a> {
        Box::pin(async move {
            if let Some(durable) = recovery.durable.as_ref() {
                return match ClientAttachment::retry_durable_founder_decision(self, durable)
                    .await
                    .map_err(|_| {
                        ClientGuidedFounderVerdictError::InvalidInput(
                            "durable Founder Verdict recovery could not be reconciled",
                        )
                    })? {
                    DurableFounderDecisionAttempt::Applied(result) => Ok(
                        ResultReviewVerdictAttempt::Committed(map_applied_decision(&result)),
                    ),
                    DurableFounderDecisionAttempt::Unknown { .. } => Ok(
                        ResultReviewVerdictAttempt::OutcomeUnknown(Box::new(recovery.clone())),
                    ),
                };
            }
            let shared =
                recovery
                    .shared
                    .as_deref()
                    .ok_or(ClientGuidedFounderVerdictError::InvalidInput(
                        "guided Founder Verdict recovery is not backed by a shared recovery",
                    ))?;
            ClientAttachment::retry_guided_founder_verdict(self, shared)
                .await
                .map(map_shared_verdict_attempt)
        })
    }

    fn collect_founder_supporting_materials<'a>(
        &'a self,
        plan: ResultReviewMaterialPlan,
    ) -> ResultReviewMaterialFuture<'a> {
        Box::pin(collect_founder_supporting_materials(self, plan))
    }

    fn prepare_founder_supporting_materials(
        &self,
        review: &TaskResultReview,
        input: ResultReviewMaterialInput,
    ) -> Result<ResultReviewMaterialPlan, String> {
        let session = self
            .kernel
            .session()
            .ok_or_else(|| "authenticated Founder session is unavailable".to_owned())?;
        let mut prepared = Vec::with_capacity(input.drafts.len());
        for draft in input.drafts {
            let material_id = format!("founder-material-input:{}", uuid::Uuid::now_v7());
            let builder = FounderSupportingMaterialBuilder::from_review(
                review,
                session,
                material_id,
                draft.role,
                draft.body,
                Some(draft.coverage),
            )
            .map_err(safe_material_error)?;
            let correlation_id = uuid::Uuid::now_v7().to_string();
            let prepared_material = builder
                .build(command_metadata(
                    &correlation_id,
                    "egopulse-tui/founder-supporting-material",
                ))
                .map_err(safe_material_error)?;
            prepared.push((prepared_material, new_founder_material_recovery_path()?));
        }
        Ok(ResultReviewMaterialPlan {
            task_id: review
                .task_view
                .task
                .as_ref()
                .map(|task| task.task_id.clone())
                .ok_or_else(|| "trusted result review omitted its Task".to_owned())?,
            allowed_roles: input.allowed_roles,
            recovery_paths: input.recovery_paths,
            prepared,
            confirmed: Vec::new(),
        })
    }

    fn build_guided_founder_verdict_with_materials(
        &self,
        review: &TaskResultReview,
        input: GuidedFounderVerdictInput,
        materials: &FounderSupportingMaterialCollection,
    ) -> Result<VerdictCommand, String> {
        let session = self
            .kernel
            .session()
            .ok_or_else(|| "authenticated Founder session is unavailable".to_owned())?;
        build_guided_founder_verdict_with_materials(review, input, session, materials)
            .map_err(safe_verdict_error)
    }

    fn submit_guided_founder_verdict_durable<'a>(
        &'a self,
        command: VerdictCommand,
        selection: GuidedFounderVerdictSelection,
        materials: Option<FounderSupportingMaterialCollection>,
        recovery_path: PathBuf,
    ) -> GuidedFounderVerdictFuture<'a> {
        Box::pin(async move {
            let sealed_command = command.clone();
            let attempt = ClientAttachment::submit_guided_founder_decision_durable(
                self,
                command,
                selection,
                materials.as_ref(),
                &recovery_path,
            )
            .await?;
            match attempt {
                DurableFounderDecisionAttempt::Applied(result) => Ok(
                    ResultReviewVerdictAttempt::Committed(map_applied_decision(&result)),
                ),
                DurableFounderDecisionAttempt::Unknown { .. } => {
                    let durable = DurableFounderVerdictRecovery::read(&recovery_path).ok();
                    Ok(ResultReviewVerdictAttempt::OutcomeUnknown(Box::new(
                        ResultReviewVerdictRecovery {
                            selection,
                            sealed_command,
                            shared: None,
                            durable,
                            recovery_path: Some(recovery_path),
                        },
                    )))
                }
            }
        })
    }

    fn retry_durable_founder_verdict<'a>(
        &'a self,
        recovery: &'a DurableFounderVerdictRecovery,
        recovery_path: PathBuf,
    ) -> DurableFounderVerdictFuture<'a> {
        Box::pin(async move {
            match ClientAttachment::retry_durable_founder_decision(self, recovery).await {
                Ok(DurableFounderDecisionAttempt::Applied(result)) => Ok(
                    ResultReviewDurableVerdictAttempt::Committed(map_applied_decision(&result)),
                ),
                Ok(DurableFounderDecisionAttempt::Unknown {
                    safe_reason_code, ..
                }) => Ok(ResultReviewDurableVerdictAttempt::Unknown {
                    recovery: Box::new(recovery.clone()),
                    recovery_path,
                    safe_reason_code,
                }),
                Err(error) => Ok(ResultReviewDurableVerdictAttempt::Unknown {
                    recovery: Box::new(recovery.clone()),
                    recovery_path,
                    safe_reason_code: durable_recovery_reason_code(&error),
                }),
            }
        })
    }

    fn retry_durable_founder_verdict_from_path<'a>(
        &'a self,
        recovery_path: PathBuf,
        expected_task_id: String,
    ) -> DurableFounderVerdictPathFuture<'a> {
        Box::pin(async move {
            let recovery = DurableFounderVerdictRecovery::read(&recovery_path)
                .map_err(safe_durable_recovery_error)?;
            if recovery.task_id() != expected_task_id {
                return Err("saved Founder Verdict belongs to a different Task".to_owned());
            }
            match ClientAttachment::retry_durable_founder_decision(self, &recovery).await {
                Ok(DurableFounderDecisionAttempt::Applied(result)) => Ok(
                    ResultReviewDurablePathAttempt::Committed(map_applied_decision(&result)),
                ),
                Ok(DurableFounderDecisionAttempt::Unknown {
                    safe_reason_code, ..
                }) => Ok(ResultReviewDurablePathAttempt::Unknown { safe_reason_code }),
                Err(error) => Ok(ResultReviewDurablePathAttempt::Unknown {
                    safe_reason_code: durable_recovery_reason_code(&error),
                }),
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultReviewVerdictStage {
    Viewing,
    Drafting,
    CollectingMaterials,
    MaterialOutcomeUnknown,
    Confirming,
    Submitting,
    RecoveryInput,
    OutcomeUnknown,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultReviewVerdictField {
    Reason,
    Proof,
    MaterialBody,
    CompensatingControl,
    RiskCategory,
    Discrepancies,
    UnverifiedItems,
    MaterialRecoveryPaths,
    VerdictRecoveryPath,
}

#[derive(Clone)]
struct VerdictDraft {
    selection: GuidedFounderVerdictSelection,
    reason_code: String,
    confirmation_proof_ref: String,
    material_body: String,
    compensating_control: String,
    risk_category: String,
    discrepancy_ids: String,
    unverified_item_ids: String,
    material_recovery_paths: String,
    active_field: ResultReviewVerdictField,
}

struct PendingVerdict {
    selection: GuidedFounderVerdictSelection,
    command: VerdictCommand,
    materials: Option<FounderSupportingMaterialCollection>,
    recovery_path: PathBuf,
}

struct MaterialRecoveryState {
    draft: VerdictDraft,
    retry_plan: ResultReviewMaterialPlan,
    recovery_path: PathBuf,
    safe_reason_code: &'static str,
}

struct VerdictRecoveryInput {
    path: String,
    outcome_unknown: bool,
    preserved_path: Option<PathBuf>,
}

struct CommittedVerdict {
    founder_verdict_id: String,
    decision: FounderVerdictDecision,
    replayed: bool,
    projection_pending: bool,
}

enum VerdictState {
    Viewing,
    Drafting(VerdictDraft),
    CollectingMaterials,
    MaterialOutcomeUnknown(Box<MaterialRecoveryState>),
    Confirming(Box<PendingVerdict>),
    Submitting,
    RecoveryInput(VerdictRecoveryInput),
    OutcomeUnknown(Box<ResultReviewVerdictRecovery>),
    DurableOutcomeUnknown(Box<DurableVerdictRecoveryState>),
    Committed(CommittedVerdict),
}

impl VerdictState {
    const fn stage(&self) -> ResultReviewVerdictStage {
        match self {
            Self::Viewing => ResultReviewVerdictStage::Viewing,
            Self::Drafting(_) => ResultReviewVerdictStage::Drafting,
            Self::CollectingMaterials => ResultReviewVerdictStage::CollectingMaterials,
            Self::MaterialOutcomeUnknown(_) => ResultReviewVerdictStage::MaterialOutcomeUnknown,
            Self::Confirming(_) => ResultReviewVerdictStage::Confirming,
            Self::Submitting => ResultReviewVerdictStage::Submitting,
            Self::RecoveryInput(_) => ResultReviewVerdictStage::RecoveryInput,
            Self::OutcomeUnknown(_) => ResultReviewVerdictStage::OutcomeUnknown,
            Self::DurableOutcomeUnknown(_) => ResultReviewVerdictStage::OutcomeUnknown,
            Self::Committed(_) => ResultReviewVerdictStage::Committed,
        }
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
    fn from_review(review: &TaskResultReview) -> Result<Self, String> {
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

enum ResultReviewWorkerEvent {
    Loaded {
        generation: u64,
        review: Box<TaskResultReview>,
        model: Box<ResultReviewPageModel>,
    },
    VerdictSettled {
        generation: u64,
        result: Result<ResultReviewVerdictAttempt, ClientGuidedFounderVerdictError>,
        retry_recovery: Option<Box<ResultReviewVerdictRecovery>>,
        recovery_path: Option<PathBuf>,
    },
    MaterialSettled {
        generation: u64,
        draft: Box<VerdictDraft>,
        result: Result<ResultReviewMaterialAttempt, String>,
    },
    DurableVerdictSettled {
        generation: u64,
        result: Result<ResultReviewDurableVerdictAttempt, String>,
        retry_recovery: Box<DurableVerdictRecoveryState>,
    },
    DurablePathVerdictSettled {
        generation: u64,
        result: Result<ResultReviewDurablePathAttempt, String>,
        recovery_path: PathBuf,
    },
    Failed {
        generation: u64,
        detail: String,
    },
}

impl ResultReviewWorkerEvent {
    fn generation(&self) -> u64 {
        match self {
            Self::Loaded { generation, .. }
            | Self::VerdictSettled { generation, .. }
            | Self::MaterialSettled { generation, .. }
            | Self::DurableVerdictSettled { generation, .. }
            | Self::DurablePathVerdictSettled { generation, .. }
            | Self::Failed { generation, .. } => *generation,
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
    trusted_review: Option<TaskResultReview>,
    verdict_state: VerdictState,
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
            trusted_review: None,
            verdict_state: VerdictState::Viewing,
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

    /// Returns only the scope carried by the validated Task snapshot, never a
    /// value reconstructed from rendered review or Artifact text.
    #[must_use]
    pub fn trusted_task_target_scope_ref(&self) -> Option<&str> {
        self.trusted_review
            .as_ref()
            .and_then(|review| review.task_view.task.as_ref())
            .map(|task| task.target_scope_ref.as_str())
            .filter(|scope| !scope.trim().is_empty())
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    #[must_use]
    pub fn has_unsettled_sent_verdict(&self) -> bool {
        match &self.verdict_state {
            VerdictState::CollectingMaterials
            | VerdictState::MaterialOutcomeUnknown(_)
            | VerdictState::Submitting
            | VerdictState::OutcomeUnknown(_)
            | VerdictState::DurableOutcomeUnknown(_) => true,
            VerdictState::RecoveryInput(recovery) => recovery.outcome_unknown,
            _ => false,
        }
    }

    #[must_use]
    pub const fn verdict_stage(&self) -> ResultReviewVerdictStage {
        self.verdict_state.stage()
    }

    #[must_use]
    pub fn verdict_selection(&self) -> Option<GuidedFounderVerdictSelection> {
        match &self.verdict_state {
            VerdictState::Drafting(draft) => Some(draft.selection),
            VerdictState::Confirming(pending) => Some(pending.selection),
            VerdictState::MaterialOutcomeUnknown(state) => Some(state.draft.selection),
            VerdictState::OutcomeUnknown(recovery) => Some(recovery.selection()),
            VerdictState::DurableOutcomeUnknown(recovery) => Some(recovery.selection),
            VerdictState::Viewing
            | VerdictState::CollectingMaterials
            | VerdictState::Submitting
            | VerdictState::RecoveryInput(_)
            | VerdictState::Committed(_) => None,
        }
    }

    #[must_use]
    pub fn verdict_active_field(&self) -> Option<ResultReviewVerdictField> {
        match &self.verdict_state {
            VerdictState::Drafting(draft) => Some(draft.active_field),
            VerdictState::RecoveryInput(_) => Some(ResultReviewVerdictField::VerdictRecoveryPath),
            _ => None,
        }
    }

    #[must_use]
    pub fn verdict_reason(&self) -> Option<&str> {
        match &self.verdict_state {
            VerdictState::Drafting(draft) => Some(&draft.reason_code),
            _ => None,
        }
    }

    #[must_use]
    pub fn verdict_proof_mask(&self) -> Option<String> {
        match &self.verdict_state {
            VerdictState::Drafting(draft) => {
                Some("*".repeat(draft.confirmation_proof_ref.chars().count()))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn verdict_draft_lines(&self) -> Option<Vec<String>> {
        match &self.verdict_state {
            VerdictState::Drafting(draft) => {
                Some(verdict_draft_lines(draft, self.trusted_review.as_ref()))
            }
            VerdictState::RecoveryInput(recovery) => Some(vec![format!(
                "> Recovery path: {}",
                if recovery.path.is_empty() {
                    "<empty>"
                } else {
                    &recovery.path
                }
            )]),
            _ => None,
        }
    }

    #[must_use]
    pub fn recovery_summary(&self) -> Option<Vec<String>> {
        match &self.verdict_state {
            VerdictState::MaterialOutcomeUnknown(state) => Some(vec![
                "Supporting-material outcome is unknown; Verdict was not sent.".to_owned(),
                format!("Reason: {}", state.safe_reason_code),
                format!("Recovery: {}", state.recovery_path.display()),
                "Press Enter to retry the exact saved material operation.".to_owned(),
            ]),
            VerdictState::OutcomeUnknown(recovery) => Some(vec![
                "The Authority commit outcome is unknown.".to_owned(),
                recovery.recovery_path().map_or_else(
                    || "Recovery remains in this session.".to_owned(),
                    |path| format!("Recovery: {}", path.display()),
                ),
                "Press Enter to retry the exact same sealed command.".to_owned(),
            ]),
            VerdictState::DurableOutcomeUnknown(state) => Some(vec![
                "The saved Founder Verdict outcome remains unknown.".to_owned(),
                format!("Reason: {}", state.safe_reason_code),
                format!("Recovery: {}", state.recovery_path.display()),
                "Press Enter to retry the exact saved command.".to_owned(),
            ]),
            VerdictState::RecoveryInput(state) if state.outcome_unknown => Some(vec![
                "The Founder Verdict Issue committed, but Task application is unresolved."
                    .to_owned(),
                format!("Recovery: {}", state.path),
                "Press Enter to reload and retry the exact saved decision.".to_owned(),
            ]),
            _ => None,
        }
    }

    #[must_use]
    pub fn confirmation_summary(&self) -> Option<Vec<String>> {
        let VerdictState::Confirming(pending) = &self.verdict_state else {
            return None;
        };
        let review = self.trusted_review.as_ref()?;
        let task = review.task_view.task.as_ref()?;
        let artifact_set = review.task_view.artifact_set.as_ref()?;
        let verification = review.task_view.verification.as_ref()?;
        Some(vec![
            format!("Task: {} revision={}", task.task_id, task.revision),
            format!(
                "Verification: {} conclusion={}",
                verification.verification_artifact_id,
                enum_name::<VerificationConclusion>(verification.conclusion)
            ),
            format!(
                "ArtifactSet: {} artifacts={}",
                artifact_set.artifact_set_id,
                artifact_set.artifact_ids.len()
            ),
            format!("Decision: {:?}", pending.selection),
            "This commits a Founder Verdict; it does not complete the Task projection.".to_owned(),
        ])
    }

    #[must_use]
    pub fn committed_summary(&self) -> Option<String> {
        let VerdictState::Committed(committed) = &self.verdict_state else {
            return None;
        };
        Some(format!(
            "Founder Verdict committed: id={} decision={:?} replayed={}; {}",
            committed.founder_verdict_id,
            committed.decision,
            committed.replayed,
            if committed.projection_pending {
                "projection await is unavailable or pending; check the projection separately"
            } else {
                "projection await token is available; projection completion remains separate"
            }
        ))
    }

    pub fn begin_verdict(
        &mut self,
        selection: GuidedFounderVerdictSelection,
    ) -> Result<(), String> {
        if !matches!(self.verdict_state, VerdictState::Viewing) {
            return Err("Finish or cancel the current Founder Verdict action first".to_owned());
        }
        let review = self
            .trusted_review
            .as_ref()
            .ok_or_else(|| "A complete trusted result review is required".to_owned())?;
        let _ = review
            .task_view
            .verification
            .as_ref()
            .and_then(|verification| VerificationConclusion::try_from(verification.conclusion).ok())
            .filter(|conclusion| *conclusion != VerificationConclusion::Unspecified)
            .ok_or_else(|| "A recognized Verification conclusion is required".to_owned())?;
        self.verdict_state = VerdictState::Drafting(VerdictDraft {
            selection,
            reason_code: String::new(),
            confirmation_proof_ref: String::new(),
            material_body: String::new(),
            compensating_control: String::new(),
            risk_category: String::new(),
            discrepancy_ids: String::new(),
            unverified_item_ids: String::new(),
            material_recovery_paths: String::new(),
            active_field: ResultReviewVerdictField::Reason,
        });
        self.set_message("Enter explicit Founder inputs; Tab changes field");
        Ok(())
    }

    pub fn begin_verdict_recovery(&mut self) -> Result<(), String> {
        if !matches!(self.verdict_state, VerdictState::Viewing) {
            return Err("Finish or cancel the current Founder Verdict action first".to_owned());
        }
        self.verdict_state = VerdictState::RecoveryInput(VerdictRecoveryInput {
            path: String::new(),
            outcome_unknown: false,
            preserved_path: None,
        });
        self.set_message("Enter the existing client-private Founder Verdict recovery path");
        Ok(())
    }

    pub fn toggle_verdict_field(&mut self) {
        if let VerdictState::Drafting(draft) = &mut self.verdict_state {
            let fields = verdict_draft_fields(draft.selection, self.trusted_review.as_ref());
            let index = fields
                .iter()
                .position(|field| *field == draft.active_field)
                .unwrap_or_default();
            draft.active_field = fields[(index + 1) % fields.len()];
        }
    }

    pub fn push_verdict_character(&mut self, character: char) {
        if let VerdictState::Drafting(draft) = &mut self.verdict_state {
            verdict_draft_value_mut(draft).push(character);
        } else if let VerdictState::RecoveryInput(recovery) = &mut self.verdict_state
            && !recovery.outcome_unknown
            && recovery.preserved_path.is_none()
        {
            recovery.path.push(character);
        }
    }

    pub fn pop_verdict_character(&mut self) {
        if let VerdictState::Drafting(draft) = &mut self.verdict_state {
            verdict_draft_value_mut(draft).pop();
        } else if let VerdictState::RecoveryInput(recovery) = &mut self.verdict_state
            && !recovery.outcome_unknown
            && recovery.preserved_path.is_none()
        {
            recovery.path.pop();
        }
    }

    pub fn prepare_verdict_confirmation(&mut self) -> Result<(), String> {
        let VerdictState::Drafting(draft) = &self.verdict_state else {
            return Err("Founder Verdict draft is unavailable".to_owned());
        };
        let draft = draft.clone();
        let review = self
            .trusted_review
            .as_ref()
            .ok_or_else(|| "Trusted result review is unavailable".to_owned())?;
        let input = material_input_for_draft(&draft, review)?;
        if input.drafts.is_empty() && input.recovery_paths.is_empty() {
            return self.finalize_verdict_confirmation(draft, None);
        }
        let plan = self
            .client
            .prepare_founder_supporting_materials(review, input)?;
        self.spawn_material_collection(draft, plan);
        self.set_message(
            "Saving and submitting Founder supporting materials before the Verdict...",
        );
        Ok(())
    }

    pub fn cancel_unsent_verdict(&mut self) -> bool {
        let cancellable = match &self.verdict_state {
            VerdictState::Drafting(_) | VerdictState::Confirming(_) => true,
            VerdictState::RecoveryInput(recovery) => !recovery.outcome_unknown,
            _ => false,
        };
        if cancellable {
            self.verdict_state = VerdictState::Viewing;
            self.set_message("Founder Verdict draft cancelled with zero sends");
            true
        } else {
            false
        }
    }

    pub fn submit_verdict(&mut self) -> Result<(), String> {
        let state = std::mem::replace(&mut self.verdict_state, VerdictState::Submitting);
        let VerdictState::Confirming(pending) = state else {
            self.verdict_state = state;
            return Err("Confirmed Founder Verdict is unavailable".to_owned());
        };
        self.spawn_verdict_submission(*pending, None);
        self.set_message("Submitting the exact sealed Founder Verdict command...");
        Ok(())
    }

    pub fn retry_verdict(&mut self) -> Result<(), String> {
        let state = std::mem::replace(&mut self.verdict_state, VerdictState::Submitting);
        match state {
            VerdictState::OutcomeUnknown(recovery) => {
                let retry_recovery = recovery.clone();
                self.spawn_verdict_retry(recovery, retry_recovery);
            }
            VerdictState::DurableOutcomeUnknown(recovery) => {
                self.spawn_durable_verdict_retry(*recovery);
            }
            VerdictState::RecoveryInput(recovery) if recovery.outcome_unknown => {
                let Some(recovery_path) = recovery.preserved_path.clone() else {
                    self.verdict_state = VerdictState::RecoveryInput(recovery);
                    return Err("Founder Verdict recovery path binding is unavailable".to_owned());
                };
                self.spawn_durable_verdict_path_retry(recovery_path);
            }
            state => {
                self.verdict_state = state;
                return Err("Founder Verdict recovery is unavailable".to_owned());
            }
        }
        self.set_message("Retrying only the exact previously sealed Founder Verdict command...");
        Ok(())
    }

    pub fn retry_material(&mut self) -> Result<(), String> {
        let state = std::mem::replace(&mut self.verdict_state, VerdictState::CollectingMaterials);
        let VerdictState::MaterialOutcomeUnknown(state) = state else {
            self.verdict_state = state;
            return Err("Founder supporting-material recovery is unavailable".to_owned());
        };
        self.spawn_material_collection(state.draft, state.retry_plan);
        self.set_message("Retrying only the exact saved supporting-material operation...");
        Ok(())
    }

    pub fn recover_verdict_from_input(&mut self) -> Result<(), String> {
        let state = std::mem::replace(&mut self.verdict_state, VerdictState::Submitting);
        let VerdictState::RecoveryInput(input) = state else {
            self.verdict_state = state;
            return Err("Founder Verdict recovery input is unavailable".to_owned());
        };
        let path = match existing_private_recovery_path(Path::new(input.path.trim())) {
            Ok(path) => path,
            Err(error) => {
                self.verdict_state = VerdictState::RecoveryInput(input);
                return Err(error);
            }
        };
        self.spawn_durable_verdict_path_retry(path);
        self.set_message("Recovering only the exact saved Founder Verdict command...");
        Ok(())
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.task_id.trim().is_empty() {
            return Err("Result review requires a selected Task".to_owned());
        }
        self.refresh().await
    }

    pub async fn refresh(&mut self) -> Result<(), String> {
        if self.has_unsettled_sent_verdict() {
            return Err(
                "Result review cannot refresh while a sent Founder Verdict remains unsettled"
                    .to_owned(),
            );
        }
        self.stop().await;
        self.verdict_state = VerdictState::Viewing;
        self.trusted_review = None;
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
                Ok(review) => match ResultReviewPageModel::from_review(&review) {
                    Ok(model) => ResultReviewWorkerEvent::Loaded {
                        generation,
                        review: Box::new(review),
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
                ResultReviewWorkerEvent::Loaded { review, model, .. } => {
                    self.trusted_review = Some(*review);
                    self.model = Some(*model);
                }
                ResultReviewWorkerEvent::VerdictSettled {
                    result,
                    retry_recovery,
                    recovery_path,
                    ..
                } => self.apply_verdict_result(result, retry_recovery, recovery_path),
                ResultReviewWorkerEvent::MaterialSettled { draft, result, .. } => {
                    self.apply_material_result(*draft, result)?;
                }
                ResultReviewWorkerEvent::DurableVerdictSettled {
                    result,
                    retry_recovery,
                    ..
                } => {
                    self.apply_durable_verdict_result(result, retry_recovery);
                }
                ResultReviewWorkerEvent::DurablePathVerdictSettled {
                    result,
                    recovery_path,
                    ..
                } => self.apply_durable_path_verdict_result(result, recovery_path),
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

    fn spawn_verdict_submission(
        &mut self,
        pending: PendingVerdict,
        retry_recovery: Option<Box<ResultReviewVerdictRecovery>>,
    ) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let client = Arc::clone(&self.client);
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let recovery_path = pending.recovery_path.clone();
        let worker = tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.submit_guided_founder_verdict_durable(
                    pending.command,
                    pending.selection,
                    pending.materials,
                    pending.recovery_path,
                ) => result,
            };
            let event = ResultReviewWorkerEvent::VerdictSettled {
                generation,
                result,
                retry_recovery,
                recovery_path: Some(recovery_path),
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    fn spawn_material_collection(&mut self, draft: VerdictDraft, plan: ResultReviewMaterialPlan) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let client = Arc::clone(&self.client);
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.collect_founder_supporting_materials(plan) => result,
            };
            let event = ResultReviewWorkerEvent::MaterialSettled {
                generation,
                draft: Box::new(draft),
                result,
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    fn spawn_durable_verdict_retry(&mut self, state: DurableVerdictRecoveryState) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let client = Arc::clone(&self.client);
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let retry_recovery = Box::new(state.clone());
        let worker = tokio::spawn(async move {
            let DurableVerdictRecoveryState {
                recovery,
                recovery_path,
                ..
            } = state;
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.retry_durable_founder_verdict(&recovery, recovery_path) => result,
            };
            let event = ResultReviewWorkerEvent::DurableVerdictSettled {
                generation,
                result,
                retry_recovery,
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    fn spawn_durable_verdict_path_retry(&mut self, recovery_path: PathBuf) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let client = Arc::clone(&self.client);
        let expected_task_id = self.task_id.clone();
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let retry_path = recovery_path.clone();
        let worker = tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.retry_durable_founder_verdict_from_path(
                    retry_path,
                    expected_task_id,
                ) => result,
            };
            let event = ResultReviewWorkerEvent::DurablePathVerdictSettled {
                generation,
                result,
                recovery_path,
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    fn spawn_verdict_retry(
        &mut self,
        recovery: Box<ResultReviewVerdictRecovery>,
        retry_recovery: Box<ResultReviewVerdictRecovery>,
    ) {
        self.generation = self.generation.wrapping_add(1).max(1);
        let generation = self.generation;
        let client = Arc::clone(&self.client);
        let (sender, events) = mpsc::channel(RESULT_REVIEW_CHANNEL_CAPACITY);
        let (cancel, mut cancellation) = watch::channel(false);
        let worker = tokio::spawn(async move {
            let result = tokio::select! {
                _ = cancellation.changed() => return,
                result = client.retry_guided_founder_verdict(&recovery) => result,
            };
            let event = ResultReviewWorkerEvent::VerdictSettled {
                generation,
                result,
                retry_recovery: Some(retry_recovery),
                recovery_path: None,
            };
            let _ = send_result_review_event(&sender, &mut cancellation, event, None).await;
        });
        self.runtime = Some(ResultReviewRuntime {
            events,
            cancel,
            worker: Some(worker),
        });
    }

    fn apply_verdict_result(
        &mut self,
        result: Result<ResultReviewVerdictAttempt, ClientGuidedFounderVerdictError>,
        retry_recovery: Option<Box<ResultReviewVerdictRecovery>>,
        recovery_path: Option<PathBuf>,
    ) {
        match result {
            Ok(ResultReviewVerdictAttempt::Committed(result)) => {
                self.set_committed(result);
            }
            Ok(ResultReviewVerdictAttempt::OutcomeUnknown(recovery)) => {
                if recovery.durable.is_none()
                    && let Some(path) = recovery.recovery_path.clone()
                {
                    self.set_durable_recovery_input(
                        path,
                        "Founder Verdict outcome is unknown; reload the preserved recovery record before exact retry",
                    );
                } else {
                    self.verdict_state = VerdictState::OutcomeUnknown(recovery);
                    self.set_message(
                        "Founder Verdict outcome is unknown; Enter exact-retries the same command, Esc/refresh cannot discard recovery",
                    );
                }
            }
            Err(
                ClientGuidedFounderVerdictError::ApplyRecoveryStorage
                | ClientGuidedFounderVerdictError::TaskAuthority { .. },
            ) if retry_recovery.is_none() && recovery_path.is_some() => {
                self.set_durable_recovery_input(
                    recovery_path.expect("guarded recovery path"),
                    "Founder Verdict was issued, but Task application was not confirmed; reload the preserved recovery record to retry explicitly",
                );
            }
            Err(error) => {
                if let Some(recovery) = retry_recovery {
                    self.verdict_state = VerdictState::OutcomeUnknown(recovery);
                    self.set_message(format!(
                        "Founder Verdict remains outcome-unknown after retry: {}",
                        safe_verdict_error(error)
                    ));
                } else {
                    self.verdict_state = VerdictState::Viewing;
                    self.set_message(format!(
                        "Founder Verdict was not committed: {}",
                        safe_verdict_error(error)
                    ));
                }
            }
        }
    }

    fn set_durable_recovery_input(&mut self, recovery_path: PathBuf, message: &str) {
        self.verdict_state = VerdictState::RecoveryInput(VerdictRecoveryInput {
            path: recovery_path.display().to_string(),
            outcome_unknown: true,
            preserved_path: Some(recovery_path.clone()),
        });
        self.set_message(format!("{message}; recovery={}", recovery_path.display()));
    }

    fn apply_material_result(
        &mut self,
        draft: VerdictDraft,
        result: Result<ResultReviewMaterialAttempt, String>,
    ) -> Result<(), String> {
        match result {
            Ok(ResultReviewMaterialAttempt::Confirmed(materials)) => {
                self.finalize_verdict_confirmation(draft, Some(materials))
            }
            Ok(ResultReviewMaterialAttempt::Unknown {
                retry_plan,
                recovery_path,
                safe_reason_code,
            }) => {
                self.verdict_state =
                    VerdictState::MaterialOutcomeUnknown(Box::new(MaterialRecoveryState {
                        draft,
                        retry_plan,
                        recovery_path: recovery_path.clone(),
                        safe_reason_code,
                    }));
                self.set_message(format!(
                    "Supporting-material outcome is unknown; Verdict was not sent; recovery={}",
                    recovery_path.display()
                ));
                Ok(())
            }
            Err(detail) => {
                self.verdict_state = VerdictState::Viewing;
                self.set_message(format!(
                    "Supporting material was not confirmed; Verdict was not sent: {detail}"
                ));
                Ok(())
            }
        }
    }

    fn apply_durable_verdict_result(
        &mut self,
        result: Result<ResultReviewDurableVerdictAttempt, String>,
        retry_recovery: Box<DurableVerdictRecoveryState>,
    ) {
        match result {
            Ok(ResultReviewDurableVerdictAttempt::Committed(result)) => self.set_committed(result),
            Ok(ResultReviewDurableVerdictAttempt::Unknown {
                recovery,
                recovery_path,
                safe_reason_code,
            }) => {
                let selection = recovery.selection();
                self.verdict_state =
                    VerdictState::DurableOutcomeUnknown(Box::new(DurableVerdictRecoveryState {
                        recovery: *recovery,
                        recovery_path: recovery_path.clone(),
                        selection,
                        safe_reason_code,
                    }));
                self.set_message(format!(
                    "Founder Verdict outcome remains unknown; recovery={}",
                    recovery_path.display()
                ));
            }
            Err(detail) => {
                self.verdict_state = VerdictState::DurableOutcomeUnknown(retry_recovery);
                self.set_message(format!(
                    "Founder Verdict remains outcome-unknown; the original recovery record is retained: {detail}"
                ));
            }
        }
    }

    fn apply_durable_path_verdict_result(
        &mut self,
        result: Result<ResultReviewDurablePathAttempt, String>,
        recovery_path: PathBuf,
    ) {
        match result {
            Ok(ResultReviewDurablePathAttempt::Committed(result)) => self.set_committed(result),
            Ok(ResultReviewDurablePathAttempt::Unknown { safe_reason_code }) => {
                self.set_durable_recovery_input(
                    recovery_path,
                    &format!(
                        "Founder Verdict outcome remains unknown ({safe_reason_code}); retry only the original recovery record"
                    ),
                );
            }
            Err(detail) => {
                self.set_durable_recovery_input(
                    recovery_path,
                    &format!(
                        "Founder Verdict recovery could not be read or reconciled; the original path is retained: {detail}"
                    ),
                );
            }
        }
    }

    fn finalize_verdict_confirmation(
        &mut self,
        draft: VerdictDraft,
        materials: Option<FounderSupportingMaterialCollection>,
    ) -> Result<(), String> {
        let review = self
            .trusted_review
            .as_ref()
            .ok_or_else(|| "Trusted result review is unavailable".to_owned())?;
        let correlation_id = uuid::Uuid::now_v7().to_string();
        let input = GuidedFounderVerdictInput {
            current_task_id: self.task_id.clone(),
            metadata: command_metadata(&correlation_id, "egopulse-tui/result-review-decide"),
            selection: draft.selection,
            reason_code: draft.reason_code,
            confirmation_proof_ref: draft.confirmation_proof_ref,
            expires_at: timestamp_after(RESULT_REVIEW_VERDICT_EXPIRY),
        };
        let command = match materials.as_ref() {
            Some(materials) => self
                .client
                .build_guided_founder_verdict_with_materials(review, input, materials)?,
            None => build_guided_founder_verdict(review, input).map_err(safe_verdict_error)?,
        };
        let recovery_path = new_founder_verdict_recovery_path()?;
        self.verdict_state = VerdictState::Confirming(Box::new(PendingVerdict {
            selection: draft.selection,
            command,
            materials,
            recovery_path,
        }));
        self.set_message("Review the exact trusted binding, then press Enter to submit");
        Ok(())
    }

    fn set_committed(&mut self, result: ResultReviewCommittedVerdict) {
        self.verdict_state = VerdictState::Committed(CommittedVerdict {
            founder_verdict_id: result.founder_verdict_id,
            decision: result.decision,
            replayed: result.replayed,
            projection_pending: result.projection_pending,
        });
        let message = self
            .committed_summary()
            .expect("committed verdict summary is available");
        self.set_message(message);
    }

    fn set_message(&mut self, message: impl Into<String>) {
        if let Some(model) = &mut self.model {
            model.message = message.into();
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

async fn collect_founder_supporting_materials(
    client: &ClientAttachment,
    mut plan: ResultReviewMaterialPlan,
) -> Result<ResultReviewMaterialAttempt, String> {
    while !plan.recovery_paths.is_empty() {
        let recovery_path = plan.recovery_paths.remove(0);
        let recovery = match DurableFounderMaterialRecovery::read(&recovery_path) {
            Ok(recovery) => recovery,
            Err(error) => {
                plan.recovery_paths.insert(0, recovery_path.clone());
                return Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path,
                    safe_reason_code: durable_recovery_reason_code(&error),
                });
            }
        };
        if recovery.task_id() != plan.task_id || !plan.allowed_roles.contains(&recovery.role()) {
            return Err(
                "saved supporting material does not belong to this Task and decision".to_owned(),
            );
        }
        match client.retry_durable_founder_material(&recovery).await {
            Ok(DurableFounderMaterialAttempt::Confirmed(receipt)) => {
                plan.confirmed.push(*receipt);
            }
            Ok(DurableFounderMaterialAttempt::Unknown { safe_reason_code }) => {
                plan.recovery_paths.insert(0, recovery_path.clone());
                return Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path,
                    safe_reason_code,
                });
            }
            Err(error) => {
                plan.recovery_paths.insert(0, recovery_path.clone());
                return Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path,
                    safe_reason_code: durable_recovery_reason_code(&error),
                });
            }
        }
    }

    while !plan.prepared.is_empty() {
        let (prepared, recovery_path) = plan.prepared.remove(0);
        match client
            .create_founder_supporting_material_durable(prepared.clone(), &recovery_path)
            .await
        {
            Ok(receipt) => plan.confirmed.push(receipt),
            Err(ClientFounderSupportingMaterialError::RecoveryStorage) => {
                plan.prepared.insert(0, (prepared, recovery_path.clone()));
                return Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path,
                    safe_reason_code: "RECOVERY_STORAGE_FAILED_NO_REQUEST_SENT",
                });
            }
            Err(ClientFounderSupportingMaterialError::Unknown { .. }) => {
                plan.recovery_paths.insert(0, recovery_path.clone());
                return Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path,
                    safe_reason_code: "SUPPORTING_MATERIAL_OUTCOME_UNKNOWN",
                });
            }
            Err(error) => return Err(safe_material_error(error)),
        }
    }

    FounderSupportingMaterialCollection::from_confirmed(plan.confirmed)
        .map(ResultReviewMaterialAttempt::Confirmed)
        .map_err(safe_verdict_error)
}

fn material_input_for_draft(
    draft: &VerdictDraft,
    review: &TaskResultReview,
) -> Result<ResultReviewMaterialInput, String> {
    let conclusion = review
        .task_view
        .verification
        .as_ref()
        .and_then(|verification| VerificationConclusion::try_from(verification.conclusion).ok())
        .filter(|conclusion| *conclusion != VerificationConclusion::Unspecified)
        .ok_or_else(|| "A recognized Verification conclusion is required".to_owned())?;
    let recovery_paths = parse_recovery_paths(&draft.material_recovery_paths)?;
    let discrepancy_ids = parse_identifier_list(&draft.discrepancy_ids, "discrepancy")?;
    let unverified_item_ids = parse_identifier_list(&draft.unverified_item_ids, "unverified item")?;
    let covered = !discrepancy_ids.is_empty() || !unverified_item_ids.is_empty();
    let mut drafts = Vec::new();
    let allowed_roles = match draft.selection {
        GuidedFounderVerdictSelection::Rework => {
            vec![FounderSupportingMaterialRole::ReworkRequiredChanges]
        }
        GuidedFounderVerdictSelection::Accept if conclusion != VerificationConclusion::Passed => {
            vec![
                FounderSupportingMaterialRole::RiskRationale,
                FounderSupportingMaterialRole::CompensatingControl,
            ]
        }
        GuidedFounderVerdictSelection::Accept | GuidedFounderVerdictSelection::Reject => Vec::new(),
    };

    match draft.selection {
        GuidedFounderVerdictSelection::Rework => {
            if !draft.material_body.trim().is_empty() {
                drafts.push(ResultReviewMaterialDraft {
                    role: FounderSupportingMaterialRole::ReworkRequiredChanges,
                    body: draft.material_body.trim().to_owned(),
                    coverage: FounderSupportingMaterialCoverage {
                        discrepancy_ids,
                        unverified_item_ids,
                        risk_category: RiskCategory::Unspecified as i32,
                    },
                });
            } else if recovery_paths.is_empty() {
                return Err(
                    "Rework requires explicit required changes or an existing material recovery path"
                        .to_owned(),
                );
            }
        }
        GuidedFounderVerdictSelection::Accept if conclusion != VerificationConclusion::Passed => {
            if !draft.material_body.trim().is_empty()
                || !draft.compensating_control.trim().is_empty()
            {
                if draft.material_body.trim().is_empty()
                    || draft.compensating_control.trim().is_empty()
                    || !covered
                {
                    return Err("non-Passed Accept requires explicit risk rationale, compensating control, and discrepancy or unverified coverage".to_owned());
                }
                let risk_category = parse_risk_category(&draft.risk_category)? as i32;
                let coverage = FounderSupportingMaterialCoverage {
                    discrepancy_ids,
                    unverified_item_ids,
                    risk_category,
                };
                drafts.push(ResultReviewMaterialDraft {
                    role: FounderSupportingMaterialRole::RiskRationale,
                    body: draft.material_body.trim().to_owned(),
                    coverage: coverage.clone(),
                });
                drafts.push(ResultReviewMaterialDraft {
                    role: FounderSupportingMaterialRole::CompensatingControl,
                    body: draft.compensating_control.trim().to_owned(),
                    coverage,
                });
            } else if recovery_paths.is_empty() {
                return Err("non-Passed Accept requires confirmed risk rationale and compensating-control materials".to_owned());
            }
        }
        GuidedFounderVerdictSelection::Accept | GuidedFounderVerdictSelection::Reject => {
            if !draft.material_body.trim().is_empty()
                || !draft.compensating_control.trim().is_empty()
                || covered
                || !recovery_paths.is_empty()
            {
                return Err("supporting materials are not accepted for this decision and Verification conclusion".to_owned());
            }
        }
    }
    Ok(ResultReviewMaterialInput {
        drafts,
        recovery_paths,
        allowed_roles,
    })
}

fn verdict_draft_fields(
    selection: GuidedFounderVerdictSelection,
    review: Option<&TaskResultReview>,
) -> Vec<ResultReviewVerdictField> {
    let conclusion = review
        .and_then(|review| review.task_view.verification.as_ref())
        .and_then(|verification| VerificationConclusion::try_from(verification.conclusion).ok());
    let mut fields = vec![
        ResultReviewVerdictField::Reason,
        ResultReviewVerdictField::Proof,
    ];
    match selection {
        GuidedFounderVerdictSelection::Rework => fields.extend([
            ResultReviewVerdictField::MaterialBody,
            ResultReviewVerdictField::Discrepancies,
            ResultReviewVerdictField::UnverifiedItems,
            ResultReviewVerdictField::MaterialRecoveryPaths,
        ]),
        GuidedFounderVerdictSelection::Accept
            if conclusion.is_some_and(|value| value != VerificationConclusion::Passed) =>
        {
            fields.extend([
                ResultReviewVerdictField::MaterialBody,
                ResultReviewVerdictField::CompensatingControl,
                ResultReviewVerdictField::RiskCategory,
                ResultReviewVerdictField::Discrepancies,
                ResultReviewVerdictField::UnverifiedItems,
                ResultReviewVerdictField::MaterialRecoveryPaths,
            ]);
        }
        _ => {}
    }
    fields
}

fn verdict_draft_value_mut(draft: &mut VerdictDraft) -> &mut String {
    match draft.active_field {
        ResultReviewVerdictField::Reason => &mut draft.reason_code,
        ResultReviewVerdictField::Proof => &mut draft.confirmation_proof_ref,
        ResultReviewVerdictField::MaterialBody => &mut draft.material_body,
        ResultReviewVerdictField::CompensatingControl => &mut draft.compensating_control,
        ResultReviewVerdictField::RiskCategory => &mut draft.risk_category,
        ResultReviewVerdictField::Discrepancies => &mut draft.discrepancy_ids,
        ResultReviewVerdictField::UnverifiedItems => &mut draft.unverified_item_ids,
        ResultReviewVerdictField::MaterialRecoveryPaths => &mut draft.material_recovery_paths,
        ResultReviewVerdictField::VerdictRecoveryPath => &mut draft.material_recovery_paths,
    }
}

fn verdict_draft_lines(draft: &VerdictDraft, review: Option<&TaskResultReview>) -> Vec<String> {
    verdict_draft_fields(draft.selection, review)
        .into_iter()
        .map(|field| {
            let active = if field == draft.active_field {
                ">"
            } else {
                " "
            };
            let (label, value) = match field {
                ResultReviewVerdictField::Reason => ("Reason", draft.reason_code.as_str()),
                ResultReviewVerdictField::Proof => ("Confirmation proof", "<masked>"),
                ResultReviewVerdictField::MaterialBody => (
                    if draft.selection == GuidedFounderVerdictSelection::Rework {
                        "Required changes"
                    } else {
                        "Risk rationale"
                    },
                    draft.material_body.as_str(),
                ),
                ResultReviewVerdictField::CompensatingControl => {
                    ("Compensating control", draft.compensating_control.as_str())
                }
                ResultReviewVerdictField::RiskCategory => {
                    ("Risk category", draft.risk_category.as_str())
                }
                ResultReviewVerdictField::Discrepancies => {
                    ("Discrepancy IDs", draft.discrepancy_ids.as_str())
                }
                ResultReviewVerdictField::UnverifiedItems => {
                    ("Unverified item IDs", draft.unverified_item_ids.as_str())
                }
                ResultReviewVerdictField::MaterialRecoveryPaths => (
                    "Material recovery paths",
                    draft.material_recovery_paths.as_str(),
                ),
                ResultReviewVerdictField::VerdictRecoveryPath => unreachable!(),
            };
            let display = if field == ResultReviewVerdictField::Proof {
                let masked = "*".repeat(draft.confirmation_proof_ref.chars().count());
                if masked.is_empty() {
                    "<empty>".to_owned()
                } else {
                    masked
                }
            } else if value.is_empty() {
                "<empty>".to_owned()
            } else {
                value.to_owned()
            };
            format!("{active} {label}: {display}")
        })
        .chain(std::iter::once(
            "Material recovery paths are separated with semicolons; IDs with commas.".to_owned(),
        ))
        .collect()
}

fn parse_identifier_list(value: &str, label: &str) -> Result<Vec<String>, String> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unique = values.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{label} coverage contains duplicate identifiers"));
    }
    Ok(values)
}

fn parse_risk_category(value: &str) -> Result<RiskCategory, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "quality" => Ok(RiskCategory::QualityResidual),
        "business" => Ok(RiskCategory::BusinessResidual),
        "operational" => Ok(RiskCategory::OperationalResidual),
        _ => Err("risk category must be quality, business, or operational".to_owned()),
    }
}

fn parse_recovery_paths(value: &str) -> Result<Vec<PathBuf>, String> {
    let paths = value
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| existing_private_recovery_path(Path::new(value)))
        .collect::<Result<Vec<_>, _>>()?;
    if paths
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != paths.len()
    {
        return Err("material recovery paths contain duplicates".to_owned());
    }
    Ok(paths)
}

pub(crate) fn client_private_recovery_directory() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|path| path.join(".local/state"))
        });
    #[cfg(not(any(windows, unix)))]
    let base: Option<PathBuf> = None;
    let base = base.ok_or_else(|| "client-private recovery directory is unavailable".to_owned())?;
    if !base.is_absolute() {
        return Err("client-private recovery directory must be absolute".to_owned());
    }
    let directory = base.join("egopulse/client/founder-verdict-recovery");
    fs::create_dir_all(&directory)
        .map_err(|_| "client-private recovery directory could not be created".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|_| {
            "client-private recovery directory permissions could not be set".to_owned()
        })?;
    }
    fs::canonicalize(directory)
        .map_err(|_| "client-private recovery directory could not be resolved".to_owned())
}

fn existing_private_recovery_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("a Founder recovery path is required".to_owned());
    }
    let directory = client_private_recovery_directory()?;
    let path =
        fs::canonicalize(path).map_err(|_| "Founder recovery file could not be read".to_owned())?;
    if !path.starts_with(&directory) || !path.is_file() {
        return Err("Founder recovery file must be inside the client-private directory".to_owned());
    }
    Ok(path)
}

fn new_founder_material_recovery_path() -> Result<PathBuf, String> {
    Ok(
        client_private_recovery_directory()?
            .join(format!("material-{}.json", uuid::Uuid::now_v7())),
    )
}

fn new_founder_verdict_recovery_path() -> Result<PathBuf, String> {
    Ok(client_private_recovery_directory()?.join(format!("verdict-{}.json", uuid::Uuid::now_v7())))
}

fn safe_material_error(error: ClientFounderSupportingMaterialError) -> String {
    match error {
        ClientFounderSupportingMaterialError::RecoveryStorage => {
            "supporting-material recovery storage failed; no request was sent and any existing record was preserved".to_owned()
        }
        ClientFounderSupportingMaterialError::InvalidInput => {
            "supporting material does not match the current trusted review".to_owned()
        }
        ClientFounderSupportingMaterialError::UnconfirmedReceipt => {
            "supporting material receipt was not confirmed".to_owned()
        }
        ClientFounderSupportingMaterialError::Kernel(_) => {
            "supporting material permission or session rejected".to_owned()
        }
        ClientFounderSupportingMaterialError::Transport(_) => {
            "supporting material transport unavailable".to_owned()
        }
        ClientFounderSupportingMaterialError::Authority => {
            "supporting material Authority rejected the request".to_owned()
        }
        ClientFounderSupportingMaterialError::Unknown { .. } => {
            "supporting-material outcome is unknown; use the saved recovery record".to_owned()
        }
    }
}

fn safe_durable_recovery_error(error: DurableFounderRecoveryError) -> String {
    match error {
        DurableFounderRecoveryError::InvalidRecord => {
            "Founder recovery record failed integrity validation".to_owned()
        }
        DurableFounderRecoveryError::PrincipalMismatch => {
            "Founder recovery requires the original authenticated principal".to_owned()
        }
        DurableFounderRecoveryError::StoreMismatch => {
            "Founder recovery belongs to a different projection store epoch".to_owned()
        }
        DurableFounderRecoveryError::Storage => {
            "Founder recovery storage is unavailable; the existing record was preserved".to_owned()
        }
    }
}

const fn durable_recovery_reason_code(error: &DurableFounderRecoveryError) -> &'static str {
    match error {
        DurableFounderRecoveryError::InvalidRecord => "RECOVERY_RECORD_INVALID",
        DurableFounderRecoveryError::PrincipalMismatch => "RECOVERY_PRINCIPAL_MISMATCH",
        DurableFounderRecoveryError::StoreMismatch => "RECOVERY_STORE_MISMATCH",
        DurableFounderRecoveryError::Storage => "RECOVERY_STORAGE_UNAVAILABLE",
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

fn safe_verdict_error(error: ClientGuidedFounderVerdictError) -> String {
    match error {
        ClientGuidedFounderVerdictError::RecoveryStorage => {
            "Founder Verdict recovery storage failed; no request was sent and any existing record was preserved".to_owned()
        }
        ClientGuidedFounderVerdictError::ApplyRecoveryStorage => {
            "Founder Verdict was issued, but Task application was not sent; preserve the recovery file and retry explicitly".to_owned()
        }
        ClientGuidedFounderVerdictError::Kernel(_) => {
            "client permission or session rejected".to_owned()
        }
        ClientGuidedFounderVerdictError::Review(error) => safe_review_error(&error),
        ClientGuidedFounderVerdictError::InvalidInput(detail)
        | ClientGuidedFounderVerdictError::NonActionable(detail)
        | ClientGuidedFounderVerdictError::MissingMaterial(detail) => detail.to_owned(),
        ClientGuidedFounderVerdictError::NonPassedAcceptRequiresRiskMaterials { conclusion } => {
            format!(
                "Accept for {conclusion:?} requires real rationale and compensating-control Artifacts"
            )
        }
        ClientGuidedFounderVerdictError::ReworkRequiresDirectiveMaterials => {
            "Rework requires a real required-changes Artifact and directive".to_owned()
        }
        ClientGuidedFounderVerdictError::RequestDigestMismatch => {
            "sealed command digest validation failed".to_owned()
        }
        ClientGuidedFounderVerdictError::BindingChanged => {
            "trusted Task result binding changed before submit".to_owned()
        }
        ClientGuidedFounderVerdictError::SessionChanged => {
            "authenticated session changed before exact retry".to_owned()
        }
        ClientGuidedFounderVerdictError::Authority { error_code, .. } => {
            format!("Founder Verdict Authority rejected code={error_code}")
        }
        ClientGuidedFounderVerdictError::TaskAuthority { error_code, .. } => {
            format!("Task Authority rejected application code={error_code}; preserve the recovery file")
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

    use super::*;
    use egopulse_domain_contracts::v01::egopulse::{
        artifact::v1::{
            ArtifactDescriptor, ArtifactSet, Claim, Evidence, LineageBinding, ProducerIdentity,
            Provenance,
        },
        common::v1::ContractReference,
        localapi::v1::{
            AvailableAction, AvailableActionKind, EvidenceGraphView, ProjectionMetadata,
            ProjectionPosition, RedactedField, SourceRevision, TaskView,
        },
        task::v1::TaskSnapshot,
        verdict::v1::{FounderAuthorityProof, FounderVerdict},
        verification::v1::{VerificationArtifact, VerificationBinding, VerificationProvenance},
    };

    #[derive(Clone)]
    enum ReadStep {
        Ready(Box<TaskResultReview>),
        Integrity,
        Pending(Arc<AtomicBool>),
    }

    #[derive(Clone, Copy)]
    enum VerdictStep {
        OutcomeUnknown,
        Committed,
        ApplyRecoveryStorage,
        PermissionDenied,
        LocalPreflightError,
    }

    #[derive(Clone, Copy)]
    enum PathRetryStep {
        ReadFailure,
        Committed,
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
        verdict_steps: Mutex<VecDeque<VerdictStep>>,
        submitted_commands: Mutex<Vec<VerdictCommand>>,
        submitted_recovery_paths: Mutex<Vec<PathBuf>>,
        path_retry_steps: Mutex<VecDeque<PathRetryStep>>,
        submit_calls: AtomicUsize,
        retry_calls: AtomicUsize,
        path_retry_calls: AtomicUsize,
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

        fn submit_guided_founder_verdict<'a>(
            &'a self,
            command: VerdictCommand,
            selection: GuidedFounderVerdictSelection,
        ) -> GuidedFounderVerdictFuture<'a> {
            self.submit_calls.fetch_add(1, Ordering::SeqCst);
            self.submitted_commands
                .lock()
                .unwrap()
                .push(command.clone());
            let step = self.verdict_steps.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { scripted_verdict_step(step, selection, command) })
        }

        fn retry_guided_founder_verdict<'a>(
            &'a self,
            recovery: &'a ResultReviewVerdictRecovery,
        ) -> GuidedFounderVerdictFuture<'a> {
            self.retry_calls.fetch_add(1, Ordering::SeqCst);
            self.submitted_commands
                .lock()
                .unwrap()
                .push(recovery.sealed_command().clone());
            let step = self.verdict_steps.lock().unwrap().pop_front().unwrap();
            let selection = recovery.selection();
            let command = recovery.sealed_command().clone();
            Box::pin(async move { scripted_verdict_step(step, selection, command) })
        }

        fn submit_guided_founder_verdict_durable<'a>(
            &'a self,
            command: VerdictCommand,
            selection: GuidedFounderVerdictSelection,
            _materials: Option<FounderSupportingMaterialCollection>,
            recovery_path: PathBuf,
        ) -> GuidedFounderVerdictFuture<'a> {
            self.submit_calls.fetch_add(1, Ordering::SeqCst);
            self.submitted_commands
                .lock()
                .unwrap()
                .push(command.clone());
            self.submitted_recovery_paths
                .lock()
                .unwrap()
                .push(recovery_path);
            let step = self.verdict_steps.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { scripted_verdict_step(step, selection, command) })
        }

        fn retry_durable_founder_verdict_from_path<'a>(
            &'a self,
            recovery_path: PathBuf,
            _expected_task_id: String,
        ) -> DurableFounderVerdictPathFuture<'a> {
            self.path_retry_calls.fetch_add(1, Ordering::SeqCst);
            self.submitted_recovery_paths
                .lock()
                .unwrap()
                .push(recovery_path);
            let step = self.path_retry_steps.lock().unwrap().pop_front().unwrap();
            Box::pin(async move {
                match step {
                    PathRetryStep::ReadFailure => Err("temporary recovery read failure".to_owned()),
                    PathRetryStep::Committed => Ok(ResultReviewDurablePathAttempt::Committed(
                        ResultReviewCommittedVerdict {
                            founder_verdict_id: "verdict:committed".to_owned(),
                            decision: FounderVerdictDecision::Accept,
                            replayed: true,
                            projection_pending: false,
                        },
                    )),
                }
            })
        }
    }

    fn scripted_verdict_step(
        step: VerdictStep,
        selection: GuidedFounderVerdictSelection,
        command: VerdictCommand,
    ) -> Result<ResultReviewVerdictAttempt, ClientGuidedFounderVerdictError> {
        match step {
            VerdictStep::OutcomeUnknown => {
                Ok(ResultReviewVerdictAttempt::OutcomeUnknown(Box::new(
                    ResultReviewVerdictRecovery::from_sealed_command_for_client_adapter(
                        selection, command,
                    ),
                )))
            }
            VerdictStep::Committed => Ok(ResultReviewVerdictAttempt::Committed(
                ResultReviewCommittedVerdict {
                    founder_verdict_id: "verdict:committed".to_owned(),
                    decision: match selection {
                        GuidedFounderVerdictSelection::Accept => FounderVerdictDecision::Accept,
                        GuidedFounderVerdictSelection::Reject => FounderVerdictDecision::Reject,
                        GuidedFounderVerdictSelection::Rework => FounderVerdictDecision::Rework,
                    },
                    replayed: true,
                    projection_pending: true,
                },
            )),
            VerdictStep::ApplyRecoveryStorage => {
                Err(ClientGuidedFounderVerdictError::ApplyRecoveryStorage)
            }
            VerdictStep::PermissionDenied => Err(ClientGuidedFounderVerdictError::Kernel(
                egopulse_client_kernel::KernelError::PermissionDenied(
                    "execute_founder_verdict".to_owned(),
                ),
            )),
            VerdictStep::LocalPreflightError => {
                Err(ClientGuidedFounderVerdictError::SessionChanged)
            }
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

    fn actionable_review(conclusion: VerificationConclusion) -> TaskResultReview {
        let lineage = LineageBinding {
            task_id: "task:review".to_owned(),
            task_revision: 4,
            work_revision: 2,
            run_id: "run:review".to_owned(),
            run_revision: 2,
            step_id: "step:review".to_owned(),
            step_revision: 2,
            attempt_id: "attempt:review".to_owned(),
            attempt_revision: 2,
            dispatch_id: "dispatch:review".to_owned(),
            fencing_token: 1,
        };
        let address =
            |seed: char| egopulse_domain_contracts::v01::egopulse::artifact::v1::ContentAddress {
                algorithm: HashAlgorithm::Sha256 as i32,
                digest: seed.to_string().repeat(64),
                byte_length: 12,
            };
        let acceptance = ContractReference {
            contract_id: "acceptance:review".to_owned(),
            version: "1".to_owned(),
            sha256: "d".repeat(64),
        };
        let metadata = |sequence, sources| ProjectionMetadata {
            schema_ref: Some(ContractReference {
                contract_id: "egopulse.localapi.v1/review".to_owned(),
                version: "0.1.0".to_owned(),
                sha256: "a".repeat(64),
            }),
            position: Some(ProjectionPosition {
                epoch: "epoch:review".to_owned(),
                sequence,
                projected_at: Some(prost_types::Timestamp {
                    seconds: sequence as i64,
                    nanos: 0,
                }),
            }),
            source_revisions: sources,
            health: ProjectionHealth::Ready as i32,
            stale: false,
            safe_health_reason_code: None,
        };
        let source = |domain: SourceDomain, id: &str, revision| SourceRevision {
            domain: domain as i32,
            aggregate_id: id.to_owned(),
            revision,
            last_event_id: format!("event:{id}:{revision}"),
        };
        let manifest = address('b');
        let artifact_set = ArtifactSet {
            artifact_set_id: "artifact-set:review".to_owned(),
            revision: 3,
            status: ArtifactSetStatus::Sealed as i32,
            lineage: Some(lineage.clone()),
            artifact_ids: vec!["artifact:review".to_owned()],
            claim_ids: vec!["claim:review".to_owned()],
            evidence_ids: vec!["evidence:review".to_owned()],
            canonical_manifest: Some(manifest.clone()),
            ..Default::default()
        };
        let verification = VerificationArtifact {
            verification_artifact_id: "verification:review".to_owned(),
            version: 2,
            binding: Some(VerificationBinding {
                lineage: Some(lineage.clone()),
                artifact_set_id: artifact_set.artifact_set_id.clone(),
                artifact_set_manifest: Some(manifest),
                claim_id: "claim:review".to_owned(),
                acceptance_contract_ref: Some(acceptance.clone()),
                ..Default::default()
            }),
            conclusion: conclusion as i32,
            canonical_payload: Some(address('c')),
            ..Default::default()
        };
        TaskResultReview {
            task_view: TaskView {
                metadata: Some(metadata(
                    20,
                    vec![
                        source(SourceDomain::Task, "task:review", 7),
                        source(SourceDomain::Artifact, "artifact-set:review", 3),
                        source(SourceDomain::Verification, "verification:review", 2),
                    ],
                )),
                task: Some(TaskSnapshot {
                    task_id: "task:review".to_owned(),
                    revision: 7,
                    work_revision: 2,
                    status: TaskStatus::VerdictPending as i32,
                    artifact_set_id: Some("artifact-set:review".to_owned()),
                    verification_artifact_id: Some("verification:review".to_owned()),
                    acceptance_contract_ref: Some(acceptance),
                    ..Default::default()
                }),
                artifact_set: Some(artifact_set),
                verification: Some(verification),
                available_actions: vec![AvailableAction {
                    kind: AvailableActionKind::SubmitFounderVerdict as i32,
                    owning_authority: "FounderVerdictAuthority".to_owned(),
                    derivation_rule_ref: "rule:task-actionability:v1".to_owned(),
                    explicit_confirmation_required: true,
                    reason_code: None,
                }],
                ..Default::default()
            },
            evidence_graph: Some(EvidenceGraphView {
                metadata: Some(metadata(
                    10,
                    vec![
                        source(SourceDomain::Artifact, "artifact-set:review", 3),
                        source(SourceDomain::Artifact, "artifact:review", 1),
                        source(SourceDomain::Artifact, "claim:review", 1),
                        source(SourceDomain::Artifact, "evidence:review", 1),
                    ],
                )),
                task_id: "task:review".to_owned(),
                artifact_set_id: "artifact-set:review".to_owned(),
                artifacts: vec![ArtifactDescriptor {
                    artifact_id: "artifact:review".to_owned(),
                    revision: 1,
                    provenance: Some(Provenance {
                        lineage: Some(lineage.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                claims: vec![Claim {
                    claim_id: "claim:review".to_owned(),
                    revision: 1,
                    lineage: Some(lineage.clone()),
                    subject_artifact_ids: vec!["artifact:review".to_owned()],
                    ..Default::default()
                }],
                evidence: vec![Evidence {
                    evidence_id: "evidence:review".to_owned(),
                    revision: 1,
                    claim_id: "claim:review".to_owned(),
                    artifact_ids: vec!["artifact:review".to_owned()],
                    lineage: Some(lineage),
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

    fn loaded_actionable_controller(
        conclusion: VerificationConclusion,
    ) -> ResultReviewController<ScriptedClient> {
        let client = Arc::new(ScriptedClient {
            steps: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            verdict_steps: Mutex::new(VecDeque::new()),
            submitted_commands: Mutex::new(Vec::new()),
            submitted_recovery_paths: Mutex::new(Vec::new()),
            path_retry_steps: Mutex::new(VecDeque::new()),
            submit_calls: AtomicUsize::new(0),
            retry_calls: AtomicUsize::new(0),
            path_retry_calls: AtomicUsize::new(0),
        });
        let review = actionable_review(conclusion);
        let model = ResultReviewPageModel::from_review(&review).unwrap();
        let mut controller = ResultReviewController::new(client, "task:review".to_owned());
        controller.trusted_review = Some(review);
        controller.model = Some(model);
        controller
    }

    #[test]
    fn trusted_task_target_scope_ref_reads_only_the_loaded_task_snapshot() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        assert_eq!(controller.trusted_task_target_scope_ref(), None);

        controller
            .trusted_review
            .as_mut()
            .expect("trusted review")
            .task_view
            .task
            .as_mut()
            .expect("trusted Task")
            .target_scope_ref = "scope:trusted-task".to_owned();
        assert_eq!(
            controller.trusted_task_target_scope_ref(),
            Some("scope:trusted-task")
        );

        controller.trusted_review = None;
        assert_eq!(controller.trusted_task_target_scope_ref(), None);
    }

    async fn pump_until_verdict_stage(
        controller: &mut ResultReviewController<ScriptedClient>,
        expected: ResultReviewVerdictStage,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                controller.pump().await.unwrap();
                if controller.verdict_stage() == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("verdict event settled");
    }

    fn prepare_accept_submission(controller: &mut ResultReviewController<ScriptedClient>) {
        controller
            .begin_verdict(GuidedFounderVerdictSelection::Accept)
            .unwrap();
        for character in "founder-accepted".chars() {
            controller.push_verdict_character(character);
        }
        controller.toggle_verdict_field();
        for character in "proof:configured".chars() {
            controller.push_verdict_character(character);
        }
        controller.prepare_verdict_confirmation().unwrap();
        controller.submit_verdict().unwrap();
    }

    #[test]
    fn verdict_draft_uses_trusted_capsule_masks_proof_and_exposes_required_material_fields() {
        let mut partial = loaded_actionable_controller(VerificationConclusion::Partial);
        partial
            .begin_verdict(GuidedFounderVerdictSelection::Accept)
            .unwrap();
        let lines = partial.verdict_draft_lines().unwrap().join("\n");
        assert!(lines.contains("Risk rationale"));
        assert!(lines.contains("Compensating control"));
        assert!(lines.contains("Risk category"));
        assert!(partial.cancel_unsent_verdict());
        partial
            .begin_verdict(GuidedFounderVerdictSelection::Rework)
            .unwrap();
        assert!(
            partial
                .verdict_draft_lines()
                .unwrap()
                .join("\n")
                .contains("Required changes")
        );
        assert!(partial.cancel_unsent_verdict());
        partial
            .begin_verdict(GuidedFounderVerdictSelection::Reject)
            .unwrap();
        for character in "founder-rejected".chars() {
            partial.push_verdict_character(character);
        }
        partial.toggle_verdict_field();
        for character in "proof:private".chars() {
            partial.push_verdict_character(character);
        }
        assert_eq!(partial.verdict_reason(), Some("founder-rejected"));
        assert_eq!(
            partial.verdict_proof_mask(),
            Some("*************".to_owned())
        );
        assert!(
            partial
                .model()
                .is_some_and(|model| !model.message.contains("proof:private"))
        );
        assert!(partial.cancel_unsent_verdict());
        assert_eq!(partial.verdict_stage(), ResultReviewVerdictStage::Viewing);
    }

    #[test]
    fn material_inputs_require_explicit_rework_or_complete_non_passed_accept_text() {
        let review = actionable_review(VerificationConclusion::Partial);
        let mut draft = VerdictDraft {
            selection: GuidedFounderVerdictSelection::Rework,
            reason_code: "rework".to_owned(),
            confirmation_proof_ref: "proof".to_owned(),
            material_body: String::new(),
            compensating_control: String::new(),
            risk_category: String::new(),
            discrepancy_ids: String::new(),
            unverified_item_ids: String::new(),
            material_recovery_paths: String::new(),
            active_field: ResultReviewVerdictField::Reason,
        };
        assert!(material_input_for_draft(&draft, &review).is_err());
        draft.material_body = "Fix the failing acceptance command".to_owned();
        let rework = material_input_for_draft(&draft, &review).unwrap();
        assert_eq!(rework.drafts.len(), 1);
        assert_eq!(
            rework.drafts[0].role,
            FounderSupportingMaterialRole::ReworkRequiredChanges
        );

        draft.selection = GuidedFounderVerdictSelection::Accept;
        draft.material_body = "Residual quality risk is bounded".to_owned();
        assert!(material_input_for_draft(&draft, &review).is_err());
        draft.compensating_control = "Keep the release disabled pending repair".to_owned();
        draft.risk_category = "quality".to_owned();
        draft.discrepancy_ids = "discrepancy:one".to_owned();
        let accept = material_input_for_draft(&draft, &review).unwrap();
        assert_eq!(accept.drafts.len(), 2);
        assert_eq!(accept.drafts[0].body, "Residual quality risk is bounded");
        assert_eq!(
            accept.drafts[1].body,
            "Keep the release disabled pending repair"
        );
    }

    #[test]
    fn missing_durable_recovery_path_keeps_the_user_in_recovery_input() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        controller.begin_verdict_recovery().unwrap();
        assert!(controller.recover_verdict_from_input().is_err());
        assert_eq!(
            controller.verdict_stage(),
            ResultReviewVerdictStage::RecoveryInput
        );
        assert!(
            controller
                .verdict_draft_lines()
                .unwrap()
                .join("\n")
                .contains("<empty>")
        );
    }

    #[tokio::test]
    async fn committed_issue_with_apply_storage_failure_keeps_exact_recovery_path() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        controller
            .client
            .verdict_steps
            .lock()
            .unwrap()
            .push_back(VerdictStep::ApplyRecoveryStorage);
        prepare_accept_submission(&mut controller);
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::RecoveryInput).await;
        let recovery_path = controller.client.submitted_recovery_paths.lock().unwrap()[0].clone();

        assert!(controller.has_unsettled_sent_verdict());
        assert!(!controller.cancel_unsent_verdict());
        assert_eq!(
            controller
                .recovery_summary()
                .expect("durable recovery summary")[1],
            format!("Recovery: {}", recovery_path.display())
        );
        assert!(
            controller
                .model()
                .expect("result review model")
                .message
                .contains("Task application was not confirmed")
        );
        assert_eq!(controller.client.submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.client.submitted_commands.lock().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn committed_issue_recovery_rereads_same_path_after_temporary_read_failure() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        controller
            .client
            .verdict_steps
            .lock()
            .unwrap()
            .push_back(VerdictStep::ApplyRecoveryStorage);
        controller
            .client
            .path_retry_steps
            .lock()
            .unwrap()
            .extend([PathRetryStep::ReadFailure, PathRetryStep::Committed]);
        prepare_accept_submission(&mut controller);
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::RecoveryInput).await;
        let recovery_path = controller.client.submitted_recovery_paths.lock().unwrap()[0].clone();

        controller.retry_verdict().unwrap();
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::RecoveryInput).await;
        assert_eq!(
            controller
                .recovery_summary()
                .expect("recovery retained after read failure")[1],
            format!("Recovery: {}", recovery_path.display())
        );
        controller.retry_verdict().unwrap();
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::Committed).await;
        assert_eq!(controller.client.path_retry_calls.load(Ordering::SeqCst), 2);
        assert_eq!(controller.client.submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            controller.client.submitted_commands.lock().unwrap().len(),
            1
        );
        assert_eq!(
            controller
                .client
                .submitted_recovery_paths
                .lock()
                .unwrap()
                .as_slice(),
            &[recovery_path.clone(), recovery_path.clone(), recovery_path]
        );
    }

    #[test]
    fn recovery_storage_errors_are_reported_as_unsent_storage_failures() {
        assert!(
            safe_material_error(ClientFounderSupportingMaterialError::RecoveryStorage)
                .contains("no request was sent")
        );
        assert!(
            safe_verdict_error(ClientGuidedFounderVerdictError::RecoveryStorage)
                .contains("no request was sent")
        );
    }

    #[test]
    fn material_unknown_retains_the_exact_retry_plan_and_blocks_verdict_submission() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Partial);
        controller
            .begin_verdict(GuidedFounderVerdictSelection::Rework)
            .unwrap();
        let VerdictState::Drafting(draft) = &controller.verdict_state else {
            panic!("Rework draft")
        };
        let draft = draft.clone();
        let recovery_path = PathBuf::from("saved-material-recovery.json");
        let plan = ResultReviewMaterialPlan {
            task_id: "task:review".to_owned(),
            allowed_roles: vec![FounderSupportingMaterialRole::ReworkRequiredChanges],
            recovery_paths: vec![recovery_path.clone()],
            prepared: Vec::new(),
            confirmed: Vec::new(),
        };
        controller
            .apply_material_result(
                draft,
                Ok(ResultReviewMaterialAttempt::Unknown {
                    retry_plan: plan,
                    recovery_path: recovery_path.clone(),
                    safe_reason_code: "RECOVERY_ORIGINAL_OUTCOME_UNKNOWN",
                }),
            )
            .unwrap();
        assert_eq!(
            controller.verdict_stage(),
            ResultReviewVerdictStage::MaterialOutcomeUnknown
        );
        assert!(controller.has_unsettled_sent_verdict());
        assert!(controller.submit_verdict().is_err());
        assert!(
            controller
                .recovery_summary()
                .unwrap()
                .join("\n")
                .contains("saved-material-recovery.json")
        );
    }

    #[test]
    fn verdict_confirmation_seals_once_and_summarizes_the_trusted_binding() {
        assert!(RESULT_REVIEW_VERDICT_EXPIRY <= Duration::from_secs(300));
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        controller
            .begin_verdict(GuidedFounderVerdictSelection::Accept)
            .unwrap();
        for character in "founder-accepted".chars() {
            controller.push_verdict_character(character);
        }
        controller.toggle_verdict_field();
        for character in "proof:configured".chars() {
            controller.push_verdict_character(character);
        }
        controller.prepare_verdict_confirmation().unwrap();
        let VerdictState::Confirming(pending) = &controller.verdict_state else {
            panic!("confirmed sealed command")
        };
        let sealed = pending.command.clone();
        assert!(
            controller
                .confirmation_summary()
                .unwrap()
                .join("\n")
                .contains("Verification: verification:review conclusion=Passed")
        );
        assert!(controller.prepare_verdict_confirmation().is_err());
        let VerdictState::Confirming(pending) = &controller.verdict_state else {
            panic!("confirmation remains intact")
        };
        assert_eq!(pending.command, sealed);
        assert!(controller.cancel_unsent_verdict());
    }

    #[tokio::test]
    async fn async_verdict_unknown_exact_retry_commits_without_losing_the_sealed_command() {
        let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
        controller
            .client
            .verdict_steps
            .lock()
            .unwrap()
            .extend([VerdictStep::OutcomeUnknown, VerdictStep::Committed]);
        prepare_accept_submission(&mut controller);
        assert_eq!(
            controller.verdict_stage(),
            ResultReviewVerdictStage::Submitting
        );
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::OutcomeUnknown).await;
        assert!(controller.has_unsettled_sent_verdict());
        assert!(controller.refresh().await.is_err());
        let first_command = controller
            .client
            .submitted_commands
            .lock()
            .unwrap()
            .first()
            .cloned()
            .unwrap();
        let VerdictState::OutcomeUnknown(recovery) = &controller.verdict_state else {
            panic!("shared submission recovery retained")
        };
        assert_eq!(recovery.sealed_command(), &first_command);

        controller.retry_verdict().unwrap();
        pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::Committed).await;
        assert!(!controller.has_unsettled_sent_verdict());
        assert_eq!(controller.client.submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(controller.client.retry_calls.load(Ordering::SeqCst), 1);
        let commands = controller.client.submitted_commands.lock().unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], commands[1]);
        assert!(
            controller
                .committed_summary()
                .unwrap()
                .contains("projection")
        );
    }

    #[tokio::test]
    async fn async_verdict_retry_errors_keep_the_original_unknown_recovery() {
        for retry_error in [
            VerdictStep::PermissionDenied,
            VerdictStep::LocalPreflightError,
        ] {
            let mut controller = loaded_actionable_controller(VerificationConclusion::Passed);
            controller
                .client
                .verdict_steps
                .lock()
                .unwrap()
                .extend([VerdictStep::OutcomeUnknown, retry_error]);
            prepare_accept_submission(&mut controller);
            pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::OutcomeUnknown)
                .await;
            let original = controller
                .client
                .submitted_commands
                .lock()
                .unwrap()
                .first()
                .cloned()
                .unwrap();

            controller.retry_verdict().unwrap();
            pump_until_verdict_stage(&mut controller, ResultReviewVerdictStage::OutcomeUnknown)
                .await;
            assert!(controller.has_unsettled_sent_verdict());
            assert!(controller.refresh().await.is_err());
            let VerdictState::OutcomeUnknown(recovery) = &controller.verdict_state else {
                panic!("retry error must retain unknown recovery")
            };
            assert_eq!(recovery.sealed_command(), &original);
            let commands = controller.client.submitted_commands.lock().unwrap();
            assert_eq!(commands.len(), 2);
            assert_eq!(commands[0], commands[1]);
        }
    }

    #[tokio::test]
    async fn controller_reads_once_maps_safe_dto_and_discards_old_generation_events() {
        let client = Arc::new(ScriptedClient {
            steps: Mutex::new(VecDeque::from([ReadStep::Ready(Box::new(review(
                "task:safe",
            )))])),
            calls: AtomicUsize::new(0),
            verdict_steps: Mutex::new(VecDeque::new()),
            submitted_commands: Mutex::new(Vec::new()),
            submitted_recovery_paths: Mutex::new(Vec::new()),
            path_retry_steps: Mutex::new(VecDeque::new()),
            submit_calls: AtomicUsize::new(0),
            retry_calls: AtomicUsize::new(0),
            path_retry_calls: AtomicUsize::new(0),
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
        assert!(
            sender
                .send(ResultReviewWorkerEvent::Loaded {
                    generation: generation - 1,
                    review: Box::new(review("task:old")),
                    model: Box::new(
                        ResultReviewPageModel::from_review(&review("task:old")).unwrap(),
                    ),
                })
                .await
                .is_ok()
        );
        assert!(
            sender
                .send(ResultReviewWorkerEvent::Failed {
                    generation: generation - 1,
                    detail: "old failure".to_owned(),
                })
                .await
                .is_ok()
        );
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
            verdict_steps: Mutex::new(VecDeque::new()),
            submitted_commands: Mutex::new(Vec::new()),
            submitted_recovery_paths: Mutex::new(Vec::new()),
            path_retry_steps: Mutex::new(VecDeque::new()),
            submit_calls: AtomicUsize::new(0),
            retry_calls: AtomicUsize::new(0),
            path_retry_calls: AtomicUsize::new(0),
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
        assert!(
            sender
                .try_send(ResultReviewWorkerEvent::Failed {
                    generation: 1,
                    detail: "full".to_owned(),
                })
                .is_ok()
        );
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
